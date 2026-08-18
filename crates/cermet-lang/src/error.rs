use thiserror::Error;

/// Errors surfaced across the Cermet API. Never carries a plaintext secret.
#[derive(Debug, Error)]
pub enum Error {
    #[error("capability denied: {0}")]
    Denied(String),
    /// A product-disabled provider was named at any authoring, request, connect, or execution seam.
    /// Content-free and stable so every surface can preserve the same fail-closed refusal.
    #[error("provider_disabled")]
    ProviderDisabled,
    /// A CALLER-SUPPLIED session id no longer references an OPEN session row (swept/closed/unknown).
    /// Distinct from [`Error::Denied`] so the daemon can map it to the wire `SESSION_EXPIRED` reason
    /// (triggering the bridge's re-Hello recovery) instead of collapsing it into the opaque
    /// execute-failure reason. Fail closed: an unresolved session NEVER leads to access.
    #[error("session expired")]
    SessionExpired,
    /// A grant-execute refusal whose CLASS is safe to surface to the caller that HOLDS the request
    /// handle. Distinct from [`Error::Denied`] so the daemon can map each class to a
    /// specific wire reason for the OWNER — the anti-oracle boundary still holds because an
    /// unknown or unowned handle never reaches these sites: it fails first as `NotFound` (unknown
    /// request) or `Denied` (not the owner), both of which stay the opaque `EXECUTE_FAILED`.
    #[error("execute refused: {0}")]
    ExecuteRefused(ExecuteRefusal),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("integrity error: {0}")]
    Integrity(String),
    /// A new approved→executing claim is refused because an MCP-repoint quiesce barrier is
    /// active. Typed distinctly from [`Error::Denied`] so the daemon/CLI can surface a transient
    /// "server is quiescing for an MCP repoint, retry shortly" instead of a permanent policy denial.
    /// Fail closed: the single-use grant is NEVER consumed while the barrier holds.
    #[error("temporarily quiesced for MCP repoint: {0}")]
    TemporaryQuiesce(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("provider error: {0}")]
    Provider(String),
    /// A provider hop that produced NO usable response and whose cause the seam itself could type:
    /// the git upstream's credential refusal and a transport failure that never got an
    /// answer. Everything else about it is an [`Error::Provider`] — same class word, same wire code,
    /// same message — but the class rides along so the recording seam three frames up writes typed
    /// evidence instead of re-deriving it from this string. A hop that DID get a response needs no
    /// variant: its status is already the typed signal.
    #[error("provider error: {1}")]
    ProviderFailed(crate::types::EffectFailureClass, String),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A filesystem fault.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// THE CTL WIRE ERROR CONTRACT, pinned here — next to `Display` — because it has TWO
/// ends and they must agree.
///
/// An error crosses the ctl socket as the pair (`code`, `reason`): **`code` carries the CLASS and
/// `reason` carries the BARE payload**. The class word is `Display`'s job and is rendered exactly
/// ONCE, client-side, after [`Error::from_wire`] rebuilds the typed variant. The daemon used to
/// frame `e.to_string()` as `reason`, which put the class on the wire twice — textually in `reason`
/// AND typed in `code` — so every prefixed variant doubled on the terminal
/// (`cermet: not found: not found: req_cdd141a4690581c1 …`).
impl Error {
    /// The stable wire CLASS code. Every class has one, so the payload never has to carry the class
    /// word to survive the trip. The HTTP mapping a socket client derives from it is unchanged:
    /// `denied`→403 / `not_found`→404 / `invalid`→400 / everything else→500.
    pub fn wire_code(&self) -> &'static str {
        match self {
            Error::Denied(_) => "denied",
            Error::ProviderDisabled => "provider_disabled",
            Error::SessionExpired => "session_expired",
            Error::ExecuteRefused(_) => "execute_refused",
            Error::NotFound(_) => "not_found",
            Error::Invalid(_) => "invalid",
            Error::Integrity(_) => "integrity",
            Error::TemporaryQuiesce(_) => "temporary_quiesce",
            Error::Crypto(_) => "crypto",
            // `Provider` is the fail-safe class an unknown code rebuilds as, so it needs no code of
            // its own; the transparent faults have no class word to preserve and join it.
            Error::Provider(_)
            | Error::ProviderFailed(..)
            | Error::Db(_)
            | Error::Json(_)
            | Error::Io(_) => "internal",
        }
    }

    /// The BARE payload for the wire — never the class word. A variant whose `Display` IS the whole
    /// message (no payload of its own) sends that stable `Display`.
    pub fn wire_payload(&self) -> String {
        match self {
            Error::Denied(payload)
            | Error::NotFound(payload)
            | Error::Invalid(payload)
            | Error::Integrity(payload)
            | Error::TemporaryQuiesce(payload)
            | Error::Crypto(payload)
            | Error::Provider(payload) => payload.clone(),
            // The class is in-process evidence for the recording seam, not a wire class: it
            // survives no round trip, and the payload is the same message `Provider` would send.
            Error::ProviderFailed(_, payload) => payload.clone(),
            Error::ExecuteRefused(class) => class.to_string(),
            Error::ProviderDisabled | Error::SessionExpired => self.to_string(),
            Error::Db(_) | Error::Json(_) | Error::Io(_) => self.to_string(),
        }
    }

    /// The failure class the SEAM typed onto this error, when it typed one. The execution
    /// recording seam asks exactly this question; every other error answers `None` and lands on the
    /// residual class, which is the honest answer for a vault fault, an egress refusal, or a
    /// template error — none of them are a provider's verdict on a credential.
    pub fn effect_failure_class(&self) -> Option<crate::types::EffectFailureClass> {
        match self {
            Error::ProviderFailed(class, _) => Some(*class),
            _ => None,
        }
    }

    /// Rebuild the typed error from the wire pair. An unknown or absent code becomes `Provider` —
    /// the fail-safe (→ 500), never a caller-actionable class.
    pub fn from_wire(code: Option<&str>, payload: &str) -> Self {
        match code {
            Some("denied") => Error::Denied(payload.to_string()),
            Some("provider_disabled") => Error::ProviderDisabled,
            Some("session_expired") => Error::SessionExpired,
            Some("execute_refused") => match ExecuteRefusal::from_wire(payload) {
                Some(class) => Error::ExecuteRefused(class),
                None => Error::Provider(payload.to_string()),
            },
            Some("not_found") => Error::NotFound(payload.to_string()),
            Some("invalid") => Error::Invalid(payload.to_string()),
            Some("integrity") => Error::Integrity(payload.to_string()),
            Some("temporary_quiesce") => Error::TemporaryQuiesce(payload.to_string()),
            Some("crypto") => Error::Crypto(payload.to_string()),
            _ => Error::Provider(payload.to_string()),
        }
    }
}

/// The distinguishable classes of a grant-execute refusal. Each maps to a specific,
/// id-free wire reason the daemon returns to the request handle's owner instead of the opaque
/// `EXECUTE_FAILED`. The variants never carry an id, so they are safe once ownership is established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecuteRefusal {
    /// The single-use grant was already claimed/executed.
    AlreadyUsed,
    /// The grant is not in an executable state.
    NotReady,
    /// The grant's lease/TTL passed before execute.
    Expired,
    /// The action template frozen on the grant no longer matches the live registry.
    TemplateDrifted,
}

impl ExecuteRefusal {
    /// The inverse of [`ExecuteRefusal`]'s `Display`, so the refusal CLASS survives the ctl round
    /// trip instead of collapsing into an untyped provider error. An unrecognized
    /// payload yields `None`, and the caller falls back to the fail-safe class.
    fn from_wire(payload: &str) -> Option<Self> {
        [
            ExecuteRefusal::AlreadyUsed,
            ExecuteRefusal::NotReady,
            ExecuteRefusal::Expired,
            ExecuteRefusal::TemplateDrifted,
        ]
        .into_iter()
        .find(|class| class.to_string() == payload)
    }
}

impl std::fmt::Display for ExecuteRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ExecuteRefusal::AlreadyUsed => "grant already used (single-use)",
            ExecuteRefusal::NotReady => "grant not ready",
            ExecuteRefusal::Expired => "grant expired",
            ExecuteRefusal::TemplateDrifted => "grant authorized under a different action template",
        };
        f.write_str(s)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// What a caller must read after the error crosses ctl and is rendered client-side. The
    /// match is EXHAUSTIVE on purpose: a new variant does not compile until its round-trip
    /// rendering is classified here.
    fn expected_round_trip(e: &Error) -> String {
        match e {
            // A classed error renders IDENTICALLY on both sides of the wire — the class travels as
            // `code`, so the prefix is added exactly once, by the client's own `Display`.
            Error::Denied(_)
            | Error::ProviderDisabled
            | Error::SessionExpired
            | Error::ExecuteRefused(_)
            | Error::NotFound(_)
            | Error::Invalid(_)
            | Error::Integrity(_)
            | Error::TemporaryQuiesce(_)
            | Error::Crypto(_)
            | Error::Provider(_)
            | Error::ProviderFailed(..) => e.to_string(),
            // A transparent fault has no class word of its own; it lands in the fail-safe
            // `Provider` class, which prefixes it once.
            Error::Db(_) | Error::Json(_) | Error::Io(_) => format!("provider error: {e}"),
        }
    }

    fn every_variant() -> Vec<Error> {
        vec![
            Error::Denied("no rule matches this request".into()),
            Error::ProviderDisabled,
            Error::SessionExpired,
            Error::ExecuteRefused(ExecuteRefusal::AlreadyUsed),
            Error::NotFound("req_cdd141a4690581c1".into()),
            Error::Invalid("resource is not an object".into()),
            Error::Integrity("request req_x grant integrity failed".into()),
            Error::TemporaryQuiesce("retry shortly".into()),
            Error::Crypto("vault open failed".into()),
            Error::Provider("stripe returned 500".into()),
            Error::Db(rusqlite::Error::QueryReturnedNoRows),
            Error::Json(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
            Error::Io(std::io::Error::other("disk gone")),
        ]
    }

    /// The daemon used to frame `e.to_string()` as the wire `reason` while `code` already carried
    /// the class, so the client rebuilt the variant around an ALREADY-PREFIXED payload and its own
    /// `Display` prefixed it again — `cermet: not found: not found: req_…`. The contract is pinned
    /// instead of the message: `reason` is the bare payload, `code` is the class.
    #[test]
    fn every_error_class_survives_the_ctl_round_trip_exactly_once() {
        let variants = every_variant();
        assert_eq!(
            variants.len(),
            13,
            "every Error variant needs a sample here; the exhaustive match below classifies it"
        );
        for e in &variants {
            let rebuilt = Error::from_wire(Some(e.wire_code()), &e.wire_payload());
            let rendered = rebuilt.to_string();
            assert_eq!(
                rendered,
                expected_round_trip(e),
                "{e:?} rendered wrong after the ctl round trip"
            );
            let payload = e.wire_payload();
            assert_eq!(
                rendered.matches(payload.as_str()).count(),
                1,
                "the payload must appear exactly once in {rendered:?}"
            );
        }
    }

    /// The wire `reason` must be the BARE payload: no class word, ever — that is what makes the
    /// doubling structurally impossible rather than patched at one call site.
    #[test]
    fn wire_payload_never_carries_the_class_word() {
        for e in every_variant() {
            let payload = e.wire_payload();
            for class in [
                "capability denied:",
                "not found:",
                "invalid input:",
                "integrity error:",
                "crypto error:",
                "provider error:",
                "execute refused:",
                "temporarily quiesced",
            ] {
                assert!(
                    !payload.contains(class),
                    "{e:?} put the class word on the wire: {payload:?}"
                );
            }
        }
    }

    /// The HTTP status classes a socket client derives from `code` (denied→403 / not_found→404 /
    /// invalid→400 / else→500) are load-bearing; pin the three that are not "else".
    #[test]
    fn actionable_wire_codes_are_stable() {
        assert_eq!(Error::Denied(String::new()).wire_code(), "denied");
        assert_eq!(Error::NotFound(String::new()).wire_code(), "not_found");
        assert_eq!(Error::Invalid(String::new()).wire_code(), "invalid");
        assert_eq!(Error::ProviderDisabled.wire_code(), "provider_disabled");
        // An unknown code is the fail-safe class, never a caller-actionable one.
        assert!(matches!(
            Error::from_wire(Some("a-code-from-the-future"), "x"),
            Error::Provider(_)
        ));
        assert!(matches!(Error::from_wire(None, "x"), Error::Provider(_)));
    }

    #[test]
    fn execute_refusal_classes_round_trip() {
        for class in [
            ExecuteRefusal::AlreadyUsed,
            ExecuteRefusal::NotReady,
            ExecuteRefusal::Expired,
            ExecuteRefusal::TemplateDrifted,
        ] {
            let e = Error::ExecuteRefused(class);
            assert!(matches!(
                Error::from_wire(Some(e.wire_code()), &e.wire_payload()),
                Error::ExecuteRefused(back) if back == class
            ));
        }
    }
}
