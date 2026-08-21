//! Compiled request-time field canonicalization.
//!
//! A verb whose identity field names a provider object that humans SPELL one way and the provider
//! IDENTIFIES another way declares one compiled profile here. Before the sentence judges the
//! request, the daemon replaces the supplied spelling with the provider's own canonical identifier,
//! and everything downstream — the decision, the frozen grant, the relay's per-hop binds, the
//! receipt — sees only the canonical value.
//!
//! Adversary (the `no adversary, no defense` rule): **T2** — an agent supplying the human-legible
//! name because that is what the task, the operator, and the provider's own dashboard say. The
//! resolution cannot WIDEN authority: the canonical value is an INPUT to the sentence, never an
//! output of it, so a slug that resolves into a team the corpus does not admit denies exactly as the
//! id would have. T1 (a steered agent naming another team's slug) lands in the same place.
//!
//! Why this is not the [`crate::evidence`] path, which also resolves provider facts pre-mint: that
//! machinery answers a different question under a different regime, and three of its properties are
//! disqualifying here.
//!   1. Its envelope is 30-second fresh ([`crate::evidence::EVIDENCE_TTL_SECS`]) and re-checked at
//!      CLAIM (`verify_grant_evidence`). A relay deploy grant is claimed by a native CLI whose
//!      session runs for minutes — an evidence-backed relay grant would be dead before it was used.
//!   2. It is anti-oracle by construction: every deny of an evidence-backed verb is rewritten to
//!      the generic `provider evidence unavailable`, with the widening suggestion, the typed deny
//!      reason and the authority kind stripped. That regime exists to keep resolved MONEY facts out
//!      of deny reasons; applied to `vercel.deploy` it would delete exactly the denial quality this
//!      change exists to improve.
//!   3. Its outputs are fields that were ABSENT from the request (`inputs`/`outputs` are disjoint,
//!      and a pre-supplied output is a `Mismatch` deny). Canonicalization rewrites a field the agent
//!      DID supply, in place.
//!
//! So this is the same seam (vault credential opened inside the daemon, one provider read, a typed
//! fail-closed denial, an audited receipt, the resolved value frozen before approval) without the
//! money regime layered on top.

/// The receipt written when a supplied value was replaced by the provider's canonical identifier.
/// Nothing is written when the request already named the canonical form — there is no event because
/// there was no resolution.
pub const CANONICALIZATION_RECEIPT_EVENT_TYPE: &str = "request_field_canonicalized";
/// The receipt written when a supplied value could not be resolved. Access never follows.
pub const CANONICALIZATION_FAILED_EVENT_TYPE: &str = "request_field_canonicalization_failed";

/// Vercel identifies a team account by `team_…`. A value already in that form is canonical and
/// short-circuits before the vault is opened — a team-id request costs no credential and makes no
/// provider hop, exactly as before this profile existed. Everything else is a name to resolve.
pub const VERCEL_TEAM_ID_PREFIX: &str = "team_";
/// The read: the teams the connected token is a member of, each carrying its own `id` and `slug`.
/// Chosen over `GET /v2/teams/{teamId}` (whose slug lookup is a QUERY override on a REQUIRED path
/// segment the caller does not have) because it needs nothing but the credential, and because a
/// bindless team listing is already the ratified, authority-free bootstrap the native CLI itself
/// makes inside an approved deploy session.
pub const VERCEL_TEAMS_PATH: &str = "/v2/teams";
/// One page at the API maximum. NOTE (accepted, not code): a connection reaching MORE than this many
/// teams can hold a slug this read does not see, and that slug then DENIES as unresolvable. Fail
/// closed, never a guess, and the operator's next move is to name the `team_…` id, which needs no
/// resolution at all. Cursor-walking every page would buy a case the ICP does not have.
pub const VERCEL_TEAMS_PAGE_LIMIT: u32 = 100;

/// The compiled canonicalizers. A template NAMES one by profile id; it can never express one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalizerKind {
    /// `vercel.deploy`'s `team`: a team slug (or the display name people type) → the `team_…` id.
    VercelTeamScope,
}

impl CanonicalizerKind {
    /// Pure and credential-free: does this supplied value ALREADY name the canonical identifier?
    /// `true` means the request is untouched — no vault open, no provider read, no receipt.
    pub fn is_canonical(self, value: &str) -> bool {
        match self {
            Self::VercelTeamScope => value.starts_with(VERCEL_TEAM_ID_PREFIX),
        }
    }
}

/// One trusted, versioned profile: which field of which verb is canonicalized, by which compiled
/// resolver, and the provenance label the receipt records.
#[derive(Debug)]
pub struct CanonicalizationProfile {
    pub id: &'static str,
    pub provider: &'static str,
    pub action: &'static str,
    /// The single request field this profile rewrites.
    pub field: &'static str,
    /// The provider-side origin of the canonical value, for the receipt.
    pub source: &'static str,
    pub resolver: CanonicalizerKind,
}

static VERCEL_DEPLOY_TEAM_SCOPE_PROFILE: CanonicalizationProfile = CanonicalizationProfile {
    id: "vercel.deploy.team_scope.v1",
    provider: "vercel",
    action: "deploy",
    field: "team",
    source: "vercel.team.id",
    resolver: CanonicalizerKind::VercelTeamScope,
};

/// Look up one trusted, versioned profile. The profile id selects exact compiled semantics, never a
/// template-authored resolver language.
pub fn profile(id: &str) -> Option<&'static CanonicalizationProfile> {
    (id == VERCEL_DEPLOY_TEAM_SCOPE_PROFILE.id).then_some(&VERCEL_DEPLOY_TEAM_SCOPE_PROFILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_canonical_form_short_circuits_before_any_credential() {
        let resolver = CanonicalizerKind::VercelTeamScope;
        assert!(resolver.is_canonical("team_abc123"));
        assert!(!resolver.is_canonical("cermet-test-team"));
        // Anything that is not a `team_…` id is a NAME to resolve — including words that once
        // carried a reserved meaning here. There is no reserved literal left.
        assert!(!resolver.is_canonical("personal"));
        assert!(!resolver.is_canonical("my-team_x"));
    }

    #[test]
    fn only_the_registered_profile_id_resolves() {
        let profile = profile("vercel.deploy.team_scope.v1").expect("the compiled profile");
        assert_eq!(profile.provider, "vercel");
        assert_eq!(profile.action, "deploy");
        assert_eq!(profile.field, "team");
        assert!(super::profile("vercel.deploy.team_scope.v2").is_none());
        assert!(super::profile("").is_none());
    }
}
