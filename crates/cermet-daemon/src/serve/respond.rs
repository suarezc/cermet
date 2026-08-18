//! The response-writing layer: the `DeadlineWriter` (absolute per-response write budget) and the
//! per-verb `write_*` helpers that project a core view onto the redacted agent wire response.

use std::os::unix::net::UnixStream as StdUnixStream;
use std::time::{Duration, Instant};

use cermet_ipc::codec::{self, write_response_frame};
use cermet_ipc::wire::{AgentRequestOutcome, AgentResponse};

/// A `Write` adapter that enforces an ABSOLUTE deadline across a whole response, re-arming the
/// per-syscall `set_write_timeout` to the shrinking remaining budget before each write. A slow
/// reader can no longer hold the handler thread past the budget: once the deadline passes,
/// the next write fails closed (`TimedOut`) and the handler returns, freeing the connection slot.
pub(crate) struct DeadlineWriter<'a> {
    stream: &'a StdUnixStream,
    deadline: Instant,
}

impl<'a> DeadlineWriter<'a> {
    pub(crate) fn new(stream: &'a StdUnixStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }
}

impl std::io::Write for DeadlineWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let now = Instant::now();
        let remaining = self.deadline.saturating_duration_since(now);
        // Guard the sub-millisecond tail: SO_SNDTIMEO rounds to a coarse resolution, and a 0
        // duration means "block forever" — so treat a near-zero budget as expired, fail closed.
        if remaining < Duration::from_millis(1) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "response write budget exceeded",
            ));
        }
        self.stream.set_write_timeout(Some(remaining))?;
        let mut s: &StdUnixStream = self.stream;
        s.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut s: &StdUnixStream = self.stream;
        s.flush()
    }
}

/// `hello` → `AgentResponse::Session { session_id }`. The reply carries only the opaque server-minted
/// handle — no authority, no secret.
pub(super) fn write_session<W: std::io::Write>(w: &mut W, session_id: &str) -> codec::Result<()> {
    write_response_frame(
        w,
        &AgentResponse::Session {
            session_id: session_id.to_string(),
            // Advertise the custody vocabulary this daemon actually speaks — the agent
            // gates its debt-clearing reconciliation on these (fail closed under version skew).
            features: cermet_ipc::wire::DAEMON_FEATURES
                .iter()
                .map(|f| f.to_string())
                .collect(),
            // And the build this daemon IS. A client process that outlives a reinstall
            // has no other way to notice its own staleness; the daemon just says which build
            // answered, and the client compares once per session.
            build: cermet_ipc::BUILD_ID.to_string(),
        },
    )
}

/// Write a fixed error envelope with a typed reason.
pub(super) fn write_error<W: std::io::Write>(w: &mut W, reason: &str) -> codec::Result<()> {
    write_error_with_effect(w, reason, None, None)
}

pub(super) fn write_error_with_effect<W: std::io::Write>(
    w: &mut W,
    reason: &str,
    effect_id: Option<&str>,
    effect_outcome: Option<cermet_core::EffectOutcome>,
) -> codec::Result<()> {
    write_response_frame(
        w,
        &AgentResponse::Error {
            reason: reason.to_string(),
            effect_id: effect_id.map(str::to_string),
            effect_outcome,
        },
    )
}

/// Tag an already-serialized core view object with its `AgentResponse` `kind` and frame it.
fn write_tagged<W: std::io::Write>(w: &mut W, kind: &str, json: &str) -> codec::Result<()> {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.insert(
                "kind".to_string(),
                serde_json::Value::String(kind.to_string()),
            );
            write_response_frame(w, &serde_json::Value::Object(map))
        }
        _ => write_error(w, "internal error"),
    }
}

/// `request` → `AgentResponse::Requested(AgentRequestOutcome)`. Deserializing the core
/// `RequestOutcome` JSON into the redacted `AgentRequestOutcome` structurally drops `grant_id`
/// (present on Allow) so the agent never sees a grant id.
pub(super) fn write_requested<W: std::io::Write>(
    w: &mut W,
    outcome_json: &str,
) -> codec::Result<()> {
    match serde_json::from_str::<AgentRequestOutcome>(outcome_json) {
        Ok(outcome) => write_response_frame(w, &AgentResponse::Requested(outcome)),
        Err(_) => write_error(w, "internal error"),
    }
}

/// `execute` → route the core `ExecOutcome` JSON by its `kind` tag.
pub(super) fn write_exec_outcome<W: std::io::Write>(
    w: &mut W,
    outcome_json: &str,
) -> codec::Result<()> {
    let kind = serde_json::from_str::<serde_json::Value>(outcome_json)
        .ok()
        .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(str::to_string));
    match kind.as_deref() {
        Some("executed") => write_tagged(w, "executed", outcome_json),
        _ => write_error(w, "internal error"),
    }
}

/// `catalog` → `AgentResponse::Catalog { catalog }`. Deserializing the core listing into the typed
/// wire response drops anything that isn't a known schema field.
pub(super) fn write_catalog<W: std::io::Write>(w: &mut W, listing_json: &str) -> codec::Result<()> {
    match serde_json::from_str::<cermet_core::types::CatalogListing>(listing_json) {
        Ok(listing) => write_response_frame(
            w,
            &AgentResponse::Catalog {
                catalog: listing.catalog,
            },
        ),
        Err(_) => write_error(w, "internal error"),
    }
}

/// `record_vocabulary_request` → the bare `vocabulary_request_recorded` acknowledgement. It carries
/// no payload on purpose: the agent needs to know only that the claim it is about to make to its
/// operator ("your log has this") is true.
pub(super) fn write_vocabulary_request_recorded<W: std::io::Write>(w: &mut W) -> codec::Result<()> {
    write_response_frame(w, &AgentResponse::VocabularyRequestRecorded)
}

/// `status` → `AgentResponse::Status { request_id, status }` from the core `RequestStatusView` object
/// (tagging it with its `kind`, exactly like `write_executed`).
pub(super) fn write_status<W: std::io::Write>(w: &mut W, view_json: &str) -> codec::Result<()> {
    write_tagged(w, "status", view_json)
}

/// `artifact` → `AgentResponse::Artifact(ArtifactSpan)` from the core `ArtifactSpan` object (tagging
/// it with its `kind`, exactly like `write_executed`). No secret — the span carries only content the
/// caller already may read.
pub(super) fn write_artifact<W: std::io::Write>(w: &mut W, span_json: &str) -> codec::Result<()> {
    write_tagged(w, "artifact", span_json)
}

/// `verify_audit` → `AgentResponse::AuditVerified{ ok }` from the core `IntegrityReport.verified`.
pub(super) fn write_audit_verified<W: std::io::Write>(
    w: &mut W,
    report_json: &str,
) -> codec::Result<()> {
    let ok = serde_json::from_str::<serde_json::Value>(report_json)
        .ok()
        .and_then(|v| v.get("verified").and_then(|b| b.as_bool()));
    match ok {
        Some(ok) => write_response_frame(
            w,
            &serde_json::json!({ "kind": "audit_verified", "ok": ok }),
        ),
        None => write_error(w, "internal error"),
    }
}

/// Write the `Credentials` response envelope from the actor's serialized array.
pub(super) fn write_credentials<W: std::io::Write>(
    w: &mut W,
    creds_json: &str,
) -> codec::Result<()> {
    let creds: serde_json::Value = match serde_json::from_str(creds_json) {
        Ok(v @ serde_json::Value::Array(_)) => v,
        _ => return write_error(w, "internal error"),
    };
    let envelope = serde_json::json!({ "kind": "credentials", "credentials": creds });
    write_response_frame(w, &envelope)
}
