//! Request/response frame vocabulary for the IPC boundary.

pub use cermet_lang::artifacts::{ArtifactAddress, ArtifactRange, ArtifactSpan};
use cermet_lang::templates::CatalogEntry;
pub use cermet_lang::types::{AuthorityKind, BudgetWindow, EffectOutcome};
use cermet_lang::types::{Decision, ExecutionResult, SafeCredential};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The distinct, fixed reason the daemon returns when a caller-supplied `session_id` does not
/// reference an OPEN session row (never silently minted — fail closed). Shared here so the daemon
/// (emit) and the MCP bridge (detect → re-`Hello` once → retry) stay in lockstep on the exact string.
pub const SESSION_EXPIRED: &str = "session expired — re-initialize";

/// The distinct, id-free reasons the daemon returns for a grant-execute refusal WHOSE
/// OWNER holds the request handle (an unknown/unowned handle still collapses to the opaque execute
/// failure, preserving the anti-oracle boundary). Shared here so the daemon (emit) and any
/// client (detect/render) agree on the exact strings.
pub const EXECUTE_ALREADY_USED: &str =
    "this grant was already used — grants are single-use; request a fresh capability";
pub const EXECUTE_NOT_READY: &str = "this grant is not ready to execute — re-request it";
pub const EXECUTE_EXPIRED: &str = "this grant expired — request it again";
pub const EXECUTE_TEMPLATE_DRIFTED: &str =
    "this grant was authorized under a different action template — re-request it";
/// The distinct, fixed refusal a `Hello` gets when the client's build does not equal the
/// daemon's. ONE inode makes every FUTURE exec generation-coherent; it cannot update a process that
/// already mapped the old one. An MCP stdio server from an 11-day-old build once served an agent
/// session across several reinstalls and a daemon restart, and nothing could refuse it — under the
/// no-backward-compat rule that surfaces later as unexplained per-call failures with no recovery
/// hint. So build identity is an ADMISSION check, not a note: a skewed client is refused BEFORE any
/// session is minted, with the one action that fixes it. Clients detect this by prefix; the daemon
/// appends both build ids so the operator can see which halves disagree (a build id is not a secret
/// — `cermet --version` prints it).
pub const BUILD_SKEW: &str = "build skew; restart the agent session";

/// The Hello-negotiated daemon FEATURE labels. The custody model's proofs are only as
/// good as the daemon behind them, so the agent gates its debt-clearing logic on what the daemon
/// PROVED it speaks at Hello — a new agent on an old daemon fails closed (holds debt, legible
/// refusal) instead of settling on a projection/refusal vocabulary the daemon doesn't have.
/// The daemon advertises `DAEMON_FEATURES` in the `session` frame; an old daemon's frame simply
/// lacks the field (serde default: empty).
///
/// `custody_proof_v1`: the typed already-terminal refusal + the `executing`-vs-`executed` status
/// projection split.
pub const FEATURE_CUSTODY_PROOF: &str = "custody_proof_v1";
/// Async execute v1: the daemon serves a principal-bound DURABLE terminal-status
/// query — `Status` carries the run `phase` (ready|running|terminal), the terminal
/// `outcome`/`termination`, and a `terminal_receipt` REBUILT from the verified audit chain (never
/// derived from grant status/clock). The MCP async surface (bounded-wait `execute_capability` +
/// long-poll `request_status`) GATES its admission on this: an old daemon that never negotiated it
/// cannot answer "did this background run finish, and how?", so the surface fails BEFORE any claim
/// (legible skew refusal) rather than silently falling back to a fully-blocking execute.
pub const FEATURE_ASYNC_EXECUTE: &str = "async_execute_v1";
/// Everything this build's daemon speaks — written into every `session` frame.
pub const DAEMON_FEATURES: &[&str] = &[FEATURE_CUSTODY_PROOF, FEATURE_ASYNC_EXECUTE];

/// The op vocabulary on `agent.sock`.
///
/// Every request but [`AgentRequest::Hello`] carries an OPTIONAL `session_id` (the handshake): a
/// caller that opened a session via `Hello` attaches its id so a whole agent conversation threads
/// onto ONE server-minted session instead of fragmenting one-per-connection. The field is
/// `#[serde(default)]` so pre-handshake clients (which omit it) still parse; the id stays
/// server-minted — the agent supplies no identity beyond the `Hello` display name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum AgentRequest {
    /// Open (mint) a session for this conversation and return its server-minted id. The agent
    /// supplies only a DISPLAY name (`agent`) — never an identity: authority is the kernel-attested
    /// peer uid. The daemon does an opportunistic idle-session sweep here.
    ///
    /// `build` is MANDATORY for admission: the daemon compares it against its own
    /// [`crate::BUILD_ID`] and refuses a mismatch with [`BUILD_SKEW`] before minting anything. It is
    /// `#[serde(default)]` only so a client that predates the field gets that LEGIBLE refusal
    /// instead of an unexplained frame-parse failure — absence deserializes to the empty string,
    /// which never equals a real build id. The reverse direction needs no accommodation: a daemon
    /// predating the field rejects the unknown key through `deny_unknown_fields` above.
    Hello {
        agent: String,
        #[serde(default)]
        build: String,
        /// The agent runtime's own name from the MCP `initialize` handshake's `clientInfo`. A
        /// SELF-REPORT and never an identity: it is display data recorded on this box's own rows,
        /// it never leaves the machine, and no authority anywhere reads it. `None`
        /// from a caller that never handshook (the git plane, an operator ctl session).
        #[serde(default)]
        client_name: Option<String>,
        #[serde(default)]
        client_version: Option<String>,
        /// What the HUMAN declared they are running, from the documented `CERMET_AGENT_MODEL`
        /// environment variable. A self-report of a different kind — a person's claim, not a
        /// runtime's — which is why its provenance is carried separately downstream.
        #[serde(default)]
        model: Option<String>,
    },
    /// Request a capability by its direct provider/action identity. Unknown fields are rejected, so
    /// retired alias forms cannot silently enter the broker.
    Request {
        provider: String,
        action: String,
        #[serde(default)]
        resource: Value,
        #[serde(default)]
        environment: Option<String>,
        #[serde(default)]
        justification: Option<String>,
        /// What the AGENT says it is, on THIS request. A self-report, never
        /// authenticated, read by no authority — and per-request rather than per-session because a
        /// runtime that switches models mid-session keeps the same session, so a session-static
        /// declaration mislabels every row after the switch.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        /// Explicit request-time money retry lineage. This is a safe logical effect handle, never an
        /// idempotency key and never an execute-time fill.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_effect: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
    /// Execute a sentence-authorized, single-use grant by the agent's stable handle (`request_id`).
    /// `grant_id` is operator-internal and never crosses this boundary.
    Execute {
        request_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
    /// List the connected providers.
    ListCredentials {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
    /// Verify the audit hash-chain integrity.
    VerifyAudit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
    /// Discover the verbs: the per-verb schema of every action this broker can request or seed
    /// (provider/action/fields/execution_targets/requestable). Read-only — no authority, no secret.
    Catalog {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
    /// Report ONE vocabulary request: a verb or field the catalog has no word for (`gap:
    /// "vocabulary_gap"`), or the probe the bridge refused because the word already exists
    /// (`gap: "authority_gap"` — a refused probe is signal too). The daemon appends it to its
    /// event log. It authorizes nothing, and nothing reads it back to decide anything.
    ///
    /// The free text arrives ALREADY scrubbed by the bridge's chokepoint (a credential-shaped form
    /// never becomes a request); the daemon re-checks the closed gap vocabulary and the string
    /// bounds on its own side of the boundary.
    RecordVocabularyRequest {
        provider: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wanted_verb: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wanted_field: Option<String>,
        gap: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ask: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rationale: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
    /// The live status of a prior request by its stable `request_id`
    /// (`ready | running | terminal`). Read-only.
    Status {
        request_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
    /// Retrieve a stored artifact by its `handle`: full, a byte/line `range`, or a `$.path`
    /// capture-pointer that returns one JSON sub-value. `range` and `path` are mutually exclusive
    /// (both set is a fail-closed error). Read-only — no authority, no secret. Fail closed: an unknown
    /// handle or a tampered blob errors, never empty-success.
    Artifact {
        handle: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        range: Option<ArtifactRange>,
        /// A `$.seg(.seg)*` capture-pointer into the retained response body parsed as JSON. Additive —
        /// an older caller omits it and reads a range or the full blob as before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
}

impl AgentRequest {
    /// The caller-supplied conversation session id, if any (every variant but `Hello` may carry one).
    /// The daemon reads this to thread a request onto its conversation's session — or to REFUSE it
    /// fail-closed when the id no longer references an open session.
    pub fn session_id(&self) -> Option<&str> {
        match self {
            AgentRequest::Hello { .. } => None,
            AgentRequest::Request { session_id, .. }
            | AgentRequest::Execute { session_id, .. }
            | AgentRequest::ListCredentials { session_id }
            | AgentRequest::VerifyAudit { session_id }
            | AgentRequest::Catalog { session_id }
            | AgentRequest::RecordVocabularyRequest { session_id, .. }
            | AgentRequest::Status { session_id, .. }
            | AgentRequest::Artifact { session_id, .. } => session_id.as_deref(),
        }
    }

    /// Stamp `session_id` onto whichever variant carries one (every variant but `Hello`). The MCP
    /// bridge builds the wire request from its command, then attaches the cached conversation session
    /// here so it need not thread the id through every constructor.
    pub fn set_session_id(&mut self, sid: Option<String>) {
        match self {
            AgentRequest::Hello { .. } => {}
            AgentRequest::Request { session_id, .. }
            | AgentRequest::Execute { session_id, .. }
            | AgentRequest::ListCredentials { session_id }
            | AgentRequest::VerifyAudit { session_id }
            | AgentRequest::Catalog { session_id }
            | AgentRequest::RecordVocabularyRequest { session_id, .. }
            | AgentRequest::Status { session_id, .. }
            | AgentRequest::Artifact { session_id, .. } => *session_id = sid,
        }
    }
}

pub const fn accepted_agent_request_operation_tags() -> &'static [&'static str] {
    &[
        "hello",
        "request",
        "execute",
        "list_credentials",
        "verify_audit",
        "catalog",
        "record_vocabulary_request",
        "status",
        "artifact",
    ]
}

/// The agent-facing request outcome: the core `RequestOutcome` MINUS `grant_id`. The agent references
/// its capability by `request_id`; `grant_id` is operator-internal and never crosses the agent
/// boundary. Omitting the field makes the leak impossible to express — a `skip_serializing` on the
/// shared type could be silently undone by a refactor; a distinct type cannot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequestOutcome {
    pub request_id: String,
    pub decision: Decision,
    pub reason: String,
    /// The window CLASSIFICATION of an exhausted budget/rate aggregate — the ONLY budget signal
    /// that crosses the agent boundary. A window enum, never a number: no limit/remaining/consumed/
    /// amount is agent-facing (anti-oracle). Present only on a budget-downgrade deny; deserialized
    /// straight from the core `RequestOutcome` JSON, so the redacted type carries it faithfully.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_exceeded: Option<BudgetWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Safe logical money-effect lineage handle. No private idempotency key can be represented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<String>,
    /// Safe sentence provenance only; no rule bytes/fingerprint/selector can be represented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_kind: Option<AuthorityKind>,
}

/// The response vocabulary on `agent.sock`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentResponse {
    /// The handshake reply: the server-minted session id for this conversation. Carries no
    /// authority and no secret — just the opaque `sess_<hex>` handle the agent attaches to its
    /// subsequent requests.
    Session {
        session_id: String,
        /// The daemon's negotiated feature labels (see `DAEMON_FEATURES`). Additive —
        /// an old daemon's frame omits it and deserializes empty, which the agent treats as
        /// "speaks none of the custody vocabulary" (fail closed).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        features: Vec<String>,
        /// The daemon's [`crate::BUILD_ID`]. Additive on the SAME seam as `features` and
        /// with the same old-frame tolerance — a daemon predating this field simply omits it, and a
        /// client reads the absence as [`crate::UNKNOWN_BUILD`], never as "same build". Detection
        /// only: a client NOTES a mismatch (in-band once for the MCP bridge, one stderr line for
        /// the operator CLI, a row in `cermet check`) and never refuses on it.
        #[serde(default)]
        build: String,
    },
    Requested(AgentRequestOutcome),
    Executed(ExecutionResult),
    Credentials {
        credentials: Vec<SafeCredential>,
    },
    AuditVerified {
        ok: bool,
    },
    /// The verb catalog: per-verb schema only, with no step bodies or values.
    Catalog {
        catalog: Vec<CatalogEntry>,
    },
    /// A request's live status, keyed by the agent's `request_id`.
    Status {
        request_id: String,
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        effect_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        effect_outcome: Option<EffectOutcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        deny_reason: Option<String>,
        /// The typed run phase, equal to `status`: `ready` | `running` | `terminal`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        phase: Option<String>,
        /// For a `terminal` phase, the settled outcome (`succeeded` | `failed` | `denied` |
        /// `abandoned`) read from the verified terminal audit event — NEVER inferred from grant
        /// status/clock. Absent unless terminal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outcome: Option<String>,
        /// For a `terminal` phase, the termination cause.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        termination: Option<String>,
        /// The DURABLE `executed` receipt rebuilt from the verified audit chain. Already redacted
        /// at record time; carries no secret. Absent unless terminal AND reconstructable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        terminal_receipt: Option<Value>,
    },
    /// One vocabulary request was appended to the event log. Carries nothing: the agent needs to
    /// know only that the claim "your operator's log has this" is true.
    VocabularyRequestRecorded,
    /// A retrieved artifact span (full or ranged). The newtype flattens the `ArtifactSpan` fields
    /// under the `kind:"artifact"` tag, exactly like `Executed(ExecutionResult)`. No secret.
    Artifact(ArtifactSpan),
    /// Fail-closed error envelope.
    Error {
        reason: String,
        /// Safe logical money-effect handle, present only when the daemon authenticated the owned
        /// request/grant before returning an execution error.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        effect_id: Option<String>,
        /// Authenticated disposition paired with `effect_id`; absent if no terminal class is known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        effect_outcome: Option<EffectOutcome>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{read_frame, write_frame};
    use cermet_lang::templates::{CatalogField, CatalogShape};
    use cermet_lang::types::Decision;

    #[test]
    fn retired_request_forms_no_longer_decode_on_the_agent_wire() {
        for frame in [
            r#"{"op":"request","alias":"deploy","resource":{}}"#,
            r#"{"op":"execute","request_id":"rq-1","wait_ms":1000}"#,
        ] {
            assert!(
                serde_json::from_str::<AgentRequest>(frame).is_err(),
                "retired frame decoded: {frame}"
            );
        }
    }
    use std::io::Cursor;

    /// The hello reply carries the daemon's build identity, exactly as it carries its
    /// feature labels — one field, one advertisement, the seam a client compares itself against.
    #[test]
    fn the_session_frame_advertises_the_daemons_build_identity() {
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &AgentResponse::Session {
                session_id: "sess_1".into(),
                features: DAEMON_FEATURES.iter().map(|f| f.to_string()).collect(),
                build: crate::BUILD_ID.to_string(),
            },
        )
        .unwrap();
        let back: Value = read_frame(&mut Cursor::new(buf)).unwrap();
        assert_eq!(back["kind"], "session");
        assert_eq!(back["build"], crate::BUILD_ID);
    }

    #[test]
    fn op_vocabulary_frames_roundtrip() {
        let reqs = vec![
            AgentRequest::Hello {
                agent: "mcp-agent".into(),
                build: crate::BUILD_ID.into(),
                client_name: Some("claude-code".into()),
                client_version: Some("1.2.3".into()),
                model: Some("claude-sonnet-4".into()),
            },
            AgentRequest::Request {
                provider: "vercel".into(),
                action: "deploy".into(),
                resource: serde_json::json!({"repo_id": "r1"}),
                environment: Some("preview".into()),
                justification: Some("ship the PR".into()),
                model: Some("claude-opus-5".into()),
                retry_effect: None,
                session_id: Some("sess_1".into()),
            },
            AgentRequest::Execute {
                request_id: "rq-1".into(),
                session_id: Some("sess_1".into()),
            },
            AgentRequest::ListCredentials { session_id: None },
            AgentRequest::VerifyAudit { session_id: None },
            AgentRequest::Catalog { session_id: None },
            AgentRequest::Status {
                request_id: "rq-1".into(),
                session_id: Some("sess_1".into()),
            },
            AgentRequest::Artifact {
                handle: "art_abc".into(),
                range: None,
                path: None,
                session_id: None,
            },
            AgentRequest::Artifact {
                handle: "art_abc".into(),
                range: Some(ArtifactRange {
                    unit: "lines".into(),
                    start: 2,
                    end: Some(10),
                }),
                path: None,
                session_id: Some("sess_1".into()),
            },
            AgentRequest::Artifact {
                handle: "art_abc".into(),
                range: None,
                path: Some("$.deployment.url".into()),
                session_id: None,
            },
        ];
        for req in &reqs {
            let mut buf = Vec::new();
            write_frame(&mut buf, req).unwrap();
            let mut cur = Cursor::new(buf);
            let back: AgentRequest = read_frame(&mut cur).unwrap();
            assert_eq!(&back, req, "request must round-trip identically");
        }

        let outcome = AgentRequestOutcome {
            request_id: "rq-1".into(),
            decision: Decision::Allow,
            reason: "allowed by scope".into(),
            budget_exceeded: None,
            hint: None,
            effect_id: None,
            authority_kind: Some(AuthorityKind::Sentence),
        };
        let exec = ExecutionResult {
            ok: true,
            provider: "vercel".into(),
            action: "deploy".into(),
            effect_id: Some("effect_0123456789abcdef0123456789abcdef".into()),
            effect_outcome: Some(EffectOutcome::Succeeded),
            result: serde_json::json!({"url": "https://preview.example"}),
            artifact: None,
            wire_stats: None,
            envelope: cermet_lang::types::ReceiptEnvelope::stamp("rq_1", Default::default()),
        };
        let cred = SafeCredential {
            reference: "vercel:default".into(),
            provider: "vercel".into(),
            account_label: Some("acme".into()),
            created_at: "2026-06-21T00:00:00Z".into(),
            last_used: None,
        };

        let responses = vec![
            AgentResponse::Session {
                session_id: "sess_1".into(),
                features: DAEMON_FEATURES.iter().map(|f| f.to_string()).collect(),
                build: crate::BUILD_ID.to_string(),
            },
            AgentResponse::Requested(outcome),
            AgentResponse::Executed(exec),
            AgentResponse::Credentials {
                credentials: vec![cred],
            },
            AgentResponse::AuditVerified { ok: true },
            AgentResponse::Catalog {
                catalog: vec![CatalogEntry {
                    provider: "vercel".into(),
                    action: "deploy".into(),
                    class: cermet_lang::templates::CatalogClass::Corpus,
                    fields: vec![CatalogField {
                        name: "project".into(),
                        ty: "str".into(),
                        required: true,
                        class: "identity".into(),
                        binding: "exact_resource_pin".into(),
                        origin: "agent_request".into(),
                        forms: vec!["=".into(), "in".into()],
                    }],
                    execution_targets: vec!["project".into()],
                    requestable: true,
                    shape: CatalogShape::HttpApiCall,
                    sentence_denied: false,
                    admitted_by: vec!["allow vercel.deploy where project = \"cermet-site\"".into()],
                    denied_by: Vec::new(),
                    response: cermet_lang::templates::ResponseContract {
                        returns: "verbatim".into(),
                        retention: "full".into(),
                        errors: "status_and_body".into(),
                    },
                }],
            },
            AgentResponse::Status {
                request_id: "rq-1".into(),
                status: "ready".into(),
                effect_id: Some("effect_0123456789abcdef0123456789abcdef".into()),
                effect_outcome: None,
                deny_reason: None,
                phase: Some("ready".into()),
                outcome: None,
                termination: None,
                terminal_receipt: None,
            },
            AgentResponse::Artifact(ArtifactSpan {
                handle: "art_abc".into(),
                digest: "deadbeef".into(),
                stored_size: 12,
                size: 12,
                truncated: false,
                unit: "bytes".into(),
                start: 0,
                end: 12,
                path: None,
                frame_truncated: false,
                content: "hello output".into(),
            }),
            AgentResponse::Error {
                reason: "unknown op on this channel".into(),
                effect_id: Some("effect_0123456789abcdef0123456789abcdef".into()),
                effect_outcome: Some(EffectOutcome::Ambiguous),
            },
        ];
        for resp in &responses {
            let mut buf = Vec::new();
            write_frame(&mut buf, resp).unwrap();
            let mut cur = Cursor::new(buf);
            let back: Value = read_frame(&mut cur).unwrap();
            assert!(back.get("kind").is_some(), "response carries its tag");
            assert_no_secret_keys(&back);
        }

        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &AgentResponse::Executed(ExecutionResult {
                ok: true,
                provider: "github".into(),
                action: "x".into(),
                effect_id: Some("effect_0123456789abcdef0123456789abcdef".into()),
                effect_outcome: Some(EffectOutcome::Succeeded),
                result: Value::Null,
                artifact: None,
                wire_stats: None,
                envelope: cermet_lang::types::ReceiptEnvelope::stamp("rq_1", Default::default()),
            }),
        )
        .unwrap();
        let mut cur = Cursor::new(buf);
        let back: Value = read_frame(&mut cur).unwrap();
        assert_eq!(back["ok"], serde_json::json!(true));
        assert_eq!(back["effect_id"], "effect_0123456789abcdef0123456789abcdef");
        assert_eq!(back["effect_outcome"], "succeeded");

        // The agent-facing `requested` outcome must NEVER carry a grant_id — even on Allow, where the
        // core RequestOutcome does. The redacted type makes this structural, not a runtime scrub.
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &AgentResponse::Requested(AgentRequestOutcome {
                request_id: "rq-allow".into(),
                decision: Decision::Allow,
                reason: "allowed".into(),
                budget_exceeded: None,
                hint: None,
                effect_id: Some("effect_0123456789abcdef0123456789abcdef".into()),
                authority_kind: Some(AuthorityKind::Sentence),
            }),
        )
        .unwrap();
        let mut cur = Cursor::new(buf);
        let back: Value = read_frame(&mut cur).unwrap();
        assert!(
            back.get("grant_id").is_none(),
            "the agent-facing requested outcome must never carry grant_id"
        );
        assert_eq!(back["effect_id"], "effect_0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn moneypath_retry_effect_round_trips_as_request_metadata_not_resource_data() {
        let request = AgentRequest::Request {
            provider: "stripe".into(),
            action: "capture_payment_intent".into(),
            resource: serde_json::json!({"payment_intent":"pi_1","amount":500}),
            environment: None,
            justification: Some("retry an ambiguous capture".into()),
            model: None,
            retry_effect: Some("effect_0123456789abcdef0123456789abcdef".into()),
            session_id: Some("sess_1".into()),
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            value["retry_effect"],
            "effect_0123456789abcdef0123456789abcdef"
        );
        assert!(value["resource"].get("retry_effect").is_none());
        assert_eq!(
            serde_json::from_value::<AgentRequest>(value).unwrap(),
            request
        );
    }

    #[test]
    fn requested_hint_is_additive_and_round_trips_on_the_agent_wire() {
        let old: AgentRequestOutcome = serde_json::from_value(serde_json::json!({
            "request_id": "rq-old",
            "decision": "deny",
            "reason": "denied",
        }))
        .unwrap();
        let old = serde_json::to_value(AgentResponse::Requested(old)).unwrap();
        assert!(
            old.get("hint").is_none(),
            "old frames remain byte-compatible"
        );

        let hint = "to allow: cermet rules allow 'stripe.support@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa where amount <= 50000'";
        let new: AgentRequestOutcome = serde_json::from_value(serde_json::json!({
            "request_id": "rq-new",
            "decision": "deny",
            "reason": "outside rule",
            "hint": hint,
        }))
        .unwrap();
        let new = serde_json::to_value(AgentResponse::Requested(new)).unwrap();
        assert_eq!(new["hint"], serde_json::json!(hint));
    }

    #[test]
    fn requested_authority_kind_is_optional() {
        let old: AgentRequestOutcome = serde_json::from_value(serde_json::json!({
            "request_id": "rq-old",
            "decision": "allow",
            "reason": "allowed",
        }))
        .unwrap();
        let old = serde_json::to_value(AgentResponse::Requested(old)).unwrap();
        assert!(old.get("authority_kind").is_none());

        let sentence: AgentRequestOutcome = serde_json::from_value(serde_json::json!({
            "request_id": "rq-sentence",
            "decision": "allow",
            "reason": "allowed",
            "authority_kind": "sentence",
        }))
        .unwrap();
        let sentence = serde_json::to_value(AgentResponse::Requested(sentence)).unwrap();
        assert_eq!(sentence["authority_kind"], serde_json::json!("sentence"));
        assert!(sentence.get("authority_fingerprint").is_none());
        assert!(sentence.get("selector").is_none());
    }

    // Anti-oracle: the ONLY budget signal on the agent wire is the
    // `budget_exceeded` WINDOW enum — never a number. This greps the serialized agent outcome: it must
    // carry the window string and NONE of the operator-side numbers (limit / consumed / projected /
    // debit). The core `RequestOutcome` JSON deserializes straight into this redacted type, so a leak
    // would have to be an explicit numeric field here — and there is none.
    #[test]
    fn budget_window_is_the_only_budget_signal_on_the_agent_wire() {
        let downgrade: AgentRequestOutcome = serde_json::from_value(serde_json::json!({
            "request_id": "rq-budget",
            "decision": "deny",
            "reason": "stripe.support budget exhausted for the day window",
            // Even if the CORE ever tried to attach numbers, the redacted type has no field to hold
            // them — deserialization drops any unknown key.
            "budget_exceeded": "day",
            "limit": 100,
            "consumed_before": 90,
            "projected": 150,
            "debit": 60,
        }))
        .unwrap();
        let value = serde_json::to_value(AgentResponse::Requested(downgrade)).unwrap();
        assert_eq!(value["budget_exceeded"], serde_json::json!("day"));
        // Not a number: the window is an enum, and no numeric budget field survives onto the wire.
        assert!(value.get("limit").is_none());
        assert!(value.get("consumed_before").is_none());
        assert!(value.get("projected").is_none());
        assert!(value.get("debit").is_none());
        // A plain (non-budget) outcome omits the field entirely (additive, legacy-safe).
        let plain: AgentRequestOutcome = serde_json::from_value(serde_json::json!({
            "request_id": "rq-plain",
            "decision": "allow",
            "reason": "allowed",
        }))
        .unwrap();
        let plain = serde_json::to_value(AgentResponse::Requested(plain)).unwrap();
        assert!(plain.get("budget_exceeded").is_none());
    }

    #[test]
    fn agent_ipc_operation_tags_are_an_exact_positive_closed_set() {
        const EXPECTED: &[&str] = &[
            "hello",
            "request",
            "execute",
            "list_credentials",
            "verify_audit",
            "catalog",
            // Reporting a word the catalog does not have. Append-only DATA — it authorizes
            // nothing, and nothing reads it back to decide anything.
            "record_vocabulary_request",
            "status",
            "artifact",
        ];
        assert_eq!(accepted_agent_request_operation_tags(), EXPECTED);
        // `language` is retired from the agent vocabulary — internal documents are
        // internal, and a wire op with no client is a path that does not exist.
        assert!(!EXPECTED.contains(&"language"));

        for op in EXPECTED {
            let parsed = serde_json::from_value::<AgentRequest>(serde_json::json!({"op": op}));
            if let Err(error) = parsed {
                assert!(
                    !error.to_string().contains("unknown variant"),
                    "accepted operation tag `{op}` was rejected as unknown: {error}"
                );
            }
        }

        let error = serde_json::from_value::<AgentRequest>(serde_json::json!({
            "op": "not_an_agent_operation"
        }))
        .unwrap_err()
        .to_string();
        let accepted = EXPECTED
            .iter()
            .map(|op| format!("`{op}`"))
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(
            error,
            format!("unknown variant `not_an_agent_operation`, expected one of {accepted}"),
            "serde's exact accepted operation vocabulary drifted"
        );
    }

    #[test]
    fn deleted_pipeline_op_tags_fail_decoding_as_unknown_variants() {
        // Pipelines are deleted. Every old pipeline op tag must fail to decode as
        // an unknown serde variant — there is deliberately no "pipeline removed" response shim, so a
        // stale client speaking one of these gets a hard decode error, not a soft acknowledgement.
        for op in [
            "request_pipeline",
            "execute_pipeline",
            "continue_pipeline",
            "retry_pipeline_step",
            "abandon_pipeline_run",
        ] {
            let error = serde_json::from_value::<AgentRequest>(serde_json::json!({"op": op}))
                .expect_err(&format!("deleted pipeline op `{op}` must not decode"))
                .to_string();
            assert!(
                error.contains("unknown variant"),
                "deleted pipeline op `{op}` must be rejected as an unknown variant, got: {error}"
            );
        }
        // The accepted vocabulary itself must carry none of them.
        for op in accepted_agent_request_operation_tags() {
            assert!(
                !op.contains("pipeline"),
                "accepted agent op vocabulary still lists a pipeline tag: {op}"
            );
        }
    }

    #[test]
    fn set_session_id_stamps_every_variant_but_hello() {
        // The bridge builds the wire request, then stamps its cached conversation session. Hello is
        // the minting frame and carries no session; every other variant must receive it.
        let mut hello = AgentRequest::Hello {
            agent: "a".into(),
            build: crate::BUILD_ID.into(),
            client_name: None,
            client_version: None,
            model: None,
        };
        hello.set_session_id(Some("sess_x".into()));
        assert_eq!(
            hello,
            AgentRequest::Hello {
                agent: "a".into(),
                build: crate::BUILD_ID.into(),
                client_name: None,
                client_version: None,
                model: None,
            },
            "Hello is untouched"
        );

        let stampable = [
            AgentRequest::Request {
                provider: "p".into(),
                action: "a".into(),
                resource: Value::Null,
                environment: None,
                justification: None,
                model: None,
                retry_effect: None,
                session_id: None,
            },
            AgentRequest::Execute {
                request_id: "rq".into(),
                session_id: None,
            },
            AgentRequest::ListCredentials { session_id: None },
            AgentRequest::VerifyAudit { session_id: None },
            AgentRequest::Catalog { session_id: None },
            AgentRequest::Status {
                request_id: "rq".into(),
                session_id: None,
            },
            AgentRequest::Artifact {
                handle: "h".into(),
                range: None,
                path: None,
                session_id: None,
            },
        ];
        for mut req in stampable {
            req.set_session_id(Some("sess_x".into()));
            let v = serde_json::to_value(&req).unwrap();
            assert_eq!(
                v.get("session_id").and_then(Value::as_str),
                Some("sess_x"),
                "set_session_id must stamp {req:?}"
            );
        }
    }

    fn assert_no_secret_keys(v: &Value) {
        const FORBIDDEN: &[&str] = &[
            "token",
            "secret",
            "credential",
            "api_key",
            "apikey",
            "password",
            "bearer",
            "access_token",
            "private_key",
        ];
        match v {
            Value::Object(map) => {
                for (k, val) in map {
                    let lk = k.to_ascii_lowercase();
                    assert!(
                        !FORBIDDEN.contains(&lk.as_str()),
                        "response carried a forbidden secret-bearing key: {k}"
                    );
                    assert_no_secret_keys(val);
                }
            }
            Value::Array(arr) => arr.iter().for_each(assert_no_secret_keys),
            _ => {}
        }
    }
}
