//! The `ctl.sock` operator op vocabulary — the human-only control channel.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Derive the durable acceptance occurrence bound to one staging nonce.
pub fn sentence_occurrence_for_token(staging_token: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"cermet.sentence.commit-occurrence\0");
    hash.update(staging_token.as_bytes());
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The read-only typed view of the daemon-owned sentence record. Corrupt records never expose bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state")]
pub enum SentenceSnapshot {
    Absent,
    Served {
        record_digest: String,
        rules_text: String,
        authority_digest: String,
        occurrence_id: String,
        rule_count: usize,
    },
    Unserved {
        record_digest: String,
        rules_text: String,
        authority_digest: String,
        occurrence_id: String,
        rule_count: usize,
    },
    Corrupt {
        record_digest: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockdownSnapshot {
    Clear,
    Engaged,
}

/// One observational read of the served-generation gate and independent owner lockdown latch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentenceAuthorityStatus {
    pub sentence: SentenceSnapshot,
    pub lockdown: LockdownSnapshot,
}

/// The typed inert result of staging one exact canonical sentence corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedSentenceCorpus {
    pub canonical_text: String,
    pub canonical_digest: String,
    pub staging_token: String,
    pub occurrence_id: String,
}

/// The typed result of committing one nonce-bound staged corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome")]
pub enum SentenceCommitOutcome {
    Committed {
        canonical_digest: String,
        occurrence_id: String,
    },
    AlreadyCommitted {
        canonical_digest: String,
        occurrence_id: String,
    },
}

impl SentenceCommitOutcome {
    pub fn canonical_digest(&self) -> &str {
        match self {
            Self::Committed {
                canonical_digest, ..
            }
            | Self::AlreadyCommitted {
                canonical_digest, ..
            } => canonical_digest,
        }
    }

    pub fn occurrence_id(&self) -> &str {
        match self {
            Self::Committed { occurrence_id, .. }
            | Self::AlreadyCommitted { occurrence_id, .. } => occurrence_id,
        }
    }
}

/// A provider token in transit on `ctl.sock` for ingestion (the [`CtlRequest::Connect`] op).
///
/// It serializes **transparently** as the bare string — the wire MUST carry the secret so it can
/// reach the daemon's vault (that is the whole point: the token goes straight to the uid-400
/// daemon instead of resting in the user's uid). But its `Debug` is **redacted**, so a
/// stray `{:?}` on a `CtlRequest` (a log line, a panic message) can never spill the token. The
/// daemon wraps it in a `secrecy::SecretString` at the moment of use, and it never travels back
/// out — the reply is a secret-free `ConnectOutcome`.
#[derive(PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RedactedToken(pub String);

impl std::fmt::Debug for RedactedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedactedToken(<redacted>)")
    }
}

/// Zeroize the token bytes on drop so a successful ingest — or an error/close path —
/// does not leave a recoverable copy lingering in the daemon/app heap. `into_inner` MOVES the string
/// out (into a `SecretString` at the call-site, which keeps the zeroize-on-drop protection), leaving
/// an empty string behind for this `Drop` to scrub. The codec frame body is also held in
/// `Zeroizing<Vec<u8>>`, so the JSON copy is scrubbed after encode/decode.
impl Drop for RedactedToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl RedactedToken {
    /// Consume the wrapper, yielding the raw token by MOVE (the call-site immediately wraps it in a
    /// `SecretString`, which keeps the protection). The wrapper's now-empty string is scrubbed on drop.
    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

/// The op vocabulary on `ctl.sock`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CtlRequest {
    /// Run the daemon self-check / health report.
    Doctor,
    /// Ingest a provider credential: hand the daemon a raw token to encrypt + store in the vault.
    /// `ctl`-only (human operator → uid-400 vault); deliberately absent from `agent.sock`. The
    /// token is redacted in `Debug` ([`RedactedToken`]) and never echoed back — the reply is a
    /// secret-free `ConnectOutcome`. This is the linchpin of the "daemon is the only keyholder"
    /// posture.
    Connect {
        provider: String,
        #[serde(default)]
        account_label: Option<String>,
        token: RedactedToken,
    },
    /// List the connected providers (the operator view; a non-mutating read).
    ListCredentials,
    /// Every stored authority profile (name, canonical body, rule count, updated_at). Read-only,
    /// and `ctl`-ONLY — deliberately absent from `agent.sock`, because a stored body is the
    /// operator's own authority draft. There is no companion WRITE op by design: a profile is
    /// stored only as part of [`CtlRequest::CommitSentences`], so every stored body carries the
    /// same staged-and-attested evidence a live corpus does.
    ListPresets,
    // ---- Keyholder ops: the broker operations cermet-app drives over ctl.sock instead of
    // opening its own vault. Each maps 1:1 onto a `BrokerHandle` method and replies with the uniform
    // `{"kind":"ok","view":..}` / `{"kind":"error",..}` envelope.
    /// Verify the audit hash-chain integrity (also available on `agent.sock`).
    VerifyAudit,
    /// Read a stored artifact span by handle — the operator/console read path for a shell run's full
    /// output. Read-only, no authority, no secret. The daemon collapses every failure class
    /// (unknown handle, tampered blob, missing content) to ONE opaque `not_found`, matching the
    /// `agent.sock` `Artifact` posture — so this surface reveals no more about handle existence.
    ReadArtifact {
        handle: String,
        #[serde(default)]
        range: Option<crate::wire::ArtifactRange>,
        /// A `$.seg(.seg)*` capture-pointer into the retained response body parsed as JSON, mutually
        /// exclusive with `range`. Additive — an older caller omits it.
        #[serde(default)]
        path: Option<String>,
    },
    /// Forward an agent's capability request, attributed to `session` (also on `agent.sock`).
    Request {
        session: String,
        request_json: String,
        /// Explicit request-time retry lineage — the safe effect handle a prior attempt reported,
        /// NEVER an idempotency key and never execute-time fill. It rides BESIDE `request_json`,
        /// exactly as `retry_effect` rides beside the resource on `agent.sock`: it is request
        /// METADATA, so it can never enter the frozen resource. The daemon authenticates the
        /// lineage (ownership, verb, frozen fields, deadline) and denies if anything fails — this
        /// side validates nothing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_effect: Option<String>,
    },
    /// Operator-initiated execute (no agent session/principal) — the `/cli/*` escape hatch.
    ///
    /// Keyed by `request_id`, the ONE public id. The operator-internal `grant_id` is
    /// resolved daemon-side through the kernel's 1:1 request→grant mapping and is no longer an
    /// input on any surface.
    ExecuteOperator { request_id: String },
    /// The cross-session history view (operator overview).
    History,
    /// The verb catalog joined against the live sentence corpus — the SAME
    /// `CatalogListing` the agent wire's `Catalog` op serves, from the same daemon-side join
    /// (`admitted_by`/`denied_by` via `SentenceEvaluator::covers`). It exists on ctl because
    /// `cermet catalog` is the operator/CLI-only agent's capability-discovery surface, and a CLI
    /// that cannot reach `agent.sock` was otherwise left probing verbs one deny at a time. Schema
    /// only: no step bodies, no values, no credential.
    Catalog,
    /// Operator-only verified execution evidence for one request. Deliberately absent from
    /// `wire.rs`, so no agent/MCP caller can reach it.
    Evidence { request_id: String },
    /// The operator's cross-session relay hop log — every chain-verified relay event,
    /// newest first (`cermet log --hops`). Read-only, operator-only: it renders the daemon's own
    /// audit rows, so it is deliberately absent from `wire.rs` like `Evidence`.
    RelayHops,
    // ---- UNIFIED CUSTODY: the ONE sentence-authority ceremony surface on EVERY OS. `ctl`-ONLY (a
    // human operator) — deliberately ABSENT from the agent wire vocabulary (`wire.rs`).
    // `StageSentences`/`CommitSentences` install authority (the daemon-owned atomic record), so they
    // are structurally unreachable from `agent.sock`. They are NOT, however, protected from a
    // same-approver-uid process: kernel peercred distinguishes daemon / approver / other, never
    // human-from-agent WITHIN the approver uid, so in the single-user topology (agent uid == approver
    // uid) any process at that uid can connect to ctl and frame these directly. The boundary this
    // surface claims is daemon-vs-approver credential/filesystem custody, NOT an agent-vs-ctl authority
    // gate. ----
    /// Read-only sentence snapshot over the daemon-owned authority record: `Absent` / `Served` /
    /// `Unserved` / `Corrupt`. Every readable present record carries its opaque exact-record digest;
    /// well-formed records add canonical text, authority digest, and occurrence id, while `Corrupt`
    /// adds only a content-free reason and NEVER raw corrupt rule bytes. Strictly
    /// observational — never repairs authority.
    SentenceSnapshot,
    /// Read the typed sentence snapshot and effective owner lockdown latch together. Observational;
    /// neither record is repaired or mutated.
    SentenceAuthorityStatus,
    /// Parse, pin, semantically validate, canonically print, and digest candidate rule text without
    /// staging or mutating authority.
    PrepareSentences { candidate_text: String },
    /// Stage a candidate corpus (round one of the two-round ceremony). The daemon canonicalizes +
    /// validates `candidate_text` against the still-live prior generation, persists a durable staged
    /// record keyed by a unique random nonce, and returns `{ canonical_text,
    /// canonical_digest, staging_token, occurrence_id }`. The occurrence is deterministically bound to
    /// that nonce so a lost response can retry only the exact commit without another presence ceremony.
    /// NOTHING is made authoritative — the prior generation stays live until `CommitSentences`. The
    /// human confirms the daemon's canonical echo, binding presence to the exact bytes that will become
    /// authoritative. Human-only ceremony RPC; every OS.
    StageSentences { candidate_text: String },
    /// Commit a previously-staged corpus (round two). The daemon flips the generation atomically iff
    /// the live generation is still the one the token was staged against (a stale/unknown/superseded
    /// token writes NOTHING and returns a typed refusal), then emits the custody audit STRICTLY AFTER
    /// the commit (idempotent, occurrence-keyed). A crash between stage and commit leaves the prior
    /// generation live; staged records are inert and TTL-swept. Human-only ceremony RPC; every OS.
    ///
    /// `preset` names the key the committed body is ALSO stored under. It rides here rather than on
    /// a write op of its own so a stored profile can only ever be a body that went through this
    /// exact ceremony — there is no second path by which one could appear.
    CommitSentences {
        staging_token: String,
        #[serde(default)]
        preset: Option<String>,
    },
    // ---- MCP-repoint quiesce barrier: the daemon-held transaction `cermet mcp
    // install` uses to prove no NEW execution can begin under the old MCP server and classify whether
    // an in-flight/terminal lease may leave an agent-side child running. `ctl`-ONLY (a human operator)
    // — deliberately ABSENT from `wire.rs`: these gate execution custody, so an agent must never reach
    // them. A same-uid agent framing one directly is denied by the ctl uid gate. ----
    /// Enter the quiesce barrier: block every NEW approved→executing claim (requests/status and
    /// already-open lease finalization continue), durably record `sha256(token)` + a hard-bounded
    /// expiry, and reply the one opaque token + this daemon instance's id. `ttl_secs` is clamped to the
    /// daemon's `[MIN,MAX]` barrier window.
    BeginMcpRepoint { ttl_secs: i64 },
    /// Classify custody under the barrier (holder-only): `quiescent` / `active` / `orphan_ambiguous`
    /// / `integrity`, read through the grant HMAC path plus verified terminal audit evidence.
    McpRepointStatus { token: String },
    /// End the barrier (holder-only) through the ordered durable release
    /// (validate → unlink → parent fsync → clear).
    EndMcpRepoint { token: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{read_frame, write_frame};
    use std::io::Cursor;

    /// The session-scoped ctl `execute` had ZERO producers — the operator path is
    /// `ExecuteOperator` (keyed by request_id) and the agent path lives in `wire.rs`. A
    /// grant-id-keyed op on ctl was a second handle for the same thing, and it is gone.
    #[test]
    fn the_grant_keyed_ctl_execute_no_longer_decodes() {
        assert!(serde_json::from_str::<CtlRequest>(
            r#"{"op":"execute","grant_id":"grant_1","session":"sess_1"}"#
        )
        .is_err());
    }

    #[test]
    fn parallel_authority_operation_tags_no_longer_decode() {
        for frame in [
            r#"{"op":"pending"}"#,
            r#"{"op":"approve","grant_id":"grant_1"}"#,
            r#"{"op":"deny","grant_id":"grant_1","reason":"no"}"#,
            r#"{"op":"approve_and_allow","grant_id":"grant_1"}"#,
            r#"{"op":"deny_and_deny","grant_id":"grant_1","reason":"no"}"#,
            r#"{"op":"validate_policy","yaml":"{}"}"#,
            r#"{"op":"apply_policy","yaml":"{}"}"#,
            r#"{"op":"profiles"}"#,
            r#"{"op":"profile_show","name":"default"}"#,
            r#"{"op":"activate_profile","name":"default"}"#,
            r#"{"op":"arm_test_mode","duration_secs":60,"all_sessions":true,"session_id":null}"#,
            r#"{"op":"disarm_test_mode"}"#,
            r#"{"op":"test_mode_status"}"#,
        ] {
            assert!(
                serde_json::from_str::<CtlRequest>(frame).is_err(),
                "retired ctl authority frame still decoded: {frame}"
            );
        }
    }

    #[test]
    fn ctl_vocabulary_roundtrips_and_is_disjoint_from_agent() {
        let reqs = vec![
            CtlRequest::Doctor,
            CtlRequest::Connect {
                provider: "vercel".into(),
                account_label: Some("acme".into()),
                token: RedactedToken("tok_xxx".into()),
            },
            CtlRequest::ListCredentials,
            CtlRequest::ListPresets,
            CtlRequest::VerifyAudit,
            CtlRequest::ReadArtifact {
                handle: "art_1".into(),
                range: None,
                path: None,
            },
            CtlRequest::ReadArtifact {
                handle: "art_1".into(),
                range: Some(crate::wire::ArtifactRange {
                    unit: "lines".into(),
                    start: 1,
                    end: Some(50),
                }),
                path: None,
            },
            CtlRequest::ReadArtifact {
                handle: "art_1".into(),
                range: None,
                path: Some("$.link".into()),
            },
            CtlRequest::Request {
                session: "sess_1".into(),
                request_json: "{}".into(),
                retry_effect: None,
            },
            CtlRequest::Request {
                session: "sess_1".into(),
                request_json: "{}".into(),
                retry_effect: Some("effect_0123456789abcdef0123456789abcdef".into()),
            },
            CtlRequest::ExecuteOperator {
                request_id: "req_0123456789abcdef".into(),
            },
            CtlRequest::History,
            CtlRequest::Catalog,
            CtlRequest::Evidence {
                request_id: "req_0123456789abcdef".into(),
            },
            CtlRequest::RelayHops,
            CtlRequest::SentenceSnapshot,
            CtlRequest::SentenceAuthorityStatus,
            CtlRequest::PrepareSentences {
                candidate_text: "allow stripe.support\n".into(),
            },
            CtlRequest::StageSentences {
                candidate_text: "allow stripe.refund where amount <= 5000\n".into(),
            },
            CtlRequest::CommitSentences {
                staging_token: "ab".repeat(32),
                preset: None,
            },
            CtlRequest::CommitSentences {
                staging_token: "ab".repeat(32),
                preset: Some("designer".into()),
            },
            CtlRequest::BeginMcpRepoint { ttl_secs: 120 },
            CtlRequest::McpRepointStatus {
                token: "tok_repoint".into(),
            },
            CtlRequest::EndMcpRepoint {
                token: "tok_repoint".into(),
            },
        ];
        for req in &reqs {
            let mut buf = Vec::new();
            write_frame(&mut buf, req).unwrap();
            let back: CtlRequest = read_frame(&mut Cursor::new(buf)).unwrap();
            assert_eq!(&back, req, "ctl request must round-trip identically");
        }

        // Human-only / ingestion ops must NOT decode as an AgentRequest. `Connect` (ingestion) and
        // `ExecuteOperator` (the operator escape hatch — execute with no agent session/principal)
        // have no agent counterpart by design. (`ListCredentials`/`Request`/`VerifyAudit` are
        // intentionally SHARED ops — the channel, not the wire form, is the gate.)
        for op in [
            CtlRequest::Connect {
                provider: "vercel".into(),
                account_label: None,
                token: RedactedToken("t".into()),
            },
            CtlRequest::ExecuteOperator {
                request_id: "req_0123456789abcdef".into(),
            },
            CtlRequest::Evidence {
                request_id: "req_0123456789abcdef".into(),
            },
            CtlRequest::RelayHops,
            // Stored authority profiles are the operator's own drafts; an agent has no counterpart.
            CtlRequest::ListPresets,
            // UNIFIED CUSTODY: the sentence-ceremony ctl ops observe/install authority and are
            // ctl-ONLY — none may decode as an AgentRequest.
            CtlRequest::SentenceSnapshot,
            CtlRequest::SentenceAuthorityStatus,
            CtlRequest::PrepareSentences {
                candidate_text: "allow stripe.support\n".into(),
            },
            CtlRequest::StageSentences {
                candidate_text: "allow stripe.refund where amount <= 5000\n".into(),
            },
            CtlRequest::CommitSentences {
                staging_token: "cd".repeat(32),
                preset: None,
            },
            // MCP-repoint quiesce barrier: begin/status/end gate execution custody — ctl-ONLY,
            // so none may decode as an AgentRequest (no agent counterpart on `agent.sock`).
            CtlRequest::BeginMcpRepoint { ttl_secs: 120 },
            CtlRequest::McpRepointStatus {
                token: "tok_repoint".into(),
            },
            CtlRequest::EndMcpRepoint {
                token: "tok_repoint".into(),
            },
        ] {
            let mut buf = Vec::new();
            write_frame(&mut buf, &op).unwrap();
            let as_agent: Result<crate::wire::AgentRequest, _> = read_frame(&mut Cursor::new(buf));
            assert!(
                as_agent.is_err(),
                "operator op {op:?} must not decode as an AgentRequest (human-only invariant)"
            );
        }
    }

    #[test]
    fn evidence_is_absent_from_the_agent_wire_vocabulary() {
        assert!(!crate::wire::accepted_agent_request_operation_tags().contains(&"evidence"));
        assert!(serde_json::from_value::<crate::wire::AgentRequest>(
            serde_json::json!({"op":"evidence","request_id":"req_0123456789abcdef"})
        )
        .is_err());
    }

    // The sentence-ceremony ops are structurally unreachable from the agent wire.
    // Their op tags are absent from the accepted-agent-op closed set AND fail to decode as
    // an AgentRequest by tag — so a repin can never be framed on agent.sock.
    #[test]
    fn sentence_ceremony_ops_are_absent_from_the_agent_wire_vocabulary() {
        for tag in [
            "sentence_snapshot",
            "sentence_authority_status",
            "prepare_sentences",
            "stage_sentences",
            "commit_sentences",
        ] {
            assert!(
                !crate::wire::accepted_agent_request_operation_tags().contains(&tag),
                "sentence-ceremony op `{tag}` must NOT be an accepted agent op tag"
            );
            let as_agent = serde_json::from_value::<crate::wire::AgentRequest>(
                serde_json::json!({ "op": tag }),
            );
            assert!(
                as_agent.is_err(),
                "agent-framed `{tag}` must be rejected (no agent counterpart)"
            );
        }
    }

    /// Stored authority profiles are operator drafts, so the read op is ctl-only: its tag is absent
    /// from the accepted-agent-op closed set AND fails to decode as an AgentRequest.
    #[test]
    fn the_preset_read_op_is_absent_from_the_agent_wire_vocabulary() {
        assert!(!crate::wire::accepted_agent_request_operation_tags().contains(&"list_presets"));
        assert!(serde_json::from_value::<crate::wire::AgentRequest>(
            serde_json::json!({ "op": "list_presets" })
        )
        .is_err());
    }

    // MCP-repoint quiesce barrier: begin/status/end gate execution custody and are ctl-ONLY.
    // Their op tags are absent from the accepted-agent-op closed set AND fail to decode as an
    // AgentRequest by tag — so a repoint barrier can never be framed on `agent.sock`.
    #[test]
    fn mcp_repoint_ops_are_absent_from_the_agent_wire_vocabulary() {
        for tag in ["begin_mcp_repoint", "mcp_repoint_status", "end_mcp_repoint"] {
            assert!(
                !crate::wire::accepted_agent_request_operation_tags().contains(&tag),
                "mcp-repoint op `{tag}` must NOT be an accepted agent op tag"
            );
            let as_agent = serde_json::from_value::<crate::wire::AgentRequest>(
                serde_json::json!({ "op": tag }),
            );
            assert!(
                as_agent.is_err(),
                "agent-framed `{tag}` must be rejected (no agent counterpart)"
            );
        }
    }

    #[test]
    fn connect_token_is_redacted_in_debug_but_carried_on_the_wire() {
        const RAW: &str = "super_secret_token_value";
        let req = CtlRequest::Connect {
            provider: "vercel".into(),
            account_label: None,
            token: RedactedToken(RAW.into()),
        };
        // A stray `{:?}` (log/panic) must NOT spill the token.
        let dbg = format!("{req:?}");
        assert!(!dbg.contains(RAW), "Debug leaked the raw token: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "Debug should show the redaction marker: {dbg}"
        );

        // But the WIRE form must carry it — the daemon needs the bytes to populate the vault.
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).unwrap();
        let body = String::from_utf8(buf[4..].to_vec()).unwrap(); // skip the 4-byte length prefix
        assert!(
            body.contains(RAW),
            "the wire MUST carry the token to the daemon: {body}"
        );
        // …and it round-trips identically (transparent serde).
        let back: CtlRequest = read_frame(&mut Cursor::new(buf)).unwrap();
        assert_eq!(back, req);
    }
}
