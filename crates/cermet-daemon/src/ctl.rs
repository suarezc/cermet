//! The `ctl.sock` operator control plane, gated by `peer.uid == approver_uid`
//! ([`ctl_authorized`]). It carries credential custody, sentence custody, observability, and direct
//! operator request/execute operations while cermetd remains the sole keyholder.
//!
//! ## Security model
//! Two jobs: key custody (master key + vault live in the daemon uid; a different uid gets EACCES) and
//! the uid gate ([`ctl_authorized`] — only the operator uid may drive ctl). The distinct agent uid is
//! denied by both this gate and the disjoint socket group.
//!
//! The agent EXECUTE path is **principal-bound, not session-bound**: `Execute{request_id}`
//! authorizes by the peercred uid (`broker::execute_request_for_principal`) and the per-connection
//! session is **audit-only** — request and execute deliberately land on different minted sessions
//! (the MCP bridge re-`Hello`s after a session expires, and a later conversation can execute a
//! `request_id` minted in an earlier one), so a session bind would break the flow. `request_id` is a same-uid
//! BEARER handle: any same-uid process that learns it can redeem the owning principal's single-use
//! grant. Single-use isolation across agents is therefore the **kernel uid boundary**, not a
//! per-connection session bind; it is real only once the agent runs as a distinct uid.
//! Proofs: `tests/ctl_socket.rs` + the priv harness (`cermet-ipc/tests/priv_uid_harness.rs`).

use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use cermet_broker_actor::{BrokerHandle, Reply};
use cermet_ipc::codec::{self, write_response_frame, MAX_RESPONSE_FRAME};
use cermet_ipc::ctl::{CtlRequest, LockdownSnapshot, SentenceAuthorityStatus, SentenceSnapshot};
use cermet_ipc::peer;
use serde_json::{json, Value};

use crate::doctor;
use crate::sentence_record::{
    AuditEmitted, CommitOutcome, CustodyAuditSink, SentenceRecordAdmin, Staged,
};
use crate::serve::{accept_loop, ConnHandler, DeadlineWriter, ServeConfig, ServeError};

/// Bind `ctl.sock` in `runtime_dir` (mode `0660`) and return the bound listener. Same-uid: no group.
pub fn bind_ctl_socket(
    runtime_dir: &Path,
) -> Result<(std::os::unix::net::UnixListener, PathBuf), ServeError> {
    bind_ctl_socket_in_group(runtime_dir, None)
}

/// Bind `ctl.sock` (mode `0660`). The daemon does NOT chgrp it: its `cermet-approvers`
/// group owner is INHERITED from the setgid runtime dir, so `0660 + inherited group` is the cross-uid
/// ACL (owner = the daemon uid, group = approvers, never world). `approvers_gid` is now a no-op,
/// retained only for the call-site signature.
pub fn bind_ctl_socket_in_group(
    runtime_dir: &Path,
    approvers_gid: Option<u32>,
) -> Result<(std::os::unix::net::UnixListener, PathBuf), ServeError> {
    crate::serve::bind_socket_in_group(runtime_dir, "ctl.sock", 0o660, approvers_gid)
}

/// The operator gate: the kernel-attested peer uid must equal the configured operator uid
/// AND must not be the uid cermetd itself runs as. Post-flip the daemon runs as a service uid the
/// human never logs in as, so only the configured operator may drive ctl, never the daemon's own
/// service account.
///
/// Defensive collapse guard: if `approver_uid == daemon_uid` (a misconfig, or a pre-flip same-uid
/// deploy where the boundary is moot) the gate denies EVERYONE. Fail closed — we never let an
/// approver==daemon collapse silently re-enable the service account to drive its own ctl plane.
pub fn ctl_authorized(peer_uid: u32, approver_uid: u32, daemon_uid: u32) -> bool {
    if approver_uid == daemon_uid {
        return false;
    }
    peer_uid == approver_uid && peer_uid != daemon_uid
}

/// Handle ONE accepted `ctl.sock` connection.
#[allow(clippy::too_many_arguments)]
pub fn handle_ctl_connection(
    mut stream: StdUnixStream,
    broker: &BrokerHandle,
    rt: &tokio::runtime::Handle,
    approver_uid: u32,
    // The distinct agent uid — forwarded to doctor so the ctl report resolves the
    // agent-plane gate + agent-uid collapse checks the same way startup does.
    agent_uid: u32,
    daemon_uid: u32,
    home: &Path,
    runtime_dir: &Path,
    // Where agent.sock lives (the separate cermet-agents dir in service mode, == runtime_dir in dev) —
    // forwarded to doctor so `cermetctl doctor` checks the agent.sock mode/group the same way startup
    // does.
    agent_runtime_dir: &Path,
    timeouts: crate::serve::ServeTimeouts,
    // The cross-uid approvers/agents gids + the service-mode refuse
    // tier, forwarded to doctor so the `cermetctl doctor` report matches the startup self-check.
    approvers_gid: Option<u32>,
    agents_gid: Option<u32>,
    service_mode: bool,
    // CUSTODY-LADDER: the declared vault-key custody rung, forwarded to doctor so the ctl report
    // answers "which rung is this box on" from the daemon that is on it.
    custody_profile: Option<cermet_ipc::custody::CustodyProfile>,
    sentence_rules_configured: bool,
    // The daemon-owned sentence RECORD admin (snapshot + staged stage/commit + adopt), installed
    // on every OS.
    record_admin: &Arc<dyn SentenceRecordAdmin>,
    lockdown_source: &Arc<dyn cermet_core::LockdownSource>,
) {
    // Write timeouts are managed per-response by DeadlineWriter (below); only the read deadline is set here.
    if stream.set_read_timeout(Some(timeouts.idle)).is_err() {
        return;
    }

    let peer = match peer::peer_cred(stream.as_raw_fd()) {
        Ok(p) => p,
        Err(_) => return,
    };
    if !ctl_authorized(peer.uid, approver_uid, daemon_uid) {
        return;
    }

    loop {
        let req: CtlRequest = match codec::read_frame(&mut stream) {
            Ok(r) => r,
            Err(_) => return,
        };
        // Each response is written under a fresh ABSOLUTE budget, reusing the
        // agent-path DeadlineWriter. The budget starts AFTER the broker/store work so a slow
        // enroll/persist can never consume it and time out the one-time secret response after the
        // principal has already been committed.
        let written = match req {
            CtlRequest::Doctor => {
                // Mirror main.rs's gate resolution so the ctl doctor report matches
                // the startup self-check — agent.sock admits the distinct agent uid (service mode),
                // collapsing onto the daemon's own uid in dev/embedded (agent == approver == daemon).
                let operator_uid = if service_mode {
                    Some(agent_uid)
                } else {
                    Some(daemon_uid)
                };
                let report = doctor::run_with_sentence_authority(
                    home,
                    runtime_dir,
                    agent_runtime_dir,
                    daemon_uid,
                    approver_uid,
                    agent_uid,
                    operator_uid,
                    approvers_gid,
                    agents_gid,
                    service_mode,
                    custody_profile,
                    sentence_rules_configured,
                    // The report answers THIS caller — the git-plane row says whether
                    // their own uid would be admitted, which is the question `cermet check` asks.
                    Some(peer.uid),
                );
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                match serde_json::to_value(&report) {
                    Ok(Value::Object(mut map)) => {
                        map.insert("kind".to_string(), Value::String("doctor".to_string()));
                        write_ctl_frame(&mut out, Value::Object(map))
                    }
                    _ => write_ctl_error(&mut out, "internal error"),
                }
            }
            // Credential ingestion. The raw token enters the daemon HERE and
            // goes straight into the vault — wrapped in a SecretString at the boundary, never held
            // beyond the call, and never echoed back (the reply is a secret-free ConnectOutcome).
            // This is what lets the daemon be the only keyholder: cermet-app forwards `connect` here instead of
            // opening its own vault.
            CtlRequest::Connect {
                provider,
                account_label,
                token,
            } => {
                let reply = rt.block_on(broker.connect(
                    provider,
                    secrecy::SecretString::new(token.into_inner()),
                    account_label,
                ));
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                // The reply is a secret-free ConnectOutcome. The raw token entered here, went into the
                // vault, and never travels back out.
                write_reply_view(&mut out, reply)
            }
            CtlRequest::ListCredentials => {
                let reply = rt.block_on(broker.list_credentials());
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
            // Stored authority profiles. A READ only: profiles are written exclusively by the
            // commit arm below, so this surface can never introduce a body the ceremony did not.
            CtlRequest::ListPresets => {
                let reply = rt.block_on(broker.list_presets());
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
            CtlRequest::VerifyAudit => {
                let reply = rt.block_on(broker.verify_audit());
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
            // Operator/console artifact read (S5). Fail closed with NO existence oracle: collapse
            // EVERY read failure (unknown handle, tampered blob, missing content, bad range) to one
            // opaque `not_found` — the SAME posture the agent surface takes (`serve.rs` →
            // `ARTIFACT_UNAVAILABLE`), so this human-facing surface reveals no more about which
            // handles exist. On success the span rides the uniform ok/view envelope.
            CtlRequest::ReadArtifact {
                handle,
                range,
                path,
            } => {
                // `range` XOR `path` (both set is fail-closed); the error joins the opaque failure
                // class below, so this surface still reveals nothing about which handles exist.
                let reply = match cermet_core::ArtifactAddress::from_wire(range, path) {
                    Ok(addr) => rt.block_on(broker.read_artifact(
                        handle,
                        addr,
                        cermet_core::ArtifactReadSurface::Ctl,
                    )),
                    Err(e) => Err(e),
                };
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                match reply {
                    Ok(_) => write_reply_view(&mut out, reply),
                    Err(e) => {
                        crate::log::emit(format!("cermetd: ctl artifact read failed: {e}"));
                        write_ctl_frame(
                            &mut out,
                            json!({
                                "kind": "error",
                                "code": "not_found",
                                "reason": "artifact unavailable",
                            }),
                        )
                    }
                }
            }
            CtlRequest::Request {
                session,
                request_json,
                retry_effect,
            } => {
                // A lazily-created session row is owned by the ctl peer (the operator).
                // A request naming a prior effect takes the retry entry, whose lineage
                // authentication (ownership, verb, byte-identical frozen fields, deadline, budget
                // adoption) is the daemon's own and unchanged — this is a route, not a check.
                let reply = rt.block_on(broker.request(
                    session,
                    request_json,
                    Some(peer.uid as i64),
                    retry_effect,
                ));
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
            CtlRequest::ExecuteOperator { request_id } => {
                let reply = rt.block_on(broker.execute_operator(request_id));
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
            CtlRequest::History => {
                let reply = rt.block_on(broker.history());
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
            // The ONE catalog join, served to a second caller. This is literally the same
            // `broker.catalog_listing()` the agent wire's `catalog` op calls (see
            // `serve/connection.rs`) — the sentence×verb join, the admitting/denying sentence text,
            // and the discoverability bit are all decided HERE, once, and both surfaces only read
            // them. No re-decision client-side, on either socket.
            CtlRequest::Catalog => {
                let reply = rt.block_on(broker.catalog_listing());
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
            CtlRequest::RelayHops => {
                let reply = rt.block_on(broker.relay_hops());
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
            CtlRequest::Evidence { request_id } => {
                let reply = rt.block_on(broker.evidence(request_id));
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
            // Read-only sentence snapshot over the daemon-owned record. The whole
            // connection is already fenced to the approver by `ctl_authorized`; a distinct-uid agent
            // never reaches here.
            CtlRequest::SentenceSnapshot => {
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, snapshot_reply(record_admin.snapshot()))
            }
            CtlRequest::SentenceAuthorityStatus => {
                let status = record_admin
                    .snapshot()
                    .map(|sentence| SentenceAuthorityStatus {
                        sentence,
                        lockdown: if lockdown_source.is_engaged() {
                            LockdownSnapshot::Engaged
                        } else {
                            LockdownSnapshot::Clear
                        },
                    });
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, authority_status_reply(status))
            }
            CtlRequest::PrepareSentences { candidate_text } => {
                let prepared = rt.block_on(broker.prepare_sentence_corpus(candidate_text));
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, prepared)
            }
            // Stage a candidate corpus (round one). The daemon canonicalizes +
            // validates against the still-live prior generation and returns its canonical echo + token;
            // NOTHING is made authoritative. Human-only; the distinct-uid topology delivers human-only
            // approval — the CLI-side presence ceremony is operator-path integrity, not an agent gate.
            CtlRequest::StageSentences { candidate_text } => {
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                // The daemon is the enforcement point — run the Broker's authority-subset
                // validation (secret-class rejection + subset checks) BEFORE staging, so a direct ctl
                // client can never stage a disallowed authority record. The CLI is never trusted to
                // pre-filter. (This is the single validation seam any later semantic check would join.)
                let staged = rt
                    .block_on(broker.prepare_sentence_corpus(candidate_text))
                    .and_then(|prepared| {
                        let prepared: cermet_core::sentence::PreparedSentenceCorpus =
                            serde_json::from_str(&prepared).map_err(|_| {
                                cermet_core::Error::Provider(
                                    "sentence preparation returned a malformed typed view".into(),
                                )
                            })?;
                        let staged = record_admin.stage(&prepared.canonical_text)?;
                        if staged.canonical_text != prepared.canonical_text
                            || staged.canonical_digest != prepared.canonical_digest
                        {
                            return Err(cermet_core::Error::Provider(
                                "sentence staging diverged from daemon preparation".into(),
                            ));
                        }
                        Ok(staged)
                    });
                write_reply_view(&mut out, stage_reply(staged))
            }
            // Commit a staged corpus (round two). The daemon flips the generation
            // atomically iff the token is still live (stale/superseded ⇒ typed refusal), then emits the
            // custody audit STRICTLY AFTER the commit via the broker (idempotent, occurrence-keyed).
            CtlRequest::CommitSentences {
                staging_token,
                preset,
            } => {
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                let sink = BrokerAuditSink { broker, rt };
                // PRE-FLIP GATE: re-validate the EXACT staged bytes through the broker's
                // authority-subset validation (secret-class rejection + subset checks) BEFORE the flip.
                // A validation failure refuses the commit outright — the generation is NEVER flipped.
                // The staged text is bytes-bound to the token, so what we validate is exactly what
                // commits; this runs OUTSIDE the store lock (no cross-thread wait under it).
                let gate: cermet_core::Result<Option<String>> = record_admin
                    .peek_staged_text(&staging_token)
                    .and_then(|staged_text| {
                        if let Some(text) = &staged_text {
                            let prepared =
                                rt.block_on(broker.prepare_sentence_corpus(text.clone()))?;
                            let prepared: cermet_core::sentence::PreparedSentenceCorpus =
                                serde_json::from_str(&prepared).map_err(|_| {
                                    cermet_core::Error::Provider(
                                        "sentence preparation returned a malformed typed view"
                                            .into(),
                                    )
                                })?;
                            if prepared.canonical_text != *text {
                                return Err(cermet_core::Error::Denied(
                                    "staged sentence bytes are no longer canonical".into(),
                                ));
                            }
                        }
                        Ok(staged_text)
                    });
                // A preset name is validated BEFORE the flip: storing is part of what the
                // operator accepted, so a name the daemon would refuse must not first change live
                // authority and only then fail.
                let gate = gate.and_then(|staged_text| match &preset {
                    Some(name) => cermet_core::presets::validate_name(name).map(|()| staged_text),
                    None => Ok(staged_text),
                });
                match gate {
                    // Hard refusal (peek error, validation refusal, or a bad preset name): no
                    // commit call ⇒ no flip.
                    Err(e) => write_reply_view(&mut out, Err(e)),
                    Ok(staged_text) => {
                        let outcome = record_admin.commit_attributed(
                            &staging_token,
                            peer.uid,
                            "presence",
                            &sink,
                        );
                        // Store the profile only AFTER the body is live, and only from here: this
                        // is the single write path into the presets table. The store is an upsert
                        // of bytes already validated above, so the failure left to report is a
                        // store fault — and it is reported rather than swallowed, because the
                        // operator asked for both halves.
                        let outcome = match (&outcome, &preset, &staged_text) {
                            (Ok(_), Some(name), Some(text)) => rt
                                .block_on(broker.store_preset(name.clone(), text.clone()))
                                .map_err(|e| {
                                    cermet_core::Error::Provider(format!(
                                        "authority committed and is live, but storing it as a \
                                         preset failed: {e}"
                                    ))
                                })
                                .and(outcome),
                            _ => outcome,
                        };
                        write_reply_view(&mut out, commit_reply(outcome))
                    }
                }
            }
            // MCP-repoint quiesce barrier: the daemon-held transaction. Begin/End
            // are serialized with every approved→executing claim on the single broker thread; Status
            // classifies custody. ctl-ONLY — an agent can never frame these (no `agent.sock` form).
            CtlRequest::BeginMcpRepoint { ttl_secs } => {
                let reply = rt.block_on(broker.begin_mcp_repoint(ttl_secs));
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
            CtlRequest::McpRepointStatus { token } => {
                let reply = rt.block_on(broker.mcp_repoint_status(token));
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
            CtlRequest::EndMcpRepoint { token } => {
                let reply = rt.block_on(broker.end_mcp_repoint(token));
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                write_reply_view(&mut out, reply)
            }
        };
        if written.is_err() {
            return;
        }
    }
}

/// The fail-closed error envelope for a NON-typed failure (a static message: an unsupported op, an
/// internal serialization fault). Carries `code:"internal"` — coarse and non-actionable by design.
/// Typed broker errors go through [`write_ctl_error_coded`], which preserves the variant.
fn write_ctl_error<W: Write>(w: &mut W, reason: &str) -> codec::Result<()> {
    write_ctl_frame(
        w,
        json!({ "kind": "error", "code": "internal", "reason": reason }),
    )
}

/// Frame one ctl reply, stamped with the build that answered it.
///
/// `ctl.sock` has no hello — it is one request, one response, connect-per-call — so there is no
/// handshake seam to advertise on the way `agent.sock` does. The daemon therefore says which build
/// answered on the REPLY, and the operator CLI compares it once per process. Every ctl reply goes
/// through here so no op can quietly answer unattributed.
fn write_ctl_frame<W: Write>(w: &mut W, mut frame: Value) -> codec::Result<()> {
    if let Value::Object(map) = &mut frame {
        map.insert(
            "build".to_string(),
            Value::String(cermet_ipc::BUILD_ID.to_string()),
        );
    }
    write_response_frame(w, &frame)
}

/// Serialize a sentence snapshot into the `{"kind":"ok","view":..}` envelope's inner `Reply` string.
fn snapshot_reply(result: cermet_core::Result<SentenceSnapshot>) -> Reply {
    result.and_then(|view| {
        serde_json::to_string(&view).map_err(|e| {
            cermet_core::Error::Provider(format!("sentence snapshot encode failed: {e}"))
        })
    })
}

fn authority_status_reply(result: cermet_core::Result<SentenceAuthorityStatus>) -> Reply {
    result.and_then(|view| {
        serde_json::to_string(&view).map_err(|e| {
            cermet_core::Error::Provider(format!("sentence authority status encode failed: {e}"))
        })
    })
}

/// Serialize a `Staged` echo (round one) into the `{"kind":"ok","view":..}` envelope's inner `Reply`.
/// A parse/validation failure already surfaced as an `Err` (definite no-stage) before reaching here.
fn stage_reply(result: cermet_core::Result<Staged>) -> Reply {
    result.and_then(|view| {
        serde_json::to_string(&view)
            .map_err(|e| cermet_core::Error::Provider(format!("sentence stage encode failed: {e}")))
    })
}

/// Serialize a `CommitOutcome` (round two) into the `{"kind":"ok","view":..}` envelope's inner
/// `Reply`. A stale/superseded token already surfaced as an `Err` (definite no-commit) before here.
fn commit_reply(result: cermet_core::Result<CommitOutcome>) -> Reply {
    result.and_then(|view| {
        serde_json::to_string(&view).map_err(|e| {
            cermet_core::Error::Provider(format!("sentence commit encode failed: {e}"))
        })
    })
}

/// The daemon-side post-commit custody-audit sink: bridges the (sync) record-store commit hook to the
/// broker's authenticated audit log over the single broker thread. Occurrence-keyed idempotency lives
/// in the broker method, so a concurrent commit or boot replay never double-chains. This
/// is the commit-hook provisioning seam any later post-commit milestone would ride.
struct BrokerAuditSink<'a> {
    broker: &'a cermet_broker_actor::BrokerHandle,
    rt: &'a tokio::runtime::Handle,
}

impl CustodyAuditSink for BrokerAuditSink<'_> {
    fn record_committed(
        &self,
        canonical_digest: &str,
        rule_count: usize,
        occurrence_id: &str,
    ) -> cermet_core::Result<AuditEmitted> {
        // The broker's `record_sentence_custody_change` is idempotent + durable — an Ok reply means
        // the audit is recorded (or already present for this occurrence), so the outbox marker may be
        // cleared (Emitted). Dedup is by the per-commit occurrence_id, never the content digest.
        self.rt
            .block_on(self.broker.record_sentence_custody_change(
                canonical_digest.to_string(),
                rule_count,
                occurrence_id.to_string(),
            ))
            .map(|_| AuditEmitted::Emitted)
    }

    fn record_committed_attributed(
        &self,
        canonical_digest: &str,
        rule_count: usize,
        occurrence_id: &str,
        operator_uid: u32,
        acceptance_path: &str,
        prior_record: Option<&str>,
    ) -> cermet_core::Result<AuditEmitted> {
        self.rt
            .block_on(self.broker.record_sentence_custody_change_attributed(
                canonical_digest.to_string(),
                rule_count,
                occurrence_id.to_string(),
                operator_uid,
                acceptance_path.to_string(),
                prior_record.map(str::to_string),
            ))
            .map(|_| AuditEmitted::Emitted)
    }
}

/// Frame a typed broker error as `{"kind":"error","code":<class>,"reason":<bare payload>}` — the
/// wire contract pinned on `cermet_core::Error` itself. `code` carries the CLASS (so the
/// client rebuilds the variant and preserves the HTTP status mapping: `denied`→403 / `not_found`→404
/// / `invalid`→400 / everything else→500) and `reason` carries the payload ONLY. Framing the
/// rendered `Display` here is what doubled the class prefix on the operator's terminal.
fn write_ctl_error_coded<W: Write>(w: &mut W, e: &cermet_core::Error) -> codec::Result<()> {
    write_ctl_frame(
        w,
        json!({ "kind": "error", "code": e.wire_code(), "reason": e.wire_payload() }),
    )
}

/// Frame a broker [`Reply`] as the uniform ctl envelope: `{"kind":"ok","view": <view>}`
/// on success, or the fail-closed `{"kind":"error","code":..,"reason":..}` envelope on a broker
/// error (the `code` lets a socket-client reconstruct the `cermet_core::Error` class and keep the
/// HTTP status). The `view` is the broker actor's already-serialized core view (an array OR object),
/// embedded verbatim so a cermet-app socket-client can reconstruct the in-process `Reply` with ONE
/// decode path. A non-JSON `Ok` body (should be impossible — the actor always serializes a core
/// type) fails closed.
///
/// NOTE: like every other ctl op, this is bounded by the 4 MiB `MAX_RESPONSE_FRAME`.
/// Oversized views return a coded error before JSON parse/re-wrap so the operator gets a clean
/// failure and the daemon avoids allocating the oversized envelope. Per-view pagination or caps
/// remain the product-level fix.
fn write_reply_view<W: Write>(w: &mut W, reply: Reply) -> codec::Result<()> {
    match reply {
        Ok(view_json) => {
            if view_json_too_large_for_ok_envelope(&view_json) {
                return write_oversize_view_error(w);
            }
            match serde_json::from_str::<Value>(&view_json) {
                Ok(view) => match write_ctl_frame(w, json!({ "kind": "ok", "view": view })) {
                    Err(codec::CodecError::FrameTooLarge(_)) => write_oversize_view_error(w),
                    other => other,
                },
                Err(_) => write_ctl_error(w, "internal error"),
            }
        }
        Err(e) => write_ctl_error_coded(w, &e),
    }
}

/// The bytes the ok envelope adds around a view — including the build stamp, so the
/// oversize guard still refuses BEFORE the frame is built rather than after the codec rejects it.
const OK_VIEW_ENVELOPE_OVERHEAD: usize =
    br#"{"kind":"ok","view":,"build":""}"#.len() + cermet_ipc::BUILD_ID.len();

fn view_json_too_large_for_ok_envelope(view_json: &str) -> bool {
    view_json.len().saturating_add(OK_VIEW_ENVELOPE_OVERHEAD) > MAX_RESPONSE_FRAME as usize
}

fn write_oversize_view_error<W: Write>(w: &mut W) -> codec::Result<()> {
    write_ctl_error(
        w,
        "response too large for one frame (exceeds the 4 MiB ctl cap); narrow the query",
    )
}

/// Serve operator connections on a pre-bound `ctl.sock` listener.
#[allow(clippy::too_many_arguments)]
pub fn serve_ctl_socket(
    listener: std::os::unix::net::UnixListener,
    broker: BrokerHandle,
    approver_uid: u32,
    // The distinct agent uid, threaded so the ctl Doctor report resolves the
    // agent-plane gate + agent-uid collapse checks the same way the startup self-check does.
    agent_uid: u32,
    home: PathBuf,
    runtime_dir: PathBuf,
    // Where agent.sock lives (== runtime_dir today). Threaded so the ctl Doctor report covers the
    // agent.sock mode the same way startup does.
    agent_runtime_dir: PathBuf,
    config: ServeConfig,
    sentence_rules_configured: bool,
    // The daemon-owned sentence record admin (snapshot + staged stage/commit + adopt), installed
    // on every OS.
    record_admin: Arc<dyn SentenceRecordAdmin>,
    lockdown_source: Arc<dyn cermet_core::LockdownSource>,
) {
    let rt = tokio::runtime::Handle::current();
    let timeouts = config.timeouts;
    let approvers_gid = config.approvers_gid;
    let agents_gid = config.agents_gid;
    let service_mode = config.service_mode;
    let custody_profile = config.custody_profile;
    // The daemon's OWN uid (authoritative for the deny-all collapse check + doctor's uid_boundary
    // report) is read from the process here, never passed in — so a caller cannot spoof it to
    // defeat the `peer != daemon` half of the ctl gate.
    let daemon_uid = nix::unistd::getuid().as_raw();
    let handle: ConnHandler = Arc::new(move |stream| {
        handle_ctl_connection(
            stream,
            &broker,
            &rt,
            approver_uid,
            agent_uid,
            daemon_uid,
            &home,
            &runtime_dir,
            &agent_runtime_dir,
            timeouts,
            approvers_gid,
            agents_gid,
            service_mode,
            custody_profile,
            sentence_rules_configured,
            &record_admin,
            &lockdown_source,
        );
    });
    accept_loop(listener, config.max_conns, handle);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cermet_ipc::codec::read_response_frame;
    use std::io::Cursor;

    #[test]
    fn oversize_view_returns_a_clean_error_not_a_dropped_frame() {
        // A view larger than the 4 MiB response cap must yield a coded error envelope, NOT a
        // FrameTooLarge that drops the operator's connection mid-call.
        let big = format!("[\"{}\"]", "x".repeat(5 * 1024 * 1024));
        let mut buf = Vec::new();
        write_reply_view(&mut buf, Ok(big))
            .expect("oversize view writes an error envelope, never FrameTooLarge");
        let v: Value = read_response_frame(&mut Cursor::new(buf)).expect("decode");
        assert_eq!(v["kind"], "error", "got {v}");
        assert_eq!(v["code"], "internal");
    }

    #[test]
    fn oversize_view_is_rejected_before_json_parse() {
        // A huge malformed view must hit the size preflight before serde_json can allocate/parse the
        // envelope. Otherwise the "clean error" path still lets an oversized response spike memory.
        let huge_malformed = format!("[{}", "x".repeat(codec::MAX_RESPONSE_FRAME as usize + 1));
        let mut buf = Vec::new();
        write_reply_view(&mut buf, Ok(huge_malformed))
            .expect("oversize malformed view writes an error envelope, never FrameTooLarge");
        let v: Value = read_response_frame(&mut Cursor::new(buf)).expect("decode");
        assert_eq!(v["kind"], "error", "got {v}");
        assert!(
            v["reason"]
                .as_str()
                .unwrap_or("")
                .contains("response too large"),
            "size preflight should win before JSON parse: {v}"
        );
    }

    /// The ctl error envelope carries the CLASS in `code` and the BARE payload in
    /// `reason`. Framing `e.to_string()` would put the class on the wire a second time, textually,
    /// and the client's own `Display` would then prefix the rebuilt variant again — producing
    /// `cermet: not found: not found: req_cdd141a4690581c1 …`.
    #[test]
    fn ctl_error_envelope_carries_the_bare_payload() {
        let cases = [
            cermet_core::Error::NotFound("req_cdd141a4690581c1 has no evidence".to_string()),
            cermet_core::Error::Denied("no rule matches this request".to_string()),
            cermet_core::Error::Invalid("resource is not an object".to_string()),
            cermet_core::Error::Integrity("grant integrity failed".to_string()),
        ];
        for e in cases {
            let mut buf = Vec::new();
            write_ctl_error_coded(&mut buf, &e).expect("frame the error");
            let v: Value = read_response_frame(&mut Cursor::new(buf)).expect("decode");
            assert_eq!(v["kind"], "error");
            assert_eq!(v["code"], e.wire_code(), "the class travels as the code");
            assert_eq!(
                v["reason"],
                e.wire_payload(),
                "the wire reason is the bare payload, never the rendered Display: {v}"
            );
            // The client rebuilds the variant from the pair; the class word appears exactly once.
            let rendered =
                cermet_core::Error::from_wire(v["code"].as_str(), v["reason"].as_str().unwrap())
                    .to_string();
            assert_eq!(
                rendered,
                e.to_string(),
                "the round trip must not double the class"
            );
        }
    }

    // ctl authorization is keyed on the configured operator uid, not the daemon's own uid.
    // peer == daemon must be denied so the service account cannot drive its own control plane.
    const DAEMON_UID: u32 = 990;
    const APPROVER_UID: u32 = 501;

    #[test]
    fn ctl_authorized_accepts_the_configured_approver() {
        assert!(
            ctl_authorized(APPROVER_UID, APPROVER_UID, DAEMON_UID),
            "the configured approver, who is not the daemon, is authorized"
        );
    }

    #[test]
    fn ctl_authorized_denies_the_daemon_service_uid() {
        assert!(
            !ctl_authorized(DAEMON_UID, APPROVER_UID, DAEMON_UID),
            "the daemon/service uid must NOT be able to drive its own ctl plane"
        );
    }

    #[test]
    fn ctl_authorized_denies_an_unrelated_uid() {
        assert!(
            !ctl_authorized(4242, APPROVER_UID, DAEMON_UID),
            "an unrelated uid (neither approver nor daemon) is denied"
        );
    }

    #[test]
    fn ctl_authorized_denies_the_agent_uid_closing_self_dealing() {
        // The agent's own uid is just "not the approver" to ctl, so the gate denies
        // it — it cannot approve its own grant.
        const AGENT_UID: u32 = 402;
        assert!(
            !ctl_authorized(AGENT_UID, APPROVER_UID, DAEMON_UID),
            "the agent uid is not the approver, so it must be denied the ctl/approve path"
        );
    }

    #[test]
    fn ctl_authorized_deny_all_when_approver_collapses_onto_daemon() {
        // Defensive collapse guard: if the configured approver == the daemon uid (misconfig or a
        // pre-flip same-uid deploy), authorize NOBODY rather than silently letting the service
        // account approve itself. Fail closed.
        assert!(
            !ctl_authorized(APPROVER_UID, APPROVER_UID, APPROVER_UID),
            "approver==daemon collapses to deny-all (even for a peer matching both)"
        );
        assert!(
            !ctl_authorized(DAEMON_UID, DAEMON_UID, DAEMON_UID),
            "approver==daemon collapses to deny-all for the daemon uid too"
        );
    }
}
#[test]
fn provider_disabled_has_a_stable_ctl_code() {
    assert_eq!(
        cermet_core::Error::ProviderDisabled.wire_code(),
        "provider_disabled"
    );
}
