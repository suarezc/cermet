//! The per-connection lifecycle: peercred single-operator gate, lazily-minted session, the request
//! dispatch loop and accept loop.

use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cermet_broker_actor::BrokerHandle;
use cermet_core::Error;
use cermet_ipc::codec;
use cermet_ipc::peer;
use cermet_ipc::wire::AgentRequest;

use super::respond::{
    write_artifact, write_audit_verified, write_catalog, write_credentials, write_error,
    write_error_with_effect, write_exec_outcome, write_requested, write_session, write_status,
    write_vocabulary_request_recorded, DeadlineWriter,
};
use super::{ServeConfig, ServeTimeouts};

/// The ONE opaque execute-failure reason, byte-identical across every `Error` class (NotFound vs
/// Denied vs internal) — so an authenticated agent cannot use the error to distinguish a
/// nonexistent grant id from a real-but-foreign one. The detailed class goes to daemon
/// stderr only, never the wire.
const EXECUTE_FAILED: &str = "unable to execute";

/// Map a TYPED execute refusal (a grant that EXISTS and is owned but is off the approved
/// path) to its distinct, id-free wire reason for the handle's owner. An unknown or unowned handle
/// never produces `ExecuteRefused` — it fails first as `NotFound`/`Denied`, which stay the opaque
/// `EXECUTE_FAILED` — so this surfaces a reason ONLY to a caller that holds the request handle, and
/// the anti-oracle boundary above is preserved.
fn execute_refusal_reason(class: cermet_core::ExecuteRefusal) -> &'static str {
    use cermet_core::ExecuteRefusal::*;
    use cermet_ipc::wire;
    match class {
        AlreadyUsed => wire::EXECUTE_ALREADY_USED,
        NotReady => wire::EXECUTE_NOT_READY,
        Expired => wire::EXECUTE_EXPIRED,
        TemplateDrifted => wire::EXECUTE_TEMPLATE_DRIFTED,
    }
}

/// The fixed, id-free reason for a `status` on a request with no grant row — so a not-found can't be
/// probed to distinguish a nonexistent request_id from a real one that minted no grant.
const STATUS_UNKNOWN: &str = "no such request";

/// The fixed, id-free reason for any failed artifact read (unknown handle, missing/tampered blob) —
/// so a guessed handle cannot be probed for existence. The class is logged, never relayed.
const ARTIFACT_UNAVAILABLE: &str = "artifact unavailable";

/// derive-don't-enroll (v1): the agent principal IS the kernel-attested peer uid. Distinct from
/// the approver namespace ("operator:uid=N") so the self-approval guard never false-collides.
pub(super) fn derive_principal_id(uid: u32) -> String {
    format!("uid:{uid}")
}

/// A bounded-admission slot; released (decremented) on drop.
pub(super) struct ConnSlot {
    active: Arc<AtomicUsize>,
}

impl ConnSlot {
    pub(super) fn try_acquire(active: &Arc<AtomicUsize>, max: usize) -> Option<ConnSlot> {
        let prev = active.fetch_add(1, Ordering::AcqRel);
        if prev >= max {
            active.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(ConnSlot {
                active: active.clone(),
            })
        }
    }
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The idle window after which the handshake sweep reclaims an OPEN session (no per-scheduler timer;
/// the sweep runs opportunistically at each `Hello`).
const SESSION_IDLE_SWEEP_SECS: i64 = 24 * 60 * 60;

/// Owns the connection's OWN lazily-minted session (the CLI/no-handshake path): a connection whose
/// requests carry NO `session_id` mints one session on first use and this guard closes it on every
/// exit path. It deliberately does NOT close a Hello-minted conversation session or a caller-supplied
/// session — the guard only closes what THIS connection minted for itself, so a whole MCP conversation
/// no longer fragments one-session-per-connection and survives past any single connection's drop.
struct AutoSessionGuard<'a> {
    broker: &'a BrokerHandle,
    rt: &'a tokio::runtime::Handle,
    session_id: std::cell::RefCell<Option<String>>,
    /// The attested peer uid recorded as the minted session's owner.
    owner_uid: Option<i64>,
}

impl AutoSessionGuard<'_> {
    /// The connection's own session, minted (and opened) once on first no-session request. Returns the
    /// id, or `Err(())` if the broker refused to open it (fail closed — the caller drops the connection).
    fn ensure(&self, agent_cmd: &str, pid: Option<i64>) -> Result<String, ()> {
        if let Some(existing) = self.session_id.borrow().clone() {
            return Ok(existing);
        }
        let id = mint_session_id();
        if self
            .rt
            // A no-handshake connection self-reported nothing, so nothing is recorded. Absence is
            // the truth about it, and it is what keeps "not captured" distinguishable downstream.
            .block_on(self.broker.open_session(
                id.clone(),
                agent_cmd.to_string(),
                pid,
                self.owner_uid,
                cermet_broker_actor::SelfReported::default(),
            ))
            .is_err()
        {
            return Err(());
        }
        *self.session_id.borrow_mut() = Some(id.clone());
        Ok(id)
    }
}

impl Drop for AutoSessionGuard<'_> {
    fn drop(&mut self) {
        if let Some(sid) = self.session_id.borrow().clone() {
            let _ = self.rt.block_on(self.broker.close_session(sid));
        }
    }
}

/// Mint a fresh connection-bound session id, `sess_<hex>`.
fn mint_session_id() -> String {
    let bytes: [u8; 16] = rand::random();
    let mut s = String::with_capacity(5 + 32);
    s.push_str("sess_");
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// The agent-uid gate on `agent.sock`. agent.sock admits ONLY the resolved
/// agent-plane uid — the distinct `cermet-agent` uid in service mode, the daemon's own uid in the
/// same-uid dev case. Everyone else — any other local uid, INCLUDING the daemon's own uid and,
/// crucially, the APPROVER uid — is refused. Denying the approver here is deliberate: an
/// approver-uid compromise must not be able to request (agent plane) AND approve (ctl plane); the
/// kernel separates the two planes.
///
/// This is an exact-ONE-uid POSITIVE allowlist. `operator_uid` is a historical name for the single
/// admitted uid (now the agent uid, not the human operator); the value is `Some(agent_uid)` in
/// service mode and `Some(getuid())` in dev.
///
/// Fail closed: an UNRESOLVED admitted uid (`None`) admits NO ONE — an unconfigured gate must never
/// fall open to every local uid. `Some(op)` admits strictly `peer_uid == op`.
pub(super) fn agent_peer_admitted(operator_uid: Option<u32>, peer_uid: u32) -> bool {
    operator_uid == Some(peer_uid)
}

/// Handle ONE accepted connection to completion.
pub fn handle_connection(
    mut stream: StdUnixStream,
    broker: &BrokerHandle,
    rt: &tokio::runtime::Handle,
    agent_cmd: &str,
    operator_uid: Option<u32>,
    timeouts: ServeTimeouts,
) {
    if stream.set_read_timeout(Some(timeouts.handshake)).is_err()
        || stream.set_write_timeout(Some(timeouts.handshake)).is_err()
    {
        return;
    }

    let peer = match peer::peer_cred(stream.as_raw_fd()) {
        Ok(p) => p,
        Err(_) => return,
    };
    let _audit_pid = peer.pid;

    // The agent-uid gate: agent.sock admits ONLY the resolved agent-plane uid (the
    // distinct agent uid in service mode; the approver is denied here). Refuse and close BEFORE any
    // byte is read or written (derive-don't-enroll v1 sends no nonce), so a non-agent uid — or an
    // unconfigured gate — gets a dropped connection with no oracle and no dispatched request. The
    // detailed reason goes only to the daemon log, never the wire.
    if !agent_peer_admitted(operator_uid, peer.uid) {
        crate::log::emit(format!(
            "cermetd: refused agent.sock connection from uid {} (admits only the operator uid {:?})",
            peer.uid, operator_uid
        ));
        return;
    }

    // derive-don't-enroll (v1): the principal IS the kernel-attested peer uid; no enrollment
    // handshake. The session is now the CONVERSATION identity: a `Hello` mints a durable one the
    // agent threads across connections; a request without one falls back to a per-connection session
    // (the CLI path), minted lazily and closed by the guard.
    let principal_id = derive_principal_id(peer.uid);
    let pid = peer.pid.map(|p| p as i64);
    // The kernel-attested peer uid — recorded as the owner of any session this connection
    // mints, and threaded into every supplied-session check so a leaked `sess_*` cannot be replayed
    // by another uid.
    let peer_uid: Option<i64> = Some(peer.uid as i64);
    let auto = AutoSessionGuard {
        broker,
        rt,
        session_id: std::cell::RefCell::new(None),
        owner_uid: peer_uid,
    };
    // Keep the handshake (short) read timeout going INTO the loop so a connection that opens but
    // never sends its FIRST request is reaped fast — there is no longer a nonce read to bound it
    // (derive-don't-enroll v1). Switch to the long idle timeout only AFTER the first request lands.
    let mut first = true;
    loop {
        let req: AgentRequest = match codec::read_frame(&mut stream) {
            Ok(r) => r,
            Err(_) => return,
        };
        if first {
            let _ = stream.set_read_timeout(Some(timeouts.idle));
            first = false;
        }

        // M1 handshake: `Hello` mints the conversation's session (stamping the agent DISPLAY name),
        // opportunistically sweeps idle sessions, and returns the id. The minted session is NOT owned
        // by the connection guard — it outlives this connection so the whole conversation threads onto
        // it.
        if let AgentRequest::Hello {
            agent,
            build,
            client_name,
            client_version,
            model,
        } = &req
        {
            // Build admission: ONE published inode makes every FUTURE exec
            // generation-coherent, but a process keeps executing the inode it already mapped — an
            // MCP bridge from an older build survives reinstalls and daemon restarts. Equality with
            // THIS daemon's build is therefore required BEFORE a session is minted: refuse the
            // skewed client here, with the one action that fixes it, rather than serving it an
            // obsolete tool surface until some later frame fails inexplicably. An absent field
            // (a client predating this check) deserializes empty and is refused the same way, which
            // is what makes the refusal legible rather than a frame-parse error.
            if build != cermet_ipc::BUILD_ID {
                let reason = format!(
                    "{} (this daemon is {}; the client is {})",
                    cermet_ipc::wire::BUILD_SKEW,
                    cermet_ipc::BUILD_ID,
                    if build.is_empty() {
                        cermet_ipc::UNKNOWN_BUILD
                    } else {
                        build.as_str()
                    }
                );
                crate::log::emit(format!("cermetd: refused a Hello on {reason}"));
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                if write_error(&mut out, &reason).is_err() {
                    return;
                }
                continue;
            }
            let sid = mint_session_id();
            let opened =
                // The caller's SELF-REPORTS, stored beside the session for the
                // local receipt row and read by no authority. Whatever they contain, they are
                // de-fanged at ingestion and mapped to closed families before anything is shared.
                rt.block_on(broker.open_session(
                    sid.clone(),
                    agent.clone(),
                    pid,
                    peer_uid,
                    cermet_broker_actor::SelfReported {
                        client_name: client_name.clone(),
                        client_version: client_version.clone(),
                        model: model.clone(),
                    },
                ));
            let mut out = DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
            let written = match opened {
                Ok(_) => {
                    let _ = rt
                        .block_on(broker.sweep_idle_sessions(sid.clone(), SESSION_IDLE_SWEEP_SECS));
                    write_session(&mut out, &sid)
                }
                Err(_) => write_error(&mut out, "internal error"),
            };
            if written.is_err() {
                return;
            }
            continue;
        }

        // Resolve the session THIS request runs under. A caller-supplied `session_id` MUST reference an
        // OPEN session row (fail closed — refuse an unknown/closed id with the distinct re-init reason,
        // never silently mint). Without one, fall back to the connection's own lazily-minted session
        // (the CLI path, guard-closed).
        //
        // This resolution is a PREFLIGHT for error quality only — correctness must NOT depend
        // on it, because a concurrent Hello's idle sweep can close the session between this check and
        // the gated core action (two separate broker-actor turns). `session_supplied` threads the
        // caller-supplied-vs-daemon-minted distinction into the core call, which re-verifies the open
        // status ATOMICALLY with the mint/execute/finalize (same actor turn) and fails closed with
        // `Error::SessionExpired` on a race.
        let session_supplied = req.session_id().is_some();
        let effective_session = match req.session_id() {
            Some(sid) => match rt.block_on(broker.session_open(sid.to_string())) {
                Ok(open) if open == "true" => sid.to_string(),
                Ok(_) => {
                    let mut out =
                        DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                    if write_error(&mut out, cermet_ipc::wire::SESSION_EXPIRED).is_err() {
                        return;
                    }
                    continue;
                }
                Err(_) => {
                    let mut out =
                        DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                    if write_error(&mut out, "internal error").is_err() {
                        return;
                    }
                    continue;
                }
            },
            None => match auto.ensure(agent_cmd, pid) {
                Ok(sid) => sid,
                Err(()) => return,
            },
        };
        let session_id = effective_session;

        // Each response is written under a fresh ABSOLUTE budget: run the broker call
        // first, then bound the write so a slow reader cannot pin the slot past `response_budget`.
        let written = match req {
            AgentRequest::Hello { .. } => {
                unreachable!("Hello is handled before session resolution")
            }
            AgentRequest::ListCredentials { .. } => {
                // The AGENT projection hides product-disabled providers. `ctl.rs` keeps
                // the unfiltered operator view so a shelved credential stays revocable.
                let res = rt.block_on(broker.list_credentials_for_agent());
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                match res {
                    Ok(json) => write_credentials(&mut out, &json),
                    Err(_) => write_error(&mut out, "internal error"),
                }
            }
            AgentRequest::Request {
                provider,
                action,
                resource,
                environment,
                justification,
                model,
                retry_effect,
                session_id: _,
            } => {
                // THE agent-boundary justification gate. Every brokered
                // command carries its reasoning. That was enforced only in
                // the former bridge-only tool layer, whose comment claimed a daemon boundary that did not
                // exist — anything speaking the wire directly minted requests whose audited row read
                // `justification: null`. T1: third-party content steering a cooperative model into a
                // request the owner's receipt cannot explain. Fail closed here; the agent-side check
                // stays as the preflight half of the sanctioned client/daemon pair.
                match justification.filter(|reason| !reason.trim().is_empty()) {
                    Some(justification) => {
                        let request_json = serde_json::json!({
                            "provider": provider,
                            "action": action,
                            "resource": resource,
                            "environment": environment,
                            "justification": justification,
                            // The agent's own per-request model claim. Carried verbatim to the
                            // broker, which de-fangs and stores it; no authority reads it.
                            "model": model,
                        })
                        .to_string();
                        let res = match retry_effect {
                            Some(effect_id) => rt.block_on(broker.request_retry_for_principal(
                                session_id.clone(),
                                principal_id.clone(),
                                request_json,
                                effect_id,
                                session_supplied,
                                peer_uid,
                            )),
                            None => rt.block_on(broker.request_for_principal(
                                session_id.clone(),
                                principal_id.clone(),
                                request_json,
                                session_supplied,
                                peer_uid,
                            )),
                        };
                        let mut out =
                            DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                        match res {
                            Ok(json) => write_requested(&mut out, &json),
                            // A caller-supplied session swept between preflight and the mint fails closed with
                            // the distinct re-init reason so the bridge re-Hellos (never a silent grant).
                            Err(Error::SessionExpired) => {
                                write_error(&mut out, cermet_ipc::wire::SESSION_EXPIRED)
                            }
                            Err(Error::Invalid(_)) => write_error(&mut out, "invalid request"),
                            Err(_) => write_error(&mut out, "internal error"),
                        }
                    }
                    None => {
                        let mut out =
                            DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                        write_error(&mut out, "a request must carry a non-empty justification")
                    }
                }
            }
            AgentRequest::Execute {
                request_id,
                session_id: _,
            } => {
                // Authorize by PRINCIPAL (uid), not session: the agent drives via short-lived
                // connections, so request and execute land on different minted sessions. `request_id`
                // is the agent's stable handle (grant_id is withheld); session is audit-only here.
                // Thread THIS connection's minted session + kernel-attested pid as audit-only
                // attribution so the provider-action event names the connection that actually
                // executed, not merely the one that requested.
                let execute_request_id = request_id.clone();
                let res = rt.block_on(broker.execute_request_for_principal(
                    request_id,
                    principal_id.clone(),
                    Some(session_id.clone()),
                    pid,
                    session_supplied,
                    peer_uid,
                ));
                let error_effect =
                    match &res {
                        Ok(_) | Err(Error::SessionExpired) => None,
                        Err(_) => rt
                            .block_on(broker.request_status_for_principal(
                                execute_request_id,
                                principal_id.clone(),
                            ))
                            .ok()
                            .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
                            .and_then(|view| {
                                let effect_id = view
                                    .get("effect_id")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_string)?;
                                let effect_outcome = view
                                    .get("effect_outcome")
                                    .cloned()
                                    .and_then(|value| serde_json::from_value(value).ok());
                                Some((effect_id, effect_outcome))
                            }),
                    };
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                match res {
                    // The core returns an `ExecOutcome` in the exact agent-wire shape.
                    Ok(json) => write_exec_outcome(&mut out, &json),
                    // A caller-supplied session swept before the lease claim fails closed with the
                    // re-init reason (distinct from the opaque execute failure) so the bridge re-Hellos.
                    Err(Error::SessionExpired) => {
                        write_error(&mut out, cermet_ipc::wire::SESSION_EXPIRED)
                    }
                    // A TYPED refusal (the owner's grant is off the approved path) relays its
                    // distinct reason — reached only after ownership was established, so no oracle.
                    Err(Error::ExecuteRefused(class)) => write_error_with_effect(
                        &mut out,
                        execute_refusal_reason(class),
                        error_effect
                            .as_ref()
                            .map(|(effect_id, _)| effect_id.as_str()),
                        error_effect
                            .as_ref()
                            .and_then(|(_, effect_outcome)| *effect_outcome),
                    ),
                    Err(Error::ProviderDisabled) => write_error_with_effect(
                        &mut out,
                        "provider_disabled",
                        error_effect
                            .as_ref()
                            .map(|(effect_id, _)| effect_id.as_str()),
                        error_effect
                            .as_ref()
                            .and_then(|(_, effect_outcome)| *effect_outcome),
                    ),
                    // Collapse every REMAINING execution-failure class (NotFound/Denied/internal) to
                    // ONE opaque reason so a guessed grant id cannot be probed for existence;
                    // the detailed class is logged via the non-blocking logger (NEVER a synchronous
                    // stderr write on the hot path — that would defeat the fresh-per-response write
                    // budget).
                    Err(e) => {
                        crate::log::emit(format!(
                            "cermetd: execute failed (session {session_id}): {e}"
                        ));
                        write_error_with_effect(
                            &mut out,
                            EXECUTE_FAILED,
                            error_effect
                                .as_ref()
                                .map(|(effect_id, _)| effect_id.as_str()),
                            error_effect
                                .as_ref()
                                .and_then(|(_, effect_outcome)| *effect_outcome),
                        )
                    }
                }
            }
            AgentRequest::VerifyAudit { .. } => {
                let res = rt.block_on(broker.verify_audit());
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                match res {
                    Ok(json) => write_audit_verified(&mut out, &json),
                    Err(_) => write_error(&mut out, "internal error"),
                }
            }
            AgentRequest::Catalog { .. } => {
                // Read-only discovery carries only sentence-derived requestable verb schemas.
                let res = rt.block_on(broker.catalog_listing());
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                match res {
                    Ok(json) => write_catalog(&mut out, &json),
                    Err(_) => write_error(&mut out, "internal error"),
                }
            }
            // A vocabulary request is a DECISION the bridge already made against the live catalog,
            // and every decision is a row: the daemon appends it to the same event log
            // `broker_start` writes to. It authorizes nothing and is never read back to decide
            // anything — the core re-checks the closed gap vocabulary and the string bounds, which
            // is this boundary's enforcement half.
            AgentRequest::RecordVocabularyRequest {
                provider,
                wanted_verb,
                wanted_field,
                gap,
                ask,
                rationale,
                session_id: _,
            } => {
                let res = rt.block_on(broker.record_vocabulary_request(
                    Some(session_id.clone()),
                    provider.clone(),
                    wanted_verb.clone(),
                    wanted_field.clone(),
                    gap.clone(),
                    ask.clone(),
                    rationale.clone(),
                ));
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                match res {
                    Ok(_) => write_vocabulary_request_recorded(&mut out),
                    // A refusal here is a malformed report, not an authority answer; the bridge
                    // renders it as "not recorded" and still hands the agent its relay text.
                    Err(e) => write_error(&mut out, &e.to_string()),
                }
            }
            AgentRequest::Status {
                request_id,
                session_id: _,
            } => {
                // Read-only: the live status of the agent's OWN request by its stable handle,
                // principal-BOUND: an unknown AND a foreign request_id answer the same
                // fixed, id-free reason — neither existence nor the widened approved_by_kind /
                // deny_reason fields ever cross to a caller that does not own the request.
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                let res = rt.block_on(
                    broker.request_status_for_principal(request_id, principal_id.clone()),
                );
                match res {
                    Ok(json) => write_status(&mut out, &json),
                    Err(Error::NotFound(_)) => write_error(&mut out, STATUS_UNKNOWN),
                    Err(_) => write_error(&mut out, "internal error"),
                }
            }
            AgentRequest::Artifact {
                handle,
                range,
                path,
                session_id: _,
            } => {
                // Read-only artifact retrieval by handle (S3). No authority, no secret. Fail closed:
                // an unknown handle / tampered blob — or an ambiguous range-AND-path — collapses to ONE
                // opaque reason so a guessed handle cannot be probed for existence; the class is logged.
                let res = match cermet_core::ArtifactAddress::from_wire(range, path) {
                    Ok(addr) => rt.block_on(broker.read_artifact(
                        handle,
                        addr,
                        cermet_core::ArtifactReadSurface::Agent,
                    )),
                    Err(e) => Err(e),
                };
                let mut out =
                    DeadlineWriter::new(&stream, Instant::now() + timeouts.response_budget);
                match res {
                    Ok(json) => write_artifact(&mut out, &json),
                    Err(e) => {
                        crate::log::emit(format!(
                            "cermetd: artifact read failed (session {session_id}): {e}"
                        ));
                        write_error(&mut out, ARTIFACT_UNAVAILABLE)
                    }
                }
            }
        };
        if written.is_err() {
            return;
        }
    }
}

/// Serve `agent.sock` connections forever on a pre-bound listener. `operator_uid` threads the
/// agent-uid gate into each connection: only a peer whose uid equals the resolved
/// agent-plane uid is served; everyone else — including the approver, and every connection when the
/// gate uid is `None` — is refused before any byte (see [`agent_peer_admitted`]).
pub fn serve_agent_socket(
    listener: std::os::unix::net::UnixListener,
    broker: BrokerHandle,
    agent_cmd: String,
    operator_uid: Option<u32>,
    config: ServeConfig,
) {
    let rt = tokio::runtime::Handle::current();
    let timeouts = config.timeouts;
    let handle: ConnHandler = Arc::new(move |stream| {
        handle_connection(stream, &broker, &rt, &agent_cmd, operator_uid, timeouts);
    });
    accept_loop(listener, config.max_conns, handle);
}

/// A per-connection handler the accept loop calls on its own blocking thread.
pub(crate) type ConnHandler = Arc<dyn Fn(StdUnixStream) + Send + Sync>;

/// The shared accept loop for both `agent.sock` and `ctl.sock`, one bounded-admission thread per connection.
pub(crate) fn accept_loop(
    listener: std::os::unix::net::UnixListener,
    max_conns: usize,
    handle: ConnHandler,
) {
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                crate::log::emit(format!("cermetd: accept error (continuing): {e}"));
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let slot = match ConnSlot::try_acquire(&active, max_conns) {
            Some(s) => s,
            None => {
                drop(stream);
                continue;
            }
        };
        let handle = handle.clone();
        std::thread::spawn(move || {
            let _slot = slot;
            handle(stream);
        });
    }
}
