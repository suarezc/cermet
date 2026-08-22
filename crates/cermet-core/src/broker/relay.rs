//! The broker half of the relay: session custody, the credentialed hop, receipts.
//!
//! Division of labour (deliberate, and it is the custody split):
//! - [`crate::relay`] decides. It holds the frozen predicate and frozen fields and no credential.
//! - THIS module holds the live sessions next to the grant state that authorized them, opens the
//!   vault for exactly one hop, and chains every hop and refusal into the audit log.
//! - [`crate::provider::RelayEgress`] BUILDS the credentialed hop inside the existing egress
//!   boundary; `RelayHopRequest::send` performs it, off this thread.
//! - `cermet-daemon` owns only the loopback listener: it parses HTTP, calls
//!   [`super::Broker::relay_hop_start`], RUNS the authorized job on a worker thread, pumps its body,
//!   and hands it back to [`super::Broker::relay_hop_complete`]. It performs NO validation — the
//!   trust boundary is crossed once (the loopback socket), and it is enforced once, here (one
//!   validation per trust-boundary crossing).
//!
//! STREAMING: THE ACTOR NEVER TOUCHES THE NETWORK. A hop's response is no longer buffered
//! before the client sees any of it, and the hop itself no longer runs on the broker thread: the
//! actor produces the verdict and a credentialed [`RelayHopJob`] that has not been sent, and the
//! adapter runs the whole thing — connect, send, head, body — on a worker thread. Two consequences
//! are the whole design:
//! - No trust boundary moved. Every check completes before the credential is attached, exactly as
//!   before; the job carries no decision and exposes no way to read the credential it holds.
//! - The actor is held for none of it, so deny-all stays reachable through an upstream that is
//!   slow, silent, or streaming a build log for minutes.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::{Duration, Instant};

use secrecy::ExposeSecret;
use serde_json::{json, Value};

use super::helpers::credential_ref;
use super::GrantRow;
use crate::audit::NewEvent;
use crate::contract::CanonicalResource;
use crate::error::{Error, Result};
use crate::provider::ProviderResponse;
use crate::relay::{RelayRefusal, RelaySession, RelayVerdict};
use crate::templates::PredicateRule;

/// Cap on live relay sessions. Each one is a TTL-bounded live capability, so the daemon holds a
/// bounded number of them; over the cap, opening REFUSES rather than growing daemon state without
/// limit (T2: a model looping on request/execute; T1: the same, steered).
const MAX_LIVE_RELAY_SESSIONS: usize = 8;

/// How much of a streaming body one pump call moves. Big enough that a 32 MB download is not a
/// million syscalls, small enough that a single log line is not held back waiting for company.
const RELAY_STREAM_CHUNK_BYTES: usize = 16 * 1024;

/// Ceiling on the wait for an upstream's response head. The effective bound is this or the session's
/// own TTL, whichever is shorter — a hop cannot usefully outlive the session that authorized it.
const RELAY_HEAD_TIMEOUT_SECS: u64 = 30;

/// How much of a response body the receipt tee keeps. Receipt derivation reads a handful of
/// top-level JSON fields (`id`, `url`, `readyState`) out of a small provider object, so bytes past
/// this are bytes nobody reads — retaining a whole 32 MB body per hop was pure waste. The client's
/// stream is unaffected: the tee simply stops being fed.
pub(super) const RELAY_OBSERVED_TEE_BYTES: usize = 32 * 1024;

/// One relay hop's response, as the loopback listener will write it back to the native client.
#[derive(Debug, Clone)]
pub struct RelayHopResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// What the loopback adapter must do with one hop.
///
/// The split exists because THE BROKER ACTOR NEVER TOUCHES THE NETWORK. `Complete` is a decision the
/// actor already finished; `Job` is an authorized, credentialed hop that has not been sent yet — the
/// adapter runs it, head and body, on a worker thread. Deny-all therefore stays reachable through an
/// upstream that is slow, silent, or streaming a build log for minutes.
pub enum RelayHopStart {
    /// A refusal: the whole response is known, nothing to perform.
    Complete(RelayHopResponse),
    /// Authorized. Connect, send, head, and body all still to come, off the actor. Boxed because it
    /// is much the larger variant and every refusal path would otherwise carry its weight.
    Job(Box<RelayHopJob>),
}

/// What the core needs to close ONE hop, frozen when the hop was authorized.
struct RelayHopTicket {
    handle: String,
    session_id: String,
    grant_id: String,
    provider: String,
    action: String,
    method: String,
    target: String,
    effect: bool,
}

/// An authorized hop, credential attached, NOT yet performed.
///
/// The adapter calls [`RelayHopJob::run`] on a worker thread. It carries the credentialed request
/// (private, no accessor, no `Debug`), so the adapter can transport it without being able to read
/// it, and it makes no decision of its own — every check already ran on the actor.
pub struct RelayHopJob {
    request: crate::provider::RelayHopRequest,
    secrets: Vec<String>,
    cap: usize,
    ttl_secs: u64,
    ticket: RelayHopTicket,
}

impl RelayHopJob {
    /// Perform the hop: connect, send, and wait for the upstream head. Blocking, and never called on
    /// the broker actor. The returned stream is handed back to
    /// [`super::Broker::relay_hop_complete`] whatever happened — head or no head.
    pub fn run(self) -> RelayHopStream {
        let deadline = Instant::now() + Duration::from_secs(self.ttl_secs);
        let (head, upstream, failed) = match self.request.send(self.cap) {
            Ok(upstream) => (
                Some(RelayHopHead {
                    status: upstream.status,
                    headers: upstream.headers,
                }),
                Some(upstream.body),
                None,
            ),
            Err(error) => (None, None, Some(error.to_string())),
        };
        RelayHopStream {
            head,
            upstream,
            secrets: self.secrets,
            observed: Vec::new(),
            response_bytes: 0,
            cap: self.cap,
            stopped: None,
            failed,
            deadline,
            ticket: self.ticket,
        }
    }
}

/// One upstream response head, as the loopback adapter will write it back.
#[derive(Debug, Clone)]
pub struct RelayHopHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

/// A performed hop: its head (if one ever arrived) and its still-arriving body.
///
/// Everything the receipt and the audit row derive from is accumulated HERE, inside cermet-core:
/// the adapter calls [`RelayHopStream::next_chunk`] until it returns `None` and hands the stream
/// back to [`super::Broker::relay_hop_complete`]. It never sees a secret, a session, or a verdict —
/// which keeps the one-validation-per-crossing shape exactly as it was when the hop was buffered.
pub struct RelayHopStream {
    /// `None` when no upstream head ever arrived — connect failed, the send failed, or the head
    /// bound lapsed. There is no body in that case and the hop audits as a failure.
    head: Option<RelayHopHead>,
    upstream: Option<Box<dyn Read + Send>>,
    /// Redaction material for the streamed bytes — defense in depth against a provider echoing the
    /// credential back, unchanged from the buffered path. Private, and never handed out.
    ///
    /// NOTE: redaction is per chunk, so a secret split across a chunk
    /// boundary is not matched. No named T1/T2/T3 adversary controls where the upstream chops its
    /// frames, and the case this guards is a provider bug, not an attack. The match itself is
    /// byte-level, so a chunk carrying no secret passes through byte for byte.
    secrets: Vec<String>,
    /// The receipt tee: the body prefix the session observes, bounded by `RELAY_OBSERVED_TEE_BYTES`.
    observed: Vec<u8>,
    response_bytes: usize,
    cap: usize,
    /// Why the body read stopped early, if it did. The head is already on the wire by then, so an
    /// over-cap or over-deadline streamed body TRUNCATES where a buffered one refused.
    stopped: Option<&'static str>,
    /// The hop failed — before the head, or on a read mid-body. Recorded on the hop's audit row.
    failed: Option<String>,
    /// The hop's total life, bounded by the session's declared TTL.
    deadline: Instant,
    ticket: RelayHopTicket,
}

impl RelayHopStream {
    /// The upstream head, or `None` if the hop never got one.
    pub fn head(&self) -> Option<&RelayHopHead> {
        self.head.as_ref()
    }

    /// The session handle this hop belongs to.
    pub fn handle(&self) -> &str {
        &self.ticket.handle
    }

    /// Whether this hop is the grant's single effect.
    pub fn effect(&self) -> bool {
        self.ticket.effect
    }

    /// Pump the next piece of body, redacted and teed. `None` ends the stream — end of body, the
    /// declared cap, the session deadline, or a read failure (each named on the hop's audit row).
    pub fn next_chunk(&mut self) -> Option<Vec<u8>> {
        if self.stopped.is_some() || self.failed.is_some() {
            return None;
        }
        let upstream = self.upstream.as_mut()?;
        let mut buf = [0u8; RELAY_STREAM_CHUNK_BYTES];
        loop {
            if Instant::now() >= self.deadline {
                self.stopped = Some("deadline");
                return None;
            }
            match upstream.read(&mut buf) {
                Ok(0) => return None,
                Ok(n) => {
                    self.response_bytes += n;
                    if self.response_bytes > self.cap {
                        self.stopped = Some("cap");
                        return None;
                    }
                    // The tee keeps only what a receipt can read; the client gets everything.
                    let room = RELAY_OBSERVED_TEE_BYTES.saturating_sub(self.observed.len());
                    if room > 0 {
                        self.observed.extend_from_slice(&buf[..n.min(room)]);
                    }
                    // The wire tee covers the relay egress too. It runs HERE, on the pump
                    // thread, so the diagnostic adds no broker-actor occupancy — and it
                    // costs nothing at all when the tee is disarmed, which is every production
                    // daemon. It sees the raw chunk and does its own credential redaction.
                    if crate::wiretap::armed() {
                        crate::wiretap::record_relay_chunk(
                            &self.ticket.provider,
                            &self.ticket.action,
                            &format!("{} {}", self.ticket.method, self.ticket.target),
                            self.head.as_ref().map_or(0, |head| head.status),
                            &buf[..n],
                            &self.secrets,
                        );
                    }
                    return Some(crate::redaction::redact_body_bytes(
                        &buf[..n],
                        &self.secrets,
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.failed = Some(error.to_string());
                    return None;
                }
            }
        }
    }

    /// Test-only view of how much the receipt tee kept.
    #[cfg(test)]
    pub(crate) fn observed_len(&self) -> usize {
        self.observed.len()
    }
}

impl RelayHopResponse {
    fn refusal(refusal: RelayRefusal) -> Self {
        // Identical in SHAPE for every class, and it is the provider-error shape the native client
        // already knows how to print (`error.code` / `error.message` is Vercel's own). It states
        // the truth about what refused and why, because the alternative was the CLI inventing an
        // authentication failure out of a status.
        //
        // `detail` rides BESIDE the stable reason word, never inside it, so anything matching on
        // `reason` keeps matching. It is folded into `message` as well, because `message` is the
        // field the native CLI actually prints — a disclosure only a JSON reader could find would
        // never reach the agent driving that CLI.
        let body = json!({
            "error": {
                "code": "cermet_relay_refused",
                "reason": refusal.reason(),
                "detail": refusal.detail(),
                "message": refusal.message(),
            }
        });
        Self {
            status: refusal.status(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(&body).unwrap_or_default(),
        }
    }

    /// The client-facing answer for a hop that never produced an upstream head.
    pub fn upstream_unavailable() -> Self {
        let body = json!({ "error": { "code": "cermet_relay_upstream_unavailable" } });
        Self {
            status: 502,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(&body).unwrap_or_default(),
        }
    }
}

impl super::Broker {
    /// This daemon's relay settings (declared config; see `crate::relay::RelayConfig`).
    pub fn relay_config(&self) -> &crate::relay::RelayConfig {
        &self.relay
    }

    /// Install the daemon's declared relay settings before any request surface is served.
    pub fn set_relay_config(&mut self, relay: crate::relay::RelayConfig) {
        self.relay = relay;
    }

    /// Open the relay session a claimed relay grant authorizes, and return the RECEIPT the agent gets
    /// in place of a provider body: the handle, the loopback URL, the exact invocation, the deadline.
    ///
    /// No credential is opened here. The grant is consumed by this call exactly like any other verb
    /// (single-use), and the session it opens is the TTL-bounded continuation of that one effect.
    pub(super) fn open_relay_session(
        &self,
        grant: &GrantRow,
        grant_id: &str,
        resource: &CanonicalResource,
        predicate: Vec<PredicateRule>,
    ) -> Result<ProviderResponse> {
        if !self.relay.enabled() {
            return Err(Error::Denied(
                "the loopback relay is disabled (`relay_listen` is empty in the daemon config), so a \
                 relay verb has nowhere to run"
                    .into(),
            ));
        }
        self.sweep_relay_sessions();
        if self.relay_sessions.borrow().len() >= MAX_LIVE_RELAY_SESSIONS {
            return Err(Error::Denied(format!(
                "{MAX_LIVE_RELAY_SESSIONS} relay sessions are already live; wait for one to close"
            )));
        }
        // Freeze the bound fields' approved values onto the session. Only str fields are bindable, so
        // this is the whole comparable surface.
        //
        // A BOUND field may be declared optional, and a request that omitted one froze it as
        // ABSENCE: it enters the map as `None`, and its binds then constrain nothing per hop. The
        // absence is read, never guessed — canonicalization refuses a resource missing a REQUIRED
        // declared field long before this point, so a field absent here is one the template declared
        // optional. (An ASSERTED field is still required by the template validator, so the same read
        // can only produce `Some` for those.)
        let mut frozen: BTreeMap<String, Option<String>> = BTreeMap::new();
        let freeze = |field: &str| -> Result<Option<String>> {
            match resource.scalar(field) {
                None => Ok(None),
                Some(_) => Ok(Some(resource.req_str(field)?.to_string())),
            }
        };
        for rule in &predicate {
            // An outcome assertion compares the same frozen fields the request binds, so
            // both are frozen here — the assertion may name a field no request location binds.
            for assertion in rule.asserts() {
                let value = freeze(&assertion.field)?;
                frozen.insert(assertion.field, value);
            }
            for bind in rule.binds() {
                // A path bind reads what the session CAPTURES from its own effect, not
                // anything the approval froze — there is no request field to read here.
                if bind.captured_name().is_some() {
                    continue;
                }
                let value = freeze(&bind.field)?;
                frozen.insert(bind.field.clone(), value);
            }
        }
        // The invocation below NAMES the frozen project. Left unnamed, the CLI guesses it
        // from the FOLDER NAME whenever the directory is unlinked — the guess lands in the create's
        // `body.name`, misses the bind the sentence froze, and burns the single-use grant before a
        // deploy is ever attempted. The value is read out of `frozen`, which IS the map the per-hop
        // bind compares against, so the flag and the enforcement can never disagree; a verb whose
        // predicate binds no project has nothing enforceable to name, and fails closed here.
        let project_arg = shell_arg(frozen.get("project").and_then(Option::as_ref).ok_or_else(
            || {
                Error::Provider(
                    "a relay verb must bind `project`: the invocation names the frozen project so \
                     the native CLI never guesses one from the directory name"
                        .into(),
                )
            },
        )?);
        let prod_flag = match frozen.get("target").and_then(Option::as_deref) {
            Some("production") => " --prod",
            _ => "",
        };
        let handle = crate::relay::mint_handle();
        let now = self.now_epoch();
        let session = RelaySession::new(
            handle.clone(),
            grant_id.to_string(),
            grant.request_id.clone(),
            grant.session_id.clone(),
            grant.provider.clone(),
            grant.action.clone(),
            grant.policy_fingerprint.clone(),
            predicate,
            frozen,
            now,
            self.relay.ttl_secs,
        );
        let expires_at = session.expires_at;
        let base_url = self.relay.base_url();
        // Accepted cost: the handle rides in argv, which is world-readable
        // through /proc for the session TTL. It is a live, predicate-bounded, single-effect, TTL'd,
        // loopback-only capability reference — never a credential. The `cermet_relay_` head makes
        // that "never a credential" property legible FROM THE STRING, to a reader who cannot ask the
        // daemon — the third-party permission classifier that blocked this very invocation being the
        // first one.
        //
        // The invocation's parts: the native command, `--api` (the loopback relay in place of Vercel's
        // origin), `--token` (the handle), `--project` (the frozen project, above), `--yes`
        // (no prompts), and `--prod` exactly when the frozen target is production (same
        // defect class as the project field: without it the CLI attempts a PREVIEW deployment,
        // `body.target` misses the bind, and the grant burns). `--project` and NOT the deprecated
        // `--name`, which CLI 58.4.4 parses, warns about, and then only uses as a fallback:
        // `--project` additionally sets the CLI's `failIfNotFound`, so an unknown project stops
        // locally instead of attempting a project-create the predicate does not admit. Both flags
        // read from `frozen`, the map the per-hop bind compares against, so invocation and
        // enforcement can never disagree. NO authority moved by any of it — the relay still refuses
        // a hop whose body misses its bind; the flags only stop the CLI manufacturing one.
        let invocation = format!(
            "vercel deploy --api {base_url} --token {handle} --project {project_arg} --yes{prod_flag}",
            base_url = base_url,
            handle = handle,
            project_arg = project_arg,
            prod_flag = prod_flag
        );
        self.audit.record(NewEvent {
            session_id: Some(&grant.session_id),
            event_type: "relay_session_opened",
            severity: "high",
            summary: &format!("{}.{} relay session opened", grant.provider, grant.action),
            data: json!({
                "grant_id": grant_id,
                "request_id": grant.request_id,
                "provider": grant.provider,
                "action": grant.action,
                "handle_prefix": handle_prefix(&handle),
                "expires_at": expires_at,
                "listen": self.relay.listen,
            }),
            secrets: &self.vault.all_secrets()?,
        })?;
        self.relay_sessions
            .borrow_mut()
            .insert(handle.clone(), session);
        Ok(ProviderResponse {
            proof: None,
            ok: true,
            failure_class: None,
            result: json!({
                "relay": {
                    "handle": handle,
                    "api_base": base_url,
                    "invocation": invocation,
                    "expires_at": expires_at,
                    "ttl_secs": self.relay.ttl_secs,
                },
            }),
            retained: None,
            envelope: Default::default(),
        })
    }

    /// Authorize and forward ONE relay hop, returning either the complete response or the forwarded
    /// hop's HEAD plus its still-arriving body. `target` is the request line's path+query exactly as
    /// the native client wrote it; `headers` are its request headers (the relay forwards a fixed
    /// subset and replaces `Authorization`); `body` is the buffered request body.
    ///
    /// Every decision — predicate, binds, lockdown, live authority — completes HERE, before the
    /// credential is attached, so streaming the body afterwards moves no trust boundary. The caller
    /// pumps the returned stream off the broker actor and hands it back to
    /// [`Self::relay_hop_complete`], which writes the hop's audit row and the receipt observation.
    ///
    /// Never returns `Err` for a refusal — a refusal is an HTTP response the client must see. `Err` is
    /// reserved for a broker-side fault (an audit or vault fault), which fails closed.
    pub fn relay_hop_start(
        &self,
        handle: &str,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<RelayHopStart> {
        Ok(RelayHopStart::Complete(
            match self.decide_relay_hop(handle, method, target, headers, body)? {
                Ok(job) => return Ok(RelayHopStart::Job(Box::new(job))),
                Err(response) => response,
            },
        ))
    }

    /// The verdict half of [`Self::relay_hop_start`], split out so every refusal path can return a
    /// complete response with `?`-style flow. `Ok(job)` means the hop is authorized and credentialed;
    /// it has NOT been sent — nothing in here touches the network.
    #[allow(clippy::result_large_err)]
    fn decide_relay_hop(
        &self,
        handle: &str,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<std::result::Result<RelayHopJob, RelayHopResponse>> {
        if body.len() > self.relay.max_body_bytes {
            self.audit_relay_refusal(None, method, target, &RelayRefusal::BodyTooLarge)?;
            return Ok(Err(RelayHopResponse::refusal(RelayRefusal::BodyTooLarge)));
        }
        // Take the session OUT of the map for the duration of the hop: one owner, no reentrancy, and a
        // burned session is simply never put back.
        let Some(mut session) = self.relay_sessions.borrow_mut().remove(handle) else {
            self.audit_relay_refusal(None, method, target, &RelayRefusal::UnknownHandle)?;
            return Ok(Err(RelayHopResponse::refusal(RelayRefusal::UnknownHandle)));
        };
        let now = self.now_epoch();
        let effect = match session.authorize(method, target, &body, now) {
            RelayVerdict::Forward { effect } => effect,
            RelayVerdict::Refuse(refusal) => {
                session.note_refusal(refusal.clone(), method, target);
                self.audit_relay_refusal(Some(&session), method, target, &refusal)?;
                // A burned or lapsed session closes here — with its receipt — and every later hop on
                // its handle is an unknown handle.
                if session.burned().is_some() || refusal == RelayRefusal::Expired {
                    self.close_relay_session(
                        &session,
                        if refusal == RelayRefusal::Expired {
                            "ttl"
                        } else {
                            "burned"
                        },
                    )?;
                } else {
                    self.relay_sessions
                        .borrow_mut()
                        .insert(handle.to_string(), session);
                }
                return Ok(Err(RelayHopResponse::refusal(refusal)));
            }
        };
        // The owner's revocation root and the live sentence authority both outrank a session already
        // opened: deny-all must stop a relay mid-flight, and an allow the operator has withdrawn must
        // not keep deploying. Either one CLOSES the session (it is not a probe, so it is not a burn).
        if let Err(error) = self.enforce_not_locked_down("relay hop egress") {
            self.audit_relay_closed_before_egress(&session, method, target, "lockdown_engaged")?;
            self.close_relay_session(&session, "lockdown_engaged")?;
            let _ = error;
            return Ok(Err(RelayHopResponse::refusal(RelayRefusal::UnknownHandle)));
        }
        let authority_holds = matches!(
            self.current_sentence_authority(),
            Ok((_, current)) if current == session.policy_fingerprint
        );
        if !authority_holds {
            self.audit_relay_closed_before_egress(&session, method, target, "authority_changed")?;
            self.close_relay_session(&session, "authority_changed")?;
            return Ok(Err(RelayHopResponse::refusal(RelayRefusal::UnknownHandle)));
        }

        let secrets = self.vault.all_secrets()?;
        let egress = self.relay_egress.get(&session.provider).ok_or_else(|| {
            Error::Provider(format!(
                "no ratified egress origin is loaded for provider {}",
                session.provider
            ))
        })?;
        // Counted BEFORE the hop runs, not after: the session goes back in the map while the hop is
        // still in flight, so the single effect must already be spent when the next hop is decided.
        // The conservative reading is unchanged — a create that gets no response may still have
        // landed, so a second one must not be admitted.
        session.note_forward(effect);
        // THE credential moment: opened for this one hop and attached inside the egress boundary,
        // which is where it has always been built into an `Authorization` header. It never touches
        // the session, the receipt, the audit data, or the client body, and the job it rides in
        // exposes no way to read it back.
        let opened = self.vault.open_secret(&credential_ref(&session.provider));
        // The head bound is the shorter of the 30 s ceiling and the session's own remaining
        // authority: a hop cannot usefully outlive the session that authorized it.
        let head_timeout = Duration::from_secs(RELAY_HEAD_TIMEOUT_SECS.min(self.relay.ttl_secs));
        let prepared = match &opened {
            Ok(secret) => egress.prepare(
                secret.expose_secret(),
                method,
                target,
                headers,
                body,
                head_timeout,
            ),
            Err(error) => Err(Error::Provider(format!(
                "relay credential unavailable: {error}"
            ))),
        };
        drop(opened);

        let outcome = match prepared {
            Ok(request) => Ok(RelayHopJob {
                request,
                secrets,
                cap: self.relay.max_body_bytes,
                ttl_secs: self.relay.ttl_secs,
                ticket: RelayHopTicket {
                    handle: handle.to_string(),
                    session_id: session.session_id.clone(),
                    grant_id: session.grant_id.clone(),
                    provider: session.provider.clone(),
                    action: session.action.clone(),
                    method: method.to_string(),
                    target: capped_target(target).0,
                    effect,
                },
            }),
            Err(error) => {
                self.audit.record(NewEvent {
                    session_id: Some(&session.session_id),
                    event_type: "relay_request_failed",
                    severity: "high",
                    summary: &format!("{}.{} relay hop failed", session.provider, session.action),
                    data: json!({
                        "grant_id": session.grant_id,
                        "provider": session.provider,
                        "action": session.action,
                        "method": method,
                        "target": capped_target(target).0,
                        "effect": effect,
                        "error": error.to_string(),
                        // The hop never left the box — the credential could not be opened, or the
                        // request could not be prepared. Our fault, and definitively no effect.
                        "failure_class": crate::types::EffectFailureClass::of(
                            crate::types::FailureSignal::LocalFault,
                        )
                        .as_str(),
                    }),
                    secrets: &secrets,
                })?;
                Err(RelayHopResponse::upstream_unavailable())
            }
        };
        self.relay_sessions
            .borrow_mut()
            .insert(handle.to_string(), session);
        Ok(outcome)
    }

    /// Apply what the upstream HEAD alone decides, the moment it lands: a definite provider 4xx on
    /// the effect hop is a definite no-effect, so the `once` effect is released.
    ///
    /// The adapter calls this before it writes the head back, so the release is in place before the
    /// client can act on the status it just received — the native two-phase create is
    /// 400-then-retry, and the retry must not meet a stale `EffectAlreadyUsed`.
    pub fn relay_hop_head(&self, handle: &str, effect: bool, status: u16) -> Result<()> {
        if let Some(session) = self.relay_sessions.borrow_mut().get_mut(handle) {
            session.observe_status(effect, status);
        }
        Ok(())
    }

    /// Close ONE hop: the receipt observation the session derives from the body it saw, and the hop's
    /// audit row — written when the hop ENDS, with the total bytes forwarded.
    ///
    /// The adapter calls this for every job it ran, including one that never got a head and one the
    /// client hung up on, so a started hop always lands exactly one terminal row.
    pub fn relay_hop_complete(&self, stream: RelayHopStream) -> Result<()> {
        let ticket = &stream.ticket;
        let Some(head) = &stream.head else {
            // No head ever arrived: connect, send, or the head bound. Nothing was observed and there
            // is no status to report.
            self.audit.record(NewEvent {
                session_id: Some(&ticket.session_id),
                event_type: "relay_request_failed",
                severity: "high",
                summary: &format!("{}.{} relay hop failed", ticket.provider, ticket.action),
                data: json!({
                    "grant_id": ticket.grant_id,
                    "provider": ticket.provider,
                    "action": ticket.action,
                    "method": ticket.method,
                    "target": ticket.target,
                    "effect": ticket.effect,
                    "error": stream.failed.clone().unwrap_or_default(),
                    // The hop was dispatched and no head ever arrived — connect, send, or the head
                    // bound. Whether the effect landed is unknown, and there is no status for a
                    // reader to classify from later, so the class is typed here.
                    "failure_class": crate::types::EffectFailureClass::of(
                        crate::types::FailureSignal::SentWithoutAnswer,
                    )
                    .as_str(),
                }),
                secrets: &self.vault.all_secrets()?,
            })?;
            return Ok(());
        };
        // NOTE (accepted): a session the TTL sweep closed mid-hop is gone from the map by now, so
        // its receipt carries the hop but not what the body said. The hop row below is still written,
        // and a hop outliving its own session's TTL is already past the deadline the approval set.
        //
        // THE one response-body read: receipt derivation, the capture, and the
        // outcome assertion all come out of this single call, off the bounded receipt tee.
        let mismatch = self
            .relay_sessions
            .borrow_mut()
            .get_mut(&ticket.handle)
            .and_then(|session| session.observe_body(ticket.effect, head.status, &stream.observed));
        let mut data = json!({
            "grant_id": ticket.grant_id,
            "provider": ticket.provider,
            "action": ticket.action,
            "method": ticket.method,
            "target": ticket.target,
            "upstream_status": head.status,
            "effect": ticket.effect,
            "response_bytes": stream.response_bytes,
        });
        if let Some(reason) = stream.stopped {
            data["response_truncated"] = json!(true);
            data["truncated_by"] = json!(reason);
        }
        if let Some(error) = &stream.failed {
            data["stream_error"] = json!(error);
        }
        self.audit.record(NewEvent {
            session_id: Some(&ticket.session_id),
            event_type: "relay_request_forwarded",
            severity: if ticket.effect { "high" } else { "info" },
            summary: &format!(
                "{}.{} relay hop {} -> {}",
                ticket.provider, ticket.action, ticket.method, head.status
            ),
            data,
            secrets: &self.vault.all_secrets()?,
        })?;
        // After the hop's own row, so the chain reads in the order it happened: the effect
        // LANDED and its response contradicts the approval. Nothing here undoes it — the session is
        // ended and the operator is told, in one high-severity row carrying frozen-vs-observed.
        if let Some(mismatch) = mismatch {
            if let Some(mut session) = self.relay_sessions.borrow_mut().remove(&ticket.handle) {
                session.note_outcome_mismatch(&ticket.method, &ticket.target);
                self.audit_relay_outcome_mismatch(&session, ticket, head.status, &mismatch)?;
                self.close_relay_session(&session, "outcome_mismatch")?;
            }
        }
        Ok(())
    }

    /// The outcome-mismatch row. `high`, because a deployment that disagrees with what a
    /// human approved is the thing an operator most needs to see, and it carries both sides —
    /// `frozen` (null when the approved value means the key must be ABSENT) and `observed`.
    fn audit_relay_outcome_mismatch(
        &self,
        session: &RelaySession,
        ticket: &RelayHopTicket,
        upstream_status: u16,
        mismatch: &crate::relay::RelayOutcomeMismatch,
    ) -> Result<()> {
        self.audit.record(NewEvent {
            session_id: Some(&session.session_id),
            event_type: "relay_outcome_mismatch",
            severity: "high",
            summary: &format!(
                "{}.{} relay outcome contradicts the approval ({})",
                session.provider, session.action, mismatch.key
            ),
            data: json!({
                "grant_id": session.grant_id,
                "provider": session.provider,
                "action": session.action,
                "method": ticket.method,
                "target": ticket.target,
                "upstream_status": upstream_status,
                "key": mismatch.key,
                "field": mismatch.field,
                "frozen": mismatch.expected,
                "observed": mismatch.observed,
                // The same three marks a burning REFUSAL row carries. A hop that ended a session is
                // ONE kind of thing to the operator surfaces — one filter (`cermet log --hops
                // --burned`) and one renderer serve every such row — and this is the only one that
                // arrives on a hop the relay authorized and forwarded. The class is read off the
                // refusal vocabulary rather than spelled again, so it cannot drift from it.
                "reason": RelayRefusal::OutcomeMismatch.reason(),
                "burned": RelayRefusal::OutcomeMismatch.burns(),
                "detail": mismatch.detail(),
                // Said on the row itself, because the row is the artifact an operator reads months
                // later: the effect had already landed when this was decided.
                "detection": "the effect already landed; the session is burned, nothing is undone",
            }),
            secrets: &self.vault.all_secrets()?,
        })?;
        Ok(())
    }

    /// Test-only: drive one hop start-to-finish and buffer it, which is what every relay test that
    /// predates streaming asserts against.
    #[cfg(test)]
    pub(crate) fn relay_hop(
        &self,
        handle: &str,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<RelayHopResponse> {
        match self.relay_hop_start(handle, method, target, headers, body)? {
            RelayHopStart::Complete(response) => Ok(response),
            RelayHopStart::Job(job) => {
                let mut stream = job.run();
                let Some(head) = stream.head().cloned() else {
                    self.relay_hop_complete(stream)?;
                    return Ok(RelayHopResponse::upstream_unavailable());
                };
                self.relay_hop_head(handle, stream.effect(), head.status)?;
                let mut body = Vec::new();
                while let Some(chunk) = stream.next_chunk() {
                    body.extend_from_slice(&chunk);
                }
                self.relay_hop_complete(stream)?;
                Ok(RelayHopResponse {
                    status: head.status,
                    headers: head.headers,
                    body,
                })
            }
        }
    }

    /// Close every lapsed session, writing each one's receipt. Called at every open and on the daemon's
    /// housekeeping tick, so a session that simply ran out of time still lands a receipt.
    pub fn sweep_relay_sessions(&self) -> usize {
        let now = self.now_epoch();
        let lapsed: Vec<RelaySession> = {
            let mut sessions = self.relay_sessions.borrow_mut();
            let handles: Vec<String> = sessions
                .iter()
                .filter(|(_, session)| now > session.expires_at)
                .map(|(handle, _)| handle.clone())
                .collect();
            handles
                .iter()
                .filter_map(|handle| sessions.remove(handle))
                .collect()
        };
        for session in &lapsed {
            // Best-effort: a failed audit write must not leave the sweep half-done.
            let _ = self.close_relay_session(session, "ttl");
        }
        lapsed.len()
    }

    /// The session's terminal record: the receipt DERIVED from what the relay observed.
    fn close_relay_session(&self, session: &RelaySession, reason: &str) -> Result<()> {
        self.audit.record(NewEvent {
            session_id: Some(&session.session_id),
            event_type: "relay_session_closed",
            severity: "info",
            summary: &format!(
                "{}.{} relay session closed ({reason})",
                session.provider, session.action
            ),
            data: session.receipt(reason),
            secrets: &self.vault.all_secrets()?,
        })?;
        Ok(())
    }

    /// (T3) the unauthenticated path is reachable by any peer uid at the loopback port, and
    /// two things about the row it writes are bounded here.
    ///
    /// The audited TARGET is capped on every path. The 512-byte predicate cap lives inside
    /// `authorize`, which a request with no live session never reaches, so an unauthenticated caller
    /// could otherwise write a 100 KB path into the durable chain per request.
    ///
    /// The SEVERITY is the tier the event actually deserves: `high` means a live grant is being probed
    /// (that is what a refusal on a session IS), while a poke at an open port with no handle is noise
    /// and belongs in the routine `info` tier. The row is never dropped — it stays a declared,
    /// auditable event — and the refusal itself is unchanged.
    fn audit_relay_refusal(
        &self,
        session: Option<&RelaySession>,
        method: &str,
        target: &str,
        refusal: &RelayRefusal,
    ) -> Result<()> {
        let (audited_target, truncated) = capped_target(target);
        let mut data = json!({
            "method": method,
            "target": audited_target,
            "reason": refusal.reason(),
            "status": refusal.status(),
            "burned": refusal.burns(),
        });
        // WHAT the refusal knew, on the row an operator reads to decide whether to widen: the
        // offending field or key, the constraint as enforced, and the offered value. The prose form
        // is one line; the structured keys beside it are what a row is grepped by.
        if let Some(detail) = refusal.detail() {
            data["detail"] = json!(detail);
        }
        match refusal {
            // The refused key NAMES. Names only — the body VALUES stay in the agent's request,
            // out of the log: the name is what an operator needs in order to decide whether to
            // ratify the key.
            RelayRefusal::UndeclaredBodyKey { keys } => data["undeclared_keys"] = json!(keys),
            RelayRefusal::NoMatchingShape(miss) => {
                if !miss.undeclared_query_keys.is_empty() {
                    data["undeclared_keys"] = json!(miss.undeclared_query_keys);
                }
            }
            RelayRefusal::BindMismatch(mismatch) => {
                data["field"] = json!(mismatch.field);
                data["bind_key"] = json!(mismatch.key);
                data["bind_position"] = json!(mismatch.position.wire());
            }
            _ => {}
        }
        if truncated {
            data["target_truncated"] = json!(true);
        }
        if let Some(session) = session {
            data["grant_id"] = json!(session.grant_id);
            data["provider"] = json!(session.provider);
            data["action"] = json!(session.action);
        }
        self.audit.record(NewEvent {
            session_id: session.map(|s| s.session_id.as_str()),
            event_type: "relay_request_refused",
            severity: if session.is_some() { "high" } else { "info" },
            summary: &format!("relay hop refused ({})", refusal.reason()),
            data,
            secrets: &self.vault.all_secrets()?,
        })?;
        Ok(())
    }

    fn audit_relay_closed_before_egress(
        &self,
        session: &RelaySession,
        method: &str,
        target: &str,
        reason: &str,
    ) -> Result<()> {
        self.audit.record(NewEvent {
            session_id: Some(&session.session_id),
            event_type: "relay_request_refused",
            severity: "high",
            summary: &format!("relay hop refused before egress ({reason})"),
            data: json!({
                "grant_id": session.grant_id,
                "provider": session.provider,
                "action": session.action,
                "method": method,
                "target": capped_target(target).0,
                "reason": reason,
                "burned": true,
            }),
            secrets: &self.vault.all_secrets()?,
        })?;
        Ok(())
    }

    /// A relay verb's frozen predicate, or `None` for a constructed verb.
    pub(super) fn relay_predicate_for(
        &self,
        provider: &str,
        action: &str,
    ) -> Option<Vec<PredicateRule>> {
        self.templates
            .loaded(provider, action)
            .and_then(|loaded| loaded.template.relay_predicate())
            .map(<[PredicateRule]>::to_vec)
    }

    /// Test-only view of the live session for a handle.
    #[cfg(test)]
    pub(crate) fn relay_session_snapshot(&self, handle: &str) -> Option<RelaySession> {
        self.relay_sessions.borrow().get(handle).cloned()
    }

    /// Test-only count of live sessions.
    #[cfg(test)]
    pub(crate) fn live_relay_sessions(&self) -> usize {
        self.relay_sessions.borrow().len()
    }
}

/// What an audit row may say about a request target — at most one predicate path's worth of
/// bytes, keeping the head so the row still names what was asked for. Every relay audit path runs
/// through this, including the unauthenticated one that never reaches the `authorize` cap.
fn capped_target(target: &str) -> (String, bool) {
    let cap = crate::templates::MAX_PREDICATE_PATH_BYTES;
    if target.len() <= cap {
        return (target.to_string(), false);
    }
    // Char-boundary-safe: take whole characters up to the byte cap.
    let mut capped = String::with_capacity(cap);
    for ch in target.chars() {
        if capped.len() + ch.len_utf8() > cap {
            break;
        }
        capped.push(ch);
    }
    (capped, true)
}

/// The audited prefix of a handle: enough to correlate two audit rows to one session, never enough to
/// replay it (the handle is a live capability reference for its TTL). Read off the RANDOM part —
/// every handle now shares a constant head, which correlates nothing.
fn handle_prefix(handle: &str) -> String {
    handle
        .strip_prefix(crate::relay::HANDLE_PREFIX)
        .unwrap_or(handle)
        .chars()
        .take(6)
        .collect()
}

/// One argument of the receipt's invocation, safe to paste into a POSIX shell.
///
/// A `str` field carries any JSON string — `Scalar::from_json` (`cermet-lang/src/contract.rs`)
/// constrains no charset — and the invocation is a line an agent pastes into ITS OWN shell, so a
/// project value holding `;` or a backtick would otherwise execute (T1: third-party content steering
/// the requested project value; T2: a fat-fingered name). Bare when the value is unambiguously inert,
/// single-quoted otherwise — a single-quoted string has no shell metacharacter but `'` itself, which
/// closes, escapes, and reopens.
pub(super) fn shell_arg(value: &str) -> String {
    let inert = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if inert {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}

/// A relay receipt carries no provider body, so nothing here is `Value`-shaped by accident: the caller
/// hands the whole `result` object to the agent unchanged.
#[allow(dead_code)]
fn _receipt_is_broker_authored(_: &Value) {}
