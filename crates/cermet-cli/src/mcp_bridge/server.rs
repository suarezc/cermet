//! `cermet mcp` — a stdio MCP server that bridges an LLM's tool calls to `agent.sock`.
//!
//! This is the same keyless boundary as the CLI, exposed as four MCP tools instead of subcommands.
//! Each tool call opens ONE short-lived `agent.sock` connection via [`super::call`] (single-use:
//! an execute consumes a grant) and renders the reply. There is NO approve/connect tool — approvals
//! are human-only, on a separate uid behind the ctl path; the model cannot express one here.
//!
//! Framing is MCP-over-stdio: newline-delimited JSON-RPC 2.0. Unknown methods return a JSON-RPC
//! error (never a crash); tool-level failures return a `content` result with `isError: true`.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use cermet_ipc::wire::{EffectOutcome, SESSION_EXPIRED};
use serde_json::{json, Value};

use super::{AgentCommand, AgentError, CatalogZoom, SessionHello};

/// The MCP protocol revision this server speaks.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// The upper bound on concurrently-executing `tools/call` workers. A long-running execute (e.g.
/// a multi-minute `cargo run`) must not serialize a fleet of parallel agents behind it, so each
/// `tools/call` runs on its own worker thread with its own daemon connection; this caps the fan-out so
/// a runaway client cannot spawn unbounded threads. Well under the daemon's `agent.sock` connection cap.
const WORKER_CAP: usize = 16;

/// The bound on lines buffered between the reader thread and dispatch. Full ⇒ the reader
/// parks (backpressure; the client's writes back up into the OS pipe, itself bounded) instead of
/// slurping an unbounded backlog that would hide EOF and eat memory. Sized for bursts, not storage.
const READER_QUEUE_DEPTH: usize = 256;

/// How often the hangup watcher polls the reader fd for POLLHUP. Cheap (non-consuming,
/// zero-timeout poll), so a long-lived healthy client costs one syscall per tick.
const HANGUP_POLL: Duration = Duration::from_millis(50);

/// The shutdown lifecycle's time budget: shutdown is bounded END-TO-END and
/// none of the phases waits forever. There is deliberately NO report phase — the daemon's ledger
/// (claim-time lease deadline + overdue sweep) is the durable custody truth; the agent's
/// reporting is best-effort-fast, never a debt the server must sit on.
#[derive(Clone, Copy)]
struct ShutdownTimings {
    /// How long the post-EOF backlog window + natural worker drain lasts, anchored at the input's
    /// actual end.
    drain: Duration,
    /// How long STARTED executions get to finish on their own past the shutdown decision — a free
    /// policy knob (an SLO, not derived from anything).
    kill_grace: Duration,
    /// After the grace, running children's process groups are KILLED and this bounds the
    /// join of started workers. DERIVED: a worker's last daemon RPC is bounded by the shared IPC
    /// call timeout — one such call is the honest join horizon; past it the worker is detached
    /// (the daemon sweep owns any unreported lease).
    kill_join: Duration,
}

impl Default for ShutdownTimings {
    fn default() -> Self {
        Self {
            drain: Duration::from_secs(120),
            kill_grace: Duration::from_secs(10),
            kill_join: cermet_ipc::client::DEFAULT_CALL_TIMEOUT,
        }
    }
}

impl ShutdownTimings {
    /// The last phase's bound: how long shutdown waits for the writer task to land the lines
    /// already admitted before deactivation. It is DERIVED, not a free constant — the flush is
    /// the join of a thread that may be parked in blocking I/O, exactly like `kill_join`, so it
    /// rides the SAME budget, capped by [`FLUSH_JOIN`] (the production ceiling: a stalled sink is
    /// detached well before the 30s call horizon). A hardcoded bound here sat OUTSIDE the declared
    /// budget and made the composed exit unbounded by it: any deployment (or test) running a
    /// tighter budget still paid the constant, so on a slow-paced sink the exit anchored at
    /// backlog exhaustion instead of at the client's close.
    fn flush_join(&self) -> Duration {
        self.kill_join.min(FLUSH_JOIN)
    }
}

/// How often the dispatch loop wakes to re-check the sink while stdin is quiet: a terminal
/// writer failure winds the server down within this interval, stdin activity or not.
const SINK_POLL: Duration = Duration::from_millis(100);

/// Async execute: how long `execute_capability` BLOCKS THE CALL before returning a handle. A
/// fast command finishes inside this window and returns its receipt INLINE (one call, exactly like
/// the old blocking execute for quick verbs); a slow one hands back `{request_id, state}` and keeps
/// running in the background (a RunSupervisor thread). Kept small so the tool call is always snappy.
const DEFAULT_EXECUTE_WAIT_MS: u64 = 2000;
/// The ceiling a caller may raise `execute_capability`'s bounded inline wait to (it must stay under a
/// client's tool-call timeout — the point of async is to never block the CALL for a whole long run).
const MAX_EXECUTE_WAIT_MS: u64 = 60_000;
/// `request_status`'s long-poll cap: how long it parks waiting for a nonterminal run to settle. Kept
/// UNDER the shared 30s IPC call timeout so a daemon-backed status read never races it.
const STATUS_LONG_POLL_CAP_MS: u64 = 20_000;
/// How often the status long-poll re-reads the daemon while a run is nonterminal.
const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// The floor a SINGLE bounded status/reconcile read gets even when the caller's wait
/// budget is ~0 (a `wait_ms:0` immediate read still does one real daemon round-trip). It caps a
/// STALLED read far below the 30s IPC default, so an immediate status can't hang for half a minute
/// when the daemon is contended behind long-held connections.
const STATUS_READ_FLOOR: Duration = Duration::from_secs(3);
/// The `poll_after_ms` hint returned to the model when a run is still nonterminal.
const POLL_AFTER_MS: u64 = 1000;
/// The cap on tracked run records. Terminal records past this are evicted oldest-settled-first — their
/// receipts stay DURABLY reconstructable from the daemon ledger (the `async_execute_v1` status), so an
/// eviction never loses truth; it just falls back to the durable query.
const RUN_SUPERVISOR_CAP: usize = 256;

/// The legible refusal `execute_capability` returns when the daemon never negotiated `async_execute_v1`
/// (version skew): the async surface cannot answer "did this background run finish, and how?" against
/// an old daemon, so it fails BEFORE any claim rather than silently blocking (contract: no fallback).
const SKEW_ASYNC_EXECUTE: &str =
    "cermetd lacks the async-execute capability (upgrade cermetd): refusing to start this run — \
     retry once the daemon is updated";
/// The busy refusal when the RunSupervisor is at its concurrent-run cap. The grant was NOT claimed
/// (admission fails before the claiming RPC), so it stays approved and re-executable — retry shortly.
const RUN_POOL_BUSY: &str =
    "server busy: too many concurrent background runs in flight; retry execute_capability shortly";

/// The legible refusal a REQUIRED-feature call gets when the daemon behind the socket no
/// longer advertises the feature — including after a mid-call session re-mint renegotiated against a
/// downgraded/older daemon. Refused BEFORE the RPC: provably unclaimed, retryable once the daemon is
/// upgraded/restarted. The prefix is shared with [`SKEW_ASYNC_EXECUTE`] so run classification treats
/// both as pre-claim skew.
const SKEW_PREFIX: &str = "cermetd lacks the";

fn feature_skew_refusal(feature: &str) -> String {
    format!(
        "{SKEW_PREFIX} {feature} capability (upgrade/restart cermetd): refusing this call — the \
         session was renegotiated without it; nothing was claimed"
    )
}

/// What an agent is told when the daemon that answered is a DIFFERENT build than this
/// MCP server binary. Note-only — nothing refuses on it — but it must reach the agent IN BAND,
/// because an agent reads tool results and nothing else: a session that outlived a reinstall is
/// otherwise indistinguishable from a current one until the wire drifts and calls start failing
/// with no recovery hint. It names both builds and the one action that fixes it.
fn build_skew_note(daemon_build: &str) -> String {
    format!(
        "NOTE (cermet build skew): this MCP session runs cermet {ours}, but cermetd is \
         {daemon_build}. The tools in this session are the OTHER build's — restart this agent \
         session (or reconnect its cermet MCP server) to pick up the installed one. Brokering \
         still works meanwhile: authority is decided daemon-side.",
        ours = cermet_ipc::BUILD_ID,
    )
}

/// The agent DISPLAY name stamped onto the session (via `Hello`) when `CERMET_AGENT_NAME` is unset.
/// It is a label only — never an identity (authority is the kernel-attested peer uid).
const DEFAULT_AGENT_NAME: &str = "mcp-agent";

/// The documented environment variable a human uses to declare which MODEL is driving this bridge,
/// e.g. `CERMET_AGENT_MODEL=claude-sonnet-4`.
///
/// Read ONCE at startup. It is a self-report and nothing more: no authority reads it, the daemon
/// stores it beside the session so this box's own receipts can say which model was driving, and
/// nothing leaves the machine. Unset is the ordinary case and means the model half is simply
/// absent, never guessed.
pub const AGENT_MODEL_ENV: &str = "CERMET_AGENT_MODEL";

/// A worker's view of the server's shutdown lifecycle. `may_start` is consulted
/// BEFORE any RPC that can claim/execute a grant and before any child spawn — the daemon performs
/// HTTP provider actions DURING the Execute RPC, so pre-RPC is the last point where refusal still
/// means "provably unstarted". `kill_now` is polled while a spawned child runs (the shutdown grace
/// elapsed → its process group is killed and the true outcome reported). The defaults describe a
/// server that is not shutting down.
pub trait ShutdownProbe {
    /// May a NEW execution (claiming RPC or child process) start? False once shutdown is decided.
    fn may_start(&self) -> bool {
        true
    }
    /// Should a running child's process group be killed now (the shutdown grace elapsed)?
    fn kill_now(&self) -> bool {
        false
    }
    /// The BRIDGE shutdown cause to stamp on a killed run's receipt (`client_eof` /
    /// `sink_failure` / `unknown`), so it names the cermet MCP bridge — never "server shutdown",
    /// which read as if cermetd had bounced (it never did). `unknown` unless a concrete cause is known.
    fn cancel_cause(&self) -> &'static str {
        "unknown"
    }
}

/// Any `Fn() -> bool` is a start-only probe (its answer is `may_start`; `kill_now` stays false) —
/// the inline dispatch path and tests pass `&|| true` / `&|| false` without ceremony.
impl<F: Fn() -> bool> ShutdownProbe for F {
    fn may_start(&self) -> bool {
        self()
    }
}

/// The `agent.sock` calls, abstracted so dispatch is testable without a live socket.
pub trait AgentTransport {
    fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError>;

    /// Run `cmd` but never block longer than `budget` — a BOUNDED daemon RPC for a
    /// tool call that advertises a wait (a `request_status` long-poll, an ambiguous reconcile).
    /// Without this a single slow/contended read on the shared connection blows the advertised
    /// bound (a 20s status cap became minutes when the daemon queued the read behind long-held
    /// connections). Default: the unbounded [`Self::call`] (an in-process fake answers instantly
    /// and has no socket to clamp); the SOCKET transport clamps the connection's read deadline.
    fn call_within(&self, cmd: &AgentCommand, _budget: Duration) -> Result<Value, AgentError> {
        self.call(cmd)
    }

    /// Record what the MCP client said about ITSELF in the `initialize` handshake, so the
    /// lazily-minted session can carry it. A SELF-REPORT: never an identity, never consulted by any
    /// authority, and never leaving this box. Default: a no-op (in-process test fakes mint no
    /// session).
    fn declare_client(&self, _name: Option<&str>, _version: Option<&str>) {}

    /// Force the conversation session (and thus the Hello feature negotiation) to
    /// be established, so a subsequent [`Self::has_feature`] reflects the real daemon. The async
    /// surface calls this BEFORE its `async_execute_v1` skew gate — the first tool call would
    /// otherwise find an empty (un-negotiated) feature set and misfire the gate. Default: a no-op
    /// (in-process test fakes need no session); the socket transport mints/reuses the session.
    fn ensure_session(&self) -> Result<(), AgentError> {
        Ok(())
    }

    /// Does the daemon behind this transport speak `feature` (a `wire::FEATURE_*`
    /// label)? Custody debt-clearing logic is GATED on this — an un-negotiated daemon holds
    /// debt and refuses reconciliation. Default TRUE: an in-process transport (test fakes —
    /// same binary) speaks this build's vocabulary by construction; the SOCKET transport
    /// overrides this from the Hello negotiation and answers false until a session proved it.
    fn has_feature(&self, _feature: &str) -> bool {
        true
    }

    /// The one in-band note this session owes the agent because the daemon behind the
    /// socket is a DIFFERENT build than this server binary — taken exactly once, by the first tool
    /// result that reports it. `None` means "nothing to say" (the usual case).
    ///
    /// A long-lived MCP server survives reinstalls and daemon restarts, so its tool surface can be
    /// an old build's while brokering keeps working (authority is daemon-side). Detection only: the
    /// note tells the agent to restart the session; nothing refuses. Default `None` — an in-process
    /// transport (test fakes) IS this build by construction.
    fn take_build_skew_note(&self) -> Option<String> {
        None
    }

    /// Execute a grant by `request_id`; an HTTP verb returns its `executed` result unchanged.
    ///
    /// `probe.may_start()` is consulted BEFORE the Execute RPC — the daemon claims the
    /// grant and (for an HTTP verb) performs the provider action DURING that call, so pre-RPC is the
    /// only refusal that means "provably unstarted". Once the RPC is issued, its reply is the truth
    /// and is settled as such.
    fn execute_capability(
        &self,
        request_id: &str,
        probe: &dyn ShutdownProbe,
    ) -> Result<Value, AgentError> {
        self.execute_capability_gated(request_id, probe, None)
    }

    /// As [`Self::execute_capability`], with an optional REQUIRED daemon feature the claiming RPC
    /// must hold AT SEND TIME: the async surface's `async_execute_v1` gate would otherwise
    /// be a one-shot pre-check that a mid-call session re-mint (which renegotiates the feature set
    /// against whatever daemon is now behind the socket) silently bypasses — the forbidden blocking
    /// fallback. Refusal happens BEFORE the RPC: provably unclaimed.
    fn execute_capability_gated(
        &self,
        request_id: &str,
        probe: &dyn ShutdownProbe,
        required_feature: Option<&str>,
    ) -> Result<Value, AgentError> {
        if !probe.may_start() {
            return Err(AgentError::Transport(SHUTDOWN_BEFORE_START.into()));
        }
        // No agent-side custody accounting. A lost/ambiguous claim is the DAEMON'S durable
        // problem — the lease carries an HMAC-covered claim-time deadline and the overdue sweep
        // terminalizes it honestly. This side reports best-effort-fast, once.
        let cmd = AgentCommand::Execute {
            request_id: request_id.to_string(),
        };
        match required_feature {
            Some(f) => self.call_requiring(&cmd, f),
            None => self.call(&cmd),
        }
    }

    /// Run `cmd` REQUIRING the daemon to speak `feature` at send time — including across
    /// any mid-call session re-mint. Default: one up-front check + a plain call (an in-process test
    /// fake's feature set is fixed for the process lifetime — there is no re-mint to race); the
    /// SOCKET transport overrides this so the re-Hello-once recovery re-verifies the renegotiated
    /// feature set BEFORE replaying the claiming RPC (a downgraded daemon gets the legible skew
    /// refusal, never the replay).
    fn call_requiring(&self, cmd: &AgentCommand, feature: &str) -> Result<Value, AgentError> {
        if !self.has_feature(feature) {
            return Err(AgentError::Server(feature_skew_refusal(feature)));
        }
        self.call(cmd)
    }
}

/// The refusal an execute gets when the server decided to shut down BEFORE its claiming RPC was
/// issued — provably unstarted, nothing was claimed. Carries no detail about the grant.
const SHUTDOWN_BEFORE_START: &str =
    "server shutting down; the request was not executed — request it again";

/// The low-level, session-agnostic `agent.sock` ops the bridge's session cache is built on: mint a
/// session (`hello`) and run one command under a given session. Split out from [`SocketTransport`] so
/// the cache + re-`Hello`-once retry is unit-testable without a live socket.
trait WireOps {
    /// Mint a session; returns the id plus what the daemon advertised about itself — its negotiated
    /// feature labels and its build identity.
    fn hello(&self) -> Result<SessionHello, AgentError>;
    fn call_with_session(&self, cmd: &AgentCommand, session: &str) -> Result<Value, AgentError>;

    /// As [`Self::call_with_session`], but the connection deadline is clamped to
    /// `budget`. Default: ignore the budget (an in-process fake is instant and has no socket); the
    /// SOCKET op clamps the client timeout so a bounded tool call can't overrun on a slow read.
    fn call_with_session_bounded(
        &self,
        cmd: &AgentCommand,
        session: &str,
        _budget: Duration,
    ) -> Result<Value, AgentError> {
        self.call_with_session(cmd, session)
    }
}

/// The cached conversation session for one MCP process: lazily minted via `Hello` on first use,
/// reused for every subsequent call so a whole conversation threads onto ONE server-minted session,
/// and re-minted EXACTLY ONCE when the daemon reports the session expired (fail closed → recover).
///
/// The refresh is SINGLE-FLIGHT and the network `hello()` runs OUTSIDE the state lock —
/// when N workers need a session at once, one leader makes the one network call and every waiter
/// parks on the condvar for that attempt's result (success or failure, broadcast once, never one
/// serial dial per waiter). A leader that panics mid-`hello` cannot poison the lock (it is not held
/// there) and a guard still completes the attempt, so the next call refreshes fresh — a bad refresh
/// is never a permanent outage.
struct SessionCache {
    state: Mutex<SessionState>,
    refreshed: Condvar,
}

#[derive(Default)]
struct SessionState {
    session: Option<String>,
    /// The daemon's Hello-negotiated feature labels — empty until a hello succeeds,
    /// and empty stays FAIL CLOSED (no custody vocabulary assumed).
    features: Vec<String>,
    /// The in-band build-skew note owed to the agent, taken by the first tool result that
    /// carries it. Set at most once per process (see `build_skew_seen`).
    pending_build_note: Option<String>,
    /// Whether the build skew has already been reported (stderr + the in-band note) — a later
    /// re-`Hello` against the same skewed daemon must not re-pollute every tool result.
    build_skew_seen: bool,
    /// A refresh leader's `hello()` is in flight; callers wait for its result instead of dialing.
    refreshing: bool,
    /// Completed refresh attempts (success or failure) — a waiter keys off the change to know the
    /// attempt IT was waiting on finished.
    attempts: u64,
    /// The message of the most recent failed attempt, broadcast to that attempt's waiters.
    last_error: Option<String>,
}

/// Completes a refresh attempt on drop — refreshing cleared, the attempt counted, every waiter woken
/// — so a `hello()` that PANICS still releases its waiters instead of stranding them mid-refresh.
struct RefreshDone<'a> {
    cache: &'a SessionCache,
}

impl Drop for RefreshDone<'_> {
    fn drop(&mut self) {
        let mut g = self.cache.lock_state();
        g.refreshing = false;
        g.attempts += 1;
        // A panicked leader published neither a session nor an error; give waiters an honest one.
        if g.session.is_none() && g.last_error.is_none() {
            g.last_error = Some("session refresh aborted".to_string());
        }
        drop(g);
        self.cache.refreshed.notify_all();
    }
}

impl SessionCache {
    fn new() -> Self {
        Self {
            state: Mutex::new(SessionState::default()),
            refreshed: Condvar::new(),
        }
    }

    /// Recover from a poisoned state lock rather than propagating the panic to every later call:
    /// the guarded data is plain state, safe to read after an unwind.
    fn lock_state(&self) -> std::sync::MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// True when the daemon's Hello advertised `feature`. False before any successful
    /// hello and false for an old daemon — the caller fails closed either way.
    fn has_feature(&self, feature: &str) -> bool {
        self.lock_state().features.iter().any(|f| f == feature)
    }

    /// Take the in-band build-skew note, if one is owed. `None` after the first take —
    /// the agent is told once, not on every tool result.
    fn take_build_skew_note(&self) -> Option<String> {
        self.lock_state().pending_build_note.take()
    }

    /// Record what the daemon said it is. A build equal to ours is silence; anything else (including
    /// the ABSENT build of a daemon predating the field) is noted ONCE — on stderr for whoever runs
    /// the server, and in-band for the agent, which reads nothing else.
    fn observe_build(state: &mut SessionState, daemon_build: &str) {
        let Some(daemon) = cermet_ipc::build_skew(daemon_build) else {
            return;
        };
        if state.build_skew_seen {
            return;
        }
        state.build_skew_seen = true;
        let note = build_skew_note(daemon);
        eprintln!("cermet mcp: {note}");
        state.pending_build_note = Some(note);
    }

    /// The cached session id, minting one via `Hello` on first use.
    fn ensure<W: WireOps>(&self, w: &W) -> Result<String, AgentError> {
        self.session_for(w, None)
    }

    /// Force a fresh `Hello` after the daemon refused `stale` as expired. Race-safe under a shared
    /// cache: a cached id that already advanced past `stale` is returned with NO network call, so N
    /// workers hitting `SESSION_EXPIRED` on the same stale id collapse to exactly ONE re-mint.
    fn remint<W: WireOps>(&self, w: &W, stale: &str) -> Result<String, AgentError> {
        self.session_for(w, Some(stale))
    }

    /// Return a usable session id, refreshing single-flight when the cache is empty or still holds
    /// `stale`. Exactly one network call per outage: the leader dials OUTSIDE the lock; every waiter
    /// receives its published result (the fresh id, or the broadcast failure).
    fn session_for<W: WireOps>(&self, w: &W, stale: Option<&str>) -> Result<String, AgentError> {
        let mut g = self.lock_state();
        loop {
            match &g.session {
                Some(s) if Some(s.as_str()) != stale => return Ok(s.clone()),
                // The refused id: discard it and fall through to refresh.
                Some(_) => g.session = None,
                None => {}
            }
            if g.refreshing {
                // A leader's hello() is in flight — wait for THAT attempt to complete. The wait
                // is BOUNDED — a leader whose hello() somehow never returns must not strand every
                // waiter forever (the field failure was a bounded call hanging indefinitely).
                // hello() is itself IPC-timeout bounded (~30s), so a cap just above that is a robust
                // fail-closed backstop — a timed-out waiter surfaces an error, never blocks unbounded.
                let seen = g.attempts;
                let wait_deadline = Instant::now()
                    + cermet_ipc::client::DEFAULT_CALL_TIMEOUT
                    + Duration::from_secs(5);
                while g.refreshing && g.attempts == seen {
                    let remaining = wait_deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(AgentError::Transport(
                            "session refresh timed out waiting on the in-flight Hello".into(),
                        ));
                    }
                    let (g2, _) = self
                        .refreshed
                        .wait_timeout(g, remaining)
                        .unwrap_or_else(|e| e.into_inner());
                    g = g2;
                }
                if g.session.is_some() || g.refreshing {
                    // Either a session was published (re-check it against `stale` at the top), or
                    // a NEWER attempt is already in flight — the awaited attempt succeeded and its
                    // id was discarded as stale before this waiter re-acquired the lock.
                    // Re-enter the loop (and wait on the new attempt) rather than misreading the
                    // discard as a failure.
                    continue;
                }
                // No session and no refresh in flight: the awaited attempt genuinely failed —
                // surface its broadcast error, never retry per waiter.
                let msg = g
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "session refresh failed".to_string());
                return Err(AgentError::Transport(msg));
            }
            // Become the refresh leader. The network call runs OUTSIDE the lock; the guard
            // publishes completion (and wakes every waiter) even if hello() panics.
            g.refreshing = true;
            drop(g);
            let done = RefreshDone { cache: self };
            let res = w.hello();
            let mut g2 = self.lock_state();
            match &res {
                Ok(hello) => {
                    g2.session = Some(hello.session_id.clone());
                    g2.features = hello.features.clone();
                    // The same frame says WHICH BUILD answered. Compared here, once per
                    // session mint, on the client side only.
                    Self::observe_build(&mut g2, &hello.build);
                    g2.last_error = None;
                }
                Err(e) => g2.last_error = Some(e.to_string()),
            }
            drop(g2);
            drop(done);
            return res.map(|hello| hello.session_id);
        }
    }

    /// Run `cmd` under the cached session, re-`Hello`ing ONCE (then retrying) if the daemon refuses
    /// the id as expired. A second expiry surfaces the error rather than looping.
    fn call<W: WireOps>(&self, w: &W, cmd: &AgentCommand) -> Result<Value, AgentError> {
        let sid = self.ensure(w)?;
        match w.call_with_session(cmd, &sid) {
            Err(AgentError::Server(reason)) if reason == SESSION_EXPIRED => {
                let fresh = self.remint(w, &sid)?;
                w.call_with_session(cmd, &fresh)
            }
            other => other,
        }
    }

    /// As [`SessionCache::call`], but the daemon RPC is clamped to `budget` — a bounded
    /// tool call (status long-poll / ambiguous reconcile) honors its advertised wait even when the
    /// read is slow/contended. The one re-`Hello` retry keeps the same clamp.
    fn call_within<W: WireOps>(
        &self,
        w: &W,
        cmd: &AgentCommand,
        budget: Duration,
    ) -> Result<Value, AgentError> {
        let sid = self.ensure(w)?;
        match w.call_with_session_bounded(cmd, &sid, budget) {
            Err(AgentError::Server(reason)) if reason == SESSION_EXPIRED => {
                let fresh = self.remint(w, &sid)?;
                w.call_with_session_bounded(cmd, &fresh, budget)
            }
            other => other,
        }
    }

    /// As [`SessionCache::call`], but `feature` must hold at EVERY send — including the
    /// replay after a re-mint. The re-Hello renegotiates the feature set against whatever daemon is
    /// now behind the socket (exactly the mid-session rebuild/downgrade window), so a one-shot
    /// pre-check upstream is not enough: the replay re-verifies and a downgraded daemon gets the
    /// legible skew refusal BEFORE the claiming RPC (provably unclaimed), never a silent replay.
    fn call_requiring<W: WireOps>(
        &self,
        w: &W,
        cmd: &AgentCommand,
        feature: &str,
    ) -> Result<Value, AgentError> {
        let sid = self.ensure(w)?;
        if !self.has_feature(feature) {
            return Err(AgentError::Server(feature_skew_refusal(feature)));
        }
        match w.call_with_session(cmd, &sid) {
            Err(AgentError::Server(reason)) if reason == SESSION_EXPIRED => {
                let fresh = self.remint(w, &sid)?;
                if !self.has_feature(feature) {
                    return Err(AgentError::Server(feature_skew_refusal(feature)));
                }
                w.call_with_session(cmd, &fresh)
            }
            other => other,
        }
    }
}

/// The production transport: each call is one short-lived `agent.sock` connection, threaded onto the
/// process-lifetime conversation session held in [`SessionCache`].
pub struct SocketTransport {
    pub socket: PathBuf,
    /// The agent DISPLAY name stamped onto the session (from `CERMET_AGENT_NAME`).
    agent: String,
    /// The human's model declaration, read ONCE at startup from [`AGENT_MODEL_ENV`].
    model: Option<String>,
    /// What the MCP client reported about itself at `initialize`. Interior mutability because the
    /// handshake lands after the transport is built and before the session is lazily minted — which
    /// is exactly the window that makes capturing it possible at all.
    client: Mutex<Option<(String, Option<String>)>>,
    cache: SessionCache,
}

impl SocketTransport {
    pub fn new(socket: PathBuf, agent: String) -> Self {
        Self {
            socket,
            agent,
            model: std::env::var(AGENT_MODEL_ENV)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            client: Mutex::new(None),
            cache: SessionCache::new(),
        }
    }
}

impl WireOps for SocketTransport {
    fn hello(&self) -> Result<SessionHello, AgentError> {
        // The session is minted LAZILY, on the first tool call — which is after `initialize` — so by
        // now the client's self-report is in hand. That ordering is what lets one message carry both
        // channels instead of needing a second one.
        let client = self
            .client
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        super::hello(
            &self.socket,
            &self.agent,
            super::SelfReport {
                client_name: client.as_ref().map(|(name, _)| name.as_str()),
                client_version: client.as_ref().and_then(|(_, v)| v.as_deref()),
                model: self.model.as_deref(),
            },
        )
    }

    fn call_with_session(&self, cmd: &AgentCommand, session: &str) -> Result<Value, AgentError> {
        super::call_with_session(&self.socket, cmd, Some(session))
    }

    fn call_with_session_bounded(
        &self,
        cmd: &AgentCommand,
        session: &str,
        budget: Duration,
    ) -> Result<Value, AgentError> {
        // Clamp the connection's read deadline to the caller's remaining budget.
        super::call_with_session_bounded(&self.socket, cmd, Some(session), budget)
    }
}

impl AgentTransport for SocketTransport {
    fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
        self.cache.call(self, cmd)
    }

    fn declare_client(&self, name: Option<&str>, version: Option<&str>) {
        let Some(name) = name.map(str::trim).filter(|name| !name.is_empty()) else {
            return;
        };
        *self
            .client
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
            name.to_string(),
            version
                .map(str::trim)
                .filter(|version| !version.is_empty())
                .map(str::to_string),
        ));
    }

    /// The bounded daemon RPC threads through the same session cache (one re-`Hello`
    /// retry), so a `request_status` long-poll honors its wait cap end-to-end.
    fn call_within(&self, cmd: &AgentCommand, budget: Duration) -> Result<Value, AgentError> {
        self.cache.call_within(self, cmd, budget)
    }

    /// Mint/reuse the conversation session so the Hello feature negotiation is established.
    fn ensure_session(&self) -> Result<(), AgentError> {
        self.cache.ensure(self).map(|_| ())
    }

    /// The Hello-negotiated answer: false until a session proved the feature.
    fn has_feature(&self, feature: &str) -> bool {
        self.cache.has_feature(feature)
    }

    /// The skew the Hello observed, owed to the agent once.
    fn take_build_skew_note(&self) -> Option<String> {
        self.cache.take_build_skew_note()
    }

    /// The feature requirement rides INTO the session-bound call, so the re-Hello-once
    /// recovery re-verifies the renegotiated feature set before any replay.
    fn call_requiring(&self, cmd: &AgentCommand, feature: &str) -> Result<Value, AgentError> {
        self.cache.call_requiring(self, cmd, feature)
    }
}

/// Run the stdio server against the resolved `agent.sock` path until stdin EOF. Returns the loop's
/// I/O result; a client that closes the pipe is a graceful shutdown, not an error. The session's
/// agent DISPLAY name comes from `CERMET_AGENT_NAME` (default `mcp-agent`).
pub fn run(socket: PathBuf) -> io::Result<()> {
    let agent = std::env::var("CERMET_AGENT_NAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_AGENT_NAME.to_string());
    let transport = SocketTransport::new(socket, agent);
    // Reads run on a dedicated thread (see `serve`), so the handle must be Send —
    // `BufReader<Stdin>` rather than the thread-bound `StdinLock`. stdin is a real fd, so
    // the hangup watcher observes the client's close independently of the unread backlog.
    serve_inner_watched(
        transport,
        io::BufReader::new(io::stdin()),
        io::stdout(),
        ShutdownTimings::default(),
        Some(0),
    )
}

/// The write queue's depth (whole serialized lines) and the bound on how long a caller retries a
/// FULL queue before declaring the sink stalled-dead: 64 queued lines with zero drain
/// progress for 10s is a client that stopped reading, not a slow one.
const WRITE_QUEUE_DEPTH: usize = 64;
const WRITE_STALL_TIMEOUT: Duration = Duration::from_millis(10_000);
const ENQUEUE_RETRY: Duration = Duration::from_millis(25);
/// The CEILING on how long shutdown waits for the writer task to flush the already-admitted lines
/// (healthy sink: instants). A sink still blocked past this is detached — deactivation never waits
/// on blocked I/O. It is a ceiling only: the bound actually used is
/// [`ShutdownTimings::flush_join`], which never exceeds the deployment's own shutdown budget.
const FLUSH_JOIN: Duration = Duration::from_secs(5);

/// One-writer, many-worker output sink. The actual I/O runs on a dedicated
/// WRITER TASK fed by a bounded queue of whole serialized lines, so no caller ever performs (or
/// waits under a lock held across) blocking I/O: `is_failed`/`deactivate` stay wakeable no matter
/// how stalled stdout is. The state lock guards ADMISSION only — enqueue (`try_send`, non-blocking)
/// happens under it, so admission is atomic with deactivation/failure and lines can never
/// interleave (a single writer thread writes whole lines in FIFO order). Fail closed: the FIRST
/// write/flush error is terminal — the task stops, the sink refuses everything after (a prefix may
/// have torn the client's framing), and dispatch winds down. A caller facing a FULL queue retries
/// non-blockingly up to `WRITE_STALL_TIMEOUT`, then declares the sink failed. Cloneable so a future
/// mid-call notification emitter can share the very same sink.
enum SinkState {
    Active(std::sync::mpsc::SyncSender<String>),
    /// The first write/flush error landed (possibly mid-line), or the queue stalled out:
    /// irreversible, nothing further is written, dispatch winds down.
    Failed,
    /// Orderly shutdown: no new admissions; already-queued lines are flushed by the writer task
    /// (bounded by [`WriterTask::finish`]), late responses are dropped.
    Closed,
}

struct SharedWriter {
    state: Arc<Mutex<SinkState>>,
}

impl Clone for SharedWriter {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

/// The handle to the writer task, kept by `serve_inner` so shutdown can flush BOUNDED: a healthy
/// sink drains its queue before serve returns; a stalled one is detached at the bound.
struct WriterTask {
    handle: std::thread::JoinHandle<()>,
}

impl WriterTask {
    fn finish(self, bound: Duration) {
        let deadline = Instant::now() + bound;
        while !self.handle.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if self.handle.is_finished() {
            let _ = self.handle.join();
        }
        // Not finished: the sink is stalled mid-write — detach rather than wait on blocked I/O.
    }
}

impl SharedWriter {
    fn new<W: Write + Send + 'static>(mut writer: W) -> (Self, WriterTask) {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(WRITE_QUEUE_DEPTH);
        let state = Arc::new(Mutex::new(SinkState::Active(tx)));
        let task_state = Arc::clone(&state);
        let handle = std::thread::spawn(move || {
            // Ends when every sender is gone (deactivation) after draining the queued lines, or on
            // the first write error (terminal).
            for line in rx {
                if writer
                    .write_all(line.as_bytes())
                    .and_then(|()| writer.flush())
                    .is_err()
                {
                    let mut g = task_state.lock().unwrap_or_else(|e| e.into_inner());
                    *g = SinkState::Failed;
                    return;
                }
            }
        });
        (Self { state }, WriterTask { handle })
    }

    /// Take the state lock, recovering from poison FAIL-CLOSED (a poisoned sink becomes `Failed`,
    /// never resumed as if healthy). No I/O ever happens under this lock.
    fn lock(&self) -> std::sync::MutexGuard<'_, SinkState> {
        match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                let mut g = poisoned.into_inner();
                *g = SinkState::Failed;
                g
            }
        }
    }

    /// Serialize `resp` to one newline-terminated line and ADMIT it to the writer task's queue —
    /// non-blocking `try_send` under the state lock (atomic with deactivation/failure), retrying a
    /// full queue up to `WRITE_STALL_TIMEOUT` before declaring the sink stalled-dead.
    /// On a failed/closed sink the line is dropped (the caller has nowhere to send it).
    fn write_response(&self, resp: &Value) -> io::Result<()> {
        let mut body = serde_json::to_string(resp).unwrap_or_else(|_| {
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}"#
                .to_string()
        });
        body.push('\n');
        let deadline = Instant::now() + WRITE_STALL_TIMEOUT;
        loop {
            {
                let mut guard = self.lock();
                match &*guard {
                    SinkState::Active(tx) => match tx.try_send(body) {
                        Ok(()) => return Ok(()),
                        Err(std::sync::mpsc::TrySendError::Full(b)) => body = b,
                        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                            // The writer task died on a write error; it set Failed under this same
                            // lock unless we raced its exit — settle the state either way.
                            *guard = SinkState::Failed;
                            return Err(io::Error::other("the response writer is gone"));
                        }
                    },
                    _ => return Ok(()),
                }
            }
            if Instant::now() >= deadline {
                // Zero drain progress on a full queue for the whole stall budget: the client
                // stopped reading. Terminal — never block shutdown on it.
                let mut guard = self.lock();
                if matches!(&*guard, SinkState::Active(_)) {
                    *guard = SinkState::Failed;
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stdout stalled; the sink is failed",
                ));
            }
            std::thread::sleep(ENQUEUE_RETRY);
        }
    }

    /// Orderly shutdown: closes ADMISSION atomically (same lock as enqueue — nothing admitted after
    /// this is ever written) and drops the sender, so the writer task drains what was already
    /// queued and exits. Never waits on I/O; the bounded flush is [`WriterTask::finish`]'s job. A
    /// sink already failed stays failed.
    fn deactivate(&self) {
        let mut guard = self.lock();
        if matches!(&*guard, SinkState::Active(_)) {
            *guard = SinkState::Closed;
        }
    }

    /// True once the sink is terminal (write error or stall) — dispatch's wind-down signal.
    fn is_failed(&self) -> bool {
        matches!(&*self.lock(), SinkState::Failed)
    }
}

/// Why the server's input ended — recorded on the phase so shutdown policy is EXPLICIT per cause
/// (today both drain identically; the enum keeps the distinction legible instead of implicit).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ShutdownCause {
    /// stdin reached EOF / the pipe hung up: the client left (or finished its one-shot batch).
    Eof,
    /// The output sink failed terminally: no answer can reach the client anymore.
    SinkFailure,
    /// A stdin READ ERROR ended the stream: terminal like EOF, but DISTINCT — never
    /// mislabeled `client_eof` (the client did not cleanly leave) and never left `unknown`.
    ReadError,
}

/// The server lifecycle as ONE explicit phase machine: every shutdown policy question —
/// may new work start? are children killed? — is a pure function of the current phase, never a
/// scattering of booleans reconstructed procedurally. Phases only advance, never regress.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ShutdownPhase {
    /// Serving normally.
    Running,
    /// The input ended (`cause`) at `anchor`: the remaining backlog gets one bounded service
    /// window anchored there and in-flight workers drain naturally. New claims may
    /// still start — a queued request admitted within the window is served whole.
    DrainingBacklog {
        cause: ShutdownCause,
        anchor: Instant,
    },
    /// The shutdown decision: nothing NEW starts — no claiming RPC, no child spawn —
    /// while already-started executions get the kill grace to finish on their own.
    RefusingClaims,
    /// The grace elapsed: running children's process groups are killed so their honest
    /// outcomes can be reported fast.
    Killing,
    /// The bounded join of started workers (a worker inside a daemon RPC is socket-timeout
    /// bounded); past the bound it is detached — the daemon's lease deadline owns anything
    /// unreported.
    Joining,
    /// Admission is closed; the writer task flushes already-queued responses, bounded.
    Flushing,
    /// Serve has returned.
    Stopped,
}

impl ShutdownPhase {
    /// May a NEW execution (claiming RPC or child spawn) start in this phase?
    fn may_start(self) -> bool {
        matches!(
            self,
            ShutdownPhase::Running | ShutdownPhase::DrainingBacklog { .. }
        )
    }

    /// Are running children's process groups killed in this phase?
    fn kill_now(self) -> bool {
        matches!(
            self,
            ShutdownPhase::Killing
                | ShutdownPhase::Joining
                | ShutdownPhase::Flushing
                | ShutdownPhase::Stopped
        )
    }
}

/// Shared accounting for the `tools/call` worker fan-out: two COUNTS (how many
/// workers, how many started executions) plus the ONE lifecycle phase. Nothing else.
struct PoolState {
    /// Workers currently running (admitted, not yet exited).
    in_flight: usize,
    /// Workers whose tool call has STARTED an execution (a claiming RPC was issued): these are
    /// joined at shutdown — a started action gets its bounded chance to land its record fast.
    started: usize,
    /// The server lifecycle phase — the single source of shutdown policy.
    phase: ShutdownPhase,
    /// The input's end cause, persisted independently of the phase (which advances
    /// past `DrainingBacklog` and drops its inline cause). Read by a killed run's `cancel_cause`
    /// (so the receipt names the bridge cause).
    cause: Option<ShutdownCause>,
}

impl ShutdownCause {
    /// The stable, secret-free label for a killed-run receipt.
    fn label(self) -> &'static str {
        match self {
            ShutdownCause::Eof => "client_eof",
            ShutdownCause::SinkFailure => "sink_failure",
            ShutdownCause::ReadError => "read_error",
        }
    }
}

/// A capped fan-out of `tools/call` worker threads. Admission is NONBLOCKING: the read
/// thread never waits on capacity — a full pool refuses the job and the caller answers with an
/// explicit busy error, so inline traffic (ping/initialize) and EOF keep flowing regardless of how
/// many executions are in flight.
struct WorkerPool {
    cap: usize,
    state: Arc<(Mutex<PoolState>, Condvar)>,
}

/// One admitted worker's handle — its [`ShutdownProbe`] — and the slot guard: Drop releases the
/// slot (and its started mark) on a normal return AND on an unwinding panic, so a panicking worker
/// never leaks a slot or stalls the drain.
struct WorkerSlot {
    state: Arc<(Mutex<PoolState>, Condvar)>,
    marked: std::cell::Cell<bool>,
}

impl ShutdownProbe for WorkerSlot {
    /// The point of no return for shutdown accounting: consulted BEFORE a claiming RPC or
    /// a child spawn. False once the server has decided to shut down — nothing new may start when
    /// no server will stay alive to record it. The first true answer marks the worker STARTED, so
    /// the shutdown drain joins it through to its terminal record.
    fn may_start(&self) -> bool {
        let (lock, _) = &*self.state;
        let mut s = lock.lock().unwrap_or_else(|e| e.into_inner());
        if !s.phase.may_start() {
            return false;
        }
        if !self.marked.get() {
            s.started += 1;
            self.marked.set(true);
        }
        true
    }

    /// True once the shutdown grace elapsed: a running child polls this and its process
    /// group is killed so its terminal report can land before the bounded join returns.
    fn kill_now(&self) -> bool {
        let (lock, _) = &*self.state;
        lock.lock()
            .unwrap_or_else(|e| e.into_inner())
            .phase
            .kill_now()
    }

    /// The recorded bridge shutdown cause (defaults to `unknown` before one is set) —
    /// stamped into a killed run's receipt so it names the bridge, not "server shutdown".
    fn cancel_cause(&self) -> &'static str {
        let (lock, _) = &*self.state;
        lock.lock()
            .unwrap_or_else(|e| e.into_inner())
            .cause
            .map(ShutdownCause::label)
            .unwrap_or("unknown")
    }
}

impl Drop for WorkerSlot {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.state;
        let mut s = lock.lock().unwrap_or_else(|e| e.into_inner());
        s.in_flight = s.in_flight.saturating_sub(1);
        if self.marked.get() {
            s.started = s.started.saturating_sub(1);
        }
        // Teardown releases COUNTS only. There is no agent-side custody debt to erase or
        // preserve — the daemon's signed lease deadline + overdue sweep own any unreported lease;
        // an unattributed counter here could never be reconciled after the worker died.
        drop(s);
        cvar.notify_all();
    }
}

impl WorkerPool {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            state: Arc::new((
                Mutex::new(PoolState {
                    in_flight: 0,
                    started: 0,
                    phase: ShutdownPhase::Running,
                    cause: None,
                }),
                Condvar::new(),
            )),
        }
    }

    /// Spawn `job` on a worker thread if a slot is free; return false (dropping the job unrun) when
    /// the pool is at cap — the caller answers busy instead of parking the read thread.
    fn try_spawn<F>(&self, job: F) -> bool
    where
        F: FnOnce(&WorkerSlot) + Send + 'static,
    {
        let (lock, _) = &*self.state;
        {
            let mut s = lock.lock().unwrap_or_else(|e| e.into_inner());
            if s.in_flight >= self.cap {
                return false;
            }
            s.in_flight += 1;
        }
        let state = Arc::clone(&self.state);
        std::thread::spawn(move || {
            // The slot's Drop releases the reservation on ANY exit (return or unwind).
            let slot = WorkerSlot {
                state,
                marked: std::cell::Cell::new(false),
            };
            job(&slot);
        });
        true
    }

    /// Record that the input ended: Running → DrainingBacklog{cause, anchor}. Called by dispatch
    /// the moment EOF/hangup/sink-failure is observed, so `may_start` policy and the drain's clock
    /// share ONE phase transition. Idempotent past Running (phases never regress).
    fn note_input_ended(&self, cause: ShutdownCause, anchor: Instant) {
        let (lock, cvar) = &*self.state;
        let mut s = lock.lock().unwrap_or_else(|e| e.into_inner());
        if s.phase == ShutdownPhase::Running {
            s.phase = ShutdownPhase::DrainingBacklog { cause, anchor };
            // Persist the cause outside the phase so it survives the phase's later
            // advance (RefusingClaims → Killing …) — the killed-run receipt
            // read it after `DrainingBacklog` is gone.
            s.cause = Some(cause);
        }
        drop(s);
        cvar.notify_all();
    }

    /// The shutdown drain — the phase machine walked forward, each transition bounded.
    /// DrainingBacklog runs out its anchored window while workers finish
    /// naturally → RefusingClaims (nothing new starts) for the kill grace → Killing (children's
    /// process groups killed) → Joining (bounded join of admitted workers so an async run's awakened
    /// tool worker can enqueue its settled response before stdout closes; a worker still parked in a
    /// daemon RPC is detached at the bound). The caller advances to Flushing/Stopped around the sink.
    fn drain(&self, timings: &ShutdownTimings) {
        let (lock, cvar) = &*self.state;
        let s = lock.lock().unwrap_or_else(|e| e.into_inner());
        let anchor = match s.phase {
            ShutdownPhase::DrainingBacklog { anchor, .. } => anchor,
            _ => Instant::now(),
        };
        let window = (anchor + timings.drain).saturating_duration_since(Instant::now());
        let mut s = Self::wait_while(cvar, s, window, |s| s.in_flight > 0);
        s.phase = ShutdownPhase::RefusingClaims;
        let mut s = Self::wait_while(cvar, s, timings.kill_grace, |s| s.started > 0);
        s.phase = ShutdownPhase::Killing;
        drop(s);
        cvar.notify_all(); // children poll kill_now; wake anything parked on the pool
        let (lock2, _) = &*self.state;
        let mut s = lock2.lock().unwrap_or_else(|e| e.into_inner());
        s.phase = ShutdownPhase::Joining;
        let _joined = Self::wait_while(cvar, s, timings.kill_join, |s| s.in_flight > 0);
    }

    /// Advance to a terminal bookkeeping phase (Flushing / Stopped) — policy-relevant only for
    /// legibility and the phase invariants; both already refuse starts and kill children.
    fn set_phase(&self, phase: ShutdownPhase) {
        let (lock, cvar) = &*self.state;
        let mut s = lock.lock().unwrap_or_else(|e| e.into_inner());
        s.phase = phase;
        drop(s);
        cvar.notify_all();
    }

    /// Condvar-wait while `pending` holds, up to `timeout`. Returns the (re-acquired) guard.
    fn wait_while<'a>(
        cvar: &Condvar,
        mut guard: std::sync::MutexGuard<'a, PoolState>,
        timeout: Duration,
        pending: impl Fn(&PoolState) -> bool,
    ) -> std::sync::MutexGuard<'a, PoolState> {
        let deadline = Instant::now() + timeout;
        while pending(&guard) {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (g, _) = cvar
                .wait_timeout(guard, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            guard = g;
        }
        guard
    }
}

/// One background run's shared state — its terminal result handed off from the
/// run thread to whoever is waiting (the `execute_capability` call, or a later `request_status`
/// long-poll). The run OUTLIVES the tool call that started it (but never the MCP server — normal
/// shutdown still kills it via the shared WorkerPool phase), so the receipt is retrievable after the
/// call returns a handle. Keyed by `request_id` in the [`RunSupervisor`]; never a grant id.
struct RunRecord {
    inner: Mutex<RunState>,
    done: Condvar,
    effect_id: Option<String>,
}

enum RunState {
    /// The background thread is still executing.
    Running,
    /// The run settled — its terminal reply (or a terminal error message) is ready.
    Done(RunDone),
}

/// How a settled run's custody stands: the classification a restart decision may trust.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Settle {
    /// A definitive answer for this handle (a receipt, a denial, an already-used refusal): dedup —
    /// re-executing is pointless and the stored result returns idempotently.
    Final,
    /// PROVABLY ended without claiming the grant (a connect failure or pre-RPC refusal): a fresh
    /// `execute_capability` may restart it.
    Retryable,
    /// A post-send failure — the grant MAY have durably executed with only the reply lost. Never
    /// blindly restarted: reconciled through the durable principal-bound status first.
    Ambiguous,
}

/// A settled run's outcome, cloned out to every waiter.
#[derive(Clone)]
struct RunDone {
    /// `Ok(reply)` is the daemon's terminal receipt; `Err(message)` is a terminal error string.
    result: Result<Value, String>,
    settle: Settle,
    effect_id: Option<String>,
    effect_outcome: Option<EffectOutcome>,
}

impl RunRecord {
    fn new(effect_id: Option<String>) -> Self {
        Self {
            inner: Mutex::new(RunState::Running),
            done: Condvar::new(),
            effect_id,
        }
    }

    fn effect_id(&self) -> Option<String> {
        self.effect_id.clone().or_else(|| match &*self.lock() {
            RunState::Done(done) => done.effect_id.clone(),
            RunState::Running => None,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RunState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The run thread's terminal handoff: classify the execute result and wake every waiter.
    fn complete(&self, res: Result<Value, AgentError>) {
        let done = classify_run(res);
        *self.lock() = RunState::Done(done);
        self.done.notify_all();
    }

    /// A snapshot of the settled outcome, or `None` while still running.
    fn peek(&self) -> Option<RunDone> {
        match &*self.lock() {
            RunState::Done(d) => Some(d.clone()),
            RunState::Running => None,
        }
    }

    /// True only for a settled-but-RETRYABLE record (PROVABLY ended un-run) — the dedup returns a
    /// Running, FINAL, or AMBIGUOUS record as-is, but restarts a retryable one.
    fn is_retryable(&self) -> bool {
        matches!(&*self.lock(), RunState::Done(d) if d.settle == Settle::Retryable)
    }

    /// True for a settled record whose custody is AMBIGUOUS (a post-send failure — the grant may
    /// have durably executed). Never restarted blindly; reconciled through durable status first.
    fn is_ambiguous(&self) -> bool {
        matches!(&*self.lock(), RunState::Done(d) if d.settle == Settle::Ambiguous)
    }

    /// Block up to `budget` for the run to settle; `Some(done)` if it did, `None` on timeout.
    fn wait_terminal(&self, budget: Duration) -> Option<RunDone> {
        let deadline = Instant::now() + budget;
        let mut g = self.lock();
        loop {
            if let RunState::Done(d) = &*g {
                return Some(d.clone());
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (g2, _) = self
                .done
                .wait_timeout(g, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            g = g2;
        }
    }
}

/// Classify a background execute's result into a settled [`RunDone`] (fail closed about
/// custody). A receipt / server refusal is FINAL. RETRYABLE is reserved for results that PROVABLY
/// left the grant unclaimed: a connect failure (no frame was ever sent), the shutdown-before-start
/// refusal, and a pre-claim feature-skew refusal. Every other
/// transport failure is AMBIGUOUS — the Execute frame may have been sent and durably executed with
/// only the reply lost — and is never blindly restarted; the caller reconciles it through the
/// durable principal-bound status first.
fn classify_run(res: Result<Value, AgentError>) -> RunDone {
    let effect_id = match &res {
        Ok(value) => value
            .get("effect_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        Err(error) => error.effect_id().map(str::to_string),
    };
    let effect_outcome = match &res {
        Ok(value) => value
            .get("effect_outcome")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        Err(error) => error.effect_outcome(),
    };
    let (result, settle) = match res {
        Ok(v) => (Ok(v), Settle::Final),
        // A connect failure never opened the connection — provably no claim.
        Err(e @ AgentError::Connect(_)) => (Err(e.to_string()), Settle::Retryable),
        // The shutdown gate refused BEFORE the RPC — provably unstarted.
        Err(AgentError::Transport(m)) if m == SHUTDOWN_BEFORE_START => (Err(m), Settle::Retryable),
        // The feature-skew refusal fires BEFORE the RPC — provably unclaimed.
        Err(AgentError::Server(m)) if m.starts_with(SKEW_PREFIX) => (Err(m), Settle::Retryable),
        Err(AgentError::ServerEffect { reason, .. }) => (Err(reason), Settle::Final),
        // Any other transport failure is post-send-possible: AMBIGUOUS custody.
        Err(e @ AgentError::Transport(_)) => (Err(e.to_string()), Settle::Ambiguous),
        // A server refusal (already-used / denied / expired / authority-drift) is final for this handle.
        Err(e) => (Err(e.to_string()), Settle::Final),
    };
    RunDone {
        result,
        settle,
        effect_id,
        effect_outcome,
    }
}

/// The capped registry of in-flight/settled background runs, keyed by
/// `request_id`. It owns DEDUP (a duplicate `execute_capability` for a live run never starts a
/// second) and RESULT HANDOFF (the receipt survives the tool call that started it). Run THREADS live
/// on the supervisor's OWN [`WorkerPool`] — a SECOND pool, distinct from the tool-call fan-out so a
/// blocking `execute_capability` call (which holds a tool-call slot while it waits) can never
/// deadlock against the background run it is waiting on. The run pool reuses ALL the battle-tested
/// WorkerPool machinery (worker cap + the shutdown phase's `may_start`/`kill_now`/drain), so normal
/// shutdown kills+reports the background runs exactly as it does inline executes — the async run
/// outlives the CALL, never the cermet MCP process.
struct RunSupervisor {
    runs: Mutex<HashMap<String, Arc<RunRecord>>>,
    pool: WorkerPool,
    cap: usize,
}

impl RunSupervisor {
    fn new(run_cap: usize, map_cap: usize) -> Self {
        Self {
            runs: Mutex::new(HashMap::new()),
            pool: WorkerPool::new(run_cap),
            cap: map_cap,
        }
    }

    fn get(&self, request_id: &str) -> Option<Arc<RunRecord>> {
        self.runs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(request_id)
            .cloned()
    }

    /// Walk the run pool's shutdown drain (kill + report the background runs), then park it Stopped.
    fn shutdown(&self, timings: &ShutdownTimings) {
        self.pool.drain(timings);
        self.pool.set_phase(ShutdownPhase::Stopped);
    }

    /// Drop a SETTLED record after reconciliation proved a restart safe. A Running record
    /// is never cleared (its thread still owns the handoff).
    fn clear_settled(&self, request_id: &str) {
        let mut map = self.runs.lock().unwrap_or_else(|e| e.into_inner());
        if map.get(request_id).is_some_and(|r| r.peek().is_some()) {
            map.remove(request_id);
        }
    }

    /// Start (or dedup) the background run for `request_id`. Returns the shared record. Holds the map
    /// lock across the pool spawn so a concurrent duplicate can never see a half-registered record
    /// (it either dedups onto the live one or is refused busy). Fails closed with [`RUN_POOL_BUSY`]
    /// when the run pool is at cap — the grant is NOT claimed (admission precedes the RPC).
    fn start<T: AgentTransport + Send + Sync + 'static>(
        &self,
        request_id: &str,
        transport: &Arc<T>,
        effect_id: Option<&str>,
    ) -> Result<Arc<RunRecord>, &'static str> {
        let mut map = self.runs.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(rec) = map.get(request_id) {
            // A live run, a FINAL settled one, AND an AMBIGUOUS one all dedup (single execution /
            // idempotent result — an ambiguous record restarts only after the caller's
            // durable-status reconciliation explicitly cleared it). Only a RETRYABLE record
            // (provably ended un-run) falls through to a fresh start.
            if !rec.is_retryable() {
                return Ok(Arc::clone(rec));
            }
        }
        self.evict_settled_if_full(&mut map);
        let rec = Arc::new(RunRecord::new(effect_id.map(str::to_string)));
        let rec_bg = Arc::clone(&rec);
        let t = Arc::clone(transport);
        let rid = request_id.to_string();
        let spawned = self.pool.try_spawn(move |slot| {
            // The run's OWN pool slot is the shutdown probe: `may_start` gates the claim, `kill_now`
            // kills the child past the grace — the async run is fully shutdown-governed.
            // The async claim REQUIRES `async_execute_v1` at send time — a mid-call
            // session re-mint against a downgraded daemon refuses before the RPC, never replays.
            let res = t.execute_capability_gated(
                &rid,
                slot,
                Some(cermet_ipc::wire::FEATURE_ASYNC_EXECUTE),
            );
            rec_bg.complete(res);
        });
        if !spawned {
            return Err(RUN_POOL_BUSY);
        }
        map.insert(request_id.to_string(), Arc::clone(&rec));
        Ok(rec)
    }

    /// Keep the map bounded: when full, drop SETTLED records (their receipts stay durably
    /// reconstructable from the daemon ledger) — never a Running one.
    fn evict_settled_if_full(&self, map: &mut HashMap<String, Arc<RunRecord>>) {
        if map.len() < self.cap {
            return;
        }
        let settled: Vec<String> = map
            .iter()
            .filter(|(_, r)| r.peek().is_some())
            .map(|(k, _)| k.clone())
            .collect();
        for k in settled {
            map.remove(&k);
            if map.len() < self.cap {
                break;
            }
        }
    }
}

/// The dispatch loop: one JSON-RPC message per line in, one response line out.
/// `tools/call` requests are dispatched onto capped worker threads (each with its own daemon
/// connection) so a long execute never serializes a fleet of parallel agents; `initialize`,
/// `tools/list`, `ping`, and notifications stay inline. All responses go through ONE shared,
/// whole-line-atomic writer, so out-of-order worker completions never interleave — JSON-RPC ids
/// correlate request↔response. A line that is not valid JSON yields a parse-error response with a
/// null id rather than aborting the stream. Blocking reads live on a dedicated thread feeding a
/// channel, so a terminal sink failure winds the server down promptly even when stdin is
/// open but quiet. EOF (or that failure) stops new work and runs the bounded shutdown drain:
/// started executions reach their terminal records, nothing new starts, hung
/// children are killed and reported — the exit is bounded end-to-end.
pub fn serve<T, R, W>(transport: T, reader: R, writer: W) -> io::Result<()>
where
    T: AgentTransport + Send + Sync + 'static,
    R: BufRead + Send + 'static,
    W: Write + Send + 'static,
{
    serve_inner(transport, reader, writer, ShutdownTimings::default())
}

fn serve_inner<T, R, W>(
    transport: T,
    reader: R,
    writer: W,
    timings: ShutdownTimings,
) -> io::Result<()>
where
    T: AgentTransport + Send + Sync + 'static,
    R: BufRead + Send + 'static,
    W: Write + Send + 'static,
{
    serve_inner_watched(transport, reader, writer, timings, None)
}

/// As [`serve_inner`], with an optional raw fd to WATCH FOR HANGUP: when the reader is
/// backed by a real pipe, `poll(2)`-observing POLLHUP on its fd sees the client close its end the
/// instant it happens — independent of how much unread backlog sits in the kernel pipe or the
/// bounded reader queue. Readers without an fd (in-memory tests) rely on EOF-as-read alone.
fn serve_inner_watched<T, R, W>(
    transport: T,
    reader: R,
    writer: W,
    timings: ShutdownTimings,
    hangup_fd: Option<std::os::fd::RawFd>,
) -> io::Result<()>
where
    T: AgentTransport + Send + Sync + 'static,
    R: BufRead + Send + 'static,
    W: Write + Send + 'static,
{
    let transport = Arc::new(transport);
    let (writer, writer_task) = SharedWriter::new(writer);
    let pool = Arc::new(WorkerPool::new(WORKER_CAP));
    // The background-run registry (dedup + result handoff) with its OWN worker
    // pool (bounded run fan-out + shutdown kill/report), distinct from the tool-call `pool` so a
    // waiting execute call never deadlocks against the background run it awaits.
    let supervisor = Arc::new(RunSupervisor::new(WORKER_CAP, RUN_SUPERVISOR_CAP));
    // The listChanged baseline (the requestable-verb set as last served via tools/list).
    let verbs = Arc::new(VerbSurface::new());

    // The blocking reads happen on their own thread; the dispatch loop selects on this
    // channel with a poll interval, so it can wind down on sink failure without another stdin line.
    // The channel is BOUNDED (backpressure — the reader parks on a full queue rather than
    // slurping an unbounded backlog into memory) and real EOF is signaled on a side flag the
    // INSTANT the reader sees it, independently of any queued-but-undispatched lines. The thread
    // is deliberately never joined — at shutdown it may sit in a read that only ends when the
    // client closes the pipe or the process exits; its sends fail once the loop is gone.
    let eof_flag = Arc::new(AtomicBool::new(false));
    // A read error is terminal like EOF but must be LABELED distinctly. Stored BEFORE the
    // eof flag (SeqCst), so any observer that saw eof=true also sees the true cause — the shutdown
    // line can never mislabel a read error as `client_eof` no matter which path notes it first.
    let read_err_flag = Arc::new(AtomicBool::new(false));
    let reader_eof = Arc::clone(&eof_flag);
    let reader_err = Arc::clone(&read_err_flag);
    let (line_tx, line_rx) =
        std::sync::mpsc::sync_channel::<io::Result<String>>(READER_QUEUE_DEPTH);
    std::thread::spawn(move || {
        for line in reader.lines() {
            let stop = line.is_err();
            if stop {
                // A read error is terminal for the stream — as EOF-like as it gets.
                reader_err.store(true, Ordering::SeqCst);
                reader_eof.store(true, Ordering::SeqCst);
            }
            if line_tx.send(line).is_err() || stop {
                return;
            }
        }
        // Real EOF: flagged BEFORE the sender drops, so dispatch sees it even behind a backlog.
        reader_eof.store(true, Ordering::SeqCst);
    });

    // The reader parks on a full queue, so EOF-as-read can hide behind an OS-pipe
    // backlog bigger than the queue. When the reader is a real pipe, a watcher observes HANGUP
    // (poll POLLHUP — non-consuming) independently of admission: the flag — and with it the
    // shutdown clock — anchors at the client's actual close. The watcher exits once the flag is
    // set by either side.
    if let Some(fd) = hangup_fd {
        let watcher_eof = Arc::clone(&eof_flag);
        std::thread::spawn(move || loop {
            if watcher_eof.load(Ordering::SeqCst) {
                return;
            }
            if cermet_ipc::hangup::hung_up(fd) {
                watcher_eof.store(true, Ordering::SeqCst);
                return;
            }
            std::thread::sleep(HANGUP_POLL);
        });
    }

    let result = dispatch_loop(
        &transport,
        &line_rx,
        &eof_flag,
        &read_err_flag,
        &writer,
        &pool,
        &supervisor,
        &verbs,
        &timings,
    );

    // Shutdown: the phase machine walked forward, every transition bounded. Dispatch
    // already moved the pool to DrainingBacklog at the input's actual end, so the
    // drain's clock is anchored there; then admission closes and the writer task flushes the
    // already-queued responses BOUNDED — a healthy sink lands them, a stalled one is detached.
    pool.drain(&timings);
    // The tool-call workers have drained; now kill + report the BACKGROUND runs on
    // the supervisor's own pool (an async run outlives the CALL, never the cermet MCP process —
    // normal shutdown still kills). Its drain reuses the same bounded machinery, so the exit
    // stays bounded.
    supervisor.shutdown(&timings);
    pool.set_phase(ShutdownPhase::Flushing);
    writer.deactivate();
    writer_task.finish(timings.flush_join());
    pool.set_phase(ShutdownPhase::Stopped);
    // The bridge stopped, and WHY (`client_eof` / `sink_failure` / `read_error`, or
    // `unknown` if the input never formally ended).

    match result {
        // The client closed the pipe mid-stream — a graceful shutdown, not an error.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// The dispatch side of [`serve_inner`]: receive lines from the reader thread, answer inline or
/// fan out to workers. Returns on EOF, a read error, an inline write error, or a terminal sink
/// failure — recording the input's end on the POOL PHASE (`note_input_ended`, the drain's
/// anchor). Does NOT drain — the caller owns shutdown so it runs on every exit path.
///
/// EOF is observed on the reader's side flag, independently of queued lines. From that
/// instant the remaining backlog gets ONE post-EOF service window (`timings.drain` — the same
/// budget the drain's phase 1 composes from); at its deadline the still-unadmitted lines are
/// DROPPED, not admitted: the client already left, an execution started for it would side-effect
/// with nobody to answer, and a refusal would have no reader. The one-shot pipe pattern
/// (`echo requests | server`) still gets every answer — its backlog clears in microseconds.
#[allow(clippy::too_many_arguments)] // one loop, one call site (serve_inner_watched)
fn dispatch_loop<T>(
    transport: &Arc<T>,
    lines: &std::sync::mpsc::Receiver<io::Result<String>>,
    eof_flag: &AtomicBool,
    read_err_flag: &AtomicBool,
    writer: &SharedWriter,
    pool: &Arc<WorkerPool>,
    supervisor: &Arc<RunSupervisor>,
    verbs: &Arc<VerbSurface>,
    timings: &ShutdownTimings,
) -> io::Result<()>
where
    T: AgentTransport + Send + Sync + 'static,
{
    use std::sync::mpsc::RecvTimeoutError;
    // The stream-end cause, resolved at note time. The reader sets `read_err_flag`
    // BEFORE `eof_flag`, so an observer that saw eof also sees the true cause.
    let eof_cause = || {
        if read_err_flag.load(Ordering::SeqCst) {
            ShutdownCause::ReadError
        } else {
            ShutdownCause::Eof
        }
    };
    let mut backlog_deadline: Option<Instant> = None;
    loop {
        // Once the sink is terminally failed there is no channel for any answer — stop
        // dispatching (side-effecting calls into a dead pipe would be work the client cannot see)
        // and wind down. Checked every wake, so a quiet stdin cannot delay it past SINK_POLL.
        if writer.is_failed() {
            pool.note_input_ended(ShutdownCause::SinkFailure, Instant::now());
            return Ok(());
        }
        // The input's actual end (EOF-as-read or the hangup watcher): ONE phase
        // transition anchors both the backlog service window here and the drain's clock.
        if backlog_deadline.is_none() && eof_flag.load(Ordering::SeqCst) {
            let anchor = Instant::now();
            pool.note_input_ended(eof_cause(), anchor);
            backlog_deadline = Some(anchor + timings.drain);
        }
        if let Some(deadline) = backlog_deadline {
            if Instant::now() >= deadline {
                // The post-EOF window closed with lines still queued: drop them unadmitted and
                // hand control to the bounded drain — the client already left.
                return Ok(());
            }
        }
        let line = match lines.recv_timeout(SINK_POLL) {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => {
                // A read error ends the stream like EOF, but the cause is DISTINCT —
                // record it so any killed-run receipt says `read_error`,
                // never `unknown` (and never a false `client_eof`).
                pool.note_input_ended(ShutdownCause::ReadError, Instant::now());
                return Err(e);
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                // The queue is fully drained and the reader is gone — EOF even if the flag race
                // hasn't been observed yet (a read-error end still labels itself).
                pool.note_input_ended(eof_cause(), Instant::now());
                return Ok(());
            }
        };
        // Re-check after the wait: a line that arrived AS the sink failed must not be dispatched.
        if writer.is_failed() {
            pool.note_input_ended(ShutdownCause::SinkFailure, Instant::now());
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }
        let msg = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => msg,
            Err(_) => {
                writer.write_response(&error_response(Value::Null, -32700, "Parse error"))?;
                continue;
            }
        };
        let has_id = msg.get("id").is_some();
        let method = msg.get("method").and_then(Value::as_str);
        let is_tool_call = has_id && method == Some("tools/call");
        // tools/list is DYNAMIC now (a catalog fetch), so it rides a worker too — the dispatch
        // thread must never block on a daemon call.
        let is_tools_list = has_id && method == Some("tools/list");
        if is_tool_call || is_tools_list {
            // Dispatch onto a worker thread with its OWN daemon connection so a long execute cannot
            // block a concurrent catalog/status call. The id correlates the out-of-order response.
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            let busy_id = id.clone();
            let params = msg.get("params").cloned();
            let transport = Arc::clone(transport);
            let supervisor = Arc::clone(supervisor);
            let verbs = Arc::clone(verbs);
            let worker_writer = writer.clone();
            let spawned = pool.try_spawn(move |slot| {
                // A worker panic must still produce a JSON-RPC error for this id (never a silent drop —
                // the client would hang until timeout). `AssertUnwindSafe`: on unwind we discard any
                // half-mutated state and answer with an internal error, so cross-panic invariants of the
                // shared transport are not relied upon here.
                let response = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    if is_tools_list {
                        result_response(id.clone(), tools_list_with(&*transport, Some(&*verbs)))
                    } else {
                        run_tool_call(
                            &transport,
                            &supervisor,
                            &verbs,
                            &worker_writer,
                            params.as_ref(),
                            id.clone(),
                            slot,
                        )
                    }
                }))
                .unwrap_or_else(|_| error_response(id.clone(), -32603, "Internal error"));
                // The write can fail if the client went away; nothing to recover, drop it.
                let _ = worker_writer.write_response(&response);
            });
            if !spawned {
                if is_tools_list {
                    // Never busy-error a tools/list: serve the meta-tools inline (fail closed —
                    // generated verbs absent, which grants nothing; the client re-lists later).
                    writer.write_response(&result_response(
                        busy_id,
                        json!({ "tools": static_tools() }),
                    ))?;
                } else {
                    // A full pool answers busy INLINE — the dispatch loop never parks on
                    // capacity, so ping/initialize/EOF keep flowing past a saturated fleet.
                    writer.write_response(&error_response(
                        busy_id,
                        -32000,
                        "Server busy: too many concurrent tool calls in flight; retry shortly",
                    ))?;
                }
            }
        } else if let Some(resp) = handle_message(&**transport, &msg) {
            writer.write_response(&resp)?;
        }
    }
}

/// Dispatch one parsed JSON-RPC message. Returns `Some(response)` for a request (a message carrying
/// an `id`), `None` for a notification (no `id`, e.g. `notifications/initialized`).
fn handle_message<T: AgentTransport>(transport: &T, msg: &Value) -> Option<Value> {
    let has_id = msg.get("id").is_some();
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let method = msg.get("method").and_then(Value::as_str);
    match method {
        // The inline path never runs at shutdown, so its shutdown probe is always open.
        Some(m) if has_id => Some(handle_request(transport, m, msg.get("params"), id, &|| {
            true
        })),
        // A notification (no id) — nothing to reply. `notifications/initialized` lands here.
        Some(_) => None,
        // Has an id but no method: a malformed request. Absent id + absent method: ignore.
        None if has_id => Some(error_response(id, -32600, "Invalid Request")),
        None => None,
    }
}

fn handle_request<T: AgentTransport>(
    transport: &T,
    method: &str,
    params: Option<&Value>,
    id: Value,
    probe: &dyn ShutdownProbe,
) -> Value {
    match method {
        // The handshake's `clientInfo` is the runtime naming ITSELF. Recorded here for the
        // lazily-minted session; it changes nothing about the reply.
        "initialize" => {
            let info = params.and_then(|p| p.get("clientInfo"));
            transport.declare_client(
                info.and_then(|i| i.get("name")).and_then(Value::as_str),
                info.and_then(|i| i.get("version")).and_then(Value::as_str),
            );
            result_response(id, initialize_result())
        }
        // Base-protocol liveness check; a valid empty reply keeps a pinging client happy.
        "ping" => result_response(id, json!({})),
        "tools/list" => result_response(id, tools_list_result(transport)),
        "tools/call" => {
            let result = handle_tool_call(transport, params, probe);
            tool_call_response(transport, id, result)
        }
        _ => error_response(id, -32601, "Method not found"),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        // The tool list is DYNAMIC (generated verb tools track the ratified catalog), so the
        // server declares listChanged and emits `notifications/tools/list_changed` when the
        // requestable-verb set is observed to have drifted from the last-served list. Accepted
        // limitation: ratification happens on ctl.sock (no push channel), so the signal lags until
        // the agent's next catalog-observing call.
        "capabilities": { "tools": { "listChanged": true } },
        "serverInfo": { "name": "cermet", "version": env!("CARGO_PKG_VERSION") },
        // The ENTRY POINT, stated once where every client reads it before the first tool call. A
        // bare tool list leaves an agent picking the most task-shaped name, often reaching the
        // catalog tool only after exhausting its other ideas.
        "instructions": "Start with the `catalog` tool: it lists what this box admits and how each \
                         verb is reached — some verbs are exercised by running a native command \
                         (git) rather than by a request.",
    })
}

/// The tool catalogue for the userspace flow. Cermet brokers CREDENTIALED provider actions: instead
/// of holding an API token, you request a scoped, sentence-authorized *verb*. The credential never reaches
/// you. `execute_capability` takes a `request_id` (not a `grant_id`): grant_id is operator-internal
/// and never crosses the agent boundary. There is deliberately no authority mutation tool.
///
/// The flow to teach: FIRST call `catalog` — its default zoom is the CONTRACT (the verbs a standing
/// sentence admits, with their bounds), and `scope: "all"` is the dictionary for proposing new
/// authority. `request_capability` then returns a definite sentence allow or deny. Execute an allow;
/// do not retry a deny — relay its widening suggestion to the operator instead.
///
/// The hybrid surface: the list is the STATIC meta-tools plus one thin GENERATED tool
/// per RULED verb (`provider-action`, [`generated_verb_tools`]) — the transcript line reads
/// `vercel-deploy` instead of `execute_capability`, and client permission rules become per-verb. The
/// registered set IS the standing authority: a verb no sentence admits is not a tool, so the tool
/// list never overstates what the agent may do (and the unruled long tail costs no schema tokens).
/// Fail closed: a catalog fetch failure serves the meta-tools ALONE — never the whole dictionary —
/// and says so on the catalog tool, since the agent would otherwise read an empty verb list as "this
/// box can do nothing" rather than "authority could not be read".
fn tools_list_result<T: AgentTransport>(transport: &T) -> Value {
    tools_list_with(transport, None)
}

/// As [`tools_list_result`], optionally recording the served ruled-verb-set hash on `verbs`
/// (the serve path's listChanged baseline). A failed catalog fetch records nothing — the previous
/// baseline stands and only the meta-tools are served.
fn tools_list_with<T: AgentTransport>(transport: &T, verbs: Option<&VerbSurface>) -> Value {
    let mut tools = static_tools();
    match transport.call(&AgentCommand::Catalog) {
        Ok(frame) => {
            if let Some(v) = verbs {
                v.note_served(requestable_verb_hash(&frame));
            }
            tools.extend(generated_verb_tools(&frame));
        }
        Err(e) => note_unreadable_authority(&mut tools, &e),
    }
    json!({ "tools": tools })
}

/// Fail-closed guidance: with the corpus unreadable, NO per-verb tool is registered. Say
/// that on the `catalog` tool itself — the one tool the agent is told to start with — so the empty
/// verb surface reads as "authority unreadable", not "this box can do nothing".
fn note_unreadable_authority(tools: &mut [Value], error: &AgentError) {
    let Some(catalog) = tools
        .iter_mut()
        .find(|t| t.get("name").and_then(Value::as_str) == Some("catalog"))
    else {
        return;
    };
    let Some(obj) = catalog.as_object_mut() else {
        return;
    };
    let previous = obj
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    obj.insert(
        "description".to_string(),
        json!(format!(
            "AUTHORITY UNREADABLE ({error}): no per-verb tool is registered in this session — that \
             is fail-closed, not an empty box. Use `request_capability` for any verb; the daemon \
             still decides it. {previous}"
        )),
    );
}

/// The static meta-tools. There is deliberately no authority-mutation tool here.
fn static_tools() -> Vec<Value> {
    let arr = json!(
        [
            {
                "name": "catalog",
                "description":
                    "START HERE. One noun, TWO ZOOMS, chosen with `scope`. \
                     scope=\"allowed\" (the DEFAULT) is your CONTRACT: only the verbs a standing \
                     sentence admits right now, one line each, carrying the fields you supply, the \
                     execution `shape`, and the admitting sentence WITH ITS BOUNDS — request one of \
                     these directly and it lands. scope=\"all\" is the DICTIONARY: every verb this \
                     box knows (provider, action, fields with type/required/class, \
                     execution_targets, shape, response contract), each entry stamped with its \
                     authority status — use it to PROPOSE, i.e. to name a real verb and real fields \
                     when asking your operator to widen authority. An unruled verb is still \
                     reachable: `request_capability` returns a DENY carrying a widening suggestion \
                     for the operator; relay that, do not retry. Read-only; no secret, no \
                     credential. `provider`/`keyword` narrow a large result to a BOUNDED candidate \
                     set (`limit` caps it).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scope": { "type": "string", "enum": ["allowed", "all"], "description": "\"allowed\" (default) = only what standing sentences admit, with the admitting sentence and bounds. \"all\" = the full dictionary, every entry stamped with its authority status." },
                        "provider": { "type": "string", "description": "Filter to one provider (e.g. \"stripe\"; substring match)." },
                        "keyword": { "type": "string", "description": "Filter to verbs whose provider/action/field/shape matches this text (substring)." },
                        "limit": { "type": "integer", "description": "Cap the returned candidate set (default 20). Only applies when a filter is given." }
                    }
                }
            },
            {
                "name": "request_capability",
                "description":
                    "Request a scoped verb by provider and action. Its own per-verb tool is the \
                     shorter path when one is registered; THIS is the tool for a verb no standing \
                     sentence admits yet — the answer will be a definite DENY carrying a widening \
                     suggestion for your operator, which is how an unruled action gets proposed \
                     (see `catalog` with scope=\"all\" for the verbs and fields that exist). \
                     Returns a sentence-authority decision and a request_id — never a credential. On \
                     ALLOW call execute_capability immediately; on DENY relay the widening \
                     suggestion to your operator and stop — do not retry.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "provider": { "type": "string", "description": "The provider, e.g. \"stripe\"." },
                        "action": { "type": "string", "description": "The action, e.g. \"get_charge\"." },
                        "resource": { "type": "object", "description": "The scoped resource fields frozen into the grant." },
                        "environment": { "type": "string", "description": "Optional environment, e.g. \"preview\"." },
                        "justification": { "type": "string", "description": "Required human-readable reason for the request." },
                        "retry_effect": { "type": "string", "description": "Explicitly retry a prior ambiguous money effect using its safe effect_id. Never an idempotency key." },
                        "model": { "type": "string", "description": "Optional: which MODEL is driving this request (e.g. \"claude-opus-5\", \"gpt-5.6\"). A self-report recorded on this machine's own receipt row — it is not authenticated, grants nothing, never leaves the box, and never affects the decision. Say it per request, since it changes when the model does." }
                    },
                    "required": ["provider", "action", "justification"]
                }
            },
            {
                "name": "request_status",
                "description":
                    "Check where a prior request/run stands, by its request_id — the phase is one of \
                     `ready` (sentence-authorized, call execute_capability), `running` (executing in \
                     the background), or `terminal` \
                     (finished: it returns the receipt, rebuilt from the audit ledger even from a \
                     later session). This is the POLLING half of the async execute: after \
                     execute_capability hands back a still-running run, poll here. Pass `wait_ms` to \
                     LONG-POLL (block up to that many ms, capped ~20s, for the run to finish) instead \
                     of returning immediately. Read-only.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "request_id": { "type": "string", "description": "The request_id returned by request_capability." },
                        "wait_ms": { "type": "integer", "description": "Long-poll up to this many ms for the run to reach a terminal state (default 0 = return the current phase immediately; capped ~20s)." }
                    },
                    "required": ["request_id"]
                }
            },
            {
                "name": "execute_capability",
                "description":
                    "Run a single-use grant by its request_id. ASYNC-FIRST: it blocks the call only \
                     briefly (default ~2s) — a fast command finishes inside that window and returns \
                     its receipt inline; a slower one keeps RUNNING IN THE BACKGROUND and returns \
                     \"still running (request_id …)\", which you resolve by polling request_status \
                     (optionally with wait_ms to long-poll) — never by re-requesting (grants are \
                     single-use). The result is \
                     redacted of any secret; the credential never reaches you. For an HTTP verb the \
                     result is only the SLICE the verb's keep list chose — the full response is \
                     retained; the receipt names its artifact handle, fetchable via `artifact` (use \
                     `$.path` for one field). A grant executes only once. Set `wait_ms` to change the \
                     inline wait (0 returns a handle immediately).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "request_id": { "type": "string", "description": "The request_id returned by request_capability." },
                        "wait_ms": { "type": "integer", "description": "How long (ms) to block the call for the run to finish before returning a background handle (default ~2000; 0 = return immediately; capped ~60s)." }
                    },
                    "required": ["request_id"]
                }
            },
            {
                "name": "request_vocabulary",
                "description":
                    "The verb or field DOES NOT EXIST. Two different walls stop a request, and only \
                     one of them is this tool: (1) AUTHORITY — the verb exists but no standing \
                     sentence admits your ask; you get a DENY carrying a widening suggestion, and \
                     the answer is to relay that suggestion to YOUR OPERATOR (do not file it here). \
                     (2) VOCABULARY — the verb, or a field on it, is not in the catalog at all, so \
                     the ask cannot even be expressed and there is no deny to widen; THAT is what \
                     this tool reports. Check `catalog` with scope=\"all\" first — a verb listed \
                     there EXISTS and this tool will refuse it. What it does: returns the formed \
                     request for you to GIVE TO YOUR OPERATOR (they are the ones who ask us for a \
                     new verb), and records the event in the daemon's log. In this tool nothing is \
                     stored and nothing is sent anywhere. It grants nothing, unblocks nothing \
                     right now, and changes no authority.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "provider": { "type": "string", "description": "The provider the missing verb belongs to — existing (e.g. \"stripe\") or one Cermet does not support yet." },
                        "verb": { "type": "string", "description": "The wanted action name alone (e.g. \"list_disputes\"), bare and undotted. With `field`, this instead names the EXISTING verb the missing field belongs on." },
                        "field": { "type": "string", "description": "A missing field on the verb named by `verb` (which must already exist)." },
                        "ask": { "type": "string", "description": "What you were actually trying to do — the ask that hit the wall. Never include a credential; a form carrying one is refused." },
                        "rationale": { "type": "string", "description": "Why it matters. Prose is fine here; this goes to the vendor, not into any policy." }
                    },
                    "required": ["provider"]
                }
            },
            {
                "name": "list_connected_providers",
                "description":
                    "List the connected CREDENTIAL providers (references and providers only, never \
                     secrets). Use it to confirm the provider a verb needs is connected.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "verify_audit",
                "description": "Verify the tamper-evidence of the audit hash-chain.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "artifact",
                "description":
                    "Fetch a stored response/output by its `handle` (returned in an execution \
                     receipt). An HTTP receipt's `result` is only the SLICE the verb's keep list \
                     chose; the FULL provider response is retained and fetchable here. Read-only; no \
                     secret. Pull the least you need: use `path` (a `$.a.b` capture-pointer) to get \
                     ONE field the slice dropped for tens of tokens, or `range` for a byte/line \
                     window (`unit` \"lines\" 1-based inclusive / \"bytes\" 0-based end-exclusive, \
                     with `start` and optional `end`). Supply `range` OR `path`, not both; omit both \
                     for the full blob.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "handle": { "type": "string", "description": "The artifact handle from a receipt." },
                        "path": { "type": "string", "description": "A `$.a.b` capture-pointer returning one JSON sub-value of the retained response. Cheapest way to recover a field the keep list dropped." },
                        "range": {
                            "type": "object",
                            "description": "A byte/line window. Omit (with `path`) for the full blob.",
                            "properties": {
                                "unit": { "type": "string", "enum": ["lines", "bytes"] },
                                "start": { "type": "integer" },
                                "end": { "type": "integer" }
                            },
                            "required": ["unit", "start"]
                        }
                    },
                    "required": ["handle"]
                }
            }
        ]
    );
    let mut tools = match arr {
        Value::Array(v) => v,
        _ => unreachable!("static_tools is a literal array"),
    };
    // Stamp the advisory display annotations (title + readOnlyHint). Done here, off one table,
    // rather than inline on 14 literals so the read-only set is auditable in one place.
    for tool in &mut tools {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some((title, read_only)) = meta_tool_annotation(name) else {
            continue;
        };
        let mut ann = serde_json::Map::new();
        ann.insert("title".to_string(), json!(title));
        if read_only {
            ann.insert("readOnlyHint".to_string(), json!(true));
        }
        if let Some(obj) = tool.as_object_mut() {
            obj.insert("annotations".to_string(), Value::Object(ann));
        }
    }
    tools
}

/// Display annotations for the meta-tools: a human-readable `title` for EVERY tool, and
/// `readOnlyHint: true` for the six that neither mint a grant nor cause a side effect (`catalog`,
/// `request_status`, `list_connected_providers`, `verify_audit`, `artifact`).
/// Annotations are ADVISORY hints (MCP spec) — a client may ignore them, and they are NEVER an
/// approval affordance: `readOnlyHint` can only relax a CLIENT's tool-permission prompt for tools
/// that are genuinely side-effect-free and return no secret; it has NO bearing on Cermet's own
/// grant approvals, which stay human-only in the console. The mutating tools (request/execute/
/// the pipeline verbs) deliberately carry NO `readOnlyHint`, so they still prompt.
/// `None` ⇒ no annotation for that name.
fn meta_tool_annotation(name: &str) -> Option<(&'static str, bool)> {
    Some(match name {
        "catalog" => ("Catalog", true),
        "request_capability" => ("Request capability", false),
        "request_status" => ("Request status", true),
        "execute_capability" => ("Execute capability", false),
        // NOT read-only: it appends a row to the daemon's event log. It is also not a grant — it
        // authorizes nothing — so it carries no other hint either.
        "request_vocabulary" => ("Request vocabulary", false),
        "list_connected_providers" => ("List connected providers", true),
        "verify_audit" => ("Verify audit", true),
        "artifact" => ("Fetch artifact", true),
        _ => return None,
    })
}

/// A catalog-frame entry is on the AGENT SURFACE when the broker has the verb loaded
/// AND the live sentence corpus admits it. BOTH bits are decided daemon-side, against the one
/// corpus; the bridge only reads them here — it never re-decides authority, and a rule revoked
/// mid-session still denies at the daemon exactly as it does today.
fn frame_entry_is_ruled(e: &Value) -> bool {
    e.get("requestable").and_then(Value::as_bool) == Some(true)
        && e.get("sentence_denied").and_then(Value::as_bool) != Some(true)
}

/// The argument names every GENERATED verb tool reserves for its own call protocol — a verb
/// whose catalog fields collide with one of these is NOT projected (fail closed: it stays
/// requestable via `request_capability`, where no such collision exists).
const VERB_TOOL_RESERVED: &[&str] = &[
    "justification",
    "request_id",
    "retry_effect",
    "wait_ms",
    "model",
];

/// One `[a-z0-9_]+` name segment — the broker-side `is_ident` charset. Only such segments are
/// projected, so `provider-action` (hyphen separator) is reversible and collision-free.
fn is_tool_segment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The generated tool name for a verb, and its inverse. The hyphen is the ONE separator (it cannot
/// appear inside a segment), so the mapping is bijective over projected verbs.
fn verb_tool_name(provider: &str, action: &str) -> String {
    format!("{provider}-{action}")
}

fn split_verb_tool_name(name: &str) -> Option<(String, String)> {
    let (provider, action) = name.split_once('-')?;
    (is_tool_segment(provider) && is_tool_segment(action))
        .then(|| (provider.to_string(), action.to_string()))
}

/// Project each REQUESTABLE catalog verb as a thin generated MCP tool. The schema mirrors
/// request-time semantics exactly — agent-request fields are fillable (secret-class included; they
/// ride the same `resource` path request_capability uses, so redaction fires unchanged), while
/// provider-resolved fields are omitted — plus the call-protocol args: `justification` (REQUIRED),
/// `request_id` (resume a prior call; NEVER re-requests), and `wait_ms` (the async inline wait).
/// A non-requestable verb is simply absent (fail closed); so is one whose field names collide with
/// the reserved args or whose name segments fall outside the reversible charset.
fn generated_verb_tools(frame: &Value) -> Vec<Value> {
    let empty = Vec::new();
    let entries = frame
        .get("catalog")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let mut out = Vec::new();
    for e in entries {
        // Sentence-scope the advertisement — a verb the active corpus cannot cover does not exist
        // as a tool ("never advertise authority policy would deny"). The verb stays reachable via
        // `request_capability` (where the daemon decides it per-resource); it is only absent from
        // the auto-injected tool schemas, which is where the token bloat lives.
        if !frame_entry_is_ruled(e) {
            continue;
        }
        let (Some(provider), Some(action)) = (
            e.get("provider").and_then(Value::as_str),
            e.get("action").and_then(Value::as_str),
        ) else {
            continue;
        };
        if !is_tool_segment(provider) || !is_tool_segment(action) {
            continue;
        }
        let mut props = serde_json::Map::new();
        let mut required: Vec<String> = Vec::new();
        let mut reserved_collision = false;
        for f in e.get("fields").and_then(Value::as_array).unwrap_or(&empty) {
            match f.get("origin").and_then(Value::as_str) {
                // Neither is an input an agent can offer: one the daemon reads back from the
                // provider, the other it derives from the vaulted credential. Both are omitted from
                // the tool schema so the model is never shown a field it may not fill.
                Some("provider_resolved" | "credential_derived") => continue,
                Some("agent_request") => {}
                _ => {
                    reserved_collision = true;
                    break;
                }
            }
            let Some(fname) = f.get("name").and_then(Value::as_str) else {
                continue;
            };
            if VERB_TOOL_RESERVED.contains(&fname) {
                reserved_collision = true;
                break;
            }
            let class = f.get("class").and_then(Value::as_str).unwrap_or("field");
            let description = format!("{class} field of {provider}.{action}");
            let schema = match f.get("type").and_then(Value::as_str) {
                Some("int") => json!({ "type": "integer", "description": description }),
                Some("bool") => json!({ "type": "boolean", "description": description }),
                _ => json!({ "type": "string", "description": description }),
            };
            props.insert(fname.to_string(), schema);
            if f.get("required").and_then(Value::as_bool) == Some(true) {
                required.push(fname.to_string());
            }
        }
        if reserved_collision {
            continue;
        }
        props.insert(
            "justification".to_string(),
            json!({ "type": "string", "description": "REQUIRED: why this command is being run (audited alongside the request)." }),
        );
        props.insert(
            "request_id".to_string(),
            json!({ "type": "string", "description": "RESUME a prior call of this tool: fetch/await that run's receipt instead of minting a new request. Never re-request — grants are single-use." }),
        );
        props.insert(
            "retry_effect".to_string(),
            json!({ "type": "string", "description": "Retry a prior ambiguous money effect by its returned effect_id. The broker authenticates lineage and reuses its hidden key." }),
        );
        props.insert(
            "wait_ms".to_string(),
            json!({ "type": "integer", "description": "How long (ms) to block this call for the run to finish before returning a background handle (default ~2000; 0 = immediately; capped ~60s)." }),
        );
        props.insert(
            "model".to_string(),
            json!({ "type": "string", "description": "Optional: which MODEL is driving this request (e.g. \"claude-opus-5\", \"gpt-5.6\"). A self-report recorded on this machine's own receipt row — it is not authenticated, grants nothing, never leaves the box, and never affects the decision. Say it per request, since it changes when the model does." }),
        );
        required.push("justification".to_string());
        // A RELAY verb does not run the effect — it authorizes it and mints a single-use
        // relay session, and the CALLER bridges the rest with the native CLI. Describing it as
        // "runs it, returning the receipt" is what surprises a naive agent at the moment of use
        // (one with no `vercel` binary installed stopped there).
        let description = if e.get("shape").and_then(Value::as_str) == Some("relay") {
            format!(
                "Brokered verb {provider}.{action}: authorizes the scoped capability against \
                 sentence authority and mints a SINGLE-USE relay session — it does not run the \
                 effect itself. YOU then run the printed `invocation` with the native {provider} \
                 CLI (which must be installed; the broker brings the credential, not the tool), \
                 pointed at the loopback relay with the session handle in its token slot. The \
                 receipt completes when that CLI's own hops complete. The credential never reaches \
                 you; a sentence deny is final (do not retry)."
            )
        } else {
            format!(
                "Brokered verb {provider}.{action}: requests the scoped capability from sentence \
                 authority and runs it, returning the \
                 redacted receipt — inline when it finishes fast, else a background handle (resume \
                 by calling this tool again with `request_id`, or poll `request_status`). The \
                 credential never reaches you; a sentence deny is final (do not retry)."
            )
        };
        out.push(json!({
            "name": verb_tool_name(provider, action),
            // A display title only. NO readOnlyHint — verbs carry no read-only classification
            // today; inventing one ad hoc would be a policy statement in disguise.
            "annotations": { "title": format!("{provider} · {action}") },
            "description": description,
            "inputSchema": { "type": "object", "properties": props, "required": required }
        }));
    }
    out
}

/// listChanged state: the hash of the requestable-verb set as LAST SERVED via tools/list, plus
/// the last hash already announced — so one drift is announced once, and nothing is announced before
/// the client ever listed (there is no stale list to invalidate).
struct VerbSurface {
    state: Mutex<VerbSurfaceState>,
}

#[derive(Default)]
struct VerbSurfaceState {
    served: Option<u64>,
    notified: Option<u64>,
}

impl VerbSurface {
    fn new() -> Self {
        Self {
            state: Mutex::new(VerbSurfaceState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VerbSurfaceState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record the verb-set hash a tools/list reply just served; clears any pending announcement.
    fn note_served(&self, h: u64) {
        let mut s = self.lock();
        s.served = Some(h);
        s.notified = None;
    }

    /// True exactly once per drift: the current set differs from the last-served one and this
    /// change has not been announced yet. Never true before a first tools/list.
    fn should_announce(&self, current: u64) -> bool {
        let mut s = self.lock();
        match s.served {
            Some(served) if served != current && s.notified != Some(current) => {
                s.notified = Some(current);
                true
            }
            _ => false,
        }
    }

    fn has_served(&self) -> bool {
        self.lock().served.is_some()
    }
}

/// The stable hash of the ADVERTISED verb set in a catalog frame (sorted `provider.action` names) —
/// requestable AND sentence-discoverable, so a corpus change can alter
/// the hash and `listChanged` re-scopes the advertisement.
fn requestable_verb_hash(frame: &Value) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut names: Vec<String> = frame
        .get("catalog")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter(|e| frame_entry_is_ruled(e))
                .filter_map(|e| {
                    let p = e.get("provider").and_then(Value::as_str)?;
                    let a = e.get("action").and_then(Value::as_str)?;
                    Some(format!("{p}.{a}"))
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    names.hash(&mut h);
    h.finish()
}

/// listChanged: after a call that can OBSERVE a catalog change (a request, a
/// generated verb call), re-check the requestable set and emit `notifications/tools/list_changed`
/// on drift from the last-served list — once per drift. Best-effort: a failed catalog read emits
/// nothing (the next observation re-checks). Skipped entirely before the first tools/list.
fn refresh_verb_surface<T: AgentTransport>(
    transport: &T,
    verbs: &VerbSurface,
    writer: &SharedWriter,
) {
    if !verbs.has_served() {
        return;
    }
    if let Ok(frame) = transport.call(&AgentCommand::Catalog) {
        if verbs.should_announce(requestable_verb_hash(&frame)) {
            let _ = writer.write_response(&json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed"
            }));
        }
    }
}

/// A tool result: the `content` array plus the `isError` flag.
type ToolResult = (Vec<Value>, bool);

fn text_content(text: impl Into<String>) -> Value {
    json!({ "type": "text", "text": text.into() })
}

fn ok_text(text: impl Into<String>) -> ToolResult {
    (vec![text_content(text)], false)
}

fn err_text(text: impl Into<String>) -> ToolResult {
    (vec![text_content(text)], true)
}

fn with_effect_handle(mut result: ToolResult, effect_id: Option<&str>) -> ToolResult {
    if let Some(effect_id) = effect_id {
        result.0.push(text_content(format!(
            "effect (structured JSON - use for an authenticated retry only if this run is ambiguous):\n{}",
            json!({ "effect_id": effect_id })
        )));
    }
    result
}

fn with_effect_outcome(
    mut result: ToolResult,
    effect_id: Option<&str>,
    effect_outcome: Option<EffectOutcome>,
) -> ToolResult {
    let Some(effect_id) = effect_id else {
        return result;
    };
    let Some(effect_outcome) = effect_outcome else {
        return with_effect_handle(result, Some(effect_id));
    };
    let (name, guidance) = match effect_outcome {
        EffectOutcome::PreEffect => (
            "definitely_pre_effect",
            "Request a fresh effect; the provider mutation was not invoked.",
        ),
        EffectOutcome::Succeeded => ("succeeded", "Do not retry this effect."),
        EffectOutcome::DefinitelyFailed => ("definitely_failed", "Do not retry this effect."),
        EffectOutcome::Ambiguous => (
            "ambiguous",
            "Use retry_effect with this authenticated effect_id; the broker will reuse its hidden key.",
        ),
    };
    result.0.push(text_content(format!(
        "effect (authenticated structured JSON):\n{}\n{guidance}",
        json!({ "effect_id": effect_id, "effect_outcome": name })
    )));
    result
}

fn handle_tool_call<T: AgentTransport>(
    transport: &T,
    params: Option<&Value>,
    probe: &dyn ShutdownProbe,
) -> ToolResult {
    let params = params.cloned().unwrap_or(Value::Null);
    let name = params.get("name").and_then(Value::as_str);
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);
    match name {
        Some("catalog") => tool_catalog(transport, &args),
        Some("request_capability") => tool_request(transport, &args),
        Some("request_status") => tool_status(transport, &args),
        Some("execute_capability") => tool_execute(transport, &args, probe),
        Some("request_vocabulary") => tool_request_vocabulary(transport, &args),
        Some("list_connected_providers") => passthrough(transport, &AgentCommand::List),
        Some("verify_audit") => passthrough(transport, &AgentCommand::Verify),
        Some("artifact") => tool_artifact(transport, &args),
        // Generated verb tools (hyphenated names) are served ONLY on the worker path
        // (`run_tool_call` — they need the RunSupervisor); here they read as unknown.
        Some(other) => err_text(format!("unknown tool: {other}")),
        None => err_text("tools/call is missing the tool name"),
    }
}

/// The SERVE-path `tools/call` handler.
/// `execute_capability` / `request_status` are the async surface (they need the RunSupervisor for
/// the background run + its result handoff); a HYPHENATED name is a generated verb tool
/// (request → async execute; no static tool name contains a hyphen); `request_capability` /
/// `request_capability` / verb calls additionally re-check the catalog for a listChanged announcement.
/// Every other tool routes to the shared [`handle_request`] dispatch unchanged. (The inline/test
/// `handle_message` path keeps the synchronous [`tool_execute`]/[`tool_status`] and no verb tools —
/// `tools/call` is never actually served inline, so that path is a test convenience, not the
/// product surface.)
fn run_tool_call<T: AgentTransport + Send + Sync + 'static>(
    transport: &Arc<T>,
    supervisor: &Arc<RunSupervisor>,
    verbs: &VerbSurface,
    writer: &SharedWriter,
    params: Option<&Value>,
    id: Value,
    probe: &WorkerSlot,
) -> Value {
    let p = params.cloned().unwrap_or(Value::Null);
    let name = p.get("name").and_then(Value::as_str).map(str::to_string);
    let args = p.get("arguments").cloned().unwrap_or(Value::Null);
    let (content, is_error) = match name.as_deref() {
        Some("execute_capability") => tool_execute_async(transport, supervisor, &args),
        Some("request_status") => tool_status_async(transport.as_ref(), supervisor, &args),
        Some("request_capability") => {
            let r = tool_request(transport.as_ref(), &args);
            refresh_verb_surface(transport.as_ref(), verbs, writer);
            r
        }
        // A hyphen marks a GENERATED verb tool (static names never contain one).
        Some(n) if n.contains('-') => {
            let r = tool_verb_call(transport, supervisor, n, &args);
            refresh_verb_surface(transport.as_ref(), verbs, writer);
            r
        }
        // Every other tool is unchanged (and the probe is the worker's shutdown slot).
        _ => return handle_request(transport.as_ref(), "tools/call", params, id, probe),
    };
    tool_call_response(transport.as_ref(), id, (content, is_error))
}

/// Frame one tool result, leading with the build-skew note when this session owes one.
/// Both dispatch paths (inline and worker) go through here, so the note rides whichever tool result
/// happens to be first — and, being taken, rides exactly one.
fn tool_call_response<T: AgentTransport + ?Sized>(
    transport: &T,
    id: Value,
    (mut content, is_error): ToolResult,
) -> Value {
    if let Some(note) = transport.take_build_skew_note() {
        content.insert(0, text_content(note));
    }
    result_response(id, json!({ "content": content, "isError": is_error }))
}

/// One generated verb tool's call — internally `request_capability` → the async execute.
/// A fast auto-allowed verb completes in ONE call (the receipt inline); an ASK or a slow run
/// returns the resumable text WITH the request_id. An explicit `request_id` arg RESUMES that run
/// (fetch/await its receipt) and NEVER re-requests — grants are single-use; a hidden retry loop
/// would mint new grants. A policy deny is a tool error (final; do not retry).
fn tool_verb_call<T: AgentTransport + Send + Sync + 'static>(
    transport: &Arc<T>,
    supervisor: &Arc<RunSupervisor>,
    name: &str,
    args: &Value,
) -> ToolResult {
    let Some((provider, action)) = split_verb_tool_name(name) else {
        return err_text(format!("unknown tool: {name}"));
    };
    // RESUME path: the caller already holds a run handle from a prior call of this tool.
    if args.get("request_id").and_then(Value::as_str).is_some() {
        return tool_status_async(transport.as_ref(), supervisor, args);
    }
    // Every brokered command carries its reasoning: required in the
    // generated schema AND enforced here (a schema is advisory to a hostile client).
    let justification = match args.get("justification").and_then(Value::as_str) {
        Some(j) if !j.trim().is_empty() => j.to_string(),
        _ => {
            return err_text(format!(
                "{name} requires a 'justification' string — say why this command is being run"
            ))
        }
    };
    // The verb's resource fields are the remaining top-level args — the SAME `resource` path
    // request_capability uses (secret-class fields included; redaction fires unchanged broker-side).
    let mut resource = args.as_object().cloned().unwrap_or_default();
    for k in VERB_TOOL_RESERVED {
        resource.remove(*k);
    }
    let cmd = AgentCommand::Request {
        provider,
        action,
        resource: Value::Object(resource),
        environment: None,
        justification: Some(justification),
        retry_effect: args
            .get("retry_effect")
            .and_then(Value::as_str)
            .map(str::to_string),
        // The agent's own claim about what it is, per call. Never checked, never authority.
        model: args
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
    };
    // Render through the typed, redacted projection — never the raw frame.
    let requested = match transport.call(&cmd) {
        Ok(resp) => match super::render(&cmd, &resp) {
            Ok(out) => out.json,
            Err(e) => return err_text(e.to_string()),
        },
        Err(e) => return err_text(e.to_string()),
    };
    let request_id = requested
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let decision = requested
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("");
    let reason = requested
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("");
    let effect_id = requested.get("effect_id").and_then(Value::as_str);
    if decision == "deny" {
        let hint_clause = requested
            .get("hint")
            .and_then(Value::as_str)
            .filter(|hint| !hint.is_empty())
            .map(render_advisory_widen_hint)
            .unwrap_or_default();
        let deny_text = render_deny_text(
            &request_id,
            reason,
            requested.get("authority_kind").and_then(Value::as_str),
        );
        return err_text(format!("{deny_text}{hint_clause}"));
    }
    if request_id.is_empty() {
        return err_text("the broker's requested frame carried no request_id");
    }
    if decision != "allow" {
        return err_text("malformed sentence-authority decision");
    }
    let mut exec_args = json!({ "request_id": request_id });
    if let Some(ms) = args.get("wait_ms") {
        exec_args["wait_ms"] = ms.clone();
    }
    tool_execute_async_with_effect(transport, supervisor, &exec_args, effect_id)
}

/// Async execute: `execute_capability(request_id, wait_ms=2000)`. Starts (or dedups) the
/// background run, then BLOCKS THE CALL up to `wait_ms` for it to settle — returning the terminal
/// receipt INLINE when it does, else a `{request_id, state}` handle the model polls via
/// `request_status`. Fails BEFORE any claim under `async_execute_v1` version skew (no silent
/// fallback to a fully-blocking execute).
fn tool_execute_async<T: AgentTransport + Send + Sync + 'static>(
    transport: &Arc<T>,
    supervisor: &Arc<RunSupervisor>,
    args: &Value,
) -> ToolResult {
    tool_execute_async_with_effect(transport, supervisor, args, None)
}

fn tool_execute_async_with_effect<T: AgentTransport + Send + Sync + 'static>(
    transport: &Arc<T>,
    supervisor: &Arc<RunSupervisor>,
    args: &Value,
    requested_effect_id: Option<&str>,
) -> ToolResult {
    let request_id = match args.get("request_id").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return err_text("execute_capability requires a 'request_id' string"),
    };
    // The advertised inline wait bounds the WHOLE call, not just `wait_terminal`. The
    // pre-wait setup (session mint, ambiguous reconcile — daemon RPCs on the shared connection) is
    // charged against it, so a slow setup shrinks the run wait instead of overrunning the bound (the
    // field failure was a wait_ms=60000 execute exceeding its bound because setup ran uncounted).
    let call_started = Instant::now();
    // Establish the session first so the feature negotiation is known, THEN gate on it.
    if let Err(e) = transport.ensure_session() {
        return with_effect_handle(err_text(e.to_string()), requested_effect_id);
    }
    // A generated call may carry the typed RequestOutcome's effect directly. Generic execute derives
    // it from the broker's authenticated status projection; an undocumented tool argument is ignored.
    let broker_effect_id = requested_effect_id.map(str::to_string).or_else(|| {
        transport
            .call_within(
                &AgentCommand::Status {
                    request_id: request_id.clone(),
                },
                STATUS_READ_FLOOR,
            )
            .ok()
            .and_then(|status| {
                status
                    .get("effect_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
    });
    let effect_id = broker_effect_id.as_deref();
    if !transport.has_feature(cermet_ipc::wire::FEATURE_ASYNC_EXECUTE) {
        return with_effect_handle(err_text(SKEW_ASYNC_EXECUTE), effect_id);
    }
    // A prior attempt that settled AMBIGUOUS (a post-send failure — the grant may have
    // durably executed with only the reply lost) is NEVER blindly restarted. Reconcile through the
    // durable principal-bound status first: terminal ⇒ its verified receipt; provably unclaimed
    // ready ⇒ the record clears and a fresh start below is safe; anything else (incl.
    // a failed status read) surfaces WITHOUT a restart.
    if let Some(rec) = supervisor.get(&request_id) {
        if rec.is_ambiguous() {
            let rec_effect_id = rec.effect_id();
            match reconcile_ambiguous(transport.as_ref(), &request_id, rec_effect_id.as_deref()) {
                Reconciled::Unclaimed => supervisor.clear_settled(&request_id),
                Reconciled::Answer(result) => return result,
            }
        }
    }
    let wait_ms = execute_wait_ms(args);
    let rec = match supervisor.start(&request_id, transport, effect_id) {
        Ok(rec) => rec,
        Err(msg) => return with_effect_handle(err_text(msg), effect_id),
    };
    // The run wait is the advertised budget MINUS whatever the setup already spent — so the whole
    // call returns within `wait_ms` + epsilon regardless of a slow session mint / reconcile.
    let run_wait = Duration::from_millis(wait_ms).saturating_sub(call_started.elapsed());
    match rec.wait_terminal(run_wait) {
        Some(done) => {
            let result_effect_id = done.effect_id.clone().or_else(|| rec.effect_id());
            with_effect_outcome(
                render_run_done(&done),
                result_effect_id.as_deref(),
                done.effect_outcome,
            )
        }
        // Still running past the bounded wait: hand back the request_id + state. The run keeps going
        // in the background; NEVER re-request (grants are single-use).
        None => {
            let running_effect_id = rec.effect_id();
            with_effect_handle(
                ok_text(format!(
            "Run started (request_id {request_id}) — still running past the {wait_ms}ms wait. It \
             continues in the background: poll request_status with this request_id for the receipt \
             (it long-polls up to {}s), or call execute_capability again. Do NOT re-request the \
             capability — grants are single-use.",
            STATUS_LONG_POLL_CAP_MS / 1000
        )),
                running_effect_id.as_deref(),
            )
        }
    }
}

/// `request_status(request_id, wait_ms=0)` as a capped long-poll. The in-process
/// run record is used ONLY as an AWAIT signal (the long-poll parks on it instead of hammering the
/// daemon); the receipt itself ALWAYS renders from the daemon's durable, chain-verified projection
/// (a cached in-memory success must never outrank a withheld/unverifiable durable receipt —
/// the same-session and cross-session answers must agree under tampering). Terminal ⇒ the durable
/// receipt; nonterminal ⇒ the phase + a `poll_after_ms` hint.
fn tool_status_async<T: AgentTransport>(
    transport: &T,
    supervisor: &RunSupervisor,
    args: &Value,
) -> ToolResult {
    let request_id = match args.get("request_id").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return err_text("request_status requires a 'request_id' string"),
    };
    let deadline = Instant::now() + Duration::from_millis(status_wait_ms(args));
    // Await the in-memory run up to the budget (await only — never render from it).
    let mut known_running = false;
    let mut known_effect = None;
    if let Some(rec) = supervisor.get(&request_id) {
        known_effect = rec.effect_id();
        known_running = rec
            .wait_terminal(deadline.saturating_duration_since(Instant::now()))
            .is_none();
    }
    // The budget is END-TO-END — when it is already spent and the phase is known from the
    // in-memory record, answer WITHOUT starting another daemon RPC. (With no in-memory knowledge,
    // one status RPC always runs — the immediate-read contract — bounded by the transport timeout.)
    if known_running && Instant::now() >= deadline {
        return with_effect_handle(
            ok_text(async_phase_text(&request_id, "running")),
            known_effect.as_deref(),
        );
    }
    // Durable daemon status, long-poll bounded by the SAME deadline. EVERY read is
    // clamped to the remaining budget (call_within), so a slow/contended read on the shared
    // connection can never push the poll past its advertised cap — the field failure was a
    // wait_ms=20000 status sitting ~2 minutes because a single unbounded read blew the bound.
    let mut first = true;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        // The FIRST read gets a floor (a wait_ms:0 status still does one real round-trip); later
        // iterations use only the remaining budget, so the floor never overruns the deadline.
        let rpc_budget = if first {
            remaining.max(STATUS_READ_FLOOR)
        } else {
            remaining
        };
        first = false;
        let resp = match transport.call_within(
            &AgentCommand::Status {
                request_id: request_id.clone(),
            },
            rpc_budget,
        ) {
            Ok(r) => r,
            // A daemon we cannot even reach is a real failure — surface it.
            Err(e @ AgentError::Connect(_)) => {
                return with_effect_handle(err_text(e.to_string()), known_effect.as_deref())
            }
            // The daemon answered but refused to project status. This includes grant-integrity
            // failures: outcome is unknown and another request/execute could duplicate an effect.
            Err(AgentError::Server(_)) => {
                return with_effect_handle(
                    unverifiable_status_error(&request_id),
                    known_effect.as_deref(),
                )
            }
            // A bounded read that did not complete in time is NOT terminal: tell the model to poll
            // again (never fabricate an outcome). Retry within the budget, else return "in progress".
            Err(_) => {
                if Instant::now() + STATUS_POLL_INTERVAL >= deadline {
                    return with_effect_handle(
                        ok_text(async_phase_text(&request_id, "unknown")),
                        known_effect.as_deref(),
                    );
                }
                std::thread::sleep(STATUS_POLL_INTERVAL);
                continue;
            }
        };
        match resp.get("phase").and_then(Value::as_str) {
            None => {
                return with_effect_handle(
                    err_text("daemon returned no typed run phase"),
                    resp.get("effect_id")
                        .and_then(Value::as_str)
                        .or(known_effect.as_deref()),
                )
            }
            Some("terminal") => {
                return render_terminal_status(&request_id, &resp, known_effect.as_deref())
            }
            Some(other) => {
                // Re-poll only when the next sleep+RPC cycle still fits the budget.
                if Instant::now() + STATUS_POLL_INTERVAL >= deadline {
                    return with_effect_handle(
                        ok_text(async_phase_text(&request_id, other)),
                        resp.get("effect_id")
                            .and_then(Value::as_str)
                            .or(known_effect.as_deref()),
                    );
                }
                std::thread::sleep(STATUS_POLL_INTERVAL);
            }
        }
    }
}

/// The reconciliation verdict for an AMBIGUOUS prior attempt, read from the durable
/// principal-bound status. `Unclaimed` is the ONLY verdict that permits a restart.
enum Reconciled {
    /// The grant is provably ready and unclaimed — a fresh start is safe.
    Unclaimed,
    /// Any other answer is returned to the caller as-is, WITHOUT a restart.
    Answer(ToolResult),
}

fn reconcile_ambiguous<T: AgentTransport>(
    transport: &T,
    request_id: &str,
    fallback_effect_id: Option<&str>,
) -> Reconciled {
    // Bound this pre-execute reconciliation read so it can't hang the execute call for
    // the full 30s IPC timeout on a contended connection — the whole execute tool stays within its
    // advertised wait.
    let resp = match transport.call_within(
        &AgentCommand::Status {
            request_id: request_id.to_string(),
        },
        STATUS_READ_FLOOR,
    ) {
        Ok(r) => r,
        Err(AgentError::Server(_)) => {
            return Reconciled::Answer(with_effect_handle(
                unverifiable_status_error(request_id),
                fallback_effect_id,
            ))
        }
        // Custody cannot be proven: refuse the restart (fail closed), surface the read failure.
        Err(e) => {
            return Reconciled::Answer(with_effect_handle(
                err_text(format!(
                    "cannot reconcile the prior attempt for request_id {request_id} (status read \
                     failed: {e}); not restarting — poll request_status and retry once it answers"
                )),
                fallback_effect_id,
            ))
        }
    };
    let effect_id = resp
        .get("effect_id")
        .and_then(Value::as_str)
        .or(fallback_effect_id);
    match resp.get("phase").and_then(Value::as_str) {
        Some("terminal") => Reconciled::Answer(render_terminal_status(
            request_id,
            &resp,
            fallback_effect_id,
        )),
        Some("ready") => Reconciled::Unclaimed,
        Some(other) => Reconciled::Answer(with_effect_handle(
            ok_text(async_phase_text(request_id, other)),
            effect_id,
        )),
        None => Reconciled::Answer(with_effect_handle(
            err_text(format!(
                "cannot reconcile request_id {request_id}: daemon returned no typed run phase"
            )),
            effect_id,
        )),
    }
}

fn unverifiable_status_error(request_id: &str) -> ToolResult {
    err_text(format!(
        "Request {request_id} status could NOT be verified. Treat the execution outcome as UNKNOWN; \
         do not execute or request it again because the action may already have run. Ask the human \
         to inspect the Cermet console."
    ))
}

/// The bounded inline wait for `execute_capability`: numeric `wait_ms` (capped), else the default.
fn execute_wait_ms(args: &Value) -> u64 {
    args.get("wait_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_EXECUTE_WAIT_MS)
        .min(MAX_EXECUTE_WAIT_MS)
}

/// The long-poll budget for `request_status`: numeric `wait_ms` (default 0 = immediate), capped
/// under the IPC call timeout.
fn status_wait_ms(args: &Value) -> u64 {
    args.get("wait_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(STATUS_LONG_POLL_CAP_MS)
}

/// Render a settled background run's terminal receipt or error.
fn render_run_done(done: &RunDone) -> ToolResult {
    match &done.result {
        Ok(v) => {
            // `render` for Execute is keyed on the reply kind only; the request_id is unused here.
            let cmd = AgentCommand::Execute {
                request_id: String::new(),
            };
            match super::render(&cmd, v) {
                Ok(out) => (vec![text_content(out.text)], !out.ok),
                Err(e) => err_text(e.to_string()),
            }
        }
        Err(m) => err_text(m.clone()),
    }
}

/// Render a daemon-reported TERMINAL status: the DURABLE receipt (rebuilt from the verified audit
/// chain) when present, else an honest outcome line (denied / abandoned / receipt-not-reconstructable).
fn render_terminal_status(
    request_id: &str,
    resp: &Value,
    fallback_effect_id: Option<&str>,
) -> ToolResult {
    let outcome = resp.get("outcome").and_then(Value::as_str).unwrap_or("");
    let effect_id = resp
        .get("effect_id")
        .and_then(Value::as_str)
        .or(fallback_effect_id);
    let effect_outcome: Option<EffectOutcome> = resp
        .get("effect_outcome")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok());
    if let Some(receipt) = resp.get("terminal_receipt") {
        let cmd = AgentCommand::Execute {
            request_id: request_id.to_string(),
        };
        return with_effect_outcome(
            match super::render(&cmd, receipt) {
                Ok(out) => {
                    let head = format!("Run finished (request_id {request_id}, {outcome}).\n");
                    (vec![text_content(head + &out.text)], !out.ok)
                }
                Err(e) => err_text(e.to_string()),
            },
            effect_id,
            effect_outcome,
        );
    }
    let text = match outcome {
        "denied" => format!("Denied (request_id {request_id}). Do not retry."),
        "abandoned" if effect_outcome == Some(EffectOutcome::Ambiguous) => format!(
            "The grant for request_id {request_id} was abandoned after its authenticated effect-start. \
             Use retry_effect with the authenticated effect_id below; never mint a replacement."
        ),
        "abandoned" => format!(
            "The grant for request_id {request_id} lapsed / was abandoned before it finished. \
             Request the capability again."
        ),
        "succeeded" | "failed" => format!(
            "Run finished (request_id {request_id}, {outcome}) — its receipt is no longer \
             reconstructable from the ledger."
        ),
        // A terminal grant with NO chain-verified outcome is never a benign clean finish —
        // the provider action may or may not have happened and the record cannot prove which.
        // Surface it as needing attention; the human's console is the recovery path, not a retry.
        _ => {
            return with_effect_outcome(
                err_text(format!(
                    "Request {request_id} reached a terminal state but its outcome could NOT be \
                 verified from the ledger. Treat the result as UNKNOWN — do not assume success and \
                 do not blindly retry (the action may already have run); ask the human to check \
                 the Cermet console."
                )),
                effect_id,
                effect_outcome,
            )
        }
    };
    with_effect_outcome(ok_text(text), effect_id, effect_outcome)
}

/// The model-facing text for a still-nonterminal run, carrying the phase + a `poll_after_ms` hint.
fn async_phase_text(request_id: &str, phase: &str) -> String {
    let what = match phase {
        "ready" => "ready — call execute_capability to run it",
        "running" => "running in the background",
        _ => "in progress",
    };
    format!(
        "request_id {request_id} is {phase} ({what}). Not finished yet — poll request_status again \
         (poll_after_ms: {POLL_AFTER_MS})."
    )
}

/// Report where a prior request stands, by its request_id. Read-only — it never mutates a grant.
fn tool_status<T: AgentTransport>(transport: &T, args: &Value) -> ToolResult {
    let request_id = match args.get("request_id").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return err_text("request_status requires a 'request_id' string"),
    };
    passthrough(transport, &AgentCommand::Status { request_id })
}

fn tool_request<T: AgentTransport>(transport: &T, args: &Value) -> ToolResult {
    let provider = args
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let action = args
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if provider.is_empty() || action.is_empty() {
        return err_text("request_capability needs a 'provider' and 'action' pair");
    }
    let cmd = AgentCommand::Request {
        provider,
        action,
        resource: args.get("resource").cloned().unwrap_or(Value::Null),
        environment: args
            .get("environment")
            .and_then(Value::as_str)
            .map(str::to_string),
        justification: args
            .get("justification")
            .and_then(Value::as_str)
            .map(str::to_string),
        retry_effect: args
            .get("retry_effect")
            .and_then(Value::as_str)
            .map(str::to_string),
        model: args
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
    };
    match transport.call(&cmd) {
        // Render from the redacted, fail-closed typed projection — never the raw reply.
        Ok(resp) => match super::render(&cmd, &resp) {
            Ok(out) => render_request_mcp(&out.json),
            Err(e) => err_text(e.to_string()),
        },
        Err(e) => err_text(e.to_string()),
    }
}

/// A typed sentence decision returned alongside the friendly text. `next_action` names only an
/// agent-side action and can never install or mutate authority.
fn request_decision_block(
    request_id: &str,
    decision: &str,
    reason: &str,
    effect_id: Option<&str>,
) -> Value {
    let (grant_state, next_action) = match decision {
        "allow" => ("ready", "execute"),
        "deny" => ("denied", "stop"),
        _ => ("invalid", "stop"),
    };
    let mut block = json!({
        "request_id": request_id,
        "authority_match": decision,
        "grant_state": grant_state,
        "next_action": next_action,
        "reason": reason,
    });
    if let Some(effect_id) = effect_id {
        block["effect_id"] = json!(effect_id);
    }
    block
}

/// Only a SENTENCE deny is final ("do not retry"). A pre-authority refusal —
/// admission/canonicalization/registry, recognizable because the wire carries no `authority_kind`
/// (lifecycle.rs attaches it to policy denies alone) — is a correctable input problem: the corpus
/// never decided anything, and rendering it with sentence-deny finality teaches a cooperative
/// model to give up instead of fixing its request. Both agent-facing deny renders route through
/// here so the two surfaces cannot drift apart again.
fn render_deny_text(request_id: &str, reason: &str, authority_kind: Option<&str>) -> String {
    let is_sentence = authority_kind == Some("sentence");
    let reason_label = if is_sentence {
        "sentence reason"
    } else {
        "reason"
    };
    let reason_clause = if reason.is_empty() {
        String::new()
    } else {
        format!(" ({reason_label}: {reason})")
    };
    if is_sentence {
        format!(
            "Denied by sentence authority (request_id {request_id}){reason_clause}. You cannot \
             run this capability; do not retry it."
        )
    } else {
        format!(
            "Refused before authority evaluation (request_id {request_id}){reason_clause}. \
             Sentence authority never decided this request — submit a new corrected request."
        )
    }
}

fn render_advisory_widen_hint(hint: &str) -> String {
    let command = match hint.strip_prefix("to allow: ") {
        Some(command) => format!("\nAdvisory widen command:\n{command}"),
        None => format!("\nAdvisory widen hint:\n{hint}"),
    };
    format!(
        "{command}\nAlternative operator workflow: edit the CERMET.md authority block, then run \
         `cermet doc apply`."
    )
}

/// Turn the redacted `requested` projection into MCP-facing guidance.
///
/// The friendly text is followed by the TYPED decision block (verbatim JSON) so the loop is
/// drivable from structured fields alone — the prose is a courtesy, never load-bearing.
fn render_request_mcp(view: &Value) -> ToolResult {
    let request_id = view.get("request_id").and_then(Value::as_str).unwrap_or("");
    let decision = view.get("decision").and_then(Value::as_str).unwrap_or("");
    let reason = view.get("reason").and_then(Value::as_str).unwrap_or("");
    let authority_kind = view.get("authority_kind").and_then(Value::as_str);
    let hint = view
        .get("hint")
        .and_then(Value::as_str)
        .filter(|hint| !hint.is_empty());

    let mut text = match decision {
        "allow" => {
            let (allow_label, reason_label) = match authority_kind {
                Some("sentence") => ("Allowed by sentence authority", "sentence reason"),
                _ => ("Allowed", "authority reason"),
            };
            let reason_clause = if reason.is_empty() {
                String::new()
            } else {
                format!(" ({reason_label}: {reason})")
            };
            format!(
                "{allow_label} (request_id {request_id}){reason_clause}. Call execute_capability with this \
                 request_id to run it now."
            )
        }
        "deny" => render_deny_text(request_id, reason, authority_kind),
        _ => return err_text("malformed sentence-authority decision"),
    };
    if decision == "deny" {
        if let Some(hint) = hint {
            text.push_str(&render_advisory_widen_hint(hint));
        }
    }
    let block = request_decision_block(
        request_id,
        decision,
        reason,
        view.get("effect_id").and_then(Value::as_str),
    );
    text.push_str("\n\ndecision (structured JSON — drive off THIS, not the prose above):\n");
    text.push_str(&serde_json::to_string(&block).unwrap_or_default());
    ok_text(text)
}

/// The default cap on a filtered `catalog` candidate set — small enough to stay legible on a
/// schema-unaware host, overridable via `limit`.
const CATALOG_FILTER_DEFAULT_LIMIT: usize = 20;

/// `catalog` is ONE noun with TWO ZOOMS. `scope: "allowed"` (the default) projects only
/// the verbs a standing sentence admits — the compact contract, each line carrying its admitting
/// sentence and bounds. `scope: "all"` is the full dictionary, every entry stamped with its
/// authority status so a proposal to the operator names a real verb and real fields.
///
/// Optional `provider` / `keyword` filters + a `limit` bound the candidate set
/// for hosts that cannot use the per-verb generated tools (schema-unaware, or a truncated
/// tools/list). Both zooms and every filter are pure PROJECTIONS of the daemon's frame — no secret,
/// no authority, no re-decision; they change what is shown, never what is requestable.
fn tool_catalog<T: AgentTransport>(transport: &T, args: &Value) -> ToolResult {
    let zoom = match args.get("scope").and_then(Value::as_str) {
        None | Some("allowed") => CatalogZoom::Allowed,
        Some("all") => CatalogZoom::All,
        Some(other) => {
            return err_text(format!(
                "unknown catalog scope {other:?} — use \"allowed\" (what standing sentences admit, \
                 the default) or \"all\" (the full dictionary with each entry's authority status)"
            ))
        }
    };
    let provider = args
        .get("provider")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_ascii_lowercase());
    let keyword = args
        .get("keyword")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_ascii_lowercase());
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|n| n as usize);
    let frame = match transport.call(&AgentCommand::Catalog) {
        Ok(f) => f,
        Err(e) => return err_text(e.to_string()),
    };
    // Project the zoom BEFORE filtering so the filter header counts within the zoom the agent asked
    // for ("3 of 19", not "3 of 69"). The renderer applies the same zoom — it is what the zoom
    // MEANS — so this projection only has to be honest about the counts.
    let frame = scoped_frame(frame, zoom);
    // No filter at all → the whole zoom, unbounded (the `allowed` zoom is short BY CONSTRUCTION —
    // it is exactly the standing authority — and truncating the dictionary silently would hide
    // verbs an agent is meant to propose).
    if provider.is_none() && keyword.is_none() && limit.is_none() {
        return match super::render_catalog_zoom(&frame, zoom, super::CatalogSurface::Mcp) {
            Ok(out) => (vec![text_content(out.text)], !out.ok),
            Err(e) => err_text(e.to_string()),
        };
    }
    let cap = limit.unwrap_or(CATALOG_FILTER_DEFAULT_LIMIT);
    let (filtered, included, matched, total) =
        filter_catalog_frame(&frame, provider.as_deref(), keyword.as_deref(), cap);
    match super::render_catalog_zoom(&filtered, zoom, super::CatalogSurface::Mcp) {
        Ok(out) => {
            let mut what = Vec::new();
            if let Some(p) = &provider {
                what.push(format!("provider~{p}"));
            }
            if let Some(k) = &keyword {
                what.push(format!("keyword~{k}"));
            }
            let filter_desc = if what.is_empty() {
                "limit only".to_string()
            } else {
                what.join(" ")
            };
            let scope_desc = match zoom {
                CatalogZoom::Allowed => "scope=allowed (verbs a standing sentence admits)",
                CatalogZoom::All => "scope=all (the full dictionary)",
            };
            let header = format!(
                "catalog {scope_desc}, filter [{filter_desc}]: showing {included} of {matched} \
                 matching verbs ({total} in this scope). Drop the filter to see all of them.\n"
            );
            (vec![text_content(header + &out.text)], !out.ok)
        }
        Err(e) => err_text(e.to_string()),
    }
}

/// `request_vocabulary`: report a word that DOES NOT EXIST.
///
/// This tool is the vocabulary-gap channel and nothing else. The authority gap — a verb that exists
/// but no standing sentence admits — already has its channel (the deny's widening suggestion, routed
/// to the operator), so a form naming an EXISTING verb is refused here and pointed back at it. That
/// refusal is the whole discipline: two walls, two answers.
///
/// Two things happen to a validated request, and neither is a store of our own. It goes BACK to the
/// agent as a formed block to relay to its operator — "the agent tells the operator" is the native
/// mechanism for a vendor-bound feature ask — and it is reported to the DAEMON, which appends it to
/// the same event log `broker_start` writes to, because a vocabulary request is a decision and
/// every decision is a row. Nothing is stored by this process and nothing is transmitted anywhere.
///
/// A REFUSED authority-gap probe is recorded too: that an agent could not tell the two walls apart
/// is signal about the product. Both recordings are best-effort against the claim: with the daemon
/// unreachable the agent still gets its relay text, and the response says the event was NOT
/// recorded rather than claiming a row that does not exist.
fn tool_request_vocabulary<T: AgentTransport>(transport: &T, args: &Value) -> ToolResult {
    let text = |key: &str| {
        args.get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
    };
    let Some(provider) = text("provider") else {
        return err_text(
            "request_vocabulary needs a 'provider' — the provider the missing verb belongs to \
             (existing, or one Cermet does not support yet)",
        );
    };
    // The dictionary is the daemon's; an unreadable one is a refusal, not an empty catalog (which
    // would read as "nothing exists" and let an authority ask be reported as a vocabulary one).
    let catalog = match transport.call(&AgentCommand::Catalog) {
        Ok(frame) => frame,
        Err(e) => {
            return err_text(format!(
                "the verb catalog is unreadable ({e}), so this ask cannot be checked against it — \
                 retry once the daemon answers"
            ))
        }
    };
    let form = crate::vocab_request::RequestForm {
        provider,
        wanted_verb: text("verb"),
        wanted_field: text("field"),
        ask: text("ask"),
        rationale: text("rationale"),
    };
    // A malformed or credential-shaped form becomes nothing at all: not a relay, not a row.
    let (request, gap) = match crate::vocab_request::capture(&form, &catalog) {
        Ok(captured) => captured,
        Err(refusal) => return err_text(refusal),
    };
    // The free text reaching the daemon is the SCRUBBED text — capture is the only way to build a
    // request, and it is the chokepoint.
    let recorded = transport
        .call(&AgentCommand::RecordVocabularyRequest {
            provider: request.provider.clone(),
            wanted_verb: request.wanted_verb.clone(),
            wanted_field: request.wanted_field.clone(),
            gap: gap.label().to_string(),
            ask: request.ask.clone(),
            rationale: request.rationale.clone(),
        })
        .is_ok();
    if let crate::vocab_request::Gap::Authority(refusal) = gap {
        // The probe is a row too — that an agent could not tell the two walls apart is signal —
        // but it is NOT a feature request, and the wording must not let it read as one.
        let noted = if recorded {
            "(Your operator's log notes that this was asked here; it is not a feature request.)"
        } else {
            "(The daemon did not record this attempt.)"
        };
        return err_text(format!("{refusal}\n\n{noted}"));
    }
    let ledger = if recorded {
        "Your operator's log has this request (it is a row like any other decision); relaying it \
         speaks to them directly and speeds it up."
    } else {
        "The daemon did not record this request — its log does NOT have it. Relaying the block \
         above is the only copy."
    };
    ok_text(format!(
        "{}\n\nGive this block to your operator: it names a verb Cermet has no word for, and \
         they are the ones who ask us for it. Nothing here is stored by this bridge and nothing is \
         sent anywhere. This grants nothing and changes no authority; if you need a verb that DOES exist, request \
         it normally and relay the deny's widening suggestion instead.\n{ledger}",
        crate::vocab_request::render(&request)
    ))
}

/// Keep only the entries the requested zoom shows — `Allowed` drops everything no standing
/// sentence admits; `All` keeps the dictionary whole.
fn scoped_frame(frame: Value, zoom: CatalogZoom) -> Value {
    if zoom == CatalogZoom::All {
        return frame;
    }
    let mut out = frame;
    if let Some(entries) = out.get_mut("catalog").and_then(Value::as_array_mut) {
        entries.retain(frame_entry_is_ruled);
    }
    out
}

/// True when `entry` matches the `provider`/`keyword` filter (both lowercased already; substring
/// match). An absent filter half is a match. A keyword hits provider, action, any field name, or the
/// shape — the cues an agent selects a verb by.
fn catalog_entry_matches(entry: &Value, provider: Option<&str>, keyword: Option<&str>) -> bool {
    let ep = entry
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let ea = entry
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if let Some(p) = provider {
        if !ep.contains(p) {
            return false;
        }
    }
    if let Some(k) = keyword {
        let mut hay = format!("{ep}.{ea}");
        if let Some(shape) = entry.get("shape").and_then(Value::as_str) {
            hay.push(' ');
            hay.push_str(&shape.to_ascii_lowercase());
        }
        for f in entry
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(fname) = f.get("name").and_then(Value::as_str) {
                hay.push(' ');
                hay.push_str(&fname.to_ascii_lowercase());
            }
        }
        if !hay.contains(k) {
            return false;
        }
    }
    true
}

/// Build a filtered catalog frame: the verb list narrowed by the predicate and capped to `limit`.
/// Returns the frame plus (included, matched, total) verb counts for the header line.
fn filter_catalog_frame(
    frame: &Value,
    provider: Option<&str>,
    keyword: Option<&str>,
    limit: usize,
) -> (Value, usize, usize, usize) {
    let empty = Vec::new();
    let entries = frame
        .get("catalog")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let total = entries.len();
    let matches: Vec<Value> = entries
        .iter()
        .filter(|e| catalog_entry_matches(e, provider, keyword))
        .cloned()
        .collect();
    let matched = matches.len();
    let included: Vec<Value> = matches.into_iter().take(limit).collect();
    let included_count = included.len();

    let mut out = frame.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("catalog".to_string(), Value::Array(included));
    }
    (out, included_count, matched, total)
}

/// Retrieve a stored artifact by handle: full, a byte/line `range`, or a `$.path` capture-pointer
/// (one JSON sub-value). Read-only; the reply carries no secret. `range` and `path` are mutually
/// exclusive. A malformed `range`/`path` is a tool error, never a crash.
fn tool_artifact<T: AgentTransport>(transport: &T, args: &Value) -> ToolResult {
    let handle = match args.get("handle").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return err_text("artifact requires a 'handle' string"),
    };
    let range = match args.get("range") {
        None | Some(Value::Null) => None,
        Some(r) => {
            let unit = match r.get("unit").and_then(Value::as_str) {
                Some(u @ ("lines" | "bytes")) => u.to_string(),
                _ => return err_text("artifact range needs a 'unit' of \"lines\" or \"bytes\""),
            };
            let start = match r.get("start").and_then(Value::as_u64) {
                Some(n) => n,
                None => return err_text("artifact range needs an integer 'start'"),
            };
            let end = match r.get("end") {
                None | Some(Value::Null) => None,
                Some(e) => match e.as_u64() {
                    Some(n) => Some(n),
                    None => return err_text("artifact range 'end' must be an integer"),
                },
            };
            Some(cermet_ipc::wire::ArtifactRange { unit, start, end })
        }
    };
    let path = match args.get("path") {
        None | Some(Value::Null) => None,
        Some(Value::String(p)) => {
            // Same `$.a.b` grammar as the template `capture` lookup — validate before sending.
            let Some(rest) = p.strip_prefix("$.") else {
                return err_text("artifact 'path' must be a capture-pointer like \"$.a.b\"");
            };
            if rest.is_empty() || rest.split('.').any(str::is_empty) {
                return err_text("artifact 'path' segments must be non-empty (e.g. \"$.a.b\")");
            }
            Some(p.clone())
        }
        Some(_) => return err_text("artifact 'path' must be a string"),
    };
    if range.is_some() && path.is_some() {
        return err_text("artifact takes a 'range' OR a 'path', not both");
    }
    passthrough(
        transport,
        &AgentCommand::Artifact {
            handle,
            range,
            path,
        },
    )
}

fn tool_execute<T: AgentTransport>(
    transport: &T,
    args: &Value,
    probe: &dyn ShutdownProbe,
) -> ToolResult {
    let request_id = match args.get("request_id").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => return err_text("execute_capability requires a 'request_id' string"),
    };
    // Render the HTTP verb's `executed` result through the shared CLI renderer.
    match transport.execute_capability(&request_id, probe) {
        Ok(resp) => {
            let cmd = AgentCommand::Execute { request_id };
            match super::render(&cmd, &resp) {
                Ok(out) => (vec![text_content(out.text)], !out.ok),
                Err(e) => err_text(e.to_string()),
            }
        }
        Err(AgentError::Server(m)) => err_text(m),
        Err(AgentError::ServerEffect {
            reason,
            effect_id,
            effect_outcome,
        }) => with_effect_outcome(err_text(reason), Some(&effect_id), effect_outcome),
        Err(e) => err_text(e.to_string()),
    }
}

/// Call the wire, render with the shared CLI renderer, and map its `ok` flag to `isError`. The CLI
/// text for execute/list/verify is already MCP-appropriate (it names no CLI subcommand).
fn passthrough<T: AgentTransport>(transport: &T, cmd: &AgentCommand) -> ToolResult {
    match transport.call(cmd) {
        Ok(resp) => match super::render(cmd, &resp) {
            Ok(out) => (vec![text_content(out.text)], !out.ok),
            Err(e) => err_text(e.to_string()),
        },
        Err(e) => err_text(e.to_string()),
    }
}

fn result_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests;
