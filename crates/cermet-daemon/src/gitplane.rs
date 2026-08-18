//! The attested STREAM plane: `git.sock`.
//!
//! One more SO_PEERCRED-gated unix listener, following the agent plane exactly (bind in the agents
//! runtime dir, peercred on accept, bounded-admission accept loop). The daemon spawns
//! `git receive-pack` / `git upload-pack` on the repo's persistent mirror with its stdio wired to
//! the connection, and gets out of the way.
//!
//! **Cermet is authorization and receipt — nothing else.** No frames, no
//! staging, no wire format of ours: after one short header line, the connection carries git's own
//! protocol byte-for-byte. Hostile input is `receive-pack`'s problem — git's most-hardened surface
//! — and the daemon never looks at a pack.
//!
//! Cermet appears exactly twice in a push: git's `update` hook (which calls back over
//! [`hook`](crate::gitplane::hook)) and the credentialed hop the hook confirms.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cermet_broker_actor::BrokerHandle;
use cermet_core::git::{GitConfig, GitService, RepoId};

use cermet_ipc::peer;

use crate::serve::{accept_loop, ServeConfig};

/// Cap on the request pkt-line, matching git-daemon's own (`MAX_PACKET_MAX_SIZE`-bounded reads of
/// a request that git-daemon caps at 4096). Long enough for any legal identity plus extra args,
/// short enough that a client cannot make us buffer.
const MAX_REQUEST_BYTES: usize = 4096;

/// The per-stream context a spawned `receive-pack`'s update hook calls back with. Keyed by a
/// PER-STREAM token the daemon puts in the child's environment, so a hook invocation can prove
/// which attested stream it belongs to without the hook being trusted to say.
///
/// Per-stream, not per-invocation: git runs the `update` hook once per ref, so one `git push` of
/// three branches legitimately presents the same token three times. It dies with the stream
/// ([`TokenGuard`]), not with the first read.
#[derive(Clone)]
pub struct StreamContext {
    pub repo: RepoId,
    pub principal: String,
    pub session_id: String,
    pub peer_uid: Option<i64>,
}

/// Live streams, by hook token. One entry per in-flight `receive-pack`.
pub type HookRegistry = Arc<Mutex<std::collections::HashMap<String, StreamContext>>>;

pub fn hook_registry() -> HookRegistry {
    Arc::new(Mutex::new(std::collections::HashMap::new()))
}

/// Everything the git plane needs that is not per-connection.
#[derive(Clone)]
pub struct GitPlane {
    pub broker: BrokerHandle,
    pub git: GitConfig,
    /// The program git's `update` hook execs — this daemon's own binary.
    pub hook_program: PathBuf,
    /// Where a hook invocation calls back.
    pub hook_socket: PathBuf,
    pub registry: HookRegistry,
    /// The uids this listener admits. Unlike `agent.sock` — whose only legitimate client is the
    /// bridge process the sudoers pin spawns AS the agent uid — the git helper connects DIRECTLY as
    /// whoever typed it, and on today's single-principal box that is the operator's session uid
    /// (the human AND every harness agent under it). The set is a set so the
    /// multi-principal track adds per-agent uids as entries, not code. Empty admits no one.
    pub admitted_uids: Vec<u32>,
}

/// Bind `git.sock` beside `agent.sock`. Reachability is set wide enough for every admitted uid to
/// reach it — the set spans disjoint groups, so the caller passes a wide mode — then narrowed to
/// the admitted set by the kernel-attested peercred check on accept — never call the file
/// mode the boundary.
pub fn bind_git_socket(
    agent_runtime_dir: &std::path::Path,
    mode: u32,
) -> Result<(std::os::unix::net::UnixListener, PathBuf), crate::serve::ServeError> {
    crate::serve::bind_socket(agent_runtime_dir, "git.sock", mode)
}

/// The uids any DIRECT-connection plane admits. A plane client (`git-remote-cermet` today; any
/// future provider-native surface that connects a stream rather than riding the bridge) presents
/// its CALLER'S real uid — there is no sudo'd hop converting to the agent uid — so in service mode
/// the set is {agent_uid, approver_uid}: the agent service account AND the operator's session uid,
/// which is what the human and every harness agent actually present as. Dev mode admits the
/// daemon's own uid (the same-uid path, matching the agent gate). Sole consumer today: `git.sock`.
/// Pure + unit-pinned. Lives HERE, beside the gate that consumes it, because `doctor` reports
/// the same set to the caller asking whether their own push will be admitted — two
/// readings of one rule, never two copies of it.
pub fn admitted_uids(
    service_mode: bool,
    agent_uid: u32,
    approver_uid: u32,
    dev_uid: u32,
) -> Vec<u32> {
    let mut uids = if service_mode {
        vec![agent_uid, approver_uid]
    } else {
        vec![dev_uid]
    };
    uids.dedup();
    uids
}

/// Serve `git.sock` forever on a pre-bound listener.
pub fn serve_git_socket(
    listener: std::os::unix::net::UnixListener,
    plane: GitPlane,
    config: ServeConfig,
) {
    let rt = tokio::runtime::Handle::current();
    let timeouts = config.timeouts;
    let handle: crate::serve::ConnHandler = Arc::new(move |stream| {
        handle_stream(stream, &plane, &rt, timeouts);
    });
    accept_loop(listener, config.max_conns, handle);
}

/// Handle ONE git stream to completion.
fn handle_stream(
    mut stream: StdUnixStream,
    plane: &GitPlane,
    rt: &tokio::runtime::Handle,
    timeouts: crate::serve::ServeTimeouts,
) {
    let peer = match peer::peer_cred(stream.as_raw_fd()) {
        Ok(p) => p,
        Err(_) => return,
    };
    // Bound the handshake, exactly as the agent plane does. Without it a client that
    // connects and never sends a newline holds this handler thread and its `ConnSlot` forever, and
    // `max_conns` of them wedge the plane until the daemon restarts. Armed
    // BEFORE the admission gate so the refusal write below is bounded too.
    if stream.set_read_timeout(Some(timeouts.handshake)).is_err()
        || stream.set_write_timeout(Some(timeouts.handshake)).is_err()
    {
        return;
    }

    // Kernel-attested membership gate, refused before any byte is READ. Identity only — authority
    // is the sentence corpus's job at the hook: an admission-set exclusion is an
    // undeclared deny no sentence expresses, so the set carries every uid that legitimately issues
    // commands. The refusal writes one legible ERR: a silent drop surfaces to the
    // caller as a mute "Connection reset by peer", which is expensive to diagnose and pays off
    // no named adversary by staying silent.
    if !plane.admitted_uids.contains(&peer.uid) {
        return refuse(
            &mut stream,
            &format!(
                "cermet: uid {} is not admitted to the git plane — run git as the \
                 installed agent or approver user (see `cermet check`)",
                peer.uid
            ),
        );
    }
    let GitRequest { service, repo } = match read_request(&mut stream) {
        Ok(request) => request,
        Err(why) => return refuse(&mut stream, &why),
    };

    let principal = format!("uid:{}", peer.uid);
    let session_id = match open_session(plane, rt, &principal, peer.pid, peer.uid) {
        Some(id) => id,
        None => {
            return refuse(
                &mut stream,
                "cermet: could not open a session for this stream",
            )
        }
    };

    // A PUSH creates the mirror on first contact and (re)installs the update hook; the DECISION for
    // it comes later, from git's own `update` hook once receive-pack knows the refs.
    //
    // A FETCH decides FIRST and then refreshes. The read stream is this verb's door: a
    // sentence must allow reading this repo, and then the mirror is brought up to date from the
    // upstream before a single ref is advertised. There is deliberately NO path from here to
    // `upload-pack` that skips the refresh — serving a stale mirror silently was the whole bug — and
    // the mirror is created only after the allow, so an unruled repo still materializes nothing.
    let mirror = match service {
        GitService::ReceivePack => {
            match cermet_core::git::ensure_mirror(&plane.git, &repo, &plane.hook_program) {
                Ok(path) => path,
                Err(error) => return refuse(&mut stream, &format!("cermet: {error}")),
            }
        }
        GitService::UploadPack => {
            let attempt = cermet_core::FetchAttempt {
                repo: repo.clone(),
                principal: principal.clone(),
                session_id: session_id.clone(),
                peer_uid: Some(peer.uid as i64),
                hook_program: plane.hook_program.clone(),
            };
            let broker = plane.broker.clone();
            let verdict = rt.block_on(async move { broker.authorize_fetch(attempt).await });
            match verdict {
                Ok(verdict) if verdict.allow => {
                    crate::log::emit(format!("cermetd: {}", verdict.message));
                }
                Ok(verdict) => return refuse(&mut stream, &verdict.message),
                Err(error) => return refuse(&mut stream, &format!("cermet: {error}")),
            }
            cermet_core::git::mirror_path(&plane.git, &repo)
        }
    };

    let token = cermet_core::git::stream_token();
    if let Ok(mut map) = plane.registry.lock() {
        map.insert(
            token.clone(),
            StreamContext {
                repo: repo.clone(),
                principal,
                session_id,
                peer_uid: Some(peer.uid as i64),
            },
        );
    }
    let _guard = TokenGuard {
        registry: plane.registry.clone(),
        token: token.clone(),
    };

    let mut command = match cermet_core::git::service_command(&plane.git, service, &mirror) {
        Ok(command) => command,
        Err(error) => return refuse(&mut stream, &format!("cermet: {error}")),
    };
    // The ONLY two additions to the hermetic environment: where the update hook asks, and which
    // attested stream is asking.
    command.env("CERMET_HOOK_SOCKET", &plane.hook_socket);
    command.env("CERMET_HOOK_TOKEN", &token);

    // CLEAR the handshake timeout before the fd is duplicated: `SO_RCVTIMEO`/`SO_SNDTIMEO` are
    // SOCKET-level, so they ride the dup'd descriptor into `receive-pack` and would make git fail
    // mid-transfer on any pause longer than the handshake budget. The stream's own
    // lifetime is the bound from here on.
    if stream.set_read_timeout(None).is_err() || stream.set_write_timeout(None).is_err() {
        return refuse(&mut stream, "cermet: could not hand the stream to git");
    }

    // stdio IS the connection: git's protocol travels the way git's protocol travels. A socket is
    // not a `File`, so the fds are duplicated into owned handles the child inherits directly —
    // nothing of ours sits between git and the wire.
    let (stdin, stdout) = match (dup_stdio(&stream), dup_stdio(&stream)) {
        (Some(a), Some(b)) => (a, b),
        _ => return refuse(&mut stream, "cermet: could not wire the stream"),
    };
    command
        .stdin(stdin)
        .stdout(stdout)
        .stderr(std::process::Stdio::piped());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return refuse(&mut stream, &format!("cermet: cannot start git: {error}")),
    };
    // The child now owns the only copies of the connection. Drop ours: if the daemon kept a handle
    // open, the client would never see end-of-stream when git finished and would hang forever.
    drop(stream);
    // git writes human text (including our hook's refusal) to its stderr; receive-pack relays the
    // hook's own stderr through the protocol itself, so this is daemon-log material only.
    if let Some(err) = child.stderr.take() {
        let mut buf = Vec::new();
        let _ = std::io::Read::take(err, 64 * 1024).read_to_end(&mut buf);
        if !buf.is_empty() {
            crate::log::emit(format!(
                "cermetd: git {} on {}: {}",
                service.as_str(),
                repo.slug(),
                String::from_utf8_lossy(&buf).trim()
            ));
        }
    }
    let _ = child.wait();
}

/// Duplicate the connection's fd into an owned `Stdio` the child inherits.
fn dup_stdio(stream: &StdUnixStream) -> Option<std::process::Stdio> {
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: `dup` returns a fresh fd we own outright; wrapping it in `OwnedFd` transfers that
    // ownership to the `Stdio`, which closes it after the spawn.
    let fd = unsafe { libc::dup(stream.as_raw_fd()) };
    if fd < 0 {
        return None;
    }
    Some(std::process::Stdio::from(unsafe {
        OwnedFd::from_raw_fd(fd)
    }))
}

/// Mint (or reuse) the session this stream's decisions are audited under.
fn open_session(
    plane: &GitPlane,
    rt: &tokio::runtime::Handle,
    principal: &str,
    pid: Option<u32>,
    uid: u32,
) -> Option<String> {
    let session_id = cermet_core::git::stream_session_id();
    let broker = plane.broker.clone();
    let id = session_id.clone();
    let cmd = format!("git-stream {principal}");
    let pid = pid.map(|p| p as i64);
    let result = rt.block_on(async move {
        broker
            // The git plane has no handshake and no self-report: nothing is captured, so nothing
            // is recorded.
            .open_session(
                id,
                cmd,
                pid,
                Some(uid as i64),
                cermet_broker_actor::SelfReported::default(),
            )
            .await
            .ok()
    });
    result.map(|_| session_id)
}

/// One decoded stream request.
struct GitRequest {
    service: GitService,
    repo: RepoId,
}

/// Read GIT-DAEMON'S OWN request pkt-line, the format every git client already knows how to write:
///
/// ```text
/// 0033git-upload-pack /github/acme/website\0host=cermet\0
/// ```
///
/// A 4-hex length covering the whole packet, then `<service> <path>NUL`, then zero or more
/// `key=valueNUL` extra args. This replaced a bespoke one-line header of ours.
/// The reason is NOT that git writes this format for us over `connect` — it does
/// not; our helper writes it. It is that the format is not ours to own or version: any git-daemon
/// -format client (`git daemon --inetd` behind a socket, a future helper) substitutes for our
/// helper without the plane changing, which is the same boundary rule the `ERR` pkt-line refusal
/// follows — where git owns a mechanism, use git's.
fn read_request(stream: &mut StdUnixStream) -> Result<GitRequest, String> {
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|e| format!("cermet: could not read the request pkt-line: {e}"))?;
    let length = std::str::from_utf8(&length)
        .ok()
        .and_then(|hex| usize::from_str_radix(hex, 16).ok())
        .ok_or_else(|| "cermet: the request is not a pkt-line".to_string())?;
    if !(5..=MAX_REQUEST_BYTES).contains(&length) {
        return Err(format!(
            "cermet: request pkt-line length {length} is outside 5..={MAX_REQUEST_BYTES}"
        ));
    }
    let mut payload = vec![0u8; length - 4];
    stream
        .read_exact(&mut payload)
        .map_err(|e| format!("cermet: the request pkt-line is truncated: {e}"))?;
    parse_request(&payload)
}

/// Decode the request payload. Fail closed on anything that is not exactly one known service and
/// one valid repo identity.
fn parse_request(payload: &[u8]) -> Result<GitRequest, String> {
    let mut fields = payload.split(|b| *b == 0);
    let head = fields
        .next()
        .ok_or_else(|| "cermet: the request names no service".to_string())?;
    let head = std::str::from_utf8(head).map_err(|_| "cermet: the request is not UTF-8")?;
    let (service, path) = head
        .split_once(' ')
        .ok_or_else(|| "cermet: the request must be `<service> <path>`".to_string())?;
    let service = GitService::parse(service)
        .ok_or_else(|| format!("cermet: `{service}` is not a git service this plane serves"))?;
    // The repo identity is validated HERE, at the trust-boundary crossing, BEFORE a path
    // is joined or any git process exists. Nothing downstream re-sanitizes it.
    let repo = RepoId::parse(path.trim_start_matches('/')).map_err(|e| format!("cermet: {e}"))?;

    // Extra args are git-daemon's `key=value` list. All of them are accepted and IGNORED: `host=` has
    // nothing to mean on a unix socket, and there is deliberately no protocol-version handling —
    // `connect`, the capability the helper announces, is git's v0/v1 fd-splice
    // capability, so no shipped client can ask for v2 here and version negotiation happens in band.
    Ok(GitRequest { service, repo })
}

/// Refuse the stream in GIT'S OWN error vocabulary: an `ERR <message>` pkt-line, which both
/// services accept at advertisement time and which git's transport renders as
/// `fatal: remote error: <message>` in the agent's ordinary `git push`/`git fetch` output.
///
/// A bare sentence is not a pkt-line — git would read the first four
/// bytes as a length and die with `fatal: protocol error: bad line length character: cerm`, so
/// every pre-spawn refusal would reach the human as noise. Git already owns this mechanism; inventing a
/// plain-text one would be a clear product-boundary violation.
///
/// A pkt-line is `%04x` of the TOTAL length (payload + the four length bytes) followed by the
/// payload.
fn refuse(stream: &mut StdUnixStream, message: &str) {
    crate::log::emit(format!("cermetd: git.sock refusal: {message}"));
    let _ = stream.write_all(&err_pkt_line(message));
    let _ = stream.flush();
}

/// Encode `message` as an `ERR` pkt-line. Payloads are clamped so the 4-hex length always fits
/// (git's own limit is 65516 bytes of payload); our refusals are sentences, so this only ever
/// matters if a provider error string runs away.
fn err_pkt_line(message: &str) -> Vec<u8> {
    const MAX_PAYLOAD: usize = 65516;
    let body = format!("ERR {}", message.replace('\n', "; "));
    let mut body = body.into_bytes();
    body.truncate(MAX_PAYLOAD);
    let mut out = format!("{:04x}", body.len() + 4).into_bytes();
    out.extend_from_slice(&body);
    out
}

/// Drops a stream's hook token when the stream ends, so a token can never outlive its connection.
/// This — not consume-on-read — is what bounds the token's life: a multi-ref push needs it more
/// than once.
struct TokenGuard {
    registry: HookRegistry,
    token: String,
}

impl Drop for TokenGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.registry.lock() {
            map.remove(&self.token);
        }
    }
}

pub mod hook;

#[cfg(test)]
mod tests {
    use super::*;

    const T_AGENT_UID: u32 = 903;
    const T_APPROVER_UID: u32 = 902;
    const T_DEV_UID: u32 = 901;

    // git.sock has NO bridge hop — callers arrive as their real uid — so service mode
    // must admit the operator's session uid alongside the agent service account, or nobody who
    // actually types `git push` on the box can reach the plane.
    #[test]
    fn plane_admits_agent_and_approver_uids_in_service() {
        let uids = admitted_uids(true, T_AGENT_UID, T_APPROVER_UID, T_DEV_UID);
        assert!(
            uids.contains(&T_AGENT_UID),
            "agent service account admitted"
        );
        assert!(
            uids.contains(&T_APPROVER_UID),
            "the operator session uid must be admitted — the git helper connects directly, \
             with no sudo'd bridge converting the caller to the agent uid"
        );
        assert!(
            !uids.contains(&T_DEV_UID),
            "the daemon/dev uid is NOT admitted in service mode"
        );
    }

    #[test]
    fn plane_admits_only_dev_uid_in_dev_mode() {
        assert_eq!(
            admitted_uids(false, T_AGENT_UID, T_APPROVER_UID, T_DEV_UID),
            vec![T_DEV_UID],
            "dev/embedded mode admits the daemon's own uid, matching the agent gate"
        );
    }
}
