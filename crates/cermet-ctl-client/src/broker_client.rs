//! `CtlBrokerClient` — the keyless `ctl.sock` client that lets cermet-app drive the broker hosted by
//! cermetd (the daemon uid) instead of embedding its own vault. It holds **NO master key** and opens
//! **NO database**: the master key and the three SQLite DBs live only in the daemon process. This is
//! the cermet-app side of the keyholder split.
//!
//! Each method mirrors the daemon-side broker handle 1:1 — same signature, same
//! `Reply = Result<String, cermet_core::Error>` — so the HTTP handlers and `AppState` are unchanged
//! when the broker field is swapped to this type. The blocking [`SocketClient`] call runs on a
//! `spawn_blocking` worker (connect-per-call) under a fixed timeout, so a wedged/slow daemon can
//! never pin a tokio worker.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cermet_broker_core::Reply;
use cermet_ipc::codec::{MAX_FRAME, MAX_RESPONSE_FRAME};
use cermet_ipc::ctl::{
    CtlRequest, RedactedToken, SentenceAuthorityStatus, SentenceCommitOutcome, SentenceSnapshot,
    StagedSentenceCorpus,
};
use cermet_lang::Error;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use zeroize::Zeroizing;

/// Per-call `ctl.sock` timeout. A wedged/slow daemon (or a non-cermetd impostor that accepts but
/// never replies) becomes a fast `Provider` error instead of a hung worker thread — the cermet-app
/// usage-site mitigation (the `SocketClient` lib itself defaults to no timeout).
const CTL_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// A cheap-to-clone, keyless client of the daemon's `ctl.sock`.
#[derive(Clone)]
pub struct CtlBrokerClient {
    sock: PathBuf,
    /// The trusted daemon identity: the launcher passes the expected daemon uid in
    /// `CERMET_DAEMON_UID`. A different-uid attacker cannot write uid-501's launch env, so this is
    /// the trusted anchor that `verify_keyholder_socket` binds the connected peer + inode owner to.
    expected_daemon_uid: u32,
    timeout: Duration,
}

impl CtlBrokerClient {
    /// Construct a client targeting `ctl_sock` — the authoritative endpoint the launcher passes in
    /// `CERMET_CTL_SOCK` (cermet-app is a separate-uid-only client and never reconstructs the path).
    /// `expected_daemon_uid` is the launcher-passed trusted daemon identity.
    pub fn new(ctl_sock: PathBuf, expected_daemon_uid: u32) -> Self {
        Self {
            sock: ctl_sock,
            expected_daemon_uid,
            timeout: CTL_CALL_TIMEOUT,
        }
    }

    /// As [`new`](Self::new) but with an explicit per-call timeout (tests use a short one).
    pub fn with_timeout(ctl_sock: PathBuf, expected_daemon_uid: u32, timeout: Duration) -> Self {
        Self {
            sock: ctl_sock,
            expected_daemon_uid,
            timeout,
        }
    }

    /// Boot handshake: prove the daemon is LIVE before cermet-app binds its listener.
    /// Sends `CtlRequest::Doctor` and accepts ONLY a serving keyholder — the response must be
    /// `kind=="doctor"` AND `serving==true`. Any transport error, a non-`doctor`/error envelope, or
    /// `serving:false` fails closed (`Err`), so the app never serves-and-500s against an absent or
    /// refusing daemon. This call also exercises per-connection `verify_keyholder_socket`.
    pub async fn verify_boot(&self) -> Result<(), Error> {
        let v = self.raw(CtlRequest::Doctor).await?;
        let kind = v.get("kind").and_then(Value::as_str);
        let serving = v.get("serving").and_then(Value::as_bool);
        if kind == Some("doctor") && serving == Some(true) {
            Ok(())
        } else {
            Err(Error::Provider(format!(
                "cermetd is not serving (boot handshake failed): {v}"
            )))
        }
    }

    /// Connect (per call), send one request, read one response — fully async over a tokio
    /// `UnixStream` under an ABSOLUTE deadline covering connect + write + read. A wedged,
    /// slow, backlog-saturated, or non-cermetd-impostor socket becomes a fast `Provider` error and
    /// never parks a worker. Transport faults map to `Provider` (→ 500).
    async fn raw(&self, req: CtlRequest) -> Result<Value, Error> {
        match tokio::time::timeout(self.timeout, self.raw_inner(req)).await {
            Ok(r) => r,
            Err(_elapsed) => Err(Error::Provider(format!(
                "cermetd ctl.sock timed out after {:?} ({})",
                self.timeout,
                self.sock.display()
            ))),
        }
    }

    /// The unbounded inner call (length-prefixed JSON framing); `raw` wraps it in the deadline.
    /// Every reply passes through [`note_build_skew`] on the way out.
    async fn raw_inner(&self, req: CtlRequest) -> Result<Value, Error> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::UnixStream::connect(&self.sock)
            .await
            .map_err(|e| {
                let plain = format!(
                    "cermetd ctl.sock unreachable at {}: {e}",
                    self.sock.display()
                );
                // This is the ONE seam every operator command's ctl call passes through,
                // so a permission-denied connect gets its diagnosis here — the fresh-install group
                // login lag, named on the error the operator is already reading. Every other error
                // (and every successful connect) pays nothing.
                match crate::group_hint::hint_for_this_process(e.kind()) {
                    Some(hint) => Error::Provider(format!("{plain}\n{hint}")),
                    None => Error::Provider(plain),
                }
            })?;
        // Prove the connected peer IS the keyholder daemon BEFORE writing any byte — most
        // importantly the raw provider token in `connect()`. Because this client is connect-per-call,
        // the check is PER-CONNECTION, not a one-time boot check.
        verify_keyholder_socket(&self.sock, &stream, self.expected_daemon_uid)?;
        // Request frame: 4-byte LE length + JSON body, bounded by the codec request cap.
        let body = Zeroizing::new(
            serde_json::to_vec(&req)
                .map_err(|e| Error::Provider(format!("ctl request encode failed: {e}")))?,
        );
        if body.len() as u64 > MAX_FRAME as u64 {
            return Err(Error::Provider(
                "ctl request exceeds the frame cap".to_string(),
            ));
        }
        stream
            .write_all(&(body.len() as u32).to_le_bytes())
            .await
            .map_err(|e| Error::Provider(format!("ctl write failed: {e}")))?;
        stream
            .write_all(body.as_slice())
            .await
            .map_err(|e| Error::Provider(format!("ctl write failed: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| Error::Provider(format!("ctl flush failed: {e}")))?;
        // Response frame: 4-byte LE length + JSON body, bounded by the codec response cap.
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| Error::Provider(format!("ctl read failed: {e}")))?;
        let len = u32::from_le_bytes(len_buf);
        if len > MAX_RESPONSE_FRAME {
            return Err(Error::Provider(
                "ctl response exceeds the frame cap".to_string(),
            ));
        }
        let mut body = Zeroizing::new(vec![0u8; len as usize]);
        stream
            .read_exact(body.as_mut_slice())
            .await
            .map_err(|e| Error::Provider(format!("ctl read failed: {e}")))?;
        let reply: Value = serde_json::from_slice(body.as_slice())
            .map_err(|e| Error::Provider(format!("ctl response decode failed: {e}")))?;
        note_build_skew(&reply);
        Ok(reply)
    }

    // ---- reads (uniform ok/view envelope) ------------------------------------------------------
    /// MCP-repoint quiesce barrier (ctl-only). Enter the barrier — the daemon blocks every new
    /// approved→executing claim and replies a serialized `McpRepointBegin` (token + instance id +
    /// expiry). `cermet mcp install` uses this before repointing the registered MCP server binary.
    pub async fn begin_mcp_repoint(&self, ttl_secs: i64) -> Reply {
        self.raw(CtlRequest::BeginMcpRepoint { ttl_secs })
            .await
            .and_then(decode_view)
    }

    /// Classify custody under the barrier (holder-only) — a serialized `McpQuiesceStatus`.
    pub async fn mcp_repoint_status(&self, token: String) -> Reply {
        self.raw(CtlRequest::McpRepointStatus { token })
            .await
            .and_then(decode_view)
    }

    /// End the barrier (holder-only) through the ordered durable release.
    pub async fn end_mcp_repoint(&self, token: String) -> Reply {
        self.raw(CtlRequest::EndMcpRepoint { token })
            .await
            .and_then(decode_view)
    }
    pub async fn list_credentials(&self) -> Reply {
        self.raw(CtlRequest::ListCredentials)
            .await
            .and_then(decode_view)
    }
    /// Every stored authority profile (name, canonical body, rule count, updated_at). Read-only;
    /// there is deliberately no companion write op — a profile is stored only by
    /// [`Self::commit_sentences`], as part of the ceremony that made that body live.
    pub async fn list_presets(&self) -> Reply {
        self.raw(CtlRequest::ListPresets)
            .await
            .and_then(decode_view)
    }
    pub async fn verify_audit(&self) -> Reply {
        self.raw(CtlRequest::VerifyAudit)
            .await
            .and_then(decode_view)
    }
    /// Read a stored artifact span by handle (the console/CLI shell-output read path). The daemon
    /// collapses every failure to an opaque `not_found`, so a bad/unknown handle surfaces as
    /// `Error::NotFound` → 404 with no existence oracle. `range`/`path` ride RAW: the daemon-side
    /// `ArtifactAddress::from_wire` is the ONE validator of exclusivity + path grammar,
    /// and its rejection joins the same opaque not_found class as a bad handle.
    pub async fn read_artifact(
        &self,
        handle: String,
        range: Option<cermet_ipc::wire::ArtifactRange>,
        path: Option<String>,
    ) -> Reply {
        self.raw(CtlRequest::ReadArtifact {
            handle,
            range,
            path,
        })
        .await
        .and_then(decode_view)
    }
    pub async fn history(&self) -> Reply {
        self.raw(CtlRequest::History).await.and_then(decode_view)
    }
    /// The sentence-joined verb catalog (`{"catalog":[…]}`) — the same daemon-side
    /// projection `agent.sock` serves, so `cermet catalog` renders authority the DAEMON decided
    /// rather than re-joining a corpus it cannot read.
    pub async fn catalog(&self) -> Reply {
        self.raw(CtlRequest::Catalog).await.and_then(decode_view)
    }
    /// The daemon's own health report. Its reply is its OWN envelope
    /// (`{"kind":"doctor", serving, checks:[...]}`), not the uniform ok/view one, so it is decoded
    /// here rather than through `decode_view`. Read-only, no authority, no secret: every check is a
    /// name/status/detail triple the daemon authored about itself.
    ///
    /// `cermet check` asks for it because some questions only the enforcer can answer — whether THIS
    /// caller's uid is admitted to the git plane is one (the admission set is daemon-private config,
    /// and the caller's uid is kernel-attested on this very connection).
    pub async fn doctor(&self) -> Result<Value, Error> {
        let reply = self.raw(CtlRequest::Doctor).await?;
        match reply.get("kind").and_then(Value::as_str) {
            Some("doctor") => Ok(reply),
            Some("error") => Err(error_from_envelope(&reply)),
            _ => Err(Error::Provider(format!(
                "unexpected ctl doctor response: {reply}"
            ))),
        }
    }

    /// The operator's relay hop log, newest first.
    pub async fn relay_hops(&self) -> Reply {
        self.raw(CtlRequest::RelayHops).await.and_then(decode_view)
    }

    pub async fn evidence(&self, request_id: String) -> Reply {
        self.raw(CtlRequest::Evidence { request_id })
            .await
            .and_then(decode_view)
    }
    /// Forward one capability request. `retry_effect` is the OPTIONAL safe effect handle of a prior
    /// attempt whose outcome nothing observed determined — request metadata, never resource data.
    /// Passed through unexamined: the daemon authenticates the lineage and is the only side that may
    /// refuse it.
    pub async fn request(
        &self,
        session: String,
        request_json: String,
        retry_effect: Option<String>,
    ) -> Reply {
        self.raw(CtlRequest::Request {
            session,
            request_json,
            retry_effect,
        })
        .await
        .and_then(decode_view)
    }
    /// The operator execute is keyed by `request_id` — the one public id. The daemon
    /// resolves the grant.
    pub async fn execute_operator(&self, request_id: String) -> Reply {
        self.raw(CtlRequest::ExecuteOperator { request_id })
            .await
            .and_then(decode_view)
    }

    /// Read-only snapshot of the daemon-owned sentence record. Returns the
    /// `SentenceSnapshot` JSON (`Absent` / `Valid` / `Corrupt`, each present state carrying its opaque
    /// exact-record digest + canonical text). Every OS.
    pub async fn sentence_snapshot(&self) -> Result<SentenceSnapshot, Error> {
        self.raw(CtlRequest::SentenceSnapshot)
            .await
            .and_then(decode_typed_view)
    }

    /// Read the served-generation and owner-lockdown observations as one typed view.
    pub async fn sentence_authority_status(&self) -> Result<SentenceAuthorityStatus, Error> {
        self.raw(CtlRequest::SentenceAuthorityStatus)
            .await
            .and_then(decode_typed_view)
    }

    /// Prepare candidate rule text without staging or mutating the live generation.
    pub async fn prepare_sentences(
        &self,
        candidate_text: String,
    ) -> Result<cermet_lang::sentence::PreparedSentenceCorpus, Error> {
        self.raw(CtlRequest::PrepareSentences { candidate_text })
            .await
            .and_then(decode_typed_view)
    }

    /// Round one: stage a candidate corpus. The daemon canonicalizes + validates
    /// against the still-live prior generation and returns the typed canonical text, digest, nonce,
    /// and nonce-bound occurrence; NOTHING is made authoritative. A parse/validation failure is a
    /// daemon error (definite no-stage).
    pub async fn stage_sentences(
        &self,
        candidate_text: String,
    ) -> Result<StagedSentenceCorpus, Error> {
        self.raw(CtlRequest::StageSentences { candidate_text })
            .await
            .and_then(decode_typed_view)
    }

    /// Round two: commit a staged corpus. The daemon flips the generation
    /// atomically iff the token is still live (a stale/unknown/superseded token is a daemon error —
    /// definite no-commit) and returns the `CommitOutcome` JSON (`Committed` / `AlreadyCommitted`).
    ///
    /// `preset` names the key the committed body is ALSO stored under. It rides on the commit so a
    /// stored profile is always one this ceremony produced; the daemon validates the name and is
    /// the only side that may refuse it.
    pub async fn commit_sentences(
        &self,
        staging_token: String,
        preset: Option<String>,
    ) -> Result<SentenceCommitOutcome, Error> {
        self.raw(CtlRequest::CommitSentences {
            staging_token,
            preset,
        })
        .await
        .and_then(decode_typed_view)
    }

    /// Ingest a provider credential. The raw token is exposed ONLY to build the wire request, then
    /// travels (redacted in `Debug`) to the daemon, which holds the vault; cermet-app never persists
    /// it. Keeps the in-process `connect` signature so the handler call sites are unchanged.
    pub async fn connect(
        &self,
        provider: String,
        token: SecretString,
        account_label: Option<String>,
    ) -> Reply {
        let req = CtlRequest::Connect {
            provider,
            account_label,
            token: RedactedToken(token.expose_secret().to_string()),
        };
        self.raw(req).await.and_then(decode_view)
    }
}

/// Per-connection keyholder verification: prove the peer on the other end of
/// `ctl.sock` is the TRUSTED daemon identity before the client sends a single byte (most importantly
/// the raw provider token in `connect()`).
///
/// Trust model: `expected_daemon_uid` is the trusted anchor — the launcher passes it in
/// `CERMET_DAEMON_UID`, and a different-uid attacker cannot write uid-501's launch env. WITHOUT it,
/// today's self-consistency check (peer == inode owner, mode 0o660) is satisfied by an
/// ATTACKER-OWNED 0o660 socket on a hostile `CERMET_CTL_SOCK` path (e.g. `/tmp/evil/ctl.sock`),
/// which would then receive the raw token — a credential-custody leak.
///
/// The on-disk runtime-dir contract is DEFENSE-IN-DEPTH: even a forged/misconfigured
/// `expected_daemon_uid` must still OWN a properly hardened runtime dir (0o700 same-uid/macOS-home,
/// or setgid 0o2711 Linux cross-uid), so an attacker cannot satisfy the binding by squatting a
/// socket in a world-traversable/other-writable directory.
///
/// Checks ALL of, fail closed (`Error::Provider`) on any failure, BEFORE any write:
///   1. `sock` is absolute (reject a relative path).
///   2. the parent runtime dir is a DIRECTORY, owned by `expected_daemon_uid`, mode ∈ {0o700,
///      0o2711}, and NOT other-writable.
///   3. the socket inode is a socket, owned by `expected_daemon_uid`, mode == 0o660.
///   4. the kernel-attested CONNECTED-peer uid == `expected_daemon_uid`.
fn verify_keyholder_socket(
    sock: &Path,
    stream: &tokio::net::UnixStream,
    expected_daemon_uid: u32,
) -> Result<(), Error> {
    // 1. Absolute path only — a relative ctl.sock path is never a trusted launcher endpoint.
    if !sock.is_absolute() {
        return Err(Error::Provider(format!(
            "ctl.sock path {} is not absolute (untrusted endpoint)",
            sock.display()
        )));
    }
    // 2. Runtime-dir contract (defense-in-depth): the daemon-owned dir the socket lives in must be
    // hardened, so a forged expected uid cannot be satisfied by a socket in a hostile/traversable dir.
    let runtime_dir = sock.parent().ok_or_else(|| {
        Error::Provider(format!(
            "ctl.sock path {} has no parent runtime dir",
            sock.display()
        ))
    })?;
    let dir_meta = std::fs::symlink_metadata(runtime_dir)
        .map_err(|e| Error::Provider(format!("ctl runtime dir stat failed: {e}")))?;
    if !dir_meta.file_type().is_dir() {
        return Err(Error::Provider(format!(
            "ctl runtime dir {} is not a directory (impostor)",
            runtime_dir.display()
        )));
    }
    if dir_meta.uid() != expected_daemon_uid {
        return Err(Error::Provider(format!(
            "ctl runtime dir {} owner {} is not the expected daemon uid {} (untrusted)",
            runtime_dir.display(),
            dir_meta.uid(),
            expected_daemon_uid
        )));
    }
    let dir_mode = dir_meta.mode() & 0o7777;
    if dir_mode != 0o700 && dir_mode != 0o2711 {
        return Err(Error::Provider(format!(
            "ctl runtime dir {} mode {dir_mode:#o} is not a hardened daemon dir (0o700 or 0o2711)",
            runtime_dir.display()
        )));
    }
    if dir_mode & 0o002 != 0 {
        return Err(Error::Provider(format!(
            "ctl runtime dir {} is other-writable (mode {dir_mode:#o}) — not a trusted dir",
            runtime_dir.display()
        )));
    }
    // 3. Socket inode contract. No-follow: inspect the path's own inode, not a symlink target.
    let meta = std::fs::symlink_metadata(sock)
        .map_err(|e| Error::Provider(format!("ctl.sock stat failed: {e}")))?;
    if !meta.file_type().is_socket() {
        return Err(Error::Provider(format!(
            "ctl.sock at {} is not a socket inode (impostor)",
            sock.display()
        )));
    }
    if meta.uid() != expected_daemon_uid {
        return Err(Error::Provider(format!(
            "ctl.sock {} owner {} is not the expected daemon uid {} (impostor)",
            sock.display(),
            meta.uid(),
            expected_daemon_uid
        )));
    }
    let mode = meta.mode() & 0o777;
    if mode != 0o660 {
        return Err(Error::Provider(format!(
            "ctl.sock mode {mode:#o} is not the daemon's exact 0o660 (impostor)"
        )));
    }
    // 4. Kernel-attested connected peer must BE the trusted daemon identity.
    let peer = cermet_ipc::peer::peer_cred(stream.as_raw_fd())
        .map_err(|e| Error::Provider(format!("ctl peer-cred lookup failed: {e}")))?;
    if peer.uid != expected_daemon_uid {
        return Err(Error::Provider(format!(
            "ctl.sock peer uid {} is not the expected daemon uid {} (not the keyholder)",
            peer.uid, expected_daemon_uid
        )));
    }
    Ok(())
}

/// Say ONCE, on stderr, when the daemon that answered is a different build than this
/// binary. `ctl.sock` has no handshake to compare on, so the comparison rides the reply — but it
/// belongs HERE, at the one place every operator command's ctl call passes through, not in each
/// command. Detection only: nothing refuses, and a note never changes an exit code.
fn note_build_skew(reply: &Value) {
    static NOTED: std::sync::Once = std::sync::Once::new();
    if let Some(note) = build_skew_note(reply) {
        NOTED.call_once(|| eprintln!("cermet: {note}"));
    }
}

/// The line [`note_build_skew`] prints, or `None` when the daemon is this same build. Pure, so the
/// wording and the absent-stamp case are testable without a process.
fn build_skew_note(reply: &Value) -> Option<String> {
    let advertised = reply.get("build").and_then(Value::as_str).unwrap_or("");
    let daemon = cermet_ipc::build_skew(advertised)?;
    Some(format!(
        "note: this CLI is cermet {ours}, but cermetd is {daemon} — one of the two is stale. \
         Reinstall the pair (`make -C dist install`) if a command behaves unexpectedly; \
         authority and receipts are unaffected.",
        ours = cermet_ipc::BUILD_ID,
    ))
}

/// Reconstruct a `cermet_core::Error` from the daemon's error envelope, preserving the HTTP status
/// class (`denied`→403 / `not_found`→404 / `invalid`→400 / else→500). The (`code`, `reason`) pair is
/// the wire contract pinned on `Error` itself: `code` is the CLASS and `reason` is the
/// BARE payload, so the class prefix is rendered exactly once — here, by the rebuilt variant's
/// `Display`. An unknown code becomes `Provider` (→ 500), the fail-safe.
fn error_from_envelope(v: &Value) -> Error {
    Error::from_wire(
        v.get("code").and_then(Value::as_str),
        v.get("reason")
            .and_then(Value::as_str)
            .unwrap_or("ctl error"),
    )
}

/// Decode the uniform `{"kind":"ok","view":..}` / `{"kind":"error",..}` envelope into a `Reply`. A
/// `kind:"ok"` with NO `view` is rejected (fail closed) rather than read as an empty success —
/// closing that class at the cermet-app boundary.
fn decode_view(v: Value) -> Reply {
    match v.get("kind").and_then(Value::as_str) {
        Some("ok") => match v.get("view") {
            Some(view) => Ok(view.to_string()),
            None => Err(Error::Provider(format!(
                "malformed ctl ok envelope (no view): {v}"
            ))),
        },
        Some("error") => Err(error_from_envelope(&v)),
        _ => Err(Error::Provider(format!("unexpected ctl response: {v}"))),
    }
}

fn decode_typed_view<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, Error> {
    match v.get("kind").and_then(Value::as_str) {
        Some("ok") => v
            .get("view")
            .cloned()
            .ok_or_else(|| Error::Provider("malformed ctl ok envelope (no view)".into()))
            .and_then(|view| {
                serde_json::from_value(view)
                    .map_err(|_| Error::Provider("malformed typed ctl response".into()))
            }),
        Some("error") => Err(error_from_envelope(&v)),
        _ => Err(Error::Provider("unexpected ctl response envelope".into())),
    }
}

#[cfg(test)]
mod tests;
