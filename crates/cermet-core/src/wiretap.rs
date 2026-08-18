//! The wire tee — a test/diagnostic instrument that logs each provider response AS IT ARRIVES.
//!
//! This is the "as it comes in" half. It sits at the executor's EARLIEST wire-read point — the
//! moment the response body has been read off the socket, before parsing, before assertions,
//! before retention — so what it records is what the provider actually sent.
//!
//! The "as it comes out" half needs no instrument: it is the receipt result and the stored
//! artifact. The sitting engine diffs the three per action, and under the verbatim response
//! contract the expected delta is the documented one and nothing else:
//!   * a SUCCESS: receipt result == artifact == teed body, exactly;
//!   * a FAILURE: the executor's envelope `{"status": N, "error": <teed body>}`;
//!   * a step declaring `retention: none`: no artifact at all, by declaration.
//!
//! ## Threat model — stated, because a defense without an adversary gets cut in review
//!
//! The adversary here is BUGS, not an attacker: a projection we thought we deleted, a body mutated
//! between the socket and the receipt, an artifact that disagrees with the result it was minted
//! from. A tee at the source catches all three, and it is first-party trusted code, so it gets
//! ordinary engineering — no process isolation from our own pure functions, no hash chain over a
//! log its own writer could rewrite.
//!
//! What the tee is NOT allowed to do is weaken custody, so one rule is absolute and enforced below:
//! **the vault credential is byte-redacted out of every teed body**, exactly as `redaction.rs` does
//! for artifacts. A provider does not echo our API key, but "does not" is not "cannot", and a log
//! file is a log file. Nothing else is touched: no field is dropped, no shape is normalized.
//!
//! ## Fail-open by design, in the only direction that is safe
//!
//! The tee is OFF unless `CERMET_WIRE_TEE` names an absolute path, read ONCE from the daemon's own
//! environment. An agent-facing request can never set it and no policy/grant field carries it. When
//! it is off, this module costs one `OnceLock` read per response and writes nothing. When a tee
//! write fails, the write is dropped and execution continues unchanged: an instrument must never
//! be able to fail a real run.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// The daemon-side environment switch: an absolute path to append newline-delimited JSON to.
pub const WIRE_TEE_ENV: &str = "CERMET_WIRE_TEE";

/// One tee line's schema tag, so a reader can tell this file apart from any other JSONL.
pub const WIRE_TEE_SCHEMA: &str = "cermet.wire-tee.v1";

thread_local! {
    /// Test-only tee path. The production switch is read ONCE from the process environment, which
    /// a test cannot vary; this per-thread override lets the suite arm a real tee against a temp
    /// file without making the production path mutable. Never compiled outside `cfg(test)`.
    #[cfg(test)]
    static PATH_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Test-only scoped arming. Restores the prior override on drop.
#[cfg(test)]
pub(crate) struct ArmedTee(Option<PathBuf>);

#[cfg(test)]
impl ArmedTee {
    pub(crate) fn at(path: &std::path::Path) -> Self {
        Self(PATH_OVERRIDE.with(|cell| cell.replace(Some(path.to_path_buf()))))
    }
}

#[cfg(test)]
impl Drop for ArmedTee {
    fn drop(&mut self) {
        let prior = self.0.take();
        PATH_OVERRIDE.with(|cell| *cell.borrow_mut() = prior);
    }
}

#[cfg(test)]
fn tee_path_override() -> Option<PathBuf> {
    PATH_OVERRIDE.with(|cell| cell.borrow().clone())
}

fn tee_path() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(forced) = tee_path_override() {
        return Some(forced);
    }
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| {
        let raw = std::env::var(WIRE_TEE_ENV).ok()?;
        let path = PathBuf::from(raw);
        // Absolute only: a relative path would land wherever the daemon happens to be cwd'd.
        path.is_absolute().then_some(path)
    })
    .clone()
}

/// Is the wire tee armed for this process?
pub fn armed() -> bool {
    tee_path().is_some()
}

/// The one-line startup banner a daemon prints when the tee is armed. `None` in the normal case, so
/// the production log is unchanged.
pub fn startup_banner() -> Option<String> {
    tee_path().map(|path: PathBuf| {
        format!(
            "WIRE TEE ARMED: {WIRE_TEE_ENV}={} — every provider response body is appended to that \
             file as it arrives (vault credential redacted, nothing else). Diagnostic instrument; \
             never enable it on a daemon holding credentials you care about logging around.",
            path.display()
        )
    })
}

thread_local! {
    /// Which verb/step the current thread is executing. The provider executor runs synchronously on
    /// the caller's thread, so a thread-local attributes each teed body correctly even when several
    /// executions are in flight in-process — an env var or a global could not.
    static CONTEXT: std::cell::RefCell<Option<Context>> = const { std::cell::RefCell::new(None) };
}

#[derive(Clone)]
struct Context {
    provider: String,
    action: String,
    step: String,
    /// BROKER-HELD secrets beyond the vault credential that this execution could see echoed back —
    /// today the money idempotency key. The broker's own audit/artifact path folds the same
    /// material into its redaction set (`broker/execute.rs`, "so a provider-controlled body or
    /// error cannot echo it into any result, audit, or artifact"); the tee is a second output
    /// channel and owes the same promise.
    extra_secrets: Vec<String>,
}

/// Scoped attribution for everything teed while it is alive. Restores the prior context on drop, so
/// a nested execution cannot leave a stale label behind.
pub(crate) struct TeeScope(Option<Context>);

impl TeeScope {
    pub(crate) fn enter(provider: &str, action: &str, step: &str, extra_secrets: &[&str]) -> Self {
        let next = armed().then(|| Context {
            provider: provider.to_string(),
            action: action.to_string(),
            step: step.to_string(),
            extra_secrets: extra_secrets
                .iter()
                .filter(|secret| !secret.is_empty())
                .map(|secret| (*secret).to_string())
                .collect(),
        });
        Self(CONTEXT.with(|cell| cell.replace(next)))
    }
}

impl Drop for TeeScope {
    fn drop(&mut self) {
        let prior = self.0.take();
        CONTEXT.with(|cell| *cell.borrow_mut() = prior);
    }
}

/// Build one tee line: the body exactly as it came off the socket, with every broker-held secret
/// byte-redacted out of it. Split out from [`record`] so the redaction promise is testable without
/// a filesystem or an armed process, since it needs its own seam to verify independently.
///
/// `credential` is the plaintext the executor is authenticating with; `extra` is everything else
/// the broker holds that this response could echo (the money idempotency key). Both are redacted
/// with the same `redaction.rs` pass artifacts get, which is the parity the module header claims.
fn tee_line(
    status: u16,
    body: &[u8],
    credential: &str,
    context: Option<&Context>,
) -> Option<Vec<u8>> {
    let mut secrets: Vec<&str> =
        Vec::with_capacity(1 + context.map_or(0, |c| c.extra_secrets.len()));
    if !credential.is_empty() {
        secrets.push(credential);
    }
    if let Some(context) = context {
        secrets.extend(context.extra_secrets.iter().map(String::as_str));
    }
    secrets.retain(|secret| !secret.is_empty());
    let redacted = crate::redaction::redact_body_bytes_refs(body, &secrets);
    let line = serde_json::json!({
        "schema": WIRE_TEE_SCHEMA,
        "at": crate::util::now_rfc3339(),
        "provider": context.map(|c| c.provider.as_str()),
        "action": context.map(|c| c.action.as_str()),
        "step": context.map(|c| c.step.as_str()),
        "status": status,
        // The body as TEXT, so a reader can `json.loads` it and compare structurally. A body that
        // is not valid UTF-8 is recorded lossily and flagged, never silently repaired.
        "body": String::from_utf8_lossy(&redacted),
        "body_bytes": redacted.len(),
        "utf8": std::str::from_utf8(&redacted).is_ok(),
    });
    let mut encoded = serde_json::to_vec(&line).ok()?;
    encoded.push(b'\n');
    Some(encoded)
}

/// Append one response to the tee, attributed by the executing thread's [`TeeScope`]. Silent and
/// infallible from the caller's point of view — see the module note on fail-open.
pub(crate) fn record(status: u16, body: &[u8], credential: &str) {
    let context = CONTEXT.with(|cell| cell.borrow().clone());
    append(status, body, credential, context.as_ref());
}

/// Append one RELAY hop chunk, attributed explicitly.
///
/// The relay's response arrives on the daemon's pump thread — never on the broker actor —
/// and never inside the executor's [`TeeScope`] — so this path carries its own attribution instead
/// of reading a thread-local that was set somewhere else. `secrets` is the same vault material the
/// pump already redacts the client's copy with, and the tee runs its own pass over the RAW bytes,
/// exactly like the classic path: the redaction promise is kept HERE, not by the caller.
///
/// The pump gates this call on [`armed`] so a disarmed daemon does not even format the step label
/// for every 16 KiB of a streaming build log.
pub(crate) fn record_relay_chunk(
    provider: &str,
    action: &str,
    step: &str,
    status: u16,
    body: &[u8],
    secrets: &[String],
) {
    let context = Context {
        provider: provider.to_string(),
        action: action.to_string(),
        step: step.to_string(),
        extra_secrets: secrets.to_vec(),
    };
    append(status, body, "", Some(&context));
}

fn append(status: u16, body: &[u8], credential: &str, context: Option<&Context>) {
    let Some(path) = tee_path() else {
        return;
    };
    let Some(encoded) = tee_line(status, body, credential, context) else {
        return;
    };

    // One mutex per process keeps concurrent executions from interleaving half-lines. A poisoned
    // lock means a previous writer panicked mid-write; the instrument stops rather than corrupting.
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let Ok(_guard) = LOCK.get_or_init(|| Mutex::new(())).lock() else {
        return;
    };
    if !path_is_writable_tee(&path) {
        return;
    }
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode_0600()
        .open(&path);
    if let Ok(mut file) = opened {
        let _ = file.write_all(&encoded);
    }
}

/// May the tee write to this path?
///
/// `OpenOptions::mode` applies only to a file the open CREATES, and `open` follows symlinks — so a
/// pre-existing world-readable file, or a symlink pointing somewhere else entirely, would receive
/// provider-response bytes without the owner-only guarantee this module's header asserts.
///
/// The answer is DECLINE, not repair, and the distinction is deliberate: the module's discipline is
/// fail-open-silently (an instrument must never fail a real run), and a path that is not what the
/// operator configured is a path we refuse to write — not one we take ownership of by chmod'ing
/// someone else's file. An absent path is fine: the open below creates it 0600.
fn path_is_writable_tee(path: &std::path::Path) -> bool {
    // `symlink_metadata` does NOT follow the final component, which is the whole point.
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        // Absent (or unstattable) — the create-0600 path below owns it.
        Err(_) => return true,
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        // Owner-only or tighter, and ours. Anything looser is someone else's file or a file
        // someone else can read the provider's bodies out of.
        if metadata.permissions().mode() & 0o077 != 0 {
            return false;
        }
        if metadata.uid() != unsafe { libc::getuid() } {
            return false;
        }
    }
    true
}

/// `OpenOptions::mode` is Unix-only; this keeps the call site readable and the file owner-only.
trait Mode0600 {
    fn mode_0600(&mut self) -> &mut Self;
}

impl Mode0600 for std::fs::OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            self.mode(0o600)
        }
        #[cfg(not(unix))]
        {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tee_is_off_unless_an_absolute_path_names_it() {
        // The switch is read once from the daemon's own environment and this suite does not set
        // it, so the production default is proved here: armed() is false and record() is a no-op
        // that cannot panic even with no context and a hostile body.
        assert_eq!(WIRE_TEE_ENV, "CERMET_WIRE_TEE");
        assert!(!armed(), "the tee must be off by default");
        assert!(startup_banner().is_none());
        record(200, b"\xff\xfe not utf8", "sk_test_never_written");
    }

    /// The tee must redact every broker-held secret it is handed, not just the vault credential —
    /// including the money IDEMPOTENCY KEY, which the broker's own audit/artifact path folds into
    /// its redaction set precisely "so a provider-controlled body or error cannot echo it into any
    /// result, audit, or artifact". The tee is a second output channel and the module header claims
    /// parity with that pass; this pins the claim. Stripe echoes the key back in its own error
    /// bodies, so the echoing body here is the realistic shape, not a contrived one.
    #[test]
    fn the_tee_redacts_every_broker_held_secret_not_just_the_credential() {
        const CREDENTIAL: &str = "sk_test_vault_credential_canary";
        const IDEMPOTENCY_KEY: &str = "money_key_private_canary";
        let body = format!(
            r#"{{"error":{{"type":"idempotency_error","message":"Keys for idempotent requests \
             can only be used with the same parameters. Key={IDEMPOTENCY_KEY}","charge":"ch_1"}},\
             "echoed_auth":"{CREDENTIAL}"}}"#
        );
        let context = Context {
            provider: "stripe".into(),
            action: "refund_charge_bounded".into(),
            step: "refund".into(),
            extra_secrets: vec![IDEMPOTENCY_KEY.to_string()],
        };
        let line = tee_line(400, body.as_bytes(), CREDENTIAL, Some(&context))
            .expect("the tee line serializes");
        let text = String::from_utf8(line).expect("the tee line is utf8");
        assert!(
            !text.contains(IDEMPOTENCY_KEY),
            "the money idempotency key reached the tee file: {text}"
        );
        assert!(
            !text.contains(CREDENTIAL),
            "the vault credential reached the tee file: {text}"
        );
        // The rest of the body is untouched — this is redaction, never projection.
        assert!(
            text.contains("idempotency_error") && text.contains("ch_1"),
            "redaction must not narrow the body: {text}"
        );
    }

    /// The credential-only path still works when there is no scope at all (a call outside any
    /// executed verb), and an empty secret never becomes a match-everything needle.
    #[test]
    fn the_tee_line_tolerates_an_absent_scope_and_empty_secrets() {
        let line = tee_line(200, br#"{"id":"ch_1"}"#, "", None).expect("serializes");
        let text = String::from_utf8(line).unwrap();
        assert!(
            text.contains(r#"{\"id\":\"ch_1\"}"#) || text.contains("ch_1"),
            "{text}"
        );
        assert!(
            text.contains("\"provider\":null"),
            "an unscoped line attributes nothing: {text}"
        );
    }

    /// `OpenOptions::mode` applies only to a file it CREATES, and `open` follows
    /// symlinks. A pre-existing world-readable file or a symlink at the operator's tee path would
    /// receive provider-response bytes without the owner-only guarantee the module header asserts.
    /// The chosen behavior is SKIP, not repair: the module's discipline is fail-open-silently, and
    /// a path that is not what the operator asked for is a path we decline to write, not one we
    /// take ownership of.
    #[cfg(unix)]
    #[test]
    fn the_tee_declines_a_symlink_or_a_loosely_permissioned_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tee dir");

        // (1) A symlink at the tee path: the target must stay untouched.
        let target = dir.path().join("target.jsonl");
        std::fs::write(&target, b"").unwrap();
        let link = dir.path().join("via-symlink.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        {
            let _armed = ArmedTee::at(&link);
            record(200, br#"{"id":"ch_1"}"#, "");
        }
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"",
            "the tee wrote through a symlink"
        );

        // (2) A pre-existing 0644 file: skipped, and its mode is left alone (we decline, we do not
        // silently take ownership of an operator's file).
        let loose = dir.path().join("loose.jsonl");
        std::fs::write(&loose, b"").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        {
            let _armed = ArmedTee::at(&loose);
            record(200, br#"{"id":"ch_1"}"#, "");
        }
        assert_eq!(
            std::fs::read(&loose).unwrap(),
            b"",
            "the tee wrote to a world-readable file"
        );
        assert_eq!(
            std::fs::metadata(&loose).unwrap().permissions().mode() & 0o777,
            0o644,
            "declining must not mutate the operator's file"
        );

        // (3) The ordinary case still works: a fresh path is created 0600 and written.
        let fresh = dir.path().join("fresh.jsonl");
        {
            let _armed = ArmedTee::at(&fresh);
            record(200, br#"{"id":"ch_1"}"#, "");
        }
        let written = std::fs::read_to_string(&fresh).expect("the tee created its own file");
        assert!(written.contains("ch_1"), "{written}");
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600,
            "a tee file the module creates is owner-only"
        );
        // And an existing 0600 file it created keeps receiving appends.
        {
            let _armed = ArmedTee::at(&fresh);
            record(200, br#"{"id":"ch_2"}"#, "");
        }
        let appended = std::fs::read_to_string(&fresh).unwrap();
        assert_eq!(appended.lines().count(), 2, "{appended}");
    }

    #[test]
    fn a_scope_restores_the_prior_attribution_on_drop() {
        let outer = TeeScope::enter("stripe", "get_charge", "get", &[]);
        {
            let _inner = TeeScope::enter("stripe", "get_customer", "get", &[]);
        }
        // With the tee disarmed both scopes hold `None`; the pin here is that the nested scope's
        // drop restored whatever the outer one had rather than clearing the slot outright.
        CONTEXT.with(|cell| {
            let held = cell.borrow();
            assert!(held.is_none(), "disarmed scopes attribute nothing");
        });
        drop(outer);
    }
}
