//! The git seam: a hermetic runner for the credentialed hop, plus the persistent per-remote bare
//! MIRROR the daemon serves git's own wire protocol from.
//!
//! Git talks to git. The daemon wires an attested stream to `git receive-pack` / `git upload-pack`
//! on a mirror, and git does the transfer: quarantine, thin-pack completion, connectivity checking,
//! ref transactions, error rendering. Cermet appears exactly twice —
//!
//! 1. **the update hook**, git's sanctioned per-ref policy seam, which asks the broker about
//!    `(repo, branch, old, new)` before anything lands, and
//! 2. **the credentialed hop**, `mirror → upstream`, run by the hermetic runner below.
//!
//! There is deliberately NO Cermet-owned carrier, staging area, wire format, or quarantine here:
//! git's own quarantine (the `tmp_objdir-incoming-*` receive-pack uses) is the one that exists, and
//! git migrates those objects into the mirror before the `update` hook runs — so the hook and the
//! hop both see them with no plumbing of ours.
//!
//! What the hermetic runner buys, threat by threat:
//! - **Accident / config bleed**: `GIT_CONFIG_NOSYSTEM=1`, a neutralized global config, a
//!   controlled `HOME`, a cleared environment, and an absolute registered binary path mean no
//!   credential helper, URL rewrite, proxy, alias, or hook from box config can steer the child.
//! - **Peer uids on the box**: the credential is injected through
//!   `GIT_CONFIG_COUNT`/`_KEY_n`/`_VALUE_n` environment config, NEVER argv and never the URL —
//!   `/proc/<pid>/cmdline` is world-readable, `/proc/<pid>/environ` is not. Mirrors are 0700,
//!   daemon-owned.
//! - **Hostile pushed input**: not ours to parse. `git receive-pack` reads agent bytes; it is git's
//!   most-hardened surface, and the daemon never looks at a pack.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::types::{EffectFailureClass, FailureSignal};

/// The box's git (`git_binary`). A root-owned absolute path, so a peer uid on the box cannot
/// substitute the binary the daemon runs, and no PATH lookup ever happens.
pub const DEFAULT_GIT_BINARY: &str = "/usr/bin/git";

/// Where per-remote bare mirrors live (`git_mirror_dir`). Daemon-owned, 0700.
pub const DEFAULT_MIRROR_DIR: &str = "/var/lib/cermetd/mirrors";

/// Wall-clock ceiling on ONE hermetic git invocation (`git_timeout_secs`). Bounds a wedged
/// credentialed hop; the streamed `receive-pack`/`upload-pack` services are not run under it (they
/// live and die with their attested connection).
pub const DEFAULT_GIT_TIMEOUT_SECS: u64 = 300;

/// How long a mirror survives with no authorized contact before the startup sweep drops it
/// (`git_mirror_retention_days`, `0` = keep forever). A dropped mirror costs one re-seed from
/// upstream, never correctness.
pub const DEFAULT_MIRROR_RETENTION_DAYS: i64 = 90;

/// Minimum git the seam will run. Everything used here is ancient plumbing except environment
/// config, which landed in git 2.31. Checked PER REQUEST, never at boot.
pub const MIN_GIT_VERSION: (u32, u32) = (2, 31);

/// Default ceiling on the bytes ONE push may write into a mirror (`git_max_push_bytes`).
///
/// Enforced by GIT, not by us: it is written into the mirror's own config as
/// `receive.maxInputSize` at creation, so `receive-pack` refuses an oversize pack itself
/// ("fatal: pack exceeds maximum allowed size") before the bytes land. That matters because the
/// agent's whole pack is indexed into the mirror BEFORE any decision exists — that is what makes
/// the hook seam work — so without a cap an UNAUTHORIZED push could fill the filesystem the broker
/// keeps its state DB and audit log on — a model looping a large-artifact push it has no rule for,
/// whether by accident or because something steered it there.
pub const DEFAULT_MAX_PUSH_BYTES: u64 = 512 << 20;

/// Row cap on a derived changed-path list. Beyond this the list is truncated and says so; counts
/// stay saturating, so a huge push costs a bounded render.
pub const MAX_CHANGED_ROWS: usize = 200;

/// Cap on one derived path string. A longer path is counted but not rendered rather than
/// truncated: a truncated path would show the human a DIFFERENT path than the one that lands.
pub const MAX_PATH_BYTES: usize = 512;

/// Git's all-zero object id — what the `update` hook receives as `old` for a ref CREATION and as
/// `new` for a DELETION.
pub const NULL_OID: &str = "0000000000000000000000000000000000000000";

/// Hard cap on bytes captured from one hermetic invocation's stdout/stderr.
const MAX_CAPTURED_BYTES: usize = 1 << 20;

/// Cap on the stderr transcript kept for a receipt.
const MAX_STDERR_CHARS: usize = 4 << 10;

/// The git seam's settings. All of them are declared daemon settings (`git_binary` /
/// `git_mirror_dir` / `git_timeout_secs` / `git_mirror_retention_days`) — behavior that is not a
/// setting does not exist.
///
/// `binary` DEFAULTS to the box's git: there is no registration act and nothing to turn on. The daemon boots
/// on every box, git-less or not — usability is checked PER REQUEST, and a missing or too-old git
/// is a legible refusal naming the setting. Verbs are vocabulary, not boot-time promises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitConfig {
    pub binary: PathBuf,
    pub mirror_dir: PathBuf,
    pub timeout: Duration,
    pub mirror_retention_days: i64,
    pub max_push_bytes: u64,
}

impl GitConfig {
    /// The seam rooted at `mirror_dir`, using the box's default git.
    pub fn at(mirror_dir: impl Into<PathBuf>) -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_GIT_BINARY),
            mirror_dir: mirror_dir.into(),
            timeout: Duration::from_secs(DEFAULT_GIT_TIMEOUT_SECS),
            mirror_retention_days: DEFAULT_MIRROR_RETENTION_DAYS,
            max_push_bytes: DEFAULT_MAX_PUSH_BYTES,
        }
    }

    /// Point the seam at a different git.
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }
}

impl Default for GitConfig {
    fn default() -> Self {
        Self::at(DEFAULT_MIRROR_DIR)
    }
}

/// The refusal a git operation gets when this box's git is missing or unusable. Legible on purpose:
/// it names the setting the operator has to change. Reaches the agent as a git `ERR` pkt-line, so
/// it renders as `remote error: …` in an ordinary `git push`.
fn unusable(binary: &Path, why: &str) -> Error {
    Error::Provider(format!(
        "git at {} is not usable ({why}). Point `git_binary` in the daemon config at a git >= {}.{} \
         and restart cermetd; git verbs stay unavailable until then, and every other verb is \
         unaffected.",
        binary.display(),
        MIN_GIT_VERSION.0,
        MIN_GIT_VERSION.1
    ))
}

type RegistrationMap = std::collections::HashMap<PathBuf, std::result::Result<String, String>>;

/// Registration state, resolved ONCE per (process, binary path). [`preflight`] is the verification;
/// this memoizes it so the per-request check costs a map lookup, not a `git --version`.
fn registration_cache() -> &'static Mutex<RegistrationMap> {
    static CACHE: OnceLock<Mutex<RegistrationMap>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(RegistrationMap::new()))
}

/// This box's usable git, or a legible refusal. Every git operation goes through here — there is no
/// boot-time requirement anywhere: the daemon boots identically on a git-less box and refuses git
/// operations one request at a time.
///
/// The check is memoized per binary path, so the per-request cost is a map lookup rather than a
/// `git --version`.
pub fn usable(cfg: &GitConfig) -> Result<PathBuf> {
    let binary = cfg.binary.clone();
    let cached = registration_cache()
        .lock()
        .ok()
        .and_then(|map| map.get(&binary).cloned());
    if let Some(result) = cached {
        return result
            .map(|_| binary.clone())
            .map_err(|why| unusable(&binary, &why));
    }
    let outcome = preflight(cfg).map_err(|error| error.to_string());
    if let Ok(mut map) = registration_cache().lock() {
        map.insert(binary.clone(), outcome.clone());
    }
    outcome
        .map(|_| binary.clone())
        .map_err(|why| unusable(&binary, &why))
}

/// Verify the configured git: it must run and report a version at or above [`MIN_GIT_VERSION`].
/// Returns the reported version string. Runs on first use, never at boot.
pub fn preflight(cfg: &GitConfig) -> Result<String> {
    let binary = &cfg.binary;
    let run = run_with(binary, cfg, None, &["--version"], None, None)?;
    if !run.ok() {
        return Err(run.failure("--version"));
    }
    let reported = String::from_utf8_lossy(&run.stdout).trim().to_string();
    let version = parse_version(&reported).ok_or_else(|| {
        Error::Provider(format!(
            "{} reported an unparseable version `{reported}`",
            binary.display()
        ))
    })?;
    if version < MIN_GIT_VERSION {
        return Err(Error::Provider(format!(
            "git {}.{} is older than the required {}.{} (environment config `GIT_CONFIG_COUNT`, \
             the credential channel, landed in 2.31)",
            version.0, version.1, MIN_GIT_VERSION.0, MIN_GIT_VERSION.1
        )));
    }
    Ok(reported)
}

/// `git version 2.53.0` → `(2, 53)`. Any other shape is `None` (fail closed at the caller).
fn parse_version(reported: &str) -> Option<(u32, u32)> {
    let rest = reported.strip_prefix("git version ")?;
    let mut parts = rest.split(['.', '-', ' ']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

// ---------------------------------------------------------------------------
// The hermetic runner
// ---------------------------------------------------------------------------

/// One completed hermetic git invocation. Neither `stdout` nor `stderr` can carry the credential:
/// it rides environment config, never argv and never the URL, so git has nothing to echo.
#[derive(Debug)]
pub struct GitRun {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub timed_out: bool,
}

impl GitRun {
    pub fn ok(&self) -> bool {
        !self.timed_out && self.code == Some(0)
    }

    fn failure(&self, what: &str) -> Error {
        if self.timed_out {
            return Error::Provider(format!("git {what} timed out"));
        }
        let code = self
            .code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        Error::Provider(format!("git {what} failed (exit {code}): {}", self.stderr))
    }
}

/// One `http.<url>.extraHeader` credential binding for a single invocation. Built inside the
/// custody boundary, moved into the child's environment, dropped with the `Command`.
pub struct GitCredential {
    /// The exact remote URL the header is scoped to (git matches `http.<url>.*` by URL prefix).
    pub url: String,
    /// The full header line, e.g. `Authorization: Basic <base64>`.
    pub header: String,
}

/// Build a hermetic `Command` for `binary`. The environment is CLEARED and rebuilt from a fixed
/// set — nothing from the daemon's own environment reaches the child.
///
/// Public because the daemon's stream plane builds `receive-pack`/`upload-pack` commands with the
/// same hermeticity before wiring their stdio to an attested connection.
pub fn hermetic_command(
    binary: &Path,
    cfg: &GitConfig,
    cwd: Option<&Path>,
    args: &[&str],
) -> Command {
    let mut cmd = Command::new(binary);
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.env_clear();
    // A controlled HOME that is ours and holds no git config. The global-config neutralization
    // below already covers `~/.gitconfig`; pointing HOME here keeps anything else git might look up
    // (`~/.git-credentials`, `~/.config/git/*`) inside a directory the daemon owns.
    cmd.env("HOME", &cfg.mirror_dir);
    // `GIT_CONFIG_NOSYSTEM=1` is the documented switch that disables the system config ENTIRELY.
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    // No interactive credential prompt, no askpass helper, no terminal.
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("GIT_ASKPASS", "");
    cmd.env("SSH_ASKPASS", "");
    // Stable, parseable output regardless of box locale.
    cmd.env("LC_ALL", "C");
    cmd.env("LANG", "C");
    // git shells out to itself and (for https) to git-remote-http; both live beside the configured
    // binary. Nothing is resolved through an inherited PATH.
    if let Some(bindir) = binary.parent() {
        cmd.env("PATH", bindir);
    }
    // The child leads its OWN process group, so the watchdog can signal the whole tree.
    // `git-remote-https` is a GRANDCHILD holding the same pipe write ends — killing only the direct
    // child leaves `run()` blocked on those pipes long past the declared `git_timeout_secs`.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    cmd
}

/// Run one hermetic git invocation to completion, bounded by `cfg.timeout` and
/// [`MAX_CAPTURED_BYTES`]. Requires a REGISTERED git.
pub fn run(
    cfg: &GitConfig,
    cwd: Option<&Path>,
    args: &[&str],
    stdin_file: Option<&Path>,
    credential: Option<&GitCredential>,
) -> Result<GitRun> {
    let binary = usable(cfg)?;
    run_with(&binary, cfg, cwd, args, stdin_file, credential)
}

fn run_with(
    binary: &Path,
    cfg: &GitConfig,
    cwd: Option<&Path>,
    args: &[&str],
    stdin_file: Option<&Path>,
    credential: Option<&GitCredential>,
) -> Result<GitRun> {
    let mut cmd = hermetic_command(binary, cfg, cwd, args);
    if let Some(cred) = credential {
        cmd.env("GIT_CONFIG_COUNT", "1");
        cmd.env("GIT_CONFIG_KEY_0", format!("http.{}.extraHeader", cred.url));
        cmd.env("GIT_CONFIG_VALUE_0", &cred.header);
    }
    match stdin_file {
        Some(path) => {
            let file = std::fs::File::open(path).map_err(|e| {
                Error::Provider(format!("git input {} is not readable: {e}", path.display()))
            })?;
            cmd.stdin(Stdio::from(file));
        }
        None => {
            cmd.stdin(Stdio::null());
        }
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| Error::Provider(format!("cannot run git at {}: {e}", binary.display())))?;
    let pid = child.id();
    let mut child_out = child.stdout.take().expect("stdout was piped");
    let mut child_err = child.stderr.take().expect("stderr was piped");
    let child = Mutex::new(child);
    let finished = AtomicBool::new(false);
    let timed_out = AtomicBool::new(false);
    let deadline = Instant::now() + cfg.timeout;

    // Readers drain both pipes (so the child can never block on a full pipe) while a watchdog kills
    // the whole PROCESS GROUP at the deadline; that closes every copy of the pipe write ends —
    // including the transport helper grandchild's — which is what ends the readers.
    let (stdout, stderr) = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !finished.load(Ordering::Relaxed) {
                if Instant::now() >= deadline {
                    timed_out.store(true, Ordering::Relaxed);
                    kill_process_group(pid, Signal::Term);
                    // A grandchild that ignores TERM still holds the pipes; follow with KILL.
                    std::thread::sleep(Duration::from_millis(200));
                    kill_process_group(pid, Signal::Kill);
                    if let Ok(mut guard) = child.lock() {
                        let _ = guard.kill();
                    }
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let out = scope.spawn(move || read_capped(&mut child_out));
        let err = scope.spawn(move || read_capped(&mut child_err));
        let stdout = out.join().unwrap_or_default();
        let stderr = err.join().unwrap_or_default();
        finished.store(true, Ordering::Relaxed);
        (stdout, stderr)
    });

    let status = child
        .lock()
        .map_err(|_| Error::Provider("git runner state was poisoned".into()))?
        .wait()
        .map_err(|e| Error::Provider(format!("git did not complete: {e}")))?;

    let mut stderr_text = String::from_utf8_lossy(&stderr).into_owned();
    stderr_text.truncate(
        stderr_text
            .char_indices()
            .nth(MAX_STDERR_CHARS)
            .map(|(i, _)| i)
            .unwrap_or(stderr_text.len()),
    );
    Ok(GitRun {
        code: status.code(),
        stdout,
        stderr: stderr_text.trim_end().to_string(),
        timed_out: timed_out.load(Ordering::Relaxed),
    })
}

#[derive(Clone, Copy)]
enum Signal {
    Term,
    Kill,
}

/// Signal the child's whole process group.
#[cfg(unix)]
fn kill_process_group(pid: u32, signal: Signal) {
    let sig = match signal {
        Signal::Term => libc::SIGTERM,
        Signal::Kill => libc::SIGKILL,
    };
    // SAFETY: `killpg` on our own child's process group. The child was spawned with
    // `process_group(0)`, so the group id equals its pid and names no process but the subtree we
    // started.
    unsafe {
        libc::killpg(pid as libc::pid_t, sig);
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: u32, _signal: Signal) {}

/// Read at most [`MAX_CAPTURED_BYTES`], then keep draining so the child is never blocked on a full
/// pipe by our own cap.
fn read_capped(reader: &mut impl std::io::Read) -> Vec<u8> {
    let mut kept = Vec::new();
    if reader
        .take(MAX_CAPTURED_BYTES as u64)
        .read_to_end(&mut kept)
        .is_err()
        || kept.len() < MAX_CAPTURED_BYTES
    {
        return kept;
    }
    let mut sink = [0u8; 64 * 1024];
    while matches!(reader.read(&mut sink), Ok(n) if n > 0) {}
    kept
}

/// A PER-STREAM token naming one live attested git stream — the update hook's proof of which stream
/// it belongs to. Random, never derived from anything the agent supplies.
///
/// Per-stream, NOT single-use: one `git push` of three refs legitimately presents it three times
/// (git runs the `update` hook once per ref). It dies with the stream, not with the first read.
pub fn stream_token() -> String {
    crate::util::new_id("gstream")
}

/// The session id a git stream's decisions are audited under.
pub fn stream_session_id() -> String {
    crate::util::new_id("sess")
}

// ---------------------------------------------------------------------------
// Repo identity (validated BEFORE any git process is spawned)
// ---------------------------------------------------------------------------

/// One addressable remote repository. Its parts are validated at stream-open, before a mirror path
/// is joined or a git process exists.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepoId {
    pub provider: String,
    pub owner: String,
    pub name: String,
}

const MAX_REPO_SEGMENT: usize = 100;

/// Whether `segment` is a safe single path component for a provider/owner/repo name: 1..=100 bytes
/// of `[A-Za-z0-9._-]`, not starting with `.` or `-`, and never `.`/`..`.
///
/// A malformed identity must never reach a path join, a human-read refusal rendering, or a spawned
/// process. Refusing here — ONCE, at the trust-boundary crossing — is why nothing downstream
/// re-sanitizes.
pub fn is_valid_repo_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= MAX_REPO_SEGMENT
        && !segment.starts_with('.')
        && !segment.starts_with('-')
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl RepoId {
    /// Parse and VALIDATE `provider/owner/name`. Fail closed on anything else.
    pub fn parse(spec: &str) -> Result<Self> {
        let parts: Vec<&str> = spec.split('/').collect();
        let [provider, owner, name] = parts.as_slice() else {
            return Err(Error::Invalid(format!(
                "repository `{spec}` is not `provider/owner/name`"
            )));
        };
        let name = name.strip_suffix(".git").unwrap_or(name);
        for (label, segment) in [("provider", *provider), ("owner", *owner), ("name", name)] {
            if !is_valid_repo_segment(segment) {
                return Err(Error::Invalid(format!(
                    "repository {label} is not a valid name (1..={MAX_REPO_SEGMENT} chars of \
                     [A-Za-z0-9._-], not starting with `.` or `-`)"
                )));
            }
        }
        Ok(RepoId {
            provider: provider.to_string(),
            owner: owner.to_string(),
            name: name.to_string(),
        })
    }

    /// `owner/name` — the form a sentence and a receipt speak.
    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

// ---------------------------------------------------------------------------
// The persistent mirror
// ---------------------------------------------------------------------------

/// The mirror path for one repo. Every segment was validated by [`RepoId::parse`], so this join
/// cannot traverse.
pub fn mirror_path(cfg: &GitConfig, repo: &RepoId) -> PathBuf {
    cfg.mirror_dir
        .join(&repo.provider)
        .join(&repo.owner)
        .join(format!("{}.git", repo.name))
}

/// Create (0700) and `git init --bare` the mirror for `repo` if it does not exist, and (always)
/// install the update hook pointing at `hook_program`. Returns the mirror path.
///
/// Created on FIRST AUTHORIZED CONTACT and persistent thereafter: bases from earlier traffic are
/// present, so every later push is O(delta) in both directions. A per-request empty mirror cannot
/// give that: a repo with more history than the pack cap would be unpushable.
pub fn ensure_mirror(cfg: &GitConfig, repo: &RepoId, hook_program: &Path) -> Result<PathBuf> {
    let dir = mirror_path(cfg, repo);
    if !dir.join("objects").is_dir() {
        create_private_dir(&cfg.mirror_dir)?;
        if let Some(parent) = dir.parent() {
            create_private_dir(parent)?;
        }
        create_private_dir(&dir)?;
        let path = dir.to_string_lossy().into_owned();
        let initialized = run(cfg, None, &["init", "--bare", "-q", &path], None, None)?;
        if !initialized.ok() {
            return Err(initialized.failure("init --bare"));
        }
        // The push cap, written ONCE into the mirror's own config — git's home for receive
        // settings, and the only place a repo-local value survives the hermetic environment.
        // `receive-pack` then enforces it itself, refusing an oversize pack before the bytes land,
        // so the bound is git's rather than a size check of ours.
        let cap = cfg.max_push_bytes.to_string();
        let configured = run(
            cfg,
            Some(&dir),
            &["config", "receive.maxInputSize", &cap],
            None,
            None,
        )?;
        if !configured.ok() {
            return Err(configured.failure("config receive.maxInputSize"));
        }
    }
    install_update_hook(&dir, hook_program)?;
    touch_mirror(&dir);
    Ok(dir)
}

/// Write `<mirror>/hooks/update` as a two-line shell stub that execs `hook_program`. Rewritten on
/// every contact so a daemon upgrade (a new binary path) can never leave a mirror pointing at a
/// stale program — a mirror whose hook does not run is a mirror with no authorization on it.
fn install_update_hook(mirror: &Path, hook_program: &Path) -> Result<()> {
    let hooks = mirror.join("hooks");
    std::fs::create_dir_all(&hooks)
        .map_err(|e| Error::Provider(format!("cannot create {}: {e}", hooks.display())))?;
    let script = format!(
        "#!/bin/sh\n# Installed by cermetd: git's per-ref policy seam.\nexec {} git-update-hook \"$@\"\n",
        shell_quote(&hook_program.to_string_lossy())
    );
    // Write-then-RENAME, never write-in-place. `fs::write` truncates, so a concurrent push to the
    // same repo could exec a zero-length `hooks/update` — and an empty script EXITS 0, which
    // receive-pack reads as ALLOW: the ref would land in the mirror with no sentence decision and
    // no audit row. A rename removes the window entirely rather than shrinking it, and its own
    // failure mode leaves the PREVIOUS hook in place, which is the closed direction.
    let path = hooks.join("update");
    let staged = hooks.join("update.staging");
    std::fs::write(&staged, script)
        .map_err(|e| Error::Provider(format!("cannot write {}: {e}", staged.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::Provider(format!("cannot chmod {}: {e}", staged.display())))?;
    }
    std::fs::rename(&staged, &path)
        .map_err(|e| Error::Provider(format!("cannot install {}: {e}", path.display())))?;
    Ok(())
}

/// Single-quote a path for `/bin/sh`. The path is the daemon's own executable, not agent data; this
/// is correctness for odd install paths, not a defense.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// 0700, daemon-owned: a peer uid on the box must not read or plant objects in a mirror.
fn create_private_dir(dir: &Path) -> Result<()> {
    if !dir.is_dir() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::Provider(format!("cannot create {}: {e}", dir.display())))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::Provider(format!("cannot secure {}: {e}", dir.display())))?;
    }
    Ok(())
}

/// The marker whose mtime the aging sweep reads.
const CONTACT_STAMP: &str = "cermet-last-contact";

/// Stamp a mirror as contacted, so the aging sweep measures TIME SINCE LAST AUTHORIZED CONTACT
/// rather than time since creation.
fn touch_mirror(mirror: &Path) {
    let _ = std::fs::write(mirror.join(CONTACT_STAMP), b"");
}

/// Ask git to repack a mirror. Mirror HYGIENE, not per-request cleanup: a persistent store that
/// only ever grows is the cost of persistence, and `gc --auto` is git's own answer to it (it does
/// nothing until git's own thresholds say otherwise).
pub fn gc_mirror(cfg: &GitConfig, mirror: &Path) -> Result<()> {
    let run = run(cfg, Some(mirror), &["gc", "--auto", "--quiet"], None, None)?;
    if !run.ok() {
        return Err(run.failure("gc --auto"));
    }
    Ok(())
}

/// Startup aging sweep: drop mirrors with no authorized contact inside the window. Returns how many
/// were removed. Best-effort and coordination-free — a swept mirror is re-seeded from upstream on
/// next contact, so aging costs bandwidth, never correctness.
pub fn purge_expired_mirrors(cfg: &GitConfig, now_epoch: i64) -> usize {
    if cfg.mirror_retention_days <= 0 {
        return 0;
    }
    let cutoff = now_epoch - cfg.mirror_retention_days * 86_400;
    let mut removed = 0;
    for mirror in walk_mirrors(&cfg.mirror_dir) {
        // The contact stamp is the normal clock; an ORPHAN (a mirror whose `git init` never
        // finished) has none, so fall back to the directory's own mtime rather than treating an
        // absent stamp as "never expires".
        let modified = last_contact(&mirror.join(CONTACT_STAMP)).or_else(|| last_contact(&mirror));
        if modified.is_some_and(|m| m < cutoff) && std::fs::remove_dir_all(&mirror).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn last_contact(path: &Path) -> Option<i64> {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

/// Every `<root>/<provider>/<owner>/<name>.git` that looks like one of ours. Anything else under
/// the root belongs to somebody else and is not ours to sweep.
fn walk_mirrors(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(providers) = std::fs::read_dir(root) else {
        return out;
    };
    for provider in providers.flatten() {
        let Ok(owners) = std::fs::read_dir(provider.path()) else {
            continue;
        };
        for owner in owners.flatten() {
            let Ok(repos) = std::fs::read_dir(owner.path()) else {
                continue;
            };
            for repo in repos.flatten() {
                let path = repo.path();
                // `.git` shape ALONE, not `objects/` presence. A failed `git init` (no usable git,
                // a full disk) leaves a mirror directory with no object store, and an
                // `objects/`-gated walk would skip exactly those — the orphans the sweep most
                // needs to reclaim.
                if path.is_dir() && path.extension().is_some_and(|e| e == "git") {
                    out.push(path);
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The streamed services (git's own wire protocol)
// ---------------------------------------------------------------------------

/// The two git services the attested stream plane serves from a mirror. A closed enum: the wire
/// header names one of exactly these, never a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitService {
    /// `git receive-pack` — the agent pushes into the mirror. Hostile input is ITS problem.
    ReceivePack,
    /// `git upload-pack` — the agent fetches from the mirror.
    UploadPack,
}

impl GitService {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "receive-pack" | "git-receive-pack" => Some(GitService::ReceivePack),
            "upload-pack" | "git-upload-pack" => Some(GitService::UploadPack),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            GitService::ReceivePack => "receive-pack",
            GitService::UploadPack => "upload-pack",
        }
    }
}

/// A hermetic `Command` for one service on `mirror`, ready for the caller to wire stdio to an
/// attested connection. Deliberately NOT run under `cfg.timeout`: a stream lives and dies with its
/// connection, and a long fetch is not a wedged hop.
pub fn service_command(cfg: &GitConfig, service: GitService, mirror: &Path) -> Result<Command> {
    let binary = usable(cfg)?;
    let path = mirror.to_string_lossy().into_owned();
    Ok(hermetic_command(
        &binary,
        cfg,
        None,
        &[service.as_str(), &path],
    ))
}

// ---------------------------------------------------------------------------
// Derived facts (for the human-read refusal rendering)
// ---------------------------------------------------------------------------

/// One row of a changed-path list: git's `--name-status` letter plus the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedPath {
    pub status: String,
    pub path: String,
}

/// The bounded facts derived from a proposed ref update. Every count saturates and every list is
/// row-capped, so a huge push costs a bounded render.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangedPaths {
    pub rows: Vec<ChangedPath>,
    pub truncated: bool,
    pub total: u64,
}

/// `git diff-tree` the proposed update inside the mirror.
///
/// DEMAND-DRIVEN by construction — nothing calls this unless a consumer of content facts asks, and
/// it runs in git's own code, in the moment it is consumed. At `update`-hook time the pushed
/// objects have already been migrated out of receive-pack's quarantine into the mirror, so there is
/// nothing of ours to plumb: git can simply see them.
///
/// A ref CREATION (`old` == [`NULL_OID`]) diffs against the commit's own root, so the list is
/// honestly "everything added".
pub fn changed_paths(cfg: &GitConfig, mirror: &Path, old: &str, new: &str) -> Result<ChangedPaths> {
    let mut args: Vec<&str> = vec!["diff-tree", "-r", "--name-status", "--no-commit-id", "-z"];
    if old == NULL_OID {
        args.push("--root");
        args.push(new);
    } else {
        args.push(old);
        args.push(new);
    }
    let run = run(cfg, Some(mirror), &args, None, None)?;
    if !run.ok() {
        return Err(Error::Provider(format!(
            "git could not produce the changed-path list for {old}..{new}: {}",
            run.stderr
        )));
    }
    Ok(parse_name_status(&run.stdout))
}

/// Parse `diff-tree -z --name-status`: NUL-separated `status`, `path`, `status`, `path`, …
/// Bounded: at most [`MAX_CHANGED_ROWS`] rows are KEPT, the total is counted with `saturating_add`,
/// and an over-long path is counted but not rendered (a truncated path would name a DIFFERENT path
/// than the one that lands).
fn parse_name_status(stdout: &[u8]) -> ChangedPaths {
    let mut rows = Vec::new();
    let mut total: u64 = 0;
    let mut fields = stdout.split(|b| *b == 0).filter(|f| !f.is_empty());
    while let Some(status) = fields.next() {
        let Some(path) = fields.next() else { break };
        total = total.saturating_add(1);
        if rows.len() >= MAX_CHANGED_ROWS || path.len() > MAX_PATH_BYTES {
            continue;
        }
        rows.push(ChangedPath {
            // `--name-status` letters are ASCII; a non-UTF-8 PATH is legal in git and renders
            // lossily here (rendering only — git's own objects, not this string, are what land).
            status: String::from_utf8_lossy(status).into_owned(),
            path: String::from_utf8_lossy(path).into_owned(),
        });
    }
    let truncated = total > rows.len() as u64;
    ChangedPaths {
        rows,
        truncated,
        total,
    }
}

// ---------------------------------------------------------------------------
// The credentialed hop
// ---------------------------------------------------------------------------

/// What the UPSTREAM actually did, parsed from `git push --porcelain`'s machine-readable line.
///
/// This is the honest answer to "what did my agent change on GitHub", and it is not the same as the
/// hook's `old`: the hook reports the MIRROR's tip, and with no fetch refresh the mirror can be
/// arbitrarily behind — a third party's direct push, or a re-created mirror after aging, both make
/// the two diverge. The porcelain line is the upstream's own account of the transition it
/// performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTransition {
    /// The oid the upstream ref moved FROM, or `None` when it created the ref — and on a deletion,
    /// where git's porcelain line reports no oid at all.
    pub from: Option<String>,
    /// True when the upstream had no such ref before this push.
    pub created: bool,
    /// True when the upstream REMOVED the ref.
    pub deleted: bool,
}

/// Parse the one `--porcelain` status line for `refname`, which is FULLY QUALIFIED
/// (`refs/heads/main`, `refs/tags/v1.0.0`) — the same string the update hook reported, so a tag and
/// a same-named branch can never be confused for one another.
///
/// The shapes git emits (verified against git 2.53, `core.abbrev=no` so the oids are full):
///   ` \t<src>:refs/heads/main\t<from>..<to>`   — an update
///   `*\t<src>:refs/heads/main\t[new branch]`   — a creation
///   `*\t<src>:refs/tags/v1\t[new tag]`         — a creation in the tag namespace
///   `-\t:refs/heads/main\t[deleted]`           — a deletion
/// Anything else yields `None` rather than a guess: an unparsed line means the receipt says
/// "unknown", never a fabricated oid. A deletion's `from` is `None` because git's own line carries
/// no oid for it — the tip the daemon held is a separate, separately-labelled fact.
pub fn parse_upstream_transition(stdout: &[u8], refname: &str) -> Option<UpstreamTransition> {
    let text = String::from_utf8_lossy(stdout);
    let want = refname;
    for line in text.lines() {
        // `To <url>` and `Done` have no tab-separated refspec; skip them rather than aborting the
        // scan (a `?` here would return None for the whole output).
        let mut fields = line.split('\t');
        let (Some(_flag), Some(refspec)) = (fields.next(), fields.next()) else {
            continue;
        };
        let summary = fields.next().unwrap_or_default();
        if refspec.split(':').nth(1) != Some(want) {
            continue;
        }
        if summary.starts_with("[new") {
            return Some(UpstreamTransition {
                from: None,
                created: true,
                deleted: false,
            });
        }
        if summary.starts_with("[deleted]") {
            return Some(UpstreamTransition {
                from: None,
                created: false,
                deleted: true,
            });
        }
        if let Some((from, _to)) = summary.split_once("..") {
            let from = from.trim_start_matches(['+', ' ']);
            if is_oid(from) {
                return Some(UpstreamTransition {
                    from: Some(from.to_string()),
                    created: false,
                    deleted: false,
                });
            }
        }
        return None;
    }
    None
}

fn is_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Carry an authorized ref update from the mirror to the upstream: the ONE step that needs the
/// vaulted secret, and the only place Cermet touches the network.
///
/// Run from inside the update hook's decision, BEFORE the mirror's own ref moves, so the hook
/// confirms only on upstream success and **the mirror ref advances iff upstream's did**. A plain
/// push: the upstream server's fast-forward rule is the concurrency control, and its refusal rides
/// git's error channel back into the agent's `git push` output.
///
/// A [`NULL_OID`] `new_oid` is a DELETION, and it carries as git's own delete refspec (an empty
/// source). This is git's spelling for the same transition the hook reported; there is nothing of
/// ours to invent.
pub fn carry_to_upstream(
    cfg: &GitConfig,
    mirror: &Path,
    upstream_url: &str,
    credential: Option<&GitCredential>,
    new_oid: &str,
    refname: &str,
) -> Result<GitRun> {
    let source = if new_oid == NULL_OID { "" } else { new_oid };
    let refspec = format!("{source}:{refname}");
    let run = run(
        cfg,
        Some(mirror),
        &[
            // `core.abbrev=no` so the porcelain summary carries FULL oids: the receipt's
            // upstream-from value is parsed out of it, and an abbreviated oid is not an identity
            // anything can be pinned to.
            "-c",
            "core.abbrev=no",
            "push",
            "--porcelain",
            upstream_url,
            &refspec,
        ],
        None,
        credential,
    )?;
    if !run.ok() {
        return Err(upstream_refusal(
            &format!("upstream refused {refspec}"),
            &run.stderr,
            credential,
        ));
    }
    Ok(run)
}

/// git's own words when a server demanded authentication and git had nothing left to offer.
///
/// The message names git's FALLBACK ("could not read Username"), not what happened, so it reads as
/// "no credential was sent" — the exact opposite of the truth when the daemon attached one.
fn upstream_demanded_credentials(stderr: &str) -> bool {
    let text = stderr.to_ascii_lowercase();
    text.contains("could not read username")
        || text.contains("could not read password")
        || text.contains("authentication failed")
}

/// Refuse an upstream hop in words the operator can act on.
///
/// The daemon is the only party that knows whether it attached a credential, so it is the
/// only party that can tell "we sent nothing" from "we sent something the upstream rejected". git
/// renders those two identically. A fresh-box run once spent its entire diagnosis on that ambiguity
/// while the real cause was a dead operator token. git's own text is always kept — this only says
/// what it means, and it says nothing at all when no credential was attached.
///
/// The refusal also carries its CLASS: the same condition that decides the wording
/// decides `provider_auth_refused`, so the terminal event records typed evidence instead of leaving
/// that fact to live only inside this sentence. Everything else is the honest residual — git exits
/// non-zero identically for a non-fast-forward, an unresolvable host and a missing repository, and
/// the class comes from what the seam KNOWS (did we attach a credential, did the upstream demand
/// one), never from mining git's prose for a finer answer.
fn upstream_refusal(what: &str, stderr: &str, credential: Option<&GitCredential>) -> Error {
    let class = EffectFailureClass::of(FailureSignal::GitUpstream {
        credential_attached: credential.is_some(),
        demanded_credentials: upstream_demanded_credentials(stderr),
    });
    if class == EffectFailureClass::ProviderAuthRefused {
        return Error::ProviderFailed(
            class,
            format!(
                "{what}: the upstream did not accept the vaulted credential — it is expired, \
                 revoked, or without access to this repository; git said: {stderr}"
            ),
        );
    }
    Error::ProviderFailed(class, format!("{what}: {stderr}"))
}

/// One ref the upstream refresh moved, as the mirror's own refs report it before and after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshedRef {
    pub refname: String,
    /// The mirror's previous tip, or `None` when the ref is new here.
    pub from: Option<String>,
    /// The upstream's tip, or `None` when the ref was PRUNED (deleted upstream).
    pub to: Option<String>,
}

/// What a refresh did, derived from the mirror's refs either side of the hop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refresh {
    /// At most [`MAX_CHANGED_ROWS`] rows; `total` stays honest past the cap.
    pub refs: Vec<RefreshedRef>,
    pub truncated: bool,
    pub total: u64,
}

/// The refresh's argv. Every option here is plumbing at or below [`MIN_GIT_VERSION`], so the seam
/// runs on the oldest git it claims to support — notably NOT `git fetch --porcelain`, which is git
/// 2.41 and fails outright on anything older.
fn refresh_argv(upstream_url: &str) -> [&str; 4] {
    [
        "fetch",
        "--prune",
        upstream_url,
        "+refs/heads/*:refs/heads/*",
    ]
}

/// Refresh the mirror FROM the upstream: the reversed credentialed hop, and the ONLY way a read
/// stream ever has current refs to serve.
///
/// `+refs/heads/*:refs/heads/*` with `--prune` makes the mirror's branch namespace equal the
/// upstream's — forced, because the mirror is a mirror and not a place with opinions, and pruned so a
/// branch deleted upstream stops being served here.
///
/// The receipt is DERIVED from the mirror's own refs, snapshotted either side of the fetch: this
/// mirror is daemon-owned and nothing else writes it, so the two snapshots differ by exactly what
/// the fetch did. Nothing here reads git's account of itself — not the human table, which is prose
/// in the box's locale, and not `--porcelain`, which does not exist across the supported version
/// range.
///
/// Failure is a REFUSAL, never a fallback: the caller must not serve a stale mirror when this
/// returns `Err` — a brokered fetch that cannot reach the actual remote is broken, and quietly
/// serving old refs would hide that.
pub fn refresh_from_upstream(
    cfg: &GitConfig,
    mirror: &Path,
    upstream_url: &str,
    credential: Option<&GitCredential>,
) -> Result<Refresh> {
    let before = ref_snapshot(cfg, mirror)?;
    let run = run(
        cfg,
        Some(mirror),
        &refresh_argv(upstream_url),
        None,
        credential,
    )?;
    if !run.ok() {
        return Err(upstream_refusal(
            "the upstream refresh failed",
            &run.stderr,
            credential,
        ));
    }
    let after = ref_snapshot(cfg, mirror)?;
    align_mirror_head(cfg, mirror, upstream_url, credential)?;
    Ok(diff_snapshots(&before, &after))
}

/// Every ref the mirror holds, by full name. `for-each-ref` is the plumbing answer to "what does
/// this repository have", and it covers whatever the refspec wrote plus the tags a fetch follows
/// along with them.
fn ref_snapshot(cfg: &GitConfig, mirror: &Path) -> Result<BTreeMap<String, String>> {
    let listed = run(
        cfg,
        Some(mirror),
        &["for-each-ref", "--format=%(objectname) %(refname)"],
        None,
        None,
    )?;
    if !listed.ok() {
        return Err(listed.failure("for-each-ref"));
    }
    Ok(parse_ref_snapshot(&listed.stdout))
}

/// Parse `<oid><SP><refname>` lines. A refname cannot contain a space, so the first one splits the
/// pair; anything that is not a ref line is ignored rather than guessed at.
fn parse_ref_snapshot(stdout: &[u8]) -> BTreeMap<String, String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|line| {
            let (oid, refname) = line.trim().split_once(' ')?;
            refname
                .starts_with("refs/")
                .then(|| (refname.to_string(), oid.to_string()))
        })
        .collect()
}

/// What changed between two snapshots: a ref only in `after` is new (no `from`), one only in
/// `before` was PRUNED (no `to`), a differing oid is an ordinary update, and a ref the fetch left
/// alone is not part of what the refresh did. Bounded like every other derived list here — rows
/// past the cap are counted, not rendered. Ordering is the snapshots' own, so the same refresh
/// always renders the same receipt.
fn diff_snapshots(before: &BTreeMap<String, String>, after: &BTreeMap<String, String>) -> Refresh {
    let mut refs = Vec::new();
    let mut total: u64 = 0;
    let names: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    for refname in names {
        let (from, to) = (before.get(refname), after.get(refname));
        if from == to {
            continue;
        }
        total = total.saturating_add(1);
        if refs.len() >= MAX_CHANGED_ROWS || refname.len() > MAX_PATH_BYTES {
            continue;
        }
        refs.push(RefreshedRef {
            refname: refname.clone(),
            from: from.cloned(),
            to: to.cloned(),
        });
    }
    let truncated = total > refs.len() as u64;
    Refresh {
        refs,
        truncated,
        total,
    }
}

/// Make the mirror's HEAD name a branch the mirror actually has — the upstream's default one.
///
/// a mirror is `git init --bare`, so its HEAD names git's compiled default
/// (`refs/heads/master`), and the refresh above writes only `refs/heads/*`. On a repository whose
/// default branch is `main` the mirror's HEAD therefore stayed DANGLING, and `upload-pack` does not
/// advertise a dangling HEAD: a `--single-branch` clone (which `--depth` implies) had no branch to
/// select and came back EMPTY with exit 0, while a full clone fetched everything and then could not
/// check out. HEAD is part of what a read stream serves, so the refresh owns it.
///
/// Costs a round trip ONLY when HEAD is broken — a mirror already pointing somewhere real is left
/// alone, so the steady state is the same single hop as before. `ls-remote --symref` is git's own
/// answer to "what does the remote's HEAD name"; nothing here parses a protocol or guesses a branch.
///
/// The mirror COPIES the upstream and never invents: an upstream that advertises no HEAD of its own
/// (an empty repository, or a bare repo nobody set a default branch on) leaves this mirror's HEAD
/// exactly as it was, and the mirror then behaves for a clone precisely as the upstream itself
/// would. The silent-empty-clone defect was the mirror DISAGREEING with the upstream; faithfully
/// reproducing an upstream's own headlessness is not that, and refusing it would make repositories
/// unreachable through the broker that are reachable without it.
fn align_mirror_head(
    cfg: &GitConfig,
    mirror: &Path,
    upstream_url: &str,
    credential: Option<&GitCredential>,
) -> Result<()> {
    let have = branches(cfg, mirror)?;
    if have.is_empty() || head_resolves(cfg, mirror)? {
        return Ok(());
    }
    let Some(refname) = upstream_head_branch(cfg, upstream_url, credential)? else {
        return Ok(());
    };
    if !have.iter().any(|branch| branch == &refname) {
        return Ok(());
    }
    let pointed = run(
        cfg,
        Some(mirror),
        &["symbolic-ref", "HEAD", &refname],
        None,
        None,
    )?;
    if !pointed.ok() {
        return Err(pointed.failure("symbolic-ref HEAD"));
    }
    Ok(())
}

/// Does the mirror's HEAD point at a ref that exists? `symbolic-ref` names the target;
/// `show-ref --verify` says whether it is real.
fn head_resolves(cfg: &GitConfig, mirror: &Path) -> Result<bool> {
    let head = run(
        cfg,
        Some(mirror),
        &["symbolic-ref", "--quiet", "HEAD"],
        None,
        None,
    )?;
    if !head.ok() {
        return Ok(false);
    }
    let target = String::from_utf8_lossy(&head.stdout).trim().to_string();
    if target.is_empty() {
        return Ok(false);
    }
    let exists = run(
        cfg,
        Some(mirror),
        &["show-ref", "--verify", "--quiet", &target],
        None,
        None,
    )?;
    Ok(exists.ok())
}

/// The mirror's branch refs, by full name.
fn branches(cfg: &GitConfig, mirror: &Path) -> Result<Vec<String>> {
    let listed = run(
        cfg,
        Some(mirror),
        &["for-each-ref", "--format=%(refname)", "refs/heads/"],
        None,
        None,
    )?;
    if !listed.ok() {
        return Err(listed.failure("for-each-ref"));
    }
    Ok(String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// What the upstream's HEAD is a symref to, e.g. `refs/heads/main`. `None` when the upstream
/// advertises no symbolic HEAD (an empty repository, or one whose own HEAD dangles).
fn upstream_head_branch(
    cfg: &GitConfig,
    upstream_url: &str,
    credential: Option<&GitCredential>,
) -> Result<Option<String>> {
    let listed = run(
        cfg,
        None,
        &["ls-remote", "--symref", upstream_url, "HEAD"],
        None,
        credential,
    )?;
    if !listed.ok() {
        return Err(listed.failure("ls-remote --symref"));
    }
    Ok(parse_symref_head(&listed.stdout))
}

/// Parse `ref: refs/heads/main\tHEAD` out of `git ls-remote --symref`. Only a `refs/heads/` target
/// is accepted — a HEAD pointing anywhere else is not a branch this mirror serves.
fn parse_symref_head(stdout: &[u8]) -> Option<String> {
    String::from_utf8_lossy(stdout).lines().find_map(|line| {
        let (target, name) = line.strip_prefix("ref: ")?.split_once('\t')?;
        (name.trim() == "HEAD" && target.starts_with("refs/heads/"))
            .then(|| target.trim().to_string())
    })
}

#[cfg(test)]
mod tests;
