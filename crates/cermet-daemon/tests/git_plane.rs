//! End-to-end coverage of the git-native stream plane, entirely OFFLINE.
//!
//! A real `git push` runs against the daemon's `git.sock`: git's own `receive-pack` receives the
//! pack into the persistent mirror, git's own `update` hook asks the broker, the broker decides by
//! sentence and (on allow) carries the update to a `file://` upstream, and the hook confirms only
//! if that landed. Every assertion below is about what the AGENT sees in its ordinary push output
//! and about the `mirror ≡ upstream` invariant.
//!
//! The client side is the SHIPPED `git-remote-cermet`, linked into a scratch bin dir under the name
//! git looks for. Nothing here is stubbed on the client side.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use cermet_broker_actor::{spawn_with_sentence_authority, BrokerHandle};
use cermet_core::{BrokerConfig, SentenceAuthoritySource};
use cermet_daemon::gitplane::{self, GitPlane};
use cermet_daemon::serve::ServeConfig;
use tempfile::TempDir;

const SYSTEM_GIT: &str = "/usr/bin/git";

/// The real `git-remote-cermet`, reachable by the name git looks for. It is the `cermet` binary
/// under a second argv[0], so the test links the built CLI into a scratch bin dir and puts that on
/// git's PATH — the same side-by-side arrangement the installed pair has.
///
/// This replaced a python `ext::` relay: these tests now drive the SHIPPED client stack (git → the
/// helper → the socket), so nothing about the client surface is stubbed.
fn helper_bin_dir() -> PathBuf {
    let cli = built_cli_binary();
    let dir = cli
        .parent()
        .expect("the test binary has a directory")
        .join("cermet-git-helper-bin");
    std::fs::create_dir_all(&dir).expect("scratch bin dir");
    let helper = dir.join("git-remote-cermet");
    // Publish exactly once per process, and atomically across processes. Both runners need it:
    // `cargo test` shares one process across parallel THREADS, `nextest` gives each test its own
    // PROCESS. A `OnceLock` settles the threads; staging under a unique name and `rename`-ing into
    // place settles the processes, so a concurrent `git` always execs a complete binary rather than
    // hitting the window that remove-then-link left open.
    static PUBLISHED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    PUBLISHED.get_or_init(|| {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let unique = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let staging = dir.join(format!("git-remote-cermet.{}.{unique}", std::process::id()));
        let _ = std::fs::remove_file(&staging);
        std::fs::hard_link(&cli, &staging)
            .or_else(|_| std::fs::copy(&cli, &staging).map(|_| ()))
            .expect("stage git-remote-cermet");
        std::fs::rename(&staging, &helper).expect("publish git-remote-cermet beside the cli");
    });
    dir
}

/// The `cermet` binary this test run built. `cargo`/`nextest` both put integration-test binaries in
/// `target/<profile>/deps`, with the bin targets one directory up.
fn built_cli_binary() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test binary path");
    dir.pop(); // deps/
    if dir.ends_with("deps") {
        dir.pop();
    }
    let cli = dir.join("cermet");
    assert!(
        cli.exists(),
        "the `cermet` binary must be built for the client-surface tests: {}",
        cli.display()
    );
    cli
}

struct Harness {
    _dir: TempDir,
    root: PathBuf,
    socket: PathBuf,
    upstream: PathBuf,
    git: cermet_core::git::GitConfig,
    broker: BrokerHandle,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        // The two accept loops never return, so a plain runtime drop would block the test forever.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

struct Rules(std::sync::Mutex<cermet_core::sentence::RuleSet>);

impl SentenceAuthoritySource for Rules {
    fn current_authority(
        &self,
    ) -> cermet_core::Result<cermet_core::AuthenticatedSentenceAuthority> {
        let rules = self.0.lock().unwrap().clone();
        Ok(cermet_core::AuthenticatedSentenceAuthority {
            digest: cermet_core::sentence::authority_digest(&rules),
            rules,
        })
    }
}

/// Encode `payload` as a pkt-line, the way every git client does.
fn pkt_line(payload: &str) -> Vec<u8> {
    let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
    out.extend_from_slice(payload.as_bytes());
    out
}

/// Read a refusal to end-of-stream, tolerating a connection reset.
///
/// The daemon writes its `ERR` pkt-line and closes; on a unix socket a close can surface to the peer
/// as `ECONNRESET` after the bytes have already been delivered, so "reset" here means "the refusal
/// arrived and the daemon hung up", which is exactly the intended behaviour. Real git treats it the
/// same way — the end-to-end deny test asserts `remote error:` in git's own output.
fn read_refusal(stream: &mut std::os::unix::net::UnixStream) -> String {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&raw).into_owned()
}

fn git(root: &Path, cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(SYSTEM_GIT)
        .args(args)
        .current_dir(cwd)
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .expect("git runs")
}

fn git_ok(root: &Path, cwd: &Path, args: &[&str]) -> String {
    let out = git(root, cwd, args);
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

impl Harness {
    fn start(rules: &str) -> Self {
        Self::build(rules, None, None)
    }

    /// A harness whose configured git does not exist — the "this box cannot do git" posture. The
    /// daemon still boots; only git operations refuse.
    fn start_with_broken_git(rules: &str) -> Self {
        Self::build(rules, Some("no-such-git"), None)
    }

    /// A harness whose plane admits NO uid — every connection hits the peercred gate's refusal.
    fn start_admitting_no_one(rules: &str) -> Self {
        Self::build(rules, None, Some(Vec::new()))
    }

    fn build(rules: &str, broken_git: Option<&str>, admitted: Option<Vec<u32>>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir_all(root.join("run")).unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();

        // The upstream GitHub stands in as a local bare repo; the descriptor's git origin is
        // overridden to this `file://` root by the test-only env hook the HTTP base already uses.
        let upstream_root = root.join("upstream");
        std::fs::create_dir_all(upstream_root.join("acme")).unwrap();
        let upstream = upstream_root.join("acme").join("website.git");
        git_ok(
            &root,
            &root,
            &["init", "-q", "--bare", upstream.to_str().unwrap()],
        );
        // The test upstream is declared in a PER-BROKER synthetic github descriptor
        // (precedent: `broker/tests.rs` `github_egress_substituted_broker`). A
        // `std::env::set_var` would be process-global — so under `cargo test`, where these tests
        // share one process, parallel threads would steal each other's upstream. A
        // descriptor is per-broker and therefore correct under every runner.
        let descriptors: Vec<String> = BrokerConfig::vendored_descriptors()
            .into_iter()
            .filter(|d| !d.contains("name: github\n"))
            .chain([format!(
                "name: github\negress:\n  - https://api.github.com\nauth: bearer\nheaders:\n  \
                 Accept: application/vnd.github+json\nsplit:\n  - field: repo\n    into: [owner, \
                 name]\n    sep: \"/\"\ngit:\n  origin: file://{}\n  auth: basic:x-access-token\n",
                upstream_root.display()
            )])
            .collect();

        let git_cfg =
            cermet_core::git::GitConfig::at(root.join("mirrors")).with_binary(match broken_git {
                None => PathBuf::from(SYSTEM_GIT),
                Some(name) => root.join(name),
            });
        let parsed = cermet_core::sentence::parse_rules(rules).unwrap();
        let broker = spawn_with_sentence_authority(
            BrokerConfig {
                git: git_cfg.clone(),
                dir: root.join("home"),
                master_key: vec![7u8; 32],
                action_templates: cermet_core::templates::VENDORED_CATALOG
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                provider_descriptors: descriptors,
                artifacts: cermet_core::ArtifactConfig::default(),
            },
            std::sync::Arc::new(Rules(std::sync::Mutex::new(parsed))),
        )
        .expect("broker opens");
        connect_credential(&broker);

        // The hook program is a stub that execs the real hook client through the test binary's own
        // `cermetd` build. Tests run the hook logic in-process instead: the stub forwards to a tiny
        // script that speaks the same one-line protocol.
        let hook_program = write_hook_stub(&root);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let registry = gitplane::hook_registry();
        let (git_listener, socket) =
            gitplane::bind_git_socket(&root.join("run"), 0o600).expect("bind git.sock");
        let (hook_listener, hook_socket) =
            gitplane::hook::bind_hook_socket(&root.join("run")).expect("bind githook.sock");
        // SAFETY: `getuid` always succeeds and has no preconditions.
        let uid = unsafe { libc::getuid() };

        let plane = GitPlane {
            broker: broker.clone(),
            git: git_cfg.clone(),
            hook_program,
            hook_socket,
            registry: registry.clone(),
            admitted_uids: admitted.unwrap_or_else(|| vec![uid]),
        };
        let config = ServeConfig::default();
        let hook_broker = broker.clone();
        runtime.spawn_blocking(move || gitplane::serve_git_socket(git_listener, plane, config));
        runtime.spawn_blocking(move || {
            gitplane::hook::serve_hook_socket(hook_listener, hook_broker, registry, uid, config)
        });

        Harness {
            _dir: dir,
            root,
            socket,
            upstream,
            git: git_cfg,
            broker,
            runtime: Some(runtime),
        }
    }

    /// The receipt log, newest first — the same rows `cermet log` renders. A push decided through
    /// git's hook is an ordinary request, so it is visible here or it left no receipt at all.
    fn receipts(&self) -> Vec<serde_json::Value> {
        let broker = self.broker.clone();
        let json = self
            .runtime
            .as_ref()
            .expect("the harness runtime is live")
            .block_on(async move { broker.history().await })
            .expect("the receipt log reads");
        serde_json::from_str(&json).expect("the receipt log is JSON")
    }

    /// The newest receipt naming this branch, whatever it decided.
    fn receipt_for_branch(&self, branch: &str) -> Option<serde_json::Value> {
        self.receipts()
            .into_iter()
            .find(|row| row["resource"]["branch"] == serde_json::json!(branch))
    }

    /// A local clone with one commit; returns its oid.
    fn source(&self) -> (PathBuf, String) {
        let src = self.root.join("clone");
        std::fs::create_dir_all(src.join("docs")).unwrap();
        git_ok(&self.root, &src, &["init", "-q", "-b", "main", "."]);
        std::fs::write(src.join("README.md"), "hello\n").unwrap();
        std::fs::write(src.join("docs/guide.md"), "guide\n").unwrap();
        git_ok(&self.root, &src, &["add", "-A"]);
        git_ok(&self.root, &src, &["commit", "-q", "-m", "one"]);
        let oid = git_ok(&self.root, &src, &["rev-parse", "HEAD"]);
        (src, oid)
    }

    /// Run git through the REAL helper, exactly as a wired repo arranges it: the helper on PATH and
    /// the remote spelled `cermet::<provider>/<owner>/<name>`. Returns `(succeeded, combined
    /// output)` — the output IS what a human would see.
    fn git_via_helper(&self, cwd: &Path, args: &[&str]) -> (bool, String) {
        let mut full: Vec<&str> = Vec::new();
        full.extend_from_slice(args);
        let out = std::process::Command::new(SYSTEM_GIT)
            .args(&full)
            .current_dir(cwd)
            .env("HOME", &self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .env("CERMET_GIT_SOCK", &self.socket)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    helper_bin_dir().display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .output()
            .expect("git runs");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (out.status.success(), text)
    }

    fn push(&self, src: &Path, repo: &str, refspec: &str) -> (bool, String) {
        let remote = format!("cermet::{repo}");
        self.git_via_helper(src, &["push", &remote, refspec])
    }

    /// A fetch through the plane. The daemon decides the read, refreshes the mirror from the
    /// upstream, and only then serves.
    fn fetch(&self, src: &Path, repo: &str, refspec: &str) -> (bool, String) {
        let remote = format!("cermet::{repo}");
        self.git_via_helper(src, &["fetch", &remote, refspec])
    }

    /// Open the stream plane socket directly and send `header` (no trailing newline is added when
    /// `header` is None — that is the stalled-client case).
    /// Open the stream plane socket directly and send `request` as git-daemon's own pkt-line
    /// (`None` sends nothing at all — the stalled-client case).
    fn raw_stream(&self, request: Option<&str>) -> std::os::unix::net::UnixStream {
        let mut s =
            std::os::unix::net::UnixStream::connect(&self.socket).expect("connect git.sock");
        if let Some(request) = request {
            s.write_all(&pkt_line(request)).unwrap();
            s.flush().unwrap();
        }
        s
    }

    /// Commit straight into the upstream bare repo, standing in for a third party (or for a repo
    /// that existed before this host ever heard of it). Returns the new tip.
    fn seed_upstream_out_of_band(&self, body: &str, message: &str) -> String {
        let scratch = self.root.join(format!("oob-{}", message.replace(' ', "-")));
        git_ok(
            &self.root,
            &self.root,
            &["init", "-q", "-b", "main", scratch.to_str().unwrap()],
        );
        std::fs::write(scratch.join("oob.txt"), body).unwrap();
        git_ok(&self.root, &scratch, &["add", "-A"]);
        git_ok(&self.root, &scratch, &["commit", "-q", "-m", message]);
        git_ok(
            &self.root,
            &scratch,
            &["push", "-q", self.upstream.to_str().unwrap(), "main"],
        );
        git_ok(&self.root, &scratch, &["rev-parse", "HEAD"])
    }

    /// Advance an upstream that already has history, out of band.
    fn advance_upstream_out_of_band(&self, body: &str, message: &str) -> String {
        let scratch = self.root.join(format!("adv-{}", message.replace(' ', "-")));
        git_ok(
            &self.root,
            &self.root,
            &[
                "clone",
                "-q",
                "-b",
                "main",
                self.upstream.to_str().unwrap(),
                scratch.to_str().unwrap(),
            ],
        );
        std::fs::write(scratch.join("oob.txt"), body).unwrap();
        git_ok(&self.root, &scratch, &["add", "-A"]);
        git_ok(&self.root, &scratch, &["commit", "-q", "-m", message]);
        git_ok(&self.root, &scratch, &["push", "-q", "origin", "main"]);
        git_ok(&self.root, &scratch, &["rev-parse", "HEAD"])
    }

    fn mirror(&self) -> PathBuf {
        cermet_core::git::mirror_path(
            &self.git,
            &cermet_core::git::RepoId::parse("github/acme/website").unwrap(),
        )
    }

    fn ref_of(&self, repo: &Path, branch: &str) -> Option<String> {
        let out = git(
            &self.root,
            &self.root,
            &[
                "--git-dir",
                repo.to_str().unwrap(),
                "rev-parse",
                &format!("refs/heads/{branch}"),
            ],
        );
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

fn connect_credential(broker: &BrokerHandle) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let _ = broker
            .connect(
                "github".into(),
                secrecy::SecretString::new("ghp_fixture_never_in_a_receipt".into()),
                None,
            )
            .await;
    });
}

/// The `update` hook git runs. In production this is `cermetd git-update-hook`; the test binary is
/// not `cermetd`, so the stub speaks the same one-line JSON protocol from `/bin/sh` + python.
fn write_hook_stub(root: &Path) -> PathBuf {
    let client = root.join("hook-client.py");
    std::fs::write(
        &client,
        r#"
import json, os, socket, sys
sock = os.environ.get("CERMET_HOOK_SOCKET")
token = os.environ.get("CERMET_HOOK_TOKEN")
if not sock or not token:
    sys.stderr.write("cermet: this mirror was pushed to outside an attested stream; refusing\n")
    sys.exit(1)
q = {"token": token, "refname": sys.argv[1], "old": sys.argv[2], "new": sys.argv[3]}
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock)
s.sendall((json.dumps(q) + "\n").encode())
f = s.makefile("rb")
answer = json.loads(f.readline().decode())
for line in answer["message"].splitlines():
    sys.stderr.write(line + "\n")
sys.exit(0 if answer["allow"] else 1)
"#,
    )
    .unwrap();
    let stub = root.join("cermetd-hook");
    let mut file = std::fs::File::create(&stub).unwrap();
    // The stub swallows the `git-update-hook` argv[1] the real binary dispatches on.
    write!(
        file,
        "#!/bin/sh\nshift\nexec python3 '{}' \"$@\"\n",
        client.display()
    )
    .unwrap();
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    stub
}

/// Push authority only — the read side is a SEPARATE rule, so these two are never conflated.
const ALLOW: &str = "allow github.push where owner = \"acme\" and name = \"website\"";

/// Both sides, the shape a working box carries.
const ALLOW_BOTH: &str = "allow github.push where owner = \"acme\" and name = \"website\"\n\
                          allow github.fetch where owner = \"acme\" and name = \"website\"";

// ---------------------------------------------------------------------------

#[test]
fn an_allowed_push_streams_through_receive_pack_and_lands_upstream() {
    let h = Harness::start(ALLOW);
    let (src, oid) = h.source();

    let (ok, output) = h.push(&src, "github/acme/website", "main");
    assert!(ok, "the push should be authorized and carried:\n{output}");
    assert!(
        output.contains("cermet: carried main@"),
        "the receipt rides git's own channel:\n{output}"
    );
    // mirror ≡ upstream: the hook confirms ONLY after the credentialed hop lands.
    assert_eq!(h.ref_of(&h.upstream, "main").as_deref(), Some(oid.as_str()));
    assert_eq!(h.ref_of(&h.mirror(), "main").as_deref(), Some(oid.as_str()));
}

/// A silent pre-read drop of the peercred gate's refusal would surface to the
/// caller as a mute "Connection reset by peer" — a failure class that is expensive to diagnose.
/// The gate still refuses before READING a byte; it writes one legible
/// ERR pkt-line naming the uid so the caller learns what to fix.
#[test]
fn an_unadmitted_uid_reads_a_legible_refusal_instead_of_a_mute_reset() {
    let h = Harness::start_admitting_no_one("allow github.push where owner = \"acme\"");
    let mut stream = std::os::unix::net::UnixStream::connect(&h.socket).expect("connect");
    let refusal = read_refusal(&mut stream);
    // SAFETY: `getuid` always succeeds and has no preconditions.
    let uid = unsafe { libc::getuid() };
    assert!(
        refusal.contains("ERR") && refusal.contains(&format!("uid {uid}")),
        "the refusal names the caller's uid on git's own error channel:\n{refusal:?}"
    );
    assert!(
        refusal.contains("not admitted"),
        "the refusal says WHY:\n{refusal:?}"
    );
}

#[test]
fn an_unruled_push_is_refused_in_gits_own_output_and_moves_nothing() {
    // A corpus that says nothing about this repo: no standing authority, so deny.
    let h = Harness::start("allow github.push where owner = \"other\" and name = \"repo\"");
    let (src, _oid) = h.source();

    let (ok, output) = h.push(&src, "github/acme/website", "main");
    assert!(!ok, "no sentence speaks, so the push is refused:\n{output}");
    assert!(
        output.contains("no standing authority"),
        "the refusal is legible in the agent's push output:\n{output}"
    );
    // the refusal addresses the RIGHT party. It used to tell the pusher — normally an
    // agent — to "add the rule and re-push", which is a human-only, presence-gated act it cannot
    // perform. What it can do is hand the sentence to its operator.
    assert!(
        output.contains("ask your operator") && !output.contains("add the rule and re-push"),
        "a refusal must not instruct the agent to perform a human-only act:\n{output}"
    );
    assert!(
        output.contains("hook declined"),
        "it rides git's own error channel:\n{output}"
    );
    // The refusal renders facts derived from git's OWN objects, not the agent's description.
    assert!(
        output.contains("README.md") && output.contains("docs/guide.md"),
        "the human sees what the push actually touches:\n{output}"
    );
    assert_eq!(
        h.ref_of(&h.upstream, "main"),
        None,
        "nothing reached upstream"
    );
    assert_eq!(
        h.ref_of(&h.mirror(), "main"),
        None,
        "the mirror is unchanged"
    );
}

#[test]
fn a_push_the_upstream_refuses_leaves_the_mirror_unchanged() {
    let h = Harness::start(ALLOW);
    let (src, first) = h.source();
    assert!(h.push(&src, "github/acme/website", "main").0);

    // Somebody else advances the upstream out from under us; our next push is a non-fast-forward.
    let other = h.root.join("other");
    git_ok(
        &h.root,
        &h.root,
        &[
            "clone",
            "-q",
            "-b",
            "main",
            h.upstream.to_str().unwrap(),
            other.to_str().unwrap(),
        ],
    );
    std::fs::write(other.join("README.md"), "theirs\n").unwrap();
    git_ok(&h.root, &other, &["add", "-A"]);
    git_ok(&h.root, &other, &["commit", "-q", "-m", "theirs"]);
    let theirs = git_ok(&h.root, &other, &["rev-parse", "HEAD"]);
    git_ok(&h.root, &other, &["push", "-q", "origin", "main"]);

    git_ok(&h.root, &src, &["reset", "-q", "--hard", &first]);
    std::fs::write(src.join("README.md"), "ours\n").unwrap();
    git_ok(&h.root, &src, &["add", "-A"]);
    git_ok(&h.root, &src, &["commit", "-q", "-m", "ours"]);
    let ours = git_ok(&h.root, &src, &["rev-parse", "HEAD"]);

    let (ok, output) = h.push(&src, "github/acme/website", "+main");
    assert!(!ok, "the upstream's fast-forward rule refuses:\n{output}");
    assert!(
        output.contains("upstream refused") || output.contains("mirror is unchanged"),
        "the upstream's own words reach the agent:\n{output}"
    );
    assert_eq!(
        h.ref_of(&h.upstream, "main").as_deref(),
        Some(theirs.as_str())
    );
    assert_eq!(
        h.ref_of(&h.mirror(), "main").as_deref(),
        Some(first.as_str()),
        "mirror ≡ upstream is preserved by NOT advancing the mirror on a failed hop"
    );
    assert_ne!(
        h.ref_of(&h.mirror(), "main").as_deref(),
        Some(ours.as_str())
    );
}

#[test]
fn a_malformed_repo_identity_is_refused_before_any_git_process_exists() {
    let h = Harness::start(ALLOW);
    let (src, _oid) = h.source();

    for hostile in [
        "github/../../evil",
        "github/acme",
        "github/.hidden/x",
        "github/acme/-rf",
    ] {
        let (ok, output) = h.push(&src, hostile, "main");
        assert!(!ok, "`{hostile}` must be refused: {output}");
        // The refusal is a git ERR pkt-line, so the REASON reaches the agent.
        assert!(
            output.contains("remote error: cermet:"),
            "`{hostile}` must be refused legibly, in git's own error channel:\n{output}"
        );
    }
    // The observable property, not a tautology. None of the four should have created
    // anything anywhere — the identity is validated before a path is joined, so the mirror root
    // does not even come into existence.
    assert!(
        !h.git.mirror_dir.exists(),
        "a refused identity must create no directory: {} exists",
        h.git.mirror_dir.display()
    );
}

#[test]
fn a_second_push_reuses_the_persistent_mirror() {
    let h = Harness::start(ALLOW);
    let (src, _first) = h.source();
    assert!(h.push(&src, "github/acme/website", "main").0);

    std::fs::write(src.join("README.md"), "again\n").unwrap();
    git_ok(&h.root, &src, &["add", "-A"]);
    git_ok(&h.root, &src, &["commit", "-q", "-m", "two"]);
    let second = git_ok(&h.root, &src, &["rev-parse", "HEAD"]);

    let (ok, output) = h.push(&src, "github/acme/website", "main");
    assert!(ok, "{output}");
    assert_eq!(
        h.ref_of(&h.upstream, "main").as_deref(),
        Some(second.as_str())
    );
    // The mirror kept the first push's objects: this is what makes every later push O(delta) and
    // what a per-request store could never do.
    assert_eq!(
        h.ref_of(&h.mirror(), "main").as_deref(),
        Some(second.as_str())
    );
}

/// A deletion is an update to the zero oid, decided under the SAME push sentence that covers the
/// repo — git's own model of what push authority means. It executes and leaves an ALLOW receipt.
#[test]
fn a_covered_branch_deletion_is_carried_and_receipted() {
    let h = Harness::start(ALLOW);
    let (src, oid) = h.source();
    git_ok(&h.root, &src, &["branch", "feature"]);
    let (ok, output) = h.push(&src, "github/acme/website", "feature");
    assert!(ok, "{output}");
    assert_eq!(
        h.ref_of(&h.upstream, "feature").as_deref(),
        Some(oid.as_str())
    );

    let (ok, output) = h.push(&src, "github/acme/website", ":feature");
    assert!(
        ok,
        "the push sentence covering this repo covers deleting its refs:\n{output}"
    );
    assert!(
        output.contains("cermet: deleted feature"),
        "the receipt names the ref and rides git's own channel:\n{output}"
    );
    assert_eq!(
        h.ref_of(&h.upstream, "feature"),
        None,
        "the deletion reached the upstream"
    );
    assert_eq!(
        h.ref_of(&h.mirror(), "feature"),
        None,
        "mirror ≡ upstream: the mirror's ref went with it"
    );

    let receipt = h
        .receipt_for_branch("feature")
        .expect("a deletion leaves a receipt like any other attempted effect");
    assert_eq!(receipt["decision"], "allow");
    assert_eq!(receipt["provider"], "github");
    assert_eq!(receipt["action"], "push");
    assert_eq!(
        receipt["resource"]["new_oid"],
        serde_json::json!(cermet_core::git::NULL_OID),
        "the receipt names the zero-oid transition, not a guess at one"
    );
    assert_eq!(
        receipt["resource"]["mirror_old_oid"],
        serde_json::json!(oid),
        "and the tip it moved from"
    );
    assert!(
        receipt["request_id"].is_string(),
        "the deletion carries a request id:\n{receipt}"
    );
}

/// The other half of the contract: a deletion no sentence admits is refused WITH a receipt, in the
/// broker's own words, never git's bare "failed to push some refs".
#[test]
fn an_unruled_branch_deletion_is_refused_with_a_receipt() {
    // Push authority for a DIFFERENT repo, so nothing here speaks for `acme/website`.
    let h = Harness::start("allow github.push where owner = \"other\" and name = \"repo\"");
    let (src, oid) = h.source();
    git_ok(&h.root, &src, &["branch", "feature"]);
    // Seed both sides out of band: the ref exists to delete, without any allowed push creating it.
    git_ok(
        &h.root,
        &src,
        &["push", "-q", h.upstream.to_str().unwrap(), "feature"],
    );
    let mirror = cermet_core::git::ensure_mirror(
        &h.git,
        &cermet_core::git::RepoId::parse("github/acme/website").unwrap(),
        &h.root.join("cermetd-hook"),
    )
    .unwrap();
    // Into the mirror by fetch, not by push: a push would meet the mirror's own update hook, and
    // this ref is meant to predate any decision.
    git_ok(
        &h.root,
        &h.root,
        &[
            "--git-dir",
            mirror.to_str().unwrap(),
            "fetch",
            "-q",
            h.upstream.to_str().unwrap(),
            "+refs/heads/feature:refs/heads/feature",
        ],
    );

    let (ok, output) = h.push(&src, "github/acme/website", ":feature");
    assert!(!ok, "no sentence admits this deletion:\n{output}");
    assert!(
        output.contains("no standing authority"),
        "the refusal is legible in the agent's push output:\n{output}"
    );
    assert!(
        output.contains("ask your operator"),
        "and it addresses the party that can widen authority:\n{output}"
    );
    assert_eq!(
        h.ref_of(&h.upstream, "feature").as_deref(),
        Some(oid.as_str()),
        "nothing was deleted"
    );
    assert_eq!(
        h.ref_of(&mirror, "feature").as_deref(),
        Some(oid.as_str()),
        "and the mirror kept its ref"
    );

    let receipt = h
        .receipt_for_branch("feature")
        .expect("a refused deletion leaves a deny row, not silence");
    assert_eq!(receipt["decision"], "deny");
    assert_eq!(
        receipt["resource"]["new_oid"],
        serde_json::json!(cermet_core::git::NULL_OID)
    );
    assert!(
        receipt["reason"].is_string(),
        "the deny row carries why:\n{receipt}"
    );
}

#[test]
fn a_stalled_client_releases_its_connection_slot_instead_of_wedging_the_plane() {
    // With no read timeout on the header a client that connects and says nothing would hold its
    // handler thread and its `ConnSlot` forever, and `max_conns` of them would wedge the plane
    // until the daemon restarted. The handshake budget is what bounds it.
    let h = Harness::start(ALLOW);
    let (src, oid) = h.source();

    // Connect and send nothing at all.
    let mut stalled = h.raw_stream(None);
    // The daemon must give up on its own and close, rather than holding the slot.
    stalled
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let mut sink = Vec::new();
    let read = stalled.read_to_end(&mut sink);
    assert!(
        read.is_ok(),
        "the daemon closes a stalled handshake rather than holding it: {read:?}"
    );

    // And the plane still serves: the slot came back.
    let (ok, output) = h.push(&src, "github/acme/website", "main");
    assert!(ok, "the plane is still healthy:\n{output}");
    assert_eq!(h.ref_of(&h.upstream, "main").as_deref(), Some(oid.as_str()));
}

#[test]
fn every_pre_spawn_refusal_reaches_the_agent_as_a_git_error() {
    // Refusals are ERR pkt-lines, so git renders them as `remote error: …`, rather than
    // arriving as `fatal: protocol error: bad line length character: cerm`.
    let h = Harness::start(ALLOW);
    for (request, expected) in [
        (
            "git-receive-pack /github/../../evil\0host=cermet\0",
            "provider/owner/name",
        ),
        (
            "git-receive-pack /github/acme\0host=cermet\0",
            "provider/owner/name",
        ),
        (
            "notaservice /github/acme/website\0host=cermet\0",
            "not a git service",
        ),
        ("garbage\0host=cermet\0", "must be `<service> <path>`"),
        // A read of a repo no sentence covers: the refusal names the rule to add (replacing the
        // old "nothing to serve … push to it first" message from a since-removed stale-serve design).
        (
            "git-upload-pack /github/acme/nothing-here\0host=cermet\0",
            "no standing authority to read",
        ),
    ] {
        let mut stream = h.raw_stream(Some(request));
        let text = read_refusal(&mut stream);
        // A pkt-line: 4 hex length digits covering the whole packet, then `ERR <message>`.
        assert!(
            text.len() > 4 && text[4..].starts_with("ERR "),
            "`{request}` must be refused as an ERR pkt-line, got {text:?}"
        );
        let declared = usize::from_str_radix(&text[..4], 16).expect("a hex pkt-line length");
        assert_eq!(
            declared,
            text.len(),
            "the declared length covers the packet"
        );
        assert!(
            text.contains(expected),
            "`{request}` must say why: {text:?}"
        );
    }
}

#[test]
fn an_unusable_git_refuses_the_stream_legibly_naming_the_setting() {
    // The operator-directed payoff: no registration ceremony, the daemon boots fine, and a box whose
    // `git_binary` does not work answers an ordinary `git push` with a reason.
    let h = Harness::start_with_broken_git(ALLOW);
    let mut stream = h.raw_stream(Some("git-receive-pack /github/acme/website\0host=cermet\0"));
    let text = read_refusal(&mut stream);
    assert!(text[4..].starts_with("ERR "), "{text:?}");
    assert!(text.contains("is not usable"), "{text:?}");
    assert!(
        text.contains("git_binary"),
        "it names the setting: {text:?}"
    );
}

// ---------------------------------------------------------------------------
// A read serves only what a just-succeeded refresh produced
// ---------------------------------------------------------------------------

#[test]
fn a_clone_of_a_repo_this_host_has_never_seen_works() {
    // The headline case: nothing has ever been pushed through the plane; the upstream has
    // history; a clone of a `cermet::` remote must produce it. Without the refresh this would refuse with
    // "nothing to serve … push to it first", which would make the natural first command impossible.
    let h = Harness::start(ALLOW_BOTH);
    let upstream_tip = h.seed_upstream_out_of_band("seeded\n", "seeded upstream");
    assert!(
        !h.mirror().exists(),
        "no mirror exists before the first contact"
    );

    let reader = h.root.join("reader");
    std::fs::create_dir_all(&reader).unwrap();
    git_ok(&h.root, &reader, &["init", "-q", "-b", "main", "."]);
    let (ok, output) = h.fetch(&reader, "github/acme/website", "main");
    assert!(ok, "a clone of an unseen repo must work:\n{output}");
    assert_eq!(
        git_ok(&h.root, &reader, &["rev-parse", "FETCH_HEAD"]),
        upstream_tip,
        "what arrived is the UPSTREAM's tip, not something a prior push left"
    );
    // The refresh created and seeded the mirror on the way.
    assert_eq!(
        h.ref_of(&h.mirror(), "main").as_deref(),
        Some(upstream_tip.as_str())
    );
}

/// From a cold-start usability trial, end to end through the real plane: `git clone --depth 1`
/// of a `cermet::` remote came back an EMPTY repository with exit 0. `--depth` implies
/// `--single-branch`, which asks the server which branch HEAD names; the mirror's HEAD named git's
/// compiled default (`refs/heads/master`), which a `main` repository does not have, so `upload-pack`
/// advertised no HEAD, the client wanted nothing, and the clone was empty. The refresh now copies
/// the upstream's default branch onto the mirror's HEAD.
#[test]
fn a_shallow_clone_of_a_main_branch_repo_is_not_empty() {
    let h = Harness::start(ALLOW_BOTH);
    h.seed_upstream_out_of_band("seeded\n", "seeded upstream");
    // What a real forge advertises, and what a bare `git init` does not set.
    git_ok(
        &h.root,
        &h.root,
        &[
            "--git-dir",
            h.upstream.to_str().unwrap(),
            "symbolic-ref",
            "HEAD",
            "refs/heads/main",
        ],
    );

    let out = h.root.join("shallow-reader");
    let (ok, output) = h.git_via_helper(
        &h.root,
        &[
            "clone",
            "--depth",
            "1",
            "cermet::github/acme/website",
            out.to_str().unwrap(),
        ],
    );
    assert!(ok, "a shallow clone must succeed:\n{output}");
    assert!(
        out.join("oob.txt").is_file(),
        "`git clone --depth 1` must not answer with an empty repository:\n{output}"
    );
    assert!(
        out.join(".git/shallow").is_file(),
        "and it really is shallow — the negotiation ran:\n{output}"
    );
}

#[test]
fn a_fetch_reflects_an_out_of_band_upstream_change() {
    // The divergence this harness stages, now on the READ side: a third party advances the
    // upstream, and the very next fetch must show it. This is the property "serve the mirror as-is"
    // could not have.
    let h = Harness::start(ALLOW_BOTH);
    let (src, first) = h.source();
    assert!(h.push(&src, "github/acme/website", "main").0);

    let theirs = h.advance_upstream_out_of_band("theirs\n", "theirs");
    assert_ne!(theirs, first);

    let reader = h.root.join("reader");
    std::fs::create_dir_all(&reader).unwrap();
    git_ok(&h.root, &reader, &["init", "-q", "-b", "main", "."]);
    let (ok, output) = h.fetch(&reader, "github/acme/website", "main");
    assert!(ok, "{output}");
    assert_eq!(
        git_ok(&h.root, &reader, &["rev-parse", "FETCH_HEAD"]),
        theirs,
        "the fetch must reflect the upstream, not the mirror's last push"
    );
}

#[test]
fn a_read_with_no_fetch_sentence_is_refused_and_never_serves_stale_refs() {
    // Push authority is not read authority. The mirror here HAS content (a push put it there), which
    // is exactly the state where a silent stale serve would have been invisible.
    let h = Harness::start(ALLOW);
    let (src, first) = h.source();
    assert!(h.push(&src, "github/acme/website", "main").0);
    assert_eq!(
        h.ref_of(&h.mirror(), "main").as_deref(),
        Some(first.as_str())
    );

    let reader = h.root.join("reader");
    std::fs::create_dir_all(&reader).unwrap();
    git_ok(&h.root, &reader, &["init", "-q", "-b", "main", "."]);
    let (ok, output) = h.fetch(&reader, "github/acme/website", "main");
    assert!(!ok, "no fetch rule, no read:\n{output}");
    assert!(
        output.contains("remote error: cermet: no standing authority to read"),
        "the refusal is legible through real git:\n{output}"
    );
    assert!(
        output.contains("allow github.fetch where owner = \"acme\" and name = \"website\""),
        "and it names the rule to add:\n{output}"
    );
    // Nothing was served: the reader learned no ref at all.
    assert!(
        !output.contains(&first),
        "a refused read must not leak the mirror's refs:\n{output}"
    );
}

#[test]
fn a_refresh_that_fails_refuses_and_carries_gits_error() {
    // The other half of the ruling: an unreachable upstream must REFUSE, not fall back to whatever
    // the mirror already holds. The mirror is populated first so "serve stale" would have succeeded.
    let h = Harness::start(ALLOW_BOTH);
    let (src, first) = h.source();
    assert!(h.push(&src, "github/acme/website", "main").0);
    assert_eq!(
        h.ref_of(&h.mirror(), "main").as_deref(),
        Some(first.as_str())
    );

    // Take the upstream away.
    std::fs::rename(&h.upstream, h.root.join("upstream/acme/moved.git")).unwrap();

    let reader = h.root.join("reader");
    std::fs::create_dir_all(&reader).unwrap();
    git_ok(&h.root, &reader, &["init", "-q", "-b", "main", "."]);
    let (ok, output) = h.fetch(&reader, "github/acme/website", "main");
    assert!(!ok, "an unreachable upstream must refuse:\n{output}");
    assert!(
        output.contains("remote error: cermet:"),
        "the refusal rides git's error channel:\n{output}"
    );
    assert!(
        output.contains("refusing to serve a stale mirror")
            || output.contains("upstream refresh failed"),
        "it says why, in git's own words:\n{output}"
    );
    assert!(!output.contains(&first), "and it serves nothing:\n{output}");
}
