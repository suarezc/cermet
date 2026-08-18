//! `git-remote-cermet` end to end: a repository wired to a `cermet::` remote reaches the daemon's
//! stream plane through PLAIN git.
//!
//! There is no `cermet git` wrapper. The wiring is a remote URL git resolves to a helper
//! by name, so the user's own `git push` is the whole integration — which is exactly what these
//! tests drive. Offline: the "remote" is a stub socket or a local bare repo, and nothing touches the
//! network.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

const SYSTEM_GIT: &str = "/usr/bin/git";

/// The built `cermet` binary, plus a scratch bin dir holding it under the helper's name.
fn binaries() -> (PathBuf, PathBuf) {
    let mut dir = std::env::current_exe().expect("test binary path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    let cermet = dir.join("cermet");
    assert!(
        cermet.exists(),
        "the `cermet` binary must be built: {}",
        cermet.display()
    );
    let bin = dir.join("cermet-front-end-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let helper = bin.join("git-remote-cermet");
    // Publish exactly once per process, and atomically across processes. Both runners need it:
    // `cargo test` shares one process across parallel THREADS, `nextest` gives each test its own
    // PROCESS. A `OnceLock` settles the threads; staging under a unique name and `rename`-ing into
    // place settles the processes, so a concurrent `git` always execs a complete binary rather than
    // hitting the window that remove-then-link left open.
    static PUBLISHED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    PUBLISHED.get_or_init(|| {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let unique = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let staging = bin.join(format!("git-remote-cermet.{}.{unique}", std::process::id()));
        let _ = std::fs::remove_file(&staging);
        std::fs::hard_link(&cermet, &staging)
            .or_else(|_| std::fs::copy(&cermet, &staging).map(|_| ()))
            .expect("stage git-remote-cermet");
        std::fs::rename(&staging, &helper).expect("publish git-remote-cermet beside the cli");
    });
    (cermet, bin)
}

struct Repo {
    _dir: tempfile::TempDir,
    root: PathBuf,
    work: PathBuf,
}

impl Repo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let repo = Repo {
            _dir: dir,
            root,
            work,
        };
        repo.git(&["init", "-q", "-b", "main", "."]);
        std::fs::write(repo.work.join("a.txt"), "a\n").unwrap();
        repo.git(&["add", "-A"]);
        repo.git(&["commit", "-q", "-m", "one"]);
        repo
    }

    fn base(cmd: &mut Command) -> &mut Command {
        cmd.env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
    }

    fn git(&self, args: &[&str]) -> (bool, String) {
        let mut cmd = Command::new(SYSTEM_GIT);
        Self::base(&mut cmd)
            .args(args)
            .current_dir(&self.work)
            .env("HOME", &self.root);
        let out = cmd.output().expect("git runs");
        (out.status.success(), combined(&out))
    }

    /// The user's own git, with the helper reachable on PATH and the stream plane named — exactly
    /// the environment an installed box gives it.
    fn git_wired(&self, socket: &Path, args: &[&str]) -> (bool, String) {
        let (_cermet, bin) = binaries();
        let mut cmd = Command::new(SYSTEM_GIT);
        Self::base(&mut cmd)
            .args(args)
            .current_dir(&self.work)
            .env("HOME", &self.root)
            .env("CERMET_GIT_SOCK", socket)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            );
        let out = cmd.output().expect("git runs");
        (out.status.success(), combined(&out))
    }
}

fn combined(out: &std::process::Output) -> String {
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    text
}

/// A socket that exists, accepts connections, RECORDS what arrived, then hangs up without speaking
/// git. The recording is the proof the helper arrived, without needing the daemon.
fn dead_socket(root: &Path) -> (PathBuf, Arc<Mutex<Vec<u8>>>) {
    let path = root.join("git.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind stub socket");
    let arrived = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&arrived);
    std::thread::spawn(move || {
        for conn in listener.incoming().take(8).flatten() {
            let mut conn = conn;
            let mut buf = [0u8; 256];
            if let Ok(read) = std::io::Read::read(&mut conn, &mut buf) {
                recorder.lock().unwrap().extend_from_slice(&buf[..read]);
            }
        }
    });
    (path, arrived)
}

/// The stub's recording, once it has one. The helper's write and the stub's read are different
/// threads in different processes, so a bounded wait replaces a race.
fn arrived_request(arrived: &Arc<Mutex<Vec<u8>>>) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let seen = arrived.lock().unwrap().clone();
        if !seen.is_empty() || std::time::Instant::now() >= deadline {
            return String::from_utf8_lossy(&seen).into_owned();
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn a_wired_repo_reaches_the_stream_plane_with_plain_git_push() {
    // The whole client-side chain, with no cermet command in it: the remote URL names the helper,
    // git resolves it by name on PATH, and the helper reaches the socket. The stub then hangs up, so
    // the push fails — but it fails HAVING ARRIVED, which is what this proves (the plane's own tests
    // cover the far side). Arrival is read off the SOCKET, not off git's rendering of the helper's
    // exit: whether the helper's write loses a race with the stub's hang-up (and so reports EPIPE
    // under its own name) or wins it (and exits silently on the following EOF) is scheduling, and
    // both orderings happen on a loaded box.
    let repo = Repo::new();
    let (socket, arrived) = dead_socket(&repo.root);
    repo.git(&["remote", "add", "origin", "cermet::github/acme/website"]);

    let (ok, output) = repo.git_wired(&socket, &["push", "origin", "main"]);
    assert!(!ok, "a socket that says nothing cannot complete a push");
    let request = arrived_request(&arrived);
    assert!(
        request.contains("git-receive-pack /github/acme/website"),
        "plain git push routed through the helper onto the plane: got {request:?}, git said \
         {output}"
    );
    assert!(
        !output.contains("Could not resolve host"),
        "nothing should touch the network: {output}"
    );
}

#[test]
fn a_wired_remote_with_no_daemon_gives_the_helpers_own_legible_message() {
    let repo = Repo::new();
    let socket = repo.root.join("definitely-absent.sock");
    repo.git(&["remote", "add", "origin", "cermet::github/acme/website"]);

    let (ok, output) = repo.git_wired(&socket, &["push", "origin", "main"]);
    assert!(!ok);
    assert!(
        output.contains("cannot reach the cermet daemon"),
        "{output}"
    );
    assert!(
        output.contains("Plain git commands work without the daemon"),
        "the refusal distinguishes brokered from plain use: {output}"
    );
}

#[test]
fn an_unwired_remote_is_none_of_the_helpers_business() {
    // A repository the operator never wired is bare git, daemon or no daemon.
    let repo = Repo::new();
    let (socket, _arrived) = dead_socket(&repo.root);
    let elsewhere = repo.root.join("elsewhere.git");
    let out = Command::new(SYSTEM_GIT)
        .args(["init", "-q", "--bare", elsewhere.to_str().unwrap()])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success());
    repo.git(&["remote", "add", "local", elsewhere.to_str().unwrap()]);

    let (ok, output) = repo.git_wired(&socket, &["push", "local", "main"]);
    assert!(ok, "an unwired remote is untouched:\n{output}");
    assert!(!output.contains("cermet::"), "{output}");
}

// ---------------------------------------------------------------------------
// The wiring `connect github` writes, read back through git itself
// ---------------------------------------------------------------------------

#[test]
fn wiring_reads_the_repos_remotes_and_points_a_github_one_at_the_broker() {
    use cermet_cli::git_remote::wiring;

    let repo = Repo::new();
    repo.git(&[
        "remote",
        "add",
        "origin",
        "https://github.com/acme/website.git",
    ]);
    repo.git(&[
        "remote",
        "add",
        "upstream",
        "https://gitlab.com/acme/site.git",
    ]);

    let remotes = wiring::remotes(&repo.work).expect("a repository answers");
    let origin = remotes.iter().find(|r| r.name == "origin").unwrap();
    assert_eq!(
        origin.brokered_url().as_deref(),
        Some("cermet::github/acme/website")
    );
    assert!(!origin.is_brokered(), "not yet");
    let upstream = remotes.iter().find(|r| r.name == "upstream").unwrap();
    assert_eq!(upstream.brokered_url(), None, "gitlab is not brokered");

    wiring::set_url(&repo.work, "origin", "cermet::github/acme/website").expect("set-url");
    let after = wiring::remotes(&repo.work).unwrap();
    assert!(after.iter().any(|r| r.name == "origin" && r.is_brokered()));
    // git's own view is the record: the wiring is a remote URL, and nothing else changed.
    let (_, listed) = repo.git(&["remote", "-v"]);
    assert!(listed.contains("cermet::github/acme/website"), "{listed}");
    assert!(
        listed.contains("https://gitlab.com/acme/site.git"),
        "{listed}"
    );
}

#[test]
fn wiring_has_nothing_to_say_outside_a_repository() {
    use cermet_cli::git_remote::wiring;
    let dir = tempfile::tempdir().unwrap();
    assert!(wiring::remotes(dir.path()).is_none());
    assert!(!wiring::insteadof_configured(dir.path()));
}

// ---------------------------------------------------------------------------
// The helper must never outlive a dead service
// ---------------------------------------------------------------------------

#[test]
fn the_helper_exits_when_the_service_dies_while_git_awaits_a_read() {
    // A daemon that accepts, reads the request, and closes stands in for every real trigger:
    // cermetd restarted mid-push, receive-pack OOM-killed, any crash of the service child.
    // Git's side of the helper's stdin stays OPEN — it is waiting to read a reply —
    // so the upstream pump can never finish. Joining it deadlocked both processes forever with no
    // output; detaching it means this process returns, fd 1 closes, and git gets its EOF.
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dies.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::thread::spawn(move || {
        for mut conn in listener.incoming().take(2).flatten() {
            // Read the request pkt-line, then hang up without speaking git.
            let mut sink = [0u8; 256];
            let _ = std::io::Read::read(&mut conn, &mut sink);
            drop(conn);
        }
    });

    let (_cermet, bin) = binaries();
    let helper = bin.join("git-remote-cermet");
    let mut child = Command::new(helper)
        .args(["origin", "github/acme/website"])
        .env("CERMET_GIT_SOCK", &socket)
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("helper runs");

    // Drive the handshake, then hold stdin OPEN — exactly as git does while awaiting a reply.
    let mut stdin = child.stdin.take().expect("piped");
    stdin.write_all(b"capabilities\n").unwrap();
    stdin.flush().unwrap();
    stdin.write_all(b"connect git-receive-pack\n").unwrap();
    stdin.flush().unwrap();

    // The helper must exit on its own. Poll rather than wait so a regression fails as a timeout here
    // instead of hanging the suite.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break Some(status),
            None if std::time::Instant::now() >= deadline => break None,
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    };
    if status.is_none() {
        let _ = child.kill();
        panic!("the helper hung after the service died");
    }
    drop(stdin);
}
