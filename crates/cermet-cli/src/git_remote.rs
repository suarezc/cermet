//! `git-remote-cermet` — the remote helper, and nothing more than a socket shim.
//!
//! Git's remote-helper protocol has a `connect` capability that exists for exactly this shape: the
//! helper is told which service to reach, arranges for it, answers with a blank line, and then GIT
//! SPEAKS ITS OWN PROTOCOL end to end over the helper's stdio. That is the whole implementation —
//! there is no push command, no fetch command, no ref advertisement, no capability emulation, and
//! no wire format of ours.
//!
//! Cermet is authorization and receipt — nothing else. A remote helper that implemented
//! `push`/`fetch` itself would be a second git; this one is a pipe.
//!
//! The request it writes onto the socket is GIT-DAEMON'S OWN pkt-line
//! (`git-upload-pack /github/acme/website\0host=cermet\0`), so both ends of this connection speak a
//! format git already implements. The daemon answers refusals as `ERR <message>` pkt-lines, which
//! git renders as `fatal: remote error: …` — so a refusal needs no handling here either.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// The argv[0] name git looks for when a remote URL is `cermet::<path>`.
pub const HELPER_PROGRAM: &str = "git-remote-cermet";

/// `git.sock` lives in the agents runtime dir beside `agent.sock` — see
/// [`crate::mcp::SYSTEM_AGENT_SOCK`] for why that dir differs by platform.
#[cfg(target_os = "macos")]
pub const DEFAULT_GIT_SOCK: &str = "/var/cermetd-agents/git.sock";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_GIT_SOCK: &str = "/run/cermetd-agents/git.sock";

/// Where the helper looks for the stream plane.
///
/// The primary path is the installed default: a wired repo on an installed box needs no environment
/// at all. `CERMET_GIT_SOCK` is the declared override for tests and nonstandard installs, in the same
/// shape as `CERMET_CTL_SOCK` / `CERMET_AGENT_SOCK`. It selects which socket the client trusts, which
/// buys an attacker nothing — the real socket is peercred-gated and the daemon is the decider — but
/// it IS behavior, so it is named HERE rather than left implicit. Absent it, the `CERMET_HOME`
/// convention applies, then the installed default.
pub fn resolve_git_socket(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(path) = explicit {
        return path;
    }
    if let Some(path) = std::env::var_os("CERMET_GIT_SOCK") {
        return PathBuf::from(path);
    }
    if let Some(home) = std::env::var_os("CERMET_HOME") {
        return PathBuf::from(home).join("run").join("git.sock");
    }
    PathBuf::from(DEFAULT_GIT_SOCK)
}

/// Cap on one helper-protocol command line. Git's own commands are short words.
const MAX_COMMAND_BYTES: u64 = 4096;

/// Run the helper. `url` is the part of the remote after `cermet::` — a
/// `<provider>/<owner>/<name>` path, which is what [`wiring`] writes into the repo's remote (or what
/// a `url.cermet::github/.insteadOf` line rewrites a github URL into).
pub fn run(socket: PathBuf, url: &str) -> Result<(), String> {
    let repo = url.trim_start_matches('/').trim_end_matches('/');
    if repo.is_empty() {
        return Err("no repository path in the cermet:: remote URL".into());
    }

    // A `BufReader` over `Stdin` (not a held `StdinLock`): the splice below reads stdin from another
    // thread, and a lock held across that hand-off would deadlock. The reader is MOVED into the
    // splice so anything git already buffered into it still reaches the daemon.
    let mut reader = BufReader::new(std::io::stdin());
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .by_ref()
            .take(MAX_COMMAND_BYTES)
            .read_line(&mut line)
            .map_err(|e| format!("reading a helper command: {e}"))?;
        if read == 0 {
            // Git closed the conversation without asking for anything. Nothing to do.
            return Ok(());
        }
        match line.trim_end() {
            // The ONE capability we implement. Announcing only `connect` is what makes git speak
            // its native protocol instead of asking us to emulate fetch/push.
            "capabilities" => {
                let mut out = std::io::stdout();
                out.write_all(b"connect\n\n")
                    .and_then(|()| out.flush())
                    .map_err(|e| format!("answering capabilities: {e}"))?;
            }
            command => {
                let Some(service) = command.strip_prefix("connect ") else {
                    if command.is_empty() {
                        continue;
                    }
                    // Any other command means git wanted a capability we did not announce.
                    return Err(format!("unsupported helper command `{command}`"));
                };
                return connect(reader, &socket, service.trim(), repo);
            }
        }
    }
}

/// Open the stream plane, write git-daemon's request pkt-line, tell git we are connected, and then
/// get out of the way: from the blank line on, every byte in both directions is git's.
fn connect(
    reader: BufReader<std::io::Stdin>,
    socket: &PathBuf,
    service: &str,
    repo: &str,
) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| {
        format!(
            "cannot reach the cermet daemon at {} ({e}). Is cermetd running? Plain git commands \
             work without the daemon — only brokered remotes need it.",
            socket.display()
        )
    })?;
    stream
        .write_all(&request_pkt_line(service, repo))
        .and_then(|()| stream.flush())
        .map_err(|e| format!("sending the git service request: {e}"))?;

    // The positive `connect` response is a bare newline; the service's own output follows it.
    let mut out = std::io::stdout();
    out.write_all(b"\n")
        .and_then(|()| out.flush())
        .map_err(|e| format!("answering connect: {e}"))?;

    splice(reader, stream)
}

/// `<4-hex total length><service> <path>\0host=cermet\0`.
///
/// `host=` is required by the format and meaningless here (a unix socket has no virtual hosting), so
/// it carries a constant.
///
/// There is deliberately no `version=` extra arg: `connect` IS git's v0/v1 capability —
/// `stateless-connect` is the v2 one — so announcing only `connect` pins this transport to v0/v1 by
/// construction, and git exports no protocol preference to a `connect` helper. Version negotiation
/// happens in band, which is the working default.
fn request_pkt_line(service: &str, repo: &str) -> Vec<u8> {
    let payload = format!("{service} /{repo}\0host=cermet\0").into_bytes();
    let mut out = format!("{:04x}", payload.len() + 4).into_bytes();
    out.extend_from_slice(&payload);
    out
}

/// Shuttle bytes both ways until each direction ends. Two threads and no interpretation: the helper
/// never parses, buffers, or rewrites git's protocol.
///
/// The downstream half writes to fd 1 through an UNBUFFERED handle, not `std::io::stdout()`. That is
/// load-bearing: Rust's `Stdout` is line-buffered, and git's protocol is binary — a flush packet
/// (`0000`) carries no newline, so a line-buffered writer holds the ref advertisement in its buffer
/// and both ends wait on each other forever.
fn splice(mut reader: BufReader<std::io::Stdin>, stream: UnixStream) -> Result<(), String> {
    let mut to_daemon = stream
        .try_clone()
        .map_err(|e| format!("duplicating the stream: {e}"))?;
    let mut from_daemon = stream;

    // Deliberately DETACHED, never joined. The upstream pump blocks reading git's stdin,
    // which git holds open for as long as it expects a reply; if the downstream direction ends first
    // — the service died, cermetd restarted, receive-pack was OOM-killed — joining here waits on a
    // thread that can never finish, while this process keeps fd 1 open so git never sees EOF either.
    // Returning instead closes fd 1, git gets its EOF, and the orphaned pump dies with the process.
    std::thread::spawn(move || {
        let _ = relay(&mut reader, &mut to_daemon);
        // Half-close so the service sees end-of-input and finishes, rather than waiting forever.
        let _ = to_daemon.shutdown(std::net::Shutdown::Write);
    });

    let mut out = raw_stdout();
    relay(&mut from_daemon, &mut *out)
        .map(|_| ())
        .map_err(|e| format!("relaying the git stream: {e}"))
}

/// An explicit read/write/flush loop. Deliberately NOT `io::copy`: its Linux specializations pick
/// `splice`/`copy_file_range` paths for pipe and file targets, and a shim that must never hold a
/// byte is clearer when the loop is visible.
fn relay(from: &mut impl Read, to: &mut impl Write) -> std::io::Result<u64> {
    let mut buf = [0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        let read = match from.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        to.write_all(&buf[..read])?;
        to.flush()?;
        total += read as u64;
    }
}

/// fd 1 as an unbuffered writer. `ManuallyDrop` because closing our own stdout on the way out would
/// truncate whatever git had not read yet.
fn raw_stdout() -> std::mem::ManuallyDrop<std::fs::File> {
    use std::os::fd::FromRawFd as _;
    // SAFETY: fd 1 is open for the lifetime of the process, and the handle is never closed (the
    // `ManuallyDrop` is what guarantees that).
    std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(1) })
}

/// Wiring a repository to the broker: reading what a repo's remotes point at, and pointing one at
/// `cermet::`.
///
/// The shape is git's own — a remote URL with a transport scheme git resolves to a remote helper by
/// name. It is what `git remote -v` shows, what `git remote set-url` sets, and what git blesses for
/// exactly this purpose. The alternative (a global `url.cermet::github/.insteadOf` line) is
/// recognized here but never written: it rewrites EVERY github URL on the box, is invisible in
/// `git remote -v`, and ranks unpredictably against a user's own aliases.
///
/// Everything here shells out to the user's own git. Cermet is authorization and receipt; the repo's
/// configuration belongs to git, and git already has a command for it.
pub mod wiring {
    use std::path::Path;

    /// Every URL spelling of a github remote a user might have in `.git/config`.
    pub const GITHUB_SPELLINGS: &[&str] = &[
        "https://github.com/",
        "http://github.com/",
        "ssh://git@github.com/",
        "git@github.com:",
    ];

    /// One remote as git reports it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Remote {
        pub name: String,
        pub url: String,
    }

    impl Remote {
        /// Does this remote already reach the broker?
        pub fn is_brokered(&self) -> bool {
            self.url.starts_with("cermet::")
        }

        /// The `cermet::github/<owner>/<name>` URL this remote should carry, if it is a github one.
        pub fn brokered_url(&self) -> Option<String> {
            let path = GITHUB_SPELLINGS
                .iter()
                .find_map(|spelling| self.url.strip_prefix(spelling))?;
            let path = path.trim_end_matches('/').trim_end_matches(".git");
            (!path.is_empty()).then(|| format!("cermet::github/{path}"))
        }
    }

    /// Ask git for the repository's remotes. `None` when the answer is not ours to have — not a
    /// repository, or no git on PATH. (`git remote -v` rather than a config read precisely BECAUSE
    /// it fails outside a work tree: "no remotes here" and "not a repository" are different answers.)
    pub fn remotes(cwd: &Path) -> Option<Vec<Remote>> {
        let listed = ask(cwd, &["remote", "-v"])?;
        let mut remotes: Vec<Remote> = Vec::new();
        for line in listed.lines() {
            let Some((name, rest)) = line.split_once('\t') else {
                continue;
            };
            let url = rest.split_whitespace().next().unwrap_or_default();
            if url.is_empty() || remotes.iter().any(|r| r.name == name) {
                continue;
            }
            remotes.push(Remote {
                name: name.to_string(),
                url: url.to_string(),
            });
        }
        Some(remotes)
    }

    /// Is the documented `url.cermet::github/.insteadOf` line in force here? Recognized so a user
    /// who wired their box that way is not told they are unwired.
    pub fn insteadof_configured(cwd: &Path) -> bool {
        ask(
            cwd,
            &[
                "config",
                "--get-regexp",
                r"^url\.cermet::github/\.insteadof$",
            ],
        )
        .is_some_and(|listed| !listed.trim().is_empty())
    }

    /// Point one remote at the broker: `git remote set-url <name> <url>`.
    pub fn set_url(cwd: &Path, remote: &str, url: &str) -> Result<(), String> {
        let out = std::process::Command::new("git")
            .args(["remote", "set-url", remote, url])
            .current_dir(cwd)
            .output()
            .map_err(|e| format!("cannot run git: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    /// A read-only question for the user's git; `None` for any failure, because the absence of an
    /// answer is not evidence of anything.
    fn ask(cwd: &Path, question: &[&str]) -> Option<String> {
        let out = std::process::Command::new("git")
            .args(question)
            .current_dir(cwd)
            .output()
            .ok()?;
        // `config --get-regexp` exits 1 with no output when nothing matches, which is an answer.
        if !out.status.success() && !out.stderr.is_empty() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_github_remote_maps_onto_its_brokered_url_and_others_do_not() {
        let brokered = |url: &str| {
            wiring::Remote {
                name: "origin".into(),
                url: url.into(),
            }
            .brokered_url()
        };
        for spelling in [
            "https://github.com/acme/website.git",
            "http://github.com/acme/website",
            "ssh://git@github.com/acme/website.git",
            "git@github.com:acme/website.git",
        ] {
            assert_eq!(
                brokered(spelling).as_deref(),
                Some("cermet::github/acme/website"),
                "{spelling}"
            );
        }
        // Not github, and already brokered, are both left alone.
        assert_eq!(brokered("https://gitlab.com/acme/website.git"), None);
        assert_eq!(brokered("cermet::github/acme/website"), None);
        assert!(wiring::Remote {
            name: "origin".into(),
            url: "cermet::github/acme/website".into(),
        }
        .is_brokered());
    }

    #[test]
    fn the_request_is_a_well_formed_git_daemon_pkt_line() {
        let raw = request_pkt_line("git-upload-pack", "github/acme/website");
        let text = String::from_utf8(raw.clone()).unwrap();
        let declared = usize::from_str_radix(&text[..4], 16).unwrap();
        assert_eq!(declared, raw.len(), "the length covers the whole packet");
        assert_eq!(
            &text[4..],
            "git-upload-pack /github/acme/website\0host=cermet\0"
        );
    }
}
