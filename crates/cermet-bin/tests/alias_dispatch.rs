//! The installed names, driven through the REAL executable.
//!
//! ONE-BINARY: `cermetd` and `git-remote-cermet` are root-created relative symlinks to the one
//! regular `cermet` target, so "which role am I" is decided by the invocation name — and that
//! decision has to hold both through a real symlink (what the service manager and git actually
//! exec) and through a forged `argv[0]` (what `exec -a` gives any caller). Both must route
//! IDENTICALLY, because neither confers any authority: the process keeps its caller's uid either
//! way and meets the service-uid asserts and peercred gates as itself.
//!
//! It also carries what `cermet-daemon/tests/cli_surface.rs` used to prove: `cermetd --help` /
//! `-h` / `--version` short-circuit before ANY daemon machinery (home lock, keychain, vault), so a
//! curious operator's first `cermetd --help` on a box with no secrets service prints usage rather
//! than a keychain error.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TARGET: &str = env!("CARGO_BIN_EXE_cermet");

/// ONE publication-shaped directory for the whole test binary: one regular target, two relative
/// symlinks to it — the exact layout `publish_multicall` and the packages lay down.
///
/// Two deliberate choices here, both learned the hard way:
///
/// * **Hard link, not copy.** A debug `cermet` is ~170 MB. Copying that into `TMPDIR` puts bulk in
///   a tmpfs — this box caps `/tmp` at 8 GB with no swap, and the copy really did fail `ENOSPC`.
///   A hard link is a regular, non-symlink file at zero bytes, which is exactly the property under
///   test, and it also removes the `ETXTBSY` race the previous copy had: nothing is ever opened for
///   writing, so a sibling thread's fork cannot inherit a write fd to the file about to be exec'd.
/// * **Staged beside the binary, not in `TMPDIR`.** A hard link cannot cross filesystems, and the
///   profile directory is the one place guaranteed to be on the same filesystem as the target.
///
/// Still built exactly once, behind a `OnceLock`: one staging directory, not one per test.
fn published() -> &'static Path {
    static PUBLISHED: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    PUBLISHED
        .get_or_init(|| {
            let profile_dir = Path::new(TARGET)
                .parent()
                .expect("the built binary lives in target/<profile>");
            let dir = tempfile::Builder::new()
                .prefix(".alias-dispatch-")
                .tempdir_in(profile_dir)
                .expect("a staging prefix beside the built binary");
            std::fs::hard_link(TARGET, dir.path().join("cermet"))
                .expect("stage the one regular target");
            for alias in ["cermetd", "git-remote-cermet", "cermet-agent"] {
                std::os::unix::fs::symlink("cermet", dir.path().join(alias))
                    .expect("stage the alias");
            }
            dir
        })
        .path()
}

/// The one regular target in the staged prefix.
fn target() -> PathBuf {
    published().join("cermet")
}

/// Run a staged invocation with the operator's own state directory pointed somewhere unreachable.
/// The CLI role journals what it prints under `$XDG_STATE_HOME` (default `$HOME/.local/state`), and
/// a test must never append to the developer's own journal; an unwritable path simply journals
/// nothing, which is what "best effort" means.
fn output(command: &mut Command) -> (bool, String, String) {
    let out: Output = command
        .env("HOME", "/nonexistent-home-for-the-alias-dispatch-test")
        .env_remove("XDG_STATE_HOME")
        .output()
        .expect("the cermet binary runs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_cermetd_alias_prints_usage_without_touching_custody_machinery() {
    let dir = published();
    for arg in ["--help", "-h", "help"] {
        let (ok, stdout, stderr) = output(Command::new(dir.join("cermetd")).arg(arg));
        assert!(ok, "`cermetd {arg}` must exit 0; stderr: {stderr}");
        assert!(
            stdout.contains("cermetd") && stdout.contains("cermet"),
            "usage names the daemon and points at the operator CLI: {stdout}"
        );
        assert!(
            !stderr.contains("keychain") && !stderr.contains("master-key"),
            "help must not reach custody machinery: {stderr}"
        );
        assert!(
            !stdout.lines().any(|line| line.starts_with("    ")),
            "usage lines must not carry source-literal indentation: {stdout}"
        );
    }
}

#[test]
fn the_cermetd_alias_prints_the_build_version() {
    let dir = published();
    for arg in ["--version", "-V"] {
        let (ok, stdout, stderr) = output(Command::new(dir.join("cermetd")).arg(arg));
        assert!(ok, "`cermetd {arg}` must exit 0; stderr: {stderr}");
        assert!(
            stdout.contains(&cermet_ipc_build_id()),
            "version output carries this build's id: {stdout}"
        );
    }
}

/// The build id the binary itself prints, read back from the CLI role so the test does not link the
/// wire crate just to restate a constant.
fn cermet_ipc_build_id() -> String {
    let (_, stdout, _) = output(Command::new(TARGET).arg("--version"));
    stdout.trim().trim_start_matches("cermet ").to_string()
}

#[test]
fn an_unknown_daemon_argument_is_a_usage_error_not_a_silent_ignore() {
    let dir = published();
    for argument in ["mcp", "--socket", "serve"] {
        let out = Command::new(dir.join("cermetd"))
            .arg(argument)
            .env("HOME", "/nonexistent-home-for-the-alias-dispatch-test")
            .output()
            .expect("run the cermetd alias");
        assert_eq!(
            out.status.code(),
            Some(2),
            "`cermetd {argument}` must exit 2, not boot the daemon"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(argument), "the refusal names it: {stderr}");
    }
}

#[test]
fn a_real_symlink_and_a_forged_argv0_route_identically() {
    let dir = published();
    let target = target();

    // Through the symlink git and systemd actually exec…
    let (_, via_link, _) = output(Command::new(dir.join("cermetd")).arg("--version"));
    // …and through a forged argv[0] on the regular target, which any caller can do with `exec -a`.
    let (_, via_arg0, _) = output(Command::new(&target).arg0("cermetd").arg("--version"));
    assert_eq!(
        via_link, via_arg0,
        "the name is the dispatch; how it was supplied is not a distinction"
    );
    assert!(via_link.starts_with("cermetd "), "{via_link}");

    // And the same target under its own name is the operator CLI, not the daemon.
    let (_, cli, _) = output(Command::new(&target).arg("--version"));
    assert!(cli.starts_with("cermet "), "{cli}");
    assert_ne!(cli, via_link);
}

#[test]
fn an_unpublished_invocation_name_refuses_and_names_what_is_accepted() {
    let dir = published();
    // A name this build does not publish — including a retired one — never falls back to a role.
    let out = Command::new(dir.join("cermet-agent"))
        .arg("--version")
        .env("HOME", "/nonexistent-home-for-the-alias-dispatch-test")
        .env_remove("XDG_STATE_HOME")
        .output()
        .expect("run the unpublished name");
    assert_eq!(out.status.code(), Some(2), "an unknown name must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    for name in ["cermet-agent", "cermetd", "git-remote-cermet"] {
        assert!(stderr.contains(name), "the refusal is legible: {stderr}");
    }
}

#[test]
fn the_git_update_hook_argument_wins_before_the_name_through_every_alias() {
    // The daemon writes a hook stub that execs its own program path; through the `cermetd` symlink
    // that path RESOLVES to `.../cermet`, so a name-first router would send the hook client into
    // the operator CLI. It must reach the hook client from EITHER name — and, with no attested
    // stream environment, refuse there (never a decision, never CLI usage output).
    let dir = published();
    for name in ["cermet", "cermetd"] {
        let out = Command::new(dir.join(name))
            .args(["git-update-hook", "refs/heads/main", "aaa", "bbb"])
            .env_remove("CERMET_HOOK_SOCKET")
            .env_remove("CERMET_HOOK_TOKEN")
            .output()
            .expect("run the hook client");
        assert!(!out.status.success(), "the hook client must fail closed");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("outside an attested stream"),
            "`{name} git-update-hook` reached the hook client, not a role: {stderr}"
        );
    }
    // A malformed argument count still reaches the hook client, and is refused there.
    let out = Command::new(dir.join("cermetd"))
        .args(["git-update-hook", "refs/heads/main"])
        .output()
        .expect("run the hook client");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("expects <ref> <old> <new>"),
        "a malformed hook invocation is refused by the hook client itself"
    );
}

/// As-built deviation 2, which had no test: a non-UTF-8 ARGUMENT (not name).
///
/// Pre-merge, the CLI read `std::env::args()`, which PANICS on one — the caller got a Rust panic
/// message and an abort. The router decodes the tail once and refuses with a message instead. It
/// must not panic, and it must not lossily mangle the argument into something that parses as a
/// different request.
#[test]
fn a_non_utf8_argument_is_refused_rather_than_panicking_or_being_mangled() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let dir = published();
    // A lone 0xff byte is valid in a Unix argument and is not valid UTF-8.
    let bad = OsString::from_vec(vec![b'-', b'-', b's', b'o', b'c', b'k', b'e', b't', 0xff]);
    let out = Command::new(dir.join("cermet"))
        .arg(bad)
        .arg("log")
        .env("HOME", "/nonexistent-home-for-the-alias-dispatch-test")
        .env_remove("XDG_STATE_HOME")
        .output()
        .expect("the binary runs rather than aborting");
    assert_eq!(
        out.status.code(),
        Some(2),
        "a non-UTF-8 argument is a usage refusal, not a panic (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not valid UTF-8"),
        "the refusal says what was wrong: {stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "and it is a refusal, not a panic: {stderr}"
    );
}
