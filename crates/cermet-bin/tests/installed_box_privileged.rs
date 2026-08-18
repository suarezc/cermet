//! The ONE-BINARY acceptance legs that need a REAL installed box, and therefore a privileged gate.
//!
//! Every test here is `#[ignore]`d. They are not skipped because they are flaky or slow — they are
//! skipped because an unprivileged `cargo nextest run --workspace` has no `/etc/sudoers.d`, no
//! `cermet-agent` account, no systemd unit, and no root-owned install prefix to assert against, and
//! a test that quietly passes in the absence of the thing it checks is worse than no test.
//!
//! THE PRIVILEGED GATE THAT RUNS THEM: a maintainer acceptance pass on a real installed box —
//! install the built package as root, then run these legs.
//!
//! **TWO INVOCATIONS, and they are not interchangeable.**
//!
//! 1. The legs that need root — they start the daemon as another uid, or run `cermet setup`:
//!
//! ```text
//! sudo env "PATH=$PATH" "HOME=$HOME" cargo nextest run -p cermet-bin --run-ignored all \
//!     -E 'test(installed_box_) and not test(sudoers)'
//! ```
//!
//! (`env` because root's PATH has no cargo and sudo-rs has no `-E`; HOME so the rustup shim
//! resolves the pinned toolchain.)
//!
//! 2. The sudoers leg, which must run as the **approver** account — the human uid the installed rule
//!    names — and must NOT run as root:
//!
//! ```text
//! cargo nextest run -p cermet-bin --run-ignored all installed_box_sudoers
//! ```
//!
//! Why the split is not a preference: the rule under test is
//! `<approver> ALL=(cermet-agent:cermet-agents) NOPASSWD:NOSETENV: <one exact command>`, and root is
//! permitted *everything* by sudo before any rule is consulted. Run as root, every `sudo -l` probe
//! answers yes, so the DENIAL assertions — the entire point of that leg — cannot fail, and a
//! later edit that inverted them would pass vacuously. `require_approver()` therefore refuses to
//! proceed as root, so a wrong invocation fails with the right command rather than a confusing
//! result. (The two read-only legs — publication shape and the running service's uid/argv0/inode —
//! only stat files and read `/proc`, so they are correct under either invocation and ride with the
//! root run.)
//!
//! They are the written-down form of what that gate must prove.

use std::path::Path;
use std::process::Command;

/// The install prefix this platform publishes into. Mirrors `cermet_cli::setup::INSTALL_BIN_DIR`,
/// which is crate-private; a drift here shows up as an immediate "nothing installed" skip.
#[cfg(target_os = "macos")]
const INSTALL_BIN_DIR: &str = "/opt/cermet/bin";
#[cfg(not(target_os = "macos"))]
const INSTALL_BIN_DIR: &str = "/usr/local/bin";

const AGENT_USER: &str = "cermet-agent";

fn installed(name: &str) -> std::path::PathBuf {
    Path::new(INSTALL_BIN_DIR).join(name)
}

fn require_installed() {
    assert!(
        installed("cermet").is_file(),
        "this test needs a real install at {INSTALL_BIN_DIR}; run it under the privileged gate"
    );
}

/// The effective uid, asked of the platform rather than linked for.
fn effective_uid() -> u32 {
    let out = Command::new("id")
        .arg("-u")
        .output()
        .expect("`id -u` answers on every supported platform");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("`id -u` prints a uid")
}

/// Refuse to run the sudoers leg as root, loudly and with the right command.
///
/// sudo permits root everything before consulting a single rule, so under root every `sudo -l` probe
/// answers yes and no denial assertion below can fail. A leg that cannot fail is not a check — see
/// the module doc.
fn require_approver() {
    assert_ne!(
        effective_uid(),
        0,
        "the sudoers leg must run as the APPROVER account, not root: root is permitted everything \
         before any rule is consulted, so every denial assertion here would pass vacuously. Re-run \
         WITHOUT sudo:\n    \
         cargo nextest run -p cermet-bin --run-ignored all installed_box_sudoers"
    );
}

/// §"Setup publication" on the real box: ONE regular root-owned `0755` file, two relative symlinks,
/// nothing else carrying a cermet name.
#[test]
#[ignore = "needs a real installed box; privileged gate"]
fn installed_box_publishes_one_regular_target_and_two_relative_aliases() {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    require_installed();

    let target = installed("cermet");
    let metadata = std::fs::symlink_metadata(&target).expect("stat the target");
    assert!(
        !metadata.file_type().is_symlink() && metadata.is_file(),
        "{} must be the one REGULAR target",
        target.display()
    );
    assert_eq!(metadata.uid(), 0, "the target is root-owned");
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o755);

    for alias in ["cermetd", "git-remote-cermet"] {
        let path = installed(alias);
        let link = std::fs::symlink_metadata(&path).expect("stat the alias");
        assert!(
            link.file_type().is_symlink(),
            "{} must be a symlink, not a byte copy",
            path.display()
        );
        assert_eq!(
            std::fs::read_link(&path).unwrap(),
            Path::new("cermet"),
            "{} must be the exact RELATIVE name",
            path.display()
        );
        let resolved = std::fs::metadata(&path).expect("the alias resolves");
        assert_eq!(
            (resolved.dev(), resolved.ino()),
            (metadata.dev(), metadata.ino()),
            "{} must dereference to the one target's inode",
            path.display()
        );
    }
}

/// §"The daemon UID assertion is strong in service mode": invoking the merged `cermetd` alias as the
/// installed AGENT uid, with `CERMET_SERVICE_MODE=1` and the installed root-managed config, refuses
/// before key load, broker construction, state-DB creation, or any socket bind — exactly as the
/// separately-built `cermetd` did. This is the regression the design asks for by name.
#[test]
#[ignore = "needs the cermet-agent account and the installed config; privileged gate"]
fn installed_box_cermetd_alias_as_the_agent_uid_refuses_before_key_load() {
    require_installed();
    let home = tempfile::tempdir().expect("an agent-owned scratch home");
    // The daemon requires CERMET_HOME to be a usable owner-only directory for ITS uid before
    // anything else; hand the scratch home to the agent account so the refusal this test observes
    // is the service-identity one, not the unusable-home one.
    let agent_uid: u32 = {
        let out = Command::new("id")
            .args(["-u", AGENT_USER])
            .output()
            .expect("id -u resolves the agent account");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("the agent account has a numeric uid")
    };
    std::os::unix::fs::chown(home.path(), Some(agent_uid), None)
        .expect("root hands the scratch home to the agent uid");
    // The env rides INSIDE the command line: sudo's env_reset strips variables set on the sudo
    // process itself, silently turning this into a different test.
    let output = Command::new("sudo")
        .args(["-n", "-u", AGENT_USER, "env", "CERMET_SERVICE_MODE=1"])
        .arg(format!("CERMET_HOME={}", home.path().display()))
        .arg(installed("cermetd"))
        .output()
        .expect("run the cermetd alias as the agent uid");
    assert!(
        !output.status.success(),
        "the agent uid must not be able to start the installed service"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing") || stderr.contains("does not match the running uid"),
        "the refusal is the service-identity one, not an incidental failure: {stderr}"
    );
    // Nothing was opened: the refusal must precede key load and broker construction.
    for artifact in ["vault.db", "state.db", "audit.db", "master.key"] {
        assert!(
            !home.path().join(artifact).exists(),
            "{artifact} was created before the refusal"
        );
    }
}

/// §Sudoers: the installed rule grants the approver ONE exact command — the canonical regular
/// target with the frozen MCP argv — and nothing adjacent.
///
/// Three layers, weakest environment-dependence first:
/// 1. The rule AS SUDO PARSED IT: `sudo -l` lists this approver's rules through sudo's own parser
///    (the rule file itself is root-only), and exactly one entry names the `cermet-agent` runas,
///    carrying exactly the frozen argv. Measurable on every box.
/// 2. The allowed probe: the registered bridge invocation is permitted.
/// 3. Denial probes for argument variations. These ask sudo about the approver's WHOLE rule set, so
///    any broader passwordless grant (e.g. a temporary admin `NOPASSWD: ALL` on a maintainer
///    box) answers yes to everything and makes them unmeasurable — they are skipped, loudly,
///    when such a grant is detected; layer 1 still pins the rule's exactness.
///
/// NAME pinning is deliberately absent: modern sudo (sudo-rs, stock sudo ≥1.9.10) canonicalizes the
/// command path before matching, so a symlink alias reaching the same inode matches the rule — and
/// invoking an alias merely selects a dispatch role that refuses the frozen argv
/// (`cermetd --socket … mcp` exits 2: "takes no flags"). The rule's security content is the
/// ARGUMENT freeze, not the spelling of the path.
///
/// MUST run as the approver account, never root. See `require_approver` and the module doc.
#[test]
#[ignore = "needs the installed sudoers policy; run as the APPROVER uid, NOT root — see the module doc"]
fn installed_box_sudoers_admits_only_the_canonical_mcp_invocation() {
    require_installed();
    require_approver();
    let agent_sock = if cfg!(target_os = "macos") {
        "/var/cermetd-agents/agent.sock"
    } else {
        "/run/cermetd-agents/agent.sock"
    };
    let target = installed("cermet").display().to_string();
    let canonical = format!("{target} --socket {agent_sock} mcp");

    // Layer 1: the rule as sudo parsed it.
    let listing = Command::new("sudo")
        .args(["-l", "-n"])
        .output()
        .expect("spawn sudo -l");
    assert!(
        listing.status.success(),
        "`sudo -l -n` must answer for the approver (the rule is NOPASSWD, so listing needs no \
         password): {}",
        String::from_utf8_lossy(&listing.stderr)
    );
    let listing = String::from_utf8_lossy(&listing.stdout).into_owned();
    let runas_prefix = format!("({AGENT_USER}");
    let entries: Vec<&str> = listing
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(&runas_prefix))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "exactly one rule names the {AGENT_USER} runas:\n{listing}"
    );
    assert!(
        entries[0].contains("NOPASSWD:") && entries[0].ends_with(&canonical),
        "the one {AGENT_USER} rule is NOPASSWD for exactly `{canonical}`: {}",
        entries[0]
    );

    // `sudo -l <argv>` answers "may I", without running anything.
    let allowed = |argv: &[&str]| -> bool {
        Command::new("sudo")
            .args(["-l", "-n", "-u", AGENT_USER])
            .args(argv)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    };

    // Layer 2: the registered bridge invocation.
    assert!(
        allowed(&[&target, "--socket", agent_sock, "mcp"]),
        "the registered bridge invocation must be permitted, or the agent plane cannot launch"
    );

    // Layer 3, guarded: a command NO cermet rule could admit. If it is permitted, some broader
    // grant covers this approver and the denial probes below would measure that grant, not our rule.
    if allowed(&["/usr/bin/false"]) {
        eprintln!(
            "SKIP denial probes: a broader passwordless grant covers this approver (e.g. a \
             temporary admin NOPASSWD rule); the {AGENT_USER} rule's exactness is pinned by the \
             `sudo -l` text assertion above"
        );
        return;
    }

    let denied: [(&str, Vec<&str>); 4] = [
        // An added, omitted, or reordered argument.
        (
            "an added argument",
            vec![&target, "--socket", agent_sock, "mcp", "install"],
        ),
        ("an omitted argument", vec![&target, "mcp"]),
        (
            "reordered arguments",
            vec![&target, "mcp", "--socket", agent_sock],
        ),
        // Another socket path.
        (
            "another socket path",
            vec![&target, "--socket", "/tmp/agent.sock", "mcp"],
        ),
    ];
    for (what, argv) in denied {
        assert!(
            !allowed(&argv),
            "sudo must NOT permit {what} ({argv:?}) — the rule is one exact command"
        );
    }
}

/// §"systemd and launchd through the alias": the manager-launched daemon runs as the SERVICE uid and
/// carries `cermetd` as its `argv[0]`, while the executable it mapped is the one regular target.
/// Linux-only twice over: the probe reads `/proc`, and `parse_proc_cmdline` is compiled out of the
/// macOS library — the first full workspace build on a Mac failed HERE, at compile time.
#[cfg(not(target_os = "macos"))]
#[test]
#[ignore = "needs a running service; privileged gate"]
fn installed_box_service_runs_as_the_service_uid_under_the_cermetd_name() {
    require_installed();
    let pid = service_main_pid().expect("the service manager holds a running daemon");
    let argv0 = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|bytes| cermet_cli::cutover::parse_proc_cmdline(&bytes))
        .expect("read the daemon's argv")
        .first()
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        Path::new(&argv0).file_name().and_then(|n| n.to_str()),
        Some("cermetd"),
        "the manager launches the daemon under its role name: {argv0}"
    );

    use std::os::unix::fs::MetadataExt;
    let mapped = std::fs::metadata(format!("/proc/{pid}/exe")).expect("the mapped executable");
    let target = std::fs::metadata(installed("cermet")).expect("the published target");
    assert_eq!(
        (mapped.dev(), mapped.ino()),
        (target.dev(), target.ino()),
        "a running service must be on the CURRENTLY published object — otherwise setup's restart \
         did not take, and the cutover report should be saying so"
    );

    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read status");
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .expect("a Uid line");
    assert!(
        !uid_line.split_whitespace().skip(1).any(|uid| uid == "0"),
        "the daemon never runs as root: {uid_line}"
    );
}

#[cfg(not(target_os = "macos"))]
fn service_main_pid() -> Option<u32> {
    let out = Command::new("systemctl")
        .args(["show", "-p", "MainPID", "--value", "cermetd.service"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid != 0)
}

#[cfg(target_os = "macos")]
fn service_main_pid() -> Option<u32> {
    None
}

/// §"Existing-install migration", service half: setup stops a RUNNING daemon before publishing and
/// brings it back afterwards, on the new object. The file-layout half of this is proved
/// unprivileged in `cermet_cli::setup::tests`; only the stop/start belongs here.
#[test]
#[ignore = "mutates installed system state (stops and starts the service); privileged gate"]
fn installed_box_setup_restarts_a_running_daemon_onto_the_new_object() {
    require_installed();
    let before = service_main_pid().expect("a running daemon to migrate");
    let status = Command::new("sudo")
        .args(["-n", installed("cermet").to_str().unwrap(), "setup"])
        .status()
        .expect("run setup");
    assert!(status.success(), "setup must converge");
    let after = service_main_pid().expect("the daemon is running again after setup");

    use std::os::unix::fs::MetadataExt;
    let mapped = std::fs::metadata(format!("/proc/{after}/exe")).expect("the mapped executable");
    let target = std::fs::metadata(installed("cermet")).expect("the published target");
    assert_eq!(
        (mapped.dev(), mapped.ino()),
        (target.dev(), target.ino()),
        "the restarted daemon runs the object setup just published"
    );
    let _ = before;
}
