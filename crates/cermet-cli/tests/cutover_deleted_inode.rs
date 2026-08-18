//! THE ONE-BINARY CUTOVER REGRESSION, over REAL processes and a REAL `/proc` walk.
//!
//! Before the merge, a running daemon and a running MCP bridge had different executables, so
//! `/proc/<pid>/exe` told you which was which. Under one target both resolve to `.../cermet`, and
//! after an atomic replacement both read `.../cermet (deleted)`. A detector that took the role from
//! that resolved basename would file the stale DAEMON — the process holding the vault open, whose
//! remedy is to stop it — as a harmless keyless client whose remedy is "restart your agent session".
//!
//! So: launch two long-lived processes from one file under two different `argv[0]`s, atomically
//! replace that file, and drive the real probe. What the classifier must NOT be able to use is the
//! only thing they now have in common.
#![cfg(not(target_os = "macos"))]

use std::process::{Command, Stdio};

use cermet_cli::cutover::{
    running_processes, stale_processes, ProcessRole, RunningProcess, StaleReason,
};

/// A process that stays alive on a piped stdin nobody writes to. The bytes are irrelevant — the
/// detector reads `/proc`, never the ELF — so any long-lived program stands in for the one binary.
/// `/bin/sh` (dash) is used because it ignores `argv[0]`, which is exactly the variable under test.
fn spawn_blocking_on_stdin(program: &std::path::Path, argv0: &str) -> std::process::Child {
    use std::os::unix::process::CommandExt;
    Command::new(program)
        .arg0(argv0)
        .args(["-c", "read line"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the fixture process")
}

#[test]
fn a_stale_daemon_and_a_stale_client_on_one_deleted_target_are_told_apart() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path();
    let target = bin.join("cermet");
    // One regular target plus the alias layout an install publishes.
    std::fs::copy("/bin/sh", &target).expect("stage a long-lived program as the target");
    std::os::unix::fs::symlink("cermet", bin.join("cermetd")).unwrap();

    // The daemon, launched through the `cermetd` alias the way systemd does…
    let mut daemon = spawn_blocking_on_stdin(
        &bin.join("cermetd"),
        &format!("{}", bin.join("cermetd").display()),
    );
    // …and an agent session's MCP bridge, launched under its own name from the same file.
    let mut bridge = spawn_blocking_on_stdin(&target, &format!("{}", target.display()));

    // Atomically replace the published target, exactly as `publish_multicall` does. Both processes
    // keep running the object they already mapped, which is now unlinked.
    let replacement = bin.join(".cermet.stage");
    std::fs::write(&replacement, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::rename(&replacement, &target).expect("atomic replace");

    let processes: Vec<RunningProcess> = running_processes()
        .expect("the /proc walk answers")
        .into_iter()
        .filter(|process| process.pid == daemon.id() || process.pid == bridge.id())
        .collect();
    assert_eq!(processes.len(), 2, "both fixture processes were seen");

    // The premise of the regression: the resolved executable no longer distinguishes them.
    for process in &processes {
        assert!(
            process.deleted,
            "the replaced target reads as deleted: {process:?}"
        );
        assert_eq!(
            process.exe,
            target.display().to_string(),
            "both roles resolve to the SAME path — this is what a basename check would see"
        );
    }

    let installed = [bin.to_str().unwrap()];
    let published = std::fs::metadata(&target)
        .map(|m| {
            use std::os::unix::fs::MetadataExt;
            (m.dev(), m.ino())
        })
        .ok();
    let found = stale_processes(&processes, &[], &installed, published, std::process::id());
    assert_eq!(found.len(), 2, "both are stale: {found:?}");

    let daemon_row = found
        .iter()
        .find(|row| row.pid == daemon.id())
        .expect("the daemon is reported");
    let bridge_row = found
        .iter()
        .find(|row| row.pid == bridge.id())
        .expect("the bridge is reported");
    assert_eq!(
        daemon_row.role,
        ProcessRole::Daemon,
        "the survivor launched as `cermetd` is an ENGINE, whatever its path resolves to"
    );
    assert_eq!(
        bridge_row.role,
        ProcessRole::KeylessClient,
        "and the one launched as `cermet` is a keyless client"
    );
    assert_eq!(daemon_row.reason, StaleReason::Deleted);
    assert_eq!(bridge_row.reason, StaleReason::Deleted);
    assert!(
        !cermet_cli::cutover::is_keyless_client(daemon_row),
        "a stale daemon must never collect the keyless-client remedy"
    );
    assert!(cermet_cli::cutover::is_keyless_client(bridge_row));

    // And the receipt says the right thing about each: stop the engine, restart the session.
    let report = cermet_cli::cutover::CutoverReport {
        processes: found,
        ..Default::default()
    };
    let text = cermet_cli::cutover::setup_receipt_lines(&report).expect("a dirty box reports");
    assert!(
        text.contains(&format!("sudo kill {}", daemon.id())),
        "the engine is named in the stop line: {text}"
    );
    assert!(
        !text.contains(&format!("kill {}", bridge.id())),
        "the live session's bridge is NOT: {text}"
    );
    assert!(text.contains("restart those agent sessions"), "{text}");

    let _ = daemon.kill();
    let _ = bridge.kill();
    let _ = daemon.wait();
    let _ = bridge.wait();
}
