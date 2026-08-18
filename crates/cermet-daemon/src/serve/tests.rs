use super::connection::{agent_peer_admitted, derive_principal_id, ConnSlot};
use super::respond::{write_error_with_effect, write_requested, write_session, DeadlineWriter};
use super::socket::bind_socket;
use super::*;
use cermet_ipc::codec::read_response_frame;
use serde_json::Value;
use std::io::Cursor;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Single-operator gate fixtures.
const TEST_OPERATOR_UID: u32 = 501;
const TEST_OTHER_UID: u32 = 1001;

/// The hello reply advertises THIS daemon's build id, on the same seam that advertises its
/// features. It is the only thing a long-lived client can compare itself against.
#[test]
fn the_session_reply_advertises_this_daemons_build() {
    let mut framed = Vec::new();
    write_session(&mut framed, "sess_1").unwrap();
    let response: Value = read_response_frame(&mut Cursor::new(framed)).unwrap();

    assert_eq!(response["kind"], "session");
    assert_eq!(response["session_id"], "sess_1");
    assert_eq!(response["build"], cermet_ipc::BUILD_ID);
}

#[test]
fn daemon_requested_projection_preserves_hint_and_drops_grant_id() {
    let hint = "to allow: cermet rules allow 'stripe.support@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa where amount <= 50000'";
    let outcome = serde_json::json!({
        "request_id": "rq-m2",
        "decision": "deny",
        "reason": "outside rule",
        "hint": hint,
        "authority_kind": "sentence",
        "grant_id": "grant-must-not-cross",
    })
    .to_string();
    let mut framed = Vec::new();

    write_requested(&mut framed, &outcome).unwrap();
    let response: Value = read_response_frame(&mut Cursor::new(framed)).unwrap();

    assert_eq!(response["kind"], "requested");
    assert_eq!(response["hint"], hint);
    assert_eq!(response["authority_kind"], "sentence");
    assert!(response.get("grant_id").is_none());
    assert!(response.get("authority_fingerprint").is_none());
}

#[test]
fn moneypath_daemon_error_projection_carries_only_the_safe_effect_handle() {
    let mut framed = Vec::new();
    write_error_with_effect(
        &mut framed,
        "unable to execute",
        Some("effect_broker"),
        Some(cermet_core::types::EffectOutcome::Ambiguous),
    )
    .unwrap();
    let response: Value = read_response_frame(&mut Cursor::new(framed)).unwrap();
    assert_eq!(response["kind"], "error");
    assert_eq!(response["reason"], "unable to execute");
    assert_eq!(response["effect_id"], "effect_broker");
    assert_eq!(response["effect_outcome"], "ambiguous");
    assert!(response.get("idempotency_key").is_none());
}

#[test]
fn derive_principal_id_is_uid_prefixed() {
    assert_eq!(derive_principal_id(1001), "uid:1001");
    assert_eq!(derive_principal_id(0), "uid:0");
}

#[test]
fn agent_peer_admitted_admits_only_the_operator_uid() {
    assert!(
        agent_peer_admitted(Some(TEST_OPERATOR_UID), TEST_OPERATOR_UID),
        "the operator's own uid is admitted"
    );
}

#[test]
fn agent_peer_admitted_refuses_a_foreign_uid() {
    assert!(
        !agent_peer_admitted(Some(TEST_OPERATOR_UID), TEST_OTHER_UID),
        "any uid other than the operator is refused"
    );
}

#[test]
fn agent_peer_admitted_refuses_the_daemon_uid_when_it_is_not_the_operator() {
    // The gate does not special-case the daemon: a daemon uid distinct from the operator is
    // refused exactly like any other foreign uid (only same-uid dev overlaps).
    let daemon_uid = TEST_OTHER_UID;
    assert!(
        !agent_peer_admitted(Some(TEST_OPERATOR_UID), daemon_uid),
        "the daemon's own uid is refused unless it equals the operator uid"
    );
}

#[test]
fn agent_peer_admitted_refuses_everyone_when_operator_is_unresolved() {
    // Fail closed: an unresolved (None) operator uid admits NO ONE — never fall open.
    assert!(!agent_peer_admitted(None, TEST_OPERATOR_UID));
    assert!(!agent_peer_admitted(None, TEST_OTHER_UID));
    assert!(!agent_peer_admitted(None, 0));
}

#[test]
fn conn_slots_are_bounded_and_reusable() {
    let active = Arc::new(AtomicUsize::new(0));
    let s1 = ConnSlot::try_acquire(&active, 2).expect("slot 1");
    let _s2 = ConnSlot::try_acquire(&active, 2).expect("slot 2");
    assert_eq!(active.load(Ordering::Acquire), 2, "two slots held");
    assert!(
        ConnSlot::try_acquire(&active, 2).is_none(),
        "at the cap, the next acquire is refused"
    );
    assert_eq!(
        active.load(Ordering::Acquire),
        2,
        "a refused acquire does not leak a slot"
    );
    drop(s1);
    assert_eq!(
        active.load(Ordering::Acquire),
        1,
        "dropping a slot releases it"
    );
    let _s3 = ConnSlot::try_acquire(&active, 2).expect("a freed slot is reusable");
    assert_eq!(active.load(Ordering::Acquire), 2);
}

#[test]
fn bind_sockets_is_fail_closed_if_either_fails() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    let (a, c) = bind_sockets(run).expect("both sockets bind");
    drop((a, c));

    std::fs::remove_file(run.join("ctl.sock")).ok();
    std::fs::create_dir(run.join("ctl.sock")).unwrap();
    assert!(
        bind_sockets(run).is_err(),
        "if EITHER socket cannot bind, the daemon must fail closed before serving either"
    );
    assert!(
        !run.join("agent.sock").exists(),
        "a fail-closed bind_sockets cleans up the agent.sock it created"
    );
}

#[test]
fn bind_sockets_separate_dirs_places_each_socket_in_its_own_dir_at_its_mode() {
    // agent.sock binds in the AGENTS dir at the chosen mode (0660 in service), and ctl.sock binds
    // in the CTL dir at 0660. The two live in DIFFERENT dirs so they can inherit disjoint setgid
    // groups.
    use std::os::unix::fs::PermissionsExt;
    let base = tempfile::tempdir().unwrap();
    let agent_dir = base.path().join("agents");
    let ctl_dir = base.path().join("approvers");
    std::fs::create_dir(&agent_dir).unwrap();
    std::fs::create_dir(&ctl_dir).unwrap();

    let (a, c) =
        bind_sockets_separate_dirs(&agent_dir, 0o660, &ctl_dir, None).expect("both sockets bind");
    drop((a, c));

    let agent_path = agent_dir.join("agent.sock");
    let ctl_path = ctl_dir.join("ctl.sock");
    assert!(agent_path.exists(), "agent.sock lands in the agents dir");
    assert!(ctl_path.exists(), "ctl.sock lands in the ctl dir");
    assert!(
        !ctl_dir.join("agent.sock").exists() && !agent_dir.join("ctl.sock").exists(),
        "neither socket leaks into the other dir"
    );
    let agent_mode = std::fs::symlink_metadata(&agent_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let ctl_mode = std::fs::symlink_metadata(&ctl_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(agent_mode, 0o660, "agent.sock binds at the requested 0660");
    assert_eq!(ctl_mode, 0o660, "ctl.sock binds at 0660");
}

#[test]
fn bind_sockets_separate_dirs_is_fail_closed_and_cleans_the_agent_socket() {
    // If the ctl bind fails, the already-bound agent.sock (in the SEPARATE dir) must be removed
    // so a half-bound surface never starts, even across two dirs.
    let base = tempfile::tempdir().unwrap();
    let agent_dir = base.path().join("agents");
    let ctl_dir = base.path().join("approvers");
    std::fs::create_dir(&agent_dir).unwrap();
    std::fs::create_dir(&ctl_dir).unwrap();
    // Plant a directory at ctl.sock's path so the ctl bind fails.
    std::fs::create_dir(ctl_dir.join("ctl.sock")).unwrap();

    assert!(
        bind_sockets_separate_dirs(&agent_dir, 0o660, &ctl_dir, None).is_err(),
        "a failed ctl bind must fail closed before serving either socket"
    );
    assert!(
        !agent_dir.join("agent.sock").exists(),
        "the agent.sock created in the separate agents dir is cleaned up on fail-closed"
    );
}

#[test]
fn clean_stale_socket_pathnames_removes_only_unix_sockets() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    let agent = run.join("agent.sock");
    let listener = std::os::unix::net::UnixListener::bind(&agent).expect("bind stale agent socket");
    drop(listener);
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o660)).unwrap();

    clean_stale_socket_pathnames(run, run).expect("stale socket pathnames are removed");
    assert!(
        !agent.exists(),
        "the stale agent.sock pathname is gone before doctor runs"
    );

    std::fs::write(run.join("ctl.sock"), b"not a socket").unwrap();
    let err = clean_stale_socket_pathnames(run, run)
        .expect_err("a non-socket reserved pathname must fail closed");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
}

#[test]
fn bind_socket_sets_the_requested_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (_l, path) = bind_socket(dir.path(), "x.sock", 0o660).expect("bind");
    let mode = std::fs::symlink_metadata(&path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o660,
        "the shared bind helper sets the requested socket mode"
    );
}

#[test]
fn assert_socket_mode_requires_socket_type_and_exact_mode() {
    let dir = tempfile::tempdir().unwrap();
    let (_l, path) = bind_socket(dir.path(), "x.sock", 0o660).expect("bind");
    assert_socket_mode(&path, 0o660).expect("fresh socket at expected mode passes");
    assert!(
        assert_socket_mode(&path, 0o600).is_err(),
        "wrong socket mode must fail closed"
    );

    let regular = dir.path().join("regular.sock");
    std::fs::write(&regular, b"not a socket").unwrap();
    assert!(
        assert_socket_mode(&regular, 0o600).is_err(),
        "a non-socket at a socket path must fail closed"
    );
}

/// A supplementary gid the test process belongs to that is NOT its primary gid, or `None` when
/// the process has no second group (e.g. minimal CI). Used to PROVE the daemon does NOT chgrp:
/// passing this gid must leave the socket in the process's primary gid, never this one.
/// Sourced via `id -G` (portable across macOS/Linux; `nix::getgroups` is Apple-unavailable).
fn a_member_gid() -> Option<u32> {
    let primary = nix::unistd::getgid().as_raw();
    let out = std::process::Command::new("id").arg("-G").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|s| s.parse::<u32>().ok())
        .find(|&g| g != primary)
}

// The daemon NEVER chgrps the socket. Passing an "approvers gid" must be a no-op — the socket
// lands in the bind process's primary gid (in production: inherited from the setgid runtime dir),
// NOT the passed gid. A daemon-side chgrp would EPERM (the daemon is not in cermet-approvers), so
// it must not be attempted.
#[test]
fn bind_sockets_with_group_does_not_chgrp_ctl() {
    use std::os::unix::fs::MetadataExt;
    let Some(gid) = a_member_gid() else {
        eprintln!("skipping: process has no supplementary gid to distinguish from primary");
        return;
    };
    let primary = nix::unistd::getgid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    let (a, c) = bind_sockets_with_group(run, Some(gid)).expect("both sockets bind");
    drop((a, c));

    let ctl_gid = std::fs::symlink_metadata(run.join("ctl.sock"))
        .unwrap()
        .gid();
    assert_ne!(
            ctl_gid, gid,
            "the daemon must NOT chgrp ctl.sock to the passed gid (§0.5 D1: group via setgid inheritance)"
        );
    assert_eq!(
            ctl_gid, primary,
            "ctl.sock keeps the bind process's primary gid (in prod: the setgid-inherited approvers gid)"
        );
}

#[test]
fn bind_sockets_with_group_leaves_agent_mode_intact() {
    use std::os::unix::fs::PermissionsExt;
    let gid = a_member_gid();
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    let (a, c) = bind_sockets_with_group(run, gid).expect("both sockets bind");
    drop((a, c));

    let agent_mode = std::fs::symlink_metadata(run.join("agent.sock"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        agent_mode, 0o600,
        "agent.sock is bound 0600 owner-only, not world-reachable"
    );
    let ctl_mode = std::fs::symlink_metadata(run.join("ctl.sock"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        ctl_mode, 0o660,
        "ctl.sock keeps its 0660 mode (group-reachable, not world)"
    );
}

#[test]
fn bind_sockets_with_no_group_binds_normally() {
    // None gid binds normally and leaves ownership untouched — same as before.
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path();
    let (a, c) = bind_sockets_with_group(run, None).expect("both sockets bind without a gid");
    drop((a, c));
    assert!(run.join("agent.sock").exists() && run.join("ctl.sock").exists());
}

#[test]
fn bind_socket_in_group_does_not_chgrp() {
    use std::os::unix::fs::MetadataExt;
    let Some(gid) = a_member_gid() else {
        eprintln!("skipping: process has no supplementary gid to distinguish from primary");
        return;
    };
    let primary = nix::unistd::getgid().as_raw();
    let dir = tempfile::tempdir().unwrap();
    let (_l, path) = bind_socket_in_group(dir.path(), "g.sock", 0o660, Some(gid)).expect("bind");
    let socket_gid = std::fs::symlink_metadata(&path).unwrap().gid();
    assert_ne!(
        socket_gid, gid,
        "bind_socket_in_group must NOT chgrp to the passed gid (§0.5 D1: setgid inheritance)"
    );
    assert_eq!(
        socket_gid, primary,
        "the socket keeps the bind process's primary gid"
    );
}

#[test]
fn bind_socket_in_group_sets_only_the_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (_l, path) = bind_socket_in_group(dir.path(), "m.sock", 0o660, Some(12345)).expect("bind");
    let mode = std::fs::symlink_metadata(&path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o660,
        "bind_socket_in_group sets the requested mode even with a gid passed"
    );
}

// ---- resolve_group_gid — ONE-SHOT group-NAME → gid resolution ----

#[test]
fn resolve_group_gid_resolves_a_real_group_by_name() {
    // Round-trip a group that definitely exists: take the test process's primary gid, look up
    // its NAME, then resolve that name back through the resolver and require the same gid. This
    // proves the getgrnam_r-backed lookup works on whatever OS the suite runs (macOS + Linux).
    let primary = nix::unistd::getgid();
    let grp = crate::groupdb::by_gid(primary.as_raw())
        .expect("by_gid")
        .expect("the primary gid must name a group");
    let got = resolve_group_gid(&grp.name).expect("resolves a real group name");
    assert_eq!(
        got,
        primary.as_raw(),
        "the resolved gid matches the named group"
    );
}

#[test]
fn resolve_group_gid_errors_on_a_missing_group() {
    // A group name that does not exist must FAIL CLOSED (an error), never silently yield a 0/None
    // gid that would later be misread as "root group" or "no ACL".
    let bogus = "cermet-agents-does-not-exist-zzzzzzzz";
    assert!(
        resolve_group_gid(bogus).is_err(),
        "an unknown group name must surface an error (fail closed), not a default gid"
    );
}

// ---- assert_socket_group — POST-bind inheritance assertion ----

#[test]
fn assert_socket_group_passes_when_the_socket_carries_the_expected_gid() {
    use std::os::unix::fs::MetadataExt;
    let Some(gid) = a_member_gid() else {
        eprintln!("skipping: process has no supplementary gid to chgrp to");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let (_l, path) = bind_socket(dir.path(), "ctl.sock", 0o660).expect("bind");
    // Simulate the setgid-inheritance result: the bound socket carries the approvers gid.
    std::os::unix::fs::chown(&path, None, Some(gid)).unwrap();
    assert_eq!(
        std::fs::symlink_metadata(&path).unwrap().gid(),
        gid,
        "precondition"
    );
    assert_socket_group(&path, gid)
        .expect("a socket whose group owner equals the expected gid passes");
}

#[test]
fn assert_socket_group_fails_when_the_socket_group_differs() {
    // The bind did NOT inherit the approvers gid (e.g. the runtime dir was not setgid): the
    // post-bind assertion must FAIL CLOSED so the daemon never serves a ctl.sock the cross-uid
    // approvers cannot reach.
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let (_l, path) = bind_socket(dir.path(), "ctl.sock", 0o660).expect("bind");
    let actual = std::fs::symlink_metadata(&path).unwrap().gid();
    // Pick a gid that is definitely NOT the socket's actual group.
    let wrong = actual.wrapping_add(1);
    assert!(
        assert_socket_group(&path, wrong).is_err(),
        "a socket whose group owner != the expected approvers gid must fail closed"
    );
}

#[test]
fn assert_socket_group_errors_on_a_missing_socket() {
    // Defensive: asserting a path that does not exist surfaces an error, never a false pass.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("ctl.sock");
    assert!(
        assert_socket_group(&missing, 0).is_err(),
        "a missing socket path must error (fail closed), never silently pass"
    );
}

#[test]
fn deadline_writer_aborts_a_stalled_write_within_the_budget() {
    use std::io::Write;
    // A socketpair whose peer is NEVER read: once the kernel buffers fill, writes block.
    let (tx, _rx) = StdUnixStream::pair().expect("socketpair");
    let budget = Duration::from_millis(300);
    let start = Instant::now();
    let mut out = DeadlineWriter::new(&tx, start + budget);
    // Far larger than any socket buffer, so write_all must block on the unread peer.
    let big = vec![0u8; 64 * 1024 * 1024];
    let res = out.write_all(&big);
    let elapsed = start.elapsed();

    assert!(
        res.is_err(),
        "a stalled write must abort, not block forever"
    );
    assert!(
            elapsed >= Duration::from_millis(100),
            "it should wait for the budget, not bail instantly (would drop honest fast writes): {elapsed:?}"
        );
    assert!(
        elapsed < Duration::from_secs(5),
        "it must abort near the budget, NOT hang to the 300s idle window: {elapsed:?}"
    );
    drop(_rx);
}

#[test]
fn deadline_writer_completes_a_promptly_drained_write() {
    use std::io::{Read, Write};
    let (tx, mut rx) = StdUnixStream::pair().expect("socketpair");
    let reader = std::thread::spawn(move || {
        let mut buf = vec![0u8; 256 * 1024];
        let mut total = 0usize;
        while total < 1024 * 1024 {
            match rx.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => break,
            }
        }
        total
    });
    let mut out = DeadlineWriter::new(&tx, Instant::now() + Duration::from_secs(30));
    out.write_all(&vec![7u8; 1024 * 1024])
        .expect("a promptly-drained write completes well within the budget");
    drop(tx);
    assert_eq!(
        reader.join().unwrap(),
        1024 * 1024,
        "the reader received the whole payload"
    );
}
