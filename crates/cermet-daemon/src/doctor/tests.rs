use super::*;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

// Daemon uid + a disjoint approver uid + a disjoint agent uid used across tests, so the pairwise
// collapses (approver==daemon, agent==daemon, agent==approver) never accidentally fire unless a
// test means them to. They also have to be disjoint from the uid RUNNING the tests — the
// membership fixtures below refuse to run on a colliding uid — so they sit well above both
// platforms' interactive ranges (macOS hands the first human 501).
const DAEMON_UID: u32 = 61001;
const APPROVER_UID: u32 = 61002;
const AGENT_UID: u32 = 61003;

fn ok_runtime() -> (tempfile::TempDir, std::path::PathBuf) {
    let home = tempdir().unwrap();
    let runtime = home.path().join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o2711)).unwrap();
    (home, runtime)
}

/// A supplementary gid the test process belongs to that is NOT its primary gid, or `None` when
/// the process has no second group (minimal CI). chgrp to a member group is permitted for a
/// non-root file owner, so unprivileged tests can exercise the approvers-gid ACL. Sourced via
/// `id -G` (portable across macOS/Linux; `nix::getgroups` is Apple-unavailable).
fn a_member_gid() -> Option<u32> {
    let primary = nix::unistd::getgid().as_raw();
    let out = std::process::Command::new("id").arg("-G").output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter_map(|s| s.parse::<u32>().ok())
        .find(|&g| g != primary)
}

fn find<'a>(r: &'a DoctorReport, name: &str) -> &'a DoctorCheck {
    r.checks
        .iter()
        .find(|c| c.name == name)
        .expect("check present")
}

#[test]
fn dev_mode_still_warns_and_serves() {
    let (home, runtime) = ok_runtime();

    // service_mode = false: the same-uid collapse stays a loud warning, and we keep serving
    // so the single-uid dev daemon survives.
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        false,
    );
    assert!(report.serving, "dev mode: warn loudly, keep serving");
    let uid = find(&report, "uid_boundary");
    assert_eq!(
        uid.status, "warn",
        "the same-uid collapse is a loud warning in dev mode"
    );
    assert!(uid.detail.contains(&DAEMON_UID.to_string()) && uid.detail.contains("NO OS boundary"));
    assert!(report.warnings().any(|c| c.name == "uid_boundary"));
    assert_eq!(find(&report, "runtime_dir").status, "ok");
}

#[test]
fn service_mode_with_dedicated_uid_serves() {
    let (home, runtime) = ok_runtime();

    // service_mode = true with a dedicated daemon uid disjoint from the approver: the uid
    // boundary is IN FORCE (the daemon runs as its own uid; config.validate_runtime asserts
    // service_uid == getuid() != approver_uid upstream). The uid_boundary check reports ok and
    // the daemon SERVES.
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
    );
    let uid = find(&report, "uid_boundary");
    assert_eq!(
        uid.status, "ok",
        "in service mode the dedicated-uid boundary is in force"
    );
    assert!(
        uid.detail.contains(&DAEMON_UID.to_string()) && uid.detail.contains("boundary is in force")
    );
    assert!(
        report.serving,
        "service mode with a correct dedicated-uid setup must SERVE"
    );
}

#[test]
fn service_mode_without_sentence_rules_path_warns_in_doctor_report() {
    let (home, runtime) = ok_runtime();
    let report = run_with_sentence_authority(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
        Some(cermet_ipc::custody::CustodyProfile::SystemdHost),
        false,
        None,
    );
    let authority = find(&report, "sentence_authority");
    assert_eq!(authority.status, "warn", "{authority:?}");
    assert!(
        authority.detail.contains("sentence_rules_path")
            && authority.detail.contains("fails closed"),
        "the ctl DoctorReport must carry the same actionable warning as boot: {authority:?}"
    );
    assert!(
        report.serving,
        "an unset sentence path warns but does not refuse policy-only use"
    );
}

#[test]
fn refuses_to_serve_on_approver_collapse_in_service_mode() {
    let (home, runtime) = ok_runtime();

    // approver_uid == daemon_uid: the human-only approval split collapses onto the daemon.
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        DAEMON_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
    );
    let approver = find(&report, "approver_uid");
    assert_eq!(
        approver.status, "fail",
        "approver==daemon is a hard refuse in service mode"
    );
    assert!(
        approver.detail.contains("approve itself") || approver.detail.contains("collapses"),
        "the detail must explain the self-approval collapse"
    );
    assert!(
        !report.serving,
        "service mode: approver collapse must refuse to serve"
    );
}

#[test]
fn approver_collapse_only_warns_in_dev_mode() {
    let (home, runtime) = ok_runtime();

    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        DAEMON_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        false,
    );
    let approver = find(&report, "approver_uid");
    assert_eq!(
        approver.status, "warn",
        "dev mode: approver collapse is a loud warning"
    );
    assert!(
        report.serving,
        "dev mode keeps serving despite the approver collapse warning"
    );
}

#[test]
fn disjoint_approver_uid_is_ok() {
    let (home, runtime) = ok_runtime();

    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
    );
    let approver = find(&report, "approver_uid");
    assert_eq!(approver.status, "ok", "a disjoint approver uid passes");
    assert!(
        approver.detail.contains(&APPROVER_UID.to_string())
            && approver.detail.contains(&DAEMON_UID.to_string())
    );
}

#[test]
fn refuses_to_serve_on_loose_db_in_service_mode() {
    let (home, runtime) = ok_runtime();
    std::fs::write(home.path().join("vault.db"), b"x").unwrap();
    std::fs::set_permissions(
        home.path().join("vault.db"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
    );
    let vault = find(&report, "vault.db");
    assert_eq!(
        vault.status, "fail",
        "service mode: 0644 vault.db is a hard refuse"
    );
    assert!(
        !report.serving,
        "service mode: a loose DB must refuse to serve"
    );
}

#[test]
fn refuses_to_serve_on_loose_wal_sidecar_in_service_mode() {
    // The -wal sidecar holds the same pages, so a loose -wal must refuse even when the main DB
    // is owner-only.
    let (home, runtime) = ok_runtime();
    std::fs::write(home.path().join("vault.db"), b"x").unwrap();
    std::fs::set_permissions(
        home.path().join("vault.db"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(home.path().join("vault.db-wal"), b"x").unwrap();
    std::fs::set_permissions(
        home.path().join("vault.db-wal"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
    );
    let main = find(&report, "vault.db");
    assert_eq!(main.status, "ok", "the main DB is owner-only");
    let wal = find(&report, "vault.db-wal");
    assert_eq!(
        wal.status, "fail",
        "service mode: a loose -wal sidecar is a hard refuse"
    );
    assert!(
        !report.serving,
        "service mode: a loose -wal must refuse to serve"
    );
}

#[test]
fn loose_wal_only_warns_in_dev_mode() {
    let (home, runtime) = ok_runtime();
    std::fs::write(home.path().join("vault.db-shm"), b"x").unwrap();
    std::fs::set_permissions(
        home.path().join("vault.db-shm"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        false,
    );
    let shm = find(&report, "vault.db-shm");
    assert_eq!(
        shm.status, "warn",
        "dev mode: a loose -shm sidecar is a warning"
    );
    assert!(
        report.serving,
        "dev mode keeps serving despite the loose sidecar"
    );
}

#[test]
fn flags_a_loose_db_file() {
    let (home, runtime) = ok_runtime();

    std::fs::write(home.path().join("vault.db"), b"x").unwrap();
    std::fs::set_permissions(
        home.path().join("vault.db"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::write(home.path().join("state.db"), b"x").unwrap();
    std::fs::set_permissions(
        home.path().join("state.db"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    // dev mode: a loose DB is still a warn and we keep serving.
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        false,
    );
    let vault = find(&report, "vault.db");
    assert_eq!(
        vault.status, "warn",
        "0644 vault.db is group/world-readable"
    );
    let state = find(&report, "state.db");
    assert_eq!(state.status, "ok", "0600 state.db is owner-only");
    assert!(
        report.serving,
        "dev mode keeps serving despite the loose DB warning"
    );
}

/// Lay down a correct flipped runtime: a 2711 runtime dir group-owned by the approvers gid, with
/// ctl.sock inheriting that group and bound 0660. Returns the home + runtime + approvers gid.
fn correct_flipped_runtime(gid: u32) -> (tempfile::TempDir, std::path::PathBuf) {
    let (home, runtime) = ok_runtime();
    // setgid + approvers group on the runtime dir.
    std::os::unix::fs::chown(&runtime, None, Some(gid)).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o2711)).unwrap();
    // ctl.sock present at 0660, group-owned by the approvers gid (the setgid inheritance result).
    let ctl = runtime.join("ctl.sock");
    std::fs::write(&ctl, b"").unwrap();
    std::os::unix::fs::chown(&ctl, None, Some(gid)).unwrap();
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o660)).unwrap();
    // sanity: the bound socket really carries the approvers gid.
    assert_eq!(std::fs::symlink_metadata(&ctl).unwrap().gid(), gid);
    (home, runtime)
}

#[test]
fn correct_setgid_runtime_dir_and_ctl_sock_pass_the_acl_checks() {
    // A fully correct service-mode runtime — 2711/approvers dir + a 0660 group-inheriting
    // ctl.sock + owner-only DBs + a disjoint approver + the dedicated-uid boundary — has NO
    // failing checks and SERVES: uid_boundary reports ok for a dedicated service uid.
    let Some(gid) = a_member_gid() else {
        eprintln!("skipping: process has no supplementary gid to chgrp to");
        return;
    };
    let (home, runtime) = correct_flipped_runtime(gid);

    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        Some(gid),
        None,
        true,
    );
    assert_eq!(
        find(&report, "ctl_group").status,
        "ok",
        "{:?}",
        find(&report, "ctl_group")
    );
    assert_eq!(find(&report, "ctl.sock").status, "ok");
    assert_eq!(find(&report, "approver_uid").status, "ok");
    assert_eq!(find(&report, "vault.db").status, "ok");
    assert_eq!(find(&report, "uid_boundary").status, "ok");
    let fails: Vec<&str> = report
        .checks
        .iter()
        .filter(|c| c.status == "fail")
        .map(|c| c.name.as_str())
        .collect();
    assert!(
        fails.is_empty(),
        "a correct service-mode runtime has no failing checks, got: {fails:?}"
    );
    assert!(
        report.serving,
        "a fully correct service-mode runtime must SERVE"
    );
}

#[test]
fn correct_runtime_serves_in_dev_mode() {
    // The same correct runtime in dev mode (warn-and-serve) serves: my ACL/db/approver checks are
    // `ok` and the same-uid placeholder is a mere warning.
    let Some(gid) = a_member_gid() else {
        eprintln!("skipping: process has no supplementary gid to chgrp to");
        return;
    };
    let (home, runtime) = correct_flipped_runtime(gid);

    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        Some(gid),
        None,
        false,
    );
    assert_eq!(
        find(&report, "ctl_group").status,
        "ok",
        "{:?}",
        find(&report, "ctl_group")
    );
    assert_eq!(find(&report, "approver_uid").status, "ok");
    assert!(
        report.serving,
        "a correct 2711/approvers runtime dir + 0660 ctl.sock serves in dev mode"
    );
}

#[test]
fn refuses_to_serve_when_ctl_group_is_not_approvers_in_service_mode() {
    // ctl.sock group owner is NOT the approvers gid (and the runtime dir is not setgid-to-it):
    // the cross-uid ACL is broken, so service mode refuses.
    let Some(gid) = a_member_gid() else {
        eprintln!("skipping: process has no supplementary gid to chgrp to");
        return;
    };
    let (home, runtime) = ok_runtime(); // 2711 but group = primary gid, not `gid`
    let ctl = runtime.join("ctl.sock");
    std::fs::write(&ctl, b"").unwrap();
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o660)).unwrap();

    // We claim the approvers gid is `gid`, but neither the dir nor ctl.sock carry it.
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        Some(gid),
        None,
        true,
    );
    let g = find(&report, "ctl_group");
    assert_eq!(
        g.status, "fail",
        "a broken approvers ACL is a hard refuse in service mode"
    );
    assert!(
        !report.serving,
        "service mode: a broken ctl.sock approvers ACL must refuse"
    );
}

#[test]
fn ctl_group_drift_only_warns_in_dev_mode() {
    let Some(gid) = a_member_gid() else {
        eprintln!("skipping: process has no supplementary gid to chgrp to");
        return;
    };
    let (home, runtime) = ok_runtime();
    let ctl = runtime.join("ctl.sock");
    std::fs::write(&ctl, b"").unwrap();
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o660)).unwrap();

    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        Some(gid),
        None,
        false,
    );
    let g = find(&report, "ctl_group");
    assert_eq!(g.status, "warn", "dev mode: a ctl group drift is a warning");
    assert!(
        report.serving,
        "dev mode keeps serving despite the ctl group drift"
    );
}

#[test]
fn no_ctl_group_check_when_no_approvers_gid() {
    // dev/embedded mode has no approvers group: the ACL check is absent entirely.
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        false,
    );
    assert!(
        report.checks.iter().all(|c| c.name != "ctl_group"),
        "no approvers gid ⇒ no ctl_group ACL check"
    );
}

// ---- the ctl_group dir check must require bit-exact 2711, not just setgid + gid ----

#[test]
fn refuses_to_serve_when_runtime_dir_is_setgid_but_not_bit_exact_2711_in_service_mode() {
    // A runtime dir that is setgid + group-owned by the approvers gid but with a LOOSER mode
    // (2755 = world-listable) must be rejected: testing the setgid bit + gid alone is not enough,
    // because a world-listable runtime dir leaks the socket inventory to every local uid even
    // though inheritance would still hold.
    let Some(gid) = a_member_gid() else {
        eprintln!("skipping: process has no supplementary gid to chgrp to");
        return;
    };
    let (home, runtime) = ok_runtime();
    std::os::unix::fs::chown(&runtime, None, Some(gid)).unwrap();
    // 2755: setgid + approvers group, but world-listable — NOT the locked 2711.
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o2755)).unwrap();
    let ctl = runtime.join("ctl.sock");
    std::fs::write(&ctl, b"").unwrap();
    std::os::unix::fs::chown(&ctl, None, Some(gid)).unwrap();
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o660)).unwrap();

    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        Some(gid),
        None,
        true,
    );
    let g = find(&report, "ctl_group");
    assert_eq!(
        g.status, "fail",
        "a setgid+approvers dir that is NOT bit-exact 2711 (here 2755) must hard-refuse in \
             service mode: {g:?}"
    );
    assert!(
        !report.serving,
        "service mode: a non-2711 runtime dir must refuse to serve"
    );
}

// ---- a loose ctl.sock MODE must REFUSE (not just warn) in service mode ----

#[test]
fn refuses_to_serve_on_loose_ctl_sock_mode_in_service_mode() {
    // A ctl.sock at a mode other than 0660 (here 0666, world-reachable) must be a hard refuse in
    // service mode, not a mere warning: a world-reachable ctl.sock lets any local uid drive the
    // operator control plane.
    let (home, runtime) = ok_runtime();
    let ctl = runtime.join("ctl.sock");
    std::fs::write(&ctl, b"").unwrap();
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o666)).unwrap();

    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
    );
    let ctl_check = find(&report, "ctl.sock");
    assert_eq!(
        ctl_check.status, "fail",
        "service mode: a 0666 ctl.sock must hard-refuse (only 0660 is acceptable): {ctl_check:?}"
    );
    assert!(
        !report.serving,
        "service mode: a loose ctl.sock mode must refuse to serve"
    );
}

#[test]
fn loose_ctl_sock_mode_only_warns_in_dev_mode() {
    // The same loose ctl.sock in dev/embedded mode stays a warning and keeps serving —
    // the refuse tier is gated on service mode.
    let (home, runtime) = ok_runtime();
    let ctl = runtime.join("ctl.sock");
    std::fs::write(&ctl, b"").unwrap();
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o666)).unwrap();

    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        false,
    );
    let ctl_check = find(&report, "ctl.sock");
    assert_eq!(
        ctl_check.status, "warn",
        "dev mode: a loose ctl.sock mode is a warning"
    );
    assert!(
        report.serving,
        "dev mode keeps serving despite the loose ctl.sock mode warning"
    );
}

#[test]
fn agent_sock_expected_mode_is_0660_in_service_and_0666_in_dev() {
    // The peercred agent-uid gate — NOT the file mode — is the auth boundary.
    // The expected mode is topology-dependent: 0660 in the separate cermet-agents dir (service),
    // 0666 in the shared dir (dev). Each must PASS in its own mode, serving holds.
    let (home, runtime) = ok_runtime();
    let agent = runtime.join("agent.sock");
    let ctl = runtime.join("ctl.sock");
    std::fs::write(&ctl, b"").unwrap();
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o660)).unwrap();

    // Service mode: 0660 is the intended mode.
    std::fs::write(&agent, b"").unwrap();
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o660)).unwrap();
    let svc = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(AGENT_UID),
        None,
        None,
        true,
    );
    assert_eq!(
        find(&svc, "agent.sock").status,
        "ok",
        "0660 is the intended service-mode agent.sock mode: {:?}",
        find(&svc, "agent.sock")
    );
    assert!(
        svc.serving,
        "a 0660 agent.sock must not drop serving in service mode"
    );

    // Dev mode: 0666 is the intended mode.
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o666)).unwrap();
    let dev = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(AGENT_UID),
        None,
        None,
        false,
    );
    assert_eq!(
        find(&dev, "agent.sock").status,
        "ok",
        "0666 is the intended dev-mode agent.sock mode: {:?}",
        find(&dev, "agent.sock")
    );
    assert!(dev.serving);
}

#[test]
fn agent_sock_wrong_mode_refuses_in_service_but_warns_in_dev() {
    // In service mode the expected mode is 0660; a 0666 (world-reachable) drift is a hard REFUSE.
    // In dev the expected mode is 0666; a 0660 drift only warns.
    let (home, runtime) = ok_runtime();
    let agent = runtime.join("agent.sock");
    std::fs::write(&agent, b"").unwrap();
    let ctl = runtime.join("ctl.sock");
    std::fs::write(&ctl, b"").unwrap();
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o660)).unwrap();

    // Service mode + 0666 (wrong): the socket is the sole fail in an otherwise-ok setup → refuse.
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o666)).unwrap();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(AGENT_UID),
        None,
        None,
        true,
    );
    assert_eq!(
        find(&report, "agent.sock").status,
        "fail",
        "service mode: a 0666 agent.sock (expected 0660) is refused: {:?}",
        find(&report, "agent.sock")
    );
    assert!(
        !report.serving,
        "a wrong-mode agent.sock must drop serving in service mode"
    );

    // DEV mode + 0660 (not the 0666 dev mode): only WARNS + keeps serving.
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o660)).unwrap();
    let dev = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(AGENT_UID),
        None,
        None,
        false,
    );
    assert_eq!(
        find(&dev, "agent.sock").status,
        "warn",
        "dev mode: a non-0666 agent.sock only warns"
    );
    assert!(
        dev.serving,
        "dev mode keeps serving despite the agent.sock warning"
    );
}

// ---- single-operator gate: doctor surfaces an unresolved / collapsed operator gate ----

#[test]
fn refuses_to_serve_when_operator_gate_is_unresolved_in_service_mode() {
    // Fail closed: an UNRESOLVED (None) operator uid means agent.sock refuses ALL connections, so
    // in service mode doctor hard-refuses rather than serve a dead-but-not-obviously-so surface.
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        None,
        None,
        None,
        true,
    );
    let g = find(&report, "operator_gate");
    assert_eq!(
        g.status, "fail",
        "service mode: an unresolved operator gate is a hard refuse: {g:?}"
    );
    assert!(g.detail.contains("UNRESOLVED") || g.detail.contains("refuses ALL"));
    assert!(
        !report.serving,
        "an unresolved operator gate must refuse to serve"
    );
}

#[test]
fn unresolved_operator_gate_only_warns_in_dev_mode() {
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        None,
        None,
        None,
        false,
    );
    let g = find(&report, "operator_gate");
    assert_eq!(
        g.status, "warn",
        "dev mode: an unresolved operator gate is a warning"
    );
    assert!(
        report.serving,
        "dev mode keeps serving despite the operator-gate warning"
    );
}

#[test]
fn refuses_to_serve_when_operator_gate_equals_daemon_uid_in_service_mode() {
    // In service mode the operator uid must be DISJOINT from the daemon uid, else agent.sock would
    // admit the daemon's own uid.
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(DAEMON_UID),
        None,
        None,
        true,
    );
    let g = find(&report, "operator_gate");
    assert_eq!(
        g.status, "fail",
        "operator gate == daemon uid is a hard refuse in service mode: {g:?}"
    );
    assert!(!report.serving);
}

#[test]
fn operator_gate_equal_to_daemon_uid_only_warns_in_dev_mode() {
    // Dev/embedded: operator == agent == daemon is the expected same-uid state — a warn, serving.
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(DAEMON_UID),
        None,
        None,
        false,
    );
    let g = find(&report, "operator_gate");
    assert_eq!(
        g.status, "warn",
        "dev mode: operator == daemon is the same-uid warn"
    );
    assert!(report.serving);
}

#[test]
fn disjoint_operator_gate_is_ok() {
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
    );
    let g = find(&report, "operator_gate");
    assert_eq!(
        g.status, "ok",
        "a resolved operator uid disjoint from the daemon passes: {g:?}"
    );
    assert!(g.detail.contains(&APPROVER_UID.to_string()));
}

#[test]
fn stale_prebind_socket_pathnames_are_cleaned_before_doctor_gate() {
    // A Unix socket pathname persists after its listener exits. Without cleanup, an old daemon's
    // stale non-0600 agent.sock / non-0660 ctl.sock makes the PRE-bind startup doctor refuse
    // before the new daemon reaches bind_socket(), even though bind_socket() would replace them
    // with fresh 0600/0660 sockets.
    let (home, runtime) = ok_runtime();
    let agent = runtime.join("agent.sock");
    let ctl = runtime.join("ctl.sock");

    let a = std::os::unix::net::UnixListener::bind(&agent).unwrap();
    let c = std::os::unix::net::UnixListener::bind(&ctl).unwrap();
    drop((a, c));
    // Stale modes that both fail the service doctor: agent.sock 0666 (service expects 0660),
    // ctl.sock 0666 (expects 0660).
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o666)).unwrap();
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o666)).unwrap();

    let before = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
    );
    assert_eq!(
        find(&before, "agent.sock").status,
        "fail",
        "precondition: stale 0666 agent.sock fails service doctor (expects 0660)"
    );
    assert_eq!(
        find(&before, "ctl.sock").status,
        "fail",
        "precondition: stale 0666 ctl.sock fails service doctor"
    );
    assert!(
        !before.serving,
        "precondition: stale socket modes blocked startup"
    );

    crate::serve::clean_stale_socket_pathnames(&runtime, &runtime)
        .expect("stale Unix socket pathnames are safe to unlink before doctor");
    assert!(!agent.exists(), "stale agent.sock pathname removed");
    assert!(!ctl.exists(), "stale ctl.sock pathname removed");

    let after = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
    );
    assert_eq!(find(&after, "agent.sock").status, "ok");
    assert_eq!(find(&after, "ctl.sock").status, "ok");
    assert!(
        after.serving,
        "after stale socket cleanup, the pre-bind doctor gate no longer blocks the upgrade"
    );
}

// ---- the agent-uid pairwise collapse checks (agent==daemon, agent==approver) ----

#[test]
fn agent_equals_daemon_refuses_in_service_but_warns_in_dev() {
    // The agent uid must be disjoint from the daemon uid. Pass a disjoint operator gate uid (504)
    // so the operator_gate check does not ALSO fail — this isolates the agent_uid collapse check.
    let (home, runtime) = ok_runtime();
    let svc = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        DAEMON_UID,
        Some(504),
        None,
        None,
        true,
    );
    let a = find(&svc, "agent_uid");
    assert_eq!(
        a.status, "fail",
        "agent==daemon is a hard refuse in service mode: {a:?}"
    );
    assert!(a.detail.contains("collapses") || a.detail.contains("daemon"));
    assert!(
        !svc.serving,
        "service mode: agent==daemon must refuse to serve"
    );

    let dev = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        DAEMON_UID,
        Some(504),
        None,
        None,
        false,
    );
    assert_eq!(
        find(&dev, "agent_uid").status,
        "warn",
        "dev mode: agent==daemon is a loud warning"
    );
    assert!(
        dev.serving,
        "dev mode keeps serving despite the agent==daemon warning"
    );
}

#[test]
fn agent_equals_approver_refuses_in_service_but_warns_in_dev() {
    // The agent uid must be disjoint from the approver uid, else a compromised agent could
    // self-approve. agent_uid == APPROVER_UID trips the agent_approver check.
    let (home, runtime) = ok_runtime();
    let svc = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        APPROVER_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
    );
    let a = find(&svc, "agent_approver");
    assert_eq!(
        a.status, "fail",
        "agent==approver is a hard refuse in service mode: {a:?}"
    );
    assert!(a.detail.contains("approve") || a.detail.contains("planes"));
    assert!(
        !svc.serving,
        "service mode: agent==approver must refuse to serve"
    );

    let dev = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        APPROVER_UID,
        Some(APPROVER_UID),
        None,
        None,
        false,
    );
    assert_eq!(
        find(&dev, "agent_approver").status,
        "warn",
        "dev mode: agent==approver is a loud warning"
    );
    assert!(
        dev.serving,
        "dev mode keeps serving despite the agent==approver warning"
    );
}

#[test]
fn disjoint_agent_uid_passes_both_collapse_checks() {
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(AGENT_UID),
        None,
        None,
        true,
    );
    assert_eq!(
        find(&report, "agent_uid").status,
        "ok",
        "a disjoint agent uid passes"
    );
    assert_eq!(
        find(&report, "agent_approver").status,
        "ok",
        "an agent uid disjoint from the approver passes"
    );
    // uid_boundary now names three distinct uids in service mode.
    let boundary = find(&report, "uid_boundary");
    assert_eq!(boundary.status, "ok");
    assert!(
        boundary.detail.contains("three distinct uids")
            && boundary.detail.contains(&AGENT_UID.to_string()),
        "the uid_boundary wording names the three distinct uids: {boundary:?}"
    );
}

#[test]
fn uid_boundary_not_ok_when_a_collapse_check_fails_in_service_mode() {
    // Doctor must not narrate "three distinct uids … boundary in force" beside a FAILING
    // collapse check (contradictory security evidence). With agent_uid == daemon_uid the agent
    // collapse fails and serving=false, so uid_boundary must NOT be "ok" and must NOT claim the
    // boundary is in force — it is topology-aware (fail in service mode).
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        DAEMON_UID,
        Some(504),
        None,
        None,
        true,
    );
    // Precondition: a collapse check really is failing and the daemon refuses to serve.
    assert_eq!(
        find(&report, "agent_uid").status,
        "fail",
        "precondition: agent==daemon collapse"
    );
    assert!(
        !report.serving,
        "precondition: a failing collapse refuses to serve"
    );
    let boundary = find(&report, "uid_boundary");
    assert_ne!(
        boundary.status, "ok",
        "uid_boundary must not be ok while a collapse check fails: {boundary:?}"
    );
    assert_eq!(
        boundary.status, "fail",
        "in service mode a failing boundary is topology-aware (fail): {boundary:?}"
    );
    assert!(
        !boundary.detail.contains("in force"),
        "uid_boundary must not claim the boundary is in force during a collapse: {boundary:?}"
    );
}

#[test]
fn uid_boundary_not_ok_when_agent_uid_is_zero_in_service_mode() {
    // Zero-uid variant: agent_uid==0 fails the agent check, so uid_boundary must not report the
    // boundary as in force.
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        0,
        Some(504),
        None,
        None,
        true,
    );
    assert_eq!(
        find(&report, "agent_uid").status,
        "fail",
        "precondition: agent_uid==0 fails"
    );
    let boundary = find(&report, "uid_boundary");
    assert_eq!(boundary.status, "fail", "{boundary:?}");
    assert!(!boundary.detail.contains("in force"), "{boundary:?}");
    assert!(!report.serving);
}

#[test]
fn agent_uid_zero_refuses_in_service_even_with_distinct_daemon_and_approver() {
    // Doctor's contract is "matches the startup self-check", which refuses agent_uid==0
    // (config::validate_runtime). A pairwise-only check would PASS a zero agent uid when daemon
    // and approver are distinct and nonzero. Pass a disjoint operator gate uid (504) so the
    // operator_gate check does not ALSO fail — this isolates the agent_uid zero check.
    let (home, runtime) = ok_runtime();
    let svc = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        0,
        Some(504),
        None,
        None,
        true,
    );
    let a = find(&svc, "agent_uid");
    assert_eq!(
        a.status, "fail",
        "agent_uid 0 is a hard refuse in service mode: {a:?}"
    );
    assert!(
        a.detail.contains('0') && (a.detail.contains("root") || a.detail.contains("unset")),
        "the detail names the zero/root agent uid: {a:?}"
    );
    assert!(
        !svc.serving,
        "service mode: agent_uid 0 must refuse to serve"
    );

    // Dev/embedded: a zero agent uid is a loud warning (the same-uid root-dev edge), still serving.
    let dev = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        0,
        Some(504),
        None,
        None,
        false,
    );
    assert_eq!(
        find(&dev, "agent_uid").status,
        "warn",
        "dev mode: a zero agent uid is a loud warning"
    );
    assert!(dev.serving);
}

// ---- the cross-uid agents ACL on agent.sock ----

/// Lay down a correct flipped AGENT runtime: a 2711 dir group-owned by `gid`, with agent.sock
/// inheriting that group and bound 0660. Returns the home + separate ctl runtime + agent dir.
fn correct_agent_runtime(gid: u32) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let home = tempdir().unwrap();
    let ctl_dir = home.path().join("run");
    std::fs::create_dir_all(&ctl_dir).unwrap();
    std::fs::set_permissions(&ctl_dir, std::fs::Permissions::from_mode(0o2711)).unwrap();
    let agent_dir = home.path().join("run-agents");
    std::fs::create_dir_all(&agent_dir).unwrap();
    std::os::unix::fs::chown(&agent_dir, None, Some(gid)).unwrap();
    std::fs::set_permissions(&agent_dir, std::fs::Permissions::from_mode(0o2711)).unwrap();
    let agent = agent_dir.join("agent.sock");
    std::fs::write(&agent, b"").unwrap();
    std::os::unix::fs::chown(&agent, None, Some(gid)).unwrap();
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert_eq!(std::fs::symlink_metadata(&agent).unwrap().gid(), gid);
    (home, ctl_dir, agent_dir)
}

#[test]
fn correct_agents_dir_and_agent_sock_pass_the_agent_group_check() {
    let Some(gid) = a_member_gid() else {
        eprintln!("skipping: process has no supplementary gid to chgrp to");
        return;
    };
    let (home, ctl_dir, agent_dir) = correct_agent_runtime(gid);
    let report = run(
        home.path(),
        &ctl_dir,
        &agent_dir,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(AGENT_UID),
        None,
        Some(gid),
        true,
    );
    let g = find(&report, "agent_group");
    assert_eq!(
        g.status, "ok",
        "a correct 2711/cermet-agents dir + 0660 agent.sock passes: {g:?}"
    );
    assert_eq!(find(&report, "agent.sock").status, "ok");
}

#[test]
fn refuses_to_serve_when_agent_group_is_not_agents_in_service_mode() {
    // agent.sock group owner is NOT the agents gid (and the dir is not setgid-to-it): the cross-uid
    // agents ACL is broken, so service mode refuses.
    let Some(gid) = a_member_gid() else {
        eprintln!("skipping: process has no supplementary gid to chgrp to");
        return;
    };
    let (home, runtime) = ok_runtime(); // 2711 but group = primary gid, not `gid`
    let agent = runtime.join("agent.sock");
    std::fs::write(&agent, b"").unwrap();
    std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o660)).unwrap();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(AGENT_UID),
        None,
        Some(gid),
        true,
    );
    let g = find(&report, "agent_group");
    assert_eq!(
        g.status, "fail",
        "a broken agents ACL is a hard refuse in service mode: {g:?}"
    );
    assert!(
        !report.serving,
        "service mode: a broken agent.sock agents ACL must refuse"
    );
}

#[test]
fn no_agent_group_check_when_no_agents_gid() {
    // dev/embedded mode has no agents group: the agent_group ACL check is absent entirely.
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(AGENT_UID),
        None,
        None,
        false,
    );
    assert!(
        report.checks.iter().all(|c| c.name != "agent_group"),
        "no agents gid ⇒ no agent_group ACL check"
    );
}

// ---- doctor verifies the configured agent_uid is a member of cermet-agents ----

/// The primary gid recorded in the passwd DB for the test process's own uid (getpwuid), so the
/// membership check's primary-group branch fires. `None` if the uid does not resolve.
fn own_primary_gid(uid: u32) -> Option<u32> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.gid.as_raw())
}

#[test]
fn agent_group_membership_ok_when_agent_uid_is_a_member() {
    // A real uid whose PRIMARY group is the configured agents gid is a member — the check reports
    // ok. Use the test process's own uid + its passwd primary gid. FAIL LOUDLY (never silently
    // return-as-pass) where the fixture cannot run — a vacuous skip would let a check that never
    // reports "ok" pass.
    let uid = nix::unistd::getuid().as_raw();
    assert!(
        uid != 0 && uid != DAEMON_UID && uid != APPROVER_UID,
        "run the doctor unit tests as a normal non-root user whose uid is not a fixture uid (got \
             {uid}); a root/colliding uid cannot exercise the membership branch"
    );
    let gid = own_primary_gid(uid).unwrap_or_else(|| {
        panic!("NSS could not resolve the running uid {uid} to a passwd user — fixture cannot run")
    });
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        uid,
        Some(uid),
        None,
        Some(gid),
        true,
    );
    let m = find(&report, "agent_group_membership");
    assert_eq!(
        m.status, "ok",
        "agent_uid whose primary group is the agents gid is a member: {m:?}"
    );
    assert!(
        m.detail.contains("primary group"),
        "the detail names the primary-group branch: {m:?}"
    );
}

#[test]
fn agent_group_membership_ok_via_supplementary_member_list() {
    // Cover the SUPPLEMENTARY-membership branch — the uid's username appearing in the
    // agents group's member list, NOT the uid's primary group. Deleting that production branch
    // must not stay green. Use a REAL supplementary gid of the running user (its primary gid is,
    // by construction, a different gid), so the primary-group branch cannot fire.
    let uid = nix::unistd::getuid().as_raw();
    assert!(
        uid != 0 && uid != DAEMON_UID && uid != APPROVER_UID,
        "run the doctor unit tests as a normal non-root, non-fixture user (got {uid})"
    );
    let Some(gid) = a_member_gid() else {
        eprintln!(
            "skipping: the running user has no supplementary group beyond its primary (minimal CI)"
        );
        return;
    };
    let primary = own_primary_gid(uid)
        .unwrap_or_else(|| panic!("NSS could not resolve the running uid {uid} to a passwd user"));
    assert_ne!(
        gid, primary,
        "a_member_gid must return a NON-primary supplementary gid"
    );
    // Precondition: the running user's name is actually in that group's member list (the NSS
    // backend reflects the supplementary membership). Skip LOUDLY if a non-/etc/group backend
    // exposes the gid via getgroups but not via the group's member list.
    let uname = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| panic!("NSS could not resolve the running uid {uid} to a name"));
    let in_memlist = crate::groupdb::by_gid(gid)
        .ok()
        .flatten()
        .map(|g| g.members.iter().any(|m| m == &uname))
        .unwrap_or(false);
    if !in_memlist {
        eprintln!(
            "skipping: supplementary gid {gid} does not list '{uname}' in getgrgid mem \
                 (non-/etc/group NSS backend)"
        );
        return;
    }
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        uid,
        Some(uid),
        None,
        Some(gid),
        true,
    );
    let m = find(&report, "agent_group_membership");
    assert_eq!(
        m.status, "ok",
        "supplementary member of the agents gid is a member: {m:?}"
    );
    assert!(
        m.detail.contains("supplementary"),
        "the detail names the supplementary branch: {m:?}"
    );
}

#[test]
fn agent_group_membership_fails_in_service_when_agent_uid_is_not_a_member() {
    // An agent_uid that does not resolve to any user (so membership cannot be confirmed)
    // is a hard refuse in service mode — fail closed. Uses a very high uid unlikely to exist.
    let uid = nix::unistd::getuid().as_raw();
    let Some(gid) = own_primary_gid(uid) else {
        eprintln!("skipping: cannot resolve a real agents gid for the fixture");
        return;
    };
    let bogus_agent_uid: u32 = 4_000_000_001;
    assert!(
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(bogus_agent_uid))
            .ok()
            .flatten()
            .is_none(),
        "precondition: the bogus agent uid must not resolve to a user"
    );
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        bogus_agent_uid,
        Some(bogus_agent_uid),
        None,
        Some(gid),
        true,
    );
    let m = find(&report, "agent_group_membership");
    assert_eq!(
        m.status, "fail",
        "service mode: an unresolvable agent uid cannot confirm membership → refuse: {m:?}"
    );
    assert!(
        m.detail.contains("member") || m.detail.contains("resolve"),
        "the detail explains the membership failure: {m:?}"
    );
    assert!(
        !report.serving,
        "service mode: unverifiable agent membership must refuse to serve"
    );
}

#[test]
fn no_agent_group_membership_check_when_no_agents_gid() {
    // dev/embedded mode has no agents group: the membership check is absent entirely.
    let (home, runtime) = ok_runtime();
    let report = run(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(AGENT_UID),
        None,
        None,
        false,
    );
    assert!(
        report
            .checks
            .iter()
            .all(|c| c.name != "agent_group_membership"),
        "no agents gid ⇒ no agent_group_membership check"
    );
}

// ---- the git plane's admission, answered by the enforcer --------------------------------------

/// Build a report as if `caller` had just connected to ctl.
fn report_for_caller(
    runtime: &std::path::Path,
    home: &std::path::Path,
    caller: Option<u32>,
) -> DoctorReport {
    run_with_sentence_authority(
        home,
        runtime,
        runtime,
        DAEMON_UID,
        APPROVER_UID,
        AGENT_UID,
        Some(APPROVER_UID),
        None,
        None,
        true,
        Some(cermet_ipc::custody::CustodyProfile::SystemdHost),
        true,
        caller,
    )
}

#[test]
fn the_git_plane_row_tells_an_admitted_caller_which_uid_admitted_them() {
    let (home, runtime) = ok_runtime();
    let report = report_for_caller(&runtime, home.path(), Some(APPROVER_UID));
    let plane = find(&report, "git_plane");
    assert_eq!(plane.status, "ok", "{plane:?}");
    assert!(
        plane.detail.contains(&format!("uid {APPROVER_UID} (you)")),
        "the answer is about the CALLER, by number: {plane:?}"
    );
    assert!(
        plane.detail.contains("admitted") && plane.detail.contains("approver_uid"),
        "...and names which admitted uid they are: {plane:?}"
    );
    // The agent service account is admitted too, and is told so by name.
    let agent = find(
        &report_for_caller(&runtime, home.path(), Some(AGENT_UID)),
        "git_plane",
    )
    .clone();
    assert_eq!(agent.status, "ok", "{agent:?}");
    assert!(agent.detail.contains("agent_uid"), "{agent:?}");
}

#[test]
fn the_git_plane_row_refuses_a_caller_the_plane_would_refuse_and_names_both_uids() {
    // The failure this guards against: `check` says ✓ while the push says no. The row must carry
    // the enforcer's own answer.
    let (home, runtime) = ok_runtime();
    let stranger = 4242;
    let report = report_for_caller(&runtime, home.path(), Some(stranger));
    let plane = find(&report, "git_plane");
    assert_ne!(
        plane.status, "ok",
        "a refused caller is not a green row: {plane:?}"
    );
    assert!(
        plane.detail.contains(&format!("uid {stranger} (you)"))
            && plane.detail.contains("NOT admitted"),
        "{plane:?}"
    );
    assert!(
        plane.detail.contains(&AGENT_UID.to_string())
            && plane.detail.contains(&APPROVER_UID.to_string()),
        "the remedy names the uids that WOULD work: {plane:?}"
    );
    assert!(
        report.serving,
        "a caller outside the admission set is not a daemon fault; the daemon keeps serving"
    );
}

#[test]
fn the_boot_report_describes_the_admission_set_without_a_caller() {
    // Boot runs the doctor BEFORE any socket binds and has no caller to personalize for.
    let (home, runtime) = ok_runtime();
    let report = report_for_caller(&runtime, home.path(), None);
    let plane = find(&report, "git_plane");
    assert_eq!(plane.status, "ok", "{plane:?}");
    assert!(!plane.detail.contains("(you)"), "{plane:?}");
    assert!(
        plane.detail.contains(&AGENT_UID.to_string())
            && plane.detail.contains(&APPROVER_UID.to_string()),
        "the set is still reported: {plane:?}"
    );
    assert!(
        plane.detail.contains("not bound"),
        "and so is the socket's absence at boot: {plane:?}"
    );
}

// ---- CUSTODY-LADDER M1: the declared custody rung, reported ------------------------------------

/// The ladder is DECLARED, not merely taken: the profile the box is running on has to be readable
/// from the daemon that is running on it. This is the row `cermet check` renders — the profile by
/// name, and the rung's own honest limitation.
#[test]
fn the_custody_row_names_the_declared_profile_and_its_limitation() {
    let (home, runtime) = ok_runtime();
    for profile in cermet_ipc::custody::CustodyProfile::LADDER {
        let report = run_with_sentence_authority(
            home.path(),
            &runtime,
            &runtime,
            DAEMON_UID,
            APPROVER_UID,
            AGENT_UID,
            Some(APPROVER_UID),
            None,
            None,
            true,
            Some(profile),
            true,
            None,
        );
        let custody = find(&report, "custody");
        assert_eq!(custody.status, "ok", "{custody:?}");
        assert!(
            custody.detail.starts_with(profile.as_str()),
            "the row leads with the profile's declared name: {custody:?}"
        );
        assert!(
            custody.detail.contains(profile.limitation()),
            "...and states the rung's own limitation verbatim: {custody:?}"
        );
    }
}

/// A dev/embedded daemon holds no service key custody at all (fenced override / login keychain), so
/// the row says that rather than naming a rung it is not on. Silence would read as a claim.
#[test]
fn a_dev_daemon_reports_no_service_key_custody_rather_than_a_rung() {
    let (home, runtime) = ok_runtime();
    let report = run_with_sentence_authority(
        home.path(),
        &runtime,
        &runtime,
        DAEMON_UID,
        DAEMON_UID,
        DAEMON_UID,
        Some(DAEMON_UID),
        None,
        None,
        false,
        None,
        true,
        None,
    );
    let custody = find(&report, "custody");
    assert!(
        custody.detail.contains("dev"),
        "a dev daemon names its own shape: {custody:?}"
    );
    for profile in cermet_ipc::custody::CustodyProfile::LADDER {
        assert!(
            !custody.detail.contains(profile.as_str()),
            "a dev daemon must not claim a service custody rung: {custody:?}"
        );
    }
}
