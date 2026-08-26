//! Daemon self-check / health report.

use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use cermet_ipc::custody::CustodyProfile;
use serde::Serialize;

/// One self-check result.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: String,
    pub detail: String,
}

/// The health report.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub serving: bool,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// Checks that are not `ok`.
    pub fn warnings(&self) -> impl Iterator<Item = &DoctorCheck> {
        self.checks.iter().filter(|c| c.status != "ok")
    }
}

fn check(name: &str, status: &str, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        status: status.to_string(),
        detail: detail.into(),
    }
}

/// CUSTODY-LADDER: which mechanism holds this box's vault key, and what that mechanism honestly
/// does NOT protect.
///
/// This is a REPORT, never a verdict: every rung on the ladder is a supported, deliberately chosen
/// configuration, so the weakest one is `ok` exactly like the strongest. What would be dishonest is
/// silence — an operator (or a reader of our copy) has to be able to ask a running daemon which
/// rung it is on. The limitation is printed verbatim from the profile itself so the claim is
/// authored once (`cermet_ipc::custody`) and never paraphrased per surface.
fn custody_check(profile: Option<CustodyProfile>) -> DoctorCheck {
    match profile {
        Some(profile) => check(
            "custody",
            "ok",
            format!("{} — {}", profile.as_str(), profile.limitation()),
        ),
        // Dev/embedded: the key comes from the fenced dev override or the login keychain, not from
        // any service custody rung. Naming a rung here would be a claim about a boundary that is
        // not in force.
        None => check(
            "custody",
            "ok",
            "dev/embedded daemon — no service key custody rung (the fenced dev override / login \
             keychain holds the key)",
        ),
    }
}

fn mode_of(path: &Path) -> Option<u32> {
    std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o777)
}

/// In service mode a collapse condition is a hard refuse; in dev mode it stays a loud
/// warning so the single-uid dev daemon keeps serving.
fn collapse_status(service_mode: bool) -> &'static str {
    if service_mode {
        "fail"
    } else {
        "warn"
    }
}

fn db_check(home: &Path, file: &str, service_mode: bool) -> DoctorCheck {
    // In service mode a loose DB defeats the uid flip silently, so it's a hard refuse; in dev
    // mode it stays a loud warning so the single-uid dev daemon keeps serving. The -wal/-shm
    // sidecars carry the same plaintext-adjacent pages, so they refuse identically.
    let collapse = collapse_status(service_mode);
    match mode_of(&home.join(file)) {
        None => check(file, "ok", "absent (fresh home)"),
        Some(mode) if mode & 0o077 == 0 => check(file, "ok", format!("{mode:o} (owner-only)")),
        Some(mode) => check(
            file,
            collapse,
            format!(
                "{mode:o} is group/world-accessible; should be 0600 (the uid flip enforces this)"
            ),
        ),
    }
}

/// Each DB plus its `-wal`/`-shm` sidecars — the sidecars hold the same pages and so must
/// be just as owner-only.
fn db_checks(home: &Path, base: &str, service_mode: bool) -> Vec<DoctorCheck> {
    [
        base.to_string(),
        format!("{base}-wal"),
        format!("{base}-shm"),
    ]
    .iter()
    .map(|f| db_check(home, f, service_mode))
    .collect()
}

/// Check a bound socket's MODE against `want`. `mismatch` is the status a wrong mode produces:
/// a loose `ctl.sock` (mode != 0660) is a hard REFUSE in service mode, so the caller passes
/// `collapse_status(service_mode)` for `ctl.sock`. (`agent.sock` uses the dedicated
/// `agent_sock_check` below, since its mode is load-bearing.)
fn sock_check(runtime_dir: &Path, file: &str, want: u32, mismatch: &str) -> DoctorCheck {
    match mode_of(&runtime_dir.join(file)) {
        None => check(file, "ok", "not bound yet"),
        Some(mode) if mode == want => check(file, "ok", format!("{mode:o}")),
        Some(mode) => check(file, mismatch, format!("{mode:o}, expected {want:o}")),
    }
}

/// `agent.sock`'s expected mode depends on the topology. The peercred agent-uid gate
/// (`serve::agent_peer_admitted`), not the file mode, is the auth boundary in BOTH modes; the file
/// mode is defense-in-depth only, never the boundary itself:
///   * SERVICE mode: `0660` in the separate `2711 cermet:cermet-agents` dir — the distinct agent uid
///     reaches the socket via the inherited `cermet-agents` group, the approver/world cannot.
///   * DEV/embedded mode: `0666` in the single shared runtime dir — the same-uid path, wide open at
///     the filesystem layer and narrowed to the operator's own uid on accept.
///
/// A drift from the expected mode is a hard REFUSE in service mode and a `"warn"` in dev.
fn agent_sock_check(agent_runtime_dir: &Path, service_mode: bool) -> DoctorCheck {
    let want = if service_mode { 0o660 } else { 0o666 };
    match mode_of(&agent_runtime_dir.join("agent.sock")) {
        None => check("agent.sock", "ok", "not bound yet"),
        Some(mode) if mode == want => check("agent.sock", "ok", format!("{mode:o}")),
        Some(mode) => check(
            "agent.sock",
            collapse_status(service_mode),
            format!("{mode:o}, expected {want:o}"),
        ),
    }
}

/// The git plane's admission, answered BY THE ENFORCER and personalized to the caller.
///
/// `check`'s git-plane row used to treat "the socket accepted my connection" as health. It is not:
/// `git.sock` binds 0666 and the daemon admits EVERY connection, then applies the peercred gate
/// (`gitplane::handle_stream`) and writes an `ERR` pkt-line to a uid outside the set. So a
/// non-admitted user got a green row from the doctor and a refused push from git — the exact
/// cannot-see-which-piece-went-missing case that `cermet check` exists to kill.
///
/// The answer belongs here because the daemon is the only party that HAS it: the admission set is
/// built from its own config, and the ctl handler already knows the caller's kernel-attested uid.
/// The set comes from [`crate::gitplane::admitted_uids`] — the same function the gate itself calls,
/// so the report cannot drift from the enforcement.
///
/// Status is `warn`, never `fail`: a caller outside the set is not a daemon misconfiguration, and
/// boot (which has no caller, and runs before any socket binds) must keep serving.
fn git_plane_check(
    agent_runtime_dir: &Path,
    daemon_uid: u32,
    approver_uid: u32,
    agent_uid: u32,
    service_mode: bool,
    caller_uid: Option<u32>,
) -> DoctorCheck {
    let socket = agent_runtime_dir.join("git.sock");
    let bound = if socket.exists() {
        format!("git.sock at {}", socket.display())
    } else {
        format!("git.sock not bound yet at {}", socket.display())
    };
    let admitted =
        crate::gitplane::admitted_uids(service_mode, agent_uid, approver_uid, daemon_uid);
    let roster = if service_mode {
        format!("agent_uid {agent_uid} and approver_uid {approver_uid}")
    } else {
        format!("the daemon's own uid {daemon_uid} (dev/embedded)")
    };

    // No caller (boot): describe the set and stop. Nothing to personalize, nothing to refuse.
    let Some(caller) = caller_uid else {
        return check("git_plane", "ok", format!("{bound}; admits {roster}"));
    };
    let names = |uid: u32| -> &'static str {
        if service_mode && uid == agent_uid {
            "agent_uid"
        } else if service_mode && uid == approver_uid {
            "approver_uid"
        } else {
            "the daemon's own uid"
        }
    };
    if admitted.contains(&caller) {
        check(
            "git_plane",
            "ok",
            format!("{bound}; uid {caller} (you): admitted ({})", names(caller)),
        )
    } else {
        check(
            "git_plane",
            "warn",
            format!(
                "{bound}; uid {caller} (you): NOT admitted — the git plane admits {roster}; \
                 run git as one of those users"
            ),
        )
    }
}

/// Agent-socket gate check: `agent.sock` admits ONLY the resolved agent-plane uid — the distinct
/// `cermet-agent` uid in service mode (the approver is thereby kernel-DENIED the agent plane), the
/// daemon's own uid in dev/embedded. The peercred gate is the whole auth boundary, so it must be
/// sound: the admitted uid must be RESOLVED (`Some`) — an unresolved gate refuses ALL connections
/// (fail closed) — and, in service mode, DISJOINT from the daemon uid (else agent.sock would admit
/// the daemon's own uid). In dev/embedded mode the agent, approver, and daemon are one uid, so
/// admitted == daemon is the expected same-uid state (a warn, mirroring `uid_boundary`).
fn operator_gate_check(
    operator_uid: Option<u32>,
    daemon_uid: u32,
    service_mode: bool,
) -> DoctorCheck {
    match operator_uid {
        None => check(
            "operator_gate",
            collapse_status(service_mode),
            "the agent.sock operator uid is UNRESOLVED — agent.sock refuses ALL connections (fail \
             closed); configure the operator/approver uid",
        ),
        Some(op) if op == daemon_uid => {
            if service_mode {
                check(
                    "operator_gate",
                    "fail",
                    format!(
                        "operator gate uid ({op}) == daemon uid — agent.sock would admit the \
                         daemon's own uid; the operator must run as a disjoint uid"
                    ),
                )
            } else {
                check(
                    "operator_gate",
                    "warn",
                    format!(
                        "same-uid: agent.sock admits uid {op} == daemon uid (dev/embedded: operator \
                         == agent == daemon, no OS boundary)"
                    ),
                )
            }
        }
        Some(op) => check(
            "operator_gate",
            "ok",
            format!("agent.sock admits only the operator uid {op} (disjoint from daemon uid {daemon_uid})"),
        ),
    }
}

/// Verify a cross-uid socket ACL: the bound socket's group owner must be `expected_gid`, inherited
/// via the setgid bit on a `2711 cermet:<group>` dir — NOT a daemon chgrp.
/// We check the *inherited* group on the bound socket AND that the dir itself carries setgid + the
/// expected group (the two together are what guarantee inheritance). In service mode a drift on
/// either is a hard refuse; in dev mode it is a warning.
///
/// Group-neutral: `ctl.sock` inherits `cermet-approvers` from the runtime dir; `agent.sock` inherits
/// the disjoint `cermet-agents` from its own dir. `check_name`/`group_label` tailor the
/// diagnostics. The caller decides whether to run it (skip when the gid is `None`).
fn dir_socket_group_check(
    check_name: &str,
    group_label: &str,
    dir: &Path,
    socket_name: &str,
    expected_gid: u32,
    service_mode: bool,
) -> DoctorCheck {
    let collapse = collapse_status(service_mode);

    // The dir must be group-owned by `expected_gid` AND bit-exact 2711 for inheritance to hold
    // safely. Checking ONLY the setgid bit would accept looser/stray-bit drift — 2755
    // (world-listable), 2701 (group loses --x → the group class is stranded), 3711/6711 (stray
    // sticky/setuid). We require the full 12-bit mode to equal 2711, mirroring
    // `host_lock::harden_runtime_dir`.
    let dir_meta = std::fs::symlink_metadata(dir).ok();
    let dir_mode = dir_meta.as_ref().map(|m| m.permissions().mode() & 0o7777);
    let dir_mode_2711 = dir_mode == Some(0o2711);
    let dir_gid = dir_meta.as_ref().map(|m| m.gid());
    let dir_ok = dir_mode_2711 && dir_gid == Some(expected_gid);
    // Rendered into the drift diagnostics below: e.g. "2755" or "none" if the dir is missing.
    let dir_mode_str = dir_mode
        .map(|m| format!("{m:04o}"))
        .unwrap_or_else(|| "none".into());

    // The bound socket group owner (inherited from the setgid dir).
    let sock_gid = std::fs::symlink_metadata(dir.join(socket_name))
        .ok()
        .map(|m| m.gid());

    match sock_gid {
        None => {
            // Socket not bound yet: only the dir tells us whether inheritance will hold.
            if dir_ok {
                check(
                    check_name,
                    "ok",
                    format!("dir is setgid + group {expected_gid} ({socket_name} not bound yet)"),
                )
            } else {
                check(
                    check_name,
                    collapse,
                    format!(
                        "dir is not 2711 cermet:{group_label} (mode={dir_mode_str}, \
                         group={dir_gid:?}, want {expected_gid}) — {socket_name} will NOT inherit \
                         the {group_label} group, so cross-uid peers cannot reach it"
                    ),
                )
            }
        }
        Some(sg) if sg == expected_gid && dir_ok => check(
            check_name,
            "ok",
            format!("{socket_name} group {sg} ({group_label}, setgid-inherited)"),
        ),
        Some(sg) => check(
            check_name,
            collapse,
            format!(
                "{socket_name} group {sg} != {group_label} gid {expected_gid} OR dir not 2711 \
                 cermet:{group_label} (mode={dir_mode_str}, dir group={dir_gid:?}) — the \
                 setgid-inherited {group_label} ACL is broken"
            ),
        ),
    }
}

/// Verify the configured `agent_uid` is actually a MEMBER of `cermet-agents`. The setgid dir/mode
/// ACL (`dir_socket_group_check`) proves the *socket* carries the group; this proves the *agent
/// uid* is in that group, so filesystem reachability of the 0660 socket actually holds. The
/// installer provisions the membership; this is the runtime re-check that closes the gap between
/// "socket has the group" and "agent uid can traverse to it".
///
/// Membership is EITHER the group being the uid's passwd primary group OR the uid's username appearing
/// in the group's supplementary member list. Fail closed: an `agent_uid` that does not resolve to a
/// user, or a `cermet-agents` gid that does not resolve to a group, cannot be confirmed a member and
/// so refuses in service mode. Only called when `agents_gid` is `Some` (service mode), so a drift is
/// `collapse_status(service_mode)` = `fail`.
fn agent_group_membership_check(
    agent_uid: u32,
    agents_gid: u32,
    service_mode: bool,
) -> DoctorCheck {
    let collapse = collapse_status(service_mode);
    let user = match nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(agent_uid)) {
        Ok(Some(u)) => u,
        Ok(None) => {
            return check(
                "agent_group_membership",
                collapse,
                format!(
                "agent_uid {agent_uid} does not resolve to a user — cannot confirm cermet-agents \
                     membership (refusing)"
            ),
            )
        }
        Err(e) => {
            return check(
                "agent_group_membership",
                collapse,
                format!(
                    "getpwuid({agent_uid}) failed: {e} — cannot confirm cermet-agents membership \
                     (refusing)"
                ),
            )
        }
    };
    // Primary-group membership: the agents gid is the uid's own login group.
    if user.gid.as_raw() == agents_gid {
        return check(
            "agent_group_membership",
            "ok",
            format!(
                "agent_uid {agent_uid} ({}) has cermet-agents (gid {agents_gid}) as its primary group",
                user.name
            ),
        );
    }
    // Supplementary membership: the uid's username is in the group's member list.
    match crate::groupdb::by_gid(agents_gid) {
        Ok(Some(g)) if g.members.iter().any(|m| m == &user.name) => check(
            "agent_group_membership",
            "ok",
            format!(
                "agent_uid {agent_uid} ({}) is a supplementary member of cermet-agents (gid {agents_gid})",
                user.name
            ),
        ),
        Ok(_) => check(
            "agent_group_membership",
            collapse,
            format!(
                "agent_uid {agent_uid} ({}) is NOT a member of cermet-agents (gid {agents_gid}) — the \
                 agent cannot traverse to agent.sock; add it to the group (the installer provisions \
                 this)",
                user.name
            ),
        ),
        Err(e) => check(
            "agent_group_membership",
            collapse,
            format!(
                "getgrgid({agents_gid}) failed: {e} — cannot confirm cermet-agents membership \
                 (refusing)"
            ),
        ),
    }
}

/// Build the health report.
///
/// `service_mode` toggles the refuse tier: in service mode the collapse conditions doctor can
/// already see (the approver==daemon collapse, the broken setgid approvers ACL, and loose DB perms)
/// become hard `fail`s that flip `serving` to false (fail closed); in dev mode they stay
/// `warn`-and-serve so the single-uid dev daemon keeps running.
///
/// `approver_uid` is the single configured approver: it must be disjoint from the daemon uid or
/// approvals collapse onto the daemon. `agent_uid` is the resolved agent-plane uid: the distinct
/// `cermet-agent` uid in service mode, the daemon's own uid in dev — it must be disjoint from BOTH
/// the daemon and the approver or the two authority planes collapse. `approvers_gid`/`agents_gid`
/// are the resolved `cermet-approvers`/`cermet-agents` gids for the cross-uid
/// `ctl.sock`/`agent.sock` ACLs; both `None` in dev/embedded mode where there are no such groups.
/// `agent_runtime_dir` is where `agent.sock` lives (the separate `cermet-agents` dir in service
/// mode, == `runtime_dir` in dev). The kernel-uid asserts (`service_uid == getuid()`, nonzero) live
/// in `config.validate_runtime`, NOT here — doctor covers filesystem perms + the uid collapses.
#[allow(clippy::too_many_arguments)]
pub fn run(
    home: &Path,
    runtime_dir: &Path,
    agent_runtime_dir: &Path,
    daemon_uid: u32,
    approver_uid: u32,
    agent_uid: u32,
    operator_uid: Option<u32>,
    approvers_gid: Option<u32>,
    agents_gid: Option<u32>,
    service_mode: bool,
) -> DoctorReport {
    run_with_sentence_authority(
        home,
        runtime_dir,
        agent_runtime_dir,
        daemon_uid,
        approver_uid,
        agent_uid,
        operator_uid,
        approvers_gid,
        agents_gid,
        service_mode,
        None,
        true,
        None,
    )
}

/// Build the health report with the service's sentence-authority configuration included. The
/// ordinary `run` helper assumes it is configured for existing focused doctor tests; production boot
/// and ctl doctor call this entry point with the live config state.
#[allow(clippy::too_many_arguments)]
pub fn run_with_sentence_authority(
    home: &Path,
    runtime_dir: &Path,
    agent_runtime_dir: &Path,
    daemon_uid: u32,
    approver_uid: u32,
    agent_uid: u32,
    operator_uid: Option<u32>,
    approvers_gid: Option<u32>,
    agents_gid: Option<u32>,
    service_mode: bool,
    // CUSTODY-LADDER: the rung the config DECLARES for this box, `None` in the dev/embedded shape
    // (which loads no service key source at all).
    custody_profile: Option<CustodyProfile>,
    sentence_rules_configured: bool,
    // The kernel-attested uid of the ctl caller this report answers, when there is one.
    // `None` at boot — the daemon is reporting on itself, with nobody to personalize for.
    caller_uid: Option<u32>,
) -> DoctorReport {
    let mut checks = Vec::new();

    checks.push(custody_check(custody_profile));

    // The runtime dir is 2711 (setgid, world-traversable-not-writable), NOT 0700. We no
    // longer force 0700 here; the group ACL is verified by the dir/socket group checks.
    match mode_of(runtime_dir) {
        Some(mode) => checks.push(check("runtime_dir", "ok", format!("{mode:o}"))),
        None => checks.push(check("runtime_dir", "fail", "missing")),
    }

    // agent.sock's mode is NOT the connection gate — the kernel-attested peercred agent-uid check
    // is. Its expected mode depends on topology: 0660 in the separate cermet-agents dir (service),
    // 0666 in the shared dir (dev). A drift is a hard refuse in service mode. A ctl.sock mode other
    // than 0660 is a hard refuse in service mode too, a warn in dev mode.
    checks.push(agent_sock_check(agent_runtime_dir, service_mode));
    checks.push(git_plane_check(
        agent_runtime_dir,
        daemon_uid,
        approver_uid,
        agent_uid,
        service_mode,
        caller_uid,
    ));
    checks.push(operator_gate_check(operator_uid, daemon_uid, service_mode));
    checks.push(sock_check(
        runtime_dir,
        "ctl.sock",
        0o660,
        collapse_status(service_mode),
    ));

    // The cross-uid approvers ACL on ctl.sock, via setgid inheritance (not a daemon chgrp).
    if let Some(gid) = approvers_gid {
        checks.push(dir_socket_group_check(
            "ctl_group",
            "cermet-approvers",
            runtime_dir,
            "ctl.sock",
            gid,
            service_mode,
        ));
    }

    // The cross-uid agents ACL on agent.sock, via setgid inheritance from the separate 2711
    // cermet:cermet-agents dir (defense in depth beside the peercred gate). `None` in dev/embedded
    // mode where the agent socket shares the runtime dir and there is no cermet-agents group.
    if let Some(gid) = agents_gid {
        checks.push(dir_socket_group_check(
            "agent_group",
            "cermet-agents",
            agent_runtime_dir,
            "agent.sock",
            gid,
            service_mode,
        ));
        // The ACL above proves the SOCKET carries cermet-agents; this proves the AGENT UID is
        // a member of it, so it can actually traverse to the 0660 socket (the installer provisions
        // the membership; this is the runtime re-check).
        checks.push(agent_group_membership_check(agent_uid, gid, service_mode));
    }

    // Each DB plus its -wal/-shm sidecars.
    checks.extend(db_checks(home, "vault.db", service_mode));
    checks.extend(db_checks(home, "state.db", service_mode));
    checks.extend(db_checks(home, "audit.db", service_mode));

    // The approver uid must be disjoint from the daemon uid, else the human-only approval
    // split collapses onto the daemon (the daemon could approve itself). In dev mode this is a loud
    // warning; in service mode it is a hard refuse.
    if approver_uid == daemon_uid {
        checks.push(check(
            "approver_uid",
            collapse_status(service_mode),
            format!(
                "approver_uid ({approver_uid}) == daemon uid — the human-only approval split \
                 collapses onto the daemon (it could approve itself); the approver must run as a \
                 disjoint uid"
            ),
        ));
    } else {
        checks.push(check(
            "approver_uid",
            "ok",
            format!("approver_uid ({approver_uid}) is disjoint from daemon uid ({daemon_uid})"),
        ));
    }

    // The agent uid must be disjoint from the daemon uid, else the agent plane coincides with the
    // daemon uid that owns the vault/state (a compromised agent reaches them directly). Dev/embedded
    // (agent == daemon, same-uid) is the expected warn; service mode refuses.
    // Doctor must match the startup self-check, which ALSO refuses agent_uid == 0 (root /
    // unset) — a pairwise-only check would pass a zero agent uid when the daemon and approver happen
    // to be distinct and nonzero. Reject it first, before the pairwise comparisons.
    if agent_uid == 0 {
        checks.push(check(
            "agent_uid",
            collapse_status(service_mode),
            "agent_uid is 0 (root/unset) — the distinct agent plane requires a nonzero agent uid; \
             refuse (matches config::validate_runtime)"
                .to_string(),
        ));
    } else if agent_uid == daemon_uid {
        checks.push(check(
            "agent_uid",
            collapse_status(service_mode),
            format!(
                "agent_uid ({agent_uid}) == daemon uid — the agent plane collapses onto the daemon \
                 uid that owns the vault/state; the agent must run as a disjoint uid"
            ),
        ));
    } else {
        checks.push(check(
            "agent_uid",
            "ok",
            format!("agent_uid ({agent_uid}) is disjoint from daemon uid ({daemon_uid})"),
        ));
    }

    // The agent uid must be disjoint from the approver uid, else the two authority planes collapse
    // — a malicious agent running as the approver uid could speak ctl.sock and approve its own
    // requests (self-dealing). Dev/embedded warns; service refuses.
    if agent_uid == approver_uid {
        checks.push(check(
            "agent_approver",
            collapse_status(service_mode),
            format!(
                "agent_uid ({agent_uid}) == approver_uid — the agent and approval planes collapse; a \
                 compromised agent could approve its own requests. The agent must run as a uid \
                 disjoint from the approver"
            ),
        ));
    } else {
        checks.push(check(
            "agent_approver",
            "ok",
            format!(
                "agent_uid ({agent_uid}) is disjoint from approver uid ({approver_uid}) — the agent \
                 and approval planes are kernel-separated"
            ),
        ));
    }

    // The uid boundary. In SERVICE mode there are THREE distinct uids: the dedicated service/daemon
    // uid, the distinct agent uid (admitted to agent.sock), and the approver uid (admitted to
    // ctl.sock). When they are genuinely pairwise-disjoint and nonzero the kernel separates the
    // agent plane from the approval plane — human-only approval is a kernel property.
    //
    // This narration is only true when the pairwise collapse checks above actually PASS. Do
    // NOT report "boundary in force" beside a failing collapse (approver==daemon, agent==0, agent==
    // daemon, agent==approver) — that is contradictory security evidence next to serving=false. Gate
    // the ok narration on the same conditions those checks use; a collapse makes uid_boundary
    // topology-aware too (fail in service mode). In DEV/embedded mode all three collapse onto ONE uid,
    // so there is no OS boundary regardless — a loud warning (the distinct-uid install closes it).
    let boundary_intact = approver_uid != daemon_uid
        && agent_uid != 0
        && agent_uid != daemon_uid
        && agent_uid != approver_uid;
    if service_mode {
        if boundary_intact {
            checks.push(check(
                "uid_boundary",
                "ok",
                format!(
                    "three distinct uids: daemon/service {daemon_uid}, agent {agent_uid}, approver \
                     {approver_uid} — the OS separates the agent plane (agent.sock) from the approval \
                     plane (ctl.sock); the boundary is in force"
                ),
            ));
        } else {
            checks.push(check(
                "uid_boundary",
                collapse_status(service_mode),
                format!(
                    "the uid boundary is BROKEN — a pairwise collapse is present among daemon/service \
                     {daemon_uid}, agent {agent_uid}, approver {approver_uid} (see the approver_uid / \
                     agent_uid / agent_approver checks); the OS does not separate the agent and \
                     approval planes"
                ),
            ));
        }
    } else {
        checks.push(check(
            "uid_boundary",
            "warn",
            format!(
                "same-uid: agent + approver + daemon all run as uid {daemon_uid} — NO OS boundary \
                 (dev/embedded: a same-uid process can reach the broker DBs and the ctl plane \
                 directly); the distinct-uid service install closes this"
            ),
        ));
    }

    if service_mode && !sentence_rules_configured {
        checks.push(check(
            "sentence_authority",
            "warn",
            "sentence_rules_path is unset — every sentence-gated request (e.g. Stripe) fails closed; \
             set it to /etc/cermetd/sentences/rules.cermet and run `cermet rules allow`",
        ));
    } else {
        checks.push(check(
            "sentence_authority",
            "ok",
            if sentence_rules_configured {
                "sentence_rules_path is configured"
            } else {
                "not configured (dev mode)"
            },
        ));
    }

    // Fail closed: any `fail` check refuses to serve. Dev mode emits no `fail`s from the collapse
    // conditions above, so it keeps serving (a genuinely missing runtime_dir still refuses).
    let serving = !checks.iter().any(|c| c.status == "fail");
    DoctorReport { serving, checks }
}

#[cfg(test)]
mod tests;
