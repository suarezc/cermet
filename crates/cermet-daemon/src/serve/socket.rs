//! Socket binding + post-bind assertions for `agent.sock`/`ctl.sock` (mode, group inheritance,
//! stale-pathname cleanup, fail-closed two-socket bind). No connection handling lives here.

use std::path::{Path, PathBuf};

use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum ServeError {
    #[error("bind unix socket: {0}")]
    Bind(std::io::Error),
    #[error("chmod unix socket: {0}")]
    Chmod(std::io::Error),
}

/// Bind a unix socket `name` in `runtime_dir` and `chmod` it to `mode`. The ONE shared bind path
/// for `agent.sock` and `ctl.sock` so their remove→bind→chmod can't drift.
///
/// The daemon sets ONLY the socket MODE. The socket's GROUP owner is NOT set here: it is
/// INHERITED from the setgid (`2711 cermet cermet-approvers`) runtime dir that `tmpfiles.d`
/// provisions, so `ctl.sock` lands group-owned by `cermet-approvers` with no daemon-side `chgrp`.
/// The daemon is deliberately NOT a member of `cermet-approvers`, so a `chgrp` would `EPERM` — the
/// whole point of the setgid-inheritance model is to avoid it.
pub(crate) fn bind_socket(
    runtime_dir: &Path,
    name: &str,
    mode: u32,
) -> Result<(std::os::unix::net::UnixListener, PathBuf), ServeError> {
    bind_socket_in_group(runtime_dir, name, mode, None)
}

/// Mode-only bind. The `gid` parameter is retained for the call sites that thread an "approvers
/// gid" through, but it is a NO-OP: the cross-uid group reachability of `ctl.sock` comes from
/// setgid INHERITANCE off the runtime dir, NOT a daemon-side `chgrp` (which would `EPERM`, since
/// the daemon is intentionally not in `cermet-approvers`). The daemon sets only the MODE here; the
/// group owner is provisioned by `tmpfiles.d`.
pub(crate) fn bind_socket_in_group(
    runtime_dir: &Path,
    name: &str,
    mode: u32,
    _gid: Option<u32>,
) -> Result<(std::os::unix::net::UnixListener, PathBuf), ServeError> {
    use std::os::unix::fs::PermissionsExt;
    let path = runtime_dir.join(name);
    let _ = std::fs::remove_file(&path);
    let listener = std::os::unix::net::UnixListener::bind(&path).map_err(ServeError::Bind)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
        .map_err(ServeError::Chmod)?;
    // No chgrp: the group is inherited from the setgid runtime dir.
    Ok((listener, path))
}

fn socket_reserved_path(runtime_dir: &Path, name: &str) -> PathBuf {
    runtime_dir.join(name)
}

/// Remove only stale Unix socket pathnames before the startup doctor gate.
///
/// A daemon that exited uncleanly can leave `agent.sock`/`ctl.sock` on disk. The startup doctor
/// runs before bind, so it would inspect those stale pathnames and refuse before the bind path
/// could replace them. We clean the reserved names after the runtime dir has been hardened and
/// while the single-writer home lock is held, but we only unlink actual Unix socket inodes. A
/// regular file, directory, or symlink at a reserved socket name is not "stale socket cleanup"; it is
/// drift/tampering and must fail closed instead of being swept away.
pub fn clean_stale_socket_pathnames(
    runtime_dir: &Path,
    agent_runtime_dir: &Path,
) -> std::io::Result<()> {
    // agent.sock lives in the agents dir (== runtime_dir in dev), ctl.sock in the ctl dir. Clean
    // each at its real home so a stale inode in the SEPARATE agents dir can't block the pre-bind
    // doctor gate in service mode.
    clean_stale_socket_path(&socket_reserved_path(agent_runtime_dir, "agent.sock"))?;
    clean_stale_socket_path(&socket_reserved_path(runtime_dir, "ctl.sock"))?;
    clean_stale_socket_path(&socket_reserved_path(runtime_dir, "owner.sock"))
}

fn clean_stale_socket_path(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;

    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} exists but is not a Unix socket; refusing to remove a non-socket reserved path",
                path.display()
            ),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Assert a freshly-bound socket is really a Unix socket at the exact mode the product expects.
///
/// The pre-bind doctor may only see "not bound yet" after the stale-pathname cleanup. These
/// post-bind checks are therefore the launch-time assertions for the fresh inodes the daemon just
/// created.
pub fn assert_socket_mode(socket_path: &Path, expected_mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::symlink_metadata(socket_path)?;
    if !meta.file_type().is_socket() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not a Unix socket", socket_path.display()),
        ));
    }
    let actual = meta.permissions().mode() & 0o777;
    if actual != expected_mode {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} mode {actual:o} != expected {expected_mode:o}",
                socket_path.display()
            ),
        ));
    }
    Ok(())
}

/// Bind `agent.sock` in `runtime_dir` (mode `0666`) and return the bound `std` listener.
///
/// The peercred agent-uid gate (`agent_peer_admitted`) is the auth boundary — NOT the file mode.
/// This single-dir `0666` helper is the DEV/embedded (same-uid) shape; the live SERVICE path binds
/// `agent.sock` `0660` in the separate `cermet-agents` dir via [`bind_sockets_separate_dirs`].
/// Either way reachability is set wide enough for the admitted uid to reach the socket and then
/// narrowed to exactly one uid by the kernel-attested peercred check on accept.
pub fn bind_agent_socket(
    runtime_dir: &Path,
) -> Result<(std::os::unix::net::UnixListener, PathBuf), ServeError> {
    bind_socket(runtime_dir, "agent.sock", 0o666)
}

/// Resolve a system group's gid by NAME, ONCE at startup. Group-neutral — used for
/// `cermet-approvers` (the ctl-socket dir group) and `cermet-agents` (the agent-socket dir group).
///
/// This is a ONE-SHOT resolver — the caller resolves the gid a single time and threads the `u32`
/// through `harden_runtime_dir` / `assert_socket_group` / `doctor::run`. It is NOT a per-request
/// resolver. Portability: it goes through `crate::groupdb` (getgrnam_r-backed), which exists on
/// macOS + Linux — unlike `nix::getgroups`, which is Apple-unavailable; see that module for why
/// nix's own wrapper is unusable on macOS. Fail closed: an UNKNOWN group name is an
/// error (never a silent 0/default gid that could be misread as "root group" or "no ACL").
pub fn resolve_group_gid(group_name: &str) -> std::io::Result<u32> {
    match crate::groupdb::by_name(group_name) {
        Ok(Some(g)) => Ok(g.gid),
        Ok(None) => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("group {group_name:?} does not exist — cannot resolve the approvers gid (fail closed)"),
        )),
        Err(e) => Err(std::io::Error::other(format!(
            "getgrnam_r failed for group {group_name:?}: {e}"
        ))),
    }
}

/// POST-bind assertion that a bound socket actually INHERITED the expected gid.
///
/// The cross-uid reachability of `ctl.sock` rests on the setgid runtime dir making the bound socket
/// group-owned by `cermet-approvers` — the daemon never `chgrp`s it. After bind, the caller MUST
/// verify the inheritance actually happened (a non-setgid or wrong-group runtime dir would silently
/// produce a ctl.sock the cross-uid approvers cannot reach). Fail closed: a group mismatch — or any
/// `stat` failure (missing/foreign socket) — is an error, so the daemon refuses to serve rather than
/// expose an unreachable or mis-grouped control plane. Uses `symlink_metadata` (no follow).
pub fn assert_socket_group(socket_path: &Path, expected_gid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let actual = std::fs::symlink_metadata(socket_path)?.gid();
    if actual != expected_gid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "bound socket {socket_path:?} group {actual} != expected approvers gid \
                 {expected_gid} — the setgid runtime dir did NOT confer the approvers group, so \
                 cross-uid approvers cannot reach it — refusing"
            ),
        ));
    }
    Ok(())
}

/// Bind BOTH the agent and ctl sockets up-front, fail-closed (agent first, then ctl). Convenience
/// wrapper that passes no gid. The uid-flip path uses [`bind_sockets_with_group`] — though the gid
/// is now a no-op (group via setgid inheritance), the two entry points are kept.
pub fn bind_sockets(
    runtime_dir: &Path,
) -> Result<
    (
        std::os::unix::net::UnixListener,
        std::os::unix::net::UnixListener,
    ),
    ServeError,
> {
    bind_sockets_with_group(runtime_dir, None)
}

/// Bind BOTH sockets. The daemon does NOT chgrp `ctl.sock`: its `cermet-approvers` group owner is
/// INHERITED from the setgid runtime dir provisioned by `tmpfiles.d`, so the `approvers_gid`
/// argument is retained for the caller's intent but is a no-op here.
///
/// LEGACY collapsed-dev helper: it binds `agent.sock` `0600` in the same dir as `ctl.sock`. The LIVE
/// daemon path (`main.rs`) does NOT use this — in SERVICE mode it binds `agent.sock` `0660` in the
/// separate `cermet-agents` dir, and in DEV mode `0666` in the shared dir, both via
/// [`bind_sockets_separate_dirs`]. The AUTH BOUNDARY is the kernel-attested peercred agent-uid gate
/// (`agent_peer_admitted`), NOT the file mode. Fail closed: if EITHER socket cannot bind, neither
/// is served (the agent socket created first is removed) — a half-bound surface must never start.
pub fn bind_sockets_with_group(
    runtime_dir: &Path,
    approvers_gid: Option<u32>,
) -> Result<
    (
        std::os::unix::net::UnixListener,
        std::os::unix::net::UnixListener,
    ),
    ServeError,
> {
    // LEGACY collapsed-dev path: agent.sock 0600 in the SAME dir as ctl.sock. Not the live boundary —
    // peercred is; the live daemon binds 0666 via bind_sockets_separate_dirs directly.
    bind_sockets_separate_dirs(runtime_dir, 0o600, runtime_dir, approvers_gid)
}

/// Bind `agent.sock` in `agent_dir` at `agent_mode` and `ctl.sock` in `ctl_dir` at `0660`. Service
/// mode places `agent.sock` in a SEPARATE setgid `cermet-agents` dir at `0660` so a distinct agent
/// uid can reach it, while `ctl.sock` stays in the `cermet-approvers` dir; dev passes the same
/// dir + `0600` (via [`bind_sockets_with_group`]). The two-group split lets the agent uid reach
/// `agent.sock` without gaining any reachability to the control plane. Fail closed exactly like the
/// single-dir path: if the ctl bind fails, the agent socket already created is dropped and unlinked
/// so a half-bound surface never starts.
pub fn bind_sockets_separate_dirs(
    agent_dir: &Path,
    agent_mode: u32,
    ctl_dir: &Path,
    approvers_gid: Option<u32>,
) -> Result<
    (
        std::os::unix::net::UnixListener,
        std::os::unix::net::UnixListener,
    ),
    ServeError,
> {
    let (agent, agent_path) = bind_socket(agent_dir, "agent.sock", agent_mode)?;
    match crate::ctl::bind_ctl_socket_in_group(ctl_dir, approvers_gid) {
        Ok((ctl, _)) => Ok((agent, ctl)),
        Err(e) => {
            drop(agent);
            let _ = std::fs::remove_file(&agent_path);
            Err(e)
        }
    }
}
