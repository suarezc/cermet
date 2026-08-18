//! The shared single-writer host-lock substrate: the hardened `host.lock` flock, the owner-only
//! `CERMET_HOME` enforcement, and the no-follow `host.json` read/write — the filesystem primitives
//! both `cermet-app` (Role A) and `cermet-daemon` (Role B) contend on. The product-specific policy
//! (who advertises `host.json`, who attaches vs. fails closed) lives in each crate's wrapper; only
//! the security-load-bearing "open ONE hardened inode, flock it, validate the locked fd" is here.
//!
//! HONEST SCOPE: this hardens the FINAL `CERMET_HOME` directory and the lock/host.json inodes
//! (regular file, owned by us, no symlink at the final component). It does NOT walk the parent
//! chain — the invariant is "the final `CERMET_HOME` is a real directory we own at `0700` before
//! any path-based lock or host.json write." A full parent-chain `openat` walk is deferred. The
//! foreign-uid branches (`uid != geteuid`) fail closed but are NOT exercised by the same-uid test
//! suite — they need a privileged second-uid harness (the deferred cross-uid track).

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use fs2::FileExt;

/// The held single-writer lock. Keep it alive for the whole process: dropping it (or process death,
/// even SIGKILL) releases the advisory `flock`, so a crashed host self-heals.
#[derive(Debug)]
pub struct HostLock {
    _file: File,
}

/// Open a path as a lock file, fail-closed against symlinks and FIFOs: `O_NOFOLLOW` rejects a
/// symlink at the final component, `O_NONBLOCK` prevents an `open(O_WRONLY)` on a FIFO from blocking
/// before we ever reach the lock/validate step, and `0600` creates it owner-only.
fn open_hardened(lock_path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(lock_path)
}

/// Require an open fd to be a regular file owned by our effective uid, else fail closed. Used to
/// validate BOTH the host.lock fd (before either lock outcome) and the host.json read fd.
fn validate_regular_owned(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    let me = nix::unistd::geteuid().as_raw();
    if !meta.file_type().is_file() || meta.uid() != me {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "not a regular file owned by us — refusing",
        ));
    }
    Ok(())
}

/// Try to become the sole writer by taking an exclusive advisory lock on `lock_path`.
///
/// Fail-closed and hardened: opens with `O_NOFOLLOW | O_NONBLOCK | 0600`, validates the opened fd
/// (regular file owned by our effective uid) BEFORE branching on the lock, then takes the
/// non-blocking `flock`. Validating before the branch means a foreign-owned or non-regular
/// `host.lock` is refused even when it is ALREADY HELD (the busy/`WouldBlock` path) — not only when
/// we win the lock; otherwise an attacker who pre-creates and holds the lock would be treated as a
/// legitimate live host (fail-open-to-busy → the app attaches to an attacker-controlled host). The
/// check is on the fd, so it validates the same inode the `flock` operates on (immune to a path
/// swap after open). This catches a symlink/foreign-inode swap between open and lock; it does NOT
/// by itself close a swap between two *regular, us-owned* inodes — that residual is closed by the
/// owner-only `CERMET_HOME` (`harden_dir`, run by the callers BEFORE this), since an attacker who
/// cannot write the home directory cannot plant a competing inode in the first place. Returns the
/// held lock, `None` if another writer holds it, or an error on any hard fault.
///
/// This does NOT touch `host.json`: advertising (app) and clearing the stale advertisement (daemon)
/// are product policy that stays in the caller's wrapper.
pub fn acquire_hardened_lock(lock_path: &Path) -> io::Result<Option<HostLock>> {
    let file = open_hardened(lock_path)?;
    validate_regular_owned(&file)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(HostLock { _file: file })),
        Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Make `dir` a real, owner-only (`0700`) directory we own, or FAIL CLOSED.
///
/// Must run BEFORE the lock: the single-writer lock is only authoritative once the home is
/// owner-controlled — once `dir` is `0700` owned-by-us, no other principal can plant or swap
/// `host.lock`/`host.json` for the rest of the process.
///
/// - missing -> create `0700` (we become the owner);
/// - an existing directory we own -> (re)tighten its mode to `0700`;
/// - foreign-owned, a non-directory, or a final-component SYMLINK (`symlink_metadata` does not
///   follow) -> refuse. We never `chmod` a directory we do not own, and never follow a symlinked home.
pub fn harden_dir(dir: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) => {
            if !m.file_type().is_dir() {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    "path is not a directory (symlink/file/FIFO) — refusing",
                ));
            }
            let me = nix::unistd::geteuid().as_raw();
            if m.uid() != me {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "directory is owned by another user — refusing (will not chmod a dir we don't own)",
                ));
            }
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(dir)?;
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

/// Assert `dir` is a cross-uid runtime socket dir provisioned out-of-band (a privileged
/// `tmpfiles.d` rule: `d /run/cermetd 2711 cermet cermet-approvers -`), or FAIL CLOSED.
///
/// Group-neutral: `group_gid` is whichever group the bound sockets must inherit — `cermet-approvers`
/// for the ctl-socket dir, or `cermet-agents` for the agent-socket dir (Component 2). The assertion
/// is identical for both.
///
/// Unlike [`harden_dir`] (which OWNS + forces `0700`), this is **assert-only** — it never creates,
/// `chmod`s, or `chgrp`s. The daemon is deliberately NOT a member of that group, so it could not set
/// this layout itself (`chgrp` would `EPERM`); the dir is the trusted installer's contract and the
/// daemon's job is only to refuse to bind if the contract is wrong. The setgid bit makes sockets
/// bound here **inherit** `group_gid`, so a cross-uid peer in that group can traverse to the socket —
/// the whole point of the relaxed (not `0700`) mode.
///
/// Requires ALL of, else `Err`:
/// - a real directory (a final-component SYMLINK is refused — `symlink_metadata` does not follow);
/// - `uid == owner_uid` (the daemon/service uid);
/// - `gid == group_gid` (the group inherited by bound sockets);
/// - the setgid bit (`02000`) is set (without it sockets would NOT inherit the group);
/// - world-traversable: the other-execute bit (`0001`) is set (a cross-uid peer must `--x` in);
/// - NOT group-writable and NOT world-writable (`0020`/`0002` clear) — i.e. the permission bits are
///   exactly `0711` and the full mode is `2711`. A writable runtime dir would let a foreign principal
///   plant or swap the socket inode.
pub fn harden_runtime_dir(dir: &Path, owner_uid: u32, group_gid: u32) -> io::Result<()> {
    let m = std::fs::symlink_metadata(dir)?;
    if !m.file_type().is_dir() {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "runtime dir is not a directory (symlink/file/FIFO) — refusing",
        ));
    }
    if m.uid() != owner_uid {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "runtime dir owner != expected service uid — refusing",
        ));
    }
    if m.gid() != group_gid {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "runtime dir group != expected gid — sockets would not inherit the group — refusing",
        ));
    }
    // Require the full 12-bit mode to be EXACTLY 2711 — no looser, no special-bit drift.
    // A piecewise "setgid set AND world-x set AND not group/world-writable" check accepted strays
    // that break the cross-uid ACL: 2701 (group loses --x → the approvers class is stranded), 2755
    // (world-listable → leaks the socket inventory), and 3711/6711 (stray sticky/setuid). The whole
    // point of the privileged tmpfiles dir is a single exact layout, so assert it bit-for-bit.
    // 2711 = setgid (02000) + owner rwx (0700) + group --x (0010) + other --x (0001).
    let mode = m.permissions().mode() & 0o7777;
    if mode != 0o2711 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "runtime dir mode {mode:04o} != 2711 — the cross-uid socket dir must be EXACTLY \
                 setgid + 0711 (owner rwx, group/other --x only); any looser, missing, or stray \
                 special bit breaks the approvers ACL — refusing"
            ),
        ));
    }
    Ok(())
}

/// Validate `$CREDENTIALS_DIRECTORY` (the systemd-managed credential tmpfs the Linux service master
/// key is read out of) as a real, non-symlinked, owner-trusted, non-group/world-writable directory
/// — a defense-in-depth assertion layered UNDER the `O_NOFOLLOW` + fstat read of the
/// `cermet.key` file itself ([`read_nofollow`]). systemd provisions this dir as a `0700` ramfs, but
/// the daemon RE-ASSERTS it rather than trust the launch context: a symlinked, foreign-owned, or
/// group/world-writable credentials dir could let another principal plant or swap the decrypted key
/// inode, so any of those is refused.
///
/// Opens with `O_DIRECTORY | O_NOFOLLOW` (a final-component symlink is refused with `ELOOP`; a
/// non-directory yields `ENOTDIR`), then fstat-asserts on the OPEN fd (so it validates the exact
/// inode it opened — immune to a path swap after open):
/// - it is a directory;
/// - owner is our effective uid OR `root` (systemd may own the credential mount as root while the
///   decrypted files are owned by the service uid; a foreign NON-root owner is refused);
/// - it is neither group- nor world-writable (`0o022` clear) — a writable creds dir would let a
///   foreign principal plant or swap `cermet.key`.
pub fn validate_credentials_dir(dir: &Path) -> io::Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(dir)?;
    let meta = f.metadata()?;
    if !meta.file_type().is_dir() {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "$CREDENTIALS_DIRECTORY is not a directory (symlink/file/FIFO) — refusing",
        ));
    }
    let me = nix::unistd::geteuid().as_raw();
    if meta.uid() != me && meta.uid() != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "$CREDENTIALS_DIRECTORY is owned by a foreign (non-root) uid — refusing",
        ));
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "$CREDENTIALS_DIRECTORY is group- or world-writable — a foreign principal could swap \
             cermet.key — refusing",
        ));
    }
    // systemd provisions this dir 0700 root-private; a group/world-READABLE dir is a
    // misconfigured launch context (this DiD layer's whole reason for existing), so refuse any
    // group/other r bit too. Layered ON TOP of the write-bit refusal above (never weakens it).
    if meta.permissions().mode() & 0o044 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "$CREDENTIALS_DIRECTORY is group- or world-readable — systemd provisions it 0700 \
             root-private; anything looser is a misconfigured launch context — refusing",
        ));
    }
    Ok(())
}

/// Replace `path` with a fresh `mode` regular file containing `bytes`, fail-closed against a
/// symlink / non-regular / foreign-owned target.
///
/// Used for the app's advisory `host.json`. Fresh REPLACE (not truncate-in-place): a planted
/// symlink, a non-regular file, or a foreign-owned file is surfaced as an error rather than
/// followed/overwritten; an existing regular file we own is unlinked and re-created so a stale loose
/// mode or a hardlinked inode is never inherited.
pub fn write_replace_nofollow(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            let me = nix::unistd::geteuid().as_raw();
            if !m.file_type().is_file() || m.uid() != me {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "refusing to replace a non-regular or foreign-owned file",
                ));
            }
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)
}

/// Tighten an EXISTING secret-bearing file to `0600`, fail-closed against a symlink / non-regular /
/// foreign-owned target. This is the permission that BECOMES the boundary at the uid flip: once
/// `vault.db`/`state.db`/`audit.db`/`master.key` are `0600` owned by the daemon uid, an agent uid
/// gets `EACCES` on them.
///
/// Hardened like `open_hardened`: `O_NOFOLLOW` rejects a final-component symlink, `O_NONBLOCK`
/// keeps a planted FIFO from blocking the open, and the `fstat` requires a REGULAR file owned by our
/// effective uid before we `fchmod`. We `fchmod` the OPEN fd (not the path), so we tighten the exact
/// inode we validated — immune to a path swap between validate and chmod. We never `chmod` a file we
/// do not own and never follow a symlink to chmod its target. A missing path is an error: the caller
/// hardens only inodes that already exist (the dbs/key are created under a tight umask before Broker
/// opens for write).
///
/// Opened read-only: `fchmod` needs only an fd, not write access, and read-only avoids truncating or
/// requiring write perms on a file we may not yet be able to write.
pub fn harden_file_0600(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    validate_regular_owned(&file)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

/// Set the process umask to `0077` so every file the process creates afterward (notably sqlite's
/// `-wal`/`-shm` sidecars, which we never name explicitly) lands owner-only — group/other bits are
/// stripped at creation, closing the window between `create` and an explicit `chmod`. Returns the
/// PREVIOUS mask (umask's standard contract). Process-global: the caller runs this ONCE at startup,
/// FIRST, before any file is created.
pub fn set_umask_0077() -> nix::libc::mode_t {
    // SAFETY: umask() is async-signal-safe and only swaps a per-process scalar; no UB.
    unsafe { nix::libc::umask(0o077) }
}

/// The max bytes read from `host.json` — it carries only `{pid, port, started_at}`, so a small cap
/// bounds a hostile or corrupt file instead of streaming it unbounded.
const MAX_HOST_JSON: u64 = 64 * 1024;

/// Read `path` fail-closed: `O_NOFOLLOW | O_NONBLOCK` (no symlink-follow, and no blocking on a FIFO
/// at the path), validate the fd is a regular file we own, then read at most `MAX_HOST_JSON` bytes.
/// The caller maps any error to its fail-closed default (e.g. the app's `Busy(None)` — never start
/// a second broker just because `host.json` is missing, foreign, special, or weird).
pub fn read_nofollow(path: &Path) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    validate_regular_owned(&file)?;
    let mut buf = Vec::new();
    file.take(MAX_HOST_JSON).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Read a SECRET-bearing file (the master key) fail-closed, exactly like [`read_nofollow`] plus an
/// extra refusal: the file must NOT be group- or world-accessible in ANY of read/write.
/// Owner-owned-and-regular is sufficient for the non-secret advisory `host.json`, but a
/// master key at `0644`/`0640` leaks to other uids, and a `0602`/`0620` key is a key-SUBSTITUTION
/// vector (a foreign principal could overwrite the key) — both are the misconfiguration this
/// defense-in-depth layer must catch (the systemd credential lands `0400`, the macOS key file
/// `0600`; both pass). The check is SYMMETRIC — any group/world r OR w bit is refused — and runs on
/// the OPEN fd (immune to a path swap).
pub fn read_secret_nofollow(path: &Path) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    validate_regular_owned(&file)?;
    if file.metadata()?.permissions().mode() & 0o066 != 0 {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "secret key file is group- or world-readable/writable — it must be owner-only \
             (0600/0400) — refusing",
        ));
    }
    let mut buf = Vec::new();
    file.take(MAX_HOST_JSON).read_to_end(&mut buf)?;
    Ok(buf)
}

pub use cermet_lang::authority::{read_authority_file, MAX_AUTHORITY_FILE};

#[cfg(test)]
mod tests;
