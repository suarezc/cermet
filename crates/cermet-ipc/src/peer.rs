//! Kernel-attested peer credentials read off an accepted connection fd.

use std::os::unix::io::RawFd;

use thiserror::Error;

/// The common, platform-independent shape returned by [`peer_cred`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Peer process id. `None` on macOS. NEVER an auth input.
    pub pid: Option<u32>,
    /// Kernel-attested peer uid.
    pub uid: u32,
    /// Peer gid, where the platform reports one.
    pub gid: Option<u32>,
}

#[derive(Debug, Error)]
pub enum PeerCredError {
    #[error("peer credential lookup failed: {0}")]
    Os(#[from] nix::errno::Errno),
    /// macOS: the `xucred` layout version or group count is unusable.
    #[error("xucred unusable: version={got_version} (want {want_version}), cr_ngroups={ngroups}")]
    VersionMismatch {
        got_version: u32,
        want_version: u32,
        ngroups: i32,
    },
    /// macOS: the `xucred` uid disagreed with the `getpeereid()` uid.
    #[error("peer uid disagreement: xucred uid={xucred_uid}, getpeereid uid={getpeereid_uid}")]
    UidDisagreement {
        xucred_uid: u32,
        getpeereid_uid: u32,
    },
}

pub type Result<T> = std::result::Result<T, PeerCredError>;

/// Read the kernel-attested peer credential off an accepted connection `fd`.
///
/// On Linux `SO_PEERCRED` reads the credentials cached at connect/listen time, so on a
/// LISTENING (unconnected) socket it returns the *binding* process's own uid — silently attributing
/// the daemon's uid to a request (fail-open). Verify the fd is a CONNECTED socket before trusting
/// `SO_PEERCRED`: `getpeername` returns `ENOTCONN` on a socket with no connected peer, so a listener
/// fd is refused rather than mis-attributed.
#[cfg(target_os = "linux")]
pub fn peer_cred(fd: RawFd) -> Result<PeerCred> {
    use nix::sys::socket::{getpeername, getsockopt, sockopt::PeerCredentials, UnixAddr};
    let _connected: UnixAddr = getpeername(fd)?;
    let ucred = getsockopt(fd, PeerCredentials)?;
    Ok(PeerCred {
        pid: Some(ucred.pid() as u32),
        uid: ucred.uid(),
        gid: Some(ucred.gid()),
    })
}

/// Read the kernel-attested peer credential off an accepted connection `fd` (macOS).
#[cfg(target_os = "macos")]
pub fn peer_cred(fd: RawFd) -> Result<PeerCred> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerCred};
    use nix::unistd::getpeereid;
    let xucred = getsockopt(fd, LocalPeerCred)?;
    let (peereid_uid, gid) = getpeereid(fd)?;
    let raw: nix::libc::xucred = unsafe { std::mem::transmute(xucred) };
    let mut cred = validate_xucred(raw, peereid_uid.as_raw())?;
    cred.gid = Some(gid.as_raw());
    Ok(cred)
}

/// Pure validator for the macOS `xucred`: checks layout version, group count, and uid agreement.
#[cfg(target_os = "macos")]
pub fn validate_xucred(xucred: nix::libc::xucred, getpeereid_uid: u32) -> Result<PeerCred> {
    let want_version: u32 = nix::libc::XUCRED_VERSION;
    if xucred.cr_version != want_version || xucred.cr_ngroups == 0 {
        return Err(PeerCredError::VersionMismatch {
            got_version: xucred.cr_version,
            want_version,
            ngroups: xucred.cr_ngroups as i32,
        });
    }
    if getpeereid_uid != xucred.cr_uid {
        return Err(PeerCredError::UidDisagreement {
            xucred_uid: xucred.cr_uid,
            getpeereid_uid,
        });
    }
    Ok(PeerCred {
        pid: None,
        uid: xucred.cr_uid,
        gid: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};

    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};

    #[test]
    fn peer_cred_on_accepted_fd_reports_self_uid() {
        let (a, b) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .expect("socketpair");

        let me = nix::unistd::getuid().as_raw();
        let cred_a = peer_cred(a.as_raw_fd()).expect("peer_cred on connected end a");
        let cred_b = peer_cred(b.as_raw_fd()).expect("peer_cred on connected end b");

        assert_eq!(
            cred_a.uid, me,
            "peer uid must be our own uid (same-uid plumbing)"
        );
        assert_eq!(cred_b.uid, me);
    }

    #[test]
    fn peer_cred_on_uds_accepted_connection_reports_self_uid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("peer.sock");
        let listener = UnixListener::bind(&path).expect("bind");

        let client = UnixStream::connect(&path).expect("connect");
        let (server_conn, _addr) = listener.accept().expect("accept");

        let me = nix::unistd::getuid().as_raw();
        let cred = peer_cred(server_conn.as_raw_fd()).expect("peer_cred on accepted fd");
        assert_eq!(
            cred.uid, me,
            "accepted-fd peer uid is our own (same-uid plumbing)"
        );

        drop(client);
        drop(server_conn);
    }

    #[test]
    fn peer_cred_rejects_or_differs_on_listener_fd() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("listen.sock");
        let listener = UnixListener::bind(&path).expect("bind");

        let res = peer_cred(listener.as_raw_fd());
        assert!(
            res.is_err(),
            "peer_cred on a listener fd must error (no connected peer), got {res:?}"
        );
    }

    // The cross-uid peercred proof used to ALSO live here as a unit test
    // (`cross_uid_peer_attributed_to_caller_uid`). That unit copy bound a UDS in a default
    // tempdir (0700 on Linux), dropped uid, and blocked in an UNBOUNDED `accept()` with no
    // `make_traversable` — a hang reachable from `cargo test`. It was REMOVED.
    // The canonical, HARDENED cross-uid proof (traversable-parent + assert-ancestors +
    // bounded/timeout accept + socket-leaf chmod) lives ONLY in
    // `tests/priv_uid_harness.rs::cross_uid_peercred_reads_connecting_uid`, run via
    // `scripts/priv-test.sh`. There is intentionally NO unbounded cross-uid `accept()` at the
    // unit-test layer.

    #[cfg(target_os = "macos")]
    fn ok_xucred(uid: u32) -> nix::libc::xucred {
        nix::libc::xucred {
            cr_version: nix::libc::XUCRED_VERSION,
            cr_uid: uid,
            cr_ngroups: 1,
            cr_groups: [uid; 16],
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn zeroed_or_wrong_version_xucred_errors() {
        let zeroed: nix::libc::xucred = unsafe { std::mem::zeroed() };
        let res = validate_xucred(zeroed, 0);
        assert!(
            matches!(res, Err(PeerCredError::VersionMismatch { .. })),
            "a zeroed xucred must be rejected, got {res:?}"
        );

        let mut empty_groups = ok_xucred(501);
        empty_groups.cr_ngroups = 0;
        let res = validate_xucred(empty_groups, 501);
        assert!(
            matches!(res, Err(PeerCredError::VersionMismatch { .. })),
            "cr_ngroups == 0 must be rejected, got {res:?}"
        );

        let mut bad_version = ok_xucred(501);
        bad_version.cr_version = nix::libc::XUCRED_VERSION.wrapping_add(7);
        let res = validate_xucred(bad_version, 501);
        assert!(
            matches!(res, Err(PeerCredError::VersionMismatch { .. })),
            "a wrong-version xucred must be rejected, got {res:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn getpeereid_uid_disagreement_errors() {
        let xucred = ok_xucred(501);
        let res = validate_xucred(xucred, 0);
        assert!(
            matches!(res, Err(PeerCredError::UidDisagreement { .. })),
            "disagreeing uids must error, got {res:?}"
        );
        let ok = validate_xucred(xucred, 501).expect("agreeing uids validate");
        assert_eq!(ok.uid, 501);
    }
}
