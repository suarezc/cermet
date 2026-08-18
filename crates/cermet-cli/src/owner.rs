//! Root-only client for the independent owner revocation socket.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use cermet_ipc::codec;
use cermet_ipc::owner::{OwnerRequest, OwnerResponse};

use crate::{CliError, CliOutput};

/// `owner.sock` sits beside `ctl.sock` in the daemon's ctl runtime dir — see
/// [`crate::endpoint::DEFAULT_CTL_SOCK`] for why that dir differs by platform.
#[cfg(target_os = "macos")]
pub const DEFAULT_OWNER_SOCK: &str = "/var/cermetd/owner.sock";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_OWNER_SOCK: &str = "/var/run/cermetd/owner.sock";

pub fn resolve_owner_endpoint(socket_override: Option<String>) -> Result<(PathBuf, u32), CliError> {
    let socket = socket_override
        .filter(|path| !path.is_empty())
        .or_else(|| {
            std::env::var("CERMET_OWNER_SOCK")
                .ok()
                .filter(|path| !path.is_empty())
        })
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OWNER_SOCK));
    let (_, daemon_uid) = crate::endpoint::resolve_ctl_endpoint_real(
        None,
        None,
        std::env::var("CERMET_DAEMON_UID").ok(),
    )
    .map_err(CliError::Refused)?;
    Ok((socket, daemon_uid))
}

pub fn run_owner(
    socket: &Path,
    expected_daemon_uid: u32,
    request: OwnerRequest,
) -> Result<CliOutput, CliError> {
    let effective_uid = nix::unistd::geteuid().as_raw();
    if effective_uid != 0 {
        return Err(CliError::Refused(format!(
            "owner operations require effective uid 0; current effective uid is {effective_uid} (run with sudo)"
        )));
    }
    let mut stream = UnixStream::connect(socket).map_err(|error| {
        CliError::Refused(format!(
            "cannot connect to owner socket {}: {error}",
            socket.display()
        ))
    })?;
    let peer = cermet_ipc::peer::peer_cred(stream.as_raw_fd())
        .map_err(|error| CliError::Refused(format!("cannot attest owner-socket peer: {error}")))?;
    if peer.uid != expected_daemon_uid {
        return Err(CliError::Refused(format!(
            "owner socket peer uid {} != expected daemon uid {expected_daemon_uid}",
            peer.uid
        )));
    }
    codec::write_frame(&mut stream, &request)
        .map_err(|error| CliError::Refused(format!("owner request write failed: {error}")))?;
    let response: OwnerResponse = codec::read_response_frame(&mut stream)
        .map_err(|error| CliError::Malformed(format!("owner response is invalid: {error}")))?;
    match response {
        OwnerResponse::Status { engaged } => Ok(CliOutput {
            text: format!(
                "owner lockdown: {}",
                if engaged { "engaged" } else { "clear" }
            ),
            ok: true,
        }),
        OwnerResponse::Transitioned {
            engaged,
            occurrence_id,
        } => Ok(CliOutput {
            text: format!(
                "owner lockdown: {} (occurrence {})",
                if engaged { "engaged" } else { "clear" },
                occurrence_id
            ),
            ok: true,
        }),
        OwnerResponse::Error { message } => Err(CliError::Refused(message)),
    }
}
