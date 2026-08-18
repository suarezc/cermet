//! The `agent.sock` accept loop: peer_cred -> derive principal (uid:N) -> session-mint -> dispatch
//! (derive-don't-enroll v1; no hello/nonce handshake).

use std::time::Duration;

mod connection;
mod respond;
mod socket;

pub(crate) use connection::{accept_loop, ConnHandler};
pub use connection::{handle_connection, serve_agent_socket};
pub(crate) use respond::DeadlineWriter;
pub(crate) use socket::bind_socket;
pub(crate) use socket::bind_socket_in_group;
pub use socket::{
    assert_socket_group, assert_socket_mode, bind_agent_socket, bind_sockets,
    bind_sockets_separate_dirs, bind_sockets_with_group, clean_stale_socket_pathnames,
    resolve_group_gid, ServeError,
};

#[cfg(test)]
mod tests;

/// Per-connection read/write deadlines.
#[derive(Debug, Clone, Copy)]
pub struct ServeTimeouts {
    pub handshake: Duration,
    pub idle: Duration,
    /// Absolute (end-to-end) budget for writing ONE response frame. Unlike `idle`, which is a
    /// per-syscall write timeout a slow-but-steady reader can reset indefinitely, this
    /// caps the total drain time so a single response can never pin a connection slot for longer.
    pub response_budget: Duration,
}

impl Default for ServeTimeouts {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
            idle: Duration::from_secs(300),
            response_budget: Duration::from_secs(60),
        }
    }
}

/// Accept-loop configuration.
#[derive(Debug, Clone, Copy)]
pub struct ServeConfig {
    pub timeouts: ServeTimeouts,
    pub max_conns: usize,
    /// The resolved `cermet-approvers` gid for the cross-uid `ctl.sock` ACL; `None` in
    /// dev/embedded mode. Forwarded to `doctor::run` for the `cermetctl doctor` ctl path.
    pub approvers_gid: Option<u32>,
    /// The resolved `cermet-agents` gid for the cross-uid `agent.sock` ACL; `None` in dev/embedded
    /// mode. Forwarded to `doctor::run` so the ctl doctor report matches the startup self-check.
    pub agents_gid: Option<u32>,
    /// True on the fail-closed service-mode flip path; `false` (warn-and-serve) in
    /// dev/embedded mode. Forwarded to `doctor::run` so the ctl doctor report matches startup.
    pub service_mode: bool,
    /// CUSTODY-LADDER: the vault-key custody rung this box's config DECLARES; `None` in the
    /// dev/embedded shape. Forwarded to `doctor::run` so `cermet check` asks a RUNNING daemon which
    /// rung it is on rather than inferring one from the install.
    pub custody_profile: Option<cermet_ipc::custody::CustodyProfile>,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            timeouts: ServeTimeouts::default(),
            max_conns: 64,
            // Dev/embedded defaults: no approvers/agents group, warn-and-serve. The service-mode flip
            // populates these explicitly.
            approvers_gid: None,
            agents_gid: None,
            service_mode: false,
            // Dev/embedded: no service key custody rung at all (the fenced override / keychain).
            custody_profile: None,
        }
    }
}
