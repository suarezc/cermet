//! Independent uid-0 owner revocation surface.

use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cermet_broker_actor::BrokerHandle;
use cermet_core::Result;
use cermet_ipc::codec;
use cermet_ipc::owner::{OwnerRequest, OwnerResponse};
use cermet_ipc::peer;

use crate::lockdown::{LockdownAuditSink, LockdownIntent, LockdownStore};
use crate::serve::{accept_loop, ConnHandler, ServeConfig, ServeError};

pub fn owner_authorized(peer_uid: u32) -> bool {
    peer_uid == 0
}

pub fn bind_owner_socket(
    runtime_dir: &Path,
) -> std::result::Result<(UnixListener, PathBuf), ServeError> {
    crate::serve::bind_socket(runtime_dir, "owner.sock", 0o600)
}

struct BrokerAuditSink<'a> {
    broker: &'a BrokerHandle,
    runtime: &'a tokio::runtime::Handle,
}

impl LockdownAuditSink for BrokerAuditSink<'_> {
    fn record_transition(&self, intent: &LockdownIntent) -> Result<()> {
        self.runtime
            .block_on(self.broker.record_lockdown_transition(
                intent.occurrence_id.clone(),
                intent.target_engaged,
                intent.operator_uid,
                intent.acceptance_path.clone(),
                intent.prior_record_digest.clone(),
            ))
            .map(|_| ())
    }
}

fn handle_owner_connection(
    stream: UnixStream,
    store: &LockdownStore,
    broker: &BrokerHandle,
    runtime: &tokio::runtime::Handle,
    timeouts: crate::serve::ServeTimeouts,
) {
    if stream.set_read_timeout(Some(timeouts.idle)).is_err()
        || stream
            .set_write_timeout(Some(timeouts.response_budget))
            .is_err()
    {
        return;
    }
    let Ok(credential) = peer::peer_cred(stream.as_raw_fd()) else {
        return;
    };
    if !owner_authorized(credential.uid) {
        return;
    }

    handle_root_owner_connection(stream, store, broker, runtime, timeouts);
}

/// Handle one already-kernel-authenticated uid-0 owner stream. Production reaches this only after
/// `peer_cred` and [`owner_authorized`] succeed; exposing the post-gate seam lets hermetic tests drive
/// the exact framed transition and broker audit path without weakening the root gate.
pub fn handle_root_owner_connection(
    mut stream: UnixStream,
    store: &LockdownStore,
    broker: &BrokerHandle,
    runtime: &tokio::runtime::Handle,
    timeouts: crate::serve::ServeTimeouts,
) {
    if stream.set_read_timeout(Some(timeouts.idle)).is_err()
        || stream
            .set_write_timeout(Some(timeouts.response_budget))
            .is_err()
    {
        return;
    }
    let sink = BrokerAuditSink { broker, runtime };
    loop {
        let request: OwnerRequest = match codec::read_frame(&mut stream) {
            Ok(request) => request,
            Err(_) => return,
        };
        let response = match request {
            OwnerRequest::OwnerStatus => OwnerResponse::Status {
                engaged: store.is_engaged(),
            },
            OwnerRequest::OwnerLockdown => {
                transition_response(store.transition(true, 0, "owner_uid0", &sink))
            }
            OwnerRequest::OwnerClear => {
                transition_response(store.transition(false, 0, "owner_uid0_clear", &sink))
            }
        };
        if codec::write_response_frame(&mut stream, &response).is_err() {
            return;
        }
    }
}

fn transition_response(result: Result<crate::lockdown::LockdownOutcome>) -> OwnerResponse {
    match result {
        Ok(outcome) => OwnerResponse::Transitioned {
            engaged: outcome.engaged,
            occurrence_id: outcome.occurrence_id,
        },
        Err(error) => OwnerResponse::Error {
            message: error.to_string(),
        },
    }
}

pub fn serve_owner_socket(
    listener: UnixListener,
    store: Arc<LockdownStore>,
    broker: BrokerHandle,
    config: ServeConfig,
) {
    let runtime = tokio::runtime::Handle::current();
    let timeouts = config.timeouts;
    let handle: ConnHandler = Arc::new(move |stream| {
        handle_owner_connection(stream, &store, &broker, &runtime, timeouts);
    });
    accept_loop(listener, config.max_conns, handle);
}

pub async fn replay_pending_audits(store: &LockdownStore, broker: &BrokerHandle) {
    let pending = match store.claim_pending_audits() {
        Ok(pending) => pending,
        Err(error) => {
            crate::log::emit(format!(
                "cermetd: cannot reconcile/read lockdown audit outbox: {error}"
            ));
            return;
        }
    };
    for intent in pending {
        match broker
            .record_lockdown_transition(
                intent.occurrence_id.clone(),
                intent.target_engaged,
                intent.operator_uid,
                intent.acceptance_path,
                intent.prior_record_digest,
            )
            .await
        {
            Ok(_) => {
                if let Err(error) = store.mark_audit_delivered(&intent.occurrence_id) {
                    crate::log::emit(format!(
                        "cermetd: lockdown audit landed but delivery marker update failed: {error}"
                    ));
                    if let Err(release_error) = store.release_audit_claim(&intent.occurrence_id) {
                        crate::log::emit(format!(
                            "cermetd: lockdown audit claim release failed for {}: {release_error}",
                            intent.occurrence_id
                        ));
                    }
                }
            }
            Err(error) => {
                if let Err(release_error) = store.release_audit_claim(&intent.occurrence_id) {
                    crate::log::emit(format!(
                        "cermetd: lockdown audit claim release failed for {}: {release_error}",
                        intent.occurrence_id
                    ));
                }
                crate::log::emit(format!(
                    "cermetd: lockdown audit emit failed for {}: {error}",
                    intent.occurrence_id
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cermet_core::Error;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn owner_gate_accepts_exactly_uid_zero() {
        assert!(owner_authorized(0));
        assert!(!owner_authorized(1));
        assert!(!owner_authorized(nix::unistd::geteuid().as_raw().max(1)));
    }

    #[test]
    fn owner_socket_is_mode_0600() {
        let directory = tempfile::tempdir().unwrap();
        let (listener, path) = bind_owner_socket(directory.path()).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(listener);
    }

    #[test]
    fn transition_errors_are_closed_owner_responses() {
        let response = transition_response(Err(Error::Denied("refused".into())));
        assert!(
            matches!(response, OwnerResponse::Error { message } if message.contains("refused"))
        );
    }
}
