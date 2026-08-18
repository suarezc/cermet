//! The daemon-neutral broker CORE.
//!
//! This crate carries the pieces of the broker surface that are SAFE for a keyless production
//! client to name: the shared single-writer host-lock primitive ([`host_lock`]) and the uniform
//! [`Reply`] view/error type. It deliberately holds **NO** master key and opens **NO** vault.
//!
//! The in-process, key-LOADING broker — `spawn`/`BrokerHandle`/`Broker`, which decrypt the master
//! key and open `vault.db`/`state.db`/`audit.db` — lives one layer up in `cermet-broker-actor`,
//! which depends on this crate. Splitting the neutral core out lets `cermet-app` (the keyless
//! `ctl.sock` client, Role A) depend on `cermet-broker-core` in PRODUCTION while the key-bearing
//! `cermet-broker-actor` is reachable only as a dev-dependency (the test fixture impersonates the
//! daemon). The split is the structural guarantee that `cermet_broker_actor::spawn` is uncompilable
//! from `cermet-app/src/**` — keylessness enforced by the build graph, not by a source grep.

pub mod host_lock;
pub mod provider_tokens;

/// The uniform broker reply: a serialized core view type on `Ok`, the typed keyless error on
/// `Err`. Defined here (neutral) so the key-bearing actor and the keyless client name the SAME type;
/// the transport maps the carried `Error` to its own status seam.
pub type Reply = Result<String, cermet_lang::Error>;
