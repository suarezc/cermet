//! The keyless `ctl.sock` client + the client-side human-presence gate.
//!
//! This crate is the CLIENT half of the keyholder split: the master key + the vault live in the
//! daemon uid, and both operator surfaces — `cermet-app` (the browser console) and
//! `cermet-cli` (the operator CLI) — drive the broker over `ctl.sock` through the SAME
//! [`broker_client::CtlBrokerClient`], and gate authority-granting mutations through the SAME
//! [`presence::Presence`]. It holds NO master key and opens NO vault; it depends only on the neutral
//! `cermet-broker-core` (`Reply`) + the `cermet-ipc` ctl transport, so every operator surface shares
//! one transport + presence posture rather than a reimplementation.

/// Non-installable build marker for `test-presence`: it lives in the crate that OWNS the
/// feature, so any binary linking a presence-bypassing client carries it however the feature got
/// enabled. `cermet setup` scans for it and refuses to install. See the companion markers in
/// `cermet-core` for the full rationale. Adversary: T2 (accident).
#[cfg(feature = "test-presence")]
#[used]
static TEST_PRESENCE_BUILD_MARKER: [u8; 47] = *b"CERMET_TEST_PRESENCE_COMPILED_IN_DO_NOT_INSTALL";

pub mod broker_client;
/// The `ctl.sock` permission-denied diagnosis: the `cermet-approvers` login lag, said on
/// the error the operator is already reading.
pub mod group_hint;
/// Linux operator-path PAM password presence. Loads PAM at runtime via dlopen; on other
/// platforms `PamPasswordPresence` is an `Unavailable` stub.
pub mod pam_presence;
pub mod presence;
