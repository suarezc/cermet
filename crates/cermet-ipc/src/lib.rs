//! cermetd transport/auth shim (Unix-domain-socket boundary).

pub mod build_id;
pub mod client;
pub mod codec;
pub mod ctl;
pub mod custody;
pub mod hangup;
pub mod owner;
pub mod peer;
pub mod wire;

/// The build identity every binary linking this crate shares, and the skew comparison
/// each client surface renders. Re-exported at the root because it is not a transport concern —
/// it is what the daemon and its clients are.
pub use build_id::{build_skew, BUILD_ID, UNKNOWN_BUILD};
