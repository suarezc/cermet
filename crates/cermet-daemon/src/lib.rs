//! cermetd — the broker daemon. It runs under its own dedicated non-login service uid, launched by
//! the platform's service manager (systemd on Linux, launchd on macOS), and holds all durable
//! broker/vault state under that uid.

pub mod config;
pub mod ctl;
pub mod doctor;
/// The `cermetd` ROLE entry. ONE-BINARY: role selection lives in the composition crate's closed
/// dispatch table (`crates/cermet-bin`); this module owns the daemon's own startup spine.
pub mod entry;
pub mod gitplane;
pub mod groupdb;
pub mod lock;
pub mod lockdown;
pub mod log;
pub mod master_key;
pub mod owner;
pub mod quiesce_store;
pub mod relay;
pub mod runtime;
pub mod sentence_record;
pub mod serve;
pub mod startup;
pub mod supervise;

pub use ctl::{ctl_authorized, serve_ctl_socket};
pub use doctor::{run as doctor_run, DoctorReport};
pub use lock::{acquire_single_writer, HostLock};
pub use runtime::{resolve_runtime_dir, resolve_runtime_path, runtime_dir, RuntimeError};
pub use serve::{serve_agent_socket, ServeConfig, ServeError, ServeTimeouts};
