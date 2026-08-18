//! The build identity carried on the agent/operator wires, and the pure skew comparison.
//!
//! The live failure this closes: an MCP stdio server from an 11-day-old build served an agent
//! session across several reinstalls and a daemon restart. Brokering kept working (authority is
//! daemon-side), but the session's tool surface was the old build's and NOTHING could detect the
//! skew — and with no backward compatibility, eventual wire drift surfaces as unexplained
//! per-call failures with no recovery hint.
//!
//! [`BUILD_ID`] is computed by this crate's `build.rs`. Both `cermetd` and `cermet` link this crate,
//! so ONE compile yields ONE id: equal ids mean the same build, different ids mean skew. It is
//! DETECTION only — no surface refuses on a mismatch (that would be a new failure mode in the name
//! of tidiness); every client just says so, once.

/// This build's identity: `{version}+{short commit}`, `-dirty` when the tree had tracked
/// modifications, `{version}+nogit` when built outside a git checkout.
pub const BUILD_ID: &str = env!("CERMET_BUILD_ID");

/// What a client renders when the daemon advertised no build at all — a daemon older than this
/// field. Absence is never read as "same build" (fail closed on the reporting side too).
pub const UNKNOWN_BUILD: &str = "unknown (a daemon predating the build-identity wire)";

/// Compare the daemon's advertised build against this binary's.
///
/// `None` when they are the same build — nothing to say. `Some(display)` otherwise, carrying the
/// daemon's id (or [`UNKNOWN_BUILD`] when it advertised none) for the caller to render on ITS
/// surface: an in-band note for the MCP bridge, a stderr line for the operator CLI, a row for
/// `cermet check`. Pure: the comparison lives here once; the wording belongs to each surface.
pub fn build_skew(daemon_build: &str) -> Option<&str> {
    if daemon_build == BUILD_ID {
        None
    } else if daemon_build.is_empty() {
        Some(UNKNOWN_BUILD)
    } else {
        Some(daemon_build)
    }
}
