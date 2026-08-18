//! Keyless Cermet language and client-visible type surface.
//!
//! This crate contains no vault, credential store, broker actor, or broker provider executor. It is
//! the production dependency boundary shared by the `cermet` client and the trusted broker core.

pub mod artifacts;
pub mod authority;
pub mod contract;
pub mod error;
pub mod policy;
pub mod provider;
pub mod quiesce;
pub mod sentence;
pub mod sets;
pub mod templates;
pub mod types;
mod util;

pub use error::{Error, ExecuteRefusal, Result};
pub use quiesce::{McpQuiesceStatus, McpRepointBegin, McpRepointStatusReport, QuiesceGrantNote};
pub use types::{
    AuditEventView, CapabilityRequest, ConnectOutcome, Decision, DeniedRequestView,
    EffectFailureClass, EffectOutcome, ExecOutcome, ExecutionEvidenceView, ExecutionResult,
    FailureSignal, GrantStatus, GrantView, ReceiptEnvelope, RelayHopView, RequestEvidenceView,
    RequestLogView, RequestOutcome, SafeCredential, WireStats,
};
