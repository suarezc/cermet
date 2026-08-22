//! cermet-core — the trusted capability-broker core.

pub mod artifacts;
pub use cermet_lang::{contract, error, sets, types};
pub mod audit;
pub use cermet_lang::authority;
pub mod broker;
pub mod budget;
pub mod canonicalize;
pub mod evidence;
pub mod git;
pub mod money;
mod mutation_success;
pub mod ontology;
pub mod policy;
pub mod preconditions;
/// Stored authority profiles, keyed by an opaque name. Written only through the sentence ceremony.
pub mod presets;
pub mod provider;
mod provider_json;
pub mod redaction;
pub mod relay;
pub mod sentence;
pub mod sentence_authority;
mod stripe_inert;
pub mod templates;
pub mod vault;
pub mod wiretap;

pub(crate) mod util;

// --- Non-installable build markers -------------------------------------------------------------
//
// Each marker lives in the crate that OWNS the feature, not in the composition crate, because
// cargo's resolver unifies dev-dependency features into the normal graph: a workspace test run
// compiled these doors into `target/debug/cermet` while markers declared up in `cermet-bin` — whose
// own feature set is empty on that build — stayed out. `cermet setup` scans the bytes of the one
// binary it would publish and refuses any that carries one of these, so the scan now proves the
// property `dist/linux/cermetd.service` promises: this binary links an egress-capable core.
//
// `#[used]` keeps the static through codegen and LTO; the bytes survive `strip` because they are
// data, not a symbol name. Adversary: T2 (accident) — a developer or an agent installing a binary
// they built for testing.

/// `test-egress` reopens `CERMET_<PROVIDER>_BASE_URL`, which redirects provider traffic that
/// carries the real credential. Never installable.
#[cfg(feature = "test-egress")]
#[used]
static TEST_EGRESS_BUILD_MARKER: [u8; 45] = *b"CERMET_TEST_EGRESS_COMPILED_IN_DO_NOT_INSTALL";

/// `test-double` registers canned-response providers in the default registry. A box that served
/// those while believing it was talking to a real provider would have receipts for effects that
/// never happened. Never installable.
#[cfg(feature = "test-double")]
#[used]
static TEST_DOUBLE_BUILD_MARKER: [u8; 45] = *b"CERMET_TEST_DOUBLE_COMPILED_IN_DO_NOT_INSTALL";

/// The action-template grammar primer served verbatim by the `language` verb. `include_str!` bakes
/// `docs/LANGUAGE.md` into the binary so the teaching surface ships with the core — no file lookup at
/// runtime, no way for it to drift from the validator it documents.
pub const LANGUAGE_DOC: &str = include_str!("../../../docs/LANGUAGE.md");

pub use artifacts::{
    ArtifactAddress, ArtifactConfig, ArtifactRange, ArtifactReadSurface, ArtifactSpan,
    StoredArtifact,
};
pub use broker::{
    AuthenticatedSentenceAuthority, Broker, BrokerConfig, ExecAttribution, FetchAttempt,
    LockdownSource, McpQuiesceStatus, McpRepointBegin, McpRepointStatusReport, PersistedBarrier,
    QuiesceGrantNote, QuiesceStore, RefUpdate, RefVerdict, SentenceAuthoritySource,
    MAX_BARRIER_TTL_SECS, MIN_BARRIER_TTL_SECS,
};
pub use error::{Error, ExecuteRefusal, Result};
/// The observation the ONE provider execution seam returns for a verb whose ratified template
/// declares the proving discipline.
pub use mutation_success::EffectProof;
pub use ontology::{
    Completion, Idempotency, OntologyArtifacts, OntologyBindings, OntologyCatalog, OntologyError,
    OntologyRecord, OntologyReview, OntologySemantics, Reversibility, RiskClass, Sensitivity,
    SourceRegistry, SourceRegistryEntry, SourceRegistryError, MAX_ONTOLOGY_DOCUMENT_BYTES,
    MAX_SOURCE_REGISTRY_BYTES, OFFICIAL_SOURCE_REGISTRY_YAML, ONTOLOGY_SCHEMA,
    SOURCE_REGISTRY_SCHEMA, VENDORED_ONTOLOGY,
};
pub use relay::{
    RelayConfig, RelayRefusal, DEFAULT_RELAY_LISTEN, DEFAULT_RELAY_MAX_BODY_BYTES,
    DEFAULT_RELAY_TTL_SECS,
};
pub use sentence_authority::{
    sentence_authority_pin, sentence_pin_account, AuthenticatedSentenceFile, SentencePinSource,
    SENTENCE_PIN_SERVICE,
};
pub use types::{
    AuditEventView, CapabilityRequest, ConnectOutcome, Decision, DeniedRequestView,
    EffectFailureClass, EffectOutcome, ExecOutcome, ExecutionEvidenceView, ExecutionResult,
    FailureSignal, GrantStatus, GrantView, ReceiptEnvelope, RelayHopView, RequestEvidenceView,
    RequestLogView, RequestOutcome, SafeCredential, WireStats,
};
