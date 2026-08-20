//! The capability broker: sentence authority -> single-use grant -> execute.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use rusqlite::OptionalExtension;
use secrecy::ExposeSecret;
use serde_json::{json, Value};

use crate::audit::{AuditLog, IntegrityReport, NewEvent};
use crate::contract::{ActionContract, AllowBinding, CanonicalResource, FieldClass};
use crate::error::{Error, ExecuteRefusal, Result};
use crate::evidence::{
    EnvelopeField, EnvelopeSource, EvidenceEnvelope, EvidenceFailure, EvidenceFailureClass,
    EvidenceProfile, ProviderResolvedEnvelope, ResolvedEvidence,
};
use crate::policy::Query;
use crate::provider::{default_registry, Provider, ProviderCall};
use crate::redaction::redacted;
use crate::relay::RelaySession;
use crate::templates::TemplateRegistry;
use crate::types::{
    AuthorityKind, CapabilityRequest, ConnectOutcome, Decision, EffectOutcome, ExecOutcome,
    ExecutionResult, GrantStatus, GrantView, ReceiptEnvelope, RequestOutcome, RequestStatusView,
    SafeCredential,
};
use crate::util::{new_id, now_rfc3339};
use crate::vault::Vault;

/// How long an unspent sentence-authorized grant stays usable after it is requested.
const GRANT_TTL_SECS: i64 = 600;

/// Max length of the client-supplied agent display label persisted at session open.
const AGENT_LABEL_MAX: usize = 128;

pub struct BrokerConfig {
    /// Directory holding `audit.db`, `vault.db`, `state.db`.
    pub dir: PathBuf,
    /// Master key from the product layer (OS keychain).
    pub master_key: Vec<u8>,
    /// Ratified action-template documents (raw YAML). Loaded fail-closed at open; a bad document
    /// refuses boot.
    pub action_templates: Vec<String>,
    /// Ratified provider descriptors (raw YAML). Loaded fail-closed FIRST — a descriptor is the only
    /// way a token may ride to an origin, so a provider with no descriptor here is simply absent, and
    /// a template naming it refuses to load. github/vercel are shipped descriptors seeded here, not
    /// compiled-in structs. A bad document refuses boot.
    pub provider_descriptors: Vec<String>,
    /// Artifact-store cap + retention (defaulted; the daemon config overrides it the same way it does
    /// the rest of the daemon's settings).
    pub artifacts: crate::artifacts::ArtifactConfig,
    /// the hermetic system-git seam's settings — the config-pinned absolute binary, the
    /// per-request quarantine root, the per-invocation timeout, and the quarantine retention window
    /// swept at startup. Config keys `git_binary` / `git_quarantine_dir` / `git_timeout_secs` /
    /// `git_quarantine_retention_days`.
    pub git: crate::git::GitConfig,
}

impl BrokerConfig {
    /// The VENDORED (shipped) provider descriptors as owned strings — the github+vercel set every
    /// out-of-box daemon seeds into `providers.d`, and the default a test broker uses so github/vercel
    /// resolve exactly as before.
    pub fn vendored_descriptors() -> Vec<String> {
        crate::provider::VENDORED_PROVIDERS
            .iter()
            .map(|s| s.to_string())
            .collect()
    }
}

/// One source-authenticated sentence generation. `digest` is the canonical, domain/version-bound
/// authority identity authenticated by custody; the broker never invents a second structural identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSentenceAuthority {
    pub rules: crate::sentence::RuleSet,
    pub digest: String,
}

/// Read-only source of the sentence rules that currently hold authority.
///
/// Callers may present a ruleset when requesting a capability, but only a ruleset returned by this
/// source can authorize a sentence-backed grant. The broker re-reads it at request and claim time.
pub trait SentenceAuthoritySource: Send + Sync {
    fn current_authority(&self) -> Result<AuthenticatedSentenceAuthority>;

    fn current_ruleset(&self) -> Result<crate::sentence::RuleSet> {
        self.current_authority().map(|authority| authority.rules)
    }
}

/// Process-lifetime effective view of the independent owner deny latch. The daemon implementation
/// reconciles durable state before serving; missing/corrupt state is represented as engaged.
pub trait LockdownSource: Send + Sync {
    fn is_engaged(&self) -> bool;
}

/// What an AGENT is told when it asks for a capability on a box under the owner's deny-all. It
/// speaks the operator's own lockdown vocabulary — the state is "engaged", the root-only command
/// that lifts it is `cermet owner lockdown clear` — and it closes the door the generic
/// pre-authority render leaves open ("submit a new corrected request"), because no correction an
/// agent can make reaches past a lockdown.
const LOCKDOWN_REFUSAL: &str = "owner lockdown is engaged: the owner has put this box in deny-all, \
                                so no capability request can be granted and none will be until they \
                                lift it with `cermet owner lockdown clear` (root, on the box). A \
                                corrected or widened request will not help — do not retry; report \
                                the lockdown instead.";

/// Audit-only attribution of the connection that ACTUALLY executed a grant: the server-minted
/// session of the executing connection and its peer pid. It is recorded alongside the grant's frozen
/// request session in the `provider_action` audit event so the executor is always recoverable.
/// It never participates in authorization — it carries no agent-held authority and is drawn
/// from kernel/server-minted facts (the connection's own session + the kernel-attested pid).
#[derive(Clone, Debug, Default)]
pub struct ExecAttribution {
    /// The server-minted session of the executing connection (distinct from the request session).
    pub session_id: Option<String>,
    /// The kernel-attested pid of the executing connection.
    pub pid: Option<i64>,
    /// When true, `session_id` is a CALLER-SUPPLIED session that MUST still reference an OPEN
    /// row — verified atomically in the same core call as the execute/finalize (the single broker
    /// thread runs one call to completion, so no concurrent sweep/close can interleave in a preflight
    /// gap). A closed/unknown supplied session fails closed with [`Error::SessionExpired`]. A
    /// daemon-minted (per-connection / Hello) session leaves this false — it was just opened.
    pub require_session_open: bool,
    /// The kernel-attested peer uid of the executing connection (`None` outside the daemon,
    /// e.g. in-core tests). When a CALLER-SUPPLIED session id is validated (`require_session_open`),
    /// its stored `owner_uid` — the peer that minted it — must match this attested uid, or the call
    /// fails closed like a closed session. Binds a leaked `sess_*` to the conversation that opened it.
    pub peer_uid: Option<i64>,
}

pub use gitref::{FetchAttempt, RefUpdate, RefVerdict};

pub struct Broker {
    audit: AuditLog,
    vault: Vault,
    state: rusqlite::Connection,
    providers: HashMap<String, Box<dyn Provider>>,
    /// Provider name → SHA-256 of the loaded descriptor bytes. Frozen onto each grant at mint and
    /// re-checked at claim/execute, so a descriptor replacement invalidates every unspent dependent
    /// grant before credential use. A provider with no descriptor is simply absent.
    descriptor_hashes: HashMap<String, String>,
    /// This broker's ratified action templates — per-broker reachability, never process-global.
    templates: Arc<TemplateRegistry>,
    grant_key: [u8; 32],
    clock_override: Cell<Option<i64>>,
    /// Test-only: when non-zero AND `clock_override` is set, every `now_epoch()` read returns the
    /// current override then advances it by this step — reproducing the real within-handler clock
    /// drift (evidence load / audit persistence crossing a second) that callers must tolerate.
    #[cfg(test)]
    clock_tick: Cell<i64>,
    sentence_authority: Option<Arc<dyn SentenceAuthoritySource>>,
    lockdown_source: Option<Arc<dyn LockdownSource>>,
    /// Test-only detector for all-grants implementations that walk session-scoped queries.
    #[cfg(test)]
    list_grants_calls: Cell<usize>,
    dir: PathBuf,
    artifacts: crate::artifacts::ArtifactConfig,
    /// the git seam's settings. Held here (not only inside the provider registry)
    /// because the broker owns mirror hygiene — the startup aging sweep — and the update-hook
    /// decision path.
    git: crate::git::GitConfig,
    /// the mirror the in-flight update-hook decision is carrying FROM, set for exactly
    /// the duration of one `authorize_push` execute and cleared by its guard.
    ///
    /// A `Cell`-style scoped slot rather than a threaded parameter because the broker is a SINGLE
    /// thread by construction (one actor, one call to completion — the same reason `clock_override`
    /// and the quiesce barrier live this way), so there is no interleaving to race, and threading a
    /// git-only value through the whole claim/execute chain would put it in every HTTP verb's
    /// signature for nothing.
    git_mirror: RefCell<Option<PathBuf>>,
    /// This daemon instance's id (fresh per broker open). Returned by `begin_mcp_repoint` so the
    /// `cermet mcp install` client detects a daemon restart mid-transaction (a changed id).
    instance_id: String,
    /// The durable store for the MCP-repoint quiesce barrier. `None` in in-core tests that
    /// do not exercise durability; the daemon injects a `FileQuiesceStore`.
    quiesce_store: Option<Box<dyn quiesce::QuiesceStore>>,
    /// The live MCP-repoint quiesce barrier. In-memory only, held on the single broker
    /// thread so it serializes with every claim; the durable record is the crash-safe mirror.
    barrier: RefCell<Option<quiesce::PersistedBarrier>>,
    /// Set when a barrier release double-faults (the durable record could not be removed AND
    /// the compensating reforge also failed) — the durable mirror is unknown, so the broker enters an
    /// UNRECOVERABLE fail-closed state and refuses EVERY claim (and every barrier op) rather than
    /// serve claims with no durable record a restart could reinstate. Only a fresh boot clears it.
    quiesce_poisoned: Cell<bool>,
    /// Production constructors always enforce product availability. The only false value comes from
    /// the compile-gated semantic-test constructor used to keep disabled provider implementations
    /// exercised without making them reachable on a product surface.
    enforce_product_availability: bool,
    /// The declared `language_temporal_clauses` setting. FALSE — the shipped default — makes corpus
    /// admission refuse any `rate … per …` / `budget … per …` clause, so every decision is a pure
    /// function of `(request, corpus)`. The daemon installs its config with `set_temporal_clauses`;
    /// the machinery behind the clauses stays compiled either way, so flipping the setting on
    /// restores the windowed behavior with no code change.
    temporal_clauses: bool,
    /// The declared relay settings (listen authority, session TTL, body cap). The
    /// daemon installs its config with `set_relay_config`; the default is the shipped default.
    relay: crate::relay::RelayConfig,
    /// Live relay sessions by handle. Held HERE — next to the grant state that
    /// authorized them — so the daemon's loopback listener stays a pure HTTP adapter with no policy.
    /// `RefCell` like the rest of this struct: one broker thread owns it, one call at a time.
    relay_sessions: RefCell<HashMap<String, RelaySession>>,
    /// Per-provider relay egress, built from the same ratified descriptors the
    /// providers are. A provider absent here can never be relayed.
    relay_egress: HashMap<String, crate::provider::RelayEgress>,
}

#[derive(Clone)]
struct GrantRow {
    request_id: String,
    session_id: String,
    provider: String,
    action: String,
    resource_json: String,
    evidence_json: String,
    money_json: String,
    status: GrantStatus,
    decision: String,
    policy_fingerprint: String,
    grant_digest: String,
    expiry_epoch: Option<i64>,
    principal_id: Option<String>,
    /// The ratified template's content hash frozen at insert (`None` for a built-in action).
    template_hash: Option<String>,
    /// The SHA-256 of the loaded provider descriptor bytes, frozen at insert and re-checked at
    /// claim/execute — a descriptor replacement invalidates every unspent grant before credential use.
    descriptor_hash: String,
    /// Legacy-named durable authority provenance. New grants always stamp `sentence`; other values
    /// can exist only on authenticated pre-cutover rows and are terminalized at boot. All fields are
    /// covered by the grant HMAC.
    approved_by_kind: Option<String>,
    approver: Option<String>,
    approved_at: Option<String>,
    /// The claim-time lease stamps — `lease_opened_at` at the claim CAS,
    /// `lease_deadline` = opened + ratified per-verb max_runtime + report grace. Both folded into
    /// the grant HMAC as only-when-`Some` tags (a pre-claim grant digests byte-identically), so a
    /// raw store-edit of the deadline the sweep enforces breaks integrity. The overdue-executing
    /// sweep reads `lease_deadline`; the frozen plan carries the same max_runtime so both sides
    /// enforce ONE contract.
    lease_opened_at: Option<i64>,
    lease_deadline: Option<i64>,
}

/// The v0 requester principal recorded on every grant.
const LOCAL_REQUESTER: &str = "local-agent";

/// The greenfield schema generation stamped into `state.db` (`PRAGMA user_version`).
///
/// There are NO migrations: the schema is only ever re-declared wholesale, and a DB stamped with a
/// different generation REFUSES BOOT so the operator re-bootstraps rather than reading a shape the
/// code no longer understands. Git history is the archive of what each past generation held.
///
/// The current generation binds the grant HMAC under the `cermet-grant-v8` domain tag over, among
/// the rest of the frozen grant, the loaded provider `descriptor_hash`, canonical `evidence_json`,
/// and canonical `money_json`. Digest byte-identity with any earlier generation is deliberately NOT
/// preserved: an older grant fails integrity, it never aliases into a valid one.
///
/// An ADDITIVE column is the one exception — it migrates in place (see the ALTER after the DDL)
/// instead of burning a generation and a state wipe. The generation still moves for any change
/// that reshapes or reinterprets existing rows.
const STATE_SCHEMA_VERSION: i64 = 1;

impl Broker {
    fn provider_is_product_disabled(&self, provider: &str, action: &str) -> bool {
        self.enforce_product_availability
            && crate::provider::product_availability(provider, action)
                == crate::provider::ProductAvailability::ProviderDisabled
    }

    #[cfg(any(test, feature = "test-double"))]
    pub fn reset_audit_verification_passes_for_test(&self) {
        self.audit.reset_verification_passes();
    }

    #[cfg(any(test, feature = "test-double"))]
    pub fn audit_verification_passes_for_test(&self) -> usize {
        self.audit.verification_passes()
    }

    pub fn open(cfg: BrokerConfig) -> Result<Self> {
        Self::open_inner(cfg, None, None, true)
    }

    pub fn open_with_sentence_authority(
        cfg: BrokerConfig,
        sentence_authority: Arc<dyn SentenceAuthoritySource>,
    ) -> Result<Self> {
        Self::open_inner(cfg, Some(sentence_authority), None, true)
    }

    /// The general constructor: optional sentence authority AND the optional durable MCP-repoint
    /// quiesce store (the daemon injects a `FileQuiesceStore`; every other caller passes `None`).
    pub fn open_full(
        cfg: BrokerConfig,
        sentence_authority: Option<Arc<dyn SentenceAuthoritySource>>,
        quiesce_store: Option<Box<dyn quiesce::QuiesceStore>>,
    ) -> Result<Self> {
        Self::open_inner(cfg, sentence_authority, quiesce_store, true)
    }

    /// Compile-gated constructor for broker-dependent semantic suites that keep the disabled local
    /// provider implementations covered. It is absent from production builds and never used by a
    /// product/daemon test.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-double"))]
    pub fn open_for_semantic_test(
        cfg: BrokerConfig,
        sentence_authority: Option<Arc<dyn SentenceAuthoritySource>>,
    ) -> Result<Self> {
        Self::open_inner(cfg, sentence_authority, None, false)
    }

    /// Inject the daemon-owned independent revocation root before any request surface is served.
    pub fn set_lockdown_source(&mut self, source: Arc<dyn LockdownSource>) {
        self.lockdown_source = Some(source);
    }

    /// Install the declared `language_temporal_clauses` setting before any request surface is
    /// served. See [`Broker::temporal_clauses`].
    pub fn set_temporal_clauses(&mut self, enabled: bool) {
        self.temporal_clauses = enabled;
    }

    /// Whether this daemon admits temporal (windowed) clauses into a sentence corpus.
    pub fn temporal_clauses(&self) -> bool {
        self.temporal_clauses
    }

    fn open_inner(
        cfg: BrokerConfig,
        sentence_authority: Option<Arc<dyn SentenceAuthoritySource>>,
        quiesce_store: Option<Box<dyn quiesce::QuiesceStore>>,
        enforce_product_availability: bool,
    ) -> Result<Self> {
        // Provider descriptors load first (fail-closed): they set which providers a template may
        // extend and which providers exist at all. A bad descriptor refuses boot.
        let descriptors: Vec<crate::provider::ProviderDescriptor> = cfg
            .provider_descriptors
            .iter()
            .map(|doc| crate::provider::ProviderDescriptor::parse(doc).map_err(Error::Invalid))
            .collect::<Result<Vec<_>>>()?;
        // Freeze provider name → SHA-256 of the exact loaded descriptor bytes. This hash rides
        // every grant minted for that provider and is re-checked at claim/execute.
        #[allow(unused_mut)]
        let mut descriptor_hashes: HashMap<String, String> = cfg
            .provider_descriptors
            .iter()
            .zip(descriptors.iter())
            .map(|(doc, d)| (d.name.clone(), sha256_hex(doc.as_bytes())))
            .collect();
        // The compiled-in `mock-vercel`/`mock-github` doubles (and any other test double) are
        // registered by `default_registry` WITHOUT a descriptor document, so they carry no hash from
        // the loop above. Backfill a stable synthetic hash for them so a grant can still mint and the
        // descriptor binding exercises end-to-end in tests. This is strictly test/test-double-gated:
        // in a release binary every registered provider comes from a descriptor, so `insert_grant`'s
        // "no loaded descriptor → refuse to mint" fail-closed path is preserved for real providers.
        #[cfg(any(test, feature = "test-double"))]
        for name in ["mock-vercel", "mock-github"] {
            descriptor_hashes
                .entry(name.to_string())
                .or_insert_with(|| sha256_hex(format!("test-double-descriptor:{name}").as_bytes()));
        }
        // Two descriptors that share a `name:` would otherwise last-write-wins through the
        // `default_registry` HashMap insert, silently deciding which egress a vaulted token rides to.
        // Mirror the template loader's no-silent-shadow discipline (`templates.load` /
        // `register_provider` both refuse a duplicate): refuse boot, naming the colliding provider.
        let mut seen_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for d in &descriptors {
            if !seen_names.insert(d.name.as_str()) {
                return Err(Error::Invalid(format!(
                    "two provider descriptors declare the same name `{}` — refusing to boot \
                     (a duplicate descriptor name silently shadows which origin a vaulted token \
                     rides to; remove or rename one of the providers.d/*.yaml descriptors)",
                    d.name
                )));
            }
        }
        let provider_ceilings: std::collections::HashMap<
            String,
            crate::templates::ProviderCeiling,
        > = descriptors
            .iter()
            .map(|d| (d.name.clone(), crate::provider::descriptor_ceiling(d)))
            .collect();
        let templates = Arc::new(TemplateRegistry::with_ceilings(provider_ceilings));
        for doc in &cfg.action_templates {
            templates.load(doc).map_err(Error::Invalid)?;
        }
        let dir = &cfg.dir;
        let audit_path = dir.join("audit.db").to_string_lossy().into_owned();
        let vault_path = dir.join("vault.db").to_string_lossy().into_owned();
        let audit = AuditLog::open(&audit_path, subkey(&cfg.master_key, b"audit").to_vec())?;
        let vault = Vault::open(&vault_path, &subkey(&cfg.master_key, b"vault"))?;
        let state = rusqlite::Connection::open(dir.join("state.db"))?;
        // Greenfield schema guard: with no migrations, a state.db written by a different schema
        // generation must refuse at BOOT with a plain remedy — never serve and then fail every
        // read with raw "no such column" errors. A fresh (table-less) DB is stamped BEFORE the
        // DDL below runs, so a crash between stamp and create re-enters this fresh branch on the
        // next boot instead of refusing a stamped-but-empty file.
        let schema_generation: i64 = state.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let table_count: i64 = state.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |r| r.get(0),
        )?;
        if table_count == 0 {
            state.pragma_update(None, "user_version", STATE_SCHEMA_VERSION)?;
        } else if schema_generation != STATE_SCHEMA_VERSION {
            return Err(Error::Invalid(format!(
                "state.db at {} is schema generation {schema_generation}; this binary expects \
                 {STATE_SCHEMA_VERSION}. The schema is greenfield (no migrations) — remove the \
                 daemon's state/vault/audit DBs to re-bootstrap, or run the binary that matches \
                 the data",
                dir.display()
            )));
        }
        // Greenfield DDL: the trimmed spine declared outright — no runtime ALTERs, no migrations
        // (git history is the archive). `requests` is the atom of the agent↔broker conversation (a row
        // for EVERY request, denials included); `grants` carries sentence provenance + the frozen
        // provider-descriptor hash; `sessions` is server-minted attribution/ownership/lifecycle.
        // No profile or secondary policy store exists: sentence custody is the sole standing
        // capability authority. Legacy column names remain because the boot cutover authenticates
        // and terminalizes persisted rows minted by removed authority paths.
        state.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA busy_timeout=5000;
               CREATE TABLE IF NOT EXISTS requests (
                  id                    TEXT PRIMARY KEY,
                  provider              TEXT NOT NULL,
                  action                TEXT NOT NULL,
                  resource_json         TEXT NOT NULL,
                  justification         TEXT,
                  decision              TEXT NOT NULL,
                  reason                TEXT NOT NULL,
                  policy_fingerprint    TEXT,
                  matched_rule          TEXT,
                  deny_reason_json      TEXT,
                  principal             TEXT,
                  session_id            TEXT,
                  pid                   INTEGER,
                  created_at            TEXT NOT NULL
               );
               CREATE TABLE IF NOT EXISTS grants (
                  id                    TEXT PRIMARY KEY,
                  request_id            TEXT NOT NULL,
                  session_id            TEXT,
                  provider              TEXT NOT NULL,
                  action                TEXT NOT NULL,
                  resource_json         TEXT NOT NULL,
                  evidence_json         TEXT NOT NULL,
                  money_json            TEXT NOT NULL,
                  environment           TEXT,
                  status                TEXT NOT NULL,
                  decision              TEXT NOT NULL,
                  created_at            TEXT NOT NULL,
                  policy_fingerprint    TEXT,
                  grant_digest          TEXT,
                  expiry_epoch          INTEGER,
                  principal_id          TEXT,
                  template_hash         TEXT,
                  descriptor_hash       TEXT NOT NULL,
                  approved_by_kind      TEXT,
                  approver              TEXT,
                  approved_at           TEXT,
                  lease_opened_at       INTEGER,
                  lease_deadline        INTEGER
               );
               CREATE TABLE IF NOT EXISTS sessions (
                  id                    TEXT PRIMARY KEY,
                  created_at            TEXT NOT NULL,
                  ended_at              TEXT,
                  status                TEXT NOT NULL,
                  policy_fingerprint    TEXT,
                  agent                 TEXT,
                  pid                   INTEGER,
                  owner_uid             INTEGER
               );",
        )?;
        // The one exception to "no migrations" — an ADDITIVE column migrates in place instead of
        // forcing a state wipe. Idempotent; rows that predate `matched_rule` read NULL, which is
        // the truth about them.
        if !state
            .prepare("SELECT 1 FROM pragma_table_info('requests') WHERE name = 'matched_rule'")?
            .exists([])?
        {
            state.execute("ALTER TABLE requests ADD COLUMN matched_rule TEXT", [])?;
        }
        // The same additive shape: the evaluator's typed refusal beside the prose it was rendered
        // into. Additive and nullable — a row that predates it reads NULL, which is the truth
        // about it — and it reinterprets no existing column, so the generation stands.
        if !state
            .prepare("SELECT 1 FROM pragma_table_info('requests') WHERE name = 'deny_reason_json'")?
            .exists([])?
        {
            state.execute("ALTER TABLE requests ADD COLUMN deny_reason_json TEXT", [])?;
        }
        // The same additive exception: what the agent said it was ON THIS REQUEST. The
        // session's `agent_model` below is a declaration made once, when the session opened; this
        // is the claim attached to one request, and it exists because a runtime that switches
        // models mid-session keeps its session. Additive, nullable, read by no authority.
        if !state
            .prepare("SELECT 1 FROM pragma_table_info('requests') WHERE name = 'agent_model'")?
            .exists([])?
        {
            state.execute("ALTER TABLE requests ADD COLUMN agent_model TEXT", [])?;
        }
        // The same ruled exception: who DROVE the session, as self-reported. Three
        // additive nullable columns — the MCP handshake's `clientInfo` and the human's
        // own `CERMET_AGENT_MODEL` declaration. Rows that predate them read NULL, which
        // is the truth about them: nothing was captured. **No authority reads any of these.** They
        // are self-reports, held locally in full, and nothing sends them anywhere.
        for column in ["client_name", "client_version", "agent_model"] {
            if !state
                .prepare(&format!(
                    "SELECT 1 FROM pragma_table_info('sessions') WHERE name = '{column}'"
                ))?
                .exists([])?
            {
                state.execute(
                    &format!("ALTER TABLE sessions ADD COLUMN {column} TEXT"),
                    [],
                )?;
            }
        }
        // The artifact index (S3, first blob storage). Its own table, blobs under `dir/artifacts/`.
        crate::artifacts::ensure_schema(&state)?;
        // Stored authority profiles, keyed by an opaque name. Its own table, and deliberately not
        // the vault's — a corpus body is evidence an operator attested, never credential material.
        crate::presets::ensure_schema(&state)?;
        // Startup retention sweep (no scheduler): drop artifacts past the window and their now-orphan
        // blobs. Best-effort — a purge fault must not refuse boot.
        let _ = crate::artifacts::purge_expired(
            &state,
            &cfg.dir.join("artifacts"),
            cfg.artifacts.retention_days,
            crate::util::now_epoch(),
        );
        // the same discipline applies to per-request git quarantines. A quarantine is
        // scratch for ONE live request; anything left by an abandoned request ages out here.
        // Best-effort, and it needs no coordination with live grants — an aged-out quarantine is
        // simply rebuilt from the staged pack on demand.
        // git-native mirror hygiene: drop mirrors with no authorized contact inside the window.
        // Best-effort and coordination-free — a swept mirror is re-seeded from upstream on next
        // contact, so aging costs bandwidth, never correctness.
        //
        // There is deliberately NO boot-time git preflight here. The daemon boots on every box,
        // git-less or not; git is REGISTERED by the user (`git_binary`) and verified on first use,
        // and a git verb on a box without one refuses per-request with a legible message. Verbs are
        // vocabulary, not boot-time promises.
        let _ = crate::git::purge_expired_mirrors(&cfg.git, crate::util::now_epoch());
        let broker = Self {
            audit,
            vault,
            state,
            providers: default_registry(&descriptors, &templates, &cfg.git),
            descriptor_hashes,
            templates,
            grant_key: subkey(&cfg.master_key, b"grant"),
            clock_override: Cell::new(None),
            #[cfg(test)]
            clock_tick: Cell::new(0),
            sentence_authority,
            lockdown_source: None,
            #[cfg(test)]
            list_grants_calls: Cell::new(0),
            dir: cfg.dir.clone(),
            artifacts: cfg.artifacts,
            git: cfg.git.clone(),
            git_mirror: RefCell::new(None),
            instance_id: new_id("inst"),
            quiesce_store,
            barrier: RefCell::new(None),
            quiesce_poisoned: Cell::new(false),
            enforce_product_availability,
            // The shipped default is OFF. An operator who wants the windowed clauses back
            // declares `language_temporal_clauses = true`; nothing turns them on implicitly.
            temporal_clauses: false,
            relay: crate::relay::RelayConfig::default(),
            relay_sessions: RefCell::new(HashMap::new()),
            relay_egress: descriptors
                .iter()
                .filter_map(|d| {
                    crate::provider::RelayEgress::from_descriptor(d)
                        .map(|egress| (d.name.clone(), egress))
                })
                .collect(),
        };
        // MCP-repoint quiesce barrier: adopt any durable barrier record BEFORE serving, so
        // a daemon restart mid-repoint reinstates the claim block. A malformed record fails boot closed.
        broker.reinstate_barrier_on_boot()?;
        broker.terminalize_pre_sentence_grants_on_boot()?;
        // Converge any pre-cutover requested rows that expired before the authority cutover.
        broker.sweep_expired_requested_grants();
        // Heal either half of an audit-first terminal write before any lease can be called abandoned.
        broker.reconcile_terminal_executions_on_boot();
        // Boot-time convergence for ABANDONED leases too — an executing grant
        // whose claim-time deadline lapsed while the daemon was down is terminalized here; the
        // runtime sweep (daemon housekeeping) covers the live case.
        let _ = broker.sweep_overdue_leases();
        // The budget backstop runs once at boot (and on the housekeeping tick) — an
        // abandoned-approved budget grant or a crash-orphan mint whose TTL lapsed while the daemon was
        // down frees its reserved capacity promptly, rather than waiting for calendar rollover. Ordered
        // strictly AFTER fault-discrimination and aligned-expiry are applied, so the sweep
        // is never reachable in a fail-open form (it releases only on proven non-invocation).
        let _ = broker.sweep_expired_budget_mints();
        Ok(broker)
    }
}

mod budget;
mod execute;
mod gitref;
mod helpers;
mod lifecycle;
pub use lifecycle::SessionActor;
mod mint;
mod quiesce;
mod relay;
mod sentence_custody;
mod setup;
mod views;

pub use quiesce::{
    McpQuiesceStatus, McpRepointBegin, McpRepointStatusReport, PersistedBarrier, QuiesceGrantNote,
    QuiesceStore, MAX_BARRIER_TTL_SECS, MIN_BARRIER_TTL_SECS,
};
pub use relay::{RelayHopHead, RelayHopJob, RelayHopResponse, RelayHopStart, RelayHopStream};

use helpers::*;

/// A fresh broker scratch dir plus the guard that removes it.
///
/// Disarming the `TempDir` to return a bare `PathBuf` leaks one directory per fixture, so the guard
/// rides back with the path instead; hold it for as long as the broker lives (see [`TestBroker`]).
#[cfg(test)]
pub(super) fn fresh_broker_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("cermet-bk-")
        .tempdir()
        .unwrap();
    let path = dir.path().to_path_buf();
    (dir, path)
}

/// A test broker that owns the scratch dir it lives in.
///
/// The fixtures hand back a broker whose state/vault/audit files sit in a temp dir, and the dir has
/// to outlive the broker, so the guard rides along here. [`Deref`](std::ops::Deref) keeps every call
/// site reading as a plain `Broker`.
#[cfg(test)]
pub(super) struct TestBroker {
    broker: Broker,
    scratch: tempfile::TempDir,
}

#[cfg(test)]
impl TestBroker {
    pub(super) fn new(scratch: tempfile::TempDir, broker: Broker) -> Self {
        Self { broker, scratch }
    }

    /// Close the broker but KEEP its scratch dir, for a restart test that reopens the same state.
    /// The returned guard removes the dir when the test ends.
    pub(super) fn close(self) -> tempfile::TempDir {
        self.scratch
    }
}

#[cfg(test)]
impl std::ops::Deref for TestBroker {
    type Target = Broker;
    fn deref(&self) -> &Broker {
        &self.broker
    }
}

#[cfg(test)]
impl std::ops::DerefMut for TestBroker {
    fn deref_mut(&mut self) -> &mut Broker {
        &mut self.broker
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod quiesce_tests;

#[cfg(test)]
mod evidence_tests;
