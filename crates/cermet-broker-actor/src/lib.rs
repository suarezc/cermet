//! The broker actor: one dedicated OS thread owns the `!Sync` `cermet-core::Broker`.
//!
//! This crate is the KEY-BEARING layer: [`spawn`]/[`BrokerHandle`] construct a `cermet-core::Broker`,
//! which decrypts the master key and opens the vault. The daemon-neutral, key-free pieces — the
//! `host_lock` primitive and the [`Reply`] type — live in `cermet-broker-core` and are re-exported
//! here so existing `cermet_broker_actor::{host_lock, Reply}` paths (the daemon, the test fixtures)
//! are unchanged. Keyless clients depend on `cermet-broker-core` directly and never on this crate.

// Re-export the neutral core so `cermet_broker_actor::host_lock` / `cermet_broker_actor::Reply`
// continue to resolve for existing consumers (cermet-daemon, the cermet-app dev fixtures).
pub use cermet_broker_core::{host_lock, Reply};

use cermet_core::provider::Provider;
use cermet_core::{
    Broker, BrokerConfig, CapabilityRequest, Error, ExecAttribution, LockdownSource,
    SentenceAuthoritySource,
};
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// What a caller SELF-REPORTED about who is driving, owned because it crosses the actor channel.
///
/// Nothing here is attested and **no authority reads any of it**: the runtime's own name and version
/// from the MCP handshake, and the human's `CERMET_AGENT_MODEL` declaration.
/// `Default` is "nothing was captured", which is the truth about the git plane and every operator
/// ctl session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelfReported {
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub model: Option<String>,
}

enum Cmd {
    ListCredentials(oneshot::Sender<Reply>),
    /// The agent-facing projection — product-enabled providers only.
    ListCredentialsForAgent(oneshot::Sender<Reply>),
    Connect {
        provider: String,
        token: SecretString,
        account_label: Option<String>,
        reply: oneshot::Sender<Reply>,
    },
    Request {
        session: String,
        request_json: String,
        /// The caller's attested peer uid, stamped as the owner of a lazily-created session
        /// row so no daemon-created row is ownerless.
        owner_uid: Option<i64>,
        /// The safe effect handle of a prior attempt this request retries, or `None`. Request
        /// metadata, never resource data; the core authenticates the lineage.
        retry_effect: Option<String>,
        reply: oneshot::Sender<Reply>,
    },
    RequestForPrincipal {
        session: String,
        principal: String,
        request_json: String,
        retry_effect: Option<String>,
        /// True when `session` is CALLER-SUPPLIED and must already be open (checked
        /// atomically in the core call); false for a daemon-minted session (lazy auto-create).
        require_open: bool,
        /// The attested peer uid; a caller-supplied session must be owned by it.
        peer_uid: Option<i64>,
        reply: oneshot::Sender<Reply>,
    },
    Execute {
        grant_id: String,
        session: String,
        reply: oneshot::Sender<Reply>,
    },
    ExecuteForPrincipal {
        grant_id: String,
        session: String,
        principal: String,
        reply: oneshot::Sender<Reply>,
    },
    ExecuteRequestForPrincipal {
        request_id: String,
        principal: String,
        /// Audit-only attribution of the executing connection (its minted session + peer pid).
        exec_session: Option<String>,
        exec_pid: Option<i64>,
        /// True when `exec_session` is CALLER-SUPPLIED and must still be open.
        require_open: bool,
        /// The attested peer uid a caller-supplied `exec_session` must be owned by.
        exec_uid: Option<i64>,
        reply: oneshot::Sender<Reply>,
    },
    /// Keyed by the one public id; the broker resolves the grant.
    ExecuteOperator {
        request_id: String,
        reply: oneshot::Sender<Reply>,
    },
    /// Run the overdue-executing lease sweep once; replies with the count.
    SweepOverdueLeases(tokio::sync::oneshot::Sender<usize>),
    /// Authorize and forward ONE relay hop, serialized with every mint/claim on the
    /// broker thread. The daemon's loopback listener carries the request here verbatim and enforces
    /// nothing itself — the trust boundary is crossed once, and checked once, in the core.
    ///
    /// The reply is the VERDICT ONLY — an authorized hop comes back as a job that has not been
    /// sent. Connect, send, head, and body all run on the caller's worker thread, so this thread
    /// never waits on the network and deny-all stays reachable through a slow, silent, or streaming
    /// upstream.
    RelayHopStart {
        handle: String,
        method: String,
        target: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        reply: oneshot::Sender<cermet_core::Result<cermet_core::broker::RelayHopStart>>,
    },
    /// What the upstream HEAD alone decides, applied the moment it lands (the
    /// definite-4xx release of a `once` effect), before the client can act on that status.
    RelayHopHead {
        handle: String,
        effect: bool,
        status: u16,
        reply: oneshot::Sender<cermet_core::Result<()>>,
    },
    /// The finished hop comes back here — the receipt observation and the hop's
    /// terminal audit row (with total response bytes) are the core's to write, not the adapter's.
    RelayHopComplete {
        stream: cermet_core::broker::RelayHopStream,
        reply: oneshot::Sender<cermet_core::Result<()>>,
    },
    /// Close every lapsed relay session (each with its receipt); replies with the
    /// count closed.
    SweepRelaySessions(tokio::sync::oneshot::Sender<usize>),
    /// Run the budget/rate expiry backstop once — release every expired, un-released
    /// `budget_mint` whose grant never crossed the invocation boundary (crash-orphan or unclaimed
    /// approved). Serialized on the broker thread; replies with the count released.
    SweepExpiredBudgetMints(tokio::sync::oneshot::Sender<usize>),
    VerifyAudit(oneshot::Sender<Reply>),
    /// Emit the post-commit sentence-authority custody audit for a now-live
    /// generation. Idempotent, keyed by `canonical_digest` — a concurrent commit or a
    /// boot-adoption replay never double-chains. Serialized with every mint/claim on the single
    /// broker thread, and called STRICTLY AFTER the authority record flip.
    RecordSentenceCustodyChange {
        canonical_digest: String,
        rule_count: usize,
        /// The durable per-commit transition id the broker dedups on (NOT the content digest).
        occurrence_id: String,
        operator_uid: u32,
        acceptance_path: String,
        prior_record: Option<String>,
        reply: oneshot::Sender<Reply>,
    },
    /// CUSTODY-LADDER: one `broker_start` audit event per daemon run, naming the declared vault-key
    /// custody rung that run is on (`None` in the dev/embedded shape, which has no rung).
    RecordBrokerStart {
        custody_profile: Option<String>,
        reply: oneshot::Sender<Reply>,
    },
    /// One agent-reported vocabulary request appended to the audit log. Data, not authority:
    /// nothing reads these rows to decide anything.
    RecordVocabularyRequest {
        session_id: Option<String>,
        provider: String,
        wanted_verb: Option<String>,
        wanted_field: Option<String>,
        gap: String,
        ask: Option<String>,
        rationale: Option<String>,
        reply: oneshot::Sender<Reply>,
    },
    RecordLockdownTransition {
        occurrence_id: String,
        engaged: bool,
        operator_uid: u32,
        acceptance_path: String,
        prior_record: Option<String>,
        reply: oneshot::Sender<Reply>,
    },
    /// Daemon-side authority-subset validation of a candidate sentence corpus
    /// (secret-class rejection + subset checks) run by the ctl `StageSentences` handler BEFORE staging,
    /// so a direct ctl client can never install a disallowed authority record. Ok replies
    /// with an empty view; a disallowed corpus is a typed `Err`.
    ValidateSentenceCorpus {
        candidate_text: String,
        reply: oneshot::Sender<Reply>,
    },
    /// Agent discovery: sentence-derived requestable verb schemas.
    CatalogListing(oneshot::Sender<Reply>),
    /// Principal-BOUND by construction: there is deliberately no unbound status
    /// command, so no agent-surface caller can read a request's state without owning it.
    Status {
        request_id: String,
        principal: String,
        reply: oneshot::Sender<Reply>,
    },
    /// Handshake: mint/record the connection's own agent session (used by the daemon's agent Hello
    /// path). Core session machinery — there is no operator ctl session-open op.
    OpenSession {
        session_id: String,
        agent_cmd: String,
        pid: Option<i64>,
        /// The attested peer uid that owns this session (checked on later supplied use).
        owner_uid: Option<i64>,
        /// What the caller said about ITSELF. Never attested, read by no authority.
        actor: SelfReported,
        reply: oneshot::Sender<Reply>,
    },
    CloseSession {
        session_id: String,
        reply: oneshot::Sender<Reply>,
    },
    /// Handshake: does `session_id` reference an OPEN session row? (Fail-closed gate on a
    /// caller-supplied session id — the daemon refuses an unknown/closed id, never silently mints.)
    SessionOpen {
        session_id: String,
        reply: oneshot::Sender<Reply>,
    },
    /// Handshake: opportunistically close sessions idle beyond `idle_secs`, keeping `keep` (the
    /// just-minted handshake session). Returns the number swept.
    SweepIdleSessions {
        keep: String,
        idle_secs: i64,
        reply: oneshot::Sender<Reply>,
    },
    History(oneshot::Sender<Reply>),
    /// The cross-session relay hop log (`cermet log --hops`).
    RelayHops(oneshot::Sender<Reply>),
    /// How many vocabulary requests this box has recorded — one COUNT over the audit log's `type`
    /// column, never a chain verification.
    Evidence {
        request_id: String,
        reply: oneshot::Sender<Reply>,
    },
    ReadArtifact {
        handle: String,
        addr: Option<cermet_core::ArtifactAddress>,
        surface: cermet_core::ArtifactReadSurface,
        reply: oneshot::Sender<Reply>,
    },
    // ---- MCP-repoint quiesce barrier: ctl-only. Begin/End/Status run on the same
    // actor thread that serializes every approved→executing claim, so the barrier can never race a
    // claim. `ReleaseExpiredBarrier` is the daemon housekeeping tick's TTL-recovery hook. ----
    BeginMcpRepoint {
        ttl_secs: i64,
        reply: oneshot::Sender<Reply>,
    },
    McpRepointStatus {
        token: String,
        reply: oneshot::Sender<Reply>,
    },
    EndMcpRepoint {
        token: String,
        reply: oneshot::Sender<Reply>,
    },
    ReleaseExpiredBarrier(oneshot::Sender<Reply>),
    /// one proposed ref update from git's `update` hook. Runs on the same single actor
    /// thread every claim runs on, so the decision and the credentialed hop it confirms cannot
    /// interleave with anything else.
    AuthorizeRefUpdate {
        update: cermet_core::RefUpdate,
        reply: oneshot::Sender<Reply>,
    },
    /// one proposed mirror refresh from the read stream. Same single actor thread, so a
    /// refresh cannot interleave with a push decision on the same mirror.
    AuthorizeFetch {
        attempt: cermet_core::FetchAttempt,
        reply: oneshot::Sender<Reply>,
    },
}

/// A cheap-to-clone handle to the single broker thread.
#[derive(Clone)]
pub struct BrokerHandle {
    tx: mpsc::Sender<Cmd>,
}

#[derive(Default)]
struct SpawnOptions {
    lockdown_source: Option<Arc<dyn LockdownSource>>,
    quiesce_store: Option<Box<dyn cermet_core::QuiesceStore>>,
    semantic_test: bool,
    /// The daemon's DECLARED relay settings. `None` leaves the core default.
    relay: Option<cermet_core::RelayConfig>,
    /// The daemon's DECLARED `language_temporal_clauses` setting. `None` leaves the core default,
    /// which is OFF.
    temporal_clauses: Option<bool>,
}

fn ser<T: serde::Serialize>(r: cermet_core::Result<T>) -> Reply {
    match r {
        Ok(v) => serde_json::to_string(&v).map_err(Error::from),
        Err(e) => Err(e),
    }
}

/// Spawn the broker thread, constructing the Broker from `config` inside it.
pub fn spawn(config: BrokerConfig) -> Result<BrokerHandle, String> {
    spawn_with_providers(config, Vec::new())
}

/// Spawn the broker with a constructor-injected, read-only sentence authority source. Requests do
/// not carry a source selector; the core's fixed route decides when this authority applies.
pub fn spawn_with_sentence_authority(
    config: BrokerConfig,
    sentence_authority: Arc<dyn SentenceAuthoritySource>,
) -> Result<BrokerHandle, String> {
    spawn_inner(
        config,
        Vec::new(),
        Some(sentence_authority),
        SpawnOptions::default(),
    )
}

/// Compile-gated actor constructor for semantic suites that exercise retained disabled providers.
#[cfg(feature = "semantic-test")]
#[doc(hidden)]
pub fn spawn_with_sentence_authority_for_semantic_test(
    config: BrokerConfig,
    sentence_authority: Arc<dyn SentenceAuthoritySource>,
) -> Result<BrokerHandle, String> {
    spawn_inner(
        config,
        Vec::new(),
        Some(sentence_authority),
        SpawnOptions {
            semantic_test: true,
            ..SpawnOptions::default()
        },
    )
}

/// Spawn the broker thread and register `extra_providers` onto it before serving — the daemon's hook
/// for its own `files` provider (which carries the workspace root). Registration runs inside the
/// broker thread, and a failure (e.g. a duplicate provider name) fails startup closed: the handle is
/// never returned. `Box<dyn Provider>` is `Send` (`Provider: Send + Sync`), so the vector moves into
/// the thread with the config.
pub fn spawn_with_providers(
    config: BrokerConfig,
    extra_providers: Vec<Box<dyn Provider>>,
) -> Result<BrokerHandle, String> {
    spawn_inner(config, extra_providers, None, SpawnOptions::default())
}

pub fn spawn_with_providers_and_sentence_authority(
    config: BrokerConfig,
    extra_providers: Vec<Box<dyn Provider>>,
    sentence_authority: Arc<dyn SentenceAuthoritySource>,
) -> Result<BrokerHandle, String> {
    spawn_inner(
        config,
        extra_providers,
        Some(sentence_authority),
        SpawnOptions::default(),
    )
}

/// The daemon's full spawn: providers + optional sentence authority + the optional durable
/// MCP-repoint quiesce store.
pub fn spawn_full(
    config: BrokerConfig,
    extra_providers: Vec<Box<dyn Provider>>,
    sentence_authority: Option<Arc<dyn SentenceAuthoritySource>>,
    lockdown_source: Option<Arc<dyn LockdownSource>>,
    quiesce_store: Option<Box<dyn cermet_core::QuiesceStore>>,
    // The declared relay settings from the daemon config; `None` keeps the core
    // default (`127.0.0.1:7133`, 600s, 32 MiB).
    relay: Option<cermet_core::RelayConfig>,
    // The declared `language_temporal_clauses` setting; `None` keeps the core default (OFF).
    temporal_clauses: Option<bool>,
) -> Result<BrokerHandle, String> {
    spawn_inner(
        config,
        extra_providers,
        sentence_authority,
        SpawnOptions {
            lockdown_source,
            quiesce_store,
            semantic_test: false,
            relay,
            temporal_clauses,
        },
    )
}

fn spawn_inner(
    config: BrokerConfig,
    extra_providers: Vec<Box<dyn Provider>>,
    sentence_authority: Option<Arc<dyn SentenceAuthoritySource>>,
    options: SpawnOptions,
) -> Result<BrokerHandle, String> {
    let SpawnOptions {
        lockdown_source,
        quiesce_store,
        semantic_test,
        relay,
        temporal_clauses,
    } = options;
    let (tx, mut rx) = mpsc::channel::<Cmd>(64);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();

    std::thread::Builder::new()
        .name("cermet-broker".into())
        .spawn(move || {
            #[cfg(feature = "semantic-test")]
            let opened = if semantic_test {
                debug_assert!(quiesce_store.is_none());
                Broker::open_for_semantic_test(config, sentence_authority)
            } else {
                Broker::open_full(config, sentence_authority, quiesce_store)
            };
            #[cfg(not(feature = "semantic-test"))]
            let opened = {
                let _ = semantic_test;
                Broker::open_full(config, sentence_authority, quiesce_store)
            };
            let mut broker = match opened {
                Ok(b) => b,
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
            };
            if let Some(source) = lockdown_source {
                broker.set_lockdown_source(source);
            }
            if let Some(relay) = relay {
                broker.set_relay_config(relay);
            }
            if let Some(enabled) = temporal_clauses {
                broker.set_temporal_clauses(enabled);
            }
            for provider in extra_providers {
                if let Err(e) = broker.register_provider(provider) {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
            }
            let _ = ready_tx.send(Ok(()));
            while let Some(cmd) = rx.blocking_recv() {
                match cmd {
                    Cmd::ListCredentials(reply) => {
                        let _ = reply.send(ser(broker.list_credentials()));
                    }
                    Cmd::ListCredentialsForAgent(reply) => {
                        let _ = reply.send(ser(broker.list_credentials_for_agent()));
                    }
                    Cmd::Connect {
                        provider,
                        token,
                        account_label,
                        reply,
                    } => {
                        let _ = reply.send(ser(broker.connect_credential(
                            &provider,
                            account_label.as_deref(),
                            token.expose_secret(),
                        )));
                    }
                    Cmd::Request {
                        session,
                        request_json,
                        owner_uid,
                        retry_effect,
                        reply,
                    } => {
                        let out = match serde_json::from_str::<CapabilityRequest>(&request_json) {
                            Ok(req) => ser(match retry_effect {
                                Some(effect_id) => broker.request_retry_capability_owned(
                                    &session, req, owner_uid, &effect_id,
                                ),
                                None => broker.request_capability_owned(&session, req, owner_uid),
                            }),
                            Err(e) => Err(Error::Invalid(e.to_string())),
                        };
                        let _ = reply.send(out);
                    }
                    Cmd::RequestForPrincipal {
                        session,
                        principal,
                        request_json,
                        retry_effect,
                        require_open,
                        peer_uid,
                        reply,
                    } => {
                        let out = match serde_json::from_str::<CapabilityRequest>(&request_json) {
                            Ok(req) => ser(match retry_effect {
                                Some(effect_id) => broker
                                    .request_retry_capability_for_principal_open(
                                        &session,
                                        &principal,
                                        &effect_id,
                                        req,
                                        require_open,
                                        peer_uid,
                                    ),
                                None => broker.request_capability_for_principal_open(
                                    &session,
                                    &principal,
                                    req,
                                    require_open,
                                    peer_uid,
                                ),
                            }),
                            Err(e) => Err(Error::Invalid(e.to_string())),
                        };
                        let _ = reply.send(out);
                    }
                    Cmd::Execute {
                        grant_id,
                        session,
                        reply,
                    } => {
                        let _ = reply.send(ser(
                            broker.execute_capability_in_session(&grant_id, &session)
                        ));
                    }
                    Cmd::ExecuteForPrincipal {
                        grant_id,
                        session,
                        principal,
                        reply,
                    } => {
                        let _ = reply
                            .send(ser(broker.execute_capability_for_principal_in_session(
                                &grant_id, &session, &principal,
                            )));
                    }
                    Cmd::ExecuteRequestForPrincipal {
                        request_id,
                        principal,
                        exec_session,
                        exec_pid,
                        require_open,
                        exec_uid,
                        reply,
                    } => {
                        let exec = ExecAttribution {
                            session_id: exec_session,
                            pid: exec_pid,
                            require_session_open: require_open,
                            peer_uid: exec_uid,
                        };
                        let _ = reply.send(ser(broker.execute_request_for_principal_attributed(
                            &request_id,
                            &principal,
                            &exec,
                        )));
                    }
                    Cmd::ExecuteOperator { request_id, reply } => {
                        let _ =
                            reply.send(ser(broker.execute_capability_by_request_id(&request_id)));
                    }
                    Cmd::SweepOverdueLeases(reply) => {
                        let _ = reply.send(broker.sweep_overdue_leases());
                    }
                    Cmd::SweepExpiredBudgetMints(reply) => {
                        let _ = reply.send(broker.sweep_expired_budget_mints());
                    }
                    Cmd::RelayHopStart {
                        handle,
                        method,
                        target,
                        headers,
                        body,
                        reply,
                    } => {
                        let _ = reply.send(
                            broker.relay_hop_start(&handle, &method, &target, &headers, body),
                        );
                    }
                    Cmd::RelayHopHead {
                        handle,
                        effect,
                        status,
                        reply,
                    } => {
                        let _ = reply.send(broker.relay_hop_head(&handle, effect, status));
                    }
                    Cmd::RelayHopComplete { stream, reply } => {
                        let _ = reply.send(broker.relay_hop_complete(stream));
                    }
                    Cmd::SweepRelaySessions(reply) => {
                        let _ = reply.send(broker.sweep_relay_sessions());
                    }
                    Cmd::VerifyAudit(reply) => {
                        let _ = reply.send(ser(broker.verify_integrity()));
                    }
                    Cmd::RecordSentenceCustodyChange {
                        canonical_digest,
                        rule_count,
                        occurrence_id,
                        operator_uid,
                        acceptance_path,
                        prior_record,
                        reply,
                    } => {
                        let _ = reply.send(ser(broker.record_sentence_custody_change_attributed(
                            &canonical_digest,
                            rule_count,
                            &occurrence_id,
                            operator_uid,
                            &acceptance_path,
                            prior_record.as_deref(),
                        )));
                    }
                    Cmd::RecordBrokerStart {
                        custody_profile,
                        reply,
                    } => {
                        let _ =
                            reply.send(ser(broker.record_broker_start(custody_profile.as_deref())));
                    }
                    Cmd::RecordVocabularyRequest {
                        session_id,
                        provider,
                        wanted_verb,
                        wanted_field,
                        gap,
                        ask,
                        rationale,
                        reply,
                    } => {
                        let _ = reply.send(ser(broker.record_vocabulary_request(
                            session_id.as_deref(),
                            &provider,
                            wanted_verb.as_deref(),
                            wanted_field.as_deref(),
                            &gap,
                            ask.as_deref(),
                            rationale.as_deref(),
                        )));
                    }
                    Cmd::RecordLockdownTransition {
                        occurrence_id,
                        engaged,
                        operator_uid,
                        acceptance_path,
                        prior_record,
                        reply,
                    } => {
                        let _ = reply.send(ser(broker.record_lockdown_transition(
                            &occurrence_id,
                            engaged,
                            operator_uid,
                            &acceptance_path,
                            prior_record.as_deref(),
                        )));
                    }
                    Cmd::ValidateSentenceCorpus {
                        candidate_text,
                        reply,
                    } => {
                        let _ = reply.send(ser(
                            broker.prepare_sentence_authority_corpus(&candidate_text)
                        ));
                    }
                    Cmd::CatalogListing(reply) => {
                        let _ = reply.send(ser(broker.catalog_listing()));
                    }
                    Cmd::Status {
                        request_id,
                        principal,
                        reply,
                    } => {
                        let _ = reply.send(ser(
                            broker.request_status_for_principal(&request_id, &principal)
                        ));
                    }
                    Cmd::OpenSession {
                        session_id,
                        agent_cmd,
                        pid,
                        owner_uid,
                        actor,
                        reply,
                    } => {
                        let out = broker
                            .open_session(
                                &session_id,
                                &agent_cmd,
                                pid,
                                owner_uid,
                                cermet_core::broker::SessionActor {
                                    client_name: actor.client_name.as_deref(),
                                    client_version: actor.client_version.as_deref(),
                                    model: actor.model.as_deref(),
                                },
                            )
                            .map(|()| "{\"ok\":true}".to_string());
                        let _ = reply.send(out);
                    }
                    Cmd::CloseSession { session_id, reply } => {
                        let out = broker
                            .close_session(&session_id)
                            .map(|()| "{\"ok\":true}".to_string());
                        let _ = reply.send(out);
                    }
                    Cmd::SessionOpen { session_id, reply } => {
                        let _ = reply.send(ser(broker.session_open(&session_id)));
                    }
                    Cmd::SweepIdleSessions {
                        keep,
                        idle_secs,
                        reply,
                    } => {
                        let _ = reply.send(ser(broker.sweep_idle_sessions(&keep, idle_secs)));
                    }
                    Cmd::History(reply) => {
                        let _ = reply.send(ser(broker.history()));
                    }
                    Cmd::RelayHops(reply) => {
                        let _ = reply.send(ser(broker.relay_hops()));
                    }
                    Cmd::Evidence { request_id, reply } => {
                        let _ = reply.send(ser(broker.request_log(&request_id)));
                    }
                    Cmd::ReadArtifact {
                        handle,
                        addr,
                        surface,
                        reply,
                    } => {
                        let _ = reply.send(ser(broker.read_artifact(&handle, addr, surface)));
                    }
                    Cmd::BeginMcpRepoint { ttl_secs, reply } => {
                        let _ = reply.send(ser(broker.begin_mcp_repoint(ttl_secs)));
                    }
                    Cmd::McpRepointStatus { token, reply } => {
                        let _ = reply.send(ser(broker.mcp_repoint_status(&token)));
                    }
                    Cmd::EndMcpRepoint { token, reply } => {
                        let out = broker
                            .end_mcp_repoint(&token)
                            .map(|()| "{\"ok\":true}".to_string());
                        let _ = reply.send(out);
                    }
                    Cmd::ReleaseExpiredBarrier(reply) => {
                        let _ = reply.send(ser(broker.release_expired_barrier()));
                    }
                    Cmd::AuthorizeRefUpdate { update, reply } => {
                        let verdict = broker.authorize_ref_update(&update);
                        let _ = reply.send(
                            serde_json::to_string(&verdict).map_err(cermet_core::Error::from),
                        );
                    }
                    Cmd::AuthorizeFetch { attempt, reply } => {
                        let verdict = broker.authorize_fetch(&attempt);
                        let _ = reply.send(
                            serde_json::to_string(&verdict).map_err(cermet_core::Error::from),
                        );
                    }
                }
            }
        })
        .map_err(|e| format!("failed to spawn broker thread: {e}"))?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok(BrokerHandle { tx }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("broker thread exited before signalling readiness".to_string()),
    }
}

impl BrokerHandle {
    async fn dispatch(&self, make: impl FnOnce(oneshot::Sender<Reply>) -> Cmd) -> Reply {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(make(reply))
            .await
            .map_err(|_| Error::Provider("broker unavailable".to_string()))?;
        rx.await
            .map_err(|_| Error::Provider("broker dropped reply".to_string()))?
    }

    /// The OPERATOR (ctl) view: every vaulted credential, shelved providers included.
    pub async fn list_credentials(&self) -> Reply {
        self.dispatch(Cmd::ListCredentials).await
    }

    /// The AGENT view — product-enabled providers only, so the model is never told a
    /// shelved provider is connected when every verb it owns fails closed.
    pub async fn list_credentials_for_agent(&self) -> Reply {
        self.dispatch(Cmd::ListCredentialsForAgent).await
    }

    pub async fn connect(
        &self,
        provider: String,
        token: SecretString,
        account_label: Option<String>,
    ) -> Reply {
        self.dispatch(|reply| Cmd::Connect {
            provider,
            token,
            account_label,
            reply,
        })
        .await
    }

    pub async fn request(
        &self,
        session: String,
        request_json: String,
        owner_uid: Option<i64>,
        retry_effect: Option<String>,
    ) -> Reply {
        self.dispatch(|reply| Cmd::Request {
            session,
            request_json,
            owner_uid,
            retry_effect,
            reply,
        })
        .await
    }

    pub async fn request_for_principal(
        &self,
        session: String,
        principal: String,
        request_json: String,
        require_open: bool,
        peer_uid: Option<i64>,
    ) -> Reply {
        self.dispatch(|reply| Cmd::RequestForPrincipal {
            session,
            principal,
            request_json,
            retry_effect: None,
            require_open,
            peer_uid,
            reply,
        })
        .await
    }

    pub async fn request_retry_for_principal(
        &self,
        session: String,
        principal: String,
        request_json: String,
        retry_effect: String,
        require_open: bool,
        peer_uid: Option<i64>,
    ) -> Reply {
        self.dispatch(|reply| Cmd::RequestForPrincipal {
            session,
            principal,
            request_json,
            retry_effect: Some(retry_effect),
            require_open,
            peer_uid,
            reply,
        })
        .await
    }

    pub async fn execute(&self, grant_id: String, session: String) -> Reply {
        self.dispatch(|reply| Cmd::Execute {
            grant_id,
            session,
            reply,
        })
        .await
    }

    pub async fn execute_for_principal(
        &self,
        grant_id: String,
        session: String,
        principal: String,
    ) -> Reply {
        self.dispatch(|reply| Cmd::ExecuteForPrincipal {
            grant_id,
            session,
            principal,
            reply,
        })
        .await
    }

    /// Execute by the agent's stable handle (`request_id`), authorized by principal (uid) — session is
    /// not consulted for authorization. This is the agent-socket execute path. `exec_session` +
    /// `exec_pid` are the executing connection's minted session + peer pid, threaded through as
    /// audit-only attribution so the provider-action event names the actual executor.
    pub async fn execute_request_for_principal(
        &self,
        request_id: String,
        principal: String,
        exec_session: Option<String>,
        exec_pid: Option<i64>,
        require_open: bool,
        exec_uid: Option<i64>,
    ) -> Reply {
        self.dispatch(|reply| Cmd::ExecuteRequestForPrincipal {
            request_id,
            principal,
            exec_session,
            exec_pid,
            require_open,
            exec_uid,
            reply,
        })
        .await
    }

    /// The operator execute path, keyed by `request_id` — the one public id an operator
    /// ever supplies. The broker resolves the grant through the kernel's 1:1 request→grant mapping.
    pub async fn execute_operator(&self, request_id: String) -> Reply {
        self.dispatch(|reply| Cmd::ExecuteOperator { request_id, reply })
            .await
    }

    pub async fn verify_audit(&self) -> Reply {
        self.dispatch(Cmd::VerifyAudit).await
    }

    /// Emit the post-commit sentence-authority custody audit for a now-live generation. Idempotent,
    /// keyed by the per-commit `occurrence_id`. Called by the daemon ctl handler
    /// STRICTLY AFTER the authority record flip, and by boot adoption to replay a lost audit.
    pub async fn record_sentence_custody_change(
        &self,
        canonical_digest: String,
        rule_count: usize,
        occurrence_id: String,
    ) -> Reply {
        self.record_sentence_custody_change_attributed(
            canonical_digest,
            rule_count,
            occurrence_id,
            0,
            "presence".into(),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_sentence_custody_change_attributed(
        &self,
        canonical_digest: String,
        rule_count: usize,
        occurrence_id: String,
        operator_uid: u32,
        acceptance_path: String,
        prior_record: Option<String>,
    ) -> Reply {
        self.dispatch(|reply| Cmd::RecordSentenceCustodyChange {
            canonical_digest,
            rule_count,
            occurrence_id,
            operator_uid,
            acceptance_path,
            prior_record,
            reply,
        })
        .await
    }

    /// CUSTODY-LADDER: record which custody rung this run is on, once, at boot.
    pub async fn record_broker_start(&self, custody_profile: Option<String>) -> Reply {
        self.dispatch(|reply| Cmd::RecordBrokerStart {
            custody_profile,
            reply,
        })
        .await
    }

    /// Record one agent-reported vocabulary request (a verb or field the catalog has no word for,
    /// or the refused probe for one). Append-only data; it authorizes nothing.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_vocabulary_request(
        &self,
        session_id: Option<String>,
        provider: String,
        wanted_verb: Option<String>,
        wanted_field: Option<String>,
        gap: String,
        ask: Option<String>,
        rationale: Option<String>,
    ) -> Reply {
        self.dispatch(|reply| Cmd::RecordVocabularyRequest {
            session_id,
            provider,
            wanted_verb,
            wanted_field,
            gap,
            ask,
            rationale,
            reply,
        })
        .await
    }

    pub async fn record_lockdown_transition(
        &self,
        occurrence_id: String,
        engaged: bool,
        operator_uid: u32,
        acceptance_path: String,
        prior_record: Option<String>,
    ) -> Reply {
        self.dispatch(|reply| Cmd::RecordLockdownTransition {
            occurrence_id,
            engaged,
            operator_uid,
            acceptance_path,
            prior_record,
            reply,
        })
        .await
    }

    /// Daemon-side authority-subset validation of a candidate sentence corpus, run by the ctl
    /// `StageSentences` handler BEFORE staging (secret-class rejection + subset checks).
    pub async fn validate_sentence_corpus(&self, candidate_text: String) -> Reply {
        self.dispatch(|reply| Cmd::ValidateSentenceCorpus {
            candidate_text,
            reply,
        })
        .await
    }

    /// Read-only daemon preparation. It shares the actor command with stage/adoption validation so
    /// there is one parse/pin/semantic/canonical/digest meaning.
    pub async fn prepare_sentence_corpus(&self, candidate_text: String) -> Reply {
        self.validate_sentence_corpus(candidate_text).await
    }

    /// One pass of the daemon's DURABLE custody backstop — terminalize every
    /// executing lease whose HMAC-covered claim-time deadline lapsed unreported. Returns the count.
    pub async fn sweep_overdue_leases(&self) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.tx.send(Cmd::SweepOverdueLeases(tx)).await.is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Authorize and forward ONE relay hop. The loopback listener calls this with the
    /// request exactly as the native client wrote it; every decision is the core's.
    pub async fn relay_hop_start(
        &self,
        handle: String,
        method: String,
        target: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> cermet_core::Result<cermet_core::broker::RelayHopStart> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Cmd::RelayHopStart {
                handle,
                method,
                target,
                headers,
                body,
                reply: tx,
            })
            .await
            .map_err(|_| Error::Provider("the broker is unavailable".into()))?;
        rx.await
            .map_err(|_| Error::Provider("the broker dropped the relay hop".into()))?
    }

    /// Apply what the upstream HEAD alone decides, before the client sees it.
    pub async fn relay_hop_head(
        &self,
        handle: String,
        effect: bool,
        status: u16,
    ) -> cermet_core::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Cmd::RelayHopHead {
                handle,
                effect,
                status,
                reply: tx,
            })
            .await
            .map_err(|_| Error::Provider("the broker is unavailable".into()))?;
        rx.await
            .map_err(|_| Error::Provider("the broker dropped the relay hop".into()))?
    }

    /// Hand a finished hop back to the core, which writes the hop's audit row
    /// and the session's receipt observation.
    pub async fn relay_hop_complete(
        &self,
        stream: cermet_core::broker::RelayHopStream,
    ) -> cermet_core::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Cmd::RelayHopComplete { stream, reply: tx })
            .await
            .map_err(|_| Error::Provider("the broker is unavailable".into()))?;
        rx.await
            .map_err(|_| Error::Provider("the broker dropped the relay hop".into()))?
    }

    /// One pass of the relay-session sweep — close every lapsed session with its
    /// receipt. Returns the count closed.
    pub async fn sweep_relay_sessions(&self) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self.tx.send(Cmd::SweepRelaySessions(tx)).await.is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// One pass of the budget/rate expiry backstop — free the reserved capacity of any
    /// expired budget grant that never crossed the invocation boundary (crash-orphan mint or unclaimed
    /// approved grant). Serialized on the broker thread; returns the count released.
    pub async fn sweep_expired_budget_mints(&self) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self
            .tx
            .send(Cmd::SweepExpiredBudgetMints(tx))
            .await
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Agent discovery: sentence-derived requestable verb schemas.
    pub async fn catalog_listing(&self) -> Reply {
        self.dispatch(Cmd::CatalogListing).await
    }

    /// The live status of a request by its stable `request_id`, BOUND to the caller's principal
    /// (the `status` agent verb). Unknown/ownerless/foreign ids answer one
    /// indistinguishable `NotFound` — there is no unbound form on this handle.
    pub async fn request_status_for_principal(
        &self,
        request_id: String,
        principal: String,
    ) -> Reply {
        self.dispatch(|reply| Cmd::Status {
            request_id,
            principal,
            reply,
        })
        .await
    }

    /// Handshake: mint/record the connection's own agent session (the daemon's agent Hello path).
    pub async fn open_session(
        &self,
        session_id: String,
        agent_cmd: String,
        pid: Option<i64>,
        owner_uid: Option<i64>,
        actor: SelfReported,
    ) -> Reply {
        self.dispatch(|reply| Cmd::OpenSession {
            session_id,
            agent_cmd,
            pid,
            owner_uid,
            actor,
            reply,
        })
        .await
    }

    /// Handshake: close the connection's own agent session on drop.
    pub async fn close_session(&self, session_id: String) -> Reply {
        self.dispatch(|reply| Cmd::CloseSession { session_id, reply })
            .await
    }

    /// Handshake: does `session_id` reference an OPEN session row? Replies a JSON bool.
    pub async fn session_open(&self, session_id: String) -> Reply {
        self.dispatch(|reply| Cmd::SessionOpen { session_id, reply })
            .await
    }

    /// Handshake: sweep sessions idle beyond `idle_secs`, keeping `keep`. Replies the count swept.
    pub async fn sweep_idle_sessions(&self, keep: String, idle_secs: i64) -> Reply {
        self.dispatch(|reply| Cmd::SweepIdleSessions {
            keep,
            idle_secs,
            reply,
        })
        .await
    }

    /// The flat, newest-first grant log across all sessions (App History view).
    pub async fn history(&self) -> Reply {
        self.dispatch(Cmd::History).await
    }

    /// Every chain-verified relay event, newest first (the operator's `--hops` view).
    pub async fn relay_hops(&self) -> Reply {
        self.dispatch(Cmd::RelayHops).await
    }

    /// One operator request's record, by its one public id: verified execution evidence for a
    /// granted request, the recorded denial for a refused one.
    pub async fn evidence(&self, request_id: String) -> Reply {
        self.dispatch(|reply| Cmd::Evidence { request_id, reply })
            .await
    }

    /// Retrieve a stored artifact span by handle (the `artifact` agent verb). Read-only, no secret.
    /// `surface` (agent|ctl) is recorded on the free-but-audited `artifact_read` event.
    pub async fn read_artifact(
        &self,
        handle: String,
        addr: Option<cermet_core::ArtifactAddress>,
        surface: cermet_core::ArtifactReadSurface,
    ) -> Reply {
        self.dispatch(|reply| Cmd::ReadArtifact {
            handle,
            addr,
            surface,
            reply,
        })
        .await
    }

    /// MCP-repoint quiesce barrier (ctl-only). Enter the barrier: serialized with every claim on the
    /// single broker thread, so no new approved→executing claim can race it. Replies a serialized
    /// `McpRepointBegin` (token + instance id + expiry).
    pub async fn begin_mcp_repoint(&self, ttl_secs: i64) -> Reply {
        self.dispatch(|reply| Cmd::BeginMcpRepoint { ttl_secs, reply })
            .await
    }

    /// Classify custody under the barrier (holder-only). Replies a serialized `McpQuiesceStatus`.
    pub async fn mcp_repoint_status(&self, token: String) -> Reply {
        self.dispatch(|reply| Cmd::McpRepointStatus { token, reply })
            .await
    }

    /// End the barrier (holder-only) through the ordered durable release.
    pub async fn end_mcp_repoint(&self, token: String) -> Reply {
        self.dispatch(|reply| Cmd::EndMcpRepoint { token, reply })
            .await
    }

    /// Housekeeping TTL recovery: release a lapsed barrier through the ordered path. Replies a
    /// serialized bool (whether a release occurred).
    pub async fn release_expired_barrier(&self) -> Reply {
        self.dispatch(Cmd::ReleaseExpiredBarrier).await
    }

    /// decide one proposed ref update (and, on allow, carry it upstream). Replies a
    /// serialized [`cermet_core::RefVerdict`].
    pub async fn authorize_ref_update(
        &self,
        update: cermet_core::RefUpdate,
    ) -> Result<cermet_core::RefVerdict, cermet_core::Error> {
        let json = self
            .dispatch(|reply| Cmd::AuthorizeRefUpdate { update, reply })
            .await?;
        serde_json::from_str(&json).map_err(cermet_core::Error::from)
    }

    /// decide one proposed mirror refresh (and, on allow, perform it). Replies a
    /// serialized [`cermet_core::RefVerdict`].
    pub async fn authorize_fetch(
        &self,
        attempt: cermet_core::FetchAttempt,
    ) -> Result<cermet_core::RefVerdict, cermet_core::Error> {
        let json = self
            .dispatch(|reply| Cmd::AuthorizeFetch { attempt, reply })
            .await?;
        serde_json::from_str(&json).map_err(cermet_core::Error::from)
    }
}
