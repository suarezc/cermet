//! `cermet mcp` — the agent's entire interface to Cermet: a thin, keyless bridge over `agent.sock`.
//!
//! The boundary, stated precisely: the agent authenticates by the kernel-attested peer uid
//! (peercred on `agent.sock`). It carries no console token and cannot mutate sentence authority.
//! It references its capability by `request_id` (the stable
//! handle); `grant_id` is operator-internal and the agent-facing wire types cannot even express it.
//! The boundary is a CAPABILITY and a PROCESS boundary. This role holds no master key, opens no
//! credential DB, and invokes no token/ctl path at runtime; all broker authority lives in a process
//! whose kernel uid and filesystem access are the service uid's, which is what the `0700` state
//! dir, the owner-checked key material, and the peercred socket gates actually enforce.
//!
//! What it is NOT, since the ONE-BINARY consolidation: a build-graph exclusion. Cermet ships one
//! executable, so `cermet-core`/`cermet-broker-actor` are linked into the same file this bridge
//! runs from. The `cermet-cli` LIBRARY graph is still keyless and still tested
//! (`tests/keyless.rs`), which is what keeps this module an honest client; but code presence was
//! never privilege — `execve` gives a process the credentials its CALLER chose, nothing installed
//! is setuid or file-capable, and the daemon's bytes were already world-executable before the
//! merge.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cermet_ipc::client::SocketClient;
use cermet_ipc::wire::{AgentRequest, ArtifactRange, AuthorityKind, EffectOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod server;

/// The agent's subcommands — deliberately NARROW. There is no approve, no apply, no connect, and no
/// token surface: those are the human's, behind the ctl path on a separate uid.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentCommand {
    /// Request a scoped capability by provider and action. Prints the sentence decision and the
    /// `request_id` handle.
    Request {
        provider: String,
        action: String,
        resource: Value,
        environment: Option<String>,
        justification: Option<String>,
        retry_effect: Option<String>,
        /// What the AGENT says it is, on THIS request. A self-report the broker stores and no
        /// authority reads; per-request because a mid-session model switch keeps the session.
        model: Option<String>,
    },
    /// Execute a sentence-authorized, single-use grant by its `request_id` (NOT a `grant_id`).
    Execute { request_id: String },
    /// List the connected providers (redacted — no secret ever crosses the wire).
    List,
    /// Verify the audit hash-chain integrity.
    Verify,
    /// Discover the verbs: the per-verb schema of every action you can request or author against.
    Catalog,
    /// Report one vocabulary request — a verb or field the catalog has no word for, or the probe
    /// the bridge refused because the word already exists. The daemon appends it to its event log;
    /// it authorizes nothing.
    RecordVocabularyRequest {
        provider: String,
        wanted_verb: Option<String>,
        wanted_field: Option<String>,
        gap: String,
        ask: Option<String>,
        rationale: Option<String>,
    },
    /// Check where a prior request stands, by its `request_id`.
    Status { request_id: String },
    /// Retrieve a stored artifact by its handle: full, a byte/line range, or a `$.path`
    /// capture-pointer (one JSON sub-value). `range` and `path` are mutually exclusive. Read-only.
    Artifact {
        handle: String,
        range: Option<ArtifactRange>,
        path: Option<String>,
    },
}

impl AgentCommand {
    /// Map to the wire request the daemon's `agent.sock` understands.
    fn to_wire(&self) -> AgentRequest {
        match self {
            AgentCommand::Request {
                provider,
                action,
                resource,
                environment,
                justification,
                retry_effect,
                model,
            } => AgentRequest::Request {
                provider: provider.clone(),
                action: action.clone(),
                resource: resource.clone(),
                environment: environment.clone(),
                justification: justification.clone(),
                model: model.clone(),
                retry_effect: retry_effect.clone(),
                session_id: None,
            },
            AgentCommand::Execute { request_id } => AgentRequest::Execute {
                request_id: request_id.clone(),
                session_id: None,
            },
            AgentCommand::List => AgentRequest::ListCredentials { session_id: None },
            AgentCommand::Verify => AgentRequest::VerifyAudit { session_id: None },
            AgentCommand::Catalog => AgentRequest::Catalog { session_id: None },
            AgentCommand::RecordVocabularyRequest {
                provider,
                wanted_verb,
                wanted_field,
                gap,
                ask,
                rationale,
            } => AgentRequest::RecordVocabularyRequest {
                provider: provider.clone(),
                wanted_verb: wanted_verb.clone(),
                wanted_field: wanted_field.clone(),
                gap: gap.clone(),
                ask: ask.clone(),
                rationale: rationale.clone(),
                session_id: None,
            },
            AgentCommand::Status { request_id } => AgentRequest::Status {
                request_id: request_id.clone(),
                session_id: None,
            },
            AgentCommand::Artifact {
                handle,
                range,
                path,
            } => AgentRequest::Artifact {
                handle: handle.clone(),
                range: range.clone(),
                path: path.clone(),
                session_id: None,
            },
        }
    }
}

/// A rendered result plus whether it counts as success for the process exit code.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentOutput {
    pub text: String,
    /// Maps to the process exit code: `true` → 0, `false` → 1.
    pub ok: bool,
    /// The redacted, TYPED projection of the response — only the known no-secret fields, re-serialized
    /// from a validated view struct. `--json` prints THIS, never the raw daemon `Value`, so a forbidden
    /// key (`grant_id`/`token`/…) the daemon never should send can't be surfaced verbatim.
    pub json: Value,
}

// Typed projections of each agent-facing response. Required fields have no `#[serde(default)]`, so a
// kind-correct frame missing one fails to deserialize → `Malformed` → non-zero exit. Unknown
// keys are ignored by serde and dropped on re-serialize, so the `--json` view is redacted by
// construction.

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestedView {
    kind: String,
    request_id: String,
    decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect_id: Option<String>,
    /// Safe value-free provenance. Absent on legacy daemon frames.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority_kind: Option<AuthorityKind>,
}

/// The kept-vs-total byte counter carried on an HTTP execution (mirrors `cermet_core::WireStats`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireStatsView {
    total_bytes: u64,
    kept_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExecutedView {
    kind: String,
    ok: bool,
    provider: String,
    action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect_outcome: Option<EffectOutcome>,
    result: Value,
    /// The handle for the retained response body — the SAME body `result` carries (the response
    /// contract is verbatim). Additive — an older daemon frame omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifact: Option<String>,
    /// The kept-vs-total byte counter for this execution. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wire_stats: Option<WireStatsView>,
    /// Broker-authored metadata about this response, kept strictly outside `result` —
    /// a setup verb's declared `result_captures` and a GraphQL step's `outcome`/`conflict` verdict.
    /// Absent for every ordinary verb. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    envelope: Option<Value>,
    /// The executor's error string for a FAILED run (`ok:false`) — carried from the durable
    /// terminal receipt so the owner sees WHY it failed. Additive; absent on a successful run and on
    /// an older daemon frame. Already vault-secret-scrubbed at record time (never secret-bearing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialView {
    provider: String,
    reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialsView {
    kind: String,
    credentials: Vec<CredentialView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditView {
    kind: String,
    ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CatalogFieldView {
    name: String,
    #[serde(rename = "type")]
    ty: String,
    required: bool,
    class: String,
    binding: String,
    origin: String,
    /// The predicate forms a sentence may use on this field, already derived daemon-side
    /// from the field's kernel declaration. REQUIRED, like `response` and for the same reason: the
    /// bridge cannot recompute it (the contract lives on the daemon), so a frame without it cannot
    /// answer "what can I WHERE on" and is malformed rather than old. An empty list is a real
    /// answer — nothing may constrain this field.
    forms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CatalogEntryView {
    provider: String,
    action: String,
    fields: Vec<CatalogFieldView>,
    execution_targets: Vec<String>,
    requestable: bool,
    /// The verb's HTTP execution shape — a one-read near-miss cue so an agent can tell e.g. a
    /// git-ref deploy from an inline upload before detouring.
    /// Optional: a cosmetic cue, not a field the projection needs to be honest, so an
    /// older daemon's catalog frame without it must still list verbs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shape: Option<String>,
    /// The verb's RESPONSE CONTRACT — what it returns, what it durably stores, and what
    /// an error gives back. REQUIRED, unlike the cosmetic `shape` above: retention must always
    /// be answerable from the surface, and there is no universal default to
    /// fall back to — the contract is derived per verb from what it actually does. A frame without
    /// it cannot answer the question, so it is a MALFORMED frame, not an older one. No backward
    /// compatibility (repo policy).
    response: ResponseContractView,
    /// Whether the live sentence corpus can cover this verb at all. Computed daemon-side
    /// (the corpus lives there); the bridge only READS it — no re-decision, no second evaluator.
    #[serde(default)]
    sentence_denied: bool,
    /// The canonical text of every standing ALLOW sentence that selects this verb —
    /// selector AND bounds, which is the difference between a request that lands and a deny. NO
    /// rule numbers: the sentence IS the name, matching the log's convention.
    #[serde(default)]
    admitted_by: Vec<String>,
    /// The standing DENY sentences that select this verb. With `admitted_by` empty this
    /// verb is explicitly denied — a standing rule EXISTS and it is not a widening candidate; with
    /// `admitted_by` non-empty it is a carve-out that narrows the allow, and both must render or
    /// the surface overstates.
    #[serde(default)]
    denied_by: Vec<String>,
}

/// What a verb returns, stores, and gives back on an error. Rendered on every
/// catalog line, because a behavior an operator cannot read off a surface does not exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponseContractView {
    returns: String,
    retention: String,
    errors: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CatalogView {
    kind: String,
    catalog: Vec<CatalogEntryView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatusView {
    kind: String,
    request_id: String,
    status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effect_outcome: Option<EffectOutcome>,
    #[serde(default)]
    deny_reason: Option<String>,
    /// The typed run phase, equal to `status`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    termination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_receipt: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactView {
    kind: String,
    handle: String,
    digest: String,
    stored_size: u64,
    size: u64,
    truncated: bool,
    unit: String,
    start: u64,
    end: u64,
    /// The resolved capture-pointer for a `$.path` read (`unit == "path"`); absent for byte/line reads.
    #[serde(default)]
    path: Option<String>,
    content: String,
}

/// Everything that can go wrong driving `agent.sock`.
#[derive(Debug)]
pub enum AgentError {
    /// Bad invocation (unknown subcommand, missing arg, non-JSON `--resource`). The binary exits 2.
    Usage(String),
    /// `agent.sock` could not be reached (absent, or EACCES — the OS boundary itself, when the
    /// caller's uid is not in the socket's group).
    Connect(String),
    /// Framing/transport failure.
    Transport(String),
    /// The daemon returned a fail-closed `Error` envelope (e.g. the opaque "unable to execute").
    Server(String),
    /// An execution error carrying only the broker-derived safe effect handle. The private
    /// idempotency key is structurally absent from the wire type.
    ServerEffect {
        reason: String,
        effect_id: String,
        effect_outcome: Option<EffectOutcome>,
    },
    /// The response did not match the agent protocol.
    Malformed(String),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Usage(m) => write!(f, "{m}"),
            AgentError::Connect(m) => write!(f, "cannot reach agent.sock: {m}"),
            AgentError::Transport(m) => write!(f, "transport error: {m}"),
            AgentError::Server(m) => write!(f, "{m}"),
            AgentError::ServerEffect {
                reason,
                effect_id,
                effect_outcome,
            } => {
                write!(f, "{reason}\neffect_id: {effect_id}")?;
                if let Some(outcome) = effect_outcome {
                    write!(
                        f,
                        "\neffect_outcome: {}\n{}",
                        effect_outcome_name(*outcome),
                        effect_outcome_guidance(*outcome)
                    )?;
                }
                Ok(())
            }
            AgentError::Malformed(m) => write!(f, "malformed response: {m}"),
        }
    }
}

impl std::error::Error for AgentError {}

impl AgentError {
    pub(crate) fn effect_id(&self) -> Option<&str> {
        match self {
            Self::ServerEffect { effect_id, .. } => Some(effect_id),
            _ => None,
        }
    }

    pub(crate) fn effect_outcome(&self) -> Option<EffectOutcome> {
        match self {
            Self::ServerEffect { effect_outcome, .. } => *effect_outcome,
            _ => None,
        }
    }
}

/// The disposition's one word — the type's own, never a second table beside it.
fn effect_outcome_name(outcome: EffectOutcome) -> &'static str {
    outcome.as_str()
}

fn effect_outcome_guidance(outcome: EffectOutcome) -> &'static str {
    match outcome {
        EffectOutcome::PreEffect => "Request a fresh effect; the provider mutation was not invoked.",
        EffectOutcome::Ambiguous => {
            "Use retry_effect with this authenticated effect_id; the broker will reuse its hidden key."
        }
        EffectOutcome::Succeeded | EffectOutcome::DefinitelyFailed => "Do not retry this effect.",
    }
}

/// Split the global `--socket <path>` flag out of argv, returning `(socket_override, remaining_args)`.
/// Pure so `main` can layer the env var + a default on top, and so the split is unit-testable. The
/// flag may appear anywhere and consumes the following token (a dangling trailing `--socket` is
/// dropped). The installed sudoers rule pins `--socket <agent.sock> mcp`, so this split is what makes
/// that argv reach the stdio server.
pub fn split_global_flags(args: &[String]) -> (Option<PathBuf>, Vec<String>) {
    let mut socket = None;
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--socket" => {
                if let Some(p) = it.next() {
                    socket = Some(PathBuf::from(p));
                }
            }
            _ => rest.push(a.clone()),
        }
    }
    (socket, rest)
}

/// One short-lived connection: send the command's request frame, read exactly one response frame. A
/// fail-closed `Error` envelope maps to [`AgentError::Server`] (relaying the daemon's reason
/// verbatim — including the opaque "unable to execute", so no oracle is introduced here); any other
/// well-formed envelope is returned as its decoded [`Value`].
pub fn call(socket_path: &Path, cmd: &AgentCommand) -> Result<Value, AgentError> {
    call_with_session(socket_path, cmd, None)
}

/// As [`call`] but stamps `session_id` onto the wire request. The CLI passes `None` (a
/// per-connection session is minted server-side); the MCP bridge passes its cached conversation
/// session so a whole conversation threads onto ONE server-minted session. A caller-supplied id that
/// no longer references an open session comes back as [`AgentError::Server`] carrying
/// [`cermet_ipc::wire::SESSION_EXPIRED`] — the bridge detects that, re-`Hello`s once, and retries.
pub fn call_with_session(
    socket_path: &Path,
    cmd: &AgentCommand,
    session_id: Option<&str>,
) -> Result<Value, AgentError> {
    call_with_session_clamped(socket_path, cmd, session_id, None)
}

/// As [`call_with_session`], but the connection's read/write deadline is clamped to
/// `max` (the caller's REMAINING wait budget). A bounded tool call (a `request_status` long-poll,
/// an ambiguous reconcile) must honor its advertised wait END-TO-END even when the daemon RPC is
/// slow/contended on the shared connection — the default 30s IPC timeout would blow a 20s status
/// cap on a single stalled read. On timeout the read errors (fail closed → the caller returns
/// "still in progress, poll again", never a fabricated terminal).
pub fn call_with_session_bounded(
    socket_path: &Path,
    cmd: &AgentCommand,
    session_id: Option<&str>,
    max: Duration,
) -> Result<Value, AgentError> {
    call_with_session_clamped(socket_path, cmd, session_id, Some(max))
}

fn call_with_session_clamped(
    socket_path: &Path,
    cmd: &AgentCommand,
    session_id: Option<&str>,
    clamp: Option<Duration>,
) -> Result<Value, AgentError> {
    let mut req = cmd.to_wire();
    req.set_session_id(session_id.map(str::to_string));
    let mut client =
        SocketClient::connect(socket_path).map_err(|e| AgentError::Connect(e.to_string()))?;
    // A caller-supplied clamp (the remaining tool budget) always WINS — it may only
    // SHORTEN the deadline, never lengthen it, so a bounded status/reconcile can't inherit the wide
    // Execute wait or the 30s default.
    if let Some(max) = clamp {
        let _ = client.set_timeout(Some(max));
    }
    let resp = client
        .call(&req)
        .map_err(|e| AgentError::Transport(e.to_string()))?;
    match resp.get("kind").and_then(Value::as_str) {
        Some("error") => {
            let reason = resp
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("unable to complete the request")
                .to_string();
            match resp.get("effect_id").and_then(Value::as_str) {
                Some(effect_id) => Err(AgentError::ServerEffect {
                    reason,
                    effect_id: effect_id.to_string(),
                    effect_outcome: resp
                        .get("effect_outcome")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok()),
                }),
                None => Err(AgentError::Server(reason)),
            }
        }
        Some(_) => Ok(resp),
        None => Err(AgentError::Malformed(format!(
            "response has no kind tag: {resp}"
        ))),
    }
}

/// Handshake: open (mint) a conversation session on `agent.sock` and return its server-minted id.
/// The agent supplies only a DISPLAY name — never an identity (authority is the kernel-attested peer
/// uid). Fail closed: a non-`session` reply is a protocol error.
///
/// The handshake also carries this build's identity, which the daemon requires to EQUAL
/// its own before minting anything. A bridge left running across a reinstall is refused here — with
/// "restart the agent session" — instead of serving an obsolete tool surface.
pub fn hello(
    socket_path: &Path,
    agent: &str,
    report: SelfReport<'_>,
) -> Result<SessionHello, AgentError> {
    let mut client =
        SocketClient::connect(socket_path).map_err(|e| AgentError::Connect(e.to_string()))?;
    let resp = client
        .call(&AgentRequest::Hello {
            agent: agent.to_string(),
            build: cermet_ipc::BUILD_ID.to_string(),
            client_name: report.client_name.map(str::to_string),
            client_version: report.client_version.map(str::to_string),
            model: report.model.map(str::to_string),
        })
        .map_err(|e| AgentError::Transport(e.to_string()))?;
    session_from_frame(&resp)
}

/// What the caller says about ITSELF, carried on the handshake.
///
/// Every field is a self-report and none is an identity: authority is the kernel-attested peer uid,
/// and nothing here is ever consulted by a decision. They exist so this box's own receipts can say
/// which runtime and model produced a request; nothing is sent anywhere.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelfReport<'a> {
    pub client_name: Option<&'a str>,
    pub client_version: Option<&'a str>,
    pub model: Option<&'a str>,
}

/// What the handshake yielded: the server-minted session id, plus what the daemon advertised
/// about ITSELF on the same frame — its negotiated feature labels and its build identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHello {
    pub session_id: String,
    /// The daemon's negotiated feature labels; EMPTY from a daemon that advertised none (fail
    /// closed — no custody vocabulary is assumed).
    pub features: Vec<String>,
    /// The daemon's [`cermet_ipc::BUILD_ID`]; EMPTY from a daemon predating the field, which
    /// [`cermet_ipc::build_skew`] renders as unknown — never as "same build".
    pub build: String,
}

/// Read one hello reply frame. Split from [`hello`] so the OLD-frame tolerance is testable without a
/// socket: each advertised field is read defensively, so a daemon that omits one is a parse SUCCESS
/// carrying an absence, never a protocol error.
fn session_from_frame(resp: &Value) -> Result<SessionHello, AgentError> {
    match resp.get("kind").and_then(Value::as_str) {
        Some("session") => {
            let session_id = resp
                .get("session_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| {
                    AgentError::Malformed("session frame carried no session_id".into())
                })?;
            // The daemon's negotiated feature labels; an old daemon's frame lacks the
            // field entirely — empty means "speaks none of the custody vocabulary" (fail closed).
            let features = resp
                .get("features")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            // WHICH BUILD answered. Absent from a daemon predating the field; the
            // comparison renders that absence as unknown rather than assuming a match.
            let build = resp
                .get("build")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            Ok(SessionHello {
                session_id,
                features,
                build,
            })
        }
        Some("error") => Err(AgentError::Server(
            resp.get("reason")
                .and_then(Value::as_str)
                .unwrap_or("unable to open a session")
                .to_string(),
        )),
        other => Err(AgentError::Malformed(format!(
            "unexpected hello reply kind {other:?}"
        ))),
    }
}

/// Render a (non-error) response `Value` into agent-facing text + an `ok` flag. Pure: no I/O. The
/// rendering is keyed on the command so a kind/command mismatch fails closed as [`AgentError::Malformed`].
pub fn render(cmd: &AgentCommand, resp: &Value) -> Result<AgentOutput, AgentError> {
    let kind = resp
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| AgentError::Malformed(format!("response has no kind tag: {resp}")))?;
    match (cmd, kind) {
        (AgentCommand::Request { .. }, "requested") => render_requested(resp),
        (AgentCommand::Execute { .. }, "executed") => render_executed(resp),
        // Blocking execute: a waiting execute that did NOT run (the wait budget elapsed still
        // pending, or the human denied / it lapsed) comes back as a plain `status` frame — render it
        // like the `status` verb so the caller sees the live state and its next step.
        (AgentCommand::Execute { .. }, "status") => render_status(resp),
        (AgentCommand::List, "credentials") => render_credentials(resp),
        (AgentCommand::Verify, "audit_verified") => render_audit(resp),
        (AgentCommand::Catalog, "catalog") => render_catalog(resp),
        // The acknowledgement carries no payload: the projection is the tag itself.
        (AgentCommand::RecordVocabularyRequest { .. }, "vocabulary_request_recorded") => {
            Ok(AgentOutput {
                text: "vocabulary request recorded".to_string(),
                json: serde_json::json!({ "kind": "vocabulary_request_recorded" }),
                ok: true,
            })
        }
        (AgentCommand::Status { .. }, "status") => render_status(resp),
        (AgentCommand::Artifact { .. }, "artifact") => render_artifact(resp),
        (_, other) => Err(AgentError::Malformed(format!(
            "unexpected response kind {other:?}"
        ))),
    }
}

/// Deserialize `resp` into a typed view `T`, mapping a missing/invalid required field to `Malformed`
/// (fail closed), and return both the parsed view and its redacted re-serialization for `--json`.
fn parse_view<T: Serialize + serde::de::DeserializeOwned>(
    kind: &str,
    resp: &Value,
) -> Result<(T, Value), AgentError> {
    let view: T = serde_json::from_value(resp.clone())
        .map_err(|e| AgentError::Malformed(format!("{kind} frame: {e}")))?;
    let json = serde_json::to_value(&view).map_err(|e| AgentError::Malformed(e.to_string()))?;
    Ok((view, json))
}

/// `dispatch` then `render`.
pub fn run(socket_path: &Path, cmd: &AgentCommand) -> Result<AgentOutput, AgentError> {
    let resp = dispatch(socket_path, cmd)?;
    render(cmd, &resp)
}

/// Drive one command to a renderable response.
pub fn dispatch(socket_path: &Path, cmd: &AgentCommand) -> Result<Value, AgentError> {
    call(socket_path, cmd)
}

fn render_requested(resp: &Value) -> Result<AgentOutput, AgentError> {
    let (r, json): (RequestedView, Value) = parse_view("requested", resp)?;
    let reason = r.reason.as_deref().unwrap_or("");

    let mut text = format!(
        "request_id: {}\ndecision:   {}",
        r.request_id,
        r.decision.to_uppercase()
    );
    if !reason.is_empty() {
        text.push_str(&format!("\nreason:     {reason}"));
    }
    if let Some(effect_id) = &r.effect_id {
        text.push_str(&format!("\neffect_id:  {effect_id}"));
    }
    if r.decision == "deny" {
        if let Some(hint) = r.hint.as_deref().filter(|hint| !hint.is_empty()) {
            text.push_str(&format!("\nhint:       {hint}"));
            // The alternative route is about AUTHORITY, so it only follows an authority decision
            // (`authority_kind` is set on the `policy` deny class alone). The
            // `invalid` class carries a hint of its own — which required field is missing — and "edit the
            // authority block" is not how a caller fixes its own malformed request.
            if r.authority_kind.is_some() {
                text.push_str(
                    "\nalternative: edit the CERMET.md authority block, then run `cermet doc apply`",
                );
            }
        }
    }
    if let Some(authority) = r.authority_kind {
        let authority = match authority {
            AuthorityKind::Sentence => "sentence",
        };
        text.push_str(&format!("\nauthority:  {authority}"));
    }
    match r.decision.as_str() {
        "allow" => {
            text.push_str(&format!(
                "\n→ allowed; run it with the execute_capability tool on this request_id ({})",
                r.request_id
            ));
        }
        "deny" => {
            let authority = match r.authority_kind {
                Some(AuthorityKind::Sentence) => "sentence authority",
                None => "authority",
            };
            text.push_str(&format!("\n→ denied by {authority}."));
        }
        other => return Err(AgentError::Malformed(format!("unknown decision `{other}`"))),
    }
    // A definite sentence decision is a successful round-trip.
    Ok(AgentOutput {
        text,
        ok: true,
        json,
    })
}

/// One broker-metadata value on a receipt line. A string renders as itself — a quoted
/// `"succeeded"` is noise on a line that already names its field — and any other scalar or structure
/// renders as its own compact JSON. This is the value of ONE named field, never the envelope.
fn envelope_field(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn render_executed(resp: &Value) -> Result<AgentOutput, AgentError> {
    let (e, json): (ExecutedView, Value) = parse_view("executed", resp)?;
    let mut text = format!(
        "executed: {}.{}  ({})\n",
        e.provider,
        e.action,
        if e.ok { "ok" } else { "failed" }
    );
    // The receipt SAYS its request id, next to the command that takes it. The friction was
    // an agent holding a relay receipt with no id to chase when its deploy then failed — the id was
    // reachable only by grepping `cermet log` and correlating timestamps.
    if let Some(request_id) = e
        .envelope
        .as_ref()
        .and_then(|envelope| envelope.get("request_id"))
        .and_then(Value::as_str)
    {
        text.push_str(&format!(
            "request_id: {request_id}   (evidence: `cermet log {request_id}`)\n"
        ));
    }
    // A failed run names WHY it failed so the owner is not left an opaque "failed".
    if !e.ok {
        if let Some(err) = e.error.as_deref().filter(|s| !s.is_empty()) {
            text.push_str(&format!("error: {err}\n"));
        }
    }
    if let Some(effect_id) = &e.effect_id {
        text.push_str(&format!("effect_id: {effect_id}\n"));
    }
    if let Some(effect_outcome) = e.effect_outcome {
        text.push_str(&format!(
            "effect_outcome: {}\n{}\n",
            effect_outcome_name(effect_outcome),
            effect_outcome_guidance(effect_outcome)
        ));
    }
    // The relay receipt below names an invocation the CALLER runs with a NATIVE CLI — the
    // broker brings the credential, not the tool. Say so HERE, above the line, when this process's
    // PATH cannot resolve it. The same client-preflight check the operator CLI renders (`render.rs`).
    if let Some(warning) =
        crate::render::relay_tool_warning(&e.result, std::env::var_os("PATH").as_deref())
    {
        text.push_str(&format!("{warning}\n"));
    }
    text.push_str(&format!(
        "result: {}",
        serde_json::to_string_pretty(&e.result).unwrap_or_else(|_| e.result.to_string())
    ));
    // What the BROKER observed about this response, rendered beside the body rather than
    // mixed into it — the `result` above is the provider's own JSON and nothing else.
    //
    // Rendered as INTENTIONAL labeled fields, one per line, and never
    // as a dump of the whole envelope. A raw JSON catch-all is not a rendering: it said the
    // request_id a second time in a second notation, and it printed `{}` for the verbs that author
    // nothing. Identity already has its own line above and is not repeated here; a field nobody
    // named does not render, and an envelope with nothing left renders no line at all.
    for (field, value) in e
        .envelope
        .as_ref()
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(field, _)| field.as_str() != "request_id")
    {
        text.push_str(&format!("\ncermet {field}: {}", envelope_field(value)));
    }
    // The `result` above is the whole provider body; it is also retained as an artifact. Point a cooperative agent at it (fetch a missed field with `artifact <h> --path $.x`)
    // rather than burning a second single-use grant. Only shown when a body was actually retained.
    if let (Some(handle), Some(ws)) = (&e.artifact, &e.wire_stats) {
        text.push_str(&format!(
            "\nfull response retained — artifact {} ({} B, kept {} B)",
            handle, ws.total_bytes, ws.kept_bytes
        ));
        // Receipt legibility: the same fact, STRUCTURED, so a weak model
        // learns there is more without inferring it from byte counts.
        let block = serde_json::json!({
            "truncated": ws.total_bytes > ws.kept_bytes,
            "bytes_total": ws.total_bytes,
            "bytes_kept": ws.kept_bytes,
            "artifact": handle,
            "next_action": "fetch_full_output",
            "full_output": format!(
                "the shown result is a {}-of-{} byte slice; fetch a dropped field via the `artifact` \
                 tool (handle {handle}, e.g. path $.field)",
                ws.kept_bytes, ws.total_bytes
            ),
        });
        text.push_str(&receipt_output_block(&block));
    }
    Ok(AgentOutput {
        text,
        ok: e.ok,
        json,
    })
}

/// Receipt legibility: append the TYPED output block to a receipt so a
/// lower-powered model learns STRUCTURALLY that more output exists and how to get it (the `artifact`
/// tool + handle), never leaving "there is more" to byte-count inference. The broker already holds the
/// kept-vs-total numbers; this only renders them.
fn receipt_output_block(block: &Value) -> String {
    format!(
        "\noutput (structured JSON — full output is retained; fetch it via the `artifact` tool):\n{}\n",
        serde_json::to_string(block).unwrap_or_default()
    )
}

fn render_credentials(resp: &Value) -> Result<AgentOutput, AgentError> {
    let (c, json): (CredentialsView, Value) = parse_view("credentials", resp)?;
    let text = if c.credentials.is_empty() {
        "no providers connected".to_string()
    } else {
        let mut lines = vec![format!("connected providers ({}):", c.credentials.len())];
        for cred in &c.credentials {
            match &cred.account_label {
                Some(a) => lines.push(format!("  {}  {}  ({a})", cred.provider, cred.reference)),
                None => lines.push(format!("  {}  {}", cred.provider, cred.reference)),
            }
        }
        lines.join("\n")
    };
    Ok(AgentOutput {
        text,
        ok: true,
        json,
    })
}

fn render_audit(resp: &Value) -> Result<AgentOutput, AgentError> {
    let (a, json): (AuditView, Value) = parse_view("audit_verified", resp)?;
    let text = if a.ok {
        "audit chain: verified".to_string()
    } else {
        "audit chain: FAILED — integrity not verified".to_string()
    };
    Ok(AgentOutput {
        text,
        ok: a.ok,
        json,
    })
}

/// The two zooms of the ONE catalog noun. `Allowed` is the CONTRACT — only the verbs a
/// standing sentence admits, one compact line each, carrying the admitting sentence and its bounds;
/// it answers "what can I actually do right now". `All` is the DICTIONARY — every vendored verb, in
/// full, each stamped with its authority status, so a proposal to the operator names a real verb
/// with real fields. Mirrors `check`: same noun, two zooms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogZoom {
    Allowed,
    All,
}

/// Which SURFACE this projection is being rendered for. The projection itself — which
/// verbs, which fields, which sentences, which authority stamp — is identical and lives once, right
/// here; only the three *next-step* phrases differ, because the two surfaces genuinely have
/// different vocabulary. Telling a terminal operator to "call catalog with scope=\"all\"" names a
/// parameter their CLI does not have, and telling an MCP agent to run `cermet catalog --all` names
/// a binary it is not holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogSurface {
    /// The MCP `catalog` tool: zooms are the `scope` parameter, requests go through
    /// `request_capability`.
    Mcp,
    /// `cermet catalog` / `cermet catalog --all`: zooms are a flag, requests go through `cermet run`.
    Cli,
}

impl CatalogSurface {
    /// How to reach the DICTIONARY zoom from here.
    fn all_zoom(self) -> &'static str {
        match self {
            Self::Mcp => "`catalog` with scope=\"all\"",
            Self::Cli => "`cermet catalog --all`",
        }
    }

    /// How to reach the CONTRACT zoom from here.
    fn allowed_zoom(self) -> &'static str {
        match self {
            Self::Mcp => "`catalog` with scope=\"allowed\"",
            Self::Cli => "`cermet catalog`",
        }
    }

    /// What happens if you go ahead and request a verb no sentence admits — the one path through an
    /// authority gap, in this surface's words.
    fn unruled_path(self) -> &'static str {
        match self {
            Self::Mcp => {
                "`request_capability` on an unruled verb returns a DENY carrying a widening \
                 suggestion for your operator — relay that suggestion, do not retry the request"
            }
            Self::Cli => {
                "`cermet run <provider>.<action>` on an unruled verb denies and prints a widening \
                 suggestion — take that suggestion to whoever holds authority, do not retry the run"
            }
        }
    }
}

/// True when this verb is on the surface right now: the broker has it loaded AND the live corpus
/// admits it. Both bits are decided daemon-side; this is a read, not a re-decision.
fn entry_is_allowed(e: &CatalogEntryView) -> bool {
    e.requestable && !e.sentence_denied
}

/// The DICTIONARY entry's authority stamp — the four cases [`admission_line`] spells out, compressed
/// to the bracket tag on the verb's own line, off the same joined data, so the two can never
/// disagree.
///
/// The stamp used to be `[requestable]` / `[needs ratify]`, which report the BROKER's
/// loading state, not the caller's authority — and an agent read `[requestable]` as
/// "currently permitted" and spent its budget requesting verbs no sentence admitted. Every stamp
/// now answers the only question the dictionary is consulted for: may I call this right now. Only
/// the admitted case may read as permission.
fn authority_stamp(e: &CatalogEntryView) -> &'static str {
    if entry_is_allowed(e) {
        "allowed now"
    } else if !e.denied_by.is_empty() {
        // An explicit deny is settled: not a widening candidate, not worth proposing.
        "denied — not requestable"
    } else if !e.admitted_by.is_empty() {
        // A sentence selects it, but this broker does not hold the verb.
        "not available on this broker — a request denies"
    } else {
        "no standing sentence — ask the operator for one"
    }
}

/// The git plane's verbs are not reached through a request at all — they are exercised by running
/// git in a wired repository. A catalog entry that names only the shape leaves an agent in a NEW
/// repo with nothing to act on, so the entry states the wiring command
/// literally. `None` for every other execution shape.
fn git_plane_hint(e: &CatalogEntryView, indent: &str) -> Option<String> {
    (e.shape.as_deref() == Some("git_push")).then(|| {
        format!(
            "{indent}exercised via plain `git push` / `git fetch`, never a request; route a \
             repository through the broker with `{}` (or `git remote add origin \
             cermet::github/<owner>/<repo>` in a fresh repo)",
            cermet_lang::provider::GIT_WIRING_COMMAND
        )
    })
}

/// A relay verb is not reached by a request either: the broker authorizes a scoped session and
/// credentials a native client's OWN outbound calls, so the request answers with an invocation
/// rather than an effect. The entry says which tool runs it, the same way the git-plane entry says
/// which command wires the repository. `None` for every other execution shape.
fn relay_hint(e: &CatalogEntryView, indent: &str) -> Option<String> {
    (e.shape.as_deref() == Some("relay")).then(|| {
        format!(
            "{indent}exercised by running the native `{}` CLI against the invocation this request \
             prints; the broker supplies the credential, you supply the tool",
            e.provider
        )
    })
}

/// The compact CONTRACT view: one line per admitted verb — the fields the agent supplies, the
/// execution shape, and every sentence that admits it with its bounds. The point: an agent that
/// must otherwise cross-join a 69-verb dictionary against a terse rule list reads its standing
/// authority in one screen.
fn render_allowed_catalog(c: &CatalogView, surface: CatalogSurface) -> String {
    let allowed: Vec<&CatalogEntryView> =
        c.catalog.iter().filter(|e| entry_is_allowed(e)).collect();
    if allowed.is_empty() {
        return format!(
            "allowed now (0 verbs): no standing sentence admits any loaded verb on this box.\n\
             Nothing can be requested until your operator authors one. {} is the dictionary of \
             verbs that EXIST — ask the operator for the sentence you need from it, and note that \
             {}.",
            surface.all_zoom(),
            surface.unruled_path()
        );
    }
    let mut lines = vec![format!(
        "allowed now ({} verbs) — a standing sentence admits each of these; request it directly.",
        allowed.len()
    )];
    for e in allowed {
        let fields: Vec<String> = e
            .fields
            .iter()
            .filter(|f| f.origin == "agent_request")
            .map(|f| {
                let optional = if f.required { "" } else { "?" };
                format!("{}{optional}:{}", f.name, f.ty)
            })
            .collect();
        let shape = e.shape.as_deref().unwrap_or("unknown");
        let admitted = if e.admitted_by.is_empty() {
            "allowed by a standing sentence".to_string()
        } else {
            format!("allowed by: {}", e.admitted_by.join(" | "))
        };
        lines.push(format!(
            "  {}.{}({}) [{shape}] — {admitted}",
            e.provider,
            e.action,
            fields.join(", ")
        ));
        lines.extend(git_plane_hint(e, "      "));
        lines.extend(relay_hint(e, "      "));
        // A carve-out deny narrows this allow. It gets its own line even in the compact
        // zoom — a contract that shows the allow and hides the exception overstates capability,
        // which is the one thing this view exists to stop.
        for deny in &e.denied_by {
            lines.push(format!("      except: {deny}"));
        }
    }
    lines.push(format!(
        "\nThe bounds ARE the authority: a request outside them denies. `?` marks an optional \
         field; provider-resolved fields are omitted (the broker fills those). Everything else this \
         box knows is in {} — the full dictionary, every entry stamped with its authority status. \
         An unruled verb is still reachable: {}.",
        surface.all_zoom(),
        surface.unruled_path()
    ));
    lines.join("\n")
}

/// The authority line(s) every DICTIONARY entry carries: nothing on the agent surface may overstate
/// capability, so each entry says which sentences select it and what that means for a request.
/// Sentences render bare — no rule numbers; the sentence text is the name.
fn admission_line(e: &CatalogEntryView) -> String {
    let mut lines = Vec::new();
    if entry_is_allowed(e) {
        match e.admitted_by.split_first() {
            Some((first, rest)) => {
                lines.push(format!("    allowed by: {first}"));
                lines.extend(rest.iter().map(|a| format!("    also: {a}")));
            }
            None => lines.push("    allowed by a standing sentence".to_string()),
        }
        // A carve-out under a live allow is part of this verb's authority.
        lines.extend(e.denied_by.iter().map(|d| format!("    except: {d}")));
        return lines.join("\n");
    }
    // An EXPLICIT deny is not an authority gap and not a widening candidate — the
    // evaluator yields no widening hint for one, and promising the agent otherwise sends it to its
    // operator with a request that cannot be granted by widening anything.
    if let Some((first, rest)) = e.denied_by.split_first() {
        lines.push(format!(
            "    denied by: {first} — do not request this; an explicit deny is not a widening \
             candidate"
        ));
        lines.extend(rest.iter().map(|d| format!("    also denied by: {d}")));
        return lines.join("\n");
    }
    match e.admitted_by.first() {
        Some(a) => format!(
            "    a standing rule selects this verb ({a}), but it is not available on this broker \
             right now — a request will deny"
        ),
        None => "    no standing rule — a request will deny with a widening suggestion for the \
                 operator"
            .to_string(),
    }
}

fn render_catalog(resp: &Value) -> Result<AgentOutput, AgentError> {
    render_catalog_zoom(resp, CatalogZoom::All, CatalogSurface::Mcp)
}

/// The ONE catalog projection, rendered for whichever surface asked. Both `cermet catalog`
/// and the MCP `catalog` tool land here on a frame the daemon already joined — nothing below
/// re-decides authority, and neither caller holds a second copy of this.
pub(crate) fn render_catalog_zoom(
    resp: &Value,
    zoom: CatalogZoom,
    surface: CatalogSurface,
) -> Result<AgentOutput, AgentError> {
    let (c, _): (CatalogView, Value) = parse_view("catalog", resp)?;
    let json = serde_json::to_value(&c).map_err(|e| AgentError::Malformed(e.to_string()))?;
    if zoom == CatalogZoom::Allowed {
        return Ok(AgentOutput {
            text: render_allowed_catalog(&c, surface),
            ok: true,
            json,
        });
    }
    let text = if c.catalog.is_empty() {
        "no verbs available".to_string()
    } else {
        let mut lines = vec![format!("verbs ({}):", c.catalog.len())];
        for e in &c.catalog {
            let tag = authority_stamp(e);
            let shape = e
                .shape
                .as_deref()
                .map(|s| format!(" shape:{s}"))
                .unwrap_or_default();
            lines.push(format!("  {}.{}  [{tag}]{shape}", e.provider, e.action));
            let fields: Vec<String> = e
                .fields
                .iter()
                .map(|f| {
                    let req = if f.required { "" } else { "?" };
                    // The WHERE index, exactly as the daemon derived it from this
                    // field's declaration. `[none]` is a statement, not a gap.
                    let forms = if f.forms.is_empty() {
                        "none".to_string()
                    } else {
                        f.forms.join(" ")
                    };
                    format!(
                        "{}{req}:{} ({}, {}) [{forms}]",
                        f.name, f.ty, f.class, f.origin
                    )
                })
                .collect();
            lines.push(format!("    fields: {}", fields.join(", ")));
            lines.push(format!(
                "    execution_targets: {}",
                e.execution_targets.join(", ")
            ));
            // What this verb RETURNS and what it durably KEEPS, on the line where an
            // operator reads the verb. `stored: full` is the default and the norm; `stored: none`
            // is the money floor and the few verbs that declare a justified exception.
            lines.push(format!(
                "    response: returns: {} | stored: {} | errors: {}",
                e.response.returns, e.response.retention, e.response.errors
            ));
            lines.extend(git_plane_hint(e, "    "));
            lines.extend(relay_hint(e, "    "));
            // The dictionary is for PROPOSING, so every entry states its authority —
            // an entry that only says "requestable" overstates what the agent may actually do.
            lines.push(admission_line(e));
        }
        // The notation, once. Per-field it would cost a line per field and still not say
        // what `budget` means; `rate` has no per-field meaning at all, so it is named only here.
        //
        // The temporal half of the legend prints only when the daemon's own frame actually carries
        // a `budget` form (temporal clauses are gated OFF by default, and the daemon drops
        // `budget` from the index when they are). The legend explains the
        // index it is printed beside; teaching a clause no field advertises — and that corpus
        // admission would refuse — would send an agent to author a guaranteed deny.
        let temporal_live = c.catalog.iter().any(|e| {
            e.fields
                .iter()
                .any(|f| f.forms.iter().any(|form| form == "budget"))
        });
        let mut legend =
            "\nfields: `?` marks an optional field. The bracket after a field is what \
             a SENTENCE may do to it: `=` and `in` pin values, `<=`/`>=` bound an integer, and \
             `[none]` means no sentence may constrain it at all."
                .to_string();
        if temporal_live {
            legend.push_str(
                " `budget` means a `budget <n> per <window>` aggregate may sum that field. \
                 `rate <n> per <window>` is verb-level — it meters admissions, not a field, so it \
                 never appears on one.",
            );
        }
        lines.push(legend);
        lines.push(format!(
            "\nresponse: `returns: verbatim` — the provider's body, unedited. `stored: full` is the \
             DEFAULT: that body is durably retained as an artifact on this box, provider material \
             (customer objects, PII, bearer values) included. `stored: none` means no artifact is \
             kept; it is the money floor and a small number of justified exceptions.\n\
             \nThis is the DICTIONARY — what exists, not what you may do. The verbs you may request \
             right now are the `[allowed now]` ones (an `except:` line under one narrows it); that \
             shorter list alone is {}. A `denied by:` entry is settled — do not request it and do \
             not propose it. For anything UNRULED, name the verb and its fields to your operator as \
             the sentence you need: {}.",
            surface.allowed_zoom(),
            surface.unruled_path()
        ));
        lines.join("\n")
    };
    Ok(AgentOutput {
        text,
        ok: true,
        json,
    })
}

fn render_status(resp: &Value) -> Result<AgentOutput, AgentError> {
    let (s, json): (StatusView, Value) = parse_view("status", resp)?;
    let hint = match (s.status.as_str(), s.outcome.as_deref(), s.effect_outcome) {
        ("ready", _, _) => "  → ready; run it with the execute_capability tool on this request_id",
        ("running", _, _) => "  → running; poll status again",
        ("terminal", Some("denied"), _) => "  → terminal: denied; do not retry",
        ("terminal", Some("abandoned"), Some(EffectOutcome::Ambiguous)) => {
            "  → terminal: abandoned after effect start; retry only the same effect"
        }
        ("terminal", Some("abandoned"), _) => "  → terminal: abandoned; request it again",
        ("terminal", _, _) => "  → terminal; grants are single-use",
        _ => "",
    };
    let mut text = format!(
        "request_id: {}\nstatus:     {}{hint}",
        s.request_id, s.status
    );
    if let Some(reason) = &s.deny_reason {
        text.push_str(&format!("\nreason:     {reason}"));
    }
    if let Some(effect_id) = &s.effect_id {
        text.push_str(&format!("\neffect_id:  {effect_id}"));
    }
    if let Some(effect_outcome) = s.effect_outcome {
        text.push_str(&format!(
            "\neffect_outcome: {}\n{}",
            effect_outcome_name(effect_outcome),
            effect_outcome_guidance(effect_outcome)
        ));
    }
    Ok(AgentOutput {
        text,
        ok: true,
        json,
    })
}

fn render_artifact(resp: &Value) -> Result<AgentOutput, AgentError> {
    let (a, json): (ArtifactView, Value) = parse_view("artifact", resp)?;
    let mut text = format!(
        "artifact:   {}\ndigest:     {}\nsize:       {} bytes ({} stored{})\n",
        a.handle,
        a.digest,
        a.size,
        a.stored_size,
        if a.truncated { ", truncated" } else { "" },
    );
    match a.path.as_deref() {
        Some(p) => text.push_str(&format!("path:       {p}\n")),
        None => text.push_str(&format!("span:       {} {}..{}\n", a.unit, a.start, a.end)),
    }
    text.push_str("---\n");
    text.push_str(&a.content);
    Ok(AgentOutput {
        text,
        ok: true,
        json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// The hello reply carries what the daemon advertised about ITSELF. A frame from a
    /// daemon predating the build field must still parse — its build reads as ABSENT (empty), which
    /// the skew comparison treats as unknown, never as "same build".
    #[test]
    fn a_session_frame_carries_the_daemons_build_and_an_old_one_still_parses() {
        let current = session_from_frame(&json!({
            "kind": "session",
            "session_id": "sess_1",
            "features": ["custody_proof_v1"],
            "build": "0.1.0+abc123",
        }))
        .expect("a current session frame parses");
        assert_eq!(current.session_id, "sess_1");
        assert_eq!(current.features, vec!["custody_proof_v1".to_string()]);
        assert_eq!(current.build, "0.1.0+abc123");

        let old = session_from_frame(&json!({ "kind": "session", "session_id": "sess_1" }))
            .expect("a session frame from before the field existed still parses");
        assert!(old.features.is_empty());
        assert_eq!(old.build, "", "absence, never a claimed match");
        assert_eq!(
            cermet_ipc::build_skew(&old.build),
            Some(cermet_ipc::UNKNOWN_BUILD)
        );
    }

    /// The sudoers rule the installer mints is `<cli> --socket <agent.sock> mcp`, so the global
    /// split must strip `--socket` from anywhere in that argv and leave `mcp` as the command.
    #[test]
    fn split_global_flags_extracts_the_socket_anywhere() {
        let (socket, rest) = split_global_flags(&argv(&["--socket", "/tmp/a.sock", "mcp"]));
        assert_eq!(socket, Some(PathBuf::from("/tmp/a.sock")));
        assert_eq!(rest, argv(&["mcp"]));

        let (socket, rest) = split_global_flags(&argv(&["mcp", "--socket", "/tmp/a.sock"]));
        assert_eq!(socket, Some(PathBuf::from("/tmp/a.sock")));
        assert_eq!(rest, argv(&["mcp"]));

        let (socket, rest) = split_global_flags(&argv(&["mcp"]));
        assert_eq!(socket, None);
        assert_eq!(rest, argv(&["mcp"]));
    }

    #[test]
    fn render_requested_allow_and_deny_branch_correctly() {
        let cmd = AgentCommand::Request {
            provider: "vercel".into(),
            action: "deploy".into(),
            resource: Value::Null,
            environment: None,
            justification: None,
            retry_effect: None,
            model: None,
        };
        let allow = render(
            &cmd,
            &json!({
            "kind":"requested","request_id":"rq-a","decision":"allow",
            "reason":"sentence match","authority_kind":"sentence",
            "effect_id":"effect_0123456789abcdef0123456789abcdef"
            }),
        )
        .unwrap();
        assert!(allow.text.contains("ALLOW"));
        // The next step names the MCP tool, not a deleted `cermet mcp execute` one-shot.
        assert!(allow.text.contains("execute_capability"), "{}", allow.text);
        assert!(allow.text.contains("rq-a"));
        assert!(!allow.text.contains("cermet mcp"), "{}", allow.text);
        assert!(allow.text.contains("authority:  sentence"));
        assert_eq!(allow.json["authority_kind"], json!("sentence"));
        assert_eq!(
            allow.json["effect_id"],
            "effect_0123456789abcdef0123456789abcdef"
        );
        assert!(allow.text.contains("effect_id:"));
        assert!(!allow.text.to_lowercase().contains("approval"));

        let deny = render(
            &cmd,
            &json!({
            "kind":"requested","request_id":"rq-d","decision":"deny",
            "reason":"outside sentence","authority_kind":"sentence"
            }),
        )
        .unwrap();
        assert!(deny.text.contains("DENY"));
        assert!(deny.text.contains("denied by sentence authority"));
        assert!(deny.ok, "deny is a valid answer, exit 0");

        let sentence_deny = render(
            &cmd,
            &json!({
            "kind":"requested","request_id":"rq-sd","decision":"deny",
            "reason":"outside sentence","authority_kind":"sentence"
            }),
        )
        .unwrap();
        assert!(sentence_deny.text.contains("denied by sentence authority"));
        assert!(!sentence_deny.text.contains("fingerprint"));
        assert!(!sentence_deny.text.contains("selector"));
    }

    #[test]
    fn render_requested_preserves_the_advisory_widen_hint() {
        let hint = "to allow: cermet rules allow 'stripe.support@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa where amount <= 50000'";
        let cmd = AgentCommand::Request {
            provider: "stripe".into(),
            action: "refund".into(),
            resource: Value::Null,
            environment: None,
            justification: None,
            retry_effect: None,
            model: None,
        };
        let out = render(
            &cmd,
            &json!({
            // A POLICY deny is the only class that carries `authority_kind` (broker
            // `lifecycle::deny`), and it is what makes the authority-editing alternative apt.
            "kind":"requested","request_id":"rq-m2","decision":"deny",
            "reason":"outside rule","hint":hint,"authority_kind":"sentence"
            }),
        )
        .unwrap();

        assert_eq!(out.json["hint"], json!(hint));
        assert!(
            out.text.contains(hint),
            "the agent renderer must carry the exact safe hint"
        );
        assert!(out.text.contains("CERMET.md"));
        assert!(out.text.contains("cermet doc apply"));

        // The `invalid` class now carries a hint too (which required field is missing),
        // and it carries no `authority_kind` — so the hint renders while the authority-editing
        // alternative, which would be wrong advice for a malformed request, does not.
        let invalid = render(
            &cmd,
            &json!({
            "kind":"requested","request_id":"rq-m3","decision":"deny",
            "reason":"required field `amount` absent for stripe.refund",
            "hint":"missing required field `amount` — resend the request naming it"
            }),
        )
        .unwrap();
        assert!(invalid.text.contains("missing required field `amount`"));
        assert!(
            !invalid.text.contains("CERMET.md"),
            "a malformed request is not fixed by editing authority: {}",
            invalid.text
        );
    }
    #[test]
    fn render_credentials_empty_and_nonempty() {
        let empty = render(
            &AgentCommand::List,
            &json!({"kind":"credentials","credentials":[]}),
        )
        .unwrap();
        assert!(empty.text.contains("no providers connected"));

        let some = render(&AgentCommand::List, &json!({
            "kind":"credentials","credentials":[
                {"reference":"vercel:default","provider":"vercel","account_label":"acme","created_at":"t"}
            ]
        })).unwrap();
        assert!(some.text.contains("vercel"));
        assert!(some.text.contains("vercel:default"));
        assert!(some.text.contains("acme"));
    }

    #[test]
    fn render_audit_ok_and_failed() {
        assert!(
            render(
                &AgentCommand::Verify,
                &json!({"kind":"audit_verified","ok":true})
            )
            .unwrap()
            .ok
        );
        let bad = render(
            &AgentCommand::Verify,
            &json!({"kind":"audit_verified","ok":false}),
        )
        .unwrap();
        assert!(!bad.ok);
        assert!(bad.text.contains("FAILED"));
    }

    #[test]
    fn render_rejects_kind_command_mismatch() {
        // An execute command must never accept a `requested` frame as a result (fail closed).
        let err = render(
            &AgentCommand::Execute {
                request_id: "rq".into(),
            },
            &json!({"kind":"requested","request_id":"rq","decision":"deny"}),
        )
        .expect_err("mismatch must fail");
        assert!(matches!(err, AgentError::Malformed(_)), "got {err:?}");
    }

    // ---- a kind-correct frame missing a required field must FAIL CLOSED, never exit 0 ----

    #[test]
    fn render_requested_missing_required_field_fails_closed() {
        let cmd = AgentCommand::Request {
            provider: "vercel".into(),
            action: "deploy".into(),
            resource: Value::Null,
            environment: None,
            justification: None,
            retry_effect: None,
            model: None,
        };
        for resp in [
            json!({"kind":"requested","decision":"deny"}),
            json!({"kind":"requested","request_id":"rq"}),
        ] {
            let err = render(&cmd, &resp).expect_err("missing required field must fail closed");
            assert!(
                matches!(err, AgentError::Malformed(_)),
                "got {err:?} for {resp}"
            );
        }
    }

    #[test]
    fn render_executed_missing_required_field_fails_closed() {
        let cmd = AgentCommand::Execute {
            request_id: "rq".into(),
        };
        for resp in [
            json!({"kind":"executed","ok":true,"provider":"vercel","result":null}), // no action
            json!({"kind":"executed","ok":true,"action":"deploy","result":null}),   // no provider
        ] {
            let err = render(&cmd, &resp).expect_err("missing required field must fail closed");
            assert!(
                matches!(err, AgentError::Malformed(_)),
                "got {err:?} for {resp}"
            );
        }
    }

    // ---- --json prints the TYPED projection, so a forbidden key can't be surfaced verbatim ----

    #[test]
    fn json_projection_drops_forbidden_keys() {
        let cmd = AgentCommand::Request {
            provider: "vercel".into(),
            action: "deploy".into(),
            resource: Value::Null,
            environment: None,
            justification: None,
            retry_effect: None,
            model: None,
        };
        let resp = json!({
            "kind":"requested","request_id":"rq-7","decision":"deny",
            "grant_id":"GRANT-LEAK","token":"SEKRIT",
        });
        let out = render(&cmd, &resp).unwrap();
        let s = serde_json::to_string(&out.json).unwrap();
        assert!(
            !s.contains("grant_id") && !s.contains("GRANT-LEAK"),
            "--json leaked grant_id: {s}"
        );
        assert!(
            !s.contains("token") && !s.contains("SEKRIT"),
            "--json leaked token: {s}"
        );
        assert!(
            s.contains("rq-7"),
            "the legitimate request_id must survive the projection: {s}"
        );
    }

    #[test]
    fn to_wire_maps_every_command() {
        assert!(matches!(
            AgentCommand::List.to_wire(),
            AgentRequest::ListCredentials { .. }
        ));
        assert!(matches!(
            AgentCommand::Verify.to_wire(),
            AgentRequest::VerifyAudit { .. }
        ));
        assert!(matches!(
            AgentCommand::Execute {
                request_id: "x".into()
            }
            .to_wire(),
            AgentRequest::Execute { .. }
        ));
        assert!(matches!(
            AgentCommand::Request {
                provider: "p".into(),
                action: "a".into(),
                resource: Value::Null,
                environment: None,
                justification: None,
                retry_effect: None,
                model: None,
            }
            .to_wire(),
            AgentRequest::Request { .. }
        ));
        assert!(matches!(
            AgentCommand::Catalog.to_wire(),
            AgentRequest::Catalog { .. }
        ));
        assert!(matches!(
            AgentCommand::Status {
                request_id: "rq".into()
            }
            .to_wire(),
            AgentRequest::Status { .. }
        ));
        assert!(matches!(
            AgentCommand::Artifact {
                handle: "art_1".into(),
                range: None,
                path: None
            }
            .to_wire(),
            AgentRequest::Artifact { .. }
        ));
    }

    #[test]
    fn render_artifact_shows_span_and_content() {
        let resp = json!({
            "kind": "artifact", "handle": "art_1", "digest": "deadbeef",
            "stored_size": 12, "size": 12, "truncated": false,
            "unit": "bytes", "start": 0, "end": 12, "content": "hello output"
        });
        let out = render(
            &AgentCommand::Artifact {
                handle: "art_1".into(),
                range: None,
                path: None,
            },
            &resp,
        )
        .unwrap();
        assert!(out.ok);
        assert!(out.text.contains("art_1"));
        assert!(out.text.contains("deadbeef"));
        assert!(out.text.contains("hello output"));
    }

    #[test]
    fn render_catalog_states_each_verbs_response_contract() {
        let resp = json!({
            "kind": "catalog",
            "catalog": [
                { "provider": "stripe", "action": "get_charge",
                  "fields": [], "execution_targets": ["charge"], "requestable": true, "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"},
                  "response": { "returns": "verbatim", "retention": "full",
                                "errors": "status_and_body" } },
                { "provider": "stripe", "action": "refund_charge_bounded",
                  "fields": [], "execution_targets": ["charge"], "requestable": true, "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"},
                  "response": { "returns": "verbatim", "retention": "none",
                                "errors": "status_and_body" } }
            ]
        });
        let out = render(&AgentCommand::Catalog, &resp).unwrap();
        assert!(out.ok);
        assert!(
            out.text.contains("returns: verbatim"),
            "every verb states what it returns: {}",
            out.text
        );
        assert!(
            out.text.contains("stored: full") && out.text.contains("stored: none"),
            "the DEFAULT and the money floor are both visible, per verb: {}",
            out.text
        );
        assert!(
            out.text.contains("errors: status_and_body"),
            "the error surface is stated too: {}",
            out.text
        );
    }

    /// A frame WITHOUT the response declaration is malformed, not merely old. Retention must
    /// always be answerable from the surface; a listing that renders without it would answer
    /// "unknown" while looking successful, which is exactly the failure mode to prevent. No
    /// backward compatibility (repo policy).
    #[test]
    fn render_catalog_refuses_a_frame_without_a_response_contract() {
        let resp = json!({
            "kind": "catalog",
            "catalog": [
                { "provider": "vercel", "action": "deploy",
                  "fields": [], "execution_targets": ["project"], "requestable": true }
            ]
        });
        let error = render(&AgentCommand::Catalog, &resp)
            .expect_err("a catalog frame that cannot state what a verb keeps is malformed");
        assert!(
            matches!(error, AgentError::Malformed(_)),
            "the refusal must be the malformed-frame class: {error:?}"
        );
    }

    /// `shape` is a cosmetic cue — a catalog frame from an older daemon that lacks it
    /// must still list verbs, not fail the whole listing as Malformed.

    #[test]
    fn render_status_maps_states_to_next_step() {
        for (st, outcome, needle) in [
            ("ready", None, "execute"),
            ("running", None, "poll"),
            ("terminal", Some("denied"), "do not retry"),
            ("terminal", Some("succeeded"), "single-use"),
            ("terminal", Some("abandoned"), "again"),
        ] {
            let resp = json!({ "kind": "status", "request_id": "rq-1", "status": st, "outcome": outcome,
                "effect_id":"effect_0123456789abcdef0123456789abcdef"
            });
            let out = render(
                &AgentCommand::Status {
                    request_id: "rq-1".into(),
                },
                &resp,
            )
            .unwrap();
            assert!(out.ok);
            assert!(out.text.contains(st), "names the status: {}", out.text);
            assert!(
                out.text.contains("effect_id:"),
                "keeps the safe retry handle"
            );
            assert!(
                out.text.contains(needle),
                "guides next step for {st}: {}",
                out.text
            );
        }
    }

    #[test]
    fn abandoned_started_money_status_never_advises_a_fresh_request() {
        let resp = json!({
            "kind": "status",
            "request_id": "rq-money-abandoned",
            "status": "terminal",
            "outcome": "abandoned",
            "effect_id": "effect_authenticated",
            "effect_outcome": "ambiguous",
        });
        let out = render(
            &AgentCommand::Status {
                request_id: "rq-money-abandoned".into(),
            },
            &resp,
        )
        .unwrap();
        assert!(out.text.contains("retry_effect"), "{}", out.text);
        assert!(!out.text.contains("request it again"), "{}", out.text);
        assert!(!out.text.contains("fresh effect"), "{}", out.text);
    }

    #[test]
    fn render_executed_surfaces_the_result() {
        let out = render(
            &AgentCommand::Execute {
                request_id: "rq-1".into(),
            },
            &json!({
                "kind":"executed","ok":true,"provider":"github","action":"read_repo",
                "effect_id":"effect_0123456789abcdef0123456789abcdef",
                "result":{"full_name":"acme/widgets"}
            }),
        )
        .unwrap();
        assert!(out.ok);
        assert!(out.text.contains("github.read_repo"));
        assert!(out.text.contains("acme/widgets"));
        assert!(out.text.contains("effect_0123456789abcdef0123456789abcdef"));
        assert_eq!(
            out.json["effect_id"],
            "effect_0123456789abcdef0123456789abcdef"
        );
        assert!(!out.text.contains("full response retained"));

        let failed = render(
            &AgentCommand::Execute {
                request_id: "rq-1".into(),
            },
            &json!({
                "kind":"executed","ok":false,"provider":"github","action":"read_repo",
                "result":null
            }),
        )
        .unwrap();
        assert!(!failed.ok);
    }

    /// The agent-facing render has to SAY the request id, not merely carry it — the
    /// friction was an agent holding a relay receipt that could not name an id to `cermet log <request_id>`.
    #[test]
    fn render_executed_names_the_request_id_on_its_own_line() {
        let out = render(
            &AgentCommand::Execute {
                request_id: "rq-1".into(),
            },
            &json!({
                "kind":"executed","ok":true,"provider":"vercel","action":"deploy",
                "result":{"relay":{"handle":"cermet_relay_Ab3","api_base":"http://127.0.0.1:7133"}},
                "envelope":{"request_id":"rq_7f3a"}
            }),
        )
        .unwrap();
        assert!(
            out.text.contains("request_id: rq_7f3a"),
            "the receipt names the id the agent hands `cermet log <request_id>`: {}",
            out.text
        );
        assert!(
            out.text.contains("cermet log rq_7f3a"),
            "...and the command that takes it: {}",
            out.text
        );
        // ONCE. The raw-envelope dump this replaced said it a second time, as JSON.
        assert_eq!(
            out.text.matches("request_id").count(),
            1,
            "an ordinary receipt names the id exactly once: {}",
            out.text
        );
    }

    /// A relay receipt hands the agent an invocation to run with a NATIVE CLI. When that
    /// CLI is not installed the copy-paste line dies on "command not found" and reads as Cermet
    /// having failed — naive agents hit exactly this at the moment of use. The receipt says so,
    /// above the invocation. Client-preflight only; never blocks.
    #[test]
    fn a_relay_receipt_warns_when_the_native_cli_is_not_installed() {
        let out = render(
            &AgentCommand::Execute {
                request_id: "rq-1".into(),
            },
            &json!({
                "kind":"executed","ok":true,"provider":"vercel","action":"deploy",
                "result":{"relay":{
                    "handle":"cermet_relay_Ab3",
                    "invocation":"cermet-no-such-tool deploy --api http://127.0.0.1:7133 --yes"
                }},
                "envelope":{"request_id":"rq_7f3a"}
            }),
        )
        .unwrap();
        let warning = out
            .text
            .find("warning: 'cermet-no-such-tool' not found on PATH")
            .unwrap_or_else(|| panic!("the receipt warns: {}", out.text));
        let invocation = out.text.find("cermet-no-such-tool deploy --api").unwrap();
        assert!(
            warning < invocation,
            "the warning comes ABOVE the invocation it is about: {}",
            out.text
        );
        assert!(
            out.ok,
            "a warning never turns a successful receipt into a failure"
        );
    }

    /// The same receipt for a verb the broker executes ITSELF carries no invocation, so it never
    /// speaks about PATH.
    #[test]
    fn a_non_relay_receipt_never_mentions_path() {
        let out = render(
            &AgentCommand::Execute {
                request_id: "rq-1".into(),
            },
            &json!({
                "kind":"executed","ok":true,"provider":"github","action":"read_repo",
                "result":{"id":7},"envelope":{"request_id":"rq_7f3a"}
            }),
        )
        .unwrap();
        assert!(!out.text.contains("PATH"), "{}", out.text);
    }

    /// An agent-facing receipt had a generic `cermet: <whole envelope as JSON>` catch-all — a raw
    /// dump is not a rendering, and it made the id appear twice in two different notations. Broker
    /// metadata renders as intentional labeled fields, or it does not render.
    #[test]
    fn render_executed_labels_each_envelope_field_and_never_dumps_the_envelope() {
        let out = render(
            &AgentCommand::Execute {
                request_id: "rq-1".into(),
            },
            &json!({
                "kind":"executed","ok":false,"provider":"github","action":"merge_pull_request",
                "result":{"errors":[{"message":"not mergeable"}]},
                "envelope":{
                    "request_id":"rq_7f3a",
                    "outcome":"failed",
                    "conflict":true,
                    "created_charge":"ch_1",
                }
            }),
        )
        .unwrap();
        for (label, value) in [
            ("outcome", "failed"),
            ("conflict", "true"),
            ("created_charge", "ch_1"),
        ] {
            assert!(
                out.text.contains(&format!("cermet {label}: {value}")),
                "each broker-metadata field gets its own labeled line ({label}): {}",
                out.text
            );
        }
        assert!(
            !out.text.contains("cermet: {") && !out.text.contains("\"outcome\""),
            "no raw envelope dump survives: {}",
            out.text
        );
        assert_eq!(
            out.text.matches("request_id").count(),
            1,
            "identity renders on its own line and is not repeated as metadata: {}",
            out.text
        );
    }

    /// An empty envelope renders NOTHING — the overwhelming majority of verbs author no
    /// broker metadata, and a receipt must not grow a line that says so.
    #[test]
    fn render_executed_renders_no_metadata_line_when_there_is_none() {
        let out = render(
            &AgentCommand::Execute {
                request_id: "rq-1".into(),
            },
            &json!({
                "kind":"executed","ok":true,"provider":"github","action":"read_repo",
                "result":{"full_name":"acme/widgets"},
                "envelope":{"request_id":"rq_7f3a"}
            }),
        )
        .unwrap();
        assert!(
            !out.text.contains("\ncermet "),
            "identity is the only envelope field, so no metadata line renders: {}",
            out.text
        );
    }

    #[test]
    fn render_executed_surfaces_a_failed_runs_error_reason() {
        let out = render(
            &AgentCommand::Execute {
                request_id: "rq-1".into(),
            },
            &json!({
                "kind":"executed","ok":false,"provider":"github","action":"read_repo",
                "result":null,
                "error":"github.read_repo: repository not found"
            }),
        )
        .unwrap();
        assert!(!out.ok);
        assert!(out.text.contains("github.read_repo"));
        assert!(out.text.contains("repository not found"));
    }

    #[test]
    fn render_executed_appends_retained_artifact_affordance() {
        let out = render(
            &AgentCommand::Execute {
                request_id: "rq-1".into(),
            },
            &json!({
                "kind":"executed","ok":true,"provider":"github","action":"read_repo",
                "result":{"full_name":"acme/widgets"},
                "artifact":"art_9",
                "wire_stats":{"total_bytes":79265,"kept_bytes":96}
            }),
        )
        .unwrap();
        assert!(out.ok);
        assert!(out
            .text
            .contains("full response retained — artifact art_9 (79265 B, kept 96 B)"));

        let partial = render(
            &AgentCommand::Execute {
                request_id: "rq-1".into(),
            },
            &json!({
                "kind":"executed","ok":true,"provider":"github","action":"read_repo",
                "result":{},"artifact":"art_9"
            }),
        )
        .unwrap();
        assert!(!partial.text.contains("full response retained"));
    }

    fn structured_output_block(text: &str) -> Value {
        let line = text
            .lines()
            .find(|line| line.trim_start().starts_with("{\"artifact\""))
            .expect("a structured output block line");
        serde_json::from_str(line.trim()).expect("the output block is valid JSON")
    }

    #[test]
    fn render_executed_appends_structured_output_block() {
        let out = render(
            &AgentCommand::Execute {
                request_id: "rq".into(),
            },
            &json!({
                "kind":"executed","ok":true,"provider":"github","action":"read_repo",
                "result":{"full_name":"acme/widgets"},
                "artifact":"art_9","wire_stats":{"total_bytes":79265,"kept_bytes":96}
            }),
        )
        .unwrap();
        let block = structured_output_block(&out.text);
        assert_eq!(block["truncated"], json!(true));
        assert_eq!(block["bytes_total"], json!(79265));
        assert_eq!(block["bytes_kept"], json!(96));
        assert_eq!(block["artifact"], json!("art_9"));
        assert_eq!(block["next_action"], json!("fetch_full_output"));

        let bare = render(
            &AgentCommand::Execute {
                request_id: "rq".into(),
            },
            &json!({
                "kind":"executed","ok":true,"provider":"github","action":"read_repo","result":{}
            }),
        )
        .unwrap();
        assert!(!bare.text.contains("output (structured JSON"));
    }

    #[test]
    fn render_catalog_lists_verbs_and_their_authority_stamp() {
        let resp = json!({
            "kind": "catalog",
            "catalog": [
                { "provider": "github", "action": "read_repo",
                  "fields": [
                    { "name": "owner", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] }
                  ],
                  "execution_targets": ["owner"], "requestable": true, "shape": "http_api_call",
                  "admitted_by": ["allow github.read_repo"],
                  "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} },
                { "provider": "stripe", "action": "get_charge",
                  "fields": [], "execution_targets": ["charge"], "requestable": false, "shape": "http_api_call",
                  "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }
            ]
        });
        let out = render(&AgentCommand::Catalog, &resp).unwrap();
        assert!(out.ok);
        assert!(out.text.contains("github.read_repo"));
        assert!(out.text.contains("[allowed now]"));
        assert!(out.text.contains("agent_request"));
        assert!(out.text.contains("stripe.get_charge"));
        assert!(out
            .text
            .contains("[no standing sentence — ask the operator for one]"));
        assert!(out.text.contains("shape:http_api_call"));
    }

    /// An agent in a new repo could read the entire dictionary and still not learn how to
    /// reach the git plane — the entry named `shape:git_push` and left the wiring to be
    /// guessed. Both zooms state the literal command, in the one projection both surfaces
    /// render.
    #[test]
    fn a_git_plane_verb_states_the_wiring_command_in_both_zooms() {
        let resp = json!({
            "kind": "catalog",
            "catalog": [
                { "provider": "github", "action": "push",
                  "fields": [
                    { "name": "owner", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] }
                  ],
                  "execution_targets": ["owner"], "requestable": true, "shape": "git_push",
                  "admitted_by": ["allow github.push"],
                  "response": {"returns": "receipt", "retention": "none", "errors": "refusal"} }
            ]
        });
        for zoom in [CatalogZoom::All, CatalogZoom::Allowed] {
            let out = render_catalog_zoom(&resp, zoom, CatalogSurface::Cli).unwrap();
            assert!(
                out.text
                    .contains("git remote set-url origin cermet::github/<owner>/<repo>"),
                "{zoom:?}: {}",
                out.text
            );
            assert!(out.text.contains("git push"), "{zoom:?}: {}", out.text);
            assert!(out.text.contains("git fetch"), "{zoom:?}: {}", out.text);
        }
        // An ordinary HTTP verb carries no wiring line — the hint is keyed on the execution shape.
        let http = json!({
            "kind": "catalog",
            "catalog": [
                { "provider": "github", "action": "read_repo",
                  "fields": [], "execution_targets": ["owner"], "requestable": true, "shape": "http_api_call",
                  "admitted_by": ["allow github.read_repo"],
                  "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }
            ]
        });
        let out = render_catalog_zoom(&http, CatalogZoom::All, CatalogSurface::Cli).unwrap();
        assert!(!out.text.contains("git remote set-url"), "{}", out.text);
    }

    /// The same gap on the OTHER shape nothing reaches through a request: a relay entry named
    /// `shape:relay` and left "so how do I run it?" to be inferred. It states the tool, and the
    /// division of labour, in both zooms.
    #[test]
    fn a_relay_verb_states_how_it_is_exercised_in_both_zooms() {
        let resp = json!({
            "kind": "catalog",
            "catalog": [
                { "provider": "vercel", "action": "deploy",
                  "fields": [
                    { "name": "project", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] }
                  ],
                  "execution_targets": ["project"], "requestable": true, "shape": "relay",
                  "admitted_by": ["allow vercel.deploy where project = \"site\""],
                  "response": {"returns": "receipt", "retention": "none", "errors": "receipt"} }
            ]
        });
        for zoom in [CatalogZoom::All, CatalogZoom::Allowed] {
            let out = render_catalog_zoom(&resp, zoom, CatalogSurface::Cli).unwrap();
            assert!(
                out.text.contains(
                    "exercised by running the native `vercel` CLI against the invocation this \
                     request prints; the broker supplies the credential, you supply the tool"
                ),
                "{zoom:?}: {}",
                out.text
            );
        }
        // Keyed on the execution shape, exactly like the git-plane line: an HTTP verb has none.
        let http = json!({
            "kind": "catalog",
            "catalog": [
                { "provider": "github", "action": "read_repo",
                  "fields": [], "execution_targets": ["owner"], "requestable": true, "shape": "http_api_call",
                  "admitted_by": ["allow github.read_repo"],
                  "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }
            ]
        });
        let out = render_catalog_zoom(&http, CatalogZoom::All, CatalogSurface::Cli).unwrap();
        assert!(!out.text.contains("exercised by running"), "{}", out.text);
    }

    /// A field line stopped one inference short of "what can I WHERE on" — it printed
    /// A field line stopped one inference short of "what can I WHERE on" — it printed
    /// `amount:int (side_effect, agent_request)` and left the grammar's type rules to be guessed, so
    /// agents probed schemas one deny at a time. The dictionary now prints each field's form
    /// index, and the notation is explained once rather than per line. The index is the daemon's
    /// (derived from the field's own declaration); the renderer only prints what the frame carries.
    #[test]
    fn the_dictionary_prints_each_field_where_index() {
        let resp = json!({
            "kind": "catalog",
            "catalog": [
                { "provider": "stripe", "action": "refund",
                  "fields": [
                    { "name": "charge", "type": "str", "required": true, "class": "identity",
                      "binding": "exact_resource_pin", "origin": "agent_request",
                      "forms": ["=", "in"] },
                    { "name": "amount", "type": "int", "required": true, "class": "side_effect",
                      "binding": "bounded", "origin": "agent_request",
                      "forms": ["=", "in", "<=", ">=", "budget"] },
                    { "name": "secret_token", "type": "str", "required": false, "class": "secret",
                      "binding": "unbound", "origin": "agent_request", "forms": [] }
                  ],
                  "execution_targets": ["charge"], "requestable": true, "shape": "http_api_call",
                  "admitted_by": ["allow stripe.refund where amount <= 5000"],
                  "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }
            ]
        });
        let out = render(&AgentCommand::Catalog, &resp).unwrap();
        assert!(
            out.text
                .contains("charge:str (identity, agent_request) [= in]"),
            "{}",
            out.text
        );
        assert!(
            out.text
                .contains("amount:int (side_effect, agent_request) [= in <= >= budget]"),
            "{}",
            out.text
        );
        // An unconstrainable field says so rather than rendering an empty bracket.
        assert!(
            out.text
                .contains("secret_token?:str (secret, agent_request) [none]"),
            "{}",
            out.text
        );
        // The notation is explained ONCE, and `rate` is named there as the verb-level aggregate it
        // is — never on a field line.
        assert_eq!(out.text.matches("verb-level").count(), 1);
        assert!(out.text.contains("rate"));
        assert!(!out.text.contains("[= in rate]"));
    }

    /// The allowed zoom is the REQUEST surface — its fields are the ones an agent supplies,
    /// and the bounds a sentence already imposes are printed as the sentence itself. The form index
    /// answers a PROPOSING question, so it stays in the dictionary and the compact zoom's line budget
    /// is unchanged.
    #[test]
    fn the_allowed_zoom_line_budget_is_unchanged() {
        let resp = json!({
            "kind": "catalog",
            "catalog": [
                { "provider": "stripe", "action": "refund",
                  "fields": [
                    { "name": "amount", "type": "int", "required": true, "class": "side_effect",
                      "binding": "bounded", "origin": "agent_request",
                      "forms": ["=", "in", "<=", ">=", "budget"] }
                  ],
                  "execution_targets": ["charge"], "requestable": true, "shape": "http_api_call",
                  "admitted_by": ["allow stripe.refund where amount <= 5000"],
                  "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }
            ]
        });
        let out =
            render_catalog_zoom(&resp, CatalogZoom::Allowed, CatalogSurface::Mcp).expect("renders");
        assert!(
            out.text.contains("stripe.refund(amount:int)"),
            "{}",
            out.text
        );
        assert!(!out.text.contains("[= in"), "{}", out.text);
    }

    /// The dictionary stamp must answer "may I call this right now", and NOTHING on it may
    /// read as permission when there is none. `[requestable]` did — an agent took it for
    /// "currently permitted" and burned its budget requesting stamped-but-unruled verbs — and the
    /// stamp is derived from the SAME joined authority data the line below it renders, so the two
    /// can never disagree.
    #[test]
    fn no_dictionary_stamp_reads_as_permission_unless_a_sentence_admits_the_verb() {
        let entry = |extra: serde_json::Value| -> serde_json::Value {
            let mut e = json!({
                "provider": "stripe", "action": "get_charge",
                "fields": [], "execution_targets": ["charge"], "requestable": true,
                "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"}
            });
            let (obj, extra) = (
                e.as_object_mut().unwrap(),
                extra.as_object().unwrap().clone(),
            );
            obj.extend(extra);
            e
        };
        let stamp_of = |e: serde_json::Value| -> String {
            let out = render(
                &AgentCommand::Catalog,
                &json!({ "kind": "catalog", "catalog": [e] }),
            )
            .unwrap();
            let line = out
                .text
                .lines()
                .find(|l| l.contains("stripe.get_charge"))
                .expect("the verb line")
                .to_string();
            line[line.find('[').unwrap()..=line.find(']').unwrap()].to_string()
        };

        // Loaded, admitted, no carve-out: the ONE case that may read as permission.
        assert_eq!(
            stamp_of(entry(json!({"admitted_by": ["allow stripe.get_charge"]}))),
            "[allowed now]"
        );
        // Loaded, but an explicit deny selects it — settled, and not a widening candidate.
        assert_eq!(
            stamp_of(entry(json!({
                "sentence_denied": true,
                "denied_by": ["deny stripe.get_charge"]
            }))),
            "[denied — not requestable]"
        );
        // A sentence selects it, but this broker does not have the verb loaded.
        assert_eq!(
            stamp_of(entry(json!({
                "requestable": false,
                "admitted_by": ["allow stripe.get_charge"]
            }))),
            "[not available on this broker — a request denies]"
        );
        // Nothing rules it: the widening candidate, and the only "propose one" case.
        assert_eq!(
            stamp_of(entry(json!({"sentence_denied": true}))),
            "[no standing sentence — ask the operator for one]"
        );
        // The retired stamps are gone entirely.
        for retired in ["[requestable]", "[needs ratify]"] {
            for e in [
                entry(json!({"sentence_denied": true})),
                entry(json!({"requestable": false})),
            ] {
                assert_ne!(stamp_of(e), retired);
            }
        }
    }

    /// THE CORPUS INVARIANT: every verb a sentence can name is a verb the catalog lists. A verb the
    /// projection dropped was still nameable in a sentence and still executable by name, so an agent
    /// could read authority for a verb it could not find — and could run anyway. The projection
    /// therefore hides nothing: it renders every verb the daemon's frame carries.
    #[test]
    fn the_projection_hides_no_vendored_verb() {
        let entries: Vec<Value> = cermet_core::templates::vendored_action_templates()
            .iter()
            .map(|doc| {
                let parsed: Value = serde_yaml::from_str(doc).expect("vendored document parses");
                json!({
                    "provider": parsed["provider"],
                    "action": parsed["action"],
                    "fields": [],
                    "execution_targets": [],
                    "requestable": true,
                    "response": {"returns": "verbatim", "retention": "full",
                                 "errors": "status_and_body"},
                })
            })
            .collect();
        let expected = entries.len();
        let resp = json!({ "kind": "catalog", "catalog": entries });
        let out =
            render_catalog_zoom(&resp, CatalogZoom::All, CatalogSurface::Mcp).expect("renders");
        assert!(
            out.text.contains(&format!("verbs ({expected}):")),
            "the projection dropped a vendored verb; it must render all {expected}:\n{}",
            out.text
        );
    }

    #[test]
    fn render_catalog_tolerates_missing_shape() {
        let resp = json!({
            "kind": "catalog",
            "catalog": [
                { "provider": "github", "action": "read_repo",
                  "fields": [], "execution_targets": ["owner"], "requestable": true,
                  "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }
            ]
        });
        let out = render(&AgentCommand::Catalog, &resp).unwrap();
        assert!(out.ok);
        assert!(out.text.contains("github.read_repo"));
        assert!(!out.text.contains("shape:"));
    }
}
