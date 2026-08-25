//! Client-visible broker types.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Sentence-authority outcome for a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStatus {
    /// Authenticated pre-cutover state only; new sentence requests never mint this status.
    Requested,
    /// Sentence-authorized and not yet used.
    Approved,
    Denied,
    /// The single-use claim is being spent right now (the transient window between the atomic
    /// `approved`→`executing` claim and the terminal `executed`).
    Executing,
    Executed,
    Expired,
}

/// Authenticated disposition of one logical money effect. This is derived only from the broker's
/// chain-verified execution evidence; callers can neither submit nor override it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOutcome {
    /// Execution ended before the provider mutation boundary. A later request is a fresh effect.
    ///
    /// Spelled `definitely_pre_effect` on EVERY surface, because that is the word the durable
    /// terminal record has always used (`broker/execute.rs`, and the exact-schema evidence
    /// validator that reads those rows back). The variant name is the short one; the WORD is the
    /// record's. One fact, one word — the receipt-reconstruction path used to translate between
    /// the two, which is how a durable vocabulary and a wire vocabulary drift apart.
    #[serde(rename = "definitely_pre_effect")]
    PreEffect,
    Succeeded,
    DefinitelyFailed,
    /// The provider may have applied the effect; only an authenticated same-key retry is safe.
    Ambiguous,
}

impl EffectOutcome {
    /// The one word this disposition is spelled with — the SAME word `serde` writes and the SAME
    /// word the durable terminal record carries, so nothing between the audit row and the agent
    /// needs a translation table.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreEffect => "definitely_pre_effect",
            Self::Succeeded => "succeeded",
            Self::DefinitelyFailed => "definitely_failed",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// WHY an authorized effect did not land — the third class of the refusal taxonomy. A catalog
/// gap and a sentence gap are typed on every surface; "the sentence allowed it and the CREDENTIAL
/// could not" was collapsing into a generic failure, indistinguishable from a dropped connection
/// or a provider 500.
///
/// **The names are BEHAVIORAL, not HTTP.** Each says what the failure implies about what to do
/// next — replace the credential, back off, fix the request, reconcile an unknown outcome, update a
/// drifted template. Status codes are EVIDENCE for the classification and never the taxonomy
/// itself; the status, the body, and every message stay LOCAL on the receipt (the `status_and_body`
/// response contract is untouched) and only this ordinal class is shaped to cross.
///
/// **Every class is an OBSERVATION, never a conclusion.** The name says what a seam saw — a
/// status arrived, nothing was written to the wire, bytes went out and no response came back — and
/// never what a reader should conclude from it. "The outcome is unknown" is a derivation, so it has
/// no class of its own: it is drawn at read time, on the outcome axis, from the observation stored
/// here.
///
/// **Orthogonal to [`EffectOutcome`]**, deliberately: the outcome axis answers *did it happen*
/// (`definitely_pre_effect` / `succeeded` / `definitely_failed` / `ambiguous`) and this axis answers *what was
/// observed*. Neither re-encodes the other — a 502 that ARRIVED on a money mutation is
/// `provider_transient` (an observation about the provider's answer) sitting beside an `ambiguous`
/// outcome (the derivation about landing), and both facts are needed to act.
///
/// **Why this is not `EvidenceFailureClass`** (`cermet-core/src/evidence.rs`) or
/// `PreconditionFailureClass` (`cermet-core/src/preconditions.rs`): those type a different seam and
/// answer a different question. Both run BEFORE authority decides — "could we resolve trusted
/// provider facts / does the world satisfy this precondition" — and their vocabularies
/// (`malformed`, `mismatch`, `stale`, `integrity`, `insufficient_balance`) describe that resolution,
/// not an effect that ran. This types the ONE credentialed hop an approved grant spends, on every
/// provider and every seam, and it is the only one of the three that leaves the box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectFailureClass {
    /// The provider refused the CREDENTIAL — it is expired, revoked, or without the access the
    /// sentence assumed. Next step: re-scope or replace the key. The operator-facing payoff.
    ProviderAuthRefused,
    /// The provider refused on a POLICY of its own, independently of which credential asked. Next
    /// step: nothing about the key will help.
    ///
    /// No seam produces this today, and it is not derived from a status: providers disagree about
    /// whether 403 means "this key lacks access" (which is [`Self::ProviderAuthRefused`]) or "this
    /// is forbidden to everyone", and choosing between them from the number alone would be a guess.
    /// It ships so the vocabulary is total and a seam that gains real evidence has a name waiting.
    ProviderPolicyRefused,
    /// The provider DETERMINISTICALLY rejected the request as submitted. Next step: the fields have
    /// to change — retrying unchanged is not indicated by the observed response.
    ///
    /// Stated that way on purpose: "will fail the same way forever" is a
    /// claim about the provider's future that one `400` cannot support. What the seam observed is
    /// that this body was rejected, and that is what the class means.
    ProviderInputRefused,
    /// The provider is rate limiting. Next step: back off and retry — behaviorally distinct from
    /// every other refusal, which is why it is its own class.
    ProviderRateLimited,
    /// The provider failed on its own side. Next step: retry later; the request was fine.
    ProviderTransient,
    /// The hop never left this box, so no effect can have happened. Next step: retry freely.
    TransportPreSend,
    /// Bytes went to the wire and no application-level response came back — a timeout, a reset, a
    /// truncated stream. That is the OBSERVATION and the whole of it; which flavor it was lives in
    /// the recorded error detail beside the class, not in more classes (the taxonomy stores
    /// observations, never conclusions — "the outcome is unknown" is a DERIVATION a reader makes
    /// from this, and the projection's outcome axis is where it is drawn). Next step: reconcile
    /// before retrying — never a blind retry.
    TransportNoResponse,
    /// The effect landed and its result contradicts what was approved. Next step: an operator
    /// looks; nothing is undone.
    PostconditionMismatch,
    /// The provider answered, and the answer does not fit the ratified template — an unreadable
    /// body, or a declared field absent. Next step: the template is stale, not the request.
    ProtocolDrift,
    /// Our own execution subsystem failed, before or beside any provider answer (the vault could
    /// not be opened, egress was refused, the daemon was locked down). Next step: fix the box.
    LocalExecutionFailure,
    /// The honest residual: the effect failed and no typed signal says how. Never a guess.
    Failed,
}

/// What became of the authorized EFFECT, derived at read time from the signals already recorded.
///
/// The receipt row's decision word says what authority ruled; this says what then happened at the
/// effect layer. Without it an allowed request whose relay grant burned on a refused hop, one whose
/// window lapsed having driven nothing, and one whose deploy landed all render the same word.
///
/// **Nothing stores this.** It is computed by the view join from the recorded observations — the
/// session's open/close rows, the forwarded hops and their upstream statuses, the burning refusal's
/// reason word, the terminal execution event — and from the clock at the moment of the read. A state
/// that the recorded signals cannot distinguish has no value here: the projection leaves it `None`
/// rather than choosing, and the row renders no suffix at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    /// The last word recorded about the grant's effect is a success: a 2xx on the session's
    /// effect-bearing hop, or a terminal `provider_action_succeeded` on a verb the daemon ran
    /// itself. LAST word, because a session may attempt its effect more than once — the native
    /// two-phase create is answered `400 missing files` before the create that lands.
    Ok,
    /// A refusal ENDED the session, and no effect-bearing hop is recorded as having landed. The
    /// burning refusal's stable reason word rides beside this (`burn_reason`), so the row says which
    /// class ended it.
    ///
    /// Stated that way because "the effect did not land" is more than the record supports. An effect
    /// hop that never got a response head is spent with its outcome UNKNOWN; the native client
    /// retries, the retry is refused as `effect_already_used`, and the session burns — a row that
    /// then read "the effect did not land" would be telling an operator to stop reconciling exactly
    /// where the failure class beside it says to start.
    Burned,
    /// A relay window that ended — its terminal record exists, or the read is past the `expires_at`
    /// the approval set — having forwarded ZERO hops. The grant was spent minting authority nothing
    /// ever used.
    ExpiredUnused,
    /// A relay window that ended after forwarding hops with NOTHING recorded saying whether its
    /// effect landed. This is the honest gap: hops happened, the window is over, and no
    /// effect-bearing hop ever reached a terminal verdict. It is not a claim that the effect failed
    /// — an effect the record says failed carries its `failure_class` instead.
    Unresolved,
}

impl EffectState {
    /// The one token this state is spelled with — on the receipt row's suffix and on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            EffectState::Ok => "ok",
            EffectState::Burned => "burned",
            EffectState::ExpiredUnused => "expired_unused",
            EffectState::Unresolved => "unresolved",
        }
    }
}

/// The typed signal ONE seam observed about ONE failed effect. Every variant is a fact the seam
/// holds structurally, so [`EffectFailureClass::of`] is a pure function of (seam, signal) with no
/// text anywhere in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureSignal {
    /// An HTTP response was delivered and carried this status.
    HttpStatus(u16),
    /// The hop never left the box: the connection was never established, or the daemon itself
    /// refused to send.
    NeverSent,
    /// The request went out and no usable answer came back.
    SentWithoutAnswer,
    /// The git seam's ambiguous-exit condition. The daemon is the only party that can tell "we
    /// sent nothing" from "we sent something the upstream rejected", because git renders them
    /// identically; anything past that distinction is prose the seam refuses to mine.
    GitUpstream {
        credential_attached: bool,
        demanded_credentials: bool,
    },
    /// The provider answered and the answer does not fit the ratified template.
    ResponseShapeUnexpected,
    /// The effect landed and what it did contradicts what was approved.
    ApprovedOutcomeContradicted,
    /// Our own execution subsystem failed.
    LocalFault,
    /// The seam knows only that the effect failed.
    Unclassifiable,
}

impl EffectFailureClass {
    /// The whole classification rule, in one place.
    ///
    /// Status ranges appear here as EVIDENCE — the provider's own typed statement about its refusal
    /// — and the mapping stops exactly where providers stop agreeing:
    ///
    /// - `401`/`403` are refusals aimed at the credential's authority, and both send an operator to
    ///   the same place. `provider_policy_refused` is deliberately NOT derived from `403`.
    /// - `400`/`422` are the provider saying the request itself is unacceptable.
    /// - `429` is rate limiting, whose correct response (back off) is its own behavior.
    /// - `5xx` is the provider failing on its own side.
    /// - **Every other status is the residual**, including `404` and `409`: a 404 can mean "no such
    ///   object" or "your token may not see it" (GitHub masks private repositories that way) and a
    ///   409 is a state conflict this vocabulary has no behavior for. Guessing between them is
    ///   exactly what the residual exists to prevent.
    ///
    /// Fail closed: an unrecognized signal is [`EffectFailureClass::Failed`], never a guess at a
    /// finer class the evidence does not support.
    pub fn of(signal: FailureSignal) -> Self {
        match signal {
            FailureSignal::HttpStatus(401 | 403) => Self::ProviderAuthRefused,
            FailureSignal::HttpStatus(400 | 422) => Self::ProviderInputRefused,
            FailureSignal::HttpStatus(429) => Self::ProviderRateLimited,
            FailureSignal::HttpStatus(status) if (500..600).contains(&status) => {
                Self::ProviderTransient
            }
            FailureSignal::HttpStatus(_) => Self::Failed,
            FailureSignal::NeverSent => Self::TransportPreSend,
            FailureSignal::SentWithoutAnswer => Self::TransportNoResponse,
            FailureSignal::GitUpstream {
                credential_attached: true,
                demanded_credentials: true,
            } => Self::ProviderAuthRefused,
            // git exits non-zero the same way for a non-fast-forward, a dead host and a missing
            // repository, and separating them means reading its prose. One class, honestly.
            FailureSignal::GitUpstream { .. } => Self::Failed,
            FailureSignal::ResponseShapeUnexpected => Self::ProtocolDrift,
            FailureSignal::ApprovedOutcomeContradicted => Self::PostconditionMismatch,
            FailureSignal::LocalFault => Self::LocalExecutionFailure,
            FailureSignal::Unclassifiable => Self::Failed,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProviderAuthRefused => "provider_auth_refused",
            Self::ProviderPolicyRefused => "provider_policy_refused",
            Self::ProviderInputRefused => "provider_input_refused",
            Self::ProviderRateLimited => "provider_rate_limited",
            Self::ProviderTransient => "provider_transient",
            Self::TransportPreSend => "transport_pre_send",
            Self::TransportNoResponse => "transport_no_response",
            Self::PostconditionMismatch => "postcondition_mismatch",
            Self::ProtocolDrift => "protocol_drift",
            Self::LocalExecutionFailure => "local_execution_failure",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for EffectFailureClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The live status of a request, keyed by the agent's stable `request_id`. `status` is exactly one of
/// `ready | running | terminal`; terminal detail lives in `outcome` and `termination`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestStatusView {
    pub request_id: String,
    pub status: String,
    /// Safe logical money-effect handle. Present for every phase of a money grant so an ambiguous
    /// terminal result remains request-time retryable without exposing the broker-held key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<String>,
    /// Trusted money-effect disposition. Absent before terminal evidence and for non-money verbs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_outcome: Option<EffectOutcome>,
    /// For a denied request, the redacted `capability_denied` summary. Metadata only, never a
    /// secret. Absent unless the request was denied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    /// The typed run phase, equal to `status`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// For a `terminal` phase, the settled outcome (`succeeded` | `failed` | `denied` |
    /// `abandoned`) read from the VERIFIED terminal audit event — NEVER inferred from grant
    /// status/clock. Absent unless terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// For a `terminal` phase, the coarse termination cause (`exited` | `canceled` | `denied` |
    /// `abandoned`). Absent unless terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termination: Option<String>,
    /// The durable terminal receipt rebuilt from the verified audit chain. Already redacted at
    /// record time; absent unless terminal and reconstructable from a chain that verifies end-to-end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_receipt: Option<serde_json::Value>,
}

/// Agent-supplied capability request.
///
/// The request names a provider and action directly. Unknown fields are refused so removed request
/// shapes, including aliases, cannot silently decode.
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequest {
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub resource: Value,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub justification: Option<String>,
    /// What the AGENT says it is, on THIS request. Optional, never
    /// authenticated, and no authority reads it — the broker decides from the kernel-attested uid
    /// and the sentence corpus, and this participates in nothing.
    ///
    /// It is per-REQUEST because the session-static `CERMET_AGENT_MODEL` declaration mislabels a
    /// mid-session model switch: a runtime that hands a task to a different model keeps the same
    /// session, so every row after the switch would carry the model the session started with. The
    /// self-report is de-fanged at the same seam as every other client label and stored on the
    /// request row, which stays on this machine.
    #[serde(default)]
    pub model: Option<String>,
}

/// A hand-written REDACTING `Debug`, mirroring
/// `cermet_ipc::ctl::RedactedToken`. `resource` may carry an agent-supplied `FieldClass::Secret`
/// value (e.g. the env-var value for `env_preview_sensitive_create`); the contract is not in hand here
/// to selectively redact, so the whole resource is elided. This closes the latent class where a future
/// `{:?}` sink on a request (a log line, a panic message) could spill a submitted secret — there is no
/// such live sink today, so this is a tripwire, not a fix for a live leak.
impl std::fmt::Debug for CapabilityRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityRequest")
            .field("provider", &self.provider)
            .field("action", &self.action)
            .field("resource", &"<redacted>")
            .field("environment", &self.environment)
            .field("justification", &self.justification)
            .field("model", &self.model)
            .finish()
    }
}

/// The safe, value-free authority route that decided a capability request. This deliberately cannot
/// carry rule bytes, fingerprints, selectors, or any other authority material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    Sentence,
}

/// The window CLASSIFICATION of an exhausted budget/rate aggregate — the ONLY budget signal that
/// crosses the agent boundary (anti-oracle). It is a window enum, NOT a number: no limit,
/// remaining, consumed, or amount is ever agent-facing. Every numeric figure lives in operator-side
/// audit events (`budget_mint`/`budget_denied`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BudgetWindow {
    Hour,
    Day,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestOutcome {
    pub request_id: String,
    pub decision: Decision,
    pub reason: String,
    /// Present ONLY when a `Deny` is a budget/rate exhaustion downgrade: the window classification,
    /// never a number. Suppressed (`None`) on every other decision. Value-free by construction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_exceeded: Option<BudgetWindow>,
    /// Advisory human-only command for widening sentence authority; never grants or mutates anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Present only when the decision is `Allow`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// Safe logical money-effect lineage handle. Present only for an allowed money request; the
    /// broker-held idempotency key has no public carrier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<String>,
    /// Present only when the request reached sentence evaluation. Registry and canonicalization
    /// refusals happen before authority decides and omit this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_kind: Option<AuthorityKind>,
}

/// The compact result of an in-core (HTTP) execution: the redacted provider result plus the
/// per-execution artifact handle and kept-vs-total byte counter that form its receipt.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionResult {
    pub ok: bool,
    pub provider: String,
    pub action: String,
    /// Safe logical money-effect handle derived from the authenticated grant. The private
    /// idempotency key has no public carrier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<String>,
    /// Trusted money-effect disposition from the terminal event for this execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_outcome: Option<EffectOutcome>,
    /// Provider result, already redacted. Never contains a raw credential.
    pub result: Value,
    /// The content-addressed handle for the retained response body — the SAME body `result` above
    /// carries (the response contract is verbatim). `None` when the verb declares
    /// `retention: none` or the provider is a test double. Additive — an older wire frame omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    /// The kept-vs-total byte counter for this execution (the always-on token-efficiency number).
    /// `None` when there is no retained body to measure against. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_stats: Option<WireStats>,
    /// The BROKER-AUTHORED sibling of `result` — this receipt's identity, plus whatever the broker
    /// observed about the response. Never optional: see [`ReceiptEnvelope`].
    pub envelope: ReceiptEnvelope,
}

/// The broker-authored half of a receipt, kept strictly OUTSIDE the verbatim provider `result`.
///
/// **Identity is mandatory.** `request_id` is stamped at the ONE broker seam that authors
/// this envelope, so a verb cannot mint a receipt the agent is unable to chase — the friction it
/// kills is an agent holding a relay receipt with no id to hand `cermet log <request_id>`, left grepping
/// `cermet log` and correlating timestamps. Being a required field of the only constructor, omission
/// is unrepresentable rather than merely discouraged.
///
/// `grant_id` deliberately does NOT ride here. It is operator-internal and never crosses the agent
/// boundary — the agent-facing request outcome strips it for exactly this reason (see
/// `cermet-ipc/src/wire.rs`), and a receipt is just as agent-facing. The agent references its
/// capability by `request_id`; that is the id every operator surface takes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEnvelope {
    /// The broker-minted id of the request this receipt answers — the handle for `cermet log <request_id>`.
    pub request_id: String,
    /// Per-verb metadata that deliberately lives OUTSIDE `result`: a GraphQL step's classified
    /// `outcome`/`conflict` verdict. Injecting it into `result` would make the receipt disagree with
    /// the stored artifact and the wire body, which is the divergence the response contract forbids.
    /// Empty for the overwhelming majority of verbs.
    ///
    /// Serialized flat, alongside the identity above; the identity key is broker-reserved, and
    /// [`ReceiptEnvelope::stamp`] drops a same-named verb key rather than emit a duplicate.
    #[serde(flatten)]
    pub broker_metadata: Map<String, Value>,
}

impl ReceiptEnvelope {
    /// Stamp a receipt's identity onto the broker metadata a verb authored. Called at the broker's
    /// execution seam, which is the only place that has both.
    pub fn stamp(request_id: &str, mut broker_metadata: Map<String, Value>) -> Self {
        broker_metadata.remove("request_id");
        Self {
            request_id: request_id.to_string(),
            broker_metadata,
        }
    }
}

/// The kept-vs-total byte counter attached to an execution and its terminal audit event: `total_bytes`
/// is the full provider response body (pre-scrub true size); `kept_bytes` is what the agent actually
/// received in the narrowed result (HTTP) or the rendered receipt (shell). Their ratio is the live
/// token-efficiency measure. Carries no secret — two byte counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireStats {
    pub total_bytes: u64,
    pub kept_bytes: u64,
}

/// The result shape an agent `execute` can take.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecOutcome {
    /// An HTTP verb executed in-core (the credential stayed in the core).
    Executed(ExecutionResult),
}

/// What the product layer is allowed to see about a stored credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeCredential {
    pub reference: String,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    pub created_at: String,
    /// RFC3339 timestamp of the most recent successful execute, or `None` if never used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used: Option<String>,
}

/// The result of `connect`.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectOutcome {
    pub stored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    pub reference: String,
    pub provider: String,
    pub replaced: bool,
}

/// One audit-log row, read back for the session trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventView {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub ts: String,
    pub event_type: String,
    pub severity: String,
    pub summary: String,
    pub data: Value,
}

/// One grant's frozen lifecycle row, read back for the session trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantView {
    pub grant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub provider: String,
    pub action: String,
    /// Safe logical money-effect lineage handle. The private idempotency key is never projected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<String>,
    /// Trusted terminal money-effect disposition, when chain-verifiable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_outcome: Option<EffectOutcome>,
    /// WHY the authorized effect did not land, when it did not. Present only on a row whose
    /// effect FAILED; `None` says nothing failed, not that the cause is unknown — the unknown
    /// cause is [`EffectFailureClass::Failed`], which is a value. Operator-view only: it is
    /// filled by `history()`, the ctl surface, and every agent-facing grant projection leaves it
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<EffectFailureClass>,
    /// What became of the authorized effect, DERIVED at read time (see [`EffectState`]). `None`
    /// where the recorded signals do not determine one — a window still in flight, a request decided
    /// and never executed, a refusal that never ran anything. Same operator-view scope as
    /// `failure_class`: filled by `history()`, absent on every agent-facing grant projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_state: Option<EffectState>,
    /// The stable reason word of the refusal that burned the session, carried beside
    /// `effect_state = burned` so the receipt row names the class that ended it without a second
    /// lookup. Absent unless something burned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burn_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub resource: Value,
    pub status: String,
    pub decision: String,
    pub created_at: String,
    /// When the authorized effect REACHED ITS END (RFC3339), from the terminal execution event's own
    /// timestamp. `None` for a row whose effect never ran, is still in flight, or expired unspent —
    /// which is the truth about it, never a substituted `created_at`.
    ///
    /// Same operator-view scope as `failure_class`: filled by `history()`, absent on every
    /// agent-facing grant projection. It exists so an effect's WALL TIME is derivable from the
    /// receipt's own two timestamps rather than from a clock read at export time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_at: Option<String>,
    /// The agent-issued request handle (`req_…`) this grant was minted from. Surfaced so a grant row,
    /// its shell receipt, and its stored artifact are cross-referenceable in the views. Metadata only
    /// (a handle, never a secret); the `requests` row is the atom of the agent↔broker conversation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Durable authority provenance. New grants carry only `sentence`; other values identify
    /// authenticated pre-cutover rows. Covered by the grant HMAC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by_kind: Option<String>,
    /// Legacy pre-cutover approver identity. New sentence grants leave this absent. Covered by the
    /// grant HMAC; no secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    /// When the grant became sentence-authorized (RFC3339). HMAC-covered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
    /// The human-readable reason a request resolved as it did. Populated for requests-backed
    /// denial rows in the History log so a sentence deny is visible with its reason; `None` for
    /// ordinary grant rows (their story is the status/decision + audit trail).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The evaluator's OWN typed refusal, stored beside the prose above rather than reconstructed
    /// from it. `None` on an allow, on a refusal raised before the evaluator ran, and on a row
    /// written before the column existed — which is the truth about those rows, not a missing
    /// value to guess at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<crate::sentence::DenyReason>,
    /// The sentence-corpus digest this request was decided against, as stored on the
    /// request row (`policy_fingerprint`). Operator-view only — `history()` is a ctl surface — and
    /// it is a digest of the operator's own rule corpus, never request content. Rendered by
    /// `cermet log` so an allow names the authority it came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_fingerprint: Option<String>,
    /// The canonical printed text of the rule that admitted this request, as stored on the
    /// request row (`matched_rule`). Absent on denials and on any row no sentence rule allowed. Same
    /// operator-view scope as `authority_fingerprint`: it is the operator's own authored rule text,
    /// never request content. Rendered by `cermet log` so an allow shows the sentence itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    /// The justification the agent supplied WITH the request, as stored on the request row. It is
    /// mandatory on the MCP surface and was write-only until `cermet log` rendered it.
    /// Agent-authored text, never a secret — the operator reads it to judge intent. Absent on rows
    /// that carried none (every git-plane row).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    /// Whether this row still authenticated against its per-grant HMAC at read time.
    pub integrity_ok: bool,
    /// What the AGENT declared it was ON THIS REQUEST, read back from the request row.
    ///
    /// The FRESH half of the model self-report: `agent_model` below is the session's env-var
    /// declaration, made once when the session opened, and this is the claim the agent attached to
    /// this one request. Where both exist the per-request one is the later and more specific
    /// evidence, and the receipt row carries which of the two it used.
    ///
    /// Unauthenticated, like every other self-report here, and read by no authority. Operator-view
    /// only: filled by `history()`, absent on every agent-facing grant projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_model: Option<String>,
    /// The stored requesting principal, the daemon's `"uid:N"` string (peercred-derived). Absent for
    /// legacy/operator-minted rows. Tamper-evident: it is covered by the per-grant HMAC (`integrity_ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// The `principal_id`'s OS username, resolved from the passwd db at view-build time (e.g.
    /// `cermet-agent`). `None` when there is no principal, the uid does not resolve, or the id is not
    /// a `"uid:N"` — never a guess.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_label: Option<String>,
    /// What the SESSION self-reported about who was driving, joined from the
    /// session row at view-build time.
    ///
    /// **Nothing here is attested and no authority reads any of it.** `client_name`/`client_version`
    /// are the MCP handshake's `clientInfo` — a runtime naming itself — and `agent_model` is the
    /// human's own `CERMET_AGENT_MODEL` declaration. They are held here in FULL because this is the
    /// local operator view, and no self-report ever leaves the box.
    ///
    /// Operator-view only, like `failure_class`: filled by `history()`, and every agent-facing grant
    /// projection leaves them absent. `None` means nothing was captured, which is the truth about a
    /// git-plane row, an operator ctl session, and any client that never handshook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_model: Option<String>,
    /// Whether this row's session was opened over the AGENT socket at all. `false` means the
    /// operator drove it themselves (`cermet run` over ctl) or the git plane did — which is what
    /// separates human-driven decisions from agent-driven ones downstream, without anyone reporting
    /// anything.
    #[serde(default)]
    pub agent_session: bool,
}

/// Operator-only, request-scoped execution evidence. Every row is projected only after the
/// complete audit chain and the grant/event identity schemas verify. Provider `result` is the same
/// already-redacted narrow projection carried by the terminal execution receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEvidenceView {
    pub request_id: String,
    pub grant_id: String,
    pub provider: String,
    pub action: String,
    pub resource: Value,
    pub status: String,
    pub decision: String,
    pub integrity_ok: bool,
    /// The agent's own justification for the request, whole (the list truncates for width; this
    /// does not). Always projected, `null` when the request carried none.
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_outcome: Option<EffectOutcome>,
    /// What became of the authorized effect, DERIVED at read time from the events and hops below
    /// (see [`EffectState`]). It is here because the derivation is arithmetic a reader should not
    /// have to do: "closed by `ttl` with `hops: 0`" and "closed by `ttl` after four hops and no
    /// effect verdict" are different fates, and a window whose daemon restarted has no terminal
    /// record at all. `None` where the recorded signals determine nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_state: Option<EffectState>,
    pub events: Vec<ExecutionEvidenceView>,
    /// The relay hops this request's grant authorized, oldest first. Empty for every
    /// non-relay verb.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_hops: Vec<RelayHopView>,
    /// The relay session's terminal receipt (`relay_session_closed`), verbatim as the broker
    /// derived it from what the relay observed. `None` while the session is still live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_session: Option<Value>,
}

/// What `cermet log <request_id>` answers with. ONE id, three possible fates: a request the
/// broker granted AND executed is answered by its execution evidence; a request the broker
/// REFUSED is answered by its denial row; a request the broker ALLOWED but nobody has executed
/// yet — the state `run --ask-only` creates — is answered by its decision. Serialized untagged:
/// each fate renders as its own object, and `events`/`grant_id` (executed) vs `reason` + a
/// refusing `decision` (denied) vs `next` (decided) says which one the operator is reading.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestLogView {
    Executed(Box<RequestEvidenceView>),
    Denied(Box<DeniedRequestView>),
    Decided(Box<DecidedRequestView>),
}

/// One ALLOWED-but-unexecuted request (from a cold-start usability trial). `run --ask-only`
/// creates exactly this state and prints the id — and `cermet log <that id>` answered "not found",
/// the receipt story failing at the one place the docs point an agent to.
///
/// The record is the DECISION, not an execution: what was frozen, which sentence admitted it, and
/// the one command that finishes it. It carries no `grant_id` — a grant exists, but `request_id` is
/// the one public id  and nothing anywhere takes the other one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecidedRequestView {
    /// The one public id — `run --resume` and `log` both take it.
    pub request_id: String,
    pub provider: String,
    pub action: String,
    /// The frozen fields, rendered through the same fail-closed redaction every grant view uses.
    /// These are what execution will use: they were frozen before the grant was minted and there is
    /// no execute-time fill channel.
    pub resource: Value,
    /// `allow` — the decision as recorded.
    pub decision: String,
    /// The grant's lifecycle status (`approved`, `claimed`, …): decided, not yet terminal.
    pub status: String,
    /// The canonical text of the sentence that admitted this request. `None` only for a
    /// row whose request record predates the stored column.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    /// The sentence-corpus digest this request was decided against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_fingerprint: Option<String>,
    /// The agent's own justification, whole. `null` when the request carried none.
    #[serde(default)]
    pub justification: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_label: Option<String>,
    /// Whether the grant row still authenticated against its per-grant HMAC at read time.
    pub integrity_ok: bool,
    /// The next action, as the literal command that performs it.
    pub next: String,
}

/// One REFUSED request, rendered per id. Denials are recorded losslessly — the values are kept and
/// the provenance is the canonical sentence text — so answering `cermet log <id>` with "not found"
/// would hide a record that is right there.
///
/// This is the SAME projection `cermet log --denied` lists from, one row deep. It carries no
/// `grant_id`: a denial minted no grant, and `request_id` is the one public id.
///
/// NOTE (accepted limitation): the widening suggestion a deny returns at REQUEST time
/// (`RequestOutcome::hint`) is not stored on the request row, so it is absent here. Re-deriving it
/// at read time would evaluate TODAY's corpus against yesterday's request and print a suggestion the
/// decision never made — evidence is what was recorded, not a re-derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeniedRequestView {
    /// The one public id — this row IS the request, so it is its own handle.
    pub request_id: String,
    pub provider: String,
    pub action: String,
    /// The fields the request asked for, AS STORED: already redacted at write time by
    /// `record_request` (a secret-classed field carries its marker; an unresolved action's values
    /// are size-capped). The row's job is to say what was asked for.
    pub resource: Value,
    /// `deny` | `unsupported` | `unregistered` — the fate as the broker recorded it.
    pub decision: String,
    /// The stored reason, verbatim. It carries the deny provenance (the canonical sentence text
    /// where a rule matched) — never a rule number.
    pub reason: String,
    /// The evaluator's own typed refusal, beside the prose. Absent on a refusal that preceded
    /// evaluation and on rows written before the column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<crate::sentence::DenyReason>,
    /// The agent's own justification for the request, whole (the list truncates for width; this
    /// does not). Always projected, `null` when the request carried none.
    #[serde(default)]
    pub justification: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The sentence-corpus digest this request was decided against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_label: Option<String>,
    /// What the AGENT declared it was on this request. Unauthenticated, read by no
    /// authority, and present on a REFUSAL for the reason refusals matter most: what an agent was
    /// when it asked for something it could not have is the part worth learning from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_model: Option<String>,
}

/// One verified effect-start or terminal event in [`RequestEvidenceView`]. This is a closed
/// metadata/receipt projection, not a raw audit row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvidenceView {
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_binding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutation_invoked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect_outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub result: Value,
}

/// One verified relay event, the projection BOTH relay surfaces render: the hops under
/// a request's evidence, and the operator's cross-session `cermet log --hops`.
///
/// A closed projection of the fields the broker itself wrote onto the event — never a raw row, and
/// never anything the agent claimed: the method and target are what the relay decided against, and
/// the status is what the upstream answered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayHopView {
    /// `relay_session_opened` | `relay_request_forwarded` | `relay_request_refused` |
    /// `relay_request_failed` | `relay_session_closed`.
    pub event_type: String,
    /// When the broker chained the event.
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// What the upstream answered on a forwarded hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u64>,
    /// Why a hop was refused, or why a forwarded one failed — the broker's stable reason string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What that refusal knew beyond its reason word, in one line: the offending field or key, the
    /// frozen constraint as it was enforced, the value the hop offered, and — where one is
    /// computable — the remedy. The reason word stays the machine-readable code; this is additional
    /// to it, never a rewriting of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Whether this hop is the grant's single effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
    /// On a FORWARDED hop: the key names it carried that its matched shape does not enumerate —
    /// query then body, names only, bounded with a `+N more` mark past the cap. An OBSERVATION, not
    /// a verdict: the hop was authorized on its shape and its binds, and this says what else rode
    /// along, so an operator can see whether any of it is worth pinning. Absent when there was none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undeclared_keys: Option<Vec<String>>,
    /// Whether this refusal BURNED the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burned: Option<bool>,
    /// How the session ended, on the `relay_session_closed` row only (`burned` | `ttl` |
    /// `authority_changed` | `lockdown_engaged`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed: Option<String>,
}

/// The agent `catalog` reply payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogListing {
    pub catalog: Vec<crate::templates::CatalogEntry>,
}

#[cfg(test)]
mod tests {
    use super::{EffectFailureClass as Class, EffectOutcome, EffectState, FailureSignal as Signal};

    /// ONE word per disposition, everywhere. `as_str` is what the broker writes into the durable
    /// terminal record and what the evidence validator reads back; `serde` is what
    /// every view, wire frame and receipt renders. They must be the same string, or a translation
    /// table appears between them — which is exactly the drift that put `pre_effect` on the wire
    /// while `definitely_pre_effect` sat in the audit row for the same fact.
    #[test]
    fn every_disposition_is_spelled_one_way_by_serde_and_by_the_record() {
        for outcome in [
            EffectOutcome::PreEffect,
            EffectOutcome::Succeeded,
            EffectOutcome::DefinitelyFailed,
            EffectOutcome::Ambiguous,
        ] {
            let serialized = serde_json::to_value(outcome).expect("a disposition serializes");
            assert_eq!(
                serialized,
                serde_json::json!(outcome.as_str()),
                "{outcome:?}"
            );
            let parsed: EffectOutcome =
                serde_json::from_value(serialized).expect("and round-trips");
            assert_eq!(parsed, outcome);
        }
        // The durable word the terminal record has always carried.
        assert_eq!(EffectOutcome::PreEffect.as_str(), "definitely_pre_effect");
    }

    /// The whole classification rule, driven signal by signal. The names are BEHAVIORAL: each
    /// asserted pair says "this evidence means that next step".
    #[test]
    fn every_class_is_derived_from_a_typed_signal() {
        for (signal, expected) in [
            // Aimed at the credential's authority: re-scope or replace the key.
            (Signal::HttpStatus(401), Class::ProviderAuthRefused),
            (Signal::HttpStatus(403), Class::ProviderAuthRefused),
            // The request itself is unacceptable: the fields must change.
            (Signal::HttpStatus(400), Class::ProviderInputRefused),
            (Signal::HttpStatus(422), Class::ProviderInputRefused),
            // Back off — its own behavior, so its own class.
            (Signal::HttpStatus(429), Class::ProviderRateLimited),
            // The provider's own side failed: retry later.
            (Signal::HttpStatus(500), Class::ProviderTransient),
            (Signal::HttpStatus(502), Class::ProviderTransient),
            (Signal::HttpStatus(599), Class::ProviderTransient),
            // Nothing left the box, so nothing can have happened: retry freely.
            (Signal::NeverSent, Class::TransportPreSend),
            // It went out and we never learned the answer: reconcile, never blind-retry.
            (Signal::SentWithoutAnswer, Class::TransportNoResponse),
            // The daemon attached a credential AND the upstream demanded one.
            (
                Signal::GitUpstream {
                    credential_attached: true,
                    demanded_credentials: true,
                },
                Class::ProviderAuthRefused,
            ),
            (Signal::ResponseShapeUnexpected, Class::ProtocolDrift),
            (
                Signal::ApprovedOutcomeContradicted,
                Class::PostconditionMismatch,
            ),
            (Signal::LocalFault, Class::LocalExecutionFailure),
            // The residual. A 404 is "no such object" on one provider and "your token may not see
            // it" on another; a 409 is a state conflict this vocabulary has no behavior for; an
            // upstream that refused for some other reason, or one that demanded credentials we
            // never attached, says nothing about a key we did not send.
            (Signal::HttpStatus(404), Class::Failed),
            (Signal::HttpStatus(409), Class::Failed),
            (Signal::HttpStatus(200), Class::Failed),
            (Signal::HttpStatus(302), Class::Failed),
            (
                Signal::GitUpstream {
                    credential_attached: true,
                    demanded_credentials: false,
                },
                Class::Failed,
            ),
            (
                Signal::GitUpstream {
                    credential_attached: false,
                    demanded_credentials: true,
                },
                Class::Failed,
            ),
            (Signal::Unclassifiable, Class::Failed),
        ] {
            assert_eq!(Class::of(signal), expected, "signal {signal:?}");
        }
    }

    /// No status derives [`Class::ProviderPolicyRefused`]. Providers disagree about what 403 and
    /// 422 mean, and the class that would be a guess is left with no producer rather than made up.
    #[test]
    fn no_status_is_guessed_into_a_policy_refusal() {
        for status in 100..600u16 {
            assert_ne!(
                Class::of(Signal::HttpStatus(status)),
                Class::ProviderPolicyRefused,
                "status {status} must not be guessed into a policy refusal"
            );
        }
    }

    /// The wire spelling is the enum's own, in ONE place: the audit event's `failure_class` value
    /// (`as_str`, the `provider_evidence_failed` precedent) and the batch's serde rename must not be
    /// two vocabularies that can drift.
    #[test]
    fn the_class_has_one_spelling() {
        for class in [
            Class::ProviderAuthRefused,
            Class::ProviderPolicyRefused,
            Class::ProviderInputRefused,
            Class::ProviderRateLimited,
            Class::ProviderTransient,
            Class::TransportPreSend,
            Class::TransportNoResponse,
            Class::PostconditionMismatch,
            Class::ProtocolDrift,
            Class::LocalExecutionFailure,
            Class::Failed,
        ] {
            assert_eq!(
                serde_json::to_value(class).unwrap(),
                serde_json::Value::String(class.as_str().to_string())
            );
        }
    }

    /// The same rule for the effect-state vocabulary, which has the same two spellings to keep
    /// together: `as_str` is what the receipt row's suffix prints (`→expired_unused`) and serde is
    /// what `log <request_id>` renders. A drift between them would put two words on two surfaces
    /// for one fact — and a reader who greps the log for what the JSON told them would find
    /// nothing.
    #[test]
    fn the_effect_state_has_one_spelling() {
        for state in [
            EffectState::Ok,
            EffectState::Burned,
            EffectState::ExpiredUnused,
            EffectState::Unresolved,
        ] {
            assert_eq!(
                serde_json::to_value(state).unwrap(),
                serde_json::Value::String(state.as_str().to_string()),
                "{state:?}"
            );
            // And back, so the token a surface prints is one this build can read again.
            let parsed: EffectState =
                serde_json::from_value(serde_json::json!(state.as_str())).expect("it round-trips");
            assert_eq!(parsed, state);
        }
    }
}
