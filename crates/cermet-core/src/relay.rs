//! The loopback relay's session state and per-hop verdict.
//!
//! The native `vercel` CLI runs as the agent's own uid in the project dir and is pointed at a
//! loopback listener inside cermetd with `--api`. Its `--token` slot carries a GRANT HANDLE, not a
//! credential. Per request cermetd maps the handle to a live session, checks the request against the
//! verb's frozen predicate, and only then swaps in the vaulted token on the outbound hop.
//!
//! This module owns everything that decides; it holds NO credential and performs NO egress. The
//! credentialed hop lives in [`crate::provider::RelayEgress`]; the vault open, the audit chain, and
//! the grant lifecycle live in the broker (`broker/relay.rs`).
//!
//! Adversaries:
//! - **T1** third-party content steering a cooperative model into "also deploy prod / pull the env":
//!   every hop must match one enumerated `(method, path, query_keys)` shape AND agree with every
//!   frozen field the shape binds. A miss refuses BEFORE the credential is attached and BURNS the
//!   session — a session being probed is done. That extends to the session's own DATAFLOW:
//!   a wildcard path segment is pinned to what this session's approved effect actually produced, so
//!   "while you're in there, read the other deployment" is outside the grant too.
//! - **T2** model accident (`--prod`, a fat-fingered project): identical mechanism, same refusal.
//!   One dimension none of the per-hop checks cover is VOLUME. A shape a session may
//!   repeat (the upload) declares a `caps:` budget, so an accident loop, or a T1 "while you're there,
//!   keep uploading", stops at a finite number of hops and bytes instead of running for the TTL.
//! - **T3** a peer uid on the box: the listener is loopback-only and every request needs an unguessable
//!   handle (≥128 bits, minted here). An unknown handle is refused with nothing else revealed. A handle
//!   STOLEN out of `/proc/<pid>/cmdline` is a named, accepted cost — bounded to the predicate.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::templates::{
    predicate_path_matches, predicate_path_wildcards, PredicateRule, RelayBind, RelayCaps,
    MAX_PREDICATE_PATH_BYTES,
};

/// One query parameter as it arrived: its name, and its RAW value (`None` for a bare `?key`).
type QueryPair<'a> = (&'a str, Option<&'a str>);

/// Relay settings. Every value here is a DECLARED daemon setting (`relay_listen`, `relay_ttl_secs`,
/// `relay_max_body_bytes` in `/etc/cermetd/config.toml`); these are the defaults, not hidden behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    /// The loopback authority cermetd's relay listens on, and the authority of the URL handed to the
    /// agent. EMPTY disables the relay: no listener, and a relay verb refuses at execute.
    pub listen: String,
    /// How long a relay session stays usable after it opens.
    pub ttl_secs: u64,
    /// Cap on one buffered request or response body.
    pub max_body_bytes: usize,
}

pub const DEFAULT_RELAY_LISTEN: &str = "127.0.0.1:7133";
pub const DEFAULT_RELAY_TTL_SECS: u64 = 600;
pub const DEFAULT_RELAY_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_RELAY_LISTEN.to_string(),
            ttl_secs: DEFAULT_RELAY_TTL_SECS,
            max_body_bytes: DEFAULT_RELAY_MAX_BODY_BYTES,
        }
    }
}

impl RelayConfig {
    pub fn enabled(&self) -> bool {
        !self.listen.is_empty()
    }

    /// The base URL the native client is pointed at (`vercel --api <url>`).
    pub fn base_url(&self) -> String {
        format!("http://{}", self.listen)
    }
}

/// The constant, self-naming head every handle carries. A handle IS inert — single-use,
/// TTL'd, loopback-only, predicate-bounded — but that was illegible from the string, and a
/// third-party permission classifier read `--token <24 random chars>` as secret-handling and blocked
/// the invocation (T2: the agent then thrashes on a refusal that is not about its authority).
/// Saying so on the face of the string costs nothing and needs no daemon lookup.
///
/// UNDERSCORES, not hyphens. Probe-verified against vercel CLI 58.4.4: `--token`
/// rejects a value containing `-` ("Must not contain: \"-\"") or `.`, and accepts `_`.
pub const HANDLE_PREFIX: &str = "cermet_relay_";

/// RANDOM handle length in `[A-Za-z0-9]` characters. 24 × log2(62) ≈ 142 bits — comfortably over the
/// 128-bit floor, which is measured over this part alone (the prefix above is legibility, never
/// entropy). The alphabet is a hard requirement, not a style: see [`HANDLE_PREFIX`].
const HANDLE_CHARS: usize = 24;

/// Mint a relay handle. It is a capability REFERENCE, never a secret field: it names a live session
/// the daemon holds, carries no credential, and is what the agent puts in `--token`.
pub fn mint_handle() -> String {
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    let random: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(HANDLE_CHARS)
        .map(char::from)
        .collect();
    debug_assert!(random.chars().all(|c| c.is_ascii_alphanumeric()));
    format!("{HANDLE_PREFIX}{random}")
}

/// Bounds on the NAMES an `undeclared_body_key` refusal reports. The body is already
/// size-capped, but a body assembled from injected content (T1) could still carry hundreds of junk
/// keys or one enormous name; the audit row and the client message are bounded here for the same
/// reason `capped_target` bounds the path. Both caps are generous next to any real provider payload.
const MAX_NAMED_UNDECLARED_KEYS: usize = 8;
const MAX_UNDECLARED_KEY_NAME_BYTES: usize = 64;

/// One reported key name, truncated on a char boundary. A truncated name still tells the operator
/// which family of parameter arrived, which is what the decision needs.
fn capped_key_name(key: &str) -> String {
    if key.len() <= MAX_UNDECLARED_KEY_NAME_BYTES {
        return key.to_string();
    }
    let mut capped = String::with_capacity(MAX_UNDECLARED_KEY_NAME_BYTES);
    for ch in key.chars() {
        if capped.len() + ch.len_utf8() > MAX_UNDECLARED_KEY_NAME_BYTES {
            break;
        }
        capped.push(ch);
    }
    capped.push('…');
    capped
}

/// Which dimension of a shape's declared budget a hop would have spent past. It names the
/// YAML key an operator would edit, and it is what the audit `reason` distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCapKind {
    /// The count of authorized hops on the shape.
    Uses,
    /// The aggregate request bytes those hops carried.
    Bytes,
}

impl RelayCapKind {
    /// The `caps:` key this dimension is declared under.
    pub fn declared(&self) -> &'static str {
        match self {
            RelayCapKind::Uses => "max_uses",
            RelayCapKind::Bytes => "max_total_bytes",
        }
    }
}

/// Why a hop was refused. Every variant refuses BEFORE the credential is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayRefusal {
    /// No live session for this handle (unknown, already closed, or burned) — the T3 answer.
    UnknownHandle,
    /// The session's TTL lapsed.
    Expired,
    /// The request path itself is not something the relay will forward at all.
    MalformedRequest,
    /// The request matched no enumerated predicate shape (method, path, or an undeclared query key).
    NoMatchingShape,
    /// The shape matched but a bound frozen field disagreed with the request.
    BindMismatch,
    /// The shape matched but the body carried a top-level key the rule does not declare.
    /// A provider body parameter nobody ratified is authority nobody reviewed — Vercel's `project`,
    /// `deploymentId`, and `customEnvironmentSlugOrId` each override a field the sentence pinned.
    ///
    /// It carries the offending key NAMES — all of them, capped — because a refusal that will not
    /// say which key it refused makes widening guesswork instead of evidence. NAMES ONLY, never
    /// values: the name is what an operator needs in order to decide whether to ratify the key; the
    /// value is the agent's payload and has no business in a log or in a client-visible message.
    UndeclaredBodyKey { keys: Vec<String> },
    /// The single effect this grant authorizes has already passed.
    EffectAlreadyUsed,
    /// The hop is inside the sentence, but the shape's declared per-session budget has no
    /// room left for it. It is the ONLY refusal that is about volume rather than authority, which is
    /// why it is checked last — an out-of-sentence hop reports the authority defect, not this.
    CapExceeded { cap: RelayCapKind },
    /// The request body is over the declared cap.
    BodyTooLarge,
    /// The effect's own response contradicted a field the approval froze. It is the one
    /// class `authorize` never returns — by the time it is known the effect has ALREADY LANDED, so
    /// there is no hop left to refuse. It is recorded as the burn: the session stops here, its
    /// receipt names this as what ended it, and every later hop renders as [`Self::UnknownHandle`].
    OutcomeMismatch,
}

impl RelayRefusal {
    /// The HTTP status the native client sees. Fail closed and boring: nothing here reveals whether a
    /// handle exists, which shape was closest, or what the frozen value is.
    ///
    /// (T2) NO refusal speaks in 401 or 403. Both are lies about what happened — the
    /// identity is fine, the capability is spent or the request is outside it — and the native
    /// `vercel` CLI turns them into "Authentication error. Run `vercel login`", which sends an agent
    /// re-authenticating forever. Probed against vercel CLI 58.4.4 (loopback listener):
    /// the CLI renders [`Self::message`] verbatim at 400/402/409/410/422/451, and hard-codes its own
    /// invalid-token line at 403 on the preflight `GET /v2/user`. Nothing about the refusal's
    /// SEMANTICS changes here — only its words and its number.
    ///
    /// The classes stay distinguishable (the audit `reason` in the body always was), and that
    /// discloses nothing to a peer uid guessing handles: everything except `UnknownHandle` requires
    /// already holding a live one.
    pub fn status(&self) -> u16 {
        match self {
            // Conflict: the capability this handle named is spent or gone.
            RelayRefusal::UnknownHandle | RelayRefusal::EffectAlreadyUsed => 409,
            // Gone: it existed and its declared TTL lapsed.
            RelayRefusal::Expired => 410,
            RelayRefusal::MalformedRequest => 400,
            RelayRefusal::BodyTooLarge => 413,
            // Unprocessable: the request is well-formed and outside what the sentence authorized.
            RelayRefusal::NoMatchingShape
            | RelayRefusal::BindMismatch
            | RelayRefusal::UndeclaredBodyKey { .. }
            | RelayRefusal::CapExceeded { .. }
            | RelayRefusal::OutcomeMismatch => 422,
        }
    }

    /// What the refusal SAYS, in the field the native client prints as its own error
    /// (`error.message`, the shape Vercel's own API uses). Every line names cermet as the refuser,
    /// states the truth about the capability, and points at the trail — because the broker knew why
    /// the deploy stopped and, before this, said so only in the audit log.
    pub fn message(&self) -> String {
        let text = match self {
            RelayRefusal::UnknownHandle => {
                "cermet: no live relay session for this handle — grants are single-use, so a spent, \
                 refused, or lapsed session is gone; see `cermet log --hops` for the trail and \
                 request the capability again"
            }
            RelayRefusal::Expired => {
                "cermet: this relay session expired (its declared TTL lapsed) — see \
                 `cermet log --hops` and request the capability again"
            }
            RelayRefusal::EffectAlreadyUsed => {
                "cermet: this grant's single effect has already run — grants are single-use; see \
                 `cermet log --hops` and request the capability again"
            }
            RelayRefusal::NoMatchingShape => {
                "cermet: the approved sentence does not authorize this request — see \
                 `cermet log --hops`, and widen the rule if it should"
            }
            RelayRefusal::BindMismatch => {
                "cermet: this request contradicts a field the approval froze — see \
                 `cermet log --hops`"
            }
            // Never rendered to a live hop (the session is already closed when this is
            // recorded), but it is what the receipt and the audit row NAME, so it says the true
            // thing: the effect landed and disagrees with the approval.
            RelayRefusal::OutcomeMismatch => {
                "cermet: the provider's own response to this grant's effect contradicts a field the \
                 approval froze — the effect ALREADY LANDED, so this is detection, not prevention; \
                 see `cermet log --hops`"
            }
            // Name the DIMENSION, because the two have different fixes — a count that ran
            // out means the deploy has more files than the verb was ratified for, a byte budget that
            // ran out means it is bigger than it was ratified for. Both are one edit to the same
            // stanza, and neither is legible from "the request was refused".
            RelayRefusal::CapExceeded { cap } => {
                return format!(
                    "cermet: this relay session has spent the `{}` budget the approved verb declares \
                     for this request shape — see `cermet log --hops`, and raise the shape's `caps:` \
                     if a real deploy needs more",
                    cap.declared()
                )
            }
            // Name the keys here too. This message is what the native CLI prints, so
            // naming them is what makes widening evidence-driven without a capture harness.
            RelayRefusal::UndeclaredBodyKey { keys } => {
                return format!(
                    "cermet: the request body carries {} the approved verb does not declare ({}) — \
                     see `cermet log --hops`, and ratify the parameter if it should be allowed",
                    if keys.len() == 1 {
                        "a parameter"
                    } else {
                        "parameters"
                    },
                    keys.join(", ")
                )
            }
            RelayRefusal::MalformedRequest => {
                "cermet: the relay will not forward this request path — see `cermet log --hops`"
            }
            RelayRefusal::BodyTooLarge => {
                "cermet: the request body is over the daemon's declared `relay_max_body_bytes` cap"
            }
        };
        text.to_string()
    }

    /// The stable audit reason.
    pub fn reason(&self) -> &'static str {
        match self {
            RelayRefusal::UnknownHandle => "unknown_handle",
            RelayRefusal::Expired => "session_expired",
            RelayRefusal::MalformedRequest => "malformed_request",
            RelayRefusal::NoMatchingShape => "no_matching_shape",
            RelayRefusal::BindMismatch => "bind_mismatch",
            RelayRefusal::UndeclaredBodyKey { .. } => "undeclared_body_key",
            RelayRefusal::EffectAlreadyUsed => "effect_already_used",
            RelayRefusal::BodyTooLarge => "body_too_large",
            RelayRefusal::OutcomeMismatch => "outcome_mismatch",
            // Two reasons, not one with a payload — the audit row an operator greps is
            // where "which budget ran out" has to be answerable without reading a nested field.
            RelayRefusal::CapExceeded {
                cap: RelayCapKind::Uses,
            } => "cap_exceeded_uses",
            RelayRefusal::CapExceeded {
                cap: RelayCapKind::Bytes,
            } => "cap_exceeded_bytes",
        }
    }

    /// Whether this refusal BURNS the session. A request that misses the predicate or contradicts a
    /// frozen field is a session being probed (T1/T2) — it is done, so every later hop is an unknown handle.
    /// A lapsed TTL or an unknown handle burns nothing (there is nothing live to burn), and an
    /// oversized body is a transport limit, not a probe.
    pub fn burns(&self) -> bool {
        matches!(
            self,
            RelayRefusal::NoMatchingShape
                | RelayRefusal::BindMismatch
                | RelayRefusal::UndeclaredBodyKey { .. }
                | RelayRefusal::EffectAlreadyUsed
                | RelayRefusal::MalformedRequest
                | RelayRefusal::OutcomeMismatch
                // A session that pushes past its declared budget is not a session having
                // a bad day — the honest client's traffic is bounded by the manifest it built, so
                // the overrun is a loop or a probe. Same discipline as every other overreach.
                | RelayRefusal::CapExceeded { .. }
        )
    }
}

/// The verdict on one hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayVerdict {
    /// Authorized: forward it, and whether this hop consumed THE single effect.
    Forward {
        effect: bool,
    },
    Refuse(RelayRefusal),
}

/// What the relay observed on the wire, from which the session's receipt is DERIVED. Nothing here is
/// ever taken from the agent's claims — only from a response the relay itself forwarded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayObservations {
    pub deployment_id: Option<String>,
    pub deployment_url: Option<String>,
    pub last_state: Option<String>,
    pub hops: u64,
    pub refusals: u64,
}

/// How much of one derived response VALUE the session keeps — receipt facts, captures, and the
/// observed half of an outcome mismatch alike. The tee is already bounded; this bounds one field of
/// it, so a provider echoing a huge string cannot inflate a receipt, an audit row, or session state.
const OBSERVED_VALUE_CHARS: usize = 256;

/// The effect landed and its own response contradicts a field the approval froze. This is
/// what the audit row carries — frozen versus observed — and it is DETECTION: the deployment exists
/// by the time this value can be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayOutcomeMismatch {
    /// The top-level response key that disagreed.
    pub key: String,
    /// The frozen field the assertion compares it against.
    pub field: String,
    /// What the approval froze — `None` when the frozen value means the key must be ABSENT (Vercel
    /// has no `target: preview`, so an approved preview expects no target key back).
    pub expected: Option<String>,
    /// What the response actually carried: a string value, or `None` for absent, null, or non-string.
    pub observed: Option<String>,
}

/// One live relay session: a single-use grant's effect, held open for its TTL.
///
/// It is a FROZEN copy of what the grant authorized — the predicate the ratified template declared and
/// the field values the approval froze — so nothing it enforces can drift while it is live.
#[derive(Debug, Clone)]
pub struct RelaySession {
    pub handle: String,
    pub grant_id: String,
    pub request_id: String,
    /// The audit session of the request that opened this relay session.
    pub session_id: String,
    pub provider: String,
    pub action: String,
    /// The authenticated sentence-authority digest the grant was minted under. Re-read per hop: an
    /// authority change closes the session rather than letting a revoked allow keep deploying.
    pub policy_fingerprint: String,
    predicate: Vec<PredicateRule>,
    /// The frozen str fields the predicate binds, by name.
    frozen: BTreeMap<String, String>,
    /// What this session DERIVED from its own effect's response, by capture name. It is a
    /// second map, not more entries in `frozen`, because the two have different authorities: `frozen`
    /// is what a human approved, `captured` is what the approved effect then produced. Write-once —
    /// a session that could be re-pointed at a second deployment id is the hole this closes.
    captured: BTreeMap<String, String>,
    /// What this session has already spent against each BUDGETED shape, keyed by the
    /// shape's index in the frozen predicate (the validator refuses a duplicate `(method, path)`, so
    /// the index names exactly one shape for the session's whole life). Absent = nothing spent yet.
    spent: BTreeMap<usize, ShapeSpend>,
    pub opened_at: i64,
    pub expires_at: i64,
    effect_used: bool,
    burned: Option<BurnedHop>,
    observations: RelayObservations,
}

/// What one session has spent against one budgeted shape. Charged only on an AUTHORIZED
/// hop — a refusal costs the session nothing, because nothing was credentialed.
#[derive(Debug, Clone, Copy, Default)]
struct ShapeSpend {
    uses: u64,
    bytes: u64,
}

impl ShapeSpend {
    /// Which dimension of `caps` one more hop of `body_bytes` would spend past, if either. Saturating
    /// because the answer at the ceiling is "refuse" either way; a wrap would answer "allow".
    fn would_exceed(&self, caps: RelayCaps, body_bytes: usize) -> Option<RelayCapKind> {
        if self.uses.saturating_add(1) > caps.max_uses {
            return Some(RelayCapKind::Uses);
        }
        if self.bytes.saturating_add(body_bytes as u64) > caps.max_total_bytes {
            return Some(RelayCapKind::Bytes);
        }
        None
    }

    fn charge(&mut self, body_bytes: usize) {
        self.uses = self.uses.saturating_add(1);
        self.bytes = self.bytes.saturating_add(body_bytes as u64);
    }
}

/// The hop that burned a session, kept so the receipt can say WHICH request ended it. The native
/// `vercel` CLI swallows the relay's refusal body and prints its own guess, so this is the agent's
/// only honest mirror of what it actually asked for.
#[derive(Debug, Clone)]
struct BurnedHop {
    refusal: RelayRefusal,
    method: String,
    target: String,
}

/// How much of a refused hop's method/target the receipt keeps. The receipt is durable audit data
/// on a path any peer uid at the loopback port can reach and the burning refusal classes
/// include `MalformedRequest`, which is decided BEFORE the predicate's own path cap applies.
const RECEIPT_HOP_CHARS: usize = 256;

impl RelaySession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        handle: String,
        grant_id: String,
        request_id: String,
        session_id: String,
        provider: String,
        action: String,
        policy_fingerprint: String,
        predicate: Vec<PredicateRule>,
        frozen: BTreeMap<String, String>,
        opened_at: i64,
        ttl_secs: u64,
    ) -> Self {
        Self {
            handle,
            grant_id,
            request_id,
            session_id,
            provider,
            action,
            policy_fingerprint,
            predicate,
            frozen,
            captured: BTreeMap::new(),
            spent: BTreeMap::new(),
            opened_at,
            expires_at: opened_at + ttl_secs as i64,
            effect_used: false,
            burned: None,
            observations: RelayObservations::default(),
        }
    }

    pub fn observations(&self) -> &RelayObservations {
        &self.observations
    }

    pub fn burned(&self) -> Option<&RelayRefusal> {
        self.burned.as_ref().map(|hop| &hop.refusal)
    }

    pub fn effect_used(&self) -> bool {
        self.effect_used
    }

    /// Decide ONE hop. It reads the frozen session and the request, and nothing else — no clock but
    /// `now`, no I/O, no credential. The caller still records the verdict (`note_*`) so a refusal
    /// cannot be silently retried.
    ///
    /// It is `&mut self` for the one thing a decision must also do: CHARGE the matched
    /// shape's declared budget. Only this function knows which shape a hop matched, and charging on
    /// the decision is the same conservative reading the single effect already takes — an authorized
    /// hop has spent its budget whether or not the transport that follows succeeds.
    pub fn authorize(&mut self, method: &str, target: &str, body: &[u8], now: i64) -> RelayVerdict {
        if self.burned.is_some() {
            return RelayVerdict::Refuse(RelayRefusal::UnknownHandle);
        }
        if now > self.expires_at {
            return RelayVerdict::Refuse(RelayRefusal::Expired);
        }
        let (path, query) = match split_target(target) {
            Some(parts) => parts,
            None => return RelayVerdict::Refuse(RelayRefusal::MalformedRequest),
        };
        let query: Vec<QueryPair> = query_pairs(query);
        // The matched shape is held by INDEX, not by reference: the budget charge at the end of this
        // function needs `&mut self`, and the index names the same shape for the session's whole life
        // (the validator refuses a duplicate `(method, path)`).
        let Some(index) = self.predicate.iter().position(|rule| {
            rule.method == method
                && predicate_path_matches(&rule.path, path)
                && query
                    .iter()
                    .all(|(key, _)| rule.query_keys.iter().any(|allowed| allowed == key))
        }) else {
            return RelayVerdict::Refuse(RelayRefusal::NoMatchingShape);
        };
        let rule = &self.predicate[index];
        if rule.once && self.effect_used {
            return RelayVerdict::Refuse(RelayRefusal::EffectAlreadyUsed);
        }
        let binds = rule.binds();
        // The query binds first — they read the target, so they apply on every method,
        // including the bodyless reads a session's own polling does. Key closure above decided
        // WHICH parameters may appear; this decides what their values are allowed to say.
        for bind in &binds {
            if let Some(key) = bind.query_key() {
                if !self.query_bind_holds(bind, key, &query) {
                    return RelayVerdict::Refuse(RelayRefusal::BindMismatch);
                }
            }
        }
        // Then the path binds, which pin every wildcard segment to a value this session
        // CAPTURED from its own effect. Before the create lands nothing is captured, so a poll
        // refuses — the honest CLI never polls before the deployment it is polling for exists.
        for bind in &binds {
            if bind.path_wildcards() && !self.path_bind_holds(bind, &rule.path, path) {
                return RelayVerdict::Refuse(RelayRefusal::BindMismatch);
            }
        }
        // A rule declares a body check by declaring `body_keys` (required alongside any bind); a rule
        // with neither — an opaque upload — never has its body parsed at all.
        if let Some(allowed) = rule.body_keys() {
            let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(body) else {
                // A shape whose body must be checked but is not a JSON object cannot pass.
                return RelayVerdict::Refuse(RelayRefusal::BindMismatch);
            };
            // The body key set is CLOSED, exactly like `query_keys`. Checking only the bound
            // keys let every other documented parameter ride through credentialed — and Vercel
            // documents three that override a frozen field (`project` overrides `name`,
            // `customEnvironmentSlugOrId` overrides the target environment, `deploymentId` redeploys
            // an arbitrary existing deployment). A parameter the provider adds LATER now fails closed
            // too: drift breaks the deploy, it never widens the grant.
            // Collect EVERY undeclared key, not just the first — an operator deciding
            // whether to ratify one needs the whole set, and a second refusal costs another grant.
            let undeclared: Vec<String> = object
                .keys()
                .filter(|key| {
                    !(allowed.iter().any(|declared| &declared == key)
                        || binds.iter().any(|bind| bind.body_key() == Some(key)))
                })
                .take(MAX_NAMED_UNDECLARED_KEYS)
                .map(|key| capped_key_name(key))
                .collect();
            if !undeclared.is_empty() {
                return RelayVerdict::Refuse(RelayRefusal::UndeclaredBodyKey { keys: undeclared });
            }
            for bind in &binds {
                let Some(key) = bind.body_key() else { continue };
                if !self.body_bind_holds(bind, key, &object) {
                    return RelayVerdict::Refuse(RelayRefusal::BindMismatch);
                }
            }
        }
        // The budget is the LAST check, and the only one about VOLUME rather than
        // authority. Last on purpose: a hop that also contradicts the sentence must be refused for
        // THAT, so the trail an operator reads names the authority defect and not the byte count.
        let (effect, caps) = (rule.once, rule.caps());
        if let Some(caps) = caps {
            let spent = self.spent.entry(index).or_default();
            if let Some(cap) = spent.would_exceed(caps, body.len()) {
                return RelayVerdict::Refuse(RelayRefusal::CapExceeded { cap });
            }
            spent.charge(body.len());
        }
        RelayVerdict::Forward { effect }
    }

    /// Does one body bind hold against this request body? The frozen value is the authority; an
    /// `omit:` literal means the safe case is the key's ABSENCE (Vercel has no legal
    /// `target: preview`).
    fn body_bind_holds(
        &self,
        bind: &RelayBind,
        key: &str,
        object: &serde_json::Map<String, Value>,
    ) -> bool {
        let Some(frozen) = self.frozen.get(&bind.field) else {
            // Unreachable for a validated template (a bound field is required), and fail closed.
            return false;
        };
        let present = object.get(key);
        match &bind.absent_when {
            Some(literal) if literal == frozen => {
                matches!(present, None | Some(Value::Null))
            }
            _ => present.and_then(Value::as_str) == Some(frozen.as_str()),
        }
    }

    /// Does one QUERY bind hold? Same shape as the body form on the other authority-bearing
    /// wire position — Vercel's `teamId` names the account SCOPE a request lands in, and an approval
    /// that froze one team never authorizes a hop into another. The `omit:` literal is the
    /// personal-scope case: a personal token sends no `teamId` at all, so the key must be ABSENT.
    ///
    /// The value is compared RAW. CLI 58.4.4 sends a bare Vercel team id (`team_XXXX`, in
    /// `[A-Za-z0-9_]`), which percent-encoding never touches, so no decoder is built for a shape no
    /// client sends — an encoded value simply is not the frozen one and fails closed. A REPEATED key
    /// is ambiguous about which value the upstream would honor, and fails closed for the same reason.
    fn query_bind_holds(&self, bind: &RelayBind, key: &str, query: &[QueryPair]) -> bool {
        let Some(frozen) = self.frozen.get(&bind.field) else {
            // Unreachable for a validated template (a bound field is required), and fail closed.
            return false;
        };
        let mut present = query.iter().filter(|(name, _)| *name == key);
        let first = present.next();
        if present.next().is_some() {
            return false;
        }
        match &bind.absent_when {
            Some(literal) if literal == frozen => first.is_none(),
            _ => first.and_then(|(_, value)| *value) == Some(frozen.as_str()),
        }
    }

    /// Does one PATH bind hold? Every `*` segment of the shape's own pattern must equal the
    /// value this session captured from its effect's response — Vercel's poll and events reads all
    /// carry the deployment id, and a session that could name any id at all is authority leaking past
    /// the one effect the approval bought.
    ///
    /// Fail closed on every unknown: nothing captured yet (the create has not landed, or its response
    /// named nothing), a pattern with no wildcard, or a path that does not match. A captured value
    /// that could never BE a path segment (it contains a `/`, say) simply equals no segment, which is
    /// the same refusal — no sanitizing pass is needed to make that true.
    fn path_bind_holds(&self, bind: &RelayBind, pattern: &str, path: &str) -> bool {
        let Some(name) = bind.captured_name() else {
            // Unreachable for a validated template (a path bind must read a capture), and fail closed.
            return false;
        };
        let Some(expected) = self.captured.get(name) else {
            return false;
        };
        let Some(wildcards) = predicate_path_wildcards(pattern, path) else {
            return false;
        };
        !wildcards.is_empty() && wildcards.iter().all(|segment| segment == expected)
    }

    /// Record an authorized hop. Called after the forward so a transport failure still counts the
    /// effect: the deployment create may have landed, and a second attempt must not be admitted.
    pub fn note_forward(&mut self, effect: bool) {
        self.observations.hops = self.observations.hops.saturating_add(1);
        if effect {
            self.effect_used = true;
        }
    }

    /// Record a refusal, burning the session when the refusal class calls for it. The burning hop's
    /// method and target are kept for the receipt — the FIRST one, since that is the hop that ended
    /// the session and everything after it is an unknown handle.
    pub fn note_refusal(&mut self, refusal: RelayRefusal, method: &str, target: &str) {
        self.observations.refusals = self.observations.refusals.saturating_add(1);
        if refusal.burns() && self.burned.is_none() {
            self.burned = Some(BurnedHop {
                refusal,
                method: bounded(method),
                target: bounded(target),
            });
        }
    }

    /// End the session because its own effect's outcome contradicts the approval. It is NOT
    /// a refusal — the hop was authorized, forwarded, and answered — so the refusal COUNT is
    /// untouched; what is recorded is the burn, naming the create hop that landed the contradiction.
    /// Every later hop on the handle is an unknown handle from here.
    pub fn note_outcome_mismatch(&mut self, method: &str, target: &str) {
        if self.burned.is_none() {
            self.burned = Some(BurnedHop {
                refusal: RelayRefusal::OutcomeMismatch,
                method: bounded(method),
                target: bounded(target),
            });
        }
    }

    /// Derive receipt facts from a response the relay itself forwarded. `effect` marks the
    /// deployment-create hop, whose body names the deployment; every other 2xx read refreshes the
    /// last observed state. Claims the agent makes are never a source here.
    pub fn observe_response(
        &mut self,
        effect: bool,
        status: u16,
        body: &[u8],
    ) -> Option<RelayOutcomeMismatch> {
        self.observe_status(effect, status);
        self.observe_body(effect, status, body)
    }

    /// What the response STATUS alone decides. It is split out from the body derivation because the
    /// status is known the moment the upstream HEAD lands, and the relay applies it right there — a
    /// definite provider 4xx on the effect hop is a definite no-effect: the provider refused it and
    /// nothing was created, so the `once` effect is released. This is what admits Vercel's own
    /// two-phase create (create -> 400 missing_files -> upload -> create). The ambiguous outcomes
    /// stay consumed: a 5xx or transport silence never reaches this arm.
    pub fn observe_status(&mut self, effect: bool, status: u16) {
        if effect && (400..=499).contains(&status) {
            self.effect_used = false;
        }
    }

    /// What the response BODY names, once it has been read. THE one place a relay response body is
    /// parsed: the receipt derivation, the outcome assertion, and the capture all
    /// read the same parse of the same bounded tee, in that order.
    ///
    /// `body` is the receipt tee (`RELAY_OBSERVED_TEE_BYTES`), so a response larger than that arrives
    /// TRUNCATED and does not parse — nothing is derived, nothing is asserted, and nothing is
    /// captured, which leaves the session unable to poll. That is the accepted fail-closed cost, not
    /// a handled case: the deploy itself already succeeded or failed on its own, and only the victory
    /// lap is lost (note-not-code, and it is the same silence the receipt derivation always had).
    ///
    /// Returns the FIRST assertion that the effect's own outcome contradicted. The caller burns the
    /// session and audits it; nothing here un-deploys anything, because by now it has landed.
    pub fn observe_body(
        &mut self,
        effect: bool,
        status: u16,
        body: &[u8],
    ) -> Option<RelayOutcomeMismatch> {
        if !(200..=299).contains(&status) {
            return None;
        }
        let value = serde_json::from_slice::<Value>(body).ok()?;
        let string = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(|text| text.chars().take(OBSERVED_VALUE_CHARS).collect::<String>())
        };
        if !effect {
            if self.observations.deployment_id.is_some() {
                if let Some(state) = string("readyState").or_else(|| string("status")) {
                    self.observations.last_state = Some(state);
                }
            }
            return None;
        }
        // The receipt first, and unconditionally: an outcome that contradicts the approval is exactly
        // the one an operator needs named, so the receipt must still say WHAT landed.
        self.observations.deployment_id = string("id");
        self.observations.deployment_url = string("url");

        // Read the effect shape's own stanzas out before touching session state — unreachable for a
        // validated template to be missing (exactly one rule is the effect), and fail closed if so.
        let (asserts, captures) = self
            .predicate
            .iter()
            .find(|rule| rule.once)
            .map(|rule| (rule.asserts(), rule.captures().clone()))?;
        // The assertion, before the capture — a session whose outcome disagrees with its
        // approval is done, and has no business capturing anything to poll with.
        for assertion in asserts {
            // Unreachable for a validated template: an asserted field is required, and
            // `open_relay_session` freezes every one. Skipping it loses DETECTION only — it grants
            // nothing — so there is no reason to burn a live session over an impossible state.
            let Some(frozen) = self.frozen.get(&assertion.field) else {
                continue;
            };
            let observed = string(&assertion.key);
            let expects_absent = assertion.absent_when.as_deref() == Some(frozen.as_str());
            let holds = if expects_absent {
                matches!(value.get(&assertion.key), None | Some(Value::Null))
            } else {
                observed.as_deref() == Some(frozen.as_str())
            };
            if !holds {
                return Some(RelayOutcomeMismatch {
                    key: assertion.key,
                    field: assertion.field,
                    expected: (!expects_absent).then(|| frozen.clone()),
                    observed,
                });
            }
        }
        // What this session may then read. WRITE-ONCE: the effect's response can be
        // observed more than once (the 400-then-retry dance, a provider echo), and a re-pointable
        // session would be the same cross-hop hole with an extra step.
        for (name, key) in captures {
            let Some(observed) = string(&key) else {
                continue;
            };
            if observed.is_empty() {
                continue;
            }
            self.captured.entry(name).or_insert(observed);
        }
        None
    }

    /// The session receipt: what the relay OBSERVED, plus how the session ended.
    pub fn receipt(&self, reason: &str) -> Value {
        json!({
            "grant_id": self.grant_id,
            "request_id": self.request_id,
            "provider": self.provider,
            "action": self.action,
            "closed": reason,
            "opened_at": self.opened_at,
            "expires_at": self.expires_at,
            "hops": self.observations.hops,
            "refusals": self.observations.refusals,
            "burned": self.burned.as_ref().map(|hop| hop.refusal.reason()),
            // The hop that burned it, so the agent can self-diagnose what it asked for without the
            // operator reading the audit chain out of the daemon.
            "burned_method": self.burned.as_ref().map(|hop| hop.method.clone()),
            "burned_target": self.burned.as_ref().map(|hop| hop.target.clone()),
            "deployment_id": self.observations.deployment_id,
            "deployment_url": self.observations.deployment_url,
            "state": self.observations.last_state,
        })
    }
}

/// Split a request target into `(path, query)`, refusing anything the relay will not forward.
///
/// Refused: a non-`/`-rooted target, an over-cap target, a fragment, a non-ASCII/control/space byte, a
/// backslash, an empty or `.`/`..` segment — and any `%`. Percent-encoding is refused outright (T1):
/// the predicate compares raw segments while the upstream would decode them, so `%2e%2e%2f` in a
/// wildcard segment is a path escape. No Vercel path the predicate admits needs an escape.
fn split_target(target: &str) -> Option<(&str, Option<&str>)> {
    if !target.starts_with('/') || target.len() > MAX_PREDICATE_PATH_BYTES {
        return None;
    }
    if target.contains('#') {
        return None;
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    if path.contains('%') || path.contains('\\') || !path.is_ascii() {
        return None;
    }
    if path
        .bytes()
        .any(|b| b <= 0x20 || b == 0x7f || b == b'"' || b == b'<' || b == b'>')
    {
        return None;
    }
    for segment in path.trim_start_matches('/').split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return None;
        }
    }
    Some((path, query))
}

/// What a receipt may say about one refused hop: whole characters, bounded.
fn bounded(value: &str) -> String {
    value.chars().take(RECEIPT_HOP_CHARS).collect()
}

/// The query parameters a target carries, as `(name, raw value)`. The VALUES are read
/// too — a query value can carry as much authority as a body key's (Vercel's `teamId` IS the account
/// scope), so the shape's key allowlist decides which parameters may appear and the shape's binds
/// decide what the ratified ones are allowed to say. A bare `?key` with no `=` yields `None`, which
/// no frozen value equals.
fn query_pairs(query: Option<&str>) -> Vec<QueryPair<'_>> {
    query
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (pair, None),
        })
        .collect()
}

#[cfg(test)]
mod tests;
