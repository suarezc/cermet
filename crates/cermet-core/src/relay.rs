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
//!
//! NOTE (accepted, not code): a refused PATH bind reports the FIRST wildcard segment as what the hop
//! offered. A pattern with two `*` segments whose second one disagreed would therefore name the
//! first — the refusal is still correct, only its quoted value is the wrong segment. No shipped
//! predicate has a two-wildcard pattern, and carrying a per-segment report would add a branch and a
//! plural grammar for a shape nothing writes. What reopens it: a ratified pattern with two
//! wildcards.

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

/// Bounds on the NAMES a key-closure refusal reports. The body is already
/// size-capped, but a body assembled from injected content (T1) could still carry hundreds of junk
/// keys or one enormous name; the audit row and the client message are bounded here for the same
/// reason `capped_target` bounds the path. Both caps are generous next to any real provider payload.
const MAX_NAMED_UNDECLARED_KEYS: usize = 8;
const MAX_UNDECLARED_KEY_NAME_BYTES: usize = 64;

/// How much of one OFFERED value a refusal quotes back. The value came off the hop the same client
/// wrote, so quoting it discloses nothing it does not hold — but it is agent-controlled length (T1),
/// and an audit row is durable, so it is bounded like every other borrowed string here.
const MAX_OFFERED_VALUE_BYTES: usize = 128;

/// Characters that can move or reorder what a terminal displays: every control character, plus the
/// bidi/directional formatting set. THE definition for this crate, and the twin of the operator
/// CLI's own — a refusal detail is agent-authored text that reaches the OPERATOR'S TERMINAL twice
/// over (the native client prints the relay's error body verbatim, and `cermet log --hops` prints
/// the same detail off the audit row), so an escape sequence in a request field would replay live.
fn terminal_affecting(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// One reported string: neutralized, then truncated on a char boundary. A truncated name still
/// tells the operator which family of parameter arrived, which is what the decision needs.
///
/// THE choke point. Every agent-sourced name and value a refusal quotes back — offered values,
/// undeclared key names, the attempted path, and the frozen side of a bind wherever the standing
/// rule pinned nothing and the request chose it — passes through here, so no render site has to
/// remember to do either job.
fn capped(text: &str, max_bytes: usize) -> String {
    let mut capped = String::with_capacity(text.len().min(max_bytes));
    let mut truncated = false;
    for character in text.chars() {
        // A terminal-affecting character becomes a SPACE rather than vanishing: the same choice the
        // operator CLI's own line renderer makes, and it keeps the length of what arrived honest.
        let character = if terminal_affecting(character) {
            ' '
        } else {
            character
        };
        if capped.len() + character.len_utf8() > max_bytes {
            truncated = true;
            break;
        }
        capped.push(character);
    }
    if truncated {
        capped.push('…');
    }
    capped
}

fn capped_key_name(key: &str) -> String {
    capped(key, MAX_UNDECLARED_KEY_NAME_BYTES)
}

fn capped_value(value: &str) -> String {
    capped(value, MAX_OFFERED_VALUE_BYTES)
}

/// A list of names as a refusal spells one: backticked, comma-joined, in the order they arrived.
fn named(names: &[String]) -> String {
    names
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Where on the wire a bind reads the value it pins. It is part of what a refusal
/// discloses: `teamId` in the query and `target` in the body are different edits to whatever wrote
/// the request, and "a field disagreed" names neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayBindPosition {
    Query,
    Body,
    Path,
}

impl RelayBindPosition {
    /// How a refusal names this position to whoever wrote the request.
    pub fn wire(&self) -> &'static str {
        match self {
            RelayBindPosition::Query => "query parameter",
            RelayBindPosition::Body => "body key",
            RelayBindPosition::Path => "path",
        }
    }
}

/// What a bind requires, AS IT IS ENFORCED. It is the constraint the hop was measured against, not
/// the raw source value: an `omit:` transform turns a frozen value into the key's ABSENCE, and a
/// refusal that reported the field's value there would send the requester straight back into the
/// same refusal.
///
/// [`Self::Value`] holds the value VERBATIM — it is what the comparison itself reads — so every
/// render site of it goes through [`capped_value`]. The frozen side is agent-chosen wherever the
/// standing rule pins nothing, and it is exactly as unbounded as the offered side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayBound {
    /// The position must carry exactly this value.
    Value(String),
    /// The position must be ABSENT — an `omit:` transform binds the frozen field to the key not
    /// appearing at all (Vercel has no legal `target: preview`).
    Absent,
    /// The bind has no value to compare against, so nothing satisfies it: a path wildcard whose
    /// capture this session has not made yet (the grant's own effect has not landed), or — a state a
    /// validated template cannot reach — a field the session never froze.
    Unresolved,
}

impl RelayBound {
    /// The requirement in words, as the refusal states it. The path/capture case does not come
    /// through here: it has its own provenance and is rendered by
    /// [`RelayBindMismatch::detail`].
    fn requirement(&self) -> String {
        match self {
            RelayBound::Value(value) => format!("must carry `{}`", capped_value(value)),
            RelayBound::Absent => "must be absent".to_string(),
            RelayBound::Unresolved => {
                "has no frozen value to compare against, so nothing satisfies it".to_string()
            }
        }
    }
}

/// What the refused hop actually put at the bound position. Every variant is a fact about the
/// request the caller itself wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayOffered {
    /// The position is not on this hop at all.
    Absent,
    /// It arrived once, carrying this (bounded) value.
    Value(String),
    /// A query key arrived more than once, which is ambiguous about which value the upstream would
    /// honor — so it fails closed rather than picking one.
    Repeated,
    /// A body key arrived carrying something that is not a JSON string, which no frozen value equals.
    NotAString,
    /// A query key arrived as a bare `?key` with no `=` at all. Distinguished from
    /// [`Self::Absent`] because "it was absent" would be false, and a refusal that mis-states what
    /// arrived is worse than one that says nothing.
    Bare,
}

impl RelayOffered {
    /// What arrived, in words.
    fn offered(&self) -> String {
        match self {
            RelayOffered::Absent => "it was absent".to_string(),
            RelayOffered::Value(value) => format!("it carried `{value}`"),
            RelayOffered::Repeated => {
                "it arrived more than once, which is ambiguous about which value the upstream would \
                 honor"
                    .to_string()
            }
            RelayOffered::NotAString => "it carried a value that is not a string".to_string(),
            RelayOffered::Bare => "it arrived with no value at all".to_string(),
        }
    }
}

/// Everything a `bind_mismatch` already knows at the moment it refuses: which frozen field
/// disagreed, where the hop carries it, what the bind enforces, and what the hop offered instead.
///
/// Nothing here is new authority or new state — the frozen map, the shape and the request are all in
/// hand — and nothing here can be a secret: a bound field is an execution target the catalog already
/// prints, the offered value came off the caller's own request, and a captured value is one this
/// caller's own session already received in the response to its own approved effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayBindMismatch {
    /// What the bind compares against: the frozen field the shape binds (`team`, `project`), or a
    /// `captured.<name>` — this session's own effect response, which is a DIFFERENT provenance and
    /// says so in the detail.
    pub field: String,
    /// Where the hop carries it.
    pub position: RelayBindPosition,
    /// The wire key the bind reads (`teamId`, `name`), or — for a path bind — the shape's own path
    /// pattern, whose `*` segments are what is pinned.
    pub key: String,
    /// The constraint as it is enforced.
    pub bound: RelayBound,
    /// What this hop offered.
    pub offered: RelayOffered,
}

impl RelayBindMismatch {
    /// The CAPTURE this bind compares against, or `None` when it reads an approval-frozen field.
    fn captured_name(&self) -> Option<&str> {
        self.field.strip_prefix(crate::templates::CAPTURE_PREFIX)
    }

    /// The single-line disclosure this refusal carries into the receipt, the audit row, and the
    /// message the native client prints.
    fn detail(&self) -> String {
        // A CAPTURED bind compares against what THIS SESSION'S OWN EFFECT returned — a deployment
        // id is the approved effect's consequence and is deliberately not something a sentence can
        // pin in advance. "The grant froze it" would be false, and the remedy that follows from
        // that framing ("request the capability again") lands a fresh session on the
        // nothing-captured arm below, which refuses with the opposite message. So this case states
        // its own provenance and prescribes only what follows from it.
        if self.captured_name().is_some() {
            return match &self.bound {
                RelayBound::Value(value) => format!(
                    "this session's own effect returned `{}` as `{}`, so this hop's `{}` path must \
                     carry it; {}; a session reads only the effect it created, so drive the native \
                     client at that one",
                    capped_value(value),
                    self.field,
                    self.key,
                    self.offered.offered()
                ),
                // Nothing captured: the effect has not landed, so no value would have satisfied
                // this hop and nothing but running the effect changes that. No remedy is offered,
                // because every candidate points at a surface that cannot answer yet.
                RelayBound::Absent | RelayBound::Unresolved => format!(
                    "this hop's `{}` path is bound to `{}`, and this session has captured nothing \
                     yet (its own effect has not landed), so nothing satisfies it; {}",
                    self.key,
                    self.field,
                    self.offered.offered()
                ),
            };
        }
        let mut text = format!(
            "the grant froze `{}`, so this hop's `{}` {} {}; {}",
            self.field,
            self.key,
            self.position.wire(),
            self.bound.requirement(),
            self.offered.offered()
        );
        // The remedy, and only where one is computable. `Unresolved` has none to give — the
        // value it would name does not exist yet — and inventing one would point at a surface that
        // cannot answer.
        match &self.bound {
            RelayBound::Value(value) => text.push_str(&format!(
                "; grants are single-use, so request the capability again and drive the native \
                 client so `{}` carries `{}`",
                self.key,
                capped_value(value)
            )),
            RelayBound::Absent => text.push_str(&format!(
                "; grants are single-use, so request the capability again and drive the native \
                 client so `{}` is not sent at all",
                self.key
            )),
            RelayBound::Unresolved => {}
        }
        text
    }
}

/// Everything a `no_matching_shape` already knows: what the hop attempted, and what the session's
/// frozen predicate admits instead.
///
/// The admitted shapes are DESCRIPTOR TEXT — the ratified verb's own `method`/`path` patterns, read
/// out of a document the installer publishes WORLD-READABLE under the shared catalog directory
/// (`.../share/cermet/catalog/actions.d/<provider>.<action>.yaml`). Anyone who can reach the
/// loopback door can already read them, so naming them here discloses nothing new. (`cermet
/// catalog` is NOT the surface that carries them: it projects a verb's fields and bounds, not its
/// relay predicate.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayShapeMiss {
    /// The method this hop used.
    pub method: String,
    /// The path it asked for, bounded.
    pub path: String,
    /// The query keys this hop carried that the shape sharing its method and path does not declare.
    /// Non-empty EXACTLY when key closure is what refused it — the method and path did match — and
    /// empty when no shape has this method and path at all.
    pub undeclared_query_keys: Vec<String>,
    /// The admitted shapes worth naming, as `METHOD /path` patterns: the ONE this hop's method and
    /// path matched when key closure is the miss, and the whole inventory when nothing matched.
    /// Once the shape is known, the inventory is noise around the one fact that matters.
    pub admitted: Vec<String>,
}

impl RelayShapeMiss {
    fn detail(&self) -> String {
        if !self.undeclared_query_keys.is_empty() {
            let one = self.undeclared_query_keys.len() == 1;
            return format!(
                "the shape {} admits this hop's method and path, but the approved verb does not \
                 declare the query {} it carried ({}); re-send it without {}, or ratify {} in the \
                 verb's predicate",
                self.admitted.join(", "),
                if one { "parameter" } else { "parameters" },
                named(&self.undeclared_query_keys),
                if one { "it" } else { "them" },
                if one { "it" } else { "them" },
            );
        }
        // ...and the next step, which the old wordless message had and this must not lose. It is
        // the verb's PREDICATE that enumerates shapes, not any sentence rule, so the widening it
        // points at is the same template edit the key-closure arm names.
        format!(
            "nothing the approved verb admits matches `{} {}`; it admits {}; re-send one of those, \
             or ratify this shape in the verb's predicate if it belongs to the verb",
            self.method,
            self.path,
            self.admitted.join(", ")
        )
    }
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
    ///
    /// It carries WHAT was attempted and WHAT is admitted, because "the approved sentence does not
    /// authorize this request" is true of every miss and tells a requester nothing about which of
    /// the three dimensions refused it.
    NoMatchingShape(RelayShapeMiss),
    /// The shape matched but a bound frozen field disagreed with the request. It carries the field,
    /// the constraint as enforced, and the offered value — everything the engine held when it
    /// refused, and none of it new.
    BindMismatch(RelayBindMismatch),
    /// The shape declares a closed body surface and this hop's body is not a JSON object at all, so
    /// no bind can be evaluated. Audits as `bind_mismatch`: same class, same status, same burn.
    BodyNotAnObject,
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
    /// The HTTP status the native client sees. Fail closed and boring: the status alone reveals
    /// nothing about whether a handle exists. What the refusal SAYS is a separate question — see
    /// [`Self::detail`], which is disclosed only to a caller that already holds a live handle.
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
    ///
    /// (T3) That last sentence is what bounds [`Self::detail`] too: every detailed class is reached
    /// only by a caller holding a live handle, and every value the detail names is one of four
    /// things — descriptor text published world-readable in the installed catalog document, a field
    /// the approval froze for THIS caller's own request, a value off the very hop the caller just
    /// wrote, or a value this caller's own session already received (a capture off the response to
    /// its own approved effect). A credential structurally cannot reach here: this module holds
    /// none.
    pub fn status(&self) -> u16 {
        match self {
            // Conflict: the capability this handle named is spent or gone.
            RelayRefusal::UnknownHandle | RelayRefusal::EffectAlreadyUsed => 409,
            // Gone: it existed and its declared TTL lapsed.
            RelayRefusal::Expired => 410,
            RelayRefusal::MalformedRequest => 400,
            RelayRefusal::BodyTooLarge => 413,
            // Unprocessable: the request is well-formed and outside what the sentence authorized.
            RelayRefusal::NoMatchingShape(_)
            | RelayRefusal::BindMismatch(_)
            | RelayRefusal::BodyNotAnObject
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
            // The detailed classes SAY what they refused. The broker knew the offending field,
            // the frozen constraint and the offending key at the moment it refused; a message that
            // withheld them left the requester guessing one grant at a time.
            RelayRefusal::NoMatchingShape(miss) => {
                return format!(
                    "cermet: the approved sentence does not authorize this request — {} — see \
                     `cermet log --hops`",
                    miss.detail()
                )
            }
            RelayRefusal::BindMismatch(mismatch) => {
                // The head carries the same provenance claim the detail does, so it branches the
                // same way: a captured bind is not a field an approval froze, and a session that
                // named another deployment reached past the ONE effect its grant bought.
                let head = if mismatch.captured_name().is_some() {
                    "cermet: this request reaches past the single effect this grant authorized"
                } else {
                    "cermet: this request contradicts a field the approval froze"
                };
                return format!("{head} — {} — see `cermet log --hops`", mismatch.detail());
            }
            RelayRefusal::BodyNotAnObject => {
                "cermet: this request contradicts a field the approval froze — the approved verb \
                 declares a closed body surface for this shape, so its body must be a JSON object, \
                 and this one is not — see `cermet log --hops`"
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
            RelayRefusal::UndeclaredBodyKey { .. } => {
                return format!(
                    "cermet: this hop is outside the approved verb's declared request surface — {} \
                     — see `cermet log --hops`",
                    self.detail().unwrap_or_default()
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

    /// The stable audit reason. It is the MACHINE-READABLE code and it does not move: the
    /// disclosure a refusal carries rides in [`Self::detail`] beside it, never as a reworded token,
    /// so anything matching on the reason keeps matching.
    pub fn reason(&self) -> &'static str {
        match self {
            RelayRefusal::UnknownHandle => "unknown_handle",
            RelayRefusal::Expired => "session_expired",
            RelayRefusal::MalformedRequest => "malformed_request",
            RelayRefusal::NoMatchingShape(_) => "no_matching_shape",
            // Two variants, ONE reason: a body that is not a JSON object is the same class of
            // defect as a bound key that disagrees — the shape's declared body surface refused it.
            RelayRefusal::BindMismatch(_) | RelayRefusal::BodyNotAnObject => "bind_mismatch",
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

    /// What this refusal DISCLOSES beyond its reason word: the offending field, key, or shape, the
    /// constraint as it is enforced, the value the hop offered, and — where one is computable — the
    /// remedy. One line, in the same register the sentence deny's widening suggestion uses.
    ///
    /// `None` where the class has nothing further to say. It is deliberately not "nothing to say
    /// yet": a class that leaves this empty is one whose reason word IS the whole fact (an unknown
    /// handle, a lapsed TTL, an oversized body), and uniformity matters — a requester that sees
    /// detail on some refusals and silence on others learns that silence means "that part was fine".
    pub fn detail(&self) -> Option<String> {
        match self {
            RelayRefusal::NoMatchingShape(miss) => Some(miss.detail()),
            RelayRefusal::BindMismatch(mismatch) => Some(mismatch.detail()),
            RelayRefusal::BodyNotAnObject => Some(
                "the approved verb declares a closed body surface for this shape, so its body must \
                 be a JSON object, and this one is not"
                    .to_string(),
            ),
            RelayRefusal::UndeclaredBodyKey { keys } => Some(format!(
                "the approved verb does not declare the body {} it carried ({}); re-send it \
                 without {}, or ratify {} in the verb's predicate",
                if keys.len() == 1 { "key" } else { "keys" },
                named(keys),
                if keys.len() == 1 { "it" } else { "them" },
                if keys.len() == 1 { "it" } else { "them" },
            )),
            RelayRefusal::CapExceeded { cap } => Some(format!(
                "this session has spent the `{}` budget the approved verb declares for this request \
                 shape; raise the shape's `caps:` if a real run needs more",
                cap.declared()
            )),
            RelayRefusal::UnknownHandle
            | RelayRefusal::Expired
            | RelayRefusal::MalformedRequest
            | RelayRefusal::EffectAlreadyUsed
            | RelayRefusal::BodyTooLarge
            | RelayRefusal::OutcomeMismatch => None,
        }
    }

    /// Whether this refusal BURNS the session. A request that misses the predicate or contradicts a
    /// frozen field is a session being probed (T1/T2) — it is done, so every later hop is an unknown handle.
    /// A lapsed TTL or an unknown handle burns nothing (there is nothing live to burn), and an
    /// oversized body is a transport limit, not a probe.
    pub fn burns(&self) -> bool {
        matches!(
            self,
            RelayRefusal::NoMatchingShape(_)
                | RelayRefusal::BindMismatch(_)
                | RelayRefusal::BodyNotAnObject
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
    /// The frozen str fields the predicate binds, by name. `None` is the third state a bind has to
    /// distinguish: the field is declared OPTIONAL and this request OMITTED it, so it froze as
    /// ABSENCE and its binds constrain nothing. A name MISSING from the map is not that — it is a
    /// state a validated template cannot produce, and every read of it fails closed.
    frozen: BTreeMap<String, Option<String>>,
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
        frozen: BTreeMap<String, Option<String>>,
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
            return RelayVerdict::Refuse(RelayRefusal::NoMatchingShape(
                self.shape_miss(method, path, &query),
            ));
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
                if let Some(mismatch) = self.query_bind_mismatch(bind, key, &query) {
                    return RelayVerdict::Refuse(RelayRefusal::BindMismatch(mismatch));
                }
            }
        }
        // Then the path binds, which pin every wildcard segment to a value this session
        // CAPTURED from its own effect. Before the create lands nothing is captured, so a poll
        // refuses — the honest CLI never polls before the deployment it is polling for exists.
        for bind in &binds {
            if !bind.path_wildcards() {
                continue;
            }
            if let Some(mismatch) = self.path_bind_mismatch(bind, &rule.path, path) {
                return RelayVerdict::Refuse(RelayRefusal::BindMismatch(mismatch));
            }
        }
        // A rule declares a body check by declaring `body_keys` (required alongside any bind); a rule
        // with neither — an opaque upload — never has its body parsed at all.
        if let Some(allowed) = rule.body_keys() {
            let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(body) else {
                // A shape whose body must be checked but is not a JSON object cannot pass.
                return RelayVerdict::Refuse(RelayRefusal::BodyNotAnObject);
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
                if let Some(mismatch) = self.body_bind_mismatch(bind, key, &object) {
                    return RelayVerdict::Refuse(RelayRefusal::BindMismatch(mismatch));
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

    /// What the session's frozen predicate admits, and which dimension of it this hop missed. It
    /// reads only the frozen predicate and the request — the same two things the match above read.
    fn shape_miss(&self, method: &str, path: &str, query: &[QueryPair]) -> RelayShapeMiss {
        // At most one shape can share a (method, path): the template validator refuses a duplicate.
        // So a shape found here means the method and path DID match and only key closure refused.
        let undeclared: Vec<String> = self
            .predicate
            .iter()
            .find(|rule| rule.method == method && predicate_path_matches(&rule.path, path))
            .map(|rule| {
                query
                    .iter()
                    .filter(|(key, _)| !rule.query_keys.iter().any(|allowed| allowed == key))
                    .map(|(key, _)| capped_key_name(key))
                    .take(MAX_NAMED_UNDECLARED_KEYS)
                    .collect()
            })
            .unwrap_or_default();
        let shape = |rule: &PredicateRule| format!("`{} {}`", rule.method, rule.path);
        RelayShapeMiss {
            method: method.to_string(),
            path: capped_value(path),
            admitted: if undeclared.is_empty() {
                self.predicate.iter().map(shape).collect()
            } else {
                self.predicate
                    .iter()
                    .filter(|rule| {
                        rule.method == method && predicate_path_matches(&rule.path, path)
                    })
                    .map(shape)
                    .collect()
            },
            undeclared_query_keys: undeclared,
        }
    }

    /// The frozen constraint one bind enforces, or `None` when the bind constrains nothing at all —
    /// the field is declared OPTIONAL and this request OMITTED it, so it froze as ABSENCE.
    ///
    /// A name MISSING from the frozen map is not that: it is a state a validated template cannot
    /// produce, and it resolves to [`RelayBound::Unresolved`], which nothing satisfies.
    fn bound(&self, bind: &RelayBind) -> Option<RelayBound> {
        let frozen = match self.frozen.get(&bind.field) {
            Some(Some(frozen)) => frozen,
            Some(None) => return None,
            None => return Some(RelayBound::Unresolved),
        };
        match &bind.absent_when {
            Some(literal) if literal == frozen => Some(RelayBound::Absent),
            _ => Some(RelayBound::Value(frozen.clone())),
        }
    }

    /// Does one body bind hold against this request body? The frozen value is the authority; an
    /// `omit:` literal means the safe case is the key's ABSENCE (Vercel has no legal
    /// `target: preview`). `None` means it holds; `Some` is the refusal, carrying what it knew.
    fn body_bind_mismatch(
        &self,
        bind: &RelayBind,
        key: &str,
        object: &serde_json::Map<String, Value>,
    ) -> Option<RelayBindMismatch> {
        let bound = self.bound(bind)?;
        let present = object.get(key);
        let holds = match &bound {
            RelayBound::Absent => matches!(present, None | Some(Value::Null)),
            RelayBound::Value(frozen) => present.and_then(Value::as_str) == Some(frozen.as_str()),
            RelayBound::Unresolved => false,
        };
        if holds {
            return None;
        }
        let offered = match present {
            None | Some(Value::Null) => RelayOffered::Absent,
            Some(Value::String(value)) => RelayOffered::Value(capped_value(value)),
            Some(_) => RelayOffered::NotAString,
        };
        Some(RelayBindMismatch {
            field: bind.field.clone(),
            position: RelayBindPosition::Body,
            key: key.to_string(),
            bound,
            offered,
        })
    }

    /// Does one QUERY bind hold? Same shape as the body form on the other authority-bearing
    /// wire position — Vercel's `teamId` names the account SCOPE a request lands in, and an approval
    /// that froze one team never authorizes a hop into another. An approval that froze NO team —
    /// the field is optional and the request named no scope — constrains the key not at all, and
    /// the hop record's own target is then the only account of the scope used.
    ///
    /// The value is compared RAW. CLI 58.4.4 sends a bare Vercel team id (`team_XXXX`, in
    /// `[A-Za-z0-9_]`), which percent-encoding never touches, so no decoder is built for a shape no
    /// client sends — an encoded value simply is not the frozen one and fails closed. A REPEATED key
    /// is ambiguous about which value the upstream would honor, and fails closed for the same reason.
    fn query_bind_mismatch(
        &self,
        bind: &RelayBind,
        key: &str,
        query: &[QueryPair],
    ) -> Option<RelayBindMismatch> {
        // Froze as ABSENCE: the key rides free, repeats and all. Key closure still applies —
        // an unratified parameter never reaches this check.
        let bound = self.bound(bind)?;
        let mut present = query.iter().filter(|(name, _)| *name == key);
        let first = present.next();
        let repeated = present.next().is_some();
        let holds = !repeated
            && match &bound {
                RelayBound::Absent => first.is_none(),
                RelayBound::Value(frozen) => {
                    first.and_then(|(_, value)| *value) == Some(frozen.as_str())
                }
                RelayBound::Unresolved => false,
            };
        if holds {
            return None;
        }
        let offered = if repeated {
            RelayOffered::Repeated
        } else {
            match first {
                Some((_, Some(value))) => RelayOffered::Value(capped_value(value)),
                // A bare `?key` with no `=` is not a value, and no frozen value equals it.
                Some((_, None)) => RelayOffered::Bare,
                None => RelayOffered::Absent,
            }
        };
        Some(RelayBindMismatch {
            field: bind.field.clone(),
            position: RelayBindPosition::Query,
            key: key.to_string(),
            bound,
            offered,
        })
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
    fn path_bind_mismatch(
        &self,
        bind: &RelayBind,
        pattern: &str,
        path: &str,
    ) -> Option<RelayBindMismatch> {
        // Unreachable for a validated template (a path bind must read a capture), and fail closed.
        let expected = bind
            .captured_name()
            .and_then(|name| self.captured.get(name))
            .cloned();
        let wildcards = predicate_path_wildcards(pattern, path).unwrap_or_default();
        let holds = expected.as_ref().is_some_and(|expected| {
            !wildcards.is_empty() && wildcards.iter().all(|segment| segment == expected)
        });
        if holds {
            return None;
        }
        Some(RelayBindMismatch {
            field: bind.field.clone(),
            position: RelayBindPosition::Path,
            key: pattern.to_string(),
            // Nothing captured yet means the grant's own effect has not landed — there is no value
            // this hop could have named, and no remedy to offer beyond letting the effect run.
            bound: expected.map_or(RelayBound::Unresolved, RelayBound::Value),
            offered: match wildcards.first() {
                Some(segment) => RelayOffered::Value(capped_value(segment)),
                None => RelayOffered::Absent,
            },
        })
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
            // Unreachable for a validated template: an asserted field is REQUIRED (unlike a bound
            // one, which may be optional), and `open_relay_session` freezes every one. Skipping it
            // loses DETECTION only — it grants nothing — so there is no reason to burn a live
            // session over an impossible state.
            let Some(Some(frozen)) = self.frozen.get(&assertion.field) else {
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
            // WHY it burned, not just which class did — the receipt is the agent's own mirror of
            // the hop, and the reason word alone sent it guessing one grant at a time.
            "burned_detail": self.burned.as_ref().and_then(|hop| hop.refusal.detail()),
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
