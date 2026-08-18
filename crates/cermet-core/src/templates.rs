//! Ratified action templates: a declarative YAML document an agent proposes and a human ratifies,
//! from which the core derives an [`ActionContract`] at load time. This module owns the grammar, the
//! fail-closed validator, and a PER-BROKER registry. It does NOT wire into the broker or provider;
//! nothing here decrypts or touches a credential.
//!
//! Deliberate ABSENCES in the grammar (each a security decision, not an oversight):
//! - No `auth` block. The auth header is a PROVIDER property (`http_call` hardcodes
//!   `Authorization: Bearer <token>`); a template must never be able to steer where the token goes.
//! - No `origin`/host field. A template carries URL *paths* only; the origin comes from the
//!   provider's compiled-in, egress-pinned host.
//! - No `requires_anchored_allow`. That is a provider-level property (`contract::requires_anchored_allow`).
//!
//! `#[serde(deny_unknown_fields)]` on every struct makes all three refusals automatic at parse time.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::contract::{ActionContract, AllowBinding, FieldClass, FieldDecl, ScalarKind};

const MAX_DOC_BYTES: usize = 64 * 1024;
const MAX_FIELDS: usize = 32;
/// Cap on the generated MCP tool name `provider-action` (`verb_tool_name`,
/// crates/cermet-cli/src/mcp_bridge/server.rs). Model providers cap a tool name at 64 chars; the longest known
/// client prefix is Claude Code's `mcp__cermet__` (13), so the projectable budget is 64-13=51. A verb
/// over this is refused fail-closed at validation, so it can never enter the catalog — a client that
/// silently drops (or crashes on) an over-length tool name never sees one.
const MAX_TOOL_NAME_LEN: usize = 51;
const MAX_STEPS: usize = 8;
const MAX_KEEP: usize = 32;
const MAX_CAPTURES_PER_STEP: usize = 8;
const MAX_POLL_ATTEMPTS: u8 = 5;
const MAX_POLL_DELAY_MS: u64 = 1_000;
const MAX_STRING_CHARS: usize = 256 * 1024;

// ---- Relay-predicate caps (a predicate is human-reviewed; keep it small) ----
/// Sized to admit the unlinked CLI's `GET /v1/teams` opening hop. This is a
/// keep-it-readable bound on a HUMAN-reviewed document, not a trust boundary — every rule it admits
/// is still a closed method+path+query+body allowlist.
const MAX_PREDICATE_RULES: usize = 9;
const MAX_PREDICATE_QUERY_KEYS: usize = 16;
/// Cap on one rule's `body_keys` allowlist. Wider than the query cap because a real create
/// payload is wide (Vercel's create-deployment body has ~15 legitimate top-level fields), and still a
/// list a human reads in one screen.
const MAX_PREDICATE_BODY_KEYS: usize = 32;
const MAX_PREDICATE_BINDS: usize = 8;
/// Caps on the response-derived half of a predicate. Both are small on purpose —
/// a capture is session authority derived from a provider response, and an assertion is a frozen
/// field compared against one; a document needing many of either is describing something other than
/// one effect and its own consequences.
const MAX_PREDICATE_CAPTURES: usize = 4;
const MAX_PREDICATE_ASSERTS: usize = 4;
/// Cap on one predicate path — and on the request path the relay matches against it.
pub const MAX_PREDICATE_PATH_BYTES: usize = 512;

pub const DEFAULT_MAX_RUNTIME_SECS: u64 = 900;

// ---------------------------------------------------------------------------
// Serde grammar
// ---------------------------------------------------------------------------

/// A ratified verb. Its execution kind is exactly one supported execution shape:
/// `consumes` is the honest list of credentialed HTTP fields.
/// The compiled wire shape of one HTTP step: its method and whether it carries a body (a JSON/form
/// body or a frozen GraphQL query). Returned by [`ActionTemplate::http_step_shapes`] for the
/// wire-purity assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpStepShape {
    pub method: String,
    pub has_body: bool,
}

#[derive(Debug, Clone)]
pub struct ActionTemplate {
    provider: String,
    action: String,
    request_evidence: Option<String>,
    request_canonicalization: Option<String>,
    money: Option<MoneySpec>,
    fields: Vec<TemplateField>,
    string_char_budget: Option<StringCharBudget>,
    execution_targets: Vec<String>,
    scope: Option<ScopeMode>,
    exec: ExecKind,
}

/// The declared answer to "what does a sentence pin?" when a template names no execution target:
/// the CREDENTIAL is the resource, so the pin is the verb itself (`allow provider.action` is
/// the complete authority quantum). Claimable only by a bounded read — `validate_account_scope`
/// refuses it on anything with a blast radius (the pin is the verb).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScopeMode {
    Account,
}

// The `cermet mcp` surface exposes every ratified verb with no read/write classification
// (mcp.rs `generated_verb_tools`), so writes are gated by human console approval, not by any
// agent-surface filter.

/// The credential-bearing execution kinds. Each carries `consumes` — the honest list of fields its
/// execution reads.
#[derive(Debug, Clone)]
enum ExecKind {
    /// The broker CONSTRUCTS the request from frozen fields and makes it (`http.steps`).
    Http {
        consumes: Vec<String>,
        spec: HttpSpec,
    },
    /// The SUBPROCESS execution kind (git-native track): the effect is performed by the hermetic
    /// system-git seam (`crate::git`), not by an HTTP request. Exactly ONE declared step kind lives
    /// here — `push` — because there is exactly one credential-bearing git interaction: carry a
    /// packfile and advance a ref.
    Git {
        consumes: Vec<String>,
        spec: GitSpec,
    },
    /// The broker VALIDATES a request a native CLI constructed, then credentials it
    /// (`execution: relay` + `predicate`). No steps exist — the wire shape is the CLI's. Approved ==
    /// executed is enforced by inspection (`bind`) instead of construction.
    Relay {
        consumes: Vec<String>,
        predicate: Vec<PredicateRule>,
    },
}

/// The declared execution mode. Absent ⇒ `http` (the constructed kind every pre-relay verb uses).
/// The git-native subprocess kind is selected by the presence of `git:` while this stays `http`
/// (git never gets its own mode: `http:`/`git:` are the two `http`-mode recipes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExecutionMode {
    #[default]
    Http,
    Relay,
}

/// The parse-time shape. Deserialized with `deny_unknown_fields` (so `auth`/`origin`/typos at the top
/// level are still hard errors), then folded into the [`ExecKind`] enum by the manual `Deserialize`
/// below.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTemplate {
    provider: String,
    action: String,
    #[serde(default)]
    request_evidence: Option<String>,
    /// Names one COMPILED canonicalization profile ([`crate::canonicalize`]). The document
    /// selects semantics by id; it can never express a resolver.
    #[serde(default)]
    request_canonicalization: Option<String>,
    #[serde(default)]
    money: Option<MoneySpec>,
    fields: Vec<TemplateField>,
    #[serde(default, deserialize_with = "deserialize_present_string_char_budget")]
    string_char_budget: Option<StringCharBudget>,
    #[serde(default)]
    consumes: Option<Vec<String>>,
    execution_targets: Vec<String>,
    /// "The pin is the verb": declares the credential itself as the pinned resource. Legal only
    /// with empty `execution_targets` and a bounded read (validated in `validate_account_scope`).
    #[serde(default)]
    scope: Option<ScopeMode>,
    #[serde(default)]
    http: Option<HttpSpec>,
    #[serde(default)]
    git: Option<GitSpec>,
    /// The execution mode selector. Absent ⇒ `http`.
    #[serde(default)]
    execution: ExecutionMode,
    /// The relay's request predicate. Legal ONLY with `execution: relay`.
    #[serde(default)]
    predicate: Option<Vec<PredicateRule>>,
}

impl<'de> Deserialize<'de> for ActionTemplate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let raw = RawTemplate::deserialize(deserializer)?;
        let consumes = raw.consumes.ok_or_else(|| {
            Error::custom(
                "a template must declare `consumes` (the honest list of fields its execution reads)",
            )
        })?;
        // The execution kinds are mutually exclusive at PARSE time, so no document can carry two of
        // {constructed HTTP recipe, subprocess git hop, validated-per-hop relay predicate} — whichever
        // one the executor honoured, the others would be silent, unreviewed authority.
        let exec = match raw.execution {
            ExecutionMode::Http => {
                if raw.predicate.is_some() {
                    return Err(Error::custom(
                        "`predicate:` is legal only with `execution: relay`",
                    ));
                }
                match (raw.http, raw.git) {
                    (Some(spec), None) => ExecKind::Http { consumes, spec },
                    (None, Some(spec)) => ExecKind::Git { consumes, spec },
                    (Some(_), Some(_)) => {
                        return Err(Error::custom(
                            "a template declares exactly ONE execution kind; `http:` and `git:` are mutually exclusive",
                        ))
                    }
                    (None, None) => {
                        return Err(Error::custom(
                            "a template must declare `http:` or `git:` (the supported execution kinds)",
                        ))
                    }
                }
            }
            ExecutionMode::Relay => {
                if raw.http.is_some() {
                    return Err(Error::custom(
                        "a relay template must not declare `http:` — a relay verb constructs no \
                         request; the native client does",
                    ));
                }
                if raw.git.is_some() {
                    return Err(Error::custom(
                        "a relay template must not declare `git:` — a relay verb constructs no \
                         request; the native client does",
                    ));
                }
                let predicate = raw.predicate.ok_or_else(|| {
                    Error::custom(
                        "a relay template must declare `predicate:` (the request shapes it admits)",
                    )
                })?;
                ExecKind::Relay {
                    consumes,
                    predicate,
                }
            }
        };
        Ok(ActionTemplate {
            provider: raw.provider,
            action: raw.action,
            request_evidence: raw.request_evidence,
            request_canonicalization: raw.request_canonicalization,
            money: raw.money,
            fields: raw.fields,
            string_char_budget: raw.string_char_budget,
            execution_targets: raw.execution_targets,
            scope: raw.scope,
            exec,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MoneySpec {
    preconditions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateField {
    name: String,
    #[serde(rename = "type")]
    ty: TemplateType,
    required: bool,
    class: TemplateClass,
    binding: TemplateBinding,
    /// An optional canonical-value SHAPE constraint enforced at admission (request-time
    /// canonicalize), NOT a type. It refuses a syntactically-valid string that is the wrong KIND of
    /// value — e.g. a branch name where an immutable Git OID is required, or a
    /// leading-zero/non-decimal issue number. Generic and provider-agnostic: the template
    /// declares the shape and provider canonicalization enforces it before mint and when revalidating
    /// a stored frozen resource before claim. Legal only on a `str` field. An
    /// explicitly-present `null`/non-variant value is a hard parse error (see
    /// `deserialize_present_format`), never a silent `None` that would disable the constraint.
    #[serde(default, deserialize_with = "deserialize_present_format")]
    format: Option<FieldFormat>,
    /// Optional per-field Unicode scalar-value count. Absence means no character-specific bound;
    /// the generic byte cap still applies. Present values are validated in 1..=256 KiB.
    #[serde(default, deserialize_with = "deserialize_present_max_chars")]
    max_chars: Option<usize>,
    /// Optional inclusive ceiling for an integer field, enforced during request admission and again
    /// when a stored frozen resource is revalidated before claim. Legal only on `int`; a present
    /// value must be positive so an authoring typo cannot silently turn the field into a deny-all or
    /// unbounded shape.
    #[serde(default, deserialize_with = "deserialize_present_max_int")]
    max_int: Option<i64>,
    /// The field's ONE legal value, frozen by the ratified template rather than
    /// chosen per request. Enforced at admission (`validate_template_resource`) and again when a
    /// stored frozen resource is revalidated before claim, so a request naming any other value is
    /// DENIED before a card exists. It is what makes a verb name a promise: `deploy` declares
    /// `target: fixed: preview`, so no sentence and no request can turn it into a production deploy.
    /// Legal only on a required `str` field; the literal is `[a-z0-9_-]{1,64}`.
    #[serde(default, deserialize_with = "deserialize_present_fixed")]
    fixed: Option<String>,
}

/// One admitted request shape of a relay verb. The predicate is the ENTIRE
/// enforceable surface of a relay grant — a hop matching no rule is refused and burns the grant.
///
/// `path` is a `/`-rooted literal path in which a `*` segment matches exactly one path segment
/// (`/v13/deployments/*`, `/v2/deployments/*/events`). `query_keys` is the closed allowlist of query
/// parameter names the hop may carry — absent means NO query string is admitted, so a scope-redirecting
/// parameter (Vercel's `teamId`/`slug`) can never ride along unless a human ratified it here (an
/// injected "deploy to the other team" is refused the same as a legitimate one). `body_keys` is the
/// same closed allowlist for TOP-LEVEL body keys, and it is REQUIRED on any rule that binds: checking
/// two keys while waving the rest of the body through is how
/// `project`/`deploymentId`/`customEnvironmentSlugOrId` would each have overridden a frozen field.
/// `bind` maps a request location to a FROZEN field name: the relay reads that location out of the
/// hop and refuses unless it equals the approved value — whether the mismatch came from an injected
/// `target: production` or a fat-fingered `--prod`. `once` marks THE single effect —
/// exactly one rule per relay verb carries it, and it may pass at most once per grant.
///
/// A bind value is `<field>` or `<field>|omit:<literal>` — the SAME `omit:` spelling the constructed
/// body grammar uses, and for the same reason: some provider fields have no legal value for the safe
/// case, so the safe case is the key's ABSENCE. With `omit:preview`, a frozen `target` of `preview`
/// admits only a body with no `target` key (or an explicit null); any other frozen value must appear
/// verbatim.
///
/// The RESPONSE-derived half is shape-level too, and legal only on the
/// `once: true` effect shape: `capture` names session state read out of the effect's own 2xx body,
/// which a later shape's `path.*` bind reads back as `captured.<name>` to pin its wildcard segments
/// (a session's reads are confined to its own effect's consequences); and `assert` compares that same
/// body against the frozen fields, which is DETECTION — the effect has landed by then.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateRule {
    pub(crate) method: String,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) query_keys: Vec<String>,
    /// The closed allowlist of TOP-LEVEL body keys this shape admits, beyond the ones it
    /// binds (a bound key is admitted implicitly). REQUIRED on any rule that binds — otherwise the
    /// rule would check two keys and wave the rest of the body through. Absent means no body check at
    /// all, which is only legal for a rule with no binds (an opaque upload).
    #[serde(default)]
    pub(crate) body_keys: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) bind: BTreeMap<String, String>,
    /// Session state DERIVED from this shape's own 2xx response — `<name>: <response key>`,
    /// read as a top-level string out of the observed body. Legal only on the `once: true` effect
    /// shape: nothing but the approved effect produces a consequence a later hop may then name.
    /// A `path.*` bind on another shape reads it back as `captured.<name>`.
    #[serde(default)]
    pub(crate) capture: BTreeMap<String, String>,
    /// What this shape's 2xx response must SAY about the fields the approval froze —
    /// `<response key>: <field>`, in the same `<field>|omit:<literal>` grammar `bind` uses. Legal
    /// only on the `once: true` effect shape. The effect has already landed when this is read, so it
    /// is detection at the boundary, never prevention: a mismatch burns the session and writes a
    /// high-severity audit row carrying frozen-vs-observed.
    #[serde(default)]
    pub(crate) assert: BTreeMap<String, String>,
    /// This shape's per-session BUDGET — how many hops of it a session admits, and how many
    /// aggregate request bytes those hops may carry. Absent means the shape is unbudgeted (the reads,
    /// and the effect, which `once` already bounds to one). Every other dimension of this grammar
    /// decides ONE hop; this is the only one that bounds a session's total traffic through a shape.
    #[serde(default)]
    pub(crate) caps: Option<RelayCaps>,
    #[serde(default)]
    pub(crate) once: bool,
}

/// One shape's per-session budget. BOTH dimensions are required together: a hop count with
/// no byte bound (or the reverse) is a half-closed surface, and one hop can carry a whole body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayCaps {
    /// The most hops of this shape one session may have AUTHORIZED. A refused hop spends nothing.
    pub max_uses: u64,
    /// The most aggregate REQUEST body bytes those hops may carry, across the session. The per-hop
    /// ceiling is a separate daemon setting (`relay_max_body_bytes`); this is the total.
    pub max_total_bytes: u64,
}

/// The request position a bind reads. Both carry authority: a body key names WHAT is deployed, a
/// query key names WHERE it lands (Vercel's `teamId` is the account scope, and the
/// matcher used to check only that the key was in the allowlist).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindLocation {
    /// A top-level JSON body key.
    Body(String),
    /// A query parameter's VALUE.
    Query(String),
    /// EVERY `*` segment of the shape's own path pattern. Spelled `path.*`, and it reads a
    /// `captured.<name>` value rather than an approval-frozen field: a deployment id is not something
    /// the sentence can pin in advance, it is the approved effect's own consequence.
    PathWildcards,
}

/// One parsed relay bind: the frozen field a request location must equal, plus the optional
/// `omit:<literal>` value that means "the key must be ABSENT instead".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayBind {
    /// Where in the request this bind reads its value.
    pub location: BindLocation,
    /// The frozen field whose approved value the location must carry.
    pub field: String,
    /// The frozen value that means the key must be absent-or-null.
    pub absent_when: Option<String>,
}

/// The namespace a bind uses to read RESPONSE-DERIVED session state instead of an
/// approval-frozen field. It cannot collide with a real field name: a template field name is a
/// lowercase identifier (`is_ident`) and carries no `.`.
pub const CAPTURE_PREFIX: &str = "captured.";

impl RelayBind {
    /// The top-level body key this bind reads, or `None` for any other location.
    pub fn body_key(&self) -> Option<&str> {
        match &self.location {
            BindLocation::Body(key) => Some(key),
            _ => None,
        }
    }

    /// The query key this bind reads, or `None` for any other location.
    pub fn query_key(&self) -> Option<&str> {
        match &self.location {
            BindLocation::Query(key) => Some(key),
            _ => None,
        }
    }

    /// Does this bind pin the shape's path wildcards?
    pub fn path_wildcards(&self) -> bool {
        matches!(self.location, BindLocation::PathWildcards)
    }

    /// The CAPTURE this bind compares against, or `None` when it reads an approval-frozen field.
    /// The two sources never overlap — a captured value is the effect's own consequence, a frozen
    /// value is what the approval pinned — so the caller resolves one or the other, never both.
    pub fn captured_name(&self) -> Option<&str> {
        self.field.strip_prefix(CAPTURE_PREFIX)
    }
}

/// One parsed outcome assertion: the top-level response key, the frozen field its value
/// must equal, and the `omit:<literal>` frozen value that instead means the key must be ABSENT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAssertion {
    pub key: String,
    pub field: String,
    pub absent_when: Option<String>,
}

/// Parse a bind LOCATION: `body.<key>` (a top-level JSON body key), `query.<key>` (a query
/// parameter's value), or `path.*` (every wildcard segment of the shape's own path). Nothing else is
/// a supported request position.
fn parse_bind_location(location: &str) -> Result<BindLocation, String> {
    if let Some(key) = location.strip_prefix("body.") {
        return Ok(BindLocation::Body(key.to_string()));
    }
    if let Some(key) = location.strip_prefix("query.") {
        return Ok(BindLocation::Query(key.to_string()));
    }
    if location == "path.*" {
        return Ok(BindLocation::PathWildcards);
    }
    Err(format!(
        "predicate bind location `{location}` is not a supported request location (`body.<key>`: a \
         top-level JSON body key; `query.<key>`: a query parameter's value; `path.*`: every \
         wildcard segment of this shape's own path)"
    ))
}

/// Parse a bind value: `<field>` or `<field>|omit:<literal>`.
fn parse_bind_value(value: &str) -> Result<(String, Option<String>), String> {
    match value.split_once('|') {
        None => Ok((value.to_string(), None)),
        Some((field, transform)) => match transform.strip_prefix("omit:") {
            Some(literal) if is_omit_literal(literal) => {
                Ok((field.to_string(), Some(literal.to_string())))
            }
            _ => Err(format!(
                "has bind transform `{transform}`; the only supported bind transform is \
                 `omit:<[a-z0-9_-]{{1,64}}>`"
            )),
        },
    }
}

impl PredicateRule {
    /// The closed top-level body-key allowlist, or `None` for a rule that declares no body
    /// check at all (legal only with no binds — an opaque upload body).
    pub fn body_keys(&self) -> Option<&[String]> {
        self.body_keys.as_deref()
    }

    /// This rule's parsed binds. Only ever called on a VALIDATED template, so a malformed bind is
    /// unreachable — it is dropped rather than panicking (fail closed: a dropped bind cannot admit a
    /// request, because `validate_relay` already proved every bind parses).
    pub fn binds(&self) -> Vec<RelayBind> {
        self.bind
            .iter()
            .filter_map(|(location, value)| {
                let location = parse_bind_location(location).ok()?;
                let (field, absent_when) = parse_bind_value(value).ok()?;
                Some(RelayBind {
                    location,
                    field,
                    absent_when,
                })
            })
            .collect()
    }

    /// This shape's captures, `<name> -> <top-level response key>`. Non-empty only on the
    /// `once: true` effect shape of a validated template.
    pub fn captures(&self) -> &BTreeMap<String, String> {
        &self.capture
    }

    /// This shape's declared per-session budget, or `None` for an unbudgeted shape.
    pub fn caps(&self) -> Option<RelayCaps> {
        self.caps
    }

    /// This shape's parsed outcome assertions. Dropped rather than panicking on a
    /// malformed entry, exactly like [`Self::binds`] — `validate_relay` already proved every one
    /// parses, and a dropped assertion cannot admit anything (it only stops detecting).
    pub fn asserts(&self) -> Vec<RelayAssertion> {
        self.assert
            .iter()
            .filter_map(|(key, value)| {
                let (field, absent_when) = parse_bind_value(value).ok()?;
                Some(RelayAssertion {
                    key: key.clone(),
                    field,
                    absent_when,
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct StringCharBudget {
    fields: Vec<String>,
    max_chars: usize,
}

/// A canonical-value shape a `str` field's value must match at admission. Each is a pure predicate on
/// the string (no mutation, so the frozen/approved value is exactly what the agent supplied).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldFormat {
    /// A canonical lowercase-hex Git object ID: exactly 40 (SHA-1) or 64 (SHA-256) hex chars. Refuses
    /// a ref/branch name, an uppercase or short/long hex, and any non-hex character.
    GitOid,
    /// A canonical bare positive decimal integer: one or more ASCII digits, no leading zero, ≥ 1.
    /// Refuses `01`, `0`, a signed/decimal/whitespace form, and any non-digit — so one resource has
    /// exactly one pin string.
    Uint,
    /// A stable Vercel project ID: the literal prefix `prj_` followed by 1+ ASCII alphanumerics.
    /// Refuses a bare project SLUG/name (`website`, `my-project`) so a project is always pinned by
    /// its immutable ID, never a mutable, reassignable slug. Pure admission predicate; the value is
    /// never rewritten.
    VercelProjectId,
    /// A fully-qualified Git BRANCH ref: the literal prefix `refs/heads/` followed by a valid Git
    /// branch name. Refuses `refs/tags/*`, other ref namespaces, an abbreviated/bare branch
    /// name, and malformed refnames — so `create_branch.new_ref` can only ever create a plain branch,
    /// never a tag or arbitrary ref namespace its verb name does not promise. Pure predicate.
    GitBranchRef,
    /// A bare, same-repository Git branch name. Uses the same strict branch-name predicate as
    /// `git_branch_ref`, but without the `refs/heads/` prefix. In particular `:` is refused, so a
    /// GitHub `user:branch` cross-repository address cannot enter a same-repository verb.
    GitBranchName,
    /// An absolute HTTPS URL with a host and no userinfo or fragment. Query strings, paths, and
    /// explicit ports are legal. Pure predicate: the approved bytes are never normalized.
    HttpsUrl,
}

/// Whether `name` is a valid Git branch name (the component path AFTER `refs/heads/`). A strict subset
/// of `git check-ref-format` sufficient to refuse tags, abbreviated names, and injection: non-empty,
/// no empty path components, no leading `-`, no component starting with `.` or ending `.lock`, no `..`
/// or `@{`, no ASCII control/space, and none of `~^:?*[\` or a lone `@`.
fn is_valid_branch_name(name: &str) -> bool {
    if name.is_empty() || name == "@" || name.ends_with('/') || name.starts_with('/') {
        return false;
    }
    if name.contains("..") || name.contains("@{") || name.starts_with('-') {
        return false;
    }
    if name.bytes().any(|b| {
        b <= 0x20 || b == 0x7f || matches!(b, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
    }) {
        return false;
    }
    name.split('/').all(|comp| {
        // git check-ref-format also rejects a component ending in `.` (e.g. `feature.`).
        !comp.is_empty()
            && !comp.starts_with('.')
            && !comp.ends_with('.')
            && !comp.ends_with(".lock")
    })
}

/// Deserialize a PRESENT `format` value, rejecting an explicit `null`/non-variant. With
/// `#[serde(default)]` a `format: null` would otherwise map to `None` and silently DISABLE the
/// constraint. `deserialize_with` is invoked only when the key is present in the document, so
/// deserializing the enum DIRECTLY here turns a present `null` (or any non-variant) into a hard
/// parse error, while an ABSENT key still falls through to `default` (`None`). First-party,
/// hash-pinned YAML — this closes an authoring foot-gun, not an adversary channel.
fn deserialize_present_format<'de, D>(deserializer: D) -> Result<Option<FieldFormat>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    FieldFormat::deserialize(deserializer).map(Some)
}

fn deserialize_present_max_chars<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    usize::deserialize(deserializer).map(Some)
}

fn deserialize_present_max_int<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    i64::deserialize(deserializer).map(Some)
}

fn deserialize_present_fixed<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

fn deserialize_present_string_char_budget<'de, D>(
    deserializer: D,
) -> Result<Option<StringCharBudget>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    StringCharBudget::deserialize(deserializer).map(Some)
}

impl FieldFormat {
    /// Whether `value` matches this canonical shape. Pure predicate; no normalization.
    pub(crate) fn matches(self, value: &str) -> bool {
        match self {
            FieldFormat::GitOid => {
                matches!(value.len(), 40 | 64)
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
            FieldFormat::Uint => {
                !value.is_empty()
                    && value.bytes().all(|b| b.is_ascii_digit())
                    && value.as_bytes()[0] != b'0'
            }
            FieldFormat::VercelProjectId => value.strip_prefix("prj_").is_some_and(|rest| {
                !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric())
            }),
            FieldFormat::GitBranchRef => value
                .strip_prefix("refs/heads/")
                .is_some_and(is_valid_branch_name),
            FieldFormat::GitBranchName => {
                !value.starts_with("refs/") && is_valid_branch_name(value)
            }
            FieldFormat::HttpsUrl => {
                let lexical_authority = value
                    .strip_prefix("https://")
                    .map(|rest| rest.split(['/', '?', '#']).next().unwrap_or_default());
                value.is_ascii()
                    && !value.bytes().any(|byte| {
                        byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'\\'
                    })
                    && lexical_authority
                        .is_some_and(|authority| !authority.is_empty() && !authority.contains('@'))
                    && reqwest::Url::parse(value).is_ok_and(|url| {
                        url.scheme() == "https"
                            && url.host_str().is_some_and(|host| !host.is_empty())
                            && url.username().is_empty()
                            && url.password().is_none()
                            && url.fragment().is_none()
                    })
            }
        }
    }

    pub(crate) fn describe(self) -> &'static str {
        match self {
            FieldFormat::GitOid => "a canonical lowercase-hex Git object ID (40 or 64 hex chars)",
            FieldFormat::Uint => "a canonical bare positive decimal integer (no leading zero)",
            FieldFormat::VercelProjectId => {
                "a stable Vercel project ID (`prj_` followed by alphanumerics), not a project slug"
            }
            FieldFormat::GitBranchRef => {
                "a fully-qualified branch ref (`refs/heads/<valid-branch-name>`), not a tag or other ref"
            }
            FieldFormat::GitBranchName => {
                "a valid bare Git branch name, not a qualified ref or cross-repository `user:branch`"
            }
            FieldFormat::HttpsUrl => {
                "an exact lowercase `https://` ASCII URL with a nonempty host authority and no whitespace, controls, backslash, userinfo, password, or fragment"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateType {
    Str,
    Int,
    Bool,
}

/// `FieldClass::Unclassified` is deliberately NOT expressible — every template field must classify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateClass {
    Identity,
    SideEffect,
    FreePayload,
    Secret,
    ReadFilter,
}

/// A field binds not at all, by exact pin, by the one bounded-glob identity allowlist, or by an
/// integer sentence bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateBinding {
    Unbound,
    ExactResourcePin,
    /// The bounded-glob binding: an allow pins the field either by an exact `scope.resource` value
    /// or by a `scope.names` glob allowlist. The scope list key is always `names` (the sole list the
    /// policy engine knows), so the derived `AllowBinding` hardcodes it — matching the built-in.
    ExactOrPatternList,
    /// An integer side-effect field constrained by a sentence `<=` or `>=` conjunct.
    Bounded,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSpec {
    #[serde(default)]
    path_modes: BTreeMap<String, PathMode>,
    steps: Vec<StepSpec>,
}

/// The GIT execution kind's spec: EXACTLY ONE declared step, and there are exactly two — the two
/// credentialed git interactions there are.
///
/// `push` carries an already-authorized ref update from the daemon's mirror to the upstream.
/// `fetch` is the same picture reversed: refresh the mirror FROM the upstream so the read stream has
/// something current to serve. There is no step LIST on purpose, and no carrier/staging vocabulary
/// at all: git moves the objects (the daemon wires an attested stream to `receive-pack` /
/// `upload-pack`), and Cermet's whole job is the decision and the hop.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitSpec {
    #[serde(default)]
    pub(crate) push: Option<GitPushStep>,
    #[serde(default)]
    pub(crate) fetch: Option<GitFetchStep>,
}

/// The `fetch` step. Only the upstream address: a refresh has no per-ref vocabulary because it
/// mirrors every branch the upstream has (and prunes the ones it no longer has). Which repos may be
/// refreshed at all is the sentence's business, not this step's.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitFetchStep {
    /// The upstream's path under the provider descriptor's pinned git origin, e.g.
    /// `/{owner}/{name}.git`. A template carries PATHS only; the origin is descriptor data.
    pub(crate) remote_path: String,
}

/// The `push` step. Every value here is either a template constant (`remote_path`) or the NAME of a
/// declared field the hermetic runner reads from the frozen resource — never a value, never a
/// placeholder into anything the child interprets as an option.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitPushStep {
    /// The upstream's path under the provider descriptor's pinned git origin, e.g.
    /// `/{owner}/{name}.git`. A template carries PATHS only; the origin is descriptor data
    /// (the same rule the HTTP kind obeys).
    pub(crate) remote_path: String,
    /// The field naming the branch to advance.
    pub(crate) branch: String,
    /// The field naming the object the branch must end up at — git's `new` in the update hook's
    /// `(ref, old, new)`.
    pub(crate) new_oid: String,
    /// The field naming the MIRROR's tip for this ref — git's `old` in the update hook's
    /// `(ref, old, new)`. Optional in the grammar and in the request: absent means the mirror had no
    /// such ref.
    ///
    /// It is deliberately NOT called the upstream's tip: with no credentialed fetch
    /// refresh the mirror can lag the upstream, so this is the value the mirror's ref transaction
    /// reported and nothing more. It is never an execution guard either — concurrency control is
    /// the upstream server's own fast-forward rule, and the receipt's `upstream_old_oid` is what
    /// records the transition the upstream actually performed.
    #[serde(default)]
    pub(crate) mirror_old_oid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMode {
    /// A single percent-encoded URL segment (default expansion).
    Segment,
    /// A slash-bearing path fragment (e.g. a repo file path).
    Path,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PollSpec {
    pub(crate) attempts: u8,
    pub(crate) delay_ms: u64,
    pub(crate) until_nonempty: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepSpec {
    pub(crate) id: String,
    pub(crate) method: String,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) query: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) optional_ok: Vec<u16>,
    #[serde(default)]
    pub(crate) capture: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) body: Option<Value>,
    /// Wire encoding for `body`. JSON remains the default; Stripe's v1 API uses form encoding.
    #[serde(default)]
    pub(crate) body_encoding: BodyEncoding,
    /// Setup actions may ADD explicitly selected values captured from prior steps to the terminal
    /// result. Keys are returned field names; values are prior capture names. This is augmentation,
    /// never curation: the provider body itself is returned verbatim.
    #[serde(default)]
    pub(crate) result_captures: BTreeMap<String, String>,
    /// Setup-only bounded reconciliation polling. The executor retries this one terminal,
    /// capture-keyed GET while every selected collection is empty. The first call is immediate;
    /// `delay_ms` applies only between attempts.
    #[serde(default)]
    pub(crate) poll: Option<PollSpec>,
    /// Whether the terminal provider body is retained as an artifact. `none` caps durable storage;
    /// it never narrows the returned response (a retention cap is not a projection).
    #[serde(default)]
    pub(crate) retention: RetentionMode,
    /// The frozen-query rule: a GraphQL document as a FROZEN LITERAL. Its braces are
    /// literal text — it is NEVER placeholder-scanned and never interpolated; the executor inserts
    /// it verbatim as the wire body's top-level `"query"` key. Only the `body` (the variables
    /// object) carries classified fields. A step body may never carry its own `query` key (refused
    /// at load, with or without this field), so the mutation text can only ever be this constant.
    #[serde(default)]
    pub(crate) graphql_query: Option<String>,
    /// Outcome semantics: dotted result paths whose presence (non-null) PROVES the
    /// step's effect. For a GraphQL step these are `$.`-rooted capture pointers checked on a
    /// 2xx-with-no-errors body; for a REST step they are BARE dotted paths checked on a
    /// success body. Any missing/null path ⇒ the step FAILS — an ambiguous 2xx never renders success,
    /// and a required proof field can never silently become JSON null.
    #[serde(default)]
    pub(crate) require: Vec<String>,
    /// Exact success status: the closed set of HTTP status codes that count as success for
    /// this step. Empty ⇒ any 2xx (the legacy default). Non-empty ⇒ the actual status MUST be one of
    /// these, else the step fails closed EVEN on a 2xx — so `request_deployment` pins `201` ("request
    /// created, not deployed"), `request_workflow_cancel` pins `202` (accepted), and a drift to a
    /// different 2xx (e.g. a 200 merge-commit or 204) is never a hollow success.
    ///
    /// The admissible codes widen from 2xx to 2xx-or-3xx, and ONLY through this explicit
    /// declaration: an undeclared 3xx still fails closed exactly as it always did. Some providers
    /// answer a credentialed request by MINTING a redirect — GitHub's job-log endpoint returns `302`
    /// plus a pre-signed, short-lived blob URL in `Location` — and there the redirect IS the answer,
    /// not a detour on the way to one. The engine still never follows it
    /// (`redirect::Policy::none()`); [`StepSpec::retain_headers`] is how the minted value reaches
    /// the receipt.
    #[serde(default)]
    pub(crate) success_statuses: Vec<u16>,
    /// Response header names whose values the broker RETAINS into the step's envelope — the
    /// broker-authored sibling channel, never the provider's body (the response contract stays
    /// verbatim). Names are lowercase HTTP header tokens; each one must be PRESENT on the response
    /// or the step fails closed naming it, the same discipline `require` applies to body paths.
    ///
    /// This exists for the minted-URL shape and is deliberately tiny: `retain_headers: [location]`
    /// on a `success_statuses: [302]` step turns the credentialed mint into a receipt an agent can
    /// act on with credential-free native tooling. Empty for every other verb.
    #[serde(default)]
    pub(crate) retain_headers: Vec<String>,
    /// Assert a response path equals a FROZEN consumed field, else fail closed. Maps a dotted RESPONSE
    /// path (e.g. `head_sha`) to the name of a required, exact-pinned Str Identity execution target
    /// whose frozen value it must equal. A verification read uses it as a value-free precondition; a
    /// final mutation may use it as a reconciliation-bearing postcondition. Ordinary comparisons are
    /// required exact-pinned Str identities and make out-of-band identity a genuinely executed pin.
    /// A money template's sole mutation may carry the exact compiled success-contract mappings, which
    /// compare typed response values after invocation without satisfying request-wire consumption.
    #[serde(default)]
    pub(crate) expect_eq: BTreeMap<String, String>,
    /// Assert a response path equals a frozen scalar-or-null literal after a successful provider
    /// response. A final mutation uses it as a reconciliation-bearing postcondition; verification
    /// reads and non-final guards remain value-free preconditions. A mismatch reports failure rather
    /// than claiming a different consequence succeeded.
    #[serde(default)]
    pub(crate) expect_literal: BTreeMap<String, Value>,
}

/// The response contract, stated once: **verbatim**. The
/// provider's body is what the agent receives and what the artifact stores. A template shapes the
/// REQUEST and asserts postconditions on the response; it never edits the response.
pub const RESPONSE_CONTRACT: &str = "verbatim";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BodyEncoding {
    #[default]
    Json,
    Form,
}

/// Cap on frozen GraphQL action documents (a hard refusal at load).
pub(crate) const MAX_GRAPHQL_QUERY_LEN: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GraphqlOperation {
    Query,
    Mutation,
}

/// Minimal single-operation recognition for frozen first-party documents. The template grammar does
/// not parse GraphQL schemas, but it must distinguish a read precondition from a mutation before
/// allowing response assertions to guard a later write. Exactly one balanced selection set must consume
/// the document; shorthand queries, comments, string literals, fragments, and subscriptions stay
/// unexpressed. Dynamic strings belong in the separately classified variables object.
fn graphql_operation(document: &str) -> Option<GraphqlOperation> {
    let document = document.trim_start();
    if document.contains(['"', '#']) {
        return None;
    }
    let mut recognized = None;
    for (keyword, operation) in [
        ("query", GraphqlOperation::Query),
        ("mutation", GraphqlOperation::Mutation),
    ] {
        let Some(rest) = document.strip_prefix(keyword) else {
            continue;
        };
        if rest
            .chars()
            .next()
            .is_some_and(|c| !c.is_ascii_alphanumeric() && c != '_')
        {
            recognized = Some(operation);
            break;
        }
    }
    let operation = recognized?;

    let mut depth = 0usize;
    let mut opened = false;
    for (index, ch) in document.char_indices() {
        match ch {
            '{' => {
                opened = true;
                depth = depth.checked_add(1)?;
            }
            '}' => {
                depth = depth.checked_sub(1)?;
                if opened && depth == 0 {
                    let rest = &document[index + ch.len_utf8()..];
                    return rest.trim().is_empty().then_some(operation);
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn is_verification_read(step: &StepSpec) -> bool {
    step.method == "GET"
        || step.graphql_query.as_deref().and_then(graphql_operation)
            == Some(GraphqlOperation::Query)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RetentionMode {
    #[default]
    Full,
    None,
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
impl TemplateType {
    pub(crate) fn to_scalar(self) -> ScalarKind {
        match self {
            TemplateType::Str => ScalarKind::Str,
            TemplateType::Int => ScalarKind::Int,
            TemplateType::Bool => ScalarKind::Bool,
        }
    }
}

impl TemplateClass {
    pub(crate) fn to_field_class(self) -> FieldClass {
        match self {
            TemplateClass::Identity => FieldClass::Identity,
            TemplateClass::SideEffect => FieldClass::SideEffect,
            TemplateClass::FreePayload => FieldClass::FreePayload,
            TemplateClass::Secret => FieldClass::Secret,
            TemplateClass::ReadFilter => FieldClass::ReadFilter,
        }
    }
}

impl TemplateBinding {
    fn to_allow_binding(self) -> AllowBinding {
        match self {
            TemplateBinding::Unbound => AllowBinding::Unbound,
            TemplateBinding::ExactResourcePin => AllowBinding::ExactResourcePin,
            TemplateBinding::ExactOrPatternList => AllowBinding::ExactOrPatternList("names"),
            TemplateBinding::Bounded => AllowBinding::Bounded,
        }
    }
}

// The grammar-token spellings — identical to the YAML an author writes, so a `catalog` reader can
// copy a class/type/binding value straight back into a new template.
impl TemplateType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            TemplateType::Str => "str",
            TemplateType::Int => "int",
            TemplateType::Bool => "bool",
        }
    }
}

impl TemplateClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            TemplateClass::Identity => "identity",
            TemplateClass::SideEffect => "side_effect",
            TemplateClass::FreePayload => "free_payload",
            TemplateClass::Secret => "secret",
            TemplateClass::ReadFilter => "read_filter",
        }
    }
}

impl TemplateBinding {
    fn as_str(self) -> &'static str {
        match self {
            TemplateBinding::Unbound => "unbound",
            TemplateBinding::ExactResourcePin => "exact_resource_pin",
            TemplateBinding::ExactOrPatternList => "exact_or_pattern_list",
            TemplateBinding::Bounded => "bounded",
        }
    }
}

pub use cermet_lang::templates::{
    CatalogClass, CatalogEntry, CatalogField, CatalogShape, ResponseContract,
};

// ---------------------------------------------------------------------------
// Placeholder grammar
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Transform {
    Base64,
    /// A whole-value body sentinel: if the frozen resource value equals this literal, the enclosing
    /// object key is OMITTED from the wire body; otherwise the raw string is sent. Exists because
    /// Vercel's `target` field has no legal `preview` value — a preview deploy must send no `target`
    /// key — yet policy still needs a required, pinned `environment` field to key off. Legal only on
    /// a declared, required, Str field.
    Omit(String),
    /// A whole-value body fill-in: send the frozen resource value if present, else this fixed literal.
    /// Exists because a provider may REQUIRE a field the agent usually omits with a safe default —
    /// Vercel's env-var `type` is required by the API, so an unpinned request must still send
    /// `encrypted` (never store the secret plaintext). The literal is compile-time-fixed in the
    /// ratified template (agent-unsteerable) and approver-visible. Legal only on a declared, optional
    /// Str field (a required field is always present, so the default would be dead).
    Default(String),
    /// Render a positive bounded integer as its negative counterpart. This supports provider credit
    /// APIs without letting a one-sided `amount <= N` rule admit arbitrary negative input values.
    Negative,
    /// Escape a string for insertion inside fixed, double-quoted provider query grammar.
    QueryLiteral,
}

#[derive(Debug, Clone)]
pub(crate) struct Placeholder {
    pub(crate) name: String,
    pub(crate) optional: bool,
    pub(crate) transform: Option<Transform>,
    /// Whether the placeholder spans the ENTIRE source string (`"{x}"`) vs is embedded (`"a{x}b"`).
    pub(crate) whole: bool,
}

/// A literal run or a `{...}` placeholder — the executor consumes these to re-interpolate a step's
/// path/query/body at run time (see [`segments`]).
#[derive(Debug, Clone)]
pub(crate) enum Segment {
    Literal(String),
    Placeholder(Placeholder),
}

/// A lowercase-ascii identifier: `[a-z0-9_]`, non-empty, at most 64 chars.
fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_reserved(name: &str) -> bool {
    name == "token" || name == "parameters"
}

/// An `omit:` literal: `[a-z0-9_-]`, non-empty, at most 64 chars. A hyphen is allowed (unlike an
/// identifier) so a real API-default value like `custom-env` is expressible.
fn is_omit_literal(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Parse the `|`-suffixed transform of a placeholder body: `base64`, or `omit:<literal>`.
fn parse_transform(tf: &str) -> Result<Transform, String> {
    if tf == "base64" {
        return Ok(Transform::Base64);
    }
    if tf == "negative" {
        return Ok(Transform::Negative);
    }
    if tf == "query_literal" {
        return Ok(Transform::QueryLiteral);
    }
    if let Some(lit) = tf.strip_prefix("omit:") {
        if !is_omit_literal(lit) {
            return Err(format!(
                "has an `omit:` literal `{lit}` that is not `[a-z0-9_-]{{1,64}}`"
            ));
        }
        return Ok(Transform::Omit(lit.to_string()));
    }
    if let Some(lit) = tf.strip_prefix("default:") {
        if !is_omit_literal(lit) {
            return Err(format!(
                "has a `default:` literal `{lit}` that is not `[a-z0-9_-]{{1,64}}`"
            ));
        }
        return Ok(Transform::Default(lit.to_string()));
    }
    Err(format!(
        "uses an unknown placeholder transform `{tf}` (supported: `base64`, \
         `negative`, `query_literal`, `omit:<literal>`, `default:<literal>`)"
    ))
}

/// A capture pointer `$.seg(.seg)*` with identifier segments.
fn is_json_pointer(s: &str) -> bool {
    match s.strip_prefix("$.") {
        Some(rest) => !rest.is_empty() && rest.split('.').all(is_ident),
        None => false,
    }
}

/// A dotted keep path `seg(.seg)*` addressing PROVIDER RESPONSE fields. Unlike a template
/// identifier, a response key may carry uppercase (`[A-Za-z0-9_]`) — keep names are provider-defined
/// JSON object keys (e.g. Vercel's `readyState`/`inspectorUrl`), not template inputs. The secret
/// guard at rule 14 still fires: every secret field name is a lowercase identifier, so an uppercase
/// keep segment can never collide with one, and a lowercase segment is still checked.
fn is_response_key(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub(crate) fn is_dotted_path(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(is_response_key)
}

/// One segment of a relay predicate path — a literal `[A-Za-z0-9._~-]+`, or the
/// single-segment wildcard `*`. Deliberately no `%`: a predicate path is compared against the
/// request's raw path, so admitting percent-escapes would create two spellings of one path.
fn is_predicate_segment(segment: &str) -> bool {
    segment == "*"
        || (!segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-')))
}

/// The predicate-path syntax. `/`-rooted, bounded, no query/fragment (those are
/// declared separately as `query_keys`), and every segment either a literal or `*`.
fn validate_predicate_path(ctx: &str, path: &str) -> Result<(), String> {
    let bad = |why: &str| format!("{ctx}: predicate path `{path}` {why}");
    if !path.starts_with('/') {
        return Err(bad("is not `/`-rooted"));
    }
    if path.len() > MAX_PREDICATE_PATH_BYTES {
        return Err(bad("is over the predicate path byte cap"));
    }
    if path.contains('?') || path.contains('#') {
        return Err(bad(
            "carries a query or fragment (declare permitted query parameters as `query_keys`)",
        ));
    }
    for segment in path.trim_start_matches('/').split('/') {
        if !is_predicate_segment(segment) {
            return Err(bad(&format!(
                "has segment `{segment}`, which is neither a `[A-Za-z0-9._~-]` literal nor the \
                 single-segment wildcard `*`"
            )));
        }
    }
    Ok(())
}

/// Does the request path `path` match the predicate `pattern`? Segment-wise, with
/// `*` matching exactly one non-empty segment — so `/v13/deployments/*` admits one deployment id and
/// `/v2/deployments/*/events` admits one id followed by the literal `events`, and neither admits a
/// deeper or shorter path. Both sides are compared raw; the caller has already refused any request
/// path that is not `/`-rooted, bounded, and segment-legal.
pub fn predicate_path_matches(pattern: &str, path: &str) -> bool {
    predicate_path_wildcards(pattern, path).is_some()
}

/// The same match, keeping what the `*` segments were FILLED WITH. The verdict used to
/// discard them, which is exactly why a session could poll any deployment id it liked: a wildcard
/// segment is an authority-bearing wire position, and pinning it needs the value, not just the fact
/// that something matched. `None` means the path does not match the pattern at all.
pub fn predicate_path_wildcards<'a>(pattern: &str, path: &'a str) -> Option<Vec<&'a str>> {
    let pattern_segments = pattern.trim_start_matches('/').split('/');
    let mut path_segments = path.trim_start_matches('/').split('/');
    let mut wildcards = Vec::new();
    for expected in pattern_segments {
        let actual = path_segments.next()?;
        match expected {
            "*" if !actual.is_empty() => wildcards.push(actual),
            literal if literal == actual => {}
            _ => return None,
        }
    }
    path_segments.next().is_none().then_some(wildcards)
}

/// Scan a string for `{name}` / `{name?}` / `{name|base64}` placeholders. Fail closed: refuse any
/// unbalanced, nested, or empty brace, and any literal `{`/`}` outside a well-formed placeholder.
fn parse_placeholders(s: &str) -> Result<Vec<Placeholder>, String> {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        match chars[i] {
            '}' => return Err("has an unbalanced `}`".into()),
            '{' => {
                let start = i + 1;
                let mut j = start;
                while j < n && chars[j] != '}' && chars[j] != '{' {
                    j += 1;
                }
                if j >= n {
                    return Err("has an unbalanced `{`".into());
                }
                if chars[j] == '{' {
                    return Err("has a nested `{`".into());
                }
                let content: String = chars[start..j].iter().collect();
                let (name, optional, transform) = parse_placeholder_body(&content)?;
                out.push(Placeholder {
                    name,
                    optional,
                    transform,
                    whole: i == 0 && j == n - 1,
                });
                i = j + 1;
            }
            _ => i += 1,
        }
    }
    Ok(out)
}

/// Split a string into literal runs and `{...}` placeholders, using the same fail-closed scan as
/// [`parse_placeholders`] but preserving the literal text. The executor re-parses each step string
/// through this so a validated template is interpolated deterministically at run time.
pub(crate) fn segments(s: &str) -> Result<Vec<Segment>, String> {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut lit = String::new();
    let mut i = 0;
    while i < n {
        match chars[i] {
            '}' => return Err("has an unbalanced `}`".into()),
            '{' => {
                if !lit.is_empty() {
                    out.push(Segment::Literal(std::mem::take(&mut lit)));
                }
                let start = i + 1;
                let mut j = start;
                while j < n && chars[j] != '}' && chars[j] != '{' {
                    j += 1;
                }
                if j >= n {
                    return Err("has an unbalanced `{`".into());
                }
                if chars[j] == '{' {
                    return Err("has a nested `{`".into());
                }
                let content: String = chars[start..j].iter().collect();
                let (name, optional, transform) = parse_placeholder_body(&content)?;
                out.push(Segment::Placeholder(Placeholder {
                    name,
                    optional,
                    transform,
                    whole: i == 0 && j == n - 1,
                }));
                i = j + 1;
            }
            c => {
                lit.push(c);
                i += 1;
            }
        }
    }
    if !lit.is_empty() {
        out.push(Segment::Literal(lit));
    }
    Ok(out)
}

fn parse_placeholder_body(content: &str) -> Result<(String, bool, Option<Transform>), String> {
    if content.is_empty() {
        return Err("has an empty placeholder `{}`".into());
    }
    if let Some((name, tf)) = content.split_once('|') {
        let transform = parse_transform(tf)?;
        if name.contains('?') {
            return Err("combines `?` and a transform in one placeholder (not allowed)".into());
        }
        if !is_ident(name) {
            return Err(format!("has a malformed placeholder name `{name}`"));
        }
        return Ok((name.to_string(), false, Some(transform)));
    }
    if let Some(name) = content.strip_suffix('?') {
        if !is_ident(name) {
            return Err(format!("has a malformed placeholder name `{name}`"));
        }
        return Ok((name.to_string(), true, None));
    }
    if !is_ident(content) {
        return Err(format!("has a malformed placeholder name `{content}`"));
    }
    Ok((content.to_string(), false, None))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn leak_str(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

impl ActionTemplate {
    /// The provider this template extends (read-only accessor for the proposal store).
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The action this template defines (read-only accessor for the proposal store).
    pub fn action(&self) -> &str {
        &self.action
    }

    /// The compiled HTTP wire shape of each step, in order: `(method, has_body)`. `has_body` is true
    /// when the step carries a JSON/form body OR a frozen GraphQL query. This is the structural
    /// surface the wire-purity test reads to
    /// prove a read verb compiles to exactly one bodiless GET (not merely that its sidecar is labelled
    /// `observation`), and that a write's mutating step is a non-GET.
    pub fn http_step_shapes(&self) -> Option<Vec<HttpStepShape>> {
        match &self.exec {
            ExecKind::Http { spec, .. } => Some(
                spec.steps
                    .iter()
                    .map(|step| HttpStepShape {
                        method: step.method.clone(),
                        has_body: step.body.is_some() || step.graphql_query.is_some(),
                    })
                    .collect(),
            ),
            ExecKind::Git { .. } => None,
            ExecKind::Relay { .. } => None,
        }
    }

    /// Whether every HTTP step is semantically a verification read. Frozen GraphQL `query`
    /// documents ride POST but remain reads; GraphQL mutations and ordinary non-GET steps do not.
    /// This lets review guards classify execution shape without trusting action-name namespaces.
    pub fn http_steps_are_read_only(&self) -> Option<bool> {
        match &self.exec {
            ExecKind::Http { spec, .. } => Some(spec.steps.iter().all(is_verification_read)),
            // Not an HTTP question: the subprocess kind has no HTTP steps to classify. (Its effect
            // is unambiguously a write — a push — and it has no status codes to pin.)
            ExecKind::Git { .. } => None,
            ExecKind::Relay { .. } => None,
        }
    }

    /// Whether EVERY HTTP step pins a non-empty `success_statuses`. `None` for a non-HTTP
    /// verb. Used by the write-status-pin guard test to prove no write ships accepting any 2xx.
    pub fn every_http_step_pins_success_status(&self) -> Option<bool> {
        match &self.exec {
            ExecKind::Http { spec, .. } => Some(
                spec.steps
                    .iter()
                    .all(|step| !step.success_statuses.is_empty()),
            ),
            ExecKind::Git { .. } => None,
            ExecKind::Relay { .. } => None,
        }
    }

    fn ctx(&self) -> String {
        format!("{}.{}", self.provider, self.action)
    }

    /// The discovery view of this template: schema shape only, no step bodies, no values.
    /// `requestable` is supplied by the caller (whether the owning registry has it loaded);
    /// `temporal_clauses` is the daemon's declared `language_temporal_clauses` setting, which
    /// decides whether the per-field WHERE index may advertise `budget` — the index must never
    /// teach a form corpus admission would refuse.
    pub fn catalog_entry(&self, requestable: bool, temporal_clauses: bool) -> CatalogEntry {
        CatalogEntry {
            provider: self.provider.clone(),
            action: self.action.clone(),
            class: CatalogClass::from_action(&self.action),
            fields: self
                .fields
                .iter()
                .map(|f| CatalogField {
                    name: f.name.clone(),
                    ty: f.ty.as_str().to_string(),
                    required: f.required,
                    class: f.class.as_str().to_string(),
                    binding: f.binding.as_str().to_string(),
                    origin: if self
                        .evidence_profile()
                        .is_some_and(|profile| profile.is_output(&f.name))
                    {
                        "provider_resolved".to_string()
                    } else {
                        "agent_request".to_string()
                    },
                    // The WHERE index, derived from this field's kernel declaration.
                    forms: field_shape(f)
                        .admissible_forms(temporal_clauses)
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                })
                .collect(),
            execution_targets: self.execution_targets.clone(),
            requestable,
            shape: self.shape(),
            // Policy-independent by construction; catalog_listing (the policy-aware path) overrides
            // both of these.
            sentence_denied: false,
            admitted_by: Vec::new(),
            denied_by: Vec::new(),
            response: self.response_contract(),
        }
    }

    /// This verb's response contract, DERIVED FROM WHAT IT ACTUALLY DOES.
    ///
    /// A declared surface that is not derived from behavior is a confident lie, so there is no
    /// universal default here — each execution kind states its own truth:
    ///
    /// - **HTTP** returns the provider's body verbatim and stores it, unless the terminal step
    ///   declares `retention: none`. Its errors are the executor's `{"status", "error"}` envelope
    ///   — EXCEPT that a GraphQL step also fails in a second shape: a provider-declared failure
    ///   arrives at HTTP 200 with the body untouched and the classified verdict in the sibling
    ///   envelope. A GraphQL verb therefore declares BOTH, because it really does both.
    /// - **RELAY** makes no provider call at execute time: it opens a
    ///   predicate-bounded relay session and returns the metadata receipt naming it (handle, relay
    ///   URL, invocation, deadline). There is no provider body to return or retain, and a failure is
    ///   the same receipt shape carrying the refusal — so it declares `receipt`/`none`/`receipt`.
    pub fn response_contract(&self) -> ResponseContract {
        match &self.exec {
            ExecKind::Http { spec, .. } => {
                let terminal = spec.steps.last();
                let capped = terminal.is_some_and(|step| step.retention == RetentionMode::None);
                let graphql = terminal.is_some_and(|step| step.graphql_query.is_some());
                ResponseContract {
                    retention: if capped { "none" } else { "full" }.to_string(),
                    errors: if graphql {
                        "status_and_body_or_verdict"
                    } else {
                        "status_and_body"
                    }
                    .to_string(),
                    ..ResponseContract::http()
                }
            }
            // The subprocess kind's response is BROKER-AUTHORED from data the broker already holds
            // (the frozen resource plus the runner's own exit status) — there is no provider body to
            // return verbatim and none is retained. Its errors are the executor's refusal sentence.
            ExecKind::Git { .. } => ResponseContract {
                returns: "receipt".to_string(),
                retention: "none".to_string(),
                errors: "refusal".to_string(),
            },
            ExecKind::Relay { .. } => ResponseContract {
                returns: "receipt".to_string(),
                retention: "none".to_string(),
                errors: "receipt".to_string(),
            },
        }
    }

    /// The one-read execution shape (see [`CatalogShape`]). Purely structural: the execution kind,
    /// plus — for an HTTP verb — whether a free_payload field rides a base64 body (the inline-content
    /// "you upload the bytes" signal) vs identity pins / references only. Reads no value.
    pub fn shape(&self) -> CatalogShape {
        match &self.exec {
            ExecKind::Http { spec, .. } if self.http_uploads_inline(spec) => {
                CatalogShape::HttpInlineUpload
            }
            ExecKind::Http { .. } => CatalogShape::HttpApiCall,
            ExecKind::Git { .. } => CatalogShape::GitPush,
            ExecKind::Relay { .. } => CatalogShape::Relay,
        }
    }

    /// True iff any step body carries a `base64` transform on a declared FreePayload field — the
    /// signal that the agent supplies inline content bytes (vs a git ref / read filter).
    fn http_uploads_inline(&self, spec: &HttpSpec) -> bool {
        spec.steps
            .iter()
            .filter_map(|s| s.body.as_ref())
            .any(|b| self.body_has_inline_upload(b))
    }

    fn body_has_inline_upload(&self, body: &Value) -> bool {
        match body {
            Value::String(s) => parse_placeholders(s).is_ok_and(|phs| {
                phs.iter().any(|ph| {
                    matches!(ph.transform, Some(Transform::Base64))
                        && self
                            .field(&ph.name)
                            .is_some_and(|f| f.class == TemplateClass::FreePayload)
                })
            }),
            Value::Object(m) => m.values().any(|v| self.body_has_inline_upload(v)),
            Value::Array(a) => a.iter().any(|v| self.body_has_inline_upload(v)),
            _ => false,
        }
    }

    fn field(&self, name: &str) -> Option<&TemplateField> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// The HTTP spec, if this is an http verb (None otherwise).
    fn http_spec(&self) -> Option<&HttpSpec> {
        match &self.exec {
            ExecKind::Http { spec, .. } => Some(spec),
            ExecKind::Git { .. } => None,
            ExecKind::Relay { .. } => None,
        }
    }

    /// The subprocess spec, if this is a `git:` verb (`None` otherwise). The executor reads it to
    /// resolve the remote path and the frozen fields the hermetic runner needs.
    pub(crate) fn git_spec(&self) -> Option<&GitSpec> {
        match &self.exec {
            ExecKind::Git { spec, .. } => Some(spec),
            ExecKind::Http { .. } => None,
            ExecKind::Relay { .. } => None,
        }
    }

    /// The ordered HTTP steps — the executor walks these in order (see provider.rs).
    pub(crate) fn steps(&self) -> &[StepSpec] {
        self.http_spec().map(|h| h.steps.as_slice()).unwrap_or(&[])
    }

    /// The URL-path expansion mode of a field (default [`PathMode::Segment`]).
    pub(crate) fn path_mode(&self, field: &str) -> PathMode {
        self.http_spec()
            .and_then(|h| h.path_modes.get(field).copied())
            .unwrap_or(PathMode::Segment)
    }

    /// The declared fields the HTTP executor reads.
    fn effective_consumes(&self) -> Vec<String> {
        match &self.exec {
            ExecKind::Http { consumes, .. }
            | ExecKind::Git { consumes, .. }
            | ExecKind::Relay { consumes, .. } => consumes.clone(),
        }
    }

    /// Every declared field that appears as a URL-path placeholder, with its expansion mode. Used by
    /// the request-time resource validator so a bad path denies before a grant is ever minted.
    pub(crate) fn path_fields(&self) -> Vec<(String, PathMode)> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for step in self.steps() {
            let Ok(phs) = parse_placeholders(&step.path) else {
                continue;
            };
            for ph in phs {
                if self.field(&ph.name).is_some() && seen.insert(ph.name.clone()) {
                    let mode = self.path_mode(&ph.name);
                    out.push((ph.name, mode));
                }
            }
        }
        out
    }

    /// The declared fields carrying a canonical-value `format` shape, for the request-time resource
    /// validator (`provider::validate_template_resource`) to enforce at admission.
    pub(crate) fn format_fields(&self) -> Vec<(&str, FieldFormat)> {
        self.fields
            .iter()
            .filter_map(|f| f.format.map(|fmt| (f.name.as_str(), fmt)))
            .collect()
    }

    /// The declared fields whose value the ratified template FIXES, for the
    /// admission validator to enforce (`provider::validate_template_resource`).
    pub(crate) fn fixed_fields(&self) -> Vec<(&str, &str)> {
        self.fields
            .iter()
            .filter_map(|f| f.fixed.as_deref().map(|value| (f.name.as_str(), value)))
            .collect()
    }

    /// This verb's relay predicate, or `None` for a constructed (`http`) verb. The
    /// broker reads it to freeze a relay session's admitted request shapes at claim.
    pub fn relay_predicate(&self) -> Option<&[PredicateRule]> {
        match &self.exec {
            ExecKind::Relay { predicate, .. } => Some(predicate),
            ExecKind::Http { .. } => None,
            ExecKind::Git { .. } => None,
        }
    }

    pub(crate) fn string_char_limits(&self) -> Vec<(&str, usize)> {
        self.fields
            .iter()
            .filter_map(|field| {
                field
                    .max_chars
                    .map(|max_chars| (field.name.as_str(), max_chars))
            })
            .collect()
    }

    pub(crate) fn integer_limits(&self) -> Vec<(&str, i64)> {
        self.fields
            .iter()
            .filter_map(|field| field.max_int.map(|max_int| (field.name.as_str(), max_int)))
            .collect()
    }

    pub(crate) fn string_char_budget(&self) -> Option<(&[String], usize)> {
        self.string_char_budget
            .as_ref()
            .map(|budget| (budget.fields.as_slice(), budget.max_chars))
    }

    pub(crate) fn secret_field_names(&self) -> Vec<String> {
        self.fields
            .iter()
            .filter(|f| f.class == TemplateClass::Secret)
            .map(|f| f.name.clone())
            .collect()
    }

    pub(crate) fn evidence_profile(&self) -> Option<&'static crate::evidence::EvidenceProfile> {
        self.request_evidence
            .as_deref()
            .and_then(crate::evidence::profile)
    }

    pub(crate) fn request_evidence_id(&self) -> Option<&str> {
        self.request_evidence.as_deref()
    }

    /// The compiled profile that rewrites one supplied field to the provider's own
    /// canonical identifier before the sentence judges the request.
    pub(crate) fn canonicalization_profile(
        &self,
    ) -> Option<&'static crate::canonicalize::CanonicalizationProfile> {
        self.request_canonicalization
            .as_deref()
            .and_then(crate::canonicalize::profile)
    }

    pub(crate) fn is_money(&self) -> bool {
        self.money.is_some()
    }

    /// The two EXECUTION-DISCIPLINE bits this ratified, hash-bound template declares. They are
    /// properties of the verb, not a class of verb: the broker reads them off the template it
    /// froze on the grant (and re-verified at claim) and passes them to the ONE provider execution
    /// seam as data. Nothing on that seam asks whether a verb is "money" — it asks whether this
    /// verb's effect needs a broker-minted at-most-once key, and whether its response must be
    /// PROVED against a compiled success contract rather than believed.
    ///
    /// Both bits are declared by the template's `money:` block, which is also where the money-scoped
    /// LANGUAGE lives (the bounded `amount` side-effect field, the compiled preconditions, the
    /// success contract). Money-scoped vocabulary is legitimate there — money is removed from the
    /// execution-path type system, not from the sentence language.
    /// `tests/ontology_execution_discipline.rs` is the standing check that the axes of the reviewed
    /// sidecar can never contradict what a template declares here.
    pub(crate) fn mints_idempotency_key(&self) -> bool {
        self.money.is_some()
    }

    /// Whether this verb's response is PROVED (or refused) against its compiled success contract,
    /// producing the [`crate::mutation_success::EffectProof`] observation the broker records beside
    /// the response. See [`Self::mints_idempotency_key`].
    pub(crate) fn proves_effect(&self) -> bool {
        self.money.is_some()
    }

    pub(crate) fn precondition_names(&self) -> &[String] {
        self.money
            .as_ref()
            .map(|money| money.preconditions.as_slice())
            .unwrap_or(&[])
    }

    pub(crate) fn precondition_fingerprint(&self) -> Option<String> {
        crate::preconditions::semantics_fingerprint(
            &self.provider,
            &self.action,
            self.precondition_names(),
        )
    }

    /// Fail-closed structural validation. Any doubt refuses the document with a `provider.action:`
    /// prefixed sentence. Registry-wide cross-template checks live in [`TemplateRegistry::load`].
    /// `providers` is the ratified-descriptor ceiling map the owning registry knows — a template may
    /// only extend a provider whose descriptor pins an egress origin (rule 1).
    pub fn validate(&self, providers: &HashMap<String, ProviderCeiling>) -> Result<(), String> {
        let ctx = self.ctx();

        // ---- caps (fields; the steps cap is http-only, checked in validate_http) ----
        if self.fields.len() > MAX_FIELDS {
            return Err(format!(
                "{ctx}: declares {} fields, over the cap of {MAX_FIELDS}",
                self.fields.len()
            ));
        }

        // ---- rule 3: identifiers, duplicates, reserved names ----
        if !is_ident(&self.action) {
            return Err(format!(
                "{ctx}: action `{}` is not a lowercase identifier ([a-z0-9_], 1..=64 chars)",
                self.action
            ));
        }
        if CatalogClass::from_action(&self.action) == CatalogClass::Setup {
            if self.money.is_some() {
                return Err(format!(
                    "{ctx}: setup-class action may not declare `money`; fixture vocabulary is \
                     excluded from the money corpus"
                ));
            }
            if let Some(field) = self
                .fields
                .iter()
                .find(|field| field.class == TemplateClass::Secret)
            {
                return Err(format!(
                    "{ctx}: setup-class action may not declare secret field `{}`",
                    field.name
                ));
            }
        }
        // The generated MCP tool name is `provider-action`; refuse anything a model provider would
        // truncate/drop so an over-length verb can never reach the catalog (fail closed here, not in
        // the MCP layer).
        let tool_name_len = self.provider.len() + 1 + self.action.len();
        if tool_name_len > MAX_TOOL_NAME_LEN {
            return Err(format!(
                "{ctx}: generated MCP tool name `{}-{}` is {tool_name_len} chars, over the \
                 {MAX_TOOL_NAME_LEN}-char cap (model providers cap tool names at 64; the longest \
                 client prefix `mcp__cermet__` is 13, leaving 64-13=51)",
                self.provider, self.action
            ));
        }
        let mut seen_fields = HashSet::new();
        for f in &self.fields {
            if !is_ident(&f.name) {
                return Err(format!(
                    "{ctx}: field name `{}` is not a lowercase identifier",
                    f.name
                ));
            }
            if is_reserved(&f.name) {
                return Err(format!(
                    "{ctx}: field `{}` uses a reserved name (`token`/`parameters` may never be a field)",
                    f.name
                ));
            }
            if !seen_fields.insert(f.name.as_str()) {
                return Err(format!(
                    "{ctx}: field `{}` is declared more than once",
                    f.name
                ));
            }
            // A `fixed` value is the field's whole domain, so it is meaningful only
            // where a value is always present and comparable as a string.
            if let Some(fixed) = &f.fixed {
                if f.ty != TemplateType::Str || !f.required {
                    return Err(format!(
                        "{ctx}: field `{}` declares `fixed` but is not a required str field",
                        f.name
                    ));
                }
                if !is_omit_literal(fixed) {
                    return Err(format!(
                        "{ctx}: field `{}` has a `fixed` literal `{fixed}` that is not \
                         `[a-z0-9_-]{{1,64}}`",
                        f.name
                    ));
                }
            }
            // A `format` (canonical-value shape) constrains a STRING value; it is meaningless on a
            // non-str field and refused at load so a typo can never silently disable the check.
            if f.format.is_some() && f.ty != TemplateType::Str {
                return Err(format!(
                    "{ctx}: field `{}` declares a `format` but is not a str field; a value-shape \
                     constraint is legal only on a str",
                    f.name
                ));
            }
            if let Some(max_chars) = f.max_chars {
                if f.ty != TemplateType::Str {
                    return Err(format!(
                        "{ctx}: field `{}` declares `max_chars` but is not a str field",
                        f.name
                    ));
                }
                if !(1..=MAX_STRING_CHARS).contains(&max_chars) {
                    return Err(format!(
                        "{ctx}: field `{}` max_chars {max_chars} is outside 1..={MAX_STRING_CHARS}",
                        f.name
                    ));
                }
            }
            if let Some(max_int) = f.max_int {
                if f.ty != TemplateType::Int {
                    return Err(format!(
                        "{ctx}: field `{}` declares `max_int` but is not an int field",
                        f.name
                    ));
                }
                if max_int <= 0 {
                    return Err(format!(
                        "{ctx}: field `{}` max_int {max_int} is not positive",
                        f.name
                    ));
                }
            }
        }

        // Request-time canonicalization. The document names one compiled profile; what it
        // must line up with is the field that profile rewrites.
        if let Some(profile_id) = self.request_canonicalization.as_deref() {
            let profile = crate::canonicalize::profile(profile_id).ok_or_else(|| {
                format!(
                    "{ctx}: request_canonicalization names unknown compiled profile `{profile_id}`"
                )
            })?;
            if profile.provider != self.provider || profile.action != self.action {
                return Err(format!(
                    "{ctx}: request_canonicalization profile `{profile_id}` is registered for {}.{}, not this action",
                    profile.provider, profile.action
                ));
            }
            // A canonicalized value is provider-resolved AND agent-supplied at once; the evidence
            // path's contract is that those sets are disjoint. No document combines them.
            if self.request_evidence.is_some() {
                return Err(format!(
                    "{ctx}: request_canonicalization and request_evidence are mutually exclusive \
                     (an evidence output is absent from the request; a canonicalized field is \
                     supplied by it)"
                ));
            }
            let field = self.field(profile.field).ok_or_else(|| {
                format!(
                    "{ctx}: request_canonicalization profile `{profile_id}` names undeclared field `{}`",
                    profile.field
                )
            })?;
            if field.ty != TemplateType::Str || !field.required {
                return Err(format!(
                    "{ctx}: canonicalized field `{}` must be a required string",
                    profile.field
                ));
            }
            if !matches!(
                field.class,
                TemplateClass::Identity | TemplateClass::SideEffect
            ) {
                return Err(format!(
                    "{ctx}: canonicalized field `{}` must be identity or side_effect, not {:?}",
                    profile.field, field.class
                ));
            }
            // Canonicalizing a field no sentence can pin buys nothing: the whole point is that the
            // corpus keeps pinning the provider's identifier while the request may spell it either
            // way.
            if !self.execution_targets.iter().any(|t| t == profile.field) {
                return Err(format!(
                    "{ctx}: canonicalized field `{}` must be an execution target",
                    profile.field
                ));
            }
        }
        // A template may name only one compiled, versioned profile registered for this exact action.
        // The profile is the sole field-origin source; YAML cannot repeat or override origins.
        if let Some(profile_id) = self.request_evidence.as_deref() {
            let profile = crate::evidence::profile(profile_id).ok_or_else(|| {
                format!("{ctx}: request_evidence names unknown compiled profile `{profile_id}`")
            })?;
            if profile.provider != self.provider || profile.action != self.action {
                return Err(format!(
                    "{ctx}: request_evidence profile `{profile_id}` is registered for {}.{}, not this action",
                    profile.provider, profile.action
                ));
            }
            let mut inputs = HashSet::new();
            for input in profile.inputs {
                if !inputs.insert(input.field) {
                    return Err(format!(
                        "{ctx}: compiled profile `{profile_id}` repeats input `{}`",
                        input.field
                    ));
                }
                let field = self.field(input.field).ok_or_else(|| {
                    format!(
                        "{ctx}: request_evidence profile `{profile_id}` names undeclared input `{}`",
                        input.field
                    )
                })?;
                if field.ty.to_scalar() != input.ty {
                    return Err(format!(
                        "{ctx}: request_evidence input `{}` has type {:?}, profile requires {:?}",
                        input.field,
                        field.ty.to_scalar(),
                        input.ty
                    ));
                }
                if !field.required {
                    return Err(format!(
                        "{ctx}: request_evidence input `{}` must be required",
                        input.field
                    ));
                }
            }
            let mut outputs = HashSet::new();
            for output in profile.outputs {
                if !outputs.insert(output.field) {
                    return Err(format!(
                        "{ctx}: compiled profile `{profile_id}` repeats output `{}`",
                        output.field
                    ));
                }
                if inputs.contains(output.field) {
                    return Err(format!(
                        "{ctx}: request_evidence field `{}` overlaps the profile input/output sets",
                        output.field
                    ));
                }
                let field = self.field(output.field).ok_or_else(|| {
                    format!(
                        "{ctx}: request_evidence profile `{profile_id}` names undeclared output `{}`",
                        output.field
                    )
                })?;
                if field.ty.to_scalar() != output.ty {
                    return Err(format!(
                        "{ctx}: request_evidence output `{}` has type {:?}, profile requires {:?}",
                        output.field,
                        field.ty.to_scalar(),
                        output.ty
                    ));
                }
                if !field.required {
                    return Err(format!(
                        "{ctx}: request_evidence output `{}` must be required",
                        output.field
                    ));
                }
                if !matches!(
                    field.class,
                    TemplateClass::Identity | TemplateClass::SideEffect
                ) {
                    return Err(format!(
                        "{ctx}: request_evidence output `{}` must be identity or side_effect, not {:?}",
                        output.field, field.class
                    ));
                }
            }
            let mut sources = HashSet::new();
            for source in profile.sources {
                if !sources.insert(source.kind) {
                    return Err(format!(
                        "{ctx}: compiled profile `{profile_id}` repeats source kind `{}`",
                        source.kind
                    ));
                }
                if !inputs.contains(source.id_field) {
                    return Err(format!(
                        "{ctx}: compiled profile source `{}` references non-input id field `{}`",
                        source.kind, source.id_field
                    ));
                }
            }
        }
        if let Some(money) = &self.money {
            let profile = self.evidence_profile().ok_or_else(|| {
                format!("{ctx}: money metadata requires one compiled request_evidence profile")
            })?;
            for name in ["account", "mode", "currency"] {
                let field = self.field(name).ok_or_else(|| {
                    format!("{ctx}: money action is missing required provider-resolved `{name}`")
                })?;
                if !profile.is_output(name)
                    || !field.required
                    || field.ty != TemplateType::Str
                    || field.class != TemplateClass::Identity
                    || field.binding != TemplateBinding::ExactResourcePin
                {
                    return Err(format!(
                        "{ctx}: money field `{name}` must be a provider-resolved required exact-bound string identity"
                    ));
                }
            }
            let amount = self
                .field("amount")
                .ok_or_else(|| format!("{ctx}: money action is missing canonical `amount`"))?;
            if !amount.required
                || amount.ty != TemplateType::Int
                || amount.class != TemplateClass::SideEffect
                || amount.binding != TemplateBinding::Bounded
                || self.fields.iter().any(|field| {
                    field.name != "amount"
                        && (field.binding == TemplateBinding::Bounded
                            || field.class == TemplateClass::SideEffect)
                })
            {
                return Err(format!(
                    "{ctx}: money action must declare exactly one required bounded integer side-effect field named `amount`"
                ));
            }
            if money.preconditions.is_empty() || money.preconditions.len() > 8 {
                return Err(format!(
                    "{ctx}: money action must name 1..=8 compiled preconditions"
                ));
            }
            let mut seen = HashSet::new();
            for name in &money.preconditions {
                if !seen.insert(name.as_str()) {
                    return Err(format!(
                        "{ctx}: money precondition `{name}` is named more than once"
                    ));
                }
                if crate::preconditions::exact(&self.provider, &self.action, name).is_none() {
                    return Err(format!(
                        "{ctx}: money precondition `{name}` is not compiled for this exact provider/action"
                    ));
                }
            }
            if crate::preconditions::resolve_exact(
                &self.provider,
                &self.action,
                &money.preconditions,
            )
            .is_none()
            {
                return Err(format!(
                    "{ctx}: money action must name its complete compiled precondition set in canonical order"
                ));
            }
            let ExecKind::Http { spec, .. } = &self.exec else {
                return Err(format!(
                    "{ctx}: money metadata is only expressible on an `http:` template"
                ));
            };
            if spec.steps.len() != 1
                || spec.steps[0].method == "GET"
                || spec.steps[0].retention != RetentionMode::None
            {
                return Err(format!(
                    "{ctx}: money action must have exactly one non-GET `retention: none` mutation step"
                ));
            }
            let success_contract = crate::mutation_success::exact(&self.provider, &self.action)
                .ok_or_else(|| {
                    format!(
                        "{ctx}: money action has no compiled mutation success contract for this exact provider/action"
                    )
                })?;
            if !success_contract.matches_template(&spec.steps[0]) {
                return Err(format!(
                    "{ctx}: money response assertions do not exactly match the compiled mutation success contract"
                ));
            }
        }
        {
            let mut seen = HashSet::new();
            for t in &self.execution_targets {
                if !seen.insert(t.as_str()) {
                    return Err(format!(
                        "{ctx}: execution_targets lists `{t}` more than once"
                    ));
                }
            }
        }

        // ---- rule 5: the ONE consistency checker (never reimplement its rules here). ----
        let field_view: Vec<(&str, ScalarKind, FieldClass, AllowBinding, bool)> = self
            .fields
            .iter()
            .map(|f| {
                (
                    f.name.as_str(),
                    f.ty.to_scalar(),
                    f.class.to_field_class(),
                    f.binding.to_allow_binding(),
                    f.required,
                )
            })
            .collect();
        let consumes = self.effective_consumes();
        if let Some(budget) = &self.string_char_budget {
            if budget.fields.is_empty() {
                return Err(format!(
                    "{ctx}: string_char_budget.fields is empty; an aggregate must name at least one field"
                ));
            }
            if budget.fields.len() > MAX_FIELDS {
                return Err(format!(
                    "{ctx}: string_char_budget.fields has {} entries, over the cap of {MAX_FIELDS}",
                    budget.fields.len()
                ));
            }
            if !(1..=MAX_STRING_CHARS).contains(&budget.max_chars) {
                return Err(format!(
                    "{ctx}: string_char_budget.max_chars {} is outside 1..={MAX_STRING_CHARS}",
                    budget.max_chars
                ));
            }
            let mut seen = HashSet::new();
            for name in &budget.fields {
                if !seen.insert(name.as_str()) {
                    return Err(format!(
                        "{ctx}: string_char_budget.fields lists `{name}` more than once"
                    ));
                }
                let Some(field) = self.field(name) else {
                    return Err(format!(
                        "{ctx}: string_char_budget.fields names undeclared field `{name}`"
                    ));
                };
                if field.ty != TemplateType::Str {
                    return Err(format!(
                        "{ctx}: string_char_budget field `{name}` is not a str field"
                    ));
                }
                if !consumes.contains(name) {
                    return Err(format!(
                        "{ctx}: string_char_budget field `{name}` is not consumed by the action"
                    ));
                }
            }
        }
        let consumes_view: Vec<&str> = consumes.iter().map(String::as_str).collect();
        let targets_view: Vec<&str> = self.execution_targets.iter().map(String::as_str).collect();
        crate::contract::check_consistent(
            &self.provider,
            &self.action,
            &field_view,
            &consumes_view,
            &targets_view,
            &[],
        )?;

        // ---- rule 6: a template names a pinnable execution target OR claims account scope. ----
        // "The pin is the verb": an account-scoped bounded read has no finer
        // resource than the credential itself, so `allow provider.action` IS the complete
        // authority quantum. The claim must be DECLARED (`scope: account`) and earned (a bounded
        // read, checked below) — never inferred from request shape, which is how this concept used
        // to leak out as two provider-shaped special cases.
        match (self.execution_targets.is_empty(), self.scope) {
            (false, Some(ScopeMode::Account)) => {
                return Err(format!(
                    "{ctx}: `scope: account` contradicts named execution_targets; the account claim \
                     is that the credential IS the resource — pin the targets or drop the scope"
                ));
            }
            (true, None) => {
                return Err(format!(
                    "{ctx}: execution_targets is empty and no `scope: account` is declared; a \
                     template either names a pinnable execution target or explicitly claims \
                     account scope (a bounded read whose pin is the verb itself)"
                ));
            }
            (true, Some(ScopeMode::Account)) => self.validate_account_scope(&ctx)?,
            (false, None) => {}
        }

        // ---- exec-kind-specific validation ----
        match &self.exec {
            ExecKind::Http { consumes, spec } => {
                self.validate_http(&ctx, providers, consumes, spec)
            }
            ExecKind::Git { consumes, spec } => self.validate_git(&ctx, providers, consumes, spec),
            ExecKind::Relay {
                consumes,
                predicate,
            } => self.validate_relay(&ctx, providers, consumes, predicate),
        }
    }

    /// `scope: account` is EARNED by boundedness (rule 6): constructed `http` execution only, no
    /// money, only `read_filter` fields (an identity/side_effect field on a verb nothing can pin
    /// would be unpinned authority), and every step a statused read — a bodyless GET, or a POST
    /// whose body is a frozen GraphQL `query` (fixture discoveries reconcile through those).
    /// One injection rule survives from the shapes this replaced, on its true rationale: an unbound
    /// filter placeholder EMBEDDED inside a composite query value (a provider search DSL) must be a
    /// `query_literal` flanked by literal quotes — filter content must never rewrite the query's
    /// meaning (this stops injected filter text from steering the read). A placeholder that IS the
    /// whole value has no surrounding DSL to inject into and needs no ceremony.
    fn validate_account_scope(&self, ctx: &str) -> Result<(), String> {
        let ExecKind::Http { spec, .. } = &self.exec else {
            return Err(format!(
                "{ctx}: `scope: account` is legal only on constructed `http` execution; a relay \
                 verb declares its bounds in its predicate"
            ));
        };
        if self.money.is_some() {
            return Err(format!("{ctx}: `scope: account` refuses a money template"));
        }
        for field in &self.fields {
            if field.class != TemplateClass::ReadFilter {
                return Err(format!(
                    "{ctx}: `scope: account` field `{}` must be class `read_filter`; an account-\
                     scoped verb has nothing a sentence can pin, so no identity/side_effect/\
                     free_payload field may ride it",
                    field.name
                ));
            }
        }
        for step in &spec.steps {
            let read_shaped = match step.method.as_str() {
                "GET" => step.body.is_none() && step.graphql_query.is_none(),
                "POST" => step
                    .graphql_query
                    .as_deref()
                    .is_some_and(|query| query.trim_start().starts_with("query")),
                _ => false,
            };
            if !read_shaped || step.success_statuses.is_empty() {
                return Err(format!(
                    "{ctx}: `scope: account` step `{}` is not a statused bounded read (a bodyless \
                     GET or a frozen GraphQL `query`, with explicit success_statuses)",
                    step.id
                ));
            }
            for (qk, qv) in &step.query {
                let Ok(parts) = segments(qv) else {
                    continue; // malformed values are refused by the general query pass
                };
                if parts.len() == 1 {
                    continue; // a whole-value placeholder has no DSL around it
                }
                for (index, part) in parts.iter().enumerate() {
                    let Segment::Placeholder(ph) = part else {
                        continue;
                    };
                    let quoted_before = index
                        .checked_sub(1)
                        .and_then(|i| parts.get(i))
                        .is_some_and(|p| matches!(p, Segment::Literal(s) if s.ends_with('"')));
                    let quoted_after = parts
                        .get(index + 1)
                        .is_some_and(|p| matches!(p, Segment::Literal(s) if s.starts_with('"')));
                    if !matches!(ph.transform, Some(Transform::QueryLiteral))
                        || !quoted_before
                        || !quoted_after
                    {
                        return Err(format!(
                            "{ctx}: `scope: account` step `{}` query `{qk}` embeds placeholder \
                             `{}` inside a composite value; an embedded filter must be a quoted \
                             `query_literal` (filter content must never rewrite the query DSL)",
                            step.id, ph.name
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// The relay path. A relay verb declares no request; it declares the closed set
    /// of requests it will CREDENTIAL. Every rule here exists so that set is finite, reviewable, and
    /// complete with respect to the frozen fields:
    ///
    /// - the provider must have a ratified, egress-pinned descriptor (rule 1, as for `http`) — the
    ///   relay forwards to that origin and nowhere else;
    /// - exactly ONE rule declares `once`: the single effect a single-use grant authorizes;
    /// - a `bind` needs a request body to read, so it is refused on a bodyless method;
    /// - every bound field must be a REQUIRED str field that is `identity`/`side_effect` and either an
    ///   execution target (the sentence pins it) or `fixed` (the template pins it) — otherwise the
    ///   relay would be enforcing a value nobody constrained;
    /// - `capture`/`assert` are legal only on the `once` rule: nothing but the
    ///   approved effect produces an outcome to derive session state from or to compare;
    /// - a declared `caps` budget is positive on both dimensions — a zero cap is a shape
    ///   that admits nothing, which is spelled by not declaring the shape;
    /// - a `path.*` bind must read a DECLARED capture, on a shape whose path has a `*` to pin, and
    ///   never on the effect shape itself (its own capture does not exist until its response lands);
    /// - `consumes` must equal the bound-field set exactly (the honesty rule: a relay executor reads
    ///   nothing else), so the catalog states the true input surface — an asserted field counts, since
    ///   the approval must freeze it for the comparison to mean anything;
    /// - `money`/`request_evidence` are refused: neither combination has an exercised path here, and
    ///   an unexercised authority path is not a feature.
    fn validate_relay(
        &self,
        ctx: &str,
        providers: &HashMap<String, ProviderCeiling>,
        consumes: &[String],
        predicate: &[PredicateRule],
    ) -> Result<(), String> {
        match providers.get(&self.provider) {
            Some(ProviderCeiling::Http) => {}
            Some(ProviderCeiling::HttpAndGit) => {}
            None => {
                return Err(format!(
                    "{ctx}: provider `{}` is not template-extensible (only a provider with a ratified \
                     descriptor pinning an egress origin may be extended by a template)",
                    self.provider
                ));
            }
        }
        if self.request_evidence.is_some() {
            return Err(format!(
                "{ctx}: a relay verb may not declare `request_evidence` (provider-resolved fields \
                 have no relay path)"
            ));
        }
        if predicate.is_empty() {
            return Err(format!(
                "{ctx}: predicate is empty; a relay verb must admit at least one request shape"
            ));
        }
        if predicate.len() > MAX_PREDICATE_RULES {
            return Err(format!(
                "{ctx}: declares {} predicate rules, over the cap of {MAX_PREDICATE_RULES}",
                predicate.len()
            ));
        }
        if predicate.iter().filter(|rule| rule.once).count() != 1 {
            return Err(format!(
                "{ctx}: a relay verb must declare exactly one `once: true` predicate rule — the \
                 single effect its single-use grant authorizes"
            ));
        }
        // The captures the effect shape declares are the WHOLE vocabulary a `path.*` bind
        // may read. Collected up front because a rule earlier in the document may bind a capture the
        // effect declares later.
        let captured_names: HashSet<&str> = predicate
            .iter()
            .filter(|rule| rule.once)
            .flat_map(|rule| rule.capture.keys().map(String::as_str))
            .collect();
        let mut seen_rules: HashSet<(&str, &str)> = HashSet::new();
        let mut bound_fields: HashSet<&str> = HashSet::new();
        for rule in predicate {
            if !matches!(
                rule.method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
            ) {
                return Err(format!(
                    "{ctx}: predicate method `{}` is not one of GET/POST/PUT/PATCH/DELETE (uppercase)",
                    rule.method
                ));
            }
            validate_predicate_path(ctx, &rule.path)?;
            if !seen_rules.insert((rule.method.as_str(), rule.path.as_str())) {
                return Err(format!(
                    "{ctx}: predicate declares `{} {}` more than once",
                    rule.method, rule.path
                ));
            }
            if rule.query_keys.len() > MAX_PREDICATE_QUERY_KEYS {
                return Err(format!(
                    "{ctx}: predicate rule `{} {}` declares {} query keys, over the cap of \
                     {MAX_PREDICATE_QUERY_KEYS}",
                    rule.method,
                    rule.path,
                    rule.query_keys.len()
                ));
            }
            let mut seen_keys = HashSet::new();
            for key in &rule.query_keys {
                if !is_response_key(key) {
                    return Err(format!(
                        "{ctx}: predicate query key `{key}` is not `[A-Za-z0-9_]{{1,64}}`"
                    ));
                }
                if !seen_keys.insert(key.as_str()) {
                    return Err(format!(
                        "{ctx}: predicate rule `{} {}` lists query key `{key}` more than once",
                        rule.method, rule.path
                    ));
                }
            }
            // A BODY bind is what a bodyless method cannot satisfy. A query bind reads the request
            // target, so it is legal on every method (the CLI's reads carry the scope too).
            let binds_a_body_key = rule
                .bind
                .keys()
                .any(|location| location.starts_with("body."));
            if binds_a_body_key && matches!(rule.method.as_str(), "GET" | "DELETE") {
                return Err(format!(
                    "{ctx}: predicate rule `{} {}` declares `bind` on a bodyless method",
                    rule.method, rule.path
                ));
            }
            // A rule that inspects the body must close it. Two ratified keys plus an open
            // remainder is not a closed surface — Vercel's `project` alone voids the identity pin.
            match &rule.body_keys {
                Some(_) if matches!(rule.method.as_str(), "GET" | "DELETE") => {
                    return Err(format!(
                        "{ctx}: predicate rule `{} {}` declares `body_keys` on a bodyless method",
                        rule.method, rule.path
                    ));
                }
                None if binds_a_body_key => {
                    return Err(format!(
                        "{ctx}: predicate rule `{} {}` binds a body key but declares no `body_keys` \
                         allowlist; a rule that inspects the body must close it (declare \
                         `body_keys: []` to admit only the bound keys)",
                        rule.method, rule.path
                    ));
                }
                _ => {}
            }
            if let Some(body_keys) = &rule.body_keys {
                if body_keys.len() > MAX_PREDICATE_BODY_KEYS {
                    return Err(format!(
                        "{ctx}: predicate rule `{} {}` declares {} body keys, over the cap of \
                         {MAX_PREDICATE_BODY_KEYS}",
                        rule.method,
                        rule.path,
                        body_keys.len()
                    ));
                }
                let mut seen_body_keys = HashSet::new();
                for key in body_keys {
                    if !is_response_key(key) {
                        return Err(format!(
                            "{ctx}: predicate body key `{key}` is not `[A-Za-z0-9_]{{1,64}}`"
                        ));
                    }
                    if !seen_body_keys.insert(key.as_str()) {
                        return Err(format!(
                            "{ctx}: predicate rule `{} {}` lists body key `{key}` more than once",
                            rule.method, rule.path
                        ));
                    }
                    if rule
                        .bind
                        .keys()
                        .any(|location| location.strip_prefix("body.") == Some(key.as_str()))
                    {
                        return Err(format!(
                            "{ctx}: predicate rule `{} {}` lists body key `{key}`, which it also \
                             binds; a bound key is admitted implicitly and its VALUE is checked, so \
                             listing it here would read as an unchecked passthrough",
                            rule.method, rule.path
                        ));
                    }
                }
            }
            // A declared budget must be able to admit something. Zero on either dimension
            // is a shape nobody may ever use, which is spelled by DELETING the shape — a rule that
            // reads as "admitted, budgeted" while admitting nothing is the kind of dead enforcement
            // every other rule in here refuses.
            if let Some(caps) = rule.caps {
                for (dimension, value) in [
                    ("max_uses", caps.max_uses),
                    ("max_total_bytes", caps.max_total_bytes),
                ] {
                    if value == 0 {
                        return Err(format!(
                            "{ctx}: predicate rule `{} {}` declares `caps.{dimension}: 0`; a cap \
                             must be positive — a shape that admits nothing is spelled by not \
                             declaring the shape",
                            rule.method, rule.path
                        ));
                    }
                }
            }
            // The response-derived stanzas. Both read a 2xx response body, and
            // only ONE shape has an approved outcome to read — the single effect. On any other shape
            // `capture:` would derive session authority from a mere read, and `assert:` would compare
            // a response nobody approved against a frozen field.
            for (what, declared) in [("capture", &rule.capture), ("assert", &rule.assert)] {
                if !declared.is_empty() && !rule.once {
                    return Err(format!(
                        "{ctx}: predicate rule `{} {}` declares `{what}:`, which is legal only on \
                         the `once: true` effect shape — nothing else produces an approved outcome",
                        rule.method, rule.path
                    ));
                }
            }
            if rule.capture.len() > MAX_PREDICATE_CAPTURES {
                return Err(format!(
                    "{ctx}: predicate rule `{} {}` declares {} captures, over the cap of \
                     {MAX_PREDICATE_CAPTURES}",
                    rule.method,
                    rule.path,
                    rule.capture.len()
                ));
            }
            for (name, key) in &rule.capture {
                if !is_response_key(name) {
                    return Err(format!(
                        "{ctx}: predicate capture name `{name}` is not `[A-Za-z0-9_]{{1,64}}`"
                    ));
                }
                if !is_response_key(key) {
                    return Err(format!(
                        "{ctx}: predicate capture response key `{key}` is not \
                         `[A-Za-z0-9_]{{1,64}}` (a capture reads ONE top-level response key)"
                    ));
                }
            }
            if rule.assert.len() > MAX_PREDICATE_ASSERTS {
                return Err(format!(
                    "{ctx}: predicate rule `{} {}` declares {} assertions, over the cap of \
                     {MAX_PREDICATE_ASSERTS}",
                    rule.method,
                    rule.path,
                    rule.assert.len()
                ));
            }
            for (key, assert_value) in &rule.assert {
                if !is_response_key(key) {
                    return Err(format!(
                        "{ctx}: predicate assert response key `{key}` is not \
                         `[A-Za-z0-9_]{{1,64}}` (an assertion reads ONE top-level response key)"
                    ));
                }
                let (field_name, _) = parse_bind_value(assert_value)
                    .map_err(|why| format!("{ctx}: predicate assert `{key}` {why}"))?;
                let field =
                    self.relay_comparable_field(ctx, &format!("assert `{key}`"), &field_name)?;
                bound_fields.insert(field);
            }
            if rule.bind.len() > MAX_PREDICATE_BINDS {
                return Err(format!(
                    "{ctx}: predicate rule `{} {}` declares {} binds, over the cap of \
                     {MAX_PREDICATE_BINDS}",
                    rule.method,
                    rule.path,
                    rule.bind.len()
                ));
            }
            for (location, bind_value) in &rule.bind {
                let parsed =
                    parse_bind_location(location).map_err(|why| format!("{ctx}: {why}"))?;
                let (field_name, absent_when) = parse_bind_value(bind_value)
                    .map_err(|why| format!("{ctx}: predicate bind `{location}` {why}"))?;
                match &parsed {
                    BindLocation::Body(key) => {
                        if !is_response_key(key) {
                            return Err(format!(
                                "{ctx}: predicate bind location `{location}` names a body key that \
                                 is not `[A-Za-z0-9_]{{1,64}}`"
                            ));
                        }
                    }
                    // The two query dimensions must agree. A value bind on a key the
                    // shape's own allowlist never admits is dead enforcement — the hop already
                    // refuses at key closure — and it reads as protection that is not there.
                    BindLocation::Query(key) => {
                        if !is_response_key(key) {
                            return Err(format!(
                                "{ctx}: predicate bind location `{location}` names a query key that \
                                 is not `[A-Za-z0-9_]{{1,64}}`"
                            ));
                        }
                        if !rule.query_keys.iter().any(|allowed| allowed == key) {
                            return Err(format!(
                                "{ctx}: predicate rule `{} {}` binds query key `{key}`, which its \
                                 `query_keys` allowlist does not admit — a value bind on a key that \
                                 can never arrive enforces nothing",
                                rule.method, rule.path
                            ));
                        }
                    }
                    // The path form pins every `*` segment to a value the session CAPTURED
                    // from its own effect. Four ways it would enforce nothing, all refused here.
                    BindLocation::PathWildcards => {
                        if rule.once {
                            return Err(format!(
                                "{ctx}: predicate rule `{} {}` declares a `path.*` bind on the \
                                 effect shape; its own capture does not exist until its response \
                                 lands, so the bind could never hold",
                                rule.method, rule.path
                            ));
                        }
                        if !rule.path.split('/').any(|segment| segment == "*") {
                            return Err(format!(
                                "{ctx}: predicate rule `{} {}` declares a `path.*` bind but its \
                                 path declares no `*` segment to pin",
                                rule.method, rule.path
                            ));
                        }
                        if absent_when.is_some() {
                            return Err(format!(
                                "{ctx}: predicate bind `{location}` carries an `omit:` transform; a \
                                 path bind pins a segment that is always present, so absence is not \
                                 one of its cases"
                            ));
                        }
                        let Some(name) = field_name.strip_prefix(CAPTURE_PREFIX) else {
                            return Err(format!(
                                "{ctx}: predicate bind `{location}` names `{field_name}`; a path \
                                 bind must read a capture (`captured.<name>`), never an \
                                 approval-frozen field — a wildcard segment is the approved effect's \
                                 own consequence, not something a sentence pins in advance"
                            ));
                        };
                        if !captured_names.contains(name) {
                            return Err(format!(
                                "{ctx}: predicate bind `{location}` names no declared capture \
                                 (`{name}`); the `once: true` shape must declare it under `capture:`"
                            ));
                        }
                        continue;
                    }
                }
                if field_name.starts_with(CAPTURE_PREFIX) {
                    return Err(format!(
                        "{ctx}: predicate bind `{location}` reads a capture (`{field_name}`); only a \
                         `path.*` bind reads response-derived session state — a body or query value \
                         is compared against what the APPROVAL froze"
                    ));
                }
                let field =
                    self.relay_comparable_field(ctx, &format!("bind `{location}`"), &field_name)?;
                bound_fields.insert(field);
            }
        }
        let consumed: HashSet<&str> = consumes.iter().map(String::as_str).collect();
        if consumed.len() != consumes.len() {
            return Err(format!("{ctx}: consumes lists a field more than once"));
        }
        if consumed != bound_fields {
            let mut expected: Vec<&str> = bound_fields.into_iter().collect();
            expected.sort_unstable();
            return Err(format!(
                "{ctx}: a relay verb consumes exactly the fields its predicate binds; declare \
                 `consumes: [{}]`",
                expected.join(", ")
            ));
        }
        Ok(())
    }

    /// The field checks every relay comparison shares — a request `bind` and an outcome `assert`
    /// alike. The frozen value must be COMPARABLE (a required `str`; an absent or non-string value is
    /// not), it must be authority-relevant (`identity`/`side_effect`), and it must be a value SOMEBODY
    /// pinned: an execution target the sentence pins, or `fixed` in the template. Returns the field's
    /// own name, which is what `consumes` must account for.
    fn relay_comparable_field(
        &self,
        ctx: &str,
        what: &str,
        field_name: &str,
    ) -> Result<&str, String> {
        let field = self.field(field_name).ok_or_else(|| {
            format!("{ctx}: predicate {what} names undeclared field `{field_name}`")
        })?;
        if field.ty != TemplateType::Str || !field.required {
            return Err(format!(
                "{ctx}: predicate {what} names field `{field_name}`, which is not a required str \
                 field (an absent or non-string frozen value is not comparable)"
            ));
        }
        if !matches!(
            field.class,
            TemplateClass::Identity | TemplateClass::SideEffect
        ) {
            return Err(format!(
                "{ctx}: predicate {what} names field `{field_name}` classed {:?}; a relay enforces \
                 authority-relevant fields only (identity/side_effect)",
                field.class
            ));
        }
        let pinned_by_sentence = self.execution_targets.iter().any(|t| t == field_name);
        if !pinned_by_sentence && field.fixed.is_none() {
            return Err(format!(
                "{ctx}: predicate {what} names field `{field_name}`, which is neither an execution \
                 target (sentence-pinned) nor `fixed` (template-pinned) — the relay would enforce a \
                 value nobody constrained"
            ));
        }
        Ok(field.name.as_str())
    }

    /// The SUBPROCESS path. Same shape of rules as `validate_http`, restated for the one step kind
    /// this execution kind has: a provider whose ratified descriptor pins a GIT origin (rule 1's
    /// twin — a template can never point a credential at an origin no descriptor pinned), a
    /// placeholder-only remote path whose fields are pinned identities, and one declared field per
    /// runner input with the exact class/binding/format the runner assumes.
    fn validate_git(
        &self,
        ctx: &str,
        providers: &HashMap<String, ProviderCeiling>,
        consumes: &[String],
        git: &GitSpec,
    ) -> Result<(), String> {
        match providers.get(&self.provider) {
            Some(ProviderCeiling::HttpAndGit) => {}
            Some(ProviderCeiling::Http) => {
                return Err(format!(
                    "{ctx}: provider `{}` pins no git origin (only a provider whose ratified \
                     descriptor declares `git.origin` may be extended by a `git:` template)",
                    self.provider
                ));
            }
            None => {
                return Err(format!(
                    "{ctx}: provider `{}` is not template-extensible (only a provider with a \
                     ratified descriptor may be extended by a template)",
                    self.provider
                ));
            }
        }

        // EXACTLY ONE step: two would be two effects, needing two grants and two receipts.
        let (kind, remote_path) = match (&git.push, &git.fetch) {
            (Some(push), None) => ("push", &push.remote_path),
            (None, Some(fetch)) => ("fetch", &fetch.remote_path),
            (Some(_), Some(_)) => {
                return Err(format!(
                    "{ctx}: `git:` declares both `push` and `fetch`; a verb is one effect"
                ));
            }
            (None, None) => {
                return Err(format!(
                    "{ctx}: `git:` must declare exactly one step (`push` or `fetch`)"
                ));
            }
        };

        // ---- the remote path: literal segments plus pinned identity placeholders only ----
        if !remote_path.starts_with('/') {
            return Err(format!(
                "{ctx}: git.{kind}.remote_path `{remote_path}` must start with `/` (it is a path \
                 under the descriptor's pinned git origin, never an origin of its own)"
            ));
        }
        let path_placeholders = parse_placeholders(remote_path)
            .map_err(|m| format!("{ctx}: git.{kind}.remote_path {m}"))?;
        let mut referenced: HashSet<String> = HashSet::new();
        for ph in &path_placeholders {
            if ph.optional || ph.transform.is_some() {
                return Err(format!(
                    "{ctx}: git.{kind}.remote_path placeholder `{}` must be a plain required field \
                     (no `?`, no transform)",
                    ph.name
                ));
            }
            let field = self.field(&ph.name).ok_or_else(|| {
                format!(
                    "{ctx}: git.{kind}.remote_path references undeclared field `{}`",
                    ph.name
                )
            })?;
            if field.ty != TemplateType::Str
                || !field.required
                || field.class != TemplateClass::Identity
                || field.binding != TemplateBinding::ExactResourcePin
            {
                return Err(format!(
                    "{ctx}: git.{kind}.remote_path field `{}` must be a required, exact-pinned Str \
                     identity (it addresses the remote repository)",
                    ph.name
                ));
            }
            referenced.insert(ph.name.clone());
        }

        // ---- the runner's inputs: one declared field each, with the class/binding/format it assumes ----
        let mut check = |slot: &str,
                         name: &str,
                         required: bool,
                         class: TemplateClass,
                         binding: TemplateBinding,
                         format: FieldFormat|
         -> Result<(), String> {
            let field = self
                .field(name)
                .ok_or_else(|| format!("{ctx}: git.push.{slot} names undeclared field `{name}`"))?;
            if field.ty != TemplateType::Str
                || field.required != required
                || field.class != class
                || field.binding != binding
                || field.format != Some(format)
            {
                return Err(format!(
                    "{ctx}: git.push.{slot} field `{name}` must be a {} Str `{}`/`{}` field with \
                     `format: {}`",
                    if required { "required" } else { "optional" },
                    class.as_str(),
                    binding.as_str(),
                    match format {
                        FieldFormat::GitOid => "git_oid",
                        FieldFormat::GitBranchName => "git_branch_name",
                        _ => "…",
                    }
                ));
            }
            referenced.insert(name.to_string());
            Ok(())
        };
        if let Some(step) = &git.push {
            check(
                "branch",
                &step.branch,
                true,
                TemplateClass::Identity,
                TemplateBinding::ExactResourcePin,
                FieldFormat::GitBranchName,
            )?;
            check(
                "new_oid",
                &step.new_oid,
                true,
                TemplateClass::Identity,
                TemplateBinding::ExactResourcePin,
                FieldFormat::GitOid,
            )?;
            if let Some(old) = &step.mirror_old_oid {
                // OPTIONAL in the request: absent means the mirror had no such ref. An absent optional
                // field freezes as ABSENCE, never filled in later.
                check(
                    "mirror_old_oid",
                    old,
                    false,
                    TemplateClass::Identity,
                    TemplateBinding::ExactResourcePin,
                    FieldFormat::GitOid,
                )?;
            }
        }

        // ---- `consumes` is the honest list: exactly what the step references, no more ----
        let mut seen = HashSet::new();
        for name in consumes {
            if !seen.insert(name.as_str()) {
                return Err(format!("{ctx}: consumes lists `{name}` more than once"));
            }
            if !referenced.contains(name) {
                return Err(format!(
                    "{ctx}: consumes lists `{name}`, which the git {kind} step never references"
                ));
            }
        }
        for name in &referenced {
            if !seen.contains(name.as_str()) {
                return Err(format!(
                    "{ctx}: git.{kind} references `{name}` but `consumes` omits it"
                ));
            }
        }

        // ---- no unreferenced fields: every declared field must reach the effect ----
        for field in &self.fields {
            if !referenced.contains(&field.name) {
                return Err(format!(
                    "{ctx}: field `{}` is declared but the git {kind} step never uses it",
                    field.name
                ));
            }
        }

        // ---- the effect is a write: it can never be classified as a read ----
        if self.money.is_some() {
            return Err(format!(
                "{ctx}: money metadata is only expressible on an `http:` template"
            ));
        }
        if self.request_evidence.is_some() {
            return Err(format!(
                "{ctx}: request_evidence resolution is only expressible on an `http:` template"
            ));
        }
        Ok(())
    }

    /// The HTTP path: the egress-pinned-provider gate (rule 1), the steps cap, `consumes` dedup,
    /// `path_modes` (rule 7), and the step rules (8–15).
    fn validate_http(
        &self,
        ctx: &str,
        providers: &HashMap<String, ProviderCeiling>,
        consumes: &[String],
        http: &HttpSpec,
    ) -> Result<(), String> {
        if http.steps.len() > MAX_STEPS {
            return Err(format!(
                "{ctx}: declares {} steps, over the cap of {MAX_STEPS}",
                http.steps.len()
            ));
        }

        // ---- rule 1: the provider must have a ratified, egress-pinned (HTTP) descriptor. ----
        match providers.get(&self.provider) {
            Some(_) => {}
            None => {
                return Err(format!(
                    "{ctx}: provider `{}` is not template-extensible (only a provider with a ratified \
                     descriptor pinning an egress origin may be extended by a template)",
                    self.provider
                ));
            }
        }

        // (There is no compiled-in-built-in shadow rule: the core ships ZERO compiled-in contracts,
        // so a template can shadow nothing. The real post-kill hazard — a template-vs-template name
        // collision — is refused by `load` (single-owner-per-action, `validate_for_load` arm (a)); a
        // future re-introduced built-in would restore this rule alongside its own machinery.)

        {
            let mut seen = HashSet::new();
            for c in consumes {
                if !seen.insert(c.as_str()) {
                    return Err(format!("{ctx}: consumes lists `{c}` more than once"));
                }
            }
        }

        // ---- rule 7: path_modes ----
        for (fname, mode) in &http.path_modes {
            let Some(decl) = self.field(fname) else {
                return Err(format!(
                    "{ctx}: path_modes names `{fname}`, which is not a declared field"
                ));
            };
            if *mode == PathMode::Path
                && (decl.class != TemplateClass::Identity
                    || !decl.required
                    || decl.ty != TemplateType::Str)
            {
                return Err(format!(
                    "{ctx}: field `{fname}` is set to path-mode `path` but is not a required Str \
                     Identity field"
                ));
            }
            // A slash-bearing path-mode field is URL authority; it MUST be a pinnable
            // execution target or an allow could leave it (e.g. `name`) unpinned in the URL.
            if *mode == PathMode::Path && !self.execution_targets.iter().any(|t| t == fname) {
                return Err(format!(
                    "{ctx}: field `{fname}` is path-mode `path` (slash-bearing URL authority) but is \
                     not listed in execution_targets"
                ));
            }
        }

        self.validate_steps(ctx, consumes, http)
    }

    /// Steps (rules 8–14) plus the placeholder/consumes honesty check (rule 15).
    fn validate_steps(
        &self,
        ctx: &str,
        consumes: &[String],
        http: &HttpSpec,
    ) -> Result<(), String> {
        // ---- rule 8: steps non-empty ----
        if http.steps.is_empty() {
            return Err(format!(
                "{ctx}: http.steps is empty; a template must declare at least one step"
            ));
        }
        let last = http.steps.len() - 1;

        // step ids: identifier, unique
        let mut seen_steps = HashSet::new();
        for s in &http.steps {
            if !is_ident(&s.id) {
                return Err(format!(
                    "{ctx}: step id `{}` is not a lowercase identifier",
                    s.id
                ));
            }
            if !seen_steps.insert(s.id.as_str()) {
                return Err(format!(
                    "{ctx}: step id `{}` is declared more than once",
                    s.id
                ));
            }
        }

        // ---- rule 13d: verification reads are one LEADING prefix ----
        // The executor runs steps in document order. Once any mutation has run, a later GET/frozen
        // GraphQL query cannot be a preflight and cannot make the earlier effect safe, regardless of
        // whether the read declares a response assertion. This also makes the final-step boundary
        // structural: only a final non-verification step can carry reconciliation evidence.
        //
        // Setup has one narrow exception: a FINAL bounded read may reconcile the identity captured
        // from the setup's ONE mutation. It authorizes no later effect and does not make the earlier
        // effect safe; it merely returns the child identity needed by the sitting runner.
        if let Some(first_mutating) = http.steps.iter().position(|s| !is_verification_read(s)) {
            if let Some((_read_index, read)) = http.steps.iter().enumerate().find(|(i, step)| {
                if *i <= first_mutating || !is_verification_read(step) {
                    return false;
                }
                let prior_mutations: Vec<_> = http.steps[..*i]
                    .iter()
                    .filter(|prior| !is_verification_read(prior))
                    .collect();
                let captured: HashSet<&str> = prior_mutations
                    .iter()
                    .flat_map(|prior| prior.capture.keys().map(String::as_str))
                    .collect();
                let capture_bound = std::iter::once(step.path.as_str())
                    .chain(step.query.values().map(String::as_str))
                    .filter_map(|source| parse_placeholders(source).ok())
                    .flatten()
                    .any(|placeholder| captured.contains(placeholder.name.as_str()));
                let terminal_setup_reconciliation = CatalogClass::from_action(&self.action)
                    == CatalogClass::Setup
                    && *i == last
                    && prior_mutations.len() == 1
                    && capture_bound;
                !terminal_setup_reconciliation
            }) {
                return Err(format!(
                    "{ctx}: verification read step `{}` follows mutation step `{}`; every GET or \
                     frozen GraphQL query must form a leading prefix and PRECEDE every mutation",
                    read.id, http.steps[first_mutating].id
                ));
            }
        }

        // ---- pass 1: collect captures (rule 13) ----
        // `captures_before[i]` = captures produced by STRICTLY earlier steps; `all_captures` = every
        // capture (needed so a path/query placeholder can never name a capture from a LATER step).
        let mut all_captures: HashSet<String> = HashSet::new();
        let mut captures_before: Vec<HashSet<String>> = Vec::with_capacity(http.steps.len());
        let mut running: HashSet<String> = HashSet::new();
        for (i, step) in http.steps.iter().enumerate() {
            captures_before.push(running.clone());
            if step.capture.len() > MAX_CAPTURES_PER_STEP {
                return Err(format!(
                    "{ctx}: step `{}` declares {} captures, over the per-step cap of {MAX_CAPTURES_PER_STEP}",
                    step.id,
                    step.capture.len()
                ));
            }
            if i == last && !step.capture.is_empty() {
                return Err(format!(
                    "{ctx}: step `{}` (final) declares captures; a final-step capture is dead config",
                    step.id
                ));
            }
            for (cname, ptr) in &step.capture {
                if !is_ident(cname) {
                    return Err(format!(
                        "{ctx}: capture name `{cname}` is not a lowercase identifier"
                    ));
                }
                if is_reserved(cname) {
                    return Err(format!("{ctx}: capture `{cname}` uses a reserved name"));
                }
                if self.field(cname).is_some() {
                    return Err(format!(
                        "{ctx}: capture `{cname}` collides with a declared field name"
                    ));
                }
                if !all_captures.insert(cname.clone()) {
                    return Err(format!(
                        "{ctx}: capture `{cname}` is declared more than once"
                    ));
                }
                if !is_json_pointer(ptr) {
                    return Err(format!(
                        "{ctx}: capture `{cname}` value `{ptr}` is not a `$.seg(.seg)*` pointer"
                    ));
                }
                running.insert(cname.clone());
            }
        }

        // ---- pass 2: methods, paths, query, body, optional_ok ----
        let mut used_fields: HashSet<String> = HashSet::new();
        for (i, step) in http.steps.iter().enumerate() {
            let is_final = i == last;

            if !step.result_captures.is_empty() {
                if !is_final {
                    return Err(format!(
                        "{ctx}: non-final step `{}` declares result_captures; only the terminal \
                         result can project prior captures",
                        step.id
                    ));
                }
                if CatalogClass::from_action(&self.action) != CatalogClass::Setup {
                    return Err(format!(
                        "{ctx}: step `{}` declares result_captures outside a fixture_* setup \
                         action",
                        step.id
                    ));
                }
                if step.result_captures.len() > MAX_KEEP {
                    return Err(format!(
                        "{ctx}: step `{}` result_captures has {} entries, over the cap of {MAX_KEEP}",
                        step.id,
                        step.result_captures.len()
                    ));
                }
                for (output, capture) in &step.result_captures {
                    if !is_ident(output) || !is_ident(capture) {
                        return Err(format!(
                            "{ctx}: step `{}` result_captures `{output}: {capture}` must use \
                             lowercase identifiers",
                            step.id
                        ));
                    }
                    if vendored_secret_field_names().contains(output.as_str()) {
                        return Err(format!(
                            "{ctx}: step `{}` result_captures output `{output}` names a secret field",
                            step.id
                        ));
                    }
                    if !captures_before[i].contains(capture) {
                        return Err(format!(
                            "{ctx}: step `{}` result_captures references `{capture}`, which is not \
                             produced by a prior step",
                            step.id
                        ));
                    }
                    if let Some(pointer) = http.steps[..i]
                        .iter()
                        .find_map(|prior| prior.capture.get(capture))
                    {
                        for segment in pointer.trim_start_matches("$.").split('.') {
                            if vendored_secret_field_names().contains(segment) {
                                return Err(format!(
                                    "{ctx}: step `{}` result_captures source `{capture}` captures \
                                     secret field `{segment}`",
                                    step.id
                                ));
                            }
                        }
                    }
                }
            }

            if !matches!(
                step.method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
            ) {
                return Err(format!(
                    "{ctx}: step `{}` uses method `{}`; allowed: GET, POST, PUT, PATCH, DELETE",
                    step.id, step.method
                ));
            }

            // ---- the frozen-query rule + GraphQL step extensions ----
            // (a) STRUCTURAL: no step body may carry a top-level `query` key — with or without
            // `graphql_query`. The GraphQL document can only ever be the frozen literal, so agent
            // text can never become mutation text (custody tier 3 would collapse in one field).
            if let Some(Value::Object(m)) = &step.body {
                if m.contains_key("query") {
                    return Err(format!(
                        "{ctx}: step `{}` body carries a top-level `query` key; the GraphQL \
                         document must be the frozen `graphql_query` literal, never a body value \
                         (the frozen-query rule)",
                        step.id
                    ));
                }
            }
            if let Some(gq) = &step.graphql_query {
                if step.body_encoding != BodyEncoding::Json {
                    return Err(format!(
                        "{ctx}: step `{}` combines graphql_query with form body encoding; GraphQL \
                         requests are JSON only",
                        step.id
                    ));
                }
                // The literal is NEVER placeholder-scanned: its braces are literal GraphQL text.
                // It must be a bounded, non-empty POST-step constant.
                if gq.trim().is_empty() {
                    return Err(format!("{ctx}: step `{}` graphql_query is empty", step.id));
                }
                if gq.len() > MAX_GRAPHQL_QUERY_LEN {
                    return Err(format!(
                        "{ctx}: step `{}` graphql_query is {} bytes, over the cap of {MAX_GRAPHQL_QUERY_LEN}",
                        step.id,
                        gq.len()
                    ));
                }
                if graphql_operation(gq).is_none() {
                    return Err(format!(
                        "{ctx}: step `{}` graphql_query must contain exactly one explicit, balanced \
                         `query` or `mutation` operation; shorthand, multi-operation, fragment, \
                         comment, string-literal, and subscription documents are not supported",
                        step.id
                    ));
                }
                if let Some(body) = &step.body {
                    let Some(object) = body.as_object() else {
                        return Err(format!(
                            "{ctx}: step `{}` graphql_query body must be an object containing only \
                             `variables`",
                            step.id
                        ));
                    };
                    if object.keys().any(|key| key != "variables") {
                        return Err(format!(
                            "{ctx}: step `{}` graphql_query body may contain only `variables`; \
                             operationName and other execution selectors are forbidden",
                            step.id
                        ));
                    }
                }
                if step.method != "POST" {
                    return Err(format!(
                        "{ctx}: step `{}` declares graphql_query but its method is `{}`; a GraphQL \
                         document rides only a POST",
                        step.id, step.method
                    ));
                }
                // Every GraphQL step MUST declare its success predicate. Without a
                // non-empty `require`, success would be inferred from absence-of-errors alone — a
                // present-but-malformed `errors` shape (or a body that simply lacks the effect)
                // could render an ambiguous 200 as success on a future verb. Refused at load.
                if step.require.is_empty() {
                    return Err(format!(
                        "{ctx}: step `{}` declares graphql_query with no `require`; a GraphQL step \
                         must declare non-empty required result paths (the success predicate) — \
                         success is never inferred from the absence of errors",
                        step.id
                    ));
                }
            } else {
                // `require` is legal on a REST step too — bare dotted proof paths that
                // must resolve non-null on a success body, so a create's stable ID (issue number,
                // commit OID) can never silently become JSON null.
            }
            if step.require.len() > MAX_KEEP {
                return Err(format!(
                    "{ctx}: step `{}` require has {} entries, over the cap of {MAX_KEEP}",
                    step.id,
                    step.require.len()
                ));
            }
            {
                let own_secrets = self.secret_field_names();
                for r in &step.require {
                    if !is_dotted_path(r) {
                        return Err(format!(
                            "{ctx}: step `{}` require entry `{r}` is not a dotted path of identifiers",
                            step.id
                        ));
                    }
                    for seg in r.split('.') {
                        if own_secrets.iter().any(|s| s == seg)
                            || vendored_secret_field_names().contains(seg)
                        {
                            return Err(format!(
                                "{ctx}: require entry `{r}` names a secret field `{seg}`"
                            ));
                        }
                    }
                }
            }
            if let Some(poll) = &step.poll {
                let capture_bound = step.query.values().any(|value| {
                    parse_placeholders(value).is_ok_and(|placeholders| {
                        placeholders
                            .iter()
                            .any(|placeholder| all_captures.contains(&placeholder.name))
                    })
                });
                if CatalogClass::from_action(&self.action) != CatalogClass::Setup
                    || !is_final
                    || step.method != "GET"
                    || step.graphql_query.is_some()
                    || !step.expect_eq.is_empty()
                    || !capture_bound
                {
                    return Err(format!(
                        "{ctx}: step `{}` poll is legal only on a setup action's final \
                         capture-keyed GET reconciliation read",
                        step.id
                    ));
                }
                if !(2..=MAX_POLL_ATTEMPTS).contains(&poll.attempts) {
                    return Err(format!(
                        "{ctx}: step `{}` poll attempts {} is outside 2..={MAX_POLL_ATTEMPTS}",
                        step.id, poll.attempts
                    ));
                }
                if poll.delay_ms == 0 || poll.delay_ms > MAX_POLL_DELAY_MS {
                    return Err(format!(
                        "{ctx}: step `{}` poll delay_ms {} is outside 1..={MAX_POLL_DELAY_MS}",
                        step.id, poll.delay_ms
                    ));
                }
                if poll.until_nonempty.is_empty() || poll.until_nonempty.len() > MAX_KEEP {
                    return Err(format!(
                        "{ctx}: step `{}` poll until_nonempty must list 1..={MAX_KEEP} paths",
                        step.id
                    ));
                }
                let own_secrets = self.secret_field_names();
                for path in &poll.until_nonempty {
                    if !is_dotted_path(path)
                        || !step.require.iter().any(|required| required == path)
                    {
                        return Err(format!(
                            "{ctx}: step `{}` poll path `{path}` must be a required dotted path",
                            step.id
                        ));
                    }
                    for segment in path.split('.') {
                        if own_secrets.iter().any(|secret| secret == segment)
                            || vendored_secret_field_names().contains(segment)
                        {
                            return Err(format!(
                                "{ctx}: step `{}` poll path `{path}` names secret field `{segment}`",
                                step.id
                            ));
                        }
                    }
                }
            }
            // ---- rule 12b: success_statuses are a closed set of 2xx-or-3xx codes ----
            //
            // 3xx is admissible only because it is DECLARED. A redirect a template did not name is
            // still a failure, so the widening cannot leak into any existing verb; and the engine
            // still never follows one, so declaring it says "the redirect is this step's answer"
            // (the minted-URL shape: a credentialed GET whose 302 `Location` IS the capability),
            // never "chase it". 4xx/5xx remain unpinnable — a rejection is not a success.
            if step.success_statuses.len() > MAX_KEEP {
                return Err(format!(
                    "{ctx}: step `{}` success_statuses has {} entries, over the cap of {MAX_KEEP}",
                    step.id,
                    step.success_statuses.len()
                ));
            }
            for code in &step.success_statuses {
                if !(200..=399).contains(code) {
                    return Err(format!(
                        "{ctx}: step `{}` success_statuses code {code} is outside 2xx/3xx; only a \
                         success or a declared redirect can be a pinned success",
                        step.id
                    ));
                }
            }

            // ---- rule 12c: retain_headers name lowercase HTTP header tokens ----
            //
            // The value lands in the BROKER-AUTHORED envelope keyed by this exact name, so the name
            // is normalized here rather than at read time: one spelling, one envelope key, and no
            // way for two declarations to collide into one slot.
            if step.retain_headers.len() > MAX_KEEP {
                return Err(format!(
                    "{ctx}: step `{}` retain_headers has {} entries, over the cap of {MAX_KEEP}",
                    step.id,
                    step.retain_headers.len()
                ));
            }
            for (index, header) in step.retain_headers.iter().enumerate() {
                if header.is_empty()
                    || !header
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                {
                    return Err(format!(
                        "{ctx}: step `{}` retain_headers entry `{header}` must be a lowercase HTTP \
                         header token (a-z, 0-9, `-`)",
                        step.id
                    ));
                }
                if step.retain_headers[..index].contains(header) {
                    return Err(format!(
                        "{ctx}: step `{}` retain_headers names `{header}` twice",
                        step.id
                    ));
                }
            }

            // ---- rule 9: path ----
            if !step.path.starts_with('/') {
                return Err(format!(
                    "{ctx}: step `{}` path `{}` must start with `/`",
                    step.id, step.path
                ));
            }
            if step.path.contains('?')
                || step.path.contains('#')
                || step.path.chars().any(char::is_whitespace)
            {
                return Err(format!(
                    "{ctx}: step `{}` path `{}` must not contain `?`, `#`, or whitespace",
                    step.id, step.path
                ));
            }
            let path_phs = parse_placeholders(&step.path)
                .map_err(|m| format!("{ctx}: step `{}` path {m}", step.id))?;
            for ph in &path_phs {
                if is_reserved(&ph.name) {
                    return Err(format!(
                        "{ctx}: step `{}` path references reserved name `{}`",
                        step.id, ph.name
                    ));
                }
                if ph.optional || ph.transform.is_some() {
                    return Err(format!(
                        "{ctx}: step `{}` path placeholder `{}` may not be optional or transformed",
                        step.id, ph.name
                    ));
                }
                if all_captures.contains(&ph.name) {
                    return Err(format!(
                        "{ctx}: step `{}` path placeholder `{}` names a capture; response data must \
                         never steer the URL path",
                        step.id, ph.name
                    ));
                }
                let Some(decl) = self.field(&ph.name) else {
                    return Err(format!(
                        "{ctx}: step `{}` path placeholder `{}` names neither a declared field nor a \
                         capture",
                        step.id, ph.name
                    ));
                };
                if decl.class != TemplateClass::Identity
                    || !decl.required
                    || decl.ty != TemplateType::Str
                {
                    return Err(format!(
                        "{ctx}: step `{}` path placeholder `{}` must be a required Str Identity field",
                        step.id, ph.name
                    ));
                }
                // A path placeholder is executed URL authority; it MUST be a pinnable
                // execution target, or `/repos/{owner}/{name}/...` with `execution_targets: [owner]`
                // would leave `name` as URL authority no allow rule has to pin.
                if !self.execution_targets.iter().any(|t| t == &ph.name) {
                    return Err(format!(
                        "{ctx}: step `{}` path placeholder `{}` is not listed in execution_targets \
                         (unpinnable URL authority)",
                        step.id, ph.name
                    ));
                }
                used_fields.insert(ph.name.clone());
            }

            // ---- rule 10: query ----
            for (qk, qv) in &step.query {
                if qk.contains('{') || qk.contains('}') {
                    return Err(format!(
                        "{ctx}: step `{}` query key `{qk}` must be a literal (no placeholder)",
                        step.id
                    ));
                }
                let phs = parse_placeholders(qv)
                    .map_err(|m| format!("{ctx}: step `{}` query `{qk}` value {m}", step.id))?;
                for ph in &phs {
                    if is_reserved(&ph.name) {
                        return Err(format!(
                            "{ctx}: step `{}` query references reserved name `{}`",
                            step.id, ph.name
                        ));
                    }
                    if let Some(transform) = &ph.transform {
                        if !matches!(transform, Transform::QueryLiteral)
                            || self.scope != Some(ScopeMode::Account)
                        {
                            return Err(format!(
                                "{ctx}: step `{}` query placeholder `{}` may use only `query_literal` \
                                 and only on a `scope: account` template",
                                step.id, ph.name
                            ));
                        }
                    }
                    if ph.optional && !ph.whole {
                        return Err(format!(
                            "{ctx}: step `{}` optional query placeholder `{}` must be the whole value",
                            step.id, ph.name
                        ));
                    }
                    // A query param is authority-bearing (it can steer the executed
                    // target). A capture in a query would normally let provider RESPONSE data steer
                    // a later request. The sole exception mirrors rule 13d: a setup action's final
                    // read may reconcile the child from its one prior mutation. No later effect can
                    // consume that provider-selected value.
                    if all_captures.contains(&ph.name) {
                        let prior_mutations: Vec<_> = http.steps[..i]
                            .iter()
                            .filter(|prior| !is_verification_read(prior))
                            .collect();
                        let terminal_setup_reconciliation = CatalogClass::from_action(&self.action)
                            == CatalogClass::Setup
                            && is_final
                            && is_verification_read(step)
                            && prior_mutations.len() == 1
                            && prior_mutations[0].capture.contains_key(&ph.name);
                        if terminal_setup_reconciliation {
                            continue;
                        }
                        return Err(format!(
                            "{ctx}: step `{}` query placeholder `{}` names a capture; provider \
                             response data must never steer a query",
                            step.id, ph.name
                        ));
                    }
                    let Some(decl) = self.field(&ph.name) else {
                        return Err(format!(
                            "{ctx}: step `{}` query placeholder `{}` resolves to neither a declared \
                             field nor a capture",
                            step.id, ph.name
                        ));
                    };
                    if matches!(ph.transform, Some(Transform::QueryLiteral)) {
                        if decl.ty != TemplateType::Str
                            || decl.class != TemplateClass::ReadFilter
                            || decl.binding != TemplateBinding::Unbound
                        {
                            return Err(format!(
                                "{ctx}: step `{}` query-literal placeholder `{}` must be a \
                                 Str ReadFilter with unbound binding",
                                step.id, ph.name
                            ));
                        }
                        used_fields.insert(ph.name.clone());
                        continue;
                    }
                    // On a `scope: account` template a plain ReadFilter placeholder is a legal
                    // query value (the account validator restricts fields to ReadFilter and forces
                    // quoted `query_literal` on any EMBEDDED placeholder, so a plain one here is a
                    // whole-value filter with no DSL to inject into).
                    if self.scope == Some(ScopeMode::Account) {
                        if decl.ty != TemplateType::Str
                            || decl.class != TemplateClass::ReadFilter
                            || decl.binding != TemplateBinding::Unbound
                        {
                            return Err(format!(
                                "{ctx}: step `{}` query placeholder `{}` on a scoped template must \
                                 be a Str ReadFilter with unbound binding",
                                step.id, ph.name
                            ));
                        }
                        used_fields.insert(ph.name.clone());
                        continue;
                    }
                    // v1: elsewhere a query placeholder must be an exactly-pinned Identity/SideEffect
                    // field an allow anchors (an execution target); FreePayload/Secret are refused.
                    if decl.binding != TemplateBinding::ExactResourcePin
                        || !matches!(
                            decl.class,
                            TemplateClass::Identity | TemplateClass::SideEffect
                        )
                    {
                        return Err(format!(
                            "{ctx}: step `{}` query placeholder `{}` must be an exact-pinned Identity \
                             or SideEffect field (a query is authority-bearing)",
                            step.id, ph.name
                        ));
                    }
                    if !self.execution_targets.iter().any(|t| t == &ph.name) {
                        return Err(format!(
                            "{ctx}: step `{}` query placeholder `{}` is not listed in \
                             execution_targets; a query param could steer the executed target \
                             outside the allow scope",
                            step.id, ph.name
                        ));
                    }
                    used_fields.insert(ph.name.clone());
                }
            }

            // ---- rule 11: body ----
            if step.body_encoding == BodyEncoding::Form && step.body.is_none() {
                return Err(format!(
                    "{ctx}: step `{}` selects form body encoding without a body",
                    step.id
                ));
            }
            if let Some(body) = &step.body {
                self.check_body_value(
                    ctx,
                    &step.id,
                    &captures_before[i],
                    &all_captures,
                    &mut used_fields,
                    body,
                )?;
            }

            // ---- rule 12: optional_ok ----
            if is_final && !step.optional_ok.is_empty() {
                return Err(format!(
                    "{ctx}: step `{}` (final) sets optional_ok; only a non-final step may tolerate a \
                     status",
                    step.id
                ));
            }
            for code in &step.optional_ok {
                if !(400..=499).contains(code) {
                    return Err(format!(
                        "{ctx}: step `{}` optional_ok code {code} is outside 400..=499 (a 5xx is never \
                         tolerable)",
                        step.id
                    ));
                }
            }

            // ---- rule 13b: expect_eq frozen-resource comparison ----
            // A GET or frozen GraphQL query step may assert that a response path equals a frozen
            // identity, failing closed on drift; a final step may instead prove a postcondition.
            // Ordinary fields must be required, exact-pinned Str Identity execution targets. Money's
            // final response is the narrow typed exception: its exact mapping comes from compiled code.
            if !step.expect_eq.is_empty() {
                let money_postcondition = self.money.is_some() && is_final;
                if !is_final && !is_verification_read(step) {
                    return Err(format!(
                        "{ctx}: non-final step `{}` declares expect_eq without a read operation; a \
                         precondition assertion rides only a GET or frozen GraphQL query, never a mutation",
                        step.id
                    ));
                }
                // ---- rule 13c: expect_eq is incompatible with optional_ok ----
                // A tolerated non-2xx would `continue` PAST the head-SHA comparison (it runs only on
                // a 2xx) and then fire the mutating step — reopening the hollow-pin class from
                // the other side (the approved identity is "used" by validation yet never executed).
                // Forbid the combo so the guard can never be skipped; the executor also treats any
                // non-2xx on an expect_eq step as terminal (defense in depth).
                if !step.optional_ok.is_empty() {
                    return Err(format!(
                        "{ctx}: step `{}` declares BOTH expect_eq and optional_ok; a tolerated non-2xx \
                         would skip the verification guard before the mutation — the two are mutually \
                         exclusive",
                        step.id
                    ));
                }
                if step.expect_eq.len() > MAX_KEEP {
                    return Err(format!(
                        "{ctx}: step `{}` expect_eq has {} entries, over the cap of {MAX_KEEP}",
                        step.id,
                        step.expect_eq.len()
                    ));
                }
                for (resp_path, field_name) in &step.expect_eq {
                    if !is_dotted_path(resp_path) {
                        return Err(format!(
                            "{ctx}: step `{}` expect_eq key `{resp_path}` is not a dotted path of \
                             identifiers",
                            step.id
                        ));
                    }
                    let Some(decl) = self.field(field_name) else {
                        return Err(format!(
                            "{ctx}: step `{}` expect_eq references `{field_name}`, which is not a \
                             declared field",
                            step.id
                        ));
                    };
                    if !money_postcondition
                        && (decl.class != TemplateClass::Identity
                            || decl.binding != TemplateBinding::ExactResourcePin
                            || !decl.required
                            || decl.ty != TemplateType::Str)
                    {
                        return Err(format!(
                            "{ctx}: step `{}` expect_eq field `{field_name}` must be a required, \
                             exact-pinned Str Identity (the verified value must be one an allow pins)",
                            step.id
                        ));
                    }
                    if !money_postcondition
                        && !self.execution_targets.iter().any(|t| t == field_name)
                    {
                        return Err(format!(
                            "{ctx}: step `{}` expect_eq field `{field_name}` is not an execution \
                             target; a verified identity must be a pinnable target",
                            step.id
                        ));
                    }
                    // A money response equality proves what happened; it must not make a field look
                    // consumed on the request wire. Money fields still have to reach the mutation
                    // through an actual path/query/body placeholder.
                    if !money_postcondition {
                        used_fields.insert(field_name.clone());
                    }
                }
            }

            // ---- rule 13e: frozen-literal response assertions ----
            if !step.expect_literal.is_empty() {
                if !is_final && !is_verification_read(step) {
                    return Err(format!(
                        "{ctx}: non-final step `{}` declares expect_literal without a verification \
                         read; a precondition assertion rides only a GET or frozen GraphQL query",
                        step.id
                    ));
                }
                if !is_final && !step.optional_ok.is_empty() {
                    return Err(format!(
                        "{ctx}: non-final step `{}` declares BOTH expect_literal and optional_ok; a \
                         tolerated non-2xx would skip the literal precondition before the mutation",
                        step.id
                    ));
                }
                if step.expect_literal.len() > MAX_KEEP {
                    return Err(format!(
                        "{ctx}: step `{}` expect_literal has {} entries, over the cap of {MAX_KEEP}",
                        step.id,
                        step.expect_literal.len()
                    ));
                }
                let own_secrets = self.secret_field_names();
                for (resp_path, expected) in &step.expect_literal {
                    if !is_dotted_path(resp_path) {
                        return Err(format!(
                            "{ctx}: step `{}` expect_literal key `{resp_path}` is not a dotted path \
                             of identifiers",
                            step.id
                        ));
                    }
                    let fixed_string_array = expected.as_array().is_some_and(|values| {
                        !values.is_empty()
                            && values.len() <= MAX_KEEP
                            && values.iter().all(|value| {
                                value.as_str().is_some_and(|string| !string.is_empty())
                            })
                            && values
                                .iter()
                                .filter_map(Value::as_str)
                                .collect::<HashSet<_>>()
                                .len()
                                == values.len()
                    });
                    if !matches!(
                        expected,
                        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
                    ) && !fixed_string_array
                    {
                        return Err(format!(
                            "{ctx}: step `{}` expect_literal value for `{resp_path}` must be a \
                             scalar or null literal, or a nonempty unique string array of at most \
                             {MAX_KEEP} entries",
                            step.id
                        ));
                    }
                    for seg in resp_path.split('.') {
                        if own_secrets.iter().any(|s| s == seg)
                            || vendored_secret_field_names().contains(seg)
                        {
                            return Err(format!(
                                "{ctx}: expect_literal entry `{resp_path}` names a secret field `{seg}`"
                            ));
                        }
                    }
                }
            }

            // ---- rule 14: the response contract ----
            // VERBATIM. A template declares no return shape at all: the provider's body is what the
            // agent receives and what the artifact stores, on success and on failure alike, so
            // there is nothing here to validate about the returned fields. `retention` (validated
            // with the rest of the step above) caps durable STORAGE and is unaffected.
        }

        // ---- rule 15: placeholder/consumes honesty ----
        for c in consumes {
            if !used_fields.contains(c.as_str()) {
                return Err(format!(
                    "{ctx}: consumes lists `{c}` but no step placeholder references it (dishonest \
                     consumes)"
                ));
            }
        }
        for u in &used_fields {
            if !consumes.iter().any(|c| c == u) {
                return Err(format!(
                    "{ctx}: field `{u}` is referenced by a placeholder but is not listed in consumes"
                ));
            }
        }
        Ok(())
    }

    /// Walk a JSON body: object keys must be literal; string values may hold placeholders resolving to
    /// a declared field or a strictly-earlier capture. Optional and transformed placeholders must be
    /// the WHOLE string; transforms apply only to Str-typed declared fields (never captures). Secret
    /// fields MAY ride in the body (that is where an agent-supplied secret is carried).
    #[allow(clippy::too_many_arguments)]
    fn check_body_value(
        &self,
        ctx: &str,
        step_id: &str,
        captures_before: &HashSet<String>,
        all_captures: &HashSet<String>,
        used_fields: &mut HashSet<String>,
        v: &Value,
    ) -> Result<(), String> {
        match v {
            Value::Object(map) => {
                for (k, val) in map {
                    if k.contains('{') || k.contains('}') {
                        return Err(format!(
                            "{ctx}: step `{step_id}` body object key `{k}` must be a literal (no \
                             placeholder)"
                        ));
                    }
                    self.check_body_value(
                        ctx,
                        step_id,
                        captures_before,
                        all_captures,
                        used_fields,
                        val,
                    )?;
                }
                Ok(())
            }
            Value::Array(arr) => {
                for val in arr {
                    self.check_body_value(
                        ctx,
                        step_id,
                        captures_before,
                        all_captures,
                        used_fields,
                        val,
                    )?;
                }
                Ok(())
            }
            Value::String(s) => {
                let phs = parse_placeholders(s)
                    .map_err(|m| format!("{ctx}: step `{step_id}` body string {m}"))?;
                for ph in &phs {
                    if is_reserved(&ph.name) {
                        return Err(format!(
                            "{ctx}: step `{step_id}` body references reserved name `{}`",
                            ph.name
                        ));
                    }
                    if (ph.optional || ph.transform.is_some()) && !ph.whole {
                        return Err(format!(
                            "{ctx}: step `{step_id}` body placeholder `{}` is optional or transformed \
                             and must be the whole string value",
                            ph.name
                        ));
                    }
                    if let Some(transform) = &ph.transform {
                        let Some(decl) = self.field(&ph.name) else {
                            return Err(format!(
                                "{ctx}: step `{step_id}` body placeholder `{}` applies a transform to a \
                                 non-field (a capture cannot be transformed)",
                                ph.name
                            ));
                        };
                        if matches!(transform, Transform::Negative) {
                            if decl.ty != TemplateType::Int
                                || decl.class != TemplateClass::SideEffect
                                || decl.binding != TemplateBinding::Bounded
                                || !decl.required
                            {
                                return Err(format!(
                                    "{ctx}: step `{step_id}` body placeholder `{}` uses `negative` \
                                     on a field that is not a required bounded integer side_effect",
                                    ph.name
                                ));
                            }
                            used_fields.insert(ph.name.clone());
                            continue;
                        }
                        if matches!(transform, Transform::QueryLiteral) {
                            return Err(format!(
                                "{ctx}: step `{step_id}` body placeholder `{}` uses `query_literal`; \
                                 that transform is legal only in query grammar",
                                ph.name
                            ));
                        }
                        if decl.ty != TemplateType::Str {
                            return Err(format!(
                                "{ctx}: step `{step_id}` body placeholder `{}` transforms a non-Str field",
                                ph.name
                            ));
                        }
                        // `default:` fills an ABSENT optional field with a fixed literal; on a
                        // required field (always present) it would be dead. It never erases a key, so
                        // it needs none of the omit-only pin-coverage constraints below.
                        if matches!(transform, Transform::Default(_)) && decl.required {
                            return Err(format!(
                                "{ctx}: step `{step_id}` body placeholder `{}` uses `default:` on a \
                                 required field; default is legal only on an optional field (a required \
                                 field is always present)",
                                ph.name
                            ));
                        }
                        // `omit:` maps a pinned value to "send no key"; that is only coherent on a
                        // required field (an absent optional value has no wire meaning to compare).
                        if matches!(transform, Transform::Omit(_)) && !decl.required {
                            return Err(format!(
                                "{ctx}: step `{step_id}` body placeholder `{}` uses `omit:` on an \
                                 optional field; omit is legal only on a required field",
                                ph.name
                            ));
                        }
                        // An omitted key is invisible on the wire, so the value deciding the
                        // omission must be one the approver's pin covers — a required,
                        // exact-pinned Identity execution target. Looser placements would let a
                        // template erase an approved field from the request it produces.
                        if matches!(transform, Transform::Omit(_))
                            && !(matches!(decl.class, TemplateClass::Identity)
                                && matches!(decl.binding, TemplateBinding::ExactResourcePin)
                                && self.execution_targets.contains(&ph.name))
                        {
                            return Err(format!(
                                "{ctx}: step `{step_id}` body placeholder `{}` uses `omit:` on a \
                                 field that is not a pinned Identity execution target; omit can \
                                 erase a key from the wire, so it is legal only where policy pins \
                                 the deciding value",
                                ph.name
                            ));
                        }
                        used_fields.insert(ph.name.clone());
                        continue;
                    }
                    if self.field(&ph.name).is_some() {
                        used_fields.insert(ph.name.clone());
                    } else if all_captures.contains(&ph.name) {
                        if !captures_before.contains(&ph.name) {
                            return Err(format!(
                                "{ctx}: step `{step_id}` body placeholder `{}` uses a capture not \
                                 produced by a strictly earlier step",
                                ph.name
                            ));
                        }
                    } else {
                        return Err(format!(
                            "{ctx}: step `{step_id}` body placeholder `{}` resolves to neither a \
                             declared field nor an earlier capture",
                            ph.name
                        ));
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Registry — broker-owned, never process-global
// ---------------------------------------------------------------------------

/// A ratified, validated template with its runtime-derived contract and the content hash of the
/// exact document bytes that were ratified.
pub struct LoadedTemplate {
    pub contract: &'static ActionContract,
    pub template: ActionTemplate,
    pub content_hash: String,
}

/// The ceiling a ratified provider descriptor sets on the templates that may extend it. Membership
/// makes the provider template-extensible (rule 1) AND `requires_anchored_allow`.
#[derive(Debug, Clone)]
pub enum ProviderCeiling {
    /// An egress-pinned HTTP provider — its origin pin lives in the broker's provider map, so here we
    /// need only the fact that it is HTTP (an `http:` template may extend it).
    Http,
    /// Additionally pins a GIT transport origin (`git.origin` in the descriptor), so a `git:`
    /// template may extend it too. A provider without one cannot carry a credential over the git
    /// seam at all.
    HttpAndGit,
}

/// PER-BROKER template state. There is deliberately NO `static`/`OnceLock` backing: one broker's
/// ratified templates must be invisible to another registry instance in the same process (cargo runs
/// many brokers in one process), so an agent can never see authority a different broker was granted.
pub struct TemplateRegistry {
    loaded: RwLock<HashMap<(String, String), &'static LoadedTemplate>>,
    /// The ratified-descriptor providers this registry may extend (rule 1), each with its ceiling. A
    /// template for a provider absent from this map refuses to load — a template can never point a
    /// credential at an origin no descriptor pinned.
    /// Grows when a provider descriptor is ratified live.
    providers: RwLock<HashMap<String, ProviderCeiling>>,
}

impl Default for TemplateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The kernel declaration this template field becomes, minus its name (the caller stamps that on:
/// [`leak_contract`] leaks the real one, the catalog needs none). ONE mapping, so the catalog's
/// published form index is computed from the very `FieldDecl` the evaluator will judge
/// sentences against rather than from a second reading of the same YAML.
fn field_shape(f: &TemplateField) -> FieldDecl {
    FieldDecl {
        name: "",
        ty: f.ty.to_scalar(),
        required: f.required,
        class: f.class.to_field_class(),
        binding: f.binding.to_allow_binding(),
    }
}

/// Derive a `&'static ActionContract` from a validated template. Ratified templates are human-rare
/// and never unloaded in-process, so an O(ratified) intentional leak is acceptable and lets
/// `ActionContract` stay all-`&'static` (no lifetime plumbing through the broker).
fn leak_contract(t: &ActionTemplate) -> &'static ActionContract {
    let schema: Vec<FieldDecl> = t
        .fields
        .iter()
        .map(|f| FieldDecl {
            name: leak_str(&f.name),
            ..field_shape(f)
        })
        .collect();
    let consumes: Vec<&'static str> = t.effective_consumes().iter().map(|c| leak_str(c)).collect();
    let targets: Vec<&'static str> = t.execution_targets.iter().map(|c| leak_str(c)).collect();
    Box::leak(Box::new(ActionContract {
        provider: leak_str(&t.provider),
        action: leak_str(&t.action),
        schema: Box::leak(schema.into_boxed_slice()),
        consumes: Box::leak(consumes.into_boxed_slice()),
        execution_targets: Box::leak(targets.into_boxed_slice()),
        relations: &[],
        open: false,
    }))
}

impl TemplateRegistry {
    /// A registry whose extensible-provider set is the VENDORED (shipped) providers — the default a
    /// bare registry (tests, the non-broker `vendored_registry`) uses. A broker instead builds one
    /// with [`with_ceilings`](Self::with_ceilings) keyed on the descriptors it actually loaded.
    pub fn new() -> Self {
        Self::with_ceilings(crate::provider::vendored_provider_ceilings().clone())
    }

    /// A registry whose extensible providers are exactly `providers`, each as an HTTP
    /// (egress-pinned) ceiling. Fail closed: a template for a provider absent from this set never
    /// loads.
    pub fn with_providers(providers: HashSet<String>) -> Self {
        Self::with_ceilings(
            providers
                .into_iter()
                .map(|n| (n, ProviderCeiling::Http))
                .collect(),
        )
    }

    /// A registry whose extensible providers (and their ceilings) are exactly `providers` — the
    /// broker's ratified descriptors. Fail closed: a template for a provider absent from this map
    /// never loads.
    pub fn with_ceilings(providers: HashMap<String, ProviderCeiling>) -> Self {
        Self {
            loaded: RwLock::new(HashMap::new()),
            providers: RwLock::new(providers),
        }
    }

    /// Whether `p` has a ratified descriptor known to this registry (rule 1 + the view gate's
    /// "could a template ever have existed for this provider" + `requires_anchored_allow`).
    pub fn provider_extensible(&self, p: &str) -> bool {
        self.providers
            .read()
            .expect("template registry lock poisoned")
            .contains_key(p)
    }

    /// Add a newly-ratified descriptor's provider (with its ceiling) to the extensible set (live
    /// provider ratify).
    pub fn add_provider(&self, name: &str, ceiling: ProviderCeiling) {
        self.providers
            .write()
            .expect("template registry lock poisoned")
            .insert(name.to_string(), ceiling);
    }

    /// The propose/preview path: size-cap, parse, validate against THIS registry's provider set. NO
    /// leaking and NO registration — an unratified proposal must never mutate the registry.
    pub fn validate_doc(&self, doc: &str) -> Result<ActionTemplate, String> {
        let providers = self
            .providers
            .read()
            .expect("template registry lock poisoned")
            .clone();
        Self::validate_doc_with(&providers, doc)
    }

    fn validate_doc_with(
        providers: &HashMap<String, ProviderCeiling>,
        doc: &str,
    ) -> Result<ActionTemplate, String> {
        if doc.len() > MAX_DOC_BYTES {
            return Err(format!(
                "action template document is {} bytes, over the {MAX_DOC_BYTES}-byte cap",
                doc.len()
            ));
        }
        let template: ActionTemplate = serde_yaml::from_str(doc)
            .map_err(|e| format!("action template is not valid for the template grammar: {e}"))?;
        template.validate(providers)?;
        Ok(template)
    }

    /// Everything `load` verifies about `doc` against a GIVEN registry snapshot: the full grammar +
    /// built-in shadow refusal ([`validate_doc`]) PLUS the registry-wide secret/keep cross-checks
    /// against the templates already in `map`. Returns the parsed template so `load` need not
    /// re-parse. Never leaks, never inserts. Shared by [`check_load`](Self::check_load) and
    /// [`load`](Self::load) so the two paths' validation can never drift.
    fn validate_for_load(
        providers: &HashMap<String, ProviderCeiling>,
        map: &HashMap<(String, String), &'static LoadedTemplate>,
        doc: &str,
    ) -> Result<ActionTemplate, String> {
        let template = Self::validate_doc_with(providers, doc)?;
        let key = (template.provider.clone(), template.action.clone());
        let ctx = format!("{}.{}", key.0, key.1);

        // (a) a ratified template is single-owner per action; replacing one is an explicit ratify op.
        if map.contains_key(&key) {
            return Err(format!(
                "{ctx}: a template for this action is already loaded; replacing a ratified template \
                 is an explicit ratify-time operation"
            ));
        }

        // No template names a response path to echo — the body is returned as the provider sent
        // it — so there is no name to cross-check against another template's secret-class INPUT
        // field. Per-template secret-input custody (the request-side scrub) is validated by
        // `validate_doc_with` above.
        Ok(template)
    }

    /// A DRY RUN of [`load`](Self::load): run everything `load` validates against the CURRENT registry
    /// state — grammar + built-in shadow refusal AND the registry-wide secret/keep cross-checks — but
    /// NEVER leak and NEVER insert. On the single-threaded broker actor nothing interleaves between
    /// this check and a following `load`, so a check-then-load pair is sound: ratify (and boot
    /// reconcile) pre-verify with this so the final install cannot fail its validation. Fail closed on
    /// any doubt. (The leaked-contract consistency backstop lives in `load`; it is redundant with the
    /// grammar's own consistency check that `validate_doc` runs here, so it never fires for a doc that
    /// passes this dry run.)
    pub fn check_load(&self, doc: &str) -> Result<(), String> {
        let providers = self
            .providers
            .read()
            .expect("template registry lock poisoned")
            .clone();
        let map = self.loaded.read().expect("template registry lock poisoned");
        Self::validate_for_load(&providers, &map, doc)?;
        Ok(())
    }

    /// The ratify path: validate, run registry-wide cross-checks, derive the contract, register it.
    /// Returns the `(provider, action)` key. Fail closed on any doubt. Holds the registry WRITE lock
    /// across the whole check+insert so the primitive is atomic even outside the broker actor.
    pub fn load(&self, doc: &str) -> Result<(String, String), String> {
        let providers = self
            .providers
            .read()
            .expect("template registry lock poisoned")
            .clone();
        let mut map = self
            .loaded
            .write()
            .expect("template registry lock poisoned");
        let template = Self::validate_for_load(&providers, &map, doc)?;
        let key = (template.provider.clone(), template.action.clone());
        let ctx = format!("{}.{}", key.0, key.1);

        let contract = leak_contract(&template);
        // Backstop: the derived contract must pass the same consistency checker (an adapter bug here
        // would be a defect, not a document error — but still fail closed rather than register it).
        contract.validate_consistent().map_err(|e| {
            format!("{ctx}: template produced an inconsistent contract (adapter bug): {e}")
        })?;

        let content_hash = sha256_hex(doc.as_bytes());
        let loaded_template: &'static LoadedTemplate = Box::leak(Box::new(LoadedTemplate {
            contract,
            template,
            content_hash,
        }));
        map.insert(key.clone(), loaded_template);
        Ok(key)
    }

    /// Resolve a contract for `(provider, action)` from this registry's loaded templates. The core
    /// ships zero compiled-in contracts, so this is a plain map lookup — a template action resolves
    /// only through a broker whose registry loaded it, and everything else fails closed.
    pub fn resolve(&self, provider: &str, action: &str) -> Option<&'static ActionContract> {
        self.loaded
            .read()
            .expect("template registry lock poisoned")
            .get(&(provider.to_string(), action.to_string()))
            .map(|lt| lt.contract)
    }

    /// This registry's own loaded template for `(provider, action)`, if any (never a built-in).
    pub fn loaded(&self, provider: &str, action: &str) -> Option<&'static LoadedTemplate> {
        self.loaded
            .read()
            .expect("template registry lock poisoned")
            .get(&(provider.to_string(), action.to_string()))
            .copied()
    }

    pub fn content_hash(&self, provider: &str, action: &str) -> Option<String> {
        self.loaded(provider, action)
            .map(|lt| lt.content_hash.clone())
    }

    /// Every template loaded in THIS registry — the `catalog` verb's live set (all requestable now).
    /// Whether any loaded template declares the SUBPROCESS execution kind. The broker uses this to
    /// decide whether the hermetic git seam must be preflighted at boot: a box that ratified no
    /// `git:` verb owes us no git binary.
    pub fn any_git_template(&self) -> bool {
        self.loaded
            .read()
            .map(|loaded| loaded.values().any(|lt| lt.template.git_spec().is_some()))
            .unwrap_or(false)
    }

    pub fn loaded_entries(&self) -> Vec<&'static LoadedTemplate> {
        self.loaded
            .read()
            .expect("template registry lock poisoned")
            .values()
            .copied()
            .collect()
    }

    /// Whether ANY loaded template declares this bare `action` name (across every provider). Backs
    /// the alias-shadowing check: an alias may not be NAMED like a registered verb.
    pub fn has_action_named(&self, action: &str) -> bool {
        self.loaded
            .read()
            .expect("template registry lock poisoned")
            .keys()
            .any(|(_, a)| a == action)
    }

    /// The content hash a ratify would freeze for `doc` — sha256 of the exact bytes, identical to
    /// what [`TemplateRegistry::load`] stamps. Lets the proposal store record the hash without
    /// loading or registering the document.
    pub fn content_hash_of_doc(doc: &str) -> String {
        sha256_hex(doc.as_bytes())
    }

    /// Registry-wide secret field names: this registry's loaded templates' Secret fields. The core
    /// ships zero compiled-in contracts, so a name is secret here iff a loaded template classifies it
    /// `Secret`.
    pub fn is_secret_field_name(&self, name: &str) -> bool {
        self.loaded
            .read()
            .expect("template registry lock poisoned")
            .values()
            .any(|lt| lt.template.secret_field_names().iter().any(|s| s == name))
    }
}

// ---------------------------------------------------------------------------
// Vendored catalog — the templates shipped inside the binary
// ---------------------------------------------------------------------------

pub use cermet_lang::templates::vendored_response_contract;
/// Every action-template document vendored with the core, one `include_str!` per file in
/// `crates/cermet-core/actions/`. This is the shipped default set: what every broker and the
/// non-broker [`DefaultContractSource`](crate::policy::DefaultContractSource) resolve. Adding a
/// vendored template is a one-line addition here.
pub use cermet_lang::templates::VENDORED_CATALOG;

/// The `catalog` verb's per-verb schema, deduplicated by `(provider, action)`: every template LOADED
/// in `reg` (marked `requestable: true`) UNIONed with the vendored stdlib catalog (a vendored verb
/// not loaded here is `requestable: false` — available to seed/ratify, not live). Sorted by
/// provider then action for a stable listing. A malformed vendored document is a packaging bug that
/// the `vendored_catalog_all_load` test already turns into a build failure, so the deserialize here
/// is infallible in practice; it falls back to skipping a doc rather than failing the whole catalog.
pub fn catalog_of(reg: &TemplateRegistry, temporal_clauses: bool) -> Vec<CatalogEntry> {
    let mut out: BTreeMap<(String, String), CatalogEntry> = BTreeMap::new();
    for lt in reg.loaded_entries() {
        let entry = lt.template.catalog_entry(true, temporal_clauses);
        out.insert((entry.provider.clone(), entry.action.clone()), entry);
    }
    for doc in VENDORED_CATALOG {
        if let Ok(t) = serde_yaml::from_str::<ActionTemplate>(doc) {
            let key = (t.provider().to_string(), t.action().to_string());
            out.entry(key)
                .or_insert_with(|| t.catalog_entry(false, temporal_clauses));
        }
    }
    out.into_values().collect()
}

/// The Secret field names any SHIPPED template declares — the process-global secret-name floor a
/// template's `keep` may never return, restoring (post-built-in-retirement) the cross-provider
/// name-ban the compiled-in contracts used to provide. Derived by pure deserialization (never
/// validation or the full registry), so it is safe to consult from inside the validator without
/// re-entering [`vendored_registry`]'s init.
fn vendored_secret_field_names() -> &'static HashSet<String> {
    static NAMES: OnceLock<HashSet<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        let mut set = HashSet::new();
        for doc in VENDORED_CATALOG {
            let t: ActionTemplate = serde_yaml::from_str(doc)
                .expect("vendored action-template catalog must deserialize (packaging bug)");
            for f in &t.fields {
                if f.class == TemplateClass::Secret {
                    set.insert(f.name.clone());
                }
            }
        }
        set
    })
}

/// A process-global registry pre-loaded with [`VENDORED_CATALOG`], backing the non-broker
/// `DefaultContractSource` so policy validation and secret-field classification resolve vendored
/// template actions even with no broker in hand. Built-ins still resolve FIRST (via
/// [`TemplateRegistry::resolve`]), so this is strictly additive. A malformed vendored document is a
/// packaging bug, not a runtime condition: it panics loudly on first use (and the
/// `vendored_catalog_all_load` test makes that a build-time failure).
#[cfg(test)]
pub(crate) fn vendored_registry() -> &'static TemplateRegistry {
    static REG: OnceLock<TemplateRegistry> = OnceLock::new();
    REG.get_or_init(|| {
        let reg = TemplateRegistry::new();
        for doc in VENDORED_CATALOG {
            reg.load(doc)
                .expect("vendored action-template catalog must load (packaging bug)");
        }
        reg
    })
}

// ---------------------------------------------------------------------------
// Sentence-authoring contract bridge
// ---------------------------------------------------------------------------

/// A [`ContractSource`](crate::policy::ContractSource) backed by one broker's template registry.
#[derive(Clone)]
pub struct TemplateContractSource(pub Arc<TemplateRegistry>);

impl crate::policy::ContractSource for TemplateContractSource {
    fn contract(&self, provider: &str, action: &str) -> Option<&'static ActionContract> {
        self.0.resolve(provider, action)
    }
}

#[cfg(test)]
mod tests;
