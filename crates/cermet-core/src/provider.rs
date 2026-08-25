//! Provider adapters.

pub(crate) mod stripe_evidence;
mod stripe_preconditions;
mod vercel_canonicalize;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, USER_AGENT};
use reqwest::Method;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::canonicalize::CanonicalizationProfile;
use crate::contract::{ActionContract, CanonicalResource, Scalar};
use crate::error::{Error, Result};
use crate::evidence::{EvidenceFailure, EvidenceFailureClass, EvidenceProfile, ResolvedEvidence};
use crate::mutation_success::EffectProof;
use crate::templates::{
    is_verification_read, BodyEncoding, LoadedTemplate, PathMode, RetentionMode, Segment,
    TemplateRegistry, Transform,
};
use crate::types::{EffectFailureClass, FailureSignal};

/// The execution discipline of ONE call, derived by the BROKER from the verb's ratified,
/// hash-bound action template (never from the adapter's opinion of itself) and passed down as
/// data. There is no second execution method and no verb class: an adapter is told what this
/// effect needs, and a `Default` discipline is the plain hop every read and most writes take.
///
/// The two bits are independent properties, not a package deal — a verb could one day mint a key
/// without a compiled proof, or prove without one — which is exactly why they cross the seam as two
/// fields rather than one "is this scary" bit.
/// No `Debug`: the persisted idempotency key is a broker-private replay key, and a derive is the
/// cheapest way for it to reach a log line or a panic message by accident (T2).
#[derive(Clone, Copy, Default)]
pub struct ExecutionDiscipline<'a> {
    /// The broker-minted, DURABLY PERSISTED at-most-once key for this effect, minted with the grant
    /// before the first attempt and reused verbatim by a referenced retry. `None` when the verb's
    /// template declares no key discipline (every verb but the seven Stripe effects today), and for
    /// a provider with no native idempotency channel it would stay `None` even then.
    pub idempotency_key: Option<&'a str>,
    /// Whether the response must be PROVED against the verb's compiled success contract, yielding
    /// the [`EffectProof`] observation the broker records beside it. `false` believes the transport
    /// bit, which is the right discipline for an effect nothing can reconcile after the fact.
    pub prove_effect: bool,
}

pub struct ProviderCall<'a> {
    pub action: &'a str,
    /// What discipline this hop runs under — see [`ExecutionDiscipline`].
    pub discipline: ExecutionDiscipline<'a>,
    /// The broker-minted request id this execution belongs to. Used ONLY by the subprocess
    /// execution kind, which keys its per-request quarantine bare repo on it; the HTTP kind ignores
    /// it. It carries no authority — the grant does.
    pub request_id: &'a str,
    /// Plaintext credential used to authenticate the call; never echoed back.
    pub token: &'a str,
    /// The frozen, policy-checked resource — the only execute-time data channel.
    pub resource: &'a CanonicalResource,
    /// the daemon-held mirror this hop carries FROM. Present only for the git
    /// execution kind, whose effect is `mirror → upstream`; `None` for every HTTP verb. It is
    /// daemon-owned state, never anything the agent supplies — the agent's bytes reached the mirror
    /// through `git receive-pack`, and the mirror path is derived from the attested stream's
    /// validated repo identity.
    pub git_mirror: Option<&'a std::path::Path>,
}

pub struct ProviderResponse {
    pub ok: bool,
    /// The broker redacts this before it leaves the core.
    pub result: Value,
    /// BROKER-AUTHORED metadata about this response, kept STRICTLY OUTSIDE `result`.
    ///
    /// The response contract is verbatim: a template never edits the provider's JSON. Some things
    /// nevertheless need to reach the agent alongside it — a GraphQL step's classified
    /// `outcome`/`conflict` verdict, and a step's declared retained headers. Injecting either into
    /// the body made receipt result != stored artifact != teed body, which is the exact divergence
    /// the wire tee exists to catch. They ride here instead, the same way the money evaluation
    /// rides alongside its response rather than inside it.
    ///
    /// Empty for the overwhelming majority of verbs, and omitted from the wire when empty.
    pub envelope: serde_json::Map<String, Value>,
    /// The FULL provider response body, normally retained as a content-addressed artifact (the
    /// `keep` allowlist above is a lens over `result`, not a wall). A template may explicitly set
    /// `retention: none` when the projected result is the complete response surface. Built only on
    /// the terminal step of an HTTP verb, with every wire representation of agent-submitted secrets scrubbed
    /// ([`SecretScrub`]). `None` for a response with no retainable body (an intermediate
    /// capture step, a test double, or a fail-closed retention skip). The broker additionally
    /// byte-redacts the vault credential out of these bytes before storing.
    pub retained: Option<RetainedBody>,
    /// WHY this response is a failure, typed HERE because this is where the evidence is.
    /// `None` on every success, and on a failure whose cause this seam cannot type — the recording
    /// seam then lands on the residual rather than a guess. It is not part of the response contract:
    /// it never enters `result`, so the body an agent reads and the artifact stored beside it are
    /// byte-identical to what the provider sent.
    pub failure_class: Option<crate::types::EffectFailureClass>,
    /// What the verb's compiled success contract OBSERVED of this response — `Some` exactly when the
    /// call ran under [`ExecutionDiscipline::prove_effect`], `None` for every plain hop. The broker
    /// records the observation and derives its own verdicts from it; the adapter states no verdict
    /// of its own.
    pub proof: Option<EffectProof>,
}

impl ProviderResponse {
    /// Attach a proving verb's observation and normalize what that discipline implies (formerly
    /// `MoneyProviderResponse::into_parts`).
    ///
    /// The response rides ALONGSIDE its observation instead of being replaced by it. A proved
    /// success returns the verified body — the created object's own provider id (`re_...`,
    /// `pi_...`) reconciles to the dashboard without a follow-up search — and anything else
    /// returns what the provider actually sent. The outward `ok` bit is set from the PROOF, never
    /// from the transport bit, so a 2xx whose contract did not hold is not a success.
    ///
    /// The RETENTION cap of a proving verb is enforced here, at the custody boundary, rather than
    /// trusted to each template's `retention: none` declaration — `validate_money_terminal`
    /// (mint.rs) treats such a terminal carrying artifact evidence as structurally impossible, so
    /// the writer and the verifier have to agree by construction. A cap on durable STORAGE is not a
    /// projection: the response body above is untouched.
    pub(crate) fn proved(mut self, proof: EffectProof) -> Self {
        self.ok = proof == EffectProof::Proved;
        self.retained = None;
        self.proof = Some(proof);
        self
    }
}

/// The full response body kept for the artifact store, plus its pre-scrub true byte size (the honest
/// "total" the kept-vs-total counter measures against). `bytes` has agent-submitted secret values
/// scrubbed; `total_bytes` is the size BEFORE scrubbing so the wire-economy number reflects the real
/// body the provider sent.
#[derive(Debug, Clone)]
pub struct RetainedBody {
    pub bytes: Vec<u8>,
    pub total_bytes: u64,
}

/// Every wire representation of the agent-submitted `secret`-class fields, collected for scrubbing
/// out of the retained body. Seeded with each present secret field's raw scalar form (plus
/// its JSON-escaped variant — the retained body is serialized JSON); the body renderer ADDS the exact
/// transformed forms it emits (base64, capture-sourced values) as it renders them, so whatever byte
/// shape a provider could echo back is in the set. This is a DIFFERENT set from the vault credential
/// (redaction.rs; the broker applies that byte-level pass at store time). If a secret's rendered
/// representation ever cannot be captured, `uncapturable` trips and the body is NOT retained at all —
/// fail closed: skipping retention is safe, leaking is not.
struct SecretScrub {
    fields: Vec<&'static str>,
    /// `(field, representation bytes)` — each replaced with `[scrubbed:<field>]` in the retained bytes.
    reps: Vec<(&'static str, Vec<u8>)>,
    uncapturable: bool,
}

impl SecretScrub {
    fn new(contract: &'static ActionContract, resource: &CanonicalResource) -> Self {
        let fields: Vec<&'static str> = contract
            .schema
            .iter()
            .filter(|f| f.class == crate::contract::FieldClass::Secret)
            .map(|f| f.name)
            .collect();
        let mut scrub = Self {
            fields,
            reps: Vec::new(),
            uncapturable: false,
        };
        for f in scrub.fields.clone() {
            if let Some(sc) = resource.scalar(f) {
                let rep = scalar_query_str(sc);
                scrub.add(f, &rep);
            }
        }
        scrub
    }

    fn is_secret(&self, name: &str) -> bool {
        self.fields.contains(&name)
    }

    /// Record one rendered representation of a secret field, plus its JSON-escaped variant (how it
    /// appears inside serialized JSON bytes). The escaped form goes first: it is the more specific
    /// needle.
    fn add(&mut self, name: &str, rep: &str) {
        let Some(field) = self.fields.iter().copied().find(|f| *f == name) else {
            return;
        };
        if rep.is_empty() {
            return;
        }
        let escaped = crate::redaction::json_escaped(rep);
        if escaped != rep {
            self.reps.push((field, escaped.into_bytes()));
        }
        self.reps.push((field, rep.as_bytes().to_vec()));
    }
}

/// Does this step retain its response body as an artifact? The template's declared `retention` is
/// the only input: a cap on durable STORAGE, never on what the response says.
fn step_retains(retention: RetentionMode) -> bool {
    retention == RetentionMode::Full
}

/// Retain a response body for the artifact store: serialize it, record the true (pre-scrub) size,
/// scrub every collected secret representation. `None` — retention skipped, fail closed — when a
/// secret representation was uncapturable or the body does not serialize.
fn retain_body(body: &Value, scrub: &SecretScrub) -> Option<RetainedBody> {
    if scrub.uncapturable {
        return None;
    }
    let raw = serde_json::to_vec(body).ok()?;
    let total_bytes = raw.len() as u64;
    Some(RetainedBody {
        bytes: scrub_secret_bytes(raw, &scrub.reps),
        total_bytes,
    })
}

/// Remove request-secret byte sequences from a structured result, including otherwise-safe GraphQL
/// type/code classifications that happen to equal the submitted secret. A serialization failure or an
/// uncapturable representation returns only a static failure marker.
fn scrub_result(body: Value, scrub: &SecretScrub) -> Value {
    if scrub.reps.is_empty() {
        return body;
    }
    if scrub.uncapturable {
        return json!({ "outcome": "failed" });
    }
    let Ok(raw) = serde_json::to_vec(&body) else {
        return json!({ "outcome": "failed" });
    };
    let scrubbed = scrub_secret_bytes(raw, &scrub.reps);
    serde_json::from_slice(&scrubbed).unwrap_or_else(|_| json!({ "outcome": "failed" }))
}

/// Replace every exact-byte occurrence of each secret representation with a `[scrubbed:<field>]`
/// marker, so the stored artifact never carries a secret an agent supplied even when the provider
/// echoes it back. An empty needle is skipped (it would match everywhere).
fn scrub_secret_bytes(bytes: Vec<u8>, secrets: &[(&'static str, Vec<u8>)]) -> Vec<u8> {
    let mut out = bytes;
    for (field, needle) in secrets {
        if needle.is_empty() {
            continue;
        }
        let marker = format!("[scrubbed:{field}]").into_bytes();
        out = replace_all_bytes(&out, needle, &marker);
    }
    out
}

/// A straight byte-substring replace-all (`Vec<u8>` has no built-in). Non-overlapping, left to right.
fn replace_all_bytes(haystack: &[u8], needle: &[u8], marker: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(marker);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

pub trait Provider: Send + Sync {
    fn name(&self) -> &str;
    fn supported_actions(&self) -> &'static [&'static str];

    /// Whether this provider can serve `action`. Defaults to the compiled-in `supported_actions`;
    /// a template-extensible provider ALSO returns `true` for a ratified template it holds, so
    /// reachability of a templated action is per-broker (the registry), never a static list.
    fn supports_action(&self, action: &str) -> bool {
        self.supported_actions().contains(&action)
    }

    fn is_money_action(&self, _action: &str) -> bool {
        false
    }

    /// The contract for `action`, or `None` if the action is not contract-backed.
    fn action_contract(&self, action: &str) -> Option<&'static ActionContract>;

    /// Provider-specific pre-rewrite applied before the closed-schema check.
    fn rewrite_resource(
        &self,
        _action: &str,
        obj: serde_json::Map<String, Value>,
    ) -> Result<serde_json::Map<String, Value>> {
        Ok(obj)
    }

    /// Normalize a raw request resource into the closed, typed [`CanonicalResource`].
    fn canonicalize(&self, action: &str, raw: &Value) -> Result<CanonicalResource> {
        let resource = self.canonicalize_present_fields(action, raw)?;
        let contract = self.action_contract(action).ok_or_else(|| {
            Error::Provider(format!(
                "{}: no contract for action `{action}`",
                self.name()
            ))
        })?;
        for decl in contract.schema {
            if decl.required && !resource.contains(decl.name) {
                return Err(Error::Invalid(format!(
                    "required field `{}` absent for {}.{}",
                    decl.name, contract.provider, action
                )));
            }
        }
        Ok(resource)
    }

    /// Canonicalize every field that is present while deliberately not requiring absent fields.
    /// Discovery uses this for a known/unknown shape so provider rewrites and path/filter/size guards
    /// apply to exact literals without inventing values for fields that have not landed yet.
    fn canonicalize_present_fields(&self, action: &str, raw: &Value) -> Result<CanonicalResource> {
        let contract = self.action_contract(action).ok_or_else(|| {
            Error::Provider(format!(
                "{}: no contract for action `{action}`",
                self.name()
            ))
        })?;
        let obj = match raw {
            Value::Null => serde_json::Map::new(),
            Value::Object(m) => m.clone(),
            _ => return Err(Error::Invalid("resource must be a JSON object".into())),
        };
        let obj = self.rewrite_resource(action, obj)?;
        let mut fields = BTreeMap::new();
        for (k, v) in &obj {
            let decl = contract.field_decl(k).ok_or_else(|| {
                Error::Invalid(format!(
                    "unknown field `{k}` for {}.{}",
                    contract.provider, action
                ))
            })?;
            fields.insert(k.clone(), Scalar::from_json(decl.ty, k, v)?);
        }
        Ok(CanonicalResource::from_map(fields))
    }

    /// Whether execute needs a decrypted provider credential. `true` for every network provider (the
    /// broker opens the vault and passes the plaintext token). A provider that acts purely on locally
    /// owned state holds no secret and returns `false`; the broker then calls `execute` with an empty
    /// token and never touches the vault.
    fn requires_credential(&self) -> bool {
        true
    }

    /// Resolve trusted request-time facts for one compiled profile. Facts are inputs to policy, never
    /// a decision; the broker validates the exact output/source shape before merging them.
    fn resolve_request(
        &self,
        _profile: &'static EvidenceProfile,
        _token: &str,
        _partial: &CanonicalResource,
    ) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
        Err(EvidenceFailure::new(EvidenceFailureClass::Integrity))
    }

    /// The field this provider's own credential decides, if its descriptor declared one. The
    /// daemon populates it at request freeze and re-derives it at execution; an agent may never
    /// supply it.
    fn credential_mode_field(&self) -> Option<&str> {
        None
    }

    /// Derive the credential-decided value from the plaintext token. `None` means no declared
    /// prefix matched — unresolved, never a guess. The token is read here and nowhere else; only
    /// the derived value (a plain `"test"`/`"live"` string) leaves.
    fn credential_mode(&self, _token: &str) -> Option<&str> {
        None
    }

    /// Rewrite ONE request-supplied field to the provider's own canonical identifier,
    /// before the sentence judges the request. Never called for a value the profile's pure
    /// [`crate::canonicalize::CanonicalizerKind::is_canonical`] already accepts, so a request that
    /// names the canonical form costs no credential and makes no provider hop.
    fn canonicalize_request_field(
        &self,
        _profile: &'static CanonicalizationProfile,
        _token: &str,
        _supplied: &str,
    ) -> std::result::Result<String, EvidenceFailure> {
        Err(EvidenceFailure::new(EvidenceFailureClass::Integrity))
    }

    /// Check compiled mutable-state predicates without returning fields or authority. Implementations
    /// return only satisfied or a typed, value-free denial.
    fn check_preconditions(
        &self,
        preconditions: &[&'static crate::preconditions::CompiledPrecondition],
        _token: &str,
        _resource: &CanonicalResource,
    ) -> std::result::Result<(), crate::preconditions::PreconditionFailure> {
        match preconditions.first() {
            None => Ok(()),
            Some(precondition) => Err(crate::preconditions::PreconditionFailure::new(
                precondition.name,
                crate::preconditions::PreconditionFailureClass::Integrity,
            )),
        }
    }

    /// THE provider execution seam. One entry for every verb on every provider: the call carries
    /// the broker-derived [`ExecutionDiscipline`], and an adapter that cannot honour a discipline
    /// it is handed refuses rather than silently downgrading it. There is no second method, so
    /// there is no class of verb that reaches a different door.
    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse>;
}

impl cermet_lang::sentence::ContractProvider for dyn Provider {
    fn action_contract(&self, action: &str) -> Option<&ActionContract> {
        Provider::action_contract(self, action)
    }

    fn is_money_action(&self, action: &str) -> bool {
        Provider::is_money_action(self, action)
    }

    fn canonicalize_present_fields(
        &self,
        action: &str,
        resource: &Value,
    ) -> Result<CanonicalResource> {
        Provider::canonicalize_present_fields(self, action, resource)
    }
}

/// The open, schema-less contract the offline test doubles hand back for any action they claim.
/// Gated with the doubles so no release binary carries it.
#[cfg(any(test, feature = "test-double"))]
const MOCK_CONTRACT: ActionContract = ActionContract {
    provider: "mock",
    action: "*",
    schema: &[],
    consumes: &[],
    execution_targets: &[],
    relations: &[],
    open: true,
};

/// Build the live provider registry from the broker's RATIFIED descriptors — one [`GenericProvider`]
/// per descriptor. There is no compiled-in github/vercel: they are ordinary shipped descriptors, so a
/// provider with no ratified descriptor is simply absent (fail closed — a token can never ride to an
/// unratified origin). The offline test doubles stay a CODE provider registered under the feature gate
/// (never forced through a descriptor); a release binary holds neither a mock nor a fallback origin.
pub fn default_registry(
    descriptors: &[ProviderDescriptor],
    templates: &Arc<TemplateRegistry>,
    git: &crate::git::GitConfig,
) -> HashMap<String, Box<dyn Provider>> {
    let mut m: HashMap<String, Box<dyn Provider>> = HashMap::new();
    #[cfg(any(test, feature = "test-double"))]
    {
        m.insert("mock-vercel".into(), Box::new(MockVercel));
        m.insert("mock-github".into(), Box::new(MockGithub));
    }
    for d in descriptors {
        m.insert(
            d.name.clone(),
            Box::new(GenericProvider::from_descriptor(
                d.clone(),
                templates.clone(),
                git.clone(),
            )),
        );
    }
    m
}

// ---------------------------------------------------------------------------
// Shared HTTP helper
// ---------------------------------------------------------------------------

/// The env-override gate `resolve_origins` applies, factored out for a focused unit test: an override
/// only wins when egress is enabled (test/test-egress), otherwise the descriptor's pinned origin wins.
#[cfg(test)]
fn resolve_base(default: &str, override_val: Option<&str>, egress_enabled: bool) -> String {
    match override_val {
        Some(v) if egress_enabled => v.to_string(),
        _ => default.to_string(),
    }
}

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

fn no_redirect_client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()
        .unwrap_or_else(|_| Client::new())
}

/// The origin tuple `(scheme, host, effective port)` of a URL — `None` if it has no host.
/// Pinning the full origin (not just the host) rejects scheme drift (`http` vs `https`), port
/// drift (`:8443`), and userinfo tricks (`https://api.github.com@evil.test` → host `evil.test`).
fn url_origin(u: &reqwest::Url) -> Option<(String, String, Option<u16>)> {
    let host = u.host_str()?.to_string();
    Some((u.scheme().to_string(), host, u.port_or_known_default()))
}

pub(crate) struct Egress {
    client: Client,
    /// The allowlisted provider origins (a descriptor may pin more than one). EMPTY if every base
    /// failed to parse — which fails closed, since no request origin can ever be in an empty set.
    origins: Vec<(String, String, Option<u16>)>,
}

impl Egress {
    #[cfg(test)]
    fn new(base: &str) -> Self {
        Self::new_multi(&[base.to_string()])
    }

    /// Pin the EXACT origin (scheme + host + port) of each base; an unparseable base adds
    /// nothing (never a wildcard), so a descriptor with only bad origins allows no egress at all.
    fn new_multi(bases: &[String]) -> Self {
        let origins = bases
            .iter()
            .filter_map(|b| reqwest::Url::parse(b).ok().as_ref().and_then(url_origin))
            .collect();
        Self {
            client: no_redirect_client(),
            origins,
        }
    }

    /// True only if `url` parses and shares an EXACT allowlisted origin (scheme + host + port).
    fn allows(&self, url: &str) -> bool {
        match reqwest::Url::parse(url).ok().as_ref().and_then(url_origin) {
            Some(req) => self.origins.contains(&req),
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// The relay's credentialed outbound hop
// ---------------------------------------------------------------------------

/// Inbound request headers the relay forwards upstream. Everything else is DROPPED — most of all
/// `Authorization` (the relay replaces it with the vaulted credential) and `Cookie`. `x-vercel-*` /
/// `x-now-*` pass because the CLI's own upload protocol carries its content digest there; without
/// them the native uploader cannot work at all.
const RELAY_FORWARDED_REQUEST_HEADER_PREFIXES: &[&str] = &["x-vercel-", "x-now-"];
const RELAY_FORWARDED_REQUEST_HEADERS: &[&str] = &["content-type", "accept"];

/// Response headers the relay passes back to the native client. The body is returned verbatim, so
/// `content-encoding` must travel with it; `location` travels so a 3xx is legible to the client
/// (the relay itself never follows a redirect — that would leave the pinned origin).
const RELAY_FORWARDED_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "content-encoding",
    "location",
    "retry-after",
];

/// One upstream response whose HEAD has arrived and whose body is still coming.
///
/// The relay hands the head back the moment it lands and lets the caller pump the body, so a
/// streaming endpoint (`/events?follow=1`) reaches the native client line by line instead of after
/// the upstream finishes. `body` is credential-free by construction — the token was consumed
/// building the request headers below and is not reachable from a response.
pub(crate) struct RelayUpstreamStream {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Box<dyn std::io::Read + Send>,
}

/// The credential-bearing egress seam of a relay verb: the pinned origin of a ratified descriptor,
/// its auth shape, and its static headers. Built from the descriptor at broker open; the plaintext
/// token is passed in per hop and is never stored here.
pub(crate) struct RelayEgress {
    base: String,
    egress: Egress,
    auth: AuthShape,
    headers: Vec<(String, String)>,
}

impl RelayEgress {
    /// `None` for a descriptor pinning no origin — a relay with nowhere to forward must not exist.
    pub(crate) fn from_descriptor(d: &ProviderDescriptor) -> Option<Self> {
        let (base, origins) = resolve_origins(d);
        if base.is_empty() {
            return None;
        }
        Some(Self {
            base,
            egress: Egress::new_multi(&origins),
            auth: AuthShape::parse(&d.auth).ok()?,
            headers: d
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    /// Build ONE already-authorized hop's request with the vaulted credential attached — WITHOUT
    /// sending it. Nothing here touches the network.
    ///
    /// Custody: the plaintext token exists only as this call's argument and the header value built
    /// inside the egress boundary below — the same boundary `http_call_with_status` uses. From here
    /// it lives exactly where it always lived, inside this one request's own `Authorization` header,
    /// and it is never returned, stored on the session, or logged. [`RelayHopRequest`] exposes no
    /// accessor and no `Debug`, so the adapter that carries it to a worker thread cannot read it.
    ///
    /// `head_timeout` bounds the wait for the upstream HEAD. In blocking reqwest the same value then
    /// bounds each individual body read (it is a per-operation stall bound, not a total) — a live
    /// `follow=1` stream survives this because each read only needs to beat the stall bound, not the
    /// whole stream's duration. The hop's TOTAL life is bounded separately, by the session's
    /// declared TTL, in the caller's pump.
    pub(crate) fn prepare(
        &self,
        token: &str,
        method: &str,
        path_and_query: &str,
        request_headers: &[(String, String)],
        body: Vec<u8>,
        head_timeout: Duration,
    ) -> Result<RelayHopRequest> {
        let url = format!("{}{}", self.base, path_and_query);
        if !self.egress.allows(&url) {
            // Unreachable for a `/`-rooted path (the caller validates that), and still checked: the
            // egress pin is the one thing that keeps a credentialed hop on the ratified origin.
            return Err(Error::Provider(
                "egress blocked: the relay hop is not on the allowlisted provider origin".into(),
            ));
        }
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| Error::Invalid("relay hop method is not an HTTP method".into()))?;
        let mut rb = self
            .egress
            .client
            .request(method, url)
            .timeout(head_timeout)
            .header(USER_AGENT, "cermet/0.1");
        rb = match &self.auth {
            AuthShape::Bearer => rb.header(AUTHORIZATION, format!("Bearer {token}")),
            AuthShape::Token => rb.header(AUTHORIZATION, format!("token {token}")),
            AuthShape::Header(name) => rb.header(name.as_str(), token),
            AuthShape::Basic(user) => rb.header(AUTHORIZATION, basic_header(user, token)),
        };
        for (name, value) in &self.headers {
            rb = rb.header(name.as_str(), value.as_str());
        }
        for (name, value) in request_headers {
            let lower = name.to_ascii_lowercase();
            let forwarded = RELAY_FORWARDED_REQUEST_HEADERS.contains(&lower.as_str())
                || RELAY_FORWARDED_REQUEST_HEADER_PREFIXES
                    .iter()
                    .any(|prefix| lower.starts_with(prefix));
            if forwarded {
                rb = rb.header(lower, value.as_str());
            }
        }
        Ok(RelayHopRequest {
            request: rb.body(body),
        })
    }
}

/// One authorized hop's request: credentialed, and not yet sent.
///
/// It exists so the BROKER ACTOR NEVER TOUCHES THE NETWORK. Building this is pure and instant and
/// happens on the actor (that is where the vault is); connect, send, and the wait for the head all
/// happen in [`RelayHopRequest::send`], which the adapter calls on a worker thread. An upstream that
/// handshakes and then goes silent therefore costs one worker thread, never the broker.
pub(crate) struct RelayHopRequest {
    request: reqwest::blocking::RequestBuilder,
}

impl RelayHopRequest {
    /// Send the hop and wait for the upstream head. Blocking, and never called on the broker actor.
    pub(crate) fn send(self, max_body_bytes: usize) -> Result<RelayUpstreamStream> {
        let response = self
            .request
            .send()
            .map_err(|e| Error::Provider(format!("relay hop failed: {}", err_chain(&e))))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter(|(name, _)| RELAY_FORWARDED_RESPONSE_HEADERS.contains(&name.as_str()))
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_string(), value.to_string()))
            })
            .collect();
        // A DECLARED length over the cap is refused before a byte of body is read — unchanged from
        // the buffered path, and the only over-cap outcome that can still be a clean refusal. A body
        // of unknown length is bounded by the caller's pump instead (it has already sent the head).
        if response
            .content_length()
            .is_some_and(|length| length > max_body_bytes as u64)
        {
            return Err(Error::Provider(
                "relay upstream response exceeded the declared body cap".into(),
            ));
        }
        Ok(RelayUpstreamStream {
            status,
            headers,
            body: Box::new(response),
        })
    }
}

/// How the plaintext token is presented to a provider — chosen by the ratified descriptor, NEVER
/// hardcoded. The token is only ever built into a header string HERE, inside the http boundary that
/// already gates egress; it never escapes to a descriptor view, a proposal, an error, or a log.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthShape {
    /// `Authorization: Bearer <token>` (github, vercel, most REST APIs).
    #[default]
    Bearer,
    /// `Authorization: token <token>` (GitHub's classic scheme).
    Token,
    /// `<name>: <token>` (an API-key header, e.g. `header:X-Api-Key`).
    Header(String),
    /// `Authorization: Basic base64(<user>:<token>)` — the shape git's HTTPS transports have always
    /// spoken (`basic:x-access-token` for GitHub). The username is descriptor data; the token is the
    /// vault credential and never appears anywhere else.
    Basic(String),
}

impl AuthShape {
    fn parse(s: &str) -> std::result::Result<Self, String> {
        match s {
            "bearer" => Ok(AuthShape::Bearer),
            "token" => Ok(AuthShape::Token),
            other => match (other.strip_prefix("header:"), other.strip_prefix("basic:")) {
                (Some(name), _) if !name.is_empty() => Ok(AuthShape::Header(name.to_string())),
                (_, Some(user)) if !user.is_empty() => Ok(AuthShape::Basic(user.to_string())),
                _ => Err(format!(
                    "unknown auth shape `{s}` (expected `bearer`, `token`, `header:<name>`, or \
                     `basic:<user>`)"
                )),
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn http_call(
    egress: &Egress,
    method: Method,
    url: String,
    token: &str,
    body: Option<Value>,
    query: &[(&str, &str)],
    auth: &AuthShape,
    headers: &[(&str, &str)],
) -> Result<ProviderResponse> {
    http_call_with_encoding(
        egress,
        method,
        url,
        token,
        body,
        query,
        auth,
        headers,
        BodyEncoding::Json,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn http_call_with_encoding(
    eg: &Egress,
    method: Method,
    url: String,
    token: &str,
    body: Option<Value>,
    query: &[(&str, &str)],
    auth: &AuthShape,
    headers: &[(&str, &str)],
    body_encoding: BodyEncoding,
    success_statuses: &[u16],
) -> Result<ProviderResponse> {
    delivered_response(
        http_call_with_status(
            eg,
            method,
            url,
            token,
            body,
            query,
            auth,
            headers,
            body_encoding,
            &[],
        )?,
        success_statuses,
    )
}

enum DeliveredHttpResponse {
    Body {
        status: u16,
        bytes: Vec<u8>,
        /// The values of the step's DECLARED `retain_headers`, in declaration order, each `None`
        /// when the response did not carry that header. Empty for every step that declared none,
        /// which is every step but the minted-URL one.
        headers: Vec<(String, Option<String>)>,
    },
    StatusOnly {
        response: ProviderResponse,
    },
}

fn response_from_value(status: u16, value: Value, success_statuses: &[u16]) -> ProviderResponse {
    // What counts as success is the DECLARATION when there is one, and any 2xx when there is not.
    // The 2xx floor moved out of the declared arm rather than being widened inside it: a status is
    // a success here exactly when a ratified template named it, so a 302 is a success only for the
    // step that says `success_statuses: [302]` and stays a failure everywhere else. Every existing
    // template names 2xx codes only, so this is behaviour-identical for all of them.
    let status_ok = if success_statuses.is_empty() {
        (200..=299).contains(&status)
    } else {
        success_statuses.contains(&status)
    };
    if status_ok {
        ProviderResponse {
            proof: None,
            ok: true,
            result: value,
            retained: None,
            envelope: Default::default(),
            failure_class: None,
        }
    } else {
        ProviderResponse {
            proof: None,
            ok: false,
            result: json!({ "status": status, "error": value }),
            retained: None,
            envelope: Default::default(),
            // The provider's own status is the evidence, classified once, here.
            failure_class: Some(EffectFailureClass::of(FailureSignal::HttpStatus(status))),
        }
    }
}

fn delivered_response(
    delivered: DeliveredHttpResponse,
    success_statuses: &[u16],
) -> Result<ProviderResponse> {
    match delivered {
        DeliveredHttpResponse::Body { status, bytes, .. } => Ok(response_from_value(
            status,
            crate::provider_json::parse(&bytes)?,
            success_statuses,
        )),
        DeliveredHttpResponse::StatusOnly { response, .. } => Ok(response),
    }
}

#[allow(clippy::too_many_arguments)]
fn http_call_with_status(
    eg: &Egress,
    method: Method,
    url: String,
    token: &str,
    body: Option<Value>,
    query: &[(&str, &str)],
    auth: &AuthShape,
    headers: &[(&str, &str)],
    body_encoding: BodyEncoding,
    // The step's declared response header names, read off the delivered response and handed back
    // beside its body. Empty for every step that declares none.
    retain_headers: &[String],
) -> Result<DeliveredHttpResponse> {
    if !eg.allows(&url) {
        let req_host = reqwest::Url::parse(&url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()));
        // The daemon itself refused to send: a local fault, and definitively no effect.
        return Err(Error::ProviderFailed(
            EffectFailureClass::of(FailureSignal::LocalFault),
            format!(
                "egress blocked: request to host `{}` is not the allowlisted provider origin",
                req_host.as_deref().unwrap_or("<none>")
            ),
        ));
    }
    let rb = eg
        .client
        .request(method, url)
        .header(USER_AGENT, "cermet/0.1");
    let mut rb = match auth {
        AuthShape::Bearer => rb.header(AUTHORIZATION, format!("Bearer {token}")),
        AuthShape::Token => rb.header(AUTHORIZATION, format!("token {token}")),
        AuthShape::Header(name) => rb.header(name.as_str(), token),
        AuthShape::Basic(user) => rb.header(AUTHORIZATION, basic_header(user, token)),
    };
    if !query.is_empty() {
        rb = rb.query(query);
    }
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    if let Some(body) = &body {
        rb = match body_encoding {
            BodyEncoding::Json => rb.json(body),
            BodyEncoding::Form => rb
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(encode_form_body(body)?),
        };
    }
    // No response arrived. WHICH failure it was decides whether a retry is safe, and reqwest's own
    // typed predicate is the evidence: `is_connect` means the connection was never established, so
    // nothing was sent and no effect can have happened. Anything after that — a write error, a read
    // timeout, a dropped socket — may have delivered the request, and the honest answer is that the
    // outcome is unknown. The error's TEXT is never consulted for this.
    let resp = rb.send().map_err(|e| {
        let signal = if e.is_connect() {
            FailureSignal::NeverSent
        } else {
            FailureSignal::SentWithoutAnswer
        };
        Error::ProviderFailed(
            EffectFailureClass::of(signal),
            format!("request failed: {}", err_chain(&e)),
        )
    })?;
    let status = resp.status();
    // Read the declared headers HERE, off the delivered response, before the body is touched. Only
    // the names a ratified template asked for are read — this is not a general header channel, and
    // nothing undeclared is ever carried anywhere. A header whose value is not valid UTF-8 reads as
    // absent, which the executor then fails closed on.
    let retained_headers: Vec<(String, Option<String>)> = retain_headers
        .iter()
        .map(|name| {
            (
                name.clone(),
                resp.headers()
                    .get(name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
            )
        })
        .collect();
    if resp
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        let response =
            status_preserving_response(status, "provider response exceeded the size cap")?;
        return Ok(DeliveredHttpResponse::StatusOnly { response });
    }
    use std::io::Read;
    let mut buf = Vec::new();
    if let Err(e) = resp
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
    {
        // A body-read failure AFTER a delivered non-2xx (truncated Content-Length, reset
        // mid-body, read timeout) must preserve the rejection status, not collapse to Unreachable and
        // vault a rejected token. A 2xx we cannot read stays a genuine error → Unreachable.
        let response = status_preserving_response(
            status,
            &format!("response read failed: {}", err_chain(&e)),
        )?;
        return Ok(DeliveredHttpResponse::StatusOnly { response });
    }
    if buf.len() > MAX_RESPONSE_BYTES {
        let response =
            status_preserving_response(status, "provider response exceeded the size cap")?;
        return Ok(DeliveredHttpResponse::StatusOnly { response });
    }
    // THE WIRE TEE ([`crate::wiretap`]), off unless a daemon-side env switch names a file. This is
    // the earliest point at which the response body exists: nothing has parsed it, asserted on it,
    // projected it, or retained it. What the tee records is therefore what the provider sent, which
    // is the whole reason the instrument sits here and not one layer up.
    crate::wiretap::record(status.as_u16(), &buf, token);
    Ok(DeliveredHttpResponse::Body {
        status: status.as_u16(),
        bytes: buf,
        headers: retained_headers,
    })
}

fn encode_form_body(body: &Value) -> Result<String> {
    fn flatten(prefix: &str, value: &Value, out: &mut Vec<(String, String)>) -> Result<()> {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    let nested = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}[{key}]")
                    };
                    flatten(&nested, value, out)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    flatten(&format!("{prefix}[]"), value, out)?;
                }
            }
            Value::String(value) => out.push((prefix.to_string(), value.clone())),
            Value::Number(value) => out.push((prefix.to_string(), value.to_string())),
            Value::Bool(value) => out.push((prefix.to_string(), value.to_string())),
            Value::Null => {
                return Err(Error::Provider(format!(
                    "template form body field `{prefix}` rendered null; form values must be scalar"
                )));
            }
        }
        Ok(())
    }

    if !body.is_object() {
        return Err(Error::Provider(
            "template form body must render to an object".into(),
        ));
    }
    let mut fields = Vec::new();
    flatten("", body, &mut fields)?;
    serde_urlencoded::to_string(fields)
        .map_err(|error| Error::Provider(format!("template form encoding failed: {error}")))
}

fn err_chain<E: std::error::Error>(e: &E) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(inner) = src {
        s.push_str(" -> ");
        s.push_str(&inner.to_string());
        src = inner.source();
    }
    s
}

/// A body-level failure AFTER the HTTP status was already delivered (an over-cap body,
/// or a truncated/reset/timed-out read) must NOT erase a non-success status. A REJECTION (non-2xx) is
/// returned as an `ok:false` response carrying its status; a SUCCESS whose body cannot be read stays an
/// execution error, never a spurious success. The body is discarded either way (never read past the
/// cap, or lost to the failed read), so no oversized/hostile bytes flow onward.
fn status_preserving_response(
    status: reqwest::StatusCode,
    error_msg: &str,
) -> Result<ProviderResponse> {
    if status.is_success() {
        return Err(Error::Provider(error_msg.to_string()));
    }
    Ok(ProviderResponse {
        proof: None,
        ok: false,
        result: json!({
            "status": status.as_u16(),
            "error": error_msg,
        }),
        retained: None,
        envelope: Default::default(),
        // A rejection whose body we could not read is still that rejection: the status the provider
        // already sent classifies it, and the unread body would not have changed the answer.
        failure_class: Some(EffectFailureClass::of(FailureSignal::HttpStatus(
            status.as_u16(),
        ))),
    })
}

/// Validate a value that will be interpolated into a provider URL path.
/// A response that was DELIVERED and could not be read. A failure status classifies itself — the
/// provider already said what it thought of the request, and an unreadable error body does not
/// change that. A SUCCESS status we cannot read is the template's problem, not the request's.
fn unreadable_body_class(status: u16) -> EffectFailureClass {
    if (200..300).contains(&status) {
        EffectFailureClass::of(FailureSignal::ResponseShapeUnexpected)
    } else {
        EffectFailureClass::of(FailureSignal::HttpStatus(status))
    }
}

fn validate_path_segment(field: &str, s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::Invalid(format!("`{field}` must not be empty")));
    }
    if s == "." || s == ".." {
        return Err(Error::Invalid(format!(
            "`{field}` must not be a dot segment"
        )));
    }
    if s.chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '?' | '#' | '%' | '\\'))
    {
        return Err(Error::Invalid(format!(
            "`{field}` contains an illegal path character"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Generic action-template executor
// ---------------------------------------------------------------------------

/// Per-field byte cap for a template resource. Why: an unbounded free-payload string amplifies
/// through base64 into `grants.resource_json` and the operator views — cap it before a grant can
/// ever freeze it.
pub(crate) const MAX_TEMPLATE_STR_FIELD_BYTES: usize = 256 * 1024;

/// Request-time validation of a template resource. Runs at the END of a
/// provider's `rewrite_resource` (after any repo-sugar rewrite) so a bad path or an oversized field
/// DENIES at request time — no approvable card, no grant — instead of failing pre-egress after a
/// human already approved. Evidence preparation reuses it after merging provider-resolved fields,
/// and provider canonicalization re-enters it for the stored frozen resource before claim.
pub(crate) fn validate_template_resource(
    lt: &LoadedTemplate,
    obj: &serde_json::Map<String, Value>,
) -> Result<()> {
    for (k, v) in obj {
        if let Some(s) = v.as_str() {
            let cap = MAX_TEMPLATE_STR_FIELD_BYTES;
            if s.len() > cap {
                return Err(Error::Invalid(format!(
                    "field `{k}` is {} bytes, over the {cap}-byte field cap",
                    s.len()
                )));
            }
        }
    }
    for field in lt.contract.schema {
        if field.class != crate::contract::FieldClass::ReadFilter {
            continue;
        }
        if let Some(value) = obj.get(field.name).and_then(Value::as_str) {
            validate_query_literal(field.name, value)?;
        }
    }
    // Canonical-value SHAPE checks: a field declaring a `format` must carry a value of
    // that exact kind — an immutable Git OID, a canonical positive integer — or DENY at admission,
    // before an approvable card or a grant exists. Pure predicate: no value is mutated.
    for (field, format) in lt.template.format_fields() {
        if let Some(v) = obj.get(field) {
            let s = v.as_str().ok_or_else(|| {
                Error::Invalid(format!("template field `{field}` must be a string"))
            })?;
            if !format.matches(s) {
                return Err(Error::Invalid(format!(
                    "field `{field}` value is not {}",
                    format.describe()
                )));
            }
        }
    }
    // A `fixed` field has exactly one legal value, declared by the ratified
    // template. Enforced here — the same admission path a `format` runs through — so a request naming
    // any other value DENIES before an approvable card exists, and so the re-validation before claim
    // sees it again. This is what makes `deploy` structurally unable to deploy production, whether
    // the "deploy prod" value was injected or just fat-fingered.
    for (field, fixed) in lt.template.fixed_fields() {
        if let Some(value) = obj.get(field) {
            let string = value.as_str().ok_or_else(|| {
                Error::Invalid(format!("template field `{field}` must be a string"))
            })?;
            if string != fixed {
                return Err(Error::Invalid(format!(
                    "field `{field}` is fixed to `{fixed}` by the ratified action template and may \
                     not be requested with another value"
                )));
            }
        }
    }
    for (field, max_chars) in lt.template.string_char_limits() {
        if let Some(value) = obj.get(field) {
            let string = value.as_str().ok_or_else(|| {
                Error::Invalid(format!("template field `{field}` must be a string"))
            })?;
            let actual = string.chars().count();
            if actual > max_chars {
                return Err(Error::Invalid(format!(
                    "field `{field}` is {actual} characters, over the {max_chars}-character field cap"
                )));
            }
        }
    }
    for (field, max_int) in lt.template.integer_limits() {
        if let Some(value) = obj.get(field) {
            let integer = value.as_i64().ok_or_else(|| {
                Error::Invalid(format!("template field `{field}` must be an integer"))
            })?;
            if integer > max_int {
                return Err(Error::Invalid(format!(
                    "field `{field}` is {integer}, over the {max_int} integer cap"
                )));
            }
        }
    }
    if let Some((fields, max_chars)) = lt.template.string_char_budget() {
        let mut actual = 0usize;
        for field in fields {
            let Some(value) = obj.get(field) else {
                continue;
            };
            let string = value.as_str().ok_or_else(|| {
                Error::Invalid(format!("template field `{field}` must be a string"))
            })?;
            actual = actual.checked_add(string.chars().count()).ok_or_else(|| {
                Error::Invalid("string character budget overflowed while summing fields".into())
            })?;
        }
        if actual > max_chars {
            return Err(Error::Invalid(format!(
                "string_char_budget is {actual} characters, over the {max_chars}-character aggregate cap"
            )));
        }
    }
    for (field, mode) in lt.template.path_fields() {
        let Some(v) = obj.get(&field) else {
            continue;
        };
        let s = v.as_str().ok_or_else(|| {
            Error::Invalid(format!("template path field `{field}` must be a string"))
        })?;
        match mode {
            PathMode::Segment => validate_path_segment(&field, s)?,
            PathMode::Path => {
                for seg in s.split('/') {
                    validate_path_segment(&field, seg)?;
                }
            }
        }
    }
    Ok(())
}

/// Look up a `$.a.b` capture pointer against a response body. `None` if any segment is missing —
/// which a SUCCESS step turns into a fail-closed error (an ambiguous 200 never flows onward).
fn capture_lookup<'a>(v: &'a Value, ptr: &str) -> Option<&'a Value> {
    let rest = ptr.strip_prefix("$.")?;
    dotted_lookup(v, rest)
}

/// Traverse a BARE dotted identifier path (`a.b.c`, no `$.` root) against a response body. This is
/// the `expect_eq` pointer convention: its keys are validated as bare `is_dotted_path` values
/// (`templates.rs`), NOT the `$.`-rooted form `capture` uses — so the verification read must resolve
/// them without a prefix, or the guard would silently never match (a hollow always-reject pin).
fn dotted_lookup<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Render a scalar into a query-string value.
fn scalar_query_str(s: &Scalar) -> String {
    match s {
        Scalar::Str(s) => s.clone(),
        Scalar::Int(i) => i.to_string(),
        Scalar::Bool(b) => b.to_string(),
    }
}

fn validate_query_literal(field: &str, value: &str) -> Result<()> {
    if !(3..=200).contains(&value.len()) || value.chars().any(char::is_control) {
        return Err(Error::Invalid(format!(
            "query-literal field `{field}` must be 3..=200 bytes without controls"
        )));
    }
    Ok(())
}

fn escape_query_literal(field: &str, value: &str) -> Result<String> {
    validate_query_literal(field, value)?;
    Ok(value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn captured_query_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        _ => None,
    }
}

/// One query value: `None` means "omit this param" (a whole-value `{field?}` whose field is absent).
/// A capture is accepted only for the validator's setup-only terminal reconciliation exception.
fn render_query_value(
    qv: &str,
    resource: &CanonicalResource,
    captures: &BTreeMap<String, Value>,
) -> Result<Option<String>> {
    let segs = crate::templates::segments(qv)
        .map_err(|m| Error::Provider(format!("template query value {m}")))?;
    if segs.len() == 1 {
        if let Segment::Placeholder(ph) = &segs[0] {
            if ph.whole {
                if let Some(sc) = resource.scalar(&ph.name) {
                    return Ok(Some(scalar_query_str(sc)));
                }
                if let Some(captured) = captures.get(&ph.name) {
                    return captured_query_scalar(captured).map(Some).ok_or_else(|| {
                        Error::Provider(format!(
                            "template query: capture `{}` is not a scalar",
                            ph.name
                        ))
                    });
                }
                return if ph.optional {
                    Ok(None)
                } else {
                    Err(Error::Provider(format!(
                        "template query: required field or reconciliation capture `{}` is absent",
                        ph.name
                    )))
                };
            }
        }
    }
    // Embedded: string-interpolate each declared or narrowly permitted reconciliation scalar.
    let mut out = String::new();
    for seg in segs {
        match seg {
            Segment::Literal(l) => out.push_str(&l),
            Segment::Placeholder(ph) => {
                let rendered = if let Some(sc) = resource.scalar(&ph.name) {
                    scalar_query_str(sc)
                } else if let Some(captured) = captures.get(&ph.name) {
                    captured_query_scalar(captured).ok_or_else(|| {
                        Error::Provider(format!(
                            "template query: capture `{}` is not a scalar",
                            ph.name
                        ))
                    })?
                } else {
                    return Err(Error::Provider(format!(
                        "template query: field or reconciliation capture `{}` is absent",
                        ph.name
                    )));
                };
                if matches!(ph.transform, Some(Transform::QueryLiteral)) {
                    out.push_str(&escape_query_literal(&ph.name, &rendered)?);
                } else {
                    out.push_str(&rendered);
                }
            }
        }
    }
    Ok(Some(out))
}

/// A rendered body value, or a signal to OMIT the enclosing object key (a whole-value `{field?}`
/// that is absent). Omission is legal only for an object key — never inside an array (fail closed).
enum Rendered {
    Present(Value),
    Omit,
}

fn render_body_value(
    v: &Value,
    resource: &CanonicalResource,
    captures: &BTreeMap<String, Value>,
    scrub: &mut SecretScrub,
) -> Result<Rendered> {
    match v {
        Value::String(s) => render_body_string(s, resource, captures, scrub),
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, val) in map {
                match render_body_value(val, resource, captures, scrub)? {
                    Rendered::Present(rv) => {
                        out.insert(k.clone(), rv);
                    }
                    Rendered::Omit => {}
                }
            }
            Ok(Rendered::Present(Value::Object(out)))
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for val in arr {
                match render_body_value(val, resource, captures, scrub)? {
                    Rendered::Present(rv) => out.push(rv),
                    Rendered::Omit => {
                        return Err(Error::Provider(
                            "template body: an absent optional placeholder cannot be omitted inside \
                             an array (fail closed)"
                                .into(),
                        ));
                    }
                }
            }
            Ok(Rendered::Present(Value::Array(out)))
        }
        other => Ok(Rendered::Present(other.clone())),
    }
}

fn render_body_string(
    s: &str,
    resource: &CanonicalResource,
    captures: &BTreeMap<String, Value>,
    scrub: &mut SecretScrub,
) -> Result<Rendered> {
    let segs = crate::templates::segments(s)
        .map_err(|m| Error::Provider(format!("template body string {m}")))?;
    // Whole-value placeholder: renders the field's typed JSON scalar, a captured JSON value, a
    // base64 of the Str field, an `omit:` Str field (dropping the enclosing key when it equals the
    // pinned literal), or omits an absent optional key.
    if segs.len() == 1 {
        if let Segment::Placeholder(ph) = &segs[0] {
            if ph.whole {
                if let Some(Transform::Base64) = &ph.transform {
                    let raw = match resource.scalar(&ph.name) {
                        Some(Scalar::Str(s)) => s,
                        _ => {
                            return Err(Error::Provider(format!(
                                "template body: base64 placeholder `{}` is not a present string field",
                                ph.name
                            )));
                        }
                    };
                    use base64::Engine as _;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
                    // The TRANSFORMED wire form of a secret is what a provider would echo —
                    // capture the exact rendered bytes into the scrub set.
                    if scrub.is_secret(&ph.name) {
                        scrub.add(&ph.name, &encoded);
                    }
                    return Ok(Rendered::Present(Value::String(encoded)));
                }
                if let Some(Transform::Negative) = &ph.transform {
                    let amount = match resource.scalar(&ph.name) {
                        Some(Scalar::Int(value)) if *value > 0 => *value,
                        _ => {
                            return Err(Error::Provider(format!(
                                "template body: negative placeholder `{}` requires a positive integer",
                                ph.name
                            )));
                        }
                    };
                    return Ok(Rendered::Present(json!(-amount)));
                }
                if let Some(Transform::Omit(literal)) = &ph.transform {
                    let value = match resource.scalar(&ph.name) {
                        Some(Scalar::Str(s)) => s,
                        _ => {
                            return Err(Error::Provider(format!(
                                "template body: omit placeholder `{}` is not a present string field",
                                ph.name
                            )));
                        }
                    };
                    return if value == literal {
                        Ok(Rendered::Omit)
                    } else {
                        Ok(Rendered::Present(Value::String(value.clone())))
                    };
                }
                if let Some(Transform::Default(literal)) = &ph.transform {
                    // Present frozen value wins; an absent optional field falls back to the fixed
                    // literal (e.g. Vercel's required `type` defaults to `encrypted`).
                    let rendered = match resource.scalar(&ph.name) {
                        Some(Scalar::Str(s)) => s.clone(),
                        _ => literal.clone(),
                    };
                    return Ok(Rendered::Present(Value::String(rendered)));
                }
                if let Some(sc) = resource.scalar(&ph.name) {
                    return Ok(Rendered::Present(sc.to_json()));
                }
                if let Some(cv) = captures.get(&ph.name) {
                    // A capture emitted under a secret field's name (an absent optional secret with a
                    // colliding capture — exotic): capture the emitted representation too.
                    if scrub.is_secret(&ph.name) {
                        match cv {
                            Value::String(s) => scrub.add(&ph.name, s),
                            other => scrub.add(&ph.name, &other.to_string()),
                        }
                    }
                    return Ok(Rendered::Present(cv.clone()));
                }
                return if ph.optional {
                    Ok(Rendered::Omit)
                } else {
                    Err(Error::Provider(format!(
                        "template body: required placeholder `{}` resolved to neither a present field \
                         nor a capture",
                        ph.name
                    )))
                };
            }
        }
    }
    // Embedded: string-interpolate Str fields and string captures ONLY (a non-Str embedded is an
    // executor error). Optional/transform embedded placeholders are refused by the validator.
    let mut out = String::new();
    for seg in segs {
        match seg {
            Segment::Literal(l) => out.push_str(&l),
            Segment::Placeholder(ph) => {
                if let Some(Scalar::Str(s)) = resource.scalar(&ph.name) {
                    out.push_str(s);
                } else if let Some(Value::String(s)) = captures.get(&ph.name) {
                    if scrub.is_secret(&ph.name) {
                        scrub.add(&ph.name, s);
                    }
                    out.push_str(s);
                } else {
                    return Err(Error::Provider(format!(
                        "template body: embedded placeholder `{}` is not a present string field or \
                         string capture",
                        ph.name
                    )));
                }
            }
        }
    }
    Ok(Rendered::Present(Value::String(out)))
}

/// The envelope is broker-authored, but an entry can carry a value the AGENT submitted, so it gets
/// the same request-secret scrub the result does.
fn scrub_envelope(
    envelope: serde_json::Map<String, Value>,
    scrub: &SecretScrub,
) -> serde_json::Map<String, Value> {
    if envelope.is_empty() || scrub.reps.is_empty() {
        return envelope;
    }
    match scrub_result(Value::Object(envelope), scrub) {
        Value::Object(scrubbed) => scrubbed,
        // `scrub_result` degrades to a static marker when a representation is uncapturable; an
        // envelope we cannot scrub is an envelope we drop, which is the fail-closed direction.
        _ => serde_json::Map::new(),
    }
}

/// The reconciliation evidence a POST-EFFECT assertion failure returns: the provider body, as it
/// arrived. Under the verbatim response contract there is no
/// scalar squeeze and no reviewed-path allowlist to squeeze toward — a mismatch after the effect
/// boundary is exactly when the operator needs everything the provider said. Agent-submitted
/// secrets are still scrubbed.
fn postcondition_proof(result: &Value, scrub: &SecretScrub) -> Value {
    scrub_result(result.clone(), scrub)
}

/// Execute a ratified action template: interpolate each step from the frozen resource (plus mid-run
/// captures), call the provider's compiled-in `http_call` (the token goes only where the provider
/// puts it), and narrow the final response to the template's `keep` allowlist. Fail closed on any
/// missing capture (an ambiguous success never flows into a later step).
///
/// `success_contract` IS the proving half of the execution discipline — `Some` folds the compiled
/// [`EffectProof`] observation onto the response (and normalizes what that implies), `None` runs
/// the plain hop. One executor, one discipline parameter.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_template(
    eg: &Egress,
    base: &str,
    lt: &'static LoadedTemplate,
    call: ProviderCall,
    headers: &[(&str, &str)],
    auth: &AuthShape,
    success_contract: Option<&'static crate::mutation_success::MutationSuccessContract>,
) -> Result<ProviderResponse> {
    let proving = success_contract.is_some();
    let (response, proof) =
        execute_template_steps(eg, base, lt, call, headers, auth, success_contract)?;
    Ok(if proving {
        response.proved(proof)
    } else {
        response
    })
}

#[allow(clippy::too_many_arguments)]
fn execute_template_steps(
    eg: &Egress,
    base: &str,
    lt: &'static LoadedTemplate,
    call: ProviderCall,
    headers: &[(&str, &str)],
    auth: &AuthShape,
    success_contract: Option<&'static crate::mutation_success::MutationSuccessContract>,
) -> Result<(ProviderResponse, EffectProof)> {
    // The broker-held idempotency key, absent for a verb whose discipline mints none. It rides
    // the request header the caller assembled, and Stripe echoes it back in its own
    // `idempotency_error` bodies, so it belongs in the WIRE TEE's redaction set exactly as
    // `broker/execute.rs` folds it into the audit/artifact one. Reading it here sends it nowhere
    // new — this is redaction material only.
    let idempotency_key = call.discipline.idempotency_key.unwrap_or("");
    let template = &lt.template;
    let steps = template.steps();
    let last = steps.len().saturating_sub(1);
    let mut captures: BTreeMap<String, Value> = BTreeMap::new();

    // The AGENT-SUBMITTED secret representations (e.g. `set_env_var.value`) to scrub out of the
    // retained body — seeded from the frozen resource, extended by the renderer with every
    // transformed wire form it actually emits. Distinct from the vault credential
    // (`redaction.rs`), which the broker byte-redacts at store time.
    let mut scrub = SecretScrub::new(lt.contract, call.resource);

    for (i, step) in steps.iter().enumerate() {
        let is_final = i == last;
        let crossed_effect_boundary = is_final && !is_verification_read(step);

        // ---- URL path (re-validated here as defense in depth) ----
        let mut path = String::new();
        for seg in crate::templates::segments(&step.path)
            .map_err(|m| Error::Provider(format!("template path {m}")))?
        {
            match seg {
                Segment::Literal(l) => path.push_str(&l),
                Segment::Placeholder(ph) => {
                    let s = call.resource.req_str(&ph.name)?;
                    match template.path_mode(&ph.name) {
                        PathMode::Segment => validate_path_segment(&ph.name, s)?,
                        PathMode::Path => {
                            for part in s.split('/') {
                                validate_path_segment(&ph.name, part)?;
                            }
                        }
                    }
                    path.push_str(s);
                }
            }
        }
        let url = format!("{base}{path}");

        // ---- query ----
        let mut query_owned: Vec<(String, String)> = Vec::new();
        for (qk, qv) in &step.query {
            if let Some(rendered) = render_query_value(qv, call.resource, &captures)? {
                query_owned.push((qk.clone(), rendered));
            }
        }
        let query: Vec<(&str, &str)> = query_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        // ---- body ----
        let mut body = match &step.body {
            Some(b) => match render_body_value(b, call.resource, &captures, &mut scrub)? {
                Rendered::Present(v) => Some(v),
                Rendered::Omit => None,
            },
            None => None,
        };

        // The frozen-query rule: a GraphQL step's document is the ratified LITERAL,
        // inserted verbatim as the wire body's top-level `query` key AFTER rendering — it is never
        // placeholder-scanned and never interpolated, so agent text can never become mutation text.
        // (The validator refuses a template body carrying its own `query` key.)
        if let Some(gq) = &step.graphql_query {
            body = match body {
                None => Some(json!({ "query": gq })),
                Some(Value::Object(mut m)) => {
                    m.insert("query".to_string(), Value::String(gq.clone()));
                    Some(Value::Object(m))
                }
                Some(_) => {
                    return Err(Error::Provider(format!(
                        "template {}.{} step `{}`: a graphql step's body must render to an object \
                         (fail closed)",
                        lt.contract.provider, lt.contract.action, step.id
                    )));
                }
            };
        }

        let method = Method::from_bytes(step.method.as_bytes())
            .map_err(|_| Error::Provider(format!("template step uses method `{}`", step.method)))?;
        // Label everything the tee records for this step with the verb that produced it, so the
        // sitting can pair a teed body with the receipt and artifact it became.
        let _tee = crate::wiretap::TeeScope::enter(
            lt.contract.provider,
            lt.contract.action,
            &step.id,
            &[idempotency_key],
        );
        // What the step's declared `retain_headers` found on the response it acted on. Consumed
        // once, at the terminal step, into the broker-authored envelope.
        let mut retained_headers: Vec<(String, Option<String>)> = Vec::new();
        let (resp, money_evaluation) = {
            let delivered = http_call_with_status(
                eg,
                method.clone(),
                url.clone(),
                call.token,
                body.clone(),
                &query,
                auth,
                headers,
                step.body_encoding,
                &step.retain_headers,
            )?;
            match delivered {
                DeliveredHttpResponse::Body {
                    status,
                    bytes,
                    headers: delivered_headers,
                } => {
                    retained_headers = delivered_headers;
                    let (value, proved) = match success_contract {
                        Some(contract) if is_final => {
                            match contract.evaluate_raw(status, &bytes, call.resource) {
                                Ok(evaluation) => evaluation,
                                Err(_) => {
                                    // The final mutation response was delivered but did not parse.
                                    // An unreadable answer after invocation is exactly what
                                    // `ambiguous` is for (this narrows the class; it does not
                                    // empty it), and the unparseable bytes are not a result we can
                                    // hand back as JSON.
                                    return Ok((
                                        ProviderResponse {
                                            proof: None,
                                            ok: false,
                                            result: json!({
                                                "status": status,
                                                "error": "the provider response could not be parsed",
                                            }),
                                            retained: None,
                                            envelope: Default::default(),
                                            failure_class: Some(unreadable_body_class(status)),
                                        },
                                        EffectProof::Unproved,
                                    ));
                                }
                            }
                        }
                        // Some ordinary provider mutations legitimately return an empty success body
                        // (for example GitHub workflow cancellation). That explicit no-content shape is
                        // JSON null for projection; every non-empty body still uses the strict parser.
                        _ if bytes.is_empty() => (Value::Null, EffectProof::Unproved),
                        _ => (crate::provider_json::parse(&bytes)?, EffectProof::Unproved),
                    };
                    (
                        response_from_value(status, value, &step.success_statuses),
                        proved,
                    )
                }
                DeliveredHttpResponse::StatusOnly { response } => (response, EffectProof::Unproved),
            }
        };

        // GraphQL response semantics, declarative: classify a present nonempty or
        // malformed top-level `errors` value before every other response check. GitHub reports
        // mutation failures — including expectedHeadOid CAS drift — as HTTP 200 + errors, so this
        // sanitized error surface must win. Required-path checks run later, after specific response
        // assertions, through the same path as REST.
        if step.graphql_query.is_some() && resp.ok {
            if let Some(failure) = graphql_errors_failure(&resp.result) {
                let retained = step_retains(step.retention)
                    .then(|| retain_body(&resp.result, &scrub))
                    .flatten();
                // The response contract is verbatim: a GraphQL failure hands back the
                // body the provider sent, untouched. The declared classification (`outcome:
                // failed`) is the step's VERDICT, not part of the
                // response, so it rides the sibling envelope.
                let envelope =
                    scrub_envelope(failure.as_object().cloned().unwrap_or_default(), &scrub);
                let result = scrub_result(resp.result.clone(), &scrub);
                return Ok((
                    ProviderResponse {
                        proof: None,
                        ok: false,
                        result,
                        retained,
                        envelope,
                        // A GraphQL failure arrives as a 200 carrying an `errors` array whose
                        // meaning lives in its MESSAGES — a rejected input, a CAS conflict and a
                        // revoked scope all look identical from here, and reading those strings to
                        // pick between them is exactly the guess the residual exists to prevent.
                        failure_class: Some(EffectFailureClass::of(FailureSignal::Unclassifiable)),
                    },
                    EffectProof::Unproved,
                ));
            }
        }

        if resp.ok {
            // Response assertions are value-free preconditions on every verification read and every
            // non-final step. Only a final mutation has crossed the effect boundary and therefore
            // carries scrubbed scalar reconciliation evidence on mismatch.
            for (resp_path, field_name) in &step.expect_eq {
                let expected = if success_contract.is_some() && is_final {
                    call.resource
                        .scalar(field_name)
                        .ok_or_else(|| {
                            Error::Integrity(format!(
                                "compiled money success contract references absent field `{field_name}`"
                            ))
                        })?
                        .to_json()
                } else {
                    Value::String(call.resource.req_str(field_name)?.to_string())
                };
                // `resp_path` is a BARE dotted path (`head_sha`), the `expect_eq` convention — resolve
                // it directly, NOT via the `$.`-rooted `capture_lookup` (which would strip a prefix
                // that is not there and never match: the frozen-value pin would be a hollow always-reject).
                let observed = dotted_lookup(&resp.result, resp_path);
                let matches = if success_contract.is_some()
                    && is_final
                    && field_name == "mode"
                    && resp_path == "livemode"
                {
                    observed
                        .and_then(Value::as_bool)
                        .map(|live| if live { "live" } else { "test" })
                        == call.resource.get_str("mode")
                } else {
                    observed == Some(&expected)
                };
                if !matches {
                    let result = if crossed_effect_boundary {
                        let provider_proof = postcondition_proof(&resp.result, &scrub);
                        json!({
                            "outcome": "postcondition_failed",
                            "field": field_name,
                            "provider_proof": provider_proof,
                        })
                    } else {
                        json!({
                            "outcome": "precondition_failed",
                            "field": field_name,
                        })
                    };
                    return Ok((
                        ProviderResponse {
                            proof: None,
                            ok: false,
                            result,
                            retained: step_retains(step.retention)
                                .then(|| retain_body(&resp.result, &scrub))
                                .flatten(),
                            envelope: Default::default(),
                            // The SAME boundary that decides the wording decides the class: past it
                            // the effect landed and disagrees with the approval; before it nothing
                            // happened and the world simply did not match, which this vocabulary
                            // has no behavior for and so leaves as the residual.
                            failure_class: Some(EffectFailureClass::of(
                                if crossed_effect_boundary {
                                    FailureSignal::ApprovedOutcomeContradicted
                                } else {
                                    FailureSignal::Unclassifiable
                                },
                            )),
                        },
                        EffectProof::Unproved,
                    ));
                }
            }
            // Terminal postconditions compare provider evidence to frozen template
            // literals. A final mismatch happened after the mutation and requires reconciliation:
            // preserve only provider-present scalar values at reviewed keep paths, then scrub request
            // secrets. The grant is already spent and the broker never retries it; any follow-up is a
            // new request/grant that re-enters policy. Reads and non-final guards remain value-free.
            for (resp_path, expected) in &step.expect_literal {
                if dotted_lookup(&resp.result, resp_path) != Some(expected) {
                    let result = if crossed_effect_boundary {
                        let provider_proof = postcondition_proof(&resp.result, &scrub);
                        json!({
                            "outcome": "postcondition_failed",
                            "path": resp_path,
                            "provider_proof": provider_proof,
                        })
                    } else {
                        json!({
                            "outcome": "precondition_failed",
                            "path": resp_path,
                        })
                    };
                    return Ok((
                        ProviderResponse {
                            proof: None,
                            ok: false,
                            result,
                            retained: step_retains(step.retention)
                                .then(|| retain_body(&resp.result, &scrub))
                                .flatten(),
                            envelope: Default::default(),
                            // The SAME boundary that decides the wording decides the class: past it
                            // the effect landed and disagrees with the approval; before it nothing
                            // happened and the world simply did not match, which this vocabulary
                            // has no behavior for and so leaves as the residual.
                            failure_class: Some(EffectFailureClass::of(
                                if crossed_effect_boundary {
                                    FailureSignal::ApprovedOutcomeContradicted
                                } else {
                                    FailureSignal::Unclassifiable
                                },
                            )),
                        },
                        EffectProof::Unproved,
                    ));
                }
            }
            // After more specific response assertions, every generic `require`
            // proof path must resolve NON-NULL for both REST and GraphQL. A final mutation has already
            // crossed the effect boundary, so an uncovered missing proof carries the same scalar-only
            // reconciliation evidence. Missing proof on reads and non-final guards stays value-free.
            for r in &step.require {
                let present = dotted_lookup(&resp.result, r).is_some_and(|v| !v.is_null());
                if !present {
                    let result = if crossed_effect_boundary {
                        let provider_proof = postcondition_proof(&resp.result, &scrub);
                        json!({
                            "outcome": "missing_proof_path",
                            "path": r,
                            "provider_proof": provider_proof,
                        })
                    } else {
                        json!({ "outcome": "missing_proof_path", "path": r })
                    };
                    return Ok((
                        ProviderResponse {
                            proof: None,
                            ok: false,
                            result,
                            retained: step_retains(step.retention)
                                .then(|| retain_body(&resp.result, &scrub))
                                .flatten(),
                            envelope: Default::default(),
                            // A path the ratified template DECLARES did not resolve. Whatever the
                            // provider meant, the answer no longer fits the template — the template
                            // is what has to change, not the request.
                            failure_class: Some(EffectFailureClass::of(
                                FailureSignal::ResponseShapeUnexpected,
                            )),
                        },
                        EffectProof::Unproved,
                    ));
                }
            }
            // The proof discipline `require` applies to body paths, applied to the headers the
            // template DECLARED it retains. A minted-URL step whose mint is missing is not a success
            // with a hole in it — that header is the entire product of the credentialed hop, so its
            // absence fails the step closed and NAMES it.
            for (name, value) in &retained_headers {
                if value.is_none() {
                    return Ok((
                        ProviderResponse {
                            proof: None,
                            ok: false,
                            result: json!({
                                "outcome": "missing_retained_header",
                                "header": name,
                            }),
                            retained: None,
                            envelope: Default::default(),
                            // A header the ratified template DECLARES did not arrive — the same
                            // reading as a missing `require` path: the provider's answer no longer
                            // fits the template, so the template is what has to change.
                            failure_class: Some(EffectFailureClass::of(
                                FailureSignal::ResponseShapeUnexpected,
                            )),
                        },
                        EffectProof::Unproved,
                    ));
                }
            }
            // Every capture pointer MUST resolve on a success, or an ambiguous 200 (e.g. a
            // Contents-API directory array) would flow into a later write step.
            for (cname, ptr) in &step.capture {
                let v = capture_lookup(&resp.result, ptr).ok_or_else(|| {
                    Error::Provider(format!(
                        "template {}.{} step `{}`: the success response is missing the expected \
                         capture `{cname}` (pointer `{ptr}`); an ambiguous success must never flow \
                         into a later step",
                        lt.contract.provider, lt.contract.action, step.id
                    ))
                })?;
                captures.insert(cname.clone(), v.clone());
            }
            if is_final {
                // The artifact is the body the provider sent, subject only to the step's declared
                // retention cap.
                let retained = step_retains(step.retention)
                    .then(|| retain_body(&resp.result, &scrub))
                    .flatten();
                // THE RESPONSE CONTRACT: the agent gets the
                // provider's parsed JSON body UNCHANGED — array, object, or scalar — and the
                // artifact above holds those same bytes. The token rides only the Authorization
                // header (never the body), so returning the body unchanged never echoes the
                // credential; `scrub_result` below still removes agent-submitted secret values the
                // provider echoed back, which is request-side custody, not response shaping.
                let result = resp.result;
                // What follows is BROKER-AUTHORED and rides the sibling envelope, never the
                // provider's object: a graphql `outcome` is the step's own verdict, and a retained
                // header is metadata about the response. Writing either into `result` made
                // receipt != artifact != wire, which is precisely what the tee comparison catches.
                let mut envelope = serde_json::Map::new();
                // A graphql step's success is CLASSIFIED, not
                // implied — reaching here means no errors and every `require` path resolved.
                if step.graphql_query.is_some() {
                    envelope.insert("outcome".to_string(), json!("succeeded"));
                }
                // Every entry is Some by now; the loop above already failed closed on any that
                // was not.
                for (name, value) in retained_headers {
                    if let Some(value) = value {
                        envelope.insert(name, json!(value));
                    }
                }
                let envelope = scrub_envelope(envelope, &scrub);
                let result = scrub_result(result, &scrub);
                return Ok((
                    ProviderResponse {
                        proof: None,
                        ok: true,
                        result,
                        retained,
                        envelope,
                        failure_class: None,
                    },
                    money_evaluation,
                ));
            }
        } else {
            let status = resp.result.get("status").and_then(Value::as_u64);
            // Defense in depth: a non-2xx on a step that carries a head/identity guard is
            // TERMINAL — never tolerated. The guard runs only inside `if resp.ok`, so tolerating a
            // non-2xx here would skip it and fire the next (mutating) step against an unverified state.
            // The validator already forbids expect_eq+optional_ok, so this is belt-and-suspenders.
            let has_precondition =
                !step.expect_eq.is_empty() || (!is_final && !step.expect_literal.is_empty());
            let tolerated =
                !has_precondition && status.is_some_and(|s| step.optional_ok.contains(&(s as u16)));
            if tolerated {
                // Skip this step's captures (they stay absent — a downstream `{capture?}` omits).
                continue;
            }
            // THE RESPONSE CONTRACT ON THE FAILURE PATH.
            // A failure gets the same verbatim treatment a success does: the result is the
            // executor's envelope `{"status": <http status>, "error": <the provider body>}` — the
            // status is ADDED evidence, never a narrowing — and the artifact holds those same bytes
            // subject only to the step's retention cap. The
            // provider's error classification, message, and `request_log_url` deep-link survive to
            // the receipt and the durable terminal record, so diagnosing a rejection no longer
            // needs a live curl reproduction. Agent-submitted secrets are still scrubbed.
            let mut resp = resp;
            let body = std::mem::take(&mut resp.result);
            resp.retained = step_retains(step.retention)
                .then(|| retain_body(&body, &scrub))
                .flatten();
            resp.result = scrub_result(body, &scrub);
            return Ok((resp, money_evaluation));
        }
    }
    // A validated template always has a non-empty steps list whose final step returns above.
    Err(Error::Provider(
        "template executor reached the end without a final step (validated templates cannot)"
            .into(),
    ))
}

/// Classify only the GraphQL error surface on a 2xx before response assertions. Returns
/// the sanitized failure for a present nonempty/malformed `errors`, `None` when assertions may run:
/// - a PRESENT top-level `errors` key ⇒ failure: a well-formed non-empty array carries
///   each error's sanitized `type` + `extensions.code` classification — free-text `message`s are
///   DISCARDED (a provider message can echo submitted secrets);
///   ANY other shape (object, string, number, bool, null) is a malformed GraphQL
///   failure surface and fails closed as such. The single carve-out is a literal empty array — the
///   one shape that positively asserts "no errors". Success still needs the mandatory `require`
///   proof, checked after specific assertions by the executor, so nothing rides on the carve-out.
///
/// No provider knowledge lives in the executor. The outcome classification rides the result
/// (`"outcome": "failed"`); a transport `Err` stays the broker's existing ambiguous class.
///
/// The declarative `conflict_on` expected-state classification died with `github.push_commit`, its
/// only consumer: the git-native push takes its concurrency control from the
/// upstream git server's own fast-forward rule, so there is no CAS field to report drift on.
/// Evaluate a 2xx GraphQL body against the frozen error-classification contract: every present
/// `errors` shape except an empty array fails closed.
fn graphql_errors_failure(body: &Value) -> Option<Value> {
    if let Some(errs_val) = body.get("errors") {
        match errs_val.as_array() {
            Some(errs) if errs.is_empty() => {}
            Some(_) => {
                // The VERDICT only. Under the verbatim response contract the provider's
                // own `errors` array reaches the agent and the artifact untouched, so this does not
                // rebuild a sanitized copy of it.
                return Some(json!({ "outcome": "failed" }));
            }
            None => {
                return Some(json!({
                    "outcome": "failed",
                    "classification": "malformed_graphql_errors",
                }));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Provider descriptors — the ratified data that opens the language to a provider
// ---------------------------------------------------------------------------

/// A human-ratified provider descriptor. It is the ONLY thing that lets a
/// credential ride to an origin: `egress` pins the exact scheme+host+port(s), `auth` names how the
/// token is presented, and `split` declares any request sugar. It carries NO secret — a token never
/// appears in a descriptor, its view, or its audit.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDescriptor {
    pub name: String,
    #[serde(default)]
    pub egress: Vec<String>,
    #[serde(default = "default_auth")]
    pub auth: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub split: Vec<SplitRewrite>,
    /// The GIT transport pin (git-native track). Present only for a provider whose credential may
    /// ride the hermetic system-git seam; absent means a `git:` template can never extend it. Same
    /// discipline as `egress`: the descriptor is the ONLY thing that lets a credential reach an
    /// origin, and a template carries paths under it, never an origin of its own.
    #[serde(default)]
    pub git: Option<GitTransport>,
    /// The field this provider's own credential decides, if its keys carry the answer. Absent means
    /// the provider has no such field and no template of its may declare one.
    #[serde(default)]
    pub credential_mode: Option<CredentialMode>,
}

/// A provider whose credential itself says which BOOK it operates on. Stripe issues one key per
/// mode and spells the mode in the key's prefix, so the daemon can name the mode of the credential
/// it holds without asking the provider — the derived value is a plain `"test"`/`"live"` string,
/// never a secret. The plaintext is matched inside the trusted runtime and dropped.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMode {
    /// The request field the derived value populates. A template that wants it declares the field
    /// with `source: credential`; the agent may never supply it.
    pub field: String,
    /// Credential prefix → the value the field freezes to. Validation refuses a table where one
    /// prefix extends another, so a match is unambiguous without longest-prefix arbitration.
    pub by_prefix: BTreeMap<String, String>,
}

impl CredentialMode {
    /// The value this credential decides, or `None` when no declared prefix matches. Unrecognized
    /// is never a guess: the caller fails closed.
    pub fn of(&self, token: &str) -> Option<&str> {
        self.by_prefix
            .iter()
            .find(|(prefix, _)| token.starts_with(prefix.as_str()))
            .map(|(_, value)| value.as_str())
    }
}

/// A provider's git transport pin: the exact origin `git push` may reach, and how the credential is
/// presented to it (`http.<url>.extraHeader`, injected through environment config — never argv).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitTransport {
    pub origin: String,
    #[serde(default = "default_git_auth")]
    pub auth: String,
}

fn default_git_auth() -> String {
    "basic:x-access-token".to_string()
}

/// `Authorization: Basic base64(<user>:<token>)`.
fn basic_header(user: &str, token: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}"))
    )
}

/// Request sugar: split one submitted field (e.g. `repo: "owner/name"`) into the fields a template
/// pins (`owner`, `name`). Exactly one of {`field`} XOR {all of `into`} must be present.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitRewrite {
    pub field: String,
    pub into: Vec<String>,
    #[serde(default = "default_sep")]
    pub sep: String,
}

fn default_auth() -> String {
    "bearer".to_string()
}

/// A non-empty `[a-z0-9_]` token — the shape every descriptor-declared name uses.
fn is_lower_ident(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}
fn default_sep() -> String {
    "/".to_string()
}

impl ProviderDescriptor {
    /// Parse + fail-closed validate one descriptor document.
    pub fn parse(doc: &str) -> std::result::Result<Self, String> {
        let d: Self = serde_yaml::from_str(doc)
            .map_err(|e| format!("provider descriptor is not valid: {e}"))?;
        d.validate()?;
        Ok(d)
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.name.is_empty()
            || !self
                .name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(format!(
                "provider descriptor name `{}` must be a lowercase [a-z0-9_] identifier",
                self.name
            ));
        }
        if self.egress.is_empty() {
            return Err(format!(
                "provider `{}`: egress must pin at least one origin (a descriptor is the only way a \
                 token may ride to an origin)",
                self.name
            ));
        }
        for o in &self.egress {
            let u = reqwest::Url::parse(o).map_err(|_| {
                format!(
                    "provider `{}`: egress origin `{o}` is not a valid URL",
                    self.name
                )
            })?;
            if !matches!(u.scheme(), "http" | "https") {
                return Err(format!(
                    "provider `{}`: egress origin `{o}` must be http or https",
                    self.name
                ));
            }
            if url_origin(&u).is_none() {
                return Err(format!(
                    "provider `{}`: egress origin `{o}` has no host",
                    self.name
                ));
            }
            if !matches!(u.path(), "" | "/") || u.query().is_some() {
                return Err(format!(
                    "provider `{}`: egress origin `{o}` must be a bare scheme+host[:port] origin, \
                     not a path or query",
                    self.name
                ));
            }
        }
        self.auth_shape()?;
        if let Some(git) = &self.git {
            let u = reqwest::Url::parse(&git.origin).map_err(|_| {
                format!(
                    "provider `{}`: git.origin `{}` is not a valid URL",
                    self.name, git.origin
                )
            })?;
            // A credential rides this origin, so a release binary pins it to https. `file://` is
            // admitted ONLY in the egress-testing build — the same gate `resolve_origins` applies to
            // the HTTP base override — so the whole push path can be exercised against a local bare
            // repo with no network and no process-global state.
            let scheme_ok = u.scheme() == "https"
                || (cfg!(any(test, feature = "test-egress")) && u.scheme() == "file");
            if !scheme_ok {
                return Err(format!(
                    "provider `{}`: git.origin `{}` must be https (a credential rides it)",
                    self.name, git.origin
                ));
            }
            // A `file://` test origin is a PATH by nature, so the bare-origin shape is asserted
            // only for the network scheme it exists to constrain.
            if u.scheme() == "https"
                && (url_origin(&u).is_none()
                    || !matches!(u.path(), "" | "/")
                    || u.query().is_some())
            {
                return Err(format!(
                    "provider `{}`: git.origin `{}` must be a bare scheme+host[:port] origin",
                    self.name, git.origin
                ));
            }
            AuthShape::parse(&git.auth)
                .map_err(|e| format!("provider `{}`: git.{e}", self.name))?;
        }
        if let Some(mode) = &self.credential_mode {
            if !is_lower_ident(&mode.field) {
                return Err(format!(
                    "provider `{}`: credential_mode.field `{}` must be a lowercase [a-z0-9_] \
                     identifier",
                    self.name, mode.field
                ));
            }
            if mode.by_prefix.is_empty() {
                return Err(format!(
                    "provider `{}`: credential_mode.by_prefix must name at least one prefix (an \
                     empty table can never resolve, so every request would refuse)",
                    self.name
                ));
            }
            for (prefix, value) in &mode.by_prefix {
                if prefix.is_empty() {
                    return Err(format!(
                        "provider `{}`: credential_mode.by_prefix has an empty prefix, which \
                         matches every credential",
                        self.name
                    ));
                }
                if !is_lower_ident(value) {
                    return Err(format!(
                        "provider `{}`: credential_mode value `{value}` must be a lowercase \
                         [a-z0-9_] identifier",
                        self.name
                    ));
                }
                // One prefix extending another would make the match order-dependent, and the
                // derived value decides which book a credential is allowed to touch.
                for (other, other_value) in &mode.by_prefix {
                    if other != prefix && other.starts_with(prefix.as_str()) {
                        return Err(format!(
                            "provider `{}`: credential_mode prefix `{other}` ({other_value}) \
                             extends `{prefix}` ({value}); the match must be unambiguous",
                            self.name
                        ));
                    }
                }
            }
        }
        for sp in &self.split {
            if sp.into.len() < 2 {
                return Err(format!(
                    "provider `{}`: split.into must name at least two fields",
                    self.name
                ));
            }
            if sp.sep.is_empty() {
                return Err(format!(
                    "provider `{}`: split.sep must not be empty",
                    self.name
                ));
            }
        }
        Ok(())
    }

    fn auth_shape(&self) -> std::result::Result<AuthShape, String> {
        AuthShape::parse(&self.auth)
    }
}

pub use cermet_lang::provider::{
    product_availability, ProductAvailability, PRODUCT_ENABLED_PROVIDERS,
};

/// Every provider descriptor vendored with the core (one `include_str!` per file in
/// `crates/cermet-core/providers/`). This is the shipped set every daemon boots with; github and
/// vercel are ordinary ratified data here, no longer compiled-in structs.
pub const VENDORED_PROVIDERS: &[&str] = &[
    include_str!("../providers/github.yaml"),
    include_str!("../providers/vercel.yaml"),
    include_str!("../providers/stripe.yaml"),
];

/// The vendored descriptor's credential-mode table for one provider name. Test doubles that stand
/// in for a real provider carry no descriptor of their own; this is how they model the same
/// credential-decided field the shipped descriptor declares, instead of inventing a second table.
#[cfg(any(test, feature = "test-double"))]
pub fn vendored_credential_mode(name: &str) -> Option<&'static CredentialMode> {
    static TABLES: OnceLock<HashMap<String, CredentialMode>> = OnceLock::new();
    TABLES
        .get_or_init(|| {
            VENDORED_PROVIDERS
                .iter()
                .filter_map(|doc| {
                    let d = ProviderDescriptor::parse(doc)
                        .expect("vendored provider descriptor must parse (packaging bug)");
                    d.credential_mode.map(|mode| (d.name, mode))
                })
                .collect()
        })
        .get(name)
}

/// The names of the vendored (shipped) providers — the fallback "is this an egress-pinned, real
/// provider?" set for a `DefaultContractSource` with no broker in hand. Derived by pure parse.
pub fn vendored_provider_names() -> &'static HashSet<String> {
    static NAMES: OnceLock<HashSet<String>> = OnceLock::new();
    NAMES.get_or_init(|| {
        VENDORED_PROVIDERS
            .iter()
            .map(|doc| {
                ProviderDescriptor::parse(doc)
                    .expect("vendored provider descriptor must parse (packaging bug)")
                    .name
            })
            .collect()
    })
}

/// This descriptor's registry ceiling: an egress-pinned HTTP provider a template may extend.
pub fn descriptor_ceiling(d: &ProviderDescriptor) -> crate::templates::ProviderCeiling {
    match d.git {
        Some(_) => crate::templates::ProviderCeiling::HttpAndGit,
        None => crate::templates::ProviderCeiling::Http,
    }
}

/// The vendored providers as a name → ceiling map — the fallback extensible set a bare
/// [`TemplateRegistry::new`](crate::templates::TemplateRegistry::new) uses (so github/vercel load as
/// HTTP.
pub fn vendored_provider_ceilings() -> &'static HashMap<String, crate::templates::ProviderCeiling> {
    static CEILINGS: OnceLock<HashMap<String, crate::templates::ProviderCeiling>> = OnceLock::new();
    CEILINGS.get_or_init(|| {
        VENDORED_PROVIDERS
            .iter()
            .map(|doc| {
                let d = ProviderDescriptor::parse(doc)
                    .expect("vendored provider descriptor must parse (packaging bug)");
                (d.name.clone(), descriptor_ceiling(&d))
            })
            .collect()
    })
}

/// The descriptor's pinned git origin + auth shape. Descriptor data ONLY: there is deliberately no
/// environment override here. A test supplies a local `file://` origin through a
/// synthetic descriptor, which is per-broker and therefore safe under any test runner, where a
/// process-global env var raced between parallel threads.
fn resolve_git_transport(d: &ProviderDescriptor) -> Option<(String, AuthShape)> {
    let git = d.git.as_ref()?;
    let auth = AuthShape::parse(&git.auth).unwrap_or_default();
    Some((git.origin.clone(), auth))
}

/// Resolve a descriptor's URL base + egress allowlist, honoring the per-provider test override
/// `CERMET_<NAME>_BASE_URL` (only under `test`/`test-egress`).
fn resolve_origins(d: &ProviderDescriptor) -> (String, Vec<String>) {
    if d.egress.is_empty() {
        return (String::new(), Vec::new());
    }
    let var = format!("CERMET_{}_BASE_URL", d.name.to_ascii_uppercase());
    let egress_enabled = cfg!(any(test, feature = "test-egress"));
    match std::env::var(&var).ok() {
        Some(v) if egress_enabled => (v.clone(), vec![v]),
        _ => (d.egress[0].clone(), d.egress.clone()),
    }
}

// ---------------------------------------------------------------------------
// GenericProvider — one data-driven provider, wholly defined by a ratified descriptor
// ---------------------------------------------------------------------------

/// A provider with NO compiled-in Rust struct: its origin(s), auth shape, static headers, and request
/// sugar all come from a ratified [`ProviderDescriptor`]; its actions come from
/// this broker's ratified templates. github and vercel are just two of these.
pub struct GenericProvider {
    name: String,
    egress: Egress,
    base: String,
    auth: AuthShape,
    headers: Vec<(String, String)>,
    split: Vec<SplitRewrite>,
    /// True for an egress-pinned HTTP provider.
    brokers_credential: bool,
    /// The descriptor's GIT transport pin, if it declared one: the origin `git push` may reach and
    /// the auth shape the credential is presented in. `None` means this provider can never carry a
    /// credential over the git seam (and a `git:` template for it never loaded).
    git_transport: Option<(String, AuthShape)>,
    /// The hermetic git runner's settings — pinned binary, quarantine root, timeout, retention.
    git: crate::git::GitConfig,
    /// The descriptor's credential-mode table, if it declared one: the field this provider's own
    /// key decides, and the prefixes that decide it.
    credential_mode: Option<CredentialMode>,
    templates: Arc<TemplateRegistry>,
}

impl GenericProvider {
    /// The production constructor: env-resolved base + the broker's template registry.
    pub fn from_descriptor(
        d: ProviderDescriptor,
        templates: Arc<TemplateRegistry>,
        git: crate::git::GitConfig,
    ) -> Self {
        let brokers_credential = true;
        let (base, origins) = resolve_origins(&d);
        // auth was validated at parse; the default is a safe fallback if a descriptor is built raw.
        let auth = d.auth_shape().unwrap_or_default();
        let git_transport = resolve_git_transport(&d);
        Self {
            name: d.name,
            egress: Egress::new_multi(&origins),
            base,
            auth,
            headers: d.headers.into_iter().collect(),
            split: d.split,
            brokers_credential,
            git_transport,
            git,
            credential_mode: d.credential_mode,
            templates,
        }
    }

    #[cfg(test)]
    fn from_descriptor_with_base(
        d: ProviderDescriptor,
        base: String,
        templates: Arc<TemplateRegistry>,
    ) -> Self {
        let brokers_credential = true;
        let auth = d.auth_shape().unwrap_or_default();
        let git_transport = resolve_git_transport(&d);
        Self {
            name: d.name,
            egress: Egress::new(&base),
            base,
            auth,
            headers: d.headers.into_iter().collect(),
            split: d.split,
            brokers_credential,
            git_transport,
            git: crate::git::GitConfig::at(std::env::temp_dir()),
            credential_mode: d.credential_mode,
            templates,
        }
    }

    /// Assemble the credential binding for one git invocation. The header is built HERE, inside the
    /// custody boundary, and moved straight into the child's environment; it never becomes an
    /// argument, a URL component, a view, or a log line.
    fn git_credential(&self, url: &str, token: &str) -> crate::git::GitCredential {
        let auth = self
            .git_transport
            .as_ref()
            .map(|(_, auth)| auth)
            .unwrap_or(&self.auth);
        let header = match auth {
            AuthShape::Bearer => format!("Authorization: Bearer {token}"),
            AuthShape::Token => format!("Authorization: token {token}"),
            AuthShape::Basic(user) => format!("Authorization: {}", basic_header(user, token)),
            AuthShape::Header(name) => format!("{name}: {token}"),
        };
        crate::git::GitCredential {
            url: url.to_string(),
            header,
        }
    }

    /// The credentialed hop: carry an ALREADY-AUTHORIZED ref update from the daemon's mirror to
    /// the upstream. This is the one step that needs the vaulted secret, and the only place Cermet
    /// touches the network for a push.
    ///
    /// Everything upstream of here belongs to git: the agent pushed into the mirror over git's own
    /// wire protocol, `receive-pack` parsed the pack and migrated the objects, and git's `update`
    /// hook is what asked the broker for this decision. By the time this runs the objects are in
    /// the mirror and the ONLY thing left is the hop.
    ///
    /// A plain push — no `--force-with-lease`, no hand-carried compare-and-swap: the upstream
    /// server's fast-forward rule is the concurrency control, and its refusal rides git's error
    /// channel back into the agent's `git push` output. Because the hook confirms only on our
    /// success, the mirror ref advances iff the upstream's did.
    fn execute_git(
        &self,
        spec: &crate::templates::GitSpec,
        call: ProviderCall,
    ) -> Result<ProviderResponse> {
        let Some((origin, _)) = &self.git_transport else {
            return Err(Error::Provider(format!(
                "{}: no git transport origin is pinned by the ratified descriptor",
                self.name
            )));
        };
        let Some(mirror) = call.git_mirror else {
            return Err(Error::Provider(
                "a git verb is decided by git's update hook on a daemon-held mirror; it has no \
                 agent-facing request path"
                    .into(),
            ));
        };

        // The upstream path: literal segments plus frozen, path-validated identity pins. Both step
        // kinds address the upstream the same way.
        let remote_path = match (&spec.push, &spec.fetch) {
            (Some(push), _) => &push.remote_path,
            (_, Some(fetch)) => &fetch.remote_path,
            _ => {
                return Err(Error::Provider(
                    "a git verb declares no step (the validator refuses this shape)".into(),
                ));
            }
        };
        let mut path = String::new();
        for seg in crate::templates::segments(remote_path)
            .map_err(|m| Error::Provider(format!("git remote path {m}")))?
        {
            match seg {
                Segment::Literal(literal) => path.push_str(&literal),
                Segment::Placeholder(ph) => {
                    let value = call.resource.req_str(&ph.name)?;
                    validate_path_segment(&ph.name, value)?;
                    path.push_str(value);
                }
            }
        }
        let url = format!("{origin}{path}");

        let credential = self.git_credential(&url, call.token);
        let repository = format!(
            "{}/{}",
            call.resource.req_str("owner")?,
            call.resource.req_str("name")?
        );

        // ---- the FETCH effect: refresh this host's mirror from the upstream ----
        if let Some(_fetch) = &spec.fetch {
            let refresh =
                crate::git::refresh_from_upstream(&self.git, mirror, &url, Some(&credential))?;
            let result = json!({
                "repository": repository,
                "refreshed": true,
                "transport": "git",
                "refs": refresh
                    .refs
                    .iter()
                    .map(|r| json!({ "ref": r.refname, "from": r.from, "to": r.to }))
                    .collect::<Vec<_>>(),
                "ref_count": refresh.total,
                "truncated": refresh.truncated,
            });
            return Ok(ProviderResponse {
                proof: None,
                ok: true,
                result,
                envelope: serde_json::Map::new(),
                retained: None,
                failure_class: None,
            });
        }

        let Some(step) = &spec.push else {
            return Err(Error::Provider(
                "a git verb declares no step (the validator refuses this shape)".into(),
            ));
        };
        // The verb's own namespace, from the slot it declared. The runner never guesses: a
        // `branch:` verb moves `refs/heads/`, a `tag:` verb moves `refs/tags/`, and the fully
        // qualified name is what both the hop and the receipt carry.
        let refname = match (&step.branch, &step.tag) {
            (Some(branch), None) => format!("refs/heads/{}", call.resource.req_str(branch)?),
            (None, Some(tag)) => format!("refs/tags/{}", call.resource.req_str(tag)?),
            _ => {
                return Err(Error::Provider(
                    "a git push step names exactly one ref namespace (the validator refuses this \
                     shape)"
                        .into(),
                ));
            }
        };
        let new_oid = call.resource.req_str(&step.new_oid)?;
        let mirror_old_oid =
            step.mirror_old_oid
                .as_deref()
                .and_then(|field| match call.resource.scalar(field) {
                    Some(Scalar::Str(value)) => Some(value.as_str()),
                    _ => None,
                });

        let run = crate::git::carry_to_upstream(
            &self.git,
            mirror,
            &url,
            Some(&credential),
            new_oid,
            &refname,
        )?;

        // The receipt is DERIVED from broker-held data — the hook's frozen tuple plus the
        // upstream's own account of what it did — never echoed from a request and never parsed out
        // of provider prose.
        //
        // `upstream_old_oid` is the oid the UPSTREAM moved from, read out of git's
        // machine-readable `--porcelain` line, because that is the honest answer to "what did my
        // agent change on GitHub". `mirror_old_oid` is kept beside it, separately labelled, because
        // it is a different fact: the tip the daemon's mirror held. With no fetch refresh the two
        // legitimately differ (a third party's direct push; a re-created mirror after aging), and
        // conflating them made the receipt misstate the transition.
        let transition = crate::git::parse_upstream_transition(&run.stdout, &refname);
        let result = json!({
            "repository": repository,
            "ref": refname,
            "new_oid": new_oid,
            "upstream_old_oid": transition.as_ref().and_then(|t| t.from.clone()),
            "upstream_created_ref": transition.as_ref().map(|t| t.created),
            // A deletion is an update to the zero oid: `new_oid` already names the transition, and
            // this is the upstream's own confirmation that the ref is gone.
            "upstream_deleted_ref": transition.as_ref().map(|t| t.deleted),
            "mirror_old_oid": mirror_old_oid,
            "carried": true,
            "transport": "git",
            "porcelain": String::from_utf8_lossy(&run.stdout).trim().to_string(),
        });
        Ok(ProviderResponse {
            proof: None,
            ok: true,
            result,
            failure_class: None,
            envelope: serde_json::Map::new(),
            // Nothing to retain: there is no provider body, only broker-held facts already in the
            // receipt (`retention: none` is this kind's declared response contract).
            retained: None,
        })
    }

    fn header_refs(&self) -> Vec<(&str, &str)> {
        self.headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    /// Apply the descriptor's split sugar to the raw resource (e.g. `repo` → `owner`+`name`).
    fn apply_split(&self, obj: &mut serde_json::Map<String, Value>) -> Result<()> {
        for sp in &self.split {
            let has_field = obj.contains_key(&sp.field);
            let present: usize = sp.into.iter().filter(|k| obj.contains_key(*k)).count();
            if has_field {
                if present > 0 {
                    return Err(Error::Invalid(format!(
                        "{} resource is ambiguous: `{}` cannot be combined with {:?}",
                        self.name, sp.field, sp.into
                    )));
                }
                let raw = obj.get(&sp.field).and_then(Value::as_str).ok_or_else(|| {
                    Error::Invalid(format!("{} `{}` must be a string", self.name, sp.field))
                })?;
                let parts: Vec<String> = raw.split(sp.sep.as_str()).map(str::to_string).collect();
                if parts.len() != sp.into.len() {
                    return Err(Error::Invalid(format!(
                        "{} `{}` must be exactly `{}` ({} parts joined by `{}`)",
                        self.name,
                        sp.field,
                        sp.into.join(&sp.sep),
                        sp.into.len(),
                        sp.sep
                    )));
                }
                obj.remove(&sp.field);
                for (k, val) in sp.into.iter().zip(parts) {
                    obj.insert(k.clone(), Value::String(val));
                }
            } else if present != sp.into.len() {
                return Err(Error::Invalid(format!(
                    "{} resource needs {:?} (or `{}: \"{}\"`)",
                    self.name,
                    sp.into,
                    sp.field,
                    sp.into.join(&sp.sep)
                )));
            }
        }
        Ok(())
    }
}

pub use cermet_lang::provider::StripeCustomerResolver;

impl Provider for GenericProvider {
    fn name(&self) -> &str {
        &self.name
    }
    fn supported_actions(&self) -> &'static [&'static str] {
        // A descriptor-driven provider ships NO compiled-in built-ins; every action is a ratified
        // template this broker's registry loaded (reachability is per-broker, never a static list).
        &[]
    }
    fn supports_action(&self, action: &str) -> bool {
        self.templates.loaded(&self.name, action).is_some()
    }
    fn is_money_action(&self, action: &str) -> bool {
        self.templates
            .loaded(&self.name, action)
            .is_some_and(|loaded| loaded.template.is_money())
    }
    fn requires_credential(&self) -> bool {
        self.brokers_credential
    }
    fn action_contract(&self, action: &str) -> Option<&'static ActionContract> {
        self.templates
            .loaded(&self.name, action)
            .map(|lt| lt.contract)
    }
    fn rewrite_resource(
        &self,
        action: &str,
        mut obj: serde_json::Map<String, Value>,
    ) -> Result<serde_json::Map<String, Value>> {
        self.apply_split(&mut obj)?;
        // A templated action's path fields and field sizes validate at REQUEST time
        // (after any split sugar) — a bad path or oversized payload denies before a grant can exist.
        //
        // Provider-resolved (evidence-output) fields are NOT refused here. This rewrite
        // canonicalizes the COMPLETE merged resource at execute/claim time — where those fields are
        // legitimately present — and the symbolic prefilter probes rule-pinned values through it.
        // The request-side refusal of pre-supplied outputs is mint's explicit folded-fields check,
        // which runs before any partial canonicalization.
        if let Some(lt) = self.templates.loaded(&self.name, action) {
            validate_template_resource(lt, &obj)?;
        }
        Ok(obj)
    }
    fn resolve_request(
        &self,
        profile: &'static EvidenceProfile,
        token: &str,
        partial: &CanonicalResource,
    ) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
        if profile.provider != self.name {
            return Err(EvidenceFailure::new(EvidenceFailureClass::Integrity));
        }
        if self.name == "stripe" {
            stripe_evidence::resolve(self, profile.resolver, token, partial)
        } else {
            Err(EvidenceFailure::new(EvidenceFailureClass::Integrity))
        }
    }
    fn credential_mode_field(&self) -> Option<&str> {
        self.credential_mode
            .as_ref()
            .map(|mode| mode.field.as_str())
    }
    fn credential_mode(&self, token: &str) -> Option<&str> {
        self.credential_mode
            .as_ref()
            .and_then(|mode| mode.of(token))
    }
    fn canonicalize_request_field(
        &self,
        profile: &'static CanonicalizationProfile,
        token: &str,
        supplied: &str,
    ) -> std::result::Result<String, EvidenceFailure> {
        if profile.provider != self.name {
            return Err(EvidenceFailure::new(EvidenceFailureClass::Integrity));
        }
        if self.name == "vercel" {
            vercel_canonicalize::canonicalize(self, profile.resolver, token, supplied)
        } else {
            Err(EvidenceFailure::new(EvidenceFailureClass::Integrity))
        }
    }
    fn check_preconditions(
        &self,
        preconditions: &[&'static crate::preconditions::CompiledPrecondition],
        token: &str,
        resource: &CanonicalResource,
    ) -> std::result::Result<(), crate::preconditions::PreconditionFailure> {
        if self.name != "stripe"
            || preconditions
                .iter()
                .any(|precondition| precondition.provider != self.name)
        {
            return Err(crate::preconditions::PreconditionFailure::new(
                preconditions
                    .first()
                    .map_or("unknown", |precondition| precondition.name),
                crate::preconditions::PreconditionFailureClass::Integrity,
            ));
        }
        stripe_preconditions::check(self, preconditions, token, resource)
    }
    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        let Some(lt) = self.templates.loaded(&self.name, call.action) else {
            return Err(Error::Provider(format!(
                "{} cannot {}",
                self.name, call.action
            )));
        };
        if let Some(spec) = lt.template.git_spec() {
            // The git carrier verb declares neither discipline bit; a call that arrived carrying one
            // is a broker/template disagreement, and running the hop anyway would silently drop it.
            if call.discipline.prove_effect || call.discipline.idempotency_key.is_some() {
                return Err(Error::Integrity(
                    "the git execution kind cannot honour the requested execution discipline"
                        .into(),
                ));
            }
            return self.execute_git(spec, call);
        }
        let mut headers = self.header_refs();
        if let Some(key) = call.discipline.idempotency_key {
            if key.is_empty() {
                return Err(Error::Integrity(
                    "an execution discipline declaring a key supplied an empty one".into(),
                ));
            }
            // Split the first word to keep the authority-inertness source guard unambiguous.
            headers.push((concat!("Idem", "potency-Key"), key));
        }
        // The compiled success contract is resolved ONLY when the discipline asks for proof — the
        // broker read that bit off the same ratified template this adapter is about to run.
        let success_contract = if call.discipline.prove_effect {
            Some(
                crate::mutation_success::exact(&self.name, call.action).ok_or_else(|| {
                    Error::Integrity(
                        "the proving discipline has no compiled success contract for this provider/action"
                            .into(),
                    )
                })?,
            )
        } else {
            None
        };
        execute_template(
            &self.egress,
            &self.base,
            lt,
            call,
            &headers,
            &self.auth,
            success_contract,
        )
    }
}

// ---------------------------------------------------------------------------
// Test doubles for github/vercel: the retired compiled-in structs survive ONLY as #[cfg(test)]
// constructors that build a GenericProvider from the vendored descriptor, plus the byte-equivalence
// oracles the template port is checked against. Production has no github/vercel struct.
// ---------------------------------------------------------------------------

#[cfg(test)]
fn github_descriptor() -> ProviderDescriptor {
    ProviderDescriptor::parse(VENDORED_PROVIDERS[0]).expect("vendored github descriptor parses")
}

#[cfg(test)]
fn vercel_descriptor() -> ProviderDescriptor {
    ProviderDescriptor::parse(VENDORED_PROVIDERS[1]).expect("vendored vercel descriptor parses")
}

#[cfg(test)]
struct GithubProvider;
#[cfg(test)]
impl GithubProvider {
    fn with_base(base: String) -> GenericProvider {
        GenericProvider::from_descriptor_with_base(
            github_descriptor(),
            base,
            Arc::new(TemplateRegistry::new()),
        )
    }

    fn with_base_and_templates(base: String, templates: Arc<TemplateRegistry>) -> GenericProvider {
        GenericProvider::from_descriptor_with_base(github_descriptor(), base, templates)
    }
}

#[cfg(test)]
#[allow(dead_code)]
struct VercelProvider;
#[cfg(test)]
#[allow(dead_code)]
impl VercelProvider {
    #[allow(clippy::new_ret_no_self)]
    fn new() -> GenericProvider {
        GenericProvider::from_descriptor(
            vercel_descriptor(),
            Arc::new(TemplateRegistry::new()),
            crate::git::GitConfig::at(std::env::temp_dir()),
        )
    }
    fn with_base(base: String) -> GenericProvider {
        GenericProvider::from_descriptor_with_base(
            vercel_descriptor(),
            base,
            Arc::new(TemplateRegistry::new()),
        )
    }
    fn with_base_and_templates(base: String, templates: Arc<TemplateRegistry>) -> GenericProvider {
        GenericProvider::from_descriptor_with_base(vercel_descriptor(), base, templates)
    }
}

#[cfg(test)]
impl GenericProvider {
    /// The hand-written GitHub `read_repo` executor retained only as the request oracle for the
    /// template path. It is never reachable from production dispatch.
    fn reference_read_repo_execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        let h = self.header_refs();
        let owner = call.resource.req_str("owner")?;
        let name = call.resource.req_str("name")?;
        http_call(
            &self.egress,
            Method::GET,
            format!("{}/repos/{owner}/{name}", self.base),
            call.token,
            None,
            &[],
            &self.auth,
            &h,
        )
    }
}

// ---------------------------------------------------------------------------
// Offline test doubles (never compiled into a release binary — see `default_registry`)
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-double"))]
fn mock_canonicalize(supported: &[&str], action: &str, raw: &Value) -> Result<CanonicalResource> {
    if !supported.contains(&action) {
        return Err(Error::Provider(format!(
            "mock: unsupported action `{action}`"
        )));
    }
    let obj = match raw {
        Value::Null => serde_json::Map::new(),
        Value::Object(m) => m.clone(),
        _ => return Err(Error::Invalid("resource must be a JSON object".into())),
    };
    let mut fields = BTreeMap::new();
    for (k, v) in &obj {
        fields.insert(k.clone(), Scalar::infer(k, v)?);
    }
    Ok(CanonicalResource::from_map(fields))
}

#[cfg(any(test, feature = "test-double"))]
struct MockVercel;
#[cfg(any(test, feature = "test-double"))]
impl Provider for MockVercel {
    fn name(&self) -> &str {
        "mock-vercel"
    }
    fn supported_actions(&self) -> &'static [&'static str] {
        &[
            "create_project",
            "deploy",
            "set_env_var",
            "read_logs",
            "deploy_production",
            "delete_project",
        ]
    }
    fn action_contract(&self, action: &str) -> Option<&'static ActionContract> {
        self.supported_actions()
            .contains(&action)
            .then_some(&MOCK_CONTRACT)
    }
    fn canonicalize(&self, action: &str, raw: &Value) -> Result<CanonicalResource> {
        mock_canonicalize(self.supported_actions(), action, raw)
    }
    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        debug_assert!(!call.token.is_empty());
        let result = match call.action {
            "deploy" => {
                json!({ "url": "https://demo-preview.example.dev", "state": "READY" })
            }
            "create_project" => json!({ "project": "demo", "created": true }),
            "set_env_var" => json!({ "applied": true }),
            "read_logs" => json!({ "lines": ["build ok"] }),
            other => return Err(Error::Provider(format!("mock-vercel cannot {other}"))),
        };
        Ok(ProviderResponse {
            proof: None,
            ok: true,
            result,
            retained: None,
            envelope: Default::default(),
            failure_class: None,
        })
    }
}

#[cfg(any(test, feature = "test-double"))]
struct MockGithub;
#[cfg(any(test, feature = "test-double"))]
impl Provider for MockGithub {
    fn name(&self) -> &str {
        "mock-github"
    }
    fn supported_actions(&self) -> &'static [&'static str] {
        &[
            "read_repo",
            "create_branch",
            "open_pull_request",
            "push_branch",
            "merge_pull_request",
        ]
    }
    fn action_contract(&self, action: &str) -> Option<&'static ActionContract> {
        self.supported_actions()
            .contains(&action)
            .then_some(&MOCK_CONTRACT)
    }
    fn canonicalize(&self, action: &str, raw: &Value) -> Result<CanonicalResource> {
        mock_canonicalize(self.supported_actions(), action, raw)
    }
    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        debug_assert!(!call.token.is_empty());
        let result = match call.action {
            "read_repo" => json!({ "repo": "demo", "default_branch": "main" }),
            "create_branch" => json!({ "branch": "cermet/demo", "created": true }),
            "open_pull_request" => json!({ "number": 1, "url": "https://example/pull/1" }),
            "push_branch" => json!({ "pushed": true }),
            other => return Err(Error::Provider(format!("mock-github cannot {other}"))),
        };
        Ok(ProviderResponse {
            proof: None,
            ok: true,
            result,
            retained: None,
            envelope: Default::default(),
            failure_class: None,
        })
    }
}

#[cfg(test)]
mod tests;
