use super::*;

/// The least-privilege scope shape for a single verb.
pub(super) struct SuggestionShape {
    #[cfg(test)]
    pub(super) pinned: BTreeMap<String, Value>,
    pub(super) names: BTreeSet<String>,
    pub(super) key: String,
}

/// Redact every `FieldClass::Secret` field of `resource` to the fixed marker. `contract` is resolved
/// by the CALLER through the broker's registry (the ratified template that owns the action) — so a
/// template Secret field is always redacted. The contract is non-optional: an unresolved contract can
/// never reach here (it becomes `Vanished`, a full suppression), so redaction never silently falls
/// through to the raw resource.
pub(super) fn redact_secret_fields(contract: &ActionContract, mut resource: Value) -> Value {
    if let Some(obj) = resource.as_object_mut() {
        for (k, v) in obj.iter_mut() {
            if contract.field_class(k) == Some(FieldClass::Secret) {
                *v = Value::String(SECRET_FIELD_MARKER.to_string());
            }
        }
    }
    resource
}

/// Project the conventional environment label only when doing so cannot bypass the contract's Secret
/// classification. The resource remains the signed source; callers decide whether a vanished contract
/// should suppress the projection entirely.
pub(super) fn projected_environment(
    contract: Option<&ActionContract>,
    resource: &Value,
) -> Option<String> {
    if contract
        .is_some_and(|contract| contract.field_class("environment") == Some(FieldClass::Secret))
    {
        return None;
    }
    resource
        .as_object()
        .and_then(|fields| fields.get("environment"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// The fixed marker a `FieldClass::Secret` field's VALUE is replaced with on every read/audit
/// surface.
pub(super) const SECRET_FIELD_MARKER: &str = "[redacted: secret]";

/// The longest string value a denial row keeps verbatim; the same bound as `PAYLOAD_SHOWN_MAX_BYTES`
/// below — what is readable at a glance is what is worth storing on a row nothing executes.
const RETAINED_VALUE_MAX_BYTES: usize = 256;

/// What a deny stores when it has no field classes to redact against — an action that resolves to
/// no contract, or a record taken before canonicalization. The submitted values are RETAINED (that
/// row is the only record of what was asked for) but every string is capped, so one request cannot
/// write an unbounded blob into `state.db`. Non-string scalars carry no size; nested values are
/// capped in place. Accepted residual: an agent can plant a capped self-labelled secret at rest
/// this way, and the cap plus daemon-uid ownership of `state.db` is the whole mitigation.
pub(super) fn cap_field_values(resource: Value) -> Value {
    match resource {
        Value::String(s) if s.len() > RETAINED_VALUE_MAX_BYTES => {
            let mut end = RETAINED_VALUE_MAX_BYTES;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            Value::String(format!("{}… [truncated: {} bytes]", &s[..end], s.len()))
        }
        Value::Array(items) => Value::Array(items.into_iter().map(cap_field_values).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(k, v)| (k, cap_field_values(v)))
                .collect(),
        ),
        other => other,
    }
}

/// A free payload above these bounds never renders its bytes in a grant view — the card shows
/// `[payload not shown: N bytes, M lines]` instead. Anything small enough to read at a glance (a
/// commit message) renders as-is. View-only: the frozen `resource_json` — what executes — is
/// untouched.
const PAYLOAD_SHOWN_MAX_BYTES: usize = 256;
const PAYLOAD_SHOWN_MAX_LINES: usize = 4;

pub(super) fn summarize_large_payloads(contract: &ActionContract, mut resource: Value) -> Value {
    if let Some(obj) = resource.as_object_mut() {
        for (k, v) in obj.iter_mut() {
            if contract.field_class(k) != Some(FieldClass::FreePayload) {
                continue;
            }
            let Some(s) = v.as_str() else { continue };
            let lines = s.lines().count();
            if s.len() > PAYLOAD_SHOWN_MAX_BYTES || lines > PAYLOAD_SHOWN_MAX_LINES {
                *v = Value::String(format!(
                    "[payload not shown: {} bytes, {} lines]",
                    s.len(),
                    lines
                ));
            }
        }
    }
    resource
}

/// The marker every field value of a frozen grant is replaced with when its ratified template is no
/// longer live. Full-resource suppression: the field VALUES are dropped (keys survive — they carry
/// no data) because with the template gone or edited we no longer know which fields were Secret, so
/// selective redaction is impossible and the honest fail-closed answer is to render none.
pub(super) const FROZEN_TEMPLATE_GONE: &str =
    "[redacted: authorized under a template that is no longer live]";

/// How a grant READ view renders its frozen resource. `Live` carries a resolved contract by
/// construction — a NULL-hash grant for a template-extensible action with no live contract (e.g. a
/// legacy set_env_var row now that the built-in is retired) can only be `Vanished`, never a `Live`
/// with nothing to redact against, so the unredacted-secret path is unrepresentable.
pub(super) enum FrozenContract {
    /// Redact Secret fields with this contract: a template grant whose frozen content hash still
    /// equals the live template's, or (historically) a built-in grant with a compiled-in contract.
    Live(&'static ActionContract),
    /// No contract, but the resource is safe to render raw: a provider the template system cannot
    /// extend (files/mock) has no Secret fields.
    Raw,
    /// The grant froze a template that is gone or edited, or is a legacy template-extensible action
    /// whose contract is now retired — suppress the whole resource, fail closed.
    Vanished,
}

impl FrozenContract {
    /// Funnel a template-extensible lookup: a resolved contract redacts; an unresolved one (`None`)
    /// suppresses. Used where a NULL / matching-hash row MUST have a live contract — so absence is a
    /// fail-closed `Vanished`, never a raw render.
    pub(super) fn redact_or_suppress(contract: Option<&'static ActionContract>) -> Self {
        match contract {
            Some(c) => FrozenContract::Live(c),
            None => FrozenContract::Vanished,
        }
    }
}

pub(super) fn suppress_resource(mut resource: Value) -> Value {
    match &mut resource {
        Value::Object(obj) => {
            for v in obj.values_mut() {
                *v = Value::String(FROZEN_TEMPLATE_GONE.to_string());
            }
            resource
        }
        // A null resource carries nothing; anything else non-object is suppressed whole.
        Value::Null => resource,
        _ => Value::String(FROZEN_TEMPLATE_GONE.to_string()),
    }
}

/// `contract` is resolved by the caller through the broker's registry (the ratified template that
/// owns the action, or a registered provider seam) — so the shaper scopes a template action's
/// execution targets uniformly.
pub(super) fn widening_shape(
    contract: Option<&ActionContract>,
    provider: &str,
    action: &str,
    resource: &Value,
) -> std::result::Result<Option<SuggestionShape>, String> {
    // Gate on the CONTRACT CAPABILITY, not the provider name: a pinned allow is suggestable iff the
    // resolved contract can be pinned down to exactly one resource — every execution target is an
    // `ExactResourcePin` field. This subsumes the old github/vercel-only gate byte-for-byte — their
    // contracts all pin their execution targets — and shapes a provider-seam contract (the daemon
    // `files` provider) the same way. A contract that resolves but cannot fully pin its execution
    // targets (target-less, or MIXED with an Unbound target) -> the not_suggestable path; no contract
    // at all -> silent skip (an uncontracted action can't be shaped).
    let Some(contract) = contract else {
        return Ok(None);
    };
    if !contract.has_fully_pinned_execution_targets() {
        return Err("no scopable execution target; a bare allow is the only rule shape".into());
    }
    let Value::Object(obj) = resource else {
        return Ok(None);
    };

    let mut pinned: BTreeMap<String, Value> = BTreeMap::new();
    for t in contract.execution_targets.iter().copied() {
        match obj.get(t) {
            Some(v) => {
                pinned.insert(t.to_string(), v.clone());
            }
            None => return Ok(None),
        }
    }
    for f in contract.schema {
        if f.binding == AllowBinding::ExactResourcePin {
            match obj.get(f.name) {
                Some(v) => {
                    pinned.insert(f.name.to_string(), v.clone());
                }
                // An OPTIONAL exact-pin field ABSENT from this run is pinned to `null` — an
                // absent-field pin, so the learned allow is shape-faithful (covers only the plain
                // shape) AND still auto-allows the omitting repeat under the broker's coverage net.
                None if !f.required => {
                    pinned.insert(f.name.to_string(), Value::Null);
                }
                None => {}
            }
        }
    }

    let mut names: BTreeSet<String> = BTreeSet::new();
    if contract.has_schema_field("name") {
        if let Some(n) = obj.get("name").and_then(Value::as_str) {
            names.insert(n.to_string());
        }
    }
    let pinned_json = serde_json::to_string(&pinned).unwrap_or_default();
    let key = format!("{provider}\u{0}{action}\u{0}{pinned_json}");

    Ok(Some(SuggestionShape {
        #[cfg(test)]
        pinned,
        names,
        key,
    }))
}

/// The next move for a request that omitted a required field. An `invalid` deny is a
/// correct answer, but it was a silent one — every other deny class hands the caller something to
/// do (a policy deny carries the widening sentence), while this one said only that the request did
/// not canonicalize. The canonicalize error names the FIRST absent field and stops; the hint names
/// them ALL, so one round trip fixes the request instead of one field per round trip.
///
/// `None` when there is nothing to say: an unknown verb (no contract), a resource that is not an
/// object at all (a different story, and the reason already tells it), or no missing field — a hint
/// that guesses is worse than no hint. Names only; the caller's own values never appear here.
pub(super) fn missing_required_fields_hint(
    contract: Option<&'static ActionContract>,
    resource: &Value,
) -> Option<String> {
    let object = resource.as_object()?;
    let contract = contract?;
    let missing: Vec<&str> = contract
        .schema
        .iter()
        .filter(|decl| decl.required && !object.contains_key(decl.name))
        .map(|decl| decl.name)
        .collect();
    if missing.is_empty() {
        return None;
    }
    let named = missing
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "missing required {} {named} — resend the request naming {}; `cermet catalog` prints the \
         verb's full signature",
        if missing.len() == 1 {
            "field"
        } else {
            "fields"
        },
        if missing.len() == 1 { "it" } else { "them" },
    ))
}

pub(super) fn canonical_resource(req: &CapabilityRequest) -> Result<Value> {
    let mut resource = match &req.resource {
        Value::Null => json!({}),
        Value::Object(_) => req.resource.clone(),
        other => {
            return Err(Error::Invalid(format!(
                "resource must be a JSON object, got {}",
                crate::contract::json_shape(other)
            )))
        }
    };
    let obj = resource.as_object_mut().expect("resource is an object");
    if let Some(env) = &req.environment {
        match obj.get("environment") {
            Some(existing) => {
                let existing = existing.as_str().ok_or_else(|| {
                    Error::Invalid("resource.environment must be a string".into())
                })?;
                if existing != env {
                    return Err(Error::Invalid(
                        "conflicting environment: the request and the resource specify \
                         different environments"
                            .to_string(),
                    ));
                }
            }
            None => {
                obj.insert("environment".into(), Value::String(env.clone()));
            }
        }
    }
    Ok(resource)
}

pub(super) fn credential_ref(provider: &str) -> String {
    format!("cred_{}", provider.replace('-', "_"))
}

/// Resolve a stored `"uid:N"` principal id to its OS username via the passwd db (getpwuid_r). Returns
/// `None` for a malformed id, an unknown uid, or a lookup error — never a guess. Process-cached: a uid
/// -> name mapping is stable for a run, so we resolve each uid once (the operator views can list many
/// rows for the same principal).
pub(super) fn resolve_principal_label(principal_id: &str) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(hit) = cache.lock().unwrap().get(principal_id) {
        return hit.clone();
    }
    let resolved = principal_id
        .strip_prefix("uid:")
        .and_then(|n| n.parse::<u32>().ok())
        .and_then(|uid| {
            nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
                .ok()
                .flatten()
                .map(|u| u.name)
        });
    cache
        .lock()
        .unwrap()
        .insert(principal_id.to_string(), resolved.clone());
    resolved
}

/// The full grant column list every grant read shares, in the exact order [`Broker::grant_view_from_row`]
/// consumes — so no view path can drift from the signed-column set or the fail-closed redaction rule.
pub(super) const GRANT_VIEW_COLUMNS: &str = "id, session_id, provider, action, resource_json, \
     environment, status, decision, created_at, policy_fingerprint, grant_digest, expiry_epoch, \
     principal_id, template_hash, descriptor_hash, approved_by_kind, approver, approved_at, \
     request_id, lease_opened_at, lease_deadline, evidence_json, money_json";

#[allow(clippy::too_many_arguments)]
pub(super) fn grant_digest(
    key: &[u8; 32],
    id: &str,
    request_id: &str,
    provider: &str,
    action: &str,
    resource_json: &str,
    evidence_json: &str,
    money_json: &str,
    decision: &str,
    policy_fingerprint: &str,
    status: &str,
    session_id: &str,
    // The SHA-256 of the loaded provider descriptor bytes, REQUIRED on every grant and folded
    // UNCONDITIONALLY under the v6 domain tag. A descriptor replacement changes this hash, so an
    // unspent grant fails integrity before credential use — it never aliases.
    descriptor_hash: &str,
    expiry_epoch: Option<i64>,
    principal_id: Option<&str>,
    template_hash: Option<&str>,
    approved_by_kind: Option<&str>,
    approver: Option<&str>,
    approved_at: Option<&str>,
    // The claim-time lease stamps, folded UNCONDITIONALLY (presence byte + value after the
    // `lopn`/`ldl` tags) under the gen-5 domain tag — a store-edit OR a NULLing of the deadline the
    // overdue sweep enforces breaks the HMAC.
    lease_opened_at: Option<i64>,
    lease_deadline: Option<i64>,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    // Generation 8: evidence and private money metadata are required on every grant and
    // domain-separated from every prior schema generation.
    mac.update(b"cermet-grant-v8\0");
    // `request_id` is folded as a REQUIRED signed field (it is NOT NULL on every grant), right
    // after `id`, so a raw store edit of the req_ cross-reference handle breaks integrity.
    // Unconditional at v2 — the boot guard refuses a v1 DB, so every row is freshly minted.
    for field in [
        id,
        request_id,
        provider,
        action,
        resource_json,
        evidence_json,
        money_json,
        decision,
        policy_fingerprint,
        status,
        session_id,
    ] {
        mac.update(&(field.len() as u64).to_le_bytes());
        mac.update(field.as_bytes());
    }
    // The required provider-descriptor hash, folded unconditionally after a distinguishing tag.
    mac.update(b"dsc");
    mac.update(&(descriptor_hash.len() as u64).to_le_bytes());
    mac.update(descriptor_hash.as_bytes());
    if let Some(exp) = expiry_epoch {
        mac.update(b"exp");
        mac.update(&exp.to_le_bytes());
    }
    if let Some(p) = principal_id {
        mac.update(b"prin");
        mac.update(&(p.len() as u64).to_le_bytes());
        mac.update(p.as_bytes());
    }
    // Appended ONLY when Some, after a distinguishing tag, so a `None` template_hash digests
    // byte-identically to a grant minted before template hashes existed — every existing built-in
    // grant keeps verifying.
    if let Some(t) = template_hash {
        mac.update(b"tpl");
        mac.update(&(t.len() as u64).to_le_bytes());
        mac.update(t.as_bytes());
    }
    // Durable authority provenance. Each value is appended only when present and is therefore
    // tamper-evident, including the legacy fields needed to authenticate pre-cutover rows.
    for (tag, field) in [
        (b"abk".as_slice(), approved_by_kind),
        (b"apr".as_slice(), approver),
        (b"aat".as_slice(), approved_at),
    ] {
        if let Some(v) = field {
            mac.update(tag);
            mac.update(&(v.len() as u64).to_le_bytes());
            mac.update(v.as_bytes());
        }
    }
    // The lease stamps are folded UNCONDITIONALLY — a present stamp and an absent one digest
    // differently by construction, so NULLing the columns a sweep/finalize trusts breaks the HMAC.
    // An only-when-Some encoding would make absence indistinguishable from pre-claim.
    for (tag, field) in [
        (b"lopn".as_slice(), lease_opened_at),
        (b"ldl".as_slice(), lease_deadline),
    ] {
        mac.update(tag);
        match field {
            Some(v) => {
                mac.update(&[1u8]);
                mac.update(&v.to_le_bytes());
            }
            None => mac.update(&[0u8]),
        }
    }
    crate::util::hex(&mac.finalize().into_bytes())
}

pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Format a Unix epoch second in the same RFC3339 shape `created_at` is stored in, for a
/// string-comparable proposal-rate window bound (see `propose_contract`).
pub(super) fn rfc3339_of_epoch(epoch: i64) -> String {
    use time::OffsetDateTime;
    OffsetDateTime::from_unix_timestamp(epoch)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// SHA-256 of `bytes` as lowercase hex.
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    crate::util::hex(&h.finalize())
}

pub(super) fn subkey(master: &[u8], label: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(master);
    h.update(label);
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.finalize());
    k
}

pub(super) fn status_str(s: GrantStatus) -> &'static str {
    match s {
        GrantStatus::Requested => "requested",
        GrantStatus::Approved => "approved",
        GrantStatus::Denied => "denied",
        GrantStatus::Executing => "executing",
        GrantStatus::Executed => "executed",
        GrantStatus::Expired => "expired",
    }
}

pub(super) fn decision_str(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    }
}

pub(super) fn parse_status(s: &str) -> Result<GrantStatus> {
    match s {
        "requested" => Ok(GrantStatus::Requested),
        "approved" => Ok(GrantStatus::Approved),
        "denied" => Ok(GrantStatus::Denied),
        "executing" => Ok(GrantStatus::Executing),
        "executed" => Ok(GrantStatus::Executed),
        "expired" => Ok(GrantStatus::Expired),
        _ => Err(Error::Integrity(format!(
            "unknown persisted grant status vocabulary `{s}`"
        ))),
    }
}
