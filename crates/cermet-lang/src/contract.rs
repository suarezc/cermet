//! Action contracts and the canonical, typed resource.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::{Error, Result};

/// The scalar kinds the flat namespace permits.
///
/// Flat, and deliberately so: the one structured kind that ever existed (`change_list`) died with
/// the move to git-native transport. Its job was carrying file content through a request, and git
/// carries its own content — a broker that authorizes and receipts has no structured payload to
/// canonicalize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarKind {
    Str,
    Int,
    Bool,
}

impl ScalarKind {
    fn label(self) -> &'static str {
        match self {
            ScalarKind::Str => "string",
            ScalarKind::Int => "integer",
            ScalarKind::Bool => "boolean",
        }
    }
}

/// A single validated scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scalar {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl Scalar {
    pub fn kind(&self) -> ScalarKind {
        match self {
            Scalar::Str(_) => ScalarKind::Str,
            Scalar::Int(_) => ScalarKind::Int,
            Scalar::Bool(_) => ScalarKind::Bool,
        }
    }

    /// Fail-closed conversion of a JSON value to a scalar of the declared kind.
    #[doc(hidden)]
    pub fn from_json(kind: ScalarKind, field: &str, v: &Value) -> Result<Scalar> {
        let mismatch = || {
            Error::Invalid(format!(
                "field `{field}` must be a {} scalar, got {}",
                kind.label(),
                json_shape(v)
            ))
        };
        match kind {
            ScalarKind::Str => v
                .as_str()
                .map(|s| Scalar::Str(s.to_string()))
                .ok_or_else(mismatch),
            ScalarKind::Int => v.as_i64().map(Scalar::Int).ok_or_else(mismatch),
            ScalarKind::Bool => v.as_bool().map(Scalar::Bool).ok_or_else(mismatch),
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Scalar::Str(s) => Value::String(s.clone()),
            Scalar::Int(i) => Value::Number((*i).into()),
            Scalar::Bool(b) => Value::Bool(*b),
        }
    }

    /// Infer a scalar from JSON without a declared kind (open-schema path).
    #[doc(hidden)]
    pub fn infer(field: &str, v: &Value) -> Result<Scalar> {
        match v {
            Value::String(s) => Ok(Scalar::Str(s.clone())),
            Value::Bool(b) => Ok(Scalar::Bool(*b)),
            Value::Number(_) => v.as_i64().map(Scalar::Int).ok_or_else(|| {
                Error::Invalid(format!(
                    "field `{field}` must be an integer or string scalar"
                ))
            }),
            _ => Err(Error::Invalid(format!("field `{field}` must be a scalar"))),
        }
    }
}

/// A name for the JSON shape, for error messages (no value content).
#[doc(hidden)]
pub fn json_shape(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                "an integer"
            } else {
                "a float"
            }
        }
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// The authority role of a declared field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldClass {
    /// Backstop only — every real field must be explicitly classified.
    Unclassified,
    /// Identifies the resource acted on; an `allow` must exactly pin it.
    Identity,
    /// Authority-relevant config; must be exactly pinned or sentence-bounded by the allow.
    SideEffect,
    /// Varies per request, not authority-relevant; rides freely.
    FreePayload,
    /// An agent-supplied secret; never returned, never audited raw.
    Secret,
    /// A bounded read filter, side-effect-free.
    ReadFilter,
}

/// How an `allow` rule must bind a field (separate axis from `FieldClass`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowBinding {
    /// No allow-binding requirement.
    Unbound,
    /// An `allow` must exactly pin this field via `scope.resource`.
    ExactResourcePin,
    /// An `allow` must bind via an exact `scope.resource` pin or the named scope allowlist.
    ExactOrPatternList(&'static str),
    /// An `allow` must carry an integer `<=` or `>=` sentence conjunct for this field.
    /// Legal only for integer `SideEffect` fields.
    Bounded,
}

/// One declared field in a contract's closed schema.
#[derive(Debug, Clone, Copy)]
pub struct FieldDecl {
    pub name: &'static str,
    pub ty: ScalarKind,
    pub required: bool,
    pub class: FieldClass,
    /// How an `allow` must bind this field.
    pub binding: AllowBinding,
}

impl FieldDecl {
    /// Whether a rule-level `budget … per <window>` aggregate may SUM this field: the exact
    /// declaration shape the broker's debit freeze demands — required (an absent optional field
    /// would debit nothing), integer, side-effecting, and `bounded` (the sentence must carry a
    /// numeric cap on it).
    ///
    /// It lives on the declaration because the broker already asked it twice (freezing a debit and
    /// fingerprinting a set member's meter semantics) and the catalog's form index asks it a third
    /// time. A four-clause shape spelled out in three places drifts.
    pub fn budget_eligible(&self) -> bool {
        self.required
            && self.ty == ScalarKind::Int
            && self.class == FieldClass::SideEffect
            && self.binding == AllowBinding::Bounded
    }
}

/// A membership/derivation edge.
#[derive(Debug, Clone, Copy)]
pub struct Relation {
    pub from: &'static str,
    pub path: &'static [&'static str],
    pub expect: &'static str,
}

/// The single source of truth for one `(provider, action)`.
#[derive(Debug, Clone, Copy)]
pub struct ActionContract {
    pub provider: &'static str,
    pub action: &'static str,
    /// Closed schema; a field not listed here is rejected at canonicalize.
    pub schema: &'static [FieldDecl],
    /// Fields the executor reads. Never contains `"parameters"`.
    pub consumes: &'static [&'static str],
    /// The fields a sentence MAY pin to scope this action — the set a least-privilege `allow` is
    /// shaped around. `[]` ⇒ no scopable target, and a bare allow is the only rule shape (the
    /// `scope: account` case).
    ///
    /// It is not itself an obligation on any rule: no evaluate-time check demands that a matching
    /// rule pin these. What reads it: SUGGESTION SHAPING — the pinned allow proposed for an unruled
    /// request (`sentence::unruled_allow_hint`) and the deny's own shape key
    /// (`broker::helpers::widening_shape`), both gated on
    /// [`Self::has_fully_pinned_execution_targets`] — plus the template validator, which requires
    /// membership here for every field that reaches an executed URL (path placeholders, path-mode
    /// fields, query placeholders) or that a relay bind / outcome assertion compares against.
    pub execution_targets: &'static [&'static str],
    /// Deferred-membership edges.
    pub relations: &'static [Relation],
    /// `true` ⇒ the schema is open: any scalar field accepted, no unknown-field rejection.
    pub open: bool,
}

impl ActionContract {
    pub fn field_decl(&self, name: &str) -> Option<&FieldDecl> {
        self.schema.iter().find(|f| f.name == name)
    }

    pub fn field_kind(&self, name: &str) -> Option<ScalarKind> {
        self.field_decl(name).map(|f| f.ty)
    }

    /// The authority class of a declared field.
    pub fn field_class(&self, name: &str) -> Option<FieldClass> {
        self.field_decl(name).map(|f| f.class)
    }

    /// How an `allow` must bind a declared field.
    pub fn field_binding(&self, name: &str) -> Option<AllowBinding> {
        self.field_decl(name).map(|f| f.binding)
    }

    pub fn has_schema_field(&self, name: &str) -> bool {
        self.field_decl(name).is_some()
    }

    /// Whether an `allow` can pin EVERYTHING this action executes: the action has at least one
    /// execution target AND every execution target is a declared field bound `ExactResourcePin`. It
    /// gates the suggestion of a least-privilege pinned allow: only then can such an allow constrain
    /// every executing field instead of widening to the whole provider. `false` for a target-less action
    /// (`create_project`) or an open/stub contract with no execution target (`MOCK_CONTRACT`), and also
    /// `false` for a MIXED contract whose execution targets include an Unbound field: a partial pin
    /// would leave an executing field unconstrained, so no pinned allow is suggested for it.
    pub fn has_fully_pinned_execution_targets(&self) -> bool {
        !self.execution_targets.is_empty()
            && self.execution_targets.iter().all(|t| {
                self.field_decl(t)
                    .is_some_and(|f| f.binding == AllowBinding::ExactResourcePin)
            })
    }

    /// Internal self-consistency as a `Result`, so a runtime loader (ratified action templates)
    /// can fail closed — refuse the document — instead of crashing the daemon.
    pub fn validate_consistent(&self) -> std::result::Result<(), String> {
        let fields: Vec<(&str, ScalarKind, FieldClass, AllowBinding, bool)> = self
            .schema
            .iter()
            .map(|f| (f.name, f.ty, f.class, f.binding, f.required))
            .collect();
        let relation_froms: Vec<&str> = self.relations.iter().map(|r| r.from).collect();
        check_consistent(
            self.provider,
            self.action,
            &fields,
            self.consumes,
            self.execution_targets,
            &relation_froms,
        )
    }

    /// Internal self-consistency, asserted at registry build. Panics on violation.
    pub fn assert_consistent(&self) {
        if let Err(e) = self.validate_consistent() {
            panic!("{e}");
        }
    }
}

/// The ONE consistency checker for both the compiled-in contracts and template-derived ones —
/// a single body so the two paths cannot drift.
#[doc(hidden)]
pub fn check_consistent(
    provider: &str,
    action: &str,
    fields: &[(&str, ScalarKind, FieldClass, AllowBinding, bool)],
    consumes: &[&str],
    execution_targets: &[&str],
    relation_froms: &[&str],
) -> std::result::Result<(), String> {
    let has = |n: &str| fields.iter().any(|(f, _, _, _, _)| *f == n);
    for c in consumes {
        if *c == "parameters" {
            return Err(format!(
                "{provider}.{action}: consumes must never name `parameters` (the killed execute-time channel)"
            ));
        }
        if !has(c) {
            return Err(format!(
                "{provider}.{action}: consumes `{c}` is not a declared schema field"
            ));
        }
    }
    for t in execution_targets {
        // An execution target names a field a sentence MAY pin, so it has to be a declared schema
        // field — a target nothing backs is unpinnable by construction.
        //
        // An OPTIONAL target is legal, and means what optionality means everywhere else: a request
        // that omits it freezes it as absence, and absence is not a value. A rule that pins it then
        // refuses such a request (`missing_required_field`, naming the field); a rule that does not
        // mention it admits the request with that field unconstrained — the same "unmentioned is
        // unconstrained" every other field obeys. What an executor does with an absent target is the
        // template's own business, declared in its own document.
        //
        // The narrower positions where a target must ALSO be required — a path placeholder, a
        // slash-bearing path-mode field, a verified `expect_eq` identity — carry that requirement at
        // their own validation sites, since those are where absence would leave EXECUTED URL
        // authority unpinned.
        //
        // ONE execution-target position deliberately does NOT restate it: an HTTP query placeholder.
        // Its own validation demands `exact_resource_pin` + identity/side_effect + membership here,
        // but never required-ness — which this rule used to supply transitively, and no longer does.
        // A future author must not read that silence as a guarantee. What actually holds the line is
        // RENDER time: a whole-value `{field}` placeholder whose field is absent is a hard error, so
        // the request is never built; only the explicitly optional `{field?}` spelling renders as an
        // omitted parameter. Absence there fails closed or is declared — never silently defaulted.
        if !fields.iter().any(|(f, _, _, _, _)| *f == *t) {
            return Err(format!(
                "{provider}.{action}: execution_target `{t}` is not a declared schema field (unpinnable)"
            ));
        }
    }
    for (name, ty, class, binding, _required) in fields {
        if *class == FieldClass::Unclassified {
            return Err(format!(
                "{provider}.{action}: field `{name}` is Unclassified — every field must declare a FieldClass"
            ));
        }
        let binding_ok = match class {
            FieldClass::Identity => matches!(
                binding,
                AllowBinding::ExactResourcePin | AllowBinding::ExactOrPatternList(_)
            ),
            FieldClass::SideEffect => {
                *binding == AllowBinding::ExactResourcePin
                    || (*binding == AllowBinding::Bounded && *ty == ScalarKind::Int)
            }
            FieldClass::FreePayload | FieldClass::Secret | FieldClass::ReadFilter => {
                *binding == AllowBinding::Unbound
            }
            FieldClass::Unclassified => false,
        };
        if !binding_ok {
            return Err(format!(
                "{provider}.{action}: field `{name}` class {class:?} is incompatible with binding {binding:?}"
            ));
        }
    }
    for r in relation_froms {
        if !has(r) {
            return Err(format!(
                "{provider}.{action}: relation.from `{r}` is not a declared schema field"
            ));
        }
    }
    Ok(())
}

/// The frozen, policy-checked resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalResource {
    fields: BTreeMap<String, Scalar>,
}

impl CanonicalResource {
    /// Build from already-validated scalar fields.
    #[doc(hidden)]
    pub fn from_map(fields: BTreeMap<String, Scalar>) -> Self {
        Self { fields }
    }

    /// Merge trusted request-preparation fields without permitting replacement. Provider evidence
    /// must extend the partial agent resource; a collision is an integrity failure, never overwrite.
    #[doc(hidden)]
    pub fn merged(&self, additional: BTreeMap<String, Scalar>) -> Result<Self> {
        let mut fields = self.fields.clone();
        for (name, value) in additional {
            if fields.insert(name.clone(), value).is_some() {
                return Err(Error::Integrity(format!(
                    "trusted resource merge collided on field `{name}`"
                )));
            }
        }
        Ok(Self { fields })
    }

    /// The mirror of [`Self::merged`]: replace the value of a field that ALREADY exists, without
    /// permitting addition. Request-time canonicalization rewrites the spelling of a
    /// field the agent supplied; a name that is absent means the canonicalizer and the contract
    /// disagree about what was requested, which is an integrity failure, never a silent insert.
    #[doc(hidden)]
    pub fn replaced(&self, updates: BTreeMap<String, Scalar>) -> Result<Self> {
        let mut fields = self.fields.clone();
        for (name, value) in updates {
            if fields.insert(name.clone(), value).is_none() {
                return Err(Error::Integrity(format!(
                    "trusted resource replacement named absent field `{name}`"
                )));
            }
        }
        Ok(Self { fields })
    }

    /// A required string field. Absent, null, or a non-string kind ⇒ `Err`.
    pub fn req_str(&self, field: &str) -> Result<&str> {
        match self.fields.get(field) {
            Some(Scalar::Str(s)) => Ok(s),
            Some(other) => Err(Error::Invalid(format!(
                "frozen field `{field}` is a {}, expected a string",
                other.kind().label()
            ))),
            None => Err(Error::Invalid(format!(
                "required frozen field `{field}` is absent"
            ))),
        }
    }

    /// A required integer field. Absent or non-integer ⇒ `Err`.
    pub fn req_i64(&self, field: &str) -> Result<i64> {
        match self.fields.get(field) {
            Some(Scalar::Int(i)) => Ok(*i),
            Some(other) => Err(Error::Invalid(format!(
                "frozen field `{field}` is a {}, expected an integer",
                other.kind().label()
            ))),
            None => Err(Error::Invalid(format!(
                "required frozen field `{field}` is absent"
            ))),
        }
    }

    /// A required boolean field. Absent or non-boolean ⇒ `Err`.
    pub fn req_bool(&self, field: &str) -> Result<bool> {
        match self.fields.get(field) {
            Some(Scalar::Bool(b)) => Ok(*b),
            Some(other) => Err(Error::Invalid(format!(
                "frozen field `{field}` is a {}, expected a boolean",
                other.kind().label()
            ))),
            None => Err(Error::Invalid(format!(
                "required frozen field `{field}` is absent"
            ))),
        }
    }

    /// A best-effort string view; `None` if absent or non-string.
    pub fn get_str(&self, field: &str) -> Option<&str> {
        match self.fields.get(field) {
            Some(Scalar::Str(s)) => Some(s),
            _ => None,
        }
    }

    /// A best-effort bool view for an optional field; `None` if absent or non-bool.
    pub fn get_bool(&self, field: &str) -> Option<bool> {
        match self.fields.get(field) {
            Some(Scalar::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// A best-effort i64 view for an optional field; `None` if absent or non-int.
    pub fn get_i64(&self, field: &str) -> Option<i64> {
        match self.fields.get(field) {
            Some(Scalar::Int(n)) => Some(*n),
            _ => None,
        }
    }

    pub fn contains(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }

    /// The typed scalar for a field, if present. Template expansion and sentence evaluation use this
    /// one lookup so policy helpers cannot diverge by reparsing the canonical JSON representation.
    pub fn scalar(&self, field: &str) -> Option<&Scalar> {
        self.fields.get(field)
    }

    /// Every frozen field with its typed scalar, in canonical (sorted-name) order. The read-only
    /// companion to [`Self::scalar`] for callers that must walk the whole resource.
    pub fn scalars(&self) -> impl Iterator<Item = (&str, &Scalar)> {
        self.fields
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    /// Canonical bytes: a JSON object with keys in sorted order and no insignificant whitespace.
    pub fn to_canonical_json(&self) -> String {
        let mut map = serde_json::Map::with_capacity(self.fields.len());
        for (k, v) in &self.fields {
            map.insert(k.clone(), v.to_json());
        }
        Value::Object(map).to_string()
    }

    /// Reload a persisted resource and re-validate it against the closed schema.
    pub fn from_stored(json: &str, c: &ActionContract) -> Result<CanonicalResource> {
        let value: Value = serde_json::from_str(json)
            .map_err(|e| Error::Invalid(format!("stored resource is not valid JSON: {e}")))?;
        let Value::Object(obj) = value else {
            return Err(Error::Invalid(
                "stored resource must be a JSON object".into(),
            ));
        };
        let mut fields = BTreeMap::new();
        if c.open {
            for (k, v) in &obj {
                fields.insert(k.clone(), Scalar::infer(k, v)?);
            }
            return Ok(CanonicalResource { fields });
        }
        for (k, v) in &obj {
            let Some(decl) = c.field_decl(k) else {
                return Err(Error::Invalid(format!(
                    "stored resource has undeclared field `{k}` for {}.{}",
                    c.provider, c.action
                )));
            };
            fields.insert(k.clone(), Scalar::from_json(decl.ty, k, v)?);
        }
        for decl in c.schema {
            if decl.required && !fields.contains_key(decl.name) {
                return Err(Error::Invalid(format!(
                    "stored resource missing required field `{}` for {}.{}",
                    decl.name, c.provider, c.action
                )));
            }
        }
        Ok(CanonicalResource { fields })
    }

    /// A read-only JSON view for the policy matcher / `Pred` eval.
    pub fn as_match_value(&self) -> Value {
        let mut map = serde_json::Map::with_capacity(self.fields.len());
        for (k, v) in &self.fields {
            map.insert(k.clone(), v.to_json());
        }
        Value::Object(map)
    }
}

// The core ships ZERO compiled-in action contracts: every action is template-owned (its ratified
// document in `actions/` owns the name and the registry derives the contract at load, resolving only
// through a broker whose registry loaded it) or has no contract at all and fails closed. The old
// `ALL_CONTRACTS` / `contract_for` / built-in constructors are gone; the live secret-field source of
// truth is the template registry (built-ins ∪ loaded templates), reached through a broker.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SCHEMA: &[FieldDecl] = &[
        FieldDecl {
            name: "project",
            ty: ScalarKind::Str,
            required: true,
            class: FieldClass::Identity,
            binding: AllowBinding::ExactResourcePin,
        },
        FieldDecl {
            name: "pull_number",
            ty: ScalarKind::Int,
            required: false,
            class: FieldClass::FreePayload,
            binding: AllowBinding::Unbound,
        },
        FieldDecl {
            name: "flag",
            ty: ScalarKind::Bool,
            required: false,
            class: FieldClass::FreePayload,
            binding: AllowBinding::Unbound,
        },
    ];
    const CONTRACT: ActionContract = ActionContract {
        provider: "test",
        action: "act",
        schema: SCHEMA,
        consumes: &["project"],
        execution_targets: &["project"],
        relations: &[],
        open: false,
    };

    #[test]
    fn scalar_from_json_is_fail_closed_on_non_scalars() {
        for v in [json!([1, 2]), json!({"a": 1}), json!(null)] {
            assert!(Scalar::from_json(ScalarKind::Str, "f", &v).is_err());
            assert!(Scalar::from_json(ScalarKind::Int, "f", &v).is_err());
            assert!(Scalar::from_json(ScalarKind::Bool, "f", &v).is_err());
        }
    }

    #[test]
    fn scalar_int_rejects_float_string_and_bool_no_coercion() {
        assert!(Scalar::from_json(ScalarKind::Int, "n", &json!(412.0)).is_err());
        assert!(Scalar::from_json(ScalarKind::Int, "n", &json!("412")).is_err());
        assert!(Scalar::from_json(ScalarKind::Int, "n", &json!(true)).is_err());
        assert_eq!(
            Scalar::from_json(ScalarKind::Int, "n", &json!(412)).unwrap(),
            Scalar::Int(412)
        );
    }

    #[test]
    fn scalar_str_does_not_accept_a_number() {
        assert!(Scalar::from_json(ScalarKind::Str, "s", &json!(1)).is_err());
        assert_eq!(
            Scalar::from_json(ScalarKind::Str, "s", &json!("1")).unwrap(),
            Scalar::Str("1".into())
        );
    }

    #[test]
    fn req_accessors_fail_closed_on_absent_and_wrong_kind() {
        let mut m = BTreeMap::new();
        m.insert("project".to_string(), Scalar::Str("p".into()));
        let r = CanonicalResource::from_map(m);
        assert_eq!(r.req_str("project").unwrap(), "p");
        assert!(
            r.req_str("missing").is_err(),
            "absent field must fail closed"
        );
        assert!(
            r.req_i64("project").is_err(),
            "string read as int must fail closed"
        );
    }

    #[test]
    fn to_canonical_json_is_key_order_independent() {
        let mut a = BTreeMap::new();
        a.insert("name".to_string(), Scalar::Str("x".into()));
        a.insert("project".to_string(), Scalar::Str("p".into()));
        let mut b = BTreeMap::new();
        b.insert("project".to_string(), Scalar::Str("p".into()));
        b.insert("name".to_string(), Scalar::Str("x".into()));
        assert_eq!(
            CanonicalResource::from_map(a).to_canonical_json(),
            CanonicalResource::from_map(b).to_canonical_json(),
            "canonical JSON must be identical regardless of insertion order"
        );
    }

    #[test]
    fn from_stored_rejects_undeclared_key_and_wrong_kind() {
        assert!(
            CanonicalResource::from_stored(r#"{"project":"p","team":"x"}"#, &CONTRACT).is_err(),
            "an undeclared stored key must be rejected at reload"
        );
        assert!(
            CanonicalResource::from_stored(r#"{"project":"p","pull_number":"412"}"#, &CONTRACT)
                .is_err(),
            "a wrong-kind stored value must be rejected at reload"
        );
        assert!(
            CanonicalResource::from_stored(r#"{"pull_number":1}"#, &CONTRACT).is_err(),
            "a missing required field must be rejected at reload"
        );
        let ok = CanonicalResource::from_stored(r#"{"project":"p","pull_number":412}"#, &CONTRACT)
            .unwrap();
        assert_eq!(ok.req_str("project").unwrap(), "p");
        assert_eq!(ok.req_i64("pull_number").unwrap(), 412);
    }

    #[test]
    fn assert_consistent_accepts_a_well_formed_contract() {
        CONTRACT.assert_consistent();
    }

    #[test]
    fn bounded_binding_accepts_only_integer_side_effect_fields() {
        const BOUNDED: ActionContract = ActionContract {
            provider: "stripe",
            action: "refund",
            schema: &[FieldDecl {
                name: "amount",
                ty: ScalarKind::Int,
                required: true,
                class: FieldClass::SideEffect,
                binding: AllowBinding::Bounded,
            }],
            consumes: &["amount"],
            execution_targets: &[],
            relations: &[],
            open: false,
        };
        BOUNDED.assert_consistent();

        for (ty, class) in [
            (ScalarKind::Str, FieldClass::SideEffect),
            (ScalarKind::Int, FieldClass::Identity),
            (ScalarKind::Int, FieldClass::FreePayload),
        ] {
            let bad = ActionContract {
                schema: Box::leak(
                    vec![FieldDecl {
                        name: "amount",
                        ty,
                        required: true,
                        class,
                        binding: AllowBinding::Bounded,
                    }]
                    .into_boxed_slice(),
                ),
                ..BOUNDED
            };
            assert!(bad.validate_consistent().is_err());
        }
    }

    #[test]
    #[should_panic(expected = "parameters")]
    fn assert_consistent_rejects_parameters_in_consumes() {
        const BAD: ActionContract = ActionContract {
            provider: "test",
            action: "bad",
            schema: SCHEMA,
            consumes: &["parameters"],
            execution_targets: &[],
            relations: &[],
            open: false,
        };
        BAD.assert_consistent();
    }

    #[test]
    #[should_panic(expected = "not a declared schema field")]
    fn assert_consistent_rejects_target_absent_from_schema() {
        const BAD: ActionContract = ActionContract {
            provider: "test",
            action: "bad",
            schema: SCHEMA,
            consumes: &["project"],
            execution_targets: &["nonexistent"],
            relations: &[],
            open: false,
        };
        BAD.assert_consistent();
    }

    #[test]
    #[should_panic(expected = "Unclassified")]
    fn assert_consistent_rejects_an_unclassified_field() {
        const BAD: ActionContract = ActionContract {
            provider: "test",
            action: "bad",
            schema: &[FieldDecl {
                name: "mystery",
                ty: ScalarKind::Str,
                required: true,
                class: FieldClass::Unclassified,
                binding: AllowBinding::Unbound,
            }],
            consumes: &["mystery"],
            execution_targets: &[],
            relations: &[],
            open: false,
        };
        BAD.assert_consistent();
    }

    #[test]
    fn an_optional_execution_target_is_a_legal_declaration() {
        // An execution target names a field a sentence MAY pin; optionality is orthogonal to that.
        // An omitting request freezes the field as absence, and absence is not a value — a rule that
        // pins the field refuses that request rather than matching it, so nothing here can widen a
        // pinned rule onto an unpinned run.
        const OPTIONAL_TARGET: ActionContract = ActionContract {
            provider: "test",
            action: "optional_target",
            schema: &[FieldDecl {
                name: "project",
                ty: ScalarKind::Str,
                required: false,
                class: FieldClass::Identity,
                binding: AllowBinding::ExactResourcePin,
            }],
            consumes: &["project"],
            execution_targets: &["project"],
            relations: &[],
            open: false,
        };
        OPTIONAL_TARGET.assert_consistent();
    }

    /// The other half: a rule that PINS the optional target refuses a request that omitted it. The
    /// pin is not silently satisfied by absence, which is what makes the relaxation above safe.
    #[test]
    fn a_pinned_optional_target_refuses_a_request_that_omitted_it() {
        const OPTIONAL_TARGET: ActionContract = ActionContract {
            provider: "test",
            action: "optional_target",
            schema: &[FieldDecl {
                name: "project",
                ty: ScalarKind::Str,
                required: false,
                class: FieldClass::Identity,
                binding: AllowBinding::ExactResourcePin,
            }],
            consumes: &["project"],
            execution_targets: &["project"],
            relations: &[],
            open: false,
        };
        let omitted = CanonicalResource::from_stored("{}", &OPTIONAL_TARGET).unwrap();
        assert!(omitted.req_str("project").is_err());
    }
}
