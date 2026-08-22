//! The sentence language: a flat text codec over structural decision rules.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::contract::{
    ActionContract, CanonicalResource, FieldClass, FieldDecl, Scalar as ResourceScalar, ScalarKind,
};
use crate::sets::SetResolver;

pub const RULE_SET_VERSION: u32 = 1;

/// Domain-separated identity of canonical sentence authority. The language version is encoded
/// independently of the text so the same bytes cannot revive grants after their meaning changes.
pub fn authority_digest_for(version: u32, canonical_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut hash = Sha256::new();
    hash.update(b"cermet.sentence.authority\0");
    hash.update(version.to_be_bytes());
    hash.update(canonical_bytes);
    crate::util::hex(&hash.finalize())
}

/// Exact canonical authority bytes: ordered printer output with one trailing LF when nonempty.
pub fn canonical_rule_bytes(rules: &RuleSet) -> Vec<u8> {
    let mut text = rules
        .rules
        .iter()
        .map(print_rule)
        .collect::<Vec<_>>()
        .join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    text.into_bytes()
}

pub fn authority_digest(rules: &RuleSet) -> String {
    authority_digest_for(rules.version, &canonical_rule_bytes(rules))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuleSet {
    pub version: u32,
    pub rules: Vec<Rule>,
}

/// One exact immutable set expansion used by a prepared corpus. This is reconciliation evidence,
/// not authority: authority remains the canonical digest-pinned selector in `canonical_text`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreparedSetSnapshot {
    pub rule_index: usize,
    pub provider: String,
    pub set: String,
    pub digest: String,
    pub members: Vec<String>,
}

/// The daemon's complete, non-mutating normalization of candidate sentence text.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreparedSentenceCorpus {
    pub canonical_text: String,
    /// Domain/language-version-bound lowercase SHA-256 hex, without the display `sha256:` prefix.
    pub canonical_digest: String,
    pub rule_count: usize,
    pub set_snapshots: Vec<PreparedSetSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub effect: RuleEffect,
    pub selector: Selector,
    pub conjuncts: Vec<Pred>,
    /// An optional rule-level budget/rate aggregate clause. Aggregate-bearing rules never
    /// participate in containment/widen (a widened budget is a new authored sentence with a
    /// fresh counter). Adding this field changes `Rule`'s serde bytes so the per-rule
    /// digest and `ruleset_fingerprint` cover the aggregate.
    #[serde(default)]
    pub aggregate: Option<Aggregate>,
}

/// A rule-level aggregate predicate at admission: a materialized counter (`budget` = SUM of a
/// field; `rate` = SUM of 1s) over a fixed calendar window. One counter, two spellings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Aggregate {
    pub kind: AggregateKind,
    /// The authored cap; a positive integer (parse refuses `<= 0`).
    pub limit: i64,
    pub window: Window,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateKind {
    /// SUM of a required+bounded+int+side-effect field. `field: None` is the fieldless shorthand,
    /// whose summed field is inferred from set membership at corpus validation.
    Budget { field: Option<String> },
    /// SUM of 1s over every admitted member (no exemption concept).
    Rate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Window {
    Hour,
    Day,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Selector {
    Set {
        provider: String,
        set: String,
        #[serde(default)]
        digest: Option<String>,
    },
    Verb {
        provider: String,
        action: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scalar {
    Int(i64),
    String(String),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pred {
    Eq { field: String, value: Scalar },
    Lte { field: String, value: i64 },
    Gte { field: String, value: i64 },
    In { field: String, values: Vec<Scalar> },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow { rule_idx: usize },
    Deny { reason: DenyReason },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    ExplicitDeny {
        rule_idx: usize,
    },
    UnresolvedDeny {
        rule_idx: usize,
    },
    /// The verb itself is not in the ratified grammar — no contract resolves for it. An agent
    /// reading this has a typo or a stale catalog, not an authority gap.
    UnknownSelector,
    /// The grammar knows the verb; NO rule in the corpus mentions it. This is the authority gap
    /// only the operator can close, and it is the one an unruled request actually hits.
    NoMatchingRule,
    UnsupportedVersion {
        version: u32,
    },
    MissingField {
        rule_idx: usize,
        field: String,
    },
    /// A rule named the verb and one of its `where` conjuncts refused the request: in scope, out of
    /// bounds.
    ///
    /// `field` names WHICH declared field the failing predicate constrained. Every
    /// [`Pred`] constrains exactly one field, so the evaluator holds the name at the moment it
    /// detects the mismatch and never reconstructs it later; a compound predicate that had no single
    /// field would report `None` rather than guess, and no such predicate exists in the grammar
    /// today. This is the field's NAME, never its value — the same registry identifier
    /// [`DenyReason::MissingField`] already carries, and the only part of "which predicate" that is
    /// a fact about the vocabulary rather than about one operator's file. `rule_idx`/`pred_idx`
    /// remain positions in that file and stay local.
    ///
    /// `Option` because the member is ADDITIVE: rows stored before it existed carry the variant
    /// without it and must still deserialize — no migration, no schema bump. Absence means "not
    /// recorded", never "no field".
    PredicateMismatch {
        rule_idx: usize,
        pred_idx: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field: Option<String>,
    },
    /// A budget/rate aggregate cap was exhausted for its window. Produced by the ledger-derived mint
    /// gate (`broker::budget`) as the value-free downgrade of an otherwise-Allow aggregate rule —
    /// never by the pure `evaluate()`. Carries the window only, never a numeric figure (anti-oracle).
    BudgetExceeded {
        window: Window,
    },
}

/// The one conversion from a machine rule index to the number a HUMAN reads.
///
/// Every `rule_idx` in this module — `Decision::Allow`, every `DenyReason`, `ReferenceError`,
/// `ShadowError` — is a zero-based position into `RuleSet::rules`, because that is what indexes the
/// slice. Humans never see that basis: `cermet rules` lists from 1, and `cermet rules revoke <n>` /
/// `refresh <n>` parse a one-based number and subtract 1 to get back here. So a number rendered to a
/// person must pass through this function, and the round trip through
/// [`rule_index_from_human`] must land on the same rule. Shipping the raw index is the bug: a deny
/// that said "rule 18" named the sentence the list calls 19, and feeding 18 to `revoke` would have
/// destroyed an unrelated capability.
pub fn human_rule_number(rule_idx: usize) -> usize {
    rule_idx + 1
}

/// The inverse of [`human_rule_number`]: the slice index a human's one-based rule number means.
/// `None` for 0, which is not a rule number any surface ever prints.
pub fn rule_index_from_human(number: usize) -> Option<usize> {
    number.checked_sub(1)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SentenceError {
    message: String,
}

impl SentenceError {
    fn line(line: usize, message: impl Into<String>) -> Self {
        Self {
            message: format!("line {line}: {}", message.into()),
        }
    }

    fn request(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Read-only contract lookup needed to project a set rule onto one member action.
pub trait ContractResolver {
    fn contract(&self, provider: &str, action: &str) -> Option<&ActionContract>;

    fn action_is_money(&self, _provider: &str, _action: &str) -> bool {
        false
    }

    /// Whether one exact present field survives the provider's request-time rewrites and validation.
    /// Contract-only resolvers have no stricter provider semantics and therefore accept the value.
    fn present_field_is_valid(
        &self,
        _provider: &str,
        _action: &str,
        _field: &str,
        _value: &serde_json::Value,
    ) -> bool {
        true
    }
}

/// Provider semantics the sentence kernel needs without linking any provider executor.
pub trait ContractProvider {
    fn action_contract(&self, action: &str) -> Option<&ActionContract>;
    fn is_money_action(&self, action: &str) -> bool;
    fn canonicalize_present_fields(
        &self,
        action: &str,
        resource: &serde_json::Value,
    ) -> crate::Result<CanonicalResource>;
}

impl<T: ContractProvider + ?Sized> ContractResolver for HashMap<String, Box<T>> {
    fn contract(&self, provider: &str, action: &str) -> Option<&ActionContract> {
        self.get(provider)?.action_contract(action)
    }

    fn action_is_money(&self, provider: &str, action: &str) -> bool {
        self.get(provider)
            .is_some_and(|provider| provider.is_money_action(action))
    }

    fn present_field_is_valid(
        &self,
        provider: &str,
        action: &str,
        field: &str,
        value: &serde_json::Value,
    ) -> bool {
        let Some(provider) = self.get(provider) else {
            return false;
        };
        let resource =
            serde_json::Value::Object([(field.to_string(), value.clone())].into_iter().collect());
        provider
            .canonicalize_present_fields(action, &resource)
            .is_ok()
    }
}

/// One set-expanded sentence rule as it applies to a concrete action contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedRule {
    pub rule: Rule,
    pub original_indices: Vec<usize>,
}

/// An inert, shell-safe suggestion for a human: what would admit this request — by widening an
/// existing allow rule, by writing the first rule for a verb no rule mentions, or by naming a field
/// the request left out and the standing rule pins.
///
/// It is TEXT, and not always a command. A denial whose whole story is "the rule pins `team` and
/// your request omitted it" has no rule change worth proposing: the pin is the operator's, and the
/// fix belongs in the request. Printing a `cermet rules allow` line there would point at a surface
/// that cannot answer — and, worse, the line that would "work" is the one with the pin deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WidenHint {
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentenceEvaluation {
    pub decision: Decision,
    pub widen_hint: Option<WidenHint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentenceAuthoritySubsetError {
    kind: SentenceAuthoritySubsetErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SentenceAuthoritySubsetErrorKind {
    UnsupportedVersion(u32),
    InvalidRule(usize),
    UnpinnedSet,
}

impl std::fmt::Display for SentenceAuthoritySubsetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            SentenceAuthoritySubsetErrorKind::UnsupportedVersion(version) => {
                write!(f, "unsupported rules version {version}")
            }
            SentenceAuthoritySubsetErrorKind::InvalidRule(rule_idx) => {
                write!(
                    f,
                    "rule #{} is structurally invalid",
                    human_rule_number(rule_idx)
                )
            }
            SentenceAuthoritySubsetErrorKind::UnpinnedSet => write!(
                f,
                "stored set rules must pin an immutable sha256 expansion digest; re-run `cermet rules allow`"
            ),
        }
    }
}

impl std::error::Error for SentenceAuthoritySubsetError {}

/// Validate the complete sentence-authority subset (the pinned-set custody subset)
/// without changing the broker's allow+deny grammar. This is the one preflight for stored custody,
/// discovery, evaluation, and authorization.
pub fn validate_sentence_authority(rules: &RuleSet) -> Result<(), SentenceAuthoritySubsetError> {
    if !ruleset_version_supported(rules) {
        return Err(SentenceAuthoritySubsetError {
            kind: SentenceAuthoritySubsetErrorKind::UnsupportedVersion(rules.version),
        });
    }
    if let Some((rule_idx, _)) = rules
        .rules
        .iter()
        .enumerate()
        .find(|(_, rule)| validate_rule_structure(rule).is_err())
    {
        return Err(SentenceAuthoritySubsetError {
            kind: SentenceAuthoritySubsetErrorKind::InvalidRule(rule_idx),
        });
    }
    if !set_references_are_pinned(rules) {
        return Err(SentenceAuthoritySubsetError {
            kind: SentenceAuthoritySubsetErrorKind::UnpinnedSet,
        });
    }
    Ok(())
}

/// The shared sentence evaluator used by the persistent broker and the ctl sentence-custody path.
pub struct SentenceEvaluator<'a> {
    sets: &'a dyn SetResolver,
    contracts: &'a dyn ContractResolver,
}

/// One exact/unknown resource shape for symbolic sentence evaluation. A field named in
/// `present_unknown_fields` is guaranteed to materialize; another optional unknown may be omitted.
/// `field_variables` gives equal names to fields that must carry one shared value across a composition.
#[derive(Debug, Clone)]
pub(crate) struct ResourceShape {
    pub(crate) provider: String,
    pub(crate) action: String,
    pub(crate) known_fields: BTreeMap<String, serde_json::Value>,
    pub(crate) unknown_fields: BTreeSet<String>,
    pub(crate) present_unknown_fields: BTreeSet<String>,
    pub(crate) field_variables: BTreeMap<String, String>,
}

impl<'a> SentenceEvaluator<'a> {
    pub fn new(sets: &'a dyn SetResolver, contracts: &'a dyn ContractResolver) -> Self {
        Self { sets, contracts }
    }

    fn resolve_contract(&self, provider: &str, action: &str) -> Option<&ActionContract> {
        self.contracts
            .contract(provider, action)
            .filter(|contract| {
                (contract.provider == provider && contract.action == action)
                    || (contract.open && contract.provider == "mock" && contract.action == "*")
            })
    }

    fn resolve_set(
        &self,
        provider: &str,
        set: &str,
        digest: Option<&str>,
    ) -> Option<crate::sets::SetSnapshot> {
        let digest = digest?;
        if !crate::sets::valid_snapshot_digest(digest) {
            return None;
        }
        self.sets
            .snapshot(provider, set, digest)
            .filter(|snapshot| snapshot.is_for(provider, set, digest))
    }

    /// The exact immutable expansion a digest-pinned set selector denotes.
    pub fn set_members(&self, selector: &Selector) -> Option<Vec<String>> {
        let Selector::Set {
            provider,
            set,
            digest,
        } = selector
        else {
            return None;
        };
        self.resolve_set(provider, set, digest.as_deref())
            .map(|snapshot| snapshot.members().to_vec())
    }

    /// Deterministic action projection for discovery adapters. This expands immutable set selectors
    /// but confers no authority; every call still goes through [`Self::evaluate`].
    pub fn covered_actions(
        &self,
        rules: &RuleSet,
    ) -> Result<Vec<(String, String)>, SentenceAuthoritySubsetError> {
        validate_sentence_authority(rules)?;
        let mut covered = BTreeSet::new();
        for rule in &rules.rules {
            match &rule.selector {
                Selector::Verb { provider, action } => {
                    covered.insert((provider.clone(), action.clone()));
                }
                Selector::Set { provider, .. } => {
                    if let Some(members) = self.set_members(&rule.selector) {
                        covered
                            .extend(members.into_iter().map(|action| (provider.clone(), action)));
                    }
                }
            }
        }
        Ok(covered.into_iter().collect())
    }

    /// Read-only broker discovery projection for a bare action. Every contract field is an unknown
    /// potential request value; composed routes use [`Self::resource_shape_is_discoverable`] to keep
    /// their fixed fields fixed. This projection grants nothing; requests still evaluate exact values.
    pub fn action_is_discoverable(&self, rules: &RuleSet, provider: &str, action: &str) -> bool {
        let Some(contract) = self.resolve_contract(provider, action) else {
            return false;
        };
        let mut unknown_fields: BTreeSet<String> = contract
            .schema
            .iter()
            .map(|field| field.name.to_string())
            .collect();
        if contract.open {
            unknown_fields.extend(
                rules
                    .rules
                    .iter()
                    .flat_map(|rule| rule.conjuncts.iter().map(pred_field))
                    .map(str::to_string),
            );
        }
        self.resource_shape_is_discoverable(
            rules,
            provider,
            action,
            &BTreeMap::new(),
            &unknown_fields,
            &BTreeSet::new(),
        )
    }

    /// Whether at least one exact, contract-valid completion of a composed request shape evaluates
    /// to `Allow`. `known_fields` are immutable alias pins or pipeline literals; only names in
    /// `unknown_fields` may be supplied later; `present_unknown_fields` are the subset a composition
    /// always materializes even when the contract marks them optional. The decision is complete for
    /// the flat predicate grammar: symbolic scalar partitions are intersected per field and deny boxes
    /// are subtracted from allow boxes without enumerating Cartesian witnesses.
    pub fn resource_shape_is_discoverable(
        &self,
        rules: &RuleSet,
        provider: &str,
        action: &str,
        known_fields: &BTreeMap<String, serde_json::Value>,
        unknown_fields: &BTreeSet<String>,
        present_unknown_fields: &BTreeSet<String>,
    ) -> bool {
        self.resource_shapes_are_discoverable(
            rules,
            &[ResourceShape {
                provider: provider.to_string(),
                action: action.to_string(),
                known_fields: known_fields.clone(),
                unknown_fields: unknown_fields.clone(),
                present_unknown_fields: present_unknown_fields.clone(),
                field_variables: BTreeMap::new(),
            }],
        )
    }

    /// Complete symbolic satisfiability for a composition. Equal `field_variables` preserve one
    /// pipeline parameter's identity across every bound field and step; private fields remain
    /// existentially quantified within their own resource shape.
    pub(crate) fn resource_shapes_are_discoverable(
        &self,
        rules: &RuleSet,
        shapes: &[ResourceShape],
    ) -> bool {
        symbolic_shapes_are_discoverable(self, rules, shapes)
    }

    fn projected_discovery_rules(
        &self,
        rules: &RuleSet,
        provider: &str,
        action: &str,
    ) -> Option<(&ActionContract, Vec<Rule>)> {
        if !ruleset_version_supported(rules)
            || !set_references_are_pinned(rules)
            || rules
                .rules
                .iter()
                .any(|rule| validate_rule_structure(rule).is_err())
        {
            return None;
        }
        let contract = self.resolve_contract(provider, action)?;
        let mut projected_rules = Vec::new();
        for rule in &rules.rules {
            if !self.selector_may_cover(&rule.selector, provider, action) {
                continue;
            }
            let projected = self.project_rule(rule, provider, action)?;
            if !conjuncts_resolve(&projected.rule.conjuncts, contract) {
                return None;
            }
            projected_rules.push(projected.rule);
        }
        Some((contract, projected_rules))
    }

    pub fn evaluate(
        &self,
        rules: &RuleSet,
        provider: &str,
        action: &str,
        resource: &CanonicalResource,
    ) -> Decision {
        if !ruleset_version_supported(rules) {
            return Decision::Deny {
                reason: DenyReason::UnsupportedVersion {
                    version: rules.version,
                },
            };
        }
        let Some(contract) = self.resolve_contract(provider, action) else {
            return Decision::Deny {
                reason: DenyReason::UnknownSelector,
            };
        };
        let mut first_denial = None;
        let mut first_allow = None;
        for (rule_idx, rule) in rules.rules.iter().enumerate() {
            if validate_rule_structure(rule).is_err() {
                if rule.effect == RuleEffect::Deny
                    && self.selector_may_cover(&rule.selector, provider, action)
                {
                    return Decision::Deny {
                        reason: DenyReason::UnresolvedDeny { rule_idx },
                    };
                }
                continue;
            }
            if let Selector::Set {
                provider: selected,
                set,
                digest,
            } = &rule.selector
            {
                if rule.effect == RuleEffect::Deny
                    && selected == provider
                    && self.resolve_set(selected, set, digest.as_deref()).is_none()
                {
                    return Decision::Deny {
                        reason: DenyReason::UnresolvedDeny { rule_idx },
                    };
                }
            }
            if !self.covers(rule, provider, action) {
                continue;
            }
            let projected = match self.project_rule(rule, provider, action) {
                Some(projected) => projected,
                None if rule.effect == RuleEffect::Deny => {
                    return Decision::Deny {
                        reason: DenyReason::UnresolvedDeny { rule_idx },
                    };
                }
                None => continue,
            };
            if rule.effect == RuleEffect::Deny
                && !conjuncts_resolve(&projected.rule.conjuncts, contract)
            {
                return Decision::Deny {
                    reason: DenyReason::UnresolvedDeny { rule_idx },
                };
            }
            match evaluate_conjuncts(rule_idx, &projected.rule.conjuncts, resource) {
                Ok(()) => match rule.effect {
                    RuleEffect::Deny => {
                        return Decision::Deny {
                            reason: DenyReason::ExplicitDeny { rule_idx },
                        };
                    }
                    RuleEffect::Allow => {
                        first_allow.get_or_insert(rule_idx);
                    }
                },
                Err(reason) => {
                    let reason = match reason {
                        // Only the POSITION is projection-relative; the field name is the same
                        // predicate's either way, so it rides through unchanged.
                        DenyReason::PredicateMismatch {
                            rule_idx,
                            pred_idx,
                            field,
                        } => DenyReason::PredicateMismatch {
                            rule_idx,
                            pred_idx: projected.original_indices[pred_idx],
                            field,
                        },
                        reason => reason,
                    };
                    first_denial.get_or_insert(reason);
                }
            }
        }

        if let Some(rule_idx) = first_allow {
            // The first-matching Allow rule governs. `evaluate()` stays a PURE decision function (no
            // ledger, no clock), so an aggregate-bearing winner returns `Allow { rule_idx }`
            // exactly like a plain winner; the ledger-derived budget/rate GATE is a distinct step in the
            // mint handler (`broker::budget`), the only seam holding both the ledger and `now`. It
            // reads this typed `rule_idx`, meters that exact winning rule, and downgrades to a
            // value-free `BudgetExceeded { window }` deny (or mints a `budget_mint` before the grant).
            // A grant is NEVER minted for an aggregate rule without that gate passing.
            return Decision::Allow { rule_idx };
        }

        // The verb resolved (a contract was found above), so whatever happened here, it is
        // a corpus gap and not an unknown selector. `matched_selector` with no recorded denial means
        // a covering rule could not be projected onto this action, which is equally "no rule
        // admitted it".
        Decision::Deny {
            reason: first_denial.unwrap_or(DenyReason::NoMatchingRule),
        }
    }

    /// Evaluate once and attach a widening suggestion only to a typed out-of-bounds denial. The
    /// suggestion remains inert text; this method cannot mutate sentence authority.
    pub fn evaluate_with_widen_hint(
        &self,
        rules: &RuleSet,
        provider: &str,
        action: &str,
        resource: &CanonicalResource,
    ) -> SentenceEvaluation {
        let decision = self.evaluate(rules, provider, action, resource);
        let widen_hint = match &decision {
            Decision::Deny {
                reason: DenyReason::MissingField { .. } | DenyReason::PredicateMismatch { .. },
            } => self.widen_hint_for_request(rules, provider, action, resource),
            // A verb no rule mentions cannot be reached by widening an existing rule —
            // the path is a NEW allow, and the deny says which one.
            Decision::Deny {
                reason: DenyReason::NoMatchingRule,
            } => self.unruled_allow_hint(provider, action, resource),
            Decision::Allow { .. } | Decision::Deny { .. } => None,
        };
        SentenceEvaluation {
            decision,
            widen_hint,
        }
    }

    /// Evaluate the broker policy query representation through the same canonical-resource engine.
    /// A missing contract remains an ordinary fail-closed sentence decision; a malformed query value
    /// is returned separately so the policy adapter can report that boundary honestly.
    pub fn evaluate_match_value(
        &self,
        rules: &RuleSet,
        provider: &str,
        action: &str,
        resource: &serde_json::Value,
    ) -> Result<Decision, crate::Error> {
        let Some(contract) = self.resolve_contract(provider, action) else {
            return Ok(Decision::Deny {
                reason: DenyReason::UnknownSelector,
            });
        };
        let resource = CanonicalResource::from_stored(&resource.to_string(), contract)?;
        Ok(self.evaluate(rules, provider, action, &resource))
    }

    /// Whether `rule`'s selector names this verb — a verb selector by identity, a set selector
    /// through the pinned immutable expansion (an unresolvable set covers nothing: fail closed).
    /// Public for the discovery projection, which names the admitting sentence on the agent
    /// surface; it confers no authority — every request still goes through [`Self::evaluate`].
    pub fn covers(&self, rule: &Rule, provider: &str, action: &str) -> bool {
        match &rule.selector {
            Selector::Verb {
                provider: selected,
                action: selected_action,
            } => selected == provider && selected_action == action,
            Selector::Set {
                provider: selected,
                set,
                digest,
            } => {
                selected == provider
                    && self
                        .resolve_set(selected, set, digest.as_deref())
                        .is_some_and(|snapshot| {
                            snapshot.members().iter().any(|member| member == action)
                        })
            }
        }
    }

    fn selector_may_cover(&self, selector: &Selector, provider: &str, action: &str) -> bool {
        match selector {
            Selector::Verb {
                provider: selected,
                action: selected_action,
            } => selected == provider && selected_action == action,
            Selector::Set {
                provider: selected,
                set,
                digest,
            } => {
                selected == provider
                    && self
                        .resolve_set(selected, set, digest.as_deref())
                        .is_none_or(|snapshot| snapshot.members().iter().any(|item| item == action))
            }
        }
    }

    /// Project member-specific predicates while refusing fields absent from the whole set.
    pub fn project_rule(&self, rule: &Rule, provider: &str, action: &str) -> Option<ProjectedRule> {
        if !self.covers(rule, provider, action) {
            return None;
        }
        let Selector::Set {
            provider: selected,
            set,
            digest,
        } = &rule.selector
        else {
            return Some(ProjectedRule {
                rule: rule.clone(),
                original_indices: (0..rule.conjuncts.len()).collect(),
            });
        };
        let contract = self.resolve_contract(provider, action)?;
        let members = self
            .resolve_set(selected, set, digest.as_deref())?
            .members()
            .to_vec();
        let mut conjuncts = Vec::new();
        let mut original_indices = Vec::new();
        for (idx, pred) in rule.conjuncts.iter().enumerate() {
            let field = pred_field(pred);
            let exists_in_set = members.iter().any(|member| {
                self.resolve_contract(selected, member)
                    .is_some_and(|member_contract| {
                        member_contract.open || member_contract.field_decl(field).is_some()
                    })
            });
            if !exists_in_set {
                return None;
            }
            if contract.open || contract.field_decl(field).is_some() {
                conjuncts.push(pred.clone());
                original_indices.push(idx);
            }
        }
        Some(ProjectedRule {
            rule: Rule {
                effect: rule.effect,
                selector: rule.selector.clone(),
                conjuncts,
                aggregate: rule.aggregate.clone(),
            },
            original_indices,
        })
    }

    pub fn has_secret_conjunct(&self, rule: &Rule, provider: &str, action: &str) -> bool {
        rule.conjuncts.iter().any(|pred| {
            let field = pred_field(pred);
            match &rule.selector {
                Selector::Verb { .. } => {
                    self.resolve_contract(provider, action)
                        .is_some_and(|contract| {
                            contract.field_class(field) == Some(crate::contract::FieldClass::Secret)
                        })
                }
                Selector::Set {
                    provider: selected,
                    set,
                    digest,
                } => self
                    .resolve_set(selected, set, digest.as_deref())
                    .is_some_and(|snapshot| {
                        snapshot.members().iter().any(|member| {
                            self.resolve_contract(selected, member)
                                .is_some_and(|member_contract| {
                                    member_contract.field_class(field)
                                        == Some(crate::contract::FieldClass::Secret)
                                })
                        })
                    }),
            }
        })
    }

    /// Compute the first safe widening that admits this exact canonical request. This is advisory
    /// only: it returns text and cannot write, activate, or otherwise mutate sentence authority.
    pub fn widen_hint_for_request(
        &self,
        rules: &RuleSet,
        provider: &str,
        action: &str,
        resource: &CanonicalResource,
    ) -> Option<WidenHint> {
        if !ruleset_version_supported(rules) {
            return None;
        }
        let contract = self.resolve_contract(provider, action)?;
        let widened = rules
            .rules
            .iter()
            .enumerate()
            .filter_map(|(idx, rule)| {
                if validate_rule_structure(rule).is_err() {
                    return None;
                }
                if self.has_secret_conjunct(rule, provider, action) {
                    return None;
                }
                let effective = self.project_rule(rule, provider, action)?;
                let widened_effective =
                    widen_rule_for_request(&effective.rule, resource, contract)?;
                let omitted_pins = widened_effective.omitted_pins;
                let mut projected = widened_effective.rule.conjuncts.into_iter().peekable();
                let mut conjuncts = Vec::with_capacity(rule.conjuncts.len());
                for (original_idx, original) in rule.conjuncts.iter().enumerate() {
                    if effective
                        .original_indices
                        .binary_search(&original_idx)
                        .is_err()
                    {
                        conjuncts.push(original.clone());
                    } else if projected
                        .peek()
                        .is_some_and(|pred| pred_field(pred) == pred_field(original))
                    {
                        conjuncts.push(projected.next().expect("peeked as present"));
                    }
                }
                let reconstructed = Rule {
                    effect: rule.effect,
                    selector: rule.selector.clone(),
                    conjuncts,
                    aggregate: rule.aggregate.clone(),
                };
                if validate_rule_structure(&reconstructed).is_err()
                    || !rule_codec_round_trips(&reconstructed)
                {
                    return None;
                }
                let unchanged = reconstructed == *rule;
                Some((idx, reconstructed, omitted_pins, unchanged))
            })
            .next()?;
        let (_, reconstructed, omitted_pins, unchanged) = widened;
        let omitted = named_fields(&omitted_pins);
        // The rule already says everything it is going to say: the request omitted a field this
        // rule pins, and every other conjunct matched. There is no widening to propose — the only
        // rule text that would admit the request as written is this one with the pin DELETED, which
        // is a scope change no denial gets to suggest on a requester's behalf. So the hint addresses
        // the request instead.
        if unchanged {
            return Some(WidenHint {
                text: format!(
                    "the standing rule `{}` pins {omitted}, and this request named {}; name {} in \
                     the request — no rule change admits it while that pin stands",
                    print_rule(&reconstructed),
                    if omitted_pins.len() == 1 {
                        "no such field"
                    } else {
                        "no such fields"
                    },
                    if omitted_pins.len() == 1 {
                        "it"
                    } else {
                        "them"
                    },
                ),
            });
        }
        let command = allow_command(&print_rule(&reconstructed));
        if omitted_pins.is_empty() {
            return Some(WidenHint { text: command });
        }
        // A widening that still carries a pin the request never spoke to is not a rule the request
        // would then pass, and saying so is the difference between a remedy and a dead end.
        //
        // The clause goes BEFORE the command, never after it. Everything downstream of `to allow: `
        // is read as the command itself — the MCP bridge strips that marker and labels the rest an
        // "Advisory widen command", and an operator pastes what follows it — so a sentence trailing
        // the closing quote turns a runnable line into a broken one. Leading prose costs nothing:
        // the bridge simply renders the whole thing as a hint, which is what it is.
        Some(WidenHint {
            text: format!(
                "this request also omitted {omitted}, which the rule pins and this suggestion \
                 keeps, so name {} in the request too — {command}",
                if omitted_pins.len() == 1 {
                    "it"
                } else {
                    "them"
                },
            ),
        })
    }

    /// The widening path for a verb NO rule mentions. There is nothing to widen, so the
    /// suggestion is the FIRST rule that would admit this exact request: least privilege when the
    /// contract can be pinned (every execution target fixed to what was actually asked for), and the
    /// bare allow when it declares no execution target — which is the `scope: account` shape, where a
    /// bare allow is the only rule that can admit it at all.
    ///
    /// Advisory only, exactly like [`Self::widen_hint_for_request`]: it returns text and cannot
    /// write, activate, or otherwise mutate sentence authority. It suggests nothing it cannot prove
    /// admits the request — a rule that fails structure, codec round-trip, or its own matching is no
    /// suggestion at all.
    fn unruled_allow_hint(
        &self,
        provider: &str,
        action: &str,
        resource: &CanonicalResource,
    ) -> Option<WidenHint> {
        let contract = self.resolve_contract(provider, action)?;
        let selector = Selector::Verb {
            provider: provider.to_string(),
            action: action.to_string(),
        };
        let mut conjuncts = Vec::new();
        if contract.has_fully_pinned_execution_targets() {
            for target in contract.execution_targets {
                // A Secret field is never printed into operator-facing text, here as everywhere.
                if contract.field_class(target) == Some(crate::contract::FieldClass::Secret) {
                    return None;
                }
                let Some(value) = resource.scalar(target) else {
                    // An OPTIONAL target this request omitted: it froze as absence, so there is no
                    // value to pin and pinning it would suggest a rule that refuses the very request
                    // it is meant to admit. The suggestion leaves it unconstrained, which is exactly
                    // what "the request named no scope" means. An absent REQUIRED target is a
                    // resource the contract says cannot exist — no suggestion is made for it.
                    if contract
                        .field_decl(target)
                        .is_some_and(|decl| decl.required)
                    {
                        return None;
                    }
                    continue;
                };
                conjuncts.push(Pred::Eq {
                    field: (*target).to_string(),
                    value: sentence_scalar(value),
                });
            }
        }
        let rule = Rule {
            effect: RuleEffect::Allow,
            selector,
            conjuncts,
            aggregate: None,
        };
        if validate_rule_structure(&rule).is_err() || !rule_codec_round_trips(&rule) {
            return None;
        }
        if !conjuncts_match_resource(&rule.conjuncts, resource, contract) {
            return None;
        }
        Some(WidenHint {
            text: allow_command(&print_rule(&rule)),
        })
    }
}

/// Field names as a denial spells a list of them: backticked, comma-joined, in rule order.
fn named_fields(fields: &[String]) -> String {
    fields
        .iter()
        .map(|field| format!("`{field}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The one shell-safe rendering of a suggested allow rule, shared by both suggestion paths.
fn allow_command(printed_rule: &str) -> String {
    let argument = printed_rule.strip_prefix("allow ").unwrap_or(printed_rule);
    format!(
        "to allow: cermet rules allow {}",
        posix_shell_quote(argument)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Quoted(String),
    Eq,
    Lte,
    Gte,
    LeftBrace,
    RightBrace,
    Comma,
}

pub fn parse_rules(text: &str) -> Result<RuleSet, SentenceError> {
    let mut rules = Vec::new();
    for (line_idx, raw_line) in text.lines().enumerate() {
        let line_number = line_idx + 1;
        let line = without_comment(raw_line);
        if line.trim().is_empty() {
            continue;
        }
        let tokens = tokenize(line, line_number)?;
        rules.push(parse_rule(&tokens, line_number)?);
    }
    Ok(RuleSet {
        version: RULE_SET_VERSION,
        rules,
    })
}

fn ruleset_version_supported(rules: &RuleSet) -> bool {
    rules.version == RULE_SET_VERSION
}

/// Stable fingerprint of the structural ruleset, independent of authored whitespace/comments.
/// `RuleSet` contains only ordered structs/enums (no maps), so its serde JSON is a canonical byte
/// representation of every authority-bearing field, including the ruleset version and set digests.
pub fn ruleset_fingerprint(rules: &RuleSet) -> String {
    use sha2::{Digest, Sha256};

    let canonical = serde_json::to_vec(rules).expect("RuleSet serialization is infallible");
    let mut hash = Sha256::new();
    hash.update(canonical);
    crate::util::hex(&hash.finalize())
}

/// Whether every set selector is bound to a syntactically valid immutable expansion snapshot.
fn set_references_are_pinned(rules: &RuleSet) -> bool {
    rules.rules.iter().all(|rule| match &rule.selector {
        Selector::Verb { .. } => true,
        Selector::Set { digest, .. } => digest
            .as_deref()
            .is_some_and(crate::sets::valid_snapshot_digest),
    })
}

/// Bind every authored set reference to the resolver's current immutable expansion before storage.
/// Already-pinned references are accepted only when that exact snapshot still resolves.
pub fn pin_set_references(
    rules: &mut RuleSet,
    sets: &dyn SetResolver,
) -> Result<(), SentenceError> {
    if rules.version != RULE_SET_VERSION {
        return Err(SentenceError::request(format!(
            "unsupported rules version {}",
            rules.version
        )));
    }
    for rule in &mut rules.rules {
        let Selector::Set {
            provider,
            set,
            digest,
        } = &mut rule.selector
        else {
            continue;
        };
        let snapshot = match digest.as_deref() {
            Some(pinned) => sets
                .snapshot(provider, set, pinned)
                .filter(|snapshot| snapshot.is_for(provider, set, pinned)),
            None => sets
                .current_snapshot(provider, set)
                .filter(|snapshot| snapshot.is_for(provider, set, snapshot.digest())),
        }
        .ok_or_else(|| {
            SentenceError::request(format!(
                "set `{provider}.{set}` does not resolve to the requested immutable snapshot"
            ))
        })?;
        *digest = Some(snapshot.digest().to_string());
    }
    Ok(())
}

/// The declared daemon-config key that decides whether temporal (windowed) clauses are admissible.
/// Named in the refusal so the operator reads the fix, not just the refusal: the gate is a
/// SETTING, and a setting that no message names is unfindable.
pub const TEMPORAL_CLAUSES_SETTING: &str = "language_temporal_clauses";

/// Fail closed on any temporal clause while the gate is OFF (the shipped default).
///
/// `rate N per <window>` and `budget [field] N per <window>` are the only clauses whose decision
/// reads accumulated state — a counter over a calendar window — rather than the request alone. The
/// shipped default suspends them: a decision must be a pure function of `(request, corpus)`. The
/// MACHINERY stays compiled and tested (it may return), so the suspension is a gate at corpus
/// admission, not a deletion.
///
/// It refuses rather than ignores. Silently dropping the clause would turn an authored cap into
/// unmetered standing authority — a widening the operator never wrote.
pub fn validate_temporal_clauses(rules: &RuleSet, enabled: bool) -> Result<(), SentenceError> {
    if enabled {
        return Ok(());
    }
    for (rule_idx, rule) in rules.rules.iter().enumerate() {
        if rule.aggregate.is_some() {
            return Err(SentenceError::request(format!(
                "rule {}: temporal clauses (`rate … per …`, `budget … per …`) are disabled \
                 ({TEMPORAL_CLAUSES_SETTING} in the daemon config): decisions are computed from \
                 the request alone",
                human_rule_number(rule_idx)
            )));
        }
    }
    Ok(())
}

/// Parse, pin, semantically validate, canonically print, and digest one candidate corpus without
/// writing anything. Both daemon preparation and staging call this exact function.
///
/// `temporal_clauses` is the daemon's declared [`TEMPORAL_CLAUSES_SETTING`] value; it reaches here
/// from the broker so this stays the ONE corpus-admission seam that decides admissibility.
pub fn prepare_sentence_authority(
    candidate_text: &str,
    sets: &dyn SetResolver,
    contracts: &dyn ContractResolver,
    temporal_clauses: bool,
) -> Result<PreparedSentenceCorpus, SentenceError> {
    let mut rules = parse_rules(candidate_text)?;
    validate_temporal_clauses(&rules, temporal_clauses)?;
    pin_set_references(&mut rules, sets)?;
    validate_sentence_authority(&rules)
        .map_err(|error| SentenceError::request(format!("authority subset is invalid: {error}")))?;
    reject_secret_conjuncts(&rules, sets, contracts)?;
    validate_references(&rules, sets, contracts).map_err(|error| {
        SentenceError::request(format!("unresolved authority reference: {error}"))
    })?;
    validate_aggregate_shadowing(&rules, sets).map_err(|error| {
        SentenceError::request(format!("authority shadows a budget/rate rule: {error}"))
    })?;
    validate_money_authority(&rules, sets, contracts)?;

    let canonical_bytes = canonical_rule_bytes(&rules);
    let canonical_text = String::from_utf8(canonical_bytes.clone())
        .expect("the sentence canonical printer emits UTF-8");
    let mut set_snapshots = Vec::new();
    for (rule_index, rule) in rules.rules.iter().enumerate() {
        let Selector::Set {
            provider,
            set,
            digest: Some(digest),
        } = &rule.selector
        else {
            continue;
        };
        let snapshot = sets
            .snapshot(provider, set, digest)
            .filter(|snapshot| snapshot.is_for(provider, set, digest))
            .ok_or_else(|| {
                SentenceError::request(format!(
                    "set `{provider}.{set}` no longer resolves to its prepared snapshot"
                ))
            })?;
        set_snapshots.push(PreparedSetSnapshot {
            rule_index,
            provider: provider.clone(),
            set: set.clone(),
            digest: digest.clone(),
            members: snapshot.members().to_vec(),
        });
    }

    Ok(PreparedSentenceCorpus {
        canonical_digest: authority_digest_for(rules.version, &canonical_bytes),
        canonical_text,
        rule_count: rules.rules.len(),
        set_snapshots,
    })
}

/// Require each projected money allow to carry one exact account, mode, and currency conjunct. This
/// is semantic validation over the existing predicate grammar; it adds no syntax.
pub fn validate_money_authority(
    rules: &RuleSet,
    sets: &dyn SetResolver,
    contracts: &dyn ContractResolver,
) -> Result<(), SentenceError> {
    let evaluator = SentenceEvaluator::new(sets, contracts);
    for (rule_idx, rule) in rules.rules.iter().enumerate() {
        if rule.effect != RuleEffect::Allow {
            continue;
        }
        let actions: Vec<(String, String)> = match &rule.selector {
            Selector::Verb { provider, action } => vec![(provider.clone(), action.clone())],
            Selector::Set {
                provider,
                set,
                digest: Some(digest),
            } => sets
                .snapshot(provider, set, digest)
                .filter(|snapshot| snapshot.is_for(provider, set, digest))
                .map(|snapshot| {
                    snapshot
                        .members()
                        .iter()
                        .map(|action| (provider.clone(), action.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            Selector::Set { .. } => Vec::new(),
        };
        for (provider, action) in actions {
            if !contracts.action_is_money(&provider, &action) {
                continue;
            }
            let projected = evaluator
                .project_rule(rule, &provider, &action)
                .ok_or_else(|| {
                    SentenceError::request(format!(
                        "money allow rule #{} cannot be projected onto {provider}.{action}",
                        human_rule_number(rule_idx)
                    ))
                })?;
            for field in ["account", "mode", "currency"] {
                let exact = projected
                    .rule
                    .conjuncts
                    .iter()
                    .filter(|pred| pred_field(pred) == field)
                    .collect::<Vec<_>>();
                if exact.len() != 1 || !matches!(exact[0], Pred::Eq { .. }) {
                    return Err(SentenceError::request(format!(
                        "money allow rule #{} for {provider}.{action} must contain exactly one `{field} = ...` conjunct",
                        human_rule_number(rule_idx)
                    )));
                }
            }
        }
    }
    Ok(())
}

fn reject_secret_conjuncts(
    rules: &RuleSet,
    sets: &dyn SetResolver,
    contracts: &dyn ContractResolver,
) -> Result<(), SentenceError> {
    for rule in &rules.rules {
        let members = selector_members(&rule.selector, sets).ok_or_else(|| {
            SentenceError::request("authority selector does not resolve to live contracts")
        })?;
        let fields = rule
            .conjuncts
            .iter()
            .map(reference_pred_field)
            .chain(aggregate_budget_field(rule));
        for field in fields {
            if members.iter().any(|(provider, action)| {
                contracts
                    .contract(provider, action)
                    .and_then(|contract| contract.field_class(field))
                    == Some(FieldClass::Secret)
            }) {
                return Err(SentenceError::request(format!(
                    "authority may not constrain secret-class field `{field}`"
                )));
            }
        }
    }
    Ok(())
}

pub fn print_rule(rule: &Rule) -> String {
    let selector = match &rule.selector {
        Selector::Set {
            provider,
            set,
            digest,
        } => match digest {
            Some(digest) => format!("{provider}.{set}@{digest}"),
            // Unreachable from parsed text (a set is spelled by its pinned expansion and nothing
            // else) and unreachable from stored authority (`set_references_are_pinned`). Printed
            // for completeness only; `rule_codec_round_trips` refuses it, which is the right
            // conservative answer for a selector the dialect cannot spell.
            None => format!("{provider}.{set}"),
        },
        // The bare dotted form IS the verb. The `word:` prefix namespace is reserved for future
        // set forms, so nothing needs a prefix to disambiguate.
        Selector::Verb { provider, action } => format!("{provider}.{action}"),
    };
    let effect = match rule.effect {
        RuleEffect::Allow => "allow",
        RuleEffect::Deny => "deny",
    };
    let mut out = format!("{effect} {selector}");
    if !rule.conjuncts.is_empty() || rule.aggregate.is_some() {
        out.push_str(" where ");
        for (idx, pred) in rule.conjuncts.iter().enumerate() {
            if idx != 0 {
                out.push_str(" and ");
            }
            match pred {
                Pred::Eq { field, value } => {
                    out.push_str(field);
                    out.push_str(" = ");
                    out.push_str(&print_scalar(value));
                }
                Pred::Lte { field, value } => {
                    out.push_str(&format!("{field} <= {value}"));
                }
                Pred::Gte { field, value } => {
                    out.push_str(&format!("{field} >= {value}"));
                }
                Pred::In { field, values } => {
                    out.push_str(field);
                    out.push_str(" in {");
                    for (value_idx, value) in values.iter().enumerate() {
                        if value_idx != 0 {
                            out.push_str(", ");
                        }
                        out.push_str(&print_scalar(value));
                    }
                    out.push('}');
                }
            }
        }
        if let Some(aggregate) = &rule.aggregate {
            if !rule.conjuncts.is_empty() {
                out.push_str(" and ");
            }
            out.push_str(&print_aggregate(aggregate));
        }
    }
    out
}

fn print_aggregate(aggregate: &Aggregate) -> String {
    let window = match aggregate.window {
        Window::Hour => "hour",
        Window::Day => "day",
    };
    match &aggregate.kind {
        AggregateKind::Budget { field: Some(field) } => {
            format!("budget {field} {} per {window}", aggregate.limit)
        }
        AggregateKind::Budget { field: None } => {
            format!("budget {} per {window}", aggregate.limit)
        }
        AggregateKind::Rate => format!("rate {} per {window}", aggregate.limit),
    }
}

/// Whether these predicates match this resource under this exact contract. This helper is
/// deliberately non-authorizing: it does not inspect a selector, effect, ruleset, or set snapshot.
pub fn conjuncts_match_resource(
    conjuncts: &[Pred],
    resource: &CanonicalResource,
    contract: &ActionContract,
) -> bool {
    if !conjuncts.iter().all(pred_is_well_formed) || !conjuncts_resolve(conjuncts, contract) {
        return false;
    }
    let Ok(resource) = CanonicalResource::from_stored(&resource.to_canonical_json(), contract)
    else {
        return false;
    };
    evaluate_conjuncts(0, conjuncts, &resource).is_ok()
}

/// One computed widening: the rule, and which of its pins the request never spoke to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Widening {
    /// The widened rule. Every conjunct over a field this request OMITTED is carried into it
    /// VERBATIM — value and all.
    pub rule: Rule,
    /// Those fields, in rule order. Non-empty means the rule alone does not admit the request: it
    /// still pins something the request never named, and the request is what has to change.
    pub omitted_pins: Vec<String>,
}

/// Widen one allow rule while proving both old-authority containment and admission of this request.
///
/// A conjunct over a field the request OMITTED is not a conjunct that failed — it is one the request
/// never spoke to, and dropping it is not widening but DELETION of a pin the operator wrote. The
/// dropped-pin form of this suggestion was a scope escape with a paste in the middle: a request that
/// simply left `team` out earned a suggestion whose text was the same rule with the team pin gone,
/// and any requester could manufacture that by omitting the field. So the pin is carried through and
/// [`Widening::omitted_pins`] names it; the caller says so in words.
pub fn widen_rule_for_request(
    old: &Rule,
    resource: &CanonicalResource,
    contract: &ActionContract,
) -> Option<Widening> {
    if validate_rule_structure(old).is_err() {
        return None;
    }
    // Aggregate-bearing rules are excluded from widening: a widened budget/rate is a
    // new authored sentence with a fresh counter, never a mechanical relaxation of the old rule.
    if old.aggregate.is_some() {
        return None;
    }
    if old
        .conjuncts
        .iter()
        .any(|pred| contract.field_decl(pred_field(pred)).is_none())
    {
        return None;
    }
    if old.conjuncts.iter().any(|pred| {
        contract.field_class(pred_field(pred)) == Some(crate::contract::FieldClass::Secret)
    }) {
        return None;
    }
    let mut conjuncts = Vec::with_capacity(old.conjuncts.len());
    let mut omitted_pins = Vec::new();
    let mut changed = false;
    for mut pred in old.conjuncts.clone() {
        let field = pred_field(&pred).to_string();
        let Some(value) = resource.scalar(&field) else {
            // The request never named this field. Carry the conjunct — whatever its shape:
            // equality, in-set, or a comparison — exactly as the operator wrote it.
            omitted_pins.push(field);
            conjuncts.push(pred);
            continue;
        };
        match &mut pred {
            Pred::Eq {
                value: expected, ..
            } if !scalar_matches(expected, value) => {
                let old_value = expected.clone();
                let new_value = sentence_scalar(value);
                pred = Pred::In {
                    field,
                    values: vec![old_value, new_value],
                };
                changed = true;
            }
            Pred::In { values, .. }
                if !values
                    .iter()
                    .any(|expected| scalar_matches(expected, value)) =>
            {
                values.push(sentence_scalar(value));
                changed = true;
            }
            Pred::Lte { value: limit, .. } => {
                let ResourceScalar::Int(requested) = value else {
                    return None;
                };
                if *requested > *limit {
                    *limit = *requested;
                    changed = true;
                }
            }
            Pred::Gte { value: limit, .. } => {
                let ResourceScalar::Int(requested) = value else {
                    return None;
                };
                if *requested < *limit {
                    *limit = *requested;
                    changed = true;
                }
            }
            _ => {}
        }
        conjuncts.push(pred);
    }

    let widened = Rule {
        effect: old.effect,
        selector: old.selector.clone(),
        conjuncts,
        aggregate: old.aggregate.clone(),
    };
    // Nothing to say: neither a conjunct relaxed nor a pin the request left unspoken.
    if !implies(old, &widened, contract) || (!changed && omitted_pins.is_empty()) {
        return None;
    }
    if widened.effect != RuleEffect::Allow {
        return None;
    }
    // The admission proof runs over the conjuncts the request can actually be judged against. A
    // carried pin is excluded by construction — the request omitted its field, so it can neither
    // pass nor fail it — and that residue is exactly what `omitted_pins` reports instead of hiding
    // by deleting the conjunct.
    let judged: Vec<Pred> = widened
        .conjuncts
        .iter()
        .filter(|pred| !omitted_pins.iter().any(|field| field == pred_field(pred)))
        .cloned()
        .collect();
    conjuncts_match_resource(&judged, resource, contract).then_some(Widening {
        rule: widened,
        omitted_pins,
    })
}

/// The sentence literal denoting one exact frozen request value. There is one representation per
/// kind: a string is quoted, so nothing has to prove which spelling round-trips.
fn sentence_scalar(value: &ResourceScalar) -> Scalar {
    match value {
        ResourceScalar::Int(value) => Scalar::Int(*value),
        ResourceScalar::Str(value) => Scalar::String(value.clone()),
        ResourceScalar::Bool(value) => Scalar::Bool(*value),
    }
}

fn posix_shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn rule_codec_round_trips(rule: &Rule) -> bool {
    parse_rules(&print_rule(rule))
        .ok()
        .is_some_and(|parsed| parsed.rules.len() == 1 && parsed.rules.first() == Some(rule))
}

fn evaluate_conjuncts(
    rule_idx: usize,
    conjuncts: &[Pred],
    resource: &CanonicalResource,
) -> Result<(), DenyReason> {
    for (pred_idx, pred) in conjuncts.iter().enumerate() {
        let field = pred_field(pred);
        let Some(actual) = resource.scalar(field) else {
            return Err(DenyReason::MissingField {
                rule_idx,
                field: field.to_string(),
            });
        };
        if !pred_matches(pred, actual) {
            // The field the failing predicate constrains — already in hand from `pred_field` above,
            // which is why the name costs nothing and is never reconstructed downstream.
            return Err(DenyReason::PredicateMismatch {
                rule_idx,
                pred_idx,
                field: Some(field.to_string()),
            });
        }
    }
    Ok(())
}

fn conjuncts_resolve(conjuncts: &[Pred], contract: &ActionContract) -> bool {
    conjuncts.iter().all(|pred| {
        contract.open
            || contract
                .field_decl(pred_field(pred))
                .is_some_and(|decl| pred_resolves_for_decl(pred, decl))
    })
}

#[derive(Debug, Clone)]
enum SymbolicAtom {
    Absent,
    Str(String),
    StrOther,
    IntRange(i64, i64),
    Bool(bool),
    AnyPresent,
}

#[derive(Debug, Default)]
struct VariableSpec {
    kind: Option<ScalarKind>,
    strings: BTreeSet<String>,
    integers: BTreeSet<i64>,
}

impl VariableSpec {
    fn constrain_kind(&mut self, kind: ScalarKind) -> bool {
        if self.kind.is_some_and(|current| current != kind) {
            return false;
        }
        self.kind = Some(kind);
        true
    }

    fn add_scalar(&mut self, scalar: &ResourceScalar) {
        match scalar {
            ResourceScalar::Str(value) => {
                self.strings.insert(value.clone());
            }
            ResourceScalar::Int(value) => {
                self.integers.insert(*value);
            }
            ResourceScalar::Bool(_) => {}
        }
    }

    fn add_predicate(&mut self, pred: &Pred) {
        match pred {
            Pred::Eq { value, .. } => self.add_sentence_scalar(value),
            Pred::Lte { value, .. } | Pred::Gte { value, .. } => {
                self.integers.insert(*value);
            }
            Pred::In { values, .. } => {
                for value in values {
                    self.add_sentence_scalar(value);
                }
            }
        }
    }

    fn add_sentence_scalar(&mut self, scalar: &Scalar) {
        match scalar {
            Scalar::String(value) => {
                self.strings.insert(value.clone());
            }
            Scalar::Int(value) => {
                self.integers.insert(*value);
            }
            Scalar::Bool(_) => {}
        }
    }

    fn atoms(self) -> Vec<SymbolicAtom> {
        let mut atoms = vec![SymbolicAtom::Absent];
        match self.kind {
            Some(ScalarKind::Str) => {
                atoms.extend(self.strings.into_iter().map(SymbolicAtom::Str));
                atoms.push(SymbolicAtom::StrOther);
            }
            Some(ScalarKind::Int) => {
                let mut next = i64::MIN;
                for point in self.integers {
                    if next < point {
                        atoms.push(SymbolicAtom::IntRange(next, point - 1));
                    }
                    atoms.push(SymbolicAtom::IntRange(point, point));
                    let Some(after) = point.checked_add(1) else {
                        return atoms;
                    };
                    next = after;
                }
                atoms.push(SymbolicAtom::IntRange(next, i64::MAX));
            }
            Some(ScalarKind::Bool) => {
                atoms.push(SymbolicAtom::Bool(false));
                atoms.push(SymbolicAtom::Bool(true));
            }
            None => atoms.push(SymbolicAtom::AnyPresent),
        }
        atoms
    }
}

#[derive(Debug, Clone)]
enum SymbolicBase {
    Known(ResourceScalar),
    Unknown { may_be_absent: bool },
    Absent,
}

struct PendingSymbolicShape {
    provider: String,
    action: String,
    rules: Vec<Rule>,
    field_variables: BTreeMap<String, String>,
    bases: Vec<(String, SymbolicBase)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SymbolicRegion {
    domains: Vec<BTreeSet<usize>>,
}

fn symbolic_shapes_are_discoverable(
    evaluator: &SentenceEvaluator<'_>,
    rules: &RuleSet,
    shapes: &[ResourceShape],
) -> bool {
    if shapes.is_empty() {
        return false;
    }

    let mut specs: BTreeMap<String, VariableSpec> = BTreeMap::new();
    let mut pending = Vec::with_capacity(shapes.len());
    for (shape_idx, shape) in shapes.iter().enumerate() {
        let Some((contract, projected_rules)) =
            evaluator.projected_discovery_rules(rules, &shape.provider, &shape.action)
        else {
            return false;
        };
        if !projected_rules
            .iter()
            .any(|rule| rule.effect == RuleEffect::Allow)
            || !shape
                .known_fields
                .keys()
                .all(|field| contract.open || contract.field_decl(field).is_some())
            || !shape
                .unknown_fields
                .iter()
                .all(|field| contract.open || contract.field_decl(field).is_some())
            || !shape
                .present_unknown_fields
                .is_subset(&shape.unknown_fields)
            || contract.schema.iter().any(|field| {
                field.required
                    && !shape.known_fields.contains_key(field.name)
                    && !shape.unknown_fields.contains(field.name)
            })
        {
            return false;
        }

        let mut relevant_fields: BTreeSet<String> = shape.known_fields.keys().cloned().collect();
        relevant_fields.extend(shape.unknown_fields.iter().cloned());
        relevant_fields.extend(
            contract
                .schema
                .iter()
                .filter(|field| field.required)
                .map(|field| field.name.to_string()),
        );
        relevant_fields.extend(
            projected_rules
                .iter()
                .flat_map(|rule| rule.conjuncts.iter())
                .map(pred_field)
                .map(str::to_string),
        );

        let mut field_variables = BTreeMap::new();
        let mut bases = Vec::with_capacity(relevant_fields.len());
        for field in relevant_fields {
            let variable = shape
                .field_variables
                .get(&field)
                .cloned()
                .unwrap_or_else(|| format!("shape:{shape_idx}:field:{field}"));
            let field_predicates: Vec<&Pred> = projected_rules
                .iter()
                .flat_map(|rule| rule.conjuncts.iter())
                .filter(|pred| pred_field(pred) == field)
                .collect();
            let known = shape.known_fields.get(&field).and_then(|value| {
                contract.field_decl(&field).map_or_else(
                    || {
                        contract
                            .open
                            .then(|| ResourceScalar::infer(&field, value).ok())
                            .flatten()
                    },
                    |decl| ResourceScalar::from_json(decl.ty, &field, value).ok(),
                )
            });
            if shape.known_fields.contains_key(&field) && known.is_none() {
                return false;
            }
            let kind = contract
                .field_kind(&field)
                .or_else(|| known.as_ref().map(ResourceScalar::kind))
                .or_else(|| open_predicate_kind(&field_predicates));
            if !field_predicates.is_empty() && kind.is_none() {
                return false;
            }
            let spec = specs.entry(variable.clone()).or_default();
            if kind.is_some_and(|kind| !spec.constrain_kind(kind))
                || field_predicates
                    .iter()
                    .any(|pred| predicate_kind(pred).is_some_and(|kind| !spec.constrain_kind(kind)))
            {
                return false;
            }
            if let Some(known) = &known {
                spec.add_scalar(known);
            }
            for pred in field_predicates {
                spec.add_predicate(pred);
            }

            let required = contract
                .field_decl(&field)
                .is_some_and(|decl| decl.required);
            let base = if let Some(known) = known {
                SymbolicBase::Known(known)
            } else if shape.unknown_fields.contains(&field) {
                SymbolicBase::Unknown {
                    may_be_absent: !required && !shape.present_unknown_fields.contains(&field),
                }
            } else {
                SymbolicBase::Absent
            };
            field_variables.insert(field, variable.clone());
            bases.push((variable, base));
        }
        pending.push(PendingSymbolicShape {
            provider: shape.provider.clone(),
            action: shape.action.clone(),
            rules: projected_rules,
            field_variables,
            bases,
        });
    }

    let mut variable_indices = BTreeMap::new();
    let mut universes = Vec::with_capacity(specs.len());
    for (variable, spec) in specs {
        variable_indices.insert(variable, universes.len());
        universes.push(spec.atoms());
    }
    let mut base = SymbolicRegion {
        domains: universes
            .iter()
            .map(|atoms| (0..atoms.len()).collect())
            .collect(),
    };
    for (shape, source_shape) in pending.iter().zip(shapes) {
        for (field, variable) in &shape.field_variables {
            let Some(&index) = variable_indices.get(variable) else {
                return false;
            };
            // Request-time validity governs only request-suppliable fields. An
            // evidence-output (unknown) field NEVER appears in a request — the broker resolves
            // it and the rule's pin constrains the MERGED resource — so pruning its atoms
            // through the provider's request rewrite (which refuses provider-resolved fields
            // outright) would declare every trio-pinned money rule unsatisfiable and make every
            // evidence-profile verb undeliverable under sentence authority.
            if source_shape.unknown_fields.contains(field) {
                continue;
            }
            base.domains[index].retain(|atom_idx| {
                symbolic_atom_exact_json(&universes[index][*atom_idx]).is_none_or(|value| {
                    evaluator.contracts.present_field_is_valid(
                        &shape.provider,
                        &shape.action,
                        field,
                        &value,
                    )
                })
            });
            if base.domains[index].is_empty() {
                return false;
            }
        }
        for (variable, field_base) in &shape.bases {
            let Some(&index) = variable_indices.get(variable) else {
                return false;
            };
            let allowed: BTreeSet<usize> = match field_base {
                SymbolicBase::Known(value) => universes[index]
                    .iter()
                    .position(|atom| atom_contains_scalar(atom, value))
                    .into_iter()
                    .collect(),
                SymbolicBase::Unknown { may_be_absent } => universes[index]
                    .iter()
                    .enumerate()
                    .filter(|(_, atom)| *may_be_absent || !matches!(atom, SymbolicAtom::Absent))
                    .map(|(atom_idx, _)| atom_idx)
                    .collect(),
                SymbolicBase::Absent => universes[index]
                    .iter()
                    .position(|atom| matches!(atom, SymbolicAtom::Absent))
                    .into_iter()
                    .collect(),
            };
            base.domains[index] = base.domains[index]
                .intersection(&allowed)
                .copied()
                .collect();
            if base.domains[index].is_empty() {
                return false;
            }
        }
    }

    let prepared: Vec<_> = pending
        .into_iter()
        .map(|shape| {
            let field_variables = shape
                .field_variables
                .into_iter()
                .map(|(field, variable)| {
                    variable_indices
                        .get(&variable)
                        .copied()
                        .map(|index| (field, index))
                })
                .collect::<Option<BTreeMap<_, _>>>()?;
            Some((shape.rules, field_variables))
        })
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    if prepared.len() != shapes.len() {
        return false;
    }

    let mut combined = vec![base.clone()];
    for (shape_rules, field_variables) in prepared {
        let denies: Vec<_> = shape_rules
            .iter()
            .filter(|rule| rule.effect == RuleEffect::Deny)
            .filter_map(|rule| symbolic_rule_region(&base, rule, &field_variables, &universes))
            .collect();
        let mut allowed = Vec::new();
        for allow in shape_rules
            .iter()
            .filter(|rule| rule.effect == RuleEffect::Allow)
        {
            let Some(region) = symbolic_rule_region(&base, allow, &field_variables, &universes)
            else {
                continue;
            };
            let mut residual = vec![region];
            for deny in &denies {
                residual = residual
                    .into_iter()
                    .flat_map(|candidate| subtract_symbolic_region(candidate, deny))
                    .collect();
                residual = minimize_symbolic_regions(residual);
                if residual.is_empty() {
                    break;
                }
            }
            allowed.extend(residual);
        }
        allowed = minimize_symbolic_regions(allowed);
        if allowed.is_empty() {
            return false;
        }
        combined = minimize_symbolic_regions(
            combined
                .iter()
                .flat_map(|left| {
                    allowed
                        .iter()
                        .filter_map(|right| intersect_symbolic_regions(left, right))
                })
                .collect(),
        );
        if combined.is_empty() {
            return false;
        }
    }
    !combined.is_empty()
}

fn symbolic_atom_exact_json(atom: &SymbolicAtom) -> Option<serde_json::Value> {
    match atom {
        SymbolicAtom::Str(value) => Some(serde_json::Value::String(value.clone())),
        SymbolicAtom::IntRange(min, max) if min == max => Some(serde_json::Value::from(*min)),
        SymbolicAtom::Bool(value) => Some(serde_json::Value::Bool(*value)),
        SymbolicAtom::Absent
        | SymbolicAtom::StrOther
        | SymbolicAtom::IntRange(_, _)
        | SymbolicAtom::AnyPresent => None,
    }
}

fn predicate_kind(pred: &Pred) -> Option<ScalarKind> {
    match pred {
        Pred::Eq { value, .. } => sentence_scalar_kind(value),
        Pred::Lte { .. } | Pred::Gte { .. } => Some(ScalarKind::Int),
        Pred::In { values, .. } => open_predicate_kind(&[pred]).or_else(|| {
            values
                .first()
                .and_then(sentence_scalar_kind)
                .filter(|kind| {
                    values
                        .iter()
                        .all(|value| sentence_scalar_kind(value) == Some(*kind))
                })
        }),
    }
}

fn atom_contains_scalar(atom: &SymbolicAtom, scalar: &ResourceScalar) -> bool {
    match (atom, scalar) {
        (SymbolicAtom::Str(expected), ResourceScalar::Str(actual)) => expected == actual,
        (SymbolicAtom::StrOther, ResourceScalar::Str(_)) => true,
        (SymbolicAtom::IntRange(min, max), ResourceScalar::Int(actual)) => {
            min <= actual && actual <= max
        }
        (SymbolicAtom::Bool(expected), ResourceScalar::Bool(actual)) => expected == actual,
        (SymbolicAtom::AnyPresent, _) => true,
        _ => false,
    }
}

fn symbolic_rule_region(
    base: &SymbolicRegion,
    rule: &Rule,
    field_variables: &BTreeMap<String, usize>,
    universes: &[Vec<SymbolicAtom>],
) -> Option<SymbolicRegion> {
    let mut region = base.clone();
    for pred in &rule.conjuncts {
        let index = *field_variables.get(pred_field(pred))?;
        region.domains[index]
            .retain(|atom_idx| symbolic_atom_matches_pred(&universes[index][*atom_idx], pred));
        if region.domains[index].is_empty() {
            return None;
        }
    }
    Some(region)
}

fn symbolic_atom_matches_pred(atom: &SymbolicAtom, pred: &Pred) -> bool {
    match atom {
        SymbolicAtom::Str(actual) => match pred {
            Pred::Eq { value, .. } => {
                matches!(value, Scalar::String(expected) if expected == actual)
            }
            Pred::In { values, .. } => values
                .iter()
                .any(|value| matches!(value, Scalar::String(expected) if expected == actual)),
            Pred::Lte { .. } | Pred::Gte { .. } => false,
        },
        SymbolicAtom::IntRange(actual, _) => match pred {
            Pred::Eq {
                value: Scalar::Int(expected),
                ..
            } => actual == expected,
            Pred::Lte { value, .. } => actual <= value,
            Pred::Gte { value, .. } => actual >= value,
            Pred::In { values, .. } => values
                .iter()
                .any(|value| matches!(value, Scalar::Int(expected) if expected == actual)),
            Pred::Eq { .. } => false,
        },
        SymbolicAtom::Bool(actual) => match pred {
            Pred::Eq {
                value: Scalar::Bool(expected),
                ..
            } => actual == expected,
            Pred::In { values, .. } => values
                .iter()
                .any(|value| matches!(value, Scalar::Bool(expected) if expected == actual)),
            Pred::Eq { .. } | Pred::Lte { .. } | Pred::Gte { .. } => false,
        },
        SymbolicAtom::Absent | SymbolicAtom::StrOther | SymbolicAtom::AnyPresent => false,
    }
}

fn intersect_symbolic_regions(
    left: &SymbolicRegion,
    right: &SymbolicRegion,
) -> Option<SymbolicRegion> {
    let domains: Vec<BTreeSet<usize>> = left
        .domains
        .iter()
        .zip(&right.domains)
        .map(|(left, right)| left.intersection(right).copied().collect())
        .collect();
    domains
        .iter()
        .all(|domain| !domain.is_empty())
        .then_some(SymbolicRegion { domains })
}

fn subtract_symbolic_region(region: SymbolicRegion, deny: &SymbolicRegion) -> Vec<SymbolicRegion> {
    if intersect_symbolic_regions(&region, deny).is_none() {
        return vec![region];
    }
    let mut core = region;
    let mut residual = Vec::new();
    for index in 0..core.domains.len() {
        let outside: BTreeSet<usize> = core.domains[index]
            .difference(&deny.domains[index])
            .copied()
            .collect();
        if !outside.is_empty() {
            let mut piece = core.clone();
            piece.domains[index] = outside;
            residual.push(piece);
        }
        core.domains[index] = core.domains[index]
            .intersection(&deny.domains[index])
            .copied()
            .collect();
        if core.domains[index].is_empty() {
            break;
        }
    }
    residual
}

fn minimize_symbolic_regions(regions: Vec<SymbolicRegion>) -> Vec<SymbolicRegion> {
    let mut minimal: Vec<SymbolicRegion> = Vec::new();
    for region in regions {
        if minimal
            .iter()
            .any(|existing| region_contains(existing, &region))
        {
            continue;
        }
        minimal.retain(|existing| !region_contains(&region, existing));
        minimal.push(region);
    }
    minimal
}

fn region_contains(outer: &SymbolicRegion, inner: &SymbolicRegion) -> bool {
    outer
        .domains
        .iter()
        .zip(&inner.domains)
        .all(|(outer, inner)| inner.is_subset(outer))
}

fn open_predicate_kind(predicates: &[&Pred]) -> Option<ScalarKind> {
    let mut kind = None;
    for pred in predicates {
        let current = match pred {
            Pred::Eq { value, .. } => sentence_scalar_kind(value),
            Pred::Lte { .. } | Pred::Gte { .. } => Some(ScalarKind::Int),
            Pred::In { values, .. } => {
                let first = sentence_scalar_kind(values.first()?)?;
                values
                    .iter()
                    .all(|value| sentence_scalar_kind(value) == Some(first))
                    .then_some(first)
            }
        }?;
        if kind.is_some_and(|kind| kind != current) {
            return None;
        }
        kind = Some(current);
    }
    kind
}

fn sentence_scalar_kind(value: &Scalar) -> Option<ScalarKind> {
    match value {
        Scalar::Int(_) => Some(ScalarKind::Int),
        Scalar::String(_) => Some(ScalarKind::Str),
        Scalar::Bool(_) => Some(ScalarKind::Bool),
    }
}

#[doc(hidden)]
#[allow(clippy::result_unit_err)]
pub fn validate_rule_structure(rule: &Rule) -> Result<(), ()> {
    let selector_valid = match &rule.selector {
        Selector::Set {
            provider,
            set,
            digest,
        } => {
            valid_provider_ident(provider)
                && valid_ident(set)
                && digest
                    .as_deref()
                    .is_none_or(crate::sets::valid_snapshot_digest)
        }
        Selector::Verb { provider, action } => {
            valid_provider_ident(provider) && valid_ident(action)
        }
    };
    (selector_valid
        && rule.conjuncts.iter().all(pred_is_well_formed)
        && aggregate_is_well_formed(rule))
    .then_some(())
    .ok_or(())
}

/// Structural well-formedness of the rule-level aggregate: an aggregate requires an `allow`
/// effect, a positive limit, and (if explicit) a valid budget field name. `rate` carries no
/// field. This mirrors the parse-time refusals so a hand-built or deserialized rule cannot smuggle
/// a malformed aggregate past `evaluate`. Semantic kinding and budget eligibility are checked
/// separately, at corpus validation.
fn aggregate_is_well_formed(rule: &Rule) -> bool {
    let Some(aggregate) = &rule.aggregate else {
        return true;
    };
    if rule.effect != RuleEffect::Allow || aggregate.limit <= 0 {
        return false;
    }
    match &aggregate.kind {
        AggregateKind::Budget { field: Some(field) } => valid_field(field),
        AggregateKind::Budget { field: None } | AggregateKind::Rate => true,
    }
}

/// Every [`Scalar`] variant is now well formed by construction — an int, a bool, or a
/// string the printer can always quote — so the only structural question left is the field name.
fn pred_is_well_formed(pred: &Pred) -> bool {
    valid_field(pred_field(pred))
        && match pred {
            Pred::Eq { .. } | Pred::Lte { .. } | Pred::Gte { .. } => true,
            Pred::In { values, .. } => !values.is_empty(),
        }
}

/// Can this sentence literal bind this declared field at all? Consulted by kind resolution AND by
/// matching, so "resolves" and "matches" can never disagree about what a literal may bind.
///
/// The dialect dissolved the one exception this used to carry: an INTEGER literal binding a `str`
/// identity field declaring `format: uint`, because a bare-decimal identity was otherwise
/// unpinnable — the quoted form meant "resolve this name" and the bare form lexed as an integer.
/// Under the always-quoted dialect a quoted string is lexically a string and means exactly itself,
/// so `number = "3"` pins it and the coercion has nothing left to buy. Matching is by kind, with no
/// exceptions at all.
fn scalar_binds_decl(value: &Scalar, decl: &FieldDecl) -> bool {
    matches!(
        (value, decl.ty),
        (Scalar::Int(_), ScalarKind::Int)
            | (Scalar::String(_), ScalarKind::Str)
            | (Scalar::Bool(_), ScalarKind::Bool)
    )
}

fn pred_resolves_for_decl(pred: &Pred, decl: &FieldDecl) -> bool {
    match pred {
        Pred::Eq { value, .. } => scalar_binds_decl(value, decl),
        // `<=`/`>=` compare against `ResourceScalar::Int`, so they resolve on `int` fields and
        // nowhere else — the coercion's dissolution keeps this exactly the kind rule it always was.
        Pred::Lte { .. } | Pred::Gte { .. } => decl.ty == ScalarKind::Int,
        Pred::In { values, .. } => {
            !values.is_empty() && values.iter().all(|value| scalar_binds_decl(value, decl))
        }
    }
}

impl FieldDecl {
    /// The predicate forms a sentence may use on this field — the WHERE index `catalog` publishes,
    /// so an agent reads a verb's schema instead of probing it one deny at a time.
    ///
    /// DERIVED, never a second table: each comparator is decided by ASKING
    /// [`pred_resolves_for_decl`] — the same judgment rule admission runs — with every literal shape
    /// a conjunct can spell. A comparator is listed exactly when some literal makes it resolve, so
    /// the printed index cannot drift from what the evaluator will accept.
    ///
    /// Two non-comparator rules join it:
    /// - a `secret` field admits NOTHING. `reject_secret_conjuncts` refuses any rule naming one, in
    ///   a conjunct or as the budget field, so an empty index is the truthful answer whatever kind
    ///   resolution would say in isolation.
    /// - `budget` is not a comparator but the rule-level aggregate that may sum this field
    ///   ([`FieldDecl::budget_eligible`]), and it is listed ONLY when `temporal_clauses` is on —
    ///   the declared `language_temporal_clauses` setting. The index
    ///   states what a sentence MAY use, so advertising a form corpus admission would refuse would
    ///   teach an agent to author a deny. `rate` meters ADMISSIONS, not a field, so it is
    ///   verb-level and never appears here in either gate position.
    pub fn admissible_forms(&self, temporal_clauses: bool) -> Vec<&'static str> {
        if self.class == FieldClass::Secret {
            return Vec::new();
        }
        let field = self.name.to_string();
        let literals = [
            Scalar::Int(1),
            Scalar::String("v".to_string()),
            Scalar::Bool(true),
        ];
        let resolves = |pred: Pred| pred_resolves_for_decl(&pred, self);
        let mut forms = Vec::new();
        if literals.iter().cloned().any(|value| {
            resolves(Pred::Eq {
                field: field.clone(),
                value,
            })
        }) {
            forms.push("=");
        }
        if literals.iter().cloned().any(|value| {
            resolves(Pred::In {
                field: field.clone(),
                values: vec![value],
            })
        }) {
            forms.push("in");
        }
        if resolves(Pred::Lte {
            field: field.clone(),
            value: 1,
        }) {
            forms.push("<=");
        }
        if resolves(Pred::Gte { field, value: 1 }) {
            forms.push(">=");
        }
        if temporal_clauses && self.budget_eligible() {
            forms.push("budget");
        }
        forms
    }
}

/// Structural conjunct containment. Adding a comparator to [`Pred`] must add its
/// implication cases here in the same change.
///
/// This is a PROOF primitive — the decidable-containment argument, sentence minimization and
/// permission ablation all rest on it — so it must be declaration-aware. A contract-blind version is
/// unsound once an integer pin can bind a uint-formatted string field: it would report
/// `number = 3 ⇒ number <= 4`, but on such a field the left side matches `"3"`
/// through the integer-pin rule while `<= 4` compares against `ResourceScalar::Int` and matches
/// NOTHING. A rule that admits something never implies a rule that admits nothing. The resolution
/// is to REFUSE that implication, not to widen the coercion to range comparators — the coercion is
/// equality pins only, and soundness here is bought by refusing.
pub fn implies(narrower: &Rule, wider: &Rule, contract: &ActionContract) -> bool {
    // Aggregate-bearing rules never enter a containment relation: a budget/rate cap is
    // not expressible as conjunct subsumption, so neither side may carry one.
    narrower.aggregate.is_none()
        && wider.aggregate.is_none()
        && narrower.effect == wider.effect
        && narrower.selector == wider.selector
        && wider.conjuncts.iter().all(|wide| {
            narrower
                .conjuncts
                .iter()
                .any(|narrow| pred_implies(narrow, wide, contract))
        })
}

fn pred_implies(narrower: &Pred, wider: &Pred, contract: &ActionContract) -> bool {
    let field = pred_field(narrower);
    if field != pred_field(wider) {
        return false;
    }
    // The cross-operator implications below reason NUMERICALLY, so they hold only where
    // both sides actually range over integers. On an open contract, or a field this contract does
    // not declare, nothing is known — refuse rather than assume.
    let numeric_field = contract
        .field_decl(field)
        .is_some_and(|decl| decl.ty == ScalarKind::Int);
    match (narrower, wider) {
        (Pred::Eq { value: a, .. }, Pred::Eq { value: b, .. }) => a == b,
        (Pred::Lte { value: a, .. }, Pred::Lte { value: b, .. }) => a <= b,
        (Pred::Gte { value: a, .. }, Pred::Gte { value: b, .. }) => a >= b,
        (Pred::In { values: a, .. }, Pred::In { values: b, .. }) => {
            a.iter().all(|value| b.contains(value))
        }
        (Pred::Eq { value, .. }, Pred::In { values, .. }) => values.contains(value),
        (Pred::In { values, .. }, Pred::Eq { value, .. }) => {
            !values.is_empty() && values.iter().all(|candidate| candidate == value)
        }
        (
            Pred::Eq {
                value: Scalar::Int(a),
                ..
            },
            Pred::Lte { value: b, .. },
        ) => numeric_field && a <= b,
        (
            Pred::Eq {
                value: Scalar::Int(a),
                ..
            },
            Pred::Gte { value: b, .. },
        ) => numeric_field && a >= b,
        (Pred::In { values, .. }, Pred::Lte { value, .. }) => {
            numeric_field
                && values
                    .iter()
                    .all(|candidate| matches!(candidate, Scalar::Int(n) if n <= value))
        }
        (Pred::In { values, .. }, Pred::Gte { value, .. }) => {
            numeric_field
                && values
                    .iter()
                    .all(|candidate| matches!(candidate, Scalar::Int(n) if n >= value))
        }
        _ => false,
    }
}

fn pred_field(pred: &Pred) -> &str {
    match pred {
        Pred::Eq { field, .. }
        | Pred::Lte { field, .. }
        | Pred::Gte { field, .. }
        | Pred::In { field, .. } => field,
    }
}

fn pred_matches(pred: &Pred, actual: &ResourceScalar) -> bool {
    match pred {
        Pred::Eq { value, .. } => scalar_matches(value, actual),
        Pred::Lte { value, .. } => matches!(actual, ResourceScalar::Int(n) if n <= value),
        Pred::Gte { value, .. } => matches!(actual, ResourceScalar::Int(n) if n >= value),
        Pred::In { values, .. } => values.iter().any(|value| scalar_matches(value, actual)),
    }
}

/// Matching is by kind, exactly. The dialect change removed the last exception (an integer pin on
/// a uint-formatted `str` identity): with strings always quoted, `number = "3"` says it directly
/// and this function has no declaration to consult.
fn scalar_matches(expected: &Scalar, actual: &ResourceScalar) -> bool {
    match (expected, actual) {
        (Scalar::Int(a), ResourceScalar::Int(b)) => a == b,
        (Scalar::String(a), ResourceScalar::Str(b)) => a == b,
        (Scalar::Bool(a), ResourceScalar::Bool(b)) => a == b,
        _ => false,
    }
}

fn parse_rule(tokens: &[Token], line: usize) -> Result<Rule, SentenceError> {
    let mut cursor = Cursor::new(tokens, line);
    let effect = match cursor.take_word("one of `allow` or `deny`")? {
        "allow" => RuleEffect::Allow,
        "deny" => RuleEffect::Deny,
        _ => {
            return Err(SentenceError::line(
                line,
                "expected one of `allow` or `deny`",
            ));
        }
    };
    let selector = parse_selector(cursor.take_word("selector")?, line)?;
    if cursor.done() {
        return Ok(Rule {
            effect,
            selector,
            conjuncts: Vec::new(),
            aggregate: None,
        });
    }
    cursor.expect_word("where")?;
    let mut conjuncts = Vec::new();
    let mut aggregate: Option<Aggregate> = None;
    loop {
        // A leading `budget`/`rate` word in the where-chain is a rule-level aggregate clause,
        // not a field predicate. Dispatch it to the aggregate arm; everything else is a
        // conjunct.
        if matches!(cursor.peek(), Some(Token::Word(word)) if word == "budget" || word == "rate") {
            let parsed = parse_aggregate(&mut cursor, line)?;
            if aggregate.is_some() {
                return Err(SentenceError::line(
                    line,
                    "a rule may declare at most one budget or rate aggregate",
                ));
            }
            if effect != RuleEffect::Allow {
                return Err(SentenceError::line(
                    line,
                    "budget and rate aggregates require an `allow` effect",
                ));
            }
            aggregate = Some(parsed);
            if cursor.done() {
                break;
            }
            cursor.expect_word("and")?;
            if cursor.done() {
                return Err(SentenceError::line(line, "expected a conjunct after `and`"));
            }
            continue;
        }
        let field = cursor.take_word("field")?.to_string();
        if !valid_field(&field) {
            return Err(SentenceError::line(line, "invalid field name"));
        }
        let pred = match cursor.next() {
            Some(Token::Eq) => Pred::Eq {
                value: cursor.take_scalar(&field)?,
                field,
            },
            Some(Token::Lte) => Pred::Lte {
                field,
                value: cursor.take_integer()?,
            },
            Some(Token::Gte) => Pred::Gte {
                field,
                value: cursor.take_integer()?,
            },
            Some(Token::Word(word)) if word == "in" => {
                cursor.expect(Token::LeftBrace, "`{`")?;
                if cursor.peek() == Some(&Token::RightBrace) {
                    return Err(SentenceError::line(line, "an `in` set must not be empty"));
                }
                let mut values = Vec::new();
                loop {
                    values.push(cursor.take_scalar(&field)?);
                    match cursor.next() {
                        Some(Token::Comma) => {}
                        Some(Token::RightBrace) => break,
                        _ => {
                            return Err(SentenceError::line(
                                line,
                                "expected `,` or `}` in `in` set",
                            ));
                        }
                    }
                }
                Pred::In { field, values }
            }
            _ => {
                return Err(SentenceError::line(
                    line,
                    "expected one of `=`, `==`, `<=`, `>=`, or `in`",
                ));
            }
        };
        conjuncts.push(pred);
        if cursor.done() {
            break;
        }
        cursor.expect_word("and")?;
        if cursor.done() {
            return Err(SentenceError::line(line, "expected a conjunct after `and`"));
        }
    }
    Ok(Rule {
        effect,
        selector,
        conjuncts,
        aggregate,
    })
}

/// Parse one aggregate clause (`budget [field] <positive-int> per <window>` or
/// `rate <positive-int> per <window>`). The caller has already confirmed a leading
/// `budget`/`rate` word is next. Structural refusals live here: a non-positive limit, a field
/// before `rate`, and an unknown window.
fn parse_aggregate(cursor: &mut Cursor<'_>, line: usize) -> Result<Aggregate, SentenceError> {
    let keyword = cursor.take_word("`budget` or `rate`")?;
    let kind = match keyword {
        "budget" => {
            // Disambiguate by the next token: an integer-first is the fieldless shorthand; an
            // identifier-then-integer is the explicit summed-field spelling.
            match cursor.peek() {
                Some(Token::Word(word)) if integer_literal(word) => {
                    AggregateKind::Budget { field: None }
                }
                Some(Token::Word(word)) => {
                    let field = word.clone();
                    if !valid_field(&field) {
                        return Err(SentenceError::line(line, "invalid budget field name"));
                    }
                    cursor.next();
                    AggregateKind::Budget { field: Some(field) }
                }
                _ => {
                    return Err(SentenceError::line(
                        line,
                        "expected a field or a positive integer after `budget`",
                    ));
                }
            }
        }
        "rate" => {
            // `rate` meters admissions, not a field; a field before the int is a parse error.
            if matches!(cursor.peek(), Some(Token::Word(word)) if !integer_literal(word)) {
                return Err(SentenceError::line(
                    line,
                    "`rate` takes no field; write `rate <positive-int> per <window>`",
                ));
            }
            AggregateKind::Rate
        }
        _ => unreachable!("caller guaranteed a `budget`/`rate` word"),
    };
    let limit = cursor.take_integer()?;
    if limit <= 0 {
        return Err(SentenceError::line(
            line,
            "aggregate limit must be a positive integer",
        ));
    }
    cursor.expect_word("per")?;
    let window = match cursor.take_word("`hour` or `day`")? {
        "hour" => Window::Hour,
        "day" => Window::Day,
        _ => {
            return Err(SentenceError::line(line, "expected `hour` or `day`"));
        }
    };
    Ok(Aggregate {
        kind,
        limit,
        window,
    })
}

/// The ONE selector spelling: a bare `provider.action` is one verb, and
/// `provider.set@sha256:<64hex>` is one immutable set expansion. The `word:` prefix namespace stays
/// RESERVED for future set forms (`class:`, `family:`), so a prefixed selector is a parse error
/// rather than legacy input: a parser that accepted two spellings of one rule would be two
/// corpuses.
fn parse_selector(raw: &str, line: usize) -> Result<Selector, SentenceError> {
    // Checked BEFORE the `@` split, whose digest legitimately carries a `sha256:` colon.
    if raw.split('@').next().unwrap_or(raw).contains(':') {
        return Err(SentenceError::line(
            line,
            "set-prefix forms are reserved; write the verb bare: `allow provider.action`",
        ));
    }
    let (raw, digest) = match raw.split_once('@') {
        Some((selector, digest))
            if !digest.contains('@') && crate::sets::valid_snapshot_digest(digest) =>
        {
            (selector, Some(digest.to_string()))
        }
        Some(_) => {
            return Err(SentenceError::line(
                line,
                "set snapshot must be `@sha256:` followed by 64 lowercase hex characters",
            ));
        }
        None => (raw, None),
    };
    let Some((provider, name)) = raw.split_once('.') else {
        return Err(SentenceError::line(
            line,
            "selector must be `provider.name`",
        ));
    };
    if name.contains('.') || !valid_provider_ident(provider) || !valid_ident(name) {
        return Err(SentenceError::line(line, "invalid selector"));
    }
    // The pinned expansion digest is what makes a selector a SET; without one it is the verb.
    Ok(match digest {
        Some(digest) => Selector::Set {
            provider: provider.to_string(),
            set: name.to_string(),
            digest: Some(digest),
        },
        None => Selector::Verb {
            provider: provider.to_string(),
            action: name.to_string(),
        },
    })
}

fn without_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '#' if !quoted => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn tokenize(line: &str, line_number: usize) -> Result<Vec<Token>, SentenceError> {
    let chars: Vec<char> = line.chars().collect();
    let mut tokens = Vec::new();
    let mut idx = 0;
    while idx < chars.len() {
        if chars[idx].is_whitespace() {
            idx += 1;
            continue;
        }
        match chars[idx] {
            '=' => {
                idx += 1;
                if chars.get(idx) == Some(&'=') {
                    idx += 1;
                }
                tokens.push(Token::Eq);
            }
            '<' | '>' => {
                let comparator = chars[idx];
                idx += 1;
                if chars.get(idx) != Some(&'=') {
                    return Err(SentenceError::line(
                        line_number,
                        "unsupported comparator; expected `<=` or `>=`",
                    ));
                }
                idx += 1;
                tokens.push(if comparator == '<' {
                    Token::Lte
                } else {
                    Token::Gte
                });
            }
            '{' => {
                idx += 1;
                tokens.push(Token::LeftBrace);
            }
            '}' => {
                idx += 1;
                tokens.push(Token::RightBrace);
            }
            ',' => {
                idx += 1;
                tokens.push(Token::Comma);
            }
            '"' => {
                let (value, next) = tokenize_string(&chars, idx + 1, line_number)?;
                idx = next;
                tokens.push(Token::Quoted(value));
            }
            _ => {
                let start = idx;
                while idx < chars.len()
                    && !chars[idx].is_whitespace()
                    && !matches!(chars[idx], '=' | '<' | '>' | '{' | '}' | ',' | '"')
                {
                    idx += 1;
                }
                tokens.push(Token::Word(chars[start..idx].iter().collect()));
            }
        }
    }
    Ok(tokens)
}

fn tokenize_string(
    chars: &[char],
    mut idx: usize,
    line: usize,
) -> Result<(String, usize), SentenceError> {
    let mut value = String::new();
    while idx < chars.len() {
        match chars[idx] {
            '"' => return Ok((value, idx + 1)),
            '\\' => {
                idx += 1;
                let Some(escaped) = chars.get(idx) else {
                    return Err(SentenceError::line(line, "unterminated string escape"));
                };
                // Exactly two escapes exist. A string is a literal, so
                // the only characters needing an escape are the two the codec itself uses.
                match escaped {
                    '"' => value.push('"'),
                    '\\' => value.push('\\'),
                    _ => {
                        return Err(SentenceError::line(
                            line,
                            "the only string escapes are `\\\"` and `\\\\`",
                        ));
                    }
                }
                idx += 1;
            }
            ch => {
                value.push(ch);
                idx += 1;
            }
        }
    }
    Err(SentenceError::line(line, "unterminated quoted string"))
}

fn print_scalar(value: &Scalar) -> String {
    match value {
        Scalar::Int(value) => value.to_string(),
        Scalar::String(value) => quote_string(value),
        Scalar::Bool(value) => value.to_string(),
    }
}

/// The inverse of the two escapes [`tokenize_string`] accepts. Anything else rides through
/// verbatim — including a control character, which the line-based grammar simply cannot spell a
/// newline for; such a rule fails `rule_codec_round_trips` and is therefore never suggested,
/// which is the fail-safe answer without a branch.
fn quote_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn valid_ident(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_provider_ident(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

/// Field-name rule for both predicate and explicit-budget-field positions. Beyond `valid_ident`
/// per dotted segment, a field must be codec-disambiguable so the language stays closed under
/// print→parse: it may not be a bare integer literal (the budget lookahead would misread it as
/// the fieldless limit) and may not be a reserved aggregate keyword (`budget`/`rate`
/// are dispatched to the aggregate arm at every conjunct head, so they can never round-trip as a
/// predicate field). This keeps the accepted-field set equal to the disambiguable set,
/// which the structural guard (`aggregate_is_well_formed`, `pred_is_well_formed`) relies on.
fn valid_field(value: &str) -> bool {
    !integer_literal(value)
        && !is_reserved_aggregate_keyword(value)
        && value.split('.').all(valid_ident)
}

/// `budget` and `rate` head an aggregate clause; they are never a predicate or budget field name.
fn is_reserved_aggregate_keyword(value: &str) -> bool {
    matches!(value, "budget" | "rate")
}

fn integer_literal(value: &str) -> bool {
    let digits = value
        .strip_prefix('-')
        .or_else(|| value.strip_prefix('+'))
        .unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

struct Cursor<'a> {
    tokens: &'a [Token],
    idx: usize,
    line: usize,
}

impl<'a> Cursor<'a> {
    fn new(tokens: &'a [Token], line: usize) -> Self {
        Self {
            tokens,
            idx: 0,
            line,
        }
    }

    fn next(&mut self) -> Option<&'a Token> {
        let token = self.tokens.get(self.idx);
        self.idx += usize::from(token.is_some());
        token
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.idx)
    }

    fn done(&self) -> bool {
        self.idx == self.tokens.len()
    }

    fn expect(&mut self, expected: Token, label: &str) -> Result<(), SentenceError> {
        if self.next() == Some(&expected) {
            Ok(())
        } else {
            Err(SentenceError::line(self.line, format!("expected {label}")))
        }
    }

    fn expect_word(&mut self, expected: &str) -> Result<(), SentenceError> {
        match self.next() {
            Some(Token::Word(word)) if word == expected => Ok(()),
            _ => Err(SentenceError::line(
                self.line,
                format!("expected `{expected}`"),
            )),
        }
    }

    fn take_word(&mut self, label: &str) -> Result<&'a str, SentenceError> {
        match self.next() {
            Some(Token::Word(word)) => Ok(word),
            _ => Err(SentenceError::line(self.line, format!("expected {label}"))),
        }
    }

    fn take_integer(&mut self) -> Result<i64, SentenceError> {
        let raw = self.take_word("integer")?;
        raw.parse()
            .map_err(|_| SentenceError::line(self.line, "expected an integer"))
    }

    /// Bare literals are int/bool ONLY; every string is double-quoted. `field` is carried in so the
    /// refusal can show the operator the exact line they meant to write rather than reporting an
    /// unnamed token.
    fn take_scalar(&mut self, field: &str) -> Result<Scalar, SentenceError> {
        match self.next() {
            Some(Token::Quoted(value)) => Ok(Scalar::String(value.clone())),
            Some(Token::Word(value)) => {
                if integer_literal(value) {
                    return value
                        .parse::<i64>()
                        .map(Scalar::Int)
                        .map_err(|_| SentenceError::line(self.line, "expected an integer"));
                }
                match value.as_str() {
                    "true" => Ok(Scalar::Bool(true)),
                    "false" => Ok(Scalar::Bool(false)),
                    _ => Err(SentenceError::line(
                        self.line,
                        format!(
                            "string values are quoted: {field} = {}",
                            quote_string(value)
                        ),
                    )),
                }
            }
            _ => Err(SentenceError::line(
                self.line,
                format!(
                    "expected a literal: an integer, `true`/`false`, or a quoted string \
                         (string values are quoted: {field} = \"...\")"
                ),
            )),
        }
    }
}

/// A whole-corpus reference-resolution failure: a verb, set, set member, or conjunct field that no
/// current catalog/set membership declares. Independent of the budget/aggregate checks.
///
/// `rule_idx` is the zero-based slice position; every `Display` below renders it through
/// [`human_rule_number`], because the person reading this just authored that corpus and will find
/// the offending line with `cermet rules`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReferenceError {
    #[error("rule {}: unresolved verb {provider}.{action}", human_rule_number(*rule_idx))]
    UnresolvedVerb {
        rule_idx: usize,
        provider: String,
        action: String,
    },
    #[error("rule {}: unresolved set {provider}.{set}", human_rule_number(*rule_idx))]
    UnresolvedSet {
        rule_idx: usize,
        provider: String,
        set: String,
    },
    #[error("rule {}: unresolved set member {provider}.{action}", human_rule_number(*rule_idx))]
    UnresolvedSetMember {
        rule_idx: usize,
        provider: String,
        action: String,
    },
    #[error("rule {}: unresolved conjunct field `{field}`", human_rule_number(*rule_idx))]
    UnresolvedField { rule_idx: usize, field: String },
}

/// An unbudgeted `allow` shadows a later aggregate-bearing `allow`: it is
/// ordered first, its selector overlaps the budgeted rule, and `first_allow` wins — so requests the
/// budget rule was meant to meter mint UNMETERED through the earlier plain allow. Refused at corpus
/// validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "rule {} (allow{}) is ordered before the aggregate-bearing rule {} \
     and overlaps it at {provider}.{action}; it would match first and mint {}, bypassing the \
     later rule's budget/rate cap — reorder the aggregate rule ahead, tighten the earlier allow off \
     the metered scope, or make the two rules byte-identical so they meter ONE counter",
    human_rule_number(*.plain_idx),
    if *.earlier_meters_differently { ", metering a DIFFERENT aggregate" } else { ", no aggregate" },
    human_rule_number(*.aggregate_idx),
    if *.earlier_meters_differently { "under a different cap" } else { "UNMETERED" }
)]
pub struct ShadowError {
    /// Zero-based slice positions; both render through [`human_rule_number`].
    pub plain_idx: usize,
    pub aggregate_idx: usize,
    pub provider: String,
    pub action: String,
    /// The earlier overlapping allow carries an aggregate, but NOT one identical to the later
    /// rule's — as opposed to carrying no aggregate at all.
    pub earlier_meters_differently: bool,
}

/// Fail closed on any earlier `allow` that shadows a later aggregate-bearing `allow`.
/// The ledger-derived gate meters the FIRST-matching aggregate rule; an earlier overlapping allow wins
/// first and its OWN aggregate (or absence of one) is what gets metered — the later rule's cap is never
/// evaluated. Sound over-approximation: selector-member overlap (an earlier allow sharing ANY covered
/// `(provider, action)` with the budgeted rule creates a bypass hole for the requests it admits,
/// whatever its predicate). An earlier allow is EXEMPT only when it shares the later rule's ledger
/// COUNTER IDENTITY — `aggregate_id` over the full canonical rule, i.e. the rules are byte-identical
/// — so first-match meters the very same counter. An equal aggregate CLAUSE on a different
/// predicate is NOT exempt: it would meter a SEPARATE counter and overlapping caps would admit their
/// sum; a different or weaker earlier aggregate (`rate 1 per hour` before `budget amount 100 per
/// day`) suppresses the later monetary cap. Both are refused. First-match evaluation
/// semantics are unchanged; this is a validation-time lint only.
pub fn validate_aggregate_shadowing(
    rules: &RuleSet,
    sets: &dyn SetResolver,
) -> Result<(), ShadowError> {
    for (aggregate_idx, budgeted) in rules.rules.iter().enumerate() {
        if budgeted.effect != RuleEffect::Allow || budgeted.aggregate.is_none() {
            continue;
        }
        let Some(members_b) = reference_selector_members(&budgeted.selector, sets) else {
            // An unresolved selector is already refused by `validate_references`; nothing to compare.
            continue;
        };
        let counter_b = aggregate_id(budgeted);
        for (plain_idx, earlier) in rules.rules.iter().enumerate().take(aggregate_idx) {
            if earlier.effect != RuleEffect::Allow {
                continue;
            }
            // The ledger meters on `aggregate_id` — a digest of the ENTIRE canonical rule
            // (selector + predicates + aggregate clause), not the aggregate clause alone. Exempt an
            // earlier overlapping allow ONLY when its COUNTER IDENTITY is identical to this rule's, i.e.
            // it is byte-identical and therefore drains the SAME ledger counter (first-match selecting it
            // is not a bypass). Equal aggregate CLAUSES with different predicates meter SEPARATE counters
            // (`amount<=50 budget 100/day` before `amount<=5000 budget 100/day` would admit 200 under two
            // nominally-100 caps) — refuse. A different/weaker aggregate, or none, is likewise
            // refused. First-match EVALUATION semantics are unchanged; this is authoring-time only.
            if aggregate_id(earlier) == counter_b {
                continue;
            }
            let earlier_meters_differently = earlier.aggregate.is_some();
            let Some(members_p) = reference_selector_members(&earlier.selector, sets) else {
                continue;
            };
            if let Some((provider, action)) = members_p.iter().find(|m| members_b.contains(m)) {
                return Err(ShadowError {
                    plain_idx,
                    aggregate_idx,
                    provider: provider.clone(),
                    action: action.clone(),
                    earlier_meters_differently,
                });
            }
        }
    }
    Ok(())
}

fn reference_pred_field(pred: &Pred) -> &str {
    match pred {
        Pred::Eq { field, .. }
        | Pred::Lte { field, .. }
        | Pred::Gte { field, .. }
        | Pred::In { field, .. } => field,
    }
}

fn aggregate_budget_field(rule: &Rule) -> Option<&str> {
    match rule.aggregate.as_ref().map(|aggregate| &aggregate.kind) {
        Some(AggregateKind::Budget { field: Some(field) }) => Some(field),
        _ => None,
    }
}

/// The sorted, deduped `(provider, action)` members a selector covers (a `Verb` is itself; a `Set`
/// its pinned snapshot's members) — the ordered member-eligibility set the budget `resolution_digest`
/// folds (`crate::budget`). `None` when the selector does not resolve (fail closed).
pub fn selector_members(
    selector: &Selector,
    sets: &dyn SetResolver,
) -> Option<Vec<(String, String)>> {
    reference_selector_members(selector, sets)
}

/// The (provider, action) members a selector covers: a `Verb` is itself; a `Set` is its pinned
/// immutable snapshot's members. An unpinned/invalid/unresolvable set returns `None`.
fn reference_selector_members(
    selector: &Selector,
    sets: &dyn SetResolver,
) -> Option<Vec<(String, String)>> {
    match selector {
        Selector::Verb { provider, action } => Some(vec![(provider.clone(), action.clone())]),
        Selector::Set {
            provider,
            set,
            digest,
        } => {
            let digest = digest.as_deref()?;
            if !crate::sets::valid_snapshot_digest(digest) {
                return None;
            }
            let snapshot = sets
                .snapshot(provider, set, digest)
                .filter(|s| s.is_for(provider, set, digest))?;
            let mut members: Vec<(String, String)> = snapshot
                .members()
                .iter()
                .map(|a| (provider.clone(), a.clone()))
                .collect();
            members.sort();
            members.dedup();
            Some(members)
        }
    }
}

/// Fail closed on ANY unresolved reference in a candidate corpus BEFORE it can commit:
/// every selector verb / set / set member must resolve to a current contract, and every conjunct field
/// must be a declared schema field of at least one covered member. A dormant rule on a not-yet-shipped
/// verb must be REFUSED here — otherwise it commits inert and silently activates on a later catalog
/// upgrade (authority change without re-authoring). The aggregate/overlap checks are not part of
/// this function; they live in [`validate_aggregate_shadowing`].
pub fn validate_references(
    rules: &RuleSet,
    sets: &dyn SetResolver,
    contracts: &dyn ContractResolver,
) -> Result<(), ReferenceError> {
    for (rule_idx, rule) in rules.rules.iter().enumerate() {
        match &rule.selector {
            Selector::Verb { provider, action } => {
                let resolved = contracts
                    .contract(provider, action)
                    .filter(|c| c.provider == *provider && c.action == *action);
                let Some(contract) = resolved else {
                    return Err(ReferenceError::UnresolvedVerb {
                        rule_idx,
                        provider: provider.clone(),
                        action: action.clone(),
                    });
                };
                for pred in &rule.conjuncts {
                    let field = reference_pred_field(pred);
                    // An OPEN contract accepts any scalar field at canonicalize, so a
                    // conjunct field it does not declare is NOT unresolved — only a CLOSED contract's
                    // undeclared field is refused here.
                    if !contract.open && !contract.has_schema_field(field) {
                        return Err(ReferenceError::UnresolvedField {
                            rule_idx,
                            field: field.to_string(),
                        });
                    }
                }
                if let Some(field) = aggregate_budget_field(rule) {
                    if !contract.open && !contract.has_schema_field(field) {
                        return Err(ReferenceError::UnresolvedField {
                            rule_idx,
                            field: field.to_string(),
                        });
                    }
                }
            }
            Selector::Set { provider, set, .. } => {
                let members =
                    reference_selector_members(&rule.selector, sets).ok_or_else(|| {
                        ReferenceError::UnresolvedSet {
                            rule_idx,
                            provider: provider.clone(),
                            set: set.clone(),
                        }
                    })?;
                for (p, a) in &members {
                    if contracts
                        .contract(p, a)
                        .filter(|c| c.provider == *p && c.action == *a)
                        .is_none()
                    {
                        return Err(ReferenceError::UnresolvedSetMember {
                            rule_idx,
                            provider: p.clone(),
                            action: a.clone(),
                        });
                    }
                }
                // A conjunct field is legal if AT LEAST ONE covered member declares it (a mixed-set
                // field only the debiting members carry is fine; a field NO member declares is refused).
                for pred in &rule.conjuncts {
                    let field = reference_pred_field(pred);
                    // A member with an OPEN contract accepts any scalar field, so it
                    // "declares" the conjunct for resolution purposes.
                    let declared_somewhere = members.iter().any(|(p, a)| {
                        contracts
                            .contract(p, a)
                            .is_some_and(|c| c.open || c.has_schema_field(field))
                    });
                    if !declared_somewhere {
                        return Err(ReferenceError::UnresolvedField {
                            rule_idx,
                            field: field.to_string(),
                        });
                    }
                }
                if let Some(field) = aggregate_budget_field(rule) {
                    let declared_somewhere = members.iter().any(|(p, a)| {
                        contracts
                            .contract(p, a)
                            .is_some_and(|c| c.open || c.has_schema_field(field))
                    });
                    if !declared_somewhere {
                        return Err(ReferenceError::UnresolvedField {
                            rule_idx,
                            field: field.to_string(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// Product-availability preflight over raw selector tokens. This intentionally runs before the full
/// sentence parser so a recognizably disabled provider receives the stable product refusal even when
/// the rest of the proposed rule is malformed.
pub fn preflight_product_availability(candidate_text: &str) -> crate::Result<()> {
    for line in candidate_text.lines() {
        let line = without_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let first = words.next().unwrap_or_default();
        let selector = if matches!(first, "allow" | "deny") {
            words.next().unwrap_or_default()
        } else {
            first
        };
        let selector = selector
            .strip_prefix("verb:")
            .or_else(|| selector.strip_prefix("set:"))
            .unwrap_or(selector);
        let Some((provider, action)) = selector.split_once('.') else {
            continue;
        };
        let action = action.split('@').next().unwrap_or(action);
        if crate::provider::product_availability(provider, action)
            == crate::provider::ProductAvailability::ProviderDisabled
        {
            return Err(crate::Error::ProviderDisabled);
        }
    }
    Ok(())
}

/// Repeat the availability check over parsed selectors. A set selector is provider-scoped just like
/// a direct verb selector; its set name is passed only to keep the central policy's `(provider,
/// action)` shape.
pub fn validate_product_availability(rules: &RuleSet) -> crate::Result<()> {
    for rule in &rules.rules {
        let (provider, action) = match &rule.selector {
            Selector::Verb { provider, action } => (provider, action),
            Selector::Set { provider, set, .. } => (provider, set),
        };
        if crate::provider::product_availability(provider, action)
            == crate::provider::ProductAvailability::ProviderDisabled
        {
            return Err(crate::Error::ProviderDisabled);
        }
    }
    Ok(())
}

/// Domain-separated identity of one canonical aggregate-bearing rule.
pub fn aggregate_id(rule: &Rule) -> String {
    use sha2::{Digest, Sha256};

    const AGGREGATE_DOMAIN: &[u8] = b"cermet-aggregate-v1\0";
    let canonical = serde_json::to_vec(rule).expect("Rule serialization is infallible");
    let mut hash = Sha256::new();
    hash.update(AGGREGATE_DOMAIN);
    hash.update((canonical.len() as u64).to_le_bytes());
    hash.update(&canonical);
    crate::util::hex(&hash.finalize())
}

/// The OWNING tests for the temporal-clause gate in this crate.
///
/// The clauses stay in the grammar and the AST — they are gated, not deleted — so the tests come in
/// pairs: the gate OFF (the shipped default) must refuse and NAME the setting, and the gate ON must
/// leave the old behavior byte-identical.
/// The OWNING tests for the sentence surface dialect: "kill verb: and
/// use literals". ONE spelling per rule: a bare dotted verb selector, and string values that are
/// always double-quoted. There is no accept-both grace period — a parser that took two spellings of
/// one rule would be two corpuses.
#[cfg(test)]
mod dialect_tests {
    use super::*;
    use crate::contract::{
        ActionContract, AllowBinding, CanonicalResource, FieldClass, FieldDecl, ScalarKind,
    };

    const PINNED_DIGEST: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    /// A `str` IDENTITY field declaring `format: uint` — the exact shape the old integer-pin
    /// coercion was minted for, and the one this dialect dissolves now that a quoted string is
    /// lexically a string.
    const NUMBER_SCHEMA: &[FieldDecl] = &[FieldDecl {
        name: "number",
        ty: ScalarKind::Str,
        required: true,
        class: FieldClass::Identity,
        binding: AllowBinding::ExactResourcePin,
    }];

    const NUMBER_CONTRACT: ActionContract = ActionContract {
        provider: "github",
        action: "comment_thread",
        schema: NUMBER_SCHEMA,
        consumes: &["number"],
        execution_targets: &["number"],
        relations: &[],
        open: false,
    };

    /// `verb:` is gone as a spelling, and it does not degrade to "valid legacy input" either: the
    /// whole `word:` prefix namespace is RESERVED (future `class:`/`family:` sets), so it is a parse
    /// error like any other old spelling, and the message says so.
    #[test]
    fn a_prefixed_selector_is_a_parse_error_naming_the_reserved_namespace() {
        for source in [
            "allow verb:vercel.deploy\n",
            "deny verb:stripe.refund where amount <= 5000\n",
            "allow set:stripe.read\n",
            "allow class:stripe.read\n",
        ] {
            let error = parse_rules(source).expect_err("a prefixed selector must not parse");
            let message = error.to_string();
            assert!(
                message.contains("reserved"),
                "the refusal must say the prefix namespace is reserved: {message}"
            );
            assert!(
                message.contains("allow provider.action") || message.contains("provider.action"),
                "the refusal must name the spelling that works: {message}"
            );
        }
    }

    /// The bare dotted form is now exactly one verb — not a set, which is what it used to mean.
    #[test]
    fn a_bare_dotted_selector_is_one_verb() {
        let rules = parse_rules("allow vercel.deploy\n").expect("the bare verb form parses");
        assert_eq!(
            rules.rules[0].selector,
            Selector::Verb {
                provider: "vercel".into(),
                action: "deploy".into(),
            }
        );
    }

    /// A set is spelled by its immutable expansion digest and nothing else. Stored authority always
    /// pins one (`set_references_are_pinned`), so this is the only set spelling the codec must
    /// round-trip.
    #[test]
    fn a_digest_pinned_selector_is_a_set_and_round_trips() {
        let source = format!("allow stripe.read@{PINNED_DIGEST}\n");
        let rules = parse_rules(&source).expect("a pinned set parses");
        assert_eq!(
            rules.rules[0].selector,
            Selector::Set {
                provider: "stripe".into(),
                set: "read".into(),
                digest: Some(PINNED_DIGEST.into()),
            }
        );
        assert_eq!(print_rule(&rules.rules[0]), source.trim_end());
    }

    /// An unquoted string is a parse error, and the message teaches the dialect rather than only
    /// reporting a token.
    #[test]
    fn an_unquoted_string_value_is_a_parse_error_naming_the_dialect() {
        for source in [
            "allow vercel.deploy where project = acme-live\n",
            "allow vercel.deploy where target in {preview, production}\n",
            "allow vercel.deploy where target in {\"preview\", production}\n",
        ] {
            let error = parse_rules(source).expect_err("a bare string must not parse");
            let message = error.to_string();
            assert!(
                message.contains("string values are quoted"),
                "the refusal must name the new dialect: {message}"
            );
        }
    }

    /// Bare literals are int/bool ONLY; strings are quoted, in scalar and set position alike.
    #[test]
    fn quoted_strings_and_bare_int_bool_literals_parse() {
        let rules = parse_rules(
            "allow vercel.deploy where project = \"acme-live\" and target in {\"preview\", \
             \"production\"} and amount <= 5000 and count = 3 and dry_run = true\n",
        )
        .expect("the new dialect parses");
        assert_eq!(
            rules.rules[0].conjuncts,
            vec![
                Pred::Eq {
                    field: "project".into(),
                    value: Scalar::String("acme-live".into()),
                },
                Pred::In {
                    field: "target".into(),
                    values: vec![
                        Scalar::String("preview".into()),
                        Scalar::String("production".into()),
                    ],
                },
                Pred::Lte {
                    field: "amount".into(),
                    value: 5000,
                },
                Pred::Eq {
                    field: "count".into(),
                    value: Scalar::Int(3),
                },
                Pred::Eq {
                    field: "dry_run".into(),
                    value: Scalar::Bool(true),
                },
            ]
        );
    }

    /// The canonical printer emits ONE dialect: bare selector, quoted strings.
    #[test]
    fn the_printer_emits_only_the_new_dialect() {
        let rule = Rule {
            effect: RuleEffect::Allow,
            selector: Selector::Verb {
                provider: "vercel".into(),
                action: "deploy".into(),
            },
            conjuncts: vec![
                Pred::Eq {
                    field: "project".into(),
                    value: Scalar::String("acme-live".into()),
                },
                Pred::In {
                    field: "target".into(),
                    values: vec![
                        Scalar::String("preview".into()),
                        Scalar::String("production".into()),
                    ],
                },
            ],
            aggregate: None,
        };
        assert_eq!(
            print_rule(&rule),
            "allow vercel.deploy where project = \"acme-live\" and target in {\"preview\", \
             \"production\"}"
        );
        assert_eq!(parse_rules(&print_rule(&rule)).unwrap().rules[0], rule);
    }

    /// Escapes are exactly `\"` and `\\`. Nothing else is an escape, in either direction.
    #[test]
    fn only_quote_and_backslash_are_escapes() {
        let rules = parse_rules("allow vercel.deploy where project = \"a\\\"b\\\\c\"\n")
            .expect("the two escapes parse");
        assert_eq!(
            rules.rules[0].conjuncts[0],
            Pred::Eq {
                field: "project".into(),
                value: Scalar::String("a\"b\\c".into()),
            }
        );
        assert_eq!(
            print_rule(&rules.rules[0]),
            "allow vercel.deploy where project = \"a\\\"b\\\\c\""
        );
        for source in [
            "allow vercel.deploy where project = \"a\\nb\"\n",
            "allow vercel.deploy where project = \"a\\tb\"\n",
            "allow vercel.deploy where project = \"a\\u0041b\"\n",
        ] {
            let error = parse_rules(source).expect_err("no other escape exists");
            assert!(
                error.to_string().contains("escape"),
                "{}",
                error.to_string()
            );
        }
    }

    /// The old integer-pin coercion is DISSOLVED. It existed only because a bare decimal lexed
    /// as an integer while the quoted form meant "resolve this name"; with quoting mandatory and
    /// literal, `number = "3"` says exactly what it says, and the integer pin no longer binds a
    /// string field at all.
    #[test]
    fn an_integer_pin_no_longer_binds_a_uint_formatted_string_field() {
        let resource = CanonicalResource::from_stored(r#"{"number":"3"}"#, &NUMBER_CONTRACT)
            .expect("a canonical uint identity");
        let integer_pin = parse_rules("allow github.comment_thread where number = 3\n")
            .expect("an integer literal still parses");
        assert!(
            !conjuncts_match_resource(&integer_pin.rules[0].conjuncts, &resource, &NUMBER_CONTRACT),
            "an integer literal must no longer bind a `str` field"
        );
        let quoted_pin = parse_rules("allow github.comment_thread where number = \"3\"\n")
            .expect("the quoted pin parses");
        assert!(
            conjuncts_match_resource(&quoted_pin.rules[0].conjuncts, &resource, &NUMBER_CONTRACT),
            "the quoted pin is how a bare-decimal identity is written now"
        );
    }
}

#[cfg(test)]
mod temporal_gate_tests {
    use super::*;
    use crate::contract::{
        ActionContract, AllowBinding, CanonicalResource, FieldClass, FieldDecl, ScalarKind,
    };

    const AMOUNT_SCHEMA: &[FieldDecl] = &[FieldDecl {
        name: "amount",
        ty: ScalarKind::Int,
        required: true,
        class: FieldClass::SideEffect,
        binding: AllowBinding::Bounded,
    }];

    const AMOUNT_CONTRACT: ActionContract = ActionContract {
        provider: "stripe",
        action: "refund",
        schema: AMOUNT_SCHEMA,
        consumes: &["amount"],
        execution_targets: &[],
        relations: &[],
        open: false,
    };

    /// Every temporal spelling the grammar admits. If a new one is ever added it belongs here, or
    /// the gate has a hole.
    const TEMPORAL_CORPORA: &[&str] = &[
        "allow stripe.refund where rate 30 per day\n",
        "allow stripe.refund where rate 10 per hour\n",
        "allow stripe.refund where budget amount 50000 per day\n",
        "allow stripe.refund where budget 100 per hour\n",
        "allow stripe.refund where amount <= 5000 and budget amount 50000 per day\n",
    ];

    #[test]
    fn the_gate_off_refuses_every_temporal_clause_and_names_the_setting() {
        for source in TEMPORAL_CORPORA {
            let rules = parse_rules(source).expect("the grammar still parses the clause");
            let error = validate_temporal_clauses(&rules, false)
                .expect_err("a temporal clause must not pass a closed gate");
            let message = error.to_string();
            assert!(
                message.contains(TEMPORAL_CLAUSES_SETTING),
                "the refusal must name the setting that would re-enable it: {message}"
            );
            assert!(
                message.contains("disabled"),
                "the refusal must say the clause is disabled, not merely wrong: {message}"
            );
        }
    }

    #[test]
    fn the_gate_on_admits_every_temporal_clause() {
        for source in TEMPORAL_CORPORA {
            let rules = parse_rules(source).unwrap();
            assert!(
                validate_temporal_clauses(&rules, true).is_ok(),
                "an OPEN gate must leave the clause exactly as it was: {source}"
            );
        }
    }

    /// The whole point of the suspension: every predicate evaluable from the request alone is
    /// untouched by the gate.
    #[test]
    fn stateless_predicates_are_unaffected_by_a_closed_gate() {
        for source in [
            "allow stripe.refund where amount <= 5000\n",
            "allow stripe.refund where amount >= 1\n",
            "allow stripe.refund where amount = 500\n",
            "allow stripe.refund where amount in {100, 500}\n",
            "deny stripe.refund where amount >= 10000\n",
        ] {
            let rules = parse_rules(source).unwrap();
            assert!(
                validate_temporal_clauses(&rules, false).is_ok(),
                "a closed temporal gate must not touch a stateless predicate: {source}"
            );
        }
    }

    /// A deny's advisory widening suggestion is operator-facing TEXT an operator may paste back.
    /// It must never propose a clause the gate refuses — and it cannot, because an aggregate-bearing
    /// rule is excluded from widening entirely. This pins that exclusion.
    #[test]
    fn a_widening_suggestion_never_proposes_a_temporal_clause() {
        let over_bound =
            CanonicalResource::from_stored(r#"{"amount":9000}"#, &AMOUNT_CONTRACT).unwrap();
        for source in TEMPORAL_CORPORA {
            let rules = parse_rules(source).unwrap();
            let widened = widen_rule_for_request(&rules.rules[0], &over_bound, &AMOUNT_CONTRACT);
            assert!(
                widened.is_none(),
                "a temporal rule must never be mechanically widened into a suggestion: {source}"
            );
        }
        // The stateless twin still widens — the exclusion is about the clause, not about widening.
        let stateless = parse_rules("allow stripe.refund where amount <= 5000\n").unwrap();
        let widened = widen_rule_for_request(&stateless.rules[0], &over_bound, &AMOUNT_CONTRACT)
            .expect("a stateless bound is still widenable");
        let printed = print_rule(&widened.rule);
        assert!(!printed.contains("budget"), "{printed}");
        assert!(!printed.contains("rate"), "{printed}");
        assert!(!printed.contains(" per "), "{printed}");
    }
}

#[cfg(test)]
mod form_index_tests {
    use super::*;
    use crate::contract::{AllowBinding, FieldClass, FieldDecl, ScalarKind};

    /// Every declaration shape a contract can carry. `FieldDecl` is plain data, so the product is
    /// enumerated whole rather than sampled — the index must be right for all of them, including the
    /// combinations no shipped template happens to declare.
    fn every_declaration() -> Vec<FieldDecl> {
        let mut decls = Vec::new();
        for ty in [ScalarKind::Str, ScalarKind::Int, ScalarKind::Bool] {
            for required in [true, false] {
                for class in [
                    FieldClass::Identity,
                    FieldClass::SideEffect,
                    FieldClass::FreePayload,
                    FieldClass::Secret,
                    FieldClass::ReadFilter,
                ] {
                    for binding in [
                        AllowBinding::Unbound,
                        AllowBinding::ExactResourcePin,
                        AllowBinding::ExactOrPatternList("names"),
                        AllowBinding::Bounded,
                    ] {
                        decls.push(FieldDecl {
                            name: "f",
                            ty,
                            required,
                            class,
                            binding,
                        });
                    }
                }
            }
        }
        decls
    }

    /// Sentences spelling `form` on field `f`, written INDEPENDENTLY of the index's own probes:
    /// every literal shape the grammar can put in a conjunct, including multi-value and
    /// mixed-literal `in` lists.
    fn sentences_using(form: &str) -> Vec<Pred> {
        let field = || "f".to_string();
        let literals = [
            Scalar::Int(1),
            Scalar::String("v".to_string()),
            Scalar::Bool(true),
        ];
        match form {
            "=" => literals
                .into_iter()
                .map(|value| Pred::Eq {
                    field: field(),
                    value,
                })
                .collect(),
            "in" => {
                let mut preds: Vec<Pred> = literals
                    .iter()
                    .cloned()
                    .map(|value| Pred::In {
                        field: field(),
                        values: vec![value],
                    })
                    .collect();
                preds.push(Pred::In {
                    field: field(),
                    values: literals.to_vec(),
                });
                preds.push(Pred::In {
                    field: field(),
                    values: vec![Scalar::Int(1), Scalar::Int(2)],
                });
                preds.push(Pred::In {
                    field: field(),
                    values: vec![Scalar::String("a".into()), Scalar::String("b".into())],
                });
                preds
            }
            "<=" => vec![
                Pred::Lte {
                    field: field(),
                    value: 1,
                },
                Pred::Lte {
                    field: field(),
                    value: -7,
                },
            ],
            ">=" => vec![
                Pred::Gte {
                    field: field(),
                    value: 1,
                },
                Pred::Gte {
                    field: field(),
                    value: -7,
                },
            ],
            other => panic!("unknown comparator {other}"),
        }
    }

    /// The catalog's WHERE index is a CLAIM about the evaluator, so it is checked against
    /// the evaluator itself over every declaration shape. A comparator the index prints must have a
    /// sentence that resolves; a comparator it omits must have none. A second table listing e.g.
    /// `<=` for `str` (or dropping it from `int`) fails here, so the rendering cannot drift.
    #[test]
    fn admissible_forms_are_exactly_what_the_evaluator_resolves() {
        for decl in every_declaration() {
            // Checked in BOTH gate positions: the comparator half of the index is decided by the
            // evaluator and must not move when the temporal gate does.
            for temporal_clauses in [false, true] {
                let forms = decl.admissible_forms(temporal_clauses);
                if decl.class == FieldClass::Secret {
                    // `reject_secret_conjuncts` refuses ANY rule naming a secret field, so no form is
                    // usable however the kernel's kind resolution would answer.
                    assert!(
                        forms.is_empty(),
                        "a secret field admits no sentence form: {decl:?} -> {forms:?}"
                    );
                    continue;
                }
                for form in ["=", "in", "<=", ">="] {
                    let resolves = sentences_using(form)
                        .iter()
                        .any(|pred| pred_resolves_for_decl(pred, &decl));
                    assert_eq!(
                        forms.contains(&form),
                        resolves,
                        "the index and the evaluator disagree about `{form}` on {decl:?} \
                     (index says {forms:?})"
                    );
                }
                // `rate` meters admissions, not a field: it is verb-level and never per-field.
                assert!(!forms.contains(&"rate"));
                // `budget` is listed ONLY when the declared gate admits it — the index must never
                // teach a form corpus admission would refuse.
                assert_eq!(
                    forms.contains(&"budget"),
                    temporal_clauses && decl.budget_eligible(),
                    "the index advertised `budget` against the gate: {decl:?} -> {forms:?}"
                );
            }
        }
    }

    /// The forms print in one fixed order, so two verbs' indexes read the same way.
    #[test]
    fn the_form_index_is_ordered_and_bounded() {
        let bounded_int = FieldDecl {
            name: "amount",
            ty: ScalarKind::Int,
            required: true,
            class: FieldClass::SideEffect,
            binding: AllowBinding::Bounded,
        };
        // With the temporal gate OPEN the summable field carries `budget` last in the fixed order.
        assert_eq!(
            bounded_int.admissible_forms(true),
            vec!["=", "in", "<=", ">=", "budget"]
        );
        // With the SHIPPED default (gate closed) the same field advertises comparators only.
        assert_eq!(
            bounded_int.admissible_forms(false),
            vec!["=", "in", "<=", ">="]
        );
        let identity_str = FieldDecl {
            ty: ScalarKind::Str,
            class: FieldClass::Identity,
            binding: AllowBinding::ExactResourcePin,
            ..bounded_int
        };
        assert_eq!(identity_str.admissible_forms(true), vec!["=", "in"]);
        // An optional int side-effect field still compares, but cannot be summed: an absent
        // optional field would silently debit nothing.
        let optional_int = FieldDecl {
            required: false,
            ..bounded_int
        };
        assert_eq!(
            optional_int.admissible_forms(true),
            vec!["=", "in", "<=", ">="]
        );
    }
}

/// The OWNING tests for [`DenyReason`]'s STORED shape.
///
/// A typed refusal is serialized into the `requests.deny_reason_json` column and read back by a
/// build that may be newer than the one that wrote it, so every member added to a variant is an
/// additive wire change: no migration, no schema-version bump, and rows written before the
/// addition must still deserialize.
#[cfg(test)]
mod deny_reason_storage_tests {
    use super::*;

    /// The exact bytes an older build wrote for a predicate mismatch. `field` arrives as absence,
    /// not as an error and not as a placeholder.
    #[test]
    fn a_predicate_mismatch_stored_before_the_field_existed_reads_back() {
        let stored = r#"{"predicate_mismatch":{"rule_idx":17,"pred_idx":4}}"#;
        assert_eq!(
            serde_json::from_str::<DenyReason>(stored).expect("old rows still deserialize"),
            DenyReason::PredicateMismatch {
                rule_idx: 17,
                pred_idx: 4,
                field: None,
            }
        );
    }

    /// What this build writes survives its own round trip, name included.
    #[test]
    fn a_predicate_mismatch_round_trips_through_storage_with_its_field() {
        let reason = DenyReason::PredicateMismatch {
            rule_idx: 17,
            pred_idx: 4,
            field: Some("team".into()),
        };
        let json = serde_json::to_string(&reason).expect("serializable");
        assert!(json.contains("\"field\":\"team\""), "{json}");
        assert_eq!(
            serde_json::from_str::<DenyReason>(&json).expect("deserializable"),
            reason
        );
    }
}

/// The OWNING tests for the machine-index/human-number seam in this crate.
///
/// Two surface classes live here: the conversion pair itself, and every corpus-validation error
/// whose `Display` names a rule position to the person who just authored that corpus. The third
/// class (broker deny reasons) is owned in `cermet-core`, and the fourth (the `rules` list and
/// `revoke`/`refresh` input) in `cermet-cli` — each pinned where its rendering lives.
#[cfg(test)]
mod human_rule_number_tests {
    use super::*;

    /// The contract every human-facing renderer depends on: what a person reads, fed back to
    /// `cermet rules revoke`, must land on the rule the machine meant. `run_revoke` performs exactly
    /// `rule_index_from_human` then `rules.rules.get(index)`, so this round trip IS the revoke path.
    #[test]
    fn the_number_a_human_reads_round_trips_to_the_index_the_machine_meant() {
        for rule_idx in 0..64usize {
            let number = human_rule_number(rule_idx);
            assert_eq!(
                number,
                rule_idx + 1,
                "the list renders idx + 1; every other surface must agree"
            );
            assert!(number >= 1, "0 is rejected by `rules revoke` as not a rule");
            assert_eq!(
                rule_index_from_human(number),
                Some(rule_idx),
                "revoke's own arithmetic must land back on the same rule"
            );
        }
        assert_eq!(
            rule_index_from_human(0),
            None,
            "no surface prints rule 0; it is not a rule number"
        );
    }

    /// Corpus-validation refusals are read by the human who just wrote the corpus, and they name a
    /// position in it. A `rule 0` there is unresolvable against a list that starts at 1.
    #[test]
    fn every_corpus_validation_error_names_a_one_based_rule() {
        let first = |e: &dyn std::fmt::Display| e.to_string();

        let cases: Vec<(String, &str)> = vec![
            (
                first(&ReferenceError::UnresolvedVerb {
                    rule_idx: 0,
                    provider: "stripe".into(),
                    action: "refund".into(),
                }),
                "rule 1: unresolved verb stripe.refund",
            ),
            (
                first(&ReferenceError::UnresolvedSet {
                    rule_idx: 4,
                    provider: "stripe".into(),
                    set: "support".into(),
                }),
                "rule 5: unresolved set stripe.support",
            ),
            (
                first(&ReferenceError::UnresolvedSetMember {
                    rule_idx: 11,
                    provider: "stripe".into(),
                    action: "refund".into(),
                }),
                "rule 12: unresolved set member stripe.refund",
            ),
            (
                first(&ReferenceError::UnresolvedField {
                    rule_idx: 2,
                    field: "amount".into(),
                }),
                "rule 3: unresolved conjunct field `amount`",
            ),
        ];
        for (rendered, expected) in cases {
            assert_eq!(rendered, expected);
        }

        let shadow = ShadowError {
            plain_idx: 0,
            aggregate_idx: 3,
            provider: "stripe".into(),
            action: "refund".into(),
            earlier_meters_differently: false,
        }
        .to_string();
        assert!(
            shadow.starts_with("rule 1 (allow, no aggregate) is ordered before the "),
            "the shadowing rule must be named as the list names it: {shadow}"
        );
        assert!(
            shadow.contains("aggregate-bearing rule 4"),
            "both positions in one message must share the one basis: {shadow}"
        );
    }
}
