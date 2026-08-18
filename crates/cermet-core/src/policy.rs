//! Sentence-authority evaluation for broker capability requests.
use serde_json::Value;

use crate::types::Decision;

pub struct Query<'a> {
    pub provider: &'a str,
    pub action: &'a str,
    pub resource: &'a Value,
}
/// What the evaluator decided, in every form the broker needs it: the answer, the sentence a human
/// reads, the admitting rule's canonical text on an allow, and the evaluator's OWN typed refusal
/// beside the prose it used to be flattened into.
///
/// The prose is the operator's; the typed reason is the record's. Reconstructing "which of the
/// eight refusals was this" by matching that sentence would be parsing our own message format, and
/// a wording change would silently reclassify history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVerdict {
    pub decision: Decision,
    pub reason: String,
    /// On an allow, the canonical printed text of the admitting rule — a rule's identity is its
    /// text, the exact bytes the corpus digest covers, not its position in a file.
    pub matched_rule: Option<String>,
    /// The typed refusal, present on every deny the sentence evaluator itself produced. `None` on
    /// an allow, and on a refusal raised before evaluation (a resource that is not canonical for
    /// the resolved contract) — that one has no `DenyReason` to give, and inventing one would claim
    /// the evaluator ran.
    pub deny_reason: Option<crate::sentence::DenyReason>,
}

pub trait PolicyEvaluator {
    /// The decision, its human-readable reason, and — on an allow — the canonical printed text of
    /// the admitting rule. A rule's identity is its text, the exact bytes the corpus digest
    /// covers, not its position in a file.
    fn evaluate(&self, query: &Query) -> PolicyVerdict;
}
pub struct SentencePolicy<'a> {
    rules: &'a crate::sentence::RuleSet,
    evaluator: crate::sentence::SentenceEvaluator<'a>,
}

impl<'a> SentencePolicy<'a> {
    pub fn new(
        rules: &'a crate::sentence::RuleSet,
        sets: &'a dyn crate::sets::SetResolver,
        contracts: &'a dyn crate::sentence::ContractResolver,
    ) -> Self {
        Self {
            rules,
            evaluator: crate::sentence::SentenceEvaluator::new(sets, contracts),
        }
    }
}

impl PolicyEvaluator for SentencePolicy<'_> {
    fn evaluate(&self, query: &Query) -> PolicyVerdict {
        use crate::sentence::{human_rule_number, Decision as SentenceDecision, DenyReason};

        let sentence_decision = match self.evaluator.evaluate_match_value(
            self.rules,
            query.provider,
            query.action,
            query.resource,
        ) {
            Ok(decision) => decision,
            Err(_) => {
                return PolicyVerdict {
                    decision: Decision::Deny,
                    reason: format!(
                        "{}.{} denied by sentence authority: query resource is not canonical for the resolved action contract",
                        query.provider, query.action
                    ),
                    matched_rule: None,
                    // The evaluator never ran, so it has no typed refusal to report.
                    deny_reason: None,
                };
            }
        };

        // The admitting rule's canonical text, read off the same ordered corpus the digest covers.
        let matched_rule = match &sentence_decision {
            SentenceDecision::Allow { rule_idx } => self
                .rules
                .rules
                .get(*rule_idx)
                .map(crate::sentence::print_rule),
            SentenceDecision::Deny { .. } => None,
        };
        // The typed refusal, kept whole. Every arm below renders it into prose for a human; this
        // keeps the thing that was rendered, so the record and the sentence can never disagree.
        let deny_reason = match &sentence_decision {
            SentenceDecision::Allow { .. } => None,
            SentenceDecision::Deny { reason } => Some(reason.clone()),
        };
        let (decision, reason) = match sentence_decision {
            SentenceDecision::Allow { .. } => (
                Decision::Allow,
                format!(
                    "{}.{} allowed by sentence authority",
                    query.provider, query.action
                ),
            ),
            // Every rule number below is rendered through `human_rule_number`, because a
            // deny that names a rule is an instruction to go find that line in `cermet rules` and
            // widen or revoke it. The typed `rule_idx` on the wire stays zero-based (it indexes the
            // corpus slice); only this display seam converts.
            SentenceDecision::Deny {
                reason: DenyReason::ExplicitDeny { rule_idx },
            } => (
                Decision::Deny,
                format!(
                    "{}.{} denied by sentence authority rule {}",
                    query.provider,
                    query.action,
                    human_rule_number(rule_idx)
                ),
            ),
            SentenceDecision::Deny {
                reason: DenyReason::UnresolvedDeny { rule_idx },
            } => (
                Decision::Deny,
                format!(
                    "{}.{} denied by sentence authority: rule {} could not be resolved",
                    query.provider,
                    query.action,
                    human_rule_number(rule_idx)
                ),
            ),
            // Unknown selector and unmatched selector are distinct answers to distinct questions.
            // An unknown selector is the agent's to fix (a typo, or a verb this daemon does not
            // carry); an unruled verb is the operator's, and the widening suggestion attached
            // alongside says exactly which command closes it.
            SentenceDecision::Deny {
                reason: DenyReason::UnknownSelector,
            } => (
                Decision::Deny,
                format!(
                    "{}.{} denied by sentence authority: unknown selector — no such verb in the ratified grammar",
                    query.provider, query.action
                ),
            ),
            SentenceDecision::Deny {
                reason: DenyReason::NoMatchingRule,
            } => (
                Decision::Deny,
                format!(
                    "{}.{} denied by sentence authority: no rule matches this request",
                    query.provider, query.action
                ),
            ),
            SentenceDecision::Deny {
                reason: DenyReason::UnsupportedVersion { version },
            } => (
                Decision::Deny,
                format!(
                    "{}.{} denied by sentence authority: unsupported ruleset version {version}",
                    query.provider, query.action
                ),
            ),
            SentenceDecision::Deny {
                reason: DenyReason::MissingField { rule_idx, field },
            } => (
                Decision::Deny,
                format!(
                    "{}.{} denied by sentence authority: rule {} requires missing field `{field}`",
                    query.provider,
                    query.action,
                    human_rule_number(rule_idx)
                ),
            ),
            // `pred_idx` counts the rule's `where` conjuncts left to right, and it is numbered from
            // 1 here for the same reason as the rule: the two numbers sit in ONE sentence a person
            // reads, and mixing bases inside it would be confusing. "rule 19 predicate 1"
            // is the FIRST conjunct of the rule the list calls 19.
            // The field NAME rides at the end: a position tells the operator where to
            // look, the name tells them what the sentence was arguing about, which is the part they
            // can act on without opening the file. It is appended rather than spliced so the
            // sentence a reader already knows stays intact.
            SentenceDecision::Deny {
                reason:
                    DenyReason::PredicateMismatch {
                        rule_idx,
                        pred_idx,
                        field,
                    },
            } => (
                Decision::Deny,
                format!(
                    "{}.{} denied by sentence authority: rule {} predicate {} did not match{}",
                    query.provider,
                    query.action,
                    human_rule_number(rule_idx),
                    pred_idx + 1,
                    match &field {
                        Some(field) => format!(" (field `{field}`)"),
                        None => String::new(),
                    }
                ),
            ),
            SentenceDecision::Deny {
                reason: DenyReason::BudgetExceeded { window },
            } => (
                Decision::Deny,
                format!(
                    "{}.{} denied by sentence authority: budget exhausted for the {} window",
                    query.provider,
                    query.action,
                    match window {
                        crate::sentence::Window::Hour => "hour",
                        crate::sentence::Window::Day => "day",
                    }
                ),
            ),
        };
        PolicyVerdict {
            decision,
            reason,
            matched_rule,
            deny_reason,
        }
    }
}

pub use cermet_lang::policy::{ContractSource, DefaultContractSource};
