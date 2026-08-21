//! Human-only CLI operations over the sentence custody seam ([`crate::sentence_custody`]).

use std::collections::BTreeSet;

use cermet_lang::contract::FieldClass;
use cermet_lang::policy::{ContractSource, DefaultContractSource};
use cermet_lang::sentence::{
    parse_rules, pin_set_references, print_rule, Pred, Rule, RuleSet, Selector,
};
use cermet_lang::sets::SetResolver;

use crate::sentence_custody::{
    CustodyError, RuleCorpusExpectation, RuleCorpusSnapshot, SentenceCustody,
};
use crate::tty::Terminal;
use crate::{CliError, CliOutput};

/// Catalog seam used only at authoring time to decide whether a quoted value names an identity.
/// Evaluation never consults it or any provider.
pub trait RuleCatalog {
    fn field_class(
        &self,
        selector: &Selector,
        field: &str,
        sets: &dyn SetResolver,
    ) -> Result<FieldClass, String>;
}

/// The vendored verb catalog. Set selectors fail closed until their member catalog lands; an
/// unquoted pinned id or numeric bound does not need this lookup.
pub struct VendoredRuleCatalog;

impl RuleCatalog for VendoredRuleCatalog {
    fn field_class(
        &self,
        selector: &Selector,
        field: &str,
        sets: &dyn SetResolver,
    ) -> Result<FieldClass, String> {
        match selector {
            Selector::Verb { provider, action } => {
                let contract = DefaultContractSource
                    .contract(provider, action)
                    .ok_or_else(|| format!("unknown verb selector `{provider}.{action}`"))?;
                contract
                    .field_class(field)
                    .ok_or_else(|| format!("unknown field `{field}` for `{provider}.{action}`"))
            }
            Selector::Set {
                provider,
                set,
                digest,
            } => {
                let snapshot = match digest.as_deref() {
                    Some(digest) => sets
                        .snapshot(provider, set, digest)
                        .filter(|snapshot| snapshot.is_for(provider, set, digest)),
                    None => sets
                        .current_snapshot(provider, set)
                        .filter(|snapshot| snapshot.is_for(provider, set, snapshot.digest())),
                }
                .ok_or_else(|| format!("unknown set selector `{provider}.{set}`"))?;
                let mut class = None;
                for action in snapshot.members() {
                    let contract = DefaultContractSource
                        .contract(provider, action)
                        .ok_or_else(|| {
                            format!("set `{provider}.{set}` has unknown member `{action}`")
                        })?;
                    let Some(member_class) = contract.field_class(field) else {
                        continue;
                    };
                    if class.is_some_and(|existing| existing != member_class) {
                        return Err(format!(
                            "field `{field}` has inconsistent classes in set `{provider}.{set}`"
                        ));
                    }
                    class = Some(member_class);
                }
                class.ok_or_else(|| format!("unknown field `{field}` for set `{provider}.{set}`"))
            }
        }
    }
}

/// A quoted string is a LITERAL and nothing else.
///
/// An earlier dialect let a quoted scalar on an identity field mean RESOLVE THIS NAME: `cermet rules
/// allow` handed it to a provider's authoring-time read adapter and stored the id that came back,
/// while a bare ident meant the literal. Quoting is now MANDATORY for every string, so the quote
/// marks can no longer carry that distinction — `owner = "suarezc"` is the ordinary way to write a
/// literal, and resolving it would turn the commonest rule in the corpus into a provider call.
/// The seam (`ProviderRead`, its Stripe adapter, the fail-closed placeholder, and the
/// `resolve_names`/`resolve_scalar` pass) is therefore deleted, not gated: it was already reachable
/// only through a credential path the daemon-only design fails closed, so it produced refusals and
/// nothing else. Name resolution, if it returns, needs its own declared vocabulary rather than a
/// second meaning for a quote.
/// The response-contract lines the allow ceremony echoes for a rule's selector.
///
/// A SET does NOT share one contract by construction, and assuming it does is a trap.
/// `stripe.charge_ops` is five money-floor verbs that store nothing, and `refund_ops` mixes two
/// full reads with one capped mutation; assuming `full` would tell the operator the opposite of the
/// truth on the selector where the member-level fact is hardest to look up by hand. So the members are
/// resolved and GROUPED: one line per distinct contract, naming the members it covers. Identical
/// members still collapse to a single line — that is the common case, not the guaranteed one.
fn response_contract_lines(selector: &Selector, sets: &dyn SetResolver) -> Vec<String> {
    let members: Vec<(String, cermet_lang::templates::ResponseContract)> = match selector {
        Selector::Verb { provider, action } => {
            cermet_lang::templates::vendored_response_contract(provider, action)
                .map(|contract| vec![(action.clone(), contract)])
                .unwrap_or_default()
        }
        Selector::Set {
            provider,
            set,
            digest,
        } => {
            let snapshot = match digest.as_deref() {
                Some(digest) => sets.snapshot(provider, set, digest),
                None => sets.current_snapshot(provider, set),
            };
            snapshot
                .map(|snapshot| {
                    snapshot
                        .members()
                        .iter()
                        .filter_map(|action| {
                            cermet_lang::templates::vendored_response_contract(provider, action)
                                .map(|contract| (action.clone(), contract))
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
    };

    // Group by contract, preserving first-seen order so the line an operator reads first is the
    // one covering the first member of the set.
    let mut grouped: Vec<(cermet_lang::templates::ResponseContract, Vec<String>)> = Vec::new();
    for (action, contract) in members {
        match grouped.iter_mut().find(|(seen, _)| *seen == contract) {
            Some((_, actions)) => actions.push(action),
            None => grouped.push((contract, vec![action])),
        }
    }
    grouped
        .into_iter()
        .map(|(contract, actions)| {
            format!("returns ({}): {}", actions.join(", "), contract.summary())
        })
        .collect()
}

pub fn run_allow(
    custody: &dyn SentenceCustody,
    terminal: &dyn Terminal,
    catalog: &dyn RuleCatalog,
    sets: &dyn SetResolver,
    text: &str,
    yes: bool,
) -> Result<CliOutput, CliError> {
    let text = normalize_allow_input(text)?;
    cermet_lang::sentence::preflight_product_availability(&text)
        .map_err(|_| CliError::Refused("provider_disabled".into()))?;
    let mut parsed = parse_rules(&text).map_err(|error| CliError::Usage(error.to_string()))?;
    cermet_lang::sentence::validate_product_availability(&parsed)
        .map_err(|_| CliError::Refused("provider_disabled".into()))?;
    pin_set_references(&mut parsed, sets).map_err(|error| CliError::Refused(error.to_string()))?;
    let mut rules = parsed.rules;
    if rules.len() != 1 {
        return Err(CliError::Usage(
            "allow expects exactly one non-comment rule".into(),
        ));
    }
    let rule = rules.remove(0);
    reject_secret_conjuncts(catalog, sets, &rule)?;
    let canonical = print_rule(&rule);
    let (mut stored, expected_source, recovering_pin_mismatch) =
        match custody.read_rule_corpus_for_update().map_err(map_custody)? {
            RuleCorpusSnapshot::Authenticated(authenticated) => {
                (authenticated.rules, authenticated.source, false)
            }
            RuleCorpusSnapshot::PinMismatch { source } => (
                RuleSet {
                    version: 1,
                    rules: Vec::new(),
                },
                source,
                true,
            ),
        };

    // `--yes` may skip the routine canonical-echo confirm (the presence-gated CAS
    // below still governs the swap) but must NEVER auto-confirm a pin-mismatch recovery —
    // replacing an untrusted corpus is an anomaly for the interactive path, not a script.
    if yes && recovering_pin_mismatch {
        return Err(CliError::Refused(
            "the existing rule corpus does not match its approval pin; --yes may not \
             auto-confirm corpus replacement — rerun without --yes for the interactive \
             recovery"
                .into(),
        ));
    }
    let mut prompt = format!("Cermet understood this rule as:\n  {canonical}");
    // The operator is authoring the WHERE. Echo the SELECT before they decide —
    // what the verb returns, what is stored, and what an error gives back — so "allow" is never
    // consent to a response surface they were never shown.
    for line in response_contract_lines(&rule.selector, sets) {
        prompt.push_str(&format!("\n  {line}"));
    }
    if recovering_pin_mismatch {
        prompt.push_str(
            "\n\nThe existing rule corpus does not match its approval pin.\nIf you continue, \
             the untrusted existing rule corpus will be replaced.\nAfter recovery, only the \
             displayed canonical rule will remain.",
        );
    }
    prompt.push_str("\nAllow this rule?");
    if !yes && !terminal.confirm(&prompt, false) {
        return Err(CliError::Refused(
            "rule confirmation declined; custody was not changed".into(),
        ));
    }

    stored.rules.push(rule);
    let number = stored.rules.len();
    let expected = if recovering_pin_mismatch {
        RuleCorpusExpectation::PinMismatch(&expected_source)
    } else {
        RuleCorpusExpectation::Authenticated(&expected_source)
    };
    let receipt = custody
        .compare_and_swap_rules_with_presence(
            expected,
            &stored,
            &format!("add Cermet rule: {canonical}"),
        )
        .map_err(map_custody)?;
    let known = receipt.is_known();
    let final_live = known && receipt.live_is_exact;
    Ok(CliOutput {
        text: format!(
            "{} rule #{number}: {canonical}\n{}",
            if final_live {
                "added"
            } else if known {
                "add committed but is not final for proposed"
            } else {
                "add outcome unknown for proposed"
            },
            render_mutation_receipt(&receipt)
        ),
        ok: final_live,
    })
}

fn normalize_allow_input(text: &str) -> Result<String, CliError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(CliError::Usage("allow expects a rule".into()));
    }
    let mut lines = text.lines().map(str::to_string).collect::<Vec<_>>();
    let rule_idx = lines
        .iter()
        .position(|line| {
            let line = line.trim_start();
            !line.is_empty() && !line.starts_with('#')
        })
        .ok_or_else(|| CliError::Usage("allow expects a rule".into()))?;
    let rule = lines[rule_idx].trim_start();
    let mut words = rule.splitn(2, char::is_whitespace);
    let first = words.next().unwrap_or_default();
    // The rule text carries its own EFFECT. `allow` may be elided (the historical convenience) and
    // `deny` is passed through verbatim — the language has both, and "a matching deny wins over
    // every allow" is what the daemon enforces. A deny rule is authority-NARROWING by
    // construction, the ceremony below echoes the canonical rule INCLUDING its effect before the
    // operator accepts, and the presence-gated CAS swap is unchanged.
    if first == "allow" || first == "deny" {
        let body = words.next().unwrap_or_default().trim_start();
        if body.is_empty() {
            return Err(CliError::Usage(format!(
                "bare `{first}` has no selector; pass a rule after it"
            )));
        }
        lines[rule_idx] = format!("{first} {body}");
    } else {
        lines[rule_idx] = format!("allow {rule}");
    }
    Ok(lines.join("\n"))
}

fn reject_secret_conjuncts(
    catalog: &dyn RuleCatalog,
    sets: &dyn SetResolver,
    rule: &Rule,
) -> Result<(), CliError> {
    for pred in &rule.conjuncts {
        let field = match pred {
            Pred::Eq { field, .. }
            | Pred::In { field, .. }
            | Pred::Lte { field, .. }
            | Pred::Gte { field, .. } => field,
        };
        let class = catalog
            .field_class(&rule.selector, field, sets)
            .map_err(CliError::Refused)?;
        if class == FieldClass::Secret {
            return Err(CliError::Refused(format!(
                "rule may not constrain secret-class field `{field}`"
            )));
        }
    }
    Ok(())
}

pub fn run_rules(custody: &dyn SentenceCustody) -> Result<CliOutput, CliError> {
    let rules = custody.read_rules().map_err(map_custody)?;
    let text = if rules.rules.is_empty() {
        "No rules configured.".to_string()
    } else {
        rules
            .rules
            .iter()
            .enumerate()
            .map(|(idx, rule)| format!("{}. {}", idx + 1, listed_rule(rule)))
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(CliOutput { text, ok: true })
}

/// One rule AS THE `rules allow` ARGUMENT SPELLS IT (from a cold-start usability trial).
///
/// The list rendered `5. allow github.push where …` while the command that applies a rule is
/// `cermet rules allow '<rule>'`, so copying a listed row produced `allow allow …` — two dialects
/// for one sentence, in the two places most likely to be read together. The leading `allow` is
/// elidable in the language (see `normalize_allow_input`) and the daemon's own widening hints
/// already omit it, so the LIST drops it too and the two surfaces agree. A `deny` rule keeps its
/// keyword: it is not elidable, and dropping it would render a narrowing rule as a widening one.
fn listed_rule(rule: &Rule) -> String {
    let printed = print_rule(rule);
    printed
        .strip_prefix("allow ")
        .map(str::to_string)
        .unwrap_or(printed)
}

pub fn run_revoke(
    custody: &dyn SentenceCustody,
    terminal: &dyn Terminal,
    number: usize,
    yes: bool,
) -> Result<CliOutput, CliError> {
    let authenticated = custody.read_authenticated_rules().map_err(map_custody)?;
    let mut rules = authenticated.rules;
    let index = number.checked_sub(1).ok_or_else(|| {
        CliError::Usage("revoke expects a one-based rule number (1 or greater)".into())
    })?;
    let rule = rules.rules.get(index).ok_or_else(|| {
        CliError::Refused(format!(
            "rule #{number} does not exist ({} rule(s) configured)",
            rules.rules.len()
        ))
    })?;
    let canonical = print_rule(rule);
    // `--yes` skips only this CLI-side confirm so scripts can revoke
    // noninteractively; the presence-gated CAS below still governs the custody swap.
    if !yes && !terminal.confirm(&format!("Revoke rule #{number}?\n  {canonical}"), false) {
        return Err(CliError::Refused(
            "rule revocation declined; custody was not changed".into(),
        ));
    }
    rules.rules.remove(index);
    let receipt = custody
        .compare_and_swap_rules_with_presence(
            RuleCorpusExpectation::Authenticated(&authenticated.source),
            &rules,
            &format!("revoke Cermet rule #{number}: {canonical}"),
        )
        .map_err(map_custody)?;
    let known = receipt.is_known();
    let final_live = known && receipt.live_is_exact;
    Ok(CliOutput {
        text: format!(
            "{} rule #{number}: {canonical}\n{}",
            if final_live {
                "revoked"
            } else if known {
                "revoke committed but is not final for selected"
            } else {
                "revoke outcome unknown for selected"
            },
            render_mutation_receipt(&receipt)
        ),
        ok: final_live,
    })
}

/// Rebind exactly one stored set selector to the resolver's current immutable expansion. The full
/// deterministic diff is the existing OS-presence reason; a declined/unavailable gate writes nothing.
pub fn run_refresh(
    custody: &dyn SentenceCustody,
    sets: &dyn SetResolver,
    number: usize,
) -> Result<CliOutput, CliError> {
    let authenticated = custody.read_authenticated_rules().map_err(map_custody)?;
    let mut rules = authenticated.rules;
    let index = number.checked_sub(1).ok_or_else(|| {
        CliError::Usage("refresh expects a one-based rule number (1 or greater)".into())
    })?;
    let rule = rules.rules.get(index).ok_or_else(|| {
        CliError::Refused(format!(
            "rule #{number} does not exist ({} rule(s) configured)",
            rules.rules.len()
        ))
    })?;
    let (provider, set, old_digest) = match &rule.selector {
        Selector::Set {
            provider,
            set,
            digest: Some(digest),
        } => (provider.clone(), set.clone(), digest.clone()),
        Selector::Set { .. } => {
            return Err(CliError::Refused(format!(
                "rule #{number} has an unpinned set selector and confers no authority; re-author it with `cermet rules allow`"
            )));
        }
        Selector::Verb { .. } => {
            return Err(CliError::Refused(format!(
                "rule #{number} selects a direct verb and has no set snapshot to refresh"
            )));
        }
    };
    let old = sets
        .snapshot(&provider, &set, &old_digest)
        .filter(|snapshot| snapshot.is_for(&provider, &set, &old_digest))
        .ok_or_else(|| {
            CliError::Refused(format!(
                "rule #{number} references unknown set snapshot `{provider}.{set}@{old_digest}`; no change made"
            ))
        })?;
    let new = sets
        .current_snapshot(&provider, &set)
        .filter(|snapshot| snapshot.is_for(&provider, &set, snapshot.digest()))
        .ok_or_else(|| {
            CliError::Refused(format!(
                "set `{provider}.{set}` has no valid current snapshot; no change made"
            ))
        })?;

    let old_members = old.members().iter().collect::<BTreeSet<_>>();
    let new_members = new.members().iter().collect::<BTreeSet<_>>();
    let added = new_members
        .difference(&old_members)
        .copied()
        .collect::<Vec<_>>();
    let removed = old_members
        .difference(&new_members)
        .copied()
        .collect::<Vec<_>>();
    let summary = format_refresh(
        number,
        &provider,
        &set,
        &old_digest,
        new.digest(),
        &added,
        &removed,
    );
    if old_digest == new.digest() {
        return Ok(CliOutput {
            text: summary,
            ok: true,
        });
    }

    let Selector::Set { digest, .. } = &mut rules.rules[index].selector else {
        unreachable!("selected as a set above")
    };
    *digest = Some(new.digest().to_string());
    let receipt = custody
        .compare_and_swap_rules_with_presence(
            RuleCorpusExpectation::Authenticated(&authenticated.source),
            &rules,
            &summary,
        )
        .map_err(map_custody)?;
    let known = receipt.is_known();
    let final_live = known && receipt.live_is_exact;
    Ok(CliOutput {
        text: format!("{summary}\n{}", render_mutation_receipt(&receipt)),
        ok: final_live,
    })
}

fn format_refresh(
    number: usize,
    provider: &str,
    set: &str,
    old_digest: &str,
    new_digest: &str,
    added: &[&String],
    removed: &[&String],
) -> String {
    let mut out = format!(
        "refresh Cermet rule #{number} set {provider}.{set}\nold digest: {old_digest}\nnew digest: {new_digest}\nadded members:"
    );
    if added.is_empty() {
        out.push_str("\n  (none)");
    } else {
        for member in added {
            out.push_str(&format!("\n  + {member}"));
        }
    }
    out.push_str("\nremoved members:");
    if removed.is_empty() {
        out.push_str("\n  (none)");
    } else {
        for member in removed {
            out.push_str(&format!("\n  - {member}"));
        }
    }
    out
}

fn render_mutation_receipt(receipt: &crate::sentence_custody::CorpusMutationReceipt) -> String {
    use crate::sentence_custody::{CorpusDocumentSync, CorpusMutationReceiptState};
    use cermet_ipc::ctl::LockdownSnapshot;

    let lockdown = match receipt.lockdown {
        Some(LockdownSnapshot::Clear) => "clear",
        Some(LockdownSnapshot::Engaged) => "engaged",
        None => "unknown",
    };
    let document_sync = match receipt.document_sync {
        CorpusDocumentSync::State(state) => state,
        CorpusDocumentSync::Required => "required",
        CorpusDocumentSync::Unavailable(reason) => reason,
    };
    let mut output = match receipt.state {
        CorpusMutationReceiptState::Known => format!(
            "receipt_state: known\n{}: sha256:{}\noccurrence_id: {}\nacceptance_path: {}\nlockdown: {lockdown}\ndocument_sync: {document_sync}",
            if receipt.live_is_exact {
                "live"
            } else {
                "committed"
            },
            receipt.authority_digest,
            receipt.occurrence_id,
            receipt.acceptance_path
        ),
        CorpusMutationReceiptState::Unknown => format!(
            "receipt_state: unknown\ncandidate: sha256:{}\noccurrence_id: {}\nstaging_token: {}\nacceptance_path: {}\nlockdown: {lockdown}\ndocument_sync: {document_sync}\nWARNING: exact mutation outcome remains unknown; preserve this token/occurrence and do not repeat this mutation command.",
            receipt.authority_digest,
            receipt.occurrence_id,
            receipt.staging_token,
            receipt.acceptance_path
        ),
    };
    if receipt.state == CorpusMutationReceiptState::Known && !receipt.live_is_exact {
        output.push_str("\nWARNING: this transaction committed, but that exact occurrence is not the observed final served authority.");
    }
    if receipt.lockdown == Some(LockdownSnapshot::Engaged) {
        output.push_str("\nWARNING: owner lockdown is engaged; execution remains disabled.");
    }
    output
}

fn map_custody(error: CustodyError) -> CliError {
    match error {
        CustodyError::PresenceDenied => {
            CliError::Presence("human presence declined; custody was not changed".into())
        }
        CustodyError::PresenceUnavailable(message) => CliError::Presence(message),
        CustodyError::MissingSecret(provider) => CliError::Refused(format!(
            "no {provider} key is connected; run `cermet connect {provider}` before using a quoted identity name"
        )),
        other => CliError::Refused(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cermet_lang::sentence::parse_rules;

    fn listed(text: &str) -> String {
        let rules = parse_rules(text).expect("the fixture parses");
        rules
            .rules
            .iter()
            .enumerate()
            .map(|(idx, rule)| format!("{}. {}", idx + 1, listed_rule(rule)))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// one sentence, one spelling. A listed row must be exactly what `rules allow` takes,
    /// so copying it back is a no-op rather than `allow allow …`.
    #[test]
    fn a_listed_allow_row_is_the_argument_rules_allow_takes() {
        assert_eq!(
            listed("allow github.push where owner = \"acme\""),
            "1. github.push where owner = \"acme\""
        );
        // `deny` is NOT elidable — dropping it would render a narrowing rule as a widening one.
        assert_eq!(
            listed("allow github.push\ndeny github.push where owner = \"acme\""),
            "1. github.push\n2. deny github.push where owner = \"acme\""
        );
    }
}
