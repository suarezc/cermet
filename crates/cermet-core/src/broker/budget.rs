//! The ledger-derived budget/rate mint gate — the impure half of `crate::budget`.
//!
//! This is the distinct gate step in the mint handler, the only seam holding BOTH the
//! append-only audit ledger and `now`. It runs on the single serialized broker thread AFTER
//! `evaluate()` returns a typed `Allow { rule_idx }` and BEFORE the `policy_decision` audit emit (no
//! allowed-then-denied pair) and BEFORE `insert_grant`. It reads the winning rule's aggregate, freezes
//! the debit (frozen before execution, never filled at execute time), loads the bounded ledger
//! evidence, and calls the PURE
//! `crate::budget::decide_aggregate`. On admit it appends a durable `budget_mint` BEFORE the grant row;
//! on exhaustion it appends `budget_denied` and downgrades to a value-free `BudgetExceeded { window }`;
//! on invalid/ambiguous evidence it appends an operator-only `budget_gate_error` and returns a generic
//! deny. Fail closed always.

use super::*;

use crate::budget::{
    self, AggregateDecision, AggregateLedgerEvent, AggregateMeter, Fault, FrozenDebit, LedgerKind,
    ResolvedAggregate, WindowProof,
};
use crate::sentence::Window;

/// The gate's verdict, consumed by the mint handler.
pub(super) enum BudgetGate {
    /// The winning rule carries no aggregate — proceed to the ordinary mint unchanged.
    NoAggregate,
    /// Admit: append this `budget_mint` durably, THEN insert the grant.
    Admit(Box<AdmitTicket>),
    /// The cap is exhausted — downgrade to a value-free `BudgetExceeded { window }` deny. The
    /// `budget_denied` proof is already appended.
    Exceeded { window: Window },
    /// The evidence was invalid/ambiguous or the debit could not be frozen — a generic value-free
    /// deny. The operator-only `budget_gate_error` is already appended.
    Invalid,
}

/// Everything the mint handler needs to append the `budget_mint` provenance once it has
/// the grant id. Carries the single captured `decision_at_epoch` so the mint ts, the fixed calendar
/// bucket, and the grant expiry cannot drift from the check's clock.
pub(super) struct AdmitTicket {
    aggregate_id: String,
    resolution_digest: String,
    kind_str: &'static str,
    debit_field: Option<String>,
    limit: i64,
    window: Window,
    decision_at_epoch: i64,
    proof: WindowProof,
}

pub(super) struct RetryBudgetSubstitutionTicket {
    parent_grant_id: String,
    parent_mint_event_id: Option<String>,
}

macro_rules! budget_release_causes {
    ($($variant:ident => $value:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(super) enum BudgetReleaseCause {
            $($variant),+
        }

        impl BudgetReleaseCause {
            const ALL: &'static [Self] = &[$(Self::$variant),+];

            fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }

            fn parse(value: &str) -> Option<Self> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|cause| cause.as_str() == value)
            }
        }
    };
}

budget_release_causes! {
    Denied => "denied",
    CanceledUnclaimed => "canceled_unclaimed",
    ExpiredUnclaimed => "expired_unclaimed",
    PreInvocationTerminalFailure => "pre_invocation_terminal_failure",
    EvidenceStaleBeforeGrant => "evidence_stale_before_grant",
    AuthorityCutoverUnclaimed => "authority_cutover_unclaimed",
}

pub(super) struct RetryBudgetLineage<'a> {
    eligible_parent_grant_id: &'a str,
    reservation_owner_id: &'a str,
    reservation_owner_grant: &'a GrantRow,
    grant_ids: &'a BTreeSet<String>,
    request_ids: &'a BTreeSet<String>,
}

impl<'a> RetryBudgetLineage<'a> {
    pub(super) fn new(
        eligible_parent_grant_id: &'a str,
        reservation_owner_id: &'a str,
        reservation_owner_grant: &'a GrantRow,
        grant_ids: &'a BTreeSet<String>,
        request_ids: &'a BTreeSet<String>,
    ) -> Self {
        Self {
            eligible_parent_grant_id,
            reservation_owner_id,
            reservation_owner_grant,
            grant_ids,
            request_ids,
        }
    }
}

impl RetryBudgetSubstitutionTicket {
    pub(super) fn parent_grant_id(&self) -> &str {
        &self.parent_grant_id
    }

    fn parent_mint_event_id(&self) -> Option<&str> {
        self.parent_mint_event_id.as_deref()
    }
}

struct RetryAggregate {
    resolved: ResolvedAggregate,
    debit_field: Option<String>,
    debit: i64,
    decision_at_epoch: i64,
}

struct ParsedBudgetMint {
    event_id: String,
    rowid: i64,
    aggregate_id: String,
    resolution_digest: String,
    grant_id: String,
    request_id: String,
    meter: AggregateMeter,
    debit_field: Option<String>,
    debit: i64,
    limit: i64,
    decision_at_epoch: i64,
    expires_at_epoch: i64,
    proof: WindowProof,
}

struct ParsedBudgetPopulation {
    mints: Vec<ParsedBudgetMint>,
    releases: Vec<ParsedBudgetRelease>,
}

impl AdmitTicket {
    /// The single captured grant expiry: the mint ticket's `decision_at_epoch + TTL`. The
    /// grant row MUST be inserted with THIS expiry — not an independently re-sampled `now_epoch() +
    /// TTL` — so the mint-driven sweep can never free capacity while the grant is still executable
    /// (a re-sampled grant expiry would be strictly later than the mint's, opening a window where the
    /// sweep releases a live grant's debit and a new grant consumes the freed capacity).
    pub(super) fn grant_expiry_epoch(&self) -> i64 {
        self.decision_at_epoch + GRANT_TTL_SECS
    }
}

impl Broker {
    pub(super) fn retry_budget_substitution(
        &self,
        lineage: RetryBudgetLineage<'_>,
        rules: &crate::sentence::RuleSet,
        provider: &str,
        action: &str,
        resource: &CanonicalResource,
    ) -> Result<RetryBudgetSubstitutionTicket> {
        let current = self.resolve_retry_aggregate(rules, provider, action, resource)?;

        // Capture one immutable prefix, then authenticate the complete chain before trusting any row
        // in it. The actor owns this connection, so no broker command can interleave an append.
        let prefix = self.audit.max_rowid()?;
        let rows = self.audit.verified_budget_ledger_rows(prefix)?;
        // Parse and exact-schema-validate the COMPLETE fixed-prefix population before inspecting a
        // grant id or returning unbudgeted. Malformed raw linkage can never hide as absence.
        let population = parse_retry_budget_population(&rows)?;
        let lineage_mints: Vec<_> = population
            .mints
            .iter()
            .filter(|mint| {
                lineage.grant_ids.contains(&mint.grant_id)
                    || lineage.request_ids.contains(&mint.request_id)
            })
            .collect();

        let Some(current) = current else {
            if lineage_mints.is_empty() {
                return Ok(RetryBudgetSubstitutionTicket {
                    parent_grant_id: lineage.eligible_parent_grant_id.to_string(),
                    parent_mint_event_id: None,
                });
            }
            return Err(retry_budget_error(
                "budgeted parent no longer resolves as unbudgeted",
            ));
        };

        if lineage_mints.len() != 1 {
            return Err(retry_budget_error(
                "effect lineage has duplicate or mismatched budget mints",
            ));
        }
        let parent_mint = *lineage_mints
            .first()
            .ok_or_else(|| retry_budget_error("aggregate parent has no budget mint"))?;
        if parent_mint.aggregate_id != current.resolved.aggregate_id
            || parent_mint.resolution_digest != current.resolved.resolution_digest
            || parent_mint.meter != current.resolved.meter
            || parent_mint.limit != current.resolved.limit
            || parent_mint.proof.window != current.resolved.window
            || parent_mint.debit_field != current.debit_field
            || parent_mint.debit != current.debit
            || parent_mint.grant_id != lineage.reservation_owner_id
            || parent_mint.request_id != lineage.reservation_owner_grant.request_id
            || lineage.reservation_owner_grant.expiry_epoch != Some(parent_mint.expires_at_epoch)
        {
            return Err(retry_budget_error(
                "parent budget mint does not match current authority",
            ));
        }

        // Reproduce the parent's original allow proof against exactly the ledger prefix it named.
        let parent_evidence = retry_ledger_evidence(
            &population,
            &current.resolved.aggregate_id,
            parent_mint.proof.evidence_through_rowid,
        );
        let original = budget::decide_aggregate(
            &current.resolved,
            FrozenDebit::Value(parent_mint.debit),
            &parent_evidence,
            parent_mint.decision_at_epoch,
            parent_mint.proof.evidence_through_rowid,
        );
        if !matches!(original, AggregateDecision::Allow(ref proof) if proof == &parent_mint.proof) {
            return Err(retry_budget_error(
                "parent budget mint proof is not reproducible",
            ));
        }

        // Validate the current aggregate ledger through the fixed prefix. Exceeded is coherent here:
        // this child adds no projected debit and reuses the already-counted parent reservation.
        let current_evidence =
            retry_ledger_evidence(&population, &current.resolved.aggregate_id, prefix);
        match budget::decide_aggregate(
            &current.resolved,
            FrozenDebit::Value(current.debit),
            &current_evidence,
            current.decision_at_epoch,
            prefix,
        ) {
            AggregateDecision::Allow(_) | AggregateDecision::DenyExceeded(_) => {}
            AggregateDecision::DenyInvalid(_) => {
                return Err(retry_budget_error("current budget proof is invalid"));
            }
        }

        let parent_event_count = current_evidence
            .iter()
            .filter(|event| event.event_id == parent_mint.event_id)
            .count();
        if parent_event_count != 1 {
            return Err(retry_budget_error(
                "parent budget mint is absent from the current proof",
            ));
        }
        if population
            .releases
            .iter()
            .any(|release| release.mint_event_id == parent_mint.event_id)
        {
            return Err(retry_budget_error("parent budget mint was released"));
        }

        Ok(RetryBudgetSubstitutionTicket {
            parent_grant_id: lineage.eligible_parent_grant_id.to_string(),
            parent_mint_event_id: Some(parent_mint.event_id.clone()),
        })
    }

    fn resolve_retry_aggregate(
        &self,
        rules: &crate::sentence::RuleSet,
        provider: &str,
        action: &str,
        resource: &CanonicalResource,
    ) -> Result<Option<RetryAggregate>> {
        let rule_idx = match self.evaluate_sentence(rules, provider, action, resource) {
            crate::sentence::Decision::Allow { rule_idx } => rule_idx,
            _ => return Err(retry_budget_error("retry typed decision is not allow")),
        };
        let rule = &rules.rules[rule_idx];
        let Some(aggregate) = &rule.aggregate else {
            return Ok(None);
        };
        let (meter, debit_field) = budget::resolve_meter(aggregate)
            .ok_or_else(|| retry_budget_error("retry aggregate is unresolved"))?;
        let members =
            crate::sentence::selector_members(&rule.selector, &crate::sets::VendoredSetResolver)
                .ok_or_else(|| retry_budget_error("retry selector members are unresolved"))?;
        let member_semantics: Vec<_> = members
            .iter()
            .map(|(member_provider, member_action)| {
                self.member_semantics(
                    meter,
                    debit_field.as_deref(),
                    member_provider,
                    member_action,
                )
            })
            .collect();
        let contract = self
            .providers
            .get(provider)
            .and_then(|registered| registered.action_contract(action));
        let debit = match freeze_debit(meter, debit_field.as_deref(), resource, contract) {
            FrozenDebit::Value(value) if value > 0 => value,
            _ => return Err(retry_budget_error("retry debit is invalid")),
        };
        if meter == AggregateMeter::Rate && debit != 1 {
            return Err(retry_budget_error("retry rate debit is invalid"));
        }
        Ok(Some(RetryAggregate {
            resolved: ResolvedAggregate {
                meter,
                limit: aggregate.limit,
                window: aggregate.window,
                aggregate_id: budget::aggregate_id(rule),
                resolution_digest: budget::resolution_digest(
                    debit_field.as_deref(),
                    &member_semantics,
                ),
            },
            debit_field,
            debit,
            decision_at_epoch: self.now_epoch(),
        }))
    }

    pub(super) fn record_money_retry_link(
        &self,
        session: &str,
        child_grant_id: &str,
        effect_id: &str,
        authority_fingerprint: &str,
        ticket: &RetryBudgetSubstitutionTicket,
        secrets: &[String],
    ) -> Result<()> {
        let parent_budget = if ticket.parent_mint_event_id().is_some() {
            "aggregate"
        } else {
            "unbudgeted"
        };
        self.audit.record_durable(NewEvent {
            session_id: Some(session),
            event_type: "money_retry_linked",
            severity: "info",
            summary: "money retry linked to prior effect",
            data: json!({
                "parent_grant_id": ticket.parent_grant_id,
                "child_grant_id": child_grant_id,
                "effect_id": effect_id,
                "parent_budget": parent_budget,
                "parent_mint_event_id": ticket.parent_mint_event_id,
                "authority_fingerprint": authority_fingerprint,
            }),
            secrets,
        })?;
        Ok(())
    }

    /// The budget/rate admission gate. Returns [`BudgetGate::NoAggregate`] for a plain winner.
    pub(super) fn budget_gate(
        &self,
        rules: &crate::sentence::RuleSet,
        provider: &str,
        action: &str,
        resource: &CanonicalResource,
        secrets: &[String],
        session: &str,
    ) -> Result<BudgetGate> {
        // Re-derive the TYPED sentence decision from the SAME total `evaluate()` that produced the
        // broker Allow — deterministic, so the winning `rule_idx` is identical by construction. This is
        // NOT an independent re-scan: it meters the exact rule the mint is admitting.
        let rule_idx = match self.evaluate_sentence(rules, provider, action, resource) {
            crate::sentence::Decision::Allow { rule_idx } => rule_idx,
            // The gate only runs when the broker decision was Allow; a non-Allow typed result is a
            // divergence — fail closed (never mint).
            _ => {
                self.record_budget_gate_error(session, None, "typed_decision_not_allow", secrets)?;
                return Ok(BudgetGate::Invalid);
            }
        };
        let rule = &rules.rules[rule_idx];
        let Some(aggregate) = &rule.aggregate else {
            return Ok(BudgetGate::NoAggregate);
        };

        // Resolve the meter + summed field. The fieldless `budget` shorthand needs corpus
        // validation (not in this tree) to infer its summed field — fail closed until then.
        let Some((meter, summed_field)) = budget::resolve_meter(aggregate) else {
            self.record_budget_gate_error(session, None, "unresolved_summed_field", secrets)?;
            return Ok(BudgetGate::Invalid);
        };
        // The ordered member-eligibility set for the resolution digest.
        let Some(members) =
            crate::sentence::selector_members(&rule.selector, &crate::sets::VendoredSetResolver)
        else {
            self.record_budget_gate_error(session, None, "unresolved_selector_members", secrets)?;
            return Ok(BudgetGate::Invalid);
        };

        let aggregate_id = budget::aggregate_id(rule);
        // Fold each eligible member's meter-relevant contract semantics (field decl +
        // descriptor/template identity + eligibility) into the resolution digest, so a silent contract
        // revision (a newly-eligible member field or a unit change on the same-named int) changes the
        // digest and trips `AmbiguousResolution` instead of silently summing old + new mints. `members`
        // is already sorted+deduped by `(provider, action)`.
        let member_semantics: Vec<budget::MemberSemantics> = members
            .iter()
            .map(|(p, a)| self.member_semantics(meter, summed_field.as_deref(), p, a))
            .collect();
        let resolution_digest =
            budget::resolution_digest(summed_field.as_deref(), &member_semantics);
        let contract = self
            .providers
            .get(provider)
            .and_then(|p| p.action_contract(action));
        let debit = freeze_debit(meter, summed_field.as_deref(), resource, contract);

        // Capture ONE decision_at_epoch, then load the bounded ledger evidence. A read
        // failure BEFORE the pure fn is fail-closed.
        let decision_at_epoch = self.now_epoch();
        let (evidence, prefix_rowid) = match self.load_evidence(&aggregate_id) {
            Ok(v) => v,
            Err(_) => {
                self.record_budget_gate_error(
                    session,
                    Some(&aggregate_id),
                    "evidence_load_failed",
                    secrets,
                )?;
                return Ok(BudgetGate::Invalid);
            }
        };

        let resolved = ResolvedAggregate {
            meter,
            limit: aggregate.limit,
            window: aggregate.window,
            aggregate_id: aggregate_id.clone(),
            resolution_digest: resolution_digest.clone(),
        };
        match budget::decide_aggregate(&resolved, debit, &evidence, decision_at_epoch, prefix_rowid)
        {
            AggregateDecision::Allow(proof) => Ok(BudgetGate::Admit(Box::new(AdmitTicket {
                aggregate_id,
                resolution_digest,
                kind_str: meter_str(meter),
                debit_field: summed_field,
                limit: aggregate.limit,
                window: aggregate.window,
                decision_at_epoch,
                proof,
            }))),
            AggregateDecision::DenyExceeded(proof) => {
                self.record_budget_denied(
                    session,
                    &aggregate_id,
                    &resolution_digest,
                    meter_str(meter),
                    summed_field.as_deref(),
                    &proof,
                    secrets,
                )?;
                Ok(BudgetGate::Exceeded {
                    window: aggregate.window,
                })
            }
            AggregateDecision::DenyInvalid(fault) => {
                self.record_budget_gate_error(
                    session,
                    Some(&aggregate_id),
                    fault_str(fault),
                    secrets,
                )?;
                Ok(BudgetGate::Invalid)
            }
        }
    }

    /// One member's meter-relevant contract semantics for the `resolution_digest`, resolved
    /// against this broker's own contract / descriptor / template stores. `field_decl` is the summed
    /// field's `type|required|class|binding` fingerprint (budget only); `eligible` mirrors the exact
    /// shape `freeze_debit` demands (a member that can actually debit); descriptor/template identity
    /// catches a same-named contract/unit revision.
    fn member_semantics(
        &self,
        meter: AggregateMeter,
        summed_field: Option<&str>,
        provider: &str,
        action: &str,
    ) -> budget::MemberSemantics {
        let contract = self
            .providers
            .get(provider)
            .and_then(|p| p.action_contract(action));
        let (eligible, field_decl) = match (meter, summed_field, contract) {
            (AggregateMeter::Rate, _, _) => (true, None),
            (AggregateMeter::Budget, Some(field), Some(c)) => match c.field_decl(field) {
                Some(decl) => {
                    let eligible = decl.budget_eligible();
                    let fp = format!(
                        "{:?}|{}|{:?}|{:?}",
                        decl.ty, decl.required, decl.class, decl.binding
                    );
                    (eligible, Some(fp))
                }
                None => (false, None),
            },
            (AggregateMeter::Budget, _, _) => (false, None),
        };
        budget::MemberSemantics {
            provider: provider.to_string(),
            action: action.to_string(),
            eligible,
            field_decl,
            descriptor_hash: self.descriptor_hash(provider).map(str::to_string),
            template_hash: self.templates.content_hash(provider, action),
        }
    }

    /// Load the bounded ledger evidence for one aggregate: capture the current max rowid as the proof
    /// prefix, then read every `budget_mint`/`budget_release` for this aggregate at `rowid <= prefix`.
    /// A malformed OWN event (we author these; an agent cannot write the audit log) is a hard error —
    /// fail closed. The window filter + SUM are the pure `decide_aggregate`.
    pub(super) fn load_evidence(
        &self,
        aggregate_id: &str,
    ) -> Result<(Vec<AggregateLedgerEvent>, i64)> {
        let prefix = self.audit.max_rowid()?;
        let rows = self.audit.budget_ledger_events(aggregate_id, prefix)?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let malformed = || {
                Error::Integrity(format!(
                    "budget ledger event {} ({}) is malformed",
                    row.event_id, row.event_type
                ))
            };
            let kind = match row.event_type.as_str() {
                "budget_mint" => LedgerKind::Mint {
                    grant_id: row
                        .data
                        .get("grant_id")
                        .and_then(Value::as_str)
                        .ok_or_else(malformed)?
                        .to_string(),
                    debit: row
                        .data
                        .get("debit")
                        .and_then(Value::as_i64)
                        .ok_or_else(malformed)?,
                    resolution_digest: row
                        .data
                        .get("resolution_digest")
                        .and_then(Value::as_str)
                        .ok_or_else(malformed)?
                        .to_string(),
                    ts_epoch: row
                        .data
                        .get("decision_at_epoch")
                        .and_then(Value::as_i64)
                        .ok_or_else(malformed)?,
                    // The mint's recorded TTL horizon, consumed by the reservation-lineage and
                    // expiry-sweep checks. An absent/non-integer field is a malformed own event.
                    expires_at_epoch: row
                        .data
                        .get("expires_at_epoch")
                        .and_then(Value::as_i64)
                        .ok_or_else(malformed)?,
                },
                "budget_release" => LedgerKind::Release {
                    mint_event_id: row
                        .data
                        .get("mint_event_id")
                        .and_then(Value::as_str)
                        .ok_or_else(malformed)?
                        .to_string(),
                    grant_id: row
                        .data
                        .get("grant_id")
                        .and_then(Value::as_str)
                        .ok_or_else(malformed)?
                        .to_string(),
                },
                _ => continue,
            };
            events.push(AggregateLedgerEvent {
                event_id: row.event_id,
                rowid: row.rowid,
                kind,
            });
        }
        Ok((events, prefix))
    }

    /// Append the durable `budget_mint` proof. Called from the mint handler with the grant id,
    /// BEFORE `insert_grant`, using the ticket's single `decision_at_epoch` as the event ts (so the
    /// fixed calendar bucket the next request sums over cannot drift).
    pub(super) fn record_budget_mint(
        &self,
        session: &str,
        grant_id: &str,
        request_id: &str,
        ticket: &AdmitTicket,
        secrets: &[String],
    ) -> Result<String> {
        let p = &ticket.proof;
        let data = json!({
            "aggregate_id": ticket.aggregate_id,
            "resolution_digest": ticket.resolution_digest,
            "grant_id": grant_id,
            "request_id": request_id,
            "kind": ticket.kind_str,
            "debit_field": ticket.debit_field,
            "debit": p.debit,
            "limit": ticket.limit,
            "window": window_str(ticket.window),
            "decision_at_epoch": ticket.decision_at_epoch,
            "expires_at_epoch": ticket.grant_expiry_epoch(),
            "evidence_through_rowid": p.evidence_through_rowid,
            "window_start": p.window_start,
            "window_end": p.window_end,
            "consumed_before": p.consumed_before,
            "live_mint_count": p.live_mint_count,
            "release_count": p.release_count,
            "projected": p.projected,
        });
        // The money event is appended with TRUE power-loss durability (fsync'd) BEFORE the
        // grant row is written — so power loss can never lose the mint while keeping the grant.
        self.audit.record_at_durable(
            ticket.decision_at_epoch,
            NewEvent {
                session_id: Some(session),
                event_type: "budget_mint",
                severity: "info",
                summary: &format!(
                    "{} debit {} admitted ({}/{} in {} window)",
                    ticket.kind_str,
                    p.debit,
                    p.projected,
                    ticket.limit,
                    window_str(ticket.window)
                ),
                data,
                secrets,
            },
        )
    }

    /// The operator receipt for a gate DENY-exceeded (no grant). Same proof fields as `budget_mint`
    /// minus grant id / expiry.
    #[allow(clippy::too_many_arguments)]
    fn record_budget_denied(
        &self,
        session: &str,
        aggregate_id: &str,
        resolution_digest: &str,
        kind_str: &str,
        debit_field: Option<&str>,
        proof: &WindowProof,
        secrets: &[String],
    ) -> Result<()> {
        let data = json!({
            "aggregate_id": aggregate_id,
            "resolution_digest": resolution_digest,
            "kind": kind_str,
            "debit_field": debit_field,
            "debit": proof.debit,
            "limit": proof.limit,
            "window": window_str(proof.window),
            "window_start": proof.window_start,
            "window_end": proof.window_end,
            "consumed_before": proof.consumed_before,
            "live_mint_count": proof.live_mint_count,
            "release_count": proof.release_count,
            "projected": proof.projected,
            "evidence_through_rowid": proof.evidence_through_rowid,
        });
        self.audit.record(NewEvent {
            session_id: Some(session),
            event_type: "budget_denied",
            severity: "medium",
            summary: &format!(
                "{kind_str} debit {} refused ({}/{} would exceed {} window)",
                proof.debit,
                proof.projected,
                proof.limit,
                window_str(proof.window)
            ),
            data,
            secrets,
        })?;
        Ok(())
    }

    /// Void a grant's OWN `budget_mint` by appending a `budget_release` tombstone — ONLY when the
    /// reserved value was authoritatively NOT spent. A release cancels exactly one mint (its own),
    /// never adds capacity, so it is not an overspend channel. No-op for a non-budget grant. Idempotent:
    /// a re-tried terminalize never double-tombstones (`budget_release_exists`). RELEASE-second: the
    /// caller has ALREADY terminalized the grant status (terminal-state-first) — a crash between the two
    /// merely holds capacity (fail-closed) until the expiry sweep re-appends the missing release.
    /// Every emitted cause is typed and shares one vocabulary with retry-ledger parsing.
    pub(super) fn release_budget_for_grant(
        &self,
        grant_id: &str,
        cause: BudgetReleaseCause,
    ) -> Result<()> {
        let Some((mint_event_id, aggregate_id)) = self.audit.budget_mint_ref_for_grant(grant_id)?
        else {
            return Ok(());
        };
        if self.audit.budget_release_exists(&mint_event_id)? {
            return Ok(());
        }
        self.audit.record(NewEvent {
            session_id: None,
            event_type: "budget_release",
            severity: "info",
            summary: &format!("budget debit released ({})", cause.as_str()),
            // No amount: a release tombstones its mint, never a signed negative.
            data: json!({
                "mint_event_id": mint_event_id,
                "aggregate_id": aggregate_id,
                "grant_id": grant_id,
                "cause": cause.as_str(),
            }),
            secrets: &self.vault.all_secrets()?,
        })?;
        Ok(())
    }

    /// The budget backstop sweep: release every live `budget_mint` whose grant never crossed the
    /// invocation boundary and whose TTL has lapsed — crash-orphan mints (grant row absent) AND
    /// unclaimed budget grants the `requested`-only lease sweep does not cover (a budget grant mints
    /// `approved`). Idempotent and best-effort. Returns the count released. Window rollover self-heals
    /// anything this misses; this is the belt that frees capacity promptly. Public housekeeping API (a
    /// daemon tick may call it); NOT boot reconciliation — boot needs none (there is no counter).
    pub fn sweep_expired_budget_mints(&self) -> usize {
        let now = self.now_epoch();
        let mints = match self
            .audit
            .expired_unreleased_budget_mints(now, GRANT_TTL_SECS)
        {
            Ok(m) => m,
            Err(_) => return 0,
        };
        let mut released = 0;
        for (_mint_event_id, _aggregate_id, grant_id, mint_expires) in mints {
            // Distinguish a PROVEN-absent grant (crash-orphan: mint durable, grant row
            // never inserted ⇒ never invoked ⇒ release) from an AMBIGUOUS read fault (a transient
            // SQL/decode fault, or a present row that fails integrity, or a present row past the
            // invocation boundary). On any ambiguity we RETAIN. For a PRESENT grant the mint's validated
            // expiry must equal the grant's HMAC-covered expiry AND the grant must have actually expired
            // — so a mint tampered to expire early can never free a still-executable grant's capacity.
            let releasable = self
                .budget_grant_releasable(&grant_id, mint_expires, now)
                .unwrap_or(false);
            if releasable
                && self
                    .release_budget_for_grant(&grant_id, BudgetReleaseCause::ExpiredUnclaimed)
                    .is_ok()
            {
                released += 1;
            }
        }
        released
    }

    /// Whether an expired budget grant's debit may be released. `Ok(true)`
    /// ONLY for:
    /// - a PROVEN-absent grant (definite empty query result — a crash-orphan mint, never inserted); or
    /// - a present, integrity-valid `Requested`/`Approved` grant whose HMAC-covered expiry EQUALS the
    ///   mint's validated `expires_at_epoch` and has actually lapsed (`now > expiry`); or
    /// - a present, integrity-valid `Expired` grant that was NEVER CLAIMED (no lease stamps — the
    ///   ordinary unclaimed-expiry crash window) with the same mint/grant expiry match; or
    /// - a terminal (`Executed`/`Expired`-with-lease) grant whose durable `mutation_invoked:false` fact
    ///   proves pre-invocation termination.
    ///
    /// Any SQL/decode fault, failed integrity, an abandoned `Executing`-turned-`Expired` lease with no
    /// pre-invocation fact, or a mint/grant expiry mismatch yields `Ok(false)`/`Err` — the caller
    /// RETAINS the debit (fail closed; never release on an ambiguous read or an unproven expiry).
    fn budget_grant_releasable(&self, grant_id: &str, mint_expires: i64, now: i64) -> Result<bool> {
        // A DEFINITE empty result is proven absence; a query fault propagates as `Err` (retain).
        let exists: Option<i64> = self
            .state
            .query_row(
                "SELECT 1 FROM grants WHERE id=?1",
                rusqlite::params![grant_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(_) = exists else {
            return Ok(true); // crash-orphan: proven absent.
        };
        // Present: a read fault propagates (retain); integrity is re-checked before trusting the row's
        // status/expiry (a tampered/downgraded row is never released on).
        let g = self.load_grant(grant_id)?;
        self.assert_grant_integrity(grant_id, &g)?;
        // The mint's validated expiry must equal the grant's HMAC-covered expiry, and that
        // expiry must have actually lapsed. A mint recording an early `expires_at_epoch` while its grant
        // is signed through a later expiry can NEVER free capacity a still-executable grant holds.
        let expiry_proven = g.expiry_epoch == Some(mint_expires) && now > mint_expires;
        match g.status {
            // Never invoked — release ONLY with a proven, lapsed HMAC expiry.
            GrantStatus::Requested | GrantStatus::Approved => Ok(expiry_proven),
            GrantStatus::Expired => {
                // An ORDINARY unclaimed-approved grant flipped to Expired whose `budget_release`
                // was crash-interrupted has NO `mutation_invoked:false` fact. Absent lease stamps prove it
                // was never claimed (never invoked) — recover it with the same proven-expiry gate. An
                // abandoned `Executing` lease also becomes Expired but CARRIES lease stamps (it may have
                // crossed the effect boundary): fall through to the pre-invocation-fact check, KEEP otherwise.
                if g.lease_opened_at.is_none() && g.lease_deadline.is_none() {
                    return Ok(expiry_proven);
                }
                Ok(self.audit.grant_terminated_before_invocation(grant_id)?)
            }
            // A terminal grant whose durable terminal record proves pre-invocation termination.
            _ => Ok(self.audit.grant_terminated_before_invocation(grant_id)?),
        }
    }

    /// Operator-only: the gate saw malformed/ambiguous evidence or could not freeze the debit. The
    /// agent gets a GENERIC value-free deny (never `BudgetExceeded`, which would imply a coherent
    /// balance). `fault` is a fixed, number-free classification string.
    fn record_budget_gate_error(
        &self,
        session: &str,
        aggregate_id: Option<&str>,
        fault: &str,
        secrets: &[String],
    ) -> Result<()> {
        self.audit.record(NewEvent {
            session_id: Some(session),
            event_type: "budget_gate_error",
            severity: "high",
            summary: &format!("budget gate refused: {fault}"),
            data: json!({ "aggregate_id": aggregate_id, "fault": fault }),
            secrets,
        })?;
        Ok(())
    }
}

struct ParsedBudgetRelease {
    event_id: String,
    rowid: i64,
    mint_event_id: String,
    aggregate_id: String,
    grant_id: String,
}

fn retry_budget_error(message: &str) -> Error {
    Error::Integrity(format!("retry budget substitution failed: {message}"))
}

fn exact_object<'a>(
    value: &'a Value,
    expected_keys: &[&str],
    event_type: &str,
) -> Result<&'a serde_json::Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| retry_budget_error(&format!("{event_type} data is not an object")))?;
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected_keys.iter().copied().collect();
    if actual != expected {
        return Err(retry_budget_error(&format!(
            "{event_type} does not have the exact schema"
        )));
    }
    Ok(object)
}

fn object_str<'a>(object: &'a serde_json::Map<String, Value>, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| retry_budget_error(&format!("budget event has invalid {field}")))
}

fn object_i64(object: &serde_json::Map<String, Value>, field: &str) -> Result<i64> {
    object
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| retry_budget_error(&format!("budget event has invalid {field}")))
}

fn object_u64(object: &serde_json::Map<String, Value>, field: &str) -> Result<u64> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| retry_budget_error(&format!("budget event has invalid {field}")))
}

fn parse_budget_mint(row: &crate::audit::BudgetLedgerRow) -> Result<ParsedBudgetMint> {
    const KEYS: &[&str] = &[
        "aggregate_id",
        "resolution_digest",
        "grant_id",
        "request_id",
        "kind",
        "debit_field",
        "debit",
        "limit",
        "window",
        "decision_at_epoch",
        "expires_at_epoch",
        "evidence_through_rowid",
        "window_start",
        "window_end",
        "consumed_before",
        "live_mint_count",
        "release_count",
        "projected",
    ];
    if row.event_type != "budget_mint" {
        return Err(retry_budget_error("expected a budget_mint"));
    }
    let object = exact_object(&row.data, KEYS, "budget_mint")?;
    let aggregate_id = object_str(object, "aggregate_id")?.to_string();
    let resolution_digest = object_str(object, "resolution_digest")?.to_string();
    if !budget::is_canonical_aggregate_id(&aggregate_id)
        || !budget::is_canonical_aggregate_id(&resolution_digest)
    {
        return Err(retry_budget_error("budget_mint has a malformed digest"));
    }
    let meter = match object_str(object, "kind")? {
        "budget" => AggregateMeter::Budget,
        "rate" => AggregateMeter::Rate,
        _ => return Err(retry_budget_error("budget_mint has an invalid kind")),
    };
    let debit_field = match object.get("debit_field") {
        Some(Value::Null) => None,
        Some(Value::String(field)) if !field.is_empty() => Some(field.clone()),
        _ => return Err(retry_budget_error("budget_mint has an invalid debit_field")),
    };
    let debit = object_i64(object, "debit")?;
    let limit = object_i64(object, "limit")?;
    if limit <= 0
        || debit <= 0
        || (meter == AggregateMeter::Budget && (debit_field.is_none() || debit > limit))
        || (meter == AggregateMeter::Rate && (debit_field.is_some() || debit != 1))
    {
        return Err(retry_budget_error(
            "budget_mint has an invalid debit schema",
        ));
    }
    let window = match object_str(object, "window")? {
        "hour" => Window::Hour,
        "day" => Window::Day,
        _ => return Err(retry_budget_error("budget_mint has an invalid window")),
    };
    let decision_at_epoch = object_i64(object, "decision_at_epoch")?;
    let expires_at_epoch = object_i64(object, "expires_at_epoch")?;
    let evidence_through_rowid = object_i64(object, "evidence_through_rowid")?;
    let consumed_before = object_i64(object, "consumed_before")?;
    let projected = object_i64(object, "projected")?;
    if evidence_through_rowid < 0
        || evidence_through_rowid >= row.rowid
        || consumed_before < 0
        || consumed_before.checked_add(debit) != Some(projected)
        || projected > limit
    {
        return Err(retry_budget_error(
            "budget_mint has invalid proof arithmetic",
        ));
    }
    let (expected_start, expected_end) = budget::window_bounds(window, decision_at_epoch)
        .ok_or_else(|| retry_budget_error("budget_mint window overflows"))?;
    let proof = WindowProof {
        window,
        window_start: object_i64(object, "window_start")?,
        window_end: object_i64(object, "window_end")?,
        consumed_before,
        debit,
        limit,
        projected,
        live_mint_count: object_u64(object, "live_mint_count")?,
        release_count: object_u64(object, "release_count")?,
        evidence_through_rowid,
    };
    if proof.window_start != expected_start || proof.window_end != expected_end {
        return Err(retry_budget_error("budget_mint has invalid window bounds"));
    }
    Ok(ParsedBudgetMint {
        event_id: row.event_id.clone(),
        rowid: row.rowid,
        aggregate_id,
        resolution_digest,
        grant_id: object_str(object, "grant_id")?.to_string(),
        request_id: object_str(object, "request_id")?.to_string(),
        meter,
        debit_field,
        debit,
        limit,
        decision_at_epoch,
        expires_at_epoch,
        proof,
    })
}

fn parse_budget_release(row: &crate::audit::BudgetLedgerRow) -> Result<ParsedBudgetRelease> {
    const KEYS: &[&str] = &["mint_event_id", "aggregate_id", "grant_id", "cause"];
    if row.event_type != "budget_release" {
        return Err(retry_budget_error("expected a budget_release"));
    }
    let object = exact_object(&row.data, KEYS, "budget_release")?;
    let aggregate_id = object_str(object, "aggregate_id")?.to_string();
    if !budget::is_canonical_aggregate_id(&aggregate_id) {
        return Err(retry_budget_error(
            "budget_release has a malformed aggregate id",
        ));
    }
    if BudgetReleaseCause::parse(object_str(object, "cause")?).is_none() {
        return Err(retry_budget_error("budget_release has an invalid cause"));
    }
    Ok(ParsedBudgetRelease {
        event_id: row.event_id.clone(),
        rowid: row.rowid,
        mint_event_id: object_str(object, "mint_event_id")?.to_string(),
        aggregate_id,
        grant_id: object_str(object, "grant_id")?.to_string(),
    })
}

fn parse_retry_budget_population(
    rows: &[crate::audit::BudgetLedgerRow],
) -> Result<ParsedBudgetPopulation> {
    let mut mints = Vec::new();
    let mut releases = Vec::new();
    for row in rows {
        match row.event_type.as_str() {
            "budget_mint" => mints.push(parse_budget_mint(row)?),
            "budget_release" => releases.push(parse_budget_release(row)?),
            _ => {
                return Err(retry_budget_error(
                    "budget snapshot contains an unknown event",
                ))
            }
        }
    }

    let mut mint_by_event = BTreeMap::new();
    let mut mint_by_grant = BTreeSet::new();
    for mint in &mints {
        if mint_by_event.insert(mint.event_id.as_str(), mint).is_some()
            || !mint_by_grant.insert(mint.grant_id.as_str())
        {
            return Err(retry_budget_error("duplicate budget mint linkage"));
        }
    }
    let mut released_mints = BTreeSet::new();
    for release in &releases {
        let mint = mint_by_event
            .get(release.mint_event_id.as_str())
            .ok_or_else(|| retry_budget_error("orphan budget release"))?;
        if release.aggregate_id != mint.aggregate_id || release.grant_id != mint.grant_id {
            return Err(retry_budget_error("budget release linkage mismatch"));
        }
        if !released_mints.insert(release.mint_event_id.as_str()) {
            return Err(retry_budget_error("duplicate budget release"));
        }
    }
    Ok(ParsedBudgetPopulation { mints, releases })
}

fn retry_ledger_evidence(
    population: &ParsedBudgetPopulation,
    aggregate_id: &str,
    through_rowid: i64,
) -> Vec<AggregateLedgerEvent> {
    let mut events = Vec::new();
    for mint in population
        .mints
        .iter()
        .filter(|mint| mint.rowid <= through_rowid)
    {
        if mint.aggregate_id != aggregate_id {
            continue;
        }
        events.push(AggregateLedgerEvent {
            event_id: mint.event_id.clone(),
            rowid: mint.rowid,
            kind: LedgerKind::Mint {
                grant_id: mint.grant_id.clone(),
                debit: mint.debit,
                resolution_digest: mint.resolution_digest.clone(),
                ts_epoch: mint.decision_at_epoch,
                expires_at_epoch: mint.expires_at_epoch,
            },
        });
    }
    for release in population
        .releases
        .iter()
        .filter(|release| release.rowid <= through_rowid)
    {
        if release.aggregate_id != aggregate_id {
            continue;
        }
        events.push(AggregateLedgerEvent {
            event_id: release.event_id.clone(),
            rowid: release.rowid,
            kind: LedgerKind::Release {
                mint_event_id: release.mint_event_id.clone(),
                grant_id: release.grant_id.clone(),
            },
        });
    }
    events.sort_by_key(|event| event.rowid);
    events
}

/// Freeze the debit from the already-canonical resource. `rate` debits the literal `1`. A budget
/// debit is the value of a REQUIRED + `Bounded` + integer + `SideEffect` field; anything else — absent,
/// non-integer, non-positive, or wrong class/binding — is `Invalid` (never debit zero, never admit).
fn freeze_debit(
    meter: AggregateMeter,
    summed_field: Option<&str>,
    resource: &CanonicalResource,
    contract: Option<&ActionContract>,
) -> FrozenDebit {
    match meter {
        AggregateMeter::Rate => FrozenDebit::Value(1),
        AggregateMeter::Budget => {
            let (Some(field), Some(contract)) = (summed_field, contract) else {
                return FrozenDebit::Invalid;
            };
            let Some(decl) = contract.field_decl(field) else {
                return FrozenDebit::Invalid;
            };
            if !decl.budget_eligible() {
                return FrozenDebit::Invalid;
            }
            match resource.get_i64(field) {
                Some(v) if v > 0 => FrozenDebit::Value(v),
                _ => FrozenDebit::Invalid,
            }
        }
    }
}

fn meter_str(meter: AggregateMeter) -> &'static str {
    match meter {
        AggregateMeter::Budget => "budget",
        AggregateMeter::Rate => "rate",
    }
}

pub(super) fn window_str(window: Window) -> &'static str {
    match window {
        Window::Hour => "hour",
        Window::Day => "day",
    }
}

/// The agent-facing window classification (anti-oracle) — the ONLY budget signal that crosses the
/// agent boundary.
pub(super) fn budget_window(window: Window) -> crate::types::BudgetWindow {
    match window {
        Window::Hour => crate::types::BudgetWindow::Hour,
        Window::Day => crate::types::BudgetWindow::Day,
    }
}

fn fault_str(fault: Fault) -> &'static str {
    match fault {
        Fault::DebitInvalid => "debit_invalid",
        Fault::RateDebitNotOne => "rate_debit_not_one",
        Fault::Overflow => "arithmetic_overflow",
        Fault::WindowOverflow => "window_overflow",
        Fault::OrphanRelease => "orphan_release",
        Fault::DuplicateRelease => "duplicate_release",
        Fault::ReleaseGrantMismatch => "release_grant_mismatch",
        Fault::AmbiguousResolution => "ambiguous_resolution",
        Fault::HistoricalMintInvalid => "historical_mint_invalid",
    }
}

#[cfg(test)]
mod budget_form_tests {
    use super::*;
    use cermet_lang::contract::{AllowBinding, FieldClass, FieldDecl, ScalarKind};
    use std::collections::BTreeMap;

    /// The catalog prints `budget` on a field to say a `budget … per <window>` aggregate
    /// may SUM it. That is a claim about `freeze_debit`, checked here against `freeze_debit` itself
    /// over every declaration shape — so the printed index cannot promise a meter the broker would
    /// then refuse as `debit_invalid`, and cannot hide one it would accept.
    #[test]
    fn the_budget_form_matches_what_freeze_debit_will_meter() {
        let resource = CanonicalResource::from_map(BTreeMap::from([(
            "f".to_string(),
            cermet_lang::contract::Scalar::Int(5),
        )]));
        for ty in [ScalarKind::Str, ScalarKind::Int, ScalarKind::Bool] {
            for required in [true, false] {
                for class in [
                    FieldClass::Identity,
                    FieldClass::SideEffect,
                    FieldClass::FreePayload,
                    FieldClass::ReadFilter,
                ] {
                    for binding in [
                        AllowBinding::Unbound,
                        AllowBinding::ExactResourcePin,
                        AllowBinding::ExactOrPatternList("names"),
                        AllowBinding::Bounded,
                    ] {
                        let decl = FieldDecl {
                            name: "f",
                            ty,
                            required,
                            class,
                            binding,
                        };
                        let contract: &'static ActionContract =
                            Box::leak(Box::new(ActionContract {
                                provider: "p",
                                action: "a",
                                schema: Box::leak(Box::new([decl])),
                                consumes: &["f"],
                                execution_targets: &[],
                                relations: &[],
                                open: false,
                            }));
                        let metered = matches!(
                            freeze_debit(
                                AggregateMeter::Budget,
                                Some("f"),
                                &resource,
                                Some(contract)
                            ),
                            FrozenDebit::Value(_)
                        );
                        assert_eq!(
                            decl.admissible_forms(true).contains(&"budget"),
                            metered,
                            "the catalog index and freeze_debit disagree about {decl:?}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod retry_release_cause_tests {
    use super::*;

    #[test]
    fn moneypath_retry_parser_accepts_every_budget_release_emitter_cause() {
        let emitter_causes: Vec<_> = BudgetReleaseCause::ALL
            .iter()
            .copied()
            .map(BudgetReleaseCause::as_str)
            .collect();
        let mut parser_causes = Vec::new();
        for cause in &emitter_causes {
            let row = crate::audit::BudgetLedgerRow {
                rowid: 2,
                event_id: "evt_release".into(),
                event_type: "budget_release".into(),
                data: json!({
                    "mint_event_id": "evt_mint",
                    "aggregate_id": "a".repeat(64),
                    "grant_id": "grant_1",
                    "cause": cause,
                }),
            };
            if parse_budget_release(&row).is_ok() {
                parser_causes.push(*cause);
            }
        }
        assert_eq!(parser_causes, emitter_causes);
        assert!(BudgetReleaseCause::parse("unknown_release_cause").is_none());
    }
}
