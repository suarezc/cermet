//! Ledger-derived budget/rate admission.
//!
//! The authority is a SUM over the broker's own append-only audit log — `budget_mint` events minus
//! their `budget_release` tombstones — within the sentence's fixed calendar window, serialized at the
//! single broker thread's mint seam. There is NO mutable counter (nothing to reconcile at boot); every
//! aggregate figure is a rebuildable view over the immutable event stream.
//!
//! This module is PURE: [`decide_aggregate`] performs no I/O and reads no clock (the single
//! `now_epoch` is captured by the caller). The impure evidence load + ledger append + gate wiring live
//! in `broker::budget`. Fail-closed always: a complete proof may produce [`AggregateDecision::Allow`]
//! or [`AggregateDecision::DenyExceeded`]; any invalid/ambiguous/overflowing evidence is
//! [`AggregateDecision::DenyInvalid`] (the caller turns it into an operator-only `budget_gate_error`
//! plus a generic, value-free agent deny — never a coherent `BudgetExceeded`).

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::sentence::{Aggregate, AggregateKind, Window};

/// Domain tag for the aggregate identity digest (matched-rule digest).
/// Domain tag for the resolution digest (summed field + ordered member eligibility).
const RESOLUTION_DOMAIN: &[u8] = b"cermet-resolution-v1\0";

/// Which meter a resolved aggregate applies: `Budget` sums a frozen integer field; `Rate` sums the
/// literal `1` per admitted request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateMeter {
    Budget,
    Rate,
}

/// The debit frozen from the request's already-canonical resource: the frozen field the
/// grant HMAC covers, never recomputed at execute. `Invalid` folds every fail-closed freeze fault
/// (absent / non-integer / non-positive / non-required-bounded field) into one value-free variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrozenDebit {
    Value(i64),
    Invalid,
}

/// A matched aggregate rule resolved for metering: its meter, authored cap, window, and the two
/// domain-separated digests that bound the ledger view (`aggregate_id` = the matched rule alone;
/// `resolution_digest` = the resolved summed field + ordered member eligibility).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAggregate {
    pub meter: AggregateMeter,
    pub limit: i64,
    pub window: Window,
    pub aggregate_id: String,
    pub resolution_digest: String,
}

/// One immutable ledger event relevant to an aggregate, read from the audit log (rowid-ordered).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateLedgerEvent {
    pub event_id: String,
    pub rowid: i64,
    pub kind: LedgerKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerKind {
    /// A budget/rate-bearing grant was minted. `ts_epoch` is the mint's `decision_at_epoch` (its
    /// window bucket is fixed by THIS value — a release inherits it). `expires_at_epoch` is the
    /// mint's recorded TTL horizon, validated against `ts_epoch + TTL` before the count trusts it.
    Mint {
        grant_id: String,
        debit: i64,
        resolution_digest: String,
        ts_epoch: i64,
        expires_at_epoch: i64,
    },
    /// A minted-but-unconsumed debit was voided. Tombstones exactly one mint by `mint_event_id`
    /// (never a signed negative amount).
    Release {
        mint_event_id: String,
        grant_id: String,
    },
}

/// The reproducible proof recorded on every allow (`budget_mint`) and deny (`budget_denied`) — replaying
/// the ledger up to `evidence_through_rowid`, selecting live mints in `[window_start, window_end)`,
/// reproduces `consumed_before` exactly. Never agent-facing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowProof {
    pub window: Window,
    pub window_start: i64,
    pub window_end: i64,
    pub consumed_before: i64,
    pub debit: i64,
    pub limit: i64,
    pub projected: i64,
    pub live_mint_count: u64,
    pub release_count: u64,
    pub evidence_through_rowid: i64,
}

/// Why a proof could not be completed. Operator-only (a `budget_gate_error`); the agent gets a generic
/// value-free deny, NEVER a `BudgetExceeded` (which would imply a coherent balance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The frozen debit field was absent / non-integer / non-positive / non-required-bounded.
    DebitInvalid,
    /// A `rate` aggregate whose debit was not exactly `1`.
    RateDebitNotOne,
    /// Checked arithmetic overflowed while folding consumed + debit.
    Overflow,
    /// The window bounds overflowed for this clock value.
    WindowOverflow,
    /// A release referenced a `mint_event_id` with no corresponding mint (over the bounded prefix).
    OrphanRelease,
    /// More than one release tombstoned the same mint.
    DuplicateRelease,
    /// A release's `grant_id` did not match its mint's.
    ReleaseGrantMismatch,
    /// An in-window mint carried a different `resolution_digest` — a contract revision silently
    /// changed what the budget meters. Deny; do not start a fresh bucket.
    AmbiguousResolution,
    /// A historical in-window mint carried a debit shape this aggregate can never have authored
    /// (a budget mint with `debit` outside `1..=limit`, or a rate mint with `debit != 1`) — malformed
    /// evidence that would undercount `consumed_before` and admit over-cap. Deny; never sum a mint we
    /// could not have minted.
    HistoricalMintInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregateDecision {
    Allow(WindowProof),
    DenyExceeded(WindowProof),
    DenyInvalid(Fault),
}

/// Fixed UTC calendar-bucket bounds `[start, end)` for `window` containing `now`. `None` on
/// overflow (fail closed). Inclusive lower, exclusive upper: a mint at exactly the boundary belongs
/// to the later bucket.
pub fn window_bounds(window: Window, now: i64) -> Option<(i64, i64)> {
    let period: i64 = match window {
        Window::Hour => 3600,
        Window::Day => 86400,
    };
    let start = now.div_euclid(period).checked_mul(period)?;
    let end = start.checked_add(period)?;
    Some((start, end))
}

/// Whether `id` is a canonical aggregate identifier — the exact shape [`aggregate_id`] emits: 64
/// lowercase hex characters (a SHA-256 via `crate::util::hex`). A `budget_mint`/`budget_release`
/// carrying an aggregate id outside this shape (`""`, wrong length, uppercase, non-hex) is malformed OWN
/// evidence — the loader hard-errors on it rather than reading it as a foreign (skippable) id.
pub fn is_canonical_aggregate_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The domain-separated digest of the canonical matched `Rule` ALONE — not the whole ruleset
/// fingerprint, so an unrelated rule edit does not reset a live budget.
pub use cermet_lang::sentence::aggregate_id;

/// One resolved set member's meter-relevant contract semantics, folded into the `resolution_digest`.
/// A silent contract revision that changes what the budget meters — a newly-eligible member
/// field, a unit change on the same-named int, a class/binding flip — changes this member's fingerprint
/// and therefore the digest, so old + new mints no longer sum silently (they trip `AmbiguousResolution`
/// instead of over-admitting). Built by the broker at the mint seam from its own contract/descriptor/
/// template resolvers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberSemantics {
    pub provider: String,
    pub action: String,
    /// Whether this member can debit under the aggregate: for `budget`, it declares the summed field
    /// with the required + bounded + int + side-effect shape `freeze_debit` demands; for `rate`, it is
    /// simply a resolved member. A member flipping eligible changes the digest.
    pub eligible: bool,
    /// The summed field's declaration fingerprint on this member's contract (`type|required|class|
    /// binding`), if the contract declares that field. `None` for `rate` or an undeclared field.
    pub field_decl: Option<String>,
    /// The loaded provider-descriptor identity — catches a contract/unit revision that keeps the field
    /// name and shape but changes the descriptor bytes.
    pub descriptor_hash: Option<String>,
    /// The ratified template identity for this action (a built-in action has none).
    pub template_hash: Option<String>,
}

/// The domain-separated digest of the resolved summed field + ordered set-member eligibility AND each
/// member's meter-relevant contract semantics. `summed_field = None` for `rate` (it
/// meters admissions, not a field). Members must be sorted+deduped by the caller (by `(provider,
/// action)`). Binding the per-member contract declaration + descriptor/template identity is what makes
/// the ambiguity guarantee cover a contract-SEMANTICS change, not merely a rule/field-NAME change.
pub fn resolution_digest(
    summed_field: Option<&str>,
    ordered_members: &[MemberSemantics],
) -> String {
    let mut h = Sha256::new();
    h.update(RESOLUTION_DOMAIN);
    match summed_field {
        Some(field) => {
            h.update(b"field\0");
            h.update((field.len() as u64).to_le_bytes());
            h.update(field.as_bytes());
        }
        None => h.update(b"rate\0"),
    }
    h.update((ordered_members.len() as u64).to_le_bytes());
    let fold_opt = |h: &mut Sha256, tag: &[u8], v: Option<&str>| {
        h.update(tag);
        match v {
            Some(s) => {
                h.update([1u8]);
                h.update((s.len() as u64).to_le_bytes());
                h.update(s.as_bytes());
            }
            None => h.update([0u8]),
        }
    };
    for m in ordered_members {
        h.update((m.provider.len() as u64).to_le_bytes());
        h.update(m.provider.as_bytes());
        h.update((m.action.len() as u64).to_le_bytes());
        h.update(m.action.as_bytes());
        h.update([m.eligible as u8]);
        fold_opt(&mut h, b"decl\0", m.field_decl.as_deref());
        fold_opt(&mut h, b"desc\0", m.descriptor_hash.as_deref());
        fold_opt(&mut h, b"tmpl\0", m.template_hash.as_deref());
    }
    crate::util::hex(&h.finalize())
}

/// The meter + summed field an [`Aggregate`] resolves to. `Budget { field: Some(f) }` sums `f`;
/// `Rate` sums `1`. `Budget { field: None }` (the fieldless shorthand) is UNRESOLVED here — its
/// summed field is inferred from set membership at corpus validation, which is not present in
/// this tree; the gate fails closed on it.
pub fn resolve_meter(aggregate: &Aggregate) -> Option<(AggregateMeter, Option<String>)> {
    match &aggregate.kind {
        AggregateKind::Budget { field: Some(f) } => Some((AggregateMeter::Budget, Some(f.clone()))),
        AggregateKind::Budget { field: None } => None,
        AggregateKind::Rate => Some((AggregateMeter::Rate, None)),
    }
}

/// The PURE budget/rate decision. No I/O, no clock — `now_epoch` and `evidence` are captured by
/// the caller at the serialized mint seam. Validates event shapes/refs/digests and folds counts +
/// totals with checked arithmetic. Only a complete proof produces `Allow`/`DenyExceeded`; anything
/// invalid is `DenyInvalid(fault)`.
pub fn decide_aggregate(
    agg: &ResolvedAggregate,
    debit: FrozenDebit,
    evidence: &[AggregateLedgerEvent],
    now_epoch: i64,
    evidence_through_rowid: i64,
) -> AggregateDecision {
    // 1. Freeze the debit. Rate debits the literal 1; a budget debit must be strictly positive.
    let debit = match debit {
        FrozenDebit::Invalid => return AggregateDecision::DenyInvalid(Fault::DebitInvalid),
        FrozenDebit::Value(d) if d <= 0 => {
            return AggregateDecision::DenyInvalid(Fault::DebitInvalid);
        }
        FrozenDebit::Value(d) => d,
    };
    if agg.meter == AggregateMeter::Rate && debit != 1 {
        return AggregateDecision::DenyInvalid(Fault::RateDebitNotOne);
    }

    // 2. Window bounds (overflow ⇒ fail closed).
    let Some((window_start, window_end)) = window_bounds(agg.window, now_epoch) else {
        return AggregateDecision::DenyInvalid(Fault::WindowOverflow);
    };

    // 4. Index each mint's grant id by event id (for orphan/mismatch detection over the bounded
    //    prefix). Debit/resolution/ts are read directly from `evidence` in the sum pass below.
    let mut mint_grant: HashMap<&str, &str> = HashMap::new();
    for ev in evidence {
        if let LedgerKind::Mint { grant_id, .. } = &ev.kind {
            mint_grant.insert(ev.event_id.as_str(), grant_id.as_str());
        }
    }

    // 4. Validate releases and collect tombstones. A release tombstones EXACTLY one mint by
    //    `mint_event_id`; an orphan / duplicate / grant-mismatched release is invalid evidence.
    let mut tombstoned: HashMap<&str, ()> = HashMap::new();
    let mut release_count = 0u64;
    for ev in evidence {
        if let LedgerKind::Release {
            mint_event_id,
            grant_id,
        } = &ev.kind
        {
            let Some(mint_grant_id) = mint_grant.get(mint_event_id.as_str()) else {
                return AggregateDecision::DenyInvalid(Fault::OrphanRelease);
            };
            if *mint_grant_id != grant_id.as_str() {
                return AggregateDecision::DenyInvalid(Fault::ReleaseGrantMismatch);
            }
            if tombstoned.insert(mint_event_id.as_str(), ()).is_some() {
                return AggregateDecision::DenyInvalid(Fault::DuplicateRelease);
            }
            release_count += 1;
        }
    }

    // 5. Sum live in-window mints with checked arithmetic; any in-window mint under a DIFFERENT
    //    resolution_digest makes the aggregate ambiguous (deny; do not start a fresh bucket).
    let mut consumed_before: i64 = 0;
    let mut live_mint_count = 0u64;
    for ev in evidence {
        let LedgerKind::Mint {
            debit: mint_debit,
            resolution_digest,
            ts_epoch,
            ..
        } = &ev.kind
        else {
            continue;
        };
        if *ts_epoch < window_start || *ts_epoch >= window_end {
            continue;
        }
        if resolution_digest.as_str() != agg.resolution_digest {
            return AggregateDecision::DenyInvalid(Fault::AmbiguousResolution);
        }
        // Validate every historical in-window mint's debit shape before trusting it —
        // this aggregate could only have authored a budget debit in `1..=limit` (the mint invariant
        // `consumed_before + debit <= limit` with `consumed_before >= 0` bounds a live debit by the cap)
        // or a rate debit of exactly `1`. A mint outside that shape is malformed evidence that would
        // undercount `consumed_before`; fail closed rather than sum it. Applied to EVERY in-window mint
        // (even a tombstoned one) — corrupt evidence is corrupt.
        match agg.meter {
            AggregateMeter::Budget if *mint_debit < 1 || *mint_debit > agg.limit => {
                return AggregateDecision::DenyInvalid(Fault::HistoricalMintInvalid);
            }
            AggregateMeter::Rate if *mint_debit != 1 => {
                return AggregateDecision::DenyInvalid(Fault::HistoricalMintInvalid);
            }
            _ => {}
        }
        if tombstoned.contains_key(ev.event_id.as_str()) {
            continue;
        }
        consumed_before = match consumed_before.checked_add(*mint_debit) {
            Some(v) => v,
            None => return AggregateDecision::DenyInvalid(Fault::Overflow),
        };
        live_mint_count += 1;
    }

    // 6. Compare with checked arithmetic. `total <= limit` admits; `> limit` is exceeded.
    let projected = match consumed_before.checked_add(debit) {
        Some(v) => v,
        None => return AggregateDecision::DenyInvalid(Fault::Overflow),
    };
    let proof = WindowProof {
        window: agg.window,
        window_start,
        window_end,
        consumed_before,
        debit,
        limit: agg.limit,
        projected,
        live_mint_count,
        release_count,
        evidence_through_rowid,
    };
    if projected <= agg.limit {
        AggregateDecision::Allow(proof)
    } else {
        AggregateDecision::DenyExceeded(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg(meter: AggregateMeter, limit: i64) -> ResolvedAggregate {
        ResolvedAggregate {
            meter,
            limit,
            window: Window::Day,
            aggregate_id: "A".into(),
            resolution_digest: "R".into(),
        }
    }

    // Test grant TTL, mirrors the broker's GRANT_TTL_SECS.
    const TTL: i64 = 600;

    fn mint(id: &str, rowid: i64, grant: &str, debit: i64, ts: i64) -> AggregateLedgerEvent {
        // A well-formed mint always carries `expires_at_epoch == ts + TTL`.
        mint_exp(id, rowid, grant, debit, ts, ts + TTL)
    }

    fn mint_exp(
        id: &str,
        rowid: i64,
        grant: &str,
        debit: i64,
        ts: i64,
        expires: i64,
    ) -> AggregateLedgerEvent {
        AggregateLedgerEvent {
            event_id: id.into(),
            rowid,
            kind: LedgerKind::Mint {
                grant_id: grant.into(),
                debit,
                resolution_digest: "R".into(),
                ts_epoch: ts,
                expires_at_epoch: expires,
            },
        }
    }

    fn release(id: &str, rowid: i64, mint_id: &str, grant: &str) -> AggregateLedgerEvent {
        AggregateLedgerEvent {
            event_id: id.into(),
            rowid,
            kind: LedgerKind::Release {
                mint_event_id: mint_id.into(),
                grant_id: grant.into(),
            },
        }
    }

    // now = 100_000 → Day bucket [86400, 172800).
    const NOW: i64 = 100_000;

    #[test]
    fn empty_ledger_admits_up_to_limit() {
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(60),
            &[],
            NOW,
            0,
        );
        match d {
            AggregateDecision::Allow(p) => {
                assert_eq!(p.consumed_before, 0);
                assert_eq!(p.projected, 60);
                assert_eq!(p.window_start, 86400);
                assert_eq!(p.window_end, 172800);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn boundary_total_equals_limit_admits() {
        let ev = [mint("m1", 1, "g1", 60, NOW)];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(40),
            &ev,
            NOW,
            1,
        );
        assert!(matches!(d, AggregateDecision::Allow(p) if p.projected == 100));
    }

    #[test]
    fn one_over_limit_denies_exceeded() {
        let ev = [mint("m1", 1, "g1", 60, NOW)];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(41),
            &ev,
            NOW,
            1,
        );
        assert!(matches!(d, AggregateDecision::DenyExceeded(p) if p.projected == 101));
    }

    #[test]
    fn released_mint_is_not_consumed() {
        let ev = [mint("m1", 1, "g1", 60, NOW), release("r1", 2, "m1", "g1")];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(60),
            &ev,
            NOW,
            2,
        );
        assert!(
            matches!(d, AggregateDecision::Allow(p) if p.consumed_before == 0 && p.release_count == 1)
        );
    }

    #[test]
    fn frozen_debit_invalid_denies_invalid() {
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Invalid,
            &[],
            NOW,
            0,
        );
        assert_eq!(d, AggregateDecision::DenyInvalid(Fault::DebitInvalid));
    }

    #[test]
    fn nonpositive_debit_denies_invalid() {
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(0),
            &[],
            NOW,
            0,
        );
        assert_eq!(d, AggregateDecision::DenyInvalid(Fault::DebitInvalid));
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(-5),
            &[],
            NOW,
            0,
        );
        assert_eq!(d, AggregateDecision::DenyInvalid(Fault::DebitInvalid));
    }

    #[test]
    fn rate_debit_must_be_one() {
        let d = decide_aggregate(
            &agg(AggregateMeter::Rate, 5),
            FrozenDebit::Value(2),
            &[],
            NOW,
            0,
        );
        assert_eq!(d, AggregateDecision::DenyInvalid(Fault::RateDebitNotOne));
        let ok = decide_aggregate(
            &agg(AggregateMeter::Rate, 5),
            FrozenDebit::Value(1),
            &[],
            NOW,
            0,
        );
        assert!(matches!(ok, AggregateDecision::Allow(_)));
    }

    #[test]
    fn overflow_folding_consumed_denies_invalid() {
        let ev = [mint("m1", 1, "g1", i64::MAX, NOW)];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, i64::MAX),
            FrozenDebit::Value(1),
            &ev,
            NOW,
            1,
        );
        assert_eq!(d, AggregateDecision::DenyInvalid(Fault::Overflow));
    }

    #[test]
    fn orphan_release_denies_invalid() {
        let ev = [release("r1", 1, "does_not_exist", "g1")];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(1),
            &ev,
            NOW,
            1,
        );
        assert_eq!(d, AggregateDecision::DenyInvalid(Fault::OrphanRelease));
    }

    #[test]
    fn duplicate_release_denies_invalid() {
        let ev = [
            mint("m1", 1, "g1", 10, NOW),
            release("r1", 2, "m1", "g1"),
            release("r2", 3, "m1", "g1"),
        ];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(1),
            &ev,
            NOW,
            3,
        );
        assert_eq!(d, AggregateDecision::DenyInvalid(Fault::DuplicateRelease));
    }

    #[test]
    fn release_grant_mismatch_denies_invalid() {
        let ev = [
            mint("m1", 1, "g1", 10, NOW),
            release("r1", 2, "m1", "OTHER"),
        ];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(1),
            &ev,
            NOW,
            2,
        );
        assert_eq!(
            d,
            AggregateDecision::DenyInvalid(Fault::ReleaseGrantMismatch)
        );
    }

    #[test]
    fn different_resolution_digest_in_window_denies_ambiguous() {
        let mut ev = mint("m1", 1, "g1", 10, NOW);
        if let LedgerKind::Mint {
            resolution_digest, ..
        } = &mut ev.kind
        {
            *resolution_digest = "DIFFERENT".into();
        }
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(1),
            &[ev],
            NOW,
            1,
        );
        assert_eq!(
            d,
            AggregateDecision::DenyInvalid(Fault::AmbiguousResolution)
        );
    }

    #[test]
    fn historical_negative_budget_mint_denies_invalid() {
        // A historical in-window mint with debit <= 0 would undercount consumed_before
        // (here -100 + new 100 = projected 0 <= cap 100) — it must fail closed, never admit.
        let ev = [mint("m1", 1, "g1", -100, NOW)];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(100),
            &ev,
            NOW,
            1,
        );
        assert_eq!(
            d,
            AggregateDecision::DenyInvalid(Fault::HistoricalMintInvalid)
        );
    }

    #[test]
    fn historical_zero_budget_mint_denies_invalid() {
        let ev = [mint("m1", 1, "g1", 0, NOW)];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(10),
            &ev,
            NOW,
            1,
        );
        assert_eq!(
            d,
            AggregateDecision::DenyInvalid(Fault::HistoricalMintInvalid)
        );
    }

    #[test]
    fn historical_rate_mint_not_one_denies_invalid() {
        // A historical rate mint with debit != 1 (here 0) disappears from the count.
        let ev = [mint("m1", 1, "g1", 0, NOW)];
        let d = decide_aggregate(
            &agg(AggregateMeter::Rate, 5),
            FrozenDebit::Value(1),
            &ev,
            NOW,
            1,
        );
        assert_eq!(
            d,
            AggregateDecision::DenyInvalid(Fault::HistoricalMintInvalid)
        );
    }

    #[test]
    fn historical_tombstoned_malformed_mint_still_denies_invalid() {
        // Even a released (tombstoned) malformed mint is corrupt evidence ⇒ fail closed.
        let ev = [mint("m1", 1, "g1", -5, NOW), release("r1", 2, "m1", "g1")];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(10),
            &ev,
            NOW,
            2,
        );
        assert_eq!(
            d,
            AggregateDecision::DenyInvalid(Fault::HistoricalMintInvalid)
        );
    }

    #[test]
    fn canonical_aggregate_id_syntax() {
        // Exactly 64 lowercase hex is canonical; anything else is not.
        assert!(is_canonical_aggregate_id(&aggregate_id(
            &crate::sentence::parse_rules(
                "allow stripe.refund where amount <= 5 and budget amount 100 per day"
            )
            .unwrap()
            .rules[0]
        )));
        assert!(is_canonical_aggregate_id(&"a".repeat(64)));
        assert!(!is_canonical_aggregate_id(""));
        assert!(!is_canonical_aggregate_id("A"));
        assert!(!is_canonical_aggregate_id(&"a".repeat(63)));
        assert!(!is_canonical_aggregate_id(&"A".repeat(64))); // uppercase
        assert!(!is_canonical_aggregate_id(&"g".repeat(64))); // non-hex
    }

    #[test]
    fn historical_budget_debit_over_limit_denies_invalid() {
        // A tombstoned impossible debit (101 under cap 100) must be HistoricalMintInvalid,
        // never silently skipped so a fresh request is admitted.
        let ev = [mint("m1", 1, "g1", 101, NOW), release("r1", 2, "m1", "g1")];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(10),
            &ev,
            NOW,
            2,
        );
        assert_eq!(
            d,
            AggregateDecision::DenyInvalid(Fault::HistoricalMintInvalid)
        );
    }

    #[test]
    fn historical_budget_debit_at_limit_is_valid() {
        // The upper bound is inclusive: a debit exactly == limit is a legal historical shape.
        let ev = [mint("m1", 1, "g1", 100, NOW), release("r1", 2, "m1", "g1")];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(10),
            &ev,
            NOW,
            2,
        );
        assert!(matches!(d, AggregateDecision::Allow(p) if p.consumed_before == 0));
    }

    #[test]
    fn out_of_window_mint_is_not_consumed() {
        // A mint in the PREVIOUS day bucket (ts < window_start) does not count.
        let ev = [mint("m1", 1, "g1", 90, NOW - 86400)];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(60),
            &ev,
            NOW,
            1,
        );
        assert!(matches!(d, AggregateDecision::Allow(p) if p.consumed_before == 0));
    }

    #[test]
    fn window_lower_bound_is_inclusive_upper_exclusive() {
        // ts exactly at window_start counts; ts exactly at window_end does not.
        let at_start = [mint("m1", 1, "g1", 40, 86400)];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(60),
            &at_start,
            NOW,
            1,
        );
        assert!(matches!(d, AggregateDecision::Allow(p) if p.consumed_before == 40));
        let at_end = [mint("m1", 1, "g1", 40, 172800)];
        let d = decide_aggregate(
            &agg(AggregateMeter::Budget, 100),
            FrozenDebit::Value(60),
            &at_end,
            NOW,
            1,
        );
        assert!(matches!(d, AggregateDecision::Allow(p) if p.consumed_before == 0));
    }

    fn member(provider: &str, action: &str, eligible: bool, decl: Option<&str>) -> MemberSemantics {
        MemberSemantics {
            provider: provider.into(),
            action: action.into(),
            eligible,
            field_decl: decl.map(str::to_string),
            descriptor_hash: Some("desc".into()),
            template_hash: None,
        }
    }

    #[test]
    fn resolution_digest_changes_when_a_member_becomes_eligible() {
        // A pinned set has members A and B; initially only A's field is eligible.
        // A contract revision makes B's field eligible WITHOUT changing selector or field name — the
        // digest MUST change so old + new mints trip AmbiguousResolution instead of summing silently.
        let before = resolution_digest(
            Some("amount"),
            &[
                member("stripe", "a", true, Some("Int|true|SideEffect|Bounded")),
                member("stripe", "b", false, None),
            ],
        );
        let after = resolution_digest(
            Some("amount"),
            &[
                member("stripe", "a", true, Some("Int|true|SideEffect|Bounded")),
                member("stripe", "b", true, Some("Int|true|SideEffect|Bounded")),
            ],
        );
        assert_ne!(
            before, after,
            "a newly-eligible member must change the resolution digest"
        );
    }

    #[test]
    fn resolution_digest_changes_on_a_field_decl_revision() {
        // A unit/binding/class revision on the SAME field name changes the fingerprint → digest.
        let before = resolution_digest(
            Some("amount"),
            &[member(
                "stripe",
                "a",
                true,
                Some("Int|true|SideEffect|Bounded"),
            )],
        );
        let after = resolution_digest(
            Some("amount"),
            &[member(
                "stripe",
                "a",
                true,
                Some("Int|true|SideEffect|ExactResourcePin"),
            )],
        );
        assert_ne!(before, after);
    }

    #[test]
    fn resolution_digest_changes_on_descriptor_identity_revision() {
        // A contract/unit revision surfaced only in the descriptor bytes still moves the digest.
        let mut m1 = member("stripe", "a", true, Some("Int|true|SideEffect|Bounded"));
        let mut m2 = m1.clone();
        m1.descriptor_hash = Some("v1".into());
        m2.descriptor_hash = Some("v2".into());
        assert_ne!(
            resolution_digest(Some("amount"), &[m1]),
            resolution_digest(Some("amount"), &[m2])
        );
    }

    #[test]
    fn aggregate_id_is_matched_rule_digest_not_ruleset() {
        let rules = crate::sentence::parse_rules(
            "allow stripe.refund where amount <= 5000 and budget amount 100 per day",
        )
        .unwrap();
        let a = aggregate_id(&rules.rules[0]);
        // Editing an UNRELATED rule leaves this aggregate's id unchanged.
        let rules2 = crate::sentence::parse_rules(
            "allow stripe.refund where amount <= 5000 and budget amount 100 per day\nallow stripe.support where amount <= 1",
        )
        .unwrap();
        assert_eq!(a, aggregate_id(&rules2.rules[0]));
    }
}
