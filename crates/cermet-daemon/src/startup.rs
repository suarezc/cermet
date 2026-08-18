//! Durable daemon startup reconciliation shared by the binary and hermetic integration proofs.

use std::sync::Arc;

use cermet_broker_actor::BrokerHandle;

use crate::lockdown::LockdownStore;
use crate::sentence_record::{self, SentenceRecordAdmin, SentenceRecordStore};

pub fn adopt_lockdown(store: &LockdownStore) {
    match store.adopt() {
        Ok(outcome) => eprintln!(
            "cermetd: owner lockdown state adopted (engaged={})",
            outcome.engaged
        ),
        Err(error) => eprintln!(
            "cermetd: owner lockdown state could not be reconciled ({error}); effective state remains engaged"
        ),
    }
}

/// Run the post-broker durable recovery gates before any daemon socket begins serving.
pub async fn recover_after_broker_start(
    record: &Arc<SentenceRecordStore>,
    lockdown: &LockdownStore,
    broker: &BrokerHandle,
) {
    crate::owner::replay_pending_audits(lockdown, broker).await;
    match record.adopt() {
        Ok(sentence_record::AdoptOutcome::Adopted {
            canonical_digest,
            rule_count,
            canonical_text,
        }) => {
            let short = &canonical_digest[..canonical_digest.len().min(12)];
            match broker.validate_sentence_corpus(canonical_text).await {
                Ok(_) => {
                    record.mark_generation_validated(&canonical_digest);
                    eprintln!(
                        "cermetd: adopted + validated sentence authority (generation {short}, \
                         {rule_count} rules)"
                    );
                }
                Err(error) => {
                    // Retain WHY, keyed to the generation it was computed for, so the deny every
                    // sentence-routed request now gets NAMES the problem instead of only the state.
                    // The authority decision is unchanged — the positive validation gate already
                    // denies an unvalidated generation. This is the difference between an operator
                    // reading "did not pass semantic validation" and reading the failing rule.
                    record.mark_generation_validation_failed(&canonical_digest, &error.to_string());
                    eprintln!(
                        "cermetd: adopted sentence authority FAILED semantic validation ({error}); \
                         sentence-routed requests DENY until re-authored via `cermet rules allow` \
                         (generation {short})"
                    )
                }
            }
        }
        Ok(sentence_record::AdoptOutcome::Absent) => eprintln!(
            "cermetd: no sentence authority record; sentence requests deny-all until `cermet rules allow`"
        ),
        Ok(sentence_record::AdoptOutcome::Corrupt { reason, .. }) => eprintln!(
            "cermetd: sentence authority record is unusable ({reason}); sentence requests deny-all \
             until re-authored"
        ),
        Err(error) => eprintln!(
            "cermetd: cannot read the sentence authority record ({error}); sentence requests deny-all \
             until adopted-and-validated"
        ),
    }
    replay_pending_custody_audits(record.as_ref(), broker).await;
    match record.sweep_staged(sentence_record::STAGED_TTL_SECS) {
        Ok(swept) if swept > 0 => {
            eprintln!("cermetd: swept {swept} inert staged sentence record(s) at boot")
        }
        _ => {}
    }
}

/// Replay every committed-but-unaudited sentence occurrence through the broker audit chain.
pub async fn replay_pending_custody_audits(
    record: &dyn SentenceRecordAdmin,
    broker: &BrokerHandle,
) {
    let pending = match record.pending_audit_records() {
        Ok(pending) => pending,
        Err(error) => {
            eprintln!(
                "cermetd: cannot read the sentence audit outbox ({error}); custody audits may be delayed"
            );
            return;
        }
    };
    for marker in pending {
        let short = marker.target_digest[..marker.target_digest.len().min(12)].to_string();
        match broker
            .record_sentence_custody_change_attributed(
                marker.target_digest,
                marker.rule_count,
                marker.occurrence_id.clone(),
                marker.operator_uid,
                marker.acceptance_path,
                marker.prior_record,
            )
            .await
        {
            Ok(_) => record.clear_pending_audit(&marker.occurrence_id),
            Err(error) => eprintln!(
                "cermetd: could not emit the custody audit for generation {short} ({error}); will retry"
            ),
        }
    }
}
