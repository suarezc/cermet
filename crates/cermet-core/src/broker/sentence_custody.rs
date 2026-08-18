//! Post-commit custody-change audit emission for the unified sentence-authority flow.
//!
//! The staged `Stage → Commit` ceremony flips the daemon-owned authority record atomically; the
//! custody audit is emitted STRICTLY AFTER that commit and is **idempotent, keyed by the
//! acceptance occurrence id**: a concurrent ceremony's commit can never drop another
//! ceremony's audit, repeated content remains occurrence-distinct, and a crash between commit and audit
//! is recovered from the record/outbox pair. Re-emitting one occurrence is a no-op.
//!
//! This is the audit spine any later commit-hook milestone rides: a post-commit provisioning audit
//! would hook the SAME point (the commit-hook provisioning seam).

use serde_json::json;

use crate::audit::NewEvent;
use crate::broker::Broker;
use crate::sentence::PreparedSentenceCorpus;
use crate::{Error, Result};

/// The audit event type for a committed sentence-authority generation.
pub(crate) const SENTENCE_CUSTODY_CHANGE: &str = "sentence_custody_change";
pub(crate) const LOCKDOWN_TRANSITION: &str = "owner_lockdown_transition";
/// CUSTODY-LADDER: one event per daemon run, naming the vault-key custody rung that run was on.
pub(crate) const BROKER_START: &str = "broker_start";
/// One agent-reported VOCABULARY REQUEST: a verb or field the catalog has no word for (or, when
/// the bridge's check said the word already exists, the refused probe for one).
pub(crate) const VOCABULARY_REQUEST: &str = "vocabulary_request";

/// The two gap classes a vocabulary probe can land in. Closed vocabulary — the daemon refuses
/// anything else rather than recording a class it cannot interpret later.
const GAP_CLASSES: &[&str] = &["vocabulary_gap", "authority_gap"];
/// Bounds on the reported strings. The bridge applies the same ones before it sends (client
/// preflight); these are the enforcement side of the pair, because the daemon is the party whose
/// log grows.
const MAX_NAME_CHARS: usize = 64;
const MAX_TEXT_CHARS: usize = 1000;

impl Broker {
    /// CUSTODY-LADDER: record which custody rung was active for THIS run.
    ///
    /// Custody is a property of the box at a moment, not of the product: a reinstall or a migration
    /// can move a broker up or down the ladder, and a receipt read a year later has to be
    /// interpretable against the custody that was actually carrying it. So the rung goes into the
    /// hash-chained ledger once per start, by its declared name, and is never rewritten.
    ///
    /// `profile` is the declared spelling (`cermet_ipc::custody::CustodyProfile::as_str`) — passed
    /// as a string because the core has no dependency on the transport shim and does not need one:
    /// what it records is what the config declared. `None` is the dev/embedded daemon, which holds
    /// no service custody rung; it records a null rather than inventing a name for one.
    pub fn record_broker_start(&self, profile: Option<&str>) -> Result<()> {
        self.audit.record(NewEvent {
            session_id: None,
            event_type: BROKER_START,
            severity: "info",
            summary: "broker started",
            data: json!({ "custody_profile": profile }),
            secrets: &self.vault.all_secrets()?,
        })?;
        Ok(())
    }

    /// Record one agent-reported vocabulary request — a decision, and every decision is a row.
    ///
    /// A vocabulary gap (the catalog has no word for what the agent needed) is data about the
    /// PRODUCT, not authority: nothing reads these rows to decide anything, and recording one
    /// grants nothing, changes no corpus, and is never consulted by the broker again. It lands in
    /// the same free-form event log `broker_start` writes to — no new store, no schema bump.
    ///
    /// The bridge already checked the ask against the live catalog and scrubbed the free text; that
    /// is the client preflight. THIS is the enforcement side of the same boundary: the gap class
    /// must be one of the two that exist, and every string is bounded, because a caller across a
    /// trust boundary is a caller whose input is checked once on each side and no more.
    #[allow(clippy::too_many_arguments)]
    pub fn record_vocabulary_request(
        &self,
        session_id: Option<&str>,
        provider: &str,
        wanted_verb: Option<&str>,
        wanted_field: Option<&str>,
        gap: &str,
        ask: Option<&str>,
        rationale: Option<&str>,
    ) -> Result<()> {
        if !GAP_CLASSES.contains(&gap) {
            return Err(Error::Invalid(format!(
                "unknown vocabulary gap class {gap:?}"
            )));
        }
        let name = |value: &str, what: &str| -> Result<()> {
            if value.is_empty() || value.chars().count() > MAX_NAME_CHARS {
                return Err(Error::Invalid(format!(
                    "vocabulary request {what} must be 1..={MAX_NAME_CHARS} characters"
                )));
            }
            Ok(())
        };
        name(provider, "provider")?;
        for (value, what) in [(wanted_verb, "verb"), (wanted_field, "field")] {
            if let Some(value) = value {
                name(value, what)?;
            }
        }
        if wanted_verb.is_none() && wanted_field.is_none() {
            return Err(Error::Invalid(
                "a vocabulary request names a wanted verb, a wanted field, or both".to_string(),
            ));
        }
        for (value, what) in [(ask, "ask"), (rationale, "rationale")] {
            if value.is_some_and(|v| v.chars().count() > MAX_TEXT_CHARS) {
                return Err(Error::Invalid(format!(
                    "vocabulary request {what} must be at most {MAX_TEXT_CHARS} characters"
                )));
            }
        }
        let subject = match (wanted_verb, wanted_field) {
            (Some(verb), Some(field)) => format!("{provider}.{verb} + field {field}"),
            (Some(verb), None) => format!("{provider}.{verb}"),
            (None, Some(field)) => format!("{provider} field {field}"),
            (None, None) => provider.to_string(),
        };
        self.audit.record(NewEvent {
            session_id,
            event_type: VOCABULARY_REQUEST,
            severity: "info",
            summary: &format!("vocabulary request: {subject} ({gap})"),
            data: json!({
                "provider": provider,
                "wanted_verb": wanted_verb,
                "wanted_field": wanted_field,
                "gap": gap,
                "ask": ask,
                "rationale": rationale,
            }),
            secrets: &self.vault.all_secrets()?,
        })?;
        Ok(())
    }

    /// Read back events of one type. TEST-ONLY: the audit log is daemon-private, and nothing in the
    /// product reads the chain by type except the verifier.
    #[cfg(test)]
    pub(crate) fn audit_events_of_type_for_test(
        &self,
        event_type: &str,
    ) -> Result<Vec<cermet_lang::types::AuditEventView>> {
        self.audit.events_of_type(event_type)
    }
}

impl Broker {
    pub fn record_lockdown_transition(
        &self,
        occurrence_id: &str,
        engaged: bool,
        operator_uid: u32,
        acceptance_path: &str,
        prior_record: Option<&str>,
    ) -> Result<()> {
        if self
            .audit
            .events_of_type(LOCKDOWN_TRANSITION)?
            .iter()
            .any(|event| {
                event
                    .data
                    .get("occurrence_id")
                    .and_then(|value| value.as_str())
                    == Some(occurrence_id)
            })
        {
            return Ok(());
        }
        self.audit.record(NewEvent {
            session_id: None,
            event_type: LOCKDOWN_TRANSITION,
            severity: "high",
            summary: if engaged {
                "owner lockdown engaged"
            } else {
                "owner lockdown cleared"
            },
            data: json!({
                "occurrence_id": occurrence_id,
                "engaged": engaged,
                "prior_record_digest": prior_record,
                "operator_uid": operator_uid,
                "acceptance_path": acceptance_path,
            }),
            secrets: &self.vault.all_secrets()?,
        })?;
        Ok(())
    }

    /// Daemon-side authority-subset validation of a candidate sentence corpus — the enforcement point
    /// the ctl `StageSentences` path runs BEFORE staging, so a direct ctl client can never install a
    /// disallowed authority record (the CLI is never trusted to pre-filter).
    ///
    /// It runs (a) the existing authority-subset restriction (version / rule structure / set-pinning /
    /// admitted allow-or-deny effect) and (b) the secret-class rejection: no conjunct may constrain a
    /// secret-class field, resolved against the broker's own contract + set resolvers (never the CLI's).
    pub fn validate_sentence_authority_corpus(&self, candidate_text: &str) -> Result<()> {
        self.prepare_sentence_authority_corpus(candidate_text)
            .map(|_| ())
    }

    /// The single daemon-side preparation path used by read-only check and durable staging.
    ///
    /// This is also the ONE place the declared `language_temporal_clauses` gate is enforced: with
    /// it off — the shipped default — a corpus carrying a `rate … per …` or `budget … per …`
    /// clause is refused here, naming the setting. Enforcing it
    /// at the corpus-admission crossing (not again at decision time) is the one-validation-per-
    /// trust-boundary shape: no new authority enters by any other route.
    pub fn prepare_sentence_authority_corpus(
        &self,
        candidate_text: &str,
    ) -> Result<PreparedSentenceCorpus> {
        let sets = crate::sets::VendoredSetResolver;
        if self.enforce_product_availability {
            crate::sentence::preflight_product_availability(candidate_text)?;
            let parsed = crate::sentence::parse_rules(candidate_text).map_err(|error| {
                Error::Invalid(format!("sentence authority preparation failed: {error}"))
            })?;
            crate::sentence::validate_product_availability(&parsed)?;
        }
        crate::sentence::prepare_sentence_authority(
            candidate_text,
            &sets,
            &self.providers,
            self.temporal_clauses,
        )
        .map_err(|error| Error::Invalid(format!("sentence authority preparation failed: {error}")))
    }

    /// Whether a custody-change audit for exactly this transition OCCURRENCE already exists in the
    /// authenticated audit log. Dedup is keyed by the per-commit `occurrence_id`, NOT the
    /// content digest — so a genuine re-transition to a previously-live generation (A → B → A) is a
    /// distinct audit event, while a boot/tick replay of the SAME pending marker (same occurrence) is
    /// idempotent and never double-chains.
    pub fn sentence_custody_occurrence_exists(&self, occurrence_id: &str) -> Result<bool> {
        Ok(self
            .audit
            .events_of_type(SENTENCE_CUSTODY_CHANGE)?
            .iter()
            .any(|ev| ev.data.get("occurrence_id").and_then(|v| v.as_str()) == Some(occurrence_id)))
    }

    /// Emit the custody-change audit for a now-live generation. Idempotent by `occurrence_id` (the
    /// durable per-commit transition id carried on the record store's audit-pending marker): if an
    /// event for this occurrence already exists, this is a no-op (a concurrent commit or a boot-adoption
    /// replay of the same pending marker never double-chains). A DIFFERENT occurrence — including a
    /// re-add of a previously-live `canonical_digest` — is always a fresh event.
    ///
    /// MUST be called only AFTER the authority record has been durably flipped to `canonical_digest`
    /// (or on boot adoption of an already-live generation) — the state is authoritative, the audit is
    /// eventually-consistent.
    pub fn record_sentence_custody_change(
        &self,
        canonical_digest: &str,
        rule_count: usize,
        occurrence_id: &str,
    ) -> Result<()> {
        self.record_sentence_custody_change_attributed(
            canonical_digest,
            rule_count,
            occurrence_id,
            0,
            "presence",
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_sentence_custody_change_attributed(
        &self,
        canonical_digest: &str,
        rule_count: usize,
        occurrence_id: &str,
        operator_uid: u32,
        acceptance_path: &str,
        prior_record: Option<&str>,
    ) -> Result<()> {
        if self.sentence_custody_occurrence_exists(occurrence_id)? {
            return Ok(());
        }
        self.audit.record(NewEvent {
            session_id: None,
            event_type: SENTENCE_CUSTODY_CHANGE,
            severity: "high",
            summary: &format!(
                "sentence authority committed (generation {}, {rule_count} rule{})",
                &canonical_digest[..canonical_digest.len().min(12)],
                if rule_count == 1 { "" } else { "s" }
            ),
            data: json!({
                "canonical_digest": canonical_digest,
                "rule_count": rule_count,
                "occurrence_id": occurrence_id,
                "prior_record_digest": prior_record,
                "operator_uid": operator_uid,
                "acceptance_path": acceptance_path,
            }),
            secrets: &self.vault.all_secrets()?,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::broker::{Broker, BrokerConfig, TestBroker};

    fn test_broker() -> TestBroker {
        test_broker_inner(true)
    }

    /// The scratch dir is RAII: `guard` deletes the `cermet-custody-audit-*` directory on drop, so
    /// this fixture leaks nothing per test.
    fn test_broker_inner(enforce_product_availability: bool) -> TestBroker {
        let (guard, dir) = crate::broker::fresh_broker_dir();
        // Load the vendored catalog so contract kinding (secret-class) resolves in the
        // authority-subset validation test below.
        let cfg = BrokerConfig {
            git: crate::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
            dir,
            master_key: vec![5u8; 32],
            action_templates: crate::templates::VENDORED_CATALOG
                .iter()
                .map(|s| s.to_string())
                .collect(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        };
        let broker = if enforce_product_availability {
            Broker::open(cfg).unwrap()
        } else {
            Broker::open_for_semantic_test(cfg, None).unwrap()
        };
        TestBroker::new(guard, broker)
    }

    /// CUSTODY-LADDER: custody can change across a migration or a reinstall,
    /// so the chain has to retain WHICH rung was active while it was carrying effects. One
    /// `broker_start` event per run does that — the audit table is a free-form
    /// `(type, severity, summary, data_json)` log with no version pragma, so this needs no schema
    /// bump and mints no migration.
    #[test]
    fn broker_start_records_the_custody_profile_that_was_active() {
        let broker = test_broker();
        broker.record_broker_start(Some("systemd-host")).unwrap();
        let events = broker
            .audit_events_of_type_for_test("broker_start")
            .unwrap();
        assert_eq!(events.len(), 1, "one event per run");
        assert_eq!(
            events[0]
                .data
                .get("custody_profile")
                .and_then(|v| v.as_str()),
            Some("systemd-host"),
            "the rung is recorded by its declared name: {:?}",
            events[0].data
        );

        // A restart on a DIFFERENT rung appends; it never rewrites what the earlier run recorded.
        broker.record_broker_start(Some("file-protected")).unwrap();
        let events = broker
            .audit_events_of_type_for_test("broker_start")
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0]
                .data
                .get("custody_profile")
                .and_then(|v| v.as_str()),
            Some("systemd-host"),
            "history keeps the profile that was active then"
        );
    }

    #[test]
    fn validate_sentence_corpus_refuses_an_unresolved_verb() {
        let broker = test_broker();
        // A dormant rule on a verb no catalog member declares must be REFUSED at commit —
        // otherwise it commits inert and silently becomes live authority when a later catalog upgrade
        // introduces the verb (activation without re-authoring). Fail closed at the validation seam.
        let err = broker
            .validate_sentence_authority_corpus("allow stripe.future_action\n")
            .expect_err("an unresolved verb must be refused at commit");
        match err {
            crate::Error::Invalid(m) => assert!(
                m.to_lowercase().contains("unresolved") || m.contains("future_action"),
                "expected the unresolved-reference refusal, got: {m}"
            ),
            other => panic!("expected Invalid, got {other:?}"),
        }
        // An unresolved conjunct FIELD on a routed verb is likewise refused.
        broker
            .validate_sentence_authority_corpus(
                "allow stripe.refund where nonexistent_field <= 5\n",
            )
            .expect_err("an unresolved conjunct field must be refused at commit");
        // A fully-resolved corpus still validates.
        broker
            .validate_sentence_authority_corpus("allow stripe.refund where amount <= 5000\n")
            .expect("a fully-resolved allow corpus validates");
    }

    #[test]
    fn prepare_pins_sets_and_preserves_resolvable_explicit_pins() {
        use crate::sets::SetResolver;

        let broker = test_broker();
        let resolver = crate::sets::VendoredSetResolver;
        let current = resolver
            .current_snapshot("stripe", "support")
            .expect("vendored support set");

        // The one live dialect: a set is spelled by its immutable expansion and NOTHING else.
        // The bare dotted form is the VERB now, so `allow stripe.support` names a verb the catalog
        // does not carry and fails reference validation — it does not silently become a set.
        assert!(
            broker
                .prepare_sentence_authority_corpus("allow stripe.support\n")
                .is_err(),
            "a bare dotted selector is a verb, and `stripe.support` is not one"
        );

        let pinned = format!("allow stripe.support@{}\n", current.digest());
        let explicit = broker
            .prepare_sentence_authority_corpus(&pinned)
            .expect("an explicit resolvable snapshot is the set spelling");
        assert_eq!(explicit.rule_count, 1);
        assert_eq!(explicit.set_snapshots.len(), 1);
        assert_eq!(explicit.set_snapshots[0].digest, current.digest());
        assert_eq!(explicit.set_snapshots[0].members, current.members());
        assert_eq!(
            explicit.canonical_text, pinned,
            "prepare must preserve an explicit exact pin"
        );

        let unknown = format!("allow stripe.support@sha256:{}\n", "0".repeat(64));
        assert!(
            broker.prepare_sentence_authority_corpus(&unknown).is_err(),
            "an unresolved historical pin must fail closed"
        );
    }

    /// A broker whose declared `language_temporal_clauses` setting is ON — the operator switch that
    /// restores the windowed clauses. Used by the tests that exercise the temporal machinery, which
    /// is gated rather than deleted.
    fn test_broker_with_temporal_clauses() -> TestBroker {
        let mut broker = test_broker();
        broker.set_temporal_clauses(true);
        broker
    }

    /// The gate OFF is the shipped default: corpus admission — the ONE crossing new authority
    /// enters through — refuses every temporal spelling and names the setting that would restore it.
    /// Refusing, not ignoring: a silently dropped cap is standing authority the operator never wrote.
    #[test]
    fn the_default_gate_refuses_every_temporal_clause_and_names_the_setting() {
        let broker = test_broker();
        assert!(
            !broker.temporal_clauses(),
            "the shipped default must be OFF; nothing may turn it on implicitly"
        );
        for candidate in [
            "allow stripe.refund where rate 30 per day\n",
            "allow stripe.refund where rate 10 per hour\n",
            "allow stripe.refund where budget amount 50000 per day\n",
            "allow stripe.refund where budget 100 per hour\n",
            "allow stripe.refund where amount <= 5000 and budget amount 50000 per day\n",
        ] {
            let error = broker
                .prepare_sentence_authority_corpus(candidate)
                .expect_err("a temporal clause must not be admitted with the gate closed")
                .to_string();
            assert!(
                error.contains(crate::sentence::TEMPORAL_CLAUSES_SETTING),
                "the refusal must name the setting: {error}"
            );
        }
        // The read-only check surface runs the same seam, so it refuses identically.
        assert!(
            broker
                .validate_sentence_authority_corpus("allow stripe.refund where rate 30 per day\n")
                .is_err(),
            "check and stage must share ONE admission answer"
        );
    }

    /// The suspension is about accumulated state, not about bounds: every predicate evaluable from
    /// the request alone still prepares with the gate closed.
    #[test]
    fn stateless_authority_still_prepares_with_the_gate_closed() {
        let broker = test_broker();
        for candidate in [
            "allow stripe.refund where amount <= 5000\n",
            "allow stripe.refund where amount >= 1\n",
            "deny stripe.create_standard_payout where amount >= 10000\n",
        ] {
            broker
                .prepare_sentence_authority_corpus(candidate)
                .unwrap_or_else(|e| {
                    panic!("a stateless corpus must still prepare: {candidate} {e}")
                });
        }
    }

    /// The catalog's per-field WHERE index is what an agent reads INSTEAD of probing one deny at a
    /// time, so it must agree with the gate: advertising `budget` while corpus admission refuses it
    /// would teach an agent to author a guaranteed deny. `rate` is verb-level and never on a field
    /// in either position.
    #[test]
    fn the_catalog_form_index_follows_the_temporal_gate() {
        let closed = test_broker();
        let summable = |broker: &Broker| {
            broker
                .catalog()
                .unwrap()
                .iter()
                .flat_map(|entry| entry.fields.clone())
                .any(|field| field.forms.iter().any(|form| form == "budget"))
        };
        let no_rate = |broker: &Broker| {
            broker
                .catalog()
                .unwrap()
                .iter()
                .flat_map(|entry| entry.fields.clone())
                .all(|field| field.forms.iter().all(|form| form != "rate"))
        };
        assert!(
            !summable(&closed),
            "the shipped default must not advertise a form corpus admission refuses"
        );
        assert!(no_rate(&closed));

        let open = test_broker_with_temporal_clauses();
        assert!(
            summable(&open),
            "with the gate open the summable fields must advertise `budget` again"
        );
        assert!(no_rate(&open), "`rate` is verb-level in either position");
    }

    /// The gate ON restores the windowed behavior exactly: the clause is admitted and canonically
    /// round-trips. This is the coverage that keeps the machinery honest while it is switched off.
    #[test]
    fn the_opened_gate_admits_a_temporal_clause_unchanged() {
        let broker = test_broker_with_temporal_clauses();
        let candidate =
            "allow stripe.refund where amount <= 5000 and budget amount 50000 per day\n";
        let prepared = broker
            .prepare_sentence_authority_corpus(candidate)
            .expect("an opened gate admits the clause exactly as before");
        assert_eq!(prepared.canonical_text, candidate);
        assert_eq!(prepared.rule_count, 1);
    }

    #[test]
    fn prepare_rejects_secret_dormant_and_shadowing_without_echoing_source() {
        // The metering-shadow refusal below is temporal-clause machinery, so this test needs the
        // gate OPEN — with it closed the corpus is refused one step earlier, for a different reason.
        let broker = test_broker_with_temporal_clauses();
        for candidate in [
            "allow stripe.future_action\n",
            "allow stripe.refund where budget nonexistent_field 100 per day\n",
            "allow stripe.refund\nallow stripe.refund where budget amount 100 per day\n",
        ] {
            let error = broker
                .prepare_sentence_authority_corpus(candidate)
                .expect_err("invalid authority must not prepare")
                .to_string();
            assert!(
                !error.contains("M2_SECRET_CANARY"),
                "preparation errors must not echo candidate values: {error}"
            );
        }
    }

    fn custody_event_count(broker: &Broker) -> usize {
        broker
            .audit
            .events_of_type(super::SENTENCE_CUSTODY_CHANGE)
            .unwrap()
            .len()
    }

    #[test]
    fn custody_change_audit_is_idempotent_by_occurrence_id() {
        let broker = test_broker();
        let digest = "a".repeat(64);
        assert!(!broker.sentence_custody_occurrence_exists("occ-1").unwrap());

        broker
            .record_sentence_custody_change(&digest, 2, "occ-1")
            .unwrap();
        assert!(broker.sentence_custody_occurrence_exists("occ-1").unwrap());
        assert_eq!(custody_event_count(&broker), 1);

        // A second emit for the SAME occurrence (a boot/tick replay of the same pending marker)
        // never double-chains — idempotent by occurrence_id.
        broker
            .record_sentence_custody_change(&digest, 2, "occ-1")
            .unwrap();
        assert_eq!(
            custody_event_count(&broker),
            1,
            "replay must not double-chain"
        );
    }

    #[test]
    fn custody_change_audit_carries_transition_occurrence_and_acceptance_path() {
        let broker = test_broker();
        let digest = "a".repeat(64);
        let prior = "b".repeat(64);
        broker
            .record_sentence_custody_change_attributed(
                &digest,
                2,
                "occ-m3",
                1000,
                "presence",
                Some(&prior),
            )
            .unwrap();

        let events = broker
            .audit
            .events_of_type(super::SENTENCE_CUSTODY_CHANGE)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data["canonical_digest"], digest);
        assert_eq!(events[0].data["rule_count"], 2);
        assert_eq!(events[0].data["occurrence_id"], "occ-m3");
        assert_eq!(events[0].data["operator_uid"], 1000);
        assert_eq!(events[0].data["acceptance_path"], "presence");
        assert_eq!(events[0].data["prior_record_digest"], prior);
    }

    #[test]
    fn reactivation_to_a_prior_generation_is_a_distinct_audit_event() {
        let broker = test_broker();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        // A -> B -> A. Each commit is a distinct transition occurrence, so the verified audit must
        // carry THREE events — the digest-only dedup that suppressed the third A→ event is gone.
        broker
            .record_sentence_custody_change(&a, 1, "occ-a1")
            .unwrap();
        broker
            .record_sentence_custody_change(&b, 1, "occ-b1")
            .unwrap();
        broker
            .record_sentence_custody_change(&a, 1, "occ-a2")
            .unwrap();
        assert_eq!(
            custody_event_count(&broker),
            3,
            "A→B→A is three transitions; the reactivation is not suppressed by content digest"
        );
        // Replaying the last occurrence (crash between emit and marker-clear) is still idempotent.
        broker
            .record_sentence_custody_change(&a, 1, "occ-a2")
            .unwrap();
        assert_eq!(custody_event_count(&broker), 3);
    }

    #[test]
    fn lockdown_transition_audit_is_high_severity_and_idempotent_by_occurrence() {
        let broker = test_broker();
        let prior = "a".repeat(64);
        broker
            .record_lockdown_transition("occ-lock-1", true, 0, "owner", Some(&prior))
            .unwrap();
        broker
            .record_lockdown_transition("occ-lock-1", true, 0, "owner", Some(&prior))
            .unwrap();

        let events = broker
            .audit
            .events_of_type(super::LOCKDOWN_TRANSITION)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, "high");
        assert_eq!(events[0].data["occurrence_id"], "occ-lock-1");
        assert_eq!(events[0].data["engaged"], true);
        assert_eq!(events[0].data["operator_uid"], 0);
    }
}
