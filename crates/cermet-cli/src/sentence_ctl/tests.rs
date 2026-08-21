//! Platform-generic tests for the ONE daemon-native staged sentence custody. These run on Linux; only
//! the real ctl client + the platform presence adapter are production-selected.

use super::*;
use secrecy::SecretString;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

type Log = Arc<Mutex<Vec<&'static str>>>;

fn token_of(text: &str) -> String {
    let mut h = DefaultHasher::new();
    text.hash(&mut h);
    format!("{:016x}", h.finish()).repeat(4)
}

/// A CONSISTENT in-memory daemon: `stage` records the candidate against the live generation, `commit`
/// flips it iff still live (superseded ⇒ Denied; idempotent re-commit ⇒ Committed). Faithful to the
/// daemon-owned staged protocol so `run_allow`/`run_revoke`/`run_refresh` reuse VERBATIM.
#[derive(Default)]
struct Backend {
    live: Mutex<Option<String>>, // token of the live generation (None = absent)
    corpus: Mutex<HashMap<String, String>>, // token -> canonical text
    staged: Mutex<HashMap<String, Option<String>>>, // token -> staged_against (live at stage)
    corrupt: Mutex<bool>,        // when set, snapshot reports a corrupt record
    corrupt_after_snapshot: Mutex<bool>, // one-shot: corrupt immediately after this snapshot
    unserved: Mutex<bool>,
    commit_transport_losses: Mutex<usize>,
    status_unavailable: Mutex<bool>,
    status_occurrence_override: Mutex<Option<String>>,
    lockdown_engaged: Mutex<bool>,
    delay_commit_until_after_status: Mutex<bool>,
    pending_commit: Mutex<Option<String>>,
    mismatched_ack_after_commit: Mutex<bool>,
    expire_after_timeout: Mutex<bool>,
    unserved_after_commit: Mutex<bool>,
    log: Log,
}

struct BackendClient(Arc<Backend>);

impl StagedSentenceClient for BackendClient {
    fn snapshot(&self) -> Result<RecordSnapshot> {
        if *self.0.corrupt.lock().unwrap() {
            return Ok(RecordSnapshot::Corrupt {
                reason: "test: record does not match its approval pin".into(),
            });
        }
        if *self.0.unserved.lock().unwrap() {
            return Ok(RecordSnapshot::Unserved);
        }
        let snapshot = match &*self.0.live.lock().unwrap() {
            None => Ok(RecordSnapshot::Absent),
            Some(token) => {
                let text = self.0.corpus.lock().unwrap().get(token).cloned().unwrap();
                let rules = cermet_lang::sentence::parse_rules(&text)
                    .map_err(|e| CustodyError::InvalidRules(e.to_string()))?;
                Ok(RecordSnapshot::Valid { rules })
            }
        };
        let mut corrupt_after_snapshot = self.0.corrupt_after_snapshot.lock().unwrap();
        if *corrupt_after_snapshot {
            *self.0.corrupt.lock().unwrap() = true;
            *corrupt_after_snapshot = false;
        }
        snapshot
    }

    fn authority_status(&self) -> Result<cermet_ipc::ctl::SentenceAuthorityStatus> {
        use cermet_ipc::ctl::{LockdownSnapshot, SentenceAuthorityStatus, SentenceSnapshot};

        if *self.0.status_unavailable.lock().unwrap() {
            return Err(CustodyError::Storage("test: status unavailable".into()));
        }
        let lockdown = if *self.0.lockdown_engaged.lock().unwrap() {
            LockdownSnapshot::Engaged
        } else {
            LockdownSnapshot::Clear
        };
        let sentence = if *self.0.corrupt.lock().unwrap() {
            SentenceSnapshot::Corrupt {
                record_digest: "d".repeat(64),
                reason: "test: corrupt".into(),
            }
        } else {
            match &*self.0.live.lock().unwrap() {
                None => SentenceSnapshot::Absent,
                Some(token) => {
                    let rules_text = self.0.corpus.lock().unwrap().get(token).cloned().unwrap();
                    let rules = cermet_lang::sentence::parse_rules(&rules_text).unwrap();
                    let authority_digest = cermet_lang::sentence::authority_digest_for(
                        rules.version,
                        rules_text.as_bytes(),
                    );
                    let occurrence_id = self
                        .0
                        .status_occurrence_override
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap_or_else(|| cermet_ipc::ctl::sentence_occurrence_for_token(token));
                    if *self.0.unserved.lock().unwrap() {
                        SentenceSnapshot::Unserved {
                            record_digest: "d".repeat(64),
                            rules_text,
                            authority_digest,
                            occurrence_id,
                            rule_count: rules.rules.len(),
                        }
                    } else {
                        SentenceSnapshot::Served {
                            record_digest: "d".repeat(64),
                            rules_text,
                            authority_digest,
                            occurrence_id,
                            rule_count: rules.rules.len(),
                        }
                    }
                }
            }
        };
        let status = SentenceAuthorityStatus { sentence, lockdown };
        if let Some(token) = self.0.pending_commit.lock().unwrap().take() {
            *self.0.live.lock().unwrap() = Some(token);
        }
        Ok(status)
    }

    fn stage(&self, candidate_text: String) -> Result<StagedEcho> {
        self.0.log.lock().unwrap().push("stage");
        // Validate/canonicalize like the daemon (a bad corpus is a definite no-stage).
        let rules = cermet_lang::sentence::parse_rules(&candidate_text)
            .map_err(|e| CustodyError::InvalidRules(e.to_string()))?;
        let canonical = super::encode_rules(&rules)?;
        let canonical_text = String::from_utf8(canonical).unwrap();
        let token = token_of(&canonical_text);
        let occurrence_id = cermet_ipc::ctl::sentence_occurrence_for_token(&token);
        self.0
            .corpus
            .lock()
            .unwrap()
            .insert(token.clone(), canonical_text.clone());
        let against = self.0.live.lock().unwrap().clone();
        self.0.staged.lock().unwrap().insert(token.clone(), against);
        Ok(StagedEcho {
            canonical_digest: cermet_lang::sentence::authority_digest_for(
                rules.version,
                canonical_text.as_bytes(),
            ),
            canonical_text,
            staging_token: token,
            occurrence_id,
        })
    }

    fn commit(&self, staging_token: String) -> CommitResult {
        self.0.log.lock().unwrap().push("commit");
        let occurrence_id = cermet_ipc::ctl::sentence_occurrence_for_token(&staging_token);
        let Some(against) = self.0.staged.lock().unwrap().get(&staging_token).cloned() else {
            return CommitResult::Denied("unknown/stale token".into());
        };
        let mut live = self.0.live.lock().unwrap();
        if self.0.pending_commit.lock().unwrap().as_ref() == Some(&staging_token)
            && live.as_deref() != Some(staging_token.as_str())
        {
            return CommitResult::Transport;
        }
        if live.as_deref() == Some(staging_token.as_str()) {
            let committed = CommitResult::Committed {
                canonical_digest: self
                    .0
                    .corpus
                    .lock()
                    .unwrap()
                    .get(&staging_token)
                    .map(|text| {
                        cermet_lang::sentence::authority_digest_for(
                            cermet_lang::sentence::RULE_SET_VERSION,
                            text.as_bytes(),
                        )
                    })
                    .unwrap(),
                occurrence_id,
            };
            let mut losses = self.0.commit_transport_losses.lock().unwrap();
            if *losses > 0 {
                *losses -= 1;
                return CommitResult::Transport;
            }
            return committed; // idempotent
        }
        if *live != against {
            return CommitResult::Denied("superseded".into());
        }
        let mut delay = self.0.delay_commit_until_after_status.lock().unwrap();
        if *delay {
            *delay = false;
            *self.0.pending_commit.lock().unwrap() = Some(staging_token);
            return CommitResult::Transport;
        }
        let mut expire = self.0.expire_after_timeout.lock().unwrap();
        if *expire {
            *expire = false;
            self.0.staged.lock().unwrap().remove(&staging_token);
            return CommitResult::Transport;
        }
        let canonical_digest = self
            .0
            .corpus
            .lock()
            .unwrap()
            .get(&staging_token)
            .map(|text| {
                cermet_lang::sentence::authority_digest_for(
                    cermet_lang::sentence::RULE_SET_VERSION,
                    text.as_bytes(),
                )
            })
            .unwrap();
        *live = Some(staging_token);
        if *self.0.unserved_after_commit.lock().unwrap() {
            *self.0.unserved.lock().unwrap() = true;
        }
        let committed = CommitResult::Committed {
            canonical_digest,
            occurrence_id,
        };
        let mut mismatched = self.0.mismatched_ack_after_commit.lock().unwrap();
        if *mismatched {
            *mismatched = false;
            return CommitResult::Committed {
                canonical_digest: "f".repeat(64),
                occurrence_id: "e".repeat(64),
            };
        }
        let mut losses = self.0.commit_transport_losses.lock().unwrap();
        if *losses > 0 {
            *losses -= 1;
            CommitResult::Transport
        } else {
            committed
        }
    }
}

/// A presence that logs when it is invoked, so a test can pin its exact position in the ceremony.
struct LoggingPresence {
    outcome: PresenceOutcome,
    log: Log,
}
impl Presence for LoggingPresence {
    fn confirm(&self, _reason: &str) -> PresenceOutcome {
        self.log.lock().unwrap().push("presence");
        self.outcome.clone()
    }
}

fn rule_set(text: &str) -> RuleSet {
    cermet_lang::sentence::parse_rules(text).unwrap()
}

fn custody_with(backend: Arc<Backend>, presence: PresenceOutcome) -> (StagedSentenceCustody, Log) {
    let log = backend.log.clone();
    let presence = Arc::new(LoggingPresence {
        outcome: presence,
        log: log.clone(),
    });
    (
        StagedSentenceCustody::new(Box::new(BackendClient(backend)), presence),
        log,
    )
}

struct ReplacingDocumentObserver {
    status: cermet_ipc::ctl::SentenceAuthorityStatus,
}

impl CorpusDocumentSyncObserver for ReplacingDocumentObserver {
    fn observe(
        &self,
        _status: Option<&cermet_ipc::ctl::SentenceAuthorityStatus>,
    ) -> CorpusDocumentObservation {
        CorpusDocumentObservation {
            sync: CorpusDocumentSync::Required,
            status: Some(self.status.clone()),
        }
    }
}

#[test]
fn presence_adapter_invoked_exactly_at_confirm_between_stage_and_commit() {
    let backend = Arc::new(Backend::default());
    let (custody, log) = custody_with(backend.clone(), PresenceOutcome::Confirmed);
    let rules = rule_set("allow stripe.refund where amount <= 5000\n");
    custody
        .compare_and_swap_rules_with_presence(
            RuleCorpusExpectation::Authenticated(&[]),
            &rules,
            "add rule",
        )
        .expect("ceremony succeeds");
    assert_eq!(
        *log.lock().unwrap(),
        vec!["stage", "presence", "commit"],
        "presence is invoked exactly at confirm — AFTER the daemon's canonical echo, BEFORE commit"
    );
    // The generation flipped.
    assert!(backend.live.lock().unwrap().is_some());
}

#[test]
fn declined_presence_stages_but_never_commits_authority() {
    let backend = Arc::new(Backend::default());
    let (custody, log) = custody_with(backend.clone(), PresenceOutcome::Denied);
    let rules = rule_set("allow stripe.refund where amount <= 5000\n");
    let err = custody
        .compare_and_swap_rules_with_presence(
            RuleCorpusExpectation::Authenticated(&[]),
            &rules,
            "add rule",
        )
        .unwrap_err();
    assert!(matches!(err, CustodyError::PresenceDenied));
    assert_eq!(
        *log.lock().unwrap(),
        vec!["stage", "presence"],
        "a declined presence must NEVER reach commit"
    );
    assert!(
        backend.live.lock().unwrap().is_none(),
        "a declined presence installs no authority (the staged record is inert)"
    );
}

#[test]
fn unavailable_presence_installs_no_authority() {
    let backend = Arc::new(Backend::default());
    let (custody, _log) = custody_with(
        backend.clone(),
        PresenceOutcome::Unavailable("no tty".into()),
    );
    let rules = rule_set("allow stripe.refund where amount <= 5000\n");
    let err = custody
        .compare_and_swap_rules_with_presence(
            RuleCorpusExpectation::Authenticated(&[]),
            &rules,
            "add rule",
        )
        .unwrap_err();
    assert!(matches!(err, CustodyError::PresenceUnavailable(_)));
    assert!(backend.live.lock().unwrap().is_none());
}

#[test]
fn superseded_token_surfaces_as_rules_changed() {
    // Two custodies over the SAME backend stage against the same (absent) prior generation; the first
    // commit wins, the second's token is superseded ⇒ RulesChanged.
    let backend = Arc::new(Backend::default());
    let a = rule_set("allow stripe.refund where amount <= 5000\n");
    let b = rule_set("allow stripe.refund where amount <= 1000\n");
    // Stage both first (manually) so both bind to the absent prior generation.
    let client = BackendClient(backend.clone());
    let ta = client
        .stage(String::from_utf8(super::encode_rules(&a).unwrap()).unwrap())
        .unwrap();
    let tb = client
        .stage(String::from_utf8(super::encode_rules(&b).unwrap()).unwrap())
        .unwrap();
    assert!(matches!(
        client.commit(ta.staging_token),
        CommitResult::Committed { .. }
    ));
    assert!(matches!(
        client.commit(tb.staging_token),
        CommitResult::Denied(_)
    ));
}

#[test]
fn production_snapshot_parser_accepts_served_daemon_wire_shape() {
    let snapshot = parse_snapshot(
        serde_json::from_str(r#"{"state":"Served","record_digest":"record","rules_text":"allow stripe.refund where amount <= 5000\n","authority_digest":"authority","occurrence_id":"occurrence","rule_count":1}"#).unwrap(),
    )
    .expect("the current Served ctl shape parses");
    match snapshot {
        RecordSnapshot::Valid { rules } => assert_eq!(rules.rules.len(), 1),
        other => panic!("expected authenticated rules, got {other:?}"),
    }
}

#[test]
fn production_snapshot_parser_accepts_unserved_daemon_wire_shape() {
    let snapshot = parse_snapshot(
        serde_json::from_str(r#"{"state":"Unserved","record_digest":"record","rules_text":"allow stripe.refund where amount <= 5000\n","authority_digest":"authority","occurrence_id":"occurrence","rule_count":1}"#).unwrap(),
    )
    .expect("the current Unserved ctl shape parses");
    assert!(matches!(snapshot, RecordSnapshot::Unserved), "{snapshot:?}");
}

#[test]
fn production_snapshot_parser_keeps_absent_and_corrupt_fail_closed() {
    assert!(matches!(
        parse_snapshot(serde_json::from_str(r#"{"state":"Absent"}"#).unwrap()).unwrap(),
        RecordSnapshot::Absent
    ));
    assert!(matches!(
        parse_snapshot(
            serde_json::from_str(
                r#"{"state":"Corrupt","record_digest":"record","reason":"pin mismatch"}"#,
            )
            .unwrap()
        )
        .unwrap(),
        RecordSnapshot::Corrupt { reason } if reason == "pin mismatch"
    ));
}

struct ConfirmingTerminal;
impl crate::tty::Terminal for ConfirmingTerminal {
    fn is_interactive(&self) -> bool {
        true
    }
    fn confirm(&self, _prompt: &str, _default: bool) -> bool {
        true
    }
    fn launch(&self, _url: &str) {}
    fn read_secret(&self, _prompt: &str) -> std::result::Result<SecretString, crate::CliError> {
        Err(crate::CliError::Refused("no secret in this test".into()))
    }
}

#[test]
fn allow_refuses_disabled_provider_before_parse_stage_or_presence() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    let (custody, log) = custody_with(backend, PresenceOutcome::Confirmed);
    let error = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "fs.read where malformed",
        true,
    )
    .expect_err("disabled provider must refuse without ceremony");
    assert!(matches!(error, crate::CliError::Refused(ref reason) if reason == "provider_disabled"));
    assert!(
        log.lock().unwrap().is_empty(),
        "no read, stage, presence, or commit may run"
    );
}

#[test]
fn incremental_staging_preserves_stable_provider_refusal() {
    let error = classify_stage_error(cermet_lang::Error::ProviderDisabled);

    assert!(matches!(error, CustodyError::ProviderDisabled));
    assert_eq!(error.to_string(), "provider_disabled");
}

#[test]
fn lost_response_allow_and_numbered_revoke_retry_only_the_exact_commit_without_presence() {
    use crate::rule_cli::{run_allow, run_revoke, run_rules};
    let backend = Arc::new(Backend::default());
    let (custody, log) = custody_with(backend.clone(), PresenceOutcome::Confirmed);
    // allow → the staged ceremony stages, confirms, commits.
    let document = tempfile::tempdir().unwrap();
    let document_path = document.path().join("CERMET.md");
    let document_bytes = b"repository proposal remains untouched";
    std::fs::write(&document_path, document_bytes).unwrap();
    *backend.commit_transport_losses.lock().unwrap() = 1;
    let added = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("run_allow succeeds against StagedSentenceCustody");
    for expected in [
        "live: sha256:",
        "occurrence_id:",
        "document_sync: document state not observed",
    ] {
        assert!(added.text.contains(expected), "{}", added.text);
    }
    assert_eq!(std::fs::read(&document_path).unwrap(), document_bytes);
    // rules → lists the just-committed rule.
    let listed = run_rules(&custody).expect("run_rules reads back");
    assert!(listed.text.contains("stripe.refund"), "{}", listed.text);
    // revoke → removes it; rules is then empty.
    *backend.commit_transport_losses.lock().unwrap() = 1;
    let revoked = run_revoke(&custody, &ConfirmingTerminal, 1, false).expect("run_revoke succeeds");
    assert!(
        revoked
            .text
            .contains("document_sync: document state not observed"),
        "{}",
        revoked.text
    );
    assert!(revoked.text.contains("live: sha256:"), "{}", revoked.text);
    assert_eq!(std::fs::read(&document_path).unwrap(), document_bytes);
    let after = run_rules(&custody).expect("run_rules after revoke");
    assert_eq!(after.text, "No rules configured.");
    assert_eq!(
        *log.lock().unwrap(),
        vec!["stage", "presence", "commit", "stage", "presence", "commit"],
        "transport reconciliation retries only each exact commit token and never repeats presence"
    );
    assert!(!added.text.contains("rerun"), "{}", added.text);
    assert!(!revoked.text.contains("rerun"), "{}", revoked.text);
}

#[test]
fn run_refresh_preserves_set_history_and_reports_unexported_live_without_touching_document() {
    use crate::rule_cli::{run_allow, run_refresh};
    use cermet_lang::sets::{SetResolver, SetSnapshot};

    struct ChangingResolver {
        prior: SetSnapshot,
        current: SetSnapshot,
    }
    impl SetResolver for ChangingResolver {
        fn current_snapshot(&self, provider: &str, set: &str) -> Option<SetSnapshot> {
            self.current
                .is_for(provider, set, self.current.digest())
                .then(|| self.current.clone())
        }
        fn snapshot(&self, provider: &str, set: &str, digest: &str) -> Option<SetSnapshot> {
            [&self.prior, &self.current]
                .into_iter()
                .find(|snapshot| snapshot.is_for(provider, set, digest))
                .cloned()
        }
    }
    let prior = SetSnapshot::new(
        "stripe",
        "support",
        vec!["lookup_customer".into(), "refund".into()],
    )
    .unwrap();
    let current = SetSnapshot::new(
        "stripe",
        "support",
        vec!["credit_balance".into(), "refund".into()],
    )
    .unwrap();
    assert_ne!(prior.digest(), current.digest());
    let resolver = ChangingResolver {
        prior: prior.clone(),
        current: current.clone(),
    };
    let backend = Arc::new(Backend::default());
    let (custody, log) = custody_with(backend.clone(), PresenceOutcome::Confirmed);
    run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &resolver,
        &format!("stripe.support@{}", prior.digest()),
        false,
    )
    .expect("historical set rule is accepted");
    let document = tempfile::tempdir().unwrap();
    let path = document.path().join("CERMET.md");
    std::fs::write(&path, b"draft bytes").unwrap();

    *backend.commit_transport_losses.lock().unwrap() = 1;
    let refreshed = run_refresh(&custody, &resolver, 1).expect("set refresh succeeds");

    assert!(
        refreshed.text.contains(prior.digest()),
        "{}",
        refreshed.text
    );
    assert!(
        refreshed.text.contains(current.digest()),
        "{}",
        refreshed.text
    );
    assert!(
        refreshed
            .text
            .contains("document_sync: document state not observed"),
        "{}",
        refreshed.text
    );
    assert!(
        refreshed.text.contains("live: sha256:"),
        "{}",
        refreshed.text
    );
    assert_eq!(std::fs::read(path).unwrap(), b"draft bytes");
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "presence")
            .count(),
        2,
        "seed allow and refresh each require presence exactly once"
    );
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "commit")
            .count(),
        2,
        "status proves the exact refresh occurrence without replaying the command"
    );
    assert!(!refreshed.text.contains("rerun"), "{}", refreshed.text);
}

#[test]
fn repeated_transport_loss_returns_a_truthful_unknown_receipt_without_replay_advice() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    *backend.commit_transport_losses.lock().unwrap() = 10;
    *backend.status_unavailable.lock().unwrap() = true;
    let (custody, log) = custody_with(backend, PresenceOutcome::Confirmed);

    let output = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("unknown commit state is a structured receipt");

    assert!(
        !output.ok,
        "unknown outcome must return a nonzero CLI result"
    );
    assert!(
        output.text.contains("receipt_state: unknown"),
        "{}",
        output.text
    );
    assert!(output.text.contains("occurrence_id:"), "{}", output.text);
    assert!(output.text.contains("staging_token:"), "{}", output.text);
    assert!(output.text.contains("lockdown: unknown"), "{}", output.text);
    assert!(!output.text.contains("added rule"), "{}", output.text);
    assert!(!output.text.contains("rerun"), "{}", output.text);
    assert_eq!(
        *log.lock().unwrap(),
        vec!["stage", "presence", "commit", "commit", "commit", "commit"],
    );
}

#[test]
fn in_flight_commit_completing_after_early_baseline_status_reconciles_exact_token() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    *backend.delay_commit_until_after_status.lock().unwrap() = true;
    let (custody, log) = custody_with(backend, PresenceOutcome::Confirmed);

    let output = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("the original handler completes after the early baseline observation");

    assert!(output.ok, "{}", output.text);
    assert!(
        output.text.contains("receipt_state: known"),
        "{}",
        output.text
    );
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "presence")
            .count(),
        1,
    );
}

#[test]
fn mismatched_ack_after_success_reconciles_without_repeating_mutation_or_presence() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    *backend.mismatched_ack_after_commit.lock().unwrap() = true;
    let (custody, log) = custody_with(backend, PresenceOutcome::Confirmed);

    let output = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("the exact staged occurrence proves the malformed acknowledgement's commit");

    assert!(output.ok, "{}", output.text);
    assert!(
        output.text.contains("receipt_state: known"),
        "{}",
        output.text
    );
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "presence")
            .count(),
        1,
    );
}

#[test]
fn timeout_followed_by_staged_expiry_preserves_exact_unknown_token_and_do_not_repeat() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    *backend.expire_after_timeout.lock().unwrap() = true;
    let (custody, log) = custody_with(backend, PresenceOutcome::Confirmed);

    let output = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("expiry after timeout remains a structured unknown receipt");

    assert!(!output.ok, "{}", output.text);
    assert!(
        output.text.contains("receipt_state: unknown"),
        "{}",
        output.text
    );
    assert!(output.text.contains("staging_token:"), "{}", output.text);
    assert!(output.text.contains("do not repeat"), "{}", output.text);
    assert!(!output.text.contains("added rule"), "{}", output.text);
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "presence")
            .count(),
        1,
    );
}

#[test]
fn exact_unserved_occurrence_proves_commit_without_claiming_served_authority() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    *backend.commit_transport_losses.lock().unwrap() = 10;
    *backend.unserved_after_commit.lock().unwrap() = true;
    let (custody, log) = custody_with(backend, PresenceOutcome::Confirmed);

    let output = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("the exact unserved record is a known committed transaction");

    assert!(
        !output.ok,
        "unserved authority is not a successful final live state"
    );
    assert!(
        output.text.contains("receipt_state: known"),
        "{}",
        output.text
    );
    assert!(
        output.text.contains("committed: sha256:"),
        "{}",
        output.text
    );
    assert!(
        !output.text.contains("outcome remains unknown"),
        "{}",
        output.text
    );
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "presence")
            .count(),
        1,
    );
}

#[test]
fn exact_ack_is_known_but_different_final_occurrence_is_not_reported_live() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    *backend.status_occurrence_override.lock().unwrap() = Some("e".repeat(64));
    let (custody, _log) = custody_with(backend, PresenceOutcome::Confirmed);

    let output = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("the mismatch is a structured unknown receipt");

    assert!(
        !output.ok,
        "the committed transaction is no longer final live"
    );
    assert!(
        output.text.contains("receipt_state: known"),
        "{}",
        output.text
    );
    assert!(
        output.text.contains("committed: sha256:"),
        "{}",
        output.text
    );
    assert!(
        output
            .text
            .contains("not the observed final served authority"),
        "{}",
        output.text
    );
    assert!(!output.text.contains("added rule"), "{}", output.text);
}

#[test]
fn document_observer_winner_replaces_the_earlier_success_and_lockdown_receipt() {
    use crate::rule_cli::run_allow;
    use cermet_ipc::ctl::{LockdownSnapshot, SentenceAuthorityStatus, SentenceSnapshot};

    let backend = Arc::new(Backend::default());
    let (custody, _log) = custody_with(backend, PresenceOutcome::Confirmed);
    let custody = custody.with_document_sync(Arc::new(ReplacingDocumentObserver {
        status: SentenceAuthorityStatus {
            sentence: SentenceSnapshot::Absent,
            lockdown: LockdownSnapshot::Engaged,
        },
    }));

    let output = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("a superseded commit remains a structured receipt");

    assert!(!output.ok, "{}", output.text);
    assert!(
        output.text.contains("receipt_state: known"),
        "{}",
        output.text
    );
    assert!(
        output.text.contains("committed: sha256:"),
        "{}",
        output.text
    );
    assert!(output.text.contains("lockdown: engaged"), "{}", output.text);
    assert!(!output.text.contains("added rule"), "{}", output.text);
}

#[test]
fn semantically_unserved_record_refuses_incremental_mutation_and_names_apply_recovery() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    let (custody, _log) = custody_with(backend.clone(), PresenceOutcome::Confirmed);
    run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("seed served rule");
    *backend.unserved.lock().unwrap() = true;

    let error = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 6000",
        false,
    )
    .expect_err("ordinary allow must not activate an unserved corpus");

    let message = error.to_string();
    assert!(message.contains("unserved"), "{message}");
    assert!(message.contains("cermet doc apply --recover"), "{message}");
}

#[test]
fn incremental_receipt_reports_presence_and_effective_engaged_lockdown() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    *backend.lockdown_engaged.lock().unwrap() = true;
    let (custody, _log) = custody_with(backend, PresenceOutcome::Confirmed);

    let output = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("authority may be authored while owner lockdown remains engaged");

    assert!(
        output.text.contains("receipt_state: known"),
        "{}",
        output.text
    );
    assert!(
        output.text.contains("acceptance_path: presence"),
        "{}",
        output.text
    );
    assert!(output.text.contains("lockdown: engaged"), "{}", output.text);
    assert!(
        output.text.contains("execution remains disabled"),
        "{}",
        output.text
    );
}

/// A terminal whose confirm PANICS: proves a code path never consulted it.
struct UnconsultableTerminal;
impl crate::tty::Terminal for UnconsultableTerminal {
    fn is_interactive(&self) -> bool {
        false
    }
    fn confirm(&self, _prompt: &str, _default: bool) -> bool {
        panic!("--yes must never consult the terminal confirm");
    }
    fn launch(&self, _url: &str) {}
    fn read_secret(&self, _prompt: &str) -> std::result::Result<SecretString, crate::CliError> {
        Err(crate::CliError::Refused("no secret in this test".into()))
    }
}

/// A terminal that declines every confirm — the shape a non-tty stdin collapses to
/// (EOF → fail-closed default false).
/// Captures the ceremony prompt so a test can assert what the operator was actually shown, then
/// declines — the prompt is the subject, not the outcome.
struct CapturingTerminal(std::sync::Mutex<Vec<String>>);
impl crate::tty::Terminal for CapturingTerminal {
    fn is_interactive(&self) -> bool {
        true
    }
    fn confirm(&self, prompt: &str, _default: bool) -> bool {
        self.0.lock().unwrap().push(prompt.to_string());
        false
    }
    fn launch(&self, _url: &str) {}
    fn read_secret(&self, _prompt: &str) -> std::result::Result<SecretString, crate::CliError> {
        Err(crate::CliError::Refused("no secret in this test".into()))
    }
}

/// An operator authoring the WHERE must see the SELECT before they decide. The allow ceremony
/// echoes the verb's response contract — what it returns, what is stored, and what an error gives
/// back — so "allow" is never consent to a response surface nobody showed them.
#[test]
fn the_allow_ceremony_echoes_the_verbs_response_contract() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    let (custody, _log) = custody_with(backend, PresenceOutcome::Confirmed);
    let terminal = CapturingTerminal(std::sync::Mutex::new(Vec::new()));
    let _ = run_allow(
        &custody,
        &terminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    );
    let prompts = terminal.0.lock().unwrap().clone();
    let prompt = prompts
        .first()
        .expect("the ceremony consulted the operator");
    assert!(
        prompt.contains("returns (refund):"),
        "the ceremony must name the verb whose response it is describing: {prompt}"
    );
    assert!(
        prompt.contains("verbatim"),
        "the ceremony must state WHAT comes back: {prompt}"
    );
    assert!(
        prompt.contains("the full response is stored as an artifact"),
        "stripe.refund retains by default; the ceremony must say what is stored: {prompt}"
    );
    assert!(
        prompt.contains("HTTP status plus the provider's error body"),
        "the ceremony must state the ERROR surface too: {prompt}"
    );

    // `retention: none` is the exception, not the norm — the money floor is where it survives on a
    // product verb. A capped verb says so, and the operator learns there will be no artifact to
    // fetch, which is a fact about this rule they can only get here.
    let capped = CapturingTerminal(std::sync::Mutex::new(Vec::new()));
    let _ = run_allow(
        &custody,
        &capped,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund_charge_bounded where amount <= 5000 and charge = \"ch_1\" \
         and account = \"acct_1\" and mode = \"test\" and currency = \"usd\"",
        false,
    );
    let capped_prompts = capped.0.lock().unwrap().clone();
    let capped_prompt = capped_prompts
        .first()
        .expect("the ceremony consulted the operator");
    assert!(
        capped_prompt.contains("nothing is stored as an artifact"),
        "a retention-capped verb must say there is no artifact: {capped_prompt}"
    );
}

/// Regression: echoing a SET rule with a hard-coded `full` contract means approving
/// `stripe.charge_ops` — five verbs that are ALL money-floor `retention: none` — tells the operator
/// every response body would be stored as an artifact. Exactly backwards, on the one selector where
/// the member-level fact is hardest to look up by hand. A mixed set must not hide the split either.
#[test]
fn a_set_prompt_derives_its_members_contracts_instead_of_assuming_full() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    let (custody, _log) = custody_with(backend, PresenceOutcome::Confirmed);

    let pinned = |set: &str| {
        use cermet_lang::sets::SetResolver as _;
        format!(
            "stripe.{set}@{}",
            cermet_lang::sets::VendoredSetResolver
                .current_snapshot("stripe", set)
                .expect("a vendored set")
                .digest()
        )
    };

    let prompt_for = |sentence: &str| {
        let terminal = CapturingTerminal(std::sync::Mutex::new(Vec::new()));
        let _ = run_allow(
            &custody,
            &terminal,
            &crate::rule_cli::VendoredRuleCatalog,
            &cermet_lang::sets::VendoredSetResolver,
            sentence,
            false,
        );
        let held = terminal.0.lock().unwrap().clone();
        held.first().cloned().unwrap_or_default()
    };

    // All-money set: every member is structurally `retention: none`, and the prompt must say so.
    let money_set = prompt_for(&format!(
        "allow {} where amount <= 5000",
        pinned("charge_ops")
    ));
    assert!(
        money_set.contains("nothing is stored as an artifact"),
        "an all-money set must state the floor, not the opposite: {money_set}"
    );
    assert!(
        !money_set.contains("the full response is stored as an artifact"),
        "the prompt claimed artifacts for a set that stores none: {money_set}"
    );

    // Mixed set: two full reads plus one capped mutation. The split is the fact worth surfacing —
    // collapsing it to either single answer is a lie in one direction or the other.
    let mixed = prompt_for(&format!(
        "allow {} where amount <= 5000",
        pinned("refund_ops")
    ));
    assert!(
        mixed.contains("nothing is stored as an artifact")
            && mixed.contains("the full response is stored as an artifact"),
        "a mixed set must show BOTH member behaviors: {mixed}"
    );
    assert!(
        mixed.contains("refund_charge_bounded"),
        "and name which members carry which: {mixed}"
    );
}

struct DecliningTerminal;
impl crate::tty::Terminal for DecliningTerminal {
    fn is_interactive(&self) -> bool {
        false
    }
    fn confirm(&self, _prompt: &str, default: bool) -> bool {
        default
    }
    fn launch(&self, _url: &str) {}
    fn read_secret(&self, _prompt: &str) -> std::result::Result<SecretString, crate::CliError> {
        Err(crate::CliError::Refused("no secret in this test".into()))
    }
}

// Revoke needs a noninteractive path. `--yes` skips ONLY the CLI-side confirm —
// the presence-gated CAS still governs the custody swap — while a declined confirm without
// `--yes` stays fail-closed and leaves custody untouched.
#[test]
fn run_revoke_yes_skips_confirm_but_declined_confirm_stays_fail_closed() {
    use crate::rule_cli::{run_allow, run_revoke, run_rules};
    let backend = Arc::new(Backend::default());
    let (custody, _log) = custody_with(backend, PresenceOutcome::Confirmed);
    run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("run_allow succeeds");
    // Without --yes on a non-tty: the confirm collapses to its fail-closed default and the
    // rule survives.
    let err = run_revoke(&custody, &DecliningTerminal, 1, false)
        .expect_err("declined confirm must refuse");
    assert!(matches!(err, crate::CliError::Refused(_)), "{err:?}");
    assert!(
        run_rules(&custody)
            .expect("rules after declined revoke")
            .text
            .contains("stripe.refund"),
        "custody must be unchanged after a declined revoke"
    );
    // With --yes: the terminal is never consulted (a consult panics) and the rule is removed
    // through the presence-gated CAS.
    run_revoke(&custody, &UnconsultableTerminal, 1, true).expect("--yes revoke succeeds");
    assert_eq!(
        run_rules(&custody).expect("rules after --yes revoke").text,
        "No rules configured."
    );
}

// The allow surface: `--yes` skips only the canonical-echo confirm; a declined
// confirm without `--yes` stays fail-closed and writes nothing.
#[test]
fn run_allow_yes_skips_confirm_but_declined_confirm_stays_fail_closed() {
    use crate::rule_cli::{run_allow, run_rules};
    let backend = Arc::new(Backend::default());
    let (custody, _log) = custody_with(backend, PresenceOutcome::Confirmed);
    let err = run_allow(
        &custody,
        &DecliningTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect_err("declined confirm must refuse");
    assert!(matches!(err, crate::CliError::Refused(_)), "{err:?}");
    assert_eq!(
        run_rules(&custody)
            .expect("rules after declined allow")
            .text,
        "No rules configured.",
        "custody must be unchanged after a declined allow"
    );
    run_allow(
        &custody,
        &UnconsultableTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        true,
    )
    .expect("--yes allow succeeds without consulting the terminal");
    assert!(run_rules(&custody)
        .expect("rules after --yes allow")
        .text
        .contains("stripe.refund"));
}

// Guard: `--yes` must NEVER auto-confirm the pin-mismatch recovery prompt — replacing
// an untrusted corpus is an anomaly a script loop fails loudly on, not one it heals over.
#[test]
fn run_allow_yes_refuses_pin_mismatch_recovery() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    *backend.corrupt.lock().unwrap() = true;
    let (custody, _log) = custody_with(backend, PresenceOutcome::Confirmed);
    let err = run_allow(
        &custody,
        &UnconsultableTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        true,
    )
    .expect_err("--yes over a pin-mismatch recovery must refuse");
    assert!(matches!(err, crate::CliError::Refused(_)), "{err:?}");
    let msg = format!("{err}");
    assert!(
        msg.contains("interactive"),
        "the refusal must direct the operator to the interactive recovery path: {msg}"
    );
}

// The authenticated snapshot read by allow/revoke remains the original-state CAS
// expectation. If the live record becomes corrupt after that read, staging/commit must refuse even
// when --yes skips the routine CLI confirmation.
#[test]
fn allow_yes_refuses_when_record_corrupts_after_initial_read() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    *backend.corrupt_after_snapshot.lock().unwrap() = true;
    let (custody, _log) = custody_with(backend, PresenceOutcome::Confirmed);
    let err = run_allow(
        &custody,
        &UnconsultableTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        true,
    )
    .expect_err("allow --yes must preserve the original authenticated-record CAS");
    assert!(matches!(err, crate::CliError::Refused(_)), "{err:?}");
}

#[test]
fn revoke_yes_refuses_when_record_corrupts_after_initial_read() {
    use crate::rule_cli::{run_allow, run_revoke};
    let backend = Arc::new(Backend::default());
    let (custody, _log) = custody_with(backend.clone(), PresenceOutcome::Confirmed);
    run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "stripe.refund where amount <= 5000",
        false,
    )
    .expect("seed rule");
    *backend.corrupt_after_snapshot.lock().unwrap() = true;
    let err = run_revoke(&custody, &UnconsultableTerminal, 1, true)
        .expect_err("revoke --yes must preserve the original authenticated-record CAS");
    assert!(matches!(err, crate::CliError::Refused(_)), "{err:?}");
}

/// The sentence language has two rule effects and the daemon enforces "a matching deny wins over
/// every allow", so the direct-custody CLI must be able to STAGE a deny. Blindly prefixing
/// `allow ` to any text that does not already start with `allow` would make
/// `cermet rules allow "deny x"` parse as the selector `deny` and fail usage, leaving the
/// effect reachable only through the whole-corpus document path. Staging a deny is
/// authority-NARROWING by construction (it can only remove reachability, never add it), the
/// canonical echo prints the effect the operator is accepting, and the presence-gated CAS swap is
/// unchanged.
#[test]
fn the_direct_custody_path_stages_an_explicit_deny_rule() {
    use crate::rule_cli::{run_allow, run_rules};
    let backend = Arc::new(Backend::default());
    let (custody, _log) = custody_with(backend.clone(), PresenceOutcome::Confirmed);
    run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "github.request_workflow_cancel where owner = \"acme\"",
        false,
    )
    .expect("the broader allow stages");
    let denied = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "deny github.request_workflow_cancel",
        false,
    )
    .expect("an explicit deny rule stages through the direct custody path");
    assert!(
        denied.text.contains("deny github.request_workflow_cancel"),
        "the ceremony must echo the DENY effect it staged: {}",
        denied.text
    );
    let listed = run_rules(&custody).expect("run_rules reads back");
    assert!(
        listed
            .text
            // the list renders a rule as `rules allow` takes it — `allow` elided,
            // `deny` kept, so a copied row is a no-op rather than `allow allow …`.
            .contains("1. github.request_workflow_cancel where owner = \"acme\"")
            && listed
                .text
                .contains("2. deny github.request_workflow_cancel"),
        "both effects must be listed in canonical form: {}",
        listed.text
    );
}

/// The pass-through is exactly two effect keywords wide. A bare `deny`, and any other leading
/// word, still take the historical path (`allow <text>`) or refuse — no third effect appears.
#[test]
fn a_bare_deny_has_no_selector_and_is_refused() {
    use crate::rule_cli::run_allow;
    let backend = Arc::new(Backend::default());
    let (custody, _log) = custody_with(backend.clone(), PresenceOutcome::Confirmed);
    let error = run_allow(
        &custody,
        &ConfirmingTerminal,
        &crate::rule_cli::VendoredRuleCatalog,
        &cermet_lang::sets::VendoredSetResolver,
        "deny",
        false,
    )
    .expect_err("a bare deny names no selector");
    assert!(
        matches!(error, crate::CliError::Usage(_)),
        "a bare deny must be a usage refusal, not a staged rule: {error:?}"
    );
}

/// The OWNING test for the CLI's own rule-numbering surface: the `rules` listing and the
/// number `revoke` consumes are ONE numbering.
///
/// This is the contract every other surface is measured against — a deny reason, a corpus-validation
/// error, or anything else that names a rule to a person is correct exactly when its number selects
/// the same sentence here. So the list is not spot-checked: every position is read out of the
/// rendered text and revoked, and the rule that disappears must be the one that line named.
#[test]
fn the_listed_rule_number_is_exactly_what_revoke_consumes() {
    use crate::rule_cli::{run_allow, run_revoke, run_rules};

    let authored = [
        "stripe.get_charge",
        "stripe.list_active_prices",
        "stripe.refund where amount <= 5000",
        "stripe.search_customers",
    ];

    for target in 1..=authored.len() {
        let backend = Arc::new(Backend::default());
        let (custody, _log) = custody_with(backend.clone(), PresenceOutcome::Confirmed);
        for rule in authored {
            run_allow(
                &custody,
                &ConfirmingTerminal,
                &crate::rule_cli::VendoredRuleCatalog,
                &cermet_lang::sets::VendoredSetResolver,
                rule,
                false,
            )
            .expect("run_allow commits under a confirmed presence");
        }

        let listed = run_rules(&custody).expect("run_rules reads back");
        let lines: Vec<&str> = listed.text.lines().collect();
        assert_eq!(lines.len(), authored.len(), "{}", listed.text);

        // The list is the source of truth for what "rule N" means. Read N and its sentence off the
        // rendered line rather than assuming the order.
        let (printed_number, sentence) = lines[target - 1]
            .split_once(". ")
            .expect("each listed rule is `<n>. <sentence>`");
        assert_eq!(
            printed_number.parse::<usize>().unwrap(),
            cermet_lang::sentence::human_rule_number(target - 1),
            "the listing must number from 1: {}",
            listed.text
        );

        // The confirm prompt echoes the sentence revoke is about to remove; a mismatch there is the
        // operator's last chance to catch a wrong number, so it must name the same line.
        let revoked = run_revoke(
            &custody,
            &ConfirmingTerminal,
            printed_number.parse().unwrap(),
            false,
        )
        .expect("run_revoke succeeds");
        assert!(
            revoked.text.contains(sentence),
            "revoke #{printed_number} reported a different sentence than the list showed \
             ({sentence}): {}",
            revoked.text
        );

        let after = run_rules(&custody).expect("run_rules after revoke");
        assert!(
            !after.text.contains(sentence),
            "revoke #{printed_number} left the sentence it named standing: {}",
            after.text
        );
        assert_eq!(
            after.text.lines().count(),
            authored.len() - 1,
            "revoke removed more or less than the one rule it named: {}",
            after.text
        );
    }
}
