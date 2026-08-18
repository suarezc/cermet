//! Tests for the MCP-repoint quiesce barrier.

use super::quiesce::{classify_quiesce, McpQuiesceStatus, PersistedBarrier, QuiesceGrantRow};
use super::*;
use crate::audit::VerifiedAuditSnapshot;
use crate::types::CapabilityRequest;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// ---- A recording, fault-injectable durable store (mirrors the sentence-pin PinIo test pattern) ----

#[derive(Default)]
struct RecStore {
    log: Mutex<Vec<&'static str>>,
    committed: Mutex<Option<PersistedBarrier>>,
    fail_write: AtomicBool,
    fail_load: AtomicBool,
    fail_unlink: AtomicBool,
    fail_fsync: AtomicBool,
}

/// A `Send` adapter the Broker owns, sharing the `Arc<RecStore>` the test inspects.
struct ArcStore(Arc<RecStore>);

impl super::quiesce::QuiesceStore for ArcStore {
    fn write(&self, record: &PersistedBarrier) -> Result<()> {
        self.0.log.lock().unwrap().push("write");
        if self.0.fail_write.load(Ordering::SeqCst) {
            return Err(Error::Provider("injected write fault".into()));
        }
        *self.0.committed.lock().unwrap() = Some(record.clone());
        Ok(())
    }
    fn load(&self) -> Result<Option<PersistedBarrier>> {
        if self.0.fail_load.load(Ordering::SeqCst) {
            return Err(Error::Integrity("injected malformed barrier record".into()));
        }
        Ok(self.0.committed.lock().unwrap().clone())
    }
    fn unlink(&self) -> Result<()> {
        self.0.log.lock().unwrap().push("unlink");
        if self.0.fail_unlink.load(Ordering::SeqCst) {
            return Err(Error::Provider("injected unlink fault".into()));
        }
        *self.0.committed.lock().unwrap() = None;
        Ok(())
    }
    fn fsync_parent(&self) -> Result<()> {
        self.0.log.lock().unwrap().push("fsync_parent");
        if self.0.fail_fsync.load(Ordering::SeqCst) {
            return Err(Error::Provider("injected parent-fsync fault".into()));
        }
        Ok(())
    }
}

fn broker_with_store(store: Arc<RecStore>) -> TestBroker {
    struct FixedSentenceAuthority(crate::sentence::RuleSet);

    impl SentenceAuthoritySource for FixedSentenceAuthority {
        fn current_authority(&self) -> Result<AuthenticatedSentenceAuthority> {
            Ok(AuthenticatedSentenceAuthority {
                digest: crate::sentence::authority_digest(&self.0),
                rules: self.0.clone(),
            })
        }
    }

    let rules = crate::sentence::parse_rules("allow stripe.get_charge").unwrap();
    let (guard, dir) = fresh_broker_dir();
    let broker = Broker::open_full(
        BrokerConfig {
            git: crate::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
            dir,
            master_key: vec![5u8; 32],
            action_templates: crate::templates::VENDORED_CATALOG
                .iter()
                .map(|s| s.to_string())
                .collect(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        Some(Arc::new(FixedSentenceAuthority(rules))),
        Some(Box::new(ArcStore(store))),
    )
    .unwrap();
    TestBroker::new(guard, broker)
}

fn row(id: &str, status: &str, opened: Option<i64>, deadline: Option<i64>) -> QuiesceGrantRow {
    QuiesceGrantRow {
        id: id.to_string(),
        integrity_ok: true,
        status: status.to_string(),
        lease_opened_at: opened,
        lease_deadline: deadline,
    }
}

fn verified(outcomes: &[(&str, bool)]) -> VerifiedAuditSnapshot {
    let mut s = VerifiedAuditSnapshot::unverified();
    s.verified = true;
    for (id, ok) in outcomes {
        s.terminal_outcomes.insert((*id).to_string(), *ok);
    }
    s
}

// ===================== classification matrix =====================

#[test]
fn future_deadline_executing_lease_is_active() {
    let now = 1_000;
    let rows = vec![row("g1", "executing", Some(900), Some(1_500))];
    let s = classify_quiesce(now, &rows, &verified(&[]));
    assert!(matches!(s, McpQuiesceStatus::Active { .. }), "{s:?}");
}

#[test]
fn verified_report_completion_and_never_claimed_expiry_are_quiescent() {
    let now = 2_000;
    let rows = vec![
        // reported execution that reached a verified terminal completion
        row("done", "executed", Some(100), Some(500)),
        // an expired grant that NEVER began execution (no lease stamps)
        row("neverran", "expired", None, None),
        // parked/approved grants never began
        row("parked", "requested", None, None),
        row("appr", "approved", None, None),
    ];
    let s = classify_quiesce(now, &rows, &verified(&[("done", true)]));
    assert_eq!(s, McpQuiesceStatus::Quiescent, "{s:?}");
}

#[test]
fn elapsed_executing_and_swept_unreported_leases_are_orphan_ambiguous() {
    let now = 2_000;
    // executing lease whose signed deadline has passed with no verified report
    let past = vec![row("g1", "executing", Some(100), Some(1_000))];
    assert!(
        matches!(
            classify_quiesce(now, &past, &verified(&[])),
            McpQuiesceStatus::OrphanAmbiguous { .. }
        ),
        "an executing lease past deadline must be orphan-ambiguous, never safe"
    );
    // swept-to-expired grant that carries execution stamps but no verified completion
    let swept = vec![row("g2", "expired", Some(100), Some(1_000))];
    assert!(
        matches!(
            classify_quiesce(now, &swept, &verified(&[])),
            McpQuiesceStatus::OrphanAmbiguous { .. }
        ),
        "a swept lease with execution stamps but no verified report is orphan-ambiguous"
    );
}

#[test]
fn deadline_cross_while_draining_never_becomes_quiescent() {
    let rows = vec![row("g1", "executing", Some(900), Some(1_500))];
    // before the deadline: Active (client drains)
    assert!(matches!(
        classify_quiesce(1_400, &rows, &verified(&[])),
        McpQuiesceStatus::Active { .. }
    ));
    // one poll later, past the deadline with no report: OrphanAmbiguous, NEVER Quiescent
    let after = classify_quiesce(1_600, &rows, &verified(&[]));
    assert!(
        matches!(after, McpQuiesceStatus::OrphanAmbiguous { .. }),
        "a crossed deadline must flip Active→OrphanAmbiguous, not →Quiescent: {after:?}"
    );
}

#[test]
fn executed_grant_with_unverified_audit_is_an_integrity_error_not_quiescent() {
    let rows = vec![row("g1", "executed", Some(100), Some(500))];
    let mut audit = VerifiedAuditSnapshot::unverified(); // verified = false
    audit.terminal_outcomes.insert("g1".into(), true); // present but on an UNVERIFIED chain
    let s = classify_quiesce(2_000, &rows, &audit);
    assert!(
        matches!(s, McpQuiesceStatus::Integrity { .. }),
        "a reported completion on an unverified chain must be an integrity error: {s:?}"
    );
}

#[test]
fn one_hmac_failure_wins_over_active_and_is_never_quiescent() {
    let now = 1_000;
    let mut tampered = row("bad", "executing", Some(900), Some(1_500));
    tampered.integrity_ok = false; // store-tampered grant
    let rows = vec![
        row("live", "executing", Some(900), Some(1_500)), // an otherwise-Active lease
        tampered,
    ];
    let s = classify_quiesce(now, &rows, &verified(&[]));
    assert!(
        matches!(s, McpQuiesceStatus::Integrity { .. }),
        "an HMAC failure must dominate Active and never read as safe: {s:?}"
    );
}

#[test]
fn executing_lease_missing_stamps_is_an_integrity_error() {
    let rows = vec![row("g1", "executing", None, None)];
    let s = classify_quiesce(1_000, &rows, &verified(&[]));
    assert!(matches!(s, McpQuiesceStatus::Integrity { .. }), "{s:?}");
}

// ===================== barrier lifecycle + durability =====================

#[test]
fn begin_blocks_a_racing_new_claim_but_leaves_the_grant_unconsumed() {
    let store = Arc::new(RecStore::default());
    let b = broker_with_store(store);
    b.connect_credential("stripe", None, "sk_test_demo_secret_123456789")
        .unwrap();
    let grant_id = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_charge".into(),
                resource: serde_json::json!({ "charge": "ch_quiesce_fixture" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap()
        .grant_id
        .expect("the sentence-authorized request mints an approved grant");

    let begin = b.begin_mcp_repoint(120).unwrap();
    assert!(!begin.token.is_empty());
    // A NEW claim refuses with the typed temporary-quiesce result and does NOT consume the grant.
    let err = b.execute_capability(&grant_id).unwrap_err();
    assert!(
        matches!(err, Error::TemporaryQuiesce(_)),
        "a claim under an active barrier must be typed TemporaryQuiesce: {err:?}"
    );
    let status: String = b
        .state
        .query_row("SELECT status FROM grants WHERE id=?1", [&grant_id], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        status, "approved",
        "the single-use grant must not be consumed"
    );

    // Ending the barrier re-enables claims (the claim gate is clear again).
    b.end_mcp_repoint(&begin.token).unwrap();
    assert!(
        b.enforce_quiesce_barrier().is_ok(),
        "claims re-enabled after End"
    );
}

#[test]
fn begin_is_durable_before_ack_and_refuses_a_second_token() {
    let store = Arc::new(RecStore::default());
    let b = broker_with_store(store.clone());
    let begin = b.begin_mcp_repoint(300).unwrap();
    // Durable record written (hash + expiry), and it is NOT the raw token.
    let rec = store
        .committed
        .lock()
        .unwrap()
        .clone()
        .expect("record persisted");
    assert_eq!(rec.expires_at, begin.expires_at);
    assert!(
        store.log.lock().unwrap().contains(&"write"),
        "the barrier record must be durably written before begin acks"
    );
    // Only one token may exist.
    assert!(
        b.begin_mcp_repoint(300).is_err(),
        "a second begin while a live barrier holds must refuse"
    );
}

#[test]
fn status_is_holder_only() {
    let store = Arc::new(RecStore::default());
    let b = broker_with_store(store);
    let begin = b.begin_mcp_repoint(300).unwrap();
    assert!(
        b.mcp_repoint_status("not-the-token").is_err(),
        "a wrong token must not read status"
    );
    // No grants → quiescent for the real holder; the report echoes this daemon's instance id.
    let report = b.mcp_repoint_status(&begin.token).unwrap();
    assert_eq!(report.status, McpQuiesceStatus::Quiescent);
    assert_eq!(report.instance_id, begin.instance_id);
    assert!(
        b.end_mcp_repoint("not-the-token").is_err(),
        "a wrong token must not release the barrier"
    );
    // The barrier is still up after the failed release.
    assert!(b.enforce_quiesce_barrier().is_err());
}

#[test]
fn successful_release_orders_unlink_then_parent_fsync_then_clear() {
    let store = Arc::new(RecStore::default());
    let b = broker_with_store(store.clone());
    let begin = b.begin_mcp_repoint(300).unwrap();
    store.log.lock().unwrap().clear();
    b.end_mcp_repoint(&begin.token).unwrap();
    assert_eq!(
        *store.log.lock().unwrap(),
        vec!["unlink", "fsync_parent"],
        "release order must be unlink → parent fsync"
    );
    assert!(store.committed.lock().unwrap().is_none(), "record removed");
    assert!(b.enforce_quiesce_barrier().is_ok(), "claims re-enabled");
}

#[test]
fn release_fault_at_unlink_keeps_claims_blocked_and_reforges_the_record() {
    let store = Arc::new(RecStore::default());
    let b = broker_with_store(store.clone());
    let begin = b.begin_mcp_repoint(300).unwrap();
    store.fail_unlink.store(true, Ordering::SeqCst);
    let err = b.end_mcp_repoint(&begin.token).unwrap_err();
    assert!(format!("{err}").contains("unlink"), "{err}");
    // Claims remain blocked, and the durable record is reforged (durable state known).
    assert!(b.enforce_quiesce_barrier().is_err(), "claims stay blocked");
    assert!(
        store.committed.lock().unwrap().is_some(),
        "the record must be durably reforged on a release fault"
    );
    let log = store.log.lock().unwrap().clone();
    assert!(
        log.iter().rposition(|s| *s == "write") > log.iter().position(|s| *s == "unlink"),
        "a reforge write must follow the failed unlink: {log:?}"
    );
}

#[test]
fn release_fault_at_parent_fsync_keeps_claims_blocked_and_reforges() {
    let store = Arc::new(RecStore::default());
    let b = broker_with_store(store.clone());
    let begin = b.begin_mcp_repoint(300).unwrap();
    store.fail_fsync.store(true, Ordering::SeqCst);
    let err = b.end_mcp_repoint(&begin.token).unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("fsync"), "{err}");
    assert!(b.enforce_quiesce_barrier().is_err(), "claims stay blocked");
    assert!(
        store.committed.lock().unwrap().is_some(),
        "unlink took effect but was not durable — the record must be reforged"
    );
}

#[test]
fn ttl_expiry_releases_through_the_same_ordered_path_on_the_claim_check() {
    let store = Arc::new(RecStore::default());
    let b = broker_with_store(store.clone());
    b.set_now(1_000);
    let _begin = b.begin_mcp_repoint(60).unwrap(); // expires at 1_060
    assert!(b.enforce_quiesce_barrier().is_err(), "blocked before TTL");
    b.set_now(2_000); // past expiry
    store.log.lock().unwrap().clear();
    // The claim check releases the lapsed barrier through the ordered path, then admits the claim.
    assert!(
        b.enforce_quiesce_barrier().is_ok(),
        "TTL recovery admits claims"
    );
    assert_eq!(*store.log.lock().unwrap(), vec!["unlink", "fsync_parent"]);
    assert!(store.committed.lock().unwrap().is_none());
}

#[test]
fn barrier_survives_restart_via_boot_reinstatement() {
    let store = Arc::new(RecStore::default());
    let b1 = broker_with_store(store.clone());
    let _begin = b1.begin_mcp_repoint(600).unwrap();
    drop(b1);
    // A "restart": a fresh broker over the SAME durable store reinstates the block before serving.
    let b2 = broker_with_store(store.clone());
    assert!(
        b2.enforce_quiesce_barrier().is_err(),
        "a restart must reinstate the claim block from the durable record"
    );
}

#[test]
fn a_failed_release_still_reinstates_the_barrier_across_restart() {
    let store = Arc::new(RecStore::default());
    let b1 = broker_with_store(store.clone());
    let begin = b1.begin_mcp_repoint(600).unwrap();
    store.fail_fsync.store(true, Ordering::SeqCst);
    assert!(b1.end_mcp_repoint(&begin.token).is_err());
    drop(b1);
    store.fail_fsync.store(false, Ordering::SeqCst);
    // The reforged record still blocks after a restart — only a fully-ordered release re-enables.
    let b2 = broker_with_store(store.clone());
    assert!(
        b2.enforce_quiesce_barrier().is_err(),
        "reforged record still blocks"
    );
}

#[test]
fn release_double_fault_poisons_the_broker_into_unrecoverable_fail_closed() {
    // unlink Err AND the compensating reforge-write Err — the durable mirror is unknown, so
    // the broker must refuse EVERY claim and barrier op until restart (never serve claims with no
    // durable record a restart could reinstate).
    let store = Arc::new(RecStore::default());
    let b = broker_with_store(store.clone());
    let begin = b.begin_mcp_repoint(300).unwrap();
    store.fail_unlink.store(true, Ordering::SeqCst);
    store.fail_write.store(true, Ordering::SeqCst);
    let err = b.end_mcp_repoint(&begin.token).unwrap_err();
    assert!(
        format!("{err}").to_lowercase().contains("unrecoverable"),
        "a double-fault release must report an unrecoverable state: {err}"
    );
    // Claims stay blocked, and now EVERYTHING refuses (poisoned) — even after the faults clear.
    store.fail_unlink.store(false, Ordering::SeqCst);
    store.fail_write.store(false, Ordering::SeqCst);
    assert!(
        b.enforce_quiesce_barrier().is_err(),
        "poisoned: claims refuse"
    );
    assert!(
        b.begin_mcp_repoint(300).is_err(),
        "poisoned: no new barrier"
    );
    assert!(
        b.end_mcp_repoint(&begin.token).is_err(),
        "poisoned: end refuses"
    );
}

#[test]
fn a_malformed_barrier_record_fails_boot_closed() {
    let store = Arc::new(RecStore::default());
    *store.committed.lock().unwrap() = Some(PersistedBarrier {
        token_hash: [0u8; 32],
        expires_at: i64::MAX,
    });
    store.fail_load.store(true, Ordering::SeqCst);
    let (_dir_guard, dir) = fresh_broker_dir();
    let opened = Broker::open_full(
        BrokerConfig {
            git: crate::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
            dir,
            master_key: vec![5u8; 32],
            action_templates: vec![],
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        None,
        Some(Box::new(ArcStore(store))),
    );
    assert!(
        opened.is_err(),
        "a malformed/unverifiable barrier record must fail boot closed"
    );
}
