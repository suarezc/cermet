//! Platform-generic tests for the universal daemon-owned sentence record store + the staged two-round
//! ceremony. These run on Linux (plain unix files); only the production presence prompt is
//! platform-specific and lives in the CLI custody.

use super::*;
use std::collections::BTreeSet;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::Mutex as StdMutex;

fn me() -> u32 {
    nix::unistd::geteuid().as_raw()
}

const R1: &str = "allow stripe.refund where amount <= 5000\n";
const R2: &str = "allow stripe.refund where amount <= 1000\n";

fn parse(text: &str) -> RuleSet {
    parse_rules(text).expect("test rule parses")
}

fn write_raw(path: &Path, bytes: &[u8], mode: u32) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .expect("create record file");
    f.write_all(bytes).expect("write record bytes");
    f.set_permissions(std::fs::Permissions::from_mode(mode))
        .expect("set mode");
}

fn store_in(dir: &Path) -> SentenceRecordStore {
    SentenceRecordStore::new(
        SentenceRecordStore::record_path(dir),
        SentenceRecordStore::staged_dir(dir),
        None,
        me(),
    )
}

fn store_with_projection(dir: &Path, projection: &Path) -> SentenceRecordStore {
    SentenceRecordStore::new(
        SentenceRecordStore::record_path(dir),
        SentenceRecordStore::staged_dir(dir),
        Some(projection.to_path_buf()),
        me(),
    )
}

fn file_mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn projection_is_0640_and_leaves_no_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let sentences = dir.path().join("sentences");
    let projection = sentences.join("rules.cermet");
    let store = store_with_projection(dir.path(), &projection);
    author(&store, &RecordingSink::default(), R1);

    assert_eq!(
        file_mode(&projection),
        0o640,
        "the projection must be readable by the group it exists for"
    );
    let names: Vec<_> = std::fs::read_dir(&sentences)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        vec![std::ffi::OsString::from("rules.cermet")],
        "projection regeneration must not leave its write_temp_and_fsync temp behind"
    );
}

#[test]
fn non_projection_write_temp_products_remain_0600() {
    let dir = tempfile::tempdir().unwrap();
    let projection = dir.path().join("sentences/rules.cermet");
    let store = store_with_projection(dir.path(), &projection);
    let staged = store.stage(R1).expect("stage");
    let staged_path = SentenceRecordStore::staged_dir(dir.path()).join(&staged.staging_token);
    assert_eq!(
        file_mode(&staged_path),
        0o600,
        "staged record must stay private"
    );

    store
        .commit(&staged.staging_token, &FailingSink)
        .expect("commit succeeds while failed audit delivery retains its outbox product");
    assert_eq!(
        file_mode(&SentenceRecordStore::record_path(dir.path())),
        0o600,
        "authoritative sentence record must stay private"
    );
    let outbox = SentenceRecordStore::audit_pending_dir(dir.path());
    let markers: Vec<_> = std::fs::read_dir(&outbox)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(
        markers.len(),
        1,
        "failed audit delivery retains exactly one marker"
    );
    assert_eq!(
        file_mode(&markers[0]),
        0o600,
        "audit-pending marker must stay private"
    );
}

#[test]
fn projection_write_does_not_follow_a_symlink_across_the_uid_boundary() {
    let dir = tempfile::tempdir().unwrap();
    // A daemon-owned "authority" file the service-uid projection write must never be able to clobber.
    let secret = dir.path().join("daemon_owned_authority");
    std::fs::write(&secret, b"AUTHORITY-RECORD").unwrap();
    // The projection target is an approver-planted SYMLINK redirecting into daemon-owned state.
    let sentences = dir.path().join("sentences");
    std::fs::create_dir_all(&sentences).unwrap();
    let projection = sentences.join("rules.cermet");
    std::os::unix::fs::symlink(&secret, &projection).unwrap();

    let store = store_with_projection(dir.path(), &projection);
    let sink = RecordingSink::default();
    // Authoring regenerates the projection — it must NOT follow the symlink.
    author(&store, &sink, R1);

    assert_eq!(
        std::fs::read(&secret).unwrap(),
        b"AUTHORITY-RECORD",
        "the daemon-owned target was clobbered THROUGH the symlink — custody boundary crossed"
    );
    let meta = std::fs::symlink_metadata(&projection).unwrap();
    assert!(
        meta.file_type().is_file(),
        "the projection is a regular file (the symlink was replaced, not followed)"
    );
}

/// A recording custody-audit sink for the store's post-commit hook. `digests()` retains the deduped
/// content projection; `occurrences()` records EVERY emitted acceptance occurrence — a
/// re-transition to a prior digest is a distinct occurrence.
#[derive(Default)]
struct RecordingSink {
    emitted: StdMutex<Vec<String>>,
    occurrences: StdMutex<Vec<String>>,
}
impl CustodyAuditSink for RecordingSink {
    fn record_committed(
        &self,
        canonical_digest: &str,
        _rule_count: usize,
        occurrence_id: &str,
    ) -> Result<AuditEmitted> {
        let mut e = self.emitted.lock().unwrap();
        if !e.iter().any(|d| d == canonical_digest) {
            e.push(canonical_digest.to_string());
        }
        self.occurrences
            .lock()
            .unwrap()
            .push(occurrence_id.to_string());
        Ok(AuditEmitted::Emitted)
    }
}
impl RecordingSink {
    fn digests(&self) -> Vec<String> {
        self.emitted.lock().unwrap().clone()
    }
    fn occurrences(&self) -> Vec<String> {
        self.occurrences.lock().unwrap().clone()
    }
}

/// A sink that always fails — models "the record flipped, but the post-commit audit could not be
/// written" so a test can prove the flip precedes (and is independent of) the audit.
struct FailingSink;
impl CustodyAuditSink for FailingSink {
    fn record_committed(&self, _d: &str, _c: usize, _occ: &str) -> Result<AuditEmitted> {
        Err(Error::Provider("audit sink down".into()))
    }
}

/// Stage `text` then commit it — the full ceremony, returning the committed digest.
fn author(store: &SentenceRecordStore, sink: &dyn CustodyAuditSink, text: &str) -> String {
    let staged = store.stage(text).expect("stage");
    match store.commit(&staged.staging_token, sink).expect("commit") {
        CommitOutcome::Committed {
            canonical_digest, ..
        }
        | CommitOutcome::AlreadyCommitted {
            canonical_digest, ..
        } => canonical_digest,
    }
}

fn pending_marker(
    target_digest: &str,
    rule_count: usize,
    occurrence_id: &str,
    confirmed: bool,
) -> PendingAudit {
    PendingAudit {
        occurrence_id: occurrence_id.to_string(),
        target_digest: target_digest.to_string(),
        prior_record: None,
        rule_count,
        operator_uid: me(),
        acceptance_path: "presence".into(),
        confirmed,
    }
}

fn live_occurrence(store: &SentenceRecordStore) -> String {
    match store.snapshot().unwrap() {
        SentenceSnapshot::Served { occurrence_id, .. }
        | SentenceSnapshot::Unserved { occurrence_id, .. } => occurrence_id,
        other => panic!("expected a present valid record, got {other:?}"),
    }
}

// ---- A re-transition to a prior generation is a distinct, replay-idempotent audit ----------------

#[test]
fn reactivation_produces_a_distinct_audit_occurrence() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    // A -> B -> A. Each successful commit is one authority transition = one occurrence. The two A
    // commits carry DISTINCT occurrence ids, so the broker (which dedups on occurrence) records both.
    let a1 = author(&store, &sink, R1);
    let _b = author(&store, &sink, R2);
    let a2 = author(&store, &sink, R1);
    assert_eq!(a1, a2, "the two A commits are the same content digest");

    let occ = sink.occurrences();
    assert_eq!(
        occ.len(),
        3,
        "A→B→A is three emitted transitions, got {occ:?}"
    );
    let distinct: std::collections::BTreeSet<_> = occ.iter().collect();
    assert_eq!(
        distinct.len(),
        3,
        "every transition has a distinct occurrence id: {occ:?}"
    );
}

#[test]
fn housekeeping_reconciles_a_live_intent_only_marker() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    // Author R1 (committed, confirmed, emitted, marker cleared).
    let digest = author(&store, &sink, R1);

    // Model a commit whose POST-FLIP confirm was LOST: the LIVE generation carries an intent-only
    // marker. `pending_audits` excludes it (never emitted) and `sweep_orphan_intents` keeps it (it IS
    // live) — so without reconciliation it stays unaudited until the next boot.
    let outbox = SentenceRecordStore::audit_pending_dir(dir.path());
    let occurrence = live_occurrence(&store);
    write_raw(
        &outbox.join(&occurrence),
        &serde_json::to_vec(&pending_marker(&digest, 1, &occurrence, false)).unwrap(),
        0o600,
    );
    assert!(
        store.pending_audits().unwrap().is_empty(),
        "an intent-only marker for the live gen is not yet emittable"
    );

    // The housekeeping tick heals it: promote the live generation's marker to confirmed.
    store.reconcile_live_audit_marker().expect("reconcile");
    let pending = store.pending_audits().unwrap();
    assert_eq!(
        pending
            .iter()
            .map(|(d, _, _)| d.clone())
            .collect::<Vec<_>>(),
        vec![digest.clone()],
        "the live generation's audit is emittable after reconciliation"
    );

    // Replay now emits it. A second reconcile is idempotent (already confirmed).
    store
        .reconcile_live_audit_marker()
        .expect("reconcile is idempotent");
    let sink2 = RecordingSink::default();
    store.emit_pending_audits(&sink2).expect("replay");
    assert_eq!(
        sink2.digests(),
        vec![digest],
        "the once-flipped live generation is audited"
    );
}

// The reconcile path must PROVE the outbox durable before promoting the live intent marker
// to confirmed — the same hard gate the normal supersession path uses. When the outbox dir fsync
// fails, reconcile fails closed and leaves the marker intent-only (never a non-durable "confirmed"
// audit); the next tick / boot retries.
#[test]
fn reconcile_fails_closed_when_the_marker_cannot_be_proven_durable() {
    let dir = tempfile::tempdir().unwrap();
    // Author R1 with real I/O, then plant a live intent-only marker (a lost post-flip confirm).
    let author_store = store_in(dir.path());
    let sink = RecordingSink::default();
    let digest = author(&author_store, &sink, R1);
    let outbox = SentenceRecordStore::audit_pending_dir(dir.path());
    let occurrence = live_occurrence(&author_store);
    write_raw(
        &outbox.join(&occurrence),
        &serde_json::to_vec(&pending_marker(&digest, 1, &occurrence, false)).unwrap(),
        0o600,
    );

    // A store whose outbox-dir fsync fails: prove_durable() cannot succeed.
    let store = store_with_fsync_fail(dir.path(), outbox.clone());
    let err = store
        .reconcile_live_audit_marker()
        .expect_err("a non-durable reconcile must fail closed");
    assert!(matches!(err, Error::Provider(_)), "{err:?}");

    // The marker was NOT promoted — a healthy store still sees it as intent-only (not yet emittable).
    let healthy = store_in(dir.path());
    assert!(
        healthy.pending_audits().unwrap().is_empty(),
        "a failed durability proof must leave the marker intent-only, never a confirmed non-durable audit"
    );
}

// ---- Staged two-round protocol; confirmation bound to daemon-canonical bytes ---------------------

#[test]
fn stage_returns_daemon_canonical_echo_and_token() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    // Deliberately non-canonical input (extra whitespace / missing trailing newline): the daemon
    // echoes back ITS canonical form, and the token is the digest of THAT, so the human confirms the
    // exact bytes that will become authoritative.
    let staged = store
        .stage("allow   stripe.refund where amount <= 5000")
        .expect("stage");
    let expected = String::from_utf8(canonical_rule_bytes(&parse(R1))).unwrap();
    assert_eq!(
        staged.canonical_text, expected,
        "daemon echoes its canonical form"
    );
    assert_eq!(
        staged.staging_token.len(),
        64,
        "a stage nonce is 32 bytes of hex"
    );
    assert!(
        staged
            .staging_token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "the stage nonce uses lowercase hex only"
    );
    assert_eq!(
        staged.canonical_digest,
        canonical_digest(staged.canonical_text.as_bytes()),
        "the candidate digest is distinct metadata, not the staging token"
    );
    assert_eq!(
        staged.occurrence_id,
        occurrence_for_nonce(&staged.staging_token),
        "stage exposes the exact deterministic occurrence retained for commit reconciliation"
    );
    assert_ne!(staged.canonical_digest, staged.staging_token);
    // Staging makes NOTHING authoritative: the prior (absent) generation stays live.
    assert!(
        store.current_ruleset().is_err(),
        "stage must not install authority"
    );
}

#[test]
fn same_candidate_restaging_never_reuses_or_resurrects_an_old_ceremony() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    author(&store, &sink, R1); // A

    let old_b = store.stage(R2).expect("stage B against A");
    let c = store
        .stage("allow stripe.refund where amount <= 2000\n")
        .expect("stage C against A");
    store.commit(&c.staging_token, &sink).expect("commit C");
    let new_b = store.stage(R2).expect("stage the same B against C");

    assert_ne!(
        old_b.staging_token, new_b.staging_token,
        "every stage gets a fresh nonce"
    );
    assert_eq!(old_b.canonical_digest, new_b.canonical_digest);
    store
        .commit(&old_b.staging_token, &sink)
        .expect_err("restaging B must not overwrite the old B ceremony's exact A baseline");
    store
        .commit(&new_b.staging_token, &sink)
        .expect("the new B ceremony bound to C remains valid");
}

#[test]
fn malformed_and_traversal_shaped_stage_tokens_are_rejected_before_path_construction() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    let staged_dir = SentenceRecordStore::staged_dir(dir.path());

    let malformed = vec![
        String::new(),
        "deadbeef".into(),
        "A".repeat(64),
        "../sentence.record".into(),
        "g".repeat(64),
    ];
    for token in &malformed {
        let err = store
            .commit(token, &sink)
            .expect_err("a malformed token must be a typed no-write refusal");
        assert!(
            matches!(err, Error::Denied(_)),
            "malformed token {token:?}: {err:?}"
        );
        assert!(
            store.peek_staged_text(token).is_err(),
            "peek validates syntax before constructing a staged path"
        );
    }
    assert!(
        !staged_dir.exists(),
        "invalid tokens construct and write no staging paths"
    );
    assert!(!SentenceRecordStore::record_path(dir.path()).exists());
}

#[test]
fn changed_corrupt_bytes_stale_an_absent_or_corrupt_baseline() {
    let dir = tempfile::tempdir().unwrap();
    let record = SentenceRecordStore::record_path(dir.path());
    let store = store_in(dir.path());
    write_raw(&record, b"corrupt-a", 0o600);
    let staged = store
        .stage(R1)
        .expect("corrupt state is an exact recoverable baseline");
    write_raw(&record, b"corrupt-b", 0o600);

    store
        .commit(&staged.staging_token, &RecordingSink::default())
        .expect_err("changed corrupt bytes must stale the ceremony, never collapse to absent");
    assert_eq!(std::fs::read(record).unwrap(), b"corrupt-b");
}

#[test]
fn every_absent_corrupt_unserved_and_served_baseline_change_stales_the_stage() {
    let sink = RecordingSink::default();

    let absent_dir = tempfile::tempdir().unwrap();
    let absent_store = store_in(absent_dir.path());
    let absent_stage = absent_store.stage(R1).unwrap();
    let absent_record = SentenceRecordStore::record_path(absent_dir.path());
    write_raw(&absent_record, b"now-present", 0o600);
    absent_store
        .commit(&absent_stage.staging_token, &sink)
        .expect_err("Absent -> Present(Corrupt) must stale the exact baseline");
    assert_eq!(std::fs::read(&absent_record).unwrap(), b"now-present");

    let corrupt_dir = tempfile::tempdir().unwrap();
    let corrupt_record = SentenceRecordStore::record_path(corrupt_dir.path());
    write_raw(&corrupt_record, b"corrupt-a", 0o600);
    let corrupt_store = store_in(corrupt_dir.path());
    let corrupt_stage = corrupt_store.stage(R1).unwrap();
    write_raw(&corrupt_record, b"corrupt-b", 0o600);
    corrupt_store
        .commit(&corrupt_stage.staging_token, &sink)
        .expect_err("Present(Corrupt A) -> Present(Corrupt B) must stale the exact baseline");

    let unserved_dir = tempfile::tempdir().unwrap();
    let authority_digest = author(&store_in(unserved_dir.path()), &sink, R1);
    let unserved_store = store_in(unserved_dir.path());
    assert!(matches!(
        unserved_store.snapshot().unwrap(),
        SentenceSnapshot::Unserved { .. }
    ));
    let unserved_stage = unserved_store.stage(R2).unwrap();
    unserved_store.mark_generation_validated(&authority_digest);
    unserved_store
        .commit(&unserved_stage.staging_token, &sink)
        .expect_err(
            "Present(Unserved) -> Present(Served) must stale even with identical record bytes",
        );

    let served_dir = tempfile::tempdir().unwrap();
    let served_store = store_in(served_dir.path());
    author(&served_store, &sink, R1);
    assert!(matches!(
        served_store.snapshot().unwrap(),
        SentenceSnapshot::Served { .. }
    ));
    let served_stage = served_store.stage(R2).unwrap();
    served_store.mark_generation_validated(&"f".repeat(64));
    served_store
        .commit(&served_stage.staging_token, &sink)
        .expect_err(
            "Present(Served) -> Present(Unserved) must stale the exact served-state baseline",
        );
}

#[test]
fn snapshot_uses_the_same_process_lifetime_served_gate_as_authority() {
    let dir = tempfile::tempdir().unwrap();
    let digest = author(&store_in(dir.path()), &RecordingSink::default(), R1);
    let fresh = store_in(dir.path());
    assert!(
        fresh.current_ruleset().is_err(),
        "fresh process has not validated the record"
    );
    assert!(
        matches!(fresh.snapshot().unwrap(), SentenceSnapshot::Unserved { .. }),
        "well-formed but unvalidated bytes must report Unserved"
    );
    fresh.mark_generation_validated(&digest);
    assert!(matches!(
        fresh.snapshot().unwrap(),
        SentenceSnapshot::Served { .. }
    ));
}

#[test]
fn commit_with_stale_token_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    let err = store
        .commit(&"deadbeef".repeat(8), &sink)
        .expect_err("an unknown/stale token must be refused");
    assert!(matches!(err, Error::Denied(_)), "{err:?}");
    assert!(sink.digests().is_empty(), "a refused commit emits no audit");
    assert!(store.current_ruleset().is_err(), "nothing was installed");
}

#[test]
fn commit_flips_generation_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    let digest = author(&store, &sink, R1);
    // The generation is now live and reads back exactly.
    let rules = store
        .current_ruleset()
        .expect("authority live after commit");
    assert_eq!(rules, parse(R1));
    match store.snapshot().unwrap() {
        SentenceSnapshot::Served { rule_count, .. } => assert_eq!(rule_count, 1),
        other => panic!("expected Served, got {other:?}"),
    }
    assert_eq!(
        sink.digests(),
        vec![digest],
        "exactly one custody audit, keyed by the generation"
    );
}

#[test]
fn crash_between_stage_and_commit_leaves_prior_generation_live() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    author(&store, &sink, R1); // prior generation G1 is live
                               // Stage a replacement but "crash" before committing (never call commit).
    let staged = store.stage(R2).expect("stage");
    assert!(dir
        .path()
        .join("sentence.staged")
        .join(&staged.staging_token)
        .exists());
    // The prior generation stays live and authoritative; the staged record is inert.
    assert_eq!(store.current_ruleset().unwrap(), parse(R1));
    assert_eq!(sink.digests().len(), 1, "no audit for an uncommitted stage");
}

// ---- Durable staged identity; a concurrent commit cannot drop another ceremony's audit -----------

#[test]
fn concurrent_ceremonies_second_commit_refused_first_audit_survives() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    // Two ceremonies stage against the SAME (absent) prior generation.
    let a = store.stage(R1).expect("stage A");
    let b = store.stage(R2).expect("stage B");
    assert_ne!(a.staging_token, b.staging_token);
    // Ceremony A commits first — the generation flips to A.
    store.commit(&a.staging_token, &sink).expect("commit A");
    // Ceremony B's token was staged against the now-superseded prior generation ⇒ refused.
    let err = store
        .commit(&b.staging_token, &sink)
        .expect_err("a superseded token must be refused");
    assert!(matches!(err, Error::Denied(_)), "{err:?}");
    // A's authority + audit survive B's refused commit; B never chained an audit.
    assert_eq!(store.current_ruleset().unwrap(), parse(R1));
    assert_eq!(
        sink.digests(),
        vec![a.canonical_digest],
        "only A's audit exists"
    );
}

// ---- Audits emit strictly after the authority commit, recoverable from the record ----------------

#[test]
fn custody_audit_emitted_only_after_commit_and_replayable_via_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());

    // Staging alone touches no sink (the audit is a COMMIT-time, post-flip event).
    let good = RecordingSink::default();
    let staged = store.stage(R1).expect("stage");
    assert!(
        good.digests().is_empty(),
        "stage must not emit a custody audit"
    );

    // Commit with a FAILING sink: the flip is durable (authority is live) and commit returns
    // Ok(Committed) — a post-flip audit failure NEVER undoes the flip. A durable outbox
    // marker persists for replay.
    let outcome = store
        .commit(&staged.staging_token, &FailingSink)
        .expect("the flip stands even when the post-commit audit fails");
    assert!(
        matches!(outcome, CommitOutcome::Committed { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        store.current_ruleset().unwrap(),
        parse(R1),
        "the generation is live even though the post-commit audit failed"
    );
    assert_eq!(
        store.pending_audits().unwrap().len(),
        1,
        "a flipped generation with a failed audit has a durable pending marker"
    );

    // Recovery: boot classifies via adopt() (refreshing the live marker), then the drain replays the
    // pending audit through the real sink — the sink, not adopt, does the emitting.
    match store.adopt().expect("adopt") {
        AdoptOutcome::Adopted {
            canonical_digest,
            rule_count,
            ..
        } => {
            assert_eq!(canonical_digest, staged.canonical_digest);
            assert_eq!(rule_count, 1);
        }
        other => panic!("expected Adopted, got {other:?}"),
    }
    store.emit_pending_audits(&good).expect("replay");
    assert_eq!(good.digests(), vec![staged.canonical_digest.clone()]);
    assert!(
        store.pending_audits().unwrap().is_empty(),
        "the marker is cleared after the audit lands"
    );
    // Idempotent replay: adopting + draining again never double-chains.
    store.adopt().expect("adopt again");
    store.emit_pending_audits(&good).expect("replay again");
    assert_eq!(good.digests().len(), 1, "adoption replay is idempotent");
}

// ---- Commit binds staged bytes to the confirmed token --------------------------------------------

#[test]
fn commit_refuses_when_staged_bytes_do_not_match_token() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    let staged = store.stage(R1).expect("stage");
    // Tamper the staged record's canonical bytes so they no longer hash to the token the human
    // confirmed. The commit must refuse — it can never install bytes the ceremony did not cover.
    let path = dir
        .path()
        .join("sentence.staged")
        .join(&staged.staging_token);
    let mut rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    rec["canonical_text"] = serde_json::json!("allow stripe.refund where amount <= 999999\n");
    write_raw(&path, &serde_json::to_vec(&rec).unwrap(), 0o600);

    let err = store
        .commit(&staged.staging_token, &sink)
        .expect_err("commit must refuse staged bytes that do not hash to the token");
    assert!(matches!(err, Error::Denied(_)), "{err:?}");
    assert!(store.current_ruleset().is_err(), "nothing was installed");
    assert!(sink.digests().is_empty());
}

// ---- The audit sink runs with the record lock RELEASED -------------------------------------------

#[test]
fn commit_emits_audit_with_the_record_lock_released() {
    use std::sync::Arc as StdArc;
    let dir = tempfile::tempdir().unwrap();
    let store = StdArc::new(store_in(dir.path()));
    let staged = store.stage(R1).expect("stage");

    // A reentrant sink that reads the store's authority from INSIDE the audit callback. If commit
    // still held the record mutex, this same-thread re-lock would deadlock; it does not, because the
    // audit is emitted only AFTER the lock is released — no cross-thread wait happens under the lock.
    struct ReentrantSink {
        store: StdArc<SentenceRecordStore>,
        saw_live: Mutex<Option<bool>>,
    }
    impl CustodyAuditSink for ReentrantSink {
        fn record_committed(&self, _d: &str, _c: usize, _occ: &str) -> Result<AuditEmitted> {
            let live = self.store.current_ruleset().is_ok();
            *self.saw_live.lock().unwrap() = Some(live);
            Ok(AuditEmitted::Emitted)
        }
    }
    let sink = ReentrantSink {
        store: store.clone(),
        saw_live: Mutex::new(None),
    };
    store.commit(&staged.staging_token, &sink).expect("commit");
    assert_eq!(
        *sink.saw_live.lock().unwrap(),
        Some(true),
        "the audit callback observed the live record — the record lock was released before emit"
    );
}

// ---- Replay recovers EVERY pending generation across supersession + restart ----------------------

#[test]
fn adopt_replays_all_pending_generations_not_just_the_latest() {
    // The interleaving: A commits (its marker is written before the flip) but its audit sink is DOWN,
    // then B supersedes A (also sink-down), then a "restart" (adopt) drains the outbox through a real
    // sink — A's audit is NEVER lost despite supersession.
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let a = store.stage(R1).expect("stage A");
    store
        .commit(&a.staging_token, &FailingSink)
        .expect("commit A");
    let b = store.stage(R2).expect("stage B");
    store
        .commit(&b.staging_token, &FailingSink)
        .expect("commit B");
    assert_eq!(
        store.pending_audits().unwrap().len(),
        2,
        "both generations are pending"
    );

    // Restart: adopt classifies + refreshes the live marker; the replay emits BOTH the superseded (A)
    // and the live (B) generation's audits through a real sink.
    let good = RecordingSink::default();
    store.adopt().expect("adopt");
    store.emit_pending_audits(&good).expect("replay");
    let mut got = good.digests();
    got.sort();
    let mut want = vec![a.canonical_digest.clone(), b.canonical_digest.clone()];
    want.sort();
    assert_eq!(
        got, want,
        "a superseded generation's audit is NEVER dropped"
    );
    assert!(store.pending_audits().unwrap().is_empty());
}

#[test]
fn a_to_b_to_a_during_audit_outage_replays_three_occurrences() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    author(&store, &FailingSink, R1);
    author(&store, &FailingSink, R2);
    author(&store, &FailingSink, R1);

    let pending = store
        .pending_audits()
        .expect("all occurrence intents remain readable");
    assert_eq!(
        pending.len(),
        3,
        "A -> B -> A is three pending transition occurrences"
    );
    let occurrences: BTreeSet<_> = pending
        .iter()
        .map(|(_, _, occurrence)| occurrence)
        .collect();
    assert_eq!(occurrences.len(), 3);

    let replay = RecordingSink::default();
    store
        .emit_pending_audits(&replay)
        .expect("audit sink recovered");
    assert_eq!(replay.occurrences().len(), 3);
}

#[test]
fn record_v2_and_outbox_preserve_the_same_occurrence_and_actor_across_recovery() {
    type Attribution = (String, u32, String, Option<String>);

    #[derive(Default)]
    struct AttributedSink(StdMutex<Vec<Attribution>>);

    impl CustodyAuditSink for AttributedSink {
        fn record_committed(&self, _d: &str, _c: usize, _occ: &str) -> Result<AuditEmitted> {
            unreachable!("the attributed path is required")
        }

        fn record_committed_attributed(
            &self,
            _digest: &str,
            _count: usize,
            occurrence_id: &str,
            operator_uid: u32,
            acceptance_path: &str,
            prior_record: Option<&str>,
        ) -> Result<AuditEmitted> {
            self.0.lock().unwrap().push((
                occurrence_id.to_string(),
                operator_uid,
                acceptance_path.to_string(),
                prior_record.map(str::to_string),
            ));
            Ok(AuditEmitted::Emitted)
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let staged = store.stage(R1).unwrap();
    let outcome = store
        .commit_attributed(&staged.staging_token, 4242, "presence:test", &FailingSink)
        .unwrap();
    let occurrence = outcome.occurrence_id().to_string();
    let marker = store.read_marker(&occurrence).unwrap().unwrap();
    assert_eq!(marker.occurrence_id, occurrence);
    assert_eq!(marker.operator_uid, 4242);
    assert_eq!(marker.acceptance_path, "presence:test");
    assert!(matches!(
        store.snapshot().unwrap(),
        SentenceSnapshot::Served { occurrence_id, .. } if occurrence_id == occurrence
    ));

    let mut interrupted = marker;
    interrupted.confirmed = false;
    write_raw(
        &SentenceRecordStore::audit_pending_dir(dir.path()).join(&occurrence),
        &serde_json::to_vec(&interrupted).unwrap(),
        0o600,
    );
    let restarted = store_in(dir.path());
    restarted.adopt().unwrap();
    let recovered = restarted.read_marker(&occurrence).unwrap().unwrap();
    assert!(recovered.confirmed);
    assert_eq!(recovered.operator_uid, 4242);
    assert_eq!(recovered.acceptance_path, "presence:test");

    let sink = AttributedSink::default();
    restarted.emit_pending_audits(&sink).unwrap();
    assert_eq!(
        sink.0.lock().unwrap().as_slice(),
        &[(occurrence, 4242, "presence:test".into(), None)]
    );
}

// ---- An over-age staged corpus is refused at commit ----------------------------------------------

#[test]
fn commit_refuses_an_expired_staged_record() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    let staged = store.stage(R1).expect("stage");
    // Age the staged record far past the TTL (created_at_unix = 0).
    let path = dir
        .path()
        .join("sentence.staged")
        .join(&staged.staging_token);
    let mut rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    rec["created_at_unix"] = serde_json::json!(0);
    write_raw(&path, &serde_json::to_vec(&rec).unwrap(), 0o600);

    let err = store
        .commit(&staged.staging_token, &sink)
        .expect_err("an expired staged corpus must be refused");
    assert!(matches!(err, Error::Denied(_)), "{err:?}");
    assert!(store.current_ruleset().is_err());
}

// ---- An acknowledged stage/commit must be durable (dir-fsync failure fails closed) ---------------

/// Real file I/O except `fsync_dir`, which fails for exactly `fail_dir` (models a durability fault on
/// one directory). Relaxed reads (no security checks) — sufficient for the durability tests.
struct SelectiveFsyncFail {
    fail_dir: std::path::PathBuf,
}
impl RecordIo for SelectiveFsyncFail {
    fn read(&self, path: &Path, _owner: u32) -> Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Provider(e.to_string())),
        }
    }
    fn write_temp_and_fsync(
        &self,
        dir: &Path,
        name: &str,
        bytes: &[u8],
    ) -> std::io::Result<std::path::PathBuf> {
        std::fs::create_dir_all(dir)?;
        let temp = dir.join(format!(".{name}.{}.tmp", rand::random::<u64>()));
        std::fs::write(&temp, bytes)?;
        Ok(temp)
    }
    fn rename(&self, temp: &Path, final_path: &Path) -> std::io::Result<()> {
        std::fs::rename(temp, final_path)
    }
    fn fsync_dir(&self, dir: &Path) -> std::io::Result<()> {
        if dir == self.fail_dir {
            Err(std::io::Error::other("injected dir fsync failure"))
        } else {
            Ok(())
        }
    }
    fn remove(&self, temp: &Path) {
        let _ = std::fs::remove_file(temp);
    }
}

fn store_with_fsync_fail(dir: &Path, fail_dir: std::path::PathBuf) -> SentenceRecordStore {
    SentenceRecordStore::with_io(
        SentenceRecordStore::record_path(dir),
        SentenceRecordStore::staged_dir(dir),
        None,
        me(),
        Box::new(SelectiveFsyncFail { fail_dir }),
    )
}

#[test]
fn stage_fails_when_the_staging_dir_fsync_fails() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_with_fsync_fail(dir.path(), SentenceRecordStore::staged_dir(dir.path()));
    let err = store
        .stage(R1)
        .expect_err("a non-durable stage must fail closed");
    assert!(matches!(err, Error::Provider(_)), "{err:?}");
}

// ---- A FAILED parent-dir fsync is retried (not suppressed by `dir.exists()`) ---------------------

/// Real file I/O except `fsync_dir` of `target`, which fails the first `fail_count` calls then
/// succeeds — models a transient durability fault on one directory.
struct FsyncFailsNTimes {
    target: std::path::PathBuf,
    succeed_first: std::sync::atomic::AtomicUsize,
    remaining: std::sync::atomic::AtomicUsize,
}
impl RecordIo for FsyncFailsNTimes {
    fn read(&self, path: &Path, _owner: u32) -> Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Provider(e.to_string())),
        }
    }
    fn write_temp_and_fsync(
        &self,
        dir: &Path,
        name: &str,
        bytes: &[u8],
    ) -> std::io::Result<std::path::PathBuf> {
        std::fs::create_dir_all(dir)?;
        let temp = dir.join(format!(".{name}.{}.tmp", rand::random::<u64>()));
        std::fs::write(&temp, bytes)?;
        Ok(temp)
    }
    fn rename(&self, temp: &Path, final_path: &Path) -> std::io::Result<()> {
        std::fs::rename(temp, final_path)
    }
    fn fsync_dir(&self, dir: &Path) -> std::io::Result<()> {
        use std::sync::atomic::Ordering;
        if dir == self.target && self.succeed_first.load(Ordering::SeqCst) > 0 {
            self.succeed_first.fetch_sub(1, Ordering::SeqCst);
            return Ok(());
        }
        if dir == self.target && self.remaining.load(Ordering::SeqCst) > 0 {
            self.remaining.fetch_sub(1, Ordering::SeqCst);
            return Err(std::io::Error::other(
                "injected transient dir fsync failure",
            ));
        }
        Ok(())
    }
    fn remove(&self, temp: &Path) {
        let _ = std::fs::remove_file(temp);
    }
}

#[test]
fn ensure_dir_durable_retries_the_parent_fsync_after_a_transient_failure() {
    let dir = tempfile::tempdir().unwrap();
    // Fail the FIRST fsync of the state root (the PARENT of the lazily-created `sentence.staged/`),
    // then succeed. The first stage must fail closed; the SECOND must RETRY the parent fsync (governed
    // by the durability flag, not `dir.exists()`) and succeed.
    let store = SentenceRecordStore::with_io(
        SentenceRecordStore::record_path(dir.path()),
        SentenceRecordStore::staged_dir(dir.path()),
        None,
        me(),
        Box::new(FsyncFailsNTimes {
            target: dir.path().to_path_buf(),
            succeed_first: std::sync::atomic::AtomicUsize::new(0),
            remaining: std::sync::atomic::AtomicUsize::new(1),
        }),
    );
    let err = store
        .stage(R1)
        .expect_err("first stage fails closed on the parent-dir fsync fault");
    assert!(matches!(err, Error::Provider(_)), "{err:?}");
    // The directory now exists, but its parent durability was NOT achieved — the retry must re-fsync.
    store
        .stage(R1)
        .expect("second stage retries the parent fsync and succeeds");
}

// ---- Lazy staging/outbox dir creation fsyncs its PARENT (first write is durable) -----------------

#[test]
fn stage_fails_when_the_parent_dir_fsync_fails_on_first_creation() {
    let dir = tempfile::tempdir().unwrap();
    // Fail fsync on the state root — the PARENT of the lazily-created `sentence.staged/`. The first
    // stage must fail closed rather than acknowledge a crash-volatile new directory entry.
    let store = store_with_fsync_fail(dir.path(), dir.path().to_path_buf());
    let err = store
        .stage(R1)
        .expect_err("a non-durable staging-dir creation must fail closed");
    assert!(matches!(err, Error::Provider(_)), "{err:?}");
}

// ---- A no-op / skip sink can NEVER clear a pending audit -----------------------------------------

#[test]
fn noop_sink_never_clears_pending_markers() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let a = store.stage(R1).expect("stage");
    // A failed audit sink at commit leaves a durable pending marker.
    store
        .commit(&a.staging_token, &FailingSink)
        .expect("commit");
    assert_eq!(store.pending_audits().unwrap().len(), 1);
    // The production `NoopAuditSink` reports `Skipped`, so draining through it must NOT clear the
    // marker — otherwise boot's classify-only pass would destroy every pending audit.
    store
        .emit_pending_audits(&NoopAuditSink)
        .expect("a skip-only drain does not error");
    assert_eq!(
        store.pending_audits().unwrap().len(),
        1,
        "a no-op/skip sink must never clear a pending audit"
    );
    // A real sink then emits + clears it.
    let good = RecordingSink::default();
    store.emit_pending_audits(&good).expect("real drain");
    assert!(store.pending_audits().unwrap().is_empty());
    assert_eq!(good.digests(), vec![a.canonical_digest]);
}

// ---- A corrupt outbox marker is a LOUD error, never a silent skip --------------------------------

#[test]
fn corrupt_audit_marker_is_a_loud_error_not_silently_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let a = store.stage(R1).expect("stage");
    store
        .commit(&a.staging_token, &FailingSink)
        .expect("commit"); // one valid marker
                           // Plant a corrupt marker (non-numeric content) in the outbox.
    let outbox = SentenceRecordStore::audit_pending_dir(dir.path());
    let corrupt_name = "d".repeat(64);
    write_raw(&outbox.join(&corrupt_name), b"not json", 0o600);
    // The scan surfaces the corruption as a loud error — never a silent skip that strands the marker.
    assert!(
        store.pending_audits().is_err(),
        "a corrupt marker must be a loud error, never silently skipped"
    );
    assert!(
        outbox.join(&corrupt_name).exists(),
        "a marker that can't be interpreted is retained for the operator, never deleted"
    );
}

// ---- The marker is written BEFORE the flip, so a marker fault NEVER leaves an unaudited
//      flipped generation (marker-before-flip is the durability gate) -----------------------------

/// Real file I/O except `write_temp_and_fsync` into the OUTBOX dir, which fails — models a marker
/// write fault while writes into the staged/record dirs succeed.
struct AuditOutboxBroken {
    outbox: std::path::PathBuf,
}
impl RecordIo for AuditOutboxBroken {
    fn read(&self, path: &Path, _owner: u32) -> Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Provider(e.to_string())),
        }
    }
    fn write_temp_and_fsync(
        &self,
        dir: &Path,
        name: &str,
        bytes: &[u8],
    ) -> std::io::Result<std::path::PathBuf> {
        if dir == self.outbox {
            return Err(std::io::Error::other("injected audit-outbox write failure"));
        }
        std::fs::create_dir_all(dir)?;
        let temp = dir.join(format!(".{name}.{}.tmp", rand::random::<u64>()));
        std::fs::write(&temp, bytes)?;
        Ok(temp)
    }
    fn rename(&self, temp: &Path, final_path: &Path) -> std::io::Result<()> {
        std::fs::rename(temp, final_path)
    }
    fn fsync_dir(&self, _dir: &Path) -> std::io::Result<()> {
        Ok(())
    }
    fn remove(&self, temp: &Path) {
        let _ = std::fs::remove_file(temp);
    }
}

#[test]
fn marker_write_failure_fails_the_commit_before_the_flip() {
    let dir = tempfile::tempdir().unwrap();
    let store = SentenceRecordStore::with_io(
        SentenceRecordStore::record_path(dir.path()),
        SentenceRecordStore::staged_dir(dir.path()),
        None,
        me(),
        Box::new(AuditOutboxBroken {
            outbox: SentenceRecordStore::audit_pending_dir(dir.path()),
        }),
    );
    let sink = RecordingSink::default();
    let staged = store.stage(R1).expect("stage");
    // The audit marker (written BEFORE the flip) cannot be persisted. commit must FAIL, and NO flip may
    // be exposed — so there is never a flipped-but-unaudited generation for a later supersession to
    // lose. The marker is part of the durability gate.
    let err = store
        .commit(&staged.staging_token, &sink)
        .expect_err("a marker that cannot be written durably must fail the commit before the flip");
    assert!(matches!(err, Error::Provider(_)), "{err:?}");
    assert!(
        store.current_ruleset().is_err(),
        "the flip did NOT happen — no unaudited generation exists"
    );
    assert!(sink.digests().is_empty());
}

// ---- A future staged timestamp (clock rollback) is refused ---------------------------------------

#[test]
fn commit_refuses_a_future_staged_timestamp() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    let staged = store.stage(R1).expect("stage");
    // Rewrite the staged timestamp far into the future (models a clock rollback since staging).
    let path = dir
        .path()
        .join("sentence.staged")
        .join(&staged.staging_token);
    let mut rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    rec["created_at_unix"] = serde_json::json!(u64::MAX / 2);
    write_raw(&path, &serde_json::to_vec(&rec).unwrap(), 0o600);

    let err = store
        .commit(&staged.staging_token, &sink)
        .expect_err("a future staged timestamp is a clock anomaly and must be refused");
    assert!(matches!(err, Error::Denied(_)), "{err:?}");
    assert!(store.current_ruleset().is_err());
}

// ---- boot adoption gate ---------------------------------------------------------------------------

#[test]
fn fresh_boot_without_record_denies_all() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    assert!(
        store.current_ruleset().is_err(),
        "a fresh boot with no record must deny-all (fail closed)"
    );
    assert_eq!(store.adopt().unwrap(), AdoptOutcome::Absent);
    assert!(store.pending_audits().unwrap().is_empty());
}

#[test]
fn boot_adoption_gate_refuses_tampered_record() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    author(&store, &sink, R1);
    // Tamper a byte in the on-disk rule bytes: the embedded authority digest no longer matches.
    let path = SentenceRecordStore::record_path(dir.path());
    let mut raw = std::fs::read(&path).unwrap();
    let last = raw.len() - 2; // inside the rule bytes, before the trailing newline
    raw[last] ^= 0x20;
    write_raw(&path, &raw, 0o600);

    match store.adopt().expect("adopt") {
        AdoptOutcome::Corrupt { .. } => {}
        other => panic!("a tampered record must fail adoption (Corrupt), got {other:?}"),
    }
    assert!(
        store.current_ruleset().is_err(),
        "a tampered record denies sentence-routed requests until re-authored"
    );
    // A corrupt record is never adopted, so no marker is written for it (nothing to replay).
    assert!(
        store.pending_audits().unwrap().is_empty(),
        "a corrupt record chains no audit"
    );
}

// ---- The /etc projection is a regenerated READ view, never authority -----------------------------

#[test]
fn etc_projection_is_regenerated_on_commit_and_never_read_as_authority() {
    let dir = tempfile::tempdir().unwrap();
    let projection = dir.path().join("etc/rules.cermet");
    let store = SentenceRecordStore::new(
        SentenceRecordStore::record_path(dir.path()),
        SentenceRecordStore::staged_dir(dir.path()),
        Some(projection.clone()),
        me(),
    );
    let sink = RecordingSink::default();
    author(&store, &sink, R1);
    // The projection is regenerated on commit with the canonical bytes.
    assert_eq!(
        std::fs::read(&projection).unwrap(),
        canonical_rule_bytes(&parse(R1)),
        "commit regenerates the operator read projection"
    );
    // Tamper the projection: authority is unaffected — the record, not the projection, is truth.
    std::fs::write(&projection, b"allow stripe.refund where amount <= 999999\n").unwrap();
    assert_eq!(
        store.current_ruleset().unwrap(),
        parse(R1),
        "the projection is NEVER read as authority"
    );
    // A subsequent commit refreshes the projection back to the authoritative bytes.
    author(&store, &sink, R2);
    assert_eq!(
        std::fs::read(&projection).unwrap(),
        canonical_rule_bytes(&parse(R2))
    );
}

// ---- Security posture (fail closed on foreign / loose / non-canonical) ---------------------------

#[test]
fn stage_refuses_a_noncanonical_or_unpinned_proposal() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    // Definite no-stage for anything the one dialect does not spell. `set:` is a RESERVED prefix
    // form (so an unpinned set has no spelling at all), and a bare string value is
    // not a literal — both die at stage, before any record is written.
    for proposal in [
        "allow stripe.refund where customer in set:vips\n",
        "allow set:stripe.support\n",
        "allow stripe.refund where charge = ch_unquoted\n",
    ] {
        let err = store
            .stage(proposal)
            .expect_err("an off-dialect proposal must be refused before staging");
        assert!(matches!(err, Error::Invalid(_)), "{proposal:?}: {err:?}");
    }
}

#[test]
fn foreign_owner_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = SentenceRecordStore::new(
        SentenceRecordStore::record_path(dir.path()),
        SentenceRecordStore::staged_dir(dir.path()),
        None,
        me().wrapping_add(1), // expect a DIFFERENT owner than the file actually has
    );
    let sink = RecordingSink::default();
    // Author via a correctly-owned store, then read via the foreign-expecting store.
    author(&store_in(dir.path()), &sink, R1);
    assert!(
        store.current_ruleset().is_err(),
        "a record not owned by the expected uid must fail closed"
    );
}

#[test]
fn group_or_other_writable_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    author(&store, &sink, R1);
    let path = SentenceRecordStore::record_path(dir.path());
    let raw = std::fs::read(&path).unwrap();
    write_raw(&path, &raw, 0o660); // group-writable
    assert!(
        store.current_ruleset().is_err(),
        "a group/other-writable record must fail closed"
    );
}

#[test]
fn a_symlinked_record_fails_closed() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.record");
    write_raw(
        &real,
        &build_record(&canonical_rule_bytes(&parse(R1)), &"a".repeat(64)),
        0o600,
    );
    let path = SentenceRecordStore::record_path(dir.path());
    symlink(&real, &path).unwrap();
    let store = store_in(dir.path());
    assert!(
        store.current_ruleset().is_err(),
        "a symlinked record must fail closed (O_NOFOLLOW)"
    );
}

#[test]
fn sweep_removes_inert_staged_records() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    store.stage(R1).expect("stage");
    store.stage(R2).expect("stage");
    // ttl=0 sweeps everything staged (all are "older than 0s").
    assert_eq!(store.sweep_staged(0).unwrap(), 2);
    // ttl huge keeps nothing to sweep now.
    assert_eq!(store.sweep_staged(u64::MAX).unwrap(), 0);
}

// ---- Positive validation gate + two-state markers + staged peek ----------------------------------

#[test]
fn unvalidated_generation_denies_until_marked_validated() {
    // The POSITIVE gate (fail closed by default): `current_ruleset` serves ONLY a generation
    // `validate_corpus` demonstrably passed this process lifetime. A fresh process (boot before
    // validation, a transient boot read Err, or a raw on-disk edit) has an un-validated record ⇒ deny.
    let dir = tempfile::tempdir().unwrap();
    let digest = {
        let store = store_in(dir.path());
        let sink = RecordingSink::default();
        let d = author(&store, &sink, R1);
        // commit marks the just-committed generation validated (its caller pre-validated the bytes).
        assert_eq!(
            store.current_ruleset().unwrap(),
            parse(R1),
            "the committing process serves"
        );
        d
    };

    // A FRESH process over the same dir (models boot): the record is on disk but NOT yet validated this
    // lifetime ⇒ deny-all — an unvalidated adopted corpus must NOT serve, even if a read succeeds.
    let store2 = store_in(dir.path());
    let err = store2
        .current_ruleset()
        .expect_err("an un-validated generation must deny (positive gate)");
    assert!(
        err.to_string().contains("semantic validation"),
        "the deny names the gate: {err}"
    );

    // Marking THIS generation validated (as boot does after `validate_corpus` passes) restores service.
    store2.mark_generation_validated(&digest);
    assert_eq!(
        store2.current_ruleset().unwrap(),
        parse(R1),
        "validated ⇒ serves"
    );

    // A validation stamped for a DIFFERENT generation does NOT enable this record (digest-exact).
    store2.mark_generation_validated(&"f".repeat(64));
    assert!(
        store2.current_ruleset().is_err(),
        "the gate is exact — another generation's validation never serves this record"
    );
}

/// A deny-all that says only "did not pass semantic validation" tells the operator that something is
/// wrong and nothing about WHAT. The reason is the daemon's OWN validation text — never agent input,
/// so there is nothing to scrub — and it is the difference between a one-minute fix and a support
/// round trip. Boot adoption retains the failure; the deny renders it, still naming the recovery
/// commands.
#[test]
fn a_boot_validation_failure_is_named_in_the_deny_it_causes() {
    let dir = tempfile::tempdir().unwrap();
    let digest = {
        let store = store_in(dir.path());
        let sink = RecordingSink::default();
        author(&store, &sink, R1)
    };

    // A fresh process over the same dir (models boot). Before boot validation runs, the deny is the
    // generic one — nothing has been learned about this generation yet.
    let store2 = store_in(dir.path());
    let generic = store2.current_ruleset().unwrap_err().to_string();
    assert!(
        generic.contains("semantic validation"),
        "the pre-validation deny still names the gate: {generic}"
    );

    // Boot adoption ran `validate_corpus` over exactly these bytes and it FAILED. The daemon retains
    // that reason against the generation it was computed for.
    let reason = "rule 4: temporal clauses (`rate … per …`, `budget … per …`) are disabled \
                  (language_temporal_clauses in the daemon config): decisions are computed from the \
                  request alone";
    store2.mark_generation_validation_failed(&digest, reason);

    let named = store2
        .current_ruleset()
        .expect_err("a corpus that failed boot validation must still deny")
        .to_string();
    assert!(
        named.contains(reason),
        "the deny must name what actually failed: {named}"
    );
    assert!(
        named.contains("cermet doc check"),
        "the deny must name the command that reproduces the failure: {named}"
    );
    assert!(
        named.contains("cermet rules allow"),
        "the deny must still name the generic recovery command: {named}"
    );

    // The retained reason is DIGEST-EXACT: it explains the generation it was computed for, and is
    // never misattributed to a different record that is unvalidated for its own reason.
    let other = store_in(dir.path());
    other.mark_generation_validation_failed(&"f".repeat(64), "some other generation's problem");
    let unrelated = other.current_ruleset().unwrap_err().to_string();
    assert!(
        !unrelated.contains("some other generation's problem"),
        "another generation's failure must not be attributed to this record: {unrelated}"
    );
    assert!(
        unrelated.contains("semantic validation"),
        "with no failure for THIS generation the deny falls back to the generic text: {unrelated}"
    );

    // A later success clears it: the corpus that now serves carries no stale failure explanation.
    store2.mark_generation_validated(&digest);
    assert_eq!(
        store2.current_ruleset().unwrap(),
        parse(R1),
        "validated ⇒ serves"
    );
}

#[test]
fn orphan_pre_flip_marker_is_swept_never_emitted() {
    // (a) A crash between the pre-flip INTENT marker and the flip leaves an intent-only marker for a
    // generation that NEVER went live. adopt must SWEEP it (loud log) — replay must NOT fabricate a
    // "committed" audit for it.
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    // Establish a live generation R1 (committed + confirmed).
    author(&store, &sink, R1);

    // Simulate a DIFFERENT ceremony that wrote its intent marker but crashed before flipping: an
    // intent-only marker whose digest is NOT the live generation.
    let ghost = "a".repeat(64);
    let ghost_occurrence = "b".repeat(64);
    store
        .write_audit_intent(pending_marker(&ghost, 3, &ghost_occurrence, false))
        .expect("write ghost intent");
    assert!(
        store
            .pending_audits()
            .unwrap()
            .iter()
            .all(|(d, _, _)| d != &ghost),
        "an intent-only marker is not emittable"
    );

    // adopt (boot) sweeps the orphan intent (never-live), keeps the live confirmed marker.
    store.adopt().expect("adopt");
    let markers = store.pending_audits().unwrap();
    assert!(
        markers.iter().all(|(d, _, _)| d != &ghost),
        "the orphan intent marker was swept, never emitted"
    );

    // A full replay never emits the ghost.
    let sink2 = RecordingSink::default();
    store.emit_pending_audits(&sink2).expect("replay");
    assert!(
        !sink2.digests().contains(&ghost),
        "replay must never fabricate a committed audit for a never-live generation"
    );
}

#[test]
fn live_generation_with_unconfirmed_marker_is_confirmed_by_adopt() {
    // (b) A generation flips, but a crash lands immediately after the rename, before the confirm. The
    // marker is intent-only yet the generation IS live. On restart, adopt must CONFIRM it from the live
    // record (a flipped generation is always audited), then replay emits it.
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let sink = RecordingSink::default();
    let digest = author(&store, &sink, R1);

    // Force the live generation's marker back to INTENT-only (models the crash-after-rename window).
    let occurrence = live_occurrence(&store);
    let outbox = SentenceRecordStore::audit_pending_dir(dir.path());
    std::fs::create_dir_all(&outbox).unwrap();
    write_raw(
        &outbox.join(&occurrence),
        &serde_json::to_vec(&pending_marker(&digest, 1, &occurrence, false)).unwrap(),
        0o600,
    );
    assert!(
        store.pending_audits().unwrap().is_empty(),
        "an intent-only marker for the live gen is not yet emittable"
    );

    // adopt confirms the live generation's marker (the live record proves it flipped).
    store.adopt().expect("adopt");
    let pending = store.pending_audits().unwrap();
    assert_eq!(
        pending
            .iter()
            .map(|(d, c, _)| (d.clone(), *c))
            .collect::<Vec<_>>(),
        vec![(digest.clone(), 1)],
        "adopt confirmed the live gen's marker"
    );

    let sink2 = RecordingSink::default();
    store.emit_pending_audits(&sink2).expect("replay");
    assert_eq!(
        sink2.digests(),
        vec![digest],
        "the once-flipped live generation is audited"
    );
}

#[test]
fn superseded_but_confirmed_generation_keeps_its_audit() {
    // (c) A flips (confirmed), then B supersedes A (also confirmed). A's audit must STILL be emitted —
    // confirmation is a per-generation property, NOT "is it live now". Model A's audit as un-drained
    // (a failing sink at A's commit), then confirm B supersedes, then drain: BOTH emit.
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let digest_a = author(&store, &FailingSink, R1); // A commits+confirms; its audit did NOT drain
    let digest_b = author(&store, &FailingSink, R2); // B supersedes A; A is no longer live
    assert_ne!(digest_a, digest_b);
    assert_eq!(store.current_ruleset().unwrap(), parse(R2), "B is live");

    // adopt (boot) must NOT sweep A's marker — A WAS live (confirmed), so it keeps its audit.
    store.adopt().expect("adopt");
    let sink = RecordingSink::default();
    store.emit_pending_audits(&sink).expect("replay");
    let mut got = sink.digests();
    got.sort();
    let mut want = vec![digest_a, digest_b];
    want.sort();
    assert_eq!(
        got, want,
        "a superseded-but-once-live generation keeps its confirmed audit"
    );
}

#[test]
fn peek_staged_text_returns_exact_staged_bytes() {
    // The ctl Commit handler re-validates the EXACT staged bytes (peeked) BEFORE the flip, and
    // provisions that exact generation — never a live re-read. `peek_staged_text` exposes them.
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let staged = store.stage(R1).expect("stage");
    let peeked = store
        .peek_staged_text(&staged.staging_token)
        .expect("peek ok")
        .expect("staged text present");
    assert_eq!(
        peeked, staged.canonical_text,
        "peek returns the exact staged canonical text"
    );
    // The peeked bytes hash to the token (the ceremony is bytes-bound), so validating them ==
    // validating what will commit.
    assert_eq!(canonical_digest(peeked.as_bytes()), staged.canonical_digest);
    // An unknown token peeks nothing.
    assert!(store.peek_staged_text(&"a".repeat(64)).unwrap().is_none());
}

// ---- No confirm/validate for a generation whose flip has not had a SUCCESSFUL record-dir
//      fsync THIS process lifetime; a retry after fsync failure must re-fsync first ---------------

#[test]
fn a_retry_after_a_failed_record_dir_fsync_re_fsyncs_before_confirming() {
    let dir = tempfile::tempdir().unwrap();
    // The staging dir sits under a distinct parent so stage's fsync does not consume the injected
    // record-dir failure. With no outgoing generation to re-prove, the first target-dir fsync happens
    // after the record rename: the generation is visible but its durability is unknown.
    let store = SentenceRecordStore::with_io(
        SentenceRecordStore::record_path(dir.path()),
        dir.path().join("staged_area").join("sentence.staged"),
        None,
        me(),
        Box::new(FsyncFailsNTimes {
            target: dir.path().to_path_buf(), // the record's parent dir
            // The outbox's first-write parent fsync succeeds; fail the subsequent record-rename
            // durability fence, then let the lost-response retry re-prove it.
            succeed_first: std::sync::atomic::AtomicUsize::new(1),
            remaining: std::sync::atomic::AtomicUsize::new(1),
        }),
    );
    let sink = RecordingSink::default();

    let staged = store
        .stage(R1)
        .expect("stage (distinct staging parent fsync ok)");
    let err = store.commit(&staged.staging_token, &sink).expect_err(
        "the post-rename record-dir fsync fails, so the generation must remain unconfirmed",
    );
    assert!(matches!(err, Error::Provider(_)), "{err:?}");
    assert!(
        store.current_ruleset().is_err(),
        "an unproven-durable generation is never validated/served (mark_generation_validated skipped)"
    );

    // Lost-response retry: replay the SAME ceremony token. A fresh stage would intentionally mint a
    // distinct acceptance occurrence even for the same content; only this nonce identifies the
    // visible rename whose durability was unknown.
    let out = store
        .commit(&staged.staging_token, &sink)
        .expect("after a successful re-fsync the retry confirms + validates");
    assert!(
        matches!(out, CommitOutcome::AlreadyCommitted { .. }),
        "{out:?}"
    );
    assert_eq!(
        store.current_ruleset().unwrap(),
        parse(R1),
        "a generation whose flip was re-proven durable this lifetime is served"
    );
}

// ---- A legacy single-integer marker is UNCONFIRMED — a loud error, never confirmed ---------------

#[test]
fn a_legacy_single_integer_marker_is_a_loud_error_never_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let outbox = SentenceRecordStore::audit_pending_dir(dir.path());
    std::fs::create_dir_all(&outbox).unwrap();
    // The predecessor's PRE-FLIP single-integer format would fabricate authenticated "committed"
    // evidence from a never-live orphan. It must be a loud error (retained), never confirmed.
    let legacy = "d".repeat(64);
    write_raw(&outbox.join(&legacy), b"1", 0o600);
    assert!(
        store.pending_audits().is_err(),
        "a legacy single-integer marker must be a loud error, never treated as confirmed"
    );
    assert!(
        outbox.join(&legacy).exists(),
        "retained for the operator, never emitted or cleared"
    );
}

// ---- Strict marker parse — trailing/malformed tokens are loud + retained -------------------------

#[test]
fn a_marker_with_trailing_tokens_is_a_loud_error() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let outbox = SentenceRecordStore::audit_pending_dir(dir.path());
    std::fs::create_dir_all(&outbox).unwrap();
    // Valid is exactly `<count> <i|c> <occurrence_id>`; a FOURTH token is malformed.
    let malformed = "d".repeat(64);
    write_raw(&outbox.join(&malformed), b"1 c occ garbage", 0o600);
    assert!(
        store.pending_audits().is_err(),
        "a marker with trailing tokens must be a loud error, never accepted/emitted"
    );
    assert!(outbox.join(&malformed).exists(), "retained, never cleared");
    // An unknown state token is equally loud.
    let store2 = store_in(dir.path());
    write_raw(&outbox.join("c".repeat(64)), b"2 x occ", 0o600);
    assert!(store2.pending_audits().is_err());
}

// ---- A once-live generation whose confirm failed is CONFIRMED at supersession, never swept -------

#[test]
fn a_once_live_generation_with_a_failed_confirm_is_never_swept_on_supersession() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    // Commit A with a DOWN sink so A's confirmed marker persists.
    let a = store.stage(R1).expect("stage A");
    store
        .commit(&a.staging_token, &FailingSink)
        .expect("commit A");
    // Simulate A's POST-flip confirm having FAILED: downgrade A's marker to intent-only. A is live.
    let outbox = SentenceRecordStore::audit_pending_dir(dir.path());
    let a_occurrence = occurrence_for_nonce(&a.staging_token);
    write_raw(
        &outbox.join(&a_occurrence),
        &serde_json::to_vec(&pending_marker(
            &a.canonical_digest,
            1,
            &a_occurrence,
            false,
        ))
        .unwrap(),
        0o600,
    );
    assert!(!store.read_marker(&a_occurrence).unwrap().unwrap().confirmed);

    // Commit B (staged against A) supersedes A. A is provably live ⇒ CONFIRMED before the flip, so it
    // can never become a sweepable never-live orphan. A's occurrence id is PRESERVED across the
    // confirm (a re-confirm is the same transition, not a new one).
    let b = store.stage(R2).expect("stage B");
    store
        .commit(&b.staging_token, &FailingSink)
        .expect("commit B");
    assert!(
        store.read_marker(&a_occurrence).unwrap().unwrap().confirmed,
        "the outgoing live generation is confirmed at supersession, occurrence preserved"
    );

    // Restart: adopt classifies B, sweeps orphan INTENTS (A is CONFIRMED ⇒ not swept). Replay emits both.
    store.adopt().expect("adopt");
    let good = RecordingSink::default();
    store.emit_pending_audits(&good).expect("replay");
    let mut got = good.digests();
    got.sort();
    let mut want = vec![a.canonical_digest.clone(), b.canonical_digest.clone()];
    want.sort();
    assert_eq!(
        got, want,
        "the once-live superseded generation's audit is NEVER lost"
    );
}

// ---- Confirmed is ABSORBING — an intent write never downgrades a confirmed marker ----------------

#[test]
fn occurrence_keyed_intents_for_the_same_digest_never_overwrite_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let digest = "d".repeat(64);
    let first = "a".repeat(64);
    let second = "b".repeat(64);
    store
        .write_audit_intent(pending_marker(&digest, 3, &first, false))
        .expect("first intent");
    store.confirm_audit(&first).expect("confirm first");
    store
        .write_audit_intent(pending_marker(&digest, 3, &second, false))
        .expect("second same-content occurrence");

    assert!(store.read_marker(&first).unwrap().unwrap().confirmed);
    assert!(!store.read_marker(&second).unwrap().unwrap().confirmed);
}

// ---- The fsync-proving primitive gates the SUPERSESSION + ADOPT paths, never trusting a
//      visible-but-unfsynced record/marker rename -------------------------------------------------

fn distinct_staged(dir: &Path) -> std::path::PathBuf {
    dir.join("staged_area").join("sentence.staged")
}

#[test]
fn supersession_fails_if_the_outgoing_record_cannot_be_re_proven_durable() {
    let dir = tempfile::tempdir().unwrap();
    author(&store_in(dir.path()), &RecordingSink::default(), R1); // A live + durable
                                                                  // A store whose RECORD-dir (state-root) fsync always fails; its staging dir sits under a DISTINCT
                                                                  // parent so stage's own fsyncs succeed. Superseding A must re-prove A's record durable FIRST —
                                                                  // a failed fsync fails the commit; A is never superseded on a visible-but-unfsynced flip.
    let store = SentenceRecordStore::with_io(
        SentenceRecordStore::record_path(dir.path()),
        distinct_staged(dir.path()),
        None,
        me(),
        Box::new(FsyncFailsNTimes {
            target: dir.path().to_path_buf(),
            succeed_first: std::sync::atomic::AtomicUsize::new(0),
            remaining: std::sync::atomic::AtomicUsize::new(usize::MAX),
        }),
    );
    let staged = store.stage(R2).expect("stage B against live A");
    let err = store
        .commit(&staged.staging_token, &RecordingSink::default())
        .expect_err(
            "superseding must re-prove the outgoing record durable; a failed fsync fails it",
        );
    assert!(matches!(err, Error::Provider(_)), "{err:?}");
    // A (R1) is still live — B (R2) did NOT supersede it.
    match store_in(dir.path()).snapshot().unwrap() {
        SentenceSnapshot::Unserved { rules_text, .. } => {
            assert!(rules_text.contains("5000"), "A stays live: {rules_text}")
        }
        other => panic!("expected A still present but Unserved in a fresh store, got {other:?}"),
    }
}

#[test]
fn supersession_re_fsyncs_the_outbox_marker_never_trusting_a_visible_one() {
    let dir = tempfile::tempdir().unwrap();
    author(&store_in(dir.path()), &RecordingSink::default(), R1);
    let outbox = SentenceRecordStore::audit_pending_dir(dir.path());
    // A store whose OUTBOX-dir fsync always fails (record + staged fsyncs succeed — distinct targets).
    // Superseding must re-fsync the outgoing generation's MARKER (a visible-but-unfsynced `c` is never
    // trusted) — a failed outbox fsync fails the commit.
    let store = SentenceRecordStore::with_io(
        SentenceRecordStore::record_path(dir.path()),
        distinct_staged(dir.path()),
        None,
        me(),
        Box::new(FsyncFailsNTimes {
            target: outbox.clone(),
            succeed_first: std::sync::atomic::AtomicUsize::new(0),
            remaining: std::sync::atomic::AtomicUsize::new(usize::MAX),
        }),
    );
    let staged = store.stage(R2).expect("stage B");
    let err = store
        .commit(&staged.staging_token, &RecordingSink::default())
        .expect_err(
            "a failed outbox-dir fsync must fail the supersession (marker not proven durable)",
        );
    assert!(matches!(err, Error::Provider(_)), "{err:?}");
}

#[test]
fn adopt_refuses_a_visible_but_unfsynced_record() {
    let dir = tempfile::tempdir().unwrap();
    author(&store_in(dir.path()), &RecordingSink::default(), R1); // record on disk
                                                                  // A store whose record-dir fsync always fails: adopt must NOT confirm/serve a record it cannot
                                                                  // re-prove durable this process lifetime — it returns Err (boot then denies-all).
    let store = SentenceRecordStore::with_io(
        SentenceRecordStore::record_path(dir.path()),
        distinct_staged(dir.path()),
        None,
        me(),
        Box::new(FsyncFailsNTimes {
            target: dir.path().to_path_buf(),
            succeed_first: std::sync::atomic::AtomicUsize::new(0),
            remaining: std::sync::atomic::AtomicUsize::new(usize::MAX),
        }),
    );
    let err = store
        .adopt()
        .expect_err("adopt must re-prove the record durable before confirming a visible record");
    assert!(matches!(err, Error::Provider(_)), "{err:?}");
}

/// The corpus upgrade path, which is RE-AUTHORING and nothing else.
///
/// The corpus is stored as canonical sentence TEXT and re-parsed on every read, so a generation
/// written in a superseded dialect (`allow verb:stripe.refund where charge = ch_x`) cannot be
/// adopted. There is deliberately no migration: no backward compatibility, no rewrite-on-boot —
/// the daemon fails closed, and the refusal must name the failing line and the command that fixes
/// it, because a bare "does not parse" leaves the operator with nothing to act on.
#[test]
fn a_corpus_in_the_superseded_dialect_fails_closed_and_says_how_to_recover() {
    let old_dialect = b"allow verb:stripe.refund where charge = ch_x and amount <= 5000\n";
    let record = build_record(old_dialect, &"a".repeat(OCCURRENCE_ID_LEN));

    let Interpreted::Corrupt { reason, .. } = interpret(&record) else {
        panic!("an old-dialect corpus must never be adopted");
    };
    assert!(
        reason.contains("do not parse"),
        "the refusal must say the bytes did not parse: {reason}"
    );
    assert!(
        reason.contains("reserved"),
        "and carry the parser's own reason, not swallow it: {reason}"
    );
    assert!(
        reason.contains("cermet rules allow"),
        "and name the re-authoring command: {reason}"
    );
}
