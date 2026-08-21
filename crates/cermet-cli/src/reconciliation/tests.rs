use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::path::PathBuf;

use cermet_ipc::ctl::{LockdownSnapshot, SentenceAuthorityStatus, SentenceSnapshot};
use cermet_lang::sentence::{
    authority_digest_for, canonical_rule_bytes, parse_rules, pin_set_references,
    PreparedSentenceCorpus, PreparedSetSnapshot, Selector,
};
use cermet_lang::sets::SetResolver;

use super::*;

struct FakeClient {
    statuses: RefCell<VecDeque<Result<SentenceAuthorityStatus, String>>>,
    prepared_inputs: RefCell<Vec<String>>,
    prepare_failures: RefCell<VecDeque<Option<PreparationFailure>>>,
}

impl FakeClient {
    fn new(statuses: Vec<Result<SentenceAuthorityStatus, String>>) -> Self {
        Self {
            statuses: RefCell::new(statuses.into()),
            prepared_inputs: RefCell::new(Vec::new()),
            prepare_failures: RefCell::new(VecDeque::new()),
        }
    }

    fn with_prepare_failures(
        statuses: Vec<Result<SentenceAuthorityStatus, String>>,
        failures: Vec<Option<PreparationFailure>>,
    ) -> Self {
        Self {
            statuses: RefCell::new(statuses.into()),
            prepared_inputs: RefCell::new(Vec::new()),
            prepare_failures: RefCell::new(failures.into()),
        }
    }

    fn inputs(&self) -> Vec<String> {
        self.prepared_inputs.borrow().clone()
    }
}

impl ReconciliationClient for FakeClient {
    fn prepare(
        &self,
        candidate_text: String,
    ) -> Result<PreparedSentenceCorpus, PreparationFailure> {
        self.prepared_inputs
            .borrow_mut()
            .push(candidate_text.clone());
        if let Some(Some(failure)) = self.prepare_failures.borrow_mut().pop_front() {
            return Err(failure);
        }
        prepare_candidate(&candidate_text)
    }

    fn authority_status(&self) -> Result<SentenceAuthorityStatus, String> {
        let mut statuses = self.statuses.borrow_mut();
        if statuses.len() > 1 {
            statuses.pop_front().unwrap()
        } else {
            statuses
                .front()
                .cloned()
                .unwrap_or_else(|| Err("unavailable".into()))
        }
    }
}

#[test]
fn preparation_errors_keep_semantic_and_product_refusals_distinct_from_transport() {
    assert_eq!(
        classify_preparation_error(&cermet_lang::Error::Invalid("invalid candidate".into())),
        PreparationFailure::Invalid("invalid candidate".into())
    );
    assert_eq!(
        classify_preparation_error(&cermet_lang::Error::ProviderDisabled),
        PreparationFailure::ProviderDisabled
    );
    for error in [
        cermet_lang::Error::Denied("ctl authorization".into()),
        cermet_lang::Error::NotFound("endpoint".into()),
        cermet_lang::Error::Provider("transport".into()),
        cermet_lang::Error::Integrity("response".into()),
    ] {
        assert_eq!(
            classify_preparation_error(&error),
            PreparationFailure::Unavailable
        );
    }
}

fn prepare_candidate(candidate_text: &str) -> Result<PreparedSentenceCorpus, PreparationFailure> {
    let mut rules = parse_rules(candidate_text)
        .map_err(|error| PreparationFailure::Invalid(error.to_string()))?;
    let sets = cermet_lang::sets::VendoredSetResolver;
    pin_set_references(&mut rules, &sets)
        .map_err(|error| PreparationFailure::Invalid(error.to_string()))?;
    let canonical = canonical_rule_bytes(&rules);
    let mut set_snapshots = Vec::new();
    for (rule_index, rule) in rules.rules.iter().enumerate() {
        if let Selector::Set {
            provider,
            set,
            digest: Some(digest),
        } = &rule.selector
        {
            let snapshot = sets
                .snapshot(provider, set, digest)
                .expect("fake preparation resolves the vendored set");
            set_snapshots.push(PreparedSetSnapshot {
                rule_index,
                provider: provider.clone(),
                set: set.clone(),
                digest: digest.clone(),
                members: snapshot.members().to_vec(),
            });
        }
    }
    Ok(PreparedSentenceCorpus {
        canonical_text: String::from_utf8(canonical.clone()).unwrap(),
        canonical_digest: authority_digest_for(rules.version, &canonical),
        rule_count: rules.rules.len(),
        set_snapshots,
    })
}

struct SwitchOnPrepareClient {
    live: RefCell<SentenceAuthorityStatus>,
    replacement: SentenceAuthorityStatus,
    switch_on_call: usize,
    prepare_calls: Cell<usize>,
}

impl SwitchOnPrepareClient {
    fn new(
        live: SentenceAuthorityStatus,
        replacement: SentenceAuthorityStatus,
        switch_on_call: usize,
    ) -> Self {
        Self {
            live: RefCell::new(live),
            replacement,
            switch_on_call,
            prepare_calls: Cell::new(0),
        }
    }
}

impl ReconciliationClient for SwitchOnPrepareClient {
    fn prepare(
        &self,
        candidate_text: String,
    ) -> Result<PreparedSentenceCorpus, PreparationFailure> {
        let call = self.prepare_calls.get() + 1;
        self.prepare_calls.set(call);
        let prepared = prepare_candidate(&candidate_text)?;
        if call == self.switch_on_call {
            *self.live.borrow_mut() = self.replacement.clone();
        }
        Ok(prepared)
    }

    fn authority_status(&self) -> Result<SentenceAuthorityStatus, String> {
        Ok(self.live.borrow().clone())
    }
}

struct RewriteOnPrepareClient {
    live: SentenceAuthorityStatus,
    path: PathBuf,
    replacement: Vec<u8>,
    rewrite_on_call: usize,
    prepare_calls: Cell<usize>,
}

impl RewriteOnPrepareClient {
    fn new(
        live: SentenceAuthorityStatus,
        path: PathBuf,
        replacement: Vec<u8>,
        rewrite_on_call: usize,
    ) -> Self {
        Self {
            live,
            path,
            replacement,
            rewrite_on_call,
            prepare_calls: Cell::new(0),
        }
    }
}

impl ReconciliationClient for RewriteOnPrepareClient {
    fn prepare(
        &self,
        candidate_text: String,
    ) -> Result<PreparedSentenceCorpus, PreparationFailure> {
        let call = self.prepare_calls.get() + 1;
        self.prepare_calls.set(call);
        let prepared = prepare_candidate(&candidate_text)?;
        if call == self.rewrite_on_call {
            std::thread::sleep(std::time::Duration::from_millis(2));
            std::fs::write(&self.path, &self.replacement).unwrap();
        }
        Ok(prepared)
    }

    fn authority_status(&self) -> Result<SentenceAuthorityStatus, String> {
        Ok(self.live.clone())
    }
}

struct RewriteOnStatusClient {
    live: SentenceAuthorityStatus,
    path: PathBuf,
    replacement: Vec<u8>,
    rewrite_on_call: usize,
    status_calls: Cell<usize>,
}

struct ReplaceRootOnPrepareClient {
    live: SentenceAuthorityStatus,
    root: PathBuf,
    moved_root: PathBuf,
    replacement: Vec<u8>,
    replaced: Cell<bool>,
}

impl ReconciliationClient for ReplaceRootOnPrepareClient {
    fn prepare(
        &self,
        candidate_text: String,
    ) -> Result<PreparedSentenceCorpus, PreparationFailure> {
        let prepared = prepare_candidate(&candidate_text)?;
        if !self.replaced.replace(true) {
            std::fs::rename(&self.root, &self.moved_root).unwrap();
            std::fs::create_dir(&self.root).unwrap();
            std::fs::create_dir(self.root.join(".git")).unwrap();
            std::fs::write(self.root.join("CERMET.md"), &self.replacement).unwrap();
        }
        Ok(prepared)
    }

    fn authority_status(&self) -> Result<SentenceAuthorityStatus, String> {
        Ok(self.live.clone())
    }
}

impl ReconciliationClient for RewriteOnStatusClient {
    fn prepare(
        &self,
        candidate_text: String,
    ) -> Result<PreparedSentenceCorpus, PreparationFailure> {
        prepare_candidate(&candidate_text)
    }

    fn authority_status(&self) -> Result<SentenceAuthorityStatus, String> {
        let call = self.status_calls.get() + 1;
        self.status_calls.set(call);
        if call == self.rewrite_on_call {
            std::thread::sleep(std::time::Duration::from_millis(2));
            std::fs::write(&self.path, &self.replacement).unwrap();
        }
        Ok(self.live.clone())
    }
}

fn absent() -> SentenceAuthorityStatus {
    SentenceAuthorityStatus {
        sentence: SentenceSnapshot::Absent,
        lockdown: LockdownSnapshot::Clear,
    }
}

fn served(text: &str) -> SentenceAuthorityStatus {
    let rules = parse_rules(text).unwrap();
    let bytes = canonical_rule_bytes(&rules);
    assert_eq!(bytes, text.as_bytes());
    SentenceAuthorityStatus {
        sentence: SentenceSnapshot::Served {
            record_digest: "record".into(),
            rules_text: text.into(),
            authority_digest: authority_digest_for(rules.version, &bytes),
            occurrence_id: cermet_ipc::ctl::sentence_occurrence_for_token(&"b".repeat(64)),
            rule_count: rules.rules.len(),
        },
        lockdown: LockdownSnapshot::Clear,
    }
}

fn unserved(text: &str) -> SentenceAuthorityStatus {
    let served = served(text);
    let SentenceSnapshot::Served {
        record_digest,
        rules_text,
        authority_digest,
        occurrence_id,
        rule_count,
    } = served.sentence
    else {
        unreachable!()
    };
    SentenceAuthorityStatus {
        sentence: SentenceSnapshot::Unserved {
            record_digest,
            rules_text,
            authority_digest,
            occurrence_id,
            rule_count,
        },
        lockdown: LockdownSnapshot::Engaged,
    }
}

fn corrupt() -> SentenceAuthorityStatus {
    SentenceAuthorityStatus {
        sentence: SentenceSnapshot::Corrupt {
            record_digest: "record".into(),
            reason: "content-free".into(),
        },
        lockdown: LockdownSnapshot::Engaged,
    }
}

fn repository() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join(".git")).unwrap();
    directory
}

fn write_document(root: &Path, marker: &AuthorityMarker, body: &[u8], prose: &str) {
    let bytes = [
        prose.as_bytes(),
        format!(
            "\n<!-- cermet:authority:v1 -->\nPinned authority: `{}` <!-- cermet:pinned:v1 -->\n\n```cermet\n",
            marker.as_str()
        )
        .as_bytes(),
        body,
        b"```\n<!-- /cermet:authority:v1 -->\n",
    ]
    .concat();
    std::fs::write(root.join("CERMET.md"), bytes).unwrap();
}

fn marker_for(body: &str) -> AuthorityMarker {
    let analysis = crate::cermet_document::analyze_body(body).unwrap();
    AuthorityMarker::from_digest(analysis.digest)
}

fn assert_composed_status(
    body: &str,
    marker: AuthorityMarker,
    status: Result<SentenceAuthorityStatus, String>,
    expected: &str,
    exit: u8,
) {
    let repo = repository();
    write_document(repo.path(), &marker, body.as_bytes(), "ordinary prose");
    let text = run_status(&FakeClient::new(vec![status.clone()]), repo.path(), false);
    assert_eq!(text.exit_code, exit, "{}", text.text);
    assert!(
        text.text.starts_with(&format!("state: {expected}\n")),
        "{}",
        text.text
    );
    let json = run_status(&FakeClient::new(vec![status]), repo.path(), true);
    assert_eq!(json.exit_code, exit, "{}", json.text);
    let value: serde_json::Value = serde_json::from_str(&json.text).unwrap();
    assert_eq!(value["state"], expected, "{value}");
}

#[test]
fn status_composes_typed_candidate_marker_and_live_dimensions() {
    let a = "allow stripe.refund where amount <= 100\n";
    let b = "allow stripe.refund where amount <= 200\n";
    let c = "deny stripe.refund where amount >= 300\n";

    assert_composed_status(a, marker_for(a), Ok(served(a)), "aligned", 0);
    assert_composed_status(
        "",
        AuthorityMarker::none(),
        Ok(absent()),
        "aligned_no_authority",
        0,
    );
    assert_composed_status(b, marker_for(a), Ok(served(a)), "unapplied_document", 1);
    assert_composed_status(a, marker_for(a), Ok(served(b)), "unexported_live", 1);
    assert_composed_status(a, marker_for(b), Ok(served(a)), "marker_stale", 1);
    assert_composed_status(a, marker_for(b), Ok(served(c)), "diverged", 1);

    let missing = repository();
    let missing_output = run_status(&FakeClient::new(vec![Ok(absent())]), missing.path(), true);
    assert_eq!(missing_output.exit_code, 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&missing_output.text).unwrap()["state"],
        "repo_missing"
    );

    let invalid = repository();
    std::fs::write(invalid.path().join("CERMET.md"), b"not a managed document").unwrap();
    let invalid_output = run_status(&FakeClient::new(vec![Ok(absent())]), invalid.path(), true);
    assert_eq!(invalid_output.exit_code, 2);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&invalid_output.text).unwrap()["state"],
        "repo_invalid"
    );

    assert_composed_status(a, marker_for(a), Ok(unserved(a)), "dataplane_unserved", 2);
    assert_composed_status(a, marker_for(a), Ok(corrupt()), "dataplane_corrupt", 2);
    assert_composed_status(
        a,
        marker_for(a),
        Err("transport canary".into()),
        "dataplane_unknown",
        2,
    );
}

#[test]
fn mutation_document_sync_receipts_reuse_the_formal_repository_drift_model() {
    let old = "allow stripe.refund where amount <= 100\n";
    let live = "allow stripe.refund where amount <= 200\n";

    let missing = repository();
    assert_eq!(
        observe_mutation_document_sync(
            &FakeClient::new(vec![Ok(served(live))]),
            missing.path(),
            Some(&served(live)),
        ),
        CorpusDocumentSync::State("repo_missing")
    );

    let dirty = repository();
    write_document(
        dirty.path(),
        &marker_for(old),
        old.as_bytes(),
        "ordinary prose",
    );
    assert_eq!(
        observe_mutation_document_sync(
            &FakeClient::new(vec![Ok(served(live))]),
            dirty.path(),
            Some(&served(live)),
        ),
        CorpusDocumentSync::State("unexported_live")
    );

    let stale = repository();
    write_document(
        stale.path(),
        &marker_for(old),
        live.as_bytes(),
        "ordinary prose",
    );
    assert_eq!(
        observe_mutation_document_sync(
            &FakeClient::new(vec![Ok(served(live))]),
            stale.path(),
            Some(&served(live)),
        ),
        CorpusDocumentSync::State("marker_stale")
    );

    assert_eq!(
        observe_mutation_document_sync(
            &FakeClient::new(Vec::new()),
            &tempfile::tempdir().unwrap().path().join("not-a-repository"),
            Some(&served(live)),
        ),
        CorpusDocumentSync::Unavailable("no CERMET.md found from this directory")
    );
    assert_eq!(
        observe_mutation_document_sync(&FakeClient::new(Vec::new()), stale.path(), None),
        CorpusDocumentSync::Required
    );
}

#[test]
fn mutation_document_sync_refuses_to_pair_repository_bytes_with_a_stale_live_observation() {
    let old = "allow stripe.refund where amount <= 100\n";
    let winner = "allow stripe.refund where amount <= 200\n";
    let repo = repository();
    write_document(
        repo.path(),
        &marker_for(old),
        old.as_bytes(),
        "ordinary prose",
    );
    let client = SwitchOnPrepareClient::new(served(old), served(winner), 1);

    assert_eq!(
        observe_mutation_document_sync(&client, repo.path(), Some(&served(old))),
        CorpusDocumentSync::Required,
        "a changed live observation cannot be combined into a formal repository state"
    );
}

#[test]
fn mutation_document_sync_refuses_unstable_invalid_and_missing_repository_evidence() {
    let live = "allow stripe.refund where amount <= 200\n";

    let changed = repository();
    write_document(
        changed.path(),
        &marker_for(live),
        live.as_bytes(),
        "ordinary prose",
    );
    let replacement = render_template(&marker_for(live), live.as_bytes()).unwrap();
    let client = RewriteOnPrepareClient::new(
        served(live),
        changed.path().join("CERMET.md"),
        replacement,
        1,
    );
    assert_eq!(
        observe_mutation_document_sync(&client, changed.path(), Some(&served(live))),
        CorpusDocumentSync::Required,
        "a file change collapsed to Invalid is unstable, not formal repo_invalid"
    );

    let created = repository();
    let replacement = render_template(&marker_for(live), live.as_bytes()).unwrap();
    let client = RewriteOnStatusClient {
        live: served(live),
        path: created.path().join("CERMET.md"),
        replacement,
        rewrite_on_call: 1,
        status_calls: Cell::new(0),
    };
    assert_eq!(
        observe_mutation_document_sync(&client, created.path(), Some(&served(live))),
        CorpusDocumentSync::Required,
        "a document created during observation is unstable, not formal repo_invalid"
    );
}

#[test]
fn mutation_document_sync_refuses_a_replaced_physical_repository_root() {
    let live = "allow stripe.refund where amount <= 200\n";
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("repo");
    let moved_root = parent.path().join("replaced-repo");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join(".git")).unwrap();
    write_document(&root, &marker_for(live), live.as_bytes(), "ordinary prose");
    let replacement = render_template(&marker_for(live), live.as_bytes()).unwrap();
    let client = ReplaceRootOnPrepareClient {
        live: served(live),
        root: root.clone(),
        moved_root,
        replacement,
        replaced: Cell::new(false),
    };

    assert_eq!(
        observe_mutation_document_sync(&client, &root, Some(&served(live))),
        CorpusDocumentSync::Required,
        "a replacement checkout cannot inherit the held checkout's formal sync state"
    );
}

#[test]
fn check_and_fix_send_only_body_preserve_marker_and_never_render_prose() {
    const CANARY: &str = "M2_HOSTILE_PROSE_SECRET_CANARY";
    let repo = repository();
    let loose = " allow   stripe.refund where amount<=5000 # draft\n";
    write_document(
        repo.path(),
        &AuthorityMarker::none(),
        loose.as_bytes(),
        CANARY,
    );
    let client = FakeClient::new(Vec::new());

    let check = run_check(&client, repo.path(), false);
    assert_eq!(check.exit_code, 1);
    assert!(check.text.contains("canonical: no"));
    assert!(!check.text.contains(CANARY));
    assert_eq!(client.inputs(), vec![loose]);

    let fix = run_check(&client, repo.path(), true);
    assert_eq!(fix.exit_code, 0, "{}", fix.text);
    assert!(fix.text.contains("final_file: intended"));
    assert!(!fix.text.contains(CANARY));
    let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
    let parsed = ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(parsed.marker(), &AuthorityMarker::none());
    assert_eq!(parsed.body(), "allow stripe.refund where amount <= 5000\n");
    assert!(String::from_utf8(bytes).unwrap().contains(CANARY));
    assert!(client.inputs().iter().all(|input| !input.contains(CANARY)));
}

#[test]
fn oversized_prepare_frame_fails_before_the_client_is_called() {
    let repo = repository();
    let body = format!("# {}\n", "x".repeat(cermet_ipc::codec::MAX_FRAME as usize));
    write_document(
        repo.path(),
        &AuthorityMarker::none(),
        body.as_bytes(),
        "ordinary prose",
    );
    let client = FakeClient::new(Vec::new());
    let output = run_check(&client, repo.path(), false);
    assert_eq!(output.exit_code, 2);
    assert!(
        client.inputs().is_empty(),
        "oversize text must not cross the client seam"
    );
}

#[test]
fn init_hydrates_served_or_absent_and_refuses_clobber_or_corrupt() {
    let body = "allow stripe.refund where amount <= 5000\n";

    let served_repo = repository();
    let served_client = FakeClient::new(vec![Ok(served(body)), Ok(served(body))]);
    let output = run_init(&served_client, served_repo.path());
    assert_eq!(output.exit_code, 0, "{}", output.text);
    let bytes = std::fs::read(served_repo.path().join("CERMET.md")).unwrap();
    let parsed = ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(parsed.body(), body);
    assert_eq!(parsed.marker(), &marker_for(body));

    let absent_repo = repository();
    let absent_client = FakeClient::new(vec![Ok(absent()), Ok(absent())]);
    assert_eq!(run_init(&absent_client, absent_repo.path()).exit_code, 0);
    let bytes = std::fs::read(absent_repo.path().join("CERMET.md")).unwrap();
    let parsed = ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(parsed.body(), "");
    assert!(parsed.marker().is_none());

    let corrupt_repo = repository();
    assert_eq!(
        run_init(&FakeClient::new(vec![Ok(corrupt())]), corrupt_repo.path()).exit_code,
        2
    );
    assert!(!corrupt_repo.path().join("CERMET.md").exists());

    let existing = run_init(&served_client, served_repo.path());
    assert_eq!(existing.exit_code, 2);
    assert!(existing.text.contains("already exists"));
}

#[test]
fn export_preserves_prose_guards_drafts_and_allows_marker_only_repair() {
    const PROSE: &str = "EXPORT_PROSE_CANARY";
    let live = "allow stripe.refund where amount <= 5000\n";
    let draft = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(live), draft.as_bytes(), PROSE);

    let refused = run_export(&FakeClient::new(vec![Ok(served(live))]), repo.path(), false);
    assert_eq!(refused.exit_code, 1);
    assert!(refused.text.contains("unapplied document edits preserved"));
    assert_eq!(
        ManagedDocument::parse(&std::fs::read(repo.path().join("CERMET.md")).unwrap())
            .unwrap()
            .body(),
        draft
    );

    let client = FakeClient::new(vec![Ok(served(live)), Ok(served(live))]);
    let exported = run_export(&client, repo.path(), true);
    assert_eq!(exported.exit_code, 0, "{}", exported.text);
    assert!(exported.text.contains("state: aligned"));
    assert!(exported.text.contains("final_file: intended"));
    assert!(!exported.text.contains(PROSE));
    let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
    let parsed = ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(parsed.body(), live);
    assert_eq!(parsed.marker(), &marker_for(live));
    assert!(String::from_utf8(bytes).unwrap().contains(PROSE));
    assert!(client.inputs().iter().all(|input| !input.contains(PROSE)));

    let marker_repo = repository();
    write_document(
        marker_repo.path(),
        &AuthorityMarker::none(),
        live.as_bytes(),
        PROSE,
    );
    let marker_client = FakeClient::new(vec![Ok(served(live)), Ok(served(live))]);
    let repaired = run_export(&marker_client, marker_repo.path(), false);
    assert_eq!(repaired.exit_code, 0, "{}", repaired.text);
    let bytes = std::fs::read(marker_repo.path().join("CERMET.md")).unwrap();
    assert_eq!(ManagedDocument::parse(&bytes).unwrap().body(), live);
}

#[test]
fn first_export_treats_untouched_initialized_empty_document_as_the_absent_baseline() {
    let live = "allow stripe.refund where amount <= 5000\n";
    let repo = repository();
    write_document(repo.path(), &AuthorityMarker::none(), b"", "ordinary prose");
    let client = FakeClient::new(vec![Ok(served(live)), Ok(served(live))]);

    let exported = run_export(&client, repo.path(), false);

    assert_eq!(exported.exit_code, 0, "{}", exported.text);
    assert!(
        exported.text.contains("state: aligned"),
        "{}",
        exported.text
    );
    let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
    let document = ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(document.body(), live);
    assert_eq!(document.marker(), &marker_for(live));
}

#[test]
fn export_reports_a_concurrent_live_change_as_unexported() {
    let first = "allow stripe.refund where amount <= 5000\n";
    let second = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(first), first.as_bytes(), "prose");
    let client = FakeClient::new(vec![Ok(served(first)), Ok(served(second))]);
    let output = run_export(&client, repo.path(), false);
    assert_eq!(output.exit_code, 1, "{}", output.text);
    assert!(
        output.text.contains("state: unexported_live"),
        "{}",
        output.text
    );
    assert!(output.text.contains("live_changed: yes"), "{}", output.text);
}

#[test]
fn init_rechecks_live_after_final_document_preparation() {
    let first = "allow stripe.refund where amount <= 5000\n";
    let second = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    let client = SwitchOnPrepareClient::new(served(first), served(second), 2);

    let output = run_init(&client, repo.path());

    assert_eq!(output.exit_code, 1, "{}", output.text);
    assert!(
        output.text.contains("state: unexported_live"),
        "{}",
        output.text
    );
    assert!(output.text.contains("live_changed: yes"), "{}", output.text);
    let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
    let document = ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(document.body(), first);
    assert_eq!(document.marker(), &marker_for(first));
}

#[test]
fn init_existing_document_observes_live_after_document_preparation() {
    let first = "allow stripe.refund where amount <= 5000\n";
    let second = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(first), first.as_bytes(), "prose");
    let client = SwitchOnPrepareClient::new(served(first), served(second), 1);

    let output = run_init(&client, repo.path());

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(output.text.contains("already exists"), "{}", output.text);
    assert!(
        output.text.contains("state: unexported_live"),
        "{}",
        output.text
    );
}

#[test]
fn export_observes_live_after_document_preparation_before_guarding_drafts() {
    let first = "allow stripe.refund where amount <= 5000\n";
    let second = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(first), second.as_bytes(), "prose");
    let client = SwitchOnPrepareClient::new(served(first), served(second), 1);

    let output = run_export(&client, repo.path(), false);

    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(output.text.contains("state: aligned"), "{}", output.text);
    let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
    let document = ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(document.body(), second);
    assert_eq!(document.marker(), &marker_for(second));
}

#[test]
fn export_rechecks_live_after_final_document_preparation() {
    let first = "allow stripe.refund where amount <= 5000\n";
    let second = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(first), first.as_bytes(), "prose");
    let client = SwitchOnPrepareClient::new(served(first), served(second), 3);

    let output = run_export(&client, repo.path(), false);

    assert_eq!(output.exit_code, 1, "{}", output.text);
    assert!(
        output.text.contains("state: unexported_live"),
        "{}",
        output.text
    );
    assert!(output.text.contains("live_changed: yes"), "{}", output.text);
    let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
    let document = ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(document.body(), first);
    assert_eq!(document.marker(), &marker_for(first));
}

#[test]
fn init_final_report_uses_the_file_bytes_after_daemon_preparation() {
    let intended = "allow stripe.refund where amount <= 5000\n";
    let replacement = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    let replacement_bytes =
        render_template(&marker_for(replacement), replacement.as_bytes()).unwrap();
    let client = RewriteOnPrepareClient::new(
        served(intended),
        repo.path().join("CERMET.md"),
        replacement_bytes.clone(),
        2,
    );

    let output = run_init(&client, repo.path());

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("state: repo_invalid"),
        "{}",
        output.text
    );
    assert!(output.text.contains("interference: yes"), "{}", output.text);
    assert!(
        output.text.contains("final_file: changed"),
        "{}",
        output.text
    );
    assert_eq!(
        std::fs::read(repo.path().join("CERMET.md")).unwrap(),
        replacement_bytes
    );
}

#[test]
fn export_final_report_uses_the_file_bytes_after_daemon_preparation() {
    let intended = "allow stripe.refund where amount <= 5000\n";
    let replacement = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(
        repo.path(),
        &marker_for(intended),
        intended.as_bytes(),
        "prose",
    );
    let replacement_bytes =
        render_template(&marker_for(replacement), replacement.as_bytes()).unwrap();
    let client = RewriteOnPrepareClient::new(
        served(intended),
        repo.path().join("CERMET.md"),
        replacement_bytes.clone(),
        3,
    );

    let output = run_export(&client, repo.path(), false);

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("state: repo_invalid"),
        "{}",
        output.text
    );
    assert!(output.text.contains("interference: yes"), "{}", output.text);
    assert!(
        output.text.contains("final_file: changed"),
        "{}",
        output.text
    );
    assert_eq!(
        std::fs::read(repo.path().join("CERMET.md")).unwrap(),
        replacement_bytes
    );
}

#[test]
fn init_never_calls_a_status_time_file_rewrite_aligned() {
    let intended = "allow stripe.refund where amount <= 5000\n";
    let replacement = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    let replacement_bytes =
        render_template(&marker_for(replacement), replacement.as_bytes()).unwrap();
    let client = RewriteOnStatusClient {
        live: served(intended),
        path: repo.path().join("CERMET.md"),
        replacement: replacement_bytes,
        rewrite_on_call: 2,
        status_calls: Cell::new(0),
    };

    let output = run_init(&client, repo.path());

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("state: repo_invalid"),
        "{}",
        output.text
    );
    assert!(output.text.contains("interference: yes"), "{}", output.text);
    assert!(
        output.text.contains("final_file: changed"),
        "{}",
        output.text
    );
}

#[test]
fn init_detects_an_identical_byte_in_place_rewrite_during_preparation() {
    let intended = "allow stripe.refund where amount <= 5000\n";
    let repo = repository();
    let intended_bytes = render_template(&marker_for(intended), intended.as_bytes()).unwrap();
    let client = RewriteOnPrepareClient::new(
        served(intended),
        repo.path().join("CERMET.md"),
        intended_bytes,
        2,
    );

    let output = run_init(&client, repo.path());

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("state: repo_invalid"),
        "{}",
        output.text
    );
    assert!(output.text.contains("interference: yes"), "{}", output.text);
    assert!(
        output.text.contains("final_file: intended"),
        "{}",
        output.text
    );
}

#[test]
fn status_and_diff_recheck_the_file_after_their_last_daemon_call() {
    let intended = "allow stripe.refund where amount <= 5000\n";
    for diff in [false, true] {
        let repo = repository();
        let intended_bytes = render_template(&marker_for(intended), intended.as_bytes()).unwrap();
        std::fs::write(repo.path().join("CERMET.md"), &intended_bytes).unwrap();
        let client = RewriteOnStatusClient {
            live: served(intended),
            path: repo.path().join("CERMET.md"),
            replacement: intended_bytes,
            rewrite_on_call: 1,
            status_calls: Cell::new(0),
        };

        let output = if diff {
            run_diff(&client, repo.path())
        } else {
            run_status(&client, repo.path(), false)
        };

        assert_eq!(output.exit_code, 2, "{}", output.text);
        assert!(
            output.text.contains("state: repo_invalid"),
            "{}",
            output.text
        );
    }
}

#[test]
fn export_refuses_an_identical_byte_rewrite_before_replace() {
    let intended = "allow stripe.refund where amount <= 5000\n";
    let repo = repository();
    let intended_bytes = render_template(&marker_for(intended), intended.as_bytes()).unwrap();
    std::fs::write(repo.path().join("CERMET.md"), &intended_bytes).unwrap();
    let client = RewriteOnPrepareClient::new(
        served(intended),
        repo.path().join("CERMET.md"),
        intended_bytes,
        2,
    );

    let output = run_export(&client, repo.path(), false);

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output
            .text
            .contains("file changed before the safe replacement"),
        "{}",
        output.text
    );
}

#[test]
fn export_of_absent_authority_writes_empty_none_and_aligns() {
    let live = "allow stripe.refund where amount <= 5000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(live), live.as_bytes(), "prose");
    let client = FakeClient::new(vec![Ok(absent()), Ok(absent())]);
    let output = run_export(&client, repo.path(), false);
    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(output.text.contains("state: aligned_no_authority"));
    let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
    let parsed = ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(parsed.body(), "");
    assert!(parsed.marker().is_none());
}

#[test]
fn comments_only_source_is_draft_not_aligned_no_authority() {
    let repo = repository();
    write_document(
        repo.path(),
        &AuthorityMarker::none(),
        b"# reviewed source is not exactly empty\n",
        "prose",
    );
    let client = FakeClient::new(vec![Ok(absent())]);

    let output = run_status(&client, repo.path(), true);

    assert_eq!(output.exit_code, 1, "{}", output.text);
    let value: serde_json::Value = serde_json::from_str(&output.text).unwrap();
    assert_eq!(value["state"], "unapplied_document", "{value}");
    assert_eq!(value["canonical"], false, "{value}");
}

#[test]
fn diff_has_marker_only_semantics_and_deterministic_set_member_changes() {
    let rule = "allow stripe.refund\n";
    assert_eq!(unified_rule_diff(rule, rule), "rules: unchanged");

    let old = prepared_set_corpus(0, 'a', &["lookup_customer", "refund"], "");
    let new = prepared_set_corpus(0, 'b', &["credit_balance", "refund"], "");
    assert_eq!(
        render_set_diff(&old, &new),
        "set stripe.support (occurrence 1):\n- lookup_customer\n+ credit_balance"
    );
}

/// Regression: `doc diff` exists to answer "what would applying this change?", so a one-line edit
/// must render as one line.
///
/// Dumping the whole document as `-` followed by the whole live corpus as `+` makes a 23-rule
/// corpus render 47 changed lines for a single added sentence — and in the reverted orientation the
/// `+` side would be the authority you already have rather than the one you are proposing.
#[test]
fn a_one_line_edit_renders_as_one_line_in_the_apply_direction() {
    let live = "allow stripe.get_charge\n\
                allow stripe.list_active_prices\n\
                allow stripe.search_customers\n";
    let document = "allow stripe.get_charge\n\
                    allow stripe.list_active_prices\n\
                    allow stripe.search_customers\n\
                    allow stripe.refund where amount <= 5000\n";

    let added = unified_rule_diff(document, live);
    assert_eq!(
        added,
        "--- live\n\
         +++ document\n\
         @@ -3,1 +3,2 @@\n\
         \x20allow stripe.search_customers\n\
         +allow stripe.refund where amount <= 5000",
        "adding one sentence must show one `+` line, in the direction apply moves"
    );

    // The reverse edit is the same hunk with the sign flipped — and the untouched rules stay out of
    // the changed set either way.
    let removed = unified_rule_diff(live, document);
    assert_eq!(
        removed,
        "--- live\n\
         +++ document\n\
         @@ -3,2 +3,1 @@\n\
         \x20allow stripe.search_customers\n\
         -allow stripe.refund where amount <= 5000",
        "removing one sentence must show one `-` line"
    );

    // A middle edit keeps both neighbours as context and changes exactly the line that changed.
    let edited = "allow stripe.get_charge\n\
                  allow stripe.list_active_prices where product = \"prod_x\"\n\
                  allow stripe.search_customers\n";
    let changed = unified_rule_diff(edited, live);
    assert_eq!(
        changed.lines().filter(|l| l.starts_with('-')).count(),
        2,
        "one replaced line plus the `--- live` header: {changed}"
    );
    assert_eq!(
        changed.lines().filter(|l| l.starts_with('+')).count(),
        2,
        "one replaced line plus the `+++ document` header: {changed}"
    );
    assert!(
        changed.contains(" allow stripe.get_charge"),
        "the untouched neighbour must survive as context, not as a change: {changed}"
    );
    assert!(
        !changed.contains("-allow stripe.get_charge"),
        "an untouched rule must never be rendered as removed: {changed}"
    );

    // Identical corpora still short-circuit.
    assert_eq!(unified_rule_diff(live, live), "rules: unchanged");
}

#[test]
fn duplicate_set_rules_do_not_union_away_member_changes() {
    let document = prepared_duplicate_set_corpus(&[('a', "lookup_customer"), ('b', "refund")]);
    let live = prepared_duplicate_set_corpus(&[('b', "refund"), ('a', "lookup_customer")]);
    let output = render_set_diff(&document, &live);
    assert!(output.contains("occurrence 1"), "{output}");
    assert!(output.contains("occurrence 2"), "{output}");
}

#[test]
fn set_deltas_ignore_unrelated_rule_positions() {
    let document = prepared_set_corpus(
        1,
        'a',
        &["lookup_customer", "refund"],
        "deny stripe.refund where amount >= 9000\n",
    );
    let live = prepared_set_corpus(0, 'a', &["lookup_customer", "refund"], "");

    assert_eq!(render_set_diff(&document, &live), "");
}

fn prepared_set_corpus(
    rule_index: usize,
    digest_char: char,
    members: &[&str],
    prefix: &str,
) -> PreparedSentenceCorpus {
    let digest = format!("sha256:{}", digest_char.to_string().repeat(64));
    let rule = format!("allow stripe.support@{digest}\n");
    let canonical_text = format!("{prefix}{rule}");
    PreparedSentenceCorpus {
        canonical_digest: authority_digest_for(
            cermet_lang::sentence::RULE_SET_VERSION,
            canonical_text.as_bytes(),
        ),
        canonical_text,
        rule_count: rule_index + 1,
        set_snapshots: vec![PreparedSetSnapshot {
            rule_index,
            provider: "stripe".into(),
            set: "support".into(),
            digest,
            members: members.iter().map(|member| (*member).to_string()).collect(),
        }],
    }
}

fn prepared_duplicate_set_corpus(entries: &[(char, &str)]) -> PreparedSentenceCorpus {
    let canonical_text = entries
        .iter()
        .map(|(digest, _)| {
            format!(
                "allow stripe.support@sha256:{}\n",
                digest.to_string().repeat(64)
            )
        })
        .collect::<String>();
    PreparedSentenceCorpus {
        canonical_digest: authority_digest_for(
            cermet_lang::sentence::RULE_SET_VERSION,
            canonical_text.as_bytes(),
        ),
        canonical_text,
        rule_count: entries.len(),
        set_snapshots: entries
            .iter()
            .enumerate()
            .map(|(rule_index, (digest, member))| PreparedSetSnapshot {
                rule_index,
                provider: "stripe".into(),
                set: "support".into(),
                digest: format!("sha256:{}", digest.to_string().repeat(64)),
                members: vec![(*member).to_string()],
            })
            .collect(),
    }
}

#[test]
fn malformed_prepared_view_is_rejected_without_a_panic() {
    let malformed = PreparedSentenceCorpus {
        canonical_text: "allow stripe.refund\n".into(),
        canonical_digest: "not-a-digest".into(),
        rule_count: 1,
        set_snapshots: Vec::new(),
    };
    assert!(!prepared_view_is_valid(&malformed));

    let wrong_count = PreparedSentenceCorpus {
        canonical_digest: authority_digest_for(
            cermet_lang::sentence::RULE_SET_VERSION,
            b"allow stripe.refund\n",
        ),
        rule_count: 2,
        ..malformed
    };
    assert!(!prepared_view_is_valid(&wrong_count));
}

#[test]
fn status_json_remains_json_when_repository_discovery_fails() {
    let outside = tempfile::tempdir().unwrap();
    let output = run_status(
        &FakeClient::new(Vec::new()),
        &outside.path().join("missing"),
        true,
    );
    assert_eq!(output.exit_code, 2);
    let value: serde_json::Value = serde_json::from_str(&output.text).unwrap();
    assert_eq!(value["state"], "dataplane_unknown");
    assert_eq!(value["document"], "invalid");
}

#[test]
fn status_unknown_is_stable_and_never_echoes_transport_or_prose() {
    const CANARY: &str = "STATUS_PROSE_CANARY";
    let repo = repository();
    write_document(repo.path(), &AuthorityMarker::none(), b"", CANARY);
    let client = FakeClient::new(vec![Err("SECRET_TRANSPORT_DETAIL".into())]);
    let output = run_status(&client, repo.path(), true);
    assert_eq!(output.exit_code, 2);
    let value: serde_json::Value = serde_json::from_str(&output.text).unwrap();
    assert_eq!(value["state"], "dataplane_unknown");
    assert_eq!(value["document"], "valid");
    assert!(!output.text.contains(CANARY));
    assert!(!output.text.contains("SECRET_TRANSPORT_DETAIL"));
    assert_eq!(client.inputs(), vec![String::new()]);
}

#[test]
fn repository_and_daemon_dimensions_are_observed_independently() {
    let missing = repository();
    let output = run_status(&FakeClient::new(vec![Ok(corrupt())]), missing.path(), true);
    let value: serde_json::Value = serde_json::from_str(&output.text).unwrap();
    assert_eq!(value["state"], "dataplane_corrupt", "{value}");
    assert_eq!(value["document"], "missing", "{value}");
    assert_eq!(value["live_state"], "corrupt", "{value}");
    assert_eq!(value["lockdown"], "engaged", "{value}");

    let invalid = repository();
    std::fs::write(invalid.path().join("CERMET.md"), b"invalid").unwrap();
    let output = run_status(
        &FakeClient::new(vec![Ok(unserved(
            "allow stripe.refund where amount <= 5000\n",
        ))]),
        invalid.path(),
        true,
    );
    let value: serde_json::Value = serde_json::from_str(&output.text).unwrap();
    assert_eq!(value["state"], "dataplane_unserved", "{value}");
    assert_eq!(value["document"], "invalid", "{value}");
    assert_eq!(value["lockdown"], "engaged", "{value}");

    let outside = tempfile::tempdir().unwrap();
    let output = run_status(
        &FakeClient::new(vec![Ok(corrupt())]),
        &outside.path().join("missing"),
        true,
    );
    let value: serde_json::Value = serde_json::from_str(&output.text).unwrap();
    assert_eq!(value["state"], "dataplane_corrupt", "{value}");
    assert_eq!(value["document"], "invalid", "{value}");
    assert_eq!(value["lockdown"], "engaged", "{value}");

    let diff = run_diff(&FakeClient::new(vec![Ok(corrupt())]), missing.path());
    assert_eq!(diff.exit_code, 2, "{}", diff.text);
    assert!(
        diff.text.contains("state: dataplane_corrupt"),
        "{}",
        diff.text
    );
    assert!(diff.text.contains("document: missing"), "{}", diff.text);
    assert!(diff.text.contains("lockdown: engaged"), "{}", diff.text);
}

/// Regression: a candidate rejected by the daemon's semantic validation must not render only
/// "repository candidate is invalid" — the reason, naming the illegal predicate, has to travel or
/// the operator is left to diagnose via the catalog.
#[test]
fn an_invalid_candidate_names_the_daemons_reason_not_just_the_fact() {
    let body = "allow stripe.refund where amount <= 5000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(body), body.as_bytes(), "prose");
    let client = FakeClient::with_prepare_failures(
        vec![Ok(served(body))],
        vec![Some(PreparationFailure::Invalid(
            "field `base` is not a predicate of github.merge_pull_request".into(),
        ))],
    );

    let check = run_check(&client, repo.path(), false);
    assert_eq!(check.exit_code, 2, "{}", check.text);
    assert!(
        check
            .text
            .contains("field `base` is not a predicate of github.merge_pull_request"),
        "the reason must reach the operator: {}",
        check.text
    );
}

#[test]
fn transport_unavailability_never_becomes_semantic_invalid_or_unserved() {
    let body = "allow stripe.refund where amount <= 5000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(body), body.as_bytes(), "prose");

    let unavailable = FakeClient::with_prepare_failures(
        vec![Ok(served(body))],
        vec![Some(PreparationFailure::Unavailable)],
    );
    let output = run_status(&unavailable, repo.path(), true);
    let value: serde_json::Value = serde_json::from_str(&output.text).unwrap();
    assert_eq!(value["state"], "dataplane_unknown", "{value}");
    assert_eq!(value["document"], "unavailable", "{value}");
    assert_eq!(value["live_state"], "served", "{value}");

    let semantic = FakeClient::with_prepare_failures(
        vec![Ok(served(body))],
        vec![Some(PreparationFailure::Invalid("semantic refusal".into()))],
    );
    let output = run_status(&semantic, repo.path(), true);
    let value: serde_json::Value = serde_json::from_str(&output.text).unwrap();
    assert_eq!(value["state"], "repo_invalid", "{value}");
    assert_eq!(value["document"], "invalid", "{value}");

    let live_prepare_unavailable = FakeClient::with_prepare_failures(
        vec![Ok(served(body))],
        vec![None, Some(PreparationFailure::Unavailable)],
    );
    let output = run_diff(&live_prepare_unavailable, repo.path());
    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("state: dataplane_unknown"),
        "{}",
        output.text
    );
    assert!(
        !output.text.contains("state: dataplane_unserved"),
        "{}",
        output.text
    );

    let live_prepare_invalid = FakeClient::with_prepare_failures(
        vec![Ok(served(body))],
        vec![
            None,
            Some(PreparationFailure::Invalid("semantic refusal".into())),
        ],
    );
    let output = run_diff(&live_prepare_invalid, repo.path());
    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("state: dataplane_unserved"),
        "{}",
        output.text
    );
}

#[test]
fn known_daemon_corruption_dominates_prepare_transport_failure_without_masking_dimensions() {
    let body = "allow stripe.refund where amount <= 5000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(body), body.as_bytes(), "prose");
    let client = FakeClient::with_prepare_failures(
        vec![Ok(corrupt())],
        vec![Some(PreparationFailure::Unavailable)],
    );

    let output = run_status(&client, repo.path(), true);

    let value: serde_json::Value = serde_json::from_str(&output.text).unwrap();
    assert_eq!(value["state"], "dataplane_corrupt", "{value}");
    assert_eq!(value["document"], "unavailable", "{value}");
    assert_eq!(value["live_state"], "corrupt", "{value}");
    assert_eq!(value["lockdown"], "engaged", "{value}");
}

type CallHook = RefCell<Option<(usize, Box<dyn FnOnce()>)>>;

struct ApplyClient {
    statuses: RefCell<VecDeque<Result<SentenceAuthorityStatus, String>>>,
    staged_inputs: RefCell<Vec<String>>,
    stage_echo: RefCell<Option<cermet_ipc::ctl::StagedSentenceCorpus>>,
    commit_attempts: RefCell<VecDeque<ApplyCommitAttempt>>,
    commits: Cell<usize>,
    prepare_calls: Cell<usize>,
    prepare_hook: CallHook,
    stage_hook: RefCell<Option<Box<dyn FnOnce()>>>,
    status_calls: Cell<usize>,
    status_hook: CallHook,
    /// What the post-commit verification read reports. The default is "nothing stored", which no
    /// pinned-document test observes — that flow commits no profile and never asks.
    stored_presets: RefCell<Result<Vec<String>, String>>,
}

impl ApplyClient {
    fn new(
        statuses: Vec<Result<SentenceAuthorityStatus, String>>,
        commit_attempt: ApplyCommitAttempt,
    ) -> Self {
        Self {
            statuses: RefCell::new(statuses.into()),
            staged_inputs: RefCell::new(Vec::new()),
            stage_echo: RefCell::new(None),
            commit_attempts: RefCell::new(vec![commit_attempt].into()),
            commits: Cell::new(0),
            prepare_calls: Cell::new(0),
            prepare_hook: RefCell::new(None),
            stage_hook: RefCell::new(None),
            status_calls: Cell::new(0),
            status_hook: RefCell::new(None),
            stored_presets: RefCell::new(Ok(Vec::new())),
        }
    }

    /// What the post-commit verification read will report.
    fn with_stored_presets(self, stored: Result<Vec<String>, String>) -> Self {
        *self.stored_presets.borrow_mut() = stored;
        self
    }

    fn with_prepare_hook(self, call: usize, hook: impl FnOnce() + 'static) -> Self {
        *self.prepare_hook.borrow_mut() = Some((call, Box::new(hook)));
        self
    }

    fn with_stage_hook(self, hook: impl FnOnce() + 'static) -> Self {
        *self.stage_hook.borrow_mut() = Some(Box::new(hook));
        self
    }

    fn with_status_hook(self, call: usize, hook: impl FnOnce() + 'static) -> Self {
        *self.status_hook.borrow_mut() = Some((call, Box::new(hook)));
        self
    }

    fn with_commit_attempts(self, attempts: Vec<ApplyCommitAttempt>) -> Self {
        *self.commit_attempts.borrow_mut() = attempts.into();
        self
    }

    fn status(&self) -> Result<SentenceAuthorityStatus, String> {
        let call = self.status_calls.get() + 1;
        self.status_calls.set(call);
        let mut statuses = self.statuses.borrow_mut();
        let status = if statuses.len() > 1 {
            statuses.pop_front().unwrap()
        } else {
            statuses
                .front()
                .cloned()
                .unwrap_or_else(|| Err("unavailable".into()))
        };
        drop(statuses);
        if self
            .status_hook
            .borrow()
            .as_ref()
            .is_some_and(|(hook_call, _)| *hook_call == call)
        {
            let (_, hook) = self.status_hook.borrow_mut().take().unwrap();
            hook();
        }
        status
    }
}

impl ReconciliationClient for ApplyClient {
    fn prepare(
        &self,
        candidate_text: String,
    ) -> Result<PreparedSentenceCorpus, PreparationFailure> {
        let call = self.prepare_calls.get() + 1;
        self.prepare_calls.set(call);
        let prepared = prepare_candidate(&candidate_text);
        if self
            .prepare_hook
            .borrow()
            .as_ref()
            .is_some_and(|(hook_call, _)| *hook_call == call)
        {
            let (_, hook) = self.prepare_hook.borrow_mut().take().unwrap();
            hook();
        }
        prepared
    }

    fn authority_status(&self) -> Result<SentenceAuthorityStatus, String> {
        self.status()
    }
}

impl ApplyTransactionClient for ApplyClient {
    fn stored_preset_names(&self) -> Result<Vec<String>, String> {
        self.stored_presets.borrow().clone()
    }

    fn stage(
        &self,
        candidate_text: String,
    ) -> Result<cermet_ipc::ctl::StagedSentenceCorpus, PreparationFailure> {
        self.staged_inputs.borrow_mut().push(candidate_text.clone());
        if let Some(echo) = self.stage_echo.borrow_mut().take() {
            return Ok(echo);
        }
        let prepared = prepare_candidate(&candidate_text)?;
        if let Some(hook) = self.stage_hook.borrow_mut().take() {
            hook();
        }
        Ok(cermet_ipc::ctl::StagedSentenceCorpus {
            canonical_text: prepared.canonical_text,
            canonical_digest: prepared.canonical_digest,
            staging_token: "b".repeat(64),
            occurrence_id: cermet_ipc::ctl::sentence_occurrence_for_token(&"b".repeat(64)),
        })
    }

    fn commit(&self, _staging_token: String, _preset: Option<String>) -> ApplyCommitAttempt {
        self.commits.set(self.commits.get() + 1);
        self.commit_attempts
            .borrow_mut()
            .pop_front()
            .unwrap_or(ApplyCommitAttempt::Unknown)
    }
}

struct RecordingTerminal {
    answer: bool,
    prompts: RefCell<Vec<String>>,
    hook: RefCell<Option<Box<dyn FnOnce()>>>,
}

impl RecordingTerminal {
    fn new(answer: bool) -> Self {
        Self {
            answer,
            prompts: RefCell::new(Vec::new()),
            hook: RefCell::new(None),
        }
    }

    fn with_hook(self, hook: impl FnOnce() + 'static) -> Self {
        *self.hook.borrow_mut() = Some(Box::new(hook));
        self
    }
}

impl crate::tty::Terminal for RecordingTerminal {
    fn is_interactive(&self) -> bool {
        true
    }

    fn confirm(&self, prompt: &str, default: bool) -> bool {
        assert!(!default, "apply confirmation must default to no");
        self.prompts.borrow_mut().push(prompt.to_string());
        if let Some(hook) = self.hook.borrow_mut().take() {
            hook();
        }
        self.answer
    }

    fn launch(&self, _url: &str) {}

    fn read_secret(&self, _prompt: &str) -> Result<secrecy::SecretString, crate::CliError> {
        unreachable!("apply never reads a secret")
    }
}

struct RecordingPresence {
    outcome: cermet_ctl_client::presence::PresenceOutcome,
    reasons: std::sync::Mutex<Vec<String>>,
    hook: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl RecordingPresence {
    fn confirmed() -> Self {
        Self {
            outcome: cermet_ctl_client::presence::PresenceOutcome::Confirmed,
            reasons: std::sync::Mutex::new(Vec::new()),
            hook: std::sync::Mutex::new(None),
        }
    }

    fn with_hook(self, hook: impl FnOnce() + Send + 'static) -> Self {
        *self.hook.lock().unwrap() = Some(Box::new(hook));
        self
    }
}

impl cermet_ctl_client::presence::Presence for RecordingPresence {
    fn confirm(&self, reason: &str) -> cermet_ctl_client::presence::PresenceOutcome {
        self.reasons.lock().unwrap().push(reason.to_string());
        if let Some(hook) = self.hook.lock().unwrap().take() {
            hook();
        }
        self.outcome.clone()
    }
}

fn acknowledged(body: &str) -> ApplyCommitAttempt {
    let prepared = prepare_candidate(body).unwrap();
    ApplyCommitAttempt::Acknowledged(cermet_ipc::ctl::SentenceCommitOutcome::Committed {
        canonical_digest: prepared.canonical_digest,
        occurrence_id: cermet_ipc::ctl::sentence_occurrence_for_token(&"b".repeat(64)),
    })
}

fn status_sequence(
    before: SentenceAuthorityStatus,
    after: SentenceAuthorityStatus,
) -> Vec<Result<SentenceAuthorityStatus, String>> {
    vec![
        Ok(before.clone()),
        Ok(before.clone()),
        Ok(before.clone()),
        Ok(before),
        Ok(after.clone()),
        Ok(after),
    ]
}

#[test]
fn apply_disabled_provider_document_preserves_stable_refusal() {
    struct DisabledProviderClient;

    impl ReconciliationClient for DisabledProviderClient {
        fn prepare(
            &self,
            candidate_text: String,
        ) -> Result<PreparedSentenceCorpus, PreparationFailure> {
            assert!(
                candidate_text.contains("fs.upsert_file"),
                "{candidate_text}"
            );
            Err(classify_preparation_error(
                &cermet_lang::Error::ProviderDisabled,
            ))
        }

        fn authority_status(&self) -> Result<SentenceAuthorityStatus, String> {
            panic!("a disabled provider refusal must precede authority lookup")
        }
    }

    impl ApplyTransactionClient for DisabledProviderClient {
        fn stored_preset_names(&self) -> Result<Vec<String>, String> {
            Ok(Vec::new())
        }

        fn stage(
            &self,
            _candidate_text: String,
        ) -> Result<cermet_ipc::ctl::StagedSentenceCorpus, PreparationFailure> {
            panic!("a disabled provider document must never stage")
        }

        fn commit(&self, _staging_token: String, _preset: Option<String>) -> ApplyCommitAttempt {
            panic!("a disabled provider document must never commit")
        }
    }

    let body = "allow fs.upsert_file where path under /srv/cermet\n";
    let repo = repository();
    write_document(
        repo.path(),
        &AuthorityMarker::none(),
        body.as_bytes(),
        "prose",
    );

    let check = run_check(&DisabledProviderClient, repo.path(), false);
    assert_eq!(check.exit_code, 1, "{}", check.text);
    assert_eq!(check.text, "provider_disabled");

    let output = run_apply(
        &DisabledProviderClient,
        repo.path(),
        None,
        false,
        false,
        &RecordingTerminal::new(true),
        &RecordingPresence::confirmed(),
    );

    assert_eq!(output.exit_code, 1, "{}", output.text);
    assert_eq!(output.text, "provider_disabled");
}

#[test]
fn apply_refuses_noncanonical_source_before_stage_confirmation_or_presence() {
    let repo = repository();
    let loose = " allow   stripe.refund where amount<=5000 # draft\n";
    write_document(
        repo.path(),
        &AuthorityMarker::none(),
        loose.as_bytes(),
        "M3_PROSE_CANARY",
    );
    let client = ApplyClient::new(vec![Ok(absent())], ApplyCommitAttempt::Unknown);
    let terminal = RecordingTerminal::new(true);
    let presence = RecordingPresence::confirmed();

    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &terminal,
        &presence,
    );

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(output.text.contains("canonical"), "{}", output.text);
    assert!(client.staged_inputs.borrow().is_empty());
    assert_eq!(client.commits.get(), 0);
    assert!(terminal.prompts.borrow().is_empty());
    assert!(presence.reasons.lock().unwrap().is_empty());
}

#[test]
fn apply_refuses_an_invalid_source_before_presence_or_commit() {
    let invalid = repository();
    write_document(
        invalid.path(),
        &AuthorityMarker::none(),
        b"this is not a sentence\n",
        "prose",
    );
    let client = ApplyClient::new(vec![Ok(absent())], ApplyCommitAttempt::Unknown);
    let terminal = RecordingTerminal::new(true);
    let presence = RecordingPresence::confirmed();
    let output = run_apply(
        &client,
        invalid.path(),
        None,
        false,
        false,
        &terminal,
        &presence,
    );
    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(client.staged_inputs.borrow().is_empty());
    assert!(presence.reasons.lock().unwrap().is_empty());
}

#[test]
fn marker_only_apply_repair_needs_no_stage_confirmation_or_presence() {
    const PROSE: &str = "M3_MARKER_REPAIR_PROSE";
    let body = "allow stripe.refund where amount <= 5000\n";
    let repo = repository();
    write_document(
        repo.path(),
        &AuthorityMarker::none(),
        body.as_bytes(),
        PROSE,
    );
    let client = ApplyClient::new(
        vec![Ok(served(body)), Ok(served(body))],
        ApplyCommitAttempt::Unknown,
    );
    let terminal = RecordingTerminal::new(true);
    let presence = RecordingPresence::confirmed();

    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &terminal,
        &presence,
    );

    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(
        output.text.contains("result: marker_repaired"),
        "{}",
        output.text
    );
    assert!(client.staged_inputs.borrow().is_empty());
    assert_eq!(client.commits.get(), 0);
    assert!(terminal.prompts.borrow().is_empty());
    assert!(presence.reasons.lock().unwrap().is_empty());
    let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
    let document = ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(document.body(), body);
    assert_eq!(document.marker(), &marker_for(body));
    assert!(String::from_utf8(bytes).unwrap().contains(PROSE));
}

#[test]
fn apply_binds_exact_body_review_presence_commit_and_marker_receipt() {
    const PROSE: &str = "M3_APPLY_PROSE_CANARY";
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), PROSE);
    let client = ApplyClient::new(
        status_sequence(served(old), served(candidate)),
        acknowledged(candidate),
    );
    let terminal = RecordingTerminal::new(true);
    let presence = RecordingPresence::confirmed();

    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &terminal,
        &presence,
    );

    assert_eq!(output.exit_code, 0, "{}", output.text);
    for fact in [
        "result: committed",
        "acceptance_path: presence",
        "occurrence_id:",
        "marker_update: updated",
        "state: aligned",
    ] {
        assert!(
            output.text.contains(fact),
            "missing {fact:?}: {}",
            output.text
        );
    }
    assert_eq!(client.staged_inputs.borrow().as_slice(), [candidate]);
    assert_eq!(client.commits.get(), 1);
    let prompts = terminal.prompts.borrow();
    assert_eq!(prompts.len(), 1);
    assert!(prompts[0].contains(repo.path().to_string_lossy().as_ref()));
    assert!(prompts[0].contains("--- live"), "{}", prompts[0]);
    assert!(prompts[0].contains("+++ candidate"), "{}", prompts[0]);
    let reasons = presence.reasons.lock().unwrap();
    assert_eq!(reasons.len(), 1);
    assert!(!reasons[0].contains(PROSE));
    assert!(!reasons[0].contains(repo.path().to_string_lossy().as_ref()));
    assert!(!reasons[0].contains("stripe.refund"));
    let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
    let document = ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(document.body(), candidate);
    assert_eq!(document.marker(), &marker_for(candidate));
    assert!(String::from_utf8(bytes).unwrap().contains(PROSE));
}

#[test]
fn apply_requires_loud_replace_and_recovery_acknowledgements() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(
        repo.path(),
        &marker_for(candidate),
        candidate.as_bytes(),
        "prose",
    );
    let client = ApplyClient::new(vec![Ok(served(old))], ApplyCommitAttempt::Unknown);
    let terminal = RecordingTerminal::new(true);
    let presence = RecordingPresence::confirmed();
    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &terminal,
        &presence,
    );
    assert_eq!(output.exit_code, 1, "{}", output.text);
    assert!(output.text.contains("--replace-live"), "{}", output.text);
    assert!(client.staged_inputs.borrow().is_empty());
    assert!(presence.reasons.lock().unwrap().is_empty());

    let recovery = repository();
    write_document(
        recovery.path(),
        &AuthorityMarker::none(),
        candidate.as_bytes(),
        "prose",
    );
    let client = ApplyClient::new(vec![Ok(corrupt())], ApplyCommitAttempt::Unknown);
    let output = run_apply(
        &client,
        recovery.path(),
        None,
        false,
        false,
        &terminal,
        &presence,
    );
    assert_eq!(output.exit_code, 1, "{}", output.text);
    assert!(output.text.contains("--recover"), "{}", output.text);
    assert!(client.staged_inputs.borrow().is_empty());
}

#[test]
fn replace_and_recovery_flags_acknowledge_anomalies_but_still_require_presence() {
    let candidate = "allow stripe.refund where amount <= 6000\n";

    let replace_repo = repository();
    write_document(
        replace_repo.path(),
        &marker_for(candidate),
        candidate.as_bytes(),
        "prose",
    );
    let old = "allow stripe.refund where amount <= 5000\n";
    let replace_client = ApplyClient::new(
        status_sequence(served(old), served(candidate)),
        acknowledged(candidate),
    );
    let terminal = RecordingTerminal::new(true);
    let presence = RecordingPresence::confirmed();
    let output = run_apply(
        &replace_client,
        replace_repo.path(),
        None,
        true,
        false,
        &terminal,
        &presence,
    );
    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(terminal.prompts.borrow()[0].contains("WARNING: --replace-live"));
    assert_eq!(presence.reasons.lock().unwrap().len(), 1);

    let recovery_repo = repository();
    write_document(
        recovery_repo.path(),
        &AuthorityMarker::none(),
        candidate.as_bytes(),
        "prose",
    );
    let recovery_client = ApplyClient::new(
        status_sequence(corrupt(), served(candidate)),
        acknowledged(candidate),
    );
    let terminal = RecordingTerminal::new(true);
    let presence = RecordingPresence::confirmed();
    let output = run_apply(
        &recovery_client,
        recovery_repo.path(),
        None,
        false,
        true,
        &terminal,
        &presence,
    );
    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(terminal.prompts.borrow()[0].contains("WARNING: --recover"));
    assert_eq!(presence.reasons.lock().unwrap().len(), 1);
}

#[test]
fn apply_decline_and_unavailable_presence_never_commit() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    for (terminal_answer, presence_outcome) in [
        (
            false,
            cermet_ctl_client::presence::PresenceOutcome::Confirmed,
        ),
        (
            true,
            cermet_ctl_client::presence::PresenceOutcome::Unavailable("unavailable".into()),
        ),
    ] {
        let repo = repository();
        write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
        let client = ApplyClient::new(vec![Ok(served(old)); 6], acknowledged(candidate));
        let terminal = RecordingTerminal::new(terminal_answer);
        let presence = RecordingPresence {
            outcome: presence_outcome,
            reasons: std::sync::Mutex::new(Vec::new()),
            hook: std::sync::Mutex::new(None),
        };
        let output = run_apply(
            &client,
            repo.path(),
            None,
            false,
            false,
            &terminal,
            &presence,
        );
        assert_ne!(output.exit_code, 0, "{}", output.text);
        assert_eq!(client.commits.get(), 0, "{}", output.text);
        assert_eq!(
            ManagedDocument::parse(&std::fs::read(repo.path().join("CERMET.md")).unwrap())
                .unwrap()
                .marker(),
            &marker_for(old)
        );
    }
}

#[test]
fn apply_rejects_live_change_after_stage_before_presence() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let winner = "deny stripe.refund where amount >= 9000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let client = ApplyClient::new(
        vec![Ok(served(old)), Ok(served(winner))],
        acknowledged(candidate),
    );
    let terminal = RecordingTerminal::new(true);
    let presence = RecordingPresence::confirmed();

    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &terminal,
        &presence,
    );

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("live generation changed"),
        "{}",
        output.text
    );
    assert_eq!(client.staged_inputs.borrow().len(), 1);
    assert_eq!(client.commits.get(), 0);
    assert!(terminal.prompts.borrow().is_empty());
    assert!(presence.reasons.lock().unwrap().is_empty());
}

#[test]
fn apply_lost_response_credits_only_exact_candidate_and_keeps_prior_or_third_unknown() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let third = "deny stripe.refund where amount >= 9000\n";
    let mut same_candidate_other_occurrence = served(candidate);
    let SentenceSnapshot::Served { occurrence_id, .. } =
        &mut same_candidate_other_occurrence.sentence
    else {
        unreachable!()
    };
    *occurrence_id = "e".repeat(64);
    for (observed, expected_result, marker_advanced, commit_count) in [
        (served(candidate), "committed_after_reconciliation", true, 1),
        (served(old), "commit_outcome_unknown", false, 4),
        (served(third), "commit_outcome_unknown", false, 4),
        (
            same_candidate_other_occurrence,
            "commit_outcome_unknown",
            false,
            4,
        ),
    ] {
        let repo = repository();
        write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
        let client = ApplyClient::new(
            status_sequence(served(old), observed.clone()),
            ApplyCommitAttempt::Unknown,
        );
        let terminal = RecordingTerminal::new(true);
        let presence = RecordingPresence::confirmed();

        let output = run_apply(
            &client,
            repo.path(),
            None,
            false,
            false,
            &terminal,
            &presence,
        );

        assert!(output.text.contains(expected_result), "{}", output.text);
        assert_eq!(
            client.commits.get(),
            commit_count,
            "only the exact token receives bounded retries"
        );
        let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
        let marker = ManagedDocument::parse(&bytes).unwrap().marker().clone();
        assert_eq!(
            marker == marker_for(candidate),
            marker_advanced,
            "{}",
            output.text
        );
    }
}

#[test]
fn applying_empty_corpus_is_a_presence_accepted_authority_change() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(old), b"", "prose");
    let committed_empty = served("");
    let client = ApplyClient::new(
        status_sequence(served(old), committed_empty),
        acknowledged(""),
    );
    let terminal = RecordingTerminal::new(true);
    let presence = RecordingPresence::confirmed();

    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &terminal,
        &presence,
    );

    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert_eq!(presence.reasons.lock().unwrap().len(), 1);
    assert!(output.text.contains("rules: 0"), "{}", output.text);
    assert_eq!(client.commits.get(), 1);
}

#[test]
fn apply_refuses_file_replacement_body_edit_and_marker_edit_at_precommit_boundaries() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let concurrent = "deny stripe.refund where amount >= 9000\n";

    // Replacement immediately after staging.
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let path = repo.path().join("CERMET.md");
    let moved = repo.path().join("CERMET.before-stage");
    let replacement = render_template(&marker_for(old), concurrent.as_bytes()).unwrap();
    let client = ApplyClient::new(vec![Ok(served(old)); 8], acknowledged(candidate))
        .with_stage_hook({
            let path = path.clone();
            move || {
                std::fs::rename(&path, moved).unwrap();
                std::fs::write(&path, replacement).unwrap();
            }
        });
    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &RecordingTerminal::new(true),
        &RecordingPresence::confirmed(),
    );
    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(output.text.contains("CERMET.md changed"), "{}", output.text);
    assert_eq!(client.commits.get(), 0);

    // In-place body edit during the default-no terminal review.
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let replacement = render_template(&marker_for(old), concurrent.as_bytes()).unwrap();
    let path = repo.path().join("CERMET.md");
    let terminal = RecordingTerminal::new(true).with_hook({
        let path = path.clone();
        move || std::fs::write(path, replacement).unwrap()
    });
    let client = ApplyClient::new(vec![Ok(served(old)); 8], acknowledged(candidate));
    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &terminal,
        &RecordingPresence::confirmed(),
    );
    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert_eq!(client.commits.get(), 0);

    // Marker-only edit while the OS presence ceremony is open.
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let replacement = render_template(&marker_for(candidate), candidate.as_bytes()).unwrap();
    let path = repo.path().join("CERMET.md");
    let presence = RecordingPresence::confirmed()
        .with_hook(move || std::fs::write(path, replacement).unwrap());
    let client = ApplyClient::new(vec![Ok(served(old)); 8], acknowledged(candidate));
    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &RecordingTerminal::new(true),
        &presence,
    );
    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert_eq!(client.commits.get(), 0);
}

#[test]
fn apply_refuses_a_physical_repository_root_change_before_commit() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let holder = tempfile::tempdir().unwrap();
    let root = holder.path().join("repo");
    let moved = holder.path().join("moved-repo");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join(".git")).unwrap();
    write_document(&root, &marker_for(old), candidate.as_bytes(), "prose");
    let root_for_hook = root.clone();
    let moved_for_hook = moved.clone();
    let terminal = RecordingTerminal::new(true).with_hook(move || {
        std::fs::rename(&root_for_hook, &moved_for_hook).unwrap();
        std::fs::create_dir(&root_for_hook).unwrap();
        std::fs::create_dir(root_for_hook.join(".git")).unwrap();
        std::fs::write(
            root_for_hook.join("CERMET.md"),
            render_template(&marker_for(old), candidate.as_bytes()).unwrap(),
        )
        .unwrap();
    });
    let client = ApplyClient::new(vec![Ok(served(old)); 8], acknowledged(candidate));

    let output = run_apply(
        &client,
        &root,
        None,
        false,
        false,
        &terminal,
        &RecordingPresence::confirmed(),
    );

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("repository root changed"),
        "{}",
        output.text
    );
    assert_eq!(client.commits.get(), 0);
    std::fs::remove_dir_all(moved).unwrap();
}

#[test]
fn stale_stage_cas_preserves_the_concurrent_winner_and_never_advances_marker() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let winner = "deny stripe.refund where amount >= 9000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let client = ApplyClient::new(
        status_sequence(served(old), served(winner)),
        ApplyCommitAttempt::Refused,
    );

    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &RecordingTerminal::new(true),
        &RecordingPresence::confirmed(),
    );

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("stale_stage_conflict"),
        "{}",
        output.text
    );
    let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
    assert_eq!(
        ManagedDocument::parse(&bytes).unwrap().marker(),
        &marker_for(old)
    );
}

#[test]
fn post_commit_marker_cas_and_final_file_races_report_committed_but_unreconciled() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let concurrent = "deny stripe.refund where amount >= 9000\n";

    // A concurrent edit after the commit observation wins before marker CAS.
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let concurrent_bytes = render_template(&marker_for(old), concurrent.as_bytes()).unwrap();
    let path = repo.path().join("CERMET.md");
    let client = ApplyClient::new(
        status_sequence(served(old), served(candidate)),
        acknowledged(candidate),
    )
    .with_status_hook(5, {
        let path = path.clone();
        let concurrent_bytes = concurrent_bytes.clone();
        move || std::fs::write(path, concurrent_bytes).unwrap()
    });
    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &RecordingTerminal::new(true),
        &RecordingPresence::confirmed(),
    );
    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("result: committed_but_unreconciled"),
        "{}",
        output.text
    );
    assert!(
        output
            .text
            .contains("marker_update: preserved_concurrent_edit"),
        "{}",
        output.text
    );
    assert_eq!(std::fs::read(&path).unwrap(), concurrent_bytes);

    // A writer immediately after marker publication is caught by final preparation/status.
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let concurrent_bytes = render_template(&marker_for(old), concurrent.as_bytes()).unwrap();
    let path = repo.path().join("CERMET.md");
    let client = ApplyClient::new(
        status_sequence(served(old), served(candidate)),
        acknowledged(candidate),
    )
    .with_prepare_hook(3, {
        let path = path.clone();
        let concurrent_bytes = concurrent_bytes.clone();
        move || std::fs::write(path, concurrent_bytes).unwrap()
    });
    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &RecordingTerminal::new(true),
        &RecordingPresence::confirmed(),
    );
    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("committed_but_unreconciled"),
        "{}",
        output.text
    );
    assert_eq!(std::fs::read(path).unwrap(), concurrent_bytes);
}

#[test]
fn apply_keeps_an_unavailable_post_commit_read_unknown_until_candidate_is_observed() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let client = ApplyClient::new(
        vec![
            Ok(served(old)),
            Ok(served(old)),
            Ok(served(old)),
            Ok(served(old)),
            Err("first post-commit read unavailable".into()),
            Ok(served(candidate)),
        ],
        acknowledged(candidate),
    );

    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &RecordingTerminal::new(true),
        &RecordingPresence::confirmed(),
    );

    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(output.text.contains("result: committed"), "{}", output.text);
    assert!(!output.text.contains("conflict"), "{}", output.text);
    assert!(!output.text.contains("marker_stale"), "{}", output.text);
    assert_eq!(
        ManagedDocument::parse(&std::fs::read(repo.path().join("CERMET.md")).unwrap())
            .unwrap()
            .marker(),
        &marker_for(candidate),
    );
}

#[test]
fn apply_in_flight_handler_completes_after_early_baseline_using_only_staged_token() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let client = ApplyClient::new(
        vec![
            Ok(served(old)),
            Ok(served(old)),
            Ok(served(old)),
            Ok(served(old)),
            Ok(served(old)),
            Ok(served(candidate)),
        ],
        ApplyCommitAttempt::Unknown,
    )
    .with_commit_attempts(vec![ApplyCommitAttempt::Unknown, acknowledged(candidate)]);
    let presence = RecordingPresence::confirmed();

    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &RecordingTerminal::new(true),
        &presence,
    );

    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(output.text.contains("result: committed"), "{}", output.text);
    assert_eq!(
        client.commits.get(),
        2,
        "only the same staged commit is retried"
    );
    assert_eq!(presence.reasons.lock().unwrap().len(), 1);
}

#[test]
fn apply_mismatched_ack_after_success_reconciles_exact_occurrence() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let prepared = prepare_candidate(candidate).unwrap();
    let bad = ApplyCommitAttempt::Acknowledged(cermet_ipc::ctl::SentenceCommitOutcome::Committed {
        canonical_digest: prepared.canonical_digest,
        occurrence_id: "e".repeat(64),
    });
    let client = ApplyClient::new(status_sequence(served(old), served(candidate)), bad);
    let presence = RecordingPresence::confirmed();

    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &RecordingTerminal::new(true),
        &presence,
    );

    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert_eq!(presence.reasons.lock().unwrap().len(), 1);
    assert!(
        !output.text.contains("committed_outcome_malformed"),
        "{}",
        output.text
    );
}

#[test]
fn apply_timeout_then_restart_or_expiry_preserves_unknown_token_and_occurrence() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let client = ApplyClient::new(vec![Ok(served(old)); 12], ApplyCommitAttempt::Unknown)
        .with_commit_attempts(vec![
            ApplyCommitAttempt::Unknown,
            ApplyCommitAttempt::Refused,
            ApplyCommitAttempt::Refused,
        ]);
    let presence = RecordingPresence::confirmed();

    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &RecordingTerminal::new(true),
        &presence,
    );

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("result: commit_outcome_unknown"),
        "{}",
        output.text
    );
    assert!(output.text.contains("staging_token:"), "{}", output.text);
    assert!(output.text.contains("occurrence_id:"), "{}", output.text);
    assert!(output.text.contains("do not repeat"), "{}", output.text);
    assert_eq!(presence.reasons.lock().unwrap().len(), 1);
}

#[test]
fn apply_exact_unserved_occurrence_proves_commit_but_never_claims_served_or_aligned() {
    let old = "allow stripe.refund where amount <= 5000\n";
    let candidate = "allow stripe.refund where amount <= 6000\n";
    let repo = repository();
    write_document(repo.path(), &marker_for(old), candidate.as_bytes(), "prose");
    let client = ApplyClient::new(
        status_sequence(served(old), unserved(candidate)),
        ApplyCommitAttempt::Unknown,
    );

    let output = run_apply(
        &client,
        repo.path(),
        None,
        false,
        false,
        &RecordingTerminal::new(true),
        &RecordingPresence::confirmed(),
    );

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(
        output.text.contains("result: committed_but_unreconciled"),
        "{}",
        output.text
    );
    assert!(
        output.text.contains("state: dataplane_unserved"),
        "{}",
        output.text
    );
    assert!(
        !output.text.contains("commit_outcome_unknown"),
        "{}",
        output.text
    );
    assert!(!output.text.contains("staging_token:"), "{}", output.text);
    assert_eq!(
        client.commits.get(),
        1,
        "status proves the exact committed occurrence"
    );
}

/// The corpus body the profile tests install.
const PROFILE_BODY: &str = "allow stripe.refund where amount <= 5000\n";

/// A commit that carried a profile key is only DONE when the key is there.
///
/// The daemon writes the corpus and the profile as two steps. A fault in the second, a lost reply,
/// or a daemon that dies between them all leave the same observable state: authority is live, and
/// the profile is not stored. Reporting that as a success would tell an operator a profile exists
/// that they could not then apply.
#[test]
fn a_commit_whose_profile_did_not_reach_the_store_is_not_reported_as_stored() {
    let client = ApplyClient::new(
        vec![
            Ok(absent()),
            Ok(served(PROFILE_BODY)),
            Ok(served(PROFILE_BODY)),
        ],
        acknowledged(PROFILE_BODY),
    )
    .with_stored_presets(Ok(Vec::new()));

    let output = run_body_apply(
        &client,
        BodyApply {
            body: PROFILE_BODY,
            preset: "designer",
            source: "stored profile",
        },
        false,
        &RecordingTerminal::new(true),
        &RecordingPresence::confirmed(),
    );

    assert_ne!(output.exit_code, 0, "{}", output.text);
    assert!(
        output.text.contains("committed") && output.text.contains("live"),
        "the report must say authority IS live: {}",
        output.text
    );
    assert!(
        output.text.contains("not stored") || output.text.contains("NOT stored"),
        "the report must say the profile was not stored: {}",
        output.text
    );
    assert!(
        output.text.contains("designer"),
        "the report names the key: {}",
        output.text
    );
    assert!(
        !output.text.contains("result: committed\n"),
        "a not-stored profile must not read as a clean commit: {}",
        output.text
    );
    // The message is prose, not a wrapped source literal with its indentation baked in.
    assert!(
        !output.text.contains("  "),
        "the report carries a wrapped-literal space run: {:?}",
        output.text
    );
}

/// The same posture when the verification read itself cannot be made: unconfirmed is not confirmed.
#[test]
fn a_profile_that_cannot_be_confirmed_stored_is_not_reported_as_stored() {
    let client = ApplyClient::new(
        vec![
            Ok(absent()),
            Ok(served(PROFILE_BODY)),
            Ok(served(PROFILE_BODY)),
        ],
        acknowledged(PROFILE_BODY),
    )
    .with_stored_presets(Err("ctl unreachable".into()));

    let output = run_body_apply(
        &client,
        BodyApply {
            body: PROFILE_BODY,
            preset: "designer",
            source: "stored profile",
        },
        false,
        &RecordingTerminal::new(true),
        &RecordingPresence::confirmed(),
    );

    assert_ne!(output.exit_code, 0, "{}", output.text);
    assert!(output.text.contains("designer"), "{}", output.text);
}

/// The confirming case: the key IS there, so the ceremony reports a clean commit.
#[test]
fn a_commit_whose_profile_reached_the_store_reports_a_clean_commit() {
    let client = ApplyClient::new(
        vec![
            Ok(absent()),
            Ok(served(PROFILE_BODY)),
            Ok(served(PROFILE_BODY)),
        ],
        acknowledged(PROFILE_BODY),
    )
    .with_stored_presets(Ok(vec!["designer".into()]));

    let output = run_body_apply(
        &client,
        BodyApply {
            body: PROFILE_BODY,
            preset: "designer",
            source: "stored profile",
        },
        false,
        &RecordingTerminal::new(true),
        &RecordingPresence::confirmed(),
    );

    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(output.text.contains("result: committed"), "{}", output.text);
    assert!(output.text.contains("preset: designer"), "{}", output.text);
}
