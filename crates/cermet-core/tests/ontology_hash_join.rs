//! The anti-drift hash join. A sidecar's `binds` SHA-256 values must equal the
//! SHA-256 of the *actual bytes* of the vendored provider descriptor and action template it names.
//! One-byte drift in either artifact (or in a declared hash) is a hard validation failure that names
//! the artifact.

use cermet_core::{
    OntologyArtifacts, OntologyCatalog, OntologyError, OntologyRecord, SourceRegistry,
    VENDORED_ONTOLOGY,
};

fn registry() -> SourceRegistry {
    SourceRegistry::official().unwrap()
}

#[test]
fn vendored_records_parse_resolve_sources_and_hash_join_green() {
    assert_eq!(
        VENDORED_ONTOLOGY.len(),
        48,
        "twenty-three GitHub (git-native `push` + `fetch`, plus `dispatch_workflow`, `read_workflow_run_jobs`, and `read_job_log`) + twenty-three Stripe + two Vercel verbs (relay deploy + scoped list read)"
    );

    let catalog = OntologyCatalog::check(VENDORED_ONTOLOGY, &registry())
        .expect("all vendored records parse, obey caps, and resolve their sources");
    assert_eq!(catalog.len(), 48);

    // Every declared bind hash equals the SHA-256 of the real vendored artifact bytes.
    catalog
        .join_all(&OntologyArtifacts::vendored())
        .expect("all records hash-join against the vendored descriptor/template bytes");

    for (provider, action) in [
        ("github", "read_repo"),
        ("github", "read_ref"),
        ("github", "read_commit"),
        ("github", "read_tree"),
        ("github", "read_blob"),
        ("github", "read_thread"),
        ("github", "read_pull_request"),
        ("github", "push"),
        ("github", "read_workflow_run"),
        ("github", "read_workflow_run_jobs"),
        ("github", "create_branch"),
        ("github", "create_issue"),
        ("github", "comment_thread"),
        ("github", "create_pull_request_review"),
        ("github", "request_workflow_cancel"),
        ("github", "dispatch_workflow"),
        ("github", "request_deployment"),
        ("github", "create_pull_request"),
        ("github", "merge_pull_request"),
        ("github", "update_pull_request"),
        ("github", "read_secret_scanning_alerts_open"),
        ("stripe", "get_invoice"),
        ("stripe", "list_invoices_for_customer"),
        ("stripe", "get_payment_intent"),
        ("stripe", "get_dispute_summary"),
        ("stripe", "get_product"),
        ("stripe", "get_price"),
        ("stripe", "list_active_prices"),
        ("stripe", "cancel_subscription_at_period_end"),
        ("stripe", "resume_subscription_collection"),
        ("stripe", "mark_invoice_uncollectible"),
        ("stripe", "issue_credit_note_adjustment_no_email"),
        ("stripe", "archive_product"),
        ("stripe", "archive_price"),
        ("stripe", "stage_dispute_evidence"),
        ("stripe", "submit_dispute_evidence"),
        ("stripe", "update_webhook_endpoint_fixed_bundle"),
        ("stripe", "create_payment_intent_off_session"),
        ("stripe", "confirm_payment_intent"),
        ("stripe", "capture_payment_intent"),
        ("stripe", "cancel_payment_intent"),
        ("stripe", "retry_invoice_payment"),
        ("stripe", "refund_charge_bounded"),
        ("stripe", "create_standard_payout"),
    ] {
        assert!(
            catalog.get(provider, action).is_some(),
            "vendored catalog is missing {provider}.{action}"
        );
    }
}

#[test]
fn one_byte_drift_in_a_declared_descriptor_hash_fails_naming_the_artifact() {
    // Flip the last hex digit of the github descriptor hash in the read_repo record.
    let record_doc = VENDORED_ONTOLOGY[0];
    assert!(record_doc.contains("provider: github"));
    let real = OntologyRecord::parse(record_doc, &registry()).unwrap();
    let real_hash = &real.binds.provider_descriptor_sha256;
    let flipped: String = {
        let mut chars: Vec<char> = real_hash.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        chars.into_iter().collect()
    };
    let drifted = record_doc.replacen(real_hash.as_str(), &flipped, 1);

    let record = OntologyRecord::parse(&drifted, &registry()).expect("still a valid V1 lexeme");
    let error = record
        .join_artifacts(&OntologyArtifacts::vendored())
        .expect_err("a one-hex-digit drift must fail the join");
    match error {
        OntologyError::DescriptorHashMismatch { artifact, .. } => {
            assert_eq!(artifact, "providers/github.yaml");
        }
        other => panic!("expected DescriptorHashMismatch, got {other:?}"),
    }
}

#[test]
fn one_byte_drift_in_a_declared_template_hash_fails_naming_the_artifact() {
    // Find a record by content — index-independent as the vendored set grows.
    let record_doc = VENDORED_ONTOLOGY
        .iter()
        .copied()
        .find(|d| d.contains("action: merge_pull_request"))
        .expect("merge_pull_request ontology record is vendored");
    let real = OntologyRecord::parse(record_doc, &registry()).unwrap();
    let real_hash = real.binds.action_template_sha256.clone();
    let flipped: String = {
        let mut chars: Vec<char> = real_hash.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
        chars.into_iter().collect()
    };
    let drifted = record_doc.replacen(real_hash.as_str(), &flipped, 1);

    let record = OntologyRecord::parse(&drifted, &registry()).unwrap();
    let error = record
        .join_artifacts(&OntologyArtifacts::vendored())
        .expect_err("a template-hash drift must fail the join");
    match error {
        OntologyError::TemplateHashMismatch { artifact, .. } => {
            assert_eq!(artifact, "actions/github.merge_pull_request.yaml");
        }
        other => panic!("expected TemplateHashMismatch, got {other:?}"),
    }
}

#[test]
fn a_record_naming_an_absent_artifact_fails_the_join() {
    // A record whose locator has no vendored descriptor/template must fail closed, naming the
    // missing artifact — a stale record can never silently "join" to nothing.
    let doc = VENDORED_ONTOLOGY[0].replacen("action: read_repo", "action: read_nothing", 1);
    let record = OntologyRecord::parse(&doc, &registry()).unwrap();
    let error = record
        .join_artifacts(&OntologyArtifacts::vendored())
        .expect_err("no vendored template for github.read_nothing");
    match error {
        OntologyError::MissingTemplate { artifact, .. } => {
            assert_eq!(artifact, "actions/github.read_nothing.yaml");
        }
        other => panic!("expected MissingTemplate, got {other:?}"),
    }
}
