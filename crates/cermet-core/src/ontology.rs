//! Descriptive provenance for grounded ontology records.
//!
//! Source metadata is not consulted by policy, admission, grants, or provider execution.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use thiserror::Error;

pub const SOURCE_REGISTRY_SCHEMA: &str = "cermet.grounded-ontology-sources/v1";
pub const MAX_SOURCE_REGISTRY_BYTES: usize = 64 * 1024;
pub const OFFICIAL_SOURCE_REGISTRY_YAML: &str = include_str!("../ontology/sources.yaml");

pub const ONTOLOGY_SCHEMA: &str = "cermet.grounded-ontology/v1";
pub const MAX_ONTOLOGY_DOCUMENT_BYTES: usize = 16_384;

const MAX_IDENTIFIER_BYTES: usize = 64;
const MAX_RENDERED_PAIR_BYTES: usize = 51;
const MAX_SUMMARY_BYTES: usize = 512;
const MAX_CAUTION_BYTES: usize = 256;
const MAX_CAUTIONS: usize = 8;
const MIN_SOURCES: usize = 1;
const MAX_SOURCES: usize = 16;

// Vercel publishes its API and CLI reference under `vercel.com/docs`, not a
// `docs.` subdomain, so the official-host list names the apex host for it.
const OFFICIAL_SOURCE_HOSTS: &[&str] = &["docs.github.com", "docs.stripe.com", "vercel.com"];

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OntologyRecord {
    schema: String,
    pub provider: String,
    pub action: String,
    pub binds: OntologyBindings,
    pub semantics: OntologySemantics,
    pub review: OntologyReview,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OntologyBindings {
    pub provider_descriptor_sha256: String,
    pub action_template_sha256: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OntologySemantics {
    pub resource_family: String,
    pub provider_operation: String,
    pub risk_class: RiskClass,
    pub sensitivity: Sensitivity,
    pub reversibility: Reversibility,
    pub completion: Completion,
    pub idempotency: Idempotency,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OntologyReview {
    pub summary: String,
    pub cautions: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Observation,
    SensitiveObservation,
    ExternalStateChange,
    ProviderControlChange,
    ConfidentialInputWrite,
    DataLifecycleChange,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    PublicMetadata,
    SourceCode,
    Operational,
    Personal,
    Security,
    Secret,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    Reversible,
    Compensatable,
    Irreversible,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    Terminal,
    Accepted,
    Asynchronous,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Idempotency {
    Read,
    ProviderCas,
    Idempotent,
    NonIdempotent,
    Unknown,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OntologyError {
    #[error("ontology document is {actual} bytes, over the {cap}-byte cap")]
    DocumentTooLarge { actual: usize, cap: usize },
    #[error("invalid ontology document: {0}")]
    InvalidDocument(String),
    #[error("unsupported ontology schema `{0}`")]
    UnsupportedSchema(String),
    #[error(
        "ontology {field} `{value}` is not a lowercase identifier of 1..={MAX_IDENTIFIER_BYTES} bytes"
    )]
    InvalidIdentifier { field: &'static str, value: String },
    #[error("ontology provider-action pair is {actual} bytes, over the {cap}-byte cap")]
    RenderedPairTooLong { actual: usize, cap: usize },
    #[error("ontology {field} `{value}` is not exactly 64 lowercase hexadecimal characters")]
    InvalidSha256 { field: &'static str, value: String },
    #[error("ontology {field} {reason}")]
    InvalidText { field: String, reason: &'static str },
    #[error("ontology review.cautions has {actual} entries, over the {cap}-entry cap")]
    TooManyCautions { actual: usize, cap: usize },
    #[error("ontology sources has {actual} entries; expected {min}..={max}")]
    InvalidSourceCount {
        actual: usize,
        min: usize,
        max: usize,
    },
    #[error("invalid ontology source ID `{0}`")]
    InvalidSourceId(String),
    #[error("duplicate ontology source ID `{0}`")]
    DuplicateSourceId(String),
    #[error("unknown ontology source ID `{0}`")]
    UnknownSourceId(String),
    #[error("duplicate ontology binding `{provider}.{action}`")]
    DuplicateBinding { provider: String, action: String },
    #[error("ontology record names provider descriptor `{artifact}`, which is not vendored")]
    MissingDescriptor { artifact: String },
    #[error(
        "ontology provider_descriptor_sha256 does not match `{artifact}`: expected {expected}, artifact hashes to {observed}"
    )]
    DescriptorHashMismatch {
        artifact: String,
        expected: String,
        observed: String,
    },
    #[error("ontology record names action template `{artifact}`, which is not vendored")]
    MissingTemplate { artifact: String },
    #[error(
        "ontology action_template_sha256 does not match `{artifact}`: expected {expected}, artifact hashes to {observed}"
    )]
    TemplateHashMismatch {
        artifact: String,
        expected: String,
        observed: String,
    },
    #[error("ontology action template `{artifact}` is not parseable: {reason}")]
    TemplateUnparseable { artifact: String, reason: String },
    #[error(
        "ontology action template `{artifact}` declares locator `{observed}`, not the sidecar locator `{expected}`"
    )]
    TemplateLocatorMismatch {
        artifact: String,
        expected: String,
        observed: String,
    },
}

impl OntologyRecord {
    pub fn parse(document: &str, sources: &SourceRegistry) -> Result<Self, OntologyError> {
        if document.len() > MAX_ONTOLOGY_DOCUMENT_BYTES {
            return Err(OntologyError::DocumentTooLarge {
                actual: document.len(),
                cap: MAX_ONTOLOGY_DOCUMENT_BYTES,
            });
        }

        let record: Self = serde_yaml::from_str(document)
            .map_err(|error| OntologyError::InvalidDocument(error.to_string()))?;
        record.validate(sources)?;
        Ok(record)
    }

    fn validate(&self, sources: &SourceRegistry) -> Result<(), OntologyError> {
        if self.schema != ONTOLOGY_SCHEMA {
            return Err(OntologyError::UnsupportedSchema(self.schema.clone()));
        }
        validate_identifier("provider", &self.provider)?;
        validate_identifier("action", &self.action)?;

        let rendered_pair_bytes = self.provider.len() + 1 + self.action.len();
        if rendered_pair_bytes > MAX_RENDERED_PAIR_BYTES {
            return Err(OntologyError::RenderedPairTooLong {
                actual: rendered_pair_bytes,
                cap: MAX_RENDERED_PAIR_BYTES,
            });
        }

        validate_sha256(
            "binds.provider_descriptor_sha256",
            &self.binds.provider_descriptor_sha256,
        )?;
        validate_sha256(
            "binds.action_template_sha256",
            &self.binds.action_template_sha256,
        )?;
        validate_identifier("resource_family", &self.semantics.resource_family)?;
        validate_identifier("provider_operation", &self.semantics.provider_operation)?;
        validate_text(
            "review.summary".to_owned(),
            &self.review.summary,
            MAX_SUMMARY_BYTES,
        )?;

        if self.review.cautions.len() > MAX_CAUTIONS {
            return Err(OntologyError::TooManyCautions {
                actual: self.review.cautions.len(),
                cap: MAX_CAUTIONS,
            });
        }
        for (index, caution) in self.review.cautions.iter().enumerate() {
            validate_text(
                format!("review.cautions[{index}]"),
                caution,
                MAX_CAUTION_BYTES,
            )?;
        }

        if !(MIN_SOURCES..=MAX_SOURCES).contains(&self.sources.len()) {
            return Err(OntologyError::InvalidSourceCount {
                actual: self.sources.len(),
                min: MIN_SOURCES,
                max: MAX_SOURCES,
            });
        }
        let mut seen_sources = BTreeSet::new();
        for source in &self.sources {
            if !valid_source_id(source) {
                return Err(OntologyError::InvalidSourceId(source.clone()));
            }
            if !seen_sources.insert(source.as_str()) {
                return Err(OntologyError::DuplicateSourceId(source.clone()));
            }
        }
        for source in &self.sources {
            if sources.require(source).is_err() {
                return Err(OntologyError::UnknownSourceId(source.clone()));
            }
        }

        Ok(())
    }

    /// The anti-drift hash join. The record's two `binds` digests must equal
    /// the SHA-256 of the *actual bytes* of the vendored provider descriptor and action template it
    /// names, and the loaded template's own locator must equal the sidecar's `(provider, action)`.
    /// A one-byte drift in either artifact — or a stale/absent binding — is a hard failure that names
    /// the artifact, so a record can never outlive the bytes it describes.
    ///
    /// The hash equality already proves the template bytes are byte-identical to the ratified,
    /// separately-validated artifact the broker loads; this method deliberately does not re-run the
    /// full template/descriptor validator (that lives in the trusted loader and would couple the
    /// pure ontology checker to `templates`, which the authority-inertness guard forbids in reverse).
    pub fn join_artifacts(&self, artifacts: &OntologyArtifacts) -> Result<(), OntologyError> {
        let descriptor_label = format!("providers/{}.yaml", self.provider);
        let descriptor = artifacts
            .descriptors
            .get(self.provider.as_str())
            .ok_or_else(|| OntologyError::MissingDescriptor {
                artifact: descriptor_label.clone(),
            })?;
        let observed = sha256_hex(descriptor.as_bytes());
        if observed != self.binds.provider_descriptor_sha256 {
            return Err(OntologyError::DescriptorHashMismatch {
                artifact: descriptor_label,
                expected: self.binds.provider_descriptor_sha256.clone(),
                observed,
            });
        }

        let template_label = format!("actions/{}.{}.yaml", self.provider, self.action);
        let template = artifacts
            .templates
            .get(&(self.provider.as_str(), self.action.as_str()))
            .ok_or_else(|| OntologyError::MissingTemplate {
                artifact: template_label.clone(),
            })?;
        let observed = sha256_hex(template.as_bytes());
        if observed != self.binds.action_template_sha256 {
            return Err(OntologyError::TemplateHashMismatch {
                artifact: template_label,
                expected: self.binds.action_template_sha256.clone(),
                observed,
            });
        }

        // The loaded template's own provider/action must equal the sidecar locator: the hash proves
        // the bytes, this proves the bytes describe the same verb the sidecar claims to annotate.
        let locator: ArtifactLocator =
            serde_yaml::from_str(template).map_err(|error| OntologyError::TemplateUnparseable {
                artifact: template_label.clone(),
                reason: error.to_string(),
            })?;
        if locator.provider != self.provider || locator.action != self.action {
            return Err(OntologyError::TemplateLocatorMismatch {
                artifact: template_label,
                expected: format!("{}.{}", self.provider, self.action),
                observed: format!("{}.{}", locator.provider, locator.action),
            });
        }

        Ok(())
    }
}

/// The minimal locator lifted from an action template document for the join's identity check. Extra
/// template keys are intentionally ignored (no `deny_unknown_fields`): the ontology checker verifies
/// only that the bytes it hashed describe the same verb, not the full template grammar.
#[derive(Debug, Deserialize)]
struct ArtifactLocator {
    provider: String,
    action: String,
}

/// The exact provider-descriptor and action-template bytes an [`OntologyCatalog`] joins against.
///
/// This is explicit vendoring: the bytes are baked in with `include_str!` at compile
/// time, never discovered by walking a mutable directory at runtime. Keys are `provider` for
/// descriptors and `(provider, action)` for templates; the join reconstructs the artifact path
/// label deterministically.
#[derive(Debug, Clone, Default)]
pub struct OntologyArtifacts {
    descriptors: BTreeMap<&'static str, &'static str>,
    templates: BTreeMap<(&'static str, &'static str), &'static str>,
}

impl OntologyArtifacts {
    /// The vendored descriptor/template bytes referenced by [`VENDORED_ONTOLOGY`]'s records.
    pub fn vendored() -> Self {
        let mut descriptors = BTreeMap::new();
        descriptors.insert("github", include_str!("../providers/github.yaml"));
        descriptors.insert("stripe", include_str!("../providers/stripe.yaml"));
        descriptors.insert("vercel", include_str!("../providers/vercel.yaml"));

        let mut templates = BTreeMap::new();
        templates.insert(
            ("vercel", "deploy"),
            include_str!("../actions/vercel.deploy.yaml"),
        );
        templates.insert(
            ("vercel", "list_projects"),
            include_str!("../actions/vercel.list_projects.yaml"),
        );
        templates.insert(
            ("github", "read_repo"),
            include_str!("../actions/github.read_repo.yaml"),
        );
        templates.insert(
            ("github", "read_ref"),
            include_str!("../actions/github.read_ref.yaml"),
        );
        templates.insert(
            ("github", "read_commit"),
            include_str!("../actions/github.read_commit.yaml"),
        );
        templates.insert(
            ("github", "merge_pull_request"),
            include_str!("../actions/github.merge_pull_request.yaml"),
        );
        templates.insert(
            ("github", "update_pull_request"),
            include_str!("../actions/github.update_pull_request.yaml"),
        );
        templates.insert(
            ("github", "read_tree"),
            include_str!("../actions/github.read_tree.yaml"),
        );
        templates.insert(
            ("github", "read_blob"),
            include_str!("../actions/github.read_blob.yaml"),
        );
        templates.insert(
            ("github", "read_thread"),
            include_str!("../actions/github.read_thread.yaml"),
        );
        templates.insert(
            ("github", "read_pull_request"),
            include_str!("../actions/github.read_pull_request.yaml"),
        );
        templates.insert(
            ("github", "push"),
            include_str!("../actions/github.push.yaml"),
        );
        templates.insert(
            ("github", "push_tag"),
            include_str!("../actions/github.push_tag.yaml"),
        );
        templates.insert(
            ("github", "fetch"),
            include_str!("../actions/github.fetch.yaml"),
        );
        // GitHub guarded writes and automation.
        templates.insert(
            ("github", "read_workflow_run"),
            include_str!("../actions/github.read_workflow_run.yaml"),
        );
        templates.insert(
            ("github", "read_workflow_run_jobs"),
            include_str!("../actions/github.read_workflow_run_jobs.yaml"),
        );
        templates.insert(
            ("github", "read_job_log"),
            include_str!("../actions/github.read_job_log.yaml"),
        );
        templates.insert(
            ("github", "read_releases"),
            include_str!("../actions/github.read_releases.yaml"),
        );
        templates.insert(
            ("github", "read_workflow_runs"),
            include_str!("../actions/github.read_workflow_runs.yaml"),
        );
        templates.insert(
            ("github", "publish_release"),
            include_str!("../actions/github.publish_release.yaml"),
        );
        templates.insert(
            ("github", "create_issue"),
            include_str!("../actions/github.create_issue.yaml"),
        );
        templates.insert(
            ("github", "comment_thread"),
            include_str!("../actions/github.comment_thread.yaml"),
        );
        templates.insert(
            ("github", "create_branch"),
            include_str!("../actions/github.create_branch.yaml"),
        );
        templates.insert(
            ("github", "create_pull_request_review"),
            include_str!("../actions/github.create_pull_request_review.yaml"),
        );
        templates.insert(
            ("github", "request_workflow_cancel"),
            include_str!("../actions/github.request_workflow_cancel.yaml"),
        );
        templates.insert(
            ("github", "dispatch_workflow"),
            include_str!("../actions/github.dispatch_workflow.yaml"),
        );
        templates.insert(
            ("github", "request_deployment"),
            include_str!("../actions/github.request_deployment.yaml"),
        );
        templates.insert(
            ("github", "create_pull_request"),
            include_str!("../actions/github.create_pull_request.yaml"),
        );
        templates.insert(
            ("github", "read_secret_scanning_alerts_open"),
            include_str!("../actions/github.read_secret_scanning_alerts_open.yaml"),
        );
        // Stripe corpus: seven exact-resource, no-retention reads.
        templates.insert(
            ("stripe", "get_invoice"),
            include_str!("../actions/stripe.get_invoice.yaml"),
        );
        templates.insert(
            ("stripe", "list_invoices_for_customer"),
            include_str!("../actions/stripe.list_invoices_for_customer.yaml"),
        );
        templates.insert(
            ("stripe", "get_payment_intent"),
            include_str!("../actions/stripe.get_payment_intent.yaml"),
        );
        templates.insert(
            ("stripe", "get_dispute_summary"),
            include_str!("../actions/stripe.get_dispute_summary.yaml"),
        );
        templates.insert(
            ("stripe", "get_product"),
            include_str!("../actions/stripe.get_product.yaml"),
        );
        templates.insert(
            ("stripe", "get_price"),
            include_str!("../actions/stripe.get_price.yaml"),
        );
        templates.insert(
            ("stripe", "list_active_prices"),
            include_str!("../actions/stripe.list_active_prices.yaml"),
        );
        // Stripe corpus: six fixed-variant, no-retention billing and catalog mutations.
        templates.insert(
            ("stripe", "cancel_subscription_at_period_end"),
            include_str!("../actions/stripe.cancel_subscription_at_period_end.yaml"),
        );
        templates.insert(
            ("stripe", "resume_subscription_collection"),
            include_str!("../actions/stripe.resume_subscription_collection.yaml"),
        );
        templates.insert(
            ("stripe", "mark_invoice_uncollectible"),
            include_str!("../actions/stripe.mark_invoice_uncollectible.yaml"),
        );
        templates.insert(
            ("stripe", "issue_credit_note_adjustment_no_email"),
            include_str!("../actions/stripe.issue_credit_note_adjustment_no_email.yaml"),
        );
        templates.insert(
            ("stripe", "archive_product"),
            include_str!("../actions/stripe.archive_product.yaml"),
        );
        templates.insert(
            ("stripe", "archive_price"),
            include_str!("../actions/stripe.archive_price.yaml"),
        );
        // Stripe corpus: separately granted evidence stage/submit plus an exact fixed webhook
        // bundle.
        templates.insert(
            ("stripe", "stage_dispute_evidence"),
            include_str!("../actions/stripe.stage_dispute_evidence.yaml"),
        );
        templates.insert(
            ("stripe", "submit_dispute_evidence"),
            include_str!("../actions/stripe.submit_dispute_evidence.yaml"),
        );
        templates.insert(
            ("stripe", "update_webhook_endpoint_fixed_bundle"),
            include_str!("../actions/stripe.update_webhook_endpoint_fixed_bundle.yaml"),
        );
        // Moneypath: seven separately authorized money mutations.
        templates.insert(
            ("stripe", "create_payment_intent_off_session"),
            include_str!("../actions/stripe.create_payment_intent_off_session.yaml"),
        );
        templates.insert(
            ("stripe", "confirm_payment_intent"),
            include_str!("../actions/stripe.confirm_payment_intent.yaml"),
        );
        templates.insert(
            ("stripe", "capture_payment_intent"),
            include_str!("../actions/stripe.capture_payment_intent.yaml"),
        );
        templates.insert(
            ("stripe", "cancel_payment_intent"),
            include_str!("../actions/stripe.cancel_payment_intent.yaml"),
        );
        templates.insert(
            ("stripe", "retry_invoice_payment"),
            include_str!("../actions/stripe.retry_invoice_payment.yaml"),
        );
        templates.insert(
            ("stripe", "refund_charge_bounded"),
            include_str!("../actions/stripe.refund_charge_bounded.yaml"),
        );
        templates.insert(
            ("stripe", "create_standard_payout"),
            include_str!("../actions/stripe.create_standard_payout.yaml"),
        );
        templates.insert(
            ("stripe", "create_customer"),
            include_str!("../actions/stripe.create_customer.yaml"),
        );
        templates.insert(
            ("stripe", "create_product"),
            include_str!("../actions/stripe.create_product.yaml"),
        );
        templates.insert(
            ("stripe", "create_recurring_price"),
            include_str!("../actions/stripe.create_recurring_price.yaml"),
        );
        templates.insert(
            ("stripe", "create_draft_invoice"),
            include_str!("../actions/stripe.create_draft_invoice.yaml"),
        );
        templates.insert(
            ("stripe", "attach_payment_method"),
            include_str!("../actions/stripe.attach_payment_method.yaml"),
        );
        templates.insert(
            ("stripe", "create_subscription"),
            include_str!("../actions/stripe.create_subscription.yaml"),
        );
        templates.insert(
            ("stripe", "create_charge_from_source"),
            include_str!("../actions/stripe.create_charge_from_source.yaml"),
        );
        templates.insert(
            ("stripe", "list_disputes"),
            include_str!("../actions/stripe.list_disputes.yaml"),
        );
        templates.insert(
            ("stripe", "read_account"),
            include_str!("../actions/stripe.read_account.yaml"),
        );

        Self {
            descriptors,
            templates,
        }
    }
}

/// The V1 ontology records vendored with the core, one `include_str!` per file in
/// `crates/cermet-core/ontology/`: six read GitHub records (repo/ref/tree/blob/thread/PR), the
/// git-native `push` and `push_tag`, the GitHub guarded-writes-and-automation set (two Actions reads —
/// `read_workflow_run` plus `read_workflow_run_jobs` —
/// plus seven durable-broker-only writes — create_branch/create_issue/comment_thread/
/// create_pull_request_review/request_workflow_cancel/dispatch_workflow/
/// request_deployment), the verb-corpus GitHub
/// draft-PR write and bounded secret-alert read, nine Vercel reads and six Vercel writes
/// (preview/cancel/promote/rollback/env/project-create — read_logs/deploy/set_env_var retired), and
/// seven Stripe corpus reads, six Stripe fixed mutations, and three Stripe dispute/webhook mutations.
/// Each binds the exact SHA-256 of its
/// provider descriptor and action
/// template; [`OntologyArtifacts::vendored`] supplies the bytes those digests must match. This list
/// lives here (not beside `VENDORED_CATALOG` in `templates`) so the ontology never enters an
/// authority module — see the authority-inertness guard.
pub const VENDORED_ONTOLOGY: &[&str] = &[
    include_str!("../ontology/github.read_repo.yaml"),
    include_str!("../ontology/github.read_ref.yaml"),
    include_str!("../ontology/github.read_commit.yaml"),
    include_str!("../ontology/github.merge_pull_request.yaml"),
    include_str!("../ontology/github.update_pull_request.yaml"),
    include_str!("../ontology/github.read_tree.yaml"),
    include_str!("../ontology/github.read_blob.yaml"),
    include_str!("../ontology/github.read_thread.yaml"),
    include_str!("../ontology/github.read_pull_request.yaml"),
    // the system-git carrier verb.
    include_str!("../ontology/github.push.yaml"),
    // The tag namespace's own word: a branch sentence never widens onto it.
    include_str!("../ontology/github.push_tag.yaml"),
    include_str!("../ontology/github.fetch.yaml"),
    // GitHub guarded writes and automation: the two Actions reads plus seven guarded
    // writes. All run on the durable daemon (there is no separate daemonless surface).
    include_str!("../ontology/github.read_workflow_run.yaml"),
    // The CI-diagnosis read that names the failing job and, through each job's steps, the failing
    // step.
    include_str!("../ontology/github.read_workflow_run_jobs.yaml"),
    // The minted-URL read that ends the diagnosis ladder — the broker spends the credential to mint
    // a ~60s log URL, native curl moves the bytes.
    include_str!("../ontology/github.read_job_log.yaml"),
    // The release plane: find the run for a pushed commit, find the draft, publish it.
    include_str!("../ontology/github.read_workflow_runs.yaml"),
    include_str!("../ontology/github.read_releases.yaml"),
    include_str!("../ontology/github.publish_release.yaml"),
    include_str!("../ontology/github.create_branch.yaml"),
    include_str!("../ontology/github.create_issue.yaml"),
    include_str!("../ontology/github.comment_thread.yaml"),
    include_str!("../ontology/github.create_pull_request_review.yaml"),
    include_str!("../ontology/github.request_workflow_cancel.yaml"),
    include_str!("../ontology/github.dispatch_workflow.yaml"),
    include_str!("../ontology/github.request_deployment.yaml"),
    include_str!("../ontology/github.create_pull_request.yaml"),
    include_str!("../ontology/github.read_secret_scanning_alerts_open.yaml"),
    // Stripe corpus: seven narrow reads with official Stripe endpoint and permission sources.
    include_str!("../ontology/stripe.get_invoice.yaml"),
    include_str!("../ontology/stripe.list_invoices_for_customer.yaml"),
    include_str!("../ontology/stripe.get_payment_intent.yaml"),
    include_str!("../ontology/stripe.get_dispute_summary.yaml"),
    include_str!("../ontology/stripe.get_product.yaml"),
    include_str!("../ontology/stripe.get_price.yaml"),
    include_str!("../ontology/stripe.list_active_prices.yaml"),
    // Stripe corpus: six fixed billing/catalog mutations with no retained response body.
    include_str!("../ontology/stripe.cancel_subscription_at_period_end.yaml"),
    include_str!("../ontology/stripe.resume_subscription_collection.yaml"),
    include_str!("../ontology/stripe.mark_invoice_uncollectible.yaml"),
    include_str!("../ontology/stripe.issue_credit_note_adjustment_no_email.yaml"),
    include_str!("../ontology/stripe.archive_product.yaml"),
    include_str!("../ontology/stripe.archive_price.yaml"),
    // Stripe corpus: separately granted evidence stage/submit and fixed-bundle webhook redirect.
    include_str!("../ontology/stripe.stage_dispute_evidence.yaml"),
    include_str!("../ontology/stripe.submit_dispute_evidence.yaml"),
    include_str!("../ontology/stripe.update_webhook_endpoint_fixed_bundle.yaml"),
    // Moneypath: funds_collect, cash_refund, and funds_outbound operations.
    include_str!("../ontology/stripe.create_payment_intent_off_session.yaml"),
    include_str!("../ontology/stripe.confirm_payment_intent.yaml"),
    include_str!("../ontology/stripe.capture_payment_intent.yaml"),
    include_str!("../ontology/stripe.cancel_payment_intent.yaml"),
    include_str!("../ontology/stripe.retry_invoice_payment.yaml"),
    include_str!("../ontology/stripe.refund_charge_bounded.yaml"),
    include_str!("../ontology/stripe.create_standard_payout.yaml"),
    include_str!("../ontology/stripe.create_customer.yaml"),
    include_str!("../ontology/stripe.create_product.yaml"),
    include_str!("../ontology/stripe.create_recurring_price.yaml"),
    include_str!("../ontology/stripe.create_draft_invoice.yaml"),
    include_str!("../ontology/stripe.attach_payment_method.yaml"),
    include_str!("../ontology/stripe.create_subscription.yaml"),
    include_str!("../ontology/stripe.create_charge_from_source.yaml"),
    include_str!("../ontology/stripe.list_disputes.yaml"),
    include_str!("../ontology/stripe.read_account.yaml"),
    // Appended last: two hash-join tests index VENDORED_ONTOLOGY[0].
    include_str!("../ontology/vercel.deploy.yaml"),
    include_str!("../ontology/vercel.list_projects.yaml"),
];

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Clone)]
pub struct OntologyCatalog {
    records: BTreeMap<(String, String), OntologyRecord>,
}

impl OntologyCatalog {
    pub fn check(documents: &[&str], sources: &SourceRegistry) -> Result<Self, OntologyError> {
        let mut records = BTreeMap::new();
        for document in documents {
            let record = OntologyRecord::parse(document, sources)?;
            let key = (record.provider.clone(), record.action.clone());
            match records.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(record);
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    return Err(OntologyError::DuplicateBinding {
                        provider: entry.key().0.clone(),
                        action: entry.key().1.clone(),
                    });
                }
            }
        }
        Ok(Self { records })
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, provider: &str, action: &str) -> Option<&OntologyRecord> {
        self.records.get(&(provider.to_owned(), action.to_owned()))
    }

    /// Hash-join every record in the catalog against `artifacts`. Fails on the first record whose
    /// declared descriptor/template digest does not match the real vendored bytes, or whose named
    /// artifact is absent (see [`OntologyRecord::join_artifacts`]).
    pub fn join_all(&self, artifacts: &OntologyArtifacts) -> Result<(), OntologyError> {
        for record in self.records.values() {
            record.join_artifacts(artifacts)?;
        }
        Ok(())
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), OntologyError> {
    if valid_identifier(value) {
        Ok(())
    } else {
        Err(OntologyError::InvalidIdentifier {
            field,
            value: value.to_owned(),
        })
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), OntologyError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(OntologyError::InvalidSha256 {
            field,
            value: value.to_owned(),
        })
    }
}

fn validate_text(field: String, value: &str, cap: usize) -> Result<(), OntologyError> {
    let reason = if value.is_empty() {
        Some("must be nonempty")
    } else if value.len() > cap {
        Some("exceeds its UTF-8 byte cap")
    } else if value.trim() != value {
        Some("must not have leading or trailing whitespace")
    } else if value.bytes().any(|byte| byte.is_ascii_control())
        || value
            .chars()
            .any(|character| matches!(character, '\u{0085}' | '\u{2028}' | '\u{2029}'))
    {
        Some("must be single-line and contain no ASCII controls")
    } else {
        None
    };

    match reason {
        Some(reason) => Err(OntologyError::InvalidText { field, reason }),
        None => Ok(()),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRegistryDocument {
    schema: String,
    sources: Vec<SourceRegistryEntry>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceRegistryEntry {
    pub id: String,
    pub url: String,
    pub rechecked_at: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SourceRegistryError {
    #[error("source registry document is {actual} bytes, over the {cap}-byte cap")]
    DocumentTooLarge { actual: usize, cap: usize },
    #[error("invalid source registry document: {0}")]
    InvalidDocument(String),
    #[error("unsupported source registry schema `{0}`")]
    UnsupportedSchema(String),
    #[error("source registry must contain at least one source")]
    EmptyRegistry,
    #[error("invalid ontology source ID `{0}`")]
    InvalidSourceId(String),
    #[error("duplicate ontology source ID `{0}`")]
    DuplicateId(String),
    #[error("duplicate ontology source URL `{0}`")]
    DuplicateUrl(String),
    #[error("invalid ontology source recheck date `{0}`")]
    InvalidRecheckDate(String),
    #[error("invalid official ontology source URL `{0}`")]
    InvalidOfficialUrl(String),
    #[error("unknown ontology source ID `{0}`")]
    UnknownSourceId(String),
}

#[derive(Debug, Clone)]
pub struct SourceRegistry {
    entries: BTreeMap<String, SourceRegistryEntry>,
}

impl SourceRegistry {
    pub fn parse(document: &str) -> Result<Self, SourceRegistryError> {
        if document.len() > MAX_SOURCE_REGISTRY_BYTES {
            return Err(SourceRegistryError::DocumentTooLarge {
                actual: document.len(),
                cap: MAX_SOURCE_REGISTRY_BYTES,
            });
        }

        let document: SourceRegistryDocument = serde_yaml::from_str(document)
            .map_err(|error| SourceRegistryError::InvalidDocument(error.to_string()))?;
        if document.schema != SOURCE_REGISTRY_SCHEMA {
            return Err(SourceRegistryError::UnsupportedSchema(document.schema));
        }
        if document.sources.is_empty() {
            return Err(SourceRegistryError::EmptyRegistry);
        }

        let mut entries = BTreeMap::new();
        let mut urls = BTreeSet::new();
        for source in document.sources {
            if !valid_source_id(&source.id) {
                return Err(SourceRegistryError::InvalidSourceId(source.id));
            }
            if !valid_calendar_date(&source.rechecked_at) {
                return Err(SourceRegistryError::InvalidRecheckDate(source.rechecked_at));
            }
            if !valid_official_url(&source.url) {
                return Err(SourceRegistryError::InvalidOfficialUrl(source.url));
            }
            if entries.contains_key(&source.id) {
                return Err(SourceRegistryError::DuplicateId(source.id));
            }
            if !urls.insert(source.url.clone()) {
                return Err(SourceRegistryError::DuplicateUrl(source.url));
            }
            entries.insert(source.id.clone(), source);
        }

        Ok(Self { entries })
    }

    pub fn official() -> Result<Self, SourceRegistryError> {
        Self::parse(OFFICIAL_SOURCE_REGISTRY_YAML)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &SourceRegistryEntry> {
        self.entries.values()
    }

    pub fn require(&self, source_id: &str) -> Result<&SourceRegistryEntry, SourceRegistryError> {
        self.entries
            .get(source_id)
            .ok_or_else(|| SourceRegistryError::UnknownSourceId(source_id.to_owned()))
    }
}

fn valid_source_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    bytes.len() <= 64
        && (first.is_ascii_uppercase() || first.is_ascii_digit())
        && rest.iter().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_calendar_date(date: &str) -> bool {
    let bytes = date.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        return false;
    }

    let year = digits(&bytes[0..4]);
    let month = digits(&bytes[5..7]);
    let day = digits(&bytes[8..10]);
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };

    year != 0 && (1..=days_in_month).contains(&day)
}

fn digits(bytes: &[u8]) -> u16 {
    bytes
        .iter()
        .fold(0, |value, digit| value * 10 + u16::from(digit - b'0'))
}

fn valid_official_url(url: &str) -> bool {
    if !url.starts_with("https://") || url.trim() != url {
        return false;
    }

    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.port().is_none()
        && parsed
            .host_str()
            .is_some_and(|host| OFFICIAL_SOURCE_HOSTS.contains(&host))
}
