//! Non-authorizing repository reconciliation for `CERMET.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cermet_ctl_client::presence::{Presence, PresenceOutcome};
use cermet_ipc::ctl::{CtlRequest, LockdownSnapshot, SentenceAuthorityStatus, SentenceSnapshot};
use cermet_lang::sentence::{print_rule, PreparedSentenceCorpus, Selector};
use serde::Serialize;

use crate::cermet_document::{
    analyze_body, classify_drift, render_template, AuthorityDigest, AuthorityMarker,
    DataPlaneState, DriftState, ManagedDocument, RepositoryState,
};
use crate::document_store::{
    DestinationModeStatus, DocumentRead, DocumentStore, FinalDestinationState,
    PublicationDurability, PublicationOutcome, PublicationReport, ReadOutcome, TempCleanupStatus,
};
use crate::sentence_custody::{CorpusDocumentObservation, CorpusDocumentSync};

const TERMINAL_RECONCILIATION_ROUNDS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationOutput {
    pub text: String,
    pub exit_code: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparationFailure {
    Invalid(String),
    ProviderDisabled,
    Unavailable,
}

pub trait ReconciliationClient {
    fn prepare(&self, candidate_text: String)
        -> Result<PreparedSentenceCorpus, PreparationFailure>;
    fn authority_status(&self) -> Result<SentenceAuthorityStatus, String>;
}

pub trait ApplyTransactionClient: ReconciliationClient {
    fn stage(
        &self,
        candidate_text: String,
    ) -> Result<cermet_ipc::ctl::StagedSentenceCorpus, PreparationFailure>;
    fn commit(&self, staging_token: String) -> ApplyCommitAttempt;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyCommitAttempt {
    Acknowledged(cermet_ipc::ctl::SentenceCommitOutcome),
    Refused,
    Unknown,
}

pub struct CtlReconciliationClient {
    client: cermet_ctl_client::broker_client::CtlBrokerClient,
    runtime: tokio::runtime::Runtime,
}

impl CtlReconciliationClient {
    pub fn new(client: cermet_ctl_client::broker_client::CtlBrokerClient) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "cannot start the reconciliation runtime".to_string())?;
        Ok(Self { client, runtime })
    }
}

impl ReconciliationClient for CtlReconciliationClient {
    fn prepare(
        &self,
        candidate_text: String,
    ) -> Result<PreparedSentenceCorpus, PreparationFailure> {
        self.runtime
            .block_on(self.client.prepare_sentences(candidate_text))
            .map_err(|error| classify_preparation_error(&error))
    }

    fn authority_status(&self) -> Result<SentenceAuthorityStatus, String> {
        self.runtime
            .block_on(self.client.sentence_authority_status())
            .map_err(|error| error.to_string())
    }
}

impl ApplyTransactionClient for CtlReconciliationClient {
    fn stage(
        &self,
        candidate_text: String,
    ) -> Result<cermet_ipc::ctl::StagedSentenceCorpus, PreparationFailure> {
        self.runtime
            .block_on(self.client.stage_sentences(candidate_text))
            .map_err(|error| classify_preparation_error(&error))
    }

    fn commit(&self, staging_token: String) -> ApplyCommitAttempt {
        match self
            .runtime
            .block_on(self.client.commit_sentences(staging_token))
        {
            Ok(outcome) => ApplyCommitAttempt::Acknowledged(outcome),
            Err(cermet_lang::Error::Denied(_)) | Err(cermet_lang::Error::Invalid(_)) => {
                ApplyCommitAttempt::Refused
            }
            Err(_) => ApplyCommitAttempt::Unknown,
        }
    }
}

fn classify_preparation_error(error: &cermet_lang::Error) -> PreparationFailure {
    match error {
        cermet_lang::Error::Invalid(reason) => PreparationFailure::Invalid(reason.clone()),
        cermet_lang::Error::ProviderDisabled => PreparationFailure::ProviderDisabled,
        _ => PreparationFailure::Unavailable,
    }
}

struct PreparedDocument {
    read: DocumentRead,
    marker: AuthorityMarker,
    prepared: PreparedSentenceCorpus,
    canonical: bool,
    source_is_empty: bool,
}

enum DocumentView {
    Missing,
    Invalid(String),
    ProviderDisabled,
    Unavailable,
    Prepared(Box<PreparedDocument>),
}

struct ObservedState {
    drift: DriftState,
    document: &'static str,
    candidate: Option<String>,
    marker: Option<String>,
    live: Option<String>,
    live_state: &'static str,
    canonical: Option<bool>,
    lockdown: &'static str,
}

#[derive(Serialize)]
struct StatusView<'a> {
    state: &'a str,
    document: &'a str,
    candidate: Option<&'a str>,
    marker: Option<&'a str>,
    live: Option<&'a str>,
    live_state: &'a str,
    canonical: Option<bool>,
    lockdown: &'a str,
}

pub fn run_init(client: &dyn ReconciliationClient, start: &Path) -> ReconciliationOutput {
    let store = match DocumentStore::discover(start) {
        Ok(store) => store,
        Err(_) => {
            let status = client.authority_status().ok();
            let observed = compose_state(
                &DocumentView::Invalid("repository unavailable".into()),
                status.as_ref(),
            );
            return operation_failure("init: repository unavailable", &observed);
        }
    };
    match store.read() {
        Ok(ReadOutcome::Missing) => {}
        Ok(ReadOutcome::Present(_)) => {
            let document = prepare_document(client, &store);
            let status = client.authority_status().ok();
            let observed = compose_state(&document, status.as_ref());
            return operation_failure("init: CERMET.md already exists", &observed);
        }
        Err(_) => {
            let status = client.authority_status().ok();
            let observed = compose_state(
                &DocumentView::Invalid("CERMET.md is not safely readable".into()),
                status.as_ref(),
            );
            return operation_failure("init: CERMET.md is not safely readable", &observed);
        }
    }
    let status = match client.authority_status() {
        Ok(status) => status,
        Err(_) => {
            let observed = compose_state(&DocumentView::Missing, None);
            return operation_failure("init: dataplane unavailable", &observed);
        }
    };
    let mut observed = compose_state(&DocumentView::Missing, Some(&status));
    let (marker, body) = match &status.sentence {
        SentenceSnapshot::Absent => (AuthorityMarker::none(), Vec::new()),
        SentenceSnapshot::Served {
            authority_digest,
            rules_text,
            ..
        } => {
            let marker = match marker_from_hex(authority_digest) {
                Some(marker) => marker,
                None => return operation_failure("init: served snapshot is malformed", &observed),
            };
            match validate_served(client, rules_text, authority_digest) {
                Ok(_) => {}
                Err(PreparationFailure::Invalid(_)) => {
                    observed.drift = DriftState::DataPlaneUnserved;
                    observed.live = None;
                    observed.live_state = "unserved";
                    return operation_failure("init: served snapshot is not preparable", &observed);
                }
                Err(PreparationFailure::ProviderDisabled) => return provider_disabled(),
                Err(PreparationFailure::Unavailable) => {
                    observed.drift = DriftState::DataPlaneUnknown;
                    return operation_failure("init: dataplane unavailable", &observed);
                }
            }
            (marker, rules_text.as_bytes().to_vec())
        }
        SentenceSnapshot::Unserved { .. } => {
            return operation_failure("init: dataplane unserved", &observed);
        }
        SentenceSnapshot::Corrupt { .. } => {
            return operation_failure("init: dataplane corrupt", &observed);
        }
    };
    let bytes = match render_template(&marker, &body) {
        Ok(bytes) => bytes,
        Err(_) => return operation_failure("init: served snapshot cannot be rendered", &observed),
    };
    let mut report = match store.create(&bytes) {
        Ok(report) => report,
        Err(_) => return operation_failure("init: no file was safely created", &observed),
    };
    // Prepare the repository before observing live status, then refresh exact file evidence after
    // every daemon call so neither side of the final report comes from a stale race snapshot.
    let final_document = prepare_document(client, &store);
    let final_status = client.authority_status().ok();
    refresh_publication_final_state(&store, &mut report, &bytes);
    let final_observed =
        compose_final_state(&final_document, final_status.as_ref(), &report.final_state);
    let live_changed = live_changed(&status, final_status.as_ref());
    let clean = publication_is_clean(&report, &bytes);
    let mut text = format!(
        "initialized: {}\n{}\nstate: {}\nlockdown: {}\nlive_changed: {live_changed}",
        store.root_path().join("CERMET.md").display(),
        render_publication(&report, &bytes),
        drift_name(&final_observed.drift),
        final_observed.lockdown,
    );
    if !clean {
        text.push_str("\nresult: final file differs from the intended write");
    }
    ReconciliationOutput {
        exit_code: if clean {
            drift_exit(&final_observed.drift)
        } else {
            2
        },
        text,
    }
}

pub fn run_check(
    client: &dyn ReconciliationClient,
    start: &Path,
    fix: bool,
) -> ReconciliationOutput {
    let store = match DocumentStore::discover(start) {
        Ok(store) => store,
        Err(_) => return malformed("repository: unavailable"),
    };
    let prepared = match prepare_document(client, &store) {
        DocumentView::Prepared(prepared) => prepared,
        DocumentView::Missing => return malformed("check: CERMET.md is missing"),
        DocumentView::Invalid(reason) => {
            return malformed(&format!(
                "check: repository candidate is invalid — {reason}"
            ))
        }
        DocumentView::ProviderDisabled => return provider_disabled(),
        DocumentView::Unavailable => return malformed("check: dataplane unavailable"),
    };
    let digest = display_digest(&prepared.prepared.canonical_digest);
    if !fix {
        return ReconciliationOutput {
            text: format!(
                "candidate: {digest}\ncanonical: {}\nrules: {}{}",
                yes_no(prepared.canonical),
                prepared.prepared.rule_count,
                if prepared.canonical {
                    ""
                } else {
                    "\naction: run cermet check --fix"
                }
            ),
            exit_code: if prepared.canonical { 0 } else { 1 },
        };
    }
    if prepared.canonical {
        return ReconciliationOutput {
            text: format!("candidate: {digest}\ncanonical: yes\nwrite: not needed"),
            exit_code: 0,
        };
    }
    let parsed = match ManagedDocument::parse(&prepared.read.bytes) {
        Ok(parsed) => parsed,
        Err(_) => return malformed("check: repository candidate became invalid"),
    };
    let rewritten = match parsed.rewrite(
        &prepared.marker,
        prepared.prepared.canonical_text.as_bytes(),
    ) {
        Ok(rewritten) => rewritten,
        Err(_) => return malformed("check: canonical candidate cannot be rendered"),
    };
    let report = match store.replace(&prepared.read.preimage, &rewritten) {
        Ok(report) => report,
        Err(_) => return malformed("check: file changed before the safe replacement"),
    };
    let clean = publication_is_clean(&report, &rewritten);
    ReconciliationOutput {
        text: format!(
            "candidate: {digest}\ncanonical: {}\n{}",
            if clean { "yes" } else { "unknown" },
            render_publication(&report, &rewritten)
        ),
        exit_code: if clean { 0 } else { 2 },
    }
}

pub fn run_status(
    client: &dyn ReconciliationClient,
    start: &Path,
    as_json: bool,
) -> ReconciliationOutput {
    let document = observe_document(client, start);
    let authority = client.authority_status().ok();
    let final_state = current_destination_state(start);
    render_observed(
        &compose_final_state(&document, authority.as_ref(), &final_state),
        as_json,
    )
}

pub fn observe_mutation_document_sync(
    client: &dyn ReconciliationClient,
    start: &Path,
    status: Option<&SentenceAuthorityStatus>,
) -> CorpusDocumentSync {
    observe_mutation_document(client, start, status).sync
}

pub fn observe_mutation_document(
    client: &dyn ReconciliationClient,
    start: &Path,
    status: Option<&SentenceAuthorityStatus>,
) -> CorpusDocumentObservation {
    let Some(status) = status else {
        return CorpusDocumentObservation {
            sync: CorpusDocumentSync::Required,
            status: client.authority_status().ok(),
        };
    };
    let Ok(store) = DocumentStore::discover(start) else {
        return CorpusDocumentObservation {
            sync: CorpusDocumentSync::Unavailable,
            status: client.authority_status().ok(),
        };
    };
    let initial_state = read_destination_state(&store);
    let document = prepare_document(client, &store);
    let current_status = client.authority_status().ok();
    if matches!(document, DocumentView::Unavailable) {
        return CorpusDocumentObservation {
            sync: CorpusDocumentSync::Unavailable,
            status: current_status,
        };
    }
    if matches!(document, DocumentView::ProviderDisabled) {
        return CorpusDocumentObservation {
            sync: CorpusDocumentSync::Required,
            status: current_status,
        };
    }
    let Some(current_status) = current_status else {
        return CorpusDocumentObservation {
            sync: CorpusDocumentSync::Required,
            status: None,
        };
    };
    let final_state = read_destination_state(&store);
    let root_stable = DocumentStore::discover(start).is_ok_and(|rediscovered| {
        rediscovered.root_identity() == store.root_identity()
            && rediscovered.root_path() == store.root_path()
    });
    let repository_stable = match (&initial_state, &final_state) {
        (FinalDestinationState::Missing, FinalDestinationState::Missing) => true,
        (FinalDestinationState::Present(initial), FinalDestinationState::Present(final_read)) => {
            final_read.exact_state_matches(initial)
        }
        (
            FinalDestinationState::Unreadable(initial),
            FinalDestinationState::Unreadable(final_error),
        ) => final_error == initial,
        _ => false,
    };
    if &current_status != status || !root_stable || !repository_stable {
        return CorpusDocumentObservation {
            sync: CorpusDocumentSync::Required,
            status: Some(current_status),
        };
    }
    let observed = compose_final_state(&document, Some(&current_status), &final_state);
    CorpusDocumentObservation {
        sync: CorpusDocumentSync::State(drift_name(&observed.drift)),
        status: Some(current_status),
    }
}

pub fn run_diff(client: &dyn ReconciliationClient, start: &Path) -> ReconciliationOutput {
    let document = observe_document(client, start);
    if matches!(document, DocumentView::ProviderDisabled) {
        return provider_disabled();
    }
    let authority = client.authority_status().ok();
    let mut observed = compose_state(&document, authority.as_ref());
    let live_prepared = match authority.as_ref().map(|status| &status.sentence) {
        Some(SentenceSnapshot::Absent) => Some(empty_prepared()),
        Some(SentenceSnapshot::Served {
            rules_text,
            authority_digest,
            ..
        }) => match validate_served(client, rules_text, authority_digest) {
            Ok(prepared) => Some(prepared),
            Err(PreparationFailure::Invalid(_)) => {
                observed.drift = DriftState::DataPlaneUnserved;
                observed.live = None;
                observed.live_state = "unserved";
                None
            }
            Err(PreparationFailure::ProviderDisabled) => return provider_disabled(),
            Err(PreparationFailure::Unavailable) => {
                observed.drift = DriftState::DataPlaneUnknown;
                None
            }
        },
        Some(SentenceSnapshot::Unserved { .. } | SentenceSnapshot::Corrupt { .. }) | None => None,
    };
    let final_state = current_destination_state(start);
    if !document_matches_final_state(&document, &final_state) {
        observed = compose_state(
            &DocumentView::Invalid("document does not match the applied destination".into()),
            authority.as_ref(),
        );
    }
    let mut output = render_observed(&observed, false);
    let (DocumentView::Prepared(document), Some(live_prepared)) = (&document, live_prepared) else {
        return output;
    };
    output.text.push('\n');
    output.text.push_str(&unified_rule_diff(
        &document.prepared.canonical_text,
        &live_prepared.canonical_text,
    ));
    let set_diff = render_set_diff(&document.prepared, &live_prepared);
    if !set_diff.is_empty() {
        output.text.push('\n');
        output.text.push_str(&set_diff);
    }
    output
}

pub fn run_export(
    client: &dyn ReconciliationClient,
    start: &Path,
    replace_draft: bool,
) -> ReconciliationOutput {
    let store = match DocumentStore::discover(start) {
        Ok(store) => store,
        Err(_) => {
            let authority = client.authority_status().ok();
            let observed = compose_state(
                &DocumentView::Invalid("repository unavailable".into()),
                authority.as_ref(),
            );
            return operation_failure("export: repository unavailable", &observed);
        }
    };
    let document_view = prepare_document(client, &store);
    let authority = client.authority_status();
    let mut observed = compose_state(&document_view, authority.as_ref().ok());
    let authority = match authority {
        Ok(authority) => authority,
        Err(_) => return operation_failure("export: dataplane unavailable", &observed),
    };
    let document = match document_view {
        DocumentView::Prepared(document) => document,
        DocumentView::Missing => {
            return operation_failure(
                "export: CERMET.md is missing; run cermet doc check --init",
                &observed,
            );
        }
        DocumentView::Invalid(reason) => {
            return operation_failure(
                &format!("export: repository candidate is invalid — {reason}"),
                &observed,
            );
        }
        DocumentView::ProviderDisabled => return provider_disabled(),
        DocumentView::Unavailable => {
            return operation_failure("export: dataplane unavailable", &observed);
        }
    };
    let (live_marker, live_text, exported_live) = match &authority.sentence {
        SentenceSnapshot::Absent => (AuthorityMarker::none(), String::new(), "none".to_string()),
        SentenceSnapshot::Served {
            authority_digest,
            rules_text,
            ..
        } => {
            match validate_served(client, rules_text, authority_digest) {
                Ok(_) => {}
                Err(PreparationFailure::Invalid(_)) => {
                    observed.drift = DriftState::DataPlaneUnserved;
                    observed.live = None;
                    observed.live_state = "unserved";
                    return operation_failure(
                        "export: served snapshot is not preparable",
                        &observed,
                    );
                }
                Err(PreparationFailure::ProviderDisabled) => return provider_disabled(),
                Err(PreparationFailure::Unavailable) => {
                    observed.drift = DriftState::DataPlaneUnknown;
                    return operation_failure("export: dataplane unavailable", &observed);
                }
            }
            let Some(marker) = marker_from_hex(authority_digest) else {
                return operation_failure("export: served snapshot is malformed", &observed);
            };
            (marker, rules_text.clone(), display_digest(authority_digest))
        }
        SentenceSnapshot::Unserved { .. } => {
            return operation_failure("export: dataplane unserved", &observed);
        }
        SentenceSnapshot::Corrupt { .. } => {
            return operation_failure("export: dataplane corrupt", &observed);
        }
    };
    let candidate = display_digest(&document.prepared.canonical_digest);
    let initialized_absent_baseline = document.source_is_empty && document.marker.is_none();
    let unapplied = !initialized_absent_baseline
        && candidate != document.marker.as_str()
        && candidate != live_marker.as_str();
    if unapplied && !replace_draft {
        return ReconciliationOutput {
            text: format!(
                "export: unapplied document edits preserved\naction: rerun with --replace-draft\nstate: {}\nlockdown: {}",
                drift_name(&observed.drift),
                observed.lockdown
            ),
            exit_code: 1,
        };
    }
    let parsed = match ManagedDocument::parse(&document.read.bytes) {
        Ok(parsed) => parsed,
        Err(_) => {
            return operation_failure("export: repository candidate became invalid", &observed);
        }
    };
    let rewritten = match parsed.rewrite(&live_marker, live_text.as_bytes()) {
        Ok(rewritten) => rewritten,
        Err(_) => {
            return operation_failure("export: served snapshot cannot be rendered", &observed);
        }
    };
    let prior_marker = document.marker.as_str().to_string();
    let mut report = match store.replace(&document.read.preimage, &rewritten) {
        Ok(report) => report,
        Err(_) => {
            return operation_failure(
                "export: file changed before the safe replacement",
                &observed,
            );
        }
    };
    // Prepare the repository before observing live status, then refresh exact file evidence after
    // every daemon call so neither side of the final report comes from a stale race snapshot.
    let final_document = prepare_document(client, &store);
    let final_status = client.authority_status().ok();
    refresh_publication_final_state(&store, &mut report, &rewritten);
    let final_observed =
        compose_final_state(&final_document, final_status.as_ref(), &report.final_state);
    let live_changed = live_changed(&authority, final_status.as_ref());
    let clean = publication_is_clean(&report, &rewritten);
    ReconciliationOutput {
        text: format!(
            "exported_live: {exported_live}\nprior_marker: {prior_marker}\n{}\nstate: {}\nlockdown: {}\nlive_changed: {live_changed}",
            render_publication(&report, &rewritten),
            drift_name(&final_observed.drift),
            final_observed.lockdown,
        ),
        exit_code: if clean {
            drift_exit(&final_observed.drift)
        } else {
            2
        },
    }
}

pub fn run_apply(
    client: &dyn ApplyTransactionClient,
    start: &Path,
    replace_live: bool,
    recover: bool,
    terminal: &dyn crate::tty::Terminal,
    presence: &dyn Presence,
) -> ReconciliationOutput {
    let store = match DocumentStore::discover(start) {
        Ok(store) => store,
        Err(_) => return malformed("apply: repository unavailable"),
    };
    let document = match prepare_document(client, &store) {
        DocumentView::Prepared(document) => document,
        DocumentView::Missing => {
            return malformed("apply: CERMET.md is missing; run cermet doc check --init")
        }
        DocumentView::Invalid(reason) => {
            return malformed(&format!(
                "apply: repository candidate is invalid — {reason}"
            ))
        }
        DocumentView::ProviderDisabled => return provider_disabled(),
        DocumentView::Unavailable => return malformed("apply: dataplane unavailable"),
    };
    if !document.canonical {
        return malformed("apply: authority body is not canonical; run cermet check --fix first");
    }
    let baseline = match client.authority_status() {
        Ok(status) => status,
        Err(_) => return apply_failure(client, start, "apply: dataplane unavailable", 2),
    };
    let candidate_digest = document.prepared.canonical_digest.clone();
    let candidate_display = display_digest(&candidate_digest);
    let marker = document.marker.as_str();

    if candidate_is_live(&baseline.sentence, &document.prepared) {
        if marker == candidate_display {
            return apply_no_change(client, start, &baseline, &candidate_display);
        }
        return repair_apply_marker(client, start, &store, &document, &baseline);
    }

    match &baseline.sentence {
        SentenceSnapshot::Absent if document.source_is_empty && document.marker.is_none() => {
            return apply_no_change(client, start, &baseline, "none");
        }
        SentenceSnapshot::Unserved { .. } | SentenceSnapshot::Corrupt { .. } if !recover => {
            return apply_failure(
                client,
                start,
                "apply: recovery would replace an unserved or corrupt record; rerun with --recover",
                1,
            );
        }
        SentenceSnapshot::Served {
            authority_digest, ..
        } if marker != display_digest(authority_digest) && !replace_live => {
            return apply_failure(
                client,
                start,
                "apply: the marker does not name the served baseline; rerun with --replace-live",
                1,
            );
        }
        SentenceSnapshot::Absent if marker != "none" && !replace_live => {
            return apply_failure(
                client,
                start,
                "apply: the marker does not name the absent baseline; rerun with --replace-live",
                1,
            );
        }
        _ => {}
    }

    let prior_prepared = match &baseline.sentence {
        SentenceSnapshot::Served {
            rules_text,
            authority_digest,
            ..
        } => match validate_served(client, rules_text, authority_digest) {
            Ok(prepared) => prepared,
            Err(PreparationFailure::Invalid(_)) => {
                return apply_failure(client, start, "apply: served baseline is not preparable", 2);
            }
            Err(PreparationFailure::ProviderDisabled) => return provider_disabled(),
            Err(PreparationFailure::Unavailable) => {
                return apply_failure(client, start, "apply: dataplane unavailable", 2);
            }
        },
        SentenceSnapshot::Absent
        | SentenceSnapshot::Unserved { .. }
        | SentenceSnapshot::Corrupt { .. } => empty_prepared(),
    };

    let staged = match client.stage(document.prepared.canonical_text.clone()) {
        Ok(staged) => staged,
        Err(PreparationFailure::Invalid(reason)) => {
            return apply_failure(
                client,
                start,
                &format!("apply: staging rejected the candidate — {reason}"),
                2,
            );
        }
        Err(PreparationFailure::ProviderDisabled) => return provider_disabled(),
        Err(PreparationFailure::Unavailable) => {
            return apply_failure(client, start, "apply: staging unavailable", 2);
        }
    };
    // No client-side re-verification of the daemon's staging echo: the daemon canonicalizes and
    // the daemon commits, so recomputing its canonical digest or re-deriving its `occurrence_id`
    // from its own `staging_token` would only check the daemon's arithmetic against itself.
    if let Err(reason) = apply_precommit_recheck(client, start, &store, &document, &baseline) {
        return apply_failure(client, start, reason, 2);
    }

    let old_display = baseline_identity(&baseline.sentence);
    let warning = match &baseline.sentence {
        SentenceSnapshot::Unserved { .. } | SentenceSnapshot::Corrupt { .. } => {
            "WARNING: --recover will replace an unserved/corrupt daemon record.\n"
        }
        SentenceSnapshot::Served {
            authority_digest, ..
        } if marker != display_digest(authority_digest) => {
            "WARNING: --replace-live will replace a live generation not named by the marker.\n"
        }
        SentenceSnapshot::Absent if marker != "none" => {
            "WARNING: --replace-live acknowledges a marker that does not name the absent baseline.\n"
        }
        _ => "",
    };
    let (git_branch, git_head) = git_context(store.root_path());
    let rule_diff = transition_rule_diff(
        &prior_prepared.canonical_text,
        &document.prepared.canonical_text,
    );
    let set_diff = render_set_diff(&prior_prepared, &document.prepared);
    let review = format!(
        "Apply this exact CERMET.md authority corpus?\n{warning}repository: {}\ngit_branch: {git_branch}\ngit_head: {git_head}\nold_live: {old_display}\nnew_live: {candidate_display}\nrules: {}\n{rule_diff}{}",
        safe_one_line(&store.root_path().to_string_lossy()),
        document.prepared.rule_count,
        if set_diff.is_empty() {
            String::new()
        } else {
            format!("\n{set_diff}")
        }
    );
    if !terminal.is_interactive() || !terminal.confirm(&review, false) {
        return apply_failure(
            client,
            start,
            "apply: terminal confirmation declined; staged authority remains inert",
            1,
        );
    }
    if let Err(reason) = apply_precommit_recheck(client, start, &store, &document, &baseline) {
        return apply_failure(client, start, reason, 2);
    }

    let presence_reason = format!(
        "Apply Cermet authority {old_display} -> {candidate_display} ({} rule{})",
        document.prepared.rule_count,
        if document.prepared.rule_count == 1 {
            ""
        } else {
            "s"
        }
    );
    match presence.confirm(&presence_reason) {
        PresenceOutcome::Confirmed => {}
        PresenceOutcome::Denied => {
            return apply_failure(
                client,
                start,
                "apply: human presence declined; staged authority remains inert",
                1,
            );
        }
        PresenceOutcome::Unavailable(_) => {
            return apply_failure(
                client,
                start,
                "apply: human presence unavailable; staged authority remains inert",
                2,
            );
        }
    }
    if let Err(reason) = apply_precommit_recheck(client, start, &store, &document, &baseline) {
        return apply_failure(client, start, reason, 2);
    }

    let staged_occurrence = staged.occurrence_id;
    let staging_token = staged.staging_token;
    let attempt = client.commit(staging_token.clone());
    let terminal = reconcile_apply_commit(
        client,
        &staging_token,
        &document.prepared,
        &staged_occurrence,
        attempt,
    );
    let (resolution, occurrence_id) = match terminal {
        ApplyTerminalCommit::Refused => {
            return apply_post_commit_failure(
                client,
                start,
                "stale_stage_conflict",
                "apply: exact generation CAS refused; the concurrent winner remains live",
                None,
            );
        }
        ApplyTerminalCommit::Unknown { status } => {
            let message = format!(
                "apply: exact transaction remains outcome-unknown after bounded reconciliation\nstaging_token: {staging_token}\noccurrence_id: {staged_occurrence}\nWARNING: preserve this token/occurrence and do not repeat apply or its presence ceremony"
            );
            return apply_post_commit_failure(
                client,
                start,
                "commit_outcome_unknown",
                &message,
                status.as_ref(),
            );
        }
        ApplyTerminalCommit::Committed { resolution, status } => {
            let Some(status) = status else {
                return apply_post_commit_failure(
                    client,
                    start,
                    "committed_but_unreconciled",
                    "apply: authority commit was acknowledged but final live state is unavailable",
                    None,
                );
            };
            if !candidate_is_exact_occurrence(
                &status.sentence,
                &document.prepared,
                &staged_occurrence,
            ) {
                return apply_post_commit_failure(
                    client,
                    start,
                    "committed_but_superseded",
                    "apply: authority committed, then another generation won before marker update",
                    Some(&status),
                );
            }
            (resolution, staged_occurrence.clone())
        }
    };

    let parsed = ManagedDocument::parse(&document.read.bytes)
        .expect("prepared document remains valid in its held preimage");
    let candidate_marker = marker_from_hex(&candidate_digest)
        .expect("validated prepared candidate carries a lowercase digest");
    let rewritten = parsed
        .rewrite(
            &candidate_marker,
            document.prepared.canonical_text.as_bytes(),
        )
        .expect("canonical candidate can be rendered into its source document");
    let mut publication = store.replace(&document.read.preimage, &rewritten).ok();
    let marker_update = match publication.as_ref() {
        Some(report) if publication_is_clean(report, &rewritten) => "updated",
        Some(_) => "interfered",
        None => "preserved_concurrent_edit",
    };

    let final_document = prepare_document(client, &store);
    let final_status = client.authority_status().ok();
    if let Some(report) = publication.as_mut() {
        refresh_publication_final_state(&store, report, &rewritten);
    }
    let final_state = read_destination_state(&store);
    let final_observed = compose_final_state(&final_document, final_status.as_ref(), &final_state);
    let aligned = marker_update == "updated" && final_observed.drift == DriftState::Aligned;
    let result = if aligned {
        resolution
    } else {
        "committed_but_unreconciled"
    };
    let lockdown = final_status
        .as_ref()
        .map(|status| lockdown_name(status.lockdown))
        .unwrap_or("unknown");
    ReconciliationOutput {
        text: format!(
            "result: {result}\ncommit_resolution: {resolution}\nreceipt: sentence_authority_transition\nold_live: {old_display}\nnew_live: {candidate_display}\nrules: {}\noccurrence_id: {occurrence_id}\nacceptance_path: presence\nmarker_update: {marker_update}\nstate: {}\nlockdown: {lockdown}",
            document.prepared.rule_count,
            drift_name(&final_observed.drift),
        ),
        exit_code: if aligned { 0 } else { 2 },
    }
}

enum ApplyTerminalCommit {
    Refused,
    Committed {
        resolution: &'static str,
        status: Option<SentenceAuthorityStatus>,
    },
    Unknown {
        status: Option<SentenceAuthorityStatus>,
    },
}

fn reconcile_apply_commit(
    client: &dyn ApplyTransactionClient,
    staging_token: &str,
    candidate: &PreparedSentenceCorpus,
    occurrence_id: &str,
    first: ApplyCommitAttempt,
) -> ApplyTerminalCommit {
    if matches!(&first, ApplyCommitAttempt::Refused) {
        return ApplyTerminalCommit::Refused;
    }
    if let Some(resolution) = apply_ack_resolution(&first, candidate, occurrence_id) {
        return ApplyTerminalCommit::Committed {
            resolution,
            status: observe_apply_terminal_status(client, candidate, occurrence_id),
        };
    }

    for _ in 0..TERMINAL_RECONCILIATION_ROUNDS {
        let status = client.authority_status().ok();
        if status.as_ref().is_some_and(|status| {
            candidate_is_exact_occurrence(&status.sentence, candidate, occurrence_id)
        }) {
            return ApplyTerminalCommit::Committed {
                resolution: "committed_after_reconciliation",
                status,
            };
        }
        let attempt = client.commit(staging_token.to_string());
        if let Some(resolution) = apply_ack_resolution(&attempt, candidate, occurrence_id) {
            return ApplyTerminalCommit::Committed {
                resolution,
                status: observe_apply_terminal_status(client, candidate, occurrence_id),
            };
        }
    }

    let final_status = client.authority_status().ok();
    if final_status.as_ref().is_some_and(|status| {
        candidate_is_exact_occurrence(&status.sentence, candidate, occurrence_id)
    }) {
        ApplyTerminalCommit::Committed {
            resolution: "committed_after_reconciliation",
            status: final_status,
        }
    } else {
        ApplyTerminalCommit::Unknown {
            status: final_status,
        }
    }
}

fn apply_ack_resolution(
    attempt: &ApplyCommitAttempt,
    candidate: &PreparedSentenceCorpus,
    occurrence_id: &str,
) -> Option<&'static str> {
    match attempt {
        ApplyCommitAttempt::Acknowledged(outcome)
            if outcome.canonical_digest() == candidate.canonical_digest
                && outcome.occurrence_id() == occurrence_id =>
        {
            Some(match outcome {
                cermet_ipc::ctl::SentenceCommitOutcome::Committed { .. } => "committed",
                cermet_ipc::ctl::SentenceCommitOutcome::AlreadyCommitted { .. } => {
                    "already_committed"
                }
            })
        }
        _ => None,
    }
}

fn observe_apply_terminal_status(
    client: &dyn ReconciliationClient,
    candidate: &PreparedSentenceCorpus,
    occurrence_id: &str,
) -> Option<SentenceAuthorityStatus> {
    let mut final_status = client.authority_status().ok();
    for _ in 0..TERMINAL_RECONCILIATION_ROUNDS {
        if final_status.as_ref().is_some_and(|status| {
            candidate_is_exact_occurrence(&status.sentence, candidate, occurrence_id)
        }) {
            break;
        }
        final_status = client.authority_status().ok();
    }
    final_status
}

fn apply_precommit_recheck(
    client: &dyn ApplyTransactionClient,
    start: &Path,
    store: &DocumentStore,
    document: &PreparedDocument,
    baseline: &SentenceAuthorityStatus,
) -> Result<(), &'static str> {
    let rediscovered = DocumentStore::discover(start)
        .map_err(|_| "apply: physical repository root changed before commit; refusing")?;
    if rediscovered.root_identity() != store.root_identity()
        || rediscovered.root_path() != store.root_path()
    {
        return Err("apply: physical repository root changed before commit; refusing");
    }
    match store.read() {
        Ok(ReadOutcome::Present(current)) if current.exact_state_matches(&document.read) => {}
        _ => return Err("apply: CERMET.md changed before commit; refusing"),
    }
    let status = client
        .authority_status()
        .map_err(|_| "apply: live generation became unavailable before commit; refusing")?;
    if status.sentence != baseline.sentence {
        return Err("apply: live generation changed before commit; refusing");
    }
    Ok(())
}

fn apply_no_change(
    client: &dyn ReconciliationClient,
    start: &Path,
    baseline: &SentenceAuthorityStatus,
    digest: &str,
) -> ReconciliationOutput {
    let status = run_status(client, start, false);
    ReconciliationOutput {
        text: format!(
            "result: no_change\nlive: {digest}\npresence: not_required\nlockdown: {}\n{}",
            lockdown_name(baseline.lockdown),
            status.text
        ),
        exit_code: status.exit_code,
    }
}

fn repair_apply_marker(
    client: &dyn ReconciliationClient,
    start: &Path,
    store: &DocumentStore,
    document: &PreparedDocument,
    baseline: &SentenceAuthorityStatus,
) -> ReconciliationOutput {
    let parsed = match ManagedDocument::parse(&document.read.bytes) {
        Ok(parsed) => parsed,
        Err(_) => return malformed("apply: repository candidate became invalid"),
    };
    let marker = match marker_from_hex(&document.prepared.canonical_digest) {
        Some(marker) => marker,
        None => return malformed("apply: daemon candidate digest is malformed"),
    };
    let rewritten = match parsed.rewrite(&marker, document.prepared.canonical_text.as_bytes()) {
        Ok(rewritten) => rewritten,
        Err(_) => return malformed("apply: marker repair cannot be rendered"),
    };
    let report = match store.replace(&document.read.preimage, &rewritten) {
        Ok(report) => report,
        Err(_) => {
            return apply_failure(
                client,
                start,
                "apply: marker repair preserved a concurrent file edit",
                2,
            );
        }
    };
    let final_status = run_status(client, start, false);
    let clean = publication_is_clean(&report, &rewritten) && final_status.exit_code == 0;
    ReconciliationOutput {
        text: format!(
            "result: {}\npresence: not_required\nauthority_mutation: none\nlockdown: {}\n{}",
            if clean {
                "marker_repaired"
            } else {
                "marker_repair_unreconciled"
            },
            lockdown_name(baseline.lockdown),
            final_status.text,
        ),
        exit_code: if clean { 0 } else { 2 },
    }
}

fn apply_failure(
    client: &dyn ReconciliationClient,
    start: &Path,
    message: &str,
    exit_code: u8,
) -> ReconciliationOutput {
    let status = run_status(client, start, false);
    ReconciliationOutput {
        text: format!("{message}\n{}", status.text),
        exit_code,
    }
}

fn apply_post_commit_failure(
    client: &dyn ReconciliationClient,
    start: &Path,
    result: &str,
    message: &str,
    status: Option<&SentenceAuthorityStatus>,
) -> ReconciliationOutput {
    let document = observe_document(client, start);
    let final_state = current_destination_state(start);
    let observed = compose_final_state(&document, status, &final_state);
    let status = render_observed(&observed, false);
    ReconciliationOutput {
        text: format!(
            "result: {result}\nmarker_update: not_attempted\n{message}\n{}",
            status.text
        ),
        exit_code: 2,
    }
}

fn candidate_is_live(snapshot: &SentenceSnapshot, candidate: &PreparedSentenceCorpus) -> bool {
    matches!(
        snapshot,
        SentenceSnapshot::Served {
            rules_text,
            authority_digest,
            rule_count,
            ..
        } if rules_text == &candidate.canonical_text
            && authority_digest == &candidate.canonical_digest
            && *rule_count == candidate.rule_count
    )
}

fn candidate_is_exact_occurrence(
    snapshot: &SentenceSnapshot,
    candidate: &PreparedSentenceCorpus,
    occurrence_id: &str,
) -> bool {
    matches!(
        snapshot,
        SentenceSnapshot::Served {
            rules_text,
            authority_digest,
            occurrence_id: live_occurrence,
            rule_count,
            ..
        }
        | SentenceSnapshot::Unserved {
            rules_text,
            authority_digest,
            occurrence_id: live_occurrence,
            rule_count,
            ..
        } if rules_text == &candidate.canonical_text
            && authority_digest == &candidate.canonical_digest
            && live_occurrence == occurrence_id
            && *rule_count == candidate.rule_count
    )
}

fn baseline_identity(snapshot: &SentenceSnapshot) -> String {
    match snapshot {
        SentenceSnapshot::Absent => "none".into(),
        SentenceSnapshot::Served {
            authority_digest, ..
        } => display_digest(authority_digest),
        SentenceSnapshot::Unserved { record_digest, .. } => {
            format!("unserved-record:sha256:{record_digest}")
        }
        SentenceSnapshot::Corrupt { record_digest, .. } => {
            format!("corrupt-record:sha256:{record_digest}")
        }
    }
}

fn transition_rule_diff(old: &str, new: &str) -> String {
    if old == new {
        return "rules: unchanged".into();
    }
    let old: Vec<&str> = old.lines().collect();
    let new: Vec<&str> = new.lines().collect();
    let mut out = format!(
        "--- live\n+++ candidate\n@@ -1,{} +1,{} @@\n",
        old.len(),
        new.len()
    );
    for line in old {
        out.push('-');
        out.push_str(line);
        out.push('\n');
    }
    for line in new {
        out.push('+');
        out.push_str(line);
        out.push('\n');
    }
    out.trim_end().to_string()
}

fn git_context(root: &Path) -> (String, String) {
    let run = |arguments: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(arguments)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|value| safe_one_line(value.trim()))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown".into())
    };
    (
        run(&["symbolic-ref", "--short", "HEAD"]),
        run(&["rev-parse", "HEAD"]),
    )
}

fn safe_one_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .collect()
}

fn prepare_document(client: &dyn ReconciliationClient, store: &DocumentStore) -> DocumentView {
    let read = match store.read() {
        Ok(ReadOutcome::Missing) => return DocumentView::Missing,
        Ok(ReadOutcome::Present(read)) => read,
        Err(_) => return DocumentView::Invalid("CERMET.md is not safely readable".into()),
    };
    let parsed = match ManagedDocument::parse(&read.bytes) {
        Ok(parsed) => parsed,
        Err(error) => return DocumentView::Invalid(error.to_string()),
    };
    let marker = parsed.marker().clone();
    let source = parsed.body().to_string();
    let prepared = match prepare_bounded(client, source.clone()) {
        Ok(prepared) => prepared,
        Err(PreparationFailure::Invalid(reason)) => return DocumentView::Invalid(reason),
        Err(PreparationFailure::ProviderDisabled) => return DocumentView::ProviderDisabled,
        Err(PreparationFailure::Unavailable) => return DocumentView::Unavailable,
    };
    let read = match store.read() {
        Ok(ReadOutcome::Present(current)) if current.exact_state_matches(&read) => current,
        _ => return DocumentView::Invalid("CERMET.md changed while it was being prepared".into()),
    };
    DocumentView::Prepared(Box::new(PreparedDocument {
        canonical: source.as_bytes() == prepared.canonical_text.as_bytes(),
        source_is_empty: source.is_empty(),
        marker,
        prepared,
        read,
    }))
}

fn observe_document(client: &dyn ReconciliationClient, start: &Path) -> DocumentView {
    match DocumentStore::discover(start) {
        Ok(store) => prepare_document(client, &store),
        Err(_) => DocumentView::Invalid("repository unavailable".into()),
    }
}

fn prepare_bounded(
    client: &dyn ReconciliationClient,
    candidate_text: String,
) -> Result<PreparedSentenceCorpus, PreparationFailure> {
    let request = CtlRequest::PrepareSentences {
        candidate_text: candidate_text.clone(),
    };
    let size = serde_json::to_vec(&request)
        .map_err(|_| PreparationFailure::Invalid("candidate cannot be encoded".into()))?
        .len();
    if size > cermet_ipc::codec::MAX_FRAME as usize {
        return Err(PreparationFailure::Invalid(
            "candidate is larger than one ctl frame".into(),
        ));
    }
    let prepared = client.prepare(candidate_text)?;
    prepared_view_is_valid(&prepared)
        .then_some(prepared)
        .ok_or(PreparationFailure::Unavailable)
}

fn prepared_view_is_valid(prepared: &PreparedSentenceCorpus) -> bool {
    let Ok(analysis) = analyze_body(&prepared.canonical_text) else {
        return false;
    };
    if !analysis.is_canonical
        || analysis.rules.rules.len() != prepared.rule_count
        || analysis.digest.as_str() != display_digest(&prepared.canonical_digest)
    {
        return false;
    }

    let expected_sets = analysis
        .rules
        .rules
        .iter()
        .filter(|rule| matches!(rule.selector, cermet_lang::sentence::Selector::Set { .. }))
        .count();
    let mut seen = BTreeSet::new();
    expected_sets == prepared.set_snapshots.len()
        && prepared.set_snapshots.iter().all(|snapshot| {
            if !seen.insert(snapshot.rule_index) {
                return false;
            }
            let Some(rule) = analysis.rules.rules.get(snapshot.rule_index) else {
                return false;
            };
            let cermet_lang::sentence::Selector::Set {
                provider,
                set,
                digest: Some(digest),
            } = &rule.selector
            else {
                return false;
            };
            if provider != &snapshot.provider || set != &snapshot.set || digest != &snapshot.digest
            {
                return false;
            }
            cermet_lang::sets::SetSnapshot::new(
                &snapshot.provider,
                &snapshot.set,
                snapshot.members.clone(),
            )
            .is_some_and(|rebuilt| {
                rebuilt.digest() == snapshot.digest && rebuilt.members() == snapshot.members
            })
        })
}

fn validate_served(
    client: &dyn ReconciliationClient,
    rules_text: &str,
    authority_digest: &str,
) -> Result<PreparedSentenceCorpus, PreparationFailure> {
    let prepared = prepare_bounded(client, rules_text.to_string())?;
    if prepared.canonical_text != rules_text || prepared.canonical_digest != authority_digest {
        return Err(PreparationFailure::Invalid(
            "served snapshot does not match its digest".into(),
        ));
    }
    Ok(prepared)
}

fn repository_fields(
    document: &DocumentView,
) -> (
    RepositoryState,
    &'static str,
    Option<String>,
    Option<String>,
    Option<bool>,
) {
    match document {
        DocumentView::Missing => (RepositoryState::Missing, "missing", None, None, None),
        DocumentView::Invalid(_) => (RepositoryState::Invalid, "invalid", None, None, None),
        DocumentView::ProviderDisabled => (
            RepositoryState::Invalid,
            "provider_disabled",
            None,
            None,
            None,
        ),
        DocumentView::Unavailable => (RepositoryState::Unknown, "unavailable", None, None, None),
        DocumentView::Prepared(document) => {
            let candidate = digest_from_hex(&document.prepared.canonical_digest)
                .expect("daemon prepared a valid digest");
            let candidate_text = candidate.as_str().to_string();
            let marker = document.marker.as_str().to_string();
            (
                RepositoryState::Valid {
                    candidate,
                    source_is_empty: document.source_is_empty,
                    marker: document.marker.clone(),
                },
                "valid",
                Some(candidate_text),
                Some(marker),
                Some(document.canonical),
            )
        }
    }
}

fn data_plane_fields(
    snapshot: &SentenceSnapshot,
) -> (DataPlaneState, &'static str, Option<String>) {
    match snapshot {
        SentenceSnapshot::Absent => (DataPlaneState::Absent, "absent", Some("none".into())),
        SentenceSnapshot::Served {
            authority_digest, ..
        } => match digest_from_hex(authority_digest) {
            Some(digest) => {
                let display = digest.as_str().to_string();
                (DataPlaneState::Served(digest), "served", Some(display))
            }
            None => (DataPlaneState::Corrupt, "corrupt", None),
        },
        SentenceSnapshot::Unserved { .. } => (DataPlaneState::Unserved, "unserved", None),
        SentenceSnapshot::Corrupt { .. } => (DataPlaneState::Corrupt, "corrupt", None),
    }
}

fn compose_state(
    document: &DocumentView,
    authority: Option<&SentenceAuthorityStatus>,
) -> ObservedState {
    let (repository, document_name, candidate, marker, canonical) = repository_fields(document);
    let (live, live_state, live_display, lockdown) = match authority {
        Some(authority) => {
            let (live, live_state, live_display) = data_plane_fields(&authority.sentence);
            (
                live,
                live_state,
                live_display,
                lockdown_name(authority.lockdown),
            )
        }
        None => (DataPlaneState::Unknown, "unknown", None, "unknown"),
    };
    ObservedState {
        drift: classify_drift(&repository, &live),
        document: document_name,
        candidate,
        marker,
        live: live_display,
        live_state,
        canonical,
        lockdown,
    }
}

fn compose_final_state(
    document: &DocumentView,
    status: Option<&SentenceAuthorityStatus>,
    final_state: &FinalDestinationState,
) -> ObservedState {
    if !document_matches_final_state(document, final_state) {
        return compose_state(
            &DocumentView::Invalid("document does not match the applied destination".into()),
            status,
        );
    }
    compose_state(document, status)
}

fn document_matches_final_state(
    document: &DocumentView,
    final_state: &FinalDestinationState,
) -> bool {
    match document {
        DocumentView::Prepared(prepared) => matches!(
            final_state,
            FinalDestinationState::Present(current)
                if current.exact_state_matches(&prepared.read)
        ),
        DocumentView::Missing => matches!(final_state, FinalDestinationState::Missing),
        DocumentView::Invalid(_) | DocumentView::ProviderDisabled | DocumentView::Unavailable => {
            true
        }
    }
}

fn render_observed(observed: &ObservedState, as_json: bool) -> ReconciliationOutput {
    render_status(
        observed.drift.clone(),
        observed.document,
        observed.candidate.as_deref(),
        observed.marker.as_deref(),
        observed.live.as_deref(),
        observed.live_state,
        observed.canonical,
        observed.lockdown,
        as_json,
    )
}

pub fn status_json_failure() -> ReconciliationOutput {
    render_status(
        DriftState::DataPlaneUnknown,
        "unknown",
        None,
        None,
        None,
        "unknown",
        None,
        "unknown",
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn render_status(
    drift: DriftState,
    document: &str,
    candidate: Option<&str>,
    marker: Option<&str>,
    live: Option<&str>,
    live_state: &str,
    canonical: Option<bool>,
    lockdown: &str,
    as_json: bool,
) -> ReconciliationOutput {
    let state = drift_name(&drift);
    let view = StatusView {
        state,
        document,
        candidate,
        marker,
        live,
        live_state,
        canonical,
        lockdown,
    };
    let text = if as_json {
        serde_json::to_string(&view).expect("status view serializes")
    } else {
        format!(
            "state: {state}\ndocument: {document}\ncandidate: {}\nmarker: {}\nlive: {}\nlive_state: {live_state}\ncanonical: {}\nlockdown: {lockdown}",
            candidate.unwrap_or("unknown"),
            marker.unwrap_or("unknown"),
            live.unwrap_or("unknown"),
            canonical.map(yes_no).unwrap_or("unknown"),
        )
    };
    ReconciliationOutput {
        text,
        exit_code: drift_exit(&drift),
    }
}

fn operation_failure(message: &str, observed: &ObservedState) -> ReconciliationOutput {
    let dimensions = render_observed(observed, false);
    ReconciliationOutput {
        text: format!("{message}\n{}", dimensions.text),
        exit_code: 2,
    }
}

fn provider_disabled() -> ReconciliationOutput {
    ReconciliationOutput {
        text: "provider_disabled".to_string(),
        exit_code: 1,
    }
}

fn live_changed(
    initial: &SentenceAuthorityStatus,
    final_status: Option<&SentenceAuthorityStatus>,
) -> &'static str {
    match final_status {
        Some(final_status) if final_status.sentence == initial.sentence => "no",
        Some(_) => "yes",
        None => "unknown",
    }
}

fn marker_from_hex(hex: &str) -> Option<AuthorityMarker> {
    digest_from_hex(hex).map(AuthorityMarker::from_digest)
}

fn digest_from_hex(hex: &str) -> Option<AuthorityDigest> {
    AuthorityDigest::from_hex(hex).ok()
}

fn display_digest(hex: &str) -> String {
    format!("sha256:{hex}")
}

fn lockdown_name(lockdown: LockdownSnapshot) -> &'static str {
    match lockdown {
        LockdownSnapshot::Clear => "clear",
        LockdownSnapshot::Engaged => "engaged",
    }
}

fn drift_name(state: &DriftState) -> &'static str {
    match state {
        DriftState::Aligned => "aligned",
        DriftState::AlignedNoAuthority => "aligned_no_authority",
        DriftState::UnappliedDocument => "unapplied_document",
        DriftState::UnexportedLive => "unexported_live",
        DriftState::MarkerStale => "marker_stale",
        DriftState::Diverged => "diverged",
        DriftState::RepoMissing => "repo_missing",
        DriftState::RepoInvalid => "repo_invalid",
        DriftState::DataPlaneUnserved => "dataplane_unserved",
        DriftState::DataPlaneCorrupt => "dataplane_corrupt",
        DriftState::DataPlaneUnknown => "dataplane_unknown",
    }
}

fn drift_exit(state: &DriftState) -> u8 {
    match state {
        DriftState::Aligned | DriftState::AlignedNoAuthority => 0,
        DriftState::UnappliedDocument
        | DriftState::UnexportedLive
        | DriftState::MarkerStale
        | DriftState::Diverged
        | DriftState::RepoMissing => 1,
        DriftState::RepoInvalid
        | DriftState::DataPlaneUnserved
        | DriftState::DataPlaneCorrupt
        | DriftState::DataPlaneUnknown => 2,
    }
}

fn publication_is_clean(report: &PublicationReport, intended: &[u8]) -> bool {
    matches!(
        report.outcome,
        PublicationOutcome::Created | PublicationOutcome::Replaced
    ) && matches!(report.durability, PublicationDurability::Durable)
        && matches!(report.destination_mode, DestinationModeStatus::Applied)
        && matches!(
            report.temp_cleanup,
            TempCleanupStatus::Complete | TempCleanupStatus::NotRequired
        )
        && !report.source_interference_detected
        && !report.pre_rename_edit_detected
        && !report.final_interference_detected
        && matches!(
            &report.final_state,
            FinalDestinationState::Present(read) if read.bytes == intended
        )
}

fn refresh_publication_final_state(
    store: &DocumentStore,
    report: &mut PublicationReport,
    intended: &[u8],
) {
    let final_state = read_destination_state(store);
    let unchanged = matches!(
        (&report.final_state, &final_state),
        (
            FinalDestinationState::Present(prior),
            FinalDestinationState::Present(current)
        ) if current.exact_state_matches(prior) && current.bytes == intended
    );
    if !unchanged {
        report.final_interference_detected = true;
    }
    report.final_state = final_state;
}

fn current_destination_state(start: &Path) -> FinalDestinationState {
    match DocumentStore::discover(start) {
        Ok(store) => read_destination_state(&store),
        Err(error) => FinalDestinationState::Unreadable(error.to_string()),
    }
}

fn read_destination_state(store: &DocumentStore) -> FinalDestinationState {
    match store.read() {
        Ok(ReadOutcome::Missing) => FinalDestinationState::Missing,
        Ok(ReadOutcome::Present(read)) => FinalDestinationState::Present(read),
        Err(error) => FinalDestinationState::Unreadable(error.to_string()),
    }
}

fn render_publication(report: &PublicationReport, intended: &[u8]) -> String {
    let write = match report.outcome {
        PublicationOutcome::Created => "created",
        PublicationOutcome::Replaced => "replaced",
        PublicationOutcome::Interfered(_) => "interfered",
    };
    let durability = match report.durability {
        PublicationDurability::Durable => "durable",
        PublicationDurability::Uncertain(_) => "uncertain",
        PublicationDurability::NotClaimedInterference => "not_claimed",
    };
    let final_file = match &report.final_state {
        FinalDestinationState::Present(read) if read.bytes == intended => "intended",
        FinalDestinationState::Present(_) => "changed",
        FinalDestinationState::Missing => "missing",
        FinalDestinationState::Unreadable(_) => "unreadable",
    };
    let mode = match report.destination_mode {
        DestinationModeStatus::Applied => "applied",
        DestinationModeStatus::Failed(_) => "failed",
        DestinationModeStatus::NotClaimedInterference => "not_claimed",
    };
    let interference = report.source_interference_detected
        || report.pre_rename_edit_detected
        || report.final_interference_detected;
    format!(
        "write: {write}\ndurability: {durability}\nmode: {mode}\ninterference: {}\nfinal_file: {final_file}",
        yes_no(interference)
    )
}

/// A minimal unified diff of two canonical rule corpora.
///
/// Orientation is the direction `doc apply` moves: `--- live` is the authority served right now,
/// `+++ document` is what you are proposing. Reading it the other way describes reverting your own
/// edit, which is never the question `doc diff` is asked.
///
/// A real diff matters here: dumping every old line as `-` followed by every new line as `+` turns
/// a one-sentence edit to a 23-rule corpus into 47 changed lines and buries the change. Corpora are
/// tens of lines, so the classic O(n·m) LCS table is the right amount of machinery — exact, small,
/// and no new dependency.
fn unified_rule_diff(document: &str, live: &str) -> String {
    /// One line of surrounding context. A rule corpus is a set of independent sentences, not prose:
    /// the neighbours orient you in the list, and more of them just re-prints the corpus.
    const CONTEXT: usize = 1;

    if document == live {
        return "rules: unchanged".into();
    }
    let old: Vec<&str> = live.lines().collect();
    let new: Vec<&str> = document.lines().collect();

    // lcs[i][j] = length of the longest common subsequence of old[i..] and new[j..].
    let mut lcs = vec![vec![0usize; new.len() + 1]; old.len() + 1];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            lcs[i][j] = if old[i] == new[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    #[derive(PartialEq, Clone, Copy)]
    enum Op {
        Context,
        Del,
        Ins,
    }
    // Each entry carries its 1-based position on BOTH sides, so a hunk header can be read straight
    // off the ops it contains — including an insert-only hunk, which has no old-side line of its own.
    let mut script: Vec<(Op, usize, usize, &str)> = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < old.len() && j < new.len() {
        if old[i] == new[j] {
            script.push((Op::Context, i + 1, j + 1, old[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            // Prefer the deletion on a tie so a replaced line reads `-old` then `+new`.
            script.push((Op::Del, i + 1, j + 1, old[i]));
            i += 1;
        } else {
            script.push((Op::Ins, i + 1, j + 1, new[j]));
            j += 1;
        }
    }
    while i < old.len() {
        script.push((Op::Del, i + 1, j + 1, old[i]));
        i += 1;
    }
    while j < new.len() {
        script.push((Op::Ins, i + 1, j + 1, new[j]));
        j += 1;
    }

    // Group the changes into hunks: every changed op, widened by CONTEXT, with overlaps merged.
    let mut hunks: Vec<(usize, usize)> = Vec::new();
    for (idx, (op, ..)) in script.iter().enumerate() {
        if *op == Op::Context {
            continue;
        }
        let start = idx.saturating_sub(CONTEXT);
        let end = (idx + CONTEXT + 1).min(script.len());
        match hunks.last_mut() {
            Some((_, prev_end)) if *prev_end >= start => *prev_end = end.max(*prev_end),
            _ => hunks.push((start, end)),
        }
    }

    let mut out = String::from("--- live\n+++ document\n");
    for (start, end) in hunks {
        let span = &script[start..end];
        let counts = |sides: [Op; 2]| span.iter().filter(|(op, ..)| sides.contains(op)).count();
        let old_count = counts([Op::Context, Op::Del]);
        let new_count = counts([Op::Context, Op::Ins]);
        // With no line of its own on a side, a hunk anchors at the line it follows — `-0,0` for an
        // insertion before the first rule, which is what unified diff means.
        let anchor =
            |count: usize, pick: fn(&(Op, usize, usize, &str)) -> usize, sides: [Op; 2]| {
                if count == 0 {
                    pick(&span[0]).saturating_sub(1)
                } else {
                    span.iter()
                        .find(|entry| sides.contains(&entry.0))
                        .map(pick)
                        .unwrap_or(0)
                }
            };
        let old_start = anchor(old_count, |e| e.1, [Op::Context, Op::Del]);
        let new_start = anchor(new_count, |e| e.2, [Op::Context, Op::Ins]);
        out.push_str(&format!(
            "@@ -{old_start},{old_count} +{new_start},{new_count} @@\n"
        ));
        for (op, _, _, text) in span {
            out.push(match op {
                Op::Context => ' ',
                Op::Del => '-',
                Op::Ins => '+',
            });
            out.push_str(text);
            out.push('\n');
        }
    }
    out.trim_end().to_string()
}

fn render_set_diff(document: &PreparedSentenceCorpus, live: &PreparedSentenceCorpus) -> String {
    let document = set_members(document);
    let live = set_members(live);
    let keys: BTreeSet<_> = document.keys().chain(live.keys()).cloned().collect();
    let mut lines = Vec::new();
    for key in keys {
        let empty = BTreeSet::new();
        let old = document.get(&key).map(|set| &set.members).unwrap_or(&empty);
        let new = live.get(&key).map(|set| &set.members).unwrap_or(&empty);
        let removed: Vec<_> = old.difference(new).collect();
        let added: Vec<_> = new.difference(old).collect();
        if removed.is_empty() && added.is_empty() {
            continue;
        }
        let set = document
            .get(&key)
            .or_else(|| live.get(&key))
            .expect("a union key exists on one side");
        lines.push(format!(
            "set {}.{} (occurrence {}):",
            set.provider, set.set, key.1
        ));
        lines.extend(removed.into_iter().map(|member| format!("- {member}")));
        lines.extend(added.into_iter().map(|member| format!("+ {member}")));
    }
    lines.join("\n")
}

struct SetMembers {
    provider: String,
    set: String,
    members: BTreeSet<String>,
}

fn set_members(corpus: &PreparedSentenceCorpus) -> BTreeMap<(String, usize), SetMembers> {
    let Ok(rules) = cermet_lang::sentence::parse_rules(&corpus.canonical_text) else {
        return BTreeMap::new();
    };
    let mut snapshots: Vec<_> = corpus.set_snapshots.iter().collect();
    snapshots.sort_by_key(|snapshot| snapshot.rule_index);
    let mut occurrence_by_identity = BTreeMap::<String, usize>::new();
    let mut result = BTreeMap::new();
    for snapshot in snapshots {
        let Some(mut rule) = rules.rules.get(snapshot.rule_index).cloned() else {
            continue;
        };
        let Selector::Set { digest, .. } = &mut rule.selector else {
            continue;
        };
        *digest = None;
        let identity = print_rule(&rule);
        let occurrence = occurrence_by_identity.entry(identity.clone()).or_default();
        *occurrence += 1;
        result.insert(
            (identity, *occurrence),
            SetMembers {
                provider: snapshot.provider.clone(),
                set: snapshot.set.clone(),
                members: snapshot.members.iter().cloned().collect(),
            },
        );
    }
    result
}

fn empty_prepared() -> PreparedSentenceCorpus {
    PreparedSentenceCorpus {
        canonical_text: String::new(),
        canonical_digest: cermet_lang::sentence::authority_digest_for(
            cermet_lang::sentence::RULE_SET_VERSION,
            b"",
        ),
        rule_count: 0,
        set_snapshots: Vec::new(),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn malformed(message: &str) -> ReconciliationOutput {
    ReconciliationOutput {
        text: message.to_string(),
        exit_code: 2,
    }
}

#[cfg(test)]
mod tests;
