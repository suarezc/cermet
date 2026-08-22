//! The ONE daemon-native sentence custody — the `cermet rules allow`/`revoke`/
//! `refresh`/`rules` ceremony on EVERY OS, driven over `ctl.sock` against the daemon-owned atomic
//! authority record.
//!
//! Authoring is the two-round STAGED ceremony: author text → `StageSentences`
//! (the daemon canonicalizes + validates and returns its canonical echo + a token) → the human
//! confirms THAT canonical echo via the platform presence adapter (PAM on Linux, Touch ID / device-
//! owner auth on macOS — presence decides nothing but presence) → `CommitSentences(token)` flips the
//! generation atomically. Staging installs no authority; a declined presence simply never commits,
//! and the inert staged record is TTL-swept.
//!
//! Confirmation binding: the human confirms the DAEMON's canonical bytes (the echo), so a
//! daemon that canonicalized differently could never be confirmed into authority — the presence
//! ceremony covers exactly the bytes the token commits.
//!
//! Threat-model note: the presence ceremony is operator-path integrity, NOT proof of
//! presence to the daemon and NOT a same-uid boundary — any process already at the approver uid can
//! speak ctl directly. The cross-uid daemon/agent separation is what stops a distinct-uid agent.
//!
//! The orchestration/trait here is platform-generic (fully tested on Linux with a mock client +
//! `FixedPresence`). Only the production wiring (`CtlStagedClient`, the real ctl client, and the
//! platform presence) selects a backend.

use std::path::PathBuf;
use std::sync::Arc;

use cermet_ctl_client::presence::{Presence, PresenceOutcome};
use cermet_lang::sentence::RuleSet;

use crate::sentence_custody::{
    encode_rules, AuthenticatedRuleCorpus, CorpusDocumentObservation, CorpusDocumentSync,
    CorpusDocumentSyncObserver, CorpusMutationReceipt, CorpusMutationReceiptState, CustodyError,
    Result, RuleCorpusExpectation, RuleCorpusSnapshot, SentenceCustody,
};

const TERMINAL_RECONCILIATION_ROUNDS: usize = 3;

/// A read-only view of the daemon-owned record. `Corrupt` NEVER carries raw rule bytes.
#[derive(Debug, Clone)]
pub enum RecordSnapshot {
    Absent,
    Valid { rules: RuleSet },
    Unserved,
    Corrupt { reason: String },
}

/// The daemon's canonical echo from round one (`stage`).
#[derive(Debug, Clone)]
pub struct StagedEcho {
    pub canonical_text: String,
    pub canonical_digest: String,
    pub staging_token: String,
    pub occurrence_id: String,
}

/// The already-classified outcome of a `commit` call.
#[derive(Debug, Clone)]
pub enum CommitResult {
    /// The daemon flipped the generation (or it already equalled the staged corpus — idempotent).
    Committed {
        canonical_digest: String,
        occurrence_id: String,
    },
    /// A definite no-commit: a stale/unknown/superseded token (the live authority moved).
    Denied(String),
    /// The response was lost in transit; the commit MAY have taken effect. The caller retains this
    /// exact token and may retry only `CommitSentences`, without repeating presence or mutation.
    Transport,
}

/// The narrow ctl surface the staged ceremony needs. Injected so the orchestration is unit-testable
/// without a live daemon.
pub trait StagedSentenceClient: Send + Sync {
    fn snapshot(&self) -> Result<RecordSnapshot>;
    fn authority_status(&self) -> Result<cermet_ipc::ctl::SentenceAuthorityStatus>;
    /// Round one: stage a candidate corpus; the daemon canonicalizes + validates and returns its echo.
    fn stage(&self, candidate_text: String) -> Result<StagedEcho>;
    /// Round two: commit a staged token.
    fn commit(&self, staging_token: String) -> CommitResult;
}

/// The ONE daemon-native sentence custody. Sentence-only in behavior: the credential methods fail
/// closed (connect rides ctl `Connect`; name→id resolution is unavailable in the daemon design).
pub struct StagedSentenceCustody {
    client: Box<dyn StagedSentenceClient>,
    presence: Arc<dyn Presence>,
    document_sync: Option<Arc<dyn CorpusDocumentSyncObserver>>,
}

impl StagedSentenceCustody {
    pub fn new(client: Box<dyn StagedSentenceClient>, presence: Arc<dyn Presence>) -> Self {
        Self {
            client,
            presence,
            document_sync: None,
        }
    }

    pub fn with_document_sync(mut self, observer: Arc<dyn CorpusDocumentSyncObserver>) -> Self {
        self.document_sync = Some(observer);
        self
    }
}

impl SentenceCustody for StagedSentenceCustody {
    fn read_rules(&self) -> Result<RuleSet> {
        match self.client.snapshot()? {
            RecordSnapshot::Absent => Ok(RuleSet {
                version: 1,
                rules: Vec::new(),
            }),
            RecordSnapshot::Valid { rules } => Ok(rules),
            RecordSnapshot::Unserved => Err(CustodyError::RulesUnserved),
            RecordSnapshot::Corrupt { .. } => Err(CustodyError::RulesPinMismatch),
        }
    }

    fn read_authenticated_rules(&self) -> Result<AuthenticatedRuleCorpus> {
        match self.client.snapshot()? {
            RecordSnapshot::Absent => Ok(AuthenticatedRuleCorpus {
                rules: RuleSet {
                    version: 1,
                    rules: Vec::new(),
                },
                source: Vec::new(),
            }),
            RecordSnapshot::Valid { rules } => {
                let source = encode_rules(&rules)?;
                Ok(AuthenticatedRuleCorpus { rules, source })
            }
            RecordSnapshot::Unserved => Err(CustodyError::RulesUnserved),
            RecordSnapshot::Corrupt { .. } => Err(CustodyError::RulesPinMismatch),
        }
    }

    fn read_rule_corpus_for_update(&self) -> Result<RuleCorpusSnapshot> {
        match self.client.snapshot()? {
            RecordSnapshot::Absent => {
                Ok(RuleCorpusSnapshot::Authenticated(AuthenticatedRuleCorpus {
                    rules: RuleSet {
                        version: 1,
                        rules: Vec::new(),
                    },
                    source: Vec::new(),
                }))
            }
            RecordSnapshot::Valid { rules } => {
                let source = encode_rules(&rules)?;
                Ok(RuleCorpusSnapshot::Authenticated(AuthenticatedRuleCorpus {
                    rules,
                    source,
                }))
            }
            RecordSnapshot::Unserved => Err(CustodyError::RulesUnserved),
            // A corrupt record is recoverable by presence-gated re-author, but NEVER by parsing its
            // bytes into authority: expose an EMPTY untrusted source so the re-author discards all old
            // rules.
            RecordSnapshot::Corrupt { .. } => {
                Ok(RuleCorpusSnapshot::PinMismatch { source: Vec::new() })
            }
        }
    }

    fn compare_and_swap_rules_with_presence(
        &self,
        expected: RuleCorpusExpectation<'_>,
        rules: &RuleSet,
        summary: &str,
    ) -> Result<CorpusMutationReceipt> {
        // Encode + validate client-side FIRST so a bad ruleset never even reaches the daemon.
        let new_bytes = encode_rules(rules)?;
        let new_text = String::from_utf8(new_bytes)
            .map_err(|_| CustodyError::Storage("canonical rules are not valid UTF-8".into()))?;
        let expected_digest = cermet_lang::sentence::authority_digest_for(
            cermet_lang::sentence::RULE_SET_VERSION,
            new_text.as_bytes(),
        );

        // Round one: stage. The daemon canonicalizes + validates and echoes its canonical bytes + a
        // token. NOTHING is authoritative yet; the prior generation stays live.
        let echo = self.client.stage(new_text.clone())?;

        // Confirmation binding is the reason this echo exists: the presence prompt below names
        // `echo.canonical_text`, so the human confirms the DAEMON's canonical bytes — the exact
        // bytes that go live. The client does NOT re-derive those bytes' digest or the daemon's
        // `occurrence_id` from its own `staging_token`: that would only compare the daemon's answer
        // against a local recomputation of the daemon's own arithmetic.

        // Original-state CAS: stage binds commit to the generation live at staging, but
        // allow/revoke must also prove that generation is the authenticated record their initial
        // read observed. Re-read only AFTER staging: a pre-stage change is detected here, while any
        // later change is rejected by the daemon's staged-against CAS at commit.
        match (expected, self.client.snapshot()?) {
            (RuleCorpusExpectation::Authenticated([]), RecordSnapshot::Absent) => {}
            (RuleCorpusExpectation::Authenticated(source), RecordSnapshot::Valid { rules })
                if encode_rules(&rules)?.as_slice() == source => {}
            (RuleCorpusExpectation::Authenticated(_), RecordSnapshot::Corrupt { .. }) => {
                return Err(CustodyError::RulesPinMismatch);
            }
            (_, RecordSnapshot::Unserved) => return Err(CustodyError::RulesUnserved),
            (RuleCorpusExpectation::PinMismatch(_), RecordSnapshot::Corrupt { .. }) => {}
            _ => return Err(CustodyError::RulesChanged),
        }
        let reason = format!("{summary}\n{}", echo.canonical_text);

        // A non-TTY / declined / unavailable presence commits NOTHING — the inert staged record is
        // TTL-swept.
        require_presence(self.presence.as_ref(), &reason)?;

        // Any ambiguous response enters a bounded terminal loop that queries/retries only this exact
        // nonce. Presence and mutation calculation are never repeated. Baseline/other status is not
        // proof of non-commit because the original timed-out handler may still be running.
        let staging_token = echo.staging_token;
        let expected_occurrence = echo.occurrence_id;
        let first = self.client.commit(staging_token.clone());
        if matches!(&first, CommitResult::Denied(_)) {
            return Err(CustodyError::RulesChanged);
        }
        let (mut known, mut final_status) = reconcile_incremental_commit(
            self.client.as_ref(),
            &staging_token,
            &new_text,
            &expected_digest,
            &expected_occurrence,
            rules.rules.len(),
            first,
        );
        let document_observation = self
            .document_sync
            .as_ref()
            .map(|observer| observer.observe(final_status.as_ref()))
            .unwrap_or(CorpusDocumentObservation {
                sync: CorpusDocumentSync::Unavailable("document state not observed"),
                status: final_status.clone(),
            });
        final_status = document_observation.status;
        known |= final_status.as_ref().is_some_and(|status| {
            status_is_exact_generation(
                status,
                &new_text,
                &expected_digest,
                &expected_occurrence,
                rules.rules.len(),
            )
        });
        let live_is_exact = final_status.as_ref().is_some_and(|status| {
            status_is_exact_commit(
                status,
                &new_text,
                &expected_digest,
                &expected_occurrence,
                rules.rules.len(),
            )
        });
        Ok(CorpusMutationReceipt {
            authority_digest: expected_digest,
            occurrence_id: expected_occurrence,
            staging_token,
            state: if known {
                CorpusMutationReceiptState::Known
            } else {
                CorpusMutationReceiptState::Unknown
            },
            acceptance_path: "presence",
            lockdown: final_status.as_ref().map(|status| status.lockdown),
            live_is_exact,
            document_sync: document_observation.sync,
        })
    }
}

fn require_presence(presence: &dyn Presence, reason: &str) -> Result<()> {
    match presence.confirm(reason) {
        PresenceOutcome::Confirmed => Ok(()),
        PresenceOutcome::Denied => Err(CustodyError::PresenceDenied),
        PresenceOutcome::Unavailable(message) => Err(CustodyError::PresenceUnavailable(message)),
    }
}

fn reconcile_incremental_commit(
    client: &dyn StagedSentenceClient,
    staging_token: &str,
    canonical_text: &str,
    canonical_digest: &str,
    occurrence_id: &str,
    rule_count: usize,
    first: CommitResult,
) -> (bool, Option<cermet_ipc::ctl::SentenceAuthorityStatus>) {
    if commit_matches(&first, canonical_digest, occurrence_id) {
        return (true, client.authority_status().ok());
    }

    for _ in 0..TERMINAL_RECONCILIATION_ROUNDS {
        let status = client.authority_status().ok();
        if status.as_ref().is_some_and(|status| {
            status_is_exact_generation(
                status,
                canonical_text,
                canonical_digest,
                occurrence_id,
                rule_count,
            )
        }) {
            return (true, status);
        }
        let attempt = client.commit(staging_token.to_string());
        if commit_matches(&attempt, canonical_digest, occurrence_id) {
            return (true, client.authority_status().ok());
        }
    }

    let final_status = client.authority_status().ok();
    let known = final_status.as_ref().is_some_and(|status| {
        status_is_exact_generation(
            status,
            canonical_text,
            canonical_digest,
            occurrence_id,
            rule_count,
        )
    });
    (known, final_status)
}

fn commit_matches(attempt: &CommitResult, canonical_digest: &str, occurrence_id: &str) -> bool {
    matches!(
        attempt,
        CommitResult::Committed {
            canonical_digest: committed_digest,
            occurrence_id: committed_occurrence,
        } if committed_digest == canonical_digest && committed_occurrence == occurrence_id
    )
}

fn status_is_exact_commit(
    status: &cermet_ipc::ctl::SentenceAuthorityStatus,
    canonical_text: &str,
    canonical_digest: &str,
    occurrence_id: &str,
    rule_count: usize,
) -> bool {
    matches!(
        &status.sentence,
        cermet_ipc::ctl::SentenceSnapshot::Served {
            rules_text,
            authority_digest,
            occurrence_id: live_occurrence,
            rule_count: live_rule_count,
            ..
        } if rules_text == canonical_text
            && authority_digest == canonical_digest
            && live_occurrence == occurrence_id
            && *live_rule_count == rule_count
    )
}

fn status_is_exact_generation(
    status: &cermet_ipc::ctl::SentenceAuthorityStatus,
    canonical_text: &str,
    canonical_digest: &str,
    occurrence_id: &str,
    rule_count: usize,
) -> bool {
    matches!(
        &status.sentence,
        cermet_ipc::ctl::SentenceSnapshot::Served {
            rules_text,
            authority_digest,
            occurrence_id: live_occurrence,
            rule_count: live_rule_count,
            ..
        }
        | cermet_ipc::ctl::SentenceSnapshot::Unserved {
            rules_text,
            authority_digest,
            occurrence_id: live_occurrence,
            rule_count: live_rule_count,
            ..
        } if rules_text == canonical_text
            && authority_digest == canonical_digest
            && live_occurrence == occurrence_id
            && *live_rule_count == rule_count
    )
}

// ---- production wiring: the real ctl-backed staged client -----------------------------------------

/// The real ctl-backed staged client: a keyless `CtlBrokerClient` + a dedicated current-thread runtime
/// (these sync custody methods own their runtime rather than borrowing the outer dispatch runtime).
pub struct CtlStagedClient {
    client: cermet_ctl_client::broker_client::CtlBrokerClient,
    rt: tokio::runtime::Runtime,
}

pub struct CtlDocumentSyncObserver {
    client: crate::reconciliation::CtlReconciliationClient,
    start: PathBuf,
}

impl CtlDocumentSyncObserver {
    pub fn new(
        client: cermet_ctl_client::broker_client::CtlBrokerClient,
        start: PathBuf,
    ) -> Result<Self> {
        let client = crate::reconciliation::CtlReconciliationClient::new(client)
            .map_err(CustodyError::Storage)?;
        Ok(Self { client, start })
    }
}

impl CorpusDocumentSyncObserver for CtlDocumentSyncObserver {
    fn observe(
        &self,
        status: Option<&cermet_ipc::ctl::SentenceAuthorityStatus>,
    ) -> CorpusDocumentObservation {
        crate::reconciliation::observe_mutation_document(&self.client, &self.start, status)
    }
}

impl CtlStagedClient {
    pub fn new(client: cermet_ctl_client::broker_client::CtlBrokerClient) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| CustodyError::Storage(format!("cannot start the ctl runtime: {e}")))?;
        Ok(Self { client, rt })
    }
}

impl StagedSentenceClient for CtlStagedClient {
    fn snapshot(&self) -> Result<RecordSnapshot> {
        let snapshot = self
            .rt
            .block_on(self.client.sentence_snapshot())
            .map_err(|e| CustodyError::Storage(e.to_string()))?;
        parse_snapshot(snapshot)
    }

    fn authority_status(&self) -> Result<cermet_ipc::ctl::SentenceAuthorityStatus> {
        self.rt
            .block_on(self.client.sentence_authority_status())
            .map_err(|error| CustodyError::Storage(error.to_string()))
    }

    fn stage(&self, candidate_text: String) -> Result<StagedEcho> {
        let staged = self
            .rt
            .block_on(self.client.stage_sentences(candidate_text))
            .map_err(classify_stage_error)?;
        Ok(StagedEcho {
            canonical_text: staged.canonical_text,
            canonical_digest: staged.canonical_digest,
            staging_token: staged.staging_token,
            occurrence_id: staged.occurrence_id,
        })
    }

    fn commit(&self, staging_token: String) -> CommitResult {
        match self
            .rt
            // The incremental rule ceremony installs a corpus, never a stored profile: a profile
            // is authored as a whole document, and there is no rule-at-a-time form of one.
            .block_on(self.client.commit_sentences(staging_token, None))
        {
            Ok(outcome) => CommitResult::Committed {
                canonical_digest: outcome.canonical_digest().to_string(),
                occurrence_id: outcome.occurrence_id().to_string(),
            },
            Err(cermet_lang::Error::Denied(m)) | Err(cermet_lang::Error::Invalid(m)) => {
                CommitResult::Denied(m)
            }
            Err(_) => CommitResult::Transport,
        }
    }
}

fn classify_stage_error(error: cermet_lang::Error) -> CustodyError {
    match error {
        cermet_lang::Error::Invalid(message) | cermet_lang::Error::Denied(message) => {
            CustodyError::InvalidRules(message)
        }
        cermet_lang::Error::ProviderDisabled => CustodyError::ProviderDisabled,
        other => CustodyError::Storage(other.to_string()),
    }
}

/// Parse a `SentenceSnapshot` ctl view into a [`RecordSnapshot`]. Corrupt bytes are never parsed into
/// authority — only the daemon's content-free reason is carried.
fn parse_snapshot(snapshot: cermet_ipc::ctl::SentenceSnapshot) -> Result<RecordSnapshot> {
    use cermet_ipc::ctl::SentenceSnapshot;

    Ok(match snapshot {
        SentenceSnapshot::Absent => RecordSnapshot::Absent,
        SentenceSnapshot::Served { rules_text, .. } => {
            let rules = cermet_lang::sentence::parse_rules(&rules_text)
                .map_err(|e| CustodyError::InvalidRules(e.to_string()))?;
            RecordSnapshot::Valid { rules }
        }
        SentenceSnapshot::Unserved { .. } => RecordSnapshot::Unserved,
        SentenceSnapshot::Corrupt { reason, .. } => RecordSnapshot::Corrupt { reason },
    })
}

#[cfg(test)]
mod tests;
