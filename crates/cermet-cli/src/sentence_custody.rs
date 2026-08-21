//! The sentence-only CLI custody seam.
//!
//! One narrow trait, [`SentenceCustody`], reads the current sentence authority and presence-gates a
//! whole-corpus compare-and-swap. It carries NO secret method by construction, so the ONE daemon-native
//! ctl custody ([`crate::sentence_ctl::StagedSentenceCustody`] — the staged `Stage → confirm →
//! Commit` ceremony on every OS) implements exactly this and never touches a credential API.
//! `run_rules`/`run_revoke`/`run_refresh`/`run_allow` all operate through this seam.
//!
//! It carries no credential API at all. The `Custody` extension trait that once sat on top of it —
//! the authoring-time name→id resolution seam, `get_secret`/`set_secret_with_presence` — is gone
//! with the seam it served: a quoted string is a LITERAL since the dialect ruling, so nothing asks
//! a provider to resolve one. Both methods were already fail-closed stubs in the daemon-only design
//! (the login-Keychain backend behind them died with the daemonless runtime in M4), so what is
//! deleted here is a trait with no caller.

use cermet_lang::sentence::{print_rule, RuleSet};

pub type Result<T> = std::result::Result<T, CustodyError>;

#[derive(Debug, thiserror::Error)]
pub enum CustodyError {
    #[error("human presence declined; custody was not changed")]
    PresenceDenied,
    #[error("{0}")]
    PresenceUnavailable(String),
    #[error("no credential is connected for provider `{0}`")]
    MissingSecret(String),
    #[error("provider_disabled")]
    ProviderDisabled,
    #[error("custody storage failed: {0}")]
    Storage(String),
    #[error("the rules do not match their approval pin; re-run `cermet rules allow` to re-author")]
    RulesPinMismatch,
    #[error(
        "the sentence authority record is semantically unserved; ordinary incremental mutation is disabled; recover explicitly with `cermet doc apply --recover`"
    )]
    RulesUnserved,
    #[error("stored rules are invalid: {0}")]
    InvalidRules(String),
    #[error(
        "rules changed while human presence was open; custody was not changed; retry the command"
    )]
    RulesChanged,
    #[error("stored credential for `{0}` is not valid UTF-8")]
    InvalidSecret(String),
}

/// The exact rule corpus a read observed, plus its canonical source bytes (the CAS expectation).
#[derive(Debug, Clone)]
pub struct AuthenticatedRuleCorpus {
    pub(crate) rules: RuleSet,
    pub(crate) source: Vec<u8>,
}

/// A read snapshot of the sentence authority for an update ceremony.
#[derive(Debug, Clone)]
pub enum RuleCorpusSnapshot {
    Authenticated(AuthenticatedRuleCorpus),
    /// Exact untrusted state, used only by the disclosed presence-gated re-author flow.
    PinMismatch {
        source: Vec<u8>,
    },
}

/// The exact state a presence-gated whole-corpus replacement is allowed to supersede.
#[derive(Debug, Clone, Copy)]
pub enum RuleCorpusExpectation<'a> {
    Authenticated(&'a [u8]),
    PinMismatch(&'a [u8]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusMutationReceipt {
    pub authority_digest: String,
    pub occurrence_id: String,
    pub staging_token: String,
    pub state: CorpusMutationReceiptState,
    pub acceptance_path: &'static str,
    pub lockdown: Option<cermet_ipc::ctl::LockdownSnapshot>,
    pub live_is_exact: bool,
    pub document_sync: CorpusDocumentSync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusMutationReceiptState {
    Known,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusDocumentSync {
    State(&'static str),
    Required,
    Unavailable(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusDocumentObservation {
    pub sync: CorpusDocumentSync,
    pub status: Option<cermet_ipc::ctl::SentenceAuthorityStatus>,
}

pub trait CorpusDocumentSyncObserver: Send + Sync {
    fn observe(
        &self,
        status: Option<&cermet_ipc::ctl::SentenceAuthorityStatus>,
    ) -> CorpusDocumentObservation;
}

impl CorpusMutationReceipt {
    pub fn is_known(&self) -> bool {
        self.state == CorpusMutationReceiptState::Known
    }
}

/// The SENTENCE-ONLY custody seam: read the current authority and presence-gate a whole-corpus
/// compare-and-swap. No method exposes a secret or an ungated mutation.
pub trait SentenceCustody: Send + Sync {
    fn read_rules(&self) -> Result<RuleSet>;
    fn read_authenticated_rules(&self) -> Result<AuthenticatedRuleCorpus> {
        let rules = self.read_rules()?;
        let source = encode_rules(&rules)?;
        Ok(AuthenticatedRuleCorpus { rules, source })
    }
    fn read_rule_corpus_for_update(&self) -> Result<RuleCorpusSnapshot> {
        self.read_authenticated_rules()
            .map(RuleCorpusSnapshot::Authenticated)
    }
    fn compare_and_swap_rules_with_presence(
        &self,
        expected: RuleCorpusExpectation<'_>,
        rules: &RuleSet,
        summary: &str,
    ) -> Result<CorpusMutationReceipt>;
}

pub(crate) fn encode_rules(rules: &RuleSet) -> Result<Vec<u8>> {
    validate_sentence_authority(rules)?;
    let mut text = rules
        .rules
        .iter()
        .map(print_rule)
        .collect::<Vec<_>>()
        .join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    Ok(text.into_bytes())
}

fn validate_sentence_authority(rules: &RuleSet) -> Result<()> {
    cermet_lang::sentence::validate_sentence_authority(rules)
        .map_err(|error| CustodyError::InvalidRules(error.to_string()))
}
