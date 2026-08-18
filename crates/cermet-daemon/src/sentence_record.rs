//! The daemon-owned sentence authority record — ONE atomic authority record on EVERY OS.
//!
//! ONE durable file under the 0700 state dir holds a fixed format/version header, a 32-byte
//! domain/version-bound authority digest, committing occurrence id, and canonical UTF-8 sentence
//! bytes in one generation, so a single rename makes them atomic (no multi-file mismatch window).
//! The daemon is the sole owner and writer; the shared agent/approver uid gets EACCES on the 0700 dir.
//! The digest and occurrence are authority EVIDENCE, not secrets.
//!
//! Authoring is a **two-round staged ceremony**, the ONE flow on every platform:
//!   1. `stage(candidate_text)` — canonicalize + validate against the still-live prior generation,
//!      persist a durable STAGED record keyed by a unique random nonce, return the daemon's canonical
//!      echo + digest + token. NOTHING is made authoritative; the prior generation stays live. (A
//!      crash here leaves the prior generation live; staged records are inert, swept.)
//!   2. `commit(staging_token, sink)` — flip the generation atomically IFF the live generation is
//!      still the one the token was staged against (stale/unknown/superseded ⇒ typed refusal), then
//!      emit the custody audit STRICTLY AFTER the commit (idempotent and occurrence-keyed).
//!
//! Interpretation order (fail closed at every step; corrupt bytes are NEVER adopted or executed):
//!   read (O_NOFOLLOW, regular, single-link, daemon-euid-owned, no group/other write, size-capped)
//!   → compute the OPAQUE sha256 generation digest over the exact raw record BEFORE interpreting
//!   → verify the embedded authority digest against the rule bytes → parse → validate immutable sets
//!   → verify canonical re-encoding. Any failure ⇒ sentence authority unavailable (deny-all).
//!
//! Boot adoption (`adopt`) runs the SAME interpretation as an ADOPTION GATE: a valid record is
//! adopted (and its custody audit replayed idempotently, recovering a crash between commit and
//! audit); an absent/tampered/corrupt record makes sentence-routed requests DENY until re-authored
//! (fail closed).
//!
//! The defended boundary is daemon-versus-approver credential/filesystem custody. The presence
//! ceremony on the CLI protects operator-path ceremony integrity; it does NOT prove presence to the
//! daemon and is NOT a same-uid security boundary.
//!
//! The record/CAS/digest/staging logic is platform-GENERIC (plain unix file syscalls) so it is fully
//! tested on Linux. Only the production presence prompt (Touch ID / PAM) is platform-specific and
//! lives in the CLI custody, not here.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use cermet_core::sentence::{parse_rules, print_rule, RuleSet, Selector, RULE_SET_VERSION};
use cermet_core::{Error, Result, SentenceAuthoritySource};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use cermet_ipc::ctl::{
    SentenceCommitOutcome as CommitOutcome, SentenceSnapshot, StagedSentenceCorpus as Staged,
};

/// Fixed record header (format + version). A record that does not begin with these bytes is corrupt
/// (never silently reinterpreted under a new format).
pub const RECORD_MAGIC: &[u8] = b"cermet.sentence.record.v2\n";

const AUTHORITY_DIGEST_LEN: usize = 32;
const OCCURRENCE_ID_LEN: usize = 64;
const RECORD_HEADER_LEN: usize = RECORD_MAGIC.len() + AUTHORITY_DIGEST_LEN + OCCURRENCE_ID_LEN;

/// The lifetime of a staged (but uncommitted) record. A ceremony that stages and does not commit
/// within this window is inert: `commit` refuses an over-age token and the housekeeping
/// sweep reaps it. Sized for a human Stage→confirm→Commit ceremony, not a background job.
pub const STAGED_TTL_SECS: u64 = 3600;

/// The opaque generation digest over the EXACT raw record, lowercase hex. Computed before any
/// interpretation so a readable-but-corrupt record still carries a stable token.
pub fn record_digest(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The domain/language-version-bound identity of canonical authority (not the framed record).
pub fn canonical_digest(canonical_bytes: &[u8]) -> String {
    cermet_core::sentence::authority_digest_for(RULE_SET_VERSION, canonical_bytes)
}

/// Canonical rule bytes: each rule printed by the canonical printer, newline-joined, trailing newline
/// when non-empty.
pub fn canonical_rule_bytes(rules: &RuleSet) -> Vec<u8> {
    let mut text = rules
        .rules
        .iter()
        .map(print_rule)
        .collect::<Vec<_>>()
        .join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    text.into_bytes()
}

/// Build one complete v2 record. One atomic generation binds the authority digest, the exact
/// committing occurrence, and canonical text.
fn build_record(rule_bytes: &[u8], occurrence_id: &str) -> Vec<u8> {
    let digest = hex_to_32(&canonical_digest(rule_bytes)).expect("authority digest is 32-byte hex");
    debug_assert!(valid_token(occurrence_id));
    let mut record = Vec::with_capacity(RECORD_HEADER_LEN + rule_bytes.len());
    record.extend_from_slice(RECORD_MAGIC);
    record.extend_from_slice(&digest);
    record.extend_from_slice(occurrence_id.as_bytes());
    record.extend_from_slice(rule_bytes);
    record
}

/// Validate a proposed ruleset the SAME way interpretation validates a stored one, returning the
/// canonical rule bytes. Fail closed so a bad proposal never reaches a write (definite no-commit).
///
/// This runs the EXISTING validation (set-digest pinning + canonical fixpoint). This is the ONE
/// validation seam the stage step and boot adoption both run — any later semantic check would join it.
pub fn validate_and_canonicalize(rules: &RuleSet) -> Result<Vec<u8>> {
    validate_set_digests(rules)?;
    let bytes = canonical_rule_bytes(rules);
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Invalid("proposed sentence rules are not valid UTF-8".into()))?;
    let reparsed = parse_rules(text)
        .map_err(|_| Error::Invalid("proposed sentence rules do not parse".into()))?;
    if canonical_rule_bytes(&reparsed) != bytes {
        return Err(Error::Invalid(
            "proposed sentence rules are not canonical".into(),
        ));
    }
    Ok(bytes)
}

fn validate_set_digests(rules: &RuleSet) -> Result<()> {
    for rule in &rules.rules {
        if let Selector::Set { digest, .. } = &rule.selector {
            let pinned = digest
                .as_deref()
                .is_some_and(cermet_core::sets::valid_snapshot_digest);
            if !pinned {
                return Err(Error::Invalid(
                    "a set rule does not pin an immutable expansion digest".into(),
                ));
            }
        }
    }
    Ok(())
}

/// The outcome of interpreting an exact raw record. A corrupt record NEVER yields rules.
#[derive(Debug, Clone)]
pub enum Interpreted {
    Valid {
        digest: String,
        rules: RuleSet,
        authority_digest: String,
        occurrence_id: String,
    },
    Corrupt {
        digest: String,
        reason: String,
    },
}

/// Interpret an exact raw record. The digest is computed BEFORE any interpretation. Any interpretation
/// failure yields `Corrupt` with a content-free reason (never raw rule bytes).
pub fn interpret(raw: &[u8]) -> Interpreted {
    let digest = record_digest(raw);
    let corrupt = |reason: &str| Interpreted::Corrupt {
        digest: digest.clone(),
        reason: reason.to_string(),
    };
    if !raw.starts_with(RECORD_MAGIC) {
        return corrupt("record header/version is missing or unrecognized");
    }
    if raw.len() < RECORD_HEADER_LEN {
        return corrupt("record is truncated before the v2 authority header");
    }
    let authority_bytes = &raw[RECORD_MAGIC.len()..RECORD_MAGIC.len() + AUTHORITY_DIGEST_LEN];
    let occurrence_bytes = &raw[RECORD_MAGIC.len() + AUTHORITY_DIGEST_LEN..RECORD_HEADER_LEN];
    let occurrence_id = match std::str::from_utf8(occurrence_bytes) {
        Ok(id) if valid_token(id) => id.to_string(),
        _ => return corrupt("committing occurrence id is malformed"),
    };
    let rule_bytes = &raw[RECORD_HEADER_LEN..];
    let computed = canonical_digest(rule_bytes);
    if authority_bytes != hex_to_32(&computed).expect("computed authority digest is valid hex") {
        return corrupt("embedded authority digest does not match the canonical rule bytes");
    }
    let text = match std::str::from_utf8(rule_bytes) {
        Ok(text) => text,
        Err(_) => return corrupt("sentence rules are not valid UTF-8"),
    };
    let rules = match parse_rules(text) {
        Ok(rules) => rules,
        // The parse error is the whole story for the one upgrade this product has: the corpus is
        // stored as canonical TEXT and re-parsed here, so a corpus authored in a superseded
        // dialect fails closed and the operator must RE-AUTHOR it (no backward compatibility, no
        // one-shot migration — see `docs/LANGUAGE.md` §3). Saying "do not parse" and swallowing
        // which line and why would leave that operator with nothing to act on.
        Err(error) => {
            return corrupt(&format!(
                "sentence rules do not parse ({error}); re-author the corpus with \
                 `cermet rules allow`"
            ))
        }
    };
    if validate_set_digests(&rules).is_err() {
        return corrupt("a set rule does not pin an immutable expansion digest");
    }
    if canonical_rule_bytes(&rules) != rule_bytes {
        return corrupt("sentence rules are not canonical");
    }
    Interpreted::Valid {
        digest,
        rules,
        authority_digest: computed,
        occurrence_id,
    }
}

/// The boot ADOPTION-GATE outcome.
#[derive(Debug, Clone, PartialEq)]
pub enum AdoptOutcome {
    Adopted {
        canonical_digest: String,
        rule_count: usize,
        /// The adopted generation's canonical rule text — carried out of the SAME classify read so the
        /// boot semantic gate validates EXACTLY these bytes, never a second (racy/failable)
        /// snapshot read.
        canonical_text: String,
    },
    Absent,
    Corrupt {
        record_digest: String,
        reason: String,
    },
}

/// The durable staged record persisted between round one and round two. Daemon-internal (NOT
/// authority) — held in the 0700 state dir, 0600, keyed by canonical digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StagedRecord {
    nonce: String,
    canonical_digest: String,
    staged_against: ExactBaseline,
    /// The daemon-validated canonical rule bytes this staging will make authoritative.
    canonical_text: String,
    created_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state")]
enum ExactBaseline {
    Absent,
    Present {
        record_digest: String,
        served_state: PresentServedState,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PresentServedState {
    Served,
    Unserved,
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingAudit {
    pub occurrence_id: String,
    pub target_digest: String,
    pub prior_record: Option<String>,
    pub rule_count: usize,
    pub operator_uid: u32,
    pub acceptance_path: String,
    pub confirmed: bool,
}

#[derive(Debug, Clone)]
struct LiveGeneration {
    authority_digest: String,
    occurrence_id: String,
}

/// Whether a sink actually landed the custody audit (`Emitted`) or merely accepted the call without
/// durably recording it (`Skipped`). Only an `Emitted` outcome may clear the outbox marker — so a
/// no-op / non-durable sink can NEVER destroy a pending audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEmitted {
    Emitted,
    Skipped,
}

/// The post-commit custody-audit sink. `record_committed` is called STRICTLY AFTER the
/// authority flip and MUST be idempotent, keyed by `occurrence_id` (the durable per-commit transition
/// id on the outbox marker) — so a concurrent commit or a boot-adoption replay of the SAME
/// pending marker never drops or double-chains an audit, while a genuine re-transition to a prior
/// generation (A→B→A) still records a distinct event. It reports whether the audit was durably
/// recorded (`Emitted`) so the outbox marker is cleared ONLY on a real emit.
pub trait CustodyAuditSink {
    fn record_committed(
        &self,
        canonical_digest: &str,
        rule_count: usize,
        occurrence_id: &str,
    ) -> Result<AuditEmitted>;

    fn record_committed_attributed(
        &self,
        canonical_digest: &str,
        rule_count: usize,
        occurrence_id: &str,
        operator_uid: u32,
        acceptance_path: &str,
        prior_record: Option<&str>,
    ) -> Result<AuditEmitted> {
        let _ = (operator_uid, acceptance_path, prior_record);
        self.record_committed(canonical_digest, rule_count, occurrence_id)
    }
}

/// A sink that records NOTHING and always reports `Skipped`, so it can never clear an outbox marker.
/// Production boot/tick drain the outbox through the REAL broker sink (the async replay
/// loop); this exists only for callers/tests that must classify without emitting.
pub struct NoopAuditSink;
impl CustodyAuditSink for NoopAuditSink {
    fn record_committed(
        &self,
        _canonical_digest: &str,
        _rule_count: usize,
        _occurrence_id: &str,
    ) -> Result<AuditEmitted> {
        Ok(AuditEmitted::Skipped)
    }
}

/// The ctl-only sentence admin over the staged two-round ceremony. The read-only `SentenceSnapshot`
/// and the boot `adopt` gate round it out.
pub trait SentenceRecordAdmin: Send + Sync {
    fn snapshot(&self) -> Result<SentenceSnapshot>;
    fn stage(&self, candidate_text: &str) -> Result<Staged>;
    /// The canonical text of a staged record, so the ctl Commit handler can re-validate the
    /// EXACT staged bytes through the broker's `validate_corpus` BEFORE the flip (a validation failure
    /// refuses without ever flipping) and provision the EXACT generation it committed (never a live
    /// re-read a racing ceremony could swap). `None` when the token is unknown/stale.
    fn peek_staged_text(&self, staging_token: &str) -> Result<Option<String>>;
    fn commit(&self, staging_token: &str, sink: &dyn CustodyAuditSink) -> Result<CommitOutcome> {
        self.commit_attributed(staging_token, 0, "presence", sink)
    }
    fn commit_attributed(
        &self,
        staging_token: &str,
        operator_uid: u32,
        acceptance_path: &str,
        sink: &dyn CustodyAuditSink,
    ) -> Result<CommitOutcome>;
    /// Remove staged records older than `ttl_secs` (inert once the ceremony ended or crashed).
    fn sweep_staged(&self, ttl_secs: u64) -> Result<usize>;
    /// Boot adoption gate: classify the record and refresh the live generation's audit-pending marker
    /// unconditionally. Emission is driven separately through the real broker sink via
    /// [`Self::pending_audits`] + [`Self::clear_pending_audit`] — `adopt` never emits.
    fn adopt(&self) -> Result<AdoptOutcome>;
    /// Every committed-but-unaudited generation (`canonical_digest`, `rule_count`, `occurrence_id`).
    /// The async housekeeping tick / boot drive replay through this + [`Self::clear_pending_audit`] so
    /// the sync `CustodyAuditSink` is not needed off the ctl thread. The `occurrence_id` is
    /// the durable per-commit transition id the broker dedups on.
    fn pending_audit_records(&self) -> Result<Vec<PendingAudit>>;
    fn pending_audits(&self) -> Result<Vec<(String, usize, String)>> {
        Ok(self
            .pending_audit_records()?
            .into_iter()
            .map(|marker| {
                (
                    marker.target_digest,
                    marker.rule_count,
                    marker.occurrence_id,
                )
            })
            .collect())
    }
    /// Clear a pending-audit marker after its custody audit has landed.
    fn clear_pending_audit(&self, occurrence_id: &str);
    /// Reconcile the LIVE generation's audit marker on the housekeeping tick — if a commit's
    /// best-effort post-flip confirm FAILED, the live generation carries an intent-only marker that
    /// `pending_audits` excludes (so replay never emits it) and `sweep_orphan_intents` keeps (it IS
    /// live), leaving live authority unaudited until the next boot. Promoting it to confirmed here makes
    /// the audit emittable within one tick instead. A no-op when the live marker is already confirmed,
    /// already emitted (absent), or there is no valid live generation. Errors surface for a loud retry.
    fn reconcile_live_audit_marker(&self) -> Result<()>;
}

/// The durable record file backend. Split from the store so CAS/digest/ordering semantics test against
/// real unix files.
pub trait RecordIo: Send + Sync {
    /// The security-checked read. `Ok(None)` is ABSENT; `Ok(Some(bytes))` is a safely-read daemon-owned
    /// regular single-link file with no group/other write; `Err` is a security event (symlink, foreign
    /// owner, multi-link, group/other-writable, oversize, or I/O error).
    fn read(&self, path: &Path, expected_owner_uid: u32) -> Result<Option<Vec<u8>>>;
    fn write_temp_and_fsync(&self, dir: &Path, name: &str, bytes: &[u8]) -> io::Result<PathBuf>;
    fn rename(&self, temp: &Path, final_path: &Path) -> io::Result<()>;
    fn fsync_dir(&self, dir: &Path) -> io::Result<()>;
    fn remove(&self, temp: &Path);
}

/// The universal daemon-owned sentence store. It is BOTH the read-only `SentenceAuthoritySource` and
/// the ctl-only `SentenceRecordAdmin`, behind ONE mutex so a read and a stage/commit never interleave.
pub struct SentenceRecordStore {
    path: PathBuf,
    staged_dir: PathBuf,
    /// The audit OUTBOX: one durable occurrence-keyed marker per acceptance transition, written under
    /// the lock at commit and cleared only after its custody audit lands. Boot adoption plus the
    /// housekeeping tick replay every pending marker, so repeated content transitions remain distinct
    /// and a flipped generation's audit can never be permanently dropped.
    audit_pending_dir: PathBuf,
    /// Whether the staging / outbox directory's PARENT has been fsync-durably created. A
    /// flag (not `dir.exists()`) governs the short-circuit, so a FAILED parent fsync is retried on the
    /// next write rather than silently skipped, and success is recorded ONLY after a successful fsync.
    staged_dir_durable: AtomicBool,
    audit_pending_dir_durable: AtomicBool,
    /// The Linux operator-facing rules file, regenerated on commit as a read PROJECTION only (never
    /// read as authority). `None` where no projection is exported.
    projection_path: Option<PathBuf>,
    /// The canonical digest of the generation the broker's semantic `validate_corpus`
    /// demonstrably PASSED over THIS process lifetime — a POSITIVE gate (default deny). `current_ruleset`
    /// serves a well-formed record ONLY when its live digest equals this; any other state (a fresh process
    /// before boot validation, a transient boot read failure, or a raw on-disk edit to an un-validated
    /// generation) DENIES fail-closed until validation succeeds. Set by the two paths that establish a
    /// served generation: boot adoption (`main.rs` after `validate_corpus` passes) and a successful
    /// `commit` (the ctl handler pre-validates the exact staged bytes before calling it).
    validated_digest: Mutex<Option<String>>,
    /// The generation boot adoption ran `validate_corpus` over and the exact reason it FAILED, as
    /// `(canonical_digest, reason)`. Purely explanatory: the positive gate above already denies, and
    /// this only decides WHAT the deny says. A deny-all reading "did not pass semantic validation"
    /// names a state, not a problem; the operator then has to go find the boot log. The reason is the
    /// daemon's own validation text — never agent input — so it is rendered verbatim with nothing to
    /// scrub. Kept DIGEST-KEYED so an explanation computed for one generation is never attributed to a
    /// different record that happens to be unvalidated for its own reason. Cleared by
    /// [`Self::mark_generation_validated`], so a corpus that now serves carries no stale failure.
    boot_validation_failure: Mutex<Option<(String, String)>>,
    expected_owner_uid: u32,
    io: Box<dyn RecordIo>,
    lock: Mutex<()>,
}

impl SentenceRecordStore {
    pub fn new(
        path: PathBuf,
        staged_dir: PathBuf,
        projection_path: Option<PathBuf>,
        expected_owner_uid: u32,
    ) -> Self {
        let audit_pending_dir = Self::audit_pending_dir_for(&path);
        Self {
            path,
            staged_dir,
            audit_pending_dir,
            staged_dir_durable: AtomicBool::new(false),
            audit_pending_dir_durable: AtomicBool::new(false),
            projection_path,
            validated_digest: Mutex::new(None),
            boot_validation_failure: Mutex::new(None),
            expected_owner_uid,
            io: Box::new(RealRecordIo),
            lock: Mutex::new(()),
        }
    }

    #[cfg(test)]
    pub fn with_io(
        path: PathBuf,
        staged_dir: PathBuf,
        projection_path: Option<PathBuf>,
        expected_owner_uid: u32,
        io: Box<dyn RecordIo>,
    ) -> Self {
        let audit_pending_dir = Self::audit_pending_dir_for(&path);
        Self {
            path,
            staged_dir,
            audit_pending_dir,
            staged_dir_durable: AtomicBool::new(false),
            audit_pending_dir_durable: AtomicBool::new(false),
            projection_path,
            validated_digest: Mutex::new(None),
            boot_validation_failure: Mutex::new(None),
            expected_owner_uid,
            io,
            lock: Mutex::new(()),
        }
    }

    pub fn record_path(state_dir: &Path) -> PathBuf {
        state_dir.join("sentence.record")
    }

    pub fn staged_dir(state_dir: &Path) -> PathBuf {
        state_dir.join("sentence.staged")
    }

    pub fn audit_pending_dir(state_dir: &Path) -> PathBuf {
        state_dir.join("sentence.audit_pending")
    }

    /// The audit outbox dir lives beside the record under the same state dir.
    fn audit_pending_dir_for(record_path: &Path) -> PathBuf {
        record_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|dir| dir.join("sentence.audit_pending"))
            .unwrap_or_else(|| PathBuf::from("sentence.audit_pending"))
    }

    fn read_record(&self) -> Result<Option<Vec<u8>>> {
        self.io.read(&self.path, self.expected_owner_uid)
    }

    fn exact_baseline(&self) -> Result<ExactBaseline> {
        let validated = self
            .validated_digest
            .lock()
            .map_err(|_| poisoned())?
            .clone();
        Ok(match self.read_record()? {
            None => ExactBaseline::Absent,
            Some(bytes) => {
                let opaque = record_digest(&bytes);
                let served_state = match interpret(&bytes) {
                    Interpreted::Valid {
                        authority_digest, ..
                    } if validated.as_deref() == Some(authority_digest.as_str()) => {
                        PresentServedState::Served
                    }
                    Interpreted::Valid { .. } => PresentServedState::Unserved,
                    Interpreted::Corrupt { .. } => PresentServedState::Corrupt,
                };
                ExactBaseline::Present {
                    record_digest: opaque,
                    served_state,
                }
            }
        })
    }

    fn live_generation(&self) -> Result<Option<LiveGeneration>> {
        Ok(match self.read_record()? {
            None => None,
            Some(bytes) => match interpret(&bytes) {
                Interpreted::Valid {
                    authority_digest,
                    occurrence_id,
                    ..
                } => Some(LiveGeneration {
                    authority_digest,
                    occurrence_id,
                }),
                Interpreted::Corrupt { .. } => None,
            },
        })
    }

    /// THE ONE fsync-proving primitive: re-fsync the record directory AND the audit
    /// outbox directory UNCONDITIONALLY, so a record rename or a marker rename that is merely OS-VISIBLE
    /// (its own dir fsync failed, or a predecessor process never fsynced it) is NEVER treated as durable.
    ///
    /// EVERY path that would confirm / validate / serve / SUPERSEDE a generation NOT freshly flipped by
    /// this process's own `commit_record` — the AlreadyCommitted retry, the supersession
    /// `confirm_outgoing_generation` gate, and boot `adopt` — routes through this FIRST. A generation
    /// whose dir fsync never succeeded this process lifetime is therefore not confirmable/supersedable:
    /// `?` fails the caller until a successful fsync. Re-fsync is unconditional (no "already visible"
    /// short-circuit) — durability is proven by the fsync, never inferred from a rename being visible.
    fn prove_durable(&self) -> Result<()> {
        let record_dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        self.io.fsync_dir(record_dir).map_err(|e| {
            Error::Provider(format!(
                "sentence record dir fsync failed (generation not proven durable): {e}"
            ))
        })?;
        // The outbox holds the audit markers; a `c` marker's rename is durable only once its dir is
        // fsynced. Only fsync it if it exists (no markers yet ⇒ nothing to prove).
        if self.audit_pending_dir.exists() {
            self.io.fsync_dir(&self.audit_pending_dir).map_err(|e| {
                Error::Provider(format!(
                    "audit-outbox dir fsync failed (marker not proven durable): {e}"
                ))
            })?;
        }
        Ok(())
    }

    fn snapshot_locked(&self) -> Result<SentenceSnapshot> {
        match self.read_record()? {
            None => Ok(SentenceSnapshot::Absent),
            Some(bytes) => Ok(match interpret(&bytes) {
                Interpreted::Valid {
                    digest,
                    rules,
                    authority_digest,
                    occurrence_id,
                } => {
                    let fields = (
                        digest,
                        String::from_utf8(canonical_rule_bytes(&rules))
                            .expect("canonical rule bytes are utf-8"),
                        authority_digest.clone(),
                        occurrence_id,
                        rules.rules.len(),
                    );
                    let validated = self
                        .validated_digest
                        .lock()
                        .map_err(|_| poisoned())?
                        .clone();
                    if validated.as_deref() == Some(authority_digest.as_str()) {
                        SentenceSnapshot::Served {
                            record_digest: fields.0,
                            rules_text: fields.1,
                            authority_digest: fields.2,
                            occurrence_id: fields.3,
                            rule_count: fields.4,
                        }
                    } else {
                        SentenceSnapshot::Unserved {
                            record_digest: fields.0,
                            rules_text: fields.1,
                            authority_digest: fields.2,
                            occurrence_id: fields.3,
                            rule_count: fields.4,
                        }
                    }
                }
                Interpreted::Corrupt { digest, reason } => SentenceSnapshot::Corrupt {
                    record_digest: digest,
                    reason,
                },
            }),
        }
    }

    fn staged_path(&self, token: &str) -> Result<PathBuf> {
        validate_token(token)?;
        Ok(self.staged_dir.join(token))
    }

    /// Create `dir` if absent and fsync its PARENT so the new directory entry is itself durable —
    /// otherwise the FIRST acknowledged write into a lazily-created dir is crash-volatile
    /// even though the file's own fsync succeeded.
    ///
    /// The short-circuit is governed by `durable` (set ONLY after a SUCCESSFUL parent fsync),
    /// NOT by `dir.exists()`. So a parent fsync that FAILS on the first attempt is retried on the next
    /// call — the directory being present is not proof its entry is durable. No write into the dir is
    /// acknowledged until the parent fsync has actually succeeded.
    fn ensure_dir_durable(&self, dir: &Path, durable: &AtomicBool) -> Result<()> {
        if durable.load(Ordering::Acquire) {
            return Ok(());
        }
        if !dir.exists() {
            std::fs::create_dir_all(dir)
                .map_err(|e| Error::Provider(format!("cannot create {}: {e}", dir.display())))?;
        }
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            // A failure leaves `durable` false, so the next call retries this fsync before ever
            // acknowledging a write into the dir.
            self.io.fsync_dir(parent).map_err(|e| {
                Error::Provider(format!(
                    "parent-dir fsync after creating {} failed (dir not durable): {e}",
                    dir.display()
                ))
            })?;
        }
        durable.store(true, Ordering::Release);
        Ok(())
    }

    fn write_staged(&self, token: &str, record: &StagedRecord) -> Result<()> {
        self.ensure_dir_durable(&self.staged_dir, &self.staged_dir_durable)?;
        let bytes = serde_json::to_vec(record)
            .map_err(|e| Error::Provider(format!("cannot serialize the staged record: {e}")))?;
        let temp = self
            .io
            .write_temp_and_fsync(&self.staged_dir, token, &bytes)
            .map_err(|e| Error::Provider(format!("sentence staged temp write failed: {e}")))?;
        let final_path = self.staged_path(token)?;
        if let Err(e) = self.io.rename(&temp, &final_path) {
            self.io.remove(&temp);
            return Err(Error::Provider(format!(
                "sentence staged record rename failed: {e}"
            )));
        }
        // A directory-fsync failure means the stage is NOT durable — fail the operation
        // (fail closed) rather than acknowledge a volatile stage that a crash could lose.
        self.io.fsync_dir(&self.staged_dir).map_err(|e| {
            Error::Provider(format!(
                "sentence staging dir fsync failed (stage not durable): {e}"
            ))
        })?;
        Ok(())
    }

    fn read_staged(&self, token: &str) -> Result<Option<StagedRecord>> {
        let path = self.staged_path(token)?;
        match self.io.read(&path, self.expected_owner_uid)? {
            None => Ok(None),
            Some(bytes) => {
                Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
                    Error::Provider(format!("corrupt staged record: {e}"))
                })?))
            }
        }
    }

    fn commit_record(&self, record: &[u8]) -> Result<()> {
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error::Provider("sentence record path has no file name".into()))?;
        let temp = self
            .io
            .write_temp_and_fsync(dir, name, record)
            .map_err(|e| Error::Provider(format!("sentence record temp write failed: {e}")))?;
        if let Err(e) = self.io.rename(&temp, &self.path) {
            self.io.remove(&temp);
            return Err(Error::Provider(format!(
                "sentence record rename failed (old generation retained): {e}"
            )));
        }
        // The rename made the new generation observable, but it is not DURABLE until the dir
        // fsync succeeds. Propagate the failure so `commit` returns an error and emits NO audit for a
        // flip that a crash could lose — the caller re-runs the ceremony (idempotent by token).
        self.io.fsync_dir(dir).map_err(|e| {
            Error::Provider(format!(
                "sentence record dir fsync failed (commit not durable): {e}"
            ))
        })?;
        Ok(())
    }

    fn audit_pending_path(&self, occurrence_id: &str) -> Result<PathBuf> {
        validate_token(occurrence_id)?;
        Ok(self.audit_pending_dir.join(occurrence_id))
    }

    fn write_audit_marker(&self, marker: &PendingAudit) -> Result<()> {
        validate_token(&marker.occurrence_id)?;
        self.ensure_dir_durable(&self.audit_pending_dir, &self.audit_pending_dir_durable)?;
        let bytes = serde_json::to_vec(marker)
            .map_err(|e| Error::Provider(format!("cannot serialize audit intent: {e}")))?;
        let temp = self
            .io
            .write_temp_and_fsync(&self.audit_pending_dir, &marker.occurrence_id, &bytes)
            .map_err(|e| Error::Provider(format!("audit-pending temp write failed: {e}")))?;
        let final_path = self.audit_pending_path(&marker.occurrence_id)?;
        if let Err(e) = self.io.rename(&temp, &final_path) {
            self.io.remove(&temp);
            return Err(Error::Provider(format!("audit-pending rename failed: {e}")));
        }
        self.io
            .fsync_dir(&self.audit_pending_dir)
            .map_err(|e| Error::Provider(format!("audit-outbox dir fsync failed: {e}")))?;
        Ok(())
    }

    fn write_audit_intent(&self, marker: PendingAudit) -> Result<()> {
        if self.read_marker(&marker.occurrence_id)?.is_some() {
            return Err(Error::Denied(
                "sentence transition occurrence already exists".into(),
            ));
        }
        self.write_audit_marker(&marker)
    }

    fn confirm_audit(&self, occurrence_id: &str) -> Result<()> {
        let Some(mut marker) = self.read_marker(occurrence_id)? else {
            return Ok(()); // already emitted and cleared
        };
        marker.confirmed = true;
        self.write_audit_marker(&marker)
    }

    fn read_marker(&self, occurrence_id: &str) -> Result<Option<PendingAudit>> {
        let path = self.audit_pending_path(occurrence_id)?;
        match self.io.read(&path, self.expected_owner_uid)? {
            None => Ok(None),
            Some(bytes) => parse_audit_marker(occurrence_id, &bytes).map(Some),
        }
    }

    fn clear_audit_pending(&self, occurrence_id: &str) {
        if let Ok(path) = self.audit_pending_path(occurrence_id) {
            self.io.remove(&path);
        }
    }

    /// The current live generation is about to be SUPERSEDED — durably secure its audit
    /// FIRST (hard gate), so a once-live generation can never later be mistaken for a never-live orphan
    /// and swept. Two steps, both `?` (the superseding commit fails if either can't be secured — the
    /// outgoing generation stays live until its evidence is durable). First `prove_durable()` re-fsyncs
    /// the record + outbox dirs, so the outgoing generation's rename and its marker are proven durable
    /// and never merely trusted because they are VISIBLE (a failed dir fsync on the outgoing commit
    /// leaves both visible-but-not-durable). Then `confirm_audit()` (re-)writes its CONFIRMED
    /// marker and fsyncs the outbox — UNCONDITIONALLY, never a "already `c` ⇒ no-op": a visible-but-
    /// unfsynced `c` marker must be re-written + fsynced, not trusted. A no-op only when there is no live
    /// generation (the first authoring).
    fn confirm_outgoing_generation(&self, live: Option<&LiveGeneration>) -> Result<()> {
        let Some(live) = live else {
            return Ok(());
        };
        self.prove_durable()?;
        self.confirm_audit(&live.occurrence_id)
    }

    /// Reap every INTENT-only marker whose generation is NOT `live_digest` — such a marker was
    /// written before a flip that then failed / crashed, so that generation NEVER went live and must
    /// never be emitted as a "committed" audit. Confirmed markers (once-live, possibly superseded) are
    /// LEFT for replay. A malformed marker list is ignored here (the loud path is `read_audit_markers`
    /// in the emit/replay flow). Each reaped orphan is logged loudly. Called under the record lock.
    fn sweep_orphan_intents(&self, live_occurrence: Option<&str>) {
        let markers = match self.read_audit_markers() {
            Ok(m) => m,
            Err(_) => return, // surfaced loudly by the emit/replay path; not this belt's job
        };
        for marker in markers {
            if marker.confirmed {
                continue;
            }
            if live_occurrence == Some(marker.occurrence_id.as_str()) {
                continue; // the live generation's intent is confirmed by the caller, not swept
            }
            eprintln!(
                "cermetd: sweeping an orphan pre-flip audit marker for generation {} — its flip never \
                 completed, so no custody audit is (or ever was) owed",
                &marker.target_digest[..marker.target_digest.len().min(12)]
            );
            self.clear_audit_pending(&marker.occurrence_id);
        }
    }

    /// Every pending marker as `(digest, rule_count, confirmed)`. Written atomically (temp+rename), so a
    /// read never sees a partial file; `.`-prefixed temps are skipped. An unreadable
    /// / malformed / legacy marker is a loud `Err` (retained, never silently skipped or defaulted).
    fn read_audit_markers(&self) -> Result<Vec<PendingAudit>> {
        let entries = match std::fs::read_dir(&self.audit_pending_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(Error::Provider(format!(
                    "cannot scan the audit-outbox dir: {e}"
                )))
            }
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry
                .map_err(|e| Error::Provider(format!("cannot read an audit-outbox entry: {e}")))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue; // an in-flight temp, never a committed marker
            }
            let bytes = self
                .io
                .read(&entry.path(), self.expected_owner_uid)?
                .ok_or_else(|| {
                    Error::Provider(format!("audit marker `{name}` vanished during the scan"))
                })?;
            let marker = parse_audit_marker(&name, &bytes)?;
            out.push(marker);
        }
        Ok(out)
    }

    /// Emit every CONFIRMED pending custody audit through `sink`, clearing a marker ONLY when the sink
    /// reports `Emitted`. An INTENT-only marker is NEVER emitted here (it is not yet
    /// proof the generation went live — `adopt` confirms the live one and sweeps the rest). Idempotent by
    /// digest (the sink dedups). A failed/skipped emit LEAVES its marker + returns the error.
    /// Runs with the record lock NOT held.
    fn emit_pending_audits(&self, sink: &dyn CustodyAuditSink) -> Result<()> {
        let mut first_err = None;
        for marker in self.read_audit_markers()? {
            if !marker.confirmed {
                continue; // intent-only — never a fabricated "committed" audit
            }
            match sink.record_committed_attributed(
                &marker.target_digest,
                marker.rule_count,
                &marker.occurrence_id,
                marker.operator_uid,
                &marker.acceptance_path,
                marker.prior_record.as_deref(),
            ) {
                Ok(AuditEmitted::Emitted) => self.clear_audit_pending(&marker.occurrence_id),
                Ok(AuditEmitted::Skipped) => {} // retained for a real drain — never cleared here
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Regenerate the operator-facing read PROJECTION (Linux `/etc/cermetd/sentences/rules.cermet`).
    /// Best-effort: a failure here NEVER blocks the authoritative commit — the record is the sole
    /// authority; the projection is only a convenience the daemon exports, never read back as truth.
    ///
    /// Written SYMLINK-SAFELY — a temp file created `O_NOFOLLOW | O_EXCL` in the projection's
    /// own directory, then `rename`d over the target. `rename(2)` REPLACES a symlink at the destination
    /// without following it, and the `O_EXCL` temp can never be a pre-planted symlink, so a service-uid
    /// write can no longer be redirected through an approver-planted `rules.cermet` symlink into
    /// daemon-owned state (the custody-boundary crossing). The shipped installer additionally provisions
    /// this directory daemon-owned (defense in depth), so the approver cannot manipulate its contents.
    fn refresh_projection(&self, canonical_bytes: &[u8]) {
        let Some(path) = &self.projection_path else {
            return;
        };
        let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
            return;
        };
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        let _ = std::fs::create_dir_all(dir);
        // Never open `path` directly for writing (that would FOLLOW a symlink at `path`). Write a fresh
        // O_NOFOLLOW|O_EXCL temp, then atomically rename it over the target.
        if let Ok(temp) = self.io.write_temp_and_fsync(dir, name, canonical_bytes) {
            // The projection exists for the approvers' group to read (the installer's
            // setgid 2750 cermet:cermet-approvers dir); the helper's private 0600 default would
            // defeat that. Group-read only here — every other write_temp_and_fsync caller
            // (staged tokens, records, audit pending) keeps 0600. Best-effort like the rest of
            // this refresh: on failure the projection stays 0600 (readers fail closed).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o640));
            }
            if self.io.rename(&temp, path).is_err() {
                self.io.remove(&temp);
            }
        }
    }
}

impl SentenceAuthoritySource for SentenceRecordStore {
    fn current_authority(&self) -> Result<cermet_core::AuthenticatedSentenceAuthority> {
        let _g = self.lock.lock().map_err(|_| poisoned())?;
        match self.read_record()? {
            None => Err(Error::Denied(
                "no sentence authority record; sentence requests deny-all until `cermet rules allow`"
                    .into(),
            )),
            Some(bytes) => match interpret(&bytes) {
                Interpreted::Valid { rules, .. } => {
                    // POSITIVE GATE (fail closed by default): serve ONLY the generation the
                    // broker's semantic `validate_corpus` demonstrably passed over THIS process lifetime.
                    // A fresh process before boot validation, a transient boot read failure, or a raw
                    // on-disk edit to an un-validated generation all leave the live digest ≠ the
                    // validated one ⇒ DENY (joins the absent/corrupt deny class), until validation
                    // succeeds (boot re-adopt, or a re-authored commit that pre-validates its bytes).
                    let live = canonical_digest(&canonical_rule_bytes(&rules));
                    let validated = self
                        .validated_digest
                        .lock()
                        .map_err(|_| poisoned())?
                        .clone();
                    if validated.as_deref() == Some(live.as_str()) {
                        Ok(cermet_core::AuthenticatedSentenceAuthority {
                            digest: live,
                            rules,
                        })
                    } else {
                        // Say WHY when we know why. A retained boot-validation failure for THIS
                        // exact generation is the answer the operator needs; anything else (a fresh
                        // process before boot validation, a transient read failure, a raw on-disk
                        // edit) has no explanation to give and falls back to naming the gate.
                        let failure = self
                            .boot_validation_failure
                            .lock()
                            .map_err(|_| poisoned())?
                            .clone();
                        Err(Error::Denied(match failure {
                            Some((failed, reason)) if failed == live => format!(
                                "the standing corpus failed validation at boot ({reason}) — \
                                 deny-all until corrected; run `cermet doc check`, then re-author \
                                 via `cermet rules allow`"
                            ),
                            _ => "sentence authority has not passed semantic validation this daemon \
                                  lifetime; deny-all until adopted-and-validated or re-authored via \
                                  `cermet rules allow`"
                                .to_string(),
                        }))
                    }
                }
                Interpreted::Corrupt { reason, .. } => Err(Error::Denied(format!(
                    "sentence authority record is unusable ({reason}); deny-all"
                ))),
            },
        }
    }
}

impl SentenceRecordStore {
    /// Mark `canonical_digest` as the generation `validate_corpus` PASSED over this process
    /// lifetime — the positive gate `current_ruleset` consults. Called by the two paths that establish
    /// a served generation: boot adoption (`main.rs`, after the broker validates the adopted bytes) and
    /// a successful `commit` (whose caller pre-validated the exact staged bytes). Overwrites
    /// the prior value: only the currently-served generation matters.
    pub fn mark_generation_validated(&self, canonical_digest: &str) {
        if let Ok(mut guard) = self.validated_digest.lock() {
            *guard = Some(canonical_digest.to_string());
        }
        // A generation that now validates carries no failure explanation.
        if let Ok(mut guard) = self.boot_validation_failure.lock() {
            *guard = None;
        }
    }

    /// Retain WHY boot adoption's `validate_corpus` refused `canonical_digest`, so the deny it causes
    /// can name the actual problem instead of only the state. This does NOT gate anything — the
    /// positive gate above is the whole authority decision and is unchanged; the corpus denies either
    /// way. `reason` is the broker's own validation text (see [`Self::boot_validation_failure`]).
    pub fn mark_generation_validation_failed(&self, canonical_digest: &str, reason: &str) {
        if let Ok(mut guard) = self.boot_validation_failure.lock() {
            *guard = Some((canonical_digest.to_string(), reason.to_string()));
        }
    }
}

impl SentenceRecordAdmin for SentenceRecordStore {
    fn snapshot(&self) -> Result<SentenceSnapshot> {
        let _g = self.lock.lock().map_err(|_| poisoned())?;
        self.snapshot_locked()
    }

    fn stage(&self, candidate_text: &str) -> Result<Staged> {
        // Parse + validate + canonicalize FIRST so a bad proposal is a definite no-stage.
        let rules = parse_rules(candidate_text)
            .map_err(|e| Error::Invalid(format!("proposed sentence rules do not parse: {e}")))?;
        let canonical_bytes = validate_and_canonicalize(&rules)?;
        let canonical_text = String::from_utf8(canonical_bytes.clone())
            .map_err(|_| Error::Invalid("canonical sentence rules are not valid UTF-8".into()))?;
        let digest = canonical_digest(&canonical_bytes);
        let token = new_stage_nonce();
        let occurrence_id = occurrence_for_nonce(&token);

        let _g = self.lock.lock().map_err(|_| poisoned())?;
        // Bind the staged record to the generation live RIGHT NOW — the commit CAS refuses if a
        // concurrent ceremony moves the live generation off this before we commit.
        let staged_against = self.exact_baseline()?;
        let record = StagedRecord {
            nonce: token.clone(),
            canonical_digest: digest.clone(),
            staged_against,
            canonical_text: canonical_text.clone(),
            created_at_unix: now_unix(),
        };
        self.write_staged(&token, &record)?;
        Ok(Staged {
            canonical_text,
            canonical_digest: digest,
            staging_token: token,
            occurrence_id,
        })
    }

    fn peek_staged_text(&self, staging_token: &str) -> Result<Option<String>> {
        validate_token(staging_token)?;
        let _g = self.lock.lock().map_err(|_| poisoned())?;
        Ok(self.read_staged(staging_token)?.map(|r| r.canonical_text))
    }

    fn commit_attributed(
        &self,
        staging_token: &str,
        operator_uid: u32,
        acceptance_path: &str,
        sink: &dyn CustodyAuditSink,
    ) -> Result<CommitOutcome> {
        validate_token(staging_token)?;
        if acceptance_path.trim().is_empty() || acceptance_path.len() > 64 {
            return Err(Error::Denied(
                "sentence acceptance path is malformed".into(),
            ));
        }
        let occurrence_id = occurrence_for_nonce(staging_token);
        // PHASE 1 — under the record lock: validate, flip the generation, and durably record the
        // audit-pending marker. NO cross-thread wait happens under the lock (the audit sink, which
        // routes to the broker actor, is emitted in phase 2 AFTER the lock is released).
        let outcome = {
            let _g = self.lock.lock().map_err(|_| poisoned())?;
            let staged = self.read_staged(staging_token)?.ok_or_else(|| {
                Error::Denied(
                    "unknown or stale staging token; nothing was written — re-stage with `cermet rules allow`"
                        .into(),
                )
            })?;

            if staged.nonce != staging_token
                || canonical_digest(staged.canonical_text.as_bytes()) != staged.canonical_digest
            {
                return Err(Error::Denied(
                    "the staged record's nonce or candidate digest is invalid; refusing to commit — \
                     re-stage with `cermet rules allow`"
                        .into(),
                ));
            }

            // Staged-at is a trusted-daemon wall clock. A staged timestamp in the FUTURE
            // means the clock rolled back since staging — refuse (fail closed) rather than let a
            // rollback silently extend the token's validity. (Trusted clock, out of the agent threat
            // model, but cheap to clamp.)
            let now = now_unix();
            if now < staged.created_at_unix {
                return Err(Error::Denied(
                    "the staged corpus carries a future timestamp (daemon clock anomaly); nothing was \
                     written — re-stage with `cermet rules allow`"
                        .into(),
                ));
            }
            // An over-age staged corpus is inert — refuse it (the sweep reaps the file).
            if now.saturating_sub(staged.created_at_unix) >= STAGED_TTL_SECS {
                return Err(Error::Denied(
                    "the staged corpus expired before commit; nothing was written — re-stage with \
                     `cermet rules allow`"
                        .into(),
                ));
            }

            let rules = parse_rules(&staged.canonical_text)
                .map_err(|e| Error::Provider(format!("staged record no longer parses: {e}")))?;
            let rule_count = rules.rules.len();
            let live_gen = self.live_generation()?;
            let live_baseline = self.exact_baseline()?;

            if live_gen.as_ref().is_some_and(|live| {
                live.occurrence_id == occurrence_id
                    && live.authority_digest == staged.canonical_digest
            }) {
                // Idempotent re-commit: the live generation ALREADY equals this staged corpus (a
                // lost-response ceremony re-sending its commit). A prior commit's rename may
                // have been OS-visible before its dir fsync failed, so before confirming/validating a
                // generation this process has NOT freshly flipped, re-fsync the record dir — a retry
                // must re-prove durability, never confirm/serve an unproven-durable generation.
                self.prove_durable()?;
                let _ = self.confirm_audit(&occurrence_id);
                self.mark_generation_validated(&staged.canonical_digest);
                CommitOutcome::AlreadyCommitted {
                    canonical_digest: staged.canonical_digest.clone(),
                    occurrence_id: occurrence_id.clone(),
                }
            } else {
                // Supersession CAS: the live generation must still be the one this token was staged
                // against.
                if staged.staged_against != live_baseline {
                    return Err(Error::Denied(
                        "the sentence authority changed since this corpus was staged (a concurrent \
                         ceremony committed first); nothing was written — re-stage with `cermet rules allow`"
                            .into(),
                    ));
                }
                // The OUTGOING live generation is about to be superseded — durably CONFIRM
                // its audit FIRST (hard gate). A once-live generation can then never become a sweepable
                // intent-only orphan; if its confirm cannot be secured, THIS commit fails and the
                // outgoing generation stays live until its audit evidence is durable.
                self.confirm_outgoing_generation(live_gen.as_ref())?;

                let rule_bytes = validate_and_canonicalize(&rules)?;
                let record = build_record(&rule_bytes, &occurrence_id);
                // Write the durable INTENT marker BEFORE the flip, so no flipped generation is
                // ever unmarked. An intent marker is NOT emittable — if the flip fails or a crash lands
                // between here and the flip, this generation never went live and its intent-only marker
                // is SWEPT (never a fabricated "committed" audit). This write never downgrades
                // a prior CONFIRMED marker for the same digest (a re-add keeps its confirmed evidence).
                let prior_record = match &staged.staged_against {
                    ExactBaseline::Absent => None,
                    ExactBaseline::Present { record_digest, .. } => Some(record_digest.clone()),
                };
                self.write_audit_intent(PendingAudit {
                    occurrence_id: occurrence_id.clone(),
                    target_digest: staged.canonical_digest.clone(),
                    prior_record,
                    rule_count,
                    operator_uid,
                    acceptance_path: acceptance_path.to_string(),
                    confirmed: false,
                })?;
                // Flip the generation atomically. `commit_record` returns ONLY after the flip's record-
                // dir fsync SUCCEEDS this process lifetime; an `Err` here means the
                // generation did NOT flip durably (the intent marker stays unconfirmed and is swept).
                self.commit_record(&record)?;
                self.refresh_projection(&rule_bytes);
                // The flip is durable (its dir fsync succeeded) ⇒ CONFIRM the marker (still under the
                // lock, so no other ceremony supersedes between rename and confirm). The
                // caller pre-validated these exact bytes ⇒ mark them served-validated.
                // Confirm is best-effort here — a lost confirm is re-derived by `adopt`, and any later
                // supersession first confirms this generation via `confirm_outgoing_generation`.
                let _ = self.confirm_audit(&occurrence_id);
                self.mark_generation_validated(&staged.canonical_digest);
                CommitOutcome::Committed {
                    canonical_digest: staged.canonical_digest.clone(),
                    occurrence_id: occurrence_id.clone(),
                }
            }
        };

        // PHASE 2 — lock released. Emit the custody audit STRICTLY AFTER the commit. A sink
        // failure here does NOT undo the flip (which is authoritative and durable); the marker persists
        // for boot/tick replay, so the flip is never treated as if it did not happen.
        let _ = self.emit_pending_audits(sink);
        Ok(outcome)
    }

    fn sweep_staged(&self, ttl_secs: u64) -> Result<usize> {
        let _g = self.lock.lock().map_err(|_| poisoned())?;
        let now = now_unix();
        let mut swept = 0usize;
        let entries = match std::fs::read_dir(&self.staged_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(Error::Provider(format!("cannot scan the staging dir: {e}"))),
        };
        for entry in entries.flatten() {
            let token = entry.file_name().to_string_lossy().to_string();
            let expired = self
                .read_staged(&token)
                .ok()
                .flatten()
                .map(|r| now.saturating_sub(r.created_at_unix) >= ttl_secs)
                .unwrap_or(true); // an unreadable/corrupt staged file is inert — sweep it.
            if expired {
                self.io.remove(&entry.path());
                swept += 1;
            }
        }
        Ok(swept)
    }

    fn adopt(&self) -> Result<AdoptOutcome> {
        // The adoption gate CLASSIFIES the daemon-owned record. What GATES serving is `current_ruleset`
        // (it independently reads + interprets the same record and denies on absent/corrupt) — NOT this
        // method. So `adopt` reports the classification and refreshes the audit outbox as a BELT; an
        // `Err`/`Corrupt`/`Absent` here reflects a record the authority source ALSO refuses, keeping the
        // deny-all claim honest. For a live record, re-derive its generation and re-write the marker as
        // a BEST-EFFORT belt (the intent marker was already written before the commit's flip): a
        // belt-write failure does NOT change the outcome or gate serving — the valid record still
        // serves, the audit is eventually-consistent, and the failure is logged for the tick to retry.
        // Emission itself is driven by the async replay loop through the REAL broker sink — `adopt`
        // never emits.
        let _g = self.lock.lock().map_err(|_| poisoned())?;
        match self.read_record()? {
            None => {
                // No live generation ⇒ every intent-only marker is an orphan (never went live).
                self.sweep_orphan_intents(None);
                Ok(AdoptOutcome::Absent)
            }
            Some(bytes) => match interpret(&bytes) {
                Interpreted::Valid {
                    rules,
                    authority_digest,
                    occurrence_id,
                    ..
                } => {
                    let rule_bytes = canonical_rule_bytes(&rules);
                    let digest = authority_digest;
                    let rule_count = rules.rules.len();
                    // A boot-adopted record's dir entry may not have been fsynced by the
                    // crashed predecessor — its presence is not proof of durability THIS process
                    // lifetime. Re-fsync the record dir BEFORE confirming/adopting (hard gate): a
                    // failure returns Err ⇒ boot logs it and `current_ruleset` denies-all (never
                    // `mark_generation_validated`), fail-closed, until a lifetime with a successful
                    // record-dir fsync. Only a proven-durable generation may be confirmed/validated.
                    self.prove_durable()?;
                    // The live record + a successful fsync PROVE this generation went live durably ⇒
                    // CONFIRM its marker (re-deriving a confirmation lost to a crash between a commit's
                    // rename and its confirm). Best-effort belt: a confirm-write failure does not gate
                    // serving (the record is proven durable; the tick retries the audit).
                    if let Err(e) = self.confirm_audit(&occurrence_id) {
                        eprintln!(
                            "cermetd: could not confirm the sentence audit marker at adoption for \
                             generation {} ({e}); the housekeeping tick will retry the audit",
                            &digest[..digest.len().min(12)]
                        );
                    }
                    // Sweep INTENT-only markers for any OTHER generation — an intent that was
                    // never confirmed AND is not the live generation never went live (a crash between a
                    // commit's intent-write and its flip), so it must be reaped with a loud log, NEVER
                    // emitted as a fabricated "committed" audit. A CONFIRMED marker (a superseded but
                    // once-live generation) is LEFT for replay.
                    self.sweep_orphan_intents(Some(&occurrence_id));
                    let canonical_text =
                        String::from_utf8(rule_bytes).unwrap_or_else(|_| String::new());
                    Ok(AdoptOutcome::Adopted {
                        canonical_digest: digest,
                        rule_count,
                        canonical_text,
                    })
                }
                Interpreted::Corrupt { digest, reason } => {
                    // No live generation ⇒ every intent-only marker is an orphan (never went live).
                    self.sweep_orphan_intents(None);
                    Ok(AdoptOutcome::Corrupt {
                        record_digest: digest,
                        reason,
                    })
                }
            },
        }
    }

    fn pending_audit_records(&self) -> Result<Vec<PendingAudit>> {
        // Only CONFIRMED markers are emittable — an intent-only marker for a live generation
        // was already confirmed by `adopt`; any remaining intent-only marker is an orphan awaiting sweep.
        Ok(self
            .read_audit_markers()?
            .into_iter()
            .filter(|marker| marker.confirmed)
            .collect())
    }

    fn clear_pending_audit(&self, occurrence_id: &str) {
        self.clear_audit_pending(occurrence_id)
    }

    fn reconcile_live_audit_marker(&self) -> Result<()> {
        let _g = self.lock.lock().map_err(|_| poisoned())?;
        let Some(bytes) = self.read_record()? else {
            return Ok(()); // no live generation ⇒ nothing to reconcile
        };
        let Interpreted::Valid {
            authority_digest,
            occurrence_id,
            ..
        } = interpret(&bytes)
        else {
            return Ok(()); // a corrupt record is handled by the deny-all read gate, not here
        };
        match self.read_marker(&occurrence_id)? {
            // Already confirmed (normal) or already emitted + cleared (absent) — nothing owed.
            Some(PendingAudit {
                confirmed: true, ..
            })
            | None => Ok(()),
            // Intent-only for the LIVE generation ⇒ it demonstrably flipped (it is live) but its
            // post-flip confirm was lost. Promote it to confirmed (occurrence preserved) so replay
            // emits it — the same reconciliation `adopt` performs at boot.
            Some(PendingAudit {
                confirmed: false, ..
            }) => {
                eprintln!(
                    "cermetd: reconciling an unconfirmed live sentence audit marker for generation {} \
                     (a prior commit's post-flip confirm was lost); promoting to confirmed for replay",
                    &authority_digest[..authority_digest.len().min(12)]
                );
                // Prove the record + outbox durable BEFORE promoting the marker to confirmed —
                // the SAME hard durability gate the normal supersession path uses
                // (`confirm_outgoing_generation`). Without it, a reconciled audit could be emitted from a
                // visible-but-not-fsynced marker — durable on the normal path, merely
                // trusted here. Fail closed: if durability can't be proven, the marker stays intent-only
                // and the next tick / boot retries.
                self.prove_durable()?;
                self.confirm_audit(&occurrence_id)
            }
        }
    }
}

fn poisoned() -> Error {
    Error::Provider("sentence record store lock poisoned".into())
}

/// Read one audit marker from the outbox. An unparseable file is a loud `Err`, so the caller RETAINS
/// the marker and surfaces it rather than silently defaulting or dropping a custody audit.
///
/// NOTE: a well-formedness pass used to run after this
/// deserialize — the filename's token shape, `marker.occurrence_id == name`, the hex shape of
/// `target_digest` / `prior_record`, and `acceptance_path` bounds. Every marker in this outbox is
/// written by THIS daemon into its own 0700 directory via `write_temp_and_fsync` + `rename`, so the
/// file a reader sees is always a complete file the daemon serialized — never a torn write. A file
/// that parses as JSON but carries wrong VALUES is therefore a root-only artifact (someone with
/// write access to daemon-owned state), which this daemon does not defend against. This is a
/// documented limitation, not a gap: the crash-replay dedup below it (occurrence-id reconciliation,
/// intent-vs-confirmed, orphan sweeping) is genuine durability and is unchanged.
fn parse_audit_marker(name: &str, bytes: &[u8]) -> Result<PendingAudit> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Provider(format!("corrupt audit marker `{name}`: {e}")))
}

fn new_stage_nonce() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn occurrence_for_nonce(nonce: &str) -> String {
    cermet_ipc::ctl::sentence_occurrence_for_token(nonce)
}

fn valid_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_token(token: &str) -> Result<()> {
    if valid_token(token) {
        Ok(())
    } else {
        Err(Error::Denied(
            "malformed sentence staging/occurrence token; expected 64 lowercase hex characters"
                .into(),
        ))
    }
}

fn hex_to_32(hex: &str) -> Option<[u8; 32]> {
    if !valid_token(hex) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        out[index] = (hi << 4) | lo;
    }
    Some(out)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build the universal daemon-owned record store. Installed on EVERY OS: the record is always the
/// sole sentence source, so an absent record is deny-all through ONE path rather than a profile
/// fallback. `projection_path` is the operator-facing read projection to regenerate on commit (Linux
/// `/etc/cermetd/sentences/rules.cermet`); `None` exports none.
pub fn build_record_store(
    state_dir: &Path,
    projection_path: Option<PathBuf>,
) -> Arc<SentenceRecordStore> {
    let owner = nix::unistd::geteuid().as_raw();
    Arc::new(SentenceRecordStore::new(
        SentenceRecordStore::record_path(state_dir),
        SentenceRecordStore::staged_dir(state_dir),
        projection_path,
        owner,
    ))
}

/// Real security-checked read + durable syscalls. Mirrors the hardened pin-reader posture, plus a
/// single-link requirement (a hard link to a foreign inode is refused).
struct RealRecordIo;

impl RecordIo for RealRecordIo {
    fn read(&self, path: &Path, expected_owner_uid: u32) -> Result<Option<Vec<u8>>> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(Error::Denied(format!(
                    "cannot read the sentence record at {}: {e}",
                    path.display()
                )))
            }
        };
        let meta = file.metadata().map_err(|e| {
            Error::Denied(format!(
                "cannot stat the sentence record at {}: {e}",
                path.display()
            ))
        })?;
        let me = expected_owner_uid;
        if !meta.file_type().is_file() || meta.uid() != me {
            return Err(Error::Denied(format!(
                "sentence record at {} is not a regular file owned by the daemon uid {me}",
                path.display()
            )));
        }
        if meta.nlink() != 1 {
            return Err(Error::Denied(format!(
                "sentence record at {} has {} hard links (expected exactly 1)",
                path.display(),
                meta.nlink()
            )));
        }
        if meta.permissions().mode() & 0o022 != 0 {
            return Err(Error::Denied(format!(
                "sentence record at {} is group/other-writable",
                path.display()
            )));
        }
        let cap = cermet_core::authority::MAX_AUTHORITY_FILE;
        let mut buf = Vec::new();
        file.take(cap + 1).read_to_end(&mut buf).map_err(|e| {
            Error::Denied(format!(
                "cannot read the sentence record at {}: {e}",
                path.display()
            ))
        })?;
        if buf.len() as u64 > cap {
            return Err(Error::Denied(
                "sentence record exceeds the maximum authority-file size".into(),
            ));
        }
        Ok(Some(buf))
    }

    fn write_temp_and_fsync(&self, dir: &Path, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let temp = dir.join(format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        Ok(temp)
    }

    fn rename(&self, temp: &Path, final_path: &Path) -> io::Result<()> {
        std::fs::rename(temp, final_path)
    }

    fn fsync_dir(&self, dir: &Path) -> io::Result<()> {
        std::fs::File::open(dir)?.sync_all()
    }

    fn remove(&self, temp: &Path) {
        let _ = std::fs::remove_file(temp);
    }
}

#[cfg(test)]
mod tests;
