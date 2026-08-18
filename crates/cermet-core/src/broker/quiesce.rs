//! The MCP-repoint quiesce barrier.
//!
//! Before an operator repoints the registered MCP server binary (`cermet mcp install`), the daemon
//! must prove no NEW execution can begin under the old server and classify whether any in-flight or
//! recently-terminal execution leaves an agent-side child possibly still running. This module owns
//! the barrier state, the durable-record store seam, and the fail-closed classification.
//!
//! ## Ownership & serialization
//! The barrier lives IN the `Broker`, which is owned by the single broker-actor thread. Every
//! approved→executing claim funnels through [`Broker::enforce_quiesce_barrier`] at the top of
//! `claim_and_run`, and begin/end/status/reinstate all run on that same thread — so barrier
//! installation and claims are inherently serialized with no lock: a claim can never race a
//! begin.
//!
//! ## Durability & release ordering
//! The daemon injects a [`QuiesceStore`] that persists ONLY `sha256(token)` + a hard-bounded expiry
//! (never the raw token) in a mode-0600 record, fsynced BEFORE `begin` acks. Release — whether the
//! operator's `EndMcpRepoint`, the claim-path TTL recovery, or housekeeping — follows ONE order:
//! validate the token → unlink the record → fsync the parent dir → clear the in-memory barrier →
//! (the ctl layer then) ack. A failure at unlink or parent-fsync keeps claims blocked and durably
//! REFORGES the same record before returning an error, so a partial unlink can never reopen claims
//! and a restart still reinstates the barrier.
//!
//! ## Execution custody
//! A daemon-side deadline revokes lease AUTHORITY and records an unreported outcome, but cermetd
//! cannot signal a setsid child running under the agent uid, so it must NEVER infer that child is
//! gone. An executing lease past its deadline, or a swept/terminal lease with execution stamps but no
//! chain-verified report-based completion, is [`McpQuiesceStatus::OrphanAmbiguous`] — never Quiescent.

use crate::audit::VerifiedAuditSnapshot;
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

/// The minimum and maximum barrier TTL the daemon will honor. The floor keeps a fat-fingered tiny
/// TTL from making the barrier useless; the ceiling is the hard bound past which a crashed installer
/// can never wedge claims. The client's own drain budget must sit comfortably inside this window.
pub const MIN_BARRIER_TTL_SECS: i64 = 5;
pub const MAX_BARRIER_TTL_SECS: i64 = 30 * 60;
pub use cermet_lang::quiesce::{
    McpQuiesceStatus, McpRepointBegin, McpRepointStatusReport, QuiesceGrantNote,
};

/// The durable barrier record: `sha256(token)` + a hard-bounded wall-clock expiry. The raw token is
/// NEVER persisted — a reader of the on-disk record cannot forge an End/Status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedBarrier {
    pub token_hash: [u8; 32],
    pub expires_at: i64,
}

/// The daemon-owned durable store for the barrier record. Injected into the `Broker`; in-core tests
/// use an in-memory recorder that can inject faults at each ordered step. Every method is fail-closed:
/// a malformed/unverifiable record surfaces as `Err`, never a silently-absent barrier.
pub trait QuiesceStore: Send {
    /// Durably persist `record` — temp create+write+fsync → rename → parent-dir fsync — and return
    /// only AFTER the parent fsync. Used for both the initial begin and the release-failure reforge.
    fn write(&self, record: &PersistedBarrier) -> Result<()>;
    /// Load the persisted record, or `None` when absent. A present-but-malformed/unverifiable record
    /// is `Err` (fail closed): boot refuses and status/release surface the integrity fault.
    fn load(&self) -> Result<Option<PersistedBarrier>>;
    /// Release step (2): unlink the record file. `Ok` means the file is gone (an already-absent file
    /// is `Ok`); `Err` means the unlink may or may not have taken effect (the caller reforges).
    fn unlink(&self) -> Result<()>;
    /// Release step (3): fsync the record's parent directory so the unlink is durable.
    fn fsync_parent(&self) -> Result<()>;
}

/// The minimal per-grant projection the classifier needs (produced in `views.rs`).
pub(super) struct QuiesceGrantRow {
    pub id: String,
    pub integrity_ok: bool,
    pub status: String,
    pub lease_opened_at: Option<i64>,
    pub lease_deadline: Option<i64>,
}

fn sha256_hex_token(token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.finalize().into()
}

/// Mint an opaque 32-byte random token, hex-encoded (64 chars).
fn mint_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl super::Broker {
    fn now(&self) -> i64 {
        self.now_epoch()
    }

    /// After a release double-fault the durable mirror is unknown, so the broker is
    /// unrecoverably fail-closed. Every claim and barrier op consults this first; only a fresh boot
    /// (which reads the durable record) clears it.
    fn quiesce_poison_check(&self) -> Result<()> {
        if self.quiesce_poisoned.get() {
            return Err(Error::Provider(
                "MCP-repoint barrier is in an unrecoverable fail-closed state (a release could not be \
                 made durable); refusing all claims and barrier operations until cermetd is restarted"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Claim-path gate: refuse a NEW approved→executing claim while a barrier holds. A
    /// barrier whose hard-bounded TTL has lapsed is released here through the SAME durable ordering as
    /// `EndMcpRepoint` before the claim proceeds, so a crashed installer never wedges claims forever.
    pub(super) fn enforce_quiesce_barrier(&self) -> Result<()> {
        self.quiesce_poison_check()?;
        let expired = {
            let b = self.barrier.borrow();
            match b.as_ref() {
                None => return Ok(()),
                Some(rec) => self.now() > rec.expires_at,
            }
        };
        if expired {
            // TTL recovery through the ordered release, then admit the claim.
            self.release_barrier_durably()?;
            return Ok(());
        }
        Err(Error::TemporaryQuiesce(
            "the daemon is quiescing for an MCP-server repoint; retry the request shortly".into(),
        ))
    }

    /// Enter the barrier and return the one token + instance id. Refuses if a live (unexpired) barrier
    /// already exists — only one token may exist. Durably persists `sha256(token)` + expiry BEFORE the
    /// in-memory barrier is installed (and thus before the ack), so a crash after the durable write
    /// leaves a claim-blocking barrier that TTL-recovers rather than a lost one.
    pub fn begin_mcp_repoint(&self, ttl_secs: i64) -> Result<McpRepointBegin> {
        self.quiesce_poison_check()?;
        // A stale (expired) barrier is released first; a live one refuses.
        let existing_live = {
            let b = self.barrier.borrow();
            b.as_ref().map(|rec| self.now() <= rec.expires_at)
        };
        match existing_live {
            Some(true) => return Err(Error::Denied(
                "an MCP-repoint barrier is already active; end it (or wait for its TTL) before \
                     beginning another"
                    .into(),
            )),
            Some(false) => self.release_barrier_durably()?,
            None => {}
        }
        let ttl = ttl_secs.clamp(MIN_BARRIER_TTL_SECS, MAX_BARRIER_TTL_SECS);
        let token = mint_token();
        let rec = PersistedBarrier {
            token_hash: sha256_hex_token(&token),
            expires_at: self.now() + ttl,
        };
        if let Some(store) = self.quiesce_store.as_ref() {
            store.write(&rec)?; // durable BEFORE ack
        }
        let expires_at = rec.expires_at;
        *self.barrier.borrow_mut() = Some(rec);
        Ok(McpRepointBegin {
            token,
            instance_id: self.instance_id.clone(),
            expires_at,
        })
    }

    /// Classify custody under the barrier (holder-only). Verifies the token, refuses if the barrier is
    /// absent or its TTL has lapsed (the client then refuses/retries — a lapsed barrier no longer
    /// blocks new claims, so its classification is not stable). Reads every grant through the HMAC path
    /// and folds in verified terminal audit evidence.
    pub fn mcp_repoint_status(&self, token: &str) -> Result<McpRepointStatusReport> {
        self.quiesce_poison_check()?;
        self.validate_barrier_token(token)?;
        let rows = self.load_quiesce_rows()?;
        let audit = self
            .audit
            .verified_snapshot()
            .unwrap_or_else(|_| VerifiedAuditSnapshot::unverified());
        Ok(McpRepointStatusReport {
            instance_id: self.instance_id.clone(),
            status: classify_quiesce(self.now(), &rows, &audit),
        })
    }

    /// End the barrier (holder-only): validate the token, then release through the ordered durable
    /// path. On a release-command failure the token stays live for retry/TTL recovery.
    pub fn end_mcp_repoint(&self, token: &str) -> Result<()> {
        self.quiesce_poison_check()?;
        self.validate_barrier_token(token)?;
        self.release_barrier_durably()
    }

    /// Housekeeping / boot hook: release a barrier whose TTL has lapsed through the ordered path.
    /// Returns whether a release occurred.
    pub fn release_expired_barrier(&self) -> Result<bool> {
        let expired = {
            let b = self.barrier.borrow();
            b.as_ref().map(|rec| self.now() > rec.expires_at)
        };
        match expired {
            Some(true) => {
                self.release_barrier_durably()?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Boot reinstatement: adopt any durable barrier record BEFORE serving either socket. A malformed
    /// record is `Err` (boot fails closed). A present record — even an expired one — reinstates the
    /// in-memory barrier so claims stay blocked; the runtime claim-gate / housekeeping releases an
    /// expired one through the ordered path. Called from `open_inner`.
    pub(super) fn reinstate_barrier_on_boot(&self) -> Result<()> {
        let Some(store) = self.quiesce_store.as_ref() else {
            return Ok(());
        };
        if let Some(rec) = store.load()? {
            *self.barrier.borrow_mut() = Some(rec);
        }
        Ok(())
    }

    fn validate_barrier_token(&self, token: &str) -> Result<()> {
        let rec = self
            .barrier
            .borrow()
            .clone()
            .ok_or_else(|| Error::Denied("no active MCP-repoint barrier".into()))?;
        if self.now() > rec.expires_at {
            return Err(Error::Denied(
                "the MCP-repoint barrier has expired; begin a new one".into(),
            ));
        }
        // Constant-time-ish compare on the fixed-length hash.
        if sha256_hex_token(token) != rec.token_hash {
            return Err(Error::Denied("MCP-repoint token mismatch".into()));
        }
        Ok(())
    }

    /// The exact ordered release shared by End, claim-path TTL recovery, and housekeeping:
    /// (2) unlink → (3) fsync parent → (4) clear the in-memory barrier. On failure at unlink or
    /// parent-fsync the in-memory barrier is LEFT installed (claims stay blocked) and the same record
    /// is durably reforged before returning an error, so a partial unlink can never reopen claims.
    fn release_barrier_durably(&self) -> Result<()> {
        let rec = match self.barrier.borrow().clone() {
            Some(r) => r,
            None => return Ok(()),
        };
        if let Some(store) = self.quiesce_store.as_ref() {
            // (2) unlink
            if let Err(unlink_err) = store.unlink() {
                // The unlink may have taken effect — reforge to a known durable state, stay blocked.
                // If the compensating reforge ALSO fails, the durable mirror is unknown —
                // poison the broker into an unrecoverable fail-closed state (no claims served without
                // a durable record a restart could reinstate).
                if let Err(write_err) = store.write(&rec) {
                    self.quiesce_poisoned.set(true);
                    return Err(Error::Provider(format!(
                        "MCP-repoint barrier release DOUBLE-FAULTED (unlink failed: {unlink_err}; and \
                         the compensating reforge failed: {write_err}); the durable record is unknown \
                         — the broker is now in an unrecoverable fail-closed state and serves no claims until \
                         cermetd restarts"
                    )));
                }
                return Err(Error::Provider(format!(
                    "MCP-repoint barrier release failed at unlink ({unlink_err}); the barrier record \
                     was reforged and claims remain blocked — retry End or wait for the TTL"
                )));
            }
            // (3) fsync parent
            if let Err(fsync_err) = store.fsync_parent() {
                // The unlink took effect but is not durable — reforge, stay blocked. Same double-fault
                // poison rule as above.
                if let Err(write_err) = store.write(&rec) {
                    self.quiesce_poisoned.set(true);
                    return Err(Error::Provider(format!(
                        "MCP-repoint barrier release DOUBLE-FAULTED (parent fsync failed: {fsync_err}; \
                         and the compensating reforge failed: {write_err}); the durable record is \
                         unknown — the broker is now in an unrecoverable fail-closed state and serves no claims \
                         until cermetd restarts"
                    )));
                }
                return Err(Error::Provider(format!(
                    "MCP-repoint barrier release outcome unknown after unlink (parent fsync failed: \
                     {fsync_err}); the barrier record was reforged and claims remain blocked"
                )));
            }
        }
        // (4) clear the in-memory barrier — only after durable removal succeeded.
        *self.barrier.borrow_mut() = None;
        Ok(())
    }
}

/// Fold per-grant verdicts into ONE fail-closed classification. Precedence:
/// Integrity > Active > OrphanAmbiguous > Quiescent. Integrity always wins (never masked as safe or
/// drainable); Active is reported while genuine leases drain, and a coexisting orphan surfaces once
/// the actives clear — a deadline crossed while draining flips that lease to OrphanAmbiguous, never
/// to Quiescent.
pub(super) fn classify_quiesce(
    now: i64,
    rows: &[QuiesceGrantRow],
    audit: &VerifiedAuditSnapshot,
) -> McpQuiesceStatus {
    let mut integrity: Vec<QuiesceGrantNote> = Vec::new();
    let mut active: Vec<QuiesceGrantNote> = Vec::new();
    let mut orphan: Vec<QuiesceGrantNote> = Vec::new();
    let note = |id: &str, reason: &str| QuiesceGrantNote {
        grant_id: id.to_string(),
        reason: reason.to_string(),
    };
    let verified_complete = |id: &str| audit.verified && audit.terminal_outcomes.contains_key(id);
    for r in rows {
        if !r.integrity_ok {
            integrity.push(note(&r.id, "grant HMAC integrity failure"));
            continue;
        }
        match r.status.as_str() {
            "executing" => match (r.lease_opened_at, r.lease_deadline) {
                (Some(_), Some(deadline)) if now <= deadline => {
                    active.push(note(&r.id, "executing lease within its signed deadline"));
                }
                (Some(_), Some(_)) => {
                    orphan.push(note(
                        &r.id,
                        "executing lease reached/passed its signed deadline with no verified report",
                    ));
                }
                _ => integrity.push(note(
                    &r.id,
                    "executing grant is missing complete signed lease stamps",
                )),
            },
            "executed" => {
                if !audit.verified {
                    integrity.push(note(
                        &r.id,
                        "audit chain unverified; cannot prove terminal completion",
                    ));
                } else if audit.terminal_outcomes.contains_key(&r.id) {
                    // verified terminal completion → counts toward Quiescent
                } else {
                    orphan.push(note(
                        &r.id,
                        "executed grant lacks verified terminal completion (transport-ambiguous)",
                    ));
                }
            }
            // Any terminal / other status (expired, swept, denied, requested, approved): the question
            // is whether execution BEGAN. A lease-open stamp proves a plan was handed to the agent.
            _ => {
                if r.lease_opened_at.is_some() && !verified_complete(&r.id) {
                    orphan.push(note(
                        &r.id,
                        "swept/terminal lease carries execution stamps but no verified report-based \
                         completion",
                    ));
                }
                // else: execution never began (never-claimed / expired-before-claim) → Quiescent.
            }
        }
    }
    if !integrity.is_empty() {
        return McpQuiesceStatus::Integrity {
            reason: "one or more grants failed integrity verification".into(),
            grants: integrity,
        };
    }
    if !active.is_empty() {
        return McpQuiesceStatus::Active { grants: active };
    }
    if !orphan.is_empty() {
        return McpQuiesceStatus::OrphanAmbiguous { grants: orphan };
    }
    McpQuiesceStatus::Quiescent
}
