//! Append-only, HMAC-chained audit log.

use hmac::{Hmac, Mac};
use rusqlite::{params, Connection};
use serde_json::Value;
use sha2::Sha256;

use crate::error::Result;
use crate::redaction::redacted;
use crate::types::AuditEventView;
use crate::util::{hex, new_id, now_rfc3339};

type HmacSha256 = Hmac<Sha256>;

/// The data-payload marker for an audit row whose `data_json` no longer parses: the
/// degraded view fetch replaces the unreadable payload with `{ this-key: true }` — an explicit,
/// render-visible placeholder, never a silent skip. No broker write path ever authors this key.
pub const UNPARSEABLE_EVENT_DATA_KEY: &str = "unparseable_data_json";

pub struct AuditLog {
    conn: Connection,
    key: Vec<u8>,
    /// Test-only count of ordered end-to-end HMAC-chain passes.
    #[cfg(any(test, feature = "test-double"))]
    verification_passes: std::cell::Cell<usize>,
    /// Test-only single-shot fault injector: when set to an event type, the NEXT `record` of that
    /// type returns an error instead of writing (then clears). Used to prove the audit-first ordering
    /// of the shell finalize — a mid-finalize audit-write failure must leave neither a consumed grant
    /// nor an unchained artifact row. `cfg(test)` only; absent from production builds.
    #[cfg(test)]
    fail_next_type: std::cell::RefCell<Option<String>>,
}

/// One raw `budget_mint`/`budget_release` row loaded for the budget gate — the rowid (its position in
/// the immutable log), the event id, its type, and the parsed `data` payload. Assembled into the pure
/// `crate::budget::AggregateLedgerEvent` by `broker::budget`.
#[derive(Debug, Clone)]
pub struct BudgetLedgerRow {
    pub rowid: i64,
    pub event_id: String,
    pub event_type: String,
    pub data: Value,
}

pub(crate) struct MoneyRetryAuditEvents {
    pub events: Vec<MoneyRetryAuditEvent>,
}

pub(crate) struct MoneyRetryAuditEvent {
    pub rowid: i64,
    pub session_id: Option<String>,
    pub event_type: String,
    pub data: Value,
}

pub(crate) struct ExecutionAuditEvent {
    pub event_type: String,
    pub data: Value,
}

/// One chain-verified relay event. It keeps `ts` because both relay surfaces render
/// WHEN a hop happened — an operator diagnosing a burn is reading a timeline.
/// What ONE recorded event says about a grant's effect.
///
/// THREE states, not two. A success is a STATEMENT about the effect, and a projection
/// that only ever recorded failures had no way to express one: the class of a superseded attempt
/// stood forever. The vercel CLI's own deploy protocol posts the deployment create twice — the first
/// is answered `400 missing files`, which is how its upload negotiation starts, and the second, after
/// the files are uploaded, is the deployment that lands — so every landed deploy reported
/// `provider_input_refused` on the operator's receipt row, while a
/// deploy whose effect never reached the provider at all reported nothing.
enum EffectVerdict {
    /// This event says nothing about the grant's effect: a read hop, a session opening, a row whose
    /// typed values are absent or will not parse.
    Silent,
    /// The grant's effect-bearing hop ANSWERED successfully. The effect landed.
    Landed,
    /// The effect failed, with the class the record supports.
    Failed(crate::types::EffectFailureClass),
}

/// The verdict ONE recorded event supports.
///
/// Pure over the row, and its only inputs are typed values the broker itself wrote: the class the
/// seam recorded, or the status integer the provider sent. No message, body, or reason string is
/// read here, and an event carrying neither is the residual `failed`, never a guess.
///
/// The recorded class is authoritative where it exists; the status is what classifies a row written
/// BEFORE the class existed. Those are not two rules — the status ranges the fallback uses are the
/// same [`crate::types::EffectFailureClass::of`] arm the seam itself used — so history classifies
/// exactly as today's writes do, and nothing had to be stored twice to make that true.
fn effect_verdict(event_type: &str, data: &Value) -> EffectVerdict {
    use crate::types::{EffectFailureClass, FailureSignal};
    let recorded = |data: &Value| {
        data.get("failure_class").map(|value| {
            // An unrecognized spelling fails closed to the residual rather than dropping the
            // failure on the floor.
            serde_json::from_value::<EffectFailureClass>(value.clone())
                .unwrap_or(EffectFailureClass::Failed)
        })
    };
    let is_effect_hop = |data: &Value| data.get("effect").and_then(Value::as_bool) == Some(true);
    match event_type {
        // The verb's own terminal failure. `result` is the executor's own failure envelope
        // (`{status, error}`, authored in `provider.rs`), so its status is the provider's typed
        // signal — never a key sniffed out of a provider's body.
        "provider_action_failed" => EffectVerdict::Failed(
            recorded(data)
                .or_else(|| {
                    let result = data.get("result")?.as_object()?;
                    result.get("error")?;
                    let status = u16::try_from(result.get("status")?.as_u64()?).ok()?;
                    (100..=599)
                        .contains(&status)
                        .then(|| EffectFailureClass::of(FailureSignal::HttpStatus(status)))
                })
                .unwrap_or(EffectFailureClass::Failed),
        ),
        // A relay hop that ANSWERED. Only the session's effect-bearing hops are the grant's effect;
        // a read hop's 404 is not this grant's outcome.
        "relay_request_forwarded" if is_effect_hop(data) => {
            let Some(status) = data
                .get("upstream_status")
                .and_then(Value::as_u64)
                .and_then(|status| u16::try_from(status).ok())
            else {
                return EffectVerdict::Silent;
            };
            if (200..300).contains(&status) {
                EffectVerdict::Landed
            } else {
                EffectVerdict::Failed(EffectFailureClass::of(FailureSignal::HttpStatus(status)))
            }
        }
        // A relay hop that never answered; the class was typed where it happened.
        "relay_request_failed" if is_effect_hop(data) => {
            EffectVerdict::Failed(recorded(data).unwrap_or(EffectFailureClass::Failed))
        }
        // The effect LANDED and its response contradicts what was approved. The hop it
        // rode in on answered 2xx, so nothing else about the record says the effect failed — this
        // row is the whole evidence, and the event type is itself the typed signal. It is written
        // AFTER the hop's own row and ends the session, so it is the last word by construction.
        "relay_outcome_mismatch" => EffectVerdict::Failed(EffectFailureClass::of(
            FailureSignal::ApprovedOutcomeContradicted,
        )),
        _ => EffectVerdict::Silent,
    }
}

pub(crate) struct RelayAuditEvent {
    pub at: String,
    pub event_type: String,
    pub data: Value,
}

/// One string field of an event's recorded data, by name. An event that never carried it simply has
/// none — nothing here reconstructs a field.
fn text(data: &Value, key: &str) -> Option<String> {
    data.get(key)
        .and_then(Value::as_str)
        .map(std::string::ToString::to_string)
}

/// What one grant's effect layer RECORDED — the raw material [`crate::types::EffectState`] is
/// derived from. Every member is an observation read off a row the broker already writes; none of it
/// is a conclusion, and none of it is stored in this shape.
#[derive(Debug, Default, Clone)]
pub(crate) struct EffectSignals {
    /// Whether any relay event names this grant at all. It separates the two effect layers: a relay
    /// verb's effect is a hop inside its window, a plain verb's effect is the daemon's own
    /// credentialed call.
    pub relay: bool,
    /// The deadline the approval set on the window (epoch seconds), as the session's own rows
    /// declare it.
    pub expires_at: Option<i64>,
    /// How many hops the window forwarded upstream.
    pub hops: u64,
    /// The stable reason word of the refusal that burned the session, when one did.
    pub burned: Option<String>,
    /// How the window ended, when a terminal record exists. `None` for a window still open — and
    /// also for one whose daemon restarted before it could close, which is why the clock is
    /// consulted too.
    pub closed: Option<String>,
    /// The last word an effect-bearing HOP recorded: `Some(true)` a 2xx, `Some(false)` a failure or
    /// a landed effect the approval's own outcome assertion contradicted.
    pub hop_landed: Option<bool>,
    /// The last word the grant's TERMINAL execution event recorded. For a relay verb this is the
    /// session being minted, never a deploy landing.
    pub terminal_landed: Option<bool>,
}

impl EffectSignals {
    /// The last word about the grant's own effect: the hop for a relay verb, the terminal execution
    /// event for every other. `None` when nothing recorded one either way.
    pub(crate) fn landed(&self) -> Option<bool> {
        if self.relay {
            self.hop_landed
        } else {
            self.terminal_landed
        }
    }
}

pub struct NewEvent<'a> {
    pub session_id: Option<&'a str>,
    pub event_type: &'a str,
    pub severity: &'a str,
    pub summary: &'a str,
    pub data: Value,
    /// Secrets to scrub from `data`/`summary` before persistence.
    pub secrets: &'a [String],
}

#[derive(Debug, serde::Serialize)]
pub struct IntegrityReport {
    pub event_count: u64,
    pub verified: bool,
    /// Content-free event-type counts from the same complete chain verification. The ctl operator
    /// surface uses count deltas to prove exact budget-ledger rows without opening daemon-owned
    /// SQLite; the agent wire still projects only the boolean `verified` result.
    pub event_types: std::collections::BTreeMap<String, u64>,
}

/// The independently-verified terminal result of a grant's execution, read from the tamper-evident
/// audit chain — NOT from the grant's `status` string (an HTTP grant CAS's to `executed` even on a
/// provider error, so status is not a truth of success). `ok` is true ONLY for a chained
/// `provider_action_succeeded`. The artifact and result are read from the SAME verified event, and
/// `result` is the bytes `redacted()` scrubbed at record time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalOutcome {
    pub ok: bool,
    pub artifact: Option<String>,
    pub result: Option<Value>,
}

/// One report request's audit evidence, derived while verifying the ordered chain exactly once.
/// Event-derived fields are populated only when the complete chain verifies end to end.
#[derive(Debug)]
pub(crate) struct VerifiedAuditSnapshot {
    pub verified: bool,
    pub terminal_outcomes: std::collections::HashMap<String, bool>,
}

impl VerifiedAuditSnapshot {
    pub(crate) fn unverified() -> Self {
        Self {
            verified: false,
            terminal_outcomes: std::collections::HashMap::new(),
        }
    }
}

impl AuditLog {
    pub fn open(path: &str, key: Vec<u8>) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA busy_timeout=5000;
             CREATE TABLE IF NOT EXISTS audit_events (
                rowid       INTEGER PRIMARY KEY AUTOINCREMENT,
                id          TEXT NOT NULL UNIQUE,
                session_id  TEXT,
                ts          TEXT NOT NULL,
                type        TEXT NOT NULL,
                severity    TEXT NOT NULL,
                summary     TEXT NOT NULL,
                data_json   TEXT NOT NULL,
                prev_hash   TEXT,
                event_hash  TEXT NOT NULL
             );",
        )?;
        Ok(Self {
            conn,
            key,
            #[cfg(any(test, feature = "test-double"))]
            verification_passes: std::cell::Cell::new(0),
            #[cfg(test)]
            fail_next_type: std::cell::RefCell::new(None),
        })
    }

    #[cfg(test)]
    pub(crate) fn tamper_first_event_for_test(&self) -> Result<()> {
        self.conn.execute(
            "UPDATE audit_events SET summary = summary || '-tampered' WHERE rowid = \
             (SELECT MIN(rowid) FROM audit_events)",
            [],
        )?;
        Ok(())
    }

    /// Test-only: arm a single-shot write fault on the next `record` of `event_type`.
    #[cfg(test)]
    pub(crate) fn fail_next_record_of(&self, event_type: &str) {
        *self.fail_next_type.borrow_mut() = Some(event_type.to_string());
    }

    pub fn record(&self, ev: NewEvent) -> Result<String> {
        self.record_with_ts(now_rfc3339(), ev)
    }

    /// As [`AuditLog::record`], but the stored `ts` is `epoch` rendered RFC3339 rather than a freshly
    /// sampled clock. The budget gate captures ONE `decision_at_epoch` before loading evidence and
    /// uses it for the `budget_mint`/`budget_denied` ts, so the mint's fixed calendar bucket and the
    /// reproduced proof cannot drift from the check's clock. The HMAC chain covers `ts`
    /// exactly as `record` does.
    pub fn record_at(&self, epoch: i64, ev: NewEvent) -> Result<String> {
        self.record_with_ts(crate::util::rfc3339_of_epoch(epoch), ev)
    }

    /// As [`AuditLog::record_at`], but forces TRUE power-loss durability for THIS append before it
    /// returns: the budget ledger runs WAL with `synchronous=NORMAL` (a commit survives a
    /// process crash via the OS page cache, but power loss can lose un-fsynced WAL frames). A
    /// `budget_mint` MUST be durable before the grant row is written — else power loss could lose the
    /// mint while keeping the grant (fail-OPEN over-budget). We raise `synchronous=FULL` around this one
    /// commit (fsyncing its WAL frames) and restore the prior level immediately — targeted to the money
    /// event, NOT a blanket audit-log slowdown.
    pub fn record_at_durable(&self, epoch: i64, ev: NewEvent) -> Result<String> {
        let prior: i64 = self
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))?;
        // synchronous=FULL (2): fsync the WAL on this commit so the append survives power loss.
        self.conn.pragma_update(None, "synchronous", 2)?;
        let result = self.record_with_ts(crate::util::rfc3339_of_epoch(epoch), ev);
        // Restore the prior level even on error — scoped durability, never a persistent FULL.
        let _ = self.conn.pragma_update(None, "synchronous", prior);
        result
    }

    /// Power-loss-durable append at the current clock. Provider evidence uses the same FULL WAL path
    /// as budget mints so a grant row can never outlive its prerequisite receipt.
    pub fn record_durable(&self, ev: NewEvent) -> Result<String> {
        self.record_at_durable(crate::util::now_epoch(), ev)
    }

    /// Durable append plus the event's authenticated chain hash. Evidence binds both this hash and
    /// the lookup id without changing the legacy canonical event/hash format.
    pub(crate) fn record_durable_with_hash(&self, ev: NewEvent) -> Result<(String, String)> {
        let id = self.record_durable(ev)?;
        let event_hash = self.conn.query_row(
            "SELECT event_hash FROM audit_events WHERE id=?1",
            params![id],
            |row| row.get(0),
        )?;
        Ok((id, event_hash))
    }

    fn record_with_ts(&self, ts: String, ev: NewEvent) -> Result<String> {
        #[cfg(test)]
        {
            let mut armed = self.fail_next_type.borrow_mut();
            if armed.as_deref() == Some(ev.event_type) {
                *armed = None;
                return Err(crate::error::Error::Integrity(
                    "injected audit write fault (test)".to_string(),
                ));
            }
        }
        let id = new_id("evt");
        let data = redacted_for_record(ev.data, ev.secrets);
        let summary = redact_summary(ev.summary, ev.secrets);
        let prev = self.latest_hash()?;
        let canonical = canonical_event(
            ev.session_id,
            &ts,
            ev.event_type,
            ev.severity,
            &summary,
            &data,
        );
        let hash = chain_hash(&self.key, prev.as_deref().unwrap_or(""), &canonical);
        self.conn.execute(
            "INSERT INTO audit_events (id, session_id, ts, type, severity, summary, data_json, prev_hash, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![id, ev.session_id, ts, ev.event_type, ev.severity, summary, data.to_string(), prev, hash],
        )?;
        Ok(id)
    }

    /// Recompute the chain and verify integrity.
    pub fn verify(&self) -> Result<IntegrityReport> {
        #[cfg(any(test, feature = "test-double"))]
        self.verification_passes
            .set(self.verification_passes.get() + 1);
        let mut stmt = self.conn.prepare(
            "SELECT session_id, ts, type, severity, summary, data_json, prev_hash, event_hash
             FROM audit_events ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
            ))
        })?;

        let mut prev = String::new();
        let mut verified = true;
        let mut count = 0u64;
        let mut event_types = std::collections::BTreeMap::new();
        for row in rows {
            let (session, ts, ty, sev, summary, data_json, prev_hash, event_hash) = row?;
            let data: Value = serde_json::from_str(&data_json)?;
            let canonical = canonical_event(session.as_deref(), &ts, &ty, &sev, &summary, &data);
            let expected = chain_hash(&self.key, &prev, &canonical);
            if prev_hash.unwrap_or_default() != prev || event_hash != expected {
                verified = false;
            }
            prev = event_hash.clone();
            count += 1;
            *event_types.entry(ty).or_insert(0) += 1;
        }
        Ok(IntegrityReport {
            event_count: count,
            verified,
            event_types,
        })
    }

    /// Verify the complete ordered chain and fold every event-derived report projection in the same
    /// pass. Any row decode, JSON parse, hash, or link anomaly discards all accumulated evidence.
    pub(crate) fn verified_snapshot(&self) -> Result<VerifiedAuditSnapshot> {
        #[cfg(any(test, feature = "test-double"))]
        self.verification_passes
            .set(self.verification_passes.get() + 1);
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, ts, type, severity, summary, data_json, prev_hash, event_hash
             FROM audit_events ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, String>(8)?,
            ))
        })?;

        let mut prev = String::new();
        let mut terminal_outcomes = std::collections::HashMap::new();

        for row in rows {
            let (
                id,
                session_id,
                ts,
                event_type,
                severity,
                summary,
                data_json,
                prev_hash,
                event_hash,
            ) = match row {
                Ok(row) => row,
                Err(_) => return Ok(VerifiedAuditSnapshot::unverified()),
            };
            let data: Value = match serde_json::from_str(&data_json) {
                Ok(data) => data,
                Err(_) => return Ok(VerifiedAuditSnapshot::unverified()),
            };
            let canonical = canonical_event(
                session_id.as_deref(),
                &ts,
                &event_type,
                &severity,
                &summary,
                &data,
            );
            let expected = chain_hash(&self.key, &prev, &canonical);
            if prev_hash.unwrap_or_default() != prev || event_hash != expected {
                return Ok(VerifiedAuditSnapshot::unverified());
            }
            prev = event_hash;

            let event = AuditEventView {
                id,
                session_id,
                ts,
                event_type,
                severity,
                summary,
                data,
            };
            if matches!(
                event.event_type.as_str(),
                "provider_action_succeeded" | "provider_action_failed"
            ) {
                if let Some(grant_id) = event.data.get("grant_id").and_then(Value::as_str) {
                    terminal_outcomes.insert(
                        grant_id.to_string(),
                        event.event_type == "provider_action_succeeded",
                    );
                }
            }
        }

        Ok(VerifiedAuditSnapshot {
            verified: true,
            terminal_outcomes,
        })
    }

    /// Ordered, redacted event rows for one session. Errors on the first row whose `data_json` no
    /// longer parses — the fail-closed posture for authority-adjacent consumers (the policy learner
    /// must never derive a suggestion from evidence it cannot read). The VIEW paths use
    /// [`events_for_session_degraded`](Self::events_for_session_degraded) instead.
    pub fn events_for_session(&self, session_id: &str) -> Result<Vec<AuditEventView>> {
        self.events_for_session_inner(session_id, false)
    }

    /// Like [`events_for_session`](Self::events_for_session), but degrades PER ROW instead of
    /// erroring the whole fetch: a row whose `data_json` no longer parses keeps its intact
    /// columns (id/session/ts/type/severity/summary) and carries the explicit
    /// `{UNPARSEABLE_EVENT_DATA_KEY: true}` payload — NEVER a silent skip (dropping an audit row
    /// from a timeline fabricates absence). The corrupt row also breaks the HMAC chain, so every
    /// consumer of this variant renders under `verified=false`. View paths only.
    pub fn events_for_session_degraded(&self, session_id: &str) -> Result<Vec<AuditEventView>> {
        self.events_for_session_inner(session_id, true)
    }

    fn events_for_session_inner(
        &self,
        session_id: &str,
        degrade: bool,
    ) -> Result<Vec<AuditEventView>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, ts, type, severity, summary, data_json
             FROM audit_events WHERE session_id = ?1 ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![session_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, session_id, ts, event_type, severity, summary, data_json) = row?;
            let data: Value = match serde_json::from_str(&data_json) {
                Ok(v) => v,
                Err(_) if degrade => {
                    serde_json::json!({ UNPARSEABLE_EVENT_DATA_KEY: true })
                }
                Err(e) => return Err(e.into()),
            };
            out.push(AuditEventView {
                id,
                session_id,
                ts,
                event_type,
                severity,
                summary,
                data,
            });
        }
        Ok(out)
    }

    /// Ordered, redacted event rows of one `event_type`, across all sessions — a type-scoped scan
    /// (the token-efficiency aggregation keys off the terminal `provider_action_*` events; the
    /// `artifact_read` trail reads back this way too). Read-only; the append-only chain is untouched.
    pub fn events_of_type(&self, event_type: &str) -> Result<Vec<AuditEventView>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, ts, type, severity, summary, data_json
             FROM audit_events WHERE type = ?1 ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![event_type], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, session_id, ts, event_type, severity, summary, data_json) = row?;
            let data: Value = serde_json::from_str(&data_json)?;
            out.push(AuditEventView {
                id,
                session_id,
                ts,
                event_type,
                severity,
                summary,
                data,
            });
        }
        Ok(out)
    }

    /// Whether a `contract_ratified` event for exactly this proposal id AND content hash has been
    /// recorded. A narrow read-only existence probe for the boot reconcile: staged
    /// template authority may only be published when its audit evidence exists — a 'ratified' state
    /// row alone is not proof, since state.db and audit.db are separate files. Ratifications are
    /// human-rare, so scanning the typed rows is fine; the append-only chain is untouched.
    pub fn contract_ratified_exists(&self, proposal_id: &str, content_hash: &str) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT data_json FROM audit_events WHERE type='contract_ratified'")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for row in rows {
            let data: Value = serde_json::from_str(&row?)?;
            if data.get("proposal_id").and_then(Value::as_str) == Some(proposal_id)
                && data.get("content_hash").and_then(Value::as_str) == Some(content_hash)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether the fully verified chain contains a terminal `provider_action_{succeeded,failed}` event
    /// for exactly this grant id. Used by audit-first shell finalize recovery: audit.db and
    /// state.db are separate files, so an interrupted finalize can leave the terminal event chained but
    /// the grant's `executing→executed` flip uncommitted. A re-sent report completes only that flip.
    pub fn provider_action_event_exists(&self, grant_id: &str) -> Result<bool> {
        Ok(self.verified_terminal_event(grant_id)?.is_some())
    }

    /// The one terminal provider event for a grant, only from a completely verified audit chain.
    pub(crate) fn verified_terminal_event(&self, grant_id: &str) -> Result<Option<Value>> {
        let mut events = self.verified_grant_events(
            grant_id,
            &["provider_action_succeeded", "provider_action_failed"],
        )?;
        if events.len() > 1 {
            return Err(crate::error::Error::Integrity(format!(
                "grant {grant_id} has duplicate terminal execution evidence"
            )));
        }
        Ok(events.pop().map(|(_, data)| data))
    }

    /// Ordered effect-start and terminal rows for one grant, returned after one complete audit chain
    /// verification (the chain is the operator-facing tamper-evidence the `audit-verify` surface
    /// sells). The broker does not re-validate these rows' schema or identity on top of this chain
    /// verification — that would be a second pass over the daemon's own writes.
    pub(crate) fn verified_execution_events(
        &self,
        grant_id: &str,
        request_id: &str,
    ) -> Result<Vec<ExecutionAuditEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT rowid, session_id, ts, type, severity, summary, data_json, prev_hash, event_hash
             FROM audit_events ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
            ))
        })?;
        let mut prev = String::new();
        let mut events = Vec::new();
        for row in rows {
            let (
                _rowid,
                session,
                ts,
                event_type,
                severity,
                summary,
                data_json,
                prev_hash,
                event_hash,
            ) = row?;
            let data: Value = serde_json::from_str(&data_json).map_err(|error| {
                crate::error::Error::Integrity(format!("audit event data is malformed: {error}"))
            })?;
            let canonical = canonical_event(
                session.as_deref(),
                &ts,
                &event_type,
                &severity,
                &summary,
                &data,
            );
            let expected = chain_hash(&self.key, &prev, &canonical);
            if prev_hash.unwrap_or_default() != prev || event_hash != expected {
                return Err(crate::error::Error::Integrity(
                    "audit chain failed verification".into(),
                ));
            }
            prev = event_hash;
            if !matches!(
                event_type.as_str(),
                "capability_effect_starting"
                    | "provider_action_succeeded"
                    | "provider_action_failed"
            ) {
                continue;
            }
            let claims_grant = data.get("grant_id").and_then(Value::as_str) == Some(grant_id);
            let claims_request = data.get("request_id").and_then(Value::as_str) == Some(request_id);
            if claims_grant || claims_request {
                events.push(ExecutionAuditEvent { event_type, data });
            }
        }
        Ok(events)
    }

    /// Every rowid-ordered start/terminal event that claims either the target grant or logical effect,
    /// after one complete chain verification pass. The caller validates exact event schemas and
    /// sequence; selecting on BOTH identities ensures a target-grant/wrong-effect or
    /// target-effect/missing-grant row cannot hide.
    pub(crate) fn verified_money_retry_events(
        &self,
        grant_id: &str,
        request_id: &str,
        effect_id: &str,
    ) -> Result<MoneyRetryAuditEvents> {
        let mut stmt = self.conn.prepare(
            "SELECT rowid, session_id, ts, type, severity, summary, data_json, prev_hash, event_hash
             FROM audit_events ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
            ))
        })?;
        let mut prev = String::new();
        let mut events = Vec::new();
        for row in rows {
            let (
                rowid,
                session,
                ts,
                event_type,
                severity,
                summary,
                data_json,
                prev_hash,
                event_hash,
            ) = row?;
            let data: Value = serde_json::from_str(&data_json).map_err(|error| {
                crate::error::Error::Integrity(format!("audit event data is malformed: {error}"))
            })?;
            let canonical = canonical_event(
                session.as_deref(),
                &ts,
                &event_type,
                &severity,
                &summary,
                &data,
            );
            let expected = chain_hash(&self.key, &prev, &canonical);
            if prev_hash.unwrap_or_default() != prev || event_hash != expected {
                return Err(crate::error::Error::Integrity(
                    "audit chain failed verification".into(),
                ));
            }
            prev = event_hash;

            if !matches!(
                event_type.as_str(),
                "capability_effect_starting"
                    | "provider_action_succeeded"
                    | "provider_action_failed"
            ) {
                continue;
            }
            let raw_grant_id = data.get("grant_id").and_then(Value::as_str);
            let claims_grant = raw_grant_id == Some(grant_id);
            let claims_request = data.get("request_id").and_then(Value::as_str) == Some(request_id);
            let claims_effect = data.get("effect_id").and_then(Value::as_str) == Some(effect_id);
            // Every exact-effect claimant reaches the broker. Only the broker can prove from HMAC-bound
            // grant ancestry that a different string grant id is a legitimate sibling; an unproved
            // claimant must remain relevant malformed evidence and fail closed.
            if !(claims_grant || claims_request || claims_effect) {
                continue;
            }
            events.push(MoneyRetryAuditEvent {
                rowid,
                session_id: session,
                event_type,
                data,
            });
        }
        Ok(MoneyRetryAuditEvents { events })
    }

    /// Verify the full chain, then return matching typed events by exact parsed `grant_id`. Unlike
    /// model-facing degraded views, an integrity consumer never turns a broken chain into absence.
    fn verified_grant_events(
        &self,
        grant_id: &str,
        event_types: &[&str],
    ) -> Result<Vec<(String, Value)>> {
        let mut stmt = self.conn.prepare(
            "SELECT session_id, ts, type, severity, summary, data_json, prev_hash, event_hash
             FROM audit_events ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
            ))
        })?;
        let mut prev = String::new();
        let mut found = Vec::new();
        for row in rows {
            let (session, ts, ty, sev, summary, data_json, prev_hash, event_hash) = row?;
            let data: Value = serde_json::from_str(&data_json).map_err(|error| {
                crate::error::Error::Integrity(format!("audit event data is malformed: {error}"))
            })?;
            let canonical = canonical_event(session.as_deref(), &ts, &ty, &sev, &summary, &data);
            let expected = chain_hash(&self.key, &prev, &canonical);
            if prev_hash.unwrap_or_default() != prev || event_hash != expected {
                return Err(crate::error::Error::Integrity(
                    "audit chain failed verification".into(),
                ));
            }
            prev = event_hash;
            if event_types.contains(&ty.as_str())
                && data.get("grant_id").and_then(Value::as_str) == Some(grant_id)
            {
                found.push((ty, data));
            }
        }
        Ok(found)
    }

    /// Every relay event, rowid-ordered (oldest first), after one complete chain
    /// verification — optionally narrowed to ONE grant. This is the single read both relay surfaces
    /// project: `cermet log <request_id>` (grant-scoped) and `cermet log --hops`
    /// (cross-session). Like every other integrity consumer here, a broken chain is an error, never
    /// an absence.
    pub(crate) fn verified_relay_events(
        &self,
        grant_id: Option<&str>,
    ) -> Result<Vec<RelayAuditEvent>> {
        const RELAY_EVENT_TYPES: &[&str] = &[
            "relay_session_opened",
            "relay_request_forwarded",
            "relay_request_refused",
            "relay_request_failed",
            // A hop the relay authorized, forwarded, and then found contradicted the approval. It
            // ends the session exactly as a burning refusal does, and it is the burn whose whole
            // value to an operator is the frozen-vs-observed pair on its own row — so the view a
            // burn is diagnosed from is precisely where it has to appear.
            "relay_outcome_mismatch",
            "relay_session_closed",
        ];
        let mut stmt = self.conn.prepare(
            "SELECT session_id, ts, type, severity, summary, data_json, prev_hash, event_hash
             FROM audit_events ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
            ))
        })?;
        let mut prev = String::new();
        let mut found = Vec::new();
        for row in rows {
            let (session, ts, ty, sev, summary, data_json, prev_hash, event_hash) = row?;
            let data: Value = serde_json::from_str(&data_json).map_err(|error| {
                crate::error::Error::Integrity(format!("audit event data is malformed: {error}"))
            })?;
            let canonical = canonical_event(session.as_deref(), &ts, &ty, &sev, &summary, &data);
            let expected = chain_hash(&self.key, &prev, &canonical);
            if prev_hash.unwrap_or_default() != prev || event_hash != expected {
                return Err(crate::error::Error::Integrity(
                    "audit chain failed verification".into(),
                ));
            }
            prev = event_hash;
            if !RELAY_EVENT_TYPES.contains(&ty.as_str()) {
                continue;
            }
            // An unauthenticated poke at the loopback port writes a refusal row with no grant at
            // all; it belongs in the cross-session log and never under someone's request.
            if grant_id.is_some() && data.get("grant_id").and_then(Value::as_str) != grant_id {
                continue;
            }
            found.push(RelayAuditEvent {
                at: ts,
                event_type: ty,
                data,
            });
        }
        Ok(found)
    }

    /// Every grant whose EFFECT failed, with the class the record supports — ONE
    /// type-scoped read for a whole receipt log, not a per-row join.
    ///
    /// Two sources, because an effect fails in two places. A verb's own hop fails on its terminal
    /// `provider_action_failed` row; a RELAY verb's terminal row is the session opening
    /// successfully, and the effect that failed is a hop the session marked `effect`. A
    /// terminal failure wins where a grant somehow has both — it is the closer record of the grant's
    /// own outcome.
    ///
    /// **Among a session's effect hops the LAST one decides, and a success decides too.**
    /// A session may make its effect attempt more than once — the vercel CLI's create/upload
    /// negotiation is answered `400 missing files` before the create that lands — so a projection
    /// that only ever wrote failures reported every landed deploy as `provider_input_refused`,
    /// forever, on the receipt row, which reads this same field. A landed
    /// hop now CLEARS the class its superseded attempt left, and a refused last attempt still keeps
    /// its own.
    ///
    /// NOTE (accepted, not code): the same last-word rule is not applied across TERMINAL rows. A
    /// re-driven non-relay grant could in principle hold a `provider_action_failed` followed by a
    /// `provider_action_succeeded`; no such record has been observed, and the money path keeps its
    /// own verified disposition, so the terminal axis stays as it was rather than growing a branch
    /// for a case nothing on any box has produced.
    ///
    /// Deliberately NOT a chain-verification pass (the `events_of_type` precedent): this is a
    /// legibility projection, not a custody claim. Nothing here gates a retry, releases a budget, or
    /// authorizes anything — the money disposition keeps its verified read, and the receipt row is
    /// still rendered only when its own grant HMAC authenticates. A row whose data will not parse
    /// classifies nothing rather than failing the whole log; it never invents a class.
    pub(crate) fn effect_failure_classes(
        &self,
    ) -> Result<std::collections::HashMap<String, crate::types::EffectFailureClass>> {
        let mut stmt = self.conn.prepare(
            "SELECT type, data_json FROM audit_events
             WHERE type IN ('provider_action_failed', 'relay_request_forwarded',
                            'relay_request_failed', 'relay_outcome_mismatch')
             ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut terminal = std::collections::HashMap::new();
        // `None` is a landed effect: the entry EXISTS so a later read knows the last word was a
        // success, which is exactly what an insert-only map could not say.
        let mut hops: std::collections::HashMap<String, Option<crate::types::EffectFailureClass>> =
            std::collections::HashMap::new();
        for row in rows {
            let (event_type, data_json) = row?;
            let Ok(data) = serde_json::from_str::<Value>(&data_json) else {
                continue;
            };
            let Some(grant_id) = data.get("grant_id").and_then(Value::as_str) else {
                continue;
            };
            match effect_verdict(&event_type, &data) {
                EffectVerdict::Silent => continue,
                EffectVerdict::Failed(class) if event_type == "provider_action_failed" => {
                    terminal.insert(grant_id.to_string(), class);
                }
                // Rowid order, last write wins: the session's most recent statement about its own
                // effect is the grant's outcome.
                EffectVerdict::Failed(class) => {
                    hops.insert(grant_id.to_string(), Some(class));
                }
                EffectVerdict::Landed => {
                    hops.insert(grant_id.to_string(), None);
                }
            }
        }
        let mut classes: std::collections::HashMap<String, crate::types::EffectFailureClass> = hops
            .into_iter()
            .filter_map(|(grant_id, class)| class.map(|class| (grant_id, class)))
            .collect();
        classes.extend(terminal);
        Ok(classes)
    }

    /// The recorded SIGNALS each grant's effect layer left behind — ONE type-scoped read for a whole
    /// receipt log, the [`Self::effect_failure_classes`] shape.
    ///
    /// This returns observations only. It concludes nothing: whether a window that forwarded no hops
    /// and holds no terminal record is "in flight" or "expired unused" depends on a clock this read
    /// does not hold, and the view join that owns the clock draws that line
    /// ([`crate::types::EffectState`]). Nothing new is stored to make any of it answerable — every
    /// field below is read out of rows the broker was already writing.
    ///
    /// Deliberately NOT a chain-verification pass, for the [`Self::effect_failure_classes`] reason:
    /// this is a legibility projection, not a custody claim. Nothing here gates a retry, releases a
    /// budget, or authorizes anything, and the receipt row it feeds is still rendered only when its
    /// own grant HMAC authenticates. A row whose data will not parse contributes nothing rather than
    /// failing the whole log.
    pub(crate) fn effect_signals(
        &self,
    ) -> Result<std::collections::HashMap<String, EffectSignals>> {
        let mut stmt = self.conn.prepare(
            "SELECT type, data_json FROM audit_events
             WHERE type IN ('relay_session_opened', 'relay_request_forwarded',
                            'relay_request_refused', 'relay_request_failed',
                            'relay_session_closed', 'relay_outcome_mismatch',
                            'provider_action_succeeded', 'provider_action_failed')
             ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out: std::collections::HashMap<String, EffectSignals> =
            std::collections::HashMap::new();
        for row in rows {
            let (event_type, data_json) = row?;
            let Ok(data) = serde_json::from_str::<Value>(&data_json) else {
                continue;
            };
            let Some(grant_id) = data.get("grant_id").and_then(Value::as_str) else {
                continue;
            };
            let signals = out.entry(grant_id.to_string()).or_default();
            match event_type.as_str() {
                // The window's own two rows: the one that declares its deadline, and the one that
                // says it is over. Both carry `expires_at`, and it is the same number.
                "relay_session_opened" => {
                    signals.relay = true;
                    signals.expires_at = data.get("expires_at").and_then(Value::as_i64);
                }
                "relay_session_closed" => {
                    signals.relay = true;
                    signals.closed = text(&data, "closed");
                    if signals.expires_at.is_none() {
                        signals.expires_at = data.get("expires_at").and_then(Value::as_i64);
                    }
                    // The terminal receipt carries the burning refusal's reason word too. Read as a
                    // fallback for a session whose per-hop row this pass could not parse, never as
                    // an override: a session burns once, and the FIRST record of it is the hop.
                    if signals.burned.is_none() {
                        signals.burned = text(&data, "burned");
                    }
                }
                // Counted from the durable per-hop rows rather than from the closing receipt's own
                // tally, so a window with no terminal record (its daemon restarted) still reports
                // what it drove.
                "relay_request_forwarded" => {
                    signals.relay = true;
                    signals.hops = signals.hops.saturating_add(1);
                }
                "relay_request_refused" => {
                    signals.relay = true;
                    if signals.burned.is_none()
                        && data.get("burned").and_then(Value::as_bool) == Some(true)
                    {
                        signals.burned = text(&data, "reason");
                    }
                }
                "relay_outcome_mismatch" => {
                    signals.relay = true;
                    if signals.burned.is_none() {
                        signals.burned = Some("outcome_mismatch".to_string());
                    }
                }
                "relay_request_failed" => signals.relay = true,
                _ => {}
            }
            // The LAST word about the effect, rowid-ordered — the [`Self::effect_failure_classes`]
            // rule, and it must agree with it. A relay grant's terminal
            // `provider_action_succeeded` records the SESSION being minted, not a deploy landing, so
            // it is never read as the effect's outcome; the effect of a relay verb is its
            // effect-bearing hop and nothing else.
            match (event_type.as_str(), effect_verdict(&event_type, &data)) {
                ("provider_action_succeeded", _) => signals.terminal_landed = Some(true),
                ("provider_action_failed", _) => signals.terminal_landed = Some(false),
                (_, EffectVerdict::Landed) => signals.hop_landed = Some(true),
                (_, EffectVerdict::Failed(_)) => signals.hop_landed = Some(false),
                (_, EffectVerdict::Silent) => {}
            }
        }
        Ok(out)
    }

    /// When each grant's effect REACHED ITS END, from the terminal execution event's own `ts` — one
    /// type-scoped read for a whole receipt log, the [`Self::effect_failure_classes`] shape.
    ///
    /// The terminal event is the last `provider_action_succeeded`/`provider_action_failed` row a
    /// grant has, taken in rowid order so a recovered/re-driven run reports the end that actually
    /// happened last. A grant with no such row has no end, and the map simply has no entry: a run
    /// still in flight, a refusal that never ran, a grant that expired unspent.
    ///
    /// Deliberately NOT a chain-verification pass, for the [`Self::effect_failure_classes`] reason:
    /// this is a legibility projection, not a custody claim. Nothing gates on it — it feeds the
    /// receipt view's `terminal_at`, which is rendered and bucketed and authorizes nothing.
    pub(crate) fn effect_terminal_times(
        &self,
    ) -> Result<std::collections::HashMap<String, String>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, data_json FROM audit_events
             WHERE type IN ('provider_action_succeeded', 'provider_action_failed')
             ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut ends = std::collections::HashMap::new();
        for row in rows {
            let (ts, data_json) = row?;
            let Ok(data) = serde_json::from_str::<Value>(&data_json) else {
                continue;
            };
            let Some(grant_id) = data.get("grant_id").and_then(Value::as_str) else {
                continue;
            };
            // Later rows overwrite earlier ones: rowid order means the last write is the last end.
            ends.insert(grant_id.to_string(), ts);
        }
        Ok(ends)
    }

    /// The highest `rowid` in the append-only log right now (0 when empty). The budget gate captures
    /// this as the `evidence_through_rowid` prefix that bounds a decision's proof — a LATER release can
    /// never retroactively alter an EARLIER decision's reproduced number.
    pub fn max_rowid(&self) -> Result<i64> {
        let n: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(rowid), 0) FROM audit_events",
            [],
            |r| r.get(0),
        )?;
        Ok(n)
    }

    /// All `budget_mint`/`budget_release` events for one `aggregate_id`, rowid-ordered, with
    /// `rowid <= up_to_rowid` (the captured proof prefix). Read-only; the append-only chain is
    /// untouched. The window filter, digest checks, and SUM are the PURE `crate::budget::decide_aggregate`
    /// — this method only loads the bounded evidence the gate sums over.
    pub fn budget_ledger_events(
        &self,
        aggregate_id: &str,
        up_to_rowid: i64,
    ) -> Result<Vec<BudgetLedgerRow>> {
        Ok(self
            .budget_ledger_rows(up_to_rowid)?
            .into_iter()
            .filter(|row| {
                row.data.get("aggregate_id").and_then(Value::as_str) == Some(aggregate_id)
            })
            .collect())
    }

    /// A fixed-prefix snapshot of every budget event, available only after the complete current audit
    /// chain verifies. Retry admission uses the unfiltered rows to prove both exact parent-mint
    /// ownership and absence of a release that was mislabeled with another aggregate id.
    pub(crate) fn verified_budget_ledger_rows(
        &self,
        up_to_rowid: i64,
    ) -> Result<Vec<BudgetLedgerRow>> {
        if !self.verify()?.verified {
            return Err(crate::error::Error::Integrity(
                "budget ledger snapshot requires an intact audit chain".into(),
            ));
        }
        self.budget_ledger_rows(up_to_rowid)
    }

    fn budget_ledger_rows(&self, up_to_rowid: i64) -> Result<Vec<BudgetLedgerRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT rowid, id, type, data_json FROM audit_events \
              WHERE type IN ('budget_mint','budget_release') AND rowid <= ?1 ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![up_to_rowid], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (rowid, event_id, event_type, data_json) = row?;
            let data: Value = serde_json::from_str(&data_json)?;
            // A `budget_mint`/`budget_release` is an event WE authored; it always carries
            // a CANONICAL string `aggregate_id` (64 lowercase hex). An event of these types with an
            // absent/non-string id, OR a string id that is not canonical (`""`, wrong length, uppercase,
            // non-hex), is malformed OWN evidence — hard-error (fail closed), never `continue` (which
            // would read a corrupt mint as "no consumption" and admit over-cap). The syntax check runs
            // before callers select an aggregate, so a malformed id can never masquerade as foreign
            // evidence. A valid unequal id remains available to retry's cross-aggregate linkage check.
            match data.get("aggregate_id").and_then(Value::as_str) {
                None => {
                    return Err(crate::error::Error::Integrity(format!(
                        "budget ledger event {event_id} ({event_type}) has no valid aggregate_id"
                    )));
                }
                Some(id) if !crate::budget::is_canonical_aggregate_id(id) => {
                    return Err(crate::error::Error::Integrity(format!(
                        "budget ledger event {event_id} ({event_type}) has a malformed aggregate_id"
                    )));
                }
                Some(_) => {}
            }
            out.push(BudgetLedgerRow {
                rowid,
                event_id,
                event_type,
                data,
            });
        }
        Ok(out)
    }

    /// Whether a `budget_release` tombstone already exists for exactly this `mint_event_id`. The
    /// idempotence probe the release paths check BEFORE appending, so a retried terminalize (crash
    /// between the terminal flip and the release append) never double-tombstones a mint.
    pub fn budget_release_exists(&self, mint_event_id: &str) -> Result<bool> {
        let pattern = format!("%\"mint_event_id\":\"{mint_event_id}\"%");
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit_events WHERE type = 'budget_release' AND data_json LIKE ?1",
            params![pattern],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// The `(budget_mint event id, aggregate_id)` for a grant (if any), for the release paths that
    /// void a grant's own mint by `mint_event_id`. `None` means verified absence for a non-budget
    /// grant; broken, malformed, or duplicate evidence is an integrity error.
    pub fn budget_mint_ref_for_grant(&self, grant_id: &str) -> Result<Option<(String, String)>> {
        if !self.verify()?.verified {
            return Err(crate::error::Error::Integrity(
                "budget mint lookup requires an intact audit chain".into(),
            ));
        }
        let mut stmt = self.conn.prepare(
            "SELECT id, data_json FROM audit_events WHERE type = 'budget_mint' ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut found = None;
        for row in rows {
            let (event_id, data_json) = row?;
            let data: Value = serde_json::from_str(&data_json)?;
            if data.get("grant_id").and_then(Value::as_str) != Some(grant_id) {
                continue;
            }
            if found.is_some() {
                return Err(crate::error::Error::Integrity(format!(
                    "grant {grant_id} has duplicate budget mint evidence"
                )));
            }
            let aggregate_id = data
                .get("aggregate_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    crate::error::Error::Integrity(format!(
                        "grant {grant_id} has malformed budget mint evidence"
                    ))
                })?;
            found = Some((event_id, aggregate_id.to_string()));
        }
        Ok(found)
    }

    /// Whether this grant has a durable terminal record proving it was terminalized BEFORE any provider
    /// invocation: a `provider_action_failed` event carrying `mutation_invoked == false`
    /// (a vault-open failure or a post-claim/pre-egress authority refusal — no provider-side effect was
    /// possible). This authenticated fact lets the expiry sweep idempotently recover the `budget_release`
    /// a crash left un-appended between the status flip and the release. An abandoned `Executing` lease
    /// records `lease_abandoned` (not this), and an at/after-invocation failure records
    /// `mutation_invoked == true` — neither matches, so both correctly KEEP the debit.
    pub fn grant_terminated_before_invocation(&self, grant_id: &str) -> Result<bool> {
        let pattern = format!("%\"grant_id\":\"{grant_id}\"%");
        let mut stmt = self.conn.prepare(
            "SELECT data_json FROM audit_events WHERE type = 'provider_action_failed' \
             AND data_json LIKE ?1",
        )?;
        let rows = stmt.query_map(params![pattern], |r| r.get::<_, String>(0))?;
        for row in rows {
            let data: Value = serde_json::from_str(&row?)?;
            // Match this exact grant AND the trusted pre-invocation classification (fail closed: only an
            // explicit `false` earns a release; an absent/true field never does).
            if data.get("grant_id").and_then(Value::as_str) == Some(grant_id)
                && data.get("mutation_invoked").and_then(Value::as_bool) == Some(false)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Every live (un-released) `budget_mint` whose `expires_at_epoch < now` — the crash-orphan +
    /// unclaimed-budget-grant backstop: a mint whose grant never crossed the invocation boundary
    /// and whose TTL has lapsed. Returns `(mint_event_id, aggregate_id, grant_id, expires_at_epoch)`. A
    /// mint already tombstoned by a `budget_release` is excluded. Small-N local daemon; a scan is fine.
    ///
    /// The stored `expires_at_epoch` is NOT trusted — every returned mint is validated to
    /// carry a full, self-consistent epoch schema: `decision_at_epoch` present and non-negative, and
    /// the checked relationship `expires_at_epoch == decision_at_epoch + grant_ttl_secs`. A mint whose
    /// epoch schema is malformed/mismatched (a first-party corruption, or a mint whose expiry was
    /// tampered early) is SKIPPED — never returned as releasable (fail-closed: the sweep retains its
    /// debit rather than free a capacity a still-executable grant holds). The caller additionally
    /// proves a PRESENT grant's HMAC-covered expiry matches before releasing.
    pub fn expired_unreleased_budget_mints(
        &self,
        now: i64,
        grant_ttl_secs: i64,
    ) -> Result<Vec<(String, String, String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT m.id, m.data_json FROM audit_events m \
             WHERE m.type = 'budget_mint' \
             AND NOT EXISTS ( \
                 SELECT 1 FROM audit_events r WHERE r.type = 'budget_release' \
                 AND r.data_json LIKE '%\"mint_event_id\":\"' || m.id || '\"%') \
             ORDER BY m.rowid",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (event_id, data_json) = row?;
            let data: Value = serde_json::from_str(&data_json)?;
            let (Some(decision), Some(expires), Some(aggregate_id), Some(grant_id)) = (
                data.get("decision_at_epoch").and_then(Value::as_i64),
                data.get("expires_at_epoch").and_then(Value::as_i64),
                data.get("aggregate_id").and_then(Value::as_str),
                data.get("grant_id").and_then(Value::as_str),
            ) else {
                continue; // missing epoch/id ⇒ malformed ⇒ retain (never release).
            };
            // Full epoch-schema validation: non-negative decision + checked
            // `expires == decision + TTL`. Any mismatch ⇒ retain.
            if decision < 0 || decision.checked_add(grant_ttl_secs) != Some(expires) {
                continue;
            }
            if expires < now {
                out.push((
                    event_id,
                    aggregate_id.to_string(),
                    grant_id.to_string(),
                    expires,
                ));
            }
        }
        Ok(out)
    }

    /// True only when the verified chain contains the exact abandonment identity for this lease.
    /// A broken chain, duplicate event, or same-grant event with different signed fields is an
    /// integrity error, never textual evidence that suppresses the real abandonment record.
    pub fn lease_abandoned_event_exists(
        &self,
        grant_id: &str,
        request_id: &str,
        grant_digest: &str,
        lease_opened_at: Option<i64>,
        lease_deadline: Option<i64>,
    ) -> Result<bool> {
        let mut events = self.verified_grant_events(grant_id, &["lease_abandoned"])?;
        if events.len() > 1 {
            return Err(crate::error::Error::Integrity(format!(
                "grant {grant_id} has duplicate abandonment evidence"
            )));
        }
        let Some((_, data)) = events.pop() else {
            return Ok(false);
        };
        let identity_matches = data.get("request_id").and_then(Value::as_str) == Some(request_id)
            && data.get("grant_digest").and_then(Value::as_str) == Some(grant_digest)
            && data.get("lease_opened_at").and_then(Value::as_i64) == lease_opened_at
            && data.get("lease_deadline").and_then(Value::as_i64) == lease_deadline
            && data.get("outcome").and_then(Value::as_str) == Some("unreported");
        if !identity_matches {
            return Err(crate::error::Error::Integrity(format!(
                "grant {grant_id} abandonment evidence has the wrong lease identity"
            )));
        }
        Ok(true)
    }

    /// True when the grant's chained terminal event records a shutdown-CANCELED run:
    /// the persisted cancellation marker the idempotent-recovery path reads to know it must
    /// complete the RUN half (fail the operation, expire remaining step grants) before emitting
    /// the typed already-terminal proof.
    pub fn provider_action_event_canceled(&self, grant_id: &str) -> Result<bool> {
        let pattern = format!("%\"grant_id\":\"{grant_id}\"%");
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit_events \
             WHERE type IN ('provider_action_succeeded','provider_action_failed') \
             AND data_json LIKE ?1 AND data_json LIKE '%\"canceled\":true%'",
            params![pattern],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Every grant id that has a chained `provider_action_succeeded` event, harvested GLOBALLY (one
    /// scan over the typed rows, no per-session filter). The policy suggester keys off this
    /// success EVENT rather than a grant's raw `status` string: a grant's requesting and executing
    /// sessions can differ, and the two-phase shell finalize can leave the row at `executing` even
    /// after the terminal success event chained — a per-session or status-string join misses both.
    pub fn succeeded_grant_ids(&self) -> Result<std::collections::HashSet<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT data_json FROM audit_events WHERE type='provider_action_succeeded'")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = std::collections::HashSet::new();
        for row in rows {
            let data: Value = serde_json::from_str(&row?)?;
            if let Some(gid) = data.get("grant_id").and_then(Value::as_str) {
                out.insert(gid.to_string());
            }
        }
        Ok(out)
    }

    /// The most recent `capability_denied` reason (redacted summary) for this grant id, if any.
    /// Read-only; the summary is already secret-redacted at record time, so it is safe to
    /// surface as the request-status deny reason. `None` when the grant was never human-denied.
    pub fn capability_denied_reason(&self, grant_id: &str) -> Result<Option<String>> {
        let pattern = format!("%\"grant_id\":\"{grant_id}\"%");
        let mut stmt = self.conn.prepare(
            "SELECT summary FROM audit_events \
             WHERE type='capability_denied' AND data_json LIKE ?1 \
             ORDER BY rowid DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![pattern])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    /// The independently-verified terminal outcome of `grant_id` (the pipeline ordering gate's truth
    /// source). Walks the WHOLE chain from genesis, re-deriving each event's hash exactly as
    /// [`Self::verify`] does; an outcome is evidence ONLY off a chain that verifies end-to-end — a
    /// break ANYWHERE, even after the matching event, returns `None`, never a partial result. The
    /// LAST terminal `provider_action_{succeeded,failed}` event carrying this grant id
    /// yields the outcome. This is an EXACT JSON read (never a `data_json LIKE` scan — that
    /// anti-pattern cannot tell success from failure). Fail closed: absent, unparseable, or any chain
    /// break ⇒ `None`, which the gate treats as REFUSED (only `Some(ok == true)` advances a pipeline).
    pub fn terminal_outcome(&self, grant_id: &str) -> Result<Option<TerminalOutcome>> {
        let mut stmt = self.conn.prepare(
            "SELECT session_id, ts, type, severity, summary, data_json, prev_hash, event_hash
             FROM audit_events ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
            ))
        })?;
        let mut prev = String::new();
        let mut found: Option<TerminalOutcome> = None;
        for row in rows {
            let (session, ts, ty, sev, summary, data_json, prev_hash, event_hash) = row?;
            // ANY anomaly ANYWHERE in the scan — an unparseable event, a prev_hash gap, a
            // hash mismatch — invalidates the WHOLE log as evidence, including a success already
            // found BEFORE the break (a store writer could otherwise tamper any later row and keep an
            // earlier forged/real success trusted). Success is returned only off a chain that
            // verifies end-to-end. Fail closed: return None outright, never the partial result.
            let data: Value = match serde_json::from_str(&data_json) {
                Ok(d) => d,
                Err(_) => return Ok(None),
            };
            let canonical = canonical_event(session.as_deref(), &ts, &ty, &sev, &summary, &data);
            let expected = chain_hash(&self.key, &prev, &canonical);
            if prev_hash.unwrap_or_default() != prev || event_hash != expected {
                return Ok(None);
            }
            prev = event_hash;
            if (ty == "provider_action_succeeded" || ty == "provider_action_failed")
                && data.get("grant_id").and_then(Value::as_str) == Some(grant_id)
            {
                found = Some(TerminalOutcome {
                    ok: ty == "provider_action_succeeded",
                    artifact: data
                        .get("artifact")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    result: data.get("result").cloned(),
                });
            }
        }
        Ok(found)
    }

    /// The DURABLE terminal record for `grant_id` — the whole `data` payload of the LAST verified
    /// `provider_action_{succeeded,failed}` event carrying this grant. Same end-to-end chain
    /// re-derivation as [`Self::terminal_outcome`]: the record is evidence ONLY off a chain that
    /// verifies from genesis, so a store-side tamper anywhere invalidates it (`None`). This is what
    /// lets a background run's receipt be rebuilt from the audit bytes long after the in-process
    /// supervisor forgot it — never fabricated from grant status/clock.
    pub fn terminal_receipt(&self, grant_id: &str) -> Result<Option<Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT session_id, ts, type, severity, summary, data_json, prev_hash, event_hash
             FROM audit_events ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
            ))
        })?;
        let mut prev = String::new();
        let mut found: Option<Value> = None;
        for row in rows {
            let (session, ts, ty, sev, summary, data_json, prev_hash, event_hash) = row?;
            let data: Value = match serde_json::from_str(&data_json) {
                Ok(d) => d,
                Err(_) => return Ok(None),
            };
            let canonical = canonical_event(session.as_deref(), &ts, &ty, &sev, &summary, &data);
            let expected = chain_hash(&self.key, &prev, &canonical);
            if prev_hash.unwrap_or_default() != prev || event_hash != expected {
                return Ok(None);
            }
            prev = event_hash;
            if (ty == "provider_action_succeeded" || ty == "provider_action_failed")
                && data.get("grant_id").and_then(Value::as_str) == Some(grant_id)
            {
                found = Some(data);
            }
        }
        Ok(found)
    }

    /// The verified terminal outcome of EVERY grant that has a terminal
    /// `provider_action_{succeeded,failed}` event, harvested in ONE end-to-end chain
    /// re-derivation. The map is `grant_id → ok` for the LAST terminal event per grant. Fail closed
    /// exactly like [`Self::terminal_outcome`]: ANY anomaly anywhere in the scan — an
    /// unparseable event, a prev_hash gap, a hash mismatch — invalidates the WHOLE log as evidence
    /// and returns `None` (never a partial map trusted beside a broken chain). The report withholds
    /// its terminal-reason splits when this is `None`, mirroring the learned-section gate.
    pub fn verified_terminal_outcomes(
        &self,
    ) -> Result<Option<std::collections::HashMap<String, bool>>> {
        #[cfg(any(test, feature = "test-double"))]
        self.verification_passes
            .set(self.verification_passes.get() + 1);
        let mut stmt = self.conn.prepare(
            "SELECT session_id, ts, type, severity, summary, data_json, prev_hash, event_hash
             FROM audit_events ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
            ))
        })?;
        let mut prev = String::new();
        let mut out: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
        for row in rows {
            let (session, ts, ty, sev, summary, data_json, prev_hash, event_hash) = row?;
            let data: Value = match serde_json::from_str(&data_json) {
                Ok(d) => d,
                Err(_) => return Ok(None),
            };
            let canonical = canonical_event(session.as_deref(), &ts, &ty, &sev, &summary, &data);
            let expected = chain_hash(&self.key, &prev, &canonical);
            if prev_hash.unwrap_or_default() != prev || event_hash != expected {
                return Ok(None);
            }
            prev = event_hash;
            if ty == "provider_action_succeeded" || ty == "provider_action_failed" {
                if let Some(gid) = data.get("grant_id").and_then(Value::as_str) {
                    out.insert(gid.to_string(), ty == "provider_action_succeeded");
                }
            }
        }
        Ok(Some(out))
    }

    #[cfg(any(test, feature = "test-double"))]
    pub(crate) fn reset_verification_passes(&self) {
        self.verification_passes.set(0);
    }

    #[cfg(any(test, feature = "test-double"))]
    pub(crate) fn verification_passes(&self) -> usize {
        self.verification_passes.get()
    }

    fn latest_hash(&self) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1")?;
        let mut rows = stmt.query([])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }
}

/// The exact value-tree transform applied to every audit payload before it is chained. Callers that
/// persist a binding over a redacted projection use this first, then authenticate those final bytes.
pub(crate) fn redacted_for_record(value: Value, secrets: &[String]) -> Value {
    redacted(value, secrets)
}

fn redact_summary(summary: &str, secrets: &[String]) -> String {
    match redacted(Value::String(summary.to_string()), secrets) {
        Value::String(s) => s,
        _ => summary.to_string(),
    }
}

fn canonical_event(
    session: Option<&str>,
    ts: &str,
    ty: &str,
    sev: &str,
    summary: &str,
    data: &Value,
) -> String {
    let ev = serde_json::json!({
        "session_id": session,
        "ts": ts,
        "type": ty,
        "severity": sev,
        "summary": summary,
        "data": data,
    });
    canonical_json(&ev)
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonical_json(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        scalar => serde_json::to_string(scalar).unwrap(),
    }
}

fn chain_hash(key: &[u8], prev: &str, canonical: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(prev.as_bytes());
    mac.update(canonical.as_bytes());
    hex(mac.finalize().into_bytes().as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn log() -> AuditLog {
        AuditLog::open(":memory:", b"test-key".to_vec()).unwrap()
    }

    // Canonical (64 lowercase hex) aggregate ids for the budget-ledger tests.
    const CANON_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CANON_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// The terminal execution event is where an effect ENDED, and the projection reads the LAST one
    /// a grant has: a re-driven run's second terminal row is the end that actually happened. A grant
    /// that never reached a terminal row has no end at all, and gets no entry rather than a guess.
    #[test]
    fn the_terminal_times_are_the_last_terminal_event_per_grant() {
        let l = log();
        for (epoch, ty, grant) in [
            (1_785_000_001, "provider_action_succeeded", "g1"),
            (1_785_000_002, "provider_action_failed", "g2"),
            // g1 re-driven: the later row wins.
            (1_785_000_009, "provider_action_succeeded", "g1"),
            // An in-flight claim is not a terminal row and must add nothing.
            (1_785_000_010, "provider_action_started", "g3"),
        ] {
            l.record_at(
                epoch,
                NewEvent {
                    session_id: Some("s1"),
                    event_type: ty,
                    severity: "info",
                    summary: "x",
                    data: json!({ "grant_id": grant }),
                    secrets: &[],
                },
            )
            .unwrap();
        }

        let ends = l.effect_terminal_times().unwrap();
        assert_eq!(
            ends.get("g1").map(String::as_str),
            Some(crate::util::rfc3339_of_epoch(1_785_000_009).as_str())
        );
        assert_eq!(
            ends.get("g2").map(String::as_str),
            Some(crate::util::rfc3339_of_epoch(1_785_000_002).as_str())
        );
        assert_eq!(
            ends.get("g3"),
            None,
            "an unfinished run has no end: {ends:?}"
        );
    }

    #[test]
    fn clean_chain_verifies() {
        let l = log();
        for i in 0..3 {
            l.record(NewEvent {
                session_id: Some("s1"),
                event_type: "policy_decision",
                severity: "info",
                summary: "x",
                data: json!({ "decision": "allow", "i": i }),
                secrets: &[],
            })
            .unwrap();
        }
        let report = l.verify().unwrap();
        assert!(report.verified);
        assert_eq!(report.event_count, 3);
        assert_eq!(
            report.event_types,
            std::collections::BTreeMap::from([("policy_decision".to_string(), 3)])
        );
    }

    #[test]
    fn tampering_with_data_is_detected() {
        let l = log();
        l.record(NewEvent {
            session_id: Some("s1"),
            event_type: "policy_decision",
            severity: "info",
            summary: "x",
            data: json!({ "decision": "allow", "action": "deploy" }),
            secrets: &[],
        })
        .unwrap();
        l.record(NewEvent {
            session_id: Some("s1"),
            event_type: "noise",
            severity: "info",
            summary: "y",
            data: json!({}),
            secrets: &[],
        })
        .unwrap();

        l.conn
            .execute(
                "UPDATE audit_events SET data_json = ?1 WHERE rowid = 1",
                params![json!({ "decision": "deny", "action": "delete_project" }).to_string()],
            )
            .unwrap();

        assert!(
            !l.verify().unwrap().verified,
            "data tamper must break verification"
        );
    }

    #[test]
    fn events_for_session_scopes_and_orders_and_stays_redacted() {
        let l = log();
        let secret = "ghp_supersecrettoken1234567890".to_string();
        l.record(NewEvent {
            session_id: Some("s1"),
            event_type: "policy_decision",
            severity: "info",
            summary: "decide",
            data: json!({ "decision": "allow" }),
            secrets: &[],
        })
        .unwrap();
        l.record(NewEvent {
            session_id: Some("s2"),
            event_type: "policy_decision",
            severity: "info",
            summary: "a different session",
            data: json!({}),
            secrets: &[],
        })
        .unwrap();
        l.record(NewEvent {
            session_id: Some("s1"),
            event_type: "provider_action_succeeded",
            severity: "info",
            summary: "ran",
            data: json!({ "token": secret }),
            secrets: std::slice::from_ref(&secret),
        })
        .unwrap();

        let evs = l.events_for_session("s1").unwrap();
        assert_eq!(evs.len(), 2, "only s1's events, never s2's");
        assert_eq!(evs[0].event_type, "policy_decision");
        assert_eq!(
            evs[1].event_type, "provider_action_succeeded",
            "rowid insertion order preserved"
        );

        let dumped = serde_json::to_string(&evs).unwrap();
        assert!(
            !dumped.contains(&secret),
            "a scrubbed secret must never resurface via the read API"
        );

        assert!(l.events_for_session("ghost").unwrap().is_empty());
    }

    fn terminal_event(l: &AuditLog, grant_id: &str, ok: bool) {
        let data = json!({ "grant_id": grant_id });
        l.record(NewEvent {
            session_id: Some("s1"),
            event_type: if ok {
                "provider_action_succeeded"
            } else {
                "provider_action_failed"
            },
            severity: if ok { "info" } else { "high" },
            summary: "ran",
            data,
            secrets: &[],
        })
        .unwrap();
    }

    #[test]
    fn terminal_outcome_reads_exact_success_and_failure() {
        let l = log();
        terminal_event(&l, "g1", true);
        terminal_event(&l, "g2", false);
        assert_eq!(
            l.terminal_outcome("g1").unwrap(),
            Some(TerminalOutcome {
                ok: true,
                artifact: None,
                result: None
            })
        );
        assert_eq!(
            l.terminal_outcome("g2").unwrap(),
            Some(TerminalOutcome {
                ok: false,
                artifact: None,
                result: None
            }),
            "a failure event must NOT read as success (the LIKE-scan anti-pattern's bug)"
        );
    }

    #[test]
    fn terminal_outcome_absent_is_none() {
        let l = log();
        terminal_event(&l, "g1", true);
        assert_eq!(
            l.terminal_outcome("ghost").unwrap(),
            None,
            "no event ⇒ None (fail closed)"
        );
    }

    #[test]
    fn terminal_outcome_past_a_chain_break_is_none() {
        let l = log();
        // A benign event, then the grant's success — but tamper the FIRST event so the chain breaks
        // BEFORE the success event. The success is now unreachable trusted evidence ⇒ None.
        l.record(NewEvent {
            session_id: Some("s1"),
            event_type: "policy_decision",
            severity: "info",
            summary: "x",
            data: json!({ "decision": "allow" }),
            secrets: &[],
        })
        .unwrap();
        terminal_event(&l, "g1", true);
        assert_eq!(
            l.terminal_outcome("g1").unwrap(),
            Some(TerminalOutcome {
                ok: true,
                artifact: None,
                result: None
            })
        );
        l.conn
            .execute(
                "UPDATE audit_events SET data_json = ?1 WHERE rowid = 1",
                params![json!({ "decision": "deny" }).to_string()],
            )
            .unwrap();
        assert!(!l.verify().unwrap().verified, "the tamper breaks the chain");
        assert_eq!(
            l.terminal_outcome("g1").unwrap(),
            None,
            "a success event only reachable past a chain break must NOT be trusted (fail closed)"
        );
    }

    #[test]
    fn verified_terminal_outcomes_maps_grants_and_withholds_on_a_broken_chain() {
        // One clean pass over the chain yields grant_id → ok for the LAST
        // terminal event per grant; a chain break ANYWHERE withholds the WHOLE map (fail closed).
        let l = log();
        terminal_event(&l, "g_ok", true);
        terminal_event(&l, "g_bad", false);
        let map = l
            .verified_terminal_outcomes()
            .unwrap()
            .expect("a clean chain yields the map");
        assert_eq!(map.get("g_ok"), Some(&true));
        assert_eq!(map.get("g_bad"), Some(&false));
        assert_eq!(
            map.get("g_never"),
            None,
            "a grant with no terminal event is absent (⇒ ambiguous)"
        );
        // Tamper the first row → the chain no longer verifies end-to-end ⇒ the map is withheld.
        l.conn
            .execute(
                "UPDATE audit_events SET data_json = ?1 WHERE rowid = 1",
                params![json!({ "forged": true }).to_string()],
            )
            .unwrap();
        assert!(!l.verify().unwrap().verified, "the tamper breaks the chain");
        assert_eq!(
            l.verified_terminal_outcomes().unwrap(),
            None,
            "a broken chain withholds the whole map (fail closed), never a partial trusted result"
        );
    }

    #[test]
    fn terminal_outcome_with_a_chain_break_after_the_success_is_none() {
        // A success recorded BEFORE a later chain break must not be returned — a broken log
        // is not trusted evidence anywhere. Success only off a FULLY verified chain.
        let l = log();
        terminal_event(&l, "g1", true);
        l.record(NewEvent {
            session_id: Some("s1"),
            event_type: "noise",
            severity: "info",
            summary: "later event",
            data: json!({}),
            secrets: &[],
        })
        .unwrap();
        // Tamper the LATER event (after the success).
        l.conn
            .execute(
                "UPDATE audit_events SET data_json = ?1 WHERE rowid = (SELECT MAX(rowid) FROM audit_events)",
                params![json!({ "forged": true }).to_string()],
            )
            .unwrap();
        assert!(!l.verify().unwrap().verified, "the tamper breaks the chain");
        assert_eq!(
            l.terminal_outcome("g1").unwrap(),
            None,
            "a chain break ANYWHERE in the scan invalidates the outcome (fail closed)"
        );
    }

    #[test]
    fn budget_mint_without_aggregate_id_hard_errors() {
        // A budget_mint we authored always carries a string aggregate_id. One MISSING it is
        // malformed OWN evidence — `budget_ledger_events` must hard-error (fail closed), NOT `continue`
        // (which would read the corrupt mint as no consumption and admit over-cap).
        let l = log();
        l.record(NewEvent {
            session_id: Some("s1"),
            event_type: "budget_mint",
            severity: "info",
            summary: "x",
            // No aggregate_id at all.
            data: json!({ "grant_id": "g1", "debit": 10, "resolution_digest": "R", "decision_at_epoch": 5 }),
            secrets: &[],
        })
        .unwrap();
        let err = l
            .budget_ledger_events("A", l.max_rowid().unwrap())
            .unwrap_err();
        assert!(
            matches!(err, crate::error::Error::Integrity(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn budget_mint_with_nonstring_aggregate_id_hard_errors() {
        let l = log();
        l.record(NewEvent {
            session_id: Some("s1"),
            event_type: "budget_mint",
            severity: "info",
            summary: "x",
            data: json!({ "aggregate_id": 12345, "grant_id": "g1", "debit": 10 }),
            secrets: &[],
        })
        .unwrap();
        let err = l
            .budget_ledger_events("A", l.max_rowid().unwrap())
            .unwrap_err();
        assert!(
            matches!(err, crate::error::Error::Integrity(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn record_at_durable_records_then_restores_the_prior_synchronous_level() {
        // The durable budget_mint append raises synchronous=FULL for the one commit, then
        // restores the prior level — scoped power-loss durability, never a persistent blanket slowdown.
        let l = log();
        let prior: i64 = l
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        let id = l
            .record_at_durable(
                42,
                NewEvent {
                    session_id: Some("s1"),
                    event_type: "budget_mint",
                    severity: "info",
                    summary: "x",
                    data: json!({ "aggregate_id": CANON_A, "grant_id": "g1", "debit": 10, "resolution_digest": "R", "decision_at_epoch": 42, "expires_at_epoch": 642 }),
                    secrets: &[],
                },
            )
            .unwrap();
        assert!(
            id.starts_with("evt"),
            "the durable append still returns the event id"
        );
        let after: i64 = l
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            after, prior,
            "synchronous is restored — no blanket FULL slowdown"
        );
        // The event is present and readable as ledger evidence.
        let events = l
            .budget_ledger_events(CANON_A, l.max_rowid().unwrap())
            .unwrap();
        assert_eq!(events.len(), 1);
        assert!(
            l.verify().unwrap().verified,
            "the durable append keeps the chain intact"
        );
    }

    #[test]
    fn budget_mint_for_a_different_aggregate_is_skipped_not_errored() {
        // A VALID CANONICAL, unequal aggregate_id is a different aggregate's evidence — correctly skipped.
        let l = log();
        l.record(NewEvent {
            session_id: Some("s1"),
            event_type: "budget_mint",
            severity: "info",
            summary: "x",
            data: json!({ "aggregate_id": CANON_B, "grant_id": "g1", "debit": 10 }),
            secrets: &[],
        })
        .unwrap();
        let events = l
            .budget_ledger_events(CANON_A, l.max_rowid().unwrap())
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn expired_unreleased_skips_malformed_epoch_mints() {
        // The sweep query validates the full epoch schema (non-negative decision, checked
        // `expires == decision + TTL`) and skips (retains) any mint that fails it — never trusting a
        // tampered/early `expires_at_epoch` to free a still-executable grant's capacity.
        let ttl = 600;
        let mint = |l: &AuditLog, decision: i64, expires: i64, grant: &str| {
            l.record(NewEvent {
                session_id: Some("s1"),
                event_type: "budget_mint",
                severity: "info",
                summary: "x",
                data: json!({
                    "aggregate_id": CANON_A, "grant_id": grant, "debit": 10,
                    "resolution_digest": "R", "decision_at_epoch": decision, "expires_at_epoch": expires
                }),
                secrets: &[],
            })
            .unwrap();
        };

        // Valid: decision 100, expires 700 (== 100+600), now 800 ⇒ returned.
        let l = log();
        mint(&l, 100, 700, "g_ok");
        let got = l.expired_unreleased_budget_mints(800, ttl).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].3, 700,
            "the validated expiry is returned to the sweep"
        );

        // Tampered-early expires (NEW-1): decision 100 but expires 99 (!= 100+600) ⇒ skipped (retain).
        let l = log();
        mint(&l, 100, 99, "g_early");
        assert!(l
            .expired_unreleased_budget_mints(800, ttl)
            .unwrap()
            .is_empty());

        // Negative decision epoch ⇒ skipped (retain).
        let l = log();
        mint(&l, -1, -1 + ttl, "g_neg");
        assert!(l
            .expired_unreleased_budget_mints(800, ttl)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn budget_mint_with_malformed_string_aggregate_id_hard_errors() {
        // An invalid-but-string aggregate_id ("" / wrong length / uppercase) is malformed OWN
        // evidence — hard-error BEFORE the unequal-id skip, never read as a foreign (skippable) id.
        for bad in [
            "",
            "A",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let l = log();
            l.record(NewEvent {
                session_id: Some("s1"),
                event_type: "budget_mint",
                severity: "info",
                summary: "x",
                data: json!({ "aggregate_id": bad, "grant_id": "g1", "debit": 10 }),
                secrets: &[],
            })
            .unwrap();
            let err = l
                .budget_ledger_events(CANON_A, l.max_rowid().unwrap())
                .unwrap_err();
            assert!(
                matches!(err, crate::error::Error::Integrity(_)),
                "id {bad:?}: got {err:?}"
            );
        }
    }
}
