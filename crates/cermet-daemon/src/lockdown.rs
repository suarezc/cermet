//! Durable independent owner lockdown latch.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::Arc;
use std::sync::Mutex;

use cermet_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const VERSION: u32 = 1;
const BOOTSTRAP_OCCURRENCE: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const LATCH_EFFECTIVE_ENGAGED: usize = 1;
const LATCH_PENDING_ONE: usize = 2;
const LATCH_MAX_PENDING: usize = usize::MAX >> 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockdownRecord {
    version: u32,
    engaged: bool,
    occurrence_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockdownIntent {
    pub version: u32,
    pub occurrence_id: String,
    pub target_engaged: bool,
    pub prior_record_digest: Option<String>,
    pub operator_uid: u32,
    pub acceptance_path: String,
    pub confirmed: bool,
    pub delivered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LockdownOutcome {
    pub engaged: bool,
    pub occurrence_id: String,
}

pub trait LockdownAuditSink {
    fn record_transition(&self, intent: &LockdownIntent) -> Result<()>;
}

#[cfg(test)]
type TransitionHook = Arc<dyn Fn(bool) + Send + Sync>;
#[cfg(test)]
type FaultHook = Arc<dyn Fn() -> Result<()> + Send + Sync>;

pub struct LockdownStore {
    record_path: PathBuf,
    outbox_dir: PathBuf,
    expected_owner_uid: u32,
    latch_state: AtomicUsize,
    lock: Mutex<LockdownState>,
    #[cfg(test)]
    prelock_hook: Mutex<Option<TransitionHook>>,
    #[cfg(test)]
    record_parent_sync_hook: Mutex<Option<FaultHook>>,
    #[cfg(test)]
    audit_delivery_write_hook: Mutex<Option<FaultHook>>,
}

#[derive(Default)]
struct LockdownState {
    audit_in_flight: HashSet<String>,
}

impl LockdownStore {
    pub fn new(state_dir: &Path, expected_owner_uid: u32) -> Self {
        Self {
            record_path: Self::record_path(state_dir),
            outbox_dir: Self::outbox_dir(state_dir),
            expected_owner_uid,
            latch_state: AtomicUsize::new(LATCH_EFFECTIVE_ENGAGED),
            lock: Mutex::new(LockdownState::default()),
            #[cfg(test)]
            prelock_hook: Mutex::new(None),
            #[cfg(test)]
            record_parent_sync_hook: Mutex::new(None),
            #[cfg(test)]
            audit_delivery_write_hook: Mutex::new(None),
        }
    }

    pub fn record_path(state_dir: &Path) -> PathBuf {
        state_dir.join("lockdown.record")
    }

    pub fn outbox_dir(state_dir: &Path) -> PathBuf {
        state_dir.join("lockdown.audit_pending")
    }

    /// Install/bootstrap operation. Runtime never calls this: after installation, absence is engaged.
    pub fn initialize_clear(state_dir: &Path, expected_owner_uid: u32) -> Result<()> {
        let path = Self::record_path(state_dir);
        if path.exists() {
            return Ok(());
        }
        let record = LockdownRecord {
            version: VERSION,
            engaged: false,
            occurrence_id: BOOTSTRAP_OCCURRENCE.into(),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|e| Error::Provider(format!("cannot encode initial lockdown record: {e}")))?;
        write_new_durable(&path, &bytes)?;
        let metadata = std::fs::metadata(&path)?;
        if metadata.uid() != expected_owner_uid {
            return Err(Error::Denied(format!(
                "initial lockdown record owner {} != expected daemon uid {expected_owner_uid}",
                metadata.uid()
            )));
        }
        Ok(())
    }

    pub fn is_engaged(&self) -> bool {
        self.latch_state.load(Ordering::Acquire) != 0
    }

    fn publish_effective(&self, engaged: bool) {
        if engaged {
            self.latch_state
                .fetch_or(LATCH_EFFECTIVE_ENGAGED, Ordering::Release);
        } else {
            self.latch_state
                .fetch_and(!LATCH_EFFECTIVE_ENGAGED, Ordering::Release);
        }
    }

    pub fn adopt(&self) -> Result<LockdownOutcome> {
        self.publish_effective(true);
        let _guard = self.lock.lock().map_err(|_| poisoned())?;
        let record = match self.read_record() {
            Ok(Some(record)) => record,
            Ok(None) => {
                self.reconcile_complete_outbox_locked(None)?;
                return Ok(LockdownOutcome {
                    engaged: true,
                    occurrence_id: String::new(),
                });
            }
            Err(_) => {
                return Ok(LockdownOutcome {
                    engaged: true,
                    occurrence_id: String::new(),
                });
            }
        };

        self.reconcile_complete_outbox_locked(Some(&record))?;
        let effective = self.effective_record_state(&record)?;
        self.publish_effective(effective);
        Ok(LockdownOutcome {
            engaged: effective,
            occurrence_id: record.occurrence_id,
        })
    }

    pub fn transition(
        &self,
        target_engaged: bool,
        operator_uid: u32,
        acceptance_path: &str,
        sink: &dyn LockdownAuditSink,
    ) -> Result<LockdownOutcome> {
        if operator_uid != 0 {
            return Err(Error::Denied(
                "owner lockdown transitions require exact peer uid 0".into(),
            ));
        }
        if acceptance_path.trim().is_empty() || acceptance_path.len() > 64 {
            return Err(Error::Denied("owner acceptance path is malformed".into()));
        }
        let _pending_engage = if target_engaged {
            Some(PendingEngageGuard::acquire(self)?)
        } else {
            None
        };
        self.publish_effective(true);
        #[cfg(test)]
        let prelock_hook = self.prelock_hook.lock().map_err(|_| poisoned())?.clone();
        #[cfg(test)]
        if let Some(hook) = prelock_hook {
            hook(target_engaged);
        }

        let outcome = {
            let _guard = self.lock.lock().map_err(|_| poisoned())?;
            self.publish_effective(true);
            let prior_raw = self.read_record_raw()?;
            let prior_record = match prior_raw.as_deref() {
                Some(raw) => Some(parse_record(raw)?),
                None => None,
            };
            self.reconcile_complete_outbox_locked(prior_record.as_ref())?;
            let prior_effective = if let Some(record) = prior_record.as_ref() {
                self.effective_record_state(record)?
            } else {
                true
            };
            if prior_record
                .as_ref()
                .is_some_and(|record| record.engaged == target_engaged)
                && prior_effective == target_engaged
            {
                let record = prior_record.expect("checked present");
                self.publish_effective(target_engaged);
                LockdownOutcome {
                    engaged: target_engaged,
                    occurrence_id: record.occurrence_id,
                }
            } else {
                let occurrence_id = random_id();
                let mut intent = LockdownIntent {
                    version: VERSION,
                    occurrence_id: occurrence_id.clone(),
                    target_engaged,
                    prior_record_digest: prior_raw.as_deref().map(record_digest),
                    operator_uid,
                    acceptance_path: acceptance_path.to_string(),
                    confirmed: false,
                    delivered: false,
                };
                self.write_intent(&intent)?;
                let record = LockdownRecord {
                    version: VERSION,
                    engaged: target_engaged,
                    occurrence_id: occurrence_id.clone(),
                };
                self.write_record(&record)?;
                intent.confirmed = true;
                self.write_intent(&intent)?;
                self.publish_effective(target_engaged);
                LockdownOutcome {
                    engaged: target_engaged,
                    occurrence_id,
                }
            }
        };

        let _ = self.replay(sink);
        Ok(outcome)
    }

    pub fn pending(&self) -> Result<Vec<LockdownIntent>> {
        read_intents(&self.outbox_dir, self.expected_owner_uid)
    }

    pub fn mark_audit_delivered(&self, occurrence_id: &str) -> Result<()> {
        validate_id(occurrence_id)?;
        let mut state = self.lock.lock().map_err(|_| poisoned())?;
        state.audit_in_flight.remove(occurrence_id);
        let Some(mut intent) = self.read_intent(occurrence_id)? else {
            return Ok(());
        };
        if !intent.delivered {
            intent.delivered = true;
            #[cfg(test)]
            if let Some(hook) = self
                .audit_delivery_write_hook
                .lock()
                .map_err(|_| poisoned())?
                .clone()
            {
                hook()?;
            }
            self.write_intent(&intent)?;
        }
        if self
            .read_record()?
            .is_some_and(|record| record.occurrence_id != occurrence_id)
        {
            remove_durable(&self.outbox_dir.join(occurrence_id))?;
        }
        Ok(())
    }

    pub fn release_audit_claim(&self, occurrence_id: &str) -> Result<()> {
        validate_id(occurrence_id)?;
        self.lock
            .lock()
            .map_err(|_| poisoned())?
            .audit_in_flight
            .remove(occurrence_id);
        Ok(())
    }

    pub fn replay(&self, sink: &dyn LockdownAuditSink) -> Result<()> {
        let mut first_error = None;
        for intent in self.claim_pending_audits()? {
            match sink.record_transition(&intent) {
                Ok(()) => {
                    if let Err(error) = self.mark_audit_delivered(&intent.occurrence_id) {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                        if let Err(error) = self.release_audit_claim(&intent.occurrence_id) {
                            if first_error.is_none() {
                                first_error = Some(error);
                            }
                        }
                    }
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    if let Err(error) = self.release_audit_claim(&intent.occurrence_id) {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Reconcile the live record's matching intent before returning replay candidates. Both direct
    /// transition retry and daemon housekeeping use this path, so a post-record confirmation failure
    /// is repaired without requiring a restart or replacing the occurrence.
    pub fn reconciled_pending(&self) -> Result<Vec<LockdownIntent>> {
        self.publish_effective(true);
        let _guard = self.lock.lock().map_err(|_| poisoned())?;
        self.reconcile_and_read_pending_locked()
    }

    pub fn claim_pending_audits(&self) -> Result<Vec<LockdownIntent>> {
        self.publish_effective(true);
        let mut state = self.lock.lock().map_err(|_| poisoned())?;
        let pending = self.reconcile_and_read_pending_locked()?;
        let claimed = pending
            .into_iter()
            .filter(|intent| state.audit_in_flight.insert(intent.occurrence_id.clone()))
            .collect();
        Ok(claimed)
    }

    fn reconcile_and_read_pending_locked(&self) -> Result<Vec<LockdownIntent>> {
        let record = self.read_record()?;
        self.reconcile_complete_outbox_locked(record.as_ref())?;
        if let Some(record) = record.as_ref() {
            let effective = self.effective_record_state(record)?;
            self.publish_effective(effective);
        }
        Ok(self
            .pending()?
            .into_iter()
            .filter(|intent| intent.confirmed && !intent.delivered)
            .collect())
    }

    fn read_record_raw(&self) -> Result<Option<Vec<u8>>> {
        secure_read(&self.record_path, self.expected_owner_uid)
    }

    fn read_record(&self) -> Result<Option<LockdownRecord>> {
        let Some(raw) = self.read_record_raw()? else {
            return Ok(None);
        };
        parse_record(&raw).map(Some)
    }

    fn write_record(&self, record: &LockdownRecord) -> Result<()> {
        let bytes = serde_json::to_vec(record)
            .map_err(|e| Error::Provider(format!("cannot encode lockdown record: {e}")))?;
        atomic_write(&self.record_path, &bytes)
    }

    fn read_intent(&self, occurrence_id: &str) -> Result<Option<LockdownIntent>> {
        validate_id(occurrence_id)?;
        let path = self.outbox_dir.join(occurrence_id);
        let Some(raw) = secure_read(&path, self.expected_owner_uid)? else {
            return Ok(None);
        };
        parse_intent(occurrence_id, &raw).map(Some)
    }

    fn write_intent(&self, intent: &LockdownIntent) -> Result<()> {
        validate_intent(intent)?;
        ensure_dir_durable(&self.outbox_dir)?;
        let bytes = serde_json::to_vec(intent)
            .map_err(|e| Error::Provider(format!("cannot encode lockdown intent: {e}")))?;
        atomic_write(&self.outbox_dir.join(&intent.occurrence_id), &bytes)
    }

    fn reconcile_live_intent_locked(&self, record: &LockdownRecord) -> Result<()> {
        if record.occurrence_id == BOOTSTRAP_OCCURRENCE {
            return Ok(());
        }
        let Some(mut intent) = self.read_intent(&record.occurrence_id)? else {
            return Ok(());
        };
        if intent.target_engaged == record.engaged && intent.operator_uid == 0 && !intent.confirmed
        {
            self.sync_record_parent()?;
            intent.confirmed = true;
            self.write_intent(&intent)?;
        }
        Ok(())
    }

    fn sync_record_parent(&self) -> Result<()> {
        #[cfg(test)]
        if let Some(hook) = self
            .record_parent_sync_hook
            .lock()
            .map_err(|_| poisoned())?
            .clone()
        {
            hook()?;
        }
        let parent = self
            .record_path
            .parent()
            .ok_or_else(|| Error::Provider("lockdown record path has no parent".into()))?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn effective_record_state(&self, record: &LockdownRecord) -> Result<bool> {
        if record.occurrence_id == BOOTSTRAP_OCCURRENCE {
            return Ok(record.engaged);
        }
        let supported = self
            .read_intent(&record.occurrence_id)?
            .is_some_and(|intent| {
                intent.confirmed
                    && intent.target_engaged == record.engaged
                    && intent.operator_uid == 0
            });
        Ok(if supported { record.engaged } else { true })
    }

    fn reconcile_complete_outbox_locked(&self, record: Option<&LockdownRecord>) -> Result<()> {
        if let Some(record) = record {
            self.reconcile_live_intent_locked(record)?;
        }
        let intents = self.pending()?;
        self.sweep_orphan_intents(&intents, record.map(|record| record.occurrence_id.as_str()))
    }

    fn sweep_orphan_intents(
        &self,
        intents: &[LockdownIntent],
        live_occurrence: Option<&str>,
    ) -> Result<()> {
        for intent in intents {
            let is_live = live_occurrence == Some(intent.occurrence_id.as_str());
            let orphan_intent = !intent.confirmed && !is_live;
            let delivered_and_superseded =
                intent.delivered && live_occurrence.is_some() && !is_live;
            if orphan_intent || delivered_and_superseded {
                remove_durable(&self.outbox_dir.join(&intent.occurrence_id))?;
            }
        }
        Ok(())
    }
}

struct PendingEngageGuard<'a> {
    store: &'a LockdownStore,
}

impl<'a> PendingEngageGuard<'a> {
    fn acquire(store: &'a LockdownStore) -> Result<Self> {
        if store
            .latch_state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state >> 1 == LATCH_MAX_PENDING {
                    None
                } else {
                    Some((state + LATCH_PENDING_ONE) | LATCH_EFFECTIVE_ENGAGED)
                }
            })
            .is_err()
        {
            store.publish_effective(true);
            return Err(Error::Provider(
                "too many pending lockdown engage requests".into(),
            ));
        }
        Ok(Self { store })
    }
}

impl Drop for PendingEngageGuard<'_> {
    fn drop(&mut self) {
        if self
            .store
            .latch_state
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state >> 1 == 0 {
                    None
                } else {
                    Some(state - LATCH_PENDING_ONE)
                }
            })
            .is_err()
        {
            self.store.publish_effective(true);
        }
    }
}

impl cermet_core::LockdownSource for LockdownStore {
    fn is_engaged(&self) -> bool {
        self.is_engaged()
    }
}

fn valid_record(record: &LockdownRecord) -> bool {
    record.version == VERSION
        && (record.occurrence_id == BOOTSTRAP_OCCURRENCE || valid_id(&record.occurrence_id))
}

fn parse_record(raw: &[u8]) -> Result<LockdownRecord> {
    let record: LockdownRecord = serde_json::from_slice(raw).map_err(|_| {
        Error::Denied("lockdown record is malformed; effective state is engaged".into())
    })?;
    if !valid_record(&record) {
        return Err(Error::Denied(
            "lockdown record version/occurrence is invalid; effective state is engaged".into(),
        ));
    }
    Ok(record)
}

fn parse_intent(name: &str, raw: &[u8]) -> Result<LockdownIntent> {
    let intent: LockdownIntent = serde_json::from_slice(raw)
        .map_err(|e| Error::Provider(format!("corrupt lockdown intent `{name}`: {e}")))?;
    validate_intent(&intent)?;
    if intent.occurrence_id != name {
        return Err(Error::Provider(format!(
            "lockdown intent filename `{name}` disagrees with its occurrence"
        )));
    }
    Ok(intent)
}

fn validate_intent(intent: &LockdownIntent) -> Result<()> {
    if intent.version != VERSION
        || !valid_id(&intent.occurrence_id)
        || intent
            .prior_record_digest
            .as_deref()
            .is_some_and(|digest| !valid_id(digest))
        || intent.acceptance_path.trim().is_empty()
        || intent.acceptance_path.len() > 64
        || intent.operator_uid != 0
        || (intent.delivered && !intent.confirmed)
    {
        return Err(Error::Provider(
            "lockdown intent metadata is malformed".into(),
        ));
    }
    Ok(())
}

fn read_intents(dir: &Path, owner: u32) -> Result<Vec<LockdownIntent>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(Error::Provider(format!(
                "cannot scan lockdown outbox: {error}"
            )))
        }
    };
    let mut intents = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|e| Error::Provider(format!("cannot scan lockdown outbox: {e}")))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        validate_id(&name)?;
        let raw = secure_read(&entry.path(), owner)?
            .ok_or_else(|| Error::Provider(format!("lockdown intent `{name}` vanished")))?;
        intents.push(parse_intent(&name, &raw)?);
    }
    Ok(intents)
}

fn secure_read(path: &Path, owner: u32) -> Result<Option<Vec<u8>>> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::Denied(format!(
                "cannot read {}: {error}",
                path.display()
            )))
        }
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(Error::Denied(format!(
            "{} is not a private daemon-owned regular file",
            path.display()
        )));
    }
    let mut raw = Vec::new();
    file.take(16 * 1024 + 1).read_to_end(&mut raw)?;
    if raw.len() > 16 * 1024 {
        return Err(Error::Denied(format!("{} is oversized", path.display())));
    }
    Ok(Some(raw))
}

fn ensure_dir_durable(dir: &Path) -> Result<()> {
    if !dir.exists() {
        std::fs::create_dir(dir)?;
        if let Some(parent) = dir.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

fn write_new_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Provider("durable record path has no parent".into()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Provider("durable record path has no filename".into()))?;
    let temp = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    write_new_durable(&temp, bytes)?;
    if let Err(error) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(error.into());
    }
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn remove_durable(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn record_digest(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn random_id() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_id(value: &str) -> Result<()> {
    if valid_id(value) {
        Ok(())
    } else {
        Err(Error::Provider(
            "malformed lockdown occurrence/digest".into(),
        ))
    }
}

fn poisoned() -> Error {
    Error::Provider("lockdown store lock poisoned".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, Mutex as StdMutex};

    #[derive(Default)]
    struct RecordingSink(StdMutex<Vec<String>>);

    impl LockdownAuditSink for RecordingSink {
        fn record_transition(&self, intent: &LockdownIntent) -> Result<()> {
            let mut occurrences = self.0.lock().unwrap();
            occurrences.push(intent.occurrence_id.clone());
            Ok(())
        }
    }

    impl RecordingSink {
        fn occurrences(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    struct FailingSink;
    impl LockdownAuditSink for FailingSink {
        fn record_transition(&self, _intent: &LockdownIntent) -> Result<()> {
            Err(Error::Provider("audit unavailable".into()))
        }
    }

    #[test]
    fn concurrent_engage_and_clear_publish_the_final_serialized_record_state() {
        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = Arc::new(LockdownStore::new(dir.path(), owner));
        store.adopt().unwrap();
        let _: &AtomicUsize = &store.latch_state;

        let engage_order = Arc::new(AtomicUsize::new(0));
        let engages_paused = Arc::new(Barrier::new(3));
        let first_engage_released = Arc::new(Barrier::new(2));
        let second_engage_released = Arc::new(Barrier::new(2));
        *store.prelock_hook.lock().unwrap() = Some(Arc::new({
            let engage_order = engage_order.clone();
            let engages_paused = engages_paused.clone();
            let first_engage_released = first_engage_released.clone();
            let second_engage_released = second_engage_released.clone();
            move |target_engaged| {
                if target_engaged {
                    let order = engage_order.fetch_add(1, Ordering::Relaxed);
                    engages_paused.wait();
                    match order {
                        0 => first_engage_released.wait(),
                        1 => second_engage_released.wait(),
                        _ => panic!("unexpected extra engage caller"),
                    };
                }
            }
        }));

        let first_store = store.clone();
        let first_engage = std::thread::spawn(move || {
            first_store.transition(true, 0, "owner_uid0_first", &FailingSink)
        });
        while engage_order.load(Ordering::Acquire) != 1 {
            std::thread::yield_now();
        }
        let second_store = store.clone();
        let second_engage = std::thread::spawn(move || {
            second_store.transition(true, 0, "owner_uid0_second", &FailingSink)
        });
        engages_paused.wait();
        store
            .transition(false, 0, "owner_uid0_clear", &FailingSink)
            .unwrap();
        assert!(
            store.is_engaged(),
            "queued validated engages must keep the effective gate engaged after an older clear returns"
        );
        first_engage_released.wait();
        first_engage.join().unwrap().unwrap();
        assert!(
            store.is_engaged(),
            "the remaining queued engage must keep the gate engaged after the first completes"
        );
        store
            .transition(false, 0, "owner_uid0_intervening_clear", &FailingSink)
            .unwrap();
        assert!(
            store.is_engaged(),
            "the remaining queued engage must keep the gate engaged after an intervening clear returns"
        );
        second_engage_released.wait();
        second_engage.join().unwrap().unwrap();

        let durable = store.read_record().unwrap().unwrap();
        assert!(durable.engaged, "engage is the final serialized writer");
        assert_eq!(
            store.is_engaged(),
            durable.engaged,
            "the process-local gate must publish the final serialized durable state"
        );
    }

    #[test]
    fn audited_live_clear_survives_housekeeping_restart_and_retry_without_replay() {
        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);
        store.adopt().unwrap();
        store
            .transition(true, 0, "owner_uid0", &FailingSink)
            .unwrap();

        let sink = RecordingSink::default();
        let cleared = store
            .transition(false, 0, "owner_uid0_clear", &sink)
            .unwrap();
        let calls_after_delivery = sink.occurrences();
        let delivered = store
            .read_intent(&cleared.occurrence_id)
            .unwrap()
            .expect("audit delivery must retain evidence supporting the live clear");
        assert!(delivered.confirmed);
        assert!(delivered.delivered);

        assert!(store.reconciled_pending().unwrap().is_empty());
        store.replay(&sink).unwrap();
        assert_eq!(sink.occurrences(), calls_after_delivery);
        assert!(!store.is_engaged());

        let restarted = LockdownStore::new(dir.path(), owner);
        let adopted = restarted.adopt().unwrap();
        assert!(!adopted.engaged);
        assert_eq!(adopted.occurrence_id, cleared.occurrence_id);
        restarted.replay(&sink).unwrap();
        assert_eq!(sink.occurrences(), calls_after_delivery);

        let retried = restarted
            .transition(false, 0, "owner_uid0_clear", &sink)
            .unwrap();
        assert_eq!(retried.occurrence_id, cleared.occurrence_id);
        assert_eq!(sink.occurrences(), calls_after_delivery);

        restarted
            .transition(true, 0, "owner_uid0", &FailingSink)
            .unwrap();
        assert!(
            restarted
                .read_intent(&cleared.occurrence_id)
                .unwrap()
                .is_none(),
            "delivered live evidence is pruned only after a later record supersedes it"
        );
    }

    #[test]
    fn clear_transition_with_corrupt_live_evidence_fails_engaged() {
        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);
        store.adopt().unwrap();
        store
            .transition(true, 0, "owner_uid0", &FailingSink)
            .unwrap();
        let cleared = store
            .transition(false, 0, "owner_uid0_clear", &FailingSink)
            .unwrap();
        assert!(!store.is_engaged());

        std::fs::write(store.outbox_dir.join(&cleared.occurrence_id), b"corrupt").unwrap();
        store
            .transition(false, 0, "owner_uid0_clear", &FailingSink)
            .expect_err("corrupt live evidence must not authorize clear");
        assert!(
            store.is_engaged(),
            "every transition must engage before resolving durable state"
        );
    }

    #[test]
    fn clear_transition_with_unrelated_corrupt_outbox_evidence_fails_engaged() {
        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);
        store.adopt().unwrap();
        store
            .transition(true, 0, "owner_uid0", &FailingSink)
            .unwrap();

        let corrupt_occurrence = "1".repeat(64);
        std::fs::write(store.outbox_dir.join(corrupt_occurrence), b"corrupt").unwrap();

        store
            .transition(false, 0, "owner_uid0_clear", &FailingSink)
            .expect_err("clear must validate the complete outbox before publishing false");
        assert!(
            store.is_engaged(),
            "unresolved unrelated outbox evidence must leave the latch engaged"
        );
    }

    #[test]
    fn visible_unconfirmed_clear_requires_successful_record_parent_refsync() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);
        store.adopt().unwrap();
        store
            .transition(true, 0, "owner_uid0", &FailingSink)
            .unwrap();

        let occurrence_id = "7".repeat(64);
        store
            .write_intent(&LockdownIntent {
                version: VERSION,
                occurrence_id: occurrence_id.clone(),
                target_engaged: false,
                prior_record_digest: store
                    .read_record_raw()
                    .unwrap()
                    .as_deref()
                    .map(record_digest),
                operator_uid: 0,
                acceptance_path: "owner_uid0_clear".into(),
                confirmed: false,
                delivered: false,
            })
            .unwrap();
        store
            .write_record(&LockdownRecord {
                version: VERSION,
                engaged: false,
                occurrence_id: occurrence_id.clone(),
            })
            .unwrap();

        let attempts = Arc::new(AtomicUsize::new(0));
        *store.record_parent_sync_hook.lock().unwrap() = Some(Arc::new({
            let attempts = attempts.clone();
            move || {
                if attempts.fetch_add(1, AtomicOrdering::SeqCst) == 0 {
                    Err(Error::Provider(
                        "injected record parent fsync failure".into(),
                    ))
                } else {
                    Ok(())
                }
            }
        }));

        store
            .reconciled_pending()
            .expect_err("failed re-fsync must leave visible clear unresolved");
        assert!(store.is_engaged());
        assert!(
            !store
                .read_intent(&occurrence_id)
                .unwrap()
                .unwrap()
                .confirmed
        );

        let pending = store.reconciled_pending().unwrap();
        assert_eq!(attempts.load(AtomicOrdering::SeqCst), 2);
        let reconciled = pending
            .iter()
            .find(|intent| intent.occurrence_id == occurrence_id)
            .expect("the original occurrence remains the replay candidate");
        assert!(reconciled.confirmed);
        assert!(!store.is_engaged());
    }

    #[test]
    fn audit_claims_are_exclusive_and_failed_delivery_is_retryable() {
        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);
        store.adopt().unwrap();
        let transitioned = store
            .transition(true, 0, "owner_uid0", &FailingSink)
            .unwrap();

        let first = store.claim_pending_audits().unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].occurrence_id, transitioned.occurrence_id);
        assert!(store.claim_pending_audits().unwrap().is_empty());

        store
            .release_audit_claim(&transitioned.occurrence_id)
            .unwrap();
        let retry = store.claim_pending_audits().unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].occurrence_id, transitioned.occurrence_id);
        store
            .mark_audit_delivered(&transitioned.occurrence_id)
            .unwrap();
        assert!(store.claim_pending_audits().unwrap().is_empty());
    }

    #[test]
    fn delivery_marker_failure_does_not_strand_later_batch_claims() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);
        store.adopt().unwrap();
        store
            .transition(true, 0, "owner_uid0", &FailingSink)
            .unwrap();
        store
            .transition(false, 0, "owner_uid0_clear", &FailingSink)
            .unwrap();

        let delivery_writes = Arc::new(AtomicUsize::new(0));
        *store.audit_delivery_write_hook.lock().unwrap() = Some(Arc::new({
            let delivery_writes = delivery_writes.clone();
            move || {
                if delivery_writes.fetch_add(1, AtomicOrdering::SeqCst) == 0 {
                    Err(Error::Provider(
                        "injected delivered-marker persistence failure".into(),
                    ))
                } else {
                    Ok(())
                }
            }
        }));

        let sink = RecordingSink::default();
        store
            .replay(&sink)
            .expect_err("the first delivered-marker persistence failure is reported");
        let first_batch = sink.occurrences();
        assert_eq!(
            first_batch.len(),
            2,
            "a marker failure for the first claim must not skip the later claim"
        );

        let retry = store.claim_pending_audits().unwrap();
        assert_eq!(retry.len(), 1, "only the failed marker remains retryable");
        assert_eq!(retry[0].occurrence_id, first_batch[0]);
        store.release_audit_claim(&retry[0].occurrence_id).unwrap();

        store.replay(&sink).unwrap();
        assert!(store.claim_pending_audits().unwrap().is_empty());
    }

    #[test]
    fn adopt_read_error_preserves_unconfirmed_intents() {
        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);
        let intent = LockdownIntent {
            version: VERSION,
            occurrence_id: "6".repeat(64),
            target_engaged: false,
            prior_record_digest: None,
            operator_uid: 0,
            acceptance_path: "owner_uid0_clear".into(),
            confirmed: false,
            delivered: false,
        };
        store.write_intent(&intent).unwrap();
        std::fs::write(LockdownStore::record_path(dir.path()), b"corrupt").unwrap();

        let adopted = store.adopt().unwrap();
        assert!(adopted.engaged);
        assert!(store.is_engaged());
        assert!(
            store.read_intent(&intent.occurrence_id).unwrap().is_some(),
            "unresolved record reads must preserve recovery evidence"
        );
    }

    #[test]
    fn live_unconfirmed_occurrence_is_reconciled_on_retry_and_periodic_replay() {
        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);
        store.adopt().unwrap();

        // Deterministic crash state: the record rename landed, but rewriting the matching intent as
        // confirmed failed. This is exactly the post-record failure window in `transition`.
        let occurrence_id = "9".repeat(64);
        store
            .write_intent(&LockdownIntent {
                version: VERSION,
                occurrence_id: occurrence_id.clone(),
                target_engaged: true,
                prior_record_digest: store
                    .read_record_raw()
                    .unwrap()
                    .as_deref()
                    .map(record_digest),
                operator_uid: 0,
                acceptance_path: "owner_uid0".into(),
                confirmed: false,
                delivered: false,
            })
            .unwrap();
        store
            .write_record(&LockdownRecord {
                version: VERSION,
                engaged: true,
                occurrence_id: occurrence_id.clone(),
            })
            .unwrap();

        let retried = store
            .transition(true, 0, "owner_uid0", &FailingSink)
            .expect("idempotent retry reconciles the landed occurrence");
        assert_eq!(retried.occurrence_id, occurrence_id);
        assert!(
            store
                .read_intent(&occurrence_id)
                .unwrap()
                .unwrap()
                .confirmed,
            "retry must confirm the existing occurrence instead of minting a replacement"
        );
        // The same reconciliation must be present on the periodic replay path and remain idempotent.
        let sink = RecordingSink::default();
        store.replay(&sink).unwrap();
        store.replay(&sink).unwrap();
        assert_eq!(sink.occurrences(), vec![occurrence_id.clone()]);

        // Recreate the failure window for a clear and enter through the exact scan used by the
        // daemon's periodic housekeeping task. It confirms the same occurrence and publishes the
        // now-supported clear before audit replay; no owner retry or process restart is needed.
        let periodic_occurrence = "8".repeat(64);
        store
            .write_intent(&LockdownIntent {
                version: VERSION,
                occurrence_id: periodic_occurrence.clone(),
                target_engaged: false,
                prior_record_digest: store
                    .read_record_raw()
                    .unwrap()
                    .as_deref()
                    .map(record_digest),
                operator_uid: 0,
                acceptance_path: "owner_uid0_clear".into(),
                confirmed: false,
                delivered: false,
            })
            .unwrap();
        store
            .write_record(&LockdownRecord {
                version: VERSION,
                engaged: false,
                occurrence_id: periodic_occurrence.clone(),
            })
            .unwrap();

        let pending = store.reconciled_pending().unwrap();
        assert!(pending
            .iter()
            .any(|intent| { intent.occurrence_id == periodic_occurrence && intent.confirmed }));
        assert!(!store.is_engaged());
        store.replay(&sink).unwrap();
        assert_eq!(sink.occurrences(), vec![occurrence_id, periodic_occurrence]);
    }

    #[test]
    fn missing_or_corrupt_installed_record_is_effectively_engaged() {
        let dir = tempfile::tempdir().unwrap();
        let store = LockdownStore::new(dir.path(), nix::unistd::geteuid().as_raw());
        store.adopt().expect("missing state adopts fail closed");
        assert!(store.is_engaged());

        std::fs::write(LockdownStore::record_path(dir.path()), b"corrupt").unwrap();
        store.adopt().expect("corrupt state adopts fail closed");
        assert!(store.is_engaged());
    }

    #[test]
    fn initialized_clear_then_engage_and_clear_are_occurrence_distinct_and_replayable() {
        let dir = tempfile::tempdir().unwrap();
        LockdownStore::initialize_clear(dir.path(), nix::unistd::geteuid().as_raw()).unwrap();
        let store = LockdownStore::new(dir.path(), nix::unistd::geteuid().as_raw());
        store.adopt().unwrap();
        assert!(!store.is_engaged());

        let sink = RecordingSink::default();
        let engaged = store.transition(true, 0, "owner", &FailingSink).unwrap();
        assert!(
            store.is_engaged(),
            "engage is effective and durable despite audit outage"
        );
        let cleared = store
            .transition(false, 0, "owner_presence", &FailingSink)
            .unwrap();
        assert!(
            !store.is_engaged(),
            "clear becomes effective only after replayable evidence is durable"
        );
        assert_ne!(engaged.occurrence_id, cleared.occurrence_id);

        store.adopt().unwrap();
        store.replay(&sink).unwrap();
        assert_eq!(sink.occurrences().len(), 2);
        store.replay(&sink).unwrap();
        assert_eq!(
            sink.occurrences().len(),
            2,
            "confirmed transition replay is idempotent"
        );
    }

    #[test]
    fn intent_only_is_swept_but_a_live_matching_occurrence_is_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);

        let orphan = LockdownIntent {
            version: VERSION,
            occurrence_id: "a".repeat(64),
            target_engaged: true,
            prior_record_digest: None,
            operator_uid: 0,
            acceptance_path: "owner_uid0".into(),
            confirmed: false,
            delivered: false,
        };
        store.write_intent(&orphan).unwrap();
        store.adopt().unwrap();
        assert!(store.read_intent(&orphan.occurrence_id).unwrap().is_none());

        let matching = LockdownIntent {
            occurrence_id: "b".repeat(64),
            ..orphan
        };
        store.write_intent(&matching).unwrap();
        store
            .write_record(&LockdownRecord {
                version: VERSION,
                engaged: true,
                occurrence_id: matching.occurrence_id.clone(),
            })
            .unwrap();
        store.adopt().unwrap();
        assert!(store.is_engaged());
        assert!(
            store
                .read_intent(&matching.occurrence_id)
                .unwrap()
                .unwrap()
                .confirmed
        );
    }

    #[test]
    fn clear_record_without_matching_clear_evidence_stays_engaged_and_can_be_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);
        let unsupported_occurrence = "c".repeat(64);
        store
            .write_record(&LockdownRecord {
                version: VERSION,
                engaged: false,
                occurrence_id: unsupported_occurrence.clone(),
            })
            .unwrap();

        store.adopt().unwrap();
        assert!(store.is_engaged());
        let recovered = store
            .transition(false, 0, "owner_uid0_clear", &FailingSink)
            .unwrap();
        assert!(!store.is_engaged());
        assert_ne!(recovered.occurrence_id, unsupported_occurrence);
    }

    #[test]
    fn matching_occurrence_with_the_wrong_target_cannot_support_a_clear() {
        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);
        let occurrence_id = "d".repeat(64);
        store
            .write_intent(&LockdownIntent {
                version: VERSION,
                occurrence_id: occurrence_id.clone(),
                target_engaged: true,
                prior_record_digest: None,
                operator_uid: 0,
                acceptance_path: "owner_uid0".into(),
                confirmed: false,
                delivered: false,
            })
            .unwrap();
        store
            .write_record(&LockdownRecord {
                version: VERSION,
                engaged: false,
                occurrence_id,
            })
            .unwrap();

        store.adopt().unwrap();
        assert!(store.is_engaged());
    }

    #[test]
    fn clear_intent_only_is_swept_and_matching_live_clear_is_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let owner = nix::unistd::geteuid().as_raw();
        LockdownStore::initialize_clear(dir.path(), owner).unwrap();
        let store = LockdownStore::new(dir.path(), owner);
        store.adopt().unwrap();
        store
            .transition(true, 0, "owner_uid0", &FailingSink)
            .unwrap();
        assert!(store.is_engaged());

        let intent_only = LockdownIntent {
            version: VERSION,
            occurrence_id: "e".repeat(64),
            target_engaged: false,
            prior_record_digest: store
                .read_record_raw()
                .unwrap()
                .as_deref()
                .map(record_digest),
            operator_uid: 0,
            acceptance_path: "owner_uid0_clear".into(),
            confirmed: false,
            delivered: false,
        };
        store.write_intent(&intent_only).unwrap();
        store.adopt().unwrap();
        assert!(
            store.is_engaged(),
            "an intent-only clear never changes effective state"
        );
        assert!(store
            .read_intent(&intent_only.occurrence_id)
            .unwrap()
            .is_none());

        let matching = LockdownIntent {
            occurrence_id: "f".repeat(64),
            ..intent_only
        };
        store.write_intent(&matching).unwrap();
        store
            .write_record(&LockdownRecord {
                version: VERSION,
                engaged: false,
                occurrence_id: matching.occurrence_id.clone(),
            })
            .unwrap();
        store.adopt().unwrap();
        assert!(!store.is_engaged());
        assert!(
            store
                .read_intent(&matching.occurrence_id)
                .unwrap()
                .unwrap()
                .confirmed
        );
    }
}
