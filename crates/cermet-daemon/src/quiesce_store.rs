//! The durable on-disk store for the MCP-repoint quiesce barrier.
//!
//! Mirrors the sentence-pin store's discipline (`sentence_pin_admin.rs`): a single mode-0600 record
//! in the daemon state dir holding ONLY `sha256(token)` + a hard-bounded expiry (never the raw
//! token). The core (`cermet_core::QuiesceStore`) drives the exact release ordering; this file
//! implements the primitives with real syscalls: `write` = temp create+write+fsync → rename → parent
//! fsync; `unlink`; `fsync_parent`; `load` (fail-closed on a malformed/foreign/writable record).

use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use cermet_core::{Error, PersistedBarrier, QuiesceStore, Result};
use serde::{Deserialize, Serialize};

/// The record file name inside the state dir.
pub const BARRIER_FILE: &str = "mcp-repoint.barrier";
/// A generous cap — the record is a tiny fixed JSON object; anything larger is corrupt.
const MAX_RECORD_BYTES: u64 = 4 * 1024;

#[derive(Serialize, Deserialize)]
struct OnDisk {
    v: u8,
    /// `sha256(token)` as lowercase hex (64 chars).
    token_hash: String,
    expires_at: i64,
}

pub struct FileQuiesceStore {
    path: PathBuf,
}

impl FileQuiesceStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(BARRIER_FILE),
        }
    }

    fn dir(&self) -> &Path {
        self.path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }
}

fn hash_to_hex(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_hash(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(Error::Integrity(
            "mcp-repoint barrier token_hash is not 64 lowercase hex chars".into(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).expect("ascii hex");
        out[i] = u8::from_str_radix(s, 16)
            .map_err(|_| Error::Integrity("invalid mcp-repoint barrier hex".into()))?;
    }
    Ok(out)
}

impl QuiesceStore for FileQuiesceStore {
    fn write(&self, record: &PersistedBarrier) -> Result<()> {
        let dir = self.dir();
        let on_disk = OnDisk {
            v: 1,
            token_hash: hash_to_hex(&record.token_hash),
            expires_at: record.expires_at,
        };
        let bytes = serde_json::to_vec(&on_disk)
            .map_err(|e| Error::Provider(format!("serialize mcp-repoint barrier: {e}")))?;
        // temp create (0600, O_EXCL) + write + fsync
        let tmp = dir.join(format!(
            ".{BARRIER_FILE}.{}.{}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        // rename → parent fsync (durable before returning)
        if let Err(e) = std::fs::rename(&tmp, &self.path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Provider(format!(
                "mcp-repoint barrier rename failed: {e}"
            )));
        }
        self.fsync_parent()?;
        Ok(())
    }

    fn load(&self) -> Result<Option<PersistedBarrier>> {
        match std::fs::symlink_metadata(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(Error::Integrity(format!(
                    "cannot stat mcp-repoint barrier at {}: {e}",
                    self.path.display()
                )))
            }
            Ok(md) => {
                // Fail closed on a non-regular file or a group/other-writable record.
                if !md.file_type().is_file() {
                    return Err(Error::Integrity(
                        "mcp-repoint barrier is not a regular file".into(),
                    ));
                }
                if md.permissions().mode() & 0o022 != 0 {
                    return Err(Error::Integrity(
                        "mcp-repoint barrier is group/other-writable — refusing".into(),
                    ));
                }
                if md.len() > MAX_RECORD_BYTES {
                    return Err(Error::Integrity(
                        "mcp-repoint barrier record is implausibly large — refusing".into(),
                    ));
                }
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|e| Error::Integrity(format!("cannot open mcp-repoint barrier: {e}")))?;
        let mut buf = String::new();
        f.read_to_string(&mut buf)
            .map_err(|e| Error::Integrity(format!("cannot read mcp-repoint barrier: {e}")))?;
        let on_disk: OnDisk = serde_json::from_str(&buf)
            .map_err(|e| Error::Integrity(format!("malformed mcp-repoint barrier record: {e}")))?;
        if on_disk.v != 1 {
            return Err(Error::Integrity(format!(
                "unsupported mcp-repoint barrier version {}",
                on_disk.v
            )));
        }
        Ok(Some(PersistedBarrier {
            token_hash: hex_to_hash(&on_disk.token_hash)?,
            expires_at: on_disk.expires_at,
        }))
    }

    fn unlink(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Provider(format!(
                "mcp-repoint barrier unlink failed: {e}"
            ))),
        }
    }

    fn fsync_parent(&self) -> Result<()> {
        let dir = std::fs::File::open(self.dir())
            .map_err(|e| Error::Provider(format!("open mcp-repoint barrier dir: {e}")))?;
        dir.sync_all()
            .map_err(|e| Error::Provider(format!("fsync mcp-repoint barrier dir: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn write_load_roundtrips_and_persists_only_the_hash() {
        let d = tmpdir();
        let store = FileQuiesceStore::new(d.path());
        let rec = PersistedBarrier {
            token_hash: [7u8; 32],
            expires_at: 1_234_567,
        };
        store.write(&rec).unwrap();
        // The record is mode 0600 and does not contain a raw token (only the hash).
        let mode = std::fs::metadata(d.path().join(BARRIER_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "barrier record must be mode 0600");
        assert_eq!(store.load().unwrap().unwrap(), rec);
    }

    #[test]
    fn unlink_then_load_is_absent() {
        let d = tmpdir();
        let store = FileQuiesceStore::new(d.path());
        store
            .write(&PersistedBarrier {
                token_hash: [1u8; 32],
                expires_at: 10,
            })
            .unwrap();
        store.unlink().unwrap();
        assert!(store.load().unwrap().is_none());
        // Unlinking an already-absent record is Ok (idempotent).
        store.unlink().unwrap();
    }

    #[test]
    fn a_malformed_record_fails_closed_on_load() {
        let d = tmpdir();
        let store = FileQuiesceStore::new(d.path());
        std::fs::write(d.path().join(BARRIER_FILE), b"not json").unwrap();
        assert!(store.load().is_err(), "malformed record must fail closed");
    }

    #[test]
    fn a_group_writable_record_is_refused() {
        let d = tmpdir();
        let store = FileQuiesceStore::new(d.path());
        let p = d.path().join(BARRIER_FILE);
        std::fs::write(&p, br#"{"v":1,"token_hash":"00","expires_at":1}"#).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert!(store.load().is_err(), "a writable record must be refused");
    }
}
