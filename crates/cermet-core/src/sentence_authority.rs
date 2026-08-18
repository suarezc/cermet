//! Credential-free, read-only sentence authority for the durable broker.
//!
//! The rule file is intentionally readable by the daemon and writable by the human owner. Its bytes
//! confer authority only when an independent pin source returns their exact SHA-256. This adapter has
//! no mutation or credential API; the presence-gated operator custody path remains the sole writer.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::broker::{AuthenticatedSentenceAuthority, SentenceAuthoritySource};
use crate::error::{Error, Result};
use crate::sentence::{parse_rules, print_rule, RuleSet, Selector};

/// System Keychain service shared by the macOS daemon reader and the human custody writer.
pub const SENTENCE_PIN_SERVICE: &str = "dev.cermet.sentence-authority.v1";

/// The System Keychain account is scoped to the configured human authority owner.
pub fn sentence_pin_account(owner_uid: u32) -> String {
    format!("rules-pin:{owner_uid}")
}

/// Exact-byte pin used by cross-uid sentence authority. The pin is authority evidence, not a secret.
pub fn sentence_authority_pin(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Narrow source of the independent exact-byte pin. It deliberately has no write operation.
pub trait SentencePinSource: Send + Sync {
    fn current_pin(&self) -> Result<[u8; 32]>;
}

/// A canonical sentence file authenticated by an independent exact-byte pin.
pub struct AuthenticatedSentenceFile {
    path: PathBuf,
    expected_owner_uid: u32,
    pin: Arc<dyn SentencePinSource>,
}

impl AuthenticatedSentenceFile {
    pub fn new(path: PathBuf, expected_owner_uid: u32, pin: Arc<dyn SentencePinSource>) -> Self {
        Self {
            path,
            expected_owner_uid,
            pin,
        }
    }

    fn read_exact_bytes(&self) -> Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&self.path)
            .map_err(|error| authority_read_error(&self.path, error))?;
        let metadata = file
            .metadata()
            .map_err(|error| authority_read_error(&self.path, error))?;
        if !metadata.file_type().is_file() || metadata.uid() != self.expected_owner_uid {
            return Err(Error::Denied(format!(
                "sentence authority at {} is not a regular file owned by uid {}",
                self.path.display(),
                self.expected_owner_uid
            )));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(Error::Denied(format!(
                "sentence authority at {} is group/other-writable",
                self.path.display()
            )));
        }
        let mut bytes = Vec::new();
        file.take(crate::authority::MAX_AUTHORITY_FILE + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| authority_read_error(&self.path, error))?;
        if bytes.len() as u64 > crate::authority::MAX_AUTHORITY_FILE {
            return Err(Error::Denied(
                "sentence authority exceeds the maximum authority-file size".into(),
            ));
        }
        Ok(bytes)
    }
}

impl SentenceAuthoritySource for AuthenticatedSentenceFile {
    fn current_authority(&self) -> Result<AuthenticatedSentenceAuthority> {
        let bytes = self.read_exact_bytes()?;
        let pin = self.pin.current_pin()?;
        if sentence_authority_pin(&bytes) != pin {
            return Err(Error::Denied(
                "sentence authority exact-byte pin mismatch".into(),
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::Denied("sentence authority is not valid UTF-8".into()))?;
        let rules = parse_rules(text)
            .map_err(|error| Error::Denied(format!("sentence authority is invalid: {error}")))?;
        for rule in &rules.rules {
            if let Selector::Set { digest, .. } = &rule.selector {
                let pinned = digest
                    .as_deref()
                    .is_some_and(crate::sets::valid_snapshot_digest);
                if !pinned {
                    return Err(Error::Denied(
                        "sentence authority set rules must pin an immutable expansion digest"
                            .into(),
                    ));
                }
            }
        }
        if canonical_rule_bytes(&rules) != bytes {
            return Err(Error::Denied(
                "sentence authority bytes are not canonical".into(),
            ));
        }
        Ok(AuthenticatedSentenceAuthority {
            digest: crate::sentence::authority_digest_for(rules.version, &bytes),
            rules,
        })
    }
}

fn canonical_rule_bytes(rules: &RuleSet) -> Vec<u8> {
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

fn authority_read_error(path: &Path, error: std::io::Error) -> Error {
    Error::Denied(format!(
        "cannot read sentence authority at {}: {error}",
        path.display()
    ))
}
