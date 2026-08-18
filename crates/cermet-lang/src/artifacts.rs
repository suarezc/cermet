//! Client-visible artifact address and receipt types.

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Which socket a stored artifact was read over — recorded on the `artifact_read` audit event so a
/// retrieval is attributable to the AI agent (`agent.sock`) or the human operator/console (`ctl.sock`).
/// Carries no authority (an artifact read is free-but-audited): it is a provenance tag only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactReadSurface {
    Agent,
    Ctl,
}

impl ArtifactReadSurface {
    pub fn tag(self) -> &'static str {
        match self {
            ArtifactReadSurface::Agent => "agent",
            ArtifactReadSurface::Ctl => "ctl",
        }
    }
}

pub const DEFAULT_MAX_BYTES: usize = 5 * 1024 * 1024;
pub const DEFAULT_RETENTION_DAYS: i64 = 90;
pub const MAX_VIEW_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactConfig {
    pub max_bytes: usize,
    pub retention_days: i64,
}

impl Default for ArtifactConfig {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            retention_days: DEFAULT_RETENTION_DAYS,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredArtifact {
    pub handle: String,
    pub digest: String,
    pub size: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRange {
    #[serde(default = "default_unit")]
    pub unit: String,
    pub start: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<u64>,
}

fn default_unit() -> String {
    "bytes".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactAddress {
    Range(ArtifactRange),
    Path(String),
}

impl ArtifactAddress {
    pub fn from_wire(range: Option<ArtifactRange>, path: Option<String>) -> Result<Option<Self>> {
        match (range, path) {
            (Some(_), Some(_)) => Err(Error::Invalid(
                "artifact read takes a range OR a path, not both".to_string(),
            )),
            (Some(range), None) => Ok(Some(Self::Range(range))),
            (None, Some(path)) => {
                validate_path_grammar(&path)?;
                Ok(Some(Self::Path(path)))
            }
            (None, None) => Ok(None),
        }
    }

    pub fn into_wire(self) -> (Option<ArtifactRange>, Option<String>) {
        match self {
            Self::Range(range) => (Some(range), None),
            Self::Path(path) => (None, Some(path)),
        }
    }
}

#[doc(hidden)]
pub fn validate_path_grammar(path: &str) -> Result<()> {
    let rest = path.strip_prefix("$.").ok_or_else(|| {
        Error::Invalid(format!(
            "artifact path must be a capture-pointer like \"$.a.b\", got {path:?}"
        ))
    })?;
    if rest.is_empty() || rest.split('.').any(str::is_empty) {
        return Err(Error::Invalid(format!(
            "artifact path segments must be non-empty (e.g. \"$.a.b\"), got {path:?}"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactSpan {
    pub handle: String,
    pub digest: String,
    pub stored_size: u64,
    pub size: u64,
    pub truncated: bool,
    pub unit: String,
    pub start: u64,
    pub end: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    pub frame_truncated: bool,
    pub content: String,
}
