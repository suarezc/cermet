//! Core-private, canonical money grant metadata.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MONEY_METADATA_VERSION: u8 = 1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum MoneyMetadata {
    #[serde(rename = "none")]
    None { version: u8 },
    #[serde(rename = "mutation")]
    Mutation {
        version: u8,
        effect_id: String,
        idempotency_key: String,
        precondition_fingerprint: String,
        retry_deadline_epoch: i64,
    },
    #[serde(rename = "retry")]
    Retry {
        version: u8,
        effect_id: String,
        idempotency_key: String,
        parent_grant_id: String,
        precondition_fingerprint: String,
        retry_deadline_epoch: i64,
    },
}

impl MoneyMetadata {
    pub fn none() -> Self {
        Self::None {
            version: MONEY_METADATA_VERSION,
        }
    }

    pub fn fresh(precondition_fingerprint: String, retry_deadline_epoch: i64) -> Self {
        let mut key = [0u8; 32];
        let mut effect = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut effect);
        Self::Mutation {
            version: MONEY_METADATA_VERSION,
            effect_id: format!("effect_{}", crate::util::hex(&effect)),
            idempotency_key: format!("cermet_{}", crate::util::hex(&key)),
            precondition_fingerprint,
            retry_deadline_epoch,
        }
    }

    pub fn retry(&self, parent_grant_id: String) -> Option<Self> {
        Some(Self::Retry {
            version: MONEY_METADATA_VERSION,
            effect_id: self.effect_id()?.to_string(),
            idempotency_key: self.idempotency_key()?.to_string(),
            parent_grant_id,
            precondition_fingerprint: self.precondition_fingerprint()?.to_string(),
            retry_deadline_epoch: self.retry_deadline_epoch()?,
        })
    }

    pub fn to_canonical_json(&self) -> String {
        crate::evidence::canonical_json(
            &serde_json::to_value(self).expect("money metadata serializes"),
        )
    }

    pub fn from_canonical_json(json: &str) -> Result<Self, String> {
        let value: Value = serde_json::from_str(json)
            .map_err(|error| format!("money metadata is not valid JSON: {error}"))?;
        if crate::evidence::canonical_json(&value) != json {
            return Err("money metadata is not canonical JSON".into());
        }
        let metadata: Self = serde_json::from_value(value)
            .map_err(|error| format!("money metadata has an invalid shape: {error}"))?;
        let version = match &metadata {
            Self::None { version }
            | Self::Mutation { version, .. }
            | Self::Retry { version, .. } => *version,
        };
        if version != MONEY_METADATA_VERSION {
            return Err("money metadata has an unsupported version".into());
        }
        match &metadata {
            Self::None { .. } => {}
            Self::Mutation {
                effect_id,
                idempotency_key,
                precondition_fingerprint,
                retry_deadline_epoch,
                ..
            }
            | Self::Retry {
                effect_id,
                idempotency_key,
                precondition_fingerprint,
                retry_deadline_epoch,
                ..
            } => {
                if !valid_effect_id(effect_id)
                    || !valid_idempotency_key(idempotency_key)
                    || !valid_fingerprint(precondition_fingerprint)
                    || *retry_deadline_epoch < 0
                {
                    return Err("money metadata contains a malformed private field".into());
                }
            }
        }
        if let Self::Retry {
            parent_grant_id, ..
        } = &metadata
        {
            if parent_grant_id.is_empty() || parent_grant_id.len() > 128 {
                return Err("money retry metadata has a malformed parent grant id".into());
            }
        }
        Ok(metadata)
    }

    pub fn is_money(&self) -> bool {
        !matches!(self, Self::None { .. })
    }

    pub fn is_retry(&self) -> bool {
        matches!(self, Self::Retry { .. })
    }

    pub fn effect_id(&self) -> Option<&str> {
        match self {
            Self::None { .. } => None,
            Self::Mutation { effect_id, .. } | Self::Retry { effect_id, .. } => Some(effect_id),
        }
    }

    pub(crate) fn idempotency_key(&self) -> Option<&str> {
        match self {
            Self::None { .. } => None,
            Self::Mutation {
                idempotency_key, ..
            }
            | Self::Retry {
                idempotency_key, ..
            } => Some(idempotency_key),
        }
    }

    pub fn precondition_fingerprint(&self) -> Option<&str> {
        match self {
            Self::None { .. } => None,
            Self::Mutation {
                precondition_fingerprint,
                ..
            }
            | Self::Retry {
                precondition_fingerprint,
                ..
            } => Some(precondition_fingerprint),
        }
    }

    pub fn retry_deadline_epoch(&self) -> Option<i64> {
        match self {
            Self::None { .. } => None,
            Self::Mutation {
                retry_deadline_epoch,
                ..
            }
            | Self::Retry {
                retry_deadline_epoch,
                ..
            } => Some(*retry_deadline_epoch),
        }
    }

    pub fn parent_grant_id(&self) -> Option<&str> {
        match self {
            Self::Retry {
                parent_grant_id, ..
            } => Some(parent_grant_id),
            Self::None { .. } | Self::Mutation { .. } => None,
        }
    }
}

fn valid_effect_id(value: &str) -> bool {
    value
        .strip_prefix("effect_")
        .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn valid_idempotency_key(value: &str) -> bool {
    value
        .strip_prefix("cermet_")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn valid_fingerprint(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moneypath_metadata_is_canonical_and_keys_are_256_bit() {
        assert_eq!(
            MoneyMetadata::none().to_canonical_json(),
            r#"{"kind":"none","version":1}"#
        );
        let metadata = MoneyMetadata::fresh(format!("sha256:{}", "a".repeat(64)), 600);
        assert_eq!(
            metadata.idempotency_key().unwrap().len(),
            "cermet_".len() + 64
        );
        let json = metadata.to_canonical_json();
        assert!(MoneyMetadata::from_canonical_json(&json).unwrap() == metadata);
        assert!(MoneyMetadata::from_canonical_json(r#"{"version":1,"kind":"none"}"#).is_err());
    }
}
