//! Closed vocabulary for the independent uid-0 owner revocation socket.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum OwnerRequest {
    OwnerStatus,
    OwnerLockdown,
    OwnerClear,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OwnerResponse {
    Status {
        engaged: bool,
    },
    Transitioned {
        engaged: bool,
        occurrence_id: String,
    },
    Error {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_vocabulary_is_closed_and_disjoint_from_ctl_and_agent() {
        for request in [
            OwnerRequest::OwnerStatus,
            OwnerRequest::OwnerLockdown,
            OwnerRequest::OwnerClear,
        ] {
            let value = serde_json::to_value(request).unwrap();
            assert!(serde_json::from_value::<crate::ctl::CtlRequest>(value.clone()).is_err());
            assert!(serde_json::from_value::<crate::wire::AgentRequest>(value).is_err());
        }

        for tag in ["owner_status", "owner_lockdown", "owner_clear"] {
            assert!(!crate::wire::accepted_agent_request_operation_tags().contains(&tag));
        }

        let commit = serde_json::to_value(crate::ctl::CtlRequest::CommitSentences {
            staging_token: "a".repeat(64),
            preset: None,
        })
        .unwrap();
        assert!(serde_json::from_value::<OwnerRequest>(commit).is_err());
    }
}
