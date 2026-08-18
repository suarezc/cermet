//! Client-visible MCP repoint status types.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRepointBegin {
    pub token: String,
    pub instance_id: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRepointStatusReport {
    pub instance_id: String,
    pub status: McpQuiesceStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuiesceGrantNote {
    pub grant_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum McpQuiesceStatus {
    Quiescent,
    Active {
        grants: Vec<QuiesceGrantNote>,
    },
    OrphanAmbiguous {
        grants: Vec<QuiesceGrantNote>,
    },
    Integrity {
        reason: String,
        grants: Vec<QuiesceGrantNote>,
    },
}
