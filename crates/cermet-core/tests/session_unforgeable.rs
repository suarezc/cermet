//! Session + operation identity is server-controlled, never agent-supplied.

use cermet_core::{Broker, BrokerConfig, CapabilityRequest};
use serde_json::json;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const KEY: &[u8] = &[7u8; 32];

/// A scratch dir and the guard that removes it, so no leftover directory survives the test.
fn tmpdir() -> (TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("cermet-m2a-")
        .tempdir()
        .unwrap();
    let path = dir.path().to_path_buf();
    (dir, path)
}

fn open(dir: &Path, _policy_yaml: &str) -> Broker {
    Broker::open(BrokerConfig {
        git: cermet_core::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
        dir: dir.to_path_buf(),
        master_key: KEY.to_vec(),
        action_templates: cermet_core::templates::VENDORED_CATALOG
            .iter()
            .map(|s| s.to_string())
            .collect(),
        provider_descriptors: BrokerConfig::vendored_descriptors(),
        artifacts: cermet_core::ArtifactConfig::default(),
    })
    .unwrap()
}

const POLICY_ALLOW: &str = r#"
providers:
  mock-vercel:
    allow:
      - action: deploy
        scope: { environment: preview }
"#;

fn connect(b: &Broker) {
    b.connect_credential("mock-vercel", None, "vercel_demo_secret_123456789")
        .unwrap();
}

#[test]
fn agent_request_body_cannot_set_session() {
    let parsed = serde_json::from_str::<CapabilityRequest>(
        r#"{"provider":"mock-vercel","action":"deploy",
            "session_id":"attacker-sess",
            "environment":"preview","resource":{}}"#,
    );
    assert!(
        parsed.is_err(),
        "session_id must not decode inside a capability request body"
    );
}

#[test]
fn blank_server_session_fails_closed() {
    let (_dir, dir) = tmpdir();
    let b = open(&dir, POLICY_ALLOW);
    connect(&b);
    let req = CapabilityRequest {
        provider: "mock-vercel".into(),
        action: "deploy".into(),
        resource: json!({}),
        environment: Some("preview".into()),
        justification: None,
        model: None,
    };
    let res = b.request_capability("   ", req);
    assert!(
        res.is_err(),
        "a blank server session must fail closed, not mint one; got {res:?}"
    );
}
