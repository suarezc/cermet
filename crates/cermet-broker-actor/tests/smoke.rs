//! Smoke tests for the daemon-neutral broker actor.

use cermet_broker_actor::spawn;
use cermet_core::{BrokerConfig, Error};
use tempfile::tempdir;

fn config(dir: &std::path::Path) -> BrokerConfig {
    BrokerConfig {
        git: cermet_core::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
        dir: dir.to_path_buf(),
        master_key: vec![5u8; 32],
        action_templates: vec![],
        provider_descriptors: BrokerConfig::vendored_descriptors(),
        artifacts: cermet_core::ArtifactConfig::default(),
    }
}

#[tokio::test]
async fn list_credentials_is_empty_on_a_fresh_home() {
    let dir = tempdir().unwrap();
    let h = spawn(config(dir.path())).expect("broker opens");
    let json = h
        .list_credentials()
        .await
        .expect("list_credentials round-trips");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v.as_array().map(|a| a.len()), Some(0), "no credentials yet");
}

#[tokio::test]
async fn malformed_request_body_is_a_typed_core_invalid() {
    let dir = tempdir().unwrap();
    let h = spawn(config(dir.path())).expect("broker opens");
    let err = h
        .request("s1".to_string(), "not json at all".to_string(), None, None)
        .await
        .expect_err("a malformed request body must fail closed");
    assert!(
        matches!(err, Error::Invalid(_)),
        "expected a typed core Invalid, got {err:?}"
    );
}
