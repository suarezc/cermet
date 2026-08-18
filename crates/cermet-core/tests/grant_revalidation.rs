//! A grant approved under one policy must not remain executable after the policy changes.

use cermet_core::{
    AuthenticatedSentenceAuthority, Broker, BrokerConfig, CapabilityRequest, Decision,
    SentenceAuthoritySource,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

const KEY: &[u8] = &[7u8; 32];

/// A scratch dir and the guard that removes it.
fn tmpdir() -> (TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("cermet-t2c3-")
        .tempdir()
        .unwrap();
    let path = dir.path().to_path_buf();
    (dir, path)
}

struct MutableAuthority(Mutex<cermet_core::sentence::RuleSet>);

impl SentenceAuthoritySource for MutableAuthority {
    fn current_authority(&self) -> cermet_core::Result<AuthenticatedSentenceAuthority> {
        let rules = self.0.lock().unwrap().clone();
        Ok(AuthenticatedSentenceAuthority {
            digest: cermet_core::sentence::authority_digest(&rules),
            rules,
        })
    }
}

fn open(dir: &Path, source: Arc<MutableAuthority>) -> Broker {
    Broker::open_with_sentence_authority(
        BrokerConfig {
            git: cermet_core::git::GitConfig::at(
                std::env::temp_dir().join("cermet-test-quarantine"),
            ),
            dir: dir.to_path_buf(),
            master_key: KEY.to_vec(),
            action_templates: cermet_core::templates::VENDORED_CATALOG
                .iter()
                .map(|s| s.to_string())
                .collect(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: cermet_core::ArtifactConfig::default(),
        },
        source,
    )
    .unwrap()
}

#[test]
fn t2_class3_approved_grant_is_rejected_after_policy_change() {
    let (_dir_guard, dir) = tmpdir();

    let source = Arc::new(MutableAuthority(Mutex::new(
        cermet_core::sentence::parse_rules(
            "allow mock-vercel.deploy where environment = \"preview\"",
        )
        .unwrap(),
    )));

    let grant_id = {
        let b = open(&dir, source.clone());
        b.connect_credential("mock-vercel", None, "vercel_demo_secret_123456789")
            .unwrap();
        let out = b
            .request_capability(
                "s1",
                CapabilityRequest {
                    provider: "mock-vercel".into(),
                    action: "deploy".into(),
                    resource: json!({}),
                    environment: Some("preview".into()),
                    justification: None,
                    model: None,
                },
            )
            .unwrap();
        assert_eq!(
            out.decision,
            Decision::Allow,
            "deploy should be allowed under v1: {}",
            out.reason
        );
        out.grant_id.expect("an allow decision yields a grant")
    };

    *source.0.lock().unwrap() =
        cermet_core::sentence::parse_rules("deny mock-vercel.deploy").unwrap();
    let b2 = open(&dir, source);
    let res = b2.execute_capability(&grant_id);
    assert!(
        res.is_err(),
        "a grant minted under the old sentence corpus must be rejected after it changes; got {res:?}"
    );
}
