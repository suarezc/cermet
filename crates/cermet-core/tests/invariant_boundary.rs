//! Grant-kernel field-freezing invariant boundary end-to-end tests.

use cermet_core::{
    AuthenticatedSentenceAuthority, Broker, BrokerConfig, CapabilityRequest, Decision,
    SentenceAuthoritySource,
};
use serde_json::json;
use std::path::PathBuf;
use tempfile::TempDir;

const KEY: &[u8] = &[9u8; 32];

/// A scratch dir and the guard that removes it.
fn tmpdir() -> (TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("cermet-ib-")
        .tempdir()
        .unwrap();
    let path = dir.path().to_path_buf();
    (dir, path)
}

struct FixedAuthority(cermet_core::sentence::RuleSet);

impl SentenceAuthoritySource for FixedAuthority {
    fn current_authority(&self) -> cermet_core::Result<AuthenticatedSentenceAuthority> {
        Ok(AuthenticatedSentenceAuthority {
            digest: cermet_core::sentence::authority_digest(&self.0),
            rules: self.0.clone(),
        })
    }
}

/// This suite proves grant-kernel invariants (owner-spoof, contract-less actions, field
/// freezing) on the vendored `github`/`mock-vercel` descriptors. Those providers sit outside the
/// shipped product surface but stay vendored and covered, so the suite opens a broker that does
/// NOT enforce product availability — otherwise every case here would pass for the trivial
/// `provider_disabled` reason instead of the invariant under test. The shelf itself is proven in
/// `broker::tests` and `ontology_setup_corpus`.
fn open(rules: &str) -> (TempDir, Broker) {
    let (guard, dir) = tmpdir();
    let broker = Broker::open_for_semantic_test(
        BrokerConfig {
            git: cermet_core::git::GitConfig::at(
                std::env::temp_dir().join("cermet-test-quarantine"),
            ),
            dir,
            master_key: KEY.to_vec(),
            action_templates: cermet_core::templates::VENDORED_CATALOG
                .iter()
                .map(|s| s.to_string())
                .collect(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: cermet_core::ArtifactConfig::default(),
        },
        Some(std::sync::Arc::new(FixedAuthority(
            cermet_core::sentence::parse_rules(rules).unwrap(),
        ))),
    )
    .unwrap();
    (guard, broker)
}

fn read_repo(repo: &str) -> CapabilityRequest {
    CapabilityRequest {
        provider: "github".into(),
        action: "read_repo".into(),
        resource: json!({ "repo": repo }),
        environment: None,
        justification: None,
        model: None,
    }
}

const GH_ALLOW_ACME_WEBSITE: &str =
    "allow github.read_repo where owner = \"acme\" and name = \"website\"";

#[test]
fn ib_owner_spoof_17_evil_owner_does_not_satisfy_an_acme_scoped_allow() {
    let (_dir, b) = open(GH_ALLOW_ACME_WEBSITE);

    let ok = b
        .request_capability("s1", read_repo("acme/website"))
        .unwrap();
    assert_eq!(
        ok.decision,
        Decision::Allow,
        "the pinned owner/name must be allowed"
    );

    let spoof = b
        .request_capability("s1", read_repo("evil/website"))
        .unwrap();
    assert_ne!(
        spoof.decision,
        Decision::Allow,
        "owner=evil must not satisfy the acme-scoped allow (T2 / owner-spoof)"
    );
}

#[test]
fn ib_unsupported_action_34_contractless_action_fails_closed_at_request() {
    let (_dir, b) = open("allow github.push_branch");
    let out = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "github".into(),
                action: "push_branch".into(),
                resource: json!({ "repo": "acme/website" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    assert_eq!(
        out.decision,
        Decision::Deny,
        "a contract-less action must fail closed at request"
    );
}

#[test]
fn ib_dropped_builtin_create_branch_fails_closed_at_request() {
    // create_branch was a compiled-in github built-in that was dropped with no
    // replacement (no contract, no template). Even with an allow rule naming it, a request fails
    // closed at request time (unsupported) — a dropped built-in must not stay reachable.
    let (_dir, b) = open("allow github.create_branch\nallow github.push_branch");
    for action in ["create_branch", "push_branch"] {
        let out = b
            .request_capability(
                "s1",
                CapabilityRequest {
                    provider: "github".into(),
                    action: action.into(),
                    resource: json!({ "owner": "acme", "name": "website" }),
                    environment: None,
                    justification: None,
                    model: None,
                },
            )
            .unwrap();
        assert_eq!(
            out.decision,
            Decision::Deny,
            "a dropped/uncontracted github action ({action}) must fail closed at request: {}",
            out.reason
        );
    }
}

#[test]
fn ib_deny_rule_for_dropped_action_still_parses_and_denies() {
    let (_dir, b) = open("deny github.create_branch");
    let out = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "github".into(),
                action: "create_branch".into(),
                resource: json!({ "owner": "acme", "name": "website" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    assert_eq!(
        out.decision,
        Decision::Deny,
        "a request for a dropped action under a deny rule stays denied: {}",
        out.reason
    );
}

#[test]
fn mock_grant_round_trips_through_from_stored_at_execute() {
    let (_dir, b) = open("allow mock-vercel.deploy where environment = \"preview\"");
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
    assert_eq!(out.decision, Decision::Allow);
    let grant = out.grant_id.expect("allow yields a grant");
    let result = b
        .execute_capability(&grant)
        .expect("a mock grant must execute (from_stored round-trips)");
    assert!(result.ok, "the offline mock execute must succeed");
}

#[test]
fn ib_owner_spoof_17b_ambiguous_repo_owner_shape_is_denied() {
    let (_dir, b) = open(GH_ALLOW_ACME_WEBSITE);
    let out = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "github".into(),
                action: "read_repo".into(),
                resource: json!({ "repo": "website", "owner": "evil" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    assert_eq!(
        out.decision,
        Decision::Deny,
        "the ambiguous repo+owner shape must be denied"
    );
}
