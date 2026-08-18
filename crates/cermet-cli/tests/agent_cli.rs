#![allow(dead_code, unused_variables, unused_imports)]

//! Integration tests for the `cermet mcp` bridge library over a REAL `agent.sock`.
//!
//! These stand up the daemon's agent-socket serve path (`bind_agent_socket` + `handle_connection`)
//! against a live broker actor in a tempdir, then drive the bridge's `call`/`render`/`run` exactly as
//! the binary does. The make-or-break flow: the agent REQUESTS over one short-lived connection (it
//! gets back only a `request_id`; `grant_id` is withheld), and the agent EXECUTES by `request_id` over
//! a fresh connection, authorized by sentence authority and the per-uid principal.

use std::path::Path;

use cermet_broker_actor::{spawn_with_sentence_authority, BrokerHandle};
use cermet_cli::mcp_bridge::{AgentCommand, AgentError};
use cermet_core::{AuthenticatedSentenceAuthority, BrokerConfig, SentenceAuthoritySource};
use cermet_daemon::serve::{bind_agent_socket, handle_connection, ServeTimeouts};
use secrecy::SecretString;
use tempfile::tempdir;

/// mock-vercel is the OFFLINE provider (no network) so an approved deploy actually executes.
fn broker(dir: &Path) -> BrokerHandle {
    broker_with(dir)
}

fn broker_with(dir: &Path) -> BrokerHandle {
    struct FixedSentenceAuthority(cermet_core::sentence::RuleSet);

    impl SentenceAuthoritySource for FixedSentenceAuthority {
        fn current_authority(&self) -> cermet_core::Result<AuthenticatedSentenceAuthority> {
            Ok(AuthenticatedSentenceAuthority {
                digest: cermet_core::sentence::authority_digest(&self.0),
                rules: self.0.clone(),
            })
        }
    }

    let rules = cermet_core::sentence::parse_rules("allow mock-vercel.deploy").unwrap();
    spawn_with_sentence_authority(
        BrokerConfig {
            git: cermet_core::git::GitConfig::at(
                std::env::temp_dir().join("cermet-test-quarantine"),
            ),
            dir: dir.to_path_buf(),
            master_key: vec![7u8; 32],
            action_templates: vec![],
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: cermet_core::ArtifactConfig::default(),
        },
        std::sync::Arc::new(FixedSentenceAuthority(rules)),
    )
    .expect("broker opens")
}

/// Serve EXACTLY ONE connection in dev mode (service_mode = false → the approver-deny is
/// inert), then the thread joins. For a two-connection flow, call this twice (re-binding agent.sock
/// in the same dir works: `bind_socket` removes the stale path first, once the prior listener drops).
fn serve_one(
    runtime_dir: &Path,
    broker: BrokerHandle,
) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    let (listener, path) = bind_agent_socket(runtime_dir).expect("bind agent.sock");
    let rt = tokio::runtime::Handle::current();
    let handle = std::thread::spawn(move || {
        let (conn, _addr) = listener.accept().expect("accept");
        // Single-operator gate: agent.sock admits ONLY the operator uid; these same-uid tests
        // connect as our own uid, so the operator IS our uid.
        handle_connection(
            conn,
            &broker,
            &rt,
            "cermet-mcp-test",
            Some(nix::unistd::getuid().as_raw()),
            ServeTimeouts::default(),
        );
    });
    (path, handle)
}

#[tokio::test]
async fn list_over_a_real_socket_renders_no_providers() {
    let dir = tempdir().unwrap();
    let (path, server) = serve_one(dir.path(), broker(dir.path()));

    let out = cermet_cli::mcp_bridge::run(&path, &AgentCommand::List).expect("list ok");
    server.join().unwrap();

    assert!(out.ok);
    assert!(
        out.text.contains("no providers connected"),
        "got: {}",
        out.text
    );
}

#[tokio::test]
async fn verify_over_a_real_socket_reports_a_fresh_chain_verified() {
    let dir = tempdir().unwrap();
    let (path, server) = serve_one(dir.path(), broker(dir.path()));

    let out = cermet_cli::mcp_bridge::run(&path, &AgentCommand::Verify).expect("verify ok");
    server.join().unwrap();

    assert!(out.ok);
    assert!(out.text.contains("verified"), "got: {}", out.text);
}

#[tokio::test]
async fn execute_of_an_unknown_request_is_an_opaque_server_error() {
    // The binary must surface the daemon's single collapsed reason — never an existence oracle — and
    // exit non-zero.
    let dir = tempdir().unwrap();
    let (path, server) = serve_one(dir.path(), broker(dir.path()));

    let err = cermet_cli::mcp_bridge::run(
        &path,
        &AgentCommand::Execute {
            request_id: "does-not-exist".into(),
        },
    )
    .expect_err("unknown request must fail");
    server.join().unwrap();

    match err {
        AgentError::Server(reason) => {
            assert_eq!(reason, "unable to execute", "the opaque collapsed reason");
        }
        other => panic!("expected an opaque Server error, got {other:?}"),
    }
}

#[tokio::test]
async fn request_then_execute_over_short_lived_connections() {
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());

    // A connected mock credential so the offline execute can actually run.
    broker
        .connect(
            "mock-vercel".into(),
            SecretString::new("mock-token".to_string()),
            None,
        )
        .await
        .expect("connect the mock credential");

    let req_cmd = AgentCommand::Request {
        provider: "mock-vercel".into(),
        action: "deploy".into(),
        resource: serde_json::json!({"project":"demo","repo_id":123,"ref":"main"}),
        environment: Some("preview".into()),
        // The daemon boundary requires a non-empty reason on every agent request; this fixture
        // supplies one like a real caller.
        justification: Some("ship the preview for review".into()),
        retry_effect: None,
        model: None,
    };

    // CONNECTION 1: the agent requests via the binary's transport. It gets a request_id; the grant_id
    // is withheld (the agent-facing outcome can't even express one).
    let (path1, server1) = serve_one(dir.path(), broker.clone());
    let req_resp = cermet_cli::mcp_bridge::call(&path1, &req_cmd).expect("request call");
    server1.join().unwrap();

    assert_eq!(req_resp["kind"], "requested", "got {req_resp}");
    assert_eq!(req_resp["decision"], serde_json::json!("allow"));
    assert_eq!(req_resp["authority_kind"], serde_json::json!("sentence"));
    assert!(req_resp.get("approval_required").is_none());
    assert!(
        req_resp
            .get("grant_id")
            .map(|v| v.is_null())
            .unwrap_or(true),
        "grant_id must never reach the agent, got {req_resp}"
    );
    let request_id = req_resp["request_id"]
        .as_str()
        .expect("the agent gets a request_id")
        .to_string();

    // The rendered agent-facing text must point at execute and never leak a grant_id.
    let rendered =
        cermet_cli::mcp_bridge::render(&req_cmd, &req_resp).expect("render the requested frame");
    assert!(rendered.ok);
    assert!(rendered.text.contains(&request_id));
    assert!(rendered.text.to_lowercase().contains("allowed"));
    assert!(
        !rendered.text.contains("grant_id"),
        "rendered request output leaked a grant_id: {}",
        rendered.text
    );

    // CONNECTION 2 (fresh, a DIFFERENT minted session): execute by request_id via the binary.
    let exec_cmd = AgentCommand::Execute {
        request_id: request_id.clone(),
    };
    let (path2, server2) = serve_one(dir.path(), broker.clone());
    let out = cermet_cli::mcp_bridge::run(&path2, &exec_cmd).expect("execute run");
    server2.join().unwrap();

    assert!(out.ok, "execute should succeed, got: {}", out.text);
    assert!(out.text.contains("mock-vercel.deploy"), "got: {}", out.text);
    assert!(
        !out.text.contains("grant_id"),
        "execute output leaked a grant_id: {}",
        out.text
    );
}

/// A vocabulary request is a DECISION, and every decision is a row: the daemon appends it to the
/// same free-form event log `broker_start` writes to. Both gap classes land — a refused
/// authority-gap probe says an agent could not tell the two walls apart, which is signal too.
#[tokio::test]
async fn a_vocabulary_request_lands_in_the_daemon_event_log_in_both_gap_classes() {
    let dir = tempdir().unwrap();
    let handle = broker(dir.path());

    for (gap, verb) in [
        ("vocabulary_gap", "list_disputes"),
        ("authority_gap", "deploy"),
    ] {
        let (path, server) = serve_one(dir.path(), handle.clone());
        let out = cermet_cli::mcp_bridge::run(
            &path,
            &AgentCommand::RecordVocabularyRequest {
                provider: "stripe".into(),
                wanted_verb: Some(verb.into()),
                wanted_field: None,
                gap: gap.into(),
                ask: Some("settle a dispute we lost".into()),
                rationale: Some("weekly finance reconciliation".into()),
            },
        )
        .expect("the daemon records the event");
        server.join().unwrap();
        assert!(out.ok, "got: {}", out.text);
    }

    // The chain still verifies WITH the new event type, and the events are counted like any other.
    let (path, server) = serve_one(dir.path(), handle.clone());
    let verified = cermet_cli::mcp_bridge::run(&path, &AgentCommand::Verify).expect("verify");
    server.join().unwrap();
    assert!(verified.ok, "got: {}", verified.text);

    // The operator-side view (the same report `cermet audit-verify` renders) counts them by type.
    let report: serde_json::Value =
        serde_json::from_str(&handle.verify_audit().await.expect("verify")).expect("report");
    assert_eq!(report["verified"], serde_json::json!(true));
    assert_eq!(
        report["event_types"]["vocabulary_request"],
        serde_json::json!(2),
        "both gap classes must be rows: {report}"
    );
}

/// The daemon is the enforcement side of this boundary: a gap class it cannot interpret later, or
/// an unbounded string, is refused rather than written into the ledger.
#[tokio::test]
async fn the_daemon_refuses_a_malformed_vocabulary_request() {
    let dir = tempdir().unwrap();
    let handle = broker(dir.path());

    let (path, server) = serve_one(dir.path(), handle.clone());
    let err = cermet_cli::mcp_bridge::run(
        &path,
        &AgentCommand::RecordVocabularyRequest {
            provider: "stripe".into(),
            wanted_verb: Some("list_disputes".into()),
            wanted_field: None,
            gap: "made_up_class".into(),
            ask: None,
            rationale: None,
        },
    )
    .expect_err("an unknown gap class must be refused");
    server.join().unwrap();
    assert!(format!("{err}").contains("gap"), "got: {err}");

    let (path, server) = serve_one(dir.path(), handle.clone());
    let err = cermet_cli::mcp_bridge::run(
        &path,
        &AgentCommand::RecordVocabularyRequest {
            provider: "stripe".into(),
            wanted_verb: Some("list_disputes".into()),
            wanted_field: None,
            gap: "vocabulary_gap".into(),
            ask: Some("x".repeat(5000)),
            rationale: None,
        },
    )
    .expect_err("an unbounded ask must be refused");
    server.join().unwrap();
    assert!(format!("{err}").contains("at most"), "got: {err}");

    // Nothing was written: the ledger has no vocabulary_request rows at all.
    let report: serde_json::Value =
        serde_json::from_str(&handle.verify_audit().await.expect("verify")).expect("report");
    assert!(
        report["event_types"].get("vocabulary_request").is_none(),
        "a refused report must write no row: {report}"
    );
}
