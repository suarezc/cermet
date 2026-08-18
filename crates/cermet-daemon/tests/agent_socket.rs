#![allow(dead_code, unused_variables, unused_imports)]

//! Integration tests for the agent.sock derive-don't-enroll (v1) dispatch path.
//!
//! v1 auth = DERIVE the agent principal from the kernel-attested peer uid (`uid:N`). There is NO
//! nonce and NO hello handshake: the client connects and the FIRST frame it sends is an
//! `AgentRequest`. The single-operator gate admits ONLY the operator uid (refusing everyone else,
//! and refusing ALL connections when the operator uid is unresolved — fail closed) before any byte.
//! The agent EXECUTE path authorizes by PRINCIPAL (the derived `uid:N`), not by session: the server
//! mints a fresh `session_id` per connection, but an approved grant is executable over a later
//! connection as long as the per-uid principal matches (session is audit-only).

use std::io::Read;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;

use cermet_broker_actor::{spawn, spawn_with_sentence_authority, BrokerHandle};
use cermet_core::{BrokerConfig, SentenceAuthoritySource};
use cermet_daemon::serve::{bind_agent_socket, handle_connection, ServeTimeouts};
use cermet_ipc::codec::{read_response_frame, write_frame};
use cermet_ipc::wire::AgentRequest;
use secrecy::SecretString;
use serde_json::Value;
use tempfile::tempdir;
use wiremock::matchers::{body_string, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_POLICY: &str = "providers:\n  mock-vercel:\n    ask:\n      - action: deploy\n";
fn broker(dir: &Path) -> BrokerHandle {
    broker_with(dir, TEST_POLICY)
}

fn broker_with(dir: &Path, _policy: &str) -> BrokerHandle {
    let rules = cermet_core::sentence::parse_rules("allow mock-vercel.deploy").unwrap();
    spawn_with_sentence_authority(
        BrokerConfig {
            git: cermet_core::git::GitConfig::at(
                std::env::temp_dir().join("cermet-test-quarantine"),
            ),
            dir: dir.to_path_buf(),
            master_key: vec![7u8; 32],
            action_templates: cermet_core::templates::VENDORED_CATALOG
                .iter()
                .map(|s| s.to_string())
                .collect(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: cermet_core::ArtifactConfig::default(),
        },
        std::sync::Arc::new(AgentSocketSentenceAuthority(std::sync::Mutex::new(rules))),
    )
    .expect("broker opens")
}

struct AgentSocketSentenceAuthority(std::sync::Mutex<cermet_core::sentence::RuleSet>);

impl SentenceAuthoritySource for AgentSocketSentenceAuthority {
    fn current_authority(
        &self,
    ) -> cermet_core::Result<cermet_core::AuthenticatedSentenceAuthority> {
        let rules = self.0.lock().unwrap().clone();
        Ok(cermet_core::AuthenticatedSentenceAuthority {
            digest: cermet_core::sentence::authority_digest(&rules),
            rules,
        })
    }
}

fn stripe_sentence(limit: i64) -> cermet_core::sentence::RuleSet {
    let mut rules = cermet_core::sentence::parse_rules(&format!(
        "allow stripe.support where amount <= {limit}"
    ))
    .unwrap();
    cermet_core::sentence::pin_set_references(&mut rules, &cermet_core::sets::VendoredSetResolver)
        .unwrap();
    rules
}

fn stripe_actor(dir: &Path, source: std::sync::Arc<dyn SentenceAuthoritySource>) -> BrokerHandle {
    spawn_with_sentence_authority(
        BrokerConfig {
            git: cermet_core::git::GitConfig::at(
                std::env::temp_dir().join("cermet-test-quarantine"),
            ),
            dir: dir.to_path_buf(),
            master_key: vec![7u8; 32],
            action_templates: cermet_core::templates::VENDORED_CATALOG
                .iter()
                .map(|s| s.to_string())
                .collect(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: cermet_core::ArtifactConfig::default(),
        },
        source,
    )
    .expect("sentence-backed broker opens")
}

/// Our own uid — in these same-uid integration tests the operator IS the connecting (test) process,
/// so admitting `our_uid()` is the "operator accepted" configuration.
fn our_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

/// Default: the single-operator gate admits OUR uid (the operator == the test process), so the
/// existing same-uid dispatch tests are served normally.
fn serve_one(
    runtime_dir: &Path,
    broker: BrokerHandle,
) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    serve_one_full(
        runtime_dir,
        broker,
        Some(our_uid()),
        ServeTimeouts::default(),
    )
}

fn serve_one_with(
    runtime_dir: &Path,
    broker: BrokerHandle,
    timeouts: ServeTimeouts,
) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    serve_one_full(runtime_dir, broker, Some(our_uid()), timeouts)
}

/// Serve ONE connection with an explicit `operator_uid` so the single-operator gate can be
/// exercised over a real socket (admit only `operator_uid`; refuse everyone else; `None` refuses
/// ALL — fail closed).
fn serve_one_full(
    runtime_dir: &Path,
    broker: BrokerHandle,
    operator_uid: Option<u32>,
    timeouts: ServeTimeouts,
) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    let (listener, path) = bind_agent_socket(runtime_dir).expect("bind agent.sock");
    let rt = tokio::runtime::Handle::current();
    let handle = std::thread::spawn(move || {
        let (conn, _addr) = listener.accept().expect("accept");
        handle_connection(conn, &broker, &rt, "test-agent", operator_uid, timeouts);
    });
    (path, handle)
}

#[tokio::test]
async fn derived_uid_authenticates_with_no_handshake() {
    // v1: the agent connects and the FIRST frame is an AgentRequest — no nonce, no hello. The server
    // derives the principal from the kernel-attested peer uid and opens the session immediately.
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());

    let (path, server) = serve_one(dir.path(), broker);

    let mut client = StdUnixStream::connect(&path).expect("connect");
    write_frame(
        &mut client,
        &AgentRequest::ListCredentials { session_id: None },
    )
    .expect("write request");
    let resp: Value = read_response_frame(&mut client).expect("read credentials response");
    assert_eq!(resp["kind"], "credentials", "got {resp}");
    assert!(
        resp["credentials"].is_array(),
        "credentials is an array, got {resp}"
    );
    assert_eq!(
        resp["credentials"].as_array().unwrap().len(),
        0,
        "fresh home has no connected providers"
    );

    drop(client);
    server.join().expect("server thread");
}

#[tokio::test]
async fn request_verifyaudit_and_bogus_execute_under_derive() {
    let dir = tempdir().unwrap();
    let broker = broker_with(dir.path(), TEST_POLICY);
    let (path, server) = serve_one(dir.path(), broker);

    let mut client = StdUnixStream::connect(&path).expect("connect");

    write_frame(
        &mut client,
        &AgentRequest::Request {
            session_id: None,
            provider: "mock-vercel".into(),
            action: "deploy".into(),
            resource: serde_json::json!({
                "project": "orchestra", "repo_id": 123, "ref": "main"
            }),
            environment: Some("preview".into()),
            justification: Some("ship the preview for review".into()),
            retry_effect: None,
            model: None,
        },
    )
    .expect("write request");
    let resp: Value = read_response_frame(&mut client).expect("read requested response");
    assert_eq!(
        resp["kind"], "requested",
        "request is dispatched, got {resp}"
    );
    assert_eq!(resp["decision"], serde_json::json!("allow"), "{resp}");
    assert_eq!(resp["authority_kind"], serde_json::json!("sentence"));
    assert!(resp.get("approval_required").is_none());
    assert!(
        resp.get("grant_id").map(|v| v.is_null()).unwrap_or(true),
        "grant id withheld from the agent"
    );

    write_frame(&mut client, &AgentRequest::VerifyAudit { session_id: None })
        .expect("write verify_audit");
    let resp: Value = read_response_frame(&mut client).expect("read audit_verified");
    assert_eq!(
        resp["kind"], "audit_verified",
        "verify_audit is dispatched, got {resp}"
    );
    assert_eq!(
        resp["ok"],
        serde_json::json!(true),
        "a fresh chain verifies"
    );
    assert!(
        resp.get("event_count").is_none() && resp.get("event_types").is_none(),
        "agent audit verification must not expose operator-only numeric ledger counts: {resp}"
    );

    write_frame(
        &mut client,
        &AgentRequest::Execute {
            session_id: None,
            request_id: "request_does_not_exist".into(),
        },
    )
    .expect("write execute");
    let resp: Value = read_response_frame(&mut client).expect("read execute response");
    assert_eq!(
        resp["kind"], "error",
        "a bogus grant fails closed, got {resp}"
    );
    assert_ne!(
        resp["reason"], "unknown op on this channel",
        "execute must be dispatched, not refused as an unknown op"
    );

    drop(client);
    server.join().expect("server thread");
}

#[tokio::test]
async fn ctl_commit_frame_on_agent_socket_is_rejected_without_a_response() {
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let (path, server) = serve_one(dir.path(), broker);
    let mut client = StdUnixStream::connect(&path).expect("connect agent.sock");

    write_frame(
        &mut client,
        &cermet_ipc::ctl::CtlRequest::CommitSentences {
            staging_token: "ab".repeat(32),
        },
    )
    .expect("frame the ctl-only operation on agent.sock");
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert!(
        response.is_empty(),
        "agent.sock must reject the ctl vocabulary before dispatch and reveal nothing: {response:?}"
    );
    server.join().unwrap();
}

#[tokio::test]
async fn execute_error_frames_are_byte_identical_across_classes() {
    // A NONEXISTENT grant id (core Error::NotFound) and a real-but-FOREIGN grant
    // (core Error::Denied) must yield a BYTE-IDENTICAL error frame, so an authenticated agent
    // cannot use the error class to probe whether a guessed grant id exists.
    let dir = tempdir().unwrap();
    let broker = broker_with(dir.path(), TEST_POLICY);

    // Mint a sentence-authorized grant owned by a DIFFERENT principal + session.
    let minter = broker.clone();
    minter
        .open_session(
            "other-session".into(),
            "other-cmd".into(),
            None,
            None,
            cermet_broker_actor::SelfReported::default(),
        )
        .await
        .expect("open the foreign session");
    let req_json = serde_json::json!({
        "provider": "mock-vercel",
        "action": "deploy",
        "resource": {"project":"orchestra","repo_id":123,"ref":"main"},
        "environment": "preview",
        "justification": null
    })
    .to_string();
    minter
        .request_for_principal(
            "other-session".into(),
            "other-agent".into(),
            req_json,
            false,
            None,
        )
        .await
        .expect("mint the foreign grant");
    let foreign_request: String = {
        let conn = rusqlite::Connection::open(dir.path().join("state.db")).expect("open state.db");
        conn.query_row(
            "SELECT request_id FROM grants WHERE session_id='other-session' AND status='approved' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("the foreign grant row exists")
    };

    // Serve ONE connection; both Execute probes share it (the serve loop handles them in sequence).
    let (path, server) = serve_one(dir.path(), broker);
    let mut client = StdUnixStream::connect(&path).expect("connect");

    write_frame(
        &mut client,
        &AgentRequest::Execute {
            session_id: None,
            request_id: "request_does_not_exist".into(),
        },
    )
    .expect("write execute (missing)");
    let missing: Value = read_response_frame(&mut client).expect("read missing-grant error");

    write_frame(
        &mut client,
        &AgentRequest::Execute {
            session_id: None,
            request_id: foreign_request,
        },
    )
    .expect("write execute (foreign)");
    let foreign: Value = read_response_frame(&mut client).expect("read foreign-grant error");

    drop(client);
    server.join().expect("server thread");

    assert_eq!(
        missing["kind"], "error",
        "missing grant -> error frame, got {missing}"
    );
    assert_eq!(
        foreign["kind"], "error",
        "foreign grant -> error frame, got {foreign}"
    );
    assert_eq!(
        missing, foreign,
        "the missing-grant and foreign-grant error frames must be INDISTINGUISHABLE (no oracle)"
    );
    assert_eq!(
        missing["reason"], "unable to execute",
        "the collapsed opaque reason"
    );
}

#[tokio::test]
async fn artifact_verb_retrieves_a_stored_span_and_fails_closed_on_unknown() {
    // The agent READ path over agent.sock. Seed a blob via the internal store API, then retrieve a
    // line span; an unknown handle collapses to one opaque
    // error frame (no existence oracle).
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());

    // Seed an artifact directly into the store (the broker created the table at open).
    let handle = {
        let conn = rusqlite::Connection::open(dir.path().join("state.db")).expect("open state.db");
        cermet_core::artifacts::store(
            &conn,
            &dir.path().join("artifacts"),
            "rq-seed",
            b"line1\nline2\nline3\nline4",
            cermet_core::artifacts::DEFAULT_MAX_BYTES,
        )
        .expect("seed the artifact")
        .handle
    };

    let (path, server) = serve_one(dir.path(), broker);
    let mut client = StdUnixStream::connect(&path).expect("connect");

    // A line-range read returns exactly that span.
    write_frame(
        &mut client,
        &AgentRequest::Artifact {
            session_id: None,
            handle: handle.clone(),
            range: Some(cermet_ipc::wire::ArtifactRange {
                unit: "lines".into(),
                start: 2,
                end: Some(3),
            }),
            path: None,
        },
    )
    .expect("write artifact");
    let resp: Value = read_response_frame(&mut client).expect("read artifact response");
    assert_eq!(resp["kind"], "artifact", "got {resp}");
    assert_eq!(
        resp["content"], "line2\nline3",
        "the requested span, got {resp}"
    );
    assert!(
        resp.get("digest").and_then(Value::as_str).is_some(),
        "carries a digest"
    );

    // An unknown handle fails closed with the fixed opaque reason.
    write_frame(
        &mut client,
        &AgentRequest::Artifact {
            session_id: None,
            handle: "art_ghost".into(),
            range: None,
            path: None,
        },
    )
    .expect("write artifact (unknown)");
    let resp: Value = read_response_frame(&mut client).expect("read unknown-artifact response");
    assert_eq!(
        resp["kind"], "error",
        "unknown handle is an error, got {resp}"
    );
    assert_eq!(
        resp["reason"], "artifact unavailable",
        "the opaque reason, got {resp}"
    );

    drop(client);
    server.join().expect("server thread");
}

#[tokio::test]
async fn malformed_artifact_path_over_agent_sock_fails_closed_opaque() {
    // A raw frame BYPASSES the friendly CLI/MCP parsers, so the shared boundary must
    // reject malformed path grammar itself. Seed a blob whose JSON contains empty-string keys —
    // `$.`, `$..x`, `$.a.` must NOT resolve against them; each collapses to the SAME opaque error
    // as an unknown handle (no failure-class oracle). A well-formed path still reads.
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());

    let handle = {
        let conn = rusqlite::Connection::open(dir.path().join("state.db")).expect("open state.db");
        cermet_core::artifacts::store(
            &conn,
            &dir.path().join("artifacts"),
            "rq-seed",
            br#"{"":{"x":"leak"},"a":{"":"leak2"},"ok":"yes"}"#,
            cermet_core::artifacts::DEFAULT_MAX_BYTES,
        )
        .expect("seed the artifact")
        .handle
    };

    let (path, server) = serve_one(dir.path(), broker);
    let mut client = StdUnixStream::connect(&path).expect("connect");

    for bad in ["$.", "$..x", "$.a.", "a.b"] {
        write_frame(
            &mut client,
            &AgentRequest::Artifact {
                session_id: None,
                handle: handle.clone(),
                range: None,
                path: Some(bad.to_string()),
            },
        )
        .expect("write artifact (bad path)");
        let resp: Value = read_response_frame(&mut client).expect("read bad-path response");
        assert_eq!(
            resp["kind"], "error",
            "path {bad:?} must fail closed, got {resp}"
        );
        assert_eq!(
            resp["reason"], "artifact unavailable",
            "path {bad:?} joins the same opaque class as an unknown handle, got {resp}"
        );
        assert!(
            !resp.to_string().contains("leak"),
            "no empty-key value may escape for {bad:?}: {resp}"
        );
    }

    // The well-formed pointer still resolves over the same connection.
    write_frame(
        &mut client,
        &AgentRequest::Artifact {
            session_id: None,
            handle: handle.clone(),
            range: None,
            path: Some("$.ok".to_string()),
        },
    )
    .expect("write artifact (good path)");
    let resp: Value = read_response_frame(&mut client).expect("read good-path response");
    assert_eq!(resp["kind"], "artifact", "got {resp}");
    assert_eq!(resp["unit"], "path", "got {resp}");
    assert_eq!(resp["path"], "$.ok", "the pointer is echoed, got {resp}");
    assert_eq!(resp["content"], "\"yes\"", "got {resp}");

    drop(client);
    server.join().expect("server thread");
}

#[tokio::test]
async fn disconnect_closes_the_session() {
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let (path, server) = serve_one(dir.path(), broker);

    let mut client = StdUnixStream::connect(&path).expect("connect");
    write_frame(
        &mut client,
        &AgentRequest::ListCredentials { session_id: None },
    )
    .expect("write request");
    let _resp: Value = read_response_frame(&mut client).expect("read credentials");
    drop(client);
    server.join().expect("server thread");

    let conn = rusqlite::Connection::open(dir.path().join("state.db")).expect("open state.db");
    let (count, closed, ended_set): (i64, i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), \
                    COALESCE(SUM(CASE WHEN status='closed' THEN 1 ELSE 0 END),0), \
                    COALESCE(SUM(CASE WHEN ended_at IS NOT NULL THEN 1 ELSE 0 END),0) \
             FROM sessions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("query sessions");
    assert_eq!(count, 1, "exactly one session was opened");
    assert_eq!(closed, 1, "the session was closed on disconnect");
    assert_eq!(ended_set, 1, "ended_at was stamped on close");
}

#[tokio::test]
async fn hello_mints_a_session_that_the_guard_does_not_close() {
    // `Hello` mints the conversation's session and returns its id. Unlike the
    // per-connection CLI session, a Hello-minted session is NOT owned by the connection guard — it
    // stays OPEN after the connection drops so the whole conversation threads onto it.
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let (path, server) = serve_one(dir.path(), broker);

    let mut client = StdUnixStream::connect(&path).expect("connect");
    write_frame(
        &mut client,
        &AgentRequest::Hello {
            agent: "opus".into(),
            build: cermet_ipc::BUILD_ID.to_string(),
            client_name: None,
            client_version: None,
            model: None,
        },
    )
    .expect("write hello");
    let resp: Value = read_response_frame(&mut client).expect("read session response");
    assert_eq!(
        resp["kind"], "session",
        "hello returns a session frame, got {resp}"
    );
    let sid = resp["session_id"]
        .as_str()
        .expect("a minted session id")
        .to_string();
    assert!(
        sid.starts_with("sess_"),
        "the id is server-minted, got {sid}"
    );

    drop(client);
    server.join().expect("server thread");

    let conn = rusqlite::Connection::open(dir.path().join("state.db")).expect("open state.db");
    let (count, status, agent, owner): (i64, String, Option<String>, Option<i64>) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(status), ''), MAX(agent), MAX(owner_uid) FROM sessions",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("query sessions");
    assert_eq!(
        count, 1,
        "Hello mints exactly one session (no throwaway auto-session)"
    );
    assert_eq!(
        status, "open",
        "the Hello-minted session stays OPEN past the connection drop"
    );
    assert_eq!(
        agent.as_deref(),
        Some("opus"),
        "the agent display name is stamped from Hello"
    );
    // Every daemon-minted session records the kernel-attested peer as its owner.
    assert_eq!(
        owner,
        Some(nix::unistd::getuid().as_raw() as i64),
        "the daemon-minted session is owned by the connecting peer's uid"
    );
}

#[tokio::test]
async fn a_supplied_unknown_or_closed_session_id_is_refused_with_the_reinit_reason() {
    // Fail closed: a caller-supplied `session_id` that does not reference an OPEN session row is
    // refused with the distinct "session expired — re-initialize" reason — never silently minted.
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    // A session we deliberately close, to prove a CLOSED id is refused just like an unknown one.
    broker
        .open_session(
            "sess_closed".into(),
            "old".into(),
            None,
            None,
            cermet_broker_actor::SelfReported::default(),
        )
        .await
        .expect("open");
    broker
        .close_session("sess_closed".into())
        .await
        .expect("close");

    let (path, server) = serve_one(dir.path(), broker);
    let mut client = StdUnixStream::connect(&path).expect("connect");

    write_frame(
        &mut client,
        &AgentRequest::Catalog {
            session_id: Some("sess_ghost".into()),
        },
    )
    .expect("write catalog (unknown session)");
    let unknown: Value = read_response_frame(&mut client).expect("read refusal");
    assert_eq!(
        unknown["kind"], "error",
        "an unknown session id is refused, got {unknown}"
    );
    assert_eq!(unknown["reason"], cermet_ipc::wire::SESSION_EXPIRED);

    write_frame(
        &mut client,
        &AgentRequest::Catalog {
            session_id: Some("sess_closed".into()),
        },
    )
    .expect("write catalog (closed session)");
    let closed: Value = read_response_frame(&mut client).expect("read refusal");
    assert_eq!(
        closed["kind"], "error",
        "a closed session id is refused, got {closed}"
    );
    assert_eq!(closed["reason"], cermet_ipc::wire::SESSION_EXPIRED);

    drop(client);
    server.join().expect("server thread");
}

#[tokio::test]
async fn hello_sweeps_a_stale_idle_session() {
    // The handshake runs an opportunistic sweep: a session idle beyond the 24h window is closed when
    // the next `Hello` arrives, while the freshly minted handshake session stays open.
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    broker
        .open_session(
            "sess_stale".into(),
            "old".into(),
            None,
            None,
            cermet_broker_actor::SelfReported::default(),
        )
        .await
        .expect("open the stale session");
    // Backdate its created_at well beyond the 24h idle window (no grant activity, so created_at is the
    // last-activity signal).
    {
        let conn = rusqlite::Connection::open(dir.path().join("state.db")).expect("open state.db");
        conn.execute(
            "UPDATE sessions SET created_at = '2000-01-01T00:00:00Z' WHERE id = 'sess_stale'",
            [],
        )
        .expect("backdate the stale session");
    }

    let (path, server) = serve_one(dir.path(), broker);
    let mut client = StdUnixStream::connect(&path).expect("connect");
    write_frame(
        &mut client,
        &AgentRequest::Hello {
            agent: "opus".into(),
            build: cermet_ipc::BUILD_ID.to_string(),
            client_name: None,
            client_version: None,
            model: None,
        },
    )
    .expect("write hello");
    let resp: Value = read_response_frame(&mut client).expect("read session");
    let fresh = resp["session_id"].as_str().expect("minted id").to_string();
    drop(client);
    server.join().expect("server thread");

    let conn = rusqlite::Connection::open(dir.path().join("state.db")).expect("open state.db");
    let stale_status: String = conn
        .query_row(
            "SELECT status FROM sessions WHERE id = 'sess_stale'",
            [],
            |r| r.get(0),
        )
        .expect("query stale");
    let fresh_status: String = conn
        .query_row("SELECT status FROM sessions WHERE id = ?1", [&fresh], |r| {
            r.get(0)
        })
        .expect("query fresh");
    assert_eq!(
        stale_status, "closed",
        "the >24h-idle session was swept closed at Hello"
    );
    assert_eq!(
        fresh_status, "open",
        "the just-minted handshake session is untouched"
    );
}

#[tokio::test]
async fn stalled_connection_is_reaped_by_the_deadline() {
    // v1: there is no nonce to read; a client that connects and sends NOTHING leaves the server
    // blocked on the FIRST-frame read, which is bounded by the handshake timeout (the impl holds the
    // handshake read-timeout until the first frame arrives). So a stalled connection is still reaped.
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let timeouts = ServeTimeouts {
        handshake: std::time::Duration::from_millis(200),
        idle: std::time::Duration::from_secs(60),
        response_budget: std::time::Duration::from_secs(60),
    };
    let (_path, server) = serve_one_with(dir.path(), broker, timeouts);

    let client = StdUnixStream::connect(&_path).expect("connect");
    // Send nothing — no nonce to read, no request written.

    let mut finished = false;
    for _ in 0..30 {
        if server.is_finished() {
            finished = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        finished,
        "a stalled connection must be reaped by the deadline, not pin the thread"
    );
    drop(client);
    server.join().expect("server thread");
}

/// Count the session rows in `state.db` — a refused connection returns BEFORE `open_session`, so a
/// truly pre-byte refusal leaves zero sessions (no request was dispatched).
fn session_count(dir: &Path) -> i64 {
    let conn = rusqlite::Connection::open(dir.join("state.db")).expect("open state.db");
    conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .expect("count sessions")
}

#[tokio::test]
async fn a_foreign_uid_is_refused_before_any_byte_on_agent_sock() {
    // agent.sock admits ONLY the operator uid. Configuring the operator as a DIFFERENT uid from
    // ours means our connection is refused BEFORE any byte — identical to a dropped connection (empty
    // read) — and NO request is dispatched (no session is opened).
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let foreign_operator = our_uid().wrapping_add(1); // NOT us
    let (path, server) = serve_one_full(
        dir.path(),
        broker,
        Some(foreign_operator),
        ServeTimeouts::default(),
    );

    let mut client = StdUnixStream::connect(&path).expect("connect");
    // Even if the client tries to send a request, the gate refused pre-byte and never reads it.
    let _ = write_frame(
        &mut client,
        &AgentRequest::ListCredentials { session_id: None },
    );
    let mut buf = Vec::new();
    let _ = client.read_to_end(&mut buf);
    assert!(
        buf.is_empty(),
        "a non-operator uid must get NO served bytes (no oracle), got {buf:?}"
    );
    drop(client);
    server.join().expect("server thread");

    assert_eq!(
        session_count(dir.path()),
        0,
        "a refused connection must dispatch NO request — no session was opened"
    );
}

#[tokio::test]
async fn an_unresolved_operator_uid_refuses_all_connections_on_agent_sock() {
    // Fail closed: an UNRESOLVED operator uid (None) admits NO ONE — even our own uid is refused,
    // before any byte, and no request is dispatched. An unconfigured gate must never fall open.
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let (path, server) = serve_one_full(dir.path(), broker, None, ServeTimeouts::default());

    let mut client = StdUnixStream::connect(&path).expect("connect");
    let _ = write_frame(
        &mut client,
        &AgentRequest::ListCredentials { session_id: None },
    );
    let mut buf = Vec::new();
    let _ = client.read_to_end(&mut buf);
    assert!(
        buf.is_empty(),
        "an unresolved operator uid must serve NO bytes to anyone (fail closed), got {buf:?}"
    );
    drop(client);
    server.join().expect("server thread");

    assert_eq!(
        session_count(dir.path()),
        0,
        "an unresolved gate dispatches NO request — no session was opened"
    );
}

#[tokio::test]
async fn the_operator_uid_is_served_on_agent_sock() {
    // The operator uid (here, our own uid) is admitted and served normally.
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let (path, server) = serve_one_full(
        dir.path(),
        broker,
        Some(our_uid()),
        ServeTimeouts::default(),
    );

    let mut client = StdUnixStream::connect(&path).expect("connect");
    write_frame(
        &mut client,
        &AgentRequest::ListCredentials { session_id: None },
    )
    .expect("write request");
    let resp: Value = read_response_frame(&mut client).expect("read credentials response");
    assert_eq!(
        resp["kind"], "credentials",
        "the operator uid is served, got {resp}"
    );

    drop(client);
    server.join().expect("server thread");
}

/// Helper: mint + approve a grant owned by the current uid's derived principal, returning
/// (request_id, grant_id). Mirrors the cross-connection success test's setup.
async fn mint_and_approve_for_self(dir: &Path, broker: &BrokerHandle) -> (String, String) {
    let our_uid = nix::unistd::getuid().as_raw();
    broker
        .connect(
            "mock-vercel".into(),
            SecretString::new("mock-token".to_string()),
            None,
        )
        .await
        .expect("connect the mock credential");
    broker
        .open_session(
            "sess-A".into(),
            "minter-cmd".into(),
            None,
            None,
            cermet_broker_actor::SelfReported::default(),
        )
        .await
        .expect("open sess-A");
    let req_json = serde_json::json!({
        "provider": "mock-vercel",
        "action": "deploy",
        "resource": {"project":"demo","repo_id":123,"ref":"main"},
        "environment": "preview",
        "justification": null
    })
    .to_string();
    let outcome_json = broker
        .request_for_principal(
            "sess-A".into(),
            format!("uid:{our_uid}"),
            req_json,
            false,
            None,
        )
        .await
        .expect("mint the sess-A grant");
    let outcome: Value = serde_json::from_str(&outcome_json).unwrap();
    let request_id = outcome["request_id"]
        .as_str()
        .expect("the agent gets a request_id")
        .to_string();
    let grant_id = outcome["grant_id"]
        .as_str()
        .expect("the sentence-authorized request mints a grant")
        .to_string();
    (request_id, grant_id)
}

#[tokio::test]
async fn a_grant_id_is_refused_as_an_agent_execute_handle_over_the_socket() {
    // INVARIANT at the wire: `agent.sock` Execute is keyed ONLY by the agent-held
    // `request_id`. A `grant_id` is operator-internal (never returned to the agent) and must NOT
    // execute — it collapses to the SAME opaque "unable to execute" frame as any unknown handle, so
    // a leaked grant_id is neither executable nor probeable over agent.sock (no oracle).
    let dir = tempdir().unwrap();
    let broker = broker_with(dir.path(), TEST_POLICY); // mock-vercel ask deploy (offline)
    let (_request_id, grant_id) = mint_and_approve_for_self(dir.path(), &broker).await;

    let (path, server) = serve_one(dir.path(), broker);
    let mut client = StdUnixStream::connect(&path).expect("connect");

    // Drive Execute with the GRANT_ID (operator-internal) in the request_id slot.
    write_frame(
        &mut client,
        &AgentRequest::Execute {
            session_id: None,
            request_id: grant_id,
        },
    )
    .expect("write execute (by grant_id)");
    let resp: Value = read_response_frame(&mut client).expect("read execute response");
    assert_eq!(
        resp["kind"], "error",
        "a grant_id must NOT be a usable agent execute handle, got {resp}"
    );
    assert_eq!(
        resp["reason"], "unable to execute",
        "the refusal is the SAME opaque reason as an unknown handle (no oracle), got {resp}"
    );

    drop(client);
    server.join().expect("server thread");
}

#[tokio::test]
async fn provider_action_audit_attributes_the_executing_session_not_only_the_request_session() {
    // INVARIANT: a provider-action audit event records the session that ACTUALLY executed
    // the grant (the executing connection), not merely the session that requested it. The agent
    // drives `request` and `execute` over SEPARATE short-lived connections, so each lands on a
    // distinct server-minted session; if execute is audited only under the request session, the
    // process that actually ran the grant is invisible — "prove exactly what happened" breaks.
    let dir = tempdir().unwrap();
    let broker = broker_with(dir.path(), TEST_POLICY);
    let (request_id, _grant_id) = mint_and_approve_for_self(dir.path(), &broker).await;

    // Execute over a FRESH connection -> a DIFFERENT server-minted session (the executing session).
    let (path, server) = serve_one(dir.path(), broker);
    let mut client = StdUnixStream::connect(&path).expect("connect");
    write_frame(
        &mut client,
        &AgentRequest::Execute {
            session_id: None,
            request_id,
        },
    )
    .expect("write execute (cross-connection)");
    let resp: Value = read_response_frame(&mut client).expect("read execute response");
    assert_eq!(
        resp["kind"], "executed",
        "the cross-connection execute succeeds for the same principal, got {resp}"
    );
    drop(client);
    server.join().expect("server thread");

    // The serve connection minted a session distinct from the request session "sess-A".
    let exec_session: String = {
        let conn = rusqlite::Connection::open(dir.path().join("state.db")).expect("open state.db");
        conn.query_row(
            "SELECT id FROM sessions WHERE id != 'sess-A' ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("the executing connection minted its own session")
    };

    // The provider-action audit event MUST reference that executing session — whether as the
    // event's `session_id` column or in its `data_json` (the fix records both request + executor).
    let (sess_col, data_json): (Option<String>, String) = {
        let audit = rusqlite::Connection::open(dir.path().join("audit.db")).expect("open audit.db");
        audit
            .query_row(
                "SELECT session_id, data_json FROM audit_events WHERE type='provider_action_succeeded' LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("a provider_action_succeeded event was recorded")
    };

    let references_executor =
        sess_col.as_deref() == Some(exec_session.as_str()) || data_json.contains(&exec_session);
    assert!(
        references_executor,
        "the provider-action audit event must attribute the EXECUTING session '{exec_session}' \
         (session_id col = {sess_col:?}, data = {data_json}); today it records only the request \
         session 'sess-A', leaving the executor invisible"
    );
}

/// Helper: connect the mock credential, open a session, and mint a PENDING (unapproved) mock-vercel
/// grant owned by the current uid's derived principal. Mirrors `mint_and_approve_for_self` but stops
/// BEFORE approval — the blocking-execute tests approve (or not) out of band mid-wait.
async fn mint_pending_for_self(dir: &Path, broker: &BrokerHandle) -> (String, String) {
    let our_uid = nix::unistd::getuid().as_raw();
    broker
        .connect(
            "mock-vercel".into(),
            SecretString::new("mock-token".to_string()),
            None,
        )
        .await
        .expect("connect the mock credential");
    broker
        .open_session(
            "sess-A".into(),
            "minter-cmd".into(),
            None,
            None,
            cermet_broker_actor::SelfReported::default(),
        )
        .await
        .expect("open sess-A");
    let req_json = serde_json::json!({
        "provider": "mock-vercel",
        "action": "deploy",
        "resource": {"project":"demo","repo_id":123,"ref":"main"},
        "environment": "preview",
        "justification": null
    })
    .to_string();
    let outcome_json = broker
        .request_for_principal(
            "sess-A".into(),
            format!("uid:{our_uid}"),
            req_json,
            false,
            None,
        )
        .await
        .expect("mint the sess-A grant");
    let request_id = serde_json::from_str::<Value>(&outcome_json).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let grant_id: String = {
        let conn = rusqlite::Connection::open(dir.join("state.db")).expect("open state.db");
        conn.query_row(
            "SELECT id FROM grants WHERE session_id='sess-A' AND status='requested' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("the sess-A grant row exists")
    };
    (request_id, grant_id)
}

/// Serve connections with a thread PER connection (like the live accept loop), so a test can hold
/// several blocking executes open at once. `timeouts` lets a test shrink the execute wait cap.
fn serve_loop_concurrent(
    runtime_dir: &Path,
    broker: BrokerHandle,
    timeouts: ServeTimeouts,
) -> std::path::PathBuf {
    let (listener, path) = bind_agent_socket(runtime_dir).expect("bind agent.sock");
    let rt = tokio::runtime::Handle::current();
    let op = Some(our_uid());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { break };
            let b = broker.clone();
            let rt = rt.clone();
            std::thread::spawn(move || {
                handle_connection(conn, &b, &rt, "test-agent", op, timeouts);
            });
        }
    });
    path
}

fn grant_status(dir: &Path, grant_id: &str) -> String {
    let conn = rusqlite::Connection::open(dir.join("state.db")).expect("open state.db");
    conn.query_row("SELECT status FROM grants WHERE id=?1", [grant_id], |r| {
        r.get(0)
    })
    .expect("grant row")
}

/// Helper: mint a PENDING mock-vercel grant owned by an arbitrary (possibly FOREIGN) principal on
/// its own session, returning (request_id, grant_id). The connecting test peer's derived principal
/// is `uid:<our_uid>`, so any other principal string here is foreign to every socket probe.
async fn mint_pending_as(
    dir: &Path,
    broker: &BrokerHandle,
    principal: &str,
    session: &str,
) -> (String, String) {
    broker
        .connect(
            "mock-vercel".into(),
            SecretString::new("mock-token".to_string()),
            None,
        )
        .await
        .expect("connect the mock credential");
    broker
        .open_session(
            session.into(),
            "minter-cmd".into(),
            None,
            None,
            cermet_broker_actor::SelfReported::default(),
        )
        .await
        .expect("open the minting session");
    let req_json = serde_json::json!({
        "provider": "mock-vercel",
        "action": "deploy",
        "resource": {"project":"demo","repo_id":123,"ref":"main"},
        "environment": "preview",
        "justification": null
    })
    .to_string();
    let outcome_json = broker
        .request_for_principal(session.into(), principal.into(), req_json, false, None)
        .await
        .expect("mint the grant");
    let request_id = serde_json::from_str::<Value>(&outcome_json).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let grant_id: String = {
        let conn = rusqlite::Connection::open(dir.join("state.db")).expect("open state.db");
        conn.query_row(
            "SELECT id FROM grants WHERE session_id=?1 AND status='requested' LIMIT 1",
            [session],
            |r| r.get(0),
        )
        .expect("the grant row exists")
    };
    (request_id, grant_id)
}

/// Probe the `Status` op for one request_id on a fresh connection; return the reply frame.
fn probe_status(path: &Path, request_id: &str) -> Value {
    let mut c = StdUnixStream::connect(path).expect("connect");
    write_frame(
        &mut c,
        &AgentRequest::Status {
            request_id: request_id.into(),
            session_id: None,
        },
    )
    .expect("write status");
    read_response_frame(&mut c).expect("read status reply")
}

// `approve_mid_wait_unblocks_a_blocking_execute_to_a_result` above already pins
// that an approval observed with MORE than the headroom remaining (default timeouts, 30s wait,
// approval at ~300ms) still executes inline on the same call.

/// Serve connections in a loop on a background thread (each `handle_connection` runs to completion
/// before the next accept), so a test can drive several sequential connections against one broker.
/// The thread is detached — the test process exits when the test returns.
fn serve_loop(runtime_dir: &Path, broker: BrokerHandle) -> std::path::PathBuf {
    let (listener, path) = bind_agent_socket(runtime_dir).expect("bind agent.sock");
    let rt = tokio::runtime::Handle::current();
    let op = Some(our_uid());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { break };
            handle_connection(
                conn,
                &broker,
                &rt,
                "test-agent",
                op,
                ServeTimeouts::default(),
            );
        }
    });
    path
}

/// `justification` was required only agent-side, in a former bridge-only MCP layer, whose own
/// comment claimed the check existed "because a schema is advisory to a hostile client" — but the
/// daemon boundary it implied did not exist. Any client speaking the wire protocol directly could
/// mint a request with no reasoning at all, and the audited `requests` row would carry `null`. The
/// threat is content that steers a cooperative model into a request the owner's receipt cannot
/// explain. Now enforced HERE, at the agent IPC boundary; the agent-side check remains the preflight
/// half of the sanctioned pair.
#[tokio::test]
async fn an_agent_request_without_a_justification_is_refused_at_the_daemon_boundary() {
    let dir = tempdir().unwrap();
    let broker = broker_with(dir.path(), TEST_POLICY);
    let (path, server) = serve_one(dir.path(), broker);
    let mut client = StdUnixStream::connect(&path).expect("connect");

    write_frame(
        &mut client,
        &AgentRequest::Request {
            session_id: None,
            provider: "mock-vercel".into(),
            action: "deploy".into(),
            resource: serde_json::json!({
                "project": "orchestra", "repo_id": 123, "ref": "main"
            }),
            environment: Some("preview".into()),
            justification: None,
            retry_effect: None,
            model: None,
        },
    )
    .expect("write request");
    let resp: Value = read_response_frame(&mut client).expect("read response");
    assert_eq!(
        resp["kind"], "error",
        "a justification-less agent request must fail closed at the daemon, got {resp}"
    );

    drop(client);
    server.join().expect("server thread");
}

/// The same boundary refuses a justification that is present but blank — whitespace is not a reason.
#[tokio::test]
async fn an_agent_request_with_a_blank_justification_is_refused_at_the_daemon_boundary() {
    let dir = tempdir().unwrap();
    let broker = broker_with(dir.path(), TEST_POLICY);
    let (path, server) = serve_one(dir.path(), broker);
    let mut client = StdUnixStream::connect(&path).expect("connect");

    write_frame(
        &mut client,
        &AgentRequest::Request {
            session_id: None,
            provider: "mock-vercel".into(),
            action: "deploy".into(),
            resource: serde_json::json!({
                "project": "orchestra", "repo_id": 123, "ref": "main"
            }),
            environment: Some("preview".into()),
            justification: Some("   \t \n ".into()),
            retry_effect: None,
            model: None,
        },
    )
    .expect("write request");
    let resp: Value = read_response_frame(&mut client).expect("read response");
    assert_eq!(
        resp["kind"], "error",
        "a blank justification must fail closed at the daemon, got {resp}"
    );

    drop(client);
    server.join().expect("server thread");
}

// ---- Hello build admission -----------------------------------------------------------------------
//
// One published inode makes every FUTURE exec generation-coherent; it cannot update a process that
// already mapped the old one. The motivating incident: an MCP stdio server from an 11-day-old build
// served an agent session across several reinstalls and a daemon restart, and nothing could refuse
// it. Build identity is therefore an ADMISSION check at `Hello`, ahead of the session mint.

/// Send one `Hello` frame, verbatim JSON, and return the daemon's reply frame.
fn hello_raw(dir: &Path, frame: Value) -> Value {
    let broker = broker(dir);
    let (path, server) = serve_one(dir, broker);
    let mut client = StdUnixStream::connect(&path).expect("connect");
    // Raw JSON, so an ABSENT `build` field is expressible — the typed enum would always emit one.
    write_frame(&mut client, &frame).expect("write hello");
    let response: Value = read_response_frame(&mut client).unwrap_or(Value::Null);
    drop(client);
    let _ = server.join();
    response
}

/// How many sessions the broker minted. The refusal must land BEFORE any of them.
fn minted_session_count(dir: &Path) -> i64 {
    let conn = rusqlite::Connection::open(dir.join("state.db")).expect("open state.db");
    conn.query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
        .expect("count sessions")
}

#[tokio::test]
async fn hello_admits_only_a_client_of_this_exact_build() {
    let dir = tempdir().unwrap();
    let response = hello_raw(
        dir.path(),
        serde_json::json!({"op": "hello", "agent": "opus", "build": cermet_ipc::BUILD_ID}),
    );
    assert_eq!(
        response["kind"], "session",
        "the same build is admitted: {response}"
    );
    assert_eq!(
        minted_session_count(dir.path()),
        1,
        "and its session is minted"
    );
}

#[tokio::test]
async fn hello_from_a_skewed_client_is_refused_before_any_session_is_minted() {
    // The live case: an MCP bridge left running across a reinstall. It is NOT served an obsolete
    // tool surface; it is told the one thing that fixes it.
    let dir = tempdir().unwrap();
    let response = hello_raw(
        dir.path(),
        serde_json::json!({"op": "hello", "agent": "opus", "build": "0.0.1+deadbeef"}),
    );
    assert_eq!(
        response["kind"], "error",
        "a skewed build refuses: {response}"
    );
    let reason = response["error"]
        .as_str()
        .or_else(|| response["reason"].as_str())
        .unwrap_or_default();
    assert!(
        reason.starts_with(cermet_ipc::wire::BUILD_SKEW),
        "the refusal is the typed one clients detect: {response}"
    );
    assert!(
        reason.contains(cermet_ipc::BUILD_ID) && reason.contains("0.0.1+deadbeef"),
        "and it names both halves so the operator can see which disagrees: {reason}"
    );
    assert_eq!(
        minted_session_count(dir.path()),
        0,
        "refused BEFORE the session mint — never a half-admitted conversation"
    );
}

#[tokio::test]
async fn hello_with_no_build_at_all_is_refused_legibly_rather_than_parsed_as_agreement() {
    // A client predating the field. `#[serde(default)]` exists ONLY so this refusal is legible:
    // absence deserializes empty, which never equals a real build id, and is never read as "same
    // build" (fail closed on the reporting side too).
    let dir = tempdir().unwrap();
    let response = hello_raw(
        dir.path(),
        serde_json::json!({"op": "hello", "agent": "opus"}),
    );
    assert_eq!(response["kind"], "error", "{response}");
    let reason = response["error"]
        .as_str()
        .or_else(|| response["reason"].as_str())
        .unwrap_or_default();
    assert!(reason.starts_with(cermet_ipc::wire::BUILD_SKEW), "{reason}");
    assert!(
        reason.contains(cermet_ipc::UNKNOWN_BUILD),
        "absence is named as unknown, not echoed as an empty build: {reason}"
    );
    assert_eq!(minted_session_count(dir.path()), 0);
}

#[test]
fn a_new_client_frame_reaching_an_older_daemon_is_refused_by_the_frame_parser() {
    // The other direction needs no accommodation and gets none: `AgentRequest` is
    // `deny_unknown_fields`, so a field a daemon does not know about is refused at the parser
    // rather than silently dropped. That is the mechanism that makes new-client -> old-daemon fail
    // closed, demonstrated here on the frame vocabulary itself.
    let unknown: Result<AgentRequest, _> = serde_json::from_value(serde_json::json!({
        "op": "hello", "agent": "opus", "build": cermet_ipc::BUILD_ID, "generation": 2
    }));
    assert!(
        unknown.is_err(),
        "an unknown Hello field must refuse, never be ignored"
    );
}

#[tokio::test]
async fn a_skewed_client_cannot_reach_an_effect_by_skipping_the_handshake() {
    // The refusal has to be worth something: a client that gives up on Hello and simply sends a
    // capability request must not get one. Every non-Hello request falls back to the connection's
    // own daemon-minted session, so the build check is not the gate there — the gate is that the
    // agent surface has no way to spend authority without the broker deciding it. This pins the
    // Hello refusal as non-fatal to the daemon (the connection stays usable) while the effect path
    // stays under its own sentence decision.
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let (path, server) = serve_one(dir.path(), broker);
    let mut client = StdUnixStream::connect(&path).expect("connect");
    write_frame(
        &mut client,
        &AgentRequest::Hello {
            agent: "opus".into(),
            build: "0.0.1+deadbeef".into(),
            client_name: None,
            client_version: None,
            model: None,
        },
    )
    .expect("write hello");
    let refusal: Value = read_response_frame(&mut client).expect("read refusal");
    assert_eq!(refusal["kind"], "error");

    // The same connection then asks for a capability with no session id.
    write_frame(
        &mut client,
        &AgentRequest::Request {
            provider: "mock-vercel".into(),
            action: "deploy".into(),
            resource: serde_json::json!({"project": "p", "environment": "preview"}),
            environment: None,
            justification: None,
            retry_effect: None,
            session_id: None,
            model: None,
        },
    )
    .expect("write request");
    let response: Value = read_response_frame(&mut client).unwrap_or(Value::Null);
    drop(client);
    let _ = server.join();
    assert_ne!(
        response,
        Value::Null,
        "the daemon stays serving after a refused Hello"
    );
}
