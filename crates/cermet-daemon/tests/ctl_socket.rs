#![allow(dead_code, unused_variables, unused_imports)]

//! Integration tests for the `ctl.sock` operator channel.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::sync::Arc;

use cermet_broker_actor::{spawn, BrokerHandle};
use cermet_core::BrokerConfig;
use cermet_daemon::ctl::{bind_ctl_socket, handle_ctl_connection};
use cermet_daemon::sentence_record::{build_record_store, NoopAuditSink, SentenceRecordAdmin};
use cermet_daemon::serve::{bind_agent_socket, handle_connection, ServeTimeouts};
use cermet_ipc::codec::{read_response_frame, write_frame, MAX_FRAME};
use cermet_ipc::ctl::{CtlRequest, RedactedToken};
use cermet_ipc::wire::AgentRequest;
use serde_json::{json, Value};
use tempfile::tempdir;

/// A synthetic "daemon runs as this service uid" used by the ctl harness so the `peer != daemon`
/// gate is satisfiable in tests: the test process's peer uid is `getuid()`, which
/// must differ from the daemon uid for an approver==peer to be authorized. Chosen far from any real
/// login uid; the happy-path tests pass `approver = getuid()` so `getuid() != THIS` holds.
const TEST_DAEMON_UID: u32 = 999_001;

const VERCEL_ASK_POLICY: &str = "providers:\n  vercel:\n    ask:\n      - action: deploy\n";

struct ClearLockdown;

impl cermet_core::LockdownSource for ClearLockdown {
    fn is_engaged(&self) -> bool {
        false
    }
}

fn clear_lockdown() -> Arc<dyn cermet_core::LockdownSource> {
    Arc::new(ClearLockdown)
}

struct EngagedLockdown;

impl cermet_core::LockdownSource for EngagedLockdown {
    fn is_engaged(&self) -> bool {
        true
    }
}

fn engaged_lockdown() -> Arc<dyn cermet_core::LockdownSource> {
    Arc::new(EngagedLockdown)
}

/// A default (unused-by-the-test) sentence record admin over a fresh state dir owned by us — supplied
/// to the ctl serve helpers whose test focus is not the sentence ceremony.
fn default_record_admin(dir: &Path) -> Arc<dyn SentenceRecordAdmin> {
    build_record_store(dir, None)
}

fn broker(dir: &Path) -> BrokerHandle {
    spawn(BrokerConfig {
        git: cermet_core::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
        dir: dir.to_path_buf(),
        master_key: vec![7u8; 32],
        action_templates: cermet_core::templates::VENDORED_CATALOG
            .iter()
            .map(|s| s.to_string())
            .collect(),
        provider_descriptors: BrokerConfig::vendored_descriptors(),
        artifacts: cermet_core::ArtifactConfig::default(),
    })
    .expect("broker opens")
}

fn serve_agent_one(
    dir: &Path,
    broker: BrokerHandle,
) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    let (listener, path) = bind_agent_socket(dir).expect("bind agent.sock");
    let rt = tokio::runtime::Handle::current();
    let handle = std::thread::spawn(move || {
        let (conn, _addr) = listener.accept().expect("accept");
        // Single-operator gate: agent.sock admits ONLY the operator uid. These same-uid tests
        // connect as our own uid, so the operator uid IS our uid.
        handle_connection(
            conn,
            &broker,
            &rt,
            "test-agent",
            Some(nix::unistd::getuid().as_raw()),
            ServeTimeouts::default(),
        );
    });
    (path, handle)
}

fn serve_ctl_one(
    dir: &Path,
    broker: BrokerHandle,
    approver_uid: u32,
) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    serve_ctl_shared(dir, broker, approver_uid)
}

fn serve_ctl_shared(
    dir: &Path,
    broker: BrokerHandle,
    approver_uid: u32,
) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    serve_ctl_shared_with(dir, broker, approver_uid, ServeTimeouts::default())
}

/// As [`serve_ctl_shared`], but with caller-chosen timeouts (e.g. a tiny `response_budget`).
fn serve_ctl_shared_with(
    dir: &Path,
    broker: BrokerHandle,
    approver_uid: u32,
    timeouts: ServeTimeouts,
) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    // The daemon uid is synthetic + distinct from the test's peer uid so the
    // `peer != daemon` gate is satisfiable; the approver is supplied per-test.
    serve_ctl_shared_with_daemon(
        dir,
        broker,
        approver_uid,
        TEST_DAEMON_UID,
        timeouts,
        false,
        true,
    )
}

/// As [`serve_ctl_shared_with`], but with an explicit daemon uid (for the approver==daemon
/// collapse test). `handle_ctl_connection` takes `(approver_uid, agent_uid, daemon_uid, ..)`.
fn serve_ctl_shared_with_daemon(
    dir: &Path,
    broker: BrokerHandle,
    approver_uid: u32,
    daemon_uid: u32,
    timeouts: ServeTimeouts,
    service_mode: bool,
    sentence_rules_configured: bool,
) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    let record_admin = default_record_admin(dir);
    let (listener, path) = bind_ctl_socket(dir).expect("bind ctl.sock");
    let rt = tokio::runtime::Handle::current();
    let home = dir.to_path_buf();
    let runtime = dir.to_path_buf();
    let handle = std::thread::spawn(move || {
        let (conn, _addr) = listener.accept().expect("accept");
        handle_ctl_connection(
            conn,
            &broker,
            &rt,
            approver_uid,
            // dev same-uid: the agent uid collapses onto the daemon uid.
            daemon_uid,
            daemon_uid,
            &home,
            &runtime,
            // dev tests collapse the agent dir onto the runtime dir.
            &runtime,
            // dev-mode doctor defaults (no approvers/agents gid, warn-and-serve) — these ctl tests
            // exercise the pre-flip same-uid path.
            timeouts,
            None,
            None,
            service_mode,
            // dev-shape ctl tests: no service key custody rung.
            None,
            sentence_rules_configured,
            &record_admin,
            &clear_lockdown(),
        );
    });
    (path, handle)
}

/// Serve one ctl connection backed by a caller-supplied sentence RECORD admin (the unified store).
fn serve_ctl_with_record_admin(
    dir: &Path,
    broker: BrokerHandle,
    approver_uid: u32,
    admin: Arc<dyn SentenceRecordAdmin>,
) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    serve_ctl_with_record_admin_and_lockdown(dir, broker, approver_uid, admin, clear_lockdown())
}

fn serve_ctl_with_record_admin_and_lockdown(
    dir: &Path,
    broker: BrokerHandle,
    approver_uid: u32,
    admin: Arc<dyn SentenceRecordAdmin>,
    lockdown: Arc<dyn cermet_core::LockdownSource>,
) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
    let (listener, path) = bind_ctl_socket(dir).expect("bind ctl.sock");
    let rt = tokio::runtime::Handle::current();
    let home = dir.to_path_buf();
    let runtime = dir.to_path_buf();
    let handle = std::thread::spawn(move || {
        let (conn, _addr) = listener.accept().expect("accept");
        handle_ctl_connection(
            conn,
            &broker,
            &rt,
            approver_uid,
            TEST_DAEMON_UID,
            TEST_DAEMON_UID,
            &home,
            &runtime,
            &runtime,
            ServeTimeouts::default(),
            None,
            None,
            false,
            None,
            true,
            &admin,
            &lockdown,
        );
    });
    (path, handle)
}

#[tokio::test]
async fn sentence_stage_commit_is_live_for_the_approver_and_denied_to_a_non_approver() {
    let dir = tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    // The record + staged files live under a fresh state dir owned by us (test uid == approver uid).
    let state = tempdir().unwrap();
    let store: Arc<dyn SentenceRecordAdmin> = build_record_store(state.path(), None);

    let (path, server) =
        serve_ctl_with_record_admin(dir.path(), broker(dir.path()), uid, store.clone());
    let mut client = StdUnixStream::connect(path).unwrap();

    // Absent authority.
    write_frame(&mut client, &CtlRequest::SentenceSnapshot).unwrap();
    let snap: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(snap["kind"], "ok", "{snap}");
    assert_eq!(snap["view"]["state"], "Absent", "{snap}");

    // Round one: stage. The daemon echoes its canonical form + a token; NOTHING is authoritative yet.
    write_frame(
        &mut client,
        &CtlRequest::StageSentences {
            candidate_text: "allow stripe.refund where amount <= 5000\n".into(),
        },
    )
    .unwrap();
    let staged: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(staged["kind"], "ok", "{staged}");
    let token = staged["view"]["staging_token"]
        .as_str()
        .unwrap()
        .to_string();
    let digest = staged["view"]["canonical_digest"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        digest, token,
        "a staging nonce is not the candidate digest: {staged}"
    );

    // Still absent until commit.
    write_frame(&mut client, &CtlRequest::SentenceSnapshot).unwrap();
    let snap: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(
        snap["view"]["state"], "Absent",
        "stage installs no authority: {snap}"
    );

    // Round two: commit the token → the generation flips.
    write_frame(
        &mut client,
        &CtlRequest::CommitSentences {
            preset: None,
            staging_token: token.clone(),
        },
    )
    .unwrap();
    let committed: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(committed["kind"], "ok", "{committed}");
    assert_eq!(committed["view"]["outcome"], "Committed", "{committed}");
    assert_eq!(committed["view"]["canonical_digest"], digest, "{committed}");
    assert!(
        committed["view"]["occurrence_id"].is_string(),
        "{committed}"
    );

    // Snapshot now Served through the process-lifetime semantic validation gate.
    write_frame(&mut client, &CtlRequest::SentenceSnapshot).unwrap();
    let snap: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(snap["view"]["state"], "Served", "{snap}");
    assert_eq!(snap["view"]["rule_count"], 1, "{snap}");
    assert_eq!(snap["view"]["authority_digest"], digest, "{snap}");
    assert_eq!(
        snap["view"]["occurrence_id"], committed["view"]["occurrence_id"],
        "{snap}"
    );

    // An unknown/stale token is denied and writes nothing.
    write_frame(
        &mut client,
        &CtlRequest::CommitSentences {
            preset: None,
            staging_token: "deadbeef".repeat(8),
        },
    )
    .unwrap();
    let stale: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(stale["kind"], "error", "{stale}");
    assert_eq!(stale["code"], "denied", "{stale}");
    drop(client);
    server.join().unwrap();

    // A non-approver uid is served nothing (the ctl gate, not the record admin).
    let state2 = tempdir().unwrap();
    let store2: Arc<dyn SentenceRecordAdmin> = build_record_store(state2.path(), None);
    let (path, server) =
        serve_ctl_with_record_admin(dir.path(), broker(dir.path()), uid.wrapping_add(1), store2);
    let mut client = StdUnixStream::connect(path).unwrap();
    let _ = write_frame(&mut client, &CtlRequest::SentenceSnapshot);
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    assert!(response.is_empty(), "a non-approver is served nothing");
    drop(client);
    server.join().unwrap();
}

#[tokio::test]
async fn prepare_is_non_mutating_and_stage_reuses_its_pinned_canonical_form() {
    let dir = tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let state = tempdir().unwrap();
    let store = build_record_store(state.path(), None);
    let live = store
        .stage("allow stripe.refund where amount <= 5000\n")
        .unwrap();
    store.commit(&live.staging_token, &NoopAuditSink).unwrap();
    let pending = store
        .stage("allow stripe.refund where amount <= 6000\n")
        .unwrap();
    let live_before = store.snapshot().unwrap();
    let staged_before = store.peek_staged_text(&pending.staging_token).unwrap();
    let broker = broker(dir.path());
    let audit_before: i64 = rusqlite::Connection::open(dir.path().join("audit.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
        .unwrap();
    let (path, server) = serve_ctl_with_record_admin_and_lockdown(
        dir.path(),
        broker,
        uid,
        store.clone(),
        engaged_lockdown(),
    );
    let mut client = StdUnixStream::connect(path).unwrap();

    write_frame(&mut client, &CtlRequest::SentenceAuthorityStatus).unwrap();
    let status_before: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(status_before["view"]["sentence"]["state"], "Served");
    assert_eq!(status_before["view"]["lockdown"], "engaged");

    // A set is spelled by its immutable expansion; prepare must accept the
    // authored bytes verbatim (whitespace and comments aside) and canonicalize them.
    let candidate = format!(
        "# draft\n allow   stripe.support@{}\n",
        cermet_core::sets::SetResolver::current_snapshot(
            &cermet_core::sets::VendoredSetResolver,
            "stripe",
            "support"
        )
        .expect("the vendored support set")
        .digest()
    );
    write_frame(
        &mut client,
        &CtlRequest::PrepareSentences {
            candidate_text: candidate.clone(),
        },
    )
    .unwrap();
    let prepared: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(prepared["kind"], "ok", "{prepared}");
    let canonical = prepared["view"]["canonical_text"]
        .as_str()
        .expect("prepared canonical text")
        .to_string();
    assert!(canonical.contains("stripe.support@sha256:"), "{prepared}");
    assert_eq!(store.snapshot().unwrap(), live_before);
    assert_eq!(
        store.peek_staged_text(&pending.staging_token).unwrap(),
        staged_before,
        "preparation must not rewrite or consume an existing staged corpus"
    );
    const LOG_CANARY: &str = "M2_PREPARE_AUDIT_LOG_CANARY";
    write_frame(
        &mut client,
        &CtlRequest::PrepareSentences {
            candidate_text: format!(
                "allow stripe.refund where amount = \"safe\" and rate 1 per {LOG_CANARY}\n"
            ),
        },
    )
    .unwrap();
    let rejected: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(rejected["kind"], "error", "{rejected}");
    assert!(
        !rejected.to_string().contains(LOG_CANARY),
        "the ctl error must not echo the malformed token: {rejected}"
    );
    let audit_after: i64 = rusqlite::Connection::open(dir.path().join("audit.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        audit_after, audit_before,
        "preparation must not append audit"
    );
    write_frame(&mut client, &CtlRequest::SentenceAuthorityStatus).unwrap();
    let status_after: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(status_after["view"], status_before["view"]);

    write_frame(
        &mut client,
        &CtlRequest::StageSentences {
            candidate_text: candidate.clone(),
        },
    )
    .unwrap();
    let staged: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(staged["kind"], "ok", "{staged}");
    assert_eq!(staged["view"]["canonical_text"], canonical, "{staged}");
    assert_eq!(
        store.snapshot().unwrap(),
        live_before,
        "staging must remain non-authoritative"
    );
    write_frame(&mut client, &CtlRequest::SentenceAuthorityStatus).unwrap();
    let status: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(status["view"]["sentence"]["state"], "Served", "{status}");
    assert_eq!(status["view"]["lockdown"], "engaged", "{status}");
    assert_eq!(
        store.peek_staged_text(&pending.staging_token).unwrap(),
        staged_before,
        "a separate stage must not alter the pre-existing staged corpus"
    );
    drop(client);
    server.join().unwrap();
}

#[tokio::test]
async fn prepare_accepts_exact_serialized_frame_cap_and_rejects_one_byte_over_real_framing() {
    let dir = tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (path, server) = serve_ctl_one(dir.path(), broker(dir.path()), uid);
    let mut client = StdUnixStream::connect(path).unwrap();

    let seed = CtlRequest::PrepareSentences {
        candidate_text: "#".into(),
    };
    let seed_len = serde_json::to_vec(&seed).unwrap().len();
    let exact = CtlRequest::PrepareSentences {
        candidate_text: format!("#{}", "x".repeat(MAX_FRAME as usize - seed_len)),
    };
    assert_eq!(
        serde_json::to_vec(&exact).unwrap().len(),
        MAX_FRAME as usize
    );
    write_frame(&mut client, &exact).expect("an exact-cap serialized request must be framed");
    let accepted: Value = read_response_frame(&mut client).unwrap();
    assert_eq!(accepted["kind"], "ok", "{accepted}");

    let over = CtlRequest::PrepareSentences {
        candidate_text: format!("#{}", "x".repeat(MAX_FRAME as usize + 1 - seed_len)),
    };
    let over_body = serde_json::to_vec(&over).unwrap();
    assert_eq!(over_body.len(), MAX_FRAME as usize + 1);
    client
        .write_all(&(over_body.len() as u32).to_le_bytes())
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert!(
        response.is_empty(),
        "the real decoder must reject an over-cap frame before dispatch: {response:?}"
    );

    drop(client);
    server.join().unwrap();
}

/// The keyholder-cutover linchpin. A credential is INGESTED into the daemon's vault over
/// `ctl.sock` (the only channel `cermet-app`, as the approver uid, can reach), then read back via
/// `ListCredentials` — proving the daemon can be the sole keyholder. The raw token must NEVER be
/// echoed back on either reply (the "raw credential never leaves the core" invariant, ingestion side).
#[tokio::test]
async fn connect_then_list_over_ctl_ingests_into_the_daemon_vault() {
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let uid = nix::unistd::getuid().as_raw();
    let (cpath, cserver) = serve_ctl_one(dir.path(), broker.clone(), uid);
    let mut c = StdUnixStream::connect(&cpath).expect("connect ctl");

    const RAW_TOKEN: &str = "tok_super_secret_value_42";
    write_frame(
        &mut c,
        &CtlRequest::Connect {
            provider: "stripe".into(),
            account_label: Some("acme".into()),
            token: RedactedToken(RAW_TOKEN.into()),
        },
    )
    .unwrap();
    let resp: Value = read_response_frame(&mut c).expect("connect outcome");
    assert_eq!(resp["kind"], "ok", "uniform cutover envelope, got {resp}");
    assert_eq!(
        resp["view"]["stored"],
        json!(true),
        "the credential was stored, got {resp}"
    );
    assert_eq!(resp["view"]["provider"], "stripe");
    assert!(
        !serde_json::to_string(&resp).unwrap().contains(RAW_TOKEN),
        "the raw token must never be echoed back on the connect reply: {resp}"
    );

    write_frame(&mut c, &CtlRequest::ListCredentials).unwrap();
    let creds: Value = read_response_frame(&mut c).expect("credentials");
    assert_eq!(creds["kind"], "ok", "got {creds}");
    let arr = creds["view"].as_array().expect("credentials view array");
    assert!(
        arr.iter().any(|c| c["provider"] == "stripe"),
        "stripe is now a connected provider in the daemon vault, got {creds}"
    );
    assert!(
        !serde_json::to_string(&creds).unwrap().contains(RAW_TOKEN),
        "list_credentials must not leak the token: {creds}"
    );

    drop(c);
    cserver.join().expect("ctl server");
}

/// The operator execute op is WIRED and fails closed on an unknown request — proving the dispatch
/// without a live provider call (a real execute would hit the network). The session-scoped
/// grant-keyed shape is gone from ctl; `ExecuteOperator` is the whole operator execute surface.
#[tokio::test]
async fn ctl_execute_ops_fail_closed_for_unknown_grant() {
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let uid = nix::unistd::getuid().as_raw();
    let (cpath, cserver) = serve_ctl_one(dir.path(), broker.clone(), uid);
    let mut c = StdUnixStream::connect(&cpath).expect("connect ctl");

    write_frame(
        &mut c,
        &CtlRequest::ExecuteOperator {
            request_id: "does_not_exist".into(),
        },
    )
    .unwrap();
    let exop: Value = read_response_frame(&mut c).expect("execute_operator reply");
    assert_eq!(
        exop["kind"], "error",
        "operator-execute of an unknown request id fails closed, got {exop}"
    );

    drop(c);
    cserver.join().expect("ctl server");
}

#[tokio::test]
async fn malformed_artifact_path_over_ctl_sock_fails_closed_opaque() {
    // A raw ctl frame bypasses the friendly CLI parser, so the shared boundary must reject
    // malformed path grammar itself. Seed a blob whose JSON contains empty-string keys — `$.`,
    // `$..x`, `$.a.` must NOT resolve against them; each collapses to the SAME opaque
    // not_found/"artifact unavailable" as an unknown handle. A well-formed path still reads.
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let uid = nix::unistd::getuid().as_raw();

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

    let (cpath, cserver) = serve_ctl_one(dir.path(), broker.clone(), uid);
    let mut c = StdUnixStream::connect(&cpath).expect("connect ctl");

    for bad in ["$.", "$..x", "$.a.", "a.b"] {
        write_frame(
            &mut c,
            &CtlRequest::ReadArtifact {
                handle: handle.clone(),
                range: None,
                path: Some(bad.to_string()),
            },
        )
        .unwrap();
        let resp: Value = read_response_frame(&mut c).expect("bad-path reply");
        assert_eq!(
            resp["kind"], "error",
            "path {bad:?} must fail closed, got {resp}"
        );
        assert_eq!(
            resp["code"], "not_found",
            "path {bad:?} joins the same opaque class as an unknown handle, got {resp}"
        );
        assert_eq!(resp["reason"], "artifact unavailable", "got {resp}");
        assert!(
            !resp.to_string().contains("leak"),
            "no empty-key value may escape for {bad:?}: {resp}"
        );
    }

    // The well-formed pointer still resolves over the same connection.
    write_frame(
        &mut c,
        &CtlRequest::ReadArtifact {
            handle: handle.clone(),
            range: None,
            path: Some("$.ok".to_string()),
        },
    )
    .unwrap();
    let resp: Value = read_response_frame(&mut c).expect("good-path reply");
    assert_eq!(resp["kind"], "ok", "got {resp}");
    assert_eq!(resp["view"]["unit"], "path", "got {resp}");
    assert_eq!(
        resp["view"]["path"], "$.ok",
        "the pointer is echoed, got {resp}"
    );
    assert_eq!(resp["view"]["content"], "\"yes\"", "got {resp}");

    drop(c);
    cserver.join().expect("ctl server");
}

/// End-to-end: when the connecting peer IS the daemon uid, the ctl plane refuses it even
/// though peer==daemon — post-flip the service account must not be able to drive ctl. Here the
/// test's real peer uid is `getuid()`, so we set `daemon_uid = getuid()` and `approver = getuid()`
/// (collapse): the gate denies-all, served-nothing.

#[tokio::test]
async fn ctl_doctor_reports_the_uid_collapse() {
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let uid = nix::unistd::getuid().as_raw();
    let (cpath, cserver) = serve_ctl_one(dir.path(), broker, uid);

    let mut c = StdUnixStream::connect(&cpath).expect("connect ctl");
    write_frame(&mut c, &CtlRequest::Doctor).expect("write doctor");
    let d: Value = read_response_frame(&mut c).expect("doctor report");
    assert_eq!(d["kind"], "doctor");
    assert_eq!(d["serving"], json!(true), "warn loudly, keep serving");
    let checks = d["checks"].as_array().expect("checks");
    let uid_check = checks
        .iter()
        .find(|c| c["name"] == "uid_boundary")
        .expect("a uid_boundary check");
    assert_eq!(
        uid_check["status"], "warn",
        "the same-uid collapse is a loud warning"
    );
    drop(c);
    cserver.join().expect("ctl server");
}

#[tokio::test]
async fn ctl_doctor_reports_unconfigured_sentence_authority_from_live_config() {
    let dir = tempdir().unwrap();
    let uid = nix::unistd::getuid().as_raw();
    let (cpath, cserver) = serve_ctl_shared_with_daemon(
        dir.path(),
        broker(dir.path()),
        uid,
        TEST_DAEMON_UID,
        ServeTimeouts::default(),
        true,
        false,
    );
    let mut client = StdUnixStream::connect(cpath).expect("connect ctl");
    write_frame(&mut client, &CtlRequest::Doctor).expect("write doctor");
    let report: Value = read_response_frame(&mut client).expect("doctor report");
    let authority = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "sentence_authority")
        .expect("sentence authority check");
    assert_eq!(authority["status"], "warn", "{report}");
    assert!(
        authority["detail"]
            .as_str()
            .unwrap()
            .contains("sentence_rules_path is unset"),
        "{report}"
    );
    drop(client);
    cserver.join().expect("ctl server");
}

/// ctl has no hello frame, so the daemon stamps the build it IS onto its ctl replies —
/// the ok envelope, the error envelope, and the doctor report alike. That stamp is what lets a
/// `cermet` binary installed weeks ago notice it is not the daemon's build.
#[tokio::test]
async fn ctl_replies_carry_the_daemons_build_identity() {
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let uid = nix::unistd::getuid().as_raw();
    let (cpath, cserver) = serve_ctl_one(dir.path(), broker, uid);
    let mut c = StdUnixStream::connect(&cpath).expect("connect ctl");

    write_frame(&mut c, &CtlRequest::ListCredentials).expect("write list");
    let ok: Value = read_response_frame(&mut c).expect("credentials");
    assert_eq!(ok["kind"], "ok");
    assert_eq!(ok["build"], cermet_ipc::BUILD_ID, "ok envelope: {ok}");

    write_frame(
        &mut c,
        &CtlRequest::ExecuteOperator {
            request_id: "req_does_not_exist".into(),
        },
    )
    .expect("write execute");
    let err: Value = read_response_frame(&mut c).expect("error envelope");
    assert_eq!(err["kind"], "error");
    assert_eq!(err["build"], cermet_ipc::BUILD_ID, "error envelope: {err}");

    write_frame(&mut c, &CtlRequest::Doctor).expect("write doctor");
    let doctor: Value = read_response_frame(&mut c).expect("doctor report");
    assert_eq!(doctor["kind"], "doctor");
    assert_eq!(
        doctor["build"],
        cermet_ipc::BUILD_ID,
        "doctor report: {doctor}"
    );

    drop(c);
    cserver.join().expect("ctl server");
}
