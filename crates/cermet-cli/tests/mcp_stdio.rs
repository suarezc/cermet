//! End-to-end MCP-over-stdio test against a STUB `agent.sock`.
//!
//! Unlike the in-module unit tests (which fake the transport), this drives the full bridge:
//! `serve` → `SocketTransport::call` → the moved bridge call → the length-prefixed codec over a real
//! unix socket. The stub is a canned responder — one framed request in, one framed reply out —
//! same-uid, so it needs no daemon, broker, or vault.

use std::io::{Cursor, Write};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;

use cermet_cli::mcp_bridge::server::{serve, SocketTransport};
use cermet_ipc::codec::{read_frame, write_response_frame};
use cermet_ipc::wire::AgentRequest;
use serde_json::{json, Value};
use tempfile::tempdir;

/// A `Write` sink the test still holds after `serve` consumes it — `serve` takes the writer by
/// value so it can share it across worker threads.
#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);
impl SharedBuf {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}
impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Bind a stub `agent.sock` that first answers the `Hello` handshake with a minted session, then
/// answers the real request with `reply` — asserting the real request matches `expect` AND carries
/// the minted session id. Two connections: the bridge's `hello` opens one, the actual call another.
fn stub_socket(
    dir: &std::path::Path,
    expect: AgentRequest,
    reply: Value,
) -> (std::path::PathBuf, thread::JoinHandle<()>) {
    // A CURRENT daemon: it advertises the build it is, so no test below grows a build-skew note
    // it did not ask about.
    stub_socket_built(dir, expect, reply, Some(cermet_ipc::BUILD_ID))
}

/// As [`stub_socket`], with control over the `build` the stub daemon advertises: `None` models a
/// daemon PREDATING the build-identity field.
fn stub_socket_built(
    dir: &std::path::Path,
    mut expect: AgentRequest,
    reply: Value,
    build: Option<&str>,
) -> (std::path::PathBuf, thread::JoinHandle<()>) {
    let path = dir.join("agent.sock");
    let build = build.map(str::to_string);
    let listener = UnixListener::bind(&path).expect("bind stub agent.sock");
    let handle = thread::spawn(move || {
        // Connection 1: the handshake. The bridge mints its conversation session before the call.
        let (mut c1, _) = listener.accept().expect("accept handshake");
        let hello: AgentRequest = read_frame(&mut c1).expect("read the hello frame");
        assert!(
            matches!(hello, AgentRequest::Hello { .. }),
            "the bridge's first frame must be the Hello handshake, got {hello:?}"
        );
        // Async execute: the stub models a CURRENT daemon, so it advertises the negotiated
        // feature set — the async surface fails closed (before any claim, no conn 2) against a
        // featureless session frame, which would strand this stub's second accept forever.
        let mut session = json!({
            "kind": "session",
            "session_id": "sess_stub",
            "features": cermet_ipc::wire::DAEMON_FEATURES,
        });
        if let Some(build) = build {
            session["build"] = json!(build);
        }
        write_response_frame(&mut c1, &session).expect("write the session reply");
        drop(c1);

        // Money-safe async execute derives its effect handle from the broker's authenticated status
        // projection before starting; ordinary requests have no preflight.
        if let AgentRequest::Execute { request_id, .. } = &expect {
            let (mut status_conn, _) = listener.accept().expect("accept status preflight");
            let status: AgentRequest = read_frame(&mut status_conn).expect("read status preflight");
            assert_eq!(
                status,
                AgentRequest::Status {
                    request_id: request_id.clone(),
                    session_id: Some("sess_stub".into()),
                }
            );
            write_response_frame(
                &mut status_conn,
                &json!({
                    "kind":"status", "request_id":request_id, "status":"ready",
                    "phase":"ready", "effect_id":"effect_broker"
                }),
            )
            .expect("write status preflight");
        }

        // The real request, threaded onto the minted session.
        let (mut c2, _) = listener.accept().expect("accept request");
        let got: AgentRequest = read_frame(&mut c2).expect("read the request frame");
        expect.set_session_id(Some("sess_stub".into()));
        assert_eq!(
            got, expect,
            "the bridge forwarded the wrong wire request or session"
        );
        write_response_frame(&mut c2, &reply).expect("write the canned reply");
    });
    (path, handle)
}

#[test]
fn tools_call_request_capability_rides_the_real_socket_and_returns_sentence_deny() {
    let dir = tempdir().unwrap();
    let (path, server) = stub_socket(
        dir.path(),
        AgentRequest::Request {
            session_id: None,
            provider: "github".into(),
            action: "read_repo".into(),
            resource: json!({ "owner": "acme", "name": "widgets" }),
            environment: None,
            justification: None,
            model: None,
            retry_effect: None,
        },
        json!({
            "kind": "requested", "request_id": "rq-42", "decision": "deny",
            "reason": "outside sentence", "authority_kind": "sentence"
        }),
    );

    let transport = SocketTransport::new(path, "test-agent".into());
    let input = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "request_capability",
            "arguments": {
                "provider": "github", "action": "read_repo",
                "resource": { "owner": "acme", "name": "widgets" }
            }
        }
    })
    .to_string()
        + "\n";

    let out = SharedBuf::new();
    serve(transport, Cursor::new(input), out.clone()).expect("serve ok");
    server.join().unwrap();

    let resp: Value = serde_json::from_str(out.text().trim()).unwrap();
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(resp["result"]["isError"], json!(false));
    assert!(text.contains("Denied by sentence authority"), "got: {text}");
    assert!(text.contains("rq-42"), "got: {text}");
    assert!(text.contains("do not retry"), "got: {text}");
}

#[test]
fn tools_call_execute_rides_the_real_socket_and_surfaces_the_witness() {
    let dir = tempdir().unwrap();
    let (path, server) = stub_socket(
        dir.path(),
        AgentRequest::Execute {
            session_id: None,
            request_id: "rq-42".into(),
        },
        json!({
            "kind": "executed", "ok": true, "provider": "github", "action": "read_repo",
            "effect_id": "effect_broker",
            "result": { "full_name": "acme/widgets" }
        }),
    );

    let transport = SocketTransport::new(path, "test-agent".into());
    let input = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "execute_capability", "arguments": { "request_id": "rq-42" } }
    })
    .to_string()
        + "\n";

    let out = SharedBuf::new();
    serve(transport, Cursor::new(input), out.clone()).expect("serve ok");
    server.join().unwrap();

    let resp: Value = serde_json::from_str(out.text().trim()).unwrap();
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(resp["result"]["isError"], json!(false));
    assert!(text.contains("github.read_repo"), "got: {text}");
    assert!(text.contains("acme/widgets"), "got: {text}");
    assert!(
        resp["result"]["content"]
            .as_array()
            .unwrap()
            .iter()
            .any(|part| part["text"]
                .as_str()
                .is_some_and(|text| text.contains("effect_broker"))),
        "the broker-derived effect handle was lost: {resp}"
    );
}

/// A session served by a daemon of a DIFFERENT build must say so where an agent can see it — in
/// band, on the first tool result, once. The failure it guards: a stale MCP server that keeps
/// brokering across reinstalls with nothing able to detect the skew.
#[test]
fn a_daemon_predating_the_build_field_is_noted_in_band_on_the_first_tool_result() {
    let dir = tempdir().unwrap();
    let (path, server) = stub_socket_built(
        dir.path(),
        AgentRequest::ListCredentials { session_id: None },
        json!({ "kind": "credentials", "credentials": [] }),
        None,
    );

    let transport = SocketTransport::new(path, "test-agent".into());
    let input = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "list_connected_providers", "arguments": {} }
    })
    .to_string()
        + "\n";

    let out = SharedBuf::new();
    serve(transport, Cursor::new(input), out.clone()).expect("serve ok");
    server.join().unwrap();

    let resp: Value = serde_json::from_str(out.text().trim()).unwrap();
    let note = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(note.contains("build skew"), "got: {note}");
    assert!(note.contains(cermet_ipc::BUILD_ID), "names us: {note}");
    assert!(
        note.contains("unknown"),
        "and the daemon it could not name: {note}"
    );
    assert!(note.contains("restart"), "and the fix: {note}");
    assert_eq!(
        resp["result"]["isError"],
        json!(false),
        "a note never turns a good result into an error"
    );
    assert_eq!(
        resp["result"]["content"].as_array().unwrap().len(),
        2,
        "the real result still follows the note"
    );
}
