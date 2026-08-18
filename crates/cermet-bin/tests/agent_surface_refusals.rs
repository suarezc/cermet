//! THE AGENT SURFACE, END TO END: what an MCP client actually reads when it calls a tool.
//!
//! This is the test class whose absence let a real regression ship. `github-fetch` / `github-push`
//! are registered tools; the broker has authored a precise signpost for them ("not requestable —
//! run `git fetch` against a `cermet::` remote, wire one with …"); and yet the agent read the string
//! `internal error`, because the refusal travelled the `Err` channel that the agent wire flattens
//! into its infrastructure catch-all. Core tests saw the refusal. Bridge tests saw a stubbed socket.
//! Nothing in the workspace saw the whole sentence arrive at the agent — measured live: most runs
//! that hit the door never recovered from it.
//!
//! `cermet-bin` is the only crate that composes both halves (`cermet-daemon` + `cermet-cli`), so the
//! whole path runs in one process here: a REAL broker → the REAL `agent.sock` dispatch → the REAL
//! MCP stdio bridge, driven by an ordinary `tools/call` JSON-RPC line.
//!
//! Every INTENTIONAL refusal an agent can provoke on the request path belongs here, which is why
//! this file is named for refusals rather than for the first one it caught: the git-plane signpost
//! and the owner lockdown, which failed identically and for the same reason.

use std::io::{Cursor, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use cermet_broker_actor::BrokerHandle;
use cermet_cli::mcp_bridge::server::{serve, SocketTransport};
use cermet_core::{BrokerConfig, LockdownSource, SentenceAuthoritySource};
use cermet_daemon::serve::{bind_agent_socket, handle_connection, ServeTimeouts};
use serde_json::{json, Value};
use tempfile::tempdir;

/// A `Write` sink the test still holds after `serve` consumes it.
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

/// The corpus under test admits the git verbs by name — the refusal must hold *because the verb is
/// git-kind*, not because no sentence selects it (that would be an ordinary sentence deny).
struct FixedAuthority(cermet_core::sentence::RuleSet);
impl SentenceAuthoritySource for FixedAuthority {
    fn current_authority(
        &self,
    ) -> cermet_core::Result<cermet_core::AuthenticatedSentenceAuthority> {
        Ok(cermet_core::AuthenticatedSentenceAuthority {
            digest: cermet_core::sentence::authority_digest(&self.0),
            rules: self.0.clone(),
        })
    }
}

/// The owner's deny-all latch, engaged for the whole of a test that wants it.
struct EngagedLockdown;
impl LockdownSource for EngagedLockdown {
    fn is_engaged(&self) -> bool {
        true
    }
}

fn broker(dir: &Path) -> BrokerHandle {
    broker_with_lockdown(dir, None)
}

fn broker_with_lockdown(dir: &Path, lockdown: Option<Arc<dyn LockdownSource>>) -> BrokerHandle {
    let mut rules = cermet_core::sentence::parse_rules(
        "allow github.fetch where owner = \"acme\" and name = \"website\"\n\
         allow github.push where owner = \"acme\" and name = \"website\"\n\
         allow github.read_repo where owner = \"acme\" and name = \"website\"",
    )
    .expect("the corpus parses");
    cermet_core::sentence::pin_set_references(&mut rules, &cermet_core::sets::VendoredSetResolver)
        .expect("set references pin");
    cermet_broker_actor::spawn_full(
        BrokerConfig {
            git: cermet_core::git::GitConfig::at(dir.join("quarantine")),
            dir: dir.to_path_buf(),
            master_key: vec![7u8; 32],
            action_templates: cermet_core::templates::VENDORED_CATALOG
                .iter()
                .map(|s| s.to_string())
                .collect(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: cermet_core::ArtifactConfig::default(),
        },
        Vec::new(),
        Some(Arc::new(FixedAuthority(rules))),
        lockdown,
        None,
        None,
        None,
    )
    .expect("broker opens")
}

/// Serve `agent.sock` for the life of the test: the bridge opens one connection for its handshake
/// and one per call, so this accepts in a loop rather than once.
fn serve_agent_socket(dir: &Path, broker: BrokerHandle) -> std::path::PathBuf {
    let (listener, path) = bind_agent_socket(dir).expect("bind agent.sock");
    let rt = tokio::runtime::Handle::current();
    // The operator IS this test process (same-uid), which is the "operator accepted" configuration.
    let operator_uid = unsafe { libc::getuid() };
    std::thread::spawn(move || {
        while let Ok((conn, _addr)) = listener.accept() {
            let broker = broker.clone();
            let rt = rt.clone();
            std::thread::spawn(move || {
                handle_connection(
                    conn,
                    &broker,
                    &rt,
                    "test-agent",
                    Some(operator_uid),
                    ServeTimeouts::default(),
                );
            });
        }
    });
    path
}

/// Drive ONE `tools/call` through the real bridge against the real socket, returning the tool
/// result's concatenated text.
fn call_tool(socket: &Path, name: &str, arguments: Value) -> (String, Value) {
    let input = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
    .to_string()
        + "\n";
    let out = SharedBuf::new();
    serve(
        SocketTransport::new(socket.to_path_buf(), "test-agent".into()),
        Cursor::new(input),
        out.clone(),
    )
    .expect("the bridge serves");
    let response: Value = serde_json::from_str(out.text().trim()).expect("one JSON-RPC response");
    let text = response["result"]["content"]
        .as_array()
        .expect("a tool result carries content")
        .iter()
        .filter_map(|part| part["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    (text, response)
}

/// The whole point: the tool call an agent actually makes returns the SIGNPOST, not "internal
/// error" — and leaves a receipt, so an agent hammering a painted door is operator-visible.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_git_plane_tools_answer_an_agent_with_the_signpost_not_internal_error() {
    let dir = tempdir().unwrap();
    let broker = broker(dir.path());
    let socket = serve_agent_socket(dir.path(), broker.clone());

    for (tool, arguments, own_command) in [
        (
            "github-fetch",
            json!({
                "owner": "acme", "name": "website",
                "justification": "clone the repo to read its build script"
            }),
            "git fetch",
        ),
        (
            "github-push",
            json!({
                "owner": "acme", "name": "website", "branch": "main",
                "new_oid": "a".repeat(40),
                "justification": "publish the reviewed commit"
            }),
            "git push",
        ),
    ] {
        let socket = socket.clone();
        let (text, response) =
            tokio::task::spawn_blocking(move || call_tool(&socket, tool, arguments))
                .await
                .expect("the bridge call completes");

        assert!(
            !text.contains("internal error"),
            "{tool} answered with the infrastructure catch-all: {text}\n{response}"
        );
        assert!(
            text.contains("not requestable"),
            "{tool} must say the verb is not requestable: {text}"
        );
        assert!(
            text.contains("cermet::github"),
            "{tool} must name the remote that IS the door: {text}"
        );
        assert!(
            text.contains("git remote set-url origin cermet::github/<owner>/<repo>"),
            "{tool} must name the wiring command verbatim: {text}"
        );
        assert!(
            text.contains(own_command),
            "{tool} must name ITS OWN git command ({own_command}): {text}"
        );
    }

    // The refusals are receipted: two rows, each carrying the signpost the agent was given. While
    // this refusal was an `Err` it recorded nothing at all — the operator could not see the probes.
    let history: Value = serde_json::from_str(&broker.history().await.expect("history reads"))
        .expect("history is JSON");
    let rows = history.as_array().cloned().unwrap_or_default();
    for action in ["fetch", "push"] {
        let row = rows
            .iter()
            .find(|row| {
                row["provider"] == json!("github")
                    && row["action"] == json!(action)
                    && row["decision"] == json!("deny")
            })
            .unwrap_or_else(|| panic!("github.{action} left a deny receipt: {history}"));
        assert!(
            row["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("not requestable")),
            "the receipt carries the refusal verbatim: {row}"
        );
    }
}

/// The same defect one guard over: on a locked-down box every capability request answered
/// `internal error`, so an agent could not tell "the owner stopped everything" from "the broker is
/// broken" — and the attempts left no trace, in exactly the situation an operator most wants to see
/// who is still knocking.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_locked_down_box_tells_the_agent_it_is_locked_down_and_receipts_the_attempt() {
    let dir = tempdir().unwrap();
    let broker = broker_with_lockdown(dir.path(), Some(Arc::new(EngagedLockdown)));
    let socket = serve_agent_socket(dir.path(), broker.clone());

    let call_socket = socket.clone();
    let (text, response) = tokio::task::spawn_blocking(move || {
        call_tool(
            &call_socket,
            "github-read_repo",
            json!({
                "owner": "acme", "name": "website",
                "justification": "read the repo description for the release note"
            }),
        )
    })
    .await
    .expect("the bridge call completes");

    assert!(
        !text.contains("internal error"),
        "a lockdown answered with the infrastructure catch-all: {text}\n{response}"
    );
    assert!(
        text.contains("owner lockdown is engaged"),
        "the refusal uses the operator's own lockdown vocabulary: {text}"
    );
    assert!(
        text.contains("cermet owner lockdown clear"),
        "and names the one command that lifts it: {text}"
    );
    // The generic pre-authority wrapper invites a corrected request; a lockdown must not leave that
    // standing, because no correction the agent can make will help.
    assert!(
        text.contains("will not help") || text.contains("do not retry"),
        "the refusal tells the agent not to keep trying: {text}"
    );

    let history: Value = serde_json::from_str(&broker.history().await.expect("history reads"))
        .expect("history is JSON");
    let row = history
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .find(|row| row["provider"] == json!("github") && row["decision"] == json!("deny"))
        .unwrap_or_else(|| panic!("the lockdown refusal left a receipt: {history}"));
    assert!(
        row["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("owner lockdown is engaged")),
        "the receipt says why: {row}"
    );
}
