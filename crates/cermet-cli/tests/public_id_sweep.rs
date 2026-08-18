//! The public-id sweep for the operator CLI — the mirror of the MCP `--json` scrub test.
//!
//! `request_id` is the ONE public id. `grant_id` is operator-internal record data: it lives in the
//! audit rows and in the `log <request_id>` evidence JSON, and NOWHERE else. The CLI's inputs and
//! help text hold that line already, but two EMISSION sites did not — the `--ask-only` decision
//! receipt printed the daemon's `grant_id` verbatim, and the hop log appended `(grant <id>)` —
//! because nothing swept the rendered output.
//!
//! The failure mode: a renderer grows a field, or a new daemon field arrives, and an
//! operator-internal handle reaches the terminal where the next reader learns to pass it around.
//!
//! CONVENTION: every agent-path CLI output belongs in `surfaces()` below, rendered from the most
//! grant-bearing input its source can produce (a REAL minted grant where a fixture can mint one, a
//! deliberately poisoned daemon frame where it cannot). Adding an agent-path renderer without
//! adding it here is the gap this file exists to close. The `log <request_id>` evidence JSON is
//! DELIBERATELY not swept: it is the record surface and keeps `grant_id` on purpose.

use cermet_cli::check::{run_check, CheckEnv};
use cermet_cli::receipt_log::{run_log_history, run_log_hops, LogFilter};
use cermet_cli::{dispatch, CliCommand, CliOutput};

mod common;
use common::BrokerFixture;

/// `mock-vercel.deploy` is the offline verb, so an allowed request really executes and a real grant
/// is really minted behind the receipt.
const ALLOWED: &str = "allow mock-vercel.deploy";

fn deploy(ask_only: bool) -> CliCommand {
    CliCommand::Run {
        retry_effect: None,
        provider: "mock-vercel".into(),
        action: "deploy".into(),
        resource: serde_json::json!({"project":"demo","repo_id":123,"ref":"main"}),
        environment: Some("preview".into()),
        justification: Some("the public-id sweep".into()),
        ask_only,
    }
}

async fn fixture_with_rules(rules: &str) -> BrokerFixture {
    let fixture = BrokerFixture::with_sentence_rules(rules);
    fixture
        .connect_mock_credential("mock-vercel")
        .await
        .expect("connect the offline mock credential");
    fixture
}

/// A hop log frame with a grant id in EVERY slot the daemon can put one in.
fn poisoned_hops() -> String {
    serde_json::json!([
        {
            "event_type": "relay_session_opened",
            "at": "2026-08-02T10:00:00Z",
            "provider": "github",
            "action": "push",
            "grant_id": "grant_deadbeefdeadbeef"
        },
        {
            "event_type": "relay_request_forwarded",
            "at": "2026-08-02T10:00:01Z",
            "provider": "github",
            "action": "push",
            "grant_id": "grant_deadbeefdeadbeef",
            "method": "POST",
            "target": "https://github.example/repo.git",
            "upstream_status": 200,
            "response_bytes": 12,
            "effect": true
        },
        {
            "event_type": "relay_session_closed",
            "at": "2026-08-02T10:00:02Z",
            "grant_id": "grant_deadbeefdeadbeef",
            "closed": "burned",
            "burned": true,
            "reason": "the session burned"
        }
    ])
    .to_string()
}

/// A history frame whose rows carry grant ids, including one whose timestamp cannot parse — the
/// `--since` filter turns that row into a rendered ERROR, which is CLI output too.
fn poisoned_history(created_at: &str) -> String {
    serde_json::json!([{
        "grant_id": "grant_deadbeefdeadbeef",
        "provider": "mock-vercel",
        "action": "deploy",
        "resource": {"project": "demo"},
        "status": "executed",
        "decision": "allow",
        "created_at": created_at,
        "request_id": "req_00000000000000ff",
        "approved_by_kind": "sentence",
        "matched_rule": ALLOWED,
        "integrity_ok": true
    }])
    .to_string()
}

/// A history frame LONGER than the default window, so the windowed render — and its
/// truncation line, a rendered surface of its own — is really exercised by the sweep. Every row
/// carries a grant handle, so a note that quoted any row would fail loudly.
fn overlong_history() -> String {
    let rows: Vec<serde_json::Value> = (0..LOG_WINDOW_SWEEP_ROWS)
        .map(|n| {
            serde_json::json!({
                "grant_id": format!("grant_{n:016x}"),
                "provider": "mock-vercel",
                "action": "deploy",
                "resource": {"project": "demo"},
                "status": "executed",
                "decision": "allow",
                "created_at": format!("2026-08-02T00:{:02}:00Z", n % 60),
                "request_id": format!("req_{n:016x}"),
                "approved_by_kind": "sentence",
                "matched_rule": ALLOWED,
                "integrity_ok": true
            })
        })
        .collect();
    serde_json::to_string(&rows).unwrap()
}

/// One more than the default window, so the note fires with the smallest possible fixture.
const LOG_WINDOW_SWEEP_ROWS: usize = 101;

fn check_env(root: &std::path::Path) -> CheckEnv {
    CheckEnv {
        cwd: root.to_path_buf(),
        path: Some(root.join("bin").into_os_string()),
        git_sock: root.join("git.sock"),
        agent_sock: root.join("agent.sock"),
        path_registration: None,
        cutover: Default::default(),
        update: Default::default(),
    }
}

/// The whole point: NO agent-path CLI output carries a `grant_` token — not the id, not the key
/// name, not a "(grant …)" aside.
fn assert_no_grant_token(surface: &str, text: &str) {
    assert!(
        !text.contains("grant_"),
        "{surface} emitted an operator-internal grant handle:\n{text}"
    );
}

#[tokio::test]
async fn no_agent_path_cli_output_carries_a_grant_handle() {
    let mut surfaces: Vec<(String, String)> = Vec::new();
    let mut record = |name: &str, out: Result<CliOutput, cermet_cli::CliError>| {
        surfaces.push((
            name.to_string(),
            match out {
                Ok(out) => out.text,
                // A rendered error is CLI output as much as a receipt is.
                Err(error) => error.to_string(),
            },
        ));
    };

    // --- the real ctl path, with a real minted grant behind every allow ---------------------
    let allowing = fixture_with_rules(ALLOWED).await;

    let decided = dispatch(&allowing.client, &deploy(true))
        .await
        .expect("--ask-only decides");
    let request_id = serde_json::from_str::<serde_json::Value>(&decided.text)
        .expect("the decision receipt is JSON")["request_id"]
        .as_str()
        .expect("the receipt carries the one public id")
        .to_string();
    record("run --ask-only (allow)", Ok(decided));

    record(
        "run --resume",
        dispatch(&allowing.client, &CliCommand::Resume { request_id }).await,
    );
    record(
        "run (fused allow)",
        dispatch(&allowing.client, &deploy(false)).await,
    );

    // The morning receipt, rendered from the REAL history the two runs above just wrote.
    let history = allowing.client.history().await.expect("history view");
    assert!(
        history.contains("grant_"),
        "the sweep is vacuous unless the daemon view really carries grant ids: {history}"
    );
    record("log", run_log_history(&history, &LogFilter::default()));
    record(
        "log --denied-only",
        run_log_history(
            &history,
            &LogFilter {
                denied_only: true,
                ..LogFilter::default()
            },
        ),
    );

    // --- the deny half (an empty corpus denies everything: fail closed) ----------------------
    let denying = fixture_with_rules("").await;
    let refused = dispatch(&denying.client, &deploy(true))
        .await
        .expect("--ask-only decides even when the corpus denies");
    let denied_request_id = serde_json::from_str::<serde_json::Value>(&refused.text)
        .expect("the decision receipt is JSON")["request_id"]
        .as_str()
        .expect("a denial still carries the one public id")
        .to_string();
    record("run --ask-only (deny)", Ok(refused));
    record(
        "run (fused deny)",
        dispatch(&denying.client, &deploy(false)).await,
    );
    // `log <request_id>` on a DENIED id renders the recorded denial. Unlike the granted
    // evidence JSON (deliberately unswept — it is the record surface and keeps `grant_id`), a
    // denial minted no grant, so no grant handle may appear in it at all.
    record(
        "log <denied request_id>",
        dispatch(
            &denying.client,
            &CliCommand::Evidence {
                request_id: denied_request_id,
            },
        )
        .await,
    );

    // --- renderers no fixture can drive, fed a deliberately poisoned daemon frame ------------
    record(
        "log --hops",
        run_log_hops(&poisoned_hops(), &LogFilter::default()),
    );
    record(
        "log --hops --denied",
        run_log_hops(
            &poisoned_hops(),
            &LogFilter {
                denied_only: true,
                ..LogFilter::default()
            },
        ),
    );
    record(
        "log (poisoned rows)",
        run_log_history(
            &poisoned_history("2026-08-02T10:00:00Z"),
            &LogFilter::default(),
        ),
    );
    record(
        "log (windowed, truncation line)",
        run_log_history(&overlong_history(), &LogFilter::default()),
    );
    record(
        "log --since (unparseable row timestamp)",
        run_log_history(
            &poisoned_history("not-a-timestamp"),
            &LogFilter {
                since: Some("2026-08-01T00:00:00Z"),
                ..LogFilter::default()
            },
        ),
    );

    // --- the plumbing checklist --------------------------------------------------------------
    let root = tempfile::tempdir().expect("tempdir");
    record(
        "check",
        run_check(Ok(&allowing.client), None, &check_env(root.path())).await,
    );

    // --- capability discovery, both zooms -----------------------------------------------------
    record(
        "catalog",
        dispatch(&allowing.client, &CliCommand::Catalog { all: false }).await,
    );
    record(
        "catalog --all",
        dispatch(&allowing.client, &CliCommand::Catalog { all: true }).await,
    );

    // Non-vacuity: a surface that failed to render at all would sweep clean for the WRONG reason.
    let text_of = |name: &str| -> String {
        surfaces
            .iter()
            .find(|(surface, _)| surface == name)
            .unwrap_or_else(|| panic!("{name} is not in the sweep"))
            .1
            .clone()
    };
    assert!(text_of("run --ask-only (allow)").contains("req_"));
    assert!(text_of("run --resume").contains("mock-vercel"));
    assert!(text_of("run (fused allow)").contains("mock-vercel"));
    assert!(text_of("run (fused deny)")
        .to_lowercase()
        .contains("denied"));
    assert!(text_of("run --ask-only (deny)").contains("\"deny\""));
    assert!(text_of("log").contains("mock-vercel.deploy"));
    assert!(text_of("log --hops").contains("OPENED"));
    assert!(text_of("log --hops").contains("HOP"));
    assert!(text_of("log (poisoned rows)").contains("mock-vercel.deploy"));
    assert!(
        text_of("log --since (unparseable row timestamp)").contains("req_00000000000000ff"),
        "the bad-row error names the row by its ONE public id"
    );
    assert!(text_of("check").contains("plumbing"));
    // The truncation line really rendered (so the sweep above really swept it).
    assert!(
        text_of("log (windowed, truncation line)")
            .contains("showing the 100 most recent of 101 rows"),
        "the windowed render must carry its honest tail"
    );
    let denied_evidence = text_of("log <denied request_id>");
    assert!(
        denied_evidence.contains("mock-vercel") && denied_evidence.contains("\"deny\""),
        "the denied id must RENDER its record, not answer not-found: {denied_evidence}"
    );
    // The corpus here admits `mock-vercel.deploy`, which is a POLICY verb with no catalog template,
    // so the allowed zoom is legitimately empty — the non-vacuity claim is that both zooms really
    // rendered the daemon's join, which the dictionary's 69 stamped verbs prove.
    assert!(text_of("catalog").contains("allowed now"));
    assert!(text_of("catalog --all").contains("github.read_repo"));

    for (surface, text) in &surfaces {
        assert_no_grant_token(surface, text);
    }
}
