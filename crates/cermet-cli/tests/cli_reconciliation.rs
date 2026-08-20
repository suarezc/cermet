//! Process-level regressions for the repository reconciliation front-end.

use std::process::{Command, Output};
use std::sync::Arc;

mod common;
use common::{BrokerFixture, TEST_POLICY};

fn cermet() -> Command {
    Command::new(common::cermet_binary())
}

fn assert_json_failure(output: Output) {
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout:?}");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["state"], "dataplane_unknown", "{value}");
    assert_eq!(value["document"], "unknown", "{value}");
    assert_eq!(value["live_state"], "unknown", "{value}");
    assert_eq!(value["lockdown"], "unknown", "{value}");
}

#[test]
fn status_json_parse_and_endpoint_preflight_failures_emit_one_json_envelope() {
    let parse = cermet()
        .args(["doc", "status", "--json", "--unexpected"])
        .output()
        .unwrap();
    assert_json_failure(parse);

    let repo = tempfile::tempdir().unwrap();
    std::fs::create_dir(repo.path().join(".git")).unwrap();
    let endpoint = cermet()
        .args(["doc", "status", "--json"])
        .current_dir(repo.path())
        .env("CERMET_CTL_SOCK", repo.path().join("missing.sock"))
        .env("CERMET_DAEMON_UID", "not-a-uid")
        .output()
        .unwrap();
    assert_json_failure(endpoint);

    let unreachable = cermet()
        .args(["doc", "status", "--json"])
        .current_dir(repo.path())
        .env("CERMET_CTL_SOCK", repo.path().join("missing.sock"))
        .env(
            "CERMET_DAEMON_UID",
            nix::unistd::getuid().as_raw().to_string(),
        )
        .output()
        .unwrap();
    assert_eq!(unreachable.status.code(), Some(2), "{unreachable:?}");
    assert!(
        unreachable.stderr.is_empty(),
        "stderr was not empty: {unreachable:?}"
    );
    let stdout = String::from_utf8(unreachable.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout:?}");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(value["state"], "dataplane_unknown", "{value}");
    assert_eq!(value["document"], "missing", "{value}");
    assert_eq!(value["live_state"], "unknown", "{value}");
}

#[test]
fn status_json_deleted_cwd_failure_emits_one_json_envelope() {
    let parent = tempfile::tempdir().unwrap();
    let cwd = parent.path().join("deleted-cwd");
    std::fs::create_dir(&cwd).unwrap();
    let output = Command::new("sh")
        .arg("-c")
        .arg(
            "cd \"$BROKEN_CWD\" && rmdir \"$BROKEN_CWD\" && exec \"$CERMET_BIN\" doc status --json",
        )
        .env("BROKEN_CWD", &cwd)
        .env("CERMET_BIN", common::cermet_binary())
        .env("CERMET_CTL_SOCK", parent.path().join("missing.sock"))
        .env(
            "CERMET_DAEMON_UID",
            nix::unistd::getuid().as_raw().to_string(),
        )
        .output()
        .unwrap();
    assert_json_failure(output);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_secret_predicate_never_echoes_from_the_cli_process() {
    let fx = BrokerFixture::new(TEST_POLICY);
    for (candidate, canary) in [
        (
            "allow stripe.refund where amount = \"M2_PROCESS_MALFORMED_SECRET_CANARY\"$\n",
            "M2_PROCESS_MALFORMED_SECRET_CANARY",
        ),
        (
            "allow stripe.refund where amount <M2_CHECK_COMPARATOR_CANARY\n",
            "M2_CHECK_COMPARATOR_CANARY",
        ),
        (
            "allow stripe.refund where amount = \"safe\" and rate -4545454545 per day\n",
            "-4545454545",
        ),
        (
            "allow stripe.refund where amount = \"safe\" and rate 1 per M2_CHECK_WINDOW_CANARY\n",
            "M2_CHECK_WINDOW_CANARY",
        ),
        (
            "allow stripe.refund where amount under \"/M2_CHECK_PATH_CANARY\"\n",
            "M2_CHECK_PATH_CANARY",
        ),
    ] {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir(repo.path().join(".git")).unwrap();
        let document = format!(
            "# prose\n\n<!-- cermet:authority:v1 -->\nPinned authority: `none` <!-- cermet:pinned:v1 -->\n\n```cermet\n{candidate}```\n<!-- /cermet:authority:v1 -->\n"
        );
        std::fs::write(repo.path().join("CERMET.md"), document).unwrap();

        let output = cermet()
            .args(["doc", "check"])
            .current_dir(repo.path())
            .env("CERMET_CTL_SOCK", fx.sock_path())
            .env(
                "CERMET_DAEMON_UID",
                nix::unistd::getuid().as_raw().to_string(),
            )
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert_process_output_omits(&output, canary);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_process_parser_failures_never_echo_aggregate_window_or_path_tokens() {
    let fx = BrokerFixture::new(TEST_POLICY);
    for (candidate, canary) in [
        (
            "stripe.refund where amount = \"safe\" and rate M2_ALLOW_LIMIT_CANARY per day",
            "M2_ALLOW_LIMIT_CANARY",
        ),
        (
            "stripe.refund where amount <M2_ALLOW_COMPARATOR_CANARY",
            "M2_ALLOW_COMPARATOR_CANARY",
        ),
        (
            "stripe.refund where amount = \"safe\" and rate -4646464646 per day",
            "-4646464646",
        ),
        (
            "stripe.refund where amount = \"safe\" and rate 1 per M2_ALLOW_WINDOW_CANARY",
            "M2_ALLOW_WINDOW_CANARY",
        ),
        (
            "stripe.refund where amount under \"/M2_ALLOW_PATH_CANARY\"",
            "M2_ALLOW_PATH_CANARY",
        ),
    ] {
        let output = cermet()
            .args(["rules", "allow", candidate])
            .env("CERMET_CTL_SOCK", fx.sock_path())
            .env(
                "CERMET_DAEMON_UID",
                nix::unistd::getuid().as_raw().to_string(),
            )
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert_process_output_omits(&output, canary);
    }
}

fn assert_process_output_omits(output: &Output, canary: &str) {
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !rendered.contains(canary),
        "CLI output echoed authored token {canary:?}: {rendered}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn apply_runs_the_real_typed_stage_commit_and_marker_flow_over_ctl() {
    let state = tempfile::tempdir().unwrap();
    let record = cermet_daemon::sentence_record::build_record_store(state.path(), None);
    let fx = BrokerFixture::with_record_admin(
        TEST_POLICY,
        Some(record.clone() as Arc<dyn cermet_daemon::sentence_record::SentenceRecordAdmin>),
    );
    let repo = tempfile::tempdir().unwrap();
    std::fs::create_dir(repo.path().join(".git")).unwrap();
    let candidate = "allow stripe.refund where amount <= 5000\n";
    let source = format!(
        "REAL_CTL_PROSE_CANARY\n<!-- cermet:authority:v1 -->\nPinned authority: `none` <!-- cermet:pinned:v1 -->\n\n```cermet\n{candidate}```\n<!-- /cermet:authority:v1 -->\n"
    );
    std::fs::write(repo.path().join("CERMET.md"), source).unwrap();
    let repo_path = repo.path().to_path_buf();
    let ctl = fx.client.clone();

    let output = tokio::task::spawn_blocking(move || {
        let client = cermet_cli::reconciliation::CtlReconciliationClient::new(ctl).unwrap();
        cermet_cli::reconciliation::run_apply(
            &client,
            &repo_path,
            None,
            false,
            false,
            &cermet_cli::tty::ScriptedTerminal::new(true, "", vec![true]),
            &cermet_ctl_client::presence::FixedPresence(
                cermet_ctl_client::presence::PresenceOutcome::Confirmed,
            ),
        )
    })
    .await
    .unwrap();

    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(output.text.contains("result: committed"), "{}", output.text);
    assert!(output.text.contains("state: aligned"), "{}", output.text);
    let live = fx.client.sentence_authority_status().await.unwrap();
    let cermet_ipc::ctl::SentenceSnapshot::Served {
        rules_text,
        authority_digest,
        occurrence_id,
        rule_count,
        ..
    } = live.sentence
    else {
        panic!("real apply did not establish a served generation")
    };
    assert_eq!(rules_text, candidate);
    assert_eq!(rule_count, 1);
    assert_eq!(authority_digest.len(), 64);
    assert_eq!(occurrence_id.len(), 64);
    let bytes = std::fs::read(repo.path().join("CERMET.md")).unwrap();
    let document = cermet_cli::cermet_document::ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(document.body(), candidate);
    assert_eq!(
        document.marker().as_str(),
        format!("sha256:{authority_digest}")
    );
    assert!(String::from_utf8(bytes)
        .unwrap()
        .contains("REAL_CTL_PROSE_CANARY"));
}
