//! `cermet connect` over the REAL ctl path, in its deterministic (offline mock-vercel) cases:
//! capture-from-stdin, empty-token fail-closed, idempotent reuse, replace, and env-token adoption
//! with the sole-custody warning.
//!
//! The invariant under test is SECRET HYGIENE: across every path the (obviously-fake) token must
//! never appear in the command output — discovery surfaces only the env-var NAME, and capture is via
//! the no-echo `SecretString` path. Fake values only; a real token never enters a fixture.

use std::collections::HashMap;

use cermet_cli::connect::{run_connect, ConnectArgs, MapTokenSource};
use cermet_cli::tty::ScriptedTerminal;
use cermet_cli::CliError;
use cermet_ctl_client::broker_client::CtlBrokerClient;

mod common;
use common::BrokerFixture;

const POLICY: &str = "providers:\n  mock-vercel:\n    ask:\n      - action: deploy\n";

fn cargs(replace: bool, adopt: bool) -> ConnectArgs {
    ConnectArgs {
        provider: "mock-vercel".into(),
        account_label: None,
        replace,
        adopt,
    }
}
fn empty_src() -> MapTokenSource {
    MapTokenSource {
        env: HashMap::new(),
        gh: None,
    }
}

async fn connect_with(
    client: &CtlBrokerClient,
    interactive: bool,
    secret: &str,
    src: &MapTokenSource,
    args: &ConnectArgs,
) -> Result<String, CliError> {
    let term = ScriptedTerminal::new(interactive, secret, vec![]);
    // A scratch cwd that is not a git repository: the github wiring step has nothing to offer here,
    // and these cases are about token custody.
    let cwd = tempfile::tempdir().expect("cwd");
    run_connect(client, &term, src, args, cwd.path())
        .await
        .map(|o| o.text)
}

#[tokio::test]
async fn connect_reads_the_token_from_stdin_never_echoing_it() {
    let fx = BrokerFixture::new(POLICY);
    let token = "vc_live_FAKEtoken_3x9zQ";
    let out = connect_with(&fx.client, false, token, &empty_src(), &cargs(false, false))
        .await
        .expect("connect ok");
    assert!(out.contains("mock-vercel credential stored"), "{out}");
    assert!(
        !out.contains(token),
        "the token must never be echoed: {out}"
    );
    assert!(out.contains("The agent never sees it."), "{out}");
}

#[tokio::test]
async fn connect_refuses_a_label_containing_the_token() {
    let fx = BrokerFixture::new(POLICY);
    let token = "vc_live_FAKEtoken_3x9zQ";
    let args = ConnectArgs {
        provider: "mock-vercel".into(),
        account_label: Some(format!("prod ({token})")),
        replace: false,
        adopt: false,
    };
    let err = connect_with(&fx.client, false, token, &empty_src(), &args)
        .await
        .expect_err("a token-bearing label must refuse before anything is stored");
    match err {
        CliError::Refused(msg) => {
            assert!(
                !msg.contains(token),
                "the refusal must not echo the token: {msg}"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    // Nothing reached the vault: the refusal fires before the ctl send.
    let credentials: serde_json::Value =
        serde_json::from_str(&fx.client.list_credentials().await.unwrap()).unwrap();
    assert!(credentials.as_array().unwrap().is_empty(), "{credentials}");
}

#[tokio::test]
async fn connect_empty_token_fails_closed() {
    let fx = BrokerFixture::new(POLICY);
    let err = connect_with(&fx.client, false, "", &empty_src(), &cargs(false, false))
        .await
        .expect_err("an empty token must fail closed");
    assert!(matches!(err, CliError::Refused(_)), "{err:?}");
}

#[tokio::test]
async fn connect_is_idempotent_and_hints_replace() {
    let fx = BrokerFixture::new(POLICY);
    connect_with(
        &fx.client,
        false,
        "vc_first_FAKE",
        &empty_src(),
        &cargs(false, false),
    )
    .await
    .expect("first connect stores");
    // Second connect, non-interactive, no --replace → keeps the existing, hints at --replace.
    let out = connect_with(
        &fx.client,
        false,
        "vc_again_FAKE",
        &empty_src(),
        &cargs(false, false),
    )
    .await
    .expect("idempotent keep ok");
    assert!(out.contains("already connected"), "{out}");
    assert!(out.contains("Use --replace"), "{out}");
}

/// A git repo with one `origin`, for the already-connected wiring cases below.
fn repo(root: &std::path::Path, origin: &str) -> std::path::PathBuf {
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    for args in [
        vec!["init", "-q", "-b", "main", "."],
        vec!["remote", "add", "origin", origin],
    ] {
        let out = std::process::Command::new("git")
            .args(&args)
            .current_dir(&work)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?}");
    }
    work
}

async fn connect_github_in(
    client: &CtlBrokerClient,
    cwd: &std::path::Path,
) -> Result<String, CliError> {
    let term = ScriptedTerminal::new(false, "unused", vec![]);
    let args = ConnectArgs {
        provider: "github".into(),
        account_label: None,
        replace: false,
        adopt: false,
    };
    run_connect(client, &term, &empty_src(), &args, cwd)
        .await
        .map(|o| o.text)
}

/// with a github credential already in the vault, `connect
/// github` short-circuited at "already connected" and said nothing about THIS repository — so an
/// agent in a new repo had no reachable path to the wiring command. The already-connected reply now
/// carries the same offer the first-time connect prints.
#[tokio::test]
async fn an_already_connected_github_still_offers_the_wiring_for_an_unwired_repo() {
    let fx = BrokerFixture::new(POLICY);
    fx.connect_mock_credential("github")
        .await
        .expect("github is already connected");
    let dir = tempfile::tempdir().unwrap();
    let work = repo(dir.path(), "https://github.com/acme/website.git");

    let out = connect_github_in(&fx.client, &work)
        .await
        .expect("already-connected reply");
    assert!(out.contains("already connected"), "{out}");
    assert!(
        out.contains("git remote set-url origin cermet::github/acme/website"),
        "the offer names this repository's exact wiring command: {out}"
    );
}

#[tokio::test]
async fn an_already_connected_github_says_nothing_extra_in_a_wired_or_non_repo_cwd() {
    let fx = BrokerFixture::new(POLICY);
    fx.connect_mock_credential("github")
        .await
        .expect("github is already connected");

    let dir = tempfile::tempdir().unwrap();
    let wired = repo(dir.path(), "cermet::github/acme/website");
    let out = connect_github_in(&fx.client, &wired)
        .await
        .expect("already-connected reply");
    assert!(out.contains("already connected"), "{out}");
    assert!(
        !out.contains("set-url") && !out.contains("already reaches"),
        "a wired repo needs no offer and no extra line: {out}"
    );

    let elsewhere = tempfile::tempdir().unwrap();
    let out = connect_github_in(&fx.client, elsewhere.path())
        .await
        .expect("already-connected reply");
    assert!(out.contains("already connected"), "{out}");
    assert!(
        !out.contains("set-url"),
        "outside a git repository there is nothing to wire: {out}"
    );
}

#[tokio::test]
async fn connect_replace_overwrites() {
    let fx = BrokerFixture::new(POLICY);
    connect_with(
        &fx.client,
        false,
        "vc_first_FAKE",
        &empty_src(),
        &cargs(false, false),
    )
    .await
    .expect("first connect stores");
    let out = connect_with(
        &fx.client,
        false,
        "vc_second_FAKE",
        &empty_src(),
        &cargs(true, false),
    )
    .await
    .expect("replace ok");
    assert!(out.contains("mock-vercel credential stored"), "{out}");
    assert!(
        !out.contains("vc_second_FAKE"),
        "the new token must never be echoed: {out}"
    );
}

#[tokio::test]
async fn connect_adopts_an_env_token_and_warns_about_sole_custody() {
    let fx = BrokerFixture::new(POLICY);
    // mock-vercel's discovery env var is the uppercased fallback name.
    let mut env = HashMap::new();
    env.insert(
        "MOCK-VERCEL_TOKEN".to_string(),
        "vc_env_FAKE_999".to_string(),
    );
    let src = MapTokenSource { env, gh: None };
    let out = connect_with(&fx.client, false, "unused-stdin", &src, &cargs(false, true))
        .await
        .expect("adopt ok");
    assert!(out.contains("mock-vercel credential stored"), "{out}");
    assert!(
        !out.contains("vc_env_FAKE_999"),
        "the token must never be echoed: {out}"
    );
    assert!(
        out.contains("$MOCK-VERCEL_TOKEN still holds") && out.contains("sole custody"),
        "the sole-custody warning names the source var, not the value: {out}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cermet_connect_stripe_binary_routes_to_the_daemon_vault() {
    use std::io::Write;
    use std::process::Stdio;

    let fx = BrokerFixture::new("");
    let socket = fx.sock_path().to_path_buf();
    let daemon_uid = nix::unistd::getuid().as_raw().to_string();
    let output = tokio::task::spawn_blocking(move || {
        let mut child = common::cermet_command()
            .args(["connect", "stripe"])
            .env("CERMET_CTL_SOCK", socket)
            .env("CERMET_DAEMON_UID", daemon_uid)
            .env_remove("STRIPE_TEST_KEY")
            .env_remove("STRIPE_API_KEY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn cermet");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"sk_test_daemon_route_only\n")
            .unwrap();
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stdout={stdout}\nstderr={stderr}");
    assert!(stdout.contains("stripe credential stored"), "{stdout}");
    assert!(!stdout.contains("sk_test_daemon_route_only"), "{stdout}");
    assert!(!stderr.contains("sk_test_daemon_route_only"), "{stderr}");

    let credentials: serde_json::Value =
        serde_json::from_str(&fx.client.list_credentials().await.unwrap()).unwrap();
    assert!(
        credentials
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["provider"] == "stripe"),
        "the binary must use ctl Connect, not an in-process custody: {credentials}"
    );
}
