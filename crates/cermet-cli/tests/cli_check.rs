//! `cermet check [<provider>]` — the read-only plumbing checklist.
//!
//! The failure it addresses: a user or agent resets their git config, PATH, or a credential and
//! cannot see why the invisible integration stopped working. `check` is the accessor that makes it
//! visible. It REPORTS; it never fixes, and it never touches daemon state.

use std::path::{Path, PathBuf};

use cermet_cli::check::{run_check, CheckEnv};

mod common;
use common::BrokerFixture;

/// A scratch PATH directory, optionally holding fake executables of the given names.
fn path_dir(root: &Path, tools: &[&str]) -> PathBuf {
    let dir = root.join("bin");
    std::fs::create_dir_all(&dir).unwrap();
    for tool in tools {
        let file = dir.join(tool);
        std::fs::write(&file, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
    }
    dir
}

fn git(cwd: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repo with an `origin`, wired or not.
fn repo(root: &Path, origin: &str) -> PathBuf {
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q", "-b", "main", "."]);
    git(&work, &["remote", "add", "origin", origin]);
    work
}

fn env_at(cwd: PathBuf, path: PathBuf, git_sock: PathBuf, agent_sock: PathBuf) -> CheckEnv {
    CheckEnv {
        cwd,
        path: Some(path.into_os_string()),
        git_sock,
        agent_sock,
        // The cutover and update-check probes read the real machine; a checklist test drives
        // fixtures, so all three are pinned to "nothing found" here and exercised in the unit tests
        // that own them.
        path_registration: None,
        cutover: Default::default(),
        update: Default::default(),
    }
}

/// A socket that exists and accepts connections — enough to prove reachability.
fn live_socket(path: PathBuf) -> PathBuf {
    let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind stub socket");
    std::thread::spawn(move || {
        for conn in listener.incoming().take(16) {
            drop(conn);
        }
    });
    path
}

#[tokio::test]
async fn a_wired_repo_with_every_piece_in_place_is_all_green() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = BrokerFixture::with_sentence_rules("allow github.read_repo");
    fixture.connect_mock_credential("github").await.unwrap();

    let work = repo(dir.path(), "cermet::github/acme/website");
    let bin = path_dir(dir.path(), &["git-remote-cermet"]);
    let env = env_at(
        work,
        bin,
        live_socket(dir.path().join("git.sock")),
        live_socket(dir.path().join("agent.sock")),
    );

    let out = run_check(Ok(&fixture.client), Some("github"), &env)
        .await
        .expect("check renders");
    assert!(
        out.ok,
        "everything is in place, so check is green:\n{}",
        out.text
    );
    assert!(!out.text.contains('✗'), "{}", out.text);
    assert!(out.text.contains("git-remote-cermet"), "{}", out.text);
    assert!(
        out.text.contains("cermet::github/acme/website"),
        "the wired remote is named: {}",
        out.text
    );
    // The rules line is informational, and it counts the github mentions.
    assert!(out.text.contains("rule"), "{}", out.text);
}

/// an unwired repository is a VALID state, not a failure — the
/// row is informational and names the one command that wires it.
#[tokio::test]
async fn an_unwired_repo_is_informational_and_names_the_exact_command() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = BrokerFixture::with_sentence_rules("");
    fixture.connect_mock_credential("github").await.unwrap();

    let work = repo(dir.path(), "https://github.com/acme/website.git");
    let bin = path_dir(dir.path(), &["git-remote-cermet"]);
    let env = env_at(
        work,
        bin,
        live_socket(dir.path().join("git.sock")),
        live_socket(dir.path().join("agent.sock")),
    );

    let out = run_check(Ok(&fixture.client), Some("github"), &env)
        .await
        .expect("check renders");
    assert!(
        out.ok,
        "an unwired repo is a valid state, not a gap: {}",
        out.text
    );
    assert!(
        out.text
            .contains("git remote set-url origin cermet::github/acme/website"),
        "the row names the exact command: {}",
        out.text
    );
    assert!(
        out.text.contains("not brokered"),
        "...and says what it found: {}",
        out.text
    );
}

/// A repository with no github remote at all — the case a NEW repo starts in. It gets the same
/// command in its placeholder form; anything less leaves the agent with nothing to act on.
#[tokio::test]
async fn a_repo_with_no_github_remote_still_names_the_wiring_command() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = BrokerFixture::with_sentence_rules("");
    fixture.connect_mock_credential("github").await.unwrap();

    let work = repo(dir.path(), "https://gitlab.com/acme/site.git");
    let bin = path_dir(dir.path(), &["git-remote-cermet"]);
    let env = env_at(
        work,
        bin,
        live_socket(dir.path().join("git.sock")),
        live_socket(dir.path().join("agent.sock")),
    );

    let out = run_check(Ok(&fixture.client), Some("github"), &env)
        .await
        .expect("check renders");
    assert!(out.ok, "{}", out.text);
    assert!(
        out.text
            .contains("git remote set-url origin cermet::github/<owner>/<repo>"),
        "the placeholder form is still a command: {}",
        out.text
    );
}

#[tokio::test]
async fn a_missing_native_cli_reads_like_the_relay_warning() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = BrokerFixture::with_sentence_rules("");
    fixture.connect_mock_credential("vercel").await.unwrap();

    // An empty PATH: the `vercel` CLI the relay invocation needs is not installed.
    let env = env_at(
        dir.path().to_path_buf(),
        path_dir(dir.path(), &[]),
        dir.path().join("absent-git.sock"),
        dir.path().join("absent-agent.sock"),
    );

    let out = run_check(Ok(&fixture.client), Some("vercel"), &env)
        .await
        .expect("check renders");
    assert!(!out.ok, "{}", out.text);
    assert!(
        out.text.contains("'vercel' not found on PATH"),
        "the same line the CLI prints above a relay invocation: {}",
        out.text
    );
}

#[tokio::test]
async fn an_unknown_provider_exits_two_and_lists_the_known_ones() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = BrokerFixture::with_sentence_rules("");
    let env = env_at(
        dir.path().to_path_buf(),
        path_dir(dir.path(), &[]),
        dir.path().join("absent-git.sock"),
        dir.path().join("absent-agent.sock"),
    );

    let error = run_check(Ok(&fixture.client), Some("heroku"), &env)
        .await
        .expect_err("an unknown provider is a usage error (exit 2)");
    let message = error.to_string();
    assert!(message.contains("heroku"), "{message}");
    for known in ["github", "vercel", "stripe"] {
        assert!(message.contains(known), "{message}");
    }
}

#[tokio::test]
async fn the_bare_form_doctors_the_plumbing_then_every_connected_provider() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = BrokerFixture::with_sentence_rules("");
    fixture.connect_mock_credential("github").await.unwrap();
    fixture.connect_mock_credential("stripe").await.unwrap();

    let work = repo(dir.path(), "cermet::github/acme/website");
    let bin = path_dir(dir.path(), &["git-remote-cermet"]);
    let env = env_at(
        work,
        bin,
        live_socket(dir.path().join("git.sock")),
        live_socket(dir.path().join("agent.sock")),
    );

    let out = run_check(Ok(&fixture.client), None, &env)
        .await
        .expect("bare check renders");
    assert!(out.ok, "every section is green here:\n{}", out.text);
    assert!(out.text.contains("plumbing"), "{}", out.text);
    for provider in ["github", "stripe"] {
        assert!(
            out.text.contains(provider),
            "the bare form doctors every connected provider: {}",
            out.text
        );
    }
    // Stripe's informational line is the pinned API version.
    assert!(
        out.text.contains(cermet_lang::provider::STRIPE_API_VERSION),
        "{}",
        out.text
    );
}

#[tokio::test]
async fn one_red_section_drives_the_bare_forms_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = BrokerFixture::with_sentence_rules("");
    fixture.connect_mock_credential("github").await.unwrap();

    // Everything is fine except the helper, which is not installed.
    let work = repo(dir.path(), "cermet::github/acme/website");
    let env = env_at(
        work,
        path_dir(dir.path(), &[]),
        live_socket(dir.path().join("git.sock")),
        live_socket(dir.path().join("agent.sock")),
    );

    let out = run_check(Ok(&fixture.client), None, &env)
        .await
        .expect("bare check renders");
    assert!(
        !out.ok,
        "one gap makes the whole run non-zero: {}",
        out.text
    );
    assert!(out.text.contains("git-remote-cermet"), "{}", out.text);
    // The bare form never exits 2 — that is the explicit-argument case only.
    assert!(out.text.contains('✗'), "{}", out.text);
}

#[tokio::test]
async fn an_unreachable_daemon_is_reported_not_raised() {
    let dir = tempfile::tempdir().unwrap();
    let env = env_at(
        dir.path().to_path_buf(),
        path_dir(dir.path(), &[]),
        dir.path().join("absent-git.sock"),
        dir.path().join("absent-agent.sock"),
    );

    let out = run_check(
        Err("no cermetd service account on this box".into()),
        None,
        &env,
    )
    .await
    .expect("a doctor reports its own failure rather than failing closed");
    assert!(!out.ok, "{}", out.text);
    assert!(
        out.text.contains("no cermetd service account"),
        "the resolution failure IS the finding: {}",
        out.text
    );
}

// ---- the git-plane row asks the enforcer, not the socket -------------------------------------

/// The daemon's own git-plane verdict, as the ctl `Doctor` report carries it.
fn doctor_row(text: &str) -> String {
    text.lines()
        .find(|line| line.contains("git plane"))
        .unwrap_or_else(|| panic!("no git-plane row in:\n{text}"))
        .to_string()
}

#[tokio::test]
async fn the_git_plane_row_reports_the_daemons_own_admission_verdict() {
    // The fixture serves ctl as this test's own uid, so the caller IS the approver: admitted.
    let dir = tempfile::tempdir().unwrap();
    let fixture = BrokerFixture::with_sentence_rules("");
    let env = env_at(
        dir.path().to_path_buf(),
        path_dir(dir.path(), &["git-remote-cermet"]),
        live_socket(dir.path().join("git.sock")),
        live_socket(dir.path().join("agent.sock")),
    );

    let out = run_check(Ok(&fixture.client), None, &env)
        .await
        .expect("check renders");
    let row = doctor_row(&out.text);
    assert!(
        row.contains('✓') && row.contains("(you)"),
        "the row carries the daemon's own personalized verdict: {row}"
    );
}

#[tokio::test]
async fn an_unreachable_daemon_never_reads_as_not_admitted() {
    // The distinction that matters: "I could not ask" is not "you are refused".
    let dir = tempfile::tempdir().unwrap();
    let env = env_at(
        dir.path().to_path_buf(),
        path_dir(dir.path(), &["git-remote-cermet"]),
        live_socket(dir.path().join("git.sock")),
        live_socket(dir.path().join("agent.sock")),
    );

    let out = run_check(Err("no cermetd on this box".into()), None, &env)
        .await
        .expect("check renders");
    let row = doctor_row(&out.text);
    assert!(
        row.contains("unreachable") || row.contains("cannot ask"),
        "an unaskable daemon says so: {row}"
    );
    assert!(
        !row.contains("NOT admitted"),
        "...and never claims the caller is refused: {row}"
    );
}
