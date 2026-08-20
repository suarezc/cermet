//! The slim command surface, at the CLI level: what parses, what each retired name now teaches,
//! and what the fused `run` renders.
//!
//! `run` is the whole point: one command decides AND executes. These tests drive the real parse →
//! dispatch → render path over a REAL `ctl.sock` (the shared `BrokerFixture`), so a fusion that
//! forgot to execute, or executed after a deny, fails here.

use cermet_cli::{parse, CliCommand, CliError};
use secrecy::SecretString;

mod common;
use common::BrokerFixture;

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

fn usage_of(args: &[&str]) -> String {
    match parse(&argv(args)) {
        Err(CliError::Usage(message)) => message,
        other => panic!("{args:?} must be a usage error, got {other:?}"),
    }
}

// ---- the surface itself ---------------------------------------------------------------------

/// `cermet --version` did not exist — it exited 2 as a bad
/// invocation, and the build string was reachable only by running `cermet check` against a live
/// daemon. Asking a tool what it is must never require its daemon.
#[test]
fn version_is_a_first_class_surface_agreeing_with_the_build_check() {
    for spelling in [&["--version"][..], &["-V"][..]] {
        let printed = cermet_cli::version_text(&argv(spelling))
            .unwrap_or_else(|| panic!("{spelling:?} must answer with a version"));
        assert_eq!(
            printed,
            format!("cermet {}", cermet_ipc::BUILD_ID),
            "the version IS the build id `cermet check` compares — one string, not two"
        );
    }
    // It is a top-level question, not a flag any command carries.
    assert!(cermet_cli::version_text(&argv(&["run", "--version"])).is_none());
    assert!(cermet_cli::version_text(&argv(&[])).is_none());
}

#[test]
fn the_help_is_short_and_names_every_live_command() {
    let usage = usage_of(&[]);
    // A screen, not a fixed inventory: the bound moved from 30 to 32 when `update` landed on the
    // surface, and back down when the upload noun was stripped. Still one page on any ordinary
    // terminal.
    assert!(
        usage.lines().count() < 35,
        "the help must fit on a screen ({} lines):\n{usage}",
        usage.lines().count()
    );
    for command in [
        "run <provider>.<action>",
        "run --resume",
        "log",
        "artifact",
        "audit-verify",
        "check",
        // The twelfth command — the CLI's capability-discovery surface.
        "catalog",
        "rules",
        "doc",
        // The `doc apply` ceremony reached by a stored profile's name instead of a document.
        "preset list",
        "connect",
        "owner",
        "setup",
        // The thirteenth: the noun that contacts cermet.dev — when typed, and on the daily check,
        // which leaves a local notice and installs nothing.
        "update",
        // Its off switch is on the banner because a default-on behavior nobody can find the
        // switch for is the thing that line exists to prevent.
        "update --daily on|off",
        "mcp",
    ] {
        assert!(
            usage.contains(command),
            "help must name `{command}`:\n{usage}"
        );
    }
    // The retired vocabulary is gone from the banner, and so is the WORKFLOWS legend.
    for dead in [
        "WORKFLOWS",
        "evidence <",
        "secure <",
        "cermet git",
        "<grant_id>",
        // STRIPPED 2026-08-17: the decision-trace upload noun and its config key are gone from the
        // product, so neither spelling may survive on the surface an operator reads first.
        "telemetry",
        "research",
    ] {
        assert!(
            !usage.contains(dead),
            "help still advertises `{dead}`:\n{usage}"
        );
    }
}

#[test]
fn every_retired_command_name_teaches_its_replacement() {
    for (retired, expected) in [
        (&["request", "vercel", "deploy"][..], "run"),
        (&["execute", "req_1"][..], "run --resume"),
        (&["evidence", "req_1", "--json"][..], "log <request_id>"),
        (&["allow", "allow x.y"][..], "rules allow"),
        (&["revoke", "1"][..], "rules revoke"),
        (&["refresh", "1"][..], "rules refresh"),
        (&["init"][..], "doc check --init"),
        (&["diff"][..], "doc diff"),
        (&["status"][..], "doc status"),
        (&["export"][..], "doc export"),
        (&["apply"][..], "doc apply"),
        (&["secure", "github"][..], "removed"),
        (&["git", "push"][..], "git push"),
    ] {
        let message = usage_of(retired);
        assert!(
            message.contains(expected),
            "`cermet {}` must point at `{expected}`, got:\n{message}",
            retired.join(" ")
        );
    }
    // An unrelated unknown command is still just unknown.
    assert!(usage_of(&["frobnicate"]).contains("frobnicate"));
}

#[test]
fn run_takes_the_dotted_verb_and_its_request_fields() {
    assert_eq!(
        parse(&argv(&["run", "vercel.deploy"])).unwrap(),
        CliCommand::Run {
            retry_effect: None,
            provider: "vercel".into(),
            action: "deploy".into(),
            resource: serde_json::json!({}),
            environment: None,
            justification: None,
            ask_only: false,
        }
    );
    assert_eq!(
        parse(&argv(&[
            "run",
            "vercel.deploy",
            "--resource",
            "{\"project\":\"x\"}",
            "--environment",
            "preview",
            "--justification",
            "ship it",
            "--ask-only",
        ]))
        .unwrap(),
        CliCommand::Run {
            retry_effect: None,
            provider: "vercel".into(),
            action: "deploy".into(),
            resource: serde_json::json!({"project":"x"}),
            environment: Some("preview".into()),
            justification: Some("ship it".into()),
            ask_only: true,
        }
    );
    // The space-separated form is the sentence vocabulary's, not the CLI's.
    assert!(usage_of(&["run", "vercel", "deploy"]).contains("vercel.deploy"));
    assert!(usage_of(&["run", "vercel"]).contains("<provider>.<action>"));
    assert!(matches!(
        parse(&argv(&["run", "vercel.deploy", "--resource", "{not json"])),
        Err(CliError::Usage(_))
    ));
}

/// The referenced-retry channel is reachable from the operator surface. The flag carries the
/// safe effect handle a failed attempt named, as request METADATA — it never enters the resource
/// — and the CLI judges nothing about it.
#[test]
fn run_carries_the_retry_reference_the_daemon_authenticates() {
    let parsed = parse(&argv(&[
        "run",
        "stripe.refund_charge_bounded",
        "--resource",
        "{\"charge\":\"ch_1\",\"amount\":100}",
        "--justification",
        "the first attempt got no answer",
        "--retry-effect",
        "effect_0123456789abcdef0123456789abcdef",
    ]))
    .unwrap();
    let CliCommand::Run {
        retry_effect,
        resource,
        ..
    } = parsed
    else {
        panic!("run parses to a Run");
    };
    assert_eq!(
        retry_effect.as_deref(),
        Some("effect_0123456789abcdef0123456789abcdef")
    );
    assert!(
        resource.get("retry_effect").is_none(),
        "the reference is request metadata, never resource data: {resource}"
    );

    // A handle shape the daemon would refuse is still ACCEPTED here: one validation, on the
    // enforcement side. The CLI must not grow a second opinion about lineage.
    assert!(matches!(
        parse(&argv(&[
            "run",
            "vercel.deploy",
            "--retry-effect",
            "nonsense"
        ])),
        Ok(CliCommand::Run { .. })
    ));
    // `--resume` finishes a decided request and freezes everything; a retry is a NEW request.
    assert!(matches!(
        parse(&argv(&[
            "run",
            "--resume",
            "req_5fba5ab82ad01ded",
            "--retry-effect",
            "effect_0123456789abcdef0123456789abcdef",
        ])),
        Err(CliError::Usage(_))
    ));
}

#[test]
fn run_resume_takes_the_one_public_id_and_nothing_else() {
    assert_eq!(
        parse(&argv(&["run", "--resume", "req_5fba5ab82ad01ded"])).unwrap(),
        CliCommand::Resume {
            request_id: "req_5fba5ab82ad01ded".into(),
        }
    );
    // The operator-internal grant handle is refused with the form that works.
    let grant = usage_of(&["run", "--resume", "grant_29629c62b9c80d64"]);
    assert!(grant.contains("req_"), "{grant}");
    // Approved fields == executed fields: a resume cannot carry new fields.
    let refields = usage_of(&["run", "--resume", "req_1", "--resource", "{}"]);
    assert!(refields.contains("frozen"), "{refields}");
    assert!(usage_of(&["run", "--resume", "req_1", "vercel.deploy"]).contains("frozen"));
}

#[test]
fn log_has_a_list_form_and_a_one_request_zoom() {
    assert!(matches!(
        parse(&argv(&["log"])).unwrap(),
        CliCommand::Log { hops: false, .. }
    ));
    assert!(matches!(
        parse(&argv(&["log", "--hops", "--denied"])).unwrap(),
        CliCommand::Log {
            hops: true,
            denied_only: true,
            ..
        }
    ));
    assert_eq!(
        parse(&argv(&["log", "req_0123456789abcdef"])).unwrap(),
        CliCommand::Evidence {
            request_id: "req_0123456789abcdef".into(),
        }
    );
    // The two forms do not mix: the list flags narrow a list, not one request.
    assert!(usage_of(&["log", "req_1", "--denied"]).contains("log <request_id>"));
    assert!(usage_of(&["log", "req_1", "req_2"]).contains("log <request_id>"));
}

/// The window and its filters are DECLARED — the default window, `--all` and `--provider`
/// are settings, so they parse AND they appear in the help (undeclared behavior paths do not exist).
#[test]
fn log_declares_its_window_and_its_filters() {
    assert!(matches!(
        parse(&argv(&["log"])).unwrap(),
        CliCommand::Log {
            all: false,
            provider: None,
            ..
        }
    ));
    assert!(matches!(
        parse(&argv(&["log", "--all"])).unwrap(),
        CliCommand::Log { all: true, .. }
    ));
    let one = parse(&argv(&["log", "--provider", "stripe", "--denied"])).unwrap();
    assert!(
        matches!(&one, CliCommand::Log { provider: Some(p), denied_only: true, all: false, .. } if p == "stripe"),
        "{one:?}"
    );
    // The filters compose with the window and with each other.
    assert!(matches!(
        parse(&argv(&[
            "log",
            "--since",
            "2026-08-03T00:00:00Z",
            "--provider",
            "vercel",
            "--hops",
            "--all",
        ]))
        .unwrap(),
        CliCommand::Log {
            hops: true,
            all: true,
            ..
        }
    ));
    // Asked twice is a question, not a narrowing.
    assert!(usage_of(&["log", "--provider", "a", "--provider", "b"]).contains("only once"));
    // The id form still refuses every list flag.
    assert!(usage_of(&["log", "req_1", "--all"]).contains("log <request_id>"));
    assert!(usage_of(&["log", "req_1", "--provider", "stripe"]).contains("log <request_id>"));

    // Declared in the banner, and in `log --help` in full.
    let banner = usage_of(&[]);
    for declared in ["--provider", "--all", "newest 100 rows"] {
        assert!(
            banner.contains(declared),
            "the banner must declare {declared}:\n{banner}"
        );
    }
    let log_help = cermet_cli::help_text(&argv(&["log", "--help"])).expect("log has help");
    for declared in ["--since", "--provider", "--denied", "--hops", "--all"] {
        assert!(
            log_help.contains(declared),
            "`log --help` must declare {declared}:\n{log_help}"
        );
    }
}

#[test]
fn rules_is_a_noun_with_its_three_mutations() {
    assert_eq!(parse(&argv(&["rules"])).unwrap(), CliCommand::Rules);
    assert_eq!(
        parse(&argv(&["rules", "allow", "allow stripe.refund", "--yes"])).unwrap(),
        CliCommand::Allow {
            rule: "allow stripe.refund".into(),
            yes: true,
        }
    );
    assert_eq!(
        parse(&argv(&["rules", "revoke", "2"])).unwrap(),
        CliCommand::Revoke {
            number: 2,
            yes: false,
        }
    );
    assert_eq!(
        parse(&argv(&["rules", "refresh", "3"])).unwrap(),
        CliCommand::Refresh { number: 3 }
    );
    for invalid in [
        vec!["rules", "revoke", "0"],
        vec!["rules", "refresh", "zero"],
        vec!["rules", "pin", "1"],
        vec!["rules", "allow"],
    ] {
        assert!(
            matches!(parse(&argv(&invalid)), Err(CliError::Usage(_))),
            "{invalid:?} must be a usage error"
        );
    }
}

#[test]
fn doc_is_a_noun_and_init_folds_into_check() {
    assert_eq!(
        parse(&argv(&["doc", "check"])).unwrap(),
        CliCommand::DocCheck { fix: false }
    );
    assert_eq!(
        parse(&argv(&["doc", "check", "--fix"])).unwrap(),
        CliCommand::DocCheck { fix: true }
    );
    assert_eq!(
        parse(&argv(&["doc", "check", "--init"])).unwrap(),
        CliCommand::Init
    );
    assert_eq!(parse(&argv(&["doc", "diff"])).unwrap(), CliCommand::Diff);
    assert_eq!(
        parse(&argv(&["doc", "status", "--json"])).unwrap(),
        CliCommand::Status { as_json: true }
    );
    assert_eq!(
        parse(&argv(&["doc", "export", "--replace-draft"])).unwrap(),
        CliCommand::Export {
            replace_draft: true
        }
    );
    assert_eq!(
        parse(&argv(&["doc", "apply", "--replace-live", "--recover"])).unwrap(),
        CliCommand::Apply {
            file: None,
            replace_live: true,
            recover: true,
        }
    );
    for invalid in [
        vec!["doc"],
        vec!["doc", "check", "--fix", "--init"],
        vec!["doc", "status", "--fix"],
        vec!["doc", "publish"],
    ] {
        assert!(
            matches!(parse(&argv(&invalid)), Err(CliError::Usage(_))),
            "{invalid:?} must be a usage error"
        );
    }
}

#[test]
fn check_takes_an_optional_provider() {
    assert_eq!(
        parse(&argv(&["check"])).unwrap(),
        CliCommand::Check { provider: None }
    );
    assert_eq!(
        parse(&argv(&["check", "github"])).unwrap(),
        CliCommand::Check {
            provider: Some("github".into()),
        }
    );
    assert!(matches!(
        parse(&argv(&["check", "github", "vercel"])),
        Err(CliError::Usage(_))
    ));
    // `check --fix` was the DOCUMENT check; it now lives under `doc`.
    assert!(usage_of(&["check", "--fix"]).contains("doc check"));
}

#[test]
fn secure_and_git_are_gone_from_the_command_set() {
    assert!(parse(&argv(&["secure", "github", "--yes"])).is_err());
    assert!(parse(&argv(&["git", "status"])).is_err());
}

// ---- the fusion, over a real ctl.sock --------------------------------------------------------

/// `mock-vercel.deploy` is the offline verb, so an allowed request really executes.
const ALLOWED: &str = "allow mock-vercel.deploy";

async fn fixture_with_rules(rules: &str) -> BrokerFixture {
    let fixture = BrokerFixture::with_sentence_rules(rules);
    fixture
        .connect_mock_credential("mock-vercel")
        .await
        .expect("connect the offline mock credential");
    fixture
}

fn deploy(ask_only: bool) -> CliCommand {
    CliCommand::Run {
        retry_effect: None,
        provider: "mock-vercel".into(),
        action: "deploy".into(),
        resource: serde_json::json!({"project":"demo","repo_id":123,"ref":"main"}),
        environment: Some("preview".into()),
        justification: Some("the fused run proof".into()),
        ask_only,
    }
}

#[tokio::test]
async fn run_decides_and_executes_in_one_command() {
    let fixture = fixture_with_rules(ALLOWED).await;
    let out = cermet_cli::dispatch(&fixture.client, &deploy(false))
        .await
        .expect("an allowed run executes");
    assert!(out.ok, "{}", out.text);
    // The receipt of an EXECUTION, not of a decision: the provider action ran.
    assert!(
        out.text.contains("mock-vercel") && out.text.contains("deploy"),
        "the execution receipt names the verb: {}",
        out.text
    );
    assert!(
        out.text.contains("req_"),
        "the receipt carries the one public id: {}",
        out.text
    );
    assert!(
        !out.text.contains("grant_"),
        "the operator-internal handle stays internal: {}",
        out.text
    );
}

#[tokio::test]
async fn run_ask_only_answers_with_the_decision_receipt_as_json() {
    // `--ask-only` asked a question, so the answer is the receipt and NOTHING else — callers parse
    // this, and a trailing hint line would make it unparseable.
    let fixture = fixture_with_rules(ALLOWED).await;
    let out = cermet_cli::dispatch(&fixture.client, &deploy(true))
        .await
        .expect("--ask-only returns the decision");
    assert!(out.ok, "{}", out.text);
    let decision: serde_json::Value =
        serde_json::from_str(&out.text).expect("--ask-only output is JSON and nothing else");
    assert_eq!(decision["decision"], "allow", "{}", out.text);
    assert!(
        decision["request_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("req_")),
        "the receipt carries the id `run --resume` takes: {}",
        out.text
    );
}

#[tokio::test]
async fn run_ask_only_answers_a_deny_the_same_parseable_way() {
    // Same JSON shape as an allow — deliberately — but exit 1 . `cermet --help` documents "0 success/aligned, 1 denied", and a wrapper
    // that checks only the exit code was reading a deny as a success. The receipt stays the whole
    // output, so a caller may still branch on `decision`; the exit code no longer lies to one that
    // does not.
    let fixture = fixture_with_rules("").await;
    let out = cermet_cli::dispatch(&fixture.client, &deploy(true))
        .await
        .expect("--ask-only returns the decision");
    assert!(
        !out.ok,
        "a denied decision exits 1, as the documented contract says: {}",
        out.text
    );
    let decision: serde_json::Value =
        serde_json::from_str(&out.text).expect("--ask-only output is JSON and nothing else");
    assert_eq!(decision["decision"], "deny", "{}", out.text);
    assert!(
        decision["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "a deny carries its reason: {}",
        out.text
    );
}

#[tokio::test]
async fn a_denied_run_never_executes_and_exits_nonzero() {
    // An empty corpus denies everything (fail closed).
    let fixture = fixture_with_rules("").await;
    let out = cermet_cli::dispatch(&fixture.client, &deploy(false))
        .await
        .expect("a deny is a rendered outcome, not a transport error");
    assert!(!out.ok, "a denied run must exit non-zero: {}", out.text);
    assert!(
        out.text.to_lowercase().contains("denied"),
        "the denial says so: {}",
        out.text
    );
    assert!(
        !out.text.contains("\"envelope\""),
        "a denied run must not carry an execution receipt: {}",
        out.text
    );
}

/// The other half of N3: the flag reaches the DAEMON, and the daemon is what refuses it. An effect
/// handle with no lineage is a recorded DENY, not a client-side error — proof both that the frame
/// carried the reference and that no second opinion sits in front of it.
#[tokio::test]
async fn a_retry_reference_with_no_lineage_is_denied_by_the_daemon() {
    let fixture = fixture_with_rules(ALLOWED).await;
    let mut cmd = deploy(false);
    if let CliCommand::Run { retry_effect, .. } = &mut cmd {
        *retry_effect = Some("effect_0123456789abcdef0123456789abcdef".into());
    }
    let out = cermet_cli::dispatch(&fixture.client, &cmd)
        .await
        .expect("the daemon answers with a decision, not a transport error");
    assert!(
        !out.ok,
        "an unauthenticated lineage must not execute: {}",
        out.text
    );
    assert!(
        out.text.contains("retry effect lineage is unavailable"),
        "the daemon's own refusal reaches the operator: {}",
        out.text
    );
}

#[tokio::test]
async fn resume_executes_a_request_left_at_its_decision() {
    let fixture = fixture_with_rules(ALLOWED).await;
    let decided = cermet_cli::dispatch(&fixture.client, &deploy(true))
        .await
        .expect("--ask-only decision");
    let decision: serde_json::Value = serde_json::from_str(&decided.text).expect("decision JSON");
    let request_id = decision["request_id"]
        .as_str()
        .expect("a decided request")
        .to_string();

    let out = cermet_cli::dispatch(&fixture.client, &CliCommand::Resume { request_id })
        .await
        .expect("resume executes the approved request");
    assert!(out.ok, "{}", out.text);
    assert!(out.text.contains("mock-vercel"), "{}", out.text);
}

#[tokio::test]
async fn log_of_one_request_renders_its_verified_evidence() {
    let fixture = fixture_with_rules(ALLOWED).await;
    let out = cermet_cli::dispatch(&fixture.client, &deploy(false))
        .await
        .expect("run");
    let request_id = out
        .text
        .split('"')
        .find(|word| word.starts_with("req_"))
        .expect("the receipt names a request id")
        .to_string();

    let evidence = cermet_cli::dispatch(&fixture.client, &CliCommand::Evidence { request_id })
        .await
        .expect("log <request_id> reads the evidence");
    assert!(evidence.ok, "{}", evidence.text);
    // It is the JSON `evidence --json` rendered.
    let parsed: serde_json::Value =
        serde_json::from_str(&evidence.text).expect("the id form renders JSON");
    assert!(parsed.is_object(), "{}", evidence.text);
}

// Keeps the unused import honest on builds that skip the async cases.
#[allow(dead_code)]
fn _secret_string_is_used(s: SecretString) -> SecretString {
    s
}

/// `cermet log <request_id>` on a DENIED id must not answer `cermet: not found: not found: req_…
/// was denied (…)` — a doubled class prefix wrapped around a sentence apologizing for a record
/// that was right there. The denial IS the evidence; render it.
/// An id the broker never saw still fails closed, with its class named exactly once.
#[tokio::test]
async fn log_renders_a_denied_request_and_names_not_found_once() {
    // An empty corpus denies everything: fail closed.
    let fixture = fixture_with_rules("").await;
    let decided = cermet_cli::dispatch(&fixture.client, &deploy(true))
        .await
        .expect("--ask-only decides even when the corpus denies");
    let request_id = serde_json::from_str::<serde_json::Value>(&decided.text)
        .expect("the decision receipt is JSON")["request_id"]
        .as_str()
        .expect("a denial still carries the one public id")
        .to_string();

    let rendered = cermet_cli::dispatch(
        &fixture.client,
        &CliCommand::Evidence {
            request_id: request_id.clone(),
        },
    )
    .await
    .expect("a denied request id renders its record");
    let view: serde_json::Value =
        serde_json::from_str(&rendered.text).expect("the deny evidence is JSON");
    assert_eq!(view["request_id"], serde_json::json!(request_id));
    assert_eq!(view["provider"], serde_json::json!("mock-vercel"));
    assert_eq!(view["action"], serde_json::json!("deploy"));
    assert_eq!(view["decision"], serde_json::json!("deny"));
    assert_eq!(
        view["resource"]["project"],
        serde_json::json!("demo"),
        "the requested fields render verbatim — deny rows are lossless"
    );
    assert!(
        view["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "the stored reason carries the deny provenance: {view}"
    );
    assert!(view["created_at"].as_str().is_some_and(|t| !t.is_empty()));
    assert!(
        view.get("grant_id").is_none(),
        "a denial minted no grant, so no grant handle may render: {view}"
    );

    // The id the broker never saw: one class prefix, once.
    let error = cermet_cli::dispatch(
        &fixture.client,
        &CliCommand::Evidence {
            request_id: "req_ffffffffffffffff".into(),
        },
    )
    .await
    .expect_err("an unknown id fails closed")
    .to_string();
    assert_eq!(
        error.matches("not found:").count(),
        1,
        "the error class crosses the ctl wire ONCE: {error}"
    );
    assert_eq!(
        error,
        "not found: no execution evidence for req_ffffffffffffffff"
    );
}
