use super::*;
use cermet_ipc::wire::ArtifactRange;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

// ---- parse ---------------------------------------------------------------------------------

#[test]
fn parse_mcp_install_client_selector() {
    use crate::mcp::McpClient;
    // Bare `mcp` (the retired daemonless server) is now unknown/incomplete.
    assert!(matches!(parse(&argv(&["mcp"])), Err(CliError::Usage(_))));
    // Default client is claude (existing behavior byte-compatible).
    match parse(&argv(&["mcp", "install"])).unwrap() {
        CliCommand::McpInstall(a) => assert_eq!(a.client, McpClient::Claude),
        other => panic!("expected McpInstall, got {other:?}"),
    }
    match parse(&argv(&["mcp", "install", "--client", "opencode"])).unwrap() {
        CliCommand::McpInstall(a) => assert_eq!(a.client, McpClient::OpenCode),
        other => panic!("expected McpInstall, got {other:?}"),
    }
    match parse(&argv(&["mcp", "install", "--client", "claude"])).unwrap() {
        CliCommand::McpInstall(a) => assert_eq!(a.client, McpClient::Claude),
        other => panic!("expected McpInstall, got {other:?}"),
    }
    // An unknown client is a usage error, not a silent default.
    assert!(matches!(
        parse(&argv(&["mcp", "install", "--client", "cursor"])),
        Err(CliError::Usage(_))
    ));
}

/// `cermet update` — the thirteenth command. Two forms: the operator's, and the privileged half it
/// re-execs itself as through sudo.
#[test]
fn parse_update_has_two_forms_and_they_do_not_mix() {
    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(
        parse(&argv(&["update"])).unwrap(),
        CliCommand::Update { check: false }
    );
    assert_eq!(
        parse(&argv(&["update", "--check"])).unwrap(),
        CliCommand::Update { check: true }
    );
    assert_eq!(
        parse(&argv(&["update", "--apply", DIGEST])).unwrap(),
        CliCommand::UpdateApply {
            sha256: DIGEST.to_string()
        }
    );
    // --apply carries the digest of the bytes the unprivileged half already verified; asking it to
    // "check" as well is two different commands in one invocation.
    assert!(matches!(
        parse(&argv(&["update", "--apply", DIGEST, "--check"])),
        Err(CliError::Usage(_))
    ));
    // A digest that is not a digest never reaches the privileged path.
    assert!(matches!(
        parse(&argv(&["update", "--apply", "nope"])),
        Err(CliError::Usage(_))
    ));
    assert!(matches!(
        parse(&argv(&["update", "--apply"])),
        Err(CliError::Usage(_))
    ));
    assert!(matches!(
        parse(&argv(&["update", "--force"])),
        Err(CliError::Usage(_))
    ));
    assert!(matches!(
        parse(&argv(&["update", "nightly"])),
        Err(CliError::Usage(_))
    ));

    // The packaged box's privileged half: a package path plus the digest it was verified against.
    assert_eq!(
        parse(&argv(&[
            "update",
            "--apply-deb",
            "/var/tmp/x/cermet_0.1.1_amd64.deb",
            "--sha256",
            DIGEST
        ]))
        .unwrap(),
        CliCommand::UpdateApplyDeb {
            package: "/var/tmp/x/cermet_0.1.1_amd64.deb".to_string(),
            sha256: DIGEST.to_string(),
        }
    );
    // Neither half is complete without the other, and the two halves never mix.
    for bad in [
        vec!["update", "--apply-deb", "/tmp/x.deb"],
        vec!["update", "--sha256", DIGEST],
        vec!["update", "--apply-deb", "/tmp/x.deb", "--sha256", "nope"],
        vec![
            "update",
            "--apply-deb",
            "/tmp/x.deb",
            "--sha256",
            DIGEST,
            "--check",
        ],
        vec!["update", "--apply", DIGEST, "--apply-deb", "/tmp/x.deb"],
    ] {
        assert!(
            matches!(parse(&argv(&bad)), Err(CliError::Usage(_))),
            "{bad:?} must be a usage error"
        );
    }
}

/// Help is a first-class surface at every depth, and that is a dispatch-layer rule — so a command
/// added later inherits it. Asserted, not assumed. The banner has to name the command too, or it is
/// undiscoverable.
#[test]
fn update_is_on_both_help_surfaces() {
    let one = help_text(&argv(&["update", "--help"])).expect("update has its own usage");
    assert!(one.contains("--check"), "{one}");
    assert!(
        one.contains("CERMET_UPDATE_ORIGIN"),
        "the origin override is declared where the command is documented: {one}"
    );
    assert!(
        one.contains("https://github.com/suarezc/cermet/releases"),
        "the usage names the release channel it contacts: {one}"
    );
    // The daily check is documented where the command is, and so is the fact that it never
    // installs: default-on is only honest if what it does — and does not do — is findable.
    assert!(one.contains("--daily on|off"), "{one}");
    assert!(one.contains("--daily-check"), "{one}");
    assert!(
        one.contains("It installs nothing"),
        "the check's usage says what it does NOT do: {one}"
    );
    let banner = help_text(&argv(&["--help"])).expect("the banner");
    assert!(banner.contains("update"), "{banner}");
    assert!(
        banner.contains("update --daily on|off"),
        "a default-on behavior whose off switch is off the banner is undiscoverable: {banner}"
    );
}

/// The daily check's two forms, under the EXISTING `update` noun rather than a noun of their own:
/// the knob, and the scheduled run the installed timer invokes.
#[test]
fn the_daily_check_lives_under_the_update_noun_and_does_not_mix_with_installing() {
    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(
        parse(&argv(&["update", "--daily-check"])).unwrap(),
        CliCommand::UpdateDailyCheck
    );
    assert_eq!(
        parse(&argv(&["update", "--daily", "on"])).unwrap(),
        CliCommand::UpdateDaily { enabled: true }
    );
    assert_eq!(
        parse(&argv(&["update", "--daily", "off"])).unwrap(),
        CliCommand::UpdateDaily { enabled: false }
    );

    // A knob whose value is a guess is not a knob, and a missing value names nothing.
    for bad in [
        vec!["update", "--daily", "true"],
        vec!["update", "--daily", "yes"],
        vec!["update", "--daily"],
        vec!["update", "--daily", "ON"],
    ] {
        assert!(
            matches!(parse(&argv(&bad)), Err(CliError::Usage(_))),
            "{bad:?} must be a usage error"
        );
    }

    // Neither form mixes with installing, with `--check`, with the other, or with a privileged
    // half: those are different commands, and guessing which was meant is what a fail-closed
    // parser must not do.
    for bad in [
        vec!["update", "--daily-check", "--check"],
        vec!["update", "--check", "--daily", "off"],
        vec!["update", "--daily-check", "--daily", "on"],
        vec!["update", "--daily", "on", "--apply", DIGEST],
        vec!["update", "--daily-check", "--apply-deb", "/tmp/x.deb"],
        vec!["update", "--daily", "on", "--sha256", DIGEST],
    ] {
        assert!(
            matches!(parse(&argv(&bad)), Err(CliError::Usage(_))),
            "{bad:?} must be a usage error"
        );
    }
}

/// The model self-report is a DECLARED behavior path, so it is documented where the
/// command that reads it is documented — undeclared behavior does not exist.
#[test]
fn the_model_self_report_env_is_declared_on_the_mcp_help() {
    let help = help_text(&argv(&["mcp", "--help"])).expect("mcp has its own usage");
    for fact in [
        crate::mcp_bridge::server::AGENT_MODEL_ENV,
        "SELF-REPORT",
        "no authority reads it",
        "it grants nothing",
    ] {
        assert!(
            help.contains(fact),
            "mcp --help must state {fact:?}: {help}"
        );
    }
}

#[test]
fn parse_closed_owner_lockdown_vocabulary() {
    assert_eq!(
        parse(&argv(&["owner", "status"])).unwrap(),
        CliCommand::OwnerStatus
    );
    assert_eq!(
        parse(&argv(&["owner", "lockdown"])).unwrap(),
        CliCommand::OwnerLockdown
    );
    assert_eq!(
        parse(&argv(&["owner", "lockdown", "clear"])).unwrap(),
        CliCommand::OwnerLockdownClear
    );
    assert!(matches!(
        parse(&argv(&["owner", "approve"])),
        Err(CliError::Usage(_))
    ));
}

#[test]
fn parse_revoke_number_and_yes_flag() {
    // `--yes` skips only the CLI-side y/N confirm (the presence gate still governs the custody
    // swap), giving scripts a noninteractive revoke path.
    assert!(matches!(
        parse(&argv(&["rules", "revoke", "2"])).unwrap(),
        CliCommand::Revoke {
            number: 2,
            yes: false
        }
    ));
    assert!(matches!(
        parse(&argv(&["rules", "revoke", "2", "--yes"])).unwrap(),
        CliCommand::Revoke {
            number: 2,
            yes: true
        }
    ));
    assert!(matches!(
        parse(&argv(&["rules", "revoke", "--yes", "3"])).unwrap(),
        CliCommand::Revoke {
            number: 3,
            yes: true
        }
    ));
    assert!(matches!(
        parse(&argv(&["rules", "revoke", "--no"])),
        Err(CliError::Usage(_))
    ));
    assert!(matches!(
        parse(&argv(&["rules", "revoke", "0", "--yes"])),
        Err(CliError::Usage(_))
    ));
}

// ---- artifact parse/render -------------------------------------------------------------------

#[test]
fn parse_artifact_handle_and_range() {
    assert_eq!(
        parse(&argv(&["artifact", "art_1"])).unwrap(),
        CliCommand::Artifact {
            handle: "art_1".into(),
            range: None,
            path: None,
        }
    );
    // "full read forwards no range"
    assert_eq!(
        parse(&argv(&["artifact", "art_1", "--range", "lines:1-50"])).unwrap(),
        CliCommand::Artifact {
            handle: "art_1".into(),
            range: Some(ArtifactRange {
                unit: "lines".into(),
                start: 1,
                end: Some(50)
            }),
            path: None,
        }
    );
    // A `$.path` capture-pointer rides the same subcommand.
    assert_eq!(
        parse(&argv(&["artifact", "art_1", "--path", "$.deployment.url"])).unwrap(),
        CliCommand::Artifact {
            handle: "art_1".into(),
            range: None,
            path: Some("$.deployment.url".into()),
        }
    );
}

#[test]
fn parse_artifact_rejects_a_bad_range() {
    // "words:1" — a malformed range NEVER reaches the host (a parse-time usage error).
    assert!(matches!(
        parse(&argv(&["artifact", "art_1", "--range", "words:1"])),
        Err(CliError::Usage(_))
    ));
    assert!(matches!(
        parse(&argv(&["artifact", "art_1", "--range", "lines:"])),
        Err(CliError::Usage(_))
    ));
}

#[test]
fn parse_artifact_path_validated_and_exclusive_with_range() {
    // A pointer missing the `$.` prefix or with an empty segment is a client-side usage error.
    assert!(matches!(
        parse(&argv(&["artifact", "art_1", "--path", "deployment.url"])),
        Err(CliError::Usage(_))
    ));
    assert!(matches!(
        parse(&argv(&["artifact", "art_1", "--path", "$.a..b"])),
        Err(CliError::Usage(_))
    ));
    // --range and --path are mutually exclusive.
    assert!(matches!(
        parse(&argv(&[
            "artifact",
            "art_1",
            "--range",
            "bytes:0-4",
            "--path",
            "$.a"
        ])),
        Err(CliError::Usage(_))
    ));
}

#[test]
fn render_artifact_prints_metadata_and_content() {
    // Ported from test_artifact_prints_metadata_and_content: art_1, "42 bytes", content survive.
    let span = json!({
        "handle": "art_1",
        "digest": "sha256:abc",
        "size": 42,
        "stored_size": 42,
        "truncated": false,
        "unit": "bytes",
        "start": 0,
        "end": 42,
        "content": "test result: ok. 12 passed; 0 failed",
    });
    let out = render_artifact("art_1", false, &span).unwrap();
    assert!(out.ok);
    assert!(out.text.contains("art_1"), "{}", out.text);
    assert!(out.text.contains("42 bytes"), "{}", out.text);
    assert!(out.text.contains("12 passed; 0 failed"), "{}", out.text);
    // No range given ⇒ no span line.
    assert!(!out.text.contains("span:"), "{}", out.text);
}

#[test]
fn render_artifact_shows_span_and_frame_truncation_note() {
    let span = json!({
        "handle": "art_1",
        "digest": "d",
        "size": 100000,
        "stored_size": 100000,
        "truncated": true,
        "unit": "bytes",
        "start": 0,
        "end": 512,
        "frame_truncated": true,
        "content": "head bytes",
    });
    let out = render_artifact("art_1", true, &span).unwrap();
    assert!(out.text.contains("span:     bytes 0..512"), "{}", out.text);
    assert!(
        out.text.contains("truncated (head+tail kept)"),
        "{}",
        out.text
    );
    assert!(
        out.text.contains("output too large to show in full"),
        "{}",
        out.text
    );
}

// ---- a malformed artifact view must ERROR, never render as an empty success -----------------

fn full_span() -> Value {
    json!({
        "handle": "art_1",
        "digest": "sha256:abc",
        "size": 42,
        "stored_size": 42,
        "truncated": false,
        "unit": "bytes",
        "start": 0,
        "end": 42,
        "content": "test result: ok. 12 passed; 0 failed",
    })
}

#[test]
fn render_artifact_missing_required_field_fails_closed() {
    // Required span fields must never default to empty/zero — a view missing any of them is a
    // malformed response and must fail closed, not print a hollow artifact.
    for missing in [
        "handle",
        "digest",
        "size",
        "stored_size",
        "truncated",
        "unit",
        "start",
        "end",
        "content",
    ] {
        let mut span = full_span();
        span.as_object_mut().unwrap().remove(missing);
        match render_artifact("art_1", false, &span) {
            Err(CliError::Malformed(_)) => {}
            other => panic!("span missing {missing:?} must fail closed, got {other:?}"),
        }
    }
}

#[test]
fn render_artifact_mistyped_field_fails_closed() {
    // A mistyped required field (version skew / corruption) is malformed, not zero.
    for (field, bad) in [
        ("size", json!("forty-two")),
        ("start", json!("0")),
        ("content", json!(42)),
        ("truncated", json!("no")),
    ] {
        let mut span = full_span();
        span[field] = bad.clone();
        match render_artifact("art_1", false, &span) {
            Err(CliError::Malformed(_)) => {}
            other => panic!("mistyped {field:?} ({bad}) must fail closed, got {other:?}"),
        }
    }
}

#[test]
fn render_artifact_only_frame_truncated_may_default() {
    // The one explicitly-optional field: a span WITHOUT frame_truncated still renders (it
    // defaults false — no paging note), everything else present.
    let out = render_artifact("art_1", false, &full_span())
        .expect("frame_truncated is optional and defaults false");
    assert!(!out.text.contains("output too large"), "{}", out.text);
    assert!(out.text.contains("12 passed"), "{}", out.text);
}

// ---- degenerate ranges are rejected client-side, never forwarded ----------------------------

#[test]
fn parse_range_rejects_a_reversed_range() {
    for spec in ["bytes:10-2", "lines:40-2"] {
        assert!(
            matches!(
                parse(&argv(&["artifact", "art_1", "--range", spec])),
                Err(CliError::Usage(_))
            ),
            "reversed range {spec:?} must be a usage error, not forwarded for the daemon to clamp"
        );
    }
}

#[test]
fn parse_range_rejects_zero_line_start() {
    // Lines are 1-based: `lines:0` cannot name a line; reject it rather than let the daemon
    // silently clamp it.
    for spec in ["lines:0", "lines:0-5"] {
        assert!(
            matches!(
                parse(&argv(&["artifact", "art_1", "--range", spec])),
                Err(CliError::Usage(_))
            ),
            "{spec:?} must be a usage error (lines are 1-based)"
        );
    }
    // bytes are 0-based: bytes:0 stays valid.
    assert!(parse(&argv(&["artifact", "art_1", "--range", "bytes:0-4"])).is_ok());
}

#[test]
fn parse_range_accepts_huge_but_semantically_valid_spans() {
    // Only reject the semantically invalid — no invented caps: u64::MAX as an END is fine.
    assert_eq!(
        parse(&argv(&[
            "artifact",
            "art_1",
            "--range",
            "bytes:0-18446744073709551615"
        ]))
        .unwrap(),
        CliCommand::Artifact {
            handle: "art_1".into(),
            range: Some(ArtifactRange {
                unit: "bytes".into(),
                start: 0,
                end: Some(u64::MAX)
            }),
            path: None,
        }
    );
    // Equal endpoints satisfy end >= start.
    assert!(parse(&argv(&["artifact", "art_1", "--range", "bytes:5-5"])).is_ok());
    assert!(parse(&argv(&["artifact", "art_1", "--range", "lines:3-3"])).is_ok());
    // Non-numeric stays rejected.
    assert!(matches!(
        parse(&argv(&["artifact", "art_1", "--range", "bytes:a-9"])),
        Err(CliError::Usage(_))
    ));
}

// ---- explicit empty/whitespace values are usage errors at PARSE time ------------------------

#[test]
fn parse_rejects_empty_or_whitespace_positionals() {
    // Refused at parse time — before any I/O and structurally before any presence prompt (the
    // CliCommand is never constructed, so dispatch/gate can never run).
    for empty in ["", "   "] {
        for args in [vec!["run", "--resume", empty], vec!["artifact", empty]] {
            assert!(
                matches!(parse(&argv(&args)), Err(CliError::Usage(_))),
                "{args:?} must be a usage error (explicit empty value)"
            );
        }
    }
}

// ---- a relay receipt warns when the native CLI is not installed -----------------------------

#[test]
fn relay_receipt_warns_when_the_native_tool_is_missing_from_path() {
    // The invocation is copy-pasteable ONLY if the native CLI exists. A controlled, EMPTY PATH is
    // the miss case.
    let empty = tempfile::tempdir().unwrap();
    let result = json!({
        "relay": { "invocation": "vercel deploy --api http://127.0.0.1:7133 --token cermet_relay_Ab3 --project website --yes" }
    });
    let warning = render::relay_tool_warning(&result, Some(empty.path().as_os_str()))
        .expect("a missing native CLI warns");
    assert!(
        warning.starts_with("warning: 'vercel' not found on PATH"),
        "the warning names the tool: {warning}"
    );
    assert!(
        warning.contains("invoke it by full path"),
        "...and the way out: {warning}"
    );
}

#[test]
fn relay_receipt_is_silent_when_the_native_tool_resolves_on_path() {
    let dir = tempfile::tempdir().unwrap();
    let tool = dir.path().join("vercel");
    std::fs::write(&tool, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = json!({
        "relay": { "invocation": "vercel deploy --api http://127.0.0.1:7133 --token cermet_relay_Ab3 --project website --yes" }
    });
    assert_eq!(
        render::relay_tool_warning(&result, Some(dir.path().as_os_str())),
        None,
        "an installed native CLI must not warn"
    );
    // A non-executable file of the same name is not a resolvable tool.
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(render::relay_tool_warning(&result, Some(dir.path().as_os_str())).is_some());
}

#[test]
fn a_receipt_without_a_relay_invocation_never_warns() {
    // Never block, never speak on a verb the broker executed itself.
    for result in [
        json!({}),
        json!({ "id": "ch_1", "amount": 100 }),
        json!({ "relay": { "handle": "cermet_relay_Ab3" } }),
    ] {
        assert_eq!(render::relay_tool_warning(&result, None), None);
    }
}

#[test]
fn cli_execute_receipt_prints_the_missing_tool_warning_above_the_invocation() {
    // The CLI half: `cermet run` renders the execution receipt as JSON, so the warning is
    // the line ABOVE it. `cermet-no-such-tool` resolves nowhere, whatever the runner's PATH is.
    let view = json!({
        "ok": true, "provider": "vercel", "action": "deploy",
        "result": { "relay": { "invocation": "cermet-no-such-tool deploy --yes" } }
    })
    .to_string();
    let out = crate::dispatch::json_output(&view).unwrap();
    let (first, rest) = out.text.split_once('\n').unwrap();
    assert!(
        first.starts_with("warning: 'cermet-no-such-tool' not found on PATH"),
        "the warning leads the receipt: {}",
        out.text
    );
    assert!(
        rest.contains("cermet-no-such-tool deploy --yes"),
        "...and the invocation is still rendered below it: {}",
        out.text
    );
    // A receipt with no relay invocation renders exactly the JSON, no warning line.
    let plain = crate::dispatch::json_output(&json!({"ok": true}).to_string()).unwrap();
    assert!(!plain.text.contains("warning:"), "{}", plain.text);
}

// ---- `request_id` is the ONLY public id an agent or operator ever supplies -------------------

/// `--resume` must never answer "grant already used" by prescribing `--resume` again.
///
/// The live sequence: a relay mint's ctl reply was lost to a client-side timeout AFTER the daemon
/// had decided and minted the session, so the timeout advised `cermet run --resume <req>` and the
/// resume answered `grant already used (single-use)` — with the identical advice glued underneath.
/// A used grant's effect cannot run twice, so the resume advice is wrong for this class of refusal
/// and the operator is sent in a circle.
#[test]
fn an_already_used_grant_is_never_answered_with_the_resume_advice_that_just_failed() {
    use cermet_lang::error::{Error, ExecuteRefusal};

    let text = crate::dispatch::execute_failure_text(
        &Error::ExecuteRefused(ExecuteRefusal::AlreadyUsed),
        "req_33adeeebd22638c1",
    );
    assert!(
        text.contains("grant already used (single-use)"),
        "the daemon's own typed refusal still leads: {text}"
    );
    assert!(
        !text.contains("--resume"),
        "the advice that just failed must not be repeated: {text}"
    );
    // What the operator's work actually is, and where it is: a relay grant's ONE effect is the
    // session mint, and the receipt carries its handle and ready-to-run invocation.
    assert!(
        text.contains("cermet log req_33adeeebd22638c1"),
        "the receipt is where the effect's own result lives: {text}"
    );
    assert!(
        text.contains("cermet run"),
        "a fresh request is the path to a fresh effect: {text}"
    );

    // Every other execute failure IS resumable — the decision stands and nothing ran — so the
    // resume advice stays exactly where it was.
    for still_resumable in [
        Error::ExecuteRefused(ExecuteRefusal::NotReady),
        Error::Provider("stripe returned 500".into()),
    ] {
        let text = crate::dispatch::execute_failure_text(&still_resumable, "req_abc");
        assert!(
            text.contains("cermet run --resume req_abc"),
            "a refusal that ran no effect is still finishable: {text}"
        );
    }
}

#[test]
fn the_usage_banner_names_request_id_as_the_one_handle() {
    // Help must not advertise an id the operator cannot use anywhere.
    let usage = match parse(&argv(&[])) {
        Err(CliError::Usage(u)) => u,
        other => panic!("no command prints usage, got {other:?}"),
    };
    assert!(usage.contains("run --resume <request_id>"), "{usage}");
    assert!(usage.contains("log <request_id>"), "{usage}");
    assert!(!usage.contains("<grant_id>"), "{usage}");
}
