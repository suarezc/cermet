//! Structural tests: the retired daemonless / app / tray verbs no longer parse. `mcp install`
//! survives; bare `mcp` (the daemonless server), `open`, `broker-connect`, `rules-pin`, and
//! `log --results` all fail parsing. The daemon-backed surface is the only path.

use cermet_cli::{parse, CliCommand};

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[test]
fn bare_mcp_no_longer_serves_the_daemonless_server() {
    // `cermet mcp` was the in-process daemonless sentence MCP server — deleted with the runtime.
    assert!(
        parse(&argv(&["mcp"])).is_err(),
        "bare `cermet mcp` must be unknown/incomplete now (the daemonless server is gone)"
    );
}

#[test]
fn mcp_install_still_parses() {
    // The retained registration path stays: it repoints `cermet mcp` over cermetd.
    assert!(
        matches!(
            parse(&argv(&["mcp", "install"])),
            Ok(CliCommand::McpInstall(_))
        ),
        "`cermet mcp install` must still parse"
    );
}

#[test]
fn open_no_longer_parses() {
    // `cermet open` bootstrapped a browser session against cermet-app, which is deleted.
    assert!(
        parse(&argv(&["open"])).is_err(),
        "`cermet open` must fail parsing (cermet-app is gone)"
    );
}

#[test]
fn broker_connect_no_longer_parses() {
    // `broker-connect` was the daemonless-vs-broker connect alias; only `connect` remains.
    assert!(
        parse(&argv(&["broker-connect", "stripe"])).is_err(),
        "`broker-connect` must fail parsing (only `connect` remains)"
    );
}

#[test]
fn rules_pin_no_longer_parses() {
    // `rules-pin` printed the daemonless Keychain approval pin for cross-uid provisioning — gone.
    assert!(
        parse(&argv(&["rules-pin"])).is_err(),
        "`rules-pin` must fail parsing (the daemonless Keychain pin is gone)"
    );
}

#[test]
fn log_results_flag_no_longer_parses() {
    // `--results` inlined the daemonless receipt result; the daemon History path has no analogue.
    assert!(
        parse(&argv(&["log", "--results"])).is_err(),
        "`log --results` must fail parsing (the daemonless receipt result is gone)"
    );
    // Plain `log` (and its retained flags) still parse.
    assert!(
        matches!(parse(&argv(&["log"])), Ok(CliCommand::Log { .. })),
        "plain `cermet log` must still parse"
    );
    assert!(
        matches!(
            parse(&argv(&["log", "--denied"])),
            Ok(CliCommand::Log { .. })
        ),
        "`cermet log --denied` must still parse"
    );
    // The relay hop view is a DECLARED flag, not an undeclared behavior path — it parses and it
    // is named in the usage banner.
    assert!(
        matches!(
            parse(&argv(&["log", "--hops"])),
            Ok(CliCommand::Log { hops: true, .. })
        ),
        "`cermet log --hops` must parse as the relay hop view"
    );
    assert!(
        matches!(
            parse(&argv(&["log"])),
            Ok(CliCommand::Log { hops: false, .. })
        ),
        "the hop view is asked for; plain `cermet log` is still the grant receipt"
    );
    let usage = parse(&argv(&["log", "--nonsense"]))
        .expect_err("an unknown log flag is a usage error")
        .to_string();
    assert!(usage.contains("--nonsense"), "{usage}");
}

#[test]
fn cermet_md_cutover_removes_parallel_authority_commands() {
    for args in [
        &["pending"][..],
        &["approve", "grant_1"],
        &["deny", "grant_1"],
        &["policy", "apply", "--from", "policy.yaml"],
        &["profile", "list"],
        &["profile", "show", "default"],
        &["profile", "activate", "default"],
        &["sentence-status"],
        &["test-mode", "on", "30m"],
        &["test-mode", "off"],
    ] {
        assert!(
            parse(&argv(args)).is_err(),
            "retired authority surface must not parse: {args:?}"
        );
    }
}

#[test]
fn capability_requests_no_longer_accept_profile_aliases() {
    assert!(
        parse(&argv(&["run", "--alias", "deploy"])).is_err(),
        "alias-form requests must disappear at the one-corpus cutover"
    );
    assert!(
        matches!(
            parse(&argv(&["run", "vercel.projects_list"])),
            Ok(CliCommand::Run { .. })
        ),
        "direct provider.action requests remain"
    );
}
