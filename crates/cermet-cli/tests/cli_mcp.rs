//! `cermet mcp install`. The `claude` shell-out + binary
//! resolution are behind the `ClaudeCli` seam (a fake here), so these pin: the built argv shape,
//! idempotency (remove-then-add), binary/sock resolution, the fail-closed manual-command fallback, and
//! the CLAUDE.md guidance stanza's idempotency + no-symlink-follow.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cermet_cli::mcp::{
    append_guidance_stanza, append_guidance_symlink_idempotent, default_agent_sock,
    find_bridge_binary, mcp_add_command, opencode_server_entry, project_claude_md, run_mcp_install,
    write_opencode_config, ClaudeCli, ConfigWrite, GuidanceOutcome, McpClient, McpInstallArgs,
    ProcOutcome, GUIDANCE_MARKER,
};
use cermet_cli::tty::ScriptedTerminal;

/// A fake `claude`/binary resolver that records the argv it is asked to run.
struct FakeClaude {
    claude_on_path: bool,
    agent: Option<PathBuf>,
    add_code: i32,
    add_stderr: String,
    /// When set, the `mcp remove` shell-out models a child that overran its bound and was
    /// killed — `run` returns `ErrorKind::TimedOut`, exactly as `StdClaudeCli` does on a real timeout.
    remove_times_out: bool,
    calls: Mutex<Vec<Vec<String>>>,
}

impl FakeClaude {
    fn new(claude_on_path: bool, agent: Option<&str>) -> Self {
        Self {
            claude_on_path,
            agent: agent.map(PathBuf::from),
            add_code: 0,
            add_stderr: String::new(),
            remove_times_out: false,
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl ClaudeCli for FakeClaude {
    fn which(&self, cmd: &str) -> Option<PathBuf> {
        match cmd {
            "claude" if self.claude_on_path => Some(PathBuf::from("/usr/bin/claude")),
            "cermet" => self.agent.clone(),
            _ => None,
        }
    }
    fn run(&self, argv: &[String], _timeout: std::time::Duration) -> std::io::Result<ProcOutcome> {
        self.calls.lock().unwrap().push(argv.to_vec());
        if argv.get(1).map(String::as_str) == Some("mcp")
            && argv.get(2).map(String::as_str) == Some("remove")
        {
            if self.remove_times_out {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "remove overran its bound and was killed",
                ));
            }
            return Ok(ProcOutcome {
                code: 0,
                stderr: String::new(),
            });
        }
        Ok(ProcOutcome {
            code: self.add_code,
            stderr: self.add_stderr.clone(),
        })
    }
    fn bridge_binary(&self) -> Option<PathBuf> {
        self.agent.clone()
    }
}

fn args(sock: Option<&str>, binary: Option<&str>) -> McpInstallArgs {
    McpInstallArgs {
        sock: sock.map(str::to_string),
        binary: binary.map(str::to_string),
        name: "cermet".into(),
        guidance: Some(false), // never touch a CLAUDE.md in the registration tests
        force: false,
        client: McpClient::Claude,
    }
}

use cermet_core::{McpQuiesceStatus, McpRepointBegin, McpRepointStatusReport};

/// One scripted outcome of a `status()` poll.
#[derive(Clone)]
enum Sc {
    Quiescent,
    Active,
    Orphan,
    Integrity,
    Err(String),
    /// A daemon restart mid-flow: `status` reports a DIFFERENT instance id (still quiescent), which
    /// the client detects and refuses on (fail closed, potentially-partial registration).
    Restart,
}

/// A scripted MCP-repoint barrier. `begin` mints one token; `status` pops the next
/// script (default `Quiescent` when the queue drains, so the happy-path rechecks pass); `end` records
/// the token. It records every token seen so a test can prove ONE token spans the whole remove/add.
struct FakeBarrier {
    begin_ok: bool,
    instance: String,
    statuses: Mutex<std::collections::VecDeque<Sc>>,
    /// When set, `status` returns this class on EVERY poll (ignoring the queue) — models a daemon
    /// that stays non-quiescent for the whole transaction (the `--force` proof).
    sticky: Option<Sc>,
    /// When `Some(n)`, `begin` reports a lease expiring `n` seconds from NOW (real wall clock) — used
    /// to model a near-exhausted lease so the pre-mutation budget check refuses.
    lease_secs: Option<i64>,
    minted_token: Mutex<Option<String>>,
    status_tokens: Mutex<Vec<String>>,
    ends: Mutex<Vec<String>>,
}

impl FakeBarrier {
    fn new(begin_ok: bool, statuses: Vec<Sc>) -> Self {
        Self {
            begin_ok,
            instance: "inst-1".into(),
            statuses: Mutex::new(statuses.into()),
            sticky: None,
            lease_secs: None,
            minted_token: Mutex::new(None),
            status_tokens: Mutex::new(Vec::new()),
            ends: Mutex::new(Vec::new()),
        }
    }
    /// The always-quiescent barrier (idle daemon → install proceeds).
    fn quiescent() -> Self {
        Self::new(true, vec![])
    }
    /// A reachable daemon that reports `sc` on EVERY poll (never drains).
    fn sticky(sc: Sc) -> Self {
        Self {
            sticky: Some(sc),
            ..Self::new(true, vec![])
        }
    }
    /// A quiescent daemon whose barrier lease expires in `secs` — a near-exhausted lease.
    fn short_lease(secs: i64) -> Self {
        Self {
            lease_secs: Some(secs),
            ..Self::new(true, vec![])
        }
    }
}

impl cermet_cli::mcp::RepointBarrier for FakeBarrier {
    fn begin(&self, _ttl_secs: i64) -> Result<McpRepointBegin, String> {
        if !self.begin_ok {
            return Err("cermetd ctl.sock unreachable (connection refused)".into());
        }
        let token = "tok-fake-1".to_string();
        *self.minted_token.lock().unwrap() = Some(token.clone());
        let expires_at = match self.lease_secs {
            Some(secs) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                now + secs
            }
            None => 9_999_999_999,
        };
        Ok(McpRepointBegin {
            token,
            instance_id: self.instance.clone(),
            expires_at,
        })
    }
    fn status(&self, token: &str) -> Result<McpRepointStatusReport, String> {
        self.status_tokens.lock().unwrap().push(token.to_string());
        let sc = self.sticky.clone().unwrap_or_else(|| {
            self.statuses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Sc::Quiescent)
        });
        let report = |inst: &str, status| McpRepointStatusReport {
            instance_id: inst.to_string(),
            status,
        };
        Ok(match sc {
            Sc::Quiescent => report(&self.instance, McpQuiesceStatus::Quiescent),
            Sc::Active => report(&self.instance, McpQuiesceStatus::Active { grants: vec![] }),
            Sc::Orphan => report(
                &self.instance,
                McpQuiesceStatus::OrphanAmbiguous { grants: vec![] },
            ),
            Sc::Integrity => report(
                &self.instance,
                McpQuiesceStatus::Integrity {
                    reason: "tamper".into(),
                    grants: vec![],
                },
            ),
            Sc::Err(e) => return Err(e),
            Sc::Restart => report("inst-2-RESTARTED", McpQuiesceStatus::Quiescent),
        })
    }
    fn end(&self, token: &str) {
        self.ends.lock().unwrap().push(token.to_string());
    }
}

// A non-interactive terminal: no prompts, never appends guidance.
fn term() -> ScriptedTerminal {
    ScriptedTerminal::new(false, "unused", vec![])
}

#[test]
fn default_sock_follows_cermet_home_when_no_system_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let absent = tmp.path().join("absent/agent.sock");
    assert_eq!(
        default_agent_sock(&absent, &home),
        home.join("run").join("agent.sock")
    );
}

#[test]
fn default_sock_prefers_the_system_socket_when_serving() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("agent.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    let home = tmp.path().join("home");
    assert_eq!(default_agent_sock(&sock_path, &home), sock_path);
}

#[test]
fn default_sock_ignores_a_non_socket_file_at_the_system_path() {
    let tmp = tempfile::tempdir().unwrap();
    let fake = tmp.path().join("agent.sock");
    std::fs::write(&fake, "not a socket").unwrap();
    let home = tmp.path().join("home");
    assert_eq!(
        default_agent_sock(&fake, &home),
        home.join("run").join("agent.sock")
    );
}

#[test]
fn find_bridge_binary_prefers_release_over_debug() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::create_dir_all(root.join("target/release")).unwrap();
    std::fs::create_dir_all(root.join("target/debug")).unwrap();
    for rel in ["target/release/cermet", "target/debug/cermet"] {
        let p = root.join(rel);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let fake = FakeClaude::new(true, None);
    assert_eq!(
        find_bridge_binary(Some(root), &fake),
        Some(root.join("target/release/cermet"))
    );
}

#[test]
fn install_holds_one_token_across_remove_then_add_and_ends_it() {
    // The quiesce transaction: begin → drain (quiescent) → hold the SAME token across remove+add →
    // End. Proves the argv shape, that ONE token spans every status check, and End ran.
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    let barrier = FakeBarrier::quiescent();
    let out = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&barrier),
    )
    .expect("install ok");
    assert!(out.ok, "{}", out.text);
    let calls = fake.calls.lock().unwrap();
    assert_eq!(calls[0], vec!["claude", "mcp", "remove", "cermet"]);
    assert_eq!(
        calls[1],
        mcp_add_command("cermet", Path::new("/opt/cermet"), "/tmp/agent.sock")
    );
    assert!(
        out.text.contains("registered MCP server 'cermet'"),
        "{}",
        out.text
    );
    // EVERY status check used the one begin-minted token, and the barrier was ended.
    let tokens = barrier.status_tokens.lock().unwrap();
    assert!(
        !tokens.is_empty() && tokens.iter().all(|t| t == "tok-fake-1"),
        "{tokens:?}"
    );
    assert_eq!(
        *barrier.ends.lock().unwrap(),
        vec!["tok-fake-1".to_string()]
    );
}

// ---- MCP-repoint quiesce transaction -------------------------------------------------------------

#[test]
fn orphan_ambiguous_refuses_without_force_and_touches_no_config() {
    // An expired/unreported lease may leave an agent-side child — normal repoint REFUSES and
    // never touches the `claude mcp` registration.
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    let barrier = FakeBarrier::new(true, vec![Sc::Orphan]);
    let out = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&barrier),
    )
    .expect("returns a refusal output, not an error");
    assert!(!out.ok, "orphan-ambiguous must refuse: {}", out.text);
    assert!(
        out.text.contains("--force"),
        "names the override: {}",
        out.text
    );
    assert!(
        fake.calls.lock().unwrap().is_empty(),
        "no config mutation on the fail-closed refusal"
    );
    // The barrier is released even on the refusal path.
    assert_eq!(
        *barrier.ends.lock().unwrap(),
        vec!["tok-fake-1".to_string()]
    );
}

#[test]
fn integrity_error_refuses_without_force() {
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    let barrier = FakeBarrier::new(true, vec![Sc::Integrity]);
    let out = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&barrier),
    )
    .expect("refusal output");
    assert!(!out.ok, "integrity fault must refuse: {}", out.text);
    assert!(fake.calls.lock().unwrap().is_empty());
}

#[test]
fn active_lease_drains_then_the_repoint_proceeds() {
    // A genuinely-active lease is boundedly drained (one poll), then Quiescent → proceed.
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    let barrier = FakeBarrier::new(true, vec![Sc::Active, Sc::Quiescent]);
    let out = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&barrier),
    )
    .expect("install ok after drain");
    assert!(
        out.ok,
        "an active lease must drain then proceed: {}",
        out.text
    );
    assert!(
        !fake.calls.lock().unwrap().is_empty(),
        "the repoint runs after the drain"
    );
}

#[test]
fn force_spans_the_mutation_against_a_persistently_orphan_ambiguous_daemon() {
    // A REACHABLE daemon that reports OrphanAmbiguous on EVERY poll (never drains to
    // Quiescent). `--force` must proceed through the COMPLETE remove/add mutation — the pre-mutation
    // rechecks must tolerate the non-Quiescent class under force — and emit the orphan warning.
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    let barrier = FakeBarrier::sticky(Sc::Orphan);
    let a = McpInstallArgs {
        force: true,
        ..args(Some("/tmp/agent.sock"), Some("/opt/cermet"))
    };
    let out =
        run_mcp_install(&a, &fake, &term(), Some(&barrier)).expect("install ok under --force");
    assert!(
        out.ok,
        "--force must repoint against a persistently-orphan daemon: {}",
        out.text
    );
    assert!(
        out.text.contains("--force"),
        "the success line warns of a possible orphan: {}",
        out.text
    );
    // The FULL mutation ran: remove THEN add, both under the held barrier.
    let calls = fake.calls.lock().unwrap();
    assert_eq!(
        calls[0],
        vec!["claude", "mcp", "remove", "cermet"],
        "{calls:?}"
    );
    assert_eq!(
        calls[1],
        mcp_add_command("cermet", Path::new("/opt/cermet"), "/tmp/agent.sock"),
        "the add must run under --force despite the daemon never quiescing"
    );
    assert_eq!(
        *barrier.ends.lock().unwrap(),
        vec!["tok-fake-1".to_string()],
        "barrier ended after"
    );
}

#[test]
fn force_still_aborts_on_a_daemon_restart_mid_mutation() {
    // `--force` tolerates a non-Quiescent CLASS but the recheck stays LIVE for instance
    // change — a restart between remove and add still stops fail-closed and reports PARTIAL.
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    // drain(orphan, forced-proceed) → before-remove recheck(orphan, ok) → between recheck(RESTART).
    let barrier = FakeBarrier::new(true, vec![Sc::Orphan, Sc::Orphan, Sc::Restart]);
    let a = McpInstallArgs {
        force: true,
        ..args(Some("/tmp/agent.sock"), Some("/opt/cermet"))
    };
    let err = run_mcp_install(&a, &fake, &term(), Some(&barrier))
        .expect_err("a mid-mutation restart must stop even under --force");
    match err {
        cermet_cli::CliError::Refused(m) => assert!(m.contains("PARTIAL"), "{m}"),
        other => panic!("expected Refused, got {other:?}"),
    }
    let calls = fake.calls.lock().unwrap();
    assert_eq!(
        calls.len(),
        1,
        "only remove ran before the restart abort: {calls:?}"
    );
}

#[test]
fn a_hung_remove_is_killed_and_no_add_mutation_lands() {
    // The `claude mcp remove` child overruns its bound and is killed (ErrorKind::TimedOut);
    // the transaction aborts BEFORE `add`, so no mutation lands after the barrier lease would lapse.
    let mut fake = FakeClaude::new(true, Some("/opt/cermet"));
    fake.remove_times_out = true;
    let barrier = FakeBarrier::quiescent();
    let err = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&barrier),
    )
    .expect_err("a timed-out remove must abort the transaction");
    match err {
        cermet_cli::CliError::Refused(m) => assert!(m.contains("PARTIAL"), "reports partial: {m}"),
        other => panic!("expected Refused, got {other:?}"),
    }
    let calls = fake.calls.lock().unwrap();
    assert_eq!(
        calls.len(),
        1,
        "only the (killed) remove ran; the add never mutated: {calls:?}"
    );
    assert_eq!(calls[0], vec!["claude", "mcp", "remove", "cermet"]);
}

#[test]
fn a_near_exhausted_lease_refuses_before_any_mutation() {
    // After a slow drain the remaining lease is too small to cover remove+add. The client
    // must refuse BEFORE any config change (measuring from the daemon-reported expiry), not overrun
    // the lease and leave `add` running after the daemon TTL-recovers the barrier.
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    // Quiescent, but the lease expires in 10s — far below the ~50s remove+add budget.
    let barrier = FakeBarrier::short_lease(10);
    let err = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&barrier),
    )
    .expect_err("a near-exhausted lease must refuse pre-mutation");
    match err {
        cermet_cli::CliError::Refused(m) => {
            assert!(
                m.contains("lease remain"),
                "names the remaining-lease refusal: {m}"
            );
            assert!(m.contains("BEFORE any change"), "refuses pre-mutation: {m}");
        }
        other => panic!("expected Refused, got {other:?}"),
    }
    assert!(
        fake.calls.lock().unwrap().is_empty(),
        "no remove/add ran — refusal is strictly before any mutation"
    );
    // The barrier is still released on the refusal path.
    assert_eq!(
        *barrier.ends.lock().unwrap(),
        vec!["tok-fake-1".to_string()]
    );
}

#[test]
fn daemon_unreachable_refuses_without_force_and_forces_with_it() {
    // Daemon unavailability is never "there can be no live call": refuse without --force (no config
    // touched), proceed with it.
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    let down = FakeBarrier::new(false, vec![]);
    let out = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&down),
    )
    .expect("refusal output");
    assert!(!out.ok, "an unreachable daemon must refuse: {}", out.text);
    assert!(
        fake.calls.lock().unwrap().is_empty(),
        "no config mutation on refuse"
    );

    let fake2 = FakeClaude::new(true, Some("/opt/cermet"));
    let down2 = FakeBarrier::new(false, vec![]);
    let a = McpInstallArgs {
        force: true,
        ..args(Some("/tmp/agent.sock"), Some("/opt/cermet"))
    };
    let out2 = run_mcp_install(&a, &fake2, &term(), Some(&down2)).expect("ok under force");
    assert!(out2.ok, "--force proceeds with no daemon: {}", out2.text);
    assert!(
        !fake2.calls.lock().unwrap().is_empty(),
        "--force ran the repoint"
    );
}

#[test]
fn no_daemon_endpoint_refuses_with_zero_mutation_without_force() {
    // No ctl anchors at all (barrier None): refuse without --force, touching no client config.
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    let out = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        None,
    )
    .expect("refusal output");
    assert!(!out.ok, "no endpoint must refuse: {}", out.text);
    assert!(
        fake.calls.lock().unwrap().is_empty(),
        "zero config mutation"
    );
}

#[test]
fn barrier_lost_during_drain_refuses_without_force_and_touches_no_config() {
    // A transport failure on a status poll (barrier lost) refuses fail-closed before any mutation.
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    let barrier = FakeBarrier::new(true, vec![Sc::Err("ctl.sock timed out".into())]);
    let out = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&barrier),
    )
    .expect("refusal output");
    assert!(!out.ok, "a lost barrier must refuse: {}", out.text);
    assert!(fake.calls.lock().unwrap().is_empty(), "no config mutation");
}

#[test]
fn restart_between_remove_and_add_stops_and_reports_partial() {
    // The daemon restarts mid-mutation (instance id changes on the between-steps
    // recheck). The client STOPS before adding and reports a potentially-partial registration — it
    // never silently continues. remove ran; add did NOT.
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    // drain(quiescent) → before-remove recheck(quiescent) → between recheck(RESTART).
    let barrier = FakeBarrier::new(true, vec![Sc::Quiescent, Sc::Quiescent, Sc::Restart]);
    let err = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&barrier),
    )
    .expect_err("a mid-mutation restart must stop, not silently continue");
    match err {
        cermet_cli::CliError::Refused(m) => {
            assert!(
                m.contains("PARTIAL"),
                "reports potentially-partial registration: {m}"
            );
        }
        other => panic!("expected a Refused error, got {other:?}"),
    }
    let calls = fake.calls.lock().unwrap();
    assert_eq!(
        calls.len(),
        1,
        "only the remove ran before the abort: {calls:?}"
    );
    assert_eq!(calls[0], vec!["claude", "mcp", "remove", "cermet"]);
    // The barrier is still ended (best-effort release) on the abort path.
    assert_eq!(
        *barrier.ends.lock().unwrap(),
        vec!["tok-fake-1".to_string()]
    );
}

#[test]
fn install_without_binary_fails_closed_with_a_build_hint() {
    let fake = FakeClaude::new(true, None); // bridge_binary -> None
    let err = run_mcp_install(&args(Some("/tmp/agent.sock"), None), &fake, &term(), None)
        .expect_err("no binary must fail closed");
    match err {
        cermet_cli::CliError::Usage(m) => assert!(m.contains("cermet binary"), "{m}"),
        other => panic!("expected a Usage error, got {other:?}"),
    }
}

#[test]
fn install_without_claude_prints_the_manual_command() {
    let fake = FakeClaude::new(false, Some("/opt/cermet"));
    let barrier = FakeBarrier::quiescent();
    let out = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&barrier),
    )
    .expect("renders a manual fallback");
    assert!(!out.ok, "no claude on PATH must exit non-zero");
    let manual = mcp_add_command("cermet", Path::new("/opt/cermet"), "/tmp/agent.sock").join(" ");
    assert!(out.text.contains(&manual), "{}", out.text);
}

#[test]
fn install_add_failure_prints_manual_and_stderr_and_exits_nonzero() {
    let mut fake = FakeClaude::new(true, Some("/opt/cermet"));
    fake.add_code = 1;
    fake.add_stderr = "boom".into();
    let barrier = FakeBarrier::quiescent();
    let out = run_mcp_install(
        &args(Some("/tmp/agent.sock"), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&barrier),
    )
    .expect("renders a manual fallback");
    assert!(!out.ok);
    assert!(out.text.contains("claude mcp add"), "{}", out.text);
    assert!(out.text.contains("boom"), "{}", out.text);
}

#[test]
fn install_manual_command_quotes_a_sock_path_with_spaces() {
    let sock = "/tmp/a b/agent.sock";
    let fake = FakeClaude::new(false, Some("/opt/cermet"));
    let barrier = FakeBarrier::quiescent();
    let out = run_mcp_install(
        &args(Some(sock), Some("/opt/cermet")),
        &fake,
        &term(),
        Some(&barrier),
    )
    .expect("renders a manual fallback");
    assert!(!out.ok);
    assert!(
        out.text.contains("'CERMET_AGENT_SOCK=/tmp/a b/agent.sock'"),
        "the space-carrying env token must be a single quoted word: {}",
        out.text
    );
}

#[test]
fn install_rejects_an_option_like_name() {
    let fake = FakeClaude::new(true, Some("/opt/cermet"));
    let bad = McpInstallArgs {
        sock: Some("/tmp/a.sock".into()),
        binary: Some("/opt/cermet".into()),
        name: "-evil".into(),
        guidance: Some(false),
        force: false,
        client: McpClient::Claude,
    };
    let err = run_mcp_install(&bad, &fake, &term(), None)
        .expect_err("a leading-dash name must be refused");
    match err {
        cermet_cli::CliError::Usage(m) => assert!(m.contains("plain identifier"), "{m}"),
        other => panic!("expected Usage, got {other:?}"),
    }
    assert!(
        fake.calls.lock().unwrap().is_empty(),
        "no shell-out before the name is validated"
    );
}

// ---- guidance stanza: idempotent, no symlink-follow, project-boundary walk ------------------------

#[test]
fn guidance_appends_once_and_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let claude_md = tmp.path().join("CLAUDE.md");
    std::fs::write(&claude_md, "# My Project\n").unwrap();

    assert_eq!(
        append_guidance_stanza(&claude_md).unwrap(),
        GuidanceOutcome::Appended
    );
    let body1 = std::fs::read_to_string(&claude_md).unwrap();
    assert!(body1.contains("Running commands through Cermet"), "{body1}");
    // The exact OPEN marker appears once (the close marker `<!-- /cermet:mcp-guidance -->` differs).
    assert_eq!(
        body1.matches(GUIDANCE_MARKER).count(),
        1,
        "exactly one open marker"
    );
    assert!(
        body1.starts_with("# My Project\n"),
        "original content preserved"
    );

    assert_eq!(
        append_guidance_stanza(&claude_md).unwrap(),
        GuidanceOutcome::Present
    );
    let body2 = std::fs::read_to_string(&claude_md).unwrap();
    assert_eq!(body2, body1, "no double-append");
}

#[test]
fn guidance_refuses_a_symlinked_target_and_never_writes_through_it() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside.txt");
    std::fs::write(&outside, "original\n").unwrap();
    let link = tmp.path().join("CLAUDE.md");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let err =
        append_guidance_stanza(&link).expect_err("a symlinked target must be refused (O_NOFOLLOW)");
    assert!(matches!(err, cermet_cli::CliError::Refused(_)), "{err:?}");
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "original\n",
        "the link target must be byte-for-byte untouched"
    );
}

#[test]
fn project_claude_md_refuses_a_symlink_stops_at_git_root_and_never_ascends_past_home() {
    // symlink refused.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let proj = home.join("proj");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("secret.txt"), proj.join("CLAUDE.md")).unwrap();
    assert!(matches!(
        project_claude_md(&proj, &home),
        Err(cermet_cli::CliError::Refused(_))
    ));

    // no CLAUDE.md + no .git on the walk → target cwd, never a ~/CLAUDE.md ancestor.
    let tmp2 = tempfile::tempdir().unwrap();
    let home2 = tmp2.path().join("home");
    let work = home2.join("work/proj");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(home2.join("CLAUDE.md"), "# home — off-limits\n").unwrap();
    assert_eq!(
        project_claude_md(&work, &home2).unwrap(),
        work.join("CLAUDE.md")
    );

    // stops at the first .git ancestor (its CLAUDE.md), never an ancestor beyond it.
    let tmp3 = tempfile::tempdir().unwrap();
    let home3 = tmp3.path().join("home");
    let root = home3.join("repo");
    let sub = root.join("a/b");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::write(root.join("CLAUDE.md"), "# repo root\n").unwrap();
    std::fs::write(home3.join("CLAUDE.md"), "# ancestor — off-limits\n").unwrap();
    assert_eq!(
        project_claude_md(&sub, &home3).unwrap(),
        root.join("CLAUDE.md")
    );

    // .git but no CLAUDE.md anywhere → create at the git root.
    std::fs::remove_file(root.join("CLAUDE.md")).unwrap();
    assert_eq!(
        project_claude_md(&sub, &home3).unwrap(),
        root.join("CLAUDE.md")
    );
}

// ---- OpenCode registrar (opencode.json V1 schema) ------------------------------------------------

/// The `mcp` map value at `name`, unwrapped, or a panic with the whole doc for a legible failure.
fn mcp_entry(root: &serde_json::Value, name: &str) -> serde_json::Value {
    root.get("mcp")
        .and_then(|m| m.get(name))
        .cloned()
        .unwrap_or_else(|| panic!("no mcp.{name} in {root:#}"))
}

#[test]
fn opencode_config_fresh_file_writes_the_v1_server_entry() {
    let tmp = tempfile::tempdir().unwrap();
    // A nested path that does not exist yet — the writer must create the parent dirs.
    let path = tmp.path().join(".config/opencode/opencode.json");
    let outcome =
        write_opencode_config(&path, "cermet", Path::new("/opt/cermet"), "/tmp/agent.sock")
            .expect("fresh write ok");
    assert!(matches!(outcome, ConfigWrite::Written));

    let root: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    // Top-level `mcp` map, V1 local-server shape with `enabled` (not `mcp.servers`/`disabled`).
    let entry = mcp_entry(&root, "cermet");
    assert_eq!(entry["type"], "local");
    assert_eq!(entry["command"], serde_json::json!(["/opt/cermet", "mcp"]));
    assert_eq!(entry["enabled"], true);
    // The same env contract every client gets.
    assert_eq!(entry["environment"]["CERMET_AGENT_SOCK"], "/tmp/agent.sock");
    assert_eq!(entry["environment"]["CERMET_AGENT_NAME"], "cermet");
    // A fresh file gets the schema pointer for editor validation.
    assert_eq!(root["$schema"], "https://opencode.ai/config.json");
    // Same shape the pure helper produces.
    assert_eq!(
        entry,
        opencode_server_entry(Path::new("/opt/cermet"), "/tmp/agent.sock", "cermet")
    );
}

#[test]
fn opencode_config_merge_preserves_unrelated_keys_and_servers() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("opencode.json");
    std::fs::write(
        &path,
        r#"{
          "$schema": "https://opencode.ai/config.json",
          "model": "anthropic/claude",
          "mcp": {
            "other": { "type": "local", "command": ["other-server"], "enabled": true }
          }
        }"#,
    )
    .unwrap();

    write_opencode_config(&path, "cermet", Path::new("/opt/cermet"), "/tmp/agent.sock")
        .expect("merge ok");

    let root: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    // Unrelated top-level key and the unrelated server are untouched.
    assert_eq!(root["model"], "anthropic/claude");
    assert_eq!(
        mcp_entry(&root, "other")["command"],
        serde_json::json!(["other-server"])
    );
    // Our entry is added alongside.
    assert_eq!(mcp_entry(&root, "cermet")["type"], "local");
}

#[test]
fn opencode_config_reinstall_is_idempotent_updating_the_existing_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("opencode.json");
    write_opencode_config(&path, "cermet", Path::new("/opt/cermet"), "/tmp/old.sock")
        .expect("first write");
    // Re-install with a different sock: the entry updates in place, never duplicates.
    write_opencode_config(&path, "cermet", Path::new("/opt/cermet"), "/tmp/new.sock")
        .expect("second write");

    let root: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        root["mcp"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| *k == "cermet")
            .count(),
        1,
        "exactly one cermet entry (no duplicate)"
    );
    assert_eq!(
        mcp_entry(&root, "cermet")["environment"]["CERMET_AGENT_SOCK"],
        "/tmp/new.sock"
    );
}

#[test]
fn opencode_config_unparseable_file_is_reported_and_left_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("opencode.json");
    let garbage = "{ this is not: valid json ]]]";
    std::fs::write(&path, garbage).unwrap();

    let outcome =
        write_opencode_config(&path, "cermet", Path::new("/opt/cermet"), "/tmp/agent.sock")
            .expect("returns an Unparseable outcome, not an error");
    assert!(
        matches!(outcome, ConfigWrite::Unparseable(_)),
        "unparseable must be signalled"
    );
    // Fail closed: never clobber an operator's config.
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        garbage,
        "the file is byte-for-byte untouched"
    );
}

#[test]
fn opencode_config_replaces_by_rename_never_truncating_in_place() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("opencode.json");
    write_opencode_config(&path, "cermet", Path::new("/opt/cermet"), "/tmp/1.sock")
        .expect("first write");
    let ino1 = std::fs::metadata(&path).unwrap().ino();
    write_opencode_config(&path, "cermet", Path::new("/opt/cermet"), "/tmp/2.sock")
        .expect("second write");
    let ino2 = std::fs::metadata(&path).unwrap().ino();
    // The target must be REPLACED via same-dir temp + rename (a fresh inode), never
    // truncated in place — a crash mid-write must never leave the operator's config empty.
    assert_ne!(ino1, ino2, "replace-by-rename, not in-place truncate");
    // And the swap leaves no temp litter behind.
    let names: Vec<String> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["opencode.json"], "no temp litter: {names:?}");
}

#[test]
fn opencode_config_symlinked_target_keeps_the_link_and_updates_the_resolved_file() {
    // The dotfiles setup: opencode.json is a symlink into a repo elsewhere. The rename must land
    // on the RESOLVED file — replacing the LINK itself would silently detach the dotfiles copy.
    let tmp = tempfile::tempdir().unwrap();
    let dotfiles = tmp.path().join("dotfiles");
    std::fs::create_dir_all(&dotfiles).unwrap();
    let real = dotfiles.join("opencode.json");
    std::fs::write(&real, r#"{ "model": "anthropic/claude" }"#).unwrap();
    let link = tmp.path().join("opencode.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    write_opencode_config(&link, "cermet", Path::new("/opt/cermet"), "/tmp/agent.sock")
        .expect("write through the resolved target");

    let meta = std::fs::symlink_metadata(&link).unwrap();
    assert!(
        meta.file_type().is_symlink(),
        "the symlink must survive the install"
    );
    let root: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&real).unwrap()).unwrap();
    assert_eq!(root["model"], "anthropic/claude", "merged, not clobbered");
    assert_eq!(
        mcp_entry(&root, "cermet")["type"],
        "local",
        "the resolved file carries the entry"
    );
}

#[test]
fn opencode_agents_symlink_to_a_guided_target_is_idempotent_not_a_refusal() {
    // A project may symlink AGENTS.md → CLAUDE.md. When the link's target already carries the
    // guidance, the OpenCode guidance step reports "present" (idempotent), never refuses.
    let tmp = tempfile::tempdir().unwrap();
    let claude_md = tmp.path().join("CLAUDE.md");
    append_guidance_stanza(&claude_md).unwrap(); // seed the marker into the real target
    let agents = tmp.path().join("AGENTS.md");
    std::os::unix::fs::symlink(&claude_md, &agents).unwrap();

    assert_eq!(
        append_guidance_symlink_idempotent(&agents).unwrap(),
        GuidanceOutcome::Present,
        "a symlink to a target that already carries the guidance is idempotent success"
    );
    // The link is never written through: a symlink whose target LACKS the marker is refused.
    let plain = tmp.path().join("plain.md");
    std::fs::write(&plain, "# no marker here\n").unwrap();
    let link2 = tmp.path().join("AGENTS2.md");
    std::os::unix::fs::symlink(&plain, &link2).unwrap();
    assert!(matches!(
        append_guidance_symlink_idempotent(&link2),
        Err(cermet_cli::CliError::Refused(_))
    ));
    assert_eq!(
        std::fs::read_to_string(&plain).unwrap(),
        "# no marker here\n",
        "target untouched"
    );
}

#[test]
fn opencode_agents_regular_file_appends_via_the_nofollow_path() {
    // A regular (non-symlink) AGENTS.md appends the stanza just like CLAUDE.md, idempotently.
    let tmp = tempfile::tempdir().unwrap();
    let agents = tmp.path().join("AGENTS.md");
    std::fs::write(&agents, "# Agents\n").unwrap();
    assert_eq!(
        append_guidance_symlink_idempotent(&agents).unwrap(),
        GuidanceOutcome::Appended
    );
    assert_eq!(
        append_guidance_symlink_idempotent(&agents).unwrap(),
        GuidanceOutcome::Present
    );
    let body = std::fs::read_to_string(&agents).unwrap();
    assert_eq!(
        body.matches(GUIDANCE_MARKER).count(),
        1,
        "exactly one open marker"
    );
    assert!(body.starts_with("# Agents\n"), "original content preserved");
}
