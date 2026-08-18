//! `cermet mcp install` — register the Rust `cermet mcp` stdio server with an agent client.
//!
//! Idempotent (remove-then-add), argv quoted for a SAFE copy-paste fallback, and the optional
//! CLAUDE.md guidance stanza stays inside the project boundary and NEVER follows a symlink — the
//! append opens `O_NOFOLLOW` and writes at the fd, so a link swapped in after the boundary walk is
//! refused, not chased.
//!
//! The registered argv launches this same binary with the literal `mcp` subcommand. It reads
//! `CERMET_AGENT_SOCK` (socket) and `CERMET_AGENT_NAME` (session display name) from the environment.

use std::path::{Path, PathBuf};

use crate::tty::Terminal;
use crate::CliError;

/// The installed system daemon's `agent.sock` (present as a real socket only while that daemon
/// serves), resolved PER PLATFORM. Both platforms run the same three-uid service topology, so the
/// agent socket lives in the SEPARATE agents runtime dir (`2711 <service>:cermet-agents`), never
/// the daemon's own. Only the dir's
/// spelling differs: macOS wipes `/var/run` at boot, so its runtime dirs sit in persistent `/var`
/// (`setup::AGENT_RUNTIME_DIR`).
#[cfg(target_os = "macos")]
pub const SYSTEM_AGENT_SOCK: &str = "/var/cermetd-agents/agent.sock";
#[cfg(not(target_os = "macos"))]
pub const SYSTEM_AGENT_SOCK: &str = "/run/cermetd-agents/agent.sock";

/// The idempotency marker + plain-language nudge appended to a project's CLAUDE.md.
pub const GUIDANCE_MARKER: &str = "<!-- cermet:mcp-guidance -->";
/// The guidance stanza appended to a project's CLAUDE.md. It names the registered server
/// (`cermet mcp`, a client of cermetd) and its discovery → request → execute flow, whose first
/// step is that the ruled tool list is the standing authority. It
/// carries no raw-shell deny/reroute policy: routing raw commands is the operator's own client
/// configuration, not something Cermet writes.
pub const GUIDANCE_STANZA: &str = "<!-- cermet:mcp-guidance -->
## Running commands through Cermet

Cermet registers the `cermet mcp` stdio server (a client of the cermetd daemon). Its tool list
IS your standing authority: every verb a sentence admits appears as its own tool (for example
`github-read_repo`, `vercel-deploy`), and calling that tool requests and runs the capability in
one step. Prefer it over reaching for a raw provider token — the credential is held by the daemon
and never reaches you.

1. Call `catalog` to see what standing sentences already admit (its default zoom): one line per
   verb with the fields you supply and the sentence that admits it, bounds included. Call it with
   `scope: all` for the full dictionary of verbs that EXIST, each stamped with its authority
   status — that is what you read to propose authority you do not have yet.
2. For a verb with no per-verb tool, call `request_capability` with the verb, its fields, and a
   `justification`. If no sentence admits it the answer is a definite deny carrying a
   widening suggestion for your operator: relay that suggestion, do not retry.
3. Call `execute_capability` on a sentence-authorized grant (a per-verb tool call already did
   this for you).

You get the result plus an audited record and a compact receipt, with the full response kept as a
retrievable artifact (`artifact`), so long transcripts stay short. Native file tools
(Read/Grep/Glob/Edit/Write) are not brokered.

Git is not a verb here, and there is no cermet git command. A push is decided by git's own update
hook on the daemon's mirror: commit locally, then run plain `git push <remote> <branch>` in your
shell. That reaches the broker when the repository's remote is a `cermet::` URL, which
`cermet connect github` offers to wire and `cermet check github` reads back. Refusals arrive in
git's own output (`remote error: cermet: …`), naming what to fix.
<!-- /cermet:mcp-guidance -->
";

/// Which agent client `mcp install` registers with. BOTH register the same client-agnostic
/// `cermet mcp` stdio server; only the registration surface differs — Claude Code's `claude mcp`
/// CLI vs OpenCode's global `opencode.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum McpClient {
    #[default]
    Claude,
    OpenCode,
}

/// The parsed `mcp install` arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct McpInstallArgs {
    pub sock: Option<String>,
    pub binary: Option<String>,
    pub name: String,
    /// `Some(true)` = `--guidance`, `Some(false)` = `--no-guidance`, `None` = offer interactively.
    pub guidance: Option<bool>,
    /// Which client to register with (default `claude`; existing behavior byte-compatible).
    pub client: McpClient,
    /// `--force`. The MCP-repoint quiesce transaction refuses — fail closed —
    /// when the daemon is unreachable, when it cannot establish/verify the barrier, when the barrier
    /// reports an orphan-ambiguous / integrity state, or when a genuinely-active lease does not drain
    /// before the timeout. `--force` is the explicit operator override that repoints anyway, warning
    /// that an agent-side child may still be running.
    pub force: bool,
}

/// The daemon-held MCP-repoint quiesce barrier transaction `cermet mcp install` drives before it
/// repoints the registered MCP server binary. Three narrow ctl operations: `begin` enters the
/// barrier (blocking every NEW
/// approved→executing claim while requests/status and already-open lease finalization continue),
/// `status` classifies custody through the grant-HMAC + verified-audit path, and `end` releases it
/// through the daemon's ordered durable release. An `Err` carries a transport/decode failure string.
pub trait RepointBarrier {
    fn begin(&self, ttl_secs: i64) -> Result<cermet_lang::McpRepointBegin, String>;
    fn status(&self, token: &str) -> Result<cermet_lang::McpRepointStatusReport, String>;
    /// Best-effort release — the daemon's TTL recovers a barrier this never manages to end.
    fn end(&self, token: &str);
}

/// The barrier TTL `begin` requests (clamped daemon-side). It must be strictly larger than the
/// WORST-CASE client budget that draws on the SAME lease clock: the full drain, then both bounded
/// remove/add shell-outs, plus a safety margin. The const assertion below enforces that.
const REPOINT_TTL_SECS: i64 = 120;
/// How often the drain loop re-polls `status` while a genuinely-active lease drains.
const DRAIN_POLL: std::time::Duration = std::time::Duration::from_millis(500);
/// The bounded ceiling on the active-lease drain, in seconds — it and the two mutation shell-outs
/// draw on the SAME barrier lease, so it is sized to leave the full mutation budget inside the lease.
const DRAIN_TIMEOUT_SECS: u64 = 60;
/// The hard bound (seconds) on each `claude mcp remove/add` shell-out — a hung child is
/// killed rather than mutating after the lease would lapse.
const STEP_MUTATION_TIMEOUT_SECS: u64 = 20;
/// Slack between the worst-case client budget and the lease, absorbing poll/scheduling jitter
/// and the epoch/`Instant` clock split so the mutation provably finishes before the daemon TTL-recovers.
const MUTATION_MARGIN_SECS: u64 = 10;
/// The full post-drain mutation budget (both shell-outs + margin) that must fit in the remaining lease.
const MUTATION_BUDGET_SECS: u64 = 2 * STEP_MUTATION_TIMEOUT_SECS + MUTATION_MARGIN_SECS;

/// The whole transaction — drain, then remove+add, plus margin — must provably sit inside a
/// single live lease, or a slow-but-legit drain leaves `claude mcp add` running after the daemon
/// TTL-recovers the barrier and readmits claims. Enforced at COMPILE time so a constant re-tune that
/// breaks the budget fails the build, not a rehearsal.
const _: () = assert!(
    (DRAIN_TIMEOUT_SECS + MUTATION_BUDGET_SECS) < REPOINT_TTL_SECS as u64,
    "MCP-repoint budget (drain + remove/add + margin) must be strictly inside the barrier lease"
);

const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(DRAIN_TIMEOUT_SECS);
const STEP_MUTATION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(STEP_MUTATION_TIMEOUT_SECS);

/// The one-line warning `--force` prints when it accepts a repoint the barrier could not prove safe.
const FORCE_ORPHAN_WARNING: &str =
    "⚠ --force: repointing without a proved-quiescent daemon; an agent-side shell child started \
     under the old MCP server may still be running.";

/// A held quiesce barrier: the token + daemon-instance id, threaded through the remove/add mutation
/// so each step re-checks the barrier is still up on the SAME daemon before proceeding. `force`
/// makes the recheck tolerate a non-Quiescent CLASS (Orphan/Integrity/Active — the operator already
/// accepted a possible orphan) while STILL aborting on a daemon restart or a lost barrier (force
/// must actually span the mutation, but never silently proceed through a restart mid-mutation).
struct RepointGuard<'a> {
    barrier: &'a dyn RepointBarrier,
    token: String,
    instance_id: String,
    /// The daemon-reported lease expiry (unix epoch seconds) — the AUTHORITY for how much lease is
    /// left, so the pre-mutation budget check measures from `begin`, not from client hope.
    expires_at: i64,
    force: bool,
}

/// Current wall-clock, unix epoch seconds — the same basis the daemon uses for the barrier expiry.
fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl RepointGuard<'_> {
    /// Re-verify (between mutation steps) that the barrier is still held on the SAME daemon instance.
    /// Without `--force` the daemon must still be Quiescent (new claims are blocked, so a healthy
    /// barrier stays so). A daemon restart (changed instance id) or a lost barrier (transport failure)
    /// ALWAYS stops the flow fail-closed — even under `--force` — so a restart mid-mutation never
    /// silently continues. Only the non-Quiescent CLASS is tolerated under `--force`. `where_` names
    /// the step for a precise partial-state message.
    fn recheck(&self, where_: &str) -> Result<(), CliError> {
        match self.barrier.status(&self.token) {
            Err(e) => Err(CliError::Refused(format!(
                "the MCP-repoint barrier was lost {where_} ({e}); the daemon may have restarted — \
                 the MCP registration may be PARTIAL. Reconcile it by hand (check `claude mcp list`) \
                 and re-run `cermet mcp install`."
            ))),
            Ok(rep) if rep.instance_id != self.instance_id => Err(CliError::Refused(format!(
                "the daemon restarted {where_} (instance changed); the MCP registration may be \
                 PARTIAL. Reconcile it by hand and re-run `cermet mcp install`."
            ))),
            Ok(rep) if !self.force && rep.status != cermet_lang::McpQuiesceStatus::Quiescent => {
                Err(CliError::Refused(format!(
                    "the daemon is no longer quiescent {where_}; the MCP registration may be PARTIAL. \
                     Reconcile it by hand and re-run `cermet mcp install`."
                )))
            }
            Ok(_) => Ok(()),
        }
    }

    /// Refuse BEFORE any config mutation when the OBSERVED remaining lease (daemon-reported
    /// expiry minus now) cannot cover the full remove+add budget. Measured from `begin`, not from
    /// hope, so a slow-but-legit drain that consumed most of the lease refuses instead of leaving the
    /// `add` running past a barrier the daemon has already TTL-recovered. Applies even under `--force`
    /// (which accepts an orphaned child, not a barrier-less registration rewrite).
    fn lease_covers_mutation(&self) -> Result<(), CliError> {
        let remaining = self.expires_at - now_epoch_secs();
        if remaining < MUTATION_BUDGET_SECS as i64 {
            return Err(CliError::Refused(format!(
                "only {remaining}s of the MCP-repoint barrier lease remain — less than the \
                 {MUTATION_BUDGET_SECS}s needed to complete the remove+add inside a live barrier; \
                 refusing BEFORE any change (fail closed). Re-run once the daemon is idle so the \
                 drain leaves more lease."
            )));
        }
        Ok(())
    }
}

/// The outcome of establishing the barrier + draining to quiescence.
enum Gate<'a> {
    /// Refuse the repoint without touching any client config (fail closed).
    Refuse(crate::CliOutput),
    /// Proceed with the mutation; `guard` is `Some` when a barrier is held (End it afterward), `None`
    /// under `--force` with no reachable/verifiable daemon. `warning` is prepended to the success line.
    Proceed {
        guard: Option<RepointGuard<'a>>,
        warning: Option<String>,
    },
}

/// A barrier-held refusal that `--force` converts to a proceed. Without `--force`, the barrier is
/// ended (no client config touched) and the refusal is returned.
fn refuse_forceable<'a>(
    barrier: &'a dyn RepointBarrier,
    force: bool,
    guard: RepointGuard<'a>,
    text: String,
) -> Gate<'a> {
    if force {
        Gate::Proceed {
            guard: Some(guard),
            warning: Some(FORCE_ORPHAN_WARNING.to_string()),
        }
    } else {
        barrier.end(&guard.token);
        Gate::Refuse(crate::CliOutput { text, ok: false })
    }
}

/// Begin the barrier and boundedly drain genuinely-active leases. Proceeds ONLY on a proved
/// `Quiescent`. Orphan-ambiguous / integrity / drain-timeout / restart / barrier-loss all refuse
/// (fail closed) unless `--force`. On any refusal the barrier is ended and no client config is touched.
fn begin_and_drain(barrier: &dyn RepointBarrier, force: bool) -> Gate<'_> {
    let begin = match barrier.begin(REPOINT_TTL_SECS) {
        Ok(b) => b,
        // The daemon is unreachable / cannot establish the barrier. Daemon unavailability is NEVER
        // "there can be no live call" — refuse unless the operator forces it (no barrier held).
        Err(e) => {
            return if force {
                Gate::Proceed {
                    guard: None,
                    warning: Some(FORCE_ORPHAN_WARNING.to_string()),
                }
            } else {
                Gate::Refuse(crate::CliOutput {
                    text: format!(
                        "✗ cannot reach the daemon to quiesce it for an MCP repoint ({e}); refusing \
                         (fail closed). Start cermetd and retry, or pass --force to repoint anyway \
                         (accepting a possible orphaned agent-side child)."
                    ),
                    ok: false,
                })
            };
        }
    };
    let guard = RepointGuard {
        barrier,
        token: begin.token.clone(),
        instance_id: begin.instance_id.clone(),
        expires_at: begin.expires_at,
        force,
    };
    let start = std::time::Instant::now();
    loop {
        match barrier.status(&begin.token) {
            Err(e) => {
                barrier.end(&begin.token);
                return if force {
                    Gate::Proceed {
                        guard: None,
                        warning: Some(FORCE_ORPHAN_WARNING.to_string()),
                    }
                } else {
                    Gate::Refuse(crate::CliOutput {
                        text: format!(
                            "✗ lost contact with the daemon while quiescing it ({e}); refusing \
                             (fail closed). Retry, or pass --force to repoint anyway."
                        ),
                        ok: false,
                    })
                };
            }
            Ok(rep) if rep.instance_id != begin.instance_id => {
                // The daemon restarted mid-drain — the barrier reinstated on a NEW instance.
                barrier.end(&begin.token);
                return if force {
                    Gate::Proceed {
                        guard: None,
                        warning: Some(FORCE_ORPHAN_WARNING.to_string()),
                    }
                } else {
                    Gate::Refuse(crate::CliOutput {
                        text:
                            "✗ the daemon restarted while quiescing it for the repoint; refusing \
                               (fail closed). Retry, or pass --force to repoint anyway."
                                .to_string(),
                        ok: false,
                    })
                };
            }
            Ok(rep) => match rep.status {
                cermet_lang::McpQuiesceStatus::Quiescent => {
                    return Gate::Proceed {
                        guard: Some(guard),
                        warning: None,
                    };
                }
                cermet_lang::McpQuiesceStatus::Active { .. } => {
                    if start.elapsed() > DRAIN_TIMEOUT {
                        return refuse_forceable(
                            barrier,
                            force,
                            guard,
                            format!(
                                "✗ active execution lease(s) did not drain within {}s; refusing to \
                                 repoint (fail closed). Re-run once idle, or pass --force.",
                                DRAIN_TIMEOUT.as_secs()
                            ),
                        );
                    }
                    std::thread::sleep(DRAIN_POLL);
                    continue;
                }
                cermet_lang::McpQuiesceStatus::OrphanAmbiguous { .. } => {
                    return refuse_forceable(
                        barrier,
                        force,
                        guard,
                        "✗ the daemon cannot prove no agent-side child from a prior call is still \
                         running (an expired/unreported execution lease); refusing to repoint (fail \
                         closed). Pass --force to repoint anyway (accepting a possible orphan)."
                            .to_string(),
                    );
                }
                cermet_lang::McpQuiesceStatus::Integrity { .. } => {
                    return refuse_forceable(
                        barrier,
                        force,
                        guard,
                        "✗ the daemon reported an integrity fault while classifying in-flight work; \
                         refusing to repoint (fail closed). Investigate the audit chain, or pass \
                         --force."
                            .to_string(),
                    );
                }
            },
        }
    }
}

/// The refusal when there is no daemon endpoint at all (the launcher passed no ctl anchors). Daemon
/// unavailability is never "there can be no live call" — refuse unless `--force`.
fn refuse_daemon_unavailable() -> crate::CliOutput {
    crate::CliOutput {
        text: "✗ no daemon endpoint is available to quiesce for an MCP repoint (set \
               CERMET_CTL_SOCK / CERMET_DAEMON_UID via the launcher). Refusing (fail closed) — pass \
               --force to repoint anyway, accepting a possible orphaned agent-side child."
            .to_string(),
        ok: false,
    }
}

/// The outcome of running the `claude` CLI (returncode + captured stderr).
pub struct ProcOutcome {
    pub code: i32,
    pub stderr: String,
}

/// The shell-out seam: PATH lookups + running `claude`. Behind a trait so `mcp install` is testable
/// without a real `claude` CLI.
///
/// `run` takes a hard `timeout` — a hung `claude mcp remove/add` child must NOT outlive the
/// quiesce barrier lease (if it did, the daemon TTL-recovers, claims resume, and the still-running
/// child could mutate the registration afterward). A timed-out child is killed and reaped and the
/// call returns `ErrorKind::TimedOut`, which the caller treats as a bounded, fail-closed abort.
pub trait ClaudeCli {
    fn which(&self, cmd: &str) -> Option<PathBuf>;
    fn run(&self, argv: &[String], timeout: std::time::Duration) -> std::io::Result<ProcOutcome>;
    /// Resolve the built `cermet` binary (target/release|debug near the running exe, then PATH).
    /// A trait method so `mcp install` can be tested with a controlled resolution (`None` proves
    /// the fail-closed "build it" hint).
    fn bridge_binary(&self) -> Option<PathBuf>;
}

/// The real implementation: `which`-on-PATH + `std::process::Command`.
pub struct StdClaudeCli;

impl ClaudeCli for StdClaudeCli {
    fn which(&self, cmd: &str) -> Option<PathBuf> {
        which_on_path(cmd)
    }
    fn run(&self, argv: &[String], timeout: std::time::Duration) -> std::io::Result<ProcOutcome> {
        use std::io::Read;
        use std::process::{Command, Stdio};
        // Spawn with a piped stderr so we can surface `claude`'s failure text, then poll `try_wait`
        // to a hard deadline. A child that overruns is killed + reaped so it can never mutate the
        // registration after the barrier lease would lapse.
        let mut child = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                let mut stderr = String::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut stderr);
                }
                return Ok(ProcOutcome {
                    code: status.code().unwrap_or(-1),
                    stderr,
                });
            }
            if start.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "`{}` exceeded its {}s bound and was killed",
                        argv.join(" "),
                        timeout.as_secs()
                    ),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    fn bridge_binary(&self) -> Option<PathBuf> {
        find_bridge_binary(repo_root_from_exe().as_deref(), self)
    }
}

/// A `shutil.which`-style PATH search: return the first executable named `cmd` on `$PATH`.
pub fn which_on_path(cmd: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(cmd);
        if let Ok(m) = std::fs::metadata(&candidate) {
            if m.is_file() && m.permissions().mode() & 0o111 != 0 {
                return Some(candidate);
            }
        }
    }
    None
}

/// The agent-launch constants. On the installed SERVICE topology the agent bridge
/// MUST run as the distinct `cermet-agent` uid via the pinned NOPASSWD sudo rule, launching the
/// INSTALLED root-owned binary — a direct spawn runs as the approver, which the DAC + peercred gates
/// deny. These mirror the installer's `/etc/sudoers.d/cermet-agent` rule exactly, so the
/// installed path is per platform: macOS publishes into the root-owned `/opt/cermet/bin` rather than
/// Homebrew's `/usr/local/bin`, and sudo matches the command byte for byte.
const R1_AGENT_RUN_USER: &str = "cermet-agent";
const R1_AGENT_RUN_GROUP: &str = "cermet-agents";
#[cfg(target_os = "macos")]
const R1_AGENT_INSTALLED_BIN: &str = "/opt/cermet/bin/cermet";
#[cfg(not(target_os = "macos"))]
const R1_AGENT_INSTALLED_BIN: &str = "/usr/local/bin/cermet";

/// How the MCP client should spawn the agent bridge, resolved per platform + topology.
pub struct AgentLaunch {
    /// The command tokens the client runs (after `--` for `claude mcp add`; the `command` array for
    /// OpenCode). The last token is always `mcp`.
    pub argv: Vec<String>,
    /// The environment pairs to register with the command (name, value).
    pub env: Vec<(String, String)>,
}

/// Resolve the agent-bridge launch for a client registration.
///
/// - **Installed service topology** (`sock` is the installed daemon's [`SYSTEM_AGENT_SOCK`], on
///   either platform): the sudo invocation `sudo -n -u cermet-agent -g cermet-agents
///   /usr/local/bin/cermet --socket <SYSTEM_AGENT_SOCK> mcp` — the exact argv `cermet setup` mints
///   the sudoers rule for. The socket is PINNED in argv; `CERMET_AGENT_SOCK` is NOT registered (the
///   sudo rule is `NOSETENV` and `--socket` is the one source of truth), and the display name cannot
///   propagate through the `NOSETENV` rule (accepted: one `cermet-agent` uid is one trust domain —
///   no per-registration name to isolate).
/// - **Dev loops** (any other `sock`): spawn the discovered binary directly, socket + display name
///   via env — the bridge runs as the login user (same-uid).
pub fn agent_launch(name: &str, binary: &Path, sock: &str) -> AgentLaunch {
    if sock == SYSTEM_AGENT_SOCK {
        AgentLaunch {
            argv: vec![
                "sudo".into(),
                "-n".into(),
                "-u".into(),
                R1_AGENT_RUN_USER.into(),
                "-g".into(),
                R1_AGENT_RUN_GROUP.into(),
                R1_AGENT_INSTALLED_BIN.into(),
                "--socket".into(),
                SYSTEM_AGENT_SOCK.into(),
                "mcp".into(),
            ],
            env: Vec::new(),
        }
    } else {
        AgentLaunch {
            argv: vec![binary.to_string_lossy().into_owned(), "mcp".into()],
            env: vec![
                ("CERMET_AGENT_SOCK".into(), sock.to_string()),
                ("CERMET_AGENT_NAME".into(), name.to_string()),
            ],
        }
    }
}

/// The idempotent Claude registration argv. Each registered env
/// pair goes before `--`; the launch command (from [`agent_launch`]) sits after `--` so `claude`
/// never parses its flags.
pub fn mcp_add_command(name: &str, binary: &Path, sock: &str) -> Vec<String> {
    let launch = agent_launch(name, binary, sock);
    let mut argv = vec![
        "claude".to_string(),
        "mcp".into(),
        "add".into(),
        name.into(),
    ];
    for (key, value) in &launch.env {
        argv.push("--env".into());
        argv.push(format!("{key}={value}"));
    }
    argv.push("--".into());
    argv.extend(launch.argv);
    argv
}

/// A plain identifier (letters, digits, `.`, `_`, `-`; no leading dash): `name` flows into
/// `claude mcp remove <name>` and the add argv, so a leading `-` must not be read as an option.
pub fn valid_server_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Port of Python `shlex.quote`: return `s` unquoted when every char is shell-safe, else single-quote
/// it (escaping any embedded `'` as `'"'"'`). An empty string becomes `''`.
pub fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let safe = s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-' | '_')
    });
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

/// Port of Python `shlex.join`: space-join each token, `shlex_quote`d.
pub fn shlex_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shlex_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The built `cermet` binary: prefer `target/release`, then `target/debug`, then PATH. `root`
/// is the workspace root (from the running exe path); `None` skips the target/ probes (PATH only).
pub fn find_bridge_binary(root: Option<&Path>, claude: &dyn ClaudeCli) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(root) = root {
        for rel in ["target/release/cermet", "target/debug/cermet"] {
            let candidate = root.join(rel);
            if let Ok(m) = std::fs::metadata(&candidate) {
                if m.is_file() && m.permissions().mode() & 0o111 != 0 {
                    return Some(candidate);
                }
            }
        }
    }
    claude.which("cermet")
}

/// The workspace root inferred from the running CLI binary (`<root>/target/{release,debug}/cermet`).
fn repo_root_from_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // exe -> .../target/<profile>/cermet ; three parents up is the workspace root.
    exe.parent()?.parent()?.parent().map(Path::to_path_buf)
}

/// Is `p` a live unix-domain socket (no-follow)?
fn is_socket(p: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::symlink_metadata(p)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
}

/// The live `agent.sock`: the system daemon's socket when one is serving, else
/// `$CERMET_HOME/run/agent.sock`.
pub fn default_agent_sock(system_sock: &Path, home: &Path) -> PathBuf {
    if is_socket(system_sock) {
        system_sock.to_path_buf()
    } else {
        home.join("run").join("agent.sock")
    }
}

/// Locate the project CLAUDE.md, staying INSIDE the project boundary. A symlinked
/// CLAUDE.md is refused (the append never follows a link). See [`project_guidance_file`].
pub fn project_claude_md(cwd: &Path, home: &Path) -> Result<PathBuf, CliError> {
    project_guidance_file(cwd, home, "CLAUDE.md", true)
}

/// Locate the project guidance file `filename` (CLAUDE.md or AGENTS.md), staying INSIDE the project
/// boundary. Walk up from `cwd` for an existing regular file, but never past the project
/// (`.git` root) and never to/above `$HOME`. `cwd`/`home` must be pre-resolved (realpath).
///
/// `refuse_symlink` refuses a symlinked target outright (the CLAUDE.md rule). AGENTS.md passes
/// `false`: a project may symlink `AGENTS.md → CLAUDE.md`, so the symlink is RETURNED and the caller's
/// append step (`append_guidance_symlink_idempotent`) decides — never writing through the link, but
/// treating an already-guided target as idempotent success rather than a hard refusal.
pub fn project_guidance_file(
    cwd: &Path,
    home: &Path,
    filename: &str,
    refuse_symlink: bool,
) -> Result<PathBuf, CliError> {
    // $HOME and everything above it are off-limits.
    let mut forbidden: Vec<PathBuf> = vec![home.to_path_buf()];
    forbidden.extend(home.ancestors().skip(1).map(Path::to_path_buf));

    let mut d = cwd.to_path_buf();
    loop {
        let candidate = d.join(filename);
        let meta = std::fs::symlink_metadata(&candidate);
        if let Ok(m) = &meta {
            if m.file_type().is_symlink() {
                if refuse_symlink {
                    return Err(CliError::Refused(format!(
                        "refusing to write guidance: {} is a symlink (it could point outside the \
                         project); remove the link or add the note by hand",
                        candidate.display()
                    )));
                }
                return Ok(candidate);
            }
            if m.file_type().is_file() {
                return Ok(candidate);
            }
        }
        if d.join(".git").exists() {
            return Ok(candidate);
        }
        let parent = d.parent().map(Path::to_path_buf);
        match parent {
            Some(p) if p != d && !forbidden.contains(&p) && !forbidden.contains(&d) => d = p,
            _ => break,
        }
    }
    Ok(cwd.join(filename))
}

/// Whether the guidance stanza was newly written or was already present.
#[derive(Debug, PartialEq)]
pub enum GuidanceOutcome {
    Appended,
    Present,
}

/// Append the guidance stanza idempotently, at the fd: open `O_NOFOLLOW` (a symlink at the
/// target fails the open, never followed) and WITHOUT truncation, read the current bytes, and append
/// only when the marker is absent.
pub fn append_guidance_stanza(path: &Path) -> Result<GuidanceOutcome, CliError> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            CliError::Refused(format!(
                "refusing to write guidance to {}: {e} (a symlinked target is never followed)",
                path.display()
            ))
        })?;
    let mut existing = String::new();
    file.read_to_string(&mut existing)
        .map_err(|e| CliError::Refused(format!("could not read {}: {e}", path.display())))?;
    if existing.contains(GUIDANCE_MARKER) {
        return Ok(GuidanceOutcome::Present);
    }
    let sep = if existing.is_empty() || existing.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    file.seek(SeekFrom::End(0))
        .and_then(|_| write!(file, "{sep}\n{GUIDANCE_STANZA}"))
        .map_err(|e| {
            CliError::Refused(format!(
                "could not append guidance to {}: {e}",
                path.display()
            ))
        })?;
    Ok(GuidanceOutcome::Appended)
}

/// Append the guidance stanza to an OpenCode `AGENTS.md`, symlink-aware. A regular file (or an
/// absent one) is appended at the fd with `O_NOFOLLOW` via [`append_guidance_stanza`] — never
/// followed. A SYMLINK is never written through, but a project may symlink `AGENTS.md → CLAUDE.md`: when
/// the link's target already carries the marker the stanza is effectively present, so report it (the
/// idempotent case); a symlink WITHOUT the marker still refuses (add the note to its target by hand).
pub fn append_guidance_symlink_idempotent(path: &Path) -> Result<GuidanceOutcome, CliError> {
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if m.file_type().is_symlink() {
            let body = std::fs::read_to_string(path).unwrap_or_default();
            if body.contains(GUIDANCE_MARKER) {
                return Ok(GuidanceOutcome::Present);
            }
            return Err(CliError::Refused(format!(
                "{} is a symlink without the Cermet guidance; add the note by hand to its target \
                 (refusing to write through the link)",
                path.display()
            )));
        }
    }
    append_guidance_stanza(path)
}

/// Which client's guidance file the offer targets.
enum GuidanceKind {
    Claude,
    OpenCode,
}

/// The optional guidance offer: `Some(true)` forces it, `Some(false)` skips it, `None` prompts
/// (interactive only). Returns the human-facing note appended to the success output, or an error (a
/// symlinked/boundary-violating target refuses — the registration already stands). The target file
/// and symlink policy follow `kind`: CLAUDE.md (symlink refused) for Claude, AGENTS.md (symlink
/// idempotent) for OpenCode.
fn offer_guidance(
    force: Option<bool>,
    term: &dyn Terminal,
    kind: GuidanceKind,
) -> Result<Option<String>, CliError> {
    if force == Some(false) {
        return Ok(None);
    }
    let cwd = std::env::current_dir()
        .map_err(|e| CliError::Refused(format!("cannot resolve the current directory: {e}")))?;
    let cwd = std::fs::canonicalize(&cwd).unwrap_or(cwd);
    let home = home_dir();
    let home = std::fs::canonicalize(&home).unwrap_or(home);
    let (filename, refuse_symlink) = match kind {
        GuidanceKind::Claude => ("CLAUDE.md", true),
        GuidanceKind::OpenCode => ("AGENTS.md", false),
    };
    let target = project_guidance_file(&cwd, &home, filename, refuse_symlink)?;
    if force.is_none() {
        if !term.is_interactive() {
            return Ok(None);
        }
        let prompt = format!(
            "Add a short note to {} suggesting build/test commands route through Cermet's tools \
             (audited, compact receipts)?",
            target.display()
        );
        if !term.confirm(&prompt, false) {
            return Ok(None);
        }
    }
    let outcome = match kind {
        GuidanceKind::Claude => append_guidance_stanza(&target)?,
        GuidanceKind::OpenCode => append_guidance_symlink_idempotent(&target)?,
    };
    match outcome {
        GuidanceOutcome::Present => Ok(Some(format!(
            "{filename} guidance already present in {} (left unchanged).",
            target.display()
        ))),
        GuidanceOutcome::Appended => Ok(Some(format!(
            "✓ appended Cermet guidance to {}.",
            target.display()
        ))),
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn cermet_home() -> PathBuf {
    crate::cermet_home()
}

/// Drive `mcp install`. Idempotent: any prior registration under `name` is removed first, then added.
/// The binary/socket are resolved BEFORE the barrier so a missing binary never begins a transaction.
/// The daemon-held quiesce barrier is entered next and the SAME token is held across the complete
/// remove/add mutation; End runs on success and every handled failure. On any refusal (fail closed)
/// no client config is touched.
pub fn run_mcp_install(
    args: &McpInstallArgs,
    claude: &dyn ClaudeCli,
    term: &dyn Terminal,
    barrier: Option<&dyn RepointBarrier>,
) -> Result<crate::CliOutput, CliError> {
    if !valid_server_name(&args.name) {
        return Err(CliError::Usage(
            "--name must be a plain identifier (letters, digits, '.', '_', '-'; no leading dash)."
                .to_string(),
        ));
    }
    // Resolve the binary + socket FIRST — a missing binary refuses without ever entering the barrier.
    let bin_path = match &args.binary {
        Some(b) => PathBuf::from(b),
        None => match claude.bridge_binary() {
            Some(p) => p,
            None => {
                return Err(CliError::Usage(
                    "Could not find the cermet binary. Build it (`cargo build -p \
                     cermet-cli --bin cermet`) or pass --binary <path>."
                        .to_string(),
                ));
            }
        },
    };
    let sock = args.sock.clone().unwrap_or_else(|| {
        default_agent_sock(Path::new(SYSTEM_AGENT_SOCK), &cermet_home())
            .to_string_lossy()
            .into_owned()
    });

    // Enter the quiesce barrier (or refuse). `guard` (when held) blocks new claims through the
    // mutation; `warning` is a `--force` note prepended to a success line.
    let (guard, warning) = match barrier {
        Some(b) => match begin_and_drain(b, args.force) {
            Gate::Refuse(out) => return Ok(out),
            Gate::Proceed { guard, warning } => (guard, warning),
        },
        // No daemon endpoint at all — daemon unavailability is never "no live call".
        None => {
            if !args.force {
                return Ok(refuse_daemon_unavailable());
            }
            (None, Some(FORCE_ORPHAN_WARNING.to_string()))
        }
    };

    // The binary/socket/barrier steps above are client-agnostic; only the registration surface differs.
    let result = match args.client {
        McpClient::Claude => register_claude(
            &args.name,
            claude,
            term,
            &bin_path,
            &sock,
            args.guidance,
            guard.as_ref(),
        ),
        McpClient::OpenCode => register_opencode(
            &args.name,
            term,
            &bin_path,
            &sock,
            args.guidance,
            guard.as_ref(),
        ),
    };

    // End the barrier on success AND every handled failure (the daemon's TTL recovers a missed End).
    if let Some(g) = &guard {
        g.barrier.end(&g.token);
    }
    // Prepend a `--force` orphan warning to a successful registration line.
    match (result, &warning) {
        (Ok(mut out), Some(w)) if out.ok => {
            out.text = format!("{w}\n{}", out.text);
            Ok(out)
        }
        (other, _) => other,
    }
}

/// Register with Claude Code via the `claude mcp` CLI (idempotent remove-then-add). On any failure
/// (no `claude` on PATH, run error, non-zero add) it renders the exact SAFE manual command and
/// returns `ok:false`.
fn register_claude(
    name: &str,
    claude: &dyn ClaudeCli,
    term: &dyn Terminal,
    bin_path: &Path,
    sock: &str,
    guidance: Option<bool>,
    guard: Option<&RepointGuard<'_>>,
) -> Result<crate::CliOutput, CliError> {
    let add_cmd = mcp_add_command(name, bin_path, sock);
    // The printed fallback is a SAFE copy-paste even when the sock/path carries shell
    // metacharacters — quote each token. Display-only; the real call uses the argv vector.
    let manual = shlex_join(&add_cmd);

    if claude.which("claude").is_none() {
        return Ok(crate::CliOutput {
            text: format!("✗ The `claude` CLI is not on PATH. Register manually:\n  {manual}"),
            ok: false,
        });
    }

    // Barrier still held on the same daemon before the FIRST mutation? (No config touched yet.)
    // AND does the OBSERVED remaining lease cover the whole remove+add budget? Both are
    // pre-mutation, fail-closed — a near-exhausted lease refuses here rather than overrunning it.
    if let Some(g) = guard {
        g.lease_covers_mutation()?;
        g.recheck("before the registration was changed")?;
    }
    // Idempotent: drop any prior registration (tolerate absence), then add fresh. The token is held
    // across BOTH steps and re-checked between them — the barrier is never released mid-mutation.
    // Each shell-out is bounded by STEP_MUTATION_TIMEOUT (well inside the 120s barrier
    // lease), so a hung `claude` child is killed rather than mutating after the lease would lapse.
    match claude.run(
        &[
            "claude".into(),
            "mcp".into(),
            "remove".into(),
            name.to_string(),
        ],
        STEP_MUTATION_TIMEOUT,
    ) {
        // A timed-out `remove` is a bounded, fail-closed abort — do NOT proceed to `add` (a killed
        // child may have partially mutated). A non-timeout error / nonzero (absent prior) is tolerated.
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            return Err(CliError::Refused(format!(
                "`claude mcp remove` did not finish within {}s and was killed; the MCP registration \
                 may be PARTIAL. Reconcile it by hand and re-run `cermet mcp install`. ({e})",
                STEP_MUTATION_TIMEOUT.as_secs()
            )));
        }
        _ => {}
    }
    if let Some(g) = guard {
        g.recheck("after removing the old registration but before adding the new one")?;
    }
    let result = claude.run(&add_cmd, STEP_MUTATION_TIMEOUT);
    match result {
        Err(e) => {
            return Ok(crate::CliOutput {
                text: format!("✗ Failed to run `claude` ({e}). Register manually:\n  {manual}"),
                ok: false,
            });
        }
        Ok(out) if out.code != 0 => {
            let mut text = String::from("✗ `claude mcp add` failed. Register manually:");
            if !out.stderr.trim().is_empty() {
                text.push('\n');
                text.push_str(out.stderr.trim());
            }
            text.push_str(&format!("\n  {manual}"));
            return Ok(crate::CliOutput { text, ok: false });
        }
        Ok(_) => {}
    }

    // After the final mutation step, confirm the barrier held throughout (same daemon, still up).
    if let Some(g) = guard {
        g.recheck("after adding the new registration")?;
    }

    let mut text = format!(
        "✓ registered MCP server '{name}' → {} (CERMET_AGENT_SOCK={sock})\n\
         Restart Claude Code (or /mcp reconnect) to pick it up, then ask it to use `catalog`.",
        bin_path.display()
    );
    // The registration stands even if the guidance offer refuses: the "registered" line has
    // already printed before a symlink refusal propagates non-zero.
    if let Some(note) = offer_guidance(guidance, term, GuidanceKind::Claude)? {
        text.push('\n');
        text.push_str(&note);
    }
    Ok(crate::CliOutput { text, ok: true })
}

/// Register with OpenCode by merging our server into the global `opencode.json` and offering the
/// AGENTS.md guidance. Same env contract as every client. Raw-shell deny policy is the
/// operator's own client configuration — Cermet neither writes nor recommends a deny block.
fn register_opencode(
    name: &str,
    term: &dyn Terminal,
    bin_path: &Path,
    sock: &str,
    guidance: Option<bool>,
    guard: Option<&RepointGuard<'_>>,
) -> Result<crate::CliOutput, CliError> {
    let config_path = opencode_config_path(&home_dir());
    // Barrier still held + lease covers the mutation before touching the config (pre-mutation).
    if let Some(g) = guard {
        g.lease_covers_mutation()?;
        g.recheck("before the OpenCode config was changed")?;
    }
    let written = write_opencode_config(&config_path, name, bin_path, sock)?;
    if let Some(g) = guard {
        g.recheck("after writing the OpenCode config")?;
    }
    match written {
        ConfigWrite::Unparseable(detail) => {
            let snippet = serde_json::to_string_pretty(&serde_json::json!({
                "mcp": { name: opencode_server_entry(bin_path, sock, name) }
            }))
            .unwrap_or_default();
            return Ok(crate::CliOutput {
                text: format!(
                    "✗ {} is not valid JSON ({detail}); refusing to overwrite it (fail closed). \
                     Merge this in by hand under \"mcp\":\n{snippet}",
                    config_path.display()
                ),
                ok: false,
            });
        }
        ConfigWrite::Written => {}
    }

    let mut text = format!(
        "✓ registered MCP server '{name}' in {} (CERMET_AGENT_SOCK={sock})\n\
         Restart OpenCode to pick it up, then ask it to use `catalog`.",
        config_path.display(),
    );
    if let Some(note) = offer_guidance(guidance, term, GuidanceKind::OpenCode)? {
        text.push('\n');
        text.push_str(&note);
    }
    Ok(crate::CliOutput { text, ok: true })
}

/// The global OpenCode config OUR `mcp install --client opencode` writes (machine-scoped broker).
/// Honors `$XDG_CONFIG_HOME`, else `~/.config`.
pub fn opencode_config_path(home: &Path) -> PathBuf {
    match std::env::var_os("XDG_CONFIG_HOME").filter(|x| !x.is_empty()) {
        Some(x) => PathBuf::from(x).join("opencode").join("opencode.json"),
        None => home.join(".config").join("opencode").join("opencode.json"),
    }
}

/// The cermet MCP server entry for `opencode.json` — OpenCode's V1 local-server schema
/// (`type`/`command`/`environment`/`enabled`) carrying the same env contract as every client.
pub fn opencode_server_entry(binary: &Path, sock: &str, name: &str) -> serde_json::Value {
    // The launch is platform/topology-resolved — on the Linux service topology `command` is the
    // sudo invocation with an empty environment (socket pinned in argv, no CERMET_AGENT_SOCK).
    let launch = agent_launch(name, binary, sock);
    let environment: serde_json::Map<String, serde_json::Value> = launch
        .env
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    serde_json::json!({
        "type": "local",
        "command": launch.argv,
        "environment": environment,
        "enabled": true,
    })
}

/// The result of merging our server into `opencode.json`.
#[derive(Debug)]
pub enum ConfigWrite {
    /// The file was created or updated — our `mcp.<name>` entry set, all other keys/servers preserved.
    Written,
    /// The existing file is present but not parseable as a JSON object — left UNTOUCHED; the caller
    /// prints the snippet for the operator to place by hand (never clobber an operator's config).
    Unparseable(String),
}

/// Merge the cermet server into the OpenCode config at `path`: create it (and parent dirs) if absent,
/// preserve every other key and server, and set — idempotently overwriting — our own `mcp.<name>`
/// entry. `path` is a parameter so tests drive temp dirs; production passes [`opencode_config_path`].
/// Fail closed: if the existing file is not a JSON object it is left untouched (`Unparseable`).
pub fn write_opencode_config(
    path: &Path,
    name: &str,
    binary: &Path,
    sock: &str,
) -> Result<ConfigWrite, CliError> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(CliError::Refused(format!(
                "cannot read {}: {e}",
                path.display()
            )));
        }
    };
    let mut root: serde_json::Value = match existing.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => match serde_json::from_str(s) {
            Ok(v) => v,
            Err(e) => return Ok(ConfigWrite::Unparseable(e.to_string())),
        },
        _ => serde_json::json!({}),
    };
    let Some(obj) = root.as_object_mut() else {
        return Ok(ConfigWrite::Unparseable(
            "top-level value is not a JSON object".into(),
        ));
    };
    obj.entry("$schema".to_string())
        .or_insert_with(|| serde_json::json!("https://opencode.ai/config.json"));
    let mcp = obj
        .entry("mcp".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let Some(mcp_obj) = mcp.as_object_mut() else {
        return Ok(ConfigWrite::Unparseable(
            "\"mcp\" is present but is not a JSON object".into(),
        ));
    };
    mcp_obj.insert(name.to_string(), opencode_server_entry(binary, sock, name));

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::Refused(format!("cannot create {}: {e}", parent.display())))?;
    }
    let mut text = serde_json::to_string_pretty(&root)
        .map_err(|e| CliError::Refused(format!("cannot serialize opencode.json: {e}")))?;
    text.push('\n');
    // Persist via same-dir temp + rename so a crash/short write never leaves the
    // operator's global config truncated (fs::write truncates in place). Crash-robustness only —
    // no fsync/lock (no concurrent-installer adversary). A symlinked target (the dotfiles setup)
    // is resolved first: rename would replace the LINK, not the file it points to.
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let dir = target.parent().ok_or_else(|| {
        CliError::Refused(format!("{} has no parent directory", target.display()))
    })?;
    let tmp = dir.join(format!(".opencode.json.tmp-{}", std::process::id()));
    std::fs::write(&tmp, text)
        .map_err(|e| CliError::Refused(format!("cannot write {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, &target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        CliError::Refused(format!("cannot replace {}: {e}", target.display()))
    })?;
    Ok(ConfigWrite::Written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_command_shape_env_before_and_command_after_separator() {
        let argv = mcp_add_command(
            "cermet",
            Path::new("/opt/cermet"),
            "/home/u/.cermet/run/agent.sock",
        );
        assert_eq!(
            argv,
            vec![
                "claude",
                "mcp",
                "add",
                "cermet",
                "--env",
                "CERMET_AGENT_SOCK=/home/u/.cermet/run/agent.sock",
                "--env",
                "CERMET_AGENT_NAME=cermet",
                "--",
                "/opt/cermet",
                "mcp",
            ]
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_service_topology_registers_the_r1_sudo_invocation() {
        // Registering against the installed Linux service daemon (sock == SYSTEM_AGENT_SOCK)
        // must launch the bridge as the distinct cermet-agent uid via the sudo rule — the pinned
        // INSTALLED binary (not the discovered build path), NO CERMET_AGENT_SOCK env (the rule is
        // NOSETENV; --socket is the one source of truth).
        let argv = mcp_add_command("cermet", Path::new("/some/build/cermet"), SYSTEM_AGENT_SOCK);
        assert_eq!(
            argv,
            vec![
                "claude",
                "mcp",
                "add",
                "cermet",
                "--",
                "sudo",
                "-n",
                "-u",
                "cermet-agent",
                "-g",
                "cermet-agents",
                "/usr/local/bin/cermet",
                "--socket",
                "/run/cermetd-agents/agent.sock",
                "mcp",
            ]
        );
        assert!(
            !argv.iter().any(|a| a.contains("CERMET_AGENT_SOCK")),
            "the R1 sudo shape registers no CERMET_AGENT_SOCK env: {argv:?}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn opencode_linux_service_entry_uses_the_sudo_command_and_no_socket_env() {
        // The OpenCode entry carries the same sudo command and an EMPTY environment on the
        // Linux service topology.
        let entry =
            opencode_server_entry(Path::new("/some/build/cermet"), SYSTEM_AGENT_SOCK, "cermet");
        assert_eq!(
            entry["command"],
            serde_json::json!([
                "sudo",
                "-n",
                "-u",
                "cermet-agent",
                "-g",
                "cermet-agents",
                "/usr/local/bin/cermet",
                "--socket",
                "/run/cermetd-agents/agent.sock",
                "mcp"
            ])
        );
        assert_eq!(entry["environment"], serde_json::json!({}));
    }

    #[test]
    fn valid_name_rejects_leading_dash_and_bad_chars() {
        assert!(valid_server_name("cermet"));
        assert!(valid_server_name("cermet.v2_test-1"));
        assert!(!valid_server_name("-evil"));
        assert!(!valid_server_name(""));
        assert!(!valid_server_name("a b"));
    }

    #[test]
    fn guidance_stanza_names_the_daemon_backed_flow() {
        // The retained stanza names the registered server and its discovery→request→execute flow,
        // and carries NO raw-shell deny/reroute policy.
        assert!(
            GUIDANCE_STANZA.contains("cermet mcp"),
            "names the registered server"
        );
        assert!(
            GUIDANCE_STANZA.contains("request_capability"),
            "names the request step"
        );
        assert!(
            GUIDANCE_STANZA.contains("execute_capability"),
            "names the execute step"
        );
        // What is forbidden is a CLIENT-SIDE deny/reroute policy — routing raw commands
        // is the operator's own client configuration. The bare word "deny" is not the test: the
        // stanza must be able to teach what a BROKER deny means (relay the widening suggestion),
        // because that is the whole discovery protocol for a verb no sentence admits yet.
        for forbidden in [
            "BLOCKED",
            "deny raw",
            "refuse",
            "instead of the raw shell",
            "must not run",
        ] {
            assert!(
                !GUIDANCE_STANZA.contains(forbidden),
                "the stanza must carry no client-side deny/reroute policy, found {forbidden:?}"
            );
        }
        assert!(
            GUIDANCE_STANZA.contains("widening suggestion"),
            "the stanza teaches the unruled-verb path: deny → relay the widening suggestion"
        );
    }

    #[test]
    fn shlex_quote_matches_python_for_spaces_and_safe() {
        assert_eq!(shlex_quote("plain"), "plain");
        assert_eq!(
            shlex_quote("CERMET_AGENT_SOCK=/tmp/a"),
            "CERMET_AGENT_SOCK=/tmp/a"
        );
        assert_eq!(shlex_quote(""), "''");
        assert_eq!(
            shlex_quote("CERMET_AGENT_SOCK=/tmp/a b/agent.sock"),
            "'CERMET_AGENT_SOCK=/tmp/a b/agent.sock'"
        );
        assert_eq!(shlex_quote("it's"), "'it'\"'\"'s'");
    }
}
