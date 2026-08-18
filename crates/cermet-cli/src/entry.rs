//! `cermet` — the operator CLI role of the one shipped binary.
//!
//! ONE-BINARY: this is a library entry module, not a `[[bin]]`. The workspace ships a single
//! executable (`crates/cermet-bin`) whose closed dispatch table selects this role from the exact
//! `cermet` basename and calls [`run`] with the arguments AFTER the program name. Role selection
//! belongs to that router: nothing here reads `argv[0]`, `current_exe()`, or an env var to decide
//! what it is.
//!
//! Resolves the daemon endpoint from the launcher-passed env (`CERMET_CTL_SOCK` +
//! `CERMET_DAEMON_UID`), builds the keyless [`CtlBrokerClient`], selects the platform presence gate
//! (macOS Touch-ID; fail-closed elsewhere), then parses → dispatches → renders. Fail closed
//! everywhere: a missing endpoint, a refused presence, or a broker error exits non-zero and never
//! falls back to any in-process broker.
//!
//! Commands with local seams are driven directly here, not through ctl dispatch. `mcp install` is
//! local setup that skips ctl endpoint resolution; `connect` still needs its operator transport.

use std::path::PathBuf;
use std::process::ExitCode;

use crate::check::{run_check, CheckEnv};
use crate::connect::{run_connect, StdTokenSource};
use crate::mcp::{run_mcp_install, StdClaudeCli};
use crate::tty::{StdTerminal, Terminal};
use crate::{CliCommand, CliError, CliOutput};
use cermet_ctl_client::broker_client::CtlBrokerClient;

/// The operator CLI role. `args` is the invocation WITHOUT the program name.
pub fn run(args: &[String]) -> ExitCode {
    let argv: Vec<String> = args.to_vec();
    print_update_notice(&argv);
    // Help is a FIRST-CLASS surface — stdout, exit 0. Checked ahead of the MCP bridge so
    // `cermet mcp --help` answers here rather than falling into the bridge's own argument parser.
    if let Some(help) = crate::help_text(&argv) {
        println!("{help}");
        return ExitCode::SUCCESS;
    }
    // so is `--version`, and for the same reason — it is a question about this binary,
    // answerable with no daemon, no socket, and no config.
    if let Some(version) = crate::version_text(&argv) {
        println!("{version}");
        return ExitCode::SUCCESS;
    }
    if let Some(exit) = run_mcp_bridge(&argv) {
        return exit;
    }
    let (socket_override, rest) = crate::split_socket_flag(&argv);
    let status_json = doc_status_json_requested(&rest);

    let cmd = match crate::parse(&rest) {
        Ok(c) => c,
        Err(CliError::Usage(m)) => {
            if status_json {
                return finish_reconciliation(crate::reconciliation::status_json_failure());
            }
            eprintln!("cermet: {m}");
            return ExitCode::from(2);
        }
        Err(e) => {
            if status_json {
                return finish_reconciliation(crate::reconciliation::status_json_failure());
            }
            eprintln!("cermet: {e}");
            return ExitCode::from(2);
        }
    };

    // Commands with a local seam (setup / sentence ceremony): driven directly here.
    match &cmd {
        CliCommand::OwnerStatus | CliCommand::OwnerLockdown | CliCommand::OwnerLockdownClear => {
            if matches!(cmd, CliCommand::OwnerLockdownClear)
                && (!StdTerminal.is_interactive()
                    || !StdTerminal.confirm(
                        "Clear owner lockdown and restore capability execution?",
                        false,
                    ))
            {
                return finish(Err(CliError::Refused(
                    "owner lockdown clear requires an explicit interactive confirmation; latch unchanged"
                        .into(),
                )));
            }
            let (socket, daemon_uid) =
                match crate::owner::resolve_owner_endpoint(socket_override.clone()) {
                    Ok(endpoint) => endpoint,
                    Err(error) => return finish(Err(error)),
                };
            let request = match cmd {
                CliCommand::OwnerStatus => cermet_ipc::owner::OwnerRequest::OwnerStatus,
                CliCommand::OwnerLockdown => cermet_ipc::owner::OwnerRequest::OwnerLockdown,
                CliCommand::OwnerLockdownClear => cermet_ipc::owner::OwnerRequest::OwnerClear,
                _ => unreachable!(),
            };
            return finish(crate::owner::run_owner(&socket, daemon_uid, request));
        }
        CliCommand::Init
        | CliCommand::DocCheck { .. }
        | CliCommand::Diff
        | CliCommand::Status { .. }
        | CliCommand::Export { .. }
        | CliCommand::Apply { .. }
        | CliCommand::Allow { .. }
        | CliCommand::Rules
        | CliCommand::Revoke { .. }
        | CliCommand::Refresh { .. } => {
            let client = match resolve_client(socket_override.clone()) {
                Ok(client) => client,
                Err(error) => {
                    if status_json {
                        return finish_reconciliation(crate::reconciliation::status_json_failure());
                    }
                    eprintln!("cermet: {error}");
                    return ExitCode::from(2);
                }
            };
            let cwd = match std::env::current_dir() {
                Ok(cwd) => cwd,
                Err(_) => {
                    if status_json {
                        return finish_reconciliation(crate::reconciliation::status_json_failure());
                    }
                    eprintln!("cermet: cannot resolve the current repository path");
                    return ExitCode::from(2);
                }
            };
            let output = match crate::dispatch_authority_command(
                &client,
                &cmd,
                &cwd,
                &StdTerminal,
                sentence_presence(),
            ) {
                Ok(Some(output)) => output,
                Ok(None) => unreachable!(),
                Err(error) => return finish(Err(error)),
            };
            println!("{}", output.text);
            return ExitCode::from(output.exit_code);
        }
        CliCommand::McpInstall(args) => {
            // Before repointing the registered MCP server, drive the daemon-held quiesce barrier:
            // begin → drain only genuinely-active leases → proceed only on proved
            // Quiescent → hold the same token across the remove/add mutation → End. The barrier is
            // built ONLY when the launcher passed the trusted ctl anchors; with no daemon endpoint the
            // transaction is absent and install refuses without --force (daemon unavailability is
            // never "there can be no live call").
            let barrier = mcp_repoint_barrier(socket_override.clone());
            let barrier_ref = barrier
                .as_ref()
                .map(|b| b as &dyn crate::mcp::RepointBarrier);
            return finish(run_mcp_install(
                args,
                &StdClaudeCli,
                &StdTerminal,
                barrier_ref,
            ));
        }
        // `check` is a doctor: an endpoint it cannot even resolve is its FIRST FINDING, not a reason
        // to refuse to run. So it resolves the client itself and reports either way.
        CliCommand::Check { provider } => {
            let client = resolve_client(socket_override.clone());
            let env = CheckEnv::from_process(resolve_agent_socket(
                None,
                std::env::var_os("CERMET_AGENT_SOCK"),
            ));
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("cermet: cannot start the runtime: {e}");
                    return ExitCode::FAILURE;
                }
            };
            return finish(rt.block_on(run_check(
                client.as_ref().map_err(String::clone),
                provider.as_deref(),
                &env,
            )));
        }
        // `update` talks to the origin and to sudo, and to no daemon at all. It has to work on a
        // box whose daemon is down — an operator updating BECAUSE it is down is the ordinary case —
        // so it is driven here rather than through ctl dispatch.
        CliCommand::Update { check } => return finish(crate::update::run(*check)),
        // The SCHEDULED check: the installed timer runs exactly this, as the operator. It talks to
        // the origin and to the operator's own config directory, and to nothing else — no sudo, no
        // daemon, no install.
        CliCommand::UpdateDailyCheck => return finish(run_daily_update_check()),
        CliCommand::UpdateDaily { enabled } => {
            return finish(crate::update_check::run_daily_setting(
                &crate::settings::config_path(),
                *enabled,
            ))
        }
        CliCommand::UpdateApply { sha256 } => return finish(crate::update::run_apply(sha256)),
        CliCommand::UpdateApplyDeb { package, sha256 } => {
            return finish(crate::update::run_apply_deb(
                std::path::Path::new(package),
                sha256,
            ))
        }
        CliCommand::Setup(args) => {
            return match crate::setup::run(args) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("[cermet-setup] REFUSED: {error}");
                    ExitCode::FAILURE
                }
            };
        }
        _ => {}
    }

    let client = match build_client(socket_override) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cermet: cannot start the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    // `connect` needs the terminal + token source (its raw token never leaves SecretString), and the
    // cwd, because `connect github` offers to wire THIS repository's remote.
    if let CliCommand::Connect(args) = &cmd {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        return finish(rt.block_on(run_connect(
            &client,
            &StdTerminal,
            &StdTokenSource,
            args,
            &cwd,
        )));
    }

    // `log` is the morning receipt: route through the daemon's `History` RPC. Read-only, no
    // presence.
    if let CliCommand::Log {
        since,
        provider,
        denied_only,
        hops,
        all,
    } = &cmd
    {
        // The window and the filters are applied CLI-side, on the full view the ctl
        // `History`/`RelayHops` ops already serve. Those ops are unit variants with no limit or
        // filter parameter, and adding one would be a new protocol shape across four crates for no
        // gain here: the cost this bug is about is the operator's/agent's CONTEXT, not the bytes on
        // a local unix socket, and the honest "N rows exist" line needs the full count anyway.
        let filter = crate::receipt_log::LogFilter {
            since: since.as_deref(),
            provider: provider.as_deref(),
            denied_only: *denied_only,
            all: *all,
        };
        // `--hops` is the relay view of the same log — what the native client did with a
        // session the daemon authorized, and why the session stopped.
        if *hops {
            let hops_json = match rt.block_on(client.relay_hops()) {
                Ok(json) => json,
                Err(e) => return finish(Err(CliError::Server(e))),
            };
            return finish(crate::receipt_log::run_log_hops(&hops_json, &filter));
        }
        let history_json = match rt.block_on(client.history()) {
            Ok(json) => json,
            Err(e) => return finish(Err(CliError::Server(e))),
        };
        return finish(crate::receipt_log::run_log_history(&history_json, &filter));
    }

    // No presence adapter is built here: every command `dispatch` serves is
    // decide-or-read, so the one this used to construct was never consulted. Authority mutations
    // go through `sentence_presence()` below.
    finish(rt.block_on(crate::dispatch(&client, &cmd)))
}

/// One run of the daily update check, against THIS box: the operator's own settings file, the
/// project's GitHub releases, this platform's target, and this box's install channel.
///
/// A channel this box cannot classify (the fail-closed case `cermet update` refuses on) is treated
/// as the tarball channel HERE, because nothing is installed either way: the worst it can do is
/// record a notice for a box whose typed `cermet update` will then explain the ambiguity properly.
/// Refusing the check instead would leave that box permanently unaware of a security release.
fn run_daily_update_check() -> Result<CliOutput, CliError> {
    let config = crate::settings::config_path();
    let enabled = crate::settings::read_update_check(&config)?;
    crate::update_check::run_daily_check(
        enabled,
        &crate::update_check::state_dir(&config),
        &crate::update::origin(std::env::var(crate::update::ORIGIN_ENV).ok()),
        crate::update::UPDATE_REPO,
        crate::update::host_target(),
        crate::update::host_channel().unwrap_or(crate::update::Channel::Tarball),
        crate::update::CURRENT_VERSION,
        time::OffsetDateTime::now_utc(),
        &crate::update::fetch,
    )
}

/// The one-line update notice, before anything else this invocation does.
///
/// On STDERR, so no machine reading stdout can ever be polluted by it, and skipped outright for the
/// two invocations whose stderr is a protocol-adjacent channel rather than a human's terminal. It is
/// a pure read of a file the operator's own scheduled check wrote: an unreadable or absent state
/// prints nothing, because a notice must never be able to break a command.
fn print_update_notice(argv: &[String]) {
    if crate::update_check::notice_is_suppressed(argv) {
        return;
    }
    let dir = crate::update_check::state_dir(&crate::settings::config_path());
    if let Ok(Some(state)) = crate::update_check::read_state(&dir) {
        if let Some(line) = crate::update_check::notice(&state, crate::update::CURRENT_VERSION) {
            eprintln!("{line}");
        }
    }
}

/// Where `agent.sock` lives in service mode. Dev/embedded runs and tests override this with
/// `--socket <path>` or `CERMET_AGENT_SOCK`. This IS the constant the bridge registration
/// and the sudoers rule pin — not a bin-local twin that agrees today and drifts silently tomorrow.
const DEFAULT_AGENT_SOCK: &str = crate::mcp::SYSTEM_AGENT_SOCK;

fn resolve_agent_socket(
    socket_flag: Option<PathBuf>,
    env_sock: Option<std::ffi::OsString>,
) -> PathBuf {
    socket_flag
        .or_else(|| env_sock.filter(|s| !s.is_empty()).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_AGENT_SOCK))
}

fn is_mcp_bridge_command(args: &[String]) -> bool {
    args.first().map(String::as_str) == Some("mcp")
        && args.get(1).map(String::as_str) != Some("install")
}

/// The `git-remote-cermet` role: git's remote helper, and nothing else. The router selects it from
/// the exact `git-remote-cermet` basename — git looks a remote helper up by NAME on PATH, so the
/// name IS the dispatch. It speaks git's protocol on stdio and must never emit CLI chatter.
///
/// `args` is the invocation WITHOUT the program name; git calls the helper as
/// `git-remote-cermet <remote> <url>`, and the url is the part after `cermet::`. With a bare remote
/// name and no url, there is nothing to connect to.
pub fn run_git_remote_helper(args: &[String]) -> ExitCode {
    let url = args.get(1).cloned().unwrap_or_default();
    let socket = crate::git_remote::resolve_git_socket(None);
    match crate::git_remote::run(socket, &url) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("git-remote-cermet: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatch the keyless agent bridge before the operator CLI resolves `ctl.sock`.
///
/// There are exactly TWO `cermet mcp` invocations: bare `cermet mcp` runs the stdio MCP server (the
/// agent's whole interface, and the argv the installed sudoers rule pins), and `cermet mcp install`
/// — handled by the operator CLI below — registers it. There is no one-shot subcommand family, so
/// anything else under `mcp` is a usage error naming the two that exist.
fn run_mcp_bridge(argv: &[String]) -> Option<ExitCode> {
    let (socket_flag, rest) = crate::mcp_bridge::split_global_flags(argv);
    if !is_mcp_bridge_command(&rest) {
        return None;
    }
    if rest.len() > 1 {
        eprintln!(
            "cermet mcp: unknown argument {:?}\n\
             USAGE:\n    \
             cermet [--socket <path>] mcp        (run the stdio MCP server)\n    \
             cermet mcp install [--client claude|opencode]  (register it with an agent client)",
            rest[1]
        );
        return Some(ExitCode::from(2));
    }

    let socket = resolve_agent_socket(socket_flag, std::env::var_os("CERMET_AGENT_SOCK"));
    Some(match crate::mcp_bridge::server::run(socket) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cermet mcp: {error}");
            ExitCode::FAILURE
        }
    })
}

/// The ctl-backed MCP-repoint quiesce barrier `cermet mcp install` drives. Each
/// method is a single ctl round-trip whose view JSON deserializes into the shared `cermet_lang` type.
/// Built best-effort: `None` when the trusted ctl anchors are absent (no daemon endpoint), in which
/// case install refuses without `--force`.
struct CtlRepointBarrier {
    rt: tokio::runtime::Runtime,
    client: CtlBrokerClient,
}

impl crate::mcp::RepointBarrier for CtlRepointBarrier {
    fn begin(&self, ttl_secs: i64) -> Result<cermet_lang::McpRepointBegin, String> {
        let json = self
            .rt
            .block_on(self.client.begin_mcp_repoint(ttl_secs))
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&json).map_err(|e| e.to_string())
    }
    fn status(&self, token: &str) -> Result<cermet_lang::McpRepointStatusReport, String> {
        let json = self
            .rt
            .block_on(self.client.mcp_repoint_status(token.to_string()))
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&json).map_err(|e| e.to_string())
    }
    fn end(&self, token: &str) {
        let _ = self
            .rt
            .block_on(self.client.end_mcp_repoint(token.to_string()));
    }
}

/// Build the ctl barrier if the ctl endpoint is resolvable; `None` otherwise (no daemon endpoint —
/// install refuses without `--force`).
fn mcp_repoint_barrier(socket_override: Option<String>) -> Option<CtlRepointBarrier> {
    let client = build_client(socket_override).ok()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    Some(CtlRepointBarrier { rt, client })
}

/// Resolve the trusted ctl endpoint + daemon uid and build the keyless client. The
/// installed CLI defaults the socket to `/var/run/cermetd/ctl.sock` and resolves the daemon uid from
/// the root-managed service account (`cermet`/`_cermet`); `--socket`/`CERMET_CTL_SOCK` and
/// `CERMET_DAEMON_UID` remain dev overrides. Fails closed (a non-zero [`ExitCode`]) on a
/// missing/ambiguous account or an unparseable uid — never guess the peer we hand a request (and, in
/// `connect`, a token) to. Peer-uid verification at connect time is unchanged.
fn build_client(socket_override: Option<String>) -> Result<CtlBrokerClient, ExitCode> {
    resolve_client(socket_override).map_err(|msg| {
        eprintln!("cermet: {msg}");
        ExitCode::FAILURE
    })
}

fn resolve_client(socket_override: Option<String>) -> Result<CtlBrokerClient, String> {
    let sock_env = std::env::var("CERMET_CTL_SOCK").ok();
    let uid_env = std::env::var("CERMET_DAEMON_UID").ok();
    match crate::endpoint::resolve_ctl_endpoint_real(socket_override, sock_env, uid_env) {
        Ok((sock, expected_daemon_uid)) => Ok(CtlBrokerClient::new(sock, expected_daemon_uid)),
        Err(msg) => Err(msg),
    }
}

/// `doc status --json` promises machine-readable output on EVERY path, including the ones that never
/// reach dispatch (a bad invocation, an unresolvable endpoint). Detected on raw argv for that reason.
fn doc_status_json_requested(args: &[String]) -> bool {
    args.first().is_some_and(|command| command == "doc")
        && args.get(1).is_some_and(|command| command == "status")
        && args.iter().skip(2).any(|argument| argument == "--json")
}

fn finish_reconciliation(output: crate::reconciliation::ReconciliationOutput) -> ExitCode {
    println!("{}", output.text);
    ExitCode::from(output.exit_code)
}

/// Presence used by both whole-document apply and incremental sentence-corpus mutations.
fn sentence_presence() -> std::sync::Arc<dyn cermet_ctl_client::presence::Presence> {
    // The adapter is the only platform-specific piece. The test-only gate is off by default, and
    // even test builds require CERMET_TEST_PRESENCE=1 per invocation.
    #[cfg(feature = "test-presence")]
    let presence: std::sync::Arc<dyn cermet_ctl_client::presence::Presence> =
        std::sync::Arc::new(cermet_ctl_client::presence::TestPresence);
    #[cfg(all(not(feature = "test-presence"), target_os = "macos"))]
    let presence: std::sync::Arc<dyn cermet_ctl_client::presence::Presence> =
        std::sync::Arc::new(cermet_ctl_client::presence::MacosUserPresence);
    #[cfg(all(not(feature = "test-presence"), not(target_os = "macos")))]
    let presence: std::sync::Arc<dyn cermet_ctl_client::presence::Presence> =
        std::sync::Arc::new(cermet_ctl_client::pam_presence::PamPasswordPresence);
    presence
}

fn finish(result: Result<CliOutput, CliError>) -> ExitCode {
    match result {
        Ok(out) => {
            // `update --apply` succeeds having already printed setup's own receipt, so it carries
            // no text of its own; a blank line is not a report.
            if !out.text.is_empty() {
                println!("{}", out.text);
            }
            if out.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(CliError::Usage(m)) => {
            eprintln!("cermet: {m}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("cermet: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn mcp_bridge_socket_precedence_is_flag_then_env_then_service_default() {
        assert_eq!(
            resolve_agent_socket(None, None),
            PathBuf::from(DEFAULT_AGENT_SOCK)
        );
        assert_eq!(
            resolve_agent_socket(None, Some(OsString::from("/env/agent.sock"))),
            PathBuf::from("/env/agent.sock")
        );
        assert_eq!(
            resolve_agent_socket(
                Some(PathBuf::from("/flag/agent.sock")),
                Some(OsString::from("/env/agent.sock")),
            ),
            PathBuf::from("/flag/agent.sock")
        );
        assert_eq!(
            resolve_agent_socket(None, Some(OsString::new())),
            PathBuf::from(DEFAULT_AGENT_SOCK)
        );
    }

    #[test]
    fn bare_mcp_uses_the_bridge_but_install_stays_operator_side() {
        assert!(is_mcp_bridge_command(&["mcp".into()]));
        // There is no one-shot family, but a leftover invocation of one is still intercepted
        // HERE (a usage error naming the two that exist) rather than falling through to
        // the operator CLI's parser, which would report it as an unknown top-level command.
        assert!(is_mcp_bridge_command(&["mcp".into(), "catalog".into()]));
        assert!(!is_mcp_bridge_command(&["mcp".into(), "install".into()]));
        assert!(!is_mcp_bridge_command(&["status".into()]));
    }
}
