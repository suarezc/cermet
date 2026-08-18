//! `cermet check [<provider>]` — the read-only plumbing checklist.
//!
//! The integration Cermet aims for is invisible: a wired repo pushes with plain `git push`, a relay
//! verb hands back an invocation the native CLI runs. Invisible integrations break invisibly — the
//! failure case is a user or agent who resets their git config, their PATH, or a credential and has
//! no way to see WHICH piece went missing. This is that way.
//!
//! It only ever REPORTS. Every finding is a `✗` with the one command that fixes it; nothing here
//! mutates a repository, a config file, or daemon state (one validation per boundary: `check` is not
//! a second enforcement of anything — the daemon still decides, and `connect` still connects).
//!
//! Exit codes: 0 all green, 1 any gap, 2 an unknown provider (the explicit-argument case only).

use std::ffi::OsString;
use std::path::PathBuf;

use cermet_ctl_client::broker_client::CtlBrokerClient;
use serde::Deserialize;
use serde_json::Value;

use crate::cutover::CutoverReport;
use crate::git_remote::wiring;
use crate::render::which;
use crate::{CliError, CliOutput};

/// The providers with a checklist of their own. An explicit argument outside this set is a usage
/// error; the bare form doctors whatever is CONNECTED, with the generic rows for anything else.
pub const KNOWN_PROVIDERS: &[&str] = &["github", "vercel", "stripe"];

/// The process facts a checklist reads. Passed in rather than read from the environment so the
/// probes are testable without mutating process-wide state (the same reason
/// [`crate::render::relay_tool_warning`] takes a `PATH`).
pub struct CheckEnv {
    pub cwd: PathBuf,
    pub path: Option<OsString>,
    pub git_sock: PathBuf,
    pub agent_sock: PathBuf,
    /// The platform's declarative PATH registration for the install prefix, when one is installed.
    /// Its presence turns "not on PATH" from a ✗ into "this shell predates the install".
    pub path_registration: Option<PathBuf>,
    /// What is still running or still registered from a previous engine. Probed once at
    /// construction rather than inside the rows, for the same reason `path` is passed in.
    pub cutover: CutoverReport,
    /// The daily update check's own state: the setting, and what the last check saw. Read from the
    /// operator's own config directory at construction, like every other environment fact here.
    pub update: crate::update_check::UpdateCheckReport,
}

impl CheckEnv {
    pub fn from_process(agent_sock: PathBuf) -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        Self {
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            path: std::env::var_os("PATH"),
            git_sock: crate::git_remote::resolve_git_socket(None),
            agent_sock,
            path_registration: crate::cutover::path_registration(),
            cutover: crate::cutover::detect(home.as_deref()),
            update: crate::update_check::UpdateCheckReport::read(&crate::settings::config_path()),
        }
    }
}

/// One connected credential, as the operator view reports it. Never a secret — a reference and a
/// date are all a checklist needs.
#[derive(Debug, Deserialize)]
struct CredentialRow {
    provider: String,
    reference: String,
    created_at: String,
}

enum Mark {
    Pass,
    Gap,
    Info,
}

struct Row {
    mark: Mark,
    label: String,
    detail: String,
    remedy: Option<String>,
}

fn pass(label: &str, detail: impl Into<String>) -> Row {
    Row {
        mark: Mark::Pass,
        label: label.into(),
        detail: detail.into(),
        remedy: None,
    }
}

fn gap(label: &str, detail: impl Into<String>, remedy: impl Into<String>) -> Row {
    Row {
        mark: Mark::Gap,
        label: label.into(),
        detail: detail.into(),
        remedy: Some(remedy.into()),
    }
}

/// Split a transport error into `(headline, diagnosis)`. The ctl client appends a group-membership
/// diagnosis to a permission-denied connect on following lines; the checklist is a table,
/// so the headline stays the row and the diagnosis collapses to one line for the remedy column.
fn split_diagnosis(reason: &str) -> (String, Option<String>) {
    match reason.split_once('\n') {
        None => (reason.to_string(), None),
        Some((headline, rest)) => (
            headline.to_string(),
            Some(rest.lines().map(str::trim).collect::<Vec<_>>().join(" ")),
        ),
    }
}

fn info(label: &str, detail: impl Into<String>) -> Row {
    Row {
        mark: Mark::Info,
        label: label.into(),
        detail: detail.into(),
        remedy: None,
    }
}

/// Render the checklist. `client` is the resolved ctl client or the reason there isn't one — an
/// unreachable daemon is the checklist's FIRST finding, never a reason to refuse to run.
pub async fn run_check(
    client: Result<&CtlBrokerClient, String>,
    provider: Option<&str>,
    env: &CheckEnv,
) -> Result<CliOutput, CliError> {
    if let Some(name) = provider {
        if !KNOWN_PROVIDERS.contains(&name) {
            return Err(CliError::Usage(format!(
                "no checklist for provider {name:?}; known providers: {}",
                KNOWN_PROVIDERS.join(", ")
            )));
        }
    }

    let live = client.as_ref().ok().copied();
    let credentials = match client {
        Ok(client) => client.list_credentials().await.map_err(|e| e.to_string()),
        Err(reason) => Err(reason),
    };
    let connected: Vec<CredentialRow> = credentials
        .as_ref()
        .ok()
        .and_then(|view| serde_json::from_str(view).ok())
        .unwrap_or_default();

    // One doctor round trip, for the one question only the enforcer can answer.
    let health = match live {
        Some(client) => client.doctor().await.map_err(|e| e.to_string()),
        None => Err(credentials
            .as_ref()
            .err()
            .cloned()
            .unwrap_or_else(|| "cermetd is unreachable".to_string())),
    };

    let mut sections = vec![
        (
            "plumbing".to_string(),
            plumbing(&health, &credentials, &connected, env),
        ),
        ("stale engines".to_string(), cutover_rows(&env.cutover)),
    ];

    let subjects: Vec<String> = match provider {
        Some(name) => vec![name.to_string()],
        None => connected
            .iter()
            .map(|row| row.provider.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect(),
    };
    if subjects.is_empty() {
        sections.push((
            "providers".to_string(),
            vec![info(
                "none connected",
                "start with `cermet connect github` (or vercel, stripe)",
            )],
        ));
    }
    for name in subjects {
        let rows = provider_rows(live, &name, &connected, env).await;
        sections.push((name, rows));
    }

    Ok(render(&sections))
}

/// The pieces every provider depends on: the daemon, its git stream plane, the remote helper, and
/// the agent bridge socket.
fn plumbing(
    health: &Result<Value, String>,
    credentials: &Result<String, String>,
    connected: &[CredentialRow],
    env: &CheckEnv,
) -> Vec<Row> {
    let mut rows = Vec::new();
    rows.push(match credentials {
        Ok(_) => pass(
            "cermetd",
            format!(
                "serving on ctl.sock — {} provider(s) connected",
                connected.len()
            ),
        ),
        Err(reason) => {
            let (headline, diagnosis) = split_diagnosis(reason);
            gap(
                "cermetd",
                headline,
                // A diagnosis from the transport (the `cermet-approvers` login lag) is a
                // better remedy than the generic one, because it names THIS box's actual reason.
                diagnosis.unwrap_or_else(|| {
                    if cfg!(target_os = "macos") {
                        "start the daemon: `sudo launchctl bootstrap system \
                         /Library/LaunchDaemons/dev.cermet.cermetd.plist` (or `make -C dist \
                         install` on a fresh box)"
                            .to_string()
                    } else {
                        "start the daemon: `sudo systemctl start cermetd` (or `make -C dist \
                         install` on a fresh box)"
                            .to_string()
                    }
                }),
            )
        }
    });
    rows.push(build_row(health.as_ref()));
    rows.push(custody_row(health.as_ref()));
    rows.push(git_helper_row(env));
    rows.push(git_plane_row(health.as_ref()));
    rows.push(update_row(&env.update));
    rows.push(if env.agent_sock.exists() {
        pass("agent bridge", env.agent_sock.display().to_string())
    } else {
        gap(
            "agent bridge",
            format!("{} is absent", env.agent_sock.display()),
            "start cermetd, then register the bridge with `cermet mcp install`",
        )
    });
    rows
}

/// What the daily update check knows: whether it runs, when it last ran, what is running versus
/// what is available, and which verification mode said so.
///
/// It is never a ✗ for "an update exists" — being a version behind is not a plumbing FAULT, and a
/// checklist that goes red because software moved trains people to ignore red. A ✗ here means the
/// mechanism itself is broken: a settings or state file that cannot be read. A pending update, and
/// an update check that has never run, are `·` rows carrying the command that acts on them.
fn update_row(report: &crate::update_check::UpdateCheckReport) -> Row {
    let label = "update check";
    if let Some(problem) = &report.problem {
        return gap(
            label,
            problem.clone(),
            "fix or delete the file it names, then run `cermet update --daily-check`",
        );
    }
    let running = crate::update::CURRENT_VERSION;
    if !report.enabled {
        return info(
            label,
            format!("off — running {running} (cermet update --daily on)"),
        );
    }
    let Some(state) = &report.state else {
        return info(
            label,
            format!("on, and it has not run yet — running {running} (cermet update --daily-check)"),
        );
    };
    let mode = state
        .verification
        .map(|verification| verification.word())
        .unwrap_or("not-checked");
    let mut detail = match crate::update_check::notice(state, running) {
        Some(_) if state.security => format!(
            "SECURITY UPDATE available — running {running}, {} published ({mode}) — last checked              {} — run: cermet update",
            state.available.as_deref().unwrap_or("?"),
            state.checked_at
        ),
        Some(_) => format!(
            "running {running}, {} available ({mode}) — last checked {} — run: cermet update",
            state.available.as_deref().unwrap_or("?"),
            state.checked_at
        ),
        None => format!("running {running}, nothing newer — last checked {}", state.checked_at),
    };
    if let Some(notes) = &state.notes {
        detail.push_str(&format!(" — {notes}"));
    }
    // A check that did not COMPLETE is said out loud rather than read as "nothing newer": silence
    // is never health.
    if let Some(problem) = &state.problem {
        detail.push_str(&format!("\n     last check did not complete: {problem}"));
    }
    info(label, detail)
}

/// Are this CLI and the daemon the same build?
///
/// The invisible-integration case again: an installed pair drifts apart the moment one half is
/// reinstalled and the other keeps running, and nothing else on this checklist would show it — the
/// daemon keeps deciding correctly, so every other row stays green while the client's surface is a
/// build old. `cermetd` stamps the build that answered onto its ctl replies; this row prints both.
/// A daemon we could not ask is `·`, never a ✗ — "I could not ask" is not "you are skewed".
fn build_row(report: Result<&Value, &String>) -> Row {
    let label = "build";
    let Ok(report) = report else {
        return info(label, format!("this CLI is {}", cermet_ipc::BUILD_ID));
    };
    let advertised = report.get("build").and_then(Value::as_str).unwrap_or("");
    match cermet_ipc::build_skew(advertised) {
        None => pass(label, format!("cermet and cermetd are {advertised}")),
        Some(daemon) => gap(
            label,
            format!(
                "cermetd is {daemon}; this CLI is {} — one of the two is stale",
                cermet_ipc::BUILD_ID
            ),
            "reinstall the pair: `make -C dist install`, then restart any agent session holding \
             an MCP connection",
        ),
    }
}

/// One named row out of the daemon's health report, as `(status, detail)`.
fn named_check<'a>(report: &'a Value, name: &str) -> Option<(&'a str, &'a str)> {
    let check = report
        .get("checks")
        .and_then(Value::as_array)?
        .iter()
        .find(|check| check.get("name").and_then(Value::as_str) == Some(name))?;
    Some((
        check.get("status").and_then(Value::as_str).unwrap_or(""),
        check.get("detail").and_then(Value::as_str).unwrap_or(""),
    ))
}

/// CUSTODY-LADDER: which mechanism holds this box's vault key, and what it does NOT protect.
///
/// The ladder is AUTOMATIC — `cermet setup` takes the strongest rung the box can carry — so this
/// row is where an operator finds out what "automatic" chose here, and it is asked of the RUNNING
/// daemon rather than inferred from files this CLI can see. Every rung is a supported choice, so
/// there is no ✗ and no remedy: the detail is the daemon's own sentence, printed verbatim, for the
/// same reason the git-plane row is (one source of truth for the claim).
fn custody_row(report: Result<&Value, &String>) -> Row {
    let label = "custody";
    let Ok(report) = report else {
        return info(label, "unknown — cermetd is unreachable");
    };
    match named_check(report, label) {
        Some((_, detail)) => pass(label, detail),
        None => info(
            label,
            "cermetd's health report carries no custody row (version skew?)",
        ),
    }
}

/// Is the remote helper on PATH — and if not, is that because the SHELL is older than the install?
///
/// macOS publishes `/opt/cermet/bin` through `/etc/paths.d/cermet`,
/// which `path_helper` reads at LOGIN. In the very shell that ran `sudo cermet setup` nothing is on
/// PATH yet, and a bare ✗ would tell the operator to reinstall a perfectly good install. When the
/// registration is on disk, the honest answer is "open a new shell". Linux publishes into a
/// directory that is already on every PATH, has nothing to register, and keeps the original row.
fn git_helper_row(env: &CheckEnv) -> Row {
    let Some(found) = which(env.path.as_deref(), crate::git_remote::HELPER_PROGRAM) else {
        return match &env.path_registration {
            Some(registration) => gap(
                "git-remote-cermet",
                format!(
                    "not on this shell's PATH, but {} registers it — this shell predates the install",
                    registration.display()
                ),
                "open a new login shell, or `eval $(/usr/libexec/path_helper -s)` in this one",
            ),
            None => gap(
                "git-remote-cermet",
                "not on PATH — git cannot resolve a `cermet::` remote without it",
                "reinstall the pair: `make -C dist install` puts the helper beside `cermet`",
            ),
        };
    };
    pass("git-remote-cermet", found.display().to_string())
}

/// What a previous engine left running or still registered. Read-only, like everything
/// else here: a stale engine is reported with the command that stops it, never stopped.
fn cutover_rows(report: &CutoverReport) -> Vec<Row> {
    let mut rows = Vec::new();
    for process in &report.processes {
        if crate::cutover::is_keyless_client(process) {
            rows.push(gap(
                "stale agent client",
                format!(
                    "pid {} is running {} ({}) — a keyless client on the old binary; authority \
                     stays with the daemon",
                    process.pid,
                    process.exe,
                    process.reason.detail()
                ),
                "restart the agent session that owns it",
            ));
        } else {
            rows.push(gap(
                "stale engine",
                format!(
                    "pid {} is running {} ({}) — it serves its OWN credentials and rules",
                    process.pid,
                    process.exe,
                    process.reason.detail()
                ),
                format!("sudo kill {}", process.pid),
            ));
        }
    }
    for registration in &report.registrations {
        rows.push(gap(
            "stale MCP server",
            format!(
                "{} in {} launches {}",
                registration.name, registration.source, registration.exe
            ),
            "cermet mcp install, then restart the agent session (a live one keeps the old server)",
        ));
    }
    for note in &report.notes {
        rows.push(info("probe", note.clone()));
    }
    if rows.is_empty() {
        rows.push(pass(
            "stale engines",
            "no cermet process or MCP registration from another install",
        ));
    }
    rows
}

/// The git plane's row: whether THIS uid may push, answered by the daemon that decides it.
///
/// Connecting proves nothing: `git.sock` is bound 0666 and the daemon accepts every
/// connection, applying its kernel-attested peercred gate afterwards — so "I connected" would be a
/// green row for a uid whose very next `git push` gets refused, and the daemon's own refusal text
/// points back here. The doctor report carries the verdict (`git_plane` check) built from the same
/// `admitted_uids` the gate calls, personalized to the caller's uid on that ctl connection.
///
/// The detail is printed VERBATIM, as pass text or as the remedy: one source of truth, no
/// second-guessing on this side. An unaskable daemon says exactly that — never a bare ✗, which would
/// read as "you are refused" when the truth is "I could not ask".
fn git_plane_row(report: Result<&Value, &String>) -> Row {
    let label = "git plane";
    let report = match report {
        Ok(report) => report,
        Err(reason) => {
            // Only the headline: the transport's diagnosis (if any) is already the cermetd row's
            // remedy, and a checklist that repeats it per dependent row teaches nothing twice.
            return info(
                label,
                format!("cannot ask cermetd — {}", split_diagnosis(reason).0),
            );
        }
    };
    let (status, detail) = match named_check(report, "git_plane") {
        Some(pair) => pair,
        // A daemon whose report has no git-plane row is one this CLI does not match. Say so rather
        // than infer health from its silence.
        None => {
            return info(
                label,
                "cermetd's health report carries no git-plane check (version skew?)",
            )
        }
    };
    if status == "ok" {
        pass(label, detail)
    } else {
        // No remedy line: the daemon's own detail already names the fix ("run git as one of those
        // users", with the uids), and paraphrasing it here would be the second source of truth this
        // whole row exists to remove.
        Row {
            mark: Mark::Gap,
            label: label.into(),
            detail: detail.into(),
            remedy: None,
        }
    }
}

async fn provider_rows(
    client: Option<&CtlBrokerClient>,
    provider: &str,
    connected: &[CredentialRow],
    env: &CheckEnv,
) -> Vec<Row> {
    let mut rows = Vec::new();
    rows.push(
        match connected.iter().find(|row| row.provider == provider) {
            Some(row) => pass(
                "credential",
                format!(
                    "{} (added {})",
                    row.reference,
                    row.created_at.chars().take(10).collect::<String>()
                ),
            ),
            None => gap(
                "credential",
                "not connected — the broker has no token to spend for this provider",
                format!("cermet connect {provider}"),
            ),
        },
    );

    match provider {
        "github" => rows.extend(repo_wiring(env)),
        "vercel" => {
            rows.push(match which(env.path.as_deref(), "vercel") {
                Some(found) => pass("vercel CLI", found.display().to_string()),
                None => gap(
                    "vercel CLI",
                    // The same sentence printed above a relay invocation: a relay verb hands
                    // back a command the CALLER runs, so the caller's PATH is the one that matters.
                    "'vercel' not found on PATH — a relay invocation will fail as written",
                    "install the Vercel CLI (`npm i -g vercel`), or run the invocation by full path",
                ),
            });
            rows.push(relay_activity(client).await);
        }
        // The pinned version is what every stripe call is made against; it is the thing an operator
        // wants echoed back, and it changes only when we change it.
        "stripe" => rows.push(info(
            "API version",
            format!("pinned to {}", cermet_lang::provider::STRIPE_API_VERSION),
        )),
        _ => {}
    }

    rows.push(rules_mentioning(client, provider).await);
    rows
}

/// Is THIS repository wired? The question is per-repo because the URL is: `git remote -v` is where
/// the answer lives, and where a reset git config makes it disappear.
///
/// An unwired repository is a VALID state, not a finding: the row is
/// informational and carries the one command that wires it — the concrete URL when a github remote
/// is there to derive it from, the placeholder form otherwise (the case a NEW repo starts in).
/// Outside a work tree there is no row at all.
fn repo_wiring(env: &CheckEnv) -> Option<Row> {
    let remotes = wiring::remotes(&env.cwd)?;
    let brokered: Vec<&wiring::Remote> = remotes.iter().filter(|r| r.is_brokered()).collect();
    if !brokered.is_empty() {
        return Some(pass(
            "repo wiring",
            brokered
                .iter()
                .map(|r| format!("{} → {}", r.name, r.url))
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    if wiring::insteadof_configured(&env.cwd) {
        return Some(pass(
            "repo wiring",
            "url.cermet::github/.insteadOf is configured — github URLs are rewritten",
        ));
    }
    Some(
        match remotes.iter().find_map(|r| Some((r, r.brokered_url()?))) {
            Some((remote, brokered_url)) => info(
                "repo wiring",
                format!(
                    "{} → {} is not brokered — wire it with: git remote set-url {} {brokered_url}",
                    remote.name, remote.url, remote.name
                ),
            ),
            None => info(
                "repo wiring",
                format!(
                    "this repository's remotes are not brokered — wire one with: {}",
                    cermet_lang::provider::GIT_WIRING_COMMAND
                ),
            ),
        },
    )
}

/// What the relay has actually done here. The CLI has no accessor for the daemon's configured relay
/// address, so this reports the hop log — evidence, not a guess at a listen address.
async fn relay_activity(client: Option<&CtlBrokerClient>) -> Row {
    let Some(client) = client else {
        return info("relay", "unknown — cermetd is unreachable");
    };
    match client.relay_hops().await {
        Ok(view) => {
            let hops: Vec<Value> = serde_json::from_str(&view).unwrap_or_default();
            match hops
                .first()
                .and_then(|hop| hop.get("at"))
                .and_then(Value::as_str)
            {
                Some(at) => info(
                    "relay",
                    format!("{} hop(s) recorded, last at {at}", hops.len()),
                ),
                None => info("relay", "no relay sessions recorded on this box yet"),
            }
        }
        Err(error) => info("relay", format!("hop log unreadable: {error}")),
    }
}

/// How much standing authority mentions this provider. Informational: a corpus that mentions nothing
/// is a perfectly good corpus, and `rules` is where the answer is edited.
async fn rules_mentioning(client: Option<&CtlBrokerClient>, provider: &str) -> Row {
    let Some(client) = client else {
        return info("standing rules", "unknown — cermetd is unreachable");
    };
    let text = match client.sentence_snapshot().await {
        Ok(cermet_ipc::ctl::SentenceSnapshot::Served { rules_text, .. })
        | Ok(cermet_ipc::ctl::SentenceSnapshot::Unserved { rules_text, .. }) => rules_text,
        Ok(_) => String::new(),
        Err(error) => return info("standing rules", format!("unreadable: {error}")),
    };
    let mentions = text
        .lines()
        .filter(|line| line.contains(&format!("{provider}.")))
        .count();
    info(
        "standing rules",
        format!("{mentions} rule(s) mention {provider} verbs"),
    )
}

fn render(sections: &[(String, Vec<Row>)]) -> CliOutput {
    let mut text = String::new();
    let mut ok = true;
    for (title, rows) in sections {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(title);
        text.push('\n');
        for row in rows {
            let mark = match row.mark {
                Mark::Pass => '✓',
                Mark::Gap => {
                    ok = false;
                    '✗'
                }
                Mark::Info => '·',
            };
            text.push_str(&format!("  {mark} {:<18} {}\n", row.label, row.detail));
            if let Some(remedy) = &row.remedy {
                text.push_str(&format!("      → {remedy}\n"));
            }
        }
    }
    CliOutput {
        text: text.trim_end().to_string(),
        ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cutover::{McpRegistration, StaleProcess, StaleReason};
    use serde_json::json;

    fn env_with(path: Option<OsString>, path_registration: Option<PathBuf>) -> CheckEnv {
        CheckEnv {
            cwd: PathBuf::from("/"),
            path,
            git_sock: PathBuf::from("/nonexistent/git.sock"),
            agent_sock: PathBuf::from("/nonexistent/agent.sock"),
            path_registration,
            cutover: CutoverReport::default(),
            update: crate::update_check::UpdateCheckReport::default(),
        }
    }

    /// The update row: never a ✗ for "software moved", always a ✗ for a mechanism that is broken.
    /// A checklist that goes red because a release exists trains people to ignore red.
    #[test]
    fn the_update_row_reports_state_and_only_faults_on_a_broken_mechanism() {
        use crate::update_check::{UpdateCheckReport, UpdateState};
        let running = crate::update::CURRENT_VERSION;

        // Never run: on, and it says the command that runs it.
        let fresh = update_row(&UpdateCheckReport {
            enabled: true,
            ..Default::default()
        });
        assert!(
            matches!(fresh.mark, Mark::Info),
            "not yet run is not a fault"
        );
        assert!(fresh.detail.contains("--daily-check"), "{}", fresh.detail);

        // Off: said out loud, with the way back. A default-on behavior turned off must be visible.
        let off = update_row(&UpdateCheckReport::default());
        assert!(matches!(off.mark, Mark::Info));
        assert!(off.detail.contains("off"), "{}", off.detail);
        assert!(off.detail.contains("--daily on"), "{}", off.detail);

        // Nothing newer.
        let current = update_row(&UpdateCheckReport {
            enabled: true,
            state: Some(UpdateState {
                checked_at: "2026-08-17T04:17:00Z".to_string(),
                running: running.to_string(),
                ..Default::default()
            }),
            problem: None,
        });
        assert!(matches!(current.mark, Mark::Info));
        assert!(
            current.detail.contains("nothing newer"),
            "{}",
            current.detail
        );
        assert!(
            current.detail.contains("2026-08-17T04:17:00Z"),
            "{}",
            current.detail
        );

        // A security release: the row carries the same escalation the one-line notice does, the
        // verification mode word, and the advisory.
        let urgent = update_row(&UpdateCheckReport {
            enabled: true,
            state: Some(UpdateState {
                checked_at: "2026-08-17T04:17:00Z".to_string(),
                running: running.to_string(),
                available: Some("99.9.9".to_string()),
                security: true,
                notes: Some("https://github.com/suarezc/cermet/releases/tag/v99.9.9".to_string()),
                verification: Some(crate::update::Verification::GithubRelease),
                problem: None,
            }),
            problem: None,
        });
        assert!(
            matches!(urgent.mark, Mark::Info),
            "being a version behind is not a PLUMBING fault"
        );
        assert!(
            urgent.detail.contains("SECURITY UPDATE"),
            "{}",
            urgent.detail
        );
        assert!(
            urgent.detail.contains("github-release"),
            "{}",
            urgent.detail
        );
        assert!(urgent.detail.contains("cermet update"), "{}", urgent.detail);
        assert!(
            urgent
                .detail
                .contains("https://github.com/suarezc/cermet/releases/tag/v99.9.9"),
            "{}",
            urgent.detail
        );

        // A check that did not COMPLETE is said out loud rather than read as "nothing newer":
        // silence is never health.
        let stale = update_row(&UpdateCheckReport {
            enabled: true,
            state: Some(UpdateState {
                checked_at: "2026-08-17T04:17:00Z".to_string(),
                running: running.to_string(),
                problem: Some("the second source could not be reached".to_string()),
                ..Default::default()
            }),
            problem: None,
        });
        assert!(
            stale.detail.contains("did not complete"),
            "{}",
            stale.detail
        );

        // A file the mechanism itself cannot read IS a ✗, with the remedy.
        let broken = update_row(&UpdateCheckReport {
            enabled: true,
            state: None,
            problem: Some("state.json is not a readable update-check state".to_string()),
        });
        assert!(
            matches!(broken.mark, Mark::Gap),
            "a broken mechanism is a gap"
        );
        assert!(broken.remedy.is_some(), "and it carries the remedy");
    }

    #[test]
    fn a_down_daemon_hint_speaks_the_platform_service_manager() {
        // With cermetd stopped, the hint must name the platform's own service manager —
        // a macOS box must never be told `sudo systemctl start cermetd`.
        let rows = plumbing(
            &Err("unreachable".to_string()),
            &Err("cermetd ctl.sock unreachable".to_string()),
            &[],
            &env_with(None, None),
        );
        let remedy = rows[0]
            .remedy
            .clone()
            .expect("a down daemon carries a remedy");
        if cfg!(target_os = "macos") {
            assert!(remedy.contains("launchctl bootstrap"), "{remedy}");
            assert!(!remedy.contains("systemctl"), "{remedy}");
        } else {
            assert!(remedy.contains("systemctl start cermetd"), "{remedy}");
        }
    }

    #[test]
    fn a_missing_helper_on_a_box_that_registered_the_path_hints_a_fresh_shell() {
        // `sudo cermet setup` cannot change the PATH of the shell that ran it.
        let row = git_helper_row(&env_with(
            Some(OsString::from("/nonexistent")),
            Some(PathBuf::from("/etc/paths.d/cermet")),
        ));
        assert!(matches!(row.mark, Mark::Gap));
        assert!(
            row.detail.contains("predates the install"),
            "{}",
            row.detail
        );
        let remedy = row.remedy.unwrap();
        assert!(remedy.contains("new login shell"), "{remedy}");
        assert!(remedy.contains("path_helper"), "{remedy}");
    }

    #[test]
    fn a_missing_helper_with_no_path_registration_still_says_reinstall() {
        let row = git_helper_row(&env_with(Some(OsString::from("/nonexistent")), None));
        assert!(matches!(row.mark, Mark::Gap));
        assert!(row.remedy.unwrap().contains("make -C dist install"));
    }

    /// outside a work tree there is no repository to report on,
    /// and a row saying so is noise on every `check` run from a home directory.
    #[test]
    fn outside_a_git_repository_there_is_no_repo_row() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = env_with(None, None);
        env.cwd = dir.path().to_path_buf();
        assert!(repo_wiring(&env).is_none());
    }

    #[test]
    fn a_box_with_no_stale_engine_says_so_once() {
        let rows = cutover_rows(&CutoverReport::default());
        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0].mark, Mark::Pass));
    }

    #[test]
    fn a_stale_process_and_a_stale_registration_each_carry_their_own_remedy() {
        let rows = cutover_rows(&CutoverReport {
            processes: vec![StaleProcess {
                pid: 51234,
                exe: "/usr/local/bin/cermet-agent".into(),
                role: crate::cutover::ProcessRole::RetiredEngine,
                reason: StaleReason::Deleted,
            }],
            registrations: vec![McpRegistration {
                source: "/Users/dev/.claude.json".into(),
                name: "cermet".into(),
                exe: "/Users/dev/cermet/target/release/cermet".into(),
            }],
            notes: vec!["could not enumerate processes — ps exited 1".into()],
        });
        assert_eq!(rows.len(), 3);
        assert!(matches!(rows[0].mark, Mark::Gap));
        assert_eq!(rows[0].remedy.as_deref(), Some("sudo kill 51234"));
        assert!(matches!(rows[1].mark, Mark::Gap));
        assert!(rows[1]
            .remedy
            .as_deref()
            .unwrap()
            .contains("cermet mcp install"));
        // A probe that could not answer is never rendered as health.
        assert!(matches!(rows[2].mark, Mark::Info));
    }

    /// A keyless-client survivor (a live session's MCP server on the old binary) gets
    /// restart-the-session advice, never a kill line — killing it severs that session's tools.
    #[test]
    fn a_keyless_client_survivor_gets_restart_advice_not_a_kill_line() {
        let rows = cutover_rows(&CutoverReport {
            processes: vec![StaleProcess {
                pid: 675,
                exe: "/usr/local/bin/cermet".into(),
                role: crate::cutover::ProcessRole::KeylessClient,
                reason: StaleReason::Deleted,
            }],
            registrations: vec![],
            notes: vec![],
        });
        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0].mark, Mark::Gap));
        let remedy = rows[0].remedy.as_deref().unwrap();
        assert!(remedy.contains("restart the agent session"), "{remedy}");
        assert!(!remedy.contains("kill"), "{remedy}");
        assert!(
            !rows[0].detail.contains("OWN credentials"),
            "{}",
            rows[0].detail
        );
    }

    fn report(status: &str, detail: &str) -> Value {
        report_with("git_plane", status, detail)
    }

    fn report_with(name: &str, status: &str, detail: &str) -> Value {
        json!({
            "kind": "doctor",
            "serving": true,
            "checks": [
                {"name": "agent.sock", "status": "ok", "detail": "660"},
                {"name": name, "status": status, "detail": detail},
            ]
        })
    }

    #[test]
    fn a_refused_caller_gets_the_daemons_own_words_and_no_invented_remedy() {
        // The daemon's detail already names the fix. A CLI-side paraphrase beside it would
        // be the second source of truth this row exists to remove.
        let detail = "git.sock at /run/cermetd-agents/git.sock; uid 1001 (you): NOT admitted — \
                      the git plane admits agent_uid 994 and approver_uid 1000; run git as one of \
                      those users";
        let row = git_plane_row(Ok(&report("warn", detail)));
        assert!(matches!(row.mark, Mark::Gap));
        assert_eq!(row.detail, detail, "printed verbatim");
        assert!(row.remedy.is_none(), "the detail IS the remedy");
    }

    #[test]
    fn an_admitted_caller_is_green_with_the_uid_that_admitted_them() {
        let row = git_plane_row(Ok(&report(
            "ok",
            "git.sock at /run/cermetd-agents/git.sock; uid 1000 (you): admitted (approver_uid)",
        )));
        assert!(matches!(row.mark, Mark::Pass));
        assert!(row.detail.contains("admitted (approver_uid)"));
    }

    /// A CLI and a daemon from different builds is a plumbing gap like any other — the
    /// row names both and the command that ends the skew. Nothing refuses over it.
    #[test]
    fn the_build_row_names_both_builds_and_flags_only_a_real_skew() {
        let mut same = report("ok", "");
        same["build"] = json!(cermet_ipc::BUILD_ID);
        let row = build_row(Ok(&same));
        assert!(matches!(row.mark, Mark::Pass));
        assert!(row.detail.contains(cermet_ipc::BUILD_ID), "{}", row.detail);

        let mut skewed = report("ok", "");
        skewed["build"] = json!("0.0.1+deadbeef");
        let row = build_row(Ok(&skewed));
        assert!(matches!(row.mark, Mark::Gap));
        assert!(row.detail.contains("0.0.1+deadbeef"), "{}", row.detail);
        assert!(row.detail.contains(cermet_ipc::BUILD_ID), "{}", row.detail);
        assert!(row.remedy.unwrap().contains("make -C dist install"));

        // A daemon predating the stamp is skew too — absence is never read as a match.
        let row = build_row(Ok(&report("ok", "")));
        assert!(matches!(row.mark, Mark::Gap));
        assert!(row.detail.contains("unknown"), "{}", row.detail);

        // And a daemon that could not be asked is neither ✓ nor ✗.
        let row = build_row(Err(&"cermetd ctl.sock unreachable".to_string()));
        assert!(matches!(row.mark, Mark::Info));
        assert!(row.detail.contains(cermet_ipc::BUILD_ID), "{}", row.detail);
    }

    /// CUSTODY-LADDER: `cermet check` reports WHICH custody rung this box's broker is on, in the
    /// daemon's own words — the profile name and the rung's honest limitation, printed verbatim.
    /// The ladder is automatic, so this row is how an operator finds out what automatic chose.
    #[test]
    fn the_custody_row_prints_the_daemons_own_profile_and_limitation() {
        let detail = "file-protected — does not protect vault key from: disk snapshots or backups";
        let row = custody_row(Ok(&report_with("custody", "ok", detail)));
        assert!(matches!(row.mark, Mark::Pass));
        assert_eq!(row.detail, detail, "printed verbatim");
        assert!(row.remedy.is_none(), "every rung is a supported choice");

        // A daemon we could not ask, and one whose report predates the row, are `·` — never a ✓
        // (which would claim custody we did not verify) and never a ✗ (which would read as a fault).
        let unreachable = custody_row(Err(&"cermetd ctl.sock unreachable".to_string()));
        assert!(matches!(unreachable.mark, Mark::Info));
        let skewed = custody_row(Ok(
            &json!({"kind": "doctor", "serving": true, "checks": []}),
        ));
        assert!(matches!(skewed.mark, Mark::Info));
    }

    /// The ctl transport appends a group-membership diagnosis to a permission-denied
    /// connect. The checklist is a TABLE — the diagnosis belongs to the one row it explains, as
    /// that row's remedy, and every other row that merely relays the same error keeps its single
    /// line. Otherwise a multi-line error breaks the columns and repeats itself down the report.
    #[test]
    fn a_diagnosed_connect_failure_becomes_the_cermetd_rows_remedy_and_nothing_elses() {
        let reason =
            "cermetd ctl.sock unreachable at /run/cermetd/ctl.sock: Permission denied (os \
                      error 13)\nsetup added you to cermet-approvers, and group membership loads \
                      at login — log out and back in once,\nor run this one command as:\n    sg \
                      cermet-approvers -c 'cermet check'";
        let rows = plumbing(
            &Err(reason.to_string()),
            &Err(reason.to_string()),
            &[],
            &env_with(None, None),
        );
        let cermetd = &rows[0];
        assert!(
            !cermetd.detail.contains('\n'),
            "the row keeps one line: {:?}",
            cermetd.detail
        );
        assert!(
            cermetd.detail.contains("Permission denied"),
            "and it is still the real error: {:?}",
            cermetd.detail
        );
        let remedy = cermetd.remedy.clone().expect("a gap carries a remedy");
        assert!(
            remedy.contains("setup added you to cermet-approvers")
                && remedy.contains("sg cermet-approvers -c 'cermet check'"),
            "the diagnosis IS the remedy here: {remedy}"
        );
        assert!(
            !remedy.contains("systemctl") && !remedy.contains("launchctl"),
            "starting the daemon is not the fix for a permission wall: {remedy}"
        );
        assert!(
            !remedy.contains('\n'),
            "a remedy is one line in a table: {remedy}"
        );

        let relayed = git_plane_row(Err(&reason.to_string()));
        assert!(
            !relayed.detail.contains('\n') && !relayed.detail.contains("setup added you"),
            "a relaying row does not repeat the diagnosis: {:?}",
            relayed.detail
        );
    }

    #[test]
    fn silence_is_never_read_as_health() {
        // Neither an unreachable daemon nor one whose report lacks the row may render as ✓ or as ✗:
        // "I could not ask" is a different answer from "you are refused".
        let unreachable = git_plane_row(Err(&"cermetd ctl.sock unreachable".to_string()));
        assert!(matches!(unreachable.mark, Mark::Info));
        assert!(unreachable.detail.contains("cannot ask"));

        let skewed = git_plane_row(Ok(
            &json!({"kind": "doctor", "serving": true, "checks": []}),
        ));
        assert!(matches!(skewed.mark, Mark::Info));
        assert!(skewed.detail.contains("no git-plane check"));
    }
}
