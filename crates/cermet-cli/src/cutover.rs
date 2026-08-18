//! Cutover hygiene: what a green install could NOT stop and could NOT repoint.
//!
//! An install can finish green while older `cermet-agent mcp` processes keep running (a process
//! outlives the `unlink` of its own binary) and while an agent client's MCP registration still
//! points at an older build in a dev checkout — which goes on serving that session's tools and can
//! execute a real provider call under the OLD credential store and rule set. No invariant breaks;
//! each engine enforces its own. What is missing is any way to SEE it.
//!
//! So this module only ever REPORTS. It never kills a process, never rewrites a registration, and
//! never fails an install: every probe degrades to a note. These are first-party operator eyes, not
//! a control.

use std::path::{Path, PathBuf};

/// Executable basenames this project has ever published. `git-remote-cermet` belongs here because
/// git resolves a remote helper by NAME on PATH, so a stale copy is as load-bearing as a stale
/// `cermet`.
pub(crate) const CERMET_BINARY_NAMES: &[&str] = &[
    "cermet",
    "cermetd",
    "cermet-agent",
    "cermet-rs",
    "cermet-app",
    "git-remote-cermet",
];

/// Directories an installed cermet binary legitimately runs from: this platform's install prefix,
/// plus the package-managed directory (a `dpkg`-installed daemon runs from `/usr/bin` and is not
/// stale). Both come from `setup` so there is one source of truth for where "installed" is.
pub(crate) const INSTALLED_BIN_DIRS: &[&str] = &[
    crate::setup::INSTALL_BIN_DIR,
    crate::setup::PACKAGED_BIN_DIR,
];

/// One process as the platform reports it.
///
/// ONE-BINARY reclassification: role and staleness are now SEPARATE facts, gathered separately.
/// Under one target `cermetd`, `cermet mcp`, and `git-remote-cermet` all resolve to `.../cermet`,
/// and after an atomic replacement all three read `.../cermet (deleted)`. Deciding the role from
/// that resolved name would file a stale DAEMON — an engine holding the vault open — as a harmless
/// keyless client, which is precisely the survivor an operator most needs named.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunningProcess {
    pub pid: u32,
    /// The executable path the platform resolves for this process. Used for STALENESS only.
    pub exe: String,
    /// The executable's path no longer resolves to a file — it is running code that is off disk.
    pub deleted: bool,
    /// `argv[0]` as the process was launched. Forgeable, and harmless that it is: this decides only
    /// how a REPORT is worded, never what anyone is allowed to do.
    pub argv0: String,
    /// The full launch argv, for the role arguments that no name carries.
    pub argv: Vec<String>,
    /// The `(dev, ino)` of the executable object this process actually mapped, where the platform
    /// can say. This is what makes staleness a fact rather than a guess about names.
    pub identity: Option<(u64, u64)>,
    /// The role the SERVICE MANAGER attributes to this pid — the strongest evidence there is,
    /// because the manager launched it.
    pub manager_role: Option<ProcessRole>,
}

/// What a running cermet process IS. Ordered evidence, per the ONE-BINARY design: the service
/// manager's own pid, then the exact `argv[0]` basename, then exact role arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessRole {
    /// The broker: it holds the vault and serves authority. A stale one is worth stopping.
    Daemon,
    /// A `cermet` CLI, the `cermet mcp` bridge, git's remote helper, or the daemon's hook client.
    /// Authority never lives here: every decision and credentialed hop happens in whatever daemon
    /// is live now, so the remedy is to restart the session that owns it, never a kill line.
    KeylessClient,
    /// An old-architecture engine, from before custody moved into the daemon. Those held their own
    /// credentials, so they keep the kill advice.
    RetiredEngine,
    /// A cermet-named process this build cannot place.
    Unknown,
}

/// Why a running cermet process is not this install's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleReason {
    /// Its executable is a path this build retires.
    Retired,
    /// Its executable has been unlinked — it is running code no longer on disk.
    Deleted,
    /// It is a cermet binary, but not one this install published.
    OutsidePrefix,
    /// It runs a DIFFERENT executable object than the one now published at the install path — the
    /// upgrade landed, this process did not get it.
    SupersededBuild,
}

impl StaleReason {
    pub fn detail(self) -> String {
        match self {
            Self::Retired => "retired artifact".to_string(),
            Self::Deleted => "binary deleted".to_string(),
            Self::OutsidePrefix => format!("outside {}", crate::setup::INSTALL_BIN_DIR),
            Self::SupersededBuild => "superseded by the published binary".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleProcess {
    pub pid: u32,
    pub exe: String,
    pub role: ProcessRole,
    pub reason: StaleReason,
}

/// A cermet MCP server entry found in an agent client's registration, reduced to the one thing that
/// decides staleness: which executable the client will launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRegistration {
    /// Where it was read from, for the operator's benefit.
    pub source: String,
    /// The server name the client registered it under.
    pub name: String,
    /// The resolved cermet executable in the launch argv.
    pub exe: String,
}

/// Everything the cutover probes found. Empty is the healthy answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CutoverReport {
    pub processes: Vec<StaleProcess>,
    pub registrations: Vec<McpRegistration>,
    /// Why a probe could not answer. Never an error: a `ps` that will not run is a note, not a
    /// failed install.
    pub notes: Vec<String>,
}

impl CutoverReport {
    pub fn is_clean(&self) -> bool {
        self.processes.is_empty() && self.registrations.is_empty() && self.notes.is_empty()
    }
}

// ---- Pure classification --------------------------------------------------------------------

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_cermet_binary(exe: &str) -> bool {
    CERMET_BINARY_NAMES.contains(&basename(exe))
}

/// PURE. What this process IS, in the design's evidence order.
///
/// The RESOLVED executable basename is deliberately absent from this ladder: under one binary it is
/// `cermet` for every role, and after a replacement it is `cermet (deleted)` for every role.
pub fn classify_role(process: &RunningProcess, retired: &[&str]) -> ProcessRole {
    // 1. The service manager launched it and says so. Nothing beats that.
    if let Some(role) = process.manager_role {
        return role;
    }
    // A retired PATH is a pre-merge engine regardless of how it was named: those binaries predate
    // the merge, so their own path is still authoritative about what they are.
    if retired.contains(&process.exe.as_str()) {
        return ProcessRole::RetiredEngine;
    }
    // 2. The exact `argv[0]` basename — the name that actually selects the role inside the one
    //    binary's dispatch table.
    let role = match basename(&process.argv0) {
        "cermetd" => Some(ProcessRole::Daemon),
        "cermet" | "git-remote-cermet" => Some(ProcessRole::KeylessClient),
        "cermet-agent" | "cermet-rs" | "cermet-app" => Some(ProcessRole::RetiredEngine),
        _ => None,
    };
    if let Some(role) = role {
        // 3. Exact role arguments, for the one role a name does not carry: the daemon's own
        //    short-lived update-hook client runs under EITHER name and is a keyless client.
        if process.argv.get(1).map(String::as_str) == Some("git-update-hook") {
            return ProcessRole::KeylessClient;
        }
        return role;
    }
    ProcessRole::Unknown
}

/// Is `exe` published by an install, i.e. does it sit directly in one of `installed`?
pub fn is_installed_exe(exe: &str, installed: &[&str]) -> bool {
    Path::new(exe)
        .parent()
        .and_then(Path::to_str)
        .is_some_and(|dir| installed.contains(&dir))
}

/// PURE. Why this process is not this install's, or `None` when it is current.
///
/// Staleness is decided by the executable OBJECT, never by the role: `identity` is the `(dev, ino)`
/// the process actually mapped, and `published` is the object now sitting at the install path. Where
/// a platform cannot report either, the older path/deletion evidence still applies — a partial
/// answer beats a false clean one.
pub fn staleness(
    process: &RunningProcess,
    retired: &[&str],
    installed: &[&str],
    published: Option<(u64, u64)>,
) -> Option<StaleReason> {
    if retired.contains(&process.exe.as_str()) {
        return Some(StaleReason::Retired);
    }
    if !is_cermet_binary(&process.exe) && !is_cermet_binary(&process.argv0) {
        return None;
    }
    if process.deleted {
        return Some(StaleReason::Deleted);
    }
    if !is_installed_exe(&process.exe, installed) {
        return Some(StaleReason::OutsidePrefix);
    }
    match (process.identity, published) {
        (Some(loaded), Some(published)) if loaded != published => {
            Some(StaleReason::SupersededBuild)
        }
        _ => None,
    }
}

/// PURE. Which of `processes` is a cermet process this install does not own, each carrying its role
/// and its (separately decided) reason.
///
/// `self_pid` is never reported: `cermet setup` itself runs from outside the prefix (that is what
/// `make -C dist install` does), so the installer would otherwise name itself first.
pub fn stale_processes(
    processes: &[RunningProcess],
    retired: &[&str],
    installed: &[&str],
    published: Option<(u64, u64)>,
    self_pid: u32,
) -> Vec<StaleProcess> {
    processes
        .iter()
        .filter(|process| process.pid != self_pid)
        .filter_map(|process| {
            let reason = staleness(process, retired, installed, published)?;
            Some(StaleProcess {
                pid: process.pid,
                exe: process.exe.clone(),
                role: classify_role(process, retired),
                reason,
            })
        })
        .collect()
}

/// PURE. A survivor that serves no authority of its own — the `cermet` CLI, the MCP stdio server,
/// git's remote helper, the daemon's hook client.
///
/// 2026-08-09 friction find: after a reinstall, the receipt told the operator to `sudo kill` pids
/// that were LIVE agent sessions' MCP servers on the old unlinked binary; following it severs that
/// session's broker tools. The advice for a keyless client is to restart the owning session, and
/// the kill line must not name it. The role is what decides — under one binary the resolved path is
/// the same for a client and for the daemon holding the vault open.
pub fn is_keyless_client(process: &StaleProcess) -> bool {
    matches!(process.role, ProcessRole::KeylessClient)
}

/// PURE. Parse `ps -axo pid=,comm=` output into (pid, executable path) pairs. Unparseable lines are
/// skipped — this is a best-effort probe, and half an answer beats a refusal.
pub fn parse_ps_lines(text: &str) -> Vec<(u32, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, exe) = line.split_once(char::is_whitespace)?;
            Some((pid.parse().ok()?, exe.trim().to_string()))
        })
        .filter(|(_, exe)| !exe.is_empty())
        .collect()
}

/// PURE. Split a `/proc/<pid>/exe` link target into its path and whether the file is gone. Linux
/// appends `" (deleted)"` to the link target of an unlinked executable, which is exactly the
/// zombie-engine signal — no stat needed.
pub fn parse_proc_exe_link(target: &str) -> (String, bool) {
    match target.strip_suffix(" (deleted)") {
        Some(path) => (path.to_string(), true),
        None => (target.to_string(), false),
    }
}

/// PURE. The cermet executable a launch argv will actually run.
///
/// The installed registration is `sudo -n -u cermet-agent -g cermet-agents /opt/cermet/bin/cermet
/// --socket … mcp`, so this cannot simply take argv[0], and it cannot match on basename alone
/// either — `cermet-agent` appears there as a USER name. Requiring a `/` is what separates the
/// path from the account.
pub fn executable_in_argv(argv: &[String]) -> Option<String> {
    argv.iter()
        .find(|token| token.contains('/') && is_cermet_binary(token))
        .cloned()
}

/// PURE. Every cermet MCP server entry in one registration document, reduced to its executable.
///
/// Covers both shapes we write: Claude Code's `mcpServers` map (`command` string + `args`, at the
/// top level and under each `projects.<dir>`) and OpenCode's `mcp` map (`command` argv array). A
/// document that will not parse yields nothing — never an error.
pub fn registrations_in(source: &str, document: &str) -> Vec<McpRegistration> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(document) else {
        return Vec::new();
    };
    let mut maps: Vec<&serde_json::Value> = Vec::new();
    for key in ["mcpServers", "mcp"] {
        if let Some(map) = root.get(key) {
            maps.push(map);
        }
    }
    if let Some(projects) = root.get("projects").and_then(serde_json::Value::as_object) {
        for project in projects.values() {
            if let Some(map) = project.get("mcpServers") {
                maps.push(map);
            }
        }
    }

    let mut found = Vec::new();
    for map in maps {
        let Some(servers) = map.as_object() else {
            continue;
        };
        for (name, entry) in servers {
            let mut argv: Vec<String> = Vec::new();
            match entry.get("command") {
                Some(serde_json::Value::String(command)) => argv.push(command.clone()),
                Some(serde_json::Value::Array(command)) => argv.extend(
                    command
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string),
                ),
                _ => continue,
            }
            if let Some(args) = entry.get("args").and_then(serde_json::Value::as_array) {
                argv.extend(
                    args.iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string),
                );
            }
            if let Some(exe) = executable_in_argv(&argv) {
                found.push(McpRegistration {
                    source: source.to_string(),
                    name: name.clone(),
                    exe,
                });
            }
        }
    }
    found.sort_by(|a, b| (&a.source, &a.name).cmp(&(&b.source, &b.name)));
    found
}

// ---- Probes ----------------------------------------------------------------------------------

/// The `(dev, ino)` of the executable object now published at the install path — what a running
/// process's mapped object is compared against. `None` when nothing is published there yet, or the
/// platform will not say.
///
/// KNOWN LIMITATION (report-only, and this module only ever reports): it takes the FIRST of
/// `INSTALLED_BIN_DIRS` that exists. On a dpkg-installed box both `/usr/local/bin/cermet` and
/// `/usr/bin/cermet` hold identical bytes at DIFFERENT inodes, so a process legitimately running the
/// `/usr/bin` copy would be reported `SupersededBuild`. Left as a note rather than handled: the
/// installed `ExecStart` and the MCP registration both name the `/usr/local/bin` copy, so nothing
/// this install launches takes that path, and the remedy the report prints (restart it) is harmless
/// if followed anyway.
pub fn published_identity(installed: &[&str]) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    installed
        .iter()
        .map(|dir| Path::new(dir).join(crate::setup::MULTICALL_TARGET))
        .find_map(|path| std::fs::metadata(path).ok())
        .map(|metadata| (metadata.dev(), metadata.ino()))
}

/// PURE. Split a `ps -axo pid=,args=` line into (pid, argv). BSD `ps` prints the full launch argv,
/// whose first element is the program as invoked.
pub fn parse_ps_argv_lines(text: &str) -> Vec<(u32, Vec<String>)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, rest) = line.split_once(char::is_whitespace)?;
            let argv: Vec<String> = rest.split_whitespace().map(str::to_string).collect();
            (!argv.is_empty()).then_some((pid.parse().ok()?, argv))
        })
        .collect()
}

/// Enumerate running processes with their executable paths, launch argv, and mapped identity.
/// Public so the deleted-inode regression fixture can drive the REAL walker over real processes.
///
/// macOS: `ps -axo pid=,comm=` gives the resolved executable path (BSD `ps` prints it in full), and
/// a second `pid=,args=` pass gives the launch argv. There is no portable way to prove WHICH inode a
/// running process mapped, so `identity` stays `None`: the report says "restart required" from the
/// deletion/prefix evidence rather than claiming a false clean result, which is exactly the
/// best-effort contract this module promises.
#[cfg(target_os = "macos")]
pub fn running_processes() -> Result<Vec<RunningProcess>, String> {
    fn ps(format: &str) -> Result<String, String> {
        let output = std::process::Command::new("ps")
            .args(["-axo", format])
            .output()
            .map_err(|error| format!("cannot run ps: {error}"))?;
        if !output.status.success() {
            return Err(format!("ps exited {}", output.status));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
    let argv_by_pid: std::collections::HashMap<u32, Vec<String>> =
        parse_ps_argv_lines(&ps("pid=,args=")?)
            .into_iter()
            .collect();
    let manager = manager_daemon_pid();
    Ok(parse_ps_lines(&ps("pid=,comm=")?)
        .into_iter()
        .map(|(pid, exe)| {
            let argv = argv_by_pid.get(&pid).cloned().unwrap_or_default();
            RunningProcess {
                deleted: !Path::new(&exe).exists(),
                argv0: argv.first().cloned().unwrap_or_else(|| exe.clone()),
                argv,
                identity: None,
                manager_role: (manager == Some(pid)).then_some(ProcessRole::Daemon),
                pid,
                exe,
            }
        })
        .collect())
}

/// Enumerate running processes with their executable paths, launch argv, and mapped identity.
/// Public so the deleted-inode regression fixture can drive the REAL walker over real processes.
///
/// Linux: `readlink /proc/<pid>/exe` is exact and carries the `" (deleted)"` marker for free, and
/// `stat` on that same magic link resolves to the mapped INODE even after the file is unlinked —
/// which is what lets staleness be a fact about the object rather than a guess about the name.
/// `/proc/<pid>/cmdline` supplies the launch argv. An unreadable entry is skipped (a process that
/// exited mid-walk, or one owned by another uid).
#[cfg(not(target_os = "macos"))]
pub fn running_processes() -> Result<Vec<RunningProcess>, String> {
    use std::os::unix::fs::MetadataExt;
    let entries =
        std::fs::read_dir("/proc").map_err(|error| format!("cannot read /proc: {error}"))?;
    let manager = manager_daemon_pid();
    let mut processes = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(target) = std::fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        let (exe, deleted) = parse_proc_exe_link(&target.to_string_lossy());
        let argv = std::fs::read(entry.path().join("cmdline"))
            .map(|bytes| parse_proc_cmdline(&bytes))
            .unwrap_or_default();
        // Follows the MAGIC LINK, not the pathname: this answers "which object is this process
        // running", which stays true after the file it came from is unlinked or replaced.
        let identity = std::fs::metadata(entry.path().join("exe"))
            .ok()
            .map(|metadata| (metadata.dev(), metadata.ino()));
        processes.push(RunningProcess {
            argv0: argv.first().cloned().unwrap_or_else(|| exe.clone()),
            argv,
            identity,
            manager_role: (manager == Some(pid)).then_some(ProcessRole::Daemon),
            pid,
            exe,
            deleted,
        });
    }
    Ok(processes)
}

/// PURE. `/proc/<pid>/cmdline` is NUL-separated with a trailing NUL.
#[cfg(any(not(target_os = "macos"), test))]
pub fn parse_proc_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

/// The pid the SERVICE MANAGER attributes to the daemon, when it will say. Best effort: a manager
/// that is not installed, not running, or holding no job simply yields `None`, and the argv ladder
/// takes over.
#[cfg(not(target_os = "macos"))]
fn manager_daemon_pid() -> Option<u32> {
    let output = std::process::Command::new("systemctl")
        .args(["show", "-p", "MainPID", "--value", "cermetd.service"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid != 0)
}

#[cfg(target_os = "macos")]
fn manager_daemon_pid() -> Option<u32> {
    let output = std::process::Command::new("launchctl")
        .args(["print", "system/dev.cermet.cermetd"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("pid = "))
        .and_then(|pid| pid.trim().parse::<u32>().ok())
}

/// Every registration document that can decide which cermet an agent client launches HERE: the two
/// home-rooted global configs, plus each `.mcp.json` on the working directory's ancestry.
///
/// Claude Code keeps its user- and project-scoped servers in `~/.claude.json`; OpenCode uses its own
/// global config. Project-local `.mcp.json` files count too: a stale one high on the ancestry
/// registers a retired engine for every project beneath it, and skipping them makes `check` report
/// `stale engines ✓` over the top of it. They ARE enumerable for the case that matters — the client
/// resolves one by walking UP from cwd, so the scan walks the same ancestry. What remains uncovered,
/// deliberately: a `.mcp.json` in some other checkout you are not standing in. `check` answers for
/// where you are, not for every path on the box.
fn registration_files(home: Option<&Path>, cwd: Option<&Path>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(home) = home {
        files.push(home.join(".claude.json"));
        files.push(crate::mcp::opencode_config_path(home));
    }
    if let Some(cwd) = cwd {
        files.extend(
            cwd.ancestors()
                .map(|dir| dir.join(".mcp.json"))
                .filter(|path| path.is_file()),
        );
    }
    files
}

/// Read each registration document and keep only the servers that would launch a cermet from
/// outside an install prefix. Missing/unreadable/unparseable files add nothing.
fn stale_registrations(files: &[PathBuf]) -> Vec<McpRegistration> {
    let mut found = Vec::new();
    for file in files {
        let Ok(document) = std::fs::read_to_string(file) else {
            continue;
        };
        found.extend(
            registrations_in(&file.display().to_string(), &document)
                .into_iter()
                .filter(|reg| !is_installed_exe(&reg.exe, INSTALLED_BIN_DIRS)),
        );
    }
    found
}

/// The platform's declarative PATH registration for the install prefix, when one is installed.
///
/// macOS publishes `/etc/paths.d/cermet`, which `path_helper` reads at LOGIN — so a shell that
/// predates the install has no `cermet` on PATH and deserves a hint, not a bare ✗.
/// Linux publishes into a directory that is already on every PATH: nothing to register, nothing to
/// hint.
#[cfg(target_os = "macos")]
pub fn path_registration() -> Option<PathBuf> {
    let file = PathBuf::from(crate::setup::PATHS_D_DEST);
    file.exists().then_some(file)
}

#[cfg(not(target_os = "macos"))]
pub fn path_registration() -> Option<PathBuf> {
    None
}

/// Run both probes. Best effort by construction: every failure becomes a note, and the caller can
/// always render something.
pub fn detect(home: Option<&Path>) -> CutoverReport {
    let mut report = CutoverReport::default();
    let retired = crate::setup::retired_artifacts();
    match running_processes() {
        Ok(processes) => {
            report.processes = stale_processes(
                &processes,
                &retired,
                INSTALLED_BIN_DIRS,
                published_identity(INSTALLED_BIN_DIRS),
                std::process::id(),
            );
        }
        Err(reason) => report
            .notes
            .push(format!("could not enumerate processes — {reason}")),
    }
    if home.is_none() {
        report.notes.push(
            "could not resolve the operator's home directory — MCP registrations unchecked".into(),
        );
    }
    let cwd = std::env::current_dir().ok();
    if cwd.is_none() {
        report.notes.push(
            "could not resolve the working directory — project-scoped .mcp.json unchecked".into(),
        );
    }
    report.registrations = stale_registrations(&registration_files(home, cwd.as_deref()));
    report
}

// ---- Rendering ---------------------------------------------------------------------------------

/// The cutover block for `cermet setup`'s next-step receipt, or `None` when there is nothing to say.
/// Each line is already prefixed the way the rest of the receipt is.
pub fn setup_receipt_lines(report: &CutoverReport) -> Option<String> {
    if report.is_clean() {
        return None;
    }
    let mut lines: Vec<String> = Vec::new();
    let (clients, engines): (Vec<&StaleProcess>, Vec<&StaleProcess>) = report
        .processes
        .iter()
        .partition(|process| is_keyless_client(process));
    if !engines.is_empty() {
        lines.push(format!(
            "cutover: {} stale engine(s) survived this install — a process outlives the",
            engines.len()
        ));
        lines
            .push("         unlink of its own binary, and keeps serving its OWN authority:".into());
        for process in &engines {
            lines.push(format!(
                "           pid {}  {}  ({})",
                process.pid,
                process.exe,
                process.reason.detail()
            ));
        }
        lines.push(format!(
            "         stop them:  sudo kill {}",
            engines
                .iter()
                .map(|p| p.pid.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }
    if !clients.is_empty() {
        lines.push(format!(
            "cutover: {} agent client(s) survived this install on the old binary; authority",
            clients.len()
        ));
        lines.push(
            "         stays with the daemon — a live agent session keeps its MCP server until it"
                .into(),
        );
        lines.push("         reconnects:".into());
        for process in &clients {
            lines.push(format!(
                "           pid {}  {}  ({})",
                process.pid,
                process.exe,
                process.reason.detail()
            ));
        }
        lines.push(
            "         restart those agent sessions (kill one only if no session owns it)".into(),
        );
    }
    if !report.registrations.is_empty() {
        lines.push(format!(
            "cutover: {} MCP registration(s) launch a cermet outside {}:",
            report.registrations.len(),
            crate::setup::INSTALL_BIN_DIR
        ));
        for registration in &report.registrations {
            lines.push(format!(
                "           {}  {}  ({})",
                registration.name, registration.exe, registration.source
            ));
        }
        lines.push("         repoint:  cermet mcp install".into());
        lines.push(
            "         then restart the agent session — a live one keeps the old server until it \
             reconnects"
                .into(),
        );
    }
    for note in &report.notes {
        lines.push(format!("cutover: {note}"));
    }
    Some(
        lines
            .into_iter()
            .map(|line| format!("[cermet-setup] {line}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTALLED: &[&str] = &["/opt/cermet/bin", "/usr/bin"];
    const RETIRED: &[&str] = &["/usr/local/bin/cermet-agent", "/usr/local/bin/cermetd"];

    /// A live process launched as `argv0` from `exe`, mapping the published object.
    fn live(pid: u32, exe: &str, argv0: &str) -> RunningProcess {
        RunningProcess {
            pid,
            exe: exe.into(),
            deleted: false,
            argv0: argv0.into(),
            argv: vec![argv0.into()],
            identity: Some(PUBLISHED),
            manager_role: None,
        }
    }

    /// The object now published at the install path.
    const PUBLISHED: (u64, u64) = (66, 4242);

    #[test]
    fn ps_output_yields_the_pid_and_the_full_executable_path() {
        // Verbatim `ps -axo pid=,comm=` on macOS: right-aligned pids, full paths in `comm`.
        let text = "    1 /sbin/launchd\n72997 /opt/cermet/bin/cermetd\n\
                    44292 /Users/dev/cermet/target/release/cermet\n\nnot-a-pid line\n";
        assert_eq!(
            parse_ps_lines(text),
            vec![
                (1, "/sbin/launchd".to_string()),
                (72997, "/opt/cermet/bin/cermetd".to_string()),
                (44292, "/Users/dev/cermet/target/release/cermet".to_string()),
            ]
        );
    }

    #[test]
    fn the_launch_argv_is_recovered_from_both_platforms_shapes() {
        // Linux: NUL-separated with a trailing NUL. macOS: `ps -axo pid=,args=`.
        assert_eq!(
            parse_proc_cmdline(b"/usr/local/bin/cermetd\0"),
            vec!["/usr/local/bin/cermetd".to_string()]
        );
        assert_eq!(
            parse_proc_cmdline(b"/usr/local/bin/cermet\0--socket\0/run/a.sock\0mcp\0"),
            vec![
                "/usr/local/bin/cermet".to_string(),
                "--socket".to_string(),
                "/run/a.sock".to_string(),
                "mcp".to_string(),
            ]
        );
        assert_eq!(parse_proc_cmdline(b""), Vec::<String>::new());
        assert_eq!(
            parse_ps_argv_lines("  501 /opt/cermet/bin/cermet --socket /a.sock mcp\n bad line\n"),
            vec![(
                501,
                vec![
                    "/opt/cermet/bin/cermet".to_string(),
                    "--socket".to_string(),
                    "/a.sock".to_string(),
                    "mcp".to_string(),
                ]
            )]
        );
    }

    #[test]
    fn a_proc_exe_link_marked_deleted_is_read_as_deleted() {
        assert_eq!(
            parse_proc_exe_link("/usr/local/bin/cermet-agent (deleted)"),
            ("/usr/local/bin/cermet-agent".to_string(), true)
        );
        assert_eq!(
            parse_proc_exe_link("/usr/bin/cermetd"),
            ("/usr/bin/cermetd".to_string(), false)
        );
    }

    /// THE ONE-BINARY REGRESSION, at the classification layer.
    ///
    /// After an atomic replacement of the one target, a stale daemon and a stale MCP bridge BOTH
    /// have `/proc/<pid>/exe` reading `.../cermet (deleted)`. Role must come from the service
    /// manager's pid and from `argv[0]`; taking it from the resolved basename would file the daemon
    /// — the process holding the vault open — as a harmless keyless client.
    #[test]
    fn a_stale_daemon_and_a_stale_bridge_that_both_resolve_to_cermet_are_told_apart() {
        let deleted =
            |pid: u32, argv0: &str, argv: Vec<&str>, manager: Option<ProcessRole>| RunningProcess {
                pid,
                exe: "/usr/bin/cermet".into(),
                deleted: true,
                argv0: argv0.into(),
                argv: argv.into_iter().map(str::to_string).collect(),
                identity: Some((66, 111)),
                manager_role: manager,
            };
        let processes = vec![
            // Launched by systemd through the `cermetd` alias.
            deleted(
                101,
                "/usr/bin/cermetd",
                vec!["/usr/bin/cermetd"],
                Some(ProcessRole::Daemon),
            ),
            // A live agent session's MCP bridge, same resolved path, same deleted marker.
            deleted(
                202,
                "/usr/bin/cermet",
                vec!["/usr/bin/cermet", "--socket", "/run/a.sock", "mcp"],
                None,
            ),
        ];
        let found = stale_processes(&processes, RETIRED, INSTALLED, Some(PUBLISHED), 1);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].role, ProcessRole::Daemon, "{found:?}");
        assert_eq!(found[1].role, ProcessRole::KeylessClient, "{found:?}");
        assert!(!is_keyless_client(&found[0]), "the daemon is an ENGINE");
        assert!(is_keyless_client(&found[1]));
        assert!(found.iter().all(|p| p.reason == StaleReason::Deleted));

        // Without the manager's answer, `argv[0]` alone still separates them.
        let mut argv_only = processes.clone();
        argv_only[0].manager_role = None;
        let found = stale_processes(&argv_only, RETIRED, INSTALLED, Some(PUBLISHED), 1);
        assert_eq!(found[0].role, ProcessRole::Daemon, "{found:?}");
        assert_eq!(found[1].role, ProcessRole::KeylessClient, "{found:?}");
    }

    #[test]
    fn the_daemons_own_hook_client_is_a_keyless_client_under_either_name() {
        // `<program> git-update-hook <ref> <old> <new>` is a short-lived CLIENT of the daemon that
        // runs under whichever name the daemon's own program path carried. Role ARGUMENTS decide.
        for argv0 in ["/usr/bin/cermet", "/usr/bin/cermetd"] {
            let hook = RunningProcess {
                pid: 7,
                exe: "/usr/bin/cermet".into(),
                deleted: true,
                argv0: argv0.into(),
                argv: vec![
                    argv0.into(),
                    "git-update-hook".into(),
                    "refs/heads/main".into(),
                    "aaa".into(),
                    "bbb".into(),
                ],
                identity: Some((66, 111)),
                manager_role: None,
            };
            assert_eq!(classify_role(&hook, RETIRED), ProcessRole::KeylessClient);
        }
    }

    #[test]
    fn a_process_running_a_superseded_object_at_the_current_path_is_reported() {
        // The upgrade case one atomic rename cannot fix: the path is right, the file is not
        // deleted (a new one took its place), but this process mapped the OLD object.
        let mut superseded = live(31337, "/usr/bin/cermet", "/usr/bin/cermetd");
        superseded.identity = Some((66, 4241));
        superseded.manager_role = Some(ProcessRole::Daemon);
        let found = stale_processes(&[superseded], RETIRED, INSTALLED, Some(PUBLISHED), 1);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].reason, StaleReason::SupersededBuild);
        assert_eq!(found[0].role, ProcessRole::Daemon);
    }

    #[test]
    fn an_unknowable_identity_never_manufactures_staleness() {
        // macOS cannot prove the mapped inode. An absent answer is not evidence of skew: the
        // report falls back to deletion/prefix evidence rather than claiming a false positive.
        let mut unknown = live(5, "/usr/bin/cermet", "/usr/bin/cermet");
        unknown.identity = None;
        assert_eq!(
            stale_processes(&[unknown], RETIRED, INSTALLED, Some(PUBLISHED), 1),
            vec![]
        );
        // And an install that has published nothing yet cannot compare either.
        let current = live(6, "/usr/bin/cermet", "/usr/bin/cermet");
        assert_eq!(
            stale_processes(&[current], RETIRED, INSTALLED, None, 1),
            vec![]
        );
    }

    #[test]
    fn a_retired_artifact_still_running_is_reported() {
        let found = stale_processes(
            &[live(
                9,
                "/usr/local/bin/cermet-agent",
                "/usr/local/bin/cermet-agent",
            )],
            RETIRED,
            INSTALLED,
            Some(PUBLISHED),
            1,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, StaleReason::Retired);
        assert_eq!(found[0].role, ProcessRole::RetiredEngine);
        assert_eq!(found[0].pid, 9);
    }

    #[test]
    fn a_cermet_running_from_an_unlinked_binary_is_reported() {
        // The July zombies: the install deleted the file, the process kept going.
        let mut gone = live(51234, "/opt/cermet/bin/cermet", "/opt/cermet/bin/cermet");
        gone.deleted = true;
        let found = stale_processes(&[gone], RETIRED, INSTALLED, Some(PUBLISHED), 1);
        assert_eq!(found.len(), 1, "deleted beats being inside the prefix");
        assert_eq!(found[0].reason, StaleReason::Deleted);
    }

    #[test]
    fn a_cermet_outside_the_install_prefix_is_reported() {
        let found = stale_processes(
            &[live(
                44292,
                "/Users/dev/cermet/target/release/cermet",
                "/Users/dev/cermet/target/release/cermet",
            )],
            RETIRED,
            INSTALLED,
            Some(PUBLISHED),
            1,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].reason, StaleReason::OutsidePrefix);
    }

    #[test]
    fn installed_engines_the_installer_itself_and_strangers_are_never_reported() {
        let processes = vec![
            live(1, "/opt/cermet/bin/cermet", "/opt/cermet/bin/cermetd"),
            live(2, "/usr/bin/cermet", "/usr/bin/cermetd"),
            live(3, "/sbin/launchd", "/sbin/launchd"),
            // this is `cermet setup` itself
            live(
                4,
                "/Users/dev/cermet/target/release/cermet",
                "/Users/dev/cermet/target/release/cermet",
            ),
        ];
        assert_eq!(
            stale_processes(&processes, RETIRED, INSTALLED, Some(PUBLISHED), 4),
            vec![]
        );
    }

    #[test]
    fn a_claude_registration_into_a_dev_checkout_resolves_that_executable() {
        // A stale registration: an older build in a dev checkout, project-scoped.
        let document = r#"{
          "projects": {
            "/Users/dev/cermet": {
              "mcpServers": {
                "cermet": {
                  "command": "/Users/dev/cermet/target/release/cermet",
                  "args": ["mcp"],
                  "env": {"CERMET_AGENT_SOCK": "/tmp/agent.sock"}
                }
              }
            }
          }
        }"#;
        let found = registrations_in("~/.claude.json", document);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "cermet");
        assert_eq!(found[0].exe, "/Users/dev/cermet/target/release/cermet");
        assert!(!is_installed_exe(&found[0].exe, INSTALLED));
    }

    #[test]
    fn the_installed_sudo_launch_resolves_the_binary_not_the_account_name() {
        // `-u cermet-agent` is a USER whose name is also a published binary name. Taking argv[0]
        // would find `sudo`; matching on basename alone would find the account.
        let document = r#"{"mcpServers": {"cermet": {"command": "sudo", "args": [
          "-n", "-u", "cermet-agent", "-g", "cermet-agents",
          "/opt/cermet/bin/cermet", "--socket", "/var/cermetd-agents/agent.sock", "mcp"]}}}"#;
        let found = registrations_in("~/.claude.json", document);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].exe, "/opt/cermet/bin/cermet");
        assert!(
            is_installed_exe(&found[0].exe, INSTALLED),
            "the installed registration is not stale"
        );
    }

    #[test]
    fn an_opencode_command_array_registration_resolves_its_executable() {
        let document = r#"{"$schema": "x", "mcp": {"cermet": {"type": "local",
          "command": ["/opt/cermet/bin/cermet", "mcp"], "enabled": true}}}"#;
        let found = registrations_in("opencode.json", document);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].exe, "/opt/cermet/bin/cermet");
    }

    #[test]
    fn unreadable_or_foreign_registrations_yield_nothing_rather_than_an_error() {
        assert_eq!(registrations_in("x", "{not json"), vec![]);
        assert_eq!(registrations_in("x", "[]"), vec![]);
        assert_eq!(
            registrations_in(
                "x",
                r#"{"mcpServers": {"github": {"command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-github"]}}}"#
            ),
            vec![],
            "a non-cermet server is not our business"
        );
    }

    /// A `.mcp.json` high on the ancestry registers a retired engine for every project beneath it,
    /// so a scan that reads only the two home-rooted configs reports `stale engines ✓` over the top
    /// of it. The client resolves one by walking up from cwd, so the scan walks the same ancestry
    /// and reduces each hit exactly like the home configs.
    #[test]
    fn an_ancestor_mcp_json_launching_a_cermet_from_elsewhere_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let deep = root.join("projects/widgets/crates");
        std::fs::create_dir_all(&deep).unwrap();

        // Two ancestors: one stale (a retired engine from an older install), one installed.
        std::fs::write(
            root.join(".mcp.json"),
            r#"{"mcpServers": {"cermet": {"command": "/Users/you/dev/python/.venv/bin/cermet",
              "args": ["mcp"]}}}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("projects/.mcp.json"),
            format!(
                r#"{{"mcpServers": {{"cermet": {{"command": "sudo",
              "args": ["-n", "-u", "cermet-agent", "{}/cermet", "mcp"]}}}}}}"#,
                crate::setup::INSTALL_BIN_DIR
            ),
        )
        .unwrap();

        let files = registration_files(None, Some(&deep));
        assert!(
            files.contains(&root.join(".mcp.json"))
                && files.contains(&root.join("projects/.mcp.json")),
            "both ancestor documents apply to {}: {files:?}",
            deep.display()
        );

        let found = stale_registrations(&files);
        assert_eq!(found.len(), 1, "exactly the out-of-prefix one: {found:?}");
        assert_eq!(found[0].exe, "/Users/you/dev/python/.venv/bin/cermet");
        assert!(
            found[0].source.ends_with(".mcp.json"),
            "the operator is told which document to fix: {}",
            found[0].source
        );
    }

    #[test]
    fn the_home_configs_and_the_cwd_ancestry_are_both_scanned_and_neither_is_required() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let deep = temp.path().join("home/work/repo");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join(".mcp.json"), "{}").unwrap();

        let both = registration_files(Some(&home), Some(&deep));
        assert!(both.contains(&home.join(".claude.json")));
        assert!(both.contains(&deep.join(".mcp.json")));

        // A missing home is not a missing ancestry scan, and vice versa.
        assert!(registration_files(None, Some(&deep)).contains(&deep.join(".mcp.json")));
        assert!(registration_files(Some(&home), None).contains(&home.join(".claude.json")));

        // Nothing on the ancestry: an empty answer, never an error.
        let bare = temp.path().join("elsewhere/a/b");
        std::fs::create_dir_all(&bare).unwrap();
        assert_eq!(
            stale_registrations(&registration_files(None, Some(&bare))),
            vec![]
        );
    }

    #[test]
    fn a_clean_box_renders_no_cutover_block() {
        assert_eq!(setup_receipt_lines(&CutoverReport::default()), None);
    }

    #[test]
    fn the_receipt_names_every_pid_the_kill_command_and_the_repoint_pair() {
        let report = CutoverReport {
            processes: vec![
                StaleProcess {
                    pid: 51234,
                    exe: "/usr/local/bin/cermet-agent".into(),
                    role: ProcessRole::RetiredEngine,
                    reason: StaleReason::Deleted,
                },
                StaleProcess {
                    pid: 51240,
                    exe: "/usr/local/bin/cermet-agent".into(),
                    role: ProcessRole::RetiredEngine,
                    reason: StaleReason::Retired,
                },
            ],
            registrations: vec![McpRegistration {
                source: "/Users/dev/.claude.json".into(),
                name: "cermet".into(),
                exe: "/Users/dev/cermet/target/release/cermet".into(),
            }],
            notes: vec![],
        };
        let text = setup_receipt_lines(&report).expect("a dirty box renders a block");
        assert!(text.contains("pid 51234"), "{text}");
        assert!(text.contains("pid 51240"), "{text}");
        assert!(text.contains("sudo kill 51234 51240"), "{text}");
        assert!(text.contains("cermet mcp install"), "{text}");
        assert!(text.contains("restart the agent session"), "{text}");
        assert!(
            text.lines().all(|line| line.starts_with("[cermet-setup] ")),
            "every line carries the receipt prefix:\n{text}"
        );
    }

    /// After a reinstall, a naive receipt says `sudo kill` for pids that are LIVE agent sessions'
    /// MCP servers on the old unlinked binary — following that severs the session's broker tools.
    /// A keyless client serves no authority of its own; the advice for it is to restart the owning
    /// session, and the kill line must not name it.
    #[test]
    fn a_surviving_keyless_client_is_told_to_restart_its_session_not_be_killed() {
        let report = CutoverReport {
            processes: vec![
                StaleProcess {
                    pid: 675,
                    exe: "/usr/local/bin/cermet".into(),
                    role: ProcessRole::KeylessClient,
                    reason: StaleReason::Deleted,
                },
                StaleProcess {
                    pid: 3104222,
                    exe: "/usr/local/bin/cermet".into(),
                    role: ProcessRole::Daemon,
                    reason: StaleReason::Deleted,
                },
            ],
            registrations: vec![],
            notes: vec![],
        };
        let text = setup_receipt_lines(&report).expect("a dirty box renders a block");
        assert!(text.contains("pid 675"), "{text}");
        assert!(text.contains("pid 3104222"), "{text}");
        assert!(text.contains("sudo kill 3104222"), "{text}");
        assert!(
            !text.contains("kill 675"),
            "no kill advice for the keyless client:\n{text}"
        );
        assert!(text.contains("restart those agent sessions"), "{text}");
        assert!(
            !text.contains("OWN authority") || text.contains("sudo kill 3104222"),
            "the authority claim belongs to engines only:\n{text}"
        );
    }

    #[test]
    fn a_client_only_survivor_set_renders_no_kill_line_at_all() {
        let report = CutoverReport {
            processes: vec![StaleProcess {
                pid: 675,
                exe: "/usr/local/bin/cermet".into(),
                role: ProcessRole::KeylessClient,
                reason: StaleReason::OutsidePrefix,
            }],
            registrations: vec![],
            notes: vec![],
        };
        let text = setup_receipt_lines(&report).expect("a dirty box renders a block");
        assert!(!text.contains("sudo kill"), "{text}");
        assert!(text.contains("restart those agent sessions"), "{text}");
    }

    #[test]
    fn a_probe_that_could_not_answer_says_so_instead_of_going_quiet() {
        let report = CutoverReport {
            notes: vec!["could not enumerate processes — ps exited 1".into()],
            ..CutoverReport::default()
        };
        let text = setup_receipt_lines(&report).expect("a note is still worth printing");
        assert!(text.contains("could not enumerate processes"), "{text}");
    }
}
