//! `cermetd` — the daemon role entry (the startup spine that assembles the locked-decision pieces:
//! the setgid runtime dir, explicit service mode + kernel-uid asserts, live approver-deny, and
//! service key custody).
//!
//! ONE-BINARY: this is a library entry module, not a `[[bin]]`. The workspace ships a single
//! executable (`crates/cermet-bin`) whose closed dispatch table selects this role from the exact
//! `cermetd` basename — the root-owned alias the service manager launches. The router owns role
//! selection; [`run`] is the synchronous wrapper that builds the multithread runtime and drives the
//! async body, so the router itself owns no runtime.

use std::path::PathBuf;
use std::process::ExitCode;

use cermet_core::BrokerConfig;

use crate::{
    config, ctl, doctor, lock, log, master_key, runtime, sentence_record, serve, startup, supervise,
};

// Ratified action templates ARE authority (they define new executable actions), so `actions.d/`
// gets the same hardened-read posture as `policy.yaml`: each `*.yaml` is read through the hardened
// owner-checked reader; an ABSENT dir means no templates (fail closed to less authority), but a
// PRESENT dir with any unreadable/foreign/symlinked/non-UTF-8 file REFUSES BOOT rather than
// loading it or silently skipping it. Filenames are sorted for a deterministic load order.
fn resolve_action_templates(home: &std::path::Path) -> Result<Vec<String>, String> {
    let dir = home.join("actions.d");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(format!(
                "cannot read the actions.d dir at {} (refusing, fail-closed): {e}",
                dir.display()
            ))
        }
    };
    let mut names: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            format!(
                "cannot enumerate the actions.d dir at {} (refusing, fail-closed): {e}",
                dir.display()
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            names.push(path);
        }
    }
    names.sort();
    let mut docs = Vec::with_capacity(names.len());
    for path in names {
        let bytes = cermet_broker_actor::host_lock::read_authority_file(&path).map_err(|e| {
            format!(
                "action template at {} is not a regular owner-owned file (refusing, fail-closed): {e}",
                path.display()
            )
        })?;
        let doc = String::from_utf8(bytes).map_err(|_| {
            format!(
                "action template at {} is not valid UTF-8 — refusing",
                path.display()
            )
        })?;
        docs.push(doc);
    }
    Ok(docs)
}

// Ratified provider descriptors ARE authority (a descriptor is the ONLY way a token may ride to an
// origin, and it defines a provider the language can extend), so `providers.d/` gets the same
// hardened-read posture as `actions.d/`: each `*.yaml` is read through the hardened owner-checked
// reader; an ABSENT dir means no providers (fail closed — every real request DENIES at the
// registry wall), but a PRESENT dir with any unreadable/foreign/symlinked/non-UTF-8 file REFUSES
// BOOT. Sorted for a deterministic load order.
fn resolve_provider_descriptors(home: &std::path::Path) -> Result<Vec<String>, String> {
    let dir = home.join("providers.d");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(format!(
                "cannot read the providers.d dir at {} (refusing, fail-closed): {e}",
                dir.display()
            ))
        }
    };
    let mut names: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            format!(
                "cannot enumerate the providers.d dir at {} (refusing, fail-closed): {e}",
                dir.display()
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            names.push(path);
        }
    }
    names.sort();
    let mut docs = Vec::with_capacity(names.len());
    for path in names {
        let bytes = cermet_broker_actor::host_lock::read_authority_file(&path).map_err(|e| {
            format!(
                "provider descriptor at {} is not a regular owner-owned file (refusing, fail-closed): {e}",
                path.display()
            )
        })?;
        let doc = String::from_utf8(bytes).map_err(|_| {
            format!(
                "provider descriptor at {} is not valid UTF-8 — refusing",
                path.display()
            )
        })?;
        docs.push(doc);
    }
    Ok(docs)
}

// Key custody (CUSTODY-LADDER): service mode reads ONLY the source the DECLARED custody rung
// names (fail-closed); dev/test uses the fenced CERMET_UNSAFE_DEV_MASTER_KEY override then the
// login keychain. `service_mode` is threaded so a dev process can never read a service key and
// service mode never falls back to the login keychain; `custody` is threaded so the source follows
// the config rather than the platform.
fn load_master_key(
    home: &std::path::Path,
    service_mode: bool,
    custody: Option<cermet_ipc::custody::CustodyProfile>,
) -> Result<Vec<u8>, String> {
    master_key::load_with_mode(home, service_mode, custody)
}

/// The secret-bearing inodes under `CERMET_HOME` that must be `0600`-owned before the broker opens:
/// the `file-protected` rung's service `master.key` (absent on the sealed rungs and in dev →
/// skipped) plus the three DBs and their sqlite `-wal`/`-shm` sidecars, which also carry secret
/// pages.
const HARDENED_INODES: [&str; 10] = [
    "master.key",
    "vault.db",
    "state.db",
    "audit.db",
    "vault.db-wal",
    "state.db-wal",
    "audit.db-wal",
    "vault.db-shm",
    "state.db-shm",
    "audit.db-shm",
];

/// Retighten any pre-existing key/DB inode to `0600` (fresh ones are `0600` from the startup umask),
/// and REFUSE a symlink at any of these paths.
///
/// `harden_file_0600` is `O_NOFOLLOW`, so it already rejects a *non-dangling* symlink — but the old
/// inline loop gated it on `Path::exists()`, which FOLLOWS symlinks and so returns `false` for a
/// *dangling* symlink. A dangling `vault.db` symlink was therefore skipped here, then FOLLOWED by
/// rusqlite when the broker created the DB — planting it outside the hardened `0700` home. Stat
/// without following (`symlink_metadata`) and fail closed on any symlink, dangling or not; an absent
/// inode is fine (created under the umask); a present regular file is hardened.
fn harden_secret_inodes(home: &std::path::Path) -> Result<(), String> {
    for name in HARDENED_INODES {
        let p = home.join(name);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!(
                    "{} is a symlink — refusing (a planted symlink would redirect the file outside the 0700 home)",
                    p.display()
                ));
            }
            Ok(_) => cermet_broker_actor::host_lock::harden_file_0600(&p)
                .map_err(|e| format!("cannot harden {} to 0600: {e}", p.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot stat {}: {e}", p.display())),
        }
    }
    Ok(())
}

/// Resolve the single uid admitted to the `agent.sock` peercred gate.
///
/// In SERVICE mode ONLY the distinct configured agent uid is admitted — NOT the approver uid (it is
/// deliberately kernel-DENIED the agent plane) and NOT the daemon's own uid. In dev/embedded mode the
/// admitted uid is the daemon's own uid (the same-uid path). Always `Some(_)`: an unresolved gate
/// (`None`) admits no one, so the caller passes a resolved uid and the gate fails closed only on a
/// genuine misconfiguration.
///
/// Pure + unit-pinned: a regression to the old `Some(approver_uid)` wiring — or to
/// `Some(dev_uid)` in service mode — fails `resolves_agent_gate_to_agent_uid_in_service` by name. The
/// full end-to-end proof (real daemon accept path, real peer uid) is a live rehearsal.
fn resolve_agent_gate_uid(service_mode: bool, agent_uid: u32, dev_uid: u32) -> Option<u32> {
    if service_mode {
        Some(agent_uid)
    } else {
        Some(dev_uid)
    }
}

/// `cermetd --help` / `-h` / `help`. Answerable before ANY daemon machinery (home lock, keychain,
/// vault): a curious operator's first `cermetd --help` on a box with no secrets service must print
/// usage, never a keychain error. cermetd deliberately has no other flags — it is launched by the
/// service manager, and the operator surface is `cermet`.
pub fn help_text() -> String {
    format!(
        "cermetd {} — the Cermet daemon (broker core, vault custody, receipts)\n\
         \n\
         cermetd takes no flags or subcommands; it is run by the service manager, which\n\
         `sudo cermet setup` installs, enables, and starts (systemd on Linux, launchd on macOS).\n\
         \n\
         `cermetd` is a root-owned symlink to the one shipped `cermet` executable; the name\n\
         is how the service manager (and this binary's dispatch table) name the daemon role.\n\
         \n\
         The operator surface is the `cermet` CLI: try `cermet --help` or\n\
         `cermet check` against a running daemon. Docs: https://cermet.dev/quickstart.html",
        env!("CARGO_PKG_VERSION")
    )
}

/// `cermetd --version` / `-V`: the BUILD id, not the package version — the same string
/// `cermet --version` and `cermet check`'s build row print, so an operator comparing the two halves
/// of an install is comparing the thing that actually differs when they skew.
pub fn version_text() -> String {
    format!("cermetd {}", cermet_ipc::BUILD_ID)
}

/// The daemon role, synchronously. The router owns no runtime, so the multithread Tokio runtime the
/// serve loops need is constructed here and drives [`serve_daemon`].
pub fn run() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cermetd: cannot start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(serve_daemon())
}

async fn serve_daemon() -> ExitCode {
    // umask FIRST, before anything creates a file/socket, so fresh inodes (incl. sqlite -wal/-shm)
    // are 0600-from-birth.
    cermet_broker_actor::host_lock::set_umask_0077();

    let home: PathBuf = match runtime::resolve_home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("cermetd: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Create parents only; harden_dir makes the final home 0700-from-birth (no pre-hardening window).
    if let Some(parent) = home.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = cermet_broker_actor::host_lock::harden_dir(&home) {
        eprintln!("cermetd: CERMET_HOME is not a usable owner-only directory: {e}");
        return ExitCode::FAILURE;
    }

    let _lock = match lock::acquire_single_writer(&home) {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            eprintln!(
                "cermetd: another writer already owns CERMET_HOME ({}); refusing to start \
                 (single-writer)",
                home.display()
            );
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("cermetd: host lock error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let uid = nix::unistd::getuid().as_raw();

    // Service mode is the EXPLICIT launch signal (never inferred); the config is then
    // validated against the uid the daemon ACTUALLY runs as. In dev (no signal) this is the embedded
    // same-uid shape and validate_runtime is a no-op.
    let service_mode = config::service_mode_from_env();
    let config_path = std::env::var_os("CERMET_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/cermetd/config.toml"));
    let cfg = match config::load(&config_path, service_mode) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cermetd: config error ({}): {e}", config_path.display());
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = cfg.validate_runtime(uid) {
        eprintln!("cermetd: config does not match the running uid (refusing, fail-closed): {e}");
        return ExitCode::FAILURE;
    }

    // Socket dir: dev uses CERMET_HOME/run; service uses the tmpfiles-provisioned setgid socket dir
    // (cfg.runtime_dir = /run/cermetd, 2711 cermet:cermet-approvers).
    let runtime_dir = if cfg.service_mode {
        cfg.runtime_dir.clone()
    } else {
        match runtime::runtime_dir(&home) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("cermetd: cannot open runtime dir: {e}");
                return ExitCode::FAILURE;
            }
        }
    };

    // In service mode, resolve the cermet-approvers gid ONCE and assert the
    // tmpfiles-provisioned runtime dir is bit-exact 2711 cermet:cermet-approvers BEFORE binding, so
    // ctl.sock inherits the approvers group via setgid (the daemon never chgrps). Dev/embedded mode
    // has no approvers group, so approvers_gid stays None and these asserts are skipped — dev stays
    // byte-identical.
    let approvers_gid: Option<u32> = if cfg.service_mode {
        let gid = match serve::resolve_group_gid("cermet-approvers") {
            Ok(g) => g,
            Err(e) => {
                eprintln!("cermetd: cannot resolve the cermet-approvers gid (refusing): {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) = cermet_broker_actor::host_lock::harden_runtime_dir(&runtime_dir, uid, gid) {
            eprintln!(
                "cermetd: runtime dir {} is not the required 2711 cermet:cermet-approvers layout \
                 (refusing): {e}",
                runtime_dir.display()
            );
            return ExitCode::FAILURE;
        }
        Some(gid)
    } else {
        None
    };

    // In SERVICE mode agent.sock lives in a SEPARATE 2711 cermet:cermet-agents dir
    // and binds 0660. The peercred agent-uid gate — not the file mode/group — is THE auth boundary:
    // connections are ADMITTED by the kernel-attested peer uid. The 0660 + cermet-agents
    // group is defense in depth, and FILESYSTEM reachability of the socket requires the agent uid to
    // be a member of cermet-agents — a provisioning contract the installer owns, NOT asserted
    // here. In DEV/embedded mode it shares the single runtime dir and binds 0666 (the
    // same-uid path).
    let agent_runtime_dir: PathBuf = if cfg.service_mode {
        cfg.agent_runtime_dir.clone()
    } else {
        runtime_dir.clone()
    };
    let agent_mode: u32 = if cfg.service_mode { 0o660 } else { 0o666 };

    // Resolve the cermet-agents gid ONCE and assert the separate
    // agent-socket dir is bit-exact 2711 cermet:cermet-agents BEFORE binding, so agent.sock inherits
    // the cermet-agents group via setgid (the daemon never chgrps). Dev/embedded mode shares the
    // runtime dir with no agents group, so agents_gid stays None and this assert is skipped.
    let agents_gid: Option<u32> = if cfg.service_mode {
        let gid = match serve::resolve_group_gid("cermet-agents") {
            Ok(g) => g,
            Err(e) => {
                eprintln!("cermetd: cannot resolve the cermet-agents gid (refusing): {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) =
            cermet_broker_actor::host_lock::harden_runtime_dir(&agent_runtime_dir, uid, gid)
        {
            eprintln!(
                "cermetd: agent runtime dir {} is not the required 2711 cermet:cermet-agents layout \
                 (refusing): {e}",
                agent_runtime_dir.display()
            );
            return ExitCode::FAILURE;
        }
        Some(gid)
    } else {
        None
    };

    // agent.sock admits ONLY the distinct agent uid. In SERVICE mode that is the
    // configured `cermet-agent` uid (validated distinct from BOTH the daemon and the approver), so the
    // approver is thereby kernel-DENIED the agent plane — deliberate: an approver-uid compromise must
    // not be able to request AND approve. In DEV/embedded mode the agent, approver, and daemon are one
    // uid, so the admitted uid is the daemon's own uid. Fail closed lives in the gate: were this ever
    // `None`, agent.sock would refuse ALL connections rather than fall open.
    let operator_uid: Option<u32> = resolve_agent_gate_uid(cfg.service_mode, cfg.agent_uid, uid);

    // Service mode → OS-backed protected key (fail-closed); dev → fenced override / login
    // keychain. Never a plaintext file; service mode never silently falls back.
    let master_key = match load_master_key(&home, cfg.service_mode, cfg.custody_profile) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("cermetd: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Retighten any pre-existing key/DB inode to 0600 and REFUSE a symlink at any of them.
    // See `harden_secret_inodes`.
    if let Err(e) = harden_secret_inodes(&home) {
        eprintln!("cermetd: {e} (refusing, fail-closed)");
        return ExitCode::FAILURE;
    }

    // derive-don't-enroll (v1): agent.sock authenticates by the kernel-attested peer uid; there is
    // no enrollment. The non-blocking logger is not yet initialized here (init_stderr runs later),
    // so emit straight to stderr.
    eprintln!("cermetd: agent.sock authenticates by derived peer uid (derive-don't-enroll v1)");

    // The wire tee is read from THIS process's environment, never from a request. Announce it
    // once, loudly, so the journal itself records that this daemon is writing provider bodies to a
    // file — an instrument, never a production posture.
    if let Some(banner) = cermet_core::wiretap::startup_banner() {
        eprintln!("cermetd: {banner}");
    }

    let action_templates = match resolve_action_templates(&home) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cermetd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let provider_descriptors = match resolve_provider_descriptors(&home) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cermetd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let broker_config = BrokerConfig {
        git: cfg.git.clone(),
        dir: home.clone(),
        master_key,
        action_templates,
        provider_descriptors,
        artifacts: cermet_core::ArtifactConfig {
            max_bytes: cfg.artifact_max_bytes,
            retention_days: cfg.artifact_retention_days,
        },
    };
    // ONE daemon-owned atomic authority record on EVERY OS under the 0700
    // state dir. The record store is ALWAYS the sole sentence source, so an absent record is deny-all
    // through one path — never a profile fallback or "unconfigured". The operator-facing rules file
    // (`cfg.sentence_rules_path`, e.g. Linux `/etc/cermetd/sentences/rules.cermet`) is regenerated on
    // commit as a READ PROJECTION only, never read back as authority.
    let record_store = sentence_record::build_record_store(&home, cfg.sentence_rules_path.clone());
    let sentence_source: Option<std::sync::Arc<dyn cermet_core::SentenceAuthoritySource>> =
        Some(record_store.clone() as std::sync::Arc<dyn cermet_core::SentenceAuthoritySource>);
    // The record store is always installed, so sentence authority is always "configured" (an absent
    // record is a deny-all posture, not an unconfigured one).
    let sentence_rules_configured = true;
    // The ctl-only sentence admin (snapshot + staged stage/commit + adopt), on every OS.
    let record_admin: std::sync::Arc<dyn crate::sentence_record::SentenceRecordAdmin> =
        record_store.clone();
    let lockdown_store = std::sync::Arc::new(crate::lockdown::LockdownStore::new(&home, uid));
    startup::adopt_lockdown(&lockdown_store);
    let lockdown_source: std::sync::Arc<dyn cermet_core::LockdownSource> = lockdown_store.clone();
    // MCP-repoint quiesce barrier: the durable state-dir record. The broker adopts any
    // unexpired record at open (reinstate before serving) and fails boot closed on a malformed one.
    let quiesce_store: Option<Box<dyn cermet_core::QuiesceStore>> =
        Some(Box::new(crate::quiesce_store::FileQuiesceStore::new(&home)));
    let opened_broker = cermet_broker_actor::spawn_full(
        broker_config,
        vec![],
        sentence_source,
        Some(lockdown_source.clone()),
        quiesce_store,
        // The declared relay settings ride to the core, which composes the loopback
        // URL and invocation a relay verb's receipt hands the agent.
        Some(cfg.relay.clone()),
        // The declared `language_temporal_clauses` setting rides to the core's corpus-admission seam.
        Some(cfg.temporal_clauses),
    );
    let broker = match opened_broker {
        Ok(h) => h,
        Err(e) => {
            eprintln!("cermetd: failed to open broker: {e}");
            return ExitCode::FAILURE;
        }
    };
    // CUSTODY-LADDER: the chain records which vault-key custody rung THIS run is on, before
    // anything is served. Custody can change across a reinstall or a migration, so a receipt has to
    // be interpretable against the custody that was actually carrying it. A failed write is loud
    // but not fatal: it is evidence about the run, not authority over it.
    if let Err(error) = broker
        .record_broker_start(cfg.custody_profile.map(|p| p.as_str().to_string()))
        .await
    {
        eprintln!("cermetd: could not record the custody profile at start: {error}");
    }

    // Boot adoption, sentence/lockdown audit replay, and inert-stage sweeping are one shared
    // production recovery seam, executed before any socket begins serving.
    startup::recover_after_broker_start(&record_store, &lockdown_store, &broker).await;

    // The startup doctor runs before bind, but old daemon versions could leave stale Unix
    // socket pathnames behind. Clean ONLY stale socket inodes now (after runtime-dir hardening and
    // under the single-writer lock) so doctor doesn't fail an upgrade before bind gets to replace
    // them. Non-socket/symlink impostors at reserved names still fail closed.
    if let Err(e) = serve::clean_stale_socket_pathnames(&runtime_dir, &agent_runtime_dir) {
        eprintln!("cermetd: cannot clean stale socket pathnames (refusing): {e}");
        return ExitCode::FAILURE;
    }

    // The refuse-to-serve self-check is a HARD ENTRY GATE — it runs and can refuse BEFORE
    // any socket binds, never after. The stale-socket cleanup above means pre-bind socket pathnames
    // are either absent or fail-closed non-socket drift; the fresh bound socket modes are asserted
    // immediately after bind. In service mode the collapse conditions are hard fails; in dev they
    // stay warn-and-serve. `approvers_gid` was resolved above (Some in service mode after the
    // runtime-dir assert, None in dev) so doctor's ctl-group/runtime-dir checks run on the real gid.
    let report = doctor::run_with_sentence_authority(
        &home,
        &runtime_dir,
        &agent_runtime_dir,
        uid,
        cfg.approver_uid,
        cfg.agent_uid,
        operator_uid,
        approvers_gid,
        agents_gid,
        cfg.service_mode,
        cfg.custody_profile,
        sentence_rules_configured,
        None,
    );
    for c in report.warnings() {
        eprintln!("cermetd doctor [{}] {}: {}", c.status, c.name, c.detail);
    }
    if !report.serving {
        eprintln!("cermetd: doctor refuses to serve (fail-closed); see the doctor checks above");
        return ExitCode::FAILURE;
    }

    // Entry gate passed — NOW bind the sockets. In service mode thread the approvers gid through the
    // group-aware bind (a no-op for the bind itself — the group comes from setgid
    // inheritance — but it keeps the call-site intent explicit).
    // Component 2: agent.sock binds in its (possibly separate) agents dir at `agent_mode` (0660 with
    // a cermet-agents group in service mode, 0666 in the shared dir in dev); ctl.sock binds in the
    // runtime dir at 0660. Fail closed if either cannot bind.
    let (agent_listener, ctl_listener) = match serve::bind_sockets_separate_dirs(
        &agent_runtime_dir,
        agent_mode,
        &runtime_dir,
        approvers_gid,
    ) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("cermetd: cannot bind sockets (refusing to start): {e}");
            return ExitCode::FAILURE;
        }
    };
    // git-native stream plane state. `hook_program` is this very binary: git's `update` hook is a
    // two-line stub the daemon writes into each mirror that execs `cermetd git-update-hook`.
    let hook_registry = crate::gitplane::hook_registry();
    let hook_program = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("cermetd"));
    let hook_socket_path = runtime_dir.join("githook.sock");
    let git_settings = cfg.git.clone();
    let git_broker = broker.clone();
    let githook_broker = broker.clone();
    // SAFETY: `getuid` is always successful and has no preconditions.
    let daemon_uid_for_hook = unsafe { libc::getuid() };
    // git.sock binds 0666, NOT agent_mode: its admitted set spans the agent AND approver uids,
    // which live in deliberately-disjoint groups, so no single group ACL can express
    // it — the setgid dir would stamp cermet-agents and 0660 would kernel-refuse the admitted
    // approver. Reachability stays wide; the peercred admission gate on accept is THE boundary,
    // and the dir is world-traversable-not-listable by the tmpfiles contract.
    let git_listener = match crate::gitplane::bind_git_socket(&agent_runtime_dir, 0o666) {
        Ok((listener, _)) => listener,
        Err(error) => {
            eprintln!("cermetd: cannot bind git.sock (refusing to start): {error}");
            return ExitCode::FAILURE;
        }
    };
    let githook_listener = match crate::gitplane::hook::bind_hook_socket(&runtime_dir) {
        Ok((listener, _)) => listener,
        Err(error) => {
            eprintln!("cermetd: cannot bind githook.sock (refusing to start): {error}");
            return ExitCode::FAILURE;
        }
    };
    let owner_listener = match crate::owner::bind_owner_socket(&runtime_dir) {
        Ok((listener, _)) => listener,
        Err(error) => {
            eprintln!("cermetd: cannot bind owner.sock (refusing to start): {error}");
            drop(agent_listener);
            drop(ctl_listener);
            let _ = std::fs::remove_file(agent_runtime_dir.join("agent.sock"));
            let _ = std::fs::remove_file(runtime_dir.join("ctl.sock"));
            return ExitCode::FAILURE;
        }
    };

    // A single cleanup closure so every post-bind refusal removes BOTH sockets from their real dirs.
    let unlink_all = || {
        let _ = std::fs::remove_file(agent_runtime_dir.join("agent.sock"));
        let _ = std::fs::remove_file(runtime_dir.join("ctl.sock"));
        let _ = std::fs::remove_file(runtime_dir.join("owner.sock"));
    };

    if let Err(e) = serve::assert_socket_mode(&agent_runtime_dir.join("agent.sock"), agent_mode) {
        eprintln!("cermetd: agent.sock mode/type check failed after bind (refusing): {e}");
        drop(agent_listener);
        drop(ctl_listener);
        drop(owner_listener);
        unlink_all();
        return ExitCode::FAILURE;
    }
    if let Err(e) = serve::assert_socket_mode(&runtime_dir.join("ctl.sock"), 0o660) {
        eprintln!("cermetd: ctl.sock mode/type check failed after bind (refusing): {e}");
        drop(agent_listener);
        drop(ctl_listener);
        drop(owner_listener);
        unlink_all();
        return ExitCode::FAILURE;
    }
    if let Err(e) = serve::assert_socket_mode(&runtime_dir.join("owner.sock"), 0o600) {
        eprintln!("cermetd: owner.sock mode/type check failed after bind (refusing): {e}");
        drop(agent_listener);
        drop(ctl_listener);
        drop(owner_listener);
        unlink_all();
        return ExitCode::FAILURE;
    }

    // Verify ctl.sock actually INHERITED the approvers group from the setgid
    // runtime dir (the daemon never chgrps it). A wrong/missing group means cross-uid approvers
    // cannot reach the control plane — refuse rather than serve a broken boundary. Service mode only.
    if let Some(gid) = approvers_gid {
        if let Err(e) = serve::assert_socket_group(&runtime_dir.join("ctl.sock"), gid) {
            eprintln!(
                "cermetd: ctl.sock did not inherit the approvers group (refusing to serve): {e}"
            );
            drop(agent_listener);
            drop(ctl_listener);
            drop(owner_listener);
            unlink_all();
            return ExitCode::FAILURE;
        }
    }

    // Verify agent.sock actually INHERITED the cermet-agents group
    // from the setgid agent dir (the daemon never chgrps it). A wrong/missing group means the distinct
    // agent uid cannot reach the agent plane — refuse rather than serve a broken boundary. The
    // peercred gate is still THE auth boundary; this is the defense-in-depth layer. Service mode only.
    if let Some(gid) = agents_gid {
        if let Err(e) = serve::assert_socket_group(&agent_runtime_dir.join("agent.sock"), gid) {
            eprintln!(
                "cermetd: agent.sock did not inherit the cermet-agents group (refusing to serve): {e}"
            );
            drop(agent_listener);
            drop(ctl_listener);
            drop(owner_listener);
            unlink_all();
            return ExitCode::FAILURE;
        }
    }

    // Per-request serve-loop diagnostics go through a non-blocking, drop-on-full logger so a stalled
    // stderr can never pin an agent.sock handler past the response budget.
    log::init_stderr();

    println!(
        "cermetd serving agent.sock in {} (mode={agent_mode:o}) + ctl.sock/owner.sock in {} (service_mode={})",
        agent_runtime_dir.display(),
        runtime_dir.display(),
        cfg.service_mode
    );

    // Thread the resolved approvers gid + service_mode into BOTH serve loops
    // so the `cermetctl doctor` report over ctl.sock matches the startup self-check (a ctl.sock
    // mode/group drift FAILS, not just warns, in service mode). Copy type — reused by both closures.
    let serve_config = serve::ServeConfig {
        approvers_gid,
        agents_gid,
        service_mode: cfg.service_mode,
        custody_profile: cfg.custody_profile,
        ..serve::ServeConfig::default()
    };

    // The daemon's custody housekeeping — the overdue-executing lease sweep runs
    // periodically (plus once at boot inside Broker::open), so an abandoned lease is terminalized
    // within one tick of its HMAC-covered deadline. Purely internal: no agent push exists or is
    // needed; a late reporter gets the typed already-terminal refusal.
    let sweep_broker = broker.clone();
    // The staged-TTL sweep runs on the SAME housekeeping tick, so a staged record a crashed
    // ceremony left behind is reaped within one tick of its TTL. The same tick retries any
    // custody audit whose emit failed (loud, never a silent drop).
    let sweep_record_admin = record_admin.clone();
    let sweep_lockdown_store = lockdown_store.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tick.tick().await;
            let swept = sweep_broker.sweep_overdue_leases().await;
            if swept > 0 {
                log::emit(format!("cermetd: swept {swept} overdue execution lease(s)"));
            }
            // The budget/rate expiry backstop runs on the SAME tick (plus once at boot inside
            // Broker::open) — an abandoned-approved budget grant or a crash-orphan mint frees its
            // reserved capacity within one tick of its TTL, not only at calendar rollover. Serialized on
            // the broker thread; releases only on proven non-invocation.
            // A relay session that simply ran out of time closes on this same tick,
            // with the receipt it derived from what it observed on the wire.
            let relay_closed = sweep_broker.sweep_relay_sessions().await;
            if relay_closed > 0 {
                log::emit(format!(
                    "cermetd: closed {relay_closed} lapsed relay session(s)"
                ));
            }
            let budget_released = sweep_broker.sweep_expired_budget_mints().await;
            if budget_released > 0 {
                log::emit(format!(
                    "cermetd: released {budget_released} expired budget/rate reservation(s)"
                ));
            }
            match sweep_record_admin.sweep_staged(sentence_record::STAGED_TTL_SECS) {
                Ok(n) if n > 0 => log::emit(format!(
                    "cermetd: swept {n} inert staged sentence record(s)"
                )),
                Err(e) => log::emit(format!("cermetd: staged-record sweep failed: {e}")),
                _ => {}
            }
            // Before replay, reconcile the live generation's marker — a commit whose
            // best-effort post-flip confirm was lost leaves an intent-only marker replay would skip.
            // Promote it to confirmed here so the audit lands within one tick, not only at the next boot.
            if let Err(e) = sweep_record_admin.reconcile_live_audit_marker() {
                log::emit(format!(
                    "cermetd: could not reconcile the live sentence audit marker ({e}); will retry"
                ));
            }
            startup::replay_pending_custody_audits(sweep_record_admin.as_ref(), &sweep_broker)
                .await;
            crate::owner::replay_pending_audits(&sweep_lockdown_store, &sweep_broker).await;
            // MCP-repoint quiesce barrier: TTL-recover a barrier a crashed installer left
            // behind, through the SAME ordered durable release as EndMcpRepoint, so claims are never
            // wedged past the hard-bounded expiry.
            if let Ok(json) = sweep_broker.release_expired_barrier().await {
                if json == "true" {
                    log::emit(
                        "cermetd: released an expired MCP-repoint quiesce barrier".to_string(),
                    );
                }
            }
        }
    });

    // The loopback relay listener. It is the seam a native client (today the `vercel`
    // CLI, pointed here with `--api`) reaches, and it enforces nothing itself — every hop is decided by
    // the broker. A configured-but-unbindable or non-loopback address is a HARD failure: the relay's
    // door must be exactly where the operator declared it, or not open at all.
    match crate::relay::serve(cfg.relay.clone(), broker.clone()).await {
        Ok(Some(addr)) => log::emit(format!("cermetd: relay listening on http://{addr}")),
        Ok(None) => log::emit(
            "cermetd: relay disabled (relay_listen is empty); relay verbs will refuse".to_string(),
        ),
        Err(e) => {
            eprintln!("cermetd: cannot serve the relay listener (refusing): {e}");
            return ExitCode::FAILURE;
        }
    }

    // The agent path admits ONLY the agent-plane uid resolved above (the distinct
    // agent uid in service mode); every other uid — including the approver — and, were it unresolved,
    // every connection, is refused before any byte.
    let agent_broker = broker.clone();
    let agent = tokio::task::spawn_blocking(move || {
        serve::serve_agent_socket(
            agent_listener,
            agent_broker,
            "cermetd".to_string(),
            operator_uid,
            serve_config,
        )
    });
    // The ctl gate authorizes the single configured approver uid (not the daemon
    // uid). serve_ctl_socket reads the daemon's own uid internally.
    let ctl_home = home.clone();
    let ctl_runtime = runtime_dir.clone();
    let ctl_agent_runtime = agent_runtime_dir.clone();
    let ctl_approver = cfg.approver_uid;
    let ctl_agent_uid = cfg.agent_uid;
    let owner_broker = broker.clone();
    let ctl = tokio::task::spawn_blocking(move || {
        ctl::serve_ctl_socket(
            ctl_listener,
            broker,
            ctl_approver,
            ctl_agent_uid,
            ctl_home,
            ctl_runtime,
            ctl_agent_runtime,
            serve_config,
            sentence_rules_configured,
            record_admin,
            lockdown_source,
        )
    });

    let owner = tokio::task::spawn_blocking(move || {
        crate::owner::serve_owner_socket(owner_listener, lockdown_store, owner_broker, serve_config)
    });

    // the attested STREAM plane plus the update hook's callback channel. `git.sock`
    // admits the uids that actually issue git commands — unlike `agent.sock` there is no
    // sudo'd bridge hop converting the caller to the agent uid, so the caller's REAL uid arrives
    // at the door (on today's box that is the operator's session uid, covering the human
    // and every harness agent under it). `githook.sock` admits only the daemon's own uid, because
    // its only legitimate client is a hook in a process the daemon itself spawned.
    let git_plane = crate::gitplane::GitPlane {
        broker: git_broker,
        git: git_settings,
        hook_program: hook_program.clone(),
        hook_socket: hook_socket_path,
        registry: hook_registry.clone(),
        admitted_uids: crate::gitplane::admitted_uids(
            cfg.service_mode,
            cfg.agent_uid,
            cfg.approver_uid,
            uid,
        ),
    };
    let git = tokio::task::spawn_blocking(move || {
        crate::gitplane::serve_git_socket(git_listener, git_plane, serve_config)
    });
    let githook = tokio::task::spawn_blocking(move || {
        crate::gitplane::hook::serve_hook_socket(
            githook_listener,
            githook_broker,
            hook_registry,
            daemon_uid_for_hook,
            serve_config,
        )
    });

    let (which, res) = supervise::supervise_surfaces(agent, ctl, owner, git, githook).await;
    match res {
        Ok(()) => {
            eprintln!("cermetd: {which} accept loop returned unexpectedly; exiting fail-closed")
        }
        Err(e) => eprintln!("cermetd: {which} serve task panicked: {e}; exiting fail-closed"),
    }
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::{
        harden_secret_inodes, resolve_action_templates, resolve_agent_gate_uid,
        resolve_provider_descriptors,
    };
    use std::os::unix::fs::PermissionsExt;

    // Pin the SERVICE-MODE agent-gate uid resolution so a regression to
    // the old approver-uid wiring (or to getuid()) fails here by name. Distinct fixture uids so a
    // wrong choice is unambiguous: agent 903, approver 902, daemon/dev 901.
    const T_AGENT_UID: u32 = 903;
    const T_APPROVER_UID: u32 = 902;
    const T_DEV_UID: u32 = 901;

    #[test]
    fn resolves_agent_gate_to_agent_uid_in_service() {
        // Service mode admits ONLY the distinct agent uid — NOT the approver, NOT the daemon/dev uid.
        assert_eq!(
            resolve_agent_gate_uid(true, T_AGENT_UID, T_DEV_UID),
            Some(T_AGENT_UID),
            "service-mode agent.sock gate must resolve to the configured agent uid"
        );
        // Regression guards: it must NOT be the approver uid nor the daemon/dev uid.
        assert_ne!(
            resolve_agent_gate_uid(true, T_AGENT_UID, T_DEV_UID),
            Some(T_APPROVER_UID),
            "the approver uid must NOT be admitted to agent.sock (it is kernel-denied the agent plane)"
        );
        assert_ne!(
            resolve_agent_gate_uid(true, T_AGENT_UID, T_DEV_UID),
            Some(T_DEV_UID),
            "the daemon/dev uid must NOT be admitted to agent.sock in service mode"
        );
    }

    #[test]
    fn resolves_agent_gate_to_dev_uid_in_dev_mode() {
        // Dev/embedded mode: the admitted uid is the daemon's own (same-uid) uid, unchanged behavior.
        assert_eq!(
            resolve_agent_gate_uid(false, T_AGENT_UID, T_DEV_UID),
            Some(T_DEV_UID),
            "dev-mode agent.sock gate resolves to the daemon's own uid"
        );
    }

    /// Write an authority-file fixture (policy / provider descriptor / action template) with an
    /// explicit 0600 mode, umask-independent — the boot authority reader refuses a group/other-
    /// writable file, and Ubuntu's default 0002 umask would otherwise leave a plain write group-
    /// writable and rightly refused. Production writes these docs 0600 already.
    fn write_authority_0600(path: impl AsRef<std::path::Path>, contents: &str) {
        let path = path.as_ref();
        std::fs::write(path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn daemon_providers_dir_owner_check_refuses_like_actions_d() {
        // A descriptor is authority (the only thing that lets a token ride to an origin), so
        // providers.d gets the SAME hardened-read posture as actions.d. Absent dir ⇒ no providers.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_provider_descriptors(dir.path()).unwrap(),
            Vec::<String>::new()
        );

        let providers = dir.path().join("providers.d");
        std::fs::create_dir_all(&providers).unwrap();

        // (a) a symlinked descriptor must REFUSE boot (never followed, never silently skipped).
        let attacker = dir.path().join("attacker.yaml");
        std::fs::write(&attacker, "name: github\n").unwrap();
        std::os::unix::fs::symlink(&attacker, providers.join("github.yaml")).unwrap();
        assert!(
            resolve_provider_descriptors(dir.path())
                .expect_err("a symlinked descriptor must fail closed")
                .contains("refusing"),
            "the error signals a fail-closed refusal"
        );
        std::fs::remove_file(providers.join("github.yaml")).unwrap();

        // (b) a group/other-writable descriptor refuses boot.
        let p = providers.join("loose.yaml");
        std::fs::write(&p, "name: vercel\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            resolve_provider_descriptors(dir.path()).is_err(),
            "a group/other-writable descriptor must refuse boot"
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(&p).unwrap();

        // (c) only *.yaml load, in deterministic order; a staged file is ignored.
        write_authority_0600(providers.join("b.yaml"), "doc-b");
        write_authority_0600(providers.join("a.yaml"), "doc-a");
        std::fs::write(providers.join("acme.yaml.staged"), "doc-staged").unwrap();
        std::fs::write(providers.join("notes.txt"), "nope").unwrap();
        assert_eq!(
            resolve_provider_descriptors(dir.path()).unwrap(),
            vec!["doc-a".to_string(), "doc-b".to_string()],
            "only *.yaml descriptors load, in filename order; staged/other ignored"
        );
    }

    #[test]
    fn daemon_actions_dir_foreign_file_refuses_boot() {
        // An ABSENT actions.d dir is simply "no templates" (fail closed to LESS authority).
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_action_templates(dir.path()).unwrap(),
            Vec::<String>::new()
        );

        // A symlinked template doc must REFUSE boot (the hardened-read posture) — never be followed,
        // never silently skipped.
        let actions = dir.path().join("actions.d");
        std::fs::create_dir_all(&actions).unwrap();
        let attacker = dir.path().join("attacker.yaml");
        std::fs::write(&attacker, "provider: github\n").unwrap();
        std::os::unix::fs::symlink(&attacker, actions.join("github.attacker_planted.yaml"))
            .unwrap();
        let err = resolve_action_templates(dir.path())
            .expect_err("a symlinked action template must fail closed");
        assert!(
            err.contains("refusing"),
            "the error signals a fail-closed refusal: {err}"
        );
    }

    #[test]
    fn daemon_actions_dir_group_writable_doc_refuses_boot() {
        // Templates ARE authority: a group/other-writable doc (another uid could rewrite it into a
        // new executable action) refuses boot, same as policy.yaml.
        let dir = tempfile::tempdir().unwrap();
        let actions = dir.path().join("actions.d");
        std::fs::create_dir_all(&actions).unwrap();
        let p = actions.join("loose.yaml");
        std::fs::write(&p, "provider: github\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            resolve_action_templates(dir.path()).is_err(),
            "a group/other-writable template doc must refuse boot"
        );
    }

    #[test]
    fn daemon_actions_dir_loads_owned_docs_in_sorted_order() {
        let dir = tempfile::tempdir().unwrap();
        let actions = dir.path().join("actions.d");
        std::fs::create_dir_all(&actions).unwrap();
        write_authority_0600(actions.join("b.yaml"), "doc-b");
        write_authority_0600(actions.join("a.yaml"), "doc-a");
        std::fs::write(actions.join("notes.txt"), "not a template").unwrap();
        assert_eq!(
            resolve_action_templates(dir.path()).unwrap(),
            vec!["doc-a".to_string(), "doc-b".to_string()],
            "only *.yaml docs load, in deterministic filename order"
        );
    }

    #[test]
    fn staged_file_in_actions_d_neither_loads_nor_blocks_boot() {
        // ratify STAGES an install as `<p>.<a>.yaml.staged`, whose extension is `staged`,
        // NOT `yaml`. The daemon's `*.yaml` boot filter must therefore ignore it — a mid-publish crash
        // must never boot-load unratified authority, and a stray staged file must not fail the boot.
        let dir = tempfile::tempdir().unwrap();
        let actions = dir.path().join("actions.d");
        std::fs::create_dir_all(&actions).unwrap();
        write_authority_0600(actions.join("github.attacker_planted.yaml"), "doc-live");
        std::fs::write(actions.join("github.e2e_probe.yaml.staged"), "doc-staged").unwrap();
        assert_eq!(
            resolve_action_templates(dir.path()).unwrap(),
            vec!["doc-live".to_string()],
            "only the `.yaml` file is returned; the `.yaml.staged` file is neither loaded nor fatal"
        );
    }

    #[test]
    fn harden_secret_inodes_refuses_a_symlinked_db() {
        // A non-dangling symlink at a DB path: harden_file_0600 (O_NOFOLLOW) would already reject it,
        // but we refuse uniformly via symlink_metadata before ever touching it.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere.db");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("vault.db")).unwrap();
        assert!(
            harden_secret_inodes(dir.path()).is_err(),
            "a symlinked DB path must fail closed"
        );
    }

    #[test]
    fn harden_secret_inodes_refuses_a_dangling_symlinked_db() {
        // The dangling-symlink case: Path::exists() returns false and the old loop
        // skipped it, after which rusqlite would follow it and create the DB outside the 0700 home.
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dir.path().join("missing.db"), dir.path().join("vault.db"))
            .unwrap();
        assert!(
            harden_secret_inodes(dir.path()).is_err(),
            "a DANGLING symlinked DB must fail closed (exists() would skip it)"
        );
    }

    #[test]
    fn harden_secret_inodes_tightens_a_loose_regular_db_and_skips_absent() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("vault.db");
        std::fs::write(&p, b"secret-pages").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        // The other inodes are absent → skipped, not an error.
        harden_secret_inodes(dir.path())
            .expect("a loose owned DB is hardened; absent ones skipped");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the loose DB is retightened to 0600");
    }

    #[test]
    fn unseeded_home_makes_the_boot_doctor_warn_but_still_serve() {
        // The zero-capability boot signal: an unseeded home loads zero templates, and the boot
        // doctor (whose warnings main() prints to stderr) must surface that as a loud WARN — never a
        // refusal (a fresh install legitimately has no actions.d).
        let dir = tempfile::tempdir().unwrap();
        assert!(
            resolve_action_templates(dir.path()).unwrap().is_empty(),
            "an unseeded home loads zero templates"
        );
        let runtime = dir.path().join("run");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o2711)).unwrap();
        let report = crate::doctor::run(
            dir.path(),
            &runtime,
            &runtime,
            501,
            502,
            501,
            Some(502),
            None,
            None,
            false,
        );
        let at = report
            .checks
            .iter()
            .find(|c| c.name == "action_templates")
            .expect("the boot doctor carries an action_templates check");
        assert_eq!(at.status, "warn", "an unseeded boot warns: {at:?}");
        assert!(
            at.detail.contains("actions.d"),
            "the warn names the actions.d path: {at:?}"
        );
        assert!(
            report.serving,
            "a zero-template boot is a warn, never a refusal"
        );
    }
}
