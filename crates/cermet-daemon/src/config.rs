//! Daemon config: parse `/etc/cermetd/config.toml`.
//!
//! The shipped template is `dist/linux/config.toml`. This module reads it and produces a
//! VALIDATED [`DaemonConfig`]. The split that matters is `service_mode`:
//!
//!   * `service_mode` comes from an EXPLICIT launch signal — `CERMET_SERVICE_MODE=1` in the
//!     systemd unit (or a `--service` flag the caller passes), NEVER inferred from an optional
//!     `service_uid` field. That inference is what made the installed default fail open
//!     a config file with a `service_uid` would silently enter the fail-closed
//!     path with no kernel-uid check, so the signal governs instead.
//!   * a dev-mode daemon (started without the service signal) runs as a single uid ⇒
//!     `service_mode = false` (the fail-open dev path; warn-and-serve).
//!
//! Two-phase validation, both fail-closed ("unresolved must never lead to access"):
//!   1. parse-time (filesystem/getuid-FREE, unit-testable): a configured `service_uid` with a
//!      self-contradicting identity (`approver_uid == service_uid`, either uid `0`, or an empty
//!      `runtime_dir`) is rejected.
//!   2. [`DaemonConfig::validate_runtime`] (takes the kernel uid as a param so the central wiring
//!      passes `getuid()`): in service mode it asserts `service_uid == kernel_uid`,
//!      `approver_uid != kernel_uid`, and both uids nonzero — else `Err`. In dev mode it is a
//!      no-op.

use std::path::{Path, PathBuf};

use cermet_ipc::custody::CustodyProfile;
use serde::Deserialize;
use thiserror::Error;

/// The daemon's runtime dir under `CERMET_HOME` when none is configured (dev default).
// The ctl socket dir (NOT the state dir): the tmpfiles-provisioned setgid dir at /run/cermetd
// (2711 cermet:cermet-approvers) where `ctl.sock` lives. State/DBs live under
// CERMET_HOME=/var/lib/cermetd.
const DEFAULT_RUNTIME_DIR: &str = "/run/cermetd";

/// The SEPARATE agent-socket runtime dir in service mode. `agent.sock` binds here at `0660`,
/// inheriting the disjoint `cermet-agents` group from a `2711 cermet:cermet-agents` dir —
/// mirroring ctl's approvers shape. Admission to agent.sock is by the kernel peercred agent-uid
/// gate, NOT the group; the 0660 + cermet-agents group is defense in depth, and filesystem
/// reachability additionally requires the agent uid to be a member of `cermet-agents` — a
/// membership the installer provisions, not verified here. In dev mode the agent socket shares
/// the single runtime dir
/// (== `runtime_dir`) at `0666`, the same-uid path.
const DEFAULT_AGENT_RUNTIME_DIR: &str = "/run/cermetd-agents";

/// The explicit launch signal for service mode. `CERMET_SERVICE_MODE=1` ⇒ service mode;
/// anything else (unset, "0", "") ⇒ dev mode. Set by the systemd unit, never in a dev launch.
pub const SERVICE_MODE_ENV: &str = "CERMET_SERVICE_MODE";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    /// The file exists but is not valid TOML for our schema.
    #[error("config is malformed: {0}")]
    Malformed(String),
    /// `approver_uid == service_uid`: the approver≠daemon split is what keeps approvals
    /// human-only. Collapsing them would let the daemon approve its own `Ask` grants.
    #[error("approver_uid ({uid}) must not equal service_uid (the daemon cannot approve itself)")]
    ApproverEqualsService { uid: u32 },
    /// `agent_uid == service_uid`: the agent plane would collapse onto the daemon
    /// uid — a compromised agent could then reach the daemon-owned vault/state directly.
    #[error(
        "agent_uid ({uid}) must not equal service_uid (the agent and daemon must be distinct uids)"
    )]
    AgentEqualsService { uid: u32 },
    /// `agent_uid == approver_uid`: the two authority planes would collapse. A
    /// malicious agent running as the approver uid could speak ctl.sock and approve its own requests —
    /// exactly the self-dealing the distinct agent uid closes.
    #[error("agent_uid ({uid}) must not equal approver_uid (a compromised agent could then approve its own requests)")]
    AgentEqualsApprover { uid: u32 },
    /// uid 0 is root; running the service or the approver as root defeats the boundary.
    #[error("uid 0 (root) is not allowed for {which}")]
    RootUid { which: &'static str },
    /// A configured (service-mode) config must name a non-empty runtime_dir.
    #[error("runtime_dir must be non-empty in service mode")]
    EmptyRuntimeDir,
    /// Runtime assert: the configured `service_uid` does not match the uid the daemon
    /// actually runs as (`getuid()`). The whole flip rests on the daemon running as `cermet`; a
    /// mismatch means the boundary is not in force, so refuse.
    #[error(
        "service_uid ({configured}) does not match the kernel uid the daemon runs as ({kernel})"
    )]
    ServiceUidMismatch { configured: u32, kernel: u32 },
    /// Runtime assert: the daemon is running as the approver uid — it could approve its
    /// own authority. Authority changes are human-only; refuse.
    #[error(
        "the daemon must not run as the operator uid ({kernel}) — authority changes are human-only"
    )]
    ApproverEqualsKernel { kernel: u32 },
    /// Runtime assert: the daemon is running as the AGENT uid — the agent plane
    /// would then coincide with the daemon uid that owns the vault/state. Refuse.
    #[error("the daemon must not run as the agent uid ({kernel}) — the agent and daemon must be distinct uids")]
    AgentEqualsKernel { kernel: u32 },
    /// CUSTODY-LADDER: service mode without a declared `custody_profile`. There is deliberately no
    /// default rung — the key SOURCE follows from it, and a guessed source either opens nothing or
    /// opens the wrong thing. `cermet setup` writes this key from what the box could actually carry.
    #[error(
        "custody_profile is not declared in the config; service mode has no default key custody \
         — run `sudo cermet setup`, which selects the strongest rung this box supports and \
         records it"
    )]
    CustodyProfileMissing,
    /// CUSTODY-LADDER: a `custody_profile` this build does not implement. Refused by name rather
    /// than treated as any rung — an unrecognized value is not evidence for a weaker OR a stronger
    /// one.
    #[error("custody_profile {value:?} is not a custody profile this build implements (systemd-tpm2+host, systemd-host, file-protected)")]
    UnknownCustodyProfile { value: String },
    /// IO error reading the file (a present-but-unreadable file fails closed; only NotFound
    /// yields dev defaults).
    #[error("config io error: {0}")]
    Io(String),
}

/// The validated daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    /// The service (daemon) uid. `0` in dev defaults (embedded, never used as an authority).
    pub service_uid: u32,
    /// The single human operator uid permitted to drive the ctl plane.
    pub approver_uid: u32,
    /// The distinct `cermet-agent` uid that runs the model-driven agent/MCP process.
    /// In service mode this is REQUIRED and validated distinct from BOTH the service uid and the
    /// operator uid: agent.sock admits ONLY this uid, so the operator is thereby kernel-denied the
    /// agent plane, and a malicious agent cannot reach ctl.sock to self-authorize. In dev/embedded mode
    /// the agent resolves to `getuid()` at wiring time (this field is unused / `0` in the dev shape).
    pub agent_uid: u32,
    /// True when the EXPLICIT launch signal (`CERMET_SERVICE_MODE=1` / `--service`) is set: the
    /// fail-closed flip path with the runtime kernel-uid assertion. False for the embedded /
    /// same-uid dev path (the fail-open loop). This is NOT inferred from `service_uid`.
    pub service_mode: bool,
    /// The daemon-owned ctl runtime dir holding `ctl.sock` (setgid `cermet-approvers`, 2711). In
    /// dev/embedded mode `agent.sock` shares this dir (0666 + peercred gate); in service mode the
    /// agent socket lives in the separate [`Self::agent_runtime_dir`].
    pub runtime_dir: PathBuf,
    /// The agent-socket runtime dir. In service mode this is the SEPARATE
    /// `2711 cermet:cermet-agents` dir (default `/run/cermetd-agents`) so a distinct agent uid can
    /// reach `agent.sock` (0660, group-inherited) while the approver cannot; in dev/embedded mode it
    /// equals `runtime_dir` (the single-dir 0666 same-uid path).
    pub agent_runtime_dir: PathBuf,
    /// Human-owned canonical sentence file. The daemon receives read-only filesystem access; exact
    /// bytes authenticate through the separately provisioned System Keychain pin.
    pub sentence_rules_path: Option<PathBuf>,
    /// Artifact-store cap: max bytes kept per stored blob before head+tail truncation (default ~5 MiB).
    pub artifact_max_bytes: usize,
    /// Artifact-store retention window in days; older blobs are swept at startup (default 90, `0` off).
    pub artifact_retention_days: i64,
    /// the git seam. `git_binary` is the ABSOLUTE path of the box's git (defaulted, so
    /// there is no registration act; usability is checked per request and the daemon boots on a
    /// git-less box either way), `git_mirror_dir` roots the persistent 0700 per-remote bare mirrors
    /// the daemon serves `receive-pack`/`upload-pack` from, `git_timeout_secs` bounds one hermetic
    /// invocation, `git_mirror_retention_days` ages out mirrors with no authorized contact, and
    /// `git_max_push_bytes` becomes each mirror's own `receive.maxInputSize` so git caps what one
    /// push may write.
    pub git: cermet_core::git::GitConfig,
    /// Whether this daemon admits TEMPORAL (windowed) sentence clauses — `rate N per <window>` and
    /// `budget [field] N per <window>` — into a corpus. Config key `language_temporal_clauses`,
    /// DEFAULT FALSE: a decision must be a pure function of `(request, corpus)`, so nothing
    /// accumulated is consulted at decision time. With it false the broker's corpus-admission seam
    /// refuses any such clause, naming this key. The machinery stays compiled, so setting it true
    /// restores the windowed behavior with no code change.
    pub temporal_clauses: bool,
    /// The loopback relay a `execution: relay` verb runs through. `relay_listen` is
    /// the loopback authority cermetd binds (and the `--api` base handed to the native client);
    /// EMPTY disables the relay entirely. `relay_ttl_secs` bounds one session; `relay_max_body_bytes`
    /// caps one buffered request or response body.
    pub relay: cermet_core::RelayConfig,
    /// CUSTODY-LADDER: which mechanism holds this box's vault key, as DECLARED by `cermet setup`
    /// (config key `custody_profile`). It is the AUTHORITATIVE input to the key-source dispatch in
    /// [`crate::master_key`] — the daemon reads what the config declares and refuses anything else,
    /// so the config and the box can never silently disagree about custody. REQUIRED in service
    /// mode (there is no default rung); `None` in the dev/embedded shape, which loads no service
    /// key source at all.
    pub custody_profile: Option<CustodyProfile>,
}

/// The raw TOML shape, mirroring `dist/linux/config.toml`. `service_uid` is OPTIONAL — its
/// PRESENCE selects the configured-identity shape (and triggers parse-time identity validation),
/// but it does NOT flip `service_mode`; the explicit launch signal does.
#[derive(Debug, Deserialize)]
struct RawConfig {
    service_uid: Option<u32>,
    approver_uid: Option<u32>,
    agent_uid: Option<u32>,
    runtime_dir: Option<String>,
    agent_runtime_dir: Option<String>,
    sentence_rules_path: Option<String>,
    artifact_max_bytes: Option<usize>,
    artifact_retention_days: Option<i64>,
    git_binary: Option<String>,
    git_mirror_dir: Option<String>,
    git_timeout_secs: Option<u64>,
    git_mirror_retention_days: Option<i64>,
    git_max_push_bytes: Option<u64>,
    relay_listen: Option<String>,
    relay_ttl_secs: Option<u64>,
    relay_max_body_bytes: Option<usize>,
    language_temporal_clauses: Option<bool>,
    custody_profile: Option<String>,
}

/// Temporal (windowed) sentence clauses are OFF unless the operator declares otherwise. An absent
/// key is the shipped default, never an implicit enable.
const DEFAULT_TEMPORAL_CLAUSES: bool = false;

/// Default artifact-store cap (~5 MiB), mirroring the core default so an absent config matches.
const DEFAULT_ARTIFACT_MAX_BYTES: usize = 5 * 1024 * 1024;
/// Default artifact-store retention window in days.
const DEFAULT_ARTIFACT_RETENTION_DAYS: i64 = 90;
/// git-native defaults, taken from the core so an absent config matches the broker's own.
const DEFAULT_GIT_BINARY: &str = cermet_core::git::DEFAULT_GIT_BINARY;
const DEFAULT_MIRROR_DIR: &str = cermet_core::git::DEFAULT_MIRROR_DIR;
const DEFAULT_GIT_TIMEOUT_SECS: u64 = cermet_core::git::DEFAULT_GIT_TIMEOUT_SECS;
const DEFAULT_MIRROR_RETENTION_DAYS: i64 = cermet_core::git::DEFAULT_MIRROR_RETENTION_DAYS;
const DEFAULT_MAX_PUSH_BYTES: u64 = cermet_core::git::DEFAULT_MAX_PUSH_BYTES;

/// Fold the declared `git_*` keys onto the core's defaults.
///
/// `git_binary` DEFAULTS to the box's git: there is no registration
/// act. Usability is checked per request, so the daemon boots identically whether or not this box
/// has a git, and a missing or too-old one is a legible refusal naming this key.
fn git_config(raw: &RawConfig) -> cermet_core::git::GitConfig {
    cermet_core::git::GitConfig {
        binary: raw
            .git_binary
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_GIT_BINARY)),
        mirror_dir: raw
            .git_mirror_dir
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_MIRROR_DIR)),
        timeout: std::time::Duration::from_secs(
            raw.git_timeout_secs.unwrap_or(DEFAULT_GIT_TIMEOUT_SECS),
        ),
        mirror_retention_days: raw
            .git_mirror_retention_days
            .unwrap_or(DEFAULT_MIRROR_RETENTION_DAYS),
        max_push_bytes: raw.git_max_push_bytes.unwrap_or(DEFAULT_MAX_PUSH_BYTES),
    }
}
/// Relay defaults, taken from the core so an absent config matches the broker's own.
const DEFAULT_RELAY_LISTEN: &str = cermet_core::DEFAULT_RELAY_LISTEN;
const DEFAULT_RELAY_TTL_SECS: u64 = cermet_core::DEFAULT_RELAY_TTL_SECS;
const DEFAULT_RELAY_MAX_BODY_BYTES: usize = cermet_core::DEFAULT_RELAY_MAX_BODY_BYTES;

impl DaemonConfig {
    /// The embedded / same-uid dev defaults used when no config file is present.
    /// `service_mode = false` — the fail-open path the local loop relies on.
    fn dev_default() -> Self {
        DaemonConfig {
            git: cermet_core::git::GitConfig::default(),
            service_uid: 0,
            approver_uid: 0,
            // Dev/embedded: the agent resolves to getuid() at wiring time; this field is unused.
            agent_uid: 0,
            service_mode: false,
            runtime_dir: PathBuf::from(DEFAULT_RUNTIME_DIR),
            // Dev/embedded: agent.sock shares the single runtime dir.
            agent_runtime_dir: PathBuf::from(DEFAULT_RUNTIME_DIR),
            sentence_rules_path: None,
            artifact_max_bytes: DEFAULT_ARTIFACT_MAX_BYTES,
            artifact_retention_days: DEFAULT_ARTIFACT_RETENTION_DAYS,
            temporal_clauses: DEFAULT_TEMPORAL_CLAUSES,
            relay: cermet_core::RelayConfig::default(),
            // CUSTODY-LADDER: the dev/embedded loop loads no service key source (the fenced
            // override / login keychain), so it declares no custody rung. Service mode REQUIRES
            // one — enforced once, in `parse`.
            custody_profile: None,
        }
    }

    /// Assert the config is coherent with the uid the daemon ACTUALLY runs as.
    ///
    /// The central wiring passes `nix::unistd::getuid()` so this stays getuid-free and testable.
    /// In dev mode (`!service_mode`) this is a no-op — the embedded same-uid loop runs as one uid
    /// and must not be tripped. In service mode it fails CLOSED on any of:
    ///   * either uid is `0` (root) in the config — defense in depth beyond parse-time;
    ///   * `service_uid != kernel_uid` — the daemon is not running as `cermet`, so the boundary
    ///     is not in force;
    ///   * `approver_uid == kernel_uid` — the daemon could drive its own operator plane;
    ///   * `agent_uid` is `0`, equals `kernel_uid`, or equals `approver_uid` —
    ///     any of these collapses the distinct agent plane the kernel gate relies on.
    pub fn validate_runtime(&self, kernel_uid: u32) -> Result<(), ConfigError> {
        if !self.service_mode {
            return Ok(());
        }
        if self.service_uid == 0 {
            return Err(ConfigError::RootUid {
                which: "service_uid",
            });
        }
        if self.approver_uid == 0 {
            return Err(ConfigError::RootUid {
                which: "approver_uid",
            });
        }
        if self.service_uid != kernel_uid {
            return Err(ConfigError::ServiceUidMismatch {
                configured: self.service_uid,
                kernel: kernel_uid,
            });
        }
        if self.approver_uid == kernel_uid {
            return Err(ConfigError::ApproverEqualsKernel { kernel: kernel_uid });
        }
        // Mirror the parse-time agent pairwise guards at runtime (defense in depth
        // beyond parse) — the agent uid must be nonzero, distinct from the daemon (kernel) uid, and
        // distinct from the approver uid.
        if self.agent_uid == 0 {
            return Err(ConfigError::RootUid { which: "agent_uid" });
        }
        if self.agent_uid == kernel_uid {
            return Err(ConfigError::AgentEqualsKernel { kernel: kernel_uid });
        }
        if self.agent_uid == self.approver_uid {
            return Err(ConfigError::AgentEqualsApprover {
                uid: self.agent_uid,
            });
        }
        Ok(())
    }
}

/// Map the raw `CERMET_SERVICE_MODE` value to the service-mode signal. Only the exact
/// value `"1"` turns service mode on; unset / "0" / "" / anything else ⇒ dev mode. Pure so the
/// signal logic is unit-testable without touching the process environment.
pub fn service_mode_from_signal(raw: Option<&str>) -> bool {
    raw == Some("1")
}

/// Read the explicit service-mode launch signal from the process environment. This is the
/// ONLY place that touches the env; `load`/`parse` take the resulting bool so they stay pure.
pub fn service_mode_from_env() -> bool {
    service_mode_from_signal(std::env::var(SERVICE_MODE_ENV).ok().as_deref())
}

/// Load and validate the daemon config at `path`, with `service_mode` supplied by the EXPLICIT
/// launch signal — NOT inferred from the config. The central wiring passes
/// [`service_mode_from_env`].
///
/// * Missing file ⇒ dev defaults (`service_mode` honoured but the file is absent so it stays the
///   embedded shape). This is the ONLY fall-open leg.
/// * A present-but-unreadable file ⇒ `Err(Io)` (fail closed — never silently dev-default over a
///   real-but-broken config).
/// * A present, parseable file with a configured `service_uid` ⇒ its identity is fully validated;
///   any uid-collapse / root / empty-runtime_dir contradiction is rejected REGARDLESS of the
///   signal. The signal only flips the `service_mode` flag (and thus the runtime kernel-uid
///   assertion in [`DaemonConfig::validate_runtime`]).
pub fn load(path: &Path, service_mode: bool) -> Result<DaemonConfig, ConfigError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut cfg = DaemonConfig::dev_default();
            cfg.service_mode = service_mode;
            return Ok(cfg);
        }
        Err(e) => return Err(ConfigError::Io(e.to_string())),
    };
    parse(&text, service_mode)
}

/// Parse + validate already-read TOML text. Split from [`load`] so tests can exercise the
/// validation without touching the filesystem. `service_mode` is the EXPLICIT launch signal, not
/// inferred from `service_uid` presence.
///
/// Parse-time identity validation fires whenever a `service_uid` is configured, independent of the
/// signal — a broken identity should never load. The signal only sets the `service_mode` flag.
pub fn parse(text: &str, service_mode: bool) -> Result<DaemonConfig, ConfigError> {
    let cfg = parse_shape(text, service_mode)?;
    // CUSTODY-LADDER: one place asserts the declared-rung requirement, for BOTH config shapes and
    // AFTER every other validation — so a config with an undeclared rung AND a uid collapse still
    // reports the uid collapse, which is the more fundamental defect.
    if cfg.service_mode && cfg.custody_profile.is_none() {
        return Err(ConfigError::CustodyProfileMissing);
    }
    Ok(cfg)
}

fn parse_shape(text: &str, service_mode: bool) -> Result<DaemonConfig, ConfigError> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError::Malformed(e.to_string()))?;

    // Computed before any field is moved out of `raw`.
    let git = git_config(&raw);
    // Validate the SPELLING here (in both shapes): an unrecognized rung is a refusal, never a
    // fallback to any other rung.
    let custody_profile = match raw.custody_profile.as_deref() {
        Some(value) => Some(CustodyProfile::parse(value).ok_or_else(|| {
            ConfigError::UnknownCustodyProfile {
                value: value.to_string(),
            }
        })?),
        None => None,
    };

    if raw.service_uid.is_none() {
        // No configured service identity — the dev/embedded shape. Keep the fail-open defaults and
        // carry the explicit signal onto service_mode.
        let mut cfg = DaemonConfig::dev_default();
        cfg.service_mode = service_mode;
        // Dev/embedded: no distinct agent uid; agent.sock shares the single runtime dir. An
        // `agent_runtime_dir` key in the dev shape is honoured for parity but defaults to the runtime
        // dir (the same-uid path). The central wiring overrides both with CERMET_HOME/run at boot.
        cfg.agent_runtime_dir = raw
            .agent_runtime_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| cfg.runtime_dir.clone());
        cfg.sentence_rules_path = raw.sentence_rules_path.map(PathBuf::from);
        if let Some(listen) = raw.relay_listen {
            cfg.relay.listen = listen;
        }
        if let Some(n) = raw.relay_ttl_secs {
            cfg.relay.ttl_secs = n;
        }
        if let Some(n) = raw.relay_max_body_bytes {
            cfg.relay.max_body_bytes = n;
        }
        if let Some(n) = raw.artifact_max_bytes {
            cfg.artifact_max_bytes = n;
        }
        if let Some(n) = raw.artifact_retention_days {
            cfg.artifact_retention_days = n;
        }
        if let Some(enabled) = raw.language_temporal_clauses {
            cfg.temporal_clauses = enabled;
        }
        cfg.git = git;
        cfg.custody_profile = custody_profile;
        return Ok(cfg);
    }

    let service_uid = raw.service_uid.expect("checked is_some above");
    // approver_uid is REQUIRED once a service identity is configured; an unset one is a
    // misconfiguration, not 0.
    let approver_uid = raw.approver_uid.ok_or(ConfigError::RootUid {
        // An absent approver_uid would default to 0 (root) — reject it as the root case so
        // the operator gets a clear "approver missing/root" failure rather than a silent uid 0.
        which: "approver_uid (missing)",
    })?;
    // A configured service identity REQUIRES a distinct agent uid. An absent
    // one is a misconfiguration, not a silent 0 (root) — reject it as the root case so the operator
    // gets a clear "agent missing/root" failure. No override: the human-only-approval kernel claim must
    // never be true only sometimes.
    let agent_uid = raw.agent_uid.ok_or(ConfigError::RootUid {
        which: "agent_uid (missing)",
    })?;

    // Fail-closed validation (order: cheapest contradiction first).
    if service_uid == 0 {
        return Err(ConfigError::RootUid {
            which: "service_uid",
        });
    }
    if approver_uid == 0 {
        return Err(ConfigError::RootUid {
            which: "approver_uid",
        });
    }
    if agent_uid == 0 {
        return Err(ConfigError::RootUid { which: "agent_uid" });
    }
    if approver_uid == service_uid {
        return Err(ConfigError::ApproverEqualsService { uid: approver_uid });
    }
    // The agent uid must be distinct from BOTH the daemon (service) uid and the
    // approver uid — the two-plane kernel separation rests on all three being disjoint.
    if agent_uid == service_uid {
        return Err(ConfigError::AgentEqualsService { uid: agent_uid });
    }
    if agent_uid == approver_uid {
        return Err(ConfigError::AgentEqualsApprover { uid: agent_uid });
    }

    let runtime_dir = match raw.runtime_dir {
        Some(s) if !s.trim().is_empty() => PathBuf::from(s),
        Some(_) => return Err(ConfigError::EmptyRuntimeDir),
        None => PathBuf::from(DEFAULT_RUNTIME_DIR),
    };
    // The separate agent-socket dir defaults to /run/cermetd-agents. An explicitly
    // empty value is the same misconfiguration as an empty runtime_dir — reject it.
    let agent_runtime_dir = match raw.agent_runtime_dir {
        Some(s) if !s.trim().is_empty() => PathBuf::from(s),
        Some(_) => return Err(ConfigError::EmptyRuntimeDir),
        None => PathBuf::from(DEFAULT_AGENT_RUNTIME_DIR),
    };

    Ok(DaemonConfig {
        service_uid,
        approver_uid,
        agent_uid,
        // The EXPLICIT launch signal sets service_mode, NOT the presence of service_uid.
        service_mode,
        runtime_dir,
        agent_runtime_dir,
        sentence_rules_path: raw.sentence_rules_path.map(PathBuf::from),
        artifact_max_bytes: raw.artifact_max_bytes.unwrap_or(DEFAULT_ARTIFACT_MAX_BYTES),
        relay: cermet_core::RelayConfig {
            listen: raw
                .relay_listen
                .unwrap_or_else(|| DEFAULT_RELAY_LISTEN.to_string()),
            ttl_secs: raw.relay_ttl_secs.unwrap_or(DEFAULT_RELAY_TTL_SECS),
            max_body_bytes: raw
                .relay_max_body_bytes
                .unwrap_or(DEFAULT_RELAY_MAX_BODY_BYTES),
        },
        artifact_retention_days: raw
            .artifact_retention_days
            .unwrap_or(DEFAULT_ARTIFACT_RETENTION_DAYS),
        temporal_clauses: raw
            .language_temporal_clauses
            .unwrap_or(DEFAULT_TEMPORAL_CLAUSES),
        git,
        custody_profile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SERVICE: &str = r#"
        service_uid = 900
        approver_uid = 1000
        agent_uid = 910
        runtime_dir = "/var/lib/cermetd"
        custody_profile = "systemd-host"
    "#;

    /// CUSTODY-LADDER M1: which mechanism holds the vault key is a DECLARED setting, and in service
    /// mode it is REQUIRED. There is no default rung: an absent key would make the daemon guess a
    /// key SOURCE, and guessing wrong is either "opens nothing" or — worse — "opens something else".
    /// Fail closed and name the command that writes it.
    #[test]
    fn service_mode_requires_a_declared_custody_profile() {
        let undeclared = VALID_SERVICE.replace("custody_profile = \"systemd-host\"", "");
        assert_eq!(
            parse(&undeclared, true).unwrap_err(),
            ConfigError::CustodyProfileMissing
        );
        // Dev mode never loads a service key source, so it neither needs nor invents one.
        assert_eq!(parse(&undeclared, false).unwrap().custody_profile, None);
    }

    /// The declared spelling is the contract `cermet setup` writes. An unrecognized one is refused
    /// by name rather than silently treated as the weakest (or the strongest) rung.
    #[test]
    fn a_declared_custody_profile_parses_and_an_unknown_one_fails_closed() {
        for spelling in ["systemd-tpm2+host", "systemd-host", "file-protected"] {
            let text = VALID_SERVICE.replace("systemd-host", spelling);
            assert_eq!(
                parse(&text, true).unwrap().custody_profile,
                CustodyProfile::parse(spelling),
                "{spelling} must round-trip through the config"
            );
        }
        let bogus = VALID_SERVICE.replace("systemd-host", "uid-file");
        assert_eq!(
            parse(&bogus, true).unwrap_err(),
            ConfigError::UnknownCustodyProfile {
                value: "uid-file".to_string()
            }
        );
    }

    #[test]
    fn valid_service_config_yields_service_mode_true() {
        // service_mode comes from the EXPLICIT launch signal (passed true here), not from
        // service_uid presence.
        let cfg = parse(VALID_SERVICE, true).expect("a well-formed service config loads");
        assert!(
            cfg.service_mode,
            "the explicit service signal carries onto service_mode"
        );
        assert_eq!(cfg.service_uid, 900);
        assert_eq!(cfg.approver_uid, 1000);
        assert_eq!(cfg.runtime_dir, PathBuf::from("/var/lib/cermetd"));
    }

    /// Temporal (windowed) clauses are OFF unless declared. An ABSENT key must be that default in
    /// BOTH config shapes — a dev daemon that quietly kept them on
    /// would make the suspension a property of the install rather than of the product.
    #[test]
    fn temporal_clauses_default_off_in_both_config_shapes() {
        assert!(
            !parse(VALID_SERVICE, true).unwrap().temporal_clauses,
            "an absent language_temporal_clauses must default OFF in the service shape"
        );
        assert!(
            !parse("", false).unwrap().temporal_clauses,
            "an absent language_temporal_clauses must default OFF in the dev shape"
        );
        assert!(
            !DaemonConfig::dev_default().temporal_clauses,
            "the no-config-file fallback must default OFF too"
        );
    }

    /// The other gate position: the declared switch is honoured in both shapes, so an operator who
    /// wants the windowed clauses back gets them by declaring one key.
    #[test]
    fn temporal_clauses_opt_in_is_honoured_in_both_config_shapes() {
        let service = format!("{VALID_SERVICE}\nlanguage_temporal_clauses = true\n");
        assert!(parse(&service, true).unwrap().temporal_clauses);
        assert!(
            parse("language_temporal_clauses = true\n", false)
                .unwrap()
                .temporal_clauses,
            "the dev shape reads the same key"
        );
        // An explicit `false` is still false — declaring the key does not itself turn it on.
        let off = format!("{VALID_SERVICE}\nlanguage_temporal_clauses = false\n");
        assert!(!parse(&off, true).unwrap().temporal_clauses);
    }

    #[test]
    fn approver_equal_to_service_is_rejected() {
        let toml = r#"
            service_uid = 900
            approver_uid = 900
            agent_uid = 910
            runtime_dir = "/var/lib/cermetd"
        "#;
        assert_eq!(
            parse(toml, true).unwrap_err(),
            ConfigError::ApproverEqualsService { uid: 900 },
            "approver_uid == service_uid collapses the human-only approval split"
        );
    }

    #[test]
    fn service_uid_zero_is_rejected() {
        let toml = r#"
            service_uid = 0
            approver_uid = 1000
            agent_uid = 910
            runtime_dir = "/var/lib/cermetd"
        "#;
        assert_eq!(
            parse(toml, true).unwrap_err(),
            ConfigError::RootUid {
                which: "service_uid"
            },
            "service_uid 0 (root) defeats the separate-uid boundary"
        );
    }

    #[test]
    fn approver_uid_zero_is_rejected() {
        let toml = r#"
            service_uid = 900
            approver_uid = 0
            agent_uid = 910
            runtime_dir = "/var/lib/cermetd"
        "#;
        assert_eq!(
            parse(toml, true).unwrap_err(),
            ConfigError::RootUid {
                which: "approver_uid"
            },
            "approver_uid 0 (root) is rejected"
        );
    }

    #[test]
    fn empty_runtime_dir_is_rejected_in_service_mode() {
        let toml = r#"
            service_uid = 900
            approver_uid = 1000
            agent_uid = 910
            runtime_dir = ""
        "#;
        assert_eq!(
            parse(toml, true).unwrap_err(),
            ConfigError::EmptyRuntimeDir,
            "service mode requires a non-empty runtime_dir"
        );
    }

    // The separate agent-socket dir knob is REVIVED. A configured
    // `agent_runtime_dir` is honoured (the distinct `cermet-agents`-group dir where agent.sock binds
    // at 0660), disjoint from the ctl runtime_dir.
    #[test]
    fn agent_runtime_dir_knob_is_honoured() {
        let toml = r#"
            service_uid = 900
            approver_uid = 1000
            agent_uid = 910
            runtime_dir = "/run/cermetd"
            agent_runtime_dir = "/run/cermetd-agents"
            custody_profile = "systemd-host"
        "#;
        let cfg = parse(toml, true).expect("loads");
        assert_eq!(cfg.runtime_dir, PathBuf::from("/run/cermetd"));
        assert_eq!(
            cfg.agent_runtime_dir,
            PathBuf::from("/run/cermetd-agents"),
            "the agent socket dir is the separate configured dir"
        );
    }

    #[test]
    fn agent_runtime_dir_defaults_to_run_cermetd_agents_in_service_mode() {
        // With no agent_runtime_dir configured, the separate agent dir defaults to /run/cermetd-agents.
        let cfg = parse(VALID_SERVICE, true).expect("loads");
        assert_eq!(
            cfg.agent_runtime_dir,
            PathBuf::from("/run/cermetd-agents"),
            "an unset agent_runtime_dir defaults to the separate service dir"
        );
    }

    // ---- the distinct agent uid is REQUIRED + pairwise-disjoint in service mode

    #[test]
    fn missing_agent_uid_in_service_mode_is_rejected() {
        // A configured service identity REQUIRES a distinct agent uid. An absent one would default
        // to 0/root; reject rather than serve with a collapsed or root agent plane.
        let toml = r#"
            service_uid = 900
            approver_uid = 1000
            runtime_dir = "/var/lib/cermetd"
        "#;
        assert_eq!(
            parse(toml, true).unwrap_err(),
            ConfigError::RootUid {
                which: "agent_uid (missing)"
            },
            "service mode with no agent_uid must be rejected (required, not optional)"
        );
    }

    #[test]
    fn agent_uid_zero_is_rejected() {
        let toml = r#"
            service_uid = 900
            approver_uid = 1000
            agent_uid = 0
            runtime_dir = "/var/lib/cermetd"
        "#;
        assert_eq!(
            parse(toml, true).unwrap_err(),
            ConfigError::RootUid { which: "agent_uid" },
            "agent_uid 0 (root) defeats the distinct-agent boundary"
        );
    }

    #[test]
    fn agent_uid_equal_to_service_is_rejected() {
        let toml = r#"
            service_uid = 900
            approver_uid = 1000
            agent_uid = 900
            runtime_dir = "/var/lib/cermetd"
        "#;
        assert_eq!(
            parse(toml, true).unwrap_err(),
            ConfigError::AgentEqualsService { uid: 900 },
            "agent_uid == service_uid collapses the agent plane onto the daemon uid"
        );
    }

    #[test]
    fn agent_uid_equal_to_approver_is_rejected() {
        let toml = r#"
            service_uid = 900
            approver_uid = 1000
            agent_uid = 1000
            runtime_dir = "/var/lib/cermetd"
        "#;
        assert_eq!(
            parse(toml, true).unwrap_err(),
            ConfigError::AgentEqualsApprover { uid: 1000 },
            "agent_uid == approver_uid would let a compromised agent drive ctl.sock"
        );
    }

    #[test]
    fn valid_service_config_carries_the_agent_uid() {
        let cfg = parse(VALID_SERVICE, true).expect("a well-formed service config loads");
        assert_eq!(cfg.agent_uid, 910, "the distinct agent uid is parsed");
    }

    #[test]
    fn absent_file_yields_dev_defaults_with_service_mode_false() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        let cfg = load(&path, false).expect("a missing config file yields dev defaults");
        assert!(
            !cfg.service_mode,
            "an absent config is the fail-open embedded/dev path: service_mode = false"
        );
        assert_eq!(cfg.runtime_dir, PathBuf::from(DEFAULT_RUNTIME_DIR));
    }

    #[test]
    fn malformed_toml_is_err() {
        let cfg = parse("this is = = not valid toml ][", true);
        assert!(
            matches!(cfg, Err(ConfigError::Malformed(_))),
            "a present-but-malformed config must fail closed, not dev-default"
        );
    }

    #[test]
    fn present_unreadable_file_fails_closed_not_dev_default() {
        // A directory at the config path makes read_to_string fail with something OTHER than
        // NotFound → must be an Io error, NOT a silent fall-through to dev defaults.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config-as-dir.toml");
        std::fs::create_dir(&path).unwrap();
        assert!(
            matches!(load(&path, true), Err(ConfigError::Io(_))),
            "a present-but-unreadable config must fail closed, never silently dev-default"
        );
    }

    #[test]
    fn missing_approver_in_service_mode_is_rejected() {
        // A service_uid with NO approver_uid would default to 0/root; reject rather than serve
        // with a root or absent approver.
        let toml = r#"
            service_uid = 900
            runtime_dir = "/var/lib/cermetd"
        "#;
        assert!(
            matches!(parse(toml, true), Err(ConfigError::RootUid { .. })),
            "service mode with no approver_uid must be rejected"
        );
    }

    #[test]
    fn config_without_service_uid_is_dev_shape() {
        // A config file present but with no service_uid is still the embedded/dev shape:
        // service_mode stays false. Unknown keys (e.g. the retired host_allowlist)
        // parse without effect.
        let toml = r#"
            host_allowlist = ["api.github.com"]
        "#;
        let cfg = parse(toml, false).expect("a service_uid-less config is the dev shape");
        assert!(!cfg.service_mode);
    }

    // ---- service mode is an EXPLICIT launch signal, validated against the kernel uid

    #[test]
    fn service_mode_signal_true_yields_service_mode_true() {
        // The explicit launch signal (CERMET_SERVICE_MODE=1 / --service) — not service_uid presence
        // — is what flips service_mode on.
        let cfg = parse(VALID_SERVICE, true).expect("a well-formed service config loads");
        assert!(
            cfg.service_mode,
            "the explicit service signal means service mode"
        );
        assert_eq!(cfg.service_uid, 900);
        assert_eq!(cfg.approver_uid, 1000);
    }

    #[test]
    fn absent_service_signal_yields_dev_even_with_service_uid_present() {
        // A configured service_uid must NOT by itself flip service mode. Without the
        // explicit launch signal the daemon stays in dev mode (warn-and-serve), never the
        // installed-default-fail-open path.
        let cfg = parse(VALID_SERVICE, false).expect("a config with no signal is dev shape");
        assert!(
            !cfg.service_mode,
            "service_uid presence must NOT infer service mode"
        );
    }

    #[test]
    fn service_mode_from_env_reads_explicit_signal() {
        assert!(
            service_mode_from_signal(Some("1")),
            "CERMET_SERVICE_MODE=1 is the explicit on signal"
        );
        assert!(
            !service_mode_from_signal(None),
            "an absent env var is the dev default"
        );
        assert!(
            !service_mode_from_signal(Some("0")),
            "CERMET_SERVICE_MODE=0 is off"
        );
        assert!(!service_mode_from_signal(Some("")), "an empty value is off");
    }

    #[test]
    fn validate_runtime_passes_coherent_service_config() {
        let cfg = parse(VALID_SERVICE, true).unwrap();
        // service_uid == kernel uid (900), approver_uid (1000) != kernel uid, both nonzero.
        assert_eq!(cfg.validate_runtime(900), Ok(()));
    }

    #[test]
    fn validate_runtime_rejects_service_uid_not_kernel_uid() {
        let cfg = parse(VALID_SERVICE, true).unwrap();
        // The daemon was launched as uid 901 but the config names service_uid 900.
        assert_eq!(
            cfg.validate_runtime(901),
            Err(ConfigError::ServiceUidMismatch {
                configured: 900,
                kernel: 901
            }),
            "service_uid must equal the kernel uid the daemon actually runs as"
        );
    }

    #[test]
    fn validate_runtime_rejects_approver_equal_to_kernel_uid() {
        // VALID_SERVICE has service_uid 900, approver_uid 1000. The mismatch check is ordered
        // first, so to exercise the approver-collapse branch the kernel uid must equal BOTH
        // service_uid and approver_uid — i.e. a config where service_uid happens to equal the
        // approver is already rejected by parse(); construct the collapse directly.
        let cfg = DaemonConfig {
            git: cermet_core::git::GitConfig::default(),
            custody_profile: Some(CustodyProfile::SystemdHost),
            service_uid: 1000,
            approver_uid: 1000,
            agent_uid: 1001,
            service_mode: true,
            runtime_dir: PathBuf::from("/run/cermetd"),
            agent_runtime_dir: PathBuf::from("/run/cermetd-agents"),
            sentence_rules_path: None,
            artifact_max_bytes: 5 * 1024 * 1024,
            artifact_retention_days: 90,
            temporal_clauses: false,
            relay: cermet_core::RelayConfig::default(),
        };
        assert_eq!(
            cfg.validate_runtime(1000),
            Err(ConfigError::ApproverEqualsKernel { kernel: 1000 }),
            "the daemon must never run as the approver uid (it could approve its own Ask grants)"
        );
    }

    #[test]
    fn validate_runtime_rejects_kernel_uid_zero() {
        let cfg = parse(VALID_SERVICE, true).unwrap();
        assert_eq!(
            cfg.validate_runtime(0),
            Err(ConfigError::ServiceUidMismatch {
                configured: 900,
                kernel: 0
            }),
            "running the service as root (uid 0) is rejected via the mismatch (config service_uid is nonzero)"
        );
    }

    #[test]
    fn validate_runtime_rejects_zero_uids_in_config() {
        // A config that somehow carried a zero uid (defense in depth beyond parse()): validate_runtime
        // independently refuses both zero uids even if the kernel uid matched.
        let cfg = DaemonConfig {
            git: cermet_core::git::GitConfig::default(),
            custody_profile: Some(CustodyProfile::SystemdHost),
            service_uid: 0,
            approver_uid: 1000,
            agent_uid: 1001,
            service_mode: true,
            runtime_dir: PathBuf::from("/run/cermetd"),
            agent_runtime_dir: PathBuf::from("/run/cermetd-agents"),
            sentence_rules_path: None,
            artifact_max_bytes: 5 * 1024 * 1024,
            artifact_retention_days: 90,
            temporal_clauses: false,
            relay: cermet_core::RelayConfig::default(),
        };
        assert_eq!(
            cfg.validate_runtime(0),
            Err(ConfigError::RootUid {
                which: "service_uid"
            }),
            "service_uid 0 is rejected at runtime even if kernel uid matched"
        );
        let cfg = DaemonConfig {
            git: cermet_core::git::GitConfig::default(),
            custody_profile: Some(CustodyProfile::SystemdHost),
            service_uid: 900,
            approver_uid: 0,
            agent_uid: 1001,
            service_mode: true,
            runtime_dir: PathBuf::from("/run/cermetd"),
            agent_runtime_dir: PathBuf::from("/run/cermetd-agents"),
            sentence_rules_path: None,
            artifact_max_bytes: 5 * 1024 * 1024,
            artifact_retention_days: 90,
            temporal_clauses: false,
            relay: cermet_core::RelayConfig::default(),
        };
        assert_eq!(
            cfg.validate_runtime(900),
            Err(ConfigError::RootUid {
                which: "approver_uid"
            }),
            "approver_uid 0 is rejected at runtime"
        );
    }

    #[test]
    fn validate_runtime_rejects_agent_equal_to_kernel_uid() {
        // The daemon must never run as the AGENT uid. Construct the collapse
        // directly (parse() already rejects agent==service, and the mismatch check is ordered first).
        let cfg = DaemonConfig {
            git: cermet_core::git::GitConfig::default(),
            custody_profile: Some(CustodyProfile::SystemdHost),
            service_uid: 900,
            approver_uid: 1000,
            agent_uid: 900,
            service_mode: true,
            runtime_dir: PathBuf::from("/run/cermetd"),
            agent_runtime_dir: PathBuf::from("/run/cermetd-agents"),
            sentence_rules_path: None,
            artifact_max_bytes: 5 * 1024 * 1024,
            artifact_retention_days: 90,
            temporal_clauses: false,
            relay: cermet_core::RelayConfig::default(),
        };
        assert_eq!(
            cfg.validate_runtime(900),
            Err(ConfigError::AgentEqualsKernel { kernel: 900 }),
            "the daemon must never run as the agent uid"
        );
    }

    #[test]
    fn validate_runtime_rejects_agent_equal_to_approver() {
        // Mirror: agent == approver is refused at runtime too (defense in depth).
        let cfg = DaemonConfig {
            git: cermet_core::git::GitConfig::default(),
            custody_profile: Some(CustodyProfile::SystemdHost),
            service_uid: 900,
            approver_uid: 1000,
            agent_uid: 1000,
            service_mode: true,
            runtime_dir: PathBuf::from("/run/cermetd"),
            agent_runtime_dir: PathBuf::from("/run/cermetd-agents"),
            sentence_rules_path: None,
            artifact_max_bytes: 5 * 1024 * 1024,
            artifact_retention_days: 90,
            temporal_clauses: false,
            relay: cermet_core::RelayConfig::default(),
        };
        assert_eq!(
            cfg.validate_runtime(900),
            Err(ConfigError::AgentEqualsApprover { uid: 1000 }),
            "agent == approver is rejected at runtime"
        );
    }

    #[test]
    fn validate_runtime_rejects_agent_uid_zero_in_config() {
        let cfg = DaemonConfig {
            git: cermet_core::git::GitConfig::default(),
            custody_profile: Some(CustodyProfile::SystemdHost),
            service_uid: 900,
            approver_uid: 1000,
            agent_uid: 0,
            service_mode: true,
            runtime_dir: PathBuf::from("/run/cermetd"),
            agent_runtime_dir: PathBuf::from("/run/cermetd-agents"),
            sentence_rules_path: None,
            artifact_max_bytes: 5 * 1024 * 1024,
            artifact_retention_days: 90,
            temporal_clauses: false,
            relay: cermet_core::RelayConfig::default(),
        };
        assert_eq!(
            cfg.validate_runtime(900),
            Err(ConfigError::RootUid { which: "agent_uid" }),
            "agent_uid 0 is rejected at runtime"
        );
    }

    #[test]
    fn validate_runtime_passes_coherent_service_config_with_distinct_agent() {
        // service_uid == kernel (900), approver (1000) and agent (910) both distinct + nonzero.
        let cfg = parse(VALID_SERVICE, true).unwrap();
        assert_eq!(cfg.validate_runtime(900), Ok(()));
    }

    #[test]
    fn validate_runtime_is_noop_in_dev_mode() {
        // Dev mode (no explicit signal): validate_runtime never asserts — the embedded same-uid loop
        // (service_uid == approver_uid == kernel uid) keeps working.
        let cfg = parse(VALID_SERVICE, false).unwrap();
        assert!(!cfg.service_mode);
        assert_eq!(
            cfg.validate_runtime(12345),
            Ok(()),
            "dev mode performs no kernel-uid assertion"
        );
    }
}
