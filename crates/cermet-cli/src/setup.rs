//! Linux service provisioning for `cermet setup`.
//!
//! This is a port of the former `dist/install.sh`, not a second installation design. Packages
//! place the two binaries and vendored source files; this module owns every privileged mutation.
//! Pure planning, parsing, and rendering stay unit tested here.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use cermet_ipc::custody::CustodyProfile;
use rand::RngCore;

use crate::CliError;

/// macOS reserves the leading underscore for role accounts; Linux has no such convention. Only the
/// daemon's own account differs — the approver/agent group names are a cross-platform contract with
/// the daemon (`serve::resolve_group_gid("cermet-approvers")`).
#[cfg(target_os = "macos")]
const SERVICE_USER: &str = "_cermet";
#[cfg(target_os = "macos")]
const SERVICE_GROUP: &str = "_cermet";
#[cfg(not(target_os = "macos"))]
const SERVICE_USER: &str = "cermet";
#[cfg(not(target_os = "macos"))]
const SERVICE_GROUP: &str = "cermet";
const APPROVERS_GROUP: &str = "cermet-approvers";
const AGENT_USER: &str = "cermet-agent";
const AGENTS_GROUP: &str = "cermet-agents";
/// gid 0's group name. macOS has no `root` group — `install -g root` fails there.
#[cfg(target_os = "macos")]
const ROOT_GROUP: &str = "wheel";
#[cfg(not(target_os = "macos"))]
const ROOT_GROUP: &str = "root";

/// The prefix `setup` publishes into, and the only directory tree it owns on the PATH.
///
/// macOS does NOT use `/usr/local`. On a Homebrew Mac that prefix belongs to the human's own admin
/// account, and `install -d -o root` rewrites an existing directory's owner, so publishing there
/// would silently seize Homebrew's bin dir and
/// break every later `brew` write with no undo and no receipt line. It is also the wrong place on
/// the merits: root launches `cermetd` from this path at boot, and an operator-writable directory
/// is exactly what a compromised or prompt-injected agent running as the operator uid can rewrite.
/// `/opt/cermet` is
/// created by setup, owned by root, and shared with nothing — which is what makes the
/// `assert_root_secure` below a real check instead of one satisfied by the line above it.
#[cfg(target_os = "macos")]
pub(crate) const INSTALL_PREFIX: &str = "/opt/cermet";
#[cfg(target_os = "macos")]
pub(crate) const INSTALL_BIN_DIR: &str = "/opt/cermet/bin";
#[cfg(not(target_os = "macos"))]
pub(crate) const INSTALL_PREFIX: &str = "/usr/local";
#[cfg(not(target_os = "macos"))]
pub(crate) const INSTALL_BIN_DIR: &str = "/usr/local/bin";

/// ONE-BINARY: the single regular executable this install publishes. Everything else in the bin dir
/// that carries a cermet name is a relative symlink to THIS file.
pub(crate) const MULTICALL_TARGET: &str = "cermet";

/// The two role aliases, published as EXACT relative symlinks to [`MULTICALL_TARGET`] in the same
/// directory. They are role identification, not a privilege boundary: `execve` gives a process the
/// credentials its caller chose, so the name only decides which entry the one binary runs.
///
/// * `cermetd` is the path systemd's `ExecStart` and launchd's `ProgramArguments[0]` name, so it is
///   what an operator sees in `systemctl status`, a process listing, and the journal.
/// * `git-remote-cermet` is git's lookup key: git resolves a remote helper by NAME on PATH, which is
///   why it has to sit beside `cermet` on an installed PATH.
///
/// RELATIVE, not absolute: the relationship survives a relocated prefix, and `ls -l` in the bin dir
/// shows the whole story without resolving anything.
pub(crate) const MULTICALL_ALIASES: [&str; 2] = ["cermetd", "git-remote-cermet"];

#[cfg(target_os = "macos")]
const CLI_DEST: &str = "/opt/cermet/bin/cermet";
#[cfg(not(target_os = "macos"))]
const CLI_DEST: &str = "/usr/local/bin/cermet";

/// How `/opt/cermet/bin` reaches an operator's PATH: one declarative line read by
/// `/usr/libexec/path_helper` at login. No symlinks — a symlink into `/usr/local/bin` would put the
/// launch path back in an operator-writable directory, which is exactly what this prefix avoids.
/// `path_helper` APPENDS `/etc/paths.d/*` after `/etc/paths` (whose first entry is
/// `/usr/local/bin`), so a stale copy there would still win the lookup — which is why any
/// `/usr/local/bin/{cermet,cermetd}` left by an earlier install are retired artifacts, not merely
/// ignored.
#[cfg(target_os = "macos")]
pub(crate) const PATHS_D_DEST: &str = "/etc/paths.d/cermet";
/// Where the OS package manager places the pair. A present, coherent pair here is the
/// authoritative source (package authority): after `dpkg -i` of a newer package the running
/// `cermet` is usually the STALE `/usr/local/bin` copy (it precedes `/usr/bin` on both
/// `secure_path` and the user PATH), so resolving "the binary beside me" would republish the
/// old pair onto itself forever.
pub(crate) const PACKAGED_BIN_DIR: &str = "/usr/bin";
const SUDOERS_DEST: &str = "/etc/sudoers.d/cermet-agent";
const CONFIG_DIR: &str = "/etc/cermetd";
const CONFIG_DEST: &str = "/etc/cermetd/config.toml";
const SENTENCES_DIR: &str = "/etc/cermetd/sentences";
const RULES_FILE: &str = "/etc/cermetd/sentences/rules.cermet";
#[cfg(target_os = "linux")]
const PAM_DEST: &str = "/etc/pam.d/cermet";
#[cfg(target_os = "linux")]
const UNIT_DEST: &str = "/etc/systemd/system/cermetd.service";
#[cfg(target_os = "linux")]
const TMPFILES_DEST: &str = "/etc/tmpfiles.d/cermetd.conf";
/// The credential-transport preflight. cermetd's vault key is delivered as a systemd
/// credential, which needs /run to have SHARED mount propagation; hosts always do, container
/// managers often do not. This unit converges that one prerequisite or refuses, and cermetd
/// Requires= it, so an environment that cannot carry the delivery keeps the daemon DOWN with one
/// legible reason instead of crash-looping on a filesystem error.
#[cfg(any(target_os = "linux", test))]
const PREFLIGHT_UNIT_DEST: &str = "/etc/systemd/system/cermet-credential-env.service";
/// The daily UPDATE CHECK, as a systemd timer + oneshot service running as the HUMAN approver.
/// It CHECKS AND NOTICES and never installs: one parameterless GET, a local state file, and a line
/// `cermet` prints until the operator runs `cermet update` themselves. cermetd contains no
/// update-check code at all, so the credential-holding process still has no vendor-facing client.
#[cfg(any(target_os = "linux", test))]
const UPDATE_CHECK_UNIT_DEST: &str = "/etc/systemd/system/cermet-update-check.service";
#[cfg(any(target_os = "linux", test))]
const UPDATE_CHECK_TIMER_DEST: &str = "/etc/systemd/system/cermet-update-check.timer";
/// The token both platforms' scheduler assets carry where the operator's account name goes. Setup
/// substitutes it at install time — the approver is discovered from the config, so it cannot be
/// baked into a shipped file.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
const APPROVER_TOKEN: &str = "CERMET_APPROVER_USER";
/// The preflight's executable. `libexec` because it is a helper the service manager runs, never
/// something an operator invokes: it does not belong beside `cermet` on anyone's PATH.
#[cfg(any(target_os = "linux", test))]
const CREDENTIAL_ENV_DEST: &str = "/usr/local/libexec/cermet-credential-env";
#[cfg(target_os = "linux")]
const CREDENTIAL_ENV_DIR: &str = "/usr/local/libexec";
const STATE_DIR: &str = "/var/lib/cermetd";
/// systemd's own on-disk store for ENCRYPTED credential data, which the service manager searches
/// when a unit names a credential without a path. Using it is what lets `cermetd.service` carry the
/// pathless `LoadCredentialEncrypted=cermet.key`: present ⇒ delivered, absent ⇒ non-fatal, so ONE
/// unit serves every rung of the ladder with no drop-in, no conditional wiring, and no
/// Cermet-invented location (never reinvent the wheel).
#[cfg(any(target_os = "linux", test))]
const CREDSTORE_DIR: &str = "/etc/credstore.encrypted";
// The Linux sealed-credential blob, at the name systemd looks up. Read by the cross-file contract
// test on every platform, so it stays compiled in wherever tests run.
#[cfg(any(target_os = "linux", test))]
const SEALED_KEY: &str = "/etc/credstore.encrypted/cermet.key";
#[cfg(any(target_os = "linux", test))]
const CRED_NAME: &str = "cermet.key";

/// The root-owned scratch root for the install lock and the materialized embedded payload. `/run`
/// does not exist on macOS; `/var/run` is its equivalent (and is what `/run` symlinks to on Linux —
/// pinning each platform's own spelling keeps the lock path stable per platform).
#[cfg(target_os = "macos")]
const SCRATCH_ROOT: &str = "/var/run";
#[cfg(not(target_os = "macos"))]
const SCRATCH_ROOT: &str = "/run";
#[cfg(target_os = "macos")]
const INSTALL_LOCK: &str = "/var/run/cermetd.install.lock";
#[cfg(not(target_os = "macos"))]
const INSTALL_LOCK: &str = "/run/cermetd.install.lock";

/// The macOS LaunchDaemon: one plist, loaded with `launchctl bootstrap system`. The label is the
/// plist's basename and the service target `system/<label>` is what `bootout`/`print` address.
#[cfg(target_os = "macos")]
const PLIST_DEST: &str = "/Library/LaunchDaemons/dev.cermet.cermetd.plist";
#[cfg(any(target_os = "macos", test))]
const PLIST_LABEL: &str = "dev.cermet.cermetd";
/// The daily update check's own LaunchDaemon: the macOS counterpart of the systemd timer.
#[cfg(target_os = "macos")]
const UPDATE_CHECK_PLIST_DEST: &str = "/Library/LaunchDaemons/dev.cermet.update-check.plist";
#[cfg(target_os = "macos")]
const UPDATE_CHECK_PLIST_LABEL: &str = "dev.cermet.update-check";
/// The one-shot boot-time socket-dir provisioner from the earlier shell installer. Its whole job
/// was surviving the reboot wipe of `/var/run`; the persistent runtime dirs below retire it.
#[cfg(target_os = "macos")]
const RETIRED_RUNTIME_DIR_LABEL: &str = "dev.cermet.runtime-dir";
/// The retired upload LaunchDaemon's label — booted out before its plist is unlinked.
#[cfg(target_os = "macos")]
const RETIRED_UPLOAD_LABEL: &str = "dev.cermet.research";
/// macOS's `/var/run` is wiped at every boot (the reason the retired tree needed a second,
/// root-running LaunchDaemon just to recreate the socket dir). A LaunchDaemon that runs as
/// `_cermet` cannot recreate a root-owned dir under `/var/run` itself, and one plist cannot both
/// run as root and run as the service account — so the two socket dirs live in persistent `/var`
/// instead, exactly mirroring Linux's `/run/cermetd` + `/run/cermetd-agents` pair. `setup` owns
/// their convergence; stale sockets inside them are unlinked by the daemon's own pre-bind sweep
/// (`serve::clean_stale_socket_pathnames`).
#[cfg(target_os = "macos")]
const RUNTIME_DIR: &str = "/var/cermetd";
#[cfg(target_os = "macos")]
const AGENT_RUNTIME_DIR: &str = "/var/cermetd-agents";
/// The daemon's stdio log — the plist's `StandardOutPath`/`StandardErrorPath`.
///
/// launchd opens those paths AS THE TARGET USER, before exec. On a stock Mac `/var/log`
/// is `root:wheel 0755`, so `_cermet` cannot create the file, the spawn fails PRE-EXEC (`state =
/// spawn scheduled`, `last exit code = 78`), KeepAlive throttle-loops it, and the log that would
/// have explained all this is the very file that could not be created. Used Macs carry a relic
/// `cermetd.log` from an earlier install, which is why only virgin machines were bitten. The plist
/// is correct and unchanged; setup owns the file's existence and ownership, exactly as it owns the
/// runtime dirs' — converged on EVERY run so a previously-broken or relic box heals on re-run.
/// Linux needs no analog: that daemon logs through journald.
#[cfg(any(target_os = "macos", test))]
const DAEMON_LOG_FILE: &str = "/var/log/cermetd.log";
/// How long setup keeps watching a freshly bootstrapped daemon that shows NO failure evidence.
/// Failure itself is not on a timer — the poll refuses the instant launchd reports an exit — so
/// this cap only bounds the remaining case: a first boot that is merely slow (vault mint, catalog
/// seed, a loaded machine). It errs long on purpose, and capping out is not a failure verdict —
/// the report it earns says nothing has failed and a re-run is safe.
#[cfg(any(target_os = "macos", test))]
const SERVING_TIMEOUT_SECS: u64 = 60;
/// When a quiet wait starts to look like a hang to the human watching it, say what is happening.
#[cfg(target_os = "macos")]
const SERVING_PROGRESS_SECS: u64 = 15;
/// The `file-protected` rung's key file: a plain service-account-owned `0600` file under
/// `CERMET_HOME`, read by `cermet-daemon`'s `master_key::load_service_key_for_rung`. It is the ONLY
/// rung on macOS (no systemd-creds analog, no login session for a Keychain item) and the bottom
/// rung on Linux, taken when systemd credential delivery cannot work on this box. Other local uids
/// are defeated by owner+mode; it does not protect the key from disk snapshots or backups, which is
/// exactly what the profile's limitation says out loud.
const MASTER_KEY_FILE: &str = "/var/lib/cermetd/master.key";
/// The build markers a NON-INSTALLABLE build embeds, paired with the feature that put each one
/// there. All three are test-only doors the shipped binary must not have: `test-presence` bypasses
/// the human-presence ceremony, `test-egress` reopens `CERMET_*_BASE_URL` so a stray env var can
/// redirect provider traffic that carries the real credential, and `test-double` registers
/// canned-response providers in the default registry. The adversary is T2 (accident) — a developer
/// or an agent installing a binary they built for testing.
///
/// Each marker is emitted by the crate that OWNS its feature (`cermet-ctl-client`, `cermet-core`),
/// never by the composition crate: cargo unifies dev-dependency features into the normal
/// graph, so a build could acquire the door without the composition crate's own feature ever being
/// named, and a marker declared up there was simply absent. Placed at the owner, the scan proves
/// "this binary links a contaminated library", which is the property that actually matters.
///
/// Stored REVERSED so the production binary's own scanner does not embed the forbidden markers and
/// reject itself. A contaminated build still embeds the forward form.
const NON_INSTALLABLE_MARKERS_REVERSED: &[(&str, &[u8])] = &[
    (
        "test-presence",
        b"LLATSNI_TON_OD_NI_DELIPMOC_ECNESERP_TSET_TEMREC",
    ),
    (
        "test-egress",
        b"LLATSNI_TON_OD_NI_DELIPMOC_SSERGE_TSET_TEMREC",
    ),
    (
        "test-double",
        b"LLATSNI_TON_OD_NI_DELIPMOC_ELBUOD_TSET_TEMREC",
    ),
];

#[derive(Debug)]
struct EmbeddedAsset {
    path: &'static str,
    bytes: &'static [u8],
}

macro_rules! embedded_asset {
    ($path:literal) => {
        EmbeddedAsset {
            path: $path,
            bytes: include_bytes!(concat!("../../../dist/", $path)),
        }
    };
}

// One manifest, pointing directly at dist/: the package payload and the tree payload can never
// become separate source trees. Package copies under /usr/share/cermet are browsable only; setup
// correctness uses these bytes compiled into cermet.
const EMBEDDED_PAYLOAD: &[EmbeddedAsset] = &[
    embedded_asset!("linux/cermetd.service"),
    embedded_asset!("linux/cermetd.tmpfiles"),
    embedded_asset!("linux/cermet-credential-env.service"),
    embedded_asset!("linux/cermet-credential-env.sh"),
    embedded_asset!("linux/cermet-update-check.service"),
    embedded_asset!("linux/cermet-update-check.timer"),
    embedded_asset!("linux/config.toml"),
    embedded_asset!("linux/pam.cermet"),
    // Both platforms' service assets are carried by both builds — a few KB, and one manifest is
    // one thing to keep true. `SourceLayout` picks the pair this platform installs.
    embedded_asset!("macos/dev.cermet.cermetd.plist"),
    embedded_asset!("macos/dev.cermet.update-check.plist"),
    embedded_asset!("macos/config.toml"),
    embedded_asset!("catalog/actions.d/github.create_pull_request_review.yaml"),
    embedded_asset!("catalog/actions.d/github.comment_thread.yaml"),
    embedded_asset!("catalog/actions.d/github.create_branch.yaml"),
    embedded_asset!("catalog/actions.d/github.create_pull_request.yaml"),
    embedded_asset!("catalog/actions.d/github.dispatch_workflow.yaml"),
    embedded_asset!("catalog/actions.d/github.create_issue.yaml"),
    embedded_asset!("catalog/actions.d/github.fetch.yaml"),
    embedded_asset!("catalog/actions.d/github.push.yaml"),
    embedded_asset!("catalog/actions.d/github.push_tag.yaml"),
    embedded_asset!("catalog/actions.d/github.read_blob.yaml"),
    embedded_asset!("catalog/actions.d/github.read_commit.yaml"),
    embedded_asset!("catalog/actions.d/github.merge_pull_request.yaml"),
    embedded_asset!("catalog/actions.d/github.update_pull_request.yaml"),
    embedded_asset!("catalog/actions.d/github.read_pull_request.yaml"),
    embedded_asset!("catalog/actions.d/github.read_ref.yaml"),
    embedded_asset!("catalog/actions.d/github.read_repo.yaml"),
    embedded_asset!("catalog/actions.d/github.read_secret_scanning_alerts_open.yaml"),
    embedded_asset!("catalog/actions.d/github.read_job_log.yaml"),
    embedded_asset!("catalog/actions.d/github.read_releases.yaml"),
    embedded_asset!("catalog/actions.d/github.read_workflow_runs.yaml"),
    embedded_asset!("catalog/actions.d/github.publish_release.yaml"),
    embedded_asset!("catalog/actions.d/github.read_thread.yaml"),
    embedded_asset!("catalog/actions.d/github.read_tree.yaml"),
    embedded_asset!("catalog/actions.d/github.read_workflow_run.yaml"),
    embedded_asset!("catalog/actions.d/github.read_workflow_run_jobs.yaml"),
    embedded_asset!("catalog/actions.d/github.request_deployment.yaml"),
    embedded_asset!("catalog/actions.d/github.request_workflow_cancel.yaml"),
    embedded_asset!("catalog/actions.d/stripe.archive_price.yaml"),
    embedded_asset!("catalog/actions.d/stripe.archive_product.yaml"),
    embedded_asset!("catalog/actions.d/stripe.cancel_payment_intent.yaml"),
    embedded_asset!("catalog/actions.d/stripe.cancel_subscription.yaml"),
    embedded_asset!("catalog/actions.d/stripe.cancel_subscription_at_period_end.yaml"),
    embedded_asset!("catalog/actions.d/stripe.capture_payment_intent.yaml"),
    embedded_asset!("catalog/actions.d/stripe.confirm_payment_intent.yaml"),
    embedded_asset!("catalog/actions.d/stripe.create_payment_intent_off_session.yaml"),
    embedded_asset!("catalog/actions.d/stripe.create_standard_payout.yaml"),
    embedded_asset!("catalog/actions.d/stripe.credit_balance.yaml"),
    embedded_asset!("catalog/actions.d/stripe.get_charge.yaml"),
    embedded_asset!("catalog/actions.d/stripe.get_dispute_summary.yaml"),
    embedded_asset!("catalog/actions.d/stripe.get_invoice.yaml"),
    embedded_asset!("catalog/actions.d/stripe.get_payment_intent.yaml"),
    embedded_asset!("catalog/actions.d/stripe.get_price.yaml"),
    embedded_asset!("catalog/actions.d/stripe.get_product.yaml"),
    embedded_asset!("catalog/actions.d/stripe.get_subscription.yaml"),
    embedded_asset!("catalog/actions.d/stripe.issue_credit_note_adjustment_no_email.yaml"),
    embedded_asset!("catalog/actions.d/stripe.list_active_prices.yaml"),
    embedded_asset!("catalog/actions.d/stripe.list_charges.yaml"),
    embedded_asset!("catalog/actions.d/stripe.list_invoices_for_customer.yaml"),
    embedded_asset!("catalog/actions.d/stripe.list_refunds.yaml"),
    embedded_asset!("catalog/actions.d/stripe.lookup_customer.yaml"),
    embedded_asset!("catalog/actions.d/stripe.mark_invoice_uncollectible.yaml"),
    embedded_asset!("catalog/actions.d/stripe.pause_subscription.yaml"),
    embedded_asset!("catalog/actions.d/stripe.refund.yaml"),
    embedded_asset!("catalog/actions.d/stripe.refund_charge_bounded.yaml"),
    embedded_asset!("catalog/actions.d/stripe.resume_subscription_collection.yaml"),
    embedded_asset!("catalog/actions.d/stripe.retry_invoice_payment.yaml"),
    // The first relay verb ships in the installed catalog too.
    embedded_asset!("catalog/actions.d/vercel.deploy.yaml"),
    embedded_asset!("catalog/actions.d/vercel.list_projects.yaml"),
    embedded_asset!("catalog/actions.d/stripe.search_customers.yaml"),
    embedded_asset!("catalog/actions.d/stripe.stage_dispute_evidence.yaml"),
    embedded_asset!("catalog/actions.d/stripe.submit_dispute_evidence.yaml"),
    embedded_asset!("catalog/actions.d/stripe.update_webhook_endpoint_fixed_bundle.yaml"),
    embedded_asset!("catalog/providers.d/github.yaml"),
    embedded_asset!("catalog/providers.d/stripe.yaml"),
    embedded_asset!("catalog/providers.d/vercel.yaml"),
];

/// Binaries earlier installs published under names this build no longer ships. Every platform's
/// PATH gets swept: a stale `cermet-rs` beside the current `cermet` is an operator trap.
pub(crate) const RETIRED_BINARIES: &[&str] = &[
    "/usr/local/bin/cermet-rs",
    "/usr/local/bin/cermet-app",
    "/usr/local/bin/cermet-agent",
];

/// The systemd CIDR egress firewall is dead — the unit no longer declares deny-all and
/// setup no longer generates this drop-in. A prior install's copy would otherwise sit here forever
/// as an allow-list with nothing to permit exceptions to: dead config litter, removed and reported
/// like any other retired artifact.
/// STRIPPED 2026-08-17: the decision-trace upload program is gone from the product, so the timer
/// and oneshot service earlier installs provisioned are dead scheduler units. They are named here —
/// the files being deleted are what a convergence report has to say — and the enable symlink goes
/// with them, because a `wants` link outliving its unit is a dangling reference systemd complains
/// about at every reload. [`stop_retired_upload_timer`] stops the job before this sweep unlinks it.
#[cfg(not(target_os = "macos"))]
pub(crate) const RETIRED_PLATFORM_ARTIFACTS: &[&str] = &[
    "/etc/systemd/system/cermetd.service.d/10-egress-allow.conf",
    "/etc/systemd/system/cermet-research.service",
    "/etc/systemd/system/cermet-research.timer",
    "/etc/systemd/system/timers.target.wants/cermet-research.timer",
];

/// The retired upload timer's unit name, for the stop that precedes the unlink.
#[cfg(any(target_os = "linux", test))]
const RETIRED_UPLOAD_TIMER: &str = "cermet-research.timer";

/// The earlier macOS shell installer's boot-time socket-dir provisioner — a second LaunchDaemon
/// and its root helper script, whose only job was recreating `/var/run/cermetd` after the boot
/// wipe. Persistent runtime dirs retire both. The daemon is booted out before its plist is
/// unlinked (`bootout_retired_daemon`), so launchd is never left holding a job with no plist.
/// Plus every binary an earlier installer published into `/usr/local/bin`. They are not
/// merely stale: `/etc/paths` lists `/usr/local/bin` BEFORE anything `path_helper` appends from
/// `/etc/paths.d`, so a surviving copy there shadows the `/opt/cermet/bin` install for every bare
/// `cermet` and for git's `git-remote-cermet` lookup. Removing FILES from that directory is fine;
/// the directory itself is Homebrew's and setup never creates, chowns, or asserts on it.
#[cfg(target_os = "macos")]
/// Plus (STRIPPED 2026-08-17) the decision-trace upload program's LaunchDaemon: the program is gone
/// from the product, so an earlier install's plist is a job scheduled to run a subcommand this
/// build does not have. It is booted out before it is unlinked, like the runtime-dir daemon above.
pub(crate) const RETIRED_PLATFORM_ARTIFACTS: &[&str] = &[
    "/Library/LaunchDaemons/dev.cermet.runtime-dir.plist",
    "/Library/LaunchDaemons/dev.cermet.research.plist",
    "/usr/local/libexec/cermet/provision-runtime-dir.sh",
    "/usr/local/bin/cermet",
    "/usr/local/bin/cermetd",
    "/usr/local/bin/git-remote-cermet",
];

// The top-level exact names removed by the true vendor reset, including the daemon's host lock and
// advisory metadata files. Prefix-shaped interrupted-write remnants and sqlite sidecars are added
// by `force_clean_reset`.
const FORCE_CLEAN_FILES: &[&str] = &[
    "vault.db",
    "state.db",
    "audit.db",
    "host.lock",
    "host.json",
    // The macOS service key. Absent on Linux, but listing it unconditionally keeps ONE reset
    // inventory: a key the reset skipped would make `write_master_key` refuse to mint over it.
    "master.key",
    "mcp-repoint.barrier",
    "lockdown.record",
    "sentence.record",
    "sentence.pin",
    "policy.yaml",
];
const FORCE_CLEAN_TREES: &[&str] = &[
    "mirrors",
    "lockdown.audit_pending",
    "artifacts",
    "sentence.staged",
    "sentence.audit_pending",
    "actions.d",
    "providers.d",
    "profiles.d",
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetupArgs {
    pub from_tree: Option<PathBuf>,
    pub force_clean_bootstrap: bool,
    /// The binary to publish, when the caller already knows which one. Not a CLI flag: the only
    /// setter is [`converge_with_binary`], which `cermet update` calls with the download it just
    /// verified. Without it the source is resolved by [`resolve_binary_source`]'s package-first
    /// precedence, which is right for `dpkg -i` and wrong for an update — the package copy is the
    /// OLD one there.
    pub binary_source: Option<PathBuf>,
}

/// Converge this installation, publishing `binary` instead of the package/running copy.
///
/// This is the seam `cermet update` reuses rather than growing a second publisher: everything after
/// it — the converged-layout no-op, stopping the daemon before the first byte lands, the atomic
/// rename, the service assets this release ships, the restart — is `setup`'s existing flow,
/// unchanged. Root-only, and by construction the caller is the NEW binary, so the embedded payload
/// it converges from is the new release's.
pub fn converge_with_binary(binary: &Path) -> Result<(), String> {
    // `run` self-elevates when it is not root, and the re-exec it builds is a plain `cermet setup`
    // — which would resolve its own source and publish something OTHER than `binary`. So this seam
    // never elevates: its caller does, and arrives here already privileged.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if unsafe { libc::geteuid() } != 0 {
        return Err("publishing an update needs administrator access".into());
    }
    run(&SetupArgs {
        from_tree: None,
        force_clean_bootstrap: false,
        binary_source: Some(binary.to_path_buf()),
    })
}

pub fn parse_setup(args: &[String]) -> Result<SetupArgs, CliError> {
    let mut from_tree = None;
    let mut force_clean_bootstrap = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--from-tree" if from_tree.is_none() => {
                let path = match args.get(index + 1) {
                    Some(value) if !value.starts_with("--") => {
                        index += 1;
                        PathBuf::from(value)
                    }
                    _ => PathBuf::from("."),
                };
                from_tree = Some(path);
            }
            "--from-tree" => {
                return Err(CliError::Usage(
                    "setup accepts --from-tree only once".into(),
                ));
            }
            "--force-clean-bootstrap" if !force_clean_bootstrap => {
                force_clean_bootstrap = true;
            }
            "--force-clean-bootstrap" => {
                return Err(CliError::Usage(
                    "setup accepts --force-clean-bootstrap only once".into(),
                ));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "setup: unexpected argument {other:?}; expected --from-tree [<repo>] or \
                     --force-clean-bootstrap"
                )));
            }
        }
        index += 1;
    }
    Ok(SetupArgs {
        from_tree,
        force_clean_bootstrap,
        binary_source: None,
    })
}

/// The `dist/` subdirectory holding this platform's service assets.
#[cfg(target_os = "macos")]
const PLATFORM_ASSET_DIR: &str = "macos";
#[cfg(not(target_os = "macos"))]
const PLATFORM_ASSET_DIR: &str = "linux";

#[derive(Debug)]
struct SourceLayout {
    /// ONE-BINARY: the single regular executable to publish. There is no pair to keep coherent.
    binary: PathBuf,
    config: PathBuf,
    catalog: PathBuf,
    #[cfg(not(target_os = "macos"))]
    unit: PathBuf,
    #[cfg(not(target_os = "macos"))]
    tmpfiles: PathBuf,
    /// The credential-transport preflight — its unit and the script the unit execs.
    #[cfg(not(target_os = "macos"))]
    preflight_unit: PathBuf,
    #[cfg(not(target_os = "macos"))]
    credential_env: PathBuf,
    #[cfg(not(target_os = "macos"))]
    pam: PathBuf,
    /// The daily update check's scheduler: a timer + oneshot service on Linux, one LaunchDaemon on
    /// macOS, both running `cermet update --daily-check` as the human approver.
    #[cfg(not(target_os = "macos"))]
    update_check_unit: PathBuf,
    #[cfg(not(target_os = "macos"))]
    update_check_timer: PathBuf,
    #[cfg(target_os = "macos")]
    plist: PathBuf,
    #[cfg(target_os = "macos")]
    update_check_plist: PathBuf,
    _embedded: Option<EmbeddedPayloadRoot>,
}

impl SourceLayout {
    fn resolve(from_tree: Option<&Path>, binary_source: Option<&Path>) -> Result<Self, String> {
        // Both source shapes reduce to ONE binary plus one asset root: `dist/` in a tree, or the
        // materialized embedded payload otherwise (whose layout mirrors `dist/` exactly).
        let (binary, assets, embedded) = if let Some(repo) = from_tree {
            let repo = repo
                .canonicalize()
                .map_err(|error| format!("cannot resolve tree {}: {error}", repo.display()))?;
            (
                repo.join("target/release").join(MULTICALL_TARGET),
                repo.join("dist"),
                None,
            )
        } else {
            // An EXPLICIT source wins outright: `cermet update` has already downloaded, verified,
            // and re-verified the bytes it means, and the package-first precedence below would
            // publish the OLD package copy over them.
            let binary = match binary_source {
                Some(explicit) => explicit.to_path_buf(),
                None => {
                    let running = std::env::current_exe().map_err(|error| {
                        format!("cannot locate the running cermet binary: {error}")
                    })?;
                    resolve_binary_source(Path::new(PACKAGED_BIN_DIR), &running)?
                }
            };
            let embedded = EmbeddedPayloadRoot::materialize()?;
            let root = embedded.path.clone();
            (binary, root, Some(embedded))
        };
        let platform = assets.join(PLATFORM_ASSET_DIR);
        Ok(Self {
            binary,
            config: platform.join("config.toml"),
            catalog: assets.join("catalog"),
            #[cfg(not(target_os = "macos"))]
            unit: platform.join("cermetd.service"),
            #[cfg(not(target_os = "macos"))]
            tmpfiles: platform.join("cermetd.tmpfiles"),
            #[cfg(not(target_os = "macos"))]
            preflight_unit: platform.join("cermet-credential-env.service"),
            #[cfg(not(target_os = "macos"))]
            credential_env: platform.join("cermet-credential-env.sh"),
            #[cfg(not(target_os = "macos"))]
            pam: platform.join("pam.cermet"),
            #[cfg(not(target_os = "macos"))]
            update_check_unit: platform.join("cermet-update-check.service"),
            #[cfg(not(target_os = "macos"))]
            update_check_timer: platform.join("cermet-update-check.timer"),
            #[cfg(target_os = "macos")]
            plist: platform.join("dev.cermet.cermetd.plist"),
            #[cfg(target_os = "macos")]
            update_check_plist: platform.join("dev.cermet.update-check.plist"),
            _embedded: embedded,
        })
    }

    /// The service assets this platform installs, beyond the shared config template and catalog.
    #[cfg(not(target_os = "macos"))]
    fn platform_assets(&self) -> Vec<(&'static str, &PathBuf)> {
        vec![
            ("systemd unit", &self.unit),
            ("tmpfiles rule", &self.tmpfiles),
            ("credential preflight unit", &self.preflight_unit),
            ("credential preflight script", &self.credential_env),
            ("PAM service", &self.pam),
            ("update check unit", &self.update_check_unit),
            ("update check timer", &self.update_check_timer),
        ]
    }

    #[cfg(target_os = "macos")]
    fn platform_assets(&self) -> Vec<(&'static str, &PathBuf)> {
        vec![
            ("LaunchDaemon plist", &self.plist),
            ("update check plist", &self.update_check_plist),
        ]
    }

    fn preflight(&self) -> Result<(), String> {
        require_regular_source(&self.binary, true)
            .map_err(|error| format!("cermet binary {}: {error}", self.binary.display()))?;
        for (label, path) in
            std::iter::once(("config template", &self.config)).chain(self.platform_assets())
        {
            require_regular_source(path, false)
                .map_err(|error| format!("{label} {}: {error}", path.display()))?;
        }
        catalog_seed_plan(&self.catalog, Path::new(STATE_DIR))?;
        // ONE-BINARY: one target, so the contamination scan runs ONCE, on the exact bytes that get
        // published under all three names.
        reject_non_installable_binary(&self.binary)
    }
}

/// Resolve the ONE binary to publish, in explicit precedence order:
/// 1. the package-managed `cermet` in `packaged_dir` — the package manager is the authority on what
///    version is installed, so an upgrade republishes the NEW binary even when the running `cermet`
///    is the stale `/usr/local/bin` copy;
/// 2. otherwise the running executable itself (cargo-install, a hand-unpacked tarball,
///    `/usr/local/bin` with no package installed);
/// 3. otherwise fail closed.
///
/// A candidate counts only when it is a regular, non-symlink, executable file — so an already-linked
/// `cermetd` alias can never be mistaken for a publishable source.
fn resolve_binary_source(packaged_dir: &Path, running: &Path) -> Result<PathBuf, String> {
    let packaged = packaged_dir.join(MULTICALL_TARGET);
    let packaged_error = match require_regular_source(&packaged, true) {
        Ok(()) => return Ok(packaged),
        Err(error) => error,
    };
    require_regular_source(running, true).map_err(|running_error| {
        format!(
            "cannot locate a publishable {MULTICALL_TARGET} binary: package copy {} \
             ({packaged_error}); the running executable {} ({running_error})",
            packaged.display(),
            running.display()
        )
    })?;
    Ok(running.to_path_buf())
}

#[derive(Debug)]
struct EmbeddedPayloadRoot {
    path: PathBuf,
}

impl EmbeddedPayloadRoot {
    fn materialize() -> Result<Self, String> {
        let mut root = None;
        for _ in 0..16 {
            let candidate = Path::new(SCRATCH_ROOT).join(format!(
                "cermet-setup-payload.{:016x}",
                rand::rngs::OsRng.next_u64()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).map_err(
                        |error| {
                            format!(
                                "cannot secure embedded payload directory {}: {error}",
                                candidate.display()
                            )
                        },
                    )?;
                    root = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "cannot create embedded payload directory under {SCRATCH_ROOT}: {error}"
                    ));
                }
            }
        }
        let root = root.ok_or_else(|| {
            format!("cannot allocate a unique embedded payload directory under {SCRATCH_ROOT}")
        })?;
        let payload = Self { path: root };
        for asset in EMBEDDED_PAYLOAD {
            let destination = payload.path.join(asset.path);
            let parent = destination.parent().ok_or_else(|| {
                format!(
                    "embedded payload path {} has no parent",
                    destination.display()
                )
            })?;
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            options
                .open(&destination)
                .and_then(|mut file| file.write_all(asset.bytes))
                .map_err(|error| {
                    format!(
                        "cannot materialize embedded payload {}: {error}",
                        destination.display()
                    )
                })?;
        }
        Ok(payload)
    }
}

impl Drop for EmbeddedPayloadRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn run(args: &SetupArgs) -> Result<(), String> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = args;
        return Err("cermet setup supports Linux/systemd and macOS/launchd only".into());
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if unsafe { libc::geteuid() } != 0 {
            return self_elevate(args);
        }
        #[cfg(target_os = "macos")]
        return run_macos(args);
        #[cfg(target_os = "linux")]
        run_linux(args)
    }
}

/// Run unprivileged, `cermet setup` states what it needs root for — ONE comprehensible consent
/// boundary — then re-execs itself through sudo at its own absolute path (one-run install;
/// this also retires the `sudo "$(command -v cermet)" setup` footgun, since the
/// binary knows its own path and sudo's PATH does not). Non-interactive callers get the exact
/// command instead of a hang.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn self_elevate(args: &SetupArgs) -> Result<(), String> {
    use std::io::IsTerminal;
    let exe = std::env::current_exe()
        .map_err(|error| format!("cannot resolve the running cermet binary: {error}"))?;
    let mut argv: Vec<String> = vec![exe.display().to_string(), "setup".into()];
    if let Some(repo) = &args.from_tree {
        argv.push("--from-tree".into());
        argv.push(repo.display().to_string());
    }
    if args.force_clean_bootstrap {
        argv.push("--force-clean-bootstrap".into());
    }
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "setup needs administrator access; run: sudo {}",
            argv.join(" ")
        ));
    }
    println!(
        "Cermet needs administrator access once to:
           • create the local broker's own service account
           • create its credential vault (readable by the broker alone)
           • install and start the background service
           • create the isolated agent IPC endpoints"
    );
    let mut sudo = Command::new("sudo");
    sudo.args(&argv);
    let status = sudo
        .status()
        .map_err(|error| format!("cannot invoke sudo: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("setup did not complete under sudo; see the output above".into())
    }
}

#[cfg(target_os = "linux")]
fn run_linux(args: &SetupArgs) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("must run as root (try: sudo cermet setup)".into());
    }
    require_commands(&[
        "getent",
        "groupadd",
        "useradd",
        "id",
        "install",
        "chown",
        "visudo",
        "systemctl",
        // NOT systemd-creds: since the custody ladder landed it is the top two rungs' prerequisite,
        // not the install's. A box without it is provisioned on `file-protected` and told so;
        // refusing the whole install over it would be the leave-the-broker-stopped tier the ladder
        // replaced.
    ])?;

    let sources = SourceLayout::resolve(args.from_tree.as_deref(), args.binary_source.as_deref())?;
    sources.preflight()?;
    let _lock = InstallLock::acquire(Path::new(INSTALL_LOCK))?;
    ok("preflight", "root, inputs, utilities, and install lock");

    ensure_group(SERVICE_GROUP)?;
    ensure_user(SERVICE_USER, SERVICE_GROUP, false)?;
    ensure_group(APPROVERS_GROUP)?;
    ensure_group(AGENTS_GROUP)?;
    ensure_user(AGENT_USER, AGENTS_GROUP, true)?;

    let service_uid = uid_for(SERVICE_USER)?;
    let agent_account_uid = uid_for(AGENT_USER)?;
    if service_uid == 0 || agent_account_uid == 0 || service_uid == agent_account_uid {
        return Err(format!(
            "partial topology: service uid {service_uid} and agent uid {agent_account_uid} \
             must be distinct and non-root"
        ));
    }
    assert_plane_topology(service_uid, agent_account_uid)?;
    ok(
        "accounts",
        &format!("service uid {service_uid}, agent uid {agent_account_uid}, disjoint groups"),
    );

    // ONE-BINARY migration/upgrade coordination: decide (and, if publication will change anything,
    // stop the running daemon) BEFORE the first byte lands. See `ServiceCutover`.
    let cutover = ServiceCutover::begin(&sources)?;
    publish_multicall(&sources)?;
    cleanup_retired_artifacts()?;

    install_dir(Path::new(CONFIG_DIR), "root", "root", 0o755)?;
    let (approver_uid, agent_uid) =
        install_or_validate_config(&sources.config, service_uid, agent_account_uid)?;
    let approver = uid_name(approver_uid)?;
    if approver.is_empty() {
        return Err(format!(
            "approver uid {approver_uid} does not resolve to a user"
        ));
    }
    if agent_uid != agent_account_uid {
        return Err(format!(
            "configured agent_uid {agent_uid} does not match the {AGENT_USER} account uid \
             {agent_account_uid}"
        ));
    }
    install_dir(
        Path::new(SENTENCES_DIR),
        SERVICE_USER,
        APPROVERS_GROUP,
        0o2750,
    )?;
    fixed(
        "config",
        &format!("service_uid={service_uid}, approver_uid={approver_uid}, agent_uid={agent_uid}"),
    );

    install_sudoers(approver_uid)?;
    atomic_install_file(&sources.pam, Path::new(PAM_DEST), "root", "root", 0o644)?;
    atomic_install_file(&sources.unit, Path::new(UNIT_DEST), "root", "root", 0o644)?;
    // The preflight before the unit that Requires= it, so no window exists where cermetd names a
    // dependency that is not on disk. 0755: the service manager execs it.
    install_dir(Path::new(CREDENTIAL_ENV_DIR), "root", ROOT_GROUP, 0o755)?;
    atomic_install_file(
        &sources.credential_env,
        Path::new(CREDENTIAL_ENV_DEST),
        "root",
        ROOT_GROUP,
        0o755,
    )?;
    atomic_install_file(
        &sources.preflight_unit,
        Path::new(PREFLIGHT_UNIT_DEST),
        "root",
        ROOT_GROUP,
        0o644,
    )?;
    fixed(
        "credential transport",
        "preflight installed (converges /run propagation, or refuses before cermetd starts)",
    );
    atomic_install_file(
        &sources.tmpfiles,
        Path::new(TMPFILES_DEST),
        "root",
        "root",
        0o644,
    )?;
    if command_exists("systemd-tmpfiles") {
        let mut command = Command::new("systemd-tmpfiles");
        command.arg("--create").arg(TMPFILES_DEST);
        checked(command, "apply the cermetd tmpfiles rule")?;
        fixed("runtime dirs", "tmpfiles rule installed and applied");
    } else {
        eprintln!(
            "[cermet-setup] REFUSED: systemd-tmpfiles is unavailable; the installed daemon \
             cannot get its required socket directories before boot"
        );
        return Err("systemd-tmpfiles is required to converge the runtime directories".into());
    }
    install_update_check_scheduler(&sources, &approver)?;
    // The unit fragments on disk just changed — the freshly installed unit, and the
    // retired egress drop-in `cleanup_retired_artifacts` removed above. systemd serves the version
    // it last read until told otherwise, so reload before anything starts the service.
    let mut reload = Command::new("systemctl");
    reload.arg("daemon-reload");
    checked(reload, "reload systemd after unit installation")?;
    fixed("systemd", "unit fragments reloaded");

    if args.force_clean_bootstrap {
        force_clean_reset()?;
    }
    install_dir(Path::new(STATE_DIR), SERVICE_USER, SERVICE_GROUP, 0o700)?;
    // systemd's own encrypted-credential store, root-private. Created unconditionally: the unit
    // names the credential without a path, so the STORE is part of the wiring even on a box whose
    // ladder lands below the sealed rungs and puts nothing in it.
    install_dir(Path::new(CREDSTORE_DIR), "root", ROOT_GROUP, 0o700)?;
    // CUSTODY-LADDER: provisioning the key IS the rung selection — the mechanism that actually
    // held the key is the one recorded, so the declared profile and the artifact on disk always
    // agree. A box that cannot carry sealed delivery descends here, loudly.
    let custody = provision_master_key(args.force_clean_bootstrap)?;
    record_custody_profile(custody)?;
    initialize_lockdown_record()?;
    seed_catalog(&sources.catalog)?;

    // Assets are installed and reloaded; NOW the daemon setup stopped may come back on the newly
    // published binary.
    cutover.finish();
    // Membership needs no daemon, so it lands BEFORE the liveness gate: however the wait below
    // ends, the human can already reach the ctl socket — a slow boot must never leave the box
    // serving but unreachable by its own approver.
    let membership_added = ensure_approver_membership(&approver);
    // Install ends with the service enabled and running, like every service-shaped package.
    // Starting the daemon changes no authority — a fresh corpus is deny-all — so there is no
    // second decision to reserve for a second command.
    ensure_service_live()?;
    enable_update_check_scheduler();

    print_completion(&approver, membership_added, custody);
    report_cutover(&approver);
    Ok(())
}

/// Converge "the service is enabled at boot and running now", idempotently, and report which of
/// those publishing had to change. A failure to start is a WARN with the remedy, never an abort:
/// the install itself is complete and correct.
#[cfg(target_os = "linux")]
fn ensure_service_live() -> Result<(), String> {
    let mut enable = Command::new("systemctl");
    enable.args(["enable", "cermetd.service"]);
    if let Err(error) = checked(enable, "enable cermetd at boot") {
        println!("[cermet-setup] WARN service: {error}");
    }
    if daemon_is_running() {
        ok("service", "cermetd enabled and running");
    } else {
        match start_daemon_service() {
            Ok(()) => fixed("service", "cermetd enabled and started"),
            Err(error) => println!(
                "[cermet-setup] WARN service: {error}\n\
                 [cermet-setup]      inspect with: journalctl -u cermetd -n 50, then: {}",
                start_daemon_command()
            ),
        }
    }
    Ok(())
}

/// launchd equivalent: a plist under /Library/LaunchDaemons with RunAtLoad loads at every boot
/// once bootstrapped, so "bootstrap now" is the whole enablement story.
///
/// This step REFUSES rather than warns — but only on EVIDENCE. On launchd the failure it catches
/// is silent by construction — the crash-loop is loaded, and the log that would explain it is the
/// file the child could not create — so an install whose daemon has EXITED is a failed install,
/// refused the moment launchd says so, carrying the evidence that names which failure it was. A
/// daemon that has never exited is a boot in progress however long it takes; if it outlasts the
/// watch window the step reports patience (nothing failed, here is what to watch), never failure.
#[cfg(target_os = "macos")]
fn ensure_service_live() -> Result<(), String> {
    if !launchd_job_is_loaded() {
        let mut bootstrap = Command::new("launchctl");
        bootstrap.args(["bootstrap", "system", PLIST_DEST]);
        if let Err(error) = checked(bootstrap, "bootstrap the cermetd LaunchDaemon") {
            println!("[cermet-setup] WARN service: {error}");
        }
    }
    // Already-loaded is deliberately NOT re-bootstrapped: launchd rejects a duplicate bootstrap,
    // and that rejection would mask the real state the wait below reads.
    wait_until_serving()?;
    ok("service", "cermetd bootstrapped and serving");
    Ok(())
}

/// Converge the daemon's stdio log — the other half of the virgin-boot fix, and the half that makes the virgin
/// Mac boot at all.
///
/// launchd opens `StandardOutPath`/`StandardErrorPath` as the job's UserName BEFORE exec. Stock
/// `/var/log` is `root:wheel 0755`, so `_cermet` cannot create `cermetd.log` there and the spawn
/// dies with exit 78 having written nothing. Setup runs as root and owns this file's existence
/// exactly as it owns the runtime dirs': created if absent, then owner and mode converged on EVERY
/// run so a box broken by an earlier install, or carrying a root-owned relic from one, heals by
/// re-running setup. Existing content is never touched — the file is opened for APPEND, never
/// truncated: the log of the failure is the thing being repaired, not something to erase.
#[cfg(target_os = "macos")]
fn converge_daemon_log_file() -> Result<(), String> {
    let path = Path::new(DAEMON_LOG_FILE);
    let created = !path.exists();
    if created {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| format!("cannot create {DAEMON_LOG_FILE}: {error}"))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o640))
        .map_err(|error| format!("cannot chmod {DAEMON_LOG_FILE}: {error}"))?;
    chown(path, SERVICE_USER, SERVICE_GROUP)?;
    fixed(
        "daemon log",
        &format!(
            "{}{DAEMON_LOG_FILE} as {SERVICE_USER}:{SERVICE_GROUP} 0640 — launchd opens it as \
             {SERVICE_USER} before exec, and stock /var/log is root-only",
            if created { "created " } else { "converged " }
        ),
    );
    Ok(())
}

/// Put the approver in [`APPROVERS_GROUP`], idempotently. Membership is not optional — presence
/// ceremonies require it — and the approver IS the human already running setup as root, so there
/// is no second decision to leave manual ( one-run install). Returns whether
/// membership was newly granted (a fresh grant reaches existing sessions only after a re-log-in).
fn ensure_approver_membership(approver: &str) -> bool {
    if approver_in_group(approver) {
        ok(
            "approvers",
            &format!("{approver} is already in {APPROVERS_GROUP}"),
        );
        return false;
    }
    #[cfg(target_os = "linux")]
    let mut add = {
        let mut command = Command::new("usermod");
        command.args(["-aG", APPROVERS_GROUP, approver]);
        command
    };
    #[cfg(target_os = "macos")]
    let mut add = {
        let mut command = Command::new("dseditgroup");
        command.args(["-o", "edit", "-a", approver, "-t", "user", APPROVERS_GROUP]);
        command
    };
    let _ = &mut add;
    match checked(add, &format!("add {approver} to {APPROVERS_GROUP}")) {
        Ok(()) => {
            fixed(
                "approvers",
                &format!("added {approver} to {APPROVERS_GROUP}"),
            );
            true
        }
        Err(error) => {
            println!("[cermet-setup] WARN approvers: {error}");
            false
        }
    }
}

/// CUSTODY-LADDER: the vault line of the closing summary — the rung this box landed on, and what
/// that rung honestly does not protect, straight from the profile so the claim is authored once.
///
/// This is the line that makes an automatic ladder non-silent: nothing else in the install tells an
/// operator that their container took `file-protected` instead of a sealed rung.
fn vault_ready_lines(custody: CustodyProfile) -> [String; 2] {
    [
        format!("✓ credential vault ready (custody: {})", custody.as_str()),
        format!("  {}", custody.limitation()),
    ]
}

/// The closing summary, each line derived from a real probe of the box — never advice the box
/// already took, and no required follow-up command: `cermet check` is the doctor for when a line
/// is ✗, not an initiation step.
fn print_completion(approver: &str, membership_added: bool, custody: CustodyProfile) {
    // CUSTODY-LADDER: which artifact proves the vault key is provisioned follows the RUNG, not the
    // platform — a Linux box on `file-protected` is proved by the key file, exactly like macOS.
    let key_ready = if custody.is_systemd_credential() {
        #[cfg(any(target_os = "linux", test))]
        {
            Path::new(SEALED_KEY).is_file()
        }
        #[cfg(not(any(target_os = "linux", test)))]
        {
            false
        }
    } else {
        Path::new(MASTER_KEY_FILE).is_file()
    };
    let git_ready = fs::metadata(Path::new(INSTALL_BIN_DIR).join("git-remote-cermet"))
        .map(|metadata| metadata.is_file())
        .unwrap_or(false);
    let running = daemon_is_serving();
    println!();
    if running {
        println!("[cermet-setup] ✓ broker running (cermetd, starts at boot)");
    } else {
        println!("[cermet-setup] ✗ broker not running — run: cermet check");
    }
    if key_ready {
        for line in vault_ready_lines(custody) {
            println!("[cermet-setup] {line}");
        }
    } else {
        println!("[cermet-setup] ✗ credential vault key missing — run: cermet check");
    }
    if git_ready {
        println!("[cermet-setup] ✓ git integration ready (git-remote-cermet)");
    } else {
        println!("[cermet-setup] ✗ git integration missing — run: cermet check");
    }
    // The operator's own settings file, recorded and handed over, then the ONE line setup prints
    // about what it turned on. It sits after the probes (they report what the box did) and before
    // the next-step line, so the run still ends by naming what to do next. Default-on is only
    // legitimate if the run that enables it says what it does and what it does NOT do.
    record_operator_settings(approver);
    announce_update_check(approver);
    if running && key_ready && git_ready {
        println!("[cermet-setup] next: cermet connect github   (or vercel, stripe)");
    }
    if membership_added {
        println!(
            "[cermet-setup] note: {APPROVERS_GROUP} membership reaches existing sessions after a \
             re-log-in"
        );
    } else if !approver_in_group(approver) {
        #[cfg(target_os = "linux")]
        println!(
            "[cermet-setup] note: presence ceremonies need the human in {APPROVERS_GROUP}:\n\
             [cermet-setup]       sudo usermod -aG {APPROVERS_GROUP} {approver}  (then re-log-in)"
        );
        #[cfg(target_os = "macos")]
        println!(
            "[cermet-setup] note: presence ceremonies need the human in {APPROVERS_GROUP}:\n\
             [cermet-setup]       sudo dseditgroup -o edit -a {approver} -t user {APPROVERS_GROUP}"
        );
    }
}

/// Is `user` a member of [`APPROVERS_GROUP`], asked of the platform (`id -nG`)?
fn approver_in_group(user: &str) -> bool {
    Command::new("id")
        .args(["-nG", user])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .any(|group| group == APPROVERS_GROUP)
        })
        .unwrap_or(false)
}

/// The macOS delivery of the same install: identical step order and reporting to [`run_linux`],
/// with launchd for systemd, Directory Service for `useradd`, directly converged runtime dirs for
/// tmpfiles, and a plain owner-only key file for systemd-creds.
///
/// Presence has NO analog here yet — macOS presence is device-owner authentication
/// (LocalAuthentication), which is not implemented. Until it is, this installs no PAM equivalent
/// and presence-requiring ceremonies stay refused.
#[cfg(target_os = "macos")]
fn run_macos(args: &SetupArgs) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("must run as root (try: sudo cermet setup)".into());
    }
    require_commands(&["dscl", "id", "install", "chown", "visudo", "launchctl"])?;

    let sources = SourceLayout::resolve(args.from_tree.as_deref(), args.binary_source.as_deref())?;
    sources.preflight()?;
    let _lock = InstallLock::acquire(Path::new(INSTALL_LOCK))?;
    ok("preflight", "root, inputs, utilities, and install lock");

    ensure_role_group(SERVICE_GROUP, "Cermet Daemon")?;
    ensure_role_user(SERVICE_USER, SERVICE_GROUP, "Cermet Daemon")?;
    ensure_role_group(APPROVERS_GROUP, "Cermet Approvers")?;
    ensure_role_group(AGENTS_GROUP, "Cermet Agents")?;
    ensure_role_user(AGENT_USER, AGENTS_GROUP, "Cermet Agent")?;

    let service_uid = uid_for(SERVICE_USER)?;
    let agent_account_uid = uid_for(AGENT_USER)?;
    if service_uid == 0 || agent_account_uid == 0 || service_uid == agent_account_uid {
        return Err(format!(
            "partial topology: service uid {service_uid} and agent uid {agent_account_uid} \
             must be distinct and non-root"
        ));
    }
    assert_plane_topology(service_uid, agent_account_uid)?;
    ok(
        "accounts",
        &format!("service uid {service_uid}, agent uid {agent_account_uid}, disjoint groups"),
    );

    let cutover = ServiceCutover::begin(&sources)?;
    publish_multicall(&sources)?;
    publish_path_entry()?;
    // Before the plist is unlinked below: launchd holds a loaded job by its plist, so unlinking
    // first would strand a running helper with nothing left to address it by.
    bootout_retired_daemon(RETIRED_RUNTIME_DIR_LABEL)?;
    cleanup_retired_artifacts()?;

    install_dir(Path::new(CONFIG_DIR), "root", ROOT_GROUP, 0o755)?;
    let (approver_uid, agent_uid) =
        install_or_validate_config(&sources.config, service_uid, agent_account_uid)?;
    assert_config_matches_converged_runtime_dirs(
        &fs::read_to_string(CONFIG_DEST)
            .map_err(|error| format!("cannot re-read {CONFIG_DEST}: {error}"))?,
    )?;
    let approver = uid_name(approver_uid)?;
    if approver.is_empty() {
        return Err(format!(
            "approver uid {approver_uid} does not resolve to a user"
        ));
    }
    if agent_uid != agent_account_uid {
        return Err(format!(
            "configured agent_uid {agent_uid} does not match the {AGENT_USER} account uid \
             {agent_account_uid}"
        ));
    }
    install_dir(
        Path::new(SENTENCES_DIR),
        SERVICE_USER,
        APPROVERS_GROUP,
        0o2750,
    )?;
    fixed(
        "config",
        &format!("service_uid={service_uid}, approver_uid={approver_uid}, agent_uid={agent_uid}"),
    );

    install_sudoers(approver_uid)?;

    // No tmpfiles analog is needed: setup runs as root and owns convergence of these two dirs, and
    // they are persistent (see RUNTIME_DIR) so no boot-time helper has to recreate them. The
    // setgid bit is what makes ctl.sock/agent.sock inherit their group with no daemon chgrp — the
    // daemon re-asserts the exact 2711 layout before it binds and refuses otherwise.
    install_dir(
        Path::new(RUNTIME_DIR),
        SERVICE_USER,
        APPROVERS_GROUP,
        0o2711,
    )?;
    install_dir(
        Path::new(AGENT_RUNTIME_DIR),
        SERVICE_USER,
        AGENTS_GROUP,
        0o2711,
    )?;
    fixed(
        "runtime dirs",
        &format!("{RUNTIME_DIR} and {AGENT_RUNTIME_DIR} converged 2711"),
    );
    converge_daemon_log_file()?;

    if args.force_clean_bootstrap {
        force_clean_reset()?;
    }
    install_dir(Path::new(STATE_DIR), SERVICE_USER, SERVICE_GROUP, 0o700)?;
    // CUSTODY-LADDER: macOS has ONE rung today — the _cermet-owned 0600 key file. It is declared
    // through the same seam as Linux's, so every surface asks the config, not the platform.
    let custody = write_master_key(args.force_clean_bootstrap)?;
    record_custody_profile(custody)?;
    initialize_lockdown_record()?;
    seed_catalog(&sources.catalog)?;

    let plist = Path::new(PLIST_DEST);
    let converged = published_file_is_current(&sources.plist, plist, 0o644)?;
    install_dir(plist.parent().unwrap(), "root", ROOT_GROUP, 0o755)?;
    atomic_install_file(&sources.plist, plist, "root", ROOT_GROUP, 0o644)?;
    if converged {
        ok("launchd", "the installed plist already matches this build");
    } else {
        fixed("launchd", &format!("installed {PLIST_DEST}"));
    }
    install_update_check_scheduler(&sources, &approver)?;

    // Assets are installed; NOW the daemon setup stopped may come back on the newly published
    // binary.
    cutover.finish();
    // Membership needs no daemon, so it lands BEFORE the liveness gate: however the wait below
    // ends, the human can already reach the ctl socket — a slow boot must never leave the box
    // serving but unreachable by its own approver.
    let membership_added = ensure_approver_membership(&approver);
    // Install ends with the job bootstrapped and running — same rationale
    // as the Linux path: a fresh corpus is deny-all, so starting the daemon grants nothing.
    ensure_service_live()?;
    enable_update_check_scheduler();

    print_completion(&approver, membership_added, custody);
    report_cutover(&approver);
    Ok(())
}

fn require_regular_source(path: &Path, executable: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("must be a regular, non-symlink file".into());
    }
    if executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err("is not executable".into());
    }
    Ok(())
}

fn reject_non_installable_binary(path: &Path) -> Result<(), String> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    for (feature, reversed) in NON_INSTALLABLE_MARKERS_REVERSED {
        let marker = reversed.iter().rev().copied().collect::<Vec<_>>();
        if bytes
            .windows(marker.len())
            .any(|window| window == marker.as_slice())
        {
            return Err(format!(
                "refusing to install {}: cermet was compiled with {feature}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn require_commands(names: &[&str]) -> Result<(), String> {
    for name in names {
        if !command_exists(name) {
            return Err(format!("required command is unavailable: {name}"));
        }
    }
    Ok(())
}

fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|directory| {
            let path = directory.join(name);
            fs::metadata(path)
                .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
    })
}

struct InstallLock {
    path: PathBuf,
}

impl InstallLock {
    fn acquire(path: &Path) -> Result<Self, String> {
        fs::create_dir(path).map_err(|error| {
            format!(
                "another setup appears to be running ({} could not be created: {error})",
                path.display()
            )
        })?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

// ---- Account provisioning: NSS/shadow utilities on Linux, Directory Service on macOS ----------
// The two layers expose the same four questions to the shared code above (`uid_for`, `uid_name`,
// `primary_group_name`, `group_members`) plus their own ensure_* convergence.

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct PasswdEntry {
    uid: u32,
    gid: u32,
    shell: String,
}

#[cfg(target_os = "linux")]
fn getent(database: &str, key: &str) -> Result<Option<String>, String> {
    let output = Command::new("getent")
        .args([database, key])
        .output()
        .map_err(|error| format!("cannot run getent {database} {key}: {error}"))?;
    match output.status.code() {
        Some(0) => String::from_utf8(output.stdout)
            .map(Some)
            .map_err(|_| format!("getent {database} {key} returned non-UTF-8")),
        Some(2) => Ok(None),
        _ => Err(format!(
            "getent {database} {key} failed with {}",
            output.status
        )),
    }
}

#[cfg(target_os = "linux")]
fn passwd_entry(user: &str) -> Result<Option<PasswdEntry>, String> {
    let Some(row) = getent("passwd", user)? else {
        return Ok(None);
    };
    let fields: Vec<&str> = row.trim_end().split(':').collect();
    if fields.len() != 7 {
        return Err(format!("malformed passwd record for {user}"));
    }
    Ok(Some(PasswdEntry {
        uid: fields[2]
            .parse()
            .map_err(|_| format!("invalid uid in passwd record for {user}"))?,
        gid: fields[3]
            .parse()
            .map_err(|_| format!("invalid gid in passwd record for {user}"))?,
        shell: fields[6].to_string(),
    }))
}

#[cfg(target_os = "linux")]
fn group_record(group: &str) -> Result<Option<(u32, Vec<String>)>, String> {
    let Some(row) = getent("group", group)? else {
        return Ok(None);
    };
    let fields: Vec<&str> = row.trim_end().split(':').collect();
    if fields.len() != 4 {
        return Err(format!("malformed group record for {group}"));
    }
    let gid = fields[2]
        .parse()
        .map_err(|_| format!("invalid gid in group record for {group}"))?;
    let members = fields[3]
        .split(',')
        .filter(|member| !member.is_empty())
        .map(str::to_string)
        .collect();
    Ok(Some((gid, members)))
}

#[cfg(target_os = "linux")]
fn ensure_group(group: &str) -> Result<(), String> {
    if group_record(group)?.is_some() {
        ok("group", &format!("{group} already exists"));
        return Ok(());
    }
    let mut command = Command::new("groupadd");
    command.args(["--system", group]);
    checked(command, &format!("create system group {group}"))?;
    fixed("group", &format!("created {group}"));
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_user(user: &str, primary_group: &str, agent: bool) -> Result<(), String> {
    let expected_gid = group_record(primary_group)?
        .ok_or_else(|| format!("required group {primary_group} disappeared"))?
        .0;
    if let Some(entry) = passwd_entry(user)? {
        if entry.uid == 0
            || entry.gid != expected_gid
            || !matches!(
                entry.shell.as_str(),
                "/usr/sbin/nologin" | "/sbin/nologin" | "/bin/false" | "/usr/bin/false"
            )
        {
            return Err(format!(
                "partial provisioning: existing {user} must be non-root, nologin, with primary \
                 group {primary_group}"
            ));
        }
        if agent {
            let output = command_output("id", &["-Gn", user])?;
            let extras: Vec<&str> = output
                .split_whitespace()
                .filter(|group| *group != primary_group)
                .collect();
            if !extras.is_empty() {
                return Err(format!(
                    "partial provisioning: {user} has extra groups {}; expected only {primary_group}",
                    extras.join(",")
                ));
            }
        }
        ok("user", &format!("{user} posture is correct"));
        return Ok(());
    }
    let mut command = Command::new("useradd");
    command.args([
        "--system",
        "--no-create-home",
        "--shell",
        "/usr/sbin/nologin",
        "--gid",
        primary_group,
        user,
    ]);
    checked(command, &format!("create system user {user}"))?;
    fixed("user", &format!("created {user}"));
    Ok(())
}

#[cfg(target_os = "linux")]
fn uid_for(user: &str) -> Result<u32, String> {
    passwd_entry(user)?
        .map(|entry| entry.uid)
        .ok_or_else(|| format!("user {user} does not resolve"))
}

#[cfg(target_os = "linux")]
fn uid_name(uid: u32) -> Result<String, String> {
    let row = getent("passwd", &uid.to_string())?
        .ok_or_else(|| format!("uid {uid} does not resolve to an installed user"))?;
    Ok(row.split(':').next().unwrap_or_default().to_string())
}

#[cfg(target_os = "linux")]
fn primary_group_name(user: &str) -> Result<String, String> {
    let entry = passwd_entry(user)?.ok_or_else(|| format!("user {user} disappeared"))?;
    let row = getent("group", &entry.gid.to_string())?
        .ok_or_else(|| format!("gid {} for {user} does not resolve", entry.gid))?;
    Ok(row.split(':').next().unwrap_or_default().to_string())
}

#[cfg(target_os = "linux")]
fn group_members(group: &str) -> Result<Vec<String>, String> {
    Ok(group_record(group)?
        .ok_or_else(|| format!("required group {group} disappeared"))?
        .1)
}

// ---- macOS: Directory Service ----------------------------------------------------------------
// macOS ships no useradd/groupadd/getent. `dscl` is the native tool for both reading and writing
// the local node, and `id` answers the uid/name questions POSIX-style.

/// The one attribute value `dscl . -read <record> <key>` printed, or `None` when the record or the
/// key is absent. dscl prints either `Key: value`, a native-namespaced `dsAttrTypeNative:Key: value`
/// (so the value is after the LAST colon), or a bare `Key:` with the value indented on the next
/// line — the shape it always uses for `RealName`.
#[cfg(target_os = "macos")]
fn parse_dscl_scalar(stdout: &str) -> Option<String> {
    let text = stdout.trim_end();
    let first = text.lines().next()?;
    if first.starts_with("No such key") {
        return None;
    }
    let (_, inline) = first.rsplit_once(':')?;
    let inline = inline.trim();
    if !inline.is_empty() {
        return Some(inline.to_string());
    }
    let continued = text.lines().nth(1)?.trim();
    (!continued.is_empty()).then(|| continued.to_string())
}

/// The numeric ids in a `dscl . -list <path> <IdAttribute>` listing (`name<pad>id` per line).
/// Apple's own placeholder records carry negative ids, which parse as neither taken nor free.
#[cfg(target_os = "macos")]
fn parse_dscl_id_list(stdout: &str) -> BTreeSet<u32> {
    stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next_back()?.parse::<u32>().ok())
        .collect()
}

/// The lowest id in `range` nobody holds. Fails closed on a full range rather than reusing an id a
/// live account owns files under.
#[cfg(target_os = "macos")]
fn first_free_id(taken: &BTreeSet<u32>, range: std::ops::Range<u32>) -> Option<u32> {
    range.into_iter().find(|id| !taken.contains(id))
}

/// The id window role accounts are allocated from. macOS reserves everything under 500 for system
/// accounts and Apple's own occupy the low end; the installer starts above them.
#[cfg(target_os = "macos")]
const ROLE_ID_RANGE: std::ops::Range<u32> = 400..500;

/// The attributes a role account record must carry: a fixed identity, no shell, no home to write
/// into, no password to log in with, and hidden from the login window.
#[cfg(target_os = "macos")]
fn role_user_attributes(uid: u32, gid: u32, real_name: &str) -> Vec<(String, String)> {
    vec![
        ("UniqueID".into(), uid.to_string()),
        ("PrimaryGroupID".into(), gid.to_string()),
        ("UserShell".into(), "/usr/bin/false".into()),
        ("NFSHomeDirectory".into(), "/var/empty".into()),
        ("RealName".into(), real_name.into()),
        ("Password".into(), "*".into()),
        ("IsHidden".into(), "1".into()),
    ]
}

#[cfg(target_os = "macos")]
fn role_group_attributes(gid: u32, real_name: &str) -> Vec<(String, String)> {
    vec![
        ("PrimaryGroupID".into(), gid.to_string()),
        ("RealName".into(), real_name.into()),
        ("Password".into(), "*".into()),
    ]
}

#[cfg(target_os = "macos")]
fn dscl_read(record: &str, key: &str) -> Result<Option<String>, String> {
    let output = Command::new("dscl")
        .args([".", "-read", record, key])
        .output()
        .map_err(|error| format!("cannot run dscl -read {record} {key}: {error}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| format!("dscl -read {record} {key} returned non-UTF-8"))?;
    Ok(parse_dscl_scalar(&text))
}

#[cfg(target_os = "macos")]
fn dscl_create(record: &str, key: &str, value: &str) -> Result<(), String> {
    let mut command = Command::new("dscl");
    command.args([".", "-create", record, key, value]);
    checked(command, &format!("set {key} on {record}"))
}

#[cfg(target_os = "macos")]
fn dscl_taken_ids(node: &str, attribute: &str) -> Result<BTreeSet<u32>, String> {
    Ok(parse_dscl_id_list(&command_output(
        "dscl",
        &[".", "-list", node, attribute],
    )?))
}

/// Converge one Directory Service record to `attributes`, creating it when absent. Only the
/// attributes that actually differ are written, so a re-run reports `ok` instead of `fixed`.
/// `UniqueID`/`PrimaryGroupID` are part of `attributes` on creation only — an existing record's
/// identity is never re-assigned under files that already carry it.
#[cfg(target_os = "macos")]
fn converge_dscl_record(
    record: &str,
    label: &str,
    attributes: &[(String, String)],
) -> Result<(), String> {
    let existed = dscl_read(record, "RecordName")?.is_some();
    if !existed {
        dscl_create(
            record,
            "RecordName",
            record.rsplit('/').next().unwrap_or(record),
        )?;
    }
    let mut changed = Vec::new();
    for (key, value) in attributes {
        if existed && matches!(key.as_str(), "UniqueID") {
            continue;
        }
        if dscl_read(record, key)?.as_deref() == Some(value.as_str()) {
            continue;
        }
        dscl_create(record, key, value)?;
        changed.push(key.as_str());
    }
    if !existed {
        fixed(label, &format!("created {record}"));
    } else if changed.is_empty() {
        ok(label, &format!("{record} posture is correct"));
    } else {
        fixed(label, &format!("{record} converged {}", changed.join(", ")));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn ensure_role_group(group: &str, real_name: &str) -> Result<(), String> {
    let record = format!("/Groups/{group}");
    let gid = match dscl_read(&record, "PrimaryGroupID")? {
        Some(value) => value
            .parse()
            .map_err(|_| format!("{record} has a non-numeric PrimaryGroupID {value:?}"))?,
        None => first_free_id(&dscl_taken_ids("/Groups", "PrimaryGroupID")?, ROLE_ID_RANGE)
            .ok_or_else(|| format!("no free gid in {ROLE_ID_RANGE:?} for {group}"))?,
    };
    if gid == 0 {
        return Err(format!("{group} must not be gid 0"));
    }
    converge_dscl_record(&record, "group", &role_group_attributes(gid, real_name))
}

#[cfg(target_os = "macos")]
fn ensure_role_user(user: &str, primary_group: &str, real_name: &str) -> Result<(), String> {
    let group_record = format!("/Groups/{primary_group}");
    let gid: u32 = dscl_read(&group_record, "PrimaryGroupID")?
        .ok_or_else(|| format!("required group {primary_group} disappeared"))?
        .parse()
        .map_err(|_| format!("{group_record} has a non-numeric PrimaryGroupID"))?;
    let record = format!("/Users/{user}");
    let uid = match dscl_read(&record, "UniqueID")? {
        Some(value) => value
            .parse()
            .map_err(|_| format!("{record} has a non-numeric UniqueID {value:?}"))?,
        None => first_free_id(&dscl_taken_ids("/Users", "UniqueID")?, ROLE_ID_RANGE)
            .ok_or_else(|| format!("no free uid in {ROLE_ID_RANGE:?} for {user}"))?,
    };
    if uid == 0 {
        return Err(format!("{user} must not be uid 0"));
    }
    converge_dscl_record(&record, "user", &role_user_attributes(uid, gid, real_name))
}

#[cfg(target_os = "macos")]
fn uid_for(user: &str) -> Result<u32, String> {
    command_output("id", &["-u", user])?
        .trim()
        .parse()
        .map_err(|_| format!("user {user} does not resolve to a numeric uid"))
}

#[cfg(target_os = "macos")]
fn uid_name(uid: u32) -> Result<String, String> {
    Ok(command_output("id", &["-un", &uid.to_string()])
        .map_err(|error| format!("uid {uid} does not resolve to an installed user: {error}"))?
        .trim()
        .to_string())
}

#[cfg(target_os = "macos")]
fn primary_group_name(user: &str) -> Result<String, String> {
    Ok(command_output("id", &["-gn", user])?.trim().to_string())
}

#[cfg(target_os = "macos")]
fn group_members(group: &str) -> Result<Vec<String>, String> {
    let record = format!("/Groups/{group}");
    if dscl_read(&record, "PrimaryGroupID")?.is_none() {
        return Err(format!("required group {group} disappeared"));
    }
    Ok(dscl_read(&record, "GroupMembership")?
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect())
}

fn assert_not_member(user: &str, group: &str) -> Result<(), String> {
    let members = group_members(group)?;
    if members.iter().any(|member| member == user) || primary_group_name(user)? == group {
        return Err(format!(
            "partial topology: {user} must not be a member of {group}"
        ));
    }
    Ok(())
}

fn assert_plane_topology(service_uid: u32, agent_uid: u32) -> Result<(), String> {
    // TOPOLOGY DOCUMENTATION: `cermet ∉ cermet-approvers` remains a cheap assertion describing
    // the intended three-plane shape. The real custody boundary is the service uid: daemon files
    // and memory are inaccessible to the human's agent-running uid (no same-uid read or ptrace).
    assert_not_member(SERVICE_USER, APPROVERS_GROUP)?;
    assert_not_member(AGENT_USER, APPROVERS_GROUP)?;
    assert_not_member(SERVICE_USER, AGENTS_GROUP)?;
    if service_uid == agent_uid {
        return Err("service and agent accounts share a uid".into());
    }
    Ok(())
}

fn assert_root_secure(path: &Path) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
        return Err(format!(
            "{} must be a root-owned directory with no group/other write bits",
            path.display()
        ));
    }
    Ok(())
}

/// Is the published multicall layout already exactly what publishing would produce — one regular
/// `0755` target holding `source`'s bytes, plus both aliases as symlinks whose target is EXACTLY the
/// relative name `cermet`?
///
/// Every question is asked with `symlink_metadata`/`read_link`. An unexpected link is never followed
/// while deciding whether the install is current: a `cermetd` pointing somewhere else must read as
/// NOT converged, not as "well, it resolves to a cermet".
fn multicall_layout_is_current(bin_dir: &Path, source: &Path) -> Result<bool, String> {
    if !published_binary_is_current(source, &bin_dir.join(MULTICALL_TARGET))? {
        return Ok(false);
    }
    for alias in MULTICALL_ALIASES {
        if !alias_is_current(bin_dir, alias)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Is `alias` already the exact relative symlink to [`MULTICALL_TARGET`]?
fn alias_is_current(bin_dir: &Path, alias: &str) -> Result<bool, String> {
    let path = bin_dir.join(alias);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    };
    if !metadata.file_type().is_symlink() {
        return Ok(false);
    }
    let target = fs::read_link(&path)
        .map_err(|error| format!("cannot read the link at {}: {error}", path.display()))?;
    Ok(target == Path::new(MULTICALL_TARGET))
}

/// Publish ONE regular target plus its two exact relative aliases into `bin_dir`.
///
/// `root_owned` stages through `install -o root -g <root group>`; the unprivileged layout fixture
/// passes false so the same publication code — not a re-implementation of it — is what the layout
/// test exercises.
///
/// Ordering is load-bearing: the target lands FIRST, so an alias never points at a missing file. The
/// renames are atomic individually; there is no multi-name filesystem transaction and none is
/// claimed. Once the aliases exist, one atomic rename of the target changes the generation used by
/// every FUTURE exec — it does not touch a running process, which is what the mandatory Hello
/// build-equality check and the service restart below are for.
fn publish_multicall_into(bin_dir: &Path, source: &Path, root_owned: bool) -> Result<(), String> {
    let mut staged = StagedFiles::default();
    staged.stage(source, &bin_dir.join(MULTICALL_TARGET), 0o755, root_owned)?;
    staged.commit()?;

    for alias in MULTICALL_ALIASES {
        if alias_is_current(bin_dir, alias)? {
            continue;
        }
        let destination = bin_dir.join(alias);
        let stage = unique_path(bin_dir, &format!(".{alias}.stage"))?;
        std::os::unix::fs::symlink(MULTICALL_TARGET, &stage).map_err(|error| {
            format!(
                "cannot stage the {alias} alias at {}: {error}",
                stage.display()
            )
        })?;
        if let Err(error) = fs::rename(&stage, &destination) {
            let _ = fs::remove_file(&stage);
            return Err(format!(
                "failed to publish the {alias} alias at {}: {error}; re-run setup to converge",
                destination.display()
            ));
        }
    }
    Ok(())
}

/// The service half of publication: the one fact an atomic rename cannot fix.
///
/// A Unix process keeps executing the inode it mapped; replacing the file changes only what the
/// NEXT exec gets. A live daemon therefore stays on the old build until it is restarted, which is
/// why setup restarts it whenever publication actually changed something. (Live agent sessions are
/// the other half, and are handled by the mandatory Hello build-equality check: their MCP bridges
/// fail closed with a typed restart refusal instead of quietly speaking an obsolete schema. Setup
/// never kills a session.)
///
/// Every step is idempotent: a converged install stops nothing, and a run that failed part way
/// converges on the next one.
struct ServiceCutover {
    /// The service was running when setup started, so setup owes the operator a running service.
    was_running: bool,
    /// Whether setup stopped it (and must therefore start it again).
    stopped: bool,
}

impl ServiceCutover {
    /// Decide what the service needs, and — if publication will change anything — stop it and prove
    /// it stopped BEFORE the first byte is published.
    fn begin(sources: &SourceLayout) -> Result<Self, String> {
        let bin_dir = Path::new(INSTALL_BIN_DIR);
        let converged = multicall_layout_is_current(bin_dir, &sources.binary)?;
        let was_running = daemon_is_running();
        let mut cutover = Self {
            was_running,
            stopped: false,
        };
        if converged {
            // Nothing to publish, so nothing to coordinate — an already-current install must not
            // bounce the operator's daemon just for running setup again.
            return Ok(cutover);
        }
        if was_running {
            stop_and_prove_daemon_stopped(StopReason::Publication)?;
            cutover.stopped = true;
            fixed(
                "service",
                "stopped cermetd so the running daemon cannot outlive its own publication",
            );
        }
        Ok(cutover)
    }

    /// Bring the service back if setup stopped it. A failure to start is REPORTED with the exact
    /// recovery command and left stopped — never silently rolled back under clients that may already
    /// have started on the new binary.
    fn finish(&self) {
        if !self.stopped {
            if self.was_running {
                ok("service", "cermetd was already current and stayed running");
            }
            return;
        }
        match start_daemon_service() {
            Ok(()) => fixed("service", "restarted cermetd on the newly published binary"),
            Err(error) => println!(
                "[cermet-setup] WARN service: {error}\n\
                 [cermet-setup]      the new binary is published; the daemon is NOT running. Start \
                 it with:\n\
                 [cermet-setup]        {}",
                start_daemon_command()
            ),
        }
    }
}

/// True while the service manager holds a running daemon.
#[cfg(target_os = "linux")]
fn daemon_is_running() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "cermetd.service"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn daemon_is_running() -> bool {
    launchd_job_is_loaded()
}

/// Is the broker actually SERVING? Distinct from [`daemon_is_running`] on macOS, where loadedness
/// and liveness are different questions: a crash-looping LaunchDaemon is loaded. The
/// cutover still asks the loadedness question — it needs to know whether there is a job to stop —
/// but every line setup PRINTS about the broker comes from this one.
#[cfg(target_os = "linux")]
fn daemon_is_serving() -> bool {
    // systemd already answers the serving question: a crash-looping unit reports `activating` or
    // `failed`, never `active`.
    daemon_is_running()
}

#[cfg(target_os = "macos")]
fn daemon_is_serving() -> bool {
    parse_launchd_print(&launchd_print_text()).is_running() && ctl_socket_present()
}

#[cfg(target_os = "linux")]
fn start_daemon_service() -> Result<(), String> {
    let mut start = Command::new("systemctl");
    start.args(["start", "cermetd.service"]);
    checked(start, "restart cermetd after publication")?;
    if !daemon_is_running() {
        return Err("cermetd did not come back up after publication".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn start_daemon_service() -> Result<(), String> {
    let mut bootstrap = Command::new("launchctl");
    bootstrap.args(["bootstrap", "system", PLIST_DEST]);
    checked(bootstrap, "re-bootstrap cermetd after publication")?;
    // Loadedness is not the question: a job that launchd accepted and then failed to
    // spawn is loaded, and reporting it as "back up" is how a dead broker got green-lit.
    wait_until_serving()
}

#[cfg(target_os = "linux")]
fn start_daemon_command() -> String {
    "sudo systemctl start cermetd".to_string()
}

#[cfg(target_os = "macos")]
fn start_daemon_command() -> String {
    format!("sudo launchctl bootstrap system {PLIST_DEST}")
}

/// Publish the one binary and its role aliases into the install prefix.
fn publish_multicall(sources: &SourceLayout) -> Result<(), String> {
    // BSD/GNU `install -d` converges the TARGET's owner and mode but leaves pre-existing
    // intermediates alone, so creating the prefix explicitly is what keeps `/opt` (macOS) and
    // `/usr` (Linux) untouched. On Linux the prefix already exists and is not ours to create.
    #[cfg(target_os = "macos")]
    install_dir(Path::new(INSTALL_PREFIX), "root", ROOT_GROUP, 0o755)?;
    install_dir(Path::new(INSTALL_BIN_DIR), "root", ROOT_GROUP, 0o755)?;
    assert_root_secure(Path::new(INSTALL_PREFIX))?;
    // The root-owned, non-operator-writable bin directory is what makes the sudoers rule's exact
    // path mean fixed BYTES. It is asserted, not assumed: symlink ownership is irrelevant here —
    // the DIRECTORY is what prevents replacement.
    assert_root_secure(Path::new(INSTALL_BIN_DIR))?;

    // A converged layout is left UNTOUCHED, not re-staged: `ServiceCutover::begin` skips the
    // restart on the same answer, so republishing here would re-mint the target's inode under a
    // daemon that keeps running the old one — every idempotent re-run of setup would leave the live
    // service on a deleted inode. Ownership of the target is not compared — only root could have
    // changed it, and root is not an adversary.
    let converged = multicall_layout_is_current(Path::new(INSTALL_BIN_DIR), &sources.binary)?;
    if !converged {
        publish_multicall_into(Path::new(INSTALL_BIN_DIR), &sources.binary, true)?;
    }

    let detail = format!(
        "one root:{ROOT_GROUP} 0755 {MULTICALL_TARGET} from {}, with {} and {} as relative role \
         aliases to it",
        sources.binary.parent().unwrap_or(&sources.binary).display(),
        MULTICALL_ALIASES[0],
        MULTICALL_ALIASES[1],
    );
    if converged {
        ok("binary", &format!("already published {detail}"));
    } else {
        fixed("binary", &format!("published {detail}"));
    }
    Ok(())
}

/// The `/etc/paths.d/cermet` document: one line, the install bin dir. `path_helper` reads it at
/// login and appends it to PATH.
#[cfg(target_os = "macos")]
fn paths_d_document() -> String {
    format!("{INSTALL_BIN_DIR}\n")
}

/// Publish the PATH entry. macOS-only: on Linux the prefix is already on every PATH.
#[cfg(target_os = "macos")]
fn publish_path_entry() -> Result<(), String> {
    let destination = Path::new(PATHS_D_DEST);
    let document = paths_d_document();
    let converged = fs::read_to_string(destination).is_ok_and(|current| current == document);
    install_dir(destination.parent().unwrap(), "root", ROOT_GROUP, 0o755)?;
    atomic_write(destination, document.as_bytes(), "root", ROOT_GROUP, 0o644)?;
    if converged {
        ok(
            "PATH",
            &format!("{PATHS_D_DEST} already names {INSTALL_BIN_DIR}"),
        );
    } else {
        fixed(
            "PATH",
            &format!(
                "{PATHS_D_DEST} names {INSTALL_BIN_DIR} (new login shells, or `eval $(/usr/libexec/path_helper -s)`)"
            ),
        );
    }
    Ok(())
}

/// Refuse an installed config whose socket dirs are not the ones this install just converged.
///
/// `install_or_validate_config` deliberately PRESERVES an existing `/etc/cermetd/config.toml` — it
/// is the operator's file, and setup does not rewrite it. But a config carried over from another
/// platform layout (an earlier macOS installer wrote `/var/run/cermetd`) passes every
/// other check, so setup would print "complete" and the daemon would then crash-loop under
/// `KeepAlive` complaining about directory modes for a directory nothing created. Fail closed here,
/// naming both sides and the remedy, instead of shipping a documented crash loop.
#[cfg(target_os = "macos")]
fn assert_config_matches_converged_runtime_dirs(config: &str) -> Result<(), String> {
    for (key, converged) in [
        ("runtime_dir", RUNTIME_DIR),
        ("agent_runtime_dir", AGENT_RUNTIME_DIR),
    ] {
        let configured = active_string_value(config, key)?;
        if configured.as_deref() != Some(converged) {
            let found = match configured {
                Some(value) => format!("{value:?}"),
                None => "nothing".to_string(),
            };
            return Err(format!(
                "{CONFIG_DEST} sets {key} to {found}, but this install converged {converged}. The \
                 daemon would find no socket dir there and crash-loop under KeepAlive. This config \
                 predates the current layout and is not migrated — clear it and re-run:\n    \
                 sudo rm -rf /etc/cermetd \"/Library/Application Support/cermetd\""
            ));
        }
    }
    Ok(())
}

/// True when `destination` is already a regular, non-symlink `0755` file holding exactly the
/// bytes of `source` — i.e. publishing would change nothing.
fn published_binary_is_current(source: &Path, destination: &Path) -> Result<bool, String> {
    published_file_is_current(source, destination, 0o755)
}

/// The same question for an installed file at any mode: would publishing change a byte?
fn published_file_is_current(source: &Path, destination: &Path, mode: u32) -> Result<bool, String> {
    let metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!("cannot inspect {}: {error}", destination.display()));
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o7777 != mode
    {
        return Ok(false);
    }
    let published = fs::read(destination)
        .map_err(|error| format!("cannot read {}: {error}", destination.display()))?;
    let staging =
        fs::read(source).map_err(|error| format!("cannot read {}: {error}", source.display()))?;
    Ok(published == staging)
}

#[derive(Default)]
struct StagedFiles {
    pairs: Vec<(PathBuf, PathBuf)>,
    committed: bool,
}

impl StagedFiles {
    /// Stage `source` for an atomic rename onto `destination`.
    ///
    /// `root_owned` is false ONLY in the unprivileged layout fixture, so the publication and
    /// migration tests drive this exact code rather than a twin of it.
    fn stage(
        &mut self,
        source: &Path,
        destination: &Path,
        mode: u32,
        root_owned: bool,
    ) -> Result<(), String> {
        let parent = destination
            .parent()
            .ok_or_else(|| format!("{} has no parent", destination.display()))?;
        let stage = unique_path(
            parent,
            &format!(
                ".{}.stage",
                destination
                    .file_name()
                    .unwrap_or_else(|| OsStr::new("cermet"))
                    .to_string_lossy()
            ),
        )?;
        let mut command = Command::new("install");
        if root_owned {
            command.args(["-o", "root", "-g", ROOT_GROUP]);
        }
        command
            .args(["-m", &format!("{mode:04o}")])
            .arg(source)
            .arg(&stage);
        checked(
            command,
            &format!("stage {} from {}", destination.display(), source.display()),
        )?;
        self.pairs.push((stage, destination.to_path_buf()));
        Ok(())
    }

    fn commit(&mut self) -> Result<(), String> {
        for (stage, destination) in &self.pairs {
            fs::rename(stage, destination).map_err(|error| {
                format!(
                    "failed to publish {} from {}: {error}; re-run setup to converge",
                    destination.display(),
                    stage.display()
                )
            })?;
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for StagedFiles {
    fn drop(&mut self) {
        if !self.committed {
            for (stage, _) in &self.pairs {
                let _ = fs::remove_file(stage);
            }
        }
    }
}

/// Name what this install could NOT stop or repoint — retired/deleted/out-of-prefix
/// cermet processes (a process outlives the unlink of its own binary) and MCP registrations that
/// launch a cermet from somewhere else. REPORTING only, and best effort: a probe that cannot answer
/// prints a note. Nothing here fails an install, and nothing here kills anything.
fn report_cutover(approver: &str) {
    let home = home_dir_of(approver);
    let report = crate::cutover::detect(home.as_deref());
    if let Some(block) = crate::cutover::setup_receipt_lines(&report) {
        println!("{block}");
    }
}

/// The human's home directory — where an agent client keeps its MCP registrations. `setup` runs as
/// root under `sudo`, so `$HOME` is root's; the approver account is the human, and the platform's
/// own directory service is the only thing that knows where their home is.
#[cfg(target_os = "linux")]
fn home_dir_of(user: &str) -> Option<PathBuf> {
    let row = getent("passwd", user).ok()??;
    row.trim_end()
        .split(':')
        .nth(5)
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

#[cfg(target_os = "macos")]
fn home_dir_of(user: &str) -> Option<PathBuf> {
    dscl_read(&format!("/Users/{user}"), "NFSHomeDirectory")
        .ok()?
        .map(PathBuf::from)
}

/// Every path this build retires on this platform. One list, so the sweep below and the cutover
/// probe that looks for a retired binary still RUNNING can never disagree about what is retired.
pub(crate) fn retired_artifacts() -> Vec<&'static str> {
    RETIRED_BINARIES
        .iter()
        .chain(RETIRED_PLATFORM_ARTIFACTS)
        .copied()
        .collect()
}

/// Stop and disable the retired upload timer before its unit files are unlinked.
///
/// Only when something of it is actually on this box: a `systemctl disable` for a unit systemd has
/// never heard of is a non-zero exit and a line of noise on every fresh install. A failure is
/// ignored — the files go either way, and a box whose systemd cannot answer still ends up without
/// the units.
#[cfg(target_os = "linux")]
fn stop_retired_upload_timer() {
    let present = RETIRED_PLATFORM_ARTIFACTS
        .iter()
        .any(|path| path_exists_no_follow(Path::new(path)));
    if !present {
        return;
    }
    let mut disable = Command::new("systemctl");
    disable
        .args(["disable", "--now", RETIRED_UPLOAD_TIMER])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = disable.status();
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn stop_retired_upload_timer() {}

/// The macOS half: unload the retired job before its plist is unlinked, so launchd is never left
/// holding a job with no plist.
#[cfg(target_os = "macos")]
fn stop_retired_upload_timer() {
    let _ = bootout_retired_daemon(RETIRED_UPLOAD_LABEL);
}

fn cleanup_retired_artifacts() -> Result<(), String> {
    stop_retired_upload_timer();
    for retired in RETIRED_BINARIES.iter().chain(RETIRED_PLATFORM_ARTIFACTS) {
        let path = Path::new(retired);
        if path_exists_no_follow(path) {
            fs::remove_file(path)
                .map_err(|error| format!("cannot remove retired artifact {retired}: {error}"))?;
            fixed("cleanup", &format!("removed retired artifact {retired}"));
        }
    }
    Ok(())
}

fn prepare_new_config(
    template: &str,
    service_uid: u32,
    approver_uid: Option<u32>,
    agent_uid: u32,
) -> Result<String, String> {
    let approver_uid =
        approver_uid.ok_or_else(|| "cannot derive a distinct human approver uid".to_string())?;
    if service_uid == 0
        || approver_uid == 0
        || agent_uid == 0
        || service_uid == approver_uid
        || service_uid == agent_uid
        || approver_uid == agent_uid
    {
        return Err(format!(
            "service_uid={service_uid}, approver_uid={approver_uid}, and agent_uid={agent_uid} \
             must be pairwise distinct and non-root"
        ));
    }
    let config = set_numeric_key(template, "service_uid", service_uid);
    let config = set_numeric_key(&config, "approver_uid", approver_uid);
    Ok(set_numeric_key(&config, "agent_uid", agent_uid))
}

fn set_numeric_key(config: &str, key: &str, value: u32) -> String {
    let mut replaced = false;
    let mut lines = Vec::new();
    for line in config.lines() {
        if !replaced && line_assigns_key(line, key) {
            lines.push(format!("{key} = {value}"));
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        lines.push(format!("{key} = {value}"));
    }
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

/// The string-valued sibling of [`set_numeric_key`], for the declared `custody_profile`. Same rule:
/// rewrite the one ACTIVE line that assigns the key, and append only when no active line exists.
/// Comments are never touched: the templates carry the key in prose examples and a designated
/// placeholder, and rewriting whichever comment happened to come first put the live setting in
/// the middle of the documentation.
pub(crate) fn set_string_key(config: &str, key: &str, value: &str) -> String {
    let mut replaced = false;
    let mut lines = Vec::new();
    for line in config.lines() {
        if !replaced && line_assigns_key(line, key) {
            lines.push(format!("{key} = {value:?}"));
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        lines.push(format!("{key} = {value:?}"));
    }
    let mut output = lines.join("\n");
    output.push('\n');
    output
}

/// True when `line` is an ACTIVE `key = …` assignment. A commented line never matches: its
/// leading `#` survives `trim_start`, so the key prefix is not at the front.
fn line_assigns_key(line: &str, key: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix(key) else {
        return false;
    };
    rest.trim_start().starts_with('=')
}

/// Parse an operator config with the same parser the daemon uses (the `toml` crate), so exactly
/// ONE grammar exists for these files: the hand parser accepted a subset — it read a
/// single-quoted TOML string as absence — and two parsers for one file is a divergence class,
/// not a convenience.
fn toml_document(config: &str) -> Result<toml::Value, String> {
    toml::from_str(config).map_err(|error| format!("config is not valid TOML: {error}"))
}

fn active_uid(config: &str, key: &str) -> Result<u32, String> {
    toml_document(config)?
        .get(key)
        .and_then(toml::Value::as_integer)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|uid| *uid != 0)
        .ok_or_else(|| format!("config must contain exactly one active non-root numeric {key}"))
}

fn parse_uid_env(name: &str) -> Result<Option<u32>, String> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u32>()
            .map(Some)
            .map_err(|_| format!("{name}={value:?} is not a non-negative integer")),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(format!("cannot read {name}: {error}")),
    }
}

fn install_or_validate_config(
    template_path: &Path,
    service_uid: u32,
    agent_account_uid: u32,
) -> Result<(u32, u32), String> {
    let template = fs::read_to_string(template_path)
        .map_err(|error| format!("cannot read {}: {error}", template_path.display()))?;
    let destination = Path::new(CONFIG_DEST);
    if destination.exists() {
        atomic_write(
            Path::new(&format!("{CONFIG_DEST}.new")),
            template.as_bytes(),
            "root",
            ROOT_GROUP,
            0o644,
        )?;
        let mut config = fs::read_to_string(destination)
            .map_err(|error| format!("cannot read {CONFIG_DEST}: {error}"))?;
        let current_agent = active_uid_allow_unset(&config, "agent_uid")?;
        if current_agent.is_none() {
            let seed = parse_uid_env("CERMET_AGENT_UID")?.unwrap_or(agent_account_uid);
            config = set_numeric_key(&config, "agent_uid", seed);
            atomic_write(destination, config.as_bytes(), "root", ROOT_GROUP, 0o644)?;
            fixed("config", &format!("seeded agent_uid={seed}"));
        } else {
            ok("config", "preserved authoritative existing config");
        }
    } else {
        let approver_uid = parse_uid_env("CERMET_APPROVER_UID")?.or(parse_uid_env("SUDO_UID")?);
        let agent_uid = parse_uid_env("CERMET_AGENT_UID")?.unwrap_or(agent_account_uid);
        let config = prepare_new_config(&template, service_uid, approver_uid, agent_uid)?;
        atomic_write(destination, config.as_bytes(), "root", ROOT_GROUP, 0o644)?;
        fixed("config", "installed bootable config with resolved uids");
    }

    let installed = fs::read_to_string(destination)
        .map_err(|error| format!("cannot read installed config: {error}"))?;
    let configured_service = active_uid(&installed, "service_uid")?;
    let approver_uid = active_uid(&installed, "approver_uid")?;
    let agent_uid = active_uid(&installed, "agent_uid")?;
    if configured_service != service_uid {
        return Err(format!(
            "existing config service_uid={configured_service} does not match {SERVICE_USER} uid \
             {service_uid}; refusing partial provisioning"
        ));
    }
    if [configured_service, approver_uid, agent_uid]
        .iter()
        .collect::<BTreeSet<_>>()
        .len()
        != 3
    {
        return Err("configured service/approver/agent uids are not pairwise distinct".into());
    }
    uid_name(approver_uid)?;
    uid_name(agent_uid)?;
    Ok((approver_uid, agent_uid))
}

fn active_uid_allow_unset(config: &str, key: &str) -> Result<Option<u32>, String> {
    match toml_document(config)?.get(key) {
        None => Ok(None),
        Some(value) => {
            let uid = value
                .as_integer()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| format!("{key} must be numeric"))?;
            Ok((uid != 0).then_some(uid))
        }
    }
}

fn assert_sudoers_username_safe(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|value| value == '_' || value.is_ascii_lowercase());
    if !first_ok
        || !chars.all(|value| {
            value == '_' || value == '-' || value.is_ascii_lowercase() || value.is_ascii_digit()
        })
    {
        return Err(format!(
            "approver username {name:?} is unsafe for sudoers interpolation"
        ));
    }
    match name.to_ascii_uppercase().as_str() {
        "ALL" | "ROOT" | "DEFAULTS" | "CMND_ALIAS" | "USER_ALIAS" | "RUNAS_ALIAS"
        | "HOST_ALIAS" => Err(format!("approver username {name:?} is reserved by sudoers")),
        _ => Ok(()),
    }
}

/// The ONE agent-plane invocation the sudoers rule admits: the stdio MCP bridge with its socket
/// PINNED in argv. It is the only rule: the one-shot catalog subcommand a second rule once existed
/// for is deleted, and that argv must never reappear here. Written per
/// platform as a whole literal, because sudo matches the command byte for byte and each platform's
/// agents runtime dir differs — `the_sudoers_rule_admits_exactly_the_registered_bridge_invocation`
/// pins it to what `mcp::agent_launch` registers.
#[cfg(target_os = "macos")]
fn agent_bridge_command() -> String {
    format!("{CLI_DEST} --socket /var/cermetd-agents/agent.sock mcp")
}

#[cfg(not(target_os = "macos"))]
fn agent_bridge_command() -> String {
    format!("{CLI_DEST} --socket /run/cermetd-agents/agent.sock mcp")
}

fn install_sudoers(approver_uid: u32) -> Result<(), String> {
    let approver = uid_name(approver_uid)?;
    assert_sudoers_username_safe(&approver)?;
    install_dir(Path::new("/etc/sudoers.d"), "root", ROOT_GROUP, 0o755)?;
    let command = agent_bridge_command();
    let mut lines = vec![
        "# /etc/sudoers.d/cermet-agent — managed by `cermet setup`; do not hand-edit.".to_string(),
        format!("{approver} ALL=({AGENT_USER}:{AGENTS_GROUP}) NOPASSWD:NOSETENV: {command}"),
    ];
    let mut bytes = validated_sudoers_document(&lines, validate_sudoers_bytes)?;
    let mut kept = 0;
    for candidate in [
        format!("Defaults:{approver} !use_pty"),
        format!("Defaults:{approver} !requiretty"),
        format!("Defaults:{approver} env_reset"),
    ] {
        let mut trial = lines.clone();
        trial.push(candidate.clone());
        match validated_sudoers_document(&trial, validate_sudoers_bytes) {
            Ok(trial_bytes) => {
                lines = trial;
                bytes = trial_bytes;
                kept += 1;
            }
            Err(_) => {
                ok(
                    "sudoers",
                    &format!("installed visudo rejects optional {candidate:?}; omitted"),
                );
            }
        }
    }
    atomic_write_validated(
        Path::new(SUDOERS_DEST),
        &bytes,
        "root",
        ROOT_GROUP,
        0o440,
        validate_sudoers_path,
    )?;
    fixed(
        "sudoers",
        &format!("atomic visudo-validated install; {kept}/3 optional defaults retained"),
    );
    Ok(())
}

fn validated_sudoers_document(
    lines: &[String],
    validate: impl FnOnce(&[u8]) -> Result<(), String>,
) -> Result<Vec<u8>, String> {
    let mut bytes = lines.join("\n").into_bytes();
    bytes.push(b'\n');
    validate(&bytes)?;
    Ok(bytes)
}

fn validate_sudoers_bytes(bytes: &[u8]) -> Result<(), String> {
    let path = unique_path(Path::new("/etc/sudoers.d"), ".cermet-agent.validate")?;
    let result = (|| {
        fs::write(&path, bytes)
            .map_err(|error| format!("cannot stage sudoers validation: {error}"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o440))
            .map_err(|error| format!("cannot chmod sudoers validation: {error}"))?;
        validate_sudoers_path(&path)
    })();
    let _ = fs::remove_file(path);
    result
}

fn validate_sudoers_path(path: &Path) -> Result<(), String> {
    let status = Command::new("visudo")
        .arg("-cf")
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot run visudo: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("sudoers rule failed `visudo -cf`; refusing to publish".into())
    }
}

/// Why setup is stopping the daemon. The CHECK is identical either way — the daemon must be proved
/// stopped — but the two callers are answering different operator questions, and a refusal that
/// names the wrong one sends the operator looking for a problem they do not have.
#[derive(Debug, Clone, Copy)]
enum StopReason {
    /// `--force-clean-bootstrap`: the vendor reset is about to delete state.
    ForceClean,
    /// An ordinary publication: a running daemon must not outlive the binary it is running.
    Publication,
}

impl StopReason {
    /// The refusal this caller's failure means, in the operator's terms.
    fn refusal(self, detail: &str) -> String {
        match self {
            Self::ForceClean => format!(
                "force-clean could not prove the daemon stopped ({detail}); no state removed"
            ),
            Self::Publication => format!(
                "setup could not prove the daemon stopped ({detail}); nothing was published, so \
                 the installed binary and the running daemon still match — stop it by hand and \
                 re-run setup"
            ),
        }
    }
}

/// Stop the daemon and PROVE it stopped. The stop itself is best-effort (an unloaded daemon is a
/// no-op); the proof is not, for two different reasons — see [`StopReason`]. Under
/// [`StopReason::ForceClean`] a survivor would have the vault open while the reset deletes it; under
/// [`StopReason::Publication`] a survivor could be restarted through the still-old `cermetd` path
/// mid-migration, starting the OLD daemon under clients that already have the new binary.
#[cfg(target_os = "linux")]
fn stop_and_prove_daemon_stopped(reason: StopReason) -> Result<(), String> {
    let mut stop = Command::new("systemctl");
    stop.args(["stop", "cermetd.service"]);
    let _ = stop.status();
    let active = Command::new("systemctl")
        .args(["is-active", "cermetd.service"])
        .output()
        .map_err(|error| format!("cannot prove cermetd inactive: {error}"))?;
    let state_text = String::from_utf8_lossy(&active.stdout).trim().to_string();
    if !matches!(state_text.as_str(), "inactive" | "failed") {
        return Err(reason.refusal(&format!(
            "cermetd.service reported {state_text:?} after stop"
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn stop_and_prove_daemon_stopped(reason: StopReason) -> Result<(), String> {
    let mut bootout = Command::new("launchctl");
    bootout
        .args(["bootout", &launchd_service_target()])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = bootout.status();
    if launchd_job_is_loaded() {
        return Err(reason.refusal(&format!(
            "the {PLIST_LABEL} LaunchDaemon is still loaded after bootout"
        )));
    }
    Ok(())
}

/// The launchd service target for the daemon: the system-domain job addressed by `bootout`/`print`.
#[cfg(any(target_os = "macos", test))]
fn launchd_service_target() -> String {
    format!("system/{PLIST_LABEL}")
}

/// The two fields of a `launchctl print system/<label>` report that discriminate a SERVING daemon
/// from a launchd child that never reached `main`. Absent fields stay `None` — a missing
/// job prints nothing to stdout, and "no state" must never read as running.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Default, PartialEq, Eq)]
struct LaunchdJobStatus {
    state: Option<String>,
    last_exit_code: Option<String>,
}

#[cfg(any(target_os = "macos", test))]
impl LaunchdJobStatus {
    /// launchd has exactly one state that means the program is up: `running`. `spawn scheduled`,
    /// `waiting`, and `exited` are all loaded-but-not-serving.
    fn is_running(&self) -> bool {
        self.state.as_deref() == Some("running")
    }

    /// The daemon has exited at least once this load: crash evidence. A healthy job prints the
    /// literal `(never exited)` for this field until its first exit.
    fn has_exit_evidence(&self) -> bool {
        matches!(self.last_exit_code.as_deref(), Some(code) if code != "(never exited)")
    }
}

/// One launchctl snapshot, read three ways.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug, PartialEq, Eq)]
enum ServingPoll {
    /// Running with the ctl socket bound: the install's liveness claim holds.
    Serving,
    /// Alive or scheduled, never exited: a boot in progress. Not a verdict — keep watching.
    StillStarting,
    /// Evidence of failure: the daemon has exited, or launchd holds no job at all.
    Failed,
}

/// PURE. Decide what one snapshot means. Failure requires EVIDENCE (an exit code, a missing job);
/// elapsed time is deliberately not an input — a slow first boot and a fast one are
/// indistinguishable at every instant, so time alone must never turn "starting" into "failed".
#[cfg(any(target_os = "macos", test))]
fn serving_poll(status: &LaunchdJobStatus, socket_present: bool) -> ServingPoll {
    if status.is_running() && socket_present {
        return ServingPoll::Serving;
    }
    if status.state.is_none() || status.has_exit_evidence() {
        return ServingPoll::Failed;
    }
    ServingPoll::StillStarting
}

/// Read `launchctl print` output. Pure, so the states that matter are tested off a Mac.
///
/// `key = value` lines only, FIRST reading of each key wins: the top-level fields come first, and
/// nested blocks (`environment = { KEY => value }`) use `=>`, so neither can shadow the answer.
#[cfg(any(target_os = "macos", test))]
fn parse_launchd_print(text: &str) -> LaunchdJobStatus {
    let mut status = LaunchdJobStatus::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if value.is_empty() || value.starts_with('{') || value.starts_with('>') {
            continue;
        }
        match key {
            "state" if status.state.is_none() => status.state = Some(value.to_string()),
            "last exit code" if status.last_exit_code.is_none() => {
                status.last_exit_code = Some(value.to_string());
            }
            _ => {}
        }
    }
    status
}

/// The refusal a non-serving daemon earns: every fact that says WHICH failure this is.
///
/// The fork that matters is the log file. ABSENT means the launchd child died before exec — it
/// never wrote a word, so there is nothing to tail and the log path itself is the suspect
/// PRESENT means the daemon ran and refused on its own terms, and the reason is in it.
#[cfg(any(target_os = "macos", test))]
fn serving_failure_report(
    status: &LaunchdJobStatus,
    log_present: bool,
    socket_present: bool,
) -> String {
    let state = status
        .state
        .as_deref()
        .unwrap_or("(no job loaded — launchctl print found nothing)");
    let exit = status
        .last_exit_code
        .as_deref()
        .unwrap_or("(none reported)");
    let log_line = if log_present {
        format!(
            "{DAEMON_LOG_FILE}: present — the daemon execed and then refused, so its reason is \
             the last lines of that file:\n\
             [cermet-setup]        sudo tail -50 {DAEMON_LOG_FILE}"
        )
    } else {
        format!(
            "{DAEMON_LOG_FILE}: ABSENT — the launchd child died BEFORE exec and never wrote a \
             word. launchd opens the plist's stdio paths as {SERVICE_USER}; a log path \
             {SERVICE_USER} cannot create fails the spawn with exit 78. Re-run `sudo cermet \
             setup`: it converges that file to {SERVICE_USER}:{SERVICE_GROUP} 0640."
        )
    };
    format!(
        "cermetd failed while starting — the install is NOT usable\n\
         [cermet-setup]      launchctl state: {state}\n\
         [cermet-setup]      last exit code: {exit}\n\
         [cermet-setup]      {log_line}\n\
         [cermet-setup]      ctl socket {}: {}\n\
         [cermet-setup]      full report: sudo launchctl print {}",
        crate::endpoint::DEFAULT_CTL_SOCK,
        if socket_present { "present" } else { "absent" },
        launchd_service_target(),
    )
}

/// The cap-out on a boot that has produced NO failure evidence: the daemon is alive and has never
/// exited, this box is just slower than the wait. Nothing is refused — the report says what is
/// still true, what to watch, and that a re-run is safe. Deliberately free of the failure report's
/// "NOT usable" verdict, which would be false here.
#[cfg(any(target_os = "macos", test))]
fn still_starting_report(status: &LaunchdJobStatus, socket_present: bool) -> String {
    let state = status.state.as_deref().unwrap_or("(unknown)");
    format!(
        "cermetd is still starting after {SERVING_TIMEOUT_SECS}s — slow, but nothing has \
         failed (state: {state}, never exited, ctl socket {})\n\
         [cermet-setup]      watch it finish:  sudo launchctl print {}\n\
         [cermet-setup]      then confirm:     cermet check\n\
         [cermet-setup]      re-running `sudo cermet setup` is safe — it converges and re-checks",
        if socket_present { "present" } else { "absent" },
        launchd_service_target(),
    )
}

/// `launchctl print`'s stdout, or empty when the job is not loaded (it exits non-zero and writes
/// "Could not find service ..." to stderr). Empty parses to "no state", which is not serving.
#[cfg(target_os = "macos")]
fn launchd_print_text() -> String {
    Command::new("launchctl")
        .args(["print", &launchd_service_target()])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default()
}

/// Is the ctl socket actually bound? The daemon binds it once it is ready to answer, so its
/// presence is the half of "serving" that `state = running` alone does not prove.
#[cfg(target_os = "macos")]
fn ctl_socket_present() -> bool {
    use std::os::unix::fs::FileTypeExt;
    fs::symlink_metadata(crate::endpoint::DEFAULT_CTL_SOCK)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
}

/// Poll, bounded, until the daemon is SERVING; on timeout hand back the discriminating refusal.
#[cfg(target_os = "macos")]
fn wait_until_serving() -> Result<(), String> {
    let started = std::time::Instant::now();
    let mut said_still_starting = false;
    loop {
        let status = parse_launchd_print(&launchd_print_text());
        let socket = ctl_socket_present();
        match serving_poll(&status, socket) {
            ServingPoll::Serving => return Ok(()),
            // Evidence refuses NOW — a crash-loop never deserves the full wait.
            ServingPoll::Failed => {
                return Err(serving_failure_report(
                    &status,
                    Path::new(DAEMON_LOG_FILE).exists(),
                    socket,
                ));
            }
            ServingPoll::StillStarting => {}
        }
        let waited = started.elapsed();
        if waited >= std::time::Duration::from_secs(SERVING_TIMEOUT_SECS) {
            return Err(still_starting_report(&status, socket));
        }
        if !said_still_starting && waited >= std::time::Duration::from_secs(SERVING_PROGRESS_SECS) {
            println!(
                "[cermet-setup]       cermetd is still starting ({SERVING_PROGRESS_SECS}s) — a \
                 first boot mints the vault and seeds the catalog; waiting up to \
                 {SERVING_TIMEOUT_SECS}s"
            );
            said_still_starting = true;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

/// True while launchd holds the job. `launchctl print` exits non-zero once nothing is loaded.
#[cfg(target_os = "macos")]
fn launchd_job_is_loaded() -> bool {
    Command::new("launchctl")
        .args(["print", &launchd_service_target()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Boot out a LaunchDaemon this build no longer ships, before its plist is unlinked.
///
/// BEST EFFORT, deliberately: a non-zero `launchctl bootout` is read as "not loaded" and
/// the install continues. There is no re-check, so a job launchd is still tearing down (bootout is
/// asynchronous and can report `EINPROGRESS`) can outlive the unlink of its plist. That is
/// acceptable and self-healing rather than ignored: the plist is gone, so the job cannot come back
/// at the next boot, and the only thing it provisioned — the old `/var/run` socket dir — is not a
/// path anything in this build reads. Contrast `stop_and_prove_daemon_stopped`, which DOES re-check,
/// because there a survivor would have the vault open while the reset deletes it.
#[cfg(target_os = "macos")]
fn bootout_retired_daemon(label: &str) -> Result<(), String> {
    let target = format!("system/{label}");
    let mut bootout = Command::new("launchctl");
    bootout
        .args(["bootout", &target])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(status) = bootout.status() else {
        return Ok(());
    };
    if !status.success() {
        return Ok(()); // not loaded
    }
    fixed(
        "cleanup",
        &format!("booted out retired LaunchDaemon {label}"),
    );
    Ok(())
}

fn force_clean_reset() -> Result<(), String> {
    let state = Path::new(STATE_DIR);
    if fs::symlink_metadata(state)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(format!("refusing force-clean: {STATE_DIR} is a symlink"));
    }

    println!(
        "[cermet-setup] WARNING: --force-clean-bootstrap is a TRUE VENDOR RESET; old vault access \
         will be lost"
    );
    stop_and_prove_daemon_stopped(StopReason::ForceClean)?;

    let mut candidates = Vec::new();
    if state.exists() {
        for entry in
            fs::read_dir(state).map_err(|error| format!("cannot inspect {STATE_DIR}: {error}"))?
        {
            let entry = entry.map_err(|error| format!("cannot inspect state entry: {error}"))?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(kind) = force_clean_kind(&name) {
                candidates.push((entry.path(), kind));
            }
        }
    }
    if path_exists_no_follow(Path::new(RULES_FILE)) {
        candidates.push((PathBuf::from(RULES_FILE), ForceCleanKind::File));
    }
    // The sealed blob lives in systemd's credential store, outside the state dir the sweep walks —
    // named here for the same reason the rules file is. A reset that left it behind would make the
    // next install refuse to mint over a key nothing can open.
    #[cfg(target_os = "linux")]
    if path_exists_no_follow(Path::new(SEALED_KEY)) {
        candidates.push((PathBuf::from(SEALED_KEY), ForceCleanKind::File));
    }
    for (path, kind) in &candidates {
        if *kind == ForceCleanKind::File {
            let metadata = fs::symlink_metadata(path).map_err(|error| {
                format!("cannot inspect reset path {}: {error}", path.display())
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!(
                    "REFUSED: force-clean expected a regular file at {}, found {}; no reset \
                     files were removed",
                    path.display(),
                    if metadata.file_type().is_symlink() {
                        "a symlink"
                    } else if metadata.is_dir() {
                        "a directory"
                    } else {
                        "a non-regular file"
                    }
                ));
            }
        }
    }
    for (path, kind) in candidates {
        match kind {
            ForceCleanKind::File => fs::remove_file(&path)
                .map_err(|error| format!("cannot remove reset file {}: {error}", path.display()))?,
            ForceCleanKind::Tree => remove_no_follow(&path)?,
        }
        fixed(
            "vendor reset",
            &format!("DELETED {} (unrecoverable)", path.display()),
        );
    }
    ok("vendor reset", "exact reset inventory cleared");
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForceCleanKind {
    File,
    Tree,
}

fn force_clean_kind(name: &str) -> Option<ForceCleanKind> {
    if FORCE_CLEAN_FILES.contains(&name)
        || ["vault.db", "state.db", "audit.db"]
            .iter()
            .any(|db| name == format!("{db}-wal") || name == format!("{db}-shm"))
        || (name.starts_with(".mcp-repoint.barrier.") && name.ends_with(".tmp"))
        || name.starts_with(".lockdown.record.")
        || (name.starts_with(".sentence.record.") && name.ends_with(".tmp"))
        || (name.starts_with(".sentence.pin.") && name.ends_with(".tmp"))
        || (!name.starts_with('.') && name.ends_with(".yaml.bak"))
    {
        Some(ForceCleanKind::File)
    } else if FORCE_CLEAN_TREES.contains(&name) {
        Some(ForceCleanKind::Tree)
    } else {
        None
    }
}

/// A fresh key must never appear over surviving state: it would silently orphan the vault the old
/// key opened. The only way past this is the explicit vendor reset.
fn refuse_fresh_key_over_state(force_clean: bool) -> Result<(), String> {
    let entries: Vec<_> = fs::read_dir(STATE_DIR)
        .map_err(|error| format!("cannot inspect {STATE_DIR}: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect {STATE_DIR}: {error}"))?;
    if entries.is_empty() {
        return Ok(());
    }
    let names = entries
        .iter()
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let direction = if force_clean {
        "the vendor reset left unexpected state"
    } else {
        "restore the original key or use --force-clean-bootstrap"
    };
    Err(format!(
        "refusing to mint a fresh key over nonempty state ({names}); {direction}"
    ))
}

/// 32 random bytes as the 64 lowercase hex chars every key reader expects. The caller zeroizes the
/// buffer once it is written.
fn mint_key_hex() -> [u8; 64] {
    let mut random = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let mut key_hex = [0_u8; 64];
    for (index, byte) in random.iter().copied().enumerate() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        key_hex[index * 2] = HEX[(byte >> 4) as usize];
        key_hex[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    random.fill(0);
    key_hex
}

/// Provision the `file-protected` rung: a plain service-account-owned `0600` key file under
/// `CERMET_HOME`, which is what `cermet-daemon`'s reader opens (`O_NOFOLLOW`, owner == its euid, no
/// group/world read). Mode `0600` rather than `0400` because the daemon's own startup hardening
/// normalizes these inodes to `0600` — installing `0400` would make every re-run see a mode it did
/// not write.
///
/// This is macOS's only rung (no systemd-creds analog, no login session for a Keychain item) AND
/// the bottom rung on Linux. ONE provisioner, exactly as there is one reader: other local uids are
/// defeated by owner + mode on both, and the rung says out loud what it does not defend.
fn write_master_key(force_clean: bool) -> Result<CustodyProfile, String> {
    let key = Path::new(MASTER_KEY_FILE);
    let service_uid = uid_for(SERVICE_USER)?;
    if path_exists_no_follow(key) {
        let metadata = fs::symlink_metadata(key)
            .map_err(|error| format!("cannot stat {MASTER_KEY_FILE}: {error}"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != service_uid
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(format!(
                "partial provisioning: {MASTER_KEY_FILE} must be a regular file owned by \
                 {SERVICE_USER} with mode 0600"
            ));
        }
        ok("master key", "key file exists; left byte-for-byte intact");
        return Ok(CustodyProfile::FileProtected);
    }

    refuse_fresh_key_over_state(force_clean)?;
    let mut key_hex = mint_key_hex();
    let result = exclusive_write(key, &key_hex, SERVICE_USER, SERVICE_GROUP, 0o600);
    key_hex.fill(0);
    result?;
    fixed(
        "master key",
        &format!("minted 32 bytes into a {SERVICE_USER}-owned 0600 key file"),
    );
    Ok(CustodyProfile::FileProtected)
}

/// CUSTODY-LADDER: walk the SEALED rungs strongest-first and return the one that actually sealed.
///
/// The attempt IS the detection. `systemd-creds`'s own `auto` policy would pick TPM2-plus-host on a
/// TPM box and host-only everywhere else — silently, with no way for us to report which happened —
/// so setup never uses `auto`. It ASKS for `host+tpm2`; if this box cannot do that, it asks for
/// `host`. Whatever answered is what gets recorded and printed, so the product's custody claim and
/// the blob on disk can never disagree.
///
/// `seal` is the provisioning attempt for one `--with-key` value, injected so the ladder's ORDER
/// and its descent are testable without a TPM (and without a systemd at all). An exhausted ladder
/// returns every reason: that string is what the automatic descent to `file-protected` reports.
#[cfg_attr(target_os = "macos", allow(dead_code))] // Linux ladder; macOS has one rung (file-protected)
fn select_sealed_profile(
    mut seal: impl FnMut(&str) -> Result<(), String>,
) -> Result<CustodyProfile, String> {
    let mut refusals = Vec::new();
    for (with_key, profile) in [
        ("host+tpm2", CustodyProfile::SystemdTpm2Host),
        ("host", CustodyProfile::SystemdHost),
    ] {
        match seal(with_key) {
            Ok(()) => return Ok(profile),
            Err(reason) => refusals.push(format!("--with-key={with_key}: {reason}")),
        }
    }
    Err(refusals.join("; "))
}

/// CUSTODY-LADDER: the ladder decision, with both probes injected so the ORDER and the descent are
/// testable without a systemd, a TPM, or a container.
///
/// `delivery` answers "can this box actually be HANDED a systemd credential" — a different question
/// from "can this box encrypt one". When it says no, the sealed rungs are not attempted at all: a
/// blob the service manager could never deliver is worse than no blob, because the key would be
/// unrecoverable rather than merely weakly held.
///
/// `Err` is not a failure — it is the REASON to descend, and the caller prints it.
#[cfg_attr(target_os = "macos", allow(dead_code))] // Linux ladder; macOS has one rung
fn choose_custody_rung(
    delivery: Result<(), String>,
    seal: impl FnMut(&str) -> Result<(), String>,
) -> Result<CustodyProfile, String> {
    delivery?;
    select_sealed_profile(seal)
}

/// The descent, said out loud: automatic, but never silent.
///
/// Three things an operator must be able to read off the install: why the stronger rungs were not
/// taken, which rung was taken instead, and what that rung does not protect. Returned as lines
/// rather than printed so the wording is pinned by a test — this is the product's custody claim.
#[cfg_attr(target_os = "macos", allow(dead_code))] // Linux ladder; macOS has one rung
fn descent_lines(reason: &str) -> Vec<String> {
    let profile = CustodyProfile::FileProtected;
    vec![
        format!(
            "NOTE custody: no systemd-credential custody rung is available on this box ({reason})"
        ),
        format!(
            "     taking the strongest rung that works here: {} — {}",
            profile.as_str(),
            profile.limitation()
        ),
    ]
}

/// Can this box actually be handed a systemd credential? Answered by RUNNING the shipped preflight
/// (`cermet-credential-env`), which is the one implementation of that check — the same executable
/// `cermet-credential-env.service` runs before `cermetd` at every boot. Setup does not re-derive it
/// here: one validator, and if it converges `/run` now it will converge it at boot too.
///
/// `systemd-creds` is checked first because its absence means no rung can be sealed at all; it is no
/// longer an install prerequisite, just the top two rungs' prerequisite.
#[cfg(target_os = "linux")]
fn sealed_delivery_workable() -> Result<String, String> {
    if !command_exists("systemd-creds") {
        return Err("systemd-creds is not available on this box".to_string());
    }
    let output = Command::new(CREDENTIAL_ENV_DEST)
        .output()
        .map_err(|error| format!("cannot run the credential-transport preflight: {error}"))?;
    if output.status.success() {
        // The preflight may have CHANGED this box (converging /run's propagation), so its own words
        // are reported rather than swallowed: an install that alters a mount says that it did.
        return Ok(last_line(
            &output.stdout,
            "credential transport prerequisite satisfied",
        ));
    }
    // The preflight's own stderr already explains the environment in full; quote its last line so
    // the descent names a cause rather than an exit code.
    Err(last_line(
        &output.stderr,
        "the credential-transport preflight refused",
    ))
}

/// The last non-empty line of a child's output, or `fallback` when it said nothing.
#[cfg(target_os = "linux")]
fn last_line(bytes: &[u8], fallback: &str) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .unwrap_or(fallback)
        .trim()
        .to_string()
}

/// Provision this box's vault key on the strongest rung it can carry, and return that rung.
///
/// Idempotent by inspection: an already-provisioned box keeps its key byte-for-byte and reports the
/// rung it is already on, so a re-run never re-decides custody for a vault that already exists.
#[cfg(target_os = "linux")]
fn provision_master_key(force_clean: bool) -> Result<CustodyProfile, String> {
    if let Some(existing) = existing_rung()? {
        return Ok(existing);
    }

    refuse_fresh_key_over_state(force_clean)?;

    let mut key_hex = mint_key_hex();
    // ONE key, offered to each rung in turn: the ladder descends over the SEALING MECHANISM, never
    // over the key material, so a descent cannot orphan a vault.
    let delivery = match sealed_delivery_workable() {
        Ok(said) => {
            ok("credential transport", &said);
            Ok(())
        }
        Err(reason) => Err(reason),
    };
    let sealed = choose_custody_rung(delivery, |with_key| seal_blob_with_key(&key_hex, with_key));
    match sealed {
        Ok(profile) => {
            key_hex.fill(0);
            fixed(
                "master key",
                &format!(
                    "minted 32 bytes and piped directly into systemd-creds --with-key; sealed \
                     root:root 0600 at {SEALED_KEY} (custody: {})",
                    profile.as_str()
                ),
            );
            Ok(profile)
        }
        Err(reason) => {
            for line in descent_lines(&reason) {
                println!("[cermet-setup] {line}");
            }
            let result = exclusive_write(
                Path::new(MASTER_KEY_FILE),
                &key_hex,
                SERVICE_USER,
                SERVICE_GROUP,
                0o600,
            );
            key_hex.fill(0);
            result?;
            fixed(
                "master key",
                &format!("minted 32 bytes into a {SERVICE_USER}-owned 0600 key file"),
            );
            Ok(CustodyProfile::FileProtected)
        }
    }
}

/// The rung this box is ALREADY on, by inspecting which key artifact exists, or `None` on a box
/// with no vault key yet.
#[cfg(target_os = "linux")]
fn existing_rung() -> Result<Option<CustodyProfile>, String> {
    let sealed = Path::new(SEALED_KEY);
    if path_exists_no_follow(sealed) {
        let metadata = fs::symlink_metadata(sealed)
            .map_err(|error| format!("cannot stat {SEALED_KEY}: {error}"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(format!(
                "partial provisioning: {SEALED_KEY} must be a root:root regular file mode 0600"
            ));
        }
        // A blob that is already here stays byte-for-byte: it can only be opened by the systemd
        // installation that sealed it, so there is nothing to re-derive and nothing to upgrade in
        // place. Which rung it is on is what the config declares — and a blob whose rung nothing
        // declares is a half-provisioned box, not a rung to guess at. Fail closed: a custody claim
        // is never inferred.
        // A refusal owes the operator the way out. This state is reachable only from a first
        // setup that was interrupted between sealing the key and recording the rung, so no vault
        // exists yet and re-minting cannot orphan one — which is what makes the reset SAFE to name
        // here rather than merely available.
        let declared = declared_custody_profile()?.ok_or_else(|| {
            format!(
                "partial provisioning: a sealed blob exists at {SEALED_KEY} but {CONFIG_DEST} \
                 declares no custody_profile, so this install cannot say what holds the vault key. \
                 Only an interrupted first setup leaves this, and no vault exists yet — re-run: \
                 sudo cermet setup --force-clean-bootstrap"
            )
        })?;
        ok(
            "master key",
            &format!(
                "sealed blob exists; left byte-for-byte intact (custody: {})",
                declared.as_str()
            ),
        );
        return Ok(Some(declared));
    }
    if path_exists_no_follow(Path::new(MASTER_KEY_FILE)) {
        // Delegated to the shared file-rung provisioner, which owns the owner/mode validation.
        // `force_clean` is irrelevant on this branch: the key exists, so nothing is minted.
        return write_master_key(false).map(Some);
    }
    Ok(None)
}

/// Seal `key_hex` into [`SEALED_KEY`] with ONE explicit `--with-key` value, or report why not.
///
/// The plaintext is piped on stdin and never written anywhere but into `systemd-creds`; the
/// ciphertext lands on a unique temp IN THE DESTINATION'S OWN DIRECTORY that is hard-linked into
/// place, so a concurrent installer cannot be raced into overwriting a live blob. On any failure
/// the temp is removed and NOTHING is published, which is what lets the caller simply try the next
/// rung.
///
/// The stage's directory is not a free choice: `link(2)` is `EXDEV` across filesystems, so staging
/// in the state dir made every box with a separate `/var` fail to seal and descend a rung for a
/// reason that was ours, not the machine's.
#[cfg(target_os = "linux")]
fn seal_blob_with_key(key_hex: &[u8], with_key: &str) -> Result<(), String> {
    // BESIDE the destination, never in the state dir — the publish below is a hard link.
    let temp = publish_stage_path(Path::new(SEALED_KEY), ".cermet.key.cred")?;
    let result = (|| {
        let mut child = Command::new("systemd-creds")
            .arg("encrypt")
            .arg(format!("--name={CRED_NAME}"))
            .arg(format!("--with-key={with_key}"))
            .arg("-")
            .arg(&temp)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            // systemd-creds narrates on stderr even when it succeeds ("credential secret file is
            // not located on encrypted media, using anyway"). A rung we are only TRYING must not
            // print that at the operator; the failing rung's reason is reported by the caller.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("cannot start systemd-creds encrypt: {error}"))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "systemd-creds stdin was not piped".to_string())?;
        stdin
            .write_all(key_hex)
            .map_err(|error| format!("cannot pipe master key to systemd-creds: {error}"))?;
        drop(stdin);
        let status = child
            .wait()
            .map_err(|error| format!("cannot wait for systemd-creds: {error}"))?;
        if !status.success() {
            return Err(format!(
                "systemd-creds encrypt exited {status}; no plaintext was written"
            ));
        }
        chown(&temp, "root", "root")?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot chmod sealed key temp: {error}"))?;
        fs::hard_link(&temp, Path::new(SEALED_KEY)).map_err(|error| {
            format!(
                "{SEALED_KEY} appeared during sealing or could not be published exclusively: {error}"
            )
        })
    })();
    let _ = fs::remove_file(&temp);
    result
}

/// The custody rung the installed config DECLARES, if any. `Ok(None)` covers both "no config yet"
/// and "config predates the ladder"; an unrecognized spelling is an error, never a silent None —
/// the declared rung is authoritative for the daemon's key source, so a value we cannot read is a
/// state we must not overwrite by guessing.
#[cfg_attr(target_os = "macos", allow(dead_code))] // read by the Linux ladder's already-sealed branch
fn declared_custody_profile() -> Result<Option<CustodyProfile>, String> {
    let text = match fs::read_to_string(CONFIG_DEST) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot read {CONFIG_DEST}: {error}")),
    };
    let Some(value) = active_string_value(&text, "custody_profile")? else {
        return Ok(None);
    };
    CustodyProfile::parse(&value).map(Some).ok_or(format!(
        "{CONFIG_DEST} declares custody_profile {value:?}, which this build does not implement"
    ))
}

/// The string a config assigns `key`, through the real TOML parser ([`toml_document`]).
/// `Ok(None)` when the key is absent; a file that does not parse, or a non-string value, is an
/// error — never a silent absence.
pub(crate) fn active_string_value(config: &str, key: &str) -> Result<Option<String>, String> {
    match toml_document(config)?.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_string()))
            .ok_or_else(|| format!("{key} must be a string")),
    }
}

/// Write the selected rung into the config the daemon reads. This is the moment the ladder stops
/// being a decision and becomes a DECLARED setting (undeclared behavior paths do not exist): from
/// here the daemon's key source follows the file, not the installer's memory.
fn record_custody_profile(profile: CustodyProfile) -> Result<(), String> {
    let config = fs::read_to_string(CONFIG_DEST)
        .map_err(|error| format!("cannot read {CONFIG_DEST}: {error}"))?;
    let updated = set_string_key(&config, "custody_profile", profile.as_str());
    if updated != config {
        atomic_write(
            Path::new(CONFIG_DEST),
            updated.as_bytes(),
            "root",
            ROOT_GROUP,
            0o644,
        )?;
        fixed(
            "custody",
            &format!("declared custody_profile = {:?}", profile.as_str()),
        );
    } else {
        ok(
            "custody",
            &format!("custody_profile = {:?}", profile.as_str()),
        );
    }
    println!("[cermet-setup]       {}", profile.limitation());
    Ok(())
}

fn initialize_lockdown_record() -> Result<(), String> {
    let destination = Path::new(STATE_DIR).join("lockdown.record");
    if path_exists_no_follow(&destination) {
        let metadata = fs::symlink_metadata(&destination)
            .map_err(|error| format!("cannot stat {}: {error}", destination.display()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "{} exists but is not a regular file",
                destination.display()
            ));
        }
        ok("lockdown", "owner lockdown record preserved");
        return Ok(());
    }
    let bytes = br#"{"version":1,"engaged":false,"occurrence_id":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
    exclusive_write(&destination, bytes, SERVICE_USER, SERVICE_GROUP, 0o600)?;
    fixed("lockdown", "initialized explicit clear generation");
    Ok(())
}

#[derive(Debug)]
struct CatalogSeedEntry {
    source_dir: PathBuf,
    destination_dir: PathBuf,
    files: Vec<PathBuf>,
    replace_whole_directory: bool,
}

fn catalog_seed_plan(source: &Path, state: &Path) -> Result<Vec<CatalogSeedEntry>, String> {
    let mut plan = Vec::new();
    for subdir in ["actions.d", "providers.d"] {
        let source_dir = source.join(subdir);
        if !source_dir.is_dir() {
            return Err(format!(
                "vendored catalog subdir {} is missing",
                source_dir.display()
            ));
        }
        let mut files = fs::read_dir(&source_dir)
            .map_err(|error| format!("cannot read {}: {error}", source_dir.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension() == Some(OsStr::new("yaml")))
            .collect::<Vec<_>>();
        files.sort();
        if files.is_empty() {
            return Err(format!(
                "vendored catalog subdir {} contains no .yaml descriptors",
                source_dir.display()
            ));
        }
        for file in &files {
            require_regular_source(file, false)?;
            let text = fs::read_to_string(file)
                .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
            let _: serde_yaml::Value = serde_yaml::from_str(&text)
                .map_err(|error| format!("invalid YAML {}: {error}", file.display()))?;
        }
        plan.push(CatalogSeedEntry {
            source_dir,
            destination_dir: state.join(subdir),
            files,
            replace_whole_directory: true,
        });
    }
    Ok(plan)
}

fn seed_catalog(source: &Path) -> Result<(), String> {
    let plan = catalog_seed_plan(source, Path::new(STATE_DIR))?;
    for entry in plan {
        debug_assert!(entry.replace_whole_directory);
        if path_exists_no_follow(&entry.destination_dir) {
            remove_no_follow(&entry.destination_dir)?;
        }
        install_dir(&entry.destination_dir, SERVICE_USER, SERVICE_GROUP, 0o755)?;
        for source_file in &entry.files {
            let destination = entry
                .destination_dir
                .join(source_file.file_name().unwrap_or_default());
            atomic_install_file(
                source_file,
                &destination,
                SERVICE_USER,
                SERVICE_GROUP,
                0o644,
            )?;
        }
        fixed(
            "catalog",
            &format!(
                "wholesale reseeded {} from {} ({} descriptors)",
                entry.destination_dir.display(),
                entry.source_dir.display(),
                entry.files.len()
            ),
        );
    }
    Ok(())
}

fn install_dir(path: &Path, owner: &str, group: &str, mode: u32) -> Result<(), String> {
    let mut command = Command::new("install");
    command
        .args(["-d", "-o", owner, "-g", group, "-m", &format!("{mode:04o}")])
        .arg(path);
    checked(command, &format!("install directory {}", path.display()))
}

fn atomic_install_file(
    source: &Path,
    destination: &Path,
    owner: &str,
    group: &str,
    mode: u32,
) -> Result<(), String> {
    let bytes = fs::read(source)
        .map_err(|error| format!("cannot read source {}: {error}", source.display()))?;
    atomic_write(destination, &bytes, owner, group, mode)
}

fn atomic_write(
    destination: &Path,
    bytes: &[u8],
    owner: &str,
    group: &str,
    mode: u32,
) -> Result<(), String> {
    atomic_write_validated(destination, bytes, owner, group, mode, |_| Ok(()))
}

fn atomic_write_validated(
    destination: &Path,
    bytes: &[u8],
    owner: &str,
    group: &str,
    mode: u32,
    validate: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("{} has no parent", destination.display()))?;
    let stage = unique_path(
        parent,
        &format!(
            ".{}",
            destination
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ),
    )?;
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options
            .open(&stage)
            .map_err(|error| format!("cannot create {}: {error}", stage.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("cannot write {}: {error}", stage.display()))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync {}: {error}", stage.display()))?;
        fs::set_permissions(&stage, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot chmod {}: {error}", stage.display()))?;
        chown(&stage, owner, group)?;
        validate(&stage)?;
        fs::rename(&stage, destination).map_err(|error| {
            format!(
                "cannot atomically publish {}: {error}",
                destination.display()
            )
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&stage);
    }
    result
}

fn exclusive_write(
    destination: &Path,
    bytes: &[u8],
    owner: &str,
    group: &str,
    mode: u32,
) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("{} has no parent", destination.display()))?;
    let stage = unique_path(parent, ".cermet-exclusive")?;
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options
            .open(&stage)
            .map_err(|error| format!("cannot create {}: {error}", stage.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("cannot write {}: {error}", stage.display()))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync {}: {error}", stage.display()))?;
        fs::set_permissions(&stage, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot chmod {}: {error}", stage.display()))?;
        chown(&stage, owner, group)?;
        fs::hard_link(&stage, destination).map_err(|error| {
            format!(
                "{} appeared during setup or could not be published exclusively: {error}",
                destination.display()
            )
        })
    })();
    let _ = fs::remove_file(stage);
    result
}

fn chown(path: &Path, owner: &str, group: &str) -> Result<(), String> {
    let mut command = Command::new("chown");
    command.arg(format!("{owner}:{group}")).arg(path);
    checked(command, &format!("chown {}", path.display()))
}

fn unique_path(parent: &Path, stem: &str) -> Result<PathBuf, String> {
    for counter in 0..1000 {
        let path = parent.join(format!("{stem}.{}.{}", std::process::id(), counter));
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(path),
            Ok(_) => continue,
            Err(error) => {
                return Err(format!(
                    "cannot inspect temp path {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Err(format!(
        "cannot allocate a temporary path under {}",
        parent.display()
    ))
}

/// The staging path for a file that will be PUBLISHED into `destination` — always inside
/// `destination`'s own directory.
///
/// Publication here is `link(2)` or `rename(2)`, and both return `EXDEV` across a filesystem
/// boundary unconditionally. Deriving the stage from the destination makes "same filesystem"
/// structural rather than a fact about this box's partitioning: it cannot be true on the developer's
/// laptop and false on a server with a separate `/var`. `atomic_write_validated` and
/// `exclusive_write` already stage this way; this is that rule, named, for the one publisher whose
/// bytes are written by a CHILD PROCESS rather than by us.
fn publish_stage_path(destination: &Path, stem: &str) -> Result<PathBuf, String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", destination.display()))?;
    unique_path(parent, stem)
}

fn path_exists_no_follow(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn remove_no_follow(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    let result = if metadata.file_type().is_symlink() || !metadata.is_dir() {
        fs::remove_file(path)
    } else {
        fs::remove_dir_all(path)
    };
    result.map_err(|error| format!("cannot remove {}: {error}", path.display()))
}

fn checked(mut command: Command, description: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("{description}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{description} failed with {status}"))
    }
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let Output {
        status,
        stdout,
        stderr,
    } = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if !status.success() {
        return Err(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    String::from_utf8(stdout).map_err(|_| format!("{program} returned non-UTF-8"))
}

// ---- the operator's own settings file ------------------------------------------------------------

/// Record the operator's settings defaults in the APPROVER's own file, and hand the file to them.
///
/// Setup runs as root and the settings are the human's, not the machine's, so the file is created
/// under their home directory and chowned to them. A home directory that does not resolve means
/// there is nowhere to record them, so the defaults still stand — an absent file reads as the
/// defaults — and nothing is written.
///
/// It PRINTS nothing on its own: the one setting it records has its own line, printed by
/// [`announce_update_check`] right after. A warning is the exception, because a settings file the
/// operator has to fix by hand is a thing they need told.
fn record_operator_settings(approver: &str) {
    let Some(home) = user_home(approver) else {
        return;
    };
    let path = crate::settings::config_path_in(Some(home.clone()));
    match crate::settings::record_default(&path) {
        Ok(false) => return,
        Ok(true) => {}
        Err(error) => {
            println!(
                "[cermet-setup] WARN settings: cannot record {}: {error}",
                path.display()
            );
            return;
        }
    }
    // The file is the operator's, so it is theirs to own and to edit. Every directory the write had
    // to CREATE is handed over too: `record_default` runs `create_dir_all`, so on a fresh account it
    // may have created `~/.config` itself, and a root-owned `~/.config` would break far more than
    // this setting.
    match primary_gid(approver) {
        Some(group) => {
            for directory in created_ancestors(&home, &path) {
                if let Err(error) = chown(&directory, approver, &group) {
                    println!("[cermet-setup] WARN settings: {error}");
                }
            }
            if let Err(error) = chown(&path, approver, &group) {
                println!("[cermet-setup] WARN settings: {error}");
            }
        }
        None => println!(
            "[cermet-setup] WARN settings: no primary group resolves for {approver}; {} stays \
             root-owned",
            path.display()
        ),
    }
}

// ---- the daily update check's scheduler ------------------------------------------------------------

/// Render a shipped asset with the approver's account name substituted for [`APPROVER_TOKEN`].
///
/// The approver is discovered from the installed config, so it cannot be baked into a file that
/// ships; substitution is the whole of the templating, and a shipped asset that lost its token would
/// silently install a scheduler running as nobody in particular — so an absent token is an error.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn render_for_approver(source: &Path, approver: &str) -> Result<Vec<u8>, String> {
    let text = fs::read_to_string(source)
        .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
    if !text.contains(APPROVER_TOKEN) {
        return Err(format!(
            "{} carries no {APPROVER_TOKEN} placeholder; it cannot be pointed at the operator",
            source.display()
        ));
    }
    Ok(text.replace(APPROVER_TOKEN, approver).into_bytes())
}

/// The ONE line setup prints about the daily update check.
///
/// Four facts, because default-on earns them: what is contacted, how often, that NOTHING installs
/// itself, and the command that stops it. One line is enough for all four: nothing leaves this
/// machine but a parameterless GET, and nothing arrives but a version string.
pub(crate) fn update_check_report(enabled: bool) -> String {
    if enabled {
        "update checks: daily against https://github.com/suarezc/cermet/releases, run as you and \
         never by the daemon. \
         The notice is LOCAL and nothing installs itself; applying an update stays \
         `sudo cermet update`. Off: cermet update --daily off"
            .to_string()
    } else {
        "update checks: off — nothing is contacted on a schedule (cermet update --daily on)"
            .to_string()
    }
}

/// Report the daily update check's state from the APPROVER's own settings file. An unreadable or
/// absent file reads as the default (on), which is what the check itself does.
fn announce_update_check(approver: &str) {
    let enabled = user_home(approver)
        .map(|home| crate::settings::config_path_in(Some(home)))
        .map(|path| crate::settings::read_update_check(&path).unwrap_or(true))
        .unwrap_or(true);
    println!("[cermet-setup] {}", update_check_report(enabled));
}

/// Install the daily update check's scheduler.
///
/// Same shape, same platform-native mechanism, same uid: a systemd timer on Linux, a LaunchDaemon on
/// macOS, both running `cermet update --daily-check` as the HUMAN approver. It is not the daemon and
/// holds no key — and, because it runs unprivileged, it could not install anything even if it tried.
/// The operator's own `update_check` setting is the single control: nothing here turns the check on,
/// and `cermet update --daily off` stops it whatever the scheduler does.
#[cfg(target_os = "linux")]
fn install_update_check_scheduler(sources: &SourceLayout, approver: &str) -> Result<(), String> {
    let unit = render_for_approver(&sources.update_check_unit, approver)?;
    atomic_write_validated(
        Path::new(UPDATE_CHECK_UNIT_DEST),
        &unit,
        "root",
        ROOT_GROUP,
        0o644,
        |_| Ok(()),
    )?;
    atomic_install_file(
        &sources.update_check_timer,
        Path::new(UPDATE_CHECK_TIMER_DEST),
        "root",
        ROOT_GROUP,
        0o644,
    )?;
    fixed(
        "update check",
        &format!("daily check timer installed for {approver} (notice only; never installs)"),
    );
    Ok(())
}

/// The macOS half. `launchctl bootstrap` is deferred to [`enable_update_check_scheduler`], which
/// runs after the plist is on disk, exactly as the daemon's own bootstrap does.
#[cfg(target_os = "macos")]
fn install_update_check_scheduler(sources: &SourceLayout, approver: &str) -> Result<(), String> {
    let plist = render_for_approver(&sources.update_check_plist, approver)?;
    atomic_write_validated(
        Path::new(UPDATE_CHECK_PLIST_DEST),
        &plist,
        "root",
        ROOT_GROUP,
        0o644,
        |_| Ok(()),
    )?;
    fixed(
        "update check",
        &format!("daily check plist installed for {approver} (notice only; never installs)"),
    );
    Ok(())
}

/// Turn the check's scheduler on, idempotently. A failure is a WARN with the remedy, never an abort:
/// the install is complete and correct without it, and a box with no scheduler simply learns about
/// releases when someone types `cermet update --check`.
#[cfg(target_os = "linux")]
fn enable_update_check_scheduler() {
    let mut enable = Command::new("systemctl");
    enable.args(["enable", "--now", "cermet-update-check.timer"]);
    match checked(enable, "enable the daily update check") {
        Ok(_) => ok("update check", "daily check timer enabled"),
        Err(error) => println!("[cermet-setup] WARN update check: {error}"),
    }
}

#[cfg(target_os = "macos")]
fn enable_update_check_scheduler() {
    let mut boot = Command::new("launchctl");
    boot.args(["bootstrap", "system", UPDATE_CHECK_PLIST_DEST]);
    // Already bootstrapped is success: `bootstrap` on a loaded label errors, and re-running setup
    // must converge rather than fail.
    if checked(boot, "load the daily update check").is_err() {
        let mut kickstart = Command::new("launchctl");
        kickstart.args(["enable", &format!("system/{UPDATE_CHECK_PLIST_LABEL}")]);
        let _ = checked(kickstart, "enable the daily update check");
    }
    ok("update check", "daily check scheduled");
}

/// Every directory between `home` (exclusive) and `path`'s parent (inclusive) — the ones
/// `create_dir_all` may have had to make on the way to the settings file, outermost first.
fn created_ancestors(home: &Path, path: &Path) -> Vec<PathBuf> {
    let mut directories = Vec::new();
    let mut current = path.parent();
    while let Some(directory) = current {
        if directory == home || directory.parent().is_none() {
            break;
        }
        directories.push(directory.to_path_buf());
        current = directory.parent();
    }
    directories.reverse();
    directories
}

/// The home directory of `user`, asked of the platform's own password database.
fn user_home(user: &str) -> Option<PathBuf> {
    nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .map(|user| user.dir)
        .filter(|dir| dir.is_dir())
}

/// The primary group of `user` as a numeric gid, from the same password database. Numeric because
/// a group NAMED after the user exists on Linux (useradd's private group) but not on macOS, where
/// `chown user:user` fails outright.
fn primary_gid(user: &str) -> Option<String> {
    nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .map(|user| user.gid.to_string())
}

fn ok(step: &str, detail: &str) {
    println!("[cermet-setup] ok    {step}: {detail}");
}

fn fixed(step: &str, detail: &str) {
    println!("[cermet-setup] fixed {step}: {detail}");
}

#[cfg(test)]
mod tests {
    // ---- CUSTODY-LADDER M1: the declared rung -------------------------------------------------

    /// The ladder is walked STRONGEST FIRST and the first rung that actually provisions is the one
    /// recorded — the provisioning attempt IS the detection. Nothing here re-derives systemd's
    /// `auto` policy or parses a `.cred` header: both can disagree with what the blob really got,
    /// and a custody claim that can be wrong is worse than no claim.
    #[test]
    fn the_sealed_ladder_takes_the_strongest_rung_that_actually_seals() {
        // A box with a usable TPM2 gets the hardware-bound rung, and `host` is never attempted.
        let mut tried = Vec::new();
        let profile = select_sealed_profile(|with_key| {
            tried.push(with_key.to_string());
            Ok(())
        })
        .expect("a box that can seal gets a rung");
        assert_eq!(profile, CustodyProfile::SystemdTpm2Host);
        assert_eq!(tried, ["host+tpm2"], "the stronger rung is tried first");

        // A box with no usable TPM2 descends exactly one rung.
        let mut tried = Vec::new();
        let profile = select_sealed_profile(|with_key| {
            tried.push(with_key.to_string());
            if with_key == "host+tpm2" {
                Err("TPM device not usable".to_string())
            } else {
                Ok(())
            }
        })
        .expect("a TPM-less box still seals against the host key");
        assert_eq!(profile, CustodyProfile::SystemdHost);
        assert_eq!(tried, ["host+tpm2", "host"]);

        // A box that can seal NOTHING yields no sealed rung, and the error carries every reason —
        // this is the input the automatic descent to file-protected reads.
        let error = select_sealed_profile(|with_key| Err(format!("{with_key} unavailable")))
            .expect_err("no rung sealed");
        assert!(error.contains("host+tpm2 unavailable"), "{error}");
        assert!(error.contains("host unavailable"), "{error}");
    }

    /// Publication of the sealed blob is a HARD LINK, and `link(2)` returns `EXDEV` across a
    /// filesystem boundary unconditionally. The blob is published into `/etc/credstore.encrypted`
    /// while the daemon's state dir is `/var/lib/cermetd`, and a separate `/var` is a mainstream
    /// server layout — so staging in the state dir made a sealable box report `file-protected` for
    /// a reason that has nothing to do with what the machine can carry, and made an upgrade abort
    /// half-migrated.
    ///
    /// Two halves, because the defect had two: the RULE (a stage lives beside the file it will be
    /// published as) and its USE at the one call site that writes its bytes through a child
    /// process. The second is a source assertion for the same reason the other cross-file install
    /// contracts here are: the call cannot be exercised without root and a systemd, and the
    /// coupling it removes is one a later edit could silently reintroduce.
    #[test]
    fn a_published_file_is_always_staged_beside_its_destination() {
        let one = tempfile::tempdir().unwrap();
        let two = tempfile::tempdir().unwrap();
        // Two directories standing in for the two filesystems: the stage follows the DESTINATION,
        // never a fixed directory of its own.
        for dir in [one.path(), two.path()] {
            let stage = publish_stage_path(&dir.join("cermet.key"), ".cermet.key.cred").unwrap();
            assert_eq!(
                stage.parent(),
                Some(dir),
                "the stage must sit beside the file it will be linked to: {stage:?}"
            );
        }
        assert!(
            publish_stage_path(Path::new("/"), ".x").is_err(),
            "a destination with no parent directory has nowhere to stage"
        );
    }

    #[test]
    fn the_sealed_blob_is_staged_in_the_credstore_not_the_state_dir() {
        let setup_source = include_str!("setup.rs");
        let seal = setup_source
            .split("fn seal_blob_with_key")
            .nth(1)
            .expect("the sealing publisher is still here")
            .split("\nfn ")
            .next()
            .expect("its body ends at the next item");
        assert!(
            seal.contains("publish_stage_path(Path::new(SEALED_KEY)"),
            "the seal temp must be derived from the destination, not named independently"
        );
        assert!(
            !seal.contains("unique_path(Path::new(STATE_DIR)"),
            "staging in the state dir is the EXDEV coupling this removed"
        );
        // …and the two really are candidates for different filesystems, which is what makes the
        // assertion above load-bearing rather than cosmetic.
        assert_ne!(Path::new(SEALED_KEY).parent(), Some(Path::new(STATE_DIR)));
    }

    /// The whole ladder, in one decision. Sealed delivery is tried FIRST and only descends for a
    /// stated reason; a box that cannot carry systemd credential delivery is never asked to seal
    /// (that would leave a blob nothing can ever open), and a box where sealing fails outright
    /// descends with every refusal quoted.
    #[test]
    fn the_ladder_prefers_sealed_and_descends_only_for_a_stated_reason() {
        // Workable delivery + a usable TPM2: the top rung, no descent.
        assert_eq!(
            choose_custody_rung(Ok(()), |_| Ok(())).unwrap(),
            CustodyProfile::SystemdTpm2Host
        );
        // Workable delivery, no TPM2: one rung down, still sealed.
        assert_eq!(
            choose_custody_rung(Ok(()), |with_key| if with_key == "host" {
                Ok(())
            } else {
                Err("no TPM".to_string())
            })
            .unwrap(),
            CustodyProfile::SystemdHost
        );

        // Delivery that cannot work here: the descent reason is the delivery's own, and NOTHING is
        // sealed — a blob this box could never be handed is worse than no blob.
        let mut attempts = 0;
        let reason = choose_custody_rung(Err("/run cannot be made shared".to_string()), |_| {
            attempts += 1;
            Ok(())
        })
        .expect_err("undeliverable credentials must descend");
        assert!(reason.contains("/run cannot be made shared"), "{reason}");
        assert_eq!(
            attempts, 0,
            "a rung that cannot be delivered is never sealed"
        );

        // Delivery works but no rung will seal: descend, quoting every refusal.
        let reason = choose_custody_rung(Ok(()), |with_key| Err(format!("{with_key} refused")))
            .expect_err("an exhausted ladder descends");
        assert!(
            reason.contains("host+tpm2 refused") && reason.contains("host refused"),
            "{reason}"
        );
    }

    /// The descent is LOUD: it names why the stronger rungs were not taken, which rung was, and
    /// what that rung does not protect. A quiet descent would be the product claiming custody it
    /// does not have.
    #[test]
    fn the_descent_states_the_reason_the_rung_and_the_limitation() {
        let lines = descent_lines("--with-key=host+tpm2: no TPM").join("\n");
        assert!(lines.contains("file-protected"), "{lines}");
        assert!(lines.contains("--with-key=host+tpm2: no TPM"), "{lines}");
        assert!(
            lines.contains(CustodyProfile::FileProtected.limitation()),
            "{lines}"
        );
    }

    /// The rung is a DECLARED setting, so it is written into the config the daemon reads —
    /// appended on a first install (the templates only MENTION the key in comments, which are
    /// never touched), and rewritten in place on a re-run.
    #[test]
    fn the_declared_rung_is_appended_once_and_rewritten_in_place() {
        let template =
            "approver_uid = 1000\n# custody_profile = \"file-protected\"   # placeholder\n";
        let written = set_string_key(template, "custody_profile", "systemd-host");
        assert!(
            written.contains("\ncustody_profile = \"systemd-host\""),
            "{written}"
        );
        assert!(
            written.contains("# custody_profile = \"file-protected\""),
            "comments are documentation, never a write target: {written}"
        );
        let rewritten = set_string_key(&written, "custody_profile", "file-protected");
        assert!(
            rewritten.contains("\ncustody_profile = \"file-protected\""),
            "{rewritten}"
        );
        assert_eq!(
            rewritten.matches("\ncustody_profile = ").count(),
            1,
            "a re-run rewrites the one active line rather than appending a second: {rewritten}"
        );
    }

    /// One grammar for one file: the config readers go through the same
    /// `toml` crate the daemon uses, so every spelling TOML admits — single quotes included —
    /// means the same thing to setup as it does to the daemon. The hand parser this replaced
    /// read `custody_profile = 'x'` as ABSENT.
    #[test]
    fn config_reads_speak_full_toml_not_a_hand_rolled_subset() {
        assert_eq!(
            active_string_value("custody_profile = 'file-protected'\n", "custody_profile"),
            Ok(Some("file-protected".to_string())),
        );
        assert_eq!(
            active_string_value(
                "runtime_dir = \"/var/cermetd\"          # inline comment.\n",
                "runtime_dir"
            ),
            Ok(Some("/var/cermetd".to_string())),
        );
        // Malformed TOML is an error, never a silent absence …
        assert!(active_string_value("custody_profile = unquoted\n", "custody_profile").is_err());
        // … and TOML itself refuses a duplicated key, which is what `active_uid`'s old
        // "exactly one" loop was hand-enforcing.
        assert!(active_uid("agent_uid = 1\nagent_uid = 2\n", "agent_uid").is_err());
    }

    /// Both shipped config templates must parse under that one grammar, or setup could not read
    /// back what it installs.
    #[test]
    fn the_shipped_config_templates_are_valid_toml() {
        toml_document(include_str!("../../../dist/linux/config.toml")).expect("linux template");
        toml_document(include_str!("../../../dist/macos/config.toml")).expect("macos template");
    }

    /// The ✓-summary names the rung this box landed on AND what that rung does not protect. The
    /// ladder descends automatically, so the summary is where an operator learns it descended —
    /// "never silent" is a property of this line.
    #[test]
    fn the_vault_summary_names_the_rung_and_its_limitation() {
        for profile in CustodyProfile::LADDER {
            let lines = vault_ready_lines(profile);
            assert!(
                lines[0].contains("credential vault ready")
                    && lines[0].contains(&format!("custody: {}", profile.as_str())),
                "{lines:?}"
            );
            assert!(
                lines[1].contains(profile.limitation()),
                "the limitation is stated verbatim, never paraphrased: {lines:?}"
            );
        }
    }

    /// The shipped template documents the key, so an operator reading `/etc/cermetd/config.toml`
    /// finds out what custody their box is on and what that rung does not protect (undeclared
    /// behavior paths do not exist).
    #[test]
    fn the_config_template_documents_the_custody_profile_key() {
        let template = include_str!("../../../dist/linux/config.toml");
        assert!(
            template.contains("custody_profile"),
            "the template must document the declared custody rung"
        );
        for profile in CustodyProfile::LADDER {
            assert!(
                template.contains(profile.as_str()),
                "the template must name the {} rung",
                profile.as_str()
            );
        }
    }

    use super::*;

    /// Every non-installable build marker is refused BY NAME, and an ordinary binary passes.
    ///
    /// T2 (accident): a developer or an agent builds the harness binary — `--features
    /// test-presence` bypasses the human-presence ceremony, `--features test-egress` reopens
    /// `CERMET_*_BASE_URL` so a stray env var can redirect provider traffic carrying the real
    /// credential — and then installs it. The scan is what makes that a refusal instead of a box.
    #[test]
    fn setup_refuses_every_non_installable_build_marker() {
        let dir = tempfile::tempdir().unwrap();
        let clean = dir.path().join("clean");
        fs::write(&clean, b"an ordinary binary carries none of these").unwrap();
        assert!(reject_non_installable_binary(&clean).is_ok());

        for (feature, reversed) in NON_INSTALLABLE_MARKERS_REVERSED {
            let forward = reversed.iter().rev().copied().collect::<Vec<u8>>();
            let path = dir.path().join(format!("contaminated-{feature}"));
            let mut bytes = b"\x7fELF padding".to_vec();
            bytes.extend_from_slice(&forward);
            bytes.extend_from_slice(b"more padding");
            fs::write(&path, &bytes).unwrap();
            let refusal = reject_non_installable_binary(&path)
                .expect_err("a contaminated binary must be refused");
            assert!(
                refusal.contains(feature),
                "the refusal must name the feature that contaminated it: {refusal}"
            );
        }
    }

    #[test]
    fn setup_parser_accepts_tree_and_force_forms() {
        assert_eq!(
            parse_setup(&["--from-tree".into(), "/repo".into()]).unwrap(),
            SetupArgs {
                from_tree: Some(PathBuf::from("/repo")),
                force_clean_bootstrap: false,
                // Never set by the parser: the only setter is `converge_with_binary`.
                binary_source: None,
            }
        );
        assert_eq!(
            parse_setup(&["--from-tree".into(), "--force-clean-bootstrap".into()]).unwrap(),
            SetupArgs {
                from_tree: Some(PathBuf::from(".")),
                force_clean_bootstrap: true,
                binary_source: None,
            }
        );
        assert!(parse_setup(&["--unknown".into()]).is_err());
    }

    /// The credential-transport preflight ships, is wired to cermetd, and the two files
    /// agree with each other and with the path setup publishes the script to. This is a cross-file
    /// contract — a unit that Requires= a name nothing installs, or an ExecStart pointing where
    /// nothing is written, is a box that never starts and says nothing useful about why.
    #[test]
    fn the_credential_preflight_ships_and_is_wired_to_the_daemon() {
        let daemon_unit = include_str!("../../../dist/linux/cermetd.service");
        let preflight_unit = include_str!("../../../dist/linux/cermet-credential-env.service");
        let preflight_script = include_str!("../../../dist/linux/cermet-credential-env.sh");

        for asset in [
            "linux/cermet-credential-env.service",
            "linux/cermet-credential-env.sh",
        ] {
            assert!(
                EMBEDDED_PAYLOAD.iter().any(|carried| carried.path == asset),
                "{asset} must ride the embedded payload, or the tarball / cargo-install path \
                 installs a daemon whose Requires= names a unit that is not there"
            );
        }

        assert!(
            daemon_unit.contains("Requires=cermet-credential-env.service"),
            "cermetd must REQUIRE the preflight: a refused preflight has to keep the daemon down, \
             not merely warn"
        );
        assert!(
            daemon_unit.contains("After=cermet-credential-env.service"),
            "ordering, or the daemon can win the race and crash-loop anyway"
        );
        assert!(
            preflight_unit.contains(&format!("ExecStart={CREDENTIAL_ENV_DEST}")),
            "the unit must exec the script at the path setup publishes it to ({CREDENTIAL_ENV_DEST})"
        );
        assert!(
            preflight_unit.contains("ConditionVirtualization=container"),
            "a real host has nothing to converge; the unit must skip itself there"
        );
        assert!(
            !preflight_unit
                .lines()
                .any(|line| line.trim_start().starts_with("Restart=")),
            "a refusal is a verdict about the environment, not a transient fault — no restart loop"
        );
        // The narrowness IS the ruling: /run only, never a recursive re-share of /.
        assert!(
            !preflight_script.contains("--make-rshared"),
            "the preflight converges /run alone; rsharing / would change the propagation of every \
             nested mount in the container"
        );
        assert!(
            preflight_script.contains("mount --make-shared \"$TARGET\"")
                && preflight_script.contains("TARGET=/run"),
            "the preflight must converge /run itself"
        );
    }

    /// STRIP: the units earlier installs provisioned for the retired upload program are
    /// REMOVED by convergence, not merely stopped being installed. Every box that ran a build
    /// before the strip carries them: an upgrade that left them behind would leave a daily job
    /// scheduled to run a subcommand this binary no longer has.
    #[test]
    fn the_retired_upload_scheduler_is_swept_on_both_platforms() {
        // The whole set, per platform: unit, timer, and the enable symlink on Linux; the
        // LaunchDaemon plist on macOS. Asked of the sweep's OWN list, which is the same list the
        // cutover probe reads — one inventory, so the two can never disagree about what is retired.
        let swept = retired_artifacts();
        #[cfg(not(target_os = "macos"))]
        for path in [
            "/etc/systemd/system/cermet-research.service",
            "/etc/systemd/system/cermet-research.timer",
            "/etc/systemd/system/timers.target.wants/cermet-research.timer",
        ] {
            assert!(swept.contains(&path), "the sweep must remove {path}");
        }
        #[cfg(target_os = "macos")]
        assert!(swept.contains(&"/Library/LaunchDaemons/dev.cermet.research.plist"));

        // …and nothing of it is INSTALLED any more: neither the payload the binary carries nor the
        // per-platform asset list names it.
        for asset in EMBEDDED_PAYLOAD {
            assert!(
                !asset.path.contains("cermet-research")
                    && !asset.path.contains("dev.cermet.research"),
                "the payload still carries {}",
                asset.path
            );
        }
    }

    #[test]
    fn embedded_payload_is_complete_and_byte_matches_the_dist_sources() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let expected = [
            "linux/cermetd.service",
            "linux/cermetd.tmpfiles",
            "linux/cermet-credential-env.service",
            "linux/cermet-credential-env.sh",
            "linux/cermet-update-check.service",
            "linux/cermet-update-check.timer",
            "linux/config.toml",
            "linux/pam.cermet",
            "macos/dev.cermet.cermetd.plist",
            "macos/dev.cermet.update-check.plist",
            "macos/config.toml",
        ]
        .into_iter()
        .map(str::to_string)
        .chain(["actions.d", "providers.d"].into_iter().flat_map(|subdir| {
            let mut names = fs::read_dir(repo.join("dist/catalog").join(subdir))
                .unwrap()
                .map(|entry| {
                    format!(
                        "catalog/{subdir}/{}",
                        entry.unwrap().file_name().to_string_lossy()
                    )
                })
                .collect::<Vec<_>>();
            names.sort();
            names
        }))
        .collect::<BTreeSet<_>>();
        let embedded = EMBEDDED_PAYLOAD
            .iter()
            .map(|asset| {
                assert_eq!(
                    asset.bytes,
                    fs::read(repo.join("dist").join(asset.path)).unwrap(),
                    "{} differs from its embedded bytes",
                    asset.path
                );
                asset.path.to_string()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(embedded, expected);
    }

    fn write_binary(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn the_cargo_install_layout_publishes_the_running_executable_itself() {
        // ONE-BINARY: there is no sibling to keep coherent — the running executable IS the payload.
        let temp = tempfile::tempdir().unwrap();
        let absent_package_dir = temp.path().join("no-package-here");
        let cli = temp.path().join("cermet");
        write_binary(&cli, b"cli");

        assert_eq!(
            resolve_binary_source(&absent_package_dir, &cli).unwrap(),
            cli
        );

        // A source that is not a regular executable file is not publishable. In particular an
        // ALIAS is not: resolving one as a source would republish a symlink onto its own target.
        let alias = temp.path().join("cermetd");
        std::os::unix::fs::symlink("cermet", &alias).unwrap();
        assert!(resolve_binary_source(&absent_package_dir, &alias).is_err());

        fs::remove_file(&cli).unwrap();
        assert!(resolve_binary_source(&absent_package_dir, &cli).is_err());
    }

    #[test]
    fn the_packaged_binary_outranks_the_stale_published_one_the_running_cermet_sits_in() {
        // `dpkg -i` of a newer package replaces /usr/bin; the operator then types
        // `sudo cermet setup`, which secure_path resolves to the older copy already published in
        // /usr/local/bin. The source must be the package's binary, never the running one.
        let temp = tempfile::tempdir().unwrap();
        let packaged = temp.path().join("usr/bin");
        let published = temp.path().join("usr/local/bin");
        write_binary(&packaged.join("cermet"), b"cermet rc.2");
        write_binary(&published.join("cermet"), b"cermet rc.1");
        let running = published.join("cermet");

        assert_eq!(
            resolve_binary_source(&packaged, &running).unwrap(),
            packaged.join("cermet")
        );

        // No package copy: fall back to the running executable.
        fs::remove_file(packaged.join("cermet")).unwrap();
        assert_eq!(
            resolve_binary_source(&packaged, &running).unwrap(),
            published.join("cermet")
        );

        // Neither candidate exists: fail closed, naming both.
        fs::remove_file(published.join("cermet")).unwrap();
        let error = resolve_binary_source(&packaged, &running).unwrap_err();
        assert!(
            error.contains(&packaged.join("cermet").display().to_string())
                && error.contains(&published.join("cermet").display().to_string()),
            "{error}"
        );
    }

    /// A refusal names the operation the OPERATOR ran, not the one the shared helper was first
    /// written for. An ordinary `sudo cermet setup` that cannot stop the daemon used to abort
    /// talking about a `--force-clean-bootstrap` the operator never invoked, and about state that
    /// was never going to be removed — while saying nothing about what actually happened.
    #[test]
    fn a_failed_stop_names_the_operation_the_operator_actually_ran() {
        let publication = StopReason::Publication.refusal("cermetd.service reported \"active\"");
        assert!(
            !publication.contains("force-clean") && !publication.contains("no state removed"),
            "an ordinary upgrade must not mention a vendor reset: {publication}"
        );
        assert!(
            publication.contains("nothing was published"),
            "it says what actually happened — publication was refused: {publication}"
        );
        assert!(
            publication.contains("re-run setup"),
            "and how to finish: {publication}"
        );

        // The force-clean path keeps its own stakes, which are different and worse.
        let force_clean = StopReason::ForceClean.refusal("cermetd.service reported \"active\"");
        assert!(
            force_clean.contains("force-clean") && force_clean.contains("no state removed"),
            "{force_clean}"
        );

        // Both carry the observed detail, so the operator sees WHY the proof failed.
        for refusal in [&publication, &force_clean] {
            assert!(refusal.contains("reported"), "{refusal}");
        }
    }

    /// The ONE-BINARY publication layout, driven through the real `publish_multicall_into` over an
    /// unprivileged temp prefix: one regular target, two EXACT relative symlinks to it.
    #[test]
    fn publication_lays_down_one_regular_target_and_two_relative_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let source = temp.path().join("build/cermet");
        write_binary(&source, b"the one binary");

        assert!(
            !multicall_layout_is_current(&bin, &source).unwrap(),
            "an empty prefix is not converged"
        );
        publish_multicall_into(&bin, &source, false).unwrap();

        let target = bin.join("cermet");
        let metadata = fs::symlink_metadata(&target).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
        assert_eq!(fs::read(&target).unwrap(), b"the one binary");
        for alias in MULTICALL_ALIASES {
            let path = bin.join(alias);
            assert!(
                fs::symlink_metadata(&path)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "{alias} must be a symlink, not a byte copy"
            );
            assert_eq!(
                fs::read_link(&path).unwrap(),
                Path::new("cermet"),
                "{alias} must be a RELATIVE link to the target, so a relocated prefix still works"
            );
        }
        assert!(multicall_layout_is_current(&bin, &source).unwrap());

        // Idempotent: a second publication changes nothing and still converges.
        publish_multicall_into(&bin, &source, false).unwrap();
        assert!(multicall_layout_is_current(&bin, &source).unwrap());
        // And no staging litter survives either run.
        let leftovers = fs::read_dir(&bin)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
            .count();
        assert_eq!(leftovers, 0, "staged names must not survive a commit");
    }

    /// Convergence is decided WITHOUT following an unexpected link. An alias pointing anywhere but
    /// the exact relative `cermet` reads as not-current and is replaced — never accepted because it
    /// happens to resolve to some cermet.
    #[test]
    fn an_alias_pointing_elsewhere_is_never_followed_while_deciding_convergence() {
        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let source = temp.path().join("build/cermet");
        write_binary(&source, b"the one binary");
        publish_multicall_into(&bin, &source, false).unwrap();

        // An absolute link to the very same file is STILL not the published shape.
        fs::remove_file(bin.join("cermetd")).unwrap();
        std::os::unix::fs::symlink(bin.join("cermet"), bin.join("cermetd")).unwrap();
        assert!(!alias_is_current(&bin, "cermetd").unwrap());
        assert!(!multicall_layout_is_current(&bin, &source).unwrap());

        // A link out of the prefix entirely: also not current, and publication replaces it.
        fs::remove_file(bin.join("cermetd")).unwrap();
        std::os::unix::fs::symlink("../elsewhere/cermet", bin.join("cermetd")).unwrap();
        assert!(!alias_is_current(&bin, "cermetd").unwrap());
        publish_multicall_into(&bin, &source, false).unwrap();
        assert_eq!(
            fs::read_link(bin.join("cermetd")).unwrap(),
            Path::new("cermet")
        );
    }

    /// Failure injection: a run that published the target but died before the aliases converges on
    /// the next run, and leaves no dangling alias behind at any point.
    #[test]
    fn a_half_finished_publication_converges_on_the_next_run_with_no_dangling_alias() {
        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let source = temp.path().join("build/cermet");
        write_binary(&source, b"the one binary");

        // Simulate the crash point the design names: target published, aliases not yet.
        let mut staged = StagedFiles::default();
        staged
            .stage(&source, &bin.join("cermet"), 0o755, false)
            .unwrap();
        staged.commit().unwrap();
        assert!(!multicall_layout_is_current(&bin, &source).unwrap());
        // The target exists, so no alias can ever point at a missing file.
        assert!(bin.join("cermet").is_file());

        publish_multicall_into(&bin, &source, false).unwrap();
        assert!(multicall_layout_is_current(&bin, &source).unwrap());
        for alias in MULTICALL_ALIASES {
            assert!(
                fs::metadata(bin.join(alias)).is_ok(),
                "{alias} resolves — no dangling alias"
            );
        }
    }

    #[test]
    fn republication_is_reported_as_a_change_only_when_the_published_bytes_or_mode_differ() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source-cermet");
        let destination = temp.path().join("published-cermet");
        write_binary(&source, b"cli rc.2");

        assert!(!published_binary_is_current(&source, &destination).unwrap());
        write_binary(&destination, b"cli rc.1");
        assert!(!published_binary_is_current(&source, &destination).unwrap());
        write_binary(&destination, b"cli rc.2");
        assert!(published_binary_is_current(&source, &destination).unwrap());
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!published_binary_is_current(&source, &destination).unwrap());
    }

    #[test]
    fn config_service_uid_resolution_touches_active_lines_only() {
        let template = "# service_uid = 0\napprover_uid = 0\nagent_uid = 0\n";
        assert_eq!(
            prepare_new_config(template, 981, Some(1000), 982).unwrap(),
            "# service_uid = 0\napprover_uid = 1000\nagent_uid = 982\nservice_uid = 981\n",
            "active lines rewrite in place; the commented example stays; an absent key appends"
        );
        assert!(prepare_new_config(template, 0, Some(1000), 982).is_err());
        assert!(prepare_new_config(template, 981, Some(981), 982).is_err());
    }

    #[test]
    fn active_uid_parser_refuses_malformed_duplicate_and_zero() {
        assert_eq!(
            active_uid("approver_uid = 1000\n", "approver_uid").unwrap(),
            1000
        );
        assert!(active_uid("approver_uid = nope\n", "approver_uid").is_err());
        assert!(active_uid("approver_uid = 1\napprover_uid = 2\n", "approver_uid").is_err());
        assert!(active_uid("approver_uid = 0\n", "approver_uid").is_err());
    }

    #[test]
    fn sudoers_validation_receives_the_exact_newline_terminated_write_buffer() {
        let validated = std::cell::RefCell::new(None);
        let written =
            validated_sudoers_document(&["operator ALL=(root) true".to_string()], |bytes| {
                assert!(bytes.ends_with(b"\n"));
                validated.replace(Some(bytes.to_vec()));
                Ok(())
            })
            .unwrap();

        assert_eq!(validated.into_inner().unwrap(), written);
    }

    #[test]
    fn cleanup_lists_cover_retired_binary_and_vendor_reset_state() {
        assert!(RETIRED_BINARIES.contains(&"/usr/local/bin/cermet-agent"));
        // The systemd CIDR firewall is dead. A prior install's generated allow-list
        // outlives the deny-all it modified, so setup declares its removal like any other retired
        // artifact — an orphaned allowlist with no deny floor is config litter, not policy.
        #[cfg(target_os = "linux")]
        assert!(RETIRED_PLATFORM_ARTIFACTS
            .contains(&"/etc/systemd/system/cermetd.service.d/10-egress-allow.conf"));
        for expected in [
            "vault.db",
            "state.db",
            "audit.db",
            "host.lock",
            "host.json",
            "mcp-repoint.barrier",
            "lockdown.record",
            "sentence.record",
            "sentence.pin",
            "policy.yaml",
            "actions.d",
            "providers.d",
            "profiles.d",
        ] {
            assert_eq!(
                force_clean_kind(expected),
                Some(
                    if matches!(expected, "actions.d" | "providers.d" | "profiles.d") {
                        ForceCleanKind::Tree
                    } else {
                        ForceCleanKind::File
                    }
                ),
                "missing {expected}"
            );
        }
        for remnant in [
            "vault.db-wal",
            "audit.db-shm",
            ".sentence.pin.1.tmp",
            "policy.yaml.bak",
        ] {
            assert_eq!(
                force_clean_kind(remnant),
                Some(ForceCleanKind::File),
                "missing remnant {remnant}"
            );
        }
        assert_eq!(force_clean_kind(".hidden.yaml.bak"), None);
    }

    #[test]
    fn catalog_plan_is_wholesale_and_rejects_empty_subdirs() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("catalog");
        let state = temp.path().join("state");
        fs::create_dir_all(source.join("actions.d")).unwrap();
        fs::create_dir_all(source.join("providers.d")).unwrap();
        fs::write(source.join("actions.d/a.yaml"), "provider: p\n").unwrap();
        fs::write(source.join("providers.d/p.yaml"), "name: p\n").unwrap();
        let plan = catalog_seed_plan(&source, &state).unwrap();
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|entry| entry.replace_whole_directory));
        fs::remove_file(source.join("providers.d/p.yaml")).unwrap();
        assert!(catalog_seed_plan(&source, &state).is_err());
    }

    #[test]
    fn the_installed_names_are_one_target_and_two_relative_aliases_beside_it() {
        // The pre-merge layout published a THIRD regular file; ONE-BINARY replaces the copies with links. Git
        // resolves a remote helper by NAME on PATH, so `git-remote-cermet` still has to sit beside
        // `cermet` (the directory an installed box puts on the PATH) — as a link now, not a copy.
        assert_eq!(
            MULTICALL_TARGET, "cermet",
            "the one regular target's name is the CLI's, which is what sudoers and MCP pin"
        );
        assert_eq!(
            MULTICALL_ALIASES,
            ["cermetd", "git-remote-cermet"],
            "cermetd is the service manager's ExecStart name; git-remote-cermet is git's lookup key"
        );
        assert_eq!(
            Path::new(CLI_DEST).file_name().unwrap().to_string_lossy(),
            MULTICALL_TARGET,
            "the sudoers/MCP-pinned path IS the one regular target"
        );
        assert_eq!(
            Path::new(CLI_DEST).parent(),
            Some(Path::new(INSTALL_BIN_DIR)),
            "aliases are created in the target's own directory, which is what makes them relative"
        );
    }

    #[test]
    fn remaining_cross_file_install_contracts_are_structurally_aligned() {
        let setup_source = include_str!("setup.rs");
        let unit = include_str!("../../../dist/linux/cermetd.service");
        let tmpfiles = include_str!("../../../dist/linux/cermetd.tmpfiles");
        let config = include_str!("../../../dist/linux/config.toml");
        let build = include_str!("../../../scripts/build-release.sh");
        // The LINUX unit's path, spelled out: the install prefix is per-platform (the macOS
        // one lives at /opt/cermet/bin), and this assertion is about the shipped systemd
        // unit. `cermetd` there is the role ALIAS (a relative symlink to `cermet`), not a second
        // binary — the path is unchanged and stays what systemd, `systemctl status`, and the
        // journal name.
        assert!(unit.contains("ExecStart=/usr/local/bin/cermetd"));
        // CUSTODY-LADDER: the credential is named WITHOUT a path, so systemd looks it up in its own
        // credential store — which is what makes one unit serve every rung. With a path, an absent
        // blob fails the unit `243/CREDENTIALS`, and a `file-protected` box could never start; named
        // this way, systemd documents an absent credential as non-fatal. The blob setup writes must
        // therefore land in the store, under exactly that name.
        assert!(
            unit.contains(&format!("\nLoadCredentialEncrypted={CRED_NAME}\n")),
            "the unit must name the credential without a path"
        );
        assert_eq!(SEALED_KEY, format!("{CREDSTORE_DIR}/{CRED_NAME}"));
        // …and the preflight only has a job when there IS a blob to deliver: on a `file-protected`
        // box it is condition-skipped, which satisfies cermetd's Requires= and lets it start.
        let preflight = include_str!("../../../dist/linux/cermet-credential-env.service");
        assert!(
            preflight.contains(&format!("ConditionPathExists={SEALED_KEY}")),
            "the preflight must be conditional on the sealed blob it exists to deliver"
        );
        // The release binary aborts on panic; the daemon's memory holds the opened master key and,
        // transiently, a decrypted credential. Neither service manager may ever write a core
        // (accidental disclosure via coredump sweep or bug-report attachment).
        assert!(unit.contains("LimitCORE=0"));
        let plist = include_str!("../../../dist/macos/dev.cermet.cermetd.plist");
        assert!(
            plist.contains("HardResourceLimits") && plist.contains("<key>Core</key>"),
            "the LaunchDaemon must carry the no-core hard limit"
        );
        assert!(tmpfiles.contains("/run/cermetd         2711 cermet cermet-approvers"));
        assert!(tmpfiles.contains("/run/cermetd-agents 2711 cermet cermet-agents"));
        // There is no content spool. The daemon provisions no world-writable drop
        // box, because nothing stages content through the broker any more — git carries its own.
        assert!(
            !tmpfiles.contains("/var/spool/cermet"),
            "the spool is deleted; tmpfiles must not provision one"
        );
        assert!(
            !config.contains("spool"),
            "the spool is deleted; no spool setting may survive in the shipped config"
        );
        // the git seam's five settings are DECLARED in the shipped config — behavior
        // that is not a setting does not exist. Mirrors live under the unit's
        // own 0700 StateDirectory, so they need no tmpfiles rule.
        assert!(config.contains(r#"# git_binary = "/usr/bin/git""#));
        assert!(config.contains(r#"# git_mirror_dir = "/var/lib/cermetd/mirrors""#));
        assert!(config.contains("# git_max_push_bytes = 536870912"));
        assert!(config.contains("# git_timeout_secs = 300"));
        assert!(config.contains("# git_mirror_retention_days = 90"));
        assert!(
            config.contains("There is NO registration step"),
            "the config states the defaulted-git posture the daemon actually implements"
        );
        // The aging note must not promise a re-seed that does not exist yet.
        assert!(
            !config.contains("never correctness"),
            "the mirror-aging comment may not claim correctness is unaffected while there is no              credentialed fetch refresh"
        );
        // The systemd CIDR egress firewall is deliberately absent, unit and generator alike. The
        // only attacker it would add coverage against is a subverted daemon process, which is out
        // of scope; it does not enforce in unprivileged LXC at all, and where it would enforce it
        // strangles the vercel relay, because Vercel publishes no range contract. The in-core
        // origin pin (`Egress::allows`) is the whole egress control.
        assert!(
            !unit.contains("IPAddress"),
            "the shipped unit must declare no CIDR egress firewall"
        );
        // Split so the assertion does not embed the directive it forbids (`setup_source` is this
        // file) — the same self-reference dodge the test-presence marker needs below.
        let forbidden_directive = ["IPAddress", "Allow="].concat();
        assert!(
            !setup_source.contains(&forbidden_directive),
            "setup must not render a provider CIDR drop-in"
        );
        // The template's declared origin list must name every live provider, or a fresh install
        // ships a list that disagrees with the catalog it was installed beside.
        assert!(
            !config.contains("host_allowlist"),
            "the dead host_allowlist key must not return to the template"
        );
        assert!(config.contains(r#"runtime_dir = "/run/cermetd""#));
        assert!(config.contains(r#"agent_runtime_dir = "/run/cermetd-agents""#));
        // ONE-BINARY: the release script builds the composition crate and asserts ONE artifact.
        assert!(build.contains("target/${PROFILE}/cermet"));
        assert!(build.contains("cargo build $RELEASE_FLAG -p cermet-bin"));
        assert!(
            !build.contains("target/${PROFILE}/cermetd")
                && !build.contains("target/${PROFILE}/cermet-agent"),
            "no second build artifact — cermetd is a published alias, not a build target"
        );
        assert!(!setup_source.contains("Path::new(\"/usr/share/cermet\")"));
        for half in [
            "CERMET_TEST_PRESENCE_",
            "CERMET_TEST_EGRESS_",
            "CERMET_TEST_DOUBLE_",
        ] {
            let forbidden_marker = [half, "COMPILED_IN_DO_NOT_INSTALL"].concat();
            assert!(
                !setup_source.contains(&forbidden_marker),
                "the production scanner must not embed and reject its own forbidden marker"
            );
        }
    }

    /// Every key a config template assigns, active or commented out. Order-free, so a template can
    /// reorganize its prose freely; only the SET of declared settings is pinned.
    fn declared_config_keys(template: &str) -> BTreeSet<String> {
        template
            .lines()
            .filter_map(|line| {
                let text = line.trim_start().trim_start_matches('#').trim_start();
                let (key, rest) = text.split_once('=')?;
                let key = key.trim();
                if key.is_empty()
                    || rest.is_empty()
                    || !key
                        .chars()
                        .all(|c| c == '_' || c.is_ascii_lowercase() || c.is_ascii_digit())
                {
                    return None;
                }
                Some(key.to_string())
            })
            .collect()
    }

    #[test]
    fn the_two_config_templates_declare_the_same_keys() {
        // The macOS template is a platform twin, not a fork: same daemon, same schema, only the
        // paths and the role-account name differ. Without this, a key added to one platform's
        // template silently ships undeclared on the other, and behavior that is built must be
        // reflected in the settings file.
        let linux = declared_config_keys(include_str!("../../../dist/linux/config.toml"));
        let macos = declared_config_keys(include_str!("../../../dist/macos/config.toml"));
        assert!(
            linux.contains("approver_uid") && linux.contains("relay_listen"),
            "the key scraper found nothing recognizable: {linux:?}"
        );
        assert_eq!(linux, macos, "the two config templates drifted apart");
    }

    #[test]
    fn the_sudoers_rule_admits_exactly_the_registered_bridge_invocation() {
        // The rule and the registration are one fact spelled in two files: sudo matches the command
        // BYTE FOR BYTE, so a drift between them does not weaken a boundary — it silently stops the
        // bridge from launching at all.
        assert_eq!(
            agent_bridge_command(),
            format!("{CLI_DEST} --socket {} mcp", crate::mcp::SYSTEM_AGENT_SOCK)
        );
    }

    #[test]
    fn retired_binaries_are_swept_on_every_platform() {
        for binary in [
            "/usr/local/bin/cermet-rs",
            "/usr/local/bin/cermet-app",
            "/usr/local/bin/cermet-agent",
        ] {
            assert!(RETIRED_BINARIES.contains(&binary), "missing {binary}");
        }
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use super::*;

        #[test]
        fn install_targets_are_the_platform_native_locations() {
            assert_eq!(
                SERVICE_USER, "_cermet",
                "macOS role accounts are underscored"
            );
            assert_eq!(SERVICE_GROUP, "_cermet");
            assert_eq!(ROOT_GROUP, "wheel", "macOS has no `root` group");
            assert_eq!(
                PLIST_DEST,
                "/Library/LaunchDaemons/dev.cermet.cermetd.plist"
            );
            assert_eq!(
                Path::new(PLIST_DEST).file_name().unwrap().to_string_lossy(),
                format!("{PLIST_LABEL}.plist"),
                "launchctl addresses the job by the plist's basename"
            );
            assert_eq!(MASTER_KEY_FILE, format!("{STATE_DIR}/master.key"));
            // /usr/local is Homebrew's, operator-writable, and off limits — setup must
            // neither seize it nor publish into it. The prefix setup creates is its own.
            assert_eq!(INSTALL_PREFIX, "/opt/cermet");
            assert_eq!(INSTALL_BIN_DIR, "/opt/cermet/bin");
            // ONE-BINARY: one regular target plus its two role aliases, all under the
            // root-owned prefix. Every published name is derived from the alias list, so a new
            // alias cannot appear without this assertion seeing it.
            let published: Vec<String> = std::iter::once(CLI_DEST.to_string())
                .chain(
                    MULTICALL_ALIASES
                        .iter()
                        .map(|alias| format!("{INSTALL_BIN_DIR}/{alias}")),
                )
                .collect();
            for dest in &published {
                assert!(
                    dest.starts_with(&format!("{INSTALL_BIN_DIR}/")),
                    "{dest} must be published under the root-owned prefix"
                );
            }
            for path in [INSTALL_PREFIX.to_string(), INSTALL_BIN_DIR.to_string()]
                .iter()
                .chain(published.iter())
            {
                assert!(
                    !path.starts_with("/usr/local"),
                    "{path} reaches into Homebrew's prefix"
                );
            }
            // PATH is published declaratively; /etc/paths.d entries are appended AFTER /etc/paths
            // (which starts with /usr/local/bin), so retiring the stale copies there is what makes
            // a bare `cermet` resolve to this install.
            assert_eq!(PATHS_D_DEST, "/etc/paths.d/cermet");
            assert_eq!(paths_d_document(), format!("{INSTALL_BIN_DIR}\n"));
            // The runtime dirs must survive a reboot: macOS wipes /var/run, and this platform ships
            // ONE plist precisely because nothing has to re-provision them at boot.
            for dir in [RUNTIME_DIR, AGENT_RUNTIME_DIR] {
                assert!(
                    !dir.starts_with("/var/run/") && !dir.starts_with("/run/"),
                    "{dir} would be wiped at boot with no helper left to recreate it"
                );
            }
            assert_ne!(RUNTIME_DIR, AGENT_RUNTIME_DIR);
            assert_eq!(
                crate::endpoint::DEFAULT_CTL_SOCK,
                format!("{RUNTIME_DIR}/ctl.sock")
            );
            assert_eq!(
                crate::owner::DEFAULT_OWNER_SOCK,
                format!("{RUNTIME_DIR}/owner.sock")
            );
            assert_eq!(
                crate::mcp::SYSTEM_AGENT_SOCK,
                format!("{AGENT_RUNTIME_DIR}/agent.sock")
            );
            assert_eq!(
                crate::git_remote::DEFAULT_GIT_SOCK,
                format!("{AGENT_RUNTIME_DIR}/git.sock")
            );
        }

        #[test]
        fn the_launch_daemon_plist_matches_the_installer_contract() {
            let plist = include_str!("../../../dist/macos/dev.cermet.cermetd.plist");
            for required in [
                &format!("<string>{PLIST_LABEL}</string>"),
                // launchd names the `cermetd` ALIAS; the binary behind it is the one regular target.
                &format!(
                    "<string>{INSTALL_BIN_DIR}/{}</string>",
                    MULTICALL_ALIASES[0]
                ),
                &format!("<string>{SERVICE_USER}</string>"),
                &format!("<string>{STATE_DIR}</string>"),
                &format!("<string>{CONFIG_DEST}</string>"),
                &"<key>CERMET_SERVICE_MODE</key>".to_string(),
                &"<key>RunAtLoad</key>".to_string(),
                &"<key>KeepAlive</key>".to_string(),
            ] {
                assert!(plist.contains(required.as_str()), "plist lacks {required}");
            }
            assert!(
                !plist.contains(RETIRED_RUNTIME_DIR_LABEL),
                "the boot-time socket-dir helper is retired; the plist must not revive it"
            );
            // A base-url override is an egress-redirect surface and is compiled out of the shipped
            // daemon — the launch context must not try to set one either.
            assert!(!plist.contains("<key>CERMET_GITHUB_BASE_URL</key>"));
        }

        #[test]
        fn the_config_template_names_the_dirs_setup_actually_converges() {
            let config = include_str!("../../../dist/macos/config.toml");
            for expected in [
                format!("service_user = \"{SERVICE_USER}\""),
                format!("runtime_dir = \"{RUNTIME_DIR}\""),
                format!("agent_runtime_dir = \"{AGENT_RUNTIME_DIR}\""),
                format!("sentence_rules_path = \"{RULES_FILE}\""),
            ] {
                assert!(config.contains(&expected), "config lacks {expected}");
            }
            assert!(
                !config.contains("host_allowlist"),
                "the dead host_allowlist key must not appear"
            );
        }

        #[test]
        fn the_stale_july_box_artifacts_are_declared_retired() {
            for retired in [
                "/Library/LaunchDaemons/dev.cermet.runtime-dir.plist",
                "/usr/local/libexec/cermet/provision-runtime-dir.sh",
                // The prefix is /opt/cermet/bin, so copies an earlier install left under
                // /usr/local/bin are not just stale — they SHADOW the new install, because
                // /etc/paths puts /usr/local/bin ahead of any /etc/paths.d entry. Removing the
                // files is fine; the dir itself is Homebrew's and setup never touches it.
                "/usr/local/bin/cermet",
                "/usr/local/bin/cermetd",
            ] {
                assert!(
                    RETIRED_PLATFORM_ARTIFACTS.contains(&retired),
                    "missing {retired}"
                );
            }
            let live_paths: Vec<String> = [PLIST_DEST, CLI_DEST, PATHS_D_DEST]
                .iter()
                .map(|path| path.to_string())
                .chain(
                    MULTICALL_ALIASES
                        .iter()
                        .map(|alias| format!("{INSTALL_BIN_DIR}/{alias}")),
                )
                .collect();
            for live in live_paths.iter().map(String::as_str) {
                assert!(
                    !RETIRED_PLATFORM_ARTIFACTS.contains(&live)
                        && !RETIRED_BINARIES.contains(&live),
                    "{live} is installed by this build; the sweep must never eat it"
                );
            }
            // The macOS service key joins the vendor-reset inventory, or --force-clean-bootstrap
            // would leave a key behind and then refuse to mint over the state it did not clear.
            assert_eq!(force_clean_kind("master.key"), Some(ForceCleanKind::File));
        }

        #[test]
        fn a_role_account_is_hidden_shell_less_and_password_less() {
            let record = role_user_attributes(401, 403, "Cermet Agent");
            let value = |key: &str| {
                record
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.as_str())
            };
            assert_eq!(value("UniqueID"), Some("401"));
            assert_eq!(value("PrimaryGroupID"), Some("403"));
            assert_eq!(
                value("UserShell"),
                Some("/usr/bin/false"),
                "a role account must not be able to log in"
            );
            assert_eq!(value("NFSHomeDirectory"), Some("/var/empty"));
            assert_eq!(value("RealName"), Some("Cermet Agent"));
            assert_eq!(
                value("Password"),
                Some("*"),
                "no password hash means no password login"
            );
            assert_eq!(value("IsHidden"), Some("1"));

            let group = role_group_attributes(403, "Cermet Agents");
            assert_eq!(
                group
                    .iter()
                    .find(|(k, _)| k == "PrimaryGroupID")
                    .map(|(_, v)| v.as_str()),
                Some("403")
            );
        }

        #[test]
        fn dscl_scalar_reads_both_inline_and_continued_values() {
            assert_eq!(parse_dscl_scalar("UniqueID: 400\n").as_deref(), Some("400"));
            assert_eq!(
                parse_dscl_scalar("NFSHomeDirectory: /var/empty\n").as_deref(),
                Some("/var/empty")
            );
            // dscl namespaces native attributes, so the value is after the LAST colon.
            assert_eq!(
                parse_dscl_scalar("dsAttrTypeNative:IsHidden: 1\n").as_deref(),
                Some("1")
            );
            // A value dscl chose to continue onto the next line (RealName always does).
            assert_eq!(
                parse_dscl_scalar("RealName:\n Cermet Daemon\n").as_deref(),
                Some("Cermet Daemon")
            );
            assert_eq!(parse_dscl_scalar("No such key: IsHidden\n"), None);
            assert_eq!(parse_dscl_scalar(""), None);
        }

        #[test]
        fn dscl_id_lists_ignore_names_and_apples_negative_ids() {
            let listing = "_cermet                  400\n\
                           cermet-agent             401\n\
                           nobody                   -2\n\
                           daemon                   1\n";
            assert_eq!(
                parse_dscl_id_list(listing),
                [400, 401, 1].into_iter().collect::<BTreeSet<u32>>()
            );
            assert!(parse_dscl_id_list("").is_empty());
        }

        #[test]
        fn a_stale_platform_config_is_refused_with_the_step_zero_remedy() {
            // `install_or_validate_config` PRESERVES an operator's config — correct, it is
            // their file — while setup converges the platform's own runtime dirs. A config from an
            // earlier macOS installer then passes every existing check, setup prints "complete",
            // and the daemon crash-loops under KeepAlive with a message about directory modes.
            // Fail closed, and point at the remedy.
            let stale = "service_user = \"_cermet\"\n\
                         service_uid  = 400\n\
                         approver_uid = 501\n\
                         runtime_dir  = \"/var/run/cermetd\"\n\
                         agent_runtime_dir = \"/var/run/cermetd-agents\"\n";
            let error = assert_config_matches_converged_runtime_dirs(stale).unwrap_err();
            assert!(error.contains("runtime_dir"), "{error}");
            assert!(
                error.contains("/var/run/cermetd"),
                "names what it found: {error}"
            );
            assert!(
                error.contains(RUNTIME_DIR),
                "names what it converged: {error}"
            );
            assert!(
                error.contains("sudo rm -rf /etc/cermetd"),
                "the refusal carries the step-0 remedy: {error}"
            );

            // The agent dir is checked too, not just the first key.
            let half_stale = format!(
                "runtime_dir = \"{RUNTIME_DIR}\"\nagent_runtime_dir = \"/var/run/cermetd-agents\"\n"
            );
            assert!(assert_config_matches_converged_runtime_dirs(&half_stale).is_err());

            // An absent key is a refusal, not a pass: the daemon would fall back to a Linux default.
            assert!(assert_config_matches_converged_runtime_dirs("approver_uid = 501\n").is_err());

            // The template this build installs passes, or a FRESH install would refuse itself.
            assert_config_matches_converged_runtime_dirs(include_str!(
                "../../../dist/macos/config.toml"
            ))
            .expect("the shipped macOS template must satisfy its own check");
        }

        #[test]
        fn a_fresh_role_id_is_the_first_unused_one_and_a_full_range_fails_closed() {
            let taken = [400, 401, 402].into_iter().collect::<BTreeSet<u32>>();
            assert_eq!(first_free_id(&taken, 400..500), Some(403));
            assert_eq!(first_free_id(&BTreeSet::new(), 400..500), Some(400));
            let full = (400..500).collect::<BTreeSet<u32>>();
            assert_eq!(
                first_free_id(&full, 400..500),
                None,
                "a full range must fail closed, never wrap onto a live account"
            );
        }

        #[test]
        fn the_launchd_service_target_is_the_system_domain_job() {
            assert_eq!(launchd_service_target(), "system/dev.cermet.cermetd");
        }
    }
}

#[cfg(test)]
mod operator_settings_tests {
    use super::*;

    /// The daily update check's own line, in the run that enables it. Default-on earns four facts:
    /// what is contacted, how often, that NOTHING installs itself, and the
    /// command that stops it.
    #[test]
    fn setup_states_what_the_daily_update_check_does_and_does_not_do() {
        let on = update_check_report(true);
        assert!(on.contains("daily"), "{on}");
        assert!(
            on.contains("https://github.com/suarezc/cermet/releases"),
            "{on}"
        );
        assert!(on.contains("nothing installs itself"), "{on}");
        assert!(on.contains("sudo cermet update"), "{on}");
        assert!(on.contains("cermet update --daily off"), "{on}");
        assert!(
            on.contains("never by the daemon"),
            "the custody statement stays true and is said: {on}"
        );

        let off = update_check_report(false);
        assert!(off.contains("off"), "{off}");
        assert!(
            off.contains("nothing is contacted on a schedule"),
            "an opted-out box is told what that bought it: {off}"
        );
        assert!(off.contains("cermet update --daily on"), "{off}");
    }

    /// Every directory the write had to create is handed to the operator, not just the innermost
    /// one: on a fresh account `create_dir_all` makes `~/.config` too, and a root-owned `~/.config`
    /// would break far more than this setting.
    #[test]
    fn every_created_ancestor_is_handed_to_the_operator() {
        let home = PathBuf::from("/home/someone");
        let path = crate::settings::config_path_in(Some(home.clone()));
        assert_eq!(
            created_ancestors(&home, &path),
            vec![
                PathBuf::from("/home/someone/.config"),
                PathBuf::from("/home/someone/.config/cermet"),
            ]
        );
        // A settings file directly in the home directory has no ancestor to hand over.
        assert!(created_ancestors(&home, &home.join("config.toml")).is_empty());
    }

    /// The handover chowns to the approver's NUMERIC primary gid, never to a group
    /// assumed to share their name — macOS mints no such group and `chown user:user` fails there,
    /// leaving `~/.config/cermet` root-owned. The resolver must answer from the password database
    /// on both platforms.
    #[test]
    fn the_handover_group_is_the_numeric_primary_gid() {
        let me = nix::unistd::User::from_uid(nix::unistd::getuid())
            .expect("password database is readable")
            .expect("the current uid resolves to a user");
        assert_eq!(
            primary_gid(&me.name).as_deref(),
            Some(nix::unistd::getgid().to_string().as_str()),
            "primary_gid must return the account's own gid, numerically"
        );
    }
}

/// The macOS liveness question is "is the broker SERVING?", never "did launchd accept the
/// job?". A crash-looping LaunchDaemon IS loaded, so the old loadedness check printed
/// "✓ broker running" over a daemon that had never once reached `main`. These are the pure halves —
/// reading `launchctl print` and writing the refusal — so the logic is exercised on any host, while
/// the acceptance gate stays the release-check workflow's virgin macOS runner.
#[cfg(test)]
mod launchd_liveness_tests {
    use super::*;

    /// A healthy job: launchd reports `state = running` and has nothing to report as an exit.
    const RUNNING: &str = "\
system/dev.cermet.cermetd = {
\tactive count = 1
\tpath = /Library/LaunchDaemons/dev.cermet.cermetd.plist
\ttype = LaunchDaemon
\tstate = running

\tprogram = /opt/cermet/bin/cermetd
\targuments = {
\t\t/opt/cermet/bin/cermetd
\t}

\tenvironment = {
\t\tCERMET_SERVICE_MODE => 1
\t\tCERMET_HOME => /var/lib/cermetd
\t}

\tdomain = system
\truns = 1
\tpid = 4711
\tlast exit code = (never exited)
}
";

    /// The virgin-Mac signature: launchd scheduled the spawn, the child died BEFORE exec, and the
    /// posix_spawn failure surfaces as exit 78.
    const SPAWN_SCHEDULED: &str = "\
system/dev.cermet.cermetd = {
\tactive count = 1
\tpath = /Library/LaunchDaemons/dev.cermet.cermetd.plist
\ttype = LaunchDaemon
\tstate = spawn scheduled

\tprogram = /opt/cermet/bin/cermetd
\tdomain = system
\truns = 12
\tforks = 0
\texecs = 0
\tlast exit code = 78
}
";

    /// Nothing loaded: `launchctl print` exits non-zero and writes this to stderr, leaving stdout
    /// empty. Either text must parse to "no state", never to a running job.
    const MISSING: &str = "Could not find service \"dev.cermet.cermetd\" in domain for system\n";

    #[test]
    fn a_running_job_is_the_only_state_read_as_serving() {
        let status = parse_launchd_print(RUNNING);
        assert_eq!(status.state.as_deref(), Some("running"));
        assert_eq!(status.last_exit_code.as_deref(), Some("(never exited)"));
        assert!(status.is_running());
    }

    #[test]
    fn a_spawn_scheduled_job_is_loaded_but_not_serving() {
        let status = parse_launchd_print(SPAWN_SCHEDULED);
        assert_eq!(status.state.as_deref(), Some("spawn scheduled"));
        assert_eq!(
            status.last_exit_code.as_deref(),
            Some("78"),
            "exit 78 is the pre-exec spawn failure the loaded-check hid"
        );
        assert!(
            !status.is_running(),
            "loadedness is not liveness — this is the crash-loop the old check green-lit"
        );
    }

    #[test]
    fn a_missing_job_reports_no_state_at_all() {
        for text in [MISSING, ""] {
            let status = parse_launchd_print(text);
            assert_eq!(status.state, None);
            assert_eq!(status.last_exit_code, None);
            assert!(!status.is_running());
        }
    }

    /// `environment = { KEY => value }` blocks use `=>`, not `=`, and no nested block may shadow the
    /// top-level answer: the FIRST reading of each key wins.
    #[test]
    fn nested_blocks_do_not_shadow_the_top_level_state() {
        let text = "\
system/dev.cermet.cermetd = {
\tstate = spawn scheduled
\tenvironment = {
\t\tstate => running
\t}
\tsomething = {
\t\tstate = running
\t}
\tlast exit code = 78
}
";
        let status = parse_launchd_print(text);
        assert_eq!(status.state.as_deref(), Some("spawn scheduled"));
        assert!(!status.is_running());
    }

    /// The pre-exec death: no log file, because launchd never got far enough to open one. The
    /// refusal must SAY that, and say it is the log path that is at fault — this is the whole
    /// diagnostic the operator's virgin Mac did not get.
    #[test]
    fn the_refusal_names_the_pre_exec_death_when_the_log_is_absent() {
        let report = serving_failure_report(&parse_launchd_print(SPAWN_SCHEDULED), false, false);
        assert!(report.contains("spawn scheduled"), "{report}");
        assert!(report.contains("78"), "{report}");
        assert!(report.contains(DAEMON_LOG_FILE), "{report}");
        assert!(
            report.contains("ABSENT") && report.contains("BEFORE exec"),
            "the absent log is the discriminating evidence, not a footnote: {report}"
        );
        assert!(
            report.contains(crate::endpoint::DEFAULT_CTL_SOCK),
            "{report}"
        );
        assert!(
            report.contains("NOT usable"),
            "an evidenced failure is a failed install, said plainly: {report}"
        );
    }

    /// The other side of the fork: the log EXISTS, so the daemon execed and then refused for its
    /// own reasons — and its reason is in that file. Point at it instead of blaming the spawn.
    #[test]
    fn the_refusal_points_at_the_log_when_the_daemon_did_start() {
        let report = serving_failure_report(&parse_launchd_print(SPAWN_SCHEDULED), true, false);
        assert!(
            !report.contains("BEFORE exec"),
            "a present log disproves pre-exec death: {report}"
        );
        assert!(
            report.contains("tail") && report.contains(DAEMON_LOG_FILE),
            "the refusal hands over the command that reads the reason: {report}"
        );
    }

    /// A missing job needs a refusal too — with no state to quote, it must still be legible rather
    /// than printing an empty field.
    #[test]
    fn the_refusal_is_legible_when_launchd_holds_no_job_at_all() {
        let report = serving_failure_report(&parse_launchd_print(MISSING), false, false);
        assert!(report.contains("no job"), "{report}");
        assert!(!report.contains("state: \n"), "{report}");
    }

    /// The poll's three-way read of one launchctl snapshot. Failure needs EVIDENCE — an exit code,
    /// or no job loaded at all. Elapsed time is never evidence: a slow first boot (vault mint,
    /// catalog seed, a loaded machine) reads exactly like a fast one at every instant, so a daemon
    /// that has never exited is "still starting", however long that takes.
    #[test]
    fn the_poll_refuses_on_evidence_and_waits_on_none() {
        // Running with the socket bound: serving.
        assert_eq!(
            serving_poll(&parse_launchd_print(RUNNING), true),
            ServingPoll::Serving
        );
        // Running but not yet bound: alive, still starting.
        assert_eq!(
            serving_poll(&parse_launchd_print(RUNNING), false),
            ServingPoll::StillStarting
        );
        // An exit code is crash evidence, whatever the current state reads — refuse NOW, not at
        // the end of a window.
        assert_eq!(
            serving_poll(&parse_launchd_print(SPAWN_SCHEDULED), false),
            ServingPoll::Failed
        );
        // No job loaded is failure evidence too.
        assert_eq!(
            serving_poll(&parse_launchd_print(MISSING), false),
            ServingPoll::Failed
        );
        // Scheduled but never exited: the first instants of a normal boot. No evidence, no verdict.
        let booting = "\
system/dev.cermet.cermetd = {
\tstate = spawn scheduled
\tlast exit code = (never exited)
}
";
        assert_eq!(
            serving_poll(&parse_launchd_print(booting), false),
            ServingPoll::StillStarting
        );
    }

    /// The cap-out on a daemon that never exited is NOT a failure verdict: nothing has failed, the
    /// box is slow. The report must say that, name the watch command, and say a re-run is safe —
    /// and must not carry the failure report's "NOT usable" sentence, which would be false.
    #[test]
    fn a_slow_first_boot_earns_patience_not_a_failure_verdict() {
        let report = still_starting_report(&parse_launchd_print(RUNNING), false);
        assert!(report.contains("still starting"), "{report}");
        assert!(!report.contains("NOT usable"), "{report}");
        assert!(
            report.contains("safe") && report.contains("cermet setup"),
            "the remedy is patience plus a safe re-run: {report}"
        );
        assert!(report.contains("launchctl print"), "{report}");
        assert!(report.contains("cermet check"), "{report}");
    }

    /// The path setup converges and the path launchd opens are ONE fact. The plist is the contract;
    /// a drift between the two silently restores the virgin-boot crash-loop.
    #[test]
    fn the_converged_log_path_is_the_path_the_plist_names() {
        let plist = include_str!("../../../dist/macos/dev.cermet.cermetd.plist");
        assert!(
            plist.contains(&format!(
                "<key>StandardOutPath</key>\n  <string>{DAEMON_LOG_FILE}</string>"
            )),
            "the plist's StandardOutPath must be the file setup pre-creates"
        );
        assert!(
            plist.contains(&format!(
                "<key>StandardErrorPath</key>\n  <string>{DAEMON_LOG_FILE}</string>"
            )),
            "the plist's StandardErrorPath must be the file setup pre-creates"
        );
    }
}
