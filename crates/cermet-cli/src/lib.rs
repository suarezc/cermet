//! `cermet-cli` — the human operator CLI over `ctl.sock`.
//!
//! A keyless client of the cermetd-hosted broker (the master key + vault live in the daemon uid). It
//! drives operator requests and sentence-custody mutations through the shared [`CtlBrokerClient`].
//! Both operator and agent paths use pure `parse` → async `dispatch` → pure `render`, so the
//! parse + render layers are unit-testable and the transport is exercised over a REAL socket in
//! `tests/`.
//!
//! Authority installation is presence-gated and fail closed; grants are single-use; no secret is
//! ever printed.

use cermet_ipc::wire::ArtifactRange;
use cermet_lang::Error;
use serde_json::Value;

mod authority_dispatch;
pub mod cermet_document;
pub mod check;
pub mod connect;
pub mod cutover;
pub mod document_store;
pub mod endpoint;
/// The operator-CLI and git-remote-helper ROLE entries. ONE-BINARY: role selection lives in the
/// composition crate's closed dispatch table (`crates/cermet-bin`), which calls these with an
/// explicit argument slice.
pub mod entry;
pub mod git_remote;
/// The CLI's own output journal: one JSON line per invocation, recording what it printed.
pub mod journal;
pub mod mcp;
pub mod mcp_bridge;
pub mod owner;
/// `preset` — a stored authority profile, applied by name through the unchanged corpus ceremony.
pub mod preset;
pub mod receipt_log;
pub mod reconciliation;
pub mod rule_cli;
pub mod sentence_ctl;
pub mod sentence_custody;
/// The operator's own settings file (the daily update check's knob).
pub mod settings;
pub mod setup;
pub mod tty;
pub mod update;
/// The daily update CHECK and the local notice it leaves — never an install.
pub mod update_check;
/// The `request_vocabulary` MCP tool's capture core: the two-gap check + the credential
/// chokepoint. Nothing is stored locally and nothing is transmitted.
pub mod vocab_request;

pub(crate) mod dispatch;
mod guard;
mod parse;
mod render;

pub use authority_dispatch::{dispatch_authority_command, AuthorityCommandOutput};
pub use dispatch::dispatch;
pub use guard::cermet_home;
pub use parse::{help_text, parse, split_socket_flag, version_text};
pub use render::render_artifact;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, PartialEq)]
pub enum CliCommand {
    /// `run <provider>.<action>` — decide AND execute, in one flow. The sentence decision
    /// is unchanged and every executed field is still frozen before the grant is minted; the fusion
    /// is CLI plumbing only. On `Allow` execution proceeds without a second command; on `Deny` the
    /// refusal (plus its widening hint) is rendered and the process exits non-zero. `ask_only` stops
    /// after the decision, which is then finished with [`CliCommand::Resume`].
    Run {
        provider: String,
        action: String,
        resource: Value,
        environment: Option<String>,
        justification: Option<String>,
        ask_only: bool,
        /// `--retry-effect <effect_id>`: the safe effect handle a prior attempt reported when
        /// nothing observed determined whether its effect landed. Request METADATA — it never
        /// enters the resource. Passed to the daemon unexamined; the daemon authenticates the
        /// lineage and denies if it does not hold (one validation, on the enforcement side).
        retry_effect: Option<String>,
    },
    /// `run --resume <request_id>` — execute an already-decided request by the `request_id` its run
    /// reported: the ONE public id, from which the daemon resolves the grant. The operator path is
    /// NOT session-bound. All executed fields were frozen at request time, so this carries none.
    Resume { request_id: String },
    /// Read a stored response/output by artifact handle: full, a byte/line range, or a `$.path`
    /// capture-pointer (one JSON sub-value). `range` and `path` are mutually exclusive. Read-only.
    Artifact {
        handle: String,
        range: Option<ArtifactRange>,
        path: Option<String>,
    },
    /// Verify the audit hash-chain integrity.
    AuditVerify,
    /// `log <request_id>` — one request's record over the operator-only ctl socket, rendered as
    /// JSON: the verified execution evidence for a granted request, the recorded denial for a
    /// refused one. The zoomed-in half of `log`.
    Evidence { request_id: String },
    /// `check [<provider>]` — the read-only plumbing checklist. Diagnosis only: it
    /// reports what is unset and how to set it, and mutates nothing, locally or in the daemon.
    Check { provider: Option<String> },
    /// `catalog [--all]` — capability discovery. The default zoom is the CONTRACT: the
    /// verbs a standing sentence admits right now, each with the fields you supply and the
    /// admitting sentence quoted verbatim. `--all` is the DICTIONARY: every verb that exists,
    /// stamped with its authority, for naming the sentence you need. Both zooms render the daemon's
    /// OWN join (the same `catalog_listing()` the MCP tool reads) — read-only, no re-decision here.
    Catalog { all: bool },
    /// Read the independent owner revocation latch over owner.sock. Root-only, observational.
    OwnerStatus,
    /// Engage the independent deny latch. Root-only and authority-narrowing.
    OwnerLockdown,
    /// Clear the deny latch after an explicit owner confirmation. Root-only and authority-restoring.
    OwnerLockdownClear,
    /// `doc check --init` — create the no-clobber repository authority document from the typed live
    /// snapshot.
    Init,
    /// `doc check [--fix]` — prepare and validate the repository candidate; `--fix` canonicalizes
    /// only its managed block.
    DocCheck { fix: bool },
    /// Render deterministic three-way rule and immutable-set differences.
    Diff,
    /// Classify repository/marker/live drift and lockdown without mutation.
    Status { as_json: bool },
    /// Project served authority into the document without staging or presence.
    Export { replace_draft: bool },
    /// Presence-accept the exact canonical body as one whole-corpus transaction.
    ///
    /// `file` is the document to apply; `None` is discovery from the working directory, unchanged.
    /// A `CERMET_<name>.md` file is an authority PROFILE: the same ceremony, and on commit the
    /// daemon stores the committed body under `<name>`.
    Apply {
        file: Option<String>,
        replace_live: bool,
        recover: bool,
    },
    /// The `preset` noun: the stored authority profiles — list them, install one (the SAME
    /// whole-corpus ceremony [`CliCommand::Apply`] runs), or write one back out as a document.
    Preset(preset::PresetCommand),
    /// Connect a provider — reuse/discover a token, vault it unused. Driven by the binary front-end
    /// (needs the terminal + token-source seams), NOT the ctl `dispatch`.
    Connect(connect::ConnectArgs),
    /// Add one sentence rule through the direct, presence-gated custody path.
    /// `yes` skips only the CLI-side canonical-echo confirm; it never
    /// auto-confirms a pin-mismatch recovery, and the presence gate still governs.
    Allow { rule: String, yes: bool },
    /// List the direct-custody sentence rules in canonical form.
    Rules,
    /// Delete one numbered sentence rule through the direct, presence-gated custody path.
    /// `yes` skips only the CLI-side y/N confirm; the presence gate still governs.
    Revoke { number: usize, yes: bool },
    /// Rebind one set rule to the current immutable expansion after a presence-gated exact diff.
    Refresh { number: usize },
    /// Render the daemon-native "morning receipt" from the ctl `History` RPC.
    ///
    /// WINDOWED by default — the newest [`receipt_log::LOG_DEFAULT_ROWS`] rows. An unwindowed dump
    /// of a long log is the single largest context cost of reading it, and the log is read by agents
    /// far more often than by a human at a terminal. Never a SILENT cap: a windowed render says how
    /// many rows exist and how to widen. The filters narrow the log first; the window applies to
    /// what is left.
    Log {
        since: Option<String>,
        /// Narrow to one provider's rows.
        provider: Option<String>,
        denied_only: bool,
        /// Render the relay hop log instead of the grant receipt.
        hops: bool,
        /// The full dump — every row, unwindowed.
        all: bool,
    },
    /// `cermet journal [on|off]` — the CLI's own output journal. Bare: what it is doing, where the
    /// file is, and the bounds it enforces. `on`/`off`: the persisted switch, in the operator's own
    /// settings file. Reading the journal is NOT a command — it is a plain JSONL file, and the
    /// status form prints its path for exactly that reason.
    Journal { enabled: Option<bool> },
    /// Register the `cermet mcp` stdio server (a client of cermetd) with the agent client.
    /// Driven by the binary front-end.
    McpInstall(mcp::McpInstallArgs),
    /// Provision or converge the Linux service installation. This is the only privileged local
    /// system mutation path; packages themselves only place source files.
    Setup(setup::SetupArgs),
    /// `cermet update [--check]` — ask the origin what it publishes and install it. TYPED ONLY:
    /// this form contacts the origin when the operator types it, and `check` reports and stops.
    /// The one scheduled contact in the product is [`CliCommand::UpdateDailyCheck`], which installs
    /// nothing.
    Update { check: bool },
    /// `cermet update --daily-check` — the SCHEDULED check the installed timer/LaunchDaemon runs
    /// once a day AS THE OPERATOR. It asks the origin what it publishes,
    /// records the answer locally, and stops: no install, no sudo, no daemon. It honors the
    /// `update_check` setting and does nothing at all — including no network contact — when it is
    /// off.
    UpdateDailyCheck,
    /// `cermet update --daily on|off` — the knob for the scheduled check, in the operator's own
    /// settings file. It lives under the `update` noun because it governs exactly one thing that
    /// noun already does.
    UpdateDaily { enabled: bool },
    /// `cermet update --apply <sha256>` — the TARBALL channel's privileged half, which `update`
    /// re-execs itself as through sudo, running the STAGED (new) binary. It re-verifies the staged
    /// bytes against that digest and hands them to setup's own publish/cutover convergence.
    UpdateApply { sha256: String },
    /// `cermet update --apply-deb <path> --sha256 <hex>` — the DEB channel's privileged half. It
    /// takes a private root-owned copy of the staged package, verifies THAT copy against the
    /// digest, and applies it with `dpkg -i`. Nothing is published into the tarball prefix on this
    /// path: the package manager owns the box.
    UpdateApplyDeb { package: String, sha256: String },
}

/// Everything that can go wrong driving the operator CLI. `Usage` exits 2; the rest fail closed and
/// exit non-zero.
#[derive(Debug)]
pub enum CliError {
    /// Bad invocation (unknown subcommand, missing arg, non-JSON `--resource`, bad `--range`).
    Usage(String),
    /// The presence gate did not confirm (declined or unavailable). The mutation did NOT happen.
    Presence(String),
    /// The broker returned a fail-closed error (denied / not-found / invalid / provider).
    Server(Error),
    /// A response did not match the expected shape; fail closed.
    Malformed(String),
    /// A refusal, or a failure the CLI renders in its own words rather than the broker's. Writes
    /// nothing and exits non-zero.
    Refused(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Usage(m) => write!(f, "{m}"),
            CliError::Presence(m) => write!(f, "{m}"),
            CliError::Server(e) => write!(f, "{e}"),
            CliError::Malformed(m) => write!(f, "{m}"),
            CliError::Refused(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CliError {}

/// The rendered result of a command: text for the terminal + an `ok` flag driving the exit code.
#[derive(Debug, Clone, PartialEq)]
pub struct CliOutput {
    pub text: String,
    pub ok: bool,
}
