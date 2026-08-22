//! Operator CLI argument parsing: the top-level `parse` dispatcher plus the per-command
//! flag/positional helpers and the shared `USAGE` banner. Pure (no I/O); unit-tested via `tests.rs`.
//!
//! The surface is fifteen commands. Two of them are nouns — `rules` and `doc` —
//! because their subcommands are the same three or five operations on one thing, and one of
//! them, `run`, is the fusion of the old `request` + `execute`: an operator who is allowed to do
//! a thing does not then need a second command's permission to do it. `catalog` is the one an
//! agent reaches for FIRST: without it a CLI-only agent would have to hand-join `--help` against
//! `cermet rules`, or probe verbs one deny at a time, to learn what it could do. The `update` noun
//! is the only one in the table that contacts GitHub: `update` and `update --check` when
//! typed, and `update --daily-check` on the daily timer, which records a LOCAL notice and installs
//! nothing.
//!
//! Retired names are not silently unknown ([`retired`]): every one of them names its replacement,
//! because a CLI that shrinks without teaching just strands the people who learned the old one.

use cermet_ipc::wire::ArtifactRange;
use serde_json::json;

use super::{CliCommand, CliError};
use crate::{connect, mcp, preset, setup};

const USAGE: &str = "\
cermet — the capability broker CLI (authority changes are human-only, presence-gated)
usage: cermet [--socket <path>] <command>      (`cermet <command> --help` for one command)

AGENT WORK — capability requests and their receipts:
    catalog [--all]                                (what you may do now; --all: every verb + its authority)
    run <provider>.<action> [--resource <json>] [--environment <env>] [--justification <text>]
                            [--ask-only] [--retry-effect <effect_id>]
                                                   (decide AND execute; --ask-only prints the decision as JSON)
    run --resume <request_id>                      (execute a decided request; its fields stay frozen)
    log [--since <RFC3339>] [--provider <p>] [--denied] [--burned] [--hops] [--all]
                                                   (the receipt log: newest 100 rows unless --all)
    log <request_id>                               (one request's record, as JSON)
    artifact <handle> [--range <unit>:<start>[-<end>] | --path '$.a.b']
    audit-verify                                   (check the audit hash-chain)
    check [<provider>]                             (read-only plumbing checklist: all, or one provider)
    journal [on|off]                               (this CLI's own record of what it printed, per run)

AUTHORITY — human-only, presence-gated:
    rules                                          (numbered canonical rule list)
    rules allow \"<rule>\" [--yes] | revoke <n> [--yes] | refresh <n>
    doc check [--fix|--init] | doc diff | doc apply [<file>] [--replace-live] [--recover]
    doc export [--replace-draft] | doc status [--json]
    preset list | preset <name> | preset export <name> [<path>] [--force]
                                                   (stored authority profiles, applied by name)
    owner status | owner lockdown [clear]          (root-only independent revocation root)

CEREMONIES — one-time setup:
    connect <provider> [account_label] [--replace] [--adopt]
    setup [--from-tree [<repo>]] [--force-clean-bootstrap]
    update [--check] | update --daily on|off       (install a release; the daily check only notices)
    mcp                                            (the keyless stdio bridge agents speak)
    mcp install [--client claude|opencode] [--name <n>] [--force]

Exit codes: 0 success/aligned, 1 denied or drift, 2 bad invocation. `--version` prints this build.";

// ---- per-command usage, the text `cermet <command> --help` prints -----------------------------

const RUN_USAGE: &str = "\
run <provider>.<action> [--resource <json>] [--environment <env>] [--justification <text>]
                        [--ask-only] [--retry-effect <effect_id>]
    Decide AND execute one verb. The verb is DOTTED, exactly as the sentence corpus spells it
    (`allow vercel.deploy`). --ask-only stops at the decision and prints it as JSON — exit 0
    for an allow, 1 for a deny.
    A RELAY verb (vercel.deploy) is the exception to \"execute\": the broker authorizes it and
    mints a scoped session, then prints the invocation YOU run with the provider's own CLI.
    --retry-effect <effect_id> RETRIES the effect a prior attempt reported when nothing observed
    said whether it landed (the failure names the handle). It is a NEW request: the sentence is
    decided afresh, and the daemon allows it only if the fields are byte-identical to that attempt
    and you own it — then it reuses that effect's idempotency key and its budget debit instead of
    taking new ones. Every other field is supplied exactly as on a first attempt.
run --resume <request_id>
    Execute an already-decided request. It takes nothing else: every field was frozen when the
    request was decided.";

const LOG_USAGE: &str = "\
log [--since <RFC3339>] [--provider <name>] [--denied] [--burned] [--hops] [--all]
    The receipt log, newest first. Each row names its request id and the justification the request
    carried; pass that id to `log <request_id>` for the whole record. Without --all it renders the
    100 most recent rows and says so on a final line — the filters narrow the log FIRST, then the
    window applies.
    A row ENDS with what became of the effect its decision authorized, where the record determines
    one: `→ok` (the effect landed), `→burned(<reason>)` (a refusal ended the relay session),
    `→expired_unused` (the window ended having driven nothing), `→unresolved` (it ended after hops
    with nothing saying the effect landed). No suffix means the record does not say — a window still
    in flight, a request decided and not executed, or an effect whose failure the row already names.
      --since <RFC3339>   only rows at or after that instant, e.g. 2026-08-03T00:00:00Z
      --provider <name>   only that provider's rows
      --denied            only the refusals
      --burned            only the rows whose relay grant BURNED — allowed, then ended by a
                          refused hop (on --hops, the burning hops themselves)
      --hops              the relay hop view instead of the grant receipt
      --all               every row, unwindowed
log <request_id>
    One request's record as JSON, in whichever of its three states it is: the verified execution
    evidence of a request that ran, the recorded denial of one that was refused, or — for a
    request decided but not yet executed, which is what --ask-only leaves behind — the decision,
    its frozen fields, the sentence that admitted them and the `run --resume` that finishes it.";

const ARTIFACT_USAGE: &str =
    "artifact <handle> [--range <unit>:<start>[-<end>] | --path '$.a.b']\n\
    \x20   Read a stored response by handle: whole, a lines/bytes range, or one `$.a.b` sub-value.";

const AUDIT_VERIFY_USAGE: &str = "audit-verify\n\
    \x20   Verify the audit hash-chain. Takes no arguments.";

const CHECK_USAGE: &str = "check [<provider>]\n\
    \x20   The read-only plumbing checklist, for every provider or one. Mutates nothing.\n\
    \x20   (The CERMET.md document check is `doc check`.)";

const CATALOG_USAGE: &str = "catalog [--all]\n\
    \x20   Capability discovery. Default: the verbs a standing sentence admits right now, with\n\
    \x20   their bounds. --all: every verb that exists, each stamped with its authority.";

const RULES_USAGE: &str = "\
rules
    List the sentence corpus in canonical form.
rules allow \"<rule>\" [--yes]  |  rules revoke <n> [--yes]  |  rules refresh <n>
    Human-only, presence-gated. --yes skips only the CLI-side echo confirm, never the presence gate.";

const DOC_USAGE: &str = "\
doc check [--fix|--init] | doc diff | doc status [--json]
doc export [--replace-draft] | doc apply [<file>] [--replace-live] [--recover]
    The CERMET.md corpus flow: `doc check --fix` → `doc diff` → `doc apply`.
    `doc apply` with no file discovers this repository's CERMET.md, as it always has. Given a file
    it applies THAT document: a CERMET.md path is the identical pinned flow, and a
    CERMET_<name>.md path is an authority PROFILE — the same ceremony, and what it commits is also
    stored under <name> for `cermet preset <name>` (see `cermet preset --help`).";

const PRESET_USAGE: &str = "\
preset list
    Every stored authority profile: its name, how many rules it holds, and when it was stored.
    The profile whose body the daemon is serving right now is marked `● live`.
preset <name> [--recover]
    Install that profile. A profile is a WHOLE corpus, so this REPLACES everything currently live —
    every rule the profile does not carry is gone. The ceremony is the one `doc apply` runs: the
    review shows the rule diff against what is live, then a terminal confirmation and the presence
    gate, then the staged commit. There is no --yes.
preset export <name> [<path>] [--force]
    Write the stored body back out as `CERMET_<name>.md` (in this directory, or at <path>), which
    `doc apply` re-ingests under the same name. Refuses to overwrite without --force.

    A preset is a NAME and a body of rules — nothing else. It refers to no repository and no file
    on this box, so `designer`, `builder` and `q3r982` are equally good names; a name may hold
    letters, digits, `_` and `-`.
    Profiles are written by applying a preset document: `cermet doc apply CERMET_<name>.md` runs
    the full ceremony and stores what it commits under <name>. There is no other way to write one,
    which is what makes every stored profile a body a human attested.";

const OWNER_USAGE: &str = "owner status | owner lockdown [clear]\n\
    \x20   The root-only independent revocation root. `lockdown` engages deny-all; `lockdown clear`\n\
    \x20   restores execution after an explicit interactive confirmation.";

const CONNECT_USAGE: &str = "connect <provider> [account_label] [--replace] [--adopt]\n\
    \x20   Vault a provider credential, unused. `connect github` also offers to wire this\n\
    \x20   repository's remote so plain `git push` reaches the broker.";

const SETUP_USAGE: &str = "setup [--from-tree [<repo>]] [--force-clean-bootstrap]\n\
    \x20   Provision or converge the local service installation. The only privileged local\n\
    \x20   mutation; run unprivileged it states what needs administrator access and elevates\n\
    \x20   itself through sudo.";

const UPDATE_USAGE: &str = "\
update [--check]
    Install the release https://github.com/suarezc/cermet/releases publishes as latest, through the
    channel this box was installed by: a dpkg-managed box applies the .deb with dpkg, everything
    else publishes the tarball through `cermet setup`. The version, the checksums and the artifact
    all come from that ONE release — the same GitHub Releases you installed from — and the artifact
    is verified against the release's own SHA256SUMS before anything is installed. Restarts cermetd.
    INSTALLING IS EXPLICIT ONLY: this command contacts GitHub when you type it, and the only other
    thing in Cermet that ever contacts it is the daily check below, which installs nothing.
    The checksum comes from the same release as the artifact, so it proves the download is intact
    and matches what the release publishes, not who authored it.
      --check   report what the release channel publishes and stop.
    It also states the verification it ran: `github-release` when a checksum was resolved,
    `no-artifact` when there was nothing to install and none was.
    $CERMET_UPDATE_ORIGIN redirects both halves of that contact (http(s):// or file://) so the flow
    can be exercised against a fixture tree. It is single-source self-vouching by design: applying
    still needs your sudo, and the consent paragraph always names the url it is about to install
    from.
    It never side-loads the other channel: two cermets that can disagree is the defect this
    avoids, not a convenience.
    Where another package ecosystem owns the running binary — a cargo install under
    $CARGO_HOME/bin, a Homebrew formula under a Cellar — it DELEGATES instead: it prints that
    ecosystem's own upgrade command plus the `sudo <that path> setup` step that republishes the
    system install from it, contacts no origin, and changes nothing. Package-manager installs
    stay package-manager-managed.
update --daily on|off
    The DAILY UPDATE CHECK, on by default. Once a day, as you and never as the daemon, Cermet
    asks https://github.com/suarezc/cermet/releases what it publishes and writes the answer HERE.
    It installs nothing. While something newer is available `cermet` prints one line and
    `cermet check` shows a row; applying it stays this command, with your sudo password.
    The request carries no install id, no account, no query and no parameters at all — the
    comparison happens on this machine. Its user agent names the client version (cermet/<version>,
    the same string on every install of that release), so release adoption is visible in aggregate;
    that is what makes it possible to know who a security notice still has to reach. A release
    whose notes begin with SECURITY: says SECURITY UPDATE and prints its release page.
    `off` stops the scheduled contact entirely. The setting is yours, in ~/.config/cermet/config.toml,
    and changing it needs no root.
update --daily-check
    Run that check once, now. This is what the installed timer (Linux) / LaunchDaemon (macOS)
    invokes; typing it is how you see what it would do. With the check off it exits having
    contacted nothing.
update --apply <sha256>  |  update --apply-deb <path> --sha256 <hex>
    The two privileged halves `update` re-execs itself as through sudo, one per channel. Each
    re-verifies the staged bytes against that digest before installing them. Not for hand use.";

const JOURNAL_USAGE: &str = "\
journal
    What the output journal is doing: on or off, the file it writes, how big that file is now, and
    the two bounds it enforces. Every `cermet` command appends ONE JSON line to that file: when it
    ran, its arguments, the directory it ran in, its exit code, how long it took, and the first
    4096 bytes of what it PRINTED. Output past that is counted in a `truncated` field, not stored —
    long renders (`log`, `catalog`) re-read stores that already exist durably, while the output that
    exists nowhere else (a ceremony's review text, a refusal, a status line) is short and always
    fits. The file rotates whole at 32 MiB, keeping one previous generation as `journal.jsonl.1`.
    Nothing you TYPE is recorded — the capture is of output only, so the no-echo token prompt in
    `cermet connect` cannot appear in it. It stays on this machine and is sent nowhere.
    READING it is not a cermet command: it is a plain JSONL file, and this prints its path so you
    can `tail`, `grep` or `jq` it with your own tools. For the BROKER's record of what was decided,
    use `cermet log` and `cermet audit-verify` — those are the receipts; this is a convenience.
journal on|off
    The switch, kept in your own settings file (~/.config/cermet/config.toml). Default: on.";

const MCP_USAGE: &str = "\
mcp
    Run the keyless MCP stdio server agents speak. Takes no arguments.
    $CERMET_AGENT_NAME sets the session's display label (default: mcp-agent).
    $CERMET_AGENT_MODEL declares which MODEL is driving, e.g. claude-opus-5. It is a SELF-REPORT
    labelling this machine's own receipts: no authority reads it, it grants nothing, and it stays on
    this box. Unset means the model is simply not recorded.
    Because it is read ONCE, it mislabels a mid-session model switch. Every brokered verb tool and
    `request_capability` therefore takes an optional per-request `model` argument, which wins over
    this variable when both are present and is recorded with its own weaker provenance
    (`self_reported` — an agent's claim about itself — versus `user_configured` for this variable).
mcp install [--client claude|opencode] [--name <n>] [--force]
    Register that server with the agent client.";

/// The usage text `cermet <command> --help` prints. `None` for anything that is not a live command,
/// so an unknown name stays an unknown-command error.
fn command_usage(command: &str) -> Option<&'static str> {
    Some(match command {
        "run" => RUN_USAGE,
        "log" => LOG_USAGE,
        "artifact" => ARTIFACT_USAGE,
        "audit-verify" => AUDIT_VERIFY_USAGE,
        "check" => CHECK_USAGE,
        "catalog" => CATALOG_USAGE,
        "journal" => JOURNAL_USAGE,
        "rules" => RULES_USAGE,
        "doc" => DOC_USAGE,
        "preset" => PRESET_USAGE,
        "owner" => OWNER_USAGE,
        "connect" => CONNECT_USAGE,
        "setup" => SETUP_USAGE,
        "update" => UPDATE_USAGE,
        "mcp" => MCP_USAGE,
        _ => return None,
    })
}

/// Asking what the tool does is a SUCCESSFUL invocation, at EVERY depth.
///
/// `cermet --help` / `-h` / `help`, `cermet <command> --help`, and `--help` on any subcommand —
/// including the multi-word ones (`mcp install`, `doc check`, `rules allow`) — print to stdout and
/// exit 0. Falling through to a parser arm that reports them as bad arguments would print the usage
/// text on stderr with exit 2, which reads to a caller as "no such command". A BAD invocation is
/// unchanged: usage on stderr, exit 2, and an unknown COMMAND stays unknown even when help is what
/// was asked for.
///
/// One rule at the dispatch layer, so a subcommand added later inherits it: the request is help if
/// any argument IS `--help`/`-h` (or the first word is `help`), and the text answering it is that of
/// the command PATH — the leading run of words before the first flag, resolved at its head. A
/// subcommand with no usage text of its own therefore falls back to its parent noun's, which is
/// where the subcommand is documented anyway. A literal `--help` supplied as a flag's VALUE reads as
/// a help request under this rule; no real value is that string, and the alternative — help that
/// errors — is the defect being fixed.
pub fn help_text(args: &[String]) -> Option<&'static str> {
    let (_socket, args) = split_socket_flag(args);
    let asked = args.iter().any(|a| a == "--help" || a == "-h")
        || args.first().is_some_and(|a| a == "help");
    if !asked {
        return None;
    }
    let mut path = args
        .iter()
        .map(String::as_str)
        .take_while(|a| !a.starts_with('-'));
    let head = match path.next() {
        Some("help") => path.next(),
        other => other,
    };
    match head {
        // Bare `cermet --help` / `cermet help`: the whole banner.
        None => Some(USAGE),
        // A live command answers with its own usage; anything else is an unknown command and keeps
        // the error path in `parse`.
        Some(command) => command_usage(command),
    }
}

/// `cermet --version` / `-V`, answered without a daemon.
///
/// A cold-start usability trial asked the most ordinary question a CLI is asked and got exit 2; the build
/// string existed only inside `cermet check`, which needs a running daemon to render. This prints
/// the SAME string that check compares — `cermet-ipc`'s [`cermet_ipc::BUILD_ID`], the one id both
/// halves of an install carry — so `cermet --version` and `cermetd --version` are directly
/// comparable by eye.
///
/// Top-level only, unlike `--help`: a version is a question about the binary, not about a command,
/// and `run --version` should stay a bad invocation rather than quietly become a version query.
pub fn version_text(args: &[String]) -> Option<String> {
    let (_socket, args) = split_socket_flag(args);
    let asked = args.first().is_some_and(|a| a == "--version" || a == "-V");
    asked.then(|| format!("cermet {}", cermet_ipc::BUILD_ID))
}

/// Parse the command + flags (the global `--socket` is stripped by [`split_socket_flag`] first).
pub fn parse(args: &[String]) -> Result<CliCommand, CliError> {
    let (cmd, rest) = args
        .split_first()
        .ok_or_else(|| CliError::Usage(USAGE.to_string()))?;
    match cmd.as_str() {
        "run" => parse_run(rest),
        "log" => parse_log(rest),
        "artifact" => parse_artifact(rest),
        "audit-verify" => {
            no_args(rest, "audit-verify")?;
            Ok(CliCommand::AuditVerify)
        }
        "check" => parse_check(rest),
        "catalog" => parse_catalog(rest),
        "journal" => parse_journal(rest),
        "rules" => parse_rules(rest),
        "doc" => parse_doc(rest),
        "preset" => parse_preset(rest),
        "owner" => parse_owner(rest),
        "connect" => parse_connect(rest),
        "setup" => Ok(CliCommand::Setup(setup::parse_setup(rest)?)),
        "update" => parse_update(rest),
        "mcp" => parse_mcp(rest),
        other => Err(CliError::Usage(match retired(other) {
            Some(replacement) => format!("{replacement}\n{USAGE}"),
            None => format!("unknown command {other:?}\n{USAGE}"),
        })),
    }
}

/// What a retired command name is now. Retirement has to TEACH: an operator (or an agent working
/// from a stale README) types the old word, and the one thing they need back is the new one.
fn retired(name: &str) -> Option<String> {
    Some(match name {
        "request" => "`request` is now `run <provider>.<action>` — it decides AND executes; \
                      `run --ask-only` stops at the decision"
            .to_string(),
        "execute" => "`execute` folded into `run`; finish a decided request with \
                      `run --resume <request_id>`"
            .to_string(),
        "evidence" => "`evidence` is now `log <request_id>`".to_string(),
        "allow" => "`allow` is now `rules allow \"<rule>\"`".to_string(),
        "revoke" => "`revoke` is now `rules revoke <n>`".to_string(),
        "refresh" => "`refresh` is now `rules refresh <n>`".to_string(),
        "init" => "`init` is now `doc check --init`".to_string(),
        "diff" | "status" | "export" | "apply" => {
            format!("`{name}` is now `doc {name}`")
        }
        "secure" => "`secure` was removed — Cermet no longer edits your dotfiles".to_string(),
        "git" => "there is no `cermet git`: plain `git push` works on a repo wired by \
                  `connect github` (the installed `git-remote-cermet` helper carries it)"
            .to_string(),
        _ => return None,
    })
}

/// `run <provider>.<action> [...]` — the fused decide-and-execute — or `run --resume <request_id>`.
///
/// The verb is DOTTED because that is how the sentence corpus spells it (`allow vercel.deploy`):
/// one vocabulary, whether you are writing authority or spending it.
fn parse_run(args: &[String]) -> Result<CliCommand, CliError> {
    let mut positionals: Vec<String> = Vec::new();
    let mut resource: Option<String> = None;
    let mut environment: Option<String> = None;
    let mut justification: Option<String> = None;
    let mut ask_only = false;
    let mut retry_effect: Option<String> = None;
    let mut resume: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--resource" => resource = Some(flag_value(&mut it, "--resource")?),
            "--environment" => environment = Some(flag_value(&mut it, "--environment")?),
            "--justification" => justification = Some(flag_value(&mut it, "--justification")?),
            "--ask-only" => ask_only = true,
            // No client-side validation of the handle: the daemon authenticates the lineage and is
            // the only side that may refuse it (one validation per boundary crossing).
            "--retry-effect" => retry_effect = Some(flag_value(&mut it, "--retry-effect")?),
            "--resume" => resume = Some(flag_value(&mut it, "--resume")?),
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("run: unknown flag {flag:?}")));
            }
            pos => positionals.push(pos.to_string()),
        }
    }

    if let Some(request_id) = resume {
        // Approved fields == executed fields: a resume finishes a decision that already froze every
        // field, so there is nothing left to supply. Refusing here is the honest way to say so.
        if !positionals.is_empty()
            || resource.is_some()
            || environment.is_some()
            || justification.is_some()
            || ask_only
            || retry_effect.is_some()
        {
            return Err(CliError::Usage(
                "run --resume <request_id> takes nothing else: the request's fields were frozen \
                 when it was decided"
                    .into(),
            ));
        }
        // `request_id` is the ONE public id. The internal grant handle is refused here with the
        // form that works, rather than sent to the daemon to fail opaquely.
        if request_id.starts_with("grant_") {
            return Err(CliError::Usage(format!(
                "run --resume takes the request_id, not a grant id ({request_id}): pass the \
                 `req_…` the run reported — it is the id for resume and `log <request_id>` alike"
            )));
        }
        return Ok(CliCommand::Resume { request_id });
    }

    // The commonest miss: the sentence corpus writes `vercel.deploy`, so the verb is ONE word.
    if let [provider, action] = positionals.as_slice() {
        return Err(CliError::Usage(format!(
            "run takes one dotted verb, not two words: `run {provider}.{action}`"
        )));
    }
    let verb = one_positional(&positionals, RUN_USAGE)?;
    let (provider, action) = verb.split_once('.').ok_or_else(|| {
        CliError::Usage(format!(
            "run takes one dotted verb, `<provider>.<action>` (e.g. `run vercel.deploy`), got {verb:?}"
        ))
    })?;
    let provider = require_nonempty(provider, "provider")?;
    let action = require_nonempty(action, "action")?;
    let resource = match resource {
        Some(s) => serde_json::from_str(&s)
            .map_err(|e| CliError::Usage(format!("--resource is not valid JSON: {e}")))?,
        None => json!({}),
    };
    Ok(CliCommand::Run {
        provider,
        action,
        resource,
        environment,
        justification,
        ask_only,
        retry_effect,
    })
}

/// `log` in two zoom levels: the receipt list, or one request's verified evidence.
///
/// The list form is WINDOWED by default — the newest [`LOG_DEFAULT_ROWS`] rows — because an
/// unbounded dump is the single largest context cost a caller can hit. `--all` is the full dump;
/// `--since` and `--provider` narrow the log before the window applies.
fn parse_log(args: &[String]) -> Result<CliCommand, CliError> {
    let mut since = None;
    let mut provider = None;
    let mut denied_only = false;
    let mut burned_only = false;
    let mut hops = false;
    let mut all = false;
    let mut positionals: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--since" if since.is_none() => since = Some(flag_value(&mut it, "--since")?),
            "--since" => return Err(CliError::Usage("log accepts --since only once".into())),
            "--provider" if provider.is_none() => {
                provider = Some(flag_value(&mut it, "--provider")?)
            }
            "--provider" => {
                return Err(CliError::Usage("log accepts --provider only once".into()));
            }
            "--denied" => denied_only = true,
            // The same question one layer down: --denied finds what authority refused, --burned
            // finds what it allowed and the effect layer then ended.
            "--burned" => burned_only = true,
            // the relay hop view. Same `--since` bound; `--denied` narrows it to the
            // refusals, which is the same question one flag deeper.
            "--hops" => hops = true,
            "--all" => all = true,
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "log: unexpected {other:?}\n{LOG_USAGE}"
                )));
            }
            pos => positionals.push(pos.to_string()),
        }
    }
    if positionals.is_empty() {
        return Ok(CliCommand::Log {
            since,
            provider,
            denied_only,
            burned_only,
            hops,
            all,
        });
    }
    // The id form is a different question — one request's evidence — so the list-narrowing flags
    // have nothing to narrow, and a second id is two questions.
    if positionals.len() > 1
        || since.is_some()
        || provider.is_some()
        || denied_only
        || burned_only
        || hops
        || all
    {
        return Err(CliError::Usage(format!(
            "log <request_id> renders one request's record as JSON; the list flags \
             narrow the list form.\n{LOG_USAGE}"
        )));
    }
    Ok(CliCommand::Evidence {
        request_id: require_nonempty(&positionals[0], "log <request_id>")?,
    })
}

/// `check [<provider>]` — the read-only plumbing checklist. The document check is `doc check`.
fn parse_check(args: &[String]) -> Result<CliCommand, CliError> {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => Ok(CliCommand::Check { provider: None }),
        [provider] if !provider.starts_with("--") => Ok(CliCommand::Check {
            provider: Some(require_nonempty(provider, "check <provider>")?),
        }),
        ["--fix"] | ["--init"] => Err(CliError::Usage(
            "the CERMET.md document check is `doc check [--fix|--init]`; `check [<provider>]` is \
             the read-only plumbing checklist"
                .into(),
        )),
        _ => Err(CliError::Usage(
            "check takes at most one provider: check [<provider>]".into(),
        )),
    }
}

/// `catalog [--all]` — the two zooms of capability discovery. The zoom is a FLAG, not a
/// filter argument: the projection is the daemon's, and a provider filter here would be a second
/// way to ask a question the terminal's own `grep` already answers.
fn parse_catalog(args: &[String]) -> Result<CliCommand, CliError> {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => Ok(CliCommand::Catalog { all: false }),
        ["--all"] => Ok(CliCommand::Catalog { all: true }),
        _ => Err(CliError::Usage(CATALOG_USAGE.into())),
    }
}

/// `journal` — the status, or the switch. There is no read form: the journal is a plain file, and
/// the status prints its path so the reader's own tools can open it.
fn parse_journal(args: &[String]) -> Result<CliCommand, CliError> {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => Ok(CliCommand::Journal { enabled: None }),
        [switch] => Ok(CliCommand::Journal {
            enabled: Some(parse_switch(switch, "journal")?),
        }),
        _ => Err(CliError::Usage(JOURNAL_USAGE.into())),
    }
}

/// The `rules` noun: the list, plus the three presence-gated mutations of it.
fn parse_rules(args: &[String]) -> Result<CliCommand, CliError> {
    let Some((sub, rest)) = args.split_first() else {
        return Ok(CliCommand::Rules);
    };
    match sub.as_str() {
        "allow" => {
            let (positionals, yes) = yes_flag(rest, "rules allow")?;
            Ok(CliCommand::Allow {
                rule: single_positional(&positionals, "rules allow \"<rule>\" [--yes]")?,
                yes,
            })
        }
        "revoke" => {
            let (positionals, yes) = yes_flag(rest, "rules revoke")?;
            let number = rule_number(
                &single_positional(&positionals, "rules revoke <n> [--yes]")?,
                "revoke",
            )?;
            Ok(CliCommand::Revoke { number, yes })
        }
        "refresh" => {
            let number = rule_number(&single_positional(rest, "rules refresh <n>")?, "refresh")?;
            Ok(CliCommand::Refresh { number })
        }
        other => Err(CliError::Usage(format!(
            "unknown rules subcommand {other:?}\n{RULES_USAGE}"
        ))),
    }
}

/// The `doc` noun: the CERMET.md corpus flow, `check --fix` → `diff` → `apply`.
fn parse_doc(args: &[String]) -> Result<CliCommand, CliError> {
    let Some((sub, rest)) = args.split_first() else {
        return Err(CliError::Usage(DOC_USAGE.into()));
    };
    let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
    match (sub.as_str(), rest.as_slice()) {
        ("check", []) => Ok(CliCommand::DocCheck { fix: false }),
        ("check", ["--fix"]) => Ok(CliCommand::DocCheck { fix: true }),
        // `--init` absorbs the old top-level `init`: creating the document is the first step of
        // preparing it, not a separate verb.
        ("check", ["--init"]) => Ok(CliCommand::Init),
        ("check", _) => Err(CliError::Usage(
            "doc check accepts --fix OR --init, not both and nothing else".into(),
        )),
        ("diff", []) => Ok(CliCommand::Diff),
        ("status", []) => Ok(CliCommand::Status { as_json: false }),
        ("status", ["--json"]) => Ok(CliCommand::Status { as_json: true }),
        ("export", []) => Ok(CliCommand::Export {
            replace_draft: false,
        }),
        ("export", ["--replace-draft"]) => Ok(CliCommand::Export {
            replace_draft: true,
        }),
        // `doc apply` takes at most ONE positional: the document to apply. With none it discovers
        // this repository's CERMET.md, exactly as before.
        ("apply", arguments) => {
            let mut replace_live = false;
            let mut recover = false;
            let mut file: Option<String> = None;
            for argument in arguments {
                match *argument {
                    "--replace-live" if !replace_live => replace_live = true,
                    "--recover" if !recover => recover = true,
                    other if other.starts_with("--") => {
                        return Err(CliError::Usage(format!(
                            "doc apply: unexpected argument {other:?}; expected only \
                             --replace-live or --recover, once each"
                        )));
                    }
                    positional if file.is_none() => {
                        file = Some(require_nonempty(positional, "doc apply <file>")?)
                    }
                    _ => {
                        return Err(CliError::Usage(format!(
                            "doc apply takes at most one document\n{DOC_USAGE}"
                        )));
                    }
                }
            }
            Ok(CliCommand::Apply {
                file,
                replace_live,
                recover,
            })
        }
        ("diff" | "status" | "export", _) => Err(CliError::Usage(format!(
            "doc {sub}: unexpected arguments\n{DOC_USAGE}"
        ))),
        (other, _) => Err(CliError::Usage(format!(
            "unknown doc subcommand {other:?}\n{DOC_USAGE}"
        ))),
    }
}

/// The `preset` noun: the stored profiles — listed, installed, or written back out.
///
/// A BARE `preset` prints usage rather than guessing: there is no form that applies the document
/// you are standing in, because that is already `doc apply`.
fn parse_preset(args: &[String]) -> Result<CliCommand, CliError> {
    let Some((sub, rest)) = args.split_first() else {
        return Err(CliError::Usage(PRESET_USAGE.into()));
    };
    match sub.as_str() {
        "list" if rest.is_empty() => return Ok(CliCommand::Preset(preset::PresetCommand::List)),
        "list" => {
            return Err(CliError::Usage(format!(
                "preset list takes no arguments\n{PRESET_USAGE}"
            )))
        }
        "export" => return parse_preset_export(rest),
        flag if flag.starts_with("--") => {
            return Err(CliError::Usage(format!(
                "preset: expected `list`, `export`, or a profile name, got {flag:?}\n{PRESET_USAGE}"
            )))
        }
        _ => {}
    }
    // `--recover` is `doc apply`'s, because the ceremony IS `doc apply`'s. `--replace-live` is
    // absent: it acknowledges a pin marker naming a different live generation, and a profile —
    // which is derived from no generation — carries no marker to acknowledge.
    let mut recover = false;
    for flag in rest {
        match flag.as_str() {
            "--recover" if !recover => recover = true,
            other => {
                return Err(CliError::Usage(format!(
                    "preset: unexpected argument {other:?}; expected only --recover\n{PRESET_USAGE}"
                )));
            }
        }
    }
    Ok(CliCommand::Preset(preset::PresetCommand::Apply {
        name: preset_name(sub)?,
        recover,
    }))
}

/// `preset export <name> [<path>] [--force]`.
fn parse_preset_export(args: &[String]) -> Result<CliCommand, CliError> {
    let mut positionals: Vec<String> = Vec::new();
    let mut force = false;
    for argument in args {
        match argument.as_str() {
            "--force" if !force => force = true,
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "preset export: unexpected argument {other:?}\n{PRESET_USAGE}"
                )));
            }
            positional => positionals.push(positional.to_string()),
        }
    }
    let (name, path) = match positionals.as_slice() {
        [name] => (preset_name(name)?, None),
        [name, path] => (
            preset_name(name)?,
            Some(require_nonempty(path, "preset export <path>")?),
        ),
        _ => {
            return Err(CliError::Usage(format!(
                "preset export <name> [<path>] [--force]\n{PRESET_USAGE}"
            )));
        }
    };
    Ok(CliCommand::Preset(preset::PresetCommand::Export {
        name,
        path,
        force,
    }))
}

/// Validate a profile name at PARSE time — the same alphabet the daemon enforces. A name it would
/// refuse then never reaches a ceremony, and the refusal never echoes the raw bytes it was given.
fn preset_name(raw: &str) -> Result<String, CliError> {
    let name = require_nonempty(raw, "preset <name>")?;
    // One spelling of the rule: the refusal is the validator's own, so a name refused here reads
    // the same as one refused at ingest or by the daemon.
    match preset::validate_name(&name) {
        Ok(()) => Ok(name),
        Err(reason) => Err(CliError::Usage(format!("preset: {reason}"))),
    }
}

fn parse_owner(args: &[String]) -> Result<CliCommand, CliError> {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["status"] => Ok(CliCommand::OwnerStatus),
        ["lockdown"] => Ok(CliCommand::OwnerLockdown),
        ["lockdown", "clear"] => Ok(CliCommand::OwnerLockdownClear),
        _ => Err(CliError::Usage(format!(
            "owner expects `status`, `lockdown`, or `lockdown clear`\n{OWNER_USAGE}"
        ))),
    }
}

/// Split the global `--socket <path>` out of argv, returning `(socket_override, remaining_args)`.
/// A dangling trailing `--socket` is dropped; the command parse then fails with usage.
pub fn split_socket_flag(args: &[String]) -> (Option<String>, Vec<String>) {
    let mut socket = None;
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--socket" => {
                if let Some(p) = it.next() {
                    socket = Some(p.clone());
                }
            }
            _ => rest.push(a.clone()),
        }
    }
    (socket, rest)
}

fn parse_artifact(args: &[String]) -> Result<CliCommand, CliError> {
    let mut positionals: Vec<String> = Vec::new();
    let mut range: Option<String> = None;
    let mut path: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--range" => range = Some(flag_value(&mut it, "--range")?),
            "--path" => path = Some(flag_value(&mut it, "--path")?),
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("artifact: unknown flag {flag:?}")));
            }
            pos => positionals.push(pos.to_string()),
        }
    }
    let handle = one_positional(&positionals, ARTIFACT_USAGE)?;
    if range.is_some() && path.is_some() {
        return Err(CliError::Usage(
            "artifact takes --range OR --path, not both".to_string(),
        ));
    }
    let range = match range {
        Some(s) => Some(parse_range(&s)?),
        None => None,
    };
    let path = match path {
        Some(p) => Some(parse_artifact_path(&p)?),
        None => None,
    };
    Ok(CliCommand::Artifact {
        handle,
        range,
        path,
    })
}

/// Validate a `$.seg(.seg)*` capture-pointer client-side (same grammar as the template `capture`
/// lookup): it must start `$.` and every dot-segment must be non-empty. A malformed pointer is a
/// usage error that never reaches the host.
fn parse_artifact_path(p: &str) -> Result<String, CliError> {
    let rest = p.strip_prefix("$.").ok_or_else(|| {
        CliError::Usage(format!(
            "--path must be a capture-pointer like '$.a.b', got {p:?}"
        ))
    })?;
    if rest.is_empty() || rest.split('.').any(|s| s.is_empty()) {
        return Err(CliError::Usage(format!(
            "--path segments must be non-empty (e.g. '$.a.b'), got {p:?}"
        )));
    }
    Ok(p.to_string())
}

/// `connect <provider> [account_label] [--replace] [--adopt]`.
fn parse_connect(args: &[String]) -> Result<CliCommand, CliError> {
    let mut positionals: Vec<String> = Vec::new();
    let mut replace = false;
    let mut adopt = false;
    for a in args {
        match a.as_str() {
            "--replace" => replace = true,
            "--adopt" => adopt = true,
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("connect: unknown flag {flag:?}")));
            }
            pos => positionals.push(pos.to_string()),
        }
    }
    let (provider, account_label) = match positionals.as_slice() {
        [p] => (require_nonempty(p, "connect <provider>")?, None),
        [p, label] => (
            require_nonempty(p, "connect <provider>")?,
            Some(require_nonempty(label, "connect <account_label>")?),
        ),
        _ => {
            return Err(CliError::Usage(
                "connect <provider> [account_label] [--replace] [--adopt]".to_string(),
            ));
        }
    };
    Ok(CliCommand::Connect(connect::ConnectArgs {
        provider,
        account_label,
        replace,
        adopt,
    }))
}

/// `update [--check]`, plus the two privileged halves — one per install channel.
///
/// None of the forms mix: `--apply` (tarball) and `--apply-deb` (package) finish an update whose
/// bytes are already downloaded and verified, so there is nothing left to check, and a box has one
/// channel so it can never need both.
fn parse_update(args: &[String]) -> Result<CliCommand, CliError> {
    let mut check = false;
    let mut daily_check = false;
    let mut daily: Option<bool> = None;
    let mut apply: Option<String> = None;
    let mut apply_deb: Option<String> = None;
    let mut sha256: Option<String> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--check" if !check => check = true,
            "--daily-check" if !daily_check => daily_check = true,
            "--daily" if daily.is_none() => {
                daily = Some(parse_switch(
                    &flag_value(&mut it, "--daily")?,
                    "update --daily",
                )?)
            }
            "--apply" if apply.is_none() => apply = Some(flag_value(&mut it, "--apply")?),
            "--apply-deb" if apply_deb.is_none() => {
                apply_deb = Some(flag_value(&mut it, "--apply-deb")?)
            }
            "--sha256" if sha256.is_none() => sha256 = Some(flag_value(&mut it, "--sha256")?),
            other => {
                return Err(CliError::Usage(format!(
                    "update: unexpected {other:?}\n{UPDATE_USAGE}"
                )));
            }
        }
    }
    // The scheduled check and the knob are each a whole command. Mixing either with the typed
    // install, with `--check`, or with a privileged half asks for two different things at once,
    // and guessing which was meant is exactly what a fail-closed parser must not do.
    let solitary = [
        ("--daily-check", daily_check),
        ("--daily", daily.is_some()),
        ("--check", check),
        ("--apply", apply.is_some()),
        ("--apply-deb", apply_deb.is_some()),
        ("--sha256", sha256.is_some()),
    ];
    let named: Vec<&str> = solitary
        .iter()
        .filter(|(_, present)| *present)
        .map(|(name, _)| *name)
        .collect();
    if (daily_check || daily.is_some()) && named.len() > 1 {
        return Err(CliError::Usage(format!(
            "update: {} name different commands; run one at a time\n{UPDATE_USAGE}",
            named.join(" and ")
        )));
    }
    if daily_check {
        return Ok(CliCommand::UpdateDailyCheck);
    }
    if let Some(enabled) = daily {
        return Ok(CliCommand::UpdateDaily { enabled });
    }
    // The two privileged halves are two different commands: one publishes a staged binary, the
    // other hands a package to dpkg. Neither is completable with the other's arguments.
    if apply.is_some() && apply_deb.is_some() {
        return Err(CliError::Usage(
            "update: --apply and --apply-deb are the two install channels' privileged halves; a box has one channel"
                .into(),
        ));
    }
    if check && (apply.is_some() || apply_deb.is_some()) {
        return Err(CliError::Usage(
            "update --apply/--apply-deb finishes an update whose bytes are already verified; \
             there is nothing left for --check to report"
                .into(),
        ));
    }
    if let Some(package) = apply_deb {
        let sha256 = sha256.ok_or_else(|| {
            CliError::Usage(
                "update --apply-deb needs the --sha256 the package was verified against".into(),
            )
        })?;
        return Ok(CliCommand::UpdateApplyDeb {
            package,
            sha256: require_sha256(&sha256, "update --apply-deb --sha256")?,
        });
    }
    if let Some(digest) = apply {
        return Ok(CliCommand::UpdateApply {
            sha256: require_sha256(&digest, "update --apply")?,
        });
    }
    if sha256.is_some() {
        return Err(CliError::Usage(
            "update --sha256 belongs to --apply-deb; on its own it names nothing to install".into(),
        ));
    }
    Ok(CliCommand::Update { check })
}

/// `on` / `off`, and nothing else. A knob whose value is a guess is not a knob: an operator who
/// types `--daily true` gets told the two words that exist rather than a silent interpretation.
fn parse_switch(value: &str, what: &str) -> Result<bool, CliError> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(CliError::Usage(format!(
            "{what}: {other:?} is neither \"on\" nor \"off\""
        ))),
    }
}

/// A digest is validated at PARSE time, like every other explicit value: a malformed one can then
/// never reach the privileged path, where its only possible effect is a confusing mismatch.
fn require_sha256(value: &str, what: &str) -> Result<String, CliError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CliError::Usage(format!(
            "{what} takes a 64-character lowercase sha256, got {value:?}"
        )));
    }
    Ok(value.to_string())
}

/// `mcp install [--client claude|opencode] [--sock <p>] [--binary <p>] [--name <n>] [--guidance|--no-guidance] [--force]`.
fn parse_mcp(args: &[String]) -> Result<CliCommand, CliError> {
    // The binary front-end intercepts bare `cermet mcp` as the stdio bridge. Parsing owns only the
    // daemon-backed registration form.
    let (sub, rest) = args.split_first().ok_or_else(|| {
        CliError::Usage("incomplete command: did you mean `cermet mcp install`?".into())
    })?;
    if sub != "install" {
        return Err(CliError::Usage(format!(
            "unknown mcp subcommand {sub:?} (install)"
        )));
    }
    let mut sock = None;
    let mut binary = None;
    let mut name = "cermet".to_string();
    let mut guidance = None;
    let mut force = false;
    let mut client = mcp::McpClient::Claude;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--client" => {
                let v = flag_value(&mut it, "--client")?;
                client = match v.as_str() {
                    "claude" => mcp::McpClient::Claude,
                    "opencode" => mcp::McpClient::OpenCode,
                    other => {
                        return Err(CliError::Usage(format!(
                            "--client must be 'claude' or 'opencode', got {other:?}"
                        )));
                    }
                };
            }
            "--sock" => sock = Some(flag_value(&mut it, "--sock")?),
            "--binary" => binary = Some(flag_value(&mut it, "--binary")?),
            "--name" => name = flag_value(&mut it, "--name")?,
            // `--name=<value>` spelling: keep the raw value so `run_mcp_install`'s identifier
            // check can refuse a leading-dash name.
            other if other.starts_with("--name=") => {
                name = other.trim_start_matches("--name=").to_string()
            }
            "--guidance" => guidance = Some(true),
            "--no-guidance" => guidance = Some(false),
            // The explicit operator override: repoint even when the daemon is unreachable, or the
            // quiesce barrier reports an orphan-ambiguous / integrity / drain-timeout state — install
            // refuses all of these by default (fail closed), warning an agent-side child may survive.
            "--force" => force = true,
            other => {
                return Err(CliError::Usage(format!(
                    "mcp install: unexpected {other:?}"
                )));
            }
        }
    }
    Ok(CliCommand::McpInstall(mcp::McpInstallArgs {
        sock,
        binary,
        name,
        guidance,
        force,
        client,
    }))
}

/// Parse `<unit>:<start>[-<end>]` (unit = lines|bytes) into an [`ArtifactRange`]: a malformed range
/// is a usage error that NEVER reaches the host.
fn parse_range(s: &str) -> Result<ArtifactRange, CliError> {
    let (unit, span) = s.split_once(':').ok_or_else(|| {
        CliError::Usage(format!("--range must be <unit>:<start>[-<end>], got {s:?}"))
    })?;
    if unit != "lines" && unit != "bytes" {
        return Err(CliError::Usage(format!(
            "--range unit must be 'lines' or 'bytes', got {unit:?}"
        )));
    }
    if span.is_empty() {
        return Err(CliError::Usage(
            "--range needs a start: <unit>:<start>[-<end>]".to_string(),
        ));
    }
    let (start_s, end_s) = match span.split_once('-') {
        Some((a, b)) => (a, Some(b)),
        None => (span, None),
    };
    let start = start_s
        .parse::<u64>()
        .map_err(|_| CliError::Usage(format!("--range start is not a number: {start_s:?}")))?;
    let end = match end_s {
        Some(b) if !b.is_empty() => Some(
            b.parse::<u64>()
                .map_err(|_| CliError::Usage(format!("--range end is not a number: {b:?}")))?,
        ),
        _ => None,
    };
    // Reject the semantically invalid CLIENT-side rather than forward a degenerate range the
    // daemon silently clamps. Lines are 1-based (bytes are 0-based); when both endpoints are
    // present the span must not be reversed. No invented caps — a huge-but-ordered span is valid.
    if unit == "lines" && start == 0 {
        return Err(CliError::Usage(
            "--range lines are 1-based: start at lines:1, not lines:0".to_string(),
        ));
    }
    if let Some(e) = end {
        if e < start {
            return Err(CliError::Usage(format!(
                "--range end ({e}) must be >= start ({start})"
            )));
        }
    }
    Ok(ArtifactRange {
        unit: unit.to_string(),
        start,
        end,
    })
}

/// An EXPLICIT value must be non-empty after trim.
/// Enforced at PARSE time on every positional and flag value — before any I/O and structurally
/// before any presence prompt (the `CliCommand` is never constructed, so the gate can never fire on
/// an invalid id/name/path). Returns the trimmed value.
fn require_nonempty(value: &str, what: &str) -> Result<String, CliError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CliError::Usage(format!(
            "{what} must not be empty (explicit empty/whitespace values are refused)"
        )));
    }
    Ok(trimmed.to_string())
}

fn flag_value(it: &mut std::slice::Iter<'_, String>, flag: &str) -> Result<String, CliError> {
    let v = it
        .next()
        .cloned()
        .ok_or_else(|| CliError::Usage(format!("{flag} needs a value")))?;
    require_nonempty(&v, flag)
}

/// Split `--yes` out of a rules mutation's arguments (it skips only the CLI-side confirm; the
/// presence gate still governs).
fn yes_flag(args: &[String], what: &str) -> Result<(Vec<String>, bool), CliError> {
    let mut yes = false;
    let mut positionals = Vec::new();
    for a in args {
        match a.as_str() {
            "--yes" => yes = true,
            other if other.starts_with("--") => {
                return Err(CliError::Usage(format!("{what}: unknown flag {other:?}")));
            }
            _ => positionals.push(a.clone()),
        }
    }
    Ok((positionals, yes))
}

fn rule_number(raw: &str, what: &str) -> Result<usize, CliError> {
    let number = raw.parse::<usize>().map_err(|_| {
        CliError::Usage(format!(
            "rules {what} expects a one-based rule number, got {raw:?}"
        ))
    })?;
    if number == 0 {
        return Err(CliError::Usage(format!(
            "rules {what} expects a one-based rule number (1 or greater)"
        )));
    }
    Ok(number)
}

fn single_positional(args: &[String], usage: &str) -> Result<String, CliError> {
    match args {
        [one] if !one.starts_with("--") => require_nonempty(one, usage),
        _ => Err(CliError::Usage(usage.to_string())),
    }
}

fn one_positional(positionals: &[String], usage: &str) -> Result<String, CliError> {
    match positionals {
        [one] => require_nonempty(one, usage),
        _ => Err(CliError::Usage(usage.to_string())),
    }
}

fn no_args(args: &[String], cmd: &str) -> Result<(), CliError> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(CliError::Usage(format!("{cmd} takes no arguments")))
    }
}
