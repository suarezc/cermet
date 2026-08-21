//! The operator CLI's own output journal: one JSON line per `cermet` invocation, appended to a
//! local file, recording what the command printed.
//!
//! # Why it exists
//!
//! Most of what this CLI says is said once and then lives only in a terminal's scrollback: a
//! ceremony's review text, the confirmation a human declined, a deny's widening suggestion, a
//! `check` row. `cermet log` is the broker's receipt of what was DECIDED — it is not a record of
//! what the terminal was told, and a ceremony that was declined never reaches it at all, because
//! nothing was decided. A reader arriving later with no session context (usually an agent) has, for
//! that whole class of output, nothing to read. This file is that missing record.
//!
//! It is an operator CONVENIENCE, not an audit surface. The CLI writes it about itself, it is not
//! hash-chained, and nothing reads it back to make a decision. The audit surfaces are the daemon's:
//! `cermet log`, `cermet audit-verify`.
//!
//! Reading it is not a `cermet` command — it is a plain JSONL file. `cermet journal` prints its
//! path so it can be read with `tail`, `grep` or `jq`.
//!
//! # What is captured, and what cannot be
//!
//! Output only, at the file-descriptor level. Most of this CLI's output goes through plain
//! `println!`/`eprintln!` rather than any single seam, so the capture is process-level: descriptors
//! 1 and 2 are routed through pipes drained by in-process tee threads that forward every byte to the
//! real descriptors and accumulate a bounded copy. Descriptor 0 is never touched, so INPUT is not
//! captured by construction — the echo-suppressed secret prompt in `connect` reads from stdin and
//! can therefore never appear here, whatever the prompt around it prints.
//!
//! Only the operator CLI role journals. The daemon and git's remote helper are separate roles and
//! never reach this code; the `cermet mcp` stdio server is not, so it is excluded explicitly in
//! [`crate::entry::run`] — its stdout IS the agent protocol channel, and its traffic already has
//! receipts.
//!
//! That exclusion is by SHAPE, not by outcome: any invocation the bridge front-end claims is
//! skipped, including `cermet mcp <typo>`, which the front-end answers with a CLI usage error and
//! no protocol session at all. So a mistyped `mcp` subcommand goes unrecorded. That is a known,
//! accepted gap and not worth a branch to close: the invocation is one word, the refusal it gets
//! names the two forms that exist, and it is the operator's own typo rather than output that
//! exists nowhere else. Deciding by shape keeps ONE rule in front of the protocol channel; deciding
//! by outcome would mean knowing whether a session started before choosing to capture its stdout.
//!
//! Best effort throughout: if the plumbing cannot be established, the command runs UN-journaled
//! rather than failing. A record of what happened must never be able to stop what happens.

use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{CliError, CliOutput};

/// The most output bytes ONE entry stores.
///
/// Deliberately small, because the two kinds of output have opposite shapes. DERIVED REPRINTS —
/// `log`, `catalog`, `rules` dumps — re-render stores that already exist durably elsewhere and grow
/// without bound; journaling them whole would grow this file in proportion to a store it duplicates,
/// and the original is one command away. UNIQUE content — a ceremony's review text, a refusal, a
/// status line, the reason a command declined — is small, and always fits. So the cap costs the
/// reader nothing they cannot get elsewhere, and the file stays cheap enough to leave on by default.
pub const OUTPUT_CAP_BYTES: usize = 4096;

/// Rotate the whole file once it passes this size. One generation is kept, no compression, no
/// background work: rotation is a `rename` performed by the invocation that noticed.
pub const ROTATE_BYTES: u64 = 32 * 1024 * 1024;

/// How the rotation threshold is spelled on the operator surface.
const ROTATE_HUMAN: &str = "32 MiB";

/// The journal's file name inside the state directory, and the one kept generation's.
const FILE_NAME: &str = "journal.jsonl";

// ---- where it lives ---------------------------------------------------------------------------

/// `$XDG_STATE_HOME/cermet/journal.jsonl`, defaulting to `~/.local/state/cermet/journal.jsonl`.
///
/// The state directory is the right one by the XDG definition — state is data that persists between
/// runs, is not configuration, and is not important enough to back up. `None` when neither variable
/// gives an absolute directory, in which case nothing is journaled.
pub fn journal_path() -> Option<PathBuf> {
    journal_path_in(
        std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
    )
}

/// The resolution, taking both directories as parameters so it is testable without the process
/// environment. A relative `$XDG_STATE_HOME` is ignored, as the specification requires.
pub fn journal_path_in(state_home: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    let base = state_home.filter(|path| path.is_absolute()).or_else(|| {
        home.filter(|path| !path.as_os_str().is_empty())
            .map(|home| home.join(".local").join("state"))
    })?;
    Some(base.join("cermet").join(FILE_NAME))
}

/// The one kept generation, beside the journal: `journal.jsonl.1`.
pub fn previous_path(journal: &Path) -> PathBuf {
    let mut name = journal.as_os_str().to_os_string();
    name.push(".1");
    PathBuf::from(name)
}

// ---- the entry --------------------------------------------------------------------------------

/// What a run printed: the first [`OUTPUT_CAP_BYTES`] bytes, plus how many there were in all.
#[derive(Debug, Default)]
pub struct Captured {
    kept: Vec<u8>,
    total: usize,
}

impl Captured {
    /// Accumulate one write. Everything past the cap is counted and dropped — the kept bytes are
    /// the FIRST ones, and nothing is ever appended to them.
    pub fn push(&mut self, bytes: &[u8]) {
        self.total += bytes.len();
        let room = OUTPUT_CAP_BYTES.saturating_sub(self.kept.len());
        if room > 0 {
            self.kept.extend_from_slice(&bytes[..room.min(bytes.len())]);
        }
    }

    pub fn kept(&self) -> &[u8] {
        &self.kept
    }

    pub fn total(&self) -> usize {
        self.total
    }

    fn was_truncated(&self) -> bool {
        self.total > self.kept.len()
    }
}

/// One journal line, newline included.
///
/// The truncation is expressed by the `truncated` field and NOWHERE else: no inline marker is
/// appended to `output`, so a reader who wants the first bytes verbatim gets exactly them, and a
/// reader who wants to know whether more existed reads one field.
pub fn entry_line(
    ts: &str,
    argv: &[String],
    cwd: &Path,
    exit: u8,
    duration_ms: u64,
    captured: &Captured,
) -> String {
    let mut entry = serde_json::json!({
        "ts": ts,
        "argv": argv,
        "cwd": cwd.to_string_lossy(),
        "exit": exit,
        "duration_ms": duration_ms,
        "output": String::from_utf8_lossy(captured.kept()),
    });
    if captured.was_truncated() {
        entry["truncated"] = serde_json::json!({
            "kept": captured.kept.len(),
            "total": captured.total,
        });
    }
    format!("{entry}\n")
}

/// Append one line, rotating the file first if this write would land in an oversized journal.
///
/// Everything here is the operator's alone: the file is `0600`, the directories the journal brings
/// into being are `0700`, and nothing in the journal's own path is followed ([`refuse_symlink`]).
pub fn append_entry(journal: &Path, line: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = journal.parent() {
        refuse_symlink(parent)?;
        create_private_dirs(parent)?;
    }
    if matches!(std::fs::metadata(journal), Ok(meta) if meta.len() > ROTATE_BYTES) {
        let previous = previous_path(journal);
        refuse_symlink(&previous)?;
        std::fs::rename(journal, previous)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        // The same refusal as `refuse_symlink`, expressed as the flag the syscall itself carries —
        // so there is no window between a check and the open for a link to be swapped in.
        .custom_flags(libc::O_NOFOLLOW)
        .open(journal)?
        .write_all(line.as_bytes())
}

/// Refuse a path that is a symlink.
///
/// The adversary is a peer uid on the box. The journal lives under a directory the operator owns,
/// but on a machine whose umask left `~/.local/state` group- or world-writable a peer could
/// pre-place `journal.jsonl` — or the `cermet` directory holding it, or the generation a rotation
/// is about to rename onto — as a symlink pointing somewhere they can read, and every command's
/// output would be copied there. One rule covers all of it: nothing in the journal's own path is
/// followed. The file's `open` carries `O_NOFOLLOW`, which refuses atomically; a directory and a
/// rename target have no open to hang that flag on, so they are inspected with `symlink_metadata`,
/// which does not follow either.
///
/// A refusal costs this invocation its entry and nothing else — the caller treats every error here
/// as "run un-journaled".
fn refuse_symlink(path: &Path) -> std::io::Result<()> {
    if matches!(std::fs::symlink_metadata(path), Ok(meta) if meta.is_symlink()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is a symlink; refusing to journal through it",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Create `dir` and any missing ancestors, `0700`.
///
/// `create_dir_all` applies the ambient umask, which under `umask 000` would leave every command's
/// output world-readable. Two halves, deliberately:
///
/// * A directory this call BRINGS INTO BEING is created `0700` outright.
/// * A directory that already exists is left exactly as the operator has it — `~/.local/state` is
///   theirs and holds other programs' state, and writing a journal entry is not a licence to
///   re-permission it. The one exception is the `cermet` leaf, which IS ours: it is tightened
///   whether this run created it or an earlier one did.
fn create_private_dirs(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let mut missing: Vec<&Path> = Vec::new();
    for ancestor in dir.ancestors() {
        if ancestor.is_dir() {
            break;
        }
        missing.push(ancestor);
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    // Outermost first: a parent has to exist before its child can be made.
    for path in missing.iter().rev() {
        builder.create(path)?;
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

// ---- the capture ------------------------------------------------------------------------------

/// How long [`Capture::finish`] waits for the two tee threads to reach EOF before writing the entry
/// anyway.
///
/// Restoring the real descriptors normally closes the last reference to each pipe's write end, so
/// EOF is immediate. It would NOT be if some future code path left a detached child holding an
/// inherited descriptor 1 or 2 — and an unbounded wait there would hang the CLI forever rather than
/// merely lose a journal entry. The whole point of this file is that recording what happened can
/// never change what happens, so the wait is bounded and a timeout simply records what was
/// accumulated so far.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// A live capture: the saved real descriptors, the channel the tee threads report EOF on, and the
/// bounded accumulator they share. Ended by [`Capture::finish`].
pub struct Capture {
    saved_stdout: RawFd,
    saved_stderr: RawFd,
    drained: std::sync::mpsc::Receiver<()>,
    tees: usize,
    captured: Arc<Mutex<Captured>>,
    started: std::time::Instant,
    journal: PathBuf,
}

/// Begin capturing, or don't. `None` — journaling off, no resolvable path, or plumbing that could
/// not be established — means this invocation simply runs un-journaled.
pub fn start() -> Option<Capture> {
    if !enabled() {
        return None;
    }
    let journal = journal_path()?;
    let captured = Arc::new(Mutex::new(Captured::default()));
    let started = std::time::Instant::now();

    let saved_stdout = dup(libc::STDOUT_FILENO)?;
    let Some(saved_stderr) = dup(libc::STDERR_FILENO) else {
        close(saved_stdout);
        return None;
    };
    let (drained_tx, drained) = std::sync::mpsc::channel();
    if !tee(
        libc::STDOUT_FILENO,
        saved_stdout,
        &captured,
        drained_tx.clone(),
    ) {
        restore(saved_stdout, saved_stderr);
        return None;
    }
    if !tee(libc::STDERR_FILENO, saved_stderr, &captured, drained_tx) {
        // Descriptor 1 is already a pipe; restoring it closes that pipe's write end, which is what
        // ends the tee already running behind it.
        restore(saved_stdout, saved_stderr);
        return None;
    }

    Some(Capture {
        saved_stdout,
        saved_stderr,
        drained,
        tees: 2,
        captured,
        started,
        journal,
    })
}

impl Capture {
    /// Restore the real descriptors, collect what was printed, and append the entry.
    ///
    /// Restoring is what ENDS the capture: `dup2`ing the saved descriptors back over 1 and 2 closes
    /// the last references to the pipes' write ends, the tee threads read EOF, and each reports it
    /// once every byte it forwarded has also been accumulated. That wait is bounded by
    /// [`DRAIN_TIMEOUT`].
    pub fn finish(self, argv: &[String], exit: u8) {
        // A `print!` with no trailing newline is still sitting in the standard library's buffer,
        // which is flushed after `main` returns — that is, after the descriptors are restored. Flush
        // it here so it is both forwarded and captured.
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        let duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        restore(self.saved_stdout, self.saved_stderr);
        let deadline = std::time::Instant::now() + DRAIN_TIMEOUT;
        for _ in 0..self.tees {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if self.drained.recv_timeout(remaining).is_err() {
                break;
            }
        }

        let captured = self
            .captured
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default();
        let cwd = std::env::current_dir().unwrap_or_default();
        let line = entry_line(&ts, argv, &cwd, exit, duration_ms, &captured);
        // Best effort: an unwritable journal must never change what the command did.
        let _ = append_entry(&self.journal, &line);
    }
}

/// May this invocation journal? A settings file that does not parse reads as NO — a file the
/// operator has to fix by hand is not a file to guess an answer out of, and the conservative guess
/// for a recording switch is off.
fn enabled() -> bool {
    matches!(
        crate::settings::read_journal(&crate::settings::config_path()),
        Ok(true)
    )
}

/// Route `target` (1 or 2) through a fresh pipe, and spawn the thread that drains it: every byte
/// goes to `sink` — the saved real descriptor — and into the shared accumulator. `drained` reports
/// EOF once, after the last accumulated byte. Returns whether the plumbing was established.
fn tee(
    target: RawFd,
    sink: RawFd,
    captured: &Arc<Mutex<Captured>>,
    drained: std::sync::mpsc::Sender<()>,
) -> bool {
    let mut ends = [0 as RawFd; 2];
    // SAFETY: `pipe` writes two descriptors into the provided two-element array and reports failure
    // through its return value.
    if unsafe { libc::pipe(ends.as_mut_ptr()) } != 0 {
        return false;
    }
    let (read_end, write_end) = (ends[0], ends[1]);
    // The thread owns its own copy of the sink: `finish` needs the saved descriptor to restore with,
    // and a thread that closed it out from under that would leave the terminal disconnected.
    let Some(sink) = dup(sink) else {
        close(read_end);
        close(write_end);
        return false;
    };
    // SAFETY: `dup2` replaces `target` with a duplicate of the pipe's write end; the original write
    // end is then redundant, so `target` holds the only reference to it and closing `target` (which
    // `restore` does) is what ends the capture.
    if unsafe { libc::dup2(write_end, target) } < 0 {
        close(read_end);
        close(write_end);
        close(sink);
        return false;
    }
    close(write_end);

    let captured = Arc::clone(captured);
    std::thread::spawn(move || {
        // SAFETY: both descriptors were created or duplicated above and are owned by this thread
        // alone; wrapping them in `File` gives them a drop that closes them exactly once.
        let (mut source, mut sink) = unsafe {
            (
                std::fs::File::from_raw_fd(read_end),
                std::fs::File::from_raw_fd(sink),
            )
        };
        let mut buffer = [0u8; 8192];
        loop {
            match source.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    let bytes = &buffer[..read];
                    // Forward FIRST: the operator's terminal is the point of the output; the
                    // journal is a copy of it.
                    let _ = sink.write_all(bytes);
                    captured
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(bytes);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        // Reported only here, after the last byte is in the accumulator: receiving it is what makes
        // reading the accumulator safe.
        let _ = drained.send(());
    });
    true
}

/// Put the real descriptors back on 1 and 2, closing the saved copies (and, with them, the last
/// references to the pipes).
fn restore(saved_stdout: RawFd, saved_stderr: RawFd) {
    // SAFETY: both descriptors are ones this module duplicated and still owns.
    unsafe {
        libc::dup2(saved_stdout, libc::STDOUT_FILENO);
        libc::dup2(saved_stderr, libc::STDERR_FILENO);
    }
    close(saved_stdout);
    close(saved_stderr);
}

fn dup(fd: RawFd) -> Option<RawFd> {
    // SAFETY: `dup` reads one descriptor number and reports failure as a negative return.
    let duplicate = unsafe { libc::dup(fd) };
    (duplicate >= 0).then_some(duplicate)
}

fn close(fd: RawFd) {
    // SAFETY: every descriptor closed here was opened or duplicated by this module and is closed
    // exactly once.
    unsafe {
        libc::close(fd);
    }
}

// ---- the `journal` command --------------------------------------------------------------------

/// `cermet journal` — what the journal is doing, where it is, and what bounds it.
pub fn run_status(config: &Path) -> Result<CliOutput, CliError> {
    let enabled = crate::settings::read_journal(config)?;
    Ok(CliOutput {
        text: status_text(enabled, config, journal_path().as_deref()),
        ok: true,
    })
}

/// `cermet journal on|off` — persist the switch in the operator's own settings file.
pub fn run_setting(config: &Path, enabled: bool) -> Result<CliOutput, CliError> {
    crate::settings::write_journal(config, enabled)?;
    Ok(CliOutput {
        text: status_text(enabled, config, journal_path().as_deref()),
        ok: true,
    })
}

fn status_text(enabled: bool, config: &Path, journal: Option<&Path>) -> String {
    let switch = if enabled { "enabled" } else { "disabled" };
    let value = if enabled { "on" } else { "off" };
    let opposite = if enabled { "off" } else { "on" };
    format!(
        "output journal: {switch}\n\
         file: {file}\n\
         setting: {config} (journal = \"{value}\")\n\
         Every `cermet` command appends one JSON line here: when it ran, its arguments, the \
         directory it ran in, its exit code, how long it took, and the first {OUTPUT_CAP_BYTES} \
         bytes of what it printed. Output past that is counted, not stored — long renders like \
         `log` and `catalog` re-read stores that already exist, and the output that exists nowhere \
         else (a ceremony's review text, a refusal, a status line) is short. Nothing typed is \
         recorded: only what was printed is.\n\
         The file rotates whole at {ROTATE_HUMAN}, keeping ONE previous generation beside it as \
         `journal.jsonl.1`.\n\
         It is a local convenience record, not the audit log — read it with your own tools (`tail \
         -n1`, `jq`), and use `cermet log` for the broker's receipts.\n\
         Change it: cermet journal {opposite}",
        file = describe_file(journal),
        config = config.display(),
    )
}

/// The journal's path plus how big it is right now — or why there is no path at all.
fn describe_file(journal: Option<&Path>) -> String {
    let Some(journal) = journal else {
        return "(nowhere: neither $XDG_STATE_HOME nor $HOME names a directory, so nothing is \
                journaled)"
            .to_string();
    };
    match std::fs::metadata(journal) {
        Ok(meta) => format!("{} ({})", journal.display(), human_size(meta.len())),
        Err(_) => format!("{} (not written yet)", journal.display()),
    }
}

fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| part.to_string()).collect()
    }

    fn parsed(line: &str) -> serde_json::Value {
        assert!(line.ends_with('\n'), "an entry is ONE line: {line:?}");
        assert_eq!(
            line.matches('\n').count(),
            1,
            "no embedded newlines: {line:?}"
        );
        serde_json::from_str(line).expect("an entry is one JSON object")
    }

    #[test]
    fn an_entry_carries_the_run_and_states_no_truncation_when_none_happened() {
        let mut captured = Captured::default();
        captured.push(b"decision: allow\n");
        let line = entry_line(
            "2026-01-02T03:04:05Z",
            &argv(&["run", "stripe.refund"]),
            Path::new("/repo"),
            0,
            37,
            &captured,
        );
        let entry = parsed(&line);
        assert_eq!(entry["ts"], serde_json::json!("2026-01-02T03:04:05Z"));
        assert_eq!(entry["argv"], serde_json::json!(["run", "stripe.refund"]));
        assert_eq!(entry["cwd"], serde_json::json!("/repo"));
        assert_eq!(entry["exit"], serde_json::json!(0));
        assert_eq!(entry["duration_ms"], serde_json::json!(37));
        assert_eq!(entry["output"], serde_json::json!("decision: allow\n"));
        assert!(entry.get("truncated").is_none(), "{entry}");
    }

    /// The cap keeps the FIRST bytes verbatim and appends nothing to them; the `truncated` field is
    /// the only place the loss is stated.
    #[test]
    fn output_past_the_cap_is_counted_not_stored() {
        let mut captured = Captured::default();
        // Written in pieces, because that is how a real run writes: many small writes across two
        // descriptors, with the cap falling in the middle of one of them.
        for _ in 0..100 {
            captured.push(&b"x".repeat(50));
        }
        assert_eq!(captured.total(), 5000);
        assert_eq!(captured.kept().len(), OUTPUT_CAP_BYTES);
        assert!(captured.kept().iter().all(|byte| *byte == b'x'));

        let entry = parsed(&entry_line(
            "2026-01-02T03:04:05Z",
            &argv(&["catalog"]),
            Path::new("/repo"),
            0,
            1,
            &captured,
        ));
        let output = entry["output"].as_str().expect("output");
        assert_eq!(output.len(), OUTPUT_CAP_BYTES);
        assert!(
            !output.contains("truncat") && !output.ends_with('…'),
            "the loss is stated in a FIELD, never inline: {output:?}"
        );
        assert_eq!(entry["truncated"]["kept"], serde_json::json!(4096));
        assert_eq!(entry["truncated"]["total"], serde_json::json!(5000));
    }

    /// A multi-byte character split by the cap must not make the line unparseable.
    #[test]
    fn a_character_split_by_the_cap_still_produces_valid_json() {
        let mut captured = Captured::default();
        captured.push("é".repeat(4096).as_bytes());
        assert_eq!(captured.kept().len(), OUTPUT_CAP_BYTES);
        let entry = parsed(&entry_line(
            "2026-01-02T03:04:05Z",
            &argv(&["log"]),
            Path::new("/repo"),
            1,
            2,
            &captured,
        ));
        assert!(entry["output"].is_string(), "{entry}");
    }

    #[test]
    fn the_path_follows_the_state_directory_and_falls_back_to_home() {
        assert_eq!(
            journal_path_in(
                Some(PathBuf::from("/state")),
                Some(PathBuf::from("/home/x"))
            ),
            Some(PathBuf::from("/state/cermet/journal.jsonl"))
        );
        assert_eq!(
            journal_path_in(None, Some(PathBuf::from("/home/x"))),
            Some(PathBuf::from("/home/x/.local/state/cermet/journal.jsonl"))
        );
        // A relative state home is ignored, as the specification requires.
        assert_eq!(
            journal_path_in(Some(PathBuf::from("state")), Some(PathBuf::from("/home/x"))),
            Some(PathBuf::from("/home/x/.local/state/cermet/journal.jsonl"))
        );
        // Nowhere to write is not an error — it is simply no journal.
        assert_eq!(journal_path_in(None, None), None);
        assert_eq!(journal_path_in(None, Some(PathBuf::new())), None);
    }

    #[test]
    fn the_kept_generation_sits_beside_the_journal() {
        assert_eq!(
            previous_path(Path::new("/state/cermet/journal.jsonl")),
            PathBuf::from("/state/cermet/journal.jsonl.1")
        );
    }

    /// Appending creates the file `0600` with its parents, and rotates whole once it is oversized.
    #[test]
    fn appending_creates_a_private_file_and_rotates_it_whole() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let journal = dir
            .path()
            .join("state")
            .join("cermet")
            .join("journal.jsonl");
        append_entry(&journal, "{\"first\":true}\n").expect("append");
        assert_eq!(
            std::fs::metadata(&journal)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        for created in [
            dir.path().join("state"),
            journal.parent().expect("parent").to_path_buf(),
        ] {
            assert_eq!(
                std::fs::metadata(&created)
                    .expect("stat")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700,
                "{} must not inherit the ambient umask",
                created.display()
            );
        }
        append_entry(&journal, "{\"second\":true}\n").expect("append");
        assert_eq!(
            std::fs::read_to_string(&journal)
                .expect("read")
                .lines()
                .count(),
            2
        );

        // Oversized: the next write rotates first, then starts fresh.
        std::fs::File::options()
            .write(true)
            .open(&journal)
            .expect("open")
            .set_len(ROTATE_BYTES + 1)
            .expect("grow");
        append_entry(&journal, "{\"third\":true}\n").expect("append");
        assert_eq!(
            std::fs::read_to_string(&journal).expect("read"),
            "{\"third\":true}\n",
            "the fresh journal starts with the entry that noticed"
        );
        assert_eq!(
            std::fs::metadata(previous_path(&journal))
                .expect("stat")
                .len(),
            ROTATE_BYTES + 1
        );
    }

    /// Nothing in the journal's own path is followed: not the file, not the directory holding it,
    /// not the generation a rotation would rename onto. Each refusal is an ERROR the caller reads
    /// as "run un-journaled", and nothing is written through the planted link.
    #[test]
    fn no_part_of_the_path_is_ever_followed_through_a_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bait = dir.path().join("bait");
        std::fs::write(&bait, b"").expect("write bait");

        // The FILE.
        let cermet_dir = dir.path().join("state").join("cermet");
        std::fs::create_dir_all(&cermet_dir).expect("mkdir");
        let journal = cermet_dir.join("journal.jsonl");
        std::os::unix::fs::symlink(&bait, &journal).expect("plant");
        append_entry(&journal, "{\"leaked\":true}\n").expect_err("a symlinked journal is refused");
        assert_eq!(std::fs::metadata(&bait).expect("bait").len(), 0);
        std::fs::remove_file(&journal).expect("unplant");

        // The DIRECTORY holding it.
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("mkdir");
        let linked = dir.path().join("state").join("linked");
        std::os::unix::fs::symlink(&elsewhere, &linked).expect("plant");
        append_entry(&linked.join("journal.jsonl"), "{\"leaked\":true}\n")
            .expect_err("a symlinked journal directory is refused");
        assert!(!elsewhere.join("journal.jsonl").exists());

        // The KEPT GENERATION, at rotation.
        append_entry(&journal, "{\"first\":true}\n").expect("append");
        std::fs::File::options()
            .write(true)
            .open(&journal)
            .expect("open")
            .set_len(ROTATE_BYTES + 1)
            .expect("grow");
        std::os::unix::fs::symlink(&bait, previous_path(&journal)).expect("plant");
        append_entry(&journal, "{\"rotated\":true}\n")
            .expect_err("a symlinked kept generation is refused");
        assert_eq!(
            std::fs::metadata(&journal).expect("stat").len(),
            ROTATE_BYTES + 1,
            "the oversized journal was not rotated onto a planted link"
        );
        assert_eq!(std::fs::metadata(&bait).expect("bait").len(), 0);
    }

    /// A directory the operator already had keeps the permissions they gave it; the `cermet` leaf
    /// is ours and is tightened either way.
    #[test]
    fn an_existing_directory_is_left_as_the_operator_has_it() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        let cermet_dir = state.join("cermet");
        std::fs::create_dir_all(&cermet_dir).expect("mkdir");
        for existing in [&state, &cermet_dir] {
            std::fs::set_permissions(existing, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
        }
        append_entry(&cermet_dir.join("journal.jsonl"), "{}\n").expect("append");
        assert_eq!(
            std::fs::metadata(&state)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "a directory we did not create is the operator's business"
        );
        assert_eq!(
            std::fs::metadata(&cermet_dir)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "the journal's own directory is tightened unconditionally"
        );
    }

    /// The status text is the DECLARATION: the switch, the path, the caps, and its own off switch.
    #[test]
    fn the_status_declares_every_bound_it_enforces() {
        let text = status_text(
            true,
            Path::new("/home/x/.config/cermet/config.toml"),
            Some(Path::new("/state/cermet/journal.jsonl")),
        );
        for declared in [
            "enabled",
            "/state/cermet/journal.jsonl",
            "/home/x/.config/cermet/config.toml",
            "journal = \"on\"",
            "4096",
            ROTATE_HUMAN,
            "journal.jsonl.1",
            "cermet journal off",
        ] {
            assert!(
                text.contains(declared),
                "the status must state {declared}:\n{text}"
            );
        }
        let off = status_text(false, Path::new("/c.toml"), None);
        assert!(off.contains("disabled"), "{off}");
        assert!(off.contains("cermet journal on"), "{off}");
        assert!(
            off.contains("$XDG_STATE_HOME"),
            "an unresolvable path says so:\n{off}"
        );
    }

    #[test]
    fn sizes_read_the_way_an_operator_reads_them() {
        assert_eq!(human_size(12), "12 bytes");
        assert_eq!(human_size(2048), "2.0 KiB");
        assert_eq!(human_size(ROTATE_BYTES), "32.0 MiB");
    }
}
