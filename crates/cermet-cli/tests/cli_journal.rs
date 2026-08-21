//! The operator CLI's output journal, driven through the REAL binary.
//!
//! The journal exists because most of what the CLI says is said once and then lives only in a
//! terminal's scrollback: a ceremony's review text, the confirmation a human declined, the widening
//! suggestion a deny carried. `cermet log` is the broker's receipt of what was DECIDED; a declined
//! ceremony never reaches it, because nothing was decided. These tests drive real invocations and
//! read the file back, because the capture is a file-descriptor mechanism — an in-process double
//! would prove nothing about it.
//!
//! Every case is hermetic: `HOME` and `XDG_STATE_HOME` point at a fresh tempdir, so no test ever
//! reads or writes the box's own journal or settings.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

mod common;

/// A fresh, isolated operator home: the settings file and the journal both resolve inside it.
struct Box_ {
    dir: tempfile::TempDir,
}

impl Box_ {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn journal(&self) -> PathBuf {
        self.state().join("cermet").join("journal.jsonl")
    }

    fn previous(&self) -> PathBuf {
        self.state().join("cermet").join("journal.jsonl.1")
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("the cermet binary runs")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(common::cermet_binary());
        command
            .args(args)
            .env("HOME", self.home())
            .env("XDG_STATE_HOME", self.state())
            .stdin(Stdio::null());
        command
    }

    /// Every entry in the journal, oldest first. An absent file is no entries.
    fn entries(&self) -> Vec<Value> {
        let Ok(text) = std::fs::read_to_string(self.journal()) else {
            return Vec::new();
        };
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("every journal line is one JSON object"))
            .collect()
    }
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("the journal exists")
        .permissions()
        .mode()
        & 0o777
}

// ---- the entry ------------------------------------------------------------------------------

/// The ordinary case: one invocation, one well-formed line, carrying what the command printed.
#[test]
fn an_invocation_appends_one_entry_carrying_its_argv_exit_and_output() {
    let boxx = Box_::new();
    let out = boxx.run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));

    let entries = boxx.entries();
    assert_eq!(entries.len(), 1, "one invocation, one entry: {entries:?}");
    let entry = &entries[0];

    assert_eq!(
        entry["argv"],
        serde_json::json!(["--help"]),
        "the argument vector AFTER the program name: {entry}"
    );
    assert_eq!(entry["exit"], serde_json::json!(0), "{entry}");
    assert!(
        entry["output"]
            .as_str()
            .expect("output is a string")
            .contains("cermet — the capability broker CLI"),
        "the entry carries what the command PRINTED: {entry}"
    );
    assert!(
        entry["duration_ms"].is_u64(),
        "the entry times the run: {entry}"
    );
    assert_eq!(
        entry["cwd"],
        serde_json::json!(std::env::current_dir().expect("cwd").to_string_lossy()),
        "{entry}"
    );
    time::OffsetDateTime::parse(
        entry["ts"].as_str().expect("ts is a string"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("ts is RFC3339");
    assert!(
        entry.get("truncated").is_none(),
        "a short entry states no truncation: {entry}"
    );

    // The capture is a TEE, not a diversion: the operator still saw the banner on stdout, and
    // nothing of it leaked onto stderr.
    let stdout = String::from_utf8(out.stdout).expect("stdout is utf-8");
    assert!(
        stdout.contains("cermet — the capability broker CLI"),
        "{stdout}"
    );
    assert!(
        out.stderr.is_empty(),
        "stdout must not be rerouted onto stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A second invocation APPENDS.
    boxx.run(&["--version"]);
    let entries = boxx.entries();
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[1]["argv"], serde_json::json!(["--version"]));
}

/// The refusal path is journaled the same way, exit code and all — a command that failed is
/// exactly the one a later reader wants to see.
#[test]
fn a_refusal_is_journaled_with_its_exit_code_and_its_stderr() {
    let boxx = Box_::new();
    let out = boxx.run(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));

    let entries = boxx.entries();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["exit"], serde_json::json!(2), "{}", entries[0]);
    assert!(
        entries[0]["output"]
            .as_str()
            .expect("output")
            .contains("frobnicate"),
        "stderr is captured too: {}",
        entries[0]
    );
}

/// Aggressive truncation: the FIRST 4096 bytes are kept verbatim, nothing is appended to them, and
/// the `truncated` field — not an inline marker — is what says so.
#[test]
fn output_over_the_cap_keeps_the_first_4096_bytes_and_names_the_total() {
    let boxx = Box_::new();
    // An unknown command echoes the name it did not recognize and then the whole banner, so a long
    // name is a deterministic way to print far more than the cap.
    let long = "z".repeat(9000);
    let out = boxx.run(&[long.as_str()]);
    assert_eq!(out.status.code(), Some(2));
    let printed = String::from_utf8(out.stderr).expect("stderr is utf-8");
    assert!(
        printed.len() > 4096,
        "the fixture must overflow the cap ({} bytes)",
        printed.len()
    );

    let entries = boxx.entries();
    assert_eq!(entries.len(), 1, "{entries:?}");
    let entry = &entries[0];
    let output = entry["output"].as_str().expect("output");
    assert_eq!(
        output.len(),
        4096,
        "exactly the first 4096 bytes are kept, with nothing appended: {}",
        &output[output.len().saturating_sub(80)..]
    );
    assert!(
        printed.starts_with(output),
        "the kept bytes are the FIRST ones, verbatim"
    );
    assert_eq!(
        entry["truncated"]["kept"],
        serde_json::json!(4096),
        "{entry}"
    );
    assert_eq!(
        entry["truncated"]["total"],
        serde_json::json!(printed.len()),
        "the total counts every byte the command printed: {entry}"
    );
}

// ---- the file -------------------------------------------------------------------------------

/// The journal is the operator's own: created 0600, under `$XDG_STATE_HOME`, parents made as needed.
#[test]
fn the_journal_is_created_private_under_the_state_directory() {
    let boxx = Box_::new();
    assert!(!boxx.journal().exists());
    boxx.run(&["--version"]);
    assert!(boxx.journal().is_file(), "the journal was created");
    assert_eq!(
        mode(&boxx.journal()),
        0o600,
        "the journal is the operator's"
    );
}

/// Every directory the journal BRINGS INTO BEING is `0700`, whatever the ambient umask says — a
/// world-readable state directory would publish every command's output to any peer uid on the box.
#[test]
fn the_directories_the_journal_creates_are_private() {
    let boxx = Box_::new();
    boxx.run(&["--version"]);
    assert_eq!(
        mode(&boxx.state()),
        0o700,
        "the state directory this run created is the operator's alone"
    );
    assert_eq!(
        mode(&boxx.state().join("cermet")),
        0o700,
        "and so is the directory the journal lives in"
    );
}

/// …but a directory the OPERATOR already has is left exactly as they have it. `~/.local/state` is
/// theirs and holds other programs' state; a journal write is not a licence to re-permission it.
/// The `cermet` leaf is ours, so it is tightened whether we made it this run or an earlier one.
#[test]
fn a_directory_the_operator_already_had_is_not_re_permissioned() {
    use std::os::unix::fs::PermissionsExt;

    let boxx = Box_::new();
    std::fs::create_dir_all(boxx.state().join("cermet")).expect("mkdir");
    for (dir, existing) in [(boxx.state(), 0o755), (boxx.state().join("cermet"), 0o755)] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(existing)).expect("chmod");
    }
    boxx.run(&["--version"]);
    assert_eq!(
        mode(&boxx.state()),
        0o755,
        "a directory we did not create this run is the operator's business"
    );
    assert_eq!(
        mode(&boxx.state().join("cermet")),
        0o700,
        "the journal's own directory is tightened unconditionally"
    );
}

/// A symlink anywhere in the journal's own path is REFUSED, and the command carries on unaffected.
///
/// The adversary is a peer uid on the box: on a machine whose umask left `~/.local/state`
/// group- or world-writable, they could pre-place the journal — or the directory holding it — as a
/// symlink to somewhere they can read, and every command's output would be copied there. Refusing
/// costs this invocation its journal entry and nothing else; a record of what happened must never
/// be able to change what happens.
#[test]
fn a_symlinked_journal_is_refused_and_the_command_still_succeeds() {
    let boxx = Box_::new();
    let cermet_dir = boxx.state().join("cermet");
    std::fs::create_dir_all(&cermet_dir).expect("mkdir");
    let bait = boxx.dir.path().join("peer-readable-bait");
    std::fs::write(&bait, b"").expect("write bait");
    std::os::unix::fs::symlink(&bait, boxx.journal()).expect("plant the symlink");

    let out = boxx.run(&["--version"]);
    assert_eq!(out.status.code(), Some(0), "the command still runs");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("cermet "),
        "and still prints what it prints"
    );
    assert_eq!(
        std::fs::metadata(&bait).expect("the bait").len(),
        0,
        "nothing was written through the symlink"
    );
    assert!(
        std::fs::symlink_metadata(boxx.journal())
            .expect("the planted link")
            .is_symlink(),
        "the planted link is left exactly as it was found — not replaced, not written through"
    );
}

/// The same rule for the directory: a symlinked `cermet` directory is refused, so nothing lands
/// inside whatever it points at.
#[test]
fn a_symlinked_journal_directory_is_refused() {
    let boxx = Box_::new();
    std::fs::create_dir_all(boxx.state()).expect("mkdir");
    let elsewhere = boxx.dir.path().join("peer-owned");
    std::fs::create_dir(&elsewhere).expect("mkdir");
    std::os::unix::fs::symlink(&elsewhere, boxx.state().join("cermet")).expect("plant");

    let out = boxx.run(&["--version"]);
    assert_eq!(out.status.code(), Some(0), "the command still runs");
    assert!(
        !elsewhere.join("journal.jsonl").exists(),
        "nothing was written into the directory the link pointed at"
    );
}

/// And at rotation: a symlinked kept generation is refused rather than renamed over, so the
/// oversized journal stays put and this invocation simply goes unrecorded.
#[test]
fn a_symlinked_kept_generation_is_refused_at_rotation() {
    let boxx = Box_::new();
    std::fs::create_dir_all(boxx.state().join("cermet")).expect("mkdir");
    let over = std::fs::File::create(boxx.journal()).expect("create");
    over.set_len(33 * 1024 * 1024).expect("grow past 32 MiB");
    drop(over);
    let bait = boxx.dir.path().join("peer-readable-bait");
    std::fs::write(&bait, b"").expect("write bait");
    std::os::unix::fs::symlink(&bait, boxx.previous()).expect("plant the symlink");

    let out = boxx.run(&["--version"]);
    assert_eq!(out.status.code(), Some(0), "the command still runs");
    assert_eq!(
        std::fs::metadata(boxx.journal())
            .expect("the journal")
            .len(),
        33 * 1024 * 1024,
        "the oversized journal was not rotated onto a planted link"
    );
    assert_eq!(
        std::fs::metadata(&bait).expect("the bait").len(),
        0,
        "and nothing was written through it"
    );
}

/// With `$XDG_STATE_HOME` unset the journal falls back to the default state directory under `$HOME`.
#[test]
fn an_unset_state_home_falls_back_to_the_default_under_home() {
    let boxx = Box_::new();
    let mut command = boxx.command(&["--version"]);
    command.env_remove("XDG_STATE_HOME");
    command.output().expect("cermet runs");
    let fallback = boxx
        .home()
        .join(".local")
        .join("state")
        .join("cermet")
        .join("journal.jsonl");
    assert!(
        fallback.is_file(),
        "the default is ~/.local/state/cermet/journal.jsonl"
    );
}

/// Whole-file rotation at the threshold: one generation is kept, any previous one is replaced, and
/// the fresh journal starts with this invocation's entry.
#[test]
fn the_journal_rotates_whole_at_the_threshold_keeping_one_generation() {
    let boxx = Box_::new();
    std::fs::create_dir_all(boxx.journal().parent().expect("parent")).expect("mkdir");
    // A previous generation that must be REPLACED, not kept beside a second one.
    std::fs::write(boxx.previous(), b"the generation before last\n").expect("write .1");
    // A journal past the threshold. Sparse: the size is what the rotation reads.
    let over = std::fs::File::create(boxx.journal()).expect("create");
    over.set_len(33 * 1024 * 1024).expect("grow past 32 MiB");
    drop(over);

    boxx.run(&["--version"]);

    let rotated = std::fs::metadata(boxx.previous()).expect("the rotated generation");
    assert_eq!(
        rotated.len(),
        33 * 1024 * 1024,
        "the oversized journal became the ONE kept generation, replacing the older .1"
    );
    let entries = boxx.entries();
    assert_eq!(
        entries.len(),
        1,
        "the fresh journal carries this invocation and nothing else: {entries:?}"
    );
    assert_eq!(entries[0]["argv"], serde_json::json!(["--version"]));
    assert!(
        !boxx.state().join("cermet").join("journal.jsonl.2").exists(),
        "one generation, no compression, no background work"
    );
}

// ---- the declared setting -------------------------------------------------------------------

/// The toggle is a real, persisted setting in the operator's own settings file — and `cermet
/// journal` states where the journal is, so a reader can grep it with their own tools.
#[test]
fn the_status_form_states_the_switch_the_path_and_the_bounds() {
    let boxx = Box_::new();
    let out = boxx.run(&["journal"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).expect("stdout is utf-8");
    assert!(text.contains("enabled"), "default ON: {text}");
    assert!(
        text.contains(&boxx.journal().display().to_string()),
        "the path is printed so it can be read with tail/jq: {text}"
    );
    assert!(text.contains("4096"), "the entry cap is declared: {text}");
    assert!(
        text.contains("32 MiB"),
        "the rotation threshold is declared: {text}"
    );
    assert!(
        text.contains("cermet journal off"),
        "the status names its own off switch: {text}"
    );

    // `cermet journal` is an invocation like any other — no special-casing.
    let entries = boxx.entries();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["argv"], serde_json::json!(["journal"]));
}

#[test]
fn off_stops_appending_and_on_resumes() {
    let boxx = Box_::new();
    boxx.run(&["--version"]);
    assert_eq!(boxx.entries().len(), 1);

    let off = boxx.run(&["journal", "off"]);
    assert_eq!(off.status.code(), Some(0));
    let text = String::from_utf8(off.stdout).expect("stdout is utf-8");
    assert!(text.contains("disabled"), "{text}");
    // The command that turned it off was itself journaled — it ran while the journal was still on.
    let after_off = boxx.entries().len();

    boxx.run(&["--version"]);
    boxx.run(&["--help"]);
    assert_eq!(
        boxx.entries().len(),
        after_off,
        "nothing may be appended while the journal is off"
    );

    // The setting is persisted where the operator's own settings live.
    let config = boxx
        .home()
        .join(".config")
        .join("cermet")
        .join("config.toml");
    let body = std::fs::read_to_string(&config).expect("the settings file records it");
    assert!(body.contains("journal = \"off\""), "{body}");

    let on = boxx.run(&["journal", "on"]);
    assert_eq!(on.status.code(), Some(0));
    boxx.run(&["--version"]);
    assert!(
        boxx.entries().len() > after_off,
        "turning it back on resumes appending"
    );
    let body = std::fs::read_to_string(&config).expect("read back");
    assert!(body.contains("journal = \"on\""), "{body}");
    // The knob this file already owned is untouched by the new one.
    assert!(body.contains("update_check"), "{body}");
}

// ---- the roles that must NOT journal ----------------------------------------------------------

/// `cermet mcp` is the agent's stdio protocol channel. Capturing it would both corrupt the
/// protocol's performance and journal agent traffic that already has receipts.
#[test]
fn the_mcp_stdio_server_never_journals() {
    let boxx = Box_::new();
    let mut command = boxx.command(&["mcp"]);
    // No daemon: the server either exits on the absent socket or on stdin EOF. Either way it must
    // leave no journal behind.
    command.env("CERMET_AGENT_SOCK", boxx.dir.path().join("absent.sock"));
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut sink = String::new();
    let _ = child
        .stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut sink);
    let _ = child.wait().expect("wait");

    assert!(
        !boxx.journal().exists(),
        "the MCP stdio role must leave no journal: {:?}",
        boxx.entries()
    );

    // Asking what `mcp` IS, on the other hand, is an ordinary CLI question answered by the CLI,
    // and is journaled like any other.
    boxx.run(&["mcp", "--help"]);
    assert_eq!(boxx.entries().len(), 1, "{:?}", boxx.entries());
}
