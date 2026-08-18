//! The operator's own settings file: `$HOME/.config/cermet/config.toml`.
//!
//! ONE knob lives here — `update_check`, the daily release check (`crate::update_check`). It is
//! per-operator rather than a daemon setting: it governs nothing the daemon does, two humans on one
//! box may differ, and changing your mind must not need root. It follows the ordinary shape for a
//! CLI's own settings: one self-documenting TOML file under the user's config directory.
//!
//! # One grammar, and writes that touch only what they own
//!
//! Reads go through the `toml` crate — the same parser the daemon and `setup` use — so every
//! spelling TOML admits means the same thing everywhere, and a key this build does not know is
//! simply not this build's business. Writes are the comment-preserving line surgery `setup` already
//! performs on `/etc/cermetd/config.toml` ([`crate::setup::set_string_key`]): the ONE active
//! assignment for the key being changed is rewritten, appended when absent, and every other line —
//! comments, blank lines, and any key this build does not own — survives byte for byte.

use std::path::{Path, PathBuf};

use crate::CliError;

/// The knob's key, spelled once.
pub const UPDATE_CHECK_KEY: &str = "update_check";

/// The operator's own settings file, on every surface.
///
/// **ONE resolver, and `$XDG_CONFIG_HOME` is deliberately not consulted for THIS file.** The
/// setting is read by three things that must never disagree: this CLI, the setup
/// run that records the default, and the scheduled check. Setup runs as root and resolves the
/// approver's home from the passwd database; the scheduler units export no environment at all. An
/// operator with `XDG_CONFIG_HOME` set would otherwise write to one path while the timer read
/// another, found it absent, and read absent as the default. A fixed path makes all three agree by
/// construction rather than by convention, and every surface that states the setting prints the path
/// it used, which is the guarantee rather than a courtesy.
pub fn config_path() -> PathBuf {
    config_path_in(std::env::var_os("HOME").map(PathBuf::from))
}

/// The path resolution, taking the home directory as a parameter so it is testable without touching
/// the process environment. Setup passes the APPROVER's home, which it resolved from passwd; the CLI
/// passes `$HOME`. Same function, same answer.
pub fn config_path_in(home: Option<PathBuf>) -> PathBuf {
    home.filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_default()
        .join(".config")
        .join("cermet")
        .join("config.toml")
}

/// May the daily update check run? An absent file is the default (on): a box whose settings file was
/// never written is a box in its default state, not a box that turned anything off.
///
/// A file that does not parse, or that gives the key a value this build does not know, is an ERROR
/// rather than a quiet default in either direction — the operator asked and deserves the real
/// answer. Keys this build does not own are ignored: the file is the operator's, and a line nothing
/// here reads is not a reason to refuse the line that is read.
pub fn read_update_check(path: &Path) -> Result<bool, CliError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => {
            return Err(CliError::Malformed(format!(
                "cannot read {}: {error}",
                path.display()
            )))
        }
    };
    let value = crate::setup::active_string_value(&text, UPDATE_CHECK_KEY).map_err(|error| {
        CliError::Malformed(format!(
            "{}: {error}\nfix it by hand, or run `cermet update --daily on` / \
             `cermet update --daily off` to rewrite the line",
            path.display()
        ))
    })?;
    match value.as_deref() {
        None => Ok(true),
        Some("on") => Ok(true),
        Some("off") => Ok(false),
        Some(other) => Err(CliError::Malformed(format!(
            "{} sets {UPDATE_CHECK_KEY} = {other:?}, which is neither \"on\" nor \"off\"\nfix it by \
             hand, or run `cermet update --daily on` / `cermet update --daily off` to rewrite it",
            path.display()
        ))),
    }
}

/// Write the knob. An absent file is created with its documentation; an existing one has exactly the
/// `update_check` assignment rewritten and nothing else touched.
pub fn write_update_check(path: &Path, enabled: bool) -> Result<(), CliError> {
    let updated = match std::fs::read_to_string(path) {
        Ok(text) => crate::setup::set_string_key(&text, UPDATE_CHECK_KEY, switch(enabled)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => settings_file(enabled),
        Err(error) => {
            return Err(CliError::Malformed(format!(
                "cannot read {}: {error}",
                path.display()
            )))
        }
    };
    write_file(path, &updated)
}

/// Record the DEFAULT when nothing is recorded yet, and never touch a file that exists.
///
/// Returns whether it wrote. The existence of the file is the whole test: a recorded setting is the
/// operator's, whichever way it reads, and a re-run of setup is not a reason to reopen it.
pub fn record_default(path: &Path) -> Result<bool, CliError> {
    if path.exists() {
        return Ok(false);
    }
    write_file(path, &settings_file(true))?;
    Ok(true)
}

fn write_file(path: &Path, body: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            CliError::Malformed(format!("cannot create {}: {error}", parent.display()))
        })?;
    }
    std::fs::write(path, body)
        .map_err(|error| CliError::Malformed(format!("cannot write {}: {error}", path.display())))
}

fn switch(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
    }
}

/// A fresh settings file's exact bytes. It documents itself: an operator who finds this file a year
/// from now can read what the line governs without leaving the file.
pub fn settings_file(update_check: bool) -> String {
    format!(
        "# Cermet operator settings. Written by `cermet setup`; edit it by hand if you prefer.\n\
         \n\
         # The daily update check: one parameterless GET of {origin}, once a day, run as you and\n\
         # never by the daemon (a second one, of that release's own SHA256SUMS, only when the\n\
         # release is newer than this build). Default: on.\n\
         #\n\
         # It NEVER INSTALLS ANYTHING. All it does is leave a note on this machine, which `cermet`\n\
         # prints as one line until you update and `cermet check` reports as a row. Applying an\n\
         # update stays the explicit, sudo-gated `cermet update`. The request carries no install id,\n\
         # no account, no query and no parameters of any kind: the comparison happens here. Its user\n\
         # agent names the client version (cermet/<version>) — the same string carried by every\n\
         # install of that release — so release adoption is visible in aggregate. It names a RELEASE,\n\
         # never an installation.\n\
         # Change it at any time: `cermet update --daily off`, `cermet update --daily on`, or edit\n\
         # the line below by hand.\n\
         {UPDATE_CHECK_KEY} = \"{value}\"\n",
        value = switch(update_check),
        origin = crate::update::origin(None).release_url(crate::update::UPDATE_REPO),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `HOME` and `XDG_CONFIG_HOME` are process-global, so the tests that set them hold this lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    /// The default is ON, and reading never creates the file: asking what the setting is must not
    /// decide it.
    #[test]
    fn the_default_is_on_and_reading_never_writes() {
        let dir = temp();
        let path = dir.path().join("cermet").join("config.toml");
        assert!(read_update_check(&path).expect("an absent file reads as on"));
        assert!(!path.exists(), "reading must not create the file");
    }

    /// The knob round-trips, and a fresh file documents what the line governs.
    #[test]
    fn the_setting_round_trips_and_the_fresh_file_documents_itself() {
        let dir = temp();
        let path = dir.path().join("cermet").join("config.toml");

        write_update_check(&path, false).expect("off");
        assert!(!read_update_check(&path).expect("read back"));
        write_update_check(&path, true).expect("on");
        assert!(read_update_check(&path).expect("read back"));

        let body = std::fs::read_to_string(&path).expect("read");
        assert!(body.contains("update_check = \"on\""), "{body}");
        assert!(body.contains("NEVER INSTALLS ANYTHING"), "{body}");
        assert!(body.contains("cermet update --daily off"), "{body}");
    }

    /// The default is RECORDED once and an existing file is never rewritten — whichever way it
    /// reads. Re-running setup on a box where the operator turned the check off must not turn it
    /// back on.
    #[test]
    fn the_default_is_recorded_once_and_never_overwrites_a_recorded_setting() {
        let dir = temp();
        let fresh = dir.path().join("fresh").join("config.toml");
        assert!(record_default(&fresh).expect("record"), "it wrote");
        assert!(read_update_check(&fresh).expect("read back"));

        for recorded in [true, false] {
            let path = dir.path().join(format!("{recorded}")).join("config.toml");
            write_update_check(&path, recorded).expect("record");
            let before = std::fs::read_to_string(&path).expect("read");
            assert!(
                !record_default(&path).expect("record"),
                "an existing setting is never rewritten"
            );
            assert_eq!(
                std::fs::read_to_string(&path).expect("read"),
                before,
                "the recorded setting changed"
            );
            assert_eq!(read_update_check(&path).expect("read back"), recorded);
        }
    }

    /// Boxes provisioned by older builds may carry keys this build does not own in this
    /// very file. It reads past them without complaint, and a write of the key it DOES own
    /// leaves the unknown line, its comments, and every other byte exactly where they were —
    /// the operator's file belongs to the operator.
    #[test]
    fn an_orphan_key_from_an_older_install_reads_fine_and_is_never_rewritten() {
        let dir = temp();
        let path = dir.path().join("config.toml");
        let legacy = "# an older install wrote this file\n\
                      legacy_knob = \"off\"\n\
                      \n\
                      # the check's own documentation\n\
                      update_check = \"on\"\n";
        std::fs::write(&path, legacy).expect("write");

        assert!(
            read_update_check(&path).expect("the orphan key does not break the read"),
            "the key this build owns still answers"
        );

        write_update_check(&path, false).expect("flip the check");
        let after = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            after,
            legacy.replace("update_check = \"on\"", "update_check = \"off\""),
            "a write may touch ONLY the assignment it owns"
        );
        assert!(
            after.contains("legacy_knob = \"off\""),
            "the orphan line survives byte for byte: {after}"
        );
        assert!(!read_update_check(&path).expect("read back"));
    }

    /// A file with no `update_check` line at all gains one, and keeps everything it had.
    #[test]
    fn a_file_without_the_key_gains_it_and_keeps_its_own_content() {
        let dir = temp();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "# the operator's own notes\nsomething_else = 3\n").expect("write");
        write_update_check(&path, false).expect("off");
        let after = std::fs::read_to_string(&path).expect("read");
        assert!(after.contains("# the operator's own notes"), "{after}");
        assert!(after.contains("something_else = 3"), "{after}");
        assert!(after.contains("update_check = \"off\""), "{after}");
        assert!(!read_update_check(&path).expect("read back"));
    }

    /// A value this build does not know is refused BY NAME, naming the command that rewrites it —
    /// never a quiet default in either direction. So is a file that is not TOML.
    #[test]
    fn a_malformed_setting_is_an_error_not_a_silent_default() {
        let dir = temp();
        let path = dir.path().join("config.toml");

        std::fs::write(&path, "update_check = \"maybe\"\n").expect("write");
        let error = format!("{}", read_update_check(&path).expect_err("refused"));
        assert!(error.contains("update_check"), "{error}");
        assert!(error.contains("cermet update --daily"), "{error}");

        std::fs::write(&path, "update_check = [\"on\"]\n").expect("write");
        assert!(read_update_check(&path).is_err(), "a non-string is refused");

        std::fs::write(&path, "not = toml = at = all\n").expect("write");
        let error = format!("{}", read_update_check(&path).expect_err("refused"));
        assert!(error.contains("not valid TOML"), "{error}");

        // The file EXISTS, so the default is not recorded on top of it — a settings file the
        // operator has to fix by hand is still a settings file.
        assert!(!record_default(&path).expect("record"));
    }

    /// ONE resolver: the setting lives at a FIXED
    /// `$HOME/.config/cermet/config.toml`, and `$XDG_CONFIG_HOME` is not consulted for it.
    #[test]
    fn the_setting_ignores_xdg_so_every_surface_resolves_one_path() {
        assert_eq!(
            config_path_in(Some(PathBuf::from("/home/someone"))),
            PathBuf::from("/home/someone/.config/cermet/config.toml")
        );

        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let home = temp();
        let xdg = temp();
        let previous_home = std::env::var_os("HOME");
        let previous_xdg = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("HOME", home.path());
        std::env::set_var("XDG_CONFIG_HOME", xdg.path());

        let resolved = config_path();
        let expected = home
            .path()
            .join(".config")
            .join("cermet")
            .join("config.toml");
        assert_eq!(
            resolved, expected,
            "the CLI must not follow XDG for this file"
        );
        write_update_check(&resolved, false).expect("off");
        assert!(expected.is_file(), "the setting landed at the fixed path");
        assert!(
            !xdg.path().join("cermet").join("config.toml").exists(),
            "nothing may be written under XDG_CONFIG_HOME"
        );

        // And setup's own resolution — it passes the approver's passwd home — lands identically.
        assert_eq!(
            config_path_in(Some(home.path().to_path_buf())),
            expected,
            "setup and the CLI must agree by construction, not by convention"
        );

        match previous_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        match previous_xdg {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }
}
