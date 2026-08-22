//! `cermet preset` — a stored authority profile, applied by name.
//!
//! A preset is an opaque KEY into a daemon-side table of corpus bodies. The name means nothing to
//! the broker: `builder`, `designer` and `q3r982` are equally good keys, and none of them refers to
//! a repository, a checkout, or anything else on the box.
//!
//! A body is a WHOLE corpus, so applying one REPLACES what is live — the same thing `doc apply`
//! does with a repository's document, through the same ceremony: prepare, diff, review, terminal
//! confirm, presence, staged commit. Nothing here decides authority; it chooses which body the
//! operator is shown before they accept it.
//!
//! Profiles are written on ONE path — a `doc apply` of a `CERMET_<name>.md` document, which stores
//! the committed body under `<name>` as part of that commit. There is no write op here, so a
//! stored profile always carries the same attested evidence a live corpus does.

use std::path::{Path, PathBuf};

use cermet_ctl_client::presence::Presence;
use serde::Deserialize;

use crate::cermet_document::{render_template, AuthorityMarker};
use crate::reconciliation::{
    run_body_apply, ApplyTransactionClient, BodyApply, CtlReconciliationClient,
    ReconciliationOutput,
};
use crate::tty::Terminal;

/// The longest preset name accepted here. The daemon enforces the same cap; this is the preflight.
pub const MAX_PRESET_NAME: usize = 64;

/// The three forms of the noun. There is deliberately no form that applies the document you are
/// standing in — that is `doc apply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresetCommand {
    /// `preset list` — every stored profile.
    List,
    /// `preset <name>` — install that profile's body, replacing the live corpus.
    Apply { name: String, recover: bool },
    /// `preset export <name> [<path>]` — write the body back out as a re-appliable document.
    Export {
        name: String,
        path: Option<String>,
        force: bool,
    },
}

/// Where `preset export` writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportTarget {
    /// A directory: the file is named `CERMET_<name>.md` inside it.
    Directory(PathBuf),
    /// An exact file path, named by the operator.
    File(PathBuf),
}

/// One stored profile as the daemon reports it. Deserialized LOCALLY; a row missing a required
/// field is malformed and fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StoredPresetRow {
    pub name: String,
    pub rules_text: String,
    pub rule_count: usize,
    pub updated_at: String,
}

/// The daemon's stored profiles, behind a trait so resolution and rendering are testable without a
/// socket.
pub trait PresetStore {
    fn presets(&self) -> Result<Vec<StoredPresetRow>, String>;
}

impl PresetStore for CtlReconciliationClient {
    fn presets(&self) -> Result<Vec<StoredPresetRow>, String> {
        let view = self.presets_json()?;
        serde_json::from_str(&view).map_err(|error| format!("malformed preset view: {error}"))
    }
}

/// The words this noun's own subcommands take. A profile stored under one of them could never be
/// applied — `cermet preset list` matches the subcommand, so the name would be unreachable
/// vocabulary — so they are refused where a profile is named instead.
pub const RESERVED_NAMES: &[&str] = &["list", "export"];

/// Validate a profile name — the CLI-side preflight for the daemon's own rule, so a name it would
/// refuse never reaches a ceremony. The refusal is prose an operator reads, and it never echoes
/// the raw bytes it was given.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("a profile name must not be empty".to_string());
    }
    if name.len() > MAX_PRESET_NAME {
        return Err(format!(
            "a profile name must be at most {MAX_PRESET_NAME} characters"
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(format!(
            "`{}` is not a profile name — a name may hold only letters, digits, `_` and `-`",
            sanitized_name(name)
        ));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(format!(
            "`{name}` is reserved: it is a `cermet preset` subcommand, so a profile stored under it could never be applied. Pick another name."
        ));
    }
    Ok(())
}

/// The accepted-name predicate, for the callers that only branch on it.
pub fn name_is_valid(name: &str) -> bool {
    validate_name(name).is_ok()
}

/// Render any name for a terminal.
///
/// Applied to EVERY surface that prints a name — table cells, review text, and every error — not
/// only the ones where a name is expected to be well-formed. Stored names pass the daemon's
/// alphabet, but a name a caller TYPED has passed nothing yet, and an error message is exactly
/// where an unvalidated one shows up. One function, used unconditionally, is the only way that
/// stays true as messages are added.
pub fn sanitized_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '?'
            }
        })
        .take(MAX_PRESET_NAME)
        .collect();
    if out.is_empty() {
        out.push_str("(empty)");
    }
    out
}

/// `cermet preset list`.
///
/// `live` is the profile the daemon reports its served corpus IS — the same read-time join
/// `doc status` renders, carried here so the listing can mark that row. Nothing about "current" is
/// stored: a profile is live exactly while the daemon is serving that body.
pub fn run_preset_list(store: &dyn PresetStore, live: Option<&str>) -> ReconciliationOutput {
    let rows = match store.presets() {
        Ok(rows) => rows,
        Err(reason) => {
            return refused(format!(
                "preset: the profile store is unavailable — {reason}"
            ))
        }
    };
    if rows.is_empty() {
        return ReconciliationOutput {
            text: "No authority profiles are stored.\n\
                   Write one by applying a preset document: `cermet doc apply CERMET_<name>.md`."
                .to_string(),
            exit_code: 0,
        };
    }
    ReconciliationOutput {
        text: render_rows(&rows, live),
        exit_code: 0,
    }
}

/// `cermet preset <name>` — load the stored body and run the ceremony against it.
pub fn run_preset_apply(
    store: &dyn PresetStore,
    client: &dyn ApplyTransactionClient,
    name: &str,
    recover: bool,
    terminal: &dyn Terminal,
    presence: &dyn Presence,
) -> ReconciliationOutput {
    let row = match resolve(store, name) {
        Ok(row) => row,
        Err(output) => return output,
    };
    run_body_apply(
        client,
        BodyApply {
            body: &row.rules_text,
            preset: &row.name,
            source: "stored profile",
        },
        recover,
        terminal,
        presence,
    )
}

/// `cermet preset export <name> [<path>] [--force]` — write the stored body back out as a document
/// that `doc apply` re-ingests under the same key.
pub fn run_preset_export(
    store: &dyn PresetStore,
    name: &str,
    target: &ExportTarget,
    force: bool,
) -> ReconciliationOutput {
    let row = match resolve(store, name) {
        Ok(row) => row,
        Err(output) => return output,
    };
    let path = match target {
        ExportTarget::File(path) => path.clone(),
        ExportTarget::Directory(dir) => dir.join(format!("CERMET_{}.md", row.name)),
    };
    // The pin marker names the generation a document was derived FROM. A profile is derived from
    // nothing — it is a body under a key — so it exports unpinned, which is also what makes the
    // exported file re-appliable anywhere rather than only where it came from.
    let rendered = match render_template(&AuthorityMarker::none(), row.rules_text.as_bytes()) {
        Ok(rendered) => rendered,
        Err(_) => {
            return refused(format!(
                "preset export {}: the stored body cannot be rendered as a document",
                sanitized_name(&row.name)
            ))
        }
    };
    let display = crate::reconciliation::safe_one_line(&path.to_string_lossy());
    // Refuse to clobber: an export that silently overwrites is one that can destroy an edited
    // document the operator had not applied yet.
    if !force && path.exists() {
        return refused(format!(
            "preset export {}: {display} already exists; move it or rerun with --force",
            sanitized_name(&row.name)
        ));
    }
    match std::fs::write(&path, &rendered) {
        Ok(()) => ReconciliationOutput {
            text: format!(
                "exported: {display}\npreset: {}\nrules: {}\napply it anywhere with: cermet doc apply {display}",
                sanitized_name(&row.name),
                row.rule_count
            ),
            exit_code: 0,
        },
        Err(error) => refused(format!(
            "preset export {}: cannot write {display} ({error})",
            sanitized_name(&row.name)
        )),
    }
}

/// Look one name up. A miss names what IS stored, because the alternative is an operator guessing
/// at keys the daemon already knows.
fn resolve(store: &dyn PresetStore, name: &str) -> Result<StoredPresetRow, ReconciliationOutput> {
    let rows = match store.presets() {
        Ok(rows) => rows,
        Err(reason) => {
            return Err(refused(format!(
                "preset: the profile store is unavailable — {reason}"
            )))
        }
    };
    let wanted = name.trim();
    match rows.iter().find(|row| row.name == wanted) {
        Some(row) => Ok(row.clone()),
        None if rows.is_empty() => Err(refused(format!(
            "preset {}: no authority profiles are stored — write one by applying a preset \
             document: `cermet doc apply CERMET_<name>.md`",
            sanitized_name(wanted)
        ))),
        None => Err(refused(format!(
            "preset {}: no profile is stored under that name. Stored:\n{}",
            sanitized_name(wanted),
            rows.iter()
                .map(|row| format!("    {}", sanitized_name(&row.name)))
                .collect::<Vec<_>>()
                .join("\n")
        ))),
    }
}

fn refused(text: String) -> ReconciliationOutput {
    ReconciliationOutput { text, exit_code: 2 }
}

/// The marker on the row the daemon is serving right now.
const LIVE_MARKER: &str = "● live";

/// The list, in aligned plain columns, with the served row marked.
fn render_rows(rows: &[StoredPresetRow], live: Option<&str>) -> String {
    let cells: Vec<[String; 3]> = rows
        .iter()
        .map(|row| {
            [
                sanitized_name(&row.name),
                row.rule_count.to_string(),
                match live {
                    Some(live) if live == row.name => format!(
                        "{}  {LIVE_MARKER}",
                        crate::reconciliation::safe_one_line(&row.updated_at)
                    ),
                    _ => crate::reconciliation::safe_one_line(&row.updated_at),
                },
            ]
        })
        .collect();
    let header = ["PRESET", "RULES", "UPDATED"];
    let mut widths = header.map(str::len);
    for row in &cells {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: [&str; 3]| {
        let mut out = String::new();
        for (index, cell) in cells.iter().enumerate() {
            // The last column is never padded — trailing blanks are noise in a terminal.
            if index + 1 == cells.len() {
                out.push_str(cell);
            } else {
                out.push_str(&format!("{cell:<width$}  ", width = widths[index]));
            }
        }
        out
    };
    let mut text = line(header);
    for row in &cells {
        text.push('\n');
        text.push_str(&line([&row[0], &row[1], &row[2]]));
    }
    text
}

/// Where `preset export` writes when no path was given: the process's working directory.
pub fn export_target(path: Option<&str>) -> ExportTarget {
    match path {
        Some(path) => ExportTarget::File(PathBuf::from(path)),
        None => ExportTarget::Directory(
            std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rows(Vec<StoredPresetRow>);

    impl PresetStore for Rows {
        fn presets(&self) -> Result<Vec<StoredPresetRow>, String> {
            Ok(self.0.clone())
        }
    }

    fn row(name: &str, rules: &str) -> StoredPresetRow {
        StoredPresetRow {
            name: name.into(),
            rules_text: rules.into(),
            rule_count: rules.lines().count(),
            updated_at: "2020-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn the_accepted_alphabet_is_the_daemons() {
        for accepted in [
            "designer",
            "CERMET_BUILDER",
            "q3r982",
            "a-b_c",
            "x",
            // Only the EXACT subcommand words are taken.
            "lists",
            "exporter",
            "List",
            "Export",
        ] {
            assert!(name_is_valid(accepted), "{accepted:?}");
        }
        for refused in [
            "",
            "de signer",
            "../etc/passwd",
            "a/b",
            "a.b",
            "naïve",
            "$(id)",
            "list",
            "export",
        ] {
            assert!(!name_is_valid(refused), "{refused:?}");
        }
        assert!(name_is_valid(&"a".repeat(MAX_PRESET_NAME)));
        assert!(!name_is_valid(&"a".repeat(MAX_PRESET_NAME + 1)));
        // The reserved words are refused, and the refusal says WHY — an operator who picked one
        // needs to know it is taken, not that it is malformed.
        for reserved in RESERVED_NAMES {
            let refusal = validate_name(reserved).expect_err("a subcommand word is reserved");
            assert!(refusal.contains("reserved"), "{reserved}: {refusal}");
            assert!(refusal.contains(reserved), "{reserved}: {refusal}");
        }
        // A refusal never echoes raw bytes.
        let hostile = validate_name("de\u{1b}[2Jsigner").expect_err("bad alphabet");
        assert!(!hostile.contains('\u{1b}'), "{hostile}");
    }

    #[test]
    fn a_name_is_sanitized_and_bounded_before_it_reaches_a_terminal() {
        assert_eq!(sanitized_name("designer"), "designer");
        // Only the bytes outside the alphabet are replaced: the escape and the `[` go, the `2J`
        // they were steering with is left as the ordinary text it is.
        assert_eq!(sanitized_name("de\u{1b}[2Jsigner"), "de??2Jsigner");
        assert_eq!(sanitized_name("../etc/passwd"), "???etc?passwd");
        assert_eq!(sanitized_name(""), "(empty)");
        assert_eq!(sanitized_name("\n\r\t"), "???");
        assert_eq!(
            sanitized_name(&"a".repeat(MAX_PRESET_NAME * 2)).len(),
            MAX_PRESET_NAME
        );
    }

    #[test]
    fn every_resolution_failure_sanitizes_both_the_typed_name_and_the_stored_ones() {
        let escape = "de\u{1b}[2Jsigner";
        let stored = Rows(vec![row("designer", "allow stripe.get_charge\n")]);
        let empty = Rows(Vec::new());

        // The typed name is echoed on the miss path, and the stored names are listed beside it.
        let miss = resolve(&stored, escape).expect_err("unknown");
        assert!(!miss.text.contains('\u{1b}'), "{}", miss.text);
        assert!(miss.text.contains("designer"), "{}", miss.text);
        assert_eq!(miss.exit_code, 2);

        // The nothing-stored path echoes the typed name too.
        let bare = resolve(&empty, escape).expect_err("unknown");
        assert!(!bare.text.contains('\u{1b}'), "{}", bare.text);

        // A stored name that somehow holds an escape is sanitized when it is LISTED.
        let hostile = Rows(vec![row("de\u{1b}[2Jsigner", "allow stripe.get_charge\n")]);
        let listed = resolve(&hostile, "absent").expect_err("unknown");
        assert!(!listed.text.contains('\u{1b}'), "{}", listed.text);
        assert!(!render_rows(&hostile.0, None).contains('\u{1b}'));
    }

    #[test]
    fn a_hit_returns_the_stored_body_verbatim() {
        let rows = Rows(vec![
            row("designer", "allow stripe.get_charge\n"),
            row("builder", "allow stripe.refund where amount <= 5000\n"),
        ]);
        let found = resolve(&rows, "builder").expect("stored");
        assert_eq!(
            found.rules_text,
            "allow stripe.refund where amount <= 5000\n"
        );
        // Surrounding whitespace is not a different key.
        assert_eq!(
            resolve(&rows, "  builder ").expect("stored").name,
            "builder"
        );
    }

    #[test]
    fn the_list_renders_aligned_columns_and_says_so_when_empty() {
        let rows = [
            row("designer", "allow stripe.get_charge\n"),
            row("b", "a\nb\n"),
        ];
        let text = render_rows(&rows, None);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[0].starts_with("PRESET"), "{text}");
        let column = lines[0].find("RULES").expect("a rules column");
        for line in &lines[1..] {
            assert!(line.len() > column, "{text}");
        }

        let empty = run_preset_list(&Rows(Vec::new()), None);
        assert_eq!(empty.exit_code, 0);
        assert!(empty.text.contains("doc apply"), "{}", empty.text);
    }

    /// The listing marks the profile the daemon is serving RIGHT NOW, and marks nothing when the
    /// live corpus is not one of these bodies. The mark is derived from the daemon's read-time
    /// join — no row of this table records it.
    #[test]
    fn the_listing_marks_the_row_the_daemon_is_serving() {
        let rows = Rows(vec![
            row("designer", "allow stripe.get_charge\n"),
            row("builder", "allow stripe.refund where amount <= 5000\n"),
        ]);

        let marked = run_preset_list(&rows, Some("builder"));
        let lines: Vec<&str> = marked.text.lines().collect();
        assert!(!lines[1].contains(LIVE_MARKER), "{}", marked.text);
        assert!(lines[2].contains(LIVE_MARKER), "{}", marked.text);
        assert_eq!(
            marked.text.matches(LIVE_MARKER).count(),
            1,
            "{}",
            marked.text
        );

        // Nothing stored is live: no row is marked.
        let unmarked = run_preset_list(&rows, None);
        assert!(!unmarked.text.contains(LIVE_MARKER), "{}", unmarked.text);

        // A live name that is not stored marks nothing either.
        let absent = run_preset_list(&rows, Some("designer-2"));
        assert!(!absent.text.contains(LIVE_MARKER), "{}", absent.text);
    }

    /// The exported document must be one `doc apply` accepts back: the round trip is the whole
    /// point of export, so it is checked here rather than assumed.
    #[test]
    fn an_exported_document_parses_back_to_the_exact_body() {
        let body = "allow stripe.refund where amount <= 5000\n";
        let rendered = render_template(&AuthorityMarker::none(), body.as_bytes()).expect("render");
        let parsed = crate::cermet_document::ManagedDocument::parse(&rendered).expect("parse");
        assert_eq!(parsed.body(), body);
        assert!(parsed.marker().is_none(), "a profile exports unpinned");
    }

    #[test]
    fn export_refuses_to_clobber_and_names_the_flag_that_overrides_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rows = Rows(vec![row("designer", "allow stripe.get_charge\n")]);
        let target = ExportTarget::Directory(dir.path().to_path_buf());

        let first = run_preset_export(&rows, "designer", &target, false);
        assert_eq!(first.exit_code, 0, "{}", first.text);
        assert!(dir.path().join("CERMET_designer.md").is_file());

        let second = run_preset_export(&rows, "designer", &target, false);
        assert_eq!(second.exit_code, 2, "{}", second.text);
        assert!(second.text.contains("--force"), "{}", second.text);

        let forced = run_preset_export(&rows, "designer", &target, true);
        assert_eq!(forced.exit_code, 0, "{}", forced.text);
    }

    #[test]
    fn export_to_an_exact_path_uses_that_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rows = Rows(vec![row("designer", "allow stripe.get_charge\n")]);
        let path = dir.path().join("elsewhere.md");
        let out = run_preset_export(&rows, "designer", &ExportTarget::File(path.clone()), false);
        assert_eq!(out.exit_code, 0, "{}", out.text);
        assert!(path.is_file());
    }
}
