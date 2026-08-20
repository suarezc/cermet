//! Stored authority profiles, keyed by an opaque name.
//!
//! A preset is a NAME and a canonical corpus body — nothing else. The name carries no meaning to
//! the broker: it is a key, not a path, a repository, or a reference to anything on the box.
//!
//! The table is written on ONE path: the daemon's sentence commit, when the ceremony that installed
//! that body carried a preset name. There is no standalone write, so a stored profile is always a
//! body some operator staged, reviewed, and attested — the same evidence a live corpus carries.
//! Reading one back and applying it runs that ceremony again from the top.
//!
//! Nothing here is credential material, so it lives in the broker's own state store and never in
//! the vault. Nothing here is authority either: a stored body grants nothing until it is committed.

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util::now_rfc3339;

/// The longest preset name the daemon will store. Names are keys typed at a terminal, not prose.
pub const MAX_PRESET_NAME_BYTES: usize = 64;

/// Names the operator CLI cannot spell as a profile, because its own `preset` subcommands take
/// those words: a profile stored under one could never be applied. Enforced HERE as well as in the
/// client preflight, so the table can never hold a key no surface can reach.
pub const RESERVED_NAMES: &[&str] = &["list", "export"];

/// One stored profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPreset {
    pub name: String,
    /// The exact canonical corpus text that was committed under this key.
    pub rules_text: String,
    pub rule_count: usize,
    pub updated_at: String,
}

/// The accepted name alphabet, enforced HERE because the daemon is the enforcement point: a name
/// reaches the table only through this check, whatever a client did or did not do first.
///
/// The alphabet is deliberately narrow. A key that can hold a path separator, a shell
/// metacharacter, or a terminal escape is a key that has to be re-sanitized at every surface that
/// ever prints it; refusing those at the one write path removes that obligation from all of them.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Invalid("a preset name must not be empty".into()));
    }
    if name.len() > MAX_PRESET_NAME_BYTES {
        return Err(Error::Invalid(format!(
            "a preset name must be at most {MAX_PRESET_NAME_BYTES} characters"
        )));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(Error::Invalid(
            "a preset name may hold only letters, digits, `_` and `-`".into(),
        ));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(Error::Invalid(format!(
            "`{name}` is reserved: it is an operator-CLI subcommand of the preset noun, so a \
             profile stored under it could never be applied"
        )));
    }
    Ok(())
}

pub fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS presets (
            name        TEXT PRIMARY KEY,
            rules_text  TEXT NOT NULL,
            rule_count  INTEGER NOT NULL,
            updated_at  TEXT NOT NULL
        );",
    )?;
    Ok(())
}

/// Store one profile under `name`, replacing whatever that key held. Re-committing a key is how a
/// profile is edited: there is one body per name, and it is the last one attested.
pub fn store(
    conn: &Connection,
    name: &str,
    rules_text: &str,
    rule_count: usize,
) -> Result<StoredPreset> {
    validate_name(name)?;
    let updated_at = now_rfc3339();
    conn.execute(
        "INSERT INTO presets (name, rules_text, rule_count, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(name) DO UPDATE SET
            rules_text=excluded.rules_text,
            rule_count=excluded.rule_count,
            updated_at=excluded.updated_at",
        params![name, rules_text, rule_count as i64, updated_at],
    )?;
    Ok(StoredPreset {
        name: name.to_string(),
        rules_text: rules_text.to_string(),
        rule_count,
        updated_at,
    })
}

/// Every stored profile, name-ordered so a rendered list is stable across calls.
pub fn list(conn: &Connection) -> Result<Vec<StoredPreset>> {
    let mut stmt =
        conn.prepare("SELECT name, rules_text, rule_count, updated_at FROM presets ORDER BY name")?;
    let rows = stmt.query_map([], |row| {
        Ok(StoredPreset {
            name: row.get(0)?,
            rules_text: row.get(1)?,
            rule_count: row.get::<_, i64>(2)?.max(0) as usize,
            updated_at: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn a_key_holds_exactly_one_body_and_recommitting_it_replaces_that_body() {
        let conn = store_conn();
        store(&conn, "designer", "allow stripe.search_customers\n", 1).unwrap();
        store(&conn, "designer", "allow stripe.get_charge\n", 1).unwrap();
        let rows = list(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rules_text, "allow stripe.get_charge\n");
    }

    #[test]
    fn profiles_are_listed_in_a_stable_name_order() {
        let conn = store_conn();
        for name in ["reviewer", "builder", "designer"] {
            store(&conn, name, "allow stripe.get_charge\n", 1).unwrap();
        }
        let names: Vec<String> = list(&conn)
            .unwrap()
            .into_iter()
            .map(|row| row.name)
            .collect();
        assert_eq!(names, ["builder", "designer", "reviewer"]);
    }

    #[test]
    fn the_name_alphabet_is_enforced_at_the_write_path() {
        for accepted in [
            "designer",
            "CERMET_BUILDER",
            "q3r982",
            "a-b_c",
            "x",
            // Only the EXACT subcommand words are reserved.
            "lists",
            "exporter",
            "List",
            "Export",
        ] {
            validate_name(accepted).unwrap_or_else(|e| panic!("{accepted:?}: {e}"));
        }
        for refused in [
            "",
            "de signer",
            "../etc/passwd",
            "a/b",
            "des\u{1b}[2Jigner",
            "naïve",
            "a.b",
            "$(whoami)",
            "list",
            "export",
        ] {
            assert!(
                validate_name(refused).is_err(),
                "{refused:?} must be refused"
            );
        }
        // A reserved word is refused for a reason the operator can act on, not as a malformed name.
        for reserved in RESERVED_NAMES {
            let refusal = validate_name(reserved).expect_err("reserved").to_string();
            assert!(refusal.contains("reserved"), "{reserved}: {refusal}");
            assert!(refusal.contains(reserved), "{reserved}: {refusal}");
        }
        assert!(validate_name(&"a".repeat(MAX_PRESET_NAME_BYTES)).is_ok());
        assert!(validate_name(&"a".repeat(MAX_PRESET_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn a_refused_name_writes_nothing() {
        let conn = store_conn();
        assert!(store(&conn, "a b", "allow stripe.get_charge\n", 1).is_err());
        assert!(list(&conn).unwrap().is_empty());
    }
}
