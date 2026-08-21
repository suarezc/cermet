//! `docs/FIELDS.md` is the field reference: every key the operator-facing surfaces print, with what
//! it means. A reference that drifts from the code is worse than none — it teaches a vocabulary the
//! binary no longer speaks — so the correspondence is enforced here rather than by review.
//!
//! The test holds three things against each other:
//!
//! 1. **The DERIVED inventory** — the serde field names of the typed views the CLI prints as JSON
//!    (`run`, `run --ask-only`, `log <request_id>`, `artifact`). These are read out of the types
//!    themselves by serializing a fully-populated sample and collecting its object keys, so a
//!    renamed or added member of any of those structs shows up here with no list to update.
//! 2. **The DECLARED inventory** — [`LINE_SURFACE_FIELDS`], the keys of the surfaces that render as
//!    labelled lines rather than as a serialized struct (`doc`, `rules`, `preset`, `check`,
//!    `connect`, `update`, the relay objects the core authors, the audit report). Each group names
//!    its render site so the list has a maintenance anchor. There is no struct to introspect for
//!    these — the text is assembled with `format!` — so a list adjacent to the extraction check
//!    below is the proportionate answer.
//! 3. **The DOCUMENTED set** — the field names `docs/FIELDS.md` defines, parsed out of the first
//!    column of its `| field | meaning |` tables.
//!
//! [`every_printed_field_is_documented_and_every_documented_field_is_printed`] asserts (1 ∪ 2) == (3)
//! in both directions. [`no_printed_key_escapes_the_inventory`] then scans the CLI's own render
//! sites for `key: ` shapes and requires each one to be either in the inventory or explicitly
//! classified as prose in [`NOT_A_FIELD`] — so a newly printed key cannot quietly appear undocumented.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

// ---------------------------------------------------------------------------------------------
// 2. The declared inventory: surfaces whose text is assembled line by line.
// ---------------------------------------------------------------------------------------------

/// Every field name printed by a labelled-line surface, grouped by render site.
///
/// A group's comment names the file that prints it. When that file gains or renames a printed key,
/// this list and `docs/FIELDS.md` both have to move, and the test below says so by name.
const LINE_SURFACE_FIELDS: &[(&str, &[&str])] = &[
    // crates/cermet-cli/src/reconciliation.rs — the `doc` noun: status, check, init, diff, export,
    // apply, and the preset/body apply the `preset` noun reuses.
    (
        "doc",
        &[
            "state",
            "document",
            "candidate",
            "marker",
            "live",
            "live_state",
            "canonical",
            "lockdown",
            "rules",
            "write",
            "durability",
            "mode",
            "interference",
            "final_file",
            "initialized",
            "live_changed",
            "exported_live",
            "prior_marker",
            "repository",
            "git_branch",
            "git_head",
            "old_live",
            "new_live",
            "result",
            "commit_resolution",
            "receipt",
            "occurrence_id",
            "acceptance_path",
            "marker_update",
            "presence",
            "authority_mutation",
            "preset",
            "source",
            "staging_token",
        ],
    ),
    // crates/cermet-cli/src/rule_cli.rs — the `rules` mutation receipt.
    ("rules", &["receipt_state", "committed", "document_sync"]),
    // crates/cermet-cli/src/preset.rs — `preset list` columns and the export receipt.
    ("preset", &["stored", "exported"]),
    // crates/cermet-cli/src/connect.rs — the stored-credential receipt.
    ("connect", &["reference", "replaced"]),
    // crates/cermet-cli/src/update.rs + update_check.rs — the release plan and the recorded
    // daily-check state.
    (
        "update",
        &[
            "sha256",
            "verification",
            "available",
            "checked_at",
            "running",
            "security",
            "notes",
            "problem",
        ],
    ),
    // crates/cermet-cli/src/mcp_bridge/mod.rs — the catalog's per-verb response line, and the two
    // keys the MCP text projection of a decision adds over the JSON one.
    (
        "catalog and the MCP projection",
        &["returns", "errors", "alternative", "authority"],
    ),
    // crates/cermet-core/src/broker/relay.rs — the `relay` object a relay verb's receipt carries.
    (
        "relay object",
        &["api_base", "invocation", "ttl_secs", "expires_at"],
    ),
    // crates/cermet-core/src/relay.rs, `RelaySession::receipt` — the session's terminal record,
    // rendered verbatim under `log <request_id>`.
    (
        "relay session receipt",
        &[
            "opened_at",
            "hops",
            "refusals",
            "burned_method",
            "burned_target",
            "deployment_id",
            "deployment_url",
        ],
    ),
    // crates/cermet-core/src/audit.rs, `IntegrityReport` — what `audit-verify` prints.
    ("audit-verify", &["event_count", "verified", "event_types"]),
];

/// Keys that match the printed-key shape at a CLI render site but are not fields: message prefixes
/// naming a command or a severity, and the labels the artifact and catalog renders use for values
/// documented under their own names (`span:` prints `unit`/`start`/`end`; `note:` prints
/// `frame_truncated`; `fields:`/`response:` head the catalog legends).
const NOT_A_FIELD: &[&str] = &[
    "apply",
    "cermet",
    "check",
    "connect",
    "cutover",
    "error",
    "executed",
    "export",
    "fields",
    "init",
    "log",
    "note",
    "refused",
    "response",
    "run",
    "setup",
    "span",
    "then",
    "unreadable",
    "update",
    "warning",
];

// ---------------------------------------------------------------------------------------------
// 1. The derived inventory: serde keys of the typed views the CLI prints as JSON.
// ---------------------------------------------------------------------------------------------

/// Collect the object keys of a sample value, one level deep, plus the keys of any object member
/// this reference documents as fields in its own right (`wire_stats`, `envelope`).
fn keys_of(sample: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(object) = sample.as_object() else {
        panic!("a sample view must serialize as an object");
    };
    for (key, value) in object {
        out.insert(key.clone());
        if matches!(key.as_str(), "wire_stats" | "envelope") {
            if let Some(nested) = value.as_object() {
                out.extend(nested.keys().cloned());
            }
        }
    }
    out
}

/// The serde field names of every typed view the CLI prints as JSON, read from the types.
///
/// Each sample populates EVERY optional member: these views omit `None` on the wire, so a sample
/// with a `None` in it would silently drop that field from the inventory and let it go undocumented.
fn derived_fields() -> BTreeSet<String> {
    use cermet_lang::types::{
        DecidedRequestView, DeniedRequestView, EffectOutcome, ExecutionEvidenceView,
        ExecutionResult, ReceiptEnvelope, RelayHopView, RequestEvidenceView, WireStats,
    };

    let mut out = BTreeSet::new();

    // `run --ask-only`: the decision receipt, projected through the wire type that cannot carry a
    // grant id.
    let decision = cermet_ipc::wire::AgentRequestOutcome {
        request_id: "req_0".into(),
        decision: cermet_lang::types::Decision::Deny,
        reason: "r".into(),
        budget_exceeded: Some(cermet_lang::types::BudgetWindow::Hour),
        hint: Some("h".into()),
        effect_id: Some("eff_0".into()),
        authority_kind: Some(cermet_lang::types::AuthorityKind::Sentence),
    };
    out.extend(keys_of(
        &serde_json::to_value(&decision).expect("a decision serializes"),
    ));

    // `run` / `run --resume`: the execution receipt. `kind` is the enum tag the outcome carries.
    let execution = ExecutionResult {
        ok: true,
        provider: "p".into(),
        action: "a".into(),
        effect_id: Some("eff_0".into()),
        effect_outcome: Some(EffectOutcome::Succeeded),
        result: json!({}),
        artifact: Some("art_0".into()),
        wire_stats: Some(WireStats {
            total_bytes: 1,
            kept_bytes: 1,
        }),
        envelope: ReceiptEnvelope::stamp("req_0", serde_json::Map::new()),
    };
    out.extend(keys_of(
        &serde_json::to_value(&execution).expect("an execution result serializes"),
    ));
    out.insert("kind".to_string());

    let event = ExecutionEvidenceView {
        event_type: "provider_action_succeeded".into(),
        resource_binding: Some("hmac-sha256:00".into()),
        authority_digest: Some("sha256:00".into()),
        outcome: Some("ok".into()),
        mutation_invoked: Some(true),
        effect_outcome: Some("succeeded".into()),
        result: json!({}),
    };
    out.extend(keys_of(
        &serde_json::to_value(&event).expect("an evidence event serializes"),
    ));

    let hop = RelayHopView {
        event_type: "relay_request_forwarded".into(),
        at: "2026-01-01T00:00:00Z".into(),
        provider: Some("p".into()),
        action: Some("a".into()),
        grant_id: Some("g_0".into()),
        method: Some("POST".into()),
        target: Some("/x".into()),
        upstream_status: Some(200),
        reason: Some("bind_mismatch".into()),
        effect: Some(true),
        response_bytes: Some(1),
        burned: Some(true),
        closed: Some("burned".into()),
    };
    out.extend(keys_of(
        &serde_json::to_value(&hop).expect("a relay hop serializes"),
    ));

    // `log <request_id>`, executed: the verified execution evidence and its two nested projections.
    // Both vectors are populated: `relay_hops` is skipped when empty, so an empty sample would drop
    // the field out of the inventory and let it go undocumented.
    let evidence = RequestEvidenceView {
        request_id: "req_0".into(),
        grant_id: "g_0".into(),
        provider: "p".into(),
        action: "a".into(),
        resource: json!({}),
        status: "executed".into(),
        decision: "allow".into(),
        integrity_ok: true,
        justification: Some("j".into()),
        effect_id: Some("eff_0".into()),
        effect_outcome: Some(EffectOutcome::Succeeded),
        events: vec![event.clone()],
        relay_hops: vec![hop.clone()],
        relay_session: Some(json!({})),
    };
    out.extend(keys_of(
        &serde_json::to_value(&evidence).expect("an evidence view serializes"),
    ));

    // `log <request_id>`, decided: what `run --ask-only` leaves behind.
    let decided = DecidedRequestView {
        request_id: "req_0".into(),
        provider: "p".into(),
        action: "a".into(),
        resource: json!({}),
        decision: "allow".into(),
        status: "approved".into(),
        matched_rule: Some("allow p.a".into()),
        authority_fingerprint: Some("sha256:00".into()),
        justification: Some("j".into()),
        created_at: "2026-01-01T00:00:00Z".into(),
        principal_id: Some("uid:0".into()),
        principal_label: Some("root".into()),
        integrity_ok: true,
        next: "cermet run --resume req_0".into(),
    };
    out.extend(keys_of(
        &serde_json::to_value(&decided).expect("a decided view serializes"),
    ));

    // `log <request_id>`, denied: the recorded refusal.
    let denied = DeniedRequestView {
        request_id: "req_0".into(),
        provider: "p".into(),
        action: "a".into(),
        resource: json!({}),
        decision: "deny".into(),
        reason: "r".into(),
        deny_reason: Some(cermet_lang::sentence::DenyReason::NoMatchingRule),
        justification: Some("j".into()),
        created_at: "2026-01-01T00:00:00Z".into(),
        session_id: Some("sess_0".into()),
        authority_fingerprint: Some("sha256:00".into()),
        principal_id: Some("uid:0".into()),
        principal_label: Some("root".into()),
        request_model: Some("m".into()),
    };
    out.extend(keys_of(
        &serde_json::to_value(&denied).expect("a denied view serializes"),
    ));

    // `artifact <handle>`: the stored span.
    let span = cermet_ipc::wire::ArtifactSpan {
        handle: "art_0".into(),
        digest: "sha256:00".into(),
        size: 1,
        stored_size: 1,
        truncated: false,
        unit: "bytes".into(),
        start: 0,
        end: 1,
        content: "x".into(),
        path: Some("$.a".into()),
        frame_truncated: false,
    };
    out.extend(keys_of(
        &serde_json::to_value(&span).expect("an artifact span serializes"),
    ));

    out
}

// ---------------------------------------------------------------------------------------------
// 3. The documented set.
// ---------------------------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <root>/crates/cermet-cli.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels under the workspace root")
        .to_path_buf()
}

fn fields_doc_path() -> PathBuf {
    repo_root().join("docs").join("FIELDS.md")
}

/// A field name as this reference spells one: lowercase, digits, underscores.
fn is_field_name(token: &str) -> bool {
    !token.is_empty()
        && token.starts_with(|c: char| c.is_ascii_lowercase())
        && token
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The field names `docs/FIELDS.md` defines: every backticked token in the first column of a table
/// whose header column is `field`. Value tables (`| value | meaning |`) define vocabulary rather
/// than fields and are deliberately not read here.
fn documented_fields(doc: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_fence = false;
    let mut in_field_table = false;
    for line in doc.lines() {
        if line.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if !line.starts_with('|') {
            in_field_table = false;
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        let Some(first) = cells.first() else {
            continue;
        };
        if first.eq_ignore_ascii_case("field") {
            in_field_table = true;
            continue;
        }
        // The alignment row under a header.
        if first.chars().all(|c| c == '-' || c == ':') && !first.is_empty() {
            continue;
        }
        if !in_field_table {
            continue;
        }
        for quoted in backticked(first) {
            for token in quoted.split(',') {
                let token = token.trim().trim_end_matches(':');
                if is_field_name(token) {
                    out.insert(token.to_string());
                }
            }
        }
    }
    out
}

/// Every backtick-delimited run in `text`.
fn backticked(text: &str) -> Vec<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The assertions.
// ---------------------------------------------------------------------------------------------

fn inventory() -> BTreeSet<String> {
    let mut out = derived_fields();
    for (_, group) in LINE_SURFACE_FIELDS {
        out.extend(group.iter().map(|f| f.to_string()));
    }
    out
}

fn joined(names: &BTreeSet<String>) -> String {
    names.iter().cloned().collect::<Vec<_>>().join(", ")
}

#[test]
fn every_printed_field_is_documented_and_every_documented_field_is_printed() {
    let doc_path = fields_doc_path();
    let doc = std::fs::read_to_string(&doc_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", doc_path.display()));
    let documented = documented_fields(&doc);
    let printed = inventory();

    let undocumented: BTreeSet<String> = printed.difference(&documented).cloned().collect();
    assert!(
        undocumented.is_empty(),
        "these printed fields are not documented in {}: {}\n\
         add a `| `<field>` | what it means |` row to that surface's field table.",
        doc_path.display(),
        joined(&undocumented)
    );

    let stale: BTreeSet<String> = documented.difference(&printed).cloned().collect();
    assert!(
        stale.is_empty(),
        "{} documents these fields, which nothing prints: {}\n\
         either the field was renamed or removed (update the doc), or it is printed by a surface \
         missing from this test's LINE_SURFACE_FIELDS inventory (add it there, with its render site).",
        doc_path.display(),
        joined(&stale)
    );
}

/// Walk the CLI's own render sites for printed `key: ` shapes. Every one must be an inventoried
/// field or explicitly classified as prose — so a new printed key cannot arrive undocumented and
/// unnoticed.
#[test]
fn no_printed_key_escapes_the_inventory() {
    let src = repo_root().join("crates").join("cermet-cli").join("src");
    let mut printed_keys: BTreeSet<String> = BTreeSet::new();
    collect_printed_keys(&src, &mut printed_keys);
    assert!(
        printed_keys.len() > 40,
        "the render-site scan found only {} keys — the extraction stopped matching, which would \
         make this test vacuous",
        printed_keys.len()
    );

    let known = inventory();
    let prose: BTreeSet<String> = NOT_A_FIELD.iter().map(|s| s.to_string()).collect();
    let unclassified: BTreeSet<String> = printed_keys
        .difference(&known)
        .filter(|key| !prose.contains(*key))
        .cloned()
        .collect();
    assert!(
        unclassified.is_empty(),
        "these keys are printed by a CLI render site but are neither documented fields nor \
         classified as prose: {}\n\
         document each in {} and add it to LINE_SURFACE_FIELDS, or — if it is a message prefix or \
         a label rather than a field — add it to NOT_A_FIELD.",
        joined(&unclassified),
        fields_doc_path().display()
    );
}

/// Recursively collect `"<key>: ` and `\n<key>: ` shapes from the crate's non-test sources.
fn collect_printed_keys(dir: &Path, out: &mut BTreeSet<String>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {dir:?}: {e}"));
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            collect_printed_keys(&path, out);
            continue;
        }
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        // `tests.rs` files are fixtures, not render sites.
        if path.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("a readable source file");
        // Drop the file's own `#[cfg(test)] mod tests` tail, whose fixtures are not output.
        let source = match source.find("#[cfg(test)]\nmod tests") {
            Some(cut) => &source[..cut],
            None => &source[..],
        };
        out.extend(printed_keys_in(source));
    }
}

/// The `key` of every `"key: ` / `\nkey: ` shape in one source file — the two ways this crate
/// starts a printed `key: value` line.
fn printed_keys_in(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes: Vec<char> = source.chars().collect();
    for (index, window) in bytes.windows(2).enumerate() {
        let starts_line = window[0] == '"' || (window[0] == '\\' && window[1] == 'n');
        if !starts_line {
            continue;
        }
        let mut cursor = if window[0] == '"' {
            index + 1
        } else {
            index + 2
        };
        let start = cursor;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_lowercase()
                || bytes[cursor].is_ascii_digit()
                || bytes[cursor] == '_')
        {
            cursor += 1;
        }
        // `key: ` — at least two characters, a colon, then at least one space.
        if cursor - start < 2 || cursor + 1 >= bytes.len() || bytes[cursor] != ':' {
            continue;
        }
        if bytes[cursor + 1] != ' ' {
            continue;
        }
        let key: String = bytes[start..cursor].iter().collect();
        if is_field_name(&key) {
            out.push(key);
        }
    }
    out
}
