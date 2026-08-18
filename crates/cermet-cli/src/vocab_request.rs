//! The `request_vocabulary` MCP tool's capture core — the VOCABULARY gap, and nothing else.
//!
//! Two different walls end an agent's attempt to do something, and they have different answers:
//!
//! * **Authority gap** — the verb EXISTS but no standing sentence admits this ask. That already has
//!   a channel: the daemon's deny carries a widening suggestion, addressed to the OPERATOR, who
//!   applies it with `cermet rules allow`. Nothing here touches that path.
//! * **Vocabulary gap** — the verb, or a field on it, does not exist AT ALL: the ask cannot even be
//!   expressed, so there is no deny to widen. That is what this module validates: a feature
//!   request addressed to the vendor.
//!
//! Nothing is stored here and nothing is transmitted. The tool hands the agent a formed request to
//! relay to its operator — "the agent tells the operator" is the native mechanism — and reports the
//! event to the daemon, which appends it to the same free-form event log `broker_start` writes to.
//! A local spool for a transmission channel that does not exist was the first design of this and
//! was deleted: the data's consumer is the vendor, the operator is the courier, and the daemon's
//! own log was the store all along.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

/// Cap on each free-text field, in characters, AFTER whitespace compaction. Over the cap is a
/// refusal rather than a silent truncation: a form is a small structured thing, and quietly eating
/// the half of the rationale that explained the ask helps nobody. The daemon re-checks this bound
/// on its own side of the socket.
pub const MAX_TEXT_CHARS: usize = 1000;

/// Cap on an identifier (provider / verb / field name). Also re-checked daemon-side.
pub const MAX_NAME_CHARS: usize = 64;

/// What a caller supplies. Free-form on the way in; [`capture`] is the only way to turn one into a
/// validated request, and it validates every field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestForm {
    pub provider: String,
    /// The wanted verb's action name. Alone it means "this verb does not exist"; together with
    /// `wanted_field` it names the EXISTING verb the wanted field belongs on.
    pub wanted_verb: Option<String>,
    /// A wanted field on the verb named by `wanted_verb`.
    pub wanted_field: Option<String>,
    /// The ask that prompted this — what the agent was actually trying to do.
    pub ask: Option<String>,
    /// Free text: why it matters. This channel is TO the vendor, so prose is acceptable content —
    /// but it still never carries a credential (see [`credential_shape`]).
    pub rationale: Option<String>,
}

/// A validated vocabulary request. Every string here has been through the chokepoint: single-line,
/// terminal-safe, bounded, and credential-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VocabularyRequest {
    pub provider: String,
    pub wanted_verb: Option<String>,
    pub wanted_field: Option<String>,
    pub ask: Option<String>,
    pub rationale: Option<String>,
}

/// Which wall the ask actually hit, as computed against the live catalog. BOTH outcomes are
/// reported to the daemon: a refused authority-gap probe says an agent could not tell the two
/// apart, which is signal about the product, not noise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gap {
    /// The word does not exist. This is the channel's subject.
    Vocabulary,
    /// The word EXISTS — so this is the deny path's business, not ours. Carries the refusal the
    /// agent is shown.
    Authority(String),
}

impl Gap {
    /// The wire/audit label. Closed vocabulary, two values.
    pub fn label(&self) -> &'static str {
        match self {
            Gap::Vocabulary => "vocabulary_gap",
            Gap::Authority(_) => "authority_gap",
        }
    }
}

/// The token-pattern set, ported from the sitting harness's credential-fragment scrub. Where that
/// scrub REDACTS — its job is to keep evidence readable — this channel REFUSES: a form carrying
/// credential-shaped material never becomes a request at all, so it never reaches the operator's
/// eyes or the daemon's log.
///
/// Named adversaries: **T2** (an agent pasting the failing invocation, key and all, into `ask`) and
/// **T1** (third-party content steering it there). Neither is stopped by asking nicely in a tool
/// description, which is why the check is structural and at the one chokepoint every field crosses.
fn credential_fragment() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)(?:sk|rk)_(?:live|test)_[A-Za-z0-9_]+",
            r"|github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+",
            r"|bearer\s+\S+",
            r"|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        ))
        .expect("the credential-fragment pattern is a literal")
    })
}

/// The byte offset of the first credential-shaped fragment in `text`, if any. The offset is enough
/// to find it in the caller's own buffer; the refusal never quotes the fragment back.
pub fn credential_shape(text: &str) -> Option<usize> {
    credential_fragment().find(text).map(|m| m.start())
}

/// Validate a form. `catalog` is the daemon's catalog frame — the dictionary of every verb that
/// exists — because "does this word exist?" is the ONE question that separates this channel from
/// the deny path.
///
/// `Err` is a form that never becomes anything: malformed, credential-shaped, or unresolvable
/// against an unreadable dictionary. `Ok` carries the validated request AND which wall it hit.
pub fn capture(form: &RequestForm, catalog: &Value) -> Result<(VocabularyRequest, Gap), String> {
    let provider = name_field(&form.provider, "provider")?;
    let wanted_verb = form
        .wanted_verb
        .as_deref()
        .map(|v| name_field(v, "verb"))
        .transpose()?;
    let wanted_field = form
        .wanted_field
        .as_deref()
        .map(|f| name_field(f, "field"))
        .transpose()?;
    if wanted_verb.is_none() && wanted_field.is_none() {
        return Err(
            "say what is missing: a verb (the whole action does not exist) or a field on \
                    an existing verb (name the verb too)"
                .into(),
        );
    }
    let ask = text_field(form.ask.as_deref(), "ask")?;
    let rationale = text_field(form.rationale.as_deref(), "rationale")?;
    let gap = classify(
        catalog,
        &provider,
        wanted_verb.as_deref(),
        wanted_field.as_deref(),
    )?;
    Ok((
        VocabularyRequest {
            provider,
            wanted_verb,
            wanted_field,
            ask,
            rationale,
        },
        gap,
    ))
}

/// The exists-vs-absent check, both ways. This is the whole discipline of the channel: a word that
/// EXISTS is an authority question, and answering it here would quietly turn a demand signal about
/// missing vocabulary into a second, useless approval path.
fn classify(
    catalog: &Value,
    provider: &str,
    wanted_verb: Option<&str>,
    wanted_field: Option<&str>,
) -> Result<Gap, String> {
    // Fail closed on the dictionary itself: with no readable catalog there is no way to tell a
    // vocabulary gap from an authority one, and reporting the wrong one is the blur this channel
    // exists to prevent.
    let Some(entries) = catalog.get("catalog").and_then(Value::as_array) else {
        return Err(
            "the verb catalog could not be read, so this ask cannot be checked against it — retry \
             once the daemon answers (a verb that EXISTS is an authority question, and that \
             difference is the whole point of this channel)"
                .into(),
        );
    };
    let Some(verb) = wanted_verb else {
        // A field with no verb has nothing to hang on: the catalog cannot say whether it exists.
        return Err(format!(
            "name the {provider} verb the field belongs on too — a field on its own cannot be \
             checked against the catalog, and an unchecked name is what this channel must not report"
        ));
    };
    let entry = catalog_entry(entries, provider, verb);
    Ok(match (entry, wanted_field) {
        // The verb exists and no field was named: this is an AUTHORITY gap, not a vocabulary one.
        (Some(_), None) => Gap::Authority(format!(
            "{provider}.{verb} already EXISTS in the catalog — that is an authority gap, not a \
             vocabulary gap. Request it normally: the decision is a definite allow, or a deny \
             carrying a widening suggestion for your operator. Relay that suggestion; do not file \
             it here."
        )),
        // The host verb does not exist either — the ask is for the VERB, without a field.
        (None, Some(field)) => Gap::Authority(format!(
            "{provider}.{verb} does not exist, so a {field:?} field on it cannot: ask for the verb \
             itself (drop the field)"
        )),
        (Some(entry), Some(field)) if entry_has_field(entry, field) => Gap::Authority(format!(
            "{provider}.{verb} already has a {field:?} field — that is an authority or usage \
             question, not a vocabulary gap. Request the verb normally and read the decision."
        )),
        _ => Gap::Vocabulary,
    })
}

/// The catalog entry for `provider.action`, if the dictionary carries one. Read against the FULL
/// dictionary (every verb that exists), never the sentence-admitted subset: a verb the corpus does
/// not admit still EXISTS, and asking us to invent it would be the blur this channel refuses.
fn catalog_entry<'a>(entries: &'a [Value], provider: &str, action: &str) -> Option<&'a Value> {
    entries.iter().find(|e| {
        e.get("provider").and_then(Value::as_str) == Some(provider)
            && e.get("action").and_then(Value::as_str) == Some(action)
    })
}

fn entry_has_field(entry: &Value, field: &str) -> bool {
    entry
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|f| f.get("name").and_then(Value::as_str) == Some(field))
}

/// An identifier: lowercased, `[a-z0-9_]`, bounded. Fail closed on anything else — a malformed name
/// cannot be checked against the catalog, and an unchecked name is exactly what this channel must
/// not report.
fn name_field(raw: &str, what: &str) -> Result<String, String> {
    let value = raw.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err(format!("{what} must not be empty"));
    }
    if value.chars().count() > MAX_NAME_CHARS {
        return Err(format!(
            "{what} must be at most {MAX_NAME_CHARS} characters"
        ));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(format!(
            "{what} must be a bare name — lowercase letters, digits and underscores only (got \
             {raw:?}); a dotted verb is spelled provider=<provider> verb=<action>"
        ));
    }
    Ok(value)
}

/// A free-text field, through the one chokepoint: compacted to a single line with nothing that can
/// move or reorder a terminal's cursor (the operator reads this text, and an agent may have been
/// steered into writing it — T1), bounded, and REFUSED outright if credential-shaped.
fn text_field(raw: Option<&str>, what: &str) -> Result<Option<String>, String> {
    let Some(raw) = raw else { return Ok(None) };
    let value = one_line(raw);
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > MAX_TEXT_CHARS {
        return Err(format!(
            "{what} must be at most {MAX_TEXT_CHARS} characters — say what is missing, not the \
             whole transcript"
        ));
    }
    if let Some(offset) = credential_shape(&value) {
        return Err(format!(
            "refused: the {what} carries credential-shaped material at offset {offset}. This form \
             goes to your operator and to the vendor — rewrite it without the token (name the verb \
             and what you were trying to do; a key is never part of that)."
        ));
    }
    Ok(Some(value))
}

/// Compact to ONE line, dropping every character that can affect a terminal.
///
/// The predicate is [`crate::receipt_log::terminal_affecting`] — the SAME one every agent-authored
/// string the CLI renders goes through. It was a hand-rolled `is_control()` subset here until
/// review showed bidi overrides (U+202E and friends) walking straight through it into the
/// operator's terminal; there is one definition of "terminal-affecting" and this is a caller of it,
/// not a second opinion.
fn one_line(s: &str) -> String {
    let swept: String = s
        .chars()
        .map(|c| {
            if crate::receipt_log::terminal_affecting(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    swept.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The formed request, as the agent relays it to its operator. A plain block: nothing parses this
/// back, so it is written for a human to read and forward.
pub fn render(request: &VocabularyRequest) -> String {
    let mut out = String::from("--- vocabulary request ---\n");
    out.push_str(&format!("provider: {}\n", request.provider));
    if let Some(verb) = &request.wanted_verb {
        let role = if request.wanted_field.is_some() {
            "verb (exists; the field below does not)"
        } else {
            "wanted verb (does not exist)"
        };
        out.push_str(&format!("{role}: {verb}\n"));
    }
    if let Some(field) = &request.wanted_field {
        out.push_str(&format!("wanted field (does not exist): {field}\n"));
    }
    if let Some(ask) = &request.ask {
        out.push_str(&format!("the ask: {ask}\n"));
    }
    if let Some(rationale) = &request.rationale {
        out.push_str(&format!("why it matters: {rationale}\n"));
    }
    out.push_str(&format!(
        "cermet: {} on {}-{}\n",
        cermet_ipc::BUILD_ID,
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    out.push_str("--------------------------");
    out
}

#[cfg(test)]
mod tests;
