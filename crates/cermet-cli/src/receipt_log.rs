//! The daemon-native "morning receipt" rendered from the ctl `History` RPC.

use cermet_lang::{EffectOutcome, EffectState, GrantView, RelayHopView};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{CliError, CliOutput};

/// How many rows a bare `cermet log` renders.
///
/// An unwindowed dump is expensive to read: it costs thousands of tokens and buries the reader in
/// other sessions' activity. The log is read by agents far more often than by a human at a
/// terminal, so the DEFAULT is a window. It is never a silent cap: [`window_note`] says how many
/// rows exist and how to widen.
pub const LOG_DEFAULT_ROWS: usize = 100;

/// The narrowing one `cermet log` invocation asks for. Filters apply FIRST; the window applies to
/// what survives them (unless `all`, which is the old full dump).
#[derive(Debug, Default, Clone, Copy)]
pub struct LogFilter<'a> {
    /// Only rows at or after this RFC3339 instant — the shape the log itself prints.
    pub since: Option<&'a str>,
    /// Only this provider's rows.
    pub provider: Option<&'a str>,
    /// Only the refusals (or, on the hop view, the refused/failed hops).
    pub denied_only: bool,
    /// Only the rows whose relay grant BURNED — the sibling of `denied_only` one layer down.
    /// A denial is authority refusing; a burn is authority having said yes and the effect layer
    /// ending the session anyway, which is the harder failure to find by eye.
    pub burned_only: bool,
    /// Every row, unwindowed.
    pub all: bool,
}

/// The honest tail on a windowed render: what was shown, what exists, and how to widen.
///
/// Counts and command text only — no request id and no grant handle. A window note names no row.
fn window_note(shown: usize, total: usize, what: &str) -> String {
    format!(
        "… showing the {shown} most recent of {total} {what} — `--all` for every one, or narrow \
         with `--since <RFC3339>` / `--provider <name>`"
    )
}

/// Apply the default window to already-filtered, newest-first rows, returning the render plus the
/// honest truncation line when it bit.
fn windowed<T>(
    rows: &mut Vec<T>,
    filter: &LogFilter<'_>,
    what: &str,
    render: impl Fn(&[T]) -> String,
) -> String {
    let total = rows.len();
    if !filter.all && total > LOG_DEFAULT_ROWS {
        rows.truncate(LOG_DEFAULT_ROWS);
        return format!(
            "{}\n{}",
            render(rows),
            window_note(LOG_DEFAULT_ROWS, total, what)
        );
    }
    render(rows)
}

/// A request outcome counts as "denied" for the `--denied-only` filter iff its decision is one of the
/// non-minting refusal classes (or the lifecycle landed on a denied status).
fn is_denied(row: &GrantView) -> bool {
    matches!(
        row.decision.as_str(),
        "deny" | "unsupported" | "unregistered"
    ) || row.status == "denied"
}

/// A row counts as "burned" for `--burned` iff the daemon's own derivation says so. The CLI does not
/// re-derive it from anything: `effect_state` is the one answer, and the row's suffix and this
/// filter read the same field so they can never disagree.
fn is_burned(row: &GrantView) -> bool {
    row.effect_state == Some(EffectState::Burned)
}

/// The effect-layer suffix a row carries after everything the decision layer had to say: what became
/// of the effect that decision authorized.
///
/// `None` renders NOTHING, and that is the design. A window still in flight, a request decided and
/// never executed, a refusal that ran nothing, and an effect whose failure the row already names
/// with `— effect failed: <class>` all say nothing here. Silence means the record does not
/// determine an outcome; it never means one was determined and withheld.
fn effect_suffix(row: &GrantView) -> Option<String> {
    let state = row.effect_state?;
    Some(match (state, &row.burn_reason) {
        // The class that ended it, in the reason word the hop log and the session receipt already
        // spell it with — so one grep matches all three.
        (EffectState::Burned, Some(reason)) => format!("→burned({})", one_line(reason)),
        _ => format!("→{}", state.as_str()),
    })
}

/// Render the daemon-native "morning receipt" from the ctl `History` rows (already newest-first):
/// time, provider.action, outcome, authenticated authorization provenance, denial reason.
/// No secret: the daemon redacts every secret-classed value before a row ever reaches this renderer.
pub fn run_log_history(history_json: &str, filter: &LogFilter<'_>) -> Result<CliOutput, CliError> {
    let since = parse_since(filter.since)?;
    let rows: Vec<GrantView> = serde_json::from_str(history_json)
        .map_err(|error| CliError::Malformed(format!("cannot decode the history view: {error}")))?;
    let mut filtered = Vec::new();
    for row in rows {
        if filter.denied_only && !is_denied(&row) {
            continue;
        }
        if filter.burned_only && !is_burned(&row) {
            continue;
        }
        if filter.provider.is_some_and(|name| row.provider != name) {
            continue;
        }
        if let Some(since) = since {
            let ts = OffsetDateTime::parse(&row.created_at, &Rfc3339).map_err(|error| {
                // `request_id` is the one public id, so it is what names the bad row —
                // the row's `grant_id` is operator-internal record data and never renders.
                CliError::Malformed(format!(
                    "history row {}.{} ({}) has an invalid timestamp: {error}",
                    one_line(&row.provider),
                    one_line(&row.action),
                    one_line(row.request_id.as_deref().unwrap_or("no request id")),
                ))
            })?;
            if ts < since {
                continue;
            }
        }
        filtered.push(row);
    }
    Ok(CliOutput {
        text: windowed(&mut filtered, filter, "rows", render_history_receipt),
        ok: true,
    })
}

/// `--since` takes ONE shape: an RFC3339 instant, exactly as the log itself prints its timestamps.
/// The error teaches that shape rather than listing alternatives that do not exist.
fn parse_since(since: Option<&str>) -> Result<Option<OffsetDateTime>, CliError> {
    since
        .map(|value| {
            OffsetDateTime::parse(value, &Rfc3339).map_err(|error| {
                CliError::Usage(format!(
                    "log --since expects an RFC3339 instant like 2026-08-03T00:00:00Z (the shape \
                     the log prints), got {value:?}: {error}"
                ))
            })
        })
        .transpose()
}

/// The relay hop view (`cermet log --hops`). The grant receipt above answers "what did
/// the daemon authorize"; this answers "what did the native client then DO with it, and why did the
/// session stop" — a question that otherwise takes copying `audit.db` out with sudo. Same
/// `--since` bound as the receipt; `--denied` narrows to the refusals.
pub fn run_log_hops(hops_json: &str, filter: &LogFilter<'_>) -> Result<CliOutput, CliError> {
    let since = parse_since(filter.since)?;
    let rows: Vec<RelayHopView> = serde_json::from_str(hops_json).map_err(|error| {
        CliError::Malformed(format!("cannot decode the relay hop view: {error}"))
    })?;
    let mut filtered = Vec::new();
    for row in rows {
        if filter.denied_only && !is_refusal(&row) {
            continue;
        }
        // The same question one layer down: on the hop view a burn is a property of ONE hop — the
        // one that ended the session — so this narrows to those rows rather than to their sessions.
        if filter.burned_only && row.burned != Some(true) {
            continue;
        }
        if filter
            .provider
            .is_some_and(|name| row.provider.as_deref() != Some(name))
        {
            continue;
        }
        if let Some(since) = since {
            let ts = OffsetDateTime::parse(&row.at, &Rfc3339).map_err(|error| {
                CliError::Malformed(format!("relay hop row has an invalid timestamp: {error}"))
            })?;
            if ts < since {
                continue;
            }
        }
        filtered.push(row);
    }
    Ok(CliOutput {
        text: windowed(&mut filtered, filter, "relay hops", render_hop_log),
        ok: true,
    })
}

/// `--denied` on the hop view: the hops that did not go through.
///
/// An outcome mismatch is deliberately NOT one of them — that hop was authorized, forwarded, and
/// answered, and calling it a refusal would tell the reader the opposite of what happened. It is
/// still a hop that ended a session, and `--burned` is the filter for those.
fn is_refusal(row: &RelayHopView) -> bool {
    matches!(
        row.event_type.as_str(),
        "relay_request_refused" | "relay_request_failed"
    )
}

/// One line per relay event, already newest-first from the daemon.
///
/// A hop line identifies itself by time + verb + target, never by the grant handle the
/// view still carries — `request_id` is the one public id, the hop view has none to render, and the
/// operator-internal handle belongs to `log <request_id>` evidence and the audit rows.
pub fn render_hop_log(rows: &[RelayHopView]) -> String {
    if rows.is_empty() {
        return "No relay hops.".into();
    }
    rows.iter()
        .map(|row| {
            let verb = match row.event_type.as_str() {
                "relay_session_opened" => "OPENED",
                "relay_request_forwarded" => "HOP",
                "relay_request_refused" => "REFUSED",
                "relay_request_failed" => "FAILED",
                // Its own word, not REFUSED: this hop was authorized, forwarded, and ANSWERED —
                // what ended the session is the answer, and an operator reading the line has a
                // landed effect to deal with rather than a request that never left.
                "relay_outcome_mismatch" => "MISMATCH",
                "relay_session_closed" => "CLOSED",
                // Never guess at an event type this renderer does not know: name it verbatim.
                other => other,
            };
            let mut line = format!("{}  {verb}", one_line(&row.at));
            if let (Some(provider), Some(action)) = (&row.provider, &row.action) {
                line.push_str(&format!(" {}.{}", one_line(provider), one_line(action)));
            }
            if let Some(method) = &row.method {
                line.push(' ');
                line.push_str(&one_line(method));
            }
            if let Some(target) = &row.target {
                line.push(' ');
                line.push_str(&one_line(target));
            }
            if let Some(status) = row.upstream_status {
                line.push_str(&format!(" — {status}"));
                if let Some(bytes) = row.response_bytes {
                    line.push_str(&format!(" ({bytes} bytes)"));
                }
            }
            if let Some(closed) = &row.closed {
                line.push_str(&format!(" — {}", one_line(closed)));
            }
            if let Some(reason) = &row.reason {
                line.push_str(&format!(" — {}", one_line(reason)));
            }
            if row.burned == Some(true) {
                line.push_str(" (burned the session)");
            }
            if row.effect == Some(true) {
                line.push_str(" [the grant's single effect]");
            }
            // What a forwarded hop carried beyond its shape's declared vocabulary. It reads as the
            // OBSERVATION it is — no refusal grammar — and the list is names only, already bounded
            // by the broker that wrote it.
            if let Some(keys) = row.undeclared_keys.as_ref().filter(|keys| !keys.is_empty()) {
                let names: Vec<String> = keys.iter().map(|key| one_line(key)).collect();
                line.push_str(&format!(" — also carried {}", names.join(", ")));
            }
            // Last, and after the burn/effect marks: the reason WORD stays where a reader's eye
            // and a `grep` both already find it, and the detail — which is a sentence, not a
            // token — follows the short columns rather than pushing them off the line.
            if let Some(detail) = &row.detail {
                line.push_str(&format!(" — {}", one_line(detail)));
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render one morning-receipt line per history row.
pub fn render_history_receipt(rows: &[GrantView]) -> String {
    if rows.is_empty() {
        return "No activity.".into();
    }
    rows.iter()
        .map(|row| {
            if !row.integrity_ok {
                return format!(
                    "{}  TAMPERED/UNTRUSTED {}.{} — authorization provenance suppressed",
                    one_line(&row.created_at),
                    one_line(&row.provider),
                    one_line(&row.action)
                );
            }
            let outcome = if is_denied(row) {
                "DENIED".to_string()
            } else {
                one_line(&row.decision).to_ascii_uppercase()
            };
            let mut line = format!(
                "{}  {} {}.{}",
                one_line(&row.created_at),
                outcome,
                one_line(&row.provider),
                one_line(&row.action)
            );
            // The list is the only door to `log <request_id>`, so the row NAMES the id it is
            // reachable by. `request_id` is the one public id; a row that carries none renders
            // none.
            if let Some(request_id) = &row.request_id {
                line.push(' ');
                line.push_str(&one_line(request_id));
            }
            // New rows are sentence-authorized. The authenticated legacy values remain renderable
            // for terminal history created before the cutover.
            match row.approved_by_kind.as_deref() {
                // An allow SHOWS the sentence that allowed it — the rule's canonical text
                // is its identity, so the receipt reads against CERMET.md directly instead of
                // naming a file position. A row the daemon stored no rule for renders
                // provenance-less; this reads what was stored, it never reconstructs a rule.
                Some("sentence") => match &row.matched_rule {
                    Some(rule) => {
                        line.push_str(&format!(" — allowed by: {}", one_line(rule)));
                        if let Some(corpus) = corpus_short(row.authority_fingerprint.as_deref()) {
                            line.push_str(&format!(" (corpus {corpus})"));
                        }
                    }
                    None => line.push_str(" — allowed by a standing sentence"),
                },
                Some("policy") => line.push_str(" — allowed by policy"),
                Some("human") => {
                    line.push_str(" — approved by ");
                    line.push_str(&one_line(row.approver.as_deref().unwrap_or("a human")));
                }
                _ => {}
            }
            // The reason rides verbatim for a denial (it says WHY) and for any allow whose rule we
            // could not name; an allow already rendered as its sentence says nothing more.
            let reason_is_rendered_rule =
                row.approved_by_kind.as_deref() == Some("sentence") && row.matched_rule.is_some();
            if let (Some(reason), false) = (&row.reason, reason_is_rendered_rule) {
                line.push_str(": ");
                line.push_str(&one_line(reason));
            }
            // The evaluator's own code beside its own prose. The sentence still says WHY in
            // words; this makes the class greppable — `cermet log --denied | grep
            // predicate_mismatch` answers "what keeps getting refused for being out of bounds",
            // which no amount of grepping the prose reliably does.
            if let Some(code) = row.deny_reason.as_ref().map(deny_code) {
                line.push_str(&format!(" [{code}]"));
            }
            // A denial says WHAT was asked for. The daemon already redacted these values
            // at write time; this renders what it was handed and only bounds the display width.
            if is_denied(row) {
                if let Some(fields) = row.resource.as_object().filter(|f| !f.is_empty()) {
                    line.push_str(" — ");
                    line.push_str(
                        &fields
                            .iter()
                            .map(|(k, v)| format!("{}={}", one_line(k), render_value(v)))
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                }
            }
            // The justification the agent had to supply to make the request at all. Bounded here
            // for width only — `log <request_id>` carries it whole. A row that carried none
            // renders nothing, not an empty pair of quotes.
            if let Some(justification) = &row.justification {
                line.push_str(&format!(
                    " — \"{}\"",
                    shorten(justification, JUSTIFICATION_SHOWN_MAX_CHARS)
                ));
            }
            // WHY a failed effect failed, in the ONE word the class is spelled with, on the line
            // that already names outcomes. `provider_auth_refused` is the operator's payoff: the
            // sentence allowed it and the key could not do it.
            if let Some(class) = row.failure_class {
                line.push_str(&format!(" — effect failed: {class}"));
            }
            if let Some(effect_outcome) = row.effect_outcome {
                let outcome = match effect_outcome {
                    EffectOutcome::PreEffect => "pre_effect; request a fresh effect",
                    EffectOutcome::Succeeded => "succeeded; do not retry",
                    EffectOutcome::DefinitelyFailed => "definitely_failed; do not retry",
                    EffectOutcome::Ambiguous => "ambiguous; retry only with the same effect handle",
                };
                line.push_str(" — effect ");
                line.push_str(outcome);
            }
            // LAST, and it is the only part of the row that answers "and then what": the decision
            // word at the head says what authority ruled, and everything between says how. A row
            // whose relay grant burned, one whose window lapsed having driven nothing, and one whose
            // deploy landed all read `ALLOW <verb>` up to here.
            if let Some(suffix) = effect_suffix(row) {
                line.push(' ');
                line.push_str(&suffix);
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The stable code word for one typed refusal — the vocabulary the receipt row carries,
/// spelled once here for the operator's own log. The rule and predicate POSITIONS the reason also
/// carries are already in the prose beside it, rendered as the one-based numbers `cermet rules`
/// prints, so this adds the class and repeats nothing.
fn deny_code(reason: &cermet_lang::sentence::DenyReason) -> &'static str {
    use cermet_lang::sentence::DenyReason as D;
    match reason {
        D::ExplicitDeny { .. } => "explicit_deny",
        D::UnresolvedDeny { .. } => "unresolved",
        D::UnknownSelector => "unknown_verb",
        D::NoMatchingRule => "no_matching_rule",
        D::UnsupportedVersion { .. } => "unsupported_version",
        D::MissingField { .. } => "missing_required_field",
        D::PredicateMismatch { .. } => "predicate_mismatch",
        D::BudgetExceeded { .. } => "budget_exceeded",
    }
}

/// The first 8 hex characters of the corpus digest — enough to tie a receipt to a `cermet rules`
/// generation, short enough to read. `None` unless the stored value is plausible hex.
fn corpus_short(fingerprint: Option<&str>) -> Option<String> {
    let value = fingerprint?.trim_start_matches("sha256:");
    (value.len() >= 8 && value.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| value[..8].to_string())
}

/// The widest a single field value renders on a one-line receipt; longer values show their readable
/// prefix. Display width only — the stored row is untouched.
const VALUE_SHOWN_MAX_CHARS: usize = 64;

/// The widest a justification renders in the LIST. `log <request_id>` always carries it whole.
const JUSTIFICATION_SHOWN_MAX_CHARS: usize = 120;

/// One line of stored text, bounded to `max` characters with an ellipsis when it is longer.
fn shorten(text: &str, max: usize) -> String {
    let text = one_line(text);
    match text.char_indices().nth(max) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text,
    }
}

/// One field value on a receipt line: a string renders bare, anything else as its compact JSON.
fn render_value(value: &serde_json::Value) -> String {
    let text = match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    shorten(&text, VALUE_SHOWN_MAX_CHARS)
}

fn one_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if terminal_affecting(character) {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Characters that can move or reorder what a terminal displays: every control character, plus the
/// bidi/directional formatting set. THE definition for the crate — agent-authored text reaches the
/// operator through several surfaces (receipt rows, vocabulary requests), and each of them calls
/// this rather than hand-rolling an `is_control()` subset that misses U+202E.
pub(crate) fn terminal_affecting(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use cermet_lang::{EffectFailureClass, EffectState};

    fn row(decision: &str, kind: Option<&str>, reason: Option<&str>, ts: &str) -> GrantView {
        GrantView {
            client_name: None,
            client_version: None,
            agent_model: None,
            agent_session: false,
            grant_id: "g1".into(),
            session_id: None,
            provider: "stripe".into(),
            action: "refund".into(),
            effect_id: None,
            effect_outcome: None,
            failure_class: None,
            terminal_at: None,
            request_model: None,
            deny_reason: None,
            effect_state: None,
            burn_reason: None,
            environment: None,
            resource: serde_json::Value::Null,
            status: if decision == "deny" {
                "denied".into()
            } else {
                "executed".into()
            },
            decision: decision.into(),
            created_at: ts.into(),
            request_id: None,
            approved_by_kind: kind.map(str::to_string),
            approver: Some("operator:uid=1000".into()),
            approved_at: None,
            reason: reason.map(str::to_string),
            authority_fingerprint: None,
            matched_rule: None,
            justification: None,
            integrity_ok: true,
            principal_id: None,
            principal_label: None,
        }
    }

    /// A row as the daemon really hands it over: the public request id it is reachable by, and the
    /// justification the agent had to supply to make the request at all.
    fn attributed_row(request_id: &str, justification: Option<&str>) -> GrantView {
        let mut view = row("allow", Some("sentence"), None, "2026-08-11T10:00:00Z");
        view.matched_rule = Some("allow stripe.refund".into());
        view.request_id = Some(request_id.into());
        view.justification = justification.map(str::to_string);
        view
    }

    /// The list is the only door to `cermet log <request_id>`, so it must NAME the id — and the
    /// justification the MCP surface makes mandatory was write-only until it rendered here.
    #[test]
    fn a_list_row_names_its_request_id_and_justification() {
        let out = render_history_receipt(&[attributed_row(
            "req_9f2c1a4b7d0e3f56",
            Some("refunding the duplicate charge the customer reported"),
        )]);
        assert!(
            out.contains("ALLOW stripe.refund req_9f2c1a4b7d0e3f56"),
            "{out}"
        );
        assert!(
            out.contains(
                "— allowed by: allow stripe.refund — \"refunding the duplicate charge the \
                 customer reported\""
            ),
            "{out}"
        );
        assert_eq!(out.lines().count(), 1, "the row stays one line: {out}");
    }

    /// A row with no justification (every git-plane row) renders nothing in its place — no empty
    /// quotes, no placeholder.
    #[test]
    fn a_row_without_a_justification_renders_no_placeholder() {
        let out = render_history_receipt(&[attributed_row("req_0011223344556677", None)]);
        assert!(
            out.contains("ALLOW stripe.refund req_0011223344556677"),
            "{out}"
        );
        assert!(!out.contains('"'), "{out}");
        assert!(out.ends_with("allow stripe.refund"), "{out}");
    }

    /// The LIST bounds a long justification (the per-request JSON still carries it whole).
    #[test]
    fn a_long_justification_is_bounded_in_the_list() {
        let long = "j".repeat(400);
        let out = render_history_receipt(&[attributed_row("req_0011223344556677", Some(&long))]);
        assert!(!out.contains(&long), "{out}");
        assert!(
            out.contains(&"j".repeat(JUSTIFICATION_SHOWN_MAX_CHARS)),
            "{out}"
        );
        assert!(
            !out.contains(&"j".repeat(JUSTIFICATION_SHOWN_MAX_CHARS + 1)),
            "{out}"
        );
        assert!(
            out.ends_with("…\""),
            "the ellipsis rides inside the quotes: {out}"
        );
    }

    /// The justification is agent-authored text: it renders through the same one-line scrub every
    /// other field does, so it can never move the operator's cursor (T1).
    #[test]
    fn a_justification_cannot_affect_the_terminal() {
        let out = render_history_receipt(&[attributed_row(
            "req_0011223344556677",
            Some("first\u{1b}[2Ksecond\nthird"),
        )]);
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(!out.contains('\u{1b}'), "{out}");
    }

    #[test]
    fn renders_sentence_allow_and_denial_reason() {
        let rows = vec![
            row("allow", Some("sentence"), None, "2026-07-19T10:00:00Z"),
            row(
                "deny",
                None,
                Some("amount exceeds the standing limit"),
                "2026-07-19T09:00:00Z",
            ),
        ];
        let out = render_history_receipt(&rows);
        // No stored reason to read ⇒ the honest fallback, never an invented rule number.
        assert!(
            out.contains("ALLOW stripe.refund — allowed by a standing sentence"),
            "{out}"
        );
        assert!(
            out.contains("DENIED stripe.refund: amount exceeds the standing limit"),
            "{out}"
        );
    }

    /// An allow shows the admitting sentence VERBATIM, plus the corpus it came from.
    #[test]
    fn a_sentence_allow_renders_the_admitting_rule_verbatim() {
        let mut allowed = row(
            "allow",
            Some("sentence"),
            Some("stripe.refund allowed by sentence authority"),
            "2026-07-19T10:00:00Z",
        );
        allowed.matched_rule = Some("allow stripe.refund where amount <= 500".into());
        allowed.authority_fingerprint =
            Some("1e0bc746c6580fc927007a79e46e7d006fb1878161b7f20d6bc48e8303b4b366".into());
        let out = render_history_receipt(&[allowed]);
        assert!(
            out.contains(
                "ALLOW stripe.refund — allowed by: allow stripe.refund where amount <= 500 (corpus 1e0bc746)"
            ),
            "{out}"
        );
        // The sentence is rendered once, not repeated as a trailing verbatim reason.
        assert!(
            !out.contains(": stripe.refund allowed by sentence authority"),
            "{out}"
        );
    }

    #[test]
    fn a_sentence_allow_with_no_fingerprint_still_renders_its_rule() {
        let mut allowed = row("allow", Some("sentence"), None, "2026-07-19T10:00:00Z");
        allowed.matched_rule = Some("allow stripe.refund where amount <= 500".into());
        let out = render_history_receipt(&[allowed]);
        assert!(
            out.contains("— allowed by: allow stripe.refund where amount <= 500"),
            "{out}"
        );
        assert!(!out.contains("corpus"), "{out}");
    }

    /// A row the daemon stored no rule for renders provenance-less — no reconstructed
    /// rule, no invented number — and still shows whatever reason was stored.
    #[test]
    fn an_allow_with_no_stored_rule_renders_without_provenance() {
        let allowed = row(
            "allow",
            Some("sentence"),
            Some("allowed by an authority shape this renderer does not know"),
            "2026-07-19T10:00:00Z",
        );
        let out = render_history_receipt(&[allowed]);
        assert!(out.contains("— allowed by a standing sentence"), "{out}");
        assert!(!out.contains("allowed by:"), "{out}");
        assert!(
            out.contains(": allowed by an authority shape this renderer does not know"),
            "{out}"
        );
    }

    /// A denial names WHAT was asked for. The values arrive already redacted by the
    /// daemon's write path (a secret-classed field carries its marker) — the receipt renders what
    /// it was handed, and only bounds the display width of a long value.
    #[test]
    fn a_denial_renders_the_submitted_values() {
        let mut denied = row(
            "deny",
            None,
            Some("no rule allows this"),
            "2026-08-01T09:00:00Z",
        );
        denied.resource = serde_json::json!({
            "amount": 9000,
            "charge": "ch_92kx",
            "currency": "usd",
            "note": "n".repeat(200),
            "webhook_secret": "[redacted: secret]",
        });
        let out = render_history_receipt(&[denied]);
        assert!(
            out.contains("DENIED stripe.refund: no rule allows this — amount=9000 charge=ch_92kx currency=usd"),
            "{out}"
        );
        assert!(
            out.contains("webhook_secret=[redacted: secret]"),
            "the write-time marker renders as stored: {out}"
        );
        assert!(
            !out.contains(&"n".repeat(200)) && out.contains('…'),
            "a long value is bounded for display: {out}"
        );
    }

    #[test]
    fn money_effect_outcome_renders_retry_guidance_without_private_key_material() {
        let mut ambiguous = row("allow", Some("sentence"), None, "2026-07-19T10:00:00Z");
        ambiguous.effect_id = Some("effect_safe".into());
        ambiguous.effect_outcome = Some(EffectOutcome::Ambiguous);
        let out = render_history_receipt(&[ambiguous]);
        assert!(out.contains("ambiguous; retry only with the same effect handle"));
        assert!(!out.contains("idempotency"));
    }

    /// The operator payoff on the line they already read: an allow whose effect the provider
    /// refused on the credential SAYS so, next to the sentence that allowed it.
    /// A denial says WHY in words and names its class in one greppable word — the prose stays.
    #[test]
    fn a_denial_carries_the_evaluators_code_beside_its_prose() {
        let mut denied = row(
            "deny",
            None,
            Some("rule 2 predicate 1 did not match (field `amount`)"),
            "2026-08-15T10:00:00Z",
        );
        denied.deny_reason = Some(cermet_lang::sentence::DenyReason::PredicateMismatch {
            rule_idx: 1,
            pred_idx: 0,
            field: Some("amount".into()),
        });
        let out = render_history_receipt(&[denied]);
        assert!(out.contains("rule 2 predicate 1 did not match"), "{out}");
        // The prose the daemon writes NAMES the field the predicate constrained, so the operator's
        // own line says what the sentence was arguing about without opening the corpus.
        assert!(out.contains("(field `amount`)"), "{out}");
        assert!(out.contains("[predicate_mismatch]"), "{out}");

        // A denial the evaluator never reached keeps its prose and claims no class.
        let untyped = row(
            "deny",
            None,
            Some("unknown selector"),
            "2026-08-15T10:00:01Z",
        );
        let out = render_history_receipt(&[untyped]);
        assert!(
            out.contains("unknown selector") && !out.contains('['),
            "{out}"
        );
    }

    #[test]
    fn a_failed_effect_names_its_class_beside_the_sentence_that_allowed_it() {
        let mut refused = row("allow", Some("sentence"), None, "2026-08-15T10:00:00Z");
        refused.matched_rule = Some("allow github.push where owner = \"suarezc\"".into());
        refused.failure_class = Some(EffectFailureClass::ProviderAuthRefused);
        let out = render_history_receipt(&[refused]);
        assert!(out.contains("allowed by: allow github.push"), "{out}");
        assert!(
            out.contains("effect failed: provider_auth_refused"),
            "{out}"
        );

        // An effect that landed says nothing — absence is "nothing failed", not "cause unknown".
        let landed = row("allow", Some("sentence"), None, "2026-08-15T10:00:01Z");
        assert!(!render_history_receipt(&[landed]).contains("effect failed"));
    }

    /// A relay row with a derived effect state, as `history()` hands it over.
    fn relay_row(state: EffectState, burn_reason: Option<&str>) -> GrantView {
        let mut view = attributed_row("req_0011223344556677", None);
        view.provider = "vercel".into();
        view.action = "deploy".into();
        view.matched_rule = Some("allow vercel.deploy".into());
        view.effect_state = Some(state);
        view.burn_reason = burn_reason.map(str::to_string);
        view
    }

    /// THE disclosure: three requests that all read `ALLOW vercel.deploy` up to the suffix, and
    /// three different fates. An agent that cannot tell them apart quotes the burned one as its
    /// working example; an operator watching a window that already ended reads it as a hang.
    #[test]
    fn the_row_says_what_became_of_the_effect_its_decision_authorized() {
        let out = render_history_receipt(&[
            relay_row(EffectState::Ok, None),
            relay_row(EffectState::Burned, Some("bind_mismatch")),
            relay_row(EffectState::ExpiredUnused, None),
            relay_row(EffectState::Unresolved, None),
        ]);
        let rows: Vec<&str> = out.lines().collect();
        assert!(rows[0].ends_with("→ok"), "{out}");
        assert!(rows[1].ends_with("→burned(bind_mismatch)"), "{out}");
        assert!(rows[2].ends_with("→expired_unused"), "{out}");
        assert!(rows[3].ends_with("→unresolved"), "{out}");
        // The suffix is APPENDED: every column the row already had keeps its place, so what an
        // operator or a script greps for today still matches.
        for row in &rows {
            assert!(
                row.contains(
                    "ALLOW vercel.deploy req_0011223344556677 — allowed by: allow vercel.deploy"
                ),
                "{row}"
            );
        }
    }

    /// The in-flight window is the case that must stay SILENT. Rendering anything here would be a
    /// conclusion the record does not support, and the whole point of the suffix is that its
    /// presence means something.
    #[test]
    fn a_row_the_record_does_not_resolve_carries_no_suffix() {
        // A live relay window (no derived state), and a plain executed row from before any of this.
        let out = render_history_receipt(&[
            relay_row_in_flight(),
            row("allow", Some("sentence"), None, "2026-08-11T10:00:00Z"),
        ]);
        assert!(!out.contains('→'), "{out}");
    }

    fn relay_row_in_flight() -> GrantView {
        let mut view = relay_row(EffectState::Ok, None);
        view.effect_state = None;
        view
    }

    /// A row whose effect the record says FAILED already names the class; the suffix adds nothing
    /// and stays away rather than repeating it.
    #[test]
    fn a_failed_effect_keeps_its_class_and_gains_no_suffix() {
        let mut failed = relay_row_in_flight();
        failed.failure_class = Some(EffectFailureClass::ProviderAuthRefused);
        let out = render_history_receipt(&[failed]);
        assert!(
            out.contains("effect failed: provider_auth_refused"),
            "{out}"
        );
        assert!(!out.contains('→'), "{out}");
    }

    /// The burn reason is a stable token the daemon wrote, but it renders through the same one-line
    /// scrub every other stored string does — this surface has exactly one door for text.
    #[test]
    fn the_burn_reason_cannot_affect_the_terminal() {
        let out = render_history_receipt(&[relay_row(
            EffectState::Burned,
            Some("bind\u{1b}[2Kmismatch\nsecond"),
        )]);
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(!out.contains('\u{1b}'), "{out}");
    }

    /// `--burned` is the sibling of `--denied` one layer down: `--denied` finds what authority
    /// refused, `--burned` finds what it ALLOWED and the effect layer then ended. Without it, the
    /// burns hide among every other allow in the log.
    #[test]
    fn burned_only_narrows_to_the_sessions_that_burned() {
        let json = serde_json::to_string(&vec![
            relay_row(EffectState::Burned, Some("bind_mismatch")),
            relay_row(EffectState::Ok, None),
            relay_row(EffectState::ExpiredUnused, None),
            row("deny", None, Some("nope"), "2026-07-19T09:00:00Z"),
        ])
        .unwrap();
        let out = run_log_history(
            &json,
            &LogFilter {
                burned_only: true,
                ..LogFilter::default()
            },
        )
        .unwrap()
        .text;
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.ends_with("→burned(bind_mismatch)"), "{out}");

        // It composes with the other filters, and an empty narrowing is empty — never a fallback
        // to everything.
        let none = run_log_history(
            &json,
            &LogFilter {
                burned_only: true,
                provider: Some("stripe"),
                ..LogFilter::default()
            },
        )
        .unwrap()
        .text;
        assert_eq!(none, "No activity.");
    }

    #[test]
    fn denied_only_filters_and_since_bounds() {
        let json = serde_json::to_string(&vec![
            row("allow", Some("sentence"), None, "2026-07-19T10:00:00Z"),
            row("deny", None, Some("nope"), "2026-07-19T09:00:00Z"),
        ])
        .unwrap();
        let out = run_log_history(
            &json,
            &LogFilter {
                denied_only: true,
                ..LogFilter::default()
            },
        )
        .unwrap()
        .text;
        assert!(
            out.contains("DENIED") && !out.contains("ALLOW"),
            "denied-only: {out}"
        );
        // --since after both rows ⇒ empty.
        let empty = run_log_history(
            &json,
            &LogFilter {
                since: Some("2026-07-20T00:00:00Z"),
                ..LogFilter::default()
            },
        )
        .unwrap()
        .text;
        assert_eq!(empty, "No activity.");
    }

    /// A bare `cermet log` renders the newest 100 rows and SAYS SO — the cure for an expensive
    /// full dump may not be a silent cap.
    #[test]
    fn the_bare_log_windows_the_newest_hundred_rows_and_says_so() {
        let rows: Vec<GrantView> = (0..326)
            .map(|n| {
                row(
                    "allow",
                    Some("sentence"),
                    None,
                    &format!("2026-08-01T{:02}:{:02}:00Z", n / 60, n % 60),
                )
            })
            .collect();
        let json = serde_json::to_string(&rows).unwrap();

        let out = run_log_history(&json, &LogFilter::default()).unwrap().text;
        let body: Vec<&str> = out.lines().collect();
        assert_eq!(body.len(), 101, "100 rows plus the one honest tail:\n{out}");
        assert_eq!(
            body[100],
            "… showing the 100 most recent of 326 rows — `--all` for every one, or narrow with \
             `--since <RFC3339>` / `--provider <name>`",
            "{out}"
        );
        // The window keeps the NEWEST rows: the daemon already sorted newest-first.
        assert!(body[0].starts_with("2026-08-01T00:00:00Z"), "{out}");

        // --all is the old full dump, and it carries no tail: nothing was withheld.
        let all = run_log_history(
            &json,
            &LogFilter {
                all: true,
                ..LogFilter::default()
            },
        )
        .unwrap()
        .text;
        assert_eq!(all.lines().count(), 326, "--all renders every row");
        assert!(!all.contains("showing the"), "{all}");
    }

    /// A log SHORTER than the window says nothing extra — the note is honest reporting of
    /// truncation, not decoration on every render.
    #[test]
    fn a_short_log_carries_no_window_note() {
        let json = serde_json::to_string(&vec![row(
            "allow",
            Some("sentence"),
            None,
            "2026-07-19T10:00:00Z",
        )])
        .unwrap();
        let out = run_log_history(&json, &LogFilter::default()).unwrap().text;
        assert!(!out.contains("showing the"), "{out}");
        assert_eq!(out.lines().count(), 1, "{out}");
    }

    /// The filters narrow the log FIRST, then the window applies to what is left — so a
    /// `--provider` filter is not silently defeated by a hundred other providers' rows in front.
    #[test]
    fn filters_narrow_before_the_window_applies() {
        let mut rows: Vec<GrantView> = (0..150)
            .map(|n| {
                row(
                    "allow",
                    Some("sentence"),
                    None,
                    &format!("2026-08-01T{:02}:{:02}:00Z", n / 60, n % 60),
                )
            })
            .collect();
        let mut vercel = row("allow", Some("sentence"), None, "2026-08-01T23:59:00Z");
        vercel.provider = "vercel".into();
        rows.push(vercel);
        let json = serde_json::to_string(&rows).unwrap();

        let out = run_log_history(
            &json,
            &LogFilter {
                provider: Some("vercel"),
                ..LogFilter::default()
            },
        )
        .unwrap()
        .text;
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("vercel.refund"), "{out}");
        assert!(!out.contains("showing the"), "one row is not a truncation");

        // An unknown provider is an empty log, never a fallback to everything (fail closed).
        let none = run_log_history(
            &json,
            &LogFilter {
                provider: Some("nonesuch"),
                ..LogFilter::default()
            },
        )
        .unwrap()
        .text;
        assert_eq!(none, "No activity.");
    }

    /// The window note is a COUNT, so it can never carry a public or an operator-internal id.
    #[test]
    fn the_window_note_names_no_row() {
        let rows: Vec<GrantView> = (0..101)
            .map(|n| {
                let mut r = row(
                    "allow",
                    Some("sentence"),
                    None,
                    &format!("2026-08-01T00:{:02}:00Z", n % 60),
                );
                r.grant_id = format!("grant_{n:016x}");
                r.request_id = Some(format!("req_{n:016x}"));
                r
            })
            .collect();
        let out = run_log_history(
            &serde_json::to_string(&rows).unwrap(),
            &LogFilter::default(),
        )
        .unwrap()
        .text;
        let note = out.lines().next_back().unwrap();
        assert!(
            note.starts_with("… showing the 100 most recent of 101 rows"),
            "{note}"
        );
        assert!(!note.contains("grant_") && !note.contains("req_"), "{note}");
    }

    #[test]
    fn human_approval_shows_approver() {
        let out =
            render_history_receipt(&[row("allow", Some("human"), None, "2026-07-19T10:00:00Z")]);
        assert!(out.contains("approved by operator:uid=1000"), "{out}");
    }

    #[test]
    fn hmac_failed_row_is_marked_untrusted_and_suppresses_authorization_provenance() {
        let mut tampered = row(
            "allow",
            Some("sentence"),
            Some("forged authorization reason"),
            "2026-07-19T10:00:00Z",
        );
        tampered.integrity_ok = false;
        tampered.matched_rule = Some("allow stripe.refund where amount <= 500".into());
        let out = render_history_receipt(&[tampered]);
        assert!(
            out.contains("TAMPERED") && out.contains("UNTRUSTED"),
            "{out}"
        );
        for untrusted in [
            "ALLOW",
            "DENIED",
            "allowed by a standing sentence",
            "allow stripe.refund where amount <= 500",
            "approved by",
            "forged authorization reason",
        ] {
            assert!(
                !out.contains(untrusted),
                "HMAC-failed provenance {untrusted:?} must be suppressed: {out}"
            );
        }
    }
}

#[cfg(test)]
mod hop_tests {
    use super::*;
    use cermet_lang::RelayHopView;

    fn hop(event_type: &str, at: &str) -> RelayHopView {
        RelayHopView {
            event_type: event_type.into(),
            at: at.into(),
            provider: Some("vercel".into()),
            action: Some("deploy".into()),
            grant_id: Some("grant_relay_1".into()),
            method: None,
            target: None,
            upstream_status: None,
            reason: None,
            detail: None,
            effect: None,
            response_bytes: None,
            undeclared_keys: None,
            burned: None,
            closed: None,
        }
    }

    /// A forwarded hop that carried keys its shape does not enumerate says so on its own line, in
    /// the register of an observation. It is not a refusal and must not read as one: the hop was
    /// authorized, went upstream, and answered.
    #[test]
    fn a_forwarded_hop_names_what_it_carried_beyond_the_declared_vocabulary() {
        let mut forwarded = hop("relay_request_forwarded", "2026-08-01T10:00:01Z");
        forwarded.method = Some("POST".into());
        forwarded.target = Some("/v13/deployments".into());
        forwarded.upstream_status = Some(200);
        forwarded.effect = Some(true);
        forwarded.undeclared_keys = Some(vec!["redirects".into(), "+3 more".into()]);

        let json = serde_json::to_string(&vec![forwarded]).unwrap();
        let out = run_log_hops(&json, &LogFilter::default()).unwrap().text;
        assert!(
            out.contains("[the grant's single effect] — also carried redirects, +3 more"),
            "{out}"
        );
        assert!(
            !out.contains("refused") && !out.contains("burned"),
            "an observation must not read as a refusal: {out}"
        );
    }

    /// Without this view the operator cannot see WHY a relay session burned without copying
    /// `audit.db` out with sudo. One line per relay event, newest first, is the whole fix.
    #[test]
    fn the_hop_view_renders_the_life_of_a_session() {
        let mut opened = hop("relay_session_opened", "2026-08-01T10:00:00Z");
        opened.grant_id = Some("grant_relay_1".into());
        let mut forwarded = hop("relay_request_forwarded", "2026-08-01T10:00:01Z");
        forwarded.method = Some("GET".into());
        forwarded.target = Some("/v13/deployments/dpl_1".into());
        forwarded.upstream_status = Some(200);
        forwarded.response_bytes = Some(1234);
        let mut refused = hop("relay_request_refused", "2026-08-01T10:00:02Z");
        refused.method = Some("POST".into());
        refused.target = Some("/v13/deployments".into());
        refused.reason = Some("bind_mismatch".into());
        refused.burned = Some(true);
        refused.detail = Some(
            "the approval froze `target`, so this hop's `target` body key must be absent; it \
             carried `production`"
                .into(),
        );
        let mut closed = hop("relay_session_closed", "2026-08-01T10:00:03Z");
        closed.closed = Some("burned".into());
        closed.reason = None;

        let json = serde_json::to_string(&vec![closed, refused, forwarded, opened]).unwrap();
        let out = run_log_hops(&json, &LogFilter::default()).unwrap().text;

        // The OPENED line names the verb and the time, NOT the grant handle the view
        // carries — `request_id` is the one public id and the hop view has none to render.
        assert!(out.contains("OPENED vercel.deploy"), "{out}");
        assert!(!out.contains("grant_relay_1"), "{out}");
        assert!(
            out.contains("HOP vercel.deploy GET /v13/deployments/dpl_1 — 200 (1234 bytes)"),
            "{out}"
        );
        // The reason WORD keeps its column — it is the machine-readable code and what a reader
        // greps — and the detail follows the short marks rather than pushing them off the line.
        assert!(
            out.contains(
                "REFUSED vercel.deploy POST /v13/deployments — bind_mismatch (burned the session) \
                 — the approval froze `target`, so this hop's `target` body key must be absent; it \
                 carried `production`"
            ),
            "{out}"
        );
        assert!(out.contains("CLOSED vercel.deploy — burned"), "{out}");
        // Newest first, exactly like the grant receipt.
        assert!(
            out.find("CLOSED").unwrap() < out.find("OPENED").unwrap(),
            "{out}"
        );
    }

    /// `--hops --burned` is the drill-down the receipt row's `→burned(<reason>)` sends a reader to,
    /// and an outcome mismatch is the burn whose whole value is on its own line. It gets its OWN
    /// word — the hop was authorized, forwarded, and answered; what ended the session is the answer
    /// — and it rides the same `--burned` filter every other session-ending hop does.
    #[test]
    fn an_outcome_mismatch_renders_and_survives_the_burned_filter() {
        let mut forwarded = hop("relay_request_forwarded", "2026-08-01T10:00:01Z");
        forwarded.method = Some("POST".into());
        forwarded.target = Some("/v13/deployments".into());
        forwarded.upstream_status = Some(200);
        forwarded.effect = Some(true);
        let mut mismatch = hop("relay_outcome_mismatch", "2026-08-01T10:00:02Z");
        mismatch.method = Some("POST".into());
        mismatch.target = Some("/v13/deployments".into());
        mismatch.upstream_status = Some(200);
        mismatch.reason = Some("outcome_mismatch".into());
        mismatch.burned = Some(true);
        mismatch.detail = Some(
            "the approval froze `target`, which this provider encodes as an ABSENT `target` in the \
             effect's own response; it answered `production`"
                .into(),
        );
        let json = serde_json::to_string(&vec![mismatch, forwarded]).unwrap();

        let out = run_log_hops(&json, &LogFilter::default()).unwrap().text;
        assert!(
            out.contains(
                "MISMATCH vercel.deploy POST /v13/deployments — 200 — outcome_mismatch (burned the \
                 session) — the approval froze `target`, which this provider encodes as an ABSENT \
                 `target` in the effect's own response; it answered `production`"
            ),
            "{out}"
        );

        let burned = run_log_hops(
            &json,
            &LogFilter {
                burned_only: true,
                ..LogFilter::default()
            },
        )
        .unwrap()
        .text;
        assert_eq!(burned.lines().count(), 1, "{burned}");
        assert!(burned.contains("MISMATCH"), "{burned}");
    }

    #[test]
    fn the_hop_view_filters_by_since_and_to_refusals() {
        let mut forwarded = hop("relay_request_forwarded", "2026-08-01T10:00:01Z");
        forwarded.method = Some("GET".into());
        forwarded.target = Some("/v13/deployments/dpl_1".into());
        forwarded.upstream_status = Some(200);
        let mut refused = hop("relay_request_refused", "2026-08-01T10:00:02Z");
        refused.method = Some("POST".into());
        refused.target = Some("/v13/deployments".into());
        refused.reason = Some("no_matching_shape".into());
        refused.burned = Some(true);
        let json = serde_json::to_string(&vec![refused, forwarded]).unwrap();

        let denied = run_log_hops(
            &json,
            &LogFilter {
                denied_only: true,
                ..LogFilter::default()
            },
        )
        .unwrap()
        .text;
        assert!(
            denied.contains("REFUSED") && !denied.contains("HOP "),
            "{denied}"
        );

        let since = run_log_hops(
            &json,
            &LogFilter {
                since: Some("2026-08-01T11:00:00Z"),
                ..LogFilter::default()
            },
        )
        .unwrap()
        .text;
        assert_eq!(since, "No relay hops.");
    }

    /// The hop view is windowed on the same terms, and says so in its own noun.
    #[test]
    fn the_hop_view_windows_and_filters_by_provider() {
        let mut rows: Vec<RelayHopView> = (0..120)
            .map(|n| {
                hop(
                    "relay_request_forwarded",
                    &format!("2026-08-01T00:{n:02}:00Z"),
                )
            })
            .collect();
        let mut stripe = hop("relay_request_forwarded", "2026-08-01T23:59:00Z");
        stripe.provider = Some("stripe".into());
        rows.push(stripe);
        let json = serde_json::to_string(&rows).unwrap();

        let out = run_log_hops(&json, &LogFilter::default()).unwrap().text;
        assert_eq!(out.lines().count(), 101, "{out}");
        assert!(
            out.lines()
                .next_back()
                .unwrap()
                .contains("most recent of 121 relay hops"),
            "{out}"
        );

        let one = run_log_hops(
            &json,
            &LogFilter {
                provider: Some("stripe"),
                ..LogFilter::default()
            },
        )
        .unwrap()
        .text;
        assert_eq!(one.lines().count(), 1, "{one}");
        assert!(one.contains("stripe."), "{one}");
    }
}
