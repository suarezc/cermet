//! Capture-core tests: the credential chokepoint (closed), the exists-vs-absent catalog check BOTH
//! ways, and the terminal-safety sweep the whole crate shares.

use super::*;
use serde_json::json;

/// A dictionary with two verbs that EXIST, one of them carrying an `amount` field.
fn catalog() -> Value {
    json!({
        "kind": "catalog",
        "catalog": [
            {
                "provider": "stripe", "action": "get_charge",
                "fields": [{ "name": "charge", "type": "str", "required": true }],
                "requestable": true
            },
            {
                "provider": "stripe", "action": "refund_charge_bounded",
                "fields": [
                    { "name": "charge", "type": "str", "required": true },
                    { "name": "amount", "type": "int", "required": true }
                ],
                "requestable": true
            },
            {
                // A verb that exists but NO sentence admits — still exists, so still an authority
                // question, never a vocabulary one.
                "provider": "github", "action": "read_repo",
                "fields": [], "requestable": false
            }
        ]
    })
}

fn form(provider: &str, verb: Option<&str>, field: Option<&str>) -> RequestForm {
    RequestForm {
        provider: provider.to_string(),
        wanted_verb: verb.map(str::to_string),
        wanted_field: field.map(str::to_string),
        ask: Some("settle a dispute we lost".to_string()),
        rationale: Some("weekly finance reconciliation".to_string()),
    }
}

// ---- the credential chokepoint: refusal, not redaction -----------------------------------------

#[test]
fn a_live_key_in_the_rationale_is_refused() {
    let mut f = form("stripe", Some("list_disputes"), None);
    f.rationale = Some("it kept failing with sk_live_51H8xQeJk2mLpQrStUvWx as the key".into());
    let err = capture(&f, &catalog()).expect_err("a credential-shaped rationale must be refused");
    assert!(err.contains("credential-shaped"), "{err}");
    // The refusal names the offset, never the fragment.
    assert!(!err.contains("sk_live_51H8xQeJk2mLpQrStUvWx"), "{err}");
}

#[test]
fn a_github_token_in_the_ask_is_refused() {
    let mut f = form("github", Some("create_release"), None);
    f.ask = Some("curl -H 'Authorization: token ghp_A1b2C3d4E5f6G7h8I9j0' …".into());
    let err = capture(&f, &catalog()).expect_err("a ghp_ token in the ask must be refused");
    assert!(err.contains("credential-shaped"), "{err}");
}

#[test]
fn the_chokepoint_covers_the_whole_ported_pattern_set() {
    for shape in [
        "sk_live_abcdefghijklmnop",
        "rk_test_abcdefghijklmnop",
        "github_pat_11ABCDEFG0abcdefg",
        "ghp_A1b2C3d4E5f6G7h8I9j0",
        "gho_A1b2C3d4E5f6G7h8I9j0",
        "Bearer eyJhbGciOiJIUzI1NiJ9",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    ] {
        assert!(
            credential_shape(shape).is_some(),
            "the chokepoint must recognize {shape}"
        );
    }
    assert!(credential_shape("please add stripe.list_disputes").is_none());
}

// ---- exists vs absent, both ways ---------------------------------------------------------------

#[test]
fn an_absent_verb_is_a_vocabulary_gap() {
    let (request, gap) = capture(&form("stripe", Some("list_disputes"), None), &catalog())
        .expect("an absent verb is a vocabulary gap");
    assert_eq!(gap, Gap::Vocabulary);
    assert_eq!(gap.label(), "vocabulary_gap");
    assert_eq!(request.provider, "stripe");
    assert_eq!(request.wanted_verb.as_deref(), Some("list_disputes"));
}

#[test]
fn an_existing_verb_is_an_authority_gap() {
    let (request, gap) = capture(&form("stripe", Some("get_charge"), None), &catalog())
        .expect("an existing verb still validates — it is classified, not discarded");
    // Both outcomes are reported to the daemon, so the request survives the classification.
    assert_eq!(request.wanted_verb.as_deref(), Some("get_charge"));
    assert_eq!(gap.label(), "authority_gap");
    match gap {
        Gap::Authority(refusal) => {
            assert!(refusal.contains("already EXISTS"), "{refusal}");
            assert!(refusal.contains("widening suggestion"), "{refusal}");
        }
        other => panic!("expected an authority gap, got {other:?}"),
    }
}

#[test]
fn a_verb_that_exists_but_no_sentence_admits_is_still_an_authority_gap() {
    // The dictionary is read whole: `requestable: false` means the corpus does not admit it, which
    // is precisely the authority question — the WORD exists.
    let (_, gap) = capture(&form("github", Some("read_repo"), None), &catalog()).expect("captured");
    assert_eq!(gap.label(), "authority_gap");
}

#[test]
fn an_absent_field_on_an_existing_verb_is_a_vocabulary_gap() {
    let (request, gap) = capture(
        &form("stripe", Some("refund_charge_bounded"), Some("reason")),
        &catalog(),
    )
    .expect("a missing field on a real verb is a vocabulary gap");
    assert_eq!(gap, Gap::Vocabulary);
    assert_eq!(request.wanted_field.as_deref(), Some("reason"));
}

#[test]
fn an_existing_field_is_an_authority_gap() {
    let (_, gap) = capture(
        &form("stripe", Some("refund_charge_bounded"), Some("amount")),
        &catalog(),
    )
    .expect("captured");
    match gap {
        Gap::Authority(refusal) => assert!(refusal.contains("already has"), "{refusal}"),
        other => panic!("expected an authority gap, got {other:?}"),
    }
}

#[test]
fn a_field_on_an_absent_verb_asks_for_the_verb_instead() {
    let (_, gap) = capture(
        &form("stripe", Some("list_disputes"), Some("since")),
        &catalog(),
    )
    .expect("captured");
    match gap {
        Gap::Authority(refusal) => assert!(refusal.contains("does not exist"), "{refusal}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_field_with_no_verb_is_refused_outright() {
    let err = capture(&form("stripe", None, Some("reason")), &catalog())
        .expect_err("a field alone cannot be checked");
    assert!(err.contains("verb"), "{err}");
}

// ---- fail closed on malformed input ------------------------------------------------------------

#[test]
fn malformed_input_is_refused() {
    assert!(capture(&form("  ", Some("list_disputes"), None), &catalog()).is_err());
    assert!(capture(&form("stripe", None, None), &catalog()).is_err());

    // A dotted verb is two fields, not one name.
    let dotted = capture(
        &form("stripe", Some("stripe.list_disputes"), None),
        &catalog(),
    );
    assert!(dotted.is_err_and(|e| e.contains("bare name")));

    let mut too_long = form("stripe", Some("list_disputes"), None);
    too_long.rationale = Some("x".repeat(MAX_TEXT_CHARS + 1));
    assert!(capture(&too_long, &catalog()).is_err_and(|e| e.contains("at most")));

    // An unreadable dictionary is NOT an empty one — a frame with no `catalog` array cannot answer
    // "does this word exist?", so capture fails closed rather than classifying blind.
    let unreadable = capture(&form("stripe", Some("get_charge"), None), &json!({}));
    assert!(unreadable.is_err_and(|e| e.contains("could not be read")));
}

/// The sweep is the CRATE'S definition of terminal-affecting, not a hand-rolled `is_control()`
/// subset — a bidi override reordering what the operator reads is the T1 case that found the
/// near-duplicate.
#[test]
fn captured_text_is_one_line_and_cannot_steer_a_terminal() {
    let mut f = form("stripe", Some("list_disputes"), None);
    f.ask = Some("first\u{1b}[2Ksecond\nthird\u{202e}reversed\u{2069}".into());
    let (request, _) = capture(&f, &catalog()).expect("captured");
    let ask = request.ask.expect("an ask");
    assert!(!ask.contains('\u{1b}'), "{ask}");
    assert!(!ask.contains('\u{202e}'), "bidi override survived: {ask}");
    assert!(!ask.contains('\u{2069}'), "isolate survived: {ask}");
    assert_eq!(ask.lines().count(), 1, "{ask}");
    assert!(!ask.chars().any(crate::receipt_log::terminal_affecting));
}

#[test]
fn the_provider_and_verb_are_lowercased() {
    let (request, _) = capture(&form("STRIPE", Some("List_Disputes"), None), &catalog()).unwrap();
    assert_eq!(request.provider, "stripe");
    assert_eq!(request.wanted_verb.as_deref(), Some("list_disputes"));
}

// ---- the formed request the agent relays --------------------------------------------------------

#[test]
fn the_rendered_block_carries_the_form_and_the_build() {
    let (request, _) = capture(
        &form("stripe", Some("refund_charge_bounded"), Some("reason")),
        &catalog(),
    )
    .expect("captured");
    let block = render(&request);
    assert!(block.contains("provider: stripe"), "{block}");
    assert!(block.contains("refund_charge_bounded"), "{block}");
    assert!(
        block.contains("wanted field (does not exist): reason"),
        "{block}"
    );
    assert!(
        block.contains("the ask: settle a dispute we lost"),
        "{block}"
    );
    assert!(block.contains(cermet_ipc::BUILD_ID), "{block}");
    // Nothing in the block can steer the terminal it is pasted into.
    assert!(!block
        .chars()
        .any(|c| c != '\n' && crate::receipt_log::terminal_affecting(c)));
}
