#[test]
fn shipped_language_guide_covers_every_execution_form_without_claiming_validator_completeness() {
    let guide = cermet_core::LANGUAGE_DOC;
    let prose = guide.split_whitespace().collect::<Vec<_>>().join(" ");
    for required in ["change_list", "graphql_query", "validator is authoritative"] {
        assert!(
            guide.contains(required),
            "language guide omits {required:?}"
        );
    }
    assert!(!guide.contains("self-contained reference"), "{guide}");
    assert!(
        !guide.contains("If every item holds, your template is valid"),
        "{guide}"
    );
    assert!(
        prose.contains(
            "The Rust validator and vendored documents are authoritative for exact acceptance"
        ),
        "the guide must leave exact acceptance at the executable/vendored boundary"
    );
}

#[test]
fn served_language_guide_teaches_live_verbs_and_the_one_live_dialect() {
    let guide = cermet_core::LANGUAGE_DOC;

    // 1. The headline authority block and the authoring-examples section are Stripe verbs, and
    //    every one of them is STATELESS — decidable from the request alone. The flagship money
    //    example is a per-request bound, not a daily total.
    for headline in [
        "allow stripe.get_charge where charge = \"ch_3PabcXYZ\"",
        "allow stripe.refund where amount <= 5000",
        "allow stripe.get_price where price in {\"price_basic\", \"price_pro\"}",
        "deny stripe.create_standard_payout where amount >= 10000",
    ] {
        assert!(
            guide.contains(headline),
            "the served guide lost its Stripe headline example: {headline:?}"
        );
    }

    // 1b. The temporal clauses are GATED, not deleted — so the guide must still describe them, but
    //     never as live grammar. It must say they are disabled and NAME the setting that returns
    //     them; an operator who reads the section and authors the clause anyway must be able to
    //     find the key from the doc alone — a behavior that is not in the canonical guide does not
    //     exist.
    assert!(
        guide.contains("### 4. Temporal clauses — DISABLED BY DEFAULT"),
        "the guide must mark the temporal section as not-live in its own heading"
    );
    assert!(
        guide.contains(cermet_core::sentence::TEMPORAL_CLAUSES_SETTING),
        "the guide must name the daemon setting that gates the temporal clauses"
    );
    for gated in [
        "allow stripe.refund where amount <= 5000 and budget amount 50000 per day",
        "allow stripe.create_payment_intent_off_session where rate 10 per hour",
    ] {
        assert!(
            guide.contains(gated),
            "the gated section must still show the form it gates: {gated:?}"
        );
        let position = guide.find(gated).expect("just asserted present");
        let heading = guide
            .find("### 4. Temporal clauses — DISABLED BY DEFAULT")
            .expect("just asserted present");
        let next_section = guide.find("### 5. Authoring examples").expect("section 5");
        assert!(
            position > heading && position < next_section,
            "a temporal example outside the disabled section reads as live grammar: {gated:?}"
        );
    }

    // 2. A behavior that is not in the canonical docs DOES NOT EXIST — and that cuts both ways. The
    //    SERVED guide must teach the one live dialect (a bare verb selector, mandatory-quoted
    //    strings, two escapes, matching by kind), and must not still teach the two rules the
    //    dialect change dissolved.
    for required in [
        "**A bare dotted selector is the VERB**",
        "**String values are ALWAYS double-quoted; bare literals are int/bool ONLY**",
        "**Matching is by kind, with no exceptions.**",
        "The only escapes are `\\\"` and `\\\\`",
        "and number = \"3\"",
        "`<provider>.<set>@sha256:<digest>`",
    ] {
        assert!(
            guide.contains(required),
            "the served guide does not state the live dialect: {required:?}"
        );
    }
    for dissolved in [
        "RESOLVE THIS NAME**",
        "the one declared coercion",
        "is matched by an INTEGER pin",
        "`verb:<provider>.<action>`",
    ] {
        assert!(
            !guide.contains(dissolved),
            "the served guide still teaches the dissolved rule {dissolved:?}"
        );
    }

    // 3. `github.push_commit` was the grammar example for a structured payload type that no longer
    //    exists. The served guide must teach the surface that REPLACED it, and must not teach the
    //    deleted one.
    assert!(
        guide.contains("git push origin main"),
        "the served guide must teach the git surface that replaced the push verb"
    );
    // And it must teach the LIVE one: a wired remote plus the installed remote helper is the whole
    // client surface, so the guide must not resurrect a `cermet git` wrapper the binary does not
    // have.
    assert!(
        !guide.contains("cermet git "),
        "the served guide still teaches the deleted `cermet git` wrapper"
    );
    // Not "never mentions" — the guide explains what was removed and why, which requires naming
    // it. What must be gone is every construct that would TEACH the deleted surface as live
    // grammar.
    for construct in [
        "type: change_list",
        "|file_changes}",
        "cermet stage",
        "cermet git",
        "github.push_commit",
        "spool_dir",
    ] {
        assert!(
            !guide.contains(construct),
            "the served guide still teaches the deleted construct {construct:?}"
        );
    }
}
