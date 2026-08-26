//! `cermet catalog` — the CLI's capability-discovery surface.
//!
//! What these tests pin: the two zooms exist, they render the DAEMON's join (the admitting
//! sentences by their canonical text, no rule numbers), the dictionary's authority stamp cannot be
//! read as permission, and an unreachable daemon fails closed with an error rather than an empty
//! catalog that looks like an answer.

use cermet_cli::{dispatch, parse, CliCommand, CliError};

mod common;
use common::BrokerFixture;

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// A real vendored, loaded, read-only verb, so the corpus below really admits something this
/// broker really holds.
const ALLOWED: &str = "allow github.read_repo";

// ---- parsing --------------------------------------------------------------------------------

#[test]
fn catalog_parses_with_its_one_zoom_flag() {
    assert_eq!(
        parse(&argv(&["catalog"])).unwrap(),
        CliCommand::Catalog { all: false }
    );
    assert_eq!(
        parse(&argv(&["catalog", "--all"])).unwrap(),
        CliCommand::Catalog { all: true }
    );
}

#[test]
fn catalog_rejects_stray_arguments_and_flags() {
    for bad in [
        &["catalog", "github"][..],
        &["catalog", "--scope", "all"][..],
        &["catalog", "--everything"][..],
    ] {
        assert!(
            matches!(parse(&argv(bad)), Err(CliError::Usage(_))),
            "`cermet {}` must be a usage error",
            bad.join(" ")
        );
    }
}

// ---- the allowed zoom -----------------------------------------------------------------------

#[tokio::test]
async fn the_default_zoom_names_the_admitted_verb_and_quotes_its_sentence() {
    let fixture = BrokerFixture::with_sentence_rules(ALLOWED);
    let out = dispatch(&fixture.client, &CliCommand::Catalog { all: false })
        .await
        .expect("the allowed zoom renders");

    assert!(out.ok);
    assert!(
        out.text.contains("github.read_repo"),
        "the admitted verb must be on the surface:\n{}",
        out.text
    );
    // The sentence IS the name of the authority: quoted verbatim, never numbered.
    assert!(
        out.text.contains(ALLOWED),
        "the admitting sentence must be quoted verbatim:\n{}",
        out.text
    );
    // The compact zoom is a CONTRACT, not a dictionary: nothing this corpus does not admit.
    assert!(
        !out.text.contains("stripe."),
        "the allowed zoom must not list unadmitted verbs:\n{}",
        out.text
    );
}

#[tokio::test]
async fn an_empty_corpus_says_so_instead_of_rendering_an_empty_list() {
    let fixture = BrokerFixture::with_sentence_rules("");
    let out = dispatch(&fixture.client, &CliCommand::Catalog { all: false })
        .await
        .expect("the allowed zoom renders on an empty corpus");

    assert!(
        out.text.contains("0 verbs"),
        "an empty corpus must say so in words:\n{}",
        out.text
    );
    // And it must point at the other zoom in THIS surface's vocabulary — there is no `scope=` on a
    // CLI, and telling an operator to pass one is a dead end.
    assert!(
        out.text.contains("cermet catalog --all"),
        "the CLI must name the CLI's dictionary zoom:\n{}",
        out.text
    );
    assert!(
        !out.text.contains("scope="),
        "MCP tool vocabulary must not leak onto the CLI:\n{}",
        out.text
    );
}

// ---- the dictionary zoom --------------------------------------------------------------------

#[tokio::test]
async fn the_all_zoom_is_the_dictionary_and_stamps_unadmitted_verbs_as_not_allowed() {
    let fixture = BrokerFixture::with_sentence_rules(ALLOWED);
    let out = dispatch(&fixture.client, &CliCommand::Catalog { all: true })
        .await
        .expect("the dictionary zoom renders");

    assert!(out.ok);
    // The dictionary carries verbs the corpus does NOT admit — that is what it is for.
    assert!(
        out.text.contains("stripe."),
        "the dictionary must list verbs no sentence admits:\n{}",
        out.text
    );
    assert!(out.text.contains("github.read_repo"));
    // The stamp on an unadmitted verb must not read as permission. `requestable` did — it reads
    // as "currently permitted" — so it is gone from every stamp.
    assert!(
        out.text
            .contains("no standing sentence — ask the operator for one"),
        "an unruled verb must be stamped not-currently-allowed:\n{}",
        out.text
    );
    assert!(
        !out.text.contains("[requestable]"),
        "the permission-implying stamp must be gone:\n{}",
        out.text
    );
    assert!(
        out.text.contains("[allowed now]"),
        "the admitted verb must be stamped allowed:\n{}",
        out.text
    );
    assert!(
        out.text.contains("cermet catalog"),
        "the dictionary must name the CLI's allowed zoom:\n{}",
        out.text
    );
    assert!(
        !out.text.contains("request_capability"),
        "MCP tool vocabulary must not leak onto the CLI:\n{}",
        out.text
    );
}

// ---- fail closed ----------------------------------------------------------------------------

#[tokio::test]
async fn an_unreachable_daemon_is_an_error_not_an_empty_catalog() {
    let dir = tempfile::tempdir().expect("tempdir");
    let client = cermet_ctl_client::broker_client::CtlBrokerClient::new(
        dir.path().join("absent-ctl.sock"),
        999_001,
    );
    let error = dispatch(&client, &CliCommand::Catalog { all: false })
        .await
        .expect_err("an absent daemon must fail closed");
    let message = error.to_string();
    assert!(
        message.contains("cermetd") && message.contains("unreachable"),
        "the failure must name cermetd plainly, got: {message}"
    );
}

// ---- one join, two planes -------------------------------------------------------------------

/// `cermet catalog` (ctl) and the MCP `catalog` tool (agent.sock) are two READERS of one
/// daemon-side join — both call `Broker::catalog_listing()`. That claim is pinned here at the
/// payload level: for ONE broker, the array each plane serves is identical, attribute for
/// attribute (binding/class/requestable included — the parts rendered text cannot carry).
#[tokio::test]
async fn the_ctl_and_agent_planes_serve_the_identical_catalog_payload() {
    let fixture = BrokerFixture::with_sentence_rules(ALLOWED);

    let ctl_view: serde_json::Value =
        serde_json::from_str(&fixture.client.catalog().await.expect("ctl catalog"))
            .expect("ctl view is JSON");

    let agent_sock = fixture.serve_agent_once();
    let agent_frame =
        cermet_cli::mcp_bridge::call(&agent_sock, &cermet_cli::mcp_bridge::AgentCommand::Catalog)
            .expect("agent catalog");

    let rows = ctl_view["catalog"].as_array().expect("ctl rows");
    assert!(!rows.is_empty(), "the fixture broker holds vendored verbs");
    assert_eq!(
        ctl_view["catalog"], agent_frame["catalog"],
        "ctl and agent planes must serve the identical catalog array"
    );
    // The attributes compared against the vendored descriptors ride BOTH planes.
    let admitted = rows
        .iter()
        .find(|row| row["provider"] == "github" && row["action"] == "read_repo")
        .expect("the admitted verb is listed");
    assert_eq!(admitted["requestable"], serde_json::json!(true));
    for field in admitted["fields"].as_array().expect("typed fields") {
        for attribute in ["name", "type", "required", "class", "binding"] {
            assert!(
                field.get(attribute).is_some(),
                "the ctl projection carries the declared field attribute {attribute}: {field}"
            );
        }
    }
}

/// The WHERE index is derived on the DAEMON, from the same `FieldDecl` the evaluator
/// judges sentences against, and rides both planes with the rest of the projection. This owns the
/// emit path end to end: a projection that stopped carrying `forms` would leave every field
/// rendering `[none]` — a confident lie about what a sentence may constrain — and the unit tests,
/// which hand-write their frames, could not catch it.
#[tokio::test]
async fn the_daemon_projection_carries_each_field_where_index() {
    let fixture = BrokerFixture::with_sentence_rules(ALLOWED);
    let ctl_view: serde_json::Value =
        serde_json::from_str(&fixture.client.catalog().await.expect("ctl catalog"))
            .expect("ctl view is JSON");
    let rows = ctl_view["catalog"].as_array().expect("ctl rows");
    assert!(!rows.is_empty(), "the fixture broker holds vendored verbs");

    for row in rows {
        for field in row["fields"].as_array().expect("typed fields") {
            let forms: Vec<&str> = field["forms"]
                .as_array()
                .unwrap_or_else(|| panic!("every field carries its form index: {field}"))
                .iter()
                .map(|f| f.as_str().expect("a form"))
                .collect();
            // Whatever the declaration, every form comes from the closed set the grammar spells,
            // and `rate` — being verb-level — is never one of them.
            for form in &forms {
                assert!(
                    ["=", "in", "<=", ">=", "budget"].contains(form),
                    "unknown form {form} on {field}"
                );
            }
            // The evaluator's type rules, read back off the wire: only an integer field compares by
            // range, and only an integer field can be summed by a budget.
            if field["type"] != "int" {
                assert!(
                    !forms.contains(&"<=") && !forms.contains(&">=") && !forms.contains(&"budget"),
                    "a non-int field must not range or sum: {field}"
                );
            }
        }
    }

    let admitted = rows
        .iter()
        .find(|row| row["provider"] == "github" && row["action"] == "read_repo")
        .expect("the admitted verb is listed");
    let owner = admitted["fields"]
        .as_array()
        .expect("typed fields")
        .iter()
        .find(|f| f["name"] == "owner")
        .expect("read_repo declares owner");
    assert_eq!(owner["forms"], serde_json::json!(["=", "in"]));
}
