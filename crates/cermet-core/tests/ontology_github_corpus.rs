//! Verb-corpus GitHub batch: one draft-only PR creation shape and one bounded secret-scanning read.
//! These tests pin the reviewed authority envelopes and the secret-output projection boundary.

use cermet_core::contract::{AllowBinding, FieldClass};
use cermet_core::templates::{TemplateRegistry, VENDORED_CATALOG};
use cermet_core::{
    OntologyArtifacts, OntologyCatalog, RiskClass, SourceRegistry, VENDORED_ONTOLOGY,
};

mod common;
use common::VENDORED_ONTOLOGY_RECORDS;

fn vendored_registry() -> TemplateRegistry {
    let reg = TemplateRegistry::new();
    for doc in VENDORED_CATALOG {
        reg.load(doc).unwrap_or_else(|error| {
            panic!("vendored catalog doc failed to load: {error}\n---\n{doc}")
        });
    }
    reg
}

fn vendored_doc(action: &str) -> &'static str {
    let needle = format!("action: {action}\n");
    VENDORED_CATALOG
        .iter()
        .copied()
        .find(|doc| doc.contains("provider: github") && doc.contains(&needle))
        .unwrap_or_else(|| panic!("github.{action} template is vendored"))
}

#[test]
fn corpus_contracts_freeze_the_reviewed_execution_fields() {
    let reg = vendored_registry();

    let read = reg
        .resolve("github", "read_secret_scanning_alerts_open")
        .expect("secret-scanning read resolves");
    assert_eq!(read.execution_targets, ["owner", "name"]);
    assert!(read.has_fully_pinned_execution_targets());
    assert!(read.schema.iter().all(|field| {
        field.required
            && field.class == FieldClass::Identity
            && field.binding == AllowBinding::ExactResourcePin
    }));

    let create = reg
        .resolve("github", "create_pull_request")
        .expect("pull request creation resolves");
    // `draft` joined the targets when it stopped being a frozen literal — it is a
    // pinnable identity an operator narrows in a sentence (`where draft = true`), not template policy.
    assert_eq!(
        create.execution_targets,
        ["owner", "name", "base", "head", "draft"]
    );
    assert!(create.has_fully_pinned_execution_targets());
    for name in ["owner", "name", "base", "head", "draft"] {
        assert_eq!(create.field_class(name), Some(FieldClass::Identity));
        assert_eq!(
            create.field_binding(name),
            Some(AllowBinding::ExactResourcePin)
        );
    }
    for name in ["title", "body"] {
        assert_eq!(create.field_class(name), Some(FieldClass::FreePayload));
        assert_eq!(create.field_binding(name), Some(AllowBinding::Unbound));
        assert!(
            create.consumes.contains(&name),
            "{name} must ride the frozen request body"
        );
    }
    assert_eq!(
        create.schema.len(),
        7,
        "owner/name/base/head/draft identities plus the title/body free payload"
    );
}

#[test]
fn pr_template_carries_the_declared_draft_choice_and_projects_no_authored_payload() {
    let doc = vendored_doc("create_pull_request");
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(doc).expect("pull request template is valid YAML");
    let step = &yaml["http"]["steps"][0];
    let body = step["body"]
        .as_mapping()
        .expect("draft PR has a closed JSON body");

    assert_eq!(step["method"].as_str(), Some("POST"));
    assert_eq!(step["path"].as_str(), Some("/repos/{owner}/{name}/pulls"));
    assert_eq!(
        body.len(),
        5,
        "only title/body/head/base and the declared draft choice may ride"
    );
    assert_eq!(step["body"]["title"].as_str(), Some("{title}"));
    assert_eq!(step["body"]["body"].as_str(), Some("{body}"));
    assert_eq!(step["body"]["head"].as_str(), Some("{head}"));
    assert_eq!(step["body"]["base"].as_str(), Some("{base}"));
    // The wire carries the FROZEN FIELD, not a literal, and there is no draft
    // postcondition any more — GitHub is the authority on what it created.
    assert_eq!(step["body"]["draft"].as_str(), Some("{draft}"));
    assert!(step["expect_literal"].is_null());
    assert_eq!(step["success_statuses"][0].as_i64(), Some(201));

    let require: Vec<&str> = step["require"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(require, ["id", "number"]);
    assert!(
        step["keep"].is_null(),
        "the retired projection key must be gone from the vendored document"
    );
}

#[test]
fn secret_scanning_template_has_a_fixed_bounded_open_query_and_no_secret_keep() {
    let doc = vendored_doc("read_secret_scanning_alerts_open");
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(doc).expect("secret-scanning template is valid YAML");
    let step = &yaml["http"]["steps"][0];
    assert_eq!(step["method"].as_str(), Some("GET"));
    assert_eq!(step["query"]["state"].as_str(), Some("open"));
    assert_eq!(step["query"]["per_page"].as_str(), Some("30"));
    assert_eq!(step["query"]["hide_secret"].as_str(), Some("true"));

    // This verb's `keep` list is gone with every other projection, so a
    // literal GitHub chose to send comes back. The bound is REQUEST-side and asserted above:
    // `hide_secret=true` tells GitHub not to send it. `github` is not a product-enabled provider.
    assert!(
        step["keep"].is_null(),
        "the retired projection key must be gone from the vendored document"
    );
}

#[test]
fn new_error_and_literal_assertion_grammar_fails_closed_on_unsafe_shapes() {
    // The `error_status_only` half of this rule retired with the projection keys; the
    // grammar refuses the key itself now, which is a stronger closure than the old placement rule.
    let stale_projection = format!(
        "{}      error_status_only: true\n",
        vendored_doc("read_secret_scanning_alerts_open")
    );
    let err = TemplateRegistry::new()
        .load(&stale_projection)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("unknown field") && err.contains("error_status_only"),
        "{err}"
    );

    let structured_postcondition = vendored_doc("read_pull_request").replace(
        "      method: GET",
        "      method: GET\n      expect_literal: { draft: [] }",
    );
    let err = TemplateRegistry::new()
        .load(&structured_postcondition)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expect_literal") && err.contains("scalar or null"),
        "{err}"
    );
}

#[test]
fn github_corpus_sidecars_hash_join_and_carry_the_reviewed_risk_bands() {
    assert_eq!(
        VENDORED_ONTOLOGY.len(),
        VENDORED_ONTOLOGY_RECORDS,
        "the vendored corpus is whole before this suite checks its own slice"
    );
    let sources = SourceRegistry::official().unwrap();
    let catalog = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources).unwrap();
    assert_eq!(catalog.len(), VENDORED_ONTOLOGY_RECORDS);
    catalog.join_all(&OntologyArtifacts::vendored()).unwrap();

    assert_eq!(
        catalog
            .get("github", "create_pull_request")
            .expect("draft PR sidecar is vendored")
            .semantics
            .risk_class,
        RiskClass::ExternalStateChange
    );
    assert_eq!(
        catalog
            .get("github", "read_secret_scanning_alerts_open")
            .expect("secret-scanning sidecar is vendored")
            .semantics
            .risk_class,
        RiskClass::SensitiveObservation
    );
}
