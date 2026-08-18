//! `github.dispatch_workflow` — the `workflow_dispatch` effect. Start a run of ONE named GitHub
//! Actions workflow file on ONE named ref of ONE frozen repository.
//!
//! What these tests pin: the envelope is addressing ONLY (four required exact-pinned identities, no
//! `free_payload` and no `secret`), the wire is exactly one POST accepting the live-observed 200 and
//! the documented 204 and nothing else, and the verb carries NO authority until an operator writes a
//! sentence for it.

use cermet_core::contract::{ActionContract, AllowBinding, CanonicalResource, FieldClass};
use cermet_core::policy::{ContractSource, DefaultContractSource};
use cermet_core::sentence::{
    parse_rules, ContractResolver, Decision, DenyReason, SentenceEvaluator,
};
use cermet_core::sets::VendoredSetResolver;
use cermet_core::templates::{HttpStepShape, TemplateRegistry, VENDORED_CATALOG};
use cermet_core::{
    OntologyArtifacts, OntologyCatalog, RiskClass, SourceRegistry, VENDORED_ONTOLOGY,
};

fn vendored_registry() -> TemplateRegistry {
    let reg = TemplateRegistry::new();
    for doc in VENDORED_CATALOG {
        reg.load(doc).unwrap_or_else(|error| {
            panic!("vendored catalog doc failed to load: {error}\n---\n{doc}")
        });
    }
    reg
}

fn vendored_doc() -> &'static str {
    VENDORED_CATALOG
        .iter()
        .copied()
        .find(|doc| doc.contains("provider: github") && doc.contains("action: dispatch_workflow\n"))
        .expect("github.dispatch_workflow template is vendored")
}

#[test]
fn the_dispatch_envelope_is_four_frozen_identities_and_nothing_an_agent_authors() {
    let reg = vendored_registry();
    let contract = reg
        .resolve("github", "dispatch_workflow")
        .expect("github.dispatch_workflow resolves in the vendored catalog");

    // Addressing only: repository, workflow FILE, and the ref the run starts on. Every one of them
    // is an execution target an allow can constrain, so no sentence can be written that leaves any
    // executing field open.
    assert_eq!(
        contract.execution_targets,
        ["owner", "name", "workflow", "ref"]
    );
    assert!(contract.has_fully_pinned_execution_targets());
    for field in contract.schema {
        assert!(field.required, "`{}` must be required", field.name);
        assert_eq!(
            field.class,
            FieldClass::Identity,
            "`{}` must be an identity — this verb authors no payload",
            field.name
        );
        assert_eq!(
            field.binding,
            AllowBinding::ExactResourcePin,
            "`{}` must be exact-pinned",
            field.name
        );
    }
    // The workflow_dispatch `inputs` map is deliberately absent in v1 (its field-class design is
    // deferred): no free-form JSON object enters the frozen envelope.
    assert!(
        contract.schema.iter().all(|field| field.name != "inputs"),
        "v1 declares no `inputs` field"
    );
}

#[test]
fn the_wire_is_one_post_accepting_the_live_200_and_the_documented_204() {
    let reg = vendored_registry();
    let shapes = reg
        .loaded("github", "dispatch_workflow")
        .expect("github.dispatch_workflow is loaded")
        .template
        .http_step_shapes()
        .expect("github.dispatch_workflow is an HTTP verb");
    assert_eq!(
        shapes,
        vec![HttpStepShape {
            method: "POST".to_string(),
            has_body: true,
        }],
        "one bodied POST — there is no guard read to make, since the endpoint has no CAS to claim"
    );

    let doc = vendored_doc();
    assert!(
        doc.contains("/repos/{owner}/{name}/actions/workflows/{workflow}/dispatches"),
        "the dispatch path must be interpolated from the frozen fields"
    );
    // GitHub DOCUMENTS a 204 and ANSWERS LIVE with a 200 carrying the started run's id. Both are
    // success; anything outside the set, 2xx included, still fails closed.
    assert!(
        doc.contains("success_statuses: [200, 204]"),
        "the accepted set is the live 200 and the documented 204"
    );
    // No `require`, and the absence is load-bearing: the executor's `require` pass is not
    // status-conditional, and a 204's empty body parses to JSON null, so a declared proof path
    // would fail the documented arm closed.
    let declares = |key: &str| {
        doc.lines()
            .any(|line| line.trim_start().starts_with(&format!("{key}:")))
    };
    assert!(
        !declares("require"),
        "a status-unconditional proof path would break the empty-bodied 204 arm"
    );
    // No `retention:` key, which means the DEFAULT (full) applies — the 200 body naming the run is
    // stored as an artifact, and the 204 arm simply has no body to store.
    assert!(
        !declares("retention"),
        "the default retention keeps the run-naming 200 body"
    );
}

#[test]
fn the_ref_constraint_admits_a_tag_and_refuses_a_qualified_ref() {
    // GitHub's dispatch endpoint takes a branch OR a tag name, so the constraint must not be a
    // branch-only one. `git_branch_name` is the honest pick: its predicate is git's own
    // check-ref-format on a BARE ref component, which admits `v0.1.0` and refuses the
    // `refs/heads/...` spelling (one resource, one pin string) and the cross-repository `user:ref`
    // form. The companion unit test in `templates::tests` pins that predicate directly.
    let doc = vendored_doc();
    assert!(
        doc.lines()
            .any(|line| line.contains("name: ref,") && line.contains("format: git_branch_name")),
        "`ref` declares the bare-ref-component constraint"
    );
    assert!(
        doc.lines()
            .any(|line| line.contains("name: workflow,") && !line.contains("format:")),
        "`workflow` declares no format — the vocabulary has no workflow-file shape (note, not code)"
    );
}

#[test]
fn the_sidecar_reviews_it_as_an_external_state_change_and_hash_joins() {
    let sources = SourceRegistry::official().unwrap();
    let catalog = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources)
        .expect("all vendored records parse and resolve their sources");
    catalog
        .join_all(&OntologyArtifacts::vendored())
        .expect("every record hash-joins against the vendored bytes");
    let record = catalog
        .get("github", "dispatch_workflow")
        .expect("github.dispatch_workflow has a reviewed ontology record");
    assert_eq!(record.semantics.risk_class, RiskClass::ExternalStateChange);
}

struct VendoredContracts;

impl ContractResolver for VendoredContracts {
    fn contract(&self, provider: &str, action: &str) -> Option<&ActionContract> {
        DefaultContractSource.contract(provider, action)
    }
}

#[test]
fn admitting_the_verb_grants_no_authority_at_all() {
    // The product working: a new verb in the catalog is vocabulary, never permission. With a corpus
    // that does not mention it, the request denies with the authority-gap reason — not because the
    // selector is unknown (it resolves), but because no operator has written a sentence for it.
    let contract = DefaultContractSource
        .contract("github", "dispatch_workflow")
        .expect("the contract resolves — the verb IS in the grammar");
    let resource = CanonicalResource::from_stored(
        r#"{"owner":"acme","name":"widgets","workflow":"release.yml","ref":"main"}"#,
        contract,
    )
    .expect("the frozen envelope canonicalizes");
    let sets = VendoredSetResolver;
    let evaluator = SentenceEvaluator::new(&sets, &VendoredContracts);

    let unrelated = parse_rules("allow github.read_repo").unwrap();
    assert_eq!(
        evaluator.evaluate(&unrelated, "github", "dispatch_workflow", &resource),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule
        },
        "no sentence names it, so it denies with the authority gap"
    );

    // And it is reachable the moment an operator writes the sentence — the gap is authority, not a
    // broken verb.
    let ruled = parse_rules(
        r#"allow github.dispatch_workflow where owner = "acme" and name = "widgets" and workflow = "release.yml" and ref = "main""#,
    )
    .unwrap();
    assert!(matches!(
        evaluator.evaluate(&ruled, "github", "dispatch_workflow", &resource),
        Decision::Allow { .. }
    ));
}
