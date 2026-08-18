//! `github.read_workflow_run_jobs` — the CI-diagnosis read. Read the JOBS of ONE Actions workflow
//! run on ONE frozen repository, each job carrying its own steps and their conclusions.
//!
//! What these tests pin: the envelope is addressing ONLY (three required exact-pinned identities,
//! no `free_payload` and no `secret`), the wire is exactly one bodyless GET whose only success is a
//! 200 proving `total_count` and `jobs`, the read is BOUNDED by a fixed `per_page` literal with no
//! agent-steerable cursor, and the verb carries NO authority until an operator writes a sentence
//! for it.

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
        .find(|doc| {
            doc.contains("provider: github") && doc.contains("action: read_workflow_run_jobs\n")
        })
        .expect("github.read_workflow_run_jobs template is vendored")
}

#[test]
fn the_jobs_envelope_is_three_frozen_identities_and_nothing_an_agent_authors() {
    let reg = vendored_registry();
    let contract = reg
        .resolve("github", "read_workflow_run_jobs")
        .expect("github.read_workflow_run_jobs resolves in the vendored catalog");

    // Addressing only: the repository and the run whose jobs are read. Every one is an execution
    // target an allow can constrain, so no sentence can leave an executing field open.
    assert_eq!(contract.execution_targets, ["owner", "name", "run_id"]);
    assert!(contract.has_fully_pinned_execution_targets());
    for field in contract.schema {
        assert!(field.required, "`{}` must be required", field.name);
        assert_eq!(
            field.class,
            FieldClass::Identity,
            "`{}` must be an identity — a read authors no payload",
            field.name
        );
        assert_eq!(
            field.binding,
            AllowBinding::ExactResourcePin,
            "`{}` must be exact-pinned",
            field.name
        );
    }
}

#[test]
fn the_wire_is_one_bodyless_get_proving_the_job_list_it_returned() {
    let reg = vendored_registry();
    let shapes = reg
        .loaded("github", "read_workflow_run_jobs")
        .expect("github.read_workflow_run_jobs is loaded")
        .template
        .http_step_shapes()
        .expect("github.read_workflow_run_jobs is an HTTP verb");
    assert_eq!(
        shapes,
        vec![HttpStepShape {
            method: "GET".to_string(),
            has_body: false,
        }],
        "one bodyless GET — an observation mutates nothing and guards nothing"
    );

    let doc = vendored_doc();
    assert!(
        doc.contains("/repos/{owner}/{name}/actions/runs/{run_id}/jobs"),
        "the jobs path must be interpolated from the frozen fields"
    );
    assert!(
        doc.contains("success_statuses: [200]"),
        "200 is the ONLY success; anything else fails closed"
    );
    // A 200 that carries neither key is not a job list. Failing closed there is what keeps an empty
    // or reshaped answer from rendering as a clean diagnosis.
    assert!(
        doc.contains("require: [total_count, jobs]"),
        "the verb proves the two keys its whole value rests on"
    );
}

#[test]
fn the_read_is_bounded_by_a_fixed_page_literal_with_no_agent_cursor() {
    let doc = vendored_doc();
    assert!(
        doc.contains("per_page: \"50\""),
        "`per_page` is a FIXED query literal, never an agent field"
    );
    // No cursor, and none of the three declared fields is a paging knob: the verb reads the first
    // bounded page and `total_count` makes any truncation visible rather than silent.
    assert!(
        !doc.contains("{page}") && !doc.contains("page: \"{"),
        "there is no agent-steerable page cursor"
    );
    let contract = DefaultContractSource
        .contract("github", "read_workflow_run_jobs")
        .expect("the contract resolves");
    let names: Vec<&str> = contract.schema.iter().map(|field| field.name).collect();
    assert_eq!(names, ["owner", "name", "run_id"]);
}

#[test]
fn the_run_id_pin_admits_one_spelling_per_run() {
    // `format: uint` is a canonical bare positive decimal, so "1" and "01" can never be two pins
    // for one run — the same constraint `read_workflow_run` puts on the same identifier.
    let doc = vendored_doc();
    assert!(
        doc.lines()
            .any(|line| line.contains("name: run_id,") && line.contains("format: uint")),
        "`run_id` declares the canonical-uint constraint"
    );
}

#[test]
fn the_sidecar_reviews_it_as_an_observation_and_hash_joins() {
    let sources = SourceRegistry::official().unwrap();
    let catalog = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources)
        .expect("all vendored records parse and resolve their sources");
    catalog
        .join_all(&OntologyArtifacts::vendored())
        .expect("every record hash-joins against the vendored bytes");
    let record = catalog
        .get("github", "read_workflow_run_jobs")
        .expect("github.read_workflow_run_jobs has a reviewed ontology record");
    assert_eq!(record.semantics.risk_class, RiskClass::Observation);
    // The cautions must name the thing an agent reading this verb's output most needs to know:
    // job and step NAMES are repository-authored text (T1), and the log CONTENT is not here.
    let cautions = record.review.cautions.join(" ").to_lowercase();
    assert!(
        cautions.contains("log"),
        "the review must say the log content is not in this projection"
    );
}

struct VendoredContracts;

impl ContractResolver for VendoredContracts {
    fn contract(&self, provider: &str, action: &str) -> Option<&ActionContract> {
        DefaultContractSource.contract(provider, action)
    }
}

#[test]
fn admitting_the_verb_grants_no_authority_at_all() {
    // A new verb in the catalog is vocabulary, never permission: with a corpus that does not
    // mention it, the request denies with the authority-gap reason — the selector resolves fine.
    let contract = DefaultContractSource
        .contract("github", "read_workflow_run_jobs")
        .expect("the contract resolves — the verb IS in the grammar");
    let resource = CanonicalResource::from_stored(
        r#"{"owner":"acme","name":"widgets","run_id":"12345"}"#,
        contract,
    )
    .expect("the frozen envelope canonicalizes");
    let sets = VendoredSetResolver;
    let evaluator = SentenceEvaluator::new(&sets, &VendoredContracts);

    let unrelated = parse_rules("allow github.read_repo").unwrap();
    assert_eq!(
        evaluator.evaluate(&unrelated, "github", "read_workflow_run_jobs", &resource),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule
        },
        "no sentence names it, so it denies with the authority gap"
    );

    let ruled = parse_rules(
        r#"allow github.read_workflow_run_jobs where owner = "acme" and name = "widgets""#,
    )
    .unwrap();
    assert!(matches!(
        evaluator.evaluate(&ruled, "github", "read_workflow_run_jobs", &resource),
        Decision::Allow { .. }
    ));
}
