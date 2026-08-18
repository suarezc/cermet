//! `github.read_job_log` — the MINTED-URL read. The last rung of the diagnosis ladder:
//! `read_workflow_run` says the run failed, `read_workflow_run_jobs` says which job and which step,
//! and this hands back a short-lived, self-authorizing URL for that job's log.
//!
//! What these tests pin: the envelope is addressing ONLY (three required exact-pinned identities, no
//! `free_payload` and no `secret`), the wire is exactly one bodyless GET whose ONLY declared success
//! is a `302`, the `location` header it mints is DECLARED as retained, nothing is stored (a 302 has
//! no body), and the verb carries NO authority until an operator writes a sentence for it.
//!
//! The division of labour this shape encodes: the broker spends the vaulted credential to MINT a
//! scoped expiring capability, and credential-free native tooling (`curl`) moves the bytes — the
//! `vercel.deploy` relay at single-request scale. Nothing here follows the redirect.

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
        .find(|doc| doc.contains("provider: github") && doc.contains("action: read_job_log\n"))
        .expect("github.read_job_log template is vendored")
}

#[test]
fn the_log_envelope_is_three_frozen_identities_and_nothing_an_agent_authors() {
    let reg = vendored_registry();
    let contract = reg
        .resolve("github", "read_job_log")
        .expect("github.read_job_log resolves in the vendored catalog");

    // Addressing only: the repository and the job whose log URL is minted. Every one is an execution
    // target an allow can constrain, so no sentence can leave an executing field open.
    assert_eq!(contract.execution_targets, ["owner", "name", "job_id"]);
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
fn the_wire_is_one_bodyless_get_whose_only_success_is_the_declared_redirect() {
    let reg = vendored_registry();
    let shapes = reg
        .loaded("github", "read_job_log")
        .expect("github.read_job_log is loaded")
        .template
        .http_step_shapes()
        .expect("github.read_job_log is an HTTP verb");
    assert_eq!(
        shapes,
        vec![HttpStepShape {
            method: "GET".to_string(),
            has_body: false,
        }],
        "one bodyless GET — the credentialed mint, and nothing after it"
    );

    let doc = vendored_doc();
    assert!(
        doc.contains("/repos/{owner}/{name}/actions/jobs/{job_id}/logs"),
        "the log path must be interpolated from the frozen fields"
    );
    // The 302 IS the answer, and it is an answer only because the template DECLARES it. An
    // undeclared redirect still fails closed everywhere else in the corpus.
    assert!(
        doc.contains("success_statuses: [302]"),
        "302 is the ONLY success; anything else fails closed"
    );
    assert!(
        doc.contains("retain_headers: [location]"),
        "the minted URL is retained by DECLARATION, never by a general header channel"
    );
    // Nothing is stored: a 302 has no body. The mint rides the broker-authored envelope instead.
    assert!(
        doc.contains("retention: none"),
        "an empty response has no artifact to store"
    );
}

#[test]
fn the_broker_mints_and_stops_there() {
    let doc = vendored_doc();
    // No second step, no second origin, no follow: the whole verb is the one credentialed GET. If a
    // later change ever adds a step here, this is where "authorization and receipt, not carrier"
    // gets its say.
    assert_eq!(
        doc.matches("    - id: ").count(),
        1,
        "exactly one step: the mint"
    );
    // ...and the DECLARATION (comments excluded — the prose above it explains the shape at length)
    // names no host of its own. Every request this verb makes goes to the descriptor's pinned
    // GitHub origin; the minted URL's host is never reached from inside the daemon.
    let declaration: String = doc
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !declaration.contains("://"),
        "the declaration names no origin of its own:\n{declaration}"
    );
    let contract = DefaultContractSource
        .contract("github", "read_job_log")
        .expect("the contract resolves");
    let names: Vec<&str> = contract.schema.iter().map(|field| field.name).collect();
    assert_eq!(names, ["owner", "name", "job_id"]);
}

#[test]
fn the_job_id_pin_admits_one_spelling_per_job() {
    // `format: uint` is a canonical bare positive decimal, so "1" and "01" can never be two pins for
    // one job — the same constraint `read_workflow_run_jobs` puts on the run it belongs to.
    let doc = vendored_doc();
    assert!(
        doc.lines()
            .any(|line| line.contains("name: job_id,") && line.contains("format: uint")),
        "`job_id` declares the canonical-uint constraint"
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
        .get("github", "read_job_log")
        .expect("github.read_job_log has a reviewed ontology record");
    assert_eq!(record.semantics.risk_class, RiskClass::Observation);
    // The two facts an agent holding this receipt cannot work without: the URL EXPIRES, and it is a
    // derived grant rather than the vault credential (which is why carrying it is deliberate).
    let cautions = record.review.cautions.join(" ").to_lowercase();
    assert!(
        cautions.contains("expire"),
        "the review must say the minted URL expires: {cautions}"
    );
    assert!(
        cautions.contains("derived grant"),
        "the review must say what the URL IS: {cautions}"
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
    // A new verb in the catalog is vocabulary, never permission: with a corpus that does not mention
    // it, the request denies with the authority-gap reason — the selector resolves fine.
    let contract = DefaultContractSource
        .contract("github", "read_job_log")
        .expect("the contract resolves — the verb IS in the grammar");
    let resource = CanonicalResource::from_stored(
        r#"{"owner":"acme","name":"widgets","job_id":"12345"}"#,
        contract,
    )
    .expect("the frozen envelope canonicalizes");
    let sets = VendoredSetResolver;
    let evaluator = SentenceEvaluator::new(&sets, &VendoredContracts);

    let unrelated = parse_rules("allow github.read_repo").unwrap();
    assert_eq!(
        evaluator.evaluate(&unrelated, "github", "read_job_log", &resource),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule
        },
        "no sentence names it, so it denies with the authority gap"
    );

    let ruled =
        parse_rules(r#"allow github.read_job_log where owner = "acme" and name = "widgets""#)
            .unwrap();
    assert!(matches!(
        evaluator.evaluate(&ruled, "github", "read_job_log", &resource),
        Decision::Allow { .. }
    ));
}
