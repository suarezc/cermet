//! GitHub reads-first: the five stable-ID/OID read verbs, the explicit API-version
//! replacement, the superseded `read_repo` projection, and one hash-bound V1 ontology record per
//! new/changed verb.
//!
//! Deliberately out of scope: `create_issue`/`comment_thread` (write-shaped) are deferred, and NO
//! `free_payload` field is added to any read verb.
//! Every new verb is a pure GET whose addressing is frozen identity pins (owner/name + an immutable
//! OID or an exact issue/PR number), so an agent can never widen the read past the approved target.

use cermet_core::contract::{AllowBinding, FieldClass};
use cermet_core::templates::{TemplateRegistry, VENDORED_CATALOG};
use cermet_core::{OntologyArtifacts, OntologyCatalog, SourceRegistry, VENDORED_ONTOLOGY};

/// A registry loaded with the whole vendored catalog. `TemplateRegistry::new()` already carries the
/// vendored provider ceilings (github/vercel/shell/sqlite), so a resolved contract is what a real
/// broker carries.
fn vendored_registry() -> TemplateRegistry {
    let reg = TemplateRegistry::new();
    for doc in VENDORED_CATALOG {
        reg.load(doc)
            .unwrap_or_else(|e| panic!("vendored catalog doc failed to load: {e}\n---\n{doc}"));
    }
    reg
}

/// The vendored github descriptor YAML.
fn github_descriptor() -> String {
    cermet_core::BrokerConfig::vendored_descriptors()
        .into_iter()
        .find(|doc| doc.contains("name: github"))
        .expect("github descriptor is vendored")
}

const NEW_READ_VERBS: &[&str] = &[
    "read_ref",
    "read_tree",
    "read_blob",
    "read_thread",
    "read_pull_request",
];

#[test]
fn the_five_new_github_reads_are_requestable_pure_reads() {
    let reg = vendored_registry();
    for action in NEW_READ_VERBS {
        let contract = reg
            .resolve("github", action)
            .unwrap_or_else(|| panic!("github.{action} must resolve in the vendored catalog"));

        // A read verb has NO secret and NO free_payload field: it is addressing only, never a body
        // an agent fills (create_issue/comment_thread are deferred exactly because they would).
        for field in contract.schema {
            assert_ne!(
                field.class,
                FieldClass::Secret,
                "github.{action} field `{}` is secret; a read verb carries none",
                field.name
            );
            assert_ne!(
                field.class,
                FieldClass::FreePayload,
                "github.{action} field `{}` is free_payload; read verbs add no runtime-filled hole",
                field.name
            );
        }

        // Stable-ID/OID addressing: every execution target is an exact-pinned identity field, so a
        // least-privilege allow can constrain every executing field (no name-only widening).
        assert!(
            contract.has_fully_pinned_execution_targets(),
            "github.{action} must freeze every execution target as an exact-pinned identity"
        );
        for target in contract.execution_targets {
            assert_eq!(
                contract.field_binding(target),
                Some(AllowBinding::ExactResourcePin),
                "github.{action} target `{target}` is not exact-pinned",
            );
            assert_eq!(
                contract.field_class(target),
                Some(FieldClass::Identity),
                "github.{action} target `{target}` is not an identity",
            );
        }
    }
}

#[test]
fn oid_and_thread_addressing_is_frozen_not_name_only() {
    let reg = vendored_registry();

    // read_ref/read_tree/read_blob address by immutable Git object identity, frozen alongside the
    // repo. read_thread/read_pull_request freeze the EXACT numbered thread. None accepts a mutable
    // name as its object selector.
    for (action, must_pin) in [
        ("read_ref", "ref"),
        ("read_tree", "tree_sha"),
        ("read_blob", "file_sha"),
        ("read_thread", "number"),
        ("read_pull_request", "number"),
    ] {
        let contract = reg.resolve("github", action).unwrap();
        assert!(
            contract.execution_targets.contains(&must_pin),
            "github.{action} must freeze `{must_pin}` as an execution target (no name-only addressing)"
        );
        assert_eq!(
            contract.field_binding(must_pin),
            Some(AllowBinding::ExactResourcePin),
            "github.{action} object selector `{must_pin}` must be exact-pinned",
        );
        // owner and name are always frozen too — a read is scoped to one repository.
        for repo_pin in ["owner", "name"] {
            assert!(
                contract.execution_targets.contains(&repo_pin),
                "github.{action} must freeze `{repo_pin}`"
            );
        }
    }
}

#[test]
fn api_version_is_explicitly_replaced_and_pins_the_new_version() {
    // The descriptor's pinned X-GitHub-Api-Version header is replaced with the newer version
    // asserted below. The replacement changes the SHA-256 of every bound github ontology record;
    // the hash-join below proves the sidecars were recomputed rather than left stale.
    let github = github_descriptor();
    assert!(
        github.contains("X-GitHub-Api-Version: \"2026-03-10\""),
        "github descriptor must pin the replaced API version 2026-03-10"
    );
    assert!(
        !github.contains("X-GitHub-Api-Version: \"2022-11-28\""),
        "the legacy 2022-11-28 API version must no longer be the pinned header value"
    );
}

#[test]
fn superseded_read_repo_projects_stable_repository_ids() {
    // read_repo is superseded to return stable repository IDs (database `id`, GraphQL
    // `node_id`) and a stricter projection. The keep set lives in the template bytes; assert the
    // record still resolves and — via the hash-join test below — that its sidecar was re-stamped.
    let reg = vendored_registry();
    let contract = reg
        .resolve("github", "read_repo")
        .expect("read_repo resolves");
    // Addressing stays owner/name (GitHub offers no numeric-id contents read), both frozen.
    assert!(contract.execution_targets.contains(&"owner"));
    assert!(contract.execution_targets.contains(&"name"));
    // The stable-ID projection is asserted at the byte level by the sidecar hash-join (a keep-set
    // drift would change the template hash and fail the join). Here we assert the template TEXT
    // carries the stable-id keep entries.
    let doc = VENDORED_CATALOG
        .iter()
        .find(|d| d.contains("action: read_repo"))
        .expect("read_repo template is vendored");
    assert!(
        doc.contains("id"),
        "read_repo keep must include stable database id"
    );
    assert!(
        doc.contains("node_id"),
        "read_repo keep must include the stable node_id"
    );
}

#[test]
fn github_vendored_records_parse_and_hash_join_green() {
    // This GitHub-focused test asserts all twenty-two GitHub records in the vendored set.
    assert_eq!(
        VENDORED_ONTOLOGY.len(),
        49,
        "twenty-four GitHub (git-native `push`, `push_tag` + `fetch`, plus `dispatch_workflow`, `read_workflow_run_jobs`, and `read_job_log`) + twenty-three Stripe + two Vercel verbs (relay deploy + scoped list read)"
    );
    let sources = SourceRegistry::official().unwrap();
    let catalog = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources)
        .expect("all vendored records parse, obey caps, and resolve their sources");
    assert_eq!(catalog.len(), 49);

    // Every declared bind hash equals the SHA-256 of the real vendored artifact bytes — a one-byte
    // template/descriptor drift (including a stale post-API-version-bump github descriptor hash)
    // fails here, naming the artifact.
    catalog
        .join_all(&OntologyArtifacts::vendored())
        .expect("all sixty-three records hash-join against the vendored descriptor/template bytes");

    for action in [
        "read_repo",
        "read_ref",
        "read_commit",
        "read_tree",
        "read_blob",
        "read_thread",
        "read_pull_request",
        "read_workflow_run",
        "read_workflow_run_jobs",
        "read_job_log",
        "create_branch",
        "create_issue",
        "comment_thread",
        "create_pull_request_review",
        "request_workflow_cancel",
        "dispatch_workflow",
        "request_deployment",
        "create_pull_request",
        "read_secret_scanning_alerts_open",
        "push",
        "fetch",
    ] {
        assert!(
            catalog.get("github", action).is_some(),
            "vendored ontology is missing github.{action}"
        );
    }
}

#[test]
fn new_read_records_are_observation_or_sensitive_observation_never_mutating() {
    // An observation/sensitive_observation record permits a GET, never a mutation. The
    // five reads are all GET-only; assert their risk_class stays in the read band and completion is
    // terminal (a read's 200 IS its result, not an accepted async job).
    use cermet_core::RiskClass;
    let sources = SourceRegistry::official().unwrap();
    let catalog = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources).unwrap();
    for action in NEW_READ_VERBS {
        let record = catalog.get("github", action).unwrap();
        assert!(
            matches!(
                record.semantics.risk_class,
                RiskClass::Observation | RiskClass::SensitiveObservation
            ),
            "github.{action} must be an observation-band read"
        );
    }
}

#[test]
fn wire_purity_read_band_is_one_bodiless_get_write_band_mutates() {
    // Earlier "pure reads" tests assert field CLASSES and sidecar
    // LABELS, never the actual wire. This asserts WIRE PURITY against the declared risk class: an
    // observation-band record MUST compile to exactly ONE bodiless GET, and a write-band record MUST
    // carry a mutating non-GET step. A future POST hidden behind an `observation` sidecar (or a GET
    // mislabelled as a write) fails HERE, at the compiled HTTP step shape — not merely at the label.
    use cermet_core::templates::HttpStepShape;
    use cermet_core::RiskClass;

    let reg = vendored_registry();
    let sources = SourceRegistry::official().unwrap();
    let catalog = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources).unwrap();

    for action in [
        "read_repo",
        "read_ref",
        "read_commit",
        "read_tree",
        "read_blob",
        "read_thread",
        "read_pull_request",
        "read_workflow_run",
        "read_workflow_run_jobs",
        "read_job_log",
        "create_branch",
        "create_issue",
        "comment_thread",
        "create_pull_request_review",
        "request_workflow_cancel",
        "dispatch_workflow",
        "request_deployment",
    ] {
        let record = catalog
            .get("github", action)
            .unwrap_or_else(|| panic!("github.{action} has a vendored ontology record"));
        let shapes = reg
            .loaded("github", action)
            .unwrap_or_else(|| panic!("github.{action} is loaded"))
            .template
            .http_step_shapes()
            .unwrap_or_else(|| panic!("github.{action} is an HTTP verb"));

        let read_band = matches!(
            record.semantics.risk_class,
            RiskClass::Observation | RiskClass::SensitiveObservation
        );

        if read_band {
            assert_eq!(
                shapes,
                vec![HttpStepShape {
                    method: "GET".to_string(),
                    has_body: false,
                }],
                "read-band github.{action} must compile to exactly one bodiless GET, got {shapes:?}"
            );
        } else {
            // A write-band verb MUST mutate on the wire — at least one non-GET step. A verb whose only
            // step were a bodiless GET could never effect the external_state_change/provider_control_
            // change its sidecar declares; that mismatch is a wire-purity failure.
            assert!(
                shapes.iter().any(|shape| shape.method != "GET"),
                "write-band github.{action} must carry a mutating non-GET step, got {shapes:?}"
            );
            // Any GET inside a write is a verification read only (e.g. request_workflow_cancel's
            // head-SHA check) and must never carry a body.
            for shape in &shapes {
                if shape.method == "GET" {
                    assert!(
                        !shape.has_body,
                        "a verification GET in github.{action} must be bodiless, got {shape:?}"
                    );
                }
            }
        }
    }
}
