use std::collections::BTreeSet;

use cermet_core::contract::FieldClass;
use cermet_core::templates::{
    vendored_action_templates, HttpStepShape, TemplateRegistry, FIXTURE_CATALOG, VENDORED_CATALOG,
};
use cermet_core::{Broker, BrokerConfig};
use serde_yaml::Value;

mod common;
use common::{FIXTURE_VERBS, PRODUCT_VERBS};

const SETUP_ACTIONS: &[(&str, &str)] = &[
    ("github", "fixture_repositories_discover"),
    ("github", "fixture_workflow_runs_discover"),
    ("stripe", "fixture_account_discover"),
    ("stripe", "fixture_bypass_pending_charge_create"),
    ("stripe", "fixture_customer_create"),
    ("stripe", "fixture_dispute_charge_create"),
    ("stripe", "fixture_draft_invoice_create"),
    ("stripe", "fixture_manual_capture_payment_intent_create"),
    ("stripe", "fixture_payment_method_attach"),
    ("stripe", "fixture_price_create"),
    ("stripe", "fixture_product_create"),
    ("stripe", "fixture_refundable_charge_create"),
    ("stripe", "fixture_subscription_create"),
    ("stripe", "fixture_webhook_endpoint_create"),
];

const STRIPE_SETUP_MUTATIONS: &[&str] = &[
    "fixture_bypass_pending_charge_create",
    "fixture_customer_create",
    "fixture_dispute_charge_create",
    "fixture_draft_invoice_create",
    "fixture_manual_capture_payment_intent_create",
    "fixture_payment_method_attach",
    "fixture_price_create",
    "fixture_product_create",
    "fixture_refundable_charge_create",
    "fixture_subscription_create",
    "fixture_webhook_endpoint_create",
];

/// Every document THIS build vendors — the product catalog plus the setup fixtures, which the
/// crate's `fixtures` feature compiles in for its own tests.
fn vendored_registry() -> TemplateRegistry {
    let registry = TemplateRegistry::new();
    for doc in vendored_action_templates() {
        registry
            .load(&doc)
            .unwrap_or_else(|error| panic!("vendored template failed to load: {error}\n{doc}"));
    }
    registry
}

fn vendored_yaml(provider: &str, action: &str) -> Value {
    let provider_line = format!("provider: {provider}\n");
    let action_line = format!("action: {action}\n");
    let docs = vendored_action_templates();
    let doc = docs
        .iter()
        .find(|doc| doc.contains(&provider_line) && doc.contains(&action_line))
        .unwrap_or_else(|| panic!("{provider}.{action} must be vendored"));
    serde_yaml::from_str(doc).expect("vendored descriptor is typed YAML")
}

/// The SPLIT, asserted from both sides: the product catalog a release build vendors carries no
/// setup fixture, and the fixture catalog is exactly the `fixture_*` set this suite exercises.
/// Nothing derives an agent-visible CLASS from the name any more — a verb the catalog would have to
/// hide is a verb a sentence could name and nothing could find, so the shipped set simply does not
/// contain one.
#[test]
fn the_product_catalog_carries_no_setup_fixture() {
    let product: BTreeSet<(String, String)> = VENDORED_CATALOG
        .iter()
        .map(|doc| {
            let parsed: Value = serde_yaml::from_str(doc).expect("vendored document parses");
            (
                parsed["provider"].as_str().unwrap().to_string(),
                parsed["action"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        product.len(),
        PRODUCT_VERBS,
        "the product catalog grows only with a ratified verb"
    );
    assert!(
        !product
            .iter()
            .any(|(_, action)| action.starts_with("fixture_")),
        "a setup fixture must never enter the product catalog"
    );

    let fixtures: BTreeSet<(String, String)> = FIXTURE_CATALOG
        .iter()
        .map(|doc| {
            let parsed: Value = serde_yaml::from_str(doc).expect("fixture document parses");
            (
                parsed["provider"].as_str().unwrap().to_string(),
                parsed["action"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        fixtures,
        SETUP_ACTIONS
            .iter()
            .map(|(provider, action)| ((*provider).to_string(), (*action).to_string()))
            .collect(),
        "the fixture catalog is the exact `fixture_`-prefixed set"
    );
    assert_eq!(fixtures.len(), FIXTURE_VERBS);
}

/// A broker booted on the PRODUCT catalog alone — what an installed box does — serves the product
/// verbs of the live providers and not one fixture. Boot it on this build's full vendored set (the
/// sitting's shape) and the fixtures come with it, requestable like any other verb: no surface
/// hides them, because nothing about them is hidden any more.
#[test]
fn a_release_broker_serves_the_product_catalog_and_no_fixture() {
    let open = |templates: Vec<String>| {
        let dir = tempfile::tempdir().unwrap();
        let broker = Broker::open(BrokerConfig {
            git: cermet_core::git::GitConfig::at(
                std::env::temp_dir().join("cermet-test-quarantine"),
            ),
            dir: dir.path().to_path_buf(),
            master_key: vec![7u8; 32],
            action_templates: templates,
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: cermet_core::ArtifactConfig::default(),
        })
        .unwrap();
        let catalog = broker.catalog().unwrap();
        drop(broker);
        catalog
    };

    let release = open(VENDORED_CATALOG.iter().map(|doc| doc.to_string()).collect());
    assert_eq!(
        release
            .iter()
            .map(|entry| entry.provider.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["github", "stripe", "vercel"])
    );
    assert_eq!(release.len(), PRODUCT_VERBS);
    assert!(
        !release
            .iter()
            .any(|entry| entry.action.starts_with("fixture_")),
        "a release broker must not serve a setup fixture"
    );

    let with_fixtures = open(vendored_action_templates());
    assert_eq!(with_fixtures.len(), PRODUCT_VERBS + FIXTURE_VERBS);
    for (provider, action) in SETUP_ACTIONS {
        let entry = with_fixtures
            .iter()
            .find(|entry| entry.provider == *provider && entry.action == *action)
            .unwrap_or_else(|| panic!("{provider}.{action} is served by a fixtures build"));
        assert!(
            entry.requestable,
            "{provider}.{action} is loaded, so the catalog lists it requestable — the corpus \
             invariant: nothing a sentence can name is hidden from the catalog"
        );
    }
}

#[test]
fn setup_contracts_are_non_money_and_secret_free() {
    let registry = vendored_registry();
    for (provider, action) in SETUP_ACTIONS {
        let contract = registry
            .resolve(provider, action)
            .unwrap_or_else(|| panic!("{provider}.{action} must resolve"));
        assert!(
            contract
                .schema
                .iter()
                .all(|field| field.class != FieldClass::Secret),
            "{provider}.{action} must carry no secret field"
        );
    }
}

#[test]
fn github_repository_discovery_reads_one_pinned_repository() {
    // Discovery is an owner/name-PINNED read, not an account-wide repository search. The bound is
    // the strongest one available — the read addresses exactly one repository — and it is
    // request-side, where a bound belongs. `filter_prefix` was retired with every other response
    // projection; it must not return.
    let yaml = vendored_yaml("github", "fixture_repositories_discover");
    let fields = yaml["fields"]
        .as_sequence()
        .expect("repository discovery declares fields");
    assert_eq!(
        fields.len(),
        2,
        "discovery is addressed by owner and name only"
    );
    for field in fields {
        assert_eq!(field["class"].as_str(), Some("identity"));
        assert_eq!(field["binding"].as_str(), Some("exact_resource_pin"));
        assert_eq!(field["required"].as_bool(), Some(true));
    }
    assert_eq!(
        yaml["execution_targets"]
            .as_sequence()
            .expect("execution targets")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        ["owner", "name"],
        "both addressing fields must be pinned execution targets"
    );
    let steps = yaml["http"]["steps"]
        .as_sequence()
        .expect("repository discovery has steps");
    assert_eq!(steps.len(), 1, "one frozen GraphQL read, no inventory step");
    assert!(
        steps[0]["filter_prefix"].is_null(),
        "the retired projection key must be gone from the vendored document"
    );
    let query = steps[0]["graphql_query"]
        .as_str()
        .expect("frozen GraphQL query");
    assert!(
        query.contains("repository(owner: $owner, name: $name)"),
        "discovery must address one repository by owner/name: {query}"
    );
    assert!(
        !query.contains("search("),
        "the account-wide repository search must not return: {query}"
    );
    // Retention is DECLARED and defaults to full, so a verb that keeps its body simply says
    // nothing. Two github verbs still cap storage: read_secret_scanning_alerts_open, a
    // request-side mitigation for its sensitive body, and read_job_log, whose `302` answer has
    // no body to store at all.
    assert!(
        steps[0]["retention"].is_null(),
        "discovery follows the declared retention default; it must not re-declare a cap"
    );
    let capped: Vec<&str> = VENDORED_CATALOG
        .iter()
        .filter(|doc| doc.contains("provider: github\n") && doc.contains("retention: none"))
        .filter_map(|doc| doc.lines().find_map(|line| line.strip_prefix("action: ")))
        .collect();
    assert_eq!(
        capped,
        ["read_job_log", "read_secret_scanning_alerts_open"],
        "exactly two github verbs cap their storage: one mitigation and one bodyless mint"
    );
}

#[test]
fn stripe_setup_mutations_prove_test_mode_before_bounded_setup_effects() {
    let registry = vendored_registry();
    let get = HttpStepShape {
        method: "GET".to_string(),
        has_body: false,
    };
    let post = HttpStepShape {
        method: "POST".to_string(),
        has_body: true,
    };

    for action in STRIPE_SETUP_MUTATIONS {
        let loaded = registry
            .loaded("stripe", action)
            .unwrap_or_else(|| panic!("stripe.{action} must load"));
        let expected = match *action {
            "fixture_manual_capture_payment_intent_create" | "fixture_subscription_create" => {
                vec![get.clone(), get.clone(), post.clone(), post.clone()]
            }
            "fixture_dispute_charge_create" => {
                vec![get.clone(), get.clone(), post.clone(), get.clone()]
            }
            _ => vec![get.clone(), get.clone(), post.clone()],
        };
        assert_eq!(
            loaded.template.http_step_shapes(),
            Some(expected),
            "stripe.{action} must bind the account and prove test mode before bounded setup effects"
        );
        let yaml = vendored_yaml("stripe", action);
        let steps = yaml["http"]["steps"]
            .as_sequence()
            .expect("stripe setup action has steps");
        assert_eq!(steps[0]["path"].as_str(), Some("/v1/account"));
        assert_eq!(steps[1]["path"].as_str(), Some("/v1/balance"));
        assert_eq!(
            steps[1]["expect_literal"]["livemode"].as_bool(),
            Some(false),
            "stripe.{action} must refuse a live credential before its mutation"
        );
    }
}

#[test]
fn stripe_setup_amounts_have_descriptor_ceiling_one_hundred() {
    for (action, field_name) in [
        ("fixture_bypass_pending_charge_create", "amount"),
        ("fixture_dispute_charge_create", "amount"),
        ("fixture_manual_capture_payment_intent_create", "amount"),
        ("fixture_price_create", "unit_amount"),
        ("fixture_refundable_charge_create", "amount"),
    ] {
        let yaml = vendored_yaml("stripe", action);
        let field = yaml["fields"]
            .as_sequence()
            .expect("setup fields")
            .iter()
            .find(|field| field["name"].as_str() == Some(field_name))
            .unwrap_or_else(|| panic!("stripe.{action}.{field_name} must exist"));
        assert_eq!(
            field["max_int"].as_i64(),
            Some(100),
            "stripe.{action}.{field_name} must remain descriptor-bounded"
        );
    }
}

#[test]
fn stripe_dispute_setup_has_a_bounded_charge_keyed_reconciliation_poll() {
    let yaml = vendored_yaml("stripe", "fixture_dispute_charge_create");
    let discover = &yaml["http"]["steps"][3];
    assert_eq!(
        discover["query"]["charge"].as_str(),
        Some("{dispute_charge_id}")
    );
    assert_eq!(discover["poll"]["attempts"].as_i64(), Some(4));
    assert_eq!(discover["poll"]["delay_ms"].as_i64(), Some(250));
    assert_eq!(
        discover["poll"]["until_nonempty"]
            .as_sequence()
            .expect("poll collection")
            .iter()
            .map(|value| value.as_str().expect("poll path"))
            .collect::<Vec<_>>(),
        ["data"]
    );
    assert_eq!(
        discover["result_captures"]["created_charge"].as_str(),
        Some("dispute_charge_id")
    );
}

#[test]
fn stripe_account_discovery_returns_mode_and_account_posture() {
    // A standard-account secret key cannot see external accounts under the pinned
    // Stripe-Version, so discovery proves only account identity, currency, payout eligibility,
    // and test mode — it never claims a payout-destination page.
    let yaml = vendored_yaml("stripe", "fixture_account_discover");
    let steps = yaml["http"]["steps"]
        .as_sequence()
        .expect("account discovery has steps");
    assert_eq!(steps.len(), 2);
    assert_eq!(
        steps[0]["require"]
            .as_sequence()
            .expect("account requirements")
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>(),
        ["id", "object", "default_currency", "payouts_enabled"]
            .into_iter()
            .collect()
    );
    assert!(
        steps[0].get("capture_keep").is_none(),
        "no payout-destination page is claimable with a standard-account key"
    );
    assert_eq!(
        steps[1]["expect_literal"]["livemode"].as_bool(),
        Some(false)
    );
    assert!(
        steps[1]["keep"].is_null(),
        "the retired projection key must be gone; `require` is the posture proof"
    );
    assert_eq!(
        steps[1]["result_captures"]
            .as_mapping()
            .expect("allowlisted prior facts")
            .len(),
        3
    );
}
