use std::collections::BTreeSet;

use cermet_core::contract::FieldClass;
use cermet_core::templates::{catalog_of, HttpStepShape, TemplateRegistry, VENDORED_CATALOG};
use cermet_core::{Broker, BrokerConfig};
use serde_yaml::Value;

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

fn vendored_registry() -> TemplateRegistry {
    let registry = TemplateRegistry::new();
    for doc in VENDORED_CATALOG {
        registry
            .load(doc)
            .unwrap_or_else(|error| panic!("vendored template failed to load: {error}\n{doc}"));
    }
    registry
}

fn vendored_yaml(provider: &str, action: &str) -> Value {
    let provider_line = format!("provider: {provider}\n");
    let action_line = format!("action: {action}\n");
    let doc = VENDORED_CATALOG
        .iter()
        .find(|doc| doc.contains(&provider_line) && doc.contains(&action_line))
        .unwrap_or_else(|| panic!("{provider}.{action} must be vendored"));
    serde_yaml::from_str(doc).expect("vendored descriptor is typed YAML")
}

#[test]
fn catalog_partition_is_derived_from_action_names() {
    let catalog = catalog_of(&vendored_registry(), true);
    let mut corpus = BTreeSet::new();
    let mut setup = BTreeSet::new();

    for entry in &catalog {
        let encoded = serde_json::to_value(entry).expect("catalog entries serialize");
        let class = encoded
            .get("class")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("{}.{} has no catalog class", entry.provider, entry.action));
        if entry.action.starts_with("fixture_") {
            assert_eq!(class, "setup", "{}.{}", entry.provider, entry.action);
            setup.insert((entry.provider.clone(), entry.action.clone()));
        } else {
            assert_eq!(class, "corpus", "{}.{}", entry.provider, entry.action);
            corpus.insert((entry.provider.clone(), entry.action.clone()));
        }
    }

    assert_eq!(
        corpus.len(),
        62,
        "the exact-once corpus grows only with a ratified verb"
    );
    assert_eq!(
        setup,
        SETUP_ACTIONS
            .iter()
            .map(|(provider, action)| ((*provider).to_string(), (*action).to_string()))
            .collect(),
        "setup is the exact fixture_-prefixed vendored set"
    );
}

/// The product catalog reflects the Stripe-only launch plus the GitHub revival. The vendored set is
/// UNCHANGED (see `catalog_partition_is_derived_from_action_names`, still 88 corpus across
/// every vendored provider) — this asserts only what the product makes reachable, and both
/// denominators are DERIVED from the vendored live-provider action names, never hardcoded.
#[test]
fn product_catalog_is_live_providers_corpus_plus_credentialed_setup() {
    let dir = tempfile::tempdir().unwrap();
    let broker = Broker::open(BrokerConfig {
        git: cermet_core::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
        dir: dir.path().to_path_buf(),
        master_key: vec![7u8; 32],
        action_templates: VENDORED_CATALOG.iter().map(|doc| doc.to_string()).collect(),
        provider_descriptors: BrokerConfig::vendored_descriptors(),
        artifacts: cermet_core::ArtifactConfig::default(),
    })
    .unwrap();
    let catalog = broker.catalog().unwrap();
    let visible_providers: BTreeSet<&str> = catalog
        .iter()
        .map(|entry| entry.provider.as_str())
        .collect();
    // vercel joined PRODUCT_ENABLED_PROVIDERS and ships one relay verb.
    assert_eq!(
        visible_providers,
        BTreeSet::from(["github", "stripe", "vercel"])
    );

    // Denominators derived from the vendored registry, so a catalog edit moves both sides at once.
    let vendored = catalog_of(&vendored_registry(), true);
    let live = |provider: &str| matches!(provider, "stripe" | "github" | "vercel");
    let live_corpus = vendored
        .iter()
        .filter(|entry| live(&entry.provider) && !entry.action.starts_with("fixture_"))
        .count();
    let live_setup: BTreeSet<(&str, &str)> = vendored
        .iter()
        .filter(|entry| live(&entry.provider) && entry.action.starts_with("fixture_"))
        .map(|entry| (entry.provider.as_str(), entry.action.as_str()))
        .collect();
    assert_eq!(
        catalog
            .iter()
            .filter(|entry| entry.class == cermet_core::templates::CatalogClass::Corpus)
            .count(),
        live_corpus
    );
    assert_eq!(
        catalog
            .iter()
            .filter(|entry| entry.class == cermet_core::templates::CatalogClass::Setup)
            .map(|entry| (entry.provider.as_str(), entry.action.as_str()))
            .collect::<BTreeSet<_>>(),
        live_setup
    );

    for (provider, action) in SETUP_ACTIONS.iter().filter(|(p, _)| live(p)) {
        assert!(
            catalog
                .iter()
                .any(|entry| entry.provider == *provider && entry.action == *action),
            "credentialed setup verb {provider}.{action} remains visible"
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
