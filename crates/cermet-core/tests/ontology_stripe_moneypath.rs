//! Moneypath: seven separate Stripe money mutations and three additive task sets.

use std::collections::BTreeSet;

use cermet_core::contract::{AllowBinding, FieldClass, ScalarKind};
use cermet_core::evidence;
use cermet_core::sets::{vendored_set_actions, SetResolver, VendoredSetResolver};
use cermet_core::templates::{catalog_of, CatalogClass, TemplateRegistry, VENDORED_CATALOG};
use cermet_core::{OntologyArtifacts, OntologyCatalog, SourceRegistry, VENDORED_ONTOLOGY};
use serde_yaml::Value;

const ACTIONS: [&str; 7] = [
    "create_payment_intent_off_session",
    "confirm_payment_intent",
    "capture_payment_intent",
    "cancel_payment_intent",
    "retry_invoice_payment",
    "refund_charge_bounded",
    "create_standard_payout",
];

fn vendored_registry() -> TemplateRegistry {
    let registry = TemplateRegistry::new();
    for document in VENDORED_CATALOG {
        registry.load(document).unwrap_or_else(|error| {
            panic!("vendored template failed to load: {error}\n{document}")
        });
    }
    registry
}

fn vendored_doc(action: &str) -> &'static str {
    let needle = format!("action: {action}\n");
    VENDORED_CATALOG
        .iter()
        .copied()
        .find(|document| document.contains("provider: stripe\n") && document.contains(&needle))
        .unwrap_or_else(|| panic!("stripe.{action} template must be vendored"))
}

fn yaml_strings(value: &Value) -> Vec<&str> {
    value
        .as_sequence()
        .expect("expected a YAML sequence")
        .iter()
        .map(|item| item.as_str().expect("expected a string sequence item"))
        .collect()
}

#[test]
fn seven_moneypath_actions_and_sidecars_are_vendored_with_catalog_parity() {
    assert_eq!(VENDORED_ONTOLOGY.len(), 48);

    let templates = vendored_registry();
    let catalog = catalog_of(&templates, true);
    assert_eq!(
        catalog
            .iter()
            .filter(|entry| entry.class == CatalogClass::Corpus)
            .count(),
        58
    );
    let sources = SourceRegistry::official().unwrap();
    let ontology = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources).unwrap();
    assert_eq!(ontology.len(), 48);
    ontology.join_all(&OntologyArtifacts::vendored()).unwrap();

    for action in ACTIONS {
        assert!(
            templates.resolve("stripe", action).is_some(),
            "stripe.{action} template is absent"
        );
        assert!(
            ontology.get("stripe", action).is_some(),
            "stripe.{action} ontology sidecar is absent"
        );
    }
}

#[test]
fn moneypath_sidecars_use_the_reviewed_money_effect_labels_and_sources() {
    let sources = SourceRegistry::official().unwrap();
    let ontology = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources).unwrap();
    for (action, effect) in [
        ("create_payment_intent_off_session", "funds_collect"),
        ("confirm_payment_intent", "funds_collect"),
        ("capture_payment_intent", "funds_collect"),
        ("retry_invoice_payment", "funds_collect"),
        ("refund_charge_bounded", "cash_refund"),
        ("create_standard_payout", "funds_outbound"),
    ] {
        let record = ontology.get("stripe", action).unwrap();
        assert!(
            record.review.summary.contains(effect),
            "stripe.{action} omits effect label {effect}"
        );
        assert!(!record.sources.is_empty(), "stripe.{action}");
    }
    let cancel = ontology.get("stripe", "cancel_payment_intent").unwrap();
    assert!(cancel.review.summary.contains("Cancel"));
    assert!(!cancel.sources.is_empty());
}

#[test]
fn evidence_profiles_are_versioned_exact_and_action_specific() {
    let expected = [
        (
            "stripe.create_payment_intent_off_session.v1",
            "create_payment_intent_off_session",
            &[
                ("amount", ScalarKind::Int),
                ("customer", ScalarKind::Str),
                ("payment_method", ScalarKind::Str),
            ][..],
            &["account", "currency", "mode"][..],
        ),
        (
            "stripe.confirm_payment_intent.v1",
            "confirm_payment_intent",
            &[
                ("payment_intent", ScalarKind::Str),
                ("payment_method", ScalarKind::Str),
            ][..],
            &[
                "account",
                "amount",
                "capture_method",
                "confirmation_method",
                "currency",
                "customer",
                "mode",
                "status",
            ][..],
        ),
        (
            "stripe.capture_payment_intent.v1",
            "capture_payment_intent",
            &[
                ("amount", ScalarKind::Int),
                ("payment_intent", ScalarKind::Str),
            ][..],
            &[
                "account",
                "amount_capturable",
                "capture_method",
                "currency",
                "customer",
                "intent_amount",
                "mode",
                "status",
            ][..],
        ),
        (
            "stripe.cancel_payment_intent.v1",
            "cancel_payment_intent",
            &[("payment_intent", ScalarKind::Str)][..],
            &[
                "account",
                "amount",
                "capture_method",
                "confirmation_method",
                "currency",
                "customer",
                "mode",
                "status",
            ][..],
        ),
        (
            "stripe.retry_invoice_payment.v1",
            "retry_invoice_payment",
            &[
                ("invoice", ScalarKind::Str),
                ("payment_method", ScalarKind::Str),
            ][..],
            &[
                "account", "amount", "currency", "customer", "mode", "status",
            ][..],
        ),
        (
            "stripe.refund_charge_bounded.v1",
            "refund_charge_bounded",
            &[("amount", ScalarKind::Int), ("charge", ScalarKind::Str)][..],
            &["account", "currency", "mode"][..],
        ),
        (
            "stripe.create_standard_payout.v1",
            "create_standard_payout",
            &[
                ("amount", ScalarKind::Int),
                ("destination", ScalarKind::Str),
                ("source_type", ScalarKind::Str),
            ][..],
            &["account", "currency", "mode"][..],
        ),
    ];

    for (id, action, inputs, outputs) in expected {
        let profile = evidence::profile(id).unwrap_or_else(|| panic!("missing profile {id}"));
        assert_eq!(profile.provider, "stripe");
        assert_eq!(profile.action, action);
        assert_eq!(profile.inputs.len(), inputs.len(), "{id} input count");
        for (field, ty) in inputs {
            assert!(
                profile
                    .inputs
                    .iter()
                    .any(|input| input.field == *field && input.ty == *ty),
                "{id} is missing input {field}:{ty:?}"
            );
        }
        assert_eq!(
            profile
                .outputs
                .iter()
                .map(|output| output.field)
                .collect::<BTreeSet<_>>(),
            outputs.iter().copied().collect::<BTreeSet<_>>(),
            "{id} outputs"
        );
        assert!(profile
            .outputs
            .iter()
            .all(|output| !output.source.is_empty()));
        assert!(!profile.sources.is_empty());
    }
}

#[test]
fn money_contracts_have_one_bounded_amount_and_provider_fields_are_not_agent_inputs() {
    let registry = vendored_registry();
    let agent_inputs = [
        (
            "create_payment_intent_off_session",
            &["amount", "customer", "payment_method"][..],
        ),
        (
            "confirm_payment_intent",
            &["payment_intent", "payment_method"][..],
        ),
        ("capture_payment_intent", &["amount", "payment_intent"][..]),
        ("cancel_payment_intent", &["payment_intent"][..]),
        ("retry_invoice_payment", &["invoice", "payment_method"][..]),
        ("refund_charge_bounded", &["amount", "charge"][..]),
        (
            "create_standard_payout",
            &["amount", "destination", "source_type"][..],
        ),
    ];

    for (action, expected_agent_inputs) in agent_inputs {
        let loaded = registry.loaded("stripe", action).unwrap();
        let contract = loaded.contract;
        let amount = contract.field_decl("amount").unwrap();
        assert!(amount.required, "stripe.{action}");
        assert_eq!(amount.ty, ScalarKind::Int, "stripe.{action}");
        assert_eq!(amount.class, FieldClass::SideEffect, "stripe.{action}");
        assert_eq!(amount.binding, AllowBinding::Bounded, "stripe.{action}");
        assert_eq!(
            contract
                .schema
                .iter()
                .filter(|field| field.class == FieldClass::SideEffect)
                .map(|field| field.name)
                .collect::<Vec<_>>(),
            ["amount"],
            "stripe.{action} has a second side effect"
        );

        let entry = loaded.template.catalog_entry(true, true);
        let actual_agent_inputs = entry
            .fields
            .iter()
            .filter(|field| field.origin == "agent_request")
            .map(|field| field.name.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual_agent_inputs,
            expected_agent_inputs.iter().copied().collect(),
            "stripe.{action} agent inputs"
        );
        for field in ["account", "mode", "currency"] {
            let catalog_field = entry
                .fields
                .iter()
                .find(|candidate| candidate.name == field)
                .unwrap();
            assert!(catalog_field.required, "stripe.{action}.{field}");
            assert_eq!(catalog_field.ty, "str", "stripe.{action}.{field}");
            assert_eq!(catalog_field.class, "identity", "stripe.{action}.{field}");
            assert_eq!(
                catalog_field.binding, "exact_resource_pin",
                "stripe.{action}.{field}"
            );
            assert_eq!(
                catalog_field.origin, "provider_resolved",
                "stripe.{action}.{field}"
            );
        }
    }
}

#[test]
fn mutation_wires_freeze_the_reviewed_single_effect_shapes() {
    let expected = [
        (
            "create_payment_intent_off_session",
            "/v1/payment_intents",
            "{ amount: \"{amount}\", currency: \"{currency}\", customer: \"{customer}\", payment_method: \"{payment_method}\", confirm: false }",
        ),
        (
            "confirm_payment_intent",
            "/v1/payment_intents/{payment_intent}/confirm",
            "{ payment_method: \"{payment_method}\", off_session: true, error_on_requires_action: true }",
        ),
        (
            "capture_payment_intent",
            "/v1/payment_intents/{payment_intent}/capture",
            "{ amount_to_capture: \"{amount}\" }",
        ),
        (
            "cancel_payment_intent",
            "/v1/payment_intents/{payment_intent}/cancel",
            "{}",
        ),
        (
            "retry_invoice_payment",
            "/v1/invoices/{invoice}/pay",
            "{ payment_method: \"{payment_method}\", off_session: true }",
        ),
        (
            "refund_charge_bounded",
            "/v1/refunds",
            "{ charge: \"{charge}\", amount: \"{amount}\" }",
        ),
        (
            "create_standard_payout",
            "/v1/payouts",
            "{ amount: \"{amount}\", currency: \"{currency}\", destination: \"{destination}\", source_type: \"{source_type}\", method: standard }",
        ),
    ];

    for (action, path, body) in expected {
        let document = vendored_doc(action);
        let yaml: Value = serde_yaml::from_str(document).unwrap();
        let steps = yaml["http"]["steps"].as_sequence().unwrap();
        assert_eq!(steps.len(), 1, "stripe.{action}");
        let step = &steps[0];
        assert_eq!(step["method"].as_str(), Some("POST"), "stripe.{action}");
        assert_eq!(step["path"].as_str(), Some(path), "stripe.{action}");
        assert_eq!(
            step["body_encoding"].as_str(),
            Some("form"),
            "stripe.{action}"
        );
        assert_eq!(
            step["body"],
            serde_yaml::from_str::<Value>(body).unwrap(),
            "stripe.{action}"
        );
        assert_eq!(step["success_statuses"].as_sequence().unwrap().len(), 1);
        assert_eq!(
            step["success_statuses"][0].as_i64(),
            Some(200),
            "stripe.{action}"
        );
        assert_eq!(step["retention"].as_str(), Some("none"), "stripe.{action}");
        assert!(
            step.get("keep").is_none(),
            "stripe.{action} must not project provider response fields"
        );
        if action == "retry_invoice_payment" {
            assert!(!yaml_strings(&step["require"]).contains(&"paid"));
            assert!(step["expect_literal"].get("paid").is_none());
        }
    }
}

#[test]
fn new_task_sets_are_additive_and_existing_expansions_remain_frozen() {
    assert_eq!(
        vendored_set_actions("stripe", "charge_ops"),
        [
            "create_payment_intent_off_session",
            "confirm_payment_intent",
            "capture_payment_intent",
            "cancel_payment_intent",
            "retry_invoice_payment",
        ]
    );
    assert_eq!(
        vendored_set_actions("stripe", "refund_ops"),
        ["get_charge", "list_refunds", "refund_charge_bounded"]
    );
    assert_eq!(
        vendored_set_actions("stripe", "payout_ops"),
        ["create_standard_payout"]
    );

    let resolver = VendoredSetResolver;
    let frozen = [
        (
            "read",
            "sha256:c0400c9d9fd691b13961b94fd4adfd4222fe0756e3b7e1970d0b93f88535b050",
        ),
        (
            "mutate",
            "sha256:b00627138536f43ba66db6a64c19744d033691be570b5e8b6bbd86f3e2e5b4c5",
        ),
        (
            "support",
            "sha256:06726bc2d4b8a94a6bc20742d805049bc139bde3ed992032f3b4b5557d98927e",
        ),
        (
            "support_lookup",
            "sha256:080c2d8d757fd008a3c9c154df234a4edd08e6fb38242cdd0acab59b7aa4314a",
        ),
        (
            "billing_support",
            "sha256:4d77f7080dc0d7989ac3c9ef7fa87c68ee7fb51cb9281f9bb4e353f28ef27b5d",
        ),
        (
            "catalog_admin",
            "sha256:7af396f2eaf8a4195e8581a8698032c3eb46ca9647e636686bc48b9c09711bf1",
        ),
        (
            "dispute_ops",
            "sha256:fa4e745f29ee6ca6661c1c092671a9b180e44969c9dd35817965d5df73273644",
        ),
        (
            "webhook_admin",
            "sha256:a19e2fc616a5e8e8267670ac6b3eb92de75a3a9906f51fa1a92b6ce634d4a06b",
        ),
    ];
    for (set, digest) in frozen {
        assert_eq!(
            resolver.current_snapshot("stripe", set).unwrap().digest(),
            digest,
            "stripe.{set} expansion changed"
        );
    }
}
