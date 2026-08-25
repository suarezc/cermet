//! Stripe corpus: narrow reads, fixed mutations, and their hash-bound ontology records.

use cermet_core::contract::{AllowBinding, FieldClass, ScalarKind};
use cermet_core::templates::{HttpStepShape, TemplateRegistry, VENDORED_CATALOG};
use cermet_core::{
    Idempotency, OntologyArtifacts, OntologyCatalog, Reversibility, RiskClass, SourceRegistry,
    VENDORED_ONTOLOGY,
};
use serde_yaml::Value;

const M1_ACTIONS: [&str; 7] = [
    "get_invoice",
    "list_invoices_for_customer",
    "get_payment_intent",
    "get_dispute_summary",
    "get_product",
    "get_price",
    "list_active_prices",
];

const M2_ACTIONS: [&str; 6] = [
    "cancel_subscription_at_period_end",
    "resume_subscription_collection",
    "mark_invoice_uncollectible",
    "issue_credit_note_adjustment_no_email",
    "archive_product",
    "archive_price",
];

const M3_ACTIONS: [&str; 3] = [
    "stage_dispute_evidence",
    "submit_dispute_evidence",
    "update_webhook_endpoint_fixed_bundle",
];

const EVIDENCE_FIELDS: [&str; 27] = [
    "access_activity_log",
    "billing_address",
    "cancellation_policy",
    "cancellation_policy_disclosure",
    "cancellation_rebuttal",
    "customer_communication",
    "customer_email_address",
    "customer_name",
    "customer_purchase_ip",
    "customer_signature",
    "duplicate_charge_documentation",
    "duplicate_charge_explanation",
    "duplicate_charge_id",
    "product_description",
    "receipt",
    "refund_policy",
    "refund_policy_disclosure",
    "refund_refusal_explanation",
    "service_date",
    "service_documentation",
    "shipping_address",
    "shipping_carrier",
    "shipping_date",
    "shipping_documentation",
    "shipping_tracking_number",
    "uncategorized_file",
    "uncategorized_text",
];

const EVIDENCE_ID_FIELDS: [&str; 10] = [
    "cancellation_policy",
    "customer_communication",
    "customer_signature",
    "duplicate_charge_documentation",
    "duplicate_charge_id",
    "receipt",
    "refund_policy",
    "service_documentation",
    "shipping_documentation",
    "uncategorized_file",
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

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_sequence()
        .expect("expected a YAML sequence")
        .iter()
        .map(|item| item.as_str().expect("expected a string sequence item"))
        .collect()
}

#[test]
fn legacy_refund_returns_its_frozen_charge_for_runner_equality() {
    // The acceptance suite equality-binds the provider's `charge` on `stripe.refund`. It used to need
    // a `keep` entry to survive projection; under the verbatim contract it arrives because
    // nothing removes it. What the template still owes is the REQUEST binding.
    let yaml: Value = serde_yaml::from_str(vendored_doc("refund")).unwrap();
    let step = &yaml["http"]["steps"][0];
    assert!(
        step["keep"].is_null(),
        "the retired projection key must be gone from the vendored document"
    );
    // The REQUEST is what freezes the charge; the response then carries it back untouched.
    assert_eq!(step["body"]["charge"].as_str(), Some("{charge}"));
}

#[test]
fn three_m3_actions_are_vendored_in_both_registries() {
    let templates = vendored_registry();
    let sources = SourceRegistry::official().unwrap();
    let ontology = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources).unwrap();
    let missing_templates = M3_ACTIONS
        .iter()
        .copied()
        .filter(|action| templates.resolve("stripe", action).is_none())
        .collect::<Vec<_>>();
    let missing_sidecars = M3_ACTIONS
        .iter()
        .copied()
        .filter(|action| ontology.get("stripe", action).is_none())
        .collect::<Vec<_>>();
    assert!(
        missing_templates.is_empty() && missing_sidecars.is_empty(),
        "missing templates {missing_templates:?}; missing sidecars {missing_sidecars:?}"
    );
}

#[test]
fn stage_dispute_evidence_has_exact_optional_frozen_fields_and_output_boundary() {
    let registry = vendored_registry();
    let contract = registry
        .resolve("stripe", "stage_dispute_evidence")
        .expect("stage action must resolve");
    assert_eq!(contract.schema.len(), 28);
    assert_eq!(contract.execution_targets, ["dispute"]);
    assert_eq!(contract.consumes.len(), 28);
    assert_eq!(contract.consumes[0], "dispute");
    assert_eq!(&contract.consumes[1..], EVIDENCE_FIELDS);
    assert!(contract.has_fully_pinned_execution_targets());

    let dispute = contract.field_decl("dispute").unwrap();
    assert!(dispute.required);
    assert_eq!(dispute.ty, ScalarKind::Str);
    assert_eq!(dispute.class, FieldClass::Identity);
    assert_eq!(dispute.binding, AllowBinding::ExactResourcePin);
    for field in EVIDENCE_FIELDS {
        let declaration = contract.field_decl(field).unwrap();
        assert!(!declaration.required, "{field} must remain optional");
        assert_eq!(declaration.ty, ScalarKind::Str, "{field}");
        if EVIDENCE_ID_FIELDS.contains(&field) {
            assert_eq!(declaration.class, FieldClass::Identity, "{field}");
            assert_eq!(
                declaration.binding,
                AllowBinding::ExactResourcePin,
                "{field}"
            );
        } else {
            assert_eq!(declaration.class, FieldClass::FreePayload, "{field}");
            assert_eq!(declaration.binding, AllowBinding::Unbound, "{field}");
        }
    }
    assert!(contract.field_decl("evidence").is_none());
    assert!(contract.field_decl("enhanced_evidence").is_none());
    assert!(contract.field_decl("submit").is_none());

    let yaml: Value = serde_yaml::from_str(vendored_doc("stage_dispute_evidence")).unwrap();
    let fields = yaml["fields"].as_sequence().unwrap();
    for field in EVIDENCE_FIELDS {
        let declaration = fields
            .iter()
            .find(|declaration| declaration["name"].as_str() == Some(field))
            .unwrap();
        assert_eq!(declaration["max_chars"].as_i64(), Some(20_000), "{field}");
    }
    assert_eq!(
        strings(&yaml["string_char_budget"]["fields"]),
        EVIDENCE_FIELDS
    );
    assert_eq!(
        yaml["string_char_budget"]["max_chars"].as_i64(),
        Some(150_000)
    );
    let step = &yaml["http"]["steps"][0];
    assert_eq!(step["method"].as_str(), Some("POST"));
    assert_eq!(step["path"].as_str(), Some("/v1/disputes/{dispute}"));
    assert_eq!(step["body_encoding"].as_str(), Some("form"));
    assert_eq!(step["body"]["submit"].as_bool(), Some(false));
    let evidence = step["body"]["evidence"].as_mapping().unwrap();
    assert_eq!(evidence.len(), 27);
    for field in EVIDENCE_FIELDS {
        let placeholder = format!("{{{field}?}}");
        assert_eq!(
            step["body"]["evidence"][field].as_str(),
            Some(placeholder.as_str()),
            "{field}"
        );
    }
    assert_eq!(step["success_statuses"][0].as_i64(), Some(200));
    assert_eq!(
        strings(&step["require"]),
        ["id", "status", "evidence_details"]
    );
    // The provider error body is evidence, not a leak channel.
}

#[test]
fn submit_dispute_evidence_is_standalone_and_carries_only_fixed_submit_true() {
    let registry = vendored_registry();
    let contract = registry
        .resolve("stripe", "submit_dispute_evidence")
        .expect("submit action must resolve");
    assert_eq!(contract.schema.len(), 1);
    assert_eq!(contract.consumes, ["dispute"]);
    assert_eq!(contract.execution_targets, ["dispute"]);
    let dispute = contract.field_decl("dispute").unwrap();
    assert!(dispute.required);
    assert_eq!(dispute.class, FieldClass::Identity);
    assert_eq!(dispute.binding, AllowBinding::ExactResourcePin);
    for forbidden in EVIDENCE_FIELDS.into_iter().chain(["evidence", "submit"]) {
        assert!(contract.field_decl(forbidden).is_none(), "{forbidden}");
    }

    let yaml: Value = serde_yaml::from_str(vendored_doc("submit_dispute_evidence")).unwrap();
    let step = &yaml["http"]["steps"][0];
    assert_eq!(step["method"].as_str(), Some("POST"));
    assert_eq!(step["path"].as_str(), Some("/v1/disputes/{dispute}"));
    assert_eq!(step["body_encoding"].as_str(), Some("form"));
    assert_eq!(step["body"].as_mapping().unwrap().len(), 1);
    assert_eq!(step["body"]["submit"].as_bool(), Some(true));
    assert_eq!(step["success_statuses"][0].as_i64(), Some(200));
    assert_eq!(
        strings(&step["require"]),
        ["id", "status", "evidence_details.submission_count"]
    );
    // The provider error body is evidence, not a leak channel.
}

#[test]
fn webhook_update_has_two_exact_targets_and_one_fixed_literal_bundle() {
    let registry = vendored_registry();
    let contract = registry
        .resolve("stripe", "update_webhook_endpoint_fixed_bundle")
        .expect("webhook action must resolve");
    assert_eq!(contract.schema.len(), 2);
    assert_eq!(contract.consumes, ["endpoint", "url"]);
    assert_eq!(contract.execution_targets, ["endpoint", "url"]);
    assert!(contract.has_fully_pinned_execution_targets());
    for field in ["endpoint", "url"] {
        let declaration = contract.field_decl(field).unwrap();
        assert!(declaration.required);
        assert_eq!(declaration.ty, ScalarKind::Str);
        assert_eq!(declaration.class, FieldClass::Identity);
        assert_eq!(declaration.binding, AllowBinding::ExactResourcePin);
    }

    let document = vendored_doc("update_webhook_endpoint_fixed_bundle");
    assert!(document.contains("format: https_url"));
    let yaml: Value = serde_yaml::from_str(document).unwrap();
    let step = &yaml["http"]["steps"][0];
    assert_eq!(step["method"].as_str(), Some("POST"));
    assert_eq!(
        step["path"].as_str(),
        Some("/v1/webhook_endpoints/{endpoint}")
    );
    assert_eq!(step["body_encoding"].as_str(), Some("form"));
    assert_eq!(step["body"].as_mapping().unwrap().len(), 2);
    assert_eq!(step["body"]["url"].as_str(), Some("{url}"));
    assert_eq!(
        strings(&step["body"]["enabled_events"]),
        ["charge.succeeded", "charge.failed"]
    );
    assert_eq!(
        step["expect_literal"],
        serde_yaml::from_str::<Value>("{ enabled_events: [charge.succeeded, charge.failed] }")
            .unwrap()
    );
    assert_eq!(
        step["expect_eq"],
        serde_yaml::from_str::<Value>("{ url: url }").unwrap()
    );
    assert_eq!(
        strings(&step["require"]),
        ["id", "url", "status", "enabled_events"]
    );
    assert_eq!(step["success_statuses"][0].as_i64(), Some(200));
    // The provider error body is evidence, not a leak channel.
    assert!(!document.contains("disabled"));
    assert!(!document.contains("'*'") && !document.contains("\"*\""));
}

#[test]
fn six_m2_actions_are_vendored_in_both_registries() {
    let templates = vendored_registry();
    let sources = SourceRegistry::official().unwrap();
    let ontology = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources).unwrap();
    let missing_templates = M2_ACTIONS
        .iter()
        .copied()
        .filter(|action| templates.resolve("stripe", action).is_none())
        .collect::<Vec<_>>();
    let missing_sidecars = M2_ACTIONS
        .iter()
        .copied()
        .filter(|action| ontology.get("stripe", action).is_none())
        .collect::<Vec<_>>();

    assert!(
        missing_templates.is_empty() && missing_sidecars.is_empty(),
        "missing templates {missing_templates:?}; missing sidecars {missing_sidecars:?}"
    );
}

#[test]
fn seven_reads_are_requestable_exact_pinned_one_step_gets() {
    let registry = vendored_registry();
    for (action, target) in [
        ("get_invoice", "invoice"),
        ("list_invoices_for_customer", "customer"),
        ("get_payment_intent", "payment_intent"),
        ("get_dispute_summary", "dispute"),
        ("get_product", "product"),
        ("get_price", "price"),
        ("list_active_prices", "product"),
    ] {
        let contract = registry
            .resolve("stripe", action)
            .unwrap_or_else(|| panic!("stripe.{action} must resolve"));
        assert_eq!(contract.schema.len(), 1, "stripe.{action}");
        assert_eq!(contract.execution_targets, [target], "stripe.{action}");
        assert_eq!(contract.consumes, [target], "stripe.{action}");
        assert!(contract.has_fully_pinned_execution_targets());
        assert!(contract.schema.iter().all(|field| {
            field.required
                && field.class == FieldClass::Identity
                && field.binding == AllowBinding::ExactResourcePin
        }));

        let shapes = registry
            .loaded("stripe", action)
            .unwrap()
            .template
            .http_step_shapes()
            .unwrap();
        assert_eq!(
            shapes,
            [HttpStepShape {
                method: "GET".to_string(),
                has_body: false,
            }],
            "stripe.{action} must be exactly one bodiless GET"
        );
    }
}

#[test]
fn seven_reads_have_the_exact_reviewed_wire_and_projection_shapes() {
    struct Expected<'a> {
        action: &'a str,
        path: &'a str,
        query: &'a [(&'a str, &'a str)],
        require: &'a [&'a str],
    }

    let expected = [
        Expected {
            action: "get_invoice",
            path: "/v1/invoices/{invoice}",
            query: &[],
            require: &["id", "object", "status"],
        },
        Expected {
            action: "list_invoices_for_customer",
            path: "/v1/invoices",
            query: &[("customer", "{customer}"), ("limit", "10")],
            require: &["data", "has_more"],
        },
        Expected {
            action: "get_payment_intent",
            path: "/v1/payment_intents/{payment_intent}",
            query: &[],
            require: &["id", "object", "status"],
        },
        Expected {
            action: "get_dispute_summary",
            path: "/v1/disputes/{dispute}",
            query: &[],
            require: &["id", "object", "status"],
        },
        Expected {
            action: "get_product",
            path: "/v1/products/{product}",
            query: &[],
            require: &["id", "object", "name"],
        },
        Expected {
            action: "get_price",
            path: "/v1/prices/{price}",
            query: &[],
            require: &["id", "object", "product"],
        },
        Expected {
            action: "list_active_prices",
            path: "/v1/prices",
            query: &[
                ("product", "{product}"),
                ("active", "true"),
                ("limit", "20"),
            ],
            require: &["data", "has_more"],
        },
    ];

    for expected in expected {
        let document = vendored_doc(expected.action);
        assert!(!document.contains("expand"), "stripe.{}", expected.action);
        assert!(
            !document.contains("Stripe-Version"),
            "the descriptor must not add a Stripe-Version header"
        );
        let yaml: Value = serde_yaml::from_str(document).unwrap();
        let steps = yaml["http"]["steps"].as_sequence().unwrap();
        assert_eq!(steps.len(), 1, "stripe.{}", expected.action);
        let step = &steps[0];
        assert_eq!(step["method"].as_str(), Some("GET"));
        assert_eq!(step["path"].as_str(), Some(expected.path));
        assert!(step["body"].is_null());
        let statuses = step["success_statuses"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|status| status.as_i64().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(statuses, [200], "stripe.{}", expected.action);

        let query = step["query"].as_mapping();
        assert_eq!(
            query.map_or(0, |mapping| mapping.len()),
            expected.query.len()
        );
        for (name, value) in expected.query {
            assert_eq!(step["query"][*name].as_str(), Some(*value));
        }
        assert_eq!(strings(&step["require"]), expected.require);
        // A Stripe read surfaces its provider error body as evidence.
        assert!(
            step["error_status_only"].is_null(),
            "stripe.{}",
            expected.action
        );
    }
}

#[test]
fn six_m2_contracts_freeze_exact_targets_and_the_only_bounded_amount() {
    let registry = vendored_registry();
    for (action, target, consumes) in [
        (
            "cancel_subscription_at_period_end",
            "subscription",
            &["subscription"][..],
        ),
        (
            "resume_subscription_collection",
            "subscription",
            &["subscription"][..],
        ),
        ("mark_invoice_uncollectible", "invoice", &["invoice"][..]),
        (
            "issue_credit_note_adjustment_no_email",
            "invoice",
            &["invoice", "amount"][..],
        ),
        ("archive_product", "product", &["product"][..]),
        ("archive_price", "price", &["price"][..]),
    ] {
        let contract = registry
            .resolve("stripe", action)
            .unwrap_or_else(|| panic!("stripe.{action} must resolve"));
        assert_eq!(contract.consumes, consumes, "stripe.{action}");
        assert_eq!(contract.execution_targets, [target], "stripe.{action}");
        assert!(contract.has_fully_pinned_execution_targets());

        let identity = contract.field_decl(target).unwrap();
        assert!(identity.required);
        assert_eq!(identity.ty, ScalarKind::Str);
        assert_eq!(identity.class, FieldClass::Identity);
        assert_eq!(identity.binding, AllowBinding::ExactResourcePin);

        if action == "issue_credit_note_adjustment_no_email" {
            assert_eq!(contract.schema.len(), 2);
            let amount = contract.field_decl("amount").unwrap();
            assert!(amount.required);
            assert_eq!(amount.ty, ScalarKind::Int);
            assert_eq!(amount.class, FieldClass::SideEffect);
            assert_eq!(amount.binding, AllowBinding::Bounded);
        } else {
            assert_eq!(contract.schema.len(), 1, "stripe.{action}");
        }
    }
}

#[test]
fn six_m2_actions_have_the_exact_reviewed_wire_and_evidence_shapes() {
    struct Expected<'a> {
        action: &'a str,
        path: &'a str,
        body: Option<&'a str>,
        require: &'a [&'a str],
        expect_literal: Option<&'a str>,
    }

    let expected = [
        Expected {
            action: "cancel_subscription_at_period_end",
            path: "/v1/subscriptions/{subscription}",
            body: Some("{ cancel_at_period_end: true }"),
            require: &["id", "cancel_at_period_end"],
            expect_literal: Some("{ cancel_at_period_end: true }"),
        },
        Expected {
            action: "resume_subscription_collection",
            path: "/v1/subscriptions/{subscription}",
            body: Some("{ pause_collection: \"\" }"),
            require: &["id", "status"],
            expect_literal: Some("{ pause_collection: null }"),
        },
        Expected {
            action: "mark_invoice_uncollectible",
            path: "/v1/invoices/{invoice}/mark_uncollectible",
            body: None,
            require: &["id", "status"],
            expect_literal: Some("{ status: uncollectible }"),
        },
        Expected {
            action: "issue_credit_note_adjustment_no_email",
            path: "/v1/credit_notes",
            body: Some("{ invoice: \"{invoice}\", amount: \"{amount}\", email_type: none }"),
            require: &[
                "id",
                "invoice",
                "amount",
                "currency",
                "status",
                "pre_payment_amount",
                "post_payment_amount",
                "type",
            ],
            expect_literal: Some("{ status: issued, type: pre_payment, post_payment_amount: 0 }"),
        },
        Expected {
            action: "archive_product",
            path: "/v1/products/{product}",
            body: Some("{ active: false }"),
            require: &["id", "active"],
            expect_literal: Some("{ active: false }"),
        },
        Expected {
            action: "archive_price",
            path: "/v1/prices/{price}",
            body: Some("{ active: false }"),
            require: &["id", "active"],
            expect_literal: Some("{ active: false }"),
        },
    ];

    for expected in expected {
        let document = vendored_doc(expected.action);
        assert!(
            !document.contains("Stripe-Version"),
            "stripe.{}",
            expected.action
        );
        let yaml: Value = serde_yaml::from_str(document).unwrap();
        let steps = yaml["http"]["steps"].as_sequence().unwrap();
        assert_eq!(steps.len(), 1, "stripe.{}", expected.action);
        let step = &steps[0];
        assert_eq!(step["method"].as_str(), Some("POST"));
        assert_eq!(step["path"].as_str(), Some(expected.path));
        assert!(step["query"].is_null());
        if let Some(body) = expected.body {
            assert_eq!(step["body_encoding"].as_str(), Some("form"));
            assert_eq!(step["body"], serde_yaml::from_str::<Value>(body).unwrap());
        } else {
            assert!(step["body"].is_null());
            assert!(step["body_encoding"].is_null());
        }
        assert_eq!(strings(&step["require"]), expected.require);
        if let Some(expect_literal) = expected.expect_literal {
            assert_eq!(
                step["expect_literal"],
                serde_yaml::from_str::<Value>(expect_literal).unwrap()
            );
        } else {
            assert!(step["expect_literal"].is_null());
        }
        assert_eq!(step["success_statuses"].as_sequence().unwrap().len(), 1);
        assert_eq!(step["success_statuses"][0].as_i64(), Some(200));
        // The provider error body is evidence, not a leak channel.
        assert!(
            step["error_status_only"].is_null(),
            "stripe.{}",
            expected.action
        );
    }
}

#[test]
fn credit_note_shape_has_no_caller_selected_combined_effect_channel() {
    let document = vendored_doc("issue_credit_note_adjustment_no_email");
    assert!(
        document.contains("no caller-selected line/shipping composition"),
        "action wording must distinguish caller selection from provider allocation"
    );
    assert!(
        document.contains("Stripe may allocate the amount-level adjustment across invoice lines"),
        "action wording must acknowledge provider-side invoice-line allocation"
    );
    let yaml: Value = serde_yaml::from_str(document).unwrap();
    let field_names = yaml["fields"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|field| field["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    let body = yaml["http"]["steps"][0]["body"].as_mapping().unwrap();
    assert_eq!(field_names, ["invoice", "amount"]);
    assert_eq!(body.len(), 3);
    for forbidden in [
        "refund_amount",
        "refunds",
        "credit_amount",
        "out_of_band_amount",
        "lines",
        "shipping",
        "shipping_cost",
        "memo",
        "reason",
        "effective_at",
    ] {
        assert!(
            !field_names.contains(&forbidden),
            "caller-selected field `{forbidden}` exists"
        );
        assert!(
            !body.contains_key(Value::String(forbidden.to_string())),
            "caller-selected body key `{forbidden}` exists"
        );
    }
}

#[test]
fn six_m2_sidecars_hash_join_and_classify_credit_note_ambiguity() {
    assert_eq!(VENDORED_ONTOLOGY.len(), 52);
    let sources = SourceRegistry::official().unwrap();
    let catalog = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources).unwrap();
    assert_eq!(catalog.len(), 52);
    catalog.join_all(&OntologyArtifacts::vendored()).unwrap();

    for action in M2_ACTIONS {
        let record = catalog
            .get("stripe", action)
            .unwrap_or_else(|| panic!("stripe.{action} ontology record must be vendored"));
        assert!(!record.sources.is_empty());
    }

    let credit = catalog
        .get("stripe", "issue_credit_note_adjustment_no_email")
        .unwrap();
    assert_eq!(credit.semantics.risk_class, RiskClass::ExternalStateChange);
    assert_eq!(credit.semantics.reversibility, Reversibility::Compensatable);
    assert_eq!(credit.semantics.idempotency, Idempotency::NonIdempotent);
    let cautions = credit.review.cautions.join(" ").to_ascii_lowercase();
    assert!(cautions.contains("omitted allocation"), "{cautions}");
    assert!(cautions.contains("post-payment amount"), "{cautions}");
    assert!(cautions.contains("no automatic retry"), "{cautions}");
    assert!(cautions.contains("caller-selected"), "{cautions}");
    assert!(cautions.contains("stripe may allocate"), "{cautions}");
    assert!(cautions.contains("only while eligible"), "{cautions}");

    let uncollectible = catalog.get("stripe", "mark_invoice_uncollectible").unwrap();
    assert_eq!(
        uncollectible.semantics.reversibility,
        Reversibility::Irreversible
    );
    let cautions = uncollectible.review.cautions.join(" ").to_ascii_lowercase();
    assert!(cautions.contains("no implied compensation"), "{cautions}");
}

#[test]
fn seven_stripe_records_are_vendored_hash_bound_observations() {
    assert_eq!(VENDORED_ONTOLOGY.len(), 52);
    let sources = SourceRegistry::official().unwrap();
    let catalog = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources).unwrap();
    assert_eq!(catalog.len(), 52);
    catalog.join_all(&OntologyArtifacts::vendored()).unwrap();

    for action in M1_ACTIONS {
        let record = catalog
            .get("stripe", action)
            .unwrap_or_else(|| panic!("stripe.{action} ontology record must be vendored"));
        assert!(matches!(
            record.semantics.risk_class,
            RiskClass::Observation | RiskClass::SensitiveObservation
        ));
        assert!(!record.sources.is_empty());
    }
}

#[test]
fn three_m3_sidecars_hash_join_and_record_loaded_sandbox_limitations() {
    assert_eq!(VENDORED_ONTOLOGY.len(), 52);
    let sources = SourceRegistry::official().unwrap();
    let catalog = OntologyCatalog::check(VENDORED_ONTOLOGY, &sources).unwrap();
    assert_eq!(catalog.len(), 52);
    catalog.join_all(&OntologyArtifacts::vendored()).unwrap();

    let stage = catalog.get("stripe", "stage_dispute_evidence").unwrap();
    assert_eq!(stage.semantics.risk_class, RiskClass::ExternalStateChange);
    let stage_cautions = stage.review.cautions.join(" ").to_ascii_lowercase();
    assert!(stage_cautions.contains("files"), "{stage_cautions}");
    assert!(stage_cautions.contains("sandbox"), "{stage_cautions}");
    assert!(
        stage_cautions.contains("20,000-character"),
        "{stage_cautions}"
    );
    assert!(
        stage_cautions.contains("150,000-character"),
        "{stage_cautions}"
    );
    assert!(
        stage_cautions.contains("enforced locally"),
        "{stage_cautions}"
    );

    let submit = catalog.get("stripe", "submit_dispute_evidence").unwrap();
    assert_eq!(submit.semantics.risk_class, RiskClass::ExternalStateChange);
    let submit_cautions = submit.review.cautions.join(" ").to_ascii_lowercase();
    for required in [
        "whatever evidence",
        "does not prove",
        "prior stage grant",
        "out-of-band",
        "sandbox",
        "design validation",
    ] {
        assert!(submit_cautions.contains(required), "{submit_cautions}");
    }

    let webhook = catalog
        .get("stripe", "update_webhook_endpoint_fixed_bundle")
        .unwrap();
    assert_eq!(
        webhook.semantics.risk_class,
        RiskClass::ProviderControlChange
    );
    let webhook_cautions = webhook.review.cautions.join(" ").to_ascii_lowercase();
    assert!(
        webhook_cautions.contains("webhook_write"),
        "{webhook_cautions}"
    );
    assert!(webhook_cautions.contains("sensitive"), "{webhook_cautions}");
    assert!(
        webhook_cautions.contains("exact bundle"),
        "{webhook_cautions}"
    );
}

#[test]
fn no_stripe_action_discards_or_narrows_its_provider_response() {
    // NO Stripe verb narrows a response, on the success path or the failure path. For money verbs in
    // particular: the HTTP status, the error classification, and Stripe's `request_log_url` deep-link
    // all survive to the receipt, so diagnosing a rejection never needs a live curl reproduction.
    //
    // The check is structural over the vendored bytes: every retired response-projection key must
    // be absent from every Stripe step. `retention` is NOT in the set — a storage cap is not a
    // projection, and money keeps `retention: none`.
    const RETIRED: &[&str] = &[
        "keep",
        "result",
        "filter_prefix",
        "capture_keep",
        "error_status_only",
    ];
    let mut offenders: Vec<String> = Vec::new();
    for document in VENDORED_CATALOG.iter().copied() {
        let yaml: Value = serde_yaml::from_str(document).expect("a vendored template parses");
        if yaml["provider"].as_str() != Some("stripe") {
            continue;
        }
        let action = yaml["action"].as_str().expect("action name");
        for step in yaml["http"]["steps"]
            .as_sequence()
            .expect("an http template has steps")
        {
            for key in RETIRED {
                if !step[*key].is_null() {
                    offenders.push(format!("{action}.{key}"));
                }
            }
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "the response contract is verbatim; these still declare a projection: {offenders:?}"
    );
}
