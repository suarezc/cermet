use cermet_core::contract::{ActionContract, CanonicalResource};
use cermet_core::policy::{ContractSource, DefaultContractSource};
use cermet_core::sentence::{
    parse_rules, prepare_sentence_authority, ContractResolver, Decision, DenyReason,
    SentenceEvaluator,
};
use cermet_core::sets::{vendored_set_actions, SetResolver, SetSnapshot, VendoredSetResolver};

struct VendoredContracts;

impl ContractResolver for VendoredContracts {
    fn contract(&self, provider: &str, action: &str) -> Option<&ActionContract> {
        DefaultContractSource.contract(provider, action)
    }
}

struct MissingRefundContract;

impl ContractResolver for MissingRefundContract {
    fn contract(&self, provider: &str, action: &str) -> Option<&ActionContract> {
        if (provider, action) == ("stripe", "refund") {
            None
        } else {
            DefaultContractSource.contract(provider, action)
        }
    }
}

#[test]
fn stripe_support_is_the_stable_union_of_read_and_mutate_tiers() {
    let read = vendored_set_actions("stripe", "read");
    let mutate = vendored_set_actions("stripe", "mutate");
    let support = vendored_set_actions("stripe", "support");

    assert_eq!(
        read,
        [
            "search_customers",
            "lookup_customer",
            "list_charges",
            "get_charge",
            "list_refunds",
            "get_subscription",
        ]
    );
    assert_eq!(
        mutate,
        [
            "refund",
            "credit_balance",
            "pause_subscription",
            "cancel_subscription",
        ]
    );
    assert_eq!(support, read.into_iter().chain(mutate).collect::<Vec<_>>());
}

#[test]
fn stripe_task_sets_have_exact_reviewed_memberships() {
    assert_eq!(
        vendored_set_actions("stripe", "support_lookup"),
        [
            "search_customers",
            "lookup_customer",
            "list_charges",
            "get_charge",
            "list_refunds",
            "get_subscription",
            "get_invoice",
            "list_invoices_for_customer",
            "get_payment_intent",
            "get_dispute_summary",
        ]
    );
    assert_eq!(
        vendored_set_actions("stripe", "billing_support"),
        [
            "get_subscription",
            "get_invoice",
            "list_invoices_for_customer",
            "pause_subscription",
            "resume_subscription_collection",
            "cancel_subscription_at_period_end",
        ]
    );
    assert_eq!(
        vendored_set_actions("stripe", "catalog_admin"),
        [
            "get_product",
            "get_price",
            "list_active_prices",
            "archive_product",
            "archive_price",
        ]
    );
    assert_eq!(
        vendored_set_actions("stripe", "dispute_ops"),
        [
            "get_dispute_summary",
            "stage_dispute_evidence",
            "submit_dispute_evidence",
        ]
    );
    assert_eq!(
        vendored_set_actions("stripe", "webhook_admin"),
        ["update_webhook_endpoint_fixed_bundle"]
    );
}

#[test]
fn stripe_set_current_digests_are_fixed() {
    let resolver = VendoredSetResolver;
    let expected = [
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

    for (set, digest) in expected {
        assert_eq!(
            resolver
                .current_snapshot("stripe", set)
                .unwrap_or_else(|| panic!("stripe.{set} must resolve"))
                .digest(),
            digest,
            "stripe.{set} digest drifted"
        );
    }
}

#[test]
fn bare_task_set_and_frozen_support_prepare_and_evaluate_without_widening() {
    let sets = VendoredSetResolver;
    let contracts = VendoredContracts;
    // A set is spelled by its immutable expansion — the bare dotted form is the
    // verb — so a task-set corpus is authored pinned and prepares to exactly its own bytes.
    let lookup_text =
        "allow stripe.support_lookup@sha256:080c2d8d757fd008a3c9c154df234a4edd08e6fb38242cdd0acab59b7aa4314a\n";
    let lookup = prepare_sentence_authority(lookup_text, &sets, &contracts, false)
        .expect("the pinned task set must prepare");
    assert_eq!(lookup.canonical_text, lookup_text);
    assert_eq!(lookup.set_snapshots.len(), 1);
    assert_eq!(
        lookup.set_snapshots[0].members,
        [
            "get_charge",
            "get_dispute_summary",
            "get_invoice",
            "get_payment_intent",
            "get_subscription",
            "list_charges",
            "list_invoices_for_customer",
            "list_refunds",
            "lookup_customer",
            "search_customers",
        ]
    );

    let lookup_rules = parse_rules(&lookup.canonical_text).unwrap();
    let invoice_contract = contracts.contract("stripe", "get_invoice").unwrap();
    let invoice =
        CanonicalResource::from_stored(r#"{"invoice":"in_123"}"#, invoice_contract).unwrap();
    let mark_contract = contracts
        .contract("stripe", "mark_invoice_uncollectible")
        .unwrap();
    let mark_invoice =
        CanonicalResource::from_stored(r#"{"invoice":"in_123"}"#, mark_contract).unwrap();
    let evaluator = SentenceEvaluator::new(&sets, &contracts);
    assert_eq!(
        evaluator.evaluate(&lookup_rules, "stripe", "get_invoice", &invoice),
        Decision::Allow { rule_idx: 0 }
    );
    assert_eq!(
        evaluator.evaluate(
            &lookup_rules,
            "stripe",
            "mark_invoice_uncollectible",
            &mark_invoice,
        ),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
        },
        "an excluded verb must not inherit task-set authority"
    );

    let support_text = format!(
        "allow stripe.support@{}\n",
        sets.current_snapshot("stripe", "support")
            .expect("the wedge support set is vendored")
            .digest()
    );
    let support = prepare_sentence_authority(&support_text, &sets, &contracts, false)
        .expect("the wedge support set must still prepare");
    assert_eq!(support.set_snapshots.len(), 1);
    assert_eq!(support.set_snapshots[0].members.len(), 10);
    assert_eq!(
        support.set_snapshots[0].members,
        [
            "cancel_subscription",
            "credit_balance",
            "get_charge",
            "get_subscription",
            "list_charges",
            "list_refunds",
            "lookup_customer",
            "pause_subscription",
            "refund",
            "search_customers",
        ]
    );

    let support_rules = parse_rules(&support.canonical_text).unwrap();
    let subscription_contract = contracts.contract("stripe", "get_subscription").unwrap();
    let subscription =
        CanonicalResource::from_stored(r#"{"subscription":"sub_123"}"#, subscription_contract)
            .unwrap();
    assert_eq!(
        evaluator.evaluate(&support_rules, "stripe", "get_subscription", &subscription,),
        Decision::Allow { rule_idx: 0 }
    );
    assert_eq!(
        evaluator.evaluate(&support_rules, "stripe", "get_invoice", &invoice),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
        },
        "new corpus verbs must not widen the frozen wedge support set"
    );
}

#[test]
fn current_and_historical_support_pins_refuse_an_unavailable_member_contract() {
    let sets = VendoredSetResolver;
    let current = sets.current_snapshot("stripe", "support").unwrap();
    let historical = sets.named_snapshot("stripe", "support", "pre_m4").unwrap();

    for snapshot in [current, historical] {
        let source = format!("allow stripe.support@{}\n", snapshot.digest());
        let error = prepare_sentence_authority(&source, &sets, &MissingRefundContract, false)
            .expect_err("a set pin must not prepare with only partial contract coverage");
        // The author of this one-rule corpus finds the offending line with `cermet rules`,
        // which numbers from 1 — so a corpus-validation refusal names rule 1, not rule 0.
        assert_eq!(
            error.to_string(),
            "unresolved authority reference: rule 1: unresolved set member stripe.refund"
        );
    }
}

#[test]
fn unknown_set_names_expand_to_no_authority() {
    assert!(vendored_set_actions("stripe", "admin").is_empty());
    assert!(vendored_set_actions("unknown", "support").is_empty());
}

#[test]
fn v1_m4_snapshot_digest_is_derived_from_canonical_provider_set_and_members() {
    let first = SetSnapshot::new(
        "stripe",
        "support",
        vec!["refund".into(), "lookup_customer".into(), "refund".into()],
    )
    .unwrap();
    let reordered = SetSnapshot::new(
        "stripe",
        "support",
        vec!["lookup_customer".into(), "refund".into()],
    )
    .unwrap();
    let widened = SetSnapshot::new(
        "stripe",
        "support",
        vec![
            "lookup_customer".into(),
            "refund".into(),
            "credit_balance".into(),
        ],
    )
    .unwrap();
    let renamed = SetSnapshot::new(
        "stripe",
        "mutate",
        vec!["lookup_customer".into(), "refund".into()],
    )
    .unwrap();

    assert_eq!(first.members(), ["lookup_customer", "refund"]);
    assert_eq!(first.digest(), reordered.digest());
    assert_ne!(first.digest(), widened.digest());
    assert_ne!(first.digest(), renamed.digest());
    assert!(first.digest().starts_with("sha256:"));
    assert_eq!(first.digest().len(), "sha256:".len() + 64);
}

#[test]
fn vendored_resolver_resolves_named_history_by_digest() {
    let resolver = VendoredSetResolver;
    let pre_m4 = resolver
        .named_snapshot("stripe", "support", "pre_m4")
        .expect("the shipped expansion is named immutable history");

    assert_eq!(
        resolver.snapshot("stripe", "support", pre_m4.digest()),
        Some(pre_m4)
    );
}
