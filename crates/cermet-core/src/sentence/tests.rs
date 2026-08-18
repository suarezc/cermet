use proptest::prelude::*;

use super::*;
use crate::contract::{
    ActionContract, AllowBinding, CanonicalResource, FieldClass, FieldDecl, ScalarKind,
};

const BOUNDED_SCHEMA: &[FieldDecl] = &[
    FieldDecl {
        name: "amount",
        ty: ScalarKind::Int,
        required: false,
        class: FieldClass::SideEffect,
        binding: AllowBinding::Bounded,
    },
    FieldDecl {
        name: "customer",
        ty: ScalarKind::Str,
        required: false,
        class: FieldClass::Identity,
        binding: AllowBinding::ExactResourcePin,
    },
];

const BOUNDED_CONTRACT: ActionContract = ActionContract {
    provider: "stripe",
    action: "refund",
    schema: BOUNDED_SCHEMA,
    consumes: &["amount", "customer"],
    execution_targets: &[],
    relations: &[],
    open: false,
};

const EMPTY_CONTRACT: ActionContract = ActionContract {
    provider: "stripe",
    action: "lookup_balance",
    schema: &[],
    consumes: &[],
    execution_targets: &[],
    relations: &[],
    open: false,
};

const WRONG_PROVIDER_CONTRACT: ActionContract = ActionContract {
    provider: "github",
    action: "refund",
    schema: &[],
    consumes: &[],
    execution_targets: &[],
    relations: &[],
    open: false,
};

const AMOUNT_ONLY_SCHEMA: &[FieldDecl] = &[FieldDecl {
    name: "amount",
    ty: ScalarKind::Int,
    required: false,
    class: FieldClass::SideEffect,
    binding: AllowBinding::Bounded,
}];

const AMOUNT_ONLY_CONTRACT: ActionContract = ActionContract {
    provider: "stripe",
    action: "refund",
    schema: AMOUNT_ONLY_SCHEMA,
    consumes: &["amount"],
    execution_targets: &[],
    relations: &[],
    open: false,
};

const CUSTOMER_ONLY_SCHEMA: &[FieldDecl] = &[FieldDecl {
    name: "customer",
    ty: ScalarKind::Str,
    required: false,
    class: FieldClass::Identity,
    binding: AllowBinding::ExactResourcePin,
}];

const CUSTOMER_ONLY_CONTRACT: ActionContract = ActionContract {
    provider: "stripe",
    action: "lookup_customer",
    schema: CUSTOMER_ONLY_SCHEMA,
    consumes: &["customer"],
    execution_targets: &[],
    relations: &[],
    open: false,
};

const WRONG_MEMBER_CONTRACT: ActionContract = ActionContract {
    provider: "github",
    action: "lookup_customer",
    schema: CUSTOMER_ONLY_SCHEMA,
    consumes: &["customer"],
    execution_targets: &[],
    relations: &[],
    open: false,
};

const CHARGE_CONTRACT: ActionContract = ActionContract {
    provider: "stripe",
    action: "charge",
    schema: BOUNDED_SCHEMA,
    consumes: &["amount", "customer"],
    execution_targets: &[],
    relations: &[],
    open: false,
};

const OPEN_MEMBER_CONTRACT: ActionContract = ActionContract {
    provider: "stripe",
    action: "open_member",
    schema: &[],
    consumes: &[],
    execution_targets: &[],
    relations: &[],
    open: true,
};

const TEST_MONEY_SCHEMA: &[FieldDecl] = &[
    FieldDecl {
        name: "amount",
        ty: ScalarKind::Int,
        required: true,
        class: FieldClass::SideEffect,
        binding: AllowBinding::Bounded,
    },
    FieldDecl {
        name: "account",
        ty: ScalarKind::Str,
        required: true,
        class: FieldClass::Identity,
        binding: AllowBinding::ExactResourcePin,
    },
    FieldDecl {
        name: "mode",
        ty: ScalarKind::Str,
        required: true,
        class: FieldClass::Identity,
        binding: AllowBinding::ExactResourcePin,
    },
    FieldDecl {
        name: "currency",
        ty: ScalarKind::Str,
        required: true,
        class: FieldClass::Identity,
        binding: AllowBinding::ExactResourcePin,
    },
];

const TEST_MONEY_CONTRACT: ActionContract = ActionContract {
    provider: "stripe",
    action: "test_money_action",
    schema: TEST_MONEY_SCHEMA,
    consumes: &["amount", "account", "mode", "currency"],
    execution_targets: &["account", "mode", "currency"],
    relations: &[],
    open: false,
};

const CLOSED_MEMBER_CONTRACT: ActionContract = ActionContract {
    provider: "stripe",
    action: "closed_member",
    schema: &[],
    consumes: &[],
    execution_targets: &[],
    relations: &[],
    open: false,
};

fn verb(action: &str) -> Selector {
    Selector::Verb {
        provider: "stripe".into(),
        action: action.into(),
    }
}

fn refund_rule(conjuncts: Vec<Pred>) -> RuleSet {
    RuleSet {
        version: 1,
        rules: vec![Rule {
            effect: RuleEffect::Allow,
            selector: verb("refund"),
            conjuncts,
            aggregate: None,
        }],
    }
}

fn refund_resource(json: &str) -> CanonicalResource {
    CanonicalResource::from_stored(json, &BOUNDED_CONTRACT).unwrap()
}

#[test]
fn direct_verb_provider_accepts_registered_hyphenated_names() {
    let rules = parse_rules("allow mock-vercel.deploy").unwrap();
    assert_eq!(
        rules.rules[0].selector,
        Selector::Verb {
            provider: "mock-vercel".into(),
            action: "deploy".into(),
        }
    );
}

#[test]
fn evaluate_allows_an_in_bound_frozen_request() {
    let rules = refund_rule(vec![Pred::Lte {
        field: "amount".into(),
        value: 50,
    }]);
    let resource = refund_resource(r#"{"amount":30}"#);

    assert_eq!(
        evaluate_with_contract(&rules, &resource, &BOUNDED_CONTRACT),
        Decision::Allow { rule_idx: 0 }
    );
}

#[test]
fn evaluate_denies_an_out_of_bound_frozen_request() {
    let rules = refund_rule(vec![Pred::Lte {
        field: "amount".into(),
        value: 50,
    }]);
    let resource = refund_resource(r#"{"amount":51}"#);

    assert_eq!(
        evaluate_with_contract(&rules, &resource, &BOUNDED_CONTRACT),
        Decision::Deny {
            reason: DenyReason::PredicateMismatch {
                rule_idx: 0,
                pred_idx: 0,
                // The mismatched predicate NAMES its field. Every `Pred` constrains
                // exactly one declared field, so the evaluator has the name in hand at the moment
                // it detects the mismatch — it is not reconstructed anywhere downstream.
                field: Some("amount".into()),
            },
        }
    );
}

/// The name is the PROJECTED rule's field, and a set-selector rule projects onto the member action
/// actually being decided — so the name reported is the one the deciding contract declares, in step
/// with the `pred_idx` remap that sits beside it.
#[test]
fn a_mismatch_names_the_field_of_the_predicate_that_failed() {
    let rules = refund_rule(vec![
        Pred::Eq {
            field: "customer".into(),
            value: Scalar::String("cus_1".into()),
        },
        Pred::Lte {
            field: "amount".into(),
            value: 50,
        },
    ]);
    let resource = refund_resource(r#"{"amount":51,"customer":"cus_1"}"#);

    assert_eq!(
        evaluate_with_contract(&rules, &resource, &BOUNDED_CONTRACT),
        Decision::Deny {
            reason: DenyReason::PredicateMismatch {
                rule_idx: 0,
                pred_idx: 1,
                field: Some("amount".into()),
            },
        },
        "the SECOND conjunct failed, so its field is the one named"
    );
}

#[test]
fn evaluate_denies_when_a_predicate_field_is_missing() {
    let rules = refund_rule(vec![Pred::Lte {
        field: "amount".into(),
        value: 50,
    }]);
    let resource = refund_resource("{}");

    assert_eq!(
        evaluate_with_contract(&rules, &resource, &BOUNDED_CONTRACT),
        Decision::Deny {
            reason: DenyReason::MissingField {
                rule_idx: 0,
                field: "amount".into(),
            },
        }
    );
}

// `evaluate()` is a PURE decision function (no ledger, no clock). A matched aggregate-bearing
// Allow rule therefore returns `Allow { rule_idx }` exactly like a plain winner — the ledger-derived
// budget/rate GATE (`broker::budget`) meters it at the serialized mint seam and downgrades to a
// value-free `BudgetExceeded { window }` deny (or mints). It is never enforced inside `evaluate()`.
fn budget_refund_rule(window: Window) -> RuleSet {
    RuleSet {
        version: 1,
        rules: vec![Rule {
            effect: RuleEffect::Allow,
            selector: verb("refund"),
            conjuncts: vec![Pred::Lte {
                field: "amount".into(),
                value: 5000,
            }],
            aggregate: Some(Aggregate {
                kind: AggregateKind::Budget {
                    field: Some("amount".into()),
                },
                limit: 100_000,
                window,
            }),
        }],
    }
}

#[test]
fn evaluate_allows_a_matched_budget_conjunct_leaving_metering_to_the_gate() {
    // The pure engine does NOT meter. A matched budget rule whose per-call predicate holds returns
    // `Allow { rule_idx }`; the ledger-derived mint gate is what enforces the cap.
    let rules = budget_refund_rule(Window::Day);
    let resource = refund_resource(r#"{"amount":30}"#);
    assert_eq!(
        evaluate_with_contract(&rules, &resource, &BOUNDED_CONTRACT),
        Decision::Allow { rule_idx: 0 }
    );
}

#[test]
fn sellable_set_money_sentence_projects_with_the_shipped_budget_amount_syntax() {
    struct MoneyContracts;
    impl ContractResolver for MoneyContracts {
        fn contract(&self, provider: &str, action: &str) -> Option<&ActionContract> {
            (provider == "stripe" && action == "test_money_action").then_some(&TEST_MONEY_CONTRACT)
        }

        fn action_is_money(&self, provider: &str, action: &str) -> bool {
            provider == "stripe" && action == "test_money_action"
        }
    }

    let snapshot =
        crate::sets::SetSnapshot::new("stripe", "charge_ops", vec!["test_money_action".into()])
            .unwrap();
    let digest = snapshot.digest().to_string();
    let sets = VersionedSetResolver::new(snapshot);
    let mut rules = parse_rules(&format!(
        "allow stripe.charge_ops@{digest} where account = \"acct_123\" and mode = \"test\" and currency = \"usd\" and amount <= 5000 and budget amount 50000 per day",
    ))
    .unwrap();
    pin_set_references(&mut rules, &sets).unwrap();
    validate_references(&rules, &sets, &MoneyContracts).unwrap();
    validate_money_authority(&rules, &sets, &MoneyContracts).unwrap();

    let resource = CanonicalResource::from_stored(
        r#"{"account":"acct_123","amount":2300,"currency":"usd","mode":"test"}"#,
        &TEST_MONEY_CONTRACT,
    )
    .unwrap();
    assert_eq!(
        SentenceEvaluator::new(&sets, &MoneyContracts).evaluate(
            &rules,
            "stripe",
            "test_money_action",
            &resource,
        ),
        Decision::Allow { rule_idx: 0 }
    );
    assert!(matches!(
        rules.rules[0].aggregate.as_ref().map(|aggregate| &aggregate.kind),
        Some(AggregateKind::Budget { field: Some(field) }) if field == "amount"
    ));
}

#[test]
fn evaluate_allows_a_matched_rate_conjunct_leaving_metering_to_the_gate() {
    let rules = RuleSet {
        version: 1,
        rules: vec![Rule {
            effect: RuleEffect::Allow,
            selector: verb("refund"),
            conjuncts: vec![],
            aggregate: Some(Aggregate {
                kind: AggregateKind::Rate,
                limit: 1,
                window: Window::Hour,
            }),
        }],
    };
    let resource = refund_resource(r#"{"amount":30}"#);
    assert_eq!(
        evaluate_with_contract(&rules, &resource, &BOUNDED_CONTRACT),
        Decision::Allow { rule_idx: 0 }
    );
}

// An unbudgeted `allow` ordered before an overlapping aggregate `allow`
// would match first and mint UNMETERED — the corpus-validation lint must refuse it.
#[test]
fn aggregate_shadowing_lint_refuses_an_earlier_unbudgeted_overlapping_allow() {
    let snapshot = crate::sets::SetSnapshot::new(
        "stripe",
        "support",
        vec!["lookup_customer".into(), "refund".into()],
    )
    .unwrap();
    let sets = VersionedSetResolver::new(snapshot);

    // Plain allow FIRST, budget rule second, same set ⇒ shadow ⇒ refuse.
    let mut shadowed = parse_rules(
        "allow stripe.support\nallow stripe.support where amount <= 5000 and budget amount 100 per day",
    )
    .unwrap();
    pin_set_references(&mut shadowed, &sets).unwrap();
    let err = validate_aggregate_shadowing(&shadowed, &sets).unwrap_err();
    assert_eq!(err.plain_idx, 0);
    assert_eq!(err.aggregate_idx, 1);

    // Aggregate rule FIRST ⇒ it wins and meters ⇒ no shadow.
    let mut ordered = parse_rules(
        "allow stripe.support where amount <= 5000 and budget amount 100 per day\nallow stripe.support",
    )
    .unwrap();
    pin_set_references(&mut ordered, &sets).unwrap();
    assert!(validate_aggregate_shadowing(&ordered, &sets).is_ok());

    // An earlier rule carrying a DIFFERENT/weaker aggregate suppresses the later cap
    // (first-match meters only the earlier rate rule; the monetary cap is never evaluated) ⇒ refuse.
    let mut different = parse_rules(
        "allow stripe.support where rate 1 per hour\nallow stripe.support where amount <= 5000 and budget amount 100 per day",
    )
    .unwrap();
    pin_set_references(&mut different, &sets).unwrap();
    let err = validate_aggregate_shadowing(&different, &sets).unwrap_err();
    assert_eq!(err.plain_idx, 0);
    assert_eq!(err.aggregate_idx, 1);
    assert!(err.earlier_meters_differently);

    // Equal aggregate CLAUSES but DIFFERENT predicates meter SEPARATE ledger counters
    // (distinct `aggregate_id` over the full canonical rule), so the earlier rule does NOT drain the
    // later rule's counter — two overlapping 100-caps would admit 200. Refuse (comparing only the
    // aggregate clause would wrongly exempt this).
    let mut split_counter = parse_rules(
        "allow stripe.support where amount <= 50 and budget amount 100 per day\nallow stripe.support where amount <= 5000 and budget amount 100 per day",
    )
    .unwrap();
    pin_set_references(&mut split_counter, &sets).unwrap();
    let err = validate_aggregate_shadowing(&split_counter, &sets).unwrap_err();
    assert_eq!(err.plain_idx, 0);
    assert_eq!(err.aggregate_idx, 1);
    assert!(err.earlier_meters_differently);

    // ONLY a byte-identical earlier rule (same selector + predicates + aggregate ⇒ same `aggregate_id`
    // counter identity) is exempt — first-match selects it and it drains the SAME ledger counter.
    let mut same_counter = parse_rules(
        "allow stripe.support where amount <= 5000 and budget amount 100 per day\nallow stripe.support where amount <= 5000 and budget amount 100 per day",
    )
    .unwrap();
    pin_set_references(&mut same_counter, &sets).unwrap();
    assert!(validate_aggregate_shadowing(&same_counter, &sets).is_ok());
}

#[test]
fn evaluate_prefers_an_earlier_plain_allow_over_a_later_aggregate() {
    // First-matching-allow-wins precedence: a plain Allow that matches first governs and admits,
    // even when a later aggregate rule also covers the request.
    let rules = RuleSet {
        version: 1,
        rules: vec![
            Rule {
                effect: RuleEffect::Allow,
                selector: verb("refund"),
                conjuncts: vec![Pred::Lte {
                    field: "amount".into(),
                    value: 50,
                }],
                aggregate: None,
            },
            budget_refund_rule(Window::Day).rules.pop().unwrap(),
        ],
    };
    let resource = refund_resource(r#"{"amount":30}"#);
    assert_eq!(
        evaluate_with_contract(&rules, &resource, &BOUNDED_CONTRACT),
        Decision::Allow { rule_idx: 0 }
    );
}

#[test]
fn evaluate_denies_a_verb_no_rule_covers() {
    let rules = refund_rule(vec![Pred::Lte {
        field: "amount".into(),
        value: 50,
    }]);
    let resource = CanonicalResource::from_stored(r#"{"amount":30}"#, &CHARGE_CONTRACT).unwrap();

    assert_eq!(
        evaluate_with_contract(&rules, &resource, &CHARGE_CONTRACT),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
        }
    );
}

#[test]
fn evaluate_allows_empty_conjuncts_when_the_contract_has_no_bounded_field() {
    let rules = RuleSet {
        version: 1,
        rules: vec![Rule {
            effect: RuleEffect::Allow,
            selector: verb("lookup_balance"),
            conjuncts: vec![],
            aggregate: None,
        }],
    };
    let resource = CanonicalResource::from_stored("{}", &EMPTY_CONTRACT).unwrap();

    assert_eq!(
        evaluate_with_contract(&rules, &resource, &EMPTY_CONTRACT),
        Decision::Allow { rule_idx: 0 }
    );
}

#[test]
fn v1_m5_evaluate_does_not_inject_a_missing_bounded_field_predicate() {
    let rules = refund_rule(vec![Pred::Eq {
        field: "customer".into(),
        value: Scalar::String("cus_123".into()),
    }]);
    let resource = refund_resource(r#"{"amount":30,"customer":"cus_123"}"#);

    assert_eq!(
        evaluate_with_contract(&rules, &resource, &BOUNDED_CONTRACT),
        Decision::Allow { rule_idx: 0 }
    );
}

#[test]
fn a_later_matching_rule_can_allow_after_an_earlier_predicate_mismatch() {
    let rules = RuleSet {
        version: 1,
        rules: vec![
            Rule {
                effect: RuleEffect::Allow,
                selector: verb("refund"),
                conjuncts: vec![Pred::Lte {
                    field: "amount".into(),
                    value: 20,
                }],
                aggregate: None,
            },
            Rule {
                effect: RuleEffect::Allow,
                selector: verb("refund"),
                conjuncts: vec![Pred::Lte {
                    field: "amount".into(),
                    value: 50,
                }],
                aggregate: None,
            },
        ],
    };
    let resource = refund_resource(r#"{"amount":30}"#);

    assert_eq!(
        evaluate_with_contract(&rules, &resource, &BOUNDED_CONTRACT),
        Decision::Allow { rule_idx: 1 }
    );
}

struct FixedContractResolver(&'static ActionContract);

impl ContractResolver for FixedContractResolver {
    fn contract(&self, _provider: &str, _action: &str) -> Option<&ActionContract> {
        Some(self.0)
    }
}

fn evaluate_with_contract(
    rules: &RuleSet,
    resource: &CanonicalResource,
    contract: &'static ActionContract,
) -> Decision {
    SentenceEvaluator::new(
        &crate::sets::EmptySetResolver,
        &FixedContractResolver(contract),
    )
    .evaluate(rules, contract.provider, contract.action, resource)
}

#[test]
fn v2_m5_shared_core_owns_subset_projection_and_widen_eligibility() {
    let mut unsupported = refund_rule(vec![]);
    unsupported.version = 2;
    assert_eq!(
        validate_sentence_authority(&unsupported)
            .unwrap_err()
            .to_string(),
        "unsupported rules version 2"
    );

    // A `Set { digest: None }` is unreachable from text now (a set is spelled by its expansion),
    // but stored/deserialized authority must still refuse one.
    let unpinned_set = RuleSet {
        version: 1,
        rules: vec![Rule {
            effect: RuleEffect::Allow,
            selector: Selector::Set {
                provider: "stripe".into(),
                set: "support".into(),
                digest: None,
            },
            conjuncts: vec![Pred::Lte {
                field: "amount".into(),
                value: 50,
            }],
            aggregate: None,
        }],
    };
    assert_eq!(
        validate_sentence_authority(&unpinned_set)
            .unwrap_err()
            .to_string(),
        "stored set rules must pin an immutable sha256 expansion digest; re-run `cermet rules allow`"
    );

    let malformed = RuleSet {
        version: 1,
        rules: vec![Rule {
            effect: RuleEffect::Allow,
            selector: verb("refund"),
            conjuncts: vec![Pred::Lte {
                field: "bad-field".into(),
                value: 50,
            }],
            aggregate: None,
        }],
    };
    assert_eq!(
        validate_sentence_authority(&malformed)
            .unwrap_err()
            .to_string(),
        "rule #1 is structurally invalid"
    );

    let deny_rules = RuleSet {
        version: 1,
        rules: vec![Rule {
            effect: RuleEffect::Deny,
            selector: verb("refund"),
            conjuncts: vec![],
            aggregate: None,
        }],
    };
    validate_sentence_authority(&deny_rules)
        .expect("a structurally valid deny is valid stored sentence authority");

    let set_rules = RuleSet {
        version: 1,
        rules: vec![Rule {
            effect: RuleEffect::Allow,
            selector: projection_set_selector(),
            conjuncts: vec![Pred::Lte {
                field: "amount".into(),
                value: 50,
            }],
            aggregate: None,
        }],
    };
    validate_sentence_authority(&set_rules).unwrap();
    assert_eq!(
        SentenceEvaluator::new(&ProjectionSet, &ProjectionContracts)
            .covered_actions(&set_rules)
            .unwrap(),
        vec![
            ("stripe".to_string(), "lookup_customer".to_string()),
            ("stripe".to_string(), "refund".to_string()),
        ]
    );
    for invalid in [&unsupported, &unpinned_set, &malformed] {
        assert!(
            SentenceEvaluator::new(&ProjectionSet, &ProjectionContracts)
                .covered_actions(invalid)
                .is_err(),
            "invalid daemonless authority must not project actions"
        );
    }
    assert_eq!(
        SentenceEvaluator::new(&ProjectionSet, &ProjectionContracts)
            .covered_actions(&deny_rules)
            .unwrap(),
        vec![("stripe".to_string(), "refund".to_string())],
        "deny rules are admitted to custody and remain visible to the deny-precedence evaluator"
    );

    let rules = refund_rule(vec![Pred::Lte {
        field: "amount".into(),
        value: 50,
    }]);
    let resource = refund_resource(r#"{"amount":75}"#);
    let outcome = SentenceEvaluator::new(
        &crate::sets::EmptySetResolver,
        &FixedContractResolver(&BOUNDED_CONTRACT),
    )
    .evaluate_with_widen_hint(&rules, "stripe", "refund", &resource);
    assert_eq!(
        outcome.decision,
        Decision::Deny {
            reason: DenyReason::PredicateMismatch {
                rule_idx: 0,
                pred_idx: 0,
                field: Some("amount".into()),
            },
        }
    );
    assert_eq!(
        outcome.widen_hint.map(|hint| hint.command),
        Some("to allow: cermet rules allow 'stripe.refund where amount <= 75'".into())
    );
}

struct MismatchedMemberContracts;

impl ContractResolver for MismatchedMemberContracts {
    fn contract(&self, provider: &str, action: &str) -> Option<&ActionContract> {
        match (provider, action) {
            ("stripe", "refund") => Some(&AMOUNT_ONLY_CONTRACT),
            ("stripe", "lookup_customer") => Some(&WRONG_MEMBER_CONTRACT),
            _ => None,
        }
    }
}

#[test]
fn canonical_authority_digest_is_domain_and_language_version_bound() {
    use sha2::Digest;

    let bytes = b"allow stripe.refund where amount <= 5000\n";
    let current = authority_digest_for(1, bytes);

    assert_eq!(current.len(), 64);
    assert!(current
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_ne!(
        current,
        authority_digest_for(2, bytes),
        "identical text under another sentence-language version is another authority identity"
    );
    assert_ne!(
        current,
        crate::util::hex(&sha2::Sha256::digest(bytes)),
        "the authority identity must not collapse to an unbound content hash"
    );
}

#[test]
fn shared_evaluator_denies_resolver_contract_identity_mismatch() {
    let rules = refund_rule(vec![]);
    let sets = crate::sets::EmptySetResolver;
    let evaluate_with = |contract: &'static ActionContract| {
        let contracts = FixedContractResolver(contract);
        let resource = CanonicalResource::from_stored("{}", contract).unwrap();
        SentenceEvaluator::new(&sets, &contracts).evaluate(&rules, "stripe", "refund", &resource)
    };

    assert_eq!(
        [
            evaluate_with(&EMPTY_CONTRACT),
            evaluate_with(&WRONG_PROVIDER_CONTRACT),
        ],
        [
            Decision::Deny {
                reason: DenyReason::UnknownSelector,
            },
            Decision::Deny {
                reason: DenyReason::UnknownSelector,
            },
        ],
        "both action and provider identity mismatches must fail closed"
    );

    let set_rules = RuleSet {
        version: 1,
        rules: vec![Rule {
            effect: RuleEffect::Allow,
            selector: projection_set_selector(),
            conjuncts: vec![
                Pred::Eq {
                    field: "customer".into(),
                    value: Scalar::String("cus_must_not_disappear".into()),
                },
                Pred::Lte {
                    field: "amount".into(),
                    value: 50,
                },
            ],
            aggregate: None,
        }],
    };
    let resource =
        CanonicalResource::from_stored(r#"{"amount":30}"#, &AMOUNT_ONLY_CONTRACT).unwrap();
    assert_eq!(
        SentenceEvaluator::new(&ProjectionSet, &MismatchedMemberContracts)
            .evaluate(&set_rules, "stripe", "refund", &resource),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
        },
        "a mismatched sibling contract must not make an authored predicate disappear"
    );
}

struct ProjectionContracts;

impl ContractResolver for ProjectionContracts {
    fn contract(&self, provider: &str, action: &str) -> Option<&ActionContract> {
        match (provider, action) {
            ("stripe", "refund") => Some(&AMOUNT_ONLY_CONTRACT),
            ("stripe", "lookup_customer") => Some(&CUSTOMER_ONLY_CONTRACT),
            _ => None,
        }
    }
}

struct ProjectionSet;

impl crate::sets::SetResolver for ProjectionSet {
    fn current_snapshot(&self, provider: &str, set: &str) -> Option<crate::sets::SetSnapshot> {
        if provider == "stripe" && set == "support" {
            crate::sets::SetSnapshot::new(
                provider,
                set,
                vec!["lookup_customer".into(), "refund".into()],
            )
        } else {
            None
        }
    }
}

fn projection_set_selector() -> Selector {
    let snapshot =
        crate::sets::SetResolver::current_snapshot(&ProjectionSet, "stripe", "support").unwrap();
    Selector::Set {
        provider: "stripe".into(),
        set: "support".into(),
        digest: Some(snapshot.digest().to_string()),
    }
}

#[test]
fn projected_predicate_mismatch_reports_the_authored_index() {
    let rules = RuleSet {
        version: 1,
        rules: vec![Rule {
            effect: RuleEffect::Allow,
            selector: projection_set_selector(),
            conjuncts: vec![
                Pred::Eq {
                    field: "customer".into(),
                    value: Scalar::String("cus_authored_zero".into()),
                },
                Pred::Lte {
                    field: "amount".into(),
                    value: 50,
                },
            ],
            aggregate: None,
        }],
    };
    let resource =
        CanonicalResource::from_stored(r#"{"amount":51}"#, &AMOUNT_ONLY_CONTRACT).unwrap();

    assert_eq!(
        SentenceEvaluator::new(&ProjectionSet, &ProjectionContracts)
            .evaluate(&rules, "stripe", "refund", &resource),
        Decision::Deny {
            reason: DenyReason::PredicateMismatch {
                rule_idx: 0,
                pred_idx: 1,
                // The remap that restores the AUTHORED index carries the field name with it: the
                // two describe the same predicate and must never come apart.
                field: Some("amount".into()),
            },
        }
    );
}

#[test]
fn deny_evaluates_only_its_authored_predicates() {
    let rules = RuleSet {
        version: 1,
        rules: vec![
            Rule {
                effect: RuleEffect::Deny,
                selector: verb("refund"),
                conjuncts: vec![Pred::Eq {
                    field: "customer".into(),
                    value: Scalar::String("cus_blocked".into()),
                }],
                aggregate: None,
            },
            Rule {
                effect: RuleEffect::Allow,
                selector: verb("refund"),
                conjuncts: vec![Pred::Lte {
                    field: "amount".into(),
                    value: 50,
                }],
                aggregate: None,
            },
        ],
    };
    let resource = refund_resource(r#"{"amount":30,"customer":"cus_blocked"}"#);
    let contracts = FixedContractResolver(&BOUNDED_CONTRACT);

    assert_eq!(
        SentenceEvaluator::new(&crate::sets::EmptySetResolver, &contracts)
            .evaluate(&rules, "stripe", "refund", &resource),
        Decision::Deny {
            reason: DenyReason::ExplicitDeny { rule_idx: 0 },
        }
    );
}

#[test]
fn unresolved_covering_deny_blocks_an_overlapping_allow() {
    let rules = RuleSet {
        version: 1,
        rules: vec![
            Rule {
                effect: RuleEffect::Deny,
                selector: projection_set_selector(),
                conjuncts: vec![Pred::Eq {
                    field: "absent_from_every_member".into(),
                    value: Scalar::String("malformed".into()),
                }],
                aggregate: None,
            },
            Rule {
                effect: RuleEffect::Allow,
                selector: verb("refund"),
                conjuncts: vec![Pred::Lte {
                    field: "amount".into(),
                    value: 50,
                }],
                aggregate: None,
            },
        ],
    };
    let resource =
        CanonicalResource::from_stored(r#"{"amount":30}"#, &AMOUNT_ONLY_CONTRACT).unwrap();
    let decision = SentenceEvaluator::new(&ProjectionSet, &ProjectionContracts)
        .evaluate(&rules, "stripe", "refund", &resource);

    assert_eq!(
        decision,
        Decision::Deny {
            reason: DenyReason::UnresolvedDeny { rule_idx: 0 },
        },
        "an unresolved covering deny must block allow"
    );

    let malformed = RuleSet {
        version: 1,
        rules: vec![
            Rule {
                effect: RuleEffect::Deny,
                selector: verb("refund"),
                conjuncts: vec![Pred::Eq {
                    field: "amount".into(),
                    value: Scalar::String("not_an_integer".into()),
                }],
                aggregate: None,
            },
            Rule {
                effect: RuleEffect::Allow,
                selector: verb("refund"),
                conjuncts: vec![Pred::Lte {
                    field: "amount".into(),
                    value: 50,
                }],
                aggregate: None,
            },
        ],
    };
    let malformed_decision = SentenceEvaluator::new(
        &crate::sets::EmptySetResolver,
        &FixedContractResolver(&AMOUNT_ONLY_CONTRACT),
    )
    .evaluate(&malformed, "stripe", "refund", &resource);
    assert_eq!(
        malformed_decision,
        Decision::Deny {
            reason: DenyReason::UnresolvedDeny { rule_idx: 0 },
        },
        "a schema-incompatible covering deny must block allow"
    );
}

#[test]
fn v1_ruling_explicit_deny_uses_strict_integer_equivalent_and_precedes_allow() {
    let resource =
        CanonicalResource::from_stored(r#"{"amount":15000}"#, &AMOUNT_ONLY_CONTRACT).unwrap();
    for (text, deny_index) in [
        (
            "allow stripe.support where amount <= 20000\n\
             deny stripe.refund where amount >= 10001",
            1,
        ),
        (
            "deny stripe.refund where amount >= 10001\n\
             allow stripe.support where amount <= 20000",
            0,
        ),
    ] {
        let mut rules = parse_rules(text).unwrap();
        pin_set_references(&mut rules, &ProjectionSet).unwrap();

        assert_eq!(
            SentenceEvaluator::new(&ProjectionSet, &ProjectionContracts)
                .evaluate(&rules, "stripe", "refund", &resource),
            Decision::Deny {
                reason: DenyReason::ExplicitDeny {
                    rule_idx: deny_index,
                },
            },
            "deny precedence must not depend on authored rule order"
        );
    }
}

#[test]
fn v1_ruling_sentence_parser_rejects_ask() {
    let error = parse_rules("ask stripe.refund where amount >= 5001").unwrap_err();
    assert!(
        error.to_string().contains("one of `allow` or `deny`"),
        "{error}"
    );
}

/// Comments, `==`, and BOTH selector kinds — the bare verb and the
/// digest-pinned set. A `#` inside a quoted string is data, not a comment.
#[test]
fn parser_accepts_comments_double_equals_and_both_selector_kinds() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let parsed = parse_rules(&format!(
        r#"
        # the family rule
        allow stripe.support@{digest} where amount == 50 and customer in {{"cus_1", "Gary #1"}}
        allow stripe.refund where amount >= -10 # one verb
        "#,
    ))
    .unwrap();

    assert_eq!(parsed.version, 1);
    assert_eq!(
        parsed.rules[0].selector,
        Selector::Set {
            provider: "stripe".into(),
            set: "support".into(),
            digest: Some(digest),
        }
    );
    assert_eq!(parsed.rules[0].conjuncts.len(), 2);
    assert_eq!(parsed.rules[1].selector, verb("refund"));
}

#[test]
fn v1_m2_parser_prints_allow_and_deny_canonically() {
    let text = "allow stripe.refund where amount <= 5000\n\
                deny stripe.refund where amount >= 10000";
    let parsed = parse_rules(text).unwrap();

    assert_eq!(parsed.rules[0].effect, RuleEffect::Allow);
    assert_eq!(parsed.rules[1].effect, RuleEffect::Deny);
    assert_eq!(
        parsed
            .rules
            .iter()
            .map(print_rule)
            .collect::<Vec<_>>()
            .join("\n"),
        text
    );
    assert_eq!(parse_rules(text).unwrap(), parsed);
}

#[test]
fn parser_refuses_non_flat_or_malformed_rules() {
    for invalid in [
        "permit stripe.support",
        "allow stripe.support where amount < 50",
        "allow stripe.support where (amount = 50)",
        "allow stripe.support where amount in {}",
        "allow stripe.support trailing",
    ] {
        assert!(parse_rules(invalid).is_err(), "must refuse: {invalid}");
    }
}

#[test]
fn parser_failures_never_echo_authored_tokens() {
    let cases = [("allow M2_SELECTOR_TOKEN_CANARY", "M2_SELECTOR_TOKEN_CANARY")];

    for (candidate, canary) in cases {
        let error = parse_rules(candidate)
            .expect_err("the malformed corpus must fail parsing")
            .to_string();
        assert!(
            !error.contains(canary),
            "parser error echoed authored token {canary:?}: {error}"
        );
    }
}

// ---- budget/rate aggregate conjuncts ----

#[test]
fn parse_budget_explicit_field_hour_and_day() {
    let hour =
        parse_rules("allow stripe.support where amount <= 5000 and budget amount 50000 per hour")
            .unwrap();
    assert_eq!(
        hour.rules[0].aggregate,
        Some(Aggregate {
            kind: AggregateKind::Budget {
                field: Some("amount".into()),
            },
            limit: 50000,
            window: Window::Hour,
        })
    );
    // The predicate parses alongside the rule-level aggregate.
    assert_eq!(hour.rules[0].conjuncts.len(), 1);

    let day = parse_rules("allow stripe.support where budget amount 50000 per day").unwrap();
    assert_eq!(
        day.rules[0].aggregate,
        Some(Aggregate {
            kind: AggregateKind::Budget {
                field: Some("amount".into()),
            },
            limit: 50000,
            window: Window::Day,
        })
    );
    assert!(day.rules[0].conjuncts.is_empty());
}

#[test]
fn parse_budget_fieldless_shorthand() {
    let rules = parse_rules("allow stripe.support where budget 50000 per day").unwrap();
    assert_eq!(
        rules.rules[0].aggregate,
        Some(Aggregate {
            kind: AggregateKind::Budget { field: None },
            limit: 50000,
            window: Window::Day,
        })
    );
}

#[test]
fn parse_rate_per_hour_and_per_day() {
    for (text, window) in [
        ("allow stripe.support where rate 10 per hour", Window::Hour),
        ("allow stripe.support where rate 10 per day", Window::Day),
    ] {
        let rules = parse_rules(text).unwrap();
        assert_eq!(
            rules.rules[0].aggregate,
            Some(Aggregate {
                kind: AggregateKind::Rate,
                limit: 10,
                window,
            }),
            "wrong aggregate for: {text}"
        );
    }
}

#[test]
fn reject_rate_with_field() {
    assert!(parse_rules("allow stripe.support where rate amount 10 per hour").is_err());
}

#[test]
fn reject_zero_and_negative_limit_at_parse() {
    for text in [
        "allow stripe.support where budget 0 per day",
        "allow stripe.support where budget amount 0 per day",
        "allow stripe.support where budget -5 per day",
        "allow stripe.support where rate 0 per hour",
        "allow stripe.support where rate -1 per hour",
    ] {
        assert!(parse_rules(text).is_err(), "limit must be positive: {text}");
    }
}

#[test]
fn reject_second_aggregate_on_one_rule() {
    assert!(
        parse_rules("allow stripe.support where budget 100 per day and rate 10 per hour").is_err()
    );
    assert!(parse_rules(
        "allow stripe.support where budget 100 per day and budget amount 200 per hour"
    )
    .is_err());
}

#[test]
fn reject_aggregate_on_deny_effect() {
    assert!(parse_rules("deny stripe.support where budget 100 per day").is_err());
    assert!(parse_rules("deny stripe.support where rate 10 per hour").is_err());
    // A deny rule carrying an aggregate is also structurally invalid if built directly.
    let bad = Rule {
        effect: RuleEffect::Deny,
        selector: verb("refund"),
        conjuncts: vec![],
        aggregate: Some(Aggregate {
            kind: AggregateKind::Rate,
            limit: 10,
            window: Window::Hour,
        }),
    };
    assert!(validate_rule_structure(&bad).is_err());
}

#[test]
fn print_rule_round_trips_explicit_and_fieldless_and_rate() {
    for text in [
        "allow stripe.support where amount <= 5000 and budget amount 50000 per day",
        "allow stripe.support where budget 50000 per hour",
        "allow stripe.refund where rate 10 per hour",
        "allow stripe.support where budget amount 1 per day",
        "allow stripe.support where customer = \"safe\" and rate 3 per day",
    ] {
        let parsed = parse_rules(text).unwrap();
        assert_eq!(print_rule(&parsed.rules[0]), text, "print mismatch: {text}");
        assert_eq!(
            parse_rules(&print_rule(&parsed.rules[0])).unwrap(),
            parsed,
            "round-trip mismatch: {text}"
        );
    }
}

#[test]
fn ruleset_fingerprint_changes_when_aggregate_added() {
    let without = parse_rules("allow stripe.support where amount <= 5000").unwrap();
    let with =
        parse_rules("allow stripe.support where amount <= 5000 and budget amount 50000 per day")
            .unwrap();
    assert_ne!(ruleset_fingerprint(&without), ruleset_fingerprint(&with));

    // The window, limit, and field all participate in the fingerprint.
    let with_hour =
        parse_rules("allow stripe.support where amount <= 5000 and budget amount 50000 per hour")
            .unwrap();
    assert_ne!(ruleset_fingerprint(&with), ruleset_fingerprint(&with_hour));

    let fieldless = parse_rules("allow stripe.support where budget 50000 per day").unwrap();
    let explicit = parse_rules("allow stripe.support where budget amount 50000 per day").unwrap();
    assert_ne!(
        ruleset_fingerprint(&fieldless),
        ruleset_fingerprint(&explicit)
    );
}

#[test]
fn numeric_only_field_is_rejected_for_codec_identity() {
    // An all-digit token is indistinguishable from the fieldless budget limit, so the
    // parser can never produce `Budget{field:Some("123")}`; the structural guard must refuse it
    // too (parity), and a numeric predicate field is refused everywhere.
    assert!(parse_rules("allow stripe.support where 123 <= 5").is_err());
    let bad = Rule {
        effect: RuleEffect::Allow,
        selector: verb("refund"),
        conjuncts: vec![],
        aggregate: Some(Aggregate {
            kind: AggregateKind::Budget {
                field: Some("123".into()),
            },
            limit: 5,
            window: Window::Day,
        }),
    };
    assert!(validate_rule_structure(&bad).is_err());
    let bad_pred = Rule {
        effect: RuleEffect::Allow,
        selector: verb("refund"),
        conjuncts: vec![Pred::Lte {
            field: "123".into(),
            value: 5,
        }],
        aggregate: None,
    };
    assert!(validate_rule_structure(&bad_pred).is_err());
}

#[test]
fn budget_and_rate_are_reserved_field_keywords() {
    // `budget`/`rate` are dispatched to the aggregate arm at any conjunct head, so they
    // can never round-trip as a predicate field. Refuse them as a field name everywhere (parser +
    // structural guard + explicit-budget-field position).
    for text in [
        "allow stripe.support where budget = 5",
        "allow stripe.support where rate = 5",
        "allow stripe.support where amount <= 5 and budget = 5",
    ] {
        assert!(
            parse_rules(text).is_err(),
            "reserved keyword must not parse as a field: {text}"
        );
    }
    let bad_pred = Rule {
        effect: RuleEffect::Allow,
        selector: verb("refund"),
        conjuncts: vec![Pred::Lte {
            field: "budget".into(),
            value: 5,
        }],
        aggregate: None,
    };
    assert!(validate_rule_structure(&bad_pred).is_err());
    let bad_field = Rule {
        effect: RuleEffect::Allow,
        selector: verb("refund"),
        conjuncts: vec![],
        aggregate: Some(Aggregate {
            kind: AggregateKind::Budget {
                field: Some("rate".into()),
            },
            limit: 5,
            window: Window::Day,
        }),
    };
    assert!(validate_rule_structure(&bad_field).is_err());
}

fn arb_ident() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,7}".prop_map(|s| s)
}

fn arb_field() -> impl Strategy<Value = String> {
    prop::collection::vec(arb_ident(), 1..4)
        .prop_map(|parts| parts.join("."))
        // `budget`/`rate` are reserved aggregate keywords, never valid field names;
        // `arb_ident` starts with a letter so an all-digit field is already impossible.
        .prop_filter("budget/rate are reserved aggregate keywords", |field| {
            field != "budget" && field != "rate"
        })
}

fn arb_scalar() -> impl Strategy<Value = Scalar> {
    prop_oneof![
        any::<i32>().prop_map(|n| Scalar::Int(i64::from(n))),
        "[a-zA-Z0-9 _#\\\"\\\\]{0,12}".prop_map(Scalar::String),
        any::<bool>().prop_map(Scalar::Bool),
    ]
}

/// Only selectors the codec can SPELL: a bare verb, or a set named by its immutable expansion.
/// A `Set { digest: None }` has no spelling in the current dialect, so it is not a print/parse identity
/// candidate — `validate_sentence_authority` refuses one, and `v2_m5` owns that refusal.
fn arb_selector() -> impl Strategy<Value = Selector> {
    (arb_ident(), arb_ident(), any::<bool>()).prop_map(|(provider, name, is_set)| {
        if is_set {
            Selector::Set {
                provider,
                set: name,
                digest: Some(format!("sha256:{}", "b".repeat(64))),
            }
        } else {
            Selector::Verb {
                provider,
                action: name,
            }
        }
    })
}

fn arb_pred() -> impl Strategy<Value = Pred> {
    prop_oneof![
        (arb_field(), arb_scalar()).prop_map(|(field, value)| Pred::Eq { field, value }),
        (arb_field(), any::<i64>()).prop_map(|(field, value)| Pred::Lte { field, value }),
        (arb_field(), any::<i64>()).prop_map(|(field, value)| Pred::Gte { field, value }),
        (arb_field(), prop::collection::vec(arb_scalar(), 1..5))
            .prop_map(|(field, values)| Pred::In { field, values }),
    ]
}

fn arb_window() -> impl Strategy<Value = Window> {
    prop_oneof![Just(Window::Hour), Just(Window::Day)]
}

fn arb_aggregate() -> impl Strategy<Value = Aggregate> {
    let kind = prop_oneof![
        Just(AggregateKind::Budget { field: None }),
        arb_field().prop_map(|field| AggregateKind::Budget { field: Some(field) }),
        Just(AggregateKind::Rate),
    ];
    // Limit is a positive integer (parse refuses `<= 0`).
    (kind, 1i64..1_000_000, arb_window()).prop_map(|(kind, limit, window)| Aggregate {
        kind,
        limit,
        window,
    })
}

fn arb_rule() -> impl Strategy<Value = Rule> {
    (
        prop_oneof![Just(RuleEffect::Allow), Just(RuleEffect::Deny)],
        arb_selector(),
        prop::collection::vec(arb_pred(), 0..5),
        proptest::option::of(arb_aggregate()),
    )
        .prop_map(|(effect, selector, conjuncts, aggregate)| Rule {
            effect,
            selector,
            conjuncts,
            // Aggregates are allow-only; a deny rule with one is structurally invalid and would
            // not round-trip, so only attach the generated aggregate to allow rules.
            aggregate: if effect == RuleEffect::Allow {
                aggregate
            } else {
                None
            },
        })
}

proptest! {
    #[test]
    fn parse_after_print_is_identity_for_generated_rule_sets(
        rules in prop::collection::vec(arb_rule(), 0..12),
    ) {
        let expected = RuleSet { version: 1, rules };
        let text = expected.rules.iter().map(print_rule).collect::<Vec<_>>().join("\n");
        prop_assert_eq!(parse_rules(&text).unwrap(), expected);
    }
}

#[test]
fn containment_handles_bounds_extra_conjuncts_and_the_converse() {
    let narrow = Rule {
        effect: RuleEffect::Allow,
        selector: verb("refund"),
        conjuncts: vec![
            Pred::Lte {
                field: "amount".into(),
                value: 50,
            },
            Pred::Eq {
                field: "customer".into(),
                value: Scalar::String("cus_x".into()),
            },
        ],
        aggregate: None,
    };
    let wide = Rule {
        effect: RuleEffect::Allow,
        selector: verb("refund"),
        conjuncts: vec![Pred::Lte {
            field: "amount".into(),
            value: 100,
        }],
        aggregate: None,
    };

    assert!(implies(&narrow, &wide, &BOUNDED_CONTRACT));
    assert!(!implies(&wide, &narrow, &BOUNDED_CONTRACT));
}

#[test]
fn containment_handles_gte_eq_and_in_without_crossing_selectors() {
    let base = |conjuncts| Rule {
        effect: RuleEffect::Allow,
        selector: verb("refund"),
        conjuncts,
        aggregate: None,
    };
    assert!(implies(
        &base(vec![Pred::Gte {
            field: "amount".into(),
            value: 100,
        }]),
        &base(vec![Pred::Gte {
            field: "amount".into(),
            value: 50,
        }]),
        &BOUNDED_CONTRACT,
    ));
    assert!(implies(
        &base(vec![Pred::Eq {
            field: "customer".into(),
            value: Scalar::String("cus_x".into()),
        }]),
        &base(vec![Pred::In {
            field: "customer".into(),
            values: vec![
                Scalar::String("cus_x".into()),
                Scalar::String("cus_y".into()),
            ],
        }]),
        &BOUNDED_CONTRACT,
    ));
    assert!(implies(
        &base(vec![Pred::In {
            field: "customer".into(),
            values: vec![Scalar::String("cus_x".into())],
        }]),
        &base(vec![Pred::In {
            field: "customer".into(),
            values: vec![
                Scalar::String("cus_x".into()),
                Scalar::String("cus_y".into()),
            ],
        }]),
        &BOUNDED_CONTRACT,
    ));

    let other_selector = Rule {
        effect: RuleEffect::Allow,
        selector: verb("charge"),
        conjuncts: vec![],
        aggregate: None,
    };
    assert!(!implies(&base(vec![]), &other_selector, &BOUNDED_CONTRACT));
}

struct VersionedSetResolver {
    current: crate::sets::SetSnapshot,
    snapshots: std::collections::BTreeMap<String, crate::sets::SetSnapshot>,
}

struct M4Contracts;

impl ContractResolver for M4Contracts {
    fn contract(&self, provider: &str, action: &str) -> Option<&ActionContract> {
        match (provider, action) {
            ("stripe", "lookup_customer") => Some(&CUSTOMER_ONLY_CONTRACT),
            ("stripe", "refund") => Some(&AMOUNT_ONLY_CONTRACT),
            ("stripe", "charge") => Some(&CHARGE_CONTRACT),
            _ => None,
        }
    }
}

impl VersionedSetResolver {
    fn new(current: crate::sets::SetSnapshot) -> Self {
        Self {
            snapshots: [(current.digest().to_string(), current.clone())]
                .into_iter()
                .collect(),
            current,
        }
    }

    fn ratify(&mut self, next: crate::sets::SetSnapshot) {
        self.snapshots
            .insert(next.digest().to_string(), next.clone());
        self.current = next;
    }
}

impl crate::sets::SetResolver for VersionedSetResolver {
    fn current_snapshot(&self, provider: &str, set: &str) -> Option<crate::sets::SetSnapshot> {
        (self.current.provider() == provider && self.current.name() == set)
            .then(|| self.current.clone())
    }

    fn snapshot(
        &self,
        provider: &str,
        set: &str,
        digest: &str,
    ) -> Option<crate::sets::SetSnapshot> {
        self.snapshots
            .get(digest)
            .filter(|snapshot| snapshot.provider() == provider && snapshot.name() == set)
            .cloned()
    }
}

#[test]
fn v1_m4_pinned_set_rule_keeps_its_immutable_coverage_after_catalog_growth() {
    let old = crate::sets::SetSnapshot::new(
        "stripe",
        "support",
        vec!["lookup_customer".into(), "refund".into()],
    )
    .unwrap();
    let old_digest = old.digest().to_string();
    let mut sets = VersionedSetResolver::new(old);
    let mut rules = parse_rules(&format!(
        "allow stripe.support@{old_digest} where amount <= 50"
    ))
    .unwrap();
    pin_set_references(&mut rules, &sets).unwrap();

    let Selector::Set { digest, .. } = &rules.rules[0].selector else {
        panic!("the authored selector must remain a set")
    };
    assert_eq!(digest.as_deref(), Some(old_digest.as_str()));
    assert_eq!(
        print_rule(&rules.rules[0]),
        format!("allow stripe.support@{old_digest} where amount <= 50")
    );
    assert_eq!(
        parse_rules(&print_rule(&rules.rules[0])).unwrap().rules,
        rules.rules
    );

    sets.ratify(
        crate::sets::SetSnapshot::new(
            "stripe",
            "support",
            vec!["charge".into(), "lookup_customer".into(), "refund".into()],
        )
        .unwrap(),
    );

    let refund = CanonicalResource::from_stored(r#"{"amount":30}"#, &AMOUNT_ONLY_CONTRACT).unwrap();
    let charge = CanonicalResource::from_stored(r#"{"amount":30}"#, &CHARGE_CONTRACT).unwrap();
    let evaluator = SentenceEvaluator::new(&sets, &M4Contracts);
    assert_eq!(
        evaluator.evaluate(&rules, "stripe", "refund", &refund),
        Decision::Allow { rule_idx: 0 }
    );
    assert_eq!(
        evaluator.evaluate(&rules, "stripe", "charge", &charge),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
        },
        "a newly ratified member must not enter old standing authority"
    );
}

#[test]
fn preparation_preserves_a_resolvable_historical_pin_after_catalog_growth() {
    let historical = crate::sets::SetSnapshot::new(
        "stripe",
        "support",
        vec!["lookup_customer".into(), "refund".into()],
    )
    .unwrap();
    let historical_digest = historical.digest().to_string();
    let mut sets = VersionedSetResolver::new(historical);
    sets.ratify(
        crate::sets::SetSnapshot::new(
            "stripe",
            "support",
            vec!["charge".into(), "lookup_customer".into(), "refund".into()],
        )
        .unwrap(),
    );

    let source = format!("allow stripe.support@{historical_digest}\n");
    let prepared = prepare_sentence_authority(&source, &sets, &M4Contracts, false).unwrap();
    assert_eq!(prepared.canonical_text, source);
    assert_eq!(prepared.set_snapshots[0].digest, historical_digest);
    assert_eq!(
        prepared.set_snapshots[0].members,
        ["lookup_customer", "refund"]
    );
}

#[test]
fn malformed_projected_out_conjunct_never_becomes_a_widen_hint() {
    let snapshot = crate::sets::SetSnapshot::new(
        "stripe",
        "support",
        vec!["lookup_customer".into(), "refund".into()],
    )
    .unwrap();
    let sets = VersionedSetResolver::new(snapshot);
    let mut rules =
        parse_rules("allow stripe.support where amount <= 50 and customer = \"safe\"").unwrap();
    pin_set_references(&mut rules, &sets).unwrap();
    rules.rules[0].conjuncts[1] = Pred::Eq {
        field: "customer".into(),
        value: Scalar::String("true".into()),
    };
    let resource =
        CanonicalResource::from_stored(r#"{"amount":75}"#, &AMOUNT_ONLY_CONTRACT).unwrap();
    let evaluator = SentenceEvaluator::new(&sets, &M4Contracts);

    assert_eq!(
        evaluator.evaluate(&rules, "stripe", "refund", &resource),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
        },
        "the evaluator rejects the parser-invalid Boolean-shaped identifier"
    );
    assert!(
        evaluator
            .widen_hint_for_request(&rules, "stripe", "refund", &resource)
            .is_none(),
        "a malformed conjunct projected off this member must not be reattached into actionable text"
    );
}

#[test]
fn unsupported_ruleset_never_produces_a_widen_hint() {
    let mut rules = parse_rules("allow stripe.refund where amount <= 50").unwrap();
    rules.version = 2;
    let resource =
        CanonicalResource::from_stored(r#"{"amount":75}"#, &AMOUNT_ONLY_CONTRACT).unwrap();

    assert!(
        SentenceEvaluator::new(
            &crate::sets::EmptySetResolver,
            &FixedContractResolver(&AMOUNT_ONLY_CONTRACT),
        )
        .widen_hint_for_request(&rules, "stripe", "refund", &resource)
        .is_none(),
        "unsupported authority stays hintless"
    );
}

#[test]
fn v1_m4_unpinned_unknown_and_mismatched_set_snapshots_yield_no_authority() {
    let snapshot =
        crate::sets::SetSnapshot::new("stripe", "support", vec!["refund".into()]).unwrap();
    let sets = VersionedSetResolver::new(snapshot);
    let resource =
        CanonicalResource::from_stored(r#"{"amount":30}"#, &AMOUNT_ONLY_CONTRACT).unwrap();
    let evaluator = SentenceEvaluator::new(&sets, &M4Contracts);

    // A bare dotted selector is the VERB, so a set NAME grants nothing at all —
    // there is no unpinned set to evaluate, which is the strongest form of "yields no authority".
    let bare_set_name = parse_rules("allow stripe.support where amount <= 50").unwrap();
    assert_eq!(
        bare_set_name.rules[0].selector,
        Selector::Verb {
            provider: "stripe".into(),
            action: "support".into(),
        }
    );
    assert_eq!(
        evaluator.evaluate(&bare_set_name, "stripe", "refund", &resource),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
        }
    );

    let mut unknown_digest = parse_rules(&format!(
        "allow stripe.support@sha256:{} where amount <= 50",
        "0".repeat(64)
    ))
    .unwrap();
    let Selector::Set { digest, .. } = &mut unknown_digest.rules[0].selector else {
        unreachable!()
    };
    *digest = Some(format!("sha256:{}", "0".repeat(64)));
    assert_eq!(
        evaluator.evaluate(&unknown_digest, "stripe", "refund", &resource),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
        }
    );

    struct MismatchedSnapshotResolver(crate::sets::SetSnapshot);
    impl crate::sets::SetResolver for MismatchedSnapshotResolver {
        fn current_snapshot(
            &self,
            _provider: &str,
            _set: &str,
        ) -> Option<crate::sets::SetSnapshot> {
            Some(self.0.clone())
        }

        fn snapshot(
            &self,
            _provider: &str,
            _set: &str,
            _digest: &str,
        ) -> Option<crate::sets::SetSnapshot> {
            Some(self.0.clone())
        }
    }
    let wrong = crate::sets::SetSnapshot::new("stripe", "mutate", vec!["refund".into()]).unwrap();
    let valid = crate::sets::SetSnapshot::new("stripe", "support", vec!["refund".into()]).unwrap();
    let mut mismatched_rule = parse_rules(&format!(
        "allow stripe.support@{} where amount <= 50",
        valid.digest()
    ))
    .unwrap();
    pin_set_references(&mut mismatched_rule, &VersionedSetResolver::new(valid)).unwrap();
    assert_eq!(
        SentenceEvaluator::new(&MismatchedSnapshotResolver(wrong), &M4Contracts).evaluate(
            &mismatched_rule,
            "stripe",
            "refund",
            &resource,
        ),
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
        },
        "a resolver result whose name/content does not match the pin grants nothing"
    );

    let mut cyclic_or_unresolved = parse_rules(&format!(
        "allow stripe.support@sha256:{} where amount <= 50",
        "0".repeat(64)
    ))
    .unwrap();
    assert!(
        pin_set_references(&mut cyclic_or_unresolved, &crate::sets::EmptySetResolver,).is_err()
    );
}

#[test]
fn v1_m4_unresolved_set_deny_is_not_skipped_for_an_overlapping_allow() {
    let snapshot =
        crate::sets::SetSnapshot::new("stripe", "support", vec!["refund".into()]).unwrap();
    let sets = VersionedSetResolver::new(snapshot);
    let mut rules = parse_rules(&format!(
        "deny stripe.support@sha256:{}\n\
         allow stripe.refund where amount <= 50",
        "0".repeat(64)
    ))
    .unwrap();
    rules.rules[0].conjuncts = vec![Pred::Gte {
        field: "amount".into(),
        value: 1,
    }];
    let Selector::Set { digest, .. } = &mut rules.rules[0].selector else {
        unreachable!()
    };
    *digest = Some(format!("sha256:{}", "0".repeat(64)));
    let resource =
        CanonicalResource::from_stored(r#"{"amount":30}"#, &AMOUNT_ONLY_CONTRACT).unwrap();

    assert_eq!(
        SentenceEvaluator::new(&sets, &M4Contracts)
            .evaluate(&rules, "stripe", "refund", &resource,),
        Decision::Deny {
            reason: DenyReason::UnresolvedDeny { rule_idx: 0 },
        }
    );
}

#[test]
fn serde_empty_in_deny_on_open_contract_blocks_overlapping_allow() {
    let seed = parse_rules(
        "deny stripe.open_member where tag in {\"blocked\"}\n\
         allow stripe.open_member",
    )
    .unwrap();
    let mut encoded = serde_json::to_value(seed).unwrap();
    encoded["rules"][0]["conjuncts"][0]["in"]["values"] = serde_json::json!([]);
    let rules: RuleSet = serde_json::from_value(encoded).unwrap();
    let resource =
        CanonicalResource::from_stored(r#"{"tag":"safe"}"#, &OPEN_MEMBER_CONTRACT).unwrap();

    assert_eq!(
        SentenceEvaluator::new(
            &crate::sets::EmptySetResolver,
            &FixedContractResolver(&OPEN_MEMBER_CONTRACT),
        )
        .evaluate(&rules, "stripe", "open_member", &resource),
        Decision::Deny {
            reason: DenyReason::UnresolvedDeny { rule_idx: 0 },
        }
    );
}

#[test]
fn serde_malformed_fields_on_open_contract_denies_remain_unresolved() {
    let cases = [
        ("tag = \"blocked\"", "eq", ""),
        ("tag <= 5", "lte", "Tag"),
        ("tag >= 1", "gte", ".tag"),
        ("tag in {\"blocked\"}", "in", "tag."),
    ];
    let resource =
        CanonicalResource::from_stored(r#"{"tag":"safe"}"#, &OPEN_MEMBER_CONTRACT).unwrap();
    let evaluator = SentenceEvaluator::new(
        &crate::sets::EmptySetResolver,
        &FixedContractResolver(&OPEN_MEMBER_CONTRACT),
    );

    for (predicate, variant, malformed_field) in cases {
        let seed = parse_rules(&format!(
            "deny stripe.open_member where {predicate}\nallow stripe.open_member"
        ))
        .unwrap();
        let mut encoded = serde_json::to_value(seed).unwrap();
        encoded["rules"][0]["conjuncts"][0][variant]["field"] = serde_json::json!(malformed_field);
        let rules: RuleSet = serde_json::from_value(encoded).unwrap();

        assert_eq!(
            evaluator.evaluate(&rules, "stripe", "open_member", &resource),
            Decision::Deny {
                reason: DenyReason::UnresolvedDeny { rule_idx: 0 },
            },
            "public serde must not bypass field grammar for {variant}"
        );
    }
}

/// The old bare-`ident` scalar defended against a serde payload carrying an identifier the parser
/// would never have produced, and matching had to refuse it. The dialect change deleted
/// `Scalar::Ident` outright — a string is quoted and nothing else is a string — so the smuggling
/// route is now a TYPE error rather than a validation duty. This owns that: the variant must stay
/// unconstructible from the wire, including from a payload some older build wrote.
#[test]
fn the_deleted_ident_scalar_cannot_be_smuggled_back_through_serde() {
    let seed =
        parse_rules("deny stripe.open_member where tag = \"blocked\"\nallow stripe.open_member")
            .unwrap();
    let mut encoded = serde_json::to_value(seed).unwrap();
    encoded["rules"][0]["conjuncts"][0]["eq"]["value"] = serde_json::json!({"ident": "blocked"});
    assert!(
        serde_json::from_value::<RuleSet>(encoded).is_err(),
        "an `ident` scalar must not deserialize into a language that has no such literal"
    );
}

/// With `Scalar::Ident` deleted, every scalar variant is well formed by construction (an int, a
/// bool, or a string the printer can always quote), so the FIELD NAME is the only structurally
/// invalid thing a serde payload can still carry.
#[test]
fn every_serde_rule_is_structurally_validated_before_matching() {
    let cases = [
        (
            "invalid field name",
            Pred::Eq {
                field: "Tag".into(),
                value: Scalar::String("matched".into()),
            },
            r#"{"Tag":"matched"}"#,
        ),
        (
            "invalid field name in an In",
            Pred::In {
                field: "Tag".into(),
                values: vec![Scalar::String("safe".into())],
            },
            r#"{"Tag":"safe"}"#,
        ),
        (
            "empty In list",
            Pred::In {
                field: "tag".into(),
                values: Vec::new(),
            },
            r#"{"tag":"safe"}"#,
        ),
    ];
    let evaluator = SentenceEvaluator::new(
        &crate::sets::EmptySetResolver,
        &FixedContractResolver(&OPEN_MEMBER_CONTRACT),
    );

    for (name, malformed, resource_json) in cases {
        let resource =
            CanonicalResource::from_stored(resource_json, &OPEN_MEMBER_CONTRACT).unwrap();
        let serde_rule = |effect| {
            serde_json::from_value::<RuleSet>(
                serde_json::to_value(RuleSet {
                    version: 1,
                    rules: vec![Rule {
                        effect,
                        selector: verb("open_member"),
                        conjuncts: vec![malformed.clone()],
                        aggregate: None,
                    }],
                })
                .unwrap(),
            )
            .expect("public serde currently admits structural rule variants")
        };

        let allow = serde_rule(RuleEffect::Allow);
        assert_eq!(
            evaluator.evaluate(&allow, "stripe", "open_member", &resource),
            Decision::Deny {
                reason: DenyReason::NoMatchingRule,
            },
            "{name}: a malformed allow must not participate"
        );
        let mut deny_then_allow = serde_rule(RuleEffect::Deny);
        deny_then_allow.rules.push(Rule {
            effect: RuleEffect::Allow,
            selector: verb("open_member"),
            conjuncts: Vec::new(),
            aggregate: None,
        });
        assert_eq!(
            evaluator.evaluate(&deny_then_allow, "stripe", "open_member", &resource),
            Decision::Deny {
                reason: DenyReason::UnresolvedDeny { rule_idx: 0 },
            },
            "{name}: a covering malformed deny must not fall through"
        );
    }

    for (valid, resource_json) in [
        ("allow stripe.open_member", r#"{"tag":"anything"}"#),
        (
            "allow stripe.open_member where tag = \"safe\"",
            r#"{"tag":"safe"}"#,
        ),
        (
            "allow stripe.open_member where tag = \"true\"",
            r#"{"tag":"true"}"#,
        ),
        (
            "allow stripe.open_member where tag = \"not parser valid\"",
            r#"{"tag":"not parser valid"}"#,
        ),
    ] {
        let rules = parse_rules(valid).unwrap();
        let resource =
            CanonicalResource::from_stored(resource_json, &OPEN_MEMBER_CONTRACT).unwrap();
        assert_eq!(
            evaluator.evaluate(&rules, "stripe", "open_member", &resource),
            Decision::Allow { rule_idx: 0 },
            "valid loose and quoted-string allows retain their authored meaning: {valid}"
        );
    }
}

struct OpenProjectionContracts;

impl ContractResolver for OpenProjectionContracts {
    fn contract(&self, provider: &str, action: &str) -> Option<&ActionContract> {
        match (provider, action) {
            ("stripe", "open_member") => Some(&OPEN_MEMBER_CONTRACT),
            ("stripe", "closed_member") => Some(&CLOSED_MEMBER_CONTRACT),
            _ => None,
        }
    }
}

#[test]
fn set_projection_honors_open_concrete_and_sibling_fields() {
    let snapshot = crate::sets::SetSnapshot::new(
        "stripe",
        "support",
        vec!["closed_member".into(), "open_member".into()],
    )
    .unwrap();
    let digest = snapshot.digest().to_string();
    let sets = VersionedSetResolver::new(snapshot);
    let mut rules = parse_rules(&format!(
        "deny stripe.support@{digest} where tag = \"blocked\"\n\
         allow stripe.open_member",
    ))
    .unwrap();
    pin_set_references(&mut rules, &sets).unwrap();
    let evaluator = SentenceEvaluator::new(&sets, &OpenProjectionContracts);

    let safe = CanonicalResource::from_stored(r#"{"tag":"safe"}"#, &OPEN_MEMBER_CONTRACT).unwrap();
    assert_eq!(
        evaluator.evaluate(&rules, "stripe", "open_member", &safe),
        Decision::Allow { rule_idx: 1 },
        "an open concrete member must retain the predicate instead of blanket-denying a nonmatch"
    );

    let blocked =
        CanonicalResource::from_stored(r#"{"tag":"blocked"}"#, &OPEN_MEMBER_CONTRACT).unwrap();
    assert_eq!(
        evaluator.evaluate(&rules, "stripe", "open_member", &blocked),
        Decision::Deny {
            reason: DenyReason::ExplicitDeny { rule_idx: 0 },
        }
    );

    let projected_open = evaluator
        .project_rule(&rules.rules[0], "stripe", "open_member")
        .unwrap();
    assert_eq!(projected_open.rule.conjuncts, rules.rules[0].conjuncts);

    let projected_closed = evaluator
        .project_rule(&rules.rules[0], "stripe", "closed_member")
        .expect("an open sibling establishes that the field exists in the set");
    assert!(
        projected_closed.rule.conjuncts.is_empty(),
        "a closed concrete member still drops a field it does not declare"
    );
}

// --- the dissolved integer-pin coercion on a `format: uint` str field ----------------------------
// An earlier dialect let an INTEGER literal match a `str` identity field declaring `format: uint`.
// Its whole justification was lexical: a quoted scalar on an identity field meant RESOLVE THIS
// NAME, and a bare `3` lexed as an integer, so a bare-decimal identity had no spelling at all.
// Mandatory, literal quoting makes `number = "3"` say it directly — so the coercion has nothing
// left to buy and is gone, along with the `FieldDecl::canonical_uint` flag that existed only to
// grant it. `format: uint` itself STAYS: it is the request-value admission shape (a canonical bare
// positive decimal), checked in `templates.rs`, and never a matching rule.

const UINT_PIN_SCHEMA: &[FieldDecl] = &[
    FieldDecl {
        name: "number",
        ty: ScalarKind::Str,
        required: true,
        class: FieldClass::Identity,
        binding: AllowBinding::ExactResourcePin,
    },
    FieldDecl {
        name: "label",
        ty: ScalarKind::Str,
        required: false,
        class: FieldClass::Identity,
        binding: AllowBinding::ExactResourcePin,
    },
];

const UINT_PIN_CONTRACT: ActionContract = ActionContract {
    provider: "github",
    action: "comment_thread",
    schema: UINT_PIN_SCHEMA,
    consumes: &["number", "label"],
    execution_targets: &["number"],
    relations: &[],
    open: false,
};

fn uint_rules(text: &str) -> RuleSet {
    parse_rules(text).expect("rule parses")
}

fn uint_resource(value: &str) -> CanonicalResource {
    CanonicalResource::from_stored(
        &format!(r#"{{"number":{}}}"#, serde_json::json!(value)),
        &UINT_PIN_CONTRACT,
    )
    .expect("resource canonicalizes")
}

fn uint_decision(rule_text: &str, resource: serde_json::Value) -> Decision {
    let rules = parse_rules(rule_text).expect("rule parses");
    let Ok(resource) = CanonicalResource::from_stored(&resource.to_string(), &UINT_PIN_CONTRACT)
    else {
        // A value the declared format refuses never reaches matching at all — admission is the
        // first wall, and that is itself the guarantee a quoted pin leans on.
        return Decision::Deny {
            reason: DenyReason::UnknownSelector,
        };
    };
    evaluate_with_contract(&rules, &resource, &UINT_PIN_CONTRACT)
}

#[test]
fn a_quoted_pin_is_how_a_bare_decimal_identity_is_written() {
    assert!(matches!(
        uint_decision(
            r#"allow github.comment_thread where number = "3""#,
            serde_json::json!({ "number": "3" }),
        ),
        Decision::Allow { .. }
    ));
    // …and only for that number.
    assert!(matches!(
        uint_decision(
            r#"allow github.comment_thread where number = "3""#,
            serde_json::json!({ "number": "4" }),
        ),
        Decision::Deny { .. }
    ));
}

#[test]
fn an_integer_literal_binds_no_string_field_at_all() {
    // The coercion is gone in BOTH directions of the judgment: an integer literal neither RESOLVES
    // against a `str` field nor MATCHES one, whatever format it declares. The pair matters because
    // the two used to be checked by separate, driftable copies of the same judgment.
    let rule = &uint_rules("allow github.comment_thread where number = 3").rules[0];
    assert!(
        !conjuncts_match_resource(&rule.conjuncts, &uint_resource("3"), &UINT_PIN_CONTRACT),
        "an integer literal must not resolve or match on a string field"
    );
    assert!(matches!(
        uint_decision(
            "allow github.comment_thread where number = 3",
            serde_json::json!({ "number": "3" }),
        ),
        Decision::Deny { .. }
    ));
    // A DENY carrying the same literal is unresolvable and therefore denies the whole action —
    // fail closed, which is the correct treatment of a rule the evaluator cannot honour.
    let denied = evaluate_with_contract(
        &uint_rules(
            "allow github.comment_thread
deny github.comment_thread where number = 3",
        ),
        &uint_resource("3"),
        &UINT_PIN_CONTRACT,
    );
    assert!(
        matches!(
            denied,
            Decision::Deny {
                reason: DenyReason::UnresolvedDeny { .. }
            }
        ),
        "an unresolvable deny must fail closed, got {denied:?}"
    );
}

#[test]
fn a_quoted_pin_still_widens_and_still_implies() {
    // Widening and containment are unchanged by the dissolution; they simply see one string kind.
    let rule = &uint_rules(r#"allow github.comment_thread where number = "3""#).rules[0];
    let widened = widen_rule_for_request(rule, &uint_resource("4"), &UINT_PIN_CONTRACT)
        .expect("a quoted pin must be widenable");
    assert!(
        conjuncts_match_resource(&widened.conjuncts, &uint_resource("4"), &UINT_PIN_CONTRACT)
            && conjuncts_match_resource(
                &widened.conjuncts,
                &uint_resource("3"),
                &UINT_PIN_CONTRACT
            ),
        "the widened rule must admit the old and the new value: {widened:?}"
    );
    assert!(
        implies(rule, &widened, &UINT_PIN_CONTRACT),
        "widening must never narrow"
    );
    assert_eq!(
        print_rule(&widened),
        r#"allow github.comment_thread where number in {"3", "4"}"#
    );
}

#[test]
fn a_numeric_bound_still_resolves_only_on_an_int_field() {
    // `<=`/`>=` compare against integers, so on a string field they resolve against nothing and
    // imply nothing — that soundness result survives the coercion's dissolution.
    let narrow = &uint_rules(r#"allow github.comment_thread where number = "3""#).rules[0];
    let wide = Rule {
        effect: RuleEffect::Allow,
        selector: narrow.selector.clone(),
        conjuncts: vec![Pred::Lte {
            field: "number".into(),
            value: 4,
        }],
        aggregate: None,
    };
    assert!(
        !implies(narrow, &wide, &UINT_PIN_CONTRACT),
        "a string pin must not imply a numeric bound"
    );
    assert!(
        !conjuncts_match_resource(&wide.conjuncts, &uint_resource("3"), &UINT_PIN_CONTRACT),
        "a numeric bound must not admit a string"
    );
    // The same shape on a genuinely Int field is still sound and must keep working.
    let int_narrow = Rule {
        effect: RuleEffect::Allow,
        selector: verb("refund"),
        conjuncts: vec![Pred::Eq {
            field: "amount".into(),
            value: Scalar::Int(3),
        }],
        aggregate: None,
    };
    let int_wide = Rule {
        effect: RuleEffect::Allow,
        selector: verb("refund"),
        conjuncts: vec![Pred::Lte {
            field: "amount".into(),
            value: 4,
        }],
        aggregate: None,
    };
    assert!(
        implies(&int_narrow, &int_wide, &BOUNDED_CONTRACT),
        "numeric containment on an int field must be unaffected"
    );
}

#[test]
fn the_uint_format_is_still_the_admission_shape() {
    // The declaration the coercion was keyed off remains, doing its own job: a non-canonical value
    // never becomes a resource at all, so a quoted pin cannot be fooled by `03` or `+3` either.
    let registry = crate::templates::TemplateRegistry::new();
    for doc in crate::templates::VENDORED_CATALOG {
        registry.load(doc).expect("vendored template loads");
    }
    for (action, field) in [
        ("comment_thread", "number"),
        ("read_thread", "number"),
        ("read_pull_request", "number"),
        ("create_pull_request_review", "number"),
        ("read_workflow_run", "run_id"),
        ("request_workflow_cancel", "run_id"),
    ] {
        let contract = registry
            .resolve("github", action)
            .unwrap_or_else(|| panic!("github.{action} resolves"));
        let decl = contract
            .field_decl(field)
            .unwrap_or_else(|| panic!("github.{action}.{field} is declared"));
        assert_eq!(decl.ty, ScalarKind::Str, "github.{action}.{field}");
    }
    for hostile in ["03", "+3", " 3", "3 ", "0x3", ""] {
        assert!(
            matches!(
                uint_decision(
                    r#"allow github.comment_thread where number = "3""#,
                    serde_json::json!({ "number": hostile }),
                ),
                Decision::Deny { .. }
            ),
            "a non-canonical uint reached matching: {hostile:?}"
        );
    }
}

#[test]
fn one_shared_judgment_serves_every_declaration_site() {
    // The bug CLASS was two copies of "can this literal bind this field" drifting apart. The
    // dissolution removes the exception they disagreed about, and this keeps the single-definition
    // property that made the drift detectable.
    let source = include_str!("../../../cermet-lang/src/sentence.rs");
    assert!(
        !source.contains("fn scalar_resolves_for_kind"),
        "the second copy of the binding judgment is back"
    );
    assert!(
        !source.contains("fn uint_pin_binds"),
        "the dissolved coercion is back without a ruling"
    );
    for (site, needle) in [
        (
            "kind resolution / deny / discovery / widening admission",
            "pred_resolves_for_decl(pred, decl)",
        ),
        (
            "predicate resolution",
            "Pred::Eq { value, .. } => scalar_binds_decl(value, decl)",
        ),
    ] {
        assert!(
            source.contains(needle),
            "the {site} site no longer routes through the shared judgment"
        );
    }
    assert_eq!(source.matches("fn scalar_binds_decl(").count(), 1);
    assert_eq!(source.matches("fn scalar_matches(").count(), 1);
}

// --- an unruled verb must teach its widening path -------------------------------------------------
// Two defects lived in one deny string. `unknown or unmatched selector` bundled "this verb is not
// in the grammar" (a typo the agent must fix) with "no rule mentions this verb" (an authority gap
// only the operator can close), and the second case carried no widening suggestion at all — the
// shaper only ever widened an EXISTING allow, so a verb with no rule got a dead end. The decision
// is unchanged (Deny, fail closed); only its teaching improves.

#[test]
fn a_verb_outside_the_grammar_stays_an_unknown_selector_with_no_hint() {
    struct NoContracts;
    impl ContractResolver for NoContracts {
        fn contract(&self, _provider: &str, _action: &str) -> Option<&ActionContract> {
            None
        }
    }
    let rules = parse_rules("allow stripe.get_charge").unwrap();
    let resource = refund_resource(r#"{"amount":75}"#);
    let outcome = SentenceEvaluator::new(&crate::sets::EmptySetResolver, &NoContracts)
        .evaluate_with_widen_hint(&rules, "stripe", "refnud", &resource);
    assert_eq!(
        outcome.decision,
        Decision::Deny {
            reason: DenyReason::UnknownSelector,
        },
        "a verb the grammar does not know is a typo, not an authority gap"
    );
    assert!(
        outcome.widen_hint.is_none(),
        "there is no rule to write for a verb that does not exist"
    );
}

#[test]
fn an_unruled_account_scoped_verb_teaches_the_bare_allow() {
    // BOUNDED_CONTRACT declares no execution target, which is the `scope: account` shape: a bare
    // allow is the only rule that can admit it.
    let rules = parse_rules("allow stripe.get_charge").unwrap();
    let resource = refund_resource(r#"{"amount":75}"#);
    let outcome = SentenceEvaluator::new(
        &crate::sets::EmptySetResolver,
        &FixedContractResolver(&BOUNDED_CONTRACT),
    )
    .evaluate_with_widen_hint(&rules, "stripe", "refund", &resource);
    assert_eq!(
        outcome.decision,
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
        },
        "the grammar knows this verb; no rule mentions it"
    );
    assert_eq!(
        outcome.widen_hint.map(|hint| hint.command),
        Some("to allow: cermet rules allow 'stripe.refund'".into())
    );
}

#[test]
fn an_unruled_pinnable_verb_teaches_the_pinned_allow() {
    let rules = parse_rules("allow stripe.get_charge").unwrap();
    let resource = CanonicalResource::from_stored(
        r#"{"amount":75,"account":"acct_1","mode":"live","currency":"usd"}"#,
        &TEST_MONEY_CONTRACT,
    )
    .unwrap();
    let outcome = SentenceEvaluator::new(
        &crate::sets::EmptySetResolver,
        &FixedContractResolver(&TEST_MONEY_CONTRACT),
    )
    .evaluate_with_widen_hint(&rules, "stripe", "test_money_action", &resource);
    assert_eq!(
        outcome.decision,
        Decision::Deny {
            reason: DenyReason::NoMatchingRule,
        }
    );
    assert_eq!(
        outcome.widen_hint.map(|hint| hint.command),
        Some(
            "to allow: cermet rules allow 'stripe.test_money_action where account = \"acct_1\" and \
             mode = \"live\" and currency = \"usd\"'"
                .into()
        ),
        "least privilege: every execution target is pinned to what was actually asked for"
    );
}
