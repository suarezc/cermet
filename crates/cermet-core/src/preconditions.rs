//! Compiled, non-authorizing money preconditions.

use crate::contract::CanonicalResource;
use crate::stripe_inert::{invoice_safe_shape, payment_intent_safe_shape};
use serde_json::Value;

const PRECONDITION_FINGERPRINT_DOMAIN: &[u8] = b"cermet-money-preconditions-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreconditionKind {
    PaymentMethodBelongsToCustomer,
    InvoiceOpen,
    PiConfirmable,
    PiCapturable,
    PiCancelable,
    PayoutsEnabled,
    BalanceSufficient,
    DestinationBelongsAndCurrencyMatches,
    ChargeRefundable,
    #[cfg(any(test, feature = "test-double"))]
    TestChargeReady,
}

#[derive(Debug, Clone, Copy)]
pub struct CompiledPrecondition {
    pub name: &'static str,
    pub provider: &'static str,
    pub action: &'static str,
    pub kind: PreconditionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreconditionFailureClass {
    Unknown,
    Stale,
    Malformed,
    StateMismatch,
    RelationshipMismatch,
    InsufficientBalance,
    ProviderUnavailable,
    Integrity,
}

impl PreconditionFailureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Stale => "stale",
            Self::Malformed => "malformed",
            Self::StateMismatch => "state_mismatch",
            Self::RelationshipMismatch => "relationship_mismatch",
            Self::InsufficientBalance => "insufficient_balance",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::Integrity => "integrity",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreconditionFailure {
    pub name: &'static str,
    pub class: PreconditionFailureClass,
}

impl PreconditionFailure {
    pub fn new(name: &'static str, class: PreconditionFailureClass) -> Self {
        Self { name, class }
    }
}

const PRECONDITIONS: &[CompiledPrecondition] = &[
    CompiledPrecondition {
        name: "payment_method_belongs_to_customer",
        provider: "stripe",
        action: "create_payment_intent_off_session",
        kind: PreconditionKind::PaymentMethodBelongsToCustomer,
    },
    CompiledPrecondition {
        name: "invoice_open",
        provider: "stripe",
        action: "retry_invoice_payment",
        kind: PreconditionKind::InvoiceOpen,
    },
    CompiledPrecondition {
        name: "pi_confirmable",
        provider: "stripe",
        action: "confirm_payment_intent",
        kind: PreconditionKind::PiConfirmable,
    },
    CompiledPrecondition {
        name: "pi_capturable",
        provider: "stripe",
        action: "capture_payment_intent",
        kind: PreconditionKind::PiCapturable,
    },
    CompiledPrecondition {
        name: "pi_cancelable",
        provider: "stripe",
        action: "cancel_payment_intent",
        kind: PreconditionKind::PiCancelable,
    },
    CompiledPrecondition {
        name: "payouts_enabled",
        provider: "stripe",
        action: "create_standard_payout",
        kind: PreconditionKind::PayoutsEnabled,
    },
    CompiledPrecondition {
        name: "balance_sufficient",
        provider: "stripe",
        action: "create_standard_payout",
        kind: PreconditionKind::BalanceSufficient,
    },
    CompiledPrecondition {
        name: "destination_belongs_and_currency_matches",
        provider: "stripe",
        action: "create_standard_payout",
        kind: PreconditionKind::DestinationBelongsAndCurrencyMatches,
    },
    CompiledPrecondition {
        name: "charge_refundable",
        provider: "stripe",
        action: "refund_charge_bounded",
        kind: PreconditionKind::ChargeRefundable,
    },
    #[cfg(any(test, feature = "test-double"))]
    CompiledPrecondition {
        name: "test_charge_ready",
        provider: "stripe",
        action: "test_charge_evidence",
        kind: PreconditionKind::TestChargeReady,
    },
];

pub fn exact(provider: &str, action: &str, name: &str) -> Option<&'static CompiledPrecondition> {
    PRECONDITIONS.iter().find(|precondition| {
        precondition.provider == provider
            && precondition.action == action
            && precondition.name == name
    })
}

pub fn resolve_exact(
    provider: &str,
    action: &str,
    names: &[String],
) -> Option<Vec<&'static CompiledPrecondition>> {
    let required = PRECONDITIONS
        .iter()
        .filter(|precondition| precondition.provider == provider && precondition.action == action)
        .collect::<Vec<_>>();
    (required.len() == names.len()
        && required
            .iter()
            .zip(names)
            .all(|(precondition, name)| precondition.name == name))
    .then_some(required)
}

pub fn semantics_fingerprint(provider: &str, action: &str, names: &[String]) -> Option<String> {
    use sha2::{Digest, Sha256};

    let profiles = resolve_exact(provider, action, names)?;
    let mut hash = Sha256::new();
    hash.update(PRECONDITION_FINGERPRINT_DOMAIN);
    for profile in profiles {
        for field in [profile.provider, profile.action, profile.name] {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
    }
    hash.update(include_bytes!("preconditions.rs"));
    hash.update(include_bytes!("provider/stripe_preconditions.rs"));
    hash.update(include_bytes!("mutation_success.rs"));
    hash.update(crate::stripe_inert::IMPLEMENTATION_SOURCE);
    hash.update(crate::provider_json::IMPLEMENTATION_SOURCE);
    Some(format!("sha256:{}", crate::util::hex(&hash.finalize())))
}

fn exact_str(resource: &CanonicalResource, field: &str, observed: &Value) -> bool {
    resource
        .get_str(field)
        .is_some_and(|expected| observed.as_str() == Some(expected))
}

fn exact_i64(resource: &CanonicalResource, field: &str, observed: &Value) -> bool {
    resource
        .get_i64(field)
        .is_some_and(|expected| observed.as_i64() == Some(expected))
}

fn mode_matches(resource: &CanonicalResource, value: &Value) -> bool {
    let observed =
        value
            .get("livemode")
            .and_then(Value::as_bool)
            .map(|live| if live { "live" } else { "test" });
    resource.get_str("mode") == observed
}

fn common_object_matches(
    resource: &CanonicalResource,
    value: &Value,
    id_field: &str,
    object_field: &str,
) -> bool {
    exact_str(resource, id_field, &value["id"])
        && exact_str(resource, "currency", &value["currency"])
        && mode_matches(resource, value)
        && value.get("object").and_then(Value::as_str) == Some(object_field)
}

pub(crate) fn evaluate_observation(
    precondition: &'static CompiledPrecondition,
    resource: &CanonicalResource,
    primary: &Value,
    related: Option<&Value>,
) -> Result<(), PreconditionFailureClass> {
    use PreconditionFailureClass as Failure;
    use PreconditionKind as Kind;

    let ok = match precondition.kind {
        Kind::PaymentMethodBelongsToCustomer => {
            primary.get("object").and_then(Value::as_str) == Some("customer")
                && exact_str(resource, "customer", &primary["id"])
                && mode_matches(resource, primary)
                && primary
                    .get("account")
                    .is_none_or(|account| account.as_str() == resource.get_str("account"))
                && related.is_some_and(|method| {
                    method.get("object").and_then(Value::as_str) == Some("payment_method")
                        && exact_str(resource, "payment_method", &method["id"])
                        && exact_str(resource, "customer", &method["customer"])
                        && mode_matches(resource, method)
                        && method
                            .get("account")
                            .is_none_or(|account| account.as_str() == resource.get_str("account"))
                })
        }
        Kind::InvoiceOpen => {
            invoice_safe_shape(primary)
                && common_object_matches(resource, primary, "invoice", "invoice")
                && primary.get("status").and_then(Value::as_str) == Some("open")
                && exact_str(resource, "status", &primary["status"])
                && exact_i64(resource, "amount", &primary["amount_remaining"])
                && exact_str(resource, "customer", &primary["customer"])
                && related.is_some_and(|method| {
                    method.get("object").and_then(Value::as_str) == Some("payment_method")
                        && exact_str(resource, "payment_method", &method["id"])
                        && exact_str(resource, "customer", &method["customer"])
                })
        }
        Kind::PiConfirmable => {
            payment_intent_safe_shape(primary)
                && common_object_matches(resource, primary, "payment_intent", "payment_intent")
                && matches!(
                    primary.get("status").and_then(Value::as_str),
                    Some("requires_payment_method" | "requires_confirmation")
                )
                && exact_str(resource, "status", &primary["status"])
                && exact_i64(resource, "amount", &primary["amount"])
                && exact_str(resource, "customer", &primary["customer"])
                && exact_str(resource, "capture_method", &primary["capture_method"])
                && exact_str(
                    resource,
                    "confirmation_method",
                    &primary["confirmation_method"],
                )
                && related.is_some_and(|method| {
                    method.get("object").and_then(Value::as_str) == Some("payment_method")
                        && exact_str(resource, "payment_method", &method["id"])
                        && exact_str(resource, "customer", &method["customer"])
                })
        }
        Kind::PiCapturable => {
            payment_intent_safe_shape(primary)
                && common_object_matches(resource, primary, "payment_intent", "payment_intent")
                && primary.get("status").and_then(Value::as_str) == Some("requires_capture")
                && exact_str(resource, "status", &primary["status"])
                && exact_str(resource, "customer", &primary["customer"])
                && exact_str(resource, "capture_method", &primary["capture_method"])
                && exact_i64(resource, "intent_amount", &primary["amount"])
                && exact_i64(resource, "amount_capturable", &primary["amount_capturable"])
                && primary.get("capture_method").and_then(Value::as_str) == Some("manual")
                && primary
                    .get("amount_capturable")
                    .and_then(Value::as_i64)
                    .zip(resource.get_i64("amount"))
                    .is_some_and(|(available, amount)| available >= amount)
        }
        Kind::PiCancelable => {
            let observed_amount = match primary.get("status").and_then(Value::as_str) {
                Some("requires_capture") => &primary["amount_capturable"],
                Some(_) => &primary["amount"],
                None => &Value::Null,
            };
            payment_intent_safe_shape(primary)
                && common_object_matches(resource, primary, "payment_intent", "payment_intent")
                && matches!(
                    primary.get("status").and_then(Value::as_str),
                    Some(
                        "requires_payment_method"
                            | "requires_confirmation"
                            | "requires_action"
                            | "processing"
                            | "requires_capture"
                    )
                )
                && exact_str(resource, "status", &primary["status"])
                && exact_str(resource, "customer", &primary["customer"])
                && exact_str(resource, "capture_method", &primary["capture_method"])
                && exact_str(
                    resource,
                    "confirmation_method",
                    &primary["confirmation_method"],
                )
                && exact_i64(resource, "amount", observed_amount)
                && resource.get_i64("amount").is_some_and(|amount| amount > 0)
        }
        Kind::PayoutsEnabled => {
            primary.get("object").and_then(Value::as_str) == Some("account")
                && exact_str(resource, "account", &primary["id"])
                && primary.get("payouts_enabled").and_then(Value::as_bool) == Some(true)
        }
        Kind::BalanceSufficient => {
            let available = primary.get("available").and_then(Value::as_array);
            let currency = resource.get_str("currency");
            let source_type = resource.get_str("source_type");
            let amount = resource.get_i64("amount");
            primary.get("object").and_then(Value::as_str) == Some("balance")
                && mode_matches(resource, primary)
                && available
                    .zip(currency)
                    .zip(source_type)
                    .zip(amount)
                    .is_some_and(|(((balances, currency), source_type), amount)| {
                        let mut matching = balances.iter().filter(|balance| {
                            balance.get("currency").and_then(Value::as_str) == Some(currency)
                        });
                        let Some(balance) = matching.next() else {
                            return false;
                        };
                        matching.next().is_none()
                            && balance.get("amount").and_then(Value::as_i64) >= Some(amount)
                            && balance
                                .get("source_types")
                                .and_then(Value::as_object)
                                .and_then(|types| types.get(source_type))
                                .and_then(Value::as_i64)
                                >= Some(amount)
                    })
        }
        Kind::DestinationBelongsAndCurrencyMatches => {
            primary.get("object").and_then(Value::as_str) == Some("bank_account")
                && matches!(
                    primary.get("status").and_then(Value::as_str),
                    Some("new" | "validated" | "verified")
                )
                && exact_str(resource, "destination", &primary["id"])
                && exact_str(resource, "account", &primary["account"])
                && exact_str(resource, "currency", &primary["currency"])
        }
        Kind::ChargeRefundable => {
            common_object_matches(resource, primary, "charge", "charge")
                && primary.get("paid").and_then(Value::as_bool) == Some(true)
                && primary
                    .get("amount")
                    .and_then(Value::as_i64)
                    .zip(primary.get("amount_refunded").and_then(Value::as_i64))
                    .zip(resource.get_i64("amount"))
                    .is_some_and(|((total, refunded), amount)| {
                        total > 0
                            && refunded >= 0
                            && amount > 0
                            && total
                                .checked_sub(refunded)
                                .is_some_and(|remaining| remaining >= amount)
                    })
                && primary
                    .get("account")
                    .is_none_or(|account| account.as_str() == resource.get_str("account"))
        }
        #[cfg(any(test, feature = "test-double"))]
        Kind::TestChargeReady => {
            common_object_matches(resource, primary, "charge", "charge")
                && primary
                    .get("amount")
                    .and_then(Value::as_i64)
                    .zip(primary.get("amount_refunded").and_then(Value::as_i64))
                    .zip(resource.get_i64("amount"))
                    .is_some_and(|((total, refunded), amount)| total - refunded >= amount)
                && primary
                    .get("account")
                    .is_none_or(|account| account.as_str() == resource.get_str("account"))
        }
    };
    if ok {
        Ok(())
    } else {
        Err(match precondition.kind {
            Kind::BalanceSufficient => Failure::InsufficientBalance,
            Kind::DestinationBelongsAndCurrencyMatches
            | Kind::PaymentMethodBelongsToCustomer
            | Kind::InvoiceOpen
            | Kind::PiConfirmable => Failure::RelationshipMismatch,
            _ => Failure::StateMismatch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{CanonicalResource, Scalar};
    use std::collections::BTreeMap;

    fn resource<const N: usize>(fields: [(&str, Scalar); N]) -> CanonicalResource {
        CanonicalResource::from_map(
            fields
                .into_iter()
                .map(|(name, value)| (name.to_string(), value))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    #[test]
    fn moneypath_safe_shape_rejects_top_level_and_nested_latent_effects() {
        let baseline = serde_json::json!({
            "application_fee_amount": null,
            "transfer_data": null,
            "on_behalf_of": null,
            "setup_future_usage": null,
            "hooks": {},
            "payment_method_options": {
                "card": {
                    "request_three_d_secure": "automatic",
                    "setup_future_usage": null,
                    "unused": {"enabled": false, "value": null, "items": []}
                }
            }
        });
        assert!(payment_intent_safe_shape(&baseline));
        for (effect, changed) in [
            (
                "application fee",
                serde_json::json!({"application_fee_amount": 1}),
            ),
            (
                "hooks",
                serde_json::json!({"hooks": {"inputs": {"foo": "bar"}}}),
            ),
            (
                "mandate",
                serde_json::json!({"payment_method_options": {"card": {"mandate_options": {"reference": "mandate_1"}}}}),
            ),
            (
                "installments",
                serde_json::json!({"payment_method_options": {"card": {"installments": {"plan": {"count": 3}}}}}),
            ),
            (
                "network choice",
                serde_json::json!({"payment_method_options": {"card": {"network": "visa"}}}),
            ),
            (
                "multicapture",
                serde_json::json!({"payment_method_options": {"card": {"multicapture": {"requested": true}}}}),
            ),
            (
                "incremental authorization",
                serde_json::json!({"payment_method_options": {"card": {"request_incremental_authorization": "if_available"}}}),
            ),
            (
                "overcapture",
                serde_json::json!({"payment_method_options": {"card": {"request_overcapture": "if_available"}}}),
            ),
            (
                "future usage",
                serde_json::json!({"payment_method_options": {"card": {"setup_future_usage": "off_session"}}}),
            ),
            (
                "capture override",
                serde_json::json!({"payment_method_options": {"card": {"capture_method": "manual"}}}),
            ),
            (
                "unknown non-inert",
                serde_json::json!({"payment_method_options": {"card": {"future_option": "enabled"}}}),
            ),
        ] {
            let mut candidate = baseline.clone();
            candidate
                .as_object_mut()
                .unwrap()
                .extend(changed.as_object().unwrap().clone());
            assert!(
                !payment_intent_safe_shape(&candidate),
                "PaymentIntent safe shape accepted {effect}: {candidate}"
            );
        }

        let invoice = serde_json::json!({
            "payment_settings": {
                "default_mandate": null,
                "payment_method_options": {
                    "card": {"request_three_d_secure": "automatic"}
                },
                "payment_method_types": []
            }
        });
        assert!(invoice_safe_shape(&invoice));
        for (effect, payment_settings) in [
            (
                "default mandate",
                serde_json::json!({"default_mandate": "mandate_1"}),
            ),
            (
                "method routing",
                serde_json::json!({"payment_method_types": ["card"]}),
            ),
            (
                "method options",
                serde_json::json!({"payment_method_options": {"card": {"network": "visa"}}}),
            ),
            (
                "unknown setting",
                serde_json::json!({"save_default_payment_method": "on_subscription"}),
            ),
        ] {
            let mut candidate = invoice.clone();
            candidate["payment_settings"] = payment_settings;
            assert!(
                !invoice_safe_shape(&candidate),
                "Invoice safe shape accepted {effect}: {candidate}"
            );
        }
    }

    #[test]
    fn moneypath_balance_comparison_uses_only_frozen_values() {
        let frozen = resource([
            ("account", Scalar::Str("acct_1".into())),
            ("amount", Scalar::Int(500)),
            ("currency", Scalar::Str("usd".into())),
            ("mode", Scalar::Str("test".into())),
            ("source_type", Scalar::Str("card".into())),
            ("destination", Scalar::Str("ba_1".into())),
            ("payment_intent", Scalar::Str("pi_1".into())),
            ("customer", Scalar::Str("cus_1".into())),
            ("payment_method", Scalar::Str("pm_1".into())),
        ]);
        let precondition = exact("stripe", "create_standard_payout", "balance_sufficient").unwrap();
        assert!(evaluate_observation(
            precondition,
            &frozen,
            &serde_json::json!({"object":"balance", "livemode":false, "available": [{"currency":"usd", "amount": 500, "source_types":{"card":500}}]}),
            None
        ).is_ok());
        assert!(evaluate_observation(
            precondition,
            &frozen,
            &serde_json::json!({"object":"balance", "livemode":true, "available": [{"currency":"usd", "amount": 500, "source_types":{"card":500}}]}),
            None
        ).is_err());
        assert!(matches!(
            evaluate_observation(
                precondition,
                &frozen,
                &serde_json::json!({"object":"balance", "livemode":false, "available": [{"currency":"usd", "amount": 499, "source_types":{"card":499}}]}),
                None
            ),
            Err(PreconditionFailureClass::InsufficientBalance)
        ));

        for malformed in [
            serde_json::json!({"livemode":false, "available": [{"currency":"usd", "amount":500, "source_types":{"card":500}}]}),
            serde_json::json!({"object":"account", "livemode":false, "available": [{"currency":"usd", "amount":500, "source_types":{"card":500}}]}),
            serde_json::json!({"object":"balance", "livemode":false, "available": []}),
            serde_json::json!({"object":"balance", "livemode":false, "available": [{"currency":"usd", "amount":"500", "source_types":{"card":500}}]}),
            serde_json::json!({"object":"balance", "livemode":false, "available": [{"currency":"usd", "amount":500, "source_types":{"card":"500"}}]}),
            serde_json::json!({"object":"balance", "livemode":false, "available": [{"currency":"usd", "amount":500, "source_types":{}}]}),
            serde_json::json!({"object":"balance", "livemode":false, "available": [
                {"currency":"usd", "amount":500, "source_types":{"card":500}},
                {"currency":"usd", "amount":700, "source_types":{"card":700}}
            ]}),
        ] {
            assert!(
                evaluate_observation(precondition, &frozen, &malformed, None).is_err(),
                "ambiguous or malformed balance observation was accepted: {malformed}"
            );
        }
    }

    #[test]
    fn moneypath_payouts_enabled_uses_account_identity_and_state_not_account_mode() {
        let frozen = resource([
            ("account", Scalar::Str("acct_1".into())),
            ("amount", Scalar::Int(500)),
            ("currency", Scalar::Str("usd".into())),
            ("mode", Scalar::Str("test".into())),
            ("source_type", Scalar::Str("card".into())),
            ("destination", Scalar::Str("ba_1".into())),
        ]);
        let precondition = exact("stripe", "create_standard_payout", "payouts_enabled").unwrap();
        assert!(evaluate_observation(
            precondition,
            &frozen,
            &serde_json::json!({"id":"acct_1", "object":"account", "payouts_enabled":true}),
            None
        )
        .is_ok());
        for mismatched in [
            serde_json::json!({"id":"acct_other", "object":"account", "payouts_enabled":true}),
            serde_json::json!({"id":"acct_1", "object":"account", "payouts_enabled":false}),
            serde_json::json!({"id":"acct_1", "object":"customer", "payouts_enabled":true}),
        ] {
            assert!(evaluate_observation(precondition, &frozen, &mismatched, None).is_err());
        }
    }

    #[test]
    fn moneypath_payment_method_relationship_requires_exact_object_kind() {
        let frozen = resource([
            ("account", Scalar::Str("acct_1".into())),
            ("amount", Scalar::Int(500)),
            ("currency", Scalar::Str("usd".into())),
            ("mode", Scalar::Str("test".into())),
            ("invoice", Scalar::Str("in_1".into())),
            ("customer", Scalar::Str("cus_1".into())),
            ("payment_method", Scalar::Str("pm_1".into())),
            ("status", Scalar::Str("open".into())),
        ]);
        let precondition = exact("stripe", "retry_invoice_payment", "invoice_open").unwrap();
        let invoice = serde_json::json!({
            "id":"in_1", "object":"invoice", "currency":"usd", "livemode":false,
            "status":"open", "amount_remaining":500, "customer":"cus_1",
            "on_behalf_of":null, "transfer_data":null,
            "payment_settings": {
                "default_mandate": null,
                "payment_method_options": {"card": {"request_three_d_secure":"automatic"}},
                "payment_method_types": []
            }
        });
        for method in [
            serde_json::json!({"id":"pm_1", "customer":"cus_1"}),
            serde_json::json!({"id":"pm_1", "object":"customer", "customer":"cus_1"}),
        ] {
            assert!(
                evaluate_observation(precondition, &frozen, &invoice, Some(&method)).is_err(),
                "non-PaymentMethod relationship evidence was accepted: {method}"
            );
        }
        assert!(evaluate_observation(
            precondition,
            &frozen,
            &invoice,
            Some(&serde_json::json!({
                "id":"pm_1", "object":"payment_method", "customer":"cus_1"
            }))
        )
        .is_ok());
        let mut routed_invoice = invoice.clone();
        routed_invoice["payment_settings"]["payment_method_types"] = serde_json::json!(["card"]);
        assert!(evaluate_observation(
            precondition,
            &frozen,
            &routed_invoice,
            Some(&serde_json::json!({
                "id":"pm_1", "object":"payment_method", "customer":"cus_1"
            }))
        )
        .is_err());
    }

    #[test]
    fn moneypath_money_actions_require_their_complete_compiled_precondition_set() {
        let all = vec![
            "payouts_enabled".to_string(),
            "balance_sufficient".to_string(),
            "destination_belongs_and_currency_matches".to_string(),
        ];
        assert!(resolve_exact("stripe", "create_standard_payout", &all).is_some());
        assert!(resolve_exact(
            "stripe",
            "create_standard_payout",
            &["payouts_enabled".to_string()]
        )
        .is_none());
        assert!(resolve_exact(
            "stripe",
            "create_standard_payout",
            &[
                "payouts_enabled".to_string(),
                "payouts_enabled".to_string(),
                "destination_belongs_and_currency_matches".to_string(),
            ]
        )
        .is_none());

        for (action, names) in [
            (
                "create_payment_intent_off_session",
                vec!["payment_method_belongs_to_customer".to_string()],
            ),
            ("confirm_payment_intent", vec!["pi_confirmable".to_string()]),
            ("capture_payment_intent", vec!["pi_capturable".to_string()]),
            ("cancel_payment_intent", vec!["pi_cancelable".to_string()]),
            ("retry_invoice_payment", vec!["invoice_open".to_string()]),
            (
                "refund_charge_bounded",
                vec!["charge_refundable".to_string()],
            ),
        ] {
            assert!(
                resolve_exact("stripe", action, &names).is_some(),
                "stripe.{action} lacks its exact complete precondition set"
            );
        }
    }

    #[test]
    fn moneypath_create_and_refund_preconditions_recheck_exact_relationships_and_bounds() {
        let create_resource = resource([
            ("account", Scalar::Str("acct_1".into())),
            ("amount", Scalar::Int(500)),
            ("currency", Scalar::Str("usd".into())),
            ("mode", Scalar::Str("test".into())),
            ("customer", Scalar::Str("cus_1".into())),
            ("payment_method", Scalar::Str("pm_1".into())),
        ]);
        let create = exact(
            "stripe",
            "create_payment_intent_off_session",
            "payment_method_belongs_to_customer",
        )
        .unwrap();
        let customer = serde_json::json!({
            "id":"cus_1", "object":"customer", "livemode":false
        });
        let method = serde_json::json!({
            "id":"pm_1", "object":"payment_method", "customer":"cus_1", "livemode":false
        });
        assert!(evaluate_observation(create, &create_resource, &customer, Some(&method)).is_ok());
        for mismatched in [
            serde_json::json!({"id":"pm_1", "object":"payment_method", "customer":"cus_other", "livemode":false}),
            serde_json::json!({"id":"pm_1", "object":"payment_method", "customer":"cus_1", "livemode":true}),
            serde_json::json!({"id":"pm_1", "object":"customer", "customer":"cus_1", "livemode":false}),
        ] {
            assert!(
                evaluate_observation(create, &create_resource, &customer, Some(&mismatched))
                    .is_err()
            );
        }

        let refund_resource = resource([
            ("account", Scalar::Str("acct_1".into())),
            ("amount", Scalar::Int(500)),
            ("currency", Scalar::Str("usd".into())),
            ("mode", Scalar::Str("test".into())),
            ("charge", Scalar::Str("ch_1".into())),
        ]);
        let refundable = exact("stripe", "refund_charge_bounded", "charge_refundable").unwrap();
        let charge = serde_json::json!({
            "id":"ch_1", "object":"charge", "account":"acct_1", "currency":"usd",
            "livemode":false, "paid":true, "amount":1000, "amount_refunded":500
        });
        assert!(evaluate_observation(refundable, &refund_resource, &charge, None).is_ok());
        for mismatched in [
            serde_json::json!({"id":"ch_1", "object":"charge", "account":"acct_1", "currency":"usd", "livemode":false, "paid":true, "amount":1000, "amount_refunded":501}),
            serde_json::json!({"id":"ch_1", "object":"charge", "account":"acct_1", "currency":"usd", "livemode":false, "paid":false, "amount":1000, "amount_refunded":0}),
            serde_json::json!({"id":"ch_1", "object":"refund", "account":"acct_1", "currency":"usd", "livemode":false, "paid":true, "amount":1000, "amount_refunded":0}),
        ] {
            assert!(evaluate_observation(refundable, &refund_resource, &mismatched, None).is_err());
        }
    }

    #[test]
    fn moneypath_precondition_fingerprint_binds_observation_and_evaluation_code() {
        use sha2::{Digest, Sha256};

        let mut hash = Sha256::new();
        hash.update(PRECONDITION_FINGERPRINT_DOMAIN);
        for field in ["stripe", "capture_payment_intent", "pi_capturable"] {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
        hash.update(include_bytes!("preconditions.rs"));
        hash.update(include_bytes!("provider/stripe_preconditions.rs"));
        hash.update(include_bytes!("mutation_success.rs"));
        hash.update(include_bytes!("stripe_inert.rs"));
        hash.update(include_bytes!("provider_json.rs"));
        assert_eq!(
            semantics_fingerprint(
                "stripe",
                "capture_payment_intent",
                &["pi_capturable".to_string()]
            ),
            Some(format!("sha256:{}", crate::util::hex(&hash.finalize())))
        );
    }

    #[test]
    fn moneypath_payment_intent_and_destination_unknown_or_changed_state_denies() {
        let capture = exact("stripe", "capture_payment_intent", "pi_capturable").unwrap();
        let capture_resource = resource([
            ("account", Scalar::Str("acct_1".into())),
            ("amount", Scalar::Int(500)),
            ("currency", Scalar::Str("usd".into())),
            ("mode", Scalar::Str("test".into())),
            ("payment_intent", Scalar::Str("pi_1".into())),
            ("customer", Scalar::Str("cus_1".into())),
            ("capture_method", Scalar::Str("manual".into())),
            ("confirmation_method", Scalar::Str("automatic".into())),
            ("status", Scalar::Str("requires_capture".into())),
            ("intent_amount", Scalar::Int(900)),
            ("amount_capturable", Scalar::Int(500)),
        ]);
        let changed_customer = serde_json::json!({
            "id":"pi_1", "object":"payment_intent", "currency":"usd", "livemode":false,
            "status":"requires_capture", "amount":900, "amount_capturable":500, "customer":"cus_other",
            "capture_method":"manual", "confirmation_method":"automatic"
        });
        assert!(evaluate_observation(capture, &capture_resource, &changed_customer, None).is_err());
        let changed_capturable = serde_json::json!({
            "id":"pi_1", "object":"payment_intent", "currency":"usd", "livemode":false,
            "status":"requires_capture", "amount":900, "amount_capturable":501,
            "customer":"cus_1", "capture_method":"manual", "confirmation_method":"automatic"
        });
        assert!(
            evaluate_observation(capture, &capture_resource, &changed_capturable, None).is_err()
        );
        let changed_intent_amount = serde_json::json!({
            "id":"pi_1", "object":"payment_intent", "currency":"usd", "livemode":false,
            "status":"requires_capture", "amount":901, "amount_capturable":500,
            "customer":"cus_1", "capture_method":"manual", "confirmation_method":"automatic"
        });
        assert!(
            evaluate_observation(capture, &capture_resource, &changed_intent_amount, None).is_err()
        );

        let cancel = exact("stripe", "cancel_payment_intent", "pi_cancelable").unwrap();
        let changed_cancelable_state = serde_json::json!({
            "id":"pi_1", "object":"payment_intent", "currency":"usd", "livemode":false,
            "status":"requires_confirmation", "customer":"cus_1", "capture_method":"manual",
            "confirmation_method":"automatic"
        });
        assert!(
            evaluate_observation(cancel, &capture_resource, &changed_cancelable_state, None)
                .is_err()
        );
        let changed_cancel_amount = serde_json::json!({
            "id":"pi_1", "object":"payment_intent", "currency":"usd", "livemode":false,
            "status":"requires_capture", "amount":900, "amount_capturable":499,
            "customer":"cus_1", "capture_method":"manual", "confirmation_method":"automatic"
        });
        assert!(
            evaluate_observation(cancel, &capture_resource, &changed_cancel_amount, None).is_err()
        );

        let destination = exact(
            "stripe",
            "create_standard_payout",
            "destination_belongs_and_currency_matches",
        )
        .unwrap();
        let payout_resource = resource([
            ("account", Scalar::Str("acct_1".into())),
            ("amount", Scalar::Int(500)),
            ("currency", Scalar::Str("usd".into())),
            ("mode", Scalar::Str("test".into())),
            ("source_type", Scalar::Str("card".into())),
            ("destination", Scalar::Str("ba_1".into())),
            ("payment_intent", Scalar::Str("pi_1".into())),
            ("customer", Scalar::Str("cus_1".into())),
            ("payment_method", Scalar::Str("pm_1".into())),
        ]);
        assert!(evaluate_observation(
            destination,
            &payout_resource,
            &serde_json::json!({
                "id":"ba_1", "object":"bank_account", "account":"acct_1", "currency":"usd"
            }),
            None
        )
        .is_err());
    }
}
