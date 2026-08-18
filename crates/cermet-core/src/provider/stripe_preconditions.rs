//! Fixed Stripe reads for compiled money preconditions.

use reqwest::Method;
use serde_json::Value;

use super::{http_call_with_encoding, validate_path_segment, GenericProvider};
use crate::contract::CanonicalResource;
use crate::preconditions::{
    evaluate_observation, CompiledPrecondition, PreconditionFailure, PreconditionFailureClass,
    PreconditionKind,
};
use crate::templates::BodyEncoding;

const SUCCESS: &[u16] = &[200];

fn get(
    provider: &GenericProvider,
    token: &str,
    path: &str,
    name: &'static str,
) -> Result<Value, PreconditionFailure> {
    let response = http_call_with_encoding(
        &provider.egress,
        Method::GET,
        format!("{}{path}", provider.base),
        token,
        None,
        &[],
        &provider.auth,
        &provider.header_refs(),
        BodyEncoding::Json,
        SUCCESS,
    )
    .map_err(|_| PreconditionFailure::new(name, PreconditionFailureClass::ProviderUnavailable))?;
    if response.ok {
        Ok(response.result)
    } else {
        Err(PreconditionFailure::new(
            name,
            match response.result.get("status").and_then(Value::as_u64) {
                Some(404) => PreconditionFailureClass::Stale,
                Some(401 | 403 | 429 | 500..=599) | None => {
                    PreconditionFailureClass::ProviderUnavailable
                }
                Some(_) => PreconditionFailureClass::Malformed,
            },
        ))
    }
}

fn id<'a>(
    resource: &'a CanonicalResource,
    field: &str,
    name: &'static str,
) -> Result<&'a str, PreconditionFailure> {
    let value = resource
        .req_str(field)
        .map_err(|_| PreconditionFailure::new(name, PreconditionFailureClass::Malformed))?;
    validate_path_segment(field, value)
        .map_err(|_| PreconditionFailure::new(name, PreconditionFailureClass::Malformed))?;
    Ok(value)
}

pub(super) fn check(
    provider: &GenericProvider,
    preconditions: &[&'static CompiledPrecondition],
    token: &str,
    resource: &CanonicalResource,
) -> Result<(), PreconditionFailure> {
    for precondition in preconditions {
        let name = precondition.name;
        let (path, related_path) = match precondition.kind {
            PreconditionKind::PaymentMethodBelongsToCustomer => (
                format!("/v1/customers/{}", id(resource, "customer", name)?),
                Some(format!(
                    "/v1/payment_methods/{}",
                    id(resource, "payment_method", name)?
                )),
            ),
            PreconditionKind::InvoiceOpen => (
                format!("/v1/invoices/{}", id(resource, "invoice", name)?),
                Some(format!(
                    "/v1/payment_methods/{}",
                    id(resource, "payment_method", name)?
                )),
            ),
            PreconditionKind::PiConfirmable => (
                format!(
                    "/v1/payment_intents/{}",
                    id(resource, "payment_intent", name)?
                ),
                Some(format!(
                    "/v1/payment_methods/{}",
                    id(resource, "payment_method", name)?
                )),
            ),
            PreconditionKind::PiCapturable | PreconditionKind::PiCancelable => (
                format!(
                    "/v1/payment_intents/{}",
                    id(resource, "payment_intent", name)?
                ),
                None,
            ),
            PreconditionKind::PayoutsEnabled => ("/v1/account".to_string(), None),
            PreconditionKind::BalanceSufficient => ("/v1/balance".to_string(), None),
            PreconditionKind::DestinationBelongsAndCurrencyMatches => (
                format!(
                    "/v1/accounts/{}/external_accounts/{}",
                    id(resource, "account", name)?,
                    id(resource, "destination", name)?
                ),
                None,
            ),
            PreconditionKind::ChargeRefundable => (
                format!("/v1/charges/{}", id(resource, "charge", name)?),
                None,
            ),
            #[cfg(any(test, feature = "test-double"))]
            PreconditionKind::TestChargeReady => (
                format!("/v1/charges/{}", id(resource, "charge", name)?),
                None,
            ),
        };
        let primary = get(provider, token, &path, name)?;
        let related = match related_path {
            Some(path) => Some(get(provider, token, &path, name)?),
            None => None,
        };
        evaluate_observation(precondition, resource, &primary, related.as_ref())
            .map_err(|class| PreconditionFailure::new(name, class))?;
    }
    Ok(())
}
