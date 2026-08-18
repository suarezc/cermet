//! Narrow compiled Stripe request-evidence resolvers.

use std::collections::BTreeMap;

use reqwest::Method;
use serde_json::Value;

use super::{http_call_with_encoding, validate_path_segment, GenericProvider, ProviderResponse};
use crate::contract::{CanonicalResource, Scalar};
use crate::evidence::{
    EvidenceFailure, EvidenceFailureClass, EvidenceResolverKind, EvidenceSource, ResolvedEvidence,
    STRIPE_EVIDENCE_ACCOUNT_ID_MAX_BYTES, STRIPE_EVIDENCE_ACCOUNT_ID_PREFIX,
    STRIPE_EVIDENCE_ACCOUNT_OBJECT, STRIPE_EVIDENCE_ACCOUNT_PATH, STRIPE_EVIDENCE_BALANCE_PATH,
    STRIPE_EVIDENCE_CHARGE_OBJECT, STRIPE_EVIDENCE_CHARGE_PATH_PREFIX,
    STRIPE_EVIDENCE_CURRENCY_BYTES, STRIPE_EVIDENCE_CUSTOMER_PATH_PREFIX,
    STRIPE_EVIDENCE_EXTERNAL_ACCOUNT_PATH_PREFIX, STRIPE_EVIDENCE_INVOICE_PATH_PREFIX,
    STRIPE_EVIDENCE_PAYMENT_INTENT_PATH_PREFIX, STRIPE_EVIDENCE_PAYMENT_METHOD_PATH_PREFIX,
    STRIPE_EVIDENCE_SUCCESS_STATUSES,
};
use crate::templates::BodyEncoding;

/// The exact compiled source unit whose bytes bind surviving evidence to this implementation.
pub(crate) const IMPLEMENTATION_SOURCE: &[u8] = include_bytes!("stripe_evidence.rs");

pub(super) fn resolve(
    provider: &GenericProvider,
    resolver: EvidenceResolverKind,
    token: &str,
    partial: &CanonicalResource,
) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
    match resolver {
        EvidenceResolverKind::StripeCreatePaymentIntentOffSession => {
            resolve_create_payment_intent(provider, token, partial)
        }
        EvidenceResolverKind::StripeConfirmPaymentIntent => {
            resolve_confirm_payment_intent(provider, token, partial)
        }
        EvidenceResolverKind::StripeCapturePaymentIntent => {
            resolve_capture_payment_intent(provider, token, partial)
        }
        EvidenceResolverKind::StripeCancelPaymentIntent => {
            resolve_cancel_payment_intent(provider, token, partial)
        }
        EvidenceResolverKind::StripeRetryInvoicePayment => {
            resolve_retry_invoice_payment(provider, token, partial)
        }
        EvidenceResolverKind::StripeRefundChargeBounded => {
            resolve_refund_charge(provider, token, partial)
        }
        EvidenceResolverKind::StripeCreateStandardPayout => {
            resolve_create_standard_payout(provider, token, partial)
        }
        #[cfg(any(test, feature = "test-double"))]
        EvidenceResolverKind::StripeTestCharge => resolve_test_charge(provider, token, partial),
    }
}

fn get(
    provider: &GenericProvider,
    token: &str,
    path: &str,
) -> std::result::Result<Value, EvidenceFailure> {
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
        STRIPE_EVIDENCE_SUCCESS_STATUSES,
    )
    .map_err(|_| EvidenceFailure::new(EvidenceFailureClass::ProviderUnavailable))?;
    response_body(response)
}

fn response_body(response: ProviderResponse) -> std::result::Result<Value, EvidenceFailure> {
    if response.ok {
        return Ok(response.result);
    }
    let status = response
        .result
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok());
    let class = match status {
        Some(401) => EvidenceFailureClass::ProviderAuthentication,
        Some(403) => EvidenceFailureClass::ProviderDenied,
        Some(404) => EvidenceFailureClass::ProviderNotFound,
        Some(429) => EvidenceFailureClass::RateLimited,
        Some(500..=599) | None => EvidenceFailureClass::ProviderUnavailable,
        Some(_) => EvidenceFailureClass::Malformed,
    };
    Err(match status {
        Some(status) => EvidenceFailure::status(class, status),
        None => EvidenceFailure::new(class),
    })
}

fn input_id<'a>(
    partial: &'a CanonicalResource,
    field: &str,
) -> std::result::Result<&'a str, EvidenceFailure> {
    let value = partial
        .req_str(field)
        .map_err(|_| EvidenceFailure::new(EvidenceFailureClass::Malformed))?;
    validate_path_segment(field, value)
        .map_err(|_| EvidenceFailure::new(EvidenceFailureClass::Malformed))?;
    Ok(value)
}

fn positive_input_amount(partial: &CanonicalResource) -> std::result::Result<i64, EvidenceFailure> {
    partial
        .req_i64("amount")
        .ok()
        .filter(|amount| *amount > 0)
        .ok_or_else(|| EvidenceFailure::new(EvidenceFailureClass::Malformed))
}

fn exact_object_id(
    value: &Value,
    object: &str,
    expected_id: &str,
) -> std::result::Result<(), EvidenceFailure> {
    if value.get("object").and_then(Value::as_str) != Some(object) {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
    }
    let observed = required_str(value, "id")?;
    if observed != expected_id {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    Ok(())
}

fn required_str<'a>(
    value: &'a Value,
    field: &str,
) -> std::result::Result<&'a str, EvidenceFailure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|string| !string.is_empty() && string.len() <= 256 * 1024)
        .ok_or_else(|| EvidenceFailure::new(EvidenceFailureClass::Malformed))
}

fn required_i64(value: &Value, field: &str) -> std::result::Result<i64, EvidenceFailure> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| EvidenceFailure::new(EvidenceFailureClass::Malformed))
}

fn mode(value: &Value) -> std::result::Result<&'static str, EvidenceFailure> {
    value
        .get("livemode")
        .and_then(Value::as_bool)
        .map(|live| if live { "live" } else { "test" })
        .ok_or_else(|| EvidenceFailure::new(EvidenceFailureClass::Malformed))
}

fn currency<'a>(value: &'a Value, field: &str) -> std::result::Result<&'a str, EvidenceFailure> {
    let currency = required_str(value, field)?;
    if currency.len() == STRIPE_EVIDENCE_CURRENCY_BYTES
        && currency.bytes().all(|byte| byte.is_ascii_lowercase())
    {
        Ok(currency)
    } else {
        Err(EvidenceFailure::new(EvidenceFailureClass::Malformed))
    }
}

fn account(
    provider: &GenericProvider,
    token: &str,
) -> std::result::Result<(String, Value), EvidenceFailure> {
    let body = get(provider, token, STRIPE_EVIDENCE_ACCOUNT_PATH)?;
    if body.get("object").and_then(Value::as_str) != Some(STRIPE_EVIDENCE_ACCOUNT_OBJECT) {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
    }
    let id = required_str(&body, "id")?;
    if !id.starts_with(STRIPE_EVIDENCE_ACCOUNT_ID_PREFIX)
        || id.len() > STRIPE_EVIDENCE_ACCOUNT_ID_MAX_BYTES
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
    }
    Ok((id.to_string(), body))
}

fn optional_account_matches(value: &Value, account: &str) -> bool {
    match value.get("account") {
        None | Some(Value::Null) => true,
        Some(Value::String(observed)) => observed == account,
        Some(_) => false,
    }
}

fn same_mode(left: &Value, right: &Value) -> std::result::Result<&'static str, EvidenceFailure> {
    let observed_mode = mode(left)?;
    if mode(right)? != observed_mode {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    Ok(observed_mode)
}

fn fields(entries: &[(&str, Scalar)]) -> BTreeMap<String, Scalar> {
    entries
        .iter()
        .map(|(field, value)| ((*field).to_string(), value.clone()))
        .collect()
}

fn source(kind: &str, id: &str) -> EvidenceSource {
    EvidenceSource {
        kind: kind.to_string(),
        id: id.to_string(),
    }
}

fn resolve_create_payment_intent(
    provider: &GenericProvider,
    token: &str,
    partial: &CanonicalResource,
) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
    positive_input_amount(partial)?;
    let customer_id = input_id(partial, "customer")?;
    let method_id = input_id(partial, "payment_method")?;
    let (account, account_body) = account(provider, token)?;
    let customer = get(
        provider,
        token,
        &format!("{STRIPE_EVIDENCE_CUSTOMER_PATH_PREFIX}{customer_id}"),
    )?;
    exact_object_id(&customer, "customer", customer_id)?;
    let method = get(
        provider,
        token,
        &format!("{STRIPE_EVIDENCE_PAYMENT_METHOD_PATH_PREFIX}{method_id}"),
    )?;
    exact_object_id(&method, "payment_method", method_id)?;
    let observed_mode = same_mode(&customer, &method)?;
    if !optional_account_matches(&customer, &account)
        || !optional_account_matches(&method, &account)
        || required_str(&method, "customer")? != customer_id
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let currency = currency(&account_body, "default_currency")?;
    Ok(ResolvedEvidence {
        fields: fields(&[
            ("account", Scalar::Str(account)),
            ("mode", Scalar::Str(observed_mode.to_string())),
            ("currency", Scalar::Str(currency.to_string())),
        ]),
        sources: vec![
            source("stripe.customer", customer_id),
            source("stripe.payment_method", method_id),
        ],
    })
}

fn resolve_confirm_payment_intent(
    provider: &GenericProvider,
    token: &str,
    partial: &CanonicalResource,
) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
    let intent_id = input_id(partial, "payment_intent")?;
    let method_id = input_id(partial, "payment_method")?;
    let (account, _) = account(provider, token)?;
    let intent = get(
        provider,
        token,
        &format!("{STRIPE_EVIDENCE_PAYMENT_INTENT_PATH_PREFIX}{intent_id}"),
    )?;
    exact_object_id(&intent, "payment_intent", intent_id)?;
    if !crate::stripe_inert::payment_intent_safe_shape(&intent)
        || !optional_account_matches(&intent, &account)
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let status = required_str(&intent, "status")?;
    if !matches!(status, "requires_payment_method" | "requires_confirmation") {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let amount = required_i64(&intent, "amount")?;
    if amount <= 0 {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let customer = required_str(&intent, "customer")?;
    match intent.get("payment_method") {
        None | Some(Value::Null) => {}
        Some(Value::String(current)) if current == method_id => {}
        Some(Value::String(_)) => {
            return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
        }
        Some(_) => return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed)),
    }
    let method = get(
        provider,
        token,
        &format!("{STRIPE_EVIDENCE_PAYMENT_METHOD_PATH_PREFIX}{method_id}"),
    )?;
    exact_object_id(&method, "payment_method", method_id)?;
    let observed_mode = same_mode(&intent, &method)?;
    if !optional_account_matches(&method, &account)
        || required_str(&method, "customer")? != customer
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let currency = currency(&intent, "currency")?;
    let capture_method = required_str(&intent, "capture_method")?;
    if !matches!(capture_method, "automatic" | "automatic_async" | "manual") {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let confirmation_method = required_str(&intent, "confirmation_method")?;
    if !matches!(confirmation_method, "automatic" | "manual") {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    Ok(ResolvedEvidence {
        fields: fields(&[
            ("account", Scalar::Str(account)),
            ("mode", Scalar::Str(observed_mode.to_string())),
            ("currency", Scalar::Str(currency.to_string())),
            ("customer", Scalar::Str(customer.to_string())),
            ("amount", Scalar::Int(amount)),
            ("status", Scalar::Str(status.to_string())),
            ("capture_method", Scalar::Str(capture_method.to_string())),
            (
                "confirmation_method",
                Scalar::Str(confirmation_method.to_string()),
            ),
        ]),
        sources: vec![
            source("stripe.payment_intent", intent_id),
            source("stripe.payment_method", method_id),
        ],
    })
}

fn resolve_capture_payment_intent(
    provider: &GenericProvider,
    token: &str,
    partial: &CanonicalResource,
) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
    let requested_amount = positive_input_amount(partial)?;
    let intent_id = input_id(partial, "payment_intent")?;
    let (account, _) = account(provider, token)?;
    let intent = get(
        provider,
        token,
        &format!("{STRIPE_EVIDENCE_PAYMENT_INTENT_PATH_PREFIX}{intent_id}"),
    )?;
    exact_object_id(&intent, "payment_intent", intent_id)?;
    if !crate::stripe_inert::payment_intent_safe_shape(&intent)
        || !optional_account_matches(&intent, &account)
        || required_str(&intent, "status")? != "requires_capture"
        || required_str(&intent, "capture_method")? != "manual"
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let intent_amount = required_i64(&intent, "amount")?;
    let capturable = required_i64(&intent, "amount_capturable")?;
    if intent_amount <= 0 || capturable <= 0 || requested_amount > capturable {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let currency = currency(&intent, "currency")?;
    let customer = required_str(&intent, "customer")?;
    let observed_mode = mode(&intent)?;
    Ok(ResolvedEvidence {
        fields: fields(&[
            ("account", Scalar::Str(account)),
            ("mode", Scalar::Str(observed_mode.to_string())),
            ("currency", Scalar::Str(currency.to_string())),
            ("customer", Scalar::Str(customer.to_string())),
            ("status", Scalar::Str("requires_capture".to_string())),
            ("capture_method", Scalar::Str("manual".to_string())),
            ("intent_amount", Scalar::Int(intent_amount)),
            ("amount_capturable", Scalar::Int(capturable)),
        ]),
        sources: vec![source("stripe.payment_intent", intent_id)],
    })
}

fn resolve_cancel_payment_intent(
    provider: &GenericProvider,
    token: &str,
    partial: &CanonicalResource,
) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
    let intent_id = input_id(partial, "payment_intent")?;
    let (account, _) = account(provider, token)?;
    let intent = get(
        provider,
        token,
        &format!("{STRIPE_EVIDENCE_PAYMENT_INTENT_PATH_PREFIX}{intent_id}"),
    )?;
    exact_object_id(&intent, "payment_intent", intent_id)?;
    if !crate::stripe_inert::payment_intent_safe_shape(&intent)
        || !optional_account_matches(&intent, &account)
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let status = required_str(&intent, "status")?;
    if !matches!(
        status,
        "requires_payment_method"
            | "requires_confirmation"
            | "requires_action"
            | "processing"
            | "requires_capture"
    ) {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let amount = if status == "requires_capture" {
        required_i64(&intent, "amount_capturable")?
    } else {
        required_i64(&intent, "amount")?
    };
    if amount <= 0 {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let currency = currency(&intent, "currency")?;
    let customer = required_str(&intent, "customer")?;
    let capture_method = required_str(&intent, "capture_method")?;
    let confirmation_method = required_str(&intent, "confirmation_method")?;
    let observed_mode = mode(&intent)?;
    Ok(ResolvedEvidence {
        fields: fields(&[
            ("account", Scalar::Str(account)),
            ("mode", Scalar::Str(observed_mode.to_string())),
            ("currency", Scalar::Str(currency.to_string())),
            ("customer", Scalar::Str(customer.to_string())),
            ("amount", Scalar::Int(amount)),
            ("status", Scalar::Str(status.to_string())),
            ("capture_method", Scalar::Str(capture_method.to_string())),
            (
                "confirmation_method",
                Scalar::Str(confirmation_method.to_string()),
            ),
        ]),
        sources: vec![source("stripe.payment_intent", intent_id)],
    })
}

fn resolve_retry_invoice_payment(
    provider: &GenericProvider,
    token: &str,
    partial: &CanonicalResource,
) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
    let invoice_id = input_id(partial, "invoice")?;
    let method_id = input_id(partial, "payment_method")?;
    let (account, _) = account(provider, token)?;
    let invoice = get(
        provider,
        token,
        &format!("{STRIPE_EVIDENCE_INVOICE_PATH_PREFIX}{invoice_id}"),
    )?;
    exact_object_id(&invoice, "invoice", invoice_id)?;
    if !crate::stripe_inert::invoice_safe_shape(&invoice)
        || !optional_account_matches(&invoice, &account)
        || required_str(&invoice, "status")? != "open"
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let amount = required_i64(&invoice, "amount_remaining")?;
    if amount <= 0 {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let customer = required_str(&invoice, "customer")?;
    let method = get(
        provider,
        token,
        &format!("{STRIPE_EVIDENCE_PAYMENT_METHOD_PATH_PREFIX}{method_id}"),
    )?;
    exact_object_id(&method, "payment_method", method_id)?;
    let observed_mode = same_mode(&invoice, &method)?;
    if !optional_account_matches(&method, &account)
        || required_str(&method, "customer")? != customer
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let currency = currency(&invoice, "currency")?;
    Ok(ResolvedEvidence {
        fields: fields(&[
            ("account", Scalar::Str(account)),
            ("mode", Scalar::Str(observed_mode.to_string())),
            ("currency", Scalar::Str(currency.to_string())),
            ("customer", Scalar::Str(customer.to_string())),
            ("amount", Scalar::Int(amount)),
            ("status", Scalar::Str("open".to_string())),
        ]),
        sources: vec![
            source("stripe.invoice", invoice_id),
            source("stripe.payment_method", method_id),
        ],
    })
}

fn resolve_refund_charge(
    provider: &GenericProvider,
    token: &str,
    partial: &CanonicalResource,
) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
    let requested_amount = positive_input_amount(partial)?;
    let charge_id = input_id(partial, "charge")?;
    let (account, _) = account(provider, token)?;
    let charge = get(
        provider,
        token,
        &format!("{STRIPE_EVIDENCE_CHARGE_PATH_PREFIX}{charge_id}"),
    )?;
    exact_object_id(&charge, STRIPE_EVIDENCE_CHARGE_OBJECT, charge_id)?;
    if !optional_account_matches(&charge, &account)
        || charge.get("paid").and_then(Value::as_bool) != Some(true)
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let total = required_i64(&charge, "amount")?;
    let refunded = required_i64(&charge, "amount_refunded")?;
    let remaining = total.checked_sub(refunded);
    if total <= 0
        || refunded < 0
        || !matches!(remaining, Some(remaining) if remaining >= requested_amount)
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let currency = currency(&charge, "currency")?;
    let observed_mode = mode(&charge)?;
    Ok(ResolvedEvidence {
        fields: fields(&[
            ("account", Scalar::Str(account)),
            ("mode", Scalar::Str(observed_mode.to_string())),
            ("currency", Scalar::Str(currency.to_string())),
        ]),
        sources: vec![source("stripe.charge", charge_id)],
    })
}

fn resolve_create_standard_payout(
    provider: &GenericProvider,
    token: &str,
    partial: &CanonicalResource,
) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
    let amount = positive_input_amount(partial)?;
    let destination = input_id(partial, "destination")?;
    let source_type = input_id(partial, "source_type")?;
    if !source_type
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
    }
    let (account, account_body) = account(provider, token)?;
    if account_body.get("payouts_enabled").and_then(Value::as_bool) != Some(true) {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let balance = get(provider, token, STRIPE_EVIDENCE_BALANCE_PATH)?;
    if balance.get("object").and_then(Value::as_str) != Some("balance") {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
    }
    let observed_mode = mode(&balance)?;
    let destination_body = get(
        provider,
        token,
        &format!(
            "{STRIPE_EVIDENCE_EXTERNAL_ACCOUNT_PATH_PREFIX}{account}/external_accounts/{destination}"
        ),
    )?;
    exact_object_id(&destination_body, "bank_account", destination)?;
    if required_str(&destination_body, "account")? != account
        || !matches!(
            required_str(&destination_body, "status")?,
            "new" | "validated" | "verified"
        )
    {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let currency = currency(&destination_body, "currency")?;
    let available = balance
        .get("available")
        .and_then(Value::as_array)
        .ok_or_else(|| EvidenceFailure::new(EvidenceFailureClass::Malformed))?;
    let matches = available
        .iter()
        .filter(|entry| entry.get("currency").and_then(Value::as_str) == Some(currency))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(EvidenceFailure::new(if matches.is_empty() {
            EvidenceFailureClass::Mismatch
        } else {
            EvidenceFailureClass::Ambiguous
        }));
    }
    let entry = matches[0];
    let total = required_i64(entry, "amount")?;
    let source_amount = entry
        .get("source_types")
        .and_then(Value::as_object)
        .and_then(|types| types.get(source_type))
        .and_then(Value::as_i64)
        .ok_or_else(|| EvidenceFailure::new(EvidenceFailureClass::Malformed))?;
    if total < amount || source_amount < amount {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    Ok(ResolvedEvidence {
        fields: fields(&[
            ("account", Scalar::Str(account)),
            ("mode", Scalar::Str(observed_mode.to_string())),
            ("currency", Scalar::Str(currency.to_string())),
        ]),
        sources: vec![source("stripe.external_account", destination)],
    })
}

#[cfg(any(test, feature = "test-double"))]
fn resolve_test_charge(
    provider: &GenericProvider,
    token: &str,
    partial: &CanonicalResource,
) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
    let charge_id = input_id(partial, "charge")?;
    let (account, _) = account(provider, token)?;
    let charge = get(
        provider,
        token,
        &format!("{STRIPE_EVIDENCE_CHARGE_PATH_PREFIX}{charge_id}"),
    )?;
    exact_object_id(&charge, STRIPE_EVIDENCE_CHARGE_OBJECT, charge_id)?;
    if !optional_account_matches(&charge, &account) {
        return Err(EvidenceFailure::new(EvidenceFailureClass::Mismatch));
    }
    let currency = currency(&charge, "currency")?;
    let observed_mode = mode(&charge)?;
    Ok(ResolvedEvidence {
        fields: fields(&[
            ("account", Scalar::Str(account)),
            ("currency", Scalar::Str(currency.to_string())),
            ("mode", Scalar::Str(observed_mode.to_string())),
        ]),
        sources: vec![source("stripe.charge", charge_id)],
    })
}
