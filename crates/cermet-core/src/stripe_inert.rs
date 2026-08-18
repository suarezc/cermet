//! Strict inert-shape checks for Stripe objects that can carry latent payment effects.

use serde_json::Value;

pub(crate) const IMPLEMENTATION_SOURCE: &[u8] = include_bytes!("stripe_inert.rs");

fn absent_or_null(value: &Value, field: &str) -> bool {
    value.get(field).map_or(true, Value::is_null)
}

fn absent_or_empty(value: &Value, field: &str) -> bool {
    match value.get(field) {
        None | Some(Value::Null) => true,
        Some(Value::Object(fields)) => fields.is_empty(),
        Some(Value::Array(values)) => values.is_empty(),
        Some(_) => false,
    }
}

fn inert_option_value(field: &str, value: &Value) -> bool {
    if field == "request_three_d_secure" && value.as_str() == Some("automatic") {
        return true;
    }
    match value {
        Value::Null => true,
        Value::Bool(value) => !value,
        Value::String(value) => value.is_empty(),
        Value::Array(values) => values.is_empty(),
        Value::Object(fields) => fields
            .iter()
            .all(|(field, value)| inert_option_value(field, value)),
        Value::Number(_) => false,
    }
}

fn payment_method_options_are_inert(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::Object(options)) => options
            .iter()
            .all(|(field, value)| inert_option_value(field, value)),
        Some(_) => false,
    }
}

pub(crate) fn payment_intent_safe_shape(value: &Value) -> bool {
    [
        "application_fee_amount",
        "transfer_data",
        "on_behalf_of",
        "setup_future_usage",
    ]
    .iter()
    .all(|field| absent_or_null(value, field))
        && absent_or_empty(value, "hooks")
        && payment_method_options_are_inert(value.get("payment_method_options"))
}

pub(crate) fn invoice_safe_shape(value: &Value) -> bool {
    if !absent_or_null(value, "on_behalf_of") || !absent_or_null(value, "transfer_data") {
        return false;
    }
    let Some(settings) = value.get("payment_settings") else {
        return true;
    };
    let Some(settings) = settings.as_object() else {
        return settings.is_null();
    };
    settings.iter().all(|(field, value)| match field.as_str() {
        "default_mandate" => value.is_null(),
        "payment_method_options" => payment_method_options_are_inert(Some(value)),
        "payment_method_types" => value.is_null() || value.as_array().is_some_and(Vec::is_empty),
        _ => false,
    })
}
