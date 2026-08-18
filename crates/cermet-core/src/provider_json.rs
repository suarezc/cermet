//! Strict parser for provider-controlled JSON response bytes.

use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};

pub(crate) const IMPLEMENTATION_SOURCE: &[u8] = include_bytes!("provider_json.rs");
const INVALID_PROVIDER_JSON: &str = "provider response is not strict JSON";

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("one strict JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(Value::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(Value::Number(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(Value::Number(value.into()))
            }

            fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(Value::String(value.to_string()))
            }

            fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
                Ok(Value::String(value))
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(Value::Null)
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(Value::Null)
            }

            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(StrictJsonValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(Value::Array(values))
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                    let StrictJsonValue(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Value::Object(values))
            }
        }

        deserializer.deserialize_any(Visitor).map(StrictJsonValue)
    }
}

/// Parse one provider response directly from delivered bytes. UTF-8 must be valid, every object at
/// every depth has unique keys, and no trailing non-whitespace content is accepted. Diagnostics are
/// static so provider-controlled bytes never echo into an error surface.
pub(crate) fn parse(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Provider(INVALID_PROVIDER_JSON.to_string()))?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let StrictJsonValue(value) = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|_| Error::Provider(INVALID_PROVIDER_JSON.to_string()))?;
    deserializer
        .end()
        .map_err(|_| Error::Provider(INVALID_PROVIDER_JSON.to_string()))?;
    Ok(value)
}
