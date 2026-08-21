//! Keyless provider facts used while authoring sentence rules.

use std::io::Read;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use serde_json::Value;

use crate::{Error, Result};

/// Providers enabled in the shipped product.
///
/// This list IS the product decision — it gates catalog visibility, `connect`, mint, claim, and
/// sentence admission. A vendored, egress-pinned provider descriptor is not enough on its own: a
/// provider stays unreachable until it is named here.
pub const PRODUCT_ENABLED_PROVIDERS: &[&str] = &["github", "stripe", "vercel"];
pub const STRIPE_API_VERSION: &str = "2026-06-24.dahlia";

/// The ONE command that routes a repository through the broker's git plane, in the placeholder form
/// every surface prints when it has no concrete owner/repo in hand ( an agent
/// in a new repo could read the catalog, the run refusal, `connect github` and `check github` and
/// never learn this string). Shared so the four surfaces cannot drift apart.
pub const GIT_WIRING_COMMAND: &str = "git remote set-url origin cermet::github/<owner>/<repo>";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

fn no_redirect_client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()
        .unwrap_or_else(|_| Client::new())
}

fn url_origin(url: &reqwest::Url) -> Option<(String, String, Option<u16>)> {
    let host = url.host_str()?.to_string();
    Some((url.scheme().to_string(), host, url.port_or_known_default()))
}

struct Egress {
    client: Client,
    origins: Vec<(String, String, Option<u16>)>,
}

impl Egress {
    #[cfg(any(test, feature = "test-double"))]
    fn new(base: &str) -> Self {
        Self::new_multi(&[base.to_string()])
    }

    fn new_multi(bases: &[String]) -> Self {
        let origins = bases
            .iter()
            .filter_map(|base| reqwest::Url::parse(base).ok().as_ref().and_then(url_origin))
            .collect();
        Self {
            client: no_redirect_client(),
            origins,
        }
    }

    fn allows(&self, url: &str) -> bool {
        match reqwest::Url::parse(url).ok().as_ref().and_then(url_origin) {
            Some(request) => self.origins.contains(&request),
            None => false,
        }
    }
}

fn err_chain<E: std::error::Error>(error: &E) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        message.push_str(" -> ");
        message.push_str(&inner.to_string());
        source = inner.source();
    }
    message
}

fn response_read_error(status: reqwest::StatusCode, detail: String) -> Error {
    if status.is_success() {
        Error::Provider(detail)
    } else {
        Error::Provider("Stripe customer lookup was rejected by the provider".into())
    }
}

fn read_capped_response(
    reader: impl Read,
    status: reqwest::StatusCode,
    content_length: Option<u64>,
) -> Result<Vec<u8>> {
    if content_length.is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
        return Err(response_read_error(
            status,
            "provider response exceeded the size cap".into(),
        ));
    }
    let mut bytes = Vec::new();
    if let Err(error) = reader
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
    {
        return Err(response_read_error(
            status,
            format!("response read failed: {}", err_chain(&error)),
        ));
    }
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(response_read_error(
            status,
            "provider response exceeded the size cap".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(any(test, feature = "test-double"))]
const TEST_DOUBLE_ENABLED_PROVIDERS: &[&str] = &["mock-vercel", "mock-github"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductAvailability {
    Enabled,
    ProviderDisabled,
}

pub fn product_availability(provider: &str, _action: &str) -> ProductAvailability {
    if PRODUCT_ENABLED_PROVIDERS.contains(&provider) {
        return ProductAvailability::Enabled;
    }
    #[cfg(any(test, feature = "test-double"))]
    if TEST_DOUBLE_ENABLED_PROVIDERS.contains(&provider) {
        return ProductAvailability::Enabled;
    }
    ProductAvailability::ProviderDisabled
}

/// Authoring-only Stripe customer-name lookup. This is a narrow read adapter, not the broker's
/// provider executor: it accepts a human-supplied token and returns only one stable customer id.
pub struct StripeCustomerResolver {
    egress: Egress,
    base: String,
}

impl Default for StripeCustomerResolver {
    fn default() -> Self {
        let base = "https://api.stripe.com".to_string();
        Self {
            egress: Egress::new_multi(std::slice::from_ref(&base)),
            base,
        }
    }
}

impl StripeCustomerResolver {
    #[cfg(any(test, feature = "test-double"))]
    pub fn with_base(base: String) -> Self {
        Self {
            egress: Egress::new(&base),
            base,
        }
    }

    #[cfg(test)]
    fn with_base_and_origin(base: String, origin: String) -> Self {
        Self {
            egress: Egress::new(&origin),
            base,
        }
    }

    pub fn resolve(&self, token: &str, name: &str) -> Result<String> {
        if name.is_empty() || name.len() > 200 || name.chars().any(char::is_control) {
            return Err(Error::Provider(
                "Stripe customer name must be 1..=200 characters without controls".into(),
            ));
        }
        let escaped = name.replace('\\', "\\\\").replace('\'', "\\'");
        let url = format!("{}/v1/customers/search", self.base);
        if !self.egress.allows(&url) {
            let request_host = reqwest::Url::parse(&url)
                .ok()
                .and_then(|url| url.host_str().map(str::to_string));
            return Err(Error::Provider(format!(
                "egress blocked: request to host `{}` is not the allowlisted provider origin",
                request_host.as_deref().unwrap_or("<none>")
            )));
        }
        let response = self
            .egress
            .client
            .get(url)
            .header(USER_AGENT, "cermet/0.1")
            .bearer_auth(token)
            .header("Stripe-Version", STRIPE_API_VERSION)
            .query(&[
                ("query", format!("name:'{escaped}'")),
                ("limit", "2".into()),
            ])
            .send()
            .map_err(|error| Error::Provider(format!("request failed: {}", err_chain(&error))))?;
        let status = response.status();
        let content_length = response.content_length();
        let bytes = read_capped_response(response, status, content_length)?;
        // NOTE: Duplicate-key rejection retired: one parser consumes this; no differential pair.
        let body: Value = serde_json::from_slice(&bytes).map_err(|_| {
            Error::Provider("Stripe customer lookup returned malformed JSON".into())
        })?;
        if !status.is_success() {
            return Err(Error::Provider(
                "Stripe customer lookup was rejected by the provider".into(),
            ));
        }
        let matches = body
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Provider("Stripe customer lookup returned no data list".into()))?
            .iter()
            .filter(|customer| customer.get("name").and_then(Value::as_str) == Some(name))
            .filter_map(|customer| customer.get("id").and_then(Value::as_str))
            .filter(|id| {
                id.starts_with("cus_")
                    && id.len() <= 128
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [id] => Ok((*id).to_string()),
            [] => Err(Error::Provider(format!(
                "Stripe customer name {name:?} did not resolve to an exact customer"
            ))),
            _ => Err(Error::Provider(format!(
                "Stripe customer name {name:?} is ambiguous; use a customer id"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn stripe_resolver_restores_the_original_timeout_and_response_cap() {
        assert_eq!(REQUEST_TIMEOUT, std::time::Duration::from_secs(30));
        assert_eq!(MAX_RESPONSE_BYTES, 2 * 1024 * 1024);
    }

    #[test]
    fn stripe_resolver_pins_the_full_origin() {
        let egress = Egress::new("https://api.stripe.com");
        assert!(egress.allows("https://api.stripe.com/v1/customers/search"));
        assert!(!egress.allows("http://api.stripe.com/v1/customers/search"));
        assert!(!egress.allows("https://api.stripe.com:8443/v1/customers/search"));
        assert!(!egress.allows("https://api.stripe.com@evil.test/v1/customers/search"));

        let error = StripeCustomerResolver::with_base_and_origin(
            "http://evil.test".into(),
            "https://api.stripe.com".into(),
        )
        .resolve("sk_test_RESOLVE_SECRET", "Gary")
        .expect_err("an off-origin URL must be refused before send");
        assert_eq!(
            error.to_string(),
            "provider error: egress blocked: request to host `evil.test` is not the allowlisted provider origin"
        );
    }

    #[test]
    fn stripe_resolver_refuses_a_response_over_two_mib() {
        let mut body = br#"{"data":[{"id":"cus_123","name":"Gary","padding":""#.to_vec();
        body.resize(body.len() + MAX_RESPONSE_BYTES, b'x');
        body.extend_from_slice(br#""}]}"#);
        let error = read_capped_response(Cursor::new(body), reqwest::StatusCode::OK, None)
            .expect_err("an oversized provider response must be refused");
        assert!(
            error
                .to_string()
                .contains("provider response exceeded the size cap"),
            "{error}"
        );
    }
}
