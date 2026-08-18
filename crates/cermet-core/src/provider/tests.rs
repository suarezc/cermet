use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

/// The PROVING discipline with this hop's persisted key — exactly what the broker hands a verb
/// whose ratified template declares both bits. Every other verb takes `Default::default()`, the
/// plain hop, which is the whole point: one seam, discipline as data.
fn proving(idempotency_key: &str) -> ExecutionDiscipline<'_> {
    ExecutionDiscipline {
        idempotency_key: Some(idempotency_key),
        prove_effect: true,
    }
}

#[test]
fn d4_mock_contract_declares_no_optional_exact_pin_fields() {
    // This unions a resolved contract's OPTIONAL ExactResourcePin fields into both the
    // broker's evaluate-time coverage and the widening suggestion. MOCK_CONTRACT is open with an empty
    // schema, so that union is a no-op for every mock provider — pinned here so a future mock
    // schema change surfaces the coupling loudly instead of silently shifting mock decisions.
    use crate::contract::AllowBinding;
    let optional_exact_pins: Vec<&str> = MOCK_CONTRACT
        .schema
        .iter()
        .filter(|f| !f.required && f.binding == AllowBinding::ExactResourcePin)
        .map(|f| f.name)
        .collect();
    assert!(
        optional_exact_pins.is_empty(),
        "MOCK_CONTRACT must declare no optional exact-pin fields (D4 no-op): {optional_exact_pins:?}"
    );
}

#[test]
fn egress_disabled_ignores_base_url_override() {
    assert_eq!(
        resolve_base("https://api.vercel.com", Some("http://evil.test"), false),
        "https://api.vercel.com"
    );
    assert_eq!(
        resolve_base("https://api.github.com", Some("http://evil.test"), false),
        "https://api.github.com"
    );
    assert_eq!(
        resolve_base("https://api.vercel.com", Some("http://127.0.0.1:9"), true),
        "http://127.0.0.1:9"
    );
    assert_eq!(
        resolve_base("https://api.vercel.com", None, false),
        "https://api.vercel.com"
    );
}

#[test]
fn stripe_descriptor_pins_bearer_auth_to_the_stripe_api_origin() {
    let stripe = VENDORED_PROVIDERS
        .iter()
        .map(|doc| ProviderDescriptor::parse(doc).expect("vendored descriptor parses"))
        .find(|descriptor| descriptor.name == "stripe")
        .expect("Stripe is a vendored provider");

    assert_eq!(stripe.egress, ["https://api.stripe.com"]);
    assert_eq!(stripe.auth_shape().unwrap(), AuthShape::Bearer);
}

#[test]
fn stripe_customer_resolver_returns_one_exact_customer_id() {
    let (base, server) = one_shot_full("200 OK", r#"{"data":[{"id":"cus_123","name":"Gary"}]}"#);
    let resolver = StripeCustomerResolver::with_base(base);

    assert_eq!(
        resolver.resolve("sk_test_RESOLVE_SECRET", "Gary").unwrap(),
        "cus_123"
    );
    let request = server.join().unwrap();
    assert!(
        request.starts_with("GET /v1/customers/search?"),
        "{request}"
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer sk_test_resolve_secret"),
        "{request}"
    );
    assert!(
        !request.contains("sk_test_RESOLVE_SECRET&"),
        "credential entered the query: {request}"
    );
}

#[test]
fn stripe_customer_resolver_refuses_ambiguous_names() {
    let (base, server) = one_shot_full(
        "200 OK",
        r#"{"data":[{"id":"cus_1","name":"Gary"},{"id":"cus_2","name":"Gary"}]}"#,
    );
    let error = StripeCustomerResolver::with_base(base)
        .resolve("sk_test_RESOLVE_SECRET", "Gary")
        .expect_err("a human name must resolve uniquely");
    let _ = server.join().unwrap();
    assert!(error.to_string().contains("ambiguous"), "{error}");
    assert!(!error.to_string().contains("sk_test_RESOLVE_SECRET"));
}

#[test]
fn stripe_search_escapes_the_literal_projects_and_retains_nothing() {
    const TEMPLATE: &str = r#"
provider: stripe
action: search_customers
fields:
  - { name: email_contains, type: str, required: true, class: read_filter, binding: unbound }
consumes: [email_contains]
execution_targets: []
scope: account
http:
  steps:
    - id: search
      method: GET
      path: /v1/customers/search
      success_statuses: [200]
      query:
        limit: "10"
        query: 'email~"{email_contains|query_literal}"'
      retention: none
"#;
    let body = r#"{"data":[{"id":"cus_target","email":"ab\"\\cd@example.invalid","name":"private","metadata":{"private":"drop"}}],"has_more":false}"#;
    let (base, server) = one_shot_full("200 OK", body);
    let descriptor = ProviderDescriptor::parse(
        "name: stripe\negress:\n  - https://api.stripe.com\nauth: bearer\n",
    )
    .unwrap();
    let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
        "stripe".to_string()
    ])));
    registry.load(TEMPLATE).unwrap();
    let provider = GenericProvider::from_descriptor_with_base(descriptor, base, registry);
    let resource = provider
        .canonicalize("search_customers", &json!({"email_contains": "ab\"\\cd"}))
        .unwrap();
    let response = provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "search_customers",
            token: "sk_test_SEARCH_SECRET",
            resource: &resource,
        })
        .unwrap();
    let request = server.join().unwrap();

    assert!(
        request.starts_with("GET /v1/customers/search?"),
        "{request}"
    );
    assert!(request.contains("limit=10"), "{request}");
    assert!(
        request.contains("email%7E%22ab%5C%22%5C%5Ccd%22"),
        "{request}"
    );
    assert_eq!(
        response.result,
        json!({
            "data":[{
                "id":"cus_target",
                "email":"ab\"\\cd@example.invalid",
                "name":"private",
                "metadata":{"private":"drop"}
            }],
            "has_more": false
        }),
        "the response contract is verbatim: the search body arrives as the provider sent it"
    );
    assert!(
        response.retained.is_none(),
        "retention defaults to FULL, so this verb now stores the body it returns"
    );
}

#[test]
fn stripe_search_rejects_bad_literals_before_egress() {
    const TEMPLATE: &str = r#"
provider: stripe
action: search_customers
fields:
  - { name: email_contains, type: str, required: true, class: read_filter, binding: unbound }
consumes: [email_contains]
execution_targets: []
scope: account
http:
  steps:
    - id: search
      method: GET
      path: /v1/customers/search
      success_statuses: [200]
      query: { query: 'email~"{email_contains|query_literal}"' }
      retention: none
"#;
    let descriptor = ProviderDescriptor::parse(
        "name: stripe\negress:\n  - https://api.stripe.com\nauth: bearer\n",
    )
    .unwrap();
    let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
        "stripe".to_string()
    ])));
    registry.load(TEMPLATE).unwrap();
    let provider = GenericProvider::from_descriptor_with_base(
        descriptor,
        "http://127.0.0.1:9".into(),
        registry,
    );

    for invalid in ["", "ab", "a\nb", &"x".repeat(201)] {
        let result = provider.canonicalize("search_customers", &json!({"email_contains": invalid}));
        assert!(
            result.is_err(),
            "invalid search literal accepted: {invalid:?}"
        );
    }
}

#[test]
fn stripe_payment_intent_returns_the_provider_body_verbatim_and_retains_nothing() {
    const CLIENT_SECRET: &str = "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_YrKJUKribcBjcG8HVhfZluoGH";
    let document = crate::templates::VENDORED_CATALOG
        .iter()
        .copied()
        .find(|document| {
            document.contains("provider: stripe\n")
                && document.contains("action: get_payment_intent\n")
        })
        .expect("stripe.get_payment_intent must be vendored");
    let registry = Arc::new(TemplateRegistry::new());
    registry.load(document).unwrap();

    let body = format!(
        r#"{{"id":"pi_3MtwBwLkdIwHu7ix28a3tqPa","object":"payment_intent","amount":2000,"amount_capturable":0,"amount_received":0,"currency":"usd","customer":"cus_NeZwdNtLEOXuvB","capture_method":"automatic","canceled_at":null,"cancellation_reason":null,"latest_charge":"ch_3MtwBwLkdIwHu7ix","created":1680800504,"status":"requires_action","client_secret":"{CLIENT_SECRET}","payment_method":{{"id":"pm_1Q0PsIJvEtkwdCNYMSaVuRz6","card":{{"last4":"4242"}}}},"payment_method_options":{{"card":{{"request_three_d_secure":"automatic"}}}},"payment_method_types":["card"],"source":{{"id":"src_1N3lERLkdIwHu7ixYpTp1PHr","client_secret":"src_client_secret_omitted"}},"next_action":{{"type":"use_stripe_sdk","use_stripe_sdk":{{"stripe_js":"secret-bearing-provider-payload"}}}},"receipt_email":"private@example.invalid","shipping":{{"name":"Private Person"}}}}"#
    );
    let raw_body = body.clone();
    let (base, server) = one_shot_full("200 OK", Box::leak(body.into_boxed_str()));
    let descriptor = ProviderDescriptor::parse(
        "name: stripe\negress:\n  - https://api.stripe.com\nauth: bearer\n",
    )
    .unwrap();
    let stripe = GenericProvider::from_descriptor_with_base(descriptor, base, registry);
    let resource = stripe
        .canonicalize(
            "get_payment_intent",
            &json!({"payment_intent": "pi_3MtwBwLkdIwHu7ix28a3tqPa"}),
        )
        .unwrap();
    let response = stripe
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "get_payment_intent",
            token: "rk_test_broker_credential",
            resource: &resource,
        })
        .unwrap();
    let request = server.join().unwrap();

    assert!(
        request.starts_with("GET /v1/payment_intents/pi_3MtwBwLkdIwHu7ix28a3tqPa "),
        "{request}"
    );
    assert!(!request.contains("expand"), "{request}");
    assert!(response.ok);
    // The response contract is "print it verbatim." The secret-class
    // floor that once stripped `client_secret` / `next_action` / payment-method detail from this
    // exact body was STRUCK — projection is an explicitly enabled restriction, never ambient, and
    // zero classes ship. The PaymentIntent arrives whole.
    assert_eq!(
        response.result,
        serde_json::from_str::<Value>(&raw_body).unwrap(),
        "the result is the provider's PaymentIntent, field for field"
    );
    let returned = serde_json::to_string(&response.result).unwrap();
    for present in [
        CLIENT_SECRET,
        "client_secret",
        "payment_method",
        "source",
        "next_action",
        "private@example.invalid",
        "Private Person",
    ] {
        assert!(
            returned.contains(present),
            "the verbatim response withholds nothing: `{present}` is missing"
        );
    }
    assert!(
        response.retained.is_some(),
        "retention defaults to FULL, so this verb now stores the body it returns"
    );
}

#[test]
fn retention_none_suppresses_secret_bearing_error_artifacts_too() {
    const TEMPLATE: &str = r#"
provider: acme
action: write_secret
fields:
  - { name: target, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: value, type: str, required: true, class: secret, binding: unbound }
consumes: [target, value]
execution_targets: [target]
http:
  steps:
    - id: write
      method: POST
      path: /targets/{target}
      body: { value: "{value}" }
      retention: none
"#;
    let (base, server) = one_shot_full(
        "400 Bad Request",
        r#"{"status":400,"message":"echo SECRET_VALUE"}"#,
    );
    let descriptor =
        ProviderDescriptor::parse("name: acme\negress:\n  - https://api.acme.test\nauth: bearer\n")
            .unwrap();
    let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
        "acme".to_string()
    ])));
    registry.load(TEMPLATE).unwrap();
    let provider = GenericProvider::from_descriptor_with_base(descriptor, base, registry);
    let resource = provider
        .canonicalize(
            "write_secret",
            &json!({"target":"one", "value":"SECRET_VALUE"}),
        )
        .unwrap();
    let response = provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "write_secret",
            token: "token",
            resource: &resource,
        })
        .unwrap();
    let _ = server.join().unwrap();
    assert!(!response.ok);
    assert_eq!(
        response.result,
        json!({"status":400,"error":{"status":400,"message":"echo [scrubbed:value]"}}),
        "the error body is verbatim; only the AGENT-SUBMITTED secret is scrubbed out of it"
    );
    assert!(
        !response.result.to_string().contains("SECRET_VALUE"),
        "request-side secret custody is untouched by the verbatim response contract"
    );
    assert!(response.retained.is_none());
}

#[test]
fn form_body_encoding_flattens_nested_fields_and_negates_positive_amounts() {
    const TEMPLATE: &str = r#"
provider: acme
action: credit
fields:
  - { name: customer, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: amount, type: int, required: true, class: side_effect, binding: bounded }
consumes: [customer, amount]
execution_targets: [customer]
http:
  steps:
    - id: credit
      method: POST
      path: /customers/{customer}/credits
      body_encoding: form
      body:
        amount: "{amount|negative}"
        metadata:
          source: cermet
"#;
    let (base, server) = one_shot_full("200 OK", r#"{"id":"cbtxn_1","amount":-25}"#);
    let descriptor =
        ProviderDescriptor::parse("name: acme\negress:\n  - https://api.acme.test\nauth: bearer\n")
            .unwrap();
    let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
        "acme".to_string()
    ])));
    registry
        .load(TEMPLATE)
        .expect("the form template validates");
    let provider = GenericProvider::from_descriptor_with_base(descriptor, base, registry);
    let resource = provider
        .canonicalize("credit", &json!({"customer":"cus_1", "amount":25}))
        .unwrap();

    let response = provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "credit",
            token: "sk_test_FORM_SECRET",
            resource: &resource,
        })
        .unwrap();
    let request = server.join().unwrap();
    let lower = request.to_ascii_lowercase();
    assert!(
        lower.contains("content-type: application/x-www-form-urlencoded"),
        "request was not form encoded: {request}"
    );
    let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
    assert!(
        body.contains("amount=-25"),
        "positive credit amount was not negated: {body}"
    );
    assert!(
        body.contains("metadata%5Bsource%5D=cermet"),
        "nested form field was not bracket-flattened: {body}"
    );
    assert!(response.ok);
    assert_eq!(response.result, json!({"id":"cbtxn_1", "amount":-25}));
}

#[test]
fn negative_transform_refuses_non_positive_input_before_egress() {
    const TEMPLATE: &str = r#"
provider: acme
action: credit
fields:
  - { name: customer, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: amount, type: int, required: true, class: side_effect, binding: bounded }
consumes: [customer, amount]
execution_targets: [customer]
http:
  steps:
    - id: credit
      method: POST
      path: /customers/{customer}/credits
      body_encoding: form
      body: { amount: "{amount|negative}" }
"#;
    let descriptor =
        ProviderDescriptor::parse("name: acme\negress:\n  - https://api.acme.test\nauth: bearer\n")
            .unwrap();
    let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
        "acme".to_string()
    ])));
    registry
        .load(TEMPLATE)
        .expect("the negative transform validates");
    let provider = GenericProvider::from_descriptor_with_base(
        descriptor,
        "http://127.0.0.1:9".into(),
        registry,
    );

    for amount in [0, -1, i64::MIN] {
        let resource = provider
            .canonicalize("credit", &json!({"customer":"cus_1", "amount":amount}))
            .unwrap();
        let error = match provider.execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "credit",
            token: "sk_test_FORM_SECRET",
            resource: &resource,
        }) {
            Err(error) => error,
            Ok(_) => panic!("a non-positive credit amount must fail before HTTP"),
        };
        assert!(error.to_string().contains("positive"), "{error}");
    }
}

#[test]
fn http_call_rejects_a_url_whose_host_is_not_the_provider_allowlist() {
    let eg = Egress::new("https://api.github.com");
    let res = http_call(
        &eg,
        Method::GET,
        "http://evil.test/user".to_string(),
        "ghp_secret_tok_should_not_leave",
        None,
        &[],
        &AuthShape::Bearer,
        &[],
    );
    let msg = match res {
        Err(e) => e.to_string(),
        Ok(_) => panic!("an off-allowlist host must be rejected pre-send"),
    };
    assert!(
        msg.contains("evil.test") && msg.to_lowercase().contains("egress"),
        "must be the egress-block error, not a network error: {msg}"
    );
}

#[test]
fn egress_guard_pins_the_full_origin_not_just_the_host() {
    let eg = Egress::new("https://api.github.com");
    // A host_str-only compare would let these PASS; the origin compare rejects them.
    assert!(
        !eg.allows("http://api.github.com/user"),
        "http must not match an https base"
    );
    assert!(
        !eg.allows("https://api.github.com:8443/user"),
        "a non-default port is a different origin"
    );
    assert!(
        !eg.allows("https://api.github.com@evil.test/user"),
        "userinfo cannot disguise a foreign host"
    );
    assert!(
        !eg.allows("https://api.github.com./user"),
        "a trailing-dot host is a distinct domain"
    );
    // benign userinfo with the correct host is allowed (host unchanged); the exact origin too.
    assert!(
        eg.allows("https://user@api.github.com/user"),
        "benign userinfo with the right host is allowed"
    );
    assert!(
        eg.allows("https://api.github.com/repos/o/r"),
        "the exact allowlisted origin is allowed"
    );
    // a base that fails to parse allows nothing (no request origin equals None).
    assert!(
        !Egress::new("not a url").allows("https://api.github.com/"),
        "an unparseable base allows nothing"
    );
}

#[test]
fn egress_guard_matches_the_loopback_test_base() {
    let lo = Egress::new("http://127.0.0.1:9");
    assert!(
        lo.allows("http://127.0.0.1:9/v2/deployments"),
        "the loopback test-egress base matches itself"
    );
    assert!(
        !lo.allows("http://127.0.0.1:10/x"),
        "a different loopback port is rejected"
    );
    assert!(
        !lo.allows("https://127.0.0.1:9/x"),
        "a different scheme is rejected"
    );
}

fn one_shot(status_line: &'static str, body: &'static str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut data = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&tmp[..n]);
            if data.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let req = String::from_utf8_lossy(&data).into_owned();
        let resp = format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).unwrap();
        req
    });
    (format!("http://{addr}"), handle)
}

fn one_shot_full(
    status_line: &'static str,
    body: &'static str,
) -> (String, thread::JoinHandle<String>) {
    one_shot_full_bytes(status_line, body.as_bytes())
}

fn one_shot_full_bytes(
    status_line: &'static str,
    body: &'static [u8],
) -> (String, thread::JoinHandle<String>) {
    one_shot_full_owned(status_line, body.to_vec())
}

fn one_shot_full_owned(
    status_line: &'static str,
    body: Vec<u8>,
) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut data = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&tmp[..n]);
            if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&data[..pos]).to_lowercase();
                let want = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while data.len() < pos + 4 + want {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 {
                        break;
                    }
                    data.extend_from_slice(&tmp[..n]);
                }
                break;
            }
        }
        let request = String::from_utf8_lossy(&data).into_owned();
        let headers = format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        request
    });
    (format!("http://{addr}"), handle)
}

fn two_shot_full(
    responses: &'static [(&'static str, &'static str)],
) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for (status_line, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut data = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = stream.read(&mut tmp).unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&tmp[..n]);
                if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&data[..pos]).to_lowercase();
                    let want = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length:")
                                .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    while data.len() < pos + 4 + want {
                        let n = stream.read(&mut tmp).unwrap();
                        if n == 0 {
                            break;
                        }
                        data.extend_from_slice(&tmp[..n]);
                    }
                    break;
                }
            }
            requests.push(String::from_utf8_lossy(&data).into_owned());
            let response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
        requests
    });
    (format!("http://{addr}"), handle)
}

/// The canonical ratified `read_repo` template — the owner of the name; every read_repo test
/// runs through the TEMPLATE path (the other arm survives only as the request oracle).
const READ_REPO_TEMPLATE: &str = include_str!("../../actions/github.read_repo.yaml");

fn github_with_read_repo(base: String) -> GenericProvider {
    let reg = Arc::new(TemplateRegistry::new());
    reg.load(READ_REPO_TEMPLATE)
        .expect("the canonical read_repo template loads");
    GithubProvider::with_base_and_templates(base, reg)
}
#[test]
fn github_read_repo_sends_authenticated_get_and_parses_body() {
    let (base, server) = one_shot("200 OK", r#"{"full_name":"o/r","default_branch":"main"}"#);
    let gh = github_with_read_repo(base);
    let resource = gh
        .canonicalize("read_repo", &json!({ "repo": "o/r" }))
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "read_repo",
            token: "ghp_secret_value_123456",
            resource: &resource,
        })
        .unwrap();

    let received = server.join().unwrap();
    assert!(
        received.starts_with("GET /repos/o/r "),
        "request line: {received}"
    );
    assert!(
        received.contains("Bearer ghp_secret_value_123456"),
        "headers: {received}"
    );
    assert!(received
        .to_lowercase()
        .contains("x-github-api-version: 2026-03-10"));
    assert!(resp.ok);
    assert_eq!(resp.result["default_branch"], json!("main"));
    assert!(!resp.result.to_string().contains("ghp_secret_value_123456"));
}

#[test]
fn template_read_repo_wire_equivalent_to_reference() {
    // A field-RICH provider body (extra keys beyond the keep list) proves the template narrows
    // the very body the retired built-in returned — not a body rigged to the keep set.
    let resp = r#"{"full_name":"acme/website","default_branch":"main","html_url":"https://github.com/acme/website","visibility":"public","description":"the site","id":123,"node_id":"R_kgDOabc","stargazers_count":9,"owner":{"login":"acme"}}"#;
    let (base_t, server_t) = one_shot_full("200 OK", resp);
    let (base_r, server_r) = one_shot_full("200 OK", resp);
    let gh_template = github_with_read_repo(base_t);
    let gh_reference = GithubProvider::with_base(base_r);
    // One frozen resource, used verbatim by both paths (approved fields == executed fields).
    let resource = gh_template
        .canonicalize("read_repo", &json!({ "owner": "acme", "name": "website" }))
        .unwrap();
    let token = "ghp_secret_12345678";
    let resp_template = gh_template
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "read_repo",
            token,
            resource: &resource,
        })
        .unwrap();
    let resp_reference = gh_reference
        .reference_read_repo_execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "read_repo",
            token,
            resource: &resource,
        })
        .unwrap();

    let req_template = server_t.join().unwrap();
    let req_reference = server_r.join().unwrap();
    assert_eq!(
        normalize_host(&req_template),
        normalize_host(&req_reference),
        "the template's request must be BYTE-IDENTICAL to the reference after Host normalization"
    );
    assert!(
        req_template.starts_with("GET /repos/acme/website "),
        "request line: {req_template}"
    );

    // Under the verbatim response contract the template result and the retired built-in
    // agree EXACTLY: both hand back the body the provider sent. This is a stronger equivalence than
    // the projected one it replaces — there is no allowlist standing between them.
    assert_eq!(
        resp_template.result, resp_reference.result,
        "the template result must be the reference body, verbatim"
    );
    for present in ["stargazers_count", "description", "owner"] {
        assert!(
            resp_template.result.get(present).is_some(),
            "the verbatim result must carry the provider's `{present}`"
        );
    }
    for r in [&resp_template.result, &resp_reference.result] {
        assert!(
            !serde_json::to_string(r).unwrap().contains(token),
            "the token must never appear in a result"
        );
    }
}

#[test]
fn read_repo_template_field_class_parity_with_retired_builtin() {
    // The retired GH_READ_REPO built-in: owner+name, each a required Str Identity field bound by
    // ExactResourcePin; consumes+targets = [owner, name]. The template's derived contract must
    // match field-for-field (class x binding), so policy anchoring is byte-identical.
    let reg = Arc::new(TemplateRegistry::new());
    reg.load(READ_REPO_TEMPLATE).unwrap();
    let c = reg
        .resolve("github", "read_repo")
        .expect("read_repo resolves via its template");
    for field in ["owner", "name"] {
        assert_eq!(
            c.field_class(field),
            Some(crate::contract::FieldClass::Identity),
            "{field} class"
        );
        assert_eq!(
            c.field_binding(field),
            Some(crate::contract::AllowBinding::ExactResourcePin),
            "{field} binding"
        );
    }
    assert_eq!(c.schema.len(), 2, "exactly the two retired fields");
    assert_eq!(c.consumes.to_vec(), vec!["owner", "name"]);
    assert_eq!(c.execution_targets.to_vec(), vec!["owner", "name"]);
    assert!(
        !c.consumes.contains(&"parameters"),
        "no execute-time parameters channel"
    );
}
#[test]
fn ib_owner_spoof_15_repo_collapses_to_owner_and_name() {
    let r = github_with_read_repo("http://127.0.0.1:9".into())
        .canonicalize("read_repo", &json!({ "repo": "acme/website" }))
        .unwrap();
    assert_eq!(r.req_str("owner").unwrap(), "acme");
    assert_eq!(r.req_str("name").unwrap(), "website");
}

#[test]
fn ib_canon_repo_residue_11_repo_key_is_dropped() {
    let r = github_with_read_repo("http://127.0.0.1:9".into())
        .canonicalize("read_repo", &json!({ "repo": "acme/website" }))
        .unwrap();
    assert!(
        !r.contains("repo"),
        "the pre-split `repo` key must be stripped"
    );
}

#[test]
fn ib_owner_spoof_16_repo_with_owner_is_rejected_as_ambiguous() {
    let r = github_with_read_repo("http://127.0.0.1:9".into())
        .canonicalize("read_repo", &json!({ "repo": "demo", "owner": "evil" }));
    assert!(
        r.is_err(),
        "the {{repo,owner}} spoof shape must be rejected"
    );
}

#[test]
fn ib_canon_repo_multislash_9_is_rejected() {
    let r = github_with_read_repo("http://127.0.0.1:9".into())
        .canonicalize("read_repo", &json!({ "repo": "acme/team/website" }));
    assert!(
        r.is_err(),
        "a two-slash repo must be rejected, not split into owner=acme name=team/website"
    );
}

#[test]
fn ib_canon_repo_empty_10_empty_or_whitespace_segments_rejected() {
    let gh = github_with_read_repo("http://127.0.0.1:9".into());
    for raw in [
        json!({ "repo": "/website" }),
        json!({ "repo": "acme/" }),
        json!({ "repo": " /website" }),
        json!({ "owner": "", "name": "website" }),
        json!({ "owner": "ac me", "name": "website" }),
    ] {
        assert!(
            gh.canonicalize("read_repo", &raw).is_err(),
            "must reject empty/whitespace segment: {raw}"
        );
    }
}

#[test]
fn ib_canon_repo_multislash_9b_direct_name_with_slash_is_rejected() {
    let r = github_with_read_repo("http://127.0.0.1:9".into()).canonicalize(
        "read_repo",
        &json!({ "owner": "acme", "name": "team/website" }),
    );
    assert!(
        r.is_err(),
        "a slash in the direct name segment must be rejected"
    );
}

#[test]
fn path_segment_rejects_control_and_delimiter_chars() {
    let gh = github_with_read_repo("http://127.0.0.1:9".into());
    for bad in [
        json!("ac\tme"),
        json!("a?b"),
        json!("a#b"),
        json!("a%2f"),
        json!(".."),
        json!("a\\b"),
    ] {
        assert!(
            gh.canonicalize("read_repo", &json!({ "owner": bad, "name": "website" }))
                .is_err(),
            "owner {bad} must be rejected as an unsafe path segment"
        );
    }
}
#[test]
fn ib_canon_github_missing_owner_43_is_rejected() {
    let r = github_with_read_repo("http://127.0.0.1:9".into())
        .canonicalize("read_repo", &json!({ "name": "website" }));
    assert!(
        r.is_err(),
        "a name-only github resource must be rejected (owner is required)"
    );
}

#[test]
fn ib_canon_github_name_only_42_target_form_passes_unchanged() {
    let r = github_with_read_repo("http://127.0.0.1:9".into())
        .canonicalize("read_repo", &json!({ "owner": "acme", "name": "website" }))
        .unwrap();
    assert_eq!(r.req_str("owner").unwrap(), "acme");
    assert_eq!(r.req_str("name").unwrap(), "website");
}

#[test]
fn ib_canon_idempotent_29_canon_of_canon_is_fixpoint() {
    let gh = github_with_read_repo("http://127.0.0.1:9".into());
    let once = gh
        .canonicalize("read_repo", &json!({ "repo": "acme/website" }))
        .unwrap();
    let twice = gh
        .canonicalize("read_repo", &once.as_match_value())
        .unwrap();
    assert_eq!(
        once, twice,
        "canonicalize must be idempotent over its own output"
    );
}
/// Test-only fixture template for a generic "github write verb with GET-then-PUT wire shape".
/// `test_two_step_write` was retired from the shipped catalog; this YAML survives only as a behavioral
/// fixture that exercises the generic provider machinery.
const TWO_STEP_TEMPLATE: &str =
    include_str!("../../tests/fixtures/github.test_two_step_write.yaml");

fn github_with_two_step(base: String) -> GenericProvider {
    let reg = Arc::new(TemplateRegistry::new());
    reg.load(TWO_STEP_TEMPLATE)
        .expect("the canonical test_two_step_write template loads");
    GithubProvider::with_base_and_templates(base, reg)
}

#[test]
fn two_step_write_updates_via_get_sha_then_put_from_frozen_resource() {
    let (base, server) = two_shot_full(&[
        (
            "200 OK",
            r#"{"name":"app.js","path":"src/app.js","sha":"oldsha1234567"}"#,
        ),
        (
            "200 OK",
            r#"{"content":{"sha":"newsha"},"commit":{"sha":"c0ffee","html_url":"https://github.com/acme/website/commit/c0ffee"}}"#,
        ),
    ]);
    let gh = github_with_two_step(base);
    let resource = gh
            .canonicalize(
                "test_two_step_write",
                &json!({ "owner": "acme", "name": "website", "branch": "main", "path": "src/app.js", "payload": "hello cermet", "message": "fix tagline" }),
            )
            .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "test_two_step_write",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let reqs = server.join().unwrap();
    assert_eq!(reqs.len(), 2, "test_two_step_write is GET-sha then PUT");
    assert!(
        reqs[0].starts_with("GET /repos/acme/website/contents/src/app.js?ref=main "),
        "step 1 reads the current sha on the frozen branch: {}",
        reqs[0]
    );
    assert!(
        reqs[0].contains("Bearer ghp_secret_12345678"),
        "step 1 auth: {}",
        reqs[0]
    );
    assert!(
        reqs[1].starts_with("PUT /repos/acme/website/contents/src/app.js "),
        "step 2 writes the frozen path: {}",
        reqs[1]
    );
    assert!(
        reqs[1].contains(r#""sha":"oldsha1234567""#),
        "update carries the captured sha: {}",
        reqs[1]
    );
    assert!(
        reqs[1].contains("aGVsbG8gY2VybWV0"),
        "content is base64 of the frozen content: {}",
        reqs[1]
    );
    assert!(
        !reqs[1].contains("hello cermet"),
        "raw content never rides the wire unencoded: {}",
        reqs[1]
    );
    assert!(
        reqs[1].contains(r#""message":"fix tagline""#) && reqs[1].contains(r#""branch":"main""#),
        "message/branch from the frozen resource: {}",
        reqs[1]
    );
    assert!(resp.ok);
    let keys: Vec<&String> = resp.result.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        ["commit", "content"],
        "result is narrowed to the keep-list, nothing else"
    );
    assert_eq!(
        resp.result["commit"]["html_url"],
        json!("https://github.com/acme/website/commit/c0ffee")
    );
    assert_eq!(resp.result["content"]["sha"], json!("newsha"));
    assert!(
        !resp.result.to_string().contains("ghp_secret_12345678"),
        "token must not leak into the result"
    );
}

#[test]
fn two_step_write_create_omits_sha_when_get_returns_404() {
    let (base, server) = two_shot_full(&[
        ("404 Not Found", r#"{"message":"Not Found"}"#),
        (
            "201 Created",
            r#"{"content":{"sha":"newsha"},"commit":{"sha":"c1","html_url":"u"}}"#,
        ),
    ]);
    let gh = github_with_two_step(base);
    let resource = gh
            .canonicalize(
                "test_two_step_write",
                &json!({ "repo": "acme/website", "branch": "main", "path": "docs/new.md", "payload": "hello cermet", "message": "add doc" }),
            )
            .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "test_two_step_write",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let reqs = server.join().unwrap();
    assert!(
        !reqs[1].contains(r#""sha":"#),
        "a create (404 on read) must omit sha, never send an empty one: {}",
        reqs[1]
    );
    assert!(resp.ok);
}

#[test]
fn two_step_write_rejects_bad_path_segments_at_canonicalize() {
    // A bad path is refused at CANONICALIZE (request time) — it can never mint an
    // approvable card, let alone reach execute.
    let gh = github_with_two_step("http://127.0.0.1:9".into());
    for bad in [
        "../secrets",
        "src/../secrets",
        "/etc/passwd",
        "src//x",
        "a%2e/x",
        "sp ace/x",
        ".",
    ] {
        let err = match gh.canonicalize(
                "test_two_step_write",
                &json!({ "owner": "acme", "name": "website", "branch": "main", "path": bad, "payload": "x", "message": "m" }),
            ) {
                Err(e) => e,
                Ok(_) => panic!("path `{bad}` must be rejected at canonicalize"),
            };
        assert!(
            err.to_string().contains("path"),
            "the rejection names the path field for `{bad}`: {err}"
        );
    }
}

#[test]
fn two_step_write_executor_revalidates_the_path_as_defense_in_depth() {
    // A frozen resource that somehow bypassed request-time validation (crafted directly, not
    // via canonicalize) is re-checked by the executor pre-egress — no server is listening, so
    // reaching egress would fail differently than this typed rejection.
    let gh = github_with_two_step("http://127.0.0.1:9".into());
    let mut m = BTreeMap::new();
    for (k, v) in [
        ("owner", "acme"),
        ("name", "website"),
        ("branch", "main"),
        ("path", "../secrets"),
        ("content", "x"),
        ("message", "m"),
    ] {
        m.insert(k.to_string(), Scalar::Str(v.to_string()));
    }
    let resource = CanonicalResource::from_map(m);
    let err = match gh.execute(ProviderCall {
        discipline: Default::default(),
        git_mirror: None,
        request_id: "",
        action: "test_two_step_write",
        token: "ghp_x",
        resource: &resource,
    }) {
        Err(e) => e,
        Ok(_) => panic!("a crafted bad path must still be rejected at execute"),
    };
    assert!(
        err.to_string().contains("path"),
        "the execute-time rejection names the path field: {err}"
    );
}

#[test]
fn two_step_write_get_error_short_circuits_the_put_fail_closed() {
    // ONE connection only: if execute wrongly proceeded to the PUT after a non-404 read
    // error, the second connect would fail and execute would Err instead of surfacing 500.
    let (base, server) = one_shot_full("500 Internal Server Error", r#"{"message":"boom"}"#);
    let gh = github_with_two_step(base);
    let resource = gh
            .canonicalize(
                "test_two_step_write",
                &json!({ "owner": "acme", "name": "website", "branch": "main", "path": "src/app.js", "payload": "x", "message": "m" }),
            )
            .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "test_two_step_write",
            token: "ghp_x",
            resource: &resource,
        })
        .unwrap();
    server.join().unwrap();
    assert!(!resp.ok, "an ambiguous read error must not become a write");
    assert_eq!(resp.result["status"], json!(500));
}

#[test]
fn two_step_write_canonicalize_is_closed_and_requires_every_field() {
    let gh = github_with_two_step("http://127.0.0.1:9".into());
    let full = json!({ "owner": "a", "name": "r", "branch": "b", "path": "p", "payload": "c", "message": "m" });
    assert!(gh.canonicalize("test_two_step_write", &full).is_ok());
    for missing in ["owner", "name", "branch", "path", "payload", "message"] {
        let mut v = full.clone();
        v.as_object_mut().unwrap().remove(missing);
        assert!(
            gh.canonicalize("test_two_step_write", &v).is_err(),
            "missing `{missing}` must fail closed at canonicalize"
        );
    }
    let mut extra = full.clone();
    extra
        .as_object_mut()
        .unwrap()
        .insert("committer".into(), json!("mallory <m@evil.test>"));
    assert!(
        gh.canonicalize("test_two_step_write", &extra).is_err(),
        "the schema is closed: an undeclared field is rejected"
    );
}

/// Blank the `Host:` header value — the ONLY tolerated difference between the template and
/// reference wire captures (each talks to its own ephemeral loopback port).
fn normalize_host(req: &str) -> String {
    req.split("\r\n")
        .map(|line| {
            if line.to_ascii_lowercase().starts_with("host:") {
                "host: NORMALIZED".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

#[test]
fn template_directory_read_fails_closed() {
    // The Contents API answers a DIRECTORY read with 200 + a JSON ARRAY. The `sha`
    // capture cannot resolve against an array, so the whole execute must fail — and the
    // ONE-shot server proves no second (write) request is ever attempted.
    let (base, server) = one_shot_full(
        "200 OK",
        r#"[{"name":"a.js","sha":"s1"},{"name":"b.js","sha":"s2"}]"#,
    );
    let gh = github_with_two_step(base);
    let resource = gh
            .canonicalize(
                "test_two_step_write",
                &json!({ "owner": "acme", "name": "website", "branch": "main", "path": "src", "payload": "x", "message": "m" }),
            )
            .unwrap();
    let err = match gh.execute(ProviderCall {
        discipline: Default::default(),
        git_mirror: None,
        request_id: "",
        action: "test_two_step_write",
        token: "ghp_x",
        resource: &resource,
    }) {
        Err(e) => e,
        Ok(r) => panic!(
            "a 200 whose shape is not the expected object must never flow into the write: {:?}",
            r.result
        ),
    };
    assert!(
        err.to_string().contains("sha"),
        "the failure names the unresolvable capture: {err}"
    );
    server.join().unwrap();
}
#[test]
fn ib_contract_schema_target_subset_23_every_contract_is_self_consistent() {
    for (_name, p) in default_registry(
        &[],
        &Arc::new(TemplateRegistry::new()),
        &crate::git::GitConfig::at(std::env::temp_dir()),
    ) {
        for action in p.supported_actions() {
            if let Some(c) = p.action_contract(action) {
                c.assert_consistent();
                for consumed in c.consumes {
                    assert_ne!(
                        *consumed, "parameters",
                        "{action}: consumes must not name parameters"
                    );
                }
            }
        }
    }
}

// The `builtin_action_names` drift-pin mirror and the `validate_consistent_parity_across_all_builtins`
// backstop were retired here: with zero compiled-in built-ins the shadow-ban's built-in arm
// and its mirror are gone. Contract self-consistency is still exercised on every live contract by
// `ib_contract_schema_target_subset_23_every_contract_is_self_consistent` above (the mock contracts)
// and by the template loader (`load` runs `validate_consistent` on each derived contract).

// ---- OID/uint admission shape and read_tree projection ----
const READ_TREE_TEMPLATE: &str = include_str!("../../actions/github.read_tree.yaml");
const READ_BLOB_TEMPLATE: &str = include_str!("../../actions/github.read_blob.yaml");
const READ_THREAD_TEMPLATE: &str = include_str!("../../actions/github.read_thread.yaml");
const READ_PR_TEMPLATE: &str = include_str!("../../actions/github.read_pull_request.yaml");

fn github_with_reads(base: String) -> GenericProvider {
    let reg = Arc::new(TemplateRegistry::new());
    for doc in [
        READ_TREE_TEMPLATE,
        READ_BLOB_TEMPLATE,
        READ_THREAD_TEMPLATE,
        READ_PR_TEMPLATE,
    ] {
        reg.load(doc).expect("a github read template loads");
    }
    GithubProvider::with_base_and_templates(base, reg)
}

#[test]
fn read_tree_and_blob_reject_a_ref_name_oid_at_admission() {
    // read_tree/read_blob promise IMMUTABLE Git object addressing, but GitHub's trees/blobs
    // endpoints also accept a branch/ref name — so `tree_sha: "main"` would pin a MOVING pointer.
    // The OID-shape admission check (canonicalize → validate_template_resource) must REJECT any
    // non-OID value; only a canonical lowercase-hex OID (40 or 64 chars) is accepted.
    let gh = github_with_reads("http://127.0.0.1:1".to_string());
    let sha40 = "a".repeat(40);
    let sha64 = "b".repeat(64);

    // A ref name, an uppercase SHA, a short/long hex, and a non-hex char all DENY.
    for bad in [
        "main",
        "HEAD",
        &"A".repeat(40),
        &"a".repeat(39),
        &"a".repeat(41),
        "abcg",
    ] {
        assert!(
            gh.canonicalize(
                "read_tree",
                &json!({ "owner": "o", "name": "r", "tree_sha": bad }),
            )
            .is_err(),
            "read_tree must reject a non-OID tree_sha `{bad}`"
        );
        assert!(
            gh.canonicalize(
                "read_blob",
                &json!({ "owner": "o", "name": "r", "file_sha": bad }),
            )
            .is_err(),
            "read_blob must reject a non-OID file_sha `{bad}`"
        );
    }

    // Canonical SHA-1 (40) and SHA-256 (64) lowercase-hex OIDs are accepted.
    for good in [&sha40, &sha64] {
        gh.canonicalize(
            "read_tree",
            &json!({ "owner": "o", "name": "r", "tree_sha": good }),
        )
        .unwrap_or_else(|e| panic!("a valid OID tree_sha `{good}` must be accepted: {e}"));
        gh.canonicalize(
            "read_blob",
            &json!({ "owner": "o", "name": "r", "file_sha": good }),
        )
        .unwrap_or_else(|e| panic!("a valid OID file_sha `{good}` must be accepted: {e}"));
    }
}

#[test]
fn thread_and_pr_number_is_a_canonical_positive_integer() {
    // `number` is a typed str path segment; "1" and "01" would otherwise be two distinct pins for
    // the SAME resource. The uint admission check accepts only a canonical bare positive decimal.
    let gh = github_with_reads("http://127.0.0.1:1".to_string());
    for (action, key) in [("read_thread", "number"), ("read_pull_request", "number")] {
        for bad in ["01", "0", "abc", "1.0", "-1", "", " 1", "1 "] {
            assert!(
                gh.canonicalize(action, &json!({ "owner": "o", "name": "r", key: bad }))
                    .is_err(),
                "{action} must reject a non-canonical {key} `{bad}`"
            );
        }
        for good in ["1", "42", "1000000"] {
            gh.canonicalize(action, &json!({ "owner": "o", "name": "r", key: good }))
                .unwrap_or_else(|e| panic!("{action} must accept canonical {key} `{good}`: {e}"));
        }
    }
}

#[test]
fn read_tree_projection_drops_whole_entry_urls() {
    // read_tree keep must project the documented FIVE per-entry fields (path/mode/type/sha/size)
    // and DROP the broad entry URLs GitHub returns (`url`, `git_url`), not clone whole entries.
    let sha = "c".repeat(40);
    // The entry carries BOTH broad URLs GitHub returns (`url` AND `git_url`) so the
    // drop assertion below is non-vacuous — a projection that leaked either would fail.
    let body = r#"{"sha":"c000","truncated":false,"url":"https://api.github.com/repos/o/r/git/trees/c000","tree":[{"path":"README.md","mode":"100644","type":"blob","sha":"deadbeef","size":42,"url":"https://api.github.com/repos/o/r/git/blobs/deadbeef","git_url":"https://api.github.com/repos/o/r/git/blobs/deadbeef"}]}"#;
    let (base, server) = one_shot("200 OK", body);
    let gh = github_with_reads(base);
    let resource = gh
        .canonicalize(
            "read_tree",
            &json!({ "owner": "o", "name": "r", "tree_sha": sha }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "read_tree",
            token: "ghp_x",
            resource: &resource,
        })
        .unwrap();
    let _ = server.join().unwrap();

    let entry = &resp.result["tree"][0];
    for kept in ["path", "mode", "type", "sha", "size"] {
        assert!(
            !entry.get(kept).unwrap().is_null(),
            "kept entry field `{kept}` missing"
        );
    }
    for present in ["url", "git_url"] {
        assert!(
            entry.get(present).is_some(),
            "the verbatim result carries the provider's `{present}`"
        );
    }
    // The top-level bare tree `url` survives too: the body is returned whole.
    assert!(
        resp.result.get("url").is_some(),
        "the verbatim response carries the top-level tree url"
    );
}

// ---- Provider descriptors + GenericProvider ----

const ACME_READ_TEMPLATE: &str = "provider: acme\naction: read_thing\nfields:\n  - { name: id, type: str, required: true, class: identity, binding: exact_resource_pin }\nconsumes: [id]\nexecution_targets: [id]\nhttp:\n  steps:\n    - id: get\n      method: GET\n      path: /things/{id}\n";

/// An acme GenericProvider whose egress is pinned to `base` (the loopback test server) and whose
/// auth shape is `auth`, with the one-step read template loaded.
fn acme_provider(base: String, auth: &str) -> GenericProvider {
    let doc = format!(
        "name: acme\negress:\n  - https://api.acme.test\nauth: {auth}\nheaders:\n  X-Extra: v1\n"
    );
    let d = ProviderDescriptor::parse(&doc).expect("acme descriptor parses");
    let mut set = HashSet::new();
    set.insert("acme".to_string());
    let reg = Arc::new(TemplateRegistry::with_providers(set));
    reg.load(ACME_READ_TEMPLATE).expect("acme template loads");
    GenericProvider::from_descriptor_with_base(d, base, reg)
}

#[test]
fn descriptor_parse_is_fail_closed() {
    assert!(ProviderDescriptor::parse("name: acme\negress:\n  - https://api.acme.test\n").is_ok());
    // no egress at all
    assert!(ProviderDescriptor::parse("name: acme\negress: []\n").is_err());
    // unknown auth shape
    assert!(ProviderDescriptor::parse(
        "name: acme\negress:\n  - https://api.acme.test\nauth: hmac\n"
    )
    .is_err());
    // a non-http scheme can never carry a credential
    assert!(ProviderDescriptor::parse("name: acme\negress:\n  - ftp://api.acme.test\n").is_err());
    // an origin with a path is not a bare origin
    assert!(
        ProviderDescriptor::parse("name: acme\negress:\n  - https://api.acme.test/v1\n").is_err()
    );
    // uppercase name rejected
    assert!(ProviderDescriptor::parse("name: Acme\negress:\n  - https://api.acme.test\n").is_err());
    // header auth shape parses; the retired `verify` block is now unknown schema.
    let d = ProviderDescriptor::parse(
        "name: acme\negress:\n  - https://api.acme.test\nauth: header:X-Api-Key\n",
    )
    .unwrap();
    assert_eq!(
        d.auth_shape().unwrap(),
        AuthShape::Header("X-Api-Key".into())
    );
    assert!(ProviderDescriptor::parse(
        "name: acme\negress:\n  - https://api.acme.test\nverify:\n  endpoint: /me\n",
    )
    .is_err());
}

#[test]
fn moneypath_stripe_descriptor_pins_the_reviewed_api_version() {
    let stripe = VENDORED_PROVIDERS
        .iter()
        .map(|doc| ProviderDescriptor::parse(doc).unwrap())
        .find(|descriptor| descriptor.name == "stripe")
        .unwrap();
    assert_eq!(
        stripe.headers.get("Stripe-Version").map(String::as_str),
        Some(cermet_lang::provider::STRIPE_API_VERSION)
    );
}

const MONEYPATH_EVIDENCE_TEMPLATE: &str = r#"
provider: stripe
action: test_charge_evidence
request_evidence: stripe.test_charge.v1
money:
  preconditions: [test_charge_ready]
fields:
  - { name: charge, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: amount, type: int, required: true, class: side_effect, binding: bounded }
  - { name: account, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: currency, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: mode, type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [charge, amount, account, currency, mode]
execution_targets: [charge, account, currency, mode]
http:
  steps:
    - id: mutate
      method: POST
      path: /v1/test_evidence/{charge}
      body: { amount: "{amount}", account: "{account}", currency: "{currency}", mode: "{mode}" }
      success_statuses: [200]
      require: [id, object, amount, account, currency, livemode]
      expect_eq: { id: charge, amount: amount, account: account, currency: currency }
      expect_literal: { object: charge, livemode: false }
      retention: none
"#;

fn moneypath_resolver_provider(base: String) -> GenericProvider {
    let descriptor = VENDORED_PROVIDERS
        .iter()
        .map(|doc| ProviderDescriptor::parse(doc).unwrap())
        .find(|descriptor| descriptor.name == "stripe")
        .unwrap();
    let registry = Arc::new(TemplateRegistry::new());
    registry.load(MONEYPATH_EVIDENCE_TEMPLATE).unwrap();
    GenericProvider::from_descriptor_with_base(descriptor, base, registry)
}

fn moneypath_resolver_partial(provider: &GenericProvider) -> CanonicalResource {
    provider
        .canonicalize_present_fields(
            "test_charge_evidence",
            &json!({"charge":"ch_ok","amount":2300}),
        )
        .unwrap()
}

fn moneypath_resource() -> CanonicalResource {
    CanonicalResource::from_map(BTreeMap::from([
        ("charge".into(), Scalar::Str("ch_ok".into())),
        ("amount".into(), Scalar::Int(2300)),
        ("account".into(), Scalar::Str("acct_test".into())),
        ("currency".into(), Scalar::Str("usd".into())),
        ("mode".into(), Scalar::Str("test".into())),
    ]))
}

#[test]
fn moneypath_trusted_stripe_resolver_uses_pinned_version_and_returns_only_typed_facts() {
    let (base, server) = two_shot_full(&[
        ("200 OK", r#"{"id":"acct_test","object":"account"}"#),
        (
            "200 OK",
            r#"{"id":"ch_ok","object":"charge","account":"acct_test","currency":"usd","livemode":false,"raw_body_canary":"must_not_escape"}"#,
        ),
    ]);
    let provider = moneypath_resolver_provider(base);
    let partial = moneypath_resolver_partial(&provider);
    // Canonicalization ACCEPTS provider-resolved fields — it also canonicalizes the
    // COMPLETE merged resource at execute/claim, and the symbolic prefilter probes rule-pinned
    // values through it. The request-side refusal of a pre-supplied output is mint's explicit
    // folded-fields check (pinned by moneypath_agent_resolved_field_and_missing_agent_field_
    // deny_before_provider_io).
    assert!(provider
        .canonicalize_present_fields(
            "test_charge_evidence",
            &json!({"charge":"ch_ok","amount":2300,"account":"acct_forged"}),
        )
        .is_ok());
    let resolved = provider
        .resolve_request(
            crate::evidence::profile("stripe.test_charge.v1").unwrap(),
            "sk_test_RESOLVE_SECRET",
            &partial,
        )
        .unwrap();
    assert_eq!(resolved.fields["account"], Scalar::Str("acct_test".into()));
    assert_eq!(resolved.fields["currency"], Scalar::Str("usd".into()));
    assert_eq!(resolved.fields["mode"], Scalar::Str("test".into()));
    assert_eq!(resolved.fields.len(), 3, "raw response keys cannot escape");
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .starts_with("get /v1/account "),
        "{}",
        requests[0]
    );
    assert!(
        requests[1]
            .to_ascii_lowercase()
            .starts_with("get /v1/charges/ch_ok "),
        "{}",
        requests[1]
    );
    for request in &requests {
        let lower = request.to_ascii_lowercase();
        assert!(
            lower.contains("stripe-version: 2026-06-24.dahlia"),
            "{request}"
        );
        assert!(
            lower.contains("authorization: bearer sk_test_resolve_secret"),
            "{request}"
        );
        assert!(!request.contains("raw_body_canary"));
    }
}

#[test]
fn moneypath_money_executor_sends_the_broker_key_only_as_a_stripe_header() {
    let (base, server) = one_shot_full(
        "200 OK",
        r#"{"id":"ch_ok","object":"charge","amount":2300,"account":"acct_test","currency":"usd","livemode":false}"#,
    );
    let provider = moneypath_resolver_provider(base);
    let resource = moneypath_resource();
    let replay_key = "money_key_private_canary";
    let response = provider
        .execute(ProviderCall {
            discipline: proving(replay_key),
            git_mirror: None,
            request_id: "",
            action: "test_charge_evidence",
            token: "sk_test_money_secret",
            resource: &resource,
        })
        .unwrap();
    let outcome = response
        .proof
        .expect("the proving discipline returns an observation");
    assert_eq!(outcome, EffectProof::Proved);
    assert!(
        !response.result.is_null(),
        "the money result is the provider body"
    );
    assert!(response.retained.is_none());

    let request = server.join().unwrap();
    let (headers, body) = request.split_once("\r\n\r\n").unwrap();
    assert!(
        headers
            .to_ascii_lowercase()
            .contains("idempotency-key: money_key_private_canary"),
        "{headers}"
    );
    assert!(
        !body.contains(replay_key),
        "broker key must not enter the body"
    );
}

#[test]
fn moneypath_money_executor_does_not_treat_a_semantic_2xx_failure_as_definite() {
    let (base, server) = one_shot_full("200 OK", r#"{}"#);
    let provider = moneypath_resolver_provider(base);
    let resource = moneypath_resource();
    let response = provider
        .execute(ProviderCall {
            discipline: proving("money_key_private_canary"),
            git_mirror: None,
            request_id: "",
            action: "test_charge_evidence",
            token: "sk_test_money_secret",
            resource: &resource,
        })
        .unwrap();
    let outcome = response
        .proof
        .expect("the proving discipline returns an observation");
    assert!(!response.ok);
    assert_eq!(outcome, EffectProof::Unproved);
    server.join().unwrap();
}

#[test]
fn one_seam_carries_the_discipline_as_data_and_the_plain_hop_carries_none() {
    // The SAME `execute` runs both verbs. What differs is data on the call, and the plain hop
    // must be byte-identical to what it was before the unification: no key header, no proof
    // observation, the transport bit believed.
    let (base, server) = one_shot_full("200 OK", ACME_RICH_BODY);
    let plain = acme_read(&acme_provider_with(base, ACME_READ_TEMPLATE));
    assert!(
        plain.proof.is_none(),
        "a plain hop states no observation about an effect"
    );
    assert!(plain.ok, "a plain hop believes the transport bit");
    let request = server.join().unwrap();
    assert!(
        !request.to_ascii_lowercase().contains("idempotency-key"),
        "the plain discipline mints and sends no key: {request}"
    );

    let resource = moneypath_resource();

    let (base, server) = one_shot_full(
        "200 OK",
        r#"{"id":"ch_ok","object":"charge","amount":2300,"account":"acct_test","currency":"usd","livemode":false}"#,
    );
    let provider = moneypath_resolver_provider(base);
    let proved = provider
        .execute(ProviderCall {
            discipline: proving("cermet_seam_key_canary"),
            git_mirror: None,
            request_id: "",
            action: "test_charge_evidence",
            token: "sk_test_money_secret",
            resource: &resource,
        })
        .unwrap();
    assert_eq!(proved.proof, Some(EffectProof::Proved));
    let request = server.join().unwrap();
    assert!(
        request
            .to_ascii_lowercase()
            .contains("idempotency-key: cermet_seam_key_canary"),
        "{request}"
    );
}

#[test]
fn a_discipline_the_seam_cannot_honour_is_refused_not_downgraded() {
    // T2 (accident): a broker/template disagreement must never run the hop with the discipline
    // silently dropped. An empty key is the reachable shape of that disagreement.
    let (base, _server) = one_shot_full("200 OK", "{}");
    let provider = moneypath_resolver_provider(base);
    let resource = moneypath_resource();
    let refusal = match provider.execute(ProviderCall {
        discipline: ExecutionDiscipline {
            idempotency_key: Some(""),
            prove_effect: true,
        },
        git_mirror: None,
        request_id: "",
        action: "test_charge_evidence",
        token: "sk_test_money_secret",
        resource: &resource,
    }) {
        Ok(_) => panic!("an empty key must never reach the wire"),
        Err(error) => error.to_string(),
    };
    assert!(refusal.contains("empty one"), "{refusal}");
}

#[test]
fn the_outward_ok_bit_is_set_only_from_the_compiled_observation() {
    let response = || ProviderResponse {
        proof: None,
        ok: true,
        failure_class: None,
        result: json!({"unproved":"must_not_escape"}),
        retained: Some(RetainedBody {
            bytes: b"must_not_escape".to_vec(),
            total_bytes: 15,
        }),
        envelope: Default::default(),
    };
    for observed in [EffectProof::Unproved, EffectProof::Refused] {
        let response = response().proved(observed);
        assert_eq!(response.proof, Some(observed));
        // The `ok` bit is normalized from the COMPILED observation, never from the transport bit
        // the adapter set. The body and its retention are no longer touched.
        assert!(!response.ok);
        assert_eq!(response.result, json!({"unproved":"must_not_escape"}));
        assert!(
            response.retained.is_none(),
            "the retention cap of a proving verb is enforced at the custody boundary"
        );
    }

    let response = ProviderResponse {
        proof: None,
        ok: false,
        failure_class: None,
        result: json!({"id":"proved_1", "canary":"must_not_escape"}),
        retained: Some(RetainedBody {
            bytes: b"must_not_escape".to_vec(),
            total_bytes: 15,
        }),
        envelope: Default::default(),
    }
    .proved(EffectProof::Proved);
    assert_eq!(response.proof, Some(EffectProof::Proved));
    assert!(response.ok);
    assert_eq!(
        response.result,
        json!({"id":"proved_1", "canary":"must_not_escape"})
    );
    assert!(
        response.retained.is_none(),
        "the retention cap of a proving verb is enforced at the custody boundary"
    );
}

#[test]
fn moneypath_money_executor_requires_the_exact_raw_success_contract() {
    for (status, body) in [
        (
            "201 Created",
            r#"{"id":"ch_ok","object":"charge","amount":2300,"account":"acct_test","currency":"usd","livemode":false}"#,
        ),
        (
            "200 OK",
            r#"{"id":"ch_ok","object":"refund","amount":2300,"account":"acct_test","currency":"usd","livemode":false}"#,
        ),
        (
            "200 OK",
            r#"{"id":"ch_other","object":"charge","amount":2300,"account":"acct_test","currency":"usd","livemode":false}"#,
        ),
        (
            "200 OK",
            r#"{"id":"ch_ok","object":"charge","amount":2300,"account":"acct_other","currency":"usd","livemode":false}"#,
        ),
        (
            "200 OK",
            r#"{"id":"ch_ok","object":"charge","amount":2300,"account":"acct_test","currency":"eur","livemode":false}"#,
        ),
        (
            "200 OK",
            r#"{"id":"ch_ok","object":"charge","amount":2300,"account":"acct_test","currency":"usd","livemode":true}"#,
        ),
        (
            "200 OK",
            r#"{"id":"ch_ok","object":"charge","amount":2300,"account":"acct_test","currency":"usd"}"#,
        ),
        (
            "200 OK",
            r#"{"id":"ch_ok","object":"charge","amount":2299,"account":"acct_test","currency":"usd","livemode":false}"#,
        ),
    ] {
        let (base, server) = one_shot_full(status, body);
        let provider = moneypath_resolver_provider(base);
        let response = provider
            .execute(ProviderCall {
                discipline: proving("money_key_private_canary"),
                git_mirror: None,
                request_id: "",
                action: "test_charge_evidence",
                token: "sk_test_money_secret",
                resource: &moneypath_resource(),
            })
            .unwrap();
        let outcome = response
            .proof
            .expect("the proving discipline returns an observation");
        assert_eq!(outcome, EffectProof::Unproved, "{status}: {body}");
        server.join().unwrap();
    }
}

#[test]
fn moneypath_money_executor_classifies_malformed_raw_json_ambiguous_and_value_free() {
    let cases: &[(&str, &'static [u8])] = &[
        (
            "non-UTF8",
            b"{\"id\":\"ch_ok\",\"object\":\"charge\",\"amount\":2300,\"account\":\"acct_test\",\"currency\":\"usd\",\"livemode\":false,\"note\":\"\xff\"}",
        ),
        (
            "duplicate top-level discriminator",
            b"{\"id\":\"ch_ok\",\"object\":\"refund\",\"object\":\"charge\",\"amount\":2300,\"account\":\"acct_test\",\"currency\":\"usd\",\"livemode\":false}",
        ),
        (
            "duplicate top-level resource equality",
            b"{\"id\":\"ch_other\",\"id\":\"ch_ok\",\"object\":\"charge\",\"amount\":2300,\"account\":\"acct_test\",\"currency\":\"usd\",\"livemode\":false}",
        ),
        (
            "duplicate nested discriminator",
            b"{\"id\":\"ch_ok\",\"object\":\"charge\",\"amount\":2300,\"account\":\"acct_test\",\"currency\":\"usd\",\"livemode\":false,\"nested\":{\"object\":\"refund\",\"object\":\"charge\"}}",
        ),
        (
            "duplicate nested resource equality",
            b"{\"id\":\"ch_ok\",\"object\":\"charge\",\"amount\":2300,\"account\":\"acct_test\",\"currency\":\"usd\",\"livemode\":false,\"nested\":{\"id\":\"ch_other\",\"id\":\"ch_ok\"}}",
        ),
        (
            "trailing content",
            b"{\"id\":\"ch_ok\",\"object\":\"charge\",\"amount\":2300,\"account\":\"acct_test\",\"currency\":\"usd\",\"livemode\":false} trailing",
        ),
    ];

    for (label, body) in cases {
        let (base, server) = one_shot_full_bytes("200 OK", body);
        let provider = moneypath_resolver_provider(base);
        let response = provider
            .execute(ProviderCall {
                discipline: proving("money_key_private_canary"),
                git_mirror: None,
                request_id: "",
                action: "test_charge_evidence",
                token: "sk_test_money_secret",
                resource: &moneypath_resource(),
            })
            .unwrap();
        let outcome = response
            .proof
            .expect("the proving discipline returns an observation");
        assert_eq!(outcome, EffectProof::Unproved, "{label}");
        assert!(!response.ok, "{label}");
        // A body we could not parse is not a body we can hand back; `ambiguous` is exactly what
        // the verified-rejection contract reserves for it, and the delivered status is still
        // recorded as evidence.
        assert_eq!(response.result["status"], json!(200), "{label}");
        assert!(
            response.result.get("id").is_none(),
            "no provider field can be invented from bytes we could not read: {label}"
        );
        assert!(response.retained.is_none(), "{label}");
        server.join().unwrap();
    }
}

#[test]
fn moneypath_preconditions_reject_non_utf8_and_duplicate_json_value_free() {
    let cases: &[(&str, &'static [u8])] = &[
        (
            "non-UTF8",
            b"{\"id\":\"ch_ok\",\"object\":\"charge\",\"amount\":2300,\"amount_refunded\":0,\"account\":\"acct_test\",\"note\":\"\xff\"}",
        ),
        (
            "duplicate top-level discriminator",
            b"{\"id\":\"ch_ok\",\"object\":\"refund\",\"object\":\"charge\",\"amount\":2300,\"amount_refunded\":0,\"account\":\"acct_test\"}",
        ),
        (
            "duplicate top-level resource equality",
            b"{\"id\":\"ch_other\",\"id\":\"ch_ok\",\"object\":\"charge\",\"amount\":2300,\"amount_refunded\":0,\"account\":\"acct_test\"}",
        ),
        (
            "duplicate nested discriminator",
            b"{\"id\":\"ch_ok\",\"object\":\"charge\",\"amount\":2300,\"amount_refunded\":0,\"account\":\"acct_test\",\"nested\":{\"object\":\"refund\",\"object\":\"charge\"}}",
        ),
        (
            "duplicate nested resource equality",
            b"{\"id\":\"ch_ok\",\"object\":\"charge\",\"amount\":2300,\"amount_refunded\":0,\"account\":\"acct_test\",\"nested\":{\"id\":\"ch_other\",\"id\":\"ch_ok\"}}",
        ),
    ];

    for (label, body) in cases {
        let (base, server) = one_shot_full_bytes("200 OK", body);
        let provider = moneypath_resolver_provider(base);
        let precondition =
            crate::preconditions::exact("stripe", "test_charge_evidence", "test_charge_ready")
                .unwrap();
        let failure = provider
            .check_preconditions(
                &[precondition],
                "sk_test_money_secret",
                &moneypath_resource(),
            )
            .expect_err("malformed provider JSON must deny the precondition");
        assert_eq!(failure.name, "test_charge_ready", "{label}");
        assert_eq!(
            failure.class,
            crate::preconditions::PreconditionFailureClass::ProviderUnavailable,
            "{label}"
        );
        server.join().unwrap();
    }
}

/// End to end: the tee is a SECOND output channel next to the receipt/audit/artifact
/// path, and the money hardening that folds the idempotency key into the broker's redaction set
/// must also reach it. Stripe echoes that key back in its own `idempotency_error` bodies, so this is
/// the realistic shape. Armed against a temp file, run a real money execution, read the file.
/// The response contract says a template "never edits the response", and the wire-tee
/// comparison says receipt result == artifact == teed body EXACTLY. Two paths broke that by
/// ADDING keys to the provider's own JSON after the artifact bytes were already taken from the
/// untouched body: `result_captures` on setup verbs, and the GraphQL `outcome` classification.
/// Augmentation is still editing — the divergence it creates is the exact one the tee exists to
/// catch. Both now ride a SIBLING envelope, so the provider's object is literally untouched.
#[test]
fn result_captures_ride_a_sibling_envelope_not_the_provider_body() {
    const TEMPLATE: &str = r#"
provider: stripe
action: fixture_envelope_probe_create
fields:
  - { name: account, type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [account]
execution_targets: [account]
http:
  steps:
    - id: look
      method: GET
      path: /v1/accounts/{account}/probes
      success_statuses: [200]
      require: [id]
      capture: { seen: "$.id" }
    - id: make
      method: POST
      path: /v1/probes
      success_statuses: [200]
      require: [object]
      result_captures: { seen_probe: seen }
"#;
    const LOOKED: &str = r#"{"id":"probe_1","object":"probe"}"#;
    const READ: &str = r#"{"object":"probe","data":[{"id":"probe_2"}]}"#;
    let (base, server) = two_shot_full(&[("200 OK", LOOKED), ("200 OK", READ)]);
    let descriptor = ProviderDescriptor::parse(
        "name: stripe\negress:\n  - https://api.stripe.com\nauth: bearer\n",
    )
    .unwrap();
    let registry = Arc::new(TemplateRegistry::new());
    registry.load(TEMPLATE).expect("the probe template loads");
    let provider = GenericProvider::from_descriptor_with_base(descriptor, base, registry);
    let resource = provider
        .canonicalize(
            "fixture_envelope_probe_create",
            &json!({"account":"acct_1"}),
        )
        .unwrap();
    let response = provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "fixture_envelope_probe_create",
            token: "sk_test_probe",
            resource: &resource,
        })
        .unwrap();
    server.join().unwrap();

    assert!(response.ok);
    assert_eq!(
        response.result,
        serde_json::from_str::<Value>(READ).unwrap(),
        "the provider's terminal body is untouched — no capture key was inserted into it"
    );
    assert_eq!(
        response.envelope.get("seen_probe"),
        Some(&json!("probe_1")),
        "the capture rides the sibling envelope: {:?}",
        response.envelope
    );
    let retained = response.retained.expect("a default-retention step retains");
    assert_eq!(
        serde_json::from_slice::<Value>(&retained.bytes).unwrap(),
        response.result,
        "receipt result == stored artifact, which is what the wire-tee comparison asserts"
    );
}

#[test]
fn the_wire_tee_redacts_the_money_idempotency_key_it_could_see_echoed() {
    const KEY: &str = "money_key_private_canary";
    const TOKEN: &str = "sk_test_money_secret";
    let body = format!(
        r#"{{"error":{{"type":"idempotency_error","message":"Key={KEY} was reused","code":"x"}}}}"#
    );
    let dir = tempfile::tempdir().expect("tee dir");
    let tee = dir.path().join("wire.jsonl");
    let _armed = crate::wiretap::ArmedTee::at(&tee);

    let (base, server) = one_shot_full_owned("400 Bad Request", body.clone().into_bytes());
    let provider = moneypath_resolver_provider(base);
    let resource = moneypath_resource();
    let response = provider
        .execute(ProviderCall {
            discipline: proving(KEY),
            git_mirror: None,
            request_id: "",
            action: "test_charge_evidence",
            token: TOKEN,
            resource: &resource,
        })
        .unwrap();
    server.join().unwrap();

    let teed = std::fs::read_to_string(&tee).expect("the armed tee wrote a line");
    assert!(
        teed.contains("idempotency_error"),
        "the tee recorded the body it was supposed to: {teed}"
    );
    assert!(
        !teed.contains(KEY),
        "the money idempotency key reached the tee file: {teed}"
    );
    assert!(
        !teed.contains(TOKEN),
        "the vault credential reached the tee file: {teed}"
    );
    // Layer note, pinned so the tee fix is not mistaken for the thing that protects the receipt:
    // at the PROVIDER layer the echoed key is still in the body, because the response contract is
    // verbatim. What removes it from the agent-facing result, the audit record, and the artifact is
    // the broker's own redaction set (`broker/execute.rs`, which folds the idempotency key in
    // alongside the vault secrets). The tee bypasses that pass entirely — which is exactly why it
    // needed its own, and why the assertions above are the ones that matter.
    assert!(
        response.result.to_string().contains(KEY),
        "the verbatim provider result carries what the provider sent; the BROKER redacts it"
    );
}

#[test]
fn moneypath_money_executor_draws_the_verified_rejection_line_at_409() {
    // The verified-rejection path widens for a CLEAN TYPED 4xx answered to our
    // idempotency-keyed request means the API refused the call before touching the ledger, so the
    // effect is `definitely_failed`. `ambiguous` is reserved for genuinely unverifiable outcomes.
    //
    // 409 is the line. Stripe answers a request whose idempotency key is ALREADY IN FLIGHT with
    // 409 — the sibling request holding that key may be succeeding at this very moment, which is
    // exactly the unverifiable case. It stays ambiguous, by name, in the compiled rejection shape.
    for (status, body, expected, why) in [
        (
            "400 Bad Request",
            r#"{"error":{"type":"invalid_request_error","code":"amount_too_large"}}"#,
            EffectProof::Refused,
            "a typed validation refusal never reached the ledger",
        ),
        (
            "402 Payment Required",
            r#"{"error":{"type":"card_error","code":"card_declined"}}"#,
            EffectProof::Refused,
            "a decline is a refusal, not an unknown",
        ),
        (
            "429 Too Many Requests",
            r#"{"error":{"type":"rate_limit_error"}}"#,
            EffectProof::Refused,
            "a throttled request is rejected at the edge, unprocessed",
        ),
        (
            "409 Conflict",
            r#"{"error":{"type":"idempotency_error"}}"#,
            EffectProof::Unproved,
            "a live same-key sibling request may be succeeding right now",
        ),
        (
            "400 Bad Request",
            r#"{"oops":"an untyped refusal we cannot classify"}"#,
            EffectProof::Unproved,
            "no `error.type` means no verified rejection; fail closed",
        ),
        (
            "500 Internal Server Error",
            r#"{"error":{"type":"api_error"}}"#,
            EffectProof::Unproved,
            "a 5xx says nothing about whether the effect landed",
        ),
    ] {
        let (base, server) = one_shot_full(status, body);
        let provider = moneypath_resolver_provider(base);
        let resource = moneypath_resource();
        let response = provider
            .execute(ProviderCall {
                discipline: proving("money_key_private_canary"),
                git_mirror: None,
                request_id: "",
                action: "test_charge_evidence",
                token: "sk_test_money_secret",
                resource: &resource,
            })
            .unwrap();
        let outcome = response
            .proof
            .expect("the proving discipline returns an observation");
        assert_eq!(outcome, expected, "{status}: {why}");
        // Whichever way it classified, the evidence survives.
        assert_eq!(
            response.result["error"],
            serde_json::from_str::<Value>(body).unwrap(),
            "{status}: the provider's own answer must reach the receipt"
        );
        server.join().unwrap();
    }
}

#[test]
fn moneypath_stripe_resolver_rejects_charge_account_mismatch() {
    let (base, _server) = two_shot_full(&[
        ("200 OK", r#"{"id":"acct_connected","object":"account"}"#),
        (
            "200 OK",
            r#"{"id":"ch_ok","object":"charge","account":"acct_other","currency":"usd","livemode":false}"#,
        ),
    ]);
    let provider = moneypath_resolver_provider(base);
    let partial = moneypath_resolver_partial(&provider);
    let failure = provider
        .resolve_request(
            crate::evidence::profile("stripe.test_charge.v1").unwrap(),
            "sk_test_RESOLVE_SECRET",
            &partial,
        )
        .unwrap_err();
    assert_eq!(failure.class, EvidenceFailureClass::Mismatch);
}

#[test]
fn moneypath_stripe_resolver_rejects_response_id_mismatch() {
    let (base, _server) = two_shot_full(&[
        ("200 OK", r#"{"id":"acct_test","object":"account"}"#),
        (
            "200 OK",
            r#"{"id":"ch_other","object":"charge","currency":"usd","livemode":false}"#,
        ),
    ]);
    let provider = moneypath_resolver_provider(base);
    let failure = provider
        .resolve_request(
            crate::evidence::profile("stripe.test_charge.v1").unwrap(),
            "sk_test_RESOLVE_SECRET",
            &moneypath_resolver_partial(&provider),
        )
        .unwrap_err();
    assert_eq!(failure.class, EvidenceFailureClass::Mismatch);
}

#[test]
fn moneypath_stripe_resolver_requires_exact_200_and_charge_discriminator() {
    for responses in [
        [
            ("201 Created", r#"{"id":"acct_test","object":"account"}"#),
            (
                "200 OK",
                r#"{"id":"ch_ok","object":"charge","currency":"usd","livemode":false}"#,
            ),
        ],
        [
            ("200 OK", r#"{"id":"acct_test","object":"account"}"#),
            (
                "201 Created",
                r#"{"id":"ch_ok","object":"charge","currency":"usd","livemode":false}"#,
            ),
        ],
        [
            ("200 OK", r#"{"id":"acct_test","object":"account"}"#),
            (
                "200 OK",
                r#"{"id":"ch_ok","object":"refund","currency":"usd","livemode":false}"#,
            ),
        ],
    ] {
        let (base, _server) = two_shot_full(Box::leak(Box::new(responses)));
        let provider = moneypath_resolver_provider(base);
        let failure = provider
            .resolve_request(
                crate::evidence::profile("stripe.test_charge.v1").unwrap(),
                "sk_test_RESOLVE_SECRET",
                &moneypath_resolver_partial(&provider),
            )
            .unwrap_err();
        assert_eq!(failure.class, EvidenceFailureClass::Malformed);
    }
}

#[test]
fn moneypath_stripe_resolver_requires_three_lowercase_ascii_currency_bytes() {
    for currency in ["us", "usdd", "u1d", "USD"] {
        let charge = Box::leak(
            format!(
                r#"{{"id":"ch_ok","object":"charge","currency":"{currency}","livemode":false}}"#
            )
            .into_boxed_str(),
        );
        let responses = Box::leak(Box::new([
            ("200 OK", r#"{"id":"acct_test","object":"account"}"#),
            ("200 OK", &*charge),
        ]));
        let (base, _server) = two_shot_full(responses);
        let provider = moneypath_resolver_provider(base);
        let failure = provider
            .resolve_request(
                crate::evidence::profile("stripe.test_charge.v1").unwrap(),
                "sk_test_RESOLVE_SECRET",
                &moneypath_resolver_partial(&provider),
            )
            .unwrap_err();
        assert_eq!(failure.class, EvidenceFailureClass::Malformed);
    }
}

#[test]
fn auth_header_is_built_per_the_descriptor_shape() {
    // Each auth shape produces exactly its declared header — never a hardcoded Bearer.
    for (auth, needle, forbidden) in [
        ("token", "authorization: token acme_tok_secret_9", "bearer"),
        (
            "header:X-Api-Key",
            "x-api-key: acme_tok_secret_9",
            "authorization:",
        ),
    ] {
        let (base, server) = one_shot_full("200 OK", r#"{"name":"widget","secret_field":"x"}"#);
        let p = acme_provider(base, auth);
        let resource = p
            .canonicalize("read_thing", &json!({ "id": "widget" }))
            .unwrap();
        let resp = p
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "read_thing",
                token: "acme_tok_secret_9",
                resource: &resource,
            })
            .unwrap();
        let req = server.join().unwrap().to_lowercase();
        assert!(
            req.contains(needle),
            "auth `{auth}` must send `{needle}`: {req}"
        );
        assert!(
            !req.contains(forbidden),
            "auth `{auth}` must NOT send `{forbidden}`: {req}"
        );
        assert!(
            req.contains("x-extra: v1"),
            "the descriptor's static header rides too"
        );
        assert!(resp.ok);
        assert_eq!(
            resp.result,
            json!({ "name": "widget", "secret_field": "x" }),
            "the response is the provider body; this test owns the AUTH header, not projection"
        );
        assert!(!serde_json::to_string(&resp.result)
            .unwrap()
            .contains("acme_tok_secret_9"));
    }
}

#[test]
fn token_never_rides_to_a_non_pinned_origin() {
    // A provider built purely from a descriptor pins ONLY the descriptor's origin; a request to any
    // other origin is refused BEFORE the auth header is built, so the token never rides off-origin.
    let d =
        ProviderDescriptor::parse("name: acme\negress:\n  - https://api.acme.test\nauth: bearer\n")
            .unwrap();
    let mut set = HashSet::new();
    set.insert("acme".to_string());
    let p = GenericProvider::from_descriptor(
        d,
        Arc::new(TemplateRegistry::with_providers(set)),
        crate::git::GitConfig::at(std::env::temp_dir()),
    );
    let token = "acme_secret_TOKEN_must_not_leak";
    let msg = match http_call(
        &p.egress,
        Method::GET,
        "http://evil.test/things/x".to_string(),
        token,
        None,
        &[],
        &p.auth,
        &[],
    ) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("an off-origin request must be refused pre-send"),
    };
    assert!(
        msg.to_lowercase().contains("egress"),
        "egress-block error: {msg}"
    );
    assert!(
        !msg.contains(token),
        "the token must never appear in the refusal: {msg}"
    );
    // The pinned origin itself is allowed by the guard.
    assert!(p.egress.allows("https://api.acme.test/things/x"));
    assert!(
        !p.egress.allows("http://api.acme.test/things/x"),
        "scheme drift is a different origin"
    );
}

// ---- GitHub guarded-write action templates (create_branch, create_issue, comment_thread,
// create_pull_request_review, read_workflow_run, request_workflow_cancel, request_deployment).
// Red/fail-closed WIRE tests: every non-2xx / precondition / closed-schema violation must fail
// closed (resp.ok == false or an Err at canonicalize), never silently mutate. ----

/// A valid 40-hex Git OID (canonical lowercase). Kept as a const so the same value can be a
/// static response-body literal AND a canonicalize input without runtime formatting. (The
/// contrasting "different head" value is the inline 40-`b` literal in the mismatch test's GET
/// response body.)
const M3_OID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// One provider carrying the ratified guarded-write and verb-corpus GitHub templates.
fn github_m3(base: String) -> GenericProvider {
    let reg = Arc::new(TemplateRegistry::new());
    for doc in [
        include_str!("../../actions/github.create_branch.yaml"),
        include_str!("../../actions/github.create_issue.yaml"),
        include_str!("../../actions/github.comment_thread.yaml"),
        include_str!("../../actions/github.create_pull_request_review.yaml"),
        include_str!("../../actions/github.read_workflow_run.yaml"),
        include_str!("../../actions/github.read_workflow_run_jobs.yaml"),
        include_str!("../../actions/github.read_job_log.yaml"),
        include_str!("../../actions/github.request_workflow_cancel.yaml"),
        include_str!("../../actions/github.dispatch_workflow.yaml"),
        include_str!("../../actions/github.request_deployment.yaml"),
        include_str!("../../actions/github.create_pull_request.yaml"),
        include_str!("../../actions/github.read_secret_scanning_alerts_open.yaml"),
        include_str!("../../actions/github.merge_pull_request.yaml"),
        include_str!("../../actions/github.update_pull_request.yaml"),
    ] {
        reg.load(doc).expect("a github template loads");
    }
    GithubProvider::with_base_and_templates(base, reg)
}

#[test]
fn corpus_secret_alert_read_drops_literal_secrets_and_retains_nothing() {
    const LEAKED: &str = "ghp_FIXTURELEAKEDLITERALxxxxxxxx";
    let body = format!(
        r#"[{{"number":7,"state":"open","secret_type":"github_personal_access_token","secret_type_display_name":"GitHub Personal Access Token","secret":"{LEAKED}","created_at":"2026-07-22T00:00:00Z","html_url":"https://github.com/acme/website/security/secret-scanning/7","locations_url":"https://api.github.com/locations","validity":"active"}}]"#
    );
    let (base, server) = one_shot_full("200 OK", Box::leak(body.into_boxed_str()));
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "read_secret_scanning_alerts_open",
            &json!({ "owner": "acme", "name": "website" }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "read_secret_scanning_alerts_open",
            token: "ghp_broker_credential",
            resource: &resource,
        })
        .unwrap();
    let req = server.join().unwrap();

    assert!(
        req.starts_with("GET /repos/acme/website/secret-scanning/alerts?"),
        "{req}"
    );
    assert!(
        req.contains("state=open"),
        "open state is frozen on the wire: {req}"
    );
    assert!(
        req.contains("per_page=30"),
        "the first page is bounded on the wire: {req}"
    );
    assert!(
        req.contains("hide_secret=true"),
        "GitHub must suppress literal secrets: {req}"
    );
    assert!(resp.ok);
    let returned = serde_json::to_string(&resp.result).unwrap();
    // The verbatim contract stands for this verb too. Its `keep` list is
    // gone with every other projection, so a leaked literal GitHub chose to send DOES come back.
    // The surviving defense is request-side and asserted above: the frozen `hide_secret=true`
    // query literal tells GitHub not to send it. `github` is not a product-enabled provider.
    assert!(
        returned.contains(LEAKED),
        "the verbatim contract returns whatever the provider sent: {returned}"
    );
    for present in ["secret", "locations_url", "validity"] {
        assert!(
            resp.result[0].get(present).is_some(),
            "the verbatim response carries the provider's `{present}`"
        );
    }
    assert!(
        resp.retained.is_none(),
        "retention defaults to FULL; the request-side `hide_secret=true` is the bound"
    );
}

#[test]
fn corpus_secret_alert_failure_discards_provider_body() {
    const LEAKED: &str = "ghp_PROVIDER_ERROR_ECHO_LITERAL";
    let (base, server) = one_shot_full(
        "403 Forbidden",
        r#"{"message":"alert ghp_PROVIDER_ERROR_ECHO_LITERAL cannot be read"}"#,
    );
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "read_secret_scanning_alerts_open",
            &json!({ "owner": "acme", "name": "website" }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "read_secret_scanning_alerts_open",
            token: "ghp_broker_credential",
            resource: &resource,
        })
        .unwrap();
    let _ = server.join().unwrap();
    let result = serde_json::to_string(&resp.result).unwrap();

    assert!(!resp.ok);
    assert_eq!(resp.result["status"], json!(403));
    assert!(
        result.contains(LEAKED) && result.contains("message"),
        "the failure envelope carries the provider's error body verbatim: {result}"
    );
    assert!(resp.retained.is_none());
}

#[test]
fn corpus_pr_posts_the_frozen_draft_choice_either_way() {
    // `draft` is a DECLARED field, so the wire carries the
    // value the approver froze — true or false. The old frozen-`draft: true` literal and its
    // expect_literal postcondition are gone: draft-only is sentence policy (`where draft = true`),
    // not a vendored template's opinion.
    for (draft, body_json) in [
        (true, r#"{"id":9,"number":4,"draft":true}"#),
        (false, r#"{"id":9,"number":4,"draft":false}"#),
    ] {
        let (base, server) = one_shot_full_owned("201 Created", body_json.as_bytes().to_vec());
        let gh = github_m3(base);
        let resource = gh
            .canonicalize(
                "create_pull_request",
                &json!({
                    "owner": "acme", "name": "website", "base": "main", "head": "feature",
                    "draft": draft, "title": "Change", "body": "Review context"
                }),
            )
            .unwrap();
        let resp = gh
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "create_pull_request",
                token: "ghp_broker_credential",
                resource: &resource,
            })
            .unwrap();
        let req = server.join().unwrap();
        let sent: Value = serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert!(req.starts_with("POST /repos/acme/website/pulls "), "{req}");
        assert_eq!(
            sent,
            json!({
                "title": "Change",
                "body": "Review context",
                "head": "feature",
                "base": "main",
                "draft": draft
            }),
            "the frozen draft choice is what reaches the wire"
        );
        // Verbatim response, and a provider-reported draft that differs from the request is NOT a
        // postcondition failure any more — GitHub is the authority on what it created.
        assert!(resp.ok);
        assert_eq!(resp.result["number"], json!(4));
        assert!(resp.retained.is_some());
    }
}

#[test]
fn corpus_pr_requires_a_draft_choice_and_a_same_repository_head() {
    let gh = github_m3("http://127.0.0.1:9".into());
    // `draft` is REQUIRED: there is no template default an agent could inherit silently.
    assert!(
        gh.canonicalize(
            "create_pull_request",
            &json!({
                "owner": "acme", "name": "website", "base": "main", "head": "feature",
                "title": "Change", "body": "Review context"
            }),
        )
        .is_err(),
        "an absent draft choice must be refused, never defaulted"
    );
    for bad in [
        "fork-owner:feature",
        "refs/heads/feature",
        "feature..bad",
        "-feature",
    ] {
        assert!(
            gh.canonicalize(
                "create_pull_request",
                &json!({
                    "owner": "acme", "name": "website", "base": "main", "head": bad,
                    "draft": true, "title": "Change", "body": "Review context"
                }),
            )
            .is_err(),
            "same-repository PR must reject head `{bad}`"
        );
    }
}

// 1. create_branch happy path: POST git/refs carrying the frozen new_ref + source_oid.
#[test]
fn create_branch_happy_path_posts_frozen_ref_and_oid() {
    let (base, server) = one_shot_full(
        "201 Created",
        r#"{"ref":"refs/heads/feature","object":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":"commit"}}"#,
    );
    let gh = github_m3(base);
    let resource = gh
            .canonicalize(
                "create_branch",
                &json!({ "owner": "acme", "name": "website", "new_ref": "refs/heads/feature", "source_oid": M3_OID_A }),
            )
            .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "create_branch",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let req = server.join().unwrap();
    assert!(
        req.starts_with("POST /repos/acme/website/git/refs"),
        "create lands on the frozen repo's refs endpoint: {req}"
    );
    assert!(
        req.contains(r#""ref":"refs/heads/feature""#),
        "the fully-qualified new_ref rides the body: {req}"
    );
    assert!(
        req.contains(&format!(r#""sha":"{M3_OID_A}""#)),
        "the exact source_oid rides the body: {req}"
    );
    assert!(resp.ok, "a 201 is the created evidence");
}

// 2. create_branch on an EXISTING ref → GitHub 422 → fail closed (never silently move a branch).
#[test]
fn create_branch_existing_ref_fails_closed_422() {
    let (base, server) = one_shot_full(
        "422 Unprocessable Entity",
        r#"{"message":"Reference already exists"}"#,
    );
    let gh = github_m3(base);
    let resource = gh
            .canonicalize(
                "create_branch",
                &json!({ "owner": "acme", "name": "website", "new_ref": "refs/heads/feature", "source_oid": M3_OID_A }),
            )
            .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "create_branch",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let _ = server.join().unwrap();
    assert!(
        !resp.ok,
        "a 422 (ref exists) must fail closed, never silently re-point the branch"
    );
}

// 3. create_branch refuses a branch NAME as source_oid at canonicalize (git_oid admission).
#[test]
fn create_branch_rejects_branch_name_as_source_oid() {
    let gh = github_m3("http://127.0.0.1:9".into());
    assert!(
            gh.canonicalize(
                "create_branch",
                &json!({ "owner": "acme", "name": "website", "new_ref": "refs/heads/feature", "source_oid": "main" }),
            )
            .is_err(),
            "a create must anchor at an immutable OID, never a moving ref name"
        );
}

// 4. request_workflow_cancel run/head MISMATCH → fail closed with NO cancel POST (proof
//    that head_sha is a GENUINELY executed pin, not merely an approved one). ONE connection only
//    (the GET): if execute wrongly proceeded to the cancel POST, the second connect would be
//    refused and execute would Err — so an Ok(ok:false) here proves step 2 never fired. (Same
//    short-circuit shape as `two_step_write_get_error_short_circuits_the_put_fail_closed`.)
#[test]
fn request_workflow_cancel_head_mismatch_fails_closed_no_cancel_post() {
    let (base, server) = one_shot_full(
        "200 OK",
        r#"{"head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","status":"in_progress"}"#,
    );
    let gh = github_m3(base);
    // The approved pin is a DIFFERENT 40-hex than the run's observed head.
    let resource = gh
        .canonicalize(
            "request_workflow_cancel",
            &json!({ "owner": "acme", "name": "website", "run_id": "42", "head_sha": M3_OID_A }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "request_workflow_cancel",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let req = server.join().unwrap();
    assert!(
        !resp.ok,
        "an observed-head drift must fail closed BEFORE any cancel"
    );
    assert_eq!(resp.result["outcome"], json!("precondition_failed"));
    assert_eq!(resp.result["field"], json!("head_sha"));
    assert!(
        req.starts_with("GET /repos/acme/website/actions/runs/42"),
        "the ONLY request that fired was the verify GET — the cancel POST never ran: {req}"
    );
}

// 5. request_workflow_cancel happy path: head match → GET then cancel POST 202. This is the
// positive control: on a genuine head match the verification GET passes and the cancel POST
// fires. (It caught a real hollow-pin bug: `expect_eq` keys are BARE dotted paths but the executor
// had resolved them with the `$.`-rooted `capture_lookup`, so a match could NEVER succeed; fixed by
// resolving `expect_eq` via the bare-path `dotted_lookup`, provider.rs.)
#[test]
fn request_workflow_cancel_head_match_posts_cancel_202() {
    let (base, server) = two_shot_full(&[
        (
            "200 OK",
            r#"{"head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"in_progress"}"#,
        ),
        ("202 Accepted", ""),
    ]);
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "request_workflow_cancel",
            &json!({ "owner": "acme", "name": "website", "run_id": "42", "head_sha": M3_OID_A }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "request_workflow_cancel",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let reqs = server.join().unwrap();
    assert!(resp.ok, "head match + 202 is the accepted evidence");
    assert_eq!(
        reqs.len(),
        2,
        "guarded write is verify-GET then cancel-POST"
    );
    assert!(
        reqs[0].starts_with("GET /repos/acme/website/actions/runs/42"),
        "step 1 verifies the observed head: {}",
        reqs[0]
    );
    assert!(
        reqs[1].starts_with("POST /repos/acme/website/actions/runs/42/cancel"),
        "step 2 cancels only the exact frozen run: {}",
        reqs[1]
    );
}

// 6. request_workflow_cancel head match but run already TERMINAL → GitHub 409 → fail closed. The
// head match now passes (dotted_lookup fix), so the cancel POST fires and its 409 is surfaced as a
// fail-closed result — a run that is already terminal is never reported as cancelled.
#[test]
fn request_workflow_cancel_already_terminal_fails_closed_409() {
    let (base, server) = two_shot_full(&[
        (
            "200 OK",
            r#"{"head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"in_progress"}"#,
        ),
        (
            "409 Conflict",
            r#"{"message":"Cannot cancel a workflow run that is completed"}"#,
        ),
    ]);
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "request_workflow_cancel",
            &json!({ "owner": "acme", "name": "website", "run_id": "42", "head_sha": M3_OID_A }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "request_workflow_cancel",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let _ = server.join().unwrap();
    assert!(!resp.ok, "a 409 (already terminal) must fail closed");
}

// 6b. `dispatch_workflow` starts a run of ONE named workflow FILE on ONE named ref. GitHub's
// endpoint takes a branch OR a tag name, so the `ref` constraint must admit both —
// `git_branch_name`'s predicate is git's own check-ref-format on a bare ref COMPONENT, which is
// exactly that. What it still refuses is the qualified `refs/...` spelling (so one ref has one pin
// string) and the cross-repository `user:ref` form.
#[test]
fn dispatch_workflow_ref_admits_a_tag_and_refuses_a_qualified_or_cross_repo_ref() {
    let gh = github_m3("http://127.0.0.1:9".into());
    let canon = |r#ref: &str| {
        gh.canonicalize(
            "dispatch_workflow",
            &json!({ "owner": "acme", "name": "website", "workflow": "release.yml", "ref": r#ref }),
        )
    };
    for good in ["main", "v0.1.0", "release/2026-08", "1.0"] {
        assert!(
            canon(good).is_ok(),
            "`{good}` is a legal bare branch-or-tag name for a dispatch"
        );
    }
    for bad in [
        "refs/heads/main",
        "refs/tags/v0.1.0",
        "octocat:main",
        "-main",
        "a..b",
        "x.lock",
        "a b",
        "",
    ] {
        assert!(
            canon(bad).is_err(),
            "ref `{bad}` must be refused at admission"
        );
    }
}

// 6c. The dispatch happy path, DOCUMENTED arm: exactly ONE POST to the frozen workflow file's
// dispatches endpoint, carrying the frozen ref as its body, and 204 No Content accepted with no
// body at all (the status IS the receipt). This arm stays intact alongside the live-observed 200
// arm below — and it is precisely this arm that a `require` would break, since a 204's empty body
// parses to JSON null and no proof path can resolve against it.
#[test]
fn dispatch_workflow_posts_the_frozen_ref_and_accepts_the_documented_204() {
    let (base, server) = one_shot_full("204 No Content", "");
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "dispatch_workflow",
            &json!({ "owner": "acme", "name": "website", "workflow": "release.yml", "ref": "v0.1.0" }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "dispatch_workflow",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let req = server.join().unwrap();
    assert!(resp.ok, "204 is the accepted evidence: {:?}", resp.result);
    assert!(
        req.starts_with("POST /repos/acme/website/actions/workflows/release.yml/dispatches"),
        "one POST, no guard read, targeting exactly the frozen repository and workflow file: {req}"
    );
    assert!(
        req.contains(r#""ref":"v0.1.0""#),
        "the frozen ref rides the body: {req}"
    );
}

// 6d. The LIVE-OBSERVED arm. GitHub's reference documents a 204, but a real dispatch came back 200
// carrying a JSON body that NAMES the run it had just started — and the verb failed closed on the
// mismatch while the run was already going. Both statuses are success now, and the 200 body rides
// back verbatim under the default `retention: full`, so the receipt itself carries the run id a
// diagnosis would otherwise have to go discover.
#[test]
fn dispatch_workflow_accepts_the_live_200_and_the_receipt_names_the_run_it_started() {
    const BODY: &str = r#"{"workflow_run_id":16789012345,"run_url":"https://api.github.com/repos/acme/website/actions/runs/16789012345","html_url":"https://github.com/acme/website/actions/runs/16789012345"}"#;
    let (base, server) = one_shot_full("200 OK", BODY);
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "dispatch_workflow",
            &json!({ "owner": "acme", "name": "website", "workflow": "release.yml", "ref": "main" }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "dispatch_workflow",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let _ = server.join().unwrap();
    assert!(
        resp.ok,
        "the live 200 is a started run, not a refusal: {:?}",
        resp.result
    );
    assert_eq!(
        resp.result.get("workflow_run_id").and_then(Value::as_u64),
        Some(16789012345),
        "the 200 body is returned verbatim, so the receipt NAMES the run: {:?}",
        resp.result
    );
    let retained = resp
        .retained
        .expect("the default retention stores the body that names the run");
    assert!(
        String::from_utf8(retained.bytes)
            .expect("the retained artifact is the JSON body")
            .contains("16789012345"),
        "the artifact carries the same run id the receipt does"
    );
}

// 6e. Fail-closed discipline for this verb: any status outside the accepted {200, 204} set fails
// closed, so a rejected dispatch can never render as a started run.
#[test]
fn dispatch_workflow_status_outside_the_accepted_set_fails_closed() {
    for (status, body) in [
        ("202 Accepted", "{}"),
        ("404 Not Found", r#"{"message":"Not Found"}"#),
        (
            "422 Unprocessable Entity",
            r#"{"message":"No ref found for: v9.9.9"}"#,
        ),
    ] {
        let (base, server) = one_shot_full(status, body);
        let gh = github_m3(base);
        let resource = gh
            .canonicalize(
                "dispatch_workflow",
                &json!({ "owner": "acme", "name": "website", "workflow": "release.yml", "ref": "main" }),
            )
            .unwrap();
        let resp = gh
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "dispatch_workflow",
                token: "ghp_secret_12345678",
                resource: &resource,
            })
            .unwrap();
        let _ = server.join().unwrap();
        assert!(
            !resp.ok,
            "`{status}` is outside the accepted {{200, 204}} set and must fail closed: {:?}",
            resp.result
        );
    }
}

// 6f. `read_workflow_run_jobs` is the CI-diagnosis read. One bodyless GET at the frozen run's jobs
// endpoint, bounded by the fixed `per_page=50` literal, and the body comes back verbatim — which is
// what makes the FAILING STEP legible without ever fetching a log, since each job carries its own
// `steps` array of names and conclusions.
#[test]
fn read_workflow_run_jobs_gets_the_bounded_page_and_returns_the_step_conclusions() {
    const BODY: &str = r#"{"total_count":2,"jobs":[{"id":51,"name":"build","status":"completed","conclusion":"success","steps":[{"name":"checkout","conclusion":"success","number":1}]},{"id":52,"name":"test","status":"completed","conclusion":"failure","steps":[{"name":"checkout","conclusion":"success","number":1},{"name":"cargo nextest","conclusion":"failure","number":2}]}]}"#;
    let (base, server) = one_shot_full("200 OK", BODY);
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "read_workflow_run_jobs",
            &json!({ "owner": "acme", "name": "website", "run_id": "16789012345" }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "read_workflow_run_jobs",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let req = server.join().unwrap();
    assert!(resp.ok, "the job list is the result: {:?}", resp.result);
    assert!(
        req.starts_with("GET /repos/acme/website/actions/runs/16789012345/jobs?per_page=50"),
        "one bodyless GET at the frozen run, bounded by the fixed page literal: {req}"
    );
    // The whole point of the verb: the failing STEP is named by the projection.
    let failing_step = resp.result["jobs"][1]["steps"][1]["name"].as_str();
    assert_eq!(failing_step, Some("cargo nextest"));
    assert_eq!(
        resp.result["jobs"][1]["conclusion"].as_str(),
        Some("failure")
    );
    assert!(
        resp.retained.is_some(),
        "the default retention stores the job list as an artifact the `artifact` tool can span"
    );
}

// 6g. Fail-closed discipline for the diagnosis read: a 200 that does not carry the two proof keys
// is not a job list, and an empty or reshaped answer must never render as a clean diagnosis.
#[test]
fn read_workflow_run_jobs_without_its_proof_keys_fails_closed() {
    for (status, body) in [
        ("200 OK", r#"{"jobs":[]}"#),
        ("200 OK", r#"{"total_count":0}"#),
        ("404 Not Found", r#"{"message":"Not Found"}"#),
    ] {
        let (base, server) = one_shot_full(status, body);
        let gh = github_m3(base);
        let resource = gh
            .canonicalize(
                "read_workflow_run_jobs",
                &json!({ "owner": "acme", "name": "website", "run_id": "1" }),
            )
            .unwrap();
        let resp = gh
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "read_workflow_run_jobs",
                token: "ghp_secret_12345678",
                resource: &resource,
            })
            .unwrap();
        let _ = server.join().unwrap();
        assert!(
            !resp.ok,
            "`{status}` with body `{body}` must fail closed: {:?}",
            resp.result
        );
    }
}

// 6h. One run, one pin string: `format: uint` admits the canonical bare decimal only, so a padded
// or signed spelling can never be a second pin for the same run.
#[test]
fn read_workflow_run_jobs_run_id_admits_only_the_canonical_uint() {
    let gh = github_m3("http://127.0.0.1:9".into());
    let canon = |run_id: &str| {
        gh.canonicalize(
            "read_workflow_run_jobs",
            &json!({ "owner": "acme", "name": "website", "run_id": run_id }),
        )
    };
    for good in ["1", "16789012345"] {
        assert!(canon(good).is_ok(), "`{good}` is a canonical run id");
    }
    for bad in ["01", "+1", "-1", "1 ", "0x1", "", "1/2"] {
        assert!(
            canon(bad).is_err(),
            "run_id `{bad}` must be refused at admission"
        );
    }
}

// 7. create_pull_request_review carries the FROZEN event choice — whichever one was approved.
#[test]
fn create_pull_request_review_submits_the_frozen_event_choice() {
    // `event` is a DECLARED field. The domain distinction:
    // CERMET's own grant-approval seam stays absolutely non-agent forever; a GitHub review spelled
    // APPROVE is a provider-domain write whose narrowing is the operator's sentence
    // (`... and event = COMMENT`), not a literal frozen into a vendored template.
    for event in ["COMMENT", "APPROVE", "REQUEST_CHANGES"] {
        let (base, server) = one_shot_full_owned(
            "200 OK",
            br#"{"id":901,"html_url":"https://github.com/acme/website/pull/7#pullrequestreview-901"}"#.to_vec(),
        );
        let gh = github_m3(base);
        let resource = gh
            .canonicalize(
                "create_pull_request_review",
                &json!({ "owner": "acme", "name": "website", "number": "7", "commit_id": M3_OID_A, "event": event, "body": "left a note" }),
            )
            .unwrap();
        let resp = gh
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "create_pull_request_review",
                token: "ghp_secret_12345678",
                resource: &resource,
            })
            .unwrap();
        let req = server.join().unwrap();
        assert!(
            req.starts_with("POST /repos/acme/website/pulls/7/reviews"),
            "review lands on the exact PR: {req}"
        );
        assert!(
            req.contains(&format!(r#""event":"{event}""#)),
            "the frozen event is what reaches the wire: {req}"
        );
        assert!(
            req.contains(&format!(r#""commit_id":"{M3_OID_A}""#)),
            "the review is anchored to the exact commit OID: {req}"
        );
        assert!(req.contains(r#""body":"left a note""#), "{req}");
        assert!(resp.ok);
    }
}

// 8. `event` is REQUIRED: a review with no approved event choice is refused at admission, so the
//    value can never be defaulted silently on the agent's behalf.
#[test]
fn create_pull_request_review_requires_an_event_choice() {
    let gh = github_m3("http://127.0.0.1:9".into());
    assert!(
        gh.canonicalize(
            "create_pull_request_review",
            &json!({ "owner": "acme", "name": "website", "number": "7", "commit_id": M3_OID_A, "body": "b" }),
        )
        .is_err(),
        "an absent event must be refused, never defaulted"
    );
}

// 9. request_deployment sends every FROZEN literal, the ref+environment, and OMITS payload.
#[test]
fn request_deployment_sends_frozen_literals_and_omits_payload() {
    let (base, server) = one_shot_full(
        "201 Created",
        r#"{"id":55,"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","task":"deploy","environment":"staging","created_at":"2026-07-20T00:00:00Z","statuses_url":"https://api.github.com/repos/acme/website/deployments/55/statuses"}"#,
    );
    let gh = github_m3(base);
    let resource = gh
            .canonicalize(
                "request_deployment",
                &json!({ "owner": "acme", "name": "website", "ref": M3_OID_A, "environment": "staging" }),
            )
            .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "request_deployment",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let req = server.join().unwrap();
    assert!(
        req.starts_with("POST /repos/acme/website/deployments"),
        "the deployments endpoint: {req}"
    );
    for literal in [
        r#""task":"deploy""#,
        r#""auto_merge":false"#,
        r#""required_contexts":[]"#,
        r#""production_environment":false"#,
        r#""transient_environment":false"#,
    ] {
        assert!(
            req.contains(literal),
            "frozen literal `{literal}` must ride the body: {req}"
        );
    }
    assert!(
        req.contains(&format!(r#""ref":"{M3_OID_A}""#)),
        "the exact commit ref: {req}"
    );
    assert!(
        req.contains(r#""environment":"staging""#),
        "the human-pinned environment: {req}"
    );
    assert!(
        !req.contains(r#""payload""#),
        "no free-form deployment payload channel exists: {req}"
    );
    assert!(resp.ok, "a 201 proves the deployment REQUEST was created");
}

// 10. request_deployment refuses agent-supplied auto_merge / payload at canonicalize — these are
//     frozen literals, never fields, so a closed schema denies the extra keys.
#[test]
fn request_deployment_rejects_agent_supplied_literals() {
    let gh = github_m3("http://127.0.0.1:9".into());
    assert!(
            gh.canonicalize(
                "request_deployment",
                &json!({ "owner": "acme", "name": "website", "ref": M3_OID_A, "environment": "staging", "auto_merge": true }),
            )
            .is_err(),
            "auto_merge is a frozen literal — an agent can never flip it via a field"
        );
    assert!(
            gh.canonicalize(
                "request_deployment",
                &json!({ "owner": "acme", "name": "website", "ref": M3_OID_A, "environment": "staging", "payload": { "x": 1 } }),
            )
            .is_err(),
            "there is no free-form payload channel — the closed schema rejects it"
        );
}

// 11. request_deployment refuses a branch NAME as ref (git_oid admission — deploy an immutable commit).
#[test]
fn request_deployment_rejects_branch_name_as_ref() {
    let gh = github_m3("http://127.0.0.1:9".into());
    assert!(
        gh.canonicalize(
            "request_deployment",
            &json!({ "owner": "acme", "name": "website", "ref": "main", "environment": "staging" }),
        )
        .is_err(),
        "a deployment ref must be an exact commit OID, never a moving branch name"
    );
}

// 12. create_issue carries the request-time free_payload verbatim; the keep narrows to
//     [id, number, html_url] and never echoes a broad issue body back.
#[test]
fn create_issue_free_payload_rides_verbatim_and_result_is_narrowed() {
    let (base, server) = one_shot_full(
        "201 Created",
        r#"{"id":1,"number":7,"html_url":"https://github.com/acme/website/issues/7","body":"the full echoed issue text"}"#,
    );
    let gh = github_m3(base);
    let title = "Deploy broke staging";
    let body = "The last deploy 500s on /health.";
    let resource = gh
        .canonicalize(
            "create_issue",
            &json!({ "owner": "acme", "name": "website", "title": title, "body": body }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "create_issue",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let req = server.join().unwrap();
    assert!(
        req.starts_with("POST /repos/acme/website/issues"),
        "the issues endpoint: {req}"
    );
    assert!(
        req.contains(&format!(r#""title":"{title}""#)),
        "the agent's title rides verbatim: {req}"
    );
    assert!(
        req.contains(&format!(r#""body":"{body}""#)),
        "the agent's body rides verbatim: {req}"
    );
    assert!(resp.ok);
    assert_eq!(
        resp.result["number"],
        json!(7),
        "keep exposes the stable number"
    );
    assert_eq!(
        resp.result["html_url"],
        json!("https://github.com/acme/website/issues/7"),
        "keep exposes the html_url"
    );
    assert!(
        resp.result.get("body").is_some(),
        "the verbatim response carries the echoed issue body too: {}",
        resp.result
    );
}

// 13. comment_thread posts to the EXACT numbered thread; number carries uint admission.
#[test]
fn comment_thread_posts_to_exact_thread_and_uint_admission() {
    let (base, server) = one_shot_full(
        "201 Created",
        r#"{"id":333,"html_url":"https://github.com/acme/website/issues/7#issuecomment-333"}"#,
    );
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "comment_thread",
            &json!({ "owner": "acme", "name": "website", "number": "7", "body": "on it" }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "comment_thread",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let req = server.join().unwrap();
    assert!(
        req.starts_with("POST /repos/acme/website/issues/7/comments"),
        "the comment lands on the exact frozen thread: {req}"
    );
    assert!(
        req.contains(r#""body":"on it""#),
        "the agent's comment rides the wire: {req}"
    );
    assert!(resp.ok);
    // uint admission: a non-canonical or non-numeric `number` is refused at request time.
    for bad in ["01", "x"] {
        assert!(
            gh.canonicalize(
                "comment_thread",
                &json!({ "owner": "acme", "name": "website", "number": bad, "body": "b" }),
            )
            .is_err(),
            "`{bad}` is not a canonical uint thread number"
        );
    }
}

// 14. read_workflow_run is exactly ONE bodiless GET; the keep projects status/conclusion/head_sha.
#[test]
fn read_workflow_run_is_one_bodiless_get() {
    let (base, server) = one_shot_full(
        "200 OK",
        r#"{"id":42,"status":"completed","conclusion":"success","head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","run_attempt":1,"event":"push"}"#,
    );
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "read_workflow_run",
            &json!({ "owner": "acme", "name": "website", "run_id": "42" }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "read_workflow_run",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let req = server.join().unwrap();
    assert!(
        req.starts_with("GET /repos/acme/website/actions/runs/42"),
        "a pure GET addressing exactly one run: {req}"
    );
    let reqbody = req.split("\r\n\r\n").nth(1).unwrap_or("");
    assert!(
        reqbody.is_empty(),
        "a read carries no request body: `{reqbody}`"
    );
    assert!(
        !req.to_lowercase().contains("content-length"),
        "a bodiless GET sends no content-length: {req}"
    );
    assert!(resp.ok);
    assert_eq!(resp.result["status"], json!("completed"));
    assert_eq!(resp.result["conclusion"], json!("success"));
    assert_eq!(resp.result["head_sha"], json!(M3_OID_A));
}

// create_branch.new_ref is pinned to `git_branch_ref` — a plain branch ref only. A tag
// ref, an abbreviated name, another namespace, or a malformed refname is refused at admission, so
// the "create_branch" verb can never create a tag or arbitrary ref its name does not promise.
#[test]
fn create_branch_new_ref_rejects_tags_and_malformed_refs() {
    let gh = github_m3("http://127.0.0.1:9".into());
    assert!(
            gh.canonicalize(
                "create_branch",
                &json!({ "owner": "acme", "name": "website", "new_ref": "refs/heads/feature", "source_oid": M3_OID_A })
            )
            .is_ok(),
            "a plain branch ref is accepted"
        );
    for bad in [
        "refs/tags/v1",
        "refs/remotes/origin/main",
        "main",
        "feature",
        "refs/heads/",
        "refs/heads/..x",
        "refs/heads/-x",
        "refs/heads/x.lock",
        "refs/heads/a..b",
        "refs/heads/a b",
        "refs/heads/feature.",
        "refs/heads/dir./x",
    ] {
        assert!(
                gh.canonicalize(
                    "create_branch",
                    &json!({ "owner": "acme", "name": "website", "new_ref": bad, "source_oid": M3_OID_A })
                )
                .is_err(),
                "new_ref `{bad}` must be refused (not a plain branch ref)"
            );
    }
}

// A 2xx OUTSIDE the pinned success_statuses fails closed. request_deployment pins 201
// ("request created, not deployed"); a 202 (a merge-commit case) is NOT a hollow success.
#[test]
fn request_deployment_non_201_2xx_fails_closed() {
    let (base, server) = one_shot_full("202 Accepted", r#"{"id":5}"#);
    let gh = github_m3(base);
    let resource = gh
            .canonicalize(
                "request_deployment",
                &json!({ "owner": "acme", "name": "website", "ref": M3_OID_A, "environment": "staging" }),
            )
            .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "request_deployment",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    server.join().unwrap();
    assert!(
        !resp.ok,
        "a 202 (not the pinned 201) must fail closed, not render a hollow success: {:?}",
        resp.result
    );
}

// A 201 whose body is MISSING a required proof path fails closed — a create's stable ID
// can never silently render as null and pass as a hollow success. create_issue requires `number`.
#[test]
fn create_issue_missing_proof_path_fails_closed() {
    let (base, server) = one_shot_full("201 Created", r#"{"id":1,"html_url":"https://x/1"}"#);
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "create_issue",
            &json!({ "owner": "acme", "name": "website", "title": "t", "body": "b" }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "create_issue",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    server.join().unwrap();
    assert!(
        !resp.ok,
        "a 201 missing the required `number` proof must fail closed: {:?}",
        resp.result
    );
}

fn stripe_action(base: String, action: &str) -> GenericProvider {
    let document = crate::templates::VENDORED_CATALOG
        .iter()
        .copied()
        .find(|document| {
            document.contains("provider: stripe\n")
                && document.contains(&format!("action: {action}\n"))
        })
        .unwrap_or_else(|| panic!("stripe.{action} must be vendored"));
    let descriptor = ProviderDescriptor::parse(
        "name: stripe\negress:\n  - https://api.stripe.com\nauth: bearer\n",
    )
    .unwrap();
    let registry = Arc::new(TemplateRegistry::new());
    registry.load(document).unwrap();
    GenericProvider::from_descriptor_with_base(descriptor, base, registry)
}

#[test]
fn stripe_m2_provider_sends_only_the_reviewed_paths_and_form_fields() {
    let cases = [
        (
            "cancel_subscription_at_period_end",
            json!({"subscription":"sub_123"}),
            "/v1/subscriptions/sub_123",
            Some("cancel_at_period_end=true"),
            r#"{"id":"sub_123","status":"active","cancel_at_period_end":true,"customer":"cus_drop"}"#,
            json!({"id":"sub_123","status":"active","cancel_at_period_end":true}),
        ),
        (
            "resume_subscription_collection",
            json!({"subscription":"sub_456"}),
            "/v1/subscriptions/sub_456",
            Some("pause_collection="),
            r#"{"id":"sub_456","status":"active","pause_collection":null,"customer":"cus_drop"}"#,
            json!({"id":"sub_456","status":"active","pause_collection":null}),
        ),
        (
            "mark_invoice_uncollectible",
            json!({"invoice":"in_123"}),
            "/v1/invoices/in_123/mark_uncollectible",
            None,
            r#"{"id":"in_123","status":"uncollectible","customer_email":"drop@example.invalid"}"#,
            json!({"id":"in_123","status":"uncollectible"}),
        ),
        (
            "issue_credit_note_adjustment_no_email",
            json!({"invoice":"in_456","amount":500}),
            "/v1/credit_notes",
            Some("amount=500&email_type=none&invoice=in_456"),
            r#"{"id":"cn_123","invoice":"in_456","amount":500,"currency":"usd","status":"issued","pre_payment_amount":500,"post_payment_amount":0,"type":"pre_payment","memo":"drop"}"#,
            json!({"id":"cn_123","invoice":"in_456","amount":500,"currency":"usd","status":"issued","pre_payment_amount":500,"post_payment_amount":0,"type":"pre_payment"}),
        ),
        (
            "archive_product",
            json!({"product":"prod_123"}),
            "/v1/products/prod_123",
            Some("active=false"),
            r#"{"id":"prod_123","active":false,"name":"drop"}"#,
            json!({"id":"prod_123","active":false}),
        ),
        (
            "archive_price",
            json!({"price":"price_123"}),
            "/v1/prices/price_123",
            Some("active=false"),
            r#"{"id":"price_123","active":false,"product":"prod_drop"}"#,
            json!({"id":"price_123","active":false}),
        ),
    ];

    for (action, request_resource, path, expected_body, response_body, expected_result) in cases {
        let (base, server) = one_shot_full("200 OK", response_body);
        let stripe = stripe_action(base, action);
        let resource = stripe.canonicalize(action, &request_resource).unwrap();
        let response = stripe
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action,
                token: "rk_test_m2_secret",
                resource: &resource,
            })
            .unwrap();
        let request = server.join().unwrap();
        assert!(
            request.starts_with(&format!("POST {path} HTTP/1.1")),
            "stripe.{action}: {request}"
        );
        let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
        if let Some(expected_body) = expected_body {
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("content-type: application/x-www-form-urlencoded"),
                "stripe.{action}: {request}"
            );
            assert_eq!(body, expected_body, "stripe.{action}");
        } else {
            assert_eq!(body, "", "stripe.{action} must send no options");
            assert!(
                !request.to_ascii_lowercase().contains("content-type:"),
                "stripe.{action}: {request}"
            );
        }
        assert!(response.ok, "stripe.{action}: {:?}", response.result);
        let _ = &expected_result;
        assert_eq!(
            response.result,
            serde_json::from_str::<Value>(response_body).unwrap(),
            "stripe.{action}: the response is the provider body, verbatim"
        );
        assert!(response.retained.is_some(), "stripe.{action}");
    }
}

#[test]
fn stripe_credit_note_has_no_caller_selected_combined_effect_input_or_wire_field() {
    let stripe = stripe_action(
        "http://127.0.0.1:9".into(),
        "issue_credit_note_adjustment_no_email",
    );
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
        let mut request = json!({"invoice":"in_456","amount":500});
        request
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_string(), json!(1));
        assert!(
            stripe
                .canonicalize("issue_credit_note_adjustment_no_email", &request)
                .is_err(),
            "caller-selected combined-effect input `{forbidden}` was accepted"
        );
    }
}

#[test]
fn stripe_resume_collection_requires_present_null_clear_evidence() {
    for (body, expected_ok, expected_proof) in [
        (
            r#"{"id":"sub_456","status":"active","pause_collection":null}"#,
            true,
            None,
        ),
        (
            r#"{"id":"sub_456","status":"active"}"#,
            false,
            Some(json!({"id":"sub_456","status":"active"})),
        ),
        (
            r#"{"id":"sub_456","status":"active","pause_collection":{"behavior":"void","secret":"sk_nested_object"}}"#,
            false,
            Some(json!({"id":"sub_456","status":"active"})),
        ),
        (
            r#"{"id":"sub_456","status":"active","pause_collection":["void",{"secret":"sk_nested_array"}]}"#,
            false,
            Some(json!({"id":"sub_456","status":"active"})),
        ),
    ] {
        let (base, server) = one_shot_full("200 OK", body);
        let stripe = stripe_action(base, "resume_subscription_collection");
        let resource = stripe
            .canonicalize(
                "resume_subscription_collection",
                &json!({"subscription":"sub_456"}),
            )
            .unwrap();
        let response = stripe
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "resume_subscription_collection",
                token: "rk_test_m2_secret",
                resource: &resource,
            })
            .unwrap();
        server.join().unwrap();

        assert_eq!(response.ok, expected_ok, "{}", response.result);
        if let Some(provider_proof) = expected_proof {
            assert_eq!(response.result["outcome"], "postcondition_failed");
            assert_eq!(response.result["path"], "pause_collection");
            let _ = &provider_proof;
            assert_eq!(
                response.result["provider_proof"],
                serde_json::from_str::<Value>(body).unwrap(),
                "the reconciliation proof is the body the provider sent, verbatim"
            );
        } else {
            assert_eq!(response.result["pause_collection"], Value::Null);
        }
        assert!(response.retained.is_some());
    }
}

#[test]
fn stripe_credit_note_mismatch_proof_keeps_only_present_scalars() {
    for (response_body, failed_path) in [
        (
            r#"{"id":"cn_post","invoice":"in_456","amount":500,"currency":"usd","status":"issued","pre_payment_amount":0,"post_payment_amount":500,"type":"pre_payment","client_secret":"provider-secret-drop","customer_email":"private@example.invalid"}"#,
            "post_payment_amount",
        ),
        (
            r#"{"id":"cn_wrong","invoice":"in_456","amount":500,"currency":"usd","status":"issued","pre_payment_amount":500,"post_payment_amount":0,"type":"post_payment","client_secret":"provider-secret-drop","customer_email":"private@example.invalid"}"#,
            "type",
        ),
        (
            r#"{"id":"cn_status_object","invoice":"in_456","amount":500,"currency":"usd","status":{"value":"issued","secret":"sk_nested_status"},"pre_payment_amount":500,"post_payment_amount":0,"type":"pre_payment"}"#,
            "status",
        ),
        (
            r#"{"id":"cn_type_array","invoice":"in_456","amount":500,"currency":"usd","status":"issued","pre_payment_amount":500,"post_payment_amount":0,"type":["pre_payment",{"secret":"sk_nested_type"}]}"#,
            "type",
        ),
    ] {
        let (base, server) = one_shot_full("200 OK", response_body);
        let stripe = stripe_action(base, "issue_credit_note_adjustment_no_email");
        let resource = stripe
            .canonicalize(
                "issue_credit_note_adjustment_no_email",
                &json!({"invoice":"in_456","amount":500}),
            )
            .unwrap();
        let response = stripe
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "issue_credit_note_adjustment_no_email",
                token: "rk_test_m2_secret",
                resource: &resource,
            })
            .unwrap();
        server.join().unwrap();
        assert!(!response.ok, "mismatch requires reconciliation");
        assert_eq!(response.result["outcome"], "postcondition_failed");
        assert_eq!(response.result["path"], failed_path);
        assert_eq!(
            response.result["provider_proof"],
            serde_json::from_str::<Value>(response_body).unwrap(),
            "the reconciliation proof is the body the provider sent, verbatim"
        );
        assert!(response.retained.is_some());
    }
}

#[test]
fn https_url_format_admits_only_absolute_uncredentialed_fragmentless_https_without_rewriting() {
    const TEMPLATE: &str = r#"
provider: acme
action: update_hook
fields:
  - { name: endpoint, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: url, type: str, required: true, class: identity, binding: exact_resource_pin, format: https_url }
consumes: [endpoint, url]
execution_targets: [endpoint, url]
http:
  steps:
    - id: update
      method: POST
      path: /hooks/{endpoint}
      body: { url: "{url}" }
"#;
    let descriptor =
        ProviderDescriptor::parse("name: acme\negress:\n  - https://api.acme.test\nauth: bearer\n")
            .unwrap();
    let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
        "acme".to_string()
    ])));
    registry.load(TEMPLATE).unwrap();
    let provider = GenericProvider::from_descriptor_with_base(
        descriptor,
        "http://127.0.0.1:9".into(),
        registry,
    );

    for url in [
        "https://example.com",
        "https://example.com/hook/path?tenant=acme",
        "https://example.com:8443/hook/path?tenant=acme",
    ] {
        let resource = provider
            .canonicalize("update_hook", &json!({"endpoint":"we_123","url":url}))
            .unwrap_or_else(|error| panic!("valid HTTPS URL `{url}` was refused: {error}"));
        assert_eq!(resource.req_str("url").unwrap(), url, "URL bytes changed");
    }

    for url in [
        "http://example.com/hook",
        "/relative/hook",
        "https://user@example.com/hook",
        "https://user:password@example.com/hook",
        "https://example.com/hook#fragment",
        "https://?tenant=acme",
        "https://@example.com",
        "https:///example.com",
        "https:\\example.com\\hook",
        "https://example.com\\hook",
        "https://example.com/line\rbreak",
        "https://example.com/line\nbreak",
        "https://example.com/line\tbreak",
        "https://example.com/has space",
        "HTTPS://example.com/hook",
        "Https://example.com/hook",
        " https://example.com/hook",
        "https://user%40name@example.com/hook",
        "https://user%3Apassword@example.com/hook",
        "https://éxample.com/hook",
    ] {
        assert!(
            provider
                .canonicalize("update_hook", &json!({"endpoint":"we_123","url":url}))
                .is_err(),
            "invalid HTTPS URL `{url}` was accepted"
        );
    }
}

#[test]
fn stripe_dispute_actions_send_only_frozen_stage_or_submit_forms() {
    let stage_response = r#"{
        "id":"du_123",
        "status":"needs_response",
        "evidence":{"product_description":"must-not-return"},
        "evidence_details":{"due_by":1700000000,"has_evidence":true,"past_due":false,"submission_count":0},
        "charge":"ch_drop"
    }"#;
    let (base, server) = one_shot_full("200 OK", stage_response);
    let stripe = stripe_action(base, "stage_dispute_evidence");
    let resource = stripe
        .canonicalize(
            "stage_dispute_evidence",
            &json!({
                "dispute":"du_123",
                "cancellation_policy":"file_policy",
                "duplicate_charge_id":"ch_prior",
                "product_description":"widget"
            }),
        )
        .unwrap();
    let response = stripe
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "stage_dispute_evidence",
            token: "rk_test_m3_secret",
            resource: &resource,
        })
        .unwrap();
    let request = server.join().unwrap();
    assert!(request.starts_with("POST /v1/disputes/du_123 HTTP/1.1"));
    assert_eq!(
        request.split("\r\n\r\n").nth(1).unwrap_or_default(),
        "evidence%5Bcancellation_policy%5D=file_policy&evidence%5Bduplicate_charge_id%5D=ch_prior&evidence%5Bproduct_description%5D=widget&submit=false"
    );
    assert_eq!(
        response.result,
        json!({
            "id":"du_123",
            "charge":"ch_drop",
            "status":"needs_response",
            "evidence":{"product_description":"must-not-return"},
            "evidence_details":{"due_by":1700000000,"has_evidence":true,"past_due":false,"submission_count":0}
        }),
        "the dispute comes back whole; this test owns the frozen REQUEST form"
    );
    assert!(response.retained.is_some());

    for forbidden in ["submit", "evidence"] {
        let mut request = json!({"dispute":"du_123","product_description":"widget"});
        request.as_object_mut().unwrap().insert(
            forbidden.to_string(),
            if forbidden == "evidence" {
                json!({"uncategorized_text":"injected"})
            } else {
                json!(true)
            },
        );
        assert!(
            stripe
                .canonicalize("stage_dispute_evidence", &request)
                .is_err(),
            "agent-controlled `{forbidden}` was accepted"
        );
    }

    let submit_response = r#"{
        "id":"du_456",
        "status":"under_review",
        "evidence":{"uncategorized_text":"must-not-return"},
        "evidence_details":{"due_by":1700000000,"has_evidence":true,"past_due":false,"submission_count":1}
    }"#;
    let (base, server) = one_shot_full("200 OK", submit_response);
    let stripe = stripe_action(base, "submit_dispute_evidence");
    let resource = stripe
        .canonicalize("submit_dispute_evidence", &json!({"dispute":"du_456"}))
        .unwrap();
    let response = stripe
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "submit_dispute_evidence",
            token: "rk_test_m3_secret",
            resource: &resource,
        })
        .unwrap();
    let request = server.join().unwrap();
    assert!(request.starts_with("POST /v1/disputes/du_456 HTTP/1.1"));
    assert_eq!(
        request.split("\r\n\r\n").nth(1).unwrap_or_default(),
        "submit=true"
    );
    assert_eq!(
        response.result,
        json!({
            "evidence": {
                "uncategorized_text": "must-not-return"
            },
            "evidence_details": {
                "due_by": 1700000000,
                "has_evidence": true,
                "past_due": false,
                "submission_count": 1
            },
            "id": "du_456",
            "status": "under_review"
        })
    );
    assert!(response.retained.is_some());
    for forbidden in ["submit", "evidence", "uncategorized_text"] {
        let mut request = json!({"dispute":"du_456"});
        request
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_string(), json!(true));
        assert!(
            stripe
                .canonicalize("submit_dispute_evidence", &request)
                .is_err(),
            "submit action accepted stage-like field `{forbidden}`"
        );
    }
}

#[test]
fn stripe_webhook_fixed_bundle_sends_exact_repeated_events_and_https_url() {
    let response_body = r#"{
        "id":"we_123",
        "url":"https://example.com:8443/hooks/stripe?tenant=acme",
        "status":"enabled",
        "api_version":null,
        "enabled_events":["charge.succeeded","charge.failed"],
        "secret":"whsec_drop"
    }"#;
    let (base, server) = one_shot_full("200 OK", response_body);
    let stripe = stripe_action(base, "update_webhook_endpoint_fixed_bundle");
    let url = "https://example.com:8443/hooks/stripe?tenant=acme";
    let resource = stripe
        .canonicalize(
            "update_webhook_endpoint_fixed_bundle",
            &json!({"endpoint":"we_123","url":url}),
        )
        .unwrap();
    assert_eq!(resource.req_str("url").unwrap(), url);
    let response = stripe
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "update_webhook_endpoint_fixed_bundle",
            token: "rk_test_m3_secret",
            resource: &resource,
        })
        .unwrap();
    let request = server.join().unwrap();
    assert!(request.starts_with("POST /v1/webhook_endpoints/we_123 HTTP/1.1"));
    let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
    assert_eq!(
        body,
        "enabled_events%5B%5D=charge.succeeded&enabled_events%5B%5D=charge.failed&url=https%3A%2F%2Fexample.com%3A8443%2Fhooks%2Fstripe%3Ftenant%3Dacme"
    );
    assert!(!body.contains("%2A") && !body.contains('*'));
    assert!(!body.contains("disabled") && !body.contains("status="));
    assert_eq!(
        response.result,
        json!({
            "api_version": null,
            "enabled_events": [
                "charge.succeeded",
                "charge.failed"
            ],
            "id": "we_123",
            "secret": "whsec_drop",
            "status": "enabled",
            "url": "https://example.com:8443/hooks/stripe?tenant=acme"
        })
    );
    assert!(response.retained.is_some());

    for forbidden in ["enabled_events", "disabled", "status"] {
        let mut request = json!({"endpoint":"we_123","url":url});
        request.as_object_mut().unwrap().insert(
            forbidden.to_string(),
            if forbidden == "enabled_events" {
                json!(["*"])
            } else {
                json!(true)
            },
        );
        assert!(
            stripe
                .canonicalize("update_webhook_endpoint_fixed_bundle", &request)
                .is_err(),
            "agent-controlled webhook field `{forbidden}` was accepted"
        );
    }
}

#[test]
fn stripe_webhook_bundle_drift_is_terminal_and_array_free_in_provider_proof() {
    for (response_body, expected_proof) in [
        (
            r#"{"id":"we_123","url":"https://example.com/hook","status":"enabled","api_version":null,"enabled_events":["charge.failed","charge.succeeded"],"secret":"whsec_drop"}"#,
            json!({
                "id":"we_123",
                "url":"https://example.com/hook",
                "status":"enabled",
                "api_version":null
            }),
        ),
        (
            r#"{"id":"we_123","url":"https://example.com/hook","status":"enabled","api_version":null,"enabled_events":["*"],"secret":"whsec_drop"}"#,
            json!({
                "id":"we_123",
                "url":"https://example.com/hook",
                "status":"enabled",
                "api_version":null
            }),
        ),
        (
            r#"{"id":"we_123","url":"https://example.com/hook","status":"enabled","api_version":null,"secret":"whsec_drop"}"#,
            json!({
                "id":"we_123",
                "url":"https://example.com/hook",
                "status":"enabled",
                "api_version":null
            }),
        ),
        (
            r#"{"id":"we_123","url":"https://example.com/hook","status":"enabled","api_version":null,"enabled_events":null,"secret":"whsec_drop"}"#,
            json!({
                "id":"we_123",
                "url":"https://example.com/hook",
                "status":"enabled",
                "api_version":null,
                "enabled_events":null
            }),
        ),
    ] {
        let (base, server) = one_shot_full("200 OK", response_body);
        let stripe = stripe_action(base, "update_webhook_endpoint_fixed_bundle");
        let resource = stripe
            .canonicalize(
                "update_webhook_endpoint_fixed_bundle",
                &json!({"endpoint":"we_123","url":"https://example.com/hook"}),
            )
            .unwrap();
        let response = stripe
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "update_webhook_endpoint_fixed_bundle",
                token: "rk_test_m3_secret",
                resource: &resource,
            })
            .unwrap();
        server.join().unwrap();
        assert!(!response.ok);
        assert_eq!(response.result["outcome"], "postcondition_failed");
        assert_eq!(response.result["path"], "enabled_events");
        let _ = &expected_proof;
        assert_eq!(
            response.result["provider_proof"],
            serde_json::from_str::<Value>(response_body).unwrap(),
            "the reconciliation proof is the body the provider sent, verbatim"
        );
        assert!(response.retained.is_some());
    }
}

#[test]
fn final_expect_eq_is_an_equality_postcondition_with_scalar_only_proof() {
    const TEMPLATE: &str = r#"
provider: acme
action: update_hook
fields:
  - { name: endpoint, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: url, type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [endpoint, url]
execution_targets: [endpoint, url]
http:
  steps:
    - id: update
      method: POST
      path: /hooks/{endpoint}
      body: { url: "{url}" }
      success_statuses: [200]
      require: [id, url]
      expect_eq: { url: url }
      retention: none
"#;
    let cases = [
        (
            r#"{"id":"we_1","url":"https://example.com/hook","status":"enabled","secret":"drop"}"#,
            true,
            None,
        ),
        (
            r#"{"id":"we_1","url":"https://other.example/hook?token=provider-held-secret","status":"enabled","secret":"drop"}"#,
            false,
            Some(json!({"id":"we_1","status":"enabled"})),
        ),
        (
            r#"{"id":"we_1","status":"enabled","secret":"drop"}"#,
            false,
            Some(json!({"id":"we_1","status":"enabled"})),
        ),
        (
            r#"{"id":"we_1","url":{"value":"https://example.com/hook","secret":"nested-drop"},"status":"enabled","secret":"drop"}"#,
            false,
            Some(json!({"id":"we_1","status":"enabled"})),
        ),
    ];
    for (response_body, expected_ok, expected_proof) in cases {
        let (base, server) = one_shot_full("200 OK", response_body);
        let descriptor = ProviderDescriptor::parse(
            "name: acme\negress:\n  - https://api.acme.test\nauth: bearer\n",
        )
        .unwrap();
        let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
            "acme".to_string()
        ])));
        registry
            .load(TEMPLATE)
            .expect("a final mutation may carry an equality postcondition");
        let provider = GenericProvider::from_descriptor_with_base(descriptor, base, registry);
        let resource = provider
            .canonicalize(
                "update_hook",
                &json!({"endpoint":"we_1","url":"https://example.com/hook"}),
            )
            .unwrap();
        let response = provider
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "update_hook",
                token: "secret-token",
                resource: &resource,
            })
            .unwrap();
        server.join().unwrap();
        assert_eq!(response.ok, expected_ok, "{}", response.result);
        if let Some(proof) = expected_proof {
            assert_eq!(response.result["outcome"], "postcondition_failed");
            assert_eq!(response.result["field"], "url");
            let _ = &proof;
            assert_eq!(
                response.result["provider_proof"],
                serde_json::from_str::<Value>(response_body).unwrap(),
                "the reconciliation proof is the body the provider sent, verbatim"
            );
        } else {
            assert_eq!(response.result["url"], "https://example.com/hook");
        }
        assert!(response.retained.is_none());
    }
}

#[test]
fn final_rest_get_expect_eq_mismatch_and_missing_proof_are_value_free() {
    const TEMPLATE: &str = r#"
provider: acme
action: inspect_identity
fields:
  - { name: target, type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [target]
execution_targets: [target]
http:
  steps:
    - id: inspect
      method: GET
      path: /identities/{target}
      success_statuses: [200]
      require: [identity, proof]
      expect_eq: { identity: target }
      retention: none
"#;
    for (response_body, expected) in [
        (
            r#"{"identity":"unapproved-id","username":"private-user","secret":"provider-secret","proof":true}"#,
            json!({"outcome":"precondition_failed","field":"target"}),
        ),
        (
            r#"{"identity":"approved-id","username":"private-user","secret":"provider-secret"}"#,
            json!({"outcome":"missing_proof_path","path":"proof"}),
        ),
    ] {
        let (base, server) = one_shot_full("200 OK", response_body);
        let descriptor = ProviderDescriptor::parse(
            "name: acme\negress:\n  - https://api.acme.test\nauth: bearer\n",
        )
        .unwrap();
        let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
            "acme".to_string()
        ])));
        registry.load(TEMPLATE).unwrap();
        let provider = GenericProvider::from_descriptor_with_base(descriptor, base, registry);
        let resource = provider
            .canonicalize("inspect_identity", &json!({"target":"approved-id"}))
            .unwrap();
        let response = provider
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "inspect_identity",
                token: "secret-token",
                resource: &resource,
            })
            .unwrap();
        server.join().unwrap();
        assert!(!response.ok);
        // A CLASSIFIED graphql failure returns the body UNTOUCHED and puts its verdict
        // in the sibling envelope; a precondition/postcondition failure replaces the result with a
        // broker-authored envelope object, which is a documented delta.
        if expected["outcome"] == json!("failed") {
            assert_eq!(
                response.result,
                serde_json::from_str::<Value>(response_body).unwrap(),
                "a classified graphql failure returns the provider body verbatim"
            );
            assert_eq!(
                response.envelope.get("outcome"),
                expected.get("outcome"),
                "the `outcome` verdict rides the sibling envelope"
            );
        } else {
            assert_eq!(response.result, expected.clone());
        }
        assert!(response.retained.is_none());
    }
}

#[test]
fn final_graphql_query_expect_eq_mismatch_and_missing_proof_are_value_free() {
    const TEMPLATE: &str = r#"
provider: acme
action: inspect_viewer
fields:
  - { name: target, type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [target]
execution_targets: [target]
http:
  steps:
    - id: inspect
      method: POST
      path: /graphql
      success_statuses: [200]
      graphql_query: "query viewer($target: String!) { viewer(target: $target) { identity username secret proof } }"
      require: [data.viewer.identity, data.viewer.proof]
      body: { variables: { target: "{target}" } }
      expect_eq: { data.viewer.identity: target }
      retention: none
"#;
    for (response_body, expected) in [
        (
            r#"{"data":{"viewer":{"identity":"unapproved-id","username":"private-user","secret":"provider-secret","proof":true}}}"#,
            json!({"outcome":"precondition_failed","field":"target"}),
        ),
        (
            r#"{"data":{"viewer":{"identity":"approved-id","username":"private-user","secret":"provider-secret"}}}"#,
            json!({"outcome":"missing_proof_path","path":"data.viewer.proof"}),
        ),
    ] {
        let (base, server) = one_shot_full("200 OK", response_body);
        let descriptor = ProviderDescriptor::parse(
            "name: acme\negress:\n  - https://api.acme.test\nauth: bearer\n",
        )
        .unwrap();
        let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
            "acme".to_string()
        ])));
        registry.load(TEMPLATE).unwrap();
        let provider = GenericProvider::from_descriptor_with_base(descriptor, base, registry);
        let resource = provider
            .canonicalize("inspect_viewer", &json!({"target":"approved-id"}))
            .unwrap();
        let response = provider
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "inspect_viewer",
                token: "secret-token",
                resource: &resource,
            })
            .unwrap();
        server.join().unwrap();
        assert!(!response.ok);
        assert_eq!(response.result, expected);
        assert!(response.result.get("provider_proof").is_none());
        let rendered = serde_json::to_string(&response.result).unwrap();
        for forbidden in ["unapproved-id", "private-user", "provider-secret"] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
        assert!(response.retained.is_none());
    }
}

#[test]
fn final_graphql_mutation_postconditions_precede_require_and_reconcile_missing_proof() {
    const TEMPLATE: &str = r#"
provider: acme
action: update_viewer
fields:
  - { name: target, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: url, type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [target, url]
execution_targets: [target, url]
http:
  steps:
    - id: update
      method: POST
      path: /graphql
      success_statuses: [200]
      graphql_query: "mutation updateViewer($target: String!, $url: String!) { updateViewer(target: $target, url: $url) { id url enabled status } }"
      require: [data.updateViewer.id, data.updateViewer.url, data.updateViewer.enabled]
      body: { variables: { target: "{target}", url: "{url}" } }
      expect_eq: { data.updateViewer.url: url }
      expect_literal: { data.updateViewer.enabled: true }
      retention: none
"#;
    let cases = [
        (
            r#"{"data":{"updateViewer":null},"errors":[{"message":"discard me","extensions":{"code":"STALE"}}]}"#,
            // The `conflict: expected_state` classification died with `conflict_on`: the
            // git-native push takes its concurrency control from the upstream server's own
            // fast-forward rule, so no verb has a CAS field to report drift on. A GraphQL failure
            // is now just a failure.
            json!({ "outcome":"failed" }),
        ),
        (
            r#"{"data":{"updateViewer":{"id":"viewer_1","enabled":true,"status":"changed"}}}"#,
            json!({
                "outcome":"postcondition_failed",
                "field":"url",
                "provider_proof":{"data":{"updateViewer":{"id":"viewer_1","enabled":true,"status":"changed"}}}
            }),
        ),
        (
            r#"{"data":{"updateViewer":{"id":"viewer_1","url":null,"enabled":true,"status":"changed"}}}"#,
            json!({
                "outcome":"postcondition_failed",
                "field":"url",
                "provider_proof":{"data":{"updateViewer":{"id":"viewer_1","url":null,"enabled":true,"status":"changed"}}}
            }),
        ),
        (
            r#"{"data":{"updateViewer":{"id":"viewer_1","url":"https://example.com/hook","status":"changed"}}}"#,
            json!({
                "outcome":"postcondition_failed",
                "path":"data.updateViewer.enabled",
                "provider_proof":{"data":{"updateViewer":{"id":"viewer_1","url":"https://example.com/hook","status":"changed"}}}
            }),
        ),
        (
            r#"{"data":{"updateViewer":{"id":"viewer_1","url":"https://example.com/hook","enabled":null,"status":"changed"}}}"#,
            json!({
                "outcome":"postcondition_failed",
                "path":"data.updateViewer.enabled",
                "provider_proof":{"data":{"updateViewer":{"id":"viewer_1","url":"https://example.com/hook","enabled":null,"status":"changed"}}}
            }),
        ),
        (
            r#"{"data":{"updateViewer":{"url":"https://example.com/hook","enabled":true,"status":"changed"}}}"#,
            json!({
                "outcome":"missing_proof_path",
                "path":"data.updateViewer.id",
                "provider_proof":{"data":{"updateViewer":{"url":"https://example.com/hook","enabled":true,"status":"changed"}}}
            }),
        ),
    ];
    for (response_body, expected) in cases {
        let (base, server) = one_shot_full("200 OK", response_body);
        let descriptor = ProviderDescriptor::parse(
            "name: acme\negress:\n  - https://api.acme.test\nauth: bearer\n",
        )
        .unwrap();
        let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
            "acme".to_string()
        ])));
        registry.load(TEMPLATE).unwrap();
        let provider = GenericProvider::from_descriptor_with_base(descriptor, base, registry);
        let resource = provider
            .canonicalize(
                "update_viewer",
                &json!({"target":"viewer_1","url":"https://example.com/hook"}),
            )
            .unwrap();
        let response = provider
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "update_viewer",
                token: "secret-token",
                resource: &resource,
            })
            .unwrap();
        server.join().unwrap();
        assert!(!response.ok);
        // A CLASSIFIED graphql failure augments the verbatim body with the step's verdict keys;
        // a postcondition/missing-proof envelope replaces it. Compare against the right shape.
        if expected["outcome"] == json!("failed") {
            assert_eq!(
                response.result,
                serde_json::from_str::<Value>(response_body).unwrap(),
                "a classified graphql failure returns the provider body verbatim"
            );
            assert_eq!(
                response.envelope.get("outcome"),
                expected.get("outcome"),
                "the `outcome` verdict rides the sibling envelope"
            );
        } else {
            assert_eq!(response.result, expected.clone());
        }
        assert!(response.retained.is_none());
    }
}

#[test]
fn stripe_webhook_missing_uncovered_require_keeps_scalar_reconciliation_proof() {
    let (base, server) = one_shot_full(
        "200 OK",
        r#"{"url":"https://example.com/hook","status":"enabled","enabled_events":["charge.succeeded","charge.failed"],"secret":"whsec_drop"}"#,
    );
    let stripe = stripe_action(base, "update_webhook_endpoint_fixed_bundle");
    let resource = stripe
        .canonicalize(
            "update_webhook_endpoint_fixed_bundle",
            &json!({"endpoint":"we_123","url":"https://example.com/hook"}),
        )
        .unwrap();
    let response = stripe
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "update_webhook_endpoint_fixed_bundle",
            token: "rk_test_m3_secret",
            resource: &resource,
        })
        .unwrap();
    server.join().unwrap();

    assert!(!response.ok);
    assert_eq!(response.result["outcome"], "missing_proof_path");
    assert_eq!(response.result["path"], "id");
    assert_eq!(
        response.result["provider_proof"],
        json!({
            "url":"https://example.com/hook",
            "status":"enabled",
            "enabled_events":["charge.succeeded","charge.failed"],
            "secret":"whsec_drop"
        }),
        "the reconciliation proof is the body the provider sent"
    );
    assert!(response.retained.is_some());
}

#[test]
fn string_character_limits_are_unicode_aware_and_reapply_to_stored_json() {
    const TEMPLATE: &str = r#"
provider: acme
action: write_text
fields:
  - { name: target, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: first, type: str, required: false, class: free_payload, binding: unbound, max_chars: 4 }
  - { name: second, type: str, required: false, class: free_payload, binding: unbound, max_chars: 4 }
consumes: [target, first, second]
execution_targets: [target]
string_char_budget: { fields: [first, second], max_chars: 5 }
http:
  steps:
    - id: write
      method: POST
      path: /targets/{target}
      body: { first: "{first?}", second: "{second?}" }
"#;
    let descriptor =
        ProviderDescriptor::parse("name: acme\negress:\n  - https://api.acme.test\nauth: bearer\n")
            .unwrap();
    let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
        "acme".to_string()
    ])));
    registry.load(TEMPLATE).unwrap();
    let provider = GenericProvider::from_descriptor_with_base(
        descriptor,
        "http://127.0.0.1:9".into(),
        registry,
    );

    for request in [
        json!({"target":"one"}),
        json!({"target":"one","first":"éééé"}),
        json!({"target":"one","first":"ééé","second":"ab"}),
    ] {
        let resource = provider.canonicalize("write_text", &request).unwrap();
        let stored: Value = serde_json::from_str(&resource.to_canonical_json()).unwrap();
        provider
            .canonicalize("write_text", &stored)
            .expect("stored canonical JSON must revalidate through the same limits");
    }
    for request in [
        json!({"target":"one","first":"12345"}),
        json!({"target":"one","first":"1234","second":"56"}),
    ] {
        assert!(provider.canonicalize("write_text", &request).is_err());
    }
}

#[test]
fn integer_ceiling_refuses_over_cap_at_admission_and_on_stored_revalidation() {
    const TEMPLATE: &str = r#"
provider: acme
action: bounded_write
fields:
  - { name: target, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: amount, type: int, required: true, class: side_effect, binding: bounded, max_int: 100 }
consumes: [target, amount]
execution_targets: [target]
http:
  steps:
    - id: write
      method: POST
      path: /targets/{target}
      body: { amount: "{amount}" }
"#;
    let descriptor =
        ProviderDescriptor::parse("name: acme\negress:\n  - https://api.acme.test\nauth: bearer\n")
            .unwrap();
    let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
        "acme".to_string()
    ])));
    registry.load(TEMPLATE).unwrap();
    let provider = GenericProvider::from_descriptor_with_base(
        descriptor,
        "http://127.0.0.1:9".into(),
        registry,
    );

    for amount in [1, 100] {
        let resource = provider
            .canonicalize("bounded_write", &json!({"target":"one","amount":amount}))
            .expect("at-cap integer amounts must be admitted");
        let stored: Value = serde_json::from_str(&resource.to_canonical_json()).unwrap();
        provider
            .canonicalize("bounded_write", &stored)
            .expect("stored canonical JSON must revalidate through the same ceiling");
    }
    let error = provider
        .canonicalize("bounded_write", &json!({"target":"one","amount":101}))
        .expect_err("an over-ceiling integer must be refused before egress");
    assert!(
        error.to_string().contains("over the 100 integer cap"),
        "{error}"
    );
}

#[test]
fn stripe_setup_money_amounts_refuse_over_descriptor_ceiling() {
    let cases = [
        (
            "fixture_bypass_pending_charge_create",
            "amount",
            json!({"account":"acct_1","amount":100,"currency":"usd"}),
        ),
        (
            "fixture_dispute_charge_create",
            "amount",
            json!({"account":"acct_1","amount":100,"currency":"usd"}),
        ),
        (
            "fixture_manual_capture_payment_intent_create",
            "amount",
            json!({
                "account":"acct_1",
                "customer":"cus_1",
                "payment_method":"pm_1",
                "amount":100,
                "currency":"usd"
            }),
        ),
        (
            "fixture_price_create",
            "unit_amount",
            json!({
                "account":"acct_1",
                "product":"prod_1",
                "unit_amount":100,
                "currency":"usd"
            }),
        ),
        (
            "fixture_refundable_charge_create",
            "amount",
            json!({
                "account":"acct_1",
                "customer":"cus_1",
                "payment_method":"pm_1",
                "amount":100,
                "currency":"usd"
            }),
        ),
    ];
    for (action, field, at_cap) in cases {
        let stripe = stripe_action("http://127.0.0.1:9".into(), action);
        stripe
            .canonicalize(action, &at_cap)
            .unwrap_or_else(|error| panic!("stripe.{action} at-cap request failed: {error}"));
        let mut over_cap = at_cap;
        over_cap[field] = json!(101);
        let error = stripe
            .canonicalize(action, &over_cap)
            .expect_err("over-ceiling setup amount must fail before egress");
        assert!(
            error.to_string().contains("over the 100 integer cap"),
            "stripe.{action}.{field}: {error}"
        );
    }
}

#[test]
fn setup_reconciliation_poll_retries_until_nonempty_and_uses_created_capture() {
    const TEMPLATE: &str = r#"
provider: stripe
action: fixture_dispute_create
fields:
  - { name: account, type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [account]
execution_targets: [account]
http:
  steps:
    - id: create
      method: POST
      path: /v1/charges
      body: { account: "{account}" }
      success_statuses: [200]
      require: [id]
      capture: { created_charge: "$.id" }
      retention: none
    - id: reconcile
      method: GET
      path: /v1/disputes
      query: { charge: "{created_charge}", limit: "10" }
      success_statuses: [200]
      require: [data, has_more]
      expect_literal: { has_more: false }
      poll: { attempts: 3, delay_ms: 1, until_nonempty: [data] }
      result_captures: { created_charge: created_charge }
      retention: none
"#;
    let responses = Box::leak(Box::new([
        ("200 OK", r#"{"id":"ch_created"}"#),
        ("200 OK", r#"{"data":[],"has_more":false}"#),
        ("200 OK", r#"{"data":[],"has_more":false}"#),
        (
            "200 OK",
            r#"{"data":[{"id":"dp_created","charge":"ch_created"}],"has_more":false}"#,
        ),
    ]));
    let (base, server) = two_shot_full(responses);
    let descriptor = ProviderDescriptor::parse(
        "name: stripe\negress:\n  - https://api.stripe.com\nauth: bearer\n",
    )
    .unwrap();
    let registry = Arc::new(TemplateRegistry::with_providers(HashSet::from([
        "stripe".to_string()
    ])));
    registry
        .load(TEMPLATE)
        .expect("bounded setup reconciliation polling must load");
    let provider = GenericProvider::from_descriptor_with_base(descriptor, base, registry);
    let resource = provider
        .canonicalize("fixture_dispute_create", &json!({"account":"acct_test"}))
        .unwrap();
    let response = provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "fixture_dispute_create",
            token: "sk_test_POLL_SECRET",
            resource: &resource,
        })
        .unwrap();
    assert_eq!(
        response.result,
        json!({
            "data": [{"id":"dp_created","charge":"ch_created"}],
            "has_more": false
        }),
        "the reconciliation body is the provider's, verbatim"
    );
    assert_eq!(
        response.envelope.get("created_charge"),
        Some(&json!("ch_created")),
        "the declared capture rides the sibling envelope"
    );
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(
        requests[1..]
            .iter()
            .all(|request| request.starts_with("GET /v1/disputes?")
                && request.contains("charge=ch_created")),
        "{requests:#?}"
    );
}

#[test]
fn setup_reconciliation_poll_exhaustion_stops_at_declared_bound() {
    let responses = Box::leak(Box::new([
        ("200 OK", r#"{"id":"acct_test"}"#),
        ("200 OK", r#"{"object":"balance","livemode":false}"#),
        (
            "200 OK",
            r#"{"id":"ch_committed","object":"charge","amount":100,"currency":"usd","paid":true,"status":"succeeded","livemode":false}"#,
        ),
        ("200 OK", r#"{"data":[],"has_more":false}"#),
        ("200 OK", r#"{"data":[],"has_more":false}"#),
        ("200 OK", r#"{"data":[],"has_more":false}"#),
        ("200 OK", r#"{"data":[],"has_more":false}"#),
    ]));
    let (base, server) = two_shot_full(responses);
    let provider = stripe_action(base, "fixture_dispute_charge_create");
    let resource = provider
        .canonicalize(
            "fixture_dispute_charge_create",
            &json!({"account":"acct_test","amount":100,"currency":"usd"}),
        )
        .unwrap();
    let response = provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "fixture_dispute_charge_create",
            token: "sk_test_POLL_SECRET",
            resource: &resource,
        })
        .unwrap();
    assert_eq!(
        response.result,
        json!({ "data": [], "has_more": false }),
        concat!(
            "exhaustion must return the final empty reconciliation result so the sitting can ",
            "honestly abort after the committed charge"
        )
    );
    assert_eq!(
        response.envelope.get("created_charge"),
        Some(&json!("ch_committed")),
        "the committed charge is still reported — in the envelope"
    );
    let requests = server.join().unwrap();
    assert_eq!(
        requests.len(),
        7,
        "two safety reads, one committed mutation, and exactly four reconciliation attempts"
    );
    assert!(requests[0].starts_with("GET /v1/account "));
    assert!(requests[1].starts_with("GET /v1/balance "));
    assert!(requests[2].starts_with("POST /v1/charges "));
    assert!(
        requests[3..]
            .iter()
            .all(|request| request.starts_with("GET /v1/disputes?")
                && request.contains("charge=ch_committed")),
        "{requests:#?}"
    );
}

#[test]
fn setup_reconciliation_query_renders_the_validated_scalar_capture() {
    let resource = CanonicalResource::from_map(BTreeMap::from([(
        "account".to_string(),
        Scalar::Str("acct_test".to_string()),
    )]));
    let captures = BTreeMap::from([("created_charge".to_string(), json!("ch_created"))]);
    assert_eq!(
        render_query_value("{created_charge}", &resource, &captures).unwrap(),
        Some("ch_created".to_string())
    );
    let malformed = BTreeMap::from([("created_charge".to_string(), json!({"id":"ch_created"}))]);
    assert!(
        render_query_value("{created_charge}", &resource, &malformed).is_err(),
        "provider-selected objects must never become query authority"
    );
}

#[test]
fn stripe_stage_dispute_evidence_enforces_field_and_aggregate_character_limits() {
    let stripe = stripe_action("http://127.0.0.1:9".into(), "stage_dispute_evidence");
    let chars_20k = "x".repeat(20_000);
    let chars_10k = "x".repeat(10_000);
    let unicode_20k = "é".repeat(20_000);

    for request in [
        json!({"dispute":"du_1"}),
        json!({"dispute":"du_1","uncategorized_text":chars_20k}),
        json!({"dispute":"du_1","uncategorized_text":unicode_20k}),
        json!({
            "dispute":"du_1",
            "access_activity_log":"x".repeat(20_000),
            "billing_address":"x".repeat(20_000),
            "cancellation_policy_disclosure":"x".repeat(20_000),
            "cancellation_rebuttal":"x".repeat(20_000),
            "customer_email_address":"x".repeat(20_000),
            "customer_name":"x".repeat(20_000),
            "customer_purchase_ip":"x".repeat(20_000),
            "product_description":chars_10k,
        }),
    ] {
        stripe
            .canonicalize("stage_dispute_evidence", &request)
            .expect("exact field and aggregate character bounds must be accepted");
    }

    assert!(stripe
        .canonicalize(
            "stage_dispute_evidence",
            &json!({"dispute":"du_1","uncategorized_text":"x".repeat(20_001)}),
        )
        .is_err());
    assert!(stripe
        .canonicalize(
            "stage_dispute_evidence",
            &json!({
                "dispute":"du_1",
                "access_activity_log":"x".repeat(20_000),
                "billing_address":"x".repeat(20_000),
                "cancellation_policy_disclosure":"x".repeat(20_000),
                "cancellation_rebuttal":"x".repeat(20_000),
                "customer_email_address":"x".repeat(20_000),
                "customer_name":"x".repeat(20_000),
                "customer_purchase_ip":"x".repeat(20_000),
                "product_description":"x".repeat(10_001),
            }),
        )
        .is_err());
}

#[test]
fn stripe_webhook_url_equality_is_a_terminal_postcondition() {
    for (body, expected_proof) in [
        (
            r#"{"id":"we_123","url":"https://other.example/hook?token=provider-held-secret","status":"enabled","api_version":null,"enabled_events":["charge.succeeded","charge.failed"],"secret":"drop"}"#,
            json!({"id":"we_123","status":"enabled","api_version":null}),
        ),
        (
            r#"{"id":"we_123","status":"enabled","api_version":null,"enabled_events":["charge.succeeded","charge.failed"],"secret":"drop"}"#,
            json!({"id":"we_123","status":"enabled","api_version":null}),
        ),
    ] {
        let (base, server) = one_shot_full("200 OK", body);
        let stripe = stripe_action(base, "update_webhook_endpoint_fixed_bundle");
        let resource = stripe
            .canonicalize(
                "update_webhook_endpoint_fixed_bundle",
                &json!({"endpoint":"we_123","url":"https://example.com/hook"}),
            )
            .unwrap();
        let response = stripe
            .execute(ProviderCall {
                discipline: Default::default(),
                git_mirror: None,
                request_id: "",
                action: "update_webhook_endpoint_fixed_bundle",
                token: "rk_test_m3_secret",
                resource: &resource,
            })
            .unwrap();
        server.join().unwrap();
        assert!(!response.ok);
        assert_eq!(response.result["outcome"], "postcondition_failed");
        assert_eq!(response.result["field"], "url");
        let _ = &expected_proof;
        assert_eq!(
            response.result["provider_proof"],
            serde_json::from_str::<Value>(body).unwrap(),
            "the reconciliation proof is the body the provider sent, verbatim"
        );
        assert!(response.retained.is_some());
    }
}

fn moneypath_action(base: String, action: &str) -> GenericProvider {
    let descriptor = VENDORED_PROVIDERS
        .iter()
        .map(|document| ProviderDescriptor::parse(document).unwrap())
        .find(|descriptor| descriptor.name == "stripe")
        .unwrap();
    let document = crate::templates::VENDORED_CATALOG
        .iter()
        .copied()
        .find(|document| {
            document.contains("provider: stripe\n")
                && document.contains(&format!("action: {action}\n"))
        })
        .unwrap_or_else(|| panic!("stripe.{action} must be vendored"));
    let registry = Arc::new(TemplateRegistry::new());
    registry.load(document).unwrap();
    GenericProvider::from_descriptor_with_base(descriptor, base, registry)
}

fn moneypath_complete(provider: &GenericProvider, action: &str, value: Value) -> CanonicalResource {
    CanonicalResource::from_stored(
        &value.to_string(),
        provider.action_contract(action).unwrap(),
    )
    .unwrap()
}

fn assert_moneypath_requests(requests: &[String], paths: &[&str]) {
    assert_eq!(requests.len(), paths.len());
    for (request, path) in requests.iter().zip(paths) {
        assert!(
            request.starts_with(&format!("GET {path} HTTP/1.1")),
            "{request}"
        );
        let lower = request.to_ascii_lowercase();
        assert!(
            lower.contains("authorization: bearer rk_test_moneypath_secret"),
            "{request}"
        );
        assert!(
            lower.contains("stripe-version: 2026-06-24.dahlia"),
            "{request}"
        );
    }
}

#[test]
fn moneypath_production_evidence_profiles_use_exact_fixed_get_sequences() {
    let token = "rk_test_moneypath_secret";

    let (base, server) = two_shot_full(&[
        (
            "200 OK",
            r#"{"id":"acct_1","object":"account","default_currency":"usd"}"#,
        ),
        (
            "200 OK",
            r#"{"id":"cus_1","object":"customer","livemode":false}"#,
        ),
        (
            "200 OK",
            r#"{"id":"pm_1","object":"payment_method","customer":"cus_1","livemode":false}"#,
        ),
    ]);
    let provider = moneypath_action(base, "create_payment_intent_off_session");
    let partial = provider
        .canonicalize_present_fields(
            "create_payment_intent_off_session",
            &json!({"customer":"cus_1","payment_method":"pm_1","amount":500}),
        )
        .unwrap();
    let resolved = provider
        .resolve_request(
            crate::evidence::profile("stripe.create_payment_intent_off_session.v1").unwrap(),
            token,
            &partial,
        )
        .unwrap();
    assert_eq!(
        resolved.fields,
        BTreeMap::from([
            ("account".into(), Scalar::Str("acct_1".into())),
            ("currency".into(), Scalar::Str("usd".into())),
            ("mode".into(), Scalar::Str("test".into())),
        ])
    );
    assert_moneypath_requests(
        &server.join().unwrap(),
        &[
            "/v1/account",
            "/v1/customers/cus_1",
            "/v1/payment_methods/pm_1",
        ],
    );

    let (base, server) = two_shot_full(&[
        ("200 OK", r#"{"id":"acct_1","object":"account"}"#),
        (
            "200 OK",
            r#"{"id":"pi_1","object":"payment_intent","amount":500,"currency":"usd","customer":"cus_1","payment_method":null,"status":"requires_confirmation","capture_method":"automatic","confirmation_method":"automatic","livemode":false}"#,
        ),
        (
            "200 OK",
            r#"{"id":"pm_1","object":"payment_method","customer":"cus_1","livemode":false}"#,
        ),
    ]);
    let provider = moneypath_action(base, "confirm_payment_intent");
    let partial = provider
        .canonicalize_present_fields(
            "confirm_payment_intent",
            &json!({"payment_intent":"pi_1","payment_method":"pm_1"}),
        )
        .unwrap();
    let resolved = provider
        .resolve_request(
            crate::evidence::profile("stripe.confirm_payment_intent.v1").unwrap(),
            token,
            &partial,
        )
        .unwrap();
    assert_eq!(resolved.fields["amount"], Scalar::Int(500));
    assert_eq!(resolved.fields["customer"], Scalar::Str("cus_1".into()));
    assert_eq!(
        resolved.fields["status"],
        Scalar::Str("requires_confirmation".into())
    );
    assert_moneypath_requests(
        &server.join().unwrap(),
        &[
            "/v1/account",
            "/v1/payment_intents/pi_1",
            "/v1/payment_methods/pm_1",
        ],
    );

    let (base, server) = two_shot_full(&[
        ("200 OK", r#"{"id":"acct_1","object":"account"}"#),
        (
            "200 OK",
            r#"{"id":"pi_2","object":"payment_intent","amount":900,"amount_capturable":600,"currency":"usd","customer":"cus_1","status":"requires_capture","capture_method":"manual","confirmation_method":"automatic","livemode":false}"#,
        ),
    ]);
    let provider = moneypath_action(base, "capture_payment_intent");
    let partial = provider
        .canonicalize_present_fields(
            "capture_payment_intent",
            &json!({"payment_intent":"pi_2","amount":200}),
        )
        .unwrap();
    let resolved = provider
        .resolve_request(
            crate::evidence::profile("stripe.capture_payment_intent.v1").unwrap(),
            token,
            &partial,
        )
        .unwrap();
    assert_eq!(resolved.fields["intent_amount"], Scalar::Int(900));
    assert_eq!(resolved.fields["amount_capturable"], Scalar::Int(600));
    assert_moneypath_requests(
        &server.join().unwrap(),
        &["/v1/account", "/v1/payment_intents/pi_2"],
    );

    let (base, server) = two_shot_full(&[
        ("200 OK", r#"{"id":"acct_1","object":"account"}"#),
        (
            "200 OK",
            r#"{"id":"pi_3","object":"payment_intent","amount":900,"amount_capturable":250,"currency":"usd","customer":"cus_1","status":"requires_capture","capture_method":"manual","confirmation_method":"automatic","livemode":false}"#,
        ),
    ]);
    let provider = moneypath_action(base, "cancel_payment_intent");
    let partial = provider
        .canonicalize_present_fields("cancel_payment_intent", &json!({"payment_intent":"pi_3"}))
        .unwrap();
    let resolved = provider
        .resolve_request(
            crate::evidence::profile("stripe.cancel_payment_intent.v1").unwrap(),
            token,
            &partial,
        )
        .unwrap();
    assert_eq!(resolved.fields["amount"], Scalar::Int(250));
    assert_moneypath_requests(
        &server.join().unwrap(),
        &["/v1/account", "/v1/payment_intents/pi_3"],
    );

    let (base, server) = two_shot_full(&[
        ("200 OK", r#"{"id":"acct_1","object":"account"}"#),
        (
            "200 OK",
            r#"{"id":"in_1","object":"invoice","status":"open","amount_remaining":700,"currency":"usd","customer":"cus_1","livemode":false,"payment_settings":{"default_mandate":null,"payment_method_options":{"card":{"request_three_d_secure":"automatic"}},"payment_method_types":[]}}"#,
        ),
        (
            "200 OK",
            r#"{"id":"pm_1","object":"payment_method","customer":"cus_1","livemode":false}"#,
        ),
    ]);
    let provider = moneypath_action(base, "retry_invoice_payment");
    let partial = provider
        .canonicalize_present_fields(
            "retry_invoice_payment",
            &json!({"invoice":"in_1","payment_method":"pm_1"}),
        )
        .unwrap();
    let resolved = provider
        .resolve_request(
            crate::evidence::profile("stripe.retry_invoice_payment.v1").unwrap(),
            token,
            &partial,
        )
        .unwrap();
    assert_eq!(resolved.fields["amount"], Scalar::Int(700));
    assert_moneypath_requests(
        &server.join().unwrap(),
        &[
            "/v1/account",
            "/v1/invoices/in_1",
            "/v1/payment_methods/pm_1",
        ],
    );

    let (base, server) = two_shot_full(&[
        ("200 OK", r#"{"id":"acct_1","object":"account"}"#),
        (
            "200 OK",
            r#"{"id":"ch_1","object":"charge","paid":true,"amount":1000,"amount_refunded":100,"currency":"usd","livemode":false}"#,
        ),
    ]);
    let provider = moneypath_action(base, "refund_charge_bounded");
    let partial = provider
        .canonicalize_present_fields(
            "refund_charge_bounded",
            &json!({"charge":"ch_1","amount":500}),
        )
        .unwrap();
    let resolved = provider
        .resolve_request(
            crate::evidence::profile("stripe.refund_charge_bounded.v1").unwrap(),
            token,
            &partial,
        )
        .unwrap();
    assert_eq!(resolved.fields["currency"], Scalar::Str("usd".into()));
    assert_moneypath_requests(
        &server.join().unwrap(),
        &["/v1/account", "/v1/charges/ch_1"],
    );

    let (base, server) = two_shot_full(&[
        (
            "200 OK",
            r#"{"id":"acct_1","object":"account","payouts_enabled":true}"#,
        ),
        (
            "200 OK",
            r#"{"object":"balance","livemode":false,"available":[{"currency":"usd","amount":2000,"source_types":{"card":1500}}]}"#,
        ),
        (
            "200 OK",
            r#"{"id":"ba_1","object":"bank_account","account":"acct_1","currency":"usd","status":"verified"}"#,
        ),
    ]);
    let provider = moneypath_action(base, "create_standard_payout");
    let partial = provider
        .canonicalize_present_fields(
            "create_standard_payout",
            &json!({"amount":1000,"destination":"ba_1","source_type":"card"}),
        )
        .unwrap();
    let resolved = provider
        .resolve_request(
            crate::evidence::profile("stripe.create_standard_payout.v1").unwrap(),
            token,
            &partial,
        )
        .unwrap();
    assert_eq!(resolved.fields["account"], Scalar::Str("acct_1".into()));
    assert_eq!(resolved.fields["mode"], Scalar::Str("test".into()));
    assert_moneypath_requests(
        &server.join().unwrap(),
        &[
            "/v1/account",
            "/v1/balance",
            "/v1/accounts/acct_1/external_accounts/ba_1",
        ],
    );
}

#[test]
fn moneypath_production_evidence_malformed_and_relationship_mismatches_deny() {
    let (base, server) = one_shot_full("200 OK", r#"{"id":"acct_1","object":"customer"}"#);
    let provider = moneypath_action(base, "refund_charge_bounded");
    let partial = provider
        .canonicalize_present_fields(
            "refund_charge_bounded",
            &json!({"charge":"ch_1","amount":500}),
        )
        .unwrap();
    let failure = provider
        .resolve_request(
            crate::evidence::profile("stripe.refund_charge_bounded.v1").unwrap(),
            "rk_test_moneypath_secret",
            &partial,
        )
        .unwrap_err();
    assert_eq!(failure.class, EvidenceFailureClass::Malformed);
    server.join().unwrap();

    let (base, _server) = two_shot_full(&[
        (
            "200 OK",
            r#"{"id":"acct_1","object":"account","default_currency":"usd"}"#,
        ),
        (
            "200 OK",
            r#"{"id":"cus_1","object":"customer","livemode":false}"#,
        ),
        (
            "200 OK",
            r#"{"id":"pm_1","object":"payment_method","customer":"cus_other","livemode":false}"#,
        ),
    ]);
    let provider = moneypath_action(base, "create_payment_intent_off_session");
    let partial = provider
        .canonicalize_present_fields(
            "create_payment_intent_off_session",
            &json!({"customer":"cus_1","payment_method":"pm_1","amount":500}),
        )
        .unwrap();
    let failure = provider
        .resolve_request(
            crate::evidence::profile("stripe.create_payment_intent_off_session.v1").unwrap(),
            "rk_test_moneypath_secret",
            &partial,
        )
        .unwrap_err();
    assert_eq!(failure.class, EvidenceFailureClass::Mismatch);

    let (base, _server) = two_shot_full(&[
        ("200 OK", r#"{"id":"acct_1","object":"account"}"#),
        (
            "200 OK",
            r#"{"id":"pi_1","object":"payment_intent","amount":500,"currency":"usd","customer":"cus_1","status":"requires_confirmation","capture_method":"automatic","confirmation_method":"automatic","livemode":false,"transfer_data":{"destination":"acct_other"}}"#,
        ),
        (
            "200 OK",
            r#"{"id":"pm_1","object":"payment_method","customer":"cus_1","livemode":false}"#,
        ),
    ]);
    let provider = moneypath_action(base, "confirm_payment_intent");
    let partial = provider
        .canonicalize_present_fields(
            "confirm_payment_intent",
            &json!({"payment_intent":"pi_1","payment_method":"pm_1"}),
        )
        .unwrap();
    let failure = provider
        .resolve_request(
            crate::evidence::profile("stripe.confirm_payment_intent.v1").unwrap(),
            "rk_test_moneypath_secret",
            &partial,
        )
        .unwrap_err();
    assert_eq!(failure.class, EvidenceFailureClass::Mismatch);

    let (base, server) = two_shot_full(&[
        ("200 OK", r#"{"id":"acct_1","object":"account"}"#),
        (
            "200 OK",
            r#"{"id":"in_1","object":"invoice","status":"open","amount_remaining":700,"currency":"usd","customer":"cus_1","livemode":false,"payment_settings":{"payment_method_types":["card"]}}"#,
        ),
    ]);
    let provider = moneypath_action(base, "retry_invoice_payment");
    let partial = provider
        .canonicalize_present_fields(
            "retry_invoice_payment",
            &json!({"invoice":"in_1","payment_method":"pm_1"}),
        )
        .unwrap();
    let failure = provider
        .resolve_request(
            crate::evidence::profile("stripe.retry_invoice_payment.v1").unwrap(),
            "rk_test_moneypath_secret",
            &partial,
        )
        .unwrap_err();
    assert_eq!(failure.class, EvidenceFailureClass::Mismatch);
    assert_moneypath_requests(
        &server.join().unwrap(),
        &["/v1/account", "/v1/invoices/in_1"],
    );
}

#[test]
fn moneypath_production_mutations_send_only_exact_frozen_forms_and_hidden_key() {
    struct Case {
        action: &'static str,
        resource: Value,
        path: &'static str,
        body: &'static str,
        response: &'static str,
    }
    let cases = [
        Case {
            action: "create_payment_intent_off_session",
            resource: json!({"customer":"cus_1","payment_method":"pm_1","amount":500,"account":"acct_1","mode":"test","currency":"usd"}),
            path: "/v1/payment_intents",
            body: "amount=500&confirm=false&currency=usd&customer=cus_1&payment_method=pm_1",
            response: r#"{"id":"pi_new","object":"payment_intent","amount":500,"currency":"usd","customer":"cus_1","payment_method":"pm_1","livemode":false,"status":"requires_confirmation","client_secret":"must_drop"}"#,
        },
        Case {
            action: "confirm_payment_intent",
            resource: json!({"payment_intent":"pi_1","payment_method":"pm_1","account":"acct_1","mode":"test","currency":"usd","customer":"cus_1","amount":500,"status":"requires_confirmation","capture_method":"automatic","confirmation_method":"automatic"}),
            path: "/v1/payment_intents/pi_1/confirm",
            body: "error_on_requires_action=true&off_session=true&payment_method=pm_1",
            response: r#"{"id":"pi_1","object":"payment_intent","amount":500,"amount_capturable":0,"amount_received":500,"currency":"usd","customer":"cus_1","payment_method":"pm_1","livemode":false,"status":"succeeded","capture_method":"automatic","confirmation_method":"automatic","client_secret":"must_drop"}"#,
        },
        Case {
            action: "capture_payment_intent",
            resource: json!({"payment_intent":"pi_2","amount":200,"account":"acct_1","mode":"test","currency":"usd","customer":"cus_1","status":"requires_capture","capture_method":"manual","intent_amount":900,"amount_capturable":600}),
            path: "/v1/payment_intents/pi_2/capture",
            body: "amount_to_capture=200",
            response: r#"{"id":"pi_2","object":"payment_intent","amount":900,"amount_capturable":400,"amount_received":500,"currency":"usd","customer":"cus_1","livemode":false,"status":"requires_capture","capture_method":"manual","client_secret":"must_drop"}"#,
        },
        Case {
            action: "cancel_payment_intent",
            resource: json!({"payment_intent":"pi_3","account":"acct_1","mode":"test","currency":"usd","customer":"cus_1","amount":250,"status":"requires_capture","capture_method":"manual","confirmation_method":"automatic"}),
            path: "/v1/payment_intents/pi_3/cancel",
            body: "",
            response: r#"{"id":"pi_3","object":"payment_intent","amount":900,"currency":"usd","customer":"cus_1","livemode":false,"status":"canceled","capture_method":"manual","confirmation_method":"automatic","canceled_at":1700000000,"cancellation_reason":null,"client_secret":"must_drop"}"#,
        },
        Case {
            action: "retry_invoice_payment",
            resource: json!({"invoice":"in_1","payment_method":"pm_1","account":"acct_1","mode":"test","currency":"usd","customer":"cus_1","amount":700,"status":"open"}),
            path: "/v1/invoices/in_1/pay",
            body: "off_session=true&payment_method=pm_1",
            response: r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_due":700,"amount_paid":1200,"amount_remaining":0,"attempt_count":2,"hosted_invoice_url":"must_drop"}"#,
        },
        Case {
            action: "refund_charge_bounded",
            resource: json!({"charge":"ch_1","amount":300,"account":"acct_1","mode":"test","currency":"usd"}),
            path: "/v1/refunds",
            body: "amount=300&charge=ch_1",
            response: r#"{"id":"re_1","object":"refund","charge":"ch_1","amount":300,"currency":"usd","livemode":false,"status":"succeeded"}"#,
        },
        Case {
            action: "create_standard_payout",
            resource: json!({"amount":1000,"destination":"ba_1","source_type":"card","account":"acct_1","mode":"test","currency":"usd"}),
            path: "/v1/payouts",
            body: "amount=1000&currency=usd&destination=ba_1&method=standard&source_type=card",
            response: r#"{"id":"po_1","object":"payout","amount":1000,"currency":"usd","destination":"ba_1","source_type":"card","method":"standard","status":"pending","livemode":false,"arrival_date":1700000000}"#,
        },
    ];

    for case in cases {
        let (base, server) = one_shot_full("200 OK", case.response);
        let provider = moneypath_action(base, case.action);
        let resource = moneypath_complete(&provider, case.action, case.resource);
        let result = provider
            .execute(ProviderCall {
                discipline: proving("hidden_money_key"),
                git_mirror: None,
                request_id: "",
                action: case.action,
                token: "rk_test_mutation_secret",
                resource: &resource,
            })
            .unwrap();
        let response = result;
        let outcome = response
            .proof
            .expect("the proving discipline returns an observation");
        assert_eq!(outcome, EffectProof::Proved, "{}", case.action);
        assert!(response.ok, "{}: {:?}", case.action, response.result);
        assert!(response.retained.is_none(), "{}", case.action);
        let result_text = serde_json::to_string(&response.result).unwrap();
        // Under the verbatim override the created object comes back WHOLE — its own
        // provider id (letting reconciliation happen without a dashboard search) and, where the
        // provider sends one, its own `client_secret`. There is no secret-class floor stripping it.
        assert_eq!(
            response.result,
            serde_json::from_str::<Value>(case.response).unwrap(),
            "{}: the money success result is the verified body",
            case.action
        );
        if case.response.contains("must_drop") {
            assert!(
                result_text.contains("must_drop"),
                "{}: the floor is struck; the body is whole: {result_text}",
                case.action
            );
        }

        let request = server.join().unwrap();
        assert!(
            request.starts_with(&format!("POST {} HTTP/1.1", case.path)),
            "{}: {request}",
            case.action
        );
        let (headers, body) = request.split_once("\r\n\r\n").unwrap();
        let lower = headers.to_ascii_lowercase();
        assert!(lower.contains("authorization: bearer rk_test_mutation_secret"));
        assert!(lower.contains("stripe-version: 2026-06-24.dahlia"));
        assert!(lower.contains("idempotency-key: hidden_money_key"));
        assert_eq!(body, case.body, "{}", case.action);
        assert!(!body.contains("hidden_money_key"));
    }
}

#[test]
fn moneypath_production_raw_success_mismatches_remain_ambiguous() {
    let cases = [
        (
            "create_payment_intent_off_session",
            json!({"customer":"cus_1","payment_method":"pm_1","amount":500,"account":"acct_1","mode":"test","currency":"usd"}),
            r#"{"id":"pi_new","object":"payment_intent","amount":501,"currency":"usd","customer":"cus_1","payment_method":"pm_1","livemode":false,"status":"requires_confirmation"}"#,
        ),
        (
            "confirm_payment_intent",
            json!({"payment_intent":"pi_1","payment_method":"pm_1","account":"acct_1","mode":"test","currency":"usd","customer":"cus_1","amount":500,"status":"requires_confirmation","capture_method":"automatic","confirmation_method":"automatic"}),
            r#"{"id":"pi_1","object":"payment_intent","amount":500,"currency":"usd","customer":"cus_1","payment_method":"pm_1","livemode":false,"status":"requires_action","capture_method":"automatic","confirmation_method":"automatic"}"#,
        ),
        (
            "capture_payment_intent",
            json!({"payment_intent":"pi_2","amount":200,"account":"acct_1","mode":"test","currency":"usd","customer":"cus_1","status":"requires_capture","capture_method":"manual","intent_amount":900,"amount_capturable":600}),
            r#"{"id":"pi_2","object":"payment_intent","amount":900,"amount_capturable":399,"amount_received":500,"currency":"usd","customer":"cus_1","livemode":false,"status":"requires_capture","capture_method":"manual"}"#,
        ),
        (
            "cancel_payment_intent",
            json!({"payment_intent":"pi_3","account":"acct_1","mode":"test","currency":"usd","customer":"cus_1","amount":250,"status":"requires_capture","capture_method":"manual","confirmation_method":"automatic"}),
            r#"{"id":"pi_3","object":"payment_intent","currency":"usd","customer":"cus_1","livemode":false,"status":"succeeded","capture_method":"manual","confirmation_method":"automatic","canceled_at":1700000000}"#,
        ),
        (
            "retry_invoice_payment",
            json!({"invoice":"in_1","payment_method":"pm_1","account":"acct_1","mode":"test","currency":"usd","customer":"cus_1","amount":700,"status":"open"}),
            r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":1,"amount_paid":699,"attempt_count":2}"#,
        ),
        (
            "refund_charge_bounded",
            json!({"charge":"ch_1","amount":300,"account":"acct_1","mode":"test","currency":"usd"}),
            r#"{"id":"re_1","object":"refund","charge":"ch_other","amount":300,"currency":"usd","livemode":false,"status":"succeeded"}"#,
        ),
        (
            "create_standard_payout",
            json!({"amount":1000,"destination":"ba_1","source_type":"card","account":"acct_1","mode":"test","currency":"usd"}),
            r#"{"id":"po_1","object":"payout","amount":1000,"currency":"usd","destination":"ba_1","source_type":"card","method":"instant","status":"pending","livemode":false}"#,
        ),
    ];

    for (action, fields, body) in cases {
        let (base, server) = one_shot_full("200 OK", body);
        let provider = moneypath_action(base, action);
        let resource = moneypath_complete(&provider, action, fields);
        let response = provider
            .execute(ProviderCall {
                discipline: proving("hidden_money_key"),
                git_mirror: None,
                request_id: "",
                action,
                token: "rk_test_mutation_secret",
                resource: &resource,
            })
            .unwrap();
        let outcome = response
            .proof
            .expect("the proving discipline returns an observation");
        assert_eq!(outcome, EffectProof::Unproved, "{action}: {body}");
        assert!(!response.ok, "{action}: {body}");
        assert!(
            !response.result.is_null(),
            "an unproved 2xx still returns the body it could not prove: {action}: {body}"
        );
        assert!(response.retained.is_none(), "{action}: {body}");
        server.join().unwrap();
    }
}

#[test]
fn moneypath_cancel_success_requires_a_positive_integer_canceled_at() {
    let fields = json!({"payment_intent":"pi_3","account":"acct_1","mode":"test","currency":"usd","customer":"cus_1","amount":250,"status":"requires_capture","capture_method":"manual","confirmation_method":"automatic"});
    let mut response = json!({
        "id": "pi_3",
        "object": "payment_intent",
        "currency": "usd",
        "customer": "cus_1",
        "livemode": false,
        "status": "canceled",
        "capture_method": "manual",
        "confirmation_method": "automatic",
        "canceled_at": 1700000000
    });
    let invalid = [
        ("null", Value::Null),
        ("boolean", json!(true)),
        ("string", json!("1700000000")),
        ("object", json!({"timestamp": 1700000000})),
        ("array", json!([1700000000])),
        ("negative integer", json!(-1)),
        ("zero", json!(0)),
        ("float", json!(1700000000.5)),
    ];

    for (label, canceled_at) in invalid {
        response["canceled_at"] = canceled_at;
        let body = serde_json::to_vec(&response).unwrap();
        let (base, server) = one_shot_full_owned("200 OK", body);
        let provider = moneypath_action(base, "cancel_payment_intent");
        let resource = moneypath_complete(&provider, "cancel_payment_intent", fields.clone());
        let response = provider
            .execute(ProviderCall {
                discipline: proving("hidden_money_key"),
                git_mirror: None,
                request_id: "",
                action: "cancel_payment_intent",
                token: "rk_test_mutation_secret",
                resource: &resource,
            })
            .unwrap();
        let outcome = response
            .proof
            .expect("the proving discipline returns an observation");
        assert_eq!(outcome, EffectProof::Unproved, "{label}");
        assert!(!response.ok, "{label}");
        // Either shape is legal here and both carry the body: a failed `require` returns the
        // missing-proof envelope whose `provider_proof` IS the body, and a body that satisfies
        // `require` but not the compiled proof is returned outright.
        let carried = if response.result["outcome"] == json!("missing_proof_path") {
            response.result["provider_proof"].clone()
        } else {
            response.result.clone()
        };
        assert_eq!(carried["id"], json!("pi_3"), "{label}");
        assert!(response.retained.is_none(), "{label}");
        server.join().unwrap();
    }

    response["canceled_at"] = json!(1700000000);
    let body = serde_json::to_vec(&response).unwrap();
    let (base, server) = one_shot_full_owned("200 OK", body);
    let provider = moneypath_action(base, "cancel_payment_intent");
    let resource = moneypath_complete(&provider, "cancel_payment_intent", fields);
    let response = provider
        .execute(ProviderCall {
            discipline: proving("hidden_money_key"),
            git_mirror: None,
            request_id: "",
            action: "cancel_payment_intent",
            token: "rk_test_mutation_secret",
            resource: &resource,
        })
        .unwrap();
    let outcome = response
        .proof
        .expect("the proving discipline returns an observation");
    assert_eq!(outcome, EffectProof::Proved);
    assert!(response.ok);
    server.join().unwrap();
}

#[test]
fn moneypath_invoice_success_uses_actual_typed_dahlia_fields_without_paid() {
    let invalid = [
        r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":0,"attempt_count":2}"#,
        r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":0,"amount_paid":1200}"#,
        r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":0,"amount_paid":"1200","attempt_count":2}"#,
        r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":0,"amount_paid":-1,"attempt_count":2}"#,
        r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":0,"amount_paid":1200,"attempt_count":0}"#,
        r#"{"id":"in_other","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":0,"amount_paid":1200,"attempt_count":2}"#,
        r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_other","livemode":false,"amount_remaining":0,"amount_paid":1200,"attempt_count":2}"#,
        r#"{"id":"in_1","object":"invoice","status":"paid","currency":"eur","customer":"cus_1","livemode":false,"amount_remaining":0,"amount_paid":1200,"attempt_count":2}"#,
        r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":true,"amount_remaining":0,"amount_paid":1200,"attempt_count":2}"#,
        r#"{"id":"in_1","object":"invoice","status":"open","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":0,"amount_paid":1200,"attempt_count":2}"#,
        r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":1,"amount_paid":1200,"attempt_count":2}"#,
    ];
    for body in invalid {
        let (base, server) = one_shot_full("200 OK", body);
        let provider = moneypath_action(base, "retry_invoice_payment");
        let resource = moneypath_complete(
            &provider,
            "retry_invoice_payment",
            json!({"invoice":"in_1","payment_method":"pm_1","account":"acct_1","mode":"test","currency":"usd","customer":"cus_1","amount":700,"status":"open"}),
        );
        let response = provider
            .execute(ProviderCall {
                discipline: proving("hidden_money_key"),
                git_mirror: None,
                request_id: "",
                action: "retry_invoice_payment",
                token: "rk_test_mutation_secret",
                resource: &resource,
            })
            .unwrap();
        let outcome = response
            .proof
            .expect("the proving discipline returns an observation");
        assert_eq!(outcome, EffectProof::Unproved, "{body}");
        assert!(!response.ok, "{body}");
        assert!(
            !response.result.is_null(),
            "an unproved 2xx still returns the body it could not prove: {body}"
        );
        assert!(response.retained.is_none(), "{body}");
        server.join().unwrap();
    }
}

#[test]
fn moneypath_payout_preconditions_repeat_exact_unretained_gets() {
    let (base, server) = two_shot_full(&[
        (
            "200 OK",
            r#"{"id":"acct_1","object":"account","payouts_enabled":true}"#,
        ),
        (
            "200 OK",
            r#"{"object":"balance","livemode":false,"available":[{"currency":"usd","amount":2000,"source_types":{"card":1500}}]}"#,
        ),
        (
            "200 OK",
            r#"{"id":"ba_1","object":"bank_account","account":"acct_1","currency":"usd","status":"verified"}"#,
        ),
    ]);
    let provider = moneypath_action(base, "create_standard_payout");
    let resource = moneypath_complete(
        &provider,
        "create_standard_payout",
        json!({"amount":1000,"destination":"ba_1","source_type":"card","account":"acct_1","mode":"test","currency":"usd"}),
    );
    let names = [
        "payouts_enabled".to_string(),
        "balance_sufficient".to_string(),
        "destination_belongs_and_currency_matches".to_string(),
    ];
    let preconditions =
        crate::preconditions::resolve_exact("stripe", "create_standard_payout", &names).unwrap();
    provider
        .check_preconditions(&preconditions, "rk_test_moneypath_secret", &resource)
        .unwrap();
    assert_moneypath_requests(
        &server.join().unwrap(),
        &[
            "/v1/account",
            "/v1/balance",
            "/v1/accounts/acct_1/external_accounts/ba_1",
        ],
    );
}

#[test]
fn moneypath_payout_precondition_denies_balance_mode_mismatch() {
    let (base, server) = one_shot_full(
        "200 OK",
        r#"{"object":"balance","livemode":true,"available":[{"currency":"usd","amount":2000,"source_types":{"card":1500}}]}"#,
    );
    let provider = moneypath_action(base, "create_standard_payout");
    let resource = moneypath_complete(
        &provider,
        "create_standard_payout",
        json!({"amount":1000,"destination":"ba_1","source_type":"card","account":"acct_1","mode":"test","currency":"usd"}),
    );
    let precondition =
        crate::preconditions::exact("stripe", "create_standard_payout", "balance_sufficient")
            .unwrap();
    let failure = provider
        .check_preconditions(&[precondition], "rk_test_moneypath_secret", &resource)
        .unwrap_err();
    assert_eq!(
        failure.class,
        crate::preconditions::PreconditionFailureClass::InsufficientBalance
    );
    assert_moneypath_requests(&[server.join().unwrap()], &["/v1/balance"]);
}
#[test]
fn setup_result_capture_selection_is_explicit_and_narrow() {
    // Captures build the SIBLING ENVELOPE, never the provider body. Only the declared
    // outputs appear; an unlisted capture the broker happens to hold does not escape.
    let captures = BTreeMap::from([
        ("account_id".to_string(), json!("acct_fixture")),
        ("unlisted".to_string(), json!("must-not-escape")),
    ]);
    let selected = BTreeMap::from([("account".to_string(), "account_id".to_string())]);
    let envelope = envelope_captures(&selected, &captures).expect("the selected capture exists");
    assert_eq!(
        Value::Object(envelope),
        json!({ "account": "acct_fixture" }),
        "the envelope carries exactly the declared outputs and nothing else"
    );
    // A declared output naming a capture no prior step produced is an integrity refusal, not a
    // silently absent key.
    let dangling = BTreeMap::from([("account".to_string(), "never_captured".to_string())]);
    assert!(envelope_captures(&dangling, &captures).is_err());
}

#[test]
fn live_stripe_fixture_credential_stops_before_the_mutation() {
    let (base, server) = two_shot_full(&[
        (
            "200 OK",
            r#"{"id":"acct_live","object":"account","livemode":true}"#,
        ),
        ("200 OK", r#"{"object":"balance","livemode":true}"#),
    ]);
    let descriptor = ProviderDescriptor::parse(
        "name: stripe\negress:\n  - https://api.stripe.com\nauth: bearer\n",
    )
    .unwrap();
    let registry = Arc::new(TemplateRegistry::new());
    registry
        .load(include_str!(
            "../../actions/stripe.fixture_customer_create.yaml"
        ))
        .expect("the Stripe customer fixture descriptor loads");
    let provider = GenericProvider::from_descriptor_with_base(descriptor, base, registry);
    let resource = provider
        .canonicalize(
            "fixture_customer_create",
            &json!({
                "account": "acct_live",
                "name": "cermet-live-refusal",
                "email": "live-refusal@example.invalid",
            }),
        )
        .unwrap();

    let response = provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "fixture_customer_create",
            token: "sk_live_must_not_mutate",
            resource: &resource,
        })
        .unwrap();
    let requests = server.join().unwrap();

    assert!(!response.ok);
    assert_eq!(response.result["outcome"], json!("precondition_failed"));
    assert_eq!(response.result["path"], json!("livemode"));
    assert_eq!(requests.len(), 2, "the customer-create POST must not fire");
    assert!(requests[0].starts_with("GET /v1/account "));
    assert!(requests[1].starts_with("GET /v1/balance "));
    assert!(
        requests.iter().all(|request| !request.starts_with("POST ")),
        "live-mode refusal emitted a mutation request: {requests:?}"
    );
}

// ---------------------------------------------------------------------------
// The response contract: VERBATIM.
//
// "Ship exactly what we say we ship. SQL for agent authority; SQL for filtering comes later."
// The agent-facing result and the stored artifact carry the provider's response exactly as it
// arrived. There is no `keep` allowlist, no secret-class floor, no scalars-only error squeeze:
// projection is an explicitly ENABLED restriction, never ambient, and ZERO projection classes are
// built. The two mechanisms that are NOT response projection stay live and are pinned here — the
// vault credential never enters a body, and an agent-submitted `secret`-class field the provider
// echoes back is still scrubbed out of every retained surface.
// ---------------------------------------------------------------------------

/// The same one-step acme read as [`ACME_READ_TEMPLATE`], but declaring `retention: none` — the
/// strongest RETENTION cap the grammar has (no artifact at all). A retention cap is not a
/// projection: it bounds what is durably STORED, never what the response says.
const ACME_NO_RETENTION_TEMPLATE: &str = "provider: acme\naction: read_thing\nfields:\n  - { name: id, type: str, required: true, class: identity, binding: exact_resource_pin }\nconsumes: [id]\nexecution_targets: [id]\nhttp:\n  steps:\n    - id: get\n      method: GET\n      path: /things/{id}\n      retention: none\n";

fn acme_provider_with(base: String, template: &str) -> GenericProvider {
    let doc =
        "name: acme\negress:\n  - https://api.acme.test\nauth: bearer\nheaders:\n  X-Extra: v1\n";
    let descriptor = ProviderDescriptor::parse(doc).expect("acme descriptor parses");
    let mut set = HashSet::new();
    set.insert("acme".to_string());
    let registry = Arc::new(TemplateRegistry::with_providers(set));
    registry.load(template).expect("acme template loads");
    GenericProvider::from_descriptor_with_base(descriptor, base, registry)
}

/// A field-rich body: every member beyond `name` is what a hand-curated `keep` list used to drop —
/// `client_secret` explicitly included, per the response contract's own words: "print it verbatim".
const ACME_RICH_BODY: &str =
    r#"{"id":"t1","name":"widget","client_secret":"cs_test_verbatim_canary","nested":{"deep":1}}"#;

fn acme_read(provider: &GenericProvider) -> ProviderResponse {
    let resource = provider
        .canonicalize("read_thing", &json!({"id": "t1"}))
        .unwrap();
    provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "read_thing",
            token: "tok_acme_secret",
            resource: &resource,
        })
        .unwrap()
}

#[test]
fn the_response_contract_returns_the_provider_body_verbatim() {
    let (base, server) = one_shot_full("200 OK", ACME_RICH_BODY);
    let response = acme_read(&acme_provider_with(base, ACME_READ_TEMPLATE));
    server.join().unwrap();
    assert_eq!(
        response.result,
        serde_json::from_str::<Value>(ACME_RICH_BODY).unwrap(),
        "the result is the raw wire body; no field is curated away"
    );
    assert_eq!(
        response.result["client_secret"],
        json!("cs_test_verbatim_canary"),
        "there is no secret-class floor — that is deliberate"
    );
    let retained = response.retained.expect("a full-retention step retains");
    assert_eq!(
        serde_json::from_slice::<Value>(&retained.bytes).unwrap(),
        serde_json::from_str::<Value>(ACME_RICH_BODY).unwrap(),
        "the stored artifact is the same body the agent got: one enforcement point, no delta"
    );
    assert_eq!(retained.total_bytes, ACME_RICH_BODY.len() as u64);
}

#[test]
fn retention_none_caps_the_artifact_without_narrowing_the_response() {
    let (base, server) = one_shot_full("200 OK", ACME_RICH_BODY);
    let response = acme_read(&acme_provider_with(base, ACME_NO_RETENTION_TEMPLATE));
    server.join().unwrap();
    assert_eq!(
        response.result,
        serde_json::from_str::<Value>(ACME_RICH_BODY).unwrap(),
        "a retention cap bounds storage, never the response"
    );
    assert!(
        response.retained.is_none(),
        "`retention: none` stores nothing"
    );
}

#[test]
fn verbatim_responses_never_waive_the_vault_or_agent_secret_scrub() {
    // The verbatim contract covers PROVIDER response data. It does not touch request-side custody:
    // an agent-submitted `secret`-class field echoed back by the provider is still scrubbed out of
    // the retained body, and the credential still rides only the Authorization header.
    const ECHO_TEMPLATE: &str = "provider: acme\naction: set_thing\nfields:\n  - { name: id, type: str, required: true, class: identity, binding: exact_resource_pin }\n  - { name: value, type: str, required: true, class: secret, binding: unbound }\nconsumes: [id, value]\nexecution_targets: [id]\nhttp:\n  steps:\n    - id: put\n      method: PUT\n      path: /things/{id}\n      body: { value: \"{value}\" }\n";
    let (base, server) = one_shot_full(
        "200 OK",
        r#"{"id":"t1","echo":"AGENT_SUBMITTED_SECRET_CANARY","extra":"kept"}"#,
    );
    let provider = acme_provider_with(base, ECHO_TEMPLATE);
    let resource = provider
        .canonicalize(
            "set_thing",
            &json!({"id":"t1","value":"AGENT_SUBMITTED_SECRET_CANARY"}),
        )
        .unwrap();
    let response = provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "set_thing",
            token: "tok_acme_secret",
            resource: &resource,
        })
        .unwrap();
    server.join().unwrap();
    let serialized = response.result.to_string();
    assert!(
        serialized.contains("extra"),
        "the result is still the raw body: {serialized}"
    );
    assert!(
        !serialized.contains("AGENT_SUBMITTED_SECRET_CANARY"),
        "the agent-submitted secret must stay scrubbed: {serialized}"
    );
    let retained = String::from_utf8(response.retained.expect("retained").bytes).unwrap();
    assert!(
        !retained.contains("AGENT_SUBMITTED_SECRET_CANARY"),
        "the retained artifact must stay scrubbed too: {retained}"
    );
    assert!(
        !serialized.contains("tok_acme_secret") && !retained.contains("tok_acme_secret"),
        "the credential never enters a body"
    );
}

#[test]
fn a_failed_money_response_retains_the_provider_error_evidence() {
    // A non-success money outcome used to answer `{"status":400}` and store nothing —
    // diagnosing a failure needed a live curl reproduction. The rejection now rides the result in
    // full: the HTTP status the executor adds, plus the provider's error object verbatim.
    const ERROR_BODY: &str = r#"{"error":{"code":"amount_too_large","type":"invalid_request_error","message":"declined","request_log_url":"https://dashboard.stripe.com/test/logs/req_canary","payment_intent":{"id":"pi_1","client_secret":"pi_1_secret_canary"}}}"#;

    let (base, server) = one_shot_full("400 Bad Request", ERROR_BODY);
    let provider = moneypath_resolver_provider(base);
    let resource = moneypath_resource();
    let response = provider
        .execute(ProviderCall {
            discipline: proving("money_key_private_canary"),
            git_mirror: None,
            request_id: "",
            action: "test_charge_evidence",
            token: "sk_test_money_secret",
            resource: &resource,
        })
        .unwrap();
    let outcome = response
        .proof
        .expect("the proving discipline returns an observation");
    server.join().unwrap();
    // A clean typed 4xx after invocation is a VERIFIED rejection — no money moved.
    assert_eq!(outcome, EffectProof::Refused);
    // The executor's non-2xx envelope is `{"status": <code>, "error": <the raw wire body>}` — the
    // status is ADDED evidence, not a projection.
    assert_eq!(response.result["status"], json!(400));
    assert_eq!(
        response.result["error"]["error"]["code"],
        json!("amount_too_large"),
        "the provider error classification rides the result: {}",
        response.result
    );
    assert_eq!(
        response.result["error"]["error"]["request_log_url"],
        json!("https://dashboard.stripe.com/test/logs/req_canary"),
        "the provider-side log deep-link is evidence a money receipt requires"
    );
    assert_eq!(
        response.result["error"]["error"]["payment_intent"]["client_secret"],
        json!("pi_1_secret_canary"),
        "nested provider resources are returned verbatim, not structurally dropped"
    );
    assert!(
        !response
            .result
            .to_string()
            .contains("money_key_private_canary"),
        "the broker-held idempotency key still has no public carrier"
    );
}

#[test]
fn a_successful_money_response_returns_the_verified_body() {
    // The created object's own provider id is present in the response, never nowhere to be found.
    const SUCCESS_BODY: &str = r#"{"id":"ch_ok","object":"charge","amount":2300,"account":"acct_test","currency":"usd","livemode":false,"receipt_url":"https://pay.stripe.test/r/1"}"#;
    let (base, server) = one_shot_full("200 OK", SUCCESS_BODY);
    let provider = moneypath_resolver_provider(base);
    let resource = moneypath_resource();
    let response = provider
        .execute(ProviderCall {
            discipline: proving("money_key_private_canary"),
            git_mirror: None,
            request_id: "",
            action: "test_charge_evidence",
            token: "sk_test_money_secret",
            resource: &resource,
        })
        .unwrap();
    let outcome = response
        .proof
        .expect("the proving discipline returns an observation");
    server.join().unwrap();
    assert_eq!(outcome, EffectProof::Proved);
    assert!(response.ok);
    assert_eq!(
        response.result,
        serde_json::from_str::<Value>(SUCCESS_BODY).unwrap(),
        "money success returns the verified body, id included"
    );
    assert!(
        response.retained.is_none(),
        "the money retention cap (`retention: none`) is unchanged: no artifact"
    );
    assert!(
        !response
            .result
            .to_string()
            .contains("money_key_private_canary"),
        "the broker-held idempotency key still has no public carrier"
    );
}

// ---- github.read_commit, the commit hop of broker-fetch ---------------------------

const READ_COMMIT_TEMPLATE: &str = include_str!("../../actions/github.read_commit.yaml");

fn github_with_read_commit(base: String) -> GenericProvider {
    let reg = Arc::new(TemplateRegistry::new());
    reg.load(READ_COMMIT_TEMPLATE)
        .expect("the vendored read_commit template loads");
    GithubProvider::with_base_and_templates(base, reg)
}

/// A signed-commit body in GitHub's real shape: the `verification.payload` is the RAW commit object
/// a client re-hashes to prove the OID, so it must survive verbatim.
const COMMIT_BODY: &str = concat!(
    r#"{"sha":"3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f40","#,
    r#""tree":{"sha":"aa11bb22cc33dd44ee55ff6677889900aabbccdd"},"#,
    r#""parents":[{"sha":"1111111111111111111111111111111111111111"}],"#,
    r#""author":{"name":"A","email":"a@example.invalid","date":"2026-07-28T00:00:00Z"},"#,
    r#""committer":{"name":"C","email":"c@example.invalid","date":"2026-07-28T00:00:01Z"},"#,
    r#""message":"one snapshot commit","#,
    r#""verification":{"verified":true,"reason":"valid","#,
    r#""signature":"-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----","#,
    r#""payload":"tree aa11bb22cc33dd44ee55ff6677889900aabbccdd\n"}}"#
);

#[test]
fn github_read_commit_gets_the_pinned_oid_and_returns_the_body_verbatim() {
    let (base, server) = one_shot("200 OK", COMMIT_BODY);
    let gh = github_with_read_commit(base);
    let resource = gh
        .canonicalize(
            "read_commit",
            &json!({
                "owner": "acme",
                "name": "website",
                "commit_sha": "3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f40",
            }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "read_commit",
            token: "ghp_secret_value_123456",
            resource: &resource,
        })
        .unwrap();

    let received = server.join().unwrap();
    assert!(
        received.starts_with(
            "GET /repos/acme/website/git/commits/3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f40 "
        ),
        "the frozen OID alone addresses the read: {received}"
    );
    assert!(received.contains("Bearer ghp_secret_value_123456"));
    assert!(resp.ok);
    // Verbatim: tree, parents, message AND the verification block a fetching client
    // needs to reconstruct the raw object are all still there.
    let expected: Value = serde_json::from_str(COMMIT_BODY).unwrap();
    assert_eq!(resp.result, expected);
    assert!(
        resp.result["verification"]["payload"].is_string()
            && resp.result["verification"]["signature"].is_string(),
        "the signature block survives projection-free: {}",
        resp.result
    );
}

#[test]
fn github_read_commit_refuses_a_ref_name_at_admission() {
    // `format: git_oid`: GitHub would happily resolve a branch NAME here, which
    // would pin a moving pointer instead of an immutable object.
    let gh = github_with_read_commit("http://127.0.0.1:9".into());
    for bad in ["main", "refs/heads/main", "3f2b1a0c", ""] {
        assert!(
            gh.canonicalize(
                "read_commit",
                &json!({ "owner": "acme", "name": "website", "commit_sha": bad }),
            )
            .is_err(),
            "read_commit must refuse a non-OID commit_sha `{bad}`"
        );
    }
}

#[test]
fn github_read_commit_fails_closed_on_a_non_2xx() {
    let (base, server) = one_shot("404 Not Found", r#"{"message":"Not Found"}"#);
    let gh = github_with_read_commit(base);
    let resource = gh
        .canonicalize(
            "read_commit",
            &json!({
                "owner": "acme",
                "name": "website",
                "commit_sha": "3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f40",
            }),
        )
        .unwrap();
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "read_commit",
            token: "ghp_x",
            resource: &resource,
        })
        .unwrap();
    server.join().unwrap();
    assert!(!resp.ok, "a 404 is a failure, never an empty success");
    assert_eq!(resp.result["status"], json!(404));
    assert_eq!(resp.result["error"], json!({ "message": "Not Found" }));
}

// ---- github.merge_pull_request, the PR-flow terminal write ------------------------

fn merge_resource(gh: &GenericProvider, method: &str) -> crate::contract::CanonicalResource {
    gh.canonicalize(
        "merge_pull_request",
        &json!({
            "owner": "acme", "name": "website", "number": "7",
            "sha": M3_OID_A, "merge_method": method,
        }),
    )
    .unwrap()
}

#[test]
fn merge_pull_request_puts_the_frozen_cas_sha_and_method() {
    let (base, server) = one_shot_full(
        "200 OK",
        r#"{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","merged":true,"message":"Pull Request successfully merged"}"#,
    );
    let gh = github_m3(base);
    let resource = merge_resource(&gh, "squash");
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "merge_pull_request",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    let req = server.join().unwrap();
    assert!(
        req.starts_with("PUT /repos/acme/website/pulls/7/merge "),
        "the merge lands on the exact PR: {req}"
    );
    let sent: Value = serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(
        sent,
        json!({ "sha": M3_OID_A, "merge_method": "squash" }),
        "the frozen CAS sha and the approved method are the whole body"
    );
    assert!(resp.ok);
    // Verbatim: the merge commit's own OID comes back, which is what a caller reconciles against.
    assert_eq!(
        resp.result["sha"],
        json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    );
    assert_eq!(resp.result["merged"], json!(true));
}

#[test]
fn merge_pull_request_fails_closed_on_sha_drift_with_a_legible_receipt() {
    // 409: the PR head moved after approval. GitHub's own CAS refuses, and so do we — the commit
    // the approver ruled on is the only commit that may merge.
    let (base, server) = one_shot_full(
        "409 Conflict",
        r#"{"message":"Head branch was modified. Review and try the merge again.","documentation_url":"https://docs.github.com/rest/pulls/pulls#merge-a-pull-request"}"#,
    );
    let gh = github_m3(base);
    let resource = merge_resource(&gh, "merge");
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "merge_pull_request",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    server.join().unwrap();
    assert!(!resp.ok, "a 409 sha drift is never a success");
    assert_eq!(resp.result["status"], json!(409));
    assert!(
        resp.result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Head branch was modified"),
        "the receipt says WHY in the provider's own words: {}",
        resp.result
    );
}

#[test]
fn merge_pull_request_fails_closed_on_an_unmergeable_or_draft_pr() {
    // 405: draft, blocked by required checks, or otherwise not mergeable.
    let (base, server) = one_shot_full(
        "405 Method Not Allowed",
        r#"{"message":"Pull Request is not mergeable","documentation_url":"https://docs.github.com/rest/pulls/pulls#merge-a-pull-request"}"#,
    );
    let gh = github_m3(base);
    let resource = merge_resource(&gh, "merge");
    let resp = gh
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: None,
            request_id: "",
            action: "merge_pull_request",
            token: "ghp_secret_12345678",
            resource: &resource,
        })
        .unwrap();
    server.join().unwrap();
    assert!(!resp.ok);
    assert_eq!(resp.result["status"], json!(405));
    assert_eq!(
        resp.result["error"]["message"],
        json!("Pull Request is not mergeable")
    );
}

#[test]
fn merge_pull_request_refuses_a_non_oid_sha_and_a_non_numeric_number() {
    let gh = github_m3("http://127.0.0.1:9".into());
    for (number, sha) in [
        ("7", "main"),    // a branch name is not the CAS pin
        ("7", "aaaaaaa"), // an abbreviated OID is not canonical
        ("07", M3_OID_A), // a padded number is not a canonical uint
        ("seven", M3_OID_A),
    ] {
        assert!(
            gh.canonicalize(
                "merge_pull_request",
                &json!({
                    "owner": "acme", "name": "website", "number": number,
                    "sha": sha, "merge_method": "merge",
                }),
            )
            .is_err(),
            "merge_pull_request must refuse number={number} sha={sha}"
        );
    }
    // Every field is required: an absent merge_method can never be defaulted for the agent.
    assert!(gh
        .canonicalize(
            "merge_pull_request",
            &json!({ "owner": "acme", "name": "website", "number": "7", "sha": M3_OID_A }),
        )
        .is_err());
}

// ---- github.update_pull_request, the PR close-out write ---------------------------

const UPDATED_PR_BODY: &str =
    r#"{"id":9,"number":7,"state":"closed","title":"Edited","body":"unchanged"}"#;

fn update_pr(gh: &GenericProvider, request: Value) -> crate::contract::CanonicalResource {
    gh.canonicalize("update_pull_request", &request).unwrap()
}

fn run_update(
    gh: &GenericProvider,
    resource: &crate::contract::CanonicalResource,
) -> ProviderResponse {
    gh.execute(ProviderCall {
        discipline: Default::default(),
        git_mirror: None,
        request_id: "",
        action: "update_pull_request",
        token: "ghp_secret_12345678",
        resource,
    })
    .unwrap()
}

#[test]
fn update_pull_request_closes_with_only_the_fields_the_request_froze() {
    let (base, server) = one_shot_full("200 OK", UPDATED_PR_BODY);
    let gh = github_m3(base);
    let resource = update_pr(
        &gh,
        json!({ "owner": "acme", "name": "website", "number": "7", "state": "closed" }),
    );
    let resp = run_update(&gh, &resource);
    let req = server.join().unwrap();
    assert!(
        req.starts_with("PATCH /repos/acme/website/pulls/7 "),
        "the edit lands on the exact PR: {req}"
    );
    let sent: Value = serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    // THE POINT: absent optionals are OMITTED, not sent as null. A PATCH carrying
    // {"title": null, "body": null} would clobber both on a close.
    assert_eq!(
        sent,
        json!({ "state": "closed" }),
        "only the approved field reaches the wire"
    );
    assert!(resp.ok);
    assert_eq!(resp.result["state"], json!("closed"));
}

#[test]
fn update_pull_request_title_only_edit_omits_state_and_body() {
    let (base, server) = one_shot_full("200 OK", UPDATED_PR_BODY);
    let gh = github_m3(base);
    let resource = update_pr(
        &gh,
        json!({ "owner": "acme", "name": "website", "number": "7", "title": "Edited" }),
    );
    let _ = run_update(&gh, &resource);
    let req = server.join().unwrap();
    let sent: Value = serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(
        sent,
        json!({ "title": "Edited" }),
        "a title edit must not mention state or body at all"
    );
    let obj = sent.as_object().unwrap();
    assert!(!obj.contains_key("state") && !obj.contains_key("body"));
}

#[test]
fn update_pull_request_sends_every_present_field_together() {
    let (base, server) = one_shot_full("200 OK", UPDATED_PR_BODY);
    let gh = github_m3(base);
    let resource = update_pr(
        &gh,
        json!({
            "owner": "acme", "name": "website", "number": "7",
            "state": "closed", "title": "Edited", "body": "why it closed",
        }),
    );
    let _ = run_update(&gh, &resource);
    let req = server.join().unwrap();
    let sent: Value = serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(
        sent,
        json!({ "state": "closed", "title": "Edited", "body": "why it closed" })
    );
}

#[test]
fn update_pull_request_refuses_a_non_uint_number_at_admission() {
    let gh = github_m3("http://127.0.0.1:9".into());
    for number in ["07", "seven", "-1", "", "7.0"] {
        assert!(
            gh.canonicalize(
                "update_pull_request",
                &json!({ "owner": "acme", "name": "website", "number": number, "state": "closed" }),
            )
            .is_err(),
            "update_pull_request must refuse number `{number}`"
        );
    }
}

#[test]
fn update_pull_request_fails_closed_on_a_missing_pr_or_a_rejected_state() {
    for (status, body, code) in [
        ("404 Not Found", r#"{"message":"Not Found"}"#, 404),
        (
            "422 Unprocessable Entity",
            r#"{"message":"Validation Failed","errors":[{"field":"state","code":"invalid"}]}"#,
            422,
        ),
    ] {
        let (base, server) = one_shot_full_owned(status, body.as_bytes().to_vec());
        let gh = github_m3(base);
        let resource = update_pr(
            &gh,
            json!({ "owner": "acme", "name": "website", "number": "7", "state": "closed" }),
        );
        let resp = run_update(&gh, &resource);
        server.join().unwrap();
        assert!(!resp.ok, "{status} is never a success");
        assert_eq!(resp.result["status"], json!(code));
        assert!(resp.result["error"]["message"].is_string());
    }
}

// ---------------------------------------------------------------------------
// the receipt names the UPSTREAM's transition
// ---------------------------------------------------------------------------

struct HopFixture {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    git: crate::git::GitConfig,
}

impl HopFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let git = crate::git::GitConfig::at(root.join("mirrors"));
        HopFixture {
            _dir: dir,
            root,
            git,
        }
    }

    fn run(&self, cwd: &std::path::Path, args: &[&str]) -> String {
        let out = std::process::Command::new(crate::git::DEFAULT_GIT_BINARY)
            .args(args)
            .current_dir(cwd)
            .env("HOME", &self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "fixture git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn commit(&self, name: &str) -> String {
        let src = self.root.join("src");
        std::fs::write(src.join(name), name).unwrap();
        self.run(&src, &["add", "-A"]);
        self.run(&src, &["commit", "-q", "-m", name]);
        self.run(&src, &["rev-parse", "HEAD"])
    }

    /// A stand-in for the daemon's hook program: these tests exercise the HOP, not the decision, so
    /// the mirror's hook admits everything.
    fn allow_all_hook(&self) -> std::path::PathBuf {
        let path = self.root.join("hook");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    /// A provider whose git origin is a local `file://` root — a synthetic descriptor, so nothing
    /// process-global is involved.
    fn provider(&self) -> GenericProvider {
        let upstream_root = self.root.join("upstream");
        let descriptor = ProviderDescriptor::parse(&format!(
            "name: github\negress:\n  - https://api.github.com\nauth: bearer\ngit:\n  \
             origin: file://{}\n  auth: basic:x-access-token\n",
            upstream_root.display()
        ))
        .expect("a file:// git origin is legal in the egress-testing build");
        let templates = Arc::new(TemplateRegistry::new());
        templates
            .load(include_str!("../../actions/github.push.yaml"))
            .expect("the vendored push template loads");
        templates
            .load(include_str!("../../actions/github.fetch.yaml"))
            .expect("the vendored fetch template loads");
        GenericProvider::from_descriptor(descriptor, templates, self.git.clone())
    }

    /// A `git` that records the credential channel it was handed and then IS git.
    ///
    /// Every offline test of this seam runs against a `file://` upstream, where
    /// `http.<url>.extraHeader` is inert — so nothing here could tell an attached credential from a
    /// missing one, and a credential regression on the fetch branch would have shipped green. The
    /// wrapper makes the channel observable without giving up a working hop. `hermetic_command`
    /// clears the environment and sets HOME to the mirror dir, so that is where the log lands.
    fn recording_git(&self) -> std::path::PathBuf {
        let path = self.root.join("git-recorder");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\n{{ printf 'ARGV'; for a in \"$@\"; do printf ' %s' \"$a\"; done; \
                 printf '\\nKEY0=%s\\nVALUE0=%s\\n' \"${{GIT_CONFIG_KEY_0-}}\" \
                 \"${{GIT_CONFIG_VALUE_0-}}\"; }} >> \"$HOME/hop-invocations.log\"\n\
                 exec {} \"$@\"\n",
                crate::git::DEFAULT_GIT_BINARY
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }
}

#[test]
fn the_push_receipt_names_the_upstreams_from_oid_and_the_mirrors_tip_separately() {
    let f = HopFixture::new();
    let src = f.root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    f.run(&src, &["init", "-q", "-b", "main", "."]);
    let first = f.commit("first.txt");

    let repo = crate::git::RepoId::parse("github/acme/website").unwrap();
    let hook = f.allow_all_hook();
    let mirror = crate::git::ensure_mirror(&f.git, &repo, &hook).unwrap();
    let upstream = f.root.join("upstream/acme/website.git");
    std::fs::create_dir_all(upstream.parent().unwrap()).unwrap();
    f.run(
        &f.root,
        &["init", "-q", "--bare", upstream.to_str().unwrap()],
    );

    // Seed both, then let a third party advance ONLY the upstream.
    f.run(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);
    f.run(&src, &["push", "-q", upstream.to_str().unwrap(), "main"]);
    let theirs = f.commit("theirs.txt");
    f.run(&src, &["push", "-q", upstream.to_str().unwrap(), "main"]);
    // The agent's commit lands in the mirror, whose tip is still `first`.
    let ours = f.commit("ours.txt");
    f.run(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);

    let provider = f.provider();
    let resource = provider
        .canonicalize(
            "push",
            &json!({
                "owner": "acme",
                "name": "website",
                "branch": "main",
                "new_oid": ours,
                // What the update hook saw: the MIRROR's tip, which is stale here.
                "mirror_old_oid": first,
            }),
        )
        .expect("the decision's resource canonicalizes");
    let response = provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: Some(&mirror),
            request_id: "req_00112233445566aa",
            action: "push",
            token: "ghp_never_in_a_receipt",
            resource: &resource,
        })
        .expect("the hop lands");

    assert!(response.ok);
    // The honest answer to "what did my agent change on GitHub".
    assert_eq!(response.result["upstream_old_oid"], json!(theirs));
    assert_eq!(response.result["upstream_created_ref"], json!(false));
    assert_eq!(response.result["new_oid"], json!(ours));
    // Kept beside it, separately labelled, because it is a different fact.
    assert_eq!(response.result["mirror_old_oid"], json!(first));
    assert_ne!(response.result["upstream_old_oid"], json!(first));
    assert!(!response
        .result
        .to_string()
        .contains("ghp_never_in_a_receipt"));
}

#[test]
fn a_created_upstream_ref_is_receipted_as_a_creation_not_a_fabricated_oid() {
    let f = HopFixture::new();
    let src = f.root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    f.run(&src, &["init", "-q", "-b", "main", "."]);
    let only = f.commit("only.txt");

    let repo = crate::git::RepoId::parse("github/acme/website").unwrap();
    let hook = f.allow_all_hook();
    let mirror = crate::git::ensure_mirror(&f.git, &repo, &hook).unwrap();
    let upstream = f.root.join("upstream/acme/website.git");
    std::fs::create_dir_all(upstream.parent().unwrap()).unwrap();
    f.run(
        &f.root,
        &["init", "-q", "--bare", upstream.to_str().unwrap()],
    );
    f.run(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);

    let provider = f.provider();
    let resource = provider
        .canonicalize(
            "push",
            &json!({
                "owner": "acme",
                "name": "website",
                "branch": "main",
                "new_oid": only,
            }),
        )
        .unwrap();
    let response = provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: Some(&mirror),
            request_id: "req_00112233445566aa",
            action: "push",
            token: "ghp_never_in_a_receipt",
            resource: &resource,
        })
        .expect("creating the upstream ref is the same effect as advancing it");

    assert_eq!(response.result["upstream_created_ref"], json!(true));
    assert_eq!(response.result["upstream_old_oid"], Value::Null);
    assert_eq!(response.result["mirror_old_oid"], Value::Null);
}

/// The FETCH branch of `execute_git` — the refresh a `git clone` through the plane runs,
/// and the one a virgin box runs first — had no unit coverage at all: `HopFixture` loaded only the
/// push template, so nothing asserted that `refresh_from_upstream` is handed `Some(&credential)`.
/// This is the seam a live fresh-box run once failed on, and the level at which "did the
/// credentialed hop carry a credential" is answerable in a second instead of a container round trip.
///
/// The mirror here has never been contacted before, so this drives creation and refresh together —
/// which in this daemon are the same call.
#[test]
fn a_virgin_mirrors_refresh_carries_the_credential_scoped_to_the_upstream_it_fetches() {
    let f = HopFixture::new();
    let src = f.root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    f.run(&src, &["init", "-q", "-b", "main", "."]);
    let seeded = f.commit("seeded.txt");

    let upstream = f.root.join("upstream/acme/website.git");
    std::fs::create_dir_all(upstream.parent().unwrap()).unwrap();
    f.run(
        &f.root,
        &["init", "-q", "--bare", upstream.to_str().unwrap()],
    );
    f.run(&src, &["push", "-q", upstream.to_str().unwrap(), "main"]);

    let repo = crate::git::RepoId::parse("github/acme/website").unwrap();
    let hook = f.allow_all_hook();
    let recorder = f.recording_git();
    let git = f.git.clone().with_binary(&recorder);
    let mirror = crate::git::ensure_mirror(&git, &repo, &hook).unwrap();

    let mut provider = f.provider();
    provider.git = git.clone();
    let resource = provider
        .canonicalize("fetch", &json!({ "owner": "acme", "name": "website" }))
        .expect("the decision's resource canonicalizes");
    let response = provider
        .execute(ProviderCall {
            discipline: Default::default(),
            git_mirror: Some(&mirror),
            request_id: "req_00112233445566bb",
            action: "fetch",
            token: "ghp_never_in_a_receipt",
            resource: &resource,
        })
        .expect("the refresh lands");

    assert!(response.ok);
    assert_eq!(response.result["refreshed"], json!(true));
    assert!(!response
        .result
        .to_string()
        .contains("ghp_never_in_a_receipt"));

    // The upstream's tip is what the mirror now serves — a refresh, not an empty success.
    let served = f.run(
        &f.root,
        &[
            "--git-dir",
            mirror.to_str().unwrap(),
            "rev-parse",
            "refs/heads/main",
        ],
    );
    assert_eq!(served, seeded);

    // And the invocation that went to the upstream carried the credential, scoped to the exact URL
    // it fetched from. `file://` makes the header inert, which is precisely why it is asserted here
    // rather than inferred from the hop having worked.
    let expected_url = format!(
        "file://{}/acme/website.git",
        f.root.join("upstream").display()
    );
    let log = std::fs::read_to_string(git.mirror_dir.join("hop-invocations.log"))
        .expect("the recorder ran");
    let fetches: Vec<&str> = log
        .split("ARGV")
        .filter(|record| {
            let argv = record.lines().next().unwrap_or_default();
            argv.contains(" fetch ") && argv.contains(&expected_url)
        })
        .collect();
    assert_eq!(fetches.len(), 1, "exactly one upstream fetch ran:\n{log}");
    assert!(
        fetches[0].contains(&format!("KEY0=http.{expected_url}.extraHeader")),
        "the credential scope is the URL the fetch was given:\n{}",
        fetches[0]
    );
    assert!(
        fetches[0].contains("VALUE0=Authorization: Basic "),
        "the descriptor's `basic:x-access-token` shape is what rides it:\n{}",
        fetches[0]
    );
}

// ---------------------------------------------------------------------------
// THE MINTED URL (the relay pattern at single-request scale).
//
// GitHub answers the job-log endpoint's credentialed GET with `302` + a `Location` header carrying
// a pre-signed, self-authorizing, ~60s-expiring blob URL and an EMPTY body. The broker's whole job
// is that credentialed MINT: the redirect is the answer, not a detour. Two engine properties carry
// it — a step may DECLARE a 3xx among its `success_statuses`, and `retain_headers` lifts named
// response headers into the broker-authored envelope. The engine still never follows a redirect
// (`redirect::Policy::none()`), never opens a second origin, and never reads a byte of the log.
// ---------------------------------------------------------------------------

/// A local server for the minted-URL shape. It answers ONE connection with the canned status line,
/// verbatim `extra_headers`, and body — then WATCHES (non-blocking) for further connections. The
/// join value is `(the request it served, how many further connections arrived)`, and that count is
/// the instrument: it is how these tests prove the engine made exactly one request.
fn one_shot_counting(
    status_line: &'static str,
    extra_headers: &'static str,
    body: &'static str,
) -> (String, thread::JoinHandle<(String, usize)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut data = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&tmp[..n]);
            if data.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&data).into_owned();
        let response = format!(
            "HTTP/1.1 {status_line}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        drop(stream);
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
        let mut further = 0usize;
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok(_) => further += 1,
                Err(_) => thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        (request, further)
    });
    (format!("http://{addr}"), handle)
}

/// A github provider carrying exactly one caller-supplied template, pinned to a local base.
fn github_with_template(base: String, doc: &str) -> GenericProvider {
    let reg = Arc::new(TemplateRegistry::new());
    reg.load(doc).expect("the template loads");
    GithubProvider::with_base_and_templates(base, reg)
}

/// The engine-level probe: one bodyless GET whose ONLY declared success is a 302, retaining the
/// `location` the provider minted. Deliberately `retention: none` — a 302 has no body to store.
const MINT_TEMPLATE: &str = r#"
provider: github
action: mint_probe
fields:
  - { name: owner, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: name,  type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [owner, name]
execution_targets: [owner, name]
http:
  steps:
    - id: mint
      method: GET
      path: /repos/{owner}/{name}/logs
      success_statuses: [302]
      retain_headers: [location]
      retention: none
"#;

/// The same probe WITHOUT the 3xx declaration: proves the widening is a per-step declaration.
const UNDECLARED_TEMPLATE: &str = r#"
provider: github
action: undeclared_probe
fields:
  - { name: owner, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: name,  type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [owner, name]
execution_targets: [owner, name]
http:
  steps:
    - id: read
      method: GET
      path: /repos/{owner}/{name}/logs
      success_statuses: [200]
      retention: none
"#;

const MINTED_URL: &str =
    "https://productionresultssa0.blob.core.windows.net/actions-results/abc?sig=DERIVED&se=60";

fn mint_call<'a>(action: &'a str, resource: &'a CanonicalResource) -> ProviderCall<'a> {
    ProviderCall {
        discipline: Default::default(),
        git_mirror: None,
        request_id: "",
        action,
        token: "ghp_secret_12345678",
        resource,
    }
}

// A step that DECLARES 302 succeeds on 302, and the header it declared rides the broker-authored
// envelope — which is what the receipt carries. The response contract is untouched: a bodyless 302
// still projects as the verbatim empty body (JSON null), never a broker-invented one.
#[test]
fn a_declared_302_succeeds_and_its_receipt_carries_the_minted_location() {
    let (base, server) = one_shot_counting(
        "302 Found",
        concat!(
            "Location: ",
            "https://productionresultssa0.blob.core.windows.net/actions-results/abc?sig=DERIVED&se=60",
            "\r\n"
        ),
        "",
    );
    let gh = github_with_template(base, MINT_TEMPLATE);
    let resource = gh
        .canonicalize("mint_probe", &json!({ "owner": "acme", "name": "website" }))
        .unwrap();
    let resp = gh.execute(mint_call("mint_probe", &resource)).unwrap();
    let (request, further) = server.join().unwrap();

    assert!(resp.ok, "a DECLARED 302 is a success: {:?}", resp.result);
    assert_eq!(
        resp.envelope.get("location").and_then(Value::as_str),
        Some(MINTED_URL),
        "the minted URL rides the broker-authored envelope: {:?}",
        resp.envelope
    );
    assert_eq!(
        resp.result,
        Value::Null,
        "the response contract stays verbatim: an empty 302 body is an empty result"
    );
    assert!(
        request.starts_with("GET /repos/acme/website/logs"),
        "one bodyless GET at the frozen path: {request}"
    );
    // The credential bought the mint and stayed home: the URL is DERIVED authority, not the vault
    // credential, and nothing in the receipt carries the token.
    assert!(
        !format!("{:?}{:?}", resp.result, resp.envelope).contains("ghp_secret"),
        "the vault credential never reaches the response surface"
    );
    assert_eq!(
        further, 0,
        "the engine makes EXACTLY ONE request — the minted URL is never fetched"
    );
}

// The regression that keeps the widening per-step: an UNDECLARED 302 fails closed exactly as it did
// before this engine delta existed. This doubles as the canary for every existing JSON verb, whose
// steps all declare 2xx-only sets.
#[test]
fn an_undeclared_302_still_fails_closed() {
    let (base, server) = one_shot_counting(
        "302 Found",
        concat!(
            "Location: ",
            "https://productionresultssa0.blob.core.windows.net/actions-results/abc?sig=DERIVED&se=60",
            "\r\n"
        ),
        "",
    );
    let gh = github_with_template(base, UNDECLARED_TEMPLATE);
    let resource = gh
        .canonicalize(
            "undeclared_probe",
            &json!({ "owner": "acme", "name": "website" }),
        )
        .unwrap();
    let resp = gh
        .execute(mint_call("undeclared_probe", &resource))
        .unwrap();
    let (_, further) = server.join().unwrap();

    assert!(
        !resp.ok,
        "a 302 nobody declared is still a failure: {:?}",
        resp.result
    );
    assert_eq!(resp.result["status"], json!(302));
    assert!(
        resp.envelope.is_empty(),
        "a step that declared no retained header authors no envelope: {:?}",
        resp.envelope
    );
    assert_eq!(further, 0, "and the redirect is still never followed");
}

// A declared 302 whose Location is ABSENT fails closed and NAMES the header it did not get. A mint
// with nothing minted is not a success with a hole in it.
#[test]
fn a_declared_302_without_its_location_fails_closed_naming_the_header() {
    let (base, server) = one_shot_counting("302 Found", "", "");
    let gh = github_with_template(base, MINT_TEMPLATE);
    let resource = gh
        .canonicalize("mint_probe", &json!({ "owner": "acme", "name": "website" }))
        .unwrap();
    let resp = gh.execute(mint_call("mint_probe", &resource)).unwrap();
    let (_, further) = server.join().unwrap();

    assert!(
        !resp.ok,
        "a 302 carrying no Location is not a mint: {:?}",
        resp.result
    );
    assert_eq!(
        resp.result["outcome"], "missing_retained_header",
        "{:?}",
        resp.result
    );
    assert_eq!(resp.result["header"], "location", "{:?}", resp.result);
    assert_eq!(further, 0);
}

// The canary for the untouched majority: a 200-declared JSON verb behaves exactly as before —
// verbatim body, retained artifact, and an EMPTY envelope, because it retains no header.
#[test]
fn an_ordinary_json_verb_is_byte_identical_after_the_delta() {
    const BODY: &str = r#"{"total_count":1,"jobs":[{"id":51,"name":"build","status":"completed","conclusion":"failure","steps":[{"name":"cargo nextest","conclusion":"failure","number":2}]}]}"#;
    let (base, server) = one_shot_full("200 OK", BODY);
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "read_workflow_run_jobs",
            &json!({ "owner": "acme", "name": "website", "run_id": "16789012345" }),
        )
        .unwrap();
    let resp = gh
        .execute(mint_call("read_workflow_run_jobs", &resource))
        .unwrap();
    let _ = server.join().unwrap();
    assert!(resp.ok);
    assert_eq!(
        resp.result,
        serde_json::from_str::<Value>(BODY).unwrap(),
        "the provider's body reaches the agent unchanged"
    );
    assert!(
        resp.envelope.is_empty(),
        "no retained header, no envelope: {:?}",
        resp.envelope
    );
    assert!(resp.retained.is_some(), "the artifact path is unchanged");
}

// The shipped verb, on the wire. `github.read_job_log` is the minted-URL shape in production form:
// one credentialed GET at the frozen job's log endpoint, GitHub's 302 accepted as the answer, the
// pre-signed URL handed back in the receipt's broker envelope — and the log itself left entirely to
// the agent's own credential-free curl.
#[test]
fn read_job_log_mints_the_url_and_leaves_the_bytes_to_native_tooling() {
    let (base, server) = one_shot_counting(
        "302 Found",
        concat!(
            "Location: ",
            "https://productionresultssa0.blob.core.windows.net/actions-results/abc?sig=DERIVED&se=60",
            "\r\n"
        ),
        "",
    );
    let gh = github_m3(base);
    let resource = gh
        .canonicalize(
            "read_job_log",
            &json!({ "owner": "acme", "name": "website", "job_id": "51" }),
        )
        .unwrap();
    let resp = gh.execute(mint_call("read_job_log", &resource)).unwrap();
    let (request, further) = server.join().unwrap();

    assert!(resp.ok, "the mint succeeded: {:?}", resp.result);
    assert!(
        request.starts_with("GET /repos/acme/website/actions/jobs/51/logs"),
        "one bodyless GET at the frozen job: {request}"
    );
    assert_eq!(
        resp.envelope.get("location").and_then(Value::as_str),
        Some(MINTED_URL),
        "the receipt carries the minted URL — the whole product of the hop"
    );
    assert!(
        resp.retained.is_none(),
        "a 302 has no body, so there is no artifact to store"
    );
    assert_eq!(
        further, 0,
        "the broker mints and STOPS: the blob URL is never fetched from inside the daemon"
    );
}

// The fail-closed twin: the log endpoint answering anything but its declared 302 is not a mint.
#[test]
fn read_job_log_fails_closed_on_anything_but_the_declared_redirect() {
    for (status, body) in [
        ("200 OK", "{}"),
        ("404 Not Found", r#"{"message":"Not Found"}"#),
        ("410 Gone", r#"{"message":"Gone"}"#),
    ] {
        let (base, server) = one_shot_full(status, body);
        let gh = github_m3(base);
        let resource = gh
            .canonicalize(
                "read_job_log",
                &json!({ "owner": "acme", "name": "website", "job_id": "51" }),
            )
            .unwrap();
        let resp = gh.execute(mint_call("read_job_log", &resource)).unwrap();
        let _ = server.join().unwrap();
        assert!(
            !resp.ok,
            "`{status}` is not the declared mint: {:?}",
            resp.result
        );
        assert!(
            resp.envelope.is_empty(),
            "a failed mint authors no envelope: {:?}",
            resp.envelope
        );
    }
}

// One job, one pin string: `format: uint` admits the canonical bare decimal only.
#[test]
fn read_job_log_job_id_admits_only_the_canonical_uint() {
    let gh = github_m3("http://127.0.0.1:9".into());
    let canon = |job_id: &str| {
        gh.canonicalize(
            "read_job_log",
            &json!({ "owner": "acme", "name": "website", "job_id": job_id }),
        )
    };
    for good in ["1", "51", "45678901234"] {
        assert!(canon(good).is_ok(), "`{good}` is a canonical job id");
    }
    for bad in ["01", "+1", "-1", "1 ", "0x1", "", "1/2"] {
        assert!(
            canon(bad).is_err(),
            "job_id `{bad}` must be refused at admission"
        );
    }
}
