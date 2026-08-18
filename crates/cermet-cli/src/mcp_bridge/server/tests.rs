use super::*;
use std::cell::RefCell;
use std::io::Cursor;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// A hello reply from a daemon on THIS build — what every fake below models unless it is
/// specifically about skew, so no unrelated test grows a build-skew note.
fn hello_of(session_id: impl Into<String>, features: Vec<String>) -> SessionHello {
    SessionHello {
        session_id: session_id.into(),
        features,
        build: cermet_ipc::BUILD_ID.to_string(),
    }
}

/// A `WireOps` fake that records every `hello` + `call_with_session` and can be told to reject the
/// FIRST call as expired — so the cache's mint/reuse/re-Hello-once behavior is testable offline.
struct FakeWire {
    hellos: RefCell<u32>,
    calls: RefCell<Vec<String>>, // the session id each call ran under
    expire_first_call: RefCell<bool>,
}

impl FakeWire {
    fn new(expire_first_call: bool) -> Self {
        Self {
            hellos: RefCell::new(0),
            calls: RefCell::new(Vec::new()),
            expire_first_call: RefCell::new(expire_first_call),
        }
    }
}

impl WireOps for FakeWire {
    fn hello(&self) -> Result<SessionHello, AgentError> {
        let mut n = self.hellos.borrow_mut();
        *n += 1;
        Ok(hello_of(format!("sess_{n}"), vec![]))
    }
    fn call_with_session(&self, _cmd: &AgentCommand, session: &str) -> Result<Value, AgentError> {
        self.calls.borrow_mut().push(session.to_string());
        if *self.expire_first_call.borrow() {
            *self.expire_first_call.borrow_mut() = false;
            return Err(AgentError::Server(SESSION_EXPIRED.to_string()));
        }
        Ok(json!({ "kind": "catalog", "session": session }))
    }
}

#[test]
fn session_cache_hellos_once_then_reuses_the_cached_session() {
    let wire = FakeWire::new(false);
    let cache = SessionCache::new();
    let cmd = AgentCommand::Catalog;

    cache.call(&wire, &cmd).expect("first call ok");
    cache.call(&wire, &cmd).expect("second call ok");

    assert_eq!(
        *wire.hellos.borrow(),
        1,
        "Hello is sent once and cached for process lifetime"
    );
    assert_eq!(
        *wire.calls.borrow(),
        vec!["sess_1".to_string(), "sess_1".to_string()],
        "both calls thread onto the SAME cached session"
    );
}

#[test]
fn session_cache_rehellos_once_on_expiry_then_retries() {
    let wire = FakeWire::new(true); // the first call_with_session returns SESSION_EXPIRED
    let cache = SessionCache::new();
    let cmd = AgentCommand::Catalog;

    let resp = cache
        .call(&wire, &cmd)
        .expect("the call recovers after one re-Hello");
    assert_eq!(
        resp["session"], "sess_2",
        "the retry ran under the freshly minted session"
    );
    assert_eq!(
        *wire.hellos.borrow(),
        2,
        "exactly one re-Hello (two total) on expiry"
    );
    assert_eq!(
        *wire.calls.borrow(),
        vec!["sess_1".to_string(), "sess_2".to_string()],
        "first attempt used the stale session, the retry the re-minted one"
    );

    // A subsequent call reuses the re-minted session — no further Hello.
    cache.call(&wire, &cmd).expect("subsequent call ok");
    assert_eq!(
        *wire.hellos.borrow(),
        2,
        "no extra Hello once a fresh session is cached"
    );
    assert_eq!(wire.calls.borrow().last().unwrap(), "sess_2");
}

/// A transport that runs a closure — no socket needed.
struct FakeTransport<F: Fn(&AgentCommand) -> Result<Value, AgentError>>(F);
impl<F: Fn(&AgentCommand) -> Result<Value, AgentError>> AgentTransport for FakeTransport<F> {
    fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
        (self.0)(cmd)
    }
}

fn fixed(resp: Value) -> FakeTransport<impl Fn(&AgentCommand) -> Result<Value, AgentError>> {
    FakeTransport(move |_| Ok(resp.clone()))
}

fn tools_call(name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
}

fn call_result(resp: &Value) -> (&Value, bool) {
    let content = &resp["result"]["content"];
    let is_error = resp["result"]["isError"]
        .as_bool()
        .expect("isError present");
    (content, is_error)
}

fn first_text(content: &Value) -> &str {
    content[0]["text"].as_str().expect("text content")
}

#[test]
fn initialize_reports_protocol_and_server_info() {
    let t = fixed(Value::Null);
    let msg = json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {} });
    let resp = handle_message(&t, &msg).expect("initialize replies");
    assert_eq!(resp["id"], json!(0));
    assert_eq!(resp["result"]["protocolVersion"], json!(PROTOCOL_VERSION));
    assert!(resp["result"]["capabilities"]["tools"].is_object());
    assert_eq!(resp["result"]["serverInfo"]["name"], json!("cermet"));
    // The handshake names the ENTRY POINT. A tool list alone leaves agents picking the most
    // task-shaped name and reading `catalog` only after they have run out of other ideas.
    let instructions = resp["result"]["instructions"]
        .as_str()
        .expect("initialize carries server instructions");
    assert!(
        instructions.contains("catalog"),
        "the instructions name the entry-point tool: {instructions}"
    );
}

#[test]
fn initialized_notification_gets_no_reply() {
    let t = fixed(Value::Null);
    let msg = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    assert!(
        handle_message(&t, &msg).is_none(),
        "a notification (no id) must not produce a response"
    );
}

/// The static tool DESCRIPTIONS are the first thing the model reads, so their canonical examples
/// steer which provider it reaches for. They must name a live Stripe verb — a shelved provider
/// there teaches a request that can only fail closed.
#[test]
fn tool_descriptions_use_stripe_as_their_canonical_example() {
    let t = fixed(Value::Null);
    let msg = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    let resp = handle_message(&t, &msg).expect("tools/list replies");
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    let by_name = |name: &str| -> String {
        let tool = tools
            .iter()
            .find(|t| t["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("{name} tool is absent"));
        serde_json::to_string(tool).expect("tool serializes")
    };

    let catalog = by_name("catalog");
    assert!(
        catalog.contains("stripe"),
        "the catalog provider filter must give a live Stripe example: {catalog}"
    );
    let request = by_name("request_capability");
    assert!(
        request.contains("stripe") && request.contains("get_charge"),
        "request_capability must give a live Stripe provider/action example: {request}"
    );

    // No shelved provider may be named as an example anywhere in the static tool surface.
    let surface = serde_json::to_string(tools).expect("tools serialize");
    // github and vercel are live products; only railway is still shelved.
    let shelved = "railway";
    assert!(
        !surface.contains(shelved),
        "a product-disabled provider is used as a tool-description example: {shelved}"
    );
}

#[test]
fn tools_list_exposes_exactly_the_agent_tools_and_no_approve() {
    let t = fixed(Value::Null);
    let msg = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    let resp = handle_message(&t, &msg).expect("tools/list replies");
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(
        names,
        vec![
            "catalog",
            "request_capability",
            "request_status",
            "execute_capability",
            "request_vocabulary",
            "list_connected_providers",
            "verify_audit",
            "artifact",
        ]
    );
    // Pipelines are deleted — no pipeline tool may appear on the agent surface.
    for n in &names {
        assert!(
            !n.contains("pipeline"),
            "the MCP surface must never expose a pipeline tool, found {n:?}"
        );
    }
    // No acceptance or rule-authority mutation tool may appear on the agent surface.
    // none of the operator mutation verbs (connect/apply/deny/secure/policy/ratify/profile live
    // behind the ctl path on another uid). The exact-list assertion above is the byte-identity
    // guard: adding any new static mutation surface fails this test.
    for n in &names {
        for forbidden in ["approve", "widen", "activate", "write", "mutate", "rule"] {
            assert!(
                !n.contains(forbidden),
                "the MCP surface must never expose authority mutation `{forbidden}`, found {n:?}"
            );
        }
        for forbidden in [
            "connect", "apply", "deny", "secure", "policy", "ratify", "profile",
        ] {
            assert_ne!(
                *n, forbidden,
                "the MCP surface must not expose the operator verb {forbidden:?}"
            );
        }
    }
    // execute names its handle `request_id`, never `grant_id`.
    let exec = tools
        .iter()
        .find(|t| t["name"] == json!("execute_capability"))
        .unwrap();
    let props = &exec["inputSchema"]["properties"];
    assert!(
        props.get("request_id").is_some(),
        "execute takes request_id"
    );
    assert!(
        props.get("grant_id").is_none(),
        "execute must NOT expose a grant_id parameter"
    );
    assert_eq!(exec["inputSchema"]["required"], json!(["request_id"]));
    let req = tools
        .iter()
        .find(|t| t["name"] == json!("request_capability"))
        .unwrap();
    let rprops = &req["inputSchema"]["properties"];
    assert!(rprops.get("alias").is_none());
    assert!(rprops.get("provider").is_some());
    assert!(rprops.get("action").is_some());
    // `justification` is in the required set: the daemon enforces it at the agent IPC boundary,
    // and the schema DECLARES the behavior that is enforced.
    assert_eq!(
        req["inputSchema"]["required"],
        json!(["provider", "action", "justification"])
    );
}
#[test]
fn request_capability_with_neither_shape_errors_client_side() {
    let t = fixed(Value::Null);
    let resp = handle_message(
        &t,
        &tools_call("request_capability", json!({ "resource": { "x": 1 } })),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(is_error);
    assert!(first_text(content).contains("provider"));
}

#[test]
fn request_allow_says_execute_now() {
    let t = fixed(json!({
        "kind": "requested", "request_id": "rq-a", "decision": "allow",
        "reason": "sentence match", "authority_kind": "sentence"
    }));
    let resp = handle_message(
        &t,
        &tools_call(
            "request_capability",
            json!({ "provider": "v", "action": "a" }),
        ),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    let text = first_text(content);
    assert!(text.contains("Allowed"), "got: {text}");
    assert!(text.contains("execute_capability"));
    assert!(!text.to_lowercase().contains("approval"));
}

#[test]
fn moneypath_request_forwards_retry_effect_outside_the_frozen_resource() {
    let seen = Arc::new(Mutex::new(None));
    let captured = Arc::clone(&seen);
    let transport = FakeTransport(move |cmd: &AgentCommand| {
        *captured.lock().unwrap() = Some(cmd.clone());
        Ok(json!({
            "kind": "requested",
            "request_id": "rq-retry",
            "decision": "allow",
            "reason": "sentence match",
            "effect_id": "effect_0123456789abcdef0123456789abcdef"
        }))
    });
    let response = handle_message(
        &transport,
        &tools_call(
            "request_capability",
            json!({
                "provider": "stripe",
                "action": "capture_payment_intent",
                "resource": {"payment_intent":"pi_1","amount":500},
                "retry_effect": "effect_0123456789abcdef0123456789abcdef"
            }),
        ),
    )
    .unwrap();
    let (content, is_error) = call_result(&response);
    assert!(!is_error);
    assert!(
        first_text(content).contains("effect_0123456789abcdef0123456789abcdef"),
        "the safe retry handle must survive MCP rendering: {content:?}"
    );
    let command = seen.lock().unwrap().clone().unwrap();
    let AgentCommand::Request {
        resource,
        retry_effect,
        ..
    } = command
    else {
        panic!("request command expected")
    };
    assert_eq!(
        retry_effect.as_deref(),
        Some("effect_0123456789abcdef0123456789abcdef")
    );
    assert!(resource.get("retry_effect").is_none());
}

#[test]
fn request_deny_says_do_not_retry() {
    let t = fixed(json!({
        "kind": "requested", "request_id": "rq-d", "decision": "deny",
        "reason": "outside sentence", "authority_kind": "sentence"
    }));
    let resp = handle_message(
        &t,
        &tools_call(
            "request_capability",
            json!({ "provider": "v", "action": "a" }),
        ),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error, "deny is a valid answer, not a tool failure");
    let text = first_text(content);
    assert!(text.contains("Denied by sentence authority"), "got: {text}");
    assert!(text.contains("do not retry"));
}

#[test]
fn broker_mcp_deny_returns_the_exact_safe_widen_hint() {
    let hint = "to allow: cermet rules allow 'stripe.support@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa where amount <= 50000'";
    let t = fixed(json!({
        "kind": "requested", "request_id": "rq-m2", "decision": "deny",
        "reason": "outside rule", "hint": hint
    }));
    let resp = handle_message(
        &t,
        &tools_call(
            "request_capability",
            json!({ "provider": "stripe", "action": "refund" }),
        ),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);

    assert!(!is_error, "a broker denial is a valid MCP response");
    let text = first_text(content);
    let command = hint.strip_prefix("to allow: ").unwrap();
    assert!(
        text.lines().any(|line| line == command),
        "exact safe command missing from MCP response: {text}"
    );
    assert!(
        text.contains("CERMET.md"),
        "document workflow missing: {text}"
    );
    assert!(
        text.contains("cermet doc apply"),
        "document apply step missing: {text}"
    );
}

#[test]
fn mcp_widen_commands_survive_real_posix_tokenization_in_both_paths() {
    use std::os::unix::fs::PermissionsExt;

    let sentence = "stripe.support@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa where amount <= 50000";
    let hint = format!("to allow: cermet rules allow '{sentence}'");
    let direct = fixed(json!({
        "kind": "requested", "request_id": "rq-direct", "decision": "deny",
        "reason": "outside rule", "hint": hint
    }));
    let response = handle_message(
        &direct,
        &tools_call(
            "request_capability",
            json!({ "provider": "stripe", "action": "refund" }),
        ),
    )
    .unwrap();
    let (content, is_error) = call_result(&response);
    assert!(!is_error, "a direct request denial is a valid MCP response");
    let direct_text = first_text(content).to_string();

    let calls = Arc::new(Mutex::new(Vec::new()));
    let generated = Arc::new(VerbCallFake {
        request_reply: json!({
            "kind": "requested", "request_id": "rq-generated", "decision": "deny",
            "reason": "outside rule", "hint": hint
        }),
        execute_reply: Value::Null,
        calls,
    });
    let supervisor = Arc::new(RunSupervisor::new(4, 16));
    let (content, is_error) = tool_verb_call(
        &generated,
        &supervisor,
        "stripe-refund",
        &json!({ "amount": 50000, "justification": "test the denial" }),
    );
    assert!(is_error, "a denied generated verb must not execute");
    let generated_text = content[0]["text"].as_str().unwrap().to_string();

    for rendered in [direct_text, generated_text] {
        let command = rendered
            .lines()
            .find_map(|line| line.find("cermet rules allow ").map(|start| &line[start..]))
            .expect("the rendered response carries the advisory command");
        let dir = tempfile::tempdir().unwrap();
        let recorder = dir.path().join("cermet");
        let output = dir.path().join("argv");
        std::fs::write(
            &recorder,
            "#!/bin/sh\nprintf '%s\\000' \"$@\" > \"$CERMET_ARGV_OUT\"\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&recorder).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&recorder, permissions).unwrap();

        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .env("PATH", dir.path())
            .env("CERMET_ARGV_OUT", &output)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "the rendered command must be valid POSIX shell"
        );
        let bytes = std::fs::read(output).unwrap();
        let argv = bytes
            .split(|byte| *byte == 0)
            .filter(|arg| !arg.is_empty())
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        assert_eq!(
            argv,
            vec![
                b"rules".to_vec(),
                b"allow".to_vec(),
                sentence.as_bytes().to_vec()
            ]
        );
    }
}

/// Pull the appended structured decision block out of a request_capability tool result.
fn decision_block(text: &str) -> Value {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("{\"authority_match\""))
        .expect("a structured decision block line");
    serde_json::from_str(line.trim()).expect("the decision block is valid JSON")
}

#[test]
fn decision_block_projects_only_sentence_outcomes() {
    let allow = request_decision_block("req_1", "allow", "sentence match", None);
    assert_eq!(allow["authority_match"], json!("allow"));
    assert_eq!(allow["grant_state"], json!("ready"));
    assert_eq!(allow["next_action"], json!("execute"));
    assert_eq!(allow["request_id"], json!("req_1"));

    let deny = request_decision_block("req_3", "deny", "provider_disabled", None);
    assert_eq!(deny["reason"], "provider_disabled");
    assert_eq!(deny["grant_state"], json!("denied"));
    assert_eq!(deny["next_action"], json!("stop"));
    for d in ["allow", "deny"] {
        let na = request_decision_block("r", d, "", None)["next_action"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(matches!(na.as_str(), "execute" | "stop"));
    }
}

#[test]
fn request_capability_tool_embeds_the_decision_block() {
    let t = fixed(json!({
        "kind": "requested", "request_id": "rq-9", "decision": "deny"
    }));
    let resp = handle_message(
        &t,
        &tools_call(
            "request_capability",
            json!({ "provider": "v", "action": "a" }),
        ),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    let text = first_text(content);
    let block = decision_block(text);
    assert_eq!(block["request_id"], json!("rq-9"));
    assert_eq!(block["authority_match"], json!("deny"));
    assert_eq!(block["grant_state"], json!("denied"));
    assert_eq!(block["next_action"], json!("stop"));
}

#[test]
fn mcp_paths_render_sentence_authority_without_sensitive_provenance() {
    let direct = fixed(json!({
        "kind": "requested", "request_id": "rq-sentence", "decision": "allow",
        "reason": "sentence allow", "authority_kind": "sentence"
    }));
    let response = handle_message(
        &direct,
        &tools_call(
            "request_capability",
            json!({ "provider": "stripe", "action": "refund" }),
        ),
    )
    .unwrap();
    let direct_text = first_text(&response["result"]["content"]);
    let block = decision_block(direct_text);
    assert_eq!(block["authority_match"], json!("allow"));
    assert!(!direct_text.contains("fingerprint"));
    assert!(!direct_text.contains("selector"));

    let calls = Arc::new(Mutex::new(Vec::new()));
    let generated = Arc::new(VerbCallFake {
        request_reply: json!({
            "kind": "requested", "request_id": "rq-denied", "decision": "deny",
            "reason": "outside sentence", "authority_kind": "sentence"
        }),
        execute_reply: Value::Null,
        calls,
    });
    let supervisor = Arc::new(RunSupervisor::new(4, 16));
    let (content, is_error) = tool_verb_call(
        &generated,
        &supervisor,
        "stripe-refund",
        &json!({ "amount": 50000, "justification": "test authority rendering" }),
    );
    assert!(is_error);
    let generated_text = content[0]["text"].as_str().unwrap();
    assert!(generated_text.contains("Denied by sentence authority"));
    assert!(!generated_text.contains("fingerprint"));
    assert!(!generated_text.contains("selector"));
}

#[test]
fn request_never_leaks_a_grant_id_even_if_the_wire_carried_one() {
    // Defense in depth: even a (protocol-impossible) grant_id on the wire is dropped by the
    // typed projection before it can reach the model.
    let t = fixed(json!({
        "kind": "requested", "request_id": "rq-7", "decision": "deny", "grant_id": "GRANT-LEAK", "token": "SEKRIT"
    }));
    let resp = handle_message(
        &t,
        &tools_call(
            "request_capability",
            json!({ "provider": "v", "action": "a" }),
        ),
    )
    .unwrap();
    let text = first_text(&resp["result"]["content"]);
    assert!(!text.contains("GRANT-LEAK"), "leaked grant_id: {text}");
    assert!(!text.contains("SEKRIT"), "leaked a secret: {text}");
    assert!(text.contains("rq-7"), "the request_id must survive: {text}");
}

#[test]
fn request_missing_provider_is_a_tool_error_not_a_crash() {
    let t = fixed(Value::Null);
    let resp = handle_message(
        &t,
        &tools_call("request_capability", json!({ "action": "deploy" })),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(is_error);
    assert!(first_text(content).contains("provider"));
}

#[test]
fn execute_missing_request_id_is_a_tool_error() {
    let t = fixed(Value::Null);
    let resp = handle_message(&t, &tools_call("execute_capability", json!({}))).unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(is_error);
    assert!(first_text(content).contains("request_id"));
}

#[test]
fn moneypath_generated_tools_omit_provider_resolved_inputs() {
    let frame = json!({"kind":"catalog","catalog":[{
        "provider":"stripe",
        "action":"test_charge_evidence",
        "requestable":true,
        "sentence_denied":false,
        "execution_targets":["charge","account","currency","mode"],
        "fields":[
            {"name":"charge","type":"str","required":true,"class":"identity","binding":"exact_resource_pin","origin":"agent_request", "forms": ["=", "in"] },
            {"name":"amount","type":"int","required":true,"class":"side_effect","binding":"bounded","origin":"agent_request", "forms": ["=", "in", "<=", ">=", "budget"] },
            {"name":"account","type":"str","required":true,"class":"identity","binding":"exact_resource_pin","origin":"provider_resolved", "forms": ["=", "in"] },
            {"name":"currency","type":"str","required":true,"class":"identity","binding":"exact_resource_pin","origin":"provider_resolved", "forms": ["=", "in"] },
            {"name":"mode","type":"str","required":true,"class":"identity","binding":"exact_resource_pin","origin":"provider_resolved", "forms": ["=", "in"] }
        ]
    }]});
    let tools = generated_verb_tools(&frame);
    let schema = &tools[0]["inputSchema"];
    assert!(schema["properties"].get("charge").is_some());
    assert!(schema["properties"].get("amount").is_some());
    for resolved in ["account", "currency", "mode"] {
        assert!(
            schema["properties"].get(resolved).is_none(),
            "provider-resolved `{resolved}` must not be agent-fillable"
        );
        assert!(!schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == resolved));
    }
}

#[test]
fn moneypath_vendored_tools_expose_only_each_actions_real_agent_inputs() {
    let registry = cermet_core::templates::TemplateRegistry::new();
    for document in cermet_core::templates::VENDORED_CATALOG {
        registry.load(document).unwrap();
    }
    let frame = json!({
        "kind": "catalog",
        "catalog": cermet_core::templates::catalog_of(&registry, true),
    });
    let tools = generated_verb_tools(&frame);
    let expected = [
        (
            "stripe-create_payment_intent_off_session",
            &["amount", "customer", "payment_method"][..],
        ),
        (
            "stripe-confirm_payment_intent",
            &["payment_intent", "payment_method"][..],
        ),
        (
            "stripe-capture_payment_intent",
            &["amount", "payment_intent"][..],
        ),
        ("stripe-cancel_payment_intent", &["payment_intent"][..]),
        (
            "stripe-retry_invoice_payment",
            &["invoice", "payment_method"][..],
        ),
        ("stripe-refund_charge_bounded", &["amount", "charge"][..]),
        (
            "stripe-create_standard_payout",
            &["amount", "destination", "source_type"][..],
        ),
    ];

    for (name, expected_fields) in expected {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("missing generated tool {name}"));
        let properties = tool["inputSchema"]["properties"].as_object().unwrap();
        let mut actual = properties
            .keys()
            .filter(|field| !VERB_TOOL_RESERVED.contains(&field.as_str()))
            .map(String::as_str)
            .collect::<Vec<_>>();
        actual.sort_unstable();
        assert_eq!(actual, expected_fields, "{name}");
        for resolved in ["account", "mode", "currency"] {
            assert!(
                !properties.contains_key(resolved),
                "{name} exposes provider-resolved {resolved}"
            );
        }
    }
}

#[test]
fn moneypath_generated_tools_fail_closed_on_missing_or_unknown_field_origin() {
    for field in [
        json!({"name":"account","type":"str","required":true,"class":"identity","binding":"exact_resource_pin", "forms": ["=", "in"] }),
        json!({"name":"account","type":"str","required":true,"class":"identity","binding":"exact_resource_pin","origin":"unknown", "forms": ["=", "in"] }),
    ] {
        let frame = json!({"kind":"catalog","catalog":[{
            "provider":"stripe",
            "action":"test_charge_evidence",
            "requestable":true,
            "sentence_denied":false,
            "execution_targets":["account"],
            "fields":[field], "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }]});
        assert!(
            generated_verb_tools(&frame).is_empty(),
            "an untyped field origin must suppress the generated tool"
        );
    }
}

/// The `language` tool is RETIRED — internal files are internal. It is
/// gone from the schema AND from the dispatch, so a client that still calls it gets the ordinary
/// unknown-tool error rather than a served copy of an internal document.
#[test]
fn language_tool_is_gone_from_the_schema_and_the_dispatch() {
    let surface = serde_json::to_string(&static_tools()).expect("tools serialize");
    assert!(
        !surface.contains("language"),
        "the retired language tool is still on the agent surface: {surface}"
    );
    let t = FakeTransport(|cmd: &AgentCommand| {
        panic!("a retired tool must never reach the transport, got {cmd:?}")
    });
    let resp = handle_message(&t, &tools_call("language", Value::Null)).unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(is_error);
    assert!(first_text(content).contains("unknown tool"));
}

#[test]
fn request_status_tool_reports_state_read_only() {
    let t = FakeTransport(|cmd: &AgentCommand| {
        assert!(
            matches!(cmd, AgentCommand::Status { .. }),
            "request_status must issue the read-only Status command, got {cmd:?}"
        );
        Ok(json!({ "kind": "status", "request_id": "rq-1", "status": "ready" }))
    });
    let resp = handle_message(
        &t,
        &tools_call("request_status", json!({ "request_id": "rq-1" })),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    let text = first_text(content);
    assert!(text.contains("ready"), "got: {text}");
    assert!(text.contains("execute"), "guides to execute: {text}");
}

#[test]
fn request_status_missing_id_is_a_tool_error() {
    let t = fixed(Value::Null);
    let resp = handle_message(&t, &tools_call("request_status", json!({}))).unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(is_error);
    assert!(first_text(content).contains("request_id"));
}

#[test]
fn list_and_verify_render() {
    let list = fixed(json!({ "kind": "credentials", "credentials": [] }));
    let resp = handle_message(&list, &tools_call("list_connected_providers", Value::Null)).unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    assert!(first_text(content).contains("no providers connected"));

    let verify_ok = fixed(json!({ "kind": "audit_verified", "ok": true }));
    let resp = handle_message(&verify_ok, &tools_call("verify_audit", Value::Null)).unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    assert!(first_text(content).contains("verified"));

    let verify_bad = fixed(json!({ "kind": "audit_verified", "ok": false }));
    let resp = handle_message(&verify_bad, &tools_call("verify_audit", Value::Null)).unwrap();
    let (_c, is_error) = call_result(&resp);
    assert!(is_error, "a failed audit chain is a tool error");
}

#[test]
fn a_transport_error_becomes_a_tool_error() {
    let t = FakeTransport(|_: &AgentCommand| Err(AgentError::Connect("no socket".into())));
    let resp = handle_message(&t, &tools_call("verify_audit", Value::Null)).unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(is_error);
    assert!(
        first_text(content).contains("agent.sock"),
        "surfaces the connect error"
    );
}

#[test]
fn artifact_tool_retrieves_a_span_with_a_range() {
    let t = FakeTransport(|cmd: &AgentCommand| {
        match cmd {
            AgentCommand::Artifact {
                handle,
                range,
                path,
            } => {
                assert_eq!(handle, "art_1");
                assert!(path.is_none(), "range form leaves path unset");
                let r = range.as_ref().expect("range threaded through");
                assert_eq!(r.unit, "lines");
                assert_eq!((r.start, r.end), (2, Some(4)));
            }
            other => panic!("artifact must issue the Artifact command, got {other:?}"),
        }
        Ok(json!({
            "kind": "artifact", "handle": "art_1", "digest": "d1",
            "stored_size": 5, "size": 5, "truncated": false,
            "unit": "lines", "start": 2, "end": 4, "content": "b\nc\nd"
        }))
    });
    let resp = handle_message(
        &t,
        &tools_call(
            "artifact",
            json!({ "handle": "art_1", "range": { "unit": "lines", "start": 2, "end": 4 } }),
        ),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    assert!(
        first_text(content).contains("b\nc\nd"),
        "got: {}",
        first_text(content)
    );
}

#[test]
fn artifact_tool_retrieves_a_field_by_path() {
    let t = FakeTransport(|cmd: &AgentCommand| {
        match cmd {
            AgentCommand::Artifact {
                handle,
                range,
                path,
            } => {
                assert_eq!(handle, "art_1");
                assert!(range.is_none(), "path form leaves range unset");
                assert_eq!(path.as_deref(), Some("$.deployment.url"));
            }
            other => panic!("artifact must issue the Artifact command, got {other:?}"),
        }
        Ok(json!({
            "kind": "artifact", "handle": "art_1", "digest": "d1",
            "stored_size": 40, "size": 40, "truncated": false,
            "unit": "path", "start": 0, "end": 0, "path": "$.deployment.url",
            "content": "\"https://x.app\""
        }))
    });
    let resp = handle_message(
        &t,
        &tools_call(
            "artifact",
            json!({ "handle": "art_1", "path": "$.deployment.url" }),
        ),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    assert!(
        first_text(content).contains("https://x.app"),
        "got: {}",
        first_text(content)
    );
}

#[test]
fn artifact_tool_rejects_bad_path_and_range_plus_path() {
    let t = fixed(Value::Null);
    // A pointer without the `$.` prefix is a tool error, never sent.
    let bad = handle_message(
        &t,
        &tools_call("artifact", json!({ "handle": "a", "path": "deployment" })),
    )
    .unwrap();
    assert!(call_result(&bad).1, "bad path is a tool error");
    // range + path together is a tool error.
    let both = handle_message(
        &t,
        &tools_call(
            "artifact",
            json!({
                "handle": "a", "path": "$.a", "range": { "unit": "bytes", "start": 0 }
            }),
        ),
    )
    .unwrap();
    assert!(call_result(&both).1, "range + path is a tool error");
}

#[test]
fn artifact_tool_missing_handle_is_a_tool_error() {
    let t = fixed(Value::Null);
    let resp = handle_message(&t, &tools_call("artifact", json!({}))).unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(is_error);
    assert!(first_text(content).contains("handle"));
}

#[test]
fn unknown_tool_is_a_tool_error_not_a_crash() {
    let t = fixed(Value::Null);
    let resp = handle_message(&t, &tools_call("approve_capability", json!({}))).unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(is_error);
    assert!(first_text(content).contains("unknown tool"));
}

#[test]
fn unknown_method_is_a_jsonrpc_error() {
    let t = fixed(Value::Null);
    let msg = json!({ "jsonrpc": "2.0", "id": 5, "method": "resources/list" });
    let resp = handle_message(&t, &msg).unwrap();
    assert_eq!(resp["id"], json!(5));
    assert_eq!(resp["error"]["code"], json!(-32601));
    assert!(resp.get("result").is_none());
}

/// A `Write` sink that appends into a shared buffer a test still holds a handle to after `serve`
/// consumes it — and, being `Arc`-shared, lets a test inspect the output WHILE `serve` runs on
/// another thread. Cloneable so `SharedWriter` can hand copies to workers.
#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);
impl SharedBuf {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
    /// The parsed JSON-RPC response lines emitted so far (skips any partial trailing line).
    fn lines(&self) -> Vec<Value> {
        self.text()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}
impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn serve_replies_to_requests_skips_notifications_and_ends_at_eof() {
    let t = fixed(Value::Null);
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
    );
    let out = SharedBuf::new();
    serve(t, Cursor::new(input), out.clone()).expect("serve ok at eof");
    let text = out.text();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "only the two requests get replies: {text}");
    let r0: Value = serde_json::from_str(lines[0]).unwrap();
    let r1: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(r0["id"], json!(1));
    assert!(r0["result"]["protocolVersion"].is_string());
    assert_eq!(r1["id"], json!(2));
    assert!(r1["result"]["tools"].is_array());
}

#[test]
fn serve_reports_a_parse_error_for_a_non_json_line_without_aborting() {
    let t = fixed(Value::Null);
    let input = concat!(
        "this is not json\n",
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"initialize\",\"params\":{}}\n",
    );
    let out = SharedBuf::new();
    serve(t, Cursor::new(input), out.clone()).expect("serve survives a bad line");
    let lines = out.lines();
    assert_eq!(lines[0]["id"], Value::Null);
    assert_eq!(lines[0]["error"]["code"], json!(-32700));
    assert_eq!(
        lines[1]["id"],
        json!(7),
        "the stream keeps going after a bad line"
    );
}

// ---- concurrent tools/call dispatch -------------------------------------------------------

/// A Send+Sync transport whose `execute_capability` (the `Execute` command) BLOCKS on a shared
/// gate until the test releases it, while `catalog` (and anything else) returns immediately. Lets a
/// test prove a slow execute does not serialize a concurrent catalog call. The `Execute` reply
/// echoes the request_id into the result url so a test can correlate which id it belongs to.
struct GateTransport {
    release: Arc<(Mutex<bool>, Condvar)>,
}
impl AgentTransport for GateTransport {
    fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
        match cmd {
            AgentCommand::Execute { request_id, .. } => {
                let (lock, cvar) = &*self.release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = cvar.wait(released).unwrap();
                }
                Ok(json!({
                    "kind": "executed", "ok": true, "provider": "v", "action": "a",
                    "result": { "url": format!("ran-{request_id}") }
                }))
            }
            _ => Ok(json!({ "kind": "catalog", "catalog": [] })),
        }
    }
}

fn release_gate(gate: &Arc<(Mutex<bool>, Condvar)>) {
    let (lock, cvar) = &**gate;
    *lock.lock().unwrap() = true;
    cvar.notify_all();
}

/// Millisecond shorthand for the shutdown lifecycle budget (drain / kill grace / kill join).
fn test_timings(drain_ms: u64, grace_ms: u64, join_ms: u64) -> ShutdownTimings {
    ShutdownTimings {
        drain: Duration::from_millis(drain_ms),
        kill_grace: Duration::from_millis(grace_ms),
        kill_join: Duration::from_millis(join_ms),
    }
}

fn tools_call_line(id: u64, name: &str, args: Value) -> String {
    let msg = json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": { "name": name, "arguments": args }
    });
    format!("{}\n", serde_json::to_string(&msg).unwrap())
}

/// Poll `out` up to `budget` for a response line carrying `id`. Returns true if it appeared.
fn wait_for_id(out: &SharedBuf, id: u64, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if out.lines().iter().any(|l| l["id"] == json!(id)) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn slow_execute_does_not_block_a_concurrent_catalog_call() {
    // id 1 is a gated (blocking) execute; id 2 is a fast catalog. The catalog must complete while
    // the execute is still blocked — proof the two ran concurrently rather than serializing.
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let t = GateTransport {
        release: Arc::clone(&release),
    };
    let mut input = String::new();
    // A GENEROUS explicit wait_ms keeps the tool-call worker inline-blocked on the gated
    // background run for the whole test (never returning a background handle early),
    // preserving the concurrency semantics this test pins.
    input.push_str(&tools_call_line(
        1,
        "execute_capability",
        json!({ "request_id": "rq-1", "wait_ms": 30_000 }),
    ));
    input.push_str(&tools_call_line(2, "catalog", json!({})));
    let out = SharedBuf::new();

    // serve blocks in the EOF drain until we release the gated execute, so run it off-thread.
    let out_srv = out.clone();
    let srv = std::thread::spawn(move || {
        serve(t, Cursor::new(input), out_srv).expect("serve ok");
    });

    // Generous margin (up to 5s) — not a flaky sub-100ms assert.
    assert!(
        wait_for_id(&out, 2, Duration::from_secs(5)),
        "the catalog (id 2) did not complete while the execute was blocked — they serialized"
    );
    assert!(
        !out.lines().iter().any(|l| l["id"] == json!(1)),
        "the gated execute (id 1) must still be pending, not completed"
    );

    release_gate(&release);
    srv.join().unwrap();
    let ids: Vec<Value> = out.lines().iter().map(|l| l["id"].clone()).collect();
    assert!(
        ids.contains(&json!(1)) && ids.contains(&json!(2)),
        "both responses land: {ids:?}"
    );
}

#[test]
fn response_ids_correlate_under_out_of_order_completion() {
    // id 1 (execute) finishes AFTER id 2 (catalog). Each response's payload must map back to its
    // OWN id — the JSON-RPC id is the correlation, not arrival order.
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let t = GateTransport {
        release: Arc::clone(&release),
    };
    let mut input = String::new();
    // A generous explicit wait_ms — id 1 stays inline-blocked until the release,
    // so its response carries the RECEIPT (not a background handle) after id 2 already landed.
    input.push_str(&tools_call_line(
        1,
        "execute_capability",
        json!({ "request_id": "rq-1", "wait_ms": 30_000 }),
    ));
    input.push_str(&tools_call_line(2, "catalog", json!({})));
    let out = SharedBuf::new();

    let out_srv = out.clone();
    let srv = std::thread::spawn(move || {
        serve(t, Cursor::new(input), out_srv).expect("serve ok");
    });
    assert!(
        wait_for_id(&out, 2, Duration::from_secs(5)),
        "catalog completes first"
    );
    release_gate(&release);
    srv.join().unwrap();

    let lines = out.lines();
    let by_id = |id: u64| {
        lines
            .iter()
            .find(|l| l["id"] == json!(id))
            .map(|l| {
                l["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap_or("")
                    .to_string()
            })
            .unwrap_or_default()
    };
    // id 1 is the execute (its receipt carries the request-id-derived url); id 2 is the catalog.
    assert!(
        by_id(1).contains("ran-rq-1"),
        "id 1 must carry the execute result: {:?}",
        by_id(1)
    );
    assert!(
        !by_id(2).contains("ran-rq-1"),
        "id 2 must NOT carry the execute result: {:?}",
        by_id(2)
    );
}

#[test]
fn concurrent_writes_never_interleave_partial_lines() {
    // Hammer the one shared writer with many fast concurrent tools/call completions; EVERY emitted
    // line must parse as complete JSON and every id must appear exactly once (no torn lines).
    let n: u64 = 200;
    let t = fixed(json!({ "kind": "catalog", "catalog": [] }));
    let mut input = String::new();
    for i in 0..n {
        input.push_str(&tools_call_line(i, "catalog", json!({})));
    }
    let out = SharedBuf::new();
    serve(t, Cursor::new(input), out.clone()).expect("serve ok");

    let text = out.text();
    let raw: Vec<&str> = text.lines().collect();
    assert_eq!(
        raw.len() as u64,
        n,
        "one whole line per request, none torn or merged"
    );
    let mut ids = std::collections::HashSet::new();
    for l in &raw {
        let v: Value = serde_json::from_str(l).expect("every emitted line parses as complete JSON");
        ids.insert(v["id"].as_u64().expect("each line has an integer id"));
    }
    assert_eq!(ids.len() as u64, n, "every id appears exactly once");
}

/// A Send+Sync `WireOps` fake for the shared-cache race: `hello` counts mints; the FIRST minted
/// session (`sess_1`) is always refused as expired, any re-minted session works.
struct RacyWire {
    hellos: AtomicU32,
}
impl WireOps for RacyWire {
    fn hello(&self) -> Result<SessionHello, AgentError> {
        let n = self.hellos.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(hello_of(format!("sess_{n}"), vec![]))
    }
    fn call_with_session(&self, _cmd: &AgentCommand, session: &str) -> Result<Value, AgentError> {
        if session == "sess_1" {
            Err(AgentError::Server(SESSION_EXPIRED.to_string()))
        } else {
            Ok(json!({ "kind": "catalog", "session": session }))
        }
    }
}

#[test]
fn session_expiry_race_remints_exactly_once() {
    // N workers share ONE cache. All mint/observe sess_1, all get SESSION_EXPIRED at once. The
    // re-mint must fire EXACTLY once (total hellos == 2: the initial mint + one shared re-mint),
    // NOT once per worker.
    let wire = Arc::new(RacyWire {
        hellos: AtomicU32::new(0),
    });
    let cache = Arc::new(SessionCache::new());
    let mut handles = Vec::new();
    for _ in 0..16 {
        let w = Arc::clone(&wire);
        let c = Arc::clone(&cache);
        handles.push(std::thread::spawn(move || {
            c.call(&*w, &AgentCommand::Catalog)
                .expect("each worker recovers")
        }));
    }
    for h in handles {
        let r = h.join().unwrap();
        assert_eq!(
            r["session"], "sess_2",
            "every worker ends on the ONE re-minted session"
        );
    }
    assert_eq!(
            wire.hellos.load(Ordering::SeqCst),
            2,
            "exactly one initial mint + one re-mint across all racing workers, not one Hello per worker"
        );
}

/// A transport that panics inside `call` — to prove a worker panic still yields a JSON-RPC error
/// for that id rather than a silent drop (which would hang the client until timeout).
struct PanicTransport;
impl AgentTransport for PanicTransport {
    fn call(&self, _cmd: &AgentCommand) -> Result<Value, AgentError> {
        panic!("boom inside a worker");
    }
}

#[test]
fn worker_panic_produces_an_error_response_for_that_id() {
    // The default panic hook prints the expected "boom inside a worker" line to stderr — that is
    // noise, not a failure; the worker's catch_unwind still emits the error response.
    let t = PanicTransport;
    let input = tools_call_line(42, "catalog", json!({}));
    let out = SharedBuf::new();
    serve(t, Cursor::new(input), out.clone()).expect("serve returns despite a worker panic");

    let lines = out.lines();
    assert_eq!(
        lines.len(),
        1,
        "the panicking worker still emits exactly one response"
    );
    assert_eq!(lines[0]["id"], json!(42));
    assert_eq!(
        lines[0]["error"]["code"],
        json!(-32603),
        "a worker panic becomes a JSON-RPC internal error, never a silent drop"
    );
}

#[test]
fn eof_drains_in_flight_workers_without_losing_responses() {
    // A slow (but self-completing) execute plus fast catalogs; EOF must WAIT for the slow worker so
    // its response is not lost — all four land.
    struct SleepTransport;
    impl AgentTransport for SleepTransport {
        fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
            if let AgentCommand::Execute { .. } = cmd {
                std::thread::sleep(Duration::from_millis(300));
                Ok(json!({
                    "kind": "executed", "ok": true, "provider": "v", "action": "a",
                    "result": { "url": "slow-done" }
                }))
            } else {
                Ok(json!({ "kind": "catalog", "catalog": [] }))
            }
        }
    }
    let mut input = String::new();
    // The DEFAULT bounded wait keeps the tool-call worker blocked on this run until it settles
    // (300ms < the ~2s wait), so its receipt lands INLINE and is drained — the
    // synchronous-execute semantics this test pins are preserved by the default wait.
    input.push_str(&tools_call_line(
        1,
        "execute_capability",
        json!({ "request_id": "rq-1" }),
    ));
    for i in 2..=4 {
        input.push_str(&tools_call_line(i, "catalog", json!({})));
    }
    let out = SharedBuf::new();
    serve(SleepTransport, Cursor::new(input), out.clone()).expect("serve ok");

    let lines = out.lines();
    assert_eq!(
        lines.len(),
        4,
        "the slow in-flight worker's response is drained, not dropped"
    );
    let slow = lines
        .iter()
        .find(|l| l["id"] == json!(1))
        .expect("the slow execute (id 1) response landed");
    assert!(
        slow["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("slow-done"),
        "the drained slow response carries its own result"
    );
}

#[test]
fn drain_deadline_suppresses_a_straggler_write() {
    // A worker blocked PAST a (short) drain deadline must not write after the server has returned —
    // the shared sink is deactivated on shutdown so a late write to a torn-down pipe never happens.
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let t = GateTransport {
        release: Arc::clone(&release),
    };
    let mut input = String::new();
    // The default bounded wait keeps this tool-call worker BLOCKED on the gated background run —
    // the straggler this test needs (its handle write is then suppressed by the sink
    // deactivation, exactly like a synchronous worker's late receipt write).
    input.push_str(&tools_call_line(
        1,
        "execute_capability",
        json!({ "request_id": "rq-1" }),
    ));
    input.push_str(&tools_call_line(2, "catalog", json!({})));
    let out = SharedBuf::new();

    // Short bounded drain: the gated execute (id 1) outlasts every phase.
    serve_inner(
        t,
        Cursor::new(input),
        out.clone(),
        test_timings(50, 50, 500),
    )
    .expect("serve returns after the bounded drain");

    let before = out.lines();
    assert!(
        before.iter().any(|l| l["id"] == json!(2)),
        "the fast catalog (id 2) completed"
    );
    assert!(
        !before.iter().any(|l| l["id"] == json!(1)),
        "the still-blocked worker was not awaited past the drain deadline"
    );

    // Release the straggler AFTER shutdown: its write must be suppressed (sink deactivated).
    release_gate(&release);
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        !out.lines().iter().any(|l| l["id"] == json!(1)),
        "a straggler must not write after the server has shut down"
    );
}

// ---- the read thread never waits on pool capacity -----------------------------------------

#[test]
fn saturated_pool_answers_busy_and_keeps_inline_traffic_flowing() {
    // Fill the pool with WORKER_CAP gated executes (a realistic fleet state: 16 pending
    // approvals). The 17th tools/call must get a prompt explicit busy ERROR (never parked on
    // capacity), a subsequent ping must still be answered inline, and EOF must reach the drain
    // (bounded exit) — all while the 16 stay blocked.
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let t = GateTransport {
        release: Arc::clone(&release),
    };
    let mut input = String::new();
    // The default bounded wait keeps each tool-call worker BLOCKED on its gated background run,
    // so WORKER_CAP executes hold WORKER_CAP tool-call slots — the saturated main
    // pool this test pins. (The gated background runs also fill the supervisor's run pool.)
    for i in 0..WORKER_CAP as u64 {
        input.push_str(&tools_call_line(
            i,
            "execute_capability",
            json!({ "request_id": format!("rq-{i}") }),
        ));
    }
    let overflow_id = WORKER_CAP as u64;
    input.push_str(&tools_call_line(overflow_id, "catalog", json!({})));
    input.push_str(
        "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"ping\"}\n", // inline liveness after overflow
    );
    let out = SharedBuf::new();

    let out_srv = out.clone();
    let srv = std::thread::spawn(move || {
        // Short bounded lifecycle: the 16 gated waits (stuck in the RPC) are left detached
        // after the bounded join — the exit stays bounded.
        serve_inner(t, Cursor::new(input), out_srv, test_timings(100, 50, 500))
            .expect("serve exits bounded despite a saturated pool");
    });

    assert!(
        wait_for_id(&out, overflow_id, Duration::from_secs(5)),
        "the overflow call must be answered promptly, not parked on pool capacity"
    );
    let lines = out.lines();
    let busy = lines
        .iter()
        .find(|l| l["id"] == json!(overflow_id))
        .unwrap();
    assert!(
        busy.get("error").is_some(),
        "the overflow call gets an explicit busy ERROR, not a queued success: {busy}"
    );
    assert!(
        busy["error"]["message"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("busy"),
        "the error names the condition: {busy}"
    );
    assert!(
        wait_for_id(&out, 99, Duration::from_secs(5)),
        "ping must still be answered inline while the pool is saturated"
    );

    // EOF then the bounded drain: serve must return even though 16 workers are still gated.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !srv.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        srv.is_finished(),
        "EOF + bounded drain must exit while pre-exec waits are blocked"
    );
    release_gate(&release);
    srv.join().unwrap();
}

// ---- the first write error is terminal -------------------------------------------------------

/// A writer that commits a short PREFIX of the first line into the buffer, then errors — the
/// torn-frame case. Every later write must be refused (the sink is failed, not still active).
#[derive(Clone)]
struct PrefixFailWriter {
    buf: Arc<Mutex<Vec<u8>>>,
    failed: Arc<(Mutex<bool>, Condvar)>,
}
impl Write for PrefixFailWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut b = self.buf.lock().unwrap();
        if b.is_empty() && !buf.is_empty() {
            b.extend_from_slice(&buf[..buf.len().min(3)]);
            let (lock, cvar) = &*self.failed;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
            return Err(io::Error::other("client pipe torn mid-line"));
        }
        b.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A reader that yields its first segment, then blocks until signalled, then yields the second
/// segment and EOF — so a test can order "the write failed" strictly before "the next request
/// line is read".
struct GatedReader {
    second: Option<Vec<u8>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
    first: Cursor<Vec<u8>>,
    first_done: bool,
}
impl io::Read for GatedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.first_done {
            let n = self.first.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            self.first_done = true;
        }
        match self.second.take() {
            Some(bytes) => {
                let (lock, cvar) = &*self.gate;
                let mut open = lock.lock().unwrap();
                while !*open {
                    open = cvar.wait(open).unwrap();
                }
                drop(open);
                // The gate is signalled INSIDE the failing write, a hair before the writer
                // task flips the shared state to Failed; give that flip an enormous margin so
                // line 2 verifiably arrives at an already-failed sink.
                std::thread::sleep(Duration::from_millis(100));
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                // The test's lines are short; a partial copy would drop bytes, so insist.
                assert_eq!(n, bytes.len(), "test lines must fit the read buffer");
                Ok(n)
            }
            None => Ok(0),
        }
    }
}

/// A Send+Sync transport closure fake (the `RefCell` one is single-thread only).
struct FakeTransportSync<F: Fn(&AgentCommand) -> Result<Value, AgentError> + Send + Sync>(F);
impl<F: Fn(&AgentCommand) -> Result<Value, AgentError> + Send + Sync> AgentTransport
    for FakeTransportSync<F>
{
    fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
        (self.0)(cmd)
    }
}

#[test]
fn first_write_error_is_terminal_no_later_frames_or_executions() {
    // Line 1's response write commits a 3-byte prefix then errors. The sink must become
    // terminally failed: line 2 (released only AFTER the failure) must NOT be dispatched — no
    // further execution into a dead response channel — and no later frame may concatenate onto
    // the orphaned prefix.
    let calls = Arc::new(AtomicU32::new(0));
    let calls_t = Arc::clone(&calls);
    let t = FakeTransportSync(move |_cmd: &AgentCommand| {
        calls_t.fetch_add(1, Ordering::SeqCst);
        Ok(json!({ "kind": "catalog", "catalog": [] }))
    });

    let failed = Arc::new((Mutex::new(false), Condvar::new()));
    let writer = PrefixFailWriter {
        buf: Arc::new(Mutex::new(Vec::new())),
        failed: Arc::clone(&failed),
    };
    let reader = GatedReader {
        first: Cursor::new(tools_call_line(1, "catalog", json!({})).into_bytes()),
        second: Some(tools_call_line(2, "catalog", json!({})).into_bytes()),
        gate: Arc::clone(&failed),
        first_done: false,
    };
    let buf = Arc::clone(&writer.buf);
    serve_inner(
        t,
        io::BufReader::new(reader),
        writer,
        test_timings(5_000, 500, 500),
    )
    .expect("a dead client pipe is a graceful wind-down");

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "after the first terminal write error, NO further tool call may execute"
    );
    let written = buf.lock().unwrap().clone();
    assert_eq!(
        written.len(),
        3,
        "nothing may be written after the torn prefix — the sink is failed, not active: {:?}",
        String::from_utf8_lossy(&written)
    );
}

// ---- single-flight session refresh outside the lock ---------------------------------------

/// A wire whose `hello` blocks on a gate and then returns the scripted outcome, counting
/// attempts — the probe for single-flight refresh (one network call per outage, broadcast to
/// every concurrent waiter, never one serial timeout per waiter).
struct BarrierWire {
    attempts: AtomicU32,
    gate: Arc<(Mutex<bool>, Condvar)>,
    fail: bool,
    panic_once: AtomicU32,
}
impl WireOps for BarrierWire {
    fn hello(&self) -> Result<SessionHello, AgentError> {
        let n = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
        if self.panic_once.load(Ordering::SeqCst) > 0 {
            self.panic_once.fetch_sub(1, Ordering::SeqCst);
            panic!("hello panicked once");
        }
        let (lock, cvar) = &*self.gate;
        let mut open = lock.lock().unwrap();
        while !*open {
            open = cvar.wait(open).unwrap();
        }
        if self.fail {
            Err(AgentError::Connect("daemon down".into()))
        } else {
            Ok(hello_of(format!("sess_{n}"), vec![]))
        }
    }
    fn call_with_session(&self, _cmd: &AgentCommand, session: &str) -> Result<Value, AgentError> {
        Ok(json!({ "kind": "catalog", "session": session }))
    }
}

#[test]
fn slow_refresh_is_single_flight_for_concurrent_waiters() {
    // One slow hello in flight; every concurrent caller waits for ITS result — exactly one
    // network attempt, all callers end on the same minted session.
    let wire = Arc::new(BarrierWire {
        attempts: AtomicU32::new(0),
        gate: Arc::new((Mutex::new(false), Condvar::new())),
        fail: false,
        panic_once: AtomicU32::new(0),
    });
    let cache = Arc::new(SessionCache::new());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let w = Arc::clone(&wire);
        let c = Arc::clone(&cache);
        handles.push(std::thread::spawn(move || {
            c.call(&*w, &AgentCommand::Catalog)
        }));
    }
    // Let the callers converge on the in-flight refresh, then let it complete.
    std::thread::sleep(Duration::from_millis(200));
    release_gate(&wire.gate);
    for h in handles {
        let r = h
            .join()
            .unwrap()
            .expect("every caller shares the one refresh");
        assert_eq!(
            r["session"], "sess_1",
            "all callers ride the single minted session"
        );
    }
    assert_eq!(
        wire.attempts.load(Ordering::SeqCst),
        1,
        "exactly ONE hello for the whole burst"
    );
}

#[test]
fn failed_refresh_is_broadcast_not_retried_per_waiter() {
    // The one in-flight refresh fails; every waiter must receive that failure — never N serial
    // hello timeouts (the minutes-long outage the mutex-across-network bug caused).
    let wire = Arc::new(BarrierWire {
        attempts: AtomicU32::new(0),
        gate: Arc::new((Mutex::new(false), Condvar::new())),
        fail: true,
        panic_once: AtomicU32::new(0),
    });
    let cache = Arc::new(SessionCache::new());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let w = Arc::clone(&wire);
        let c = Arc::clone(&cache);
        handles.push(std::thread::spawn(move || {
            c.call(&*w, &AgentCommand::Catalog)
        }));
    }
    std::thread::sleep(Duration::from_millis(200));
    release_gate(&wire.gate);
    for h in handles {
        assert!(
            h.join().unwrap().is_err(),
            "every waiter sees the broadcast failure"
        );
    }
    assert_eq!(
        wire.attempts.load(Ordering::SeqCst),
        1,
        "ONE failed attempt is broadcast to all waiters — not one serial retry per waiter"
    );

    // The failure is not permanent: the NEXT call attempts a fresh refresh and succeeds.
    let ok_wire = BarrierWire {
        attempts: AtomicU32::new(0),
        gate: Arc::new((Mutex::new(true), Condvar::new())),
        fail: false,
        panic_once: AtomicU32::new(0),
    };
    let r = cache
        .call(&ok_wire, &AgentCommand::Catalog)
        .expect("a later call recovers");
    assert_eq!(r["session"], "sess_1");
}

#[test]
fn refresh_panic_does_not_poison_the_cache() {
    // The first hello PANICS. That call fails, but the cache must recover — the next call
    // refreshes normally instead of every later session-needing call being a poisoned -32603
    // until process restart.
    let wire = Arc::new(BarrierWire {
        attempts: AtomicU32::new(0),
        gate: Arc::new((Mutex::new(true), Condvar::new())),
        fail: false,
        panic_once: AtomicU32::new(1),
    });
    let cache = Arc::new(SessionCache::new());

    let w = Arc::clone(&wire);
    let c = Arc::clone(&cache);
    let panicked = std::thread::spawn(move || {
        let _ = c.call(&*w, &AgentCommand::Catalog);
    })
    .join();
    assert!(
        panicked.is_err(),
        "the panicking refresh propagates to ITS caller"
    );

    let r = cache
        .call(&*wire, &AgentCommand::Catalog)
        .expect("the cache recovers after a panicked refresh — never a permanent outage");
    assert_eq!(r["session"], "sess_2", "the retry minted a fresh session");
}

// ---- deactivation and admission are one state machine --------------------------------------

/// A writer whose first write BLOCKS mid-line until released, recording bytes — so a test can
/// hold a whole-line write in flight while deactivation is requested.
#[derive(Clone)]
struct BlockingWriter {
    buf: Arc<Mutex<Vec<u8>>>,
    entered: Arc<(Mutex<bool>, Condvar)>,
    release: Arc<(Mutex<bool>, Condvar)>,
    blocked_once: Arc<AtomicU32>,
}
impl Write for BlockingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.blocked_once.fetch_add(1, Ordering::SeqCst) == 0 {
            {
                let (lock, cvar) = &*self.entered;
                *lock.lock().unwrap() = true;
                cvar.notify_all();
            }
            let (lock, cvar) = &*self.release;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = cvar.wait(open).unwrap();
            }
        }
        self.buf.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn deactivation_is_atomic_with_admission_and_never_tears_a_line() {
    // A line's write is in flight (the writer task is blocked mid-write). Deactivation
    // requested NOW must (a) return promptly — never wait on blocked I/O — while
    // (b) admitting nothing after it, and (c) the in-flight line still lands WHOLE once the
    // sink unblocks (never torn, since only the single writer task touches the sink).
    let writer = BlockingWriter {
        buf: Arc::new(Mutex::new(Vec::new())),
        entered: Arc::new((Mutex::new(false), Condvar::new())),
        release: Arc::new((Mutex::new(false), Condvar::new())),
        blocked_once: Arc::new(AtomicU32::new(0)),
    };
    let buf = Arc::clone(&writer.buf);
    let entered = Arc::clone(&writer.entered);
    let release = Arc::clone(&writer.release);

    let (shared, task) = SharedWriter::new(writer);
    let line1 = json!({ "jsonrpc": "2.0", "id": 1, "result": { "ok": true } });
    shared.write_response(&line1).expect("line 1 admitted");
    // Wait until the writer task is verifiably blocked mid-write of line 1.
    {
        let (lock, cvar) = &*entered;
        let mut e = lock.lock().unwrap();
        while !*e {
            e = cvar.wait(e).unwrap();
        }
    }

    // Deactivate WHILE the write is blocked: it must return promptly (no waiting on I/O) and
    // close admission atomically — the next write is dropped, not queued.
    shared.deactivate();
    let _ = shared.write_response(&json!({ "jsonrpc": "2.0", "id": 2, "result": {} }));

    // Unblock the sink: the in-flight line completes WHOLE; nothing admitted after
    // deactivation ever lands.
    release_gate(&release);
    task.finish(Duration::from_secs(5));
    let written = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = written.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "exactly the one in-flight line landed: {written:?}"
    );
    assert!(
        serde_json::from_str::<Value>(lines[0]).is_ok(),
        "the in-flight line landed WHOLE, never torn: {written:?}"
    );
    assert!(
        !written.contains("\"id\":2"),
        "a post-deactivation write must be dropped"
    );
}

// ---- the gate decision lands BEFORE any RPC that can claim/execute -------------------------

#[test]
fn refused_gate_makes_no_claiming_rpc() {
    // For an HTTP verb the daemon claims the grant and performs the provider action DURING the
    // Execute RPC. A gate that refuses must therefore refuse BEFORE the RPC: zero daemon calls —
    // provably unstarted — never "call the daemon, then report the executed work as unstarted".
    let calls = Arc::new(AtomicU32::new(0));
    let calls_t = Arc::clone(&calls);
    let t = FakeTransportSync(move |_cmd: &AgentCommand| {
        calls_t.fetch_add(1, Ordering::SeqCst);
        Ok(json!({
            "kind": "executed", "ok": true, "provider": "v", "action": "a", "result": null
        }))
    });
    let res = t.execute_capability("rq-1", &|| false);
    assert!(res.is_err(), "a refused gate is a refusal");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the refusal must land BEFORE the RPC — the daemon call would claim + execute"
    );
}

#[test]
fn in_flight_execute_reports_its_true_outcome_not_unstarted() {
    // Green lock: the gate passes when the RPC is issued, then shutdown lands mid-RPC. The
    // daemon executed the HTTP verb DURING that call — the reply is the truth and must come
    // back as such, never converted into a "was not executed" error.
    let t = FakeTransportSync(|_cmd: &AgentCommand| {
        Ok(json!({
            "kind": "executed", "ok": true, "provider": "v", "action": "a",
            "result": { "url": "really-ran" }
        }))
    });
    let consults = AtomicU32::new(0);
    let gate = move || consults.fetch_add(1, Ordering::SeqCst) == 0;
    let res = t
        .execute_capability("rq-1", &gate)
        .expect("the true executed outcome is returned, never misreported as unstarted");
    assert_eq!(res["result"]["url"], "really-ran");
}

// ---- sink failure winds the server down without another stdin line -------------------------

/// A reader that yields its first segment then blocks FOREVER — an open-but-quiet stdin.
struct QuietForeverReader {
    first: Cursor<Vec<u8>>,
    first_done: bool,
}
impl io::Read for QuietForeverReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.first_done {
            let n = self.first.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            self.first_done = true;
        }
        // Block forever: stdin stays open, no more bytes ever arrive.
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
}

#[test]
fn sink_failure_winds_down_without_another_stdin_line() {
    // The one tool call's response write fails terminally. stdin stays OPEN with no further
    // bytes — the server must still wind down promptly (bounded), not sit blocked on a read
    // that will never complete.
    let t =
        FakeTransportSync(|_cmd: &AgentCommand| Ok(json!({ "kind": "catalog", "catalog": [] })));
    let writer = PrefixFailWriter {
        buf: Arc::new(Mutex::new(Vec::new())),
        failed: Arc::new((Mutex::new(false), Condvar::new())),
    };
    let reader = QuietForeverReader {
        first: Cursor::new(tools_call_line(1, "catalog", json!({})).into_bytes()),
        first_done: false,
    };
    let srv = std::thread::spawn(move || {
        serve_inner(
            t,
            io::BufReader::new(reader),
            writer,
            test_timings(5_000, 500, 500),
        )
        .expect("a dead sink is a graceful wind-down");
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !srv.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        srv.is_finished(),
        "a terminal sink failure must trigger wind-down without waiting for more stdin"
    );
    srv.join().unwrap();
}

// ---- a stalled stdout never blocks shutdown ------------------------------------------------

/// A writer whose every write blocks FOREVER — an open-but-unread stdout (client stalled).
struct StalledForeverWriter;
impl Write for StalledForeverWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn stalled_stdout_does_not_block_shutdown() {
    // One tool call's response write stalls forever (stdout open but never read). EOF then
    // arrives. Shutdown must stay bounded: deactivation never waits on blocked I/O, so serve
    // returns — the stalled sink is detached, not waited on.
    let t =
        FakeTransportSync(|_cmd: &AgentCommand| Ok(json!({ "kind": "catalog", "catalog": [] })));
    let input = tools_call_line(1, "catalog", json!({}));
    let srv = std::thread::spawn(move || {
        serve_inner(
            t,
            Cursor::new(input),
            StalledForeverWriter,
            test_timings(200, 100, 200),
        )
        .expect("a stalled sink is a bounded wind-down");
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !srv.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        srv.is_finished(),
        "a permanently stalled stdout must never make shutdown unwakeable — writes are \
             bounded and deactivation never waits on blocked I/O"
    );
    srv.join().unwrap();
}

// ---- EOF, backlog, and hangup shutdown invariants -----------------------------------------------

#[test]
fn eof_behind_a_backlog_starts_the_bounded_drain_not_the_whole_queue() {
    // A client queues a large backlog, closes stdin, and the sink is slow-but-progressing: the
    // shutdown budget must anchor at REAL EOF — dispatch stops admitting when the post-EOF
    // window closes (the unadmitted backlog is dropped; the client already left) and serve
    // returns within the composed bounds, instead of grinding the whole queue at sink pace.
    #[derive(Clone)]
    struct SlowWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }
    impl Write for SlowWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            std::thread::sleep(Duration::from_millis(20));
            self.buf.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // 200 inline pings: each response is tiny but the sink paces them at 20ms/line.
    let mut input = String::new();
    for i in 0..200 {
        input.push_str(&format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"ping"}}"#));
        input.push('\n');
    }
    let t = FakeTransportSync(|_cmd: &AgentCommand| panic!("ping is inline; no daemon call"));
    let writer = SlowWriter {
        buf: Arc::new(Mutex::new(Vec::new())),
    };
    let buf = Arc::clone(&writer.buf);

    let start = Instant::now();
    serve_inner(
        t,
        Cursor::new(input.into_bytes()),
        writer,
        test_timings(300, 50, 200),
    )
    .unwrap();
    let elapsed = start.elapsed();

    let answered = buf.lock().unwrap().iter().filter(|b| **b == b'\n').count();
    assert!(
        answered < 120,
        "after real EOF the post-EOF window bounds admission — the whole {answered}-deep \
         backlog must not be ground through at sink pace"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the drain anchors at real EOF and the exit stays bounded — serve took {elapsed:?}"
    );
}

// ---- pipe hangup is observed independently of the kernel backlog -------------------------------

#[test]
fn pipe_hangup_is_observed_behind_a_kernel_backlog() {
    // >queue-depth requests on a REAL pipe, then the client closes its end: EOF-as-read hides
    // behind the backlog (the reader parks on the full queue), so hangup must be observed
    // independently (poll POLLHUP) — the shutdown clock anchors at the CLOSE, not at backlog
    // exhaustion, and a slow-but-progressing sink cannot keep admitting work for a departed client.
    use std::os::fd::AsRawFd;

    #[derive(Clone)]
    struct SlowWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }
    impl Write for SlowWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            std::thread::sleep(Duration::from_millis(20));
            self.buf.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let (reader, writer) = std::io::pipe().expect("anonymous pipe");
    let fd = reader.as_raw_fd();
    let feeder = std::thread::spawn(move || {
        let mut w = writer;
        for i in 0..400 {
            use std::io::Write as _;
            writeln!(w, r#"{{"jsonrpc":"2.0","id":{i},"method":"ping"}}"#).unwrap();
        }
        // dropping `w` hangs the pipe up with most of the backlog unread.
    });

    let t = FakeTransportSync(|_cmd: &AgentCommand| panic!("ping is inline; no daemon call"));
    let sink = SlowWriter {
        buf: Arc::new(Mutex::new(Vec::new())),
    };
    let buf = Arc::clone(&sink.buf);
    let start = Instant::now();
    serve_inner_watched(
        t,
        io::BufReader::new(reader),
        sink,
        test_timings(300, 50, 200),
        Some(fd),
    )
    .unwrap();
    let elapsed = start.elapsed();
    feeder.join().unwrap();

    let answered = buf.lock().unwrap().iter().filter(|b| **b == b'\n').count();
    assert!(
        answered < 200,
        "hangup anchors the shutdown clock — the {answered}-deep kernel backlog must not keep \
         being admitted after the client closed"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the exit is bounded from the CLOSE, not from backlog exhaustion — serve took {elapsed:?}"
    );
}

// ---- every shutdown phase rides the DECLARED budget -------------------------------------------

#[test]
fn the_flush_phase_is_bounded_by_the_declared_budget_not_a_constant() {
    // The composed exit is only bounded end-to-end if EVERY phase is bounded by the deployment's
    // own `ShutdownTimings`. The final flush used to wait a hardcoded 5s regardless of the declared
    // budget, so a sink that had not landed its queued lines by then held the exit for five seconds
    // past a budget of a fifth of one — the exit anchored at sink pace, not at the client's close.
    // With a 50/10/100ms budget the whole shutdown, flush included, is a fraction of a second.
    let t =
        FakeTransportSync(|_cmd: &AgentCommand| Ok(json!({ "kind": "catalog", "catalog": [] })));
    let input = tools_call_line(1, "catalog", json!({}));
    let start = Instant::now();
    serve_inner(
        t,
        Cursor::new(input),
        StalledForeverWriter,
        test_timings(50, 10, 100),
    )
    .expect("a blocked sink is a bounded wind-down");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "the flush is bounded by the declared budget (50+10+100ms), never by a constant outside \
         it — serve took {elapsed:?}"
    );
}

#[test]
fn hello_negotiation_flows_into_has_feature() {
    // The daemon's advertised features ride the session frame into the cache. Before any
    // successful hello — or from a daemon that advertises nothing — the answer is FALSE:
    // fail closed, no custody vocabulary assumed.
    struct FeatureWire;
    impl WireOps for FeatureWire {
        fn hello(&self) -> Result<SessionHello, AgentError> {
            Ok(hello_of(
                "sess_1",
                vec![cermet_ipc::wire::FEATURE_CUSTODY_PROOF.to_string()],
            ))
        }
        fn call_with_session(&self, _cmd: &AgentCommand, _s: &str) -> Result<Value, AgentError> {
            Ok(json!({ "kind": "catalog" }))
        }
    }
    let cache = SessionCache::new();
    assert!(
        !cache.has_feature(cermet_ipc::wire::FEATURE_CUSTODY_PROOF),
        "fail closed before any hello"
    );
    cache.ensure(&FeatureWire).expect("hello mints");
    assert!(
        cache.has_feature(cermet_ipc::wire::FEATURE_CUSTODY_PROOF),
        "advertised → true"
    );
    assert!(
        !cache.has_feature(cermet_ipc::wire::FEATURE_ASYNC_EXECUTE),
        "only what the daemon actually advertised"
    );
}

// ---- async execute v1 --------------------------------------------------------------------------

/// A Send+Sync transport for the async surface: answers Execute with a fixed reply (optionally
/// counting the calls and/or gating the RPC so a run stays live), answers Status with a fixed frame,
/// and advertises `async_execute_v1` unless told not to (the version-skew probe).
struct AsyncFake {
    execute_reply: Value,
    execute_calls: Arc<AtomicU32>,
    gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    has_async: bool,
}
impl AsyncFake {
    fn new(execute_reply: Value) -> Self {
        Self {
            execute_reply,
            execute_calls: Arc::new(AtomicU32::new(0)),
            gate: None,
            has_async: true,
        }
    }
}
impl AgentTransport for AsyncFake {
    fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
        match cmd {
            AgentCommand::Execute { .. } => {
                self.execute_calls.fetch_add(1, Ordering::SeqCst);
                if let Some(gate) = &self.gate {
                    let (lock, cvar) = &**gate;
                    let mut open = lock.lock().unwrap();
                    while !*open {
                        open = cvar.wait(open).unwrap();
                    }
                }
                Ok(self.execute_reply.clone())
            }
            _ => Ok(json!({ "kind": "catalog", "catalog": [] })),
        }
    }
    fn has_feature(&self, f: &str) -> bool {
        f != cermet_ipc::wire::FEATURE_ASYNC_EXECUTE || self.has_async
    }
}

#[test]
fn async_execute_fast_run_completes_inline() {
    // A run that finishes inside the bounded wait returns its receipt INLINE — one call, exactly
    // like the old blocking execute for a quick verb.
    let t = Arc::new(AsyncFake::new(json!({
        "kind": "executed", "ok": true, "provider": "v", "action": "a",
        "result": { "url": "fast-done" }
    })));
    let sup = Arc::new(RunSupervisor::new(4, 16));
    let (content, is_error) = tool_execute_async(&t, &sup, &json!({ "request_id": "rq-1" }));
    assert!(!is_error, "a completed run is a success");
    assert!(
        content[0]["text"].as_str().unwrap().contains("fast-done"),
        "a run finishing within the wait returns its receipt inline: {content:?}"
    );
}

#[test]
fn async_execute_slow_run_returns_a_handle_within_the_wait_bound() {
    // A run that outlasts the (short) wait returns a `{request_id, state}` handle promptly — never
    // blocking the call for the whole run.
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let mut f = AsyncFake::new(json!({
        "kind": "executed", "ok": true, "provider": "v", "action": "a", "result": null
    }));
    f.gate = Some(Arc::clone(&gate));
    let t = Arc::new(f);
    let sup = Arc::new(RunSupervisor::new(4, 16));
    let t0 = Instant::now();
    let (content, is_error) =
        tool_execute_async(&t, &sup, &json!({ "request_id": "rq-1", "wait_ms": 50 }));
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "returns within the bounded wait, not the run duration ({:?})",
        t0.elapsed()
    );
    assert!(!is_error, "a still-running handle is a valid answer");
    assert!(
        content[0]["text"]
            .as_str()
            .unwrap()
            .contains("still running"),
        "a run past the wait returns a background handle: {content:?}"
    );
    release_gate(&gate); // let the background run finish + settle
}

#[test]
fn async_execute_dedups_a_duplicate_start() {
    // A duplicate execute_capability for the SAME request_id while the run is live must NOT start a
    // second execution (grants are single-use; the daemon CAS is the backstop, dedup is the fast path).
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let calls = Arc::new(AtomicU32::new(0));
    let mut f = AsyncFake::new(json!({
        "kind": "executed", "ok": true, "provider": "v", "action": "a", "result": null
    }));
    f.gate = Some(Arc::clone(&gate));
    f.execute_calls = Arc::clone(&calls);
    let t = Arc::new(f);
    let sup = Arc::new(RunSupervisor::new(4, 16));
    let _ = tool_execute_async(&t, &sup, &json!({ "request_id": "rq-1", "wait_ms": 0 }));
    // Let the background run enter its gated Execute (calls == 1, still Running).
    std::thread::sleep(Duration::from_millis(150));
    let _ = tool_execute_async(&t, &sup, &json!({ "request_id": "rq-1", "wait_ms": 0 }));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a duplicate start dedups onto the live run — the grant is never executed twice"
    );
    release_gate(&gate);
}

#[test]
fn async_execute_skew_fails_before_any_claim() {
    // A daemon that never negotiated async_execute_v1: the surface refuses BEFORE the claiming RPC —
    // no silent fallback to a fully-blocking execute.
    let calls = Arc::new(AtomicU32::new(0));
    let mut f = AsyncFake::new(json!({
        "kind": "executed", "ok": true, "provider": "v", "action": "a", "result": null
    }));
    f.has_async = false;
    f.execute_calls = Arc::clone(&calls);
    let t = Arc::new(f);
    let sup = Arc::new(RunSupervisor::new(4, 16));
    let (content, is_error) = tool_execute_async(&t, &sup, &json!({ "request_id": "rq-1" }));
    assert!(is_error, "version skew is a tool error");
    assert!(
        content[0]["text"]
            .as_str()
            .unwrap()
            .contains("async-execute"),
        "the refusal names the skew: {content:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no claim under skew — the refusal lands before the RPC"
    );
}

#[test]
fn async_status_running_returns_a_poll_hint() {
    let t = FakeTransportSync(|_cmd: &AgentCommand| {
        Ok(json!({
            "kind": "status", "request_id": "rq-1", "status": "running", "phase": "running",
            "effect_id": "effect_running"
        }))
    });
    let sup = RunSupervisor::new(4, 16);
    let (content, is_error) = tool_status_async(&t, &sup, &json!({ "request_id": "rq-1" }));
    assert!(
        !is_error,
        "a nonterminal phase is a valid answer, not a tool error"
    );
    let text = content[0]["text"].as_str().unwrap();
    assert!(text.contains("running"), "names the phase: {text}");
    assert!(
        text.contains("poll_after_ms"),
        "carries a poll hint: {text}"
    );
    assert!(
        content.iter().any(|part| part["text"]
            .as_str()
            .is_some_and(|text| text.contains("effect_running"))),
        "the nonterminal status response lost its effect handle: {content:?}"
    );
}

#[test]
fn async_status_without_typed_phase_fails_closed() {
    let t = FakeTransportSync(|_cmd: &AgentCommand| {
        Ok(json!({ "kind": "status", "request_id": "rq-1", "status": "ready" }))
    });
    let sup = RunSupervisor::new(4, 16);
    let (content, is_error) = tool_status_async(&t, &sup, &json!({ "request_id": "rq-1" }));
    assert!(is_error);
    assert!(
        content[0]["text"]
            .as_str()
            .unwrap()
            .contains("typed run phase"),
        "an incomplete status frame must fail closed: {content:?}"
    );
}

#[test]
fn meta_tools_carry_title_and_readonly_hint_only_on_read_only_tools() {
    let t = fixed(Value::Null);
    let msg = json!({ "jsonrpc": "2.0", "id": 41, "method": "tools/list" });
    let resp = handle_message(&t, &msg).expect("tools/list replies");
    let tools = resp["result"]["tools"].as_array().expect("tools array");

    // Every meta-tool carries a non-empty display title.
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        let title = tool["annotations"]["title"].as_str();
        assert!(
            title.is_some_and(|s| !s.is_empty()),
            "meta-tool {name:?} must carry a non-empty annotations.title"
        );
    }

    // Exactly the five side-effect-free tools advertise readOnlyHint; the mutating tools never do.
    let read_only: std::collections::HashSet<&str> = [
        "catalog",
        "request_status",
        "list_connected_providers",
        "verify_audit",
        "artifact",
    ]
    .into_iter()
    .collect();
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        let hint = tool["annotations"]["readOnlyHint"].as_bool();
        if read_only.contains(name) {
            assert_eq!(
                hint,
                Some(true),
                "read-only tool {name:?} must set readOnlyHint"
            );
        } else {
            assert!(
                hint.is_none(),
                "mutating tool {name:?} must NOT set readOnlyHint (it still prompts), got {hint:?}"
            );
        }
    }
    // None of the approval-shaped / mutating verbs are read-only-hinted (the invariant, positively).
    for n in ["request_capability", "execute_capability"] {
        let tool = tools.iter().find(|t| t["name"] == json!(n)).unwrap();
        assert!(
            tool["annotations"].get("readOnlyHint").is_none(),
            "{n} must prompt"
        );
    }
}

#[test]
fn m3b_tools_list_catalog_failure_serves_the_meta_tools_only() {
    let t = FakeTransportSync(|_: &AgentCommand| -> Result<Value, AgentError> {
        Err(AgentError::Connect("daemon down".into()))
    });
    let msg = json!({ "jsonrpc": "2.0", "id": 8, "method": "tools/list" });
    let resp = handle_message(&t, &msg).expect("tools/list replies");
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    assert_eq!(
        tools.len(),
        8,
        "catalog failure ⇒ exactly the static meta-tools (fail closed)"
    );
    assert!(
        tools
            .iter()
            .all(|t| !t["name"].as_str().unwrap_or("").contains('-')),
        "no generated verb tool without a catalog"
    );
}

#[test]
fn m3b_initialize_declares_list_changed() {
    let t = fixed(Value::Null);
    let msg = json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {} });
    let resp = handle_message(&t, &msg).expect("initialize replies");
    assert_eq!(
        resp["result"]["capabilities"]["tools"]["listChanged"],
        json!(true),
        "the dynamic tool list declares listChanged"
    );
}

#[test]
fn m3b_verb_tool_name_split_is_reversible() {
    assert_eq!(
        split_verb_tool_name("github-read_repo"),
        Some(("github".to_string(), "read_repo".to_string()))
    );
    assert_eq!(
        split_verb_tool_name(&verb_tool_name("stripe", "get_charge")),
        Some(("stripe".to_string(), "get_charge".to_string()))
    );
    assert_eq!(split_verb_tool_name("-x"), None, "empty provider refused");
    assert_eq!(split_verb_tool_name("x-"), None, "empty action refused");
    assert_eq!(
        split_verb_tool_name("no_hyphen"),
        None,
        "a meta-tool name never splits"
    );
    assert_eq!(
        split_verb_tool_name("Bad-Case"),
        None,
        "outside the is_ident charset refused"
    );
}

/// A recording transport for verb-tool calls: scripted Request/Execute replies + a call log,
/// Send+Sync so the background run thread can share it.
struct VerbCallFake {
    request_reply: Value,
    execute_reply: Value,
    calls: Arc<Mutex<Vec<AgentCommand>>>,
}
impl AgentTransport for VerbCallFake {
    fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
        self.calls.lock().unwrap().push(cmd.clone());
        match cmd {
            AgentCommand::Request { .. } => Ok(self.request_reply.clone()),
            AgentCommand::Execute { .. } | AgentCommand::Status { .. } => {
                Ok(self.execute_reply.clone())
            }
            _ => Ok(json!({ "kind": "catalog", "catalog": [] })),
        }
    }
}

#[test]
fn m3b_verb_tool_call_requests_then_executes_and_returns_the_receipt_inline() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let t = Arc::new(VerbCallFake {
        request_reply: json!({
            "kind": "requested", "request_id": "rq-v1", "decision": "allow",
            "reason": "pinned"
        }),
        execute_reply: json!({
            "kind": "executed", "ok": true, "provider": "github", "action": "read_repo",
            "result": { "full_name": "acme/widgets" }
        }),
        calls: Arc::clone(&calls),
    });
    let sup = Arc::new(RunSupervisor::new(4, 16));
    let (content, is_error) = tool_verb_call(
        &t,
        &sup,
        "github-read_repo",
        &json!({ "owner": "acme", "name": "widgets", "justification": "inspect repository" }),
    );
    assert!(
        !is_error,
        "an auto-allowed verb completes in ONE call: {content:?}"
    );
    assert!(
        content[0]["text"]
            .as_str()
            .unwrap()
            .contains("acme/widgets"),
        "the receipt lands inline: {content:?}"
    );
    let log = calls.lock().unwrap().clone();
    let req = log
        .iter()
        .find_map(|c| match c {
            AgentCommand::Request {
                provider,
                action,
                resource,
                justification,
                ..
            } => Some((
                provider.clone(),
                action.clone(),
                resource.clone(),
                justification.clone(),
            )),
            _ => None,
        })
        .expect("the verb tool minted exactly one request");
    assert_eq!(
        (req.0.as_str(), req.1.as_str()),
        ("github", "read_repo"),
        "name split is the verb"
    );
    assert_eq!(
        req.2["owner"],
        json!("acme"),
        "fields ride the resource path"
    );
    assert_eq!(req.2["name"], json!("widgets"));
    assert!(
        req.2.get("justification").is_none() && req.2.get("request_id").is_none(),
        "reserved protocol args never leak into the resource: {:?}",
        req.2
    );
    assert_eq!(
        req.3.as_deref(),
        Some("inspect repository"),
        "justification rides the request"
    );
}

#[test]
fn moneypath_generated_verb_result_preserves_the_safe_effect_handle() {
    let transport = Arc::new(VerbCallFake {
        request_reply: json!({
            "kind": "requested", "request_id": "rq-money", "decision": "allow",
            "reason": "pinned", "effect_id": "effect_0123456789abcdef0123456789abcdef"
        }),
        execute_reply: json!({
            "kind": "executed", "ok": false, "provider": "stripe",
            "action": "capture_payment_intent",
            "effect_id": "effect_0123456789abcdef0123456789abcdef",
            "result": null
        }),
        calls: Arc::new(Mutex::new(Vec::new())),
    });
    let supervisor = Arc::new(RunSupervisor::new(4, 16));
    let (content, _) = tool_verb_call(
        &transport,
        &supervisor,
        "stripe-capture_payment_intent",
        &json!({
            "payment_intent":"pi_1", "amount":500,
            "justification":"retryable capture"
        }),
    );
    assert!(
        content.iter().any(|part| part["text"]
            .as_str()
            .is_some_and(|text| text.contains("effect_0123456789abcdef0123456789abcdef"))),
        "the terminal/error result lost its retry handle: {content:?}"
    );
}

#[test]
fn moneypath_async_execute_ignores_caller_effect_and_uses_broker_status() {
    struct EffectStatusTransport {
        gate: Arc<(Mutex<bool>, Condvar)>,
    }
    impl AgentTransport for EffectStatusTransport {
        fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
            match cmd {
                AgentCommand::Status { .. } => Ok(json!({
                    "kind":"status", "request_id":"rq-money", "status":"ready",
                    "phase":"ready", "effect_id":"effect_broker"
                })),
                AgentCommand::Execute { .. } => {
                    let (lock, cvar) = &*self.gate;
                    let mut open = lock.lock().unwrap();
                    while !*open {
                        open = cvar.wait(open).unwrap();
                    }
                    Ok(json!({
                        "kind":"executed", "ok":true, "provider":"stripe",
                        "action":"capture_payment_intent", "effect_id":"effect_broker",
                        "result":{}
                    }))
                }
                _ => unreachable!(),
            }
        }
    }

    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let transport = Arc::new(EffectStatusTransport {
        gate: Arc::clone(&gate),
    });
    let supervisor = Arc::new(RunSupervisor::new(4, 16));
    let (content, is_error) = tool_execute_async(
        &transport,
        &supervisor,
        &json!({
            "request_id":"rq-money", "wait_ms":0,
            "effect_id":"effect_caller_spoof"
        }),
    );
    assert!(!is_error);
    let rendered = serde_json::to_string(&content).unwrap();
    assert!(rendered.contains("effect_broker"), "{content:?}");
    assert!(!rendered.contains("effect_caller_spoof"), "{content:?}");
    release_gate(&gate);
}

#[test]
fn moneypath_async_execution_error_preserves_broker_effect() {
    struct EffectErrorTransport;
    impl AgentTransport for EffectErrorTransport {
        fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
            match cmd {
                AgentCommand::Status { .. } => Ok(json!({
                    "kind":"status", "request_id":"rq-money", "status":"ready",
                    "phase":"ready", "effect_id":"effect_broker"
                })),
                AgentCommand::Execute { .. } => Err(AgentError::ServerEffect {
                    reason: "unable to execute".into(),
                    effect_id: "effect_broker".into(),
                    effect_outcome: Some(EffectOutcome::Ambiguous),
                }),
                _ => unreachable!(),
            }
        }
    }

    let transport = Arc::new(EffectErrorTransport);
    let supervisor = Arc::new(RunSupervisor::new(4, 16));
    let (content, is_error) = tool_execute_async(
        &transport,
        &supervisor,
        &json!({"request_id":"rq-money", "effect_id":"effect_caller_spoof"}),
    );
    assert!(is_error);
    let rendered = serde_json::to_string(&content).unwrap();
    assert!(rendered.contains("effect_broker"), "{content:?}");
    assert!(!rendered.contains("effect_caller_spoof"), "{content:?}");
}

#[test]
fn m3b_verb_tool_call_requires_justification_before_any_daemon_call() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let t = Arc::new(VerbCallFake {
        request_reply: Value::Null,
        execute_reply: Value::Null,
        calls: Arc::clone(&calls),
    });
    let sup = Arc::new(RunSupervisor::new(4, 16));
    let (content, is_error) = tool_verb_call(
        &t,
        &sup,
        "github-read_repo",
        &json!({ "owner": "acme", "name": "widgets" }),
    );
    assert!(is_error, "a missing justification is a usage error");
    assert!(content[0]["text"]
        .as_str()
        .unwrap()
        .contains("justification"));
    assert!(
        calls.lock().unwrap().is_empty(),
        "refused BEFORE any daemon call"
    );
}

#[test]
fn m3b_verb_tool_call_deny_is_final_and_never_executes() {
    let hint = "to allow: cermet rules allow 'stripe.support@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa where amount <= 50000'";
    let calls = Arc::new(Mutex::new(Vec::new()));
    let t = Arc::new(VerbCallFake {
        request_reply: json!({
            // A policy deny always carries `authority_kind: sentence` on the real wire
            // (lifecycle.rs attaches it to policy denies alone; hints ride only those).
            "kind": "requested", "request_id": "rq-d", "decision": "deny",
            "reason": "production is denied", "hint": hint, "authority_kind": "sentence"
        }),
        execute_reply: json!({
            "kind": "executed", "ok": true, "provider": "v", "action": "a", "result": null
        }),
        calls: Arc::clone(&calls),
    });
    let sup = Arc::new(RunSupervisor::new(4, 16));
    let (content, is_error) = tool_verb_call(
        &t,
        &sup,
        "github-read_repo",
        &json!({ "owner": "acme", "name": "widgets", "justification": "inspect repo" }),
    );
    assert!(
        is_error,
        "a policy deny on a verb tool is a tool error (the command did not run)"
    );
    let text = content[0]["text"].as_str().unwrap();
    assert!(text.contains("do not retry"), "deny is final: {text}");
    let command = hint.strip_prefix("to allow: ").unwrap();
    assert!(
        text.lines().any(|line| line == command),
        "generated verb denial dropped the advisory command: {text}"
    );
    // Give any (wrong) background run a moment to surface, then prove no Execute happened.
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        !calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| matches!(c, AgentCommand::Execute { .. })),
        "a denied request must NEVER reach an execute"
    );
}

#[test]
fn m3b_verb_tool_call_with_request_id_resumes_and_never_rerequests() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let t = Arc::new(VerbCallFake {
        request_reply: json!({
            "kind": "requested", "request_id": "rq-should-not-exist", "decision": "allow",
            "reason": ""
        }),
        execute_reply: json!({
            "kind": "status", "request_id": "rq-live", "status": "terminal",
            "phase": "terminal", "outcome": "succeeded", "termination": "exited",
            "effect_id": "effect_resumed",
            "terminal_receipt": {
                "kind": "executed", "ok": true, "provider": "github", "action": "read_repo",
                "result": { "out": "resumed" }
            }
        }),
        calls: Arc::clone(&calls),
    });
    let sup = Arc::new(RunSupervisor::new(4, 16));
    let (content, is_error) = tool_verb_call(
        &t,
        &sup,
        "github-read_repo",
        &json!({ "request_id": "rq-live" }),
    );
    assert!(!is_error);
    assert!(content[0]["text"].as_str().unwrap().contains("resumed"));
    assert!(
        content.iter().any(|part| part["text"]
            .as_str()
            .is_some_and(|text| text.contains("effect_resumed"))),
        "resume lost the effect handle: {content:?}"
    );
    let log = calls.lock().unwrap().clone();
    assert!(
        !log.iter()
            .any(|c| matches!(c, AgentCommand::Request { .. })),
        "resume NEVER re-requests (grants are single-use): {log:?}"
    );
    assert!(
        log.iter().any(
            |c| matches!(c, AgentCommand::Status { request_id, .. } if request_id == "rq-live")
        ),
        "resume polls the supplied handle"
    );
    assert!(
        !log.iter()
            .any(|c| matches!(c, AgentCommand::Execute { .. })),
        "resume never re-executes a single-use grant: {log:?}"
    );
}

// ---- session remint, durable reconciliation, bounded status ---------------------------------------

#[test]
fn remint_renegotiation_regates_the_required_feature_before_replay() {
    // The daemon behind the socket is swapped for an OLDER build mid-session: the Execute is refused
    // SESSION_EXPIRED, the re-Hello renegotiates an EMPTY feature set, and the replay must be
    // refused with the legible skew error BEFORE any resend — never the silent blocking fallback.
    struct DowngradingWire {
        hellos: AtomicU32,
        sends: AtomicU32,
    }
    impl WireOps for DowngradingWire {
        fn hello(&self) -> Result<SessionHello, AgentError> {
            let n = self.hellos.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                Ok(hello_of(
                    "sess_1",
                    vec![cermet_ipc::wire::FEATURE_ASYNC_EXECUTE.to_string()],
                ))
            } else {
                // The swapped (older) daemon advertises nothing.
                Ok(hello_of(format!("sess_{n}"), vec![]))
            }
        }
        fn call_with_session(&self, _cmd: &AgentCommand, _s: &str) -> Result<Value, AgentError> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            Err(AgentError::Server(SESSION_EXPIRED.to_string()))
        }
    }
    let wire = DowngradingWire {
        hellos: AtomicU32::new(0),
        sends: AtomicU32::new(0),
    };
    let cache = SessionCache::new();
    let cmd = AgentCommand::Execute {
        request_id: "rq-1".into(),
    };
    let res = cache.call_requiring(&wire, &cmd, cermet_ipc::wire::FEATURE_ASYNC_EXECUTE);
    match res {
        Err(AgentError::Server(m)) => {
            assert!(
                m.starts_with(SKEW_PREFIX),
                "a legible skew refusal, got: {m}"
            )
        }
        other => panic!("expected the skew refusal, got {other:?}"),
    }
    assert_eq!(
        wire.sends.load(Ordering::SeqCst),
        1,
        "the claiming RPC was sent ONCE; the post-remint replay was refused before the resend"
    );
    assert_eq!(
        wire.hellos.load(Ordering::SeqCst),
        2,
        "exactly one re-Hello happened"
    );
}

#[test]
fn cached_success_never_outranks_the_durable_projection() {
    // A run settled in-memory as a SUCCESS, but the daemon's durable projection answers terminal
    // WITHOUT a reconstructable receipt (the chain failed verification). request_status must render
    // the durable answer — the cached in-memory success must never outrank a withheld receipt.
    let sup = RunSupervisor::new(4, 16);
    let t_exec = Arc::new(AsyncFake::new(json!({
        "kind": "executed", "ok": true, "provider": "v", "action": "a",
        "result": { "url": "cached-success" }
    })));
    let rec = sup.start("rq-1", &t_exec, None).expect("run starts");
    rec.wait_terminal(Duration::from_secs(5))
        .expect("the run settles in memory");

    let t_status = FakeTransportSync(|cmd: &AgentCommand| {
        assert!(
            matches!(cmd, AgentCommand::Status { .. }),
            "only the durable status is consulted"
        );
        Ok(json!({
            "kind": "status", "request_id": "rq-1", "status": "terminal",
            "phase": "terminal", "outcome": "succeeded", "termination": "exited"
            // no terminal_receipt: the chain did not verify — the receipt is withheld.
        }))
    });
    let (content, is_error) = tool_status_async(&t_status, &sup, &json!({ "request_id": "rq-1" }));
    assert!(!is_error);
    let text = content[0]["text"].as_str().unwrap();
    assert!(
        !text.contains("cached-success"),
        "the cached in-memory receipt must NOT render when the durable projection withholds: {text}"
    );
    assert!(
        text.contains("no longer reconstructable"),
        "the honest withheld-receipt answer renders instead: {text}"
    );
}

/// A transport whose Execute fails with an AMBIGUOUS transport error (possibly post-send) while the
/// daemon's durable status knows the truth.
struct AmbiguousFake {
    exec_calls: Arc<AtomicU32>,
    exec_result: fn(u32) -> Result<Value, AgentError>,
    status_reply: Value,
}
impl AgentTransport for AmbiguousFake {
    fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
        match cmd {
            AgentCommand::Execute { .. } => {
                let n = self.exec_calls.fetch_add(1, Ordering::SeqCst);
                (self.exec_result)(n)
            }
            AgentCommand::Status { .. } => Ok(self.status_reply.clone()),
            _ => Ok(json!({ "kind": "catalog", "catalog": [] })),
        }
    }
}

#[test]
fn ambiguous_failure_reconciles_to_the_durable_receipt_never_a_restart() {
    // The Execute reply is lost AFTER the daemon durably executed. The next execute_capability must
    // return the DURABLE receipt via reconciliation — never a blind restart (which would hit the CAS,
    // mask the receipt, and invite a second separately-granted side effect).
    let calls = Arc::new(AtomicU32::new(0));
    let t = Arc::new(AmbiguousFake {
        exec_calls: Arc::clone(&calls),
        exec_result: |_| Err(AgentError::Transport("reply lost mid-read".into())),
        status_reply: json!({
            "kind": "status", "request_id": "rq-1", "status": "terminal",
            "phase": "terminal", "outcome": "succeeded", "termination": "exited",
            "effect_id": "effect_ambiguous",
            "terminal_receipt": {
                "kind": "executed", "ok": true, "provider": "v", "action": "a",
                "result": { "url": "durable-truth" }
            }
        }),
    });
    let sup = Arc::new(RunSupervisor::new(4, 16));
    let args = json!({ "request_id": "rq-1", "effect_id": "effect_caller_spoof" });
    // First call: the run settles AMBIGUOUS; the failure surfaces to the caller.
    let (c1, e1) = tool_execute_async(&t, &sup, &args);
    assert!(e1, "the ambiguous transport failure surfaces");
    assert!(c1.iter().any(|part| part["text"]
        .as_str()
        .is_some_and(|text| text.contains("effect_ambiguous"))));
    assert!(!serde_json::to_string(&c1)
        .unwrap()
        .contains("effect_caller_spoof"));
    // Second call: reconciled through the durable status — the receipt, not a fresh claim.
    let (c2, e2) = tool_execute_async(&t, &sup, &args);
    assert!(!e2, "reconciliation answers with the durable truth: {c2:?}");
    assert!(
        c2[0]["text"].as_str().unwrap().contains("durable-truth"),
        "the durable receipt renders: {c2:?}"
    );
    assert!(c2.iter().any(|part| part["text"]
        .as_str()
        .is_some_and(|text| text.contains("effect_ambiguous"))));
    assert!(!serde_json::to_string(&c2)
        .unwrap()
        .contains("effect_caller_spoof"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "an ambiguous run is NEVER blindly restarted — exactly one claiming RPC ever"
    );
}

#[test]
fn reconciled_unclaimed_permits_exactly_one_restart() {
    // The ambiguous failure happened BEFORE any claim (the daemon's durable status still says
    // ready): reconciliation proves the restart safe, and the second call runs the grant.
    let calls = Arc::new(AtomicU32::new(0));
    let t = Arc::new(AmbiguousFake {
        exec_calls: Arc::clone(&calls),
        exec_result: |n| {
            if n == 0 {
                Err(AgentError::Transport("connection reset".into()))
            } else {
                Ok(json!({
                    "kind": "executed", "ok": true, "provider": "v", "action": "a",
                    "result": { "url": "second-try-ran" }
                }))
            }
        },
        status_reply: json!({
            "kind": "status", "request_id": "rq-1", "status": "ready",
            "phase": "ready"
        }),
    });
    let sup = Arc::new(RunSupervisor::new(4, 16));
    let (_c1, e1) = tool_execute_async(&t, &sup, &json!({ "request_id": "rq-1" }));
    assert!(e1);
    let (c2, e2) = tool_execute_async(&t, &sup, &json!({ "request_id": "rq-1" }));
    assert!(!e2, "a provably-unclaimed grant restarts: {c2:?}");
    assert!(c2[0]["text"].as_str().unwrap().contains("second-try-ran"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "exactly one reconciled restart"
    );
}

#[test]
fn terminal_without_verified_outcome_is_never_a_clean_finish() {
    // A terminal grant with NO chain-verified outcome (the torn crash state) must render as
    // needs-attention with an explicit unknown-outcome warning — never a benign "Run finished".
    let t = FakeTransportSync(|_: &AgentCommand| {
        Ok(json!({
            "kind": "status", "request_id": "rq-1", "status": "terminal", "phase": "terminal"
            // no outcome / termination / terminal_receipt: nothing verifiable exists.
        }))
    });
    let sup = RunSupervisor::new(4, 16);
    let (content, is_error) = tool_status_async(&t, &sup, &json!({ "request_id": "rq-1" }));
    assert!(
        is_error,
        "an unverifiable terminal outcome needs attention, not a clean finish"
    );
    let text = content[0]["text"].as_str().unwrap();
    assert!(
        text.contains("could NOT be verified") && text.contains("UNKNOWN"),
        "the render names the unverifiable outcome: {text}"
    );
    assert!(
        !text.contains("Run finished"),
        "the benign phrasing is banned for an unverified terminal: {text}"
    );
}

#[test]
fn terminal_effect_guidance_is_derived_from_the_authenticated_outcome_class() {
    for (effect_outcome, expected, forbidden) in [
        ("ambiguous", "retry_effect", "fresh effect"),
        ("definitely_pre_effect", "fresh effect", "retry_effect"),
        ("succeeded", "Do not retry", "retry_effect"),
        ("definitely_failed", "Do not retry", "retry_effect"),
    ] {
        let response = json!({
            "kind": "status",
            "request_id": "rq-money",
            "status": "terminal",
            "phase": "terminal",
            "outcome": if effect_outcome == "succeeded" { "succeeded" } else { "failed" },
            "termination": "exited",
            "effect_id": "effect_authenticated",
            "effect_outcome": effect_outcome,
            "terminal_receipt": {
                "kind": "executed",
                "ok": effect_outcome == "succeeded",
                "provider": "stripe",
                "action": "capture_payment_intent",
                "effect_id": "effect_authenticated",
                "effect_outcome": effect_outcome,
                "result": null
            }
        });
        let rendered = render_terminal_status("rq-money", &response, Some("effect_spoof"));
        let text = rendered
            .0
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains(expected), "{effect_outcome}: {text}");
        assert!(!text.contains(forbidden), "{effect_outcome}: {text}");
        assert!(
            text.contains("effect_authenticated"),
            "{effect_outcome}: {text}"
        );
        assert!(!text.contains("effect_spoof"), "{effect_outcome}: {text}");
    }
}

#[test]
fn mcp_abandoned_started_money_status_only_advises_same_effect_retry() {
    let response = json!({
        "kind": "status",
        "request_id": "rq-money-abandoned",
        "status": "terminal",
        "phase": "terminal",
        "outcome": "abandoned",
        "termination": "abandoned",
        "effect_id": "effect_authenticated",
        "effect_outcome": "ambiguous",
    });
    let rendered = render_terminal_status("rq-money-abandoned", &response, None);
    let text = rendered
        .0
        .iter()
        .filter_map(|part| part["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("retry_effect"), "{text}");
    assert!(text.contains("effect_authenticated"), "{text}");
    assert!(!text.contains("Request the capability again"), "{text}");
    assert!(!text.contains("fresh effect"), "{text}");
}

#[test]
fn unverifiable_status_is_a_hard_stop_without_retry_guidance() {
    let transport =
        FakeTransportSync(|_: &AgentCommand| Err(AgentError::Server("internal error".into())));
    let supervisor = RunSupervisor::new(4, 16);
    let (content, is_error) =
        tool_status_async(&transport, &supervisor, &json!({ "request_id": "rq-1" }));
    assert!(is_error, "an integrity-side status refusal is a hard error");
    let text = content[0]["text"].as_str().unwrap();
    assert!(
        text.contains("UNKNOWN"),
        "the uncertain outcome is explicit: {text}"
    );
    assert!(
        !text.contains("poll request_status") && !text.contains("retry once"),
        "failed integrity must not guide another attempt: {text}"
    );

    let reconciled = reconcile_ambiguous(&transport, "rq-1", None);
    let Reconciled::Answer((content, is_error)) = reconciled else {
        panic!("an unverifiable prior attempt must never restart");
    };
    assert!(is_error);
    let text = content[0]["text"].as_str().unwrap();
    assert!(text.contains("UNKNOWN"));
    assert!(!text.contains("poll request_status") && !text.contains("retry once"));
}

#[test]
fn status_long_poll_respects_its_end_to_end_budget() {
    // A run that never terminates daemon-side: the long-poll must answer within its OWN budget —
    // never sleep+re-poll past the deadline.
    let t = FakeTransportSync(|_: &AgentCommand| {
        Ok(json!({
            "kind": "status", "request_id": "rq-1", "status": "running", "phase": "running"
        }))
    });
    let sup = RunSupervisor::new(4, 16);
    let t0 = Instant::now();
    let (content, is_error) =
        tool_status_async(&t, &sup, &json!({ "request_id": "rq-1", "wait_ms": 600 }));
    assert!(!is_error);
    assert!(
        t0.elapsed() < Duration::from_secs(3),
        "the long-poll is bounded end-to-end ({:?})",
        t0.elapsed()
    );
    assert!(content[0]["text"].as_str().unwrap().contains("running"));
}

// ---- a bounded status poll honors its wait even on a slow/contended daemon read ------------------

/// A daemon whose read is SLOW: `call` blocks `delay` (an unbounded, contended read), while
/// `call_within` honors its clamp — timing out at the budget when the daemon is slower.
struct SlowReadTransport {
    delay: Duration,
    within_calls: Arc<AtomicU32>,
}
impl AgentTransport for SlowReadTransport {
    fn call(&self, _cmd: &AgentCommand) -> Result<Value, AgentError> {
        std::thread::sleep(self.delay);
        Ok(
            json!({ "kind": "status", "request_id": "rq-1", "status": "running", "phase": "running" }),
        )
    }
    fn call_within(&self, _cmd: &AgentCommand, budget: Duration) -> Result<Value, AgentError> {
        self.within_calls.fetch_add(1, Ordering::SeqCst);
        if self.delay > budget {
            std::thread::sleep(budget);
            Err(AgentError::Transport("read timed out".into()))
        } else {
            std::thread::sleep(self.delay);
            Ok(
                json!({ "kind": "status", "request_id": "rq-1", "status": "running", "phase": "running" }),
            )
        }
    }
}

#[test]
fn status_poll_is_bounded_when_the_daemon_read_is_slow() {
    // The daemon read is contended (10s). WITHOUT the clamp, tool_status_async's unbounded read
    // would blow the advertised wait (a 20s status could sit for ~2 minutes). WITH
    // call_within clamping each read to the remaining budget (+ the ~3s immediate-read floor), the
    // poll returns promptly and tells the model to poll again — never fabricating a terminal.
    let within = Arc::new(AtomicU32::new(0));
    let t = SlowReadTransport {
        delay: Duration::from_secs(10),
        within_calls: Arc::clone(&within),
    };
    let sup = RunSupervisor::new(4, 16);
    let t0 = Instant::now();
    let (content, is_error) =
        tool_status_async(&t, &sup, &json!({ "request_id": "rq-1", "wait_ms": 200 }));
    let elapsed = t0.elapsed();

    assert!(
        !is_error,
        "a slow bounded read is not a hard failure: {content:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the status poll is bounded by call_within (returned in {elapsed:?}); an unbounded read \
         would have taken ~10s"
    );
    assert!(
        within.load(Ordering::SeqCst) >= 1,
        "the bounded read path (call_within) was exercised"
    );
    assert!(
        content[0]["text"]
            .as_str()
            .unwrap()
            .contains("poll request_status"),
        "the model is guided to poll again, not handed a fabricated outcome: {content:?}"
    );
}

#[test]
fn execute_surfaces_the_result_and_maps_failure_to_is_error() {
    let ok = fixed(json!({
        "kind": "executed", "ok": true, "provider": "github", "action": "read_repo",
        "result": { "full_name": "acme/widgets" }
    }));
    let resp = handle_message(
        &ok,
        &tools_call("execute_capability", json!({ "request_id": "rq-1" })),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    let text = first_text(content);
    assert!(text.contains("github.read_repo"), "got: {text}");
    assert!(text.contains("acme/widgets"));

    let failed = fixed(json!({
        "kind": "executed", "ok": false, "provider": "github", "action": "read_repo",
        "result": null
    }));
    let resp = handle_message(
        &failed,
        &tools_call("execute_capability", json!({ "request_id": "rq-1" })),
    )
    .unwrap();
    let (_, is_error) = call_result(&resp);
    assert!(is_error, "a failed execute is a tool error");
}

#[test]
fn catalog_tool_lists_verbs_read_only() {
    let transport = FakeTransport(|cmd: &AgentCommand| {
        assert!(
            matches!(cmd, AgentCommand::Catalog),
            "catalog must issue the read-only Catalog command, got {cmd:?}"
        );
        Ok(json!({
            "kind": "catalog",
            "catalog": [{
                "provider": "github", "action": "read_repo", "class": "corpus",
                "fields": [
                    { "name": "owner", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] },
                    { "name": "name", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] }
                ],
                "execution_targets": ["owner", "name"], "requestable": true,
                "shape": "http_api_call",
                "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"}
            }]
        }))
    });
    let resp = handle_message(&transport, &tools_call("catalog", Value::Null)).unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    assert!(first_text(content).contains("github.read_repo"));
}

fn three_verb_catalog() -> FakeTransport<impl Fn(&AgentCommand) -> Result<Value, AgentError>> {
    fixed(three_verb_frame())
}

/// Two verbs a standing sentence admits + one the corpus cannot cover.
fn three_verb_frame() -> Value {
    json!({
        "kind": "catalog", "catalog": [
            { "provider": "github", "action": "read_repo", "class": "corpus",
              "fields": [
                { "name": "owner", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] },
                { "name": "name", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] }
              ],
              "execution_targets": ["owner", "name"], "requestable": true, "sentence_denied": false,
              "admitted_by": ["allow github.read_repo where owner = \"acme\""],
              "shape": "http_api_call", "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} },
            { "provider": "github", "action": "read_tree", "class": "corpus",
              "fields": [{ "name": "repo_id", "type": "int", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in", "<=", ">="] }],
              "execution_targets": ["repo_id"], "requestable": true, "sentence_denied": false,
              "admitted_by": ["allow github.read_tree"],
              "shape": "http_api_call", "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} },
            { "provider": "stripe", "action": "get_charge", "class": "corpus",
              "fields": [{ "name": "charge", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] }],
              "execution_targets": ["charge"], "requestable": true, "sentence_denied": true,
              "shape": "http_api_call", "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }
        ]
    })
}

/// A corpus with an EXPLICIT deny, a CARVE-OUT deny under a live allow, and an UNRULED verb, read
/// through both zooms. A join over allow rules alone would read the explicit deny as "no standing
/// rule" (promising a widening suggestion the evaluator yields None for) and would hide the
/// carve-out in the contract view — the exact overstatement this guards against.
fn deny_truth_frame() -> Value {
    let entry = |provider: &str, action: &str, denied: bool, allow: Value, deny: Value| {
        json!({ "provider": provider, "action": action, "class": "corpus",
                "fields": [{ "name": "name", "type": "str", "required": true, "class": "identity",
                             "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] }],
                "execution_targets": ["name"], "requestable": true, "sentence_denied": denied,
                "admitted_by": allow, "denied_by": deny, "shape": "http_api_call",
                "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} })
    };
    json!({ "kind": "catalog", "catalog": [
        entry("stripe", "list_charges", true, json!(["allow stripe.read@sha256:abc"]),
              json!(["deny stripe.list_charges"])),
        entry("github", "read_repo", false, json!(["allow github.read_repo where owner = \"acme\""]),
              json!(["deny github.read_repo where name = \"secrets\""])),
        entry("github", "create_issue", true, json!([]), json!([])),
    ]})
}

#[test]
fn dictionary_tells_explicit_deny_carve_out_and_unruled_apart() {
    let transport = fixed(deny_truth_frame());
    let resp = handle_message(
        &transport,
        &tools_call("catalog", json!({ "scope": "all" })),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    let text = first_text(content);

    // (1) EXPLICIT DENY: names the standing deny, refuses to call it a widening candidate, and
    // never claims there is no standing rule.
    assert!(
        text.contains(
            "denied by: deny stripe.list_charges — do not request this; an explicit deny is \
             not a widening candidate"
        ),
        "{text}"
    );
    // (2) CARVE-OUT: the allow AND its exception, both on the entry.
    assert!(
        text.contains("allowed by: allow github.read_repo where owner = \"acme\""),
        "{text}"
    );
    assert!(
        text.contains("except: deny github.read_repo where name = \"secrets\""),
        "{text}"
    );
    // (3) UNRULED: the one real widening candidate keeps its widening promise.
    assert!(
        text.contains(
            "no standing rule — a request will deny with a widening suggestion for the operator"
        ),
        "{text}"
    );
    // The explicit-deny entry must NOT be described as unruled, and must not promise a widening
    // suggestion of its own: exactly one entry in this frame carries that line.
    assert_eq!(text.matches("no standing rule").count(), 1, "{text}");
    // No rule numbers anywhere on the agent surface.
    assert!(
        !text.contains("rule 1") && !text.contains("by rule "),
        "{text}"
    );
}

#[test]
fn contract_view_shows_the_carve_out_that_narrows_its_allow() {
    let transport = fixed(deny_truth_frame());
    let resp = handle_message(&transport, &tools_call("catalog", json!({}))).unwrap();
    let text = first_text(call_result(&resp).0).to_string();

    assert!(text.contains("allowed now (1 verbs)"), "{text}");
    assert!(
        text.contains(
            "github.read_repo(name:str) [http_api_call] — allowed by: allow \
                       github.read_repo where owner = \"acme\""
        ),
        "{text}"
    );
    assert!(
        text.contains("except: deny github.read_repo where name = \"secrets\""),
        "the contract view may not show an allow and hide its exception: {text}"
    );
    // A denied verb is not part of the contract at all, and no numbers appear.
    assert!(!text.contains("stripe.list_charges"), "{text}");
    assert!(
        !text.contains("rule 1") && !text.contains("by rule "),
        "{text}"
    );
}

/// The DEFAULT zoom is the CONTRACT. It lists only what a standing sentence admits, and each line
/// carries the admitting sentence WITH ITS BOUNDS plus the fields the agent supplies — the answer
/// to "what can I actually do right now", rather than something to reconstruct by hand from a
/// long verb dictionary and a terse rule list.
#[test]
fn catalog_default_scope_is_the_contract_with_admitting_sentences() {
    let transport = three_verb_catalog();
    let resp = handle_message(&transport, &tools_call("catalog", json!({}))).unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    let text = first_text(content);
    assert!(text.contains("allowed now (2 verbs)"), "{text}");
    assert!(
        text.contains("github.read_repo(owner:str, name:str)"),
        "the contract names the fields the agent supplies: {text}"
    );
    assert!(
        text.contains("allowed by: allow github.read_repo where owner = \"acme\""),
        "the admitting sentence and its bounds are the point: {text}"
    );
    assert!(
        !text.contains("stripe.get_charge"),
        "a verb no standing sentence admits is not part of the contract: {text}"
    );
    assert!(
        text.contains("scope=\"all\"") && text.contains("widening suggestion"),
        "the contract view must teach how to reach the long tail: {text}"
    );
}

/// The `all` zoom is the DICTIONARY — every verb that exists, each stamped with its
/// authority status. Nothing may overstate capability: an unruled verb says so, in the words the
/// agent needs to act (deny + a widening suggestion for the operator).
#[test]
fn catalog_scope_all_stamps_every_entry_with_its_authority_status() {
    let transport = three_verb_catalog();
    let resp = handle_message(
        &transport,
        &tools_call("catalog", json!({ "scope": "all" })),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    let text = first_text(content);
    assert!(text.contains("stripe.get_charge"), "{text}");
    assert!(
        text.contains(
            "no standing rule — a request will deny with a widening suggestion for the operator"
        ),
        "an unruled dictionary entry must state its authority status: {text}"
    );
    assert!(
        text.contains("allowed by: allow github.read_repo where owner = \"acme\""),
        "a ruled entry names the sentence that admits it: {text}"
    );
}

/// The dictionary never mislabels a COVERED verb as unruled just because it is not
/// available here — the honest answer is "a rule selects it, but it is not on this broker".
#[test]
fn dictionary_distinguishes_unruled_from_covered_but_unavailable() {
    let transport = fixed(json!({ "kind": "catalog", "catalog": [
        { "provider": "stripe", "action": "get_charge", "class": "corpus", "fields": [],
          "execution_targets": [], "requestable": false, "sentence_denied": false,
          "admitted_by": ["allow stripe.get_charge"],
          "shape": "http_api_call",
          "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }
    ]}));
    let resp = handle_message(
        &transport,
        &tools_call("catalog", json!({ "scope": "all" })),
    )
    .unwrap();
    let text = first_text(call_result(&resp).0).to_string();
    assert!(
        text.contains(
            "a standing rule selects this verb (allow stripe.get_charge), but it is not \
             available on this broker right now"
        ),
        "{text}"
    );
    assert!(!text.contains("no standing rule"), "{text}");
}

/// An unknown scope fails closed and names the two zooms — it never silently widens to
/// the dictionary or narrows to nothing.
#[test]
fn catalog_rejects_an_unknown_scope() {
    let transport = three_verb_catalog();
    let resp = handle_message(
        &transport,
        &tools_call("catalog", json!({ "scope": "everything" })),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(is_error);
    let text = first_text(content);
    assert!(text.contains("allowed") && text.contains("all"), "{text}");
}

/// The tool description is where an agent learns the two zooms exist at all.
#[test]
fn catalog_tool_description_teaches_both_zooms() {
    let tools = static_tools();
    let catalog = tools
        .iter()
        .find(|tool| tool["name"] == "catalog")
        .expect("catalog tool");
    let scope = &catalog["inputSchema"]["properties"]["scope"];
    assert_eq!(scope["enum"], json!(["allowed", "all"]));
    let description = catalog["description"].as_str().unwrap();
    for required in ["allowed", "all", "BOUNDS", "widening suggestion", "DEFAULT"] {
        assert!(
            description.contains(required),
            "the catalog description omits {required}: {description}"
        );
    }
}

/// The registered tool surface IS the standing authority — a verb no sentence admits is
/// not a tool. The unruled long tail stays reachable through the generic request path, so nothing
/// is lost but the schema tokens.
#[test]
fn tools_list_registers_only_ruled_verbs() {
    let transport = FakeTransportSync(|_: &AgentCommand| Ok(three_verb_frame()));
    let msg = json!({ "jsonrpc": "2.0", "id": 90, "method": "tools/list" });
    let resp = handle_message(&transport, &msg).expect("tools/list replies");
    let names: Vec<&str> = resp["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"github-read_repo") && names.contains(&"github-read_tree"));
    assert!(
        !names.contains(&"stripe-get_charge"),
        "a sentence-denied verb must not be registered: {names:?}"
    );
    assert!(
        names.contains(&"request_capability") && names.contains(&"catalog"),
        "the generic surface is unconditional: {names:?}"
    );
}

/// With the corpus unreadable, NO per-verb tool is registered (fail closed — never the
/// whole dictionary), and the guidance says so: an empty verb surface must not read as "this box
/// can do nothing".
#[test]
fn unreadable_authority_serves_generics_only_and_says_so() {
    let transport = FakeTransportSync(|_: &AgentCommand| -> Result<Value, AgentError> {
        Err(AgentError::Connect("daemon down".into()))
    });
    let msg = json!({ "jsonrpc": "2.0", "id": 91, "method": "tools/list" });
    let resp = handle_message(&transport, &msg).expect("tools/list replies");
    let tools = resp["result"]["tools"].as_array().unwrap();
    assert!(
        tools
            .iter()
            .all(|t| !t["name"].as_str().unwrap_or("").contains('-')),
        "no verb tool may be registered when authority cannot be read"
    );
    let catalog = tools
        .iter()
        .find(|t| t["name"] == "catalog")
        .expect("catalog stays registered");
    let description = catalog["description"].as_str().unwrap();
    assert!(
        description.contains("AUTHORITY UNREADABLE") && description.contains("request_capability"),
        "the degraded surface must explain itself: {description}"
    );
}

#[test]
fn catalog_provider_filter_narrows_the_candidate_set() {
    let transport = three_verb_catalog();
    let resp = handle_message(
        &transport,
        &tools_call("catalog", json!({ "provider": "github" })),
    )
    .unwrap();
    let (content, is_error) = call_result(&resp);
    assert!(!is_error);
    let text = first_text(content);
    assert!(text.contains("github.read_repo"), "got: {text}");
    assert!(text.contains("github.read_tree"), "got: {text}");
    assert!(!text.contains("stripe.get_charge"));
    assert!(
        text.contains("scope=allowed")
            && text.contains("showing 2 of 2 matching verbs (2 in this scope)"),
        "the filter header counts within the zoom the agent asked for: {text}"
    );
}

#[test]
fn catalog_keyword_filter_matches_action_and_fields() {
    let transport = three_verb_catalog();
    let resp = handle_message(
        &transport,
        &tools_call("catalog", json!({ "keyword": "tree" })),
    )
    .unwrap();
    let (content, _) = call_result(&resp);
    let text = first_text(content);
    assert!(text.contains("github.read_tree"));
    assert!(!text.contains("read_repo"));
    assert!(
        text.contains("showing 1 of 1 matching verbs (2 in this scope)"),
        "{text}"
    );
}

#[test]
fn catalog_limit_bounds_the_returned_set() {
    let transport = three_verb_catalog();
    let resp = handle_message(
        &transport,
        &tools_call("catalog", json!({ "provider": "github", "limit": 1 })),
    )
    .unwrap();
    let (content, _) = call_result(&resp);
    assert!(first_text(content).contains("showing 1 of 2 matching verbs (2 in this scope)"));
}

#[test]
fn catalog_no_filter_is_the_whole_zoom_unbounded() {
    let transport = three_verb_catalog();
    let resp = handle_message(
        &transport,
        &tools_call("catalog", json!({ "scope": "all" })),
    )
    .unwrap();
    let (content, _) = call_result(&resp);
    let text = first_text(content);
    assert!(!text.contains("catalog filter"));
    assert!(text.contains("github.read_repo") && text.contains("stripe.get_charge"));
}

fn m3b_catalog_frame() -> Value {
    json!({
        "kind": "catalog",
        "catalog": [
            {
                "provider": "github", "action": "read_repo",
                "fields": [
                    { "name": "owner", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] },
                    { "name": "name", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] }
                ],
                "execution_targets": ["owner", "name"], "requestable": true,
                "shape": "http_api_call", "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"}
            },
            {
                "provider": "stripe", "action": "refund_charge_bounded",
                "fields": [
                    { "name": "charge", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] },
                    { "name": "amount", "type": "int", "required": true, "class": "side_effect", "binding": "bounded", "origin": "agent_request", "forms": ["=", "in", "<=", ">=", "budget"] }
                ],
                "execution_targets": ["charge"], "requestable": true,
                "shape": "http_api_call", "response": {"returns": "verbatim", "retention": "none", "errors": "status_and_body"}
            },
            {
                "provider": "old", "action": "thing",
                "fields": [], "execution_targets": [], "requestable": false,
                "shape": "http_api_call", "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"}
            },
            {
                "provider": "bad", "action": "verb",
                "fields": [
                    { "name": "justification", "type": "str", "required": true, "class": "identity", "binding": "exact_resource_pin", "origin": "agent_request", "forms": ["=", "in"] }
                ],
                "execution_targets": [], "requestable": true,
                "shape": "http_api_call", "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"}
            }
        ]
    })
}

#[test]
fn generated_tools_omit_sentence_denied_verbs() {
    let frame = json!({"kind":"catalog","catalog":[
        {"provider":"github","action":"read_repo","fields":[],"execution_targets":[],"requestable":true,"sentence_denied":false, "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} },
        {"provider":"github","action":"read_tree","fields":[],"execution_targets":[],"requestable":true,"sentence_denied":false, "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} },
        {"provider":"stripe","action":"get_charge","fields":[],"execution_targets":[],"requestable":true,"sentence_denied":true, "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }
    ]});
    let tools = generated_verb_tools(&frame);
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(tools.len(), 2);
    assert!(names.contains(&"github-read_repo"));
    assert!(names.contains(&"github-read_tree"));
    assert!(!names.contains(&"stripe-get_charge"));
}

#[test]
fn advertised_hash_tracks_policy_denial_for_listchanged() {
    let frame = |denied: bool| {
        json!({"kind":"catalog","catalog":[
            {"provider":"github","action":"read_repo","requestable":true,"sentence_denied":false, "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} },
            {"provider":"stripe","action":"get_charge","requestable":true,"sentence_denied":denied, "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }
        ]})
    };
    assert_ne!(
        requestable_verb_hash(&frame(false)),
        requestable_verb_hash(&frame(true))
    );
}

#[test]
fn absent_sentence_denied_field_defaults_to_advertised() {
    let frame = json!({"kind":"catalog","catalog":[
        {"provider":"github","action":"read_repo","fields":[],"execution_targets":[],"requestable":true, "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"} }
    ]});
    assert_eq!(generated_verb_tools(&frame).len(), 1);
}

#[test]
fn m3b_tools_list_projects_requestable_verbs_as_generated_tools() {
    let transport = FakeTransportSync(|cmd: &AgentCommand| {
        assert!(matches!(cmd, AgentCommand::Catalog));
        Ok(m3b_catalog_frame())
    });
    let msg = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" });
    let resp = handle_message(&transport, &msg).expect("tools/list replies");
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();

    assert!(names.contains(&"github-read_repo"));
    assert!(names.contains(&"stripe-refund_charge_bounded"));
    assert!(!names.contains(&"old-thing"));
    assert!(!names.contains(&"bad-verb"));
    assert!(names.contains(&"catalog") && names.contains(&"execute_capability"));
    assert!(names.iter().all(|name| !name.contains("approve")));

    let refund = tools
        .iter()
        .find(|tool| tool["name"] == json!("stripe-refund_charge_bounded"))
        .unwrap();
    let schema = &refund["inputSchema"];
    let props = &schema["properties"];
    assert_eq!(props["charge"]["type"], json!("string"));
    assert_eq!(props["amount"]["type"], json!("integer"));
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(required.contains(&"charge") && required.contains(&"amount"));
    assert!(required.contains(&"justification"));
    assert!(props.get("request_id").is_some() && props.get("wait_ms").is_some());
    assert!(props.get("grant_id").is_none());
}

#[test]
fn generated_verb_tools_carry_a_title_but_no_readonly_hint() {
    let transport = FakeTransportSync(|_: &AgentCommand| Ok(m3b_catalog_frame()));
    let msg = json!({ "jsonrpc": "2.0", "id": 42, "method": "tools/list" });
    let resp = handle_message(&transport, &msg).expect("tools/list replies");
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == json!("github-read_repo"))
        .unwrap();
    assert_eq!(tool["annotations"]["title"], json!("github · read_repo"));
    assert!(tool["annotations"].get("readOnlyHint").is_none());
}

#[test]
fn m3b_verb_surface_announces_a_drift_exactly_once() {
    let surface = VerbSurface::new();
    let first_hash = requestable_verb_hash(&m3b_catalog_frame());
    assert!(!surface.should_announce(first_hash));
    surface.note_served(first_hash);
    assert!(!surface.should_announce(first_hash));

    let mut grown = m3b_catalog_frame();
    grown["catalog"].as_array_mut().unwrap().push(json!({
        "provider": "github", "action": "read_tree",
        "fields": [], "execution_targets": [], "requestable": true,
        "shape": "http_api_call",
        "response": {"returns": "verbatim", "retention": "full", "errors": "status_and_body"}
    }));
    let second_hash = requestable_verb_hash(&grown);
    assert_ne!(first_hash, second_hash);
    assert!(surface.should_announce(second_hash));
    assert!(!surface.should_announce(second_hash));
    surface.note_served(second_hash);
    assert!(!surface.should_announce(second_hash));
}

/// EVERY vendored catalog field type must have an explicit, admission-agreeing schema
/// projection. A new structured type (or a typo'd one) fails here before it can
/// ship a tool whose advertised schema the daemon refuses.
#[test]
fn every_catalog_field_type_projects_explicitly() {
    let registry = cermet_core::templates::TemplateRegistry::new();
    for document in cermet_core::templates::VENDORED_CATALOG {
        registry.load(document).unwrap();
    }
    let catalog =
        serde_json::to_value(cermet_core::templates::catalog_of(&registry, true)).unwrap();
    let frame = json!({ "kind": "catalog", "catalog": catalog });
    let tools = generated_verb_tools(&frame);
    let mut checked_fields = 0usize;
    for entry in catalog.as_array().unwrap() {
        let provider = entry["provider"].as_str().unwrap();
        let action = entry["action"].as_str().unwrap();
        let tool_name = format!("{provider}-{action}");
        let tool = tools.iter().find(|tool| tool["name"] == tool_name);
        for field in entry["fields"].as_array().unwrap() {
            if field["origin"] != json!("agent_request") {
                continue;
            }
            let fname = field["name"].as_str().unwrap();
            // The exhaustive projection map. An unlisted catalog type is a FAILURE, not a
            // default: give it an explicit projection + admission mapping before shipping.
            let declared = field["type"].as_str().unwrap();
            let expected = match declared {
                "str" => "string",
                "int" => "integer",
                "bool" => "boolean",
                "change_list" => "array",
                other => panic!(
                    "{provider}.{action} field {fname}: catalog type `{other}` has no explicit \
                     schema projection — map it before it ships a broken tool"
                ),
            };
            let Some(tool) = tool else {
                // Suppressed tools (reserved-name collisions etc.) expose no schema to check.
                continue;
            };
            let projected = &tool["inputSchema"]["properties"][fname]["type"];
            assert_eq!(
                projected,
                &json!(expected),
                "{provider}.{action} field {fname}: declared `{declared}` but advertised \
                 {projected} — a conforming client will send what admission refuses"
            );
            checked_fields += 1;
        }
    }
    assert!(
        checked_fields > 20,
        "the vendored catalog conformance sweep went hollow ({checked_fields} fields)"
    );
}

/// A pre-authority refusal (admission/canonicalization — the wire carries NO
/// `authority_kind`) is a correctable input problem. Rendering it with the sentence-deny
/// "do not retry" finality tells a cooperative model to give up instead of fixing its input.
#[test]
fn pre_authority_refusal_renders_as_correctable() {
    let generated = Arc::new(VerbCallFake {
        request_reply: json!({
            "kind": "requested", "request_id": "rq-invalid", "decision": "deny",
            "reason": "invalid input: change_list field `changes`: must be a JSON array, got a string"
        }),
        execute_reply: Value::Null,
        calls: Arc::new(Mutex::new(Vec::new())),
    });
    let supervisor = Arc::new(RunSupervisor::new(4, 16));
    let (content, is_error) = tool_verb_call(
        &generated,
        &supervisor,
        "github-push_commit",
        &json!({ "justification": "test refusal rendering" }),
    );
    assert!(is_error);
    let text = content[0]["text"].as_str().unwrap();
    assert!(text.contains("rq-invalid"), "request_id survives: {text}");
    assert!(
        text.contains("invalid input"),
        "the admission reason survives: {text}"
    );
    assert!(
        !text.contains("do not retry"),
        "an input-shape refusal must not carry sentence-deny finality: {text}"
    );
    assert!(
        text.contains("corrected request") || text.contains("correct the request"),
        "the render must invite a corrected re-request: {text}"
    );

    // The sentence deny keeps its finality untouched.
    let sentence = Arc::new(VerbCallFake {
        request_reply: json!({
            "kind": "requested", "request_id": "rq-final", "decision": "deny",
            "reason": "outside sentence", "authority_kind": "sentence"
        }),
        execute_reply: Value::Null,
        calls: Arc::new(Mutex::new(Vec::new())),
    });
    let (content, is_error) = tool_verb_call(
        &sentence,
        &supervisor,
        "github-push_commit",
        &json!({ "justification": "test refusal rendering" }),
    );
    assert!(is_error);
    let text = content[0]["text"].as_str().unwrap();
    assert!(text.contains("Denied by sentence authority"));
    assert!(
        text.contains("do not retry"),
        "sentence denies stay final: {text}"
    );
}

/// A relay verb's tool description must not promise that the tool "runs it and returns the
/// redacted receipt". It does not: it authorizes and mints a single-use RELAY SESSION, and the
/// CALLER then runs the printed invocation with the native CLI. An agent that reads the wrong
/// promise is surprised at the moment of use — and stuck if it has no such binary installed. The
/// description says what actually happens; the shipped `vercel.deploy` is the case.
#[test]
fn a_relay_verb_describes_the_bridging_the_caller_has_to_do() {
    let registry = cermet_core::templates::TemplateRegistry::new();
    for document in cermet_core::templates::VENDORED_CATALOG {
        registry.load(document).unwrap();
    }
    let catalog =
        serde_json::to_value(cermet_core::templates::catalog_of(&registry, true)).unwrap();
    let frame = json!({ "kind": "catalog", "catalog": catalog });
    let tools = generated_verb_tools(&frame);

    let relay = tools
        .iter()
        .find(|tool| tool["name"] == json!("vercel-deploy"))
        .expect("the shipped relay verb generates a tool");
    let text = relay["description"].as_str().unwrap();
    for phrase in ["relay session", "native", "installed"] {
        assert!(
            text.contains(phrase),
            "a relay tool description must say {phrase:?}: {text}"
        );
    }
    assert!(
        !text.contains("runs it, returning"),
        "...and must not claim the broker runs the effect itself: {text}"
    );

    // A verb the broker really does execute keeps the run-it-and-return-the-receipt description.
    let http = tools
        .iter()
        .find(|tool| tool["name"] == json!("github-read_repo"))
        .expect("an http verb generates a tool");
    let http_text = http["description"].as_str().unwrap();
    assert!(http_text.contains("runs it, returning"), "{http_text}");
    assert!(!http_text.contains("relay session"), "{http_text}");
}

// ---- build identity on the agent wire -----------------------------------------------------------

/// A `WireOps` fake whose daemon advertises `build` — the seam a long-lived MCP session compares
/// itself against.
struct BuildWire(&'static str);
impl WireOps for BuildWire {
    fn hello(&self) -> Result<SessionHello, AgentError> {
        Ok(SessionHello {
            session_id: "sess_1".into(),
            features: vec![],
            build: self.0.to_string(),
        })
    }
    fn call_with_session(&self, _cmd: &AgentCommand, _s: &str) -> Result<Value, AgentError> {
        Ok(json!({ "kind": "catalog" }))
    }
}

#[test]
fn a_daemon_on_this_build_owes_the_agent_no_note() {
    let cache = SessionCache::new();
    cache
        .ensure(&BuildWire(cermet_ipc::BUILD_ID))
        .expect("hello");
    assert_eq!(
        cache.take_build_skew_note(),
        None,
        "same build, nothing to say"
    );
}

#[test]
fn a_skewed_daemon_owes_the_agent_exactly_one_note() {
    let cache = SessionCache::new();
    cache.ensure(&BuildWire("0.0.1+deadbeef")).expect("hello");
    let note = cache.take_build_skew_note().expect("a skew is noted");
    assert!(note.contains("0.0.1+deadbeef"), "names the daemon: {note}");
    assert!(note.contains(cermet_ipc::BUILD_ID), "and us: {note}");
    assert!(
        note.contains("restart"),
        "and what the agent should do: {note}"
    );
    assert_eq!(
        cache.take_build_skew_note(),
        None,
        "the note is owed ONCE — every later tool result is unpolluted"
    );
}

#[test]
fn a_daemon_predating_the_field_reads_as_unknown_never_as_a_match() {
    let cache = SessionCache::new();
    cache.ensure(&BuildWire("")).expect("hello");
    let note = cache.take_build_skew_note().expect("absence is still skew");
    assert!(note.contains("unknown"), "{note}");
}

/// A transport that owes one in-band note, so the DISPATCH side is testable without a socket.
struct NotingTransport(Mutex<Option<String>>);
impl AgentTransport for NotingTransport {
    fn call(&self, _cmd: &AgentCommand) -> Result<Value, AgentError> {
        Ok(json!({ "kind": "credentials", "credentials": [] }))
    }
    fn take_build_skew_note(&self) -> Option<String> {
        self.0.lock().unwrap().take()
    }
}

#[test]
fn the_skew_note_reaches_the_agent_in_band_on_the_first_tool_result() {
    let t = NotingTransport(Mutex::new(Some("BUILD SKEW: restart me".to_string())));
    let call = tools_call("list_connected_providers", json!({}));

    let first = handle_message(&t, &call).expect("tools/call replies");
    let (content, is_error) = call_result(&first);
    assert!(!is_error, "a note never turns a good result into an error");
    assert_eq!(
        first_text(content),
        "BUILD SKEW: restart me",
        "the note leads the first result the agent reads"
    );
    assert_eq!(
        content.as_array().expect("content array").len(),
        2,
        "the real result is still there, after the note"
    );

    let second = handle_message(&t, &call).expect("tools/call replies");
    let (content, _) = call_result(&second);
    assert_eq!(
        content.as_array().expect("content array").len(),
        1,
        "the note is not repeated on every later call"
    );
}

// ---- request_vocabulary: the VOCABULARY-gap channel (never the authority one) -------------------

/// A transport that answers Catalog with the fixture and RECORDS every vocabulary-request op it is
/// asked to send, so a test can assert what the daemon would have seen.
struct RecordingTransport {
    seen: Mutex<Vec<AgentCommand>>,
    daemon_up: bool,
}

impl RecordingTransport {
    fn new(daemon_up: bool) -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
            daemon_up,
        }
    }
    fn recorded(&self) -> Vec<AgentCommand> {
        self.seen.lock().expect("lock").clone()
    }
}

impl AgentTransport for RecordingTransport {
    fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
        match cmd {
            AgentCommand::Catalog => Ok(m3b_catalog_frame()),
            AgentCommand::RecordVocabularyRequest { .. } => {
                self.seen.lock().expect("lock").push(cmd.clone());
                if self.daemon_up {
                    Ok(json!({ "kind": "vocabulary_request_recorded" }))
                } else {
                    Err(AgentError::Transport("socket gone".into()))
                }
            }
            other => panic!("unexpected op {other:?}"),
        }
    }
}

fn vocab_args() -> Value {
    json!({
        "provider": "stripe", "verb": "list_disputes",
        "ask": "settle a dispute we lost", "rationale": "weekly finance reconciliation"
    })
}

/// `tools/list` must teach the distinction on the tool itself — an agent reads the description and
/// nothing else, and a tool that reads like "ask for permission here" would collect misfiled
/// authority asks forever.
#[test]
fn request_vocabulary_teaches_the_two_gaps_in_its_description() {
    let t = fixed(Value::Null);
    let msg = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
    let resp = handle_message(&t, &msg).expect("tools/list replies");
    let tool = resp["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == json!("request_vocabulary"))
        .expect("request_vocabulary is registered")
        .to_string();
    assert!(tool.contains("DOES NOT EXIST"), "{tool}");
    assert!(tool.contains("widening suggestion"), "{tool}");
    assert!(tool.contains("OPERATOR"), "{tool}");
    // It stores nothing locally and sends nothing anywhere; both must be said, not implied.
    assert!(tool.contains("nothing is stored"), "{tool}");
    assert!(tool.contains("nothing is sent"), "{tool}");
    // It authorizes nothing, so it must never be annotated as read-only either.
    assert!(!tool.contains("readOnlyHint"), "{tool}");
}

#[test]
fn request_vocabulary_returns_the_formed_request_for_an_absent_verb() {
    let t = RecordingTransport::new(true);
    let (content, is_error) = tool_request_vocabulary(&t, &vocab_args());
    assert!(!is_error, "an absent verb is a vocabulary gap");
    let content = Value::Array(content);
    let text = first_text(&content);
    assert!(text.contains("--- vocabulary request ---"), "{text}");
    assert!(text.contains("provider: stripe"), "{text}");
    assert!(text.contains("Give this block to your operator"), "{text}");
    // THE STRIP: the block says nothing is sent, with no future transport promised.
    assert!(
        text.contains("nothing is \n         sent anywhere")
            || text.contains("nothing is sent anywhere"),
        "{text}"
    );
    assert!(
        text.contains("Your operator's log has this request"),
        "{text}"
    );

    // The daemon saw the event, classified as the vocabulary gap, carrying the scrubbed text.
    match t.recorded().as_slice() {
        [AgentCommand::RecordVocabularyRequest {
            provider,
            wanted_verb,
            gap,
            rationale,
            ..
        }] => {
            assert_eq!(provider, "stripe");
            assert_eq!(wanted_verb.as_deref(), Some("list_disputes"));
            assert_eq!(gap, "vocabulary_gap");
            assert_eq!(rationale.as_deref(), Some("weekly finance reconciliation"));
        }
        other => panic!("expected exactly one recorded event, got {other:?}"),
    }
}

/// A refused authority-gap probe is signal too: the agent gets the teach, and the daemon still gets
/// a row saying an agent could not tell the two walls apart.
#[test]
fn request_vocabulary_refuses_a_verb_that_exists_and_still_records_the_probe() {
    let t = RecordingTransport::new(true);
    let (content, is_error) = tool_request_vocabulary(
        &t,
        &json!({ "provider": "github", "verb": "read_repo", "ask": "read the repo" }),
    );
    assert!(is_error, "an existing verb is an authority gap");
    let content = Value::Array(content);
    let text = first_text(&content);
    assert!(text.contains("already EXISTS"), "{text}");
    // The refusal must not read like a filed feature request.
    assert!(!text.contains("--- vocabulary request ---"), "{text}");
    // The row is a NOTE about the probe, never a filed feature request.
    assert!(text.contains("not a feature request"), "{text}");
    match t.recorded().as_slice() {
        [AgentCommand::RecordVocabularyRequest { gap, .. }] => assert_eq!(gap, "authority_gap"),
        other => panic!("the refused probe must still be recorded, got {other:?}"),
    }
}

#[test]
fn request_vocabulary_refuses_credential_shaped_text_without_recording_anything() {
    let t = RecordingTransport::new(true);
    let (content, is_error) = tool_request_vocabulary(
        &t,
        &json!({
            "provider": "stripe", "verb": "list_disputes",
            "ask": "curl -H 'Authorization: Bearer sk_live_51H8xQeJk2mLpQrStUvWx'"
        }),
    );
    assert!(is_error);
    let content = Value::Array(content);
    assert!(first_text(&content).contains("credential-shaped"));
    assert!(
        t.recorded().is_empty(),
        "credential-shaped text must never reach the daemon"
    );
}

#[test]
fn request_vocabulary_fails_closed_on_malformed_input() {
    let t = RecordingTransport::new(true);
    // No provider at all: fail closed with the missing field named.
    let (content, is_error) = tool_request_vocabulary(&t, &json!({ "verb": "x" }));
    assert!(is_error);
    let content = Value::Array(content);
    assert!(first_text(&content).contains("provider"));

    // Neither a verb nor a field: nothing to check.
    let (_, is_error) = tool_request_vocabulary(&t, &json!({ "provider": "stripe" }));
    assert!(is_error);
    assert!(t.recorded().is_empty());
}

/// Fail closed on the dictionary: with the catalog unreadable there is no way to tell the two gaps
/// apart, so nothing is classified and nothing is recorded.
#[test]
fn request_vocabulary_refuses_when_the_catalog_is_unreadable() {
    let t = FakeTransport(|_: &AgentCommand| Err(AgentError::Transport("socket gone".into())));
    let (content, is_error) = tool_request_vocabulary(
        &t,
        &json!({ "provider": "stripe", "verb": "list_disputes" }),
    );
    assert!(is_error);
    let content = Value::Array(content);
    assert!(first_text(&content).contains("unreadable"));
}

/// Fail OPEN on the relay, CLOSED on the claim: an unreachable daemon still gets the agent its
/// formed request, and the response never says "recorded" when no row exists.
#[test]
fn request_vocabulary_never_claims_a_row_it_did_not_get() {
    let t = RecordingTransport::new(false);
    let (content, is_error) = tool_request_vocabulary(&t, &vocab_args());
    assert!(!is_error, "the relay still works with the daemon down");
    let content = Value::Array(content);
    let text = first_text(&content);
    assert!(text.contains("--- vocabulary request ---"), "{text}");
    assert!(text.contains("did not record"), "{text}");
    assert!(!text.contains("Your operator's log has this"), "{text}");
}
