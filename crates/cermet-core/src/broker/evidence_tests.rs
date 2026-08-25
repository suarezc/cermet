use super::*;

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::contract::Scalar;
use crate::evidence::{EvidenceSource, ResolvedEvidence};
use crate::mutation_success::EffectProof;
use crate::provider::{ProviderResponse, RetainedBody};
use crate::types::{EffectFailureClass, EffectOutcome};

const EVIDENCE_TEMPLATE: &str = r#"
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
  - { name: mode, type: str, required: true, class: identity, binding: exact_resource_pin, format: git_branch_name }
consumes: [charge, amount, account, currency, mode]
execution_targets: [charge, account, currency, mode]
http:
  steps:
    - id: mutate
      method: POST
      path: /v1/test_evidence/{charge}
      body_encoding: form
      body: { amount: "{amount}", account: "{account}", currency: "{currency}", mode: "{mode}" }
      success_statuses: [200]
      require: [id, object, amount, account, currency, livemode]
      expect_eq: { id: charge, amount: amount, account: account, currency: currency }
      expect_literal: { object: charge, livemode: false }
      retention: none
"#;

const ALLOW_EXACT: &str = "allow stripe.test_charge_evidence where charge = \"ch_ok\" and amount <= 5000 and account = \"acct_test\" and currency = \"usd\" and mode = \"test\"";
const TOKEN: &str = "sk_test_M1_TOKEN_CANARY";

struct StaticAuthority(crate::sentence::RuleSet);

impl SentenceAuthoritySource for StaticAuthority {
    fn current_authority(&self) -> Result<AuthenticatedSentenceAuthority> {
        Ok(AuthenticatedSentenceAuthority {
            digest: crate::sentence::authority_digest(&self.0),
            rules: self.0.clone(),
        })
    }
}

struct ChangingAuthority {
    first: crate::sentence::RuleSet,
    second: crate::sentence::RuleSet,
    calls: AtomicUsize,
}

struct MutableAuthority(Mutex<crate::sentence::RuleSet>);

impl MutableAuthority {
    fn set(&self, rules: &str) {
        *self.0.lock().unwrap() = crate::sentence::parse_rules(rules).unwrap();
    }
}

impl SentenceAuthoritySource for MutableAuthority {
    fn current_authority(&self) -> Result<AuthenticatedSentenceAuthority> {
        let rules = self.0.lock().unwrap().clone();
        Ok(AuthenticatedSentenceAuthority {
            digest: crate::sentence::authority_digest(&rules),
            rules,
        })
    }
}

impl SentenceAuthoritySource for ChangingAuthority {
    fn current_authority(&self) -> Result<AuthenticatedSentenceAuthority> {
        let rules = if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            &self.first
        } else {
            &self.second
        };
        Ok(AuthenticatedSentenceAuthority {
            digest: crate::sentence::authority_digest(rules),
            rules: rules.clone(),
        })
    }
}

#[derive(Clone)]
struct Probe {
    evidence_result: Arc<Mutex<std::result::Result<ResolvedEvidence, EvidenceFailure>>>,
    resolve_calls: Arc<AtomicUsize>,
    precondition_calls: Arc<AtomicUsize>,
    execute_calls: Arc<AtomicUsize>,
    idempotency_keys: Arc<Mutex<Vec<String>>>,
    execute_error: Arc<AtomicBool>,
    /// The money call fails with an error the SEAM itself typed — what the real HTTP seam does when
    /// it can tell "nothing was written to the wire" from "bytes went out and nothing came back".
    execute_error_class: Arc<Mutex<Option<crate::types::EffectFailureClass>>>,
    ambiguous_response: Arc<AtomicBool>,
    definitely_failed_response: Arc<AtomicBool>,
    retained_success_response: Arc<AtomicBool>,
    ambiguous_status: Arc<AtomicU16>,
    precondition_failure: Arc<Mutex<Option<crate::preconditions::PreconditionFailureClass>>>,
}

struct EvidenceProvider {
    contract: &'static ActionContract,
    probe: Probe,
}

impl Provider for EvidenceProvider {
    // A stripe stand-in models the same credential-decided field the shipped descriptor declares.
    fn credential_mode_field(&self) -> Option<&str> {
        crate::provider::vendored_credential_mode("stripe").map(|mode| mode.field.as_str())
    }
    fn credential_mode(&self, token: &str) -> Option<&str> {
        crate::provider::vendored_credential_mode("stripe").and_then(|mode| mode.of(token))
    }

    fn name(&self) -> &str {
        "stripe"
    }

    fn supported_actions(&self) -> &'static [&'static str] {
        &["test_charge_evidence"]
    }

    fn action_contract(&self, action: &str) -> Option<&'static ActionContract> {
        (action == "test_charge_evidence").then_some(self.contract)
    }

    fn is_money_action(&self, action: &str) -> bool {
        action == "test_charge_evidence"
    }

    fn resolve_request(
        &self,
        _profile: &'static EvidenceProfile,
        token: &str,
        _partial: &CanonicalResource,
    ) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
        assert_eq!(token, TOKEN);
        self.probe.resolve_calls.fetch_add(1, Ordering::SeqCst);
        self.probe.evidence_result.lock().unwrap().clone()
    }

    fn check_preconditions(
        &self,
        preconditions: &[&'static crate::preconditions::CompiledPrecondition],
        token: &str,
        resource: &CanonicalResource,
    ) -> std::result::Result<(), crate::preconditions::PreconditionFailure> {
        assert_eq!(token, TOKEN);
        assert_eq!(
            preconditions
                .iter()
                .map(|precondition| precondition.name)
                .collect::<Vec<_>>(),
            ["test_charge_ready"]
        );
        assert_eq!(resource.req_i64("amount").unwrap(), 2300);
        self.probe.precondition_calls.fetch_add(1, Ordering::SeqCst);
        match *self.probe.precondition_failure.lock().unwrap() {
            Some(class) => Err(crate::preconditions::PreconditionFailure::new(
                "test_charge_ready",
                class,
            )),
            None => Ok(()),
        }
    }

    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        assert_eq!(call.token, TOKEN);
        // ONE seam. The discipline arrives as data — this double asserts the broker handed it the
        // persisted key and the proving bit for this verb, and refuses if it did not.
        let idempotency_key = call
            .discipline
            .idempotency_key
            .expect("the broker passes this verb's persisted idempotency key");
        assert!(call.discipline.prove_effect);
        assert!(idempotency_key.starts_with("cermet_"));
        assert_eq!(idempotency_key.len(), 71);
        self.probe
            .idempotency_keys
            .lock()
            .unwrap()
            .push(idempotency_key.to_string());
        assert_eq!(call.resource.req_str("account")?, "acct_test");
        assert_eq!(call.resource.req_str("currency")?, "usd");
        assert_eq!(call.resource.req_str("mode")?, "test");
        self.probe.execute_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(class) = *self.probe.execute_error_class.lock().unwrap() {
            return Err(Error::ProviderFailed(
                class,
                format!("the seam typed this one: {idempotency_key}"),
            ));
        }
        if self.probe.execute_error.load(Ordering::SeqCst) {
            return Err(Error::Provider("no response to the keyed request".into()));
        }
        if self.probe.ambiguous_response.load(Ordering::SeqCst) {
            return Ok(ProviderResponse {
                proof: None,
                ok: true,
                failure_class: None,
                result: json!({"unproved_projection":"UNPROVED_PROJECTED_CANARY"}),
                retained: Some(RetainedBody {
                    bytes: b"UNPROVED_RAW_BODY_CANARY".to_vec(),
                    total_bytes: 25,
                }),
                envelope: Default::default(),
            }
            .proved(EffectProof::Unproved));
        }
        if self.probe.definitely_failed_response.load(Ordering::SeqCst) {
            return Ok(ProviderResponse {
                proof: None,
                ok: true,
                failure_class: None,
                result: json!({"provider_error":"declined"}),
                retained: None,
                envelope: Default::default(),
            }
            .proved(EffectProof::Refused));
        }
        let status = self.probe.ambiguous_status.load(Ordering::SeqCst);
        if status != 0 {
            return Ok(ProviderResponse {
                proof: None,
                ok: false,
                failure_class: None,
                result: json!({"status": status}),
                retained: None,
                envelope: Default::default(),
            }
            .proved(EffectProof::Unproved));
        }
        if self.probe.retained_success_response.load(Ordering::SeqCst) {
            return Ok(ProviderResponse {
                proof: None,
                // The compiled proof, not this provider-controlled bit, owns classification.
                ok: false,
                failure_class: None,
                result: json!({"raw_success_canary":"MONEY_SUCCESS_PROJECTION_CANARY"}),
                retained: Some(RetainedBody {
                    bytes: b"MONEY_SUCCESS_RAW_BODY_CANARY".to_vec(),
                    total_bytes: 29,
                }),
                envelope: Default::default(),
            }
            .proved(EffectProof::Proved));
        }
        Ok(ProviderResponse {
            proof: None,
            ok: true,
            failure_class: None,
            result: json!({"id":"result_1", "provider_echo":idempotency_key}),
            retained: None,
            envelope: Default::default(),
        }
        .proved(EffectProof::Proved))
    }
}

#[derive(Clone)]
struct CompiledContractProbe {
    response: Arc<Mutex<Vec<u8>>>,
    idempotency_keys: Arc<Mutex<Vec<String>>>,
}

struct CompiledContractProvider {
    action: &'static str,
    contract: &'static ActionContract,
    probe: CompiledContractProbe,
}

impl Provider for CompiledContractProvider {
    // A stripe stand-in models the same credential-decided field the shipped descriptor declares.
    fn credential_mode_field(&self) -> Option<&str> {
        crate::provider::vendored_credential_mode("stripe").map(|mode| mode.field.as_str())
    }
    fn credential_mode(&self, token: &str) -> Option<&str> {
        crate::provider::vendored_credential_mode("stripe").and_then(|mode| mode.of(token))
    }

    fn name(&self) -> &str {
        "stripe"
    }

    fn supported_actions(&self) -> &'static [&'static str] {
        &[]
    }

    fn supports_action(&self, action: &str) -> bool {
        action == self.action
    }

    fn is_money_action(&self, action: &str) -> bool {
        action == self.action
    }

    fn action_contract(&self, action: &str) -> Option<&'static ActionContract> {
        (action == self.action).then_some(self.contract)
    }

    fn resolve_request(
        &self,
        profile: &'static EvidenceProfile,
        token: &str,
        partial: &CanonicalResource,
    ) -> std::result::Result<ResolvedEvidence, EvidenceFailure> {
        assert_eq!(token, TOKEN);
        assert_eq!(profile.action, self.action);
        let fields = profile
            .outputs
            .iter()
            .map(|output| {
                let value = match output.field {
                    "account" => Scalar::Str("acct_1".into()),
                    "mode" => Scalar::Str("test".into()),
                    "currency" => Scalar::Str("usd".into()),
                    "customer" => Scalar::Str("cus_1".into()),
                    "amount" => Scalar::Int(if self.action == "retry_invoice_payment" {
                        700
                    } else {
                        500
                    }),
                    "status" => Scalar::Str(
                        match self.action {
                            "retry_invoice_payment" => "open",
                            "confirm_payment_intent" => "requires_confirmation",
                            "capture_payment_intent" => "requires_capture",
                            _ => unreachable!("unexpected resolved status"),
                        }
                        .into(),
                    ),
                    "capture_method" => Scalar::Str(
                        if self.action == "capture_payment_intent" {
                            "manual"
                        } else {
                            "automatic"
                        }
                        .into(),
                    ),
                    "confirmation_method" => Scalar::Str("automatic".into()),
                    "intent_amount" => Scalar::Int(900),
                    "amount_capturable" => Scalar::Int(600),
                    field => unreachable!("unexpected evidence output {field}"),
                };
                (output.field.to_string(), value)
            })
            .collect();
        let sources = profile
            .sources
            .iter()
            .map(|source| EvidenceSource {
                kind: source.kind.to_string(),
                id: partial.req_str(source.id_field).unwrap().to_string(),
            })
            .collect();
        Ok(ResolvedEvidence { fields, sources })
    }

    fn check_preconditions(
        &self,
        preconditions: &[&'static crate::preconditions::CompiledPrecondition],
        token: &str,
        _resource: &CanonicalResource,
    ) -> std::result::Result<(), crate::preconditions::PreconditionFailure> {
        assert_eq!(token, TOKEN);
        assert!(preconditions
            .iter()
            .all(|precondition| precondition.action == self.action));
        Ok(())
    }

    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        assert_eq!(call.action, self.action);
        assert_eq!(call.token, TOKEN);
        assert!(call.discipline.prove_effect);
        let idempotency_key = call
            .discipline
            .idempotency_key
            .expect("the broker passes this verb's persisted idempotency key");
        self.probe
            .idempotency_keys
            .lock()
            .unwrap()
            .push(idempotency_key.to_string());
        let bytes = self.probe.response.lock().unwrap().clone();
        let contract = crate::mutation_success::exact("stripe", self.action).unwrap();
        let (body, observed) = match contract.evaluate_raw(200, &bytes, call.resource) {
            Ok(observed) => observed,
            Err(_) => {
                return Ok(ProviderResponse {
                    proof: None,
                    ok: false,
                    failure_class: None,
                    result: Value::Null,
                    retained: None,
                    envelope: Default::default(),
                }
                .proved(EffectProof::Unproved));
            }
        };
        let proved = observed == EffectProof::Proved;
        Ok(ProviderResponse {
            proof: None,
            // Deliberately model an HTTP 200. The compiled proof, not this transport bit, owns success.
            ok: true,
            failure_class: None,
            result: if proved {
                json!({"id": body["id"]})
            } else {
                json!({"unproved_projection":"UNPROVED_PROJECTED_CANARY"})
            },
            retained: (!proved).then_some(RetainedBody {
                total_bytes: bytes.len() as u64,
                bytes,
            }),
            envelope: Default::default(),
        }
        .proved(observed))
    }
}

struct CompiledContractCase {
    name: &'static str,
    action: &'static str,
    rule: &'static str,
    request: Value,
    invalid: &'static str,
    valid: &'static str,
}

fn compiled_contract_broker(case: &CompiledContractCase) -> (TestBroker, CompiledContractProbe) {
    let template = crate::templates::VENDORED_CATALOG
        .iter()
        .copied()
        .find(|document| {
            document.contains("provider: stripe\n")
                && document.contains(&format!("action: {}\n", case.action))
        })
        .unwrap();
    let rules = crate::sentence::parse_rules(case.rule).unwrap();
    let (guard, dir) = fresh_broker_dir();
    let mut broker = Broker::open_with_sentence_authority(
        BrokerConfig {
            git: crate::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
            dir,
            master_key: vec![5u8; 32],
            action_templates: vec![template.to_string()],
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        Arc::new(StaticAuthority(rules)),
    )
    .unwrap();
    broker.connect_credential("stripe", None, TOKEN).unwrap();
    let contract = broker.templates.resolve("stripe", case.action).unwrap();
    let probe = CompiledContractProbe {
        response: Arc::new(Mutex::new(case.invalid.as_bytes().to_vec())),
        idempotency_keys: Arc::new(Mutex::new(Vec::new())),
    };
    broker.providers.insert(
        "stripe".into(),
        Box::new(CompiledContractProvider {
            action: case.action,
            contract,
            probe: probe.clone(),
        }),
    );
    (TestBroker::new(guard, broker), probe)
}

fn good_evidence() -> ResolvedEvidence {
    ResolvedEvidence {
        fields: BTreeMap::from([
            ("account".to_string(), Scalar::Str("acct_test".into())),
            ("currency".to_string(), Scalar::Str("usd".into())),
            ("mode".to_string(), Scalar::Str("test".into())),
        ]),
        sources: vec![EvidenceSource {
            kind: "stripe.charge".into(),
            id: "ch_ok".into(),
        }],
    }
}

fn request(resource: Value) -> CapabilityRequest {
    CapabilityRequest {
        provider: "stripe".into(),
        action: "test_charge_evidence".into(),
        resource,
        environment: None,
        justification: Some("mechanism proof".into()),
        model: None,
    }
}

fn broker_with(
    rules: &str,
    result: std::result::Result<ResolvedEvidence, EvidenceFailure>,
    connect: bool,
) -> (TestBroker, Probe) {
    broker_with_precondition(rules, result, connect, None)
}

fn broker_with_precondition(
    rules: &str,
    result: std::result::Result<ResolvedEvidence, EvidenceFailure>,
    connect: bool,
    precondition_failure: Option<crate::preconditions::PreconditionFailureClass>,
) -> (TestBroker, Probe) {
    let rules = crate::sentence::parse_rules(rules).unwrap();
    broker_with_authority_and_precondition(
        Arc::new(StaticAuthority(rules)),
        result,
        connect,
        precondition_failure,
    )
}

fn broker_with_authority(
    authority: Arc<dyn SentenceAuthoritySource>,
    result: std::result::Result<ResolvedEvidence, EvidenceFailure>,
    connect: bool,
) -> (TestBroker, Probe) {
    broker_with_authority_and_precondition(authority, result, connect, None)
}

fn broker_with_authority_and_precondition(
    authority: Arc<dyn SentenceAuthoritySource>,
    result: std::result::Result<ResolvedEvidence, EvidenceFailure>,
    connect: bool,
    precondition_failure: Option<crate::preconditions::PreconditionFailureClass>,
) -> (TestBroker, Probe) {
    let (guard, dir) = fresh_broker_dir();
    let mut broker = Broker::open_with_sentence_authority(
        BrokerConfig {
            git: crate::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
            dir,
            master_key: vec![5u8; 32],
            action_templates: vec![EVIDENCE_TEMPLATE.to_string()],
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        authority,
    )
    .unwrap();
    if connect {
        broker.connect_credential("stripe", None, TOKEN).unwrap();
    }
    let contract = broker
        .templates
        .resolve("stripe", "test_charge_evidence")
        .unwrap();
    let probe = Probe {
        evidence_result: Arc::new(Mutex::new(result)),
        resolve_calls: Arc::new(AtomicUsize::new(0)),
        precondition_calls: Arc::new(AtomicUsize::new(0)),
        execute_calls: Arc::new(AtomicUsize::new(0)),
        idempotency_keys: Arc::new(Mutex::new(Vec::new())),
        execute_error: Arc::new(AtomicBool::new(false)),
        execute_error_class: Arc::new(Mutex::new(None)),
        ambiguous_response: Arc::new(AtomicBool::new(false)),
        definitely_failed_response: Arc::new(AtomicBool::new(false)),
        retained_success_response: Arc::new(AtomicBool::new(false)),
        ambiguous_status: Arc::new(AtomicU16::new(0)),
        precondition_failure: Arc::new(Mutex::new(precondition_failure)),
    };
    broker.providers.insert(
        "stripe".into(),
        Box::new(EvidenceProvider {
            contract,
            probe: probe.clone(),
        }),
    );
    (TestBroker::new(guard, broker), probe)
}

fn event_data(broker: &Broker, event_type: &str) -> Vec<Value> {
    broker
        .audit
        .events_of_type(event_type)
        .unwrap()
        .into_iter()
        .map(|event| event.data)
        .collect()
}

fn ambiguous_parent(broker: &Broker, probe: &Probe, session: &str) -> RequestOutcome {
    let parent = broker
        .request_capability(session, request(json!({"charge":"ch_ok","amount":2300})))
        .unwrap();
    probe.execute_error.store(true, Ordering::SeqCst);
    assert!(broker
        .execute_capability(parent.grant_id.as_deref().unwrap())
        .is_err());
    probe.execute_error.store(false, Ordering::SeqCst);
    parent
}

fn retry_effect_start_data(
    broker: &Broker,
    parent: &RequestOutcome,
    executing_session: &str,
) -> Value {
    let grant_id = parent.grant_id.as_deref().unwrap();
    let grant = broker.load_grant(grant_id).unwrap();
    let envelope = EvidenceEnvelope::from_canonical_json(&grant.evidence_json).unwrap();
    let EvidenceEnvelope::ProviderResolved(evidence) = envelope else {
        panic!("money test grant must carry provider-resolved evidence");
    };
    let resource: Value = serde_json::from_str(&grant.resource_json).unwrap();
    let provider_fields: Vec<String> = evidence.fields.keys().cloned().collect();
    let agent_fields: Vec<String> = resource
        .as_object()
        .unwrap()
        .keys()
        .filter(|field| !evidence.fields.contains_key(*field))
        .cloned()
        .collect();
    let mut data = json!({
        "grant_id": grant_id,
        "request_id": grant.request_id,
        "provider": grant.provider,
        "action": grant.action,
        "authority_digest": grant.policy_fingerprint,
        "resource": resource,
        "agent_request_fields": agent_fields,
        "provider_resolved_fields": provider_fields,
        "request_session": grant.session_id,
        "executing_session": executing_session,
        "evidence_receipt_id": evidence.receipt_id,
        "evidence_resolution_digest": evidence.resolution_digest,
        "effect_id": parent.effect_id,
    });
    data["resource_binding"] = json!(broker
        .effect_start_resource_binding(grant_id, &grant, &data["resource"])
        .unwrap());
    data
}

fn retry_ambiguous_terminal_data(
    broker: &Broker,
    parent: &RequestOutcome,
    executing_session: &str,
) -> Value {
    let grant = broker
        .load_grant(parent.grant_id.as_deref().unwrap())
        .unwrap();
    json!({
        "grant_id": parent.grant_id,
        "request_id": grant.request_id,
        "provider": grant.provider,
        "action": grant.action,
        "outcome": "error",
        "mutation_invoked": true,
        "error": "ambiguous fixture",
        "request_session": grant.session_id,
        "executing_session": executing_session,
        "effect_id": parent.effect_id,
        "effect_outcome": "ambiguous",
    })
}

fn assert_generic_retry_denial(broker: &Broker, outcome: &RequestOutcome) {
    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.reason, "provider evidence unavailable");
    assert!(outcome.grant_id.is_none());
    assert!(outcome.effect_id.is_none());
    assert!(outcome.hint.is_none());
    assert!(outcome.budget_exceeded.is_none());
    assert_eq!(
        broker
            .state
            .query_row("SELECT COUNT(*) FROM grants", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

fn denial_shape(outcome: &RequestOutcome) -> Value {
    json!({
        "decision": outcome.decision,
        "reason": outcome.reason,
        "budget_exceeded": outcome.budget_exceeded,
        "hint": outcome.hint,
        "grant_id": outcome.grant_id,
        "effect_id": outcome.effect_id,
        "authority_kind": outcome.authority_kind,
    })
}

#[test]
fn moneypath_every_ordinary_grant_carries_hmac_bound_none_evidence() {
    let rules =
        crate::sentence::parse_rules("allow stripe.get_charge where charge = \"ch_ordinary\"")
            .unwrap();
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker =
        Broker::open_with_sentence_authority(
            BrokerConfig {
                git: crate::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
                dir,
                master_key: vec![5u8; 32],
                action_templates: vec![
                    include_str!("../../actions/stripe.get_charge.yaml").to_string()
                ],
                provider_descriptors: BrokerConfig::vendored_descriptors(),
                artifacts: crate::artifacts::ArtifactConfig::default(),
            },
            Arc::new(StaticAuthority(rules)),
        )
        .unwrap();
    let outcome = broker
        .request_capability(
            "sess_m1_none",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_charge".into(),
                resource: json!({"charge":"ch_ordinary"}),
                ..Default::default()
            },
        )
        .unwrap();
    let grant_id = outcome.grant_id.unwrap();
    let grant = broker.load_grant(&grant_id).unwrap();
    assert_eq!(grant.evidence_json, r#"{"kind":"none","version":1}"#);
    assert_eq!(grant.money_json, r#"{"kind":"none","version":1}"#);
    broker
        .state
        .execute(
            "UPDATE grants SET evidence_json=?2 WHERE id=?1",
            rusqlite::params![grant_id, r#"{"kind":"none","version":2}"#],
        )
        .unwrap();
    let tampered = broker.load_grant(&grant_id).unwrap();
    assert!(broker.assert_grant_integrity(&grant_id, &tampered).is_err());
}

#[test]
fn moneypath_evidence_mints_complete_resource_and_audits_origins_without_secret_or_body() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let outcome = broker
        .request_capability("sess_m1", request(json!({"charge":"ch_ok","amount":2300})))
        .unwrap();
    assert_eq!(outcome.decision, Decision::Allow);
    assert_eq!(probe.resolve_calls.load(Ordering::SeqCst), 1);
    let grant_id = outcome.grant_id.unwrap();
    assert_eq!(
        outcome.effect_id.as_deref(),
        Some(
            crate::money::MoneyMetadata::from_canonical_json(
                &broker.load_grant(&grant_id).unwrap().money_json
            )
            .unwrap()
            .effect_id()
            .unwrap()
        )
    );
    let grant = broker.load_grant(&grant_id).unwrap();
    assert_eq!(
        grant.resource_json,
        r#"{"account":"acct_test","amount":2300,"charge":"ch_ok","currency":"usd","mode":"test"}"#
    );
    let envelope = EvidenceEnvelope::from_canonical_json(&grant.evidence_json).unwrap();
    let money = crate::money::MoneyMetadata::from_canonical_json(&grant.money_json).unwrap();
    assert!(money.is_money());
    assert_eq!(
        broker.list_grants("sess_m1").unwrap()[0].effect_id,
        outcome.effect_id
    );
    assert_eq!(
        broker
            .request_status(&outcome.request_id)
            .unwrap()
            .effect_id,
        outcome.effect_id
    );
    let EvidenceEnvelope::ProviderResolved(_) = envelope else {
        panic!("evidence-backed grant must carry a resolved envelope")
    };
    let envelope_value: Value = serde_json::from_str(&grant.evidence_json).unwrap();
    let profile = crate::evidence::profile("stripe.test_charge.v1").unwrap();
    assert_eq!(
        envelope_value["profile_fingerprint"],
        json!(profile.semantics_fingerprint())
    );

    let execution = broker.execute_capability(&grant_id).unwrap();
    assert_eq!(execution.effect_id, outcome.effect_id);
    assert_eq!(execution.effect_outcome, Some(EffectOutcome::Succeeded));
    assert_eq!(
        broker.list_grants("sess_m1").unwrap()[0].effect_outcome,
        Some(EffectOutcome::Succeeded)
    );
    assert!(
        !execution.result.is_null(),
        "a money receipt carries the verified body"
    );
    assert!(
        execution.artifact.is_none(),
        "the money retention cap holds"
    );
    assert!(execution.wire_stats.is_none());
    assert_eq!(probe.precondition_calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.execute_calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.idempotency_keys.lock().unwrap().len(), 1);
    let effects = event_data(&broker, "capability_effect_starting");
    assert_eq!(effects.len(), 1);
    assert_eq!(
        effects[0]["agent_request_fields"],
        json!(["amount", "charge"])
    );
    assert_eq!(
        effects[0]["provider_resolved_fields"],
        json!(["account", "currency", "mode"])
    );
    let audit = std::fs::read(broker.dir.join("audit.db")).unwrap();
    let audit = String::from_utf8_lossy(&audit);
    assert!(!audit.contains(TOKEN));
    assert!(!audit.contains("raw_body"));
    assert!(!audit.contains(money.idempotency_key().unwrap()));
}

#[test]
fn moneypath_precondition_denial_is_terminal_value_free_and_before_effect_start() {
    let rule = format!("{ALLOW_EXACT} and budget amount 5000 per day");
    let (broker, probe) = broker_with_precondition(
        &rule,
        Ok(good_evidence()),
        true,
        Some(crate::preconditions::PreconditionFailureClass::StateMismatch),
    );
    let outcome = broker
        .request_capability(
            "sess_m2_precondition",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = outcome.grant_id.unwrap();
    let error = broker.execute_capability(&grant_id).unwrap_err();
    assert_eq!(
        error.to_string(),
        "capability denied: money precondition unavailable"
    );
    assert_eq!(probe.precondition_calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.execute_calls.load(Ordering::SeqCst), 0);
    assert!(event_data(&broker, "capability_effect_starting").is_empty());
    let denials = event_data(&broker, "money_precondition_denied");
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0]["failure_class"], "state_mismatch");
    assert!(denials[0].get("resource").is_none());
    assert_eq!(event_data(&broker, "budget_release").len(), 1);
    assert_eq!(
        event_data(&broker, "provider_action_failed")[0]["mutation_invoked"],
        false
    );
    let status = broker.request_status(&outcome.request_id).unwrap();
    assert_eq!(status.effect_outcome, Some(EffectOutcome::PreEffect));
}

/// A money hop that got no answer records the OBSERVATION the seam typed, and says the same thing
/// to the agent: one class, one sentence derived from it.
///
/// The seam typed "nothing was written to the wire", so the record must not stamp the residual and
/// the agent must not be told to reconcile an effect that provably did not happen.
#[test]
fn a_money_hop_that_never_left_the_box_says_so_to_the_record_and_the_agent() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let outcome = broker
        .request_capability(
            "sess_m2_pre_send",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = outcome.grant_id.unwrap();
    *probe.execute_error_class.lock().unwrap() = Some(EffectFailureClass::TransportPreSend);

    let error = broker.execute_capability(&grant_id).unwrap_err();
    assert_eq!(
        error.effect_failure_class(),
        Some(EffectFailureClass::TransportPreSend),
        "the caller-facing error carries the class the record stores"
    );
    assert_eq!(
        error.to_string(),
        "provider error: the request never left this machine and the effect did not occur; \
         a new request is the retry path"
    );
    let failure = &event_data(&broker, "provider_action_failed")[0];
    assert_eq!(failure["failure_class"], "transport_pre_send");
    assert_eq!(failure["error"], error.to_string());
    // The prose side-channel is gone: the class IS the fact, recorded once.
    assert!(failure.get("transport_error").is_none());
    assert!(failure["attempted_at"].is_string());
}

/// The conservative direction. The adapter's error says nothing structural about whether the request
/// was written, so the record must NOT claim it never left — and must not fall back on the residual
/// either, which is what discarding the typed error used to produce here.
#[test]
fn an_untyped_money_call_failure_records_no_response_never_the_residual() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let outcome = broker
        .request_capability(
            "sess_m2_no_answer",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = outcome.grant_id.clone().unwrap();
    probe.execute_error.store(true, Ordering::SeqCst);

    let error = broker.execute_capability(&grant_id).unwrap_err();
    assert_eq!(
        error.effect_failure_class(),
        Some(EffectFailureClass::TransportNoResponse)
    );
    // The second half of the sentence names the EXISTING referenced-retry channel concretely, by
    // the effect handle the agent already holds.
    assert_eq!(
        error.to_string(),
        format!(
            "provider error: the request was sent and no response arrived, so whether the effect \
             landed is not yet determined; retry this exact effect with retry_effect={}, which \
             reuses its idempotency key, rather than making a fresh request",
            outcome.effect_id.as_deref().unwrap()
        )
    );
    let failure = &event_data(&broker, "provider_action_failed")[0];
    assert_eq!(failure["failure_class"], "transport_no_response");
    // The derived money bit stays exactly as the recovery machinery writes it; the observation
    // class now sits beside it as the authoritative fact.
    assert_eq!(failure["effect_outcome"], "ambiguous");
    assert_eq!(failure["mutation_invoked"], true);
    // Nothing about the adapter's own words reaches the agent or the record.
    assert!(!error.to_string().contains("cermet_"));
    assert!(!failure["error"].as_str().unwrap().contains("cermet_"));
}

#[test]
fn moneypath_retry_reuses_authenticated_effect_and_hidden_key_without_second_debit() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_m2_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let parent_id = parent.grant_id.clone().unwrap();
    let parent_money = crate::money::MoneyMetadata::from_canonical_json(
        &broker.load_grant(&parent_id).unwrap().money_json,
    )
    .unwrap();
    probe.execute_error.store(true, Ordering::SeqCst);
    let error = broker.execute_capability(&parent_id).unwrap_err();
    // The sentence is rendered from the CLASS alone (no adapter prose) and NAMES the existing
    // referenced-retry channel by the handle the agent already holds, instead of gesturing at
    // "the safe effect handle". One rendering, shared by the returned error and the durable
    // record.
    let expected = format!(
        "provider error: the request was sent and no response arrived, so whether the effect \
         landed is not yet determined; retry this exact effect with retry_effect={}, which \
         reuses its idempotency key, rather than making a fresh request",
        parent.effect_id.as_deref().unwrap()
    );
    assert_eq!(error.to_string(), expected);
    let failure = &event_data(&broker, "provider_action_failed")[0];
    assert_eq!(failure["error"], expected);
    assert_eq!(failure["failure_class"], "transport_no_response");
    // The message states a derivation; nothing stores one. The durable row carries observations.
    assert_eq!(failure["mutation_invoked"], true);
    let audit = std::fs::read(broker.dir.join("audit.db")).unwrap();
    assert!(!String::from_utf8_lossy(&audit).contains(parent_money.idempotency_key().unwrap()));
    probe.execute_error.store(false, Ordering::SeqCst);

    let child = broker
        .request_retry_capability_for_principal_open(
            "sess_m2_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(child.decision, Decision::Allow);
    assert_eq!(child.effect_id, parent.effect_id);
    let child_id = child.grant_id.unwrap();
    let child_money = crate::money::MoneyMetadata::from_canonical_json(
        &broker.load_grant(&child_id).unwrap().money_json,
    )
    .unwrap();
    assert!(child_money.is_retry());
    assert_eq!(
        child_money.idempotency_key(),
        parent_money.idempotency_key()
    );
    assert!(event_data(&broker, "budget_mint").is_empty());
    let links = event_data(&broker, "money_retry_linked");
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["parent_budget"], "unbudgeted");
    assert!(links[0]["parent_mint_event_id"].is_null());
    assert!(links[0].get("idempotency_key").is_none());
    broker.execute_capability(&child_id).unwrap();
    let keys = probe.idempotency_keys.lock().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
}

#[test]
fn moneypath_definite_success_is_not_retry_eligible() {
    let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_m2_success_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    broker
        .execute_capability(parent.grant_id.as_deref().unwrap())
        .unwrap();
    let retry = broker
        .request_retry_capability_for_principal_open(
            "sess_m2_success_retry",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(retry.decision, Decision::Deny);
    assert!(retry.grant_id.is_none());
}

#[test]
fn moneypath_definite_failure_is_projected_and_not_retry_eligible() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_m2_definite_failure_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    probe
        .definitely_failed_response
        .store(true, Ordering::SeqCst);
    let execution = broker
        .execute_capability(parent.grant_id.as_deref().unwrap())
        .unwrap();
    assert!(!execution.ok);
    assert_eq!(
        execution.effect_outcome,
        Some(EffectOutcome::DefinitelyFailed)
    );
    let status = broker.request_status(&parent.request_id).unwrap();
    assert_eq!(status.effect_outcome, Some(EffectOutcome::DefinitelyFailed));
    let retry = broker
        .request_retry_capability_for_principal_open(
            "sess_m2_definite_failure_retry",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(retry.decision, Decision::Deny);
    assert!(retry.grant_id.is_none());
}

#[test]
fn money_success_retention_none_caps_storage_but_returns_the_body() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_success_retention",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    probe
        .retained_success_response
        .store(true, Ordering::SeqCst);

    let execution = broker
        .execute_capability(parent.grant_id.as_deref().unwrap())
        .unwrap();
    assert!(execution.ok);
    assert_eq!(execution.effect_outcome, Some(EffectOutcome::Succeeded));
    assert!(
        !execution.result.is_null(),
        "a money receipt carries the verified body"
    );
    assert!(
        execution.artifact.is_none(),
        "the money retention cap holds"
    );
    assert!(execution.wire_stats.is_none());

    let terminals = event_data(&broker, "provider_action_succeeded");
    assert_eq!(terminals.len(), 1);
    assert!(
        !terminals[0]["result"].is_null(),
        "the durable terminal record carries the same body the receipt does"
    );
    // The RETENTION cap is what `retention: none` buys and it is unchanged: no artifact handle, no
    // wire counter, and the raw body the adapter offered never reaches the artifact store.
    assert!(terminals[0].get("artifact").is_none());
    assert!(terminals[0].get("wire_stats").is_none());
    let audit_bytes = std::fs::read(broker.dir.join("audit.db")).unwrap();
    let audit = String::from_utf8_lossy(&audit_bytes);
    assert!(
        !audit.contains("MONEY_SUCCESS_RAW_BODY_CANARY"),
        "the retention cap holds: the offered artifact body never lands"
    );
    assert!(
        !audit.contains("MONEY_SUCCESS_RAW_BODY_CANARY"),
        "the separately-offered retention body still never lands"
    );
}

#[test]
fn moneypath_ambiguous_provider_response_remains_same_key_retryable() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_m2_ambiguous_response_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    probe.ambiguous_response.store(true, Ordering::SeqCst);
    let result = broker
        .execute_capability(parent.grant_id.as_deref().unwrap())
        .unwrap();
    assert!(!result.ok);
    assert!(
        !result.result.is_null(),
        "an ambiguous money outcome keeps the provider evidence"
    );
    assert!(result.artifact.is_none(), "the money retention cap holds");
    assert!(result.wire_stats.is_none());
    assert_eq!(result.effect_id, parent.effect_id);
    assert_eq!(result.effect_outcome, Some(EffectOutcome::Ambiguous));
    assert!(event_data(&broker, "provider_action_succeeded").is_empty());
    let failures = event_data(&broker, "provider_action_failed");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["outcome"], "provider_error");
    assert_eq!(failures[0]["mutation_invoked"], true);
    // The record stores the OBSERVATION the compiled contract made, and the derived disposition
    // beside it.
    assert_eq!(failures[0]["effect_proof"], "unproved");
    assert_eq!(failures[0]["effect_outcome"], "ambiguous");
    assert_eq!(failures[0]["effect_id"], json!(parent.effect_id));
    assert!(
        !failures[0]["result"].is_null(),
        "the durable terminal keeps the provider evidence"
    );
    assert!(failures[0].get("artifact").is_none());
    assert!(failures[0].get("wire_stats").is_none());
    let status = broker.request_status(&parent.request_id).unwrap();
    assert_eq!(status.outcome.as_deref(), Some("failed"));
    assert_eq!(status.effect_outcome, Some(EffectOutcome::Ambiguous));
    let receipt = status.terminal_receipt.unwrap();
    assert_eq!(receipt["ok"], false);
    assert_eq!(receipt["effect_id"], json!(parent.effect_id));
    assert!(
        !receipt["result"].is_null(),
        "the reconstructed receipt keeps the provider evidence"
    );
    let audit = std::fs::read(broker.dir.join("audit.db")).unwrap();
    let audit = String::from_utf8_lossy(&audit);
    assert!(
        !audit.contains("UNPROVED_RAW_BODY_CANARY"),
        "the retention cap holds: the offered artifact body never lands"
    );
    let parent_money = crate::money::MoneyMetadata::from_canonical_json(
        &broker
            .load_grant(parent.grant_id.as_deref().unwrap())
            .unwrap()
            .money_json,
    )
    .unwrap();
    probe.ambiguous_response.store(false, Ordering::SeqCst);

    let retry = broker
        .request_retry_capability_for_principal_open(
            "sess_m2_ambiguous_response_retry",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(retry.decision, Decision::Allow);
    assert_eq!(retry.effect_id, parent.effect_id);
    let child_id = retry.grant_id.as_deref().unwrap();
    let child_money = crate::money::MoneyMetadata::from_canonical_json(
        &broker.load_grant(child_id).unwrap().money_json,
    )
    .unwrap();
    assert_eq!(
        child_money.idempotency_key(),
        parent_money.idempotency_key()
    );
    let retry_result = broker.execute_capability(child_id).unwrap();
    assert!(retry_result.ok);
    let keys = probe.idempotency_keys.lock().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
}

#[test]
fn http_terminal_event_heals_the_audit_first_crash_window_before_status_or_abandonment() {
    for ambiguous in [false, true] {
        let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
        let parent = broker
            .request_capability(
                &format!("sess_{ambiguous}"),
                request(json!({"charge":"ch_ok","amount":2300})),
            )
            .unwrap();
        probe.ambiguous_response.store(ambiguous, Ordering::SeqCst);
        broker
            .execute_capability(parent.grant_id.as_deref().unwrap())
            .unwrap();

        // Simulate process death after the audit-first terminal append but before the state flip.
        let grant_id = parent.grant_id.as_deref().unwrap();
        let grant = broker.load_grant(grant_id).unwrap();
        let executing_digest = broker.redigest(grant_id, &grant, "executing");
        broker
            .state
            .execute(
                "UPDATE grants SET status='executing', grant_digest=?2 WHERE id=?1",
                rusqlite::params![grant_id, executing_digest],
            )
            .unwrap();

        if ambiguous {
            let deadline = broker.load_grant(grant_id).unwrap().lease_deadline.unwrap();
            broker.set_now(deadline + 1);
            assert_eq!(
                broker.sweep_overdue_leases(),
                1,
                "the sweep must heal authenticated terminal evidence before abandonment"
            );
        }

        let status = broker.request_status(&parent.request_id).unwrap();
        assert_eq!(status.status, "terminal");
        assert_eq!(
            status.effect_outcome,
            Some(if ambiguous {
                EffectOutcome::Ambiguous
            } else {
                EffectOutcome::Succeeded
            })
        );
        assert_eq!(
            broker.load_grant(grant_id).unwrap().status,
            GrantStatus::Executed,
            "status recovery must complete the authenticated terminal state"
        );
        broker.set_now(i64::MAX / 2);
        assert_eq!(broker.sweep_overdue_leases(), 0);
        assert!(event_data(&broker, "lease_abandoned").is_empty());
    }
}

#[test]
fn boot_heals_an_http_terminal_event_before_the_overdue_sweep() {
    let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_boot",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = parent.grant_id.as_deref().unwrap().to_string();
    broker.execute_capability(&grant_id).unwrap();
    let grant = broker.load_grant(&grant_id).unwrap();
    let executing_digest = broker.redigest(&grant_id, &grant, "executing");
    broker
        .state
        .execute(
            "UPDATE grants SET status='executing', grant_digest=?2 WHERE id=?1",
            rusqlite::params![grant_id, executing_digest],
        )
        .unwrap();
    let dir = broker.dir.clone();
    // Close the broker but keep the scratch dir: this test REOPENS the same state.
    let _scratch = broker.close();

    let reopened = Broker::open_with_sentence_authority(
        BrokerConfig {
            git: crate::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
            dir,
            master_key: vec![5u8; 32],
            action_templates: vec![EVIDENCE_TEMPLATE.to_string()],
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        Arc::new(StaticAuthority(
            crate::sentence::parse_rules(ALLOW_EXACT).unwrap(),
        )),
    )
    .unwrap();
    assert_eq!(
        reopened.load_grant(&grant_id).unwrap().status,
        GrantStatus::Executed
    );
    let status = reopened.request_status(&parent.request_id).unwrap();
    assert_eq!(status.effect_outcome, Some(EffectOutcome::Succeeded));
    assert!(event_data(&reopened, "lease_abandoned").is_empty());
}

#[test]
fn http_recovery_rejects_mismatched_terminal_identity_without_abandoning() {
    let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_wrong_identity",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = parent.grant_id.as_deref().unwrap();
    let grant = broker.load_grant(grant_id).unwrap();
    let opened = broker.now_epoch();
    let deadline = opened + 10;
    let executing_digest = broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
    broker
        .state
        .execute(
            "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
            rusqlite::params![grant_id, executing_digest, opened, deadline],
        )
        .unwrap();
    let executing_session = "exec_wrong_identity";
    broker
        .audit
        .record(NewEvent {
            session_id: Some(&grant.session_id),
            event_type: "capability_effect_starting",
            severity: "high",
            summary: "effect start fixture",
            data: retry_effect_start_data(&broker, &parent, executing_session),
            secrets: &[],
        })
        .unwrap();
    let mut terminal = retry_ambiguous_terminal_data(&broker, &parent, executing_session);
    terminal["action"] = json!("wrong_action");
    broker
        .audit
        .record(NewEvent {
            session_id: Some(&grant.session_id),
            event_type: "provider_action_failed",
            severity: "high",
            summary: "wrong terminal fixture",
            data: terminal,
            secrets: &[],
        })
        .unwrap();

    let unresolved = broker.request_status(&parent.request_id).unwrap();
    assert_eq!(unresolved.status, "running");
    assert!(unresolved.effect_outcome.is_none());
    broker.set_now(deadline + 1);
    assert_eq!(broker.sweep_overdue_leases(), 0);
    assert_eq!(
        broker.load_grant(grant_id).unwrap().status,
        GrantStatus::Executing
    );
    assert!(event_data(&broker, "lease_abandoned").is_empty());

    // Even if the state half were already terminal, mismatched evidence cannot become a clean
    // receipt or an effect classification through the looser historical receipt reader.
    let grant = broker.load_grant(grant_id).unwrap();
    let executed_digest = broker.redigest(grant_id, &grant, "executed");
    broker
        .state
        .execute(
            "UPDATE grants SET status='executed', grant_digest=?2 WHERE id=?1",
            rusqlite::params![grant_id, executed_digest],
        )
        .unwrap();
    let terminal_unknown = broker.request_status(&parent.request_id).unwrap();
    assert_eq!(terminal_unknown.status, "terminal");
    assert!(terminal_unknown.outcome.is_none());
    assert!(terminal_unknown.effect_outcome.is_none());
    assert!(terminal_unknown.terminal_receipt.is_none());
}

#[test]
fn http_recovery_rejects_malformed_chained_execution_evidence() {
    for case in [
        "extra_start_field",
        "wrong_start_authority",
        "extra_terminal_field",
        "wrong_audit_session",
    ] {
        let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
        let parent = broker
            .request_capability(
                &format!("sess_malformed_{case}"),
                request(json!({"charge":"ch_ok","amount":2300})),
            )
            .unwrap();
        let grant_id = parent.grant_id.as_deref().unwrap();
        let grant = broker.load_grant(grant_id).unwrap();
        let opened = broker.now_epoch();
        let deadline = opened + 10;
        let executing_digest =
            broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
        broker
            .state
            .execute(
                "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
                rusqlite::params![grant_id, executing_digest, opened, deadline],
            )
            .unwrap();
        let executing_session = "exec_malformed";
        let mut start = retry_effect_start_data(&broker, &parent, executing_session);
        let mut terminal = retry_ambiguous_terminal_data(&broker, &parent, executing_session);
        match case {
            "extra_start_field" => start["unrecognized"] = json!(true),
            "wrong_start_authority" => start["authority_digest"] = json!("sha256:wrong"),
            "extra_terminal_field" => terminal["unrecognized"] = json!(true),
            "wrong_audit_session" => {}
            _ => unreachable!(),
        }
        let audit_session = if case == "wrong_audit_session" {
            "sess_wrong_audit_identity"
        } else {
            &grant.session_id
        };
        broker
            .audit
            .record(NewEvent {
                session_id: Some(audit_session),
                event_type: "capability_effect_starting",
                severity: "high",
                summary: "malformed recovery start fixture",
                data: start,
                secrets: &[],
            })
            .unwrap();
        broker
            .audit
            .record(NewEvent {
                session_id: Some(&grant.session_id),
                event_type: "provider_action_failed",
                severity: "high",
                summary: "malformed recovery terminal fixture",
                data: terminal,
                secrets: &[],
            })
            .unwrap();

        let unresolved = broker.request_status(&parent.request_id).unwrap();
        assert_eq!(unresolved.status, "running", "case {case}");
        assert!(unresolved.effect_outcome.is_none(), "case {case}");
        broker.set_now(deadline + 1);
        assert_eq!(broker.sweep_overdue_leases(), 0, "case {case}");
        assert_eq!(
            broker.load_grant(grant_id).unwrap().status,
            GrantStatus::Executing,
            "case {case}"
        );
        assert!(event_data(&broker, "lease_abandoned").is_empty());
    }
}

#[test]
fn history_heals_terminal_state_before_projecting_retry_guidance() {
    let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let session = "sess_history_heal";
    let parent = broker
        .request_capability(session, request(json!({"charge":"ch_ok","amount":2300})))
        .unwrap();
    let grant_id = parent.grant_id.as_deref().unwrap();
    let grant = broker.load_grant(grant_id).unwrap();
    let opened = broker.now_epoch();
    let deadline = opened + 10;
    let executing_digest = broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
    broker
        .state
        .execute(
            "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
            rusqlite::params![grant_id, executing_digest, opened, deadline],
        )
        .unwrap();
    let executing_session = "exec_history_heal";
    for (event_type, data) in [
        (
            "capability_effect_starting",
            retry_effect_start_data(&broker, &parent, executing_session),
        ),
        (
            "provider_action_failed",
            retry_ambiguous_terminal_data(&broker, &parent, executing_session),
        ),
    ] {
        broker
            .audit
            .record(NewEvent {
                session_id: Some(session),
                event_type,
                severity: "high",
                summary: "history recovery fixture",
                data,
                secrets: &[],
            })
            .unwrap();
    }

    let projected = broker.list_grants(session).unwrap();
    assert_eq!(projected[0].effect_outcome, Some(EffectOutcome::Ambiguous));
    assert_eq!(projected[0].status, "executed");
    assert_eq!(
        broker.load_grant(grant_id).unwrap().status,
        GrantStatus::Executed
    );
}

#[test]
fn recovered_pre_effect_terminal_completes_the_budget_release() {
    let rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");
    let (broker, _) = broker_with(&rule, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_pre_effect_release",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = parent.grant_id.as_deref().unwrap();
    let grant = broker.load_grant(grant_id).unwrap();
    let opened = broker.now_epoch();
    let deadline = opened + 10;
    let executing_digest = broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
    broker
        .state
        .execute(
            "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
            rusqlite::params![grant_id, executing_digest, opened, deadline],
        )
        .unwrap();
    broker
        .audit
        .record(NewEvent {
            session_id: Some(&grant.session_id),
            event_type: "provider_action_failed",
            severity: "high",
            summary: "authority changed before provider invocation",
            data: json!({
                "grant_id": grant_id,
                "request_id": grant.request_id,
                "provider": grant.provider,
                "action": grant.action,
                "outcome": "authority_changed",
                "mutation_invoked": false,
                "request_session": grant.session_id,
                "executing_session": "exec_pre_effect_release",
                "effect_id": parent.effect_id,
                "effect_outcome": "definitely_pre_effect",
            }),
            secrets: &[],
        })
        .unwrap();

    let status = broker.request_status(&parent.request_id).unwrap();
    assert_eq!(status.effect_outcome, Some(EffectOutcome::PreEffect));
    assert_eq!(event_data(&broker, "budget_release").len(), 1);
    let fresh = broker
        .request_capability(
            "sess_pre_effect_fresh",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    assert_eq!(fresh.decision, Decision::Allow);
}

#[test]
fn abandoned_started_money_effect_projects_authenticated_ambiguity() {
    let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_started_abandoned",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = parent.grant_id.as_deref().unwrap();
    let grant = broker.load_grant(grant_id).unwrap();
    let opened = broker.now_epoch();
    let deadline = opened + 10;
    let executing_digest = broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
    broker
        .state
        .execute(
            "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
            rusqlite::params![grant_id, executing_digest, opened, deadline],
        )
        .unwrap();
    broker
        .audit
        .record(NewEvent {
            session_id: Some(&grant.session_id),
            event_type: "capability_effect_starting",
            severity: "high",
            summary: "started money effect without a terminal",
            data: retry_effect_start_data(&broker, &parent, "exec_started_abandoned"),
            secrets: &[],
        })
        .unwrap();

    broker.set_now(deadline + 1);
    assert_eq!(broker.sweep_overdue_leases(), 1);
    let status = broker.request_status(&parent.request_id).unwrap();
    assert_eq!(status.status, "terminal");
    assert_eq!(status.outcome.as_deref(), Some("abandoned"));
    assert_eq!(status.effect_id, parent.effect_id);
    assert_eq!(status.effect_outcome, Some(EffectOutcome::Ambiguous));
    assert!(status.terminal_receipt.is_none());
    let listed = broker.list_grants("sess_started_abandoned").unwrap();
    assert_eq!(listed[0].status, "expired");
    assert_eq!(listed[0].effect_outcome, Some(EffectOutcome::Ambiguous));
    let history = broker.history().unwrap();
    assert_eq!(
        history
            .iter()
            .find(|view| view.grant_id == grant_id)
            .unwrap()
            .effect_outcome,
        Some(EffectOutcome::Ambiguous)
    );
}

#[test]
fn malformed_request_linked_execution_evidence_blocks_abandonment() {
    for event_type in ["capability_effect_starting", "provider_action_failed"] {
        let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
        let parent = broker
            .request_capability(
                &format!("sess_{event_type}"),
                request(json!({"charge":"ch_ok","amount":2300})),
            )
            .unwrap();
        let grant_id = parent.grant_id.as_deref().unwrap();
        let grant = broker.load_grant(grant_id).unwrap();
        let opened = broker.now_epoch();
        let deadline = opened + 10;
        let executing_digest =
            broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
        broker
            .state
            .execute(
                "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
                rusqlite::params![grant_id, executing_digest, opened, deadline],
            )
            .unwrap();
        let mut malformed = json!({ "request_id": parent.request_id });
        if event_type == "provider_action_failed" {
            malformed["grant_id"] = json!(7);
        }
        broker
            .audit
            .record(NewEvent {
                session_id: Some(&grant.session_id),
                event_type,
                severity: "high",
                summary: "malformed request-linked execution evidence",
                data: malformed,
                secrets: &[],
            })
            .unwrap();

        broker.set_now(deadline + 1);
        assert_eq!(broker.sweep_overdue_leases(), 0, "{event_type}");
        assert_eq!(
            broker.load_grant(grant_id).unwrap().status,
            GrantStatus::Executing,
            "{event_type}"
        );
        assert!(event_data(&broker, "lease_abandoned").is_empty());
    }
}

#[test]
fn money_recovery_rejects_impossible_retention_shapes() {
    for (effect_outcome, event_type, outcome) in [
        ("succeeded", "provider_action_succeeded", "ok"),
        ("ambiguous", "provider_action_failed", "provider_error"),
        (
            "definitely_failed",
            "provider_action_failed",
            "provider_error",
        ),
    ] {
        // `non_null_result` is not on this list: a money terminal's `result`
        // IS the provider's body now. The RETENTION cap is what stays impossible — a money terminal
        // can carry no artifact handle and no wire counter, because none was ever stored.
        for malformed in ["artifact", "wire_stats"] {
            let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
            let parent = broker
                .request_capability(
                    &format!("sess_{effect_outcome}_{malformed}"),
                    request(json!({"charge":"ch_ok","amount":2300})),
                )
                .unwrap();
            let grant_id = parent.grant_id.as_deref().unwrap();
            let grant = broker.load_grant(grant_id).unwrap();
            let opened = broker.now_epoch();
            let deadline = opened + 10;
            let executing_digest =
                broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
            broker
                .state
                .execute(
                    "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
                    rusqlite::params![grant_id, executing_digest, opened, deadline],
                )
                .unwrap();
            let executing_session = "exec_malformed_failure";
            broker
                .audit
                .record(NewEvent {
                    session_id: Some(&grant.session_id),
                    event_type: "capability_effect_starting",
                    severity: "high",
                    summary: "money effect start fixture",
                    data: retry_effect_start_data(&broker, &parent, executing_session),
                    secrets: &[],
                })
                .unwrap();
            let mut terminal = retry_ambiguous_terminal_data(&broker, &parent, executing_session);
            terminal.as_object_mut().unwrap().remove("error");
            terminal["outcome"] = json!(outcome);
            terminal["effect_outcome"] = json!(effect_outcome);
            terminal["result"] = json!({"id":"ch_ok","object":"charge"});
            if malformed == "artifact" {
                terminal["artifact"] = json!("art_malformed_money");
                terminal["digest"] = json!("digest_malformed_money");
            } else if malformed == "wire_stats" {
                terminal["wire_stats"] = json!({"total_bytes":9,"kept_bytes":1});
            }
            broker
                .audit
                .record(NewEvent {
                    session_id: Some(&grant.session_id),
                    event_type,
                    severity: "high",
                    summary: "malformed money failure fixture",
                    data: terminal,
                    secrets: &[],
                })
                .unwrap();

            let status = broker.request_status(&parent.request_id).unwrap();
            assert_eq!(status.status, "running", "{effect_outcome}/{malformed}");
            assert!(
                status.effect_outcome.is_none(),
                "{effect_outcome}/{malformed}"
            );
            assert!(
                status.terminal_receipt.is_none(),
                "{effect_outcome}/{malformed}"
            );
            broker.set_now(deadline + 1);
            assert_eq!(
                broker.sweep_overdue_leases(),
                0,
                "{effect_outcome}/{malformed}"
            );
            assert!(event_data(&broker, "lease_abandoned").is_empty());
        }
    }
}

#[test]
fn retry_reconciles_audit_first_pre_effect_state_and_budget_before_deciding() {
    let rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");
    let (broker, _) = broker_with(&rule, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = parent.grant_id.as_deref().unwrap();
    let grant = broker.load_grant(grant_id).unwrap();
    let opened = broker.now_epoch();
    let deadline = opened + 10;
    let executing_digest = broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
    broker
        .state
        .execute(
            "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
            rusqlite::params![grant_id, executing_digest, opened, deadline],
        )
        .unwrap();
    broker
        .audit
        .record(NewEvent {
            session_id: Some(&grant.session_id),
            event_type: "provider_action_failed",
            severity: "high",
            summary: "authority changed before provider invocation",
            data: json!({
                "grant_id": grant_id,
                "request_id": grant.request_id,
                "provider": grant.provider,
                "action": grant.action,
                "outcome": "authority_changed",
                "mutation_invoked": false,
                "request_session": grant.session_id,
                "executing_session": "exec_pre_effect",
                "effect_id": parent.effect_id,
                "effect_outcome": "definitely_pre_effect",
            }),
            secrets: &[],
        })
        .unwrap();

    let retry = broker
        .request_retry_capability_for_principal_open(
            "sess_retry",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(retry.decision, Decision::Deny);
    assert_eq!(
        broker.load_grant(grant_id).unwrap().status,
        GrantStatus::Executed
    );
    assert_eq!(event_data(&broker, "budget_release").len(), 1);
    let fresh = broker
        .request_capability(
            "sess_fresh",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    assert_eq!(fresh.decision, Decision::Allow);
}

#[test]
fn moneypath_compiled_proof_is_the_only_end_to_end_money_success_source() {
    let cases = [
        CompiledContractCase {
            name: "invoice_negative_amount_paid",
            action: "retry_invoice_payment",
            rule: "allow stripe.retry_invoice_payment where invoice = \"in_1\" and payment_method = \"pm_1\" and account = \"acct_1\" and mode = \"test\" and currency = \"usd\" and customer = \"cus_1\" and amount <= 700 and status = \"open\"",
            request: json!({"invoice":"in_1","payment_method":"pm_1"}),
            invalid: r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":0,"amount_paid":-1,"attempt_count":2}"#,
            valid: r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":0,"amount_paid":1200,"attempt_count":2}"#,
        },
        CompiledContractCase {
            name: "invoice_zero_attempt",
            action: "retry_invoice_payment",
            rule: "allow stripe.retry_invoice_payment where invoice = \"in_1\" and payment_method = \"pm_1\" and account = \"acct_1\" and mode = \"test\" and currency = \"usd\" and customer = \"cus_1\" and amount <= 700 and status = \"open\"",
            request: json!({"invoice":"in_1","payment_method":"pm_1"}),
            invalid: r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":0,"amount_paid":1200,"attempt_count":0}"#,
            valid: r#"{"id":"in_1","object":"invoice","status":"paid","currency":"usd","customer":"cus_1","livemode":false,"amount_remaining":0,"amount_paid":1200,"attempt_count":2}"#,
        },
        CompiledContractCase {
            name: "confirm_status_mismatch",
            action: "confirm_payment_intent",
            rule: "allow stripe.confirm_payment_intent where payment_intent = \"pi_1\" and payment_method = \"pm_1\" and account = \"acct_1\" and mode = \"test\" and currency = \"usd\" and customer = \"cus_1\" and amount <= 500 and status = \"requires_confirmation\" and capture_method = \"automatic\" and confirmation_method = \"automatic\"",
            request: json!({"payment_intent":"pi_1","payment_method":"pm_1"}),
            invalid: r#"{"id":"pi_1","object":"payment_intent","amount":500,"currency":"usd","customer":"cus_1","payment_method":"pm_1","livemode":false,"status":"requires_action","capture_method":"automatic","confirmation_method":"automatic"}"#,
            valid: r#"{"id":"pi_1","object":"payment_intent","amount":500,"currency":"usd","customer":"cus_1","payment_method":"pm_1","livemode":false,"status":"succeeded","capture_method":"automatic","confirmation_method":"automatic"}"#,
        },
        CompiledContractCase {
            name: "capture_arithmetic_mismatch",
            action: "capture_payment_intent",
            rule: "allow stripe.capture_payment_intent where payment_intent = \"pi_2\" and amount <= 200 and account = \"acct_1\" and mode = \"test\" and currency = \"usd\" and customer = \"cus_1\" and status = \"requires_capture\" and capture_method = \"manual\" and intent_amount = 900 and amount_capturable = 600",
            request: json!({"payment_intent":"pi_2","amount":200}),
            invalid: r#"{"id":"pi_2","object":"payment_intent","amount":900,"amount_capturable":399,"amount_received":500,"currency":"usd","customer":"cus_1","livemode":false,"status":"requires_capture","capture_method":"manual"}"#,
            valid: r#"{"id":"pi_2","object":"payment_intent","amount":900,"amount_capturable":400,"amount_received":500,"currency":"usd","customer":"cus_1","livemode":false,"status":"requires_capture","capture_method":"manual"}"#,
        },
        CompiledContractCase {
            name: "refund_status_mismatch",
            action: "refund_charge_bounded",
            rule: "allow stripe.refund_charge_bounded where charge = \"ch_1\" and amount <= 300 and account = \"acct_1\" and mode = \"test\" and currency = \"usd\"",
            request: json!({"charge":"ch_1","amount":300}),
            invalid: r#"{"id":"re_1","object":"refund","charge":"ch_1","amount":300,"currency":"usd","status":"failed"}"#,
            valid: r#"{"id":"re_1","object":"refund","charge":"ch_1","amount":300,"currency":"usd","status":"succeeded"}"#,
        },
    ];

    for case in cases {
        let (broker, probe) = compiled_contract_broker(&case);
        let capability = || CapabilityRequest {
            provider: "stripe".into(),
            action: case.action.into(),
            resource: case.request.clone(),
            environment: None,
            justification: Some("compiled money success proof".into()),
            model: None,
        };
        let parent = broker
            .request_capability(&format!("sess_{}_parent", case.name), capability())
            .unwrap();
        assert_eq!(parent.decision, Decision::Allow, "{}", case.name);
        let parent_id = parent.grant_id.as_deref().unwrap();
        let parent_money = crate::money::MoneyMetadata::from_canonical_json(
            &broker.load_grant(parent_id).unwrap().money_json,
        )
        .unwrap();

        let execution = broker.execute_capability(parent_id).unwrap();
        assert!(!execution.ok, "{}", case.name);
        assert!(
            !execution.result.is_null(),
            "the provider evidence survives a non-success money outcome: {}",
            case.name
        );
        assert_eq!(execution.effect_id, parent.effect_id, "{}", case.name);
        assert!(execution.artifact.is_none(), "{}", case.name);
        assert!(execution.wire_stats.is_none(), "{}", case.name);
        assert!(
            event_data(&broker, "provider_action_succeeded").is_empty(),
            "{}",
            case.name
        );
        let failures = event_data(&broker, "provider_action_failed");
        assert_eq!(failures.len(), 1, "{}", case.name);
        assert_eq!(failures[0]["outcome"], "provider_error", "{}", case.name);
        assert_eq!(failures[0]["mutation_invoked"], true, "{}", case.name);
        assert_eq!(failures[0]["effect_proof"], "unproved", "{}", case.name);
        assert_eq!(failures[0]["effect_outcome"], "ambiguous", "{}", case.name);
        assert_eq!(
            failures[0]["effect_id"],
            json!(parent.effect_id),
            "{}",
            case.name
        );
        assert!(
            !failures[0]["result"].is_null(),
            "the durable terminal keeps the provider evidence: {}",
            case.name
        );
        assert!(failures[0].get("artifact").is_none(), "{}", case.name);
        assert!(failures[0].get("wire_stats").is_none(), "{}", case.name);
        let status = broker.request_status(&parent.request_id).unwrap();
        assert_eq!(status.outcome.as_deref(), Some("failed"), "{}", case.name);
        let receipt = status.terminal_receipt.unwrap();
        assert_eq!(receipt["ok"], false, "{}", case.name);
        assert_eq!(
            receipt["effect_id"],
            json!(parent.effect_id),
            "{}",
            case.name
        );
        assert!(
            !receipt["result"].is_null(),
            "the reconstructed receipt keeps the provider evidence: {}",
            case.name
        );
        let audit = std::fs::read(broker.dir.join("audit.db")).unwrap();
        assert!(
            !String::from_utf8_lossy(&audit).contains("UNPROVED_RAW_BODY_CANARY"),
            "the retention cap holds: the offered artifact body never lands: {}",
            case.name
        );

        *probe.response.lock().unwrap() = case.valid.as_bytes().to_vec();
        let retry = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_{}_retry", case.name),
                LOCAL_REQUESTER,
                parent.effect_id.as_deref().unwrap(),
                capability(),
                false,
                None,
            )
            .unwrap();
        assert_eq!(retry.decision, Decision::Allow, "{}", case.name);
        assert_eq!(retry.effect_id, parent.effect_id, "{}", case.name);
        let retry_id = retry.grant_id.as_deref().unwrap();
        let retry_money = crate::money::MoneyMetadata::from_canonical_json(
            &broker.load_grant(retry_id).unwrap().money_json,
        )
        .unwrap();
        assert_eq!(
            retry_money.idempotency_key(),
            parent_money.idempotency_key(),
            "{}",
            case.name
        );
        let proved = broker.execute_capability(retry_id).unwrap();
        assert!(proved.ok, "{}", case.name);
        assert_eq!(proved.effect_id, parent.effect_id, "{}", case.name);
        assert_eq!(
            proved.effect_outcome,
            Some(EffectOutcome::Succeeded),
            "{}",
            case.name
        );
        assert!(
            !proved.result.is_null(),
            "a proved money success returns the verified body: {}",
            case.name
        );
        assert!(proved.artifact.is_none(), "{}", case.name);
        assert!(proved.wire_stats.is_none(), "{}", case.name);
        let keys = probe.idempotency_keys.lock().unwrap();
        assert_eq!(keys.len(), 2, "{}", case.name);
        assert_eq!(keys[0], keys[1], "{}", case.name);
        let successes = event_data(&broker, "provider_action_succeeded");
        assert_eq!(successes.len(), 1, "{}", case.name);
        // The observation the compiled contract made, stored beside the disposition derived from
        // it. The first attempt of this same effect recorded `unproved` above; the referenced
        // retry's attempt records `proved`.
        assert_eq!(successes[0]["effect_proof"], "proved", "{}", case.name);
        assert_eq!(successes[0]["effect_outcome"], "succeeded", "{}", case.name);
        assert!(
            !successes[0]["result"].is_null(),
            "the durable terminal carries the verified body too: {}",
            case.name
        );
        assert!(successes[0].get("artifact").is_none(), "{}", case.name);
        assert!(successes[0].get("wire_stats").is_none(), "{}", case.name);
    }
}

#[test]
fn moneypath_malformed_raw_200_is_ambiguous_terminal_and_same_key_retryable() {
    const VALID: &str = r#"{"id":"re_1","object":"refund","charge":"ch_1","amount":300,"currency":"usd","status":"succeeded"}"#;
    let cases: &[(&str, &[u8])] = &[
        (
            "invalid UTF-8",
            b"{\"id\":\"re_1\",\"object\":\"refund\",\"charge\":\"ch_1\",\"amount\":300,\"currency\":\"usd\",\"status\":\"succeeded\",\"note\":\"\xff\"}",
        ),
        (
            "duplicate key",
            b"{\"id\":\"re_other\",\"id\":\"re_1\",\"object\":\"refund\",\"charge\":\"ch_1\",\"amount\":300,\"currency\":\"usd\",\"status\":\"succeeded\"}",
        ),
        (
            "trailing content",
            b"{\"id\":\"re_1\",\"object\":\"refund\",\"charge\":\"ch_1\",\"amount\":300,\"currency\":\"usd\",\"status\":\"succeeded\"} trailing",
        ),
    ];

    for (label, malformed) in cases {
        let case = CompiledContractCase {
            name: "malformed_raw_200",
            action: "refund_charge_bounded",
            rule: "allow stripe.refund_charge_bounded where charge = \"ch_1\" and amount <= 300 and account = \"acct_1\" and mode = \"test\" and currency = \"usd\"",
            request: json!({"charge":"ch_1","amount":300}),
            invalid: VALID,
            valid: VALID,
        };
        let (broker, probe) = compiled_contract_broker(&case);
        *probe.response.lock().unwrap() = malformed.to_vec();
        let capability = || CapabilityRequest {
            provider: "stripe".into(),
            action: case.action.into(),
            resource: case.request.clone(),
            environment: None,
            justification: Some("malformed raw money response proof".into()),
            model: None,
        };
        let parent = broker
            .request_capability(&format!("sess_malformed_{label}_parent"), capability())
            .unwrap();
        let parent_id = parent.grant_id.as_deref().unwrap();
        let parent_money = crate::money::MoneyMetadata::from_canonical_json(
            &broker.load_grant(parent_id).unwrap().money_json,
        )
        .unwrap();

        let execution = broker.execute_capability(parent_id).unwrap();
        assert!(!execution.ok, "{label}");
        assert!(execution.result.is_null(), "{label}");
        assert!(execution.artifact.is_none(), "{label}");
        assert!(execution.wire_stats.is_none(), "{label}");
        assert_eq!(execution.effect_id, parent.effect_id, "{label}");
        assert!(
            event_data(&broker, "provider_action_succeeded").is_empty(),
            "{label}"
        );
        let failures = event_data(&broker, "provider_action_failed");
        assert_eq!(failures.len(), 1, "{label}");
        assert_eq!(failures[0]["outcome"], "provider_error", "{label}");
        assert_eq!(failures[0]["mutation_invoked"], true, "{label}");
        assert_eq!(failures[0]["effect_outcome"], "ambiguous", "{label}");
        assert_eq!(failures[0]["effect_id"], json!(parent.effect_id), "{label}");
        assert!(failures[0]["result"].is_null(), "{label}");
        assert!(failures[0].get("artifact").is_none(), "{label}");
        let status = broker.request_status(&parent.request_id).unwrap();
        assert_eq!(status.outcome.as_deref(), Some("failed"), "{label}");
        let receipt = status.terminal_receipt.unwrap();
        assert_eq!(receipt["ok"], false, "{label}");
        assert_eq!(receipt["effect_id"], json!(parent.effect_id), "{label}");
        assert!(receipt["result"].is_null(), "{label}");

        *probe.response.lock().unwrap() = VALID.as_bytes().to_vec();
        let retry = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_malformed_{label}_retry"),
                LOCAL_REQUESTER,
                parent.effect_id.as_deref().unwrap(),
                capability(),
                false,
                None,
            )
            .unwrap();
        assert_eq!(retry.decision, Decision::Allow, "{label}");
        assert_eq!(retry.effect_id, parent.effect_id, "{label}");
        let retry_id = retry.grant_id.as_deref().unwrap();
        let retry_money = crate::money::MoneyMetadata::from_canonical_json(
            &broker.load_grant(retry_id).unwrap().money_json,
        )
        .unwrap();
        assert_eq!(
            retry_money.idempotency_key(),
            parent_money.idempotency_key(),
            "{label}"
        );
        let proved = broker.execute_capability(retry_id).unwrap();
        assert!(proved.ok, "{label}");
        assert_eq!(proved.effect_id, parent.effect_id, "{label}");
        let keys = probe.idempotency_keys.lock().unwrap();
        assert_eq!(keys.len(), 2, "{label}");
        assert_eq!(keys[0], keys[1], "{label}");
        assert_eq!(
            event_data(&broker, "provider_action_succeeded").len(),
            1,
            "{label}"
        );
    }
}

#[test]
fn moneypath_conflict_and_rate_limit_children_do_not_mask_ambiguous_lineage() {
    for status in [409, 429] {
        let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
        let parent = broker
            .request_capability(
                &format!("sess_m2_{status}_parent"),
                request(json!({"charge":"ch_ok","amount":2300})),
            )
            .unwrap();
        probe.execute_error.store(true, Ordering::SeqCst);
        assert!(broker
            .execute_capability(parent.grant_id.as_deref().unwrap())
            .is_err());
        probe.execute_error.store(false, Ordering::SeqCst);

        let first_child = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m2_{status}_child_1"),
                LOCAL_REQUESTER,
                parent.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        probe.ambiguous_status.store(status, Ordering::SeqCst);
        let response = broker
            .execute_capability(first_child.grant_id.as_deref().unwrap())
            .unwrap();
        assert!(!response.ok);
        probe.ambiguous_status.store(0, Ordering::SeqCst);

        let second_child = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m2_{status}_child_2"),
                LOCAL_REQUESTER,
                parent.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        assert_eq!(second_child.decision, Decision::Allow, "status {status}");
    }
}

#[test]
fn moneypath_retry_refuses_parent_profile_implementation_drift() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_m2_profile_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let parent_id = parent.grant_id.as_deref().unwrap();
    probe.execute_error.store(true, Ordering::SeqCst);
    assert!(broker.execute_capability(parent_id).is_err());

    let mut grant = broker.load_grant(parent_id).unwrap();
    let mut envelope: Value = serde_json::from_str(&grant.evidence_json).unwrap();
    envelope["profile_fingerprint"] = json!(format!("sha256:{}", "a".repeat(64)));
    grant.evidence_json = crate::evidence::canonical_json(&envelope);
    let digest = broker.redigest(parent_id, &grant, "executed");
    broker
        .state
        .execute(
            "UPDATE grants SET evidence_json=?2, grant_digest=?3 WHERE id=?1",
            rusqlite::params![parent_id, grant.evidence_json, digest],
        )
        .unwrap();

    let retry = broker
        .request_retry_capability_for_principal_open(
            "sess_m2_profile_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(retry.decision, Decision::Deny);
    assert!(retry.grant_id.is_none());
}

#[test]
fn pre_effect_child_projects_its_ambiguous_logical_effect_lineage() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_m2_ancestor_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    probe.execute_error.store(true, Ordering::SeqCst);
    assert!(broker
        .execute_capability(parent.grant_id.as_deref().unwrap())
        .is_err());
    probe.execute_error.store(false, Ordering::SeqCst);

    let first_child = broker
        .request_retry_capability_for_principal_open(
            "sess_m2_ancestor_child_1",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    *probe.precondition_failure.lock().unwrap() =
        Some(crate::preconditions::PreconditionFailureClass::StateMismatch);
    assert!(broker
        .execute_capability(first_child.grant_id.as_deref().unwrap())
        .is_err());
    *probe.precondition_failure.lock().unwrap() = None;

    let child_status = broker.request_status(&first_child.request_id).unwrap();
    assert_eq!(child_status.effect_outcome, Some(EffectOutcome::Ambiguous));
    assert_eq!(
        broker.list_grants("sess_m2_ancestor_child_1").unwrap()[0].effect_outcome,
        Some(EffectOutcome::Ambiguous)
    );
    assert_eq!(
        broker
            .history()
            .unwrap()
            .into_iter()
            .find(|view| view.grant_id == first_child.grant_id.as_deref().unwrap())
            .unwrap()
            .effect_outcome,
        Some(EffectOutcome::Ambiguous)
    );

    let second_child = broker
        .request_retry_capability_for_principal_open(
            "sess_m2_ancestor_child_2",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(second_child.decision, Decision::Allow);
    broker
        .execute_capability(second_child.grant_id.as_deref().unwrap())
        .unwrap();
}

#[test]
fn moneypath_post_start_pre_effect_child_traverses_to_the_ambiguous_budget_owner() {
    for malformed in [false, true] {
        let rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");
        let (broker, probe) = broker_with(&rule, Ok(good_evidence()), true);
        let suffix = if malformed { "malformed" } else { "valid" };
        let parent = ambiguous_parent(
            &broker,
            &probe,
            &format!("sess_m3_post_start_{suffix}_parent"),
        );
        let parent_id = parent.grant_id.as_deref().unwrap();
        let parent_money = crate::money::MoneyMetadata::from_canonical_json(
            &broker.load_grant(parent_id).unwrap().money_json,
        )
        .unwrap();
        let original_key = parent_money.idempotency_key().unwrap().to_string();
        let mint_id = broker.audit.events_of_type("budget_mint").unwrap()[0]
            .id
            .clone();

        let child = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m3_post_start_{suffix}_child"),
                LOCAL_REQUESTER,
                parent.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        assert_eq!(child.decision, Decision::Allow);
        let child_id = child.grant_id.as_deref().unwrap();
        let child_grant = broker.load_grant(child_id).unwrap();
        let child_money =
            crate::money::MoneyMetadata::from_canonical_json(&child_grant.money_json).unwrap();
        assert_eq!(child_money.idempotency_key(), Some(original_key.as_str()));
        assert_eq!(event_data(&broker, "budget_mint").len(), 1);

        let opened = broker.now_epoch();
        let deadline = opened + 10;
        let executing_digest =
            broker.redigest_leased(child_id, &child_grant, "executing", opened, deadline);
        broker
            .state
            .execute(
                "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
                rusqlite::params![child_id, executing_digest, opened, deadline],
            )
            .unwrap();
        let executing_session = format!("exec_m3_post_start_{suffix}");
        broker
            .audit
            .record(NewEvent {
                session_id: Some(&child_grant.session_id),
                event_type: "capability_effect_starting",
                severity: "high",
                summary: "retry child effect start fixture",
                data: retry_effect_start_data(&broker, &child, &executing_session),
                secrets: &[],
            })
            .unwrap();
        let mut terminal = retry_ambiguous_terminal_data(&broker, &child, &executing_session);
        terminal["mutation_invoked"] = json!(false);
        terminal["effect_outcome"] = json!(if malformed {
            "ambiguous"
        } else {
            "definitely_pre_effect"
        });
        broker
            .audit
            .record(NewEvent {
                session_id: Some(&child_grant.session_id),
                event_type: "provider_action_failed",
                severity: "high",
                summary: "retry child definite pre-mutation failure fixture",
                data: terminal,
                secrets: &[],
            })
            .unwrap();
        let executed_digest =
            broker.redigest_leased(child_id, &child_grant, "executed", opened, deadline);
        broker
            .state
            .execute(
                "UPDATE grants SET status='executed', grant_digest=?2 WHERE id=?1 AND status='executing'",
                rusqlite::params![child_id, executed_digest],
            )
            .unwrap();
        broker
            .release_budget_for_grant(
                child_id,
                super::budget::BudgetReleaseCause::PreInvocationTerminalFailure,
            )
            .unwrap();
        assert!(event_data(&broker, "budget_release").is_empty());

        let next = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m3_post_start_{suffix}_next"),
                LOCAL_REQUESTER,
                parent.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        if malformed {
            assert_eq!(next.decision, Decision::Deny);
            assert!(next.grant_id.is_none());
            assert_eq!(event_data(&broker, "money_retry_linked").len(), 1);
        } else {
            assert_eq!(next.decision, Decision::Allow);
            let next_money = crate::money::MoneyMetadata::from_canonical_json(
                &broker
                    .load_grant(next.grant_id.as_deref().unwrap())
                    .unwrap()
                    .money_json,
            )
            .unwrap();
            assert_eq!(next_money.idempotency_key(), Some(original_key.as_str()));
            assert_eq!(next_money.parent_grant_id(), Some(parent_id));
            let links = broker.audit.events_of_type("money_retry_linked").unwrap();
            assert_eq!(links.len(), 2);
            assert!(links
                .iter()
                .all(|link| link.data["parent_mint_event_id"] == mint_id));
        }
        assert_eq!(event_data(&broker, "budget_mint").len(), 1);
        assert!(event_data(&broker, "budget_release").is_empty());
    }
}

#[test]
fn moneypath_retry_child_cannot_outlive_the_authenticated_effect_deadline() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_m2_deadline_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let parent_id = parent.grant_id.as_deref().unwrap();
    let parent_money = crate::money::MoneyMetadata::from_canonical_json(
        &broker.load_grant(parent_id).unwrap().money_json,
    )
    .unwrap();
    let deadline = parent_money.retry_deadline_epoch().unwrap();
    probe.execute_error.store(true, Ordering::SeqCst);
    assert!(broker.execute_capability(parent_id).is_err());
    probe.execute_error.store(false, Ordering::SeqCst);

    broker.set_now(deadline - 1);
    let child = broker
        .request_retry_capability_for_principal_open(
            "sess_m2_deadline_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    let child_id = child.grant_id.unwrap();
    assert_eq!(
        broker.load_grant(&child_id).unwrap().expiry_epoch,
        Some(deadline)
    );

    broker.set_now(deadline + 1);
    assert!(broker.execute_capability(&child_id).is_err());
    assert_eq!(probe.execute_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn moneypath_retry_deadline_crossing_during_link_audit_inserts_no_child() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_m2_deadline_audit_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let parent_id = parent.grant_id.as_deref().unwrap();
    let deadline = crate::money::MoneyMetadata::from_canonical_json(
        &broker.load_grant(parent_id).unwrap().money_json,
    )
    .unwrap()
    .retry_deadline_epoch()
    .unwrap();
    probe.execute_error.store(true, Ordering::SeqCst);
    assert!(broker.execute_capability(parent_id).is_err());
    probe.execute_error.store(false, Ordering::SeqCst);

    // The first seven request-time reads reach, but do not exceed, the authenticated deadline. The
    // final read after `money_retry_linked` crosses it and must refuse before `insert_grant`.
    broker.set_now(deadline - 6);
    broker.set_clock_tick(1);
    let refusal = broker
        .request_retry_capability_for_principal_open(
            "sess_m2_deadline_audit_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        // The refusal is a DECISION on the typed channel, not an `Err` the agent wire renders as
        // "internal error". This is the insertion-boundary half of the pair;
        // `moneypath_retry_deadline_crossed_inside_the_window_is_a_decision_not_an_error` owns the
        // pre-link half.
        .expect("an elapsed retry deadline is a decision, never an Err");
    broker.set_clock_tick(0);
    assert_eq!(refusal.decision, Decision::Deny);
    assert!(refusal.grant_id.is_none());
    assert_eq!(refusal.reason, crate::evidence::EVIDENCE_DENIAL_REASON);
    let receipt: String = broker
        .state
        .query_row(
            "SELECT decision FROM requests WHERE id=?1",
            rusqlite::params![&refusal.request_id],
            |row| row.get(0),
        )
        .expect("the refusal has a receipt row");
    assert_eq!(receipt, "deny");
    assert_eq!(event_data(&broker, "money_retry_linked").len(), 1);
    assert_eq!(
        broker
            .state
            .query_row("SELECT COUNT(*) FROM grants", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1,
        "the expired retry child must not be inserted"
    );
}

#[test]
fn moneypath_independent_and_definitely_pre_effect_requests_get_fresh_keys() {
    let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let first = broker
        .request_capability(
            "sess_m2_fresh_1",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let first_id = first.grant_id.clone().unwrap();
    let first_money = crate::money::MoneyMetadata::from_canonical_json(
        &broker.load_grant(&first_id).unwrap().money_json,
    )
    .unwrap();
    let rejected_retry = broker
        .request_retry_capability_for_principal_open(
            "sess_m2_pre_effect_retry",
            LOCAL_REQUESTER,
            first.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(rejected_retry.decision, Decision::Deny);

    let second = broker
        .request_capability(
            "sess_m2_fresh_2",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let second_money = crate::money::MoneyMetadata::from_canonical_json(
        &broker
            .load_grant(second.grant_id.as_deref().unwrap())
            .unwrap()
            .money_json,
    )
    .unwrap();
    assert_ne!(first.effect_id, second.effect_id);
    assert_ne!(
        first_money.idempotency_key(),
        second_money.idempotency_key()
    );
}

#[test]
fn moneypath_budgeted_retry_substitutes_the_authenticated_parent_mint() {
    // The parent alone exactly consumes the cap. Ordinary projected admission of the same amount
    // would deny; an authenticated retry must instead prove and reuse the parent's reservation.
    let rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");
    let (broker, probe) = broker_with(&rule, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_m3_budget_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let parent_id = parent.grant_id.as_deref().unwrap();
    let parent_mints = event_data(&broker, "budget_mint");
    assert_eq!(parent_mints.len(), 1);
    assert_eq!(parent_mints[0]["grant_id"], parent_id);
    probe.execute_error.store(true, Ordering::SeqCst);
    assert!(broker.execute_capability(parent_id).is_err());
    probe.execute_error.store(false, Ordering::SeqCst);
    broker.reset_audit_verification_passes_for_test();

    let child = broker
        .request_retry_capability_for_principal_open(
            "sess_m3_budget_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(child.decision, Decision::Allow, "{}", child.reason);
    assert_eq!(broker.audit_verification_passes_for_test(), 1);
    let child_id = child.grant_id.as_deref().unwrap();
    assert_eq!(event_data(&broker, "budget_mint").len(), 1);
    assert!(event_data(&broker, "budget_denied").is_empty());

    let links = broker.audit.events_of_type("money_retry_linked").unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].data["parent_grant_id"], parent_id);
    assert_eq!(links[0].data["child_grant_id"], child_id);
    assert_eq!(links[0].data["effect_id"], parent.effect_id.unwrap());
    assert_eq!(
        links[0].data["parent_mint_event_id"],
        broker.audit.events_of_type("budget_mint").unwrap()[0].id
    );
    assert_eq!(
        links[0].data["authority_fingerprint"],
        broker.load_grant(child_id).unwrap().policy_fingerprint
    );
    for forbidden in [
        "idempotency_key",
        "debit",
        "limit",
        "consumed_before",
        "projected",
    ] {
        assert!(
            links[0].data.get(forbidden).is_none(),
            "link leaked {forbidden}"
        );
    }
}

#[test]
fn moneypath_multiple_ambiguous_budgeted_retries_reuse_the_original_mint() {
    let rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");
    let (broker, probe) = broker_with(&rule, Ok(good_evidence()), true);
    let parent = ambiguous_parent(&broker, &probe, "sess_m3_generations_parent");
    let mut latest = parent;

    for generation in 1..=3 {
        let child = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m3_generations_child_{generation}"),
                LOCAL_REQUESTER,
                latest.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        assert_eq!(child.decision, Decision::Allow, "generation {generation}");
        assert_eq!(event_data(&broker, "budget_mint").len(), 1);
        assert_eq!(event_data(&broker, "money_retry_linked").len(), generation);
        if generation < 3 {
            probe.execute_error.store(true, Ordering::SeqCst);
            assert!(broker
                .execute_capability(child.grant_id.as_deref().unwrap())
                .is_err());
            probe.execute_error.store(false, Ordering::SeqCst);
        }
        latest = child;
    }

    let mint_id = broker.audit.events_of_type("budget_mint").unwrap()[0]
        .id
        .clone();
    assert!(event_data(&broker, "money_retry_linked")
        .iter()
        .all(|link| link["parent_mint_event_id"] == mint_id));
}

#[test]
fn moneypath_retry_parent_link_cycle_missing_parent_and_mismatch_deny() {
    for case in ["cycle", "missing", "mismatch"] {
        let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
        let parent = ambiguous_parent(&broker, &probe, &format!("sess_m3_{case}_root"));
        let child = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m3_{case}_first_child"),
                LOCAL_REQUESTER,
                parent.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        probe.execute_error.store(true, Ordering::SeqCst);
        assert!(broker
            .execute_capability(child.grant_id.as_deref().unwrap())
            .is_err());
        probe.execute_error.store(false, Ordering::SeqCst);

        let replacement_parent = match case {
            "cycle" => child.grant_id.clone().unwrap(),
            "missing" => "grant_missing_lineage_parent".into(),
            "mismatch" => broker
                .request_capability(
                    "sess_m3_mismatch_independent",
                    request(json!({"charge":"ch_ok","amount":2300})),
                )
                .unwrap()
                .grant_id
                .unwrap(),
            _ => unreachable!(),
        };
        let child_id = child.grant_id.as_deref().unwrap();
        let mut grant = broker.load_grant(child_id).unwrap();
        let mut money: Value = serde_json::from_str(&grant.money_json).unwrap();
        money["parent_grant_id"] = json!(replacement_parent);
        grant.money_json = crate::evidence::canonical_json(&money);
        let digest = broker.redigest_leased(
            child_id,
            &grant,
            "executed",
            grant.lease_opened_at.unwrap(),
            grant.lease_deadline.unwrap(),
        );
        broker
            .state
            .execute(
                "UPDATE grants SET money_json=?2, grant_digest=?3 WHERE id=?1",
                rusqlite::params![child_id, grant.money_json, digest],
            )
            .unwrap();

        let retry = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m3_{case}_second_child"),
                LOCAL_REQUESTER,
                child.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        assert_eq!(retry.decision, Decision::Deny, "case {case}");
        assert!(retry.grant_id.is_none());
    }
}

#[test]
fn moneypath_retry_parent_link_depth_is_bounded() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let mut latest = ambiguous_parent(&broker, &probe, "sess_m3_depth_root");
    for generation in 1..=33 {
        let child = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m3_depth_child_{generation}"),
                LOCAL_REQUESTER,
                latest.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        if generation == 33 {
            assert_eq!(child.decision, Decision::Deny);
            assert!(child.grant_id.is_none());
            break;
        }
        assert_eq!(child.decision, Decision::Allow, "generation {generation}");
        probe.execute_error.store(true, Ordering::SeqCst);
        assert!(broker
            .execute_capability(child.grant_id.as_deref().unwrap())
            .is_err());
        probe.execute_error.store(false, Ordering::SeqCst);
        latest = child;
    }
}

#[test]
fn moneypath_terminal_only_or_malformed_retry_evidence_cannot_authenticate_lineage() {
    for case in ["terminal_only", "wrong_effect", "extra_terminal_field"] {
        let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
        let parent = broker
            .request_capability(
                &format!("sess_m3_{case}_parent"),
                request(json!({"charge":"ch_ok","amount":2300})),
            )
            .unwrap();
        let grant_id = parent.grant_id.as_deref().unwrap();
        let effect_id = parent.effect_id.as_deref().unwrap();
        let mut terminal = json!({
            "grant_id": grant_id,
            "provider": "stripe",
            "action": "test_charge_evidence",
            "outcome": "error",
            "mutation_invoked": true,
            "error": "ambiguous fixture",
            "request_session": format!("sess_m3_{case}_parent"),
            "executing_session": format!("sess_m3_{case}_parent"),
            "effect_id": if case == "wrong_effect" { "effect_00000000000000000000000000000000" } else { effect_id },
            "effect_outcome": "ambiguous",
        });
        if case == "extra_terminal_field" {
            terminal["untrusted_extra"] = json!(true);
        }
        broker
            .audit
            .record(NewEvent {
                session_id: Some(&format!("sess_m3_{case}_parent")),
                event_type: "provider_action_failed",
                severity: "high",
                summary: "forged terminal-only retry fixture",
                data: terminal,
                secrets: &[],
            })
            .unwrap();

        let retry = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m3_{case}_child"),
                LOCAL_REQUESTER,
                effect_id,
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        assert_eq!(retry.decision, Decision::Deny, "case {case}");
        assert!(retry.grant_id.is_none());
    }
}

#[test]
fn unproven_exact_effect_impostor_blocks_retry() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = ambiguous_parent(&broker, &probe, "sess_parent");
    let independent = broker
        .request_capability(
            "sess_independent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let independent_grant = broker
        .load_grant(independent.grant_id.as_deref().unwrap())
        .unwrap();
    broker
        .audit
        .record(NewEvent {
            session_id: Some(&independent_grant.session_id),
            event_type: "provider_action_failed",
            severity: "high",
            summary: "disconnected exact-effect impostor",
            data: json!({
                "grant_id": independent.grant_id,
                "provider": independent_grant.provider,
                "action": independent_grant.action,
                "outcome": "error",
                "mutation_invoked": true,
                "error": "impostor",
                "request_session": independent_grant.session_id,
                "executing_session": "exec_impostor",
                "effect_id": parent.effect_id,
                "effect_outcome": "ambiguous",
            }),
            secrets: &[],
        })
        .unwrap();

    let retry = broker
        .request_retry_capability_for_principal_open(
            "sess_retry",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(retry.decision, Decision::Deny);
    assert!(retry.grant_id.is_none());
    assert!(event_data(&broker, "money_retry_linked").is_empty());
}

#[test]
fn moneypath_retry_effect_sequence_requires_order_and_one_execution_session() {
    for case in [
        "terminal_before_start",
        "mismatched_session",
        "missing_start_session",
        "missing_terminal_session",
        "duplicate_start",
        "duplicate_terminal",
        "mismatched_terminal_action",
    ] {
        let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
        let parent = broker
            .request_capability(
                &format!("sess_m3_sequence_{case}_parent"),
                request(json!({"charge":"ch_ok","amount":2300})),
            )
            .unwrap();
        let grant = broker
            .load_grant(parent.grant_id.as_deref().unwrap())
            .unwrap();
        let mut start = retry_effect_start_data(&broker, &parent, "exec_sequence_a");
        let mut terminal = retry_ambiguous_terminal_data(&broker, &parent, "exec_sequence_a");
        match case {
            "mismatched_session" => terminal["executing_session"] = json!("exec_sequence_b"),
            "missing_start_session" => {
                start.as_object_mut().unwrap().remove("executing_session");
            }
            "missing_terminal_session" => {
                terminal
                    .as_object_mut()
                    .unwrap()
                    .remove("executing_session");
            }
            "mismatched_terminal_action" => terminal["action"] = json!("other_action"),
            _ => {}
        }
        let events = match case {
            "terminal_before_start" => vec![
                ("provider_action_failed", terminal),
                ("capability_effect_starting", start),
            ],
            "duplicate_start" => vec![
                ("capability_effect_starting", start.clone()),
                ("capability_effect_starting", start),
                ("provider_action_failed", terminal),
            ],
            "duplicate_terminal" => vec![
                ("capability_effect_starting", start),
                ("provider_action_failed", terminal.clone()),
                ("provider_action_failed", terminal),
            ],
            _ => vec![
                ("capability_effect_starting", start),
                ("provider_action_failed", terminal),
            ],
        };
        for (event_type, data) in events {
            broker
                .audit
                .record(NewEvent {
                    session_id: Some(&grant.session_id),
                    event_type,
                    severity: "high",
                    summary: "retry sequence fixture",
                    data,
                    secrets: &[],
                })
                .unwrap();
        }

        let retry = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m3_sequence_{case}_child"),
                LOCAL_REQUESTER,
                parent.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        assert_generic_retry_denial(&broker, &retry);
    }
}

#[test]
fn moneypath_authenticated_started_without_terminal_remains_retryable_after_crash() {
    let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_m3_started_crash_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = parent.grant_id.as_deref().unwrap();
    let grant = broker.load_grant(grant_id).unwrap();
    let opened = broker.now_epoch();
    let deadline = opened + 10;
    let digest = broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
    broker
        .state
        .execute(
            "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
            rusqlite::params![grant_id, digest, opened, deadline],
        )
        .unwrap();
    broker
        .audit
        .record(NewEvent {
            session_id: Some(&grant.session_id),
            event_type: "capability_effect_starting",
            severity: "high",
            summary: "authenticated crash-after-start fixture",
            data: retry_effect_start_data(&broker, &parent, "exec_started_crash"),
            secrets: &[],
        })
        .unwrap();

    let retry = broker
        .request_retry_capability_for_principal_open(
            "sess_m3_started_crash_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(retry.decision, Decision::Allow);
    assert!(retry.grant_id.is_some());
}

#[test]
fn moneypath_malformed_effect_start_cannot_authenticate_started_without_terminal() {
    let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_m3_bad_start_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = parent.grant_id.as_deref().unwrap();
    let effect_id = parent.effect_id.as_deref().unwrap().to_string();
    let grant = broker.load_grant(grant_id).unwrap();
    let opened = broker.now_epoch();
    let deadline = opened + 10;
    let digest = broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
    broker
        .state
        .execute(
            "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
            rusqlite::params![grant_id, digest, opened, deadline],
        )
        .unwrap();
    broker
        .audit
        .record(NewEvent {
            session_id: Some("sess_m3_bad_start_parent"),
            event_type: "capability_effect_starting",
            severity: "high",
            summary: "malformed effect start fixture",
            data: json!({
                "grant_id": grant_id,
                "effect_id": effect_id,
            }),
            secrets: &[],
        })
        .unwrap();

    let retry = broker
        .request_retry_capability_for_principal_open(
            "sess_m3_bad_start_child",
            LOCAL_REQUESTER,
            &effect_id,
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(retry.decision, Decision::Deny);
    assert!(retry.grant_id.is_none());
}

#[test]
fn moneypath_retry_child_never_releases_or_owns_the_parent_debit() {
    let rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");
    let (broker, probe) = broker_with(&rule, Ok(good_evidence()), true);
    broker.set_now(1_700_000_000);
    let parent = ambiguous_parent(&broker, &probe, "sess_m3_owner_parent");
    let child = broker
        .request_retry_capability_for_principal_open(
            "sess_m3_owner_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(child.decision, Decision::Allow);
    assert_eq!(event_data(&broker, "budget_mint").len(), 1);

    *probe.precondition_failure.lock().unwrap() =
        Some(crate::preconditions::PreconditionFailureClass::StateMismatch);
    assert!(broker
        .execute_capability(child.grant_id.as_deref().unwrap())
        .is_err());
    assert!(event_data(&broker, "budget_release").is_empty());
    assert_eq!(
        event_data(&broker, "provider_action_failed")
            .last()
            .unwrap()["mutation_invoked"],
        false
    );

    broker.set_now(1_700_000_701);
    assert_eq!(broker.sweep_expired_budget_mints(), 0);
    assert!(event_data(&broker, "budget_release").is_empty());
}

#[test]
fn moneypath_retry_link_append_failure_leaves_no_child_grant() {
    let rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");
    let (broker, probe) = broker_with(&rule, Ok(good_evidence()), true);
    let parent = ambiguous_parent(&broker, &probe, "sess_m3_link_parent");
    broker.audit.fail_next_record_of("money_retry_linked");

    assert!(broker
        .request_retry_capability_for_principal_open(
            "sess_m3_link_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .is_err());
    assert_eq!(
        broker
            .state
            .query_row("SELECT COUNT(*) FROM grants", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(event_data(&broker, "money_retry_linked").is_empty());
    assert_eq!(event_data(&broker, "budget_mint").len(), 1);
}

#[test]
fn moneypath_retry_rejects_changed_complete_money_identity_without_a_child() {
    for changed in ["amount", "account", "currency", "mode"] {
        let rule = format!("{ALLOW_EXACT} and budget amount 5000 per day");
        let (broker, probe) = broker_with(&rule, Ok(good_evidence()), true);
        let parent = ambiguous_parent(&broker, &probe, &format!("sess_m3_{changed}_parent"));
        let mut evidence = good_evidence();
        match changed {
            "account" => {
                evidence
                    .fields
                    .insert("account".into(), Scalar::Str("acct_other".into()));
            }
            "currency" => {
                evidence
                    .fields
                    .insert("currency".into(), Scalar::Str("eur".into()));
            }
            "mode" => {
                evidence
                    .fields
                    .insert("mode".into(), Scalar::Str("live".into()));
            }
            "amount" => {}
            _ => unreachable!(),
        }
        *probe.evidence_result.lock().unwrap() = Ok(evidence);
        let amount = if changed == "amount" { 2301 } else { 2300 };
        let retry = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m3_{changed}_child"),
                LOCAL_REQUESTER,
                parent.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":amount})),
                false,
                None,
            )
            .unwrap();
        assert_generic_retry_denial(&broker, &retry);
        assert!(event_data(&broker, "money_retry_linked").is_empty());
        assert_eq!(event_data(&broker, "budget_mint").len(), 1);
    }
}

#[test]
fn moneypath_retry_requires_parent_and_current_budget_classification_to_match_exactly() {
    let budget_2300 = format!("{ALLOW_EXACT} and budget amount 2300 per day");
    let budget_4600 = format!("{ALLOW_EXACT} and budget amount 4600 per day");
    for (parent_rule, current_rule, expected_mints) in [
        (ALLOW_EXACT.to_string(), budget_2300.clone(), 0),
        (budget_2300.clone(), ALLOW_EXACT.to_string(), 1),
        (budget_2300.clone(), budget_4600, 1),
    ] {
        let authority = Arc::new(MutableAuthority(Mutex::new(
            crate::sentence::parse_rules(&parent_rule).unwrap(),
        )));
        let (broker, probe) = broker_with_authority(authority.clone(), Ok(good_evidence()), true);
        let parent = ambiguous_parent(&broker, &probe, "sess_m3_authority_parent");
        authority.set(&current_rule);

        let retry = broker
            .request_retry_capability_for_principal_open(
                "sess_m3_authority_child",
                LOCAL_REQUESTER,
                parent.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        assert_generic_retry_denial(&broker, &retry);
        assert_eq!(event_data(&broker, "budget_mint").len(), expected_mints);
        assert!(event_data(&broker, "money_retry_linked").is_empty());
    }
}

#[test]
fn moneypath_unbudgeted_retry_validates_the_complete_fixed_prefix_budget_population() {
    for case in [
        "malformed_mint",
        "orphan_release",
        "mismatched_request_link",
    ] {
        let authority = Arc::new(MutableAuthority(Mutex::new(
            crate::sentence::parse_rules(ALLOW_EXACT).unwrap(),
        )));
        let (broker, probe) = broker_with_authority(authority.clone(), Ok(good_evidence()), true);
        let parent = ambiguous_parent(
            &broker,
            &probe,
            &format!("sess_m3_unbudgeted_{case}_parent"),
        );

        authority.set(&format!("{ALLOW_EXACT} and budget amount 10000 per day"));
        let fixture = broker
            .request_capability(
                &format!("sess_m3_unbudgeted_{case}_fixture"),
                request(json!({"charge":"ch_ok","amount":2300})),
            )
            .unwrap();
        let fixture_mint = broker.audit.events_of_type("budget_mint").unwrap()[0].clone();
        authority.set(ALLOW_EXACT);

        match case {
            "malformed_mint" => {
                let mut malformed = fixture_mint.data.clone();
                malformed["grant_id"] = json!(7);
                broker
                    .audit
                    .record(NewEvent {
                        session_id: Some("sess_m3_unbudgeted_malformed_mint_fixture"),
                        event_type: "budget_mint",
                        severity: "info",
                        summary: "malformed mint hidden-grant fixture",
                        data: malformed,
                        secrets: &[],
                    })
                    .unwrap();
            }
            "orphan_release" => {
                broker
                    .audit
                    .record(NewEvent {
                        session_id: Some("sess_m3_unbudgeted_orphan_release_fixture"),
                        event_type: "budget_release",
                        severity: "info",
                        summary: "orphan release fixture",
                        data: json!({
                            "mint_event_id": "evt_missing_parent_mint",
                            "aggregate_id": fixture_mint.data["aggregate_id"],
                            "grant_id": fixture.grant_id,
                            "cause": "expired_unclaimed",
                        }),
                        secrets: &[],
                    })
                    .unwrap();
            }
            "mismatched_request_link" => {
                let mut mismatched = fixture_mint.data.clone();
                mismatched["request_id"] = json!(parent.request_id);
                broker
                    .audit
                    .record(NewEvent {
                        session_id: Some("sess_m3_unbudgeted_mismatched_request_fixture"),
                        event_type: "budget_mint",
                        severity: "info",
                        summary: "mismatched lineage request fixture",
                        data: mismatched,
                        secrets: &[],
                    })
                    .unwrap();
            }
            _ => unreachable!(),
        }

        let retry = broker
            .request_retry_capability_for_principal_open(
                &format!("sess_m3_unbudgeted_{case}_child"),
                LOCAL_REQUESTER,
                parent.effect_id.as_deref().unwrap(),
                request(json!({"charge":"ch_ok","amount":2300})),
                false,
                None,
            )
            .unwrap();
        assert_eq!(retry.decision, Decision::Deny, "case {case}");
        assert!(retry.grant_id.is_none());
        assert_eq!(event_data(&broker, "money_retry_linked").len(), 0);
    }
}

#[test]
fn moneypath_retry_link_records_the_current_authority_fingerprint() {
    let budget_rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");
    let authority = Arc::new(MutableAuthority(Mutex::new(
        crate::sentence::parse_rules(&budget_rule).unwrap(),
    )));
    let (broker, probe) = broker_with_authority(authority.clone(), Ok(good_evidence()), true);
    let parent = ambiguous_parent(&broker, &probe, "sess_m3_fingerprint_parent");
    let parent_grant = broker
        .load_grant(parent.grant_id.as_deref().unwrap())
        .unwrap();
    authority.set(&format!(
        "{budget_rule}\ndeny stripe.get_charge where charge = \"ch_blocked\""
    ));

    let child = broker
        .request_retry_capability_for_principal_open(
            "sess_m3_fingerprint_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_eq!(child.decision, Decision::Allow);
    let child_grant = broker
        .load_grant(child.grant_id.as_deref().unwrap())
        .unwrap();
    assert_ne!(
        parent_grant.policy_fingerprint,
        child_grant.policy_fingerprint
    );
    let link = &event_data(&broker, "money_retry_linked")[0];
    assert_eq!(
        link["authority_fingerprint"],
        child_grant.policy_fingerprint
    );
    assert_eq!(event_data(&broker, "budget_mint").len(), 1);
}

#[test]
fn moneypath_retry_rejects_released_duplicate_and_malformed_parent_budget_evidence() {
    let rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");

    let (released, released_probe) = broker_with(&rule, Ok(good_evidence()), true);
    let parent = ambiguous_parent(&released, &released_probe, "sess_m3_released_parent");
    released
        .release_budget_for_grant(
            parent.grant_id.as_deref().unwrap(),
            super::budget::BudgetReleaseCause::PreInvocationTerminalFailure,
        )
        .unwrap();
    let retry = released
        .request_retry_capability_for_principal_open(
            "sess_m3_released_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_generic_retry_denial(&released, &retry);

    let (duplicate, duplicate_probe) = broker_with(&rule, Ok(good_evidence()), true);
    let parent = ambiguous_parent(&duplicate, &duplicate_probe, "sess_m3_duplicate_parent");
    let mint_data = duplicate.audit.events_of_type("budget_mint").unwrap()[0]
        .data
        .clone();
    duplicate
        .audit
        .record(NewEvent {
            session_id: Some("sess_m3_duplicate_parent"),
            event_type: "budget_mint",
            severity: "info",
            summary: "duplicate parent mint fixture",
            data: mint_data,
            secrets: &[],
        })
        .unwrap();
    let retry = duplicate
        .request_retry_capability_for_principal_open(
            "sess_m3_duplicate_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_generic_retry_denial(&duplicate, &retry);

    let (malformed, malformed_probe) = broker_with(&rule, Ok(good_evidence()), true);
    let parent = ambiguous_parent(&malformed, &malformed_probe, "sess_m3_malformed_parent");
    let mint = malformed.audit.events_of_type("budget_mint").unwrap()[0].clone();
    malformed
        .audit
        .record(NewEvent {
            session_id: Some("sess_m3_malformed_parent"),
            event_type: "budget_release",
            severity: "info",
            summary: "malformed release fixture",
            data: json!({
                "mint_event_id": mint.id,
                "aggregate_id": mint.data["aggregate_id"],
                "grant_id": parent.grant_id,
                "cause": "not_a_release_cause",
            }),
            secrets: &[],
        })
        .unwrap();
    let retry = malformed
        .request_retry_capability_for_principal_open(
            "sess_m3_malformed_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_generic_retry_denial(&malformed, &retry);
}

#[test]
fn moneypath_retry_rejects_a_missing_mint_or_broken_audit_chain_generically() {
    let rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");
    let (broker, probe) = broker_with(&rule, Ok(good_evidence()), true);
    let parent = ambiguous_parent(&broker, &probe, "sess_m3_missing_parent");
    let mint_id = broker.audit.events_of_type("budget_mint").unwrap()[0]
        .id
        .clone();
    let audit = rusqlite::Connection::open(broker.dir.join("audit.db")).unwrap();
    audit
        .execute(
            "DELETE FROM audit_events WHERE id=?1",
            rusqlite::params![mint_id],
        )
        .unwrap();
    drop(audit);

    let retry = broker
        .request_retry_capability_for_principal_open(
            "sess_m3_missing_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .unwrap();
    assert_generic_retry_denial(&broker, &retry);
    assert!(event_data(&broker, "money_retry_linked").is_empty());
}

#[test]
fn moneypath_agent_resolved_field_and_missing_agent_field_deny_before_provider_io() {
    for resource in [
        json!({"charge":"ch_ok","amount":2300,"account":"acct_forged"}),
        json!({"charge":"ch_ok"}),
    ] {
        let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
        broker.vault.reset_credential_reads();
        let outcome = broker
            .request_capability("sess_m1_invalid", request(resource))
            .unwrap();
        assert_eq!(outcome.decision, Decision::Deny);
        assert_eq!(outcome.reason, "provider evidence unavailable");
        assert!(outcome.hint.is_none());
        assert!(outcome.grant_id.is_none());
        assert_eq!(probe.resolve_calls.load(Ordering::SeqCst), 0);
        assert_eq!(broker.vault.credential_reads(), 0);
    }
}

#[test]
fn moneypath_symbolically_impossible_authority_does_no_credential_or_provider_io() {
    let impossible = "allow stripe.test_charge_evidence where charge = \"ch_other\" and amount <= 5000 and account = \"acct_test\" and currency = \"usd\" and mode = \"test\"";
    let (broker, probe) = broker_with(impossible, Ok(good_evidence()), true);
    broker.vault.reset_credential_reads();
    let outcome = broker
        .request_capability(
            "sess_m1_impossible",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.reason, "provider evidence unavailable");
    assert!(outcome.hint.is_none());
    assert_eq!(probe.resolve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(broker.vault.credential_reads(), 0);
    assert!(event_data(&broker, "provider_evidence_failed").is_empty());
}

#[test]
fn moneypath_money_allow_requires_exact_account_mode_and_currency_before_io() {
    for rule in [
        "allow stripe.test_charge_evidence where charge = \"ch_ok\" and amount <= 5000 and mode = \"test\" and currency = \"usd\"",
        "allow stripe.test_charge_evidence where charge = \"ch_ok\" and amount <= 5000 and account = \"acct_test\" and currency = \"usd\"",
        "allow stripe.test_charge_evidence where charge = \"ch_ok\" and amount <= 5000 and account = \"acct_test\" and mode = \"test\"",
        "allow stripe.test_charge_evidence where charge = \"ch_ok\" and amount <= 5000 and account = \"acct_test\" and mode = \"test\" and currency in {\"usd\"}",
    ] {
        let (broker, probe) = broker_with(rule, Ok(good_evidence()), true);
        broker.vault.reset_credential_reads();
        let outcome = broker
            .request_capability(
                "sess_m2_money_authority",
                request(json!({"charge":"ch_ok","amount":2300})),
            )
            .unwrap();
        assert_eq!(outcome.decision, Decision::Deny);
        assert_eq!(outcome.reason, "provider evidence unavailable");
        assert_eq!(probe.resolve_calls.load(Ordering::SeqCst), 0);
        assert_eq!(broker.vault.credential_reads(), 0);
    }
}

#[test]
fn moneypath_resolution_success_without_matching_allow_is_hintless_and_mints_nothing() {
    let rule = "allow stripe.test_charge_evidence where charge = \"ch_ok\" and amount <= 5000 and account = \"acct_other\" and currency = \"usd\" and mode = \"test\"";
    let (broker, probe) = broker_with(rule, Ok(good_evidence()), true);
    let outcome = broker
        .request_capability(
            "sess_m1_nomatch",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    assert_eq!(probe.resolve_calls.load(Ordering::SeqCst), 1);
    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.reason, "provider evidence unavailable");
    assert!(outcome.hint.is_none());
    assert!(outcome.grant_id.is_none());
    assert_eq!(
        broker
            .state
            .query_row("SELECT COUNT(*) FROM grants", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

/// The evidence-resolution deny is lossless like every other
/// deny seam. It records BEFORE canonicalization, so its values are size-capped; the template that
/// carries the evidence profile also carries the field classes, so `record_request` still redacts by
/// class. Nothing is destroyed.
#[test]
fn a_denied_evidence_request_retains_its_capped_values() {
    let (broker, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    // Supplying a profile OUTPUT field (`account`) is a Mismatch denial — the pre-canonicalization
    // arm, where an unknown-shaped value could otherwise store an unbounded blob.
    let outcome = broker
        .request_capability(
            "sess_2304",
            request(json!({
                "charge": "ch_retained",
                "amount": 2300,
                "account": "a".repeat(900),
            })),
        )
        .unwrap();
    assert_eq!(outcome.reason, "provider evidence unavailable");

    let stored: String = broker
        .state
        .query_row(
            "SELECT resource_json FROM requests WHERE id=?1",
            rusqlite::params![outcome.request_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        stored.contains("ch_retained") && stored.contains("2300"),
        "the submitted values are retained: {stored}"
    );
    assert!(
        !stored.contains(&"a".repeat(900)) && stored.contains("[truncated: 900 bytes]"),
        "the oversized value is capped, not destroyed: {stored}"
    );
}

#[test]
fn moneypath_failure_taxonomy_is_operator_distinct_but_agent_constant_and_hintless() {
    let (missing_credential, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), false);
    let outcome = missing_credential
        .request_capability(
            "sess_m1_no_credential",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    assert_eq!(outcome.reason, "provider evidence unavailable");
    assert!(outcome.hint.is_none());
    assert_eq!(
        event_data(&missing_credential, "provider_evidence_failed")[0]["failure_class"],
        "credential_unavailable"
    );

    for (class, status) in [
        (EvidenceFailureClass::ProviderAuthentication, Some(401)),
        (EvidenceFailureClass::ProviderDenied, Some(403)),
        (EvidenceFailureClass::ProviderNotFound, Some(404)),
        (EvidenceFailureClass::RateLimited, Some(429)),
        (EvidenceFailureClass::ProviderUnavailable, Some(503)),
        (EvidenceFailureClass::Malformed, None),
        (EvidenceFailureClass::Ambiguous, None),
        (EvidenceFailureClass::Mismatch, None),
        (EvidenceFailureClass::Integrity, None),
    ] {
        let failure = EvidenceFailure {
            class,
            http_status: status,
        };
        let (broker, _) = broker_with(ALLOW_EXACT, Err(failure), true);
        let outcome = broker
            .request_capability(
                "sess_m1_failure",
                request(json!({"charge":"ch_ok","amount":2300})),
            )
            .unwrap();
        assert_eq!(outcome.reason, "provider evidence unavailable");
        assert!(outcome.hint.is_none());
        let events = event_data(&broker, "provider_evidence_failed");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["failure_class"], class.as_str());
        assert_eq!(
            events[0].get("http_status").and_then(Value::as_u64),
            status.map(u64::from)
        );
    }
}

#[test]
fn moneypath_execute_rechecks_template_and_descriptor_bindings_before_claim() {
    let (template_drift, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let grant_id = template_drift
        .request_capability(
            "sess_m1_tpl_drift",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap()
        .grant_id
        .unwrap();
    let mut grant = template_drift.load_grant(&grant_id).unwrap();
    grant.template_hash = Some("0".repeat(64));
    let digest = template_drift.redigest(&grant_id, &grant, "approved");
    template_drift
        .state
        .execute(
            "UPDATE grants SET template_hash=?2, grant_digest=?3 WHERE id=?1",
            rusqlite::params![grant_id, grant.template_hash, digest],
        )
        .unwrap();
    assert_eq!(
        template_drift
            .execute_capability(&grant_id)
            .unwrap_err()
            .to_string(),
        "capability denied: provider evidence unavailable"
    );
    assert_eq!(
        template_drift.load_grant(&grant_id).unwrap().status,
        GrantStatus::Approved
    );

    let (mut descriptor_drift, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let grant_id = descriptor_drift
        .request_capability(
            "sess_m1_desc_drift",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap()
        .grant_id
        .unwrap();
    descriptor_drift
        .descriptor_hashes
        .insert("stripe".into(), "f".repeat(64));
    assert_eq!(
        descriptor_drift
            .execute_capability(&grant_id)
            .unwrap_err()
            .to_string(),
        "capability denied: provider evidence unavailable"
    );
    assert_eq!(
        descriptor_drift.load_grant(&grant_id).unwrap().status,
        GrantStatus::Approved
    );
}

#[test]
fn moneypath_private_metadata_is_hmac_bound_and_precondition_semantics_are_live_verified() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let grant_id = broker
        .request_capability(
            "sess_m2_precondition_semantics",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap()
        .grant_id
        .unwrap();
    let mut grant = broker.load_grant(&grant_id).unwrap();
    let mut metadata: Value = serde_json::from_str(&grant.money_json).unwrap();
    metadata["idempotency_key"] = json!(format!("cermet_{}", "1".repeat(64)));
    grant.money_json = crate::evidence::canonical_json(&metadata);
    assert!(broker.assert_grant_integrity(&grant_id, &grant).is_err());

    metadata["precondition_fingerprint"] = json!(format!("sha256:{}", "0".repeat(64)));
    grant.money_json = crate::evidence::canonical_json(&metadata);
    let digest = broker.redigest(&grant_id, &grant, "approved");
    broker
        .state
        .execute(
            "UPDATE grants SET money_json=?2, grant_digest=?3 WHERE id=?1",
            rusqlite::params![grant_id, grant.money_json, digest],
        )
        .unwrap();

    assert!(broker.execute_capability(&grant_id).is_err());
    assert_eq!(probe.precondition_calls.load(Ordering::SeqCst), 0);
    assert_eq!(probe.execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        broker.load_grant(&grant_id).unwrap().status,
        GrantStatus::Approved
    );
}

#[test]
fn moneypath_semantic_resource_and_profile_tampering_fails_even_with_a_recomputed_grant_hmac() {
    let (resource_tamper, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let grant_id = resource_tamper
        .request_capability(
            "sess_m1_resource_tamper",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap()
        .grant_id
        .unwrap();
    let mut grant = resource_tamper.load_grant(&grant_id).unwrap();
    grant.resource_json =
        r#"{"account":"acct_other","amount":2300,"charge":"ch_ok","currency":"usd","mode":"test"}"#
            .into();
    let digest = resource_tamper.redigest(&grant_id, &grant, "approved");
    resource_tamper
        .state
        .execute(
            "UPDATE grants SET resource_json=?2, grant_digest=?3 WHERE id=?1",
            rusqlite::params![grant_id, grant.resource_json, digest],
        )
        .unwrap();
    assert!(resource_tamper.execute_capability(&grant_id).is_err());
    assert_eq!(
        resource_tamper.load_grant(&grant_id).unwrap().status,
        GrantStatus::Approved
    );

    let (profile_tamper, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let grant_id = profile_tamper
        .request_capability(
            "sess_m1_profile_tamper",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap()
        .grant_id
        .unwrap();
    let mut grant = profile_tamper.load_grant(&grant_id).unwrap();
    let mut envelope: Value = serde_json::from_str(&grant.evidence_json).unwrap();
    envelope["profile"] = json!("stripe.unknown.v1");
    grant.evidence_json = crate::evidence::canonical_json(&envelope);
    let digest = profile_tamper.redigest(&grant_id, &grant, "approved");
    profile_tamper
        .state
        .execute(
            "UPDATE grants SET evidence_json=?2, grant_digest=?3 WHERE id=?1",
            rusqlite::params![grant_id, grant.evidence_json, digest],
        )
        .unwrap();
    assert!(profile_tamper.execute_capability(&grant_id).is_err());
    assert_eq!(
        profile_tamper.load_grant(&grant_id).unwrap().status,
        GrantStatus::Approved
    );
}

#[test]
fn moneypath_profile_fingerprint_is_hmac_bound_and_live_verified() {
    {
        let (session, field) = ("sess_m1_profile_fingerprint", "profile_fingerprint");
        let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
        let grant_id = broker
            .request_capability(session, request(json!({"charge":"ch_ok","amount":2300})))
            .unwrap()
            .grant_id
            .unwrap();
        let mut grant = broker.load_grant(&grant_id).unwrap();
        let mut envelope: Value = serde_json::from_str(&grant.evidence_json).unwrap();
        envelope[field] = json!(format!("sha256:{}", "0".repeat(64)));
        grant.evidence_json = crate::evidence::canonical_json(&envelope);
        assert!(broker.assert_grant_integrity(&grant_id, &grant).is_err());

        let digest = broker.redigest(&grant_id, &grant, "approved");
        broker
            .state
            .execute(
                "UPDATE grants SET evidence_json=?2, grant_digest=?3 WHERE id=?1",
                rusqlite::params![grant_id, grant.evidence_json, digest],
            )
            .unwrap();
        let error = broker.execute_capability(&grant_id).unwrap_err();
        assert!(matches!(
            error,
            Error::Denied(ref reason) if reason == "provider evidence unavailable"
        ));
        assert_eq!(probe.execute_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            broker.load_grant(&grant_id).unwrap().status,
            GrantStatus::Approved
        );
    }
}

#[test]
fn moneypath_resolver_implementation_fingerprint_mismatch_refuses_surviving_grant() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let grant_id = broker
        .request_capability(
            "sess_m1_resolver_implementation_drift",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap()
        .grant_id
        .unwrap();
    let profile = crate::evidence::profile("stripe.test_charge.v1").unwrap();
    let old_implementation_fingerprint = profile.semantics_fingerprint_for_implementation_source(
        b"fn resolve() { /* prior compiled resolver behavior */ }",
    );
    assert_ne!(
        old_implementation_fingerprint,
        profile.semantics_fingerprint()
    );

    let mut grant = broker.load_grant(&grant_id).unwrap();
    let mut envelope: Value = serde_json::from_str(&grant.evidence_json).unwrap();
    envelope["profile_fingerprint"] = json!(old_implementation_fingerprint);
    grant.evidence_json = crate::evidence::canonical_json(&envelope);
    let digest = broker.redigest(&grant_id, &grant, "approved");
    broker
        .state
        .execute(
            "UPDATE grants SET evidence_json=?2, grant_digest=?3 WHERE id=?1",
            rusqlite::params![grant_id, grant.evidence_json, digest],
        )
        .unwrap();

    let error = broker.execute_capability(&grant_id).unwrap_err();
    assert!(matches!(
        error,
        Error::Denied(ref reason) if reason == "provider evidence unavailable"
    ));
    assert_eq!(probe.execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        broker.load_grant(&grant_id).unwrap().status,
        GrantStatus::Approved
    );
}

#[test]
fn moneypath_exact_output_type_and_source_validation_fails_closed() {
    let mut missing = good_evidence();
    missing.fields.remove("mode");
    let mut extra = good_evidence();
    extra
        .fields
        .insert("extra".into(), Scalar::Str("no".into()));
    let mut wrong_type = good_evidence();
    wrong_type.fields.insert("mode".into(), Scalar::Bool(false));
    let mut wrong_source = good_evidence();
    wrong_source.sources[0].id = "ch_other".into();
    let mut duplicate_source = good_evidence();
    duplicate_source
        .sources
        .push(duplicate_source.sources[0].clone());
    let mut oversized = good_evidence();
    oversized.fields.insert(
        "account".into(),
        Scalar::Str("x".repeat(crate::provider::MAX_TEMPLATE_STR_FIELD_BYTES + 1)),
    );
    let mut invalid_format = good_evidence();
    invalid_format
        .fields
        .insert("mode".into(), Scalar::Str("refs/heads/main".into()));
    for (resolved, expected) in [
        (missing, EvidenceFailureClass::Malformed),
        (extra, EvidenceFailureClass::Malformed),
        (wrong_type, EvidenceFailureClass::Malformed),
        (wrong_source, EvidenceFailureClass::Mismatch),
        (duplicate_source, EvidenceFailureClass::Malformed),
        (oversized, EvidenceFailureClass::Malformed),
        (invalid_format, EvidenceFailureClass::Malformed),
    ] {
        let (broker, _) = broker_with(ALLOW_EXACT, Ok(resolved), true);
        let outcome = broker
            .request_capability(
                "sess_m1_shape",
                request(json!({"charge":"ch_ok","amount":2300})),
            )
            .unwrap();
        assert_eq!(outcome.decision, Decision::Deny);
        let events = event_data(&broker, "provider_evidence_failed");
        assert_eq!(events[0]["failure_class"], expected.as_str());
    }
}

#[test]
fn moneypath_resolved_secret_canary_is_rejected_before_receipt_or_persistence() {
    let mut secret_evidence = good_evidence();
    secret_evidence
        .fields
        .insert("account".into(), Scalar::Str(format!("acct_{TOKEN}")));
    let (broker, _) = broker_with(ALLOW_EXACT, Ok(secret_evidence), true);
    let outcome = broker
        .request_capability(
            "sess_m1_secret_evidence",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.reason, "provider evidence unavailable");
    assert!(event_data(&broker, "provider_evidence_resolved").is_empty());
    assert_eq!(
        event_data(&broker, "provider_evidence_failed")[0]["failure_class"],
        "integrity"
    );
    assert_eq!(
        broker
            .state
            .query_row("SELECT COUNT(*) FROM grants", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    for entry in std::fs::read_dir(&broker.dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !String::from_utf8_lossy(&bytes).contains(TOKEN),
                "resolved credential canary persisted in {}",
                path.display()
            );
        }
    }
}

#[test]
fn moneypath_budget_denial_exposes_no_match_signal() {
    let rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");
    let (broker, _) = broker_with(&rule, Ok(good_evidence()), true);
    let first = broker
        .request_capability(
            "sess_m1_budget_first",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    assert_eq!(first.decision, Decision::Allow);

    let second = broker
        .request_capability(
            "sess_m1_budget_second",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    assert_eq!(second.decision, Decision::Deny);
    assert_eq!(second.reason, "provider evidence unavailable");
    assert!(second.hint.is_none());
    assert!(second.budget_exceeded.is_none());
}

#[test]
fn moneypath_money_budget_debits_the_final_hmac_covered_canonical_amount() {
    let rule = format!("{ALLOW_EXACT} and budget amount 5000 per day");
    let (broker, _) = broker_with(&rule, Ok(good_evidence()), true);
    let first = broker
        .request_capability(
            "sess_m3_final_amount_first",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = first.grant_id.as_deref().unwrap();
    let grant = broker.load_grant(grant_id).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&grant.resource_json).unwrap()["amount"],
        2300
    );
    let mint = &event_data(&broker, "budget_mint")[0];
    assert_eq!(mint["grant_id"], grant_id);
    assert_eq!(mint["request_id"], first.request_id);
    assert_eq!(mint["debit_field"], "amount");
    assert_eq!(mint["debit"], 2300);

    let mut changed = broker.load_grant(grant_id).unwrap();
    changed.resource_json =
        r#"{"account":"acct_test","amount":1,"charge":"ch_ok","currency":"usd","mode":"test"}"#
            .into();
    assert!(broker.assert_grant_integrity(grant_id, &changed).is_err());

    let second = broker
        .request_capability(
            "sess_m3_final_amount_second",
            request(json!({"charge":"ch_ok","amount":2701})),
        )
        .unwrap();
    assert_eq!(second.decision, Decision::Deny);
    assert_eq!(second.reason, "provider evidence unavailable");
    assert_eq!(event_data(&broker, "budget_mint").len(), 1);
}

#[test]
fn moneypath_all_denials_have_one_agent_visible_shape() {
    let (not_found, _) = broker_with(
        ALLOW_EXACT,
        Err(EvidenceFailure::status(
            EvidenceFailureClass::ProviderNotFound,
            404,
        )),
        true,
    );
    let early = not_found
        .request_capability(
            "sess_m1_shape_early",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();

    let mismatched_rule = "allow stripe.test_charge_evidence where charge = \"ch_ok\" and amount <= 5000 and account = \"acct_other\" and currency = \"usd\" and mode = \"test\"";
    let (policy, _) = broker_with(mismatched_rule, Ok(good_evidence()), true);
    let post_resolution = policy
        .request_capability(
            "sess_m1_shape_policy",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();

    let budget_rule = format!("{ALLOW_EXACT} and budget amount 2300 per day");
    let (budget, _) = broker_with(&budget_rule, Ok(good_evidence()), true);
    budget
        .request_capability(
            "sess_m1_shape_budget_first",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let exhausted = budget
        .request_capability(
            "sess_m1_shape_budget_second",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();

    let expected = denial_shape(&early);
    assert_eq!(denial_shape(&post_resolution), expected);
    assert_eq!(denial_shape(&exhausted), expected);
}

#[test]
fn moneypath_deadline_crossing_after_policy_cannot_mint_or_execute() {
    let (before_insert, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    before_insert.set_now(1_000);
    // resolve=1000, first check=1011, pre-mint check=1022, insertion-boundary check=1033.
    before_insert.set_clock_tick(11);
    let outcome = before_insert
        .request_capability(
            "sess_m1_deadline_insert",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.grant_id.is_none());
    assert_eq!(
        denial_shape(&outcome),
        json!({
            "decision": "deny",
            "reason": "provider evidence unavailable",
            "budget_exceeded": null,
            "hint": null,
            "grant_id": null,
            "effect_id": null,
            "authority_kind": null,
        })
    );
    assert_eq!(
        before_insert
            .state
            .query_row("SELECT COUNT(*) FROM grants", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );

    let (after_insert_check, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    after_insert_check.set_now(2_000);
    let grant_id = after_insert_check
        .request_capability(
            "sess_m1_deadline_execute",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap()
        .grant_id
        .unwrap();
    // The grant-expiry check sees 2010, evidence verification sees 2021 (still fresh), and the
    // claim timestamp sees 2032 (stale). The provider must not run across that in-handler boundary.
    after_insert_check.set_now(2_010);
    after_insert_check.set_clock_tick(11);
    let crossing = after_insert_check
        .execute_capability(&grant_id)
        .unwrap_err();
    assert!(matches!(
        &crossing,
        Error::Denied(reason) if reason == "provider evidence unavailable"
    ));
    assert_eq!(
        crossing.to_string(),
        "capability denied: provider evidence unavailable"
    );
    assert_eq!(
        after_insert_check.load_grant(&grant_id).unwrap().status,
        GrantStatus::Approved
    );
    assert_eq!(probe.execute_calls.load(Ordering::SeqCst), 0);

    let (already_stale, stale_probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    already_stale.set_now(3_000);
    let stale_grant = already_stale
        .request_capability(
            "sess_m1_deadline_already_stale",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap()
        .grant_id
        .unwrap();
    already_stale.set_now(3_031);
    let early = already_stale.execute_capability(&stale_grant).unwrap_err();
    assert!(matches!(
        &early,
        Error::Denied(reason) if reason == "provider evidence unavailable"
    ));
    assert_eq!(early.to_string(), crossing.to_string());
    assert_eq!(stale_probe.execute_calls.load(Ordering::SeqCst), 0);
}

/// The retry deadline elapsing INSIDE the mint window is the same channel defect as the git-plane
/// signpost. The lineage boundary already answers on the typed channel — a retry whose parent is
/// ineligible gets a definite deny with a receipt — but the two rechecks that run after policy, in
/// the window between the authenticated parent and the grant insert, used to return `Err`, so the
/// identical condition reached an agent as "internal error" and recorded nothing. Same request,
/// same cause, two different answers depending on WHERE the clock crossed.
///
/// The instrument is the documented within-handler drift: freeze the clock just inside the parent's
/// retry deadline, then make every read advance it, so authentication passes and a later read in
/// the same handler is past the deadline.
#[test]
fn moneypath_retry_deadline_crossed_inside_the_window_is_a_decision_not_an_error() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    broker.set_now(1_000);
    let parent = broker
        .request_capability(
            "sess_m2_deadline_window_parent",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    // An ambiguous parent is what makes a retry eligible at all.
    probe.execute_error.store(true, Ordering::SeqCst);
    assert!(broker
        .execute_capability(parent.grant_id.as_deref().unwrap())
        .is_err());
    probe.execute_error.store(false, Ordering::SeqCst);

    // The parent's retry deadline is 1000 + GRANT_TTL_SECS = 1600. Start five seconds inside it and
    // advance one second per read: the lineage authenticates (its own read is still inside the
    // deadline), and a later read in the same handler — the recheck guarding the insert — is past
    // it. The clock is frozen and stepped, so this window is exact, not a race.
    broker.set_now(1_600 - 5);
    broker.set_clock_tick(1);
    let retry = broker
        .request_retry_capability_for_principal_open(
            "sess_m2_deadline_window_child",
            LOCAL_REQUESTER,
            parent.effect_id.as_deref().unwrap(),
            request(json!({"charge":"ch_ok","amount":2300})),
            false,
            None,
        )
        .expect("an elapsed retry deadline is a DECISION, never an Err");
    broker.set_clock_tick(0);
    assert_eq!(retry.decision, Decision::Deny);
    assert!(
        retry.grant_id.is_none(),
        "no grant is minted past the deadline"
    );
    // A money verb declares an evidence profile, so the agent-visible words are the value-free
    // evidence denial — the same shape every other money refusal wears.
    assert_eq!(retry.reason, crate::evidence::EVIDENCE_DENIAL_REASON);
    let row: (String, String) = broker
        .state
        .query_row(
            "SELECT decision, reason FROM requests WHERE id=?1",
            rusqlite::params![&retry.request_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the refusal has a receipt row");
    assert_eq!(row, ("deny".to_string(), retry.reason.clone()));
}

#[test]
fn moneypath_authority_change_after_resolution_denies_before_budget_or_grant() {
    let first =
        crate::sentence::parse_rules(&format!("{ALLOW_EXACT} and budget amount 2300 per day"))
            .unwrap();
    let second = crate::sentence::parse_rules(
        "allow stripe.test_charge_evidence where charge = \"ch_ok\" and amount <= 5000 and account = \"acct_other\" and currency = \"usd\" and mode = \"test\"",
    )
    .unwrap();
    let authority = Arc::new(ChangingAuthority {
        first,
        second,
        calls: AtomicUsize::new(0),
    });
    let (broker, probe) = broker_with_authority(authority.clone(), Ok(good_evidence()), true);
    let outcome = broker
        .request_capability(
            "sess_m1_authority_change",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.reason, "provider evidence unavailable");
    assert!(outcome.grant_id.is_none());
    assert!(outcome.authority_kind.is_none());
    assert!(outcome.hint.is_none());
    assert!(outcome.budget_exceeded.is_none());
    assert_eq!(probe.resolve_calls.load(Ordering::SeqCst), 1);
    assert!(authority.calls.load(Ordering::SeqCst) >= 2);
    assert!(event_data(&broker, "budget_mint").is_empty());
    assert_eq!(
        broker
            .state
            .query_row("SELECT COUNT(*) FROM grants", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn moneypath_stale_resolution_and_failed_durable_receipt_mint_no_grant() {
    let (stale, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    stale.set_now(1_000);
    // First freshness read sees +16s (still fresh); the immediate pre-mint recheck sees +32s and
    // must deny, proving the deadline is not checked only once before policy/budget work.
    stale.set_clock_tick(16);
    let outcome = stale
        .request_capability(
            "sess_m1_stale",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(
        event_data(&stale, "provider_evidence_failed")[0]["failure_class"],
        "stale"
    );
    assert_eq!(
        stale
            .state
            .query_row("SELECT COUNT(*) FROM grants", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );

    let (receipt_fault, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    receipt_fault
        .audit
        .fail_next_record_of("provider_evidence_resolved");
    assert!(receipt_fault
        .request_capability(
            "sess_m1_receipt",
            request(json!({"charge":"ch_ok","amount":2300}))
        )
        .is_err());
    assert_eq!(
        receipt_fault
            .state
            .query_row("SELECT COUNT(*) FROM grants", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn moneypath_rotation_or_envelope_tamper_refuses_before_claim() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let outcome = broker
        .request_capability(
            "sess_m1_rotate",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    let grant_id = outcome.grant_id.unwrap();
    broker
        .connect_credential("stripe", None, "sk_test_ROTATED")
        .unwrap();
    let error = broker.execute_capability(&grant_id).unwrap_err();
    assert_eq!(
        error.to_string(),
        "capability denied: provider evidence unavailable"
    );
    assert_eq!(
        broker.load_grant(&grant_id).unwrap().status,
        GrantStatus::Approved
    );
    assert_eq!(probe.execute_calls.load(Ordering::SeqCst), 0);

    let (tampered, _) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let grant_id = tampered
        .request_capability(
            "sess_m1_tamper",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap()
        .grant_id
        .unwrap();
    tampered
        .state
        .execute(
            "UPDATE grants SET evidence_json=?2 WHERE id=?1",
            rusqlite::params![grant_id, r#"{"kind":"none","version":1}"#],
        )
        .unwrap();
    assert!(tampered.execute_capability(&grant_id).is_err());
    assert_eq!(
        tampered.load_grant(&grant_id).unwrap().status,
        GrantStatus::Approved
    );
}

#[test]
fn real_contract_trio_pinned_money_rule_is_symbolically_satisfiable() {
    // The REAL vendored contracts and the REAL GenericProvider, no probe: a money allow rule
    // pinning the required account/mode/currency trio plus the profile inputs must pass the
    // symbolic prefilter for an inputs-only request. With no credential vaulted, the flow must
    // reach the vault and record a typed credential_unavailable evidence failure — reaching it
    // proves the prefilter admitted the shape. Without this, the trio atoms would be
    // pruned through the provider's request rewrite and every money verb would deny silently here.
    let rules = crate::sentence::parse_rules(
        "allow stripe.create_payment_intent_off_session where customer = \"cus_1\" and \
         payment_method = \"pm_1\" and amount = 100 and account = \"acct_1\" and mode = \"test\" and \
         currency = \"usd\"",
    )
    .unwrap();
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = Broker::open_with_sentence_authority(
        BrokerConfig {
            git: crate::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine")),
            dir,
            master_key: vec![5u8; 32],
            action_templates: crate::templates::VENDORED_CATALOG
                .iter()
                .map(|s| s.to_string())
                .collect(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        Arc::new(StaticAuthority(rules)),
    )
    .unwrap();
    let outcome = broker
        .request_capability(
            "sess_prefilter",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "create_payment_intent_off_session".into(),
                resource: json!({"customer":"cus_1","payment_method":"pm_1","amount":100}),
                environment: None,
                justification: Some("prefilter regression".into()),
                model: None,
            },
        )
        .unwrap();
    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.reason, "provider evidence unavailable");
    let failures = event_data(&broker, "provider_evidence_failed");
    assert_eq!(
        failures
            .iter()
            .map(|event| event["failure_class"].as_str().unwrap().to_string())
            .collect::<Vec<_>>(),
        ["credential_unavailable"],
        "the request must reach the vault, proving the symbolic prefilter admitted the rule"
    );
}

// ---------------------------------------------------------------------------
// The response contract at the BROKER boundary. The
// provider-level pins live in `provider::tests`; this one pins what the BROKER does with a money
// response: the verified body reaches the receipt and the durable terminal event, and the money
// retention cap still keeps it out of the artifact store.
// ---------------------------------------------------------------------------

#[test]
fn a_money_receipt_carries_the_verified_body_and_no_artifact() {
    let (broker, probe) = broker_with(ALLOW_EXACT, Ok(good_evidence()), true);
    let parent = broker
        .request_capability(
            "sess_money_response_contract",
            request(json!({"charge":"ch_ok","amount":2300})),
        )
        .unwrap();
    probe
        .retained_success_response
        .store(true, Ordering::SeqCst);
    let execution = broker
        .execute_capability(parent.grant_id.as_deref().unwrap())
        .unwrap();

    assert!(execution.ok);
    assert_eq!(execution.effect_outcome, Some(EffectOutcome::Succeeded));
    assert_eq!(
        execution.result,
        json!({"raw_success_canary":"MONEY_SUCCESS_PROJECTION_CANARY"}),
        "the money result is the verified body, never null"
    );

    let terminals = event_data(&broker, "provider_action_succeeded");
    assert_eq!(terminals.len(), 1);
    assert_eq!(
        terminals[0]["result"],
        json!({"raw_success_canary":"MONEY_SUCCESS_PROJECTION_CANARY"}),
        "the durable terminal record carries the same body the receipt does"
    );
}
