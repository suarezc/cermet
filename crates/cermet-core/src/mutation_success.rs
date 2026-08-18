//! Compiled provider/action success semantics for money mutations.

use serde_json::Value;

use crate::contract::CanonicalResource;
use crate::templates::StepSpec;

#[derive(Debug, Clone, Copy)]
enum Literal {
    String(&'static str),
    #[cfg(any(test, feature = "test-double"))]
    Bool(bool),
    Int(i64),
}

impl Literal {
    fn matches(self, value: Option<&Value>) -> bool {
        match self {
            Self::String(expected) => value.and_then(Value::as_str) == Some(expected),
            #[cfg(any(test, feature = "test-double"))]
            Self::Bool(expected) => value.and_then(Value::as_bool) == Some(expected),
            Self::Int(expected) => value.and_then(Value::as_i64) == Some(expected),
        }
    }

    fn matches_owned(self, value: &Value) -> bool {
        self.matches(Some(value))
    }
}

#[derive(Debug, Clone, Copy)]
struct LiteralAssertion {
    response_path: &'static str,
    expected: Literal,
}

#[derive(Debug, Clone, Copy)]
enum EqualityKind {
    Direct,
    StripeMode,
}

#[derive(Debug, Clone, Copy)]
struct ResourceEquality {
    response_path: &'static str,
    resource_field: &'static str,
    kind: EqualityKind,
}

impl ResourceEquality {
    const fn direct(response_path: &'static str, resource_field: &'static str) -> Self {
        Self {
            response_path,
            resource_field,
            kind: EqualityKind::Direct,
        }
    }

    const fn mode() -> Self {
        Self {
            response_path: "livemode",
            resource_field: "mode",
            kind: EqualityKind::StripeMode,
        }
    }

    fn matches(self, body: &Value, resource: &CanonicalResource) -> bool {
        let Some(observed) = dotted_lookup(body, self.response_path) else {
            return false;
        };
        match self.kind {
            EqualityKind::Direct => resource
                .scalar(self.resource_field)
                .is_some_and(|expected| observed == &expected.to_json()),
            EqualityKind::StripeMode => {
                observed
                    .as_bool()
                    .map(|live| if live { "live" } else { "test" })
                    == resource.get_str(self.resource_field)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum OutcomeAssertion {
    None,
    ConfirmPaymentIntent,
    CapturePaymentIntent,
    CancelPaymentIntent,
    InvoicePaid,
    RefundCreated,
}

impl OutcomeAssertion {
    fn matches(self, body: &Value, resource: &CanonicalResource) -> bool {
        match self {
            Self::None => true,
            Self::ConfirmPaymentIntent => {
                let status = body.get("status").and_then(Value::as_str);
                match resource.get_str("capture_method") {
                    Some("manual") => status == Some("requires_capture"),
                    Some("automatic") => status == Some("succeeded"),
                    Some("automatic_async") => matches!(status, Some("processing" | "succeeded")),
                    _ => false,
                }
            }
            Self::CapturePaymentIntent => {
                let Some(requested) = resource.get_i64("amount") else {
                    return false;
                };
                let Some(before_capturable) = resource.get_i64("amount_capturable") else {
                    return false;
                };
                let Some(intent_amount) = resource.get_i64("intent_amount") else {
                    return false;
                };
                let Some(after_capturable) = body.get("amount_capturable").and_then(Value::as_i64)
                else {
                    return false;
                };
                let Some(after_received) = body.get("amount_received").and_then(Value::as_i64)
                else {
                    return false;
                };
                let Some(expected_capturable) = before_capturable.checked_sub(requested) else {
                    return false;
                };
                let Some(expected_received) = intent_amount
                    .checked_sub(before_capturable)
                    .and_then(|received| received.checked_add(requested))
                else {
                    return false;
                };
                after_capturable == expected_capturable
                    && after_received == expected_received
                    && match body.get("status").and_then(Value::as_str) {
                        Some("requires_capture") => expected_capturable > 0,
                        Some("succeeded") => expected_capturable == 0,
                        _ => false,
                    }
            }
            Self::CancelPaymentIntent => body
                .get("canceled_at")
                .and_then(Value::as_i64)
                .is_some_and(|timestamp| timestamp > 0),
            Self::InvoicePaid => {
                body.get("amount_paid")
                    .and_then(Value::as_i64)
                    .is_some_and(|amount| amount >= 0)
                    && body
                        .get("attempt_count")
                        .and_then(Value::as_i64)
                        .is_some_and(|attempts| attempts > 0)
            }
            Self::RefundCreated => matches!(
                body.get("status").and_then(Value::as_str),
                Some("pending" | "succeeded")
            ),
        }
    }
}

/// What the ratified success contract OBSERVED of the provider's answer to one effect, after
/// invocation. It is an observation, not a conclusion: it says what the contract could read in
/// the body the provider sent, and stops there. Whether the effect is
/// determined follows from this observation plus the trusted invocation classification and the
/// typed failure class, and is derived where it is needed rather than stored as a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectProof {
    /// The compiled success proof holds: the effect happened, exactly as approved.
    Proved,
    /// A VERIFIED REFUSAL: the provider answered our keyed request with a clean, parseable, typed
    /// 4xx refusal whose shape the compiled rejection contract recognizes. It never processed the
    /// request.
    Refused,
    /// Anything else: a 5xx, a truncated or unparseable body, an untyped refusal, an in-flight
    /// idempotency conflict, or a 2xx whose success proof did not hold. The observation proves
    /// nothing either way — which is the whole reason the key was minted before the first attempt.
    Unproved,
}

impl EffectProof {
    /// The one word this observation is recorded with.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proved => "proved",
            Self::Refused => "refused",
            Self::Unproved => "unproved",
        }
    }
}

/// The CLOSED set of Stripe `error.type` values that prove the request was refused BEFORE it could
/// touch the ledger. Sorted, and deliberately short.
///
/// Every member is a validation/authorization-time refusal: Stripe rejects the call at the edge and
/// its idempotency contract never stores a result, because endpoint execution never began. What is
/// NOT here matters more than what is:
///
///   * `api_error` — Stripe's own "something went wrong on our end". It says nothing about whether
///     the ledger was reached, and it can arrive with a 4xx.
///   * `idempotency_error` — key reuse. The request that legitimately holds that key may have
///     executed; this one's failure proves nothing about that one's outcome.
///
/// and by STATUS, independently of type:
///
///   * `409` — a concurrent request carrying our live key. The sibling may be succeeding right now.
///   * `424` — external dependency failure. A downstream call was already attempted.
///
/// An unrecognized type is never verified: a type we have not reasoned about is not a type we can
/// claim proves non-execution.
const STRIPE_LEDGER_UNTOUCHED_ERROR_TYPES: &[&str] = &[
    "authentication_error",
    "card_error",
    "invalid_request_error",
    "permission_error",
    "rate_limit_error",
];

/// Statuses that can straddle execution regardless of the type on them (see above).
const STRIPE_EXECUTION_STRADDLING_STATUSES: &[u16] = &[409, 424];

/// How a provider signals a rejection it definitely did not act on. Compiled per provider/action,
/// like the success proof — the executor stays free of provider knowledge.
#[derive(Debug, Clone, Copy)]
enum RejectionShape {
    /// Stripe's documented error envelope: `{"error": {"type": "...", ...}}`, narrowed to the
    /// closed allowlist above. This verdict is TERMINAL — `broker/mint.rs` closes the same-key
    /// retry lineage on `definitely_failed`, after which a later request can mint a FRESH
    /// idempotency key — so it must mean "never reached the ledger", not "answered 4xx".
    StripeTypedError,
}

impl RejectionShape {
    fn verified(self, status: u16, body: &Value) -> bool {
        match self {
            Self::StripeTypedError => {
                (400..=499).contains(&status)
                    && !STRIPE_EXECUTION_STRADDLING_STATUSES.contains(&status)
                    && body
                        .get("error")
                        .and_then(|error| error.get("type"))
                        .and_then(Value::as_str)
                        .is_some_and(|kind| STRIPE_LEDGER_UNTOUCHED_ERROR_TYPES.contains(&kind))
            }
        }
    }
}

/// Trusted proof that one exact provider response means one exact money mutation succeeded.
pub(crate) struct MutationSuccessContract {
    provider: &'static str,
    action: &'static str,
    statuses: &'static [u16],
    required: &'static [&'static str],
    response_id_prefix: &'static str,
    object: LiteralAssertion,
    literals: &'static [LiteralAssertion],
    resource_equalities: &'static [ResourceEquality],
    outcome: OutcomeAssertion,
    /// How this provider signals a refusal it definitely did not act on.
    rejection: RejectionShape,
}

#[cfg(any(test, feature = "test-double"))]
const TEST_CHARGE_LITERALS: &[LiteralAssertion] = &[LiteralAssertion {
    response_path: "livemode",
    expected: Literal::Bool(false),
}];

#[cfg(any(test, feature = "test-double"))]
const TEST_CHARGE_EQUALITIES: &[ResourceEquality] = &[
    ResourceEquality::direct("id", "charge"),
    ResourceEquality::direct("amount", "amount"),
    ResourceEquality::direct("account", "account"),
    ResourceEquality::direct("currency", "currency"),
];

const CREATE_PI_LITERALS: &[LiteralAssertion] = &[LiteralAssertion {
    response_path: "status",
    expected: Literal::String("requires_confirmation"),
}];

const CREATE_PI_EQUALITIES: &[ResourceEquality] = &[
    ResourceEquality::direct("amount", "amount"),
    ResourceEquality::direct("currency", "currency"),
    ResourceEquality::direct("customer", "customer"),
    ResourceEquality::direct("payment_method", "payment_method"),
    ResourceEquality::mode(),
];

const CONFIRM_PI_EQUALITIES: &[ResourceEquality] = &[
    ResourceEquality::direct("id", "payment_intent"),
    ResourceEquality::direct("amount", "amount"),
    ResourceEquality::direct("currency", "currency"),
    ResourceEquality::direct("customer", "customer"),
    ResourceEquality::direct("payment_method", "payment_method"),
    ResourceEquality::direct("capture_method", "capture_method"),
    ResourceEquality::direct("confirmation_method", "confirmation_method"),
    ResourceEquality::mode(),
];

const CAPTURE_PI_EQUALITIES: &[ResourceEquality] = &[
    ResourceEquality::direct("id", "payment_intent"),
    ResourceEquality::direct("amount", "intent_amount"),
    ResourceEquality::direct("currency", "currency"),
    ResourceEquality::direct("customer", "customer"),
    ResourceEquality::direct("capture_method", "capture_method"),
    ResourceEquality::mode(),
];

const CANCEL_PI_LITERALS: &[LiteralAssertion] = &[LiteralAssertion {
    response_path: "status",
    expected: Literal::String("canceled"),
}];

const CANCEL_PI_EQUALITIES: &[ResourceEquality] = &[
    ResourceEquality::direct("id", "payment_intent"),
    ResourceEquality::direct("currency", "currency"),
    ResourceEquality::direct("customer", "customer"),
    ResourceEquality::direct("capture_method", "capture_method"),
    ResourceEquality::direct("confirmation_method", "confirmation_method"),
    ResourceEquality::mode(),
];

const INVOICE_LITERALS: &[LiteralAssertion] = &[
    LiteralAssertion {
        response_path: "status",
        expected: Literal::String("paid"),
    },
    LiteralAssertion {
        response_path: "amount_remaining",
        expected: Literal::Int(0),
    },
];

const INVOICE_EQUALITIES: &[ResourceEquality] = &[
    ResourceEquality::direct("id", "invoice"),
    ResourceEquality::direct("currency", "currency"),
    ResourceEquality::direct("customer", "customer"),
    ResourceEquality::mode(),
];

const REFUND_EQUALITIES: &[ResourceEquality] = &[
    ResourceEquality::direct("charge", "charge"),
    ResourceEquality::direct("amount", "amount"),
    ResourceEquality::direct("currency", "currency"),
];

const PAYOUT_LITERALS: &[LiteralAssertion] = &[
    LiteralAssertion {
        response_path: "method",
        expected: Literal::String("standard"),
    },
    LiteralAssertion {
        response_path: "status",
        expected: Literal::String("pending"),
    },
];

const PAYOUT_EQUALITIES: &[ResourceEquality] = &[
    ResourceEquality::direct("amount", "amount"),
    ResourceEquality::direct("currency", "currency"),
    ResourceEquality::direct("destination", "destination"),
    ResourceEquality::direct("source_type", "source_type"),
    ResourceEquality::mode(),
];

const CONTRACTS: &[MutationSuccessContract] = &[
    MutationSuccessContract {
        provider: "stripe",
        action: "create_payment_intent_off_session",
        statuses: &[200],
        required: &[
            "id",
            "object",
            "amount",
            "currency",
            "customer",
            "payment_method",
            "livemode",
            "status",
        ],
        response_id_prefix: "pi_",
        object: LiteralAssertion {
            response_path: "object",
            expected: Literal::String("payment_intent"),
        },
        literals: CREATE_PI_LITERALS,
        resource_equalities: CREATE_PI_EQUALITIES,
        outcome: OutcomeAssertion::None,
        rejection: RejectionShape::StripeTypedError,
    },
    MutationSuccessContract {
        provider: "stripe",
        action: "confirm_payment_intent",
        statuses: &[200],
        required: &[
            "id",
            "object",
            "amount",
            "currency",
            "customer",
            "payment_method",
            "livemode",
            "status",
            "capture_method",
            "confirmation_method",
        ],
        response_id_prefix: "pi_",
        object: LiteralAssertion {
            response_path: "object",
            expected: Literal::String("payment_intent"),
        },
        literals: &[],
        resource_equalities: CONFIRM_PI_EQUALITIES,
        outcome: OutcomeAssertion::ConfirmPaymentIntent,
        rejection: RejectionShape::StripeTypedError,
    },
    MutationSuccessContract {
        provider: "stripe",
        action: "capture_payment_intent",
        statuses: &[200],
        required: &[
            "id",
            "object",
            "amount",
            "amount_capturable",
            "amount_received",
            "currency",
            "customer",
            "livemode",
            "status",
            "capture_method",
        ],
        response_id_prefix: "pi_",
        object: LiteralAssertion {
            response_path: "object",
            expected: Literal::String("payment_intent"),
        },
        literals: &[],
        resource_equalities: CAPTURE_PI_EQUALITIES,
        outcome: OutcomeAssertion::CapturePaymentIntent,
        rejection: RejectionShape::StripeTypedError,
    },
    MutationSuccessContract {
        provider: "stripe",
        action: "cancel_payment_intent",
        statuses: &[200],
        required: &[
            "id",
            "object",
            "currency",
            "customer",
            "livemode",
            "status",
            "capture_method",
            "confirmation_method",
            "canceled_at",
        ],
        response_id_prefix: "pi_",
        object: LiteralAssertion {
            response_path: "object",
            expected: Literal::String("payment_intent"),
        },
        literals: CANCEL_PI_LITERALS,
        resource_equalities: CANCEL_PI_EQUALITIES,
        outcome: OutcomeAssertion::CancelPaymentIntent,
        rejection: RejectionShape::StripeTypedError,
    },
    MutationSuccessContract {
        provider: "stripe",
        action: "retry_invoice_payment",
        statuses: &[200],
        required: &[
            "id",
            "object",
            "status",
            "currency",
            "customer",
            "livemode",
            "amount_remaining",
            "amount_paid",
            "attempt_count",
        ],
        response_id_prefix: "in_",
        object: LiteralAssertion {
            response_path: "object",
            expected: Literal::String("invoice"),
        },
        literals: INVOICE_LITERALS,
        resource_equalities: INVOICE_EQUALITIES,
        outcome: OutcomeAssertion::InvoicePaid,
        rejection: RejectionShape::StripeTypedError,
    },
    MutationSuccessContract {
        provider: "stripe",
        action: "refund_charge_bounded",
        statuses: &[200],
        required: &["id", "object", "charge", "amount", "currency", "status"],
        response_id_prefix: "re_",
        object: LiteralAssertion {
            response_path: "object",
            expected: Literal::String("refund"),
        },
        literals: &[],
        resource_equalities: REFUND_EQUALITIES,
        outcome: OutcomeAssertion::RefundCreated,
        rejection: RejectionShape::StripeTypedError,
    },
    MutationSuccessContract {
        provider: "stripe",
        action: "create_standard_payout",
        statuses: &[200],
        required: &[
            "id",
            "object",
            "amount",
            "currency",
            "destination",
            "source_type",
            "method",
            "status",
            "livemode",
        ],
        response_id_prefix: "po_",
        object: LiteralAssertion {
            response_path: "object",
            expected: Literal::String("payout"),
        },
        literals: PAYOUT_LITERALS,
        resource_equalities: PAYOUT_EQUALITIES,
        outcome: OutcomeAssertion::None,
        rejection: RejectionShape::StripeTypedError,
    },
    #[cfg(any(test, feature = "test-double"))]
    MutationSuccessContract {
        provider: "stripe",
        action: "test_charge_evidence",
        statuses: &[200],
        required: &["id", "object", "amount", "account", "currency", "livemode"],
        response_id_prefix: "ch_",
        object: LiteralAssertion {
            response_path: "object",
            expected: Literal::String("charge"),
        },
        literals: TEST_CHARGE_LITERALS,
        resource_equalities: TEST_CHARGE_EQUALITIES,
        outcome: OutcomeAssertion::None,
        rejection: RejectionShape::StripeTypedError,
    },
];

pub(crate) fn exact(provider: &str, action: &str) -> Option<&'static MutationSuccessContract> {
    CONTRACTS
        .iter()
        .find(|contract| contract.provider == provider && contract.action == action)
}

impl MutationSuccessContract {
    /// The YAML repeats every static assertion so it cannot weaken or extend the compiled proof.
    pub(crate) fn matches_template(&self, step: &StepSpec) -> bool {
        if step.success_statuses != self.statuses
            || step.require.len() != self.required.len()
            || !step
                .require
                .iter()
                .zip(self.required)
                .all(|(actual, expected)| actual == expected)
            || step.expect_eq.len() != self.resource_equalities.len()
            || !self.resource_equalities.iter().all(|equality| {
                step.expect_eq
                    .get(equality.response_path)
                    .is_some_and(|field| field == equality.resource_field)
            })
            || step.expect_literal.len() != self.literals.len() + 1
            || !step
                .expect_literal
                .get(self.object.response_path)
                .is_some_and(|value| self.object.expected.matches_owned(value))
        {
            return false;
        }
        self.literals.iter().all(|assertion| {
            step.expect_literal
                .get(assertion.response_path)
                .is_some_and(|value| assertion.expected.matches_owned(value))
        })
    }

    /// Parse and inspect the raw delivered response before projection. Every absent, malformed,
    /// duplicate-keyed, mismatched, differently-statused, or otherwise unproved response is
    /// ambiguous after invocation.
    pub(crate) fn evaluate_raw(
        &self,
        status: u16,
        bytes: &[u8],
        resource: &CanonicalResource,
    ) -> crate::error::Result<(Value, EffectProof)> {
        let body = crate::provider_json::parse(bytes)?;
        let proved = self.statuses.contains(&status)
            && self
                .required
                .iter()
                .all(|path| dotted_lookup(&body, path).is_some_and(|value| !value.is_null()))
            && body
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.starts_with(self.response_id_prefix))
            && self
                .object
                .expected
                .matches(dotted_lookup(&body, self.object.response_path))
            && self.literals.iter().all(|assertion| {
                assertion
                    .expected
                    .matches(dotted_lookup(&body, assertion.response_path))
            })
            && self
                .resource_equalities
                .iter()
                .all(|equality| equality.matches(&body, resource))
            && self.outcome.matches(&body, resource);
        let evaluation = if proved {
            EffectProof::Proved
        } else if self.rejection.verified(status, &body) {
            EffectProof::Refused
        } else {
            EffectProof::Unproved
        };
        Ok((body, evaluation))
    }
}

fn dotted_lookup<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The money trust boundary. `definitely_failed` is TERMINAL: `broker/mint.rs`
    /// closes the same-key retry lineage on that verdict, so a later request can mint a FRESH
    /// idempotency key against a mutation that may still be completing. The verdict must therefore
    /// mean "Stripe refused this at validation time and never reached the ledger" — not merely
    /// "Stripe answered 4xx with some type on it".
    ///
    /// Stripe's idempotency contract stores a result once endpoint execution BEGINS, and three
    /// shapes do not prove execution never began:
    ///   * `424` external dependency failure — a downstream call was attempted;
    ///   * `api_error` — Stripe's own "something went wrong on our end", which can carry 4xx;
    ///   * `idempotency_error` — key reuse, where the request holding that key may have executed.
    ///
    /// Plus the general case: an `error.type` we have never seen is not one we can reason about.
    #[test]
    fn only_allowlisted_validation_refusals_are_verified_rejections() {
        let typed = |kind: &str| json!({ "error": { "type": kind, "code": "x" } });
        let shape = RejectionShape::StripeTypedError;

        // VERIFIED — refused before the ledger, by documented type.
        for (status, kind) in [
            (400, "invalid_request_error"),
            (401, "authentication_error"),
            (402, "card_error"),
            (403, "permission_error"),
            (429, "rate_limit_error"),
        ] {
            assert!(
                shape.verified(status, &typed(kind)),
                "{status}/{kind} is a validation-time refusal and must stay a verified rejection"
            );
        }

        // NOT VERIFIED — the three shapes that can straddle execution, by name.
        for (status, kind, why) in [
            (
                424,
                "invalid_request_error",
                "a downstream dependency was already called",
            ),
            (
                400,
                "api_error",
                "Stripe's own fault type says nothing about the ledger",
            ),
            (
                409,
                "idempotency_error",
                "a live same-key sibling may be succeeding",
            ),
            (
                400,
                "idempotency_error",
                "the request holding that key may have executed",
            ),
            (
                400,
                "future_error_type_we_have_never_seen",
                "unknown types are not reasoned about",
            ),
        ] {
            assert!(
                !shape.verified(status, &typed(kind)),
                "{status}/{kind} must stay ambiguous: {why}"
            );
        }

        // Shape guards, unchanged: a non-4xx, an untyped body, an empty type, and a body that is
        // not an object all stay ambiguous.
        assert!(!shape.verified(500, &typed("invalid_request_error")));
        assert!(!shape.verified(200, &typed("invalid_request_error")));
        assert!(!shape.verified(400, &json!({ "oops": "untyped" })));
        assert!(!shape.verified(400, &typed("")));
        assert!(!shape.verified(400, &json!("not an object")));
    }

    /// The allowlist is a CLOSED set stated in one place, so review can read it whole. If a type is
    /// added, this test is where the reviewer sees it.
    #[test]
    fn the_verified_rejection_allowlist_is_exactly_these_types() {
        assert_eq!(
            STRIPE_LEDGER_UNTOUCHED_ERROR_TYPES,
            [
                "authentication_error",
                "card_error",
                "invalid_request_error",
                "permission_error",
                "rate_limit_error",
            ],
            "adding a type here widens what `definitely_failed` means; justify it in review"
        );
    }
}
