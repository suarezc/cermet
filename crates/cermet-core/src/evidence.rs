//! Compiled request-evidence profiles and the core-private grant envelope.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::contract::{Scalar, ScalarKind};

pub const EVIDENCE_TTL_SECS: i64 = 30;
pub(crate) const EVIDENCE_ENVELOPE_VERSION: u8 = 1;
pub(crate) const EVIDENCE_RECEIPT_EVENT_TYPE: &str = "provider_evidence_resolved";
pub(crate) const EVIDENCE_DENIAL_REASON: &str = "provider evidence unavailable";
const EVIDENCE_PROFILE_FINGERPRINT_DOMAIN: &[u8] = b"cermet-evidence-profile-v1\0";
const EVIDENCE_RESOLUTION_DIGEST_DOMAIN: &[u8] = b"cermet-provider-evidence-v1\0";

pub(crate) const STRIPE_EVIDENCE_ACCOUNT_PATH: &str = "/v1/account";
pub(crate) const STRIPE_EVIDENCE_BALANCE_PATH: &str = "/v1/balance";
pub(crate) const STRIPE_EVIDENCE_CHARGE_PATH_PREFIX: &str = "/v1/charges/";
pub(crate) const STRIPE_EVIDENCE_CUSTOMER_PATH_PREFIX: &str = "/v1/customers/";
pub(crate) const STRIPE_EVIDENCE_EXTERNAL_ACCOUNT_PATH_PREFIX: &str = "/v1/accounts/";
pub(crate) const STRIPE_EVIDENCE_INVOICE_PATH_PREFIX: &str = "/v1/invoices/";
pub(crate) const STRIPE_EVIDENCE_PAYMENT_INTENT_PATH_PREFIX: &str = "/v1/payment_intents/";
pub(crate) const STRIPE_EVIDENCE_PAYMENT_METHOD_PATH_PREFIX: &str = "/v1/payment_methods/";
pub(crate) const STRIPE_EVIDENCE_SUCCESS_STATUSES: &[u16] = &[200];
pub(crate) const STRIPE_EVIDENCE_ACCOUNT_OBJECT: &str = "account";
pub(crate) const STRIPE_EVIDENCE_CHARGE_OBJECT: &str = "charge";
pub(crate) const STRIPE_EVIDENCE_ACCOUNT_ID_PREFIX: &str = "acct_";
pub(crate) const STRIPE_EVIDENCE_ACCOUNT_ID_MAX_BYTES: usize = 128;
pub(crate) const STRIPE_EVIDENCE_CURRENCY_BYTES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceResolverKind {
    StripeCreatePaymentIntentOffSession,
    StripeConfirmPaymentIntent,
    StripeCapturePaymentIntent,
    StripeCancelPaymentIntent,
    StripeRetryInvoicePayment,
    StripeRefundChargeBounded,
    StripeCreateStandardPayout,
    #[cfg(any(test, feature = "test-double"))]
    StripeTestCharge,
}

#[derive(Debug, Clone, Copy)]
pub struct EvidenceInputDecl {
    pub field: &'static str,
    pub ty: ScalarKind,
}

#[derive(Debug, Clone, Copy)]
pub struct EvidenceOutputDecl {
    pub field: &'static str,
    pub ty: ScalarKind,
    pub source: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct EvidenceSourceDecl {
    pub kind: &'static str,
    pub id_field: &'static str,
}

#[derive(Debug)]
pub struct EvidenceProfile {
    pub id: &'static str,
    pub provider: &'static str,
    pub action: &'static str,
    pub inputs: &'static [EvidenceInputDecl],
    pub outputs: &'static [EvidenceOutputDecl],
    pub sources: &'static [EvidenceSourceDecl],
    pub resolver: EvidenceResolverKind,
}

impl EvidenceProfile {
    pub fn output(&self, field: &str) -> Option<&EvidenceOutputDecl> {
        self.outputs.iter().find(|output| output.field == field)
    }

    pub fn is_output(&self, field: &str) -> bool {
        self.output(field).is_some()
    }

    /// Hash the actual compiled profile and resolver choices. The human-readable profile id is one
    /// input, never the semantics boundary by itself.
    pub(crate) fn semantics_fingerprint(&self) -> String {
        self.semantics_fingerprint_with_sources(
            self.resolver.implementation_source(),
            crate::stripe_inert::IMPLEMENTATION_SOURCE,
        )
    }

    #[cfg(test)]
    pub(crate) fn semantics_fingerprint_for_implementation_source(
        &self,
        implementation_source: &[u8],
    ) -> String {
        self.semantics_fingerprint_with_sources(
            implementation_source,
            crate::stripe_inert::IMPLEMENTATION_SOURCE,
        )
    }

    #[cfg(test)]
    pub(crate) fn semantics_fingerprint_for_inert_shape_source(
        &self,
        inert_shape_source: &[u8],
    ) -> String {
        self.semantics_fingerprint_with_sources(
            self.resolver.implementation_source(),
            inert_shape_source,
        )
    }

    fn semantics_fingerprint_with_sources(
        &self,
        implementation_source: &[u8],
        inert_shape_source: &[u8],
    ) -> String {
        use sha2::{Digest, Sha256};

        let inputs: Vec<Value> = self
            .inputs
            .iter()
            .map(|input| {
                serde_json::json!({
                    "field": input.field,
                    "type": scalar_kind_name(input.ty),
                })
            })
            .collect();
        let outputs: Vec<Value> = self
            .outputs
            .iter()
            .map(|output| {
                serde_json::json!({
                    "field": output.field,
                    "source": output.source,
                    "type": scalar_kind_name(output.ty),
                })
            })
            .collect();
        let sources: Vec<Value> = self
            .sources
            .iter()
            .map(|source| {
                serde_json::json!({
                    "id_field": source.id_field,
                    "kind": source.kind,
                })
            })
            .collect();
        let semantics = serde_json::json!({
            "action": self.action,
            "id": self.id,
            "inputs": inputs,
            "kernel": {
                "credential_generation_domain": String::from_utf8_lossy(crate::vault::CREDENTIAL_GENERATION_DOMAIN),
                "denial_reason": EVIDENCE_DENIAL_REASON,
                "envelope_version": EVIDENCE_ENVELOPE_VERSION,
                "receipt_event_type": EVIDENCE_RECEIPT_EVENT_TYPE,
                "resolution_digest_domain": String::from_utf8_lossy(EVIDENCE_RESOLUTION_DIGEST_DOMAIN),
                "ttl_seconds": EVIDENCE_TTL_SECS,
            },
            "outputs": outputs,
            "provider": self.provider,
            "resolver": self.resolver.semantics(),
            "sources": sources,
        });
        let mut hash = Sha256::new();
        hash.update(EVIDENCE_PROFILE_FINGERPRINT_DOMAIN);
        hash.update(canonical_json(&semantics).as_bytes());
        hash.update((implementation_source.len() as u64).to_le_bytes());
        hash.update(implementation_source);
        hash.update((inert_shape_source.len() as u64).to_le_bytes());
        hash.update(inert_shape_source);
        hash.update((crate::provider_json::IMPLEMENTATION_SOURCE.len() as u64).to_le_bytes());
        hash.update(crate::provider_json::IMPLEMENTATION_SOURCE);
        format!("sha256:{}", crate::util::hex(&hash.finalize()))
    }
}

impl EvidenceResolverKind {
    fn implementation_source(self) -> &'static [u8] {
        crate::provider::stripe_evidence::IMPLEMENTATION_SOURCE
    }

    fn semantics(self) -> Value {
        match self {
            Self::StripeCreatePaymentIntentOffSession => stripe_semantics(
                "stripe_create_payment_intent_off_session",
                &[
                    STRIPE_EVIDENCE_ACCOUNT_PATH,
                    STRIPE_EVIDENCE_CUSTOMER_PATH_PREFIX,
                    STRIPE_EVIDENCE_PAYMENT_METHOD_PATH_PREFIX,
                ],
                "payment_method.customer equals requested customer; customer/payment-method modes agree; currency is account.default_currency",
            ),
            Self::StripeConfirmPaymentIntent => stripe_semantics(
                "stripe_confirm_payment_intent",
                &[
                    STRIPE_EVIDENCE_ACCOUNT_PATH,
                    STRIPE_EVIDENCE_PAYMENT_INTENT_PATH_PREFIX,
                    STRIPE_EVIDENCE_PAYMENT_METHOD_PATH_PREFIX,
                ],
                "payment_method.customer equals payment_intent.customer; current method is absent or exact; full safe subset required",
            ),
            Self::StripeCapturePaymentIntent => stripe_semantics(
                "stripe_capture_payment_intent",
                &[
                    STRIPE_EVIDENCE_ACCOUNT_PATH,
                    STRIPE_EVIDENCE_PAYMENT_INTENT_PATH_PREFIX,
                ],
                "requires_capture; capture_method manual; requested amount positive and no greater than exact amount_capturable; full safe subset required",
            ),
            Self::StripeCancelPaymentIntent => stripe_semantics(
                "stripe_cancel_payment_intent",
                &[
                    STRIPE_EVIDENCE_ACCOUNT_PATH,
                    STRIPE_EVIDENCE_PAYMENT_INTENT_PATH_PREFIX,
                ],
                "cancelable status; canonical amount is positive intent amount or requires_capture amount_capturable; full safe subset required",
            ),
            Self::StripeRetryInvoicePayment => stripe_semantics(
                "stripe_retry_invoice_payment",
                &[
                    STRIPE_EVIDENCE_ACCOUNT_PATH,
                    STRIPE_EVIDENCE_INVOICE_PATH_PREFIX,
                    STRIPE_EVIDENCE_PAYMENT_METHOD_PATH_PREFIX,
                ],
                "open invoice; positive amount_remaining; payment_method.customer equals invoice.customer; safe routing/payment_settings subset required",
            ),
            Self::StripeRefundChargeBounded => stripe_semantics(
                "stripe_refund_charge_bounded",
                &[
                    STRIPE_EVIDENCE_ACCOUNT_PATH,
                    STRIPE_EVIDENCE_CHARGE_PATH_PREFIX,
                ],
                "charge belongs to authenticated account context and exact mode/currency; requested amount is positive and refundable",
            ),
            Self::StripeCreateStandardPayout => stripe_semantics(
                "stripe_create_standard_payout",
                &[
                    STRIPE_EVIDENCE_ACCOUNT_PATH,
                    STRIPE_EVIDENCE_BALANCE_PATH,
                    STRIPE_EVIDENCE_EXTERNAL_ACCOUNT_PATH_PREFIX,
                ],
                "destination belongs to account and supplies currency; exact source balance is typed and sufficient; payouts are enabled",
            ),
            #[cfg(any(test, feature = "test-double"))]
            Self::StripeTestCharge => serde_json::json!({
                "account_id": {
                    "max_bytes": STRIPE_EVIDENCE_ACCOUNT_ID_MAX_BYTES,
                    "prefix": STRIPE_EVIDENCE_ACCOUNT_ID_PREFIX,
                },
                "account_object": STRIPE_EVIDENCE_ACCOUNT_OBJECT,
                "account_path": STRIPE_EVIDENCE_ACCOUNT_PATH,
                "charge_object": STRIPE_EVIDENCE_CHARGE_OBJECT,
                "charge_path_prefix": STRIPE_EVIDENCE_CHARGE_PATH_PREFIX,
                "currency": {
                    "ascii_lowercase": true,
                    "bytes": STRIPE_EVIDENCE_CURRENCY_BYTES,
                },
                "id_check": "exact_requested_charge",
                "kind": "stripe_test_charge",
                "mode": {
                    "field": "livemode",
                    "false": "test",
                    "true": "live",
                },
                "success_statuses": STRIPE_EVIDENCE_SUCCESS_STATUSES,
            }),
        }
    }
}

fn stripe_semantics(kind: &str, reads: &[&str], relationship: &str) -> Value {
    serde_json::json!({
        "account_id": {
            "max_bytes": STRIPE_EVIDENCE_ACCOUNT_ID_MAX_BYTES,
            "prefix": STRIPE_EVIDENCE_ACCOUNT_ID_PREFIX,
        },
        "account_object": STRIPE_EVIDENCE_ACCOUNT_OBJECT,
        "currency": {
            "ascii_lowercase": true,
            "bytes": STRIPE_EVIDENCE_CURRENCY_BYTES,
        },
        "exact_requested_ids": true,
        "kind": kind,
        "mode": {
            "field": "livemode",
            "false": "test",
            "true": "live",
        },
        "object_discriminators": true,
        "reads": reads,
        "relationship": relationship,
        "success_statuses": STRIPE_EVIDENCE_SUCCESS_STATUSES,
    })
}

fn scalar_kind_name(kind: ScalarKind) -> &'static str {
    match kind {
        ScalarKind::Str => "str",
        ScalarKind::Int => "int",
        ScalarKind::Bool => "bool",
    }
}

#[cfg(any(test, feature = "test-double"))]
static STRIPE_TEST_CHARGE_PROFILE: EvidenceProfile = EvidenceProfile {
    id: "stripe.test_charge.v1",
    provider: "stripe",
    action: "test_charge_evidence",
    inputs: &[EvidenceInputDecl {
        field: "charge",
        ty: ScalarKind::Str,
    }],
    outputs: &[
        EvidenceOutputDecl {
            field: "account",
            ty: ScalarKind::Str,
            source: "stripe.authenticated_account.id",
        },
        EvidenceOutputDecl {
            field: "currency",
            ty: ScalarKind::Str,
            source: "stripe.charge.currency",
        },
        EvidenceOutputDecl {
            field: "mode",
            ty: ScalarKind::Str,
            source: "stripe.charge.livemode",
        },
    ],
    sources: &[EvidenceSourceDecl {
        kind: "stripe.charge",
        id_field: "charge",
    }],
    resolver: EvidenceResolverKind::StripeTestCharge,
};

static STRIPE_CREATE_PAYMENT_INTENT_OFF_SESSION_PROFILE: EvidenceProfile = EvidenceProfile {
    id: "stripe.create_payment_intent_off_session.v1",
    provider: "stripe",
    action: "create_payment_intent_off_session",
    inputs: &[
        EvidenceInputDecl {
            field: "customer",
            ty: ScalarKind::Str,
        },
        EvidenceInputDecl {
            field: "payment_method",
            ty: ScalarKind::Str,
        },
        EvidenceInputDecl {
            field: "amount",
            ty: ScalarKind::Int,
        },
    ],
    outputs: &[
        EvidenceOutputDecl {
            field: "account",
            ty: ScalarKind::Str,
            source: "stripe.authenticated_account.id",
        },
        EvidenceOutputDecl {
            field: "mode",
            ty: ScalarKind::Str,
            source: "stripe.customer_and_payment_method.livemode",
        },
        EvidenceOutputDecl {
            field: "currency",
            ty: ScalarKind::Str,
            source: "stripe.authenticated_account.default_currency",
        },
    ],
    sources: &[
        EvidenceSourceDecl {
            kind: "stripe.customer",
            id_field: "customer",
        },
        EvidenceSourceDecl {
            kind: "stripe.payment_method",
            id_field: "payment_method",
        },
    ],
    resolver: EvidenceResolverKind::StripeCreatePaymentIntentOffSession,
};

static STRIPE_CONFIRM_PAYMENT_INTENT_PROFILE: EvidenceProfile = EvidenceProfile {
    id: "stripe.confirm_payment_intent.v1",
    provider: "stripe",
    action: "confirm_payment_intent",
    inputs: &[
        EvidenceInputDecl {
            field: "payment_intent",
            ty: ScalarKind::Str,
        },
        EvidenceInputDecl {
            field: "payment_method",
            ty: ScalarKind::Str,
        },
    ],
    outputs: &[
        EvidenceOutputDecl {
            field: "account",
            ty: ScalarKind::Str,
            source: "stripe.authenticated_account.id",
        },
        EvidenceOutputDecl {
            field: "mode",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.livemode",
        },
        EvidenceOutputDecl {
            field: "currency",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.currency",
        },
        EvidenceOutputDecl {
            field: "customer",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.customer",
        },
        EvidenceOutputDecl {
            field: "amount",
            ty: ScalarKind::Int,
            source: "stripe.payment_intent.amount",
        },
        EvidenceOutputDecl {
            field: "status",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.status",
        },
        EvidenceOutputDecl {
            field: "capture_method",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.capture_method",
        },
        EvidenceOutputDecl {
            field: "confirmation_method",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.confirmation_method",
        },
    ],
    sources: &[
        EvidenceSourceDecl {
            kind: "stripe.payment_intent",
            id_field: "payment_intent",
        },
        EvidenceSourceDecl {
            kind: "stripe.payment_method",
            id_field: "payment_method",
        },
    ],
    resolver: EvidenceResolverKind::StripeConfirmPaymentIntent,
};

static STRIPE_CAPTURE_PAYMENT_INTENT_PROFILE: EvidenceProfile = EvidenceProfile {
    id: "stripe.capture_payment_intent.v1",
    provider: "stripe",
    action: "capture_payment_intent",
    inputs: &[
        EvidenceInputDecl {
            field: "payment_intent",
            ty: ScalarKind::Str,
        },
        EvidenceInputDecl {
            field: "amount",
            ty: ScalarKind::Int,
        },
    ],
    outputs: &[
        EvidenceOutputDecl {
            field: "account",
            ty: ScalarKind::Str,
            source: "stripe.authenticated_account.id",
        },
        EvidenceOutputDecl {
            field: "mode",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.livemode",
        },
        EvidenceOutputDecl {
            field: "currency",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.currency",
        },
        EvidenceOutputDecl {
            field: "customer",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.customer",
        },
        EvidenceOutputDecl {
            field: "status",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.status",
        },
        EvidenceOutputDecl {
            field: "capture_method",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.capture_method",
        },
        EvidenceOutputDecl {
            field: "intent_amount",
            ty: ScalarKind::Int,
            source: "stripe.payment_intent.amount",
        },
        EvidenceOutputDecl {
            field: "amount_capturable",
            ty: ScalarKind::Int,
            source: "stripe.payment_intent.amount_capturable",
        },
    ],
    sources: &[EvidenceSourceDecl {
        kind: "stripe.payment_intent",
        id_field: "payment_intent",
    }],
    resolver: EvidenceResolverKind::StripeCapturePaymentIntent,
};

static STRIPE_CANCEL_PAYMENT_INTENT_PROFILE: EvidenceProfile = EvidenceProfile {
    id: "stripe.cancel_payment_intent.v1",
    provider: "stripe",
    action: "cancel_payment_intent",
    inputs: &[EvidenceInputDecl {
        field: "payment_intent",
        ty: ScalarKind::Str,
    }],
    outputs: &[
        EvidenceOutputDecl {
            field: "account",
            ty: ScalarKind::Str,
            source: "stripe.authenticated_account.id",
        },
        EvidenceOutputDecl {
            field: "mode",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.livemode",
        },
        EvidenceOutputDecl {
            field: "currency",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.currency",
        },
        EvidenceOutputDecl {
            field: "customer",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.customer",
        },
        EvidenceOutputDecl {
            field: "amount",
            ty: ScalarKind::Int,
            source: "stripe.payment_intent.cancelable_amount",
        },
        EvidenceOutputDecl {
            field: "status",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.status",
        },
        EvidenceOutputDecl {
            field: "capture_method",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.capture_method",
        },
        EvidenceOutputDecl {
            field: "confirmation_method",
            ty: ScalarKind::Str,
            source: "stripe.payment_intent.confirmation_method",
        },
    ],
    sources: &[EvidenceSourceDecl {
        kind: "stripe.payment_intent",
        id_field: "payment_intent",
    }],
    resolver: EvidenceResolverKind::StripeCancelPaymentIntent,
};

static STRIPE_RETRY_INVOICE_PAYMENT_PROFILE: EvidenceProfile = EvidenceProfile {
    id: "stripe.retry_invoice_payment.v1",
    provider: "stripe",
    action: "retry_invoice_payment",
    inputs: &[
        EvidenceInputDecl {
            field: "invoice",
            ty: ScalarKind::Str,
        },
        EvidenceInputDecl {
            field: "payment_method",
            ty: ScalarKind::Str,
        },
    ],
    outputs: &[
        EvidenceOutputDecl {
            field: "account",
            ty: ScalarKind::Str,
            source: "stripe.authenticated_account.id",
        },
        EvidenceOutputDecl {
            field: "mode",
            ty: ScalarKind::Str,
            source: "stripe.invoice.livemode",
        },
        EvidenceOutputDecl {
            field: "currency",
            ty: ScalarKind::Str,
            source: "stripe.invoice.currency",
        },
        EvidenceOutputDecl {
            field: "customer",
            ty: ScalarKind::Str,
            source: "stripe.invoice.customer",
        },
        EvidenceOutputDecl {
            field: "amount",
            ty: ScalarKind::Int,
            source: "stripe.invoice.amount_remaining",
        },
        EvidenceOutputDecl {
            field: "status",
            ty: ScalarKind::Str,
            source: "stripe.invoice.status",
        },
    ],
    sources: &[
        EvidenceSourceDecl {
            kind: "stripe.invoice",
            id_field: "invoice",
        },
        EvidenceSourceDecl {
            kind: "stripe.payment_method",
            id_field: "payment_method",
        },
    ],
    resolver: EvidenceResolverKind::StripeRetryInvoicePayment,
};

static STRIPE_REFUND_CHARGE_BOUNDED_PROFILE: EvidenceProfile = EvidenceProfile {
    id: "stripe.refund_charge_bounded.v1",
    provider: "stripe",
    action: "refund_charge_bounded",
    inputs: &[
        EvidenceInputDecl {
            field: "charge",
            ty: ScalarKind::Str,
        },
        EvidenceInputDecl {
            field: "amount",
            ty: ScalarKind::Int,
        },
    ],
    outputs: &[
        EvidenceOutputDecl {
            field: "account",
            ty: ScalarKind::Str,
            source: "stripe.authenticated_account.id",
        },
        EvidenceOutputDecl {
            field: "mode",
            ty: ScalarKind::Str,
            source: "stripe.charge.livemode",
        },
        EvidenceOutputDecl {
            field: "currency",
            ty: ScalarKind::Str,
            source: "stripe.charge.currency",
        },
    ],
    sources: &[EvidenceSourceDecl {
        kind: "stripe.charge",
        id_field: "charge",
    }],
    resolver: EvidenceResolverKind::StripeRefundChargeBounded,
};

static STRIPE_CREATE_STANDARD_PAYOUT_PROFILE: EvidenceProfile = EvidenceProfile {
    id: "stripe.create_standard_payout.v1",
    provider: "stripe",
    action: "create_standard_payout",
    inputs: &[
        EvidenceInputDecl {
            field: "amount",
            ty: ScalarKind::Int,
        },
        EvidenceInputDecl {
            field: "destination",
            ty: ScalarKind::Str,
        },
        EvidenceInputDecl {
            field: "source_type",
            ty: ScalarKind::Str,
        },
    ],
    outputs: &[
        EvidenceOutputDecl {
            field: "account",
            ty: ScalarKind::Str,
            source: "stripe.authenticated_account.id",
        },
        EvidenceOutputDecl {
            field: "mode",
            ty: ScalarKind::Str,
            source: "stripe.balance.livemode",
        },
        EvidenceOutputDecl {
            field: "currency",
            ty: ScalarKind::Str,
            source: "stripe.external_account.currency",
        },
    ],
    sources: &[EvidenceSourceDecl {
        kind: "stripe.external_account",
        id_field: "destination",
    }],
    resolver: EvidenceResolverKind::StripeCreateStandardPayout,
};

/// Look up one trusted, versioned profile. The profile id selects exact compiled semantics, never a
/// template-authored resolver language.
pub fn profile(id: &str) -> Option<&'static EvidenceProfile> {
    let production = [
        &STRIPE_CREATE_PAYMENT_INTENT_OFF_SESSION_PROFILE,
        &STRIPE_CONFIRM_PAYMENT_INTENT_PROFILE,
        &STRIPE_CAPTURE_PAYMENT_INTENT_PROFILE,
        &STRIPE_CANCEL_PAYMENT_INTENT_PROFILE,
        &STRIPE_RETRY_INVOICE_PAYMENT_PROFILE,
        &STRIPE_REFUND_CHARGE_BOUNDED_PROFILE,
        &STRIPE_CREATE_STANDARD_PAYOUT_PROFILE,
    ];
    if let Some(profile) = production.into_iter().find(|profile| profile.id == id) {
        return Some(profile);
    }
    #[cfg(any(test, feature = "test-double"))]
    if id == STRIPE_TEST_CHARGE_PROFILE.id {
        return Some(&STRIPE_TEST_CHARGE_PROFILE);
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSource {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct ResolvedEvidence {
    pub fields: BTreeMap<String, Scalar>,
    pub sources: Vec<EvidenceSource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceFailureClass {
    CredentialUnavailable,
    ProviderAuthentication,
    ProviderDenied,
    ProviderNotFound,
    RateLimited,
    ProviderUnavailable,
    Malformed,
    Ambiguous,
    Mismatch,
    Stale,
    Integrity,
}

impl EvidenceFailureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CredentialUnavailable => "credential_unavailable",
            Self::ProviderAuthentication => "provider_authentication",
            Self::ProviderDenied => "provider_denied",
            Self::ProviderNotFound => "provider_not_found",
            Self::RateLimited => "rate_limited",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::Malformed => "malformed",
            Self::Ambiguous => "ambiguous",
            Self::Mismatch => "mismatch",
            Self::Stale => "stale",
            Self::Integrity => "integrity",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceFailure {
    pub class: EvidenceFailureClass,
    pub http_status: Option<u16>,
}

impl EvidenceFailure {
    pub fn new(class: EvidenceFailureClass) -> Self {
        Self {
            class,
            http_status: None,
        }
    }

    pub fn status(class: EvidenceFailureClass, status: u16) -> Self {
        Self {
            class,
            http_status: Some(status),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeField {
    pub source: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeSource {
    pub id: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderResolvedEnvelope {
    pub version: u8,
    pub credential_generation: String,
    pub fields: BTreeMap<String, EnvelopeField>,
    pub mint_deadline_epoch: i64,
    pub oldest_observed_at_epoch: i64,
    pub profile: String,
    pub profile_fingerprint: String,
    pub receipt_event_hash: String,
    pub receipt_id: String,
    pub resolution_digest: String,
    pub sources: Vec<EnvelopeSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum EvidenceEnvelope {
    #[serde(rename = "none")]
    None { version: u8 },
    #[serde(rename = "provider_resolved")]
    ProviderResolved(Box<ProviderResolvedEnvelope>),
}

impl EvidenceEnvelope {
    pub fn none() -> Self {
        Self::None {
            version: EVIDENCE_ENVELOPE_VERSION,
        }
    }

    pub fn to_canonical_json(&self) -> String {
        canonical_json(&serde_json::to_value(self).expect("evidence envelope serializes"))
    }

    pub fn from_canonical_json(json: &str) -> Result<Self, String> {
        let value: Value = serde_json::from_str(json)
            .map_err(|error| format!("evidence envelope is not valid JSON: {error}"))?;
        if canonical_json(&value) != json {
            return Err("evidence envelope is not canonical JSON".into());
        }
        let envelope: Self = serde_json::from_value(value)
            .map_err(|error| format!("evidence envelope has an invalid shape: {error}"))?;
        match &envelope {
            Self::None {
                version: EVIDENCE_ENVELOPE_VERSION,
            } => Ok(envelope),
            Self::ProviderResolved(payload) if payload.version == EVIDENCE_ENVELOPE_VERSION => {
                Ok(envelope)
            }
            _ => Err("evidence envelope has an unsupported version".into()),
        }
    }

    pub fn profile_id(&self) -> Option<&str> {
        match self {
            Self::None { .. } => None,
            Self::ProviderResolved(payload) => Some(&payload.profile),
        }
    }

    pub fn credential_generation(&self) -> Option<&str> {
        match self {
            Self::None { .. } => None,
            Self::ProviderResolved(payload) => Some(&payload.credential_generation),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn resolution_digest(
    request_id: &str,
    provider: &str,
    action: &str,
    profile: &str,
    profile_fingerprint: &str,
    template_hash: &str,
    descriptor_hash: &str,
    credential_generation: &str,
    oldest_observed_at_epoch: i64,
    mint_deadline_epoch: i64,
    fields: &BTreeMap<String, EnvelopeField>,
    sources: &[EnvelopeSource],
) -> String {
    use sha2::{Digest, Sha256};
    let value = serde_json::json!({
        "action": action,
        "credential_generation": credential_generation,
        "descriptor_hash": descriptor_hash,
        "fields": fields,
        "mint_deadline_epoch": mint_deadline_epoch,
        "oldest_observed_at_epoch": oldest_observed_at_epoch,
        "profile": profile,
        "profile_fingerprint": profile_fingerprint,
        "provider": provider,
        "request_id": request_id,
        "sources": sources,
        "template_hash": template_hash,
    });
    let mut hash = Sha256::new();
    hash.update(EVIDENCE_RESOLUTION_DIGEST_DOMAIN);
    hash.update(canonical_json(&value).as_bytes());
    format!("sha256:{}", crate::util::hex(&hash.finalize()))
}

pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("JSON key serializes"),
                        canonical_json(&map[key])
                    )
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        scalar => serde_json::to_string(scalar).expect("JSON scalar serializes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moneypath_none_envelope_is_canonical_and_versioned() {
        let json = EvidenceEnvelope::none().to_canonical_json();
        assert_eq!(json, r#"{"kind":"none","version":1}"#);
        assert_eq!(
            EvidenceEnvelope::from_canonical_json(&json).unwrap(),
            EvidenceEnvelope::none()
        );
        assert!(EvidenceEnvelope::from_canonical_json(r#"{"version":1,"kind":"none"}"#).is_err());
    }

    #[test]
    fn moneypath_resolution_digest_excludes_receipt_identity() {
        let fields = BTreeMap::from([(
            "account".into(),
            EnvelopeField {
                source: "stripe.charge.account".into(),
                value: serde_json::json!("acct_test"),
            },
        )]);
        let sources = vec![EnvelopeSource {
            id: "ch_ok".into(),
            kind: "stripe.charge".into(),
        }];
        let digest = resolution_digest(
            "req_1",
            "stripe",
            "test_charge_evidence",
            "stripe.test_charge.v1",
            "sha256:profile",
            "tpl",
            "desc",
            "sha256:gen",
            100,
            130,
            &fields,
            &sources,
        );
        let make = |receipt: &str| {
            EvidenceEnvelope::ProviderResolved(Box::new(ProviderResolvedEnvelope {
                version: 1,
                credential_generation: "sha256:gen".into(),
                fields: fields.clone(),
                mint_deadline_epoch: 130,
                oldest_observed_at_epoch: 100,
                profile: "stripe.test_charge.v1".into(),
                profile_fingerprint: "sha256:profile".into(),
                receipt_event_hash: "event_hash".into(),
                receipt_id: receipt.into(),
                resolution_digest: digest.clone(),
                sources: sources.clone(),
            }))
        };
        assert_ne!(
            make("evt_a").to_canonical_json(),
            make("evt_b").to_canonical_json()
        );
        assert_eq!(
            match make("evt_b") {
                EvidenceEnvelope::ProviderResolved(payload) => payload.resolution_digest,
                _ => unreachable!(),
            },
            digest
        );
    }

    #[test]
    fn moneypath_profile_fingerprint_is_deterministic_and_structural() {
        let baseline = STRIPE_TEST_CHARGE_PROFILE.semantics_fingerprint();
        assert_eq!(baseline, STRIPE_TEST_CHARGE_PROFILE.semantics_fingerprint());
        assert!(baseline.starts_with("sha256:"));

        let mut changed_outputs = STRIPE_TEST_CHARGE_PROFILE.outputs.to_vec();
        changed_outputs[0].source = "stripe.charge.account";
        let changed = EvidenceProfile {
            id: STRIPE_TEST_CHARGE_PROFILE.id,
            provider: STRIPE_TEST_CHARGE_PROFILE.provider,
            action: STRIPE_TEST_CHARGE_PROFILE.action,
            inputs: STRIPE_TEST_CHARGE_PROFILE.inputs,
            outputs: Box::leak(changed_outputs.into_boxed_slice()),
            sources: STRIPE_TEST_CHARGE_PROFILE.sources,
            resolver: STRIPE_TEST_CHARGE_PROFILE.resolver,
        };
        assert_ne!(baseline, changed.semantics_fingerprint());
    }

    #[test]
    fn moneypath_production_profile_fingerprints_bind_resolver_and_inert_shape_sources() {
        let ids = [
            "stripe.create_payment_intent_off_session.v1",
            "stripe.confirm_payment_intent.v1",
            "stripe.capture_payment_intent.v1",
            "stripe.cancel_payment_intent.v1",
            "stripe.retry_invoice_payment.v1",
            "stripe.refund_charge_bounded.v1",
            "stripe.create_standard_payout.v1",
        ];
        let fingerprints = ids
            .iter()
            .map(|id| {
                let profile = profile(id).unwrap();
                let actual = profile.semantics_fingerprint();
                assert!(actual.starts_with("sha256:"));
                assert_ne!(
                    actual,
                    profile.semantics_fingerprint_for_implementation_source(
                        b"different resolver implementation"
                    ),
                    "{id} did not bind implementation source"
                );
                assert_ne!(
                    actual,
                    profile.semantics_fingerprint_for_inert_shape_source(
                        b"different inert-shape implementation"
                    ),
                    "{id} did not bind inert-shape source"
                );
                actual
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(fingerprints.len(), ids.len());
    }
}
