//! Keyless action-catalog types and contract projection.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::contract::{ActionContract, AllowBinding, FieldClass, FieldDecl, ScalarKind};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub required: bool,
    pub class: String,
    pub binding: String,
    pub origin: String,
    /// The predicate forms a sentence may use on this field, in the fixed order
    /// `= in <= >= budget`. Computed daemon-side from the field's own `FieldDecl` via
    /// [`FieldDecl::admissible_forms`], so both catalog surfaces render one derived answer and
    /// neither holds a second copy of the grammar's type rules. Empty means no sentence may
    /// constrain the field at all.
    pub forms: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogShape {
    HttpInlineUpload,
    HttpApiCall,
    /// The subprocess execution shape: the client's own packfile, arriving over the attested git
    /// stream, is carried to a pinned git remote by the hermetic system-git seam, advancing one
    /// ref. Which ref NAMESPACE a verb moves (a branch, a tag) is the verb's own vocabulary; the
    /// execution shape is the same.
    GitPush,
    /// The verb credentials a native client's own requests through the loopback relay instead of
    /// constructing any request itself.
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub provider: String,
    pub action: String,
    pub fields: Vec<CatalogField>,
    pub execution_targets: Vec<String>,
    pub requestable: bool,
    pub shape: CatalogShape,
    #[serde(default)]
    pub sentence_denied: bool,
    /// The canonical text of every standing ALLOW sentence that selects this verb — selector AND
    /// bounds, which is what a request must fit. NO rule numbers: a rule has no positional
    /// identity, the sentence text IS its name. Numbers survive only as `cermet rules` list
    /// indices, operator-side, for `revoke <n>`.
    /// PRESENTATION ONLY: authority is decided daemon-side, per request, at request time.
    #[serde(default)]
    pub admitted_by: Vec<String>,
    /// The canonical text of every standing DENY sentence that selects this verb. A join
    /// over allows alone told two lies: an explicitly denied verb read as "no standing rule" (and
    /// promised a widening suggestion that `evaluate_with_widen_hint` yields None for by design),
    /// and a carve-out deny under a live allow was invisible — the surface overstated capability.
    /// Non-empty WITH `admitted_by` non-empty and `sentence_denied` clear is the carve-out shape.
    #[serde(default)]
    pub denied_by: Vec<String>,
    pub response: ResponseContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseContract {
    pub returns: String,
    pub retention: String,
    pub errors: String,
}

impl ResponseContract {
    pub fn http() -> Self {
        Self {
            returns: "verbatim".to_string(),
            retention: "full".to_string(),
            errors: "status_and_body".to_string(),
        }
    }

    pub fn summary(&self) -> String {
        let returns = match self.returns.as_str() {
            "verbatim" => "returns the provider's response verbatim",
            "query_table" => "returns a bounded {columns, rows, row_count, truncated} table",
            "receipt" => "returns a metadata receipt (no provider body exists)",
            other => return format!("returns `{other}`"),
        };
        let stored = if self.retention == "none" {
            "nothing is stored as an artifact"
        } else {
            "the full response is stored as an artifact"
        };
        let errors = match self.errors.as_str() {
            "status_and_body" => {
                "on an error you get the HTTP status plus the provider's error body"
            }
            "status_and_body_or_verdict" => {
                "on an error you get the HTTP status plus the provider's error body, or — for a \
                 provider-declared failure at HTTP 200 — that body with the verdict beside it"
            }
            "receipt" => "a failure returns the same receipt with a failure block",
            "refusal" => {
                "a refused or failed statement is an execution error, never an empty result"
            }
            other => return format!("{returns}; {stored}; errors: `{other}`"),
        };
        format!("{returns}; {stored}; {errors}")
    }
}

pub const VENDORED_CATALOG: &[&str] = &[
    include_str!("../../cermet-core/actions/github.read_repo.yaml"),
    include_str!("../../cermet-core/actions/github.read_ref.yaml"),
    include_str!("../../cermet-core/actions/github.read_commit.yaml"),
    include_str!("../../cermet-core/actions/github.read_tree.yaml"),
    include_str!("../../cermet-core/actions/github.read_blob.yaml"),
    include_str!("../../cermet-core/actions/github.read_thread.yaml"),
    include_str!("../../cermet-core/actions/github.read_pull_request.yaml"),
    include_str!("../../cermet-core/actions/github.read_workflow_run.yaml"),
    include_str!("../../cermet-core/actions/github.read_workflow_run_jobs.yaml"),
    include_str!("../../cermet-core/actions/github.read_job_log.yaml"),
    include_str!("../../cermet-core/actions/github.read_releases.yaml"),
    include_str!("../../cermet-core/actions/github.read_workflow_runs.yaml"),
    include_str!("../../cermet-core/actions/github.publish_release.yaml"),
    include_str!("../../cermet-core/actions/github.push.yaml"),
    include_str!("../../cermet-core/actions/github.push_tag.yaml"),
    include_str!("../../cermet-core/actions/github.fetch.yaml"),
    include_str!("../../cermet-core/actions/github.create_issue.yaml"),
    include_str!("../../cermet-core/actions/github.comment_thread.yaml"),
    include_str!("../../cermet-core/actions/github.create_branch.yaml"),
    include_str!("../../cermet-core/actions/github.create_pull_request_review.yaml"),
    include_str!("../../cermet-core/actions/github.request_workflow_cancel.yaml"),
    include_str!("../../cermet-core/actions/github.dispatch_workflow.yaml"),
    include_str!("../../cermet-core/actions/github.request_deployment.yaml"),
    include_str!("../../cermet-core/actions/github.create_pull_request.yaml"),
    include_str!("../../cermet-core/actions/github.merge_pull_request.yaml"),
    include_str!("../../cermet-core/actions/github.update_pull_request.yaml"),
    include_str!("../../cermet-core/actions/github.read_secret_scanning_alerts_open.yaml"),
    // The first `execution: relay` verb.
    include_str!("../../cermet-core/actions/vercel.deploy.yaml"),
    include_str!("../../cermet-core/actions/vercel.list_projects.yaml"),
    include_str!("../../cermet-core/actions/stripe.search_customers.yaml"),
    include_str!("../../cermet-core/actions/stripe.lookup_customer.yaml"),
    include_str!("../../cermet-core/actions/stripe.list_charges.yaml"),
    include_str!("../../cermet-core/actions/stripe.get_charge.yaml"),
    include_str!("../../cermet-core/actions/stripe.list_refunds.yaml"),
    include_str!("../../cermet-core/actions/stripe.get_subscription.yaml"),
    include_str!("../../cermet-core/actions/stripe.refund.yaml"),
    include_str!("../../cermet-core/actions/stripe.credit_balance.yaml"),
    include_str!("../../cermet-core/actions/stripe.pause_subscription.yaml"),
    include_str!("../../cermet-core/actions/stripe.cancel_subscription.yaml"),
    include_str!("../../cermet-core/actions/stripe.get_invoice.yaml"),
    include_str!("../../cermet-core/actions/stripe.list_invoices_for_customer.yaml"),
    include_str!("../../cermet-core/actions/stripe.get_payment_intent.yaml"),
    include_str!("../../cermet-core/actions/stripe.get_dispute_summary.yaml"),
    include_str!("../../cermet-core/actions/stripe.get_product.yaml"),
    include_str!("../../cermet-core/actions/stripe.get_price.yaml"),
    include_str!("../../cermet-core/actions/stripe.list_active_prices.yaml"),
    include_str!("../../cermet-core/actions/stripe.cancel_subscription_at_period_end.yaml"),
    include_str!("../../cermet-core/actions/stripe.resume_subscription_collection.yaml"),
    include_str!("../../cermet-core/actions/stripe.mark_invoice_uncollectible.yaml"),
    include_str!("../../cermet-core/actions/stripe.issue_credit_note_adjustment_no_email.yaml"),
    include_str!("../../cermet-core/actions/stripe.archive_product.yaml"),
    include_str!("../../cermet-core/actions/stripe.archive_price.yaml"),
    include_str!("../../cermet-core/actions/stripe.stage_dispute_evidence.yaml"),
    include_str!("../../cermet-core/actions/stripe.submit_dispute_evidence.yaml"),
    include_str!("../../cermet-core/actions/stripe.update_webhook_endpoint_fixed_bundle.yaml"),
    include_str!("../../cermet-core/actions/stripe.create_payment_intent_off_session.yaml"),
    include_str!("../../cermet-core/actions/stripe.confirm_payment_intent.yaml"),
    include_str!("../../cermet-core/actions/stripe.capture_payment_intent.yaml"),
    include_str!("../../cermet-core/actions/stripe.cancel_payment_intent.yaml"),
    include_str!("../../cermet-core/actions/stripe.retry_invoice_payment.yaml"),
    include_str!("../../cermet-core/actions/stripe.refund_charge_bounded.yaml"),
    include_str!("../../cermet-core/actions/stripe.create_standard_payout.yaml"),
    include_str!("../../cermet-core/actions/stripe.create_customer.yaml"),
    include_str!("../../cermet-core/actions/stripe.create_product.yaml"),
    include_str!("../../cermet-core/actions/stripe.create_recurring_price.yaml"),
    include_str!("../../cermet-core/actions/stripe.create_draft_invoice.yaml"),
    include_str!("../../cermet-core/actions/stripe.attach_payment_method.yaml"),
    include_str!("../../cermet-core/actions/stripe.create_subscription.yaml"),
    include_str!("../../cermet-core/actions/stripe.create_charge_from_source.yaml"),
    include_str!("../../cermet-core/actions/stripe.list_disputes.yaml"),
    include_str!("../../cermet-core/actions/stripe.read_account.yaml"),
];

#[derive(Deserialize)]
struct ContractDocument {
    provider: String,
    action: String,
    fields: Vec<ContractField>,
    consumes: Vec<String>,
    execution_targets: Vec<String>,
    /// Present for the HTTP execution kind. Absent for the subprocess (`git:`) kind, whose response
    /// contract is a broker-authored receipt with nothing retained, and absent for a relay verb,
    /// which constructs no request and so declares no steps.
    #[serde(default)]
    http: Option<HttpDocument>,
    #[serde(default)]
    git: Option<serde_yaml::Value>,
}

#[derive(Deserialize)]
struct ContractField {
    name: String,
    #[serde(rename = "type")]
    ty: String,
    required: bool,
    class: String,
    binding: String,
}

#[derive(Deserialize)]
struct HttpDocument {
    steps: Vec<HttpStep>,
}

#[derive(Deserialize)]
struct HttpStep {
    #[serde(default)]
    retention: Retention,
    #[serde(default)]
    graphql_query: Option<String>,
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Retention {
    #[default]
    Full,
    None,
}

fn leak(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

fn contract_from_document(document: ContractDocument) -> &'static ActionContract {
    let fields = document
        .fields
        .into_iter()
        .map(|field| {
            let class = match field.class.as_str() {
                "identity" => FieldClass::Identity,
                "side_effect" => FieldClass::SideEffect,
                "free_payload" => FieldClass::FreePayload,
                "secret" => FieldClass::Secret,
                "read_filter" => FieldClass::ReadFilter,
                other => panic!("unknown vendored field class {other}"),
            };
            FieldDecl {
                name: leak(field.name),
                ty: match field.ty.as_str() {
                    "str" => ScalarKind::Str,
                    "int" => ScalarKind::Int,
                    "bool" => ScalarKind::Bool,
                    other => panic!("unknown vendored field type {other}"),
                },
                required: field.required,
                class,
                binding: match field.binding.as_str() {
                    "unbound" => AllowBinding::Unbound,
                    "exact_resource_pin" => AllowBinding::ExactResourcePin,
                    "exact_or_pattern_list" => AllowBinding::ExactOrPatternList("names"),
                    "bounded" => AllowBinding::Bounded,
                    other => panic!("unknown vendored field binding {other}"),
                },
            }
        })
        .collect::<Vec<_>>();
    Box::leak(Box::new(ActionContract {
        provider: leak(document.provider),
        action: leak(document.action),
        schema: Box::leak(fields.into_boxed_slice()),
        consumes: Box::leak(
            document
                .consumes
                .into_iter()
                .map(leak)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
        execution_targets: Box::leak(
            document
                .execution_targets
                .into_iter()
                .map(leak)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
        relations: &[],
        open: false,
    }))
}

pub fn vendored_contract(provider: &str, action: &str) -> Option<&'static ActionContract> {
    static CONTRACTS: OnceLock<HashMap<(String, String), &'static ActionContract>> =
        OnceLock::new();
    CONTRACTS
        .get_or_init(|| {
            VENDORED_CATALOG
                .iter()
                .map(|text| {
                    let document: ContractDocument =
                        serde_yaml::from_str(text).expect("vendored action document must parse");
                    let key = (document.provider.clone(), document.action.clone());
                    (key, contract_from_document(document))
                })
                .collect()
        })
        .get(&(provider.to_string(), action.to_string()))
        .copied()
}

pub fn vendored_response_contract(provider: &str, action: &str) -> Option<ResponseContract> {
    static RESPONSES: OnceLock<HashMap<(String, String), ResponseContract>> = OnceLock::new();
    RESPONSES
        .get_or_init(|| {
            VENDORED_CATALOG
                .iter()
                .map(|text| {
                    let document: ContractDocument =
                        serde_yaml::from_str(text).expect("vendored action document must parse");
                    if document.git.is_some() {
                        let response = ResponseContract {
                            returns: "receipt".to_string(),
                            retention: "none".to_string(),
                            errors: "refusal".to_string(),
                        };
                        return ((document.provider, document.action), response);
                    }
                    // A relay verb declares no steps: it opens a predicate-bounded session and
                    // returns the metadata receipt naming it.
                    let Some(http) = document.http.as_ref() else {
                        let response = ResponseContract {
                            returns: "receipt".to_string(),
                            retention: "none".to_string(),
                            errors: "receipt".to_string(),
                        };
                        return ((document.provider, document.action), response);
                    };
                    let terminal = http.steps.last();
                    let response = ResponseContract {
                        returns: "verbatim".to_string(),
                        retention:
                            if terminal.is_some_and(|step| step.retention == Retention::None) {
                                "none"
                            } else {
                                "full"
                            }
                            .to_string(),
                        errors: if terminal.is_some_and(|step| step.graphql_query.is_some()) {
                            "status_and_body_or_verdict"
                        } else {
                            "status_and_body"
                        }
                        .to_string(),
                    };
                    ((document.provider, document.action), response)
                })
                .collect()
        })
        .get(&(provider.to_string(), action.to_string()))
        .cloned()
}
