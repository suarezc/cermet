use std::collections::BTreeMap;

use cermet_core::{
    SourceRegistry, SourceRegistryError, MAX_SOURCE_REGISTRY_BYTES, SOURCE_REGISTRY_SCHEMA,
};

const RECHECKED_AT: &str = "2026-07-19";
const STRIPE_RECHECKED_AT: &str = "2026-07-23";
/// The creation vocabulary reviewed with the setup-verb batch.
const STRIPE_SETUP_RECHECKED_AT: &str = "2026-08-25";
const STRIPE_SETUP_SOURCES: &[&str] = &[
    "STRIPE-CUSTOMER-CREATE",
    "STRIPE-PRODUCT-CREATE",
    "STRIPE-PRICE-CREATE",
    "STRIPE-INVOICE-CREATE",
    "STRIPE-WEBHOOK-CREATE",
    "STRIPE-PAYMENT-METHOD-ATTACH",
    "STRIPE-SUBSCRIPTION-CREATE",
    "STRIPE-CHARGE-CREATE",
    "STRIPE-DISPUTE-LIST",
    "STRIPE-TEST-TOKENS",
];
/// The invoice-finalize and webhook list/delete references, read the day those verbs landed.
const STRIPE_LIFECYCLE_RECHECKED_AT: &str = "2026-08-26";
const STRIPE_LIFECYCLE_SOURCES: &[&str] = &[
    "STRIPE-INVOICE-FINALIZE",
    "STRIPE-WEBHOOK-DELETE",
    "STRIPE-WEBHOOK-LIST",
];
/// A source added after its batch keeps its OWN review date — the date means "these docs were read
/// on this day", so back-dating a later addition into the batch date would be a small lie.
const GIT_COMMITS_RECHECKED_AT: &str = "2026-07-28";
/// The git-native carrier's own source, read the day the seam landed.
const GIT_REMOTES_RECHECKED_AT: &str = "2026-07-29";
/// The Vercel relay reviewed the Vercel API/CLI references on its own day.
const VERCEL_RECHECKED_AT: &str = "2026-07-29";
/// vercel.list_projects (scope: account read) reviewed its endpoint reference on its own day.
const VERCEL_LIST_RECHECKED_AT: &str = "2026-07-30";
/// `github.dispatch_workflow` cites the Actions *workflows* reference — the workflow-runs page
/// documents the run, not the dispatch event that creates one — read the day the verb landed.
const WORKFLOWS_RECHECKED_AT: &str = "2026-08-17";
/// `github.read_workflow_run_jobs` cites the Actions *workflow-jobs* reference — a run's job list
/// and per-step conclusions are that page's subject, not the workflow-runs page's — read the day
/// the diagnosis verb landed.
const WORKFLOW_JOBS_RECHECKED_AT: &str = "2026-08-17";
/// The release verbs (`read_releases`, `publish_release`) cite the REST releases reference — read
/// the day the release plane landed.
const RELEASES_RECHECKED_AT: &str = "2026-08-25";

const PLAN_SOURCES: &[(&str, &str)] = &[
    (
        "GH-REST-API-VERSIONS",
        "https://docs.github.com/en/rest/about-the-rest-api/api-versions",
    ),
    (
        "GH-APP-INSTALLATION-ACCESS-TOKEN",
        "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app",
    ),
    (
        "GH-PERSONAL-ACCESS-TOKENS",
        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
    ),
    (
        "GH-ACTIONS-AUTOMATIC-TOKEN",
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication",
    ),
    (
        "GH-GRAPHQL-CREATE-COMMIT",
        "https://docs.github.com/en/graphql/reference/mutations#createcommitonbranch",
    ),
    (
        "GH-GIT-HTTPS-REMOTES",
        "https://docs.github.com/en/get-started/git-basics/about-remote-repositories",
    ),
    (
        "GH-REST-REPOSITORY-CONTENTS",
        "https://docs.github.com/en/rest/repos/contents",
    ),
    (
        "GH-REST-GIT-REFERENCES",
        "https://docs.github.com/en/rest/git/refs",
    ),
    (
        "GH-REST-GIT-COMMITS",
        "https://docs.github.com/en/rest/git/commits",
    ),
    (
        "GH-REST-GIT-TREES",
        "https://docs.github.com/en/rest/git/trees",
    ),
    (
        "GH-REST-GIT-BLOBS",
        "https://docs.github.com/en/rest/git/blobs",
    ),
    ("GH-REST-ISSUES", "https://docs.github.com/en/rest/issues"),
    (
        "GH-REST-PULL-REQUESTS",
        "https://docs.github.com/en/rest/pulls",
    ),
    (
        "GH-REST-PULL-REQUEST-REVIEWS",
        "https://docs.github.com/en/rest/pulls/reviews",
    ),
    (
        "GH-REST-WORKFLOW-RUNS",
        "https://docs.github.com/en/rest/actions/workflow-runs",
    ),
    (
        "GH-REST-WORKFLOWS",
        "https://docs.github.com/en/rest/actions/workflows",
    ),
    (
        "GH-REST-WORKFLOW-JOBS",
        "https://docs.github.com/en/rest/actions/workflow-jobs",
    ),
    (
        "GH-REST-RELEASES",
        "https://docs.github.com/en/rest/releases/releases",
    ),
    (
        "GH-REST-DEPLOYMENTS",
        "https://docs.github.com/en/rest/deployments/deployments",
    ),
    (
        "GH-REST-SECRET-SCANNING",
        "https://docs.github.com/en/rest/secret-scanning/secret-scanning",
    ),
    (
        "GH-REST-ACTIONS-SECRETS",
        "https://docs.github.com/en/rest/actions/secrets",
    ),
    (
        "GH-REST-REPOSITORY-RULES",
        "https://docs.github.com/en/rest/repos/rules",
    ),
    (
        "GH-REST-DEPLOYMENT-ENVIRONMENTS",
        "https://docs.github.com/en/rest/deployments/environments",
    ),
    (
        "GH-REST-BEST-PRACTICES",
        "https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api",
    ),
    (
        "GH-REST-PAGINATION",
        "https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api",
    ),
    (
        "STRIPE-INVOICE-RETRIEVE",
        "https://docs.stripe.com/api/invoices/retrieve",
    ),
    (
        "STRIPE-INVOICE-LIST",
        "https://docs.stripe.com/api/invoices/list",
    ),
    (
        "STRIPE-PAYMENT-INTENT-RETRIEVE",
        "https://docs.stripe.com/api/payment_intents/retrieve",
    ),
    (
        "STRIPE-DISPUTE-RETRIEVE",
        "https://docs.stripe.com/api/disputes/retrieve",
    ),
    (
        "STRIPE-DISPUTE-UPDATE",
        "https://docs.stripe.com/api/disputes/update",
    ),
    (
        "STRIPE-WEBHOOK-UPDATE",
        "https://docs.stripe.com/api/webhook_endpoints/update",
    ),
    (
        "STRIPE-PRODUCT-RETRIEVE",
        "https://docs.stripe.com/api/products/retrieve",
    ),
    (
        "STRIPE-PRICE-RETRIEVE",
        "https://docs.stripe.com/api/prices/retrieve",
    ),
    (
        "STRIPE-PRICE-LIST",
        "https://docs.stripe.com/api/prices/list",
    ),
    (
        "STRIPE-SUBSCRIPTION-UPDATE",
        "https://docs.stripe.com/api/subscriptions/update",
    ),
    (
        "STRIPE-INVOICE-MARK-UNCOLLECTIBLE",
        "https://docs.stripe.com/api/invoices/mark_uncollectible",
    ),
    (
        "STRIPE-CREDIT-NOTE-CREATE",
        "https://docs.stripe.com/api/credit_notes/create",
    ),
    (
        "STRIPE-CREDIT-NOTE-GUIDE",
        "https://docs.stripe.com/billing/invoices/credit-notes#voiding",
    ),
    (
        "STRIPE-CREDIT-NOTE-VOID",
        "https://docs.stripe.com/api/credit_notes/void",
    ),
    (
        "STRIPE-PRODUCT-UPDATE",
        "https://docs.stripe.com/api/products/update",
    ),
    (
        "STRIPE-PRICE-UPDATE",
        "https://docs.stripe.com/api/prices/update",
    ),
    (
        "STRIPE-RESTRICTED-KEYS",
        "https://docs.stripe.com/keys/restricted-api-keys",
    ),
    (
        "STRIPE-APP-PERMISSIONS",
        "https://docs.stripe.com/stripe-apps/reference/permissions",
    ),
    (
        "STRIPE-ACCOUNT-RETRIEVE",
        "https://docs.stripe.com/api/accounts/retrieve",
    ),
    (
        "STRIPE-BALANCE-RETRIEVE",
        "https://docs.stripe.com/api/balance/balance_retrieve",
    ),
    (
        "STRIPE-CHARGE-RETRIEVE",
        "https://docs.stripe.com/api/charges/retrieve",
    ),
    (
        "STRIPE-CUSTOMER-RETRIEVE",
        "https://docs.stripe.com/api/customers/retrieve",
    ),
    (
        "STRIPE-EXTERNAL-ACCOUNT-RETRIEVE",
        "https://docs.stripe.com/api/external_account_bank_accounts/retrieve",
    ),
    (
        "STRIPE-INVOICE-PAY",
        "https://docs.stripe.com/api/invoices/pay",
    ),
    (
        "STRIPE-PAYMENT-INTENT-CREATE",
        "https://docs.stripe.com/api/payment_intents/create",
    ),
    (
        "STRIPE-PAYMENT-INTENT-CONFIRM",
        "https://docs.stripe.com/api/payment_intents/confirm",
    ),
    (
        "STRIPE-PAYMENT-INTENT-CAPTURE",
        "https://docs.stripe.com/api/payment_intents/capture",
    ),
    (
        "STRIPE-PAYMENT-INTENT-CANCEL",
        "https://docs.stripe.com/api/payment_intents/cancel",
    ),
    (
        "STRIPE-PAYMENT-METHOD-RETRIEVE",
        "https://docs.stripe.com/api/payment_methods/retrieve",
    ),
    (
        "STRIPE-REFUND-CREATE",
        "https://docs.stripe.com/api/refunds/create",
    ),
    (
        "STRIPE-PAYOUT-CREATE",
        "https://docs.stripe.com/api/payouts/create",
    ),
    (
        "STRIPE-CUSTOMER-CREATE",
        "https://docs.stripe.com/api/customers/create",
    ),
    (
        "STRIPE-PRODUCT-CREATE",
        "https://docs.stripe.com/api/products/create",
    ),
    (
        "STRIPE-PRICE-CREATE",
        "https://docs.stripe.com/api/prices/create",
    ),
    (
        "STRIPE-INVOICE-CREATE",
        "https://docs.stripe.com/api/invoices/create",
    ),
    (
        "STRIPE-WEBHOOK-CREATE",
        "https://docs.stripe.com/api/webhook_endpoints/create",
    ),
    (
        "STRIPE-PAYMENT-METHOD-ATTACH",
        "https://docs.stripe.com/api/payment_methods/attach",
    ),
    (
        "STRIPE-SUBSCRIPTION-CREATE",
        "https://docs.stripe.com/api/subscriptions/create",
    ),
    (
        "STRIPE-CHARGE-CREATE",
        "https://docs.stripe.com/api/charges/create",
    ),
    ("STRIPE-DISPUTE-LIST", "https://docs.stripe.com/api/disputes/list"),
    ("STRIPE-TEST-TOKENS", "https://docs.stripe.com/testing"),
    (
        "VERCEL-API-CREATE-DEPLOYMENT",
        "https://vercel.com/docs/rest-api/reference/endpoints/deployments/create-a-new-deployment",
    ),
    (
        "VERCEL-CLI-GLOBAL-OPTIONS",
        "https://vercel.com/docs/cli/global-options",
    ),
    (
        "VERCEL-API-LIST-PROJECTS",
        "https://vercel.com/docs/rest-api/reference/endpoints/projects/retrieve-a-list-of-projects",
    ),
    (
        "STRIPE-INVOICE-FINALIZE",
        "https://docs.stripe.com/api/invoices/finalize",
    ),
    (
        "STRIPE-WEBHOOK-DELETE",
        "https://docs.stripe.com/api/webhook_endpoints/delete",
    ),
    (
        "STRIPE-WEBHOOK-LIST",
        "https://docs.stripe.com/api/webhook_endpoints/list",
    ),
];

fn document(id: &str, url: &str, rechecked_at: &str) -> String {
    format!(
        "schema: {SOURCE_REGISTRY_SCHEMA}\nsources:\n  - id: {id}\n    url: {url}\n    rechecked_at: '{rechecked_at}'\n"
    )
}

#[test]
fn official_registry_is_the_exact_plan_source_set_with_stable_ids() {
    let registry = SourceRegistry::official().unwrap();
    let actual = registry
        .iter()
        .map(|source| {
            // Later corpus/provider batches retain their own exact source-review date.
            let expected_date = if STRIPE_SETUP_SOURCES.contains(&source.id.as_str()) {
                STRIPE_SETUP_RECHECKED_AT
            } else if STRIPE_LIFECYCLE_SOURCES.contains(&source.id.as_str()) {
                STRIPE_LIFECYCLE_RECHECKED_AT
            } else if source.id.starts_with("STRIPE-") {
                STRIPE_RECHECKED_AT
            } else if source.id == "VERCEL-API-LIST-PROJECTS" {
                VERCEL_LIST_RECHECKED_AT
            } else if source.id.starts_with("VERCEL-") {
                VERCEL_RECHECKED_AT
            } else if source.id == "GH-REST-GIT-COMMITS" {
                GIT_COMMITS_RECHECKED_AT
            } else if source.id == "GH-GIT-HTTPS-REMOTES" {
                GIT_REMOTES_RECHECKED_AT
            } else if source.id == "GH-REST-WORKFLOWS" {
                WORKFLOWS_RECHECKED_AT
            } else if source.id == "GH-REST-WORKFLOW-JOBS" {
                WORKFLOW_JOBS_RECHECKED_AT
            } else if source.id == "GH-REST-RELEASES" {
                RELEASES_RECHECKED_AT
            } else {
                RECHECKED_AT
            };
            assert_eq!(source.rechecked_at, expected_date);
            (source.id.as_str(), source.url.as_str())
        })
        .collect::<BTreeMap<_, _>>();
    let expected = PLAN_SOURCES.iter().copied().collect::<BTreeMap<_, _>>();

    assert_eq!(PLAN_SOURCES.len(), 72);
    assert_eq!(actual, expected);
    assert_eq!(registry.len(), PLAN_SOURCES.len());
    assert!(!registry.is_empty());

    let ids = registry
        .iter()
        .map(|source| source.id.as_str())
        .collect::<Vec<_>>();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn registry_mappings_are_closed_and_malformed_documents_fail() {
    let cases = [
        "not: [valid",
        "schema: cermet.grounded-ontology-sources/v1\nsources: wrong\n",
        "schema: cermet.grounded-ontology-sources/v1\nsources: []\nextra: false\n",
        "schema: cermet.grounded-ontology-sources/v1\nsources:\n  - id: VALID\n    url: https://docs.github.com/example\n    rechecked_at: '2026-07-19'\n    note: no\n",
        "schema: cermet.grounded-ontology-sources/v1\nschema: cermet.grounded-ontology-sources/v1\nsources: []\n",
    ];

    for case in cases {
        assert!(SourceRegistry::parse(case).is_err(), "accepted: {case}");
    }
}

#[test]
fn schema_and_nonempty_registry_are_required() {
    let wrong_schema = document("VALID", "https://docs.github.com/example", RECHECKED_AT).replacen(
        SOURCE_REGISTRY_SCHEMA,
        "cermet.grounded-ontology-sources/v2",
        1,
    );
    assert!(matches!(
        SourceRegistry::parse(&wrong_schema),
        Err(SourceRegistryError::UnsupportedSchema(_))
    ));
    assert!(
        SourceRegistry::parse(&format!("schema: {SOURCE_REGISTRY_SCHEMA}\nsources: []\n")).is_err()
    );
}

#[test]
fn duplicate_ids_and_urls_fail() {
    let duplicate_id = format!(
        "schema: {SOURCE_REGISTRY_SCHEMA}\nsources:\n  - id: DUPLICATE\n    url: https://docs.github.com/one\n    rechecked_at: '{RECHECKED_AT}'\n  - id: DUPLICATE\n    url: https://docs.github.com/two\n    rechecked_at: '{RECHECKED_AT}'\n"
    );
    assert!(matches!(
        SourceRegistry::parse(&duplicate_id),
        Err(SourceRegistryError::DuplicateId(id)) if id == "DUPLICATE"
    ));

    let duplicate_url = format!(
        "schema: {SOURCE_REGISTRY_SCHEMA}\nsources:\n  - id: FIRST\n    url: https://docs.github.com/same\n    rechecked_at: '{RECHECKED_AT}'\n  - id: SECOND\n    url: https://docs.github.com/same\n    rechecked_at: '{RECHECKED_AT}'\n"
    );
    assert!(matches!(
        SourceRegistry::parse(&duplicate_url),
        Err(SourceRegistryError::DuplicateUrl(url)) if url == "https://docs.github.com/same"
    ));
}

#[test]
fn source_id_grammar_and_cap_are_frozen() {
    let too_long = "A".repeat(65);
    let invalid = [
        "lowercase",
        "-LEADING",
        "HAS SPACE",
        "NONASCII-É",
        &too_long,
    ];

    for id in invalid {
        assert!(matches!(
            SourceRegistry::parse(&document(
                id,
                "https://docs.github.com/example",
                RECHECKED_AT
            )),
            Err(SourceRegistryError::InvalidSourceId(value)) if value == id
        ));
    }

    for id in ["0", "A.B_C-D", &"Z".repeat(64)] {
        SourceRegistry::parse(&document(
            id,
            "https://docs.github.com/example",
            RECHECKED_AT,
        ))
        .unwrap();
    }
}

#[test]
fn recheck_date_is_exact_and_calendar_valid() {
    for date in [
        "2026-2-09",
        "2026-02-29",
        "2026-04-31",
        "2026-13-01",
        "0000-01-01",
        "2026-07-19T00:00:00Z",
    ] {
        assert!(matches!(
            SourceRegistry::parse(&document(
                "VALID",
                "https://docs.github.com/example",
                date
            )),
            Err(SourceRegistryError::InvalidRecheckDate(value)) if value == date
        ));
    }

    SourceRegistry::parse(&document(
        "VALID",
        "https://docs.github.com/example",
        "2024-02-29",
    ))
    .unwrap();
}

#[test]
fn only_https_urls_on_exact_official_hosts_are_accepted() {
    for url in [
        "http://docs.github.com/example",
        "https://example.com/",
        "https://docs.github.com.example.com/",
    ] {
        assert!(matches!(
            SourceRegistry::parse(&document("VALID", url, RECHECKED_AT)),
            Err(SourceRegistryError::InvalidOfficialUrl(value)) if value == url
        ));
    }

    for url in [
        "https://docs.github.com/example",
        "https://docs.stripe.com/example",
    ] {
        SourceRegistry::parse(&document("VALID", url, RECHECKED_AT)).unwrap();
    }
}

#[test]
fn registry_document_cap_fails_before_parsing() {
    let oversized = " ".repeat(MAX_SOURCE_REGISTRY_BYTES + 1);
    assert!(matches!(
        SourceRegistry::parse(&oversized),
        Err(SourceRegistryError::DocumentTooLarge { actual, cap })
            if actual == MAX_SOURCE_REGISTRY_BYTES + 1 && cap == MAX_SOURCE_REGISTRY_BYTES
    ));
}

#[test]
fn unknown_sidecar_source_reference_cannot_resolve() {
    let registry = SourceRegistry::official().unwrap();
    assert!(matches!(
        registry.require("GH-NOT-REGISTERED"),
        Err(SourceRegistryError::UnknownSourceId(id)) if id == "GH-NOT-REGISTERED"
    ));
}
