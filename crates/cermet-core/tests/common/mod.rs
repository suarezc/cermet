#![allow(dead_code)]
//! Corpus shape counts shared by the ontology suites.
//!
//! Several suites assert the vendored corpus is WHOLE before checking their own slice of it, so the
//! count lived in eight places and a new verb had to move all eight. It lives here now: one number,
//! moved on purpose when a verb lands.

/// Vendored ontology records — one sidecar per verb that carries one. Twenty-seven GitHub (the
/// git-native `push`/`push_tag`/`fetch`, `dispatch_workflow`, `read_workflow_run_jobs`,
/// `read_job_log`, and the release plane's three among them), twenty-three Stripe, and two Vercel
/// (the relay deploy and the scoped list read).
pub const VENDORED_ONTOLOGY_RECORDS: usize = 62;

/// The verbs a build vendors — everything the catalog lists on a shipped box, and therefore
/// everything a sentence may name. There is ONE catalog: a test build and a release build vendor
/// the same set.
pub const PRODUCT_VERBS: usize = 72;
