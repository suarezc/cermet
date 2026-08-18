//! Grammar-level honesty guards for the GitHub guarded-write templates. These exercise ONLY
//! public APIs (template load), so they live as an integration test alongside the ontology
//! suite.
//!
//! The `cermet mcp` surface exposes every ratified verb with no read/write classification, so
//! writes are gated by sentence authority, not by any agent-surface filter. The guards here
//! protect the durable executor against two adversaries: hollow verification and unpinned
//! success status.

use cermet_core::templates::{TemplateRegistry, VENDORED_CATALOG};

fn vendored_registry() -> TemplateRegistry {
    let reg = TemplateRegistry::new();
    for doc in VENDORED_CATALOG {
        reg.load(doc)
            .unwrap_or_else(|e| panic!("vendored load failed: {e}\n{doc}"));
    }
    reg
}

const WRITE_TEMPLATE: &str = "\
provider: github
action: probe_write
fields:
  - { name: owner, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: name, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: title, type: str, required: true, class: free_payload, binding: unbound }
consumes: [owner, name, title]
execution_targets: [owner, name]
http:
  steps:
    - id: create
      method: POST
      path: /repos/{owner}/{name}/issues
      success_statuses: [201]
      body: { title: \"{title}\" }
      retention: none
";

fn github_write_status_guard(reg: &TemplateRegistry) -> Result<usize, String> {
    // No github write may accept "any 2xx" — every step of every write-shaped github template
    // (including the push_commit GraphQL mutation) must pin a non-empty `success_statuses`, keyed on
    // executable write metadata so the next write cannot ship unpinned.
    let mut checked = 0;
    for lt in reg.loaded_entries() {
        if lt.contract.provider != "github" {
            continue;
        }
        let Some(read_only) = lt.template.http_steps_are_read_only() else {
            continue;
        };
        if read_only {
            continue;
        }
        checked += 1;
        if lt.template.every_http_step_pins_success_status() != Some(true) {
            return Err(format!(
                "github write `{}` has a step with no success_statuses (accepts any 2xx)",
                lt.contract.action
            ));
        }
    }
    Ok(checked)
}

#[test]
fn every_github_write_template_pins_success_statuses() {
    let checked = github_write_status_guard(&vendored_registry()).expect("all writes pin statuses");
    assert_eq!(
        checked, 10,
        "expected ten github write templates, saw {checked}"
    );
}

#[test]
fn fixture_named_github_write_still_trips_the_unpinned_write_guard() {
    let fixture_write = WRITE_TEMPLATE
        .replace("action: probe_write", "action: fixture_probe_write")
        .replace("      success_statuses: [201]\n", "");
    let reg = TemplateRegistry::new();
    reg.load(&fixture_write)
        .expect("the synthetic unpinned fixture write reaches the independent guard");

    let error = github_write_status_guard(&reg)
        .expect_err("fixture_ naming must not exempt a write-shaped action from the status guard");
    assert!(error.contains("fixture_probe_write"), "{error}");
}

#[test]
fn expect_eq_with_optional_ok_on_one_step_is_rejected() {
    // A tolerated non-2xx would `continue` past the head-SHA guard then fire the mutation — the
    // same hollow-pin class from the other side. The grammar forbids the combo.
    let doc = "\
provider: github
action: probe_guard
fields:
  - { name: owner, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: name, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: head_sha, type: str, required: true, class: identity, binding: exact_resource_pin, format: git_oid }
consumes: [owner, name, head_sha]
execution_targets: [owner, name, head_sha]
http:
  steps:
    - id: g
      method: GET
      path: /repos/{owner}/{name}/runs
      optional_ok: [404]
      expect_eq: { head_sha: head_sha }
    - id: p
      method: POST
      path: /repos/{owner}/{name}/runs/cancel
      success_statuses: [202]
      retention: none
";
    let err = TemplateRegistry::new().load(doc).unwrap_err().to_string();
    assert!(
        err.contains("expect_eq") && err.contains("optional_ok"),
        "expect_eq + optional_ok on one step must be rejected, got: {err}"
    );
}

#[test]
fn success_statuses_must_be_2xx() {
    // A non-2xx pinned status is a load error.
    let bad = WRITE_TEMPLATE.replace("success_statuses: [201]", "success_statuses: [404]");
    let err = TemplateRegistry::new().load(&bad).unwrap_err().to_string();
    assert!(
        err.contains("2xx"),
        "success_statuses [404] must fail load, got: {err}"
    );
    // The 2xx-pinned form loads.
    TemplateRegistry::new()
        .load(WRITE_TEMPLATE)
        .expect("success_statuses [201] loads");
}

#[test]
fn verification_read_after_a_mutation_fails_to_load() {
    // Every verification read must sit in the leading read prefix. Assertions do not make a late read
    // safe: `POST mutate -> GET verify` has already crossed the side-effect boundary.
    let doc = "\
provider: github
action: probe_order
fields:
  - { name: owner, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: name, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: head_sha, type: str, required: true, class: identity, binding: exact_resource_pin, format: git_oid }
consumes: [owner, name, head_sha]
execution_targets: [owner, name, head_sha]
http:
  steps:
    - id: mutate
      method: POST
      path: /repos/{owner}/{name}/runs/cancel
      success_statuses: [202]
    - id: verify
      method: GET
      path: /repos/{owner}/{name}/runs
      success_statuses: [200]
      expect_eq: { head_sha: head_sha }
      retention: none
";
    let err = TemplateRegistry::new().load(doc).unwrap_err().to_string();
    assert!(
        err.contains("verification") && err.contains("PRECEDE"),
        "a POST-before-verification-GET template must fail load, got: {err}"
    );
}
