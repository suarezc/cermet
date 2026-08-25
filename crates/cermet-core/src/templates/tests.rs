use super::*;
use crate::contract::{AllowBinding, FieldClass};
use crate::policy::{ContractSource, DefaultContractSource};
use std::collections::BTreeSet;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
struct GuideInventoryField {
    name: String,
    r#type: String,
    required: bool,
    class: String,
    binding: String,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
struct GuideTargetlessQueryShape {
    verb: String,
    method: String,
    bodyless: bool,
    retention: String,
    fields: Vec<GuideInventoryField>,
    transforms: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct GuideVendoredInventory {
    field_formats: Vec<String>,
    targetless_query_shapes: Vec<GuideTargetlessQueryShape>,
}

fn transform_name(transform: &Transform) -> String {
    match transform {
        Transform::Base64 => "base64".to_string(),
        Transform::Omit(literal) => format!("omit:{literal}"),
        Transform::Default(literal) => format!("default:{literal}"),
        Transform::Negative => "negative".to_string(),
        Transform::QueryLiteral => "query_literal".to_string(),
    }
}

#[test]
fn language_guide_inventory_exactly_matches_typed_vendored_templates() {
    const START: &str = "<!-- cermet:vendored-template-inventory:start -->\n```yaml\n";
    const END: &str = "```\n<!-- cermet:vendored-template-inventory:end -->";
    let inventory_yaml = crate::LANGUAGE_DOC
        .split_once(START)
        .expect("language guide must carry its machine-checked vendored inventory")
        .1
        .split_once(END)
        .expect("language guide vendored inventory must have one closed end marker")
        .0;
    let mut documented: GuideVendoredInventory = serde_yaml::from_str(inventory_yaml).unwrap();

    let mut formats = BTreeSet::new();
    let mut targetless = Vec::new();
    for source in VENDORED_CATALOG {
        let template: ActionTemplate = serde_yaml::from_str(source).unwrap_or_else(|error| {
            panic!("vendored template is not typed YAML: {error}\n{source}")
        });
        if CatalogClass::from_action(&template.action) == CatalogClass::Setup {
            continue;
        }
        formats.extend(
            template
                .fields
                .iter()
                .filter_map(|field| field.format)
                .map(|format| {
                    serde_yaml::to_value(format)
                        .unwrap()
                        .as_str()
                        .expect("a field format serializes as its grammar token")
                        .to_string()
                }),
        );

        if template.execution_targets.is_empty() {
            assert_eq!(
                template.scope,
                Some(ScopeMode::Account),
                "{}.{} is targetless without declaring `scope: account`",
                template.provider,
                template.action
            );
            let ExecKind::Http { spec, .. } = &template.exec else {
                panic!("a scoped account read is an http verb");
            };
            let step = &spec.steps[0];
            let transforms = step
                .query
                .values()
                .flat_map(|value| parse_placeholders(value).unwrap())
                .filter_map(|placeholder| placeholder.transform.as_ref().map(transform_name))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            targetless.push(GuideTargetlessQueryShape {
                verb: format!("{}.{}", template.provider, template.action),
                method: step.method.clone(),
                bodyless: step.body.is_none() && step.graphql_query.is_none(),
                retention: match step.retention {
                    RetentionMode::Full => "full",
                    RetentionMode::None => "none",
                }
                .to_string(),
                fields: template
                    .fields
                    .iter()
                    .map(|field| GuideInventoryField {
                        name: field.name.clone(),
                        r#type: field.ty.as_str().to_string(),
                        required: field.required,
                        class: field.class.as_str().to_string(),
                        binding: field.binding.as_str().to_string(),
                    })
                    .collect(),
                transforms,
            });
        }
    }

    documented.field_formats.sort();
    documented.targetless_query_shapes.sort();
    targetless.sort();
    assert_eq!(
        documented.field_formats,
        formats.into_iter().collect::<Vec<_>>()
    );
    assert_eq!(documented.targetless_query_shapes, targetless);
}

#[test]
fn vendored_catalog_all_load() {
    // A shipped catalog that fails to parse is a packaging bug, not a runtime condition — make it
    // a loud test failure. Each doc loads cleanly into a fresh registry AND (as a set) the whole
    // catalog co-loads with no cross-template collision, exactly as `vendored_registry` does.
    assert!(
        !VENDORED_CATALOG.is_empty(),
        "the vendored catalog is non-empty"
    );
    for doc in VENDORED_CATALOG {
        let reg = TemplateRegistry::new();
        reg.load(doc)
            .unwrap_or_else(|e| panic!("vendored catalog doc failed to load: {e}\n---\n{doc}"));
    }
    let all = TemplateRegistry::new();
    for doc in VENDORED_CATALOG {
        all.load(doc)
            .unwrap_or_else(|e| panic!("vendored catalog co-load collision: {e}"));
    }
    // The process-global registry the default source reads initializes without panic.
    let reg = vendored_registry();
    assert!(
        reg.resolve("github", "push").is_some(),
        "push resolves in the catalog"
    );
}

#[test]
fn an_explicit_null_or_nonvariant_format_is_a_parse_error_not_a_silent_none() {
    // With `#[serde(default)]` a present `format: null` would deserialize to `None` and silently
    // DISABLE the shape constraint — a first-party authoring foot-gun. `deserialize_present_format`
    // makes a present null (or any non-variant) a hard parse error; an ABSENT key still loads.
    let base = "\
provider: github
action: read_probe
fields:
  - { name: owner, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: sha,   type: str, required: true, class: identity, binding: exact_resource_pin<FMT> }
consumes: [owner, sha]
execution_targets: [owner, sha]
http:
  steps:
    - id: get
      method: GET
      path: /repos/{owner}/{sha}
";
    // An ABSENT format loads cleanly (the control).
    TemplateRegistry::new()
        .load(&base.replace("<FMT>", ""))
        .expect("a field with no `format` key must load");
    // A VALID variant loads cleanly.
    TemplateRegistry::new()
        .load(&base.replace("<FMT>", ", format: git_oid"))
        .expect("a field with a valid `format` must load");
    // An explicit `null` and a non-variant both REJECT at parse.
    for bad in [
        ", format: null",
        ", format: ~",
        ", format: \"\"",
        ", format: bogus",
    ] {
        let err = TemplateRegistry::new()
            .load(&base.replace("<FMT>", bad))
            .expect_err("an explicit null/non-variant `format` must be a parse error");
        let _ = err; // the specific serde message is not pinned, only that it fails closed
    }
}

#[test]
fn vendored_catalog_actions_have_execution_targets_or_the_one_bounded_read_filter() {
    // The author layer leans on the catalog (built-ins ∪ catalog) to PIN an allow's execution
    // target; make that catalog-level guarantee explicit — every vendored action's derived
    // contract either names a pinnable execution target or is a DECLARED `scope: account`
    // bounded read ("the pin is the verb"). Rule 6 already refuses a
    // template that is neither; this is the cheap, documented restatement of the property the
    // author layer depends on, plus the closed census of the scoped set.
    let scoped_census = [
        ("stripe", "search_customers"),
        ("stripe", "fixture_account_discover"),
        ("vercel", "list_projects"),
    ];
    for doc in VENDORED_CATALOG {
        let reg = TemplateRegistry::new();
        let (provider, action) = reg
            .load(doc)
            .unwrap_or_else(|e| panic!("vendored catalog doc failed to load: {e}"));
        let contract = reg
            .resolve(&provider, &action)
            .expect("a loaded vendored action resolves through its own registry");
        assert!(
            !contract.execution_targets.is_empty()
                || scoped_census.contains(&(provider.as_str(), action.as_str())),
            "vendored action {provider}.{action} must declare an execution target or be in the \
             declared `scope: account` census (update the census deliberately, never incidentally)"
        );
    }
}

#[test]
fn bounded_template_binding_maps_to_the_contract_binding() {
    let field: TemplateField = serde_yaml::from_str(
        "{ name: amount, type: int, required: true, class: side_effect, binding: bounded }",
    )
    .unwrap();

    assert_eq!(field.binding.to_allow_binding(), AllowBinding::Bounded);
    assert_eq!(field.binding.as_str(), "bounded");
}

#[test]
fn default_source_resolves_vendored_catalog() {
    let src = DefaultContractSource;
    // The core ships zero compiled-in contracts: every vendored action resolves through the
    // vendored template catalog.
    assert!(
        src.contract("github", "read_repo").is_some(),
        "the default source resolves the vendored read_repo template"
    );
    let push = src
        .contract("github", "push")
        .expect("the default source resolves the vendored push template");
    assert_eq!(
        push.execution_targets.to_vec(),
        vec!["owner", "name", "branch"]
    );
    // A truly-unknown action still fails closed.
    assert!(
        src.contract("github", "no_such_action").is_none(),
        "unknown stays unresolved"
    );
    assert!(!vendored_registry().is_secret_field_name("owner"));
}

#[test]
fn vendors_the_complete_stripe_support_catalog() {
    let expected = [
        "cancel_subscription",
        "credit_balance",
        "get_charge",
        "get_subscription",
        "list_charges",
        "list_refunds",
        "lookup_customer",
        "pause_subscription",
        "refund",
        "search_customers",
    ];
    let source = DefaultContractSource;

    for action in expected {
        let contract = source.contract("stripe", action).unwrap_or_else(|| {
            panic!("stripe.{action} must be compiled into the vendored catalog")
        });
        assert_eq!(contract.provider, "stripe");
        assert_eq!(contract.action, action);
        if action == "search_customers" {
            assert!(contract.execution_targets.is_empty());
            let filter = contract.field_decl("email_contains").unwrap();
            assert_eq!(filter.class, FieldClass::ReadFilter);
            assert_eq!(filter.binding, AllowBinding::Unbound);
        } else {
            assert!(!contract.execution_targets.is_empty());
        }
    }

    let refund = source.contract("stripe", "refund").unwrap();
    let amount = refund
        .field_decl("amount")
        .expect("refund amount is declared");
    assert_eq!(amount.class, FieldClass::SideEffect);
    assert_eq!(amount.binding, AllowBinding::Bounded);
}

#[test]
fn stripe_search_is_the_only_narrow_targetless_http_read_shape() {
    let valid = r#"
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
"#;
    let reg = TemplateRegistry::with_providers(HashSet::from(["stripe".to_string()]));
    reg.load(valid)
        .expect("the bounded targetless read shape loads");

    // `retention: none` is not part of this shape — the retention default is FULL and the
    // shape's real bound is the frozen bodyless GET with quoted `query_literal` filters, which
    // the remaining variants still prove.
    for invalid in [
        valid.replace("method: GET", "method: POST"),
        valid.replace(
            "class: read_filter, binding: unbound",
            "class: free_payload, binding: unbound",
        ),
        valid.replace("{email_contains|query_literal}", "{email_contains}"),
        valid.replace(
            "execution_targets: []",
            "execution_targets: [email_contains]",
        ),
    ] {
        let reg = TemplateRegistry::with_providers(HashSet::from(["stripe".to_string()]));
        assert!(
            reg.load(&invalid).is_err(),
            "unsafe targetless variant loaded:\n{invalid}"
        );
    }
}

fn golden() -> String {
    r#"
provider: github
action: template_put_file
fields:
  - { name: owner,   type: str, required: true,  class: identity,     binding: exact_resource_pin }
  - { name: name,    type: str, required: true,  class: identity,     binding: exact_resource_pin }
  - { name: branch,  type: str, required: true,  class: identity,     binding: exact_resource_pin }
  - { name: path,    type: str, required: true,  class: identity,     binding: exact_resource_pin }
  - { name: content, type: str, required: true,  class: free_payload, binding: unbound }
  - { name: message, type: str, required: true,  class: free_payload, binding: unbound }
consumes: [owner, name, branch, path, content, message]
execution_targets: [owner, name, branch, path]
http:
  path_modes: { path: path }
  steps:
    - id: get_sha
      method: GET
      path: /repos/{owner}/{name}/contents/{path}
      query: { ref: "{branch}" }
      optional_ok: [404]
      capture: { sha: "$.sha" }
    - id: put
      method: PUT
      path: /repos/{owner}/{name}/contents/{path}
      body:
        message: "{message}"
        content: "{content|base64}"
        branch: "{branch}"
        sha: "{sha?}"
"#
    .to_string()
}

/// The golden doc plus a locally-declared Secret field carried in the body (never in path/query).
fn golden_with_secret() -> String {
    golden()
            .replace(
                "  - { name: message, type: str, required: true,  class: free_payload, binding: unbound }",
                "  - { name: message, type: str, required: true,  class: free_payload, binding: unbound }\n  - { name: secret_value, type: str, required: true, class: secret, binding: unbound }",
            )
            .replace(
                "consumes: [owner, name, branch, path, content, message]",
                "consumes: [owner, name, branch, path, content, message, secret_value]",
            )
            .replace(
                "        sha: \"{sha?}\"",
                "        sha: \"{sha?}\"\n        secret_value: \"{secret_value}\"",
            )
}

#[test]
fn golden_template_validates_loads_and_resolves() {
    let reg = TemplateRegistry::new();
    let (p, a) = reg.load(&golden()).expect("golden template loads");
    assert_eq!((p.as_str(), a.as_str()), ("github", "template_put_file"));

    let c = reg
        .resolve("github", "template_put_file")
        .expect("resolves");
    assert_eq!(c.provider, "github");
    assert_eq!(c.action, "template_put_file");
    assert_eq!(c.field_class("owner"), Some(FieldClass::Identity));
    assert_eq!(
        c.field_binding("owner"),
        Some(AllowBinding::ExactResourcePin)
    );
    assert_eq!(c.field_class("content"), Some(FieldClass::FreePayload));
    assert_eq!(c.field_binding("content"), Some(AllowBinding::Unbound));
    assert_eq!(
        c.consumes.to_vec(),
        vec!["owner", "name", "branch", "path", "content", "message"]
    );
    assert_eq!(
        c.execution_targets.to_vec(),
        vec!["owner", "name", "branch", "path"]
    );

    let lt = reg.loaded("github", "template_put_file").unwrap();
    assert_eq!(lt.content_hash.len(), 64);
    assert!(lt.content_hash.chars().all(|ch| ch.is_ascii_hexdigit()));

    // The preview path succeeds independently, without touching a registry.
    vendored_registry()
        .validate_doc(&golden())
        .expect("validate_doc succeeds without loading");
}

#[test]
fn validator_refuses_a_verb_whose_generated_tool_name_exceeds_the_cap() {
    // The generated MCP tool name is `provider-action`; model providers cap tool names at 64
    // chars and the longest known client prefix (`mcp__cermet__`) is 13, so the projectable budget
    // is 64-13=51. A verb that would render 52 chars must be refused fail-closed at validation, so a
    // too-long verb can never enter the catalog (else the client silently drops the tool).
    // provider `github` (6) + `-` (1) + a 45-char action = 52 chars → reject.
    let action_52 = "a".repeat(45);
    let over = golden().replace("action: template_put_file", &format!("action: {action_52}"));
    let err = vendored_registry()
        .validate_doc(&over)
        .expect_err("a 52-char generated tool name must refuse");
    assert!(
        err.contains("52") && err.contains("51") && err.contains("mcp__cermet__"),
        "the refusal names the length, the cap, and why: {err}"
    );

    // The boundary: `github` (6) + `-` (1) + a 44-char action = 51 chars → accepted.
    let action_51 = "a".repeat(44);
    let at_cap = golden().replace("action: template_put_file", &format!("action: {action_51}"));
    vendored_registry()
        .validate_doc(&at_cap)
        .expect("a 51-char generated tool name is at the cap and accepted");
}

#[test]
fn vendored_catalog_generated_tool_names_are_within_the_cap() {
    // Audit: every shipped verb's generated MCP tool name (`provider-action`) fits the 51-char
    // cross-client budget, so the whole seeded catalog is projectable on every model provider.
    for doc in VENDORED_CATALOG {
        let reg = TemplateRegistry::new();
        let (provider, action) = reg
            .load(doc)
            .unwrap_or_else(|e| panic!("vendored catalog doc failed to load: {e}"));
        let tool_name_len = provider.len() + 1 + action.len();
        assert!(
            tool_name_len <= 51,
            "vendored verb {provider}.{action} renders a {tool_name_len}-char MCP tool name, over the 51-char cap"
        );
    }
}

#[test]
fn template_for_a_descriptorless_provider_refuses_to_load() {
    // A registry that knows only `github` (no `acme` descriptor) must REFUSE an `acme` template —
    // a template can never point a credential at an origin no ratified descriptor pinned.
    let mut set = HashSet::new();
    set.insert("github".to_string());
    let reg = TemplateRegistry::with_providers(set);
    let acme = "provider: acme\naction: read_thing\nfields:\n  - { name: id, type: str, required: true, class: identity, binding: exact_resource_pin }\nconsumes: [id]\nexecution_targets: [id]\nhttp:\n  steps:\n    - id: get\n      method: GET\n      path: /things/{id}\n";
    let load_err = reg
        .load(acme)
        .expect_err("an acme template must refuse to load");
    assert!(
        load_err.contains("not template-extensible") && load_err.contains("descriptor"),
        "the refusal names the missing descriptor: {load_err}"
    );
    assert!(reg.check_load(acme).is_err(), "check_load agrees");
    assert!(reg.validate_doc(acme).is_err(), "validate_doc agrees");
    // Once the descriptor is ratified (its provider added), the SAME template loads.
    reg.add_provider("acme", ProviderCeiling::Http);
    reg.load(acme)
        .expect("with acme descriptor present the template loads");
}

#[test]
fn validator_refuses_an_auth_block() {
    let doc = golden().replace(
        "  steps:",
        "  auth: { header: Authorization, shape: \"Bearer {token}\" }\n  steps:",
    );
    assert!(
        TemplateRegistry::new().load(&doc).is_err(),
        "an `auth` block must be refused — auth is a provider property, never template data"
    );
}

#[test]
fn validator_refuses_parameters_in_consumes() {
    let doc = golden().replace(
        "consumes: [owner, name, branch, path, content, message]",
        "consumes: [owner, name, branch, path, content, message, parameters]",
    );
    let err = TemplateRegistry::new()
        .load(&doc)
        .expect_err("consuming `parameters` must be refused");
    assert!(
        err.contains("parameters"),
        "error names the killed channel: {err}"
    );
}

#[test]
fn validator_refuses_non_identity_path_placeholder() {
    let doc = golden().replace(
            "  - { name: path,    type: str, required: true,  class: identity,     binding: exact_resource_pin }",
            "  - { name: path,    type: str, required: true,  class: free_payload, binding: unbound }",
        );
    assert!(
        TemplateRegistry::new().load(&doc).is_err(),
        "a non-Identity path placeholder must be refused"
    );
}

#[test]
fn validator_refuses_unknown_or_unpinned_provider() {
    let files = golden().replace("provider: github", "provider: files");
    assert!(
        TemplateRegistry::new().load(&files).is_err(),
        "unknown provider refused"
    );
    let notion = golden().replace("provider: github", "provider: notion");
    assert!(
        TemplateRegistry::new().load(&notion).is_err(),
        "a provider without a compiled-in pinned egress must be refused"
    );
}

#[test]
fn validator_refuses_unresolvable_placeholder() {
    let doc = golden().replace("content: \"{content|base64}\"", "content: \"{typo}\"");
    assert!(
        TemplateRegistry::new().load(&doc).is_err(),
        "a placeholder resolving to no field or capture must be refused"
    );
}

#[test]
fn validator_refuses_capture_steered_paths() {
    // A path placeholder naming the `sha` capture.
    let path_cap = golden().replace(
        "      path: /repos/{owner}/{name}/contents/{path}\n      body:",
        "      path: /repos/{owner}/{name}/contents/{path}/{sha}\n      body:",
    );
    assert!(
        TemplateRegistry::new().load(&path_cap).is_err(),
        "a capture may never steer the URL path"
    );

    // A query placeholder naming a capture not produced by a strictly earlier step.
    let query_cap = golden().replace(
        "      query: { ref: \"{branch}\" }",
        "      query: { ref: \"{branch}\", extra: \"{sha}\" }",
    );
    assert!(
        TemplateRegistry::new().load(&query_cap).is_err(),
        "a query may not use a same/later step's capture"
    );
}

#[test]
fn validator_refuses_path_field_missing_from_targets() {
    // `name` stays a URL path placeholder but is dropped from execution_targets, so no
    // allow rule has to pin it — refuse.
    let doc = golden().replace(
        "execution_targets: [owner, name, branch, path]",
        "execution_targets: [owner, branch, path]",
    );
    let err = TemplateRegistry::new()
        .load(&doc)
        .expect_err("a path placeholder absent from execution_targets must be refused");
    assert!(
        err.contains("name") && err.contains("execution_targets"),
        "error names the unpinned path field: {err}"
    );
}

#[test]
fn validator_refuses_an_optional_field_in_an_executed_url() {
    // Optionality is legal on an execution target — an omitting request freezes the field as
    // absence, and a rule that pins it then refuses that request rather than matching it. Where it
    // is NOT legal is a position the executor must fill to build the outbound URL: an absent path
    // placeholder has nothing to interpolate, so a request that omitted it would execute against a
    // URL nobody approved. The narrower guard is the one that carries the weight.
    let doc = golden().replace(
            "  - { name: owner,   type: str, required: true,  class: identity,     binding: exact_resource_pin }",
            "  - { name: owner,   type: str, required: false, class: identity,     binding: exact_resource_pin }",
        );
    let err = TemplateRegistry::new()
        .load(&doc)
        .expect_err("an optional path placeholder must be refused at load");
    assert!(
        err.contains("owner") && err.contains("required"),
        "the error names the field and the requirement: {err}"
    );
}

#[test]
fn validator_refuses_unpinned_or_captured_query_placeholder() {
    // (a) a FreePayload field in a query is not authority-bearing enough — refuse.
    let free = golden().replace(
        "      query: { ref: \"{branch}\" }",
        "      query: { ref: \"{content}\" }",
    );
    assert!(
        TemplateRegistry::new().load(&free).is_err(),
        "a FreePayload query placeholder must be refused"
    );

    // (b) an exact-pinned Identity field that is NOT an execution target — refuse.
    let not_target = golden()
            .replace(
                "  - { name: path,    type: str, required: true,  class: identity,     binding: exact_resource_pin }",
                "  - { name: path,    type: str, required: true,  class: identity,     binding: exact_resource_pin }\n  - { name: team,    type: str, required: true,  class: identity,     binding: exact_resource_pin }",
            )
            .replace(
                "consumes: [owner, name, branch, path, content, message]",
                "consumes: [owner, name, branch, path, content, message, team]",
            )
            .replace(
                "      query: { ref: \"{branch}\" }",
                "      query: { ref: \"{branch}\", team: \"{team}\" }",
            );
    let err = TemplateRegistry::new()
        .load(&not_target)
        .expect_err("a query field not in execution_targets must be refused");
    assert!(
        err.contains("team") && err.contains("execution_targets"),
        "error names the untargeted query field: {err}"
    );

    // (c) a capture in a query — provider response data must never steer a request.
    let cap = golden().replace(
            "      path: /repos/{owner}/{name}/contents/{path}\n      body:",
            "      path: /repos/{owner}/{name}/contents/{path}\n      query: { probe: \"{sha}\" }\n      body:",
        );
    assert!(
        TemplateRegistry::new().load(&cap).is_err(),
        "a capture in a query must be refused outright"
    );
}

#[test]
fn validator_refuses_token_anywhere() {
    let field = golden().replace(
            "  - { name: message, type: str, required: true,  class: free_payload, binding: unbound }",
            "  - { name: message, type: str, required: true,  class: free_payload, binding: unbound }\n  - { name: token, type: str, required: true, class: free_payload, binding: unbound }",
        );
    assert!(
        TemplateRegistry::new().load(&field).is_err(),
        "a field named token refused"
    );

    let body = golden().replace("content: \"{content|base64}\"", "content: \"{token}\"");
    assert!(
        TemplateRegistry::new().load(&body).is_err(),
        "a `token` placeholder must be refused anywhere"
    );
}

#[test]
fn two_registries_do_not_cross_talk() {
    let a = TemplateRegistry::new();
    let b = TemplateRegistry::new();
    a.load(&golden_with_secret()).expect("A loads");

    assert!(
        b.resolve("github", "template_put_file").is_none(),
        "B never sees A's template"
    );
    assert!(
        b.loaded("github", "template_put_file").is_none(),
        "B has no loaded entry"
    );
    assert!(
        a.is_secret_field_name("secret_value"),
        "A knows its own template's Secret field"
    );
    assert!(
        !b.is_secret_field_name("secret_value"),
        "B must NOT see A's template Secret field (per-broker guardrail)"
    );
}

#[test]
fn duplicate_load_is_refused() {
    let reg = TemplateRegistry::new();
    reg.load(&golden()).unwrap();
    let err = reg
        .load(&golden())
        .expect_err("a second load of the same action must be refused");
    assert!(
        err.contains("already loaded"),
        "error explains the refusal: {err}"
    );
}

#[test]
fn check_load_agrees_with_load_and_never_registers() {
    // check_load is a pure DRY RUN of load: same verdict, no side effects.
    let reg = TemplateRegistry::new();
    // (1) a clean doc: check_load says Ok and leaves the registry empty; load then registers it.
    reg.check_load(&golden())
        .expect("check_load accepts a clean doc");
    assert!(
        reg.loaded("github", "template_put_file").is_none(),
        "check_load must NOT register anything"
    );
    reg.load(&golden()).unwrap();

    // (2) a registry-wide collision that validate_doc alone cannot see: one action, one ratified
    // template. Load `secret_owner`, then offer a DIFFERENT document for the same action.
    let a = golden()
            .replace("action: template_put_file", "action: secret_owner")
            .replace(
                "  - { name: message, type: str, required: true,  class: free_payload, binding: unbound }",
                "  - { name: message, type: str, required: true,  class: free_payload, binding: unbound }\n  - { name: mysecret, type: str, required: true, class: secret, binding: unbound }",
            )
            .replace(
                "consumes: [owner, name, branch, path, content, message]",
                "consumes: [owner, name, branch, path, content, message, mysecret]",
            )
            .replace(
                "        sha: \"{sha?}\"",
                "        sha: \"{sha?}\"\n        mysecret: \"{mysecret}\"",
            );
    let reg2 = TemplateRegistry::new();
    reg2.load(&a).expect("the secret-declaring template loads");

    // `b` is grammatically fine on its own but collides with the ALREADY-LOADED `a`: one action,
    // one ratified template. That is a registry-wide refusal `validate_doc` alone cannot see, which
    // is exactly the parity `check_load` has to reproduce.
    let b = golden()
        .replace("action: template_put_file", "action: secret_owner")
        .replace(
            "      query: { ref: \"{branch}\" }",
            "      query: { ref: \"{branch}\" }\n      success_statuses: [200]",
        );
    vendored_registry()
        .validate_doc(&b)
        .expect("b passes the grammar/shadow validator alone");
    let check_err = reg2
        .check_load(&b)
        .expect_err("check_load refuses the cross-template collision");
    let load_err = reg2
        .load(&b)
        .expect_err("load refuses the identical collision");
    assert_eq!(
        check_err, load_err,
        "check_load and load must give the identical verdict"
    );
    assert!(
        check_err.contains("already loaded"),
        "the refusal names the collision: {check_err}"
    );
}

#[test]
fn validator_refuses_misplaced_step_extras() {
    // optional_ok on the final step.
    let optok_final = format!(
        "{}      optional_ok: [404]\n",
        golden().trim_end_matches('\n')
    );
    assert!(
        TemplateRegistry::new().load(&optok_final).is_err(),
        "final optional_ok refused"
    );

    // capture on the final step.
    let cap_final = format!(
        "{}      capture: {{ foo: \"$.bar\" }}\n",
        golden().trim_end_matches('\n')
    );
    assert!(
        TemplateRegistry::new().load(&cap_final).is_err(),
        "final capture refused"
    );

    // optional_ok of a 5xx.
    let optok_5xx = golden().replace("optional_ok: [404]", "optional_ok: [500]");
    assert!(
        TemplateRegistry::new().load(&optok_5xx).is_err(),
        "a 5xx optional_ok refused"
    );
}

#[test]
fn validator_refuses_oversized_or_overgrown_docs() {
    let oversized = format!("{}\n# {}", golden(), "x".repeat(70_000));
    assert!(oversized.len() > MAX_DOC_BYTES);
    assert!(
        TemplateRegistry::new().load(&oversized).is_err(),
        "a document over the size cap must be refused before parse"
    );

    let mut nine = String::from(
        "provider: github\naction: many_steps\nfields:\n  - { name: owner, type: str, required: true, class: identity, binding: exact_resource_pin }\nconsumes: [owner]\nexecution_targets: [owner]\nhttp:\n  steps:\n",
    );
    for i in 0..9 {
        nine.push_str(&format!(
            "    - {{ id: s{i}, method: GET, path: /x/{{owner}} }}\n"
        ));
    }
    assert!(
        TemplateRegistry::new().load(&nine).is_err(),
        "more than the step cap must be refused"
    );
}

#[test]
fn validator_requires_consumes_to_match_used_fields() {
    let dropped = golden().replace(
        "consumes: [owner, name, branch, path, content, message]",
        "consumes: [owner, name, branch, path, content]",
    );
    assert!(
        TemplateRegistry::new().load(&dropped).is_err(),
        "a used-but-unconsumed field must be refused"
    );

    let extra = golden()
            .replace(
                "  - { name: message, type: str, required: true,  class: free_payload, binding: unbound }",
                "  - { name: message, type: str, required: true,  class: free_payload, binding: unbound }\n  - { name: extra, type: str, required: false, class: free_payload, binding: unbound }",
            )
            .replace(
                "consumes: [owner, name, branch, path, content, message]",
                "consumes: [owner, name, branch, path, content, message, extra]",
            );
    assert!(
        TemplateRegistry::new().load(&extra).is_err(),
        "a consumed-but-unused field must be refused"
    );
}

#[test]
fn fixture_named_template_refuses_money_metadata_before_other_money_validation() {
    let doc = golden()
        .replace("action: template_put_file", "action: fixture_put_file")
        .replace(
            "fields:",
            "money:\n  preconditions: [not_a_real_precondition]\nfields:",
        );
    let error = TemplateRegistry::new()
        .load(&doc)
        .expect_err("setup-class actions may never carry money metadata");
    assert!(
        error.contains("setup-class action may not declare `money`"),
        "{error}"
    );
}

#[test]
fn fixture_named_template_refuses_secret_fields_before_wire_validation() {
    let doc = golden()
        .replace("action: template_put_file", "action: fixture_put_file")
        .replace(
            "  - { name: message, type: str, required: true,  class: free_payload, binding: unbound }",
            "  - { name: message, type: str, required: true,  class: secret, binding: unbound }",
        );
    let error = TemplateRegistry::new()
        .load(&doc)
        .expect_err("setup-class actions may never carry secret fields");
    assert!(
        error.contains("setup-class action may not declare secret field `message`"),
        "{error}"
    );
}

#[test]
fn fixture_discovery_may_add_allowlisted_prior_step_captures() {
    let doc = "\
provider: stripe
action: fixture_projection_probe_discover
fields: []
consumes: []
execution_targets: []
scope: account
http:
  steps:
    - id: account
      method: GET
      path: /v1/account
      success_statuses: [200]
      require: [id]
      capture: { account_id: \"$.id\" }
      retention: none
    - id: mode
      method: GET
      path: /v1/balance
      success_statuses: [200]
      require: [livemode]
      expect_literal: { livemode: false }
      result_captures: { account_id: account_id }
      retention: none
";
    TemplateRegistry::new()
        .load(doc)
        .expect("setup discovery may ADD an explicitly allowlisted prior capture to the body");
}

#[test]
fn fixture_setup_may_project_allowlisted_prior_mutation_capture() {
    let doc = "\
provider: stripe
action: fixture_payment_intents_create
fields:
  - { name: account, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: amount, type: int, required: true, class: side_effect, binding: bounded }
consumes: [account, amount]
execution_targets: [account]
http:
  steps:
    - id: unconfirmed
      method: POST
      path: /v1/payment_intents
      body_encoding: form
      body: { amount: \"{amount}\", account: \"{account}\" }
      success_statuses: [200]
      require: [id]
      capture: { confirmation_payment_intent: \"$.id\" }
      retention: none
    - id: manual
      method: POST
      path: /v1/payment_intents
      body_encoding: form
      body: { amount: \"{amount}\" }
      success_statuses: [200]
      require: [id]
      result_captures: { confirmation_payment_intent: confirmation_payment_intent }
      retention: none
";
    TemplateRegistry::new()
        .load(doc)
        .expect("setup may return one allowlisted earlier mutation identity");
}

#[test]
fn fixture_setup_may_end_with_capture_bound_reconciliation_read() {
    let doc = "\
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
      body: { account: \"{account}\" }
      success_statuses: [200]
      require: [id]
      capture: { charge_id: \"$.id\" }
      retention: none
    - id: reconcile
      method: GET
      path: /v1/disputes
      query: { charge: \"{charge_id}\", limit: \"10\" }
      success_statuses: [200]
      require: [data, has_more]
      expect_literal: { has_more: false }
      retention: none
";
    TemplateRegistry::new()
        .load(doc)
        .expect("setup may reconcile its one captured mutation in a terminal bounded read");
}

#[test]
fn fixture_setup_may_bound_a_capture_reconciliation_poll() {
    let doc = "\
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
      body: { account: \"{account}\" }
      success_statuses: [200]
      require: [id]
      capture: { created_charge: \"$.id\" }
      retention: none
    - id: reconcile
      method: GET
      path: /v1/disputes
      query: { charge: \"{created_charge}\", limit: \"10\" }
      success_statuses: [200]
      require: [data, has_more]
      expect_literal: { has_more: false }
      poll: { attempts: 3, delay_ms: 1, until_nonempty: [data] }
      result_captures: { created_charge: created_charge }
      retention: none
";
    TemplateRegistry::new()
        .load(doc)
        .expect("setup may bound its final capture-keyed reconciliation read");
    for invalid in [
        doc.replace("attempts: 3", "attempts: 1"),
        doc.replace("attempts: 3", "attempts: 6"),
        doc.replace("delay_ms: 1", "delay_ms: 0"),
        doc.replace("delay_ms: 1", "delay_ms: 1001"),
        doc.replace("until_nonempty: [data]", "until_nonempty: [unretained]"),
        doc.replace("action: fixture_dispute_create", "action: dispute_create"),
    ] {
        TemplateRegistry::new()
            .load(&invalid)
            .expect_err("unbounded or non-setup polling must fail closed");
    }
}

#[test]
fn fixture_discovery_may_filter_a_final_collection_by_a_frozen_prefix() {
    let doc = "\
provider: github
action: fixture_prefix_probe_discover
fields: []
consumes: []
execution_targets: []
scope: account
http:
  steps:
    - id: repositories
      method: POST
      path: /graphql
      success_statuses: [200]
      graphql_query: \"query fixturePrefixProbe { viewer { repositories(first: 20) { nodes { name } } } }\"
      require: [data.viewer.repositories.nodes]
      retention: none
";
    TemplateRegistry::new()
        .load(doc)
        .expect("setup discovery may enforce one frozen response prefix before projection");
}

// ---- The `{field|omit:<literal>}` body transform ----

/// A deploy-shaped template whose body carries `target: "{environment|omit:preview}"` on a
/// required Str Identity field — the intended, legal placement for `omit:`.
fn omit_base() -> String {
    r#"
provider: vercel
action: deploy
fields:
  - { name: project,     type: str, required: true, class: identity,     binding: exact_resource_pin }
  - { name: repo_id,     type: int, required: true, class: identity,     binding: exact_resource_pin }
  - { name: ref,         type: str, required: true, class: free_payload, binding: unbound }
  - { name: environment, type: str, required: true, class: identity,     binding: exact_resource_pin }
consumes: [project, repo_id, ref, environment]
execution_targets: [project, repo_id, environment]
http:
  steps:
    - id: create
      method: POST
      path: /v13/deployments
      body:
        name: "{project}"
        project: "{project}"
        gitSource: { type: github, repoId: "{repo_id}", ref: "{ref}" }
        target: "{environment|omit:preview}"
"#
        .to_string()
}

#[test]
fn omit_accepted_on_required_str_whole_value_body() {
    let reg = TemplateRegistry::new();
    let (p, a) = reg
        .load(&omit_base())
        .expect("omit on a required Str whole-value body placeholder must load");
    assert_eq!((p.as_str(), a.as_str()), ("vercel", "deploy"));
    assert!(reg.resolve("vercel", "deploy").is_some());
}

#[test]
fn omit_refused_outside_a_whole_value_body_placeholder() {
    // in a URL path (a path placeholder may never be transformed).
    let in_path = omit_base().replace(
        "      path: /v13/deployments",
        "      path: /v13/deployments/{environment|omit:preview}",
    );
    assert!(
        TemplateRegistry::new().load(&in_path).is_err(),
        "omit in a URL path must be refused"
    );

    // in a query value (a query placeholder may never be transformed).
    let in_query = omit_base().replace(
        "      path: /v13/deployments\n",
        "      path: /v13/deployments\n      query: { target: \"{environment|omit:preview}\" }\n",
    );
    assert!(
        TemplateRegistry::new().load(&in_query).is_err(),
        "omit in a query value must be refused"
    );

    // embedded in a longer string (a transform must be the whole value).
    let embedded = omit_base().replace(
        "target: \"{environment|omit:preview}\"",
        "target: \"env-{environment|omit:preview}\"",
    );
    assert!(
        TemplateRegistry::new().load(&embedded).is_err(),
        "an embedded (non-whole-value) omit must be refused"
    );

    // on a capture (golden's `sha` is a capture; a capture can never be transformed).
    let on_capture = golden().replace("sha: \"{sha?}\"", "sha: \"{sha|omit:preview}\"");
    assert!(
        TemplateRegistry::new().load(&on_capture).is_err(),
        "omit on a capture must be refused"
    );
}

#[test]
fn omit_refused_on_wrong_field_kind_or_bad_literal() {
    // on a non-Str (Int) field.
    let on_int = omit_base().replace(
        "        target: \"{environment|omit:preview}\"",
        "        target: \"{environment|omit:preview}\"\n        flag: \"{repo_id|omit:preview}\"",
    );
    assert!(
        TemplateRegistry::new().load(&on_int).is_err(),
        "omit on an Int field must be refused"
    );

    // on an optional field (an absent optional value has no wire meaning for omit).
    let on_optional = omit_base()
            .replace(
                "  - { name: environment, type: str, required: true, class: identity,     binding: exact_resource_pin }",
                "  - { name: environment, type: str, required: true, class: identity,     binding: exact_resource_pin }\n  - { name: note, type: str, required: false, class: free_payload, binding: unbound }",
            )
            .replace(
                "consumes: [project, repo_id, ref, environment]",
                "consumes: [project, repo_id, ref, environment, note]",
            )
            .replace(
                "        target: \"{environment|omit:preview}\"",
                "        target: \"{environment|omit:preview}\"\n        note: \"{note|omit:preview}\"",
            );
    assert!(
        TemplateRegistry::new().load(&on_optional).is_err(),
        "omit on an optional field must be refused"
    );

    // empty literal.
    let empty_lit = omit_base().replace("omit:preview", "omit:");
    assert!(
        TemplateRegistry::new().load(&empty_lit).is_err(),
        "an empty omit literal must be refused"
    );

    // literal over 64 chars.
    let long_lit = omit_base().replace("omit:preview", &format!("omit:{}", "a".repeat(65)));
    assert!(
        TemplateRegistry::new().load(&long_lit).is_err(),
        "an over-64-char omit literal must be refused"
    );

    // illegal chars in the literal (uppercase, slash).
    for bad in ["omit:PREVIEW", "omit:prev/iew", "omit:pre view"] {
        let illegal = omit_base().replace("omit:preview", bad);
        assert!(
            TemplateRegistry::new().load(&illegal).is_err(),
            "an omit literal with illegal chars (`{bad}`) must be refused"
        );
    }
}

/// An omitted key is invisible on the wire, so `omit:` may decide on nothing looser than a
/// required, exact-pinned Identity execution target — the one kind of field the approver's
/// pin actually covers. Anything else lets a template hide an approved field.
#[test]
fn omit_refused_off_pinned_identity_execution_targets() {
    // on a FreePayload/unbound field (ref) — validates today only if the guard is missing.
    let on_payload = omit_base().replace(
        "        target: \"{environment|omit:preview}\"",
        "        target: \"{environment|omit:preview}\"\n        refx: \"{ref|omit:main}\"",
    );
    let err = TemplateRegistry::new()
        .load(&on_payload)
        .expect_err("omit on a FreePayload field must be refused");
    assert!(err.contains("pinned Identity execution target"), "{err}");

    // on a pinned Identity field that is NOT an execution target.
    let off_target = omit_base()
            .replace(
                "  - { name: environment, type: str, required: true, class: identity,     binding: exact_resource_pin }",
                "  - { name: environment, type: str, required: true, class: identity,     binding: exact_resource_pin }\n  - { name: region, type: str, required: true, class: identity, binding: exact_resource_pin }",
            )
            .replace(
                "consumes: [project, repo_id, ref, environment]",
                "consumes: [project, repo_id, ref, environment, region]",
            )
            .replace(
                "        target: \"{environment|omit:preview}\"",
                "        target: \"{environment|omit:preview}\"\n        region: \"{region|omit:auto}\"",
            );
    let err = TemplateRegistry::new()
        .load(&off_target)
        .expect_err("omit on a non-execution-target field must be refused");
    assert!(err.contains("pinned Identity execution target"), "{err}");

    // on a pinned SideEffect execution target — Identity only, by design.
    let on_side_effect = omit_base()
            .replace(
                "  - { name: environment, type: str, required: true, class: identity,     binding: exact_resource_pin }",
                "  - { name: environment, type: str, required: true, class: identity,     binding: exact_resource_pin }\n  - { name: mode, type: str, required: true, class: side_effect, binding: exact_resource_pin }",
            )
            .replace(
                "consumes: [project, repo_id, ref, environment]",
                "consumes: [project, repo_id, ref, environment, mode]",
            )
            .replace(
                "execution_targets: [project, repo_id, environment]",
                "execution_targets: [project, repo_id, environment, mode]",
            )
            .replace(
                "        target: \"{environment|omit:preview}\"",
                "        target: \"{environment|omit:preview}\"\n        mode: \"{mode|omit:auto}\"",
            );
    let err = TemplateRegistry::new()
        .load(&on_side_effect)
        .expect_err("omit on a SideEffect field must be refused");
    assert!(err.contains("pinned Identity execution target"), "{err}");

    // an unknown transform name is still refused (regression: not every `|x` is now legal).
    let unknown = omit_base().replace("environment|omit:preview", "environment|frobnicate");
    assert!(
        TemplateRegistry::new().load(&unknown).is_err(),
        "an unknown transform name must still be refused"
    );
}

// ---- The `result: verbatim` final-step mode ----

/// A single-step GET read template that returns the provider body UNCHANGED via `result:
/// verbatim` — the narrow read-passthrough the retired read_logs built-in embodied.
fn verbatim_base() -> String {
    r#"
provider: vercel
action: read_events
fields:
  - { name: deployment, type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [deployment]
execution_targets: [deployment]
http:
  steps:
    - id: get
      method: GET
      path: /v3/deployments/{deployment}/events
"#
    .to_string()
}

#[test]
fn a_read_template_names_no_return_shape_at_all() {
    // The response contract is verbatim, so a template declares nothing about what comes back.
    // Vercel's events endpoint answers a bare JSON array, which a keep-narrowing would have
    // nulled out; as an ordinary read, the array survives because nothing touches it.
    let reg = TemplateRegistry::new();
    let (p, a) = reg
        .load(&verbatim_base())
        .expect("a read template declaring no return shape must load");
    assert_eq!((p.as_str(), a.as_str()), ("vercel", "read_events"));
    assert!(reg.resolve("vercel", "read_events").is_some());
}

#[test]
fn the_retired_response_projection_keys_are_refused_at_load() {
    // The retirement is ENFORCED, not merely documented: `deny_unknown_fields` turns every one of
    // the old response-shaping keys into a load error, so a stale descriptor cannot silently keep
    // curating. Retention (`retention: none`) is NOT in this set — a storage cap is not a
    // projection — and is proved to still load below.
    for declaration in [
        "      keep: [events]",
        "      result: verbatim",
        "      error_status_only: true",
        "      capture_keep: { picked: [id] }",
        "      filter_prefix:\n        - { collection: events, field: name, starts_with: x }",
    ] {
        let doc = format!("{}{declaration}\n", verbatim_base());
        let err = match TemplateRegistry::new().load(&doc) {
            Err(error) => error,
            Ok(_) => panic!("a retired projection key must be refused at load: {declaration}"),
        };
        assert!(
            err.contains("unknown field"),
            "the refusal must name the unknown key: {declaration}\n{err}"
        );
    }
}

/// If a behavior isn't reflected in the configuration CLI, canonical docs, or settings, it does
/// not exist — unexpected behavior is worse than predictable leaks. Retention is scoped by that
/// rule: what Cermet durably keeps must be a stated declaration, not tribal knowledge.
///
/// The default is FULL, and this pins the catalog against it: `retention: none` survives ONLY
/// where a currently-valid justification is stated in the template. Everything else was a fossil
/// of the pre-verbatim doctrine ("the narrowed result is the complete response surface") and is
/// deleted, so the verb follows the declared default instead of a silent per-verb exception.
#[test]
fn retention_none_survives_only_where_a_stated_justification_does() {
    // The money floor: a ratified structural contract the validator itself enforces (a money
    // action MUST be one non-GET `retention: none` step), so it cannot be normalized away.
    const MONEY_FLOOR: &[&str] = &[
        "cancel_payment_intent",
        "capture_payment_intent",
        "confirm_payment_intent",
        "create_payment_intent_off_session",
        "create_standard_payout",
        "refund_charge_bounded",
        "retry_invoice_payment",
    ];
    // The two non-money survivors, each carrying a stated, still-valid reason rather than a
    // leftover (`github` is not product-enabled either way):
    //   - read_secret_scanning_alerts_open: its response space IS other people's leaked credentials,
    //     so keeping no durable copy is the point.
    //   - read_job_log: the minted-URL shape answers `302` with an EMPTY body, so there is no body
    //     to store. The mint itself rides the broker envelope into the receipt.
    const JUSTIFIED: &[&str] = &["read_secret_scanning_alerts_open", "read_job_log"];

    let mut declaring: Vec<String> = Vec::new();
    for doc in VENDORED_CATALOG {
        let template: ActionTemplate = serde_yaml::from_str(doc).expect("vendored doc parses");
        // The subprocess execution kind has no HTTP steps and no retention knob at all: its
        // declared response contract is a broker-authored receipt that stores nothing. A relay
        // verb declares no steps either, so it has no `retention` to justify.
        let ExecKind::Http { spec, .. } = &template.exec else {
            continue;
        };
        if spec
            .steps
            .iter()
            .any(|step| step.retention == RetentionMode::None)
        {
            declaring.push(format!("{}.{}", template.provider(), template.action()));
        }
    }
    declaring.sort();

    let mut expected: Vec<String> = MONEY_FLOOR
        .iter()
        .map(|action| format!("stripe.{action}"))
        .chain(JUSTIFIED.iter().map(|action| format!("github.{action}")))
        .collect();
    expected.sort();
    assert_eq!(
        declaring, expected,
        "retention defaults to FULL; a verb that declares `none` must carry a stated reason, and \
         adding one here means adding that reason to the template too"
    );
}

#[test]
fn a_retention_cap_is_not_a_projection_and_still_loads() {
    let doc = format!("{}      retention: none\n", verbatim_base());
    TemplateRegistry::new()
        .load(&doc)
        .expect("`retention: none` caps STORAGE and remains a legal declaration");
}

// ---- The frozen-query rule and the GraphQL step mandates ----
//
// These rules outlived their first example. `github.push_commit` used to be the fixture; it was
// deleted, but `graphql_query` still has a vendored consumer
// (`github.fixture_repositories_discover`, a frozen QUERY), so the rules below are live and get a
// self-contained mutation fixture instead of a verb.
const GRAPHQL_MUTATION_TEMPLATE: &str = r#"
provider: github
action: probe_graphql_write
fields:
  - { name: owner,   type: str, required: true, class: identity,     binding: exact_resource_pin }
  - { name: name,    type: str, required: true, class: identity,     binding: exact_resource_pin }
  - { name: message, type: str, required: true, class: free_payload, binding: unbound }
consumes: [owner, name, message]
execution_targets: [owner, name]
http:
  steps:
    - id: write
      method: POST
      path: /graphql
      success_statuses: [200]
      graphql_query: "mutation ($input: ProbeInput!) { probe(input: $input) { result { oid } } }"
      require: [data.probe.result.oid]
      body:
        variables:
          input:
            repositoryNameWithOwner: "{owner}/{name}"
            headline: "{message}"
"#;

#[test]
fn frozen_query_rule_refuses_a_body_query_key() {
    // THE FROZEN-QUERY RULE (structural): a top-level body key named `query` is refused at load
    // on ANY step — placeholder-bearing or not — so agent text can never become mutation text.
    let with_body_query = GRAPHQL_MUTATION_TEMPLATE.replace(
        "      body:\n        variables:",
        "      body:\n        query: \"{message}\"\n        variables:",
    );
    assert_ne!(
        with_body_query, GRAPHQL_MUTATION_TEMPLATE,
        "the fixture mutated"
    );
    let err = TemplateRegistry::new()
        .load(&with_body_query)
        .expect_err("a body `query` key must be refused at load");
    assert!(err.contains("query") && err.contains("frozen"), "{err}");
    // A LITERAL body query (no placeholder) is refused just the same — the rule is structural.
    let literal_query = GRAPHQL_MUTATION_TEMPLATE.replace(
        "      body:\n        variables:",
        "      body:\n        query: \"mutation x\"\n        variables:",
    );
    assert!(TemplateRegistry::new().load(&literal_query).is_err());
    // check_load and validate_doc agree with load.
    assert!(TemplateRegistry::new()
        .check_load(&with_body_query)
        .is_err());
    assert!(vendored_registry().validate_doc(&with_body_query).is_err());
}

#[test]
fn a_graphql_document_rides_only_a_post() {
    // A GraphQL document is a POST body; a GET step carrying one is refused at load.
    let get = GRAPHQL_MUTATION_TEMPLATE.replace("method: POST", "method: GET");
    let err = TemplateRegistry::new()
        .load(&get)
        .expect_err("a GET graphql step must be refused");
    assert!(err.contains("POST"), "{err}");
}

#[test]
fn graphql_step_without_require_refused_at_load() {
    // `require` is MANDATORY on a graphql step — without it, success would be inferred
    // from absence-of-errors alone, and a future verb could render an ambiguous 200 as success.
    let no_require =
        GRAPHQL_MUTATION_TEMPLATE.replace("      require: [data.probe.result.oid]\n", "");
    assert_ne!(no_require, GRAPHQL_MUTATION_TEMPLATE, "the fixture mutated");
    let err = TemplateRegistry::new()
        .load(&no_require)
        .expect_err("a graphql step with no `require` must be refused at load");
    assert!(
        err.contains("require") && err.contains("success predicate"),
        "the refusal names the mandate: {err}"
    );
    // An explicitly EMPTY require list is the same refusal (never a loophole).
    let empty_require = GRAPHQL_MUTATION_TEMPLATE.replace(
        "      require: [data.probe.result.oid]",
        "      require: []",
    );
    let err2 = TemplateRegistry::new()
        .load(&empty_require)
        .expect_err("an empty `require` list must be refused at load");
    assert!(err2.contains("require"), "{err2}");
    // check_load / validate_doc agree with load.
    assert!(TemplateRegistry::new().check_load(&no_require).is_err());
    assert!(vendored_registry().validate_doc(&no_require).is_err());
}

#[test]
fn expect_literal_accepts_scalars_and_fixed_string_arrays_only() {
    let base = r#"
provider: acme
action: clear
fields:
  - { name: target, type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [target]
execution_targets: [target]
http:
  steps:
    - id: clear
      method: POST
      path: /targets/{target}
      success_statuses: [200]
      require: [id]
      expect_literal: { cleared: <EXPECTED> }
      retention: none
"#;
    for expected in ["null", "true", "7", "ready", "[one, two]"] {
        TemplateRegistry::with_providers(HashSet::from(["acme".to_string()]))
            .load(&base.replace("<EXPECTED>", expected))
            .unwrap_or_else(|error| panic!("valid literal {expected} was refused: {error}"));
    }

    let oversized = format!(
        "[{}]",
        (0..=MAX_KEEP)
            .map(|index| format!("value_{index}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for structured in [
        "[]",
        "{}",
        "[[one]]",
        "[one, 2]",
        "[one, '']",
        "[one, one]",
        oversized.as_str(),
    ] {
        let error = TemplateRegistry::with_providers(HashSet::from(["acme".to_string()]))
            .load(&base.replace("<EXPECTED>", structured))
            .expect_err("only bounded unique nonempty string arrays are legal structured literals");
        assert!(
            error.contains("expect_literal"),
            "unexpected error for {structured}: {error}"
        );
    }
}

#[test]
fn https_url_is_a_reusable_string_field_format() {
    let document = r#"
provider: acme
action: set_endpoint
fields:
  - { name: endpoint, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: url, type: str, required: true, class: identity, binding: exact_resource_pin, format: https_url }
consumes: [endpoint, url]
execution_targets: [endpoint, url]
http:
  steps:
    - id: update
      method: POST
      path: /endpoints/{endpoint}
      body: { url: "{url}" }
"#;
    TemplateRegistry::with_providers(HashSet::from(["acme".to_string()]))
        .load(document)
        .expect("https_url must be a reusable string field format");
}

#[test]
fn final_expect_eq_is_a_postcondition_but_nonfinal_mutations_remain_refused() {
    let final_postcondition = r#"
provider: acme
action: set_endpoint
fields:
  - { name: endpoint, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: url, type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [endpoint, url]
execution_targets: [endpoint, url]
http:
  steps:
    - id: update
      method: POST
      path: /endpoints/{endpoint}
      body: { url: "{url}" }
      expect_eq: { url: url }
"#;
    TemplateRegistry::with_providers(HashSet::from(["acme".to_string()]))
        .load(final_postcondition)
        .expect("expect_eq is legal as a final mutation postcondition");

    let nonfinal_mutation = format!(
        "{final_postcondition}    - id: finish\n      method: POST\n      \
         path: /endpoints/{{endpoint}}/finish\n      body: {{ url: \"{{url}}\" }}\n"
    );
    let error = TemplateRegistry::with_providers(HashSet::from(["acme".to_string()]))
        .load(&nonfinal_mutation)
        .expect_err("a non-final mutation cannot carry a precondition expect_eq");
    assert!(
        error.contains("expect_eq") && error.contains("mutation"),
        "{error}"
    );
}

#[test]
fn every_verification_read_must_precede_every_mutation() {
    let late_rest_read = r#"
provider: acme
action: late_read
fields:
  - { name: id, type: str, required: true, class: identity, binding: exact_resource_pin }
consumes: [id]
execution_targets: [id]
http:
  steps:
    - id: mutate
      method: POST
      path: /objects/{id}
      body: { id: "{id}" }
    - id: verify
      method: GET
      path: /objects/{id}
"#;
    let late_graphql_read = late_rest_read
        .replace("action: late_read", "action: late_graphql_read")
        .replace(
            "      method: GET\n      path: /objects/{id}",
            "      method: POST\n      path: /graphql\n      graphql_query: \"query object($id: String!) { object(id: $id) { id } }\"\n      require: [data.object.id]\n      body: { variables: { id: \"{id}\" } }",
        );
    let late_expect_eq = late_rest_read.replace("      keep: [id]", "      expect_eq: { id: id }");
    let late_expect_literal =
        late_rest_read.replace("      keep: [id]", "      expect_literal: { active: true }");
    for document in [
        late_rest_read.to_string(),
        late_graphql_read,
        late_expect_eq,
        late_expect_literal,
    ] {
        let error = TemplateRegistry::with_providers(HashSet::from(["acme".to_string()]))
            .load(&document)
            .expect_err("a verification read after any mutation must fail load");
        assert!(
            error.contains("verification") && error.contains("PRECEDE"),
            "{error}"
        );
    }

    let preflight_then_mutations = late_rest_read
        .replace("action: late_read", "action: ordered_write")
        .replace(
            "    - id: mutate\n      method: POST\n      path: /objects/{id}\n      body: { id: \"{id}\" }\n    - id: verify\n      method: GET\n      path: /objects/{id}",
            "    - id: verify\n      method: GET\n      path: /objects/{id}\n      expect_eq: { id: id }\n    - id: mutate\n      method: POST\n      path: /objects/{id}\n      body: { id: \"{id}\" }\n    - id: finish\n      method: POST\n      path: /objects/{id}/finish\n      body: { id: \"{id}\" }",
        );
    TemplateRegistry::with_providers(HashSet::from(["acme".to_string()]))
        .load(&preflight_then_mutations)
        .expect("a leading read prefix followed only by mutations remains legal");
}

#[test]
fn string_character_limit_schema_is_closed_bounded_and_consumed() {
    let valid = r#"
provider: acme
action: write_text
fields:
  - { name: target, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: content, type: str, required: false, class: free_payload, binding: unbound, max_chars: 20000 }
  - { name: spare, type: str, required: false, class: free_payload, binding: unbound }
  - { name: count, type: int, required: false, class: side_effect, binding: bounded }
consumes: [target, content]
execution_targets: [target]
string_char_budget: { fields: [content], max_chars: 150000 }
http:
  steps:
    - id: write
      method: POST
      path: /targets/{target}
      body: { content: "{content?}" }
"#;
    let load = |document: &str| {
        TemplateRegistry::with_providers(HashSet::from(["acme".to_string()])).load(document)
    };
    load(valid).expect("bounded string fields and one aggregate character budget must load");

    for invalid in [
        valid.replace("max_chars: 20000", "max_chars: 0"),
        valid.replace("max_chars: 20000", "max_chars: 262145"),
        valid.replace("max_chars: 20000", "max_chars: null"),
        valid.replace(
            "name: count, type: int, required: false",
            "name: count, type: int, max_chars: 2, required: false",
        ),
        valid.replace("fields: [content]", "fields: []"),
        valid.replace("fields: [content]", "fields: [content, content]"),
        valid.replace("fields: [content]", "fields: [missing]"),
        valid.replace("fields: [content]", "fields: [count]"),
        valid.replace("fields: [content]", "fields: [spare]"),
        valid.replace("max_chars: 150000", "max_chars: 0"),
        valid.replace("max_chars: 150000", "max_chars: 262145"),
        valid.replace(
            "string_char_budget: { fields: [content], max_chars: 150000 }",
            "string_char_budget: { fields: [content], max_chars: 150000, extra: true }",
        ),
        valid.replace(
            "string_char_budget: { fields: [content], max_chars: 150000 }",
            "string_char_budget: null",
        ),
    ] {
        load(&invalid).expect_err("malformed character limits must fail closed");
    }
}

#[test]
fn integer_ceiling_schema_is_closed_typed_and_positive() {
    let valid = r#"
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
    let load = |document: &str| {
        TemplateRegistry::with_providers(HashSet::from(["acme".to_string()])).load(document)
    };
    load(valid).expect("a positive integer ceiling on an int field must load");

    for invalid in [
        valid.replace("max_int: 100", "max_int: 0"),
        valid.replace("max_int: 100", "max_int: -1"),
        valid.replace("max_int: 100", "max_int: null"),
        valid.replace(
            "name: target, type: str, required: true",
            "name: target, type: str, max_int: 100, required: true",
        ),
    ] {
        load(&invalid).expect_err("malformed integer ceilings must fail closed");
    }
}

const MONEYPATH_TEST_EVIDENCE_TEMPLATE: &str = r#"
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
      body_encoding: form
      body: { amount: "{amount}", account: "{account}", currency: "{currency}", mode: "{mode}" }
      success_statuses: [200]
      require: [id, object, amount, account, currency, livemode]
      expect_eq: { id: charge, amount: amount, account: account, currency: currency }
      expect_literal: { object: charge, livemode: false }
      retention: none
"#;

#[test]
fn moneypath_compiled_profile_derives_catalog_field_origins() {
    let registry = TemplateRegistry::new();
    registry
        .load(MONEYPATH_TEST_EVIDENCE_TEMPLATE)
        .expect("the exact compiled test profile loads");
    let entry = registry
        .loaded("stripe", "test_charge_evidence")
        .unwrap()
        .template
        .catalog_entry(true, true);
    let value = serde_json::to_value(entry).unwrap();
    let fields = value["fields"].as_array().unwrap();
    let origin = |name: &str| {
        fields
            .iter()
            .find(|field| field["name"] == name)
            .and_then(|field| field["origin"].as_str())
    };
    assert_eq!(origin("charge"), Some("agent_request"));
    assert_eq!(origin("amount"), Some("agent_request"));
    assert_eq!(origin("account"), Some("provider_resolved"));
    assert_eq!(origin("currency"), Some("provider_resolved"));
    assert_eq!(origin("mode"), Some("provider_resolved"));
}

#[test]
fn moneypath_profile_contract_validation_rejects_unknown_mismatched_and_bad_outputs() {
    let variants = [
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace(
            "stripe.test_charge.v1",
            "stripe.unknown.v1",
        ),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace(
            "action: test_charge_evidence",
            "action: another_action",
        ),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace(
            "name: account, type: str, required: true",
            "name: account, type: str, required: false",
        ),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace(
            "name: charge, type: str",
            "name: charge, type: int",
        ),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace(
            "name: currency, type: str",
            "name: currency, type: bool",
        ),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace(
            "name: mode, type: str, required: true, class: identity, binding: exact_resource_pin",
            "name: mode, type: str, required: true, class: free_payload, binding: unbound",
        ),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace(
            "  - { name: account, type: str, required: true, class: identity, binding: exact_resource_pin }\n",
            "",
        ),
    ];
    for variant in variants {
        assert!(
            TemplateRegistry::new().load(&variant).is_err(),
            "bad profile/template shape loaded:\n{variant}"
        );
    }
}

#[test]
fn moneypath_money_metadata_requires_the_canonical_frozen_shape() {
    TemplateRegistry::new()
        .load(MONEYPATH_TEST_EVIDENCE_TEMPLATE)
        .expect("the exact compiled money fixture loads");

    let variants = [
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace("name: amount, type: int", "name: total, type: int"),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace("required: true, class: side_effect, binding: bounded", "required: false, class: side_effect, binding: bounded"),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace("name: account, type: str, required: true, class: identity, binding: exact_resource_pin", "name: account, type: str, required: false, class: identity, binding: exact_resource_pin"),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace("name: mode, type: str, required: true, class: identity, binding: exact_resource_pin", "name: mode, type: str, required: true, class: identity, binding: exact_or_pattern_list"),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace("name: currency, type: str, required: true, class: identity, binding: exact_resource_pin", "name: currency, type: str, required: true, class: identity, binding: exact_or_pattern_list"),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace("preconditions: [test_charge_ready]", "preconditions: [unknown]"),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace("name: charge, type: str, required: true, class: identity, binding: exact_resource_pin", "name: charge, type: str, required: true, class: side_effect, binding: exact_resource_pin")
    ];
    for variant in variants {
        assert!(
            TemplateRegistry::new().load(&variant).is_err(),
            "invalid money metadata loaded:\n{variant}"
        );
    }
}

#[test]
fn moneypath_money_mutation_is_unretained_and_maps_canonical_amount() {
    let registry = TemplateRegistry::new();
    registry.load(MONEYPATH_TEST_EVIDENCE_TEMPLATE).unwrap();
    let loaded = registry.loaded("stripe", "test_charge_evidence").unwrap();
    assert!(loaded.template.is_money());
    assert_eq!(loaded.template.precondition_names(), ["test_charge_ready"]);

    for (needle, replacement) in [
        ("retention: none", "retention: full"),
        ("amount: \"{amount}\"", "amount_to_capture: 1"),
        ("method: POST", "method: GET"),
    ] {
        let variant = MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace(needle, replacement);
        assert!(
            TemplateRegistry::new().load(&variant).is_err(),
            "unsafe money wire shape loaded:\n{variant}"
        );
    }
}

#[test]
fn a_money_contract_declares_no_response_projection_because_none_exists() {
    // The grammar has no way to express a money response projection — the refusal is
    // structural, and the load error says so. `retention: none` still holds: money bodies reach
    // the receipt but never the artifact store.
    TemplateRegistry::new()
        .load(MONEYPATH_TEST_EVIDENCE_TEMPLATE)
        .expect("the money contract loads");
    for projected in ["id", "client_secret", "status", "amount"] {
        let variant = MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace(
            "      retention: none",
            &format!("      keep: [{projected}]\n      retention: none"),
        );
        let error = TemplateRegistry::new()
            .load(&variant)
            .expect_err("a money contract cannot express a response projection");
        assert!(error.contains("unknown field"), "{projected}: {error}");
    }
}

#[test]
fn moneypath_money_success_contract_must_exactly_match_compiled_semantics() {
    let variants = [
        MONEYPATH_TEST_EVIDENCE_TEMPLATE
            .replace("success_statuses: [200]", "success_statuses: [201]"),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace(
            "require: [id, object, amount, account, currency, livemode]",
            "require: [id, object, amount, account, currency]",
        ),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace("id: charge", "id: account"),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace("object: charge", "object: refund"),
        MONEYPATH_TEST_EVIDENCE_TEMPLATE.replace("livemode: false", "livemode: true"),
    ];
    for variant in variants {
        let error = TemplateRegistry::new()
            .load(&variant)
            .expect_err("money response semantics may not drift from trusted compiled code");
        assert!(error.contains("success contract"), "{error}");
    }
}

#[test]
fn moneypath_money_rejects_a_second_exact_bound_side_effect() {
    let variant = MONEYPATH_TEST_EVIDENCE_TEMPLATE
        .replace(
            "  - { name: amount, type: int, required: true, class: side_effect, binding: bounded }",
            "  - { name: amount, type: int, required: true, class: side_effect, binding: bounded }\n  - { name: fee, type: int, required: true, class: side_effect, binding: exact_resource_pin }",
        )
        .replace(
            "consumes: [charge, amount, account, currency, mode]",
            "consumes: [charge, amount, fee, account, currency, mode]",
        )
        .replace(
            "execution_targets: [charge, account, currency, mode]",
            "execution_targets: [charge, fee, account, currency, mode]",
        )
        .replace(
            "body: { amount: \"{amount}\", account:",
            "body: { amount: \"{amount}\", fee: \"{fee}\", account:",
        );
    assert!(
        TemplateRegistry::new().load(&variant).is_err(),
        "a second exact-bound side effect loaded:\n{variant}"
    );
}

// ---------------------------------------------------------------------------
// the git execution kind
// ---------------------------------------------------------------------------

const GIT_TEMPLATE: &str = r#"
provider: github
action: probe_push
fields:
  - { name: owner,   type: str, required: true,  class: identity, binding: exact_resource_pin }
  - { name: name,    type: str, required: true,  class: identity, binding: exact_resource_pin }
  - { name: branch,  type: str, required: true,  class: identity, binding: exact_resource_pin, format: git_branch_name }
  - { name: new_oid, type: str, required: true,  class: identity, binding: exact_resource_pin, format: git_oid }
  - { name: mirror_old_oid, type: str, required: false, class: identity, binding: exact_resource_pin, format: git_oid }
consumes: [owner, name, branch, new_oid, mirror_old_oid]
execution_targets: [owner, name, branch]
git:
  push:
    remote_path: "/{owner}/{name}.git"
    branch: branch
    new_oid: new_oid
    mirror_old_oid: mirror_old_oid
"#;

fn git_registry() -> TemplateRegistry {
    TemplateRegistry::with_ceilings(crate::provider::vendored_provider_ceilings().clone())
}

#[test]
fn a_git_template_loads_against_a_provider_that_pins_a_git_origin() {
    git_registry()
        .check_load(GIT_TEMPLATE)
        .expect("github pins a git origin");
}

#[test]
fn a_git_template_refuses_a_provider_with_no_pinned_git_origin() {
    // vercel has an egress origin but no `git:` block, so a credential can never ride the git seam.
    let doc = GIT_TEMPLATE.replace("provider: github", "provider: vercel");
    let error = git_registry()
        .check_load(&doc)
        .expect_err("a provider with no git origin cannot be extended by a git template");
    assert!(error.contains("pins no git origin"), "{error}");
}

#[test]
fn a_template_declaring_both_execution_kinds_is_refused() {
    let doc = format!(
        "{GIT_TEMPLATE}\nhttp:\n  steps:\n    - id: s\n      method: GET\n      path: /x\n"
    );
    let error = git_registry()
        .check_load(&doc)
        .expect_err("exactly one execution kind");
    assert!(error.contains("mutually exclusive"), "{error}");
}

#[test]
fn a_template_declaring_no_execution_kind_is_refused() {
    let doc = GIT_TEMPLATE
        .split("git:")
        .next()
        .expect("split")
        .to_string();
    let error = git_registry()
        .check_load(&doc)
        .expect_err("a template must declare an execution kind");
    assert!(error.contains("must declare `http:` or `git:`"), "{error}");
}

#[test]
fn the_git_remote_path_must_be_a_path_of_pinned_identities() {
    for (patch, expected) in [
        (
            "remote_path: \"https://evil.test/{owner}/{name}.git\"",
            "must start with `/`",
        ),
        ("remote_path: \"/{nope}/{name}.git\"", "undeclared field"),
        // `pack`-shaped fields are gone entirely, so the "wrong class in the path" case is now
        // expressed by a field that IS declared but is not a repo-addressing identity: swapping
        // `owner` out makes the honesty check fire first, which is the same refusal one step
        // earlier.
        (
            "remote_path: \"/{new_oid}/{name}.git\"",
            "which the git push step never references",
        ),
    ] {
        let doc = GIT_TEMPLATE.replace("remote_path: \"/{owner}/{name}.git\"", patch);
        let error = git_registry()
            .check_load(&doc)
            .expect_err("a remote path must be a path of pinned identities");
        assert!(error.contains(expected), "{patch}: {error}");
    }
}

#[test]
fn each_git_push_slot_must_carry_the_class_binding_and_format_the_runner_assumes() {
    // A `new_oid` without the git_oid shape would let a ref NAME through to the subprocess.
    let doc = GIT_TEMPLATE.replace(
        "{ name: new_oid, type: str, required: true,  class: identity, binding: exact_resource_pin, format: git_oid }",
        "{ name: new_oid, type: str, required: true,  class: identity, binding: exact_resource_pin }",
    );
    let error = git_registry()
        .check_load(&doc)
        .expect_err("new_oid must pin the git_oid shape");
    assert!(error.contains("git.push.new_oid field"), "{error}");

    // `mirror_old_oid` is optional by design: a required one would make ref CREATION unexpressible.
    let doc = GIT_TEMPLATE.replace(
        "{ name: mirror_old_oid, type: str, required: false, class: identity, binding: exact_resource_pin, format: git_oid }",
        "{ name: mirror_old_oid, type: str, required: true,  class: identity, binding: exact_resource_pin, format: git_oid }",
    );
    let error = git_registry()
        .check_load(&doc)
        .expect_err("the mirror's tip is a fact, never a required guard");
    assert!(error.contains("git.push.mirror_old_oid field"), "{error}");
}

/// The push step moves ONE ref, and it names which namespace it moves it in: `branch:` or `tag:`.
/// Declaring both would make one verb two effects under one sentence — a branch authority silently
/// admitting tags; declaring neither leaves the runner with no ref to move at all.
#[test]
fn a_git_push_step_names_exactly_one_of_branch_and_tag() {
    let both = GIT_TEMPLATE.replace("    branch: branch\n", "    branch: branch\n    tag: tag\n");
    let error = git_registry()
        .check_load(&both)
        .expect_err("branch and tag are alternatives, not a pair");
    assert!(
        error.contains("exactly one of `branch` and `tag`"),
        "{error}"
    );

    let neither = GIT_TEMPLATE.replace("    branch: branch\n", "");
    let error = git_registry()
        .check_load(&neither)
        .expect_err("a push step with no ref names no effect");
    assert!(
        error.contains("exactly one of `branch` and `tag`"),
        "{error}"
    );
}

/// The tag alternative is a first-class push step: same remote path, same oid slots, its own
/// `git_tag_name` admission shape on the ref component.
#[test]
fn a_git_push_step_may_name_a_tag_instead_of_a_branch() {
    let doc = GIT_TEMPLATE
        .replace(
            "  - { name: branch,  type: str, required: true,  class: identity, binding: exact_resource_pin, format: git_branch_name }",
            "  - { name: tag,     type: str, required: true,  class: identity, binding: exact_resource_pin, format: git_tag_name }",
        )
        .replace(
            "consumes: [owner, name, branch, new_oid, mirror_old_oid]",
            "consumes: [owner, name, tag, new_oid, mirror_old_oid]",
        )
        .replace(
            "execution_targets: [owner, name, branch]",
            "execution_targets: [owner, name, tag]",
        )
        .replace("    branch: branch\n", "    tag: tag\n");
    git_registry()
        .check_load(&doc)
        .expect("a tag push step is a valid git verb");

    // And the slot pins its own shape: a branch-shaped format on the tag slot is refused.
    let wrong = doc.replace("format: git_tag_name", "format: git_branch_name");
    let error = git_registry()
        .check_load(&wrong)
        .expect_err("the tag slot pins the tag shape");
    assert!(error.contains("git.push.tag field"), "{error}");
}

#[test]
fn a_git_template_consumes_exactly_what_its_step_references() {
    let doc = GIT_TEMPLATE.replace(
        "consumes: [owner, name, branch, new_oid, mirror_old_oid]",
        "consumes: [owner, name, branch, new_oid]",
    );
    let error = git_registry()
        .check_load(&doc)
        .expect_err("an omitted consumed field is a dishonest declaration");
    assert!(error.contains("`consumes` omits it"), "{error}");
}

#[test]
fn a_git_template_may_declare_neither_money_nor_request_evidence() {
    let doc = GIT_TEMPLATE.replace(
        "consumes:",
        "request_evidence: stripe.create_payment_intent_off_session/v1\nconsumes:",
    );
    let error = git_registry()
        .check_load(&doc)
        .expect_err("evidence resolution is an http-only mechanism");
    assert!(error.contains("request_evidence"), "{error}");
}

#[test]
fn the_vendored_push_verb_carries_no_carrier_vocabulary() {
    // The boundary ruling in code: a git verb declares WHO and WHERE, never HOW the bytes travel.
    let registry = crate::templates::vendored_registry();
    let loaded = registry
        .loaded("github", "push")
        .expect("github.push is vendored");
    let spec = loaded
        .template
        .git_spec()
        .expect("push declares the git execution kind");
    let push = spec.push.as_ref().expect("push declares the push step");
    assert!(spec.fetch.is_none(), "one verb, one effect");
    assert_eq!(push.remote_path, "/{owner}/{name}.git");
    assert_eq!(push.mirror_old_oid.as_deref(), Some("mirror_old_oid"));

    let fields: Vec<&str> = loaded.contract.schema.iter().map(|f| f.name).collect();
    assert_eq!(
        fields,
        vec!["owner", "name", "branch", "new_oid", "mirror_old_oid"],
        "the `old` half of the hook tuple is named for the MIRROR's tip"
    );
    for carrier in ["pack_sha256", "pack", "changes", "content", "digest"] {
        assert!(
            !fields.contains(&carrier),
            "`{carrier}` is carrier vocabulary and belongs to git, not to Cermet"
        );
    }
    // The response contract is derived from what it DOES: a broker-authored receipt, nothing stored.
    let response = loaded.template.response_contract();
    assert_eq!(response.returns, "receipt");
    assert_eq!(response.retention, "none");
    assert_eq!(response.errors, "refusal");
}

/// `push_tag` is a SEPARATE verb, not a widening of `push`. Sentence bounds are conjunctive over a
/// verb's own fields, so a standing `allow github.push where …` can only ever admit branches: the
/// tag namespace needs its own word, and that word carries the tag's own admission shape.
#[test]
fn the_vendored_tag_verb_is_a_separate_word_pinning_a_bare_tag_name() {
    let registry = crate::templates::vendored_registry();
    let loaded = registry
        .loaded("github", "push_tag")
        .expect("github.push_tag is vendored");
    let spec = loaded
        .template
        .git_spec()
        .expect("push_tag declares the git execution kind");
    let push = spec.push.as_ref().expect("push_tag declares a push step");
    assert!(spec.fetch.is_none(), "one verb, one effect");
    assert_eq!(push.branch, None, "a tag verb moves no branch");
    assert_eq!(push.tag.as_deref(), Some("tag"));

    let fields: Vec<&str> = loaded.contract.schema.iter().map(|f| f.name).collect();
    assert_eq!(
        fields,
        vec!["owner", "name", "tag", "new_oid", "mirror_old_oid"]
    );
    let tag = loaded
        .template
        .format_fields()
        .into_iter()
        .find(|(name, _)| *name == "tag")
        .expect("the tag field declares a format");
    assert_eq!(tag.1, FieldFormat::GitTagName);

    // `push` and `push_tag` share nothing on the sentence axis: `push` has no `tag` field for a
    // branch sentence to be widened onto, and vice versa.
    let branch_verb = registry.loaded("github", "push").expect("push is vendored");
    assert!(branch_verb.contract.schema.iter().all(|f| f.name != "tag"));
    assert!(loaded.contract.schema.iter().all(|f| f.name != "branch"));
}

// ---------------------------------------------------------------------------
// `execution: relay` + `predicate`
// ---------------------------------------------------------------------------

/// The shipped relay verb, minus its comments — the base every reject case below mutates.
const RELAY_DOC: &str = "\
provider: vercel
action: deploy
fields:
  - { name: project, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: target, type: str, required: true, class: side_effect, binding: exact_resource_pin, fixed: preview }
consumes: [project, target]
execution_targets: [project]
execution: relay
predicate:
  - method: POST
    path: /v13/deployments
    once: true
    query_keys: [forceNew]
    body_keys: [files]
    bind:
      body.name: project
      body.target: \"target|omit:preview\"
  - { method: POST, path: /v2/files }
  - { method: GET, path: /v13/deployments/* }
";

/// The same document with a per-session budget on the upload shape — `capped(uses, bytes)`
/// mutates only that one rule, so every other reject case above keeps its own base text.
fn capped(max_uses: &str, max_total_bytes: &str) -> String {
    RELAY_DOC.replace(
        "  - { method: POST, path: /v2/files }",
        &format!(
            "  - {{ method: POST, path: /v2/files, caps: {{ max_uses: {max_uses}, \
             max_total_bytes: {max_total_bytes} }} }}"
        ),
    )
}

fn relay_load(doc: &str) -> Result<(String, String), String> {
    TemplateRegistry::new().load(doc)
}

#[test]
fn relay_template_loads_and_declares_a_relay_shape_and_receipt_contract() {
    relay_load(RELAY_DOC).expect("the relay grammar accepts a well-formed relay verb");

    let template: ActionTemplate = serde_yaml::from_str(RELAY_DOC).unwrap();
    assert_eq!(template.shape(), CatalogShape::Relay);
    // A relay verb makes no provider call at execute: no steps, nothing to retain, receipt errors.
    assert!(template.http_step_shapes().is_none());
    assert!(template.steps().is_empty());
    let response = template.response_contract();
    assert_eq!(
        (
            response.returns.as_str(),
            response.retention.as_str(),
            response.errors.as_str()
        ),
        ("receipt", "none", "receipt")
    );
    assert_eq!(template.fixed_fields(), vec![("target", "preview")]);

    let predicate = template.relay_predicate().expect("a relay predicate");
    assert_eq!(predicate.len(), 3);
    // The binding rule declares its body vocabulary; the opaque upload rule declares none.
    assert_eq!(predicate[0].body_keys(), Some(&["files".to_string()][..]));
    assert_eq!(
        predicate.iter().filter(|r| r.body_keys().is_none()).count(),
        2,
        "only the rules with no binds leave the body unparsed"
    );
    assert_eq!(predicate.iter().filter(|rule| rule.once).count(), 1);
    assert_eq!(
        predicate[0].binds(),
        vec![
            RelayBind {
                location: BindLocation::Body("name".into()),
                field: "project".into(),
                absent_when: None
            },
            RelayBind {
                location: BindLocation::Body("target".into()),
                field: "target".into(),
                absent_when: Some("preview".into())
            },
        ]
    );
}

/// The second bind location. A query parameter's VALUE carries authority exactly like a
/// body key's (Vercel's `teamId` names the SCOPE the request lands in), so the grammar admits
/// `query.<key>` with the same `omit:` form — and a query bind is legal on a bodyless method, since
/// it reads the target, not a body.
#[test]
fn relay_grammar_accepts_a_query_value_bind_on_any_method() {
    let doc = RELAY_DOC
        .replace(
            "  - { method: GET, path: /v13/deployments/* }",
            "  - { method: GET, path: /v13/deployments/*, query_keys: [teamId], \
             bind: { query.teamId: \"scope|omit:default\" } }",
        )
        .replace(
            "consumes: [project, target]",
            "consumes: [project, target, scope]",
        )
        .replace(
            "execution_targets: [project]",
            "execution_targets: [project, scope]",
        )
        .replace(
            "fields:\n",
            "fields:\n  - { name: scope, type: str, required: true, class: identity, \
             binding: exact_resource_pin }\n",
        );
    relay_load(&doc).expect("a query-value bind is a well-formed relay bind");

    let template: ActionTemplate = serde_yaml::from_str(&doc).unwrap();
    let predicate = template.relay_predicate().expect("a relay predicate");
    let read = predicate
        .iter()
        .find(|rule| rule.path == "/v13/deployments/*")
        .expect("the read shape");
    assert_eq!(
        read.binds(),
        vec![RelayBind {
            location: BindLocation::Query("teamId".into()),
            field: "scope".into(),
            absent_when: Some("default".into()),
        }],
        "a bodyless read binds a query VALUE, and declares no body_keys to do it"
    );
    assert!(
        read.body_keys().is_none(),
        "a query bind reads the target, so it never makes the body parsed"
    );
}

/// The ratification obligation, enforced on the SHIPPED verb: a key that carries authority is BOUND,
/// not merely declared. `teamId` names the scope a request lands in, so a shape declaring the key
/// either binds it to the frozen `team` or is one of the shapes whose values are ratified
/// AUTHORITY-FREE in the document — the obligation's two branches, and no third state where a key
/// this shape knows about goes unclassified.
///
/// The authority-free set is spelled out HERE, exhaustively, so it stays a decision rather than a
/// drift: adding an unbound `teamId` shape fails this test until someone widens this list on
/// purpose. Today it holds two members, the CLI's two query-less preamble reads: the team-context
/// call (team named in the PATH, discloses no more than the bindless `GET /v1/teams`) and the
/// linked-project retrieve (project named in the path, read-only, token-scoped; the live
/// linked-dir flow sends it with no query, which the unlinked stub capture never showed).
#[test]
fn every_admitted_teamid_key_is_classified_in_the_shipped_relay_verb() {
    const RATIFIED_AUTHORITY_FREE: [(&str, &str); 2] =
        [("GET", "/teams/*"), ("GET", "/v9/projects/*")];
    let mut seen_free: Vec<(String, String)> = Vec::new();
    for doc in VENDORED_CATALOG {
        let template: ActionTemplate = serde_yaml::from_str(doc).unwrap();
        let Some(predicate) = template.relay_predicate() else {
            continue;
        };
        for rule in predicate {
            if !rule.query_keys.iter().any(|key| key == "teamId") {
                continue;
            }
            let bound = rule
                .binds()
                .into_iter()
                .find(|bind| bind.location == BindLocation::Query("teamId".into()));
            if RATIFIED_AUTHORITY_FREE
                .iter()
                .any(|(method, path)| *method == rule.method && *path == rule.path)
            {
                seen_free.push((rule.method.clone(), rule.path.clone()));
                assert_eq!(
                    bound, None,
                    "{} {}: ratified authority-free, so it must NOT also declare a bind",
                    rule.method, rule.path
                );
                continue;
            }
            assert_eq!(
                bound,
                Some(RelayBind {
                    location: BindLocation::Query("teamId".into()),
                    field: "team".into(),
                    absent_when: None,
                }),
                "{} {}: an admitted `teamId` key whose value is neither bound nor ratified \
                 authority-free is a scope the sentence never froze",
                rule.method,
                rule.path
            );
        }
    }
    assert_eq!(
        seen_free.len(),
        RATIFIED_AUTHORITY_FREE.len(),
        "the authority-free list names a shape the shipped verb no longer has: {seen_free:?}"
    );
}

/// The document-level half of the same rule: an `omit:` literal on an OPTIONAL bind field is
/// refused at load. It would be a second spelling of a state the field already has — and a
/// contradictory one, since the engine reads an absent optional field as UNCONSTRAINED while the
/// literal claims a specific frozen value demands the key's absence.
#[test]
fn relay_grammar_refuses_an_omit_transform_on_an_optional_field() {
    let doc = CANONICALIZE_DOC.replace("query.teamId: team", "query.teamId: \"team|omit:none\"");
    let err = relay_load(&doc).expect_err("an optional field cannot also carry an omit literal");
    assert!(
        err.contains("team") && err.contains("optional"),
        "the refusal names the field and why: {err}"
    );

    // ...and the same literal on a REQUIRED field stays legal, which is the shape it exists for.
    let required = doc.replace(
        "name: team, type: str, required: false",
        "name: team, type: str, required: true",
    );
    relay_load(&required).expect("`omit:` on a required field is the sanctioned shape");
}

/// An `assert` may not name an optional field at all: it exists to DETECT a landed outcome
/// contradicting the approval, and there is nothing to contradict when nothing was frozen.
#[test]
fn relay_grammar_refuses_an_assertion_on_an_optional_field() {
    let doc = CANONICALIZE_DOC.replace(
        "      query.teamId: team\n",
        "      query.teamId: team\n    assert:\n      teamId: team\n",
    );
    let err = relay_load(&doc).expect_err("an assertion on an optional field detects nothing");
    assert!(
        err.contains("team") && err.contains("optional"),
        "the refusal names the field and why: {err}"
    );
}

#[test]
fn the_shipped_deploy_is_the_only_relay_verb_and_binds_project_and_target() {
    let mut relay_verbs = Vec::new();
    for doc in VENDORED_CATALOG {
        let template: ActionTemplate = serde_yaml::from_str(doc).unwrap();
        if let Some(predicate) = template.relay_predicate() {
            relay_verbs.push(format!("{}.{}", template.provider(), template.action()));
            // Every admitted shape is enumerated; nothing is open-ended.
            assert!(
                predicate.iter().all(|rule| !rule.path.contains("**")),
                "a relay path admits one segment per `*`, never a subtree"
            );
        }
    }
    assert_eq!(relay_verbs, vec!["vercel.deploy".to_string()]);
}

/// The shipped verb's `team`, at the document level: it is OPTIONAL and its `teamId` binds carry no
/// transform. A bind whose source field can freeze as absence has no "safe absent value" to encode —
/// absence IS the unconstrained case — so an `omit:` literal there would be a second, contradictory
/// spelling of the same state. `target` keeps its `omit:` literal, which is the shape that transform
/// exists for: a REQUIRED field one of whose legal values the provider expresses by sending no key.
#[test]
fn the_shipped_team_is_optional_and_its_scope_binds_carry_no_transform() {
    let doc = VENDORED_CATALOG
        .iter()
        .copied()
        .find(|doc| doc.contains("action: deploy"))
        .expect("the vercel relay verb is vendored");
    let template: ActionTemplate = serde_yaml::from_str(doc).unwrap();

    let entry = template.catalog_entry(true, false);
    let team = entry
        .fields
        .iter()
        .find(|field| field.name == "team")
        .expect("the shipped verb declares team");
    assert!(
        !team.required,
        "a deploy that names no Vercel scope is a legal request"
    );

    let predicate = template.relay_predicate().expect("a relay predicate");
    let scope_binds: Vec<RelayBind> = predicate
        .iter()
        .flat_map(|rule| rule.binds())
        .filter(|bind| bind.field == "team")
        .collect();
    assert!(
        !scope_binds.is_empty(),
        "the scope is still bound wherever it decides where the deploy lands"
    );
    assert!(
        scope_binds.iter().all(|bind| bind.absent_when.is_none()),
        "an optional field's bind encodes absence by being absent, never by a literal: \
         {scope_binds:?}"
    );
    // ...while the REQUIRED `target` still uses one, so this is a rule about optionality and not a
    // retreat from the transform.
    assert!(
        predicate
            .iter()
            .flat_map(|rule| rule.binds())
            .any(|bind| bind.field == "target" && bind.absent_when.as_deref() == Some("preview")),
        "the required side-effect field keeps its `omit:` encoding"
    );
}

/// A shape may declare a per-session BUDGET — how many hops it admits and how many
/// aggregate request bytes they may carry. Both dimensions are required together: a count with no
/// byte bound (or the reverse) is a half-closed surface, and this grammar closes surfaces.
#[test]
fn relay_grammar_accepts_a_shape_budget_and_refuses_a_vacuous_one() {
    let doc = capped("8", "4096");
    relay_load(&doc).expect("a positive budget on a shape is well-formed");
    let template: ActionTemplate = serde_yaml::from_str(&doc).unwrap();
    let predicate = template.relay_predicate().expect("a relay predicate");
    let upload = predicate
        .iter()
        .find(|rule| rule.path == "/v2/files")
        .expect("the upload shape");
    assert_eq!(
        upload.caps(),
        Some(RelayCaps {
            max_uses: 8,
            max_total_bytes: 4096
        })
    );
    assert!(
        predicate
            .iter()
            .all(|rule| rule.path == "/v2/files" || rule.caps().is_none()),
        "a budget is per shape and declared, never a default nobody wrote"
    );

    for (why, doc, expected) in [
        (
            "a zero use budget admits nothing — delete the shape instead of declaring it dead",
            capped("0", "4096"),
            "must be positive",
        ),
        (
            "a zero byte budget admits nothing either",
            capped("8", "0"),
            "must be positive",
        ),
        (
            "half a budget is a half-closed surface",
            RELAY_DOC.replace(
                "  - { method: POST, path: /v2/files }",
                "  - { method: POST, path: /v2/files, caps: { max_uses: 8 } }",
            ),
            "missing field `max_total_bytes`",
        ),
        (
            "an unknown cap dimension must not be silently ignored",
            RELAY_DOC.replace(
                "  - { method: POST, path: /v2/files }",
                "  - { method: POST, path: /v2/files, caps: { max_uses: 8, max_total_bytes: 1, \
                 max_hops_per_minute: 3 } }",
            ),
            "unknown field",
        ),
    ] {
        let err = relay_load(&doc).expect_err(why);
        assert!(err.contains(expected), "{why}: {err}");
    }
}

#[test]
fn relay_grammar_rejects_a_predicate_that_is_not_a_closed_bounded_surface() {
    // Each case: (what is wrong, the mutated document, a substring the refusal must name).
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "an http verb may not carry a predicate",
            RELAY_DOC.replace("execution: relay\n", ""),
            "legal only with `execution: relay`",
        ),
        (
            "a relay verb may not also declare steps",
            format!("{RELAY_DOC}http:\n  steps:\n    - {{ id: g, method: GET, path: /v2/user }}\n"),
            "must not declare `http:`",
        ),
        (
            "a relay verb with no predicate admits nothing knowable",
            RELAY_DOC
                .split_once("predicate:")
                .map(|(head, _)| format!("{head}predicate: []\n"))
                .unwrap(),
            "at least one request shape",
        ),
        (
            "two `once` rules would be two effects on a single-use grant",
            RELAY_DOC.replace(
                "  - { method: POST, path: /v2/files }",
                "  - { method: POST, path: /v2/files, once: true }",
            ),
            "exactly one `once: true`",
        ),
        (
            "no `once` rule means no effect is named",
            RELAY_DOC.replace("    once: true\n", ""),
            "exactly one `once: true`",
        ),
        (
            "a relative path could escape the origin's path space",
            RELAY_DOC.replace("path: /v13/deployments\n", "path: v13/deployments\n"),
            "is not `/`-rooted",
        ),
        (
            "a query string in the path would smuggle an undeclared parameter",
            RELAY_DOC.replace(
                "path: /v13/deployments\n",
                "path: /v13/deployments?teamId=other\n",
            ),
            "carries a query or fragment",
        ),
        (
            "a traversal segment is not a literal",
            RELAY_DOC.replace("path: /v2/files }", "path: /v2/../files }"),
            "wildcard `*`",
        ),
        (
            "a lowercase method would never match the request's uppercase one",
            RELAY_DOC.replace("method: POST\n", "method: post\n"),
            "uppercase",
        ),
        (
            "the same shape twice is an authoring mistake, not two authorities",
            RELAY_DOC.replace(
                "  - { method: POST, path: /v2/files }",
                "  - { method: GET, path: /v13/deployments/* }",
            ),
            "more than once",
        ),
        (
            "a bind on a bodyless method has nothing to read",
            RELAY_DOC.replace(
                "  - { method: GET, path: /v13/deployments/* }",
                "  - { method: GET, path: /v13/deployments/*, bind: { body.name: project } }",
            ),
            "bodyless method",
        ),
        (
            "a body key or a query key are the supported request locations, nothing else",
            RELAY_DOC.replace("body.name: project", "header.x_name: project"),
            "not a supported request location",
        ),
        (
            // A shape's declared vocabulary must contain everything it pins, or the shape claims
            // not to know about a key it enforces — and the hop record would then report a PINNED
            // key as one the shape does not enumerate.
            "a query bind must name a key the shape declares",
            RELAY_DOC.replace(
                "      body.target: \"target|omit:preview\"",
                "      body.target: \"target|omit:preview\"\n      query.teamId: project",
            ),
            "vocabulary does not declare",
        ),
        (
            "a query bind names a key outside the identifier alphabet",
            RELAY_DOC.replace(
                "      body.target: \"target|omit:preview\"",
                "      body.target: \"target|omit:preview\"\n      \"query.team-id\": project",
            ),
            "names a query key that is not",
        ),
        (
            "a bind must name a declared field",
            RELAY_DOC.replace("body.name: project", "body.name: nonexistent"),
            "undeclared field",
        ),
        (
            "an unknown bind transform must not be silently ignored",
            RELAY_DOC.replace("\"target|omit:preview\"", "\"target|base64\""),
            "the only supported bind transform",
        ),
        (
            "a rule that pins a body key must declare the shape's body vocabulary",
            RELAY_DOC.replace("    body_keys: [files]\n", ""),
            "declares no `body_keys` vocabulary",
        ),
        (
            "a bodyless method has no body vocabulary to declare",
            RELAY_DOC.replace(
                "  - { method: GET, path: /v13/deployments/* }",
                "  - { method: GET, path: /v13/deployments/*, body_keys: [files] }",
            ),
            "`body_keys` on a bodyless method",
        ),
        (
            "listing a bound key would read as an unchecked passthrough",
            RELAY_DOC.replace("body_keys: [files]", "body_keys: [files, name]"),
            "which it also binds",
        ),
        (
            "a body key outside the identifier alphabet",
            RELAY_DOC.replace("body_keys: [files]", "body_keys: [\"custom-env\"]"),
            "predicate body key",
        ),
        (
            "the same body key twice",
            RELAY_DOC.replace("body_keys: [files]", "body_keys: [files, files]"),
            "more than once",
        ),
        (
            "consumes must equal the bound set exactly",
            RELAY_DOC.replace("consumes: [project, target]", "consumes: [project]"),
            "consumes exactly the fields its predicate binds",
        ),
        (
            "an undeclared query key must not ride along",
            RELAY_DOC.replace("query_keys: [forceNew]", "query_keys: [team-id]"),
            "predicate query key",
        ),
        (
            "a bound field nobody pins is a value the relay cannot enforce against",
            RELAY_DOC
                .replace("execution_targets: [project]", "execution_targets: [target]")
                .replace(
                    "{ name: target, type: str, required: true, class: side_effect, binding: exact_resource_pin, fixed: preview }",
                    "{ name: target, type: str, required: true, class: side_effect, binding: exact_resource_pin }",
                ),
            "neither an execution target",
        ),
        (
            "a free_payload bind would let the relay enforce a non-authority field",
            RELAY_DOC.replace(
                "{ name: project, type: str, required: true, class: identity, binding: exact_resource_pin }",
                "{ name: project, type: str, required: true, class: free_payload, binding: unbound }",
            ),
            "identity/side_effect",
        ),
        (
            "a `fixed` value is meaningless on an optional field",
            RELAY_DOC.replace(
                "{ name: target, type: str, required: true, class: side_effect, binding: exact_resource_pin, fixed: preview }",
                "{ name: target, type: str, required: false, class: side_effect, binding: exact_resource_pin, fixed: preview }",
            ),
            "not a required str field",
        ),
        (
            "a `fixed` literal outside the ratified alphabet is refused",
            RELAY_DOC.replace("fixed: preview", "fixed: \"Production!\""),
            "is not `[a-z0-9_-]",
        ),
        (
            "a relay verb has no money path",
            RELAY_DOC.replace(
                "execution: relay",
                "money:\n  preconditions: [balance]\nexecution: relay",
            ),
            // The money block is validated before the exec-kind dispatch, so a relay verb declaring
            // it is refused by the money rules first; either refusal is the fail-closed outcome.
            "money",
        ),
        (
            "a relay verb has no provider-resolved evidence path",
            RELAY_DOC.replace(
                "execution: relay",
                "request_evidence: stripe.refund.v1\nexecution: relay",
            ),
            "request_evidence",
        ),
    ];

    for (why, doc, expected) in cases {
        let error = relay_load(&doc).expect_err(why);
        assert!(
            error.contains(expected),
            "{why}: refusal must name `{expected}`, got: {error}"
        );
    }
}

/// The response-derived half of the grammar. `capture:` names session state read
/// out of the effect's own 2xx response; `path.*: captured.<name>` pins every wildcard segment of a
/// later shape to it; `assert:` compares the effect's outcome to the frozen fields. All three are
/// SHAPE-level, and capture/assert are legal only on the `once: true` effect — nothing else has an
/// approved outcome to derive from.
#[test]
fn relay_grammar_accepts_response_capture_path_binds_and_outcome_assertions() {
    let doc = RELAY_DOC
        .replace(
            "      body.target: \"target|omit:preview\"\n",
            "      body.target: \"target|omit:preview\"\n    capture:\n      deployment_id: id\n\
             \x20   assert:\n      name: project\n      target: \"target|omit:preview\"\n",
        )
        .replace(
            "  - { method: GET, path: /v13/deployments/* }",
            "  - { method: GET, path: /v13/deployments/*, \
             bind: { path.*: captured.deployment_id } }",
        );
    relay_load(&doc).expect("capture, path binds, and assertions are well-formed");

    let template: ActionTemplate = serde_yaml::from_str(&doc).unwrap();
    let predicate = template.relay_predicate().expect("a relay predicate");
    let effect = predicate.iter().find(|rule| rule.once).expect("the effect");
    assert_eq!(
        effect.captures().get("deployment_id").map(String::as_str),
        Some("id")
    );
    assert_eq!(
        effect.asserts(),
        vec![
            RelayAssertion {
                key: "name".into(),
                field: "project".into(),
                absent_when: None,
            },
            RelayAssertion {
                key: "target".into(),
                field: "target".into(),
                absent_when: Some("preview".into()),
            },
        ]
    );
    let read = predicate
        .iter()
        .find(|rule| rule.path == "/v13/deployments/*")
        .expect("the read shape");
    assert_eq!(
        read.binds(),
        vec![RelayBind {
            location: BindLocation::PathWildcards,
            field: "captured.deployment_id".into(),
            absent_when: None,
        }]
    );
    assert_eq!(
        read.binds()[0].captured_name(),
        Some("deployment_id"),
        "a path bind reads response-derived session state, never an approval-frozen field"
    );
}

#[test]
fn relay_grammar_rejects_capture_path_binds_and_assertions_that_enforce_nothing() {
    // The base document with the response-derived stanzas, so each case below mutates exactly one
    // thing.
    let base = RELAY_DOC
        .replace(
            "      body.target: \"target|omit:preview\"\n",
            "      body.target: \"target|omit:preview\"\n    capture:\n      deployment_id: id\n\
             \x20   assert:\n      name: project\n",
        )
        .replace(
            "  - { method: GET, path: /v13/deployments/* }",
            "  - { method: GET, path: /v13/deployments/*, \
             bind: { path.*: captured.deployment_id } }",
        );
    let cases: Vec<(&str, String, &str)> =
        vec![
        (
            "a capture on a non-effect shape derives session authority from a mere read",
            base.replace(
                "  - { method: POST, path: /v2/files }",
                "  - { method: POST, path: /v2/files, capture: { deployment_id: id } }",
            ),
            "only on the `once: true`",
        ),
        (
            "an assertion on a non-effect shape has no approved outcome to compare",
            base.replace(
                "  - { method: POST, path: /v2/files }",
                "  - { method: POST, path: /v2/files, assert: { name: project } }",
            ),
            "only on the `once: true`",
        ),
        (
            "a path bind naming a capture nobody declares can never hold",
            base.replace("captured.deployment_id }", "captured.nonexistent }"),
            "names no declared capture",
        ),
        (
            "a path bind on a shape with no wildcard segment enforces nothing",
            base.replace(
                "  - { method: POST, path: /v2/files }",
                "  - { method: POST, path: /v2/files, bind: { path.*: captured.deployment_id } }",
            ),
            "declares no `*` segment",
        ),
        (
            "a path bind on the effect itself can never hold — its own capture does not exist yet",
            base.replace("    path: /v13/deployments\n", "    path: /v13/deployments/*\n")
                .replace(
                    "      body.name: project\n",
                    "      body.name: project\n      path.*: captured.deployment_id\n",
                ),
            "the effect shape",
        ),
        (
            "a path bind must read a capture, never an approval-frozen field",
            base.replace("captured.deployment_id }", "project }"),
            "must read a capture",
        ),
        (
            "an `omit:` transform is meaningless on a path segment",
            base.replace(
                "captured.deployment_id }",
                "\"captured.deployment_id|omit:none\" }",
            ),
            "path bind",
        ),
        (
            "a body bind may not read response-derived state",
            base.replace("body.name: project", "body.name: captured.deployment_id"),
            "reads a capture",
        ),
        (
            "a capture name outside the identifier alphabet",
            base.replace("      deployment_id: id\n", "      \"deployment-id\": id\n"),
            "capture name",
        ),
        (
            "a capture response key outside the identifier alphabet",
            base.replace("      deployment_id: id\n", "      deployment_id: \"a.b\"\n"),
            "capture response key",
        ),
        (
            "an assertion must name a declared field",
            base.replace("      name: project\n", "      name: nonexistent\n"),
            "undeclared field",
        ),
        (
            "an assertion key outside the identifier alphabet",
            base.replace("      name: project\n", "      \"a-b\": project\n"),
            "assert response key",
        ),
        (
            "an assertion on a field the relay may not enforce",
            base.replace("      name: project\n", "      name: note\n")
                .replace(
                    "consumes: [project, target]",
                    "consumes: [project, target, note]",
                )
                .replace(
                    "fields:\n",
                    "fields:\n  - { name: note, type: str, required: true, class: free_payload, \
                     binding: unbound }\n",
                ),
            "identity/side_effect",
        ),
    ];

    for (why, doc, expected) in cases {
        let error = relay_load(&doc).expect_err(why);
        assert!(
            error.contains(expected),
            "{why}: refusal must name `{expected}`, got: {error}"
        );
    }
}

/// The ratification obligation applied to the SHIPPED verb's path segments: a wildcard
/// deployment id is an authority-bearing wire position exactly like a query value, so every shipped
/// shape whose path names a deployment binds it to the create's own captured id. The two wildcards
/// that stay UNBOUND are the pre-effect reads (`/v9/projects/*`, `/teams/*`), which run before
/// anything is captured and whose scope is already pinned by `query.teamId`.
#[test]
fn every_deployment_wildcard_is_bound_to_the_captured_id_in_the_shipped_relay_verb() {
    for doc in VENDORED_CATALOG {
        let template: ActionTemplate = serde_yaml::from_str(doc).unwrap();
        let Some(predicate) = template.relay_predicate() else {
            continue;
        };
        let effect = predicate.iter().find(|rule| rule.once).expect("one effect");
        assert_eq!(
            effect.captures().get("deployment_id").map(String::as_str),
            Some("id"),
            "the effect names the deployment its own session may then read"
        );
        for rule in predicate {
            if !rule.path.contains("deployments/*") {
                continue;
            }
            assert!(
                rule.binds()
                    .iter()
                    .any(|bind| bind.location == BindLocation::PathWildcards
                        && bind.captured_name() == Some("deployment_id")),
                "{} {}: a deployment id nobody pinned is a read outside this session's own effect",
                rule.method,
                rule.path
            );
        }
    }
}

#[test]
fn predicate_path_matching_is_segment_exact_with_single_segment_wildcards() {
    for (pattern, path, expected) in [
        ("/v13/deployments", "/v13/deployments", true),
        ("/v13/deployments", "/v13/deployments/", false),
        ("/v13/deployments", "/v13/deployments/dpl_1", false),
        ("/v13/deployments", "/v13", false),
        ("/v13/deployments/*", "/v13/deployments/dpl_1", true),
        ("/v13/deployments/*", "/v13/deployments", false),
        // A wildcard is ONE segment: it never walks into a sibling collection.
        (
            "/v13/deployments/*",
            "/v13/deployments/dpl_1/aliases",
            false,
        ),
        (
            "/v2/deployments/*/events",
            "/v2/deployments/dpl_1/events",
            true,
        ),
        (
            "/v2/deployments/*/events",
            "/v2/deployments/dpl_1/files",
            false,
        ),
        ("/v2/deployments/*/events", "/v2/deployments//events", false),
        ("/v2/files", "/v2/FILES", false),
    ] {
        assert_eq!(
            predicate_path_matches(pattern, path),
            expected,
            "`{pattern}` vs `{path}`"
        );
    }
}

// ---------------------------------------------------------------------------
// `request_canonicalization` — the document NAMES one compiled profile,
// and the field that profile rewrites has to be one a sentence can pin.
// ---------------------------------------------------------------------------

/// The shipped `vercel.deploy` shape, minus the parts this section does not exercise.
const CANONICALIZE_DOC: &str = "\
provider: vercel
action: deploy
request_canonicalization: vercel.deploy.team_scope.v1
fields:
  - { name: project, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: target, type: str, required: true, class: side_effect, binding: exact_resource_pin, fixed: preview }
  - { name: team, type: str, required: false, class: identity, binding: exact_resource_pin }
consumes: [project, target, team]
execution_targets: [project, team]
execution: relay
predicate:
  - method: POST
    path: /v13/deployments
    once: true
    query_keys: [forceNew, teamId]
    body_keys: [files]
    bind:
      body.name: project
      body.target: \"target|omit:preview\"
      query.teamId: team
  - { method: POST, path: /v2/files }
  - { method: GET, path: /v13/deployments/* }
";

#[test]
fn a_relay_verb_may_declare_request_canonicalization() {
    relay_load(CANONICALIZE_DOC)
        .expect("in-place canonicalization of a supplied bound field is a relay-legal shape");
    let template: ActionTemplate = serde_yaml::from_str(CANONICALIZE_DOC).unwrap();
    let profile = template
        .canonicalization_profile()
        .expect("the named profile compiles");
    assert_eq!(profile.field, "team");
    // The canonicalized field stays AGENT-SUPPLIED in the catalog: the agent names it, the daemon
    // only respells it. Nothing here is provider-resolved in the evidence sense.
    let entry = template.catalog_entry(true, false);
    let team = entry.fields.iter().find(|f| f.name == "team").unwrap();
    assert_eq!(team.origin, "agent_request");
}

#[test]
fn request_canonicalization_refuses_every_incoherent_declaration() {
    let cases = [
        (
            "an unregistered profile id",
            CANONICALIZE_DOC.replace("team_scope.v1", "team_scope.v9"),
            "unknown compiled profile",
        ),
        (
            "a profile registered for another action",
            CANONICALIZE_DOC.replace("action: deploy", "action: list_projects"),
            "not this action",
        ),
        (
            "a profile whose field the document does not declare",
            CANONICALIZE_DOC.replace(
                "  - { name: team, type: str, required: false, class: identity, binding: exact_resource_pin }\n",
                "",
            ),
            "undeclared field",
        ),
        (
            "a canonicalized field that is not a string",
            CANONICALIZE_DOC.replace(
                "name: team, type: str, required: false",
                "name: team, type: int, required: false",
            ),
            "must be a string",
        ),
        (
            "a canonicalized field that is not an identity or side effect",
            CANONICALIZE_DOC.replace(
                "name: team, type: str, required: false, class: identity",
                "name: team, type: str, required: false, class: read_filter",
            ),
            "must be identity or side_effect",
        ),
        (
            "a canonicalized field no sentence can pin",
            CANONICALIZE_DOC.replace("execution_targets: [project, team]", "execution_targets: [project]"),
            "must be an execution target",
        ),
        (
            "canonicalization combined with the evidence path",
            CANONICALIZE_DOC.replace(
                "request_canonicalization: vercel.deploy.team_scope.v1",
                "request_canonicalization: vercel.deploy.team_scope.v1\nrequest_evidence: stripe.refund.v1",
            ),
            "mutually exclusive",
        ),
    ];

    for (why, doc, expected) in cases {
        let error = relay_load(&doc).expect_err(why);
        assert!(
            error.contains(expected),
            "{why}: refusal must name `{expected}`, got: {error}"
        );
    }
}

// ---------------------------------------------------------------------------
// The minted-URL grammar: a DECLARED 3xx, and the header it retains.
// ---------------------------------------------------------------------------

/// The minted-URL shape at its smallest: one bodyless GET whose only declared success is a redirect,
/// retaining the header that redirect carries. `retention: none` because a 302 has no body to store.
const MINT_DOC: &str = r#"
provider: github
action: read_job_log
fields:
  - { name: owner,  type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: name,   type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: job_id, type: str, required: true, class: identity, binding: exact_resource_pin, format: uint }
consumes: [owner, name, job_id]
execution_targets: [owner, name, job_id]
http:
  steps:
    - id: mint
      method: GET
      path: /repos/{owner}/{name}/actions/jobs/{job_id}/logs
      success_statuses: [302]
      retain_headers: [location]
      retention: none
"#;

#[test]
fn a_step_may_declare_a_3xx_success_and_retain_the_header_it_carries() {
    let reg = TemplateRegistry::with_providers(HashSet::from(["github".to_string()]));
    reg.load(MINT_DOC)
        .expect("a declared-302 step retaining `location` is a valid template");

    // 2xx is untouched, and a rejection still cannot be pinned as a success in either direction.
    for (why, doc, expected) in [
        (
            "4xx is not a success",
            MINT_DOC.replace("success_statuses: [302]", "success_statuses: [404]"),
            "outside 2xx/3xx",
        ),
        (
            "5xx is not a success",
            MINT_DOC.replace("success_statuses: [302]", "success_statuses: [503]"),
            "outside 2xx/3xx",
        ),
        (
            "a retained header must be a lowercase HTTP token",
            MINT_DOC.replace("retain_headers: [location]", "retain_headers: [Location]"),
            "lowercase HTTP header token",
        ),
        (
            "and cannot be an empty name",
            MINT_DOC.replace("retain_headers: [location]", r#"retain_headers: [""]"#),
            "lowercase HTTP header token",
        ),
        (
            "and cannot name one header twice",
            MINT_DOC.replace(
                "retain_headers: [location]",
                "retain_headers: [location, location]",
            ),
            "twice",
        ),
    ] {
        let error = reg.load(&doc).expect_err(why);
        assert!(
            error.to_string().contains(expected),
            "{why}: refusal must name `{expected}`, got: {error}"
        );
    }
}
