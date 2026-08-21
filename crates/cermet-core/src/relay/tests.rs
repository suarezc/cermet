//! The per-hop relay verdict, decided against a frozen session.

use super::*;
use crate::templates::ActionTemplate;

/// A session over the SHIPPED `vercel.deploy` predicate — the tests judge the real verb, not a
/// fixture that could drift from it. The default is the UNSCOPED session: `team` is optional, this
/// request named no scope, so it froze as ABSENCE and the `teamId` binds constrain nothing.
fn session(project: &str) -> RelaySession {
    session_frozen(project, None, "preview")
}

/// The same session frozen to a NAMED team — the scope a team account's CLI stamps on every call.
fn session_scoped(project: &str, team: &str) -> RelaySession {
    session_frozen(project, Some(team), "preview")
}

/// The same session frozen to a NAMED target — a production approval, whose create response Vercel
/// answers with `target: "production"` rather than the preview case's absent/null key.
fn session_targeted(project: &str, target: &str) -> RelaySession {
    session_frozen(project, None, target)
}

/// The SHIPPED `vercel.deploy` predicate, exactly as the daemon loads it.
fn shipped_predicate() -> Vec<PredicateRule> {
    let doc = crate::templates::VENDORED_CATALOG
        .iter()
        .copied()
        .find(|doc| doc.contains("action: deploy"))
        .expect("the vercel relay verb is vendored");
    let template: ActionTemplate = serde_yaml::from_str(doc).expect("the relay verb parses");
    template
        .relay_predicate()
        .expect("deploy is a relay verb")
        .to_vec()
}

/// `team: None` is the request that named no scope — the field froze as ABSENCE, which is a
/// different state from "missing from the map" (that one is unreachable and fails closed).
fn session_frozen(project: &str, team: Option<&str>, target: &str) -> RelaySession {
    let predicate = shipped_predicate();
    let mut frozen = BTreeMap::new();
    frozen.insert("project".to_string(), Some(project.to_string()));
    frozen.insert("target".to_string(), Some(target.to_string()));
    frozen.insert("team".to_string(), team.map(str::to_string));
    RelaySession::new(
        "HANDLEabcdefghij123456".into(),
        "gr_1".into(),
        "req_1".into(),
        "sess_1".into(),
        "vercel".into(),
        "deploy".into(),
        "fp_1".into(),
        predicate,
        frozen,
        1_000,
        600,
    )
}

const NOW: i64 = 1_100;

fn create_body(project: &str) -> Vec<u8> {
    format!(r#"{{"name":"{project}","files":[]}}"#).into_bytes()
}

/// A 2xx create response in the shape Vercel answers with: the deployment record, whose top-level
/// `id` is the `dpl_…` the CLI then polls, whose `name` is the project, and whose `target` is absent
/// or null for a preview (Vercel has no `target: preview`). The session captures the id off it,
/// and asserts the other two against the approval.
fn create_response(id: &str, project: &str) -> Vec<u8> {
    format!(
        r#"{{"id":"{id}","url":"{project}-abc.vercel.app","name":"{project}","target":null,"readyState":"QUEUED"}}"#
    )
    .into_bytes()
}

#[test]
fn a_handle_is_alphanumeric_and_carries_over_128_bits() {
    for _ in 0..64 {
        let handle = mint_handle();
        assert_eq!(handle.len(), HANDLE_PREFIX.len() + HANDLE_CHARS);
        let random = handle
            .strip_prefix(HANDLE_PREFIX)
            .expect("every handle carries the inert prefix");
        assert!(
            random.chars().all(|c| c.is_ascii_alphanumeric()),
            "the vercel CLI refuses a `--token` containing `-` or `.`, so the alphabet is \
             load-bearing: {handle}"
        );
    }
    // 24 alphanumeric characters is ~142 bits, over the 128-bit floor. The constant prefix adds
    // legibility, never entropy — the floor is measured over the random part alone.
    let bits = (HANDLE_CHARS as f64) * 62f64.log2();
    assert!(bits >= 128.0, "handle entropy is {bits} bits");
    let mut minted = std::collections::HashSet::new();
    for _ in 0..256 {
        assert!(minted.insert(mint_handle()), "handles are not reused");
    }
}

/// The handle's inertness — single-use, TTL'd, loopback-only, predicate-bounded — is real but
/// ILLEGIBLE from the string itself, so a permission classifier can block a `--token <handle>`
/// invocation as secret-handling and leave the agent thrashing. A constant, self-naming prefix
/// makes the property readable without reading the daemon.
///
/// The alphabet is the hard constraint (probe-verified against vercel CLI 58.4.4): `--token`
/// rejects a value containing `-` ("Must not contain: \"-\"") or `.`, and ACCEPTS `_` — which is
/// why the prefix is `cermet_relay_` and not the hyphenated form.
#[test]
fn a_handle_names_itself_inert_in_the_alphabet_the_cli_accepts() {
    let handle = mint_handle();
    assert!(
        handle.starts_with("cermet_relay_"),
        "a handle says what it is on its face: {handle}"
    );
    assert!(
        !handle.contains('-') && !handle.contains('.'),
        "the vercel CLI refuses `--token` values containing `-` or `.`: {handle}"
    );
    assert!(
        handle
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "nothing outside [A-Za-z0-9_] survives the CLI's `--token` validation: {handle}"
    );
}

#[test]
fn the_declared_shapes_pass_and_the_create_carries_the_frozen_project() {
    let mut s = session("website");
    assert_eq!(
        s.authorize("POST", "/v13/deployments", &create_body("website"), NOW),
        RelayVerdict::Forward { effect: true },
        "the deployment create of the pinned project is THE effect"
    );
    // The read shapes are bound to the deployment THIS session created, so the create's
    // own response is what makes them reachable at all.
    s.observe_response(true, 200, &create_response("dpl_abc123", "website"));
    for (method, target) in [
        ("POST", "/v2/files"),
        ("GET", "/v13/deployments/dpl_abc123"),
        ("GET", "/v13/deployments/dpl_abc123?withGitRepoInfo=true"),
        ("GET", "/v2/deployments/dpl_abc123/events"),
        ("GET", "/v2/deployments/dpl_abc123/events?builds=1&follow=1"),
        (
            "POST",
            "/v13/deployments?forceNew=1&skipAutoDetectionConfirmation=1",
        ),
    ] {
        let body = if target.starts_with("/v13/deployments?") {
            create_body("website")
        } else {
            b"file bytes".to_vec()
        };
        assert!(
            matches!(
                s.authorize(method, target, &body, NOW),
                RelayVerdict::Forward { .. }
            ),
            "{method} {target} is a declared shape"
        );
    }
}

/// An UNLINKED working directory (no `.vercel/project.json`) makes the CLI resolve the team before
/// it can do anything else. Empirically captured against vercel CLI 58.4.4 (stub origin, `HOME`
/// isolated, no link file): the session opens `GET /v2/user` and then `GET /v1/teams`, no query, no
/// body. Without these shapes that second call matches nothing, so it refuses, BURNS the grant, and
/// costs a whole request→grant cycle before the deploy is even attempted. It discloses nothing
/// `vercel.list_projects` does not already return.
#[test]
fn the_unlinked_team_resolution_hop_is_admitted() {
    let mut s = session("website");
    for (method, target) in [("GET", "/v2/user"), ("GET", "/v1/teams")] {
        assert!(
            matches!(
                s.authorize(method, target, b"", NOW),
                RelayVerdict::Forward { effect: false }
            ),
            "{method} {target} is the unlinked CLI's own opening sequence"
        );
    }
}

/// ...and nothing wider than what was observed: the team LIST is read-only and query-less here, so
/// a scope-redirecting query or a write to the same path still refuses.
#[test]
fn the_admitted_teams_shape_is_exactly_the_observed_one() {
    for (method, target) in [
        ("GET", "/v1/teams?slug=team_other"),
        ("POST", "/v1/teams"),
        ("DELETE", "/v1/teams"),
        ("GET", "/v1/teams/team_other"),
    ] {
        let mut s = session("website");
        assert_eq!(
            s.authorize(method, target, b"{}", NOW),
            RelayVerdict::Refuse(RelayRefusal::NoMatchingShape),
            "{method} {target} was never observed and is not admitted"
        );
    }
}

#[test]
fn an_undeclared_shape_is_refused_and_burns_the_session() {
    // Each case is a request the relay predicate exists to refuse.
    let cases: [(&str, &str, &str, RelayRefusal); 9] = [
        (
            "reading the project's environment variables",
            "GET",
            "/v9/projects/website/env",
            RelayRefusal::NoMatchingShape,
        ),
        (
            "promoting a deployment to production",
            "PATCH",
            "/v13/deployments/dpl_abc123",
            RelayRefusal::NoMatchingShape,
        ),
        (
            "deleting a deployment",
            "DELETE",
            "/v13/deployments/dpl_abc123",
            RelayRefusal::NoMatchingShape,
        ),
        (
            "aliasing under a wildcard that admits only one segment",
            "GET",
            "/v13/deployments/dpl_abc123/aliases",
            RelayRefusal::NoMatchingShape,
        ),
        (
            // `teamId` is an ADMITTED KEY (team accounts append it to every call), but its VALUE
            // is bound to the frozen `team`, so on this scoped session it must carry that exact
            // team — a create that names another is a scope redirect and refuses at the bind,
            // without the credential.
            "a create carrying teamId outside the frozen scope fails its bind",
            "POST",
            "/v13/deployments?teamId=team_other",
            RelayRefusal::BindMismatch,
        ),
        (
            "an undeclared query key on a read",
            "GET",
            "/v13/deployments/dpl_abc123?slug=team_other",
            RelayRefusal::NoMatchingShape,
        ),
        (
            "percent-encoded traversal out of the wildcard segment",
            "GET",
            "/v13/deployments/%2e%2e%2fprojects",
            RelayRefusal::MalformedRequest,
        ),
        (
            "an absolute URL instead of a path",
            "GET",
            "http://evil.test/v13/deployments/dpl_1",
            RelayRefusal::MalformedRequest,
        ),
        (
            "a traversal segment",
            "GET",
            "/v13/../v9/projects",
            RelayRefusal::MalformedRequest,
        ),
    ];
    // A SCOPED session: one case below is a scope redirect, which only has a bind to miss when the
    // approval froze a team. Shape and syntax refusals precede the binds, so the other eight are
    // decided identically either way.
    for (why, method, target, expected) in cases {
        let mut s = session_scoped("website", "team_ours");
        let verdict = s.authorize(method, target, b"{}", NOW);
        assert_eq!(verdict, RelayVerdict::Refuse(expected.clone()), "{why}");
        s.note_refusal(expected.clone(), method, target);
        assert_eq!(
            s.burned(),
            Some(&expected),
            "{why}: a probed session is done"
        );
        // Every later hop — including a legitimate one — is now an unknown handle.
        assert_eq!(
            s.authorize("POST", "/v2/files", b"bytes", NOW),
            RelayVerdict::Refuse(RelayRefusal::UnknownHandle),
            "{why}: the burned session is an unknown handle from here on"
        );
    }
}

/// The native `vercel` CLI renders an auth-shaped refusal as "Authentication error / the token is
/// not valid" — a LIE about a spent capability, and the agent that believes it re-logs-in instead
/// of requesting a new grant.
///
/// Probed against vercel CLI 58.4.4 (a loopback listener, no real deploy): the CLI renders
/// `error.message` VERBATIM at every status it was shown EXCEPT 403, which it hard-codes to its
/// invalid-token line on the preflight `GET /v2/user`; a body with no `message` at all renders as
/// the opaque "Response Error". So the truth needs BOTH a non-auth status and a `message`.
#[test]
fn no_refusal_speaks_in_auth_statuses_and_every_one_carries_the_truth() {
    let all = [
        RelayRefusal::UnknownHandle,
        RelayRefusal::Expired,
        RelayRefusal::MalformedRequest,
        RelayRefusal::NoMatchingShape,
        RelayRefusal::BindMismatch,
        RelayRefusal::UndeclaredBodyKey {
            keys: vec!["deploymentId".into()],
        },
        RelayRefusal::EffectAlreadyUsed,
        RelayRefusal::BodyTooLarge,
        RelayRefusal::OutcomeMismatch,
    ];
    for refusal in all {
        let status = refusal.status();
        assert!(
            status != 401 && status != 403,
            "{refusal:?}: 401/403 make the native CLI print an authentication lie about a \
             capability that was spent, not an identity that failed"
        );
        let message = refusal.message();
        assert!(
            message.starts_with("cermet: "),
            "{refusal:?}: the message names who is refusing, since the CLI prints it as its own \
             error: {message}"
        );
    }
    // The two the agent actually hits after a deploy stops name the mechanism AND where to look.
    for refusal in [RelayRefusal::UnknownHandle, RelayRefusal::EffectAlreadyUsed] {
        let message = refusal.message();
        assert!(
            message.contains("single-use") && message.contains("cermet log --hops"),
            "{refusal:?}: the truth is 'the capability was spent', plus the trail: {message}"
        );
    }
    assert!(
        RelayRefusal::Expired.message().contains("expired"),
        "a lapsed TTL is a different truth from a spent grant"
    );
}

#[test]
fn a_bound_field_that_disagrees_with_the_approval_is_refused_and_burns() {
    let cases: [(&str, &str); 5] = [
        (
            "a production target (T1 injection, T2 `--prod`)",
            r#"{"name":"website","target":"production"}"#,
        ),
        (
            "an explicit staging target",
            r#"{"name":"website","target":"staging"}"#,
        ),
        (
            "a different project than the sentence pinned",
            r#"{"name":"other-site","target":null}"#,
        ),
        ("no project at all", r#"{"files":[]}"#),
        ("a non-object body on a bound shape", r#"["website"]"#),
    ];
    for (why, body) in cases {
        let mut s = session("website");
        let verdict = s.authorize("POST", "/v13/deployments", body.as_bytes(), NOW);
        assert_eq!(
            verdict,
            RelayVerdict::Refuse(RelayRefusal::BindMismatch),
            "{why}"
        );
        s.note_refusal(RelayRefusal::BindMismatch, "POST", "/v13/deployments");
        assert!(s.burned().is_some(), "{why}: a bind mismatch burns");
    }
    // The safe case really is the key's ABSENCE (Vercel has no legal `target: preview`), and an
    // explicit null is the same thing.
    let mut s = session("website");
    for body in [
        r#"{"name":"website"}"#,
        r#"{"name":"website","target":null}"#,
    ] {
        assert!(
            matches!(
                s.authorize("POST", "/v13/deployments", body.as_bytes(), NOW),
                RelayVerdict::Forward { effect: true }
            ),
            "an omitted target IS the preview case: {body}"
        );
    }
    // ...and the literal string `preview` is NOT what Vercel's API means, so it is refused too.
    assert_eq!(
        s.authorize(
            "POST",
            "/v13/deployments",
            br#"{"name":"website","target":"preview"}"#,
            NOW
        ),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch)
    );
}

#[test]
fn exactly_one_deployment_create_passes_per_session() {
    let mut s = session("website");
    let verdict = s.authorize("POST", "/v13/deployments", &create_body("website"), NOW);
    assert_eq!(verdict, RelayVerdict::Forward { effect: true });
    s.note_forward(true);
    assert!(s.effect_used());

    assert_eq!(
        s.authorize("POST", "/v13/deployments", &create_body("website"), NOW),
        RelayVerdict::Refuse(RelayRefusal::EffectAlreadyUsed),
        "one grant, one effect — a second create is refused"
    );

    // Uploads and reads stay repeatable inside the TTL — that is what makes the CLI's own protocol
    // work; what bounds them is the shape's own declared budget, far above 50.
    let mut s = session("website");
    for _ in 0..50 {
        assert!(matches!(
            s.authorize("POST", "/v2/files", b"bytes", NOW),
            RelayVerdict::Forward { effect: false }
        ));
        s.note_forward(false);
    }
    assert_eq!(s.observations().hops, 50);
    assert!(!s.effect_used());
}

#[test]
fn a_provider_rejected_create_releases_the_effect() {
    // Vercel's own two-phase protocol: the first create answers 400 `missing_files`, the CLI
    // uploads, then creates again. A definite provider 4xx means NO deployment exists, so the
    // `once` effect is released — attempt-counting would make every cold deploy impossible.
    let mut s = session("website");
    assert_eq!(
        s.authorize("POST", "/v13/deployments", &create_body("website"), NOW),
        RelayVerdict::Forward { effect: true }
    );
    s.note_forward(true);
    s.observe_response(true, 400, br#"{"error":{"code":"missing_files"}}"#);
    assert!(!s.effect_used(), "a definite 4xx is a definite no-effect");
    assert_eq!(
        s.authorize("POST", "/v13/deployments", &create_body("website"), NOW),
        RelayVerdict::Forward { effect: true },
        "the retry after the upload is the SAME single effect, not a second one"
    );

    // 2xx: the deployment exists — consumed stays consumed.
    s.note_forward(true);
    s.observe_response(true, 200, &create_response("dpl_1", "website"));
    assert!(s.effect_used());

    // 5xx and transport silence are AMBIGUOUS (it may have landed): consumed stays consumed.
    let mut s = session("website");
    s.note_forward(true);
    s.observe_response(true, 502, b"bad gateway");
    assert!(s.effect_used(), "5xx is ambiguous, fail closed");
    let mut s = session("website");
    s.note_forward(true);
    assert!(s.effect_used(), "no response at all stays consumed");
}

#[test]
fn a_lapsed_ttl_refuses_every_hop_without_burning() {
    let mut s = session("website");
    let after = s.expires_at + 1;
    assert_eq!(
        s.authorize("POST", "/v2/files", b"bytes", after),
        RelayVerdict::Refuse(RelayRefusal::Expired)
    );
    assert_eq!(
        s.authorize("POST", "/v13/deployments", &create_body("website"), after),
        RelayVerdict::Refuse(RelayRefusal::Expired)
    );
    assert!(!RelayRefusal::Expired.burns());
    // Gone / Conflict, never an auth status — the capability lapsed, the identity did not.
    assert_eq!(RelayRefusal::Expired.status(), 410);
    assert_eq!(RelayRefusal::UnknownHandle.status(), 409);
}

#[test]
fn the_receipt_is_derived_from_observed_responses_never_from_a_claim() {
    let mut s = session("website");
    s.note_forward(true);
    s.observe_response(true, 200, &create_response("dpl_real", "website"));
    s.observe_response(false, 200, br#"{"readyState":"READY"}"#);
    let receipt = s.receipt("ttl");
    assert_eq!(receipt["deployment_id"], "dpl_real");
    assert_eq!(receipt["deployment_url"], "website-abc.vercel.app");
    assert_eq!(receipt["state"], "READY");
    assert_eq!(receipt["hops"], 1);
    assert_eq!(receipt["closed"], "ttl");

    // A non-2xx, an unparseable body, and a read BEFORE any create leave the receipt untouched:
    // the relay reports what it saw, and nothing is inferred from a request the provider rejected.
    let mut s = session("website");
    s.observe_response(true, 403, br#"{"id":"dpl_never"}"#);
    s.observe_response(true, 200, b"<html>not json</html>");
    s.observe_response(false, 200, br#"{"readyState":"READY"}"#);
    let receipt = s.receipt("burned");
    assert!(receipt["deployment_id"].is_null());
    assert!(receipt["state"].is_null());
}

/// A bound key is not the whole body. Vercel's create-deployment API documents body parameters
/// that OVERRIDE the fields the sentence pinned — `project` ("when defined, this parameter
/// overrides name"), `customEnvironmentSlugOrId` (overrides the target environment), and
/// `deploymentId` (redeploy an arbitrary existing deployment). Checking only the bound keys would
/// let each of them ride through credentialed, so the body key set is a CLOSED allowlist like
/// `query_keys`.
#[test]
fn an_undeclared_create_body_key_is_refused_and_burns_the_session() {
    // Each case keeps `name` correct and `target` absent — the binds all hold. The refusal has to come
    // from the key the rule never declared.
    let cases: [(&str, &str, &str); 6] = [
        (
            "`project` overrides `name`, voiding the identity pin (T1 injection)",
            r#"{"name":"website","project":"prj_someone_else"}"#,
            "project",
        ),
        (
            "`deploymentId` redeploys an arbitrary existing deployment",
            r#"{"name":"website","deploymentId":"dpl_not_ours"}"#,
            "deploymentId",
        ),
        (
            "`customEnvironmentSlugOrId` overrides the target environment",
            r#"{"name":"website","customEnvironmentSlugOrId":"prod-clone"}"#,
            "customEnvironmentSlugOrId",
        ),
        (
            "`alias` assigns a domain the grant never authorized",
            r#"{"name":"website","alias":["www.example.com"]}"#,
            "alias",
        ),
        (
            "`project` overrides the pinned name with an arbitrary project id",
            r#"{"name":"website","project":"prj_other"}"#,
            "project",
        ),
        (
            "a body parameter Vercel adds after this predicate was ratified",
            r#"{"name":"website","someFutureParameter":true}"#,
            "someFutureParameter",
        ),
    ];
    for (why, body, offending) in cases {
        let mut s = session("website");
        // The refusal carries the offending key NAME — that is what the audit row and the client
        // message print, and what an operator ratifies from.
        let expected = RelayRefusal::UndeclaredBodyKey {
            keys: vec![offending.to_string()],
        };
        assert_eq!(
            s.authorize("POST", "/v13/deployments", body.as_bytes(), NOW),
            RelayVerdict::Refuse(expected.clone()),
            "{why}"
        );
        assert!(
            expected.message().contains(offending),
            "{why}: the client-visible message must name the key"
        );
        s.note_refusal(expected.clone(), "POST", "/v13/deployments");
        assert_eq!(
            s.burned(),
            Some(&expected),
            "{why}: an undeclared body key is a probe, so the session is done"
        );
        assert_eq!(expected.status(), 422);
    }
}

/// The other half of the closed body allowlist: the declared payload the CLI actually sends still
/// passes, and the upload path — a non-JSON body with no binds and no `body_keys` — is untouched.
#[test]
fn the_declared_create_body_keys_pass_and_the_upload_path_is_unaffected() {
    let mut s = session("website");
    let create = serde_json::json!({
        "name": "website",
        "files": [{ "file": "index.html", "sha": "a".repeat(40), "size": 12 }],
        "projectSettings": { "framework": "nextjs", "outputDirectory": ".next" },
        "meta": { "githubCommitRef": "main" },
        "gitMetadata": { "commitMessage": "copy tweak", "dirty": true },
        "monorepoManager": null,
        "regions": ["iad1"],
        "functions": {},
        "routes": [],
        "source": "cli",
    })
    .to_string();
    assert_eq!(
        s.authorize("POST", "/v13/deployments", create.as_bytes(), NOW),
        RelayVerdict::Forward { effect: true },
        "the ratified create payload still deploys"
    );

    // /v2/files carries raw file bytes: no binds, no body_keys, so no body check applies at all.
    for body in [
        &b"\x00\x01\x02 raw bytes, not JSON"[..],
        br#"{"looks":"like json but is a file"}"#,
        &[],
    ] {
        assert!(
            matches!(
                s.authorize("POST", "/v2/files", body, NOW),
                RelayVerdict::Forward { effect: false }
            ),
            "an upload body is opaque to the relay"
        );
    }
}

/// The native `vercel` CLI swallows non-2xx response bodies and prints its own guess, so the
/// relay's refusal reason never reaches the agent through the carrier. The session receipt is the
/// agent's only honest mirror, and "burned: bind_mismatch" alone does not say WHICH hop. Naming the
/// refused hop's method and target is what lets an agent self-diagnose (it asked for production;
/// the grant froze preview) instead of paging the operator.
#[test]
fn a_burned_session_receipt_names_the_hop_that_burned_it() {
    let mut s = session("website");
    let target = "/v13/deployments";
    let body = br#"{"name":"website","target":"production"}"#;
    assert_eq!(
        s.authorize("POST", target, body, NOW),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch)
    );
    s.note_refusal(RelayRefusal::BindMismatch, "POST", target);

    let receipt = s.receipt("burned");
    assert_eq!(receipt["burned"], "bind_mismatch");
    assert_eq!(receipt["burned_method"], "POST");
    assert_eq!(receipt["burned_target"], target);

    // A session that never burned keeps a receipt with nothing to explain.
    let clean = session("website").receipt("ttl");
    assert!(clean["burned"].is_null());
    assert!(clean["burned_method"].is_null());
    assert!(clean["burned_target"].is_null());
}

/// `teamId` is an authority-bearing query VALUE. The key was admitted on every scoped
/// shape (a team account's CLI stamps it on every call) while the matcher checked only key
/// MEMBERSHIP, so the executed request carried a scope the sentence never froze — and Vercel
/// auto-creates a project on an unknown name, making the blast radius mint-and-deploy in any team
/// the vaulted token reaches (T1: injected "deploy it to the other team"; T2: a stale
/// `.vercel/project.json` or a fat-fingered `--scope`).
///
/// The restored invariant: every authority-bearing wire position is value-bound to a frozen field.
/// The honest hop forwards; every other scope refuses BEFORE the credential and burns.
#[test]
fn a_scoped_create_is_pinned_to_the_frozen_team() {
    let mut s = session_scoped("website", "team_ours");
    assert_eq!(
        s.authorize(
            "POST",
            "/v13/deployments?teamId=team_ours",
            &create_body("website"),
            NOW
        ),
        RelayVerdict::Forward { effect: true },
        "the honest create — right project, right scope — is THE effect"
    );

    let cases: [(&str, &str); 4] = [
        (
            "another team the vaulted token can reach (T1 scope redirect)",
            "/v13/deployments?teamId=team_other",
        ),
        (
            "the frozen team as a prefix of a longer id",
            "/v13/deployments?teamId=team_ours_evil",
        ),
        (
            "no scope at all, while the approval froze one",
            "/v13/deployments",
        ),
        ("the key with no value at all", "/v13/deployments?teamId"),
    ];
    for (why, target) in cases {
        let mut s = session_scoped("website", "team_ours");
        assert_eq!(
            s.authorize("POST", target, &create_body("website"), NOW),
            RelayVerdict::Refuse(RelayRefusal::BindMismatch),
            "{why}"
        );
        s.note_refusal(RelayRefusal::BindMismatch, "POST", target);
        assert_eq!(
            s.burned(),
            Some(&RelayRefusal::BindMismatch),
            "{why}: a scope the approval never froze is a probe, so the session is done"
        );
    }
}

/// The other half of the same bind: `team` is OPTIONAL, and a request that named no scope froze it
/// as ABSENCE. A bind with nothing frozen behind it constrains nothing — the `teamId` key rides with
/// any value, or not at all, on every shape. This is the deploy whose scope follows the native CLI's
/// own workspace configuration; the hop record's target is then the only account of which scope that
/// turned out to be.
#[test]
fn an_unnamed_scope_binds_nothing_and_admits_every_team_id() {
    for target in [
        "/v13/deployments",
        "/v13/deployments?teamId=team_ours",
        "/v13/deployments?teamId=team_other",
        "/v13/deployments?forceNew=1&teamId=team_whatever",
        // Even the degenerate spellings a PINNED scope refuses: a valueless key, and a repeat.
        "/v13/deployments?teamId",
        "/v13/deployments?teamId=team_ours&teamId=team_other",
    ] {
        let mut s = session("website");
        assert_eq!(
            s.authorize("POST", target, &create_body("website"), NOW),
            RelayVerdict::Forward { effect: true },
            "nothing was frozen, so nothing about the scope is enforced: {target}"
        );
        assert!(
            s.burned().is_none(),
            "an unconstrained bind is not a refusal: {target}"
        );
    }
}

/// An absent bind relaxes ITS OWN position and nothing else. Key closure is untouched — `slug` is
/// Vercel's other way to name a scope and still dies at the allowlist — and the frozen
/// `project`/`target` binds still hold on the very same hop.
#[test]
fn an_unnamed_scope_relaxes_only_its_own_bind() {
    let mut s = session("website");
    assert_eq!(
        s.authorize(
            "POST",
            "/v13/deployments?teamId=team_ours&slug=team-other",
            &create_body("website"),
            NOW
        ),
        RelayVerdict::Refuse(RelayRefusal::NoMatchingShape),
        "an unratified query key refuses whether or not the scope is pinned"
    );

    let mut s = session("website");
    assert_eq!(
        s.authorize(
            "POST",
            "/v13/deployments?teamId=team_ours",
            &create_body("someone-elses-site"),
            NOW
        ),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch),
        "the frozen project still pins the create on an unscoped session"
    );

    let mut s = session("website");
    assert_eq!(
        s.authorize(
            "POST",
            "/v13/deployments?teamId=team_ours",
            br#"{"name":"website","target":"production","files":[]}"#,
            NOW
        ),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch),
        "the frozen preview target still pins the create on an unscoped session"
    );
}

/// The bind holds on every shape where the value decides WHERE the deploy lands, not only on the
/// effect. A session's reads are its own consequences: a poll or an events tail pointed at another
/// team is the same scope redirect with a different verb (the read half of the same T1 story). The
/// one ratified exception is the team-context read — see the test below.
#[test]
fn a_query_bind_holds_on_the_non_effect_shapes_too() {
    let mut s = session_scoped("website", "team_ours");
    // The deployment reads are also bound to this session's own created deployment.
    s.observe_response(true, 200, &create_response("dpl_1", "website"));
    // (`/v9/projects/*` and `/teams/*` are the two ratified authority-free reads — their
    // classification tests live below; every shape here stays value-bound.)
    for target in [
        "/v13/deployments/dpl_1?teamId=team_ours",
        "/v13/deployments/dpl_1?withGitRepoInfo=true&teamId=team_ours",
        "/v2/deployments/dpl_1/events?follow=1&teamId=team_ours",
        "/v3/now/deployments/dpl_1/events?direction=forward&format=lines&teamId=team_ours",
    ] {
        assert!(
            matches!(
                s.authorize("GET", target, b"", NOW),
                RelayVerdict::Forward { effect: false }
            ),
            "the in-scope read is what the CLI actually does: {target}"
        );
        let redirected = target.replace("teamId=team_ours", "teamId=team_other");
        assert_eq!(
            s.authorize("GET", &redirected, b"", NOW),
            RelayVerdict::Refuse(RelayRefusal::BindMismatch),
            "a read redirected out of the frozen scope refuses: {redirected}"
        );
        let unscoped = target
            .replace("?teamId=team_ours", "")
            .replace("&teamId=team_ours", "");
        assert_eq!(
            s.authorize("GET", &unscoped, b"", NOW),
            RelayVerdict::Refuse(RelayRefusal::BindMismatch),
            "a missing declared scope refuses too — absence is not agreement: {unscoped}"
        );
    }
    // The upload path is bound the same way, and its body stays opaque.
    assert!(matches!(
        s.authorize("POST", "/v2/files?teamId=team_ours", b"raw bytes", NOW),
        RelayVerdict::Forward { effect: false }
    ));
    assert_eq!(
        s.authorize("POST", "/v2/files?teamId=team_other", b"raw bytes", NOW),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch)
    );
}

/// The scope-free bootstrap reads are how the CLI DISCOVERS its scope, so they carry no bind: they
/// are query-less and read-only in the predicate, and a team-scoped session still opens with them.
#[test]
fn the_bootstrap_reads_stay_bind_less() {
    let mut s = session_scoped("website", "team_ours");
    for target in ["/v2/user", "/v1/teams"] {
        assert!(
            matches!(
                s.authorize("GET", target, b"", NOW),
                RelayVerdict::Forward { effect: false }
            ),
            "{target} is how the CLI learns which teams the token reaches"
        );
    }
}

/// A `query.teamId` bind on the team-context read refused the verbatim call the CLI makes.
/// Captured against vercel CLI 58.5.1 (stub origin, transcript seq 3): `GET /teams/<id>` with NO
/// query string — the team is named in the PATH. The bind demanded a `teamId` query value, so every
/// team-scoped deploy burned its grant on the preamble, before the deploy it exists to enable was
/// ever attempted. The earlier test that "covered" this shape synthesized `/teams/x?teamId=x`, a
/// target no CLI sends — which is why the replay test below judges the captured sequence and not a
/// target an author invented.
///
/// The values here are ratified AUTHORITY-FREE (the other branch of the obligation, not an
/// exemption): the shape is read-only and its disclosure is no greater than the bindless
/// `GET /v1/teams` list of every team the token reaches. Every effect-bearing hop's scope stays
/// bound, so a redirected preamble read cannot move a deployment.
#[test]
fn the_team_context_read_is_ratified_authority_free() {
    let mut s = session_scoped("website", "team_ours");
    // The captured shape: no query at all.
    assert!(
        matches!(
            s.authorize("GET", "/teams/team_ours", b"", NOW),
            RelayVerdict::Forward { effect: false }
        ),
        "the verbatim CLI 58.5.1 call must forward, or no team-scoped deploy can start"
    );
    // Classified authority-free, and the test says so out loud: another team's metadata read
    // forwards, and that is the ratified judgment, not an oversight.
    for target in [
        "/teams/team_other",
        "/teams/team_other?teamId=team_other",
        "/teams/team_ours?teamId=team_ours",
    ] {
        assert!(
            matches!(
                s.authorize("GET", target, b"", NOW),
                RelayVerdict::Forward { effect: false }
            ),
            "the team-context read is read-only disclosure ≤ `GET /v1/teams`: {target}"
        );
    }
    // Key closure still holds on this shape, and the scope of the EFFECT is untouched: a create
    // pointed at another team still refuses at its own bind.
    assert_eq!(
        s.authorize("GET", "/teams/team_ours?slug=team_other", b"", NOW),
        RelayVerdict::Refuse(RelayRefusal::NoMatchingShape),
        "an unratified parameter still never rides along"
    );
    assert_eq!(
        s.authorize(
            "POST",
            "/v13/deployments?teamId=team_other",
            &create_body("website"),
            NOW
        ),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch),
        "reading another team's metadata never widened where a deploy may land"
    );
}

/// The team-context read's exact class, one shape over, caught by the first LIVE linked-dir
/// deploy after the query-bind hardening: in a linked directory the CLI opens with
/// `GET /v9/projects/<name>` and NO query — the stub capture below ran UNLINKED, so its replay
/// carried `?teamId=` on this hop and the suite stayed green while the linked flow burned on
/// hop 2. The shape is now the second ratified authority-free read.
#[test]
fn the_linked_project_retrieve_is_ratified_authority_free() {
    let mut s = session_scoped("website", "team_ours");
    // The observed live shape: project named in the path, no query at all.
    assert!(
        matches!(
            s.authorize("GET", "/v9/projects/website", b"", NOW),
            RelayVerdict::Forward { effect: false }
        ),
        "the verbatim linked-dir opener must forward, or no linked deploy can start"
    );
    // Classified authority-free, said out loud: a read of other project metadata forwards (the
    // token scopes what it can see), and the earlier CLI's query-carrying form still forwards.
    for target in [
        "/v9/projects/other-project",
        "/v9/projects/website?teamId=team_ours",
        "/v9/projects/website?teamId=team_other",
    ] {
        assert!(
            matches!(
                s.authorize("GET", target, b"", NOW),
                RelayVerdict::Forward { effect: false }
            ),
            "the linked-project retrieve is read-only, token-scoped disclosure: {target}"
        );
    }
    // Key closure still holds, and the effect's own scope bind is untouched.
    assert_eq!(
        s.authorize("GET", "/v9/projects/website?slug=team_other", b"", NOW),
        RelayVerdict::Refuse(RelayRefusal::NoMatchingShape),
        "an unratified parameter still never rides along"
    );
    assert_eq!(
        s.authorize(
            "POST",
            "/v13/deployments?teamId=team_other",
            &create_body("website"),
            NOW
        ),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch),
        "reading project metadata never widened where a deploy may land"
    );
}

/// The linked-dir preamble as a live receipt log records it (the query-bind hardening refused it;
/// pre-hardening receipts show the same sequence forwarding): user → linked-project retrieve
/// (no query) → team read (no query) → the scoped create. The replay discipline, applied to the
/// flow the stub capture missed.
#[test]
fn the_live_linked_dir_preamble_forwards() {
    let mut s = session_frozen("website", Some("team_ours"), "preview");
    for (hop, method, target) in [
        ("hop 1", "GET", "/v2/user"),
        ("hop 2", "GET", "/v9/projects/website"),
        ("hop 3", "GET", "/teams/team_ours"),
    ] {
        let verdict = s.authorize(method, target, b"", NOW);
        assert!(
            matches!(verdict, RelayVerdict::Forward { effect: false }),
            "{hop}: the CLI's own {method} {target} was refused: {verdict:?}"
        );
        s.note_forward(false);
    }
    let verdict = s.authorize(
        "POST",
        "/v13/deployments?teamId=team_ours&skipAutoDetectionConfirmation=1",
        &create_body("website"),
        NOW,
    );
    assert!(
        matches!(verdict, RelayVerdict::Forward { effect: true }),
        "the scoped create must forward after the query-less preamble: {verdict:?}"
    );
}

/// The regression test the envelope earns instead of authored targets: REPLAY the captured hop
/// sequence of a real team-scoped `vercel deploy` against the SHIPPED predicate, and require every
/// hop to forward. Source: a stub-origin capture of vercel CLI 58.5.1 (`HOME` isolated, fake
/// token) — transcript seq 2-9 verbatim (method, target and the create's own 711-byte body), plus
/// the final poll the CLI's own `--debug` trace records and the create response that same log shows
/// the CLI accepting.
///
/// This is what an author-written target costs: the envelope passed a suite full of them while
/// disagreeing with the CLI on its third call. A synthetic target can only prove what its author
/// already believed; a replay fails the moment the ratified document and observed reality part.
#[test]
fn the_captured_cli_deploy_sequence_forwards_hop_for_hop() {
    // The captured create body, byte-for-byte (bodies/005-POST-v13_deployments.bin; the retry,
    // bodies/009, is byte-identical). Its top-level keys are the whole ratified body surface it
    // exercises, and `name` is the frozen project.
    const CREATE_BODY: &str = r#"{"version":2,"env":{},"build":{"env":{}},"name":"stubsite","meta":{},"projectSettings":{"sourceFilesOutsideRootDirectory":true},"source":"cli","files":[{"file":"style.css","size":17,"mode":33204,"sha":"11d7f3424347713a17b0f208ef3d4e44b164a0cd"},{"file":"index.html","size":53,"mode":33204,"sha":"59503668a37e65112006ed3ab584d1fe1727aea4"},{"file":"b.js","size":18,"mode":33204,"sha":"bfbd242840723ccfd12ccdc651faaecc278fc039"},{"file":"vercel.json","size":14,"mode":33204,"sha":"ef082b57ae1df3085ab79b07c4a5d7115506db29"},{"file":"a.js","size":18,"mode":33204,"sha":"143e65e75c65cc416a6877b81ecac8c9320ca1d9"},{"file":"assets/big.txt","size":5000,"mode":33204,"sha":"c068a1f54d77965b428a7969125313ce29abb93b"}]}"#;
    // The response the CLI accepted and drove its poll from (cli.log, "Deployment response").
    const CREATE_RESPONSE: &str = r#"{"id":"dpl_stub123","url":"stubsite-abc.vercel.app","name":"stubsite","readyState":"READY","status":"READY","target":null,"createdAt":1,"ownerId":"team_stub","projectId":"prj_stub","creator":{"uid":"usr_stub","username":"stubuser"},"regions":["iad1"],"aliasAssigned":true,"alias":[]}"#;
    // The 400 the stub answered the first create with, which is what makes the CLI upload.
    const MISSING_FILES: &str = r#"{"error":{"code":"missing_files","message":"Missing files","missing":["11d7f3424347713a17b0f208ef3d4e44b164a0cd","59503668a37e65112006ed3ab584d1fe1727aea4","bfbd242840723ccfd12ccdc651faaecc278fc039"]}}"#;

    // (transcript seq, method, target, body) — the sequence exactly as captured.
    let hops: [(&str, &str, &str, &[u8]); 8] = [
        ("seq 2", "GET", "/v2/user", b""),
        // seq 3: the team-context hop — team named in the PATH, no query at all.
        ("seq 3", "GET", "/teams/team_stub", b""),
        (
            "seq 4",
            "GET",
            "/v9/projects/prj_stub?teamId=team_stub",
            b"",
        ),
        (
            "seq 5",
            "POST",
            "/v13/deployments?teamId=team_stub&skipAutoDetectionConfirmation=1",
            CREATE_BODY.as_bytes(),
        ),
        (
            "seq 6",
            "POST",
            "/v2/files?teamId=team_stub",
            b"body{color:#111}\n",
        ),
        (
            "seq 7",
            "POST",
            "/v2/files?teamId=team_stub",
            b"<!doctype html><title>stub</title><h1>stub site</h1>\n",
        ),
        (
            "seq 8",
            "POST",
            "/v2/files?teamId=team_stub",
            b"console.log(\"b\");\n",
        ),
        (
            "seq 9",
            "POST",
            "/v13/deployments?teamId=team_stub&skipAutoDetectionConfirmation=1",
            CREATE_BODY.as_bytes(),
        ),
    ];

    let mut s = session_frozen("stubsite", Some("team_stub"), "preview");
    for (seq, method, target, body) in hops {
        let verdict = s.authorize(method, target, body, NOW);
        let RelayVerdict::Forward { effect } = verdict else {
            panic!("{seq}: the CLI's own {method} {target} was refused: {verdict:?}");
        };
        s.note_forward(effect);
        // The two-phase create: the first one is answered `400 missing_files`, which releases the
        // single effect so the retry after the uploads is the SAME effect, not a second one.
        if effect && seq == "seq 5" {
            assert!(s
                .observe_response(true, 400, MISSING_FILES.as_bytes())
                .is_none());
            assert!(!s.effect_used(), "a definite 4xx is a definite no-effect");
        } else if effect {
            assert!(
                s.observe_response(true, 200, CREATE_RESPONSE.as_bytes())
                    .is_none(),
                "{seq}: the create's own response must satisfy the assertions the envelope makes \
                 about it (name == frozen project, target == frozen target)"
            );
        }
    }
    assert!(s.effect_used(), "the deployment landed on the retry");

    // The victory lap, from the CLI's own debug trace (cli.log request #4): the events tail, whose
    // wildcard is the deployment id captured off the create response above.
    assert!(
        matches!(
            s.authorize(
                "GET",
                "/v3/now/deployments/dpl_stub123/events?direction=forward&follow=1&format=lines&teamId=team_stub",
                b"",
                NOW
            ),
            RelayVerdict::Forward { effect: false }
        ),
        "the poll the CLI actually makes must forward, or every deploy burns its victory lap"
    );
    assert!(s.burned().is_none(), "an honest deploy burns nothing");
    let receipt = s.receipt("ttl");
    assert_eq!(receipt["deployment_id"], "dpl_stub123");
    assert_eq!(receipt["deployment_url"], "stubsite-abc.vercel.app");
}

/// The two dimensions, kept distinct: KEY closure refuses a parameter nobody ratified
/// (`slug`, which redirects scope by name), and the VALUE bind pins the one that is ratified. A
/// refusal from the first dimension is `no_matching_shape`; from the second, `bind_mismatch`.
#[test]
fn key_closure_and_value_binds_are_separate_dimensions() {
    let mut s = session_scoped("website", "team_ours");
    assert_eq!(
        s.authorize(
            "POST",
            "/v13/deployments?slug=team-other&teamId=team_ours",
            &create_body("website"),
            NOW
        ),
        RelayVerdict::Refuse(RelayRefusal::NoMatchingShape),
        "an unlisted parameter never reaches the value check — the key set is closed"
    );
    assert_eq!(
        s.authorize(
            "POST",
            "/v13/deployments?teamId=team_other",
            &create_body("website"),
            NOW
        ),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch),
        "a listed parameter carrying an unapproved value refuses at its bind"
    );
}

/// Query VALUES are compared RAW, byte for byte. CLI 58.4.4 sends a bare Vercel team id
/// (`teamId=team_XXXX`, `[A-Za-z0-9_]`) — nothing that needs percent-encoding — so the relay adds no
/// decoding machinery for a shape no client sends (note-not-code). This test LOCKS that: an encoded
/// or duplicated value is not equal to the frozen one, so it fails closed rather than being decoded
/// into agreement. If a future CLI ever encodes the value, this is the test that fails first.
#[test]
fn a_query_value_is_compared_raw_and_ambiguity_fails_closed() {
    let mut s = session_scoped("website", "team_ours");
    for target in [
        // Percent-encoded, decoding to the frozen value: refused, not decoded.
        "/v13/deployments?teamId=team%5Fours",
        // A repeated key is ambiguous about which value the upstream would honor.
        "/v13/deployments?teamId=team_ours&teamId=team_other",
        "/v13/deployments?teamId=team_other&teamId=team_ours",
    ] {
        assert_eq!(
            s.authorize("POST", target, &create_body("website"), NOW),
            RelayVerdict::Refuse(RelayRefusal::BindMismatch),
            "{target}"
        );
    }
}

/// No cross-hop dataflow. The session's read shapes carry a wildcard deployment id, and
/// the matcher checked only that SOME segment was there — so a session could poll, and tail the build
/// logs of, any deployment in the frozen scope, including ones it never created (T1: injected "while
/// you're in there, read the other deployment's build log"; T2: a stale id from an earlier run).
///
/// The invariant restored: a session's authority is confined to its own approved effect and that
/// effect's own consequences. Nothing is captured until the create's own response lands, so a poll
/// BEFORE the create has nothing to agree with and refuses — the honest CLI never polls first.
#[test]
fn a_poll_before_the_create_refuses_and_burns() {
    for target in [
        "/v13/deployments/dpl_someone_else",
        "/v2/deployments/dpl_someone_else/events",
        "/v3/now/deployments/dpl_someone_else/events?format=lines",
    ] {
        let mut s = session("website");
        assert_eq!(
            s.authorize("GET", target, b"", NOW),
            RelayVerdict::Refuse(RelayRefusal::BindMismatch),
            "nothing is captured yet, so no deployment id agrees: {target}"
        );
        s.note_refusal(RelayRefusal::BindMismatch, "GET", target);
        assert!(
            s.burned().is_some(),
            "a read outside the session's own effect is a probe: {target}"
        );
    }
}

/// ...and once the create HAS landed, the session may poll exactly the deployment it created.
#[test]
fn a_poll_is_confined_to_the_deployment_this_session_created() {
    let mut s = session("website");
    assert_eq!(
        s.authorize("POST", "/v13/deployments", &create_body("website"), NOW),
        RelayVerdict::Forward { effect: true }
    );
    s.note_forward(true);
    assert!(
        s.observe_response(true, 200, &create_response("dpl_ours", "website"))
            .is_none(),
        "the honest outcome agrees with the approval"
    );

    for target in [
        "/v13/deployments/dpl_ours",
        "/v13/deployments/dpl_ours?withGitRepoInfo=true",
        "/v2/deployments/dpl_ours/events?follow=1",
        "/v3/now/deployments/dpl_ours/events?direction=forward&format=lines",
    ] {
        assert!(
            matches!(
                s.authorize("GET", target, b"", NOW),
                RelayVerdict::Forward { effect: false }
            ),
            "the CLI's own victory lap over the deployment it just created: {target}"
        );
    }
    for target in [
        "/v13/deployments/dpl_theirs",
        "/v2/deployments/dpl_theirs/events",
        "/v3/now/deployments/dpl_theirs/events?format=lines",
    ] {
        assert_eq!(
            s.authorize("GET", target, b"", NOW),
            RelayVerdict::Refuse(RelayRefusal::BindMismatch),
            "another deployment is not this session's consequence: {target}"
        );
    }
}

/// A capture is WRITE-ONCE. The effect passes at most once, but its response can be observed more
/// than once (the 400-then-retry dance, a provider echo), and a session that could be re-pointed at
/// a second deployment id would be exactly the dataflow hole the capture closes.
#[test]
fn a_capture_is_write_once() {
    let mut s = session("website");
    s.note_forward(true);
    s.observe_response(true, 200, &create_response("dpl_first", "website"));
    s.observe_response(true, 200, &create_response("dpl_second", "website"));
    assert!(
        matches!(
            s.authorize("GET", "/v13/deployments/dpl_first", b"", NOW),
            RelayVerdict::Forward { .. }
        ),
        "the FIRST observed effect response is the one the session is confined to"
    );
    assert_eq!(
        s.authorize("GET", "/v13/deployments/dpl_second", b"", NOW),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch),
        "a second response never re-points a live session"
    );
}

/// The two ways an effect response yields nothing, both fail closed. A provider 4xx means no
/// deployment exists (and releases the `once` effect, unchanged); an unparseable body — which
/// is what a create response over the bounded receipt tee looks like — yields no id either. In both
/// cases the polls refuse: the deploy itself already happened or didn't, and only the victory lap is
/// lost. That is the accepted cost, not a handled edge (note-not-code).
#[test]
fn an_effect_response_that_names_nothing_captures_nothing() {
    let mut s = session("website");
    s.note_forward(true);
    assert!(s
        .observe_response(true, 400, br#"{"error":{"code":"missing_files"}}"#)
        .is_none());
    assert!(!s.effect_used(), "a definite 4xx is a definite no-effect");
    assert_eq!(
        s.authorize("GET", "/v13/deployments/dpl_anything", b"", NOW),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch),
        "nothing was created, so nothing is pollable"
    );

    // A response truncated at the receipt tee's bound is not JSON, so it names no id.
    let mut s = session("website");
    s.note_forward(true);
    assert!(s
        .observe_response(
            true,
            200,
            br#"{"id":"dpl_ours","name":"website","files":[{"file"#
        )
        .is_none());
    assert_eq!(
        s.authorize("GET", "/v13/deployments/dpl_ours", b"", NOW),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch),
        "an unreadable outcome is not evidence of what was created"
    );
}

/// The create's own response was never compared to the fields the approval froze, so
/// provider-side semantic drift — an omitted `target` classified as production, a project resolved
/// to a different name — was silent. The assertion is DETECTION, not prevention: the deployment has
/// already landed by the time the response is read, and nothing here un-deploys it. What it buys is
/// that the session dies immediately and the operator gets a high-severity row with frozen-vs-observed.
#[test]
fn an_outcome_contradicting_the_approval_burns_the_session() {
    let cases: [(&str, &str, &str, Option<&str>, &str); 2] = [
        (
            "the provider classified an approved preview as production",
            r#"{"id":"dpl_ours","url":"u","name":"website","target":"production"}"#,
            "target",
            None,
            "production",
        ),
        (
            "the provider resolved the create to a different project",
            r#"{"id":"dpl_ours","url":"u","name":"other-site","target":null}"#,
            "name",
            Some("website"),
            "other-site",
        ),
    ];
    for (why, landed, key, expected, observed) in cases {
        let mut s = session("website");
        s.note_forward(true);
        let mismatch = s
            .observe_response(true, 200, landed.as_bytes())
            .unwrap_or_else(|| panic!("{why}: the outcome contradicts the approval"));
        assert_eq!(mismatch.key, key, "{why}");
        assert_eq!(mismatch.expected.as_deref(), expected, "{why}");
        assert_eq!(mismatch.observed.as_deref(), Some(observed), "{why}");

        // Detection, not prevention: the deployment EXISTS, and the receipt still names it — that is
        // what the operator needs in order to go deal with it.
        assert_eq!(
            s.observations().deployment_id.as_deref(),
            Some("dpl_ours"),
            "{why}"
        );
        s.note_outcome_mismatch("POST", "/v13/deployments");
        assert_eq!(s.burned(), Some(&RelayRefusal::OutcomeMismatch), "{why}");
        assert_eq!(
            s.authorize("GET", "/v13/deployments/dpl_ours", b"", NOW),
            RelayVerdict::Refuse(RelayRefusal::UnknownHandle),
            "{why}: a session whose outcome contradicts its approval is done"
        );
        let receipt = s.receipt("outcome_mismatch");
        assert_eq!(receipt["burned"], "outcome_mismatch", "{why}");
        assert_eq!(receipt["deployment_id"], "dpl_ours", "{why}");
    }
}

/// The other half: an outcome that AGREES leaves the session live, under both target encodings.
/// Vercel answers a preview create with `target: null` or no key at all (it has no legal
/// `target: preview`), and a production create with the literal — the same `omit:preview` encoding
/// the request-side bind already uses.
#[test]
fn an_outcome_that_agrees_with_the_approval_leaves_the_session_live() {
    for landed in [
        r#"{"id":"dpl_1","url":"u","name":"website","target":null}"#,
        r#"{"id":"dpl_1","url":"u","name":"website"}"#,
    ] {
        let mut s = session("website");
        s.note_forward(true);
        assert!(
            s.observe_response(true, 200, landed.as_bytes()).is_none(),
            "an absent or null target IS the preview case: {landed}"
        );
        assert!(s.burned().is_none(), "{landed}");
    }

    let mut s = session_targeted("website", "production");
    s.note_forward(true);
    assert!(
        s.observe_response(
            true,
            200,
            br#"{"id":"dpl_1","url":"u","name":"website","target":"production"}"#
        )
        .is_none(),
        "a production approval expects the literal back"
    );
    assert!(s.burned().is_none());

    // ...and the mirror image: a production approval answered as a preview is the same detection.
    let mut s = session_targeted("website", "production");
    s.note_forward(true);
    let mismatch = s
        .observe_response(true, 200, br#"{"id":"dpl_1","url":"u","name":"website"}"#)
        .expect("a production approval answered with no target is a mismatch");
    assert_eq!(mismatch.key, "target");
    assert_eq!(mismatch.expected.as_deref(), Some("production"));
    assert_eq!(mismatch.observed, None);
}

/// The budget the SHIPPED upload shape declares — the cap tests spend the REAL one, not a fixture's,
/// so a future edit to the ratified values moves the tests with it instead of silently diverging.
fn upload_caps() -> RelayCaps {
    shipped_predicate()
        .iter()
        .find(|rule| rule.method == "POST" && rule.path == "/v2/files")
        .and_then(|rule| rule.caps())
        .expect("the upload shape declares a per-session budget")
}

/// T2 an accident loop, T1 "keep uploading": before this, `POST /v2/files` was unlimited
/// in COUNT and in AGGREGATE BYTES for the whole session TTL — an approved deploy bought an
/// unbounded credentialed pipe into the operator's Vercel file store. The shape now declares a
/// budget, and a hop that would spend past it is refused BEFORE the credential is attached.
#[test]
fn the_upload_shape_spends_a_declared_use_budget() {
    let caps = upload_caps();
    let mut s = session("website");
    for use_index in 0..caps.max_uses {
        assert_eq!(
            s.authorize("POST", "/v2/files", b"f", NOW),
            RelayVerdict::Forward { effect: false },
            "upload {use_index} is inside the declared budget"
        );
    }
    let over = s.authorize("POST", "/v2/files", b"f", NOW);
    assert_eq!(
        over,
        RelayVerdict::Refuse(RelayRefusal::CapExceeded {
            cap: RelayCapKind::Uses
        }),
        "the hop that would exceed `max_uses` is refused, not the one that reaches it"
    );
    // Same discipline as every other out-of-sentence hop: it burns, and the burn is audited under
    // its own reason so the trail says WHICH budget ran out.
    assert!(matches!(over, RelayVerdict::Refuse(ref r) if r.burns()));
    s.note_refusal(
        RelayRefusal::CapExceeded {
            cap: RelayCapKind::Uses,
        },
        "POST",
        "/v2/files",
    );
    assert_eq!(
        s.burned().map(RelayRefusal::reason),
        Some("cap_exceeded_uses")
    );
    assert_eq!(
        s.authorize("POST", "/v2/files", b"f", NOW),
        RelayVerdict::Refuse(RelayRefusal::UnknownHandle),
        "a session that blew its budget is done, like every other burned session"
    );
}

/// The second dimension: the aggregate REQUEST bytes the shape may carry per session. A count cap
/// alone bounds nothing that matters — one hop can carry a whole body — so the budget closes both.
#[test]
fn the_upload_shape_spends_a_declared_byte_budget() {
    let caps = upload_caps();
    let hops = 32u64;
    assert_eq!(
        caps.max_total_bytes % hops,
        0,
        "the test spends the ratified byte budget in {hops} equal hops"
    );
    assert!(
        hops < caps.max_uses,
        "the byte budget must run out first for this test to be about bytes"
    );
    let chunk = (caps.max_total_bytes / hops) as usize;
    let body = vec![b'x'; chunk];
    let mut s = session("website");
    for hop in 0..hops {
        assert_eq!(
            s.authorize("POST", "/v2/files", &body, NOW),
            RelayVerdict::Forward { effect: false },
            "hop {hop} is inside the declared byte budget"
        );
    }
    assert_eq!(
        s.authorize("POST", "/v2/files", b"x", NOW),
        RelayVerdict::Refuse(RelayRefusal::CapExceeded {
            cap: RelayCapKind::Bytes
        }),
        "one byte past the aggregate is past it"
    );
}

/// The budget is the SESSION's, and it is the SHAPE's: a second grant starts fresh (nothing is
/// global), and spending the upload budget never touches a shape that declares no caps.
#[test]
fn the_budget_is_per_session_and_per_shape() {
    let caps = upload_caps();
    let mut spent = session("website");
    for _ in 0..caps.max_uses {
        assert!(matches!(
            spent.authorize("POST", "/v2/files", b"f", NOW),
            RelayVerdict::Forward { .. }
        ));
    }
    assert_eq!(
        spent.authorize("POST", "/v2/files", b"f", NOW),
        RelayVerdict::Refuse(RelayRefusal::CapExceeded {
            cap: RelayCapKind::Uses
        })
    );
    // The uncapped shapes of the SAME session are untouched — the counters are per shape, and the
    // create is still the one effect this grant bought.
    assert_eq!(
        spent.authorize("GET", "/v2/user", b"", NOW),
        RelayVerdict::Forward { effect: false },
        "spending the upload budget does not spend a shape that declares no budget"
    );
    assert_eq!(
        spent.authorize("POST", "/v13/deployments", &create_body("website"), NOW),
        RelayVerdict::Forward { effect: true }
    );
    // ...and a different session is a different budget: one grant's spend cannot exhaust another's.
    let mut fresh = session("website");
    assert_eq!(
        fresh.authorize("POST", "/v2/files", b"f", NOW),
        RelayVerdict::Forward { effect: false },
        "a second session opens with its own budget"
    );
}

/// The budget is the LAST check, so a hop that is outside the sentence still reports THAT. Volume is
/// the least interesting thing wrong with a scope-redirecting upload, and the trail an operator reads
/// must name the authority defect, not the budget the same hop also happens to blow.
#[test]
fn an_out_of_scope_upload_still_reports_the_bind_not_the_budget() {
    let caps = upload_caps();
    let mut s = session_scoped("website", "team_ours");
    for _ in 0..caps.max_uses {
        assert!(matches!(
            s.authorize("POST", "/v2/files?teamId=team_ours", b"f", NOW),
            RelayVerdict::Forward { .. }
        ));
    }
    assert_eq!(
        s.authorize("POST", "/v2/files?teamId=team_other", b"f", NOW),
        RelayVerdict::Refuse(RelayRefusal::BindMismatch),
        "the scope redirect is what this hop is refused for, budget or no budget"
    );
}

/// The receipt is durable audit data on a path any peer uid at the loopback port can reach, so the
/// target it names is bounded exactly like every other relay audit row.
#[test]
fn a_burned_receipts_target_is_bounded() {
    let mut s = session("website");
    let huge = format!("/{}", "a".repeat(4096));
    s.note_refusal(RelayRefusal::MalformedRequest, "GET", &huge);
    let receipt = s.receipt("burned");
    let named = receipt["burned_target"].as_str().unwrap();
    assert!(
        named.len() < huge.len() && huge.starts_with(named),
        "{named}"
    );
}
