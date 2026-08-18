#![allow(dead_code, unused_variables)]
use super::*;
use crate::contract::{FieldDecl, ScalarKind};
use crate::provider::ProviderResponse;
use crate::types::{CapabilityRequest, EffectFailureClass, RequestLogView};

fn catalog() -> Vec<String> {
    crate::templates::VENDORED_CATALOG
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn open_broker(policy: &str) -> TestBroker {
    let (guard, dir) = fresh_broker_dir();
    TestBroker::new(guard, open_broker_reuse(&dir, policy))
}

/// Open a broker over an EXISTING dir (a "restart") — reuses the same state/vault/audit + any
/// seeded `profiles.d`. The active profile, not `policy`, is the live document on a reopen.
fn open_broker_reuse(dir: &std::path::Path, policy: &str) -> Broker {
    Broker::open_for_semantic_test(
        BrokerConfig {
            git: test_quarantine(),
            dir: dir.to_path_buf(),
            master_key: vec![5u8; 32],
            action_templates: catalog(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        None,
    )
    .unwrap()
}

/// The `github.test_two_step_write` template, kept as a test-only behavioral fixture (a github write verb
/// with a GET-then-PUT wire shape). `test_two_step_write` is retired from the shipped/vendored catalog;
/// this fixture keeps it available to exercise generic broker machinery.
const TWO_STEP_TEMPLATE: &str =
    include_str!("../../tests/fixtures/github.test_two_step_write.yaml");
fn open_broker_with_templates(policy: &str, action_templates: Vec<String>) -> Result<TestBroker> {
    let (guard, dir) = fresh_broker_dir();
    Broker::open_for_semantic_test(
        BrokerConfig {
            git: test_quarantine(),
            dir,
            master_key: vec![5u8; 32],
            action_templates,
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        None,
    )
    .map(|broker| TestBroker::new(guard, broker))
}

fn open_product_broker() -> TestBroker {
    let (guard, dir) = fresh_broker_dir();
    let broker = Broker::open(BrokerConfig {
        git: test_quarantine(),
        dir,
        master_key: vec![5u8; 32],
        action_templates: crate::templates::VENDORED_CATALOG
            .iter()
            .map(|doc| doc.to_string())
            .collect(),
        provider_descriptors: BrokerConfig::vendored_descriptors(),
        artifacts: crate::artifacts::ArtifactConfig::default(),
    })
    .unwrap();
    TestBroker::new(guard, broker)
}

/// Product availability is a positive ALLOWLIST, so a provider label nobody has ruled on
/// resolves DISABLED. Production loads operator-owned descriptors from `providers.d`/`actions.d`,
/// so a denylist would let a newly authored `acme` descriptor become catalog-visible, connectable,
/// and mintable with no product-enable decision — unresolved access must never be granted.
const UNRULED_PROVIDER_LABELS: &[&str] = &["acme", "github2", "stripe-eu", "Stripe", ""];

#[test]
fn a_failed_effect_names_the_retry_channel_only_when_nothing_determined_it() {
    use crate::types::EffectFailureClass as Class;
    let message = super::execute::effect_failure_message;
    // Past the invocation boundary with no answer, the observation determines nothing — so the
    // sentence names the EXISTING channel concretely, by the handle the agent holds, and says
    // why it is the safe one.
    let named = message(Class::TransportNoResponse, "effect_abc");
    assert!(named.contains("retry_effect=effect_abc"), "{named}");
    assert!(named.contains("no response arrived"), "{named}");
    // The residual and every arrived-but-failed class take the same conservative arm: absent
    // definitive pre-send evidence, never say the effect did not happen.
    for undetermined in [
        Class::Failed,
        Class::ProviderTransient,
        Class::ProtocolDrift,
    ] {
        assert!(
            message(undetermined, "effect_abc").contains("retry_effect=effect_abc"),
            "{undetermined}"
        );
    }
    // Nothing was written (or our own box failed before the wire): the effect IS determined, and an
    // instruction to retry the SAME effect would claim more than the evidence supports.
    for determined in [Class::TransportPreSend, Class::LocalExecutionFailure] {
        let plain = message(determined, "effect_abc");
        assert!(!plain.contains("retry_effect"), "{determined}: {plain}");
        assert!(plain.contains("never left this machine"), "{determined}");
    }
    // No adapter prose reaches the agent or the record through this seam.
    assert!(!message(Class::TransportNoResponse, "effect_abc").contains("provider"));
}

#[test]
fn an_unruled_provider_label_is_never_product_enabled() {
    for label in UNRULED_PROVIDER_LABELS {
        assert_eq!(
            crate::provider::product_availability(label, "any_action"),
            crate::provider::ProductAvailability::ProviderDisabled,
            "an unruled provider label must resolve disabled, not enabled: {label:?}"
        );
    }
    for (provider, action) in [
        ("stripe", "get_charge"),
        ("github", "read_repo"),
        // Vercel joins the allowlist — the relay verb needs the whole path
        // (catalog, connect, mint, claim) reachable, and `product_availability` is the gate.
        ("vercel", "deploy"),
    ] {
        assert_eq!(
            crate::provider::product_availability(provider, action),
            crate::provider::ProductAvailability::Enabled,
            "{provider} is a product-enabled provider"
        );
    }
}

/// The operator must be able to hand cermetd a real Vercel token. Connect is the
/// first door `product_availability` closes (`connect_credential`), so prove it opens.
#[test]
fn vercel_relay_m1_connect_is_no_longer_refused_at_the_broker_layer() {
    let broker = open_product_broker();
    let outcome = broker
        .connect_credential(
            "vercel",
            Some("relay"),
            "vercel_tok_fixture_never_receipted",
        )
        .expect("a product-enabled, descriptor-backed vercel connect is accepted");
    assert_eq!(outcome.provider, "vercel");
    assert!(
        broker
            .list_credentials_for_agent()
            .unwrap()
            .iter()
            .any(|credential| credential.provider == "vercel"),
        "an enabled provider's credential is visible on the agent projection"
    );
}

#[test]
fn an_unruled_provider_is_catalog_invisible_and_connect_refused() {
    for label in UNRULED_PROVIDER_LABELS {
        let broker = open_product_broker();
        // Nothing an unruled label names may reach the visible catalog or the agent listing.
        assert!(
            broker
                .catalog()
                .unwrap()
                .iter()
                .all(|entry| entry.provider != *label),
            "an unruled provider must be catalog-invisible: {label:?}"
        );
        let error = broker
            .connect_credential(label, None, "unused")
            .expect_err("an unruled provider cannot be connected");
        assert!(
            matches!(error, Error::ProviderDisabled),
            "{label:?}: {error:?}"
        );
    }
}

#[test]
fn an_unruled_provider_request_mints_no_grant() {
    for label in UNRULED_PROVIDER_LABELS {
        let broker = open_product_broker();
        broker
            .open_session("s1", "agent", None, None, SessionActor::default())
            .unwrap();
        let outcome = broker
            .request_capability_for_principal(
                "s1",
                "uid:501",
                CapabilityRequest {
                    provider: (*label).into(),
                    action: "deploy".into(),
                    resource: json!({}),
                    environment: None,
                    justification: None,
                    model: None,
                },
            )
            .unwrap();
        assert_eq!(outcome.decision, Decision::Deny, "{label:?}");
        assert_eq!(outcome.reason, "provider_disabled", "{label:?}");
        assert!(
            outcome.grant_id.is_none(),
            "an unruled provider must never mint a grant: {label:?}"
        );
    }
}

/// A mirror root far away from the installed `/var/lib/cermetd/mirrors`. Deliberately leaves git
/// UNREGISTERED: these tests exercise authority, not the seam, so this path is never created and
/// never written.
///
/// This names a single fixed, never-created quarantine root shared with every other suite in the
/// workspace (`cermet-core/tests/session_unforgeable.rs`, `cermet-daemon/tests/ctl_socket.rs`, …)
/// rather than minting a fresh scratch dir per call, which would leak one directory per test run.
fn test_quarantine() -> crate::git::GitConfig {
    crate::git::GitConfig::at(std::env::temp_dir().join("cermet-test-quarantine"))
}

#[test]
fn broker_test_modules_have_no_pid_counter_allocators() {
    let fragments = [
        ["std::process", "::id"].concat(),
        ["std::env", "::temp_dir"].concat(),
        ["Atomic", "U"].concat(),
        [".fetch_", "add("].concat(),
    ];
    let primary = include_str!("tests.rs");
    // Per-test ALLOCATORS are forbidden. The one permitted `temp_dir` is `test_quarantine()`
    // above: a single FIXED path, the opposite of an allocator, and never created.
    for (fragment, expected) in fragments.iter().zip([0, 1, 0, 0]) {
        assert_eq!(
            primary.matches(fragment).count(),
            expected,
            "tests.rs has an unexpected `{fragment}` allocator fragment"
        );
    }
}

/// The broker test scratch dir is RAII: the dir must be GONE once its guard drops, never kept
/// alive by a fixture that returns a bare path and disarms the guard.
#[test]
fn fresh_broker_dir_is_removed_when_its_guard_drops() {
    let path = {
        let (guard, dir) = fresh_broker_dir();
        assert!(dir.is_dir(), "the fixture must create its dir: {dir:?}");
        drop(guard);
        dir
    };
    assert!(
        !path.exists(),
        "the fixture dir outlived its guard (a leaked scratch dir): {path:?}"
    );
}

/// `keep()` is the ONE call that disarms a `TempDir`, so a test module that names it has re-armed
/// a leak. Grepping the modules is the cheap standing guard (same shape as the allocator scan
/// above).
#[test]
fn no_broker_test_module_disarms_a_tempdir_guard() {
    let disarm = [".ke", "ep()"].concat();
    for (label, source) in [
        ("broker/mod.rs", include_str!("mod.rs")),
        ("broker/tests.rs", include_str!("tests.rs")),
        (
            "broker/evidence_tests.rs",
            include_str!("evidence_tests.rs"),
        ),
        ("broker/quiesce_tests.rs", include_str!("quiesce_tests.rs")),
        (
            "broker/sentence_custody.rs",
            include_str!("sentence_custody.rs"),
        ),
    ] {
        assert_eq!(
            source.matches(disarm.as_str()).count(),
            0,
            "{label} disarms a TempDir guard — the scratch dir it makes will leak"
        );
    }
}

fn two_step_req(resource: Value) -> CapabilityRequest {
    CapabilityRequest {
        provider: "github".into(),
        action: "test_two_step_write".into(),
        resource,
        environment: None,
        justification: None,
        model: None,
    }
}

fn bound_effect_start_data(
    broker: &Broker,
    grant_id: &str,
    grant: &GrantRow,
    mut data: Value,
) -> Value {
    data["resource_binding"] = json!(broker
        .effect_start_resource_binding(grant_id, grant, &data["resource"])
        .unwrap());
    data
}

// ---- S3 artifact store: the write API (store_artifact) + read path, and the audit-chain digest ----

#[test]
fn store_artifact_roundtrips_and_chains_the_digest() {
    let b = open_broker(ALLOW_DEPLOY);
    let bytes = b"cargo test output\nall 42 passed\n";
    let stored = b.store_artifact("rq-1", bytes).unwrap();
    assert!(!stored.truncated);
    assert_eq!(stored.size, bytes.len() as u64);

    // Read the full blob back through the broker read path.
    let span = b
        .read_artifact(
            &stored.handle,
            None,
            crate::artifacts::ArtifactReadSurface::Ctl,
        )
        .unwrap();
    assert_eq!(span.content, "cargo test output\nall 42 passed\n");
    assert_eq!(span.digest, stored.digest);

    // The digest is recorded in the audit chain — and the chain still verifies.
    assert!(b.verify_integrity().unwrap().verified);
    let audit = rusqlite::Connection::open(b.dir.join("audit.db")).unwrap();
    let data: String = audit
        .query_row(
            "SELECT data_json FROM audit_events WHERE type='artifact_stored'",
            [],
            |r| r.get(0),
        )
        .expect("an artifact_stored event was chained");
    assert!(
        data.contains(&stored.digest),
        "the receipt event carries the digest: {data}"
    );
    // Metadata only — the blob bytes never ride the chain.
    assert!(
        !data.contains("cargo test output"),
        "output bytes must not be in the audit event"
    );
}

#[test]
fn read_artifact_unknown_handle_fails_closed() {
    let b = open_broker(ALLOW_DEPLOY);
    assert!(matches!(
        b.read_artifact(
            "art_ghost",
            None,
            crate::artifacts::ArtifactReadSurface::Ctl
        )
        .unwrap_err(),
        Error::NotFound(_)
    ));
}

#[test]
fn post_hoc_blob_tampering_is_detected_via_digest_mismatch() {
    let b = open_broker(ALLOW_DEPLOY);
    let stored = b.store_artifact("rq-1", b"trusted evidence").unwrap();
    // The agent cannot rewrite history in service mode (blob is _cermet-owned); simulate a tamper.
    std::fs::write(
        b.dir.join("artifacts").join(&stored.digest),
        b"forged evidence!",
    )
    .unwrap();
    assert!(
        matches!(
            b.read_artifact(
                &stored.handle,
                None,
                crate::artifacts::ArtifactReadSurface::Ctl
            )
            .unwrap_err(),
            Error::Integrity(_)
        ),
        "a rewritten blob must fail the chained-digest check"
    );
}

#[test]
fn store_artifact_truncates_oversized_output() {
    let mut b = open_broker(ALLOW_DEPLOY);
    b.artifacts.max_bytes = 64;
    let big = vec![b'x'; 5000];
    let stored = b.store_artifact("rq-1", &big).unwrap();
    assert!(stored.truncated);
    assert_eq!(stored.size, 5000, "size is the ORIGINAL length");
    let span = b
        .read_artifact(
            &stored.handle,
            None,
            crate::artifacts::ArtifactReadSurface::Ctl,
        )
        .unwrap();
    assert!(span.content.contains("truncated"));
    assert!(span.stored_size < 5000);
}

// ---- Ratified action templates: boot wiring + per-broker reachability ----

#[test]
fn broker_boot_fails_closed_on_bad_template_doc() {
    let bad = "provider: github\naction: broken\n";
    assert!(
        open_broker_with_templates("providers: {}", vec![bad.to_string()]).is_err(),
        "an invalid action-template document must refuse boot"
    );
}

#[test]
fn duplicate_provider_descriptor_name_refuses_boot() {
    // Two descriptors declaring the same `name:` must not last-write-wins through the registry
    // HashMap — that would silently decide which egress a vaulted token rides to. Boot refuses,
    // naming the collision.
    let (_dir_guard, dir) = fresh_broker_dir();
    let mut descriptors = BrokerConfig::vendored_descriptors();
    // Duplicate the FIRST vendored descriptor (as if two providers.d/*.yaml files collided).
    descriptors.push(descriptors[0].clone());
    let msg = match Broker::open(BrokerConfig {
        git: test_quarantine(),
        dir,
        master_key: vec![5u8; 32],
        action_templates: Vec::new(),
        provider_descriptors: descriptors,
        artifacts: crate::artifacts::ArtifactConfig::default(),
    }) {
        Ok(_) => panic!("a duplicate provider-descriptor name must refuse boot"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("same name") && msg.contains("refusing"),
        "the error signals a fail-closed refusal on the duplicate name: {msg}"
    );
}

fn schema_guard_cfg(dir: std::path::PathBuf) -> BrokerConfig {
    BrokerConfig {
        git: test_quarantine(),
        dir,
        master_key: vec![5u8; 32],
        action_templates: Vec::new(),
        provider_descriptors: BrokerConfig::vendored_descriptors(),
        artifacts: crate::artifacts::ArtifactConfig::default(),
    }
}

#[test]
fn a_pre_greenfield_state_db_refuses_boot_not_at_read_time() {
    // The schema is greenfield (no migrations): a state.db written by an older schema
    // generation has real tables but no version stamp. Boot must refuse with a remedy,
    // never serve and then surface raw "no such column" SQL errors on the first read.
    let (_dir_guard, dir) = fresh_broker_dir();
    let conn = rusqlite::Connection::open(dir.join("state.db")).unwrap();
    conn.execute_batch("CREATE TABLE operations (id TEXT PRIMARY KEY, declared_goal TEXT);")
        .unwrap();
    drop(conn);
    let msg = match Broker::open(schema_guard_cfg(dir)) {
        Ok(_) => panic!("a pre-greenfield state.db must refuse boot"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("schema") && msg.contains("re-bootstrap"),
        "the refusal names the schema mismatch and the remedy: {msg}"
    );
}

#[test]
fn a_future_schema_generation_refuses_boot() {
    // A DOWNGRADED binary against a newer data dir is the same class of drift.
    let (_dir_guard, dir) = fresh_broker_dir();
    let conn = rusqlite::Connection::open(dir.join("state.db")).unwrap();
    conn.execute_batch("CREATE TABLE operations (id TEXT PRIMARY KEY); PRAGMA user_version = 99;")
        .unwrap();
    drop(conn);
    assert!(
        Broker::open(schema_guard_cfg(dir)).is_err(),
        "a state.db stamped with a future schema generation must refuse boot"
    );
}

#[test]
fn a_fresh_state_db_is_stamped_and_reopens_cleanly() {
    // Fresh dir → the greenfield DDL runs and the generation is stamped; a second open of
    // the SAME dir (a normal daemon restart) passes the guard.
    let (_dir_guard, dir) = fresh_broker_dir();
    drop(Broker::open(schema_guard_cfg(dir.clone())).unwrap());
    let stamped: i64 = rusqlite::Connection::open(dir.join("state.db"))
        .unwrap()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        stamped, STATE_SCHEMA_VERSION,
        "the fresh DB carries the stamp"
    );
    Broker::open(schema_guard_cfg(dir)).expect("a restart against its own state.db boots");
}

#[test]
fn a_requests_table_without_matched_rule_gains_the_column_in_place() {
    // An ADDITIVE column MIGRATES, it does not force a state wipe. A
    // state.db written before `matched_rule` existed gains the column at open; its existing rows
    // read NULL, which is the truth — they recorded no rule provenance.
    let (_dir_guard, dir) = fresh_broker_dir();
    let legacy = rusqlite::Connection::open(dir.join("state.db")).unwrap();
    legacy
        .execute_batch(
            "CREATE TABLE requests (
                id TEXT PRIMARY KEY, provider TEXT NOT NULL, action TEXT NOT NULL,
                resource_json TEXT NOT NULL, justification TEXT, decision TEXT NOT NULL,
                reason TEXT NOT NULL, policy_fingerprint TEXT, principal TEXT,
                session_id TEXT, pid INTEGER, created_at TEXT NOT NULL);
             INSERT INTO requests (id, provider, action, resource_json, decision, reason, created_at)
               VALUES ('req_before_the_column','stripe','refund','{}','allow','allowed before the \
                       column existed','2026-07-01T00:00:00Z');",
        )
        .unwrap();
    legacy
        .pragma_update(None, "user_version", STATE_SCHEMA_VERSION)
        .unwrap();
    drop(legacy);

    let mut rules =
        crate::sentence::parse_rules("allow stripe.refund where amount <= 5000").unwrap();
    crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
    let source = Arc::new(V2M1SentenceAuthority::new(rules.clone()));
    let mut broker = open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source);
    install_v2_m1_fake_stripe(&mut broker);

    assert!(
        column_names(&dir, "requests").contains("matched_rule"),
        "the additive column is added in place, not wiped for"
    );
    let legacy_rule: Option<String> = broker
        .state
        .query_row(
            "SELECT matched_rule FROM requests WHERE id='req_before_the_column'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(legacy_rule, None, "a pre-column row has no rule provenance");

    let allowed = broker
        .request_capability_with_sentence(
            "migrated-allow",
            &rules,
            v2_m1_refund_request("ch_migrated"),
        )
        .unwrap();
    assert_eq!(allowed.decision, Decision::Allow);
    let stored: Option<String> = broker
        .state
        .query_row(
            "SELECT matched_rule FROM requests WHERE id=?1",
            rusqlite::params![allowed.request_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        stored.as_deref(),
        Some(crate::sentence::print_rule(&rules.rules[0]).as_str()),
        "a fresh allow round-trips its rule text through the migrated column"
    );
}

#[test]
fn moneypath_fresh_state_has_current_generation_with_required_private_money_metadata() {
    let (_dir_guard, dir) = fresh_broker_dir();
    drop(Broker::open(schema_guard_cfg(dir.clone())).unwrap());
    let conn = rusqlite::Connection::open(dir.join("state.db")).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, STATE_SCHEMA_VERSION);
    let columns = column_names(&dir, "grants");
    assert!(columns.contains("evidence_json"));
    assert!(columns.contains("money_json"));
    assert!(!columns.contains("idempotency_key"));
    assert!(!columns.contains("effect_id"));
    for name in ["evidence_json", "money_json"] {
        let not_null: i64 = conn
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('grants') WHERE name=?1",
                [name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(not_null, 1, "every grant must carry canonical {name}");
    }
}

#[test]
fn moneypath_pre_reset_generation_7_refuses_instead_of_synthesizing_money_metadata() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let conn = rusqlite::Connection::open(dir.join("state.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE requests (id TEXT PRIMARY KEY);
         CREATE TABLE grants (id TEXT PRIMARY KEY);
         PRAGMA user_version = 7;",
    )
    .unwrap();
    drop(conn);
    let error = match Broker::open(schema_guard_cfg(dir)) {
        Ok(_) => panic!("generation 7 must not be migrated or accepted"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains(&format!("expects {STATE_SCHEMA_VERSION}"))
            && error.contains("re-bootstrap"),
        "{error}"
    );
}

// ---- Generation 6: greenfield schema cut (operations + proposals GONE, descriptor hash IN) ----

fn table_names(dir: &std::path::Path) -> std::collections::HashSet<String> {
    let conn = rusqlite::Connection::open(dir.join("state.db")).unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap();
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    rows
}

fn column_names(dir: &std::path::Path, table: &str) -> std::collections::HashSet<String> {
    let conn = rusqlite::Connection::open(dir.join("state.db")).unwrap();
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .unwrap();
    stmt.query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

#[test]
fn a_generation_5_state_db_refuses_boot_with_the_clean_bootstrap_remedy() {
    // A nonempty gen-5 DB is the previous schema shape. Generation 6 refuses it at boot,
    // no migration.
    let (_dir_guard, dir) = fresh_broker_dir();
    let conn = rusqlite::Connection::open(dir.join("state.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE requests (id TEXT PRIMARY KEY);
             CREATE TABLE grants (id TEXT PRIMARY KEY);
             CREATE TABLE operations (id TEXT PRIMARY KEY);
             CREATE TABLE proposals (id TEXT PRIMARY KEY);
             PRAGMA user_version = 5;",
    )
    .unwrap();
    drop(conn);
    let msg = match Broker::open(schema_guard_cfg(dir)) {
        Ok(_) => panic!("a generation-5 state.db must refuse boot under generation 6"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("schema") && msg.contains("re-bootstrap"),
        "the refusal names the schema mismatch and the clean-bootstrap remedy: {msg}"
    );
}

// ---- Provider-descriptor grant binding ----

/// sha256 of `bytes` as lowercase hex — the same content hash the broker freezes onto a grant.
fn sha256_hex_test(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    crate::util::hex(&h.finalize())
}

/// Two brokers over ONE dir, the second with a byte-mutated github descriptor (same semantics,
/// different SHA-256) — the descriptor-replacement fixture.
fn two_brokers_bumped_github_descriptor(
    policy: &str,
    templates: Vec<String>,
) -> (PathBuf, Broker, Broker) {
    let (_dir_guard, dir) = fresh_broker_dir();
    let vendored = BrokerConfig::vendored_descriptors();
    let bumped: Vec<String> = vendored
        .iter()
        .enumerate()
        .map(|(i, d)| {
            if i == 0 {
                format!("{d}\n# descriptor bump (semantically inert)\n")
            } else {
                d.clone()
            }
        })
        .collect();
    assert_ne!(
        bumped[0], vendored[0],
        "the bump actually changed the github descriptor bytes"
    );
    let open = |descriptors: Vec<String>| {
        Broker::open(BrokerConfig {
            git: test_quarantine(),
            dir: dir.clone(),
            master_key: vec![5u8; 32],
            action_templates: templates.clone(),
            provider_descriptors: descriptors,
            artifacts: crate::artifacts::ArtifactConfig::default(),
        })
        .unwrap()
    };
    let b1 = open(vendored);
    let b2 = open(bumped);
    (dir, b1, b2)
}

#[test]
fn request_with_bad_path_never_mints_a_grant() {
    // An invalid path denies AT REQUEST TIME — no
    // approvable card, no grant row that a human approval could be burned on.
    let b =
        open_broker_with_templates("providers: {}", vec![TWO_STEP_TEMPLATE.to_string()]).unwrap();
    let out = b
        .request_capability(
            "s1",
            two_step_req(json!({
                "owner": "acme", "name": "website", "branch": "main",
                "path": "../secrets", "payload": "x", "message": "m"
            })),
        )
        .unwrap();
    assert_eq!(
        out.decision,
        Decision::Deny,
        "a bad path must deny: {}",
        out.reason
    );
    assert!(out.grant_id.is_none());
    // No GRANT may freeze (a bad path never mints authority) — but the DENY is now visible in the
    // requests-backed History with its reason, instead of vanishing silently.
    assert!(
        requested_grant_opt(&b).is_none(),
        "no grant row may exist after a bad-path request"
    );
    let hist = b.history().unwrap();
    assert_eq!(hist.len(), 1, "the denied request is visible in history");
    assert_eq!(hist[0].decision, "deny");
    assert!(hist[0].reason.is_some(), "the denial carries its reason");
}

#[test]
fn oversized_content_is_refused_at_request() {
    // An over-cap free-payload string denies before a grant can freeze it.
    let b =
        open_broker_with_templates("providers: {}", vec![TWO_STEP_TEMPLATE.to_string()]).unwrap();
    let big = "x".repeat(256 * 1024 + 1);
    let out = b
        .request_capability(
            "s1",
            two_step_req(json!({
                "owner": "acme", "name": "website", "branch": "main",
                "path": "readme.md", "payload": big, "message": "m"
            })),
        )
        .unwrap();
    assert_eq!(
        out.decision,
        Decision::Deny,
        "oversized content must deny: {}",
        out.reason
    );
    assert!(
        out.reason.contains("payload"),
        "the refusal names the oversized field: {}",
        out.reason
    );
    // No grant froze the oversized payload — but the deny is visible in the request log.
    assert!(requested_grant_opt(&b).is_none(), "no grant row may exist");
    let hist = b.history().unwrap();
    assert_eq!(hist.len(), 1, "the denied request is visible in history");
    assert_eq!(hist[0].decision, "deny");
}

#[test]
fn unregistered_template_action_denied_unsupported() {
    // Per-broker reachability end to end: a broker WITHOUT the template doc treats test_two_step_write as
    // an unsupported action (the name resolves ONLY through a registry that loaded it).
    let b = open_broker_with_templates("providers: {}", vec![]).unwrap();
    let out = b
        .request_capability(
            "s1",
            two_step_req(json!({
                "owner": "acme", "name": "website", "branch": "main",
                "path": "readme.md", "payload": "x", "message": "m"
            })),
        )
        .unwrap();
    assert_eq!(out.decision, Decision::Deny);
    assert!(
        out.reason.contains("unsupported action"),
        "the deny is the unsupported-action refusal: {}",
        out.reason
    );
    // The vocabulary-gap deny names the demand channel: the agent hitting a verb that does
    // not exist is told, at that moment, how to tell the vendor (`request_vocabulary`).
    assert!(
        out.reason.contains("request_vocabulary"),
        "the unsupported-action deny names the vocabulary-request channel: {}",
        out.reason
    );
}

#[test]
fn unregistered_provider_is_denied_at_the_registry_wall_before_policy_evaluate() {
    // Registry wall: since `Policy::evaluate` falls through to `defaults` (an unruled
    // deny) for a provider ABSENT from the policy, the ONLY thing keeping an UNREGISTERED
    // provider from reaching evaluate at all is the broker's registry check (broker.rs request
    // path). An empty policy is the zero-config state — if the wall were gone, this request
    // would reach evaluate and fall to the default deny
    // instead of a hard registry deny. Prove it denies as `unregistered`, never reaching evaluate.
    let b = open_broker_with_templates("{}", vec![]).unwrap();
    let out = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "totally-unknown-provider".into(),
                action: "do_thing".into(),
                resource: json!({ "environment": "production" }),
                environment: Some("production".into()),
                justification: None,
                model: None,
            },
        )
        .unwrap();
    assert_eq!(
        out.decision,
        Decision::Deny,
        "an unregistered provider is denied at the registry wall, not asked: {}",
        out.reason
    );
    assert!(
        out.reason.contains("not registered"),
        "the deny is the registry-wall refusal (never reaches policy evaluate): {}",
        out.reason
    );
    // Same pointer on the registry-wall deny: an unknown PROVIDER is also a vocabulary gap.
    assert!(
        out.reason.contains("request_vocabulary"),
        "the unregistered-provider deny names the vocabulary-request channel: {}",
        out.reason
    );
}

#[test]
fn unregistered_provider_refusal_teaches_authoring() {
    // The miss must teach. An unknown provider is still an `unregistered` deny (class
    // and decision unchanged), but verbs arrive VENDORED — the message now points at the
    // packaged catalog + the `catalog` discovery tool, not the retired `propose_contract`.
    let b = open_broker_with_templates("{}", vec![]).unwrap();
    let out = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "totally-unknown-provider".into(),
                action: "do_thing".into(),
                resource: json!({ "environment": "production" }),
                environment: Some("production".into()),
                justification: None,
                model: None,
            },
        )
        .unwrap();
    assert_eq!(out.decision, Decision::Deny);
    assert!(
        out.reason.contains("not registered"),
        "class unchanged: {}",
        out.reason
    );
    // The `language` tool is retired, so the refusal points at `catalog` alone — and
    // at the zoom that answers "does a standing sentence admit anything like this".
    assert!(
        out.reason.contains("vendored") && out.reason.contains("catalog"),
        "the refusal teaches the vendored-catalog discovery path: {}",
        out.reason
    );
    assert!(
        !out.reason.contains("language"),
        "the refusal must not point at a retired tool: {}",
        out.reason
    );
}

#[test]
fn unsupported_action_refusal_teaches_authoring() {
    // An unknown action on a known provider stays an `unsupported` deny, but the
    // message now points at the vendored catalog + discovery tools (verbs arrive vendored).
    let b = open_broker_with_templates("providers: {}", vec![]).unwrap();
    let out = b
        .request_capability(
            "s1",
            two_step_req(json!({
                "owner": "acme", "name": "website", "branch": "main",
                "path": "readme.md", "payload": "x", "message": "m"
            })),
        )
        .unwrap();
    assert_eq!(out.decision, Decision::Deny);
    assert!(
        out.reason.contains("unsupported action"),
        "class unchanged: {}",
        out.reason
    );
    // The `language` tool is retired, so the refusal points at `catalog` alone — and
    // at the zoom that answers "does a standing sentence admit anything like this".
    assert!(
        out.reason.contains("vendored") && out.reason.contains("catalog"),
        "the refusal teaches the vendored-catalog discovery path: {}",
        out.reason
    );
    assert!(
        !out.reason.contains("language"),
        "the refusal must not point at a retired tool: {}",
        out.reason
    );
}

// ---- Template content is bound into grant validity + the view/gate sweep ----

/// A minimal ratified github template with a body-carried Secret field — used to prove the
/// redaction gate resolves a TEMPLATE contract, never just built-ins.
const SECRET_TEMPLATE: &str = r#"
provider: github
action: set_webhook
fields:
  - { name: owner,          type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: name,           type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: webhook_secret, type: str, required: true, class: secret,   binding: unbound }
consumes: [owner, name, webhook_secret]
execution_targets: [owner, name]
http:
  steps:
    - id: create
      method: POST
      path: /repos/{owner}/{name}/hooks
      body:
        secret: "{webhook_secret}"
"#;

fn set_webhook_req(secret: &str) -> CapabilityRequest {
    CapabilityRequest {
        provider: "github".into(),
        action: "set_webhook".into(),
        resource: json!({ "owner": "acme", "name": "website", "webhook_secret": secret }),
        environment: None,
        justification: None,
        model: None,
    }
}

/// Open TWO brokers over the SAME state dir (the honest restart-with-a-different-doc shape).
fn two_brokers_same_dir(
    policy: &str,
    first: Vec<String>,
    second: Vec<String>,
) -> (PathBuf, Broker, Broker) {
    let (_dir_guard, dir) = fresh_broker_dir();
    let open = |templates: Vec<String>| {
        Broker::open(BrokerConfig {
            git: test_quarantine(),
            dir: dir.clone(),
            master_key: vec![5u8; 32],
            action_templates: templates,
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        })
        .unwrap()
    };
    let b1 = open(first);
    let b2 = open(second);
    (dir, b1, b2)
}

#[test]
fn widening_shape_sees_template_contract() {
    // The widening shaper resolves a TEMPLATE contract's execution
    // targets, not only built-ins.
    let b =
        open_broker_with_templates("providers: {}", vec![TWO_STEP_TEMPLATE.to_string()]).unwrap();
    let contract = b.templates.resolve("github", "test_two_step_write");
    let shape = widening_shape(
        contract,
        "github",
        "test_two_step_write",
        &json!({
            "owner": "acme", "name": "website", "branch": "main",
            "path": "readme.md", "payload": "x", "message": "m"
        }),
    )
    .expect("a template action must be shapeable, not a hard error")
    .expect("a shape for an anchored template action with execution targets");
    for t in ["owner", "name", "branch", "path"] {
        assert!(
            shape.pinned.contains_key(t),
            "template execution target `{t}` must be pinned: {:?}",
            shape.pinned
        );
    }
}

#[test]
fn unratified_template_is_unreachable() {
    // Per-broker reachability, end to end: a broker WITHOUT the doc has no content hash
    // and treats the action as unsupported.
    let b = open_broker_with_templates("providers: {}", vec![]).unwrap();
    assert!(b
        .templates
        .content_hash("github", "test_two_step_write")
        .is_none());
    let out = b
        .request_capability(
            "s1",
            two_step_req(json!({
                "owner": "acme", "name": "website", "branch": "main",
                "path": "readme.md", "payload": "x", "message": "m"
            })),
        )
        .unwrap();
    assert_eq!(out.decision, Decision::Deny);
    assert!(out.reason.contains("unsupported action"));
}

// ---- store-only connect ----

struct IoTrapProvider(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Provider for IoTrapProvider {
    fn name(&self) -> &str {
        "github"
    }

    fn supported_actions(&self) -> &'static [&'static str] {
        &[]
    }

    fn action_contract(&self, _action: &str) -> Option<&'static ActionContract> {
        None
    }

    fn execute(&self, _call: ProviderCall) -> Result<ProviderResponse> {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        panic!("connect touched the provider I/O seam")
    }
}

#[test]
fn connect_vaults_exact_token_without_touching_the_provider_io_seam() {
    let mut b = open_broker("providers:\n  github: {}\n");
    let io_touched = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    b.providers.insert(
        "github".to_string(),
        Box::new(IoTrapProvider(io_touched.clone())),
    );
    let token = "  ghp_exact_token_with_whitespace  \n";

    let out = b
        .connect_credential("github", Some("work"), token)
        .expect("store-only connect succeeds");

    assert!(out.stored);
    assert_eq!(out.provider, "github");
    assert_eq!(out.account_label.as_deref(), Some("work"));
    assert!(!out.replaced);
    assert!(!io_touched.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        b.vault
            .open_secret(&credential_ref("github"))
            .unwrap()
            .expose_secret(),
        token,
        "the vault stores the operator's token byte-identically"
    );
}
// ---- Apply may ADD or NARROW authority, but must never SILENTLY weaken a live deny ----

const ALLOW_DEPLOY: &str = r#"
providers:
  mock-vercel:
    allow:
      - action: deploy
        scope: { environment: preview }
"#;

fn deploy_req() -> CapabilityRequest {
    CapabilityRequest {
        provider: "mock-vercel".into(),
        action: "deploy".into(),
        resource: json!({}),
        environment: Some("preview".into()),
        justification: None,
        model: None,
    }
}

// ---- Aliases: the alias kernel — expand, refuse, and grant NOTHING ────────────

/// A broker whose live policy carries the `push_readme` alias over the real (contracted) github
/// test_two_step_write verb, at the default (unruled ⇒ deny) tier — the seam the smuggling/round-trip tests exercise.
fn broker_with_push_readme_alias() -> TestBroker {
    let policy = r#"
providers:
  github: {}
aliases:
  push_readme:
    provider: github
    action: test_two_step_write
    resource: { owner: acme, name: website, branch: main }
    free: [path, content, message]
"#;
    open_broker_with_templates(policy, vec![TWO_STEP_TEMPLATE.to_string()]).unwrap()
}

fn readme_payload() -> Value {
    json!({ "path": "readme.md", "payload": "hello", "message": "add readme" })
}

/// Discovery: `catalog_listing()` unions the verb catalog with the ACTIVE profile's aliases,
/// so an agent discovers a profile shorthand in the same read that lists the verbs.
/// The agent catalog summary carries pinned field NAMES only — never the operator's
/// pin VALUES (project/customer ids, repo names, paths). A model calling `catalog` must not read
/// operator-custody profile content before any request or approval.
// ---- Request-shape gate BEFORE alias expansion ----
/// A broker whose `env_deploy` alias leaves `environment` on the `free` list — the seam the
/// two-channel collision test needs (both top-level `environment` and `resource.environment`).
fn broker_with_env_free_alias() -> TestBroker {
    let policy = r#"
providers:
  mock-vercel:
    ask:
      - action: deploy
aliases:
  env_deploy:
    provider: mock-vercel
    action: deploy
    resource: {}
    free: [environment]
"#;
    let b = open_broker(policy);
    b.connect_credential("mock-vercel", None, "vc_live_0123456789abcdef")
        .unwrap();
    b
}

// ---- history(): the flat, newest-first grant log across sessions (App History view) ----

#[test]
fn history_lists_all_grants_newest_first_across_sessions() {
    let policy = "providers:\n  mock-vercel:\n    ask:\n      - action: deploy\n";
    let b = open_broker(policy);
    b.connect_credential("mock-vercel", None, "vc_live_0123456789abcdef")
        .unwrap();
    b.request_capability("s1", deploy_req()).unwrap();
    b.request_capability("s2", deploy_req()).unwrap();

    let hist = b.history().unwrap();
    assert_eq!(hist.len(), 2, "history spans every session, not just one");
    let sessions: std::collections::HashSet<String> =
        hist.iter().filter_map(|g| g.session_id.clone()).collect();
    assert!(
        sessions.contains("s1") && sessions.contains("s2"),
        "grants from both sessions appear: {sessions:?}"
    );
    for w in hist.windows(2) {
        assert!(
            w[0].created_at >= w[1].created_at,
            "history is sorted newest-first by created_at"
        );
    }
}

fn req(resource: Value, environment: Option<&str>) -> CapabilityRequest {
    CapabilityRequest {
        provider: "vercel".into(),
        action: "set_env_var".into(),
        resource,
        environment: environment.map(str::to_string),
        justification: None,
        model: None,
    }
}

// ---- canonical_resource: environment fold (single source of truth) ----

#[test]
fn ib_canon_env_fold_25_top_level_environment_folds_into_resource() {
    let r = canonical_resource(&req(json!({ "project": "p" }), Some("preview"))).unwrap();
    assert_eq!(
        r.get("environment").and_then(Value::as_str),
        Some("preview")
    );
}

#[test]
fn ib_canon_env_agree_27_equal_environments_are_not_a_conflict() {
    let r = canonical_resource(&req(json!({ "environment": "preview" }), Some("preview"))).unwrap();
    assert_eq!(
        r.get("environment").and_then(Value::as_str),
        Some("preview")
    );
}

#[test]
fn ib_canon_env_conflict_26_differing_environments_are_rejected() {
    let r = canonical_resource(&req(
        json!({ "environment": "preview" }),
        Some("production"),
    ));
    assert!(
        r.is_err(),
        "a request/resource environment desync must be rejected"
    );
}

#[test]
fn ib_canon_env_conflict_case_13_is_case_sensitive() {
    let r = canonical_resource(&req(json!({ "environment": "Preview" }), Some("preview")));
    assert!(
        r.is_err(),
        "'Preview' must not silently agree with 'preview' (case-sensitive)"
    );
}

#[test]
fn ib_canon_env_nonstring_12_nonstring_existing_environment_is_rejected() {
    let r = canonical_resource(&req(json!({ "environment": 123 }), Some("preview")));
    assert!(
        r.is_err(),
        "a non-string resource.environment must fail closed at the fold"
    );
}

#[test]
fn ib_canon_nonobject_28_non_object_resource_is_rejected() {
    let r = canonical_resource(&req(json!("just-a-string"), Some("preview")));
    assert!(r.is_err(), "a scalar resource must be rejected");
}

#[test]
fn ib_canon_resource_array_15_array_resource_is_rejected() {
    let r = canonical_resource(&req(json!(["website"]), None));
    assert!(r.is_err(), "an array resource must be rejected");
}

#[test]
fn blank_session_fails_closed_at_request() {
    let b = open_broker(ALLOW_DEPLOY);
    b.connect_credential("mock-vercel", None, "vercel_demo_secret_123456789")
        .unwrap();
    assert!(
        matches!(
            b.request_capability("", deploy_req()),
            Err(Error::Denied(_))
        ),
        "an empty server session must fail closed"
    );
    assert!(
        matches!(
            b.request_capability("   ", deploy_req()),
            Err(Error::Denied(_))
        ),
        "a whitespace server session must fail closed"
    );
    let sessions: i64 = b
        .state
        .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        sessions, 0,
        "a denied blank request opens no session (the check precedes ensure_session)"
    );
}

// ---- Server-stamped session lifecycle (provenance + close) ----

#[test]
fn open_session_populates_provenance() {
    let b = open_broker(ALLOW_DEPLOY);
    b.open_session(
        "sess_run1",
        "claude --print",
        Some(4242),
        None,
        SessionActor::default(),
    )
    .unwrap();
    let (agent, pid, status): (Option<String>, Option<i64>, String) = b
        .state
        .query_row(
            "SELECT agent, pid, status FROM sessions WHERE id=?1",
            rusqlite::params!["sess_run1"],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(agent.as_deref(), Some("claude --print"));
    assert_eq!(pid, Some(4242));
    assert_eq!(status, "open");
}

/// The session's SELF-REPORTS round-trip to their own columns, and the ALTER that
/// added them is idempotent — a broker opened twice over the same file finds them already there.
///
/// They are stored in FULL locally. That is the point of the split: the operator's own view keeps
/// what was said, and no authority reads it.
#[test]
fn session_self_reports_round_trip_to_their_own_columns() {
    let b = open_broker(ALLOW_DEPLOY);
    b.open_session(
        "sess_actor",
        "mcp-agent",
        None,
        None,
        SessionActor {
            client_name: Some("claude-code"),
            client_version: Some("1.2.3"),
            model: Some("claude-sonnet-4"),
        },
    )
    .unwrap();
    let (name, version, model): (Option<String>, Option<String>, Option<String>) = b
        .state
        .query_row(
            "SELECT client_name, client_version, agent_model FROM sessions WHERE id=?1",
            rusqlite::params!["sess_actor"],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(name.as_deref(), Some("claude-code"));
    assert_eq!(version.as_deref(), Some("1.2.3"));
    assert_eq!(model.as_deref(), Some("claude-sonnet-4"));

    // Nothing captured stays NULL — "not captured" is a fact the schema keeps, never a placeholder.
    b.open_session(
        "sess_quiet",
        "mcp-agent",
        None,
        None,
        SessionActor::default(),
    )
    .unwrap();
    let absent: Option<String> = b
        .state
        .query_row(
            "SELECT client_name FROM sessions WHERE id=?1",
            rusqlite::params!["sess_quiet"],
            |r| r.get(0),
        )
        .unwrap();
    assert!(absent.is_none());
}

/// The self-reports get the SAME de-fanging as the agent label, for the same reason: every one is
/// written by a party we did not build and lands in a database an operator reads. A terminal escape
/// in `clientInfo.name` must not survive ingestion.
#[test]
fn session_self_reports_are_control_stripped_at_ingestion() {
    let b = open_broker(ALLOW_DEPLOY);
    b.open_session(
        "sess_evil_actor",
        "mcp-agent",
        None,
        None,
        SessionActor {
            client_name: Some("evil\x1b[2J\x07code\r\n"),
            client_version: Some("1\x1b[31m.0"),
            model: Some("claude\u{009b}31m-4"),
        },
    )
    .unwrap();
    let (name, version, model): (String, String, String) = b
        .state
        .query_row(
            "SELECT client_name, client_version, agent_model FROM sessions WHERE id=?1",
            rusqlite::params!["sess_evil_actor"],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    for stored in [&name, &version, &model] {
        assert!(
            !stored.chars().any(|c| c.is_control()),
            "a control character survived ingestion: {stored:?}"
        );
    }
    assert_eq!(name, "evil[2Jcode");
}

#[test]
fn agent_label_is_control_stripped_and_capped_at_ingestion() {
    // The label is client-supplied (CERMET_AGENT_NAME via Hello): terminal escapes must never
    // persist, so no render surface — CLI text, HTML, SPA — can be steered by an agent name.
    let b = open_broker(ALLOW_DEPLOY);
    b.open_session(
        "sess_evil",
        "evil\x1b[2J\x07agent\u{009b}31mname\r\n",
        None,
        None,
        SessionActor::default(),
    )
    .unwrap();
    let agent: Option<String> = b
        .state
        .query_row(
            "SELECT agent FROM sessions WHERE id=?1",
            rusqlite::params!["sess_evil"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(agent.as_deref(), Some("evil[2Jagent31mname"));

    let long = "a".repeat(4096);
    b.open_session("sess_long", &long, None, None, SessionActor::default())
        .unwrap();
    let agent: Option<String> = b
        .state
        .query_row(
            "SELECT agent FROM sessions WHERE id=?1",
            rusqlite::params!["sess_long"],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(agent.map(|a| a.chars().count()), Some(128));
}

#[test]
fn open_session_blank_fails_closed() {
    let b = open_broker(ALLOW_DEPLOY);
    assert!(
        matches!(
            b.open_session("  ", "claude", None, None, SessionActor::default()),
            Err(Error::Denied(_))
        ),
        "a blank session must not be openable"
    );
    let sessions: i64 = b
        .state
        .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(sessions, 0, "a blank open opens no session");
}

#[test]
fn close_session_sets_ended_and_status() {
    let b = open_broker(ALLOW_DEPLOY);
    b.open_session("sess_run1", "claude", None, None, SessionActor::default())
        .unwrap();
    b.close_session("sess_run1").unwrap();
    let (ended, status): (Option<String>, String) = b
        .state
        .query_row(
            "SELECT ended_at, status FROM sessions WHERE id=?1",
            rusqlite::params!["sess_run1"],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(ended.is_some(), "close stamps ended_at");
    assert_eq!(status, "closed");
}

#[test]
fn open_session_creates_no_grant() {
    let b = open_broker(ALLOW_DEPLOY);
    b.open_session(
        "sess_run1",
        "claude",
        Some(1),
        None,
        SessionActor::default(),
    )
    .unwrap();
    assert!(b.list_grants("sess_run1").unwrap().is_empty());
}

#[test]
fn session_open_reports_live_open_and_closed_and_unknown() {
    let b = open_broker(ALLOW_DEPLOY);
    b.open_session("sess_live", "claude", None, None, SessionActor::default())
        .unwrap();
    assert!(
        b.session_open("sess_live").unwrap(),
        "a freshly opened session is open"
    );
    assert!(
        !b.session_open("sess_ghost").unwrap(),
        "an unknown id is not open (fail closed)"
    );
    b.close_session("sess_live").unwrap();
    assert!(
        !b.session_open("sess_live").unwrap(),
        "a closed session is no longer open — the daemon must refuse its id"
    );
}

// ---- "What policy next time": suggest least-privilege rules ----

// The `deploy` / `create_project` built-ins are no longer registered, but the suggestion
// shaper and the exhaustive matcher tests below need a contract shape that exercises every
// field-class × binding combination — a required Identity pin that is NOT an execution target
// (`repo_id`), a FreePayload (`ref`), and a SideEffect pin (`build_command`) — which no surviving
// vercel contract carries. FakeVercel therefore serves these RETIRED shapes as self-contained
// test fixtures (the broker resolves a directly-inserted provider's contract via
// `Provider::action_contract`), preserving the matcher/suggestion coverage the drop would lose.
// `set_env_var` and `deploy` are template-owned, so FakeVercel delegates them to its registry.
const FAKE_DEPLOY_PREVIEW: ActionContract = ActionContract {
    provider: "vercel",
    action: "deploy",
    schema: &[
        FieldDecl {
            name: "project",
            ty: ScalarKind::Str,
            required: true,
            class: FieldClass::Identity,
            binding: AllowBinding::ExactResourcePin,
        },
        FieldDecl {
            name: "repo_id",
            ty: ScalarKind::Int,
            required: true,
            class: FieldClass::Identity,
            binding: AllowBinding::ExactResourcePin,
        },
        FieldDecl {
            name: "ref",
            ty: ScalarKind::Str,
            required: true,
            class: FieldClass::FreePayload,
            binding: AllowBinding::Unbound,
        },
        FieldDecl {
            name: "framework",
            ty: ScalarKind::Str,
            required: false,
            class: FieldClass::FreePayload,
            binding: AllowBinding::Unbound,
        },
        FieldDecl {
            name: "environment",
            ty: ScalarKind::Str,
            required: false,
            class: FieldClass::FreePayload,
            binding: AllowBinding::Unbound,
        },
        FieldDecl {
            name: "build_command",
            ty: ScalarKind::Str,
            required: false,
            class: FieldClass::SideEffect,
            binding: AllowBinding::ExactResourcePin,
        },
        FieldDecl {
            name: "install_command",
            ty: ScalarKind::Str,
            required: false,
            class: FieldClass::SideEffect,
            binding: AllowBinding::ExactResourcePin,
        },
        FieldDecl {
            name: "root_directory",
            ty: ScalarKind::Str,
            required: false,
            class: FieldClass::SideEffect,
            binding: AllowBinding::ExactResourcePin,
        },
    ],
    consumes: &[
        "project",
        "repo_id",
        "ref",
        "framework",
        "build_command",
        "install_command",
        "root_directory",
    ],
    execution_targets: &["project"],
    relations: &[],
    open: false,
};
const FAKE_CREATE_PROJECT: ActionContract = ActionContract {
    provider: "vercel",
    action: "create_project",
    schema: &[
        FieldDecl {
            name: "name",
            ty: ScalarKind::Str,
            required: true,
            class: FieldClass::Identity,
            binding: AllowBinding::ExactResourcePin,
        },
        FieldDecl {
            name: "framework",
            ty: ScalarKind::Str,
            required: false,
            class: FieldClass::FreePayload,
            binding: AllowBinding::Unbound,
        },
    ],
    consumes: &["name", "framework"],
    execution_targets: &[],
    relations: &[],
    open: false,
};

struct FakeVercel {
    ok: bool,
    // The broker's own registry, so `deploy` (and the live `set_env_var`) resolve here exactly as
    // the broker's contract source resolves them — a directly-inserted provider whose evaluate
    // contract agrees with what policy validation and the suggestion round-trip see.
    templates: Arc<TemplateRegistry>,
}
impl FakeVercel {
    fn new(ok: bool, templates: Arc<TemplateRegistry>) -> Self {
        Self { ok, templates }
    }
}
impl Provider for FakeVercel {
    fn name(&self) -> &str {
        "vercel"
    }
    fn supported_actions(&self) -> &'static [&'static str] {
        &["deploy", "create_project", "set_env_var", "deploy"]
    }
    fn action_contract(&self, action: &str) -> Option<&'static crate::contract::ActionContract> {
        match action {
            "deploy" => Some(&FAKE_DEPLOY_PREVIEW),
            "create_project" => Some(&FAKE_CREATE_PROJECT),
            // `deploy` and `set_env_var` are template-owned — resolve them through the registry.
            _ => self.templates.resolve("vercel", action),
        }
    }
    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        debug_assert!(
            !call.token.is_empty(),
            "the broker must inject the credential"
        );
        Ok(ProviderResponse {
            proof: None,
            ok: self.ok,
            failure_class: None,
            result: json!({ "url": "https://x.example", "id": "dpl_1" }),
            retained: None,
            envelope: Default::default(),
        })
    }
}

fn open_broker_fake_vercel(policy: &str, ok: bool) -> TestBroker {
    let mut b = open_broker(policy);
    let templates = b.templates.clone();
    b.providers.insert(
        "vercel".to_string(),
        Box::new(FakeVercel::new(ok, templates)),
    );
    b
}

const VERCEL_ASK_DEPLOY: &str = r#"
providers:
  vercel:
    ask:
      - action: deploy
"#;

fn vercel_deploy_req(project: &str, git_ref: &str) -> CapabilityRequest {
    CapabilityRequest {
        provider: "vercel".into(),
        action: "deploy".into(),
        resource: json!({ "project": project, "repo_id": 123, "ref": git_ref, "framework": "nextjs" }),
        environment: Some("preview".into()),
        justification: None,
        model: None,
    }
}

fn requested_grant(b: &Broker) -> String {
    b.state
        .query_row(
            "SELECT id FROM grants WHERE status='requested' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

/// Any grant row at all (a denial mints a `requests` row but never a grant — this proves the
/// grants table stayed empty).
fn requested_grant_opt(b: &Broker) -> Option<String> {
    b.state
        .query_row("SELECT id FROM grants LIMIT 1", [], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .unwrap()
}

struct V2M1FakeStripe {
    templates: Arc<TemplateRegistry>,
    calls: Arc<std::sync::Mutex<usize>>,
}

impl Provider for V2M1FakeStripe {
    fn name(&self) -> &str {
        "stripe"
    }

    fn supported_actions(&self) -> &'static [&'static str] {
        &["refund"]
    }

    fn action_contract(&self, action: &str) -> Option<&'static crate::contract::ActionContract> {
        self.templates.resolve("stripe", action)
    }

    fn requires_credential(&self) -> bool {
        false
    }

    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        *self.calls.lock().unwrap() += 1;
        assert_eq!(call.action, "refund");
        assert_eq!(call.resource.get_i64("amount"), Some(2300));
        Ok(ProviderResponse {
            proof: None,
            ok: true,
            failure_class: None,
            result: json!({"id": "re_m1", "amount": 2300, "status": "succeeded"}),
            retained: None,
            envelope: Default::default(),
        })
    }
}

fn install_v2_m1_fake_stripe(broker: &mut Broker) -> Arc<std::sync::Mutex<usize>> {
    let calls = Arc::new(std::sync::Mutex::new(0));
    broker.providers.insert(
        "stripe".into(),
        Box::new(V2M1FakeStripe {
            templates: broker.templates.clone(),
            calls: calls.clone(),
        }),
    );
    calls
}

// A credential-REQUIRING stripe whose `execute` always errors AFTER the adapter is invoked — used
// by the release-classification tests. With no credential enrolled, `open_secret`
// fails BEFORE `execute` (pre-invocation); with one enrolled, `execute` is invoked and returns Err.
struct V2M1CredStripe {
    templates: Arc<TemplateRegistry>,
    invoked: Arc<std::sync::atomic::AtomicBool>,
}

impl Provider for V2M1CredStripe {
    fn name(&self) -> &str {
        "stripe"
    }
    fn supported_actions(&self) -> &'static [&'static str] {
        &["refund"]
    }
    fn action_contract(&self, action: &str) -> Option<&'static crate::contract::ActionContract> {
        self.templates.resolve("stripe", action)
    }
    fn requires_credential(&self) -> bool {
        true
    }
    fn execute(&self, _call: ProviderCall) -> Result<ProviderResponse> {
        self.invoked
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Err(crate::error::Error::Denied(
            "provider failed AFTER invocation".into(),
        ))
    }
}

fn budget_broker_cred(
    dir: &std::path::Path,
    rules: crate::sentence::RuleSet,
) -> (Broker, Arc<std::sync::atomic::AtomicBool>) {
    let mut rules = rules;
    crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
    let source = Arc::new(V2M1SentenceAuthority::new(rules));
    let mut broker = open_broker_reuse_with_sentence_authority(dir, "providers: {}", source);
    let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    broker.providers.insert(
        "stripe".into(),
        Box::new(V2M1CredStripe {
            templates: broker.templates.clone(),
            invoked: invoked.clone(),
        }),
    );
    (broker, invoked)
}

struct V2ShapeStripe {
    templates: Arc<TemplateRegistry>,
    calls: Arc<std::sync::Mutex<usize>>,
}

impl Provider for V2ShapeStripe {
    fn name(&self) -> &str {
        "stripe"
    }

    fn supported_actions(&self) -> &'static [&'static str] {
        &[
            "shape_refund",
            "shape_environment",
            "shape_secret_environment",
            "symbolic_eight",
        ]
    }

    fn action_contract(&self, action: &str) -> Option<&'static crate::contract::ActionContract> {
        self.templates.resolve("stripe", action)
    }

    fn requires_credential(&self) -> bool {
        false
    }

    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        if call.action == "shape_secret_environment" {
            assert_eq!(
                call.resource.get_str("environment"),
                Some("provider_secret_value")
            );
            return Ok(ProviderResponse {
                proof: None,
                ok: true,
                failure_class: None,
                result: json!({"id": "safe_projected_result"}),
                retained: None,
                envelope: Default::default(),
            });
        }
        assert_eq!(call.action, "shape_refund");
        assert_eq!(call.resource.get_str("note"), Some("safe"));
        let mut calls = self.calls.lock().unwrap();
        *calls += 1;
        Ok(ProviderResponse {
            proof: None,
            ok: *calls > 1,
            failure_class: None,
            result: json!({"id": "re_shape", "attempt": *calls}),
            retained: None,
            envelope: Default::default(),
        })
    }
}

fn install_v2_shape_stripe(broker: &mut Broker) -> Arc<std::sync::Mutex<usize>> {
    let calls = Arc::new(std::sync::Mutex::new(0));
    broker.providers.insert(
        "stripe".into(),
        Box::new(V2ShapeStripe {
            templates: broker.templates.clone(),
            calls: calls.clone(),
        }),
    );
    calls
}

enum V2M1SentenceAuthorityState {
    Rules(crate::sentence::RuleSet),
    Failed(String),
}

struct V2M1SentenceAuthority {
    state: std::sync::Mutex<V2M1SentenceAuthorityState>,
}

impl V2M1SentenceAuthority {
    fn new(rules: crate::sentence::RuleSet) -> Self {
        Self {
            state: std::sync::Mutex::new(V2M1SentenceAuthorityState::Rules(rules)),
        }
    }

    fn activate(&self, rules: crate::sentence::RuleSet) {
        *self.state.lock().unwrap() = V2M1SentenceAuthorityState::Rules(rules);
    }

    fn fail(&self, message: &str) {
        *self.state.lock().unwrap() = V2M1SentenceAuthorityState::Failed(message.into());
    }
}

impl SentenceAuthoritySource for V2M1SentenceAuthority {
    fn current_authority(&self) -> Result<AuthenticatedSentenceAuthority> {
        match &*self.state.lock().unwrap() {
            V2M1SentenceAuthorityState::Rules(rules) => Ok(AuthenticatedSentenceAuthority {
                digest: crate::sentence::authority_digest(rules),
                rules: rules.clone(),
            }),
            V2M1SentenceAuthorityState::Failed(message) => Err(Error::Denied(message.clone())),
        }
    }
}

struct SequencedSentenceAuthority {
    snapshots: std::sync::Mutex<std::collections::VecDeque<crate::sentence::RuleSet>>,
}

impl SequencedSentenceAuthority {
    fn new(snapshots: Vec<crate::sentence::RuleSet>) -> Self {
        Self {
            snapshots: std::sync::Mutex::new(snapshots.into()),
        }
    }
}

impl SentenceAuthoritySource for SequencedSentenceAuthority {
    fn current_authority(&self) -> Result<AuthenticatedSentenceAuthority> {
        let mut snapshots = self.snapshots.lock().unwrap();
        let rules = if snapshots.len() > 1 {
            snapshots.pop_front().unwrap()
        } else {
            snapshots
                .front()
                .cloned()
                .ok_or_else(|| Error::Denied("no sentence snapshot".into()))?
        };
        Ok(AuthenticatedSentenceAuthority {
            digest: crate::sentence::authority_digest(&rules),
            rules,
        })
    }
}

struct DigestOverrideSentenceAuthority {
    rules: crate::sentence::RuleSet,
    digest: std::sync::Mutex<String>,
}

impl DigestOverrideSentenceAuthority {
    fn new(rules: crate::sentence::RuleSet, digest: String) -> Self {
        Self {
            rules,
            digest: std::sync::Mutex::new(digest),
        }
    }

    fn set_digest(&self, digest: String) {
        *self.digest.lock().unwrap() = digest;
    }
}

impl SentenceAuthoritySource for DigestOverrideSentenceAuthority {
    fn current_authority(&self) -> Result<AuthenticatedSentenceAuthority> {
        Ok(AuthenticatedSentenceAuthority {
            rules: self.rules.clone(),
            digest: self.digest.lock().unwrap().clone(),
        })
    }
}

fn open_broker_reuse_with_sentence_authority(
    dir: &std::path::Path,
    policy: &str,
    source: Arc<dyn SentenceAuthoritySource>,
) -> Broker {
    Broker::open_for_semantic_test(
        BrokerConfig {
            git: test_quarantine(),
            dir: dir.to_path_buf(),
            master_key: vec![5u8; 32],
            action_templates: catalog(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        Some(source),
    )
    .unwrap()
}

fn open_broker_with_sentence_authority_and_templates(
    policy: &str,
    source: Arc<dyn SentenceAuthoritySource>,
    action_templates: Vec<String>,
) -> TestBroker {
    let (guard, dir) = fresh_broker_dir();
    let broker = Broker::open_for_semantic_test(
        BrokerConfig {
            git: test_quarantine(),
            dir,
            master_key: vec![5u8; 32],
            action_templates,
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        Some(source),
    )
    .unwrap();
    TestBroker::new(guard, broker)
}

fn v2_m1_refund_request(charge: &str) -> CapabilityRequest {
    v2_m1_refund_request_at(charge, 2300)
}

fn v2_m1_refund_request_at(charge: &str, amount: i64) -> CapabilityRequest {
    CapabilityRequest {
        provider: "stripe".into(),
        action: "refund".into(),
        resource: json!({"charge": charge, "amount": amount}),
        environment: None,
        justification: None,
        model: None,
    }
}

fn v2_m1_rules_fingerprint(rules: &crate::sentence::RuleSet) -> String {
    crate::sentence::authority_digest(rules)
}

fn v2_m1_grant_count(broker: &Broker) -> i64 {
    broker
        .state
        .query_row("SELECT COUNT(*) FROM grants", [], |row| row.get(0))
        .unwrap()
}

fn v2_m4_insert_legacy_stripe_grant(
    broker: &Broker,
    id: &str,
    session: &str,
    status: GrantStatus,
    provenance: &str,
) -> String {
    let request_id = format!("req_{id}");
    let req = v2_m1_refund_request(&format!("ch_{id}"));
    let resource = broker
        .providers
        .get("stripe")
        .unwrap()
        .canonicalize("refund", &req.resource)
        .unwrap();
    broker.ensure_session(session, None).unwrap();
    broker
        .insert_grant(
            id,
            &request_id,
            session,
            &req,
            &resource,
            &EvidenceEnvelope::none().to_canonical_json(),
            &crate::money::MoneyMetadata::none().to_canonical_json(),
            status,
            Decision::Allow,
            Some("uid:legacy-agent"),
            "legacy-authority",
            None,
        )
        .unwrap();
    let mut grant = broker.load_grant(id).unwrap();
    grant.approved_by_kind = Some(provenance.into());
    grant.approver = (provenance == "human").then(|| "uid:legacy-human".into());
    let digest = broker.redigest(id, &grant, status_str(status));
    broker
        .state
        .execute(
            "UPDATE grants SET approved_by_kind=?2, approver=?3, grant_digest=?4 WHERE id=?1",
            rusqlite::params![id, provenance, grant.approver, digest],
        )
        .unwrap();
    let grant = broker.load_grant(id).unwrap();
    broker.assert_grant_integrity(id, &grant).unwrap();
    request_id
}

/// The ONE set spelling the current dialect admits: a set is named by its immutable expansion
/// digest, because the bare dotted form is now the verb and the `word:` prefix namespace is
/// reserved. Test fixtures that mean a SET build their text through here.
fn pinned_set(provider: &str, set: &str) -> String {
    use crate::sets::SetResolver as _;
    let snapshot = crate::sets::VendoredSetResolver
        .current_snapshot(provider, set)
        .expect("a vendored set");
    format!("{provider}.{set}@{}", snapshot.digest())
}

fn v2_m1_rules_with_limit(limit: i64) -> crate::sentence::RuleSet {
    let mut rules =
        crate::sentence::parse_rules(&format!("allow stripe.refund where amount <= {limit}"))
            .unwrap();
    crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
    rules
}
/// The authority join must tell DENY truths too. Three shapes in one corpus: an explicit
/// deny (a standing rule EXISTS and no widening hint is possible — `evaluate_with_widen_hint`
/// yields None for it by design), a carve-out deny that narrows a live allow, and a verb no rule
/// mentions. Joining only ALLOW rules would make the first read as "no standing rule" and hide the
/// second entirely.
#[test]
fn catalog_listing_names_deny_rules_and_carve_outs() {
    let mut rules = crate::sentence::parse_rules(&format!(
        "allow {}\n\
         deny stripe.list_charges\n\
         allow github.read_repo where owner = \"acme\"\n\
         deny github.read_repo where name = \"secrets\"",
        pinned_set("stripe", "read")
    ))
    .unwrap();
    crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = sentence_broker(&dir, Arc::new(V2M1SentenceAuthority::new(rules)));
    let listing = broker.catalog_listing().unwrap();
    let entry = |provider: &str, action: &str| {
        listing
            .catalog
            .iter()
            .find(|e| e.provider == provider && e.action == action)
            .unwrap_or_else(|| panic!("{provider}.{action} is in the catalog"))
    };

    // (1) EXPLICIT DENY over a set allow: a standing rule exists and it is a deny. Not an
    // authority gap, and not a widening candidate.
    let list_charges = entry("stripe", "list_charges");
    assert!(list_charges.sentence_denied);
    assert_eq!(
        list_charges.denied_by,
        vec!["deny stripe.list_charges".to_string()]
    );
    assert!(
        !list_charges.admitted_by.is_empty(),
        "the set allow still selects it — the deny is what wins, and both are reported"
    );

    // (2) CARVE-OUT: the allow is live, the deny narrows it. Both must render.
    let read_repo = entry("github", "read_repo");
    assert!(!read_repo.sentence_denied, "some request still lands");
    assert_eq!(
        read_repo.admitted_by,
        vec!["allow github.read_repo where owner = \"acme\"".to_string()]
    );
    assert_eq!(
        read_repo.denied_by,
        vec!["deny github.read_repo where name = \"secrets\"".to_string()],
        "a carve-out is part of the verb's authority and may not be dropped"
    );

    // (3) UNRULED: no rule of either effect mentions it — the one real widening candidate.
    let create_issue = entry("github", "create_issue");
    assert!(create_issue.admitted_by.is_empty() && create_issue.denied_by.is_empty());
    assert!(create_issue.sentence_denied);
}

fn representative_requests() -> Vec<CapabilityRequest> {
    vec![
        CapabilityRequest {
            provider: "github".into(),
            action: "read_repo".into(),
            resource: json!({"owner": "acme", "name": "widget"}),
            ..Default::default()
        },
        CapabilityRequest {
            provider: "stripe".into(),
            action: "get_charge".into(),
            resource: json!({"charge": "ch_m4"}),
            ..Default::default()
        },
    ]
}
fn universal_rules() -> crate::sentence::RuleSet {
    crate::sentence::parse_rules(
        "allow github.read_repo\n\
             allow stripe.get_charge",
    )
    .unwrap()
}
fn sentence_broker(dir: &std::path::Path, source: Arc<dyn SentenceAuthoritySource>) -> Broker {
    open_broker_reuse_with_sentence_authority(dir, "providers: {}", source)
}

/// The discovery listing NAMES the standing sentence that admits each verb — numbered as
/// `cermet rules` numbers it, bounds included — and a SET-selector rule admits every member through
/// the existing set machinery. Without this join the agent surface can only say "requestable",
/// forcing an agent to hand-cross-join the full catalog against the rule list. An unruled verb
/// carries no admission and stays sentence-denied.
#[test]
fn catalog_listing_names_the_admitting_sentence_for_verb_and_set_rules() {
    let mut rules = crate::sentence::parse_rules(&format!(
        "allow github.read_repo where owner = \"acme\" and name = \"widget\"\n\
         allow {}",
        pinned_set("stripe", "read")
    ))
    .unwrap();
    crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = sentence_broker(&dir, Arc::new(V2M1SentenceAuthority::new(rules)));
    let listing = broker.catalog_listing().unwrap();
    let entry = |provider: &str, action: &str| {
        listing
            .catalog
            .iter()
            .find(|e| e.provider == provider && e.action == action)
            .unwrap_or_else(|| panic!("{provider}.{action} is in the catalog"))
    };

    let read_repo = entry("github", "read_repo");
    assert!(!read_repo.sentence_denied);
    // NO rule numbers on the agent surface — positional identity is fragile.
    // The sentence text IS the name, bounds included.
    assert_eq!(
        read_repo.admitted_by,
        vec!["allow github.read_repo where owner = \"acme\" and name = \"widget\"".to_string()],
        "the admitting sentence is named by its text and its bounds"
    );

    // A set selector admits every member: the member verb names the SET sentence, digest and all.
    let get_charge = entry("stripe", "get_charge");
    assert!(!get_charge.sentence_denied);
    assert!(
        get_charge.admitted_by[0].starts_with("allow stripe.read@sha256:"),
        "a set-admitted verb names the pinned set sentence, got {:?}",
        get_charge.admitted_by[0]
    );

    // Neither rule selects this one: no admission, and the existing discoverability bit agrees.
    let create_issue = entry("github", "create_issue");
    assert!(create_issue.admitted_by.is_empty());
    assert!(create_issue.sentence_denied);
    // A non-member of the set is not admitted by it either.
    assert!(entry("stripe", "refund").admitted_by.is_empty());
}
#[test]
fn every_provider_uses_sentence_authority_and_emits_complete_pre_effect_evidence() {
    let requests = representative_requests();
    let absent = open_broker("providers: {}");
    for (index, request) in requests.iter().cloned().enumerate() {
        let outcome = absent
            .request_capability(&format!("absent-{index}"), request)
            .unwrap();
        assert_eq!(outcome.decision, Decision::Deny);
        assert!(outcome.grant_id.is_none());
    }
    let unmatched_rules = crate::sentence::parse_rules("allow stripe.get_subscription").unwrap();
    let unmatched_source = Arc::new(V2M1SentenceAuthority::new(unmatched_rules));
    let (_unmatched_dir_guard, unmatched_dir) = fresh_broker_dir();
    let unmatched = sentence_broker(&unmatched_dir, unmatched_source);
    for (index, request) in requests.iter().cloned().enumerate() {
        let outcome = unmatched
            .request_capability(&format!("unmatched-{index}"), request)
            .unwrap();
        assert_eq!(outcome.decision, Decision::Deny);
        assert!(outcome.grant_id.is_none());
    }
    let failed_source = Arc::new(V2M1SentenceAuthority::new(universal_rules()));
    failed_source.fail("served generation unavailable");
    let (_failed_dir_guard, failed_dir) = fresh_broker_dir();
    let failed = sentence_broker(&failed_dir, failed_source);
    for (index, request) in requests.iter().cloned().enumerate() {
        let outcome = failed
            .request_capability(&format!("unserved-{index}"), request)
            .unwrap();
        assert_eq!(outcome.decision, Decision::Deny);
        assert!(outcome.grant_id.is_none());
    }
    let rules = universal_rules();
    let authority_digest = crate::sentence::authority_digest(&rules);
    let source = Arc::new(V2M1SentenceAuthority::new(rules));
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = sentence_broker(&dir, source);
    let listing = broker.catalog_listing().unwrap();
    for request in &requests {
        let entry = listing
            .catalog
            .iter()
            .find(|entry| entry.provider == request.provider && entry.action == request.action)
            .unwrap();
        assert!(
            !entry.sentence_denied,
            "{}.{} must be sentence-discoverable",
            request.provider, request.action
        );
    }
    assert!(
        listing
            .catalog
            .iter()
            .find(|entry| entry.provider == "github" && entry.action == "create_issue")
            .unwrap()
            .sentence_denied,
        "an unmatched verb must not be advertised as sentence-authorized"
    );
    let mut handles = Vec::new();
    for (index, request) in requests.iter().cloned().enumerate() {
        let outcome = broker
            .request_capability(&format!("allow-{index}"), request.clone())
            .unwrap();
        assert_eq!(
            outcome.decision,
            Decision::Allow,
            "{}.{}",
            request.provider,
            request.action
        );
        assert_eq!(outcome.authority_kind, Some(AuthorityKind::Sentence));
        let grant_id = outcome.grant_id.unwrap();
        let grant = broker.load_grant(&grant_id).unwrap();
        assert_eq!(grant.approved_by_kind.as_deref(), Some("sentence"));
        assert_eq!(grant.policy_fingerprint, authority_digest);
        handles.push((outcome.request_id, request));
    }
    for (request_id, _) in &handles {
        let _ = broker.execute_request_for_principal_attributed(
            request_id,
            LOCAL_REQUESTER,
            &ExecAttribution::default(),
        );
    }
    let effects = broker
        .audit
        .events_of_type("capability_effect_starting")
        .unwrap();
    assert_eq!(
        effects.len(),
        requests.len(),
        "every execution kind emits pre-effect evidence"
    );
    let effect = |provider: &str| {
        &effects
            .iter()
            .find(|event| event.data["provider"] == json!(provider))
            .unwrap()
            .data["resource"]
    };
    assert_eq!(
        effect("github"),
        &json!({"owner": "acme", "name": "widget"})
    );
    assert_eq!(effect("stripe"), &json!({"charge": "ch_m4"}));
}
#[test]
fn sentence_provenance_guard_refuses_forged_survivors_for_every_provider() {
    let requests = representative_requests();
    let source = Arc::new(V2M1SentenceAuthority::new(universal_rules()));
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = sentence_broker(&dir, source);
    let mut handles = Vec::new();
    for (index, request) in requests.iter().cloned().enumerate() {
        let outcome = broker
            .request_capability(&format!("forged-{index}"), request)
            .unwrap();
        let grant_id = outcome.grant_id.unwrap();
        let mut grant = broker.load_grant(&grant_id).unwrap();
        grant.approved_by_kind = Some("policy".into());
        let digest = broker.redigest(&grant_id, &grant, "approved");
        broker
            .state
            .execute(
                "UPDATE grants SET approved_by_kind='policy', grant_digest=?2 WHERE id=?1",
                rusqlite::params![grant_id, digest],
            )
            .unwrap();
        handles.push(outcome.request_id);
    }
    for request_id in handles {
        let error = broker
            .execute_request_for_principal_attributed(
                &request_id,
                LOCAL_REQUESTER,
                &ExecAttribution::default(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("sentence provenance"), "{error}");
    }
    assert!(broker
        .audit
        .events_of_type("capability_effect_starting")
        .unwrap()
        .is_empty());
    assert_eq!(
        broker
            .audit
            .events_of_type("capability_execution_refused")
            .unwrap()
            .len(),
        requests.len()
    );
}
#[test]
fn boot_terminalizes_unclaimed_legacy_grants_with_authenticated_evidence() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let source = Arc::new(V2M1SentenceAuthority::new(v2_m1_rules_with_limit(5000)));
    let broker = sentence_broker(&dir, source.clone());
    let approved_request = v2_m4_insert_legacy_stripe_grant(
        &broker,
        "grant_m4_legacy_approved",
        "legacy-approved",
        GrantStatus::Approved,
        "policy",
    );
    let requested_request = v2_m4_insert_legacy_stripe_grant(
        &broker,
        "grant_m4_legacy_requested",
        "legacy-requested",
        GrantStatus::Requested,
        "human",
    );
    drop(broker);
    let reopened = sentence_broker(&dir, source);
    for request_id in [approved_request, requested_request] {
        let view = reopened.request_status(&request_id).unwrap();
        assert_eq!(view.status, "terminal");
        assert_eq!(view.outcome.as_deref(), Some("abandoned"));
    }
    let events = reopened
        .audit
        .events_of_type("authority_cutover_terminalized")
        .unwrap();
    assert_eq!(events.len(), 2);
    assert!(events
        .iter()
        .all(|event| event.data["mutation_invoked"] == json!(false)));
    assert!(events
        .iter()
        .all(|event| event.data["prior_authority_kind"] != json!("sentence")));
}
// Build a stripe broker whose sentence authority is exactly `rules`, with the fake refund
// provider installed. Shared by the budget-gate tests below.
fn budget_broker(dir: &std::path::Path, rules: crate::sentence::RuleSet) -> Broker {
    let mut rules = rules;
    crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
    let source = Arc::new(V2M1SentenceAuthority::new(rules));
    let mut broker = open_broker_reuse_with_sentence_authority(dir, "providers: {}", source);
    install_v2_m1_fake_stripe(&mut broker);
    broker
}

fn budget_rules(text: &str) -> crate::sentence::RuleSet {
    crate::sentence::parse_rules(text).unwrap()
}

#[test]
fn operator_evidence_is_verified_redacted_and_fails_closed() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000"),
    );
    let outcome = broker
        .request_capability("m7-evidence", v2_m1_refund_request("ch_m7_evidence"))
        .unwrap();
    let grant_id = outcome.grant_id.clone().expect("allowed request");
    broker.execute_capability(&grant_id).unwrap();

    let evidence = broker.evidence(&outcome.request_id).unwrap();
    assert_eq!(evidence.request_id, outcome.request_id);
    assert_eq!(evidence.grant_id, grant_id);
    assert_eq!(evidence.provider, "stripe");
    assert_eq!(evidence.action, "refund");
    assert!(evidence.integrity_ok);
    assert_eq!(evidence.resource["charge"], json!("ch_m7_evidence"));
    assert_eq!(evidence.events.len(), 2);
    assert_eq!(evidence.events[0].event_type, "capability_effect_starting");
    assert!(evidence.events[0].resource_binding.is_some());
    assert_eq!(evidence.events[1].event_type, "provider_action_succeeded");
    assert_eq!(evidence.events[1].result["id"], json!("re_m1"));
    assert!(serde_json::to_string(&evidence)
        .unwrap()
        .find("idempotency")
        .is_none());

    assert!(matches!(
        broker.evidence("req_ffffffffffffffff"),
        Err(Error::NotFound(_))
    ));
    broker.audit.tamper_first_event_for_test().unwrap();
    assert!(matches!(
        broker.evidence(&outcome.request_id),
        Err(Error::Integrity(_))
    ));
}

/// `request_id` is the ONE public id. The operator execute must not take the
/// operator-internal `grant_id`, or a single authorized action carries two ids and the operator
/// has to know which surface takes which (`evidence` takes one, `execute` the other). The kernel
/// already maps request→grant 1:1, so the operator path resolves it and the grant id stops being
/// an input anywhere.
#[test]
fn the_operator_executes_by_request_id_and_a_denial_refuses_cleanly() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000"),
    );
    let allowed = broker
        .request_capability("exec_by_id", v2_m1_refund_request("ch_exec_by_id"))
        .unwrap();
    let receipt = broker
        .execute_capability_by_request_id(&allowed.request_id)
        .expect("the request id executes its own grant");
    assert!(receipt.ok);
    assert_eq!(receipt.provider, "stripe");
    assert_eq!(receipt.action, "refund");
    // Single-use is unchanged: the same public id cannot run the effect twice.
    assert!(broker
        .execute_capability_by_request_id(&allowed.request_id)
        .is_err());

    // A DENIED request minted no grant, so its id refuses instead of executing anything.
    let denied = broker
        .request_capability("exec_by_id", v2_m1_refund_request_at("ch_deny", 999_999))
        .unwrap();
    assert!(denied.grant_id.is_none(), "the fixture must be a denial");
    assert!(
        broker
            .execute_capability_by_request_id(&denied.request_id)
            .is_err(),
        "a denied request id must never execute"
    );
    // ...and so does an id the broker never issued.
    assert!(broker
        .execute_capability_by_request_id("req_ffffffffffffffff")
        .is_err());
}

/// A denied request id IS evidence. `cermet log <denied req_id>` must not answer "not found" — that
/// would hide a record that is right there: deny rows are lossless, so the request's fate renders
/// as a VIEW. An id the broker never saw still gets the plain not-found.
#[test]
fn request_log_renders_a_denied_request_instead_of_erring() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 100"),
    );
    let denied = broker
        .request_capability("denied_view", v2_m1_refund_request("ch_denied_view"))
        .unwrap();
    assert!(
        denied.grant_id.is_none(),
        "the fixture must actually be a denial"
    );

    let view = match broker.request_log(&denied.request_id) {
        Ok(RequestLogView::Denied(view)) => view,
        other => panic!("a denied request id must render its record, got {other:?}"),
    };
    assert_eq!(view.request_id, denied.request_id);
    assert_eq!(view.provider, "stripe");
    assert_eq!(view.action, "refund");
    assert_eq!(view.decision, "deny");
    assert_eq!(
        view.reason, denied.reason,
        "the STORED reason, verbatim — it carries the deny provenance"
    );
    assert_eq!(
        view.resource["charge"],
        json!("ch_denied_view"),
        "the requested fields are kept losslessly and render verbatim"
    );
    assert!(!view.created_at.is_empty(), "the record is timestamped");
    assert!(
        view.authority_fingerprint.is_some(),
        "the corpus digest it was decided against"
    );
    // request_id is the ONE public id: a denial minted no grant, so no grant handle can render.
    let json = serde_json::to_string(&RequestLogView::Denied(view)).unwrap();
    assert!(
        !json.contains("grant_"),
        "a denial view must never carry a grant handle: {json}"
    );

    // An id the broker never saw is unchanged: there is no record to render.
    match broker.request_log("req_ffffffffffffffff") {
        Err(Error::NotFound(message)) => assert_eq!(
            message, "no execution evidence for req_ffffffffffffffff",
            "an unknown id keeps the plain not-found"
        ),
        other => panic!("unknown ids stay not-found, got {other:?}"),
    }

    // The granted half of the same door still answers with execution evidence.
    let (_allowed_guard, allowed_dir) = fresh_broker_dir();
    let allowed = budget_broker(
        &allowed_dir,
        budget_rules("allow stripe.refund where amount <= 5000"),
    );
    let outcome = allowed
        .request_capability("allow", v2_m1_refund_request("ch_ok"))
        .unwrap();
    allowed
        .execute_capability(&outcome.grant_id.clone().expect("allowed"))
        .unwrap();
    match allowed.request_log(&outcome.request_id) {
        Ok(RequestLogView::Executed(evidence)) => {
            assert_eq!(evidence.request_id, outcome.request_id)
        }
        other => panic!("a granted request id still renders its evidence, got {other:?}"),
    }
}

/// The THIRD fate. `run --ask-only` decides and executes nothing, prints a `req_…`, and tells
/// the caller to finish it with `run --resume` — and `cermet log <that id>` used to answer
/// "not found" with exit 1, because the id had a grant but no terminal execution event and the
/// evidence join has nothing to project. The record exists: the decision, the frozen fields, and
/// the sentence that admitted them. That is what renders.
#[test]
fn request_log_renders_an_allowed_but_unexecuted_request() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000"),
    );
    let mut request = v2_m1_refund_request("ch_askonly");
    request.justification = Some("the ask-only probe".into());
    let decided = broker.request_capability("askonly", request).unwrap();
    assert!(
        decided.grant_id.is_some(),
        "the fixture must actually be an allow"
    );

    let view = match broker.request_log(&decided.request_id) {
        Ok(RequestLogView::Decided(view)) => view,
        other => panic!("a decided-but-unexecuted id must render its decision, got {other:?}"),
    };
    assert_eq!(view.request_id, decided.request_id);
    assert_eq!(view.provider, "stripe");
    assert_eq!(view.action, "refund");
    assert_eq!(view.decision, "allow");
    assert_eq!(
        view.resource["charge"],
        json!("ch_askonly"),
        "the FROZEN fields are the record: they are what execution will use"
    );
    let matched = view.matched_rule.clone().expect("the admitting sentence");
    assert!(
        matched.starts_with("allow stripe.refund") && matched.ends_with("where amount <= 5000"),
        "the admitting sentence renders verbatim, pinned digest and all: {matched}"
    );
    assert_eq!(view.justification.as_deref(), Some("the ask-only probe"));
    assert!(view.authority_fingerprint.is_some());
    assert!(!view.created_at.is_empty());
    assert_eq!(
        view.next,
        format!("cermet run --resume {}", decided.request_id),
        "the record names the one command that finishes it"
    );
    // `request_id` is the ONE public id: the grant handle never renders on this surface.
    let json = serde_json::to_string(&RequestLogView::Decided(view)).unwrap();
    assert!(
        !json.contains("grant_"),
        "a decision view must never carry a grant handle: {json}"
    );

    // Executing it moves the id to the executed fate; the door is the same.
    broker
        .execute_capability_by_request_id(&decided.request_id)
        .unwrap();
    match broker.request_log(&decided.request_id) {
        Ok(RequestLogView::Executed(evidence)) => {
            assert_eq!(evidence.request_id, decided.request_id)
        }
        other => panic!("once executed the id renders evidence, got {other:?}"),
    }

    // An id the broker never saw is unchanged.
    match broker.request_log("req_ffffffffffffffff") {
        Err(Error::NotFound(_)) => {}
        other => panic!("unknown ids stay not-found, got {other:?}"),
    }
}

/// A model self-report is PER REQUEST, which is the whole point of it: one session, two requests,
/// two different declarations, and the log carries each row's own claim rather than the one the
/// session opened with. A request that declares nothing carries nothing.
///
/// It is de-fanged at the same seam as every other client-supplied label, and it authorizes
/// nothing: the second request here is refused, and its claim is recorded all the same.
#[test]
fn each_request_carries_its_own_model_self_report() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000"),
    );

    let mut first = v2_m1_refund_request("ch_first");
    first.model = Some("claude-opus-5".into());
    let first = broker.request_capability("switching", first).unwrap();

    // The SAME session, a different model — the switch a session-static declaration cannot see.
    let mut second = v2_m1_refund_request_at("ch_over_cap", 900_000);
    second.model = Some("gpt-5.6\u{7}with a control character".into());
    let second = broker.request_capability("switching", second).unwrap();
    assert!(second.grant_id.is_none(), "the fixture must be a denial");

    // A third that declares nothing at all.
    let third = broker
        .request_capability("switching", v2_m1_refund_request("ch_silent"))
        .unwrap();

    let history = broker.history().unwrap();
    let model_of = |request_id: &str| {
        history
            .iter()
            .find(|row| row.request_id.as_deref() == Some(request_id))
            .unwrap_or_else(|| panic!("the log lists {request_id}"))
            .request_model
            .clone()
    };
    assert_eq!(
        model_of(&first.request_id).as_deref(),
        Some("claude-opus-5")
    );
    assert_eq!(
        model_of(&second.request_id).as_deref(),
        Some("gpt-5.6with a control character"),
        "control characters are stripped at the same seam as every other client label"
    );
    assert_eq!(
        model_of(&third.request_id),
        None,
        "a request that declared nothing carries nothing"
    );
}

/// The justification is REQUIRED of the agent and persisted verbatim, but it used to be write-only
/// — no view read it back. Every projection the operator's `log` renders now carries it: the
/// receipt list rows, the denied request's record, and the granted one's evidence.
#[test]
fn the_log_views_read_back_the_agent_justification() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000"),
    );
    let mut allowed_request = v2_m1_refund_request("ch_justified");
    allowed_request.justification = Some("the customer was double-charged".into());
    let allowed = broker
        .request_capability("justification", allowed_request)
        .unwrap();
    broker
        .execute_capability(&allowed.grant_id.clone().expect("allowed"))
        .unwrap();

    let mut denied_request = v2_m1_refund_request_at("ch_over_cap", 900_000);
    denied_request.justification = Some("way over the cap on purpose".into());
    let denied = broker
        .request_capability("justification", denied_request)
        .unwrap();
    assert!(denied.grant_id.is_none(), "the fixture must be a denial");

    // The list: both fates carry their justification under their public request id.
    let history = broker.history().unwrap();
    for (request_id, justification) in [
        (&allowed.request_id, "the customer was double-charged"),
        (&denied.request_id, "way over the cap on purpose"),
    ] {
        let row = history
            .iter()
            .find(|row| row.request_id.as_deref() == Some(request_id.as_str()))
            .unwrap_or_else(|| panic!("the log lists {request_id}"));
        assert_eq!(row.justification.as_deref(), Some(justification));
    }

    // The per-request JSON: whole, on both fates.
    match broker.request_log(&denied.request_id) {
        Ok(RequestLogView::Denied(view)) => assert_eq!(
            view.justification.as_deref(),
            Some("way over the cap on purpose")
        ),
        other => panic!("a denied id renders its record, got {other:?}"),
    }
    match broker.request_log(&allowed.request_id) {
        Ok(RequestLogView::Executed(evidence)) => assert_eq!(
            evidence.justification.as_deref(),
            Some("the customer was double-charged")
        ),
        other => panic!("a granted id renders its evidence, got {other:?}"),
    }

    // A request that supplied none projects the ABSENCE, never a placeholder.
    let bare = broker
        .request_capability("justification", v2_m1_refund_request("ch_bare"))
        .unwrap();
    broker
        .execute_capability(&bare.grant_id.clone().expect("allowed"))
        .unwrap();
    let json = serde_json::to_value(broker.request_log(&bare.request_id).unwrap()).unwrap();
    assert_eq!(
        json["justification"],
        json!(null),
        "the per-request JSON always carries the field: {json}"
    );
}

// The ledger-derived gate admits a first within-budget refund (mints a grant
// AND a durable `budget_mint` BEFORE the grant), then denies the second whose debit would exceed
// the day cap — value-free (`budget_exceeded: Some(Day)`, no number, no grant).
#[test]
fn budget_gate_admits_then_denies_when_the_day_cap_is_exhausted() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    broker.set_now(1_700_000_000);

    let first = broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 60))
        .unwrap();
    assert_eq!(first.decision, Decision::Allow, "{}", first.reason);
    assert!(first.grant_id.is_some(), "first within-budget refund mints");
    assert!(first.budget_exceeded.is_none());

    // The durable budget_mint precedes the grant (crash-window invariant).
    let mints = broker.audit.events_of_type("budget_mint").unwrap();
    assert_eq!(mints.len(), 1, "exactly one budget_mint appended");
    assert_eq!(mints[0].data["debit"], serde_json::json!(60));
    assert_eq!(mints[0].data["consumed_before"], serde_json::json!(0));

    // 60 + 60 = 120 > 100 ⇒ exhausted. Value-free deny, no grant, no numeric leak.
    let second = broker
        .request_capability("s", v2_m1_refund_request_at("ch2", 60))
        .unwrap();
    assert_eq!(second.decision, Decision::Deny);
    assert_eq!(
        second.budget_exceeded,
        Some(crate::types::BudgetWindow::Day)
    );
    assert!(second.grant_id.is_none());
    assert!(second.hint.is_none(), "no widen hint on a budget downgrade");
    // The operator receipt carries the numbers; the agent surface never did.
    let denied = broker.audit.events_of_type("budget_denied").unwrap();
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].data["consumed_before"], serde_json::json!(60));
    assert_eq!(denied[0].data["projected"], serde_json::json!(120));
    // No numeric budget field crosses to the agent-serialized outcome.
    let wire = serde_json::to_string(&second).unwrap();
    assert!(!wire.contains("100"), "no limit leaks to the wire: {wire}");
    assert!(!wire.contains("120"), "no consumed/projected leaks: {wire}");
}

// A within-cap second request DOES mint once the first is released — and the exhausting request is
// downgraded without leaving any grant.
#[test]
fn budget_gate_boundary_total_equals_limit_admits() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    broker.set_now(1_700_000_000);
    assert_eq!(
        broker
            .request_capability("s", v2_m1_refund_request_at("ch1", 60))
            .unwrap()
            .decision,
        Decision::Allow
    );
    // 60 + 40 == 100 (== limit) admits.
    let ok = broker
        .request_capability("s", v2_m1_refund_request_at("ch2", 40))
        .unwrap();
    assert_eq!(ok.decision, Decision::Allow, "{}", ok.reason);
}

// Two requests for the last dollar are serialized by the single
// broker thread; the first's `budget_mint` is durable before the second loads evidence, so exactly
// one passes.
#[test]
fn budget_last_dollar_race_serializes_to_exactly_one_admit() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 50 per day"),
    );
    broker.set_now(1_700_000_000);
    let a = broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 50))
        .unwrap();
    let b = broker
        .request_capability("s", v2_m1_refund_request_at("ch2", 50))
        .unwrap();
    let admits = [&a, &b]
        .iter()
        .filter(|o| o.decision == Decision::Allow)
        .count();
    assert_eq!(admits, 1, "exactly one of two last-dollar requests admits");
    assert_eq!(
        a.decision,
        Decision::Allow,
        "the first serialized request wins"
    );
    assert_eq!(b.budget_exceeded, Some(crate::types::BudgetWindow::Day));
}

// A Requested-then-expired budget grant releases its debit, freeing
// capacity for a later request — the cancel case, via TTL expiry + the sweep.
#[test]
fn budget_release_on_expiry_frees_capacity_for_a_later_request() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    let t0 = 1_700_000_000;
    broker.set_now(t0);
    // g1: 60 at t0 (expires t0+600).
    broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 60))
        .unwrap();
    broker.set_now(t0 + 300);
    // g2: 30 at t0+300 (expires t0+900). Same day bucket. consumed = 90.
    broker
        .request_capability("s", v2_m1_refund_request_at("ch2", 30))
        .unwrap();

    // A further 20 would be 90 + 20 = 110 > 100 ⇒ denied.
    broker.set_now(t0 + 400);
    let denied = broker
        .request_capability("s", v2_m1_refund_request_at("ch3", 20))
        .unwrap();
    assert_eq!(denied.decision, Decision::Deny);

    // Advance past g1's TTL only; the sweep releases g1 (approved, unclaimed) but not g2.
    broker.set_now(t0 + 700);
    let released = broker.sweep_expired_budget_mints();
    assert_eq!(released, 1, "only g1 has lapsed");
    assert_eq!(
        broker.audit.events_of_type("budget_release").unwrap().len(),
        1
    );

    // consumed is now g2 (30) only ⇒ 30 + 60 = 90 ≤ 100 admits.
    let ok = broker
        .request_capability("s", v2_m1_refund_request_at("ch4", 60))
        .unwrap();
    assert_eq!(ok.decision, Decision::Allow, "{}", ok.reason);
}

// Boot needs no reconciliation: a `budget_mint` whose grant row
// is absent (crash after the durable mint, before `insert_grant`) is a phantom orphan debit — it is
// counted while live (fail-closed) and released by the expiry sweep. No counter to reconcile.
#[test]
fn budget_crash_orphan_mint_is_counted_then_released_by_expiry() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    let t0 = 1_700_000_000;
    broker.set_now(t0);
    let first = broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 80))
        .unwrap();
    let grant_id = first.grant_id.clone().unwrap();
    // Simulate the crash: the mint is durable, but the grant row never survived.
    broker
        .state
        .execute(
            "DELETE FROM grants WHERE id=?1",
            rusqlite::params![grant_id],
        )
        .unwrap();
    // The orphan debit still counts while live (fail-closed): 80 + 30 = 110 > 100 ⇒ deny.
    let denied = broker
        .request_capability("s", v2_m1_refund_request_at("ch2", 30))
        .unwrap();
    assert_eq!(denied.decision, Decision::Deny, "orphan debit is counted");

    // Past TTL, the sweep releases the crash-orphan (grant row absent ⇒ never invoked).
    broker.set_now(t0 + 700);
    assert_eq!(broker.sweep_expired_budget_mints(), 1);
    let releases = broker.audit.events_of_type("budget_release").unwrap();
    assert_eq!(
        releases[0].data["cause"],
        serde_json::json!("expired_unclaimed")
    );
    // Capacity is freed.
    let ok = broker
        .request_capability("s", v2_m1_refund_request_at("ch3", 100))
        .unwrap();
    assert_eq!(ok.decision, Decision::Allow, "{}", ok.reason);
}

// The budget expiry backstop runs at BOOT (inside Broker::open) — a crash-orphan mint
// whose TTL lapsed while the daemon was down frees its reserved capacity on restart, not only at
// calendar rollover. (The daemon housekeeping tick calls the same serialized sweep at runtime.)
#[test]
fn budget_boot_sweep_releases_a_crash_orphan_mint() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let rules =
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day");
    {
        let broker = budget_broker(&dir, rules.clone());
        broker.set_now(1_700_000_000);
        let first = broker
            .request_capability("s", v2_m1_refund_request_at("ch1", 60))
            .unwrap();
        let gid = first.grant_id.clone().unwrap();
        // Crash after the durable mint, before/with the grant lost: delete the grant row.
        broker
            .state
            .execute("DELETE FROM grants WHERE id=?1", rusqlite::params![gid])
            .unwrap();
        assert!(
            broker
                .audit
                .events_of_type("budget_release")
                .unwrap()
                .is_empty(),
            "no release before restart"
        );
    }
    // Reopen: the boot sweep runs on the real wall clock (≫ the 1_700_000_000+600 mint TTL) and
    // releases the crash-orphan. This is the wiring a direct-core-only test would have masked.
    let broker2 = budget_broker(&dir, rules);
    let releases = broker2.audit.events_of_type("budget_release").unwrap();
    assert_eq!(
        releases.len(),
        1,
        "boot sweep releases the crash-orphan mint"
    );
    assert_eq!(
        releases[0].data["cause"],
        serde_json::json!("expired_unclaimed")
    );
}

// A vault-open failure is definitively PRE-invocation (no provider call happened) — the
// grant's debit must be RELEASED (`pre_invocation_terminal_failure`), freeing the reserved
// capacity.
#[test]
fn budget_vault_open_failure_releases_the_debit_pre_invocation() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let (broker, invoked) = budget_broker_cred(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    broker.set_now(1_700_000_000);
    // No credential enrolled ⇒ open_secret fails BEFORE provider.execute.
    let first = broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 60))
        .unwrap();
    let grant_id = first.grant_id.clone().unwrap();
    assert!(
        broker.execute_capability(&grant_id).is_err(),
        "vault-open fails execute"
    );
    assert!(
        !invoked.load(std::sync::atomic::Ordering::SeqCst),
        "provider was NOT invoked"
    );

    let releases = broker.audit.events_of_type("budget_release").unwrap();
    assert_eq!(
        releases.len(),
        1,
        "pre-invocation failure releases the debit"
    );
    assert_eq!(
        releases[0].data["cause"],
        serde_json::json!("pre_invocation_terminal_failure")
    );
    // The reserved capacity is freed: a fresh 100 now admits (60 released ⇒ consumed 0).
    let ok = broker
        .request_capability("s", v2_m1_refund_request_at("ch2", 100))
        .unwrap();
    assert_eq!(ok.decision, Decision::Allow, "{}", ok.reason);
}

// The KEEP direction: an error AT/AFTER `provider.execute` (money may have moved) must
// KEEP the debit — no release, capacity stays consumed.
#[test]
fn budget_error_after_invocation_keeps_the_debit() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let (broker, invoked) = budget_broker_cred(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    broker.set_now(1_700_000_000);
    // Enroll a credential so open_secret succeeds and provider.execute is invoked (then errors).
    broker
        .vault
        .connect(&credential_ref("stripe"), "stripe", None, "tok")
        .unwrap();
    let first = broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 60))
        .unwrap();
    let grant_id = first.grant_id.clone().unwrap();
    assert!(broker.execute_capability(&grant_id).is_err());
    assert!(
        invoked.load(std::sync::atomic::Ordering::SeqCst),
        "provider WAS invoked"
    );
    assert!(
        broker
            .audit
            .events_of_type("budget_release")
            .unwrap()
            .is_empty(),
        "an at/after-invocation failure keeps the debit — no release"
    );
    // Capacity stays consumed: 60 + 60 = 120 > 100 ⇒ the next request is denied.
    let denied = broker
        .request_capability("s", v2_m1_refund_request_at("ch2", 60))
        .unwrap();
    assert_eq!(
        denied.decision,
        Decision::Deny,
        "the kept debit still counts"
    );
}

// A CRASH between the terminal status flip and the `budget_release` append leaves an
// Executed grant whose debit no sweep released. The sweep must recover it idempotently from the
// durable `mutation_invoked:false` terminal fact (an abandoned Executing lease, by contrast, KEEPS
// its debit — it has no such fact).
#[test]
fn budget_sweep_recovers_a_terminal_before_invocation_grant() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let (broker, _invoked) = budget_broker_cred(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    let t0 = 1_700_000_000;
    broker.set_now(t0);
    let first = broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 60))
        .unwrap();
    let grant_id = first.grant_id.clone().unwrap();
    // Simulate the CRASH between the terminal flip and the release append: the grant is flipped to
    // Executed and the durable `mutation_invoked:false` terminal fact is recorded, but the
    // `budget_release` never landed (as if the process died just before appending it).
    let g = broker.load_grant(&grant_id).unwrap();
    let executed_digest = broker.redigest(&grant_id, &g, "executed");
    broker
        .state
        .execute(
            "UPDATE grants SET status='executed', grant_digest=?2 WHERE id=?1",
            rusqlite::params![grant_id, executed_digest],
        )
        .unwrap();
    broker
        .audit
        .record(crate::audit::NewEvent {
            session_id: Some("s"),
            event_type: "provider_action_failed",
            severity: "high",
            summary: "vault-open failed before invocation",
            data: serde_json::json!({
                "grant_id": grant_id, "mutation_invoked": false, "outcome": "error"
            }),
            secrets: &[],
        })
        .unwrap();
    assert!(
        broker
            .audit
            .events_of_type("budget_release")
            .unwrap()
            .is_empty(),
        "the crash left no release"
    );

    // Past TTL, the sweep recovers the missing release from the durable terminal fact.
    broker.set_now(t0 + 700);
    assert_eq!(
        broker.sweep_expired_budget_mints(),
        1,
        "the sweep recovers a terminal-before-invocation grant"
    );
    let releases = broker.audit.events_of_type("budget_release").unwrap();
    assert_eq!(releases.len(), 1);
    // Idempotent: a second sweep does not double-release.
    assert_eq!(broker.sweep_expired_budget_mints(), 0);
    assert_eq!(
        broker.audit.events_of_type("budget_release").unwrap().len(),
        1
    );
}

// An ORDINARY unclaimed-approved grant flipped to `Expired` whose `budget_release` was
// crash-interrupted has NO `mutation_invoked:false` fact — but absent lease stamps prove it was
// never claimed (never invoked). The sweep recovers it (proven-expiry gated), self-healing the
// debit.
#[test]
fn budget_sweep_recovers_an_ordinary_unclaimed_expired_grant() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let (broker, _invoked) = budget_broker_cred(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    let t0 = 1_700_000_000;
    broker.set_now(t0);
    let first = broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 60))
        .unwrap();
    let grant_id = first.grant_id.clone().unwrap();
    // Simulate the crash: Approved→Expired flip landed (HMAC-valid, NO lease stamps — never
    // claimed), but the budget_release never appended.
    let g = broker.load_grant(&grant_id).unwrap();
    let expired_digest = broker.redigest(&grant_id, &g, "expired");
    broker
        .state
        .execute(
            "UPDATE grants SET status='expired', grant_digest=?2 WHERE id=?1",
            rusqlite::params![grant_id, expired_digest],
        )
        .unwrap();
    assert!(broker
        .audit
        .events_of_type("budget_release")
        .unwrap()
        .is_empty());

    // Past TTL, the sweep recovers the never-claimed Expired grant.
    broker.set_now(t0 + 700);
    assert_eq!(
        broker.sweep_expired_budget_mints(),
        1,
        "ordinary unclaimed expiry self-heals"
    );
    assert_eq!(
        broker.audit.events_of_type("budget_release").unwrap().len(),
        1
    );
    // Idempotent.
    assert_eq!(broker.sweep_expired_budget_mints(), 0);
}

// The fail-closed pre-invocation terminalizer records the authenticated
// `mutation_invoked:false` fact, flips executing→executed, and releases the debit — the single seam
// every post-claim/pre-handoff failure routes through.
#[test]
fn terminalize_pre_invocation_failure_records_fact_and_releases() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let (broker, _invoked) = budget_broker_cred(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    let t0 = 1_700_000_000;
    broker.set_now(t0);
    let first = broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 60))
        .unwrap();
    let grant_id = first.grant_id.clone().unwrap();
    // Put it Executing with lease stamps (mirrors a claim).
    let g = broker.load_grant(&grant_id).unwrap();
    let (opened, deadline) = (t0, t0 + 10);
    let digest = broker.redigest_leased(&grant_id, &g, "executing", opened, deadline);
    broker
            .state
            .execute(
                "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
                rusqlite::params![grant_id, digest, opened, deadline],
            )
            .unwrap();
    let g = broker.load_grant(&grant_id).unwrap();
    broker
        .terminalize_pre_invocation_failure(
            &grant_id,
            &g,
            opened,
            deadline,
            &[],
            "test_pre_invocation_failure",
            "provider setup failed before egress",
            "sess",
        )
        .unwrap();
    // The grant is terminal, the fact is durable, and the debit is released.
    assert_eq!(
        broker.load_grant(&grant_id).unwrap().status,
        GrantStatus::Executed
    );
    assert!(broker
        .audit
        .grant_terminated_before_invocation(&grant_id)
        .unwrap());
    let releases = broker.audit.events_of_type("budget_release").unwrap();
    assert_eq!(releases.len(), 1);
    assert_eq!(
        releases[0].data["cause"],
        serde_json::json!("pre_invocation_terminal_failure")
    );
}

#[test]
fn recovered_non_money_pre_effect_terminal_releases_its_budget() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let (broker, _invoked) = budget_broker_cred(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    let t0 = 1_700_000_000;
    broker.set_now(t0);
    let request = broker
        .request_capability("non-money", v2_m1_refund_request_at("ch1", 60))
        .unwrap();
    let grant_id = request.grant_id.as_deref().unwrap();
    let grant = broker.load_grant(grant_id).unwrap();
    let (opened, deadline) = (t0, t0 + 10);
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
                "executing_session": "non-money-executor",
            }),
            secrets: &[],
        })
        .unwrap();

    let status = broker.request_status(&request.request_id).unwrap();
    assert_eq!(status.status, "terminal");
    assert_eq!(
        broker.load_grant(grant_id).unwrap().status,
        GrantStatus::Executed
    );
    assert_eq!(
        broker.audit.events_of_type("budget_release").unwrap().len(),
        1
    );
}

#[test]
// The `altered` leg (an effect-start row recording a resource that does
// not match the frozen grant, forged straight into `audit.db`) is unreachable: writing that row
// needs the daemon's own audit key. The redaction property this test is named for is unchanged
// and still asserted.
fn recovery_replays_the_audit_writers_complete_resource_redaction() {
    const VAULT_SECRET: &str = "vault_resource_canary";
    const CHARGE: &str = "prefix_vault_resource_canary_suffix";

    {
        let altered = false;
        let (_dir_guard, dir) = fresh_broker_dir();
        let (broker, _invoked) = budget_broker_cred(
            &dir,
            budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
        );
        broker
            .connect_credential("stripe", None, VAULT_SECRET)
            .unwrap();
        let t0 = 1_700_000_000;
        broker.set_now(t0);
        let request = broker
            .request_capability(
                &format!("redaction-{altered}"),
                v2_m1_refund_request_at(CHARGE, 60),
            )
            .unwrap();
        let grant_id = request.grant_id.as_deref().unwrap();
        let grant = broker.load_grant(grant_id).unwrap();
        let (opened, deadline) = (t0, t0 + 10);
        let digest = broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
        broker
            .state
            .execute(
                "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
                rusqlite::params![grant_id, digest, opened, deadline],
            )
            .unwrap();
        let executing_session = "exec_redaction";
        let recorded_charge = if altered {
            format!("altered_{CHARGE}")
        } else {
            CHARGE.to_string()
        };
        let secrets = [VAULT_SECRET.to_string()];
        let correctly_recorded_resource =
            crate::audit::redacted_for_record(json!({"charge":CHARGE,"amount":60}), &secrets);
        let resource_binding = broker
            .effect_start_resource_binding(grant_id, &grant, &correctly_recorded_resource)
            .unwrap();
        broker
            .audit
            .record(NewEvent {
                session_id: Some(&grant.session_id),
                event_type: "capability_effect_starting",
                severity: "high",
                summary: "actual audit redaction roundtrip",
                data: json!({
                    "grant_id": grant_id,
                    "request_id": grant.request_id,
                    "provider": grant.provider,
                    "action": grant.action,
                    "authority_digest": grant.policy_fingerprint,
                    "resource": {"charge":recorded_charge,"amount":60},
                    "resource_binding": resource_binding,
                    "agent_request_fields": ["amount", "charge"],
                    "provider_resolved_fields": [],
                    "request_session": grant.session_id,
                    "executing_session": executing_session,
                }),
                secrets: &secrets,
            })
            .unwrap();
        broker
            .audit
            .record(NewEvent {
                session_id: Some(&grant.session_id),
                event_type: "provider_action_failed",
                severity: "high",
                summary: "provider unavailable after start",
                data: json!({
                    "grant_id": grant_id,
                    "request_id": grant.request_id,
                    "provider": grant.provider,
                    "action": grant.action,
                    "outcome": "error",
                    "mutation_invoked": false,
                    "error": "provider unavailable",
                    "request_session": grant.session_id,
                    "executing_session": executing_session,
                }),
                secrets: &secrets,
            })
            .unwrap();

        let recorded = broker
            .audit
            .events_of_type("capability_effect_starting")
            .unwrap()
            .pop()
            .unwrap()
            .data;
        let charge = recorded["resource"]["charge"].as_str().unwrap();
        assert!(charge.contains("[SECRET_REDACTED]"));
        assert!(!charge.contains(VAULT_SECRET));

        let status = broker.request_status(&request.request_id).unwrap();
        assert_eq!(status.status, "terminal");
        assert_eq!(
            broker.load_grant(grant_id).unwrap().status,
            GrantStatus::Executed
        );
        let _ = deadline;
    }
}

#[test]
fn effect_start_recovery_survives_vault_secret_rotation() {
    const HISTORICAL_SECRET: &str = "historical_vault_secret_canary";
    const CHARGE: &str = "prefix_historical_vault_secret_canary_suffix";

    let (_dir_guard, dir) = fresh_broker_dir();
    let (broker, _invoked) = budget_broker_cred(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    broker
        .connect_credential("stripe", None, HISTORICAL_SECRET)
        .unwrap();
    let t0 = 1_700_000_000;
    broker.set_now(t0);
    let request = broker
        .request_capability("rotation", v2_m1_refund_request_at(CHARGE, 60))
        .unwrap();
    let grant_id = request.grant_id.as_deref().unwrap();
    let grant = broker.load_grant(grant_id).unwrap();
    let (opened, deadline) = (t0, t0 + 10);
    let digest = broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
    broker
        .state
        .execute(
            "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
            rusqlite::params![grant_id, digest, opened, deadline],
        )
        .unwrap();
    let executing_session = "exec_rotation";
    let safe_resource = crate::audit::redacted_for_record(
        json!({"charge":CHARGE,"amount":60}),
        &[HISTORICAL_SECRET.to_string()],
    );
    let resource_binding = broker
        .effect_start_resource_binding(grant_id, &grant, &safe_resource)
        .unwrap();
    broker
        .audit
        .record(NewEvent {
            session_id: Some(&grant.session_id),
            event_type: "capability_effect_starting",
            severity: "high",
            summary: "historically redacted effect start",
            data: json!({
                "grant_id": grant_id,
                "request_id": grant.request_id,
                "provider": grant.provider,
                "action": grant.action,
                "authority_digest": grant.policy_fingerprint,
                "resource": safe_resource,
                "resource_binding": resource_binding,
                "agent_request_fields": ["amount", "charge"],
                "provider_resolved_fields": [],
                "request_session": grant.session_id,
                "executing_session": executing_session,
            }),
            secrets: &[],
        })
        .unwrap();
    broker
        .audit
        .record(NewEvent {
            session_id: Some(&grant.session_id),
            event_type: "provider_action_failed",
            severity: "high",
            summary: "provider unavailable after start",
            data: json!({
                "grant_id": grant_id,
                "request_id": grant.request_id,
                "provider": grant.provider,
                "action": grant.action,
                "outcome": "error",
                "mutation_invoked": false,
                "error": "provider unavailable",
                "request_session": grant.session_id,
                "executing_session": executing_session,
            }),
            secrets: &[],
        })
        .unwrap();
    broker
        .connect_credential("stripe", None, "rotated_vault_secret_canary")
        .unwrap();

    let status = broker.request_status(&request.request_id).unwrap();
    assert_eq!(status.status, "terminal");
    assert_eq!(
        broker.load_grant(grant_id).unwrap().status,
        GrantStatus::Executed
    );
}

#[test]
// The case list here covers only `valid_artifact`: the other retention-tuple cases
// (`artifact_without_wire`, `wire_without_error`, `error_without_wire`, `foreign_artifact`) are
// tuples the terminal writer structurally cannot emit — producing them requires the daemon's own
// audit key, so there is nothing to validate against. What remains is the recovery itself.
fn http_recovery_completes_for_a_retained_artifact_terminal() {
    {
        let case = "valid_artifact";
        let (_dir_guard, dir) = fresh_broker_dir();
        let (broker, _invoked) = budget_broker_cred(
            &dir,
            budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
        );
        let t0 = 1_700_000_000;
        broker.set_now(t0);
        let request = broker
            .request_capability(&format!("sess_{case}"), v2_m1_refund_request_at("ch1", 60))
            .unwrap();
        let grant_id = request.grant_id.as_deref().unwrap();
        let grant = broker.load_grant(grant_id).unwrap();
        let (opened, deadline) = (t0, t0 + 10);
        let digest = broker.redigest_leased(grant_id, &grant, "executing", opened, deadline);
        broker
            .state
            .execute(
                "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
                rusqlite::params![grant_id, digest, opened, deadline],
            )
            .unwrap();
        let executing_session = format!("exec_{case}");
        broker
            .audit
            .record(NewEvent {
                session_id: Some(&grant.session_id),
                event_type: "capability_effect_starting",
                severity: "high",
                summary: "HTTP effect start fixture",
                data: bound_effect_start_data(
                    &broker,
                    grant_id,
                    &grant,
                    json!({
                        "grant_id": grant_id,
                        "request_id": grant.request_id,
                        "provider": grant.provider,
                        "action": grant.action,
                        "authority_digest": grant.policy_fingerprint,
                        "resource": {"charge":"ch1","amount":60},
                        "agent_request_fields": ["amount", "charge"],
                        "provider_resolved_fields": [],
                        "request_session": grant.session_id,
                        "executing_session": executing_session,
                    }),
                ),
                secrets: &[],
            })
            .unwrap();
        let artifact_request = if case == "foreign_artifact" {
            "req_foreign"
        } else {
            grant.request_id.as_str()
        };
        let stored = broker
            .store_artifact_capped(
                artifact_request,
                b"retained response",
                broker.artifacts.max_bytes,
                Some(&grant.session_id),
            )
            .unwrap();
        let mut terminal = json!({
            "grant_id": grant_id,
            "request_id": grant.request_id,
            "provider": grant.provider,
            "action": grant.action,
            "outcome": "ok",
            "mutation_invoked": true,
            "result": {"ok":true},
            "request_session": grant.session_id,
            "executing_session": executing_session,
        });
        terminal["artifact"] = json!(stored.handle);
        terminal["digest"] = json!(stored.digest);
        terminal["wire_stats"] = json!({"total_bytes":17,"kept_bytes":11});
        broker
            .audit
            .record(NewEvent {
                session_id: Some(&grant.session_id),
                event_type: "provider_action_succeeded",
                severity: "info",
                summary: "HTTP terminal retention fixture",
                data: terminal,
                secrets: &[],
            })
            .unwrap();

        let status = broker.request_status(&request.request_id).unwrap();
        assert_eq!(status.status, "terminal", "{case}");
        let _ = deadline;
    }
}

// The KEEP direction: an abandoned EXECUTING lease also becomes Expired, but it may have
// crossed the effect boundary — it has no `mutation_invoked:false` fact, so the sweep KEEPS its
// debit.
#[test]
fn budget_sweep_keeps_the_debit_of_an_abandoned_executing_grant() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let (broker, _invoked) = budget_broker_cred(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    let t0 = 1_700_000_000;
    broker.set_now(t0);
    let first = broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 60))
        .unwrap();
    let grant_id = first.grant_id.clone().unwrap();
    // Drive it to Executing (claim), then abandon: enroll a credential so the claim CAS proceeds,
    // but instead of executing we terminalize the lease as abandoned (unreported — may have run).
    broker
        .vault
        .connect(&credential_ref("stripe"), "stripe", None, "tok")
        .unwrap();
    let g = broker.load_grant(&grant_id).unwrap();
    // Manually put it Executing with lease stamps (mirrors a claim), then abandon via the sweep.
    let opened = t0;
    let deadline = t0 + 10;
    let digest = broker.redigest_leased(&grant_id, &g, "executing", opened, deadline);
    broker
            .state
            .execute(
                "UPDATE grants SET status='executing', grant_digest=?2, lease_opened_at=?3, lease_deadline=?4 WHERE id=?1",
                rusqlite::params![grant_id, digest, opened, deadline],
            )
            .unwrap();
    broker.set_now(t0 + 700);
    broker.sweep_overdue_leases(); // terminalizes to Expired (lease_abandoned, unreported)

    // The mint's TTL has lapsed; the budget sweep sees the expired mint but must KEEP the debit —
    // there is no mutation_invoked:false fact for this grant.
    assert_eq!(
        broker.sweep_expired_budget_mints(),
        0,
        "an abandoned Executing grant keeps its debit"
    );
    assert!(broker
        .audit
        .events_of_type("budget_release")
        .unwrap()
        .is_empty());
}

// The expiry sweep must NOT release a grant's debit on an AMBIGUOUS state-read fault —
// only a proven-absent (crash-orphan) or present Requested/Approved grant releases. A transient
// read fault (here: the grants table is unreadable) must RETAIN the debit (an unreadable grant may
// be Executing/Executed and have moved money) — treating an unreadable state as releasable is
// wrong.
#[test]
fn budget_sweep_retains_the_debit_on_an_ambiguous_grant_read_fault() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    let t0 = 1_700_000_000;
    broker.set_now(t0);
    broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 60))
        .unwrap();

    // Simulate a transient state-read fault: the grants table becomes unreadable. The mint (audit
    // db) is untouched, so the sweep still SEES the expired mint but cannot prove the grant absent.
    broker
        .state
        .execute("ALTER TABLE grants RENAME TO grants_hidden", [])
        .unwrap();
    broker.set_now(t0 + 700);
    assert_eq!(
        broker.sweep_expired_budget_mints(),
        0,
        "an ambiguous read fault must never release the debit"
    );
    assert!(
        broker
            .audit
            .events_of_type("budget_release")
            .unwrap()
            .is_empty(),
        "no budget_release on an ambiguous read"
    );

    // Restore readability: the grant is now legitimately Approved+unclaimed ⇒ the sweep releases.
    broker
        .state
        .execute("ALTER TABLE grants_hidden RENAME TO grants", [])
        .unwrap();
    assert_eq!(
        broker.sweep_expired_budget_mints(),
        1,
        "readable Approved grant releases"
    );
    assert_eq!(
        broker.audit.events_of_type("budget_release").unwrap().len(),
        1
    );
}

// The grant's `expiry_epoch` MUST equal the `budget_mint`'s `expires_at_epoch` — both
// derived from the ONE captured `decision_at_epoch`, never independently re-sampled. With the clock
// drifting within the handler (evidence load / audit persistence crossing a second), an independent
// `now_epoch() + TTL` at insert would make the grant outlive its mint's sweep window.
#[test]
fn budget_grant_expiry_matches_the_mint_expiry_under_clock_drift() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget amount 100 per day"),
    );
    broker.set_now(1_700_000_000);
    // Every now_epoch() read inside the handler advances the frozen clock by 1s — reproducing the
    // real drift between the gate's captured epoch and a later insert-time sample.
    broker.set_clock_tick(1);
    let first = broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 60))
        .unwrap();
    let grant_id = first.grant_id.clone().unwrap();
    broker.set_clock_tick(0);

    let mints = broker.audit.events_of_type("budget_mint").unwrap();
    let mint_expires = mints[0].data["expires_at_epoch"].as_i64().unwrap();
    let grant = broker.load_grant(&grant_id).unwrap();
    assert_eq!(
        grant.expiry_epoch,
        Some(mint_expires),
        "the grant expiry must be the mint ticket's single captured expiry, not a re-sampled clock"
    );
}

// `rate` sums the literal 1 per admitted request; the same gate/release
// paths as budget. `rate 2 per hour` admits twice, denies the third (value-free, by window).
#[test]
fn rate_gate_admits_up_to_the_count_then_denies() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where rate 2 per hour"),
    );
    broker.set_now(1_700_000_000);
    assert_eq!(
        broker
            .request_capability("s", v2_m1_refund_request_at("c1", 10))
            .unwrap()
            .decision,
        Decision::Allow
    );
    assert_eq!(
        broker
            .request_capability("s", v2_m1_refund_request_at("c2", 999))
            .unwrap()
            .decision,
        Decision::Allow,
        "rate debits 1 regardless of amount"
    );
    let third = broker
        .request_capability("s", v2_m1_refund_request_at("c3", 1))
        .unwrap();
    assert_eq!(third.decision, Decision::Deny);
    assert_eq!(
        third.budget_exceeded,
        Some(crate::types::BudgetWindow::Hour)
    );
    // The rate mint records debit 1.
    let mints = broker.audit.events_of_type("budget_mint").unwrap();
    assert!(mints
        .iter()
        .all(|m| m.data["debit"] == serde_json::json!(1)));
}

// Fail-closed / anti-oracle: a budget over a field that is NOT a
// required+bounded+int+side-effect field cannot freeze a debit ⇒ `DenyInvalid`. The agent gets a
// GENERIC value-free deny (NEVER `BudgetExceeded`, which would imply a coherent balance); an
// operator-only `budget_gate_error` records the fault.
#[test]
fn budget_over_an_unfreezable_field_is_a_generic_deny_not_budget_exceeded() {
    let (_dir_guard, dir) = fresh_broker_dir();
    // `charge` is an identity string (exact-pin), not a required bounded int side-effect field.
    let broker = budget_broker(
        &dir,
        budget_rules("allow stripe.refund where amount <= 5000 and budget charge 100 per day"),
    );
    broker.set_now(1_700_000_000);
    let out = broker
        .request_capability("s", v2_m1_refund_request_at("ch1", 60))
        .unwrap();
    assert_eq!(out.decision, Decision::Deny);
    assert_eq!(
        out.budget_exceeded, None,
        "invalid evidence never implies a coherent balance"
    );
    assert_eq!(
        broker.audit.events_of_type("budget_mint").unwrap().len(),
        0,
        "no debit minted"
    );
    let errors = broker.audit.events_of_type("budget_gate_error").unwrap();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].data["fault"], serde_json::json!("debit_invalid"));
}

#[test]
fn secret_environment_never_enters_metadata_or_views() {
    const STRIPE_SECRET_ENVIRONMENT: &str = r#"
provider: stripe
action: shape_secret_environment
fields:
  - { name: charge, type: str, required: true, class: identity, binding: exact_resource_pin }
  - { name: environment, type: str, required: true, class: secret, binding: unbound }
consumes: [charge, environment]
execution_targets: [charge]
http:
  steps:
    - id: secret_environment
      method: POST
      path: /v1/secret_environment
      body: { charge: "{charge}", environment: "{environment}" }
"#;
    let rules = crate::sentence::parse_rules("allow stripe.shape_secret_environment").unwrap();
    let source = Arc::new(V2M1SentenceAuthority::new(rules));
    let mut broker = open_broker_with_sentence_authority_and_templates(
        "providers: {}",
        source,
        vec![STRIPE_SECRET_ENVIRONMENT.to_string()],
    );
    install_v2_shape_stripe(&mut broker);
    let outcome = broker
        .request_capability(
            "secret-environment-request",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "shape_secret_environment".into(),
                resource: json!({
                    "charge": "ch_secret_environment",
                    "environment": "provider_secret_value"
                }),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(outcome.decision, Decision::Allow);
    let grant_id = outcome.grant_id.unwrap();
    let stored_environment: Option<String> = broker
        .state
        .query_row(
            "SELECT environment FROM grants WHERE id=?1",
            rusqlite::params![grant_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        stored_environment, None,
        "Secret metadata is never duplicated"
    );

    let view = broker
        .history()
        .unwrap()
        .into_iter()
        .find(|view| view.grant_id == grant_id)
        .unwrap();
    assert!(view.integrity_ok);
    assert_eq!(view.environment, None);
    assert_eq!(
        view.resource["environment"],
        json!(super::helpers::SECRET_FIELD_MARKER)
    );
    broker.execute_capability(&grant_id).unwrap();
    let evidence = broker.evidence(&outcome.request_id).unwrap();
    assert_eq!(
        evidence.resource["environment"],
        json!(super::helpers::SECRET_FIELD_MARKER)
    );
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains("provider_secret_value"),
        "operator evidence reuses the grant view's secret-field redaction"
    );
}

#[test]
fn v2_m4_sentence_change_refuses_before_claim_egress_and_survives_restart() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let rules_f = v2_m1_rules_with_limit(5000);
    let rules_g = v2_m1_rules_with_limit(100);
    let source = Arc::new(V2M1SentenceAuthority::new(rules_f));
    let profile = "providers:\n  stripe:\n    allow:\n      - action: refund\n        scope:\n          resource: { charge: ch_drift }\n";
    let mut broker = open_broker_reuse_with_sentence_authority(&dir, profile, source.clone());
    let calls = install_v2_m1_fake_stripe(&mut broker);
    let outcome = broker
        .request_capability("v2-m4-drift", v2_m1_refund_request("ch_drift"))
        .unwrap();
    let grant_id = outcome
        .grant_id
        .expect("F authorizes an approved sentence grant");

    source.activate(rules_g);
    let error = broker.execute_capability(&grant_id).unwrap_err();
    assert!(error.to_string().contains("sentence authority changed"));
    assert_eq!(
        *calls.lock().unwrap(),
        0,
        "drift is checked before provider egress"
    );
    assert_eq!(
        broker.load_grant(&grant_id).unwrap().status,
        GrantStatus::Approved
    );
    let refusals = broker
        .audit
        .events_of_type("capability_execution_refused")
        .unwrap();
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].data["grant_id"], json!(grant_id));
    assert_eq!(
        refusals[0].data["reason"],
        json!("sentence_authority_changed")
    );
    drop(broker);

    let mut restarted = open_broker_reuse_with_sentence_authority(&dir, profile, source.clone());
    let restart_calls = install_v2_m1_fake_stripe(&mut restarted);
    let error = restarted.execute_capability(&grant_id).unwrap_err();
    assert!(error.to_string().contains("sentence authority changed"));
    assert_eq!(*restart_calls.lock().unwrap(), 0);
    assert_eq!(
        restarted.load_grant(&grant_id).unwrap().status,
        GrantStatus::Approved,
        "restart under G must not claim the stale F grant"
    );
}

#[test]
fn missing_or_failed_sentence_authority_source_fails_closed() {
    let rules = v2_m1_rules_with_limit(5000);
    let mut missing = open_broker("providers: {}");
    install_v2_m1_fake_stripe(&mut missing);
    let missing_before = v2_m1_grant_count(&missing);
    let missing_outcome = missing
        .request_capability_with_sentence(
            "sentence-source-missing",
            &rules,
            v2_m1_refund_request("ch_sentence_source_missing"),
        )
        .unwrap();
    assert_eq!(missing_outcome.decision, Decision::Deny);
    assert!(missing_outcome.grant_id.is_none());
    assert_eq!(v2_m1_grant_count(&missing), missing_before);

    let source = Arc::new(V2M1SentenceAuthority::new(rules.clone()));
    source.fail("authenticated sentence custody read failed");
    let (_dir_guard, dir) = fresh_broker_dir();
    let mut failed = open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source);
    install_v2_m1_fake_stripe(&mut failed);
    let failed_before = v2_m1_grant_count(&failed);
    let failed_outcome = failed
        .request_capability_with_sentence(
            "sentence-source-failed",
            &rules,
            v2_m1_refund_request("ch_sentence_source_failed"),
        )
        .unwrap();
    assert_eq!(failed_outcome.decision, Decision::Deny);
    assert!(failed_outcome.grant_id.is_none());
    assert!(failed_outcome.hint.is_none());
    assert_eq!(v2_m1_grant_count(&failed), failed_before);
}

#[test]
fn identical_text_under_a_new_language_version_cannot_revive_an_old_grant() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let rules = v2_m1_rules_with_limit(5000);
    let canonical = crate::sentence::canonical_rule_bytes(&rules);
    let v1_digest = crate::sentence::authority_digest_for(1, &canonical);
    let source = Arc::new(DigestOverrideSentenceAuthority::new(rules, v1_digest));
    let mut broker =
        open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source.clone());
    let calls = install_v2_m1_fake_stripe(&mut broker);
    let grant = broker
        .request_capability("version-bound", v2_m1_refund_request("ch_version_bound"))
        .unwrap()
        .grant_id
        .unwrap();

    source.set_digest(crate::sentence::authority_digest_for(2, &canonical));
    let error = broker.execute_capability(&grant).unwrap_err();
    assert!(error.to_string().contains("sentence authority changed"));
    assert_eq!(*calls.lock().unwrap(), 0);
    assert_eq!(
        broker.load_grant(&grant).unwrap().status,
        GrantStatus::Approved,
        "version drift refuses before the single-use claim"
    );
}

#[test]
fn version_one_non_allow_denies_without_minting_a_grant() {
    let mut rules =
        crate::sentence::parse_rules("allow stripe.refund where amount <= 100").unwrap();
    crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
    let source = Arc::new(V2M1SentenceAuthority::new(rules.clone()));
    let (_dir_guard, dir) = fresh_broker_dir();
    let mut broker = open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source);
    install_v2_m1_fake_stripe(&mut broker);
    let expected_fingerprint = v2_m1_rules_fingerprint(&rules);
    let before = v2_m1_grant_count(&broker);

    let outcome = broker
        .request_capability_with_sentence(
            "sentence-non-allow",
            &rules,
            v2_m1_refund_request("ch_sentence_non_allow"),
        )
        .unwrap();
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.grant_id.is_none());
    assert_eq!(v2_m1_grant_count(&broker), before);
    let request_fingerprint: String = broker
        .state
        .query_row(
            "SELECT policy_fingerprint FROM requests WHERE id=?1",
            rusqlite::params![outcome.request_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(request_fingerprint, expected_fingerprint);
    let decisions = broker.audit.events_of_type("policy_decision").unwrap();
    let decision = decisions.last().unwrap();
    assert_eq!(decision.data["authority_kind"], json!("sentence"));
    assert_eq!(
        decision.data["authority_fingerprint"],
        json!(expected_fingerprint)
    );
}

/// An allow's provenance is the admitting rule's canonical TEXT — the exact bytes the
/// corpus digest covers — stored typed on the request row, on the decision event, and projected
/// onto the operator's history view. A deny has no admitting sentence, so it stores none.
#[test]
fn an_allow_stores_the_admitting_rule_text_and_a_deny_stores_none() {
    let mut rules =
        crate::sentence::parse_rules("allow stripe.refund where amount <= 5000").unwrap();
    crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
    let source = Arc::new(V2M1SentenceAuthority::new(rules.clone()));
    let (_dir_guard, dir) = fresh_broker_dir();
    let mut broker = open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source);
    install_v2_m1_fake_stripe(&mut broker);
    let expected = crate::sentence::print_rule(&rules.rules[0]);

    let allowed = broker
        .request_capability_with_sentence(
            "rule-text-allow",
            &rules,
            v2_m1_refund_request("ch_rule_text"),
        )
        .unwrap();
    assert_eq!(allowed.decision, Decision::Allow);
    let stored: Option<String> = broker
        .state
        .query_row(
            "SELECT matched_rule FROM requests WHERE id=?1",
            rusqlite::params![allowed.request_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored.as_deref(), Some(expected.as_str()));
    let decisions = broker.audit.events_of_type("policy_decision").unwrap();
    assert_eq!(
        decisions.last().unwrap().data["matched_rule"],
        json!(expected)
    );
    let history = broker.history().unwrap();
    let allow_row = history
        .iter()
        .find(|row| row.request_id.as_deref() == Some(allowed.request_id.as_str()))
        .expect("the allowed request is in history");
    assert_eq!(allow_row.matched_rule.as_deref(), Some(expected.as_str()));

    let mut over_limit = v2_m1_refund_request("ch_rule_text_over");
    over_limit.resource = json!({"charge":"ch_rule_text_over","amount":50000});
    let denied = broker
        .request_capability_with_sentence("rule-text-deny", &rules, over_limit)
        .unwrap();
    assert_eq!(denied.decision, Decision::Deny);
    let stored: Option<String> = broker
        .state
        .query_row(
            "SELECT matched_rule FROM requests WHERE id=?1",
            rusqlite::params![denied.request_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, None);
    let decisions = broker.audit.events_of_type("policy_decision").unwrap();
    assert!(
        decisions.last().unwrap().data.get("matched_rule").is_none(),
        "a deny names no admitting rule"
    );
}

#[test]
fn v2_m2_out_of_bounds_sentence_request_denies_with_exact_safe_widen_hint() {
    let rules = v2_m1_rules_with_limit(5000);
    let source = Arc::new(V2M1SentenceAuthority::new(rules.clone()));
    let (_dir_guard, dir) = fresh_broker_dir();
    let mut broker = open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source);
    install_v2_m1_fake_stripe(&mut broker);
    let before = v2_m1_grant_count(&broker);
    let mut request = v2_m1_refund_request("ch_sentence_over_limit");
    request.resource = json!({"charge":"ch_sentence_over_limit", "amount":50000});

    let outcome = broker
        .request_capability_with_sentence("sentence-over-limit", &rules, request)
        .unwrap();

    let expected_hint =
        "to allow: cermet rules allow 'stripe.refund where amount <= 50000'".to_string();
    assert_eq!(outcome.decision, Decision::Deny);
    assert_eq!(outcome.hint.as_deref(), Some(expected_hint.as_str()));
    assert!(outcome.grant_id.is_none());
    assert_eq!(v2_m1_grant_count(&broker), before, "a hint mints no grant");
}

#[test]
fn v2_m3_sentence_denials_fail_closed_at_the_broker_mint_boundary() {
    struct Case {
        name: &'static str,
        rules: crate::sentence::RuleSet,
        amount: i64,
        expected: crate::sentence::Decision,
        reason: &'static str,
        /// The widening path a deny teaches, when there is one. A refusal the agent
        /// cannot act on stays hintless; a verb no rule mentions names the allow that admits it.
        hint: Option<&'static str>,
    }

    let parse = |text: &str| {
        let mut rules = crate::sentence::parse_rules(text).unwrap();
        crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
        rules
    };
    let explicit_deny = parse(
        "allow stripe.refund where amount <= 20000\n\
             deny stripe.refund where amount >= 10001",
    );
    let unmatched = parse("allow stripe.get_charge");
    let incompatible_deny = parse(
        "deny stripe.refund where amount = \"not_an_integer\"\n\
             allow stripe.refund where amount <= 5000",
    );
    let mut parser_invalid_json = serde_json::to_value(parse(
        "deny stripe.refund where charge = \"blocked\"\n\
             allow stripe.refund where amount <= 5000",
    ))
    .unwrap();
    parser_invalid_json["rules"][0]["conjuncts"][0]["eq"]["field"] = json!("Charge");
    let parser_invalid_deny: crate::sentence::RuleSet =
        serde_json::from_value(parser_invalid_json).unwrap();
    let mut unresolved_digest = crate::sentence::parse_rules(&format!(
        "deny {} where amount >= 1\n\
             allow stripe.refund where amount <= 5000",
        pinned_set("stripe", "support")
    ))
    .unwrap();
    let crate::sentence::Selector::Set { digest, .. } = &mut unresolved_digest.rules[0].selector
    else {
        unreachable!()
    };
    *digest = Some(format!("sha256:{}", "0".repeat(64)));
    let unresolved_contract_projection = parse(&format!(
        "deny {} where absent_from_every_member = \"blocked\"\n\
             allow stripe.refund where amount <= 5000",
        pinned_set("stripe", "support")
    ));
    let cases = [
        Case {
            name: "explicit_deny_precedes_allow",
            rules: explicit_deny,
            amount: 15000,
            expected: crate::sentence::Decision::Deny {
                reason: crate::sentence::DenyReason::ExplicitDeny { rule_idx: 1 },
            },
            // The typed `rule_idx` above stays zero-based (it indexes the corpus);
            // the rendered reason numbers it the way `cermet rules` lists it.
            reason: "stripe.refund denied by sentence authority rule 2",
            hint: None,
        },
        Case {
            name: "ordinary_unmatched_request",
            rules: unmatched,
            amount: 2300,
            expected: crate::sentence::Decision::Deny {
                reason: crate::sentence::DenyReason::NoMatchingRule,
            },
            reason: "stripe.refund denied by sentence authority: no rule matches this request",
            hint: Some(
                "to allow: cermet rules allow 'stripe.refund where charge = \"ch_v2_m3_ordinary_unmatched_request\"'",
            ),
        },
        Case {
            name: "schema_incompatible_covering_deny",
            rules: incompatible_deny,
            amount: 2300,
            expected: crate::sentence::Decision::Deny {
                reason: crate::sentence::DenyReason::UnresolvedDeny { rule_idx: 0 },
            },
            reason: "stripe.refund denied by sentence authority: rule 1 could not be resolved",
            hint: None,
        },
        Case {
            name: "parser_invalid_public_serde_deny",
            rules: parser_invalid_deny,
            amount: 2300,
            expected: crate::sentence::Decision::Deny {
                reason: crate::sentence::DenyReason::UnresolvedDeny { rule_idx: 0 },
            },
            reason: "stripe.refund denied by sentence authority: rule 1 could not be resolved",
            hint: None,
        },
        Case {
            name: "unresolved_historical_set_digest",
            rules: unresolved_digest,
            amount: 2300,
            expected: crate::sentence::Decision::Deny {
                reason: crate::sentence::DenyReason::UnresolvedDeny { rule_idx: 0 },
            },
            reason: "stripe.refund denied by sentence authority: rule 1 could not be resolved",
            hint: None,
        },
        Case {
            name: "unresolved_set_member_contract_projection",
            rules: unresolved_contract_projection,
            amount: 2300,
            expected: crate::sentence::Decision::Deny {
                reason: crate::sentence::DenyReason::UnresolvedDeny { rule_idx: 0 },
            },
            reason: "stripe.refund denied by sentence authority: rule 1 could not be resolved",
            hint: None,
        },
    ];

    let source = Arc::new(V2M1SentenceAuthority::new(cases[0].rules.clone()));
    let (_dir_guard, dir) = fresh_broker_dir();
    let mut broker =
        open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source.clone());
    let provider_calls = install_v2_m1_fake_stripe(&mut broker);
    let refund_contract = broker.templates.resolve("stripe", "refund").unwrap();

    for case in cases {
        source.activate(case.rules.clone());
        let fingerprint = crate::sentence::authority_digest(&case.rules);
        let charge = format!("ch_v2_m3_{}", case.name);
        let resource = CanonicalResource::from_stored(
            &json!({"amount": case.amount, "charge": charge}).to_string(),
            refund_contract,
        )
        .unwrap();
        assert_eq!(
            broker.evaluate_sentence(&case.rules, "stripe", "refund", &resource),
            case.expected,
            "{}: shared evaluator decision drifted",
            case.name
        );

        let grants_before = v2_m1_grant_count(&broker);
        let calls_before = *provider_calls.lock().unwrap();
        let outcome = broker
            .request_capability_with_sentence(
                &format!("v2-{}", case.name),
                &case.rules,
                v2_m1_refund_request_at(&charge, case.amount),
            )
            .unwrap();

        assert_eq!(outcome.decision, Decision::Deny, "{}", case.name);
        assert_eq!(outcome.reason, case.reason, "{}", case.name);
        assert_eq!(
            outcome.hint.as_deref(),
            case.hint,
            "{}: the deny's widening path drifted",
            case.name
        );
        assert!(outcome.grant_id.is_none(), "{}", case.name);
        assert_eq!(v2_m1_grant_count(&broker), grants_before, "{}", case.name);

        let execute_error = broker
            .execute_request_for_principal_attributed(
                &outcome.request_id,
                LOCAL_REQUESTER,
                &ExecAttribution::default(),
            )
            .unwrap_err();
        assert!(
            execute_error
                .to_string()
                .contains("no grant for request_id"),
            "{}: denied request unexpectedly became executable: {execute_error}",
            case.name
        );
        assert_eq!(
            *provider_calls.lock().unwrap(),
            calls_before,
            "{}",
            case.name
        );
        assert_eq!(v2_m1_grant_count(&broker), grants_before, "{}", case.name);

        let request: (String, String, String) = broker
            .state
            .query_row(
                "SELECT decision, reason, policy_fingerprint FROM requests WHERE id=?1",
                rusqlite::params![&outcome.request_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            request,
            ("deny".into(), case.reason.into(), fingerprint.clone())
        );
        let decisions = broker.audit.events_of_type("policy_decision").unwrap();
        let decision = decisions.last().unwrap();
        assert_eq!(decision.summary, case.reason, "{}", case.name);
        assert_eq!(decision.data["decision"], json!("deny"), "{}", case.name);
        assert_eq!(
            decision.data["authority_kind"],
            json!("sentence"),
            "{}",
            case.name
        );
        assert_eq!(
            decision.data["authority_fingerprint"],
            json!(fingerprint),
            "{}",
            case.name
        );
        let denials = broker.audit.events_of_type("capability_denied").unwrap();
        let denial = denials.last().unwrap();
        assert_eq!(denial.summary, case.reason, "{}", case.name);
        assert_eq!(denial.data["deny_class"], json!("policy"), "{}", case.name);
        assert_eq!(
            denial.data["authority_kind"],
            json!("sentence"),
            "{}",
            case.name
        );
        assert_eq!(
            denial.data["authority_fingerprint"],
            json!(fingerprint),
            "{}",
            case.name
        );
    }
}

/// The OWNING test for the deny-reason surface class.
///
/// A deny that names a rule is an instruction: the operator reads the number, finds that line in
/// `cermet rules`, and widens or revokes it. So the number printed here must be the number the list
/// prints, which is also the number `cermet rules revoke` takes — the reason must never ship the
/// raw zero-based slice index while the list renders `idx + 1`, or every such deny would name the
/// PRECEDING sentence, and `revoke <that number>` would destroy an unrelated capability.
///
/// The check is deliberately a round trip rather than a string match: parse the number back out of
/// the rendered reason, run `run_revoke`'s own arithmetic on it, and require that it lands on the
/// rule the typed decision says ruled. The typed `rule_idx` on the wire stays zero-based; only the
/// rendering converts.
#[test]
fn a_denys_rule_number_is_the_number_the_list_prints_and_revoke_takes() {
    struct Case {
        name: &'static str,
        text: &'static str,
        amount: i64,
        /// Where the ruling sentence sits in the corpus, zero-based — deliberately never 0, so an
        /// off-by-one cannot pass by coincidence.
        ruling_idx: usize,
    }

    let cases = [
        Case {
            name: "explicit_deny",
            text: "allow stripe.get_charge\n\
                   allow stripe.refund where amount <= 20000\n\
                   deny stripe.refund where amount >= 10001",
            amount: 15000,
            ruling_idx: 2,
        },
        Case {
            name: "predicate_mismatch",
            text: "allow stripe.get_charge\n\
                   allow stripe.list_active_prices\n\
                   allow stripe.refund where amount <= 5000",
            amount: 50000,
            ruling_idx: 2,
        },
        Case {
            name: "unresolved_deny",
            text: "allow stripe.get_charge\n\
                   deny stripe.refund where amount = \"not_an_integer\"\n\
                   allow stripe.refund where amount <= 5000",
            amount: 2300,
            ruling_idx: 1,
        },
    ];

    let parse = |text: &str| {
        let mut rules = crate::sentence::parse_rules(text).unwrap();
        crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
        rules
    };

    let first = parse(cases[0].text);
    let source = Arc::new(V2M1SentenceAuthority::new(first));
    let (_dir_guard, dir) = fresh_broker_dir();
    let mut broker =
        open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source.clone());
    install_v2_m1_fake_stripe(&mut broker);

    for case in cases {
        let rules = parse(case.text);
        source.activate(rules.clone());
        let charge = format!("ch_{}", case.name);
        let outcome = broker
            .request_capability_with_sentence(
                &format!("sess_{}", case.name),
                &rules,
                v2_m1_refund_request_at(&charge, case.amount),
            )
            .unwrap();
        assert_eq!(outcome.decision, Decision::Deny, "{}", case.name);

        // The number as a human reads it, lifted straight out of the rendered reason.
        let printed = outcome
            .reason
            .split_once("rule ")
            .and_then(|(_, rest)| {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                digits.parse::<usize>().ok()
            })
            .unwrap_or_else(|| panic!("{}: reason named no rule: {}", case.name, outcome.reason));

        assert_eq!(
            printed,
            crate::sentence::human_rule_number(case.ruling_idx),
            "{}: the reason must number the ruling sentence the way `cermet rules` lists it \
             ({}); got {:?}",
            case.name,
            case.ruling_idx + 1,
            outcome.reason
        );

        // `cermet rules revoke <n>` does exactly this, then indexes the corpus. Landing anywhere
        // else means the printed number destroys the wrong capability.
        let index = crate::sentence::rule_index_from_human(printed)
            .unwrap_or_else(|| panic!("{}: printed rule 0, which revoke rejects", case.name));
        assert_eq!(
            crate::sentence::print_rule(&rules.rules[index]),
            crate::sentence::print_rule(&rules.rules[case.ruling_idx]),
            "{}: revoke would have targeted a different sentence than the deny named",
            case.name
        );
    }
}

#[test]
fn v2_m1_sentence_allow_mints_a_persisted_hmac_grant_with_full_lifecycle() {
    let (_dir_guard, dir) = fresh_broker_dir();
    let profile_deny = "providers:\n  stripe:\n    deny:\n      - action: refund\n";
    let mut rules =
        crate::sentence::parse_rules("allow stripe.refund where amount <= 5000").unwrap();
    crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
    let source = Arc::new(V2M1SentenceAuthority::new(rules.clone()));
    let mut broker = open_broker_reuse_with_sentence_authority(&dir, profile_deny, source.clone());
    install_v2_m1_fake_stripe(&mut broker);
    broker.set_now(1_000_000);

    let ordinary_outcome = broker
        .request_capability("ordinary-session", v2_m1_refund_request("ch_ordinary"))
        .unwrap();
    assert_eq!(ordinary_outcome.decision, Decision::Allow);
    assert!(
        ordinary_outcome.grant_id.is_some(),
        "fixed routing sends ordinary Stripe requests to sentence authority, not the profile deny"
    );

    let outcome = broker
        .request_capability_with_sentence(
            "sentence-session",
            &rules,
            v2_m1_refund_request("ch_sentence_execute"),
        )
        .unwrap();
    assert_eq!(outcome.decision, Decision::Allow);
    let grant_id = outcome
        .grant_id
        .expect("a definite sentence allow mints a grant");
    let approved = broker.load_grant(&grant_id).unwrap();
    assert_eq!(approved.status, GrantStatus::Approved);
    assert_eq!(approved.decision, "allow");
    assert_eq!(
        approved.resource_json,
        r#"{"amount":2300,"charge":"ch_sentence_execute"}"#
    );
    broker.assert_grant_integrity(&grant_id, &approved).unwrap();
    let approved_digest = approved.grant_digest.clone();
    drop(broker);

    let mut broker = open_broker_reuse_with_sentence_authority(&dir, profile_deny, source);
    install_v2_m1_fake_stripe(&mut broker);
    broker.set_now(1_000_001);
    let persisted = broker.load_grant(&grant_id).unwrap();
    assert_eq!(persisted.status, GrantStatus::Approved);
    assert_eq!(persisted.grant_digest, approved_digest);
    broker
        .assert_grant_integrity(&grant_id, &persisted)
        .unwrap();

    assert!(broker.execute_capability(&grant_id).unwrap().ok);
    let executed = broker.load_grant(&grant_id).unwrap();
    assert_eq!(executed.status, GrantStatus::Executed);
    assert_ne!(executed.grant_digest, approved_digest);
    broker.assert_grant_integrity(&grant_id, &executed).unwrap();
    assert!(matches!(
        broker.execute_capability(&grant_id),
        Err(Error::ExecuteRefused(ExecuteRefusal::AlreadyUsed))
    ));

    broker.set_now(2_000_000);
    let expiring_id = broker
        .request_capability_with_sentence(
            "sentence-expiry-session",
            &rules,
            v2_m1_refund_request("ch_sentence_expiry"),
        )
        .unwrap()
        .grant_id
        .expect("a second definite allow mints an independent grant");
    let expiring = broker.load_grant(&expiring_id).unwrap();
    assert_eq!(expiring.status, GrantStatus::Approved);
    broker
        .assert_grant_integrity(&expiring_id, &expiring)
        .unwrap();
    broker.set_now(2_000_000 + GRANT_TTL_SECS + 1);
    assert!(matches!(
        broker.execute_capability(&expiring_id),
        Err(Error::ExecuteRefused(ExecuteRefusal::Expired))
    ));
    let expired = broker.load_grant(&expiring_id).unwrap();
    assert_eq!(expired.status, GrantStatus::Expired);
    assert_ne!(expired.grant_digest, expiring.grant_digest);
    broker
        .assert_grant_integrity(&expiring_id, &expired)
        .unwrap();

    let mut malformed = rules.clone();
    malformed.version = 2;
    let malformed_outcome = broker
        .request_capability_with_sentence(
            "sentence-malformed-session",
            &malformed,
            v2_m1_refund_request("ch_sentence_malformed"),
        )
        .unwrap();
    assert_eq!(malformed_outcome.decision, Decision::Deny);
    assert!(malformed_outcome.grant_id.is_none());
}

#[test]
fn persisted_grant_revalidates_string_budgets_before_claim_or_provider_io() {
    let rules = crate::sentence::parse_rules("allow stripe.stage_dispute_evidence").unwrap();
    let source = Arc::new(V2M1SentenceAuthority::new(rules));
    let (_dir_guard, dir) = fresh_broker_dir();
    let broker = open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source);
    let aggregate_over_cap = json!({
        "dispute":"du_persisted_aggregate",
        "access_activity_log":"x".repeat(20_000),
        "billing_address":"x".repeat(20_000),
        "cancellation_policy_disclosure":"x".repeat(20_000),
        "cancellation_rebuttal":"x".repeat(20_000),
        "customer_email_address":"x".repeat(20_000),
        "customer_name":"x".repeat(20_000),
        "customer_purchase_ip":"x".repeat(20_000),
        "product_description":"x".repeat(10_001),
    });
    for (session, original_dispute, tampered, expected_error) in [
        (
            "persisted-field-cap",
            "du_persisted_field",
            json!({
                "dispute":"du_persisted_field",
                "uncategorized_text":"x".repeat(20_001)
            }),
            "field cap",
        ),
        (
            "persisted-aggregate-cap",
            "du_persisted_aggregate",
            aggregate_over_cap,
            "aggregate cap",
        ),
    ] {
        let outcome = broker
            .request_capability(
                session,
                CapabilityRequest {
                    provider: "stripe".into(),
                    action: "stage_dispute_evidence".into(),
                    resource: json!({"dispute":original_dispute}),
                    environment: None,
                    justification: None,
                    model: None,
                },
            )
            .unwrap();
        assert_eq!(outcome.decision, Decision::Allow);
        let grant_id = outcome.grant_id.unwrap();
        let mut grant = broker.load_grant(&grant_id).unwrap();
        grant.resource_json = serde_json::to_string(&tampered).unwrap();
        let digest = broker.redigest(&grant_id, &grant, "approved");
        broker
            .state
            .execute(
                "UPDATE grants SET resource_json=?2, grant_digest=?3 WHERE id=?1",
                rusqlite::params![grant_id, grant.resource_json, digest],
            )
            .unwrap();
        let resealed = broker.load_grant(&grant_id).unwrap();
        broker.assert_grant_integrity(&grant_id, &resealed).unwrap();

        let error = broker.execute_capability(&grant_id).unwrap_err();
        assert!(error.to_string().contains(expected_error), "{error}");
        assert_eq!(
            broker.load_grant(&grant_id).unwrap().status,
            GrantStatus::Approved,
            "template-only revalidation fails before the single-use claim"
        );
    }
    assert!(broker
        .audit
        .events_of_type("capability_effect_starting")
        .unwrap()
        .is_empty());
    assert!(broker
        .audit
        .events_of_type("provider_action_failed")
        .unwrap()
        .is_empty());
}

#[test]
fn v1_m6_broker_sentence_policy_does_not_force_exact_resource_pins() {
    let broker = open_broker("providers: {}");
    let refund_contract = broker.templates.resolve("stripe", "refund").unwrap();
    assert_eq!(
        refund_contract.field_binding("charge"),
        Some(AllowBinding::ExactResourcePin),
        "the regression must exercise a real unpinned exact-resource field"
    );

    let mut rules = crate::sentence::parse_rules(&format!(
        "allow {} where amount <= 5000",
        pinned_set("stripe", "support")
    ))
    .unwrap();
    crate::sentence::pin_set_references(&mut rules, &crate::sets::VendoredSetResolver).unwrap();
    let stored_rule = crate::sentence::print_rule(&rules.rules[0]);
    assert!(
        stored_rule.starts_with("allow stripe.support@sha256:")
            && stored_rule.ends_with(" where amount <= 5000")
            && !stored_rule.contains("charge"),
        "the stored sentence pins the set digest but not the charge: {stored_rule}"
    );

    let matching = CanonicalResource::from_stored(
        r#"{"amount":2300,"charge":"ch_arbitrary_not_authored"}"#,
        refund_contract,
    )
    .unwrap()
    .as_match_value();
    let over_limit = CanonicalResource::from_stored(
        r#"{"amount":5001,"charge":"ch_equally_unpinned"}"#,
        refund_contract,
    )
    .unwrap()
    .as_match_value();
    let read_repo_contract = broker.templates.resolve("github", "read_repo").unwrap();
    let unmatched =
        CanonicalResource::from_stored(r#"{"owner":"acme","name":"widgets"}"#, read_repo_contract)
            .unwrap()
            .as_match_value();
    let policy = broker.sentence_policy(&rules);

    for (provider, action, resource, expected, typed) in [
        ("stripe", "refund", matching, Decision::Allow, None),
        (
            "stripe",
            "refund",
            over_limit,
            Decision::Deny,
            // The evaluator's OWN answer, kept beside the prose it renders into. The over-limit
            // request failed the rule's only conjunct — `amount <= 5000` — and the typed reason
            // says exactly that, where the prose says it in words.
            Some(crate::sentence::DenyReason::PredicateMismatch {
                rule_idx: 0,
                pred_idx: 0,
                field: Some("amount".into()),
            }),
        ),
        (
            "github",
            "read_repo",
            unmatched,
            Decision::Deny,
            Some(crate::sentence::DenyReason::NoMatchingRule),
        ),
    ] {
        let verdict = crate::policy::PolicyEvaluator::evaluate(
            &policy,
            &Query {
                provider,
                action,
                resource: &resource,
            },
        );
        assert_eq!(
            verdict.decision, expected,
            "{provider}.{action}: {}",
            verdict.reason
        );
        assert_eq!(
            verdict.deny_reason, typed,
            "{provider}.{action}: the typed refusal survives the seam that renders the prose"
        );
    }
}

// ---- exhaustive matcher: a present-unpinned Identity/SideEffect field => Ask ----
// The dropped `deploy` once anchored the whole matrix; the surviving vendored `deploy` now
// carries the Identity-pin / FreePayload cases (project+repo_id+environment
// execution targets, free `ref`), and the surviving `set_env_var` carries the SideEffect-pin cases
// (its optional, NON-target `git_branch` ExactResourcePin). The matcher branch for "a present,
// unpinned ExactResourcePin field downgrades an allow to ask" is class-agnostic, so the SideEffect
// cases prove it for what `deploy.repo_id` used to.

fn deploy_with(extra: Value) -> CapabilityRequest {
    let mut r = json!({ "project": "orchestra", "repo_id": 123, "ref": "main" });
    if let Value::Object(m) = extra {
        for (k, v) in m {
            r[k] = v;
        }
    }
    CapabilityRequest {
        provider: "vercel".into(),
        action: "deploy".into(),
        resource: r,
        environment: Some("preview".into()),
        justification: None,
        model: None,
    }
}

fn set_env_with(extra: Value) -> CapabilityRequest {
    let mut r = json!({ "project": "orchestra", "name": "NEXT_PUBLIC_API", "value": "https://api.example" });
    if let Value::Object(m) = extra {
        for (k, v) in m {
            r[k] = v;
        }
    }
    CapabilityRequest {
        provider: "vercel".into(),
        action: "set_env_var".into(),
        resource: r,
        environment: Some("preview".into()),
        justification: None,
        model: None,
    }
}

// ── The absent optional exact-pin field must not ride free ─────────────────────

// A present, unpinned ExactResourcePin field downgrading an allow to ask has no surviving
// non-target Int Identity anchor (the vendored `deploy` makes `repo_id` an execution target, so an
// allow omitting it is refused at boot, not downgraded at request time). The matcher branch is
// class-agnostic and is proven identically by `matcher_downgrades_an_unpinned_side_effect_to_ask`
// over `set_env_var.git_branch`.

#[test]
fn suggestion_pins_repo_id_from_the_binding_model() {
    // Direct unit check of `widening_shape` (below the `suggest_policy` flow): a non-target Int
    // Identity/ExactResourcePin field (`repo_id`) is pinned, the execution target (`project`) stays
    // pinned, and a FreePayload field (`ref`) is freed. This is the ONE surviving anchor for the
    // non-target Int Identity pin shape after the `deploy` drop — it runs directly against
    // the retired shape held as `FAKE_DEPLOY_PREVIEW`, needing no contract-source resolution.
    let shape = widening_shape(
        Some(&FAKE_DEPLOY_PREVIEW),
        "vercel",
        "deploy",
        &json!({ "project": "orchestra", "repo_id": 123, "ref": "main" }),
    )
    .unwrap()
    .expect("a shape for an anchored action with execution targets");
    assert_eq!(
        shape.pinned.get("repo_id"),
        Some(&json!(123)),
        "repo_id must be pinned: {:?}",
        shape.pinned
    );
    assert!(
        shape.pinned.contains_key("project"),
        "the execution target stays pinned: {:?}",
        shape.pinned
    );
}

// ---- The suggestion shaper gates on the CONTRACT, not the provider name ----
//
// A provider-seam contract (the daemon `files` provider, registered after construction) must be
// shapeable exactly like a built-in, and the gate must be the contract's own pinnable execution
// target — not a github/vercel allowlist.

const FILES_TEST_PATH: crate::contract::FieldDecl = crate::contract::FieldDecl {
    name: "path",
    ty: crate::contract::ScalarKind::Str,
    required: true,
    class: FieldClass::Identity,
    binding: AllowBinding::ExactResourcePin,
};
const FILES_TEST_READ: ActionContract = ActionContract {
    provider: "files",
    action: "read",
    schema: &[FILES_TEST_PATH],
    consumes: &["path"],
    execution_targets: &["path"],
    relations: &[],
    open: false,
};
const FILES_TEST_WRITE: ActionContract = ActionContract {
    provider: "files",
    action: "write",
    schema: &[FILES_TEST_PATH],
    consumes: &["path"],
    execution_targets: &["path"],
    relations: &[],
    open: false,
};

/// A minimal, credential-free stand-in for the daemon `files` provider: a pinned-path Identity
/// contract, `requires_credential() == false`, echoing the frozen path. Registered through the real
/// `register_provider` hook so the suggestion shaper reaches it the same way it reaches the
/// daemon provider.
struct FilesTestProvider;
impl Provider for FilesTestProvider {
    fn name(&self) -> &str {
        "files"
    }
    fn supported_actions(&self) -> &'static [&'static str] {
        &["read", "write"]
    }
    fn action_contract(&self, action: &str) -> Option<&'static ActionContract> {
        match action {
            "read" => Some(&FILES_TEST_READ),
            "write" => Some(&FILES_TEST_WRITE),
            _ => None,
        }
    }
    fn requires_credential(&self) -> bool {
        false
    }
    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        Ok(ProviderResponse {
            proof: None,
            ok: true,
            failure_class: None,
            result: json!({ "path": call.resource.req_str("path")? }),
            retained: None,
            envelope: Default::default(),
        })
    }
}

fn files_read_req(path: &str) -> CapabilityRequest {
    CapabilityRequest {
        provider: "files".into(),
        action: "read".into(),
        resource: json!({ "path": path }),
        environment: None,
        justification: None,
        model: None,
    }
}

// A MIXED-target seam contract: `tenant` is an ExactResourcePin execution target, `path` is ALSO an
// execution target but Unbound — the latent shape the gate generalization allowed. An allow can
// pin `tenant` but never `path`, so this contract must be non-suggestable and its allow must fail
// closed rather than auto-run an unconstrained executing field.
const MIX_TENANT: crate::contract::FieldDecl = crate::contract::FieldDecl {
    name: "tenant",
    ty: crate::contract::ScalarKind::Str,
    required: true,
    class: FieldClass::Identity,
    binding: AllowBinding::ExactResourcePin,
};
const MIX_PATH: crate::contract::FieldDecl = crate::contract::FieldDecl {
    name: "path",
    ty: crate::contract::ScalarKind::Str,
    required: true,
    class: FieldClass::FreePayload,
    binding: AllowBinding::Unbound,
};
const MIXED_SEAM_WRITE: ActionContract = ActionContract {
    provider: "mix",
    action: "write",
    schema: &[MIX_TENANT, MIX_PATH],
    consumes: &["tenant", "path"],
    execution_targets: &["tenant", "path"],
    relations: &[],
    open: false,
};

struct MixTestProvider;
impl Provider for MixTestProvider {
    fn name(&self) -> &str {
        "mix"
    }
    fn supported_actions(&self) -> &'static [&'static str] {
        &["write"]
    }
    fn action_contract(&self, action: &str) -> Option<&'static ActionContract> {
        match action {
            "write" => Some(&MIXED_SEAM_WRITE),
            _ => None,
        }
    }
    fn requires_credential(&self) -> bool {
        false
    }
    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        Ok(ProviderResponse {
            proof: None,
            ok: true,
            failure_class: None,
            result: json!({ "tenant": call.resource.req_str("tenant")? }),
            retained: None,
            envelope: Default::default(),
        })
    }
}

fn mix_write_req(tenant: &str, path: &str) -> CapabilityRequest {
    CapabilityRequest {
        provider: "mix".into(),
        action: "write".into(),
        resource: json!({ "tenant": tenant, "path": path }),
        environment: None,
        justification: None,
        model: None,
    }
}

#[test]
fn widening_shape_mixed_target_routes_to_not_suggestable() {
    // One ExactResourcePin target + one Unbound target. A pinned allow could constrain `tenant` but
    // never `path`, so shaping one would emit an allow that auto-runs an unconstrained executing
    // field. The gate demands EVERY execution target be pinnable -> not_suggestable.
    let r = widening_shape(
        Some(&MIXED_SEAM_WRITE),
        "mix",
        "write",
        &json!({ "tenant": "acme", "path": "/etc/passwd" }),
    );
    let reason = match r {
        Err(reason) => reason,
        Ok(_) => panic!(
            "a mixed (partially Unbound) execution-target contract must route to not_suggestable, not shape"
        ),
    };
    assert!(
        reason.contains("no scopable execution target"),
        "honest reason: {reason}"
    );
}

#[test]
fn widening_shape_pinnable_target_rule() {
    // A contract with a pinnable exact-pin execution target -> shapeable.
    assert!(
        widening_shape(
            Some(&FILES_TEST_READ),
            "files",
            "read",
            &json!({ "path": "/w/x" })
        )
        .expect("a pinnable target does not hard-error")
        .is_some(),
        "an exact-pin execution target yields a shape"
    );

    // A contract whose execution target is NOT exact-pin routes to not_suggestable with the honest
    // reason — this proves the gate is the BINDING, not mere non-emptiness of execution_targets.
    const NON_PIN_TARGET: ActionContract = ActionContract {
        provider: "seam",
        action: "wibble",
        schema: &[crate::contract::FieldDecl {
            name: "sel",
            ty: crate::contract::ScalarKind::Str,
            required: true,
            class: FieldClass::Identity,
            binding: AllowBinding::Unbound,
        }],
        consumes: &["sel"],
        execution_targets: &["sel"],
        relations: &[],
        open: false,
    };
    let reason = match widening_shape(
        Some(&NON_PIN_TARGET),
        "seam",
        "wibble",
        &json!({ "sel": "a" }),
    ) {
        Err(reason) => reason,
        Ok(_) => {
            panic!("a non-exact-pin execution target must route to not_suggestable, not shape")
        }
    };
    assert!(
        reason.contains("no scopable execution target"),
        "honest reason: {reason}"
    );

    // The MOCK_CONTRACT shape: a target-less open contract is likewise not_suggestable, not skipped.
    const OPEN_NO_TARGET: ActionContract = ActionContract {
        provider: "seam",
        action: "poke",
        schema: &[],
        consumes: &[],
        execution_targets: &[],
        relations: &[],
        open: true,
    };
    assert!(
        widening_shape(Some(&OPEN_NO_TARGET), "seam", "poke", &json!({ "x": 1 })).is_err(),
        "a target-less contract routes to not_suggestable, never silently skipped"
    );

    // No contract at all -> silent skip (Ok(None)): an uncontracted action cannot be shaped honestly.
    assert!(
        matches!(
            widening_shape(None, "seam", "poke", &json!({ "x": 1 })),
            Ok(None)
        ),
        "an uncontracted action is silently skipped, not shaped or errored"
    );
}

#[test]
fn a_sentence_denial_does_not_persist_a_secret_classed_field_value() {
    // A sentence deny for an action whose contract DOES resolve still redacts by class: the secret
    // field never reaches the requests row, the history view, or the denial event's
    // `canonical_request`. The row is lossless for everything else — this is the
    // one thing write-time redaction still removes.
    let rules = crate::sentence::parse_rules("allow github.get_repo").unwrap();
    let source = Arc::new(V2M1SentenceAuthority::new(rules));
    let b = open_broker_with_sentence_authority_and_templates(
        "providers: {}",
        source,
        vec![SECRET_TEMPLATE.to_string()],
    );
    let secret = "s3cr3t-app-value-never-log-me";
    let denied = b.request_capability("s1", set_webhook_req(secret)).unwrap();
    assert_eq!(denied.decision, Decision::Deny, "{}", denied.reason);

    let hist = b.history().unwrap();
    let blob = serde_json::to_string(&hist).unwrap();
    assert!(
        !blob.contains(secret) && blob.contains("[redacted: secret]"),
        "the denial row renders the marker, never the value: {blob}"
    );
    assert_eq!(
        hist[0].resource["owner"],
        json!("acme"),
        "the non-secret values still render: {}",
        hist[0].resource
    );
    for ev in b.audit.events_of_type("capability_denied").unwrap() {
        let blob = serde_json::to_string(&ev).unwrap();
        assert!(
            !blob.contains(secret),
            "a denial event must not carry the secret value: {blob}"
        );
    }
}
// ---- Deny is a guarded, Requested-only transition (mirrors approve) ----

fn grant_principal(b: &Broker, grant_id: &str) -> Option<String> {
    b.state
        .query_row(
            "SELECT principal_id FROM grants WHERE id=?1",
            rusqlite::params![grant_id],
            |r| r.get::<_, Option<String>>(0),
        )
        .unwrap()
}

#[test]
fn execute_by_unknown_or_unapproved_request_is_refused() {
    let b = open_broker_fake_vercel(VERCEL_ASK_DEPLOY, true);
    b.connect_credential("vercel", None, "vercel_demo_secret_123456789")
        .unwrap();
    b.set_now(1_000);
    // an unknown handle (nonexistent request id)
    assert!(
        b.execute_request_for_principal("req_does_not_exist", "uid:501")
            .is_err(),
        "an unknown request id cannot execute"
    );
    // a real, owned, but still-unapproved request
    let outcome = b
        .request_capability_for_principal("s1", "uid:501", vercel_deploy_req("orchestra", "main"))
        .unwrap();
    assert!(
        b.execute_request_for_principal(&outcome.request_id, "uid:501")
            .is_err(),
        "an unapproved request cannot execute"
    );
}

#[test]
fn principal_label_is_none_for_a_missing_unknown_or_malformed_id() {
    // Fail-to-None, never a guess: an unknown uid, a non-`uid:` principal, and garbage all resolve
    // to no label (so the UI falls back to the raw id / nothing).
    assert_eq!(
        resolve_principal_label("uid:4294967290"),
        None,
        "an unknown uid resolves to no label"
    );
    assert_eq!(
        resolve_principal_label("operator:uid=501"),
        None,
        "a non-`uid:` principal has no OS label"
    );
    assert_eq!(resolve_principal_label("uid:notanumber"), None);
    assert_eq!(resolve_principal_label(""), None);
}

// ---- Requests-backed views, approval provenance, operation lifecycle, unified proposals ----

#[test]
fn policy_deny_is_visible_in_history_and_status() {
    let policy = "providers:\n  vercel:\n    deny:\n      - action: deploy\n";
    let b = open_broker_fake_vercel(policy, true);
    let out = b
        .request_capability("s1", vercel_deploy_req("orchestra", "main"))
        .unwrap();
    assert_eq!(out.decision, Decision::Deny);
    // A policy deny mints NO grant — but the request log makes it visible with its reason.
    assert!(
        requested_grant_opt(&b).is_none(),
        "a policy deny mints no grant"
    );
    let hist = b.history().unwrap();
    assert_eq!(hist.len(), 1, "the denial is a visible history row");
    assert_eq!(hist[0].decision, "deny");
    assert!(hist[0].reason.is_some(), "the denial carries its reason");
    // The status verb answers a typed denied terminal, not "no such request".
    let status = b.request_status(&out.request_id).unwrap();
    assert_eq!(status.status, "terminal");
    assert_eq!(status.phase.as_deref(), Some("terminal"));
    assert_eq!(status.outcome.as_deref(), Some("denied"));
}

#[test]
fn unregistered_and_unsupported_requests_are_recorded() {
    let b = open_broker_fake_vercel(VERCEL_ASK_DEPLOY, true);
    let unreg = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "nope".into(),
                action: "x".into(),
                resource: json!({}),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    assert_eq!(unreg.decision, Decision::Deny);
    let unregistered_status = b.request_status(&unreg.request_id).unwrap();
    assert_eq!(unregistered_status.status, "terminal");
    assert_eq!(unregistered_status.outcome.as_deref(), Some("denied"));
    let unsup = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "vercel".into(),
                action: "nope".into(),
                resource: json!({}),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    let unsupported_status = b.request_status(&unsup.request_id).unwrap();
    assert_eq!(unsupported_status.status, "terminal");
    assert_eq!(unsupported_status.outcome.as_deref(), Some("denied"));
    assert_eq!(b.history().unwrap().len(), 2, "both refusals are visible");
}

#[test]
fn executing_status_round_trips() {
    assert_eq!(status_str(GrantStatus::Executing), "executing");
    assert_eq!(parse_status("executing").unwrap(), GrantStatus::Executing);
}

// ---- Denial-row redaction and retention ----

#[test]
fn denied_request_row_redacts_a_secret_field_at_rest() {
    // A DENIED request must NOT persist its secret-classed field value in requests.resource_json:
    // a deny never executes, so the value has no functional need to survive at rest, and the
    // template classifies `webhook_secret` as secret at request time.
    let raw = "sk-DENIED-SECRET-XYZ";
    let policy = "providers:\n  github:\n    deny:\n      - action: set_webhook\n";
    let b = open_broker_with_templates(policy, vec![SECRET_TEMPLATE.to_string()]).unwrap();
    let out = b.request_capability("s1", set_webhook_req(raw)).unwrap();
    assert_eq!(
        out.decision,
        Decision::Deny,
        "policy denies set_webhook: {}",
        out.reason
    );

    // Read the requests row RAW from SQLite, beneath any view-layer redaction.
    let stored: String = b
        .state
        .query_row(
            "SELECT resource_json FROM requests WHERE provider='github' AND action='set_webhook'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        !stored.contains(raw),
        "the raw secret must never persist in the requests row at rest: {stored}"
    );
    assert!(
        stored.contains("[redacted: secret]"),
        "the secret field stores the redaction marker: {stored}"
    );

    // History/status still work and never leak the value.
    let hist = b.history().unwrap();
    assert!(
        hist.iter()
            .any(|g| g.action == "set_webhook" && g.decision == "deny"),
        "the denial is visible in history"
    );
    assert!(
        !serde_json::to_string(&hist).unwrap().contains(raw),
        "no history view carries the secret"
    );
}

#[test]
fn unresolved_action_request_row_retains_capped_values_at_rest() {
    // A request whose action resolves to NO contract RETAINS its submitted values — that row is
    // the only signal for a verb we do not gate, and "what did they ask for" is the question it
    // exists to answer. The values are size-capped so one request cannot write an unbounded blob
    // into `state.db`; a capped self-labelled secret can still be planted this way, an accepted
    // residual.
    let b = open_broker("providers: {}");
    let huge = "x".repeat(1000);
    let req = CapabilityRequest {
        provider: "vercel".into(),
        action: "set_env_var_typo".into(),
        resource: json!({ "value": "prod-db-url", "blob": huge, "count": 7 }),
        environment: None,
        justification: None,
        model: None,
    };
    let out = b.request_capability("s1", req).unwrap();
    assert_eq!(
        out.decision,
        Decision::Deny,
        "an unresolved action denies: {}",
        out.reason
    );

    // Read the requests row RAW from SQLite, beneath any view-layer rendering.
    let stored: String = b
            .state
            .query_row(
                "SELECT resource_json FROM requests WHERE provider='vercel' AND action='set_env_var_typo'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert!(
        stored.contains("prod-db-url") && stored.contains("\"count\":7"),
        "submitted values are retained as submitted: {stored}"
    );
    assert!(
        !stored.contains(&huge) && stored.contains("[truncated: 1000 bytes]"),
        "an oversized value is capped to its prefix plus the truncation marker: {stored}"
    );

    // History shows the row with its reason AND its values (the whole point of the row).
    let hist = b.history().unwrap();
    let row = hist
        .iter()
        .find(|g| g.action == "set_env_var_typo")
        .expect("the unresolved-action denial is visible in history");
    assert!(row.reason.is_some(), "the denial carries its reason");
    assert_eq!(
        row.resource["value"],
        json!("prod-db-url"),
        "the history view renders the retained value: {}",
        row.resource
    );
}

#[test]
fn denied_history_view_renders_the_stored_values() {
    // A denial row is LOSSLESS on the read side — it renders exactly
    // what `record_request` stored. Write-time redaction is the only redaction on this path, so a
    // secret-classed field shows its marker while every other submitted value renders verbatim.
    let raw = "sk-DENIED-SECRET-XYZ";
    let policy = "providers:\n  github:\n    deny:\n      - action: set_webhook\n";
    let b = open_broker_with_templates(policy, vec![SECRET_TEMPLATE.to_string()]).unwrap();
    let out = b.request_capability("s1", set_webhook_req(raw)).unwrap();
    assert_eq!(out.decision, Decision::Deny, "{}", out.reason);

    let hist = b.history().unwrap();
    let row = hist
        .iter()
        .find(|g| g.action == "set_webhook")
        .expect("the denial is a history row");
    assert_eq!(
        (&row.resource["owner"], &row.resource["name"]),
        (&json!("acme"), &json!("website")),
        "the submitted non-secret values render verbatim: {}",
        row.resource
    );
    assert_eq!(
        row.resource["webhook_secret"],
        json!("[redacted: secret]"),
        "the secret-classed field keeps its write-time marker: {}",
        row.resource
    );
    assert!(
        !serde_json::to_string(&hist).unwrap().contains(raw),
        "no history view carries the secret"
    );
}

/// A provider that canonicalizes WITHOUT a contract — the only shape that reaches `deny()`'s
/// contract-less fallback carrying a scope, since the default canonicalization requires a contract.
struct ContractlessSeam;

impl crate::provider::Provider for ContractlessSeam {
    fn name(&self) -> &str {
        "seam"
    }
    fn supported_actions(&self) -> &'static [&'static str] {
        &["poke"]
    }
    fn action_contract(&self, _action: &str) -> Option<&'static ActionContract> {
        None
    }
    fn requires_credential(&self) -> bool {
        false
    }
    fn canonicalize(&self, _action: &str, raw: &Value) -> Result<CanonicalResource> {
        let mut fields = BTreeMap::new();
        for (name, value) in raw.as_object().cloned().unwrap_or_default() {
            let scalar = crate::contract::Scalar::infer(&name, &value)?;
            fields.insert(name, scalar);
        }
        Ok(CanonicalResource::from_map(fields))
    }
    fn execute(&self, _call: crate::provider::ProviderCall) -> Result<ProviderResponse> {
        panic!("a denied request never executes")
    }
}

#[test]
fn a_contractless_sentence_denial_caps_the_canonical_request_it_records() {
    // `deny()`'s fallback arm: sentence authority AND no resolvable contract at once. With no field
    // classes to redact against, the denial event's `canonical_request` retains what was submitted,
    // size-capped — it never destroys the values.
    let rules = crate::sentence::parse_rules("allow mock-vercel.deploy").unwrap();
    let source = Arc::new(V2M1SentenceAuthority::new(rules));
    let mut broker =
        open_broker_with_sentence_authority_and_templates("providers: {}", source, Vec::new());
    broker
        .providers
        .insert("seam".into(), Box::new(ContractlessSeam));
    let denied = broker
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "seam".into(),
                action: "poke".into(),
                resource: json!({ "target": "orchestra", "blob": "z".repeat(900) }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    assert_eq!(denied.decision, Decision::Deny, "{}", denied.reason);

    let events = broker.audit.events_of_type("capability_denied").unwrap();
    let canonical =
        &events.last().expect("the denial is audited").data["canonical_request"]["resource"];
    assert_eq!(
        canonical["target"],
        json!("orchestra"),
        "the submitted value is retained: {canonical}"
    );
    let blob = canonical["blob"]
        .as_str()
        .expect("the capped value is a string");
    assert!(
        blob.starts_with("zzz") && blob.ends_with("[truncated: 900 bytes]") && blob.len() < 320,
        "the oversized value is capped, not destroyed: {blob}"
    );
}

#[test]
fn grant_digest_binds_template_hash() {
    let key = subkey(&[5u8; 32], b"grant");
    let d = |t: Option<&str>| {
        grant_digest(
            &key,
            "g1",
            "r1",
            "github",
            "test_two_step_write",
            r#"{"owner":"a"}"#,
            r#"{"kind":"none","version":1}"#,
            r#"{"kind":"none","version":1}"#,
            "ask",
            "fp",
            "approved",
            "s1",
            "desc1",
            Some(123),
            Some("uid:1"),
            t,
            None,
            None,
            None,
            None,
            None,
        )
    };
    assert_ne!(
        d(None),
        d(Some("hashA")),
        "adding a template_hash changes the digest"
    );
    assert_ne!(
        d(Some("hashA")),
        d(Some("hashB")),
        "a different template_hash changes the digest"
    );
}

// ---- W2: the extra-provider registration hook + the credential-free execute path ----
//
// The daemon-owned `files` provider holds no secret and is registered onto the live broker after
// construction. These tests cover the two core seams that make that possible: `register_provider`
// (with a fail-closed duplicate-name error) and an execute that never touches the vault for a
// provider that declares it needs no credential.

const NOAUTH_POKE: ActionContract = ActionContract {
    provider: "noauth",
    action: "poke",
    schema: &[crate::contract::FieldDecl {
        name: "path",
        ty: crate::contract::ScalarKind::Str,
        required: true,
        class: FieldClass::Identity,
        binding: AllowBinding::ExactResourcePin,
    }],
    consumes: &["path"],
    execution_targets: &["path"],
    relations: &[],
    open: false,
};

/// A minimal credential-free provider: it declares `requires_credential() == false` and echoes the
/// frozen `path` back, so the broker's execute path can be exercised with no stored secret.
struct NoAuthProvider;
impl Provider for NoAuthProvider {
    fn name(&self) -> &str {
        "noauth"
    }
    fn supported_actions(&self) -> &'static [&'static str] {
        &["poke"]
    }
    fn action_contract(&self, action: &str) -> Option<&'static ActionContract> {
        (action == "poke").then_some(&NOAUTH_POKE)
    }
    fn requires_credential(&self) -> bool {
        false
    }
    fn execute(&self, call: ProviderCall) -> Result<ProviderResponse> {
        assert!(
            call.token.is_empty(),
            "a credential-free provider must be called with no token"
        );
        Ok(ProviderResponse {
            proof: None,
            ok: true,
            failure_class: None,
            result: json!({ "poked": call.resource.req_str("path")? }),
            retained: None,
            envelope: Default::default(),
        })
    }
}

#[test]
fn register_provider_adds_a_provider_and_refuses_a_duplicate_name() {
    let mut b = open_broker("providers:\n  noauth:\n    ask:\n      - action: poke\n");
    b.register_provider(Box::new(NoAuthProvider))
        .expect("a fresh provider registers");
    assert!(
        b.register_provider(Box::new(NoAuthProvider)).is_err(),
        "a duplicate provider name must fail closed, never silently shadow"
    );

    // A built-in name is refused too — registration can never override a default provider.
    struct DupMockVercel;
    impl Provider for DupMockVercel {
        fn name(&self) -> &str {
            "mock-vercel"
        }
        fn supported_actions(&self) -> &'static [&'static str] {
            &[]
        }
        fn action_contract(&self, _: &str) -> Option<&'static ActionContract> {
            None
        }
        fn execute(&self, _: ProviderCall) -> Result<ProviderResponse> {
            unreachable!("never dispatched")
        }
    }
    assert!(
        b.register_provider(Box::new(DupMockVercel)).is_err(),
        "registering over a built-in provider name must fail closed"
    );
}

/// As [`audit_events_of_type`], but with each row's SEVERITY beside its data — the oracle for the
/// severity tier an event class lands in.
fn audit_rows_of_type(b: &Broker, ty: &str) -> Vec<(String, Value)> {
    let conn = rusqlite::Connection::open(b.dir.join("audit.db")).unwrap();
    let mut stmt = conn
        .prepare("SELECT severity, data_json FROM audit_events WHERE type=?1 ORDER BY rowid")
        .unwrap();
    let rows = stmt
        .query_map(rusqlite::params![ty], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .unwrap();
    rows.map(|r| {
        let (severity, data) = r.unwrap();
        (severity, serde_json::from_str(&data).unwrap())
    })
    .collect()
}

/// The plaintext audit events (data_json) of a given type, read from the broker's on-disk audit
/// DB (a hash chain, not encrypted). Contract events carry `session_id = NULL`, so they are not
/// reachable via `events_for_session`; a direct read is the honest oracle here.
fn audit_events_of_type(b: &Broker, ty: &str) -> Vec<Value> {
    let conn = rusqlite::Connection::open(b.dir.join("audit.db")).unwrap();
    let mut stmt = conn
        .prepare("SELECT data_json FROM audit_events WHERE type=?1 ORDER BY rowid")
        .unwrap();
    let rows = stmt
        .query_map(rusqlite::params![ty], |r| r.get::<_, String>(0))
        .unwrap();
    rows.map(|r| serde_json::from_str(&r.unwrap()).unwrap())
        .collect()
}

/// A one-shot HTTP server that accepts ONE connection, drains the request, and replies 200 with
/// `body`. Returns its base URL and a handle yielding the raw request text.
fn one_shot_ok(body: &'static str) -> (String, std::thread::JoinHandle<String>) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut data = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&tmp[..n]);
            if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&data[..pos]).to_lowercase();
                let want = headers
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while data.len() < pos + 4 + want {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 {
                        break;
                    }
                    data.extend_from_slice(&tmp[..n]);
                }
                break;
            }
        }
        let req = String::from_utf8_lossy(&data).into_owned();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(resp.as_bytes()).unwrap();
        req
    });
    (format!("http://{addr}"), handle)
}

/// A single-step acme read template — the language speaking to a provider that has NO compiled
/// Rust struct, only a ratified descriptor.
const ACME_READ_TEMPLATE: &str = "provider: acme\naction: read_thing\nfields:\n  - { name: id, type: str, required: true, class: identity, binding: exact_resource_pin }\nconsumes: [id]\nexecution_targets: [id]\nhttp:\n  steps:\n    - id: get\n      method: GET\n      path: /things/{id}\n";

fn acme_req() -> CapabilityRequest {
    CapabilityRequest {
        provider: "acme".into(),
        action: "read_thing".into(),
        resource: json!({ "id": "widget" }),
        environment: None,
        justification: None,
        model: None,
    }
}

#[test]
fn connect_refused_for_a_descriptorless_provider() {
    // Connect honesty: no descriptor ⇒ no origin the token could ever ride to ⇒ refuse rather than
    // silently vault an unusable credential.
    let b = open_broker("providers: {}\n");
    let err = b
        .connect_credential("acme", None, "acme_tok_x")
        .expect_err("a descriptor-less provider connect must be refused");
    assert!(
        err.to_string().contains("no ratified provider descriptor"),
        "the refusal names the missing descriptor: {err}"
    );
    assert!(
        b.list_credentials().unwrap().is_empty(),
        "nothing is vaulted for a descriptor-less provider"
    );
}

struct TestLockdown {
    engaged: std::sync::atomic::AtomicBool,
    checks: std::sync::Mutex<usize>,
    engage_at: usize,
}

impl TestLockdown {
    fn mutable(engaged: bool) -> Arc<Self> {
        Arc::new(Self {
            engaged: std::sync::atomic::AtomicBool::new(engaged),
            checks: std::sync::Mutex::new(0),
            engage_at: usize::MAX,
        })
    }
}

impl LockdownSource for TestLockdown {
    fn is_engaged(&self) -> bool {
        let mut checks = self.checks.lock().expect("lockdown check counter");
        *checks += 1;
        let check = *checks;
        self.engaged.load(std::sync::atomic::Ordering::SeqCst) || check >= self.engage_at
    }
}

#[test]
fn lockdown_blocks_mint_without_creating_a_grant() {
    let mut b = open_broker_fake_vercel(ALLOW_DEPLOY, true);
    b.set_lockdown_source(TestLockdown::mutable(true));

    // Deny-all is a DECISION the owner made, so it answers on the typed channel with a receipt —
    // not an `Err` the agent wire renders as "internal error", leaving the operator who engaged
    // the lockdown unable to see who kept knocking.
    let outcome = b
        .request_capability("s1", deploy_req())
        .expect("a lockdown refusal is a decision, never an Err");
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.reason.contains("owner lockdown is engaged"));
    assert!(
        outcome.reason.contains("cermet owner lockdown clear"),
        "the refusal names the command that lifts it: {}",
        outcome.reason
    );
    assert!(requested_grant_opt(&b).is_none());
    let row: (String, String) = b
        .state
        .query_row(
            "SELECT decision, reason FROM requests WHERE id=?1",
            rusqlite::params![&outcome.request_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the refusal has a receipt row");
    assert_eq!(row, ("deny".to_string(), outcome.reason.clone()));
}

#[test]
fn a_caller_supplied_session_closed_before_the_request_applies_is_refused() {
    let b = open_broker_fake_vercel(VERCEL_ASK_DEPLOY, true);
    b.connect_credential("vercel", None, "vercel_demo_secret_123456789")
        .unwrap();
    b.set_now(1_000);
    b.open_session("sess_live", "agent", None, None, SessionActor::default())
        .unwrap();
    assert!(b.session_open("sess_live").unwrap());
    b.close_session("sess_live").unwrap();

    let res = b.request_capability_for_principal_open(
        "sess_live",
        "uid:501",
        vercel_deploy_req("orchestra", "main"),
        true,
        None,
    );
    assert!(
        matches!(res, Err(Error::SessionExpired)),
        "a closed caller-supplied session is refused, got {res:?}"
    );
    let minted: i64 = b
        .state
        .query_row(
            "SELECT COUNT(*) FROM grants WHERE session_id='sess_live'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(minted, 0);
}

#[test]
fn a_daemon_minted_session_still_auto_creates_on_request() {
    let b = open_broker_fake_vercel(VERCEL_ASK_DEPLOY, true);
    b.connect_credential("vercel", None, "vercel_demo_secret_123456789")
        .unwrap();
    b.set_now(1_000);
    b.request_capability_for_principal_open(
        "fresh",
        "uid:501",
        vercel_deploy_req("orchestra", "main"),
        false,
        None,
    )
    .expect("a daemon-minted session auto-creates");
    assert!(b.session_open("fresh").unwrap());
}

#[test]
fn artifact_stored_is_bound_to_the_grants_session() {
    let b = open_broker(ALLOW_DEPLOY);
    b.open_session("s1", "agent-A", None, None, SessionActor::default())
        .unwrap();
    let stored = b
        .store_artifact_capped("rq-session-bound", b"retained output\n", 1024, Some("s1"))
        .unwrap();

    let events = b.audit.events_for_session("s1").unwrap();
    let art = events
        .iter()
        .find(|event| event.event_type == "artifact_stored")
        .expect("the artifact_stored event is homed under the grant session");
    assert_eq!(art.data["digest"], json!(stored.digest));
    assert_eq!(art.session_id.as_deref(), Some("s1"));
}

const MOCK_ALLOW: &str = "providers:\n  mock-vercel:\n    allow:\n      - action: deploy\n        scope: { environment: preview }\n";

fn mock_cand() -> CapabilityRequest {
    CapabilityRequest {
        provider: "mock-vercel".into(),
        action: "deploy".into(),
        resource: json!({}),
        environment: Some("preview".into()),
        justification: None,
        model: None,
    }
}

#[test]
fn supplied_session_from_a_foreign_peer_is_refused() {
    let b = open_broker(MOCK_ALLOW);
    b.connect_credential("mock-vercel", None, "mock_demo_secret_123456789")
        .unwrap();
    b.open_session(
        "sess_owned",
        "agent",
        Some(4242),
        Some(501),
        SessionActor::default(),
    )
    .unwrap();

    let foreign = b.request_capability_for_principal_open(
        "sess_owned",
        "uid:502",
        mock_cand(),
        true,
        Some(502),
    );
    assert!(matches!(foreign, Err(Error::SessionExpired)));
    let minted: i64 = b
        .state
        .query_row("SELECT COUNT(*) FROM grants", [], |r| r.get(0))
        .unwrap();
    assert_eq!(minted, 0);

    let owner = b.request_capability_for_principal_open(
        "sess_owned",
        "uid:501",
        mock_cand(),
        true,
        Some(501),
    );
    assert!(owner.is_ok(), "the owning peer uid is accepted: {owner:?}");
}

#[test]
fn null_owned_session_supplied_by_attested_peer_is_refused() {
    let b = open_broker(MOCK_ALLOW);
    b.connect_credential("mock-vercel", None, "mock_demo_secret_123456789")
        .unwrap();
    b.open_session(
        "sess_orphan",
        "legacy-cli",
        None,
        None,
        SessionActor::default(),
    )
    .unwrap();

    let res = b.request_capability_for_principal_open(
        "sess_orphan",
        "uid:502",
        mock_cand(),
        true,
        Some(502),
    );
    assert!(matches!(res, Err(Error::SessionExpired)));
    let minted: i64 = b
        .state
        .query_row("SELECT COUNT(*) FROM grants", [], |r| r.get(0))
        .unwrap();
    assert_eq!(minted, 0);

    let exec = ExecAttribution {
        session_id: Some("sess_orphan".into()),
        pid: Some(1),
        require_session_open: true,
        peer_uid: Some(502),
    };
    assert!(matches!(
        b.require_supplied_session_open(&exec),
        Err(Error::SessionExpired)
    ));
}

#[test]
fn lazy_minted_session_records_the_peer_owner() {
    let b = open_broker(MOCK_ALLOW);
    b.connect_credential("mock-vercel", None, "mock_demo_secret_123456789")
        .unwrap();
    b.request_capability_for_principal_open("sess_lazy", "uid:501", mock_cand(), false, Some(501))
        .unwrap();
    let owner: Option<i64> = b
        .state
        .query_row(
            "SELECT owner_uid FROM sessions WHERE id='sess_lazy'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(owner, Some(501));

    b.request_capability_owned("sess_ctl", mock_cand(), Some(777))
        .unwrap();
    let ctl_owner: Option<i64> = b
        .state
        .query_row(
            "SELECT owner_uid FROM sessions WHERE id='sess_ctl'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ctl_owner, Some(777));
}

#[test]
fn in_process_peerless_caller_stays_permissive() {
    let b = open_broker(MOCK_ALLOW);
    b.connect_credential("mock-vercel", None, "mock_demo_secret_123456789")
        .unwrap();
    b.open_session(
        "sess_owned",
        "agent",
        None,
        Some(501),
        SessionActor::default(),
    )
    .unwrap();
    b.open_session("sess_orphan", "legacy", None, None, SessionActor::default())
        .unwrap();
    for sid in ["sess_owned", "sess_orphan"] {
        let res = b.request_capability_for_principal_open(sid, "uid:501", mock_cand(), true, None);
        assert!(res.is_ok(), "a peerless caller passes on {sid}: {res:?}");
    }
}

#[test]
fn a_failed_digest_audit_write_leaves_no_unchained_artifact_row() {
    let b = open_broker(ALLOW_DEPLOY);
    b.audit.fail_next_record_of("artifact_stored");
    let err = b
        .store_artifact_capped("rq-audit-fault", b"output\n", 1024, Some("s1"))
        .unwrap_err();
    assert!(matches!(err, Error::Integrity(_)));

    let rows: i64 = b
        .state
        .query_row(
            "SELECT COUNT(*) FROM artifacts WHERE request_id='rq-audit-fault'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "no artifact row exists outside the audit chain");
    assert!(b.verify_integrity().unwrap().verified);
}

fn grant_status(broker: &Broker, grant_id: &str) -> GrantStatus {
    broker.load_grant(grant_id).unwrap().status
}

struct AuditFakeGithub {
    templates: Arc<TemplateRegistry>,
}

impl Provider for AuditFakeGithub {
    fn name(&self) -> &str {
        "github"
    }

    fn supported_actions(&self) -> &'static [&'static str] {
        &["read_repo"]
    }

    fn action_contract(&self, action: &str) -> Option<&'static ActionContract> {
        self.templates.resolve("github", action)
    }

    fn execute(&self, _call: ProviderCall) -> Result<ProviderResponse> {
        Ok(ProviderResponse {
            proof: None,
            ok: true,
            failure_class: None,
            result: json!({"full_name": "acme/widgets"}),
            retained: None,
            envelope: Default::default(),
        })
    }
}

fn audit_fake_github_broker() -> TestBroker {
    let rules = crate::sentence::parse_rules(
        "allow github.read_repo where owner = \"acme\" and name = \"widgets\"",
    )
    .unwrap();
    let source = Arc::new(V2M1SentenceAuthority::new(rules));
    let mut broker =
        open_broker_with_sentence_authority_and_templates("providers: {}", source, catalog());
    let templates = broker.templates.clone();
    broker
        .providers
        .insert("github".into(), Box::new(AuditFakeGithub { templates }));
    broker
        .connect_credential("github", None, "github_demo_secret_123456789")
        .unwrap();
    broker
}

fn audit_fake_github_request() -> CapabilityRequest {
    CapabilityRequest {
        provider: "github".into(),
        action: "read_repo".into(),
        resource: json!({"owner": "acme", "name": "widgets"}),
        environment: None,
        justification: None,
        model: None,
    }
}

#[test]
fn a_failed_terminal_audit_write_never_leaves_a_dark_consumed_grant() {
    let b = audit_fake_github_broker();
    let outcome = b
        .request_capability("s1", audit_fake_github_request())
        .unwrap();
    let grant_id = outcome.grant_id.expect("allow mints a grant");

    b.audit.fail_next_record_of("provider_action_succeeded");
    let err = b.execute_capability(&grant_id).unwrap_err();
    assert!(matches!(err, Error::Integrity(_)));
    assert_eq!(grant_status(&b, &grant_id), GrantStatus::Executing);
    assert!(!b.audit.provider_action_event_exists(&grant_id).unwrap());
}

#[test]
fn a_retry_after_a_chained_terminal_event_does_not_double_chain() {
    let b = audit_fake_github_broker();
    let outcome = b
        .request_capability("s1", audit_fake_github_request())
        .unwrap();
    let grant_id = outcome.grant_id.expect("allow mints a grant");
    b.execute_capability(&grant_id).unwrap();

    let terminal_events_before = audit_events_of_type(&b, "provider_action_succeeded").len();
    let grant = b.load_grant(&grant_id).unwrap();
    let opened = grant
        .lease_opened_at
        .expect("HTTP execution stamps a lease");
    let deadline = grant
        .lease_deadline
        .expect("HTTP execution stamps a deadline");
    let executing_digest = b.redigest_leased(&grant_id, &grant, "executing", opened, deadline);
    b.state
        .execute(
            "UPDATE grants SET status='executing', grant_digest=?2 WHERE id=?1",
            rusqlite::params![grant_id, executing_digest],
        )
        .unwrap();

    assert!(b
        .reconcile_terminal_execution(&grant_id, &b.load_grant(&grant_id).unwrap())
        .unwrap()
        .is_some());
    assert_eq!(grant_status(&b, &grant_id), GrantStatus::Executed);
    assert_eq!(
        audit_events_of_type(&b, "provider_action_succeeded").len(),
        terminal_events_before,
        "reconciliation must never double-chain the terminal event"
    );
    assert!(b.verify_integrity().unwrap().verified);
}

fn one_shot_status(
    status_line: &'static str,
    body: &'static str,
) -> (String, std::thread::JoinHandle<String>) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut data = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&tmp[..n]);
            if let Some(pos) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&data[..pos]).to_lowercase();
                let want = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while data.len() < pos + 4 + want {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 {
                        break;
                    }
                    data.extend_from_slice(&tmp[..n]);
                }
                break;
            }
        }
        let request = String::from_utf8_lossy(&data).into_owned();
        let response = format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        request
    });
    (format!("http://{addr}"), handle)
}

const STRIPE_VAULT_CANARY: &str = "sk_test_vaultcanary_9x8y7z_never_in_a_receipt";

const STRIPE_ERROR_BODY: &str = concat!(
    r#"{"error":{"type":"invalid_request_error","code":"resource_missing","#,
    r#""param":"intent","message":"No such payment_intent: 'pi_missing'. "#,
    r#"Invalid API Key provided: sk_test_vaultcanary_9x8y7z_never_in_a_receipt","#,
    r#""doc_url":"https://stripe.com/docs/error-codes/resource-missing"}}"#
);

const STRIPE_ERROR_BODY_WITH_RESOURCE: &str = concat!(
    r#"{"error":{"type":"card_error","code":"payment_intent_authentication_failure","#,
    r#""param":"payment_method","message":"The provided PaymentMethod requires authentication.","#,
    r#""decline_code":"authentication_required","#,
    r#""doc_url":"https://stripe.com/docs/error-codes/payment-intent-authentication-failure","#,
    r#""charge":"ch_3MtwBwLkdIwHu7ix","#,
    r#""payment_intent":{"id":"pi_3MtwBwLkdIwHu7ix28a3tqPa","object":"payment_intent","#,
    r#""status":"requires_action","#,
    r#""client_secret":"pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_LEAKCANARY9x8y7z","#,
    r#""next_action":{"type":"use_stripe_sdk","#,
    r#""use_stripe_sdk":{"stripe_js":"secret-bearing-provider-payload"}}}}}"#
);

const STRIPE_NESTED_CLIENT_SECRET: &str = "pi_3MtwBwLkdIwHu7ix28a3tqPa_secret_LEAKCANARY9x8y7z";

fn stripe_egress_substituted_broker(base: &str, rules: &str) -> TestBroker {
    let b = stripe_egress_broker_without_credential(base, rules);
    b.connect_credential("stripe", None, STRIPE_VAULT_CANARY)
        .unwrap();
    b
}

/// The same broker with NOTHING in the vault: the authorized effect then dies at the vault open,
/// definitively before any provider contact.
fn stripe_egress_broker_without_credential(base: &str, rules: &str) -> TestBroker {
    let descriptors = BrokerConfig::vendored_descriptors()
        .into_iter()
        .filter(|descriptor| !descriptor.contains("name: stripe\n"))
        .chain([format!(
            "name: stripe\negress:\n  - {base}\nauth: bearer\nheaders:\n  Stripe-Version: 2026-06-24.dahlia\n"
        )])
        .collect();
    let mut parsed = crate::sentence::parse_rules(rules).unwrap();
    crate::sentence::pin_set_references(&mut parsed, &crate::sets::VendoredSetResolver).unwrap();
    let (guard, dir) = fresh_broker_dir();
    let b = Broker::open_for_semantic_test(
        BrokerConfig {
            git: test_quarantine(),
            dir,
            master_key: vec![5u8; 32],
            action_templates: catalog(),
            provider_descriptors: descriptors,
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        Some(Arc::new(V2M1SentenceAuthority::new(parsed))),
    )
    .unwrap();
    TestBroker::new(guard, b)
}

#[test]
fn a_real_terminal_carries_no_retention_key() {
    let (base, server) = one_shot_status("404 Not Found", STRIPE_ERROR_BODY);
    let b = stripe_egress_substituted_broker(
        &base,
        "allow stripe.get_payment_intent where payment_intent = \"pi_missing\"",
    );
    let outcome = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_payment_intent".into(),
                resource: json!({ "payment_intent": "pi_missing" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    b.execute_capability(outcome.grant_id.as_deref().unwrap())
        .unwrap();
    server.join().unwrap();
    let terminals = b.audit.events_of_type("provider_action_failed").unwrap();
    assert_eq!(terminals.len(), 1);
    assert!(terminals[0].data.get("retention").is_none());
}

#[test]
fn stripe_error_body_is_retained_as_evidence_with_the_vault_credential_redacted() {
    let (base, server) = one_shot_status("404 Not Found", STRIPE_ERROR_BODY);
    let b = stripe_egress_substituted_broker(
        &base,
        "allow stripe.get_payment_intent where payment_intent = \"pi_missing\"",
    );
    let outcome = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_payment_intent".into(),
                resource: json!({ "payment_intent": "pi_missing" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    let exec = b
        .execute_capability(outcome.grant_id.as_deref().unwrap())
        .unwrap();
    server.join().unwrap();

    assert!(!exec.ok);
    let error = &exec.result["error"]["error"];
    assert_eq!(exec.result["status"], json!(404));
    assert_eq!(error["type"], json!("invalid_request_error"));
    assert_eq!(error["code"], json!("resource_missing"));
    assert_eq!(error["param"], json!("intent"));
    assert_eq!(
        error["doc_url"],
        json!("https://stripe.com/docs/error-codes/resource-missing")
    );
    assert!(error["message"]
        .as_str()
        .unwrap()
        .contains("No such payment_intent: 'pi_missing'"));

    let serialized = serde_json::to_string(&exec.result).unwrap();
    assert!(!serialized.contains(STRIPE_VAULT_CANARY));
    assert!(serialized.contains("[SECRET_REDACTED]"));
    let failed = b.audit.events_of_type("provider_action_failed").unwrap();
    assert_eq!(failed.len(), 1);
    let recorded = serde_json::to_string(&failed[0].data).unwrap();
    assert!(!recorded.contains(STRIPE_VAULT_CANARY));
    assert_eq!(
        failed[0].data["result"]["error"]["error"]["code"],
        json!("resource_missing")
    );
    assert!(b.verify_integrity().unwrap().verified);
}

#[test]
fn retained_error_keeps_the_provider_body_whole_on_every_surface() {
    let (base, server) = one_shot_status("402 Payment Required", STRIPE_ERROR_BODY_WITH_RESOURCE);
    let b = stripe_egress_substituted_broker(
        &base,
        "allow stripe.get_payment_intent where payment_intent = \"pi_needs_auth\"",
    );
    let outcome = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_payment_intent".into(),
                resource: json!({ "payment_intent": "pi_needs_auth" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    let exec = b
        .execute_capability(outcome.grant_id.as_deref().unwrap())
        .unwrap();
    server.join().unwrap();

    assert!(!exec.ok);
    let error = &exec.result["error"]["error"];
    assert_eq!(error["type"], json!("card_error"));
    assert_eq!(
        error["code"],
        json!("payment_intent_authentication_failure")
    );
    assert_eq!(error["param"], json!("payment_method"));
    assert_eq!(error["decline_code"], json!("authentication_required"));
    assert_eq!(error["charge"], json!("ch_3MtwBwLkdIwHu7ix"));
    assert!(!error["payment_intent"].is_null());

    let serialized = serde_json::to_string(&exec.result).unwrap();
    for present in [
        STRIPE_NESTED_CLIENT_SECRET,
        "next_action",
        "use_stripe_sdk",
        "secret-bearing-provider-payload",
    ] {
        assert!(serialized.contains(present));
    }
    let failed = b.audit.events_of_type("provider_action_failed").unwrap();
    let recorded = serde_json::to_string(&failed[0].data).unwrap();
    assert!(recorded.contains(STRIPE_NESTED_CLIENT_SECRET));
    assert!(recorded.contains("next_action"));
    assert!(b.verify_integrity().unwrap().verified);
}

#[test]
fn retained_error_artifact_is_the_body_and_keeps_the_true_total_bytes() {
    let (base, server) = one_shot_status("402 Payment Required", STRIPE_ERROR_BODY_WITH_RESOURCE);
    let b = stripe_egress_substituted_broker(
        &base,
        "allow stripe.get_charge where charge = \"ch_needs_auth\"",
    );
    let outcome = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_charge".into(),
                resource: json!({ "charge": "ch_needs_auth" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    let exec = b
        .execute_capability(outcome.grant_id.as_deref().unwrap())
        .unwrap();
    server.join().unwrap();

    assert!(!exec.ok);
    let handle = exec.artifact.clone().expect("error body retained");
    let span = b
        .read_artifact(&handle, None, crate::artifacts::ArtifactReadSurface::Ctl)
        .unwrap();
    assert!(span
        .content
        .contains("payment_intent_authentication_failure"));
    for present in [
        STRIPE_NESTED_CLIENT_SECRET,
        "next_action",
        "secret-bearing-provider-payload",
    ] {
        assert!(span.content.contains(present));
    }

    let wire_stats = exec.wire_stats.expect("wire_stats on the error path");
    let full: Value = serde_json::from_str(STRIPE_ERROR_BODY_WITH_RESOURCE).unwrap();
    let sent = serde_json::to_vec(&json!({ "status": 402, "error": full }))
        .unwrap()
        .len() as u64;
    assert_eq!(wire_stats.total_bytes, sent);
    assert!(b.verify_integrity().unwrap().verified);
}

// ---- a git verb has no agent-facing request path ---------------------------------

/// A broker carrying the vendored catalog (so `github.push` is loaded) and `rules` as its corpus.
fn gitnative_broker(rules: &str) -> TestBroker {
    let mut parsed = crate::sentence::parse_rules(rules).unwrap();
    crate::sentence::pin_set_references(&mut parsed, &crate::sets::VendoredSetResolver).unwrap();
    let (guard, dir) = fresh_broker_dir();
    let broker = Broker::open_for_semantic_test(
        BrokerConfig {
            git: test_quarantine(),
            dir,
            master_key: vec![5u8; 32],
            action_templates: catalog(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        Some(Arc::new(V2M1SentenceAuthority::new(parsed))),
    )
    .unwrap();
    TestBroker::new(guard, broker)
}

#[test]
fn gitnative_a_push_is_not_requestable_from_the_agent_surface() {
    // The boundary ruling in code: the decision for a push is git's own `update` hook, driven by an
    // ordinary `git push`. Admitting an agent request for the same effect would be a SECOND
    // authorization surface for it, so the request path refuses and says what to run instead.
    //
    // And it refuses through the TYPED OUTCOME channel. An intentional refusal returned as `Err` is
    // flattened by the agent wire's infrastructure catch-all, so this signpost reached the operator
    // CLI and NOTHING else; the agent read "internal error" (measured live).
    let b = gitnative_broker("allow github.push where owner = \"acme\" and name = \"website\"");
    let outcome = b
        .request_capability_for_principal_owned(
            "s1",
            "uid:1000",
            CapabilityRequest {
                provider: "github".into(),
                action: "push".into(),
                resource: json!({
                    "owner": "acme",
                    "name": "website",
                    "branch": "main",
                    "new_oid": "a".repeat(40),
                }),
                environment: None,
                justification: None,
                model: None,
            },
            None,
        )
        .expect("an intentional refusal is a DECISION, never an Err");
    assert_eq!(outcome.decision, Decision::Deny);
    let message = outcome.reason.clone();
    assert!(message.contains("not requestable"), "{message}");
    assert!(
        message.contains("git push"),
        "the refusal names what to run instead: {message}"
    );
    // "a repository wired by `cermet connect github`" is not a
    // command an agent in a new repo can act on. The refusal states the wiring literally.
    assert!(
        message.contains("git remote set-url origin cermet::github/<owner>/<repo>"),
        "the refusal names the wiring command: {message}"
    );
    // Travelling the ordinary deny machinery is what makes the probe operator-visible: one receipt
    // row carrying the refusal verbatim, and one audited denial. Neither existed while this was an
    // `Err` — an agent hammering a painted door left no trace at all.
    let row: (String, String) = b
        .state
        .query_row(
            "SELECT decision, reason FROM requests WHERE id=?1",
            rusqlite::params![&outcome.request_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the refused request has a receipt row");
    assert_eq!(row, ("deny".to_string(), message.clone()));
    let denials = b.audit.events_of_type("capability_denied").unwrap();
    assert!(
        denials.iter().any(|event| event.summary == message),
        "the refusal is audited: {denials:?}"
    );
}

/// The FETCH half of the same refusal. It shares the request-path door with `push` and used to share
/// its WORDS too — telling an agent that asked to FETCH that "a git push is decided by git's update
/// hook".
#[test]
fn gitnative_a_fetch_refusal_speaks_fetch_not_push() {
    let b = gitnative_broker("allow github.fetch where owner = \"acme\" and name = \"website\"");
    let outcome = b
        .request_capability_for_principal_owned(
            "s1",
            "uid:1000",
            CapabilityRequest {
                provider: "github".into(),
                action: "fetch".into(),
                resource: json!({ "owner": "acme", "name": "website" }),
                environment: None,
                justification: None,
                model: None,
            },
            None,
        )
        .expect("an intentional refusal is a DECISION, never an Err");
    assert_eq!(outcome.decision, Decision::Deny);
    let message = outcome.reason.clone();
    assert!(message.contains("not requestable"), "{message}");
    assert!(
        message.contains("git fetch") && message.contains("git clone"),
        "the refusal names the fetch-side commands: {message}"
    );
    assert!(
        !message.contains("git push"),
        "a fetch refusal never describes itself as a push: {message}"
    );
    assert!(
        message.contains("git remote set-url origin cermet::github/<owner>/<repo>"),
        "the refusal names the wiring command: {message}"
    );
    // The fetch probe is receipted too — the class the door hammers most.
    let reason: String = b
        .state
        .query_row(
            "SELECT reason FROM requests WHERE id=?1",
            rusqlite::params![&outcome.request_id],
            |row| row.get(0),
        )
        .expect("the refused request has a receipt row");
    assert_eq!(reason, message);
}

#[test]
fn gitnative_an_ordinary_http_verb_is_still_requestable() {
    // The refusal above must be keyed on the EXECUTION KIND, not on the provider or a name.
    let b =
        gitnative_broker("allow github.read_repo where owner = \"acme\" and name = \"website\"");
    let outcome = b
        .request_capability_for_principal_owned(
            "s1",
            "uid:1000",
            CapabilityRequest {
                provider: "github".into(),
                action: "read_repo".into(),
                resource: json!({ "owner": "acme", "name": "website" }),
                environment: None,
                justification: None,
                model: None,
            },
            None,
        )
        .expect("an http verb is unaffected");
    assert_eq!(outcome.decision, Decision::Allow, "{}", outcome.reason);
}

// ---------------------------------------------------------------------------
// The loopback relay end to end inside the broker
// (adversaries T1/T2 on the predicate, T3 on the handle)
// ---------------------------------------------------------------------------

const RELAY_ALLOW: &str =
    "allow vercel.deploy where project = \"website\" and target = \"preview\" and team = \"personal\"";
/// The vaulted credential in these tests. Every assertion that it never reaches a client-facing
/// surface keys on this exact string.
const RELAY_TOKEN: &str = "vercel_tok_NEVER_IN_A_CLIENT_RESPONSE";

/// A loopback upstream that serves `responses` in order and records every request it received,
/// headers included — so a test can prove what the relay attached and what it dropped.
fn relay_upstream(
    responses: Vec<(u16, &'static str)>,
) -> (
    String,
    std::sync::mpsc::Receiver<String>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        for (status, body) in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut data = Vec::new();
            let mut tmp = [0u8; 1024];
            while let Ok(n) = stream.read(&mut tmp) {
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&tmp[..n]);
                if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&data[..pos]).to_lowercase();
                    let want = headers
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    while data.len() < pos + 4 + want {
                        let Ok(n) = stream.read(&mut tmp) else { break };
                        if n == 0 {
                            break;
                        }
                        data.extend_from_slice(&tmp[..n]);
                    }
                    break;
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&data).into_owned());
            let reason = if (200..300).contains(&status) {
                "OK"
            } else {
                "Forbidden"
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    (format!("http://{addr}"), rx, handle)
}

/// A broker whose vercel descriptor points at `base`, with a connected credential and an allow for
/// exactly one project. The relay listen authority is a declared setting, so the test declares it too.
fn relay_broker(base: &str) -> TestBroker {
    relay_broker_with_allow(base, RELAY_ALLOW)
}

/// The same relay fixture under a DIFFERENT sentence, so a test can pin a different frozen project
/// without every other relay test moving.
fn relay_broker_with_allow(base: &str, allow: &str) -> TestBroker {
    let descriptors = BrokerConfig::vendored_descriptors()
        .into_iter()
        .filter(|descriptor| !descriptor.contains("name: vercel\n"))
        .chain([format!("name: vercel\negress:\n  - {base}\nauth: bearer\n")])
        .collect();
    let mut parsed = crate::sentence::parse_rules(allow).unwrap();
    crate::sentence::pin_set_references(&mut parsed, &crate::sets::VendoredSetResolver).unwrap();
    let (guard, dir) = fresh_broker_dir();
    let mut broker = Broker::open_for_semantic_test(
        BrokerConfig {
            git: test_quarantine(),
            dir,
            master_key: vec![5u8; 32],
            action_templates: catalog(),
            provider_descriptors: descriptors,
            artifacts: crate::artifacts::ArtifactConfig::default(),
        },
        Some(Arc::new(V2M1SentenceAuthority::new(parsed))),
    )
    .unwrap();
    broker.set_relay_config(crate::relay::RelayConfig {
        listen: "127.0.0.1:7133".into(),
        ttl_secs: 600,
        max_body_bytes: 64 * 1024,
    });
    broker
        .connect_credential("vercel", None, RELAY_TOKEN)
        .unwrap();
    TestBroker::new(guard, broker)
}

fn relay_request(project: &str) -> CapabilityRequest {
    CapabilityRequest {
        provider: "vercel".into(),
        action: "deploy".into(),
        resource: json!({ "project": project, "target": "preview", "team": "personal" }),
        environment: None,
        justification: None,
        model: None,
    }
}

/// Request -> allow -> execute, returning the minted relay handle and the execute receipt.
fn open_relay(broker: &Broker, project: &str) -> (String, ExecutionResult) {
    let outcome = broker
        .request_capability("s1", relay_request(project))
        .expect("the allow admits the request");
    let result = broker
        .execute_capability(outcome.grant_id.as_deref().expect("an allowed grant"))
        .expect("executing a relay verb opens its session");
    let handle = result.result["relay"]["handle"]
        .as_str()
        .expect("the receipt names the handle")
        .to_string();
    (handle, result)
}

#[test]
fn relay_execute_returns_a_usable_handle_and_never_a_credential() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (handle, result) = open_relay(&broker, "website");

    assert!(result.ok);
    let receipt = serde_json::to_string(&result.result).unwrap();
    assert!(
        !receipt.contains(RELAY_TOKEN),
        "the execute receipt carries a capability handle, never the vaulted credential: {receipt}"
    );
    assert!(
        handle.starts_with("cermet_relay_") && handle.len() >= 22,
        "the handle names itself inert and stays high-entropy: {handle}"
    );
    assert!(
        handle
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "the vercel CLI refuses a `--token` containing `-` or `.`: {handle}"
    );
    // The receipt tells the agent exactly how to invoke the native CLI.
    let invocation = result.result["relay"]["invocation"].as_str().unwrap();
    assert_eq!(
        invocation,
        format!(
            "vercel deploy --api http://127.0.0.1:7133 --token {handle} --project website --yes"
        )
    );
    assert_eq!(
        result.result["relay"]["api_base"], "http://127.0.0.1:7133",
        "the api base is the DECLARED relay listen authority"
    );
    assert!(result.result["relay"]["expires_at"].is_i64());
    assert_eq!(broker.live_relay_sessions(), 1);
    assert!(broker.verify_integrity().unwrap().verified);
}

/// In an UNLINKED directory the native CLI guesses the project from the FOLDER NAME, and
/// that guess collides with the frozen `project` the sentence approved — the create's `body.name`
/// misses its bind, the hop is refused, and the single-use grant is burned. The receipt's
/// invocation therefore NAMES the frozen project, so the CLI never guesses. No authority moved:
/// the per-hop bind still refuses a mismatch; the flag only stops the CLI from manufacturing one.
#[test]
fn the_invocation_names_the_frozen_project_so_the_cli_never_guesses() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker_with_allow(
        &base,
        "allow vercel.deploy where project = \"cermet-site\" and target = \"preview\" and team = \"personal\"",
    );
    let (handle, result) = open_relay(&broker, "cermet-site");

    assert_eq!(
        result.result["relay"]["invocation"].as_str().unwrap(),
        format!(
            "vercel deploy --api http://127.0.0.1:7133 --token {handle} --project cermet-site --yes"
        )
    );
}

/// The same class of defect on the other frozen field: a window frozen to
/// `target = production` printed an invocation with no `--prod`, so the CLI attempted a PREVIEW
/// deployment, the create's `body.target` missed its bind, the hop was refused, and the grant
/// burned. The invocation renders `--prod` exactly when the frozen target is production — read from
/// `frozen`, the map the per-hop bind compares against, so flag and enforcement cannot disagree.
#[test]
fn a_production_target_renders_prod_in_the_invocation() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker_with_allow(
        &base,
        "allow vercel.deploy where project = \"cermet-site\" and target = \"production\" and team = \"personal\"",
    );
    let outcome = broker
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "vercel".into(),
                action: "deploy".into(),
                resource: json!({ "project": "cermet-site", "target": "production", "team": "personal" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .expect("the allow admits the request");
    let result = broker
        .execute_capability(outcome.grant_id.as_deref().expect("an allowed grant"))
        .expect("executing a relay verb opens its session");
    let invocation = result.result["relay"]["invocation"].as_str().unwrap();
    assert!(
        invocation.ends_with("--yes --prod"),
        "a production window tells the CLI so: {invocation}"
    );
}

/// The preview invocation stays flagless — `vercel deploy` without `--prod` IS the preview form.
#[test]
fn a_preview_target_renders_no_prod_flag() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (_, result) = open_relay(&broker, "website");
    let invocation = result.result["relay"]["invocation"].as_str().unwrap();
    assert!(
        !invocation.contains("--prod"),
        "a preview window must not claim production: {invocation}"
    );
}

/// The name is COPIED from the grant, never a constant: a different frozen project renders its own.
#[test]
fn a_different_frozen_project_renders_its_own_name() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (_, result) = open_relay(&broker, "website");

    let invocation = result.result["relay"]["invocation"].as_str().unwrap();
    assert!(
        invocation.contains(" --project website "),
        "the frozen project of THIS grant: {invocation}"
    );
    assert!(
        !invocation.contains("cermet-site"),
        "no other grant's project leaks in: {invocation}"
    );
}

/// The invocation is a string an agent PASTES INTO A SHELL, so a project value carrying shell
/// metacharacters would otherwise become command substitution in the agent's own shell (T1: injected
/// content steering the request's project value; T2: a fat-fingered name). Nothing constrains a `str`
/// field's charset (`contract.rs` canonicalizes any JSON string), so the composer quotes.
#[test]
fn a_shell_meaningful_project_is_quoted_in_the_invocation() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker_with_allow(
        &base,
        "allow vercel.deploy where project = \"site; touch /tmp/pwned\" and target = \"preview\" and team = \"personal\"",
    );
    let (_, result) = open_relay(&broker, "site; touch /tmp/pwned");

    let invocation = result.result["relay"]["invocation"].as_str().unwrap();
    assert!(
        invocation.contains("--project 'site; touch /tmp/pwned' --yes"),
        "a shell-meaningful project is single-quoted, so the shell sees one argument: {invocation}"
    );
}

/// The invocation's argument quoting, directly. A real Vercel project name renders bare;
/// anything else is single-quoted, including an embedded `'` — the one character a single-quoted
/// shell string cannot hold, so it closes, escapes, and reopens.
#[test]
fn shell_arg_quotes_only_what_a_shell_would_reinterpret() {
    use crate::broker::relay::shell_arg;
    assert_eq!(shell_arg("cermet-site"), "cermet-site");
    assert_eq!(shell_arg("my_app.v2"), "my_app.v2");
    assert_eq!(shell_arg(""), "''");
    assert_eq!(shell_arg("two words"), "'two words'");
    assert_eq!(shell_arg("a;b`c$d"), "'a;b`c$d'");
    assert_eq!(shell_arg("it's"), r"'it'\''s'");
}

/// The audited handle prefix has to keep CORRELATING two rows to one session, which a
/// constant `cermet_relay_` head would not do — so the projection names the random part.
#[test]
fn the_audited_handle_prefix_names_the_random_part_not_the_constant() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (handle_a, _) = open_relay(&broker, "website");
    let (handle_b, _) = open_relay(&broker, "website");
    let opened = audit_events_of_type(&broker, "relay_session_opened");
    let prefixes: Vec<&str> = opened
        .iter()
        .map(|e| e["handle_prefix"].as_str().expect("an audited prefix"))
        .collect();
    assert_ne!(
        prefixes[0], prefixes[1],
        "two sessions must be distinguishable by their audited prefix: {prefixes:?}"
    );
    for (prefix, handle) in prefixes.iter().zip([&handle_a, &handle_b]) {
        assert!(
            handle.contains(*prefix),
            "the prefix is drawn from the handle's random part: {prefix} / {handle}"
        );
        assert!(
            !prefix.starts_with("cermet"),
            "a constant head correlates nothing: {prefix}"
        );
    }
    assert!(broker.verify_integrity().unwrap().verified);
}

/// T2: a burned handle surfaced through the native CLI as
/// "Authentication error. Run `vercel login`" — a lie about a capability that was SPENT, not an
/// identity that failed, and the agent that believes it re-logs-in instead of requesting a grant.
/// The refusal keeps every semantic it had (nothing forwarded, session gone); only its words and
/// its status change.
#[test]
fn a_burned_handle_answers_with_the_truth_not_an_auth_error() {
    let (base, rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    // Burn it the way a T1-steered agent does: a shape the sentence never authorized.
    let burned = broker
        .relay_hop(&handle, "GET", "/v9/projects/website/env", &[], Vec::new())
        .unwrap();
    assert_eq!(burned.status, 422);

    // ...and now the honest answer to the next hop.
    let after = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[],
            br#"{"name":"website"}"#.to_vec(),
        )
        .unwrap();
    assert!(
        after.status != 401 && after.status != 403,
        "an auth status is what makes the native CLI print its login lie, got {}",
        after.status
    );
    assert_eq!(after.status, 409);
    let body: Value = serde_json::from_slice(&after.body).expect("a provider-error-shaped body");
    let message = body["error"]["message"]
        .as_str()
        .expect("the refusal states the truth in the field the native CLI renders");
    assert!(
        message.contains("cermet:") && message.contains("single-use"),
        "the message names the mechanism that refused and why: {message}"
    );
    assert!(
        message.contains("cermet log --hops"),
        "...and where the whole trail is: {message}"
    );
    assert!(
        !message.contains(&handle) && !message.contains(RELAY_TOKEN),
        "the truth is about the capability, never the handle or the credential: {message}"
    );
    // refuse ⇒ burn is untouched: nothing forwarded, no live session left.
    assert!(rx.try_recv().is_err());
    assert_eq!(broker.live_relay_sessions(), 0);
    assert!(broker.verify_integrity().unwrap().verified);
}

/// A relay receipt is relay COORDINATES and nothing else — if it carried no id, an agent whose
/// deploy then failed would have nothing to hand `cermet log <request_id>` and diagnosis would mean
/// grepping `cermet log` and correlating timestamps. Identity is stamped at the broker seam, so it
/// is on EVERY receipt.
#[test]
fn a_relay_receipt_names_the_request_id_that_chases_it() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let outcome = broker
        .request_capability("s1", relay_request("website"))
        .expect("the allow admits the request");
    let result = broker
        .execute_capability(outcome.grant_id.as_deref().expect("an allowed grant"))
        .expect("executing a relay verb opens its session");
    assert_eq!(
        result.envelope.request_id, outcome.request_id,
        "the receipt names the id `cermet log <request_id>` takes"
    );
    assert!(
        result.result.get("request_id").is_none(),
        "identity rides the broker-authored envelope, never the verbatim provider result"
    );
    // The durable record carries the same envelope, so a reconstructed receipt is the same receipt.
    let terminal = &audit_events_of_type(&broker, "provider_action_succeeded")[0];
    assert_eq!(terminal["envelope"]["request_id"], outcome.request_id);
}

/// The other half: identity comes from the SEAM, not from the verb — an ordinary HTTP
/// verb that authors no envelope at all still hands back a receipt the agent can chase.
#[test]
fn an_ordinary_verbs_receipt_names_its_request_id_too() {
    let (base, server) = one_shot_status("404 Not Found", STRIPE_ERROR_BODY);
    let b = stripe_egress_substituted_broker(
        &base,
        "allow stripe.get_payment_intent where payment_intent = \"pi_missing\"",
    );
    let outcome = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_payment_intent".into(),
                resource: json!({ "payment_intent": "pi_missing" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    let exec = b
        .execute_capability(outcome.grant_id.as_deref().unwrap())
        .unwrap();
    server.join().unwrap();
    assert!(!exec.ok, "a failed run is exactly when the id is needed");
    assert_eq!(exec.envelope.request_id, outcome.request_id);
    assert!(
        exec.envelope.broker_metadata.is_empty(),
        "this verb authors no broker metadata; identity is still mandatory"
    );

    // The agent that needs the id is the one whose run FAILED and who is now POLLING. The
    // durable receipt read back through `request_status` -> `reconstruct_terminal_receipt` must
    // name it too, or the id is available only on the inline reply the agent may never have seen.
    let status = b.request_status(&outcome.request_id).unwrap();
    assert_eq!(status.status, "terminal");
    let receipt = status
        .terminal_receipt
        .expect("a terminal request has a durable receipt");
    assert_eq!(
        receipt["envelope"]["request_id"], outcome.request_id,
        "the polled receipt names the id `cermet log <request_id>` takes: {receipt}"
    );
}

#[test]
fn a_declared_hop_is_credentialed_on_the_outbound_side_only() {
    let (base, rx, server) = relay_upstream(vec![
        (200, r#"{"ok":true}"#),
        (
            200,
            r#"{"id":"dpl_live","url":"website-xyz.vercel.app","name":"website","readyState":"QUEUED"}"#,
        ),
        (200, r#"{"readyState":"READY"}"#),
    ]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    // 1) an upload, 2) THE deployment create, 3) a status read.
    let upload = broker
        .relay_hop(
            &handle,
            "POST",
            "/v2/files",
            &[
                ("content-type".into(), "application/octet-stream".into()),
                ("x-vercel-digest".into(), "sha1:abc".into()),
                ("cookie".into(), "session=nope".into()),
                ("authorization".into(), "Bearer agent-supplied".into()),
            ],
            b"file bytes".to_vec(),
        )
        .unwrap();
    assert_eq!(upload.status, 200);

    let create = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments?forceNew=1",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website","files":[]}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(create.status, 200);

    let read = broker
        .relay_hop(&handle, "GET", "/v13/deployments/dpl_live", &[], Vec::new())
        .unwrap();
    assert_eq!(read.status, 200);

    // What actually went upstream: the vaulted credential, exactly once per hop, and none of the
    // client's own Authorization/Cookie.
    let requests: Vec<String> = rx.iter().take(3).collect();
    server.join().unwrap();
    assert_eq!(requests.len(), 3);
    for request in &requests {
        let lower = request.to_lowercase();
        assert!(
            request.contains(&format!("Bearer {RELAY_TOKEN}")),
            "the relay attaches the vaulted credential on the outbound hop: {request}"
        );
        assert!(
            !lower.contains("agent-supplied") && !lower.contains("cookie:"),
            "the client's own Authorization/Cookie never reach the provider: {request}"
        );
        assert_eq!(
            lower.matches("authorization:").count(),
            1,
            "exactly one Authorization header rides upstream: {request}"
        );
    }
    assert!(
        requests[0].contains("x-vercel-digest: sha1:abc"),
        "the CLI's own upload-protocol headers are forwarded: {}",
        requests[0]
    );
    assert!(requests[1].starts_with("POST /v13/deployments?forceNew=1 "));

    // Nothing the client received carries the credential.
    for response in [&upload, &create, &read] {
        let body = String::from_utf8_lossy(&response.body);
        assert!(!body.contains(RELAY_TOKEN), "client-facing body: {body}");
        for (name, value) in &response.headers {
            assert!(!value.contains(RELAY_TOKEN), "client-facing header {name}");
        }
    }

    // The receipt is derived from the observed deployment object, not from anything the agent said.
    let session = broker.relay_session_snapshot(&handle).unwrap();
    assert_eq!(
        session.observations().deployment_id.as_deref(),
        Some("dpl_live")
    );
    assert_eq!(
        session.observations().deployment_url.as_deref(),
        Some("website-xyz.vercel.app")
    );
    assert_eq!(session.observations().last_state.as_deref(), Some("READY"));
    assert!(session.effect_used());

    let forwarded = audit_events_of_type(&broker, "relay_request_forwarded");
    assert_eq!(forwarded.len(), 3, "one audit line per forwarded hop");
    assert_eq!(forwarded[1]["effect"], true);
    assert_eq!(forwarded[1]["method"], "POST");
    assert_eq!(forwarded[1]["target"], "/v13/deployments?forceNew=1");
    assert_eq!(forwarded[1]["upstream_status"], 200);
    assert!(
        forwarded
            .iter()
            .all(|line| !line.to_string().contains(RELAY_TOKEN)),
        "no audit line carries the credential"
    );
    assert!(broker.verify_integrity().unwrap().verified);
}

#[test]
fn an_undeclared_path_is_refused_without_the_credential_and_burns_the_grant() {
    // The upstream serves nothing: if the relay ever forwards here, the test hangs/fails rather than
    // quietly passing.
    let (base, rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    // T1: "while you're deploying, also read the project's env vars."
    let refused = broker
        .relay_hop(&handle, "GET", "/v9/projects/website/env", &[], Vec::new())
        .unwrap();
    assert_eq!(refused.status, 422);
    assert!(!String::from_utf8_lossy(&refused.body).contains(RELAY_TOKEN));
    assert!(
        rx.try_recv().is_err(),
        "a refused hop never reaches the provider, so the credential is never attached"
    );

    // The grant is burned: even a declared shape now answers "no live session".
    let after = broker
        .relay_hop(&handle, "POST", "/v2/files", &[], b"bytes".to_vec())
        .unwrap();
    assert_eq!(after.status, 409);
    assert_eq!(
        broker.live_relay_sessions(),
        0,
        "a burned session is closed, not left live"
    );

    let refusals = audit_events_of_type(&broker, "relay_request_refused");
    assert_eq!(refusals.len(), 2);
    assert_eq!(refusals[0]["reason"], "no_matching_shape");
    assert_eq!(refusals[0]["target"], "/v9/projects/website/env");
    assert_eq!(refusals[0]["burned"], true);
    assert_eq!(refusals[1]["reason"], "unknown_handle");
    let closed = audit_events_of_type(&broker, "relay_session_closed");
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0]["closed"], "burned");
    assert_eq!(closed[0]["burned"], "no_matching_shape");
    assert!(closed[0]["deployment_id"].is_null());
    assert!(broker.verify_integrity().unwrap().verified);
}

#[test]
fn a_production_target_is_refused_without_the_credential_and_burns_the_grant() {
    let (base, rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    // T1 injection / T2 `--prod`: the same shape, one authority-bearing body key changed.
    let refused = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website","target":"production"}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(refused.status, 422);
    assert!(
        rx.try_recv().is_err(),
        "the credential is never attached to a hop that contradicts the approval"
    );
    assert_eq!(broker.live_relay_sessions(), 0);

    // And the other bind: a different project than the sentence pinned.
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    let refused = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[],
            br#"{"name":"someone-elses-site"}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(refused.status, 422);
    let refusals = audit_events_of_type(&broker, "relay_request_refused");
    assert_eq!(refusals[0]["reason"], "bind_mismatch");
    assert!(broker.verify_integrity().unwrap().verified);
}

/// At the broker seam: the frozen `team` is what the per-hop query bind compares against,
/// so a hop pointed at another team is refused WITHOUT the credential being attached, burns the
/// session, and audits as `bind_mismatch`. Same mechanism as the body binds, a different wire
/// position — the scope rode in the query string, where the matcher used to check only the KEY.
#[test]
fn a_teamid_outside_the_frozen_scope_never_reaches_the_credentialed_hop() {
    let (base, rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    // The approval froze `team = personal`, whose bind means "no teamId at all". T1: injected
    // "deploy it into the other team" — and Vercel auto-creates a project on an unknown name, so
    // this is mint-and-deploy anywhere the vaulted token reaches.
    let refused = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments?teamId=team_other",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website"}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(refused.status, 422);
    assert!(!String::from_utf8_lossy(&refused.body).contains(RELAY_TOKEN));
    assert!(
        rx.try_recv().is_err(),
        "a hop carrying a scope the approval never froze is never credentialed"
    );
    assert_eq!(
        broker.live_relay_sessions(),
        0,
        "the probed session is done"
    );

    let refusals = audit_events_of_type(&broker, "relay_request_refused");
    assert_eq!(refusals[0]["reason"], "bind_mismatch");
    assert_eq!(refusals[0]["burned"], true);
    assert!(broker.verify_integrity().unwrap().verified);
}

/// A request that omits a REQUIRED field denies as `invalid` — correct, and until now
/// silent about what to do next. Every other deny class hands the caller its next move (a policy
/// deny carries the widening sentence); this one carried `hint: None`, so an agent that omitted a
/// field learned only that its request was invalid. The hint NAMES the missing required fields, in
/// the same "here is the request that would work" register as the widening suggestion. No new
/// mechanism: the same `hint` field on the same deny path.
#[test]
fn a_request_missing_a_required_field_is_told_which_one() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let outcome = broker
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "vercel".into(),
                action: "deploy".into(),
                resource: json!({ "project": "website", "target": "preview" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .expect("an invalid request is a DECISION, not a transport error");
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.grant_id.is_none());
    let hint = outcome
        .hint
        .as_deref()
        .expect("an invalid-request deny names the caller's next move");
    assert!(
        hint.contains("team"),
        "the hint must name the missing field: {hint}"
    );
    assert!(
        !hint.contains("project") && !hint.contains("target"),
        "only the MISSING fields are named — the supplied ones were fine: {hint}"
    );

    // Two missing fields are both named, and a request that is invalid for some OTHER reason keeps
    // its own (hintless) answer rather than acquiring a misleading one.
    let outcome = broker
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "vercel".into(),
                action: "deploy".into(),
                resource: json!({ "project": "website" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .expect("a decision");
    let hint = outcome.hint.as_deref().unwrap_or_default();
    assert!(
        hint.contains("target") && hint.contains("team"),
        "both missing fields are named: {hint}"
    );
    let outcome = broker
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "vercel".into(),
                action: "deploy".into(),
                resource: json!("not an object"),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .expect("a decision");
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(
        outcome.hint.is_none(),
        "a malformed resource is not a missing-field story: {:?}",
        outcome.hint
    );
}

/// The request layer's half of the same invariant: `team` is a REQUIRED identity field, so a request
/// that names no scope has no frozen value to enforce against and never becomes a grant — fail
/// closed by construction. Named, it FREEZES onto the session and only the in-scope hop forwards.
#[test]
fn a_relay_request_that_names_no_team_never_becomes_a_grant() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let outcome = broker.request_capability(
        "s1",
        CapabilityRequest {
            provider: "vercel".into(),
            action: "deploy".into(),
            resource: json!({ "project": "website", "target": "preview" }),
            environment: None,
            justification: None,
            model: None,
        },
    );
    match outcome {
        Err(_) => {}
        Ok(outcome) => {
            assert_ne!(
                outcome.decision,
                Decision::Allow,
                "a request naming no scope must not be allowed"
            );
            assert!(outcome.grant_id.is_none());
        }
    }
    assert_eq!(broker.live_relay_sessions(), 0);

    let (base, rx, _server) = relay_upstream(vec![(
        200,
        r#"{"id":"dpl_1","url":"x.vercel.app","name":"website"}"#,
    )]);
    let broker = relay_broker_with_allow(
        &base,
        "allow vercel.deploy where project = \"website\" and target = \"preview\" and team = \"team_ours\"",
    );
    let outcome = broker
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "vercel".into(),
                action: "deploy".into(),
                resource: json!({ "project": "website", "target": "preview", "team": "team_ours" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .expect("the allow admits the scoped request");
    let result = broker
        .execute_capability(outcome.grant_id.as_deref().expect("an allowed grant"))
        .expect("executing a relay verb opens its session");
    let handle = result.result["relay"]["handle"]
        .as_str()
        .expect("the receipt names the handle")
        .to_string();
    let forwarded = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments?teamId=team_ours",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website"}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(forwarded.status, 200);
    assert!(
        rx.try_recv().is_ok(),
        "the in-scope create is the one hop that gets the credential"
    );
}

#[test]
fn an_unknown_handle_is_refused_and_reveals_nothing() {
    let (base, rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (real, _) = open_relay(&broker, "website");

    for handle in ["", "notahandle", &real.to_lowercase(), &format!("{real}x")] {
        if handle == real {
            continue;
        }
        let response = broker
            .relay_hop(handle, "POST", "/v2/files", &[], b"bytes".to_vec())
            .unwrap();
        assert_eq!(
            response.status, 409,
            "a peer uid with no handle gets nothing (T3): {handle}"
        );
        let body = String::from_utf8_lossy(&response.body);
        assert!(!body.contains(RELAY_TOKEN) && !body.contains(&real));
    }
    assert!(rx.try_recv().is_err());
    assert_eq!(
        broker.live_relay_sessions(),
        1,
        "a wrong handle never disturbs a live session"
    );
    assert!(broker.verify_integrity().unwrap().verified);
}

#[test]
fn only_one_deployment_create_is_credentialed_per_grant() {
    let (base, rx, server) = relay_upstream(vec![(
        200,
        r#"{"id":"dpl_one","url":"one.vercel.app","name":"website"}"#,
    )]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    let first = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[],
            br#"{"name":"website"}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(first.status, 200);
    let second = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[],
            br#"{"name":"website"}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(second.status, 409, "one grant, one effect");

    let requests: Vec<String> = rx.iter().take(1).collect();
    server.join().unwrap();
    assert_eq!(requests.len(), 1, "exactly one create reached the provider");
    let refusals = audit_events_of_type(&broker, "relay_request_refused");
    assert_eq!(refusals[0]["reason"], "effect_already_used");
    assert!(broker.verify_integrity().unwrap().verified);
}

#[test]
fn a_lapsed_session_closes_with_a_receipt_and_refuses_every_later_hop() {
    let (base, rx, server) = relay_upstream(vec![(
        200,
        r#"{"id":"dpl_ttl","url":"ttl.vercel.app","name":"website","readyState":"BUILDING"}"#,
    )]);
    let broker = relay_broker(&base);
    let (handle, result) = open_relay(&broker, "website");
    broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[],
            br#"{"name":"website"}"#.to_vec(),
        )
        .unwrap();
    let _ = rx.iter().take(1).count();
    server.join().unwrap();

    // Cross the declared TTL.
    let expires_at = result.result["relay"]["expires_at"].as_i64().unwrap();
    broker.set_now(expires_at + 1);

    let after = broker
        .relay_hop(&handle, "GET", "/v13/deployments/dpl_ttl", &[], Vec::new())
        .unwrap();
    assert_eq!(
        after.status, 410,
        "a lapsed TTL is Gone, not an auth failure"
    );
    assert_eq!(broker.live_relay_sessions(), 0);

    let closed = audit_events_of_type(&broker, "relay_session_closed");
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0]["closed"], "ttl");
    assert_eq!(
        closed[0]["deployment_id"], "dpl_ttl",
        "the receipt derives from the deployment object the relay observed"
    );
    assert_eq!(closed[0]["deployment_url"], "ttl.vercel.app");
    assert!(closed[0]["burned"].is_null());
    assert!(broker.verify_integrity().unwrap().verified);
}

#[test]
fn the_sweep_closes_a_lapsed_session_with_no_further_hop() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (_handle, result) = open_relay(&broker, "website");
    assert_eq!(
        broker.sweep_relay_sessions(),
        0,
        "a live session is not swept"
    );
    broker.set_now(result.result["relay"]["expires_at"].as_i64().unwrap() + 1);
    assert_eq!(broker.sweep_relay_sessions(), 1);
    assert_eq!(broker.live_relay_sessions(), 0);
    assert_eq!(
        audit_events_of_type(&broker, "relay_session_closed")[0]["closed"],
        "ttl"
    );
    assert!(broker.verify_integrity().unwrap().verified);
}

#[test]
fn lockdown_closes_a_live_relay_session_before_egress() {
    let (base, rx, _server) = relay_upstream(vec![]);
    let mut broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    broker.set_lockdown_source(TestLockdown::mutable(true));

    let response = broker
        .relay_hop(&handle, "POST", "/v2/files", &[], b"bytes".to_vec())
        .unwrap();
    assert_eq!(response.status, 409);
    assert!(
        rx.try_recv().is_err(),
        "deny-all stops a relay session mid-flight, before the credential is opened"
    );
    assert_eq!(broker.live_relay_sessions(), 0);
    assert_eq!(
        audit_events_of_type(&broker, "relay_session_closed")[0]["closed"],
        "lockdown_engaged"
    );
    assert!(broker.verify_integrity().unwrap().verified);
}

#[test]
fn a_relay_grant_is_single_use_like_every_other_grant() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let outcome = broker
        .request_capability("s1", relay_request("website"))
        .unwrap();
    let grant_id = outcome.grant_id.as_deref().unwrap();
    broker.execute_capability(grant_id).unwrap();
    let replay = broker.execute_capability(grant_id);
    assert!(
        replay.is_err(),
        "a spent relay grant cannot open a second session"
    );
    assert_eq!(broker.live_relay_sessions(), 1);
}

#[test]
fn a_production_target_is_adjudicated_by_the_sentence_not_the_template() {
    // `target` is request-authored and SENTENCE-adjudicated. Under a preview-only allow, a
    // production request matches no rule and falls to the fail-closed default — the rule
    // adjudicates, nothing is pre-frozen at ratification.
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let outcome = broker
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "vercel".into(),
                action: "deploy".into(),
                resource: json!({ "project": "website", "target": "production", "team": "personal" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .expect("the request is admitted as a decision, not a transport error");
    assert_ne!(
        outcome.decision,
        Decision::Allow,
        "a preview-only allow must not admit a production deploy"
    );
    assert!(
        outcome.grant_id.is_none() && requested_grant_opt(&broker).is_none(),
        "no grant exists for a request no sentence allowed"
    );
}

#[test]
fn an_undeclared_create_body_key_never_reaches_the_credentialed_hop() {
    // The upstream serves nothing: if any of these bodies were ever forwarded the assertion below
    // would see the request, and the vault would have been opened to attach the credential.
    let (base, rx, _server) = relay_upstream(vec![]);
    for body in [
        // Vercel's documented overrides of the fields the sentence pinned.
        r#"{"name":"website","project":"prj_someone_else"}"#,
        r#"{"name":"website","deploymentId":"dpl_not_ours"}"#,
        r#"{"name":"website","customEnvironmentSlugOrId":"prod-clone"}"#,
        // ...and a parameter Vercel might add after this predicate was ratified.
        r#"{"name":"website","someFutureParameter":true}"#,
    ] {
        let broker = relay_broker(&base);
        let (handle, _) = open_relay(&broker, "website");
        let refused = broker
            .relay_hop(
                &handle,
                "POST",
                "/v13/deployments",
                &[("content-type".into(), "application/json".into())],
                body.as_bytes().to_vec(),
            )
            .unwrap();
        assert_eq!(refused.status, 422, "{body}");
        assert!(!String::from_utf8_lossy(&refused.body).contains(RELAY_TOKEN));
        assert_eq!(
            broker.live_relay_sessions(),
            0,
            "{body}: an undeclared body key burns the session"
        );
        let refusals = audit_events_of_type(&broker, "relay_request_refused");
        assert_eq!(refusals[0]["reason"], "undeclared_body_key", "{body}");
        assert_eq!(refusals[0]["burned"], true);
        assert!(broker.verify_integrity().unwrap().verified);
    }
    assert!(
        rx.try_recv().is_err(),
        "no undeclared-key body was ever credentialed and forwarded"
    );
}

/// A refusal that will not say WHICH key it refused makes flight-widening guesswork — the
/// descriptor's own comment promises "one audited undeclared_body_key line naming it" and the
/// behavior must deliver it. Names only, never values:
/// the key name is the thing an operator needs to decide whether to ratify it; the value is the
/// agent's payload and stays out of the log.
#[test]
fn undeclared_body_key_refusal_names_the_keys_in_message_and_audit() {
    for (body, expected) in [
        (
            r#"{"name":"website","deploymentId":"dpl_evil"}"#,
            vec!["deploymentId"],
        ),
        (
            r#"{"name":"website","deploymentId":"dpl_evil","project":"other","redirects":[]}"#,
            vec!["deploymentId", "project", "redirects"],
        ),
    ] {
        let (base, _rx, _server) = relay_upstream(vec![]);
        let broker = relay_broker(&base);
        let (handle, _) = open_relay(&broker, "website");
        let refused = broker
            .relay_hop(
                &handle,
                "POST",
                "/v13/deployments",
                &[("content-type".into(), "application/json".into())],
                body.as_bytes().to_vec(),
            )
            .unwrap();
        assert_eq!(refused.status, 422, "{body}");
        let rendered = String::from_utf8_lossy(&refused.body).to_string();
        let refusals = audit_events_of_type(&broker, "relay_request_refused");
        assert_eq!(refusals[0]["reason"], "undeclared_body_key", "{body}");
        for key in &expected {
            assert!(
                rendered.contains(key),
                "the CLI-visible refusal must name {key}: {rendered}"
            );
            assert!(
                refusals[0]["undeclared_keys"]
                    .as_array()
                    .expect("the audit row carries the named keys")
                    .iter()
                    .any(|k| k.as_str() == Some(key)),
                "the audit row must name {key}: {}",
                refusals[0]
            );
        }
        // Names only: no VALUE from the refused body may appear anywhere.
        for value in ["dpl_evil", "other"] {
            assert!(
                !rendered.contains(value),
                "value leaked to the client: {rendered}"
            );
            assert!(
                !refusals[0].to_string().contains(value),
                "value leaked to the audit row: {}",
                refusals[0]
            );
        }
        assert!(broker.verify_integrity().unwrap().verified);
    }
}

/// `headers` joins the create-body allowlist: response-header config shapes how the
/// DEPLOYED SITE answers, never which project/target deploys. The rest of the vercel.json family is
/// unevidenced and still refuses — and refuses BY NAME.
#[test]
fn headers_is_admitted_and_the_unevidenced_family_still_refuses_by_name() {
    let (base, rx, server) = relay_upstream(vec![(
        200,
        r#"{"id":"dpl_ok","url":"ok.vercel.app","name":"website","readyState":"QUEUED"}"#,
    )]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    let admitted = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website","files":[],"headers":[{"source":"/(.*)","headers":[]}]}"#
                .to_vec(),
        )
        .unwrap();
    assert_eq!(
        admitted.status, 200,
        "a create body carrying `headers` deploys"
    );
    assert!(rx.try_recv().is_ok(), "the hop reached upstream");
    drop(server);

    let (base, rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    let refused = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website","redirects":[{"source":"/a","destination":"/b"}]}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(
        refused.status, 422,
        "an unevidenced family member still refuses"
    );
    assert!(
        String::from_utf8_lossy(&refused.body).contains("redirects"),
        "and it refuses BY NAME"
    );
    assert!(
        rx.try_recv().is_err(),
        "nothing was credentialed and forwarded"
    );
}

#[test]
fn the_ratified_create_payload_still_deploys() {
    let (base, rx, server) = relay_upstream(vec![(
        200,
        r#"{"id":"dpl_ok","url":"ok.vercel.app","name":"website","readyState":"QUEUED"}"#,
    )]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    let body = json!({
        "name": "website",
        "files": [],
        "projectSettings": { "framework": "nextjs" },
        "meta": {},
        "gitMetadata": { "commitMessage": "copy tweak" },
        "source": "cli",
    })
    .to_string();
    let created = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[("content-type".into(), "application/json".into())],
            body.into_bytes(),
        )
        .unwrap();
    assert_eq!(created.status, 200);
    let requests: Vec<String> = rx.iter().take(1).collect();
    server.join().unwrap();
    assert!(requests[0].contains(&format!("Bearer {RELAY_TOKEN}")));
    assert!(broker.verify_integrity().unwrap().verified);
}

/// T3: a peer uid can reach the loopback port with no handle at all. Two things must be
/// true of what that costs us: the audited target is CAPPED (the 512-byte predicate cap runs inside
/// `authorize`, which an unknown handle never reaches), and the row is NOT `high` severity —
/// "high" means a live grant is being probed, while an unauthenticated poke at an open port is
/// noise. The refusal itself is otherwise unchanged: still refused, still audited, still a
/// declared event.
#[test]
fn an_unauthenticated_refusal_is_capped_and_not_high_severity() {
    let (base, rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);

    let huge = format!("/v2/files?pad={}", "x".repeat(100_000));
    let response = broker
        .relay_hop("nohandle", "POST", &huge, &[], b"bytes".to_vec())
        .unwrap();
    assert_eq!(response.status, 409, "the refusal itself is unchanged");
    assert!(rx.try_recv().is_err());

    let rows = audit_rows_of_type(&broker, "relay_request_refused");
    assert_eq!(rows.len(), 1, "the row is kept, not dropped");
    let (severity, data) = &rows[0];
    assert_ne!(
        severity, "high",
        "unauthenticated noise must not pollute the high-severity channel"
    );
    assert_eq!(severity, "info");
    let audited = data["target"].as_str().expect("an audited target");
    assert!(
        audited.len() <= crate::templates::MAX_PREDICATE_PATH_BYTES,
        "the audited target is capped at {} bytes, got {}",
        crate::templates::MAX_PREDICATE_PATH_BYTES,
        audited.len()
    );
    assert!(
        audited.starts_with("/v2/files?pad=xxx"),
        "the cap keeps the head, so the row still says what was asked for: {audited}"
    );
    assert_eq!(
        data["target_truncated"], true,
        "a capped row says so, so nobody reads a prefix as the whole target"
    );
    assert!(broker.verify_integrity().unwrap().verified);
}

/// The authorized side keeps its severity and its full target: a refusal on a LIVE session is a probe
/// of a real grant, and its target is already bounded by the predicate cap.
#[test]
fn a_live_session_refusal_stays_high_severity_with_its_full_target() {
    let (base, _rx, _server) = relay_upstream(vec![]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    broker
        .relay_hop(&handle, "GET", "/v9/projects/website/env", &[], Vec::new())
        .unwrap();

    let rows = audit_rows_of_type(&broker, "relay_request_refused");
    assert_eq!(rows[0].0, "high", "probing a live grant is still high");
    assert_eq!(rows[0].1["target"], "/v9/projects/website/env");
    assert_eq!(rows[0].1["reason"], "no_matching_shape");
    assert!(rows[0].1["target_truncated"].is_null());
}

// ---------------------------------------------------------------------------
// Streaming pass-through
// ---------------------------------------------------------------------------

/// A loopback upstream that answers ONE request with a CHUNKED body of unknown length: it writes
/// `first` immediately and `rest` only after the returned gate is released. That is the shape of a
/// `follow=1` build-log read — a head that lands long before the last byte — and the shape a
/// buffering relay turns into a blind wait for the whole body before returning anything.
fn relay_gated_upstream(
    status: u16,
    first: String,
    rest: String,
) -> (
    String,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        // The events path is bound to the deployment THIS session created, so the gated
        // stream is preceded by the create whose response names it — one connection each.
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let created = r#"{"id":"dpl_stream","url":"stream.vercel.app","name":"website"}"#;
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{created}",
                    created.len()
                )
                .as_bytes(),
            );
            let _ = stream.flush();
        }
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        );
        let _ = stream.write_all(format!("{:x}\r\n{first}\r\n", first.len()).as_bytes());
        let _ = stream.flush();
        let _ = gate_rx.recv();
        let _ = stream.write_all(format!("{:x}\r\n{rest}\r\n0\r\n\r\n", rest.len()).as_bytes());
        let _ = stream.flush();
    });
    (format!("http://{addr}"), gate_tx, handle)
}

/// A loopback upstream that serves each response as a two-chunk CHUNKED body — no declared length,
/// so the relay can only stream it.
fn relay_chunked_upstream(responses: Vec<(u16, String)>) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        for (status, body) in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            );
            let (head, tail) = body.split_at(body.len() / 2);
            for piece in [head, tail] {
                if !piece.is_empty() {
                    let _ =
                        stream.write_all(format!("{:x}\r\n{piece}\r\n", piece.len()).as_bytes());
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n");
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), handle)
}

/// The kernel's lead behavior: the verdict completes, the head comes back, and the body is
/// pumped WHILE the upstream is still writing it — the relay no longer waits for the last byte.
#[test]
fn a_streamed_hop_hands_back_its_head_and_pumps_the_body_as_it_arrives() {
    let (base, gate, server) =
        relay_gated_upstream(200, "first-log-line\n".to_string(), "READY\n".to_string());
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    // The create first: it is what the session captures `dpl_stream` from, and it is what
    // the real CLI does before it tails a build log.
    assert_eq!(
        broker
            .relay_hop(
                &handle,
                "POST",
                "/v13/deployments",
                &[],
                br#"{"name":"website"}"#.to_vec(),
            )
            .unwrap()
            .status,
        200
    );

    let started = broker
        .relay_hop_start(
            &handle,
            "GET",
            "/v3/now/deployments/dpl_stream/events?follow=1&format=lines",
            &[],
            Vec::new(),
        )
        .unwrap();
    let RelayHopStart::Job(job) = started else {
        panic!("a declared read is authorized, not completed in place");
    };
    // The hop itself runs OFF the actor; here the test is the pump thread.
    let mut stream = job.run();
    assert_eq!(stream.head().expect("an upstream head").status, 200);

    // The upstream is STILL holding the body open here; the first chunk must already be ours.
    let first = stream.next_chunk().expect("the first chunk arrives early");
    assert_eq!(
        String::from_utf8_lossy(&first),
        "first-log-line\n",
        "the pump returns what has landed, not what is still coming"
    );
    // Nothing is audited for a hop still in flight — the row lands when the stream ENDS. The one
    // row already there is the create's, which finished before this hop started.
    assert_eq!(
        audit_events_of_type(&broker, "relay_request_forwarded").len(),
        1,
        "the streaming hop's row is written at stream end, with the total"
    );

    gate.send(()).expect("the upstream is still waiting");
    let mut rest = Vec::new();
    while let Some(chunk) = stream.next_chunk() {
        rest.extend_from_slice(&chunk);
    }
    server.join().unwrap();
    assert_eq!(String::from_utf8_lossy(&rest), "READY\n");

    broker.relay_hop_complete(stream).unwrap();
    let rows = audit_events_of_type(&broker, "relay_request_forwarded");
    assert_eq!(rows.len(), 2, "one forwarded row per hop, streamed or not");
    let streamed = &rows[1];
    assert_eq!(streamed["upstream_status"], 200);
    assert_eq!(
        streamed["response_bytes"], 21,
        "the row carries the TOTAL bytes the stream moved"
    );
    assert_eq!(streamed["effect"], false);
    assert!(streamed["response_truncated"].is_null());
    assert!(streamed["stream_error"].is_null());
    assert!(broker.verify_integrity().unwrap().verified);
}

/// The receipt still derives from what the relay observed — accumulated chunk by chunk instead of
/// read in one gulp.
#[test]
fn a_streamed_effect_hop_still_derives_its_receipt_from_the_observed_body() {
    let (base, server) = relay_chunked_upstream(vec![(
        200,
        r#"{"id":"dpl_streamed","url":"streamed.vercel.app","name":"website","readyState":"QUEUED"}"#.to_string(),
    )]);
    let broker = relay_broker(&base);
    let (handle, result) = open_relay(&broker, "website");

    let create = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[],
            br#"{"name":"website"}"#.to_vec(),
        )
        .unwrap();
    server.join().unwrap();
    assert_eq!(create.status, 200);

    broker.set_now(result.result["relay"]["expires_at"].as_i64().unwrap() + 1);
    assert_eq!(broker.sweep_relay_sessions(), 1);
    let closed = audit_events_of_type(&broker, "relay_session_closed");
    assert_eq!(
        closed[0]["deployment_id"], "dpl_streamed",
        "the receipt derives from the deployment object the STREAM observed"
    );
    assert_eq!(closed[0]["deployment_url"], "streamed.vercel.app");
    assert!(broker.verify_integrity().unwrap().verified);
}

/// The effect-release path (6aefa3f) survives streaming: a definite provider 4xx on the effect hop
/// is still a definite no-effect, which is what admits Vercel's two-phase create.
#[test]
fn a_streamed_4xx_on_the_effect_hop_still_releases_the_effect() {
    let (base, server) = relay_chunked_upstream(vec![
        (400, r#"{"error":{"code":"missing_files"}}"#.to_string()),
        (
            200,
            r#"{"id":"dpl_second","url":"second.vercel.app","name":"website"}"#.to_string(),
        ),
    ]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    let refused = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[],
            br#"{"name":"website"}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(refused.status, 400, "the provider's own refusal comes back");
    assert!(
        !broker
            .relay_session_snapshot(&handle)
            .expect("the session is live")
            .effect_used(),
        "a definite provider 4xx releases the single effect"
    );

    let created = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[],
            br#"{"name":"website"}"#.to_vec(),
        )
        .unwrap();
    server.join().unwrap();
    assert_eq!(created.status, 200, "the retry is admitted");
    assert!(broker
        .relay_session_snapshot(&handle)
        .unwrap()
        .effect_used());
    assert!(broker.verify_integrity().unwrap().verified);
}

/// The declared body cap still bounds a streamed body. The head is already on the wire by the time
/// the cap is reached, so the stream TRUNCATES where a buffered one refused — and the audit row
/// says so, rather than letting a truncated body read as a complete one.
#[test]
fn a_streamed_body_over_the_declared_cap_truncates_and_says_so() {
    let cap = 64 * 1024; // what `relay_broker` declares
    let (base, server) = relay_chunked_upstream(vec![(200, "x".repeat(cap + 4096))]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    let response = broker
        .relay_hop(&handle, "GET", "/v9/projects/website", &[], Vec::new())
        .unwrap();
    server.join().unwrap();
    assert_eq!(response.status, 200);
    assert!(
        response.body.len() <= cap,
        "the pump stops at the declared cap: {}",
        response.body.len()
    );

    let rows = audit_events_of_type(&broker, "relay_request_forwarded");
    assert_eq!(rows[0]["response_truncated"], true);
    assert_eq!(rows[0]["truncated_by"], "cap");
    assert!(
        rows[0]["response_bytes"].as_u64().unwrap() > cap as u64,
        "the row counts what the upstream actually sent before the cap tripped"
    );
    assert!(broker.verify_integrity().unwrap().verified);
}

/// A provider that echoes the credential back never hands it to the client — unchanged from the
/// buffered path, now applied per pumped chunk.
///
/// NOTE (accepted limitation): the match is per chunk, so an echo the upstream happens to split
/// across two of its own chunks is not caught. The padding below keeps the echo inside one chunk,
/// which is what this test is about. Nothing in the T1/T2/T3 list chooses where a provider frames
/// its response, and the alternative — holding back a tail of every chunk until the next one
/// lands — would delay exactly the last bytes of a log line, a stall worth avoiding.
#[test]
fn a_streamed_body_is_redacted_before_it_reaches_the_client() {
    let (base, server) = relay_chunked_upstream(vec![(
        200,
        format!(
            r#"{{"id":"dpl_echo","name":"website","echoed":"{RELAY_TOKEN}","pad":"{}"}}"#,
            "x".repeat(256)
        ),
    )]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    let response = broker
        .relay_hop(&handle, "GET", "/v9/projects/website", &[], Vec::new())
        .unwrap();
    server.join().unwrap();
    let body = String::from_utf8_lossy(&response.body).into_owned();
    assert!(
        !body.contains(RELAY_TOKEN),
        "an echoed credential never reaches the client: {body}"
    );
    assert!(body.contains("[SECRET_REDACTED]"), "{body}");
}

/// The relay's contract with the native client is transparent pass-through. A body larger
/// than one pump read gets split at a fixed byte offset, and multi-byte characters land across that
/// offset routinely — Vercel's own build logs are full of `▲` and `✓`. Every byte must survive.
#[test]
fn a_streamed_body_crosses_the_pump_boundary_byte_exact() {
    // 8000 × 3 bytes = 24 000: comfortably past one 16 KiB read, and EVERY character is multi-byte,
    // so a decode-per-chunk cannot avoid corrupting one.
    let body = "\u{2713}".repeat(8000);
    let (base, server) = relay_chunked_upstream(vec![(200, body.clone())]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    let response = broker
        .relay_hop(&handle, "GET", "/v9/projects/website", &[], Vec::new())
        .unwrap();
    server.join().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        response.body,
        body.as_bytes(),
        "the streamed body reached the client byte for byte"
    );
}

/// The receipt tee keeps only what a receipt can read. The client's stream is untouched.
#[test]
fn the_receipt_tee_is_bounded_and_the_client_stream_is_not() {
    let cap = 64 * 1024; // what `relay_broker` declares
    let body = "z".repeat(cap - 1024);
    let (base, server) = relay_chunked_upstream(vec![(200, body.clone())]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    let started = broker
        .relay_hop_start(&handle, "GET", "/v9/projects/website", &[], Vec::new())
        .unwrap();
    let RelayHopStart::Job(job) = started else {
        panic!("a declared read is authorized");
    };
    let mut stream = job.run();
    let mut streamed = Vec::new();
    while let Some(chunk) = stream.next_chunk() {
        streamed.extend_from_slice(&chunk);
    }
    server.join().unwrap();

    assert_eq!(
        streamed.len(),
        body.len(),
        "the client gets the whole body, tee bound or not"
    );
    assert!(
        stream.observed_len() <= crate::broker::relay::RELAY_OBSERVED_TEE_BYTES,
        "the tee keeps at most {} bytes, kept {}",
        crate::broker::relay::RELAY_OBSERVED_TEE_BYTES,
        stream.observed_len()
    );
    assert!(
        stream.observed_len() < body.len(),
        "a body past the tee bound stops feeding it"
    );
    broker.relay_hop_complete(stream).unwrap();
}

/// The wire tee's banner claims "every provider response body" — the relay egress IS a provider
/// response, so it must be teed like one: on the PUMP side, chunk by chunk as it arrives (never on
/// the broker actor), attributed to the verb that authorized the hop, with the vault credential
/// byte-redacted exactly as the classic path redacts it.
#[test]
fn a_relay_hop_body_reaches_the_armed_wire_tee_with_the_credential_redacted() {
    let dir = tempfile::tempdir().expect("tee dir");
    let tee = dir.path().join("wire.jsonl");
    let _armed = crate::wiretap::ArmedTee::at(&tee);

    let (base, server) = relay_chunked_upstream(vec![(
        200,
        format!(r#"{{"id":"dpl_tee","name":"website","echoed":"{RELAY_TOKEN}"}}"#),
    )]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    let response = broker
        .relay_hop(&handle, "GET", "/v9/projects/website", &[], Vec::new())
        .unwrap();
    server.join().unwrap();
    assert_eq!(response.status, 200);

    let teed = std::fs::read_to_string(&tee).expect("the armed tee wrote a line");
    assert!(
        teed.contains("dpl_tee"),
        "the relay hop's response body reached the tee: {teed}"
    );
    assert!(
        !teed.contains(RELAY_TOKEN),
        "the vault credential reached the tee file: {teed}"
    );
    assert!(
        teed.contains(r#""provider":"vercel""#) && teed.contains(r#""status":200"#),
        "the tee line is attributed to the verb and status that produced it: {teed}"
    );
    assert!(
        teed.contains("GET /v9/projects/website"),
        "the step names the hop, so two hops of one session are told apart: {teed}"
    );
}

/// A hop whose upstream never produces a head is an upstream failure, audited as one, with no
/// `relay_request_forwarded` row claiming a status that never existed.
#[test]
fn a_hop_with_no_upstream_head_audits_as_a_failure() {
    // A port with nothing listening: connect refuses immediately, so no head can ever arrive.
    let dead = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        format!("http://{addr}")
    };
    let broker = relay_broker(&dead);
    let (handle, _) = open_relay(&broker, "website");

    let response = broker
        .relay_hop(&handle, "GET", "/v9/projects/website", &[], Vec::new())
        .unwrap();
    assert_eq!(response.status, 502);
    assert!(
        audit_events_of_type(&broker, "relay_request_forwarded").is_empty(),
        "a hop that never got a head did not forward anything"
    );
    let failed = audit_events_of_type(&broker, "relay_request_failed");
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0]["method"], "GET");
    assert_eq!(failed[0]["target"], "/v9/projects/website");
    assert!(broker.verify_integrity().unwrap().verified);
}

/// The relay records every hop richly in the audit chain — method, target, upstream
/// status, refusal reason, burn state, grant_id — and evidence must render all of it, not stop at
/// the session-open receipt. The join is there: the hops carry `grant_id`, and the request maps to
/// the grant.
#[test]
fn evidence_renders_the_relay_hops_and_the_close_receipt_under_their_request() {
    let (base, server) = relay_chunked_upstream(vec![(
        200,
        r#"{"id":"dpl_ev","url":"ev.vercel.app","name":"website"}"#.to_string(),
    )]);
    let broker = relay_broker(&base);
    let outcome = broker
        .request_capability("s1", relay_request("website"))
        .unwrap();
    let grant_id = outcome.grant_id.clone().expect("an allowed grant");
    let result = broker.execute_capability(&grant_id).unwrap();
    let handle = result.result["relay"]["handle"]
        .as_str()
        .unwrap()
        .to_string();

    broker
        .relay_hop(&handle, "GET", "/v9/projects/website", &[], Vec::new())
        .unwrap();
    server.join().unwrap();
    // A create for a project the sentence never froze: refused before the credential, and the
    // session is a probed session, so it burns and closes with its receipt.
    broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[],
            br#"{"name":"other-site","files":[]}"#.to_vec(),
        )
        .unwrap();

    let evidence = broker.evidence(&outcome.request_id).unwrap();
    let forwarded = evidence
        .relay_hops
        .iter()
        .find(|hop| hop.event_type == "relay_request_forwarded")
        .expect("the forwarded hop is rendered");
    assert_eq!(forwarded.method.as_deref(), Some("GET"));
    assert_eq!(forwarded.target.as_deref(), Some("/v9/projects/website"));
    assert_eq!(forwarded.upstream_status, Some(200));

    let refused = evidence
        .relay_hops
        .iter()
        .find(|hop| hop.event_type == "relay_request_refused")
        .expect("the refused hop is rendered — this is the one the flight could not see");
    assert_eq!(refused.method.as_deref(), Some("POST"));
    assert_eq!(refused.target.as_deref(), Some("/v13/deployments"));
    assert_eq!(refused.reason.as_deref(), Some("bind_mismatch"));
    assert_eq!(refused.burned, Some(true));

    let closed = evidence
        .relay_session
        .as_ref()
        .expect("the session's close receipt rides its request's evidence");
    assert_eq!(closed["closed"], "burned");
    assert_eq!(closed["burned"], "bind_mismatch");
    assert_eq!(closed["burned_target"], "/v13/deployments");
    assert!(broker.verify_integrity().unwrap().verified);
}

/// The agent half: the native CLI swallows the refusal body, so
/// `request_status` — the agent's own surface — must carry the session's close receipt for a
/// terminal relay request. Without it the agent's only signal is the CLI's guess.
#[test]
fn request_status_carries_the_burned_relay_sessions_receipt() {
    let (base, _server) = relay_chunked_upstream(vec![]);
    let broker = relay_broker(&base);
    let outcome = broker
        .request_capability("s1", relay_request("website"))
        .unwrap();
    let result = broker
        .execute_capability(outcome.grant_id.as_deref().unwrap())
        .unwrap();
    let handle = result.result["relay"]["handle"]
        .as_str()
        .unwrap()
        .to_string();
    broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[],
            br#"{"name":"other-site","files":[]}"#.to_vec(),
        )
        .unwrap();

    let status = broker.request_status(&outcome.request_id).unwrap();
    let receipt = status
        .terminal_receipt
        .expect("an executed relay request has a terminal receipt");
    let session = &receipt["relay_session"];
    assert_eq!(session["closed"], "burned");
    assert_eq!(session["burned"], "bind_mismatch");
    assert_eq!(session["burned_method"], "POST");
    assert_eq!(session["burned_target"], "/v13/deployments");
}

/// The operator's cross-session view: `cermet log --hops` reads this projection, newest
/// first, so a burn is diagnosable without sudo and sqlite.
#[test]
fn the_relay_hop_log_lists_every_hop_newest_first() {
    let (base, server) = relay_chunked_upstream(vec![(
        200,
        r#"{"id":"dpl_log","name":"website"}"#.to_string(),
    )]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    broker
        .relay_hop(&handle, "GET", "/v9/projects/website", &[], Vec::new())
        .unwrap();
    server.join().unwrap();
    broker
        .relay_hop(&handle, "GET", "/v13/../v9/projects", &[], Vec::new())
        .unwrap();

    let rows = broker.relay_hops().unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.event_type.as_str())
            .collect::<Vec<_>>(),
        vec![
            "relay_session_closed",
            "relay_request_refused",
            "relay_request_forwarded",
            "relay_session_opened",
        ],
        "newest first, the whole life of the session"
    );
    let refused = &rows[1];
    assert_eq!(refused.provider.as_deref(), Some("vercel"));
    assert_eq!(refused.method.as_deref(), Some("GET"));
    assert_eq!(refused.reason.as_deref(), Some("malformed_request"));
    assert_eq!(refused.burned, Some(true));
    assert!(!refused.at.is_empty());
}

/// The BROKER seam: capture rides the ONE place response bodies are already read —
/// `relay_hop_complete` handing the bounded receipt tee to `RelaySession::observe_body`. No second
/// response-parsing path exists, and what the capture buys is that the session's reads are confined
/// to the deployment its own create returned.
#[test]
fn the_create_response_confines_the_sessions_polls_to_its_own_deployment() {
    let (base, _rx, server) = relay_upstream(vec![
        (
            200,
            r#"{"id":"dpl_ours","url":"website-abc.vercel.app","name":"website","target":null}"#,
        ),
        (200, r#"{"readyState":"READY"}"#),
    ]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");

    let create = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website","files":[]}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(create.status, 200);

    let poll = broker
        .relay_hop(&handle, "GET", "/v13/deployments/dpl_ours", &[], Vec::new())
        .unwrap();
    assert_eq!(
        poll.status, 200,
        "the deployment this session created is exactly what it may read"
    );
    server.join().unwrap();

    let other = broker
        .relay_hop(
            &handle,
            "GET",
            "/v13/deployments/dpl_theirs",
            &[],
            Vec::new(),
        )
        .unwrap();
    assert_eq!(other.status, 422, "another deployment refuses at the bind");
    let refused = audit_events_of_type(&broker, "relay_request_refused");
    assert_eq!(refused.last().unwrap()["reason"], "bind_mismatch");
    assert!(
        broker.relay_session_snapshot(&handle).is_none(),
        "a session probed for a deployment it never created is done"
    );
    assert!(broker.verify_integrity().unwrap().verified);
}

/// The broker seam: the create LANDED and its own response contradicts a frozen field.
/// Nothing here prevents anything — the deployment exists — so what the broker owes the operator is
/// DETECTION: one high-severity `relay_outcome_mismatch` row carrying frozen-vs-observed, and a
/// session that stops being usable for the victory lap.
#[test]
fn a_create_outcome_contradicting_the_approval_audits_and_closes_the_session() {
    let (base, _rx, server) = relay_upstream(vec![(
        200,
        r#"{"id":"dpl_prod","url":"u","name":"website","target":"production"}"#,
    )]);
    let broker = relay_broker(&base);
    // The sentence froze `target = preview`; the provider answered with a production deployment.
    let (handle, _) = open_relay(&broker, "website");
    let create = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website","files":[]}"#.to_vec(),
        )
        .unwrap();
    server.join().unwrap();
    assert_eq!(
        create.status, 200,
        "the provider accepted it — the effect already landed, which is why this is detection"
    );

    let rows = broker
        .audit
        .events_of_type("relay_outcome_mismatch")
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].severity, "high");
    assert_eq!(rows[0].data["field"], "target");
    assert_eq!(rows[0].data["key"], "target");
    assert!(
        rows[0].data["frozen"].is_null(),
        "the approval froze `preview`, which Vercel encodes as an ABSENT target"
    );
    assert_eq!(rows[0].data["observed"], "production");
    assert_eq!(rows[0].data["target"], "/v13/deployments");

    assert!(
        broker.relay_session_snapshot(&handle).is_none(),
        "the session closed on the mismatch"
    );
    let again = broker
        .relay_hop(&handle, "GET", "/v13/deployments/dpl_prod", &[], Vec::new())
        .unwrap();
    assert_eq!(again.status, 409, "every later hop is an unknown handle");
    let closed = audit_events_of_type(&broker, "relay_session_closed");
    assert_eq!(closed.last().unwrap()["closed"], "outcome_mismatch");
    assert_eq!(closed.last().unwrap()["burned"], "outcome_mismatch");
    assert_eq!(
        closed.last().unwrap()["deployment_id"],
        "dpl_prod",
        "the receipt still names what landed — that is what the operator goes and deals with"
    );
    assert!(broker.verify_integrity().unwrap().verified);
}

// ---------------------------------------------------------------------------
// The third refusal class: the sentence allowed it and the CREDENTIAL could not
//
// A catalog gap and a sentence gap are typed on every surface; an effect that failed was one
// undifferentiated "failed", so a dead key read exactly like a network drop. The class is derived
// from the provider's OWN typed signal — the status integer it sent, or (where no response exists)
// the class the seam itself typed onto the refusal.
// ---------------------------------------------------------------------------

/// A PaymentIntent body this verb's declared `require` paths accept, so a 200 is a real success
/// rather than a broker-side verdict failure.
const STRIPE_INTENT_BODY: &str =
    r#"{"id":"pi_missing","object":"payment_intent","status":"succeeded"}"#;

/// One `stripe.get_payment_intent` run against a server that answers with `status_line`, returning
/// the receipt-log row the operator would then read.
fn row_after_status(status_line: &'static str) -> GrantView {
    let body = if status_line.starts_with('2') {
        STRIPE_INTENT_BODY
    } else {
        STRIPE_ERROR_BODY
    };
    let (base, server) = one_shot_status(status_line, body);
    let b = stripe_egress_substituted_broker(
        &base,
        "allow stripe.get_payment_intent where payment_intent = \"pi_missing\"",
    );
    let outcome = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_payment_intent".into(),
                resource: json!({ "payment_intent": "pi_missing" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    b.execute_capability(outcome.grant_id.as_deref().unwrap())
        .unwrap();
    server.join().unwrap();
    let mut history = b.history().unwrap();
    assert_eq!(history.len(), 1);
    history.pop().unwrap()
}

#[test]
fn a_status_the_provider_sent_classifies_the_failed_effect() {
    for (status_line, expected) in [
        // THE payoff: the sentence allowed it and the key could not do it.
        ("401 Unauthorized", EffectFailureClass::ProviderAuthRefused),
        ("403 Forbidden", EffectFailureClass::ProviderAuthRefused),
        // The request itself was refused; the fields must change.
        ("400 Bad Request", EffectFailureClass::ProviderInputRefused),
        (
            "422 Unprocessable Entity",
            EffectFailureClass::ProviderInputRefused,
        ),
        // Back off.
        (
            "429 Too Many Requests",
            EffectFailureClass::ProviderRateLimited,
        ),
        // The provider's own side failed; retry later.
        (
            "500 Internal Server Error",
            EffectFailureClass::ProviderTransient,
        ),
        (
            "503 Service Unavailable",
            EffectFailureClass::ProviderTransient,
        ),
        // The residual: a 404 means "no such object" on one provider and "your token may not see
        // it" on another, and this box has no evidence for which.
        ("404 Not Found", EffectFailureClass::Failed),
    ] {
        let row = row_after_status(status_line);
        assert_eq!(
            row.failure_class,
            Some(expected),
            "{status_line} must classify as {expected}"
        );
    }
}

#[test]
fn an_effect_that_landed_carries_no_failure_class() {
    let row = row_after_status("200 OK");
    assert_eq!(
        row.failure_class, None,
        "absent means nothing failed; the UNKNOWN cause is the `failed` class, which is a value"
    );
}

#[test]
fn a_hop_that_never_connected_is_pre_send_not_a_provider_verdict() {
    // Nothing is listening on this port, so the hop dies before any status exists. The seam types
    // the class onto its own refusal, because there is no status for a reader to derive one from.
    let b = stripe_egress_substituted_broker(
        "http://127.0.0.1:1",
        "allow stripe.get_payment_intent where payment_intent = \"pi_missing\"",
    );
    let outcome = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_payment_intent".into(),
                resource: json!({ "payment_intent": "pi_missing" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    b.execute_capability(outcome.grant_id.as_deref().unwrap())
        .expect_err("a hop that never connected is an execution error");

    let failed = b.audit.events_of_type("provider_action_failed").unwrap();
    assert_eq!(failed.len(), 1);
    // Recorded at the seam, in the SAME shape the evidence path already uses
    // (`provider_evidence_failed.failure_class`), spelled by the enum and nothing else.
    assert_eq!(
        failed[0].data["failure_class"],
        json!(EffectFailureClass::TransportPreSend.as_str())
    );
    let history = b.history().unwrap();
    assert_eq!(
        history[0].failure_class,
        Some(EffectFailureClass::TransportPreSend),
        "the connection was never established, so nothing was sent and a retry is safe"
    );
    assert!(b.verify_integrity().unwrap().verified);
}

#[test]
fn a_failure_that_never_reached_a_provider_is_a_local_failure() {
    // A vault-open failure: the grant was authorized and the effect never reached a provider, so
    // nothing about it is a verdict on a credential.
    let b = stripe_egress_broker_without_credential(
        "http://127.0.0.1:1",
        "allow stripe.get_payment_intent where payment_intent = \"pi_missing\"",
    );
    let outcome = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_payment_intent".into(),
                resource: json!({ "payment_intent": "pi_missing" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    b.execute_capability(outcome.grant_id.as_deref().unwrap())
        .expect_err("no credential, no hop");
    let failed = b.audit.events_of_type("provider_action_failed").unwrap();
    assert_eq!(
        failed[0].data["failure_class"],
        json!(EffectFailureClass::LocalExecutionFailure.as_str()),
        "the vault fault never invoked the provider, so it is OUR failure, not a verdict on a key"
    );
    assert_eq!(
        b.history().unwrap()[0].failure_class,
        Some(EffectFailureClass::LocalExecutionFailure)
    );
}

/// The receipt view carries WHEN the effect ended, from the terminal execution event's own stamp,
/// so an effect's wall time is derivable from the receipt itself. A row whose effect never ran has
/// no end and says so — never a substituted `created_at`, which would render every refusal as an
/// instantaneous effect.
#[test]
fn the_receipt_view_carries_the_effects_own_end() {
    let b = stripe_egress_broker_without_credential(
        "http://127.0.0.1:1",
        "allow stripe.get_payment_intent where payment_intent = \"pi_missing\"",
    );
    let outcome = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_payment_intent".into(),
                resource: json!({ "payment_intent": "pi_missing" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    b.execute_capability(outcome.grant_id.as_deref().unwrap())
        .expect_err("no credential, no hop");

    let history = b.history().unwrap();
    let ran = &history[0];
    let ended = ran
        .terminal_at
        .as_deref()
        .expect("the effect reached a terminal event, so it has an end");
    assert!(
        ended >= ran.created_at.as_str(),
        "an effect cannot end before it was requested: {ended} < {}",
        ran.created_at
    );

    // A refusal minted no grant and ran nothing: no end exists to report.
    let denied = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_payment_intent".into(),
                resource: json!({ "payment_intent": "pi_other" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    assert_eq!(denied.decision, Decision::Deny);
    let history = b.history().unwrap();
    assert!(
        history.iter().any(|row| row.decision == "deny"),
        "the refusal is in the log"
    );
    for row in history.iter().filter(|row| row.decision == "deny") {
        assert_eq!(row.terminal_at, None, "a refusal ran no effect: {row:?}");
    }
}

#[test]
fn a_relay_effect_hop_the_upstream_refused_classifies_the_grant() {
    // A relay grant's terminal event is the session OPENING, which succeeds; the effect that can
    // fail is the one hop the session marked as the effect. Here the upstream refuses the deploy
    // create with a 403 — the vercel token cannot do what the sentence allows.
    let (base, _rx, server) = relay_upstream(vec![
        (200, r#"{"ok":true}"#),
        (403, r#"{"error":{"code":"forbidden"}}"#),
    ]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    broker
        .relay_hop(&handle, "POST", "/v2/files", &[], b"file bytes".to_vec())
        .unwrap();
    let create = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments?forceNew=1",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website","files":[]}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(create.status, 403);
    drop(server);

    let history = broker.history().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].failure_class,
        Some(EffectFailureClass::ProviderAuthRefused),
        "the effect-bearing hop's status is what classifies a relay grant"
    );
}

#[test]
fn a_read_hop_that_failed_is_not_the_grants_effect() {
    let (base, _rx, server) = relay_upstream(vec![(500, r#"{"error":{"code":"boom"}}"#)]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    // The upload hop is declared but is NOT the session's effect; the deploy create is.
    let upload = broker
        .relay_hop(&handle, "POST", "/v2/files", &[], b"file bytes".to_vec())
        .unwrap();
    assert_eq!(upload.status, 500);
    drop(server);

    assert_eq!(
        broker.history().unwrap()[0].failure_class,
        None,
        "a non-effect hop's failure is not the one effect this grant authorized"
    );
}

/// The vercel CLI's own deploy protocol makes the create call TWICE — the first POST is
/// answered `400 missing files`, which is how the upload negotiation starts, and the second one
/// (after the files are uploaded) is the deployment that lands. Both hops are effect-bearing, so a
/// projection that only ever RECORDS failures leaves the first attempt's class standing forever and
/// reports every landed deploy as `provider_input_refused` on the receipt row.
///
/// A relay grant's effect outcome is the LAST effect-bearing statement the chain holds, and a
/// success is a statement.
#[test]
fn a_relay_effect_that_landed_after_a_refused_attempt_carries_no_failure_class() {
    let (base, _rx, server) = relay_upstream(vec![
        (400, r#"{"error":{"code":"missing_files","missing":["a"]}}"#),
        (200, r#"{"ok":true}"#),
        (
            200,
            r#"{"id":"dpl_1","url":"website.vercel.app","name":"website"}"#,
        ),
    ]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    let first = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments?forceNew=1",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website","files":[]}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(first.status, 400, "the upload negotiation's opening move");
    broker
        .relay_hop(&handle, "POST", "/v2/files", &[], b"file bytes".to_vec())
        .unwrap();
    let landed = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments?forceNew=1",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website","files":[{"file":"a"}]}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(landed.status, 200);
    drop(server);

    assert_eq!(
        broker.history().unwrap()[0].failure_class,
        None,
        "the effect landed; a superseded attempt is not this grant's outcome"
    );
}

/// The other half of the same fix: clearing on success must not swallow a genuine refusal. The retry
/// the negotiation triggers is itself refused, and THAT is the grant's outcome — named by the last
/// effect hop's own status, not by the first attempt's.
#[test]
fn a_relay_effect_refused_on_its_last_attempt_still_classifies_the_grant() {
    let (base, _rx, server) = relay_upstream(vec![
        (400, r#"{"error":{"code":"missing_files","missing":["a"]}}"#),
        (200, r#"{"ok":true}"#),
        (403, r#"{"error":{"code":"forbidden"}}"#),
    ]);
    let broker = relay_broker(&base);
    let (handle, _) = open_relay(&broker, "website");
    broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments?forceNew=1",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website","files":[]}"#.to_vec(),
        )
        .unwrap();
    broker
        .relay_hop(&handle, "POST", "/v2/files", &[], b"file bytes".to_vec())
        .unwrap();
    let refused = broker
        .relay_hop(
            &handle,
            "POST",
            "/v13/deployments?forceNew=1",
            &[("content-type".into(), "application/json".into())],
            br#"{"name":"website","files":[{"file":"a"}]}"#.to_vec(),
        )
        .unwrap();
    assert_eq!(refused.status, 403);
    drop(server);

    assert_eq!(
        broker.history().unwrap()[0].failure_class,
        Some(EffectFailureClass::ProviderAuthRefused),
        "the LAST effect hop is the outcome — the token could not do what the sentence allowed"
    );
}

#[test]
fn a_response_that_does_not_fit_the_template_is_protocol_drift() {
    // A 200 whose body does not satisfy the verb's declared `require` paths: the provider answered
    // successfully and the answer no longer fits what the ratified template reads.
    let (base, server) = one_shot_status("200 OK", STRIPE_ERROR_BODY);
    let b = stripe_egress_substituted_broker(
        &base,
        "allow stripe.get_payment_intent where payment_intent = \"pi_missing\"",
    );
    let outcome = b
        .request_capability(
            "s1",
            CapabilityRequest {
                provider: "stripe".into(),
                action: "get_payment_intent".into(),
                resource: json!({ "payment_intent": "pi_missing" }),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    b.execute_capability(outcome.grant_id.as_deref().unwrap())
        .unwrap();
    server.join().unwrap();
    assert_eq!(
        b.history().unwrap()[0].failure_class,
        Some(EffectFailureClass::ProtocolDrift),
        "a declared `require` path that did not resolve is the TEMPLATE drifting, not the request"
    );
}

// ---------------------------------------------------------------------------
// The typed deny reason, carried through the seam that renders it into prose
// ---------------------------------------------------------------------------

/// The refusal the EVALUATOR produced survives to the receipt row and to the operator's view,
/// beside the sentence a human reads — never reconstructed by matching that sentence.
#[test]
fn a_denied_request_stores_the_evaluators_own_typed_refusal() {
    let rules = v2_m1_rules_with_limit(5000);
    let source = Arc::new(V2M1SentenceAuthority::new(rules.clone()));
    let (_dir_guard, dir) = fresh_broker_dir();
    let mut broker = open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source);
    install_v2_m1_fake_stripe(&mut broker);

    let denied = broker
        .request_capability_with_sentence(
            "typed-deny",
            &rules,
            v2_m1_refund_request_at("ch_over", 50_000),
        )
        .unwrap();
    assert_eq!(denied.decision, Decision::Deny);

    // Stored on the request row, in the evaluator's own serde.
    let stored: Option<String> = broker
        .state
        .query_row(
            "SELECT deny_reason_json FROM requests WHERE id=?1",
            rusqlite::params![denied.request_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        stored.as_deref(),
        Some(r#"{"predicate_mismatch":{"rule_idx":0,"pred_idx":0,"field":"amount"}}"#),
        "the typed refusal is stored whole, the mismatched field's NAME included"
    );

    // And read back typed on the row the operator and the projection both see.
    let row = broker
        .history()
        .unwrap()
        .into_iter()
        .find(|row| row.request_id.as_deref() == Some(denied.request_id.as_str()))
        .expect("the denial is in history");
    assert_eq!(
        row.deny_reason,
        Some(crate::sentence::DenyReason::PredicateMismatch {
            rule_idx: 0,
            pred_idx: 0,
            // Stored and read back WHOLE, the field name included.
            field: Some("amount".into()),
        })
    );
    // The prose is untouched: the code is beside it, never instead of it.
    assert!(row.reason.unwrap().contains("predicate 1 did not match"));
}

/// A verb no rule mentions, and an allow: the two other shapes the same column must tell apart.
#[test]
fn an_unruled_verb_and_an_allow_are_distinguishable_by_the_stored_code() {
    let rules = v2_m1_rules_with_limit(5000);
    let source = Arc::new(V2M1SentenceAuthority::new(rules.clone()));
    let (_dir_guard, dir) = fresh_broker_dir();
    let mut broker = open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source);
    install_v2_m1_fake_stripe(&mut broker);

    let unruled = broker
        .request_capability_with_sentence(
            "typed-deny",
            &rules,
            CapabilityRequest {
                provider: "github".into(),
                action: "read_repo".into(),
                resource: json!({"owner":"acme","name":"widgets"}),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    assert_eq!(unruled.decision, Decision::Deny);
    let allowed = broker
        .request_capability_with_sentence("typed-deny", &rules, v2_m1_refund_request("ch_ok"))
        .unwrap();
    assert_eq!(allowed.decision, Decision::Allow);

    let history = broker.history().unwrap();
    let reason_of = |request_id: &str| {
        history
            .iter()
            .find(|row| row.request_id.as_deref() == Some(request_id))
            .expect("the row is in history")
            .deny_reason
            .clone()
    };
    assert_eq!(
        reason_of(&unruled.request_id),
        Some(crate::sentence::DenyReason::NoMatchingRule),
        "the authority gap only the operator can close names itself"
    );
    assert_eq!(
        reason_of(&allowed.request_id),
        None,
        "an allow was refused for no reason at all, so it stores none"
    );
}

/// A refusal raised BEFORE the evaluator ran stores nothing typed — claiming a `DenyReason` for it
/// would claim an evaluation that never happened.
#[test]
fn a_refusal_that_precedes_evaluation_stores_no_typed_reason() {
    let rules = v2_m1_rules_with_limit(5000);
    let source = Arc::new(V2M1SentenceAuthority::new(rules.clone()));
    let (_dir_guard, dir) = fresh_broker_dir();
    let mut broker = open_broker_reuse_with_sentence_authority(&dir, "providers: {}", source);
    install_v2_m1_fake_stripe(&mut broker);

    let unknown = broker
        .request_capability_with_sentence(
            "typed-deny",
            &rules,
            CapabilityRequest {
                provider: "stripe".into(),
                action: "not_a_verb".into(),
                resource: json!({}),
                environment: None,
                justification: None,
                model: None,
            },
        )
        .unwrap();
    assert_eq!(unknown.decision, Decision::Deny);
    let row = broker
        .history()
        .unwrap()
        .into_iter()
        .find(|row| row.request_id.as_deref() == Some(unknown.request_id.as_str()))
        .expect("the refusal is in history");
    assert_eq!(row.deny_reason, None);
    assert!(!row.reason.unwrap().is_empty(), "the prose still says why");
}

// ---------------------------------------------------------------------------
// `team` accepts the SLUG humans and tasks speak, and the canonical `team_…`
// id is what freezes. Adversary: T2 — an agent supplying the human-legible
// name.
// ---------------------------------------------------------------------------

/// The `GET /v2/teams` listing the compiled canonicalizer reads.
const TEAM_LISTING: &str = r#"{"teams":[{"id":"team_other","slug":"other-team"},{"id":"team_ours","slug":"cermet-test-team"}],"pagination":{"count":2,"next":null}}"#;

fn deploy_request(team: &str) -> CapabilityRequest {
    CapabilityRequest {
        provider: "vercel".into(),
        action: "deploy".into(),
        resource: json!({ "project": "website", "target": "preview", "team": team }),
        environment: None,
        justification: None,
        model: None,
    }
}

/// The whole defect, in one test: the corpus pins the ID, the agent speaks the SLUG, and the
/// request is admitted — because the daemon resolved the slug to that id before the sentence saw it.
#[test]
fn a_team_slug_resolves_to_the_id_the_sentence_pins() {
    let (base, rx, _server) = relay_upstream(vec![(200, TEAM_LISTING)]);
    let broker = relay_broker_with_allow(
        &base,
        "allow vercel.deploy where project = \"website\" and target = \"preview\" and team = \"team_ours\"",
    );

    let outcome = broker
        .request_capability("s1", deploy_request("cermet-test-team"))
        .expect("the request is decided");
    assert_eq!(
        outcome.decision,
        Decision::Allow,
        "the slug names the pinned team: {}",
        outcome.reason
    );

    // The ONE read the resolution makes, carrying the vaulted credential the model never sees.
    let listing_hop = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert!(
        listing_hop.starts_with("GET /v2/teams?limit=100 "),
        "the canonicalizer reads the team listing: {listing_hop}"
    );
    assert!(listing_hop.contains(&format!("Bearer {RELAY_TOKEN}")));

    // The CANONICAL id is what froze: approved == executed on the provider's own identifier.
    let grant = broker
        .load_grant(outcome.grant_id.as_deref().expect("an allowed grant"))
        .unwrap();
    assert_eq!(
        grant.resource_json,
        r#"{"project":"website","target":"preview","team":"team_ours"}"#
    );

    // ...and the receipt says what was supplied, what it resolved to, and where that came from.
    let receipts = audit_events_of_type(&broker, "request_field_canonicalized");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["field"], json!("team"));
    assert_eq!(receipts[0]["supplied"], json!("cermet-test-team"));
    assert_eq!(receipts[0]["canonical"], json!("team_ours"));
    assert_eq!(receipts[0]["source"], json!("vercel.team.id"));
    assert!(!receipts[0].to_string().contains(RELAY_TOKEN));
    assert!(broker.verify_integrity().unwrap().verified);
}

/// The other half of the ruling: a request that already names the canonical form is the request it
/// always was — no provider hop, no receipt, nothing to go wrong.
#[test]
fn a_canonical_team_passes_through_without_a_single_provider_hop() {
    for (team, allow) in [
        (
            "team_ours",
            "allow vercel.deploy where project = \"website\" and target = \"preview\" and team = \"team_ours\"",
        ),
        (
            "personal",
            "allow vercel.deploy where project = \"website\" and target = \"preview\" and team = \"personal\"",
        ),
    ] {
        let (base, rx, _server) = relay_upstream(vec![]);
        let broker = relay_broker_with_allow(&base, allow);
        let outcome = broker
            .request_capability("s1", deploy_request(team))
            .expect("the request is decided");
        assert_eq!(outcome.decision, Decision::Allow, "{}", outcome.reason);
        let grant = broker
            .load_grant(outcome.grant_id.as_deref().expect("an allowed grant"))
            .unwrap();
        assert_eq!(
            grant.resource_json,
            format!(r#"{{"project":"website","target":"preview","team":"{team}"}}"#),
            "a canonical value freezes verbatim"
        );
        assert!(
            rx.try_recv().is_err(),
            "`{team}` needs no resolution, so nothing is read"
        );
        assert!(
            audit_events_of_type(&broker, "request_field_canonicalized").is_empty(),
            "no resolution happened, so there is no resolution receipt"
        );
    }
}

/// Fail closed: a slug the connection does not reach is a typed, audited deny. It never guesses,
/// never falls back to the supplied spelling, and never mints.
#[test]
fn an_unresolvable_team_denies_typed_and_mints_nothing() {
    let (base, _rx, _server) = relay_upstream(vec![(200, TEAM_LISTING)]);
    let broker = relay_broker_with_allow(
        &base,
        "allow vercel.deploy where project = \"website\" and target = \"preview\" and team = \"team_ours\"",
    );

    let outcome = broker
        .request_capability("s1", deploy_request("cermet-tst-team"))
        .expect("the request is decided");
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.grant_id.is_none());
    assert!(
        outcome.reason.contains("team") && outcome.reason.contains("provider_not_found"),
        "the agent is told which field failed and how: {}",
        outcome.reason
    );

    let failures = audit_events_of_type(&broker, "request_field_canonicalization_failed");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["field"], json!("team"));
    assert_eq!(failures[0]["supplied"], json!("cermet-tst-team"));
    assert_eq!(failures[0]["failure_class"], json!("provider_not_found"));
    assert!(audit_events_of_type(&broker, "request_field_canonicalized").is_empty());
    assert!(broker.verify_integrity().unwrap().verified);
}

/// Resolution decides how the scope is SPELT, never which scope is admitted: a slug that resolves
/// into a team the corpus does not name denies exactly as its id would have.
#[test]
fn a_slug_resolving_outside_the_corpus_denies_like_its_id() {
    let (base, _rx, _server) = relay_upstream(vec![(200, TEAM_LISTING)]);
    let broker = relay_broker_with_allow(
        &base,
        "allow vercel.deploy where project = \"website\" and target = \"preview\" and team = \"team_ours\"",
    );
    let outcome = broker
        .request_capability("s1", deploy_request("other-team"))
        .expect("the request is decided");
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.grant_id.is_none());
    // A SENTENCE deny, with its own prose — this verb keeps the denial quality it had, which is the
    // whole reason the money path's anti-oracle evidence regime is not what does the resolving.
    assert!(
        !outcome.reason.contains("could not be resolved"),
        "the slug resolved fine; the CORPUS refused it: {}",
        outcome.reason
    );
    assert!(audit_events_of_type(&broker, "request_field_canonicalization_failed").is_empty());
}

/// Approved == executed, on the canonical value: the relay binds every credentialed hop of a
/// SLUG-authored session to the RESOLVED id. There is no execute-time fill — the spelling the agent
/// supplied is not authority and cannot ride the wire.
#[test]
fn the_resolved_id_is_what_every_hop_is_bound_to() {
    const ALLOW: &str =
        "allow vercel.deploy where project = \"website\" and target = \"preview\" and team = \"team_ours\"";
    let open = |responses: Vec<(u16, &'static str)>| {
        let (base, rx, _server) = relay_upstream(responses);
        let broker = relay_broker_with_allow(&base, ALLOW);
        let outcome = broker
            .request_capability("s1", deploy_request("cermet-test-team"))
            .expect("the slug names the pinned team");
        let result = broker
            .execute_capability(outcome.grant_id.as_deref().expect("an allowed grant"))
            .expect("executing a relay verb opens its session");
        let handle = result.result["relay"]["handle"]
            .as_str()
            .expect("the receipt names the handle")
            .to_string();
        // The listing read is the resolution's; drain it so what remains is the SESSION's traffic.
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        (broker, handle, rx)
    };

    let create = |broker: &Broker, handle: &str, team: &str| {
        broker
            .relay_hop(
                handle,
                "POST",
                &format!("/v13/deployments?teamId={team}"),
                &[("content-type".into(), "application/json".into())],
                br#"{"name":"website"}"#.to_vec(),
            )
            .unwrap()
    };

    // The SLUG the agent supplied is not the frozen scope: the bind refuses it, uncredentialed.
    let (broker, handle, rx) = open(vec![(200, TEAM_LISTING)]);
    let refused = create(&broker, &handle, "cermet-test-team");
    assert_eq!(
        refused.status, 422,
        "the supplied spelling is not authority — the bind refuses it"
    );
    assert!(
        rx.try_recv().is_err(),
        "a refused bind never reaches the provider"
    );

    // The RESOLVED id is.
    let (broker, handle, rx) = open(vec![
        (200, TEAM_LISTING),
        (
            200,
            r#"{"id":"dpl_1","url":"x.vercel.app","name":"website"}"#,
        ),
    ]);
    let forwarded = create(&broker, &handle, "team_ours");
    assert_eq!(
        forwarded.status, 200,
        "the RESOLVED id is what the session's own hops carry"
    );
    assert!(
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .starts_with("POST /v13/deployments?teamId=team_ours "),
        "the create landed in the resolved scope"
    );
}

/// Resolution spends the operator's token on an authenticated provider read, so it may run only
/// where the operator has already extended SOME
/// authority over the verb. With the profile's field held UNKNOWN, a corpus that cannot admit this
/// verb at all refuses the request on the corpus alone — no vault open, no provider hop, nothing
/// resolved and nothing disclosed.
///
/// Adversary: T1 — third-party content steering the agent into looping guessed slugs. Before this
/// gate every well-formed guess bought a credentialed `GET /v2/teams` and an existence bit back on a
/// verb the operator had never spoken about.
#[test]
fn a_slug_on_a_verb_no_sentence_admits_never_opens_the_vault() {
    let (base, rx, _server) = relay_upstream(vec![(200, TEAM_LISTING)]);
    let broker = relay_broker_with_allow(
        &base,
        "allow github.read_repo where owner = \"suarezc\" and name = \"cermet\"",
    );
    broker.vault.reset_credential_reads();

    let outcome = broker
        .request_capability("s1", deploy_request("cermet-test-team"))
        .expect("the request is decided");
    assert_eq!(outcome.decision, Decision::Deny);
    assert!(outcome.grant_id.is_none());
    // The vault-wide redaction sweep every non-evidence request already does (mint.rs), and NOT one
    // credential open more.
    assert_eq!(
        broker.vault.credential_reads(),
        1,
        "the credential was never opened"
    );
    assert!(
        rx.try_recv().is_err(),
        "an unadmitted verb never reaches the provider"
    );
    assert!(audit_events_of_type(&broker, "request_field_canonicalized").is_empty());
    assert!(audit_events_of_type(&broker, "request_field_canonicalization_failed").is_empty());
    // The refusal is about the CORPUS. Nothing was resolved, so there is no provider state to leak.
    assert!(
        outcome.reason.contains("no standing sentence"),
        "the agent is told the corpus refused it: {}",
        outcome.reason
    );
    assert!(
        !outcome.reason.contains("team_"),
        "no resolved identifier can appear: {}",
        outcome.reason
    );
    assert!(broker.verify_integrity().unwrap().verified);
}
