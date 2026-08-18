use cermet_core::{
    Completion, Idempotency, OntologyCatalog, OntologyError, OntologyRecord, Reversibility,
    RiskClass, Sensitivity, SourceRegistry, MAX_ONTOLOGY_DOCUMENT_BYTES, ONTOLOGY_SCHEMA,
};

const SOURCE: &str = "GH-GRAPHQL-CREATE-COMMIT";

fn valid_document() -> String {
    format!(
        "schema: {ONTOLOGY_SCHEMA}\
\nprovider: github\
\naction: push_commit\
\nbinds:\
\n  provider_descriptor_sha256: {}\
\n  action_template_sha256: {}\
\nsemantics:\
\n  resource_family: repository\
\n  provider_operation: commit_snapshot\
\n  risk_class: external_state_change\
\n  sensitivity: source_code\
\n  reversibility: compensatable\
\n  completion: terminal\
\n  idempotency: provider_cas\
\nreview:\
\n  summary: Create one atomic snapshot commit on a pinned branch.\
\n  cautions:\
\n    - File additions are upserts.\
\nsources:\
\n  - {SOURCE}\n",
        "a".repeat(64),
        "b".repeat(64),
    )
}

fn registry() -> SourceRegistry {
    SourceRegistry::official().unwrap()
}

fn replace_line(document: &str, field: &str, value: &str) -> String {
    let prefix = format!("  {field}: ");
    let old = document
        .lines()
        .find(|line| line.starts_with(&prefix))
        .expect("field exists");
    document.replacen(old, &format!("{prefix}{value}"), 1)
}

#[test]
fn valid_v1_record_parses_into_typed_descriptive_fields() {
    let record = OntologyRecord::parse(&valid_document(), &registry()).unwrap();

    assert_eq!(record.provider, "github");
    assert_eq!(record.action, "push_commit");
    assert_eq!(record.binds.provider_descriptor_sha256, "a".repeat(64));
    assert_eq!(record.binds.action_template_sha256, "b".repeat(64));
    assert_eq!(record.semantics.resource_family, "repository");
    assert_eq!(record.semantics.provider_operation, "commit_snapshot");
    assert_eq!(record.semantics.risk_class, RiskClass::ExternalStateChange);
    assert_eq!(record.semantics.sensitivity, Sensitivity::SourceCode);
    assert_eq!(record.semantics.reversibility, Reversibility::Compensatable);
    assert_eq!(record.semantics.completion, Completion::Terminal);
    assert_eq!(record.semantics.idempotency, Idempotency::ProviderCas);
    assert_eq!(record.review.cautions, ["File additions are upserts."]);
    assert_eq!(record.sources, [SOURCE]);
}

#[test]
fn malformed_unknown_missing_and_wrong_type_documents_fail_closed() {
    let valid = valid_document();
    let cases = [
        "not: [valid".to_owned(),
        format!("{valid}extension: false\n"),
        valid.replace(
            "  action_template_sha256:",
            "  extension: false\n  action_template_sha256:",
        ),
        valid.replace(
            "  provider_operation:",
            "  extension: false\n  provider_operation:",
        ),
        valid.replace("  summary:", "  extension: false\n  summary:"),
        valid.replacen("action: push_commit\n", "", 1),
        valid.replacen("provider: github", "provider: [github]", 1),
        valid.replacen(&format!("sources:\n  - {SOURCE}"), "sources: wrong", 1),
    ];

    for case in cases {
        assert!(
            matches!(
                OntologyRecord::parse(&case, &registry()),
                Err(OntologyError::InvalidDocument(_))
            ),
            "accepted invalid document:\n{case}"
        );
    }
}

#[test]
fn duplicate_yaml_mapping_keys_fail_at_every_mapping_level() {
    let valid = valid_document();
    let cases = [
        valid.replacen(
            "provider: github\n",
            "provider: github\nprovider: github\n",
            1,
        ),
        valid.replacen(
            &format!("  provider_descriptor_sha256: {}\n", "a".repeat(64)),
            &format!(
                "  provider_descriptor_sha256: {}\n  provider_descriptor_sha256: {}\n",
                "a".repeat(64),
                "a".repeat(64)
            ),
            1,
        ),
        valid.replacen(
            "  resource_family: repository\n",
            "  resource_family: repository\n  resource_family: repository\n",
            1,
        ),
        valid.replacen(
            "  summary: Create one atomic snapshot commit on a pinned branch.\n",
            "  summary: Create one atomic snapshot commit on a pinned branch.\n  summary: Duplicate.\n",
            1,
        ),
    ];

    for case in cases {
        let error = OntologyRecord::parse(&case, &registry()).unwrap_err();
        assert!(matches!(error, OntologyError::InvalidDocument(_)));
        assert!(error.to_string().contains("duplicate field"), "{error}");
    }
}

#[test]
fn schema_literal_and_document_byte_cap_are_exact() {
    let wrong_schema = valid_document().replacen(ONTOLOGY_SCHEMA, "cermet.grounded-ontology/v2", 1);
    assert!(matches!(
        OntologyRecord::parse(&wrong_schema, &registry()),
        Err(OntologyError::UnsupportedSchema(schema))
            if schema == "cermet.grounded-ontology/v2"
    ));

    let valid = valid_document();
    let at_cap = format!(
        "{valid}{}",
        " ".repeat(MAX_ONTOLOGY_DOCUMENT_BYTES - valid.len())
    );
    OntologyRecord::parse(&at_cap, &registry()).unwrap();

    let oversized = format!(
        "{valid}{}",
        " ".repeat(MAX_ONTOLOGY_DOCUMENT_BYTES - valid.len() + 1)
    );
    assert!(matches!(
        OntologyRecord::parse(&oversized, &registry()),
        Err(OntologyError::DocumentTooLarge { actual, cap })
            if actual == MAX_ONTOLOGY_DOCUMENT_BYTES + 1 && cap == MAX_ONTOLOGY_DOCUMENT_BYTES
    ));
}

#[test]
fn provider_action_and_rendered_pair_grammars_are_frozen() {
    let valid = valid_document();
    for (field, value) in [
        ("provider", "GitHub".to_owned()),
        ("provider", String::new()),
        ("provider", "p".repeat(65)),
        ("action", "push-commit".to_owned()),
        ("action", "a".repeat(65)),
    ] {
        let document = valid.replacen(
            if field == "provider" {
                "provider: github"
            } else {
                "action: push_commit"
            },
            &format!("{field}: '{value}'"),
            1,
        );
        assert!(matches!(
            OntologyRecord::parse(&document, &registry()),
            Err(OntologyError::InvalidIdentifier { field: actual, .. }) if actual == field
        ));
    }

    let at_cap = valid.replacen(
        "action: push_commit",
        &format!("action: {}", "a".repeat(44)),
        1,
    );
    OntologyRecord::parse(&at_cap, &registry()).unwrap();

    let over_cap = valid.replacen(
        "action: push_commit",
        &format!("action: {}", "a".repeat(45)),
        1,
    );
    assert!(matches!(
        OntologyRecord::parse(&over_cap, &registry()),
        Err(OntologyError::RenderedPairTooLong {
            actual: 52,
            cap: 51
        })
    ));
}

#[test]
fn semantic_identifiers_use_the_frozen_lowercase_grammar() {
    let valid = valid_document();
    OntologyRecord::parse(
        &replace_line(&valid, "resource_family", &"r".repeat(64)),
        &registry(),
    )
    .unwrap();

    for (field, value) in [
        ("resource_family", "Repository".to_owned()),
        ("resource_family", "resource-family".to_owned()),
        ("provider_operation", String::new()),
        ("provider_operation", "o".repeat(65)),
    ] {
        let document = replace_line(&valid, field, &format!("'{value}'"));
        assert!(matches!(
            OntologyRecord::parse(&document, &registry()),
            Err(OntologyError::InvalidIdentifier { field: actual, .. }) if actual == field
        ));
    }
}

#[test]
fn enum_values_are_exact_case_sensitive_typed_values() {
    let valid = valid_document();
    for (field, accepted) in [
        (
            "risk_class",
            &[
                "observation",
                "sensitive_observation",
                "external_state_change",
                "provider_control_change",
                "confidential_input_write",
                "data_lifecycle_change",
            ][..],
        ),
        (
            "sensitivity",
            &[
                "public_metadata",
                "source_code",
                "operational",
                "personal",
                "security",
                "secret",
            ][..],
        ),
        (
            "reversibility",
            &[
                "reversible",
                "compensatable",
                "irreversible",
                "not_applicable",
            ][..],
        ),
        ("completion", &["terminal", "accepted", "asynchronous"]),
        (
            "idempotency",
            &[
                "read",
                "provider_cas",
                "idempotent",
                "non_idempotent",
                "unknown",
            ][..],
        ),
    ] {
        for value in accepted {
            OntologyRecord::parse(&replace_line(&valid, field, value), &registry()).unwrap();
        }
    }

    for (field, value) in [
        ("risk_class", "Observation"),
        ("sensitivity", "private"),
        ("reversibility", "none"),
        ("completion", "complete"),
        ("idempotency", "non-idempotent"),
    ] {
        assert!(matches!(
            OntologyRecord::parse(&replace_line(&valid, field, value), &registry()),
            Err(OntologyError::InvalidDocument(_))
        ));
    }
}

#[test]
fn sha256_bindings_require_exact_lowercase_hex_lexemes() {
    let valid = valid_document();
    for (field, value) in [
        ("provider_descriptor_sha256", "A".repeat(64)),
        ("provider_descriptor_sha256", "a".repeat(63)),
        ("action_template_sha256", format!("{}g", "b".repeat(63))),
        (
            "action_template_sha256",
            format!("sha256:{}", "b".repeat(64)),
        ),
    ] {
        let document = replace_line(&valid, field, &value);
        let expected_field = format!("binds.{field}");
        assert!(matches!(
            OntologyRecord::parse(&document, &registry()),
            Err(OntologyError::InvalidSha256 { field: actual, .. }) if actual == expected_field
        ));
    }
}

#[test]
fn summary_enforces_utf8_byte_cap_and_single_line_clean_text() {
    let valid = valid_document();
    OntologyRecord::parse(
        &replace_line(&valid, "summary", &format!("'{}'", "é".repeat(256))),
        &registry(),
    )
    .unwrap();

    for value in [
        "''".to_owned(),
        "' leading'".to_owned(),
        "'trailing '".to_owned(),
        "\"two\\nlines\"".to_owned(),
        "\"control\\x07character\"".to_owned(),
        format!("'{}'", "é".repeat(257)),
    ] {
        assert!(matches!(
            OntologyRecord::parse(&replace_line(&valid, "summary", &value), &registry()),
            Err(OntologyError::InvalidText { field, .. }) if field == "review.summary"
        ));
    }
}

#[test]
fn cautions_enforce_required_list_entry_and_text_caps() {
    let valid = valid_document();
    let empty = valid.replace(
        "  cautions:\n    - File additions are upserts.",
        "  cautions: []",
    );
    OntologyRecord::parse(&empty, &registry()).unwrap();

    let eight = (0..8)
        .map(|index| format!("    - caution {index}"))
        .collect::<Vec<_>>()
        .join("\n");
    OntologyRecord::parse(
        &valid.replace("    - File additions are upserts.", &eight),
        &registry(),
    )
    .unwrap();

    let nine = (0..9)
        .map(|index| format!("    - caution {index}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(matches!(
        OntologyRecord::parse(
            &valid.replace("    - File additions are upserts.", &nine),
            &registry()
        ),
        Err(OntologyError::TooManyCautions { actual: 9, cap: 8 })
    ));

    for caution in [
        "''".to_owned(),
        "' leading'".to_owned(),
        "\"two\\nlines\"".to_owned(),
        format!("'{}'", "é".repeat(129)),
    ] {
        let document = valid.replace("File additions are upserts.", &caution);
        assert!(matches!(
            OntologyRecord::parse(&document, &registry()),
            Err(OntologyError::InvalidText { field, .. }) if field == "review.cautions[0]"
        ));
    }
}

#[test]
fn source_list_count_id_uniqueness_and_registry_resolution_are_checked() {
    let valid = valid_document();
    let empty = valid.replacen(&format!("sources:\n  - {SOURCE}"), "sources: []", 1);
    assert!(matches!(
        OntologyRecord::parse(&empty, &registry()),
        Err(OntologyError::InvalidSourceCount {
            actual: 0,
            min: 1,
            max: 16
        })
    ));

    let seventeen = (0..17)
        .map(|index| format!("  - SOURCE-{index}"))
        .collect::<Vec<_>>()
        .join("\n");
    let over_cap = valid.replacen(&format!("  - {SOURCE}"), &seventeen, 1);
    assert!(matches!(
        OntologyRecord::parse(&over_cap, &registry()),
        Err(OntologyError::InvalidSourceCount {
            actual: 17,
            min: 1,
            max: 16
        })
    ));

    let duplicate = valid.replacen(
        &format!("  - {SOURCE}"),
        &format!("  - {SOURCE}\n  - {SOURCE}"),
        1,
    );
    assert!(matches!(
        OntologyRecord::parse(&duplicate, &registry()),
        Err(OntologyError::DuplicateSourceId(id)) if id == SOURCE
    ));

    for source in ["lowercase", "-LEADING", &"A".repeat(65)] {
        let document = valid.replacen(SOURCE, source, 1);
        assert!(matches!(
            OntologyRecord::parse(&document, &registry()),
            Err(OntologyError::InvalidSourceId(id)) if id == source
        ));
    }

    let unknown = valid.replacen(SOURCE, "GH-NOT-REGISTERED", 1);
    assert!(matches!(
        OntologyRecord::parse(&unknown, &registry()),
        Err(OntologyError::UnknownSourceId(id)) if id == "GH-NOT-REGISTERED"
    ));
}

#[test]
fn checked_catalog_rejects_duplicate_provider_action_binding_deterministically() {
    let first = valid_document();
    let duplicate = replace_line(&first, "summary", "A different description.");
    assert!(matches!(
        OntologyCatalog::check(&[first.as_str(), duplicate.as_str()], &registry()),
        Err(OntologyError::DuplicateBinding { provider, action })
            if provider == "github" && action == "push_commit"
    ));

    let second = first.replacen("action: push_commit", "action: read_repo", 1);
    let catalog = OntologyCatalog::check(&[first.as_str(), second.as_str()], &registry()).unwrap();
    assert_eq!(catalog.len(), 2);
    assert!(catalog.get("github", "push_commit").is_some());
    assert!(catalog.get("github", "read_repo").is_some());
}
