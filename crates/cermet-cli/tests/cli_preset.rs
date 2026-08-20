//! `cermet preset` over the REAL ctl path.
//!
//! A preset is an opaque KEY into a daemon-side table of stored rule bodies. It is not a repository,
//! a checkout, or a remote — the name is immaterial, and the body under it is a FULL corpus
//! document. Applying one therefore REPLACES the live corpus, exactly as `doc apply` does.
//!
//! What these pin: a preset can only be written through the ceremonied stage/commit path (there is
//! no standalone write op), the review text an operator accepts names the preset and shows the rule
//! diff, a declined confirm changes nothing, and every rendered name is sanitized.

use std::path::Path;
use std::sync::Arc;

use cermet_cli::preset::{
    run_preset_apply, run_preset_export, run_preset_list, ExportTarget, PresetCommand,
};
use cermet_cli::reconciliation::{run_apply, CtlReconciliationClient};
use cermet_cli::tty::ScriptedTerminal;
use cermet_cli::{parse, CliCommand, CliError};
use cermet_ctl_client::broker_client::CtlBrokerClient;
use cermet_ctl_client::presence::{FixedPresence, PresenceOutcome};

mod common;
use common::{BrokerFixture, TEST_POLICY};

const DESIGNER: &str = "allow stripe.search_customers\n";
const BUILDER: &str = "allow stripe.refund where amount <= 5000\n";

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// A fixture whose sentence record is a REAL staged store, so stage/commit actually flips a
/// generation. The returned guard owns the record's state dir and must outlive the fixture.
fn fixture() -> (BrokerFixture, tempfile::TempDir) {
    let state = tempfile::tempdir().expect("state dir");
    let record = cermet_daemon::sentence_record::build_record_store(state.path(), None);
    let fx = BrokerFixture::with_record_admin(
        TEST_POLICY,
        Some(record as Arc<dyn cermet_daemon::sentence_record::SentenceRecordAdmin>),
    );
    (fx, state)
}

/// A repository holding one authority document under `name`.
fn document_at(root: &Path, name: &str, body: &str) -> std::path::PathBuf {
    std::fs::create_dir_all(root.join(".git")).unwrap();
    let source = format!(
        "PRESET_PROSE_CANARY\n<!-- cermet:authority:v1 -->\nPinned authority: `none` <!-- cermet:pinned:v1 -->\n\n```cermet\n{body}```\n<!-- /cermet:authority:v1 -->\n"
    );
    let path = root.join(name);
    std::fs::write(&path, source).unwrap();
    path
}

/// Run a blocking preset/apply command against the fixture's ctl socket.
async fn blocking<T: Send + 'static>(
    client: &CtlBrokerClient,
    body: impl FnOnce(CtlReconciliationClient) -> T + Send + 'static,
) -> T {
    let ctl = client.clone();
    tokio::task::spawn_blocking(move || body(CtlReconciliationClient::new(ctl).unwrap()))
        .await
        .unwrap()
}

async fn stored(client: &CtlBrokerClient) -> Vec<serde_json::Value> {
    let view = client.list_presets().await.expect("preset list");
    serde_json::from_str(&view).expect("the preset view is an array")
}

/// Ingest one preset by applying a `CERMET_<name>.md` document through the full ceremony.
async fn ingest(client: &CtlBrokerClient, name: &str, body: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = document_at(dir.path(), &format!("CERMET_{name}.md"), body);
    let output = blocking(client, move |ctl| {
        run_apply(
            &ctl,
            &path,
            Some(&path),
            false,
            false,
            &ScriptedTerminal::new(true, "", vec![true]),
            &FixedPresence(PresenceOutcome::Confirmed),
        )
    })
    .await;
    assert_eq!(output.exit_code, 0, "{}", output.text);
}

// ---- ingest: a preset is written only through the ceremony -------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_preset_document_is_stored_by_the_same_ceremony_that_commits_it() {
    let (fx, _state) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = document_at(dir.path(), "CERMET_designer.md", DESIGNER);
    let terminal = ScriptedTerminal::new(true, "", vec![true]);

    let (output, prompts) = blocking(&fx.client, move |ctl| {
        let out = run_apply(
            &ctl,
            &path,
            Some(&path),
            false,
            false,
            &terminal,
            &FixedPresence(PresenceOutcome::Confirmed),
        );
        let prompts = terminal.prompts.lock().unwrap().clone();
        (out, prompts)
    })
    .await;

    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(output.text.contains("result: committed"), "{}", output.text);
    assert!(output.text.contains("preset: designer"), "{}", output.text);

    // The review the operator accepted named the preset AND showed the rule diff.
    let review = prompts
        .first()
        .expect("the ceremony asked for a confirmation");
    assert!(review.contains("preset: designer"), "{review}");
    assert!(
        review.contains("+allow stripe.search_customers"),
        "{review}"
    );

    // The body is live, AND stored under the key.
    let live = fx.client.sentence_authority_status().await.unwrap();
    let cermet_ipc::ctl::SentenceSnapshot::Served { rules_text, .. } = live.sentence else {
        panic!("the ceremony did not establish a served generation")
    };
    assert_eq!(rules_text, DESIGNER);

    let rows = stored(&fx.client).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["name"], "designer");
    assert_eq!(rows[0]["rules_text"], DESIGNER);
    assert_eq!(rows[0]["rule_count"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declined_preset_ingest_stores_nothing_and_leaves_the_corpus_absent() {
    let (fx, _state) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = document_at(dir.path(), "CERMET_designer.md", DESIGNER);
    let terminal = ScriptedTerminal::new(true, "", vec![false]);

    let output = blocking(&fx.client, move |ctl| {
        run_apply(
            &ctl,
            &path,
            Some(&path),
            false,
            false,
            &terminal,
            &FixedPresence(PresenceOutcome::Confirmed),
        )
    })
    .await;

    assert_eq!(output.exit_code, 1, "{}", output.text);
    assert!(
        output.text.contains("terminal confirmation declined"),
        "{}",
        output.text
    );
    assert!(stored(&fx.client).await.is_empty());
    let live = fx.client.sentence_authority_status().await.unwrap();
    assert!(matches!(
        live.sentence,
        cermet_ipc::ctl::SentenceSnapshot::Absent
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_document_path_stores_no_preset_and_keeps_the_pinned_flow() {
    let (fx, _state) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = document_at(dir.path(), "CERMET.md", BUILDER);
    let terminal = ScriptedTerminal::new(true, "", vec![true]);
    let repo = dir.path().to_path_buf();

    let output = blocking(&fx.client, move |ctl| {
        run_apply(
            &ctl,
            &repo,
            Some(&path),
            false,
            false,
            &terminal,
            &FixedPresence(PresenceOutcome::Confirmed),
        )
    })
    .await;

    assert_eq!(output.exit_code, 0, "{}", output.text);
    // The pinned document flow ran: the marker was re-pinned, and nothing was stored.
    assert!(
        output.text.contains("marker_update: updated"),
        "{}",
        output.text
    );
    assert!(!output.text.contains("preset:"), "{}", output.text);
    assert!(stored(&fx.client).await.is_empty());
    let bytes = std::fs::read(dir.path().join("CERMET.md")).unwrap();
    let document = cermet_cli::cermet_document::ManagedDocument::parse(&bytes).unwrap();
    assert!(!document.marker().is_none(), "the marker was re-pinned");
}

// ---- list ---------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn preset_list_renders_the_stored_keys_with_their_rule_count() {
    let (fx, _state) = fixture();
    ingest(&fx.client, "designer", DESIGNER).await;
    ingest(&fx.client, "builder", BUILDER).await;

    let output = blocking(&fx.client, |ctl| run_preset_list(&ctl)).await;
    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(output.text.contains("designer"), "{}", output.text);
    assert!(output.text.contains("builder"), "{}", output.text);
    assert!(output.text.contains("PRESET"), "{}", output.text);
}

#[tokio::test(flavor = "multi_thread")]
async fn preset_list_says_so_when_nothing_is_stored() {
    let (fx, _state) = fixture();
    let output = blocking(&fx.client, |ctl| run_preset_list(&ctl)).await;
    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(output.text.contains("doc apply"), "{}", output.text);
}

// ---- apply --------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn applying_a_preset_replaces_the_live_corpus_through_the_full_ceremony() {
    let (fx, _state) = fixture();
    ingest(&fx.client, "designer", DESIGNER).await;
    ingest(&fx.client, "builder", BUILDER).await;
    // `builder` was ingested last, so it is live; switching back to `designer` REPLACES it.

    let terminal = ScriptedTerminal::new(true, "", vec![true]);
    let (output, prompts) = blocking(&fx.client, move |ctl| {
        let out = run_preset_apply(
            &ctl,
            &ctl,
            "designer",
            false,
            &terminal,
            &FixedPresence(PresenceOutcome::Confirmed),
        );
        let prompts = terminal.prompts.lock().unwrap().clone();
        (out, prompts)
    })
    .await;

    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(output.text.contains("result: committed"), "{}", output.text);
    assert!(output.text.contains("preset: designer"), "{}", output.text);

    let review = prompts
        .first()
        .expect("the ceremony asked for a confirmation");
    assert!(review.contains("preset: designer"), "{review}");
    // A full-corpus replacement: the live rule leaves, the preset's rule arrives.
    assert!(review.contains("-allow stripe.refund"), "{review}");
    assert!(
        review.contains("+allow stripe.search_customers"),
        "{review}"
    );

    let live = fx.client.sentence_authority_status().await.unwrap();
    let cermet_ipc::ctl::SentenceSnapshot::Served { rules_text, .. } = live.sentence else {
        panic!("preset apply did not establish a served generation")
    };
    assert_eq!(rules_text, DESIGNER, "a preset REPLACES the corpus");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declined_preset_apply_leaves_the_live_corpus_alone() {
    let (fx, _state) = fixture();
    ingest(&fx.client, "designer", DESIGNER).await;
    ingest(&fx.client, "builder", BUILDER).await;

    let terminal = ScriptedTerminal::new(true, "", vec![false]);
    let output = blocking(&fx.client, move |ctl| {
        run_preset_apply(
            &ctl,
            &ctl,
            "designer",
            false,
            &terminal,
            &FixedPresence(PresenceOutcome::Confirmed),
        )
    })
    .await;

    assert_eq!(output.exit_code, 1, "{}", output.text);
    let live = fx.client.sentence_authority_status().await.unwrap();
    let cermet_ipc::ctl::SentenceSnapshot::Served { rules_text, .. } = live.sentence else {
        panic!("the live generation must be untouched")
    };
    assert_eq!(rules_text, BUILDER);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_preset_name_lists_what_is_stored_and_sanitizes_it() {
    let (fx, _state) = fixture();
    ingest(&fx.client, "designer", DESIGNER).await;

    let output = blocking(&fx.client, |ctl| {
        run_preset_apply(
            &ctl,
            &ctl,
            "no\u{1b}[2Jsuch",
            false,
            &ScriptedTerminal::new(true, "", vec![true]),
            &FixedPresence(PresenceOutcome::Confirmed),
        )
    })
    .await;

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(output.text.contains("designer"), "{}", output.text);
    assert!(
        !output.text.contains('\u{1b}'),
        "a stored or typed name must never reach the terminal raw: {}",
        output.text
    );

    // Nothing was staged, confirmed, or committed on the unknown-name path.
    let live = fx.client.sentence_authority_status().await.unwrap();
    let cermet_ipc::ctl::SentenceSnapshot::Served { rules_text, .. } = live.sentence else {
        panic!("the live generation must be untouched")
    };
    assert_eq!(rules_text, DESIGNER);
}

// ---- export -------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn export_writes_a_reappliable_document_and_refuses_to_clobber() {
    let (fx, _state) = fixture();
    ingest(&fx.client, "designer", DESIGNER).await;
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().to_path_buf();

    let target = cwd.clone();
    let output = blocking(&fx.client, move |ctl| {
        run_preset_export(&ctl, "designer", &ExportTarget::Directory(target), false)
    })
    .await;
    assert_eq!(output.exit_code, 0, "{}", output.text);

    let written = cwd.join("CERMET_designer.md");
    assert!(written.is_file(), "{}", output.text);
    let bytes = std::fs::read(&written).unwrap();
    let document = cermet_cli::cermet_document::ManagedDocument::parse(&bytes).unwrap();
    assert_eq!(document.body(), DESIGNER);

    // A second export refuses rather than clobbering, and says which flag overrides it.
    let target = cwd.clone();
    let refused = blocking(&fx.client, move |ctl| {
        run_preset_export(&ctl, "designer", &ExportTarget::Directory(target), false)
    })
    .await;
    assert_eq!(refused.exit_code, 2, "{}", refused.text);
    assert!(refused.text.contains("--force"), "{}", refused.text);

    let target = cwd.clone();
    let forced = blocking(&fx.client, move |ctl| {
        run_preset_export(&ctl, "designer", &ExportTarget::Directory(target), true)
    })
    .await;
    assert_eq!(forced.exit_code, 0, "{}", forced.text);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exported_preset_document_reingests_under_the_same_key() {
    let (fx, _state) = fixture();
    ingest(&fx.client, "designer", DESIGNER).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("CERMET_designer.md");

    let target = path.clone();
    let output = blocking(&fx.client, move |ctl| {
        run_preset_export(&ctl, "designer", &ExportTarget::File(target), false)
    })
    .await;
    assert_eq!(output.exit_code, 0, "{}", output.text);

    // Re-ingesting the exported document is a no-op transition, not a failure: the body is already
    // live and already stored under that key.
    let reapply = path.clone();
    let output = blocking(&fx.client, move |ctl| {
        run_apply(
            &ctl,
            &reapply,
            Some(&reapply),
            false,
            false,
            &ScriptedTerminal::new(true, "", vec![true]),
            &FixedPresence(PresenceOutcome::Confirmed),
        )
    })
    .await;
    assert_eq!(output.exit_code, 0, "{}", output.text);
    let rows = stored(&fx.client).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
}

// ---- what an explicit document path may name --------------------------------------------------

/// No operator-facing string may carry a run of spaces from a wrapped source literal.
fn assert_reads_as_prose(text: &str) {
    assert!(
        !text.contains("  "),
        "an operator-facing message carries a wrapped-literal space run: {text:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_named_cermet_document_must_be_the_one_discovery_would_open() {
    let (fx, _state) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let root_document = document_at(dir.path(), "CERMET.md", BUILDER);
    // A second document deeper in the same repository. Discovery ascends to the ROOT, so applying
    // this path must be refused rather than silently applying the root's body instead.
    let nested = dir.path().join("variants");
    std::fs::create_dir_all(&nested).unwrap();
    let nested_document = nested.join("CERMET.md");
    std::fs::write(&nested_document, std::fs::read(&root_document).unwrap()).unwrap();

    let repo = dir.path().to_path_buf();
    let named = nested_document.clone();
    let output = blocking(&fx.client, move |ctl| {
        run_apply(
            &ctl,
            &repo,
            Some(&named),
            false,
            false,
            &ScriptedTerminal::new(true, "", vec![true]),
            &FixedPresence(PresenceOutcome::Confirmed),
        )
    })
    .await;

    assert_eq!(output.exit_code, 2, "{}", output.text);
    // The refusal names BOTH paths: the one that was typed and the one the flow actually applies.
    assert!(
        output
            .text
            .contains(&nested_document.to_string_lossy().to_string()),
        "{}",
        output.text
    );
    assert!(
        output
            .text
            .contains(&root_document.to_string_lossy().to_string()),
        "{}",
        output.text
    );
    assert_reads_as_prose(&output.text);
    // Nothing was applied.
    let live = fx.client.sentence_authority_status().await.unwrap();
    assert!(matches!(
        live.sentence,
        cermet_ipc::ctl::SentenceSnapshot::Absent
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_root_document_named_explicitly_applies_exactly_as_discovery_does() {
    let (fx, _state) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let root_document = document_at(dir.path(), "CERMET.md", BUILDER);

    let repo = dir.path().to_path_buf();
    let named = root_document.clone();
    let output = blocking(&fx.client, move |ctl| {
        run_apply(
            &ctl,
            &repo,
            Some(&named),
            false,
            false,
            &ScriptedTerminal::new(true, "", vec![true]),
            &FixedPresence(PresenceOutcome::Confirmed),
        )
    })
    .await;

    assert_eq!(output.exit_code, 0, "{}", output.text);
    assert!(
        output.text.contains("marker_update: updated"),
        "{}",
        output.text
    );
    let live = fx.client.sentence_authority_status().await.unwrap();
    let cermet_ipc::ctl::SentenceSnapshot::Served { rules_text, .. } = live.sentence else {
        panic!("the named root document did not apply")
    };
    assert_eq!(rules_text, BUILDER);
}

#[tokio::test(flavor = "multi_thread")]
async fn replace_live_is_refused_for_a_preset_document_and_the_refusal_reads_as_prose() {
    let (fx, _state) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = document_at(dir.path(), "CERMET_designer.md", DESIGNER);

    let named = path.clone();
    let output = blocking(&fx.client, move |ctl| {
        run_apply(
            &ctl,
            &named,
            Some(&named),
            true,
            false,
            &ScriptedTerminal::new(true, "", vec![true]),
            &FixedPresence(PresenceOutcome::Confirmed),
        )
    })
    .await;

    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(output.text.contains("--replace-live"), "{}", output.text);
    assert!(output.text.contains("pin marker"), "{}", output.text);
    assert_reads_as_prose(&output.text);
    assert!(stored(&fx.client).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_document_naming_a_reserved_word_is_refused_and_says_it_is_reserved() {
    let (fx, _state) = fixture();
    let dir = tempfile::tempdir().unwrap();
    for reserved in ["list", "export"] {
        let path = document_at(dir.path(), &format!("CERMET_{reserved}.md"), DESIGNER);
        let named = path.clone();
        let output = blocking(&fx.client, move |ctl| {
            run_apply(
                &ctl,
                &named,
                Some(&named),
                false,
                false,
                &ScriptedTerminal::new(true, "", vec![true]),
                &FixedPresence(PresenceOutcome::Confirmed),
            )
        })
        .await;
        assert_eq!(output.exit_code, 2, "{}", output.text);
        assert!(
            output.text.contains("reserved"),
            "{reserved}: {}",
            output.text
        );
        assert!(
            output.text.contains(reserved),
            "{reserved}: {}",
            output.text
        );
        assert_reads_as_prose(&output.text);
    }
    assert!(stored(&fx.client).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unnamed_document_refusal_reads_as_prose() {
    let (fx, _state) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = document_at(dir.path(), "NOTES.md", DESIGNER);
    let named = path.clone();
    let output = blocking(&fx.client, move |ctl| {
        run_apply(
            &ctl,
            &named,
            Some(&named),
            false,
            false,
            &ScriptedTerminal::new(true, "", vec![true]),
            &FixedPresence(PresenceOutcome::Confirmed),
        )
    })
    .await;
    assert_eq!(output.exit_code, 2, "{}", output.text);
    assert!(output.text.contains("CERMET_<name>.md"), "{}", output.text);
    assert_reads_as_prose(&output.text);
}

// ---- the parsed surface ---------------------------------------------------------------------

#[test]
fn preset_parses_its_three_forms_and_refuses_a_bare_noun() {
    assert_eq!(
        parse(&argv(&["preset", "list"])).unwrap(),
        CliCommand::Preset(PresetCommand::List)
    );
    assert_eq!(
        parse(&argv(&["preset", "designer"])).unwrap(),
        CliCommand::Preset(PresetCommand::Apply {
            name: "designer".into(),
            recover: false,
        })
    );
    assert_eq!(
        parse(&argv(&["preset", "designer", "--recover"])).unwrap(),
        CliCommand::Preset(PresetCommand::Apply {
            name: "designer".into(),
            recover: true,
        })
    );
    assert_eq!(
        parse(&argv(&["preset", "export", "designer"])).unwrap(),
        CliCommand::Preset(PresetCommand::Export {
            name: "designer".into(),
            path: None,
            force: false,
        })
    );
    assert_eq!(
        parse(&argv(&[
            "preset",
            "export",
            "designer",
            "/tmp/x.md",
            "--force"
        ]))
        .unwrap(),
        CliCommand::Preset(PresetCommand::Export {
            name: "designer".into(),
            path: Some("/tmp/x.md".into()),
            force: true,
        })
    );
    // A bare noun prints usage; applying the document you are standing in is `doc apply`.
    assert!(matches!(parse(&argv(&["preset"])), Err(CliError::Usage(_))));
    // There is no `--yes` on any ceremony.
    assert!(matches!(
        parse(&argv(&["preset", "designer", "--yes"])),
        Err(CliError::Usage(_))
    ));
    // A name outside the accepted alphabet is refused before any daemon call.
    assert!(matches!(
        parse(&argv(&["preset", "de signer"])),
        Err(CliError::Usage(_))
    ));
    assert!(matches!(
        parse(&argv(&["preset", "../etc/passwd"])),
        Err(CliError::Usage(_))
    ));
}

/// `list` and `export` are the noun's own subcommands, so a profile stored under either name
/// could never be applied — the subcommand match wins. They are refused at ingest instead.
#[test]
fn the_subcommand_words_are_not_available_as_profile_names() {
    for reserved in ["list", "export"] {
        assert!(
            !cermet_cli::preset::name_is_valid(reserved),
            "{reserved} must not be a usable profile name"
        );
        let refusal = cermet_cli::preset::validate_name(reserved).expect_err("reserved");
        assert!(refusal.contains("reserved"), "{reserved}: {refusal}");
        assert!(refusal.contains(reserved), "{reserved}: {refusal}");
    }
    // Only the exact subcommand words are taken; anything else keeping the alphabet is fine.
    for usable in ["lists", "exporter", "List", "Export", "list_v2"] {
        assert!(cermet_cli::preset::name_is_valid(usable), "{usable}");
    }
}

#[test]
fn doc_apply_takes_an_optional_file_and_defaults_to_discovery() {
    assert_eq!(
        parse(&argv(&["doc", "apply"])).unwrap(),
        CliCommand::Apply {
            file: None,
            replace_live: false,
            recover: false,
        }
    );
    assert_eq!(
        parse(&argv(&["doc", "apply", "CERMET_designer.md"])).unwrap(),
        CliCommand::Apply {
            file: Some("CERMET_designer.md".into()),
            replace_live: false,
            recover: false,
        }
    );
    assert_eq!(
        parse(&argv(&["doc", "apply", "--replace-live", "--recover"])).unwrap(),
        CliCommand::Apply {
            file: None,
            replace_live: true,
            recover: true,
        }
    );
    assert!(matches!(
        parse(&argv(&["doc", "apply", "a.md", "b.md"])),
        Err(CliError::Usage(_))
    ));
}
