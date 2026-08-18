//! The reviewed ontology may never contradict the executable discipline.
//!
//! Money is not a type, it is a point in the ontology axis space this repo already ships. The
//! execution discipline (a broker-minted at-most-once key; a response PROVED
//! against a compiled success contract instead of believed) is therefore a property of the verb.
//!
//! It is DECLARED in the ratified, hash-bound action template, because that is the artifact the
//! broker froze on the grant, re-verifies at claim, and executes — and because the grounded ontology
//! is structurally inert to policy, admission, grant minting, and provider execution
//! (`ontology_authority_inertness`). This test is the join those two facts need: for every vendored
//! verb, what the template declares must be CONSISTENT with what the reviewer wrote in its sidecar.
//! A verb the reviewer called a read, or a pure observation, can never be handed the strong
//! discipline; a verb that mints a key can never be one whose repeat the provider already makes
//! safe by construction (`provider_cas`).
//!
//! Why this direction and not a derivation: applying an axis RULE literally to the shipped sidecars
//! (`non_idempotent` → mint a key) selects a different set of verbs than the one that exists — the
//! seven Stripe effects are reviewed `idempotent` (Stripe's key mechanism is what makes them so),
//! while every GitHub write is `non_idempotent` with no key channel at all and no compiled success
//! contract to prove against. A rule that changes what a `github.create_issue` hop does is not a
//! refactor. The template declares; the sidecar constrains what it may declare; this test enforces
//! the constraint at build time.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// `(provider, action)` of every vendored action template, with whether it declares the execution
/// discipline — the `money:` block, which is what `Template::mints_idempotency_key` /
/// `Template::proves_effect` read.
fn declared_discipline() -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(crate_dir().join("actions")).expect("vendored actions directory") {
        let path = entry.expect("directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("template file name")
            .to_string();
        let text = fs::read_to_string(&path).expect("read action template");
        out.insert(name, text.lines().any(|line| line.trim_end() == "money:"));
    }
    assert!(!out.is_empty(), "no vendored action templates were scanned");
    out
}

/// One sidecar's axis values, by axis name.
fn sidecar_axes() -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(crate_dir().join("ontology")).expect("vendored ontology directory") {
        let path = entry.expect("directory entry").path();
        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(name) if name != "sources" => name.to_string(),
            _ => continue,
        };
        let text = fs::read_to_string(&path).expect("read ontology sidecar");
        let mut axes = BTreeMap::new();
        let mut in_semantics = false;
        for line in text.lines() {
            if line.starts_with("semantics:") {
                in_semantics = true;
                continue;
            }
            if in_semantics {
                if !line.starts_with("  ") {
                    in_semantics = false;
                    continue;
                }
                if let Some((axis, value)) = line.trim().split_once(": ") {
                    axes.insert(axis.to_string(), value.trim().to_string());
                }
            }
        }
        assert!(
            axes.contains_key("idempotency") && axes.contains_key("risk_class"),
            "sidecar {name} has no readable semantics block"
        );
        out.insert(name, axes);
    }
    out
}

#[test]
fn no_verb_declares_a_discipline_its_reviewed_sidecar_contradicts() {
    let sidecars = sidecar_axes();
    let mut checked = 0usize;
    for (verb, declares) in declared_discipline() {
        if !declares {
            continue;
        }
        let axes = sidecars.get(&verb).unwrap_or_else(|| {
            panic!("{verb} declares an execution discipline with no reviewed ontology sidecar")
        });
        checked += 1;
        let idempotency = axes["idempotency"].as_str();
        let risk = axes["risk_class"].as_str();
        let reversibility = axes["reversibility"].as_str();
        // A key exists to make a REPEAT safe. A read has nothing to repeat, and a `provider_cas`
        // verb's repeat is already decided by the upstream's own compare-and-swap — minting a key
        // for either would be ceremony with no effect to protect.
        assert!(
            matches!(idempotency, "idempotent" | "non_idempotent"),
            "{verb} declares the key discipline but its sidecar says `idempotency: {idempotency}`"
        );
        // Proving a response against a compiled contract is for an effect on the world that is
        // worth reconciling. An observation has no effect to prove.
        assert!(
            matches!(risk, "external_state_change" | "provider_control_change"),
            "{verb} declares the proving discipline but its sidecar says `risk_class: {risk}`"
        );
        assert!(
            matches!(reversibility, "irreversible" | "compensatable"),
            "{verb} declares the proving discipline but its sidecar says \
             `reversibility: {reversibility}` — nothing needs reconciling"
        );
    }
    assert_eq!(
        checked, 7,
        "the vendored corpus declares the execution discipline on exactly the seven Stripe effects; \
         a change here is a product decision, not a refactor"
    );
}

#[test]
fn every_read_verb_takes_the_plain_discipline() {
    let declared = declared_discipline();
    let mut reads = 0usize;
    for (verb, axes) in sidecar_axes() {
        if axes["idempotency"] != "read" {
            continue;
        }
        reads += 1;
        assert_eq!(
            declared.get(&verb),
            Some(&false),
            "{verb} is a reviewed READ and must reach the provider seam under the plain discipline"
        );
    }
    assert!(
        reads >= 10,
        "the read corpus scanned suspiciously small ({reads})"
    );
}
