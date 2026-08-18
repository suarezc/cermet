//! Structural authority-inertness guard.
//!
//! The grounded ontology is descriptive metadata: `risk_class`, `sensitivity`, and every other
//! annotation are FORBIDDEN inputs to policy, contract-set projection, grant minting, request
//! admission, and provider execution. Today that holds only because no authority module names an
//! ontology symbol. This test makes the invariant STRUCTURAL rather than prose: it fails the build
//! the moment any authority/execution module in `cermet-core` or the extracted `cermet-lang`
//! references the ontology module or its types. A future `use cermet_core::RiskClass;` in the broker
//! (or its grant-mint path) can no longer land silently.
//!
//! The forbidden token set is DERIVED at test time from the ontology module's actual public
//! surface — the module-level `pub` items in `src/ontology.rs` UNION the `pub use ontology::{…}`
//! re-export block in `lib.rs` — so a newly added (and re-exported) ontology type is forbidden
//! automatically. A hand-maintained list rots: it silently missed `Completion`,
//! `SourceRegistryEntry`, and `SourceRegistryError`.
//!
//! This guards the credential/authority surface, not a house style. `lib.rs` (module
//! registration and re-export) and `ontology.rs` itself are the only legitimate places
//! the symbols may appear;
//! catalog/render surfaces that legitimately *display* ontology facts live outside these core
//! authority modules (in the CLI/app, never in a core authority module).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The authority/execution module roots that must remain ontology-inert. A root is a flat file
/// (`policy.rs`) or a module directory (`broker/`, which contains the grant-`mint` path,
/// `execute`, `approve`, `lifecycle`, …). Every non-test `.rs` under a directory root is scanned.
/// This is the surface where a metadata leak would turn a non-authoritative label into a Cermet
/// allow: broker + grant mint, policy, sentence evaluation, contract/grant shaping, set projection,
/// provider execution, custody, and the template loader.
const FORBIDDEN_ROOTS: &[(&str, &str)] = &[
    ("cermet-core", "src/broker"),
    ("cermet-core", "src/policy.rs"),
    ("cermet-core", "src/sentence_authority.rs"),
    ("cermet-core", "src/templates.rs"),
    ("cermet-core", "src/provider.rs"),
    ("cermet-core", "src/vault.rs"),
    ("cermet-lang", "src/policy.rs"),
    ("cermet-lang", "src/sentence.rs"),
    ("cermet-lang", "src/contract.rs"),
    ("cermet-lang", "src/authority.rs"),
    ("cermet-lang", "src/sets.rs"),
    ("cermet-lang", "src/templates.rs"),
    ("cermet-lang", "src/provider.rs"),
    ("cermet-lang", "src/types.rs"),
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cermet-core lives under the workspace crates directory")
        .to_path_buf()
}

/// Every module-level `pub struct|enum|const|type|trait|fn` name declared in `src/ontology.rs`.
/// Column-0 only, so `pub fn` methods inside `impl` blocks (indented) are excluded — a method is
/// not an independently importable symbol.
fn ontology_module_pub_items() -> BTreeSet<String> {
    let text = fs::read_to_string(src_dir().join("ontology.rs")).expect("read src/ontology.rs");
    let mut names = BTreeSet::new();
    for line in text.lines() {
        // Module-level items have no leading whitespace.
        let Some(rest) = line.strip_prefix("pub ") else {
            continue;
        };
        for keyword in ["struct ", "enum ", "const ", "type ", "trait ", "fn "] {
            if let Some(after) = rest.strip_prefix(keyword) {
                let name: String = after
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    names.insert(name);
                }
                break;
            }
        }
    }
    names
}

/// Every symbol re-exported from the ontology module at the crate root, parsed from the
/// `pub use ontology::{ … };` block in `lib.rs`. These are exactly the `cermet_core::<Name>` paths
/// an authority module could import.
fn lib_reexported_ontology_symbols() -> BTreeSet<String> {
    let text = fs::read_to_string(src_dir().join("lib.rs")).expect("read src/lib.rs");
    let start = text
        .find("pub use ontology::{")
        .expect("lib.rs re-exports the ontology module");
    let after = &text[start..];
    let open = after.find('{').unwrap();
    let close = after
        .find("};")
        .expect("ontology re-export block is closed");
    let inner = &after[open + 1..close];
    inner
        .split(',')
        .map(|token| token.trim())
        .filter(|token| {
            !token.is_empty() && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .map(|token| token.to_string())
        .collect()
}

/// The derived forbidden set: the module path token `ontology` plus every public ontology symbol
/// (module-level pub items ∪ crate-root re-exports). Structurally cannot rot as types are added.
fn forbidden_tokens() -> BTreeSet<String> {
    let mut tokens: BTreeSet<String> = BTreeSet::new();
    tokens.insert("ontology".to_string());
    tokens.extend(ontology_module_pub_items());
    tokens.extend(lib_reexported_ontology_symbols());
    tokens
}

/// Token match at identifier boundaries, so scanning for `SourceRegistry` does not spuriously fire
/// inside an unrelated longer identifier and a comment word cannot masquerade as a symbol use.
fn contains_token(haystack: &str, token: &str) -> bool {
    let bytes = haystack.as_bytes();
    let tok = token.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0;
    while let Some(pos) = haystack[i..].find(token) {
        let start = i + pos;
        let end = start + tok.len();
        let left_ok = start == 0 || !is_ident(bytes[start - 1]);
        let right_ok = end == bytes.len() || !is_ident(bytes[end]);
        if left_ok && right_ok {
            return true;
        }
        i = start + 1;
    }
    false
}

/// Test modules are excluded: the guard targets shipping authority code, not test fixtures that may
/// legitimately cross-check inertness. Any non-test `.rs` under a guarded root is in scope, so a
/// `use crate::ontology::…;` in `broker/mint.rs` (not a test file) is still caught.
fn is_test_file(path: &Path) -> bool {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name == "tests.rs" || name.ends_with("_tests.rs"),
        None => false,
    }
}

fn collect_rs(root: &Path, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        if root.extension().and_then(|e| e.to_str()) == Some("rs") && !is_test_file(root) {
            out.push(root.to_path_buf());
        }
        return;
    }
    for entry in fs::read_dir(root).unwrap_or_else(|e| panic!("cannot read {root:?}: {e}")) {
        let path = entry.expect("dir entry").path();
        collect_rs(&path, out);
    }
}

#[test]
fn derived_forbidden_set_covers_the_public_ontology_surface_the_static_list_missed() {
    let tokens = forbidden_tokens();
    // These three re-exported types were absent from a former hand-kept list.
    for name in ["Completion", "SourceRegistryEntry", "SourceRegistryError"] {
        assert!(
            tokens.contains(name),
            "derived forbidden set is missing re-exported ontology type `{name}`"
        );
    }
    // And the derivation must actually find the surface, not silently yield a degenerate set.
    for name in [
        "OntologyRecord",
        "OntologyCatalog",
        "OntologyArtifacts",
        "RiskClass",
        "Sensitivity",
        "Reversibility",
        "Idempotency",
        "SourceRegistry",
        "VENDORED_ONTOLOGY",
    ] {
        assert!(
            tokens.contains(name),
            "derived forbidden set is missing `{name}`"
        );
    }
    assert!(
        tokens.len() >= 15,
        "derived forbidden set is suspiciously small ({}); scanner likely broke",
        tokens.len()
    );
}

#[test]
fn authority_modules_never_reference_the_ontology_module_or_its_types() {
    let crates = crates_dir();
    let tokens = forbidden_tokens();

    let mut scanned = 0usize;
    for (crate_name, root_name) in FORBIDDEN_ROOTS {
        let root = crates.join(crate_name).join(root_name);
        assert!(
            root.exists(),
            "guarded authority root `{crate_name}/{root_name}` no longer exists; update the inertness guard"
        );
        let mut files = Vec::new();
        collect_rs(&root, &mut files);
        assert!(
            !files.is_empty(),
            "guarded authority root `{crate_name}/{root_name}` scanned zero files; update the inertness guard"
        );

        for file in files {
            let rel = file
                .strip_prefix(&crates)
                .unwrap_or(&file)
                .display()
                .to_string();
            let text = fs::read_to_string(&file)
                .unwrap_or_else(|error| panic!("cannot read authority module {rel}: {error}"));
            for token in &tokens {
                assert!(
                    !contains_token(&text, token),
                    "authority module `{rel}` references forbidden ontology token `{token}`: the \
                     grounded ontology must stay inert to policy/admission/grant/execution (plan \
                     §8.5). A display surface belongs in the CLI/app, not a core authority module.",
                );
            }
            scanned += 1;
        }
    }

    assert!(
        scanned >= FORBIDDEN_ROOTS.len(),
        "guard scanned too few files: {scanned}"
    );
}
