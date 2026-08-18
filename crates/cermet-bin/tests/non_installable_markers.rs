//! The contamination markers must travel with the FEATURE, not with the composition crate.
//!
//! Cargo's resolver unifies dev-dependency features into the normal graph whenever it
//! builds tests and binaries in the same invocation — so `cargo nextest run --workspace` produced a
//! `target/debug/cermet` with `cermet-core`'s egress override and mock providers compiled IN, while
//! the markers stayed OUT: they lived in `cermet-bin`, whose own feature set is empty on that
//! build. `reject_non_installable_binary` therefore accepted it, and `resolve_binary_source`'s
//! publish-the-running-executable fallback would have installed it. The adversary is T2 (accident):
//! the deliberate route (`--features test-egress`) was caught; the accidental one was not.
//!
//! The fix is placement. Each marker now lives in the crate that OWNS the feature — the egress and
//! test-double markers in `cermet-core`, the presence marker in `cermet-ctl-client` — so any binary
//! that links a contaminated library carries the marker no matter who enabled the feature. The scan
//! then proves the property `dist/linux/cermetd.service` promises: *this binary links an
//! egress-capable core*.
//!
//! This test is deliberately non-vacuous in EVERY invocation. `cermet-bin`'s dev-dependencies name
//! all three features explicitly, so the binary built beside this test is always contaminated and
//! the assertion below always has something to catch. Resolver 2 keeps dev-dependency features out
//! of non-test builds, so `cargo build [--release] -p cermet-bin` — the only build
//! `dist/Makefile` ever packages — stays clean. That half is proved end to end rather than by
//! assertion: `dev/test-deb` packages the release binary and installs it in a container, and a
//! contaminated one would be refused by the very scan this test defends.

/// The markers, forward. Written split so THIS file does not itself contain a byte string the
/// production scanner refuses — the same self-reference dodge `setup.rs` needs.
fn marker(feature_word: &str) -> Vec<u8> {
    format!("CERMET_TEST_{feature_word}_COMPILED_IN_DO_NOT_INSTALL").into_bytes()
}

fn binary_bytes() -> Vec<u8> {
    std::fs::read(env!("CARGO_BIN_EXE_cermet")).expect("the bin built beside this test must exist")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Every test-only door compiled into this binary announces itself in the binary's own bytes.
#[test]
fn a_binary_linking_a_contaminated_library_carries_that_librarys_marker() {
    let bytes = binary_bytes();
    for feature_word in ["EGRESS", "DOUBLE", "PRESENCE"] {
        assert!(
            contains(&bytes, &marker(feature_word)),
            "{} was built with the {feature_word} door compiled in (cermet-bin's dev-dependencies \
             name it) but carries no marker for it — the installer scan would accept it",
            env!("CARGO_BIN_EXE_cermet"),
        );
    }
}

/// The tell the review reproduced: `cermet-core`'s test-double registry leaves this literal in any
/// binary that links it. Pinned here so the marker can never drift back out of step with the
/// capability it is supposed to announce — a build that carries the capability but not the marker
/// is exactly the hole this test defends against.
#[test]
fn the_test_double_capability_and_its_marker_travel_together() {
    let bytes = binary_bytes();
    assert!(
        contains(&bytes, b"test-double-descriptor:"),
        "expected the test-double registry to be linked into this test build"
    );
    assert!(
        contains(&bytes, &marker("DOUBLE")),
        "the test-double capability is linked in but its marker is not"
    );
}
