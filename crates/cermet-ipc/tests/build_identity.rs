//! The one build identity both `cermetd` and `cermet` link, and the pure skew comparison
//! every client surface renders. A stale client cannot know it is stale unless the build says so.

use cermet_ipc::{build_skew, BUILD_ID, UNKNOWN_BUILD};

#[test]
fn build_id_is_this_package_version_plus_a_provenance_suffix() {
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        BUILD_ID.starts_with(&format!("{version}+")),
        "BUILD_ID {BUILD_ID:?} must be `{version}+<provenance>`"
    );
    let suffix = &BUILD_ID[version.len() + 1..];
    assert!(
        !suffix.is_empty(),
        "BUILD_ID {BUILD_ID:?} carries no provenance suffix"
    );
    // Either a short commit (optionally `-dirty`) or the tarball fallback — never empty, never a
    // build failure.
    assert!(
        suffix == "nogit"
            || suffix
                .trim_end_matches("-dirty")
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
        "BUILD_ID suffix {suffix:?} is neither `nogit` nor a short commit"
    );
}

#[test]
fn a_matching_build_is_no_skew() {
    assert_eq!(build_skew(BUILD_ID), None);
}

#[test]
fn a_different_build_reports_the_daemons_own_id() {
    assert_eq!(build_skew("0.0.1+deadbeef"), Some("0.0.1+deadbeef"));
}

#[test]
fn an_absent_build_reports_the_pre_build_identity_daemon() {
    // A daemon predating the build-identity wire omits the field entirely; the client reads
    // absence as unknown, never as "same build".
    assert_eq!(build_skew(""), Some(UNKNOWN_BUILD));
}
