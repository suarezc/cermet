use std::sync::{Arc, Mutex};

use cermet_core::{
    sentence_authority_pin, AuthenticatedSentenceFile, SentenceAuthoritySource, SentencePinSource,
};

/// Write an authority-file fixture with an explicit 0600 mode, umask-independent — the authority
/// reader refuses a group/other-writable file, and Ubuntu's default 0002 umask would otherwise leave
/// a plain write group-writable.
fn write_authority_0600(path: &std::path::Path, contents: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct MutablePin(Mutex<[u8; 32]>);

impl MutablePin {
    fn set(&self, pin: [u8; 32]) {
        *self.0.lock().unwrap() = pin;
    }
}

impl SentencePinSource for MutablePin {
    fn current_pin(&self) -> cermet_core::Result<[u8; 32]> {
        Ok(*self.0.lock().unwrap())
    }
}

#[test]
fn authenticated_sentence_file_requires_exact_canonical_bytes_and_matching_pin() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.cermet");
    let source = b"allow stripe.refund where amount <= 5000\n";
    write_authority_0600(&path, source);
    let pin = Arc::new(MutablePin(Mutex::new(sentence_authority_pin(source))));
    let authority =
        AuthenticatedSentenceFile::new(path.clone(), nix::unistd::geteuid().as_raw(), pin.clone());

    let authenticated = authority
        .current_authority()
        .expect("exact pinned canonical bytes load");
    assert_eq!(authenticated.rules.rules.len(), 1);
    assert_eq!(
        authenticated.digest,
        cermet_core::sentence::authority_digest_for(1, source),
        "custody returns the exact domain/version-bound identity the broker must bind into grants"
    );

    pin.set(sentence_authority_pin(b"different\n"));
    assert!(
        authority
            .current_ruleset()
            .unwrap_err()
            .to_string()
            .contains("pin mismatch"),
        "a mismatched independent pin must fail closed"
    );

    let noncanonical = b" allow   stripe.refund where amount <= 5000\n";
    write_authority_0600(&path, noncanonical);
    pin.set(sentence_authority_pin(noncanonical));
    assert!(
        authority
            .current_ruleset()
            .unwrap_err()
            .to_string()
            .contains("not canonical"),
        "even correctly pinned bytes must use the canonical sentence codec"
    );
}

#[test]
fn authenticated_sentence_file_read_failure_never_becomes_empty_authority() {
    let dir = tempfile::tempdir().unwrap();
    let pin = Arc::new(MutablePin(Mutex::new(sentence_authority_pin(b""))));
    let authority = AuthenticatedSentenceFile::new(
        dir.path().join("missing-parent").join("rules.cermet"),
        nix::unistd::geteuid().as_raw(),
        pin,
    );

    assert!(authority.current_ruleset().is_err());
}

/// `AuthenticatedSentenceFile` refuses a rules file whose owner is NOT the
/// configured approver uid (e.g. a daemon-owned file swapped in). Owner == approver is the custody
/// contract: the human owns/writes the sentence file; a file the daemon (or anyone else) owns must
/// never confer authority even if its pin matches. Non-privileged: we simply configure an
/// expected_owner_uid that differs from the file's real owner (our own euid).
#[test]
fn authenticated_sentence_file_refuses_a_non_approver_owned_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.cermet");
    let source = b"allow stripe.refund where amount <= 5000\n";
    write_authority_0600(&path, source);
    // Pin matches the exact bytes — so ONLY the owner check can reject it.
    let pin = Arc::new(MutablePin(Mutex::new(sentence_authority_pin(source))));
    let real_owner = nix::unistd::geteuid().as_raw();
    let wrong_owner = real_owner.wrapping_add(1); // any uid other than the file's real owner
    let authority = AuthenticatedSentenceFile::new(path, wrong_owner, pin);
    let err = authority
        .current_ruleset()
        .expect_err("a file NOT owned by the expected approver uid must fail closed");
    assert!(
        err.to_string().contains("not a regular file owned by uid"),
        "the refusal must be the owner check, got: {err}"
    );
}

/// Revoke is IMMEDIATE. `current_ruleset()` re-reads the file + pin on every
/// call, so once the ceremony rewrites the file to an empty (revoked) corpus and re-pins it, the very
/// next authority read reflects the revocation — there is no stale-allow window. This is the property
/// the broker relies on when it reads authority per request.
#[test]
fn revoke_is_reflected_on_the_next_authority_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.cermet");
    let with_rule = b"allow stripe.refund where amount <= 5000\n";
    write_authority_0600(&path, with_rule);
    let pin = Arc::new(MutablePin(Mutex::new(sentence_authority_pin(with_rule))));
    let authority =
        AuthenticatedSentenceFile::new(path.clone(), nix::unistd::geteuid().as_raw(), pin.clone());
    assert_eq!(
        authority
            .current_ruleset()
            .expect("loads the allow rule")
            .rules
            .len(),
        1
    );

    // The ceremony revokes: rewrite to the canonical EMPTY corpus and re-pin (file THEN pin, as the
    // CLI ceremony commits the file before the daemon re-pins).
    let empty = b"";
    write_authority_0600(&path, empty);
    pin.set(sentence_authority_pin(empty));
    assert_eq!(
        authority
            .current_ruleset()
            .expect("empty corpus loads")
            .rules
            .len(),
        0,
        "the next read after revoke must show zero rules — no stale-allow window"
    );
}
