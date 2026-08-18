//! Master-key custody for cermetd. The source follows the DECLARED custody rung, and every path
//! fails closed.
//!
//! - **SERVICE mode** (`CERMET_SERVICE_MODE=1`): the key comes ONLY from the source the config's
//!   `custody_profile` names — never the login keychain, never the dev override, and never a
//!   different rung's source. The ladder (`cermet_ipc::custody::CustodyProfile`) has three rungs
//!   and exactly two sources:
//!     * `systemd-tpm2+host` / `systemd-host` — a **systemd encrypted credential** read at
//!       `$CREDENTIALS_DIRECTORY/cermet.key` (service-scoped, sealed at rest via
//!       `LoadCredentialEncrypted=`). Linux only.
//!     * `file-protected` — the service-account-owned `0600` `$CERMET_HOME/master.key`, protected
//!       by the separate-uid boundary (the agent uid gets a kernel `EACCES` on it, exactly like the
//!       DBs). The rung macOS has always been on, and the rung a Linux box that cannot carry
//!       systemd credential delivery lands on.
//!
//!   Both go through the SAME fail-closed reader ([`load_service_key_file`] →
//!   `host_lock::read_secret_nofollow`: `O_NOFOLLOW` + fstat regular-and-owned-by-euid and not
//!   group/world-readable, then trim + require exactly 64 hex chars → 32 bytes). There is one
//!   reader and one validation, on both platforms and both sources.
//!
//!   The declared rung is AUTHORITATIVE, not a hint: a config that says `systemd-host` reads the
//!   credential and refuses if it is absent, even when a `master.key` is lying in the state dir —
//!   and vice versa. Two sources that could substitute for each other would make custody a race
//!   between whatever happens to exist on disk.
//!
//! - **DEV / test mode** (default): a FENCED, explicitly-unsafe env override
//!   (`CERMET_UNSAFE_DEV_MASTER_KEY=1` + `CERMET_MASTER_KEY=<64 hex>`) is consulted FIRST, so local
//!   runs and the test suite never trigger a macOS keychain prompt; then the login keychain as a dev
//!   convenience. The override is compiled in ONLY under `dev-key`/`cfg(test)`, is refused under
//!   `CERMET_SERVICE_MODE=1`, and is absent from the shipped binary entirely.
//!
//! The macOS `master.key` file does NOT reopen the old same-uid hole: "no plaintext key on
//! disk" was the rule for the same-uid world, where a home-dir key file the agent could read was
//! meaningless. Once the daemon runs as `_cermet` (separate uid), a `0600` `_cermet`-owned key file
//! IS the OS-protected source — the agent uid cannot read it. (A signature-pinned System-keychain
//! item is the later hardening.) In **dev mode** there is still no key file — the fenced override /
//! login keychain is used.

use std::path::Path;

use cermet_ipc::custody::CustodyProfile;

const SERVICE: &str = "cermet-broker";
const ACCOUNT: &str = "master-key";

/// The systemd credential NAME the daemon reads (Linux). Must match the unit's
/// `LoadCredentialEncrypted=cermet.key:...` (cross-track contract): systemd decrypts the sealed blob
/// to `$CREDENTIALS_DIRECTORY/cermet.key` (tmpfs, 0400, owned by the service uid) before exec.
#[cfg_attr(target_os = "macos", allow(dead_code))] // macOS uses the master.key file, not this
const CRED_FILE: &str = "cermet.key";

/// The `file-protected` rung's key file under `$CERMET_HOME`, owned by the service account and
/// `0600`. Not macOS-only since the ladder landed: a Linux box that cannot carry systemd credential
/// delivery is provisioned onto exactly this file, by the same installer code and read by the same
/// reader.
const KEY_FILE: &str = "master.key";

fn service_mode_from_env() -> bool {
    std::env::var("CERMET_SERVICE_MODE").as_deref() == Ok("1")
}

/// Load the 32-byte master key. `service_mode` is the AUTHORITATIVE input — the central wiring passes
/// the config's `service_mode` (itself derived from the explicit `CERMET_SERVICE_MODE` launch signal).
/// There is deliberately **no** env-probing convenience wrapper: one authoritative input
/// removes the skew where a caller and the environment disagree about the mode.
pub fn load_with_mode(
    home: &Path,
    service_mode: bool,
    custody: Option<CustodyProfile>,
) -> Result<Vec<u8>, String> {
    // In service mode the key comes ONLY from the source the DECLARED rung names — never the
    // login keychain, never the dev override, never another rung's source.
    if service_mode {
        let Some(profile) = custody else {
            // Belt-and-braces over `config::parse`, which already refuses an undeclared rung in
            // service mode: two paths reach this loader and neither may end in a guessed source.
            return Err(
                "service mode with no declared custody_profile — refusing to guess which key \
                 source holds this vault (run `sudo cermet setup`, which selects the strongest \
                 rung this box supports and records it)"
                    .to_string(),
            );
        };
        return load_service_key_for_rung(home, profile);
    }
    let _ = home; // dev path: the key comes from the fenced override / login keychain, not a path.
                  // Belt-and-braces: the env signal ALONE also forces away from the dev path, so the dev
                  // keychain / unsafe override can NEVER be reached under `CERMET_SERVICE_MODE=1` even if a caller
                  // passes a stale `service_mode=false`. A param/env disagreement fails closed, never to dev.
    if service_mode_from_env() {
        return Err(
            "CERMET_SERVICE_MODE=1 but a dev key path was requested (caller passed service_mode=false) \
             — refusing to read the login keychain / dev override in a service launch (D4, fail closed)"
                .to_string(),
        );
    }
    resolve_dev(unsafe_dev_env(), read_keychain)
}

/// Read the service master key from the systemd encrypted credential. `creds_dir` is
/// the value of `$CREDENTIALS_DIRECTORY` — passed as a param (not read here) so tests exercise the
/// resolution without racing on process-global env, mirroring `resolve_dev` / `unsafe_dev_env_inner`.
///
/// Fail-closed at every step: an unset/empty credentials dir means the daemon was NOT launched with
/// `LoadCredentialEncrypted=` → there is no service key source, so refuse (NEVER fall back to the
/// login keychain or a plaintext file). The cred itself is read with `host_lock::read_nofollow`
/// (`O_NOFOLLOW` + fstat regular-and-owned-by-euid), so a symlinked / foreign-owned / non-regular
/// `cermet.key` is refused. Then it must trim to EXACTLY 64 hex chars (decoded to 32 bytes).
#[cfg_attr(target_os = "macos", allow(dead_code))] // Linux source; macOS uses load_service_key_file
fn load_service_key(creds_dir: Option<&str>) -> Result<Vec<u8>, String> {
    let dir = match creds_dir {
        Some(d) if !d.is_empty() => d,
        _ => {
            return Err(
                "service mode but CREDENTIALS_DIRECTORY is unset/empty — the daemon was not launched \
                 with LoadCredentialEncrypted=cermet.key; refusing to fall back to a plaintext file \
                 or the login keychain (D4, fail closed)"
                    .to_string(),
            );
        }
    };
    // Defense-in-depth on Linux: validate the credentials DIRECTORY itself — a real, non-symlinked,
    // owner-trusted, non-group/world-writable dir — before reading cermet.key out of it. This is
    // layered UNDER the O_NOFOLLOW + fstat read of the cred file below; systemd provisions the dir
    // 0700, but we re-assert rather than trust the launch context (fail closed on any violation).
    cermet_broker_actor::host_lock::validate_credentials_dir(Path::new(dir)).map_err(|e| {
        format!(
            "$CREDENTIALS_DIRECTORY ({dir}) failed validation: {e} (D4 defense-in-depth, fail \
             closed — the credential dir must be a real 0700-ish dir owned by the service uid/root)"
        )
    })?;
    let path = Path::new(dir).join(CRED_FILE);
    load_service_key_file(&path)
}

/// Read a 32-byte master key from a regular, owner-only key file, fail-closed — the shared core for
/// BOTH service sources (the Linux systemd credential and the macOS `_cermet`-owned `master.key`).
/// `host_lock::read_secret_nofollow` enforces `O_NOFOLLOW` + fstat (regular file owned by our euid,
/// and NOT group/world-readable), so a symlinked / foreign-owned / non-regular /
/// group/world-readable file is refused; then trim + require EXACTLY 64 hex chars.
fn load_service_key_file(path: &Path) -> Result<Vec<u8>, String> {
    let raw = cermet_broker_actor::host_lock::read_secret_nofollow(path).map_err(|e| {
        format!(
            "cannot read the service master key at {}: {e} (D4, fail closed; it must be a regular \
             file owned by the service uid, 0600/0400 owner-only — no symlink/foreign owner, no \
             group/world read)",
            path.display()
        )
    })?;
    let hex = std::str::from_utf8(&raw)
        .map_err(|_| "service master key is not valid UTF-8 hex".to_string())?;
    decode_key(hex)
}

/// Dispatch the service-mode key source on the DECLARED custody rung.
///
/// One axis, not two: the rung names the source, and the platform only decides whether a rung is
/// implementable at all. `file-protected` is the service-account-owned `0600 $CERMET_HOME/master.key`
/// on BOTH platforms; the sealed rungs are systemd credential delivery, which exists on Linux only.
fn load_service_key_for_rung(home: &Path, profile: CustodyProfile) -> Result<Vec<u8>, String> {
    if !profile.is_systemd_credential() {
        return load_service_key_file(&home.join(KEY_FILE));
    }
    #[cfg(target_os = "macos")]
    {
        let _ = home;
        Err(format!(
            "config declares custody_profile {:?}, but systemd credential delivery does not exist \
             on macOS — this box's rung is file-protected (run `sudo cermet setup`)",
            profile.as_str()
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = home; // a sealed rung's source is the systemd credential dir, not $CERMET_HOME.
        load_service_key(std::env::var("CREDENTIALS_DIRECTORY").ok().as_deref())
    }
}

/// Dev/test resolution: the fenced unsafe env override FIRST (so the keychain — and its prompt — is
/// skipped when it is set), then the login keychain. Fail-closed: an inaccessible keychain item is
/// terminal, never a silent fall-through to a different/empty key (which would open the wrong vault).
fn resolve_dev(
    unsafe_env: Option<String>,
    keychain: impl FnOnce() -> Result<Option<String>, String>,
) -> Result<Vec<u8>, String> {
    if let Some(hex) = unsafe_env {
        return decode_key(&hex);
    }
    match keychain() {
        Ok(Some(hex)) => decode_key(&hex),
        Err(access_err) => Err(format!(
            "{access_err}; refusing to fall back to a different key source (a different key would \
             open the wrong vault)"
        )),
        Ok(None) => Err(no_key_advice(cfg!(any(feature = "dev-key", test)))),
    }
}

/// What to do when no key source answered at all.
///
/// `dev_override` is whether THIS BUILD contains the fenced env override — the caller passes its own
/// `cfg!(any(feature = "dev-key", test))`, the same fence [`unsafe_dev_env`] is compiled under, so a
/// release binary never suggests a path that was compiled out of it (and both shapes stay testable
/// from one build). The recovery is stated in plain words; a spec-section reference is a note for us,
/// not advice for whoever is reading the daemon's refusal.
fn no_key_advice(dev_override: bool) -> String {
    let provision = "provision cermetd's service key source and launch it in service mode — on \
                     Linux the systemd encrypted credential `cermet.key` (LoadCredentialEncrypted=), \
                     on macOS the _cermet-owned 0600 master.key under $CERMET_HOME";
    if dev_override {
        format!(
            "no master key: set CERMET_UNSAFE_DEV_MASTER_KEY=1 + CERMET_MASTER_KEY=<64 hex> for \
             local dev, or {provision}"
        )
    } else {
        format!("no master key: {provision}")
    }
}

fn read_keychain() -> Result<Option<String>, String> {
    let entry = match keyring::Entry::new(SERVICE, ACCOUNT) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };
    match entry.get_password() {
        Ok(hex) => Ok(Some(hex)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("master-key keychain item is inaccessible: {e}")),
    }
}

/// The FENCED dev/test override. Compiled in ONLY under `dev-key`/`cfg(test)`; requires BOTH
/// `CERMET_UNSAFE_DEV_MASTER_KEY=1` and `CERMET_MASTER_KEY`; ALWAYS refused under
/// `CERMET_SERVICE_MODE=1`. Exists solely to stop keychain prompts in local dev/test — never a
/// service key source, and compiled out of the shipped (non-dev) binary.
#[cfg(any(feature = "dev-key", test))]
fn unsafe_dev_env() -> Option<String> {
    unsafe_dev_env_inner(
        service_mode_from_env(),
        std::env::var("CERMET_UNSAFE_DEV_MASTER_KEY").ok(),
        std::env::var("CERMET_MASTER_KEY").ok(),
    )
}

#[cfg(not(any(feature = "dev-key", test)))]
fn unsafe_dev_env() -> Option<String> {
    None
}

/// Pure gating for the dev override (env-free, so it's testable without racing on process env).
#[cfg(any(feature = "dev-key", test))]
fn unsafe_dev_env_inner(
    service_mode: bool,
    flag: Option<String>,
    key: Option<String>,
) -> Option<String> {
    if service_mode {
        return None; // never in service mode, belt-and-braces vs the load_with_mode dispatch
    }
    if flag.as_deref() != Some("1") {
        return None; // requires the EXPLICIT unsafe switch
    }
    key
}

fn decode_key(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(format!(
            "master key must be 64 hex chars (32 bytes), got {}",
            hex.len()
        ));
    }
    let mut out = Vec::with_capacity(32);
    let bytes = hex.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or("master key is not valid hex")?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or("master key is not valid hex")?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn service_mode_fails_closed_when_credentials_dir_unset() {
        // In service mode the key comes ONLY from the systemd encrypted credential at
        // $CREDENTIALS_DIRECTORY/cermet.key. If the daemon was NOT launched with
        // LoadCredentialEncrypted (CREDENTIALS_DIRECTORY unset/empty), there is no key source → fail
        // closed. The error names the missing credentials dir, never the login keychain / a file.
        for absent in [None, Some("")] {
            let r = load_service_key(absent);
            assert!(
                r.is_err(),
                "service mode must fail closed without a credentials dir"
            );
            let msg = r.unwrap_err();
            assert!(
                msg.contains("CREDENTIALS_DIRECTORY"),
                "the error must name the missing credentials dir, got: {msg}"
            );
            assert!(
                msg.contains("fail closed"),
                "the error must say it fails closed, got: {msg}"
            );
        }
    }

    #[test]
    fn service_mode_reads_valid_64_hex_credential() {
        // Happy path: a tmpfs CREDENTIALS_DIRECTORY holding a 64-hex cermet.key decodes
        // to the 32 raw bytes.
        let dir = tempdir().unwrap();
        // The real credentials dir is a 0700 tmpfs; force it here so the fixture is umask-safe
        // (under umask 0002 tempdir() yields 0775, which the directory validation correctly refuses).
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key_hex = "ab".repeat(32);
        let kp = dir.path().join("cermet.key");
        std::fs::write(&kp, &key_hex).unwrap();
        // systemd lands the credential 0400; force owner-only here (group/world read is refused).
        std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600)).unwrap();
        let bytes = load_service_key(Some(dir.path().to_str().unwrap())).unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(
            bytes.iter().all(|&b| b == 0xab),
            "decoded bytes must be the credential"
        );
    }

    #[test]
    fn service_mode_accepts_trailing_newline() {
        // systemd-creds may leave a trailing newline; the reader trims before length-checking.
        let dir = tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let kp = dir.path().join("cermet.key");
        std::fs::write(&kp, format!("{}\n", "cd".repeat(32))).unwrap();
        std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600)).unwrap();
        let bytes = load_service_key(Some(dir.path().to_str().unwrap())).unwrap();
        assert_eq!(bytes[0], 0xcd);
    }

    #[test]
    fn service_mode_fails_closed_on_wrong_length() {
        // The key file must be 0600 so this test exercises the LENGTH parse path — a
        // group/world-readable fixture would be rejected by the r/w-bit check FIRST and green
        // for the wrong reason. Assert the error names the length rule, not a permission refusal.
        let dir = tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let kp = dir.path().join("cermet.key");
        std::fs::write(&kp, "abcd").unwrap();
        std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = load_service_key(Some(dir.path().to_str().unwrap())).unwrap_err();
        assert!(
            err.contains("64 hex chars"),
            "must fail on the LENGTH rule, not a permission/other error, got: {err}"
        );
    }

    #[test]
    fn service_mode_fails_closed_on_non_hex() {
        // 0600 fixture so the NON-HEX parse path runs (not the r/w-bit check). Assert the
        // error names the hex rule.
        let dir = tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let kp = dir.path().join("cermet.key");
        std::fs::write(&kp, "zz".repeat(32)).unwrap();
        std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = load_service_key(Some(dir.path().to_str().unwrap())).unwrap_err();
        assert!(
            err.contains("not valid hex"),
            "must fail on the HEX rule, not a permission/other error, got: {err}"
        );
    }

    #[test]
    fn service_mode_fails_closed_on_symlinked_credential() {
        // O_NOFOLLOW: a symlinked cermet.key (e.g. an attacker pointing it at a key they control)
        // must fail closed rather than follow.
        let dir = tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let real = dir.path().join("real.key");
        std::fs::write(&real, "ab".repeat(32)).unwrap();
        symlink(&real, dir.path().join("cermet.key")).unwrap();
        assert!(
            load_service_key(Some(dir.path().to_str().unwrap())).is_err(),
            "a symlinked credential must fail closed (O_NOFOLLOW)"
        );
    }

    #[test]
    fn service_mode_fails_closed_on_group_writable_credentials_dir() {
        // Even with a valid 64-hex cermet.key inside, a group/world-writable credentials
        // dir is refused (another principal could swap the key inode) — defense-in-depth over the tmpfs.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("cermet.key"), "ab".repeat(32)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let err = load_service_key(Some(dir.path().to_str().unwrap())).unwrap_err();
        // Restore so the tempdir can be cleaned up.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            err.contains("CREDENTIALS_DIRECTORY") && err.contains("fail closed"),
            "a group-writable credentials dir must fail closed with a clear reason, got: {err}"
        );
    }

    #[test]
    fn service_mode_fails_closed_on_group_or_world_readable_credentials_dir() {
        // A root-owned (here owner-owned) 0755 credentials dir holding a valid cermet.key
        // is world-READABLE — systemd provisions the dir 0700 root-private, so anything looser is
        // a misconfigured launch context the defense-in-depth layer must catch. Refuse it.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("cermet.key"), "ab".repeat(32)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = load_service_key(Some(dir.path().to_str().unwrap())).unwrap_err();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            err.contains("CREDENTIALS_DIRECTORY") && err.contains("fail closed"),
            "a world-readable credentials dir must fail closed with a clear reason, got: {err}"
        );
    }

    #[test]
    fn service_key_file_fails_closed_on_group_or_world_readable() {
        // The master key file itself must never be group/world-readable. A cermet-owned
        // 0644 cermet.key passes the owner/regular check but leaks the key to every uid — refuse it.
        let dir = tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = dir.path().join("cermet.key");
        std::fs::write(&p, "ab".repeat(32)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load_service_key_file(&p).is_err(),
            "a 0644 world-readable key file must fail closed"
        );
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            load_service_key_file(&p).is_err(),
            "a 0640 group-readable key file must fail closed"
        );
        // A 0600 owner-only key file still reads.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_service_key_file(&p).unwrap().len(), 32);
    }

    #[test]
    fn service_mode_fails_closed_when_credential_absent() {
        // CREDENTIALS_DIRECTORY is set but cermet.key does not exist in it → fail closed.
        let dir = tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            load_service_key(Some(dir.path().to_str().unwrap())).is_err(),
            "a missing cermet.key must fail closed"
        );
    }

    #[test]
    fn service_key_file_reads_owner_owned_64_hex() {
        // The macOS service source (also the shared core): a regular, owner-owned key file holding 64
        // hex decodes to the 32 raw bytes. In production this is the _cermet-owned 0600 master.key;
        // read_nofollow requires owner==euid (the _cermet uid).
        let dir = tempdir().unwrap();
        let p = dir.path().join("master.key");
        std::fs::write(&p, "ef".repeat(32)).unwrap();
        // The _cermet-owned key file is 0600; force it here (group/world read is refused).
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let bytes = load_service_key_file(&p).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(
            bytes[0], 0xef,
            "decoded bytes must be the key file's contents"
        );
    }

    #[test]
    fn service_key_file_fails_closed_on_absent_and_symlink() {
        let dir = tempdir().unwrap();
        assert!(
            load_service_key_file(&dir.path().join("nope.key")).is_err(),
            "an absent key file must fail closed"
        );
        // O_NOFOLLOW: a symlinked master.key (attacker pointing it at a key they control) is refused.
        let real = dir.path().join("real.key");
        std::fs::write(&real, "ab".repeat(32)).unwrap();
        symlink(&real, dir.path().join("master.key")).unwrap();
        assert!(
            load_service_key_file(&dir.path().join("master.key")).is_err(),
            "a symlinked key file must fail closed (O_NOFOLLOW)"
        );
    }

    // ---- CUSTODY-LADDER M2: the declared rung selects the key SOURCE ---------------------------

    /// `file-protected` reads the daemon-owned `0600 master.key` under `$CERMET_HOME` — the SAME
    /// reader macOS has always used, now reachable on Linux too. One reader, one validation.
    #[test]
    fn the_file_protected_rung_reads_the_daemon_owned_key_file() {
        let home = tempdir().unwrap();
        let key = home.path().join("master.key");
        std::fs::write(&key, "ab".repeat(32)).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let bytes = load_with_mode(home.path(), true, Some(CustodyProfile::FileProtected)).unwrap();
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().all(|&b| b == 0xab));
    }

    /// The declared rung is AUTHORITATIVE, not a hint. A config that says `systemd-host` reads the
    /// systemd credential and NOTHING else — a `master.key` sitting in the state dir (left by an
    /// earlier install, or dropped there by someone who could write it) must never be picked up
    /// instead. Fail closed, naming the source that is actually missing.
    #[test]
    fn a_declared_sealed_rung_never_falls_back_to_a_key_file_that_is_present() {
        let home = tempdir().unwrap();
        let key = home.path().join("master.key");
        std::fs::write(&key, "cd".repeat(32)).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        for profile in [CustodyProfile::SystemdHost, CustodyProfile::SystemdTpm2Host] {
            let error = load_with_mode(home.path(), true, Some(profile))
                .expect_err("a sealed rung must not read the key file");
            // The two platforms refuse for different reasons — Linux has no credentials directory,
            // macOS has no such mechanism at all — so assert the SUBSTANCE both must carry: the
            // refusal is about the sealed rung, and never about the key file it declined to read.
            assert!(
                error.contains(profile.as_str()) || error.contains("CREDENTIALS_DIRECTORY"),
                "the refusal must name the sealed source it could not use: {error}"
            );
            assert!(
                !error.contains("master.key"),
                "a sealed rung must never mention the key file as a source: {error}"
            );
        }
    }

    /// Service mode with no declared rung is a refusal, not a default. Belt-and-braces over the
    /// config's own requirement: two paths reach this loader (config and a caller), and neither may
    /// end in a guessed key source.
    #[test]
    fn service_mode_without_a_declared_rung_fails_closed() {
        let home = tempdir().unwrap();
        let error = load_with_mode(home.path(), true, None)
            .expect_err("an undeclared rung must not resolve to any source");
        assert!(error.contains("custody_profile"), "{error}");
    }

    #[test]
    fn dev_unsafe_env_preempts_keychain_so_no_prompt() {
        // The crux of the keychain-prompt fix: when the override yields a key, the keychain thunk is
        // NEVER invoked, so the daemon/test never triggers a macOS keychain prompt.
        use std::cell::Cell;
        let kc_called = Cell::new(false);
        let r = resolve_dev(Some("ab".repeat(32)), || {
            kc_called.set(true);
            Ok(None)
        });
        assert_eq!(r.unwrap()[0], 0xab);
        assert!(
            !kc_called.get(),
            "keychain must not be consulted when the dev override is set (no prompt)"
        );
    }

    #[test]
    fn dev_falls_to_keychain_when_override_absent() {
        let from_kc = resolve_dev(None, || Ok(Some("cd".repeat(32)))).unwrap();
        assert_eq!(from_kc[0], 0xcd);
    }

    #[test]
    fn dev_keychain_access_error_fails_closed() {
        let r = resolve_dev(None, || Err("locked".to_string()));
        assert!(r.is_err(), "an inaccessible keychain item must fail closed");
        assert!(r.unwrap_err().contains("wrong vault"));
    }

    #[test]
    fn dev_no_key_anywhere_errors() {
        assert!(resolve_dev(None, || Ok(None)).is_err());
    }

    /// the no-key advice told EVERY operator to set
    /// `CERMET_UNSAFE_DEV_MASTER_KEY` — a dead end in a release binary, where that path is compiled
    /// out — and cited "(F2)", an internal spec section, at a user. Both shapes are pinned here from
    /// one build; which one ships is the caller's `cfg!`, the same fence the override uses.
    #[test]
    fn the_no_key_advice_offers_the_dev_override_only_where_it_is_compiled_in() {
        let release = no_key_advice(false);
        assert!(
            !release.contains("CERMET_UNSAFE_DEV_MASTER_KEY")
                && !release.contains("CERMET_MASTER_KEY"),
            "a release binary must not suggest a path it does not contain: {release}"
        );
        let dev = no_key_advice(true);
        assert!(
            dev.contains("CERMET_UNSAFE_DEV_MASTER_KEY=1")
                && dev.contains("CERMET_MASTER_KEY=<64 hex>"),
            "a dev build states the override it does contain: {dev}"
        );
        for advice in [&release, &dev] {
            assert!(
                !advice.contains("F2"),
                "an internal spec reference is not operator advice: {advice}"
            );
            assert!(
                advice.contains("service mode") && advice.contains("cermet.key"),
                "every shape names the real recovery — provisioning the service key: {advice}"
            );
        }
        // The shipped message uses this build's own fence, so it can never advertise a compiled-out
        // override.
        assert_eq!(
            resolve_dev(None, || Ok(None)).unwrap_err(),
            no_key_advice(cfg!(any(feature = "dev-key", test)))
        );
    }

    #[test]
    fn dev_override_gating_is_explicit_and_refuses_service_mode() {
        let key = || Some("ab".repeat(32));
        // service mode → refused even with flag+key present (belt-and-braces over the dispatch).
        assert!(unsafe_dev_env_inner(true, Some("1".into()), key()).is_none());
        // dev, no flag (or wrong flag) → None even with the key set.
        assert!(unsafe_dev_env_inner(false, None, key()).is_none());
        assert!(unsafe_dev_env_inner(false, Some("0".into()), key()).is_none());
        // dev, explicit flag + key → the override.
        assert_eq!(unsafe_dev_env_inner(false, Some("1".into()), key()), key());
        // dev, flag but no key → None.
        assert!(unsafe_dev_env_inner(false, Some("1".into()), None).is_none());
    }

    #[test]
    fn decode_key_accepts_64_hex_and_rejects_otherwise() {
        let k = decode_key(&"ab".repeat(32)).unwrap();
        assert_eq!(k.len(), 32);
        assert!(decode_key("00").is_err(), "short key rejected");
        assert!(decode_key(&"zz".repeat(32)).is_err(), "non-hex rejected");
    }
}
