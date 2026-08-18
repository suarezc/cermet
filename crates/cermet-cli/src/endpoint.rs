//! ctl endpoint resolution for the installed `cermet` operator CLI.
//!
//! The installed CLI resolves the daemon endpoint WITHOUT an ambient launcher wrapper: it defaults
//! the socket to `/var/run/cermetd/ctl.sock` and resolves the trusted daemon uid from the
//! root-managed service account (`cermet` on Linux, `_cermet` on macOS). `--socket` /
//! `CERMET_CTL_SOCK` and `CERMET_DAEMON_UID` remain DEV OVERRIDES. Resolution refuses on a MISSING
//! service account (production `getpwnam` cannot detect a duplicate/ambiguous name — it returns the
//! first entry; the ambiguous-refusal path is a resolver-contract branch exercised only in tests) —
//! the resolved uid is what keyholder verification binds to, so
//! the peer we hand a request (and, on `connect`, a token) to is never guessed. Peer-uid verification
//! at connect time is unchanged (`CtlBrokerClient` still verifies the connected peer against this uid).

use std::path::PathBuf;

/// The installed daemon's authoritative ctl socket (the root-managed runtime dir). macOS wipes
/// `/var/run` at boot, so its runtime dir is `setup::RUNTIME_DIR` in persistent `/var`; on Linux the
/// tmpfiles-provisioned `/run/cermetd` is reachable under either spelling (`/var/run` → `/run`).
#[cfg(target_os = "macos")]
pub const DEFAULT_CTL_SOCK: &str = "/var/cermetd/ctl.sock";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_CTL_SOCK: &str = "/var/run/cermetd/ctl.sock";

/// The root-managed daemon service account whose uid keyholder verification binds to.
pub fn service_account_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "_cermet"
    }
    #[cfg(not(target_os = "macos"))]
    {
        "cermet"
    }
}

/// Resolve `(ctl_sock, daemon_uid)`. `socket_override` is `--socket`; `sock_env` is
/// `CERMET_CTL_SOCK`; `uid_env` is `CERMET_DAEMON_UID`. `resolve_account` maps the service-account
/// name to `Ok(Some(uid))` (found), `Ok(None)` (no such account — refuse), or `Err` (ambiguous /
/// lookup error — refuse). Pure + resolver-injected so the precedence and refusal paths are testable.
pub fn resolve_ctl_endpoint<F>(
    socket_override: Option<String>,
    sock_env: Option<String>,
    uid_env: Option<String>,
    account: &str,
    resolve_account: F,
) -> Result<(PathBuf, u32), String>
where
    F: FnOnce(&str) -> Result<Option<u32>, String>,
{
    // Socket: explicit override → env override → the installed default. Never reconstructed.
    let sock = socket_override
        .filter(|s| !s.is_empty())
        .or_else(|| sock_env.filter(|s| !s.is_empty()))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CTL_SOCK));

    // Uid: explicit env dev override → resolve the root-managed service account. Fail closed.
    let uid = match uid_env.filter(|s| !s.is_empty()) {
        Some(s) => s
            .parse::<u32>()
            .map_err(|e| format!("CERMET_DAEMON_UID ({s:?}) is not a valid uid: {e}"))?,
        None => match resolve_account(account) {
            Ok(Some(uid)) => uid,
            Ok(None) => {
                return Err(format!(
                "cannot resolve the daemon service account `{account}` (no such user); the daemon \
                     must be installed. Refusing to guess the peer we hand a request to — set \
                     CERMET_DAEMON_UID for a dev override."
            ))
            }
            Err(e) => {
                return Err(format!(
                    "ambiguous/failed resolution of the daemon service account `{account}` ({e}); \
                     refusing (fail closed) — set CERMET_DAEMON_UID for a dev override."
                ))
            }
        },
    };
    Ok((sock, uid))
}

/// The production account resolver: `getpwnam(3)`. A `NULL` return means "no such account" → `None`
/// (the caller refuses). A match yields the uid of the FIRST passwd entry for `name` — `getpwnam`
/// does not detect a duplicate account name (a system misconfiguration it silently resolves to the
/// first hit), so this resolver never returns the `Err`/ambiguous arm; that arm is reachable only via
/// an injected resolver (tests). `getpwnam` is not thread-safe, but the CLI resolves the endpoint
/// once, single-threaded, before any runtime is built.
fn getpwnam_uid(name: &str) -> Result<Option<u32>, String> {
    use std::ffi::CString;
    let c =
        CString::new(name).map_err(|_| "service account name has an interior NUL".to_string())?;
    // SAFETY: `c` is a valid NUL-terminated C string for the duration of the call; we read only
    // `pw_uid` from the returned static-storage `passwd` before any other libc call can clobber it.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        Ok(None)
    } else {
        Ok(Some(unsafe { (*pw).pw_uid }))
    }
}

/// Production resolution: platform service account + `getpwnam`.
pub fn resolve_ctl_endpoint_real(
    socket_override: Option<String>,
    sock_env: Option<String>,
    uid_env: Option<String>,
) -> Result<(PathBuf, u32), String> {
    resolve_ctl_endpoint(
        socket_override,
        sock_env,
        uid_env,
        service_account_name(),
        getpwnam_uid,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_uid(u: u32) -> impl FnOnce(&str) -> Result<Option<u32>, String> {
        move |_| Ok(Some(u))
    }

    #[test]
    fn default_resolution_uses_the_installed_socket_and_service_account_uid() {
        let (sock, uid) =
            resolve_ctl_endpoint(None, None, None, "cermet", ok_uid(414)).expect("resolves");
        assert_eq!(sock, PathBuf::from(DEFAULT_CTL_SOCK));
        assert_eq!(uid, 414);
    }

    #[test]
    fn dev_overrides_take_precedence_and_skip_account_resolution() {
        let (sock, uid) = resolve_ctl_endpoint(
            Some("/dev/ctl.sock".into()),
            Some("/ignored/env.sock".into()),
            Some("900".into()),
            "cermet",
            |_| panic!("account resolver must not run when CERMET_DAEMON_UID is set"),
        )
        .expect("overrides win");
        assert_eq!(sock, PathBuf::from("/dev/ctl.sock"));
        assert_eq!(uid, 900);
    }

    #[test]
    fn env_socket_is_used_when_no_flag_override() {
        let (sock, _uid) = resolve_ctl_endpoint(
            None,
            Some("/run/env.sock".into()),
            Some("1".into()),
            "cermet",
            ok_uid(1),
        )
        .expect("env sock");
        assert_eq!(sock, PathBuf::from("/run/env.sock"));
    }

    #[test]
    fn a_missing_service_account_refuses() {
        let err = resolve_ctl_endpoint(None, None, None, "cermet", |_| Ok(None))
            .expect_err("a missing account must refuse");
        assert!(err.contains("cannot resolve"), "{err}");
    }

    #[test]
    fn an_ambiguous_service_account_refuses() {
        let err = resolve_ctl_endpoint(None, None, None, "cermet", |_| {
            Err("two passwd entries claim `cermet`".into())
        })
        .expect_err("an ambiguous account must refuse");
        assert!(err.to_lowercase().contains("ambiguous"), "{err}");
    }

    #[test]
    fn an_unparseable_uid_override_refuses() {
        let err = resolve_ctl_endpoint(None, None, Some("not-a-uid".into()), "cermet", ok_uid(1))
            .expect_err("bad uid override must refuse");
        assert!(err.contains("not a valid uid"), "{err}");
    }
}
