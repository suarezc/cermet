//! Human-presence gate for the human-only mutations (approve / deny).

/// The result of a presence check. Only `Confirmed` may proceed to a mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceOutcome {
    /// A live human was verified (e.g. Touch-ID success).
    Confirmed,
    /// The human explicitly declined / cancelled.
    Denied,
    /// No usable presence mechanism on this host.
    Unavailable(String),
}

/// A presence check.
pub trait Presence: Send + Sync {
    /// Prompt for human presence to authorize `reason`.
    fn confirm(&self, reason: &str) -> PresenceOutcome;
}

/// A presence that always returns a fixed outcome.
pub struct FixedPresence(pub PresenceOutcome);

impl FixedPresence {
    /// The fail-closed default: presence is unavailable.
    pub fn fail_closed() -> Self {
        FixedPresence(PresenceOutcome::Unavailable(
            "no biometric presence on this host; approve in your terminal with `cermet approve`"
                .to_string(),
        ))
    }
}

impl Presence for FixedPresence {
    fn confirm(&self, _reason: &str) -> PresenceOutcome {
        self.0.clone()
    }
}

// Only the macOS device-owner path (and its unit tests) map an LAContext reply to an outcome.
#[cfg(any(target_os = "macos", test))]
fn interpret(success: bool, had_error: bool) -> PresenceOutcome {
    if success && !had_error {
        PresenceOutcome::Confirmed
    } else {
        PresenceOutcome::Denied
    }
}

/// macOS device-owner authentication via `LAContext`: Touch ID when available, with the account
/// password as the OS-controlled fallback. Used for custody writes, which must remain possible on a
/// Mac without enrolled biometrics while still requiring a live human.
///
/// This is the ONLY macOS adapter, deliberately. A biometrics-only twin
/// (`DeviceOwnerAuthenticationWithBiometrics`) existed here with no caller; keeping an unused one
/// around invites someone wiring the biometrics-only policy by accident and locking out every Mac
/// with no enrolled Touch ID. If a biometrics-only gate is ever genuinely wanted, add it back with
/// its caller in the same change.
#[cfg(target_os = "macos")]
pub struct MacosUserPresence;

#[cfg(target_os = "macos")]
impl Presence for MacosUserPresence {
    fn confirm(&self, reason: &str) -> PresenceOutcome {
        macos::evaluate(
            objc2_local_authentication::LAPolicy::DeviceOwnerAuthentication,
            reason,
        )
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    use super::{interpret, PresenceOutcome};

    /// The LAContext dialog is drawn by the OS on the physical screen, so a terminal-only
    /// caller (SSH, an agent, a second monitor) saw NOTHING between stage and commit — a working
    /// gate is indistinguishable from a hang, and on success nothing said a ceremony happened at
    /// all, which reads as a silent bypass. These two lines are narration only: stderr, so receipts
    /// on stdout stay machine-parseable, and no gate logic, timeout, or outcome mapping is touched.
    ///
    /// NOTE: not unit-tested. The prints bracket a real `LAContext` evaluation, which cannot be
    /// driven from a test process; the outcome mapping they narrate is pinned by `interpret`'s own
    /// test. A documented gap beats a mock of the OS dialog.
    fn announce(outcome: PresenceOutcome) -> PresenceOutcome {
        match &outcome {
            PresenceOutcome::Confirmed => {
                eprintln!("cermet: device-owner authentication confirmed")
            }
            PresenceOutcome::Denied => {
                eprintln!("cermet: device-owner authentication declined — nothing was committed")
            }
            PresenceOutcome::Unavailable(why) => {
                eprintln!("cermet: device-owner authentication unavailable — {why}")
            }
        }
        outcome
    }

    pub fn evaluate(policy: LAPolicy, reason: &str) -> PresenceOutcome {
        let ctx = unsafe { LAContext::new() };

        if unsafe { ctx.canEvaluatePolicy_error(policy) }.is_err() {
            return announce(PresenceOutcome::Unavailable(
                "device-owner authentication is not available on this host".to_string(),
            ));
        }

        let reason_ns = NSString::from_str(reason);
        let (tx, rx) = mpsc::channel::<PresenceOutcome>();
        let reply = RcBlock::new(move |success: objc2::runtime::Bool, error: *mut NSError| {
            let _ = tx.send(interpret(success.as_bool(), !error.is_null()));
        });
        eprintln!(
            "cermet: waiting for device-owner authentication (Touch ID / password) — check your \
             screen"
        );
        unsafe { ctx.evaluatePolicy_localizedReason_reply(policy, &reason_ns, &reply) };

        announce(
            rx.recv_timeout(Duration::from_secs(60))
                .unwrap_or_else(|_| {
                    PresenceOutcome::Unavailable("authentication prompt timed out".to_string())
                }),
        )
    }
}

/// TEST-ONLY presence backend (cargo feature `test-presence`, OFF by default).
///
/// This exists ONLY so unattended rehearsals can run the human-only ceremony (sentence
/// `allow`/`revoke` and `approve`) without a live password / Touch-ID prompt. It is compiled
/// exclusively under `#[cfg(feature = "test-presence")]`, so the default production build
/// (`cargo build --release -p cermet-cli`, no feature) contains none of this code — the shipped
/// binary keeps its PAM-only / Touch-ID gate unchanged.
///
/// Two independent guards keep it from ever being a silent bypass:
///   1. **Compile-time**: absent unless the `test-presence` feature is explicitly enabled.
///   2. **Runtime, per-invocation**: even in a test build it returns `Confirmed` ONLY when the
///      environment variable `CERMET_TEST_PRESENCE` is exactly `"1"`. Anything else (unset, `"0"`,
///      any other value) FAILS CLOSED with `Unavailable`, identical to the Linux fail-closed default.
///
/// Every `Confirmed` prints a loud, unmissable stderr banner naming the account and the action, so a
/// bypass can never happen silently.
#[cfg(feature = "test-presence")]
pub struct TestPresence;

#[cfg(feature = "test-presence")]
impl Presence for TestPresence {
    fn confirm(&self, reason: &str) -> PresenceOutcome {
        // A runtime switch, per invocation. Only the exact string "1" bypasses; everything else
        // (including unset and "0") fails closed exactly like `FixedPresence::fail_closed`.
        if std::env::var("CERMET_TEST_PRESENCE").as_deref() != Ok("1") {
            return PresenceOutcome::Unavailable(
                "test-presence build, but CERMET_TEST_PRESENCE!=1 — failing closed. Set \
                 CERMET_TEST_PRESENCE=1 to bypass the password ceremony for unattended testing."
                    .to_string(),
            );
        }

        let account = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "<unknown>".to_string());

        eprintln!(
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        );
        eprintln!("!!! TEST PRESENCE ACTIVE — password ceremony bypassed — NON-PRODUCTION !!!");
        eprintln!("!!!   account : {account}");
        eprintln!("!!!   action  : {reason}");
        eprintln!("!!!   (built with feature `test-presence` + CERMET_TEST_PRESENCE=1)");
        eprintln!(
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        );

        PresenceOutcome::Confirmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmed_only_on_success_with_no_error() {
        assert_eq!(interpret(true, false), PresenceOutcome::Confirmed);
        assert_eq!(interpret(false, false), PresenceOutcome::Denied);
        assert_eq!(interpret(true, true), PresenceOutcome::Denied);
        assert_eq!(interpret(false, true), PresenceOutcome::Denied);
    }

    #[test]
    fn fail_closed_default_is_unavailable() {
        match FixedPresence::fail_closed().confirm("x") {
            PresenceOutcome::Unavailable(_) => {}
            other => panic!("fail_closed must be Unavailable, got {other:?}"),
        }
    }
}

// TEST-ONLY backend tests. Compiled only under `--features test-presence`, so they never run in a
// production build. All assertions live in ONE test: `CERMET_TEST_PRESENCE` is process-global, and
// `cargo test` shares one process across threads — a single test avoids cross-test env races (under
// `cargo nextest` each test is already its own process).
#[cfg(all(test, feature = "test-presence"))]
mod test_presence_tests {
    use super::*;

    #[test]
    fn confirms_only_when_env_is_exactly_one_else_fails_closed() {
        // env unset → fail closed (Unavailable), exactly like the Linux fail-closed default.
        std::env::remove_var("CERMET_TEST_PRESENCE");
        assert!(
            matches!(
                TestPresence.confirm("unit: unset"),
                PresenceOutcome::Unavailable(_)
            ),
            "unset CERMET_TEST_PRESENCE must fail closed"
        );

        // env == "0" → fail closed.
        std::env::set_var("CERMET_TEST_PRESENCE", "0");
        assert!(
            matches!(
                TestPresence.confirm("unit: 0"),
                PresenceOutcome::Unavailable(_)
            ),
            "CERMET_TEST_PRESENCE=0 must fail closed"
        );

        // env is some other truthy-looking value → still fail closed (only exact "1" opts in).
        std::env::set_var("CERMET_TEST_PRESENCE", "yes");
        assert!(
            matches!(
                TestPresence.confirm("unit: yes"),
                PresenceOutcome::Unavailable(_)
            ),
            "any value other than exactly \"1\" must fail closed"
        );

        // env == "1" → Confirmed (the deliberate, per-invocation switch).
        std::env::set_var("CERMET_TEST_PRESENCE", "1");
        assert_eq!(
            TestPresence.confirm("unit: sentence allow"),
            PresenceOutcome::Confirmed,
            "CERMET_TEST_PRESENCE=1 must confirm"
        );

        std::env::remove_var("CERMET_TEST_PRESENCE");
    }
}
