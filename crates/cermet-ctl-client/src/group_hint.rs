//! The `ctl.sock` permission-denied diagnosis: why the operator's FIRST command after install
//! hits a permission wall, said on the path they are already walking.
//!
//! `setup` adds the invoking human to `cermet-approvers`, and `ctl.sock` is group-gated on exactly
//! that group — but supplementary group membership is stamped into a process at LOGIN, so the
//! session that just ran `sudo cermet setup` still carries the old group set. Every command in that
//! session gets `EACCES` on connect. Setup warns and the quickstart documents it; neither is on the
//! path, and the error the operator actually reads teaches nothing.
//!
//! So the connect error itself carries the diagnosis: on a permission-denied connect only, ask the
//! DIRECTORY whether this user is in the group (`id -nG <user>`) and the PROCESS what groups it is
//! actually running with (`id -nG`). Membership granted but not live IS the login-lag, and it is the
//! only state that earns the re-login text. Not a member at all gets the remedy setup prints. A live
//! member who still gets `EACCES` gets the plain error, undiagnosed — a wrong diagnosis is worse
//! than none.
//!
//! Read-only, cheap, and never on a successful connect: the probes run only inside the connect
//! error path, and only for `PermissionDenied`. There is no daemon contact — by definition the
//! daemon is unreachable in this state.

use std::io::ErrorKind;
use std::process::Command;

/// The group `ctl.sock` is gated on (setgid from the daemon's runtime dir).
pub const APPROVERS_GROUP: &str = "cermet-approvers";

/// Which platform's remedy to name. macOS has no `sg`/`newgrp` — never suggest a tool the platform
/// lacks — so its arm is "new terminal window", not a one-shot command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
}

/// This build's platform, resolved once at compile time.
pub const THIS_PLATFORM: Platform = if cfg!(target_os = "macos") {
    Platform::MacOs
} else {
    Platform::Linux
};

/// What the DIRECTORY (NSS / Directory Service) says about this user's membership — deliberately
/// distinct from the process's live group set, because the gap between them is the whole diagnosis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Membership {
    /// The directory lists the user in [`APPROVERS_GROUP`].
    Granted,
    /// The directory does not list the user in [`APPROVERS_GROUP`].
    Absent,
}

/// The diagnosis, as a pure function of the four facts it needs: the errno kind, what the directory
/// says, what the live process carries, and the platform. `None` means "say nothing extra" — the
/// plain transport error stands.
///
/// `user` names the human for the remedy command; `invocation` is the already-shell-quoted command
/// line the operator ran, re-quoted here for `sg -c`.
pub fn ctl_permission_hint(
    kind: ErrorKind,
    directory: Membership,
    live_member: bool,
    platform: Platform,
    user: &str,
    invocation: &str,
) -> Option<String> {
    // Rust maps both EACCES and EPERM to `PermissionDenied`; nothing else is a group problem.
    if kind != ErrorKind::PermissionDenied {
        return None;
    }
    match (directory, live_member) {
        // A live member denied anyway: the cause is something else entirely (a stopped daemon's
        // stale socket, a hand-edited mode). Say nothing — a confident wrong answer costs more
        // than the plain errno.
        (Membership::Granted, true) => None,
        // The login lag: granted in the directory, absent from this process. THE bug this module
        // exists for.
        (Membership::Granted, false) => Some(match platform {
            Platform::Linux => format!(
                "setup added you to {APPROVERS_GROUP}, and group membership loads at login — log \
                 out and back in once,\nor run this one command as:\n    sg {APPROVERS_GROUP} -c \
                 {}",
                shell_quote(invocation)
            ),
            // No `sg`/`newgrp` on macOS: membership reaches processes started AFTER the change, so
            // the remedy is a new session, not a command.
            Platform::MacOs => format!(
                "setup added you to {APPROVERS_GROUP}, and membership reaches new processes — open \
                 a new terminal window and rerun,\nor log out and back in."
            ),
        }),
        // Never granted at all. Setup's own remedy, verbatim in shape — and pointedly NOT the
        // re-login text, which would send someone with no membership around a useless loop.
        (Membership::Absent, _) => Some(match platform {
            Platform::Linux => format!(
                "this socket is gated by the {APPROVERS_GROUP} group, and {user} is not a \
                 member:\n    sudo usermod -aG {APPROVERS_GROUP} {user}   (then log out and back \
                 in)"
            ),
            Platform::MacOs => format!(
                "this socket is gated by the {APPROVERS_GROUP} group, and {user} is not a \
                 member:\n    sudo dseditgroup -o edit -a {user} -t user {APPROVERS_GROUP}   (then \
                 log out and back in)"
            ),
        }),
    }
}

/// The impure half: gather the four facts about THIS process and hand them to
/// [`ctl_permission_hint`]. Returns `None` — silently, deliberately — whenever a probe cannot
/// answer, because a failed probe is not evidence of anything.
///
/// Costs nothing on any error but `PermissionDenied`: the gate is here, before the probes, so an
/// absent daemon (the common `NotFound`) never spawns a process. Read-only, no daemon contact.
pub fn hint_for_this_process(kind: ErrorKind) -> Option<String> {
    if kind != ErrorKind::PermissionDenied {
        return None;
    }
    let user = id_output(&["-un"])?;
    let user = user.trim();
    // `id -nG <user>` asks the DIRECTORY (NSS / Directory Service) — the same question, by the same
    // command, that `cermet setup` asked when it decided whether to add the user.
    let directory = if groups_from(&["-nG", user])?
        .iter()
        .any(|g| g == APPROVERS_GROUP)
    {
        Membership::Granted
    } else {
        Membership::Absent
    };
    // `id -nG` with no user asks THIS PROCESS's live credentials (getgroups) — what the kernel will
    // actually check against the socket's group.
    let live_member = groups_from(&["-nG"])?.iter().any(|g| g == APPROVERS_GROUP);
    let invocation = std::env::args()
        .map(|a| shell_quote(&a))
        .collect::<Vec<_>>()
        .join(" ");
    ctl_permission_hint(
        kind,
        directory,
        live_member,
        THIS_PLATFORM,
        user,
        &invocation,
    )
}

/// Run `id <args>` and return its stdout, or `None` if it could not answer.
fn id_output(args: &[&str]) -> Option<String> {
    let out = Command::new("id").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn groups_from(args: &[&str]) -> Option<Vec<String>> {
    Some(
        id_output(args)?
            .split_whitespace()
            .map(str::to_string)
            .collect(),
    )
}

/// Single-quote `arg` for a POSIX shell when it holds anything the shell would act on.
fn shell_quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '=' | ':'));
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINUX_LAG: (Membership, bool, Platform) = (Membership::Granted, false, Platform::Linux);

    fn linux_lag_hint() -> String {
        ctl_permission_hint(
            ErrorKind::PermissionDenied,
            LINUX_LAG.0,
            LINUX_LAG.1,
            LINUX_LAG.2,
            "alice",
            "cermet connect github",
        )
        .expect("granted-but-not-live must teach")
    }

    #[test]
    fn granted_but_not_live_teaches_the_login_lag_on_linux() {
        let hint = linux_lag_hint();
        assert!(
            hint.contains("setup added you to cermet-approvers"),
            "must name the cause: {hint}"
        );
        assert!(
            hint.contains("group membership loads at login"),
            "must name the mechanism: {hint}"
        );
        assert!(
            hint.contains("log out and back in"),
            "must name the durable fix: {hint}"
        );
        assert!(
            hint.contains("sg cermet-approvers -c 'cermet connect github'"),
            "must name the one-shot command carrying THEIR invocation: {hint}"
        );
    }

    #[test]
    fn granted_but_not_live_teaches_the_login_lag_on_macos() {
        let hint = ctl_permission_hint(
            ErrorKind::PermissionDenied,
            Membership::Granted,
            false,
            Platform::MacOs,
            "alice",
            "cermet connect github",
        )
        .expect("granted-but-not-live must teach on macOS too");
        assert!(
            hint.contains("setup added you to cermet-approvers"),
            "must name the cause: {hint}"
        );
        assert!(
            hint.contains("new terminal window"),
            "macOS remedy is a new session, not a command: {hint}"
        );
        assert!(
            !hint.contains("sg ") && !hint.contains("newgrp"),
            "macOS has no sg/newgrp — never suggest a tool the platform lacks: {hint}"
        );
    }

    #[test]
    fn not_a_member_gets_the_membership_remedy_not_the_relogin_text() {
        let linux = ctl_permission_hint(
            ErrorKind::PermissionDenied,
            Membership::Absent,
            false,
            Platform::Linux,
            "alice",
            "cermet connect github",
        )
        .expect("a non-member must still be told what to do");
        assert!(
            linux.contains("sudo usermod -aG cermet-approvers alice"),
            "must carry setup's own remedy: {linux}"
        );
        assert!(
            !linux.contains("setup added you"),
            "the two cases must not blur — nothing was added: {linux}"
        );
        assert!(
            !linux.contains("sg cermet-approvers -c"),
            "a one-shot sg cannot help someone with no membership: {linux}"
        );

        let macos = ctl_permission_hint(
            ErrorKind::PermissionDenied,
            Membership::Absent,
            false,
            Platform::MacOs,
            "alice",
            "cermet connect github",
        )
        .expect("a non-member must still be told what to do on macOS");
        assert!(
            macos.contains("sudo dseditgroup -o edit -a alice -t user cermet-approvers"),
            "must carry setup's own macOS remedy: {macos}"
        );
        assert!(
            !macos.contains("setup added you"),
            "the two cases must not blur: {macos}"
        );
    }

    #[test]
    fn a_live_member_hitting_eacces_is_never_diagnosed() {
        for platform in [Platform::Linux, Platform::MacOs] {
            assert_eq!(
                ctl_permission_hint(
                    ErrorKind::PermissionDenied,
                    Membership::Granted,
                    true,
                    platform,
                    "alice",
                    "cermet connect github",
                ),
                None,
                "a live member's EACCES has some OTHER cause; a wrong diagnosis is worse than none"
            );
        }
    }

    #[test]
    fn non_permission_errors_are_never_diagnosed() {
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::ConnectionRefused,
            ErrorKind::TimedOut,
        ] {
            assert_eq!(
                ctl_permission_hint(
                    kind,
                    Membership::Granted,
                    false,
                    Platform::Linux,
                    "alice",
                    "cermet connect github",
                ),
                None,
                "{kind:?} is not a group problem"
            );
        }
    }

    #[test]
    fn the_invocation_is_quoted_for_the_shell() {
        assert_eq!(shell_quote("cermet"), "cermet");
        assert_eq!(shell_quote("--provider=github"), "--provider=github");
        assert_eq!(shell_quote("two words"), "'two words'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        let hint = ctl_permission_hint(
            ErrorKind::PermissionDenied,
            Membership::Granted,
            false,
            Platform::Linux,
            "alice",
            "cermet run stripe.refund --note 'late night'",
        )
        .expect("teaches");
        assert!(
            hint.contains(
                r"sg cermet-approvers -c 'cermet run stripe.refund --note '\''late night'\'''"
            ),
            "the re-run command must survive quoting: {hint}"
        );
    }
}
