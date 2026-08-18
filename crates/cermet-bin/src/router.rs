//! The closed dispatch table of the one shipped executable.
//!
//! Cermet ships ONE regular, root-owned `0755` file. `cermetd` and `git-remote-cermet` are
//! root-created relative symlinks to it, so the role a process plays is decided here — from the
//! invocation itself, by exact byte comparison, against a CLOSED list of names. Two rules make this
//! safe to reason about:
//!
//! * **Never `current_exe()`.** The daemon writes a git `update` hook stub into each mirror that
//!   execs its own program path; through a `cermetd -> cermet` symlink that path commonly RESOLVES
//!   to `.../cermet`. A router keyed on the resolved executable would send every hook client into
//!   the operator CLI and break every push. The internal `git-update-hook` argument is therefore
//!   matched FIRST, before any name is looked at — exactly the order the daemon's own entry used.
//! * **Never an environment variable.** Role selection from the environment would be a door sudo's
//!   `NOSETENV` and the service managers cannot see; the caller's argv is what they actually
//!   control, and it confers no authority (see below).
//!
//! Forging a name confers nothing. `execve` does not hand a process the file owner's privileges:
//! systemd/launchd choose the service uid before exec, sudo may choose only the agent uid for one
//! exact command, and every other launch keeps the caller's uid. A T1/T2/T3 caller who runs the
//! `cermetd` alias — or forges `argv[0]` with `exec -a` — still arrives at the service-uid asserts,
//! the `0700` state dir, and the peercred socket gates as itself, and is refused there.
//!
//! An unknown invocation name is a REFUSAL, never a guessed role.

use std::ffi::{OsStr, OsString};

/// The daemon's internal hook-client argument. Not a public subcommand: the callback socket is
/// `0600`, admits only the daemon's own uid before reading a frame, and additionally requires a live
/// random registry token, so a caller invoking this under any other uid fails closed.
pub(crate) const HOOK_ARGUMENT: &str = "git-update-hook";

/// The three installed names. One regular target plus two relative symlinks to it.
pub(crate) const DAEMON_NAME: &str = "cermetd";
pub(crate) const HELPER_NAME: &str = "git-remote-cermet";
pub(crate) const CLI_NAME: &str = "cermet";

/// What this invocation is. Nothing outside [`route`] decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Role {
    /// The daemon's own short-lived update-hook client (`<program> git-update-hook <ref> <old> <new>`).
    GitUpdateHook,
    /// The daemon, named by the `cermetd` alias the service manager launches.
    Daemon(DaemonInvocation),
    /// Git's remote helper, named by the `git-remote-cermet` alias git looks up on PATH.
    GitRemoteHelper,
    /// The operator CLI (and, under it, the `mcp` agent bridge).
    Cli,
    /// A name this build does not publish. Carries the offending basename for the refusal.
    Unknown(OsString),
}

/// `cermetd` accepts no flags: it is launched by the service manager, and the operator surface is
/// `cermet`. An unrecognized daemon argument is a USAGE error (exit 2), not a silently ignored one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DaemonInvocation {
    Serve,
    Help,
    Version,
    Unknown(OsString),
}

/// The invocation's basename, compared as raw bytes. A non-UTF-8 name simply matches none of the
/// three published names and falls to the refusal arm.
fn basename(program: &OsStr) -> &OsStr {
    std::path::Path::new(program)
        .file_name()
        .unwrap_or(OsStr::new(""))
}

/// PURE. `argv` is the whole invocation, `argv[0]` included.
pub(crate) fn route(argv: &[OsString]) -> Role {
    // Priority 1: the internal hook argument, BEFORE any name is consulted (the `current_exe()`
    // reason in the module doc). Malformed argument counts are refused by the hook client itself,
    // which already owns that check — routing here is about WHICH role, not whether it is well formed.
    if argv.get(1).map(OsString::as_os_str) == Some(OsStr::new(HOOK_ARGUMENT)) {
        return Role::GitUpdateHook;
    }
    let Some(program) = argv.first() else {
        return Role::Unknown(OsString::new());
    };
    let name = basename(program);
    if name == OsStr::new(DAEMON_NAME) {
        return Role::Daemon(daemon_invocation(argv));
    }
    if name == OsStr::new(HELPER_NAME) {
        return Role::GitRemoteHelper;
    }
    if name == OsStr::new(CLI_NAME) {
        return Role::Cli;
    }
    Role::Unknown(name.to_os_string())
}

fn daemon_invocation(argv: &[OsString]) -> DaemonInvocation {
    let Some(first) = argv.get(1) else {
        return DaemonInvocation::Serve;
    };
    match first.to_str() {
        Some("--help" | "-h" | "help") => DaemonInvocation::Help,
        Some("--version" | "-V") => DaemonInvocation::Version,
        _ => DaemonInvocation::Unknown(first.clone()),
    }
}

/// The refusal an unpublished invocation name gets. Names what IS accepted; never guesses a role.
pub(crate) fn unknown_name_refusal(name: &OsStr) -> String {
    format!(
        "cermet: refusing to run as {:?} — this executable answers to exactly three installed \
         names: `{CLI_NAME}` (the operator CLI and `{CLI_NAME} mcp` agent bridge), `{DAEMON_NAME}` \
         (the daemon, launched by the service manager), and `{HELPER_NAME}` (git's remote helper). \
         `{DAEMON_NAME}` and `{HELPER_NAME}` are root-owned symlinks to `{CLI_NAME}`; re-run \
         `sudo {CLI_NAME} setup` if one is missing.",
        name.to_string_lossy()
    )
}

/// The refusal an unrecognized `cermetd` argument gets (exit 2).
pub(crate) fn unknown_daemon_argument_refusal(argument: &OsStr) -> String {
    format!(
        "{DAEMON_NAME}: unknown argument {:?}\n\
         {DAEMON_NAME} takes no flags or subcommands beyond --help/--version; it is started by the \
         service manager. The operator surface is `{CLI_NAME}` — try `{CLI_NAME} --help`.",
        argument.to_string_lossy()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn argv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn each_published_name_routes_to_its_own_role() {
        assert_eq!(route(&argv(&["/usr/local/bin/cermet", "log"])), Role::Cli);
        assert_eq!(
            route(&argv(&["/usr/local/bin/cermetd"])),
            Role::Daemon(DaemonInvocation::Serve)
        );
        assert_eq!(
            route(&argv(&[
                "/usr/local/bin/git-remote-cermet",
                "origin",
                "cermet::github/o/r"
            ])),
            Role::GitRemoteHelper
        );
        // The name is what dispatches, not the directory it was found in.
        assert_eq!(route(&argv(&["cermet"])), Role::Cli);
        assert_eq!(
            route(&argv(&["./target/release/cermetd"])),
            Role::Daemon(DaemonInvocation::Serve)
        );
    }

    #[test]
    fn the_hook_argument_wins_before_any_name_is_consulted() {
        // The daemon writes a hook stub that execs its own program path; through the `cermetd`
        // symlink that path RESOLVES to `.../cermet`, so a name-first router would send the hook
        // client into the operator CLI and break every push.
        for program in ["/usr/local/bin/cermet", "/usr/local/bin/cermetd"] {
            assert_eq!(
                route(&argv(&[
                    program,
                    "git-update-hook",
                    "refs/heads/main",
                    "aaa",
                    "bbb"
                ])),
                Role::GitUpdateHook,
                "{program} must reach the hook client"
            );
        }
        // A malformed argument count still routes to the hook client, which refuses it — the
        // alternative (falling through to a role) is exactly the misdispatch this ordering exists
        // to prevent.
        assert_eq!(
            route(&argv(&["/usr/local/bin/cermetd", "git-update-hook"])),
            Role::GitUpdateHook
        );
        // Only argument ONE is the hook selector; it is not a subcommand the CLI grammar admits.
        assert_eq!(
            route(&argv(&["cermet", "log", "git-update-hook"])),
            Role::Cli
        );
    }

    #[test]
    fn an_unpublished_invocation_name_is_refused_and_never_guessed() {
        for name in ["cermet-agent", "cermetdd", "cermet-rs", "sh", ""] {
            let role = route(&argv(&[name, "log"]));
            assert_eq!(
                role,
                Role::Unknown(OsString::from(name)),
                "{name:?} must refuse, not fall back to a role"
            );
        }
        // No argv at all: nothing to dispatch on.
        assert_eq!(route(&[]), Role::Unknown(OsString::new()));
    }

    #[test]
    fn a_non_utf8_invocation_name_refuses_rather_than_matching_a_role() {
        let name = OsString::from_vec(vec![b'c', b'e', b'r', b'm', 0xff, b'e', b't']);
        let mut program = OsString::from("/usr/local/bin/");
        program.push(&name);
        assert_eq!(
            route(&[program, OsString::from("log")]),
            Role::Unknown(name)
        );
    }

    #[test]
    fn the_daemon_alias_admits_only_empty_args_help_and_version() {
        assert_eq!(
            route(&argv(&["cermetd"])),
            Role::Daemon(DaemonInvocation::Serve)
        );
        for help in ["--help", "-h", "help"] {
            assert_eq!(
                route(&argv(&["cermetd", help])),
                Role::Daemon(DaemonInvocation::Help)
            );
        }
        for version in ["--version", "-V"] {
            assert_eq!(
                route(&argv(&["cermetd", version])),
                Role::Daemon(DaemonInvocation::Version)
            );
        }
        // Anything else is a usage error, NOT a silently ignored argument.
        for unknown in ["--socket", "mcp", "serve", "-x"] {
            assert_eq!(
                route(&argv(&["cermetd", unknown])),
                Role::Daemon(DaemonInvocation::Unknown(OsString::from(unknown))),
                "`cermetd {unknown}` must be a usage error"
            );
        }
    }

    #[test]
    fn the_refusals_name_what_is_accepted() {
        let refusal = unknown_name_refusal(OsStr::new("cermet-agent"));
        for name in [CLI_NAME, DAEMON_NAME, HELPER_NAME] {
            assert!(refusal.contains(name), "{refusal}");
        }
        assert!(refusal.contains("cermet-agent"), "{refusal}");
        let daemon = unknown_daemon_argument_refusal(OsStr::new("--socket"));
        assert!(
            daemon.contains("--socket") && daemon.contains(CLI_NAME),
            "{daemon}"
        );
    }
}
