//! `cermet` — the ONE executable Cermet ships.
//!
//! A composition root and nothing else: it reads the invocation once, asks [`router::route`] which
//! role it is, and calls that role's library entry. The daemon spine lives in `cermet-daemon`; the
//! operator CLI, the `mcp` agent bridge, and git's remote helper live in `cermet-cli`.
//!
//! One binary carries every role, so the broker code is present in the same file the operator runs.
//! Code presence is not privilege: the CLI/MCP role never enters the daemon entry, never opens
//! service state or key material, and all broker authority runs in a process whose kernel uid and
//! filesystem access are the service uid's. `execve` gives a process the credentials its caller
//! chose, not the file owner's — the service manager launches the daemon role under the service uid,
//! and nothing installed here is setuid or file-capable.

mod router;

use std::ffi::OsString;
use std::process::ExitCode;

use router::{DaemonInvocation, Role};

// DELIBERATELY NO CONTAMINATION MARKERS HERE. They used to live in this crate, gated on
// the features it FORWARDS — which meant a build that acquired `cermet-core/test-egress` or
// `cermet-core/test-double` through cargo's dev-dependency feature unification carried the door but
// not the marker, and `cermet setup` accepted it. Each marker now lives in the crate that owns its
// feature (`cermet-core`, `cermet-ctl-client`), so it travels with the capability rather than with
// this composition root. `tests/non_installable_markers.rs` is the proof.

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();
    match router::route(&argv) {
        Role::GitUpdateHook => match utf8_tail(&argv, 2) {
            Ok(hook_args) => cermet_daemon::gitplane::hook::run_update_hook(&hook_args),
            Err(refusal) => refuse(&refusal),
        },
        Role::Daemon(DaemonInvocation::Serve) => cermet_daemon::entry::run(),
        Role::Daemon(DaemonInvocation::Help) => {
            println!("{}", cermet_daemon::entry::help_text());
            ExitCode::SUCCESS
        }
        Role::Daemon(DaemonInvocation::Version) => {
            println!("{}", cermet_daemon::entry::version_text());
            ExitCode::SUCCESS
        }
        Role::Daemon(DaemonInvocation::Unknown(argument)) => {
            eprintln!("{}", router::unknown_daemon_argument_refusal(&argument));
            ExitCode::from(2)
        }
        Role::GitRemoteHelper => match utf8_tail(&argv, 1) {
            Ok(args) => cermet_cli::entry::run_git_remote_helper(&args),
            Err(refusal) => refuse(&refusal),
        },
        Role::Cli => match utf8_tail(&argv, 1) {
            Ok(args) => cermet_cli::entry::run(&args),
            Err(refusal) => refuse(&refusal),
        },
        Role::Unknown(name) => {
            eprintln!("{}", router::unknown_name_refusal(&name));
            ExitCode::from(2)
        }
    }
}

/// The invocation from `skip` onward as UTF-8. Every surface below this point — the sentence
/// grammar, git's helper protocol, the hook's ref/oid triple — is text, so a non-UTF-8 argument is
/// refused here once rather than lossily mangled into something that parses as a different request.
fn utf8_tail(argv: &[OsString], skip: usize) -> Result<Vec<String>, String> {
    argv.iter()
        .skip(skip)
        .map(|argument| {
            argument.clone().into_string().map_err(|bad| {
                format!(
                    "cermet: argument {:?} is not valid UTF-8; refusing rather than guessing at it",
                    bad.to_string_lossy()
                )
            })
        })
        .collect()
}

fn refuse(message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(2)
}
