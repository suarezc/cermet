//! Help is a FIRST-CLASS surface, not an error.
//!
//! `cermet --help` / `cermet help` print the usage banner. Printing it through the ERROR path —
//! stderr, exit 2 — reads to a caller (and to an agent's shell wrapper) as "that command does not
//! exist". Asking what a tool can do is a successful invocation. A BAD invocation is unchanged:
//! usage on stderr, exit 2.

use std::process::{Command, Output};

mod common;

fn run(args: &[&str]) -> Output {
    Command::new(common::cermet_binary())
        .args(args)
        .output()
        .expect("the cermet binary runs")
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("stdout is utf-8")
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).expect("stderr is utf-8")
}

#[test]
fn asking_for_help_succeeds_on_stdout() {
    for form in [vec!["--help"], vec!["-h"], vec!["help"]] {
        let out = run(&form);
        assert_eq!(
            out.status.code(),
            Some(0),
            "`cermet {}` must exit 0: {}",
            form.join(" "),
            stderr(&out)
        );
        let text = stdout(&out);
        assert!(
            text.contains("cermet — the capability broker CLI"),
            "`cermet {}` must print the usage banner on STDOUT, got: {text}",
            form.join(" ")
        );
        assert!(
            stderr(&out).is_empty(),
            "help is not a diagnostic: `cermet {}` wrote to stderr: {}",
            form.join(" "),
            stderr(&out)
        );
    }
}

#[test]
fn every_command_answers_its_own_help() {
    // Every live command in the banner, including the two that never reach the shared parse path
    // (`setup` has its own parser; `mcp` is intercepted by the stdio-bridge front-end).
    for command in [
        "catalog",
        "run",
        "log",
        "artifact",
        "audit-verify",
        "check",
        "rules",
        "doc",
        "preset",
        "owner",
        "connect",
        "setup",
        "mcp",
    ] {
        for flag in ["--help", "-h"] {
            let out = run(&[command, flag]);
            assert_eq!(
                out.status.code(),
                Some(0),
                "`cermet {command} {flag}` must exit 0: {}",
                stderr(&out)
            );
            let text = stdout(&out);
            assert!(
                text.contains(command),
                "`cermet {command} {flag}` must describe {command}, got: {text}"
            );
            assert!(
                stderr(&out).is_empty(),
                "`cermet {command} {flag}` wrote to stderr: {}",
                stderr(&out)
            );
        }
    }
}

/// Help has to answer at EVERY dispatch depth, not just at the top and at the bare noun. The
/// failing case was `cermet mcp install --help` → `cermet: mcp install: unexpected "--help"`,
/// exit 2: the noun answered, its subcommand did not. A subcommand with no usage text of its own
/// falls back to its parent noun's — which is where the subcommand is documented anyway.
#[test]
fn multi_word_subcommands_answer_help_too() {
    for (invocation, noun) in [
        (vec!["mcp", "install", "--help"], "mcp install"),
        (vec!["doc", "check", "--help"], "doc check"),
        (vec!["doc", "apply", "--help"], "doc apply"),
        (vec!["rules", "allow", "--help"], "rules allow"),
        (vec!["rules", "revoke", "--help"], "rules revoke"),
        (vec!["owner", "status", "--help"], "owner status"),
        (vec!["connect", "github", "-h"], "connect"),
        // `--help` after the command's own flags, and after a positional, is still a question.
        (vec!["log", "--denied", "--help"], "log"),
        (vec!["catalog", "--all", "--help"], "catalog"),
        (vec!["run", "vercel.deploy", "--help"], "run"),
        // The `help <command>` word form reaches the same text as `<command> --help`.
        (vec!["help", "log"], "log"),
        (vec!["help", "mcp", "install"], "mcp install"),
        // A global flag before the command must not hide the question behind it.
        (
            vec![
                "--socket",
                "/nonexistent/ctl.sock",
                "doc",
                "check",
                "--help",
            ],
            "doc check",
        ),
    ] {
        let out = run(&invocation);
        assert_eq!(
            out.status.code(),
            Some(0),
            "`cermet {}` must exit 0: {}",
            invocation.join(" "),
            stderr(&out)
        );
        let text = stdout(&out);
        assert!(
            text.contains(noun),
            "`cermet {}` must document {noun}, got: {text}",
            invocation.join(" ")
        );
        assert!(
            stderr(&out).is_empty(),
            "`cermet {}` wrote to stderr: {}",
            invocation.join(" "),
            stderr(&out)
        );
    }
}

/// The other half: a bad invocation is STILL an error. Help being exit-0 must not turn
/// a typo into a success — an agent branching on the exit code has to keep seeing the failure.
#[test]
fn a_bad_invocation_still_fails_on_stderr() {
    for bad in [
        vec!["nonesuch"],
        vec!["log", "--nonesuch"],
        vec!["run"],
        // An unknown COMMAND stays unknown even when help is what was asked for: there is no such
        // thing to describe.
        vec!["nonesuch", "--help"],
        vec!["help", "nonesuch"],
        vec![], // bare `cermet` is a missing command, not a question
    ] {
        let out = run(&bad);
        assert_eq!(
            out.status.code(),
            Some(2),
            "`cermet {}` must stay a usage error",
            bad.join(" ")
        );
        assert!(
            !stderr(&out).is_empty(),
            "`cermet {}` must diagnose on stderr",
            bad.join(" ")
        );
    }
}
