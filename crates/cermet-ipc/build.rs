//! Stamp ONE build identity into this crate, so every binary that links it agrees.
//!
//! `cermetd` and `cermet` both link `cermet-ipc`, so one compile of this crate yields one id that
//! the daemon advertises and every client compares against. Different builds from different commits
//! get different ids; that difference is what lets a stale client know it is stale.
//!
//! The id is `{CARGO_PKG_VERSION}+{short commit}` with a `-dirty` suffix when tracked files differ
//! from HEAD, falling back to `{CARGO_PKG_VERSION}+nogit` when `git` is unavailable or this is not a
//! repository (a tarball build). This script NEVER fails the build over build identity: every git
//! step degrades to the fallback.
//!
//! Accepted limitations (notes, not handling code):
//!   * Two dirty rebuilds at the same commit are indistinguishable. Dev-only: an installed build is
//!     made from a clean tree, and `-dirty` already says "this id is not a promise".
//!   * The rerun hints below are BEST EFFORT. `.git/HEAD` and the current branch's ref file cover
//!     the ordinary commit/checkout, but a packed-refs update, a detached-HEAD move, or an edit that
//!     only flips dirtiness may leave a stale id until the crate is rebuilt for another reason.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let id = match git(&["rev-parse", "--short=12", "HEAD"]) {
        Some(commit) if !commit.is_empty() => {
            // `--no-optional-locks`: `git status` would otherwise take `.git/index.lock` to refresh
            // the index, and a build racing a commit in the same checkout must never be the process
            // that loses (or wins) that lock.
            let dirty = match git(&[
                "--no-optional-locks",
                "status",
                "--porcelain",
                "--untracked-files=no",
            ]) {
                Some(status) if !status.is_empty() => "-dirty",
                _ => "",
            };
            format!("{version}+{commit}{dirty}")
        }
        _ => format!("{version}+nogit"),
    };
    println!("cargo:rustc-env=CERMET_BUILD_ID={id}");
    rerun_on_git_head();
}

/// Run one git command from the package root, yielding its trimmed stdout on success. Any failure
/// (git absent, not a repository, non-zero status, non-UTF-8 output) is `None` — the caller falls
/// back rather than failing the build.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

/// Ask cargo to re-run this script when the commit could have moved: `.git/HEAD` (which changes on
/// checkout) and, when HEAD is symbolic, the branch's ref file (which changes on commit). Resolved
/// through `git rev-parse --git-path` so a worktree's real git dir is used, not a guessed `.git/`.
///
/// Every hint is emitted ONLY for a path that exists. `rev-parse --git-path` is pure path
/// construction — it happily names a loose ref file that `git pack-refs` (which `git gc` runs) has
/// since folded into `packed-refs` — and cargo treats a MISSING `rerun-if-changed` path as always
/// dirty, which recompiled this crate and everything downstream of it on every single build. A
/// packed ref therefore gets no hint at all: staleness stays best effort, exactly as the module
/// docstring already accepts, and the id refreshes on the next rebuild for any other reason.
fn rerun_on_git_head() {
    let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) else {
        return;
    };
    rerun_if_present(&head);
    if let Some(reference) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        if let Some(ref_path) = git(&["rev-parse", "--git-path", &reference]) {
            rerun_if_present(&ref_path);
        }
    }
}

/// Emit one `rerun-if-changed` hint, but only for a path that is actually there.
fn rerun_if_present(path: &str) {
    if Path::new(path).exists() {
        println!("cargo:rerun-if-changed={path}");
    }
}
