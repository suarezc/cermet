#!/usr/bin/env bash
#
# build-release.sh — the canonical BUILD-ONLY entrypoint for the Cermet stack.
#
# ONE-BINARY: Cermet ships ONE executable. `cermetd` and `git-remote-cermet` are role names the
# installer publishes as relative symlinks to it, not separate build targets. This builds that one
# target and asserts it exists. It installs NOTHING, touches no daemon, needs no sudo. Run it
# directly — no wrapper, no build system, and no privileged step.
#
# Usage:
#   scripts/build-release.sh              # release build: the one `cermet` binary
#   scripts/build-release.sh --debug      # use target/debug instead of target/release
#   scripts/build-release.sh --no-build   # skip building; just assert the artifact already exists
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="release"
BUILD=1

for arg in "$@"; do
  case "$arg" in
    --debug)    PROFILE="debug" ;;
    --no-build) BUILD=0 ;;
    -h|--help)  sed -n '2,14p' "$0"; exit 0 ;;
    *) printf 'unknown flag: %s (see --help)\n' "$arg" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;36m[build-release]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[build-release] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

RELEASE_FLAG=""
[ "$PROFILE" = "release" ] && RELEASE_FLAG="--release"

# The ONE user-facing Rust binary the finished product ships. `cermet-bin` is the composition crate
# that owns the workspace's sole [[bin]]; a build is not a release unless it exists and is executable.
CERMET_BIN="${REPO_ROOT}/target/${PROFILE}/cermet"

if [ "$BUILD" -eq 1 ]; then
  log "building cermet (${PROFILE})…"
  cargo build $RELEASE_FLAG -p cermet-bin
else
  log "skipping build (--no-build); using target/${PROFILE}"
fi

[ -x "$CERMET_BIN" ] || die "cermet binary not found at ${CERMET_BIN} (build it, or drop --no-build)"

log "build complete (${PROFILE}) — artifact at ${CERMET_BIN}"
