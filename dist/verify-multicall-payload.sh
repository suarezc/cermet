#!/usr/bin/env bash
#
# verify-multicall-payload.sh — assert a staged/unpacked bin directory holds the ONE-BINARY shape.
#
# Cermet ships one regular executable, `cermet`, plus `cermetd` and `git-remote-cermet` as symlinks
# to it. Those two names are role identification — the path systemd's ExecStart and launchd's
# ProgramArguments[0] carry, and the name git resolves a remote helper by — not separate programs.
#
# The alias targets must be the EXACT relative name `cermet`. An absolute target would break the
# moment the prefix is relocated or the tree is unpacked somewhere else; a traversing target would
# point outside the directory the package controls; a byte copy would put the two independently
# skewable files back that the merge removed.
#
# Usage: verify-multicall-payload.sh <bin-dir>
set -euo pipefail

BIN_DIR="${1:?usage: verify-multicall-payload.sh <bin-dir>}"
TARGET=cermet
ALIASES=(cermetd git-remote-cermet)

die() { printf 'REFUSED: %s\n' "$*" >&2; exit 1; }

[ -d "$BIN_DIR" ] || die "$BIN_DIR is not a directory"

# The one regular target: a real file, executable, never a link.
if [ -L "$BIN_DIR/$TARGET" ]; then die "$BIN_DIR/$TARGET must be the regular target, not a link"; fi
[ -f "$BIN_DIR/$TARGET" ] || die "$BIN_DIR/$TARGET is missing or not a regular file"
[ -x "$BIN_DIR/$TARGET" ] || die "$BIN_DIR/$TARGET is not executable"
mode="$(stat -c '%a' "$BIN_DIR/$TARGET" 2>/dev/null || stat -f '%Lp' "$BIN_DIR/$TARGET")"
[ "$mode" = 755 ] || die "$BIN_DIR/$TARGET is mode $mode, not 755"

for alias in "${ALIASES[@]}"; do
  [ -L "$BIN_DIR/$alias" ] || die "$BIN_DIR/$alias is not a symlink (a byte copy is what one binary replaced)"
  link="$(readlink "$BIN_DIR/$alias")"
  [ "$link" = "$TARGET" ] \
    || die "$BIN_DIR/$alias points at '$link'; it must be exactly the relative name '$TARGET'"
  [ -x "$BIN_DIR/$alias" ] || die "$BIN_DIR/$alias does not resolve to an executable"
done

# Nothing else in the directory may be a second cermet executable.
extra="$(find "$BIN_DIR" -maxdepth 1 -type f -name 'cermet*' ! -name "$TARGET" -print)"
[ -z "$extra" ] || die "extra regular cermet executables in the payload:"$'\n'"$extra"

printf 'payload OK: one regular %s + %d relative aliases in %s\n' "$TARGET" "${#ALIASES[@]}" "$BIN_DIR"
