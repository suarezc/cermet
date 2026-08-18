#!/usr/bin/env bash

set -euo pipefail

REPOSITORY="${CERMET_REPOSITORY:-suarezc/cermet}"
INSTALL_DIR="${CERMET_INSTALL_DIR:-${HOME}/.local/bin}"
API_URL="https://api.github.com/repos/${REPOSITORY}/releases/latest"

die() {
  printf 'get-cermet: %s\n' "$*" >&2
  exit 1
}

# Resolve the release artifact suffix for one (uname -s, uname -m) pair. Taking both as arguments
# is what makes the whole table testable off its own host: `--print-target Darwin x86_64` below.
detect_target() {
  local os arch
  case "$1" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) die "unsupported operating system: $1 (Linux and macOS have releases)" ;;
  esac
  case "$2" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported architecture: $2" ;;
  esac
  if [ "$os" = darwin ] && [ "$arch" = amd64 ]; then
    die "no darwin_amd64 release is published (Intel Macs); build from source instead: cargo install --path crates/cermet-bin"
  fi
  TARGET="${os}_${arch}"
}

if [ "${1:-}" = --print-target ]; then
  detect_target "${2:-$(uname -s)}" "${3:-$(uname -m)}"
  printf '%s\n' "$TARGET"
  exit 0
fi

detect_target "$(uname -s)" "$(uname -m)"

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
# GNU coreutils ships sha256sum; a stock macOS has only shasum. Both read the same SHA256SUMS
# format, so the file the release publishes stays one file.
if command -v sha256sum >/dev/null 2>&1; then
  SHA256_CHECK=(sha256sum -c)
elif command -v shasum >/dev/null 2>&1; then
  SHA256_CHECK=(shasum -a 256 -c)
else
  die "sha256sum or shasum is required to verify the download"
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT

RELEASE_JSON="$WORK_DIR/release.json"
curl -qfsSL \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  "$API_URL" >"$RELEASE_JSON"

asset_urls() {
  grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' "$RELEASE_JSON" \
    | sed -E 's/^.*"([^"]+)"$/\1/'
}

TARBALL_URL="$(asset_urls | grep -E "cermet_[^/]+_${TARGET}\\.tar\\.gz$" | head -n 1 || true)"
SUMS_URL="$(asset_urls | grep -E '/SHA256SUMS$' | head -n 1 || true)"
[ -n "$TARBALL_URL" ] || die "release has no ${TARGET} tarball"
[ -n "$SUMS_URL" ] || die "release has no SHA256SUMS"

TARBALL="$WORK_DIR/$(basename "$TARBALL_URL")"
SUMS="$WORK_DIR/SHA256SUMS"
curl -qfsSL "$TARBALL_URL" -o "$TARBALL"
curl -qfsSL "$SUMS_URL" -o "$SUMS"

(
  cd "$WORK_DIR"
  grep -E "[[:space:]]$(basename "$TARBALL")$" SHA256SUMS >selected.sha256 \
    || die "tarball is absent from SHA256SUMS"
  "${SHA256_CHECK[@]}" selected.sha256
)

UNPACKED="$WORK_DIR/unpacked"
mkdir -p "$UNPACKED"
tar -xzf "$TARBALL" -C "$UNPACKED"

# ONE-BINARY: the tarball carries one regular executable plus two role aliases as RELATIVE symlinks
# to it. Refuse an absolute or traversing alias target rather than installing it: the tarball is a
# downloaded artifact, and a link that escapes its own directory would have this script write, or
# point at, something outside the install dir the caller chose.
[ -f "$UNPACKED/cermet" ] && [ ! -L "$UNPACKED/cermet" ] \
  || die "tarball omitted the regular cermet executable"
[ -x "$UNPACKED/cermet" ] || die "the cermet in the tarball is not executable"
for alias in cermetd git-remote-cermet; do
  [ -L "$UNPACKED/$alias" ] || die "tarball omitted the ${alias} alias (or shipped it as a copy)"
  link="$(readlink "$UNPACKED/$alias")"
  [ "$link" = cermet ] \
    || die "tarball's ${alias} points at '${link}'; it must be exactly the relative name 'cermet'"
done

mkdir -p "$INSTALL_DIR"
# Target first, so an alias never points at a missing file; then replace any older alias with the
# link.
install -m 0755 "$UNPACKED/cermet" "$INSTALL_DIR/cermet"
for alias in cermetd git-remote-cermet; do
  rm -f "$INSTALL_DIR/$alias"
  ln -s cermet "$INSTALL_DIR/$alias"
done

printf 'installed cermet in %s, with cermetd and git-remote-cermet as relative aliases to it\n' "$INSTALL_DIR"

# One-run install: finish with the privileged setup step right here when a
# human can answer sudo — the same liberty Tailscale's and Teleport's install scripts take. With
# no TTY (CI, pipes) we print the command instead of hanging on a password prompt.
if [ -t 0 ] && command -v sudo >/dev/null 2>&1; then
  printf 'running: sudo %s/cermet setup\n' "$INSTALL_DIR"
  sudo "$INSTALL_DIR/cermet" setup
else
  printf 'run: sudo %s/cermet setup\n' "$INSTALL_DIR"
fi
