# dist/Makefile — thin tree-build/install wrapper for Cermet.
# Invoke from the repo root: `make -C dist install`.
#
# `install` and `verify` run on BOTH Linux and macOS; `cermet setup` picks the platform's own
# service assets (dist/linux/* under systemd, dist/macos/* under launchd). The .deb is Debian-only
# and `package` refuses elsewhere; macOS ships a binary tarball only — a signed/notarized .pkg is
# not built.
#
# Releasing (manual). There is no CI: each platform's artifacts are hand-built on that platform.
#
#   Linux (on the Linux box):
#     make -C dist package
#     cd dist/out && sha256sum cermet_* > SHA256SUMS
#     gh release create <tag> dist/out/cermet_* dist/out/SHA256SUMS
#
#   macOS arm64 (on the Mac):
#     make -C dist package-darwin
#     cd dist/out && shasum -a 256 cermet_*_darwin_arm64.tar.gz >> SHA256SUMS
#     gh release upload <tag> dist/out/cermet_*_darwin_arm64.tar.gz dist/out/SHA256SUMS --clobber
#
# Name the artifact globs, never `dist/out/*` — that directory also holds the deb-root/ and
# darwin-root/ staging trees, and `gh release create` errors on a directory argument.
#
# One SHA256SUMS holds every platform's lines, because `dist/get-cermet.sh` reads one file for
# all of them. Whichever platform releases second appends and re-uploads with --clobber.
# `dist/get-cermet.sh` consumes whatever lands in GitHub Releases, however it got there.
#
#   THE RELEASE IS THE WHOLE UPDATE CHANNEL. `cermet update` reads
#   `repos/<slug>/releases/latest`, resolves checksums from that release's own SHA256SUMS, and
#   downloads that release's assets — there is no second document and no second host to publish to.
#   Upload SHA256SUMS LAST: a release whose asset is listed before its checksum is a release the
#   updater will decline to advertise until the next day's check.
#
#   A SECURITY RELEASE is marked in the release NOTES: make the body's FIRST LINE begin with
#   `SECURITY:` and the daily check escalates its local notice and prints the release page.
#
# ONE-BINARY: every artifact below carries ONE regular executable, `cermet`, plus `cermetd` and
# `git-remote-cermet` as RELATIVE symlinks to it. They are role names, not separate programs.
#
# From source, no release needed (documented in README's install section): one command, because
# there is one binary —
#     cargo install --path crates/cermet-bin
#     sudo "$HOME/.cargo/bin/cermet" setup
# setup publishes that binary and creates the two aliases beside it. The absolute path matters (a
# bare `sudo cermet` can resolve an older copy).

SHELL := /bin/bash
UNAME_S := $(shell uname -s)
DIST_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO_DIR := $(abspath $(DIST_DIR)/..)
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' "$(REPO_DIR)/Cargo.toml" | head -n 1)
# dpkg reads `0.1.0-rc.1` as upstream 0.1.0 with Debian revision rc.1 — which sorts NEWER than
# the eventual 0.1.0, so an rc could never be upgraded to the release. Debian spells a
# prerelease with a tilde, which sorts before everything: 0.1.0~rc.1 < 0.1.0.
# Only the control field is translated; artifact filenames keep the Cargo form.
DEB_VERSION := $(subst -,~,$(VERSION))
DEB_ARCH := $(shell dpkg --print-architecture 2>/dev/null || true)
OUT_DIR := $(DIST_DIR)out
PACKAGE_ROOT := $(OUT_DIR)/deb-root
DEB := $(OUT_DIR)/cermet_$(VERSION)_$(DEB_ARCH).deb
TARBALL := $(OUT_DIR)/cermet_$(VERSION)_linux_$(DEB_ARCH).tar.gz
# macOS publishes arm64 only. An Intel artifact would need a maintainer decision (and a build host),
# so `package-darwin` refuses there rather than emitting a tarball nothing fetches.
TARBALL_DARWIN := $(OUT_DIR)/cermet_$(VERSION)_darwin_arm64.tar.gz
DARWIN_STAGE := $(OUT_DIR)/darwin-root
LINUX_STAGE := $(OUT_DIR)/linux-root

.PHONY: install verify help build-release package package-darwin

help:
	@echo "Cermet packaging targets:"
	@echo "  make -C dist install       # build as the user, then sudo only cermet setup"
	@echo "  make -C dist build-release # build the one cermet binary"
	@echo "  make -C dist package       # build a local .deb and binary tarball under dist/out (Linux only)"
	@echo "  make -C dist package-darwin # build the darwin arm64 binary tarball under dist/out (macOS only)"
	@echo "  make -C dist verify        # slim packaging-structure verification"

build-release:
	@"$(REPO_DIR)/scripts/build-release.sh"

# Building is user work; only the Rust setup command runs with privilege.
install:
	@if [ "$$EUID" -eq 0 ]; then \
		echo "REFUSED: run make -C dist install WITHOUT sudo; it will sudo only the setup step" >&2; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory build-release
	@cd "$(REPO_DIR)" && sudo target/release/cermet setup --from-tree "$(REPO_DIR)"

package: build-release
	@set -e; \
	if [ "$(UNAME_S)" != "Linux" ]; then \
		echo "REFUSED: make -C dist package builds a .deb and runs only on Linux (got $(UNAME_S)); on macOS run make -C dist package-darwin" >&2; \
		exit 1; \
	fi; \
	test -n "$(VERSION)"; \
	test -n "$(DEB_ARCH)"; \
	rm -rf "$(PACKAGE_ROOT)"; \
	mkdir -p "$(PACKAGE_ROOT)/DEBIAN" "$(PACKAGE_ROOT)/usr/bin" \
		"$(PACKAGE_ROOT)/usr/share/cermet/linux"; \
	install -m 0755 "$(REPO_DIR)/target/release/cermet" "$(PACKAGE_ROOT)/usr/bin/cermet"; \
	ln -sfn cermet "$(PACKAGE_ROOT)/usr/bin/cermetd"; \
	ln -sfn cermet "$(PACKAGE_ROOT)/usr/bin/git-remote-cermet"; \
	install -m 0644 "$(DIST_DIR)linux/cermetd.service" "$(PACKAGE_ROOT)/usr/share/cermet/linux/cermetd.service"; \
	install -m 0644 "$(DIST_DIR)linux/cermetd.tmpfiles" "$(PACKAGE_ROOT)/usr/share/cermet/linux/cermetd.tmpfiles"; \
	install -m 0644 "$(DIST_DIR)linux/cermet-credential-env.service" "$(PACKAGE_ROOT)/usr/share/cermet/linux/cermet-credential-env.service"; \
	install -m 0644 "$(DIST_DIR)linux/cermet-credential-env.sh" "$(PACKAGE_ROOT)/usr/share/cermet/linux/cermet-credential-env.sh"; \
	install -m 0644 "$(DIST_DIR)linux/cermet-update-check.service" "$(PACKAGE_ROOT)/usr/share/cermet/linux/cermet-update-check.service"; \
	install -m 0644 "$(DIST_DIR)linux/cermet-update-check.timer" "$(PACKAGE_ROOT)/usr/share/cermet/linux/cermet-update-check.timer"; \
	install -m 0644 "$(DIST_DIR)linux/config.toml" "$(PACKAGE_ROOT)/usr/share/cermet/linux/config.toml"; \
	install -m 0644 "$(DIST_DIR)linux/pam.cermet" "$(PACKAGE_ROOT)/usr/share/cermet/linux/pam.cermet"; \
	find "$(PACKAGE_ROOT)" -type d -exec chmod 0755 {} +; \
	find "$(PACKAGE_ROOT)/usr/share" -type f -exec chmod 0644 {} +; \
	install -m 0755 "$(DIST_DIR)package/postinstall.sh" "$(PACKAGE_ROOT)/DEBIAN/postinst"; \
	printf '%s\n' \
		'Package: cermet' \
		'Version: $(DEB_VERSION)' \
		'Architecture: $(DEB_ARCH)' \
		'Maintainer: Cermet maintainers' \
		'Section: utils' \
		'Priority: optional' \
		'Description: Local-first capability broker for AI agents' \
		> "$(PACKAGE_ROOT)/DEBIAN/control"; \
	mkdir -p "$(OUT_DIR)"; \
	dpkg-deb --root-owner-group --build "$(PACKAGE_ROOT)" "$(DEB)"; \
	rm -rf "$(LINUX_STAGE)"; \
	mkdir -p "$(LINUX_STAGE)"; \
	install -m 0755 "$(REPO_DIR)/target/release/cermet" "$(LINUX_STAGE)/cermet"; \
	ln -sfn cermet "$(LINUX_STAGE)/cermetd"; \
	ln -sfn cermet "$(LINUX_STAGE)/git-remote-cermet"; \
	tar -C "$(LINUX_STAGE)" -czf "$(TARBALL)" cermet cermetd git-remote-cermet; \
	"$(DIST_DIR)verify-multicall-payload.sh" "$(PACKAGE_ROOT)/usr/bin"; \
	"$(DIST_DIR)verify-multicall-payload.sh" "$(LINUX_STAGE)"; \
	echo "package: $(DEB)"; \
	echo "tarball: $(TARBALL)"

# The macOS release artifact: the same one-target/two-relative-link shape the Linux side ships,
# stripped. `strip` rewrites the ad-hoc code signature that arm64 macOS requires to exec at all, so
# the `codesign --verify` is not ceremony — without it a bad strip ships a tarball that SIGKILLs.
# Sign and verify the ONE target once; a symlink is not a separate program to sign, and `codesign`
# follows it to the same bytes.
package-darwin: build-release
	@set -e; \
	if [ "$(UNAME_S)" != Darwin ]; then \
		echo "REFUSED: make -C dist package-darwin runs only on macOS (got $(UNAME_S)); on Linux run make -C dist package" >&2; \
		exit 1; \
	fi; \
	if [ "$$(uname -m)" != arm64 ]; then \
		echo "REFUSED: the only published macOS artifact is darwin arm64 (got $$(uname -m)); an Intel build is not published" >&2; \
		exit 1; \
	fi; \
	test -n "$(VERSION)"; \
	rm -rf "$(DARWIN_STAGE)"; \
	mkdir -p "$(DARWIN_STAGE)" "$(OUT_DIR)"; \
	install -m 0755 "$(REPO_DIR)/target/release/cermet" "$(DARWIN_STAGE)/cermet"; \
	strip -x "$(DARWIN_STAGE)/cermet"; \
	codesign --verify "$(DARWIN_STAGE)/cermet"; \
	ln -sfn cermet "$(DARWIN_STAGE)/cermetd"; \
	ln -sfn cermet "$(DARWIN_STAGE)/git-remote-cermet"; \
	codesign --verify "$(DARWIN_STAGE)/cermetd"; \
	codesign --verify "$(DARWIN_STAGE)/git-remote-cermet"; \
	tar -C "$(DARWIN_STAGE)" -czf "$(TARBALL_DARWIN)" cermet cermetd git-remote-cermet; \
	"$(DIST_DIR)verify-multicall-payload.sh" "$(DARWIN_STAGE)"; \
	echo "tarball: $(TARBALL_DARWIN)"

verify:
	@set -e; \
	echo "==> verify thin dist layout"; \
	test -f "$(DIST_DIR)linux/cermetd.service"; \
	test -f "$(DIST_DIR)linux/cermetd.tmpfiles"; \
	test -f "$(DIST_DIR)linux/cermet-credential-env.service"; \
	test -f "$(DIST_DIR)linux/cermet-credential-env.sh"; \
	sh -n "$(DIST_DIR)linux/cermet-credential-env.sh"; \
	grep -q '^Requires=cermet-credential-env.service$$' "$(DIST_DIR)linux/cermetd.service"; \
	test -f "$(DIST_DIR)linux/config.toml"; \
	test -f "$(DIST_DIR)linux/pam.cermet"; \
	test -f "$(DIST_DIR)linux/cermet-update-check.service"; \
	test -f "$(DIST_DIR)linux/cermet-update-check.timer"; \
	grep -q '^Unit=cermet-update-check.service$$' "$(DIST_DIR)linux/cermet-update-check.timer"; \
	grep -q '^User=CERMET_APPROVER_USER$$' "$(DIST_DIR)linux/cermet-update-check.service"; \
	grep -q -- '--daily-check' "$(DIST_DIR)linux/cermet-update-check.service"; \
	test -f "$(DIST_DIR)macos/dev.cermet.cermetd.plist"; \
	test -f "$(DIST_DIR)macos/dev.cermet.update-check.plist"; \
	grep -q 'daily-check' "$(DIST_DIR)macos/dev.cermet.update-check.plist"; \
	test -f "$(DIST_DIR)macos/config.toml"; \
	test ! -e "$(DIST_DIR)install.sh"; \
	test ! -e "$(DIST_DIR)macos/install.sh"; \
	test ! -e "$(DIST_DIR)macos/provision-runtime-dir.sh"; \
	test ! -e "$(DIST_DIR)macos/dev.cermet.runtime-dir.plist"; \
	test ! -e "$(DIST_DIR)linux/gen-egress-dropin.sh"; \
	test ! -e "$(DIST_DIR)linux/cermet-research.service"; \
	test ! -e "$(DIST_DIR)linux/cermet-research.timer"; \
	test ! -e "$(DIST_DIR)macos/dev.cermet.research.plist"; \
	test ! -e "$(DIST_DIR)lib/staged-publish.sh"; \
	test ! -e "$(DIST_DIR)test/smoke.sh"; \
	test -f "$(DIST_DIR)get-cermet.sh"; \
	test -x "$(DIST_DIR)verify-multicall-payload.sh"; \
	test ! -e "$(DIST_DIR)nfpm.yaml"; \
	test -f "$(DIST_DIR)package/postinstall.sh"; \
	test -n "$(DEB_VERSION)"; \
	if command -v dpkg >/dev/null 2>&1; then \
		case "$(VERSION)" in *-*) dpkg --compare-versions "$(DEB_VERSION)" lt "$(firstword $(subst -, ,$(VERSION)))";; esac; \
	fi; \
	if command -v plutil >/dev/null 2>&1; then plutil -lint "$(DIST_DIR)macos/dev.cermet.cermetd.plist" >/dev/null; fi; \
	if command -v plutil >/dev/null 2>&1; then plutil -lint "$(DIST_DIR)macos/dev.cermet.update-check.plist" >/dev/null; fi; \
	bash -n "$(REPO_DIR)/scripts/build-release.sh"; \
	bash -n "$(DIST_DIR)get-cermet.sh"; \
	bash -n "$(DIST_DIR)verify-multicall-payload.sh"; \
	sh -n "$(DIST_DIR)package/postinstall.sh"; \
	echo "==> verify one-binary payload shape"; \
	stage="$$(mktemp -d "$${TMPDIR:-/tmp}/cermet-dist-verify.XXXXXX")"; \
	printf '#!/bin/sh\n' >"$$stage/cermet"; chmod 0755 "$$stage/cermet"; \
	ln -sfn cermet "$$stage/cermetd"; ln -sfn cermet "$$stage/git-remote-cermet"; \
	"$(DIST_DIR)verify-multicall-payload.sh" "$$stage" >/dev/null; \
	ln -sfn "$$stage/cermet" "$$stage/cermetd"; \
	if "$(DIST_DIR)verify-multicall-payload.sh" "$$stage" >/dev/null 2>&1; then \
		rm -rf "$$stage"; echo "REFUSED: the payload check accepted an ABSOLUTE alias target" >&2; exit 1; \
	fi; \
	rm -f "$$stage/cermetd"; cp "$$stage/cermet" "$$stage/cermetd"; \
	if "$(DIST_DIR)verify-multicall-payload.sh" "$$stage" >/dev/null 2>&1; then \
		rm -rf "$$stage"; echo "REFUSED: the payload check accepted a byte-copy alias" >&2; exit 1; \
	fi; \
	rm -rf "$$stage"; \
	echo "==> verify release artifact naming"; \
	case "$(TARBALL_DARWIN)" in \
		*/cermet_$(VERSION)_darwin_arm64.tar.gz) ;; \
		*) echo "REFUSED: darwin artifact name drifted: '$(TARBALL_DARWIN)'" >&2; exit 1 ;; \
	esac; \
	echo "==> verify get-cermet target resolution"; \
	fetch="$(DIST_DIR)get-cermet.sh"; \
	test "$$(bash "$$fetch" --print-target Linux x86_64)" = linux_amd64; \
	test "$$(bash "$$fetch" --print-target Linux aarch64)" = linux_arm64; \
	test "$$(bash "$$fetch" --print-target Darwin arm64)" = darwin_arm64; \
	for unpublished in "Darwin x86_64" "FreeBSD arm64" "Linux ppc64le"; do \
		if bash "$$fetch" --print-target $$unpublished >/dev/null 2>&1; then \
			echo "REFUSED: get-cermet resolved an unpublished target for $$unpublished" >&2; exit 1; \
		fi; \
	done; \
	host_target="$$(bash "$$fetch" --print-target)"; \
	case "$(UNAME_S)" in \
		Linux)  test "$${host_target%%_*}" = linux ;; \
		Darwin) test "$$host_target" = darwin_arm64 ;; \
	esac; \
	echo "dist verify: OK"
