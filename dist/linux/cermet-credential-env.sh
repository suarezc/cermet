#!/bin/sh
# cermet-credential-env — the credential-transport preflight for cermetd.
#
# CONTRACT: ensure the systemd credential propagation prerequisite for /run, and change nothing
# else. It is not a repair tool, it does not "fix the container", and it has no opinion about any
# mount but one.
#
# Why it exists. cermetd's vault key is delivered as a systemd encrypted credential
# (LoadCredentialEncrypted=), so the daemon uid never receives the host/TPM unsealing material:
# systemd's privileged activation path decrypts the vault key and passes only that service
# credential to cermetd. systemd implements that handoff by mounting a ramfs in a child mount
# namespace and MS_MOVE-ing it onto /run/credentials/<unit> — a move that only becomes visible to
# PID 1 when /run has SHARED mount propagation. Every normally booted host has it. systemd skips
# setting it when it detects a container (it expects the container manager to have done it), and
# podman/docker start containers with private propagation — so on those, $CREDENTIALS_DIRECTORY
# names a directory that never appears, and cermetd correctly refuses to start without its key,
# over and over, with a filesystem error for a reason. That crash loop is the bug: not the
# refusal, which is right, but that it is illegible and repeated.
#
# NARROW ON PURPOSE: /run, never a recursive re-share of /. Upstream systemd's container interface
# asks specifically for /run to be MS_SHARED; making / rshared would change the propagation
# semantics of every nested mount in the container, including mounts Cermet has no business
# touching.
#
# Three outcomes, and the third is a refusal, not a fallback:
#   satisfied  — /run is already a shared mount. Nothing is done. (Real hosts land here.)
#   converged  — /run was private, or was not a mount point at all; made shared, then VERIFIED.
#   refused    — the mount operation is unavailable. Say so once, in full, and FAIL.
#
# TWO CALLERS, one verdict, two consequences (custody ladder):
#
#   `cermet setup` runs this script to ask whether sealed delivery can work on this box BEFORE it
#   provisions a key. A refusal there is the reason setup descends the custody ladder to the
#   `file-protected` rung — automatically, and out loud, naming the rung's own limitation. Nothing
#   is inferred silently: setup prints what it chose and writes it into config.toml.
#
#   `cermet-credential-env.service` runs it at boot, ahead of cermetd, and ONLY on a box whose
#   declared rung is a sealed one (the unit is conditional on the sealed blob existing). A refusal
#   there means an environment that could carry our key delivery at install time cannot carry it
#   now — the key is already sealed and cannot be un-sealed by this script — so cermetd stays down
#   with one legible reason instead of crash-looping. That is the Requires= relationship.
#
# This script never chooses a custody rung and never writes key material. It answers one question
# about the environment; what to do about the answer belongs to its callers.
#
# Idempotent: running it twice, or on a box that never needed it, is a no-op that exits 0.

set -eu

TARGET=/run
SELF=cermet-credential-env

say() { printf '%s: %s\n' "$SELF" "$*"; }
# The refusal is scoped to the TRANSPORT, never to the product. What cannot be satisfied here is
# systemd-credential delivery — not "Cermet", and not this environment's ability to run a broker.
# Both callers depend on that scoping: setup reads it as "descend the custody ladder", and the boot
# unit reads it as "this already-sealed box cannot be handed its key right now".
refuse() {
    printf '%s: REFUSED: %s\n' "$SELF" "$1" >&2
    printf '%s: systemd-credential delivery cannot hand cermetd its vault key material in this\n' "$SELF" >&2
    printf '%s: environment: systemd moves a mount onto /run/credentials, which requires %s to\n' "$SELF" "$TARGET" >&2
    printf '%s: have shared mount propagation.\n' "$SELF" >&2
    printf '%s: at install time this is not fatal: cermet setup descends to the file-protected\n' "$SELF" >&2
    printf '%s: custody rung and says so. On an already-sealed box it is, because the sealed key\n' "$SELF" >&2
    printf '%s: cannot be delivered — cermetd stays down rather than crash-looping.\n' "$SELF" >&2
    printf '%s: fix: start the container with %s mounted and shared, or run on a host/VM.\n' "$SELF" "$TARGET" >&2
    printf '%s: an operator with mount privileges can do it by hand: mount --make-shared %s\n' "$SELF" "$TARGET" >&2
    exit 1
}

# The propagation of $TARGET, read from the kernel rather than from `findmnt`, so the preflight
# depends on nothing but /proc. mountinfo lines are:
#   id parent maj:min root mountpoint options [optional…] - fstype source superopts
# The optional fields are variable in number and terminated by a literal "-", so they are scanned,
# never indexed: a mount can carry both "shared:N" and "master:N".
#
# Prints: shared | private | absent   (absent = $TARGET is not a mount point of its own)
target_state() {
    awk -v target="$TARGET" '
        {
            if ($5 != target) next
            state = "private"
            for (i = 7; i <= NF; i++) {
                if ($i == "-") break
                if ($i ~ /^shared:/) state = "shared"
            }
            print state
            found = 1
            exit
        }
        END { if (!found) print "absent" }
    ' /proc/self/mountinfo
}

state="$(target_state)"

if [ "$state" = shared ]; then
    say "$TARGET is already a shared mount; credential transport prerequisite satisfied, nothing to do"
    exit 0
fi

command -v mount >/dev/null 2>&1 || refuse "no mount command is available to converge $TARGET"

case "$state" in
    private)
        say "$TARGET is a private mount; making it shared (systemd credential transport prerequisite)"
        mount --make-shared "$TARGET" 2>&1 || refuse "cannot make $TARGET shared (no mount privileges in this environment?)"
        ;;
    absent)
        # Some runtimes give the container a root filesystem in which /run is an ordinary directory.
        # Propagation is a property of a MOUNT, so there must be one first: bind it onto itself, the
        # standard way to make a directory its own mount point, then share that.
        say "$TARGET is not a mount point; binding it onto itself so it can carry propagation"
        mount --bind "$TARGET" "$TARGET" 2>&1 || refuse "cannot bind-mount $TARGET onto itself (no mount privileges in this environment?)"
        mount --make-shared "$TARGET" 2>&1 || refuse "cannot make $TARGET shared after binding it"
        ;;
    *)
        refuse "cannot determine the mount state of $TARGET"
        ;;
esac

# VERIFY. A mount command that returned 0 is not evidence; the kernel's own view is.
state="$(target_state)"
[ "$state" = shared ] || refuse "$TARGET is still '$state' after converging it — the change did not take effect"
say "$TARGET is now a shared mount; credential transport prerequisite satisfied"
