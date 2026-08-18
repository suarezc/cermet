#!/bin/sh
# Configure and start Cermet right here, like any service-shaped package.
# `cermet setup` is idempotent and non-interactive; on a
# FIRST install it learns which human is the approver from SUDO_UID, which `sudo apt` /
# `sudo dpkg` provide. An existing config already names the approver, so upgrades never
# need it. Only the pure-root-shell first install (no sudo, e.g. a container build) has
# no approver to infer — there we print the command instead of guessing.
set -e
if [ -f /etc/cermetd/config.toml ] || [ -n "${SUDO_UID:-}" ]; then
    /usr/bin/cermet setup
else
    printf '%s\n' 'run: sudo cermet setup   (sudo is how setup learns which human approves)'
fi
