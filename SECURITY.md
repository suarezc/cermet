# Security Policy

Cermet is a credential broker: its job is holding secrets and refusing effects.
Reports about that boundary are the most valuable mail this project can receive.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability). That opens a private thread and, when a fix
needs to be developed under embargo, a temporary private fork — nothing is
public until fix and advisory publish together.

Please do not report vulnerabilities through public issues.

You can expect an acknowledgment within 48 hours. This is a small project;
triage is honest rather than instant.

## Supported versions

The latest release line only. Fixes ship as new releases, never as patches to
old ones.

## How security fixes reach installs

A security release's notes begin with `SECURITY:`. Every installed daemon's
daily update check reads exactly that one bit from the latest release and
escalates its local notice — the check is a tokenless GET against this
repository's releases, sends nothing, and installs nothing; applying an update
is always the operator's own `sudo cermet update`.

## Scope notes

The threat model is documented in `docs/REFERENCE.md` (Named adversaries).
Reports assuming a hostile root user, a compromised daemon binary, or physical
control of a live machine are out of scope by design — the interesting surface
is everything that lets an agent, a webpage, or a peer process reach an effect
or a secret without a sentence admitting it.
