# Cermet Quickstart

Every command below was verified by walking it against the shipped binaries. Expected output is
transcribed from that walk, not from memory.

Shipped targets: **Linux x86_64** (deb or tarball) and **macOS arm64** (tarball); platform
differences are called out inline.

---

## 1. Get the binaries

Two channels work today.

**From source (the reliable one).** Requires only Rust; `rust-toolchain.toml` pins the
version and rustup installs it on first `cargo`. Cermet ships ONE executable, built by the
composition crate `cermet-bin` (the workspace root is a virtual manifest, so
`cargo install --path .` refuses — name the crate):

```bash
cargo install --path crates/cermet-bin      # -> ~/.cargo/bin/cermet
```

`sudo cermet setup` publishes that binary and creates `cermetd` and `git-remote-cermet` beside it
as relative symlinks to it.

**From a release tarball, by hand.**

```bash
gh release download v0.1.0 --pattern 'cermet_*_darwin_arm64.tar.gz' --pattern SHA256SUMS
shasum -a 256 -c <(grep darwin_arm64 SHA256SUMS)
tar -xzf cermet_*_darwin_arm64.tar.gz -C ~/.local/bin
```

`dist/get-cermet.sh` from a checkout does the same resolve-verify-install unattended. Expected
tail:

```
cermet_0.1.0_darwin_arm64.tar.gz: OK
installed cermet and cermetd in /Users/you/.local/bin
run: sudo /Users/you/.local/bin/cermet setup
```

Intel Macs have no published artifact and the fetcher refuses them by name — build from source.

## 2. Install the service — one privileged step, then three explicit ones

```bash
sudo "$HOME/.cargo/bin/cermet" setup
```

Give the **absolute path**. A bare `sudo cermet setup` resolves against sudo's own PATH, which
on Linux excludes `~/.cargo/bin` entirely and on either platform can land on an older published
copy.

`setup` creates the service account, the `0700` daemon-owned vault and state dirs, the three-plane
socket topology (operator `ctl.sock`, agent `agent.sock`, git `git.sock`), and the one
`/etc/sudoers.d/cermet-agent` rule that lets your harness launch the MCP bridge as the dedicated
agent uid.

**The socket dirs differ by platform**, and everything below that names one is showing the macOS
arm: Linux uses `/run/cermetd` (operator + git) and `/run/cermetd-agents` (agent bridge); macOS uses
`/var/cermetd` and `/var/cermetd-agents`. Substitute accordingly. The install prefix differs too —
macOS publishes into `/opt/cermet/bin`, the Linux package into `/usr/bin`.

It also chooses this box's **vault-key custody**, and tells you which it chose. Cermet takes the
strongest mechanism the machine can actually carry, and never one it cannot:

| rung | what holds the key | what it does not protect |
|---|---|---|
| `systemd-tpm2+host` | a systemd credential bound to this OS install **and** this box's TPM2 | — the encrypted key is bound to this OS installation and TPM2 device |
| `systemd-host` | a systemd credential bound to this OS install's host secret | persistent Cermet files do not contain the plaintext key, but full host-image disclosure may permit recovery |
| `file-protected` | a `cermet`-owned `0600` key file, kernel-`EACCES` to every other uid | does not protect vault key from: disk snapshots or backups |

The choice is automatic but never silent: the closing summary names the rung and its limitation,
`cermet check` reports it, and it is written into `/etc/cermetd/config.toml` as `custody_profile`,
which is what the daemon reads to decide where its key comes from.

```
[cermet-setup] ✓ credential vault ready (custody: systemd-host)
[cermet-setup]   persistent Cermet files do not contain the plaintext key; full host-image
                 disclosure may permit recovery
```

macOS has one rung today (`file-protected`); a Linux box that cannot be handed a systemd
credential — many containers — lands there too, and says so instead of refusing to start.
The rung is chosen at FIRST provisioning and then stays: re-running `setup` re-declares the rung the
box is already on, because the key that exists is the key the vault is encrypted under. Moving to a
stronger rung today therefore means re-keying with `--force-clean-bootstrap`, which is a vendor
reset — it destroys the vault. A lossless in-place rung upgrade is queued post-launch.


**It ends with the daemon enabled and running** — systemd on Linux, launchd on macOS — like
any service-shaped package. A freshly installed daemon serves an empty corpus, which is
deny-all: nothing is authorized until a human writes a sentence.

```
[cermet-setup] fixed service: cermetd bootstrapped and running
[cermet-setup] ✓ broker running (cermetd, starts at boot)
[cermet-setup] ✓ credential vault ready (custody: systemd-host)
```

If the human isn't yet in `cermet-approvers` (presence ceremonies require it), the closing
lines print the exact platform command to add them.

Staying current: `cermet update` installs whatever
`https://github.com/suarezc/cermet/releases` publishes as latest — the same GitHub Releases you
installed from — through the channel this box was installed by: a package install applies the new
`.deb` with dpkg, a tarball install publishes the new tarball through the same convergence `setup`
runs. The version, the checksums and the artifact all come from that ONE release, the artifact is
verified against the release's own `SHA256SUMS` first, and the daemon is restarted. `cermet update
--check` reports and stops. Both run only when you type them, and both say what they verified:
`github-release` when a checksum was resolved, `no-artifact` when there was nothing to install.
A same-release checksum proves the download is intact and matches what the release publishes — not
who authored it. Until a release is published, both forms say so and exit 0.

**A daily check runs on its own, and it never installs anything.** Once a day, as you and never as
the daemon, Cermet asks that same release channel what it publishes and writes the answer down on
this machine. While something newer is available `cermet` prints one line and `cermet check` shows a row;
applying it is still `cermet update` with your sudo password. The request carries no install id, no
account, no query and no parameters at all — the comparison happens here. Its user agent names the
client version (`cermet/0.1.0`, identical on every install of that release), so we can see which
releases are still out there and who a security notice needs to reach. A release whose notes begin
with `SECURITY:` says SECURITY UPDATE and prints its release page. Turn the whole thing off with
`cermet update --daily off`, and nothing is contacted on a schedule.

**If you installed with `cargo install` above, `update` hands the upgrade back to cargo** instead
of publishing a second cermet beside it — package-manager installs stay package-manager-managed,
and the same will hold for a Homebrew formula. It contacts nothing and changes nothing; it prints
the two steps:

```
installed via cargo
run: cargo install --locked cermet   (or, from a source checkout: cargo install --locked --path crates/cermet-bin)
then: sudo /home/you/.cargo/bin/cermet setup   (republishes the system install from the new binary)
```

Both steps matter. `cargo install` replaces the binary in `~/.cargo/bin`; `sudo … setup`
republishes the root-owned copy the daemon actually executes and restarts it, so stopping after
the first leaves the service on the old build. Give `setup` that absolute path — `sudo` resolves a
bare `cermet` against its own PATH, which on Linux excludes `~/.cargo/bin` entirely.

Replacing an older install? `setup` also prints a `cutover:` block naming cermet processes still
running from a deleted or out-of-prefix binary and MCP registrations that still launch a cermet
from somewhere else. Do what that list says — otherwise the old engine keeps answering with its
own credentials and its own rules. One survivor it cannot see is the prior credential store; on
macOS scrub it by hand with `security find-generic-password -s cermet-broker`, then
`security delete-generic-password -s cermet-broker` for anything it finds.

**Open a new shell before step 3 — on macOS.** `/opt/cermet/bin` reaches PATH through
`/etc/paths.d/cermet`, which `path_helper` reads at **login**, so in the shell that ran the install
`cermet` is still `command not found`. A fresh **login** shell picks it up permanently. (This whole
note is macOS-only: on Linux the package publishes into `/usr/bin` — a source-tree `setup` into
`/usr/local/bin` — both already on PATH, so there is no `paths.d` step and no new shell needed.)

`eval $(/usr/libexec/path_helper -s)` also works, but it patches **only the shell you run it in**,
and only until that shell exits. Anything that spawns a new non-login shell per command — scripts,
`tmux` panes, some IDEs, most agent harnesses — comes back to `cermet: command not found` and looks
like the fix "stopped working". For those, put the directory on PATH per shell explicitly:

```bash
export PATH="/opt/cermet/bin:$PATH"
```

## 3. Prove the plumbing

```bash
cermet check
```

Read-only, always safe, mutates nothing. Exits `0` when every row is clean and `1` when any row
is `✗`, so it scripts. Real output from a working box:

```
plumbing
  ✓ cermetd            serving on ctl.sock — 3 provider(s) connected
  ✓ build              cermet and cermetd are 0.1.0+<commit>
  ✓ custody            systemd-host — persistent Cermet files do not contain the plaintext key
  ✓ git-remote-cermet  /opt/cermet/bin/git-remote-cermet
  ✓ git plane          git.sock at /var/cermetd-agents/git.sock; uid 501 (you): admitted (approver_uid)
  · update check       running 0.1.0, nothing newer — last checked <timestamp>
  ✓ agent bridge       /var/cermetd-agents/agent.sock

stale engines
  ✓ stale engines      no cermet process or MCP registration from another install
```

Three rows worth knowing before you see them:

- The **`build`** row compares this CLI against the daemon that answered. Both roles come from one
  file and one build, so a mismatch means the daemon is still running the executable it mapped
  before the last reinstall — reinstall (`make -C dist install`, which restarts the service for
  you) and restart any agent session holding an MCP connection. An MCP bridge on a skewed build is
  not merely noted, it is REFUSED at its handshake with "build skew; restart the agent session":
  a stale bridge serves an obsolete tool surface. Operator commands print a one-line note on
  stderr.

- The **`stale engines`** section always renders — a `✓` with *"no cermet process or MCP
  registration from another install"* is the clean answer, not an absent row. When it is not
  clean it distinguishes two survivor kinds. A stale **engine** (an old `cermetd` from another
  install — it serves its OWN credentials and rules) gets the `sudo kill <pid>` line: it is
  indistinguishable from a broken new one until you kill it. A stale **agent
  client** (a live session's keyless `cermet` MCP server still running an upgraded-away binary;
  authority stays with the daemon) gets *"restart the agent session that owns it"* — killing it
  would sever that session's tools mid-task. It also names each MCP registration that would
  launch a cermet from somewhere else. The scan covers running processes, `~/.claude.json`,
  the OpenCode (another agent harness) config, and every `.mcp.json` from the directory you are
  standing in up to `/` —
  not a `.mcp.json` in some other checkout.
- If `git-remote-cermet` reports *"not on this shell's PATH, but `/etc/paths.d/cermet` registers
  it — this shell predates the install"*, that is step 2's fresh-shell note, not a broken
  install.

Per-provider rows appear as you connect them. `cermet check github` shows one provider's whole
story — credential, repo wiring, standing rules — on one screen.

## 4. Connect a provider

```bash
cermet connect github
```

You paste the credential once at a masked prompt: it never enters argv or your shell history,
it crosses to the daemon exactly once, and it is encrypted at rest in the daemon-owned vault. No
agent-facing surface can read it back. **This step is not presence-gated** — you are physically
typing the token, which is the evidence, and storing a credential grants no authority. Authority
comes only from sentences (step 5). Expected:

```
✓ github credential stored — cred_github
  Label: (none); replaced: no.
  Your token is in Cermet's vault. The agent never sees it.
```

For GitHub, if you run it inside a git repository, `connect` then **offers** to repoint that
repository's remote at `cermet::github/<owner>/<repo>` — git's own transport-helper addressing,
set with git's own `remote set-url`, which is what makes plain `git push` route its one
credential-bearing hop through the broker. It is never silent: decline, or run non-interactively,
and it prints the exact `git remote set-url` command instead of editing your repo behind your
back.

Same shape for the others:

```bash
cermet connect stripe
cermet connect vercel
```

## 5. Write your first sentence

Authority is sentences. Nothing executes without one — that is the entire security model, and it
is not configurable. Two ways to author, and **both raise a presence prompt**.

**One-off, straight into the live corpus:**

```bash
cermet rules allow 'github.push where owner = "you" and name = "your-repo"'
```

**How you exercise this one:** run `git push` in a repository wired by `cermet connect github`
(step 4). `github.push` is decided by git's own update hook, not by `cermet run`, and it is the one
verb that is NOT requestable — asking for it returns a definite deny whose reason is a signpost to
the door that does work:

```
$ cermet run github.push --ask-only
{
  "request_id": "req_…",
  "decision": "deny",
  "reason": "github.push is not requestable: a git push is decided by git's update hook. Run `git push <remote> <branch>` in a repository whose remote is a `cermet::` URL — wire one with `git remote set-url origin cermet::github/<owner>/<repo>` (or `git remote add origin cermet::github/<owner>/<repo>` in a fresh repo). The refusal, if any, arrives in git's own output.",
  …
}
```

It is a decision, not a transport error, so it exits 1, is receipted like any other deny, and an
agent reading it over MCP gets the same words.

Every other verb answers the `--ask-only` loop of step 7. This one answers `git push`.

What happens, in order: the CLI echoes the rule in canonical form together with the verb's
response contract (what the verb returns and what it stores — so "allow" is never consent to a
response surface you were not shown), asks `Allow this rule?`, and only then raises the
**macOS device-owner prompt** (`LAPolicy::DeviceOwnerAuthentication` — Touch ID, with your
account password as the OS-controlled fallback, so a Mac with no enrolled biometrics still
requires a live human). On Linux that prompt is PAM. Decline it, or run where it is unavailable,
and nothing is committed: the mutation stages and stays inert.

**That prompt is drawn by macOS, on the physical screen — not in your terminal.** The terminal
prints `cermet: waiting for device-owner authentication (Touch ID / password) — check your screen`
and then blocks; the outcome line (`confirmed` / `declined` / `unavailable`) follows on stderr.
If nobody answers within ~60 seconds it fails closed with `authentication prompt timed out`. Over
SSH, or on a box whose screen you cannot reach, this command cannot succeed — that is the design,
not a bug.

The receipt names the path that accepted it:

```
added rule #24: allow github.push where owner = "you" and name = "your-repo"
receipt_state: known
live: sha256:<digest>
occurrence_id: <id>
acceptance_path: presence
lockdown: clear
document_sync: <state>
```

`acceptance_path: presence` is the line that distinguishes a real attested mutation from the
read-only paths, which print `presence: not_required`.

Two prerequisites nobody tells you: you must be in the `cermet-approvers` group (step 2), and the
echo confirm needs a **TTY**. `--yes` skips only that CLI-side echo — never the presence gate.

**The durable way — CERMET.md in your repo.** The document flow needs a **git repository**. Run it
anywhere else and it exits `2`, saying so:

```
init: repository unavailable
active_profile: (unnamed) 4b8004bd4e13
directory_file: none — no CERMET.md found from this directory
```

The corpus the `rules allow` above made live is still being served, and says so from any directory
on the box — `(unnamed)` because no stored profile holds that body. What is missing is a document
HERE. (The EXIT CODE is what to branch on: `0` aligned, `1` drift, `2` unusable.) It also needs the
file to exist first:

```bash
cermet doc check --init   # seeds CERMET.md from the LIVE corpus, with its pin
# ...edit the fenced `cermet` block inside the cermet:authority:v1 markers...
cermet doc diff           # what your document says vs what is served (exits 1 when they differ)
cermet doc apply          # presence-gated; makes it live and re-pins the hash
```

`doc check --init` prints `state: aligned`. `doc status` afterwards answers two questions — what
the daemon is serving, and what is in this directory — and both digests are truncated to the same
width, so equal prefixes mean the file IS what is live:

```
active_profile: (unnamed) 4b8004bd4e13
directory_file: CERMET.md 4b8004bd4e13
```

After an edit the prefixes differ and both `doc status` and `doc diff` exit `1`; `doc diff` then
shows the change itself — a minimal unified diff in the direction apply moves, so adding one
sentence is one `+` line:

```
--- live
+++ document
@@ -3,1 +3,2 @@
 allow stripe.search_customers
+allow stripe.refund where amount <= 5000
```

Only the managed block is authority input. Prose in CERMET.md is guidance, never policy.

**Named authority profiles — `cermet preset`.** One corpus is live at a time, and the set of rules
an agent needs depends on what it is doing: a design session needs to read, a build session needs to
push. A **preset** is a stored corpus body under a name, so switching between those sets is one
command instead of an editing session.

The name is just a key. It refers to no repository, no directory, and no file on this box —
`designer`, `builder` and `q3r982` are equally good names, and a name may hold letters, digits, `_`
and `-`.

Write one by applying a document named `CERMET_<name>.md`:

```bash
cermet doc apply CERMET_designer.md   # the full ceremony; stores what it commits under `designer`
```

A profile is written only by a ceremony like that one — either this ingest, or a later
`cermet preset <name>` that re-applies the stored body and re-stores it under the same key (which
moves its `UPDATED` time and nothing else). It is the same ceremony as any other apply — the
review, the terminal confirmation, the presence gate, the staged commit — and the body is stored as
part of the commit that made it live. There is no write path that skips it, so every stored profile
is a body a human read and attested, exactly like the live corpus.

Then switch between them by name:

```bash
cermet preset list                    # every stored profile; the served one is marked ● live
cermet preset designer                # install that profile
cermet preset export designer         # write it back out as CERMET_designer.md
```

**Applying a preset REPLACES the live corpus.** A profile is a whole corpus, not an addition to one:
accepting `cermet preset designer` installs exactly the rules `designer` holds, and every rule the
previous generation carried and this one does not is gone. The review shows that before you accept
it — removals as `-` lines, additions as `+` lines, against what is live right now.

`preset <name>` runs the ceremony `doc apply` runs, so there is no `--yes` on it either. What it
does not have is a pin marker: a profile is not derived from the generation it replaces, so there
is nothing for a marker to name, and `--replace-live` has no meaning here. `--recover` still does,
and is required to replace an unserved or corrupt daemon record.

Applying the CERMET.md of the repository you are standing in stays `cermet doc apply`.

## 6. Put the agent on the clock

Your agent uses its native tools; the broker carries the credentialed hop.

```bash
git push        # git's own plumbing, once step 4 wired the remote and a sentence admits github.push
```

Or drive one verb directly. The verb is **dotted**, spelled exactly as the corpus spells it:

```bash
cermet run stripe.get_charge --resource '{"charge":"ch_..."}'
cermet run vercel.deploy --resource '{"project":"your-site","target":"preview"}'
```

A successful run prints one JSON receipt on stdout and exits `0`. Same envelope for every verb —
the provider's body under `result`, the broker's own fields beside it, never mixed into it:

```json
{
  "action": "read_repo",
  "artifact": "art_5f2c9a41",
  "envelope": {
    "request_id": "req_644d97cb66f6cecf"
  },
  "ok": true,
  "provider": "github",
  "result": {
    "full_name": "suarezc/cermet",
    "default_branch": "main",
    "private": true
  },
  "wire_stats": {
    "total_bytes": 79265,
    "kept_bytes": 96
  }
}
```

(`result` above is trimmed for the page; the real one is GitHub's repository object verbatim.)
`envelope.request_id` is the handle `cermet log <request_id>` takes — chase the receipt with it
rather than grepping timestamps. `artifact` is the content handle for the full retained body, read
back with `cermet artifact <handle>`; `wire_stats` is how many of those bytes actually reached you.
A verb that declares `retention: none` has no `artifact` and no `wire_stats`.

`cermet catalog` is the discovery surface, and it prints the field names you need — every entry
carries its signature and the sentence that admits it:

```
allowed now (22 verbs) — a standing sentence admits each of these; request it directly.
  stripe.get_charge(charge:str) [http_api_call] — allowed by: allow stripe.get_charge
  vercel.deploy(project:str, target:str, team?:str) [relay] — allowed by: allow vercel.deploy where project = "cermet-site" and target = "preview" | ...
```

`?` marks an optional field; provider-resolved fields are omitted because the broker fills them.
`cermet catalog --all` is the full dictionary, every entry stamped with its authority status.

Two prerequisites worth knowing up front:

- **`vercel.deploy` can name a Vercel scope, and usually does not need to.** `team` is an
  OPTIONAL request field. Omit it and the deploy simply lands wherever your Vercel CLI is already
  configured to deploy — nothing about the scope is pinned, and the scope each hop actually used is
  recorded on the relay hops (`cermet log --hops`). Name it — by team id (`team_…`) or by the team
  slug your Vercel dashboard shows — and that scope is frozen for the whole session and pins the
  `?teamId=` the CLI stamps on every scoped call, so the deploy cannot wander into another scope
  mid-session. A slug is resolved to its id once, inside the daemon, before the sentence judges the
  request; a name your connection does not reach denies. **Pinning WHICH scope is the sentence's
  job, exactly like `target`**: a rule that spells `and team = "team_…"` admits only that scope and
  refuses a request that named none, while a rule that does not mention `team` leaves the choice to
  the requester. Unmentioned means unconstrained, uniformly, for every field.
- **`vercel.deploy` is a relay verb** — it prints the exact `vercel deploy` invocation to run, so
  the **Vercel CLI must be on PATH**. `cermet check` flags this: *"'vercel' not found on PATH — a
  relay invocation will fail as written."*
- **`cermet mcp install` shells out to your agent client's CLI.** Without `claude` on PATH it
  exits `1` and hands you the registration line instead:

```
✗ The `claude` CLI is not on PATH. Register manually:
  claude mcp add cermet -- sudo -n -u cermet-agent -g cermet-agents /opt/cermet/bin/cermet --socket /var/cermetd-agents/agent.sock mcp
```

With `claude` on PATH it registers for you and summarizes the target:

```
✓ registered MCP server 'cermet' → /opt/cermet/bin/cermet (CERMET_AGENT_SOCK=...)
```

That arrow is a summary, not the command. What actually got registered is the full line above —
`sudo -n -u cermet-agent -g cermet-agents /opt/cermet/bin/cermet --socket … mcp` — because the
bridge runs as the dedicated agent uid, never as you. `claude mcp get cermet` shows the real argv,
and the `sudo` prefix there is expected, not a tampered registration. It is non-interactive
(`-n`) and authorized by the single `/etc/sudoers.d/cermet-agent` rule step 2 installed.

Once registered, every verb a standing sentence admits appears as a typed tool, and the `catalog`
tool answers "what may I do right now" with the admitting sentence inline.

## 7. The first deny, and widening it

A denial is an answer, not an error. It costs one request and prints the sentence that would
widen it — for **you** to apply, never the agent. Approvals are human-only; no approve tool is
ever exposed on the agent surface.

```bash
cermet run vercel.deploy --resource '{"project":"not-my-site","target":"preview"}' --ask-only
```

```json
{
  "request_id": "req_79dd89949fc53e3b",
  "decision": "deny",
  "reason": "vercel.deploy denied by sentence authority: rule 2 predicate 1 did not match (field `project`)",
  "hint": "to allow: cermet rules allow 'vercel.deploy where project in {\"cermet-site\", \"not-my-site\"} and target = \"preview\"'",
  "authority_kind": "sentence"
}
```

`--ask-only` stops at the decision and **exits 0 for allow and deny alike**, deliberately: it
asked a question and the answer is the receipt, so a caller branches on the `decision` field.
Drop `--ask-only` and a deny renders in words and exits `1`, because then you asked for the
effect and did not get it.

The numbers in `reason` are the ones you can act on: "rule 2" is the sentence `cermet rules` lists
as 2 and the number `cermet rules revoke 2` takes, and "predicate 1" is the first `where` conjunct
of that rule.

Take the hint to whoever holds authority and apply it with `cermet rules allow` (step 5). Do not
retry the run first.

## 8. When the word doesn't exist yet

Step 7 is one of **two** walls an agent hits, and they have different answers.

| what happened | the gap | the channel |
|---|---|---|
| the verb exists, your sentences don't admit this ask | **authority** | the deny's widening suggestion — for **you** to apply with `cermet rules allow` |
| the verb, or a field on it, isn't in the catalog at all | **vocabulary** | the agent's `request_vocabulary` MCP tool — it hands the agent a formed request to give to *you*, and records the event in the daemon's log |

The difference is whether the ask can be *expressed*. `cermet catalog --all` is the dictionary of
every verb that exists; if the verb is in there, a request returns a definite decision and a deny
carries the sentence that would widen it. If it isn't in there, there is no deny to widen — the
sentence you would have to write has no word for it. That is a gap in the product, and the people
who can close it are us.

So the agent's tool checks the ask against the live catalog and, if the word genuinely does not
exist, hands back a block like this for the agent to relay to you:

```
--- vocabulary request ---
provider: stripe
wanted verb (does not exist): list_disputes
the ask: reconcile the disputes we lost this week
why it matters: the finance agent can see charges and refunds, disputes are a different object
cermet: 0.1.0+… on linux-x86_64
--------------------------
```

Three things it deliberately is not:

- **Not authority.** It grants nothing, changes no sentence, and unblocks nothing right now. A verb
  that already EXISTS is *refused* with a pointer back to the normal request path — misfiled
  authority asks would make the signal worth nothing to either of us.
- **Not a store, and not a transmission.** Nothing is written to a file of its own and nothing
  leaves the machine: there is no network client for this in the binary. The event lands in the
  daemon's own event log, the same one `broker_start` writes to, so it is counted by
  `cermet audit-verify` like any other decision. The courier is you, permanently — nothing here is
  ever sent anywhere.
- **Not a place for keys.** Free text is fine — that is the point of the rationale — but a form
  carrying credential-shaped material is refused outright rather than redacted, so it never reaches
  your terminal or your log.

## 9. Read the receipts

```bash
cermet log                # recent history, as the sentences that authorized it
cermet log <request_id>   # one request's full record as JSON — allowed or denied
cermet audit-verify       # the hash-chain, checked from genesis
```

`cermet log` renders the 100 most recent rows unless you pass `--all`, and the filters
(`--since`, `--provider`, `--denied`, `--burned`, `--hops`) narrow the log *first*, then the window
applies:

```
2026-08-14T10:12:03.481202Z  DENIED vercel.deploy: vercel.deploy denied by sentence authority: rule 2 predicate 1 did not match (field `project`) — project=not-my-site target=preview
2026-08-14T09:51:18.204551Z  ALLOW vercel.deploy — allowed by: allow vercel.deploy where project = "site" (corpus 1f2e3d4c) →burned(bind_mismatch)
2026-08-14T09:47:55.062114Z  ALLOW github.fetch — allowed by: allow github.fetch where owner = "acme" and name = "api" (corpus 1f2e3d4c) →ok
```

A row ends with what became of the effect its decision authorized, where the record determines one:
`→ok` (it landed), `→burned(<reason>)` (a refused hop ended the relay session — authority said yes
and nothing deployed), `→expired_unused` (the window ended having driven nothing), `→unresolved`
(it ended after hops with nothing saying the effect landed). No suffix means the record does not
say, most often a window still in flight. `cermet log --burned` is the same question `--denied` asks,
one layer down: `--denied` finds what authority refused, `--burned` finds what it allowed and the
effect layer then ended.

`cermet log <request_id>` returns the row as JSON — decision, reason, resource, principal,
session, and the `authority_fingerprint` of the corpus that ruled on it. `cermet audit-verify`
returns a JSON census of the verified chain (`event_count`, `event_types`), exiting non-zero if
the chain does not verify.

Every decision — allow and deny alike — is a typed row in a hash-chained log written by the
enforcement point itself. When you want to know what your agent did while you were out, the
answer is one command, and it is not a claim; it is a receipt.

### What the CLI itself printed

The receipts above are the *broker's* record of what was decided. They are not a record of what
your terminal was told — and some of what it was told exists nowhere else: the review text of a
ceremony, the reason a command refused, a confirmation somebody declined (nothing was decided, so
nothing was receipted). For that, the CLI keeps its own journal:

```bash
cermet journal            # on or off, where the file is, how big it is, what bounds it
tail -n1 ~/.local/state/cermet/journal.jsonl | jq .
cermet journal off        # stop it; `cermet journal on` resumes
```

Every `cermet` command appends **one JSON line** to
`$XDG_STATE_HOME/cermet/journal.jsonl` (by default `~/.local/state/cermet/journal.jsonl`, mode
`0600`): when it ran, its arguments, the directory it ran in, its exit code, how long it took, and
the first **4096 bytes** of what it printed. Longer output is counted in a `truncated` field rather
than stored — a long `log` or `catalog` render re-reads a store that already exists durably, while
the output that exists nowhere else is short. The file rotates whole at **32 MiB**, keeping one
previous generation as `journal.jsonl.1`.

Nothing you *type* is recorded: the capture is of output only, so the no-echo token prompt in
`cermet connect` cannot appear in it. It stays on this machine and is sent nowhere (see §10). It is
a convenience for reading back what a command said, not an audit surface — for that, use
`cermet log` and `cermet audit-verify` above. Reading it is not a `cermet` command: it is a plain
JSONL file, which is why `cermet journal` prints its path.

The case it is built for is the one where you run a command and don't recognize what came back.
Instead of re-running it and pasting the output, point your agent at the journal: `cermet journal`
gives it the path, the last line gives it exactly what your terminal was shown — the same bytes, in
the same order, with the exit code beside them — and `docs/FIELDS.md` gives it the meaning of each
field in that output. The agent can then tell you what you are looking at without you reproducing
anything, and without either of you guessing at output that has already scrolled away.

The `cermet mcp` stdio server does not journal — its stdout is the agent protocol channel, and its
traffic already has receipts.

## 10. What Cermet sends us

Two things, both about releases, and both to GitHub — the host you installed from. That is the
whole list:

1. **`cermet update` / `cermet update --check`, when you type them.** One GET of
   `https://api.github.com/repos/suarezc/cermet/releases/latest`, then that release's `SHA256SUMS`
   from `https://github.com/suarezc/cermet/releases/download/...` (which redirects to
   `release-assets.githubusercontent.com`), plus the artifact itself if you go ahead.
2. **The daily update check.** Once a day, as you and never as the daemon, the same parameterless
   GETs; it writes a note on this machine and installs nothing. `cermet update --daily off` stops
   it.

Nothing else, on any schedule, and nothing to a Cermet-operated host at all — we run no collection
endpoint, and this binary contains no code that would reach one. No usage reporting, no account, and
no install identifier — your decisions, your receipts, and your corpus stay on your box. (The daemon
talks to GitHub, Stripe and Vercel with your keys — that is the product working, and none of it
reaches us.)

## 11. Uninstall

**Linux.** Stop and disable the two units, then remove the binaries:

```bash
sudo systemctl disable --now cermetd.service
sudo systemctl disable --now cermet-update-check.timer
sudo dpkg -r cermet                    # package install
# tarball install: sudo rm -f /usr/local/bin/{cermet,cermetd,git-remote-cermet}
```

**macOS.** Unload the two daemons, then remove the prefix and the PATH entry:

```bash
sudo launchctl bootout system/dev.cermet.cermetd
sudo launchctl bootout system/dev.cermet.update-check
sudo rm -f /Library/LaunchDaemons/dev.cermet.cermetd.plist \
           /Library/LaunchDaemons/dev.cermet.update-check.plist
sudo rm -rf /opt/cermet
sudo rm -f /etc/paths.d/cermet
```

Both platforms leave the daemon's own state behind on purpose. Remove it only when you mean to:

```bash
sudo rm -rf /var/lib/cermetd          # WARNING: this destroys the vault — every stored credential
sudo rm -rf /etc/cermetd              # config, including custody_profile
sudo rm -f /etc/sudoers.d/cermet-agent
```

Your own per-operator files are separate from all of that, unprivileged, and left alone:

```bash
rm -f ~/.config/cermet/config.toml              # the update-check and journal switches
rm -f ~/.local/state/cermet/journal.jsonl*      # the CLI's output journal (§9)
```

Also drop the MCP registration from your agent client (`claude mcp remove cermet`) and repoint any
`cermet::` git remote back at its upstream URL with `git remote set-url`.

---

That's the loop: install once, connect once, write sentences, agents work through native tools,
everything lands in the log. Widen authority one sentence at a time, exactly as fast as your
agent earns it.
