# Cermet Engineering Reference

Settled engineering design: how the current system is built. This document carries no build status.

## Core Invariants

- **The raw provider credential never leaves the trusted Rust authority/execution runtime.**
  `cermet-core`, owned by `cermetd`, opens a credential only for the provider adapter and drops it.
  Plaintext never reaches a model, agent-facing request, IPC response, product layer, persisted
  plaintext, receipt, artifact, log, or telemetry.
- **Approval authority is human-rooted.** Acceptor designation and the independent revocation root are
  human acts. No approve or auto-approve vocabulary exists on the MCP/agent surface. Delegated future
  acceptance must cross the acceptance seam, not add an agent approval command.
- **Fail closed everywhere.** Access requires a definite sentence `allow`; absent, malformed,
  unserved, unresolved, stale, or unmatched authority never grants.
- **Approved fields equal executed fields.** Every field, including `free_payload`, is supplied in the
  original request, typed, canonicalized, frozen before grant mint, audited before effect, and covered
  by the grant HMAC. There is no execute-time `parameters`, fill map, or hole.
- **No action implies another action.** Every grant authorizes one execution and is single-use.
- **Cermet is authorization and receipt — nothing else.** Carriers, staging areas, wire formats,
  quarantines, and content stores belong to the native tool. File content never rides a request:
  git moves git's content — the agent commits locally and pushes, the daemon serves
  `git receive-pack` on a mirror, and the broker's whole contribution is the `update` hook's
  decision and the credentialed hop.

### Named adversaries

Defensive code across this tree names the adversary it answers, by this shorthand. **T1** is
third-party content steering a cooperative model — prompt injection carried by a README, package,
web page, or provider response. **T2** is model accident or sloppiness: a wrong call made with no
adversary at all. **T3** is another uid on the same box reaching for a socket, a file, or a process
that is not theirs.

## Process Boundary

```text
agent / MCP client -> agent.sock --+
                                   +-> cermetd -> Broker -> Vault -> Provider
operator cermet CLI -> ctl.sock ---+            -> Audit / Artifacts
owner revocation path -------------------------> Lockdown latch
```

The workspace is pure Rust:

| Crate | Role |
|---|---|
| `cermet-core` | Trusted durable broker, grant kernel, vault, audit, templates, descriptors, providers. |
| `cermet-broker-actor` | One owning thread around the non-`Sync` broker. |
| `cermet-daemon` | Sole custody host and Unix-socket server. |
| `cermet-ipc` | Closed wire types, peer credentials, and bounded framing. |
| `cermet-ctl-client` | Keyless authenticated operator transport. |
| `cermet-cli` | Keyless multicall `cermet` binary: human/operator commands, `CERMET.md` reconciliation, and the agent MCP bridge. |

The daemon owns the master key, encrypted vault, state DB, audit DB, artifacts, sentence record, and
provider execution. Agent and operator clients hold no master key and never open those stores.

## One Standing Authority

The daemon sentence corpus is the only mutable standing capability authority. There is no profile
policy, profile activation, alias, pending-approval, approve/deny, or test-window authority path.
The `policy` module is an adapter around sentence evaluation, not a second durable policy store.

### Sentence record

One daemon-owned v2 record atomically binds:

- a fixed format/language version;
- the domain-separated canonical authority digest;
- the unique committing occurrence id;
- canonical sentence bytes.

The same `SentenceRecordStore` is the read-only `SentenceAuthoritySource` and ctl-only staged admin.
It reads with no-follow, regular-file, single-link, owner, mode, and size checks; verifies the embedded
digest; parses; validates set pins; and requires canonical re-encoding. A generation is served only
after semantic preparation succeeds in the current daemon lifetime. Absence, corruption, or an
unvalidated generation denies.

### Sentence decisions

A request is first canonicalized against the provider/action contract. The `SentenceEvaluator` then
evaluates `(provider, action, canonical resource)` against the authenticated corpus:

- a matching `deny` wins independent of order;
- a matching `allow` returns a definite Allow and identifies the rule;
- no matching allow, an unresolved reference, or invalid structure returns Deny;
- an eligible predicate mismatch may return an inert widening suggestion, never authority.

The decision is a pure function of `(request, corpus)`: no counter, window, or accumulated total is
read. The temporal clauses that were the exception — `budget … per <window>` / `rate … per <window>`,
which ran through a serialized audit-ledger gate before grant mint — are GATED OFF by the daemon
setting `language_temporal_clauses`. With the shipped default, corpus admission refuses any sentence
carrying one, naming that setting; the ledger machinery stays compiled behind the gate. See
`docs/LANGUAGE.md` §4.

There is no Ask. A definite Allow directly mints an approved grant with `sentence` provenance and the
source-authenticated authority digest. A Deny records the request/audit decision but mints no grant.
See `docs/LANGUAGE.md` for the exact authoring grammar.

### Catalog projection

Agent catalog discovery uses the same authenticated sentence snapshot, contracts, sets, and evaluator.
A verb is advertised only when its validated resource domain contains an allowed completion after deny
subtraction. Catalog presence is discoverability, not a grant; each concrete request is evaluated again.

## `CERMET.md`

Repository-root `CERMET.md` is the durable, portable, reviewable projection of the daemon corpus. It is
never a runtime authority source. Only one exact managed fence carries candidate rule text; surrounding
Markdown is byte-preserved prose and never crosses sentence IPC.

The generated marker is `none` or `sha256:<canonical-authority-digest>`. It records the repository's
last reconciled accepted generation and grants nothing. An exact empty body plus marker `none`
represents the absent baseline until first export; a committed empty corpus instead has a real digest.

### Command directions

| Command | Direction and authority effect |
|---|---|
| `init` | Live -> new no-clobber document. No authority change or presence. |
| `check` | Prepare and validate the managed body. No write, staging, or authority change. |
| `check --fix` | Canonicalize only the managed body and retain the marker. Proposal write only. |
| `diff` | Render deterministic candidate/marker/live and immutable-set differences. Read-only. |
| `status [--json]` | Classify document, marker, served live generation, and lockdown. Read-only. |
| `export [--replace-draft]` | Live -> document. No staging, presence, or authority change. |
| `apply [--replace-live] [--recover]` | Document -> live through one whole-corpus acceptance ceremony. |
| `allow` / `revoke` / `refresh` | Presence-gated incremental change to the same live corpus; document untouched. |
| `rules` | Numbered canonical live corpus. Read-only. |

`export` refuses to overwrite an unapplied proposal unless `--replace-draft` is explicit. `apply`
requires `--replace-live` when the marker does not name the served baseline, and `--recover` when
replacing corrupt or unserved state. Neither flag bypasses terminal confirmation or presence.

### Apply transaction

An authority-changing apply:

1. Discovers and holds the physical repository root and exact document preimage.
2. Extracts only the managed body and requires daemon-prepared canonical equality.
3. Reads and classifies the typed live baseline; anomaly flags are checked before staging.
4. Stages exact canonical text under a unique random token bound to the exact prior record.
5. Verifies canonical text, digest, token, and deterministic occurrence echo.
6. Rechecks root, file, and live generation; displays the whole rule/set diff.
7. Obtains default-no terminal confirmation and one client-side OS presence ceremony.
8. Rechecks every precondition, then commits the exact staged token once.
9. On transport ambiguity, queries status and retries only that token; presence is never repeated.
10. Advances only the marker after exact occurrence proof, then reports final drift and lockdown.

A checkout race cannot grant because the file is inert. It can cause a loud partial success after the
daemon commit: authority committed, marker reconciliation incomplete. No failure rolls authority back
to a potentially broader corpus.

### Drift model

Let `C` be the prepared candidate, `M` the marker baseline, and `L` the typed live generation.

| State | Meaning |
|---|---|
| `aligned` | Candidate, marker, and live agree. |
| `aligned_no_authority` | Exact empty body, marker `none`, record absent. |
| `unapplied_document` | Marker equals live; candidate is an inert pending proposal. |
| `unexported_live` | Candidate/marker remain at the baseline; incremental live authority moved. |
| `marker_stale` | Candidate equals live; generated marker needs repair. |
| `diverged` | Document and live both moved from the recorded baseline. |
| `repo_missing` / `repo_invalid` | Repository artifact is absent or cannot be safely prepared. |
| `dataplane_unserved` / `dataplane_corrupt` / `dataplane_unknown` | No trustworthy served generation. |

Aligned states exit 0, valid drift exits 1, and invalid/unavailable states exit 2. Lockdown is an
orthogonal dimension and always wins execution.

## Grant Kernel

### Frozen resource

An `ActionContract` declares a closed typed field schema, field class, allow-binding metadata,
execution targets, consumed fields, and relations. Provider canonicalization rejects unknown fields,
wrong scalar kinds, and absent required fields. The resulting `CanonicalResource` serializes with
sorted keys and no insignificant whitespace.

The original request's complete canonical resource is frozen in the grant. Secret-class values remain
necessary for later execution but are redacted from request/audit views. `ProviderCall` contains only
the action, an internally opened token, and the frozen typed resource. There is no runtime parameter
channel.

### Integrity and provenance

Every grant row carries provider/action, request/session attribution, canonical resource, lifecycle
status, expiry, principal, template hash, provider-descriptor hash, sentence authority digest,
sentence provenance, optional path authorization, lease stamps, and an HMAC over the authority-bearing
fields. Integrity is verified before lifecycle interpretation or credential use.

Template or descriptor replacement invalidates an unspent grant before effect. Any corpus change also
invalidates every unspent grant because claim re-reads and compares the authenticated authority digest.
Any requested/approved row without sentence provenance is terminalized at boot, and the execution
chokepoint independently requires sentence provenance.

### Single-use execution

Execution checks lockdown, quiesce state, grant HMAC/status/expiry, sentence provenance and current
digest, template/descriptor hashes, contract/resource validity, and provider availability before the
atomic `approved -> executing` claim. It then checks lockdown and sentence authority again before
effect. A changed or unavailable source terminalizes with `provider_invoked=false`.

Before any surviving effect, the audit chain records the complete frozen non-secret resource. Then:

- credentialed HTTP execution opens one zeroizing provider secret, invokes the adapter, redacts and
  narrows output, optionally stores an artifact, records terminal evidence, and drops plaintext.
- relay execution opens no credential at all. It opens a TTL-bounded session and hands back the
  handle that names it; the credential is opened later, one hop at a time, by the mode below.
- git execution is decided before the agent surface is involved at all, by git's own `update` hook,
  and the credential rides the hermetic runner that carries the authorized update.

Every claim is single-use regardless of provider success. A concurrent or repeated execute cannot fire
the action twice.

### Execution discipline (money is not a type)

There is ONE provider execution seam. What differs between verbs is DATA on the call, derived by the
broker from the verb's ratified, hash-bound action template — never from the adapter's opinion of
itself, and never from a class of verb:

| Bit | Meaning | Who sets it |
|---|---|---|
| `idempotency_key` | the at-most-once key the broker MINTED WITH THE GRANT and persisted before the first attempt, reused verbatim by a referenced retry | minted at mint, read at execute |
| `prove_effect` | the response is PROVED against the verb's compiled success contract instead of believed, yielding an `EffectProof` observation (`proved` / `refused` / `unproved`) | the template's declaration |

The reviewed ontology sidecar CONSTRAINS what a template may declare (a verb the reviewer called a
read or a pure observation can declare neither bit; enforced at build time by
`tests/ontology_execution_discipline.rs`) and stays inert to authority, as the inertness guard
requires. Seven Stripe effects declare both bits today; every other verb takes the plain hop.

The terminal record stores the OBSERVATION (`effect_proof`) and, beside it, the `effect_outcome`
derived from it in one place. Nothing upstream of that derivation states a verdict.

### Referenced retry

The broker owns no retry loop — no background state machine, ever. The agent drives retries, the
provider dedupes on the key, and the broker authorizes every attempt:

- a request may name a prior effect (`retry_effect`, an effect handle carried outside the resource);
- the retry takes a FRESH full decision on the ordinary request path — sentence, evidence, presence;
- its canonicalized frozen fields must be byte-identical to the referenced attempt's, or it is a
  plain deny (a different request is a new effect, not a retry);
- on allow it reuses the referenced attempt's persisted idempotency key verbatim, and ADOPTS its
  budget debit rather than taking a second one;
- each attempt lands its own receipt; the HMAC-bound lineage is the audit story;
- eligibility is DERIVED at decision time from the durable evidence of the lineage, never cached.

A failed effect's error names this channel concretely — the observation, then
`retry_effect=<effect_id>` — from one rendering shared by the returned error and the durable record,
and BOTH surfaces can act on it: `retry_effect` on the MCP request tool, `cermet run --retry-effect
<effect_id>` on the CLI. Each carries the handle as request metadata beside the request, never
inside the resource, and neither client validates it: the daemon authenticates the lineage.

### Relay enforcement (validated per hop)

The kernel's second enforcement mode. A relay verb's grant authorizes no constructed request: a
native client makes its own requests against a loopback listener, carrying an opaque session handle
where it would otherwise carry a credential. Approved == executed still holds, enforced by
INSPECTION instead of construction — per hop the session maps the handle to the frozen predicate and
the frozen values of every bound field, checks the request against the admitted shapes, and compares
each bound location against the value the approval froze. Only a passing hop is credentialed, on the
outbound side, and the session tracks the one shape that is the effect so it can pass only once.

A hop whose method and path match no admitted shape, or that contradicts a bound frozen value, is
refused **without the credential being attached**, audited, and the session is BURNED:
every later hop on that handle is refused. The session also closes on TTL, on owner lockdown, and on a
sentence-authority change — the revocation root and the live authority both outrank a session already
opened. It closes with a receipt DERIVED from the responses the relay itself forwarded — never from
anything the agent claimed.

**A refusal says what it refused.** At the moment it refuses, the relay already holds the frozen
field map, the offending bind and the shape inventory, so the refusal carries them: the field, the
constraint *as enforced* (an `omit:` transform reads as "must be absent", not as the frozen
literal), the value the hop offered, and a remedy where one is computable. Nothing it names is new:
every value is descriptor text from the template document the installer publishes world-readable in
the shared catalog directory, a field this caller's own approval froze, a value off the hop this
caller just wrote, or a value this caller's own session already received as a capture off its own
effect's response — and a captured bind says so rather than claiming an approval froze it, because a
capture is the effect's consequence and no sentence can pin it in advance. Borrowed text is bounded
and stripped of terminal-affecting characters at one choke point, since the detail reaches the
operator's terminal through the native client's own error printing. The stable reason word is
unchanged — it is the machine-readable code, and the disclosure is a separate field beside it. It is
uniform across every class that knows something, because a layer that stays silent while its
neighbour names its field teaches requesters that silence means "that part was fine". The grammar
and the per-class contents are `docs/FIELDS.md` §8.6.

**Descriptors bind; they do not block.** A shape's declared `query_keys`/`body_keys` are the
VOCABULARY a sentence or a request may pin, and BINDING is the whole enforcement: where a key is
pinned, the relay checks it on every hop that carries it (`bind_mismatch`). A key the descriptor
never enumerated is the native tool's own business, so it is forwarded and NAMED on the hop's record
(`undeclared_keys`, `docs/FIELDS.md` §1.7) — surfaced, never refused. Refusing on key membership
made the broker a content firewall over payloads that decide nothing about which effect happens, and
it forced worse workarounds than the risk it removed: a deploy driven with the project's own
`vercel.json` configuration held aside ships a differently-configured artifact. So the ratification
obligation is now about BINDING, not admission: a key whose VALUE carries authority over where an
effect lands must be bound to a frozen field, or declared authority-free in the ratified document
with the reason (`docs/provider_design_principles.md`). `vercel.deploy` binds `teamId` — a team
account's CLI stamps it on every scoped call — to the frozen `team` on every shape where it decides
where the deploy lands, and ratifies the read-only team-context call authority-free: it names its
team in the PATH and, as observed, sends no query at all, disclosing no more than the bindless team
LIST beside it — a bind there refused the CLI's own third call and burned the grant before any
deploy was attempted.

What a bind pins is the value the APPROVAL froze; WHICH value that is remains the sentence's
business. A rule that spells `and team = "team_…"` admits only that scope; a rule that does not
mention `team` admits whatever the request names, exactly as an unmentioned `target` does. Unmentioned
is unconstrained, uniformly — the relay's job is that the executed session cannot contradict what was
approved, not that the approval was narrow.

`team` is also OPTIONAL, which gives a bind a third state. A request that named no scope freezes the
field as ABSENCE, and a bind reading an absent field constrains nothing — the key may carry any
value, or none, and the hop record's own target is then the whole account of that position. A rule
PINNING an optional field still
refuses the omitting request (`missing_required_field`, naming the field): absence is not a value, so
optionality never satisfies a pin. The cost is stated where it is paid — an unpinned deploy's scope
follows the native CLI's own workspace configuration, and the hop records are then the only account
of the scope it used.

**The session's own dataflow.** A relay session's read shapes carry a wildcard — the
deployment id in `/v13/deployments/*` and in the two events paths — and matching "some segment is
there" made the grant wider than the sentence: an approved deploy also bought the right to read, and
tail the build logs of, every other deployment the vaulted token reaches. The predicate had no way to
say *this* deployment, because the deployment did not exist when the sentence was written. So the
session DERIVES it: the effect shape declares `capture: { deployment_id: id }`, read write-once off
the create's own 2xx response body, and each read shape binds `path.*: captured.deployment_id`. "No
action implies another action" now covers the reads inside a session too — its authority is its own
approved effect plus that effect's own consequences, and nothing else. Before the create lands nothing
is captured, so a poll refuses: the honest client never polls for a deployment that does not exist yet.

**Outcome assertion is DETECTION, not prevention.** Everything else in this section refuses
before the credential is attached. This one cannot: it reads the response to the effect, which means
the effect has already happened. The effect shape declares `assert:` — for `vercel.deploy`, the
response's `name` against the frozen `project` and its `target` against the frozen `target`, under the
same `omit:preview` encoding the request bind uses — and a mismatch **burns the session** and writes a
high-severity `relay_outcome_mismatch` audit event carrying frozen-versus-observed. It buys three
things, none of them prevention: provider-side semantic drift stops being silent, the session cannot
go on to poll or tail anything, and the receipt still names the deployment that landed, which is what
the operator needs in order to go deal with it. The response it reads is the bounded receipt tee, so a
response too large to parse yields no assertion and no capture — fail closed, and the cost is the
victory lap, not the deploy.

**Volume is its own dimension.** Everything above decides ONE hop; none of it bounds how
many hops, or how many bytes, a session may push through a shape it admits. `vercel.deploy`'s upload
shape was unlimited in both for the whole session TTL, so an approved deploy also bought an unbounded
credentialed pipe into the operator's file store (T2: an accident loop; T1: "while you're there, keep
uploading"). A shape may now declare `caps: { max_uses, max_total_bytes }` — a per-session budget,
charged on each AUTHORIZED hop, checked after every authority check so an out-of-sentence hop still
reports the authority defect. An overrun refuses before the credential and burns, under its own
`cap_exceeded_uses` / `cap_exceeded_bytes` reason. The values are ratified in the document from observed
evidence, generously above a real deploy: what they bound is abuse, not use. What was deliberately NOT
built is the missing-set gate — pinning each upload's digest to the create's `missing_files` list —
because the bytes it would constrain are a strict subset of the content freedom the deploy already concedes
(the deploy publishes arbitrary content by design), and the gate would cost five new engine
dimensions: reading a 4xx body, a nested response path, an array-valued capture, a bind that reads a
request HEADER, and set membership. The reasoning and what reopens it live in the ratified
`vercel.deploy` document beside the shape.

**Why the body key set is closed.** Checking only the keys a rule binds is not a closed
surface. Vercel's create-deployment body documents `project` ("when defined, this parameter overrides
name"), `customEnvironmentSlugOrId` (overrides the target environment), and `deploymentId` (redeploy an
arbitrary existing deployment) — each one overrides a field the sentence pinned, while the bound
`body.name` still matches. The allowlist also makes a parameter the provider adds LATER fail closed,
which is the same posture as CLI drift: it breaks the deploy, it never widens the grant.

The predicate grammar this mode enforces — admitted shapes, `bind`, `body_keys`, `capture`, `assert`,
`caps`, `consumes` — is `docs/LANGUAGE.md` §15b.

### Git enforcement (hook-decided carry)

The kernel's third enforcement mode, and the only one whose decision point is not the agent surface.
A `git:` verb is not requestable: its decision is git's own `update` hook, the sanctioned per-ref
policy seam, running on a daemon-held mirror and driven by an ordinary `git push`. The daemon wires
an attested stream to `git receive-pack` on the mirror and git does the transfer, the quarantine,
thin-pack completion, connectivity checking, the ref transaction, and the error rendering. Cermet
appears exactly twice: the hook decision, and the credentialed hop that carries an authorized update
to the upstream.

**Reaching it.** There is no client surface — that is the design. The repository's remote URL IS the
wiring: `cermet::github/<owner>/<repo>`, which `cermet connect github` offers to write once (with
`git remote set-url`, git's own command) and `cermet check github` reads back. Git resolves that
scheme by looking up `git-remote-cermet` BY NAME on `PATH`, so plain `git push` — the user's own git,
their config, their aliases, untouched — reaches the helper. The helper implements only git's
`connect` capability: it opens the daemon's agent-side git socket, writes git-daemon's own request
pkt-line, and splices. From there git speaks its native protocol end to end.

A remote URL is used rather than a global `url.cermet::github/.insteadOf` line (which the checklist
still RECOGNIZES, for operators who prefer it, but never writes): it is per-repo, it is visible in
`git remote -v`, and it has no ranking problem — an injected global alias could be outranked by the
user's own `insteadOf` and silently send a brokered remote direct, so no bypass preflight is needed
here. Repositories nobody wired are bare git, daemon or no daemon. The socket the helper trusts is
resolved by a declared ladder: an environment override, else a path under the configured Cermet
home, else the installed default.

**The mirror.** The daemon holds one persistent bare mirror per remote repo, created on first
authorized contact. Persistence is load-bearing: bases from earlier traffic are already present, so
every push after the first is O(delta) in both directions. Its lifecycle is HYGIENE — `gc --auto`
plus an aging sweep for mirrors no sentence has covered lately — not per-request cleanup.

**The read side.** A fetch or clone is decided at stream-open, before a single ref is advertised: a
fetch sentence must allow the repo, and then the daemon refreshes the mirror from the upstream
through the same hermetic runner the push hop uses. **The only path to served refs is a refresh that
just succeeded** — no matching sentence refuses and names the rule to add, a refresh that
fails refuses and carries git's own error, and neither arm falls back to serving what the mirror
already held. A repo this host has never seen is created and seeded on the way, which is what makes
`git clone cermet::github/<owner>/<repo>` work at all. Push authority is not read authority: they are separate rules.

**The write decision.** Git's `update` hook hands the broker `(repo, branch, old, new)` — git's own
numbers, computed from the ref transaction it is about to perform, never the agent's description of
them. `old` is the MIRROR's tip, and the grammar names it `mirror_old_oid` for exactly that reason:
the mirror can lag the upstream between refreshes, so a rule pinning it pins the daemon's view
rather than the upstream's. That tuple goes through the ordinary sentence machinery: same corpus,
same grant kernel, same audit, same receipt. A deny exits the hook non-zero
and git renders the refusal into the agent's normal `git push` output; there is no held pending push.
When no sentence speaks, the refusal says so and names the fix, and it carries the bounded
changed-path list `diff-tree` derived from the objects `receive-pack` already migrated into the
mirror — so the human deciding what rule to write is looking at what the push actually touches.

**The hop.** On allow, the broker carries the update `mirror → upstream` through the hermetic runner
and the hook confirms ONLY if that landed, so **the mirror ref advances iff the upstream's did**. A
plain push: the upstream server's fast-forward rule is the entire concurrency control, and its
refusal rides git's error channel back to the agent. Ref CREATION is the same effect as advancing
(git has no bootstrap ceremony), and so is DELETION: `new` at the zero oid carries as git's own
delete refspec under the same push sentence, matching git's model of what push authority means, and
is receipted the same way either direction — an admitted deletion leaves an allow row naming the ref
and the zero-oid transition, an unadmitted one a deny row with its widening suggestion. Restricting
deletion, for an operator who wants that, is sentence-axis work rather than a hole in the decision
path. Force is deliberately absent vocabulary: the hop is a plain push, so the upstream refuses a
non-fast-forward.

**The receipt.** It derives from the hook's frozen tuple plus the upstream's OWN account of what it
did, read out of `git push --porcelain`. It carries `upstream_old_oid` (what the
upstream moved from, or null with `upstream_created_ref: true`) beside `mirror_old_oid`, separately
labelled, because those are two different facts and conflating them would misstate the effect.

**Settings and hermeticity** (`git_binary`, `git_mirror_dir`, `git_max_push_bytes`,
`git_timeout_secs`, `git_mirror_retention_days`). There is no registration step: `git_binary`
defaults to the box's git at an absolute, root-owned path. The daemon boots identically whether or
not that path works; usability is checked per request, and a missing or too-old git refuses git
operations with an `ERR` pkt-line naming the setting — which git renders as `remote error: …` in the
agent's own push output. `git_max_push_bytes` is written into each mirror's config as
`receive.maxInputSize` at creation, so git caps what one push may write (the pack arrives before any
decision exists, so that bound has to be git's). The child runs with a cleared environment plus
`GIT_CONFIG_NOSYSTEM=1`, a neutralized global config, a controlled `HOME` and no PATH lookup, and it
leads its own process group so the timeout reaps the whole tree rather than just the direct child.
The credential is injected as `GIT_CONFIG_COUNT`/`_KEY_0`/`_VALUE_0` naming `http.<url>.extraHeader`
— **environment config, never argv and never the URL**, because `/proc/<pid>/cmdline` is
world-readable while `environ` is not.

The declarations this mode enforces — the descriptor's `git:` block, the `push`/`fetch` steps and
their slot table, `consumes` — are `docs/LANGUAGE.md` §15a.

## Credential and Provider Custody

Provider descriptors fix the HTTP origins and auth shape. Action templates fix one recipe and derive
the contract. Both exact documents are hashed into execution authority.

`cermet connect` is store-only credential ingress over ctl. It never verifies the credential by calling
the provider. The token is redacted in debug, encrypted into the vault, and represented externally only
by safe provider/label/reference metadata. The first provider use is a later sentence-authorized,
single-use execution.

HTTP templates cannot name a token or origin. They contain bounded ordered paths/query/body steps; the
descriptor supplies the pinned origin and auth shape. Secret fields may enter only allowed body
positions and are scrubbed from retained/provider-returned data.

## Audit and Evidence

The audit log is HMAC-chained over complete canonical events. Custody changes are occurrence-keyed, not
content-digest-keyed, so `A -> B -> A` remains three distinct accepted transitions. The record and
outbox carry the same occurrence id; boot/housekeeping replay exact committed-but-undelivered evidence
idempotently.

Before provider effect, `capability_effect_starting` carries the complete frozen non-secret resource.
Terminal provider evidence records success/failure and whether the effect boundary was crossed.
Artifacts are content-addressed; responses expose handles, not credentials.

### What Cermet durably keeps

For an HTTP verb the response contract is **verbatim** and the retention default is **`full`**: the
provider's body is stored as a content-addressed artifact. This is declared, not incidental —
`cermet catalog --all` (and the agent's `catalog` tool with `scope: all`) prints
`response: returns: … | stored: … | errors: …` per verb, so retention is readable from the surface
its reader already uses.

The declaration is **derived from what each verb actually does**, never assumed: a
GraphQL verb also fails at HTTP 200 with the body plus a sibling verdict, and each verb declares
its own response shape; see LANGUAGE.md §6.1 for the table. The cost, stated plainly: provider response material
(customer objects, PII, bearer values a provider chose to send) is durably at rest on the operator's
box. The counter-fact, stated next to it: that body already persists ungoverned in the agent
transcript; the artifact is the *governed* copy — one audited read verb, digest-checked, inside a
blast radius you can reason about. An artifact retention window / GC knob does not exist today; it
is a **declared future setting**, named now so its absence is declared, never improvised.

Two exceptions exist and both are visible per verb as `stored: none`: the money floor (below) and
`github.read_secret_scanning_alerts_open`, whose response space is third-party leaked credentials.
Every other verb follows the declared default.

### The money floor

A verb running the proving discipline (the seven money effects today) keeps **no artifact, ever**,
structurally rather than by declaration: the loader requires one non-GET `retention: none` mutation
step, the custody boundary clears the retained body independently of the template, and
`validate_money_terminal` treats such a terminal carrying artifact evidence as impossible — writer and
verifier cannot disagree.

The body is not lost. It lives in the **ledger terminal record**: the HMAC-chained audit event for
that effect carries the verified response — the created object's provider id, amount, currency and
status on success; the HTTP status, the provider's error classification, and the provider-side log
deep-link on a rejection. That record is tamper-evident by construction, which an artifact blob is
not, and it is the surface money reconciliation reads. For money, "what does Cermet keep?" answers
**the terminal record, not the artifact store**.

## Independent Lockdown

The owner revocation latch is independent of `CERMET.md`, ctl acceptance, and the agent surface. It is
durable, occurrence-audited, and fail-engaged on missing/malformed/unreconciled state. Engage narrows
authority without artifact or presence; clear is a separate owner ceremony.

The broker checks the latch before request/mint, before claim, after claim, and at provider egress.
Therefore a grant minted while clear can still be stopped before effect. A provider call already in
flight cannot be recalled.

## IPC Surfaces

- `agent.sock` carries exactly eight operations: session hello, request, execute, status, catalog,
  list_credentials, verify_audit, and artifact. Its closed vocabulary has no acceptance, rule
  mutation, credential-connect, or lockdown operation — and no document-serving operation, since
  Cermet's own documents are not part of the agent surface.
- `ctl.sock` carries operator reads, credential ingress, direct request/execute, sentence preparation,
  staging/commit, and audit/history operations. The CLI performs terminal/presence ceremony before
  authority-changing frames.
- The owner path carries only lockdown status/engage/clear and does not decode ctl or agent frames.

Peer credentials derive the caller principal/uid. Sessions are server-minted attribution and lifecycle,
not a second authority source. Request handles remain bearer handles within one uid's trust domain.

## Durable Schema

The greenfield state schema is generation 6 and has no migrations. A mismatched nonempty DB refuses
boot. The durable spine is requests, grants, and sessions; operations, proposals, profiles, aliases,
pipelines, and runtime fill columns are absent. Every new grant requires a provider-descriptor hash and
sentence provenance.

Verbs and descriptors are vendored. Runtime contract proposal/ratification, profile policy, pipeline
composition, and agent approval are not compatibility surfaces; future designs must preserve the core
invariants above rather than reintroduce them indirectly.
