# Field reference

Every field, key, annotation, and status word the Cermet CLI prints, and what each one actually
means. This is a dictionary of the printed vocabulary, not a tour of the commands — for the walk
through a first install see `QUICKSTART.md`, for the sentence language see `LANGUAGE.md` and
`GRAMMAR.md`, and for the engineering design behind the grant kernel see `REFERENCE.md`.

Descriptions here are mechanism-level: what computes the value, what the daemon does with it, and —
where a field has a closed set of values — what every value means. Fields are grouped by the surface
that prints them, in the order the CLI's own help lists them.

This document is enforced, not maintained by review: `crates/cermet-cli/tests/fields_doc.rs` holds
the field names printed by the code against the field names defined here and fails the workspace
suite if either side gains, loses, or renames one. It describes the vocabulary of the workspace
version it ships with.

Two conventions hold throughout:

- **An absent field is a fact, not a gap.** Optional fields are omitted rather than rendered empty or
  zero. Where absence carries a specific meaning, this reference says so.
- **`request_id` is the one public id.** It is the handle every operator surface takes, and the only
  id an agent ever sees. `grant_id` exists, is operator-internal, and appears only in the
  operator-side execution evidence.

---

## 1. Decision and receipt output

`cermet run`, `cermet run --ask-only`, `cermet run --resume`, and `cermet log <request_id>` all
print JSON. Which shape you get depends on how far the request got.

### 1.1 The decision receipt (`run --ask-only`)

`--ask-only` stops at the decision and prints it. Exit code is 0 for an allow, 1 for a deny.

| field | meaning |
|---|---|
| `request_id` | The broker-minted handle for this request (`req_<hex>`). It is what `run --resume` and `log` take, and what every later receipt names. |
| `decision` | `allow` or `deny`. There is no third value and no "ask" state: the evaluator returns a definite verdict, and anything unresolved is `deny`. |
| `reason` | The human-readable sentence explaining the verdict. On an allow whose rule the daemon stored, it carries the canonical rule text; on a deny it carries the deny provenance. |
| `hint` | The advisory, human-only command that would widen sentence authority to admit this request. Present on denials the evaluator can suggest a widening for. It grants nothing and mutates nothing — an operator has to type it. |
| `budget_exceeded` | Present **only** when a deny is a budget/rate exhaustion downgrade of an otherwise-allowed request. Value is a window classification — `hour` or `day` — never a number. No limit, remaining, consumed, or amount figure ever crosses the agent boundary; the numeric ledger lives in operator-side audit events. |
| `effect_id` | The safe logical handle for this request's money effect lineage. Present only for an allowed money request. It is a lineage reference, never the broker-held idempotency key, which has no public carrier. |
| `authority_kind` | Present only when the request actually reached sentence evaluation. Its one value today is `sentence`. Registry and canonicalization refusals happen *before* authority decides and omit the field — which is how you tell "the corpus refused this" from "this never got as far as the corpus". |

`grant_id` is deliberately not in this list. The CLI deserializes the daemon's reply into a type
defined as the decision minus `grant_id`, so an unknown key has no field to land in.

### 1.2 The execution receipt (`run`, `run --resume`)

When the verb executes in-core, the receipt is the execution result.

| field | meaning |
|---|---|
| `kind` | `executed` — the discriminant of the result shape. An HTTP verb that ran inside the daemon (the credential never left it). |
| `ok` | Whether the provider call succeeded. False here is a *provider* failure; the request was still authorized and the grant is still spent. |
| `provider`, `action` | The verb that ran, as the sentence corpus spells it. |
| `result` | The provider's response, already redacted, narrowed to what the ratified template declares. Byte-identical to the stored artifact — the response contract is verbatim, so the receipt and the artifact can never disagree. |
| `artifact` | The content-addressed handle for the retained response body — the same body `result` carries. Absent when the verb declares `retention: none` or the provider is a test double. Read it with `cermet artifact <handle>`. |
| `wire_stats` | The kept-vs-total byte counter for this execution. Absent when there is no retained body to measure against. |
| `total_bytes` | Inside `wire_stats`: the full provider response body at its true pre-scrub size. |
| `kept_bytes` | Inside `wire_stats`: how many of those bytes actually came back in the narrowed result. Its ratio to `total_bytes` is the live measure of how much wire the narrowing saved. |
| `effect_id` | The safe money-effect lineage handle, as above. |
| `effect_outcome` | The authenticated disposition of the effect (see §1.6). Derived only from chain-verified execution evidence; a caller can neither submit nor override it. |
| `envelope` | The broker-authored half of the receipt, kept strictly outside the verbatim `result`. Always present. |
| `envelope.request_id` | Stamped at the one broker seam that authors the envelope, so no verb can mint a receipt whose request cannot be chased with `cermet log <request_id>`. |
| `envelope.*` (other keys) | Per-verb broker metadata that deliberately does not live in `result`: a GraphQL step's classified outcome/conflict verdict, and a step's declared retained response headers. Empty for most verbs. Injecting them into `result` would make the receipt disagree with the stored artifact. |

### 1.3 The relay object

A relay verb is the exception to "execute". The broker authorizes it, mints a predicate-bounded
session, and returns a receipt whose `result.relay` names it. You then run the printed invocation
with the provider's own CLI; each hop that CLI makes is authorized and audited individually.

| field | meaning |
|---|---|
| `handle` | The session reference (`cermet_relay_<...>`). It is a live, predicate-bounded, single-effect, TTL'd, loopback-only capability reference — never a credential. The `cermet_relay_` prefix exists so that property is legible from the string alone, to a reader who cannot ask the daemon. |
| `api_base` | The loopback address the relay listens on. You pass it to the native CLI in place of the provider's own origin, which is what routes that CLI's calls through the broker. |
| `invocation` | The complete, ready-to-run native command line, with `api_base` and `handle` already filled in and every field the sentence froze named explicitly on the command line. Named rather than left to the tool's own defaults: a CLI that guesses a value (from the working directory name, say) produces a request that misses the frozen bind and burns the single-use grant before the real call is attempted. Both the flags and the enforcement read the same frozen map, so they cannot disagree. |
| `ttl_secs` | The session's declared lifetime in seconds, from the daemon's `relay_ttl_secs` setting. |
| `expires_at` | The absolute epoch second at which the session lapses. After it, every hop is refused as an unknown handle. |

If the native tool named by `invocation` is not on the *rendering process's* `PATH`, the CLI prints
a one-line `warning:` above the receipt. It is advisory only — nothing is blocked and the receipt is
unchanged. The check runs in the printing process because that process's `PATH` is the one you will
run the invocation in; the daemon's `PATH` answers a different question.

### 1.4 `cermet log <request_id>` — three shapes

One id, three possible fates. Which keys are present says which one you are reading.

**Executed** — the request was granted *and* ran. Every field is projected only after the grant's
HMAC and the complete audit chain agree on its identity and terminal event schema.

| field | meaning |
|---|---|
| `request_id` | The public id you asked for. |
| `grant_id` | The operator-internal grant this request minted. Present here and nowhere agent-facing. |
| `provider`, `action` | The verb. |
| `resource` | The frozen fields, as stored — already redacted at write time. These are exactly the fields execution used: they were frozen before the grant was minted and there is no execute-time fill channel. |
| `status` | The grant's lifecycle status (see §1.6). |
| `decision` | The recorded verdict (`allow`). |
| `integrity_ok` | Whether the row still authenticated against its per-grant HMAC at read time. Evidence is only projected when this holds. |
| `justification` | The agent's own stated reason for making the request, whole. The list form truncates for width; this does not. `null` when the request carried none. |
| `effect_id`, `effect_outcome` | As above. |
| `effect_state` | What became of the effect this request authorized, **derived at read time** from the events, hops and session record below plus a clock read — nothing stores it. It is here because the derivation is otherwise arithmetic the reader has to do by hand: "closed by `ttl` with `hops: 0`" and "closed by `ttl` after four hops and no effect verdict" are different fates, and a window whose daemon restarted has no `relay_session` at all. Absent when the record determines nothing. The values, and the rule that picks one, are in §1.6. |
| `events` | The verified effect-start and terminal events (§1.5). |
| `relay_hops` | The relay hops this grant authorized, oldest first (§1.7). Absent for every non-relay verb. |
| `relay_session` | The relay session's terminal receipt, verbatim as the broker derived it from what the relay observed (§1.8). Absent while the session is still live. |

**Denied** — the request was refused. Denials are recorded losslessly, so this answers with the
record rather than "not found".

| field | meaning |
|---|---|
| `request_id` | This row *is* the request, so it is its own handle. No `grant_id`: a denial minted no grant. |
| `provider`, `action` | The verb that was asked for. |
| `resource` | The fields the request asked for, as stored — redacted at write time (a secret-classed field carries its marker; an unresolved action's values are size-capped). The row's job is to say what was asked for. |
| `decision` | `deny`, `unsupported`, or `unregistered` — the fate as the broker recorded it. `unsupported` and `unregistered` are refusals raised before authority evaluated anything. |
| `reason` | The stored reason, verbatim, carrying the deny provenance: where a rule matched, the canonical text of that rule — never a rule number. |
| `deny_reason` | The evaluator's own typed refusal, stored beside the prose (see §1.9). Absent on a refusal raised before evaluation ran. |
| `justification` | The agent's own reason, whole. `null` when none. |
| `created_at` | When the request was recorded (RFC3339). |
| `session_id` | The session the request arrived on, if any. |
| `authority_fingerprint` | The digest of the sentence corpus this request was decided against. |
| `principal_id`, `principal_label` | See §1.6. |
| `request_model` | What the agent declared it was on this request. Unauthenticated and read by no authority — it is kept on refusals because what an agent was when it asked for something it could not have is the part worth learning from. |

The widening `hint` a deny returns at *request* time is not stored on the request row and is
therefore absent here. Re-deriving it at read time would evaluate today's corpus against yesterday's
request and print a suggestion the decision never made.

**Decided** — the request was allowed and nobody has executed it yet. This is the state
`run --ask-only` leaves behind.

| field | meaning |
|---|---|
| `request_id` | The one public id; `run --resume` and `log` both take it. No `grant_id` — a grant exists, but nothing anywhere takes the other id. |
| `provider`, `action` | The verb. |
| `resource` | The frozen fields, rendered through the same fail-closed redaction every grant view uses. These are what execution will use. |
| `decision` | `allow`, as recorded. |
| `status` | The grant's lifecycle status: decided, not yet terminal (typically `approved`). |
| `matched_rule` | The canonical text of the sentence that admitted the request. |
| `authority_fingerprint` | The corpus digest it was decided against. |
| `justification` | The agent's own reason, whole. |
| `created_at` | RFC3339. |
| `principal_id`, `principal_label` | See §1.6. |
| `integrity_ok` | Whether the grant row still authenticated against its HMAC. |
| `next` | The literal command that finishes this request: `cermet run --resume <request_id>`. |

### 1.5 Execution evidence events

Each entry in `events` is a closed projection of one verified audit event — never a raw row.

| field | meaning |
|---|---|
| `event_type` | Which event this is. `capability_effect_starting` is written before the provider is contacted; `provider_action_succeeded` and `provider_action_failed` are the two terminal forms. |
| `resource_binding` | An HMAC over the effect's identity and its frozen fields: `hmac-sha256:<hex>`, keyed by the daemon's grant key, over the grant id, the grant's frozen resource JSON, and the canonicalized resource actually recorded on the event. It is what makes "the fields recorded on the receipt are the fields the grant froze" checkable after the fact rather than merely asserted — retry and recovery paths recompute it and refuse a mismatch. |
| `authority_digest` | The digest of the sentence corpus the grant was minted under, carried onto the effect event so the effect names the authority generation that admitted it. |
| `outcome` | The event's own coarse verdict. `ok` — the provider call succeeded. `provider_error` — the provider answered and the answer was a failure. `error` — the execution itself errored. `lockdown_engaged`, `precondition_denied`, `precondition_credential_unavailable` — pre-invocation terminal failures, named for what stopped the attempt. `unreported` — a lease ended with no terminal event of its own. |
| `mutation_invoked` | The trusted classification of whether the provider adapter was actually entered. `false` means the failure is definitively pre-invocation — no provider-side effect is possible, so a budget debit must be released. `true` means the boundary was crossed and money may have moved. This is the only thing that earns a release: never an HTTP status, never a generic error, never an agent's assertion. For a relay verb it is `true` at the moment the session is minted, because handing out live relay authority *is* the invocation boundary. |
| `effect_outcome` | The disposition of the effect, on events that carry one (§1.6). |
| `result` | The provider result as recorded on the terminal event — the same already-redacted narrow projection the receipt carried. |

### 1.6 Closed value sets carried across these receipts

**`decision`** (the evaluator's verdict): `allow` \| `deny`. Denials recorded before evaluation may
carry `unsupported` (the verb is not in the ratified grammar) or `unregistered` (no credential is
connected for the provider).

**`status`** (a grant's lifecycle):

| value | meaning |
|---|---|
| `approved` | Sentence-authorized and not yet used. |
| `executing` | The single-use claim is being spent right now — the transient window between the atomic `approved`→`executing` claim and the terminal write. |
| `executed` | The claim was spent and a terminal event was written. Note that this says the attempt *ended*, not that it succeeded: an HTTP grant lands here on a provider error too. Success is `ok`/`effect_outcome`, never `status`. |
| `denied` | The request was refused. |
| `expired` | The grant lapsed unspent. |
| `requested` | A pre-cutover state only; no new request mints it. |

**`effect_outcome`** — *did the effect happen*, derived only from chain-verified evidence:

| value | meaning |
|---|---|
| `definitely_pre_effect` | Execution ended before the provider mutation boundary. Nothing happened; a later request is a fresh effect. (Spelled this way on every surface because it is the word the durable terminal record uses.) |
| `succeeded` | The effect landed. Do not retry. |
| `definitely_failed` | The effect did not land, and that is known. Do not retry the same effect. |
| `ambiguous` | The provider may have applied the effect. Only an authenticated same-key retry is safe — pass the effect handle to `run --retry-effect`. |

**`failure_class`** — *what was observed*, deliberately orthogonal to `effect_outcome`. The names
say what the next step is, not what HTTP status arrived; status codes are evidence for the
classification, never the taxonomy itself. Every class is an observation, never a conclusion —
"the outcome is unknown" is a derivation a reader makes, so it has no class of its own.

| value | meaning |
|---|---|
| `provider_auth_refused` | The provider refused the credential — expired, revoked, or lacking the access the sentence assumed. Re-scope or replace the key. Derived from `401`/`403`, and from a git upstream that demanded credentials when the daemon had attached one. |
| `provider_policy_refused` | The provider refused on a policy of its own, independently of which credential asked. Nothing about the key will help. No seam produces this today and it is not derived from a status — providers disagree about whether `403` means "this key lacks access" or "this is forbidden to everyone", and choosing between them from the number alone would be a guess. It exists so the vocabulary is total. |
| `provider_input_refused` | The provider deterministically rejected the request as submitted. The fields have to change. Derived from `400`/`422`. |
| `provider_rate_limited` | The provider is rate limiting. Back off and retry. Derived from `429`. |
| `provider_transient` | The provider failed on its own side. Retry later; the request was fine. Derived from `5xx`. |
| `transport_pre_send` | The hop never left this box, so no effect can have happened. Retry freely. |
| `transport_no_response` | Bytes went to the wire and no application-level response came back — a timeout, a reset, a truncated stream. Reconcile before retrying; never blind-retry. Which flavor it was lives in the recorded error detail beside the class, not in more classes. |
| `postcondition_mismatch` | The effect landed and its result contradicts what was approved. An operator looks; nothing is undone. |
| `protocol_drift` | The provider answered and the answer does not fit the ratified template — an unreadable body, or a declared field absent. The template is stale, not the request. |
| `local_execution_failure` | Our own execution subsystem failed, before or beside any provider answer: the vault could not be opened, egress was refused, the daemon was locked down. Fix the box. |
| `failed` | The honest residual: the effect failed and no typed signal says how. Every status outside the ranges above lands here, including `404` and `409` — a `404` means "no such object" on one provider and "your token may not see it" on another, and a `409` is a state conflict this vocabulary has no behavior for. Guessing between them is exactly what the residual prevents. |

**`effect_state`** — *what became of the effect*, on the axis the decision word cannot answer.
`decision` says what authority ruled; `status` says how far the grant's own lifecycle got; this says
whether anything happened at the far end. **Nothing stores it.** The view join derives it from
signals already recorded — the session's open and close rows, the forwarded hops and their upstream
statuses, the burning refusal's reason word, the terminal execution event — plus the clock at the
moment of the read.

| value | meaning |
|---|---|
| `ok` | The last word recorded about the grant's effect is a success: a `2xx` on the session's effect-bearing hop, or a terminal `provider_action_succeeded` on a verb the daemon ran itself. *Last* word, because a session may attempt its effect more than once — the native two-phase create is answered `400 missing files` before the create that lands. |
| `burned` | A refusal ended the session, and no effect-bearing hop is recorded as having landed. The class that ended it rides beside this as the reason word (§8.6), so the row names *which* refusal. |
| `expired_unused` | A relay window that ended having forwarded **zero** hops: the grant was spent minting authority nothing ever drove. |
| `unresolved` | A relay window that ended after forwarding hops with nothing recorded saying whether its effect landed. This is the honest gap — not a claim the effect failed, which would carry a `failure_class` instead. |

The rule that picks one, in order: the effect landed (`ok`); else a refusal ended the session
(`burned`); else the window ended with no hops (`expired_unused`) or with hops (`unresolved`).
`ok` outranks `burned` deliberately — a window whose deploy landed and which then refused a probe on
a later read hop *did* deploy, and reporting only the burn would be the same disclosure failure in
the other direction. An effect whose own response contradicted the approval is not a success: the
mismatch is recorded as a failure, and `burned` names it.

**`burned` is not "the effect did not land."** It says a refusal ended the session and nothing
recorded an effect-bearing hop landing — which includes the case where landing is genuinely
*unknown*. An effect hop that never got a response head is spent with its outcome unknown; the
native client retries; the retry is refused as `effect_already_used`; the session burns. That row
reads `— effect failed: transport_no_response →burned(effect_already_used)`, and it is the
`failure_class` beside the suffix that says what to do — reconcile, never blind-retry.

**Absence is load-bearing.** No value means the record does not determine one — a window still in
flight, a request decided and never executed, a denial that ran nothing, or an effect whose failure
the row already names with its `failure_class`. It never means an outcome was determined and
withheld.

**Termination is derived, not read.** A relay window has ended when its terminal record exists *or*
the clock is past the `expires_at` the approval set. The second half matters: a daemon that restarts
drops its live sessions from memory without closing them, and a window with no terminal record would
otherwise read as in-flight forever.

**`principal_id` / `principal_label`**: `principal_id` is the requesting principal as the daemon
stored it — the string `uid:N`, derived from the kernel's peer credentials on the socket, and covered
by the per-grant HMAC. `principal_label` is that uid's OS username resolved from the passwd database
at view-build time (e.g. `cermet-agent`). The label is absent when there is no principal, the uid
does not resolve, or the id is not a `uid:N` — never a guess.

**`integrity_ok`**: whether the row still authenticated against its per-grant HMAC when it was read.
A false value means the stored row and its authenticator disagree, and every authority claim on that
row is suppressed rather than rendered.

### 1.7 Relay hop fields

Both relay surfaces — the hops under a request's evidence, and the cross-session `cermet log --hops`
— render the same projection. It is what the *broker* wrote onto the event, never anything the agent
claimed: the method and target are what the relay decided against, and the status is what the
upstream answered.

| field | meaning |
|---|---|
| `event_type` | `relay_session_opened` (the grant was spent and the session minted), `relay_request_forwarded` (a hop passed authorization and went upstream), `relay_request_refused` (a hop was refused before the credential was attached), `relay_request_failed` (a forwarded hop did not complete), `relay_outcome_mismatch` (a forwarded hop *answered*, and the answer contradicted a field the approval froze), `relay_session_closed` (the session's terminal record). |
| `at` | When the broker chained the event (RFC3339). |
| `provider`, `action` | The verb whose grant opened the session. |
| `grant_id` | The grant the session belongs to. Operator-side only. |
| `method` | The HTTP method the native client used on this hop. |
| `target` | The request line's path and query, exactly as the native client wrote it — the string the predicate was compared against. |
| `upstream_status` | What the upstream answered on a forwarded hop. |
| `response_bytes` | How many bytes came back on a forwarded hop. |
| `undeclared_keys` | On a forwarded hop: the key names it carried — query first, then body — that its matched shape does not enumerate. An **observation**, not a verdict: the hop was authorized on its method and path and on every bind the shape declares, and this says what else rode along, so a widening decision is made on evidence. Names only, never values; capped, with a `+N more` mark when the hop carried more names than the cap. Absent when it carried none. |
| `reason` | Why a hop was refused, or why a forwarded one failed — the broker's stable reason word (see §8 for the full set). |
| `detail` | What that refusal knew beyond its reason word, in one line: the offending field or key, the frozen constraint *as it was enforced*, the value the hop offered, and — where one is computable — the remedy. Absent on the classes whose reason word is the whole fact. The reason word does not move: `detail` is additional to it, never a rewriting of it, so anything matching on `reason` keeps matching. See §8.6. |
| `effect` | Whether this hop is the grant's single effect. A relay session authorizes exactly one effect-bearing shape; every other hop is read traffic. |
| `burned` | Whether this refusal burned the session. A hop that misses the predicate or contradicts a frozen field is a session being probed, so the session is done: every later hop renders as an unknown handle. A lapsed TTL or an unknown handle burns nothing (there is nothing live to burn), and an oversized body is a transport limit rather than a probe. |
| `closed` | On the `relay_session_closed` row only: how the session ended. `burned` (a refusal ended it), `ttl` (the declared lifetime lapsed), `authority_changed` (the sentence corpus the session was minted under is no longer live), `lockdown_engaged` (the owner's revocation root was pulled), `outcome_mismatch` (the effect's own response contradicted the approval). |

In the `--hops` list rendering, `event_type` is printed as a word — `OPENED`, `HOP`, `REFUSED`,
`FAILED`, `MISMATCH`, `CLOSED` — and an event type the renderer does not know is printed verbatim
rather than guessed at. `burned` renders as the suffix `(burned the session)`; `effect` renders as
`[the grant's single effect]`; `undeclared_keys` renders after those marks as `— also carried
<names>`, in the register of an observation rather than a refusal. `detail` renders last, after all
of them: the reason word keeps its
short column where a reader and a `grep` both already find it, and the sentence follows.

A `MISMATCH` row carries the same three marks a burning `REFUSED` row does — `reason`
(`outcome_mismatch`), `burned`, and a `detail` naming the frozen field, what the approval froze, and
what the response answered instead — so `--burned` finds every hop that ended a session with one
filter. It gets its own word rather than `REFUSED` because nothing was refused: the hop was
authorized, forwarded, and *answered*, and by the time the contradiction is visible the effect has
landed. Its own row's `detection` line says exactly that, and nothing undoes it.

### 1.8 The relay session receipt

`relay_session` is the receipt the broker derives when a session closes: what the relay observed,
plus how it ended.

| field | meaning |
|---|---|
| `grant_id`, `request_id`, `provider`, `action` | The grant and request the session belonged to. |
| `closed` | How it ended — the same five values as the hop view's `closed`. |
| `opened_at`, `expires_at` | Epoch seconds: when the session was minted, and when its TTL would have lapsed. |
| `hops` | How many hops the relay forwarded. |
| `refusals` | How many hops it refused. |
| `burned` | The reason word of the refusal that burned the session, or absent if nothing burned it. |
| `burned_method`, `burned_target` | The method and target of the hop that burned it, bounded to a fixed character count. They are here so an agent can self-diagnose what it asked for without an operator reading the audit chain out of the daemon. |
| `burned_detail` | *Why* it burned — the same one-line disclosure the hop view's `detail` carries, for the refusal that ended the session. Absent when nothing burned it, or when the burning class had nothing beyond its reason word. |
| `deployment_id`, `deployment_url`, `state` | What the session's declared captures observed in the effect's own response. Capture is write-once per name: an effect's response can legitimately be observed more than once, and a re-pointable session would be a cross-hop hole with an extra step. |

### 1.9 Typed deny reasons

`deny_reason` carries the evaluator's own code beside its prose. The prose says *why* in words; the
code makes the class greppable. Rule and predicate positions in the reason are rendered as the
one-based numbers `cermet rules` prints — a rule number shown to a person always passes through that
conversion, so the number in a deny and the number you hand `rules revoke` name the same sentence.

| code | meaning |
|---|---|
| `explicit_deny` | A `deny` rule in the corpus matched this request. |
| `unresolved` | A rule matched but could not be resolved to a verdict. Unresolved never means allow. |
| `unknown_verb` | The verb itself is not in the ratified grammar — no contract resolves for it. This is a typo or a stale catalog, not an authority gap. |
| `no_matching_rule` | The grammar knows the verb; no rule in the corpus mentions it. This is the authority gap only the operator can close, and the one an unruled request actually hits. |
| `unsupported_version` | The corpus declares a rule-set version this build does not evaluate. |
| `missing_required_field` | A rule named the verb and the request omitted a field the rule requires. The reason names the field. |
| `predicate_mismatch` | A rule named the verb and one of its `where` conjuncts refused the request: in scope, out of bounds. The reason names which declared field the failing predicate constrained — the field's name, never its value. |
| `budget_exceeded` | A budget/rate aggregate cap was exhausted for its window. Produced by the mint-time ledger gate as the value-free downgrade of an otherwise-allowed aggregate rule, never by the pure evaluator. Carries the window only. |

---

## 2. The log list (`cermet log`)

The list renders newest-first, one line per request. Filters apply first; the window applies to what
survives them. Without `--all` it renders the 100 most recent rows and says so on a final line:

```
… showing the 100 most recent of 412 rows — `--all` for every one, or narrow with `--since <RFC3339>` / `--provider <name>`
```

That note names counts and commands only — never a request id and never a grant handle. An empty
result renders `No activity.` (or `No relay hops.` for `--hops`).

### 2.1 The row grammar

A row is built left to right, and every part after the verb is omitted when the stored row has
nothing to put there — there are no placeholders and no empty quotes.

```
<created_at>  <OUTCOME> <provider>.<action> <request_id> — <provenance>[: <reason>] [<[deny_code]>] [— <field>=<value> …] [— "<justification>"] [— effect failed: <class>] [— effect <disposition>] [→<effect_state>]
```

| part | meaning |
|---|---|
| `created_at` | When the request was recorded, RFC3339 — the same shape `--since` takes. |
| outcome word | `ALLOW` for an allowed request; `DENIED` for any refusal (a `deny`, `unsupported`, or `unregistered` decision, or a grant whose status landed on `denied`). Any other decision renders as its own word, upper-cased. |
| `provider.action` | The verb, dotted exactly as the corpus spells it. |
| `request_id` | The public id this row is reachable by. The list is the only door to `log <request_id>`, so the row names the id. A row that carries none renders none. |
| provenance | How the request was authorized. `— allowed by: <canonical rule text>` when the daemon stored the admitting rule — the rule's text is its identity, so the receipt reads against `CERMET.md` directly instead of naming a file position. `— allowed by a standing sentence` when a sentence allowed it but no rule text was stored (this reads what was stored; it never reconstructs a rule). `— allowed by policy` and `— approved by <approver>` identify authenticated pre-cutover rows. |
| `(corpus <8 hex>)` | The first 8 hex characters of the corpus digest the request was decided against — enough to tie a receipt to a `cermet rules` generation, short enough to read. Rendered only when the stored fingerprint is plausible hex. |
| `: <reason>` | The stored reason verbatim. Rendered for a denial (it says why) and for any allow whose rule could not be named; an allow already rendered as its sentence adds nothing here. |
| `[<code>]` | The typed deny code in brackets — the §1.9 vocabulary. It exists so `cermet log --denied \| grep predicate_mismatch` answers "what keeps getting refused for being out of bounds", which grepping prose does not do reliably. |
| `<field>=<value>` echoes | On a denial only: what was asked for. The daemon redacted these values at write time; the renderer only bounds the display width (64 characters, with an ellipsis). A string renders bare, anything else as compact JSON. |
| `"<justification>"` | The justification the agent had to supply to make the request at all. Bounded to 120 characters here for width, with the ellipsis inside the quotes; `log <request_id>` carries it whole. |
| `— effect failed: <class>` | Present only when the authorized effect failed: the `failure_class` word from §1.6. Its absence says nothing failed, not that the cause is unknown — the unknown cause is the value `failed`. |
| `— effect <disposition>` | The effect's disposition with the action it implies: `pre_effect; request a fresh effect`, `succeeded; do not retry`, `definitely_failed; do not retry`, `ambiguous; retry only with the same effect handle`. |
| `→<effect_state>` | Last on the row, and the only part that answers *and then what*: what became of the effect the decision authorized — `→ok`, `→burned(<reason>)`, `→expired_unused`, `→unresolved`. It is the §1.6 `effect_state`, derived at read time and stored nowhere. It is a **suffix**: every column before it keeps its position, so anything grepping the row today still matches. |

The suffix is the answer to a question the rest of the row cannot reach. Up to it, a request whose
relay grant burned on a refused hop, one whose window lapsed having driven nothing, and one whose
deploy landed all render the identical `ALLOW vercel.deploy <id> — allowed by: …`. `→burned(…)`
names the class that ended the session in the same reason word §8.6 and the hop log use, so one grep
matches all three surfaces.

A row with no suffix is one the record does not resolve — see §1.6 on why absence is load-bearing.
In particular a failed effect carries `— effect failed: <class>` and no suffix: the class *is* the
state, and a token repeating it would add nothing.

A row whose grant no longer authenticates against its HMAC renders as a single suppressed line
instead — no provenance, no fields, nothing reconstructed:

```
<created_at>  TAMPERED/UNTRUSTED <provider>.<action> — authorization provenance suppressed
```

Every stored string on a row passes through a one-line scrub before it is printed: control
characters and the bidi/directional formatting set (including `U+202E`) become spaces. Agent-authored
text — the justification above all — reaches an operator through this surface, and it must never be
able to move the terminal's cursor or reorder what is displayed.

### 2.2 The hop list (`cermet log --hops`)

One line per relay event, newest first, using the §1.7 vocabulary:

```
<at>  <VERB> <provider>.<action> <method> <target> — <upstream_status> (<n> bytes) — <closed> — <reason> (burned the session) [the grant's single effect] — <detail>
```

A hop line identifies itself by time, verb, and target. It never names a grant handle: `request_id`
is the one public id, the hop view has none of its own to render, and the operator-internal handle
belongs to `log <request_id>` and the audit rows.

### 2.3 Filters

| flag | meaning |
|---|---|
| `--since <RFC3339>` | Only rows at or after that instant. One shape only — an RFC3339 instant, exactly as the log prints its own timestamps. |
| `--provider <name>` | Only that provider's rows. |
| `--denied` | Only refusals. On the receipt view that means a `deny`/`unsupported`/`unregistered` decision or a `denied` status; on the hop view it means the refused and failed hops. |
| `--burned` | The same question one layer down: `--denied` finds what authority *refused*, `--burned` finds what it *allowed* and the effect layer then ended. On the receipt view it is the rows whose §1.6 `effect_state` is `burned`; on the hop view it is the burning hops themselves — the refusals that ended a session **and** the `MISMATCH` row, which `--denied` does not match because nothing was refused. This is the drill-down a `→burned(<reason>)` suffix sends a reader to. |
| `--hops` | The relay hop view instead of the grant receipt. |
| `--all` | Every row, unwindowed. |

---

## 3. Catalog

`cermet catalog` and the MCP `catalog` tool render the same projection of the same daemon-side join —
the verb table crossed with the live sentence corpus. Neither client re-decides anything; the
admitting sentence, the denying sentence, and the discoverability bit are all decided once, in the
daemon. The two surfaces differ only in the words they use to name their own next step.

There are two zooms:

| | default | `--all` (MCP: `scope: "all"`) |
|---|---|---|
| what it is | the **contract**: only the verbs a standing sentence admits right now, with their bounds | the **dictionary**: every verb this broker knows, in full, each stamped with its authority |
| per-verb detail | the fields you supply, the shape, the admitting sentence, any narrowing carve-out | all of that plus the verb class, every field with its class/origin/admissible forms, `execution_targets`, and the response contract |

### 3.1 The verb line

Default zoom:

```
<provider>.<action>(<field>:<type>, …) [<shape>] — allowed by: <sentence>
      except: <deny sentence>
```

`--all`:

```
  <provider>.<action>  [<authority stamp>] shape:<shape>
```

| part | meaning |
|---|---|
| `provider.action` | The verb, dotted exactly as a sentence spells it. |
| field list (default zoom) | Only the fields you actually supply on a request — provider-resolved fields are filtered out, because they are not yours to send. |
| `shape` | How the verb executes (§3.2). In the default zoom it is rendered bracketed and alone. |
| authority stamp | What the live corpus says about this verb, in the `--all` zoom (§3.4). |

### 3.2 `shape` — how a verb executes

| value | meaning |
|---|---|
| `http_api_call` | The daemon constructs and sends an outbound HTTP request itself, with the credential attached inside the trusted runtime. |
| `http_inline_upload` | The same execution, where a declared `free_payload` field's bytes are embedded directly in the outbound body. |
| `git_push` | Not reached through a request at all. The verb is exercised by running native `git push` / `git fetch` against a broker-wired remote; the daemon carries the stream to a pinned upstream. Branch pushes, tag pushes, and fetches all carry this shape — which ref namespace a verb moves is its own vocabulary, not a second shape. Every entry with this shape prints the wiring command beside it: `git remote set-url origin cermet::github/<owner>/<repo>`. |
| `relay` | The verb mints a scoped session and credentials a native CLI's *own* outbound requests through a loopback relay. No provider call happens at request or execute time — the effect is the session (§1.3). |

A verb whose shape the daemon did not report renders as `shape:unknown` in the default zoom, and
omits the token entirely in `--all`. That is version tolerance, not a value.

### 3.3 Field annotations

In the `--all` zoom each field renders as:

```
<name>[?]:<type> (<class>, <origin>) [<forms>]
```

For example:

```
charge:str (identity, agent_request) [= in]
amount:int (side_effect, agent_request) [= in <= >= budget]
secret_token?:str (secret, agent_request) [none]
```

**`?`** marks the field optional. Its absence marks it required. An absent optional field freezes as
absence at request time; there is no execute-time fill.

**`type`**: `str`, `int`, or `bool`.

**`class`** — what kind of authority the field carries.

| value | meaning |
|---|---|
| `identity` | Identifies the resource being acted on. An `allow` rule must pin it exactly (to one scalar, or to an allowlist). |
| `side_effect` | Authority-relevant configuration that is not identity. An allow must either pin it exactly or bound it with `<=`, `>=`, or `in`. Quantity fields are this class, which is what makes them budgetable. |
| `free_payload` | Varies per request and carries no authority. It rides freely; no rule needs to bind it. It is still frozen in the request, audited verbatim, and covered by the grant. |
| `secret` | An agent-supplied secret. Never returned, never audited raw, and scrubbed out of every retained artifact. No sentence may reference one, which is why its form list is always `[none]`. |
| `read_filter` | A bounded filter on a read-only query verb — side-effect free. |

**`origin`** — who supplies the value.

| value | meaning |
|---|---|
| `agent_request` | You supply it on the request. |
| `provider_resolved` | The daemon fills it from the provider's own response, after the fact, as a declared evidence output. You never supply it, and the default zoom omits it from the field list for that reason. |
| `credential_derived` | The daemon fills it from the vaulted credential's own shape, before the sentence judges the request — Stripe's `mode` (`test` / `live`) is derived from the key's prefix. You never supply it (a request that carries it is refused), it never reaches the provider, and the default zoom omits it. A sentence may still pin it, which is the point: `mode = "test"` bounds a rule to the test book. With no credential connected there is nothing to derive, so the field is absent and a sentence pinning it admits nothing. |

**`forms`** — the index of ways a sentence is *allowed* to constrain this field, printed in a fixed
order. It is the WHERE-index: it tells an operator writing a rule what predicates that rule may use.

| token | meaning |
|---|---|
| `=` | A sentence may pin the field to one exact scalar. |
| `in` | A sentence may pin it to a set of scalars. |
| `<=` | A sentence may bound this integer field above. |
| `>=` | A sentence may bound it below. |
| `budget` | A rule-level `budget <field> <n> per <window>` aggregate may sum this field. Listed only when the field is budget-eligible (required, integer, side-effect, bounded) *and* the daemon's temporal clauses are enabled — the index never teaches a form the corpus would refuse. |
| `[none]` | The literal printed when the list is empty: no sentence may constrain this field at all. |

`rate` is never a per-field form. It is a verb-level admission meter and appears only in the legend
and in rule text.

### 3.4 The authority stamp

Four values, and only the first may be read as permission.

| stamp | meaning |
|---|---|
| `allowed now` | The broker has the verb loaded *and* the live corpus admits at least one concrete completion of it right now. This is a real evaluation, not a text match: it asks whether some exact, contract-valid request shape evaluates to allow. |
| `denied — not requestable` | A standing `deny` sentence explicitly selects this verb. Settled — an explicit deny is not a widening candidate, so there is nothing to propose. |
| `not available on this broker — a request denies` | A standing `allow` sentence selects the verb, but this broker does not have its template loaded. A request would still deny — for lack of the verb, not for lack of authority. |
| `no standing sentence — propose one` | The true authority gap: nothing admits it and nothing denies it. This is the one case where relaying a widening ask to whoever holds authority is the right move. |

In the `--all` zoom the same four cases also render as prose beneath the verb:

```
allowed by: <sentence>
also: <sentence>                                        (second and later admitting rules)
except: <deny sentence>                                 (each narrowing carve-out)
denied by: <sentence> — do not request this; an explicit deny is not a widening candidate
a standing rule selects this verb (<sentence>), but it is not available on this broker right now — a request will deny
no standing rule — a request will deny with a widening suggestion for the operator
```

Rules are named by their canonical text, never by number. The text is the rule's identity, so a
catalog line reads against `CERMET.md` directly.

### 3.5 The bounds line

Where a sentence appears — `allowed by:`, `also:`, `except:`, `denied by:` — it is printed in
canonical form, which is exactly the argument `cermet rules allow` takes:

```
<allow|deny> <provider>.<action>
<allow|deny> <provider>.<action> where <field> = <scalar>
                                       <field> in {v1, v2, …}
                                       <field> <= <int>
                                       <field> >= <int>
                                       <cond> and <cond> …
                                       budget <field> <n> per <hour|day>
                                       budget <n> per <hour|day>
                                       rate <n> per <hour|day>
```

`=` and `in` pin a field; `<=` and `>=` bound an integer field. `budget <field>` sums that field
against a rolling window and is enforced as a debit reserved at mint time; `budget` with no field
counts calls instead; `rate` limits how many times the verb may be *admitted* per window.

### 3.6 `execution_targets`

`--all` only:

```
    execution_targets: <field>, <field>
```

The fields an `allow` rule must pin for this verb to be admissible at all — the resource the grant
gets scoped to. An empty list means the verb has no scopable target.

### 3.7 The response line

`--all` only:

```
    response: returns: <returns> | stored: <retention> | errors: <errors>
```

| field | value | meaning |
|---|---|---|
| `returns` | `verbatim` | The provider's own response body, unedited. |
| | `receipt` | There is no provider body to return. The response is a broker-authored record: for a git verb the exit status and refusal sentence, for a relay verb the session handle, relay address, invocation, and deadline. |
| `stored` | `full` | The whole response is durably retained as a fetchable artifact. This is the default for HTTP verbs — and it means the artifact holds whatever the provider sent, including any personal data or bearer values in that body. |
| | `none` | Nothing is retained. Always the case for git and relay verbs (there is no provider body), and the deliberate floor for verbs whose responses should not be kept. |
| `errors` | `status_and_body` | An error carries the HTTP status and the body. |
| | `status_and_body_or_verdict` | The verb has a GraphQL step, which can fail at HTTP 200; the error carries a classified verdict beside the untouched body. |
| | `refusal` | Git verbs: the executor's refusal sentence. |
| | `receipt` | Relay verbs: the same receipt shape, carrying the refusal. |

### 3.8 The legends

The `--all` zoom closes with two fixed blocks, printed once rather than per verb:

- `fields:` — explains the `?` optional marker and the bracket grammar. Its `budget` / `rate`
  sentence appears only when temporal clauses are actually live in this frame, so the legend never
  teaches a form the corpus would refuse.
- `response:` — explains the `returns` / `stored` / `errors` vocabulary, then points at the default
  zoom and at what to do with an unruled verb.

---

## 4. The `doc` noun

`CERMET.md` is the repository's managed authority document. `cermet doc` is the flow that keeps it,
its own pin, and the daemon's live corpus in agreement: `doc check --fix` → `doc diff` → `doc apply`.

Three digests are compared throughout, and almost every field on this surface is one of them or a
verdict about their relationship.

| term | meaning |
|---|---|
| **candidate** | `sha256:<hex>` of the document's current fenced `cermet` body, canonicalized by the daemon. It is what this document would commit right now. |
| **marker** | The pin written inside the document, on its `Pinned authority:` line — either `none` or `sha256:<hex>`. It records what body this document last asserted was live, independently of what its body says today. |
| **live** | The corpus the daemon is currently serving, read from its own record: `sha256:<hex>` or `none`. |

The document itself is discovered by ascending from the working directory to the first ancestor
holding a `.git` marker; `CERMET.md` must live in exactly that directory. Everything outside the
managed `cermet:authority:v1` block is untouched prose.

### 4.1 `doc status`

Two lines, answering two independent questions — what the daemon is serving, and what is in the
directory you are standing in:

```
active_profile: designer 4b8004bd4e13
directory_file: CERMET.md 4b8004bd4e13
```

`--json` prints the same two values, plus `lockdown`, as a JSON object.

| field | meaning |
|---|---|
| `active_profile` | The DAEMON's live corpus — one global answer, the same from every directory on the box. The name is the FIRST stored profile whose body is exactly that corpus, joined at read time (`(unnamed)` when no stored profile matches), followed by the corpus digest. When nothing is being served it reads `none` and says why: no corpus has been applied, a stored corpus is not being served, the record is unreadable, or the daemon could not be asked. |
| `directory_file` | The `CERMET.md` reachable from this directory, and the digest of the body it would commit. With no such file it reads `none — no CERMET.md found from this directory`, which is an absence, not a fault. A file that exists but yields no candidate says so and points at `cermet doc check`. |
| `pin` | Printed ONLY when the document's body is already live under a pin naming an older corpus (the `marker_stale` drift state, §4.2). That is the one nonzero state the two digest lines cannot show — the body matches, so both prefixes agree and the surface would otherwise read as full agreement while exiting `1`, and `doc diff` would add only `rules: unchanged`. The line names the condition and the remedy: `pin: stale — this file's body is already live; its pin names an older corpus, and cermet doc apply repairs the pin without changing a rule`. |
| `lockdown` | The owner-lockdown latch: `clear`, `engaged`, or `unknown`. The TEXT form prints this line only while the latch is ENGAGED, because an engaged latch means the corpus named above is authorizing nothing — reporting the two lines alone would describe a box you are not on. `--json` always carries it. Only `cermet owner lockdown` sets it. |

Both digests are truncated to the same 12 hex characters on purpose: equal prefixes mean this
directory's file is what the daemon is serving, and unequal prefixes mean it is not. The drift
verdict itself is not printed — the EXIT CODE carries it (§4.2), and `doc diff` shows the change.

### 4.2 `state` — the drift verdict

The verdict is a pure function of how candidate, marker, and live relate. `doc status` and `doc
diff` report it as their EXIT CODE; the mutating commands (`doc check --init`, `doc export`,
`doc apply`) print it as a `state:` line on their own receipts.

| value | exit | meaning |
|---|---|---|
| `aligned` | 0 | candidate == marker == live. Document, its own pin, and the served corpus all agree. |
| `aligned_no_authority` | 0 | The untouched baseline `doc check --init` creates: empty body, `none` marker, absent live. Aligned, with nothing to align. |
| `unapplied_document` | 1 | marker == live, candidate differs. You edited the body and have not applied it: the pin still names what is live, the file's current text does not. |
| `unexported_live` | 1 | candidate == marker, live differs. The document and its pin agree with each other, and the daemon is serving something else. `doc export` would overwrite the document with live. |
| `marker_stale` | 1 | candidate == live, marker differs. The body already matches what is live; the pin was not updated to say so. |
| `diverged` | 1 | Candidate, marker, and live are three different digests. |
| `repo_missing` | 1 | The repository exists; `CERMET.md` does not. |
| `repo_invalid` | 2 | `CERMET.md` exists and cannot be parsed or read safely, or the daemon refused its body as semantically invalid. |
| `dataplane_unserved` | 2 | The live record exists and is not being enforced, or a served snapshot failed its own re-preparation check. |
| `dataplane_corrupt` | 2 | The live record's bytes fail integrity checks. |
| `dataplane_unknown` | 2 | The daemon could not be asked — for the live corpus, or for the candidate's preparation. Deliberately not reported as document drift: an unreachable daemon must never fabricate a verdict about your file. |

`doc status --json` is the one place a usage error does not go to stderr as prose. When the first
argument is `doc` and the CLI fails before it can dispatch, it prints a parseable failure object
instead, so a scripted caller always gets JSON on stdout. Nothing was read, and both lines say so:

```json
{"active_profile":"none — the daemon could not be asked","directory_file":"none — the daemon could not be asked","lockdown":"unknown"}
```

### 4.3 `doc check` and `doc check --fix`

```
candidate: sha256:<hex>
canonical: yes|no
rules: <n>
action: run cermet doc check --fix        (only when the body is not canonical)
```

| field | meaning |
|---|---|
| `canonical` | Whether the document's raw fenced-body bytes are byte-identical to what the daemon's canonicalizer prints for that body. A document can be semantically valid and not canonical — extra whitespace, comments, unnormalized ordering. `--fix` rewrites the fence to canonical form without touching the marker. |

`rules` is the number of rule statements the canonical corpus parses to. Exit is 0 when canonical,
1 when not.

`--fix` rewrites the fence. When nothing needed doing it prints `write: not needed`; otherwise it
prints the publication block (§4.6).

### 4.4 `doc check --init`

Creates the baseline `CERMET.md`.

```
initialized: <root>/CERMET.md
<publication block>
state: <state>
lockdown: <lockdown>
live_changed: yes|no|unknown
```

| field | meaning |
|---|---|
| `initialized` | The path of the `CERMET.md` this run created. |
| `live_changed` | Compares the daemon's corpus snapshot taken before the operation against the one taken after: `no`, `yes`, or `unknown` when the closing snapshot could not be read. It is on every mutating `doc` command for the same reason — an operation that touched only the file should be able to say so. |

### 4.5 `doc diff`

The two lines from `doc status`, then either `rules: unchanged` or a unified diff:

```
--- live
+++ document
@@ -a,b +c,d @@
```

The orientation is fixed and always means the same thing: `-` is the authority served right now, `+`
is what you are proposing. Reading it the other way describes reverting your own edit. Set-valued
rules get their own stanza per changed occurrence, because a one-word membership change inside a
long set is invisible in a line diff:

```
set stripe.support (occurrence 1):
- lookup_customer
+ credit_balance
```

`occurrence <n>` counts which occurrence of that set selector in the corpus changed, one-based.

### 4.6 The publication block

Written by every command that rewrites the document (`doc check --fix`, `doc export`,
`doc check --init`). It reports what happened to the file itself, separately from what happened to
authority — a clean commit followed by a failed file write is a real state, and it is not the same
as either half failing.

| field | values | meaning |
|---|---|---|
| `write` | `created` \| `replaced` \| `interfered` | Whether the file was newly created, safely replaced, or the replacement completed without being provably clean. |
| `durability` | `durable` \| `uncertain` \| `not_claimed` | Whether the write was flushed to stable storage. `not_claimed` means no durability claim is being made, not that it failed. |
| `mode` | `applied` \| `failed` \| `not_claimed` | Whether the intended content change was applied. |
| `interference` | `yes` \| `no` | Whether something else touched the file during the operation. |
| `final_file` | `intended` \| `changed` \| `missing` \| `unreadable` | What is on disk now, re-read after the write: the content that was intended, something else, nothing, or bytes that could not be read back. |

### 4.7 `doc export`

Overwrites the document with what is live.

```
exported_live: sha256:<hex>|none
prior_marker: <the marker the document carried before this write>
<publication block>
state: <state>
lockdown: <lockdown>
live_changed: yes|no|unknown
```

| field | meaning |
|---|---|
| `exported_live` | The digest of the live corpus that was written into the document, or `none` when nothing is live. |
| `prior_marker` | The marker the document carried *before* this write — what its pin used to say, kept on the receipt so the overwrite is reversible knowledge rather than a silent replacement. |

Export refuses rather than discarding unapplied local edits — edits whose candidate matches neither
the document's own marker nor live:

```
export: unapplied document edits preserved
action: rerun with --replace-draft
state: <state>
lockdown: <lockdown>
```

### 4.8 `doc apply` — the review block

`doc apply` is presence-gated and shows the whole transition before asking for confirmation.

```
Apply this exact CERMET.md authority corpus?
WARNING: <one of the acknowledgement warnings, when a flag forced past a guardrail>
repository: <repository root path>
git_branch: <git symbolic-ref --short HEAD, or unknown>
git_head: <git rev-parse HEAD, or unknown>
old_live: <baseline identity>
new_live: <candidate digest>
rules: <n>
<the transition diff, and any set diffs>
```

| field | meaning |
|---|---|
| `repository` | The repository root whose `CERMET.md` is being applied, rendered one-line-safe. |
| `git_branch`, `git_head` | The branch and commit the document is being applied from, read from git itself. `unknown` when git cannot answer — the apply is not blocked on it; the review just says so. |
| `old_live` | The identity of the baseline being replaced: `sha256:<hex>`, `none` (nothing was live), `unserved-record:sha256:<hex>`, or `corrupt-record:sha256:<hex>`. The last two spell out that the baseline is a record the daemon is not serving. |
| `new_live` | The candidate digest that will become live. |
| `rules` | How many rules the candidate carries. |

At most one `WARNING:` line appears, and only when a flag is carrying the operation past a guardrail
it would otherwise refuse at: `--recover` against an unserved or corrupt record, or `--replace-live`
against a live generation the marker does not name.

The review diff prints every old line as `-` and every new line as `+` rather than the minimal diff
`doc diff` computes. A confirmation prompt for a total authority replacement should show the whole
of both sides.

The presence prompt that follows carries only identity, never content:

```
Apply Cermet authority <old_live> -> <new_live> (<n> rules)
```

Applying a `CERMET_<name>.md` profile document uses the same ceremony with a different header
(`Apply this exact authority corpus, replacing everything live?`) and two extra fields — `preset`
(the profile name) and `source` (the file path it came from, or `stored profile` when
`cermet preset <name>` invoked it). A profile document carries no pin, so it has no marker fields.

### 4.9 `doc apply` — the receipt

```
result: <result>
commit_resolution: <resolution>
receipt: sentence_authority_transition
old_live: <baseline identity>
new_live: <candidate digest>
rules: <n>
occurrence_id: <hex>
acceptance_path: presence
marker_update: updated|interfered|preserved_concurrent_edit
state: <state>
lockdown: <lockdown>
```

| field | meaning |
|---|---|
| `result` | What the whole operation amounts to (§4.10). |
| `commit_resolution` | What the *authority commit itself* resolved to, independently of whether the file's pin was then updated. `result` and `commit_resolution` can legitimately disagree — a commit that landed cleanly followed by a marker rewrite that could not be confirmed is `committed` here and `committed_but_unreconciled` above — and both are printed so the two halves are separable. |
| `receipt` | `sentence_authority_transition` — the class of audit receipt this operation wrote. |
| `occurrence_id` | The id of this specific authority transition, stamped at staging and carried into the audit chain. It is what identifies *this* commit if you have to reconcile one by hand. |
| `acceptance_path` | How the change was accepted. `presence` — a human presence ceremony on this box. |
| `marker_update` | What happened to the document's pin after the commit: `updated` (rewritten cleanly), `interfered` (the write returned but was not provably clean), `preserved_concurrent_edit` (the guarded replace refused because the file changed underneath, so the pin was left alone rather than clobbering someone's edit), `not_attempted` (the commit did not reach that step). |
| `presence` | Printed by the two apply paths that commit nothing, always as `not_required`: no authority moved, so no human act was asked for. |
| `authority_mutation` | Printed by the marker-repair path, always as `none`: the pin was re-stamped and the live corpus was not touched. |

Two apply paths need no commit at all and say so:

```
result: no_change            candidate already equals live and the marker already matches
presence: not_required
```

```
result: marker_repaired      candidate already equals live; only the stale pin was re-stamped
presence: not_required
authority_mutation: none
```

### 4.10 `result` — every value

| value | meaning |
|---|---|
| `no_change` | Candidate already equals live and the marker already names it. Nothing was committed and no presence was required. |
| `marker_repaired` | Candidate already equals live but the pin was stale. Only the pin was re-stamped; no authority changed. |
| `marker_repair_unreconciled` | The same repair, where the file rewrite could not be confirmed clean. |
| `committed` | The corpus was committed and is live, and the document is now aligned. |
| `already_committed` | The daemon reports this exact generation was already live — the commit was idempotent. |
| `committed_after_reconciliation` | The commit acknowledgement was lost, and a bounded reconciliation poll independently found this exact occurrence live. The commit landed. |
| `committed_but_unreconciled` | The commit landed; the document did not end up aligned — the marker rewrite did not complete cleanly, or the final live state could not be read back. Authority is correct; the file needs another pass. |
| `committed_but_superseded` | The commit landed and another generation won before the marker could be updated. |
| `committed_but_preset_not_stored` | Profile documents only: the corpus committed and is live, but the second write that stores it under its name could not be confirmed. The accepted authority needs nothing redone — re-run the apply to store the profile, and the corpus it installs is the one already live. |
| `stale_stage_conflict` | The exact-generation compare-and-set refused; a concurrent winner remains live. Nothing was committed. |
| `commit_outcome_unknown` | The transaction is genuinely unresolved after bounded reconciliation. The receipt prints the `staging_token` and `occurrence_id` and says to preserve them and not to repeat the apply or its presence ceremony — repeating it is how one accepted change becomes two. |

---

## 5. `cermet rules`

### 5.1 The listing

`cermet rules` prints the live corpus in canonical form, one numbered line per rule, or
`No rules configured.` when the corpus is empty.

```
1. github.read_repo where owner = "acme"
2. deny github.read_repo where name = "secrets"
```

| part | meaning |
|---|---|
| the number | The rule's one-based position in the corpus, in stored order. It is exactly the number `rules revoke <n>` and `rules refresh <n>` take, and exactly the number a deny reason's prose reports. |
| the rule text | The rule's canonical printed form, with a leading `allow ` stripped. A `deny` keeps its keyword — eliding it would print a narrowing rule as a widening one. |

The row text is precisely the argument `cermet rules allow` accepts. That round trip is deliberate:
what you read out of the list is what you can paste back in.

### 5.2 The mutation receipt

`rules allow`, `rules revoke`, and `rules refresh` are human-only and presence-gated. Each prints a
result line and then the same receipt block.

```
added rule #<n>: <canonical rule>
receipt_state: known
live: sha256:<hex>
occurrence_id: <hex>
acceptance_path: presence
lockdown: clear
document_sync: <state>
```

The result line's verb is `added` / `revoked` on a clean mutation. When the mutation committed but
the exact generation is not the observed final served authority it reads
`add committed but is not final for proposed` (and the revoke equivalent); when the outcome could not
be established at all it reads `add outcome unknown for proposed`. The CLI exits non-zero in both of
those cases.

| field | meaning |
|---|---|
| `receipt_state` | `known` — the client observed an authority status whose corpus text, digest, occurrence, and rule count all exactly match the generation it staged. `unknown` — the bounded reconciliation loop finished without ever observing that exact match, so the mutation may or may not have taken effect. |
| `live:` / `committed:` | The same digest under two labels. `live:` means the exact generation was observed on a *served* record — the daemon is actually enforcing it. `committed:` means the flip happened but the observed record was not being served, or another generation superseded it. The digest is the canonical digest of the corpus the client asked to commit, not a value echoed back by the daemon. |
| `candidate:` | Replaces the digest line when `receipt_state` is `unknown`: the digest that *was* staged, whose fate is undetermined. |
| `occurrence_id` | The durable id of this specific commit attempt, derived deterministically from the staging token. The audit chain deduplicates transitions on it, which is what makes a retried commit idempotent rather than a second change. |
| `staging_token` | Printed only in the `unknown` case, because it is the thing the operator needs in order to *finish* the transaction rather than start a new one. The receipt says so explicitly: preserve the token and occurrence, and do not repeat the command. |
| `acceptance_path` | How the mutation was accepted. `presence` — a human presence ceremony on this box. |
| `lockdown` | The owner-lockdown latch as observed after the mutation: `clear`, `engaged`, or `unknown` (no final status was ever read). |
| `document_sync` | What this mutation did to the repository's `CERMET.md`, since a `rules allow` moves live authority out from under the document (§5.3). |

Two warning lines may follow the block:

```
WARNING: this transaction committed, but that exact occurrence is not the observed final served authority.
WARNING: owner lockdown is engaged; execution remains disabled.
```

### 5.3 `document_sync`

A `rules` mutation changes the live corpus without touching `CERMET.md`, so the receipt reports what
that did to the document's alignment.

| value | meaning |
|---|---|
| any drift state (`aligned`, `unexported_live`, …) | The document's state after the mutation, using the §4.2 vocabulary. `unexported_live` is the ordinary result: the daemon moved ahead of the file, and `doc export` catches it up. |
| `required` | The state could not be computed against a trustworthy baseline, so it refuses to name one. This is returned when the mutation's own final status was never observed, when the document is provider-disabled, when the status read after the observation failed, or when live authority, the repository root, or `CERMET.md` itself changed during the observation window. It means "go look", not "something is wrong". |
| `no CERMET.md found from this directory` | There is no repository document to be in sync with. |
| `sentence dataplane unavailable` | The daemon could not be asked to prepare the document for comparison. |
| `document state not observed` | No document observer was attached to this mutation at all. |

### 5.4 `rules refresh <n>`

`refresh` rebinds one rule's pinned set selector to the resolver's current expansion of that same
set. It refuses if the rule at `<n>` is a plain verb rule or an unpinned set.

```
refresh Cermet rule #<n> set <provider>.<set>
old digest: <hex>
new digest: <hex>
added members:
  + <member>
removed members:
  - <member>
```

| part | meaning |
|---|---|
| `old digest`, `new digest` | The pinned expansion digest before and after. These are raw hex, without the `sha256:` prefix the receipt block's digest lines carry. |
| added / removed members | Action names that entered or left the set's expansion. `(none)` when a side is empty. |

When the two digests are equal there is nothing to rebind: the summary prints alone, no
compare-and-swap runs, and no mutation receipt follows. When they differ, the full receipt block from
§5.2 is appended, and the summary text doubles as the presence prompt's stated reason.

---

## 6. `cermet preset`

A preset is a whole stored corpus under an opaque name. The name means nothing to the broker — it is
a key into a table, unconnected to any repository. The only way one is written is a `doc apply` of a
`CERMET_<name>.md` document, which stores the committed body under `<name>` in the same transaction;
there is no standalone create.

### 6.1 `preset list`

```
PRESET    RULES  UPDATED
builder   14     2026-08-19T09:12:44Z  ● live
designer  6      2026-08-18T17:03:10Z
```

| column | meaning |
|---|---|
| `PRESET` | The stored name. Every printed name is sanitized on the way out — anything outside letters, digits, `_`, and `-` becomes `?`, over-long names are truncated, and an empty one renders `(empty)`. Stored names are already validated; the sanitizer is applied unconditionally so that stays true for names a caller merely typed. |
| `RULES` | How many rules that stored corpus holds. |
| `UPDATED` | When the row was last written, RFC3339, set daemon-side at write time. |
| `● live` | Marks the FIRST stored profile whose body matches the corpus the daemon is serving right now — the same read-time join `doc status` names on its `active_profile` line, so two profiles storing identical bodies put the mark on one of them, not both. No row carries it when the live corpus is not one of these bodies. Nothing records it: a profile is live exactly while its body is being served, so applying another profile moves the mark with no write to this table. |

An empty store says so and names the one way to write one:

```
No authority profiles are stored.
Write one by applying a preset document: `cermet doc apply CERMET_<name>.md`.
```

### 6.2 `preset <name>` — applying a profile

Installing a profile replaces the entire live corpus: a profile is a whole corpus, so every rule it
does not carry is gone. It runs the same ceremony `doc apply` runs — review, terminal confirmation,
presence — and prints the same review and receipt fields as §4.8 and §4.9, with two differences:

| field | meaning |
|---|---|
| `preset` | The profile's stored name. |
| `source` | Where the body came from: `stored profile` when `cermet preset <name>` invoked it, or the file path when `doc apply CERMET_<name>.md` did. |
| `live_state` | What the daemon's own record is doing after the flip: `absent` (no corpus was ever committed), `served` (the daemon is enforcing this corpus), `unserved` (a record exists and the enforcement gate is down — the crash-recovery boundary), `corrupt` (a record exists and its bytes fail integrity checks; the bytes are never exposed), `unknown` (the daemon could not be asked). |

There is no document and no pin here, so there is no `marker_update` and no `state`. The receipt
reports `live_state` and `lockdown` instead.

### 6.3 `preset export <name> [<path>]`

```
exported: <path>
preset: <name>
rules: <n>
apply it anywhere with: cermet doc apply <path>
```

| field | meaning |
|---|---|
| `exported` | The path actually written. |
| `preset` | The profile that was exported. |
| `rules` | How many rules its stored corpus holds. |

Export always writes the document with its marker set to `none`. A profile is derived from no
particular generation, so it is unpinned, and an unpinned document is appliable on any box.

Given a directory, export writes `CERMET_<name>.md` inside it; given a file path it writes exactly
that path. It refuses to clobber an existing file without `--force`.

Two names are reserved and cannot be stored or exported: `list` and `export`. They are `preset`'s own
subcommands, and a profile stored under one would be unreachable vocabulary.

---

## 7. Operational status surfaces

### 7.1 `cermet check`

The read-only plumbing checklist. It mutates nothing, and it exits 0 when every row passes, 1 when
any row is a gap, and 2 when an explicitly named provider is not one it knows.

```
plumbing
  ✓ cermetd            serving on ctl.sock — 3 provider(s) connected
  ✓ build              cermet and cermetd are 0.1.0+<commit>
  ✓ custody            systemd-host — persistent Cermet files do not contain the plaintext key; …
  ✓ git-remote-cermet  /opt/cermet/bin/git-remote-cermet
  ✓ git plane          git.sock at /var/cermetd-agents/git.sock; uid 501 (you): admitted (approver_uid)
  ✓ agent bridge       /var/cermetd-agents/agent.sock

stale engines
  ✓ stale engines      no cermet process or MCP registration from another install
```

Every row is `  <mark> <label> <detail>`, optionally followed by an indented `→ <remedy>` line. The
mark vocabulary is three-valued:

| mark | meaning |
|---|---|
| `✓` | The probe succeeded; this part of the plumbing is healthy. |
| `✗` | A real fault. Always paired with a remedy line, and it is what makes the command exit 1. |
| `·` | Neither health nor fault: something could not be asked, or a non-fault fact worth stating (a version behind, a feature off by choice). There is no separate "skip" token — an unanswerable probe is this. |

**The `plumbing` section**, in the order it prints:

| row | what it reports |
|---|---|
| `cermetd` | Whether the daemon answers on `ctl.sock`, and how many providers are connected. A failure carries the transport error's own diagnosis, and the remedy is the platform's service-start command unless the transport supplied a more specific one. |
| `build` | Whether this CLI and the running daemon are the same build. A daemon that reports no build id reads as `unknown` and counts as skew — the row states both ids and says one of the two is stale. A daemon that cannot be reached leaves this informational, naming only this CLI's build. |
| `custody` | The vault-key custody rung and its limitation, printed verbatim as the daemon reports it (§7.2). Never a fault: every rung is supported. |
| `git-remote-cermet` | Where the git remote helper resolves on this shell's `PATH`. When it is installed but not on this shell's path, the row says so and names the registration file that would have put it there — a shell older than the install is the usual cause. |
| `git plane` | Whether `git.sock` is bound and whether *this caller's uid* is admitted to it, in the daemon's own words. The socket is world-bindable and the daemon applies its own kernel-attested peer-credential gate afterward, so the question is asked of the daemon rather than of the file mode. |
| `update check` | Whether the daily update check is on, when it last ran, and what it saw (§7.4). An available update is never a fault — only a broken read mechanism is. |
| `agent bridge` | Whether the agent socket exists, so the MCP bridge has something to speak to. |

**The `stale engines` section** reports cermet processes and MCP registrations left over from another
install. A process outlives the unlink of its own binary, so an upgrade can leave one serving its own
authority.

| row | meaning |
|---|---|
| `stale engine` | A running cermet process from another install that serves its *own* credentials and rules. The remedy is to stop it. |
| `stale agent client` | A running keyless client on the old binary. Authority stays with the daemon, so this is not an authority problem — the remedy is to restart the agent session that owns it, never to kill it, because killing it severs that session's tools. |
| `stale MCP server` | A registration that launches a cermet outside the install directory. The remedy is `cermet mcp install` and then restarting the agent session. |
| `probe` | An informational note when a probe itself could not answer. |

Each stale row names why it is stale: `retired artifact` (its executable is a path this build
retires), `binary deleted` (its executable has been unlinked — it is running code no longer on disk),
`outside <install dir>` (a cermet binary this install did not publish), or
`superseded by the published binary` (it runs a different executable object than the one now
published at the install path — the upgrade landed, this process did not get it).

**Provider sections** print once per connected provider, or once for a provider named explicitly:

| row | meaning |
|---|---|
| `credential` | Whether the vault holds a credential for this provider, with its opaque reference and the date it was added. A gap means the broker has no token to spend for it. |
| `repo wiring` | GitHub only, and only inside a git work tree: whether this repository's remote reaches GitHub through the broker. Otherwise it names the exact `git remote set-url` line that would wire it. |
| `vercel CLI` | Vercel only: where the native CLI resolves on `PATH`. A relay verb's invocation is run with it. |
| `relay` | Vercel only: how many relay hops this box has recorded and when the last one was. |
| `API version` | Stripe only: the API version this build pins. A compile-time constant, not a live probe. |
| `standing rules` | How many rules in the live corpus mention this provider's verbs. |

### 7.2 Custody rungs

The custody rung is the mechanism holding the vault key on this box. `cermet setup` picks the
strongest one the machine can actually carry, declares it in `/etc/cermetd/config.toml` as
`custody_profile`, and the daemon reads that key to decide where its key comes from. It is reported
in three places — the setup summary, `cermet check`, and the config file — and always with its
limitation attached.

| value | what holds the key | what it does not protect |
|---|---|---|
| `systemd-tpm2+host` | A systemd credential bound to this OS installation *and* this box's TPM2 device. | The encrypted key is bound to this OS installation and TPM2 device. |
| `systemd-host` | A systemd credential bound to this OS installation's host secret. | Persistent Cermet files do not contain the plaintext key; full host-image disclosure may permit recovery. |
| `file-protected` | A `cermet`-owned `0600` key file, kernel-`EACCES` to every other uid. | Does not protect the vault key from disk snapshots or backups. |

An unrecognized spelling in the config file is a fail-closed refusal naming the three this build
implements. A development or embedded daemon has no service-key rung and says so rather than
claiming one.

### 7.3 `cermet setup`

Every line is prefixed `[cermet-setup] `. Two step words carry the whole progress vocabulary:

| word | meaning |
|---|---|
| `ok    <step>: <detail>` | The box was already converged on this step. Nothing changed. |
| `fixed <step>: <detail>` | This run changed something. |

Non-fatal problems print as `WARN <area>: <error>`, and narration that is neither a step nor a fault
prints as `NOTE <area>: …`.

The steps are the install's own units of work: `preflight`, the account creation (`accounts` on
macOS; the `group` and `user` steps on Linux), `config`, `runtime dirs`, the service units
(`systemd` / `launchd`), `service`, `binary`, `master key`, `credential transport`, `custody`,
`lockdown`, `cleanup`, `vendor reset`, and `update check`.

When no systemd-credential rung is available, the descent is narrated rather than silently taken:

```
[cermet-setup] NOTE custody: no systemd-credential custody rung is available on this box (<reason>)
[cermet-setup]      taking the strongest rung that works here: file-protected — <limitation>
```

The closing summary is re-probed from the box, never a restatement of what the run intended:

| line | meaning |
|---|---|
| `✓ broker running (cermetd, starts at boot)` / `✗ broker not running` | Whether the daemon answers now. |
| `✓ credential vault ready (custody: <rung>)` + the limitation on its own line | Whether the key artifact exists, and which rung holds it. |
| `✓ git integration ready (git-remote-cermet)` / `✗ git integration missing` | Whether the git remote helper is published. |
| `update checks: on — …` / `update checks: off — …` | The daily-check setting as recorded for the approver. |
| `next: cermet connect github   (or vercel, stripe)` | Printed only when all three of the above passed. |
| `note: <group> membership reaches existing sessions after a re-log-in` | Printed when the approvers group was just changed — group membership does not reach a shell that already exists. |

If the box carries survivors from a prior install, a `cutover:` block lists them with the same
vocabulary as `cermet check`'s stale-engine rows, and names the command that clears each class.

### 7.4 `cermet update`

`update` is the only command that contacts anything of ours, and what it contacts is GitHub
Releases. Two parameterless, unauthenticated requests: the project's latest release, and — only if
that release is installable for this box — that release's own `SHA256SUMS` and artifact. The user
agent names the release, never the install.

`--check` prints the plan and stops:

| plan | text |
|---|---|
| up to date | `cermet <version> is current — <origin> publishes <version>.` |
| available | `cermet <current> — <origin> publishes <version>.` then `artifact <file>`, `sha256 <hex>`, and the command to install it. |
| nothing for this box | `<origin> publishes <version>, with no <package\|tarball> for <target>.` followed by `nothing was published; the installed binary is untouched.` |

Versions are compared by equality of the version string, not by semantic ordering: the question is
"is the origin publishing something other than what is running", not "is it newer".

| field | meaning |
|---|---|
| `artifact` | The release asset filename resolved for this box's target and install channel. |
| `sha256` | That artifact's checksum, taken from the same release's own `SHA256SUMS`. `(unresolved)` when no artifact was resolved. |
| verification mode | `github-release` — version, checksum, and artifact all came from one GitHub release, so the checksum proves the download matches what that release published. It does not prove who authored it. `no-artifact` — there was nothing to install, so no checksum was resolved. |
| channel | `deb` (dpkg-managed) or `tarball` (published by setup). Decided by asking dpkg who owns the installed binary; it fails closed and refuses rather than guessing when there is a system binary no package claims, or no dpkg to ask. |

Where another package manager owns the running binary, `update` delegates instead of acting: it
prints `installed via cargo` or `installed via Homebrew`, the upgrade command for that manager, and
the `sudo <path> setup` that republishes the system install afterward.

The applied receipt states exactly what the verification did and did not prove:

```
updated <from> → <to>
installed <file>, verified against the release's own SHA256SUMS (same release, so this is
integrity, not authenticity)
cermetd was restarted on the new build. An agent session started before now keeps the old
build's tool surface until its MCP bridge is restarted.
```

**The daily check.** `cermet update --daily on|off` records the setting in the approver's own config
file and prints what that means: one parameterless request a day, run as you and never by the daemon,
which records a local notice and installs nothing. The recorded state stores what the check *saw*:

| field | meaning |
|---|---|
| `checked_at` | When it last ran, RFC3339. |
| `running` | The version that was running when it checked — so a state file left by an older build is still legible. |
| `available` | A version this box could actually install: artifact resolved and checksum verified. Absence covers up-to-date, no release, no artifact for this target, and a failed check alike. |
| `security` | Whether the release body's first line marked it as a security release. It changes the wording of the notice and nothing else — no different request, no automatic install. |
| `notes` | The release page URL. |
| `verification` | `github-release` or `no-artifact`, as above. |
| `problem` | Why the *last* check did not complete. It is kept alongside a still-true stale `available`, so a transient failure never silently erases a real notice. |

While something is available, every operator CLI invocation prints a one-line notice on stderr:

```
cermet: update available — <running> → <available>. run: cermet update
cermet: SECURITY UPDATE available — <running> → <available>. run: cermet update
```

It is suppressed for `--json` invocations and for the bare `cermet mcp` stdio server, whose stream is
a protocol.

### 7.5 `cermet connect`

`connect` finds a provider token in the environment (or, for GitHub, from `gh auth token`), hands it
to the daemon, and never prints its value — only where it was found.

```
✓ github credential stored — cred_github
  Label: (none); replaced: no.
  Your token is in Cermet's vault. The agent never sees it.
```

| field | meaning |
|---|---|
| `reference` (after the dash) | The vault's opaque handle for the stored credential. It is what appears in `cermet check`'s credential row and in receipts; it is not the credential. |
| `Label` | The optional account label given on the command line, or `(none)`. It exists to tell two accounts of the same provider apart. |
| `replaced` | Whether this overwrote an existing credential for the provider. |

When the token came from somewhere else rather than being pasted, the output adds a note that the
source still holds it: `<source> still holds this token — Cermet hasn't taken sole custody of it yet`.
For GitHub it also reports whether the current repository reaches GitHub through the broker, and
names the `git remote set-url` line if it does not.

### 7.6 `cermet owner`

The owner plane is the independent revocation root: root-only, on its own socket, deliberately
outside the authority model the rest of the daemon enforces. It exists so deny-all is reachable
without going through the machinery it is revoking.

```
owner lockdown: engaged (occurrence <hex>)
```

| field | meaning |
|---|---|
| `owner lockdown` | The latch state: `engaged` (capability execution is denied) or `clear`. |
| `(occurrence <hex>)` | Printed on a transition only: the id stamped on this specific engage or clear and written into the audit chain. It identifies this event, not a session. |

`owner lockdown clear` requires an explicit interactive confirmation before it will contact the
daemon at all; declining or running non-interactively leaves the latch unchanged and says so.

### 7.7 `cermet mcp install`

Prints prose lines with the same `✓` / `✗` marks:

```
✓ registered MCP server '<name>' → <path> (CERMET_AGENT_SOCK=<sock>)
Restart Claude Code (or /mcp reconnect) to pick it up, then ask it to use `catalog`.
```

Every failure names the exact `claude mcp add …` command that would register it by hand, so a missing
client CLI is an inconvenience rather than a dead end.

Repointing is guarded: the daemon must prove it is quiescent — no agent-side child from a prior call
still running — before any client configuration is touched. Each refusal says which proof failed and
that `--force` is the override, and a forced repoint prepends a warning that an agent-side shell
child started under the old server may still be running.

---

## 8. Error and refusal grammars

Every refusal Cermet prints belongs to one of a small number of families. Knowing which family a
message is from tells you where in the pipeline it came from, and therefore what would change it.

### 8.1 The error prefix

A message from the daemon carries exactly one prefix, applied once, from the typed error it decoded:

| prefix | meaning |
|---|---|
| `capability denied: <detail>` | Authority refused. The detail is the deny sentence (§8.2). |
| `invalid input: <detail>` | The request was malformed before authority saw it — a bad type, an undeclared field, a value over a cap. |
| `not found: <detail>` | The named thing does not exist, or its existence is not disclosed. |
| `execute refused: <detail>` | A decided grant could not be executed (§8.5). |
| `integrity error: <detail>` | Stored evidence and its authenticator disagree. |
| `session expired` | The session the request rode on is gone. |
| `provider_disabled` | Content-free by construction: the provider is administratively off, and the message says nothing more. |
| `temporarily quiesced for MCP repoint: <detail>` | A transient barrier is up while an MCP server is repointed. Retry shortly. |
| `crypto error: <detail>` | A cryptographic operation failed. |
| `provider error: <detail>` | The provider itself failed, or an unrecognized error code was rebuilt fail-safe. |

The CLI's own refusals — parse errors, presence declines, malformed daemon responses — are printed
as `cermet: <message>` on stderr. Exit is 2 for a bad invocation, 1 for a denial or drift, 0 for
success.

### 8.2 The deny sentence

Every sentence-authority refusal reads `<provider>.<action> denied by sentence authority` followed by
what specifically refused. The rule and predicate numbers are the one-based numbers `cermet rules`
prints, so a number in a deny and the number you hand `rules revoke` name the same sentence.

| deny reason | sentence |
|---|---|
| explicit deny | `denied by sentence authority rule <N>` |
| unresolved deny | `denied by sentence authority: rule <N> could not be resolved` |
| unknown selector | `denied by sentence authority: unknown selector — no such verb in the ratified grammar` |
| no matching rule | `denied by sentence authority: no rule matches this request` |
| unsupported version | `denied by sentence authority: unsupported ruleset version <version>` |
| missing field | `denied by sentence authority: rule <N> requires missing field \`<field>\`` |
| predicate mismatch | `denied by sentence authority: rule <N> predicate <M> did not match (field \`<field>\`)` |
| budget exceeded | `denied by sentence authority: budget exhausted for the <hour\|day> window` |
| resource not canonical | `denied by sentence authority: query resource is not canonical for the resolved action contract` |

`<N>` is the rule's position in the corpus. `<M>` is which of that rule's `where` conjuncts refused,
counted left to right from 1. For a set-valued rule the evaluator projects the rule onto the member
action's fields before evaluating and then translates the position back, so `<M>` always indexes the
rule as you authored it. `<field>` is the name of the field the failing predicate constrained — the
name only, never the value.

Two refusals fire *before* authority evaluates anything and are distinct from `unknown selector`,
which fires inside the evaluator:

- **unregistered** — no verb targets this provider at all.
- **unsupported** — the provider is known and no verb matches this action.

Both name where to look: the catalog for the verbs that exist, and the vocabulary-request channel for
a verb that does not exist anywhere.

The CLI renders a denial as an outcome, not a transport error — printed, exit non-zero:

```
denied — <provider>.<action>
  <reason>
  <hint>
  request: <request_id>
```

### 8.3 The widening suggestion

`hint` is the advisory next move a deny carries. It is addressed to whoever holds authority, it
grants nothing, and it is computed two different ways:

- **When a rule matched and its bounds refused** (missing field, predicate mismatch), the suggestion
  widens an *existing* rule: the first rule in corpus order that covers this verb, names no
  secret-classed field, and can be widened to admit exactly this canonical request while still
  round-tripping through the rule codec. Rules carrying a `budget` or `rate` aggregate are never
  widened this way — a widened budget must be a newly authored sentence with a fresh counter, not a
  silent cap raise.
- **When no rule mentions the verb at all**, there is nothing to widen, so the suggestion is a
  least-privilege *first* allow: every pinnable execution target of the contract pinned to exactly
  the value this request supplied. A contract with no pinnable target yields a bare allow.

Both END in `to allow: cermet rules allow '<rule text>'`, and **nothing ever follows the closing
quote**: every consumer reads the whole remainder after `to allow: ` as the command itself — the MCP
projection labels it *Advisory widen command*, and an operator pastes it — so a trailing word turns
the one actionable line a deny carries into a broken invocation. A hint with something extra to say
says it BEFORE that marker, as a leading clause, and the projection then renders the whole line as
*Advisory widen hint* prose. There are three shapes in all:

| shape | grammar |
|---|---|
| a plain widening | `to allow: cermet rules allow '<rule text>'` |
| a widening that keeps a pin the request omitted | `<leading clause naming the omitted field> — to allow: cermet rules allow '<rule text>'` |
| an omitted pin with nothing to widen | prose only; no command (below) |

**A conjunct over a field the request OMITTED is carried into the suggestion verbatim, value and
all.** It is not a conjunct that failed — it is one the request never spoke to — and dropping it is
not a relaxation but the DELETION of a scope the operator wrote. Carrying it discloses nothing: the
pinned value is rule text the operator authored. The leading clause says so in words, naming the
field the request left out, because a rule that still pins something the request never named is not
a rule that request would then pass:

```
this request also omitted `team`, which the rule pins and this suggestion keeps, so name it in the request too — to allow: cermet rules allow 'vercel.deploy where project = "site" and target in {"preview", "production"} and team = "team_ours"'
```

When the omitted pin is the ONLY thing between the request and the rule — every other conjunct
matched — there is no widening to propose at all: the one rule text that would admit the request is
this rule with the pin deleted, which a denial does not get to suggest on a requester's behalf. The
hint then addresses the REQUEST and prints no `cermet rules allow` line, since a remedy must not
point at a surface that lacks the answer:

```
the standing rule `allow vercel.deploy where project = "site" and team = "team_ours"` pins `team`, and this request named no such field; name it in the request — no rule change admits it while that pin stands
```

No hint is attached to an explicit deny (settled — an explicit deny is not a widening candidate), an
unknown verb, an unsupported ruleset version, or a budget exhaustion. The budget case is deliberate:
a numeric widening suggestion would disclose the aggregate the deny is refusing to state.

A missing-field refusal carries its own separate hint that names *every* absent required field at
once, so one round trip fixes the request rather than one field per attempt:

```
missing required field(s) `a`, `b` — resend the request naming it/them; `cermet catalog` prints the verb's full signature
```

### 8.4 Invalid input

Refusals from the canonicalization and template layers, before any grant exists. All of them name
the field and describe the shape; none of them echo the value, so a malformed secret cannot leak
through an error message.

| shape | fires when |
|---|---|
| ``field `<f>` must be a <string\|integer\|boolean> scalar, got <shape>`` | The value's JSON type is wrong. The `<shape>` names the JSON kind only — `an object`, `a float`, `null`. |
| `resource must be a JSON object, got <shape>` | The whole resource is not an object. |
| ``undeclared field `<f>` for <provider>.<action>`` | The verb's contract does not declare that field. |
| ``field `<f>` is <n> bytes, over the <cap>-byte field cap`` | A string field exceeded its byte cap. |
| ``field `<f>` is <n> characters, over the <cap>-character field cap`` | A string field exceeded its declared character cap. |
| ``field `<f>` is <n>, over the <cap> integer cap`` | An integer field exceeded its declared ceiling. |
| `string_char_budget is <n> characters, over the <cap>-character aggregate cap` | The verb's fields together exceeded the aggregate character budget. |
| ``field `<f>` value is not <format>`` | A field with a declared format did not match it. |
| ``field `<f>` is fixed to `<v>` by the ratified action template and may not be requested with another value`` | The template pins the field; a request may not override it. |
| ``\`<f>\` must not be empty`` / `must not be a dot segment` / `contains an illegal path character` | A path-segment field failed its grammar. |
| `conflicting environment: the request and the resource specify different environments` | `--environment` and `resource.environment` disagree. |

Client-side parse refusals exit 2 and teach the shape rather than listing what does not exist — for
instance `run takes one dotted verb, `<provider>.<action>``, or
`log --since expects an RFC3339 instant like 2026-08-03T00:00:00Z (the shape the log prints)`.
Retired command names are not silently unknown: each names its replacement.

### 8.5 Execute refusals

Four typed classes, and only these four are named. They are disclosable because by the time they run,
ownership of the handle is already established.

| value | meaning |
|---|---|
| `grant already used (single-use)` | The grant's one effect has run. Resuming cannot run it again — what it produced is on its own receipt, and a fresh effect needs a fresh request. |
| `grant not ready` | The decision has not finished; there is nothing to claim yet. |
| `grant expired` | The grant, its lease, or its retry deadline lapsed. |
| `grant authorized under a different action template` | The verb's template or descriptor changed since the grant was minted. The frozen fields were approved against a different definition. |

Every other execute-time problem stays a plain denial rather than naming its cause. Two collapses are
deliberate:

- An **evidence-backed grant that drifted** reports `provider evidence unavailable` rather than
  naming which of template, descriptor, or evidence went stale — otherwise the difference is
  probeable.
- A **money precondition failure** reports `money precondition denied before mutation`. Which
  precondition and which failure class are recorded internally and never disclosed.

Any other execute failure leaves the decision standing, so the CLI appends what to do about it:

```
the decision stands — finish it with: cermet run --resume <request_id>
```

### 8.6 Relay refusals

Once a relay session is open, every hop is judged by the relay's own vocabulary — the sentence
evaluator is not consulted again. Each refusal has a stable reason word (what the audit row and
`cermet log --hops` carry), an HTTP status the native client sees, and a rule about whether it burns
the session.

| reason | status | burns | meaning |
|---|---|---|---|
| `unknown_handle` | 409 | no | No live session for this handle: unknown, already closed, or burned. There is nothing to burn. |
| `session_expired` | 410 | no | The session's declared TTL lapsed. |
| `malformed_request` | 400 | yes | The request path is not something the relay will forward at all. |
| `no_matching_shape` | 422 | yes | The request's method and path matched no enumerated predicate shape. |
| `bind_mismatch` | 422 | yes | The shape matched, and a bound frozen field disagreed with the request — or the shape pins top-level body keys and the body is not a JSON object at all, so no bind can be evaluated. |
| `effect_already_used` | 409 | yes | The single effect this grant authorizes has already passed. |
| `cap_exceeded_uses` | 422 | yes | The shape's declared per-session use budget has no room left. |
| `cap_exceeded_bytes` | 422 | yes | The shape's declared per-session byte budget has no room left. |
| `body_too_large` | 413 | no | The body is over the daemon's declared cap. A transport limit, not a probe. |
| `outcome_mismatch` | — | it *is* the burn | The effect's own response contradicted a field the approval froze. This is the one class never returned to a live hop: by the time it is known the effect has already landed. It is recorded as what ended the session. |

Burning is the rule that a session being *probed* is done: a hop that misses the predicate or
contradicts a frozen field ends the session, and every later hop renders as an unknown handle. A
lapsed TTL, an unknown handle, and an oversized body burn nothing.

**A key is never a refusal.** A shape's declared `query_keys`/`body_keys` are the VOCABULARY a
sentence or a request may pin; where a key is pinned, the bind decides every hop that carries it.
A key the descriptor never enumerated is the native tool's own business — the project's own
configuration folded into a create body, a parameter the provider added after the document was
written — so the hop is forwarded and the key is named on its record (`undeclared_keys`, §1.7).
Refusing those made the broker a content firewall over payloads that decide nothing about which
effect happens, and the workaround it forced — deploying with the project's own configuration held
aside — ships a differently-configured artifact. What still refuses is unchanged: the method+path
shape (it identifies WHICH effect a hop is), every bind, every outcome assertion, the caps, and the
one-effect rule.

No relay refusal ever answers 401 or 403. Both are lies about what happened — the identity is fine,
the capability is spent or the request is outside it — and native CLIs turn them into "log in again",
which sends an agent re-authenticating forever.

#### What a refusal discloses

At the moment it refuses, the relay already holds the frozen field map, the offending bind, and the
shape inventory. Disclosure is saying what it already holds: no new authority, no new state. Every
value a refusal names is one of four things:

- **Descriptor text** — the ratified verb's own `method`/`path` patterns, vendored into the
  world-readable `cermet` binary. Anyone who can reach the loopback door can already read it.
  (`cermet catalog` is *not* that surface: it projects a verb's fields and bounds, not its relay
  predicate.)
- **A field *this* caller's own approval froze.**
- **A value off the hop *this* caller just wrote.**
- **A value *this* caller's own session already received** — a capture taken from the response to
  its own approved effect.

A credential structurally cannot reach here, because the deciding module holds none. Every detailed
class is also reachable only by a caller already holding a live handle, so a peer uid guessing
handles learns nothing (T3).

Everything borrowed from a caller — offered values, key names, the attempted path, and the frozen
side of a bind wherever the standing rule pinned nothing and the request chose the value — passes
through one choke point that both **bounds** it (an audit row is durable and the length is the
caller's to choose) and **neutralizes terminal-affecting characters** in it (control characters and
the bidi/directional set become spaces). The detail reaches the operator's terminal twice over — the
native client prints the error body verbatim, and `cermet log --hops` prints the same line off the
audit row — so an escape sequence in a request field would otherwise replay live.

It is UNIFORM by design. A layer that names its field while its neighbour stays silent teaches
requesters that silence means "that part was fine", so every class either discloses what it knows or
has nothing left to say. The reason word stays the machine-readable code; the disclosure is the
separate `detail` field beside it, and is also folded into `message` because that is the only field
a native CLI surfaces.

| reason | `detail` carries |
|---|---|
| `bind_mismatch`, frozen field | The frozen FIELD, the wire position and key it is bound at (`teamId` query parameter, `target` body key), the constraint AS ENFORCED, and what the hop offered. The constraint is stated as enforced, never as the raw frozen value: an `omit:` transform binds a frozen value to the key's ABSENCE, so it reads "must be absent", not "must carry `preview`" — a refusal reporting the literal there would send the requester straight back into the same refusal. What arrived is stated as itself: absent, a value, a bare `?key` with no `=`, a key repeated (ambiguous upstream), or a non-string. The remedy names the re-request shape with the key set to the enforced value. |
| `bind_mismatch`, captured bind | A path wildcard is bound to a `captured.<name>` — what *this session's own effect* returned — which is a different provenance and says so: a capture is the approved effect's consequence and is deliberately not something an approval can pin in advance, so the detail never claims the grant froze it. It carries no re-request remedy either: a fresh grant has captured nothing, so that hop lands on the nothing-captured arm below and refuses with the opposite message. What it says instead is to drive the native client at the deployment this session created. When nothing is captured yet, it says that the session's own effect has not landed and offers no remedy at all. |
| `no_matching_shape` | The method and path attempted, the admitted shapes as `METHOD /path` patterns, and the next step: re-send an admitted shape, or ratify this one in the verb's predicate (shapes are enumerated by the ratified template, not by any sentence rule, so widening them is a template edit). |
| `cap_exceeded_uses`, `cap_exceeded_bytes` | Which `caps:` dimension ran out, and that raising it is a template edit. |
| everything else | Nothing. Their reason word IS the whole fact, and a detail there would be invented rather than disclosed. |

The message a native client sees names the cause in words, carries the same detail, and points at
the hop log. Its opening clause branches with the detail's provenance — a captured bind never claims
an approval froze what the effect returned:

```
cermet: this request contradicts a field the approval froze — the grant froze `team`, so this hop's `teamId` query parameter must carry `team_ours`; it carried `team_other`; grants are single-use, so request the capability again and drive the native client so `teamId` carries `team_ours` — see `cermet log --hops`
cermet: this request reaches past the single effect this grant authorized — this session's own effect returned `dpl_ours` as `captured.deployment_id`, so this hop's `/v13/deployments/*` path must carry it; it carried `dpl_theirs`; a session reads only the effect it created, so drive the native client at that one — see `cermet log --hops`
cermet: the approved sentence does not authorize this request — nothing the approved verb admits matches `GET /v9/projects/website/env`; it admits `POST /v13/deployments`, `GET /v2/user`, …; re-send one of those, or ratify this shape in the verb's predicate if it belongs to the verb — see `cermet log --hops`
```

Three refusals fire before a session even opens: the relay is disabled in the daemon config, too many
sessions are already live, or the relay verb's rule binds no project — which the invocation needs in
order to name it rather than let the native CLI guess one from the directory.

### 8.7 Presence refusals

Presence is a human act on this box, confirmed through the platform's own mechanism, and it gates
only the human-only mutations: `rules allow` / `revoke` / `refresh`, `doc apply`, and `preset <name>`.
It never gates a capability request or execution.

A presence gate has three outcomes — confirmed, declined, or unavailable — and the last two are both
refusals that leave the mutation undone.

| message | meaning |
|---|---|
| `human presence declined; custody was not changed` | The human said no. |
| `no biometric presence on this host; approve in your terminal with cermet approve` | The fail-closed default where no presence mechanism exists. |
| `rules changed while human presence was open; custody was not changed; retry the command` | The corpus was mutated by someone else while the prompt was on screen. The compare-and-swap refused rather than committing against a baseline that had moved. |
| `the rules do not match their approval pin; re-run cermet rules allow to re-author` | The staged corpus and its approval no longer correspond. |
| `the sentence authority record is semantically unserved; ordinary incremental mutation is disabled; recover explicitly with cermet doc apply --recover` | Incremental mutation is refused while the record is not being served; recovery has to be explicit. |

The whole-corpus ceremonies gate twice, and both must pass: a terminal confirmation showing the full
transition, then the presence prompt. Their refusals name which gate stopped it and state that the
staged authority remains inert:

```
apply: terminal confirmation declined; staged authority remains inert
apply: human presence declined; staged authority remains inert
apply: human presence unavailable; staged authority remains inert
```

### 8.8 Malformed-response refusals

The CLI deserializes every daemon view into its typed owner, so a missing or mistyped required field
is a malformed response and fails closed rather than rendering as an empty or zero default. These
read `view is not JSON`, `decision receipt is not a decision`, `an allowed request carried no
request_id`, `a refusal carried no reason`, and the like. They are not authority failures: they say
the transport or the shape drifted, and nothing was assumed in either direction.

---

## 9. Artifact, audit-verify, and the MCP projection

### 9.1 `cermet artifact <handle>`

Reads a stored response body by its handle. Every read failure — unknown handle, tampered blob,
missing content, a range the daemon will not serve — collapses to one opaque not-found, so this
surface discloses no more about which handles exist than the agent surface does.

```
artifact: <handle>
digest:   <digest>
size:     <n> bytes (<m> stored · truncated (head+tail kept))
span:     <unit> <start>..<end>
path:     <$.a.b>
note:     output too large to show in full — showing the first <n> bytes; read more with --range bytes:<start>-<end>
---
<content>
```

| field | meaning |
|---|---|
| `handle` | The stored handle, as the daemon echoes it. Printed on the `artifact:` line. |
| `digest` | The content digest of the stored body. It is what makes the artifact content-addressed: the same bytes always produce the same handle. |
| `size` | The body's true size in bytes, before anything was dropped. |
| `stored_size` | How many bytes were actually retained. Printed in the parentheses after `size`. |
| `truncated` | Whether the store kept only a bounded head and tail rather than the whole body. True renders as `· truncated (head+tail kept)` inside those parentheses. |
| `unit` | With `--range`: which unit the span is counted in, `lines` or `bytes`. Printed on the `span:` line. |
| `start`, `end` | With `--range`: the half-open span actually returned, in `unit`. Printed on the `span:` line. |
| `path` | With `--path`: the `$.a.b` pointer that selected this sub-value. Printed on the `path:` line, in place of `span:`. |
| `content` | The bytes themselves, printed after the `---` separator. |
| `frame_truncated` | Whether the returned frame itself had to be cut for transport — independently of `truncated`, which is about what was stored. True prints the `note:` line naming how much is shown and how to read further. |

The MCP `artifact` tool renders the same fields with wider label padding and spells truncation as a
trailing `, truncated` rather than a separate clause.

### 9.2 `cermet audit-verify`

Verifies the audit hash-chain end to end and prints the report.

| field | meaning |
|---|---|
| `event_count` | How many events the chain holds. |
| `verified` | Whether every event's recorded previous-hash and own hash matched what recomputing the chain produced. A single mismatch makes this false for the whole chain. |
| `event_types` | Content-free counts per event type, from the same complete verification pass. It is how an operator proves exactly which rows a window added without opening the daemon-owned database. |

### 9.3 The MCP text projection

The MCP tools render the same values the CLI does, as labelled text rather than JSON. A request's
decision reads:

```
request_id: <id>
decision:   ALLOW|DENY
reason:     <reason>
effect_id:  <id>
hint:       <widening command>
alternative: edit the CERMET.md authority block, then run `cermet doc apply`
authority:  sentence
→ allowed; run it with the execute_capability tool on this request_id (<id>)
```

Every key is the §1.1 field of the same name. Two are specific to this projection:

| field | meaning |
|---|---|
| `alternative` | The second route to the same widening: edit the authority document and apply it, rather than running the `rules allow` in `hint`. It follows a `hint` only on an *authority* denial — a malformed request carries its own hint (which required field is missing), and editing the authority block is not how a caller fixes its own request. |
| `authority` | Which authority decided, in the same value the JSON `authority_kind` carries: `sentence`. Its absence, here as there, means the request never reached authority. |

The trailing `→` line states the one next action the decision admits, naming the tool and the id to
hand it.

## 10. The output journal entry

One JSONL object per operator-CLI invocation, appended to the file `cermet journal` names.
Not printed output: this is the record an agent reads when a human asks what a command
said, resolving each printed field it finds inside `output` against the sections above.

| field | meaning |
|---|---|
| `ts` | RFC3339 time the invocation finished. |
| `argv` | The full argument vector after the program name, uncapped, verbatim. |
| `cwd` | The working directory the command ran in. |
| `exit` | The process exit code the shell saw. |
| `duration_ms` | Wall-clock milliseconds from entry to exit. |
| `output` | Everything the command wrote to stdout and stderr, interleaved in write order, capped. |
| `truncated` | Present only when `output` was capped: `kept` is the stored byte count, `total` what the command actually printed. Derived dumps of ever-growing stores truncate; unique content fits. |
| `kept` | (inside `truncated`) Bytes of `output` stored — the first ones, verbatim. |
| `total` | (inside `truncated`) Bytes the command printed in total. |
