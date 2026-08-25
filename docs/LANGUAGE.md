# Cermet Language

This is the agent-consumable guide to Cermet's shipped language. Part I is the standing sentence
authority an agent may draft in repository-root `CERMET.md`. Part II covers the shipped vendored
action-template forms catalog maintainers need to recognize. The Rust validator and vendored documents
are authoritative for exact acceptance; this guide is not a substitute for running them. Agents
request vendored verbs; they cannot add or alter a verb at runtime.

## Part I - Sentence Authority

### 1. Runtime lifecycle

The live broker loop has two decisions and no pending approval state:

```text
request(provider, action, complete resource) -> allow | deny
allow -> one frozen, expiring, single-use grant -> execute
deny  -> no grant; an eligible denial may include inert widening text
```

Every provider/action reads one authenticated daemon sentence corpus. An absent, unserved, corrupt,
unmatched, or unresolved corpus denies with no profile fallback. A matching `deny` wins over every
`allow`. The agent surface has request, execute, status, catalog, language, and evidence reads; it has
no approve, apply, allow, revoke, refresh, or lockdown operation.

Four invariants govern the loop:

- **The credential never reaches the agent.** The broker opens it only inside provider execution.
- **Grants are single-use.** No action implies another action.
- **Approved fields equal executed fields.** Every value is supplied in the original request,
  canonicalized, frozen, audited before effect (secret-class fields redacted), and HMAC-covered. There
  is no execute-time `parameters`, hole, or fill channel.
- **Only a definite sentence `allow` grants.** A hint, file edit, marker, malformed rule, or unknown
  state never grants.

### 2. The `CERMET.md` artifact

Only this exact managed block is candidate authority; all surrounding Markdown is inert prose:

````markdown
<!-- cermet:authority:v1 -->
Pinned authority: `none` <!-- cermet:pinned:v1 -->

```cermet
allow stripe.get_charge where charge = "ch_3PabcXYZ"
```
<!-- /cermet:authority:v1 -->
````

The marker is generated metadata: `none` or `sha256:` plus 64 lowercase hex characters. It names the
last reconciled live generation and grants nothing. Editing or deleting `CERMET.md` cannot change
runtime authority. The daemon never reads this file to decide a request; only a human operator can
import its canonical body with `cermet doc apply`.

An agent may safely:

1. Read the `language` and `catalog` MCP tools to learn valid verbs and fields.
2. Edit only the managed `cermet` fence as a proposal.
3. Run `cermet doc check`, `cermet doc check --fix`, and `cermet doc diff` for non-authorizing feedback.
4. Stop and ask the human to review and run `cermet doc apply`.

An agent must never claim that a file edit is live, invoke operator authority commands as approval,
or ask for raw credentials.

### 2a. The corpus invariant

**Every verb a sentence can name is a verb the catalog lists.** The catalog projection hides nothing
the broker loaded, and a build vendors exactly the verbs it can serve — so an agent can never read
standing authority for a verb it cannot find in the dictionary, and then execute it by name anyway.
The two sets are one set: no surface may narrow either without narrowing the other. A sentence
naming a verb this build does not hold resolves no contract, so `doc check` and `doc apply` refuse
the whole document (`unresolved verb <provider>.<action>`, with or without a `where` clause), and a
request for it denies as an unknown verb rather than as an authority gap.

### 3. Sentence grammar

One non-comment line is one rule:

```text
<allow|deny> <selector> [where <clause> [and <clause> ...]]
```

Blank lines and `#` comments outside quoted strings are ignored. Canonical output uses one space
between tokens, authored rule order, and one trailing LF when nonempty. `cermet doc check --fix` asks
the daemon to resolve, validate, pin sets, and print that canonical form. The pinned `CERMET.md`
flow refuses a noncanonical body — the document carries a marker naming exact bytes, so the bytes
have to be exact. A preset document (`CERMET_<name>.md`) carries no marker and is canonicalized
during the ceremony: what you review, commit, and store is the daemon's canonical form of what you
wrote.

Selectors:

| Form | Meaning |
|---|---|
| `<provider>.<action>` | Exactly one vendored verb. |
| `<provider>.<set>@sha256:<digest>` | One exact immutable set expansion. |

Provider identifiers are lowercase letters, digits, `_`, or `-`. Action, set, and field identifiers
are lowercase letters, digits, or `_`.

**A bare dotted selector is the VERB**. The old `verb:` prefix is gone
and does not degrade to legacy input: the whole `word:` prefix namespace is RESERVED for future set
forms, so `allow verb:vercel.deploy` and `allow set:stripe.read` are parse errors naming the
spelling that works. A set is therefore named by its immutable expansion digest and nothing else —
the only set spelling stored authority ever carried anyway, since preparation pins every set rule.

Scalar predicates are a flat conjunction:

```text
field = value
field <= integer
field >= integer
field in {value, value, ...}
```

`=` also accepts `==` as loose input; canonical output prints `=`. Predicates must name fields
declared by every selected action where they apply. Secret-class fields can never appear in
sentence predicates.

**String values are ALWAYS double-quoted; bare literals are int/bool ONLY**.
`project = "acme-live"`, `target in {"preview", "production"}`, `amount <= 5000`,
`dry_run = true`. An unquoted string is a parse error whose message shows the quoted line you meant.
The only escapes are `\"` and `\\` — nothing else is an escape, in either direction.

A quoted string means **this exact value**, and nothing else. An earlier dialect let a quoted
scalar on an identity field mean RESOLVE THIS NAME (the `allow` ceremony handed it to a provider's
authoring-time read adapter) while a bare ident meant the literal; with quoting mandatory the quote
marks can no longer carry that distinction, so name resolution is gone from the product. If it
returns it needs its own declared vocabulary, not a second meaning for a quote.

**Matching is by kind, with no exceptions.** An integer literal matches an `int` field, a quoted
string a `str` field, `true`/`false` a `bool`. The one former exception — an integer pin matching a
`str` identity field declaring `format: uint` — existed only because a bare decimal lexed as an
integer while the quoted form asked for resolution. `number = "3"` now says it directly, so the
coercion is dissolved:

```text
allow github.comment_thread where owner = "acme" and name = "api" and number = "3"
```

`format: uint` itself stays, doing its own job: it is the **admission shape** for a request value
(a canonical bare positive decimal — no leading zero, at least 1), so `03`, `+3`, and padded values
never become a resource at all. It is not, and no longer implies, a matching rule.

### 4. Temporal clauses — DISABLED BY DEFAULT

> **Not live grammar.** `budget … per …` and `rate … per …` are gated OFF by the daemon setting
> `language_temporal_clauses`. With the shipped default, a corpus containing either clause is
> **refused at admission** with a message naming that setting — never silently accepted with the
> clause dropped, which would turn an authored cap into unmetered standing authority. Everything
> else in this document is live; this section describes what returns if an operator sets that key
> to `true`.

**Why they are off.** Every other clause is decided from the request alone. These two are decided
from *accumulated state* — a counter over a fixed calendar window, metered from the audit ledger.
Suspending them makes a decision a pure function of `(request, corpus)`: a sentence can be answered
by reading it, and a receipt explained without replaying history.

**What is unaffected.** Per-request bounds are a different thing and stay fully live:
`amount <= 5000`, `amount >= 1`, `charge = ch_…`, and `price in {…}` all evaluate from the request
alone. Integer money fields use the provider's own minor currency unit (Stripe: `5000`
is $50.00) — the sentence bounds exactly the integer the API consumes, no conversion.
Note that `amount <= 5000` caps ONE refund, not a daily total — with temporal clauses off
there is no way to express a cumulative total.

**The gated forms**, for the operator who turns the key on:

```text
allow stripe.refund where amount <= 5000 and budget amount 50000 per day
allow stripe.create_payment_intent_off_session where rate 10 per hour
```

An `allow` may then contain one such clause at the end of its `where` conjunction. Forms are
`budget [field] <positive-integer> per <hour|day>` and `rate <positive-integer> per <hour|day>`.
`budget` sums the named eligible integer side-effect field; `rate` sums one per admitted grant.
`deny` cannot carry one. Such rules do not mechanically widen or participate in ordinary
containment, and rule order matters for them: preparation refuses an earlier overlapping allow that
would bypass a later cap.

**A live corpus that already carries one of these clauses does not keep working when the setting is
off.** Boot adoption re-validates the standing corpus; that validation fails, and the daemon then
**denies every sentence-routed request** until it is corrected. The deny names the failing rule and
the setting rather than only reporting a state:

```text
the standing corpus failed validation at boot (rule 4: temporal clauses (`rate … per …`,
`budget … per …`) are disabled (language_temporal_clauses in the daemon config): decisions are
computed from the request alone) — deny-all until corrected; run `cermet doc check`, then
re-author via `cermet rules allow`
```

Flipping the setting never rewrites the live corpus: run `cermet doc check`, drop the clause, and
`cermet doc apply` the corpus again.

### 5. Authoring examples

```cermet
# One exact read
allow stripe.get_charge where charge = "ch_3PabcXYZ"

# Bounded side effect
allow stripe.refund where amount <= 5000

# The book the credential itself names — the daemon derives `mode`; the sentence bounds it
allow stripe.refund where amount <= 5000 and mode = "test"

# A finite set for one verb
allow stripe.get_price where price in {"price_basic", "price_pro"}

# Explicit deny always wins
deny stripe.create_standard_payout where amount >= 10000
```

Use only catalog-reported provider/action/field names. A syntactically valid rule can still fail
semantic preparation because its verb, set, historical digest, field, scalar type, secret class, or
temporal clause (§4) is invalid or disabled. That failure is a refusal, never partial authority.

### 6. Reconciliation workflows

Incremental operator authoring changes the one live corpus and leaves the document untouched:

```text
cermet rules allow "<rule>"  -> unexported_live
cermet rules revoke <n>      -> unexported_live
cermet rules refresh <n>     -> unexported_live
cermet doc export            -> aligned
```

Declarative authoring changes the proposal first and runtime only after one whole-document ceremony:

```text
cermet doc check --init -> edit CERMET.md -> cermet doc check --fix -> cermet doc diff -> cermet doc apply
```

`doc check`, `doc check --fix`, `doc check --init`, `doc diff`, `doc status`, and `doc export` grant
nothing and require no presence. `doc apply` stages the exact canonical body, shows the whole diff,
obtains one default-no terminal confirmation and one presence ceremony, commits by exact generation
CAS, then advances only the marker. There is no `doc apply --yes`.

`doc export` projects the complete served corpus and marker without changing live authority. It
refuses to overwrite an unapplied draft unless `--replace-draft` is explicit. `doc apply` requires
`--replace-live` when the marker does not name the served baseline, and `--recover` for corrupt or
unserved record replacement. These flags acknowledge anomalies; they do not bypass confirmation or
presence.

### 7. Drift states and exits

| State | Meaning | Exit |
|---|---|---:|
| `aligned` | Candidate, marker, and served live authority agree. | 0 |
| `aligned_no_authority` | Exact empty body, marker `none`, record absent. | 0 |
| `unapplied_document` | The document changed from the marker/live baseline; runtime is unchanged. | 1 |
| `unexported_live` | Incremental live authority changed; the document remains at its baseline. | 1 |
| `marker_stale` | Body equals live authority but generated marker metadata is stale. | 1 |
| `diverged` | Document and live authority both moved from the marker baseline. | 1 |
| `repo_missing` | No repository-root `CERMET.md`. | 1 |
| `repo_invalid` | The candidate cannot be safely read, parsed, or prepared. | 2 |
| `dataplane_unserved` | A record exists but is not this process's validated generation. | 2 |
| `dataplane_corrupt` | The record cannot be interpreted safely. | 2 |
| `dataplane_unknown` | No trustworthy daemon observation is available. | 2 |

Lockdown is orthogonal and always wins at request, claim, and post-claim egress.

## Part II - Vendored Action Template Language

This is a maintained guide for catalog maintainers reading or authoring a Cermet action template. A
template is reviewed and vendored at build time; it is not agent-proposed or runtime-installed. The
validator is authoritative for every accepted key, cross-field constraint, and cap.

The following branch inventory is checked against typed `ActionTemplate` values parsed directly from
`VENDORED_CATALOG`; it is an exact current vendored inventory, not a second acceptance grammar:

<!-- cermet:vendored-template-inventory:start -->
```yaml
field_formats:
  - git_branch_name
  - git_branch_ref
  - git_oid
  - git_tag_name
  - https_url
  - uint
targetless_query_shapes:
  - verb: stripe.read_account
    method: GET
    bodyless: true
    retention: full
    fields:
      - name: mode
        type: str
        required: false
        class: identity
        binding: exact_resource_pin
    transforms: []
  - verb: stripe.search_customers
    method: GET
    bodyless: true
    retention: full
    fields:
      - name: email_contains
        type: str
        required: true
        class: read_filter
        binding: unbound
      - name: mode
        type: str
        required: false
        class: identity
        binding: exact_resource_pin
    transforms: [query_literal]
  - verb: vercel.list_projects
    method: GET
    bodyless: true
    retention: full
    fields:
      - name: search
        type: str
        required: false
        class: read_filter
        binding: unbound
    transforms: []
```
<!-- cermet:vendored-template-inventory:end -->

## 2. Document shape

A template is a YAML document with a closed top-level schema. It carries EXACTLY ONE execution
kind. `execution:` selects between the default `http` (the broker CONSTRUCTS the request from
frozen fields) and `relay` (the broker VALIDATES a request a native client constructed, then
credentials it — §15b); within the default `http` mode, the recipe is either `http:` (a
credential-bearing API call) or `git:` (the hermetic system-git subprocess seam, §15a). Declaring
two recipes, or none, is a parse error.

```yaml
provider: <string>              # the provider this verb extends
action:   <identifier>          # the verb name
fields:   [ <field>, ... ]      # the closed input schema
string_char_budget:             # optional aggregate over listed consumed string fields
  fields: [ <field-name>, ... ]
  max_chars: <positive-int>
consumes: [ <field-name>, ... ] # every field the execution reads
execution_targets: [ <field-name>, ... ]  # normally nonempty; one closed read-filter exception (§4)
execution: http|relay           # optional; default http
http:                           # `execution: http` ONLY — an HTTP or frozen-GraphQL verb (§6)
  path_modes: { <field>: segment|path }   # optional; default segment
  steps: [ <step>, ... ]                   # 1..=8 ordered HTTP steps
predicate: [ <rule>, ... ]      # `execution: relay` ONLY — the admitted request shapes (§15b)
```

**Every struct in the grammar refuses unknown keys.** The Rust typed structs, not an assumption that
this guide enumerates every nested key, define the closed accepted schema. A typo, invented field, or
`auth:` block is a hard parse error, not a silent ignore. This is what makes the deliberate absences
(§9) automatic.

- `provider` — must have a loaded vendored provider descriptor. A missing descriptor is refused.
- `action` — a lowercase identifier (see §3 rules).
- `fields` — the closed input schema (§3). At most **32** fields.
- `string_char_budget` — optional Unicode-character aggregate over a nonempty unique list of declared,
  consumed string fields. Present values are summed with checked arithmetic; absent optional fields
  count as zero. `max_chars` is in 1..=262144.
- `consumes` — the honesty list (§5): exactly the fields your steps reference.
- `execution_targets` — required authority-bearing fields the recipe can execute (§4). It is normally
  nonempty; a template with no target must declare `scope: account` (§4). Sentence authors choose
  which declared target fields to constrain.
- `scope` — `account`, legal only with empty `execution_targets`: the credential IS the resource, so
  the pin is the verb itself (`allow provider.action` is the whole authority quantum). Earned by
  boundedness (§4): a bounded read only.
- `http.path_modes` — optional map from a field name to `segment` (default) or `path` (§6).
- `http.steps` — 1..=8 ordered HTTP steps (§6).
- `http.steps[].body_encoding` — optional `json` (default) or `form` wire encoding (§6).
- `execution` — `http` (default) or `relay`. `predicate` is legal only with `relay`, and `http` is
  refused with it: no document can carry both a constructed recipe and a validated-per-hop predicate.
- `predicate` — 1..=9 admitted request shapes (§15b). Required for `execution: relay`.

---

## 3. Fields

Each entry in `fields` is:

```yaml
- { name: project, type: str, required: true, class: identity, binding: exact_resource_pin }
```

The five keys shown above are mandatory. `format`, `max_chars`, `max_int`, `fixed`, and `source`
are optional field keys.

- **`name`** — a lowercase identifier: `[a-z0-9_]`, non-empty, at most 64 characters. It must be
  unique within the template. The names **`token`** and **`parameters`** are **reserved** and may
  never be a field: they name the credential, and an execute-time fill channel the grammar does not
  have.
- **`type`** — `str`, `int`, or `bool`. The namespace is flat; content does not ride a request (§14).
- **`required`** — `true` or `false`. A required field must be present in every resource; an
  optional field may be absent.
- **`class`** — the authority role (below). One of five values; `unclassified` is **not
  expressible** — every field must classify.
- **`binding`** — the field's allow-binding contract metadata (below).
- **`max_chars`** — a Unicode-character count in 1..=262144, legal only on `str`. Admission rejects
  a present value over the bound before mint; stored frozen resources pass the same provider
  canonicalization before claim. This counts characters, not UTF-8 bytes, and does not replace the
  generic byte cap.

Two **optional** field keys exist beyond those:

- **`source`** — who supplies the value. Absent means the AGENT does, on the request, like every
  other field. The one other value is **`credential`**: the DAEMON derives it from the vaulted
  credential's own shape at request freeze, before the sentence judges anything. Which providers
  have such a field, and how it is derived, is descriptor data — a provider whose keys carry the
  answer declares `credential_mode: { field: <name>, by_prefix: { <prefix>: <value>, … } }`, and a
  template that wants that answer as a pinnable target declares the field with `source: credential`.
  Stripe issues one key per book and spells the book in the key's prefix, so every `stripe.*` verb
  declares `mode`, and `mode = "test"` in a sentence is a real bound rather than something the
  requester asserts about itself.

  The load rules make the claim structural: the field must be an **optional**, exact-pinned `str`
  `identity`, it must be an **execution target** (a derived value nothing can pin is authority
  nothing constrains), and it must be absent from `consumes` and from every step placeholder — it
  never reaches the provider. It is optional because a box with no credential connected has nothing
  to derive from; the field then freezes as absence, a sentence pinning it admits nothing, and a
  sentence that does not pin it is unaffected. A request that supplies the field itself is refused
  as malformed. Boot refuses a template whose `source: credential` field the provider descriptor
  does not declare. In the catalog the field's `origin` reads `credential_derived`, and the MCP verb
  tools omit it exactly as they omit `provider_resolved` inputs.

- **`format`** — a pure **admission predicate** on the field's scalar (reject-only, never a value
  rewrite): one of `git_oid` (a 40/64-char lowercase-hex Git object ID), `https_url` (an absolute
  lexical lowercase `https://` URL with ASCII bytes, a nonempty userinfo-free authority, a host, and
  no whitespace, controls, backslash, or fragment), `uint`, `git_branch_ref` (requires
  `refs/heads/<branch>`), or
  `git_branch_name` (requires a bare same-repository branch and rejects GitHub's cross-repository
  `user:branch` syntax), or `git_tag_name` (the component after `refs/tags/`: git's refname rules are
  one set for every namespace, so the predicate is `git_branch_name`'s — the shape is separate
  because the field addresses a different namespace and a refusal must name the right one). It
  tightens what a field will accept at admission; it adds no authority and is not a policy input.

### Field classes (the authority axis)

The class answers: *what authority role does this field carry?*

| class | meaning |
|---|---|
| `identity` | Identifies the resource acted on (which repo, which project, which environment). Must declare an exact or exact/pattern binding shape. |
| `side_effect` | Authority-relevant configuration. Must declare an exact binding shape, or `bounded` when it is an integer. |
| `free_payload` | Varies per request, not authority-relevant (a commit message, file content, a git ref). Must declare `unbound`; a rule may still explicitly inspect a non-secret field. |
| `secret` | An agent-supplied secret (e.g. an env-var value). Never returned, never audited raw. It may ride **only in the request body**, and an allow scope may **NEVER** pin it. |
| `read_filter` | A bounded, side-effect-free read filter (pagination, a `since`/`limit`). Must declare `unbound`. |

`unclassified` is a backstop the grammar refuses; you cannot write it.

### Bindings (contract metadata for allow shape)

The binding declares the field's legal authority shape. The shared checker validates this metadata
against field class and type; sentence authors still choose the predicates they write.

| binding | meaning |
|---|---|
| `unbound` | No mandatory standing-allow binding. An authored rule may still inspect a declared non-secret field. |
| `exact_resource_pin` | Declares an exact-value authority shape. It does not restrict which scalar-typed sentence operator an author may use. |
| `exact_or_pattern_list` | Declares an exact-or-bounded-pattern authority shape in contract metadata. It adds no pattern operator to sentences. |
| `bounded` | Marks an integer side-effect field as range-bindable contract shape. It neither requires a sentence predicate nor restricts that field to numeric comparators. |

Sentence predicate validity follows the declared scalar type, not `AllowBinding`: `=` and finite
non-empty `in` accept matching `str`, `int`, or `bool` values, while `<=` and `>=` require `int`.
Thus a bounded integer may use `=`, `in`, `<=`, or `>=`, and an exact-pinned integer may use those
same operators. The durable broker evaluates only author-written predicates over declared non-secret
fields; an author may also omit a predicate. No predicate is synthesized from binding metadata. A
wrong field or scalar type cannot resolve, and a request with no matching allow denies.

### The class × binding consistency rule

The validator enforces that class and binding agree. A field is refused unless:

- **`identity`** → binding is `exact_resource_pin` or `exact_or_pattern_list`.
- **`side_effect`** → binding is `exact_resource_pin`, or `bounded` when the field type is `int`.
- **`free_payload`**, **`secret`**, **`read_filter`** → binding is `unbound`.

In short: authority-bearing classes (`identity`, `side_effect`) must be pinnable; freely-varying and
secret classes must be unbound. `exact_or_pattern_list` is legal only on an `identity` field, and
`bounded` is legal only on an integer `side_effect` field.

---

## 4. execution_targets

`execution_targets` normally lists the required authority-bearing fields the recipe can execute: the
handles that identify *which* resource is affected. It remains structural contract metadata and is
included in the frozen resource; sentence authors choose whether to constrain each field. Rules:

1. Every execution target must be a **declared** field.
2. Every execution target must be a **required** field, unless it is `source: credential` — a
   daemon-derived value is optional by construction (§3), and its absence pins nothing.
3. A template must name **at least one AGENT-nameable** execution target unless it declares
   **`scope: account`** — "the pin is the verb": an account-scoped read has no finer resource
   than the credential itself, so the verb name is the complete authority quantum and a bare
   `allow provider.action` states it. The declaration is earned by boundedness, checked at
   ratification: constructed `http` execution only, no `money`, only `read_filter` fields (plus any
   `source: credential` field, which describes the credential rather than a finer resource), and
   every step a statused read (a bodyless GET, or a POST whose body is a frozen GraphQL `query`). A
   filter placeholder EMBEDDED inside a composite query value (a provider search DSL) must be a
   quoted `query_literal` — injected filter content must never rewrite the query's meaning; a
   placeholder that is the whole value has no DSL around it and rides plain.

Shipped `scope: account` verbs: `stripe.read_account` (no filter at all — the credential is the
whole resource), `stripe.search_customers` (embedded quoted filter), and `vercel.list_projects`
(whole-value optional filter):

```yaml
fields:
  - { name: email_contains, type: str, required: true, class: read_filter, binding: unbound }
  - { name: mode, type: str, required: false, class: identity, binding: exact_resource_pin, source: credential }
consumes: [email_contains]
execution_targets: [mode]
scope: account
http:
  steps:
    - id: search
      method: GET
      path: /v1/customers/search
      query: { limit: "10", query: 'email~"{email_contains|query_literal}"' }
```

**Why optional targets are refused.** If an optional execution target were absent, a provider default
could select authority not represented in the frozen resource. Therefore every target is required;
the provider cannot silently execute an omitted target value. A `source: credential` target is the
one exception, and it is exempt for the reason the rule exists: the value never reaches the
provider, so there is no omitted value for a provider default to fill.

**Express an API default without an optional target.** If the provider requires a field but you
usually want a fixed default, do *not* make it an optional target. Instead declare a **required**
field and use a body transform (§7): `{field|omit:LITERAL}` (drop the key when the frozen value is
the default) or `{field|default:LITERAL}` on an optional non-target field (send the pinned value or
  a fixed literal). This keeps the deciding value structurally classified as a required identity
execution target. A sentence author may pin it or deliberately allow every validated value; either
way, the frozen value alone decides what reaches the wire.

---

## 5. consumes

`consumes` must list **exactly** the fields that some step actually references via a placeholder —
no more, no fewer. The validator checks both directions:

- Every name in `consumes` must be referenced by at least one step placeholder (a name in
  `consumes` that no step uses is a *dishonest consumes* error).
- Every field a placeholder references must appear in `consumes` (an unreferenced-but-used field is
  an error).

`consumes` is the audit-honest declaration of what the recipe reads. It may never name
`parameters`. A field that is declared but never referenced (rare, but legal for a field that only
exists to be pinned) simply does not appear in `consumes`.

---

## 6. http.steps

`http.steps` is an ordered list of **1..=8** HTTP steps. The broker executes them in order; data
flows **only forward** (a later step may use a value captured from an earlier step's response, never
the reverse). Each step:

```yaml
- id: create              # unique lowercase identifier
  method: POST            # GET | POST | PUT | PATCH | DELETE
  path: /v13/deployments  # required; see below
  query: { ref: "{branch}" }   # optional
  optional_ok: [404]           # optional; non-final only
  success_statuses: [201]      # optional; the exact accepted status set (writes)
  expect_eq: { head_sha: head } # optional; response path == frozen identity field
  expect_literal: { data.ok: true } # optional response path == frozen literal
  graphql_query: "query ..."   # optional frozen GraphQL document (§13)
  require: [data.object.id]    # required non-null success evidence
  conflict_on: [STALE_DATA]    # optional GraphQL error type/code classification
  capture: { sha: "$.sha" }    # optional; non-final only
  body_encoding: form          # optional; json (default) | form
  body: { ... }                # optional structured object
  retention: none              # optional: store NO artifact (the default is `full` — see §6.1)
```

A step declares **nothing about what comes back**. That is not an omission from the example: the
response contract is fixed for every verb (§6.1), so there is no return shape to author.

- **`id`** — a unique lowercase identifier (`[a-z0-9_]`, ≤64).
- **`method`** — one of `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. Nothing else.

Every verification read (a REST `GET` or frozen GraphQL query) must be in one leading prefix before
every mutation. A read after any mutation is refused even when it has no response assertions: it is
too late to gate the earlier effect. One or more preflight reads followed by one or more mutations is
legal; no later step may return to reading.

### path (rule 9)

- Must start with `/`.
- Must not contain `?`, `#`, or any whitespace. (Query string goes in `query:`, never inline.)
- A `{field}` placeholder in a path must name a **required `str` `identity`** field that is **also
  listed in `execution_targets`**. Unclassified or structurally unpinnable URL authority is refused.
  A sentence author may pin that target or deliberately omit the predicate and allow its validated
  values broadly. In both cases the executed path comes only from
  the frozen resource, never an execute-time channel.
- A path placeholder may **not** be optional (`{x?}`) and may **not** carry a transform (`{x|...}`).
- A path placeholder may **not** name a capture. Provider response data must never steer the URL.

### path_modes

`http.path_modes` maps a field to how it expands in the URL:

- **`segment`** (the default; you need not list it) — a single percent-encoded URL segment. A slash
  in the value is encoded, so it stays one segment.
- **`path`** — a slash-bearing path fragment (e.g. a repo file path like `docs/a/b.md`). A
  `path`-mode field must be a **required `str` `identity`** field **and** listed in
  `execution_targets` (it is slash-bearing URL authority, so it must be pinnable).

### query (rule 10)

`query` is a map of literal keys to string values. Ordinary query placeholders carry target authority;
`scope: account` templates (§4) are the exception — their placeholders are unbound `read_filter`
values, quoted `query_literal` when embedded in a DSL, plain when they are the whole value.

- Keys must be **literal** (no placeholder in a key).
- Ordinarily, a value placeholder must resolve to an **exact-pinned `identity` or `side_effect`** field
  that is **listed in `execution_targets`**. It may not use a transform.
- `query_literal` is legal only in the validator's closed targetless GET/read-filter shape. The shipped
  `stripe.search_customers` instance applies it to the required `email_contains` field. Every
  targetless field must be a required string `read_filter` bound `unbound`, and every occurrence must
  be embedded between literal double quotes. Values are 3..=200 bytes without controls; execution
  escapes backslashes and double quotes before insertion into the frozen query grammar.
- A query placeholder may **not** name a capture (response data may not steer a query). An optional
  ordinary query placeholder must be the whole value.

### body (rule 11)

`body` is a structured object (it may nest objects and arrays). `body_encoding` selects its wire
representation: `json` is the default; `form` emits `application/x-www-form-urlencoded` with nested
keys in bracket notation (`pause_collection[behavior]`). Selecting `form` without a body is refused,
and GraphQL steps are always JSON.

- Object **keys** must be literals (no placeholder in a key).
- String **values** may contain placeholders. Each placeholder must resolve to a **declared field**
  or a **strictly earlier capture** (a capture produced by a step *before* this one).
- **Secret fields MAY ride in the body** — the body is the only place a `secret` field is allowed.

### capture (rule 13)

`capture` extracts a value from **this step's response** for a **later** step to use:

```yaml
capture: { sha: "$.sha" }
```

- Each entry maps a capture name (a lowercase identifier, not reserved) to a JSON pointer of the
  form `$.seg(.seg)*` (dot-separated identifier segments).
- At most **8** captures per step.
- A capture name may **not** collide with a declared field name, and may not be declared twice.
- Captures are **not allowed on the final step** (a final-step capture is dead — nothing consumes
  it).
- A path or query may **never** reference a capture. Only a **body** in a strictly later step may.

### optional_ok (rule 12)

`optional_ok` lists HTTP status codes that are tolerated (not treated as failure) for this step —
e.g. a `GET` that 404s to mean "file does not exist, so create it".

- Codes must be in **400..=499**. A 5xx is never tolerable.
- Legal on **non-final steps only**.

### success_statuses, require, expect_eq, and expect_literal

These response checks keep reads and writes honest:

- **`success_statuses`** — an exact closed set of accepted status codes for that step. When present, a
  2xx **outside** the set is a **failure**, so an accepted-but-not-terminal response (e.g. a `202`
  where only `201` means created) is never misread as success. Every guarded write step pins one.
- **`expect_eq`** — asserts that a response path equals the **frozen** value of a required exact-pinned
  string identity execution target. On a verification read, including a final REST GET or frozen
  GraphQL query, it is a value-free precondition. A non-final use must sit in the leading verification
  prefix before every mutation. Only a final non-read step is a postcondition: its mismatch
  returns `postcondition_failed` plus the provider's body as `provider_proof`, after
  agent-submitted-secret scrubbing (§6.1).
- **`require`** — dotted response paths that must exist and be non-null. It is mandatory and nonempty
  on every GraphQL step; REST steps may use it to stop an ambiguous 2xx from becoming success. For a
  GraphQL 2xx, a present nonempty or malformed `errors` value is classified first — the body is
  returned verbatim and the step's verdict (`outcome`, plus `conflict` when `conflict_on` matched)
  rides the receipt's sibling `envelope`, never the body (§6.1).
  Equality/literal assertions then run before `require` for both GraphQL and REST, so an overlapping
  missing/null path retains its more specific postcondition classification. An uncovered missing path
  on a final mutation returns `missing_proof_path` with the same `provider_proof`; reads and
  non-final guards stay value-free.
- **`expect_literal`** — asserts a response path equals a template-frozen JSON literal. Unlike
  `expect_eq`, it may compare a fixed string list as well as a scalar/null value. Only a mutating final
  step treats mismatch as a reconciliation-bearing postcondition; reads and non-final guards are
  value-free preconditions. A fixed list must be nonempty, unique, and contain at most 32 nonempty
  strings; objects, mixed/nested lists, duplicates, and empty lists are refused.

### 6.1 The response contract — what every verb returns

**VERBATIM.** The provider's response is returned verbatim. There is no response-filtering
mechanism.

A template shapes the **request** and asserts postconditions on the response. It never edits the
response. There is no return-shape key to write: a template declaring one fails to load with an
unknown-field error, so the absence is enforced by the loader rather than merely documented.

| surface | what you get |
| --- | --- |
| **success** | the provider's parsed JSON body, **unchanged** — array, object, or scalar |
| **failure** | `{"status": <http status>, "error": <the provider's body>}` — the status is *added* evidence, never a narrowing |
| **artifact** | the same bytes, stored under the step's `retention` (below) |
| **`envelope`** | a SIBLING field, never inside the body: what the BROKER observed — a GraphQL step's `outcome`/`conflict` verdict, or a step's declared retained headers. Absent for an ordinary verb |
| **postcondition failure** | `{"outcome": ..., "provider_proof": <the provider's body>}` — a mismatch after the effect boundary is exactly when you need everything the provider said |

This holds for **money** verbs too. A money success returns the verified object — its own provider
id (`re_…`, `pi_…`) included, so a refund reconciles to the dashboard without a follow-up search —
and a money failure returns the rejection: HTTP status, error classification, and Stripe's
`request_log_url` deep-link.

**Nothing is stripped ambiently.** Not `client_secret`, not a webhook `whsec_…`, not `next_action`,
not payment-method detail. If response filtering is ever wanted it arrives as a **declared class an
operator enables in a rule** — never a descriptor-buried list invisible to the rule author — and
today **zero such classes exist**.

**Where broker-authored metadata goes.** Some things legitimately need to reach the agent next to
the body: a GraphQL step's classified `outcome`/`conflict` verdict, and a step's declared retained
response headers. They ride a **sibling `envelope` field on the receipt**, never inside the
provider's JSON.
Writing them into the body would have made receipt result ≠ stored artifact ≠ wire body,
which is exactly the divergence the wire tee exists to catch. Augmentation is still editing.

**Two things that are NOT response projection, and are unchanged:**

- the **vault credential** is byte-redacted out of every result, artifact, and log;
- an **agent-submitted `secret`-class field** the provider echoes back is scrubbed out of every
  retained body, and retention fails closed when a representation cannot be captured.

Both are *request-side custody*: they concern material we or the agent supplied, not what the
provider chose to say.

### retention — a cap on storage, not on the response

**For an HTTP verb the default is `full`: its response body is durably retained as an artifact.**
That is the norm, it is declared, and it is visible per verb — the catalog surfaces (`cermet
catalog --all` for the operator, the `catalog` tool with `scope: all` for an agent) print a
`response: returns: … | stored: … | errors: …` line for every verb, so what a verb keeps is readable
off the surface its reader already uses rather than inferred from a template.

**The declaration is DERIVED, never assumed.** Not every verb is an HTTP verb, and a
declared surface that flattens them into one sentence is a confident lie. What each kind actually
does, and therefore declares:

| kind | returns | stored | errors |
|---|---|---|---|
| HTTP (REST) | `verbatim` — the provider's body | `full`, or `none` where declared | `status_and_body` |
| HTTP (GraphQL terminal step) | `verbatim` | `full` / `none` | `status_and_body_or_verdict` — an HTTP-level failure gets the status envelope; a provider-declared failure at 200 gets the body with its verdict in the sibling envelope |

**Say the cost plainly.** `stored: full` means the provider's response material — customer objects,
PII, email addresses, bearer values a provider chose to include — sits durably at rest in the
artifact store on the operator's own box, under `cermetd`'s uid, until something removes it.

**And the counter-fact, which belongs right next to it.** That body already persists ungoverned in
the agent's transcript either way; the response reached the model. The artifact is the *governed*
copy: owner-readable through one audited verb, integrity-checked by digest, and inside the blast
radius you can reason about. Not retaining does not make the data not exist — it makes the only
copy the one nobody is accounting for. That trade is why the default is `full`, and it is a
**setting**, not a fact of nature: see the declared future work on a retention window below.

`retention: none` on a step means **no artifact is stored**. It does not narrow the response: the
body still reaches the receipt in full. It is the exception now, and it survives in exactly two
places in the shipped catalog:

- **The money floor (7 Stripe verbs).** A ratified structural contract, not a preference: the
  validator REQUIRES a money action to be one non-GET `retention: none` mutation step, and the
  money custody boundary enforces the cap independently of the declaration, so the writer and the
  terminal-evidence verifier agree by construction. See §6.2.
- **`github.read_secret_scanning_alerts_open`.** Its response space *is* other people's leaked
  credentials — material absent from our vault, which no redaction pass can see. Not keeping a
  durable copy is a currently-valid reason rather than a leftover. Its primary bound is still
  request-side: the verb freezes `hide_secret=true` so the provider never sends the value.

Every other verb follows the declared default instead of a silent per-verb exception.

**One more declared behavior, so it is not a surprise.** A provider response larger than the
2 MiB runtime cap, or one whose body cannot be read off the socket after the status arrived, is
**not stored and not returned**: the executor preserves the HTTP status and discards the body
(`status_preserving_response`). That is a fallback, it is deliberate, and it means a very large
response yields a status-only receipt with no artifact — regardless of `retention`.

**Declared future setting (not built).** An artifact retention window / GC knob — how long the
store keeps bodies before purging — does not exist today. It is named here so its absence is
declared; when it arrives it will be a setting readable from the CLI like any other, never an
improvised default.

### 6.2 The money floor — where a money verb's body actually lives

A money verb keeps **no artifact, ever**, and that is structural rather than declarative:

- the template must declare one non-GET `retention: none` mutation step (loader-enforced), and
- the custody boundary of a proving verb clears the retained body at `ProviderResponse::proved`,
  independently of what the template said, because
- `validate_money_terminal` treats a money terminal carrying artifact evidence as *impossible* —
  so a writer that produced one and the verifier that reads it back could never agree.

The response is not lost. It lives in the **ledger terminal record**: the authenticated, HMAC-chained
audit event for that effect carries the verified body — the created object's own
provider id, amount, currency, status on a success; the HTTP status, the provider's error
classification, and Stripe's `request_log_url` deep-link on a rejection. That record is
tamper-evident by construction, which an artifact blob is not, and it is the surface money
reconciliation is supposed to read.

So for money the answer to "what does Cermet durably keep?" is: **the terminal record, not the
artifact store** — and the catalog line says `stored: none` for exactly that reason.

---

## 7. Placeholder transforms

A placeholder in a body or query value may carry a `|`-suffixed transform. Path placeholders and
captures never carry transforms. Most transforms apply only to declared `str` fields; `negative` is
the narrow integer exception.

| form | meaning | legality |
|---|---|---|
| `{x}` | The field's value, whole or embedded in a larger string. | Any declared field. |
| `{x?}` | **Optional**: omit the enclosing key entirely if the field is absent; otherwise send verbatim. | Must be the **whole** value (not embedded). Cannot combine with a transform. |
| `{x\|base64}` | Base64-encode the field's value. | Declared `str` field. Must be whole if transformed. |
| `{x\|negative}` | Render a positive integer as its negative counterpart. Non-positive values fail before egress. | Required integer `side_effect` field with `bounded` binding. |
| `{x\|query_literal}` | Escape a frozen read filter inside a fixed, double-quoted provider query expression. | Query only; the closed targetless GET/read-filter shape in §4 and §6. |
| `{x\|omit:LITERAL}` | If the frozen value **equals** `LITERAL`, **drop** the enclosing key from the wire; otherwise send the value. | Legal **only** on a **required, exact-pinned `identity` field that is an `execution_target`**. This structural rule keeps the invisible deciding value in the frozen authority resource. A sentence author may pin it or deliberately omit the predicate for a broad allow; the frozen value still decides the omission. `LITERAL` is `[a-z0-9_-]`, 1..=64. |
| `{x\|default:LITERAL}` | Send the frozen value if present, else the fixed `LITERAL`. | Legal **only** on an **optional `str` field** (a required field is always present, so a default would be dead). `LITERAL` is `[a-z0-9_-]`, 1..=64. |

Rules that bind all transforms:

- In a body, an optional (`{x?}`) or transformed (`{x|...}`) placeholder must be the **whole** string
  value of its key; it cannot be embedded in a larger literal (`"a{x?}b"` is refused). The sole
  inverse case is `query_literal`: it must be embedded between literal double quotes in a query value.
- You cannot combine `?` and a transform in one placeholder.
- A transform on a capture or path placeholder is refused. Type and placement constraints are exactly
  those in the table above; every transform other than `negative` requires a declared `str` field.
- `omit:` on an optional field is refused; `default:` on a required field is refused.

`LITERAL` allows a hyphen (unlike a field identifier) so a real API default like `custom-env` is
expressible.

---

## 8. Caps

Every cap is a hard refusal:

| limit | value |
|---|---|
| document size | 64 KiB |
| fields | 32 |
| steps | 8 |
| dotted response paths per assertion list | 32 |
| captures per step | 8 |
| frozen GraphQL document | 8 KiB |
| bytes one push may write into a mirror | `git_max_push_bytes`, default 512 MiB (§15a) |

---

## 9. Deliberate absences

Each of these is a security decision, not a missing feature. The grammar refuses them automatically
because every struct rejects unknown keys.

- **No `auth` / token field.** The `Authorization: Bearer <token>` header is a **provider**
  property. A template can never steer where the credential goes — it never even names it.
- **No `origin` / host field.** A template carries URL **paths** only. The origin is the provider's
  compiled-in, egress-pinned host. Template-supplied path data can never point the credential
  off-origin.
- **No conditionals, loops, branches, or agent-authored arithmetic.** Data flows only **forward**
  through captures. There is no `if`, no iteration, no expression evaluation; only the fixed,
  typed transforms listed in §7 exist.
- **No `requires_anchored_allow`.** That is a provider-level property, not a template's to set.
- **No agent-authored GraphQL document.** `graphql_query` is a reviewed frozen template literal;
  only the typed `body.variables` object carries request fields.

State it plainly: **the grammar is deliberately not Turing-complete.** An HTTP template is a linear
list of at most eight steps with forward-only data flow.

---

## 11. Authoring checklist

Run this over a template before it is signed into the catalog:

1. **Top-level execution kind** is `http`.
2. **`provider`** has a loaded descriptor and the action matches that provider's vendored namespace.
3. **`action`** and every **field `name`** and **step `id`** are lowercase `[a-z0-9_]`, ≤64, and
   none is `token` or `parameters`.
4. **Every field** declares `name`, `type` (`str`/`int`/`bool`), `required`, `class`,
   `binding`, and the class × binding pair is consistent (§3): identity → exact_resource_pin,
   exact_or_pattern_list; side_effect → exact_resource_pin or bounded (integer only);
   free_payload/secret/read_filter → unbound.
5. **`execution_targets`** is non-empty, and every target is a **declared, required** field, except
   for the closed one-step targetless GET/read-filter shape used by `stripe.search_customers`. No
   optional targets — express a default with `omit:` / `default:` instead.
6. **`consumes`** lists **exactly** the fields your step placeholders reference — no unused names,
   no missing ones.
7. **Every path placeholder** names a required `str` identity field that is also an execution
   target; it is not optional and not transformed; it is not a capture.
8. **Any `path`-mode field** (in `path_modes`) is a required `str` identity execution target.
9. **Every ordinary query value placeholder** is an exact-pinned identity/side_effect execution
   target; captures are always refused. The only query transform is `query_literal`, and only in the
   closed targetless GET/read-filter shape.
10. **Body** object keys are literals; string placeholders resolve to a declared field or a
    strictly earlier capture; only `secret` fields (and only in the body) carry secrets.
11. **Captures** use `$.seg(.seg)*` pointers, ≤8 per step, unique, not colliding with a field name,
    and never on the final step; nothing in a path or query references a capture.
12. **Every verification read** is in the leading read prefix before every mutation; execution never
    returns to a REST GET or frozen GraphQL query after the first mutation.
13. **`optional_ok`** codes are 400..=499 and appear on non-final steps only.
14. **No step declares a return shape.** The response contract is verbatim (§6.1); any return-shape
    key fails to load as an unknown field. Decide only whether the terminal step declares
    `retention: none` — a cap on STORAGE.
15. **Transforms** obey their legality: `omit:` only on a required, exact-pinned identity execution
    target; `default:` only on an optional `str` field; `base64` only on a `str` field; `query_literal`
    only in the targetless read-filter query shape; body transforms are whole values; `?` never
    combines with a transform.
16. **Under the caps**: ≤64 KiB, ≤32 fields, ≤8 steps, ≤32 paths per assertion list, ≤8 captures/step.

This checklist catches common HTTP-template errors; it is not a proof of validity. The validator
re-checks the complete document and refuses on any doubt.

---

## 14. Content does not ride a request

There is no structured payload type in this grammar — no `change_list`, no file-content field — and
no staging area behind one. Cermet's whole part in a flow is authorization and receipt; carriers,
staging areas, and content stores belong to the native tool, which for content means git's own
transport (`docs/REFERENCE.md`, Core Invariants).

So a request's fields are scalars: `str`, `int`, `bool`. That is the flat namespace policy reads,
approval renders, and the grant HMAC covers, and it is why an approval card can show every field it
authorized without a "payload not shown" escape hatch.

If you are looking for how to get a commit onto a remote, it is not a verb — and it is not a cermet
command either. `cermet connect github` points the repository's remote at the broker once; after
that it is your own git:

```sh
git remote -v                  # origin  cermet::github/acme/website   (what connect wired)
git commit -m "…"
git push origin main
```

Vocabulary limits arrive as hook refusals in git's own output, naming what to fix (§15a).

---

## 15a. The `git:` execution kind (git talks to git)

The second — and, deliberately, only other — execution kind. A `git:` verb is **not requestable**:
its decision is git's own `update` hook, the sanctioned per-ref policy seam, running on a
daemon-held mirror and driven by an ordinary `git push`. The agent-facing request path refuses it
and names what to run instead.

A `git:` template may extend only a provider whose ratified descriptor pins a git origin:

```yaml
# the vendored github provider descriptor
git:
  origin: https://github.com          # a bare scheme+host[:port] https origin
  auth: basic:x-access-token          # how the vault credential is presented
```

The grammar has exactly TWO declared steps, and a verb declares exactly one of them — because there
are exactly two credentialed git interactions. `push` carries an authorized ref update from the
mirror to the upstream; `fetch` is the same picture reversed, refreshing the mirror FROM the upstream
so a read has something current to serve.

```yaml
git:
  push:
    remote_path: "/{owner}/{name}.git"   # a PATH under the descriptor's git origin, never an origin
    branch:  branch                      # field naming the branch to advance (or `tag:`, never both)
    new_oid: new_oid                     # field naming git's `new` from the hook tuple
    mirror_old_oid: mirror_old_oid       # OPTIONAL: git's `old` — the MIRROR's tip, not the upstream's
```

Every value except `remote_path` is the NAME of a declared field, and each carries a fixed
class/binding/format the validator enforces:

| slot | required | type | class | binding | format |
|---|---|---|---|---|---|
| `remote_path` placeholders | yes | `str` | `identity` | `exact_resource_pin` | — |
| `branch` | one of | `str` | `identity` | `exact_resource_pin` | `git_branch_name` |
| `tag` | one of | `str` | `identity` | `exact_resource_pin` | `git_tag_name` |
| `new_oid` | yes | `str` | `identity` | `exact_resource_pin` | `git_oid` |
| `mirror_old_oid` | **no** | `str` | `identity` | `exact_resource_pin` | `git_oid` |

A push step names EXACTLY ONE of `branch` and `tag` — the two ref namespaces that have vocabulary —
and the validator refuses both or neither. They are separate because sentence bounds are conjunctive
over a verb's own fields: a standing `allow github.push where owner = … and name = …` is a BRANCH
authority, and if tags rode the same word that sentence would silently start admitting them. A
release's tag therefore needs its own sentence, naming its own version. Every other ref namespace
(`refs/notes/`, `refs/pull/`, …) has no vocabulary at all, and the update hook refuses it by name.

A `fetch` step declares only `remote_path`:

```yaml
git:
  fetch:
    remote_path: "/{owner}/{name}.git"
```

There is deliberately no per-branch vocabulary on the read side. Which REPOS may be read is the
sentence's business; a refresh of an allowed repo brings all of its branches and prunes the ones the
upstream dropped, because a mirror that served a subset would lie about the remote.

`consumes` must name exactly the referenced fields, no field may be declared and unused, and
`money`/`request_evidence` are not expressible on this kind. Notice what is ABSENT: there is no
pack, digest, content, or change-list field anywhere. A git verb declares WHO and WHERE; HOW the
bytes travel is git's.

The response contract is fixed by the kind rather than declared per verb: `returns: receipt`,
`retention: none`, `errors: refusal`. Nothing is stored as an artifact, and a refused push is an
execution error rather than a hollow success — not a success carrying a refusal.

A push outside what the hook allowed never becomes a credentialed carry. How that decision is
reached and what it costs — the mirror, the read-side refresh, the hook tuple, the hermetic runner,
the receipt derivation, and the git settings — is grant-kernel enforcement, not language:
`docs/REFERENCE.md` → Grant Kernel → *Git enforcement (hook-decided carry)*.

---

## 15b. `execution: relay` — credentialing a native client's own requests

Some effects belong to a mature local tool, not to us. A Vercel preview deploy is one: the `vercel`
CLI already walks the working tree, dedups content by digest, and uploads it. Reimplementing that
here would duplicate a tool that already works; the only part of it that actually needs Cermet is
the credential.

So a relay verb declares no request. The native client is pointed at cermetd's loopback relay (the
vercel CLI takes it on `--api`) with a **grant handle** — not a credential — in its bearer slot. Per
request the relay maps handle → live session, checks the request against this document's
`predicate`, and only then swaps in the vaulted credential and forwards it to the provider descriptor's
pinned origin.

Approved == executed still holds; it is enforced by INSPECTION instead of construction.

```yaml
execution: relay
predicate:
  - method: POST                       # GET/POST/PUT/PATCH/DELETE, uppercase
    path: /v13/deployments             # `/`-rooted; a `*` segment matches exactly ONE segment
    once: true                         # THE single effect (exactly one rule declares it)
    query_keys: [forceNew, teamId]     # the parameter names this shape KNOWS ABOUT (vocabulary)
    body_keys: [files, projectSettings]  # the TOP-LEVEL body keys it knows about; required with body binds
    bind:
      body.name: project               # a body key must equal this frozen field
      body.target: "target|omit:preview"   # ...or, at this frozen value, be ABSENT
      query.teamId: team                 # a query VALUE must equal this frozen field
                                         # (…and constrains nothing when the field is optional
                                         #  and the request omitted it)
    capture:
      deployment_id: id                # session state DERIVED from this effect's own 2xx response
    assert:
      name: project                    # ...and what that response must SAY about the frozen fields
      target: "target|omit:preview"
  - method: POST
    path: /v2/files
    caps:
      max_uses: 4096                   # per SESSION: how many hops of this shape, and…
      max_total_bytes: 268435456       # …how many aggregate request bytes they may carry
  - method: GET
    path: /v13/deployments/*
    bind:
      path.*: captured.deployment_id   # every `*` segment must equal what this session captured
  - { method: GET,  path: /v2/deployments/*/events, query_keys: [builds, follow] }
```

Rules the validator enforces (each one refuses the document, not the request):

- 1..=9 rules; no duplicate `(method, path)`; every path `/`-rooted, bounded, query/fragment-free, and
  made of `[A-Za-z0-9._~-]` literals or the single-segment wildcard `*`.
- **Exactly one** rule declares `once: true` — one grant, one effect. Every other admitted shape
  (uploads, reads) is repeatable inside the session TTL, bounded only by its own `caps` if it
  declares one.
- `query_keys` is the shape's declared parameter VOCABULARY: the names it knows about, capped at 16.
  It admits and refuses nothing on its own — a parameter outside it is forwarded and named on the
  hop's record (`undeclared_keys`). What constrains a parameter is a `bind` on it. Absent means the
  shape declares no query vocabulary, so every parameter a hop carries is reported as one it does not
  enumerate.
- `bind` maps a request location to a value the session holds. Three location forms: `body.<key>`, a
  top-level JSON body key; `query.<key>`, a query parameter's VALUE; and `path.*`, EVERY wildcard
  segment of that rule's own path. A BODY bind is refused on a bodyless method (`GET`/`DELETE`); a
  query bind reads the target, so it is legal on every method — the reads a session makes carry scope
  too. A bound query key must be listed in that rule's own `query_keys`: a value bind on a key that
  can never arrive is a shape whose declared vocabulary contradicts its own enforcement, and the
  record would then report a PINNED key as one the shape does not know about. Declaring a key and
  pinning its value are different jobs — see `docs/provider_design_principles.md`, *A key that
  carries authority is bound, not blocked*.
- `capture` (on the `once` rule only) names session state DERIVED from the effect's own 2xx response:
  `<name>: <top-level response key>`, read as a string, WRITE-ONCE. A `path.*` bind reads it back as
  `captured.<name>`, and that is the only value form a path bind takes — a wildcard segment is the
  approved effect's own consequence, never something a sentence pins in advance. Refused: a path bind
  on a rule whose path has no `*`, on a capture nobody declared, on the effect rule itself (its own
  capture does not exist until its response lands), and any `omit:` transform (a path segment is
  always present). Nothing captured yet ⇒ the bind cannot hold ⇒ the hop refuses. Captures are capped
  at 4.
- `assert` (on the `once` rule only) is what the effect's 2xx response must SAY about the frozen
  fields: `<top-level response key>: <field>`, in the same `<field>|omit:<literal>` grammar as `bind`,
  capped at 4. Its fields obey the same comparability rules as bound fields and count toward
  `consumes`. It is **detection, not prevention** — the effect has already landed when the response is
  read; a mismatch burns the session and writes a high-severity audit row carrying frozen-vs-observed.
- `body_keys` is the shape's declared TOP-LEVEL body VOCABULARY, capped at 32, and is **required on
  any rule that binds a BODY key** — declare `body_keys: []` for a rule whose only vocabulary is what
  it binds. A bound key is implicit (its VALUE is checked), so listing it here is refused as a
  passthrough. A top-level key outside the declaration is forwarded and named on the hop's record;
  what constrains a body key is a `bind` on it. Absent means the body is never parsed at all, which
  is legal only for a rule with no body binds: an opaque upload (`POST /v2/files` carries raw file
  bytes, not JSON — while a query bind can still pin the scope those bytes land in). Refused on a
  bodyless method.
- `caps` (legal on any rule) is that shape's **per-session budget**: `max_uses`, the number of hops of
  it a session may have AUTHORIZED, and `max_total_bytes`, the aggregate REQUEST body bytes those hops
  may carry. Both are required together and both must be positive — a count with no byte bound (or the
  reverse) is a half-closed surface, since one hop can carry a whole body, and a zero cap is a shape
  that admits nothing, which is spelled by not declaring the shape. Every other dimension here decides
  ONE hop; this is the only one that bounds a session's TOTAL traffic through a shape. It is charged on
  each authorized hop (a refusal spends nothing) and checked LAST, after every authority check, so a
  hop that also contradicts the sentence is refused for THAT — volume is the least interesting thing
  wrong with it. An overrun refuses before the credential and burns the session, like every other
  overreach. The per-hop ceiling is separate and is a daemon setting, not language
  (`relay_max_body_bytes`).
- A bound or asserted field must be a **required `str`** field classed `identity` or `side_effect`, and
  must be either an `execution_target` (the sentence pins it) or `fixed` (the template pins it). The
  relay never enforces a value nobody constrained. (A `path.*` bind is the exception that proves it: it
  names no field at all, it names a capture.)
- `consumes` must equal the bound-and-asserted field set exactly — a relay executor reads nothing else.
- `money` and `request_evidence` are refused on a relay verb.

A hop whose method and path match no shape, or that contradicts a bind, is refused before the
credential is attached. What that refusal then costs
— the session burn, the other close causes, and the receipt each close carries — is grant-kernel
enforcement, not language: `docs/REFERENCE.md` → Grant Kernel → *Relay enforcement (validated per
hop)*, which also carries what the declared key sets are for and what happens to a key outside them.

### `fixed` — the template pins a field's only legal value

```yaml
- { name: environment, type: str, required: true, class: side_effect, binding: exact_resource_pin, fixed: live }
```

`fixed` is legal only on a required `str` field, and the literal is `[a-z0-9_-]{1,64}`. A request naming
any other value is DENIED at admission — before an approvable card exists — and the stored frozen
resource is re-checked against it before claim. It is what makes a verb name a promise when the
value IS the verb's identity.

Use it sparingly: a value an operator might legitimately want to vary belongs to the SENTENCE
layer, not the template. `vercel.deploy` is the shape to copy — its `target` is a
sentence-adjudicated execution target (`allow … where target = "preview"`; production falls to the
fail-closed default), not a template-frozen value. `fixed` is right only where the alternative
value would be a DIFFERENT verb, not a different policy.

---
