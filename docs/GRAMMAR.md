# GRAMMAR — the language, at the design level

**Status: DESIGN RATIONALE. Companion to `docs/LANGUAGE.md`, which is
the normative authoring reference (what parses, what the validator refuses). This doc records
WHY the language is shaped the way it is and which properties its evolution must preserve.
When the two disagree about a validator rule, LANGUAGE.md wins; when a proposed feature
violates an invariant stated here, the feature loses.**

## 1. Three sub-languages

Cermet's grammar is three coupled languages:

| sub-language | who writes it | artifact |
|---|---|---|
| **template language** (LANGUAGE.md) | the vendor authors + signs (build-time) | a verb: closed field schema + frozen recipe with typed holes |
| **sentence language** | humans only | a rule: `allow <set> [where <authored predicates>]` |
| **the request** | agents | name a verb, fill its holes |

The request language is **deliberately degenerate**: nothing is composed at request time and the
agent authors no expression. That degeneracy is the security model, not a limitation: the
entire expressive power available to the untrusted party is "pick a ratified shape, fill its
typed holes."

Corollary: authority never lives in the projection layer. MCP is a wire protocol over this
schema (one verb → one tool, mechanically); the sentence never travels over it. Approvals and
ratification are human-surface acts — the rule-authoring half of the language is structurally
absent from the agent surface.

## 2. The type system: two orthogonal axes

Every field carries a **data type** (`str`, `int`, `bool`) and an
**authority type** — its class × binding (`identity`/`side_effect`/`free_payload`/`secret`/
`read_filter` × `exact_resource_pin`/`exact_or_pattern_list`/`bounded`/`unbound`). The class×binding
consistency rule (LANGUAGE.md §3) is a kinding rule: authority-bearing classes must be
pinnable, varying classes must be unbound, and illegal combinations do not parse.

The authority type is an information-flow label, and it is enforced syntactically: there is no
flow analysis, because grammar position does the work.

- `secret` is the high label. It may flow only into a request body — never a path, query,
  argv, or raw audit line. Non-interference by grammar position.
- `free_payload` is the untrusted-low label. It may never occupy an authority position (a
  URL segment, a query value, a bare argv token without the `--` guard).
- The `--` flag guard enforces one theorem: **data can never be promoted to syntax**. This is
  the anti-`eval` property and the whole injection defense.

## 3. Binding time: authority narrows monotonically as it freezes

| stage | act | what freezes |
|---|---|---|
| 0 | sign the shape (build-time) | the shape — exact bytes, content-hashed |
| 1 | request + approve | the resource — every field value, `free_payload` included |

Each stage can only **narrow**, and nothing defers past approval: a `free_payload` value is
supplied in the original request and frozen before the grant mints — there is no execute-time fill
channel. Signing fixes the shape; the request fills the holes the shape left open; nothing is left
free afterwards. "Approved fields == executed fields" is the soundness property of that staging.

**Where stage 0 executes is a product decision, not a theory change.** Ratification of the
vendored catalog happens at Cermet's build time — ratification as signing. Should user-side
ratification ever be added, for agent-authored vocabulary or the long tail of user-specific verbs,
the staging model above is unchanged; only the site of the human act moves.

## 4. Totality: the language is sub-Turing on purpose

A verb is ≤8 linear steps, forward-only dataflow, no branch/loop/arithmetic (LANGUAGE.md §9).
Consequences:

- Every safety question about a verb is decidable by inspection.
- Execution is model-free and deterministic — no model sits inside the execution path: a
  frozen recipe replays; nothing reasons at runtime.
- **The design invariant behind both:** the language's expressiveness ceiling is HUMAN REVIEW
  BANDWIDTH. Ratification is the system's axiom-introduction rule; everything downstream is
  derivation. The type system proves shape properties (no injection, no secret egress, no
  unpinned URL authority, monotone narrowing). It cannot prove provider semantics (that
  `POST /refunds` doesn't also send email) — that residual trust enters at exactly one rule,
  ratify, so the grammar's job is keeping the axioms small enough for a human to check.

## 5. The sentence language: stay conjunctive (the containment invariant)

The least-access "optimizer" rests on one relation: **containment** — sentence A ≤ sentence B
iff every request A admits, B also admits. The load-bearing fact: deciding containment is
intractable for a general predicate language and decidable for a *conjunctive* one.

**Invariant: the `where` grammar stays a conjunctive fragment** —
`field = literal ∧ field ≤/≥ literal ∧ field in {finite set}` — so containment stays computable.
Disjunction is survivable (the existing `Vec<Scope>` DNF is the normal form comparisons need);
negation and arbitrary arithmetic are refused, at the same doctrinal force as fail-closed.

**Corollary: a decision is a pure function of `(request, corpus)`.** The fragment above is evaluated
against the frozen request and nothing else — no counter, no window, no accumulated total is read
when a request is decided. The one extension that broke this, the temporal clauses
`budget … per <window>` / `rate … per <window>`, is GATED OFF by the daemon setting
`language_temporal_clauses`: with the shipped default a corpus containing one is refused at
admission, naming that setting. The machinery is gated rather than deleted, and `docs/LANGUAGE.md`
§4 carries it as not-live grammar. This matters to the optimizer capabilities below — containment
between two rules is decidable only while both sides are decided by the same frozen request, which
is exactly what a windowed counter is not.

**Literal-to-value matching is by kind, with no exceptions.** An integer literal matches an `int`
field, a double-quoted string a `str` field, `true`/`false` a `bool`. There is exactly one spelling
per kind because the surface dialect makes strings mandatory-quoted, which is what let the last
exception go.

That exception once let an integer literal ALSO match a `str` **identity** field declaring
`format: uint`. Its whole justification was lexical — under the old dialect a quoted scalar on an
identity field meant *resolve this name* and the bare form lexed as an integer, so a bare-decimal
identity had no spelling at all. With quoting mandatory and literal, `number = "3"` pins it
directly and the rule has nothing left to buy; it is dissolved, along with the declaration flag
that granted it. `format: uint` survives as what it always independently was: the admission shape
for a request VALUE (canonical bare positive decimal), never a matching rule.

**Range comparators still resolve only on `int` fields, and containment stays sound by refusing.**
`<=`/`>=` compare against integer values, which a string field never carries. `implies` is
therefore declaration-aware: on a string field it refuses `field = "3" ⇒ field <= 4`, because a
rule that admits something cannot imply one that admits nothing. Soundness of the containment
primitive — which sentence minimization, permission ablation and policy diffing all rest on — is
bought by refusing the implication, never by widening a coercion.

What decidable containment buys — the search of grant space for the least authority that still
admits what the agent actually does:

- **Sentence minimization** — replace five rules with one, provably no widening.
- **Permission ablation** — shrink a rule to what receipts show was exercised, provably.
- **Policy diffing** — "this change widens authority here" as a decidable check; what makes
  a policy-PR review real.
- The shipped policy-suggestion engine is the seed of this optimizer.

Every predicate feature is paid for in optimizer capability. That is the review question for
any proposed `where` extension.

## 6. No syntax engine

The sentence language gets **no parser framework, no grammar file, no AST machinery**. This
is not corner-cutting; it follows from §5 and it is what keeps the implementation
non-brittle:

- **The language IS the data structure.** A rule is a versioned serde struct — a selector
  plus a conjunct list — and THAT is the canonical form (stored, evaluated, compared for
  containment). The one-line text syntax (`allow <selector> where <field> <op> <value>
  [and …]`) is a **codec** over the struct: a hand-rolled tokenizer and printer, round-trip
  tested, on the order of a hundred lines.
- **Extension paths are variant additions, never rewrites.** A new comparator = a new
  `Pred` enum variant + one codec arm + one eval arm + one containment arm. A new selector
  granularity = a set name. Disjunction = another rule line (the rule *list* is the DNF —
  exactly how `Vec<Scope>` already works). Nothing in the invariant-permitted future
  (§5: conjunctive, no nesting, no negation, no arithmetic) ever needs precedence,
  parentheses, or a parse tree.
- **The invariant is what makes hand-rolling safe.** Hand parsers rot when languages grow;
  §5 forbids the growth that rots them. If a proposed feature cannot be tokenized flat
  (`field op literal` conjuncts), the feature — not the parser — is what's wrong.
- **Evaluation and containment stay structural:** eval = conjunct-wise check against the
  frozen request; containment = pairwise implication (interval/set inclusion per conjunct).
  Both are loops over a Vec, not tree walks.

## 7. The `bounded` binding

`allow stripe.support where amount <= 50` is the motivating rule for the binding spectrum's third
point: `amount` is authority-relevant yet must vary per request. `bounded` records that contract
shape without making the example's numeric predicate mandatory:

- **Contract shape:** `bounded` is legal only on an integer `side_effect` field. This kinding rule
  remains mandatory; it records that authored sentence predicates may express an integer `<=` or
  `>=` family rather than one exact value.
- **Shared sentence semantics:** predicate depth is the author's choice. The evaluator checks a
  numeric bound when the sentence contains one, but derives or injects no predicate from contract
  metadata. A predicate-free matching allow therefore covers a `bounded` field as a deliberate broad
  definite allow.
- **Containment and fail-closed:** authored bounds compose by interval inclusion, so §5 survives
  unchanged. A request with no matching allow still denies; an omitted predicate on a matching allow
  is authored breadth, not an unresolved decision.

## 8. Pointers

- `docs/LANGUAGE.md` — the normative authoring reference (the vendored catalog is authored from it).
- `docs/REFERENCE.md` — the settled engineering design (grant kernel, field class × binding).
- `crates/cermet-core/src/` — `contract.rs` (template validation), `policy/` (`Vec<Scope>`
  DNF), `templates.rs` (recipe expansion).
