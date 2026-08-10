# Security contracts, and the evidence matrix that decides whether one can be checked

**Status:** implemented in 0.17.0, corrected in 0.17.1 · **Written:** 2026-08-10 ·
**Step four**

## Two halves of one thing

This document covers two roadmap items together because they are one mechanism
seen from two ends:

- **the evidence matrix** — what a recorded execution *can* answer, made visible
  and gateable rather than inferable from a skip note;
- **security contracts** — what an application *must* be true of, written by the
  team that owns it, as data rather than as code.

They meet at a single sentence, and it is the sentence this whole release is
about:

> **A contract that requires evidence its producer never records is
> `indeterminate`. Never a pass, and never a finding either.**

Not a pass, because nothing was checked. Not a finding, because accusing an
application of a failure its instrumentation merely cannot describe is a false
red, and a false red is not a safer error than a false green — it is the error
that teaches a team to ignore the tool.

## Why contracts, and why now

Guardana has three extension points and they cover three different questions.
A **rule** is a test. An **evaluator** is judgement. A **target** is the system
under test. What none of them expresses is the fourth question, which is the one
that actually decides whether an AI application is safe:

**what is this application allowed to do?**

Which principals exist. Whose data is whose. Which actions need a human. Which
boundary may never receive a credential. Which sink is simply off-limits.

No public framework knows any of that, and no generic scanner can. OWASP can say
*excessive agency is a risk*; it cannot say *the checkout agent may call
`payments.refund` and nothing else*. That gap used to be answered with "you can
write a custom rule", and that answer stopped being a differentiator: policy
libraries are now a mainstream red-team feature, and "write Python" is a worse
offer than "write a file your security reviewer can read".

The roadmap's fifth thesis property already stated the position — *the
application's threat model belongs to its owner*. This is that sentence made
executable.

**Deterministic first, and generated attacks never before the invariants are
provable.** An attack that "seems to have worked" against an invariant nobody
wrote down is a screenshot, not evidence. The order is: state the invariant,
prove it holds or does not on a real recorded execution, and only then start
generating traffic aimed at breaking it.

## Decision 1 — a contract is a third entity, not a rule and not a profile

**Rejected: extend the profile.** A `guardana.yaml` *selects* among checks that
already exist and sets the bar they have to clear. A contract *creates* checks
nobody shipped. Folding the second into the first means a typo in a severity
threshold and a typo in a security invariant are the same class of event, in the
same file, reviewed by the same glance — and it makes the profile a document that
is simultaneously configuration and assertion. The profile stays the run's policy.

**Rejected: a new kind of YAML rule.** Superficially attractive, because YAML
rules already exist and are already loaded from user directories. It fails on
vocabulary and on audience. A YAML rule's vocabulary is *send this prompt, grade
it with that evaluator*; a contract's vocabulary is the nouns of an application —
tenants, boundaries, scopes, sinks, approvals. And a rule is written to be
*shared*: the catalog, a pack, a registry one day. A contract is deliberately
private to one application, lives in that application's repository, and is
reviewed alongside the code that has to satisfy it. Two documents with opposite
distribution stories should not be the same document.

**Accepted: a separate document that compiles into ordinary rules.**

```
contract.yaml  ──load──▶  SecurityContract  ──compile──▶  Rule objects
                             (data)                        (registered)
```

The contract is data all the way to the point where it becomes a `Rule`, and from
that point on it is an ordinary rule. This is not a cosmetic choice; it is what
buys the whole feature for almost nothing:

| Already works, unchanged | Because the compiled assertion is a `Rule` |
|---|---|
| skipped when the target cannot satisfy a capability | `RuleMeta.required_capabilities` |
| evidence redaction | the `Finding` goes through `EvidenceRedactor` |
| baselines and waivers | findings have fingerprints |
| `diff` between two runs | rules carry a digest, coverage carries a fingerprint |
| the collector envelope | normalized `Finding`, no new path |
| `--rules` include/exclude globs | ids are namespaced `contract.<name>.<assertion>` |
| `plan` costing | `estimated_requests` is 0; reading a file sends nothing |

The engine gains one loader and five assertion kinds. It gains no new execution
path, no new report channel that reporters must learn, and no second definition
of what a finding is.

### What the id looks like, and why it is namespaced

`contract.<contract-name>.<assertion-id>` — `guardana.*` stays reserved for
built-ins, exactly as a third-party pack's ids do. A profile can exclude a whole
contract with `contract.checkout.*`, and a baseline can waive one assertion
without waiving the rest.

## Decision 2 — assertions do not get an evaluator

**Rejected: a `contract` evaluator.** An `Evaluator` turns a model *response*
into a `Verdict`, and it exists because grading natural language is a matter of
degree that needs a measured confidence. A contract assertion compares two values
a producer already recorded. Its confidence is 1.0 by construction, and the
comparison has no free parameters to calibrate.

The concrete danger of routing it through an evaluator is worse than the
redundancy: `evaluator:` is configurable, and a configurable evaluator can be
pointed at `llm_judge`. A tenant boundary graded by a language model is precisely
the inversion this release exists to prevent — the reason contracts come *before*
generated attacks is that they are **provable**, and an evaluator seam is an
invitation to make them merely plausible.

What assertions do reuse is the `Verdict("inconclusive", 0.0, …)` shape when they
decline, because declining is the same act everywhere in this codebase and should
look the same in a report.

## Decision 3 — the contract document is versioned, and unknown keys are fatal

Principle 11: a document a user keeps is a contract, and a schema change without a
version strands the evidence somebody relies on. A security contract is the most
literal case of that in the whole project — the file *is* the team's threat model.

```yaml
schema_version: 1
name: checkout-agent
```

- `schema_version` is **required**. Rejected: optional with a default of 1. A
  document with no version is exactly the document whose meaning you cannot pin
  later, and defaulting reads a future file as a past one.
- A version this build has never heard of is **refused**, never read
  optimistically — the same reasoning as `load_report`: a newer writer may have
  changed the meaning of a key this reader still recognises.
- Older versions migrate forward **in memory, one step at a time**, keyed by the
  version the document *is*. The table is empty at v1 because there is nothing
  behind it yet; the machinery and its refusal path exist and are tested, so the
  first migration is a table entry rather than an architecture.
- **No `contract migrate` command.** `guardana run migrate` rewrites a *generated*
  document on disk. A contract is hand-written and owned by the team; a tool that
  rewrites it would be editing their source. When v2 arrives, the migration
  happens at load and the upgrade note tells them what to change.
- **Unknown keys raise at load.** A misspelled `assertoins:` that loaded as an
  empty contract would produce a run that checks nothing and exits `0` — a gate
  you think you configured but did not, which is worse than no gate. Same
  treatment as `guardana.yaml`, for the same reason.

## Decision 4 — five assertion kinds, each provable from what a trace already carries

Each one is deterministic, offline, and needs no field the domain model does not
already have. The dimension each one needs is what connects this half of the
release to the other half.

| Kind | The invariant | Needs |
|---|---|---|
| `tenant_boundary` | one execution serves one tenant, and every document it retrieved belongs to that tenant | `retrieval` |
| `approval_required` | an action matching a selector was preceded by a *granted* approval | `approval` + `effects` |
| `allowed_scopes` | a hop across a named boundary exercised only scopes on the allow list | `delegation` |
| `credential_boundary` | a named boundary never received a credential at all | `delegation` |
| `forbidden_sink` | no side effect landed on a sink the application forbids | `effects` |

**`tenant_boundary` is not a duplicate of `guardana.trace.cross_tenant_retrieval`.**
The built-in compares one retrieval's tenant against the documents that retrieval
returned — a within-call check that needs no application knowledge. The contract
asserts something only the application's owner can state: that the *whole
execution* stays on one tenant. An agent that retrieves for tenant A, then
retrieves for tenant B in the same run, is invisible to the built-in and is a
finding here.

**`forbidden_sink` counts `attempted` as well as `executed`, by default.** An
agent that tried to open a shell and was stopped is a fact about the agent, and a
contract saying "never shell" is violated by the attempt. `failed` is
configurable but off by default: a failure is the system refusing, which is the
opposite of a finding, and defaulting it on would report every working guardrail.

**The taxonomy mapping belongs to the assertion *kind*, not to the author.**
Principle 5 requires every rule to map to a public framework, and a contract
author should not have to know OWASP's numbering to write down that payments need
approval. Each kind therefore carries a fixed mapping. Rejected: letting the
document set `taxonomy:`. A mapping a team invents to make a report look complete
is worse than no mapping, and the mapping is the part that has to survive somebody
else's audit.

## Decision 5 — the meeting point: unverifiable is indeterminate, unconditionally

This is the part that is easiest to get wrong, and the mechanism that already
existed gets it wrong on its own.

A compiled assertion declares `required_capabilities`, so the runner already skips
it when the producer does not record that dimension, with a reason. **But a skip
only reaches the gate through `fail_on_skipped`, which defaults to `false`.** So
the default path for "the contract you wrote could not be checked at all" is a
run that exits `0`. That is a false green, and it is the one this release is
specifically about.

Why the default is nevertheless right for *built-in* rules: most skips are
ordinary. A file rule against an endpoint, a tool-calling rule against a model
nobody claimed could call tools — nobody asked for those, they simply do not
apply. Turning every one of them into a red build would make the setting useless.

So the distinction is not "was a rule skipped" but **"did the operator demand
this coverage"**, and demanded coverage is unconditional:

```yaml
# guardana.yaml — the operator demands it directly
trace:
  require: [identity, approval, effects]
```

```yaml
# contract.yaml — the operator demands it implicitly, by writing an assertion
- id: payments-need-a-human
  type: approval_required     # ⇒ requires `approval` and `effects`
```

Both produce the same thing: a set of **required dimensions**. One mechanism, two
sources, checked once against what the trace declares. Anything required and not
recorded is a `CoverageShortfall` on the result, and `gate_outcome` returns
`INDETERMINATE` for a non-empty shortfall with no policy toggle in the path.

**Rejected: a new `SkipReason` that the gate treats specially.** It would put the
same fact in two places — the skip list and the requirement check — and two
representations of one fact eventually disagree. The skip stays exactly what it
is (this rule did not run, here is the capability it needed); the shortfall is the
separate statement that the run is not entitled to a verdict.

**Rejected: recording the shortfall as a `CheckError`.** It nearly fits —
`fail_on_error` defaults to `true`, so it would block by default — and it is
wrong for two reasons. An error means a check *malfunctioned*; a producer that
does not emit approvals has malfunctioned in no way at all. And `fail_on_error`
is a toggle, so "unconditional" would have been one line of YAML away from false.

**Rejected: computing it in the CLI and not recording it.** The run document
would then be indeterminate for a reason it does not state, `diff` could not see
it, and the collector would receive a verdict with no cause. A run whose
conclusion is not in its own evidence is the failure this project has fixed
twice already.

### The implied demand ends where the assertion does *(corrected in 0.17.1)*

The two sources are the same statement — *I am gating on this coverage* — but they
are not owned by the same person, and 0.17.0 shipped as though they were. The
implicit demand was computed from every applicable assertion before the policy said
which rules would run, so `rules.exclude: ["contract.checkout.*"]` switched the
assertions off and left their requirement standing. The run then went
`indeterminate` for missing evidence that no surviving check would have read.

Measured rather than reasoned about: the same trace, the same six rules run and
seven skipped, exit `0` with the assertion deleted from the contract and exit `2`
with the assertion present and its rule excluded. Identical work, opposite verdict.

That is a **false red**, and this project owes it the same treatment as a false
green. A tool that accuses a run of missing coverage nobody asked for gets its
coverage demands turned off, and then it is protecting nothing. So the implication
now lives and dies with the assertion: `wire_contracts` demands only the dimensions
of assertions this run will actually check, using `refused_by_this_run` — the same
predicate composed from the two things the runner's plan already consults, with a
test asserting the predicate agrees with the plan the runner really builds rather
than with a second reading of the same conditions.

`trace.require:` is deliberately untouched by this. It is a sentence the operator
wrote, not an implication of a check, and a team paying for instrumentation is
entitled to demand it arrive whether or not a rule currently wants it.

**And the exclusion is printed.** Subtracting the demand silently would leave
`contracts: 1 assertion(s) apply to this execution` standing over a green report
about a rule nothing ran — a true sentence about loading and a false one about
grading. Recording it as evidence in the saved run needs a new `SkipReason` value,
which is a persisted-schema change; the roadmap carries it with that reason.

### Ordering against a finding

A finding still outranks a shortfall: a run with both is `FAIL`. The finding is a
fact somebody must act on, and reporting "we could not tell" instead would bury
it. The shortfall joins the other question-left-open branches, above them in the
sense that it needs no toggle.

## Decision 6 — a contract can say "not mine" without that being a pass

A team with three agents has three contracts. Running the checkout contract
against a support-agent trace must not print a green tick, because nothing about
checkout was verified.

```yaml
applies_to:
  ai_system: checkout-agent
```

Matched against `--ai-system`, which `analyze-trace` already takes and which the
documentation already says is **never guessed**. That is exactly the right key:
it is operator-supplied, explicit, and already recorded in the run manifest's
deployment block.

Three branches, and the third is the one that matters:

| `applies_to.ai_system` | `--ai-system` | Outcome |
|---|---|---|
| absent | anything | applies — a contract that names no system is about whatever you point it at |
| `checkout-agent` | `checkout-agent` | applies |
| `checkout-agent` | `support-agent` | **not applicable** — skipped, recorded, not counted as coverage, not a pass for those assertions |
| `checkout-agent` | *not given* | **refused** — the contract cannot know whether it applies, and a contract that cannot know must not report clean |

`NOT_APPLICABLE` is the first `SkipReason` whose `is_coverage_gap` is `False`, and
the property was written in 0.7 for exactly this: *"a future reason that is
genuinely benign has somewhere to say so, instead of being quietly folded in with
the ones that are not."* It is not a coverage gap because nothing was missing —
the contract was about something else.

**But a contract layer that graded *nothing* is a shortfall.** If contracts were
loaded and not one assertion applied to this trace, the run is `INDETERMINATE`.
That is the wrong-file case — the CI job that points at the wrong trace, or the
`--ai-system` value that drifted after a rename — and it is the only way the
not-applicable state could otherwise become a silent green.

**Rejected: skipping non-matching contracts at load.** A typo in `applies_to`
would then silently disable the contract, which is a fail-open with no trace of
itself. Loading it and reporting it as not applicable keeps the mistake visible.

## Decision 7 — `trace inspect` prints a matrix, and never a percentage

The mechanism has existed since 0.14 and was visible only as a skip note on a run
that had already happened. An operator could not gate on it, because they could
not see what was missing until a rule was missed.

```
$ guardana trace inspect run.jsonl

dimension      declared  records  needed by  unlocks
messages       yes       12       3 rule(s)  -
retrieval      yes        4       2 rule(s)  -
approval       no         0       2 rule(s)  0 rule(s)   ← not instrumented
memory         yes        2       0 rule(s)  -
```

Two columns rather than one, because the difference between them is a real and
different failure. **`declared`** is what the producer says it emits; **`records`**
is how many spans actually carry that dimension. A producer that declares
`approval` and emits none is *gradable* — that is the "recorded, absent" state
where a finding lives. A producer that declares nothing has told rules to stand
down. Showing only the first would hide a header that lies; showing only the
second would read an execution with nothing to approve as an instrumentation gap.

**No single coverage percentage, and this is a rule rather than a preference.**
One number hides which dimension is missing, and which dimension is missing is the
entire question. "78% covered" is compatible with having no identity evidence at
all, and a team that gates on a number rather than on a name will ship the day the
missing 22% is the 22% that mattered. The roadmap already refuses a universal AI
risk score for the same reason; this is that decision applied one level down.

**`needed by` counts installed rules, not a fixed list.** It is computed from the
registry, so a rule pack a team installed is counted and the number cannot rot the
way a hand-written table does. A dimension no installed rule needs says `0`, which
is honest and immediately useful: `memory` is instrumented by several frameworks
and has no capability mapped to it today, and the matrix says so out loud instead
of leaving it looking covered.

**`unlocks` is a separate column because it answers a separate question, and one
column answering both answered the wrong one.** `needed by` is how many rules read
the dimension; `unlocks` is how many would start running if it were the next thing
instrumented — which is only the rules with nothing else missing. `approval` above
is needed by two rules and unlocks neither, because both also want side effects. A
team reading the single column budgeted a sprint of instrumentation and gained no
check. Added in 0.17.1 after `guardana trace inspect` was run against a real
adapter's output and the two numbers turned out to disagree.

**It opens a file and no socket.** Same input `analyze-trace` takes, no
network, no run document written, exit `0` unless the file cannot be read. An
operator inspects the evidence they already have before deciding what to require.

### Rejected: folding this into `analyze-trace --dry-run`

`analyze-trace` grades. A flag that makes a grading command not grade is a command
with two personalities and one exit-code contract, and the coverage question is
asked at a different moment by a different person — before writing a policy, not
while gating a build.

## What this does not do

Stated so nothing here implies otherwise.

- **A satisfied contract is not a secure application.** It says these invariants
  held in this recorded execution. The attacker's request may simply not be in the
  file, and `usage-analyze-trace.md` already says so about the built-ins.
- **No contract assertion sends anything.** These grade a recording. The generated
  attacks that would try to *break* an invariant are the next step and are
  deliberately not in this one.
- **No regulation and no vendor appears in the engine.** An assertion kind names
  tenants, scopes, boundaries and sinks — domain nouns, not framework names. The
  OWASP mapping is data on the kind, as every other mapping in this repository is.
- **No shipped framework adapter can carry four of the five kinds.** Measured in
  0.17.1 against a real run from each, not against a fixture:

  | Producer | Records | Kinds it can grade |
  |---|---|---|
  | pydantic-ai 2.27.0 | `messages`, `tools` | none |
  | llama-index-core 0.14.23 | `messages`, `retrieval` | `tenant_boundary` |
  | crewai 1.15.14 | `messages`, `handoff` | none |

  `approval_required`, `allowed_scopes`, `credential_boundary` and `forbidden_sink`
  decline on all three, because no framework records approvals, delegations or side
  effects of its own accord. The declines are correct — that is
  [decision 5](#decision-5--the-meeting-point-unverifiable-is-indeterminate-unconditionally)
  doing its job — but they mean **contracts today serve a team that instruments its
  own agent**, through the native dialect, an OpenTelemetry exporter it controls, or
  `--write-trace` output it fills in. The one measured success is the shape of the
  win: a two-tenant LlamaIndex run produced a `critical` `tenant_boundary` finding
  that no built-in rule could reach, because whether one execution may serve two
  customers is knowledge only the owning team has.

## Deferred, with the reason

| Deferred | Reason |
|---|---|
| **Contract assertions over a live endpoint** | every kind here reads recorded authority — a delegation's boundary, an approval's outcome. A live probe would have to *provoke* the action to observe it, which is generated attack traffic, and the stated order is invariants first |
| **A contract-authored taxonomy mapping** | a mapping a team invents to fill a column is worse than none, and the mapping is what has to survive somebody else's audit. If a real need appears it is an *additional* reference beside the kind's, never a replacement |
| **Custom assertion kinds from a plugin** | a sixth kind today is a pull request; an extension point for kinds is an API that 1.0 would freeze. It belongs with the pack manifest and `pack validate`, where compatibility is expressed, not bolted to the loader |
| **`tenant` on `Identity`** | the boundary check would be sharper if the acting principal carried a tenant, and adding a field to a frozen-at-1.0 type to serve one assertion is how a domain model acquires an escape hatch. Retrieval already carries the tenant on both sides, which is where the failure is observable |
| **Requiring dimensions for `probe` and `scan`** | `trace.require` is a statement about a *producer's* instrumentation. The equivalent for a live target is "this provider must support tool calling", which is a different question with a different failure mode, and inventing one syntax for both before either has a user is how a schema acquires a shape nobody wanted |
| **A shortfall for a dimension declared but never recorded** | that is the gradable state, not a gap. Turning "you instrumented approvals and this execution needed none" into indeterminate would fire on every well-behaved run — the exact false red the honesty boundary exists to prevent |
