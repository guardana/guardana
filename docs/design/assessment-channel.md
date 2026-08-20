---
title: "The assessment channel"
nav_order: 21
summary: "why a run that records only problems cannot answer whether anything got better, what an Assessment carries that a Finding deliberately does not, and why the passes are the half that matters"
status: accepted
---

# The assessment channel: recording what was measured, not only what was wrong

**Status:** implemented in 0.22.0 · **Written:** 2026-08-20

## The question the finding channel cannot answer

Every channel a run had — `findings`, `unverified`, `errors`,
`coverage_shortfall` — records a *problem*. A check that ran and was satisfied
left nothing behind but its id in `rules_run`.

That is enough to gate a build. It is not enough for the question everybody asks
next: **did this get better?**

Fewer findings has three causes, and the finding count cannot separate them:

1. the system improved;
2. the test got weaker — a prompt was reworded, an expectation loosened;
3. the sample changed — a budget cut the run short, a judge stopped answering,
   a rule was excluded.

Guardana already refuses to confuse (1) with (3) at the *rule* level: `rules_run`
names rules instead of counting them, `unverified` keeps "could not grade" apart
from "clean", and the coverage fingerprint says when two runs had different
reach. What none of that gives is a **denominator**. Three findings out of four
prompts and three out of four hundred produce the same report.

## What was rejected

**A `Finding` with `severity: info` per passing check.** It would have needed no
new channel, and it is wrong in the way that matters: a measurement has a
denominator, a direction and an uncertainty, and a defect has a severity and
somebody who has to act on it. Folding them together is how a release ends up
gated on "82/100" — a number with no visible parts, no sample size and no
version of the thing that produced it.

**Changing `Rule.run()` to return a richer type.** `Iterable[Finding]` is the
contract every third-party rule implements. Widening it breaks all of them at
once, for a feature most of them will never use, which is exactly the adoption
cost the roadmap's API-stability item exists to avoid. `RuleContext` grew a sink
instead: a rule that measures calls `ctx.record(...)`, and a rule that does not
is unchanged.

**Making artifact rules record one assessment per file read.** Tempting —
it would have produced a big denominator immediately — and dishonest. "I read
this file and found nothing" is not a measurement, and putting hundreds of them
into the denominator would deflate every attack-success rate the channel is
supposed to make legible.

## The shape

```text
Assessment
  case_id      what was measured — stable across runs, different when the case differs
  assessor     what produced the verdict (an evaluator id, or a rule grading in code)
  subject_ref  what it was measured against
  status       measured | inconclusive | error | skipped
  passed       the boolean reading, or None when the case has no pass/fail sense
  value/unit/direction/threshold   the numeric reading, when there is one
  confidence   how much the assessor trusts itself, when it can say
  dataset      which versioned corpus the case came from
  rationale/tags
```

Four rules the shape enforces:

**`inconclusive`, `error` and `skipped` never become zero.** They are statuses,
not values, and `ScanResult.measured` excludes them from the denominator. A rate
computed over cases nobody could measure describes the harness, not the system.

**`passed` is `None` for an ungraded case, never `False`.** A judge that could
not read a reply has not observed a failure. Counting it as one makes a broken
grader look like a worsening model — and that is the direction somebody acts on.

**`direction` is recorded, never inferred.** A latency of 900 and a score of 900
do not move the same way, and a comparison that guesses is wrong half the time.

**`threshold` is recorded per run.** A bound that moved between two runs changes
the verdict without changing the system; a comparison that cannot see the old
bound reports that as a regression.

## `case_id`, and why it is a hash

A positional id (`rule#0`) is stable exactly until somebody reorders the prompts,
at which point every case pairs with a different one and the comparison is
confidently wrong — which is worse than empty, because it reports movement that
did not happen.

So `case_id_for(rule_id, *text)` hashes the text that distinguishes the case.
Reordering is then a no-op, and *rewording* produces a new case — the honest
reading, because a rewritten prompt is not the same test. The digest also means
a case id may appear in a report that redacts the prompt it came from.

## Comparability, and the refusal

Two assessments may be compared only when `case_id`, `assessor` and `dataset`
all agree. A YAML rule's `dataset` is its own declaration digest — the same hash
`diff` already uses to say "this rule's definition changed" — so there is one
definition of "the same test" in the project rather than two that drift.

`guardana diff` pairs on `case_id` alone and *then* checks the other two. Pairing
on the full key would make an edited expectation look like one case disappearing
and another arriving: two changes, both wrong, for one edit in a text editor.
A case whose definition moved is counted as `incomparable` and left out of every
rate, with a note saying so.

## What the gate does with it

Almost nothing, deliberately, and in exactly one direction.

A per-case pass→fail already reaches the gate as a `Finding`, so counting it
again here would make one event look like two — in the channel the project is
most careful about. What the gate gained is a single new refusal:

> A run that recorded assessments and measured **none** of them is
> `indeterminate`.

That is `verified_nothing` for the measurement channel, and it needs its own line
because the two are carried separately. A suite whose judge stopped answering
records an assessment per case, grades none, and produces no finding at all — so
every other test in the gate is satisfied and a pass rate over zero cases would
be reported as a pass.

## What is deferred, and why

**The collector does not store assessments yet.** It aggregates findings,
`unverified` and errors, so it can say a system is accumulating security problems
and cannot yet say whether its answers got better. Carrying the channel into
PostgreSQL means a migration, and a migration under a schema that will change
shape once suites and datasets land costs more than waiting. Tracked on the
roadmap under continuous assurance.

**Suites, datasets and statistics.** Confidence intervals, minimum sample sizes
and slice comparison need a `Dataset` and a `Suite` first. The channel is the
carrier; those are the payload.

**Numeric assessors.** The shape carries `value`, `unit`, `direction` and
`threshold`, and no built-in rule produces one yet. That is a deliberate order:
the persisted shape is the expensive thing to change, and shipping it empty costs
one field and buys the migration.

## See also

- [`../usage-run.md`](../usage-run.md) — the saved-run document, including this channel
- [`../usage-diff.md`](../usage-diff.md) — what a comparison does with it
- [`capability-protocols.md`](capability-protocols.md) — the other half of the 0.22 contract work
