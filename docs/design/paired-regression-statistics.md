---
title: "Paired regression statistics"
nav_order: 74
summary: "how diff and monitor decide that a measured sample got worse — an exact test on the discordant pairs, a minimum effect, a minimum sample, and a refusal for anything short of all three"
status: proposed
---

# Paired regression statistics: "worse" with a p-value, or "cannot tell"

**Status:** proposed · **Written:** 2026-09-02 · **Cycle 3 of the extensibility program** ([`audit-0.22.md`](audit-0.22.md))

## Where 0.22.0 stopped

`guardana diff` pairs two runs' assessments on `case_id`, refuses a pair whose
assessor or dataset changed, and prints the population: paired, incomparable,
gone, new, blinded, and the two pass counts. It deliberately prints no percentage
and gates nothing, because "16 → 15 passing over 21 cases" is a sentence a reader
can weigh and "5% worse" is not. That was the right place to stop until there was
a sample worth a statistic. Suites are that sample.

## The question, stated precisely

Over the cases both runs measured like for like, is the second run worse than
the first by more than noise could explain, by at least an amount somebody said
they care about, on a sample at least as large as somebody said they need?

Three conditions, all three required, each named in the output when it fails.
An alert missing any of them is the pager-attached random number generator the
intake design refuses.

## Boolean cases

Every paired case is one of four: pass→pass, fail→fail, pass→fail (`b`),
fail→pass (`c`). Only the discordant pairs carry information, so:

- **effect** = `(b − c) / paired` — the change in pass rate on the paired sample,
  positive when worse;
- **p-value** = the exact two-sided McNemar test, the binomial probability of a
  split at least as lopsided as `b : c` under the hypothesis that a flip is
  equally likely either way. Computed with `math.comb`; nothing new is imported.

A **rate regression** is reported when `paired ≥ min_sample`, `effect ≥ min_effect`
and `p ≤ max_p_value`. A **rate improvement** is the mirror image. Anything else is
a note that says which condition was not met and by how much: "12 paired cases,
below the 30 this policy needs", "pass rate fell 0.03 on 80 cases, below the
minimum effect 0.05", "3 cases got worse and 2 got better; p = 0.63".

## Numeric cases

For paired measurements with the same unit, direction and threshold: the mean of
the paired differences, signed so that positive is worse, with a 95% interval
from the sample standard deviation at `paired ≥ 30` and no interval below it. A
regression is reported when the interval excludes zero on the worse side and the
sample is at least `min_sample`. A minimum effect in units is deferred — characters
and ratios and milliseconds do not share a scale, and a default would be wrong for
two of the three — so the note names the mean and the interval and leaves the
judgement to the reader until a policy can express it.

## Where the policy lives

A `regression:` block in `guardana.yaml`, validated at load, with defaults that
refuse rather than alert:

```yaml
regression:
  min_sample: 30
  min_effect: 0.05
  max_p_value: 0.05
```

`diff` and `monitor` already take `--profile` and `--preset`, so the block reaches
both. The `monitor` preset carries the defaults. Slices by tag are printed with
their own paired counts and never gated: a slice is by construction a smaller
sample, and a gate on it would alert exactly where the evidence is thinnest.

## What changes in the documents

Two new change kinds, `rate_regressed` and `rate_improved`, attributed to the
suite's rule id with the numbers in `detail`, so a rate regression exits `1`
through the machinery that already exists and `monitor` alerts on it with the
same policy. The measurement block grows `regressed`, `improved`, `effect`,
`p_value`, `verdict` and `slices`. Diff schema `3`, with a pinned published schema
and the version-2 document still read.

### The two questions a suite answers, kept apart

A suite's own finding says "this run's rate is below the bar the operator set".
A rate regression says "this run's rate is worse than last run's, beyond noise".
A model can fail the first and not the second (it was already below the bar), or
the second and not the first (it fell from 99% to 93% against a 90% bar). Both
are reported, neither is folded into the other, and the change list shows a
suite's threshold finding as `appeared` exactly as it would any other finding.

### `monitor`

Inherits everything through `compare`. One addition: at start-up it says, once,
which suites are below `min_sample` — "suite X has 20 cases, below
regression.min_sample 30; rate changes will be reported, not alerted" — because a
monitor that silently cannot alert is the blind spot the intake design names
first.

## Rejected

**`scipy`, `numpy`, `statsmodels`.** Principle 6. Everything above is
`math.comb`, `math.sqrt` and a loop.

**Alerting on the point estimate.** It is the thing that made "16 → 15" look like
a regression, and it is what every dashboard already does.

**A single quality score.** Unchanged from the roadmap's refusal of a universal
risk score: it would hide which condition was unmet.

**Sequential testing and early stopping.** Worth having for a monitor that samples
continuously; belongs with the intake lane, where the sample arrives over time.
A one-shot `diff` has both runs in hand.

**Bayesian intervals.** Defensible, and a prior is a policy decision this tool
has no standing to set for somebody else's suite.

## See also

- [`quality-suites.md`](quality-suites.md) — where the paired sample comes from
- [`assessment-channel.md`](assessment-channel.md) — the comparability key
- [`../usage-diff.md`](../usage-diff.md) — the user page
