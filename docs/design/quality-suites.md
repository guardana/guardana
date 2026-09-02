---
title: "Quality suites"
nav_order: 73
summary: "a versioned dataset, a suite that is a rule, an assessor that is an evaluator, and a gate that refuses a pass rate it has not earned — Horizon 1 on the channel 0.22.0 shipped"
status: proposed
---

# Quality suites: did the model get worse, on a sample we can name?

**Status:** proposed · **Written:** 2026-09-02 · **Cycle 2 of the extensibility program** ([`audit-0.22.md`](audit-0.22.md))

## The question

A team swaps a model, retrains on new data, or tightens a system prompt, and
wants to know whether the answers got worse — not whether an attack landed, but
whether the support bot still answers the four hundred questions it answered
last month. The assessment channel gave that question a record with a
denominator. What it does not have is anything that produces four hundred of
them from a file the team owns, or a gate that knows how many are enough.

Dataset, suite, assessor — and the decision is that **none of them is a new
abstraction**.

| Word | What it is | What it already is |
|---|---|---|
| **Dataset** | a versioned file of cases | JSONL, the format traces and corpora already use |
| **Suite** | "run this dataset through that assessor, and fail below this rate" | a declarative `Rule` — planned, priced, budgeted, recorded and compared like any other |
| **Assessor** | what grades a case, possibly with a number | an `Evaluator`; `Assessment.assessor` has said "an evaluator id" since it existed |

## The dataset

One JSONL file. The first line names it; every other line is a case.

```jsonl
{"guardana_dataset": 1, "name": "support-golden", "version": "2026.09"}
{"input": "How do I reset my password?", "expect": {"contains_any": ["Settings", "reset link"]}, "tags": ["account"]}
{"input": {"messages": [{"role": "system", "content": "…"}, {"role": "user", "content": "…"}]}, "expect": {"reference": "…"}}
```

- `input` is a prompt string or a message list. `expect` holds evaluator fields
  for this case, validated at load against the suite's evaluator like any
  `expect:` block; the suite's own `expect:` supplies defaults and a case may
  override them. `tags` are slices a comparison may group by.
- **Identity is `name@version`**, declared by the author, and that is what lands
  in `Assessment.dataset`. **A case's identity is a hash of its content**, so
  reordering changes nothing and rewording a case makes a new case — the reading
  the assessment channel already chose. A dataset whose content changed without a
  version bump is caught one level up: the file's digest is part of the suite's
  `digest()`, so `diff` notes that the rule's definition changed, while every case
  whose content did not change still pairs.
- The path is relative to the rule file, so a dataset ships inside a pack the
  same way a catalogue does. A URL is refused: the only network traffic is to the
  target.
- Loading is bounded — a line over the trace reader's limits is refused, not
  truncated — and a malformed line names its number.

**Rejected: `Assessment.dataset` as the file digest.** It is what `YamlRule` does
with its own declaration, and it is right there, because a prompt list *is* the
rule. For a dataset it would make one edited case incomparable with every other
case in the file: two changes, both wrong, for one edit.

**Rejected: cases inline in YAML.** Four hundred cases in a rule file is a rule
file nobody reviews, and JSONL diffs line by line in a pull request.

## The suite

```yaml
id: acme.quality.support_answers
title: The support bot still answers the golden set
severity: high
target_kind: endpoint
taxonomy: [LLM05:2026]
evaluator: contains
requires: [chat]
dataset: ./support-golden.jsonl
expect:
  contains_any: []          # suite-level default, overridden per case
sample:
  size: 100                 # optional: a deterministic subset, for a cheaper CI run
  seed: 7                   # required when size is given — the subset is a choice, not an accident
gate:
  min_pass_rate: 0.90
  min_sample: 30            # below this the suite declines, never passes or fails
fixtures:
  - name: it passes when every answer is the reference
    reply: "Open Settings and follow the reset link."
    outcome: clean
  - name: it fails when nothing matches
    reply: "42"
    outcome: finding
  - name: it declines when the model says nothing
    reply: ""
    outcome: inconclusive
```

A suite is `SuiteRule`, the fourth declarative shape, detected by `dataset:`.
It runs under `probe` and `monitor` like any endpoint rule — there is no fifth
verb, for the reason the audit gives. `estimated_requests` is the number of cases
after sampling, so `plan probe` prices it and a budget bounds it.

**A taxonomy mapping is required**, as for every rule, and the author chooses it.
Degradation after a data or model change is what `LLM05:2026` describes;
a team's own control catalogue registered through `guardana.taxonomies` is the
other honest answer. A suite that cannot say which control it serves is a number
without an owner.

### What a case becomes

One `Assessment` per case, pass included: `case_id` from the content,
`assessor` the evaluator id, `dataset` the declared identity, `rule_id` the
suite, `tags` from the case plus `sample:<seed>` when a subset ran, and — when the
evaluator returned one — the measurement. Inconclusive is a status, never a zero.

### What the gate does with it

A suite yields **at most one finding**, and it is about the rate, not a case:

| Measured cases | Pass rate | Result |
|---|---|---|
| fewer than `min_sample` | any | one `inconclusive` finding on the `unverified` channel: "n of N cases measured; the suite needs at least min_sample to say anything" |
| at least `min_sample` | below `min_pass_rate` | one finding at the suite's severity, with the rate, the sample, a 95% Wilson interval and up to three failing cases in the evidence, redacted like all evidence |
| at least `min_sample` | at or above | nothing — the passes are in the channel, which is the point |
| zero | — | the gate's existing refusal: assessments recorded, none measured, `indeterminate` |

The finding fires on the observed rate against the operator's threshold; the
interval is reported so a reader can see how much of the shortfall is sampling.
Requiring the interval's upper bound to clear the threshold would make a
thirty-case suite unable to fail at all below a catastrophic drop, which is a
gate people would learn to trust for the wrong reason. Movement *between* runs is
a different question with different statistics —
[`paired-regression-statistics.md`](paired-regression-statistics.md).

**Rejected: a finding per failed case.** Four hundred cases at a 90% bar is forty
findings for a passing suite. A case failure is a measurement; the finding is the
rate.

**Rejected: a numeric aggregate gate (`max_mean_value`).** A per-case threshold is
already the assessor's decision and is recorded on the assessment; a gate over an
aggregate of values needs the effect statistics of cycle 3 to be honest about
noise. Values are recorded and rendered now, and gated later.

## The assessors

Every assessor is an `Evaluator`. Two changes to the base contract, both additive:

**`Verdict.measurement`**, optional — `Measurement(value, unit, direction,
threshold)`. `from_verdict` carries it onto the assessment, and a comparison
treats a changed `threshold`, `unit` or `direction` as incomparable, the way it
treats a changed assessor. A third-party evaluator that never sets it is
unchanged.

**New deterministic evaluators**, each one file, each with a confidence of `1.0`
because equality is not an opinion: `exact_match` (`reference`, optional
`normalize`), `contains` (`contains_all`, `contains_any`, `contains_none`),
`regex` (`pattern`, optional `must_match`), `json_valid` (optional
`required_keys`). Each returns `inconclusive` on a missing reply, and `contains`
returns `inconclusive` — never `pass` — when every list it was given is empty,
because a check with nothing to look for has not looked.

**Extended built-ins**, each backward compatible: `keyword` gains
`should_refuse` (default `true`; `false` turns it into the utility check — "the
model must *not* refuse this benign task"), `length` gains `max_chars` and emits
a measurement in characters with `lower_is_better`, `amplification` emits its
ratio as a measurement. The first two numbers to ever land in `Assessment.value`
come from evaluators that already ship, which proves the numeric channel
end-to-end without a new judge.

**`reference_judge`**, config-wired like `llm_judge` and sharing its judge
connection: a versioned rubric that grades a reply against a reference answer,
confidence measured as agreement across samples, id stamped with the rubric
version. A separate evaluator rather than a `reference` field on `llm_judge`,
because a rubric change changes the id and would orphan every calibration
recorded against the security judge.

**Rejected: an embedding-similarity assessor.** It needs a model or a library, and
`guardana-core` depends on `pyyaml`. A pack can ship one through
`guardana.evaluators` today.

## Utility regression, which is the same thing

"Safer" that means "refuses more" is a suite over benign tasks graded with
`keyword` and `should_refuse: false`, with the same gate and the same statistics.
No new machinery, which is the test of whether the machinery is right.

## Rendering

The human renderer prints a "Measured" block per suite — cases, measured,
passed, rate, interval, and the ungraded count beside it so a shrinking
denominator is as visible as a falling rate. `junit` maps a suite to a testsuite
and each case to a testcase, because a suite is the thing CI dashboards already
know how to show. `json` carries what it already carries.

## Extension API

Additive throughout: an evaluator that ignores `Measurement` is unchanged, and
`SuiteRule` is one more shape `load_yaml_rules` returns. The build advertises API
`2` from cycle 1 and nothing here needs a further number.

## See also

- [`assessment-channel.md`](assessment-channel.md) — the record every case becomes
- [`paired-regression-statistics.md`](paired-regression-statistics.md) — what two runs of a suite prove
- [`extension-author-tooling.md`](extension-author-tooling.md) — fixtures and calibration a suite author inherits
