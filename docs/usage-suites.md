---
title: "Quality suites"
nav_order: 255
summary: "quality suites: gate a deployed endpoint against a versioned golden dataset before release or in CI"
status: beta
---

# Quality suites

A quality suite checks whether a deployed support bot or RAG endpoint still answers a golden set before release or in CI. It is a declarative rule graded against a versioned dataset. It does not read production traffic; production traffic monitoring belongs to Guardana Control, a separate product.

## Dataset and rule

The first nonblank line of the JSONL dataset is this header:

```json
{"guardana_dataset": 2, "name": "support-golden", "version": "2026.09"}
```

Each later nonblank line is a case. The case fields are:

| Key | Meaning |
|---|---|
| `input` | Required. A nonempty string or a messages object whose last message is from the user. |
| `expect` | Optional evaluator fields for that case, overlaid on the rule's default expectation. |
| `tags` | Optional list of strings. A tag starting with `sample:` is refused. |
| `observed` | Optional, with `accepted`: the reply a regression case was promoted from, which its expectation must grade `fail`. |
| `accepted` | Optional, with `observed`: a correct reply, which its expectation must grade `pass`. |

`observed` and `accepted` come together or not at all, and only in the suite's own dataset,
never in a fixture dataset. A run never sends or reads them, and they are not part of a
case's identity: [`guardana case add`](usage-case.md) writes them, and `guardana rule test`,
every `guardana recipe` command and every run that selects the suite regrade them. A format-1 dataset
(`"guardana_dataset": 1`) is still read, without `observed` and `accepted`. The formats are
[`dataset-v2.schema.json`](https://guardana.dev/schemas/dataset/v2.schema.json) and
[`dataset-v1.schema.json`](https://guardana.dev/schemas/dataset/v1.schema.json).

**A regression dataset is a gate every case must pass.** A dataset holding any
`observed`/`accepted` pair refuses, when the suite is loaded, a suite that declares `sample:`
or whose `gate.min_pass_rate` is below 1, since a case that may not run, or that other cases
can outvote, prevents nothing. Set `gate.min_sample` to at most the number of cases. A case
tagged `regression` without a pair is a label only and changes no gate.

This rule grades the dataset and gates its pass rate:

```yaml
id: acme.quality.support_answers
title: The support bot still answers the golden set
severity: high
target_kind: endpoint
taxonomy: [LLM09:2025]
evaluator: contains
requires: [chat]
dataset: ./support-golden.jsonl
expect:
  contains_any: ["Settings > Security"]   # what every good answer names
sample:
  size: 100
  seed: 7
gate:
  min_pass_rate: 0.90
  min_sample: 30
fixtures:
  - name: every answer names the setting
    dataset: ./fixtures/answers-pass.jsonl
    outcome: clean
  - name: a third of the answers miss it
    dataset: ./fixtures/answers-mixed.jsonl
    outcome: finding
  - name: the model says nothing
    reply: ""
    outcome: inconclusive
```

Replace `Settings > Security` with what your good answers must contain. `contains` returns `inconclusive` when every substring list is empty, so an expectation left blank grades nothing. See [writing rules](writing-rules.md) for the rule shape.

## Run and read the suite

Run the rule with [`guardana probe`](usage-probe.md), or grade answers your application already gave with [`guardana grade`](usage-grade.md), which sends nothing to it. The profile's `trials` or `probe --trials` sets how many times each case is sent. `guardana plan probe` prices cases × K target requests and, for a judge-graded suite, cases × K × `min_agreement` judge calls ([pricing judge calls](usage-plan.md#pricing-judge-calls)). The saved run records what the judge spent in `usage.judge`.

The human report has a Measured block. A passing line can read:

```text
Measured
  acme.quality.support_answers  support-golden@2026.09: 100 of 100 cases measured, 3 trials each · pass rate 98.7% (95% CI 94 to 99.8%) · bar 90% · at or above the bar
```

A case is measured when all its planned trials were graded. Each case contributes its share of passed trials. The pass rate is the mean of those shares, so the interval is over cases rather than pooled trials. Ungraded trials stay in the denominator: `worst` counts them as failures, and `best` counts them as passes. The interval uses a 95% Wilson lower limit at `worst` and upper limit at `best`; it is conservative and does not collapse to a point when cases agree.

| Gate answer | Condition | Exit |
|---|---|---|
| Pass | `worst` meets `min_pass_rate`. | `0` |
| Fail | `best` is below `min_pass_rate`. | `1` |
| Decline | Fewer than `min_sample` cases were measured, ungraded trials could put the rate on either side of the bar, a judge's error could not be corrected (below), or the suite raised before it concluded. | `2` |
| Stopped | The run's budget ran out before every case was sent. The saved run keeps the suite's summary, declined, with how many of its cases were measured; the run stops. | `6` |

A failed suite produces one finding about the rate, whatever its severity. A declined suite produces one `unverified` entry and makes the run `indeterminate`. See [exit codes](exit-codes.md).

## Judge-graded suites

`answered` checks whether a reply to a benign task contains a refusal marker: a built-in English phrase or one of the rule's own `expect.refusal_markers`, each a whole phrase of at least four letters or digits ([refusals in another language](writing-rules.md#refusals-in-another-language)); in a script written without spaces, give the phrase, not one word. `reference_judge` grades a reply against a reference answer. Both are judge assessors, so their rates need judge-error correction. A suite without a usable calibration declines with `uncorrected — <reason>`. Record one with [`guardana calibrate --record`](usage-calibrate.md).

Judge-graded suites and judge-error correction are experimental: their behaviour, thresholds and saved fields may change in a minor release ([product status](product-status.md#released-and-experimental)).

A usable calibration has the same assessor and judge identity, per-class counts, and no starter corpus. It needs at least 30 graded samples in each class, abstention below half in each class, Youden's J of at least 0.1, and observed failures above the calibrated false-alarm rate. Every corner of its sensitivity/specificity 95% box must have sensitivity plus specificity greater than 1. A corrected rate uses the same gate test; when raw `worst` is below the bar, a pass also needs the corrected 95% lower limit to clear it.

## Sampling and fixtures

`sample: {size, seed}` selects a repeatable subset. Both values are whole numbers, and `seed` is required with `size`. The same seed selects the same cases across builds and Python versions. A size at or above the case count runs every case.

A `reply:` fixture answers every case with one reply. A fixture can use its own `dataset:` to supply cases and their replies. See [testing rules](usage-rule-test.md).

## Saved runs and limits

The saved run includes a suite summary; see [suite summaries](usage-run.md#suite-summaries) for its fields. Extension authors can see [extending Guardana](extending.md).

- Numeric measurements are recorded and rendered, but there is no gate on their aggregate.
- The collector receives the target's request count, not `usage.judge`.
- `diff` pairs cases across runs but does not test a suite's rate statistically.
- A file holds one calibration per evaluator id.
- `regex` grades replies up to 65,536 characters; longer replies are `inconclusive`. Each search runs in a separate worker process for at most 2 seconds. Longer searches are stopped and marked `inconclusive` ("regex search exceeded 2 s; not evaluated"), never a pass. Like any `inconclusive` result, this makes the run `indeterminate` (exit `2`) when `fail_on_inconclusive` is on. Backtracking patterns, such as nested quantifiers or several `.*` in a row, can still exhaust this time on a crafted reply; use possessive quantifiers or atomic groups instead.
