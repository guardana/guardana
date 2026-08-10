# `guardana trace inspect` — what a recorded execution can answer

Grading a trace tells you whether invariants held. This tells you which questions
the file can answer *at all* — before a run, before a policy, before a pipeline
discovers it the hard way.

It opens one file and no socket. It writes no run document, reaches no network,
and exits `0` unless the file cannot be read.

```bash
guardana trace inspect run.jsonl
```

```
read 3 span(s) from run.jsonl as guardana (producer: checkout-agent)

dimension   declared  records  required  needed by  unlocks
messages    yes       1        -         0 rule(s)  -
tools       no        0        -         1 rule(s)  1 rule(s)
retrieval   yes       1        -         1 rule(s)  -
memory      no        0        -         0 rule(s)  0 rule(s)
identity    yes       1        -         2 rule(s)  -
delegation  yes       2        -         2 rule(s)  -
consent     no        0        -         1 rule(s)  1 rule(s)
policy      no        0        -         1 rule(s)  1 rule(s)
approval    no        0        -         1 rule(s)  1 rule(s)
effects     yes       2        -         1 rule(s)  -
handoff     no        0        -         1 rule(s)  1 rule(s)

note: tools, memory, consent, policy, approval, handoff are not recorded at all,
so the rules needing them do not run — their silence is not evidence that nothing
happened
```

## Reading the columns

| Column | What it says |
|---|---|
| `declared` | whether the **producer states it emits this dimension**. This is the load-bearing one: a dimension that is not declared stops every rule needing it from running, because their silence would otherwise be read as evidence |
| `records` | how many records of that dimension this particular execution carries |
| `required` | whether your profile's `trace.require:` demands it (see below) |
| `needed by` | how many **installed** rules read that dimension — counted from the registry, so a rule pack you installed is included |
| `unlocks` | how many of those would **start running** if this were the next thing you instrumented. `-` where the producer already records it |

**`declared` and `records` are two different facts, and the difference matters.**

- `declared: yes`, `records: 0` — the producer emits approvals and this execution
  had nothing to approve. **Gradable.** This is where a finding lives: a rule can
  say "an action happened and no approval preceded it".
- `declared: no`, `records: 0` — the producer never emits approvals. **Not
  gradable.** Nothing here can tell an unapproved payment from a well-governed one
  that this framework simply does not describe.

A report that collapsed the two would make those indistinguishable, which is the
single inference [the trace design](design/trace-domain-model.md) exists to refuse.

**There is no coverage percentage, and there never will be.** One number is
compatible with having no identity evidence whatsoever, and a team that gates on a
number rather than on a name ships the day the missing part is the part that
mattered.

`needed by: 0` is honest and useful: `memory` is emitted by several frameworks and
no shipped rule requires it yet, so recording it buys nothing today.

**`needed by` and `unlocks` differ wherever a rule wants two dimensions, and the
difference is the part worth reading.** `guardana.trace.unapproved_side_effect`
needs approvals *and* side effects, so against a producer that records neither it is
`needed by` both and `unlocks` by neither: instrumenting approvals alone would be
work that buys no new check. One column used to answer both questions, and it
answered the wrong one — a team budgeting instrumentation read `approval: 1 rule`
and got nothing for the effort.

## Gating on it: `trace.require`

A profile can *demand* dimensions. A run whose producer does not record one is
**`indeterminate`, never a pass** — and there is no `fail_on_*` in front of it,
because you asked for this coverage explicitly.

```yaml
# guardana.yaml
name: production-traces
trace:
  require: [identity, approval, effects]
```

```bash
guardana trace inspect run.jsonl --profile guardana.yaml
```

```
error: this profile requires approval, which this producer does not record —
`guardana analyze-trace` on this file is indeterminate, never a pass
```

That is the command's real job: **you find out before the pipeline does.** The
same profile through `guardana analyze-trace` exits `2`, and the saved run records
which dimension was missing under `run.coverage.shortfall`.

`trace.require` governs traces and nothing else. A shared `guardana.yaml` carrying
it does not affect `guardana scan` or `guardana probe` — demanding that a file scan
record approvals is a category error, and reading it as one would be a gate that
can never pass.

## Machine-readable output

```bash
guardana trace inspect run.jsonl --format json
```

```json
{
  "trace_id": "run-0001",
  "source": "run.jsonl",
  "dialect": "guardana",
  "producer": "checkout-agent",
  "spans": 3,
  "truncated": null,
  "dimensions": [
    {
      "dimension": "approval",
      "declared": false,
      "records": 0,
      "required": true,
      "licenses": ["guardana.trace.unapproved_side_effect"],
      "unlocks": []
    }
  ]
}
```

`unlocks` is empty there even though `approval` is required and missing, because the
one rule needing approvals needs side effects too and this producer records neither.
`licenses` keeps its original meaning — every rule that reads the dimension — so a
consumer written against the older shape is unaffected.

## Options

| Flag | What it does |
|---|---|
| `--dialect guardana\|otel` | force the reader; detected from the file's first record otherwise |
| `--profile PATH` / `--preset NAME` | resolve `trace.require:` so the `required` column and the verdict line mean something |
| `--format human\|json` | the table, or the same facts named rather than aligned |
| `--rules PATH` | include custom YAML rules when counting what each dimension is needed by; repeatable |
| `--plugins`, `--allow-plugin` | the usual plugin-trust controls |

## Filling a gap

If your framework does not emit a dimension you need, `guardana analyze-trace
--write-trace out.jsonl` rewrites the file in Guardana's native dialect so the
missing pieces can be added by hand or by your own exporter. See
[`usage-analyze-trace.md`](usage-analyze-trace.md).

## Related

- [`usage-analyze-trace.md`](usage-analyze-trace.md) — grading the execution
- [`usage-contracts.md`](usage-contracts.md) — security contracts, which demand
  dimensions implicitly by asserting things that need them
- [`design/trace-domain-model.md`](design/trace-domain-model.md) — why absence is
  never read as evidence
