# `guardana import-observations` — carry another tool's results in as claims

You ran garak. You ran promptfoo. You have an internal harness. Their results are real
evidence and they belong beside Guardana's — without Guardana pretending it produced them.

```bash
guardana import-observations garak.report.jsonl --target https://llm.internal/v1
```

## This command never exits 0, and that is the design

Guardana did not send those prompts, did not see the replies, and cannot grade what it did
not observe. So every imported result lands in the **`unverified`** channel, no rule ran,
and the gate is `indeterminate` — exit `2`.

```
$ guardana import-observations garak.report.jsonl
imported 2 claim(s) from garak 0.13.1 via garak from garak.report.jsonl into the
  unverified channel — Guardana did not send these prompts and has not graded them
note: 1 result(s) the producer marked as passing were not imported — a pass is not a finding
note: 2 record(s) were setup or raw-attempt records, not verdicts, and were not imported
⚠ 0 rules ran — nothing was checked (this is not an all-clear).

0 finding(s); 0 rule(s) run, 0 skipped. 2 unverified.
```

**Do not gate a build on this command.** Gate on [`probe`](usage-probe.md),
[`scan`](usage-scan.md) or [`analyze-trace`](usage-analyze-trace.md), and use this to put
another tool's findings in the same report, the same collector and the same triage queue.

## What "their claim, our channel" means in practice

**The outcome stays in the producer's terms.** promptfoo's `success: false` means *this
assertion did not hold*. Whether that is an attack succeeding depends entirely on what the
assertion was, and only whoever wrote it knows — so the imported outcome is `failed`,
`passed`, `errored` or `undecided`, never "attack succeeded".

**Severity is carried and attributed.** When the producer states one it is kept, and the
evidence says who said so. When it does not — garak reports none at all — the claim is
filed at `INFO`, which is an honest floor rather than a judgement, and the evidence says
that too.

**No framework reference is attached.** Mapping somebody else's result onto `LLM01` would
be Guardana vouching for a mapping it did not make. The producer's own category travels in
the evidence, where it reads as a quotation.

**Nothing is dropped.** A record that cannot be read goes to the `errors` channel and — with
`fail_on_error` on by default — makes the run indeterminate. A dropped record is a failing
check that disappears, which is a false green arriving through the import path.

## Three formats

Detected from the file's structure rather than its name; `--producer` overrides.

### garak

A `*.report.jsonl` file. `eval` records are the verdicts.

- `fails > 0` → one claim, `failed`.
- **`nones > 0` → its own claim, `undecided`.** That field is garak telling you its own
  detector could not score an output. An importer reading only `passed` and `total` folds
  those into passes, which is the same mistake Guardana refuses to make about itself.
- A clean `eval` is **counted, not imported** — two hundred passing probes in the
  unverified channel would bury the four that matter.
- `attempt` records are the raw exchanges behind an `eval` and are not imported; importing
  both would count every claim twice. An `entry_type` this build does not recognise is
  reported rather than ignored.

### promptfoo

A `--output results.json` file. Both nestings in the wild are read (`results` as an array,
and `results.results` beside an `evalId`). `success`, `gradingResult.pass` and `error`
decide the outcome; `testCase.metadata.pluginId` becomes the category and
`metadata.severity` the reported severity. A row where neither field said anything is
`undecided`, not a pass — a row nobody graded has no verdict to import.

### generic — for your own harness

```json
{
  "guardana_observations": 1,
  "producer": { "name": "internal-redteam", "version": "4.0" },
  "target": "https://llm.internal/v1",
  "observations": [
    {
      "id": "RT-118",
      "title": "system prompt recovered via translation pivot",
      "outcome": "failed",
      "severity": "high",
      "category": "prompt-leak",
      "detail": "the reply contained the operator instruction block verbatim"
    }
  ]
}
```

Versioned like a trace: a version this build cannot read is refused rather than partially
imported. An observation with no `outcome`, or one this build does not know, is reported as
unreadable — not assumed to be a pass.

## Options

| Option | Meaning |
|---|---|
| `--producer garak\|promptfoo\|generic` | Override detection |
| `--target REF` | What the other tool was pointed at, when the file does not say |
| `--format`, `--output` | As for every command; `json` is what `diff` reads |
| `--reporter server://URL` | Forward the claims to a collector |
| `--ai-system`, `--environment` | What these results are about. Never guessed |
| `--profile`, `--preset` | Policy — `fail_on_inconclusive` is the switch that makes imported claims block |

## Turning a claim into a finding

The bar is stated and it is not moved: when Guardana can **replay** the same attack under
its own contract, the result of *that* is a finding. Until then the claim keeps its
provenance — producer, version, file, timestamp and a digest of the bytes as read — so it
can be traced back to the document that carried it.

## Related

- [`usage-analyze-trace.md`](usage-analyze-trace.md) — grading a recorded execution with
  Guardana's own rules
- [`design/trace-domain-model.md`](design/trace-domain-model.md) — why an import is a claim
  and not a verdict
- [`usage-collector.md`](usage-collector.md) — where the claims land when `--reporter` is set
