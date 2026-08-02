# `guardana run` — reading a saved run

A run saved with `--output` is not just a list of findings. It carries a **run
manifest**: what was examined, by which software, under which configuration and
limits, at what cost, and how it was gated. That is what makes a run evidence
rather than a screenshot — and what `guardana diff` compares.

```bash
guardana scan . --format json --output run.json
guardana run inspect run.json
```

```text
run 0191d4c2-8f1a-7c3e-9b21-6f0a2d8e4c11
  started:   2026-08-02 09:14:02+00:00
  completed: 2026-08-02 09:14:03+00:00
  source:    ci (github)
  guardana:  0.7.0
  target:    artifact .
  profile:   ci
  gate:      pass
  findings:  0 (0 unverified, 0 waived, 0 error(s))
  rules run: 19 (0 skipped)
  requests:  0
  tokens:    in not recorded, out not recorded
  wall time: 0.42
  evidence:  full
```

`--format json` prints the manifest itself, for anything that would rather parse
than read.

`requests: 0` above is a **measurement** — a file scan sends nothing. Tokens are
`not recorded` because there was no model to report them. The next section is
about why those two are printed differently.

## What a run costs

`usage` carries what the run actually spent: requests sent, tokens in and out,
and wall time.

The counting happens on the **target**, not on the transport, so every request to
a model is counted whatever transport is in use — a custom adapter, a scripted
double in a test, or one of the built-ins. A target that does not meter itself
(anything you wrote yourself, unless you override `Target.usage()`) reports
nothing rather than zero.

Token counts depend on the provider. The built-in OpenAI, Ollama and TGI paths
read them from the response; a transport that does not implement the optional
`UsageReportingTransport` protocol leaves them unknown. Where only *some*
requests reported tokens, the manifest carries the sum **and**
`requests_missing_token_counts`, so the number is never mistaken for the whole
bill. See [`docs/writing-rules.md`](writing-rules.md) for the protocol.

## What "not recorded" means

It means **nobody measured this**, and it is deliberately not printed as `0`.
A file scan that sends zero requests and a run from a version that never counted
requests are different facts; only one of them lets you budget the next run. The
same distinction runs through the whole document: `null` is always "not known",
never "not applicable" and never zero.

## Older runs still load

A run written by 0.6 uses schema version 1. `guardana diff` and `guardana run
inspect` **migrate it forward in memory** as they read it, so upgrading Guardana
does not strand the evidence you already have.

What version 1 never recorded arrives as an explicit unknown rather than as a
default — no usage, no execution settings, and **no gate verdict**. Recomputing
the verdict during migration would apply today's thresholds to another build's
run, which is exactly what storing the gate as a field exists to prevent.
`inspect` says so at the bottom of its output, and `diff` adds a note.

To rewrite an old file on disk at the current schema:

```bash
guardana run migrate old-run.json --output new-run.json
guardana run migrate old-run.json          # in place
```

This is a convenience, not a requirement. Nothing needs migrating to be compared.

## The document

The saved-run schema lives at
[`schemas/run-v2.schema.json`](../schemas/run-v2.schema.json), identified by
`https://guardana.dev/schemas/run/v2.schema.json`. The version is in the
identifier, so a consumer can tell which contract it is holding before parsing
anything; it changes whenever the change is not backwards-compatible. A test
validates what Guardana writes against that file, so the schema cannot drift
away from the tool.

Top level:

| Key | What it is |
|---|---|
| `schema_version` | `2`. Stated once, for the whole document. |
| `run` | the manifest — everything below |
| `findings` / `unverified` / `waived` / `errors` / `observations` | the channels |

Inside `run`:

| Block | Answers |
|---|---|
| `run_id`, `created_at`, `started_at`, `completed_at` | which run is this, and when |
| `migrated_from` | which older schema it came from, or `null` |
| `source` | who started it — a laptop, CI, a schedule |
| `guardana` | which software produced it |
| `target` | what was examined, with a fingerprint and the fields that fingerprint covers |
| `deployment` | which deployment of which AI system this verifies |
| `configuration` | which settings produced it, **by digest** |
| `execution` | what limits it ran under |
| `usage` | what it actually consumed |
| `rules` / `evaluators` | what did the checking, with digests and calibration |
| `result_summary` | the counts, the gate, and whether the run was cut short |
| `privacy` | which evidence policy was in force |

Three conventions hold everywhere in it:

**Timestamps are UTC, RFC 3339.** A local-time timestamp in an evidence record is
a bug waiting for a timezone.

**Digests name their algorithm** — `sha256:…`, never a bare hex string, so a
digest can be migrated when the algorithm moves.

**The target fingerprint says what it covers.** `target.fingerprint_inputs` lists
the fields the digest was computed from. A digest of a URL and a model name
identifies a *declared* target; it attests nothing about the weights behind it,
and the document says so rather than leaving a reader to assume the stronger
reading.

## Field names borrowed on purpose

`usage.input_tokens` and `usage.output_tokens` are the OpenTelemetry GenAI
convention's [`gen_ai.usage.input_tokens` /
`gen_ai.usage.output_tokens`](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)
without the namespace; `execution.seed` and `execution.temperature` match
`gen_ai.request.*`. If you already collect those, the manifest needs no
translation.

The SARIF output carries the same facts in SARIF's own vocabulary: `runs[].invocations[0]`
with `startTimeUtc`, `endTimeUtc`, `exitCode`, `exitCodeDescription` and
`executionSuccessful`.

## See also

- [`usage-diff.md`](usage-diff.md) — comparing two saved runs
- [`usage-scan.md`](usage-scan.md) and [`usage-probe.md`](usage-probe.md) — producing them
