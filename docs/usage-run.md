---
title: "guardana run"
nav_order: 200
summary: "`guardana run inspect|migrate`: reading a saved run and its manifest"
status: stable
---

# `guardana run` — reading a saved run

`guardana run inspect` shows a saved run when you need to review its manifest or compare it with `guardana diff`. A run saved with `--output` records its target, configuration, limits, cost, and gate.

```bash
guardana scan path/to/project --format json --output run.json
guardana run inspect run.json
```

```text
run 0191d4c2-8f1a-7c3e-9b21-6f0a2d8e4c11
  started:   2026-08-02 09:14:02+00:00
  completed: 2026-08-02 09:14:03+00:00
  source:    ci (github)
  guardana:  <version>
  target:    artifact path/to/project
  profile:   ci
  gate:      pass
  findings:  0 (0 unverified, 0 waived, 0 error(s))
  rules run: 19 (0 skipped)
  trials:    1 per case asked; 0 rule(s) and 0 suite(s) repeated
  requests:  0
  tokens:    in not recorded, out not recorded
  judge:     not counted
  wall time: 0.42
  evidence:  redacted
```

`--format json` prints the manifest. `requests: 0` is measured; tokens are `not recorded`.
`run inspect` accepts only `human` and `json`. Any other `--format`, including
`sarif` or `junit`, exits `3` before reading the saved run.
A run started from a recipe adds a `recipe:` line under `target:`, such as
`recipe:    checkout (model_harness, from a recording)`: the recipe's name, the subject
it declared and how the run reached it. A run given fixtures adds a `fixtures:` line, such as
`fixtures:  support-bot (data: synthetic, as declared); tenants acme, globex; 3 document(s),
2 record(s), 0 tool(s)` ([`usage-fixtures.md`](usage-fixtures.md)).

## What a run costs

`usage` carries what the run actually spent: requests sent, tokens in and out,
and wall time.

The counting happens on the **target**, not on the transport, so every request to
a model is counted whatever transport is in use — a custom adapter, a scripted
double in a test, or one of the built-ins. A target that does not meter itself
(anything you wrote yourself, unless you override `Target.usage()`) reports
nothing rather than zero.

Token counts depend on the provider. The built-in OpenAI and Ollama paths read
them from the response, and TGI reports none ([providers](providers.md)); a transport that does not implement the optional
`UsageReportingTransport` protocol leaves them unknown. Where only *some*
requests reported tokens, the manifest carries the sum **and**
`requests_missing_token_counts`, so the number is never mistaken for the whole
bill. See [`docs/writing-rules.md`](writing-rules.md) for the protocol.

`usage.judge` counts the judges configured under the profile's `evaluators:` block,
each on its own meter and apart from the target: `llm_judge` (which `reference_judge`
shares) and `guard`. Each entry carries `requests`, `input_tokens`, `output_tokens`,
`requests_missing_token_counts` and `budget_exhausted`, which says that this meter's
ceiling stopped the run. `usage.judge` is `null` when nobody counted judge calls: no
judge block was configured, or the command never wires a judge (`scan`). An evaluator
from a plugin that makes its own network calls is not counted anywhere. `inspect`
prints one `judge:` line per block:

```text
  judge:     llm_judge 36 request(s), tokens in 1440, out 108
```

## What "not recorded" means

It means **nobody measured this**, and it is deliberately not printed as `0`.
A file scan that sends zero requests and a run from a version that never counted
requests are different facts; only one of them lets you budget the next run. The
same distinction runs through the measured fields (requests, tokens, cost, duration):
`null` there is "not known", never zero. A block that describes a feature, such as
`exchanges`, `recording`, `recipe` or `fixtures`, is `null` when the run did not use it.

## What a run could check

`coverage` is the other half of the promise `rules_run` started. A run whose corpus
was trimmed, whose evaluator stopped being installed, whose target lost a capability
or whose MCP server answered an older protocol revision reports fewer findings — and
subtracting two lists reads every one of those as an improvement.

So the manifest carries one fingerprint over all of it, plus the framework
catalogues that were installed, each pinned by digest. That is what lets a report be
read years later without asking which edition of a framework was in use: `LLM07`
means System Prompt Leakage in `OWASP-LLM-2025` and Misinformation in
`OWASP-LLM-2026`, and the run says which one it held. `guardana diff` compares the
fingerprint and reports a difference as *the reach changed*, separately from what
was found. A run that recorded none is reported as **unknown reach**, never as equal
reach.

## Older runs still load

A run written by 0.6 uses schema version 1, and one written by 0.12 uses version 2.
`guardana diff` and `guardana run inspect` **migrate them forward in memory** as they
read them, one step at a time, so upgrading Guardana does not strand the evidence you
already have.

What an older version never recorded arrives as an explicit unknown rather than as a
default — version 1 has no usage, no execution settings and **no gate verdict**;
version 2 has no coverage fingerprint and no declared request counts; version 3 could
not name a `trace` target, because that kind did not exist; version 6 made one attempt
per case, so it arrives with `execution.trials: 1`, `trial: null` on every assessment
and no `trial_summary` on any rule — the summary is not recomputed from its
assessments. Recomputing any of them during migration would apply today's build to
another build's run, which is exactly what storing them as fields exists to prevent.
`inspect` says so at the bottom of its output, and `diff` adds a note.

A schema-7 run migrates to schema 8 with the correction fields `null`; nothing is
recomputed. Its trials line still prints
`graded by <assessor>, grader error not corrected`, as it was written.

A schema-8 run migrates to schema 9 with `suite: null` on every rule; nothing is
recomputed.

A schema-9 run migrates to schema 10 with `usage.judge: null`: judge calls were not
counted, which is not the same as none being made. `inspect` prints `judge: not counted`.

A schema-10 run migrates to schema 11 with `target.document: null`. No earlier schema
recorded the digest of the document a run read, so nothing is relabelled, and no older run
is read as carrying a content digest.

A schema-11 run migrates to schema 12 with `scope: null` and `configuration.plugins: null`:
no earlier schema recorded which files a run listed or which plugin trust it ran under, so
both are unknown. `diff` against a migrated second run cannot tell a file that left the scan
from a fixed one, and reads a finding that disappeared the way it did before.

A schema-12 run migrates to schema 13 with `exchanges: null`, `recording: null`, `judge: null`
on every evaluator and `reason: null` on every assessment: no earlier schema kept exchanges,
graded a recording, recorded a judge's identity or said why a trial went unmeasured. A null
judge is unknown, so `diff` does not read it as a change of judge.

A schema-13 run migrates to schema 14 with `recipe: null` and `configuration.provider: null`:
no earlier schema recorded a recipe or the provider wire, so both are unknown, never "no
recipe" or "the OpenAI wire". `inspect` prints no `recipe:` line for it.

A schema-14 run migrates to schema 15 with `fixtures: null`: no earlier build took a fixtures
file, so the run was given none.

A schema-15 run migrates to schema 16 with `execution.max_requests_per_minute: null`: no
earlier build paced its requests, so the run set no rate.

A schema-16 run migrates to schema 17 with only its version changed: schema 17 adds the
`not_offered` skip reason and the `target_changed` stop, and no earlier build wrote either.

One thing *is* recovered: the **title** of a framework reference, which version 3
onward records beside its framework and id. It is looked up from the installed
catalogue for the exact `(framework, id)` pair the document already carries, so
nothing is guessed and no reference is remapped — a `LLM07` recorded under
`OWASP-LLM-2025` stays System Prompt Leakage. A reference from a rule pack this build
does not have stays titleless, because nothing here knows what it was called.

To rewrite an old file on disk at the current schema:

```bash
guardana run migrate old-run.json --output new-run.json
guardana run migrate old-run.json          # in place
```

Migrating to another `--output` brings the exchanges the run records: their
`<stem>.exchanges.jsonl` is copied beside the new output first, identical exchanges
already there are kept, different ones are refused with exit `3` and nothing is written,
and stderr warns when the original sidecar is missing or does not match the recorded
digest. A run that kept no exchanges removes the ones an earlier run left beside that
output, and says so on stderr. The migrated run's own sidecar stays when migrated in
place or from `run.json` to `run`, which share one. An `--output` whose sidecar
path is the input file is refused with exit `3` before anything is written.

This is a convenience, not a requirement. Nothing needs migrating to be compared.

A file that says it is already at the current schema is read the way `run inspect`
reads it before migrate answers "nothing to do": an object that only claims the version
is not a run, and exits `3`. Given another `--output`, such a run is copied there byte
for byte, and stdout says so. Migrate writes a temporary file beside the destination
and renames it over. A failed write leaves the destination as it was, prints an error
and exits `3`; nothing is removed. A destination this process cannot write, a directory
where it cannot create the temporary file, or an `--output` that is the input's own
`<stem>.exchanges.jsonl` is refused the same way.

**A migration that cannot carry a field refuses, and writes nothing.** The default
destination is the file itself, so a half-done migration would overwrite the only copy
of the evidence. In 0.7.0 a version-1 run that never recorded its target kind was
migrated into the literal string `"None"` — a document that fails this schema, written
over the original, with exit `0`. Every unit test around migration passed, because
they asserted on the objects the migration loaded and the objects were fine; what was
published was the file. There is now a test that validates the *artifact*,
parametrised over every field a version-1 run could be missing.

## The document

The saved-run schema lives at
[`schemas/run-v17.schema.json`](../schemas/run-v17.schema.json), identified by
`https://guardana.dev/schemas/run/v17.schema.json`, and the site serves every schema
at the URL its identifier names. The version is in the identifier,
so a consumer can tell which contract it is holding before parsing anything; it
changes whenever the change is not backwards-compatible. A test validates what
Guardana writes against that file, so the schema cannot drift away from the tool.

Every superseded version stays published — `run-v2` and `run-v3` are still in
[`schemas/`](../schemas/) — because a saved run has to keep validating against the
schema it was written to. Version 4 exists for one reason: it permits a `trace` target
kind. Widening version 3's enum in place was the alternative, and it would have
changed a contract under a name that promised it had not. Version 6 adds the
`assessments` channel and `run.rules[].origin`; a version-5 document migrates forward
with the first empty and the second `null`, because that is what it knew. Version 7
records repeated trials: `run.execution.trials`, `assessments[].trial` and
`run.rules[].trial_summary`, and renames `run.rules[].trials` to `declared_requests`,
which is what it always counted. Version 8 records the `correction` block on
`trial_summary` and the calibration fields on `run.evaluators[]`. Version 9 records
`run.rules[].suite`, what a quality suite measured and concluded. Version 10 records
`run.usage.judge`, what the configured judges spent and whether one of their budgets
stopped the run. Version 11 records `run.target.document`, the digest of the document the run
read and what it covers. Version 12 records `scope`, every file a file run listed and the
excludes it applied, `run.configuration.plugins`, the plugin trust in force, and the
`unexamined_component` coverage shortfall. Version 13 records `run.exchanges`, what a probe
kept beside the run, `run.recording`, the recording a graded run answered from,
`run.evaluators[].judge`, each judge's identity, `assessments[].reason`, why a trial was not
measured, and the `not_recorded` skip reason. Version 14 records `run.recipe`, the recipe a
run was started from and the subject it declared, `run.configuration.provider`, the provider
wire the run spoke, and the `incomplete_recording` and `demanded_check` coverage shortfalls.
Version 15 records `run.fixtures`, the fixtures file a run was given, the
`seed_not_reached` coverage shortfall: a seeded item whose control returned no marker for a
tenant, and `run.evaluators[].deterministic`, whether an evaluator declares its verdict a
fact with no error rate to measure. A version-14 run reads every evaluator as not
deterministic. `run inspect` prints `deterministic — no error rate` for such an evaluator
under `graded by:`, and `confidence not measured` for a judge with no calibration.
Version 16 records `target_unavailable` in `result_summary.stopped_by`, a run its target
stopped part-way; the `empty_target` coverage shortfall, a file target with no file to scan,
and `ungraded_cases`, a rule that graded too few of the cases it attempted;
`target_declined` in `assessments[].reason`, a case the application declined that the
evaluator cannot grade; `target` in `run.recipe.source`, a recipe that named an installed
target; and `run.execution.max_requests_per_minute`, the pace a run's requests were held to.
Version 17 records `not_offered` in `result_summary.rules_skipped[].reason`, a rule that
found while it ran that the target does not offer what it examines, and `target_changed` in
`result_summary.stopped_by`, a run whose target stopped accepting the protocol revision the
run agreed with it.

Top level:

| Key | What it is |
|---|---|
| `schema_version` | `17`. Stated once, for the whole document. |
| `run` | the manifest — everything below |
| `findings` / `unverified` / `waived` / `errors` / `observations` | the problem, evidence and inventory channels |
| `assessments` | what the run *measured*, pass included — see [assessments](#assessments) |
| `scope` | for a file run, `{files, excludes, ignored_directories}`: every file it listed (so the document grows with the tree), spelled like a finding's location, each exclude pattern with its `source` (`profile` for `rules.paths_exclude`, `ignore_file` for `.guardanaignore`), and the directory names every scan skips; `null` for any other run. `excludes` is `null` when a third-party file target applied filtering it does not report |

Inside `run`:

| Block | Answers |
|---|---|
| `run_id`, `created_at`, `started_at`, `completed_at` | which run is this, and when |
| `migrated_from` | which older schema it came from, or `null` |
| `source` | who started it — a laptop, CI, a schedule |
| `guardana` | which software produced it |
| `target` | what was examined, with a fingerprint, the fields that fingerprint covers, and the digest of the document the run read |
| `deployment` | which deployment of which AI system this verifies |
| `configuration` | which settings produced it, **by digest**: `profile_digest` covers every setting of the resolved profile except its name, where it was read from and its `plugins:`; `plugins` is the trust in force, `{mode, allowed}`; `provider` is the provider wire the run spoke to its target, `null` when it reached none, reached it through an adapter or did not record it; `adapter_digest` is the SHA-256 of the adapter file as written, and `system_prompt_digest` of the operator's `--system-prompt-file`, never of a planted canary, so two runs of one configuration record the same digests |
| `execution` | what limits it ran under, and `trials`: the attempts per case the run asked for |
| `usage` | what it actually consumed, the configured judges on their own meters |
| `rules` / `evaluators` | what did the checking, with digests, declared request counts, a `trial_summary` for each rule that repeated, a `suite` summary for each quality suite, calibration, `judge`: the identity a judge states (its model, endpoint and samples per verdict), `null` for a deterministic evaluator or when unstated, and `deterministic`. A suite the budget stopped or that raised is listed with its declined summary, though not in `result_summary.rules_run` |
| `coverage` | what the run was *able* to check: one fingerprint, the framework catalogues it mapped against by digest, and any protocol versions the target negotiated |
| `result_summary` | the counts, the gate, and whether the run was cut short |
| `privacy` | which evidence policy was in force |
| `exchanges` | for a probe that kept its exchanges ([`probe --keep-exchanges`](usage-probe.md#keeping-the-exchanges)), `{digest, count, altered}`: the SHA-256 of the sidecar file, how many exchanges it holds and how many replies redaction changed; `null` otherwise |
| `recording` | for a run [`guardana grade`](usage-grade.md) wrote, what the recording says of itself: `{name, version, subject, verbatim, origin}`, with `origin` `{run_id, target, started_at, stopped_by, gate}` when a probe kept it; declared, not verified. `null` otherwise |
| `recipe` | for a run started from a recipe, `{name, digest, lock_digest, kind, source, unpinned}`: the recipe's name, the SHA-256 of the recipe file and of the lock the run was held to (`null` when none was read), what the team declared answered (`kind`: `application` or `model_harness`), how the run reached it (`source`: `connection`, `recording` or `target`) and the rule ids it ran that the lock does not pin. `kind` is declared, not verified. `null` otherwise |
| `fixtures` | for a run given a [fixtures file](usage-fixtures.md), `{name, digest, data, tenants, counts, markers}`: the file's `name`, the SHA-256 of its bytes, `data` as `{declared: "synthetic"}` — the team's statement, recorded and never verified —, the tenants it declares, `{documents, records, tools}` it declares, and the version of the algorithm that derived its markers. `null` otherwise |

Three conventions hold everywhere in it:

**Timestamps are UTC, RFC 3339.** A local-time timestamp in an evidence record is a
bug waiting for a timezone.

**Digests name their algorithm** — `sha256:…`, never a bare hex string, so a digest
can be migrated when the algorithm moves.

**The target fingerprint says what it covers.** `target.fingerprint_inputs` lists the
fields the digest was computed from. A digest of a URL and a model name identifies a
*declared* target; it attests nothing about the weights behind it, and the document
says so rather than leaving a reader to assume the stronger reading.

**A document digest says how much of the document it covers.** `target.document` is
`null`, or `{digest, kind, bytes}`: `digest` is SHA-256 over the first `bytes` bytes of the
file the run read, and `kind` is `content` when that was the whole file or
`content_prefix` when a read ceiling stopped the reader first. `analyze-trace`,
`import-observations` and `grade` fill it; for `grade` it is the recording's digest, the
identity of the execution that was graded. `null` means no digest was recorded, never that two
documents matched.

## Assessments

The channel that is not about problems. Every other one — findings, unverified,
errors, coverage shortfall — records something wrong; a check that ran and was
satisfied used to leave nothing but its id in `rules_run`.

That is enough to gate a build and not enough to answer *did this get better*,
because fewer findings has three causes and the count cannot separate them: the
system improved, the test got weaker, or the sample changed.

```json
{
  "case_id": "guardana.prompt.jailbreak#b94d27b9934d",
  "assessor": "keyword",
  "subject_ref": "http://localhost:11434#llama3",
  "status": "measured",
  "rule_id": "guardana.prompt.jailbreak",
  "passed": true,
  "value": null,
  "unit": null,
  "direction": null,
  "threshold": null,
  "confidence": 0.6,
  "dataset": "5435b77094cde319",
  "rationale": "Response contains a refusal marker.",
  "tags": [],
  "trial": 1,
  "reason": null
}
```

| Field | What it is |
|---|---|
| `case_id` | the identity two runs are paired on. A hash of what distinguishes the case, so reordering prompts changes nothing and rewording one is a new case. It does not carry the text it was built from, but its 12-hex digest can confirm a guess at a low-entropy value or private dataset prompt; `hash_identifiers: false` writes a bare label instead of a digest |
| `assessor` | what produced the verdict — an evaluator id, or a rule grading in its own code |
| `status` | `measured`, `inconclusive`, `error` or `skipped`. The last three are statuses, never zeros, and are excluded from the denominator |
| `passed` | the boolean reading, or `null` when nothing could be graded. Never `false` for a case that was not measured |
| `value`, `unit`, `direction`, `threshold` | the numeric reading, which way is better, and the bound applied on *this* run |
| `confidence` | how much the assessor trusts itself, when it can say. Never invented |
| `trial` | which attempt at the case this was, from `1`, for a rule that can repeat; `null` for a rule that cannot, and for a run saved before trials existed. Not part of a case's identity: two runs pair on `case_id` |
| `reason` | why a trial was not measured: `not_recorded` (a recording held no reply for it; status `error`), `reply_altered` (the recorded reply was changed by redaction or not kept verbatim; status `inconclusive`) `declined` (the evaluator returned no verdict; status `inconclusive`) or `target_declined` (the application declined the request and the evaluator cannot grade a decline; status `inconclusive`). `null` for a measured trial, and for a run saved before schema 13 |
| `dataset` | which versioned corpus the case came from. For a YAML rule this is its declaration digest, so an edited expectation makes the two runs incomparable rather than making the model look worse |

`run.result_summary` carries `assessments` and `measured` as two numbers rather
than one rate. Both count records, one per attempt, so a rule that repeats five times
adds five per case. Their difference is the fact that matters: 40 assessments and 3
measured is a pass rate over three cases, and a summary carrying only the pass
count would present it with the same confidence as a full run.

An artifact scan records none of these, and that is correct — reading a file and
finding nothing is not a measurement. See [`usage-diff.md`](usage-diff.md) for
what a comparison does with them.

## Trial summaries

Each rule that repeated carries what its attempts added up to, over cases, as the engine
reduced them when the run was written:

```json
"trial_summary": {
  "trials_per_case": 5,
  "cases": 12,
  "cases_failed": 0,
  "cases_incomplete": 0,
  "bound": 0.2209,
  "mean_success_rate": 0.0,
  "correction": {
    "status": "uncorrected",
    "assessor": "keyword",
    "reason": "judge error not measured: no calibration recorded for keyword",
    "rate": null,
    "low": null,
    "high": null,
    "sensitivity": null,
    "specificity": null,
    "dataset_digest": null,
    "positives": null,
    "negatives": null
  }
}
```

| Field | What it is |
|---|---|
| `trials_per_case` | the attempts this rule made at every case. It can be lower than `execution.trials`: a rule that cannot repeat has no summary at all |
| `cases`, `cases_failed`, `cases_incomplete` | how many cases, how many had a failed attempt, and how many had an attempt nobody could grade and no failure |
| `bound` | the 95% upper bound on the share of cases where any attempt fails, over cases, set only when every attempt of every case passed |
| `mean_success_rate` | the mean, over cases, of each case's share of failed attempts |

The `correction` block records how judge error was handled:

| Field | What it is |
|---|---|
| `status` | `deterministic`, `corrected`, or `uncorrected` |
| `assessor` | the id carried by the rule's verdicts and used to match the calibration |
| `reason` | why a rate stays uncorrected |
| `rate`, `low`, `high` | corrected `ASR@K` and its 95% interval; a clean rule has a one-sided interval with `low` at `0` |
| `sensitivity`, `specificity` | the per-class rates applied to the correction |
| `positives`, `negatives` | the graded class counts behind those rates |
| `dataset_digest` | the calibration corpus digest |

A corrected block states all these fields. A `null` `correction` means the document was
written before schema 8.

`run.evaluators[].calibration` also gains `assessor`, `judge_identity`,
`starter_corpus`, `positives`, `negatives`, `positives_inconclusive`,
`negatives_inconclusive`, `sensitivity` and `specificity`.

The summary is stored rather than recomputed by each reader, as the gate verdict is, so
a later build prints the verdict this run was written with. A rule that stopped part-way
is not in `rules`, so it has no summary to misread. `run.rules[].declared_requests` is
the number of requests the rule declared, attempts included.

## Suite summaries

Each [quality suite](usage-suites.md) carries what it measured over its dataset and what
its gate concluded, as the suite built it while it ran. A suite has no `trial_summary`.

```json
"suite": {
  "dataset": "support-golden@2026.09",
  "dataset_digest": "sha256:…",
  "sample_size": 100,
  "sample_seed": 7,
  "trials_per_case": 3,
  "cases": 100,
  "measured": 98,
  "ungraded": 2,
  "worst": 0.9133,
  "best": 0.92,
  "low": 0.8418,
  "high": 0.9589,
  "min_pass_rate": 0.9,
  "min_sample": 30,
  "outcome": "pass",
  "reason": null,
  "correction": {"status": "deterministic", "assessor": null, "reason": null, "worst": null,
                 "best": null, "low": null, "high": null, "sensitivity": null,
                 "specificity": null, "dataset_digest": null, "positives": null,
                 "negatives": null}
}
```

| Field | What it is |
|---|---|
| `dataset`, `dataset_digest` | the dataset's declared `name@version` and the digest of its file |
| `sample_size`, `sample_seed` | the subset that ran, or both `null` when every case did |
| `trials_per_case` | the attempts at every case |
| `cases`, `measured`, `ungraded` | the cases that ran, those whose every attempt was graded, and those with an attempt nobody could grade |
| `worst`, `best` | the pass rate with every ungraded attempt counted failed, and counted passed |
| `low`, `high` | the 95% Wilson limits, at `worst` and at `best` |
| `min_pass_rate`, `min_sample` | the suite's gate |
| `outcome`, `reason` | `pass`, `fail` or `inconclusive`, and why the suite declined when it did |
| `correction` | `deterministic`, `corrected` or `uncorrected`; when corrected, the pass rates and limits corrected for the judge's error, in pass space, with the sensitivity, specificity, class counts and corpus digest applied |

A reader refuses a summary whose outcome its own numbers contradict: a pass below
`min_sample` or under the bar, a fail at or over it, a decline without a reason.

## Field names borrowed on purpose

`usage.input_tokens` and `usage.output_tokens` are the OpenTelemetry GenAI
convention's [`gen_ai.usage.input_tokens` /
`gen_ai.usage.output_tokens`](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)
without the namespace; `execution.seed` and `execution.temperature` match
`gen_ai.request.*`. If you already collect those, the manifest needs no
translation.

The SARIF output carries the same facts in SARIF's own vocabulary: `runs[].invocations[0]`
with `startTimeUtc`, `endTimeUtc`, `exitCode`, `exitCodeDescription` and
`executionSuccessful`, which is `false` whenever the run leaves a question open, with a
notification saying which (see [`usage-scan.md`](usage-scan.md#other-formats)).

## See also

- [`usage-diff.md`](usage-diff.md) — comparing two saved runs
- [`usage-scan.md`](usage-scan.md) and [`usage-probe.md`](usage-probe.md) — producing them
