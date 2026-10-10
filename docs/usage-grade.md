---
title: "guardana grade"
nav_order: 85
summary: "`guardana grade`: grade answers your application already gave — a file you wrote, or the exchanges a probe kept — with your rules, sending nothing to the target"
status: beta
---

# `guardana grade` — grade answers that were already given

`guardana grade` runs your rules over a **recording**: the answers an application gave,
written down. It sends nothing to the target. The same suites, single-turn and scenario
rules, evaluators, gates and saved-run document as [`guardana probe`](usage-probe.md) apply,
so a run that grades recorded answers is gated and compared like a live one.

A recording comes from one of two places:

- **You write it**: the answers your application gave to your dataset's questions, collected
  however you run it.
- **`guardana probe --keep-exchanges` keeps it**: every chat exchange of the probe, redacted,
  beside the saved run, for `--url` or a pack's `--target` built on the built-in endpoint. Grading it again with a new rule, a sharper expectation or a new judge
  measures the grading on the very same replies.

```bash
guardana grade answers.jsonl --rules rules/ --profile guardana.yaml
guardana grade run.exchanges.jsonl --rules rules/ --format json --output regraded.json
guardana plan grade answers.jsonl --rules rules/      # what it would cost: judge calls only
```

For a probe's `<stem>.exchanges.jsonl`, `guardana grade`, `guardana plan grade` and
`guardana recipe run` compare the recording with the exchanges digest recorded by a saved
run beside it (`<stem>.json`, then `<stem>`). A different digest, no recorded exchanges
or an unreadable run warns on stderr; the recording is read as given and the exit code
does not change. With no saved run beside it, the recording is read as any recording.
An `--output` that is the recording or whose sidecar path is the recording is refused
with exit `3` before grading, because the report would replace or remove it.

## A recording

A recording is a JSONL file. Its first non-blank line is the header; every other non-blank
line answers one question. The [JSON Schema](https://guardana.dev/schemas/recording/v3.schema.json)
describes both lines.

```json
{"guardana_recording": 3, "name": "support-bot", "version": "2026-10-01", "verbatim": true, "subject_kind": "application", "rule": "acme.quality.support_answers"}
{"input": "How do I reset my password?", "reply": "Open Settings, then Security."}
{"input": "Where do I find my invoices?", "reply": "Ask your account manager."}
{"input": "Can I export my data?", "reply": "Settings has an Export button."}
```

| Header key | Meaning |
|---|---|
| `guardana_recording` | Required. The format, `3`, `2` or `1`. Guardana writes `3` and reads all three; a format-1 file declares no `subject_kind`, and only a format-3 line may hold `declined` or `meta`. |
| `name`, `version` | Required. What answered, and which version of the answers: they name the recording in the saved run. |
| `verbatim` | Required, `true` or `false`, no default. `true` says every reply is exactly what the application said; `false` makes every reply count as altered, so none is graded. |
| `subject` | Optional. What answered, as findings name it; defaults to `name@version`. |
| `subject_kind` | Optional, format `2` and later. What answered: `application` or `model_harness`, with the meanings a [recipe](usage-recipe.md) gives them. A recipe grading the recording takes it when the recipe declares no `subject.kind`. `recipe run` writes its recipe's kind into the exchanges it keeps; `probe --keep-exchanges` writes none. |
| `rule` | Optional. The rule a line answers when the line names none. |
| `origin` | Written by `probe --keep-exchanges`: the run id, the target, when it started, what stopped it, its gate, each rule's trials per case and every rule the run planned. |

| Line key | Meaning |
|---|---|
| `rule` | The rule whose question this answers. Required unless the header names one. |
| `input` | The question: a string for one user message, or a list of `{"role", "content"}` messages ending with a `user` message. |
| `reply` | The answer, as the application gave it. An empty reply is a reply. Required unless the line holds `declined`. |
| `declined` | Format 3, in place of `reply`: the application declined the request, as its adapter's `declines:` entry names it — `{"name", "reading", "status"}`, `reading` being `refusal` or `ungraded` and `status` one a decline may have. It is graded as the probe graded it ([how a decline is graded](usage-probe.md#how-a-decline-is-graded)). |
| `meta` | Format 3, optional: what the reply carried beside its text, as the adapter's `metadata_paths:` named it — at most 16 names, each `[a-z][a-z0-9_]*`, each a string of at most 1,024 characters. |
| `altered` | Optional, `true` when the reply is not what the application said (scrubbed, truncated). An altered reply is never graded. A declined line holds no reply, so it is never `altered`. |
| `key` | Written by `probe --keep-exchanges`: the digest of the messages as the rule sent them, so a redacted `input` still matches. |

A line `probe --keep-exchanges` kept from a guarded endpoint may hold the decline and the
reply's metadata:

```json
{"rule": "acme.guarded.refuses", "input": [{"role": "user", "content": "…"}], "declined": {"name": "content_filter", "reading": "refusal", "status": 400}, "meta": {"request_id": "r-2"}, "key": "sha256:…"}
```

A line answers the question its rule asks when the `input` is exactly the messages the rule
sends: same roles, same text. Several lines for one question are trials, read in file order.
Two rules asking the same question each need their own lines. Unknown or repeated keys, a line
over 1 MiB, a file over 64 MiB, a header with no lines, and text that is not UTF-8 are refused
with the line at fault (exit `3`).

## What is graded, and what is not

`grade` runs against a target that answers chat from the recording and supports nothing else.

| Rule | Outcome |
|---|---|
| A suite, single-turn or scenario rule the recording answers | Graded as in a probe. |
| A rule that plants a canary or offers tools | Skipped for a missing capability: a recording neither plants a canary nor offers tools. |
| An MCP or A2A rule | Skipped as `not_applicable`: the recording speaks chat and the rule examines another protocol, so nothing is missing and `fail_on_skipped` does not count it. |
| A rule no line names, and the recording's `origin` does not list | Skipped as `not_recorded`, before it runs; `plan grade` lists it too. |

Nothing missing is ever read as a pass:

- A trial of a suite with no recorded reply is ungraded (`status: error`, `reason: not_recorded`)
  and stays in the suite's denominator; a reply that is altered is ungraded too
  (`status: inconclusive`, `reason: reply_altered`). As for any ungraded trial, the suite
  passes only when its bar holds with every such trial counted as failed, and declines when
  the ungraded trials could put its rate on either side of the bar.
- Any other rule that asks a question the recording does not answer, or reaches an altered
  reply, is recorded as an error, even if the rule caught the exception itself.
- A rule the recording's `origin` says the probe planned, with no line for it (the probe
  stopped first, or the rule failed), is an error, not a skip.
- Recorded replies a rule that ran never asked for, and lines naming a rule no loaded rule has,
  are errors: an unread reply may be the failing one.
- A recording a probe kept at other trials per case than this run grades is refused before
  anything runs (exit `3`): grade it with the probe's `--trials`.
- A reply that holds a placeholder Guardana's redactor writes counts as altered.
- A declined line is read as the decline it is, before any check of the reply, whatever
  `verbatim` says: grading it reaches the verdict the probe reached.
- A run that graded nothing is `indeterminate` (exit `2`).
- A recording whose `origin` says the probe was stopped (`stopped_by` is set) holds only the
  replies that probe received before it stopped. The run carries an `incomplete_recording`
  coverage shortfall naming the origin run, so it is `indeterminate` (exit `2`) even when
  every rule passes, and fails (exit `1`) only when a finding fails it. No switch turns this
  off, and `plan grade` refuses such a recording before anything runs. Only a stop counts:
  an origin that ended `indeterminate` grades normally, and the origin is declared, not
  verified.

Under the default profile, rules the recording does not answer are skipped and do not fail the
gate; `grade` names them on stderr. Select the rules the recording answers with
`rules.include`, and use `--preset release` to refuse a run that skips any.

```console
$ guardana grade answers.jsonl --rules rules/ --profile guardana.yaml
✖ [HIGH] acme.quality.support_answers — The support bot still points to Settings
    support-golden@2026.10: 3 of 3 cases measured, 1 trial each · pass rate 66.7% (95% CI 20.7 to 93.9%) · bar 90% · below the bar  (recording:support-bot@2026-10-01)

Measured
  acme.quality.support_answers  support-golden@2026.10: 3 of 3 cases measured, 1 trial each · pass rate 66.7% (95% CI 20.7 to 93.9%) · bar 90% · below the bar

1 finding(s); 1 rule(s) run, 0 skipped. 3/3 case(s) measured. 1 component(s) observed.
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--concurrency INTEGER` | `4` | How many rules may grade at once |
| `--plugins [all\|builtins\|allowlist\|disabled]` | `builtins`, or the profile's `plugins:` | Which installed plugins to load — same meaning as on `probe` |

## Traffic and budgets

No request reaches the target: the saved run records `usage.requests: 0`. A judge configured
under `evaluators:` is called as in a probe, metered on its own and held to the budget flags
(`--max-requests`, `--max-input-tokens`, `--max-output-tokens`, `--max-duration`,
`--max-requests-per-minute`) and the profile's `budgets:`; a rate paces each judge on its own
meter. Before the first call, `grade` prints on stderr where each judge's calls
go, how many there can be and the budget they are held to, or that none is set. A judge that
cannot be reached stops the run with exit `4`.

`guardana plan grade` makes the same selection and prices the judge calls without making any:

```console
$ guardana plan grade answers.jsonl --rules rules/ --profile guardana.yaml
1 rule(s) would run, 0 skipped.
requests: 0 — every answer comes from the recording; nothing reaches the target
trials: 1 attempt(s) per case, each read from the recording
judge calls: none — no selected rule grades with a judge

No request was sent to produce this estimate.
```

## The saved run

A graded run is a [saved run](usage-run.md) like any other, with the execution it graded kept
apart from how it graded it:

- `run.target.ref` is `recording:<subject>`, never the live target's address, so a graded run
  never shares a fingerprint or a baseline waiver with a probe.
- `run.target.document` is the SHA-256 of the recording file: the execution's identity.
- `run.recording` is what the recording says of itself: `name`, `version`, `subject`,
  `verbatim` and its `origin`. It is declared, not verified; only the digest links two runs.
- `run.rules[]` and `run.evaluators[]`, including each judge's identity, are the grading.
- `run.source.kind` is still `local` or `ci`: how the run was started.

[`guardana diff`](usage-diff.md) says when the two runs graded the same recorded replies (the
probe's `run.exchanges.digest` equals the graded run's `run.target.document`), and leaves out of
its comparison every rule graded by a different evaluator or judge.

```console
$ guardana diff run.json regraded.json
Measured cases
  3 case(s) compared like for like: 3 → 3 passing

Worth knowing
  • the runs examined different targets (http://127.0.0.1:18765#support-bot and recording:http://127.0.0.1:18765#support-bot) — intended when comparing two models, worth a second look otherwise
  • the two runs did not have the same reach — a difference in findings may be a difference in what could be checked
  • both runs graded the same recorded replies (sha256:d41f52ca92a6251261f2587a5a568019166bfa429fc60894c783b39a2389d8a1), so a difference between them is not the system answering differently

✓ No regression against the previous run.

0 change(s); 0 check(s) unchanged, 0 worse.
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The gate passed. |
| `1` | The gate failed. |
| `2` | Indeterminate: a check errored, a suite declined, nothing was graded, the recording's origin was stopped, or `--preset release` met a skip. |
| `3` | Invalid usage: an unreadable recording, other trials than the probe kept, a bad profile or flag, or an `--output` that would replace or remove the recording. |
| `4` | A judge configured under `evaluators:` could not be reached. |
| `5` | An internal error. |
| `6` | A judge's budget ran out. |
| `7` | Interrupted. |
| `8` | An [installed format](outputs.md) named by `--format` failed; the verdict is printed. |

See [exit codes](exit-codes.md). `grade` has no `--reporter`: the collector does not receive
graded runs. `--format` takes the built-in formats or an [installed one](outputs.md).
