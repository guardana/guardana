---
title: "guardana diff"
nav_order: 140
summary: "`guardana diff`: compare two saved runs, fail on deterioration"
status: stable
---

# `guardana diff` — is this worse than last time?

`guardana diff` compares runs when you need to see whether a change made results worse. `scan`, `probe`, and `monitor` check current results. A regression can stop a deploy; an incomparable pair is reported as such.

## Save a run, then compare two

```bash
guardana probe --url http://localhost:11434 --model llama3 \
  --format json --output monday.json

# …swap the model, edit the system prompt, add a tool…

guardana probe --url http://localhost:11434 --model llama4 \
  --format json --output friday.json

guardana diff monday.json friday.json
```

A side that cannot be read — not a regular file, over 256 MiB, or not a Guardana run — makes
the pair incomparable (exit `2`).

Use `--output` rather than a shell redirect. A redirect in PowerShell writes
UTF-16, which the reader on the other end cannot parse, and the corruption
surfaces a day later far from its cause.

The same works for a static scan:

```bash
guardana scan . --format json --output before.json
guardana scan . --format json --output after.json
guardana diff before.json after.json
```

## Exit codes

| Code | Meaning | In CI |
|---|---|---|
| `0` | No regression meets both the policy's severity bar and `min_confidence`, and none lacks evidence; regressions below either bar are still printed | pass |
| `1` | A regression meets both the policy's severity bar and `min_confidence`, or lacks evidence to weigh | **fail** |
| `2` | The two runs could not be compared | **fail** |

`2` is not a softer `0`. A comparison nobody could make and a comparison that
found nothing wrong are opposite answers, and only one of them is safe to print
next to a green build. You will see `2` for a run saved by Guardana 0.5 or
earlier (no schema version), a truncated file, two different kinds of target, two
runs with no rule in common, or a pair of arguments passed in the wrong order.

You will also see `2` when either run recorded an error — a refused pack, a rule that
raised, a file nobody could read. Those checks never ran, so a finding missing from that
run is unknown rather than fixed, and the error's source is named.

You will also see `2` when a rule made a different number of attempts per case in the
two runs — `trials changed 1 → 5` names it. More attempts find more failures, so the
difference is sampling, not a regression, and the rule is left out of the comparison
rather than read either way. A rule that does not repeat, such as an MCP check, is
still compared when only the run's `--trials` moved. Re-save the baseline at the
new number of trials.

## What counts as worse

A check is *one rule, in one place*. Against files the place is the path; against
a live model or MCP server there is only one thing under test, so the check is
the rule itself — which is why swapping `llama3` for `llama4` still compares.

| Reported as | What happened |
|---|---|
| `appeared` | A problem where there was none. |
| `proven` | A check that could not grade now proves a problem. Not a new flaw — new evidence for an old one. |
| `blinded` | A check that used to reach a verdict no longer can. **The finding count falls here**, which is exactly why a comparison that counted would call going blind an improvement. |
| `escalated` | Same check, higher severity. |
| `coverage_lost` | A rule that ran before did not run this time. Whatever it would have found is unknown, not absent. |
| `left_scan` | The file that held a problem, or a check that could not grade, is not among the files the second run listed. Printed as `LEFT THE SCAN`. |

And the other direction, reported but never failing the build: `resolved`,
`clarified` (a check that could not grade now grades clean), `de_escalated`,
`coverage_gained`, `waiver_changed`, `count_changed`.

Two of those deserve their own sentence:

**A waiver is not a fix.** Adding a finding to a baseline reports as
`waiver_changed`, never as `resolved`. The problem did not go away; a person
decided to accept it.

**A file that left the scan is not a fixed one.** Against files, a finding is
`resolved` only when the second run listed its file and the rule found nothing there.
A file the second run did not list — deleted, moved into a skipped directory like
`build/`, renamed, or excluded by `.guardanaignore` or `rules.paths_exclude` — is
`left_scan`, and the detail names the exclude when one matches. Removing a malicious
file is a real fix, and the comparison still cannot tell it from hiding the file, so
the second run is the evidence: it lists what it read. A second run saved before
schema 12 records no listing, and a finding that disappeared from it reads as before.

**A narrower run is not a better one.** If the second run used a tighter profile,
its missing findings are `coverage_lost` — a regression — not progress. This is
the failure mode the whole feature is built around, and the reason a saved run
records *which* rules ran rather than how many.

## Noise, and why the count does not fail the build

A live model answers differently every time. If the gate tripped on "three
findings yesterday, four today" it would trip constantly, someone would switch it
off, and a scanner nobody runs is the worst outcome available.

So the comparison works on **state**, not on tallies: a model either fails a check
or it does not, and that is far steadier than how many prompts it failed. A
changed count is reported and never gates on its own. Under a static scan nothing
is lost by that — a genuinely new problem lands in a new file, which is a new
check and a regression in its own right.

The second filter is confidence. Your policy's `min_confidence` applies to
regressions backed by a graded verdict, so a shaky judge cannot stop a deploy.

**Neither filter applies to `blinded`, `coverage_lost` or `left_scan`**, and severity is the one
that mattered. An ungraded result carries confidence 0.0 by definition, and it keeps
whatever severity its rule declares — so an artifact nobody could read is a `LOW`
that every default `severity` bar filtered away, and the comparison printed "worse"
while exiting `0`. A check going dark is now a regression at any severity and any
confidence: filtering it would mean a stricter setting silently switched off
detection of exactly that.

## Policy

`guardana diff` takes `--profile` and `--preset` like the other commands, and uses
the same `fail_on` bars:

```bash
guardana diff before.json after.json --preset ci
guardana diff before.json after.json --profile guardana.yaml
```

`fail_on.severity` sets how bad a regression has to be to fail. `coverage_lost`
ignores it — a rule that did not run has no severity, and an unknown cannot be
thresholded away.

## The measured sample

A comparison of two dynamic runs also prints the population the changes happened
in:

```text
Measured cases
  21 case(s) compared like for like: 16 → 15 passing
  2 not compared (the assessor or dataset changed)
  0 gone, 0 new
```

A rule that repeats records one assessment per attempt, and the comparison counts
**cases**: a case is compared only when every planned attempt was graded, and it passes
only when every attempt passed.

Every line answers a question the change list cannot. **21 compared** is the
denominator: without it, "one fewer finding" and "half the cases stopped being
graded" look identical. **Not compared** is a refusal, not a gap — a case whose
expectation was edited is a different test, and pairing the two would attribute an
authoring decision to the model. **Gone / new** is coverage of the measurement
channel itself.

Two things it deliberately does *not* do. It never prints a single percentage: a
pass rate with no denominator beside it is exactly the number this channel exists
to stop being quoted. And it adds no new way to fail the build — a case that
started failing already reaches the gate as a finding, and counting it twice would
make one event look like two. What it can do is add a note, and going blind gets
one:

```text
Worth knowing
  • 3 case(s) produced a value before and could not be graded this time
    (guardana.prompt.jailbreak#b94d…) — a smaller sample, not a better result
```

`--format json` carries the same numbers under `measurement`. The comparison document is
version 3, described by [`diff/v3.schema.json`](https://guardana.dev/schemas/diff/v3.schema.json).

## Was it the model, or was it the test?

A saved run records a digest of every rule that ran. If a rule's own definition
changed between the two runs — someone added prompts, sharpened an expectation —
the comparison says so on the change and in its notes, so nobody blames the model
for a test that got harder.

The digest covers a rule's *declaration*. It cannot see a change inside the Python
of a plugin rule; the recorded tool version is what covers that, and a run made by
a different Guardana version is flagged in the notes.

A rule **graded differently** in the two runs — another evaluator, or a judge whose
recorded identity (model, endpoint, samples) changed — is left out of the comparison:
its findings are neither new nor resolved and its measurements are not paired, and the
comparison is incomplete (exit `2`) with a note naming it, as for a rule whose trials per
case changed. A judge identity recorded on one side only is unknown, not a change.

When one run is a [`guardana grade`](usage-grade.md) of the exchanges the other kept, or
both graded the same recording, a note says both runs graded the same recorded replies
and names the digest: a difference between them is not the system answering differently.
Only a digest of the whole file counts.

When both runs were started from a recipe and the recipes declared different subjects, one
an `application` and the other a `model_harness`, a note names both: a model reached
without the application's prompt, tools and data answers differently, so a difference may be
that rather than the system changing. A run started without a recipe declared nothing, and
no note is added.

When both runs recorded a profile digest, a provider wire, an adapter digest or a system-prompt
digest and they differ, a note names the settings that changed: a difference between the runs
may come from that rather than from the system. A setting one run did not record is unknown,
and no note is added for it.

Two runs given different [fixtures](usage-fixtures.md) — another file digest, or the same
file under another `markers` algorithm — or fixtures on one side only are an incomplete
comparison (exit `2`), not a note: an item one run asked about the other never did, so a
finding on it that disappears would otherwise read as a fixed leak. A run migrated from
schema 14 was given no fixtures.

## In CI

```yaml
- name: Save this run
  # exit 1 is a finding the comparison will judge; 2 and above still stop the job
  run: guardana scan . --format json --output current.json || test $? -eq 1

- name: Compare against the last green run
  run: guardana diff baseline.json current.json --preset ci
```

Keep `baseline.json` wherever your CI keeps artifacts, and refresh it when you
accept a change. A `2` means the pair could not be compared — treat it exactly
like a `1` until you have read why.

## What it does not do

- **It does not re-run anything.** It reads two saved runs. Repeated attempts are
  made by `probe --trials N` and saved in the run; see
  [`usage-probe.md`](usage-probe.md#repeated-trials).
- **It does not compare inventories.** What components a run *saw* is a real
  question with a real answer in the report's `observations`, but it is an
  inventory, not a gate.
- **It does not keep history.** Two runs, one answer.

## See also

- [`usage-scan.md`](usage-scan.md), [`usage-probe.md`](usage-probe.md) — producing the runs
- [`usage-monitor.md`](usage-monitor.md) — the same definition of "worse", applied continuously
- [`profiles.md`](profiles.md) — the `fail_on` bars this command reads
