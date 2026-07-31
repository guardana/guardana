# `guardana diff` — is this worse than last time?

`scan`, `probe` and `monitor` all answer *how is it now*. This one answers the
question a team actually has at every change — a new model, an edited system
prompt, one more tool wired into an agent: **is it worse than it was?**

That is what turns security testing from a launch ritual into part of the change
process. A regression stops the deploy, and a comparison that cannot honestly be
made says so instead of going green.

## Save a run, then compare two

```bash
guardana probe --url http://localhost:11434 --model llama3 \
  --format json --output monday.json

# …swap the model, edit the system prompt, add a tool…

guardana probe --url http://localhost:11434 --model llama4 \
  --format json --output friday.json

guardana diff monday.json friday.json
```

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
| `0` | Nothing got worse | pass |
| `1` | A regression above your policy's bar | **fail** |
| `2` | The two runs could not be compared | **fail** |

`2` is not a softer `0`. A comparison nobody could make and a comparison that
found nothing wrong are opposite answers, and only one of them is safe to print
next to a green build. You will see `2` for a run saved by Guardana 0.5 or
earlier (no schema version), a truncated file, two different kinds of target, two
runs with no rule in common, or a pair of arguments passed in the wrong order.

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

And the other direction, reported but never failing the build: `resolved`,
`clarified` (a check that could not grade now grades clean), `de_escalated`,
`coverage_gained`, `waiver_changed`, `count_changed`.

Two of those deserve their own sentence:

**A waiver is not a fix.** Adding a finding to a baseline reports as
`waiver_changed`, never as `resolved`. The problem did not go away; a person
decided to accept it.

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
It deliberately does **not** apply to `blinded` or `coverage_lost`: an ungraded
result carries confidence 0.0 by definition, so filtering those by confidence
would mean a stricter setting silently switched off detection of checks going
dark.

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

## Was it the model, or was it the test?

A saved run records a digest of every rule that ran. If a rule's own definition
changed between the two runs — someone added prompts, sharpened an expectation —
the comparison says so on the change and in its notes, so nobody blames the model
for a test that got harder.

The digest covers a rule's *declaration*. It cannot see a change inside the Python
of a plugin rule; the recorded tool version is what covers that, and a run made by
a different Guardana version is flagged in the notes.

## In CI

```yaml
- name: Save this run
  run: guardana scan . --format json --output current.json

- name: Compare against the last green run
  run: guardana diff baseline.json current.json --preset ci
```

Keep `baseline.json` wherever your CI keeps artifacts, and refresh it when you
accept a change. A `2` means the pair could not be compared — treat it exactly
like a `1` until you have read why.

## What it does not do

- **It does not re-run anything.** It reads two saved runs. Smoothing noise by
  repeating a probe N times would multiply the cost of every run and needs its own
  design, with that cost knowable before you start it.
- **It does not compare inventories.** What components a run *saw* is a real
  question with a real answer in the report's `observations`, but it is an
  inventory, not a gate.
- **It does not keep history.** Two runs, one answer.

## See also

- [`usage-scan.md`](usage-scan.md), [`usage-probe.md`](usage-probe.md) — producing the runs
- [`usage-monitor.md`](usage-monitor.md) — the same definition of "worse", applied continuously
- [`profiles.md`](profiles.md) — the `fail_on` bars this command reads
