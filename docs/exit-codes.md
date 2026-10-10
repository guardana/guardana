---
title: "Exit codes"
nav_order: 190
summary: "the exit-status contract every command honours"
status: stable
---

# Exit codes

Machine consumers should never have to parse human output to find out what
happened, so the exit status is a contract. It is an importable enum
(`guardana.cli.exit_codes.ExitCode`) and a test asserts that this table matches
the constants in the code, so the documentation cannot drift away from the
behaviour.

| Code | Meaning |
|---|---|
| 0 | run completed, policy passed |
| 1 | run completed, policy failed |
| 2 | result indeterminate, or a comparison could not be made |
| 3 | invalid configuration or CLI usage |
| 4 | target or judge unavailable, or authentication failed; a run its target stopped part-way is saved |
| 5 | internal Guardana error |
| 6 | budget exhausted |
| 7 | run interrupted before it finished |
| 8 | an installed output failed: a format raised or returned no text, or a reporter failed, or a delivery `delivery.required` asks for was not acknowledged; the verdict is printed |

## The reasoning

`plan scan`, `config explain` and `target inspect` accept `--format human` or
`--format json`. Any other format, including `sarif` and `junit`, exits `3`
before the command reads configuration, discovers plugins or builds a target.

**Every non-zero code is a non-pass.** Nothing in the table means "probably
fine". A CI job that treats any non-zero as a failure is *correct* by default and
gets finer control only if it asks for it — the safe reading is the default
reading.

**`2` never means "nothing was found".** It means the question was not answered:
no rule ran, **no rule that ran reached a verdict**, a check could not run under
`fail_on_error`, one side of a comparison never finished, or **coverage the operator
demanded was not there** — a dimension named in `trace.require`, or one an assertion
in a security contract needs — or **a suite declined**: too few of its cases were
measured, its judge's error could not be corrected, ungraded trials leave its pass
rate on both sides of its bar, a corrected rate clears the bar while the raw rate and
the corrected lower limit do not, or the suite raised before it concluded — or **coverage
no run can do without was not there**: a scanned path held no file other than
`.guardanaignore` files (`empty_target`), or a rule attempted cases and graded none of
them, or fewer than `fail_on.min_graded_share` (`ungraded_cases`). If indeterminate and
clean shared a code, a broken setup would read as a green build.

The second of those is worth stating on its own, because it is the one that looks
like a completed run. An endpoint answering every request with an empty message — a
rate-limited gateway, a content filter, a wrong model name — makes every rule
execute and every evaluator decline. The rule count is full, the finding count is
zero, and nothing was established. That is `2`, and no `fail_on_*` switches it off:
`fail_on_inconclusive` decides what to do when *some* checks go dark, which is a
preference, and a run with nothing at all to show is not one. One check reaching a
verdict is enough to make `0` honest again.

That last case has no `fail_on_*` setting in front of it, deliberately: the
switches cover checks nobody specifically asked for, while this one was asked for by
name. `fail_on_skipped` defaults to off, so without it the
default path for "the contract I wrote could not be checked" would have been `0`.

A declined suite has no switch in front of it either, for the same reason: its bar
is a demand its author wrote into the rule, and a pass rate the suite could not
establish is not a preference to switch off.

**`6` is separate from `1`, in both directions.** A budget stopping a run is not
a security verdict, so an under-budgeted pipeline must not report a failure that
never happened. More importantly the other way round: a team must not be able to
fix a red gate by lowering the budget until the run stops early. A stopped run is
reported as stopped whatever its partial findings say, and `guardana diff` refuses
to read the missing findings as an improvement.

**`4` is separate from `5`.** An unreachable endpoint is the user's environment;
an internal error is our defect. A crash prints one line naming the exception type
and exits `5`; the traceback is printed only with `GUARDANA_DEBUG=1`, because it can
carry a URL or a payload from the run. A judge configured under `evaluators:` that cannot be
reached or rejects the request is `4` too, and the message names the judge's block
(`evaluators.llm_judge`), not the target. Conflating them sends bug reports to the wrong
place and hides real bugs in a category people learn to ignore.

**`4` describes a result too.** A target that fails part-way — it refuses the
credentials, answers `404`, `408`, `425`, `429` or `5xx` once retried, stops answering, or
sends a reply Guardana cannot read — stops the run (`stopped_by: target_unavailable`). A
chat endpoint, an MCP server and an A2A agent stop alike, an MCP server that cannot be
reached at all included ([MCP](usage-probe.md#when-the-server-fails-part-way),
[A2A](usage-probe.md#probing-an-a2a-agent)). An MCP server that stops accepting the
protocol revision the run agreed with it stops the run too, as `stopped_by:
target_changed`: it still answers, so `target_unavailable` would name the wrong cause.
Like a budget stop either outranks the verdict, and the run is saved with what it graded
before the failure ([probe](usage-probe.md#when-the-target-fails-part-way)). A `4xx` about
one request is not the target's failure: it is an error of the rule that sent it, and the
run exits `2` under `fail_on_error`. When pooled rules stop for several reasons,
`target_unavailable` outranks `target_changed`, and both outrank the budget's stop,
because a larger budget would not have let the run finish. A target that fails before
the run has a result — an stdio MCP command that cannot be started, say — and a judge
that fails at any point, still exit `4` with nothing saved.

**`3` is usage, not policy.** A malformed `guardana.yaml` must not look like a
policy failure, or a typo in a config file reads as a security finding.

**`7` is honest partiality.** Ctrl-C is neither a pass nor a completed failure.
Nothing the command had not yet written is written afterwards, and the code says
the run did not finish. Stopping `guardana monitor` with Ctrl-C exits `7` too, even
after an alert: the alerts it printed are the record of the cycles that raised them.

**`8` is separate from `5`.** An [installed output](outputs.md) is code another
distribution shipped: a format that raised or returned no text, so nothing was written,
or a reporter whose delivery is `unknown` because it raised, returned no valid status or
ran past its deadline. The bug report belongs to that distribution, so the code is not
`5`. The verdict is printed whenever `8` replaces its code; `8` replaces `0`, `1` and `2`,
and a run that stopped keeps `4`, `6` or `7`. A receiver that refused or did not answer is not
`8` by default: the delivery line says so and the verdict keeps its code, as for the collector.
When Guardana's own redaction fails before an output is called, nothing is written or sent and the
code is `5`, under the same precedence; `GUARDANA_DEBUG=1` prints the traceback.

**`8` is also a delivery a profile required.** A profile that sets `delivery.required: true`
([profiles](profiles.md#delivery)) asks that every delivery the run makes be acknowledged: the
collector's, which answers with its own acknowledgement and not merely a `2xx`, and an installed
reporter's, whose status must be `delivered` — `not_sent` included, since a job that delivered
nothing must not pass. Anything else is `8` under the same precedence, with the verdict printed:
it replaces `0`, `1` and `2`, a stopped run keeps `4`, `6` or `7`, and a redaction failure stays
`5`. `import-observations`, which otherwise exits `2`, exits `8` the same way. `monitor` never
stops a watch for it: it counts the alert deliveries that were not acknowledged and ends a
watch that would have exited `0`, `1` or `2` with `8`. Without the key nothing changes. The
setting is not part of the verdict, so it moves no profile digest. `scan --write-baseline` and
`probe --write-mcp-pin` forward nothing, so they refuse any `--reporter` with `3` before
anything is sent, whatever the profile says.

## Which commands produce which

`scan`, `probe` and `monitor` can produce any of them. `8` needs an installed format or
reporter, which `monitor` refuses, or a delivery `delivery.required` asks for: `monitor` exits
`8` when an alert's delivery to the collector was not acknowledged. A `monitor` bounded by
`--max-cycles` exits with the worst outcome any cycle earned, judged as `probe` judges
the cycle and as `diff` judges it against the first one; a policy failure outranks a
stop, and a cycle the endpoint dropped or its target stopped is `4` when nothing worse was seen. `diff` has no target to be
unavailable, so `4` never occurs there; it uses `2` both for "these runs cannot be
compared" — including a rule whose trials per case changed between the two runs — and
for "one of them never finished". `run inspect`, `run migrate`,
`trace inspect` and `plan` produce `0` or `3` — `plan` exits `3` when the target or a
judge meter could exceed the request budget — `trace inspect` grades nothing, so
it has no verdict to report and says what is missing in its output instead.
`grade` uses the codes `probe` uses, with no target to be unavailable: `3` also covers a
recording that cannot be read, one a probe kept at other trials per case than the run
grades, and an `--output` that would replace or remove the recording, `4` a judge that
cannot be reached, and `2` a run that graded nothing
([`usage-grade.md`](usage-grade.md)). Before reading anything, `scan`, `probe`, `grade`,
`analyze-trace` and `import-observations` exit `3` when `--output` or its sidecar path
(`<stem>.exchanges.jsonl`) is a file they read: one named on the command line (the scanned
file, recording, trace or results file, `--profile`, a `--rules` file or a rule file in a
`--rules` directory, `--baseline`, a `--contract`, and for `probe` `--system-prompt-file`,
`--fixtures` and its tenants' adapters, `--adapter`, `--mcp-pin` and `--mcp-registry-entry`)
or one the profile names under `rules.paths`, `contracts:`, `calibrations:` or a judge's or
guard's `adapter`; `recipe run` refuses the same profile files inside its
`output.directory`; `analyze-trace` also exits `3` when `--write-trace` is `--output`, its
sidecar path or such a file. `run migrate` exits `3` when the sidecar path of `--output`
is its input; writing over the input itself is migrating in place. It also exits `3`
when `--output` is the input's own sidecar or the destination cannot be written; the
destination is then left as it was. `scan --write-baseline` and
`probe --mcp … --write-mcp-pin` exit `3` beside `--output` or when their file cannot be
written; `probe` exits `3` for an MCP-only flag without `--mcp`; `recipe run` exits `3`
for a recipe that names a file inside its own `output.directory`.
`probe --keep-exchanges` exits `3` before sending anything when its sidecar path holds
exchanges the other saved run of the pair (`<stem>` or `<stem>.json`) records.
`analyze-trace` adds one route to `2` the others do not have: demanded coverage that
was not available, and a security contract that turned out to be about a different
AI system than the one under test. `baseline create`, `baseline update` and
`scan --write-baseline` write nothing and produce `2` when the run is not entitled
to a snapshot — any open question the gate refuses, with a check that did not run
counted whatever `fail_on_error` says — because a snapshot taken over a rule that
never ran is missing whatever it would have found. A run that stopped exits `6` or
`7` there, as it does on `scan`. `calibrate` exits `1` when the measured error is over
`--max-ece`, `2` when the measurement is not reliable, `4` when its judge cannot be
reached, and `6` when the profile's `budgets:` stop its judge — then nothing is
measured or recorded.

A connection that cannot be used as written is `3` on `probe`, `plan probe`,
`target inspect`, `monitor` and every judge, refused before anything is sent: an
unknown `--provider`, a `--system-prompt-file` or `--adapter` that cannot be read, an
`--api-key-env` naming an unset or empty variable, `--adapter` with `--provider` or
`--api-key-env`, and an adapter whose `url:` differs from `--url` or whose `method:` is
not `POST`. On `probe --mcp` the same holds for an stdio command given without
`--allow-exec`, which starts nothing, an `--mcp-token-env` naming an unset or empty
variable, and an `--mcp-registry-entry` that cannot be read or is not an entry; on
`probe --a2a` and `plan probe --a2a`, for an agent URL whose path is neither an agent card
(ending in `.json`) nor the origin; and on `probe --a2a`, for an unset token variable, a
second caller's variable without the first, or two variables holding the same value. None
of them is `5`, which is reserved for Guardana's own defects.

`recipe lock` and `recipe run` exit `4`, writing no lock and sending nothing, when the
installed target the recipe names fails to connect while it is being built.
`recipe lock` exits `0` once it wrote the lock, `1`, writing nothing, when a regression
case of a selected suite no longer holds with the rule as it is now — a side graded the
wrong way, a side declined, the evaluator raised, or the suite's evaluator cannot regrade
without sending — where `rule test` tells those apart as `1`, `2`, `2` and `3`; `2` when
what it would pin cannot be
pinned — nothing selected, plugin trust refused an installed extension, a selected check
that would not grade — and also `2`, having written the lock, when a selected check is
unpinned; `3` for a recipe it cannot read, and, writing nothing, for a configuration whose
run could never pass, as `plan` refuses it. `recipe lock --check` uses the same codes and
`1` when a pin moved: the lock is the policy it checks, as `pack lock --check` does. A
pin that moved, or a regression case that no longer holds, is `3` on `recipe run`, which
sends nothing, because the run was refused
rather than judged, and so is anything `recipe lock` refuses with `2`; otherwise `recipe run` exits as the run's gate decides, and every rule
its lock pins is demanded coverage: one the run did not complete makes it `2` whatever the
`fail_on_*` switches say, as a demanded `analyze-trace` dimension does
([`usage-recipe.md`](usage-recipe.md)).

`case add` exits `0` when it wrote the case, or showed it without `--write`; `1` when a side
of the proof graded the wrong way; `2` when a side declined; and `3` for a refused input,
recording, rule, evaluator or flag, and for an evaluator that raised. `case list` exits `0`,
or `3` for a recording it cannot read ([`usage-case.md`](usage-case.md)). `rule test` exits
`1` when a regression pair's side graded the wrong way, `2` when one declined or raised, and
`3` when a suite holds pairs its evaluator cannot regrade without sending.

An unused code is better than a second table.

### Changed in 0.21.0

**A run where every check declined now exits `2` instead of `0`.** The guard for
"nothing was verified" counted rules that *ran*, and a rule that ran and could not
grade cleared it exactly like one that ran and concluded. Measured against a live
endpoint returning an empty message: twenty-three checks, every one of them
reporting it could not grade, exit `0`, and `gate: pass` written into the saved run.

A pipeline that was green because its endpoint had stopped answering will now be
red. That is the change working, and it is the only situation it affects — a run
with a single concluded check is unaffected.

### Fixed in 0.7.1

Two commands did not honour the table it took 0.7 to write.

- **An unreadable saved run exited `1`.** `run inspect`, `run migrate` and `diff`
  let the manifest reader's own exception escape, so the user got a traceback and
  a code that says "a finding failed the policy" — the one thing a broken input
  file is not. `run inspect` and `run migrate` now report `3`; `diff` reports `2`,
  because a comparison with an unreadable side is one that could not be made.
- **`scan --write-baseline` exited `1` where `baseline create` exited `2`** for
  the identical situation. Codes are read by pipelines that never see the message
  beside them, so a code meaning two things means nothing.

## Changed in 0.7 — breaking

Before 0.7, `2` meant three unrelated things: a bad baseline file, an unreachable
endpoint, and an impossible comparison. Those are now `3`, `4` and `2`
respectively, and `6` and `7` are new. `0` and `1` are unchanged.

There is deliberately no compatibility mode. A flag that made the same command
mean different things for two users would be a worse contract than a single
breaking change announced in the changelog — and everything that moved, moved
between non-zero codes, so no pipeline turns green by accident.
