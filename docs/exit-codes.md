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
| 4 | target unavailable or authentication failed |
| 5 | internal Guardana error |
| 6 | budget exhausted |
| 7 | run interrupted, partial evidence written |

## The reasoning

**Every non-zero code is a non-pass.** Nothing in the table means "probably
fine". A CI job that treats any non-zero as a failure is *correct* by default and
gets finer control only if it asks for it — the safe reading is the default
reading.

**`2` never means "nothing was found".** It means the question was not answered:
no rule ran, a check could not run under `fail_on_error`, or one side of a
comparison never finished. If indeterminate and clean shared a code, a broken
setup would read as a green build.

**`6` is separate from `1`, in both directions.** A budget stopping a run is not
a security verdict, so an under-budgeted pipeline must not report a failure that
never happened. More importantly the other way round: a team must not be able to
fix a red gate by lowering the budget until the run stops early. A stopped run is
reported as stopped whatever its partial findings say, and `guardana diff` refuses
to read the missing findings as an improvement.

**`4` is separate from `5`.** An unreachable endpoint is the user's environment;
an internal error is our defect. Conflating them sends bug reports to the wrong
place and hides real bugs in a category people learn to ignore.

**`3` is usage, not policy.** A malformed `guardana.yaml` must not look like a
policy failure, or a typo in a config file reads as a security finding.

**`7` is honest partiality.** Ctrl-C, or a timeout with evidence already written,
is neither a pass nor a completed failure. The partial run is kept and the code
says it is partial.

## Which commands produce which

`scan`, `probe` and `monitor` can produce any of them. `diff` has no target to be
unavailable, so `4` never occurs there; it uses `2` both for "these runs cannot be
compared" and for "one of them never finished". `run inspect`, `run migrate` and
`plan` produce `0` or `3`.

An unused code is better than a second table.

## Changed in 0.7 — breaking

Before 0.7, `2` meant three unrelated things: a bad baseline file, an unreachable
endpoint, and an impossible comparison. Those are now `3`, `4` and `2`
respectively, and `6` and `7` are new. `0` and `1` are unchanged.

There is deliberately no compatibility mode. A flag that made the same command
mean different things for two users would be a worse contract than a single
breaking change announced in the changelog — and everything that moved, moved
between non-zero codes, so no pipeline turns green by accident.
