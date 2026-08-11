---
title: "Exit codes and gate semantics"
nav_order: 120
summary: "why the codes are what they are"
status: implemented
---

# Design: stable exit codes and gate semantics

**Status:** implemented in 0.7 · the table lives in [`docs/exit-codes.md`](../exit-codes.md)

## The problem

Guardana's exit codes are stable in practice and undocumented in contract. Today:
`0` clean, `1` gate failed, `2` used for three unrelated things — a bad baseline
file, an unreachable endpoint, and an impossible comparison. A CI pipeline that
wants to treat "the endpoint was down" differently from "the model got worse"
cannot, and the only alternative is parsing human-readable output, which is not an
interface anyone should build on.

## Design

```text
0  run completed, policy passed
1  run completed, policy failed
2  result indeterminate, or a comparison could not be made
3  invalid configuration or CLI usage
4  target unavailable or authentication failed
5  internal Guardana error
6  budget exhausted
7  run interrupted, partial evidence written
```

### Decisions

**Every non-zero code is a non-pass.** Nothing in the table means "probably fine".
A CI job that treats any non-zero as a failure is *correct* by default and gets
finer control only if it asks for it. This is the whole point: the safe reading is
the default reading.

**`2` never means "nothing found".** It means "the question was not answered".
Indeterminate and clean must not share a code, or a broken setup reads as a green
build — the failure mode this project exists to prevent.

**`6` is separate from `1`.** A budget stopping a run is not a security verdict.
Merging them would let an under-budgeted pipeline report a security failure that
never happened, and — worse in the other direction — let a team "fix" a failing
gate by lowering the budget until the run stops early.

**`4` is separate from `5`.** An unreachable endpoint is the user's environment; an
internal error is our bug. Conflating them sends bug reports to the wrong place and
hides real defects in a category people learn to ignore.

**`3` is usage, not policy.** A malformed `guardana.yaml` must not look like a
policy failure, or a typo in a config file reads as a security finding.

**`7` is honest partiality.** Ctrl-C or a timeout with evidence already written is
neither a pass nor a completed failure. The partial run is kept, and the code says
it is partial.

### Migration — decided against a transitional mode

This proposed `--exit-code-mode legacy|strict` for one minor. That is **not** what
shipped: the whole table landed in 0.7 as a single breaking change, announced in
the changelog.

The reason is that the flag would have made the same command mean different
things for two users of the same version, for a full release cycle, and every
tool reading those codes would have had to know which mode produced them. Weighed
against that, the actual exposure is small: `0` and `1` are unchanged, and
everything that moved, moved *between non-zero codes*. No pipeline turns green by
accident, which is the only direction that would have justified the cost.

### What must be tested

- one test per code, asserting the exact integer — a code nobody tests is a code
  that drifts;
- a test that no command can exit `0` while `errors` is non-empty and the policy
  says `fail_on_error`;
- a test that budget exhaustion produces `6` and never `0` or `1`;
- a test that the documented table in `docs/exit-codes.md` matches the constants in
  code, so the documentation cannot drift from the behaviour.

### Open question — resolved

`diff` reuses the table. It has no target to be unavailable, so `4` never occurs
there, and it uses `2` for both "these runs cannot be compared" and "one of them
never finished". An unused code is better than a second table.
