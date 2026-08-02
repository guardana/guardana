# `guardana doctor` and `guardana config`

The commands for "why did that scan do what it did", and the ones a support
conversation should start with.

```bash
guardana doctor
guardana config validate
guardana config explain
```

## `doctor` — what this installation is

```text
✓ guardana-core: 0.7.0
✓ guardana-rules: 0.7.0
✓ guardana-cli: 0.7.0
✓ guardana-report: 0.7.0
✓ rules discovered: 32
✓ evaluators discovered: 4
✓ profile: ci parsed
! fail_on_error: off — a check that could not run will not fail the build
! budgets: no ceiling set — a probe against a paid endpoint has no upper bound

0 problem(s), 2 thing(s) worth knowing.
```

**It contacts nothing.** A diagnostic that costs money or shows up in somebody's
production logs is one people avoid running, which defeats the purpose.

It answers the questions that are otherwise guessed at:

- **which distributions are installed, and whether they agree.** A stale
  `guardana-rules` beside a current CLI is a different tool than the version
  string suggests, and it is invisible until a rule behaves oddly.
- **which plugins loaded, and which failed to import.** A failed import is a check
  that will not run.
- **whether third-party rules are installed.** They are code this process imports.
- **which settings weaken the gate.** Each is a legitimate choice; making it
  silently is what must not happen.

Exit `3` when something is broken — no rules discovered, a plugin that failed to
load. Warnings alone exit `0`: they are things worth knowing, not faults.

## `config validate` — fail before you pay

Parses the profile and stops. Useful as an early pipeline step: a typo in
`guardana.yaml` should fail in a second rather than after a probe has spent its
budget finding out.

## `config explain` — what is actually in force

```bash
guardana config explain --format json
```

A profile file shows what somebody wrote. The question they actually have is what
is *in force*, and most of a gate is defaults — including the ones nobody typed.
`explain` prints the resolved settings: thresholds, budgets, privacy, safety, and
the privacy policy digest that a run manifest also records, so a saved run can be
matched back to the configuration that produced it.

## See also

- [`profiles.md`](profiles.md) — what each setting means
- [`exit-codes.md`](exit-codes.md) — what `3` means here
