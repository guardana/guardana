---
title: "guardana baseline"
nav_order: 130
summary: "`guardana baseline`: accepted risk that expires"
status: stable
---

# `guardana baseline` — accepted risk with an owner and an end date

`guardana baseline` manages waivers when you need to accept a finding temporarily and visibly.

```bash
guardana baseline create .                  # writes guardana-baseline.yaml
guardana baseline verify                    # expired or unreviewed waivers?
guardana baseline update .                  # drop waivers for findings that are fixed
```

## The file

```yaml
version: 2
waivers:
  - fingerprint: 705c242957abe403
    rule: guardana.supply_chain.insecure_transport
    location: app.py:2
    reason: internal tool, no traffic leaves the cluster
    approved_by: security@example.com
    expires: 2026-12-31
```

**A generated baseline is deliberately not usable as-is.** Every waiver carries
placeholder text for the reason and the approver, and `verify` fails while it is
still there. A baseline nobody edited is a list of findings somebody silenced in a
hurry, and it should look like one.

## Flags

`create` and `update` both run a scan, so both take the same plugin-trust flags
`scan`/`probe` do. `verify` reads a file and runs nothing, so it takes neither.

| Flag | Default | Meaning |
|---|---|---|
| `PATH` (positional) | — | Directory to scan; required unless `--target` is used |
| `--file PATH` | `guardana-baseline.yaml` | The baseline to refresh (`update` only; `create` writes with `--output`) |
| `--profile PATH` | none (built-in default profile) | Path to a `guardana.yaml` policy file |
| `--preset [ci\|pre-training\|monitor\|release]` | none | Named policy preset (mutually exclusive with `--profile`) — see [`profiles.md`](profiles.md#named-presets---preset) |
| `--target SCHEME://LOCATOR` | none | Build a trusted installed artifact target for `create` or `update` |
| `--target-option KEY=VALUE` | none | Repeatable, non-secret configuration passed to that target |
| `--plugins [all\|builtins\|allowlist\|disabled]` | `builtins`, or the profile's `plugins:` | Which installed plugins to load — same meaning as on `probe` |
| `--allow-plugin TEXT` | none | Distribution to trust; repeatable, needs `--plugins allowlist` |

`PATH` and `--target` are mutually exclusive. `verify` only reads the baseline,
so target selection applies to `create` and `update` only.

## Expiry actually expires

An expired waiver simply stops waiving: the finding comes back and fails the gate
again. It lapses the day *after* the date written, so a waiver expiring today is
still active today.

`verify` says which waivers lapsed and when, so a red gate is traceable to an
acceptance running out rather than looking like a new problem in the code:

```text
expired: 705c2429 (guardana.supply_chain.insecure_transport) lapsed on
  2026-07-01 — it no longer waives anything
```

Since 0.7.1 `guardana scan --baseline` says the same thing, and names any waiver
still carrying the generated placeholder. `verify` is the command nobody runs in a
pipeline, so the two facts a red build most needs — *this lapsed* and *nobody ever
wrote a reason for this* — were only ever available to somebody who already
suspected them.

## Written only from a complete scan

`create` and `update` write nothing when the scan behind them is not entitled to a
snapshot, and exit `2` (`6` or `7` when the run was stopped, as `scan` would). The
gate's own open questions decide — nothing verified, a run cut short, a coverage
shortfall, anything the profile's `fail_on` refuses — and a rule that did not run
counts whatever `fail_on_error` says. A profile that selects no rule produces a
scan with nothing in it, and a baseline taken over it would waive nothing while
looking complete; for `update`, it would delete every waiver as "fixed".

## `update` only removes, and only on a complete scan

It drops waivers for findings that no longer occur and **never adds new ones**.
Accepting a risk is a decision somebody makes; `create` is where that happens.
An update that quietly widened a baseline would be the same failure as a gate that
weakens itself.

It also **refuses to touch the file** when the scan behind it was incomplete — a
rule that errored, a run cut short, a run that verified nothing. The command decides a
finding is fixed by not seeing it, and a check that did not run produces exactly
that absence. Until 0.7.1 one broken rule deleted the waiver, the reason and the
approver, printed "is fixed", and exited `0`.

`create` and `update` write the file whole, through a temporary file and a rename, so a
write that fails part-way leaves the approved baseline as it was and exits `3`. `create`
refuses an `--output` that is a file the scan reads: `.guardanaignore`, the profile or
anything it names, a rule file, or a scanned file that is not an earlier baseline.

## A typo is refused, never read around

Unknown keys raise — at the top level and inside a waiver. The reason is one letter
long:

```yaml
waivers:
  - fingerprint: 705c242957abe403
    expries: 2026-01-01      # refused since 0.21.0
```

Read around, that waiver has no expiry and never lapses, `verify` reports it "still
active", and the finding stays waived indefinitely. It is the one mistake this file
is least able to survive, and until 0.21.0 it was the one mistake this file did not
catch — while the parser beside it already refused an unreadable *date* for exactly
that reason.

## Versions

Version 1 baselines still load — their waivers have no expiry and are reported as
such, and a file without `version` is read as version 1. A file from a *newer* version
is refused rather than read optimistically: honouring waivers whose conditions this
build cannot evaluate is the fail-open the strictness exists to prevent. A `version`
that is not a whole number (`true`, `"2"`, `2.0`) is refused as `version must be an
integer`, and one below 1 as `version 0 does not exist`, with exit `3` like any other
unreadable baseline.

## See also

- [`usage-scan.md`](usage-scan.md) — `--baseline` on a run
- [`privacy.md`](privacy.md) — baselines are redacted like every other output
