---
title: "guardana baseline"
nav_order: 130
summary: "`guardana baseline`: accepted risk that expires"
status: stable
---

# `guardana baseline` — accepted risk with an owner and an end date

A waiver is the one place Guardana deliberately does not fail on a finding. The
only thing that makes that defensible is that it stays **temporary and visible**:
an accepted risk that never lapses is a finding somebody deleted.

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

## `update` only removes, and only on a complete scan

It drops waivers for findings that no longer occur and **never adds new ones**.
Accepting a risk is a decision somebody makes; `create` is where that happens.
An update that quietly widened a baseline would be the same failure as a gate that
weakens itself.

It also **refuses to touch the file** when the scan behind it was incomplete — a
rule that errored, or a run cut short — and exits `2`. The command decides a
finding is fixed by not seeing it, and a check that did not run produces exactly
that absence. Until 0.7.1 one broken rule deleted the waiver, the reason and the
approver, printed "is fixed", and exited `0`.

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
such. A file from a *newer* version is refused rather than read optimistically:
honouring waivers whose conditions this build cannot evaluate is the fail-open the
strictness exists to prevent.

## See also

- [`usage-scan.md`](usage-scan.md) — `--baseline` on a run
- [`privacy.md`](privacy.md) — baselines are redacted like every other output
