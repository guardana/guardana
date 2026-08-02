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

## `update` only removes

It drops waivers for findings that no longer occur and **never adds new ones**.
Accepting a risk is a decision somebody makes; `create` is where that happens.
An update that quietly widened a baseline would be the same failure as a gate that
weakens itself.

## Versions

Version 1 baselines still load — their waivers have no expiry and are reported as
such. A file from a *newer* version is refused rather than read optimistically:
honouring waivers whose conditions this build cannot evaluate is the fail-open the
strictness exists to prevent.

## See also

- [`usage-scan.md`](usage-scan.md) — `--baseline` on a run
- [`privacy.md`](privacy.md) — baselines are redacted like every other output
