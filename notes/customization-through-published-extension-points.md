---
title: "Customization through published extension points (#141)"
date: 2026-10-15
summary: "The customization proof passed all 12 steps using the published reference pack in a fresh environment with the network cut."
---
The maintainer ran this proof with Guardana 1.0.0rc3 from PyPI, using proof scripts at commit `a1801e0a`. The [workflow run](https://github.com/guardana/guardana/actions/runs/38747291852) records the results.

## Environment and packages

The proof used `.github/workflows/proofs.yml`, with one job on ubuntu-24.04 in a `python:3.13-slim` container.

A fresh environment outside the repository contained `guardana-cli==1.0.0rc3`, `guardana-reference-pack` 0.1.2 and pytest, installed from PyPI. The reference pack depends only on `guardana-core`.

Before the network cut, the pack's sdist was downloaded from PyPI and its sha256 checked against PyPI's JSON API. The proof then ran with `--network none`. The network canary was refused.

## Pack discovery and admission

```console
$ guardana doctor
```

Doctor exited with code 0 and listed `guardana-reference-pack`.

```console
$ guardana rule test 'reference.*'
```

This exited with code 3: an installed pack is refused until admitted.

```console
$ guardana rule test 'reference.*' --plugins allowlist --allow-plugin guardana-reference-pack
```

With the pack admitted, the command exited with code 0 and reported:

```text
2 rule(s); 6 fixture(s) passed, 0 failed, 0 could not run. 0 rule(s) not fully sampled.
```

## Validation and lock file

```console
$ guardana pack validate --plugins allowlist --allow-plugin guardana-reference-pack
```

Validation exited with code 0 and reported:

```text
2 pack(s) checked, 0 with problems
```

The proof wrote and checked a lock file:

```console
$ guardana pack lock guardana-lock.yaml --plugins allowlist --allow-plugin guardana-reference-pack
$ guardana pack lock guardana-lock.yaml --check --plugins allowlist --allow-plugin guardana-reference-pack
```

Both commands exited with code 0.

## Target, output format and reporter

```console
$ guardana scan --target reference-requirements://. --plugins allowlist --allow-plugin guardana-reference-pack --format reference-summary --reporter reference-file://summaries
```

The scan exited with code 0. It listed the pack's MEDIUM finding for an unpinned requirement, below the default `fail_on.severity` of `high`. The reporter wrote one summary file.

## Pack tests and conformance kit

The pack's own test suite, taken from the PyPI sdist, ran against the installed wheel: 45 tests passed and none was skipped.

The conformance kit in `docs/conformance-kit.md` ran row by row from a test module that imports only names in the supported surface documented in `docs/compatibility.md`. The module checks its own imports. 13 of its tests passed.

Three kit rows were recorded as not applicable to this pack. Each decision came from the pack's own rule declarations:

- `verify_rule` is outside the supported surface. The `guardana rule test` command above runs the same check.
- No pack rule needs what the MCP and A2A doubles serve, so the row for running a rule against those doubles was not applicable.
- No pack rule reads a trace, so the row using a `Trace` in a `TraceTarget` was not applicable.

The kit page names those helpers without saying they are outside the supported surface. This was recorded in #145 on 2026-10-14 as a documentation correction.

## Result

The proof passed: 12 of 12 steps held.

## What this proof does not show

The kit page lists what each check does not prove, row by row. Those limits also apply here.

This proof does not cover a pack that uses the MCP, A2A or trace rows. It does not show that a rule's samples resemble a team's real targets.
