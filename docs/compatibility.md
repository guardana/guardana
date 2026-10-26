---
title: "Compatibility"
nav_order: 57
summary: "what Guardana keeps compatible from 1.0 — the Python facade, the extension, output and kit contracts, the command line, the exit codes and every persisted document — how a name is deprecated before it goes, and where the generated surface and matrix live"
status: stable
---

# Compatibility — what stays put, and how a change is announced

This page states what an upgrade keeps working. The surface it covers is listed in full,
generated from source, in [`api-surface.json`](generated/api-surface.json); which document and
API versions each release writes is in the [compatibility matrix](generated/compatibility-matrix.md).

## The supported surface

| Surface | What is covered |
|---|---|
| Python facade | `guardana.core.verify.__all__` and `guardana.core.doubles.__all__` ([Python API](python-api.md)) |
| Extension contract | `guardana.core.__all__` except `Runner`, `guardana.core.target.protocols.__all__`, `guardana.core.target.WireProtocol`, `PythonSource` and `UnreadSource` from `guardana.core.source` (the types a `FileReader` returns), `CoverageShortfall` and `ShortfallKind` from `guardana.core.report.shortfall` (how a rule records what it could not cover), and from `guardana.core.rule.fixture`: `RuleFixture`, `DeclaredFixture`, `FixtureOutcome`, `DEMANDED_OUTCOMES`, `materialise` ([extending](extending.md)) |
| Output contract | `guardana.core.output.__all__` ([installed outputs](outputs.md)) |
| Conformance kit | `guardana.testing.__all__` and `guardana.core.testing.__all__` ([conformance kit](conformance-kit.md)) |
| Versions | the six entry-point groups, `EXTENSION_API_VERSION`, `SUPPORTED_EXTENSION_API_VERSIONS`, `OUTPUT_API_VERSION`, `SUPPORTED_OUTPUT_API_VERSIONS`, and the version of every persisted document |
| Command line | every command, its options and arguments, whether each is required, a flag, repeatable, hidden or defaulted |
| Exit codes | every `ExitCode` member and its value ([exit codes](exit-codes.md)) |
| Locators | the reserved target schemes, the target scheme and output name grammar, the reserved format and reporter names, `server://` |
| GitHub Action | every `action.yml` input, whether it is required and whether it has a default |
| Environment | the name of every `GUARDANA_*` variable Guardana reads |

For each Python name the snapshot records its kind, the module that defines it, its
parameters (name, kind, whether it has a default, and the annotation as written in source) and
return annotation, a class's public methods and fields, and an enum's members. Help text is not
part of the surface. The trace format is versioned by its own [JSON schema](usage-analyze-trace.md)
and is not repeated in the snapshot.

Everything else is internal and may change in any release: `Runner`, the registry's load
state, `guardana.cli.*`, and every module or name that starts with `_`.

## The policy

From 1.0:

- The supported surface changes incompatibly only in a major release.
- A name to be removed is deprecated first, for at least one minor release, and removed only in
  the next major. Deprecation means a `DeprecationWarning` where Python can raise one, and a
  "Deprecated" entry in the [changelog](../CHANGELOG.md) that names the replacement.
- Every 1.x release reads the persisted documents earlier releases wrote, and writes the current
  version. Runs, collector envelopes, profiles, pack manifests and locks, and datasets are tested
  against documents the releases themselves wrote. Baselines, recipe locks, recordings, contracts
  and plans are read across their versions by tests that build each older version in code;
  so are recipes, versions 1 to 3 (`test_recipe.py`, `test_recipe_documents.py`), and native
  traces, migrated from versions 1 and 2 to 3 as they are read (`trace/test_trace_load.py`). One
  exception: `load_verification` refuses a schema-1 run, which recorded no gate; `load_report`
  and `guardana run migrate` read it.
- Every 1.x release supports extension API 2 and output API 1. A new API version is opt-in
  through the range a pack's manifest declares, and support for an API version is dropped only
  in a major release.
- A Python version is supported until its upstream end of life. Dropping one is announced one
  minor release ahead.

## Versioning

From 1.0.0, [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
governs releases. Package version strings use
[PEP 440](https://packaging.python.org/en/latest/specifications/version-specifiers/).

### Historical 0.y.z releases

Guardana's convention was that a minor release carried compatible features or
breaking changes. A breaking change was announced as "Changed — breaking",
with replacement guidance. This included a new default-enabled check or an
intentionally stricter default that could fail a previously passing build.
A patch was a compatible correction.

### Choosing a release

The highest-impact change decides the version. The number of completed issues
does not.

| Version part | Change |
|---|---|
| Patch | A compatible correction, including a false-green fix within documented behaviour. The changelog states which gates may now fail. |
| Minor | Compatible opt-in functionality, a new opt-in check, or a deprecation. |
| Major | A contract break, a removal, dropping a reader for an older persisted document, a check enabled by default that can fail a previously passing build, or an intentionally stricter default. |

Experimental behaviour and thresholds are outside the stability promise; their
saved documents still follow the persisted-document policy. A contract break,
removal, dropped reader or intentionally stricter default requires a major
release. The criteria for the first stable release are in
[product status](product-status.md#stable-release-criteria).

### Severity

A finding's severity is documented behaviour; the
[rule catalog](generated/rule-catalog.md) lists each rule's default severity
and every condition under which a finding carries another severity, higher
or lower. Raising a default or conditional severity is an intentionally
stricter default and requires a major release. Restoring the documented
severity is a patch. Lowering a severity requires a minor release whose
changelog names the gates that may now pass.

### Merging and publishing

Documentation-only, test-only and maintainer-tooling-only changes need no
package release. A maintainer squash-merges a pull request after review and
checks. The merge runs CI and never publishes a package.

A maintainer chooses the version from completed issues, runs the full release
gate, waits for green CI on the exact commit, then pushes the version tag.
Publishing pauses for one approval.

One tag releases all five packages at the same version: `guardana-core`,
`guardana-rules`, `guardana-cli`, `guardana-report` and `guardana-server`.
Between Guardana's own packages the pins are exact: the five ship together at
the same version and are tested only as one set, so nothing else may resolve
beside them.

### Package versions and release candidates

A release candidate's package version is written in PEP 440 form, for example
`1.0.0rc2`, and its Git tag is `v1.0.0rc2`. PEP 440 orders these versions:

`1.0.0rc1 < 1.0.0rc2 < 1.0.0rc10 < 1.0.0`

A risky minor or major release may first use a release candidate, such as
`1.1.0rc1`. A candidate is a pre-release, not a stable release.

`scripts/release.py` refuses a candidate whose generated
`docs/generated/api-surface.json` changes since the previous tag unless the
changelog's `Unreleased` section has a `Changed`, `Deprecated` or `Removed`
entry. It refuses a final release if that surface changes at all since its
last candidate.

## Feature and field availability

Use the supported 1.0 surface defined above as the baseline. For later CLI options,
profile parameters, Python keywords and payload fields, place
`Added in Guardana <version>` beside the item. Name the first published Guardana
package version that supports it. Use `Added in Guardana Unreleased` during
development; resolve the marker to the chosen version during release preparation.
Do not infer historical introduction versions from the current source tree.

Package availability and contract versions answer different questions. A persisted
field also identifies its document type and schema version. An extension or output
addition identifies its `extension_api` or `output_api` version when applicable.
Put availability guidance for a JSON Schema field in its `description`; no runtime
`since` key or custom schema keyword is needed.

An item's documentation can use this template; bracketed values are placeholders:

| Item | Available since | Contract | Older input |
|---|---|---|---|
| [item] | `Added in Guardana <version>` | [document type and schema version, or API version] | [migration behaviour and unavailable data, or not applicable] |

Older readers may refuse a newer schema. Document how older input is migrated and
which evidence remains unavailable. Missing measurements stay unknown; migration
does not turn them into zero or a passing verdict. Availability markers follow the
existing policy for compatible 1.x additions and do not make every schema addition
a major release.

See the [compatibility matrix](generated/compatibility-matrix.md) for document and
API versions and the [changelog](../CHANGELOG.md) for release records.

## The collector envelope

A run reaches the collector as a versioned envelope. Every change to the envelope raises its
version. A collector accepts every envelope version from 2 up to its own. An agent newer than
its collector is refused with `422`, and the response names the versions the collector accepts,
so upgrade the collector before the agents that report to it. Dropping an envelope version is a
major release.

## How a change is caught

`scripts/api_surface.py` writes `api-surface.json` from source, and the documentation check
fails when the committed file no longer matches. A release candidate whose surface differs from
the previous release's is refused unless the changelog's unreleased section has a "Changed",
"Deprecated" or "Removed" section.
