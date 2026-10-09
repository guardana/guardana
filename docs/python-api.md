---
title: "Python API"
nav_order: 55
summary: "`guardana.core.verify`: run what `guardana scan` and `guardana probe` run, and read every outcome as typed data"
status: beta
---

# Python API

`guardana.core.verify` runs Guardana from Python and returns the run as typed data. `guardana scan`, `guardana probe` and `guardana grade` run through the same module, so a run from Python and a run from the command line compose the same steps: discovery under a stated plugin trust, local rules, calibrations, the canary passes of a probe, redaction, the baseline, the gate and the saved-run manifest.

```python
from pathlib import Path

from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import load_profile
from guardana.core.verify import Verifier

verifier = Verifier(
    trust=PluginTrust(mode=PluginMode.BUILTINS),
    profile=load_profile(Path("guardana.yaml")),
)
verification = verifier.scan(Path("models"), relative_to=Path.cwd())

print(verification.gate, verification.exit_code)
for finding in verification.result.findings:
    print(finding.severity.name, finding.rule_id, finding.target_ref)
verification.save(Path("run.json"))  # the document `--format json --output` writes
```

`PluginTrust`, `PluginMode` and `load_profile` are needed to build a `Verifier` but sit outside the [supported surface](compatibility.md#the-supported-surface): a minor release may change them, so pin `guardana-core` to a minor while your code imports them.

A run that fails, stays indeterminate, or is stopped by its budget or by its target failing part-way is returned like one that passed. Read `verification.gate`, `verification.exit_code` or `verification.open_questions`; nothing is raised for an outcome.

To keep runs in the optional collector, the CLI sends them with `--reporter server://<collector URL>`; the collector's [HTTP API](usage-collector.md#the-http-api) stores and serves results without starting runs. `verification.save(path)` writes the same run document as `--format json --output`.

## Configure a run

`Verifier` holds the configuration and can run several targets in turn. It is frozen: to change the configuration, build another.

| Argument | Meaning |
|---|---|
| `trust` | Required. Which installed distributions may run code: `PluginTrust(mode=PluginMode.BUILTINS)`, `PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({"acme-rules"}))`, `ALL` or `DISABLED`. |
| `profile` | The profile, from `load_profile(path)`, `preset(name)` or built in code. Defaults to `default_profile()`, which redacts evidence. |
| `rule_paths` | Directories or files of local YAML rules, loaded beside the profile's `rules.paths`. |
| `rules`, `evaluators` | Rule and evaluator objects built in code, registered for this verifier only. |
| `calibrations` | Calibration records keyed by evaluator id. Defaults to the files the profile names under `calibrations:`. |
| `concurrency` | How many endpoint rules may run at once, as `probe --concurrency`. |
| `registry` | A registry you assembled yourself. Nothing is discovered or loaded into it, so passing `rule_paths`, `rules` or `evaluators` with it raises `ValueError`, and the profile's `rules.paths` are not loaded either: load them on it with `registry.load_yaml_rule_dirs(profile.rule_paths)`. Its own trust is the one in force and recorded. Each run works on a copy that gets the profile's trials and the judges under `evaluators:`, so the registry is never changed. |
| `judge_endpoint` | An `EndpointBuilder`: how the endpoint of each judge under `evaluators:` is built from its URL, model and key. Defaults to the HTTP client; a test passes one that returns an `EndpointTarget` on a scripted transport. A judge block that sets `provider` or `adapter` is refused with `ProfileError` when you pass your own builder, which could not honour either. |
| `demanded_rules` | Rule ids the run must complete. One that is skipped, errors or is never reached becomes a `demanded_check` coverage shortfall, so the run cannot pass whatever `fail_on_*` says. Empty by default; `guardana recipe run` demands every rule its lock pins. |
| `subject_kind` | What answered, a `SubjectKind` (`application` or `model_harness`), written as `subject_kind` into the exchanges the run keeps. `None` by default, which declares nothing; `guardana recipe run` passes its recipe's kind. |
| `secrets`, `remedies` | Values your target sends to authenticate beyond those it declares itself, as a tuple of strings, and a `FailureRemedies(auth=..., rate_limited=...)` from `guardana.core.target.failure`: what a recorded failure advises for a refused credential and for a sustained rate limit. An `EndpointTarget` declares its API key and what its transport declares, and any target can declare its own with `sent_secrets()` ([extending](extending.md#adding-a-target)); pass here only what the target does not declare. Each of these values, `secrets` and declared alike, is replaced by `[redacted:credential]` in the findings, the recorded failures and the kept exchanges, in every evidence mode. A recorded failure quotes the start of the endpoint's reply under the profile's privacy policy. Empty and generic advice by default. |
| `fixtures` | The fixtures file the run was given, a `FixturesRecord` (`Fixtures.record()` from `guardana.core.fixtures`), written into the saved run as `run.fixtures`, with `data` labelled declared. `None` by default; a target that declares `Capability.SEEDED_DATA` records its own. A run given fixtures demands every registered rule that needs seeded data and has something to check on the target, and one with no such rule is a `demanded_check` shortfall too. `diff` reads two runs given different fixtures, or fixtures on one side only, as incomplete. |

Budgets, failure bars, redaction and trials come from the profile, as on the command line.

## Run a target

```python
verification = verifier.scan(path, relative_to=None, baseline=None, source=None, deployment=None)
verification = verifier.run(target, relative_to=None, baseline=None, source=None, deployment=None)
verification = verifier.grade(path, source=None, deployment=None)
```

- `scan` builds the artifact target over `path` with the profile's excludes. A path that does not exist raises `FileNotFoundError`.
- `run` takes any target: an `ArtifactTarget` or your own file target, an `EndpointTarget`, your own endpoint target, an `McpServerTarget` or an `A2aAgentTarget`. An endpoint gets one pass per canary rule with a fresh canary planted when it implements `SystemPromptPlanter`; an MCP server and an A2A agent get one pass of rules. You own the target and close it.
- `grade` reads a recording ([`guardana grade`](usage-grade.md)) and runs the rules against a `RecordedTarget` built from it, sending nothing to any target. The recording's digest becomes `manifest.target.document` and its own description `manifest.recording`. A recording that cannot be read, or one a probe kept at other trials per case than the profile runs, raises `RecordingRefusedError` before anything runs.
- With `privacy.keep_exchanges: true` in the profile, `run` keeps the chat exchanges of the built-in `EndpointTarget`'s plain pass in `verification.exchanges` and records their digest in `manifest.exchanges`; `save(path)` writes them to `exchanges_path(path)`. Any other endpoint target is refused with `UnsupportedTargetError` before anything is sent.
- `relative_to` rewrites file paths in findings, observations and the file listing relative to that directory, as the CLI does against its working directory. `scan` also rewrites the target's own reference; `run` never does, because a third-party target owns its locator.
- `baseline` is a `Baseline` from `guardana.core.report.baseline.read_baseline(path)`; its findings are waived after redaction and before the gate.
- `source` (`RunSource`) and `deployment` (`DeploymentRef`) describe where the run came from and which deployment it verifies. Left out, the run is recorded as local and the deployment as undeclared; the engine reads neither from the environment.

### Protocol targets

Both live in `guardana.core.target` and send nothing until a rule reads them.

```python
from guardana.core.target import A2aAgentTarget, McpServerTarget, RegistryEntry

server = McpServerTarget(
    "https://mcp.example.com/mcp",
    credential=token,
    registry_entry=RegistryEntry.load(Path("server.json")),
)
agent = A2aAgentTarget("https://agent.example.com", credential=alice, other_credential=bob)
```

- `McpServerTarget(url, *, credential=None, sender=None, discovery_sender=None, registry_entry=None)`, or `command=[...]` with `allow_exec=True` for an stdio server. `sender` carries the server's own requests: a `Sender`, `(url, *, method="POST", body=None, headers=None) -> RawReply`, which raises `McpError` when no reply arrived and returns a `RawReply` for every status. `discovery_sender` fetches the discovery documents at addresses the server named: a `DiscoverySender`, which also takes `alongside` and `discovery` and must connect only to an address the guard accepted. With neither, both are the built-in pinned client. A `sender` without a `discovery_sender` raises `ValueError` at construction; pass the same scripted server for both, or `guardana.core.target.send` for the built-in pinned client.
- `RegistryEntry.load(path)` reads a registry `server.json` of at most 1 MiB and raises `RegistryEntryError` (a `ValueError`) for one it cannot use.
- `A2aAgentTarget(url, *, credential=None, other_credential=None, sender=None)` takes the http(s) URL of the agent's card (ending in `.json`) or of its origin; any other path, a second credential without the first, or the same value twice, raises `ValueError`. `sender` is a `Sender`.
- A server that stops accepting the agreed revision mid-run returns the `Verification` with `result.stopped_by` `target_changed` and exit code `4`.

A target runs once. Running the same object again, starting a second run while the first is under way, or running one that already sent requests raises `TargetReusedError`: build a fresh target for each run, so its usage, its budget and whatever it cached describe that run alone. A run refused before anything was sent, over its calibrations or a budget, leaves the target free to run. A target that cannot be weakly referenced is checked by its meter alone.

## Read a result

`Verification` is frozen.

| Field | What it holds |
|---|---|
| `result` | The `ScanResult`: findings, unverified results, waived findings, errors, observations, coverage shortfalls, assessments, the file listing (`scope`), the skipped rules and why a run stopped. A rule that found the target does not offer what it examines is skipped `not_offered` (`NotOffered`, from `guardana.core.rule`), a coverage gap. Redacted under the profile's privacy policy. |
| `manifest` | The `RunManifest` a saved run carries. |
| `gate` | `GateOutcome.PASS`, `FAIL` or `INDETERMINATE`. |
| `exit_code` | The code `guardana` gives this result: `0`, `1`, `2`, `4` when its target stopped it (`target_unavailable` or `target_changed`), or `6` ([exit codes](exit-codes.md)). |
| `passed` | `True` only when the gate passed. |
| `open_questions` | Each fact that leaves part of the run's question unanswered, in the order the gate reads them. |
| `judge_usage`, `judge_stops` | What each judge configured under `evaluators:` spent, and which judge's own ceiling stopped the run. |
| `exchanges` | The `Recording` of the chat exchanges the run kept under `privacy.keep_exchanges`, redacted, or `None`. |
| `stop_messages` | What the target did when it stopped the run, as the CLI prints it. Taken before redaction, so it names the cause under `metadata_only`, which withholds the recorded reason; never saved. |
| `document()`, `save(path)` | The saved-run document, in the current run schema ([saved runs](usage-run.md)); `save` also writes kept exchanges to `exchanges_path(path)` (`run.json` → `run.exchanges.jsonl`). |

SARIF, JUnit and the terminal report are rendered by `guardana-report`: `guardana.report.get_renderer("sarif", run=verification.manifest).render(verification.result)`.

## Read a saved run back

`load_verification(path)` reads a run saved by `--format json --output` or `save()`, of any
run schema, into a `Verification` with the gate the run recorded; `exchanges` is `None`. A run
that recorded no gate raises `ReportLoadError` from `guardana.core.report.load`. An
[installed format](outputs.md#export-a-saved-run-from-python) can then export it without
sending anything: `render(select_renderer(name, trust), load_verification(path))` from
`guardana.core.output`.

## When a run cannot be carried out

Every error derives from `VerificationError`.

| Error | When | The CLI's exit code |
|---|---|---|
| `TargetUnavailableError` | The target failed in a way the run could not record, outside any rule. A target that fails while a rule sends to it stops the run instead: the `Verification` is returned with `result.stopped_by` `target_unavailable`, what was graded before the failure, and an error at stage `target` naming what the target did. | `4` |
| `JudgeUnreachableError` | A judge configured under `evaluators:` could not be reached during the run. | `4` |
| `UnenforceableBudgetError` | The profile sets a budget the target or a judge cannot enforce; refused before anything is sent. | `3` |
| `CalibrationError` | A calibration file the run was pointed at cannot be read. | `3` |
| `RecordingRefusedError` | `grade` was given a recording that cannot be read, or one a probe kept at other trials per case than this profile runs. | `3` |
| `UnsupportedTargetError` | A trace target. Its unreadable records and its contracts are read by [`guardana analyze-trace`](usage-analyze-trace.md), which this module does not run. Also an endpoint target not built on the built-in `EndpointTarget` under `privacy.keep_exchanges`. | `3` for `probe --keep-exchanges` |
| `TargetReusedError` | The target already ran, here or by sending requests elsewhere. | — |

A profile that does not load raises `ProfileError` from `guardana.core.profile`. Ctrl-C propagates as `KeyboardInterrupt`.

## Serve your application's tools in CI

`guardana.core.doubles` is public too: `open_doubles(FILE, trace=PATH)` returns `Doubles` over the tools and records a fixtures file declares, with `acting_as(tenant)`, `call(name, **arguments)`, `tool(name)` and `close()`, and raises `DoublesError` for a call or a setup it refuses. Its behaviour and its trace are described in [`usage-doubles.md`](usage-doubles.md).

## What is supported

The supported surface is `guardana.core.verify.__all__`: `Verifier`, `Verification`, `EndpointBuilder`, `exchanges_path`, `load_verification` and the errors above, with the argument and field names on this page; and `guardana.core.doubles.__all__`: `open_doubles`, `Doubles`, `DoublesError`, `PRODUCER` and `INSTRUMENTED`. Their signatures are recorded with the rest of the supported surface in [`api-surface.json`](generated/api-surface.json), generated from source, and a test pins them. The output contract in `guardana.core.output` is versioned by its own `OUTPUT_API_VERSION` ([installed outputs](outputs.md#write-your-own)). Everything else is internal and may change in any release: the `Runner`, the registry's load state, `guardana.cli.*`, and every module or name that starts with `_`.

How a supported name is deprecated and removed, and which documents an upgrade keeps reading, is on the [compatibility page](compatibility.md). Not covered yet: `monitor`, `baseline create`, trace analysis and the import of observations run only from the command line, and a run whose judge failed mid-run keeps no partial result.
