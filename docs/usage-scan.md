# `guardana scan` — static, offline, CI-friendly

Scans a directory as an **artifact target**: model files, dependency
manifests, and source. No network access, no live model required. This is
the fast, deterministic front door — the one that's safe to run on every
commit.

```bash
guardana scan <path> [OPTIONS]
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `PATH` (positional, required) | — | Directory to scan |
| `--profile PATH` | none (built-in default profile) | Path to a `guardana.yaml` policy file — see [`profiles.md`](profiles.md) |
| `--preset [ci\|pre-training\|monitor]` | none | Named policy preset (mutually exclusive with `--profile`) — see [`profiles.md`](profiles.md#named-presets---preset) |
| `--format [human\|json\|sarif\|junit]` | `human` | Output format |
| `--no-plugins` | off | Disable entry-point rule/evaluator discovery (YAML-only safe mode) — see [`SECURITY.md`](../SECURITY.md) |
| `--rules PATH` | none | Directory or file of custom YAML rules; repeatable. Combined with the profile's `rules.paths` — see [`writing-rules.md`](writing-rules.md). A malformed rule file is a warning, never an abort. |
| `--baseline PATH` | none | Baseline file: findings it lists are **waived** — still reported (as `WAIVED`), but they no longer fail the gate. A *new* finding elsewhere still does. See [Baselining](#baselining-existing-findings). |
| `--write-baseline PATH` | none | Write a baseline waiving every current finding to `PATH`, then exit 0. Add a reason to each entry before committing it. |
| `--reporter TEXT` | none | Forward findings to a collector, e.g. `server://https://collector.example.com/findings` |

## What runs

Only rules whose `target_kind` is `artifact` and whose declared
`required_capabilities` are satisfied by an artifact target (i.e.
`read_files`) execute. Endpoint-only rules (prompt injection, jailbreak,
system-prompt leak, output-secrets) are silently skipped against `scan` —
they need a live model, so use `guardana probe` for those.

Guardana dogfoods itself in CI by scanning its own source, which must stay
clean:

```console
$ guardana scan packages
✓ No findings.

0 finding(s); 17 rule(s) run, 0 skipped.
```

Note the path: in this repository, `guardana scan .` exits `1` by design —
[`examples/vulnerable-model/`](../examples/vulnerable-model/) is deliberately
malicious so the quickstart has something real to find. CI therefore scans
`packages`, not `.`.

## Example output with findings (`--format human`, the default)

```console
$ guardana scan ./some-model-repo
✖ [CRITICAL] guardana.supply_chain.pickle_opcode — Dangerous pickle opcode (arbitrary code on load)
    unpickling imports non-allowlisted callable: os.system  (./some-model-repo)
▲ [MEDIUM] guardana.supply_chain.hallucinated_package — Import of unknown package (possible slopsquat lead)
    unknown import 'torchutilz' (lead — verify it exists on PyPI)  (./some-model-repo)

2 finding(s); 17 rule(s) run, 0 skipped.
```

`hallucinated_package` scans `import`/`from` statements in `.py` source
files via `ast.parse`; it does not read `requirements.txt` or lockfiles.

## Other formats

```bash
guardana scan . --format json    # machine-readable findings + summary
guardana scan . --format sarif   # SARIF 2.1.0, for GitHub code-scanning upload
guardana scan . --format junit   # JUnit XML, for CI test-result reporting
```

## Baselining existing findings

Turning on a blocking gate for an existing repository is usually all-or-nothing:
either you fix the whole backlog first, or you exclude a rule entirely and go
blind to new occurrences. A baseline is the middle path — accept *today's*
findings with a reason, while a genuinely new one still fails the build.

```bash
# 1. Snapshot the current findings into a baseline file.
guardana scan . --write-baseline guardana-baseline.yaml

# 2. Edit guardana-baseline.yaml: replace each placeholder 'reason' with why the
#    finding is acceptable, and commit the file.

# 3. From now on, scan against it. Baselined findings are reported as WAIVED and
#    do not fail the gate; a NEW finding (a different fingerprint) still does.
guardana scan . --baseline guardana-baseline.yaml
```

A waiver is matched by a **fingerprint** — a stable hash of the rule id and the
finding's location — so it keeps waiving the same finding but never a different
one. Waived findings are never silently dropped: they appear in every format (a
`WAIVED` line in human output, a `waived` array in JSON, `suppressions` in SARIF),
so a reviewer can always see what was accepted and why. A malformed baseline file
is a hard error (exit 2), never a silent "waive nothing" or "waive everything".

## Exit codes

`scan` exits `1` (and CI treats the step as failed) when any finding's
severity is at or above the active profile's `fail_on.severity` **and**
either it has no verdict (a static check) or its verdict's `confidence` is
at or above `fail_on.min_confidence`. Otherwise it exits `0`. This is the
same `gate()` policy logic `probe` uses — see [`profiles.md`](profiles.md).

```bash
guardana scan . || echo "gate failed — see findings above"
```

## Forwarding to a collector

```bash
guardana scan . --reporter server://https://collector.example.com
```

Findings are POSTed to the collector after being printed locally — this
never blocks the local exit-code gate. See
[`architecture.md`](architecture.md#the-coreserver-boundary).
