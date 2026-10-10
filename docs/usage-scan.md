---
title: "guardana scan"
nav_order: 60
summary: "`guardana scan`: static, offline, CI-friendly"
status: stable
---

# `guardana scan` — static, offline, CI-friendly

`guardana scan` checks a directory of model files, dependency manifests, and source when you need an offline check on a commit. It calls no live model and opens no network connection unless you pass `--reporter`.

```bash
guardana scan [PATH] [OPTIONS]
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `PATH` (positional) | — | Directory to scan; required unless `--target` is used |
| `--target SCHEME://LOCATOR` | none | Build a trusted installed artifact target instead of the built-in path target |
| `--target-option KEY=VALUE` | none | Repeatable, non-secret configuration passed to that target |
| `--profile PATH` | none (built-in default profile) | Path to a `guardana.yaml` policy file — see [`profiles.md`](profiles.md) |
| `--preset [ci\|pre-training\|monitor\|release]` | none | Named policy preset (mutually exclusive with `--profile`) — see [`profiles.md`](profiles.md#named-presets---preset) |
| `--format TEXT` | `human` | Output format: `human`, `json`, `sarif`, `junit`, or an [installed format](outputs.md) |
| `--plugins [all\|builtins\|allowlist\|disabled]` | `builtins`, or the profile's `plugins:` | Which installed plugins (entry-point rules/evaluators/targets) to load — the primary plugin-trust control. `builtins` keeps Guardana's own reviewed rules while refusing third-party ones; `disabled` is YAML-only safe mode. See [`SECURITY.md`](../SECURITY.md). |
| `--allow-plugin TEXT` | none | Distribution to trust; repeatable. Only valid together with `--plugins allowlist`. |
| `--no-plugins` | off | **Deprecated** alias for `--plugins disabled`, kept for pipelines that already set it. Prefer `--plugins`. |
| `--rules PATH` | none | Directory or file of custom YAML rules; repeatable. Combined with the profile's `rules.paths` — see [`writing-rules.md`](writing-rules.md). A malformed rule file is a warning, never an abort. |
| `--baseline PATH` | none | Baseline file: findings it lists are **waived** — still reported (as `WAIVED`), but they no longer fail the gate. A *new* finding elsewhere still does. See [Baselining](#baselining-existing-findings). |
| `--write-baseline PATH` | none | Write a baseline waiving every current finding to `PATH`, then exit 0. Add a reason to each entry before committing it. Over an incomplete run it writes nothing and exits `2` — see [Baselining](#baselining-existing-findings). It produces no report, so `--output` or any `--reporter` beside it is refused with exit `3` before anything is sent. A `PATH` naming the scanned file, `--profile`, a `--rules` file or a rule file in a `--rules` directory or under the profile's `rules.paths`, `.guardanaignore`, or any file the scan read that is not an earlier baseline is also refused with exit `3`; writing the baseline again over itself works. The file is written whole through a temporary file and a rename, and a `PATH` that cannot be written exits `3`. |
| `--reporter TEXT` | none | Forward findings to a collector, e.g. `server://https://collector.example.com/findings`, or to an [installed reporter](outputs.md) as `<name>://<locator>` |
| `--ai-system TEXT` | none | Which AI system this run verifies, e.g. `support-agent`. Never guessed. |
| `--environment TEXT` | none | Where it runs, e.g. `production`. Never guessed from a branch name. |
| `--deployment-id TEXT` | none | Which version of it, if you have an identifier. |
| `--output PATH` | stdout | Write the report to a file instead of stdout — needed by `guardana diff`. See [Saving a run for comparison](#saving-a-run-for-comparison). |

`PATH` and `--target` are mutually exclusive. A custom target is installed
Python, so the plugin trust flags still decide whether its scheme exists;
`guardana doctor` lists loaded schemes. The command accepts only artifact
targets and refuses a mismatched kind before any rule runs.

## What runs

Only rules whose `target_kind` is `artifact` and whose declared
`required_capabilities` are satisfied by an artifact target (i.e.
`read_files`) execute. Built-in endpoint rules (prompt injection, jailbreak,
system-prompt leak, output-secrets) are not selected by `scan` — they need a
live model, so use `guardana probe` for those. A local endpoint rule loaded
with `--rules` or `rules.paths` does not run either, and `scan` prints a note
naming it.

## A path with no file to scan

A scan whose path holds no file other than `.guardanaignore` files is a coverage
shortfall named `empty_target`, naming the scanned path: the directory is empty, or
`rules.paths_exclude`, `.guardanaignore` and the directories every scan skips removed
every file. The run is `indeterminate` (exit `2`) under every preset, and
`guardana plan scan` refuses the same path with exit `3`. Any other file counts, a
`.DS_Store` included, because the scan listed it, not because a rule read it; a
single-file path is never empty. A third-party file target (`--target scheme://locator`)
that lists no file is the same shortfall.

A scan does not follow a symlinked directory, and does not list a symlink whose target
does not exist. It also does not list or read a symlinked file whose target, after every
link is followed, lies outside the scanned directory, because a link resolves on the
machine that scans, not where the artifact ships. Each one it meets is recorded as a source
it could not read, naming the link, so the run records an error (exit `2` under the default
`fail_on_error`). Scan the link's target directly, or exclude the link. A link the excludes
remove, or a directory link named like a directory every scan skips, is not reported. A
symlinked file whose target lies inside the scanned directory is listed and read, the
scanned directory itself may be reached through a symlink, and a single file named on the
command line is read even when it is a symlink.

## Model files no rule reads

Every model file the scan observes must be read by a rule that ran. One that no rule
read is a coverage shortfall named `unexamined_component`, one per format, so the run
is `indeterminate` (exit `2`) and never clean. There is no switch: exclude the file
with `.guardanaignore` or `rules.paths_exclude`, which the saved run then records, or
install a rule that reads the format.

A model or notebook a rule tried to read and could not is a shortfall of the same kind,
named by its file: a pickle, archive or graph that does not parse, a pickle import whose
name the scanner cannot resolve, a model file that cannot be opened (a `.bin` included,
since it may be a model), a safetensors file whose header is malformed, a file cut by a
read bound, a PMML document past the bound, a notebook that is not JSON. The rule reports
two things for it: an inconclusive "not scanned" result on the unverified channel, and an
`unexamined_component` shortfall whose name is the file's path and whose detail reads
`<rule id> could not read it: <reason>`. The file is not named a second time by format.
With no switch over it, a scan holding one such file is `indeterminate` (exit `2`) under
every preset, `ci` included, unless a finding fails it. A notebook cell that does not
parse as Python is not one: the notebook was read, and the cell is reported as an
unverified result only. The IPython line magics `%time`, `%timeit`, `%prun` and `%debug`,
and the first line of the `%%timeit`, `%%prun` and `%%debug` cell magics, are read as
Python after their options are removed; `%system` and `%sx` lines are read as shell
escapes, like `!`, and `%%sx`, `%%system` and `%%!` cells as shell cells, like `%%bash`,
whose magic is found on the first non-blank line; other magics are skipped. A magic whose
statement does not parse makes the cell inconclusive.

Shortfall names are relative to the working directory, as finding locations are, and the
scan root is removed from their detail, so a saved run names the same file on a laptop
and in CI. A format name (`tflite`) is not a path and stays as it is.

| Observed as a model | Read by |
|---|---|
| `.pkl`, `.pickle`, `.dill`, `.joblib`, `.pt`, `.pth`, `.ckpt`, `.ptl`, `.pdparams`, `.pth.tar`, `.pt.tar` | `guardana.supply_chain.pickle_opcode` |
| `.npy`, and each `.npy` inside a `.npz`, or a `.bin`, `.sav`, `.p` or `.model` that starts with the NPY magic: an object array holds a pickle stream, a numeric one cannot | `guardana.supply_chain.pickle_opcode` |
| `.bin` whose first bytes are a zip or a pickle stream (`pytorch_model.bin`); `.sav`, `.p` or `.model` whose first bytes are a pickle stream | `guardana.supply_chain.pickle_opcode` |
| `.onnx` | `guardana.supply_chain.onnx_graph` |
| `.keras`, `.h5`, `.hdf5` | `guardana.supply_chain.keras_lambda` |
| `.gguf` | `guardana.supply_chain.chat_template` |
| `.safetensors`, `.pmml` | `guardana.supply_chain.model_format` |
| `.tflite`, `.mar`, `.nemo`, `.llamafile`, `model.tar.gz`, a compressed pickle or checkpoint (`.pkl`, `.pickle` or `.joblib` followed by `.gz`, `.z`, `.xz`, `.bz2` or `.lzma`; `.joblib.lz4`; `.pt.gz`; `.pth.gz`), a `.bin` that starts like GGUF or GGML | no built-in rule |

A `.bin`, `.sav`, `.p` or `.model` whose first bytes match none of those is not listed as a
model. `pickle_opcode` also reads a `.tar` or `.zip` by its content: the members named like
a model (`pickle`, `data.pkl`, `*.pt`, `*.pth.tar`), and every member of a `.tar` that is in
fact a zip; a member named as a model that is itself an archive is a coverage shortfall,
and one `pickle.load` would read is still read as a stream. Any file `pickle_opcode` reads
that does not start as a zip and whose first 512-byte block is a tar header (`ustar`, or
the older v7 form without `ustar` magic) is read as a tar, whatever it is named, because
`torch.load` opens a legacy `torch.save` file that way. The same file is also read as the
single pickle stream `pickle.load` would read from those bytes, and findings from both
readings are reported; when the file is named `*.pth.tar` or `*.pt.tar`, or the tar holds a
member named as a model, the stream counts only if its bytes are a pickle. Inside a tar, a member that several links name is read once for each
way it is judged, not once per link. A model with no built-in rule is a coverage shortfall
too, so a scan holding one ends `indeterminate` (exit `2`) rather than clean. A rule left
out by the profile reads nothing, so a profile that excludes
`guardana.supply_chain.pickle_opcode` leaves every pickle unread. A third-party rule
counts a file as read by reporting on it, or by calling `ctx.examined(path)`
([writing rules](writing-rules.md)).

Guardana dogfoods itself in CI by scanning its own source, which must stay
clean:

```console
$ guardana scan packages --profile scripts/dogfood.yaml
✓ No findings.

0 finding(s); 19 rule(s) run, 0 skipped. 8 component(s) observed.
```

Note the path: in this repository, `guardana scan .` exits `1` by design —
[`examples/vulnerable-model/`](../examples/vulnerable-model/) is deliberately
malicious so the quickstart has something real to find. CI therefore scans
`packages`, not `.`.

## Example output with findings (`--format human`, the default)

```console
$ guardana scan ./some-model-repo
✖ [CRITICAL] guardana.supply_chain.pickle_opcode — Dangerous pickle opcode (arbitrary code on load)
    unpickling imports 1 non-allowlisted callable(s) (set b04a8341e816): os.system  (./some-model-repo)
▲ [MEDIUM] guardana.supply_chain.hallucinated_package — Import of unknown package (possible slopsquat lead)
    import 'torchutilz' isn't a known package or a declared dependency — declare it in requirements/pyproject, or verify it exists on PyPI  (./some-model-repo)

2 finding(s); 19 rule(s) run, 0 skipped. 3 component(s) observed.
```

`hallucinated_package` scans `import`/`from` statements in `.py` source
files via `ast.parse`; it does not read `requirements.txt` or lockfiles.

`pickle_opcode` reports one finding per file. Its summary names every non-allowlisted
callable the file imports, sorted and each once, after a digest of that set
(`unpickling imports 2 non-allowlisted callable(s) (set 9a0cd5b778d9): builtins.eval,
os.system`). Its detail names the archive member each was found in
(`os.system in model.pt::archive/data.pkl`). A baseline fingerprint includes the
summary, so a file that imports a different callable is a new finding, even when the
listing is long enough to be cut by the evidence bound. Callables found in the members
read before a member that failed are still reported. A pickle that imports a callable
and then one whose name the scanner cannot resolve, or that is cut by a read bound, is
reported both ways: the finding for what was found, and the file as unread.

## Other formats

```bash
guardana scan . --format json    # machine-readable findings + summary
guardana scan . --format sarif   # SARIF 2.1.0, for GitHub code-scanning upload
guardana scan . --format junit   # JUnit XML, for CI test-result reporting
```

Every format says when a run is not a clean pass, each in its own vocabulary. A run that
stopped early, verified or measured nothing, missed coverage, had a suite decline,
could not run a check or left a check without a verdict prints no `✓` in the terminal, is
an `<error>` testcase in JUnit, and sets SARIF's `executionSuccessful` to `false` with one
`toolExecutionNotifications` entry per cause (`guardana.open_question.*`,
`guardana.check_error.*`, `guardana.coverage_shortfall.*`). A skipped rule counts only when
the policy fails on skips, and then no format renders the run clean either. Either way, a
rule skipped for missing coverage (`missing_capability`, `unsafe_mode`, `not_recorded`,
`not_offered`) stays visible: a SARIF `note` notification (`guardana.skipped.<reason>`) and
a JUnit testcase holding `<skipped>`, counted in the suite's `tests` and `skipped`. A scan's
summary line always states how many components it observed, zero included.

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

A waiver is matched by a **fingerprint** — a stable hash of the rule id, the
finding's file and its evidence summary — so it keeps waiving the same finding but
never a different one. Under `privacy.evidence_mode: metadata_only` the summary is
withheld behind a note that carries a short digest of the redacted summary, so two
findings of one rule in one file still get different fingerprints. Waived findings are never silently dropped: they appear in every format (a
`WAIVED` line in human output, a `waived` array in JSON, `suppressions` in SARIF),
so a reviewer can always see what was accepted and why. A malformed baseline file
is a hard error (exit 3), never a silent "waive nothing" or "waive everything".

`--write-baseline` writes nothing when the run is not entitled to a snapshot: the
gate's own open questions decide — nothing verified, a coverage shortfall, a declined
suite, anything the profile's `fail_on` refuses — and a check that did not run counts
whatever `fail_on_error` says, because a baseline reads its silence as an answer. The
command names what was left open and exits `2`, or `6`/`7` when the run was stopped,
as `scan` itself would.

## Exit codes

`scan` exits `1` (and CI treats the step as failed) when any finding's
severity is at or above the active profile's `fail_on.severity` **and**
either it has no verdict (a static check) or its verdict's `confidence` is
at or above `fail_on.min_confidence`. It exits `2` when the run is `indeterminate`: a
check could not run, a model file no rule read, or a path with no file to scan.
Otherwise it exits `0`. This is the same `gate()` policy logic `probe` uses — see
[`profiles.md`](profiles.md) and [`exit-codes.md`](exit-codes.md).

```bash
guardana scan .
status=$?
[ "$status" -eq 0 ] || echo "gate failed with exit $status, see the findings above"
exit "$status"
```

## Forwarding to a collector

```bash
guardana scan . --reporter server://https://collector.example.com
```

Findings are POSTed to the collector after being printed locally — this
never blocks the local exit-code gate. Required collector delivery still
changes the code: each unacknowledged delivery the profile required is printed
as an `error:` line, and a final `0`, `1` or `2` becomes `8` (see
[`exit-codes.md`](exit-codes.md)). See
[`architecture.md`](architecture.md#the-coreserver-boundary).

## Saving a run for comparison

`--output <path>` writes the report to a file instead of stdout. With
`--format json` that file is a versioned document `guardana diff` reads back, so
you can ask whether the next run is worse than this one — see
[`usage-diff.md`](usage-diff.md).

```bash
guardana scan .  --format json --output run.json
```

Prefer it to a shell redirect: PowerShell redirects write UTF-16, and the reader
on the other end cannot parse that.

**`--format json` is not optional here.** `--output` on its own writes whatever
`--format` says, and that defaults to human text — a file named like a saved run
that `guardana diff` refuses. Since 0.7.1 saving any other format says so at the
moment it is written, rather than leaving it to be discovered on the next run,
which is the run you wanted compared.
