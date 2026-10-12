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

## Python files the scan cannot read

A `.py` file is decoded the way Python decodes a module it runs, so a UTF-8 byte order
mark or a PEP 263 coding line (`# -*- coding: latin-1 -*-`) is honoured. A file that is
too large, cannot be opened, cannot be decoded, or does not parse under the Python
running the scan (syntax from a newer Python, a Python 2 file, a null byte) is not
skipped: it is recorded as a source the scan could not read, so the run records an
error, and every rule that reads Python reports it as an inconclusive "not scanned"
result with an `unexamined_component` shortfall. The run is `indeterminate` (exit `2`)
whenever such a rule runs, even with `fail_on_error: false`. Scan with a Python that parses the file, or exclude it
with `.guardanaignore` or `rules.paths_exclude`.

## Model files no rule reads

Every model file the scan observes must be read by a rule that ran. One that no rule
read is a coverage shortfall named `unexamined_component`, one per format, so the run
is `indeterminate` (exit `2`) and never clean. There is no switch: exclude the file
with `.guardanaignore` or `rules.paths_exclude`, which the saved run then records, or
install a rule that reads the format.

A model or notebook a rule tried to read and could not is a shortfall of the same kind,
named by its file: a pickle, archive or graph that does not parse, a pickle import whose
name the scanner cannot resolve, a pickle of any protocol naming a callable by an
extension-registry code (`EXT1`, `EXT2`, `EXT4`), a model file that cannot be opened (a `.bin` included,
since it may be a model), a safetensors file with a malformed header (including a tensor entry
with a missing or mistyped `dtype`, `shape` or `data_offsets`), an ONNX
file without a graph (including an empty file), a `.keras` archive or Keras model directory
whose `config.json` is not a JSON object and declares no Lambda layer, a file cut by a read bound, an archive refused
before it is opened (below), a PMML document past the bound, a notebook that is not JSON
or has a cell that is not an object or a code cell whose source is not text, a notebook whose
`kernelspec.language` or `language_info.name` is not Python.
A Git LFS pointer (`version https://git-lfs.github.com/spec/v1`, what a clone without the
LFS objects holds; the whole file, not a model that merely opens with one) named as a model a rule reads, a `.pb`, `.bin`, `.sav`, `.p` or `.model`
included, is reported with the reason `a Git LFS pointer, not the model; fetch the LFS
object`. It is reported as not scanned, never as a checked model. A pointer named as a
format no rule reads is the per-format shortfall above. A plain `.zip` or `.tar` names no
model: it is read by content, and a pointer under that name is not reported. In CI, fetch
the LFS objects before the scan (`lfs: true` on `actions/checkout`, or `git lfs pull`), or
exclude the file.
The rule reports
two things for it: an inconclusive "not scanned" result on the unverified channel, and an
`unexamined_component` shortfall whose name is the file's path and whose detail reads
`<rule id> could not read it: <reason>`. The file is not named a second time by format.
With no switch over it, a scan holding one such file is `indeterminate` (exit `2`) under
every preset, `ci` included, unless a finding fails it. A notebook cell that does not
parse as Python is not one: the notebook was read, and the cell is reported as an
unverified result only. A cell too complex for the Python parser to hold is inconclusive
and a shortfall. The IPython line magics `%time`, `%timeit`, `%prun` and `%debug`,
and the first line of the `%%timeit`, `%%prun` and `%%debug` cell magics, are read as
Python after their options are removed; the bodies of `%%time`, `%%capture`, `%%writefile`
and `%%script python` cells are read as Python. `%system` and `%sx` lines are read as shell
escapes, like `!`, and so is the command an `%alias` defines, wherever the alias is called.
`%%bash`, `%%sh`, `%%sx`, `%%system`, `%%!` and `%%script` with a shell are shell cells,
whose magic is found on the first non-blank line. A shell cell is read as the shell joins
it: a line ending in a backslash, `|`, `&&` or `||` continues on the next, and a `!` or
`%` line ending in a backslash continues as IPython joins it. Magics that only change
interpreter state (`%matplotlib`, `%config`, `%env`, `%cd`, `%autoreload`, `%load_ext`
of IPython's own `autoreload` or `storemagic`, and the like) are skipped. Any other magic
is not skipped: `%run`, `%load_ext`, `%pip`, `%conda`, a magic the rule does not know,
and a cell magic that runs another language (`%%perl`, `%%R`, `%%html`, `%%script perl`)
make the cell inconclusive and add an `unexamined_component` shortfall naming the notebook
and the magic, and a foreign cell's body is never read as Python. A magic whose statement
does not parse makes the cell inconclusive. Each `{…}` expression IPython evaluates
inside a `!` line or a magic's arguments (`{{` and `}}` are literal braces) is scanned as
Python with the rest of the cell; one that is not Python syntax, such as an `awk`
program, evaluates nothing, since IPython then runs the command unexpanded.
`target = !cmd` and `target = %magic` are read as the bare form. A cell that is a single
line starting with a line magic's name (`run x.py`, `pip install x`, `ls -la`) is read as
that magic, as IPython's automagic runs it, unless the rest starts with `=` or `,` or an
earlier cell, a builtin or a keyword binds the name; after `%rehashx`, such a line
starting with any other unbound word is inconclusive, since it may name an executable.
A magic defined with `%alias_magic` is read as its target. Calls on the IPython object,
under any name `get_ipython` is imported or assigned as, are read as the escape, magic
or cell they spell (`system`, `getoutput`, `run_line_magic`, `run_cell_magic`,
`run_cell`, `run_cell_async`, a magic returned by `find_line_magic` and called, the same
methods reached through `getattr`). Its namespaces, history and display data are inert.
Any other method, an argument that is not a literal, or a method taken without being
called is reported unscanned: inconclusive and a shortfall.

An archive is refused before it is opened when listing it would cost more than listing a
model does. A zip, a `.keras` included, is refused when its end records declare more than
100,000 entries or a central directory over 25,600,000 bytes, or when that directory holds
more than 100,000 entries. A tar is refused when it holds more than 100,000 members or
more than 400,000 headers; more than 8 extended headers, or more than 1 MiB of them, in
front of one member; more than 1,000,000 global PAX records applied, counting the records
in force once for every member and PAX header after them; sparse maps listing more than
100,000 regions in all, or one stored in a member's data over 1 MiB; or a header the
scanner cannot follow. A sparse member within those bounds is read like any other. An
archive that holds no model but exceeds the entry bound, such as an image dataset,
is reported not scanned like any other refused archive. Exclude it from the scan
with `.guardanaignore` or `rules.paths_exclude`, or scan the model's directory instead.

Shortfall names are relative to the working directory, as finding locations are, and the
scan root is removed from their detail, so a saved run names the same file on a laptop
and in CI. A format name (`tflite`) is not a path and stays as it is.

| Observed as a model | Read by |
|---|---|
| `.pkl`, `.pickle`, `.dill`, `.joblib`, `.pt`, `.pth`, `.ckpt`, `.ptl`, `.pdparams`, `.pth.tar`, `.pt.tar` | `guardana.supply_chain.pickle_opcode` |
| `.npy`, and each `.npy` inside a `.npz`, or a `.bin`, `.sav`, `.p` or `.model` that starts with the NPY magic: an object array holds a pickle stream, a numeric one cannot | `guardana.supply_chain.pickle_opcode` |
| `.bin` whose first bytes are a zip or a pickle stream (`pytorch_model.bin`); `.sav`, `.p` or `.model` whose first bytes are a pickle stream | `guardana.supply_chain.pickle_opcode` |
| a compressed pickle or checkpoint (`.pkl`, `.pickle` or `.joblib` followed by `.gz`, `.z`, `.xz`, `.bz2` or `.lzma`; `.joblib.lz4`; `.pt.gz`; `.pth.gz`) | `guardana.supply_chain.pickle_opcode` |
| `.onnx` | `guardana.supply_chain.onnx_graph` |
| `.keras`, `.h5`, `.hdf5`; a `.bin`, `.model`, `.hdf`, `.weights` or `.tf` that holds the HDF5 signature at its start or after a userblock; a `config.json` beside `metadata.json` or `model.weights.h5` (an unzipped Keras model directory) | `guardana.supply_chain.keras_lambda` |
| `.gguf` | `guardana.supply_chain.chat_template` |
| `.safetensors`, `.pmml` | `guardana.supply_chain.model_format` |
| `saved_model.pb`, `saved_model.pbtxt` (the text form TensorFlow loads when there is no `.pb`; its `op` values are decoded as protobuf decodes them, and one that cannot be decoded is a shortfall) | `guardana.supply_chain.saved_model_ops` |
| `.tflite`, `.mar`, `.nemo`, `.llamafile`, `model.tar.gz`, a `.bin` that starts like GGUF or GGML | no built-in rule |

A `.bin`, `.sav`, `.p` or `.model` whose first bytes match none of those is not listed as a
model. The HDF5 signature is looked for where the HDF5 library looks: at the start and
after a userblock of 512, 1024, 2048 bytes and so on, up to the end of the file. The
model config is read from the first 16 MiB, so a file whose signature or config lies past
that is reported as not scanned rather than clean. A file with no suffix is not sniffed,
so an HDF5 model saved without one is neither listed nor read. `pickle_opcode` also reads a `.tar` or `.zip` by its content: the members named like
a model (`pickle`, `data.pkl`, `*.pt`, `*.pth.tar`, `*.pkl.gz`), every member of a `.zip`
whose first bytes are an NPY array or a pickle `PROTO` opcode whatever its name, and every member
of a `.tar` that is in fact a zip; a member named as a model that is itself an archive is a coverage
shortfall, and one `pickle.load` would read is still read as a stream. A member named as a
model it does not open inside an archive (`*.safetensors`, `*.gguf`, `*.onnx`, `*.keras`,
`model.tar.gz` and the rest of the last row above, and HDF5 files (`*.h5`, `*.hdf5`, `*.hdf`, `*.weights`, `*.tf`) and a Keras directory's
`config.json` or `model.weights.h5` inside a model archive, though not inside a plain
`.zip` or `.tar`, where HDF5 is as often a dataset) is a
coverage shortfall that names it; a zip member counts under its directory name and under an
Info-ZIP Unicode Path alike. A file or member it reads whose first bytes are a zlib, gzip,
bz2, lzma, xz or lz4 header, or joblib's own legacy one, is decompressed first, as
`joblib.load` does whatever the name, up to 64 MiB per file or member, 512 MiB per archive
and 1,024 streams back to back; past a bound, damaged part-way (what was decompressed
before the damage is still read), or in lz4 or another form it cannot decompress, it is a
coverage shortfall. A zip whose
central directory is not where its end record declares it, as with bytes before the zip
or two directories, is a coverage shortfall rather than read, because zip readers would
disagree on its members, and so is a member stored with two different sizes or whose local
header disagrees with its directory entry, and a pickle read that crosses the end of a
frame; a `.zip` is found by its end record wherever the zip data starts, and is
also read as a stream when its first bytes are not a zip's,
and a file that starts with an end record is opened as a zip, as `np.load` does. In a
legacy tar, the `storages` and `tensors` members are read as `torch.load` reads them, a
pickle before each run of raw tensor bytes; a layout it cannot follow is a coverage
shortfall. Any file `pickle_opcode` reads
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
and then one whose name the scanner cannot resolve, or names one by an extension-registry
code, or that is cut by a read bound, is reported both ways: the finding for what was
found, and the file as unread. An extension code counts where a loader reads the bytes
as a pickle: from the first byte of a file or member named as one (`*.pkl`, `*.pt`,
`data.pkl`, an object array); in the four pickles that follow a first pickle holding the
legacy `torch.save` magic number; in a file or member named `.bin`, `.sav`, `.p` or
`.model` when its stream goes on to a clean STOP or imports a callable after the code;
and wherever a pickle opens with a `PROTO` opcode of any protocol. It stays data in a
tensor storage beside a checkpoint's `data.pkl`, a numeric array, everything after those
four pickles in a file that opens with the magic number, whatever the file is named, a
member named as no model, and after a complete pickle without a `PROTO` opcode.

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

Findings are POSTed to the collector after being printed locally — by default
a collector that refuses or cannot be reached is a warning and changes no exit
code. A profile that sets [`delivery.required`](profiles.md#delivery) prints
an unacknowledged delivery as an `error:` line, and a final `0`, `1` or `2`
becomes `8` (see [`exit-codes.md`](exit-codes.md)). See
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

A scan never writes its report over a file it scanned. An `--output` that is, or whose
`<stem>.exchanges.jsonl` is, a file the scan read exits `3` after the scan and writes
nothing. Two files are exempt, each recognised by its content and never by its name: an
earlier saved run, which `guardana scan . --format json --output run.json` replaces when
run again, and the exchanges a saved run beside it (`<stem>.json` or `<stem>`) records by
digest. A recording named `customer.exchanges.jsonl` that no saved run records is refused
like any other scanned file.

**`--format json` is not optional here.** `--output` on its own writes whatever
`--format` says, and that defaults to human text — a file named like a saved run
that `guardana diff` refuses. Since 0.7.1 saving any other format says so at the
moment it is written, rather than leaving it to be discovered on the next run,
which is the run you wanted compared.
