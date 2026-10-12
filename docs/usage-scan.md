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

## What the scan leaves out

Three things keep a file out of a directory scan:

- **`rules.paths_exclude`** in the profile ([`profiles.md`](profiles.md)): glob patterns
  matched against each path relative to the scanned directory. A matching directory is not
  walked. This is the policy you chose, and it may exclude any file, a model file included.
- **`.guardanaignore`** at the root of the scanned directory: one glob pattern per line,
  blank lines and `#` comments skipped, matched the same way. The file ships with the
  target, so whoever controls the target writes it. It excludes ordinary files, but never a
  file a model loader reads: a file the scan observes as a model (every row of the table
  under [model files no rule reads](#model-files-no-rule-reads), an unzipped Keras model's
  `config.json` and `metadata.json` included), an archive or compressed file (`.zip`,
  `.tar`, `.tgz`, `.tbz2`, `.tbz`, `.txz`, or a name ending in `.gz`, `.gzip`, `.z`, `.xz`,
  `.bz2`, `.lzma` or `.lz4`) whatever it is named, and, in a directory
  that holds a model or a tokenizer (`tokenizer_config.json` or `tokenizer.json`), every
  `*config.json`, `chat_template.json`, `chat_template*.jinja`, `chat_template*.j2` and
  `keras_metadata.pb`, with the templates in its `additional_chat_templates/`. A link is
  judged by its name alone. A directory it matches is still walked for such files. A file
  it matches that a model loader reads is scanned anyway and named in the output: `Scope`
  in the terminal (the first ten, then a count), `scope.kept_models` in the saved run with
  the pattern that matched it.
  Every pattern it applied is named there too, with the file it came from
  (`scope.excludes[].file`). It still excludes a notebook, source code and a configuration
  with no model or tokenizer beside it. To leave a model file
  out, use `rules.paths_exclude`.
- **Directories every scan skips**, wherever they occur: `.git`, `.venv`, `venv`, `env`,
  `__pycache__`, `.mypy_cache`, `.ruff_cache`, `.pytest_cache`, `node_modules`, `.tox`,
  `.eggs`, `dist`, `build`, `.idea`, `.vscode` and `*.egg-info`. They stay skipped, and the
  gate does not change, but the scan searches them by file name for model files, without
  opening a file and within a bound of 10,000 entries shared across them, shallowest first.
  A `.bin`, `.model` or `.sav` counts by its name there; a file with no suffix is not
  counted.
  A skipped directory holding model files is named in the terminal with their count, and in
  the saved run as `scope.skipped_models`; `searched_all` is `false` there when the search
  stopped at its bound. To scan such a model, scan its directory directly.

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

## Chat templates and model configs

`chat_template` reads chat templates from every location a loader uses: GGUF metadata
(`tokenizer.chat_template` and its named variants); the `chat_template` key of
`tokenizer_config.json`, `chat_template.json` or `processor_config.json` (a string or a list
of named templates); a `.jinja` or `.j2` file whose name starts with `chat_template`; and
every `.jinja` or `.j2` file in an `additional_chat_templates/` directory. Transformers 5
loads these directory files as named templates and uses `default` ahead of the rest.

`remote_code_config` reads every `*config.json`. A Hub kernel repository named in
`_attn_implementation_internal` or `_attn_implementation` is `critical`. Transformers sets
either field from the config without consulting `trust_remote_code`, then downloads and
imports the kernel. The rule reads every accepted form: `org/repo`, with a `@revision`,
a `:function` or a prefix such as `paged|`; a dict keyed by sub-config name
(`{"": "org/repo"}`); and a nested sub-config such as `text_config` or `decoder`.
A kernel named in the documented `attn_implementation` field is a `medium` lead.

## Model files no rule reads

Every model file the scan observes must be read by a rule that ran. One that no rule
read is a coverage shortfall named `unexamined_component`, one per format, so the run
is `indeterminate` (exit `2`) and never clean. There is no switch: exclude the file
with `rules.paths_exclude`, which the saved run then records, or install a rule that reads
the format. `.guardanaignore` does not exclude a model file.

A model or notebook a rule tried to read and could not is a shortfall of the same kind,
named by its file: a pickle, archive or graph that does not parse, an archive member named
as a pickle (`data.pkl`, `*.pkl`, a legacy tar's `pickle`) that ends before its STOP, an
NPY header whose `descr`, `shape` or `fortran_order` numpy would refuse, a pickle import whose
name the scanner cannot resolve, a pickle of any protocol naming a callable by an
extension-registry code (`EXT1`, `EXT2`, `EXT4`), a model file that cannot be opened (a `.bin` included,
since it may be a model), a safetensors file with a malformed header (including a tensor entry
with a missing or mistyped `dtype`, `shape` or `data_offsets`, and tensors that do not
describe the payload exactly), a GGUF file declaring an unsupported version, an ONNX
file without a graph (including an empty file), a `.keras` archive or Keras model directory
whose `config.json` is not a JSON object and declares no Lambda layer, a `chat_template`
list entry that holds no template (each one, beside whatever its siblings hold), a file cut
by a read bound, an archive refused
before it is opened (below), a PMML document past the bound, a notebook that is not JSON
or has a cell that is not an object or a code cell whose source is not text, a notebook whose
`cells` or `worksheets` is not a list or has a worksheet that holds no list of cells, a
notebook whose `kernelspec.language` or `language_info.name` is not Python.
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
every preset, `ci` included, unless a finding fails it. Every cell a notebook reader runs is
read: the top-level `cells` by their `source`; the `code` of a v1 code cell, which nbformat
runs from a notebook that declares no version; and the cells of each `worksheets` entry by
their `input`, which nbformat runs instead of the top-level cells when it upgrades a v2 or v3
notebook. Each of these readings is scanned on its own, so a name bound in one does not
change how another is read. A notebook cell that does not
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
called is reported unscanned: inconclusive and a shortfall. The same applies to a call
that receives the IPython object, or `get_ipython` itself, as an argument
(`helper(get_ipython())`), because the rule does not follow what the callee does with it.
A builtin that only inspects or prints it (`print`, `isinstance`, `hasattr`, `type` and
the like) is exempt unless the notebook rebinds its name.

A cell running a local script gets one `low` finding naming each script as written:
a file passed to `sh`, `bash` or another shell, or to `python`, as an argument or
standard input (`sh < setup.sh`); a file passed to `source` or `.`; or a path run as
the command (`./run`, `tools/stage2.sh`, or a bare or absolute name ending in `.sh` or
`.py`). This applies wherever the shell command comes from: a `!` line, `%system`,
a shell cell magic, a magic defined with `%alias_magic`, an automagic `system` line
or a call on the IPython object. The rule does not read what the script runs.
`python -m`, `sh -c` with its command (which the rule reads for scripts in turn) and
a tool run by name are not scripts. A download piped to a shell remains a `high` finding.

An archive is refused before it is opened when listing it would cost more than listing a
model does. A zip, a `.keras` included, is refused when its end records declare more than
100,000 entries or a central directory over 25,600,000 bytes, or when that directory holds
more than 100,000 entries. A tar is refused when it holds more than 100,000 members or
more than 400,000 headers, a compressed tar's headers included; more than 8 extended headers, or more than 1 MiB of them, in
front of one member; more than 1,000,000 global PAX records applied, counting the records
in force once for every member and PAX header after them; sparse maps listing more than
100,000 regions in all, or one stored in a member's data over 1 MiB; or a header the
scanner cannot follow. A sparse member within those bounds is read like any other. An
archive that holds no model but exceeds the entry bound, such as an image dataset,
is reported not scanned like any other refused archive. Exclude it from the scan
with `rules.paths_exclude` (the target's `.guardanaignore` cannot exclude an archive), or
scan the model's directory instead.

Shortfall names are relative to the working directory, as finding locations are, and the
scan root is removed from their detail, so a saved run names the same file on a laptop
and in CI. A format name (`tflite`) is not a path and stays as it is.

| Observed as a model | Read by |
|---|---|
| `.pkl`, `.pkl3`, `.pickle`, `.dill`, `.joblib`, `.pt`, `.pth`, `.th`, `.ckpt`, `.ptl`, `.pdparams`, `.mdl`, `.pth.tar`, `.pt.tar` | `guardana.supply_chain.pickle_opcode` |
| `.npy`, and each `.npy` inside a `.npz`, or a `.bin`, `.sav`, `.p` or `.model` that starts with the NPY magic: an object array holds a pickle stream, a numeric one cannot | `guardana.supply_chain.pickle_opcode` |
| `.bin` whose first bytes are a zip or a pickle stream (`pytorch_model.bin`); `.sav`, `.p` or `.model` whose first bytes are a pickle stream | `guardana.supply_chain.pickle_opcode` |
| a compressed pickle, checkpoint or array (`.pkl`, `.pickle` or `.joblib` followed by `.gz`, `.gzip`, `.z`, `.xz`, `.bz2` or `.lzma`; `.joblib.lz4`; `.pt.gz`; `.pth.gz`; `.ckpt.gz`; `.npy.gz`, read as an NPY array when it decompresses to one) | `guardana.supply_chain.pickle_opcode` |
| a `.dat`, or a file with no suffix, whose first bytes are a pickle stream (listed as a model when they open with a protocol 2 to 5 header; an older pickle is read without being listed); a `.dat.gz` or `.dat` with another codec above, or a file named only by a codec (`clf.gz`, as `joblib.dump` writes it, or `.gzip`, `.z`, `.xz`, `.bz2`, `.lzma`, `.lz4`), read when it decompresses to a pickle | `guardana.supply_chain.pickle_opcode` |
| `.onnx` | `guardana.supply_chain.onnx_graph` |
| `.keras`, `.h5`, `.hdf5`; a `.bin`, `.model`, `.hdf`, `.weights` or `.tf` that holds the HDF5 signature at its start or after a userblock; a file with no suffix that holds it in its first 64 KiB; a `config.json` beside `metadata.json`, `model.weights.h5` or `model.weights.npz` (an unzipped Keras model directory); a tf_keras SavedModel's `keras_metadata.pb` | `guardana.supply_chain.keras_lambda` |
| `.gguf` | `guardana.supply_chain.chat_template` |
| `.safetensors`, `.pmml` | `guardana.supply_chain.model_format` |
| `saved_model.pb`, `saved_model.pbtxt` (the text form TensorFlow loads when there is no `.pb`; its `op` values are decoded as protobuf decodes them, and one that cannot be decoded is a shortfall) | `guardana.supply_chain.saved_model_ops` |
| `model.tar.gz` (a SageMaker model), read for its members like any compressed tar (below); one holding no member named as a model is still a shortfall | `guardana.supply_chain.pickle_opcode` |
| `.tflite`, `.mar`, `.nemo`, `.llamafile`, a `.bin` that starts like GGUF or GGML | no built-in rule |

A `.bin`, `.sav`, `.p`, `.model` or `.dat`, or a file with no suffix, whose first bytes match
none of those is not listed as a model. A `.dat`, a file with no suffix or a file named only by
a codec costs `pickle_opcode` one read of its first 64 KiB, and a file with no suffix the same one read for
`keras_lambda`: a pickle, a compressed pickle, an NPY array or an archive holding a model is
read on, and anything else, an unreadable file, a Git LFS pointer or a 7z archive among
them, is left alone without a result. A zip or tar under such a name is read like a plain
`.zip` or `.tar`. The HDF5 signature is looked for where the HDF5 library looks: at the
start and after a userblock of 512, 1024, 2048 bytes and so on, up to the end of the file,
and in a file with no suffix up to the end of its first 64 KiB. The
model config is read from the first 16 MiB, so a file whose signature or config lies past
that, or a `.keras` whose `config.json` is longer, is reported as not scanned rather than
clean, also when a Lambda layer was found in the part read. An HDF5 model saved with no
suffix behind a userblock that ends past its first 64 KiB is neither listed nor read. An
HDF5 file holding a fractal heap stored compressed, where an attribute such as the model
config is kept as bytes no search can read, is reported as not scanned. A `TFOpLambda` or
`SlicingOpLambda` layer, which tf_keras rebuilds by calling the TensorFlow function its
config names, is a `high` finding, like a Lambda layer, when that function is more than
tensor arithmetic (anything outside `math`, `nn`, `linalg`, `__operators__` and the other
arithmetic namespaces, or array functions such as `reshape` and `concat`), such as
`io.write_file`; so is a `ClassMethod` layer, which calls the method its config names on
the class it names, unless it builds a tensor (`RaggedTensor.from_row_splits` and the other
`RaggedTensor` constructors, `SparseTensor.from_value`). A layer of either kind that names
nothing it calls, or whose config cannot be decoded, is reported as not scanned. A
marshalled function (`"class_name": "__lambda__"`) anywhere in a config, which Keras 3 runs
on load without a Lambda layer around it, is a `high` finding, and so is an object naming a
callable in `os`, `subprocess`, `builtins` or another module a model has no use for (`sys`,
`socket`, `shutil`, `pty`, `importlib`, `posix`, `nt`, `runpy`, `ctypes`, `pickle`,
`marshal`, `code`), which Keras before 3.9 imports on load; a callable in any other module
outside Keras, such as a project's own, is not reported. A `TFSMLayer` is a `high` finding
naming the SavedModel it loads, which `load_model` in Keras through 3.11 loads whatever
`safe_mode` says; one
naming no path, or whose config cannot be decoded, is reported as not scanned. A layer counts
as a Lambda or a `TFSMLayer` when its `class_name` or its `registered_name` names one, since
Keras 3.8 builds the class `registered_name` names when `class_name` names nothing in the
layer's module. A `StringLookup`, `IntegerLookup` or `TextVectorization` layer reads a
string `vocabulary` as a file while Keras builds it, `safe_mode` or not; one naming an absolute path, a `..` path or a URL (`gs://` too) is a `medium` lead, the
same judgement `saved_model_ops` makes of a table's file below, and a list or a relative path
stays quiet. A tf_keras SavedModel's `keras_metadata.pb` is searched like an HDF5 model. Keras metadata that an
older SavedModel keeps inside `saved_model.pb` is not read, and neither is a `config.json`
with none of Keras' own files beside it, although `keras.saving.load_model` loads such a
directory. `saved_model_ops` reports `ReadFile` and `WriteFile` as `medium` leads wherever
they sit. `MatchingFiles`, `InitializeTableFromTextFile` and `InitializeTableFromTextFileV2`
are `medium` leads only when the graph also holds a string constant naming a file outside
the model: an absolute path, a `..` path or a URL (`file://`, `gs://`, `s3://`, which
TensorFlow opens alike) whose file name is not one the model ships under its own `assets/`,
so a vocabulary read from `assets/vocab.txt` stays quiet. `Save`, `SaveV2` and
`MergeV2Checkpoints` are not reported: every SavedModel's saver writes its checkpoint with
them. `PrintV2` is a `medium` lead only when the graph also holds a `file://` string (in
the text form, a `file://` string attribute), the output stream it writes to. The operator and
the string are not tied through the graph: a constant naming a file elsewhere beside an op
that reads another file is reported, and a path the graph builds from pieces none of which
looks like one, or a constant of fewer than five characters, is not. `pickle_opcode` also reads a `.tar` or `.zip` by its content: the members named like
a model (`pickle`, `data.pkl`, `*.pt`, `*.pth.tar`, `*.pkl.gz`; a `*.bin`, `*.sav`, `*.p`,
`*.model` or `*.dat` member only when its bytes are a pickle), every member of a `.zip`
whose first bytes are an NPY array or a pickle `PROTO` opcode whatever its name, and every member
of a `.tar` that is in fact a zip. The first bytes of a `.zip`'s other members are read for
the first 10,000 of them, and for no more than 64 MiB of local headers and first blocks;
the members past either bound are a coverage shortfall that counts them. A member of a plain
`.tar` with no suffix and no legacy torch name (`pickle`, `storages`, `tensors`) is not read,
so a pickle saved under such a name inside one is not found. A `.tar.gz`, `.tgz`, `.tar.bz2`,
`.tbz2`, `.tbz`, `.tar.xz` or `.txz` is decompressed as `tar` decompresses it, as gzip, bz2 or
xz by its first bytes and across streams written back to back, in memory and never to disk,
and its members are read like those of a plain `.tar`, under the same bounds. At most 32 bytes
are decompressed for each byte of the file, and at least 64 MiB; a compressed tar past that
bound, damaged or cut before its end, or with a header `tarfile` stops listing at before the
end of the archive, is a coverage shortfall, and so is a link named as a model inside one,
which is not followed. One that is a plain tar under that name is read as a `.tar`, and one
that holds no tar is read as `joblib.load` reads a file, by its first bytes: a pickle in it,
compressed or not, is found, and anything else is left alone. `tar` detects the compression
from the content, so a `.tar` whose bytes are gzip, bz2 or xz, a file named only by a codec
(`bundle.gz`, `.gzip`, `.z`, `.xz`, `.bz2`, `.lzma`, `.lz4`) and a `.dat` or a file with no
suffix are read as a compressed tar when they decompress to one, found in the same first
read that looks for a pickle. A compressed tar whose decompressed bytes start like a pickle
is also read as the stream `joblib.load` would unpickle from them. A `.bin` whose bytes are a
compressed tar is not read as one. A member named as
a model that is itself an archive is a coverage shortfall, and one `pickle.load` would read is still read as a stream. A member named as a
model it does not open inside an archive (`*.safetensors`, `*.gguf`, `*.onnx`, `*.keras`,
a nested `model.tar.gz` and the rest of the last row above, and HDF5 files (`*.h5`, `*.hdf5`, `*.hdf`, `*.weights`, `*.tf`) and a Keras directory's
`config.json`, `model.weights.h5` or `model.weights.npz` inside a model archive, though not inside a plain
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
`data.pkl`, an object array); in the four pickles that follow a first pickle returning the
legacy `torch.save` magic number; in a file or member named `.bin`, `.sav`, `.p` or
`.model` when its stream goes on to a clean STOP, calls what the code named, or imports a
callable after the code;
and wherever a pickle opens with a `PROTO` opcode of any protocol. It stays data in a
tensor storage beside a checkpoint's `data.pkl`, a numeric array, everything after those
four pickles in a file whose first pickle returns the magic number, whatever the file is
named, a
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

A scan never writes its report over a file it scanned. If `--output` or its
`<stem>.exchanges.jsonl` is a file the scan read, the command exits `3` after scanning
and writes nothing. Two files are exempt by content, never by name: an earlier saved
run, which `guardana scan . --format json --output run.json` replaces when run again,
and exchanges that an adjacent saved run (`<stem>.json` or `<stem>`) records by digest.
A recording named `customer.exchanges.jsonl` that no saved run records is refused
like any other scanned file.

**`--format json` is not optional here.** `--output` on its own writes whatever
`--format` says, and that defaults to human text — a file named like a saved run
that `guardana diff` refuses. Since 0.7.1 saving any other format says so at the
moment it is written, rather than leaving it to be discovered on the next run,
which is the run you wanted compared.
