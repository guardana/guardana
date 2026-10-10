---
title: "guardana recipe"
nav_order: 88
summary: "`guardana recipe lock|run`: a repository recipe that pins what a team's checks are, refuses a run whose pins moved, and leaves one reviewable directory"
status: beta
---

# `guardana recipe` — the same checks against your application, every time

A recipe is a file in your repository that names the profile your checks come from and what
answers them. `guardana recipe lock` pins what those checks are; `guardana recipe run` refuses
to send anything when a pin moved, runs otherwise, and writes one directory a reviewer opens.

```bash
guardana recipe lock                 # write guardana-recipe.lock.yaml; review and commit it
guardana recipe lock --check         # in CI: fail when a pin moved, without writing
guardana recipe run                  # check the pins, run, write the artifact directory
```

Each command reads `./guardana-recipe.yaml` unless you name another recipe file.

## The recipe

You write the recipe; Guardana never rewrites it.

```yaml
schema_version: 1
name: support-bot
profile: guardana.yaml
subject:
  kind: application
  connection:
    url: http://127.0.0.1:8080
    model: support-bot
    api_key_env: SUPPORT_BOT_KEY
deployment:
  ai_system: support-bot
  environment: ci
output:
  directory: guardana-artifact
  exchanges: false
```

| Key | Required | Meaning |
|---|---|---|
| `schema_version` | yes | `3`; `2` for a recipe without `subject.target`; `1` for one without `subject.fixtures` either. A newer version is refused with "upgrade Guardana". A schema-1 or schema-2 recipe keeps the digest its lock holds. |
| `name` | yes | The recipe's name, recorded in the run. |
| `profile` | yes | The `guardana.yaml` the checks come from, beside the recipe. |
| `subject.kind` | with `connection` or `target` | What answers: `application` or `model_harness`. No default. With `recording` it may be left out when the recording's header declares `subject_kind`; a run where neither declares one, or the two differ, is refused before anything is graded (exit `3`). |
| `subject.connection` | one of the three | `url`, `model`, and optionally `provider`, `api_key_env`, `adapter`, `system_prompt_file`, with the meanings `guardana probe` gives the same flags. |
| `subject.recording` | one of the three | A recording to grade, as `guardana grade` reads it. Nothing is sent to the application. |
| `subject.target` | one of the three | With `schema_version: 3`: an installed endpoint target, as `guardana probe --target` names it. `locator` is `scheme://value`; `options` maps each `--target-option` key to its value, every value a string. |
| `subject.fixtures` | no | With `connection` and `schema_version: 2` or later: the [fixtures file](usage-fixtures.md) declaring the synthetic data the application runs with — its tenants, seeded documents, records and tools. Refused with `recording` or `target`, and in a schema-1 recipe. |
| `deployment` | no | `ai_system`, `environment`, `deployment_id`, as the `probe` flags of the same names. |
| `output.directory` | no | The artifact directory, a subdirectory beside the recipe. Default `guardana-artifact`. |
| `output.exchanges` | no | `true` puts the replies the profile keeps into the artifact. Default `false`. |

Unknown keys are refused. Relative paths are read beside the recipe.

**Say what answers.** `application` is the endpoint your users reach, run in CI with your own
fixtures or test doubles behind it. `model_harness` is a model reached without your
application's prompt, tools and data: a result about the model, not about what your users
talk to. Guardana cannot tell the two apart from a URL, so it records what the recipe declares
and shows it in the run, the terminal report, the JUnit suite name, `run inspect` and `diff`.

### An installed target

A pack can register its own endpoint target under a scheme ([`usage-target.md`](usage-target.md)).
A recipe names it as `probe --target` does:

```yaml
schema_version: 3
name: support-bot
profile: guardana.yaml
subject:
  kind: application
  target:
    locator: acme-chat://staging
    options:
      region: eu
```

`recipe lock` and `recipe run` build the target once, through the same resolution `plan probe`
uses, and refuse with exit `3` what `probe --target` refuses: a malformed locator, a scheme no
installed distribution registers, a scheme whose target is not
an endpoint, an option the target rejects, a budget the target cannot enforce, `fixtures`
beside `target`, and kept exchanges — `output.exchanges: true` or the profile's
`privacy.keep_exchanges` — with a target that keeps none (only the built-in endpoint and a
pack's target built on it keep exchanges). The `Target` contract forbids building a target
from contacting it; a target that connects while it is built and fails exits `4`, as it does
for `plan probe`. The run records `source: target`. Its options carry no secret; what the
target declares it sends to authenticate ([`sent_secrets()`](extending.md#adding-a-target)) is
withheld from every finding, failure and kept exchange the run saves.

## The lock

`guardana recipe lock` builds the plan of the recipe's run without sending a request and
without reading a key, and writes `guardana-recipe.lock.yaml` beside the recipe. It pins:

- the recipe (its parsed content, so a comment does not count), the Guardana version and the
  plugin trust in force;
- the profile's digest;
- every selected rule's digest, which for a quality suite covers its dataset, with the
  distribution and version that registered it and its trials per case;
- every evaluator a selected rule grades with: who registered it, its judge identity and the
  calibration in force for it;
- every rule the configuration skips, by reason;
- the adapter file the connection names, as written, and the text of its system-prompt file;
- the fixtures file `subject.fixtures` names, as written, and every tenant adapter it names
  (`fixtures`, `fixtures.tenants.<name>.adapter`);
- the installed target `subject.target` names: its scheme, and the distribution and version
  that register it (`target`);
- the files of every distribution installed from a directory or a URL (`sources`).

It never pins a key or the recording: the recording is your application's answer, not your
configuration.

### Distributions installed from a directory or a URL

A distribution installed in editable mode or from a direct URL (PEP 610 `direct_url.json`) can
change its code under one version, so a version pin says nothing about it. Neither does it about
one whose metadata lives outside every `site-packages` directory, such as a `setup.py develop`
install or an `.egg-info` checkout on the path, or one installed with no `RECORD`; with no
`direct_url.json` to say where its files are, each of these stays unpinned. The lock pins each
such distribution by its files, under `sources` (`digest`, `files`), when plugin trust let the
run import any of its Guardana entry points (importing one runs its code, whether or not the
recipe selects what it registers), when it registers a selected rule, an evaluator a selected
rule grades with or the recipe's target, or when it is in the installed `Requires-Dist` closure
of one of those: every requirement whose PEP 503-normalised name is installed is followed,
markers and extras ignored, so a helper library installed editable is pinned as the pack that
imports it is.

- An **editable** install is pinned by the directory its `file://` URL names: every file under
  it by sorted POSIX relative path and the SHA-256 of its content. Untracked files count: an
  editable install imports what the directory holds, not what git tracks. Left out are
  `.git/`, `__pycache__/`, `.venv/`, `.tox/`, `.nox/`, `node_modules/`, `*.egg-info/`,
  `.mypy_cache/`, `.ruff_cache/`, `.pytest_cache/`, `.idea/`, `.vscode/` and `.DS_Store` at
  any depth; `venv/`, `build/`, `dist/`, `htmlcov/`, `.coverage`, `.coverage.*` and `.env` at
  the top of the directory only (a package of the project may carry those names); and the
  recipe's own lock file and output directory when the recipe sits inside the directory, since
  `recipe lock` and `recipe run` write them. Symlinks are followed, so a linked file is pinned
  by what it holds. The `.pth` files and setuptools `__editable__…finder.py` modules the
  install's `RECORD` lists are read first: a path they add or map outside the directory, or
  into a directory the tree pin leaves out (such as `build/`, where a setuptools strict
  editable install maps its packages, `.venv/` or `*.egg-info/`), is code the pin would not
  cover, so the distribution stays unpinned. Bytecode under `__pycache__/` is not pinned, but
  bytecode this interpreter would load in place of a pinned source (hash-based bytecode,
  whatever hash it records, or bytecode recording the source's modification time and size)
  leaves the distribution unpinned unless it is what that source compiles to; bytecode only
  another interpreter would load is checked when that interpreter pins, and this check does
  not change pin digests.
- **Any other direct URL** — a directory installed without `-e`, a VCS checkout, an archive —
  is pinned by its installed `RECORD`: each entry's path and recorded hash, except bytecode
  under `__pycache__/` and every file of its own `.dist-info` but `METADATA` (its version and
  requirements) and `entry_points.txt` (what it registers). An entry inside the install root
  is pinned only once the installed file hashes to the recorded value: a file that differs
  from its `RECORD`, cannot be read, or is hashed in `RECORD` with an algorithm other than
  SHA-256 or a stronger one leaves the distribution unpinned, with the reason; so does a
  row inside the install root without a size, or a path `RECORD` lists twice. The same
  bytecode check as for an editable install applies to each listed source. The pinned value
  is the recorded hash, so this check does not change lock digests. The rest — `RECORD`, `INSTALLER`,
  `REQUESTED`, `direct_url.json`, an installer's cache file — records the install, not the
  code that runs. A file installed outside the install root (`../../../bin/…`,
  `../../../share/…`) or under `*.data/scripts/` is pinned by its path and the SHA-256 of the
  installed file, with one exception: where its first line names the running environment's
  interpreter after `#!` (or in the `/bin/sh` launcher an installer writes for a long path),
  that path is hashed as a placeholder and any arguments after it as written. Any other first
  line is hashed as written. A console or GUI script the installer generated from `entry_points.txt` is left out only
  when it sits directly in this installation's scripts directory (`bin/` or `Scripts/`),
  is run by the environment's interpreter, and holds exactly what pip, uv or
  pypa/installer generate for its declared entry point: the import, an optional rewrite of
  `sys.argv[0]` and `sys.exit(<entry point>())`: `entry_points.txt`, which is pinned, names
  what it calls. A file no `RECORD` lists is not pinned, including a module placed in the
  scripts directory beside the wrapper, which the wrapper imports first when it runs as a
  script, and an unlisted file in `site-packages` that can be imported too; Guardana imports
  plugin entry points in its own process and does not run console scripts. An edited wrapper, a file with the same name elsewhere and a Windows `.exe`
  launcher are hashed, so a Windows lock covering a launcher moves when the installer or
  the environment changes. Installing the same code again into an environment this interpreter's
  `sysconfig` describes pins the same. An installation none of its schemes describes
  (`pip install --target` or `--prefix`, or another environment's `site-packages` on the
  path) has its generated scripts hashed too, so its pin can differ by installer.

A distribution stays under `unpinned`, with the reason, when it holds more than 20,000 files or
256 MiB, when a symlink leads outside its directory, when its editable install loads code from
outside its directory or maps its packages in a way Guardana cannot read, when it has no
`RECORD` to read, when its `RECORD` lists an entry inside the install root without a hash, or
when a file it installed outside the install root cannot be read or is not a regular file (a FIFO, a device, a socket). `unpinned` maps each
`rule:<id>`, `evaluator:<id>` and `target:<scheme>` it registers — or `distribution:<name>`
when it registers none of them — to that reason. `recipe run` computes the lock again on every
run, so it hashes each editable tree again, within the same bounds.

A lock written before `sources` existed (schema 1) is still read, with no `sources`; compared
with the current configuration it drifts `source_added` for each distribution the lock now
pins, beside the `guardana_changed` an upgrade brings. Run `guardana recipe lock` again.

## Exit codes

| Situation | `recipe lock` | `recipe lock --check` | `recipe run` |
|---|---|---|---|
| written, or every pin holds | `0` | `0` | the run's own code |
| a pin moved | — | `1` | `3`, nothing sent |
| a regression pair of a selected suite no longer holds: a side graded the wrong way or declined, the evaluator raised, or it cannot regrade without sending | `1`, nothing written | `1` | `3`, nothing sent |
| the run could never pass: a check the fixtures demand that the profile does not select, or a recording whose run stopped | `3`, nothing written | `3` | runs, and is `2` |
| something selected is `unpinned` | `2`, written | `2` | runs, and the run records what is unpinned |
| `subject.target` refused as `probe --target` refuses it | `3`, nothing written | `3` | `3`, nothing sent |
| `subject.target` fails to connect while it is built | `4`, nothing written | `4` | `4`, nothing sent |
| nothing selected, plugin trust refused an installed extension, or a selected check would not grade (a rule file that did not load, an evaluator nobody registered) | `2`, nothing written | `2` | `3` (the lock cannot match) |
| recipe or lock missing, unreadable, or from a newer Guardana | `3` | `3` | `3` |

`--check` never writes, so a first run cannot pass by creating its own lock. `recipe run`
sends nothing until the pins hold; then the run's gate decides its exit code as it does for
`probe` and `grade`. A drifted pin is named by kind, both directions — `rule_changed`,
`rule_added`, `rule_removed`, `judge_changed`, `calibration_changed`, `profile_changed`,
`trust_changed`, `guardana_changed`, `recipe_changed`, `distribution_changed`,
`skip_changed`, `trials_changed`, `subject_file_changed`, `evaluator_added`,
`evaluator_removed`, `target_changed`, `source_added`, `source_removed`, `source_changed`.
Review the change, then run `guardana recipe lock` again.

A rule about a protocol the subject does not speak is pinned as skipped `not_applicable`: an
MCP or A2A rule against a chat endpoint or a recording, a chat rule against an MCP server
or an A2A agent. A lock that pinned such a rule under another reason, `missing_capability`
or, under `--safety passive`, `unsafe_mode`, drifts `skip_changed` for it; take the lock
again.

All three commands regrade the regression pairs of every selected suite
([`guardana case add`](usage-case.md)) before they compare anything, sending nothing: each
pair's `observed` must still grade `fail` and its `accepted` `pass` with the rule as it is
now. A pair that no longer holds, or a suite whose evaluator cannot regrade without sending,
is a refusal rather than a drifted pin, because it is broken in the lock and in the
configuration alike; the refusal names each case by its rule and dataset line.

`recipe run` takes no selection, trust, trials or profile flags: those are what the lock pins.
Its one flag is `--concurrency INTEGER` (default `4`): how many rules may run at once.

Every rule the lock pins must run to completion. One that the run skips — a recording that
holds no answer for it is the usual cause — that errors or that is never reached is a
`demanded_check` coverage shortfall: the run is `indeterminate` (exit `2`) unless a finding
fails it, whatever the profile's `fail_on_*` switches say.

Before it sends anything, `recipe run` also checks what the lock does not cover: the
subject's key variable and every judge's key variable must be set, and an adapter file read
again to send must still have the digest the lock holds. With fixtures, every tenant's key
variable must be set, no two tenants may send a secret value in common, as a key or in an adapter header, and
every tenant adapter read again must still have its pinned digest; the fixtures file is read
once, so the items a run asks about are the bytes the lock compared. Each refusal exits `3` and is
written into the artifact. When the lock lists unpinned checks, the run says so on stderr,
at the end of `report.txt` and in `guardana run inspect`.

## The artifact

`recipe run` claims `output.directory` before it starts: it writes a `junit.xml` with one
error ("the run did not finish") and a `report.txt` saying so. When the run ends it replaces
the directory whole. An interrupted run leaves the placeholder; a refused run writes the
refusal into the same two files; a run its target stopped part-way replaces it with the
partial run and exits `4`. A CI step that uploads the directory therefore never shows an
earlier run's green.

| File | What it is |
|---|---|
| `run.json` | the saved run, with `run.recipe` (name, recipe and lock digests, kind, source, unpinned) |
| `report.txt` | the terminal report without colour, then the lock comparison |
| `junit.xml` | the JUnit report; its suite is named after the subject kind |
| `guardana-recipe.yaml`, `guardana-recipe.lock.yaml` | the recipe and the lock the run held |
| `run.exchanges.jsonl` | only when the profile keeps exchanges and `output.exchanges` is `true` |
| `guardana-artifact.json` | the files above and the run's `status` (`incomplete`, `refused` or `complete`); it marks the directory as one a run may replace ([`schemas/artifact-v1.schema.json`](../schemas/artifact-v1.schema.json)) |

An existing directory holding a file that `guardana-artifact.json` does not list is refused, never deleted. A recipe that names a file inside its own `output.directory` is refused with exit `3` before anything is sent. The directory is marked refused in place: `junit.xml`, `report.txt` and `guardana-artifact.json` say so; the earlier run's other files are removed, and the files the recipe names stay. A file the recipe names is never rewritten, even to mark it refused: when the recipe names `guardana-artifact.json` itself, the marker stays as it was, the reports it does not name turn red, and stderr says so. A recipe that cannot be read marks the earlier artifact refused in the directory it names, or in `guardana-artifact` beside it when even that cannot be read, and treats every string it holds as a file it may name, so none of those is rewritten. When the files the recipe names include the marker and both reports, nothing in the directory can turn red: the marker may still say `complete`, and only the exit code and stderr report the refusal. It removes only that run's `run.json` and creates none. A recipe that does not parse at all leaves the artifact as it is and warns that it still holds an earlier run's files. A recipe so broken that it no longer names its directory can leave an earlier run in a custom directory, so treat the command's exit code as the verdict, not the directory alone. A
profile that keeps exchanges without `output.exchanges: true` is refused: a CI artifact is a
copy of your application's replies that nobody controls.
