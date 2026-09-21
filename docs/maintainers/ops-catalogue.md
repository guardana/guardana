---
title: "Operations catalogue"
nav_order: 11
summary: "One row per script under scripts/: what it writes, its safe mode, what it needs. Exact flags come from each script's own --help or docstring."
status: stable
---

# Operations catalogue

One row per script under `scripts/`. This page answers "which script, is it safe,
what does it need"; exact flags come from the script's own `--help` or module
docstring, never from memory. `scripts/check_ops_catalogue.py` fails the gate
when a script has no row or a row has no script.

Columns: **Writes** = what a default run changes (`-` nothing · `repo` tracked
files · `local` untracked or temporary files · `docker` images and containers ·
`git` commits, tags, pushes). **Safe mode** = the flag that verifies without
writing (`-` = nothing to guard, `NONE` = no such flag, the script always does its
thing). **Net** = network it uses. **Needs** = tools or state it requires.

⚠ prefixes a purpose that pushes, tags, publishes, deletes a tree, or reaches
the network with no safe mode.

Four scripts have no argument parser and run for real when handed `--help`:
`release.py`, `clean_install_check.py`, `generate_sbom.py`, `image_smoke.py`.
Read their docstring instead of asking them.

## Scripts — `scripts/`

### The gate

Run through `scripts/ci_local.sh --quiet`; the gates below are what it runs, every one of
them on every CI push as well.

| script | purpose | Writes | Safe mode | Net | Needs |
|---|---|---|---|---|---|
| `ci_local.sh` | mirror every CI job, one verdict line per gate; `--fast` reports the slow jobs as NOT RUN | `local` (`cache/ci/`, `.coverage*`, `sbom/`) | `-` | `uv audit`, `uv sync --locked` | docker for PostgreSQL and the images |
| `critical_coverage.py` | per-area coverage floors over a coverage JSON report | `-` | `-` | `-` | `.coverage.json` from pytest |
| `clean_install_check.py` | install the five distributions into an empty venv and run the documented commands | `local` (temp venv outside the repo) | `NONE` (no `--help`) | package resolution | ~40 s |
| `new_pack_check.py` | gate: scaffold a pack, install it isolated, and prove it validates, grades its samples and would notice a manifest that lies | `local` (a temp venv and tree outside the repo) | `--help` | package resolution | `uv`, ~15 s |
| `generate_sbom.py` | one CycloneDX SBOM per distribution, verified against its metadata | `local` (`sbom/`, gitignored) | `--check` (writes to a temp dir) | `uv export` | — |
| `image_smoke.py` | ⚠ build both container images and run them against the documented behaviour | `docker` | `NONE` (no `--help`; `--no-build` reuses images) | base-image pull | docker running |

### Documentation and the site

Every generated file has a `--check` mode, and `test_generated_truth_is_current`
runs three of them inside pytest.

| script | purpose | Writes | Safe mode | Net | Needs |
|---|---|---|---|---|---|
| `generate_docs.py` | `docs/generated/*` and the built-in pack manifest from the live registry | `repo` | `--check` | `-` | — |
| `sync_site.py` | rewrite the landing page's rule counts from the registry | `repo` (`site/index.html`) | `--check` | `-` | — |
| `build_site.py` | ⚠ delete and rewrite `site/docs/` from `docs/**.md` | `repo` (`site/docs/`) | `--check` | `-` | — |
| `generate_sitemap.py` | `site/sitemap.xml` and `site/robots.txt` from the pages actually built, in the URL form the host serves | `repo` (`site/sitemap.xml`, `site/robots.txt`) | `--check` | `-` | `site/` already built |
| `generate_llms_txt.py` | `site/llms.txt` from `docs/index.md` | `repo` | `--check` | `-` | — |
| `og_card.html` | the source of `site/og.png`, rendered by hand (`site/README.md`) | `-` | `-` | `-` | a browser |

### Release

`RELEASING.md` is the runbook; the `release` skill is the order that has gone
wrong before.

| script | purpose | Writes | Safe mode | Net | Needs |
|---|---|---|---|---|---|
| `bump_version.py` | set all five versions, every inter-package pin, the Action and image pins, then `uv lock` | `repo` | `--dry-run` | `uv lock` | — |
| `release.py` | ⚠ gate → bump → changelog roll → commit → push `main` → wait for green CI → push the tag (PyPI publish) → move the marketplace tag | `git` + `repo` | `--dry-run` (no `--help`) | `git`, `gh`, PyPI via CI | `gh` authenticated, push rights |

### Agent tooling

Wired in `.claude/settings.json`; never invoked by hand except the checks.

| script | purpose | Writes | Safe mode | Net | Needs |
|---|---|---|---|---|---|
| `ruff_on_edit.py` | PostToolUse hook: `ruff check --fix` + `ruff format` on the file just written | `repo` (that one file) | `-` | `-` | — |
| `guard_hook.py` | PreToolUse hook: deny/ask for the commands a prompt cannot be trusted to hold | `-` | `-` | `-` | — |
| `session_start.sh` | SessionStart hook: work in flight, uncommitted paths, text engines | `-` | `-` | `-` | — |
| `check_claude_setup.py` | gate: frontmatter, rule globs, quoted paths, hook paths, CLAUDE.md budget | `-` | `-` | `-` | — |
| `check_ops_catalogue.py` | gate: every script has one row here, every row has a script | `-` | `-` | `-` | — |
| `text_model.py` | the one door to GPT (`codex`) and Gemini (`agy`) for reader-facing wording and verdicts about it | `local` (the `--out` file) | `--detect` | GPT / Gemini | `codex` or `agy` installed |

## For decision

- The four scripts without an argument parser run for real on `--help`.
  `release.py` fetches from `origin` and runs the whole gate before it notices
  that `--help` is not a version. A five-line `argparse` in each would close
  this; it is a change to release tooling, so it waits for a maintainer's yes.
- `og_card.html` is rendered by hand and `site/og.png` is committed; nothing
  checks that the two still agree.
