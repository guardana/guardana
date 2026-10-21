---
paths:
  - "scripts/**"
---
# Scripts

- **Every script's module docstring says what it writes, its safe mode and what it needs**,
  so a reader decides whether it is safe to run before running it.
- **A script that writes has `--check` or `--dry-run`, and `--help` that does nothing.** Every
  script that writes, fetches, builds or installs parses its arguments with `argparse`;
  `scripts/tests/test_script_parsers.py` proves `--help` has no side effect for each of them.
- **Generated files are never edited by hand**: `docs/generated/`, the built-in pack manifest,
  `site/docs/`, `site/llms.txt`, the counts in `site/index.html`. Every generator has `--check`
  and each is a CI gate.
- **`release.py` merges the release commit through a pull request, waits for green CI on the
  merge commit, then pushes a signed tag it verified** — and refuses when it cannot check. A tag that moved after a publish no longer names the bytes people
  installed.
- **Hooks live here, not under `.claude/`**, because `mypy --strict` skips dot-directories and a
  checked-in script the gate cannot see is an unverified corner. `guard_hook.py` is tested by a
  case table in `scripts/tests/test_guard_hook.py`; `ruff_on_edit.py` never blocks.
- **`scripts/sitegen` refuses rather than skips**: a page without front matter or without a
  `docs/index.md` entry fails the build, because the page a nav silently drops is the page
  nobody can find.
- Fixed literal subprocess commands carry `# noqa: S603` with the reason; `T201` is allowed
  here. `scripts/` is on `pythonpath`, so tests import a script by module name.
- A script that calls a model names a generally available model in one constant. A loop that
  starts an agent CLI per item boots a full session per call — batch it and state the count.
