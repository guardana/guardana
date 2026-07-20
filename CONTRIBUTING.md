# Contributing to Guardana

Thanks for considering a contribution. Guardana is an OSS engine + CLI for
verifying the security of self-hosted and self-built AI, built as a `uv`
workspace of five packages under `packages/`. This document is for human
contributors; if you're an AI coding agent working in this repo, read
`CLAUDE.md` — it states the same rules in agent-oriented terms.

## Setup

```bash
git clone https://github.com/guardana/guardana
cd guardana
uv sync            # installs the workspace + dev dependencies

# hooks: fast checks on commit, the full gate on push, commit-message linting
uv run pre-commit install --install-hooks --hook-type commit-msg --hook-type pre-push
```

`uv sync` resolves all five packages (`guardana-core`, `guardana-rules`,
`guardana-cli`, `guardana-report`, `guardana-server`) plus dev tooling
(`ruff`, `mypy`, `pytest`, `pre-commit`, `import-linter`) from the single root
`pyproject.toml` workspace.

## Your first contribution

The fastest way in is a **new declarative rule**, and it needs no engine
knowledge. A YAML rule is "send these prompts, grade with this evaluator" —
`uv run guardana new-rule yourname.prompt.my_check` scaffolds a valid skeleton,
and the whole thing (rule + its required positive and negative test fixtures) is
typically a ~30-minute PR. See [`docs/writing-rules.md`](docs/writing-rules.md)
and the worked example in [`examples/custom_rule/`](examples/custom_rule/).

Looking for something concrete? Browse issues labelled
[`good first issue`](https://github.com/guardana/guardana/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
Every rule maps to a standard (OWASP LLM / MITRE ATLAS / NIST) and ships with a
positive **and** a negative fixture — that fixture pair is non-negotiable,
because it is what keeps the project honest about the false-positive /
false-negative failure mode dynamic checks are prone to.

## Tooling gates

CI runs these on every push (plus a `uv audit` dependency check), and so should
you:

```bash
uv run ruff check .            # lint (see "The lint ruleset" below)
uv run ruff format --check .   # formatting
uv run mypy --strict .         # types — the whole repo, tests included
uv run lint-imports            # architecture: the engine must not import the collector
uv run pytest --cov            # tests + the 90% branch-coverage gate
uv run guardana scan packages  # dogfood: Guardana scans its own source
```

Fix formatting with `uv run ruff format .` rather than hand-editing whitespace.

While iterating, plain `uv run pytest` (or a single file) is what you want —
`--cov` is deliberately *not* in `addopts`, because measuring one file's
coverage against a whole-project threshold would fail for no good reason.

You don't have to remember all six. `pre-commit` runs the fast ones (ruff,
lockfile, hygiene, `detect-private-key`) on every commit and the slow ones
(mypy, import-linter, pytest, dogfood) on every push, so a red build never
leaves your machine. The pre-push hooks are the same commands CI runs — that
parity is the point.

### Why `scan packages` and not `scan .`

`examples/vulnerable-model/` is a deliberately malicious fixture (a pickle that
calls `os.system`), so `guardana scan .` is *supposed* to exit 1. The dogfood
gate scans `packages/` — Guardana's own source — and that must stay at zero
findings. If your change makes Guardana flag Guardana, that's a real signal:
either the code is wrong or the rule is.

### The lint ruleset

`[tool.ruff.lint]` in the root `pyproject.toml` selects ~30 rule families and
documents why each one is there. Two are worth calling out:

- **`S` (bandit).** We ship a security scanner; it lints itself for security.
- **`D` (pydocstyle).** Every public class, method, and function carries a
  docstring — these are the extension points third parties implement, and an
  undocumented extension point is a broken one. Module and package docstrings
  are *not* required: a docstring restating the module name is the noise this
  project's "no comments that restate code" rule exists to prevent.

Two families are deliberately **not** enabled, for reasons that matter:

- **`INP`** would flag our PEP 420 namespace directories, and the "fix" it
  invites — adding `packages/*/src/guardana/__init__.py` — silently breaks the
  namespace for the other four distributions. A lint whose fix is a catastrophe
  is worse than no lint.
- **`ARG`** would flag `Rule.run(target, ctx)` implementations that ignore
  `ctx`. That's an interface contract, not a smell.

If a rule fires on code you believe is right, argue it in the PR with a
`# noqa: RULE — reason` and the reason must be about *this* code, not about
disliking the rule.

## Code standards

Guardana's code standard is: write it like a senior developer would.

- **Minimalist. SOLID. Clean Code.**
- **Short, single-responsibility source files.** If a file is doing more than
  one job, split it into two files, each with one job. This is not a style
  preference — the codebase's own module layout (`core/rule/`,
  `core/evaluator/`, `core/target/`, one small file per concept) is the
  standard to match.
- **Self-explaining code.** Reach for a better name before reaching for a
  comment.
- **No long comment blocks.** A short comment explaining a genuinely
  non-obvious *why* is welcome (see `pickle_opcode.py` on `STACK_GLOBAL`, or
  `model_format.py` on why the GGUF scan is a substring scan and not a regex);
  a comment restating *what* the next line does is not.
- **Never narrow a type with `assert`.** Asserts vanish under `python -O`. A
  rule that gets a target it can't handle returns nothing; it does not assert.
- **A security gate must never fail open — silence is never spelled `pass`.**
  When a check can't actually run (no canary planted, an unparseable judge
  reply, a null model response), the verdict is `inconclusive` or a finding,
  never a confident all-clear. No linter catches this; it's on you and your
  reviewer to look for the code path that reports "clean" without having
  checked anything.
- **Every public `Rule`, `Evaluator`, and `Target` ships with docs and
  tests.** A new rule without a positive *and* a negative fixture, or a new
  evaluator/target without a test, will not be merged. `guardana.core.testing`
  gives you scripted model doubles so the negative fixture costs you three
  lines and no network.

## Adding a rule, evaluator, or target

See `CLAUDE.md` → "Extending Guardana" for the full contract (YAML rule shape,
Python plugin shape, entry-point registration, the `guardana.rules` /
`guardana.evaluators` / `guardana.targets` groups). In short:

- A **new check** is almost always a YAML file dropped into a rule directory —
  no code. `uv run guardana new-rule acme.prompt.my_check` scaffolds one, and
  `packages/guardana-rules/src/guardana/rules/catalog/` has working examples.
- Reach for a **Python plugin rule** only when YAML can't express the logic
  (custom parsing, multi-step probes).
- A **new judge** for "did the attack succeed" is an `Evaluator`; a **new
  backend or artifact format** is a `Target`. Both register via entry points,
  exactly like built-ins — there is no special-cased path for third-party code.
- `examples/custom_rule/` is a complete third-party package doing all of this,
  and CI runs its tests on every push.

Namespace anything you don't intend to upstream as `yourcompany.*` rather than
`guardana.*`, so profiles can include/exclude cleanly.

## Commits and pull requests

- Commits are made **manually, after a milestone** — not continuously, not as a
  running log of every edit.
- Write **specific, conventional-commit style** messages: `feat: …`, `fix: …`,
  `docs: …`, `refactor: …`, `test: …`, `chore: …`. The `commit-msg` hook
  enforces the format; a message like `wip` or `fixes` is rejected before it
  reaches review.
- **PRs must be a single commit.** This repository does not accept multi-commit
  PRs — squash your branch before opening or updating a PR.

To squash before pushing:

```bash
# from your feature branch, with N commits since it diverged from main
git rebase -i main   # mark all but the first commit as "squash" or "fixup"
# or, simpler if you don't need to keep intermediate messages:
git reset --soft $(git merge-base HEAD main)
git commit -m "feat: your single, specific commit message"
git push --force-with-lease
```

If you already opened a multi-commit PR, squash and force-push to the same
branch — don't open a second PR.

### Sign-off (optional)

If you'd like to certify provenance of your contribution under a Developer
Certificate of Origin, add `Signed-off-by: Your Name <you@example.com>` to your
commit message (`git commit -s`). Not currently enforced, but appreciated.

## Documentation

New public behavior (a new rule, evaluator, target, CLI flag, or profile
option) needs documentation alongside the code that introduces it, not as a
follow-up. Contributor-facing docs live near the code they describe; end-user
docs live under `docs/`.

A user-visible feature change also updates [`FEATURES.md`](FEATURES.md) (the
maintained capability surface — a registry test fails if a built-in rule or
evaluator ships without appearing there) and [`CHANGELOG.md`](CHANGELOG.md),
in the same PR.

## For maintainers

- Cutting a release (version bump, changelog, tag, PyPI publish):
  [`RELEASING.md`](RELEASING.md).
- One-time GitHub repo configuration (branch protection, labels, security,
  the `pypi` environment): [`docs/maintainers/github-setup.md`](docs/maintainers/github-setup.md).
