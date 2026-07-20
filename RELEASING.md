# Releasing Guardana

How a maintainer cuts a release. Guardana is five packages that version **in
lockstep** — one number, one tag, one PyPI publish for all of them — so a
release is a single deliberate act, not five.

If you only remember one thing: **`uv run python scripts/release.py <part>`** —
it runs the gate, bumps the version + pins + lock, rolls the changelog, commits,
tags `vX.Y.Z`, and pushes. Pushing the tag triggers the PyPI publish (which pauses
on the `pypi` environment for one approval click). Preview with `--dry-run` first.

```bash
uv run python scripts/release.py patch --dry-run   # show the plan, change nothing
uv run python scripts/release.py patch             # cut it: 0.1.0 -> 0.1.1
uv run python scripts/release.py 0.1.0             # first release: tag the current version, no bump
```

Only a maintainer (repo admin) can push a `v*` tag — enforced by a tag-protection
ruleset — so a release is always deliberate. The rest of this file is the why, the
manual steps the script automates, and the edge cases.

## Versioning: SemVer, and what 0.x means

Guardana follows [Semantic Versioning](https://semver.org). The twist is that it
is **pre-1.0**, and 0.x has its own rules — under SemVer, `0.y.z` makes *no*
stability promise across a **minor** bump, so the minor slot carries what the
major slot will carry after 1.0:

| You're releasing… | Bump | Pre-1.0 (`0.y.z`) | Post-1.0 (`x.y.z`) |
|---|---|---|---|
| A backwards-**incompatible** change (renamed/removed public API, a rule id change, a stricter default that can fail a previously-passing build) | **minor** pre-1.0, **major** post-1.0 | `0.1.4 → 0.2.0` | `1.4.2 → 2.0.0` |
| A backwards-**compatible** new feature (a new rule, a new flag, a new evaluator) | **minor** post-1.0, **patch**-or-minor pre-1.0 | `0.1.4 → 0.2.0` *(or `→ 0.1.5` if you want to signal "small")* | `1.4.2 → 1.5.0` |
| A backwards-compatible **bug fix** (no API change) | **patch** | `0.1.4 → 0.1.5` | `1.4.2 → 1.4.3` |

Practical pre-1.0 rule of thumb: **patch = "safe to upgrade blindly"**, **minor
= "read the changelog, something might break."** Because a security tool can
*fail a build* by design, treat "a new HIGH/CRITICAL rule that will flag code
that passed before" as a **breaking** change (minor bump) — users pin to a range
precisely so that doesn't surprise their CI. This is what the inter-package pins
(`>=0.1.0,<0.2`) encode, and what the bump script keeps correct.

> SemVer's own literal guidance for 0.x is looser — *"start at 0.1.0 and
> increment the minor version for each subsequent release"* — because 0.x makes
> no compatibility promise at all. The patch-vs-minor convention above is a
> stricter discipline we layer on top so users get a meaningful signal before
> 1.0; use it, but know that shipping everything as a minor bump would also be
> spec-legal.

### When to release 1.0

Cut `1.0.0` when the public API (the `guardana.core` surface, the rule/evaluator/
target contracts, the CLI flags, the profile schema, the collector envelope) is
one you're willing to keep stable — i.e. the next breaking change would be rare
and deliberate. 1.0 is a promise, not a maturity badge; don't rush it, but don't
hide behind 0.x forever either. Everything from 1.0 on follows the right-hand
column above.

## Why lockstep, and the one command that keeps it honest

The five packages share a version and pin to each other (`guardana-cli` needs
`guardana-core>=0.1.0,<0.2`, etc.). `uv version` bumps a single package's version
field but **never touches those pins in the other packages**, so bumping by hand
is the classic place a monorepo release drifts — `core` goes to `0.2.0` while
`cli` still says `guardana-core>=0.1.0,<0.2` and silently resolves an old core.

`scripts/bump_version.py` does the whole thing atomically: sets all five
versions, rewrites every inter-package pin to `>=<new>,<<next-breaking>`,
updates `guardana.core.__version__` (what `guardana --version` prints), and
re-locks `uv.lock`.

```bash
python scripts/bump_version.py patch          # 0.1.0 -> 0.1.1  (pins stay <0.2)
python scripts/bump_version.py minor          # 0.1.0 -> 0.2.0  (pins -> >=0.2.0,<0.3)
python scripts/bump_version.py 1.0.0          # set an explicit version (pins -> >=1.0.0,<2)
python scripts/bump_version.py patch --dry-run  # print the changes, write nothing
```

Always `--dry-run` first and read the summary line — it tells you the exact pin
range dependents will get.

## The release runbook

From a clean `main` with everything you want in the release already merged:

```bash
# 1. Confirm the tree is green — the release is only as good as this.
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict .
uv run lint-imports
uv run pytest --cov
uv run guardana scan packages          # dogfood: must be 0 findings

# 2. Bump all five packages + pins + lock (see the table above for which part).
python scripts/bump_version.py minor --dry-run   # eyeball it
python scripts/bump_version.py minor

# 3. Roll the changelog: rename "## [X.Y.Z] - Unreleased" to today's date and add
#    a fresh empty "## [Unreleased]" above it. (Keep-a-Changelog format.)
$EDITOR CHANGELOG.md

# 4. Re-run the gate — the bump changed pyprojects and the lock.
uv run pytest -q && uv run guardana scan packages

# 5. Commit the release as ONE conventional commit.
git add -A
git commit -m "chore(release): vX.Y.Z"

# 6. Tag it (annotated — see below) and push the branch, then the tag.
git tag -a vX.Y.Z -m "Guardana vX.Y.Z"
git push origin main
git push origin vX.Y.Z          # this is what triggers the publish

# 7. Publish the GitHub Release (see below), pasting the changelog section.
```

Pushing the `vX.Y.Z` tag triggers [`release.yml`](.github/workflows/release.yml),
which builds all five wheels/sdists and publishes them to PyPI via OIDC trusted
publishing. With a required reviewer on the `pypi` environment (see
[`docs/maintainers/github-setup.md`](docs/maintainers/github-setup.md)), that
publish pauses for one human click — so a stray tag can't ship unattended.

## Tags

- **`v`-prefixed, `vX.Y.Z`** — matches `release.yml`'s `tags: ["v*"]` trigger and
  is the near-universal convention (`v0.1.0`, `v1.2.3`).
- **Annotated (`git tag -a`), not lightweight.** An annotated tag carries a
  tagger, date, and message and is what `git describe` and release tooling
  expect; lightweight tags are really just branch-less bookmarks. Sign it
  (`git tag -s`) if you publish a signing key — optional, but nice for a security
  project.
- **One tag for the whole release.** Because the packages move in lockstep, a
  single `vX.Y.Z` covers all five — no per-package tags. (Independently-versioned
  monorepos use `pkg-name-vX.Y.Z`; that's not us, and adopting it would mean
  giving up lockstep.)

### Pre-releases / release candidates

For a risky release, ship a candidate first:

```bash
python scripts/bump_version.py 1.0.0rc1     # PEP 440 pre-release form (also 1.0.0b1, 1.0.0a1)
# ... changelog, commit ...
git tag -a v1.0.0rc1 -m "Guardana v1.0.0rc1"
git push origin v1.0.0rc1
```

Spell it the **PEP 440** way — `1.0.0rc1`, no separator — not the SemVer style
`1.0.0-rc.1`. PEP 440 is Python's version spec, and its canonical pre-release
form has no separator between the release and the `rc`/`b`/`a` marker; a
`-rc.1` tag would not normalize to a valid Python version and PyPI would reject
it.

`v*` still matches, so the candidate publishes to PyPI, where it's marked a
pre-release and won't be installed by a plain `pip install guardana-cli` (only
with `--pre` or an explicit `==1.0.0rc1`). Mark the GitHub Release as a
**pre-release** too. When it's proven, release the final `1.0.0`.

## First-time PyPI setup (once, before the first release)

Steady-state releases publish via OIDC trusted publishing — no API token in CI.
Getting the five projects to *exist* the first time has one wrinkle worth knowing:
PyPI allows **only one _pending_ trusted publisher per (owner, repo, workflow,
environment) configuration.** All five packages share the same repo, `release.yml`,
and `pypi` environment, so you *cannot* pre-register five pending publishers — the
second is rejected with *"a pending trusted publisher matching this configuration
has already been registered for a different project name."* (This is not a name
squat; the names are free.)

So bootstrap the five projects once with a one-time token, then attach a normal
(non-pending) trusted publisher to each — the same config on five *existing*
projects is allowed:

1. Build all five and sanity-check the metadata:
   ```bash
   for pkg in packages/*/; do uv build "$pkg" --out-dir dist/; done
   uvx twine check dist/*
   ```
2. Create an **account-scoped** PyPI API token (Account settings → API tokens) —
   account scope is required because the projects don't exist yet.
3. `uvx twine upload --skip-existing dist/*` — creates, reserves, and publishes
   all five names. **Expect a possible one-time HTTP 429:** registering five
   brand-new projects in one burst can trip PyPI's *new-project* rate limit
   partway through. That is a bootstrap artifact, not a workflow bug — wait for
   the window to clear and re-run the same command; `--skip-existing` skips what
   already landed. A normal release (a new *version* of an *existing* project) is
   not subject to this limit, so it never recurs.
4. On each of the five project pages (Manage → Publishing → Add a trusted
   publisher): owner `guardana`, repo `guardana`, workflow `release.yml`,
   environment `pypi`. Non-pending (the projects now exist), so the identical
   config on all five is accepted. Delete any leftover *pending* publisher — a
   token upload does not convert it.
5. Revoke the account token. From here on every release is OIDC via `release.yml`,
   tokenless, and `skip-existing` makes any re-run idempotent.
6. Drop the "PyPI coming soon" note from the README and add the install path
   (`uv add guardana-cli` / `uvx --from guardana-cli guardana` — the console
   script is `guardana`, the distribution is `guardana-cli`, hence `--from`).

**Going forward the auto-release is boring on purpose:** `release.py X.Y.Z` cuts
the tag, `release.yml` builds all five and publishes via OIDC behind the `pypi`
environment's one approval, and `skip-existing` means a re-tag or a partial retry
never errors. No tokens, no new-project rate limit, no surprises.

## The GitHub Release

After the tag is pushed and CI is green:

1. **Releases → Draft a new release**, choose the `vX.Y.Z` tag.
2. Title `vX.Y.Z`. For the body, paste that version's `CHANGELOG.md` section —
   it's already curated and grouped, which reads better than raw auto-notes.
   ("Generate release notes" is a fine starting point; the
   [`.github/release.yml`](.github/release.yml) config groups it by PR label.)
3. Tick **Set as the latest release** (or **pre-release** for an rc).
4. Publish. Optionally announce it in the Discussions → Announcements category.

## Hotfixes

A patch on the current line is just the runbook with `patch`. If you ever need to
fix an *old* line after a newer minor has shipped (e.g. patch `0.1.x` after `0.2`
is out), branch from that tag (`git switch -c 0.1.x v0.1.4`), apply the fix, and
release `0.1.5` from there — but pre-1.0 with a single active line, you'll almost
never need this.
