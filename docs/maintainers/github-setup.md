# GitHub repository setup (maintainers)

A one-time checklist to make `github.com/guardana/guardana` a first-class
open-source repo: healthy triage, clean contributions, and a supply chain a
security tool can stand behind. Files that live in the repo (issue/PR templates,
`CODEOWNERS`, `dependabot.yml`, `.github/release.yml`) are already committed —
this covers the settings that live in **GitHub's UI**, which a checkout can't
carry. Do these once after the first push; revisit the labels and environment
protection as the project grows.

Related: [`../../RELEASING.md`](../../RELEASING.md) (cutting a release),
[`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) (the contributor rules these
settings enforce).

## 1. Repo basics — Settings → General

- **Description:** "Security verification for self-hosted and self-built AI —
  one rule engine for your laptop, CI, and a served model."
- **Website:** `https://guardana.io`
- **Topics:** `ai-security`, `llm-security`, `prompt-injection`, `mlsecops`,
  `security-scanner`, `owasp-llm`, `supply-chain-security`, `python`, `cli`,
  `sarif` — topics are how people discover the repo.
- **Features:** Issues ✅ · Discussions ✅ (the issue-template chooser links to
  it) · Projects (optional) · Wiki ❌ (docs live in `docs/`).

## 2. Merge settings — Settings → General → Pull Requests

This is where the project's **single-commit-PR law** (see `CONTRIBUTING.md`)
stops being a request and becomes mechanically enforced:

- **Allow squash merging** ✅ — and set the default squash commit message to
  **"Pull request title and description"** so the squashed commit is the
  conventional-commit PR title.
- **Allow merge commits** ❌ and **Allow rebase merging** ❌ — squash-only means
  every PR lands as exactly one commit no matter how the contributor's branch
  looked.
- **Automatically delete head branches** ✅ — keeps the fork/branch list clean.
- **Always suggest updating pull request branches** ✅.

## 3. Protect `main` — Settings → Rules → Rulesets (or Branch protection)

Target branch `main`. Enable:

- **Require a pull request before merging** — with **1 approval** (a solo
  maintainer can set 0 and rely on required status checks; raise it the moment a
  second maintainer exists).
- **Require status checks to pass** — add the CI jobs once they've run once so
  the names appear: the `test` matrix (**3.11**, **3.12**, **3.13**) and
  **`example-plugin`**. Tick **Require branches to be up to date**.
- **Require conversation resolution before merging** ✅.
- **Require linear history** ✅ (pairs with squash-only).
- **Block force pushes** ✅ and **Restrict deletions** ✅.
- Signed commits are optional; if you enable it, document it in `CONTRIBUTING.md`
  so contributors aren't surprised.

## 4. Labels — Issues → Labels

The [`.github/release.yml`](../../.github/release.yml) release-note categories
key off these, so keep the names in sync. A small, purposeful set beats a big
one:

| Label | Colour idea | For |
|---|---|---|
| `bug` | red | A defect |
| `feature` | green | New capability |
| `rule` | teal | A new/changed detection rule |
| `security` | dark red | Security-relevant work (surfaces in release notes) |
| `documentation` | blue | Docs only |
| `breaking` | black | A backwards-incompatible change (drives a minor bump pre-1.0) |
| `dependencies` | grey | Dependency bumps (excluded from release notes) |
| `good first issue` | purple | Newcomer-friendly — GitHub surfaces these specially |
| `help wanted` | teal | Maintainer would welcome a PR |
| `needs-triage` | yellow | Not yet assessed |
| `duplicate` / `wontfix` / `invalid` | grey | Triage outcomes |

You can apply these in bulk with the GitHub CLI, e.g.
`gh label create rule --color 1abc9c --description "A detection rule"`.

## 5. Security — Settings → Security & Advisories

A tool that scans other people's supply chains must be exemplary about its own:

- **Private vulnerability reporting** ✅ — this is the "GitHub Security Advisory"
  channel `SECURITY.md` points at. Turn it on so the "Report a vulnerability"
  button appears.
- **Dependabot alerts** ✅ and **Dependabot security updates** ✅ — the committed
  `dependabot.yml` only schedules *version* updates; the alert/auto-fix side is
  a UI toggle.
- **Secret scanning** ✅ and **Push protection** ✅ — refuses a push that
  contains a detected credential. (Guardana has its own `detect-private-key`
  pre-commit hook and a secret-scanning rule; this is the server-side backstop.)
- **Code scanning (CodeQL)** — optional now; a good v0.2 addition. Our `ruff`
  `S`/bandit rules already lint for common issues in CI.

## 6. The `pypi` release environment — Settings → Environments

[`release.yml`](../../.github/workflows/release.yml) publishes from an
environment named **`pypi`** using OIDC trusted publishing (no stored token).
Create that environment and add a **required reviewer** (yourself/the
maintainers team). Then a `v*` tag push pauses for a human click before anything
reaches PyPI — a deliberate gate so an accidental or malicious tag can't publish
unattended. Configure a **PyPI Trusted Publisher** for each of the five packages
first (see `RELEASING.md` → first-time PyPI setup).

## 7. Discussions — set up categories

The bug/feature templates deliberately route questions away from Issues and into
Discussions. Seed the default categories: **Q&A** (answerable), **Ideas**,
**Show and tell**, **Announcements** (post-only — link releases here).

## 8. Actions permissions — Settings → Actions → General

- **Workflow permissions:** "Read repository contents" by default; the release
  job requests `id-token: write` explicitly in its YAML, which is the minimum
  for OIDC publishing.
- **Fork pull request workflows:** require approval for first-time contributors
  — the default, and the right one for a public repo.

## 9. Verify — Insights → Community Standards

GitHub grades the repo against a checklist (README, Code of Conduct, Contributing,
License, Issue templates, PR template). Every item should already be green from
the committed files — this page is the quick confirmation that nothing regressed.
