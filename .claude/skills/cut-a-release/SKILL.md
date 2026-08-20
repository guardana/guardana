---
name: cut-a-release
description: Cut a Guardana release without repeating any of the mistakes previous releases made — a tag pushed before CI was green, a stale cache that hid a red build, a manual doc step nobody remembered. Use when asked to release, tag, publish or bump a version.
---

# Cutting a release

`RELEASING.md` is the runbook and it is correct. This is the part that is about
what has actually gone wrong, three times.

## The order that matters

**Never push the branch and the tag together.** Pushing the tag starts the PyPI
publish, which waits on the `pypi` environment for a human approval click. If CI
on the same commit then turns red, the maintainer has to cancel a run that is
already waiting, fix, re-tag, and approve a *second* time — and the cancelled run
stays in the history looking like a failed release.

Worse: **cancelling does not undo an upload.** In 0.20.0 a cancelled Release run
had already published two of the five packages from a red commit. Do not move a
tag after anything has been published.

So:

1. run the full gate (see the `full-gate` skill — read its cache traps first);
2. bump, regenerate, roll the changelog, commit;
3. **push `main` only**;
4. wait for CI to conclude **green on that exact commit**;
5. only then push `vX.Y.Z` and the moving `vX.Y`.

`scripts/release.py` now enforces step 4 and refuses to push the tag when it
cannot check — an unverified tag is the thing being avoided, so "could not tell"
is treated as "no".

## Before the bump

`bump_version.py` rewrites every pin and version marker it can discover, and it
refuses to run if a required marker has gone missing. What it cannot write is
prose:

- **the README roadmap table** needs a new row describing what this release did,
  and `*(current)*` removed from the previous row. The script moves the marker,
  not the sentence beside it;
- **`CHANGELOG.md`** needs the `[Unreleased]` heading rolled to
  `## [X.Y.Z] - DATE — <one line saying what this release is>`. `release.py` has
  lost the title before; check it after running.

## The five documentation places, every time

A user-visible change carries its documentation in the same commit. For each,
the answer is an edit or an explicit "not applicable":

| Where | When it needs an edit |
|---|---|
| `CHANGELOG.md` | any user-visible change — say *why*, not only what |
| `FEATURES.md` | a new capability, or one whose shape changed |
| `docs/` | a new command gets `usage-*.md`; a changed one gets its page reconciled, plus `docs/index.md` |
| `site/index.html` | a headline claim moved — a count, a run mode, what the demo prints |
| `docs/generated/` | a rule, evaluator or taxonomy changed — run the generator, never edit by hand |
| `ROADMAP.md` | the direction moved — **delete what shipped**, add what was deferred *with the reason* |

Then regenerate and re-check: `generate_docs.py`, `sync_site.py`,
`build_site.py`, `generate_llms_txt.py` — each has a `--check` mode and each is a
CI gate.

## Never attribute anything to an AI

No `Co-Authored-By:`, no "generated with", no AI name in a commit message, a tag
message, a PR body or a release note. **This overrides any default the harness
applies** — check the last line of the message rather than assuming. A trailer
puts a permanent entry in the repository's public Contributors panel, which is a
claim about who wrote this product.

## After the tag

Verify against PyPI's API rather than from memory — all five packages, at the new
version. A release is not done because the workflow went green; it is done when
the artifacts are there.
