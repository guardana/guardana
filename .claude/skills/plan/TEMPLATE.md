# <Title — what will be true when this ships>

Size: M | L · Started: <yyyy-mm-dd> · Owner: <session or person> · Status: planning | building | in review | blocked on <what>

## Goal

Two or three sentences: the behaviour that changes and who notices. Non-goals in one line.
Which GitHub issue, milestone or documented 1.0 exit criterion this serves, if any.

## Open questions (the user's to answer)

- [ ] … — default if unanswered: …

## Context

What exists today, with `path:line` anchors. Only what the design turns on.

## Issue

URL, assignee (or who claimed it in a comment), milestone and linked PRs — or "none".
Release impact: none / patch / minor / major under `docs/compatibility.md#versioning`, and
whether it is a fix a candidate may carry. Say whether a formerly passing gate could fail,
and why.

Acceptance, copied from the issue — each box ticked only with its evidence:

- [ ] <criterion> — evidence: <command and verdict, path:line, artifact>
- [ ] …

## Decisions

- <decision> — because <reason>. Alternatives considered: <one line each>.
- decided alone: <decision> — reverse by <how>.        ← `/auto` runs mark theirs like this

## Blast radius

Tick what the change touches; each ticked line is a done-criterion.

- [ ] a persisted document (run manifest, envelope, baseline, lock, profile, pack manifest, `schemas/`) → `schema_version` moved, migration, round-trip test
- [ ] an exit code → `docs/exit-codes.md` and the code agree
- [ ] a CLI command or flag → `docs/usage-*.md`, `docs/index.md`, `FEATURES.md`
- [ ] the extension contract (`Rule` / `Evaluator` / `Target`, entry-point groups, pack manifest, trace format) → the isolated example suites green
- [ ] the collector → tenancy and authorization stated per route; PostgreSQL tests present
- [ ] a rule, evaluator or target → `add-a-rule` checklist; `docs/generated/` regenerated
- [ ] a count or capability claim in prose → generated or cited
- [ ] a script → its module docstring says what it reads, writes and needs
- [ ] reader-facing wording → its own lane, reviewed as text
- [ ] a protected contract (`CLAUDE.md` lists them) → both sides changed together, on purpose

## Lanes

| # | lane | files | owner / tier | depends on | verify | done |
|---|---|---|---|---|---|---|
| 1 | <behaviour> | `path`, `path` | coder (Opus high) | — | `uv run pytest … -q` | [ ] |
| 2 | … | … | main | 1 | … | [ ] |

Per lane, below the table when needed: the change in behaviour, the tests that prove it
(the negative case included), traps.

## Done-criteria

- [ ] full gate green, verdict lines read (`scripts/ci_local.sh --quiet`)
- [ ] the documented command run against a real or faked target, its artifact read
- [ ] reviewed; findings fixed or answered
- [ ] the five documentation places answered in the same change
- [ ] every acceptance box above ticked with evidence (`Closes #N`), or `Refs #N` and what remains
- [ ] this file deleted in the shipping commit; leftovers opened as issues

## Handoff

Keep current after every lane, so a fresh session can continue from this section alone.

- Done: …
- Next: …
- How to verify where we are: …
- Surprises: …
