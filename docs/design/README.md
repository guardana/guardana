# Design documents

Why something is shaped the way it is, written before the code and kept
afterwards. The user-facing documentation lives one level up in [`docs/`](../)
and answers *what* and *how*; these answer *why*, and *what was rejected*.

## Naming

**Topic, no date, no number:** `collector-tenancy.md`, not
`2026-08-04-collector-tenancy-design.md`. A link that names its subject stays
readable in a commit message years later, and a filename that leads with a date
tells a reader the age of a document instead of its content — which is the wrong
question, because a decision does not expire on a schedule.

The date lives in the header, where it is one fact among several rather than the
first thing anybody reads.

## Header

Every document opens with a status line:

```markdown
**Status:** accepted, not yet implemented · **Written:** 2026-08-04 · **Phase C, item 21**
```

Statuses in use:

| Status | Meaning |
|---|---|
| `proposed` | written, not agreed |
| `accepted, not yet implemented` | agreed; the code is not there yet |
| `implemented in X` | shipped in that release |
| `superseded by <file>` | a later document replaces it |

## A decision is not rewritten

Once a document is `accepted`, it records what was decided and why — including
the options that lost. When the direction changes, write a new document and mark
the old one `superseded by`. Editing the reasoning out of an accepted decision
leaves a repository where every past choice looks obvious and no one can tell
which constraints have since gone away.

Correcting a typo, a broken link or a factual error is not rewriting. Replacing
the argument is.

## What does not belong here

Instructions, tutorials and reference tables belong in `docs/`, so a reader
looking for how to run something never lands in an argument about alternatives.
Where both exist, the design document links to the user page rather than
duplicating it — [`exit-codes.md`](exit-codes.md) and
[`../exit-codes.md`](../exit-codes.md) are the pattern: the reasoning here, the
contract there, one copy of the table.
