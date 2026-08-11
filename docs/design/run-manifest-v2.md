---
title: "Run manifest v2"
nav_order: 90
summary: "the reproducible run record"
status: implemented
---

# Design: Run Manifest v2

**Status:** implemented in 0.7 · **Supersedes:** the `run` block introduced in 0.6

> Shipped. Where the built shape differs from this proposal, the differences and
> their reasons are recorded under "What changed during implementation" at the
> bottom; the user-facing description lives in [`docs/usage-run.md`](../usage-run.md).

## The problem

0.6 made a run saveable. `guardana diff` reads it back, which turned the JSON
report into a public contract, and it carries just enough to compare two runs:
tool version, target, profile, which rules ran and a digest of each, and a
timestamp.

That is enough for *comparison* and not enough for *evidence*. A company asking
"what exactly was verified, against what, by whom, at what cost, and can we
reproduce it" cannot answer from a 0.6 run. Specifically it cannot say:

- **what the target actually was** — `http://host#model` is a label, not a
  fingerprint; the same label can point at a different deployment tomorrow;
- **what configuration produced this** — a profile *name* is not a profile, and a
  system prompt that changed between runs is invisible;
- **what it cost** — no request count, no tokens, no wall time, so a team cannot
  budget the next run from the last one;
- **which deployment it belongs to** — no commit, no image digest, no environment,
  so a run cannot be attached to the thing it verified;
- **whether the evidence is safe to store** — no record of which redaction policy
  was in force when the evidence was written.

## Design

One versioned document, `schema_version: "2"`, versioned **independently of the
CLI**. A run written by 0.7.3 and one written by 0.9.0 are the same document if
the schema did not move; a schema change is a schema change whether or not a
release happened.

### Shape

Grouped by the question each block answers, because a flat bag of forty fields is
unreadable and invites drift:

| Block | Answers |
|---|---|
| top level | which document is this, and when |
| `source` | who started it — a laptop, CI, a schedule, a replay |
| `guardana` | what software produced it |
| `target` | what was examined, identified stably |
| `deployment` | which deployment of which AI system this verifies |
| `configuration` | what settings produced this result, by digest |
| `execution` | what limits it ran under |
| `usage` | what it actually consumed |
| `rules` / `evaluators` | what did the checking, with versions and calibration |
| `result_summary` | the counts and the gate outcome |
| `privacy` | what evidence policy was in force |

The full field list lives in `schemas/run-v2.schema.json`; it is not repeated
here, because two copies of a schema is one copy too many.

### Decisions

**Fingerprints name their algorithm.** `sha256:…`, never a bare hex string. A
digest whose algorithm is implied cannot be migrated when the algorithm changes.

**Timestamps are UTC, RFC 3339, always.** A local-time timestamp in an evidence
record is a bug waiting for a timezone.

**Nullable is explicit, and null means "not known", never "not applicable".** A
run from a laptop has no `deployment.commit_sha`; that is a null with a meaning,
and a consumer must be able to tell it from zero.

**Digests, not contents.** `configuration.system_prompt_digest` rather than the
system prompt. A manifest is an evidence record that may leave the machine that
produced it, and a system prompt is frequently the most sensitive thing in a
deployment. The digest answers "did this change between runs", which is the
question a manifest exists to answer.

**Usage is recorded even when unbounded.** A run with no budget still records what
it spent, or a team can never set a budget from experience.

**The gate outcome is a field, not an inference.** `pass | fail | indeterminate`,
written by the engine. A consumer that has to re-derive the verdict from counts
will eventually derive it differently from the engine — and the divergence will
appear as a green build.

### Compatibility

- `load_report` accepts v1 and v2, and **migrates v1 forward in memory** rather
  than refusing it: a team upgrading Guardana must be able to compare today's run
  against last week's.
- A v1 document lacks blocks v2 has; those become explicit nulls, and `diff` says
  so when a comparison depends on one of them.
- A document with no `schema_version` (0.5 and earlier) is still refused. There is
  nothing to migrate *from* — the shape was never declared.
- `guardana run migrate` rewrites a v1 file to v2 on disk for anyone who wants the
  richer document without re-running.

### Acceptance criteria

- Two runs of the same target and configuration are either reproducible or
  explicitly marked non-reproducible, with the reason.
- `diff` explains every incompatibility rather than refusing opaquely.
- No secret is written by default at any evidence mode.
- Every timestamp is UTC; every fingerprint names its algorithm.
- Schema compatibility tests cover v1→v2 migration and unknown-field handling.

## What changed during implementation

Five decisions moved. Each is here because the reason only became visible once
the code existed.

**One version number, not two.** The proposal versioned "the manifest"; the file
on disk is the manifest *plus* the finding channels, and giving it two numbers is
how they start to disagree. `schema_version` is stated once, at the root, and the
schema (`schemas/run-v2.schema.json`) describes the whole document. The manifest
block carries no version of its own.

**`schema_version` stays an integer.** The proposal wrote `"2"` as a string while
version 1 on disk is the number `1`. A field that is sometimes a string and
sometimes a number is a trap for every reader, ours included.

**More fields are nullable than planned, and one of them matters.** A migrated
version-1 document knows no `usage`, no `execution` settings, and — the important
one — **no gate verdict**. `result_summary.gate` is therefore nullable. Computing
a verdict during migration was the tempting alternative and would have been the
re-derivation that storing the gate as a field exists to prevent, done with this
build's thresholds against another build's run. Nullability is constrained rather
than free: a document with `migrated_from: null` must carry its timestamps and a
gate, enforced both in `RunManifest.__post_init__` and by an `if/then` in the
schema, so the allowance made for migration cannot become a way for a fresh run
to skip them.

**The target fingerprint declares its inputs.** `fingerprint_inputs` was not in
the proposal. Without it, a digest over a URL and a model name invites the
stronger reading — "this identifies the model" — and nothing in the document
contradicts it.

**The writer moved into the engine, next to the reader.** Serialization used to
live in `guardana-report` while the loader lived in `guardana-core`, so a field
added on one side could sit unread on the other with nothing to notice. Both
halves are now in `guardana.core.report.serialize` / `.load`.

## Open questions

1. **Does `run_id` need to be globally unique, or unique per target?** Answered
   for the local case: a fresh run gets a UUID4, and a migrated run gets a
   deterministic digest of what the old document contained, so opening the same
   file twice does not mint a new run. Whether the collector keys on it or on
   `(target, started_at)` is still open, and lands with the collector schema.
2. **Cost estimation needs a price table Guardana does not have.** Settled as
   proposed: `estimated_cost` stays null. A price table belongs in profile data
   if it arrives at all, never in the engine — the engine knows no vendor.
3. **Should the manifest record the *effective* profile, not just its digest?**
   Still open. A digest tells you it changed; it does not tell you what changed.
   An `--explain` mode that stores the resolved profile may belong here, gated on
   the privacy policy since profiles can carry endpoint URLs.
