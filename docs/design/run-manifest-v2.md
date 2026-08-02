# Design: Run Manifest v2

**Status:** proposed · **Target:** v0.7 · **Supersedes:** the `run` block introduced in 0.6

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

The full field list lives in the plan document and in
`schemas/run-manifest-v2.schema.json`; it is not repeated here, because two copies
of a schema is one copy too many.

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

### Open questions

1. **Does `run_id` need to be globally unique, or unique per target?** A UUID is
   free; the question is whether the collector should key on it or on
   `(target, started_at)`. Leaning UUID, decided when the collector schema lands.
2. **Cost estimation needs a price table Guardana does not have.** Either the
   profile carries per-provider pricing, or `estimated_cost` stays null unless
   configured. Leaning the latter — an invented cost is worse than no cost.
3. **Should the manifest record the *effective* profile, not just its digest?** A
   digest tells you it changed; it does not tell you what changed. An `--explain`
   mode that stores the resolved profile may belong here, gated on the privacy
   policy since profiles can carry endpoint URLs.
