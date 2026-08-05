# Design: runs and findings the collector can answer questions about

**Status:** implemented in 0.9.0 · **Written:** 2026-08-05 · **Phase C, item 23**

## The problem

The collector holds *submissions*. A submission says which rules ran and what they
found, and nothing about the run itself: whether it **passed or failed its gate**,
when it actually ran, what it cost, which build produced it, or what redaction was
applied to the evidence now sitting in the database.

So the three questions a team asks of a collector all fail on the same missing
facts:

- *is production failing right now?* — no gate is stored, only findings, and a run
  with findings under a baseline is not a failing run;
- *has this finding been there since Tuesday, or is it new?* — every finding is
  loose in its own submission, with no identity linking one run's sighting to the
  next;
- *did that pipeline actually run, or did it silently stop?* — a retried job stores
  twice and an aborted one stores nothing, and neither is distinguishable.

The engine already knows all of it. `RunManifest` has carried the run id, the
timestamps, the tool version, the gate, the usage and the evidence mode since 0.7,
and `guardana.core.diff` has had a stable finding identity since 0.6. Neither has
ever left the machine. "The collector envelope carrying the manifest" is recorded
debt; this is that work, and it deliberately carries *less* than the whole manifest.

## What must not get harder

- **Reporting gains no argument.** A run already sends everything this needs.
- **A v6 agent keeps working**, sends none of it, and is stored as a run that did
  not say — never as a run that passed.
- **The engine does not change shape.** `Reporter.submit` keeps its signature;
  the run block reaches the reporter the same way the deployment block does.

## Five decisions

### 1. The envelope carries the run's *verdict, cost and identity* — not the manifest

Folding the whole manifest onto the wire would tie two schemas that were separated
on purpose, and hand a collector rule digests and budget ceilings it has no
question to ask of. What it does need is what it cannot derive:

| Field | The question it answers |
|---|---|
| `run_id` | which run is this, and is it the same one I already have |
| `started_at`, `completed_at` | when did it *run* — the receive time is the collector's clock, not the run's |
| `tool_version` | is some agent in this fleet three releases behind |
| `gate` | did this run pass, fail, or fail to reach a verdict |
| `evidence_mode` | what redaction was applied to what I am holding |
| `requests`, `input_tokens`, `output_tokens`, `wall_time_seconds` | what did it cost |

Everything else — the rules and their digests, the execution ceilings, the
configuration digests, the target fingerprint — stays in the saved run, which is
the reproducibility record and is versioned independently. The model identity a
collector *does* need already arrives in the deployment block from item 22.

**`gate` is the field this item exists for.** A collector that holds findings and
not verdicts cannot distinguish a run that failed from a run whose findings were
all waived by a baseline, and reporting the second as the first is a false red the
same way the reverse is a false green.

### 2. `null` gate means "the run did not say", and is never a pass

A v6 agent sends no gate. That run is stored with a null gate and **counted as
unknown**, never folded into passing. A fleet with one old agent must not read as
green because the old agent could not speak.

This is the same rule as everywhere else in the project, applied to a new column:
absence is not success.

### 3. The finding identity is computed by the engine, not by the collector

`guardana.core.diff.finding_identity` has decided since 0.6 what makes two
sightings the same finding: the rule, plus where it was found relative to what the
run examined — and deliberately *not* the evidence summary, which for a dynamic
finding is the evaluator's rationale and moves on every re-run.

The collector must not recompute that. It does not depend on `guardana-core` — a
deliberate decoupling — so recomputing would mean a second implementation of the
same rule in a package that cannot import the first, and two notions of "the same
finding" in one system guarantee they diverge.

So the **agent sends the identity** and the collector stores it. One definition,
in the package that already owns it, reaching the collector the same way every
other fact does.

It travels as a digest rather than as a readable pair, because a location is a file
path and a path is not something to put in a grouping key that also appears in a
listing; the readable rule and target are already on every occurrence, so a listing
groups by identity and shows the newest sighting's own words.

### 4. A `Finding` is still not a table

Same reasoning that kept `ai_systems` and `environments` out of the schema in item
22, and it is worth stating rather than repeating silently: a canonical finding row
today would hold a first-seen, a last-seen and a count — all of which an aggregate
over the occurrences answers exactly. Status, owner, remediation and waiver are
what make it an entity, and they are item 24.

Creating the table now means a row whose columns are derived from the rows below
it, and a migration later that has to invent the meaning it was missing. Creating
it in item 24 means a migration with real occurrence history to build from.

The **identity is stored on every occurrence**, which is what makes that later
migration a `group by`.

### 5. The same run submitted twice is stored once

A retried pipeline job re-sends its run. Without an identity that is two runs in
the history and twice the findings, so "production got worse" answers from a
duplicate. With one, it is `on conflict do nothing` and a `200` that says
`"duplicate": true` — accepted, not stored again, and not an error, because a retry
is not a failure and a pipeline must not go red over one.

Scoped to the project and only when a run id is present: `unique (project_id,
run_id) where run_id is not null`. A v6 agent sends no run id and is stored every
time, which is the old behaviour and the honest one — nothing identifies those runs.

## Design

### Schema, migration 0005

```sql
alter table submissions
    add column run_id             text,
    add column started_at         timestamptz,
    add column completed_at       timestamptz,
    add column tool_version       text,
    add column gate               text,
    add column evidence_mode      text,
    add column requests           integer,
    add column input_tokens       integer,
    add column output_tokens      integer,
    add column wall_time_seconds  double precision;

alter table findings add column identity text;

create unique index submissions_project_run_idx
    on submissions (project_id, run_id) where run_id is not null;

create index findings_identity_idx on findings (identity) where identity is not null;
```

Every column is nullable, so nothing needs adopting: a submission already stored is
a run that did not say. The rollback drops them and needs no refusal — it loses
information and merges no tenants.

### Reads

```bash
guardana-collector run list [--project acme/web] [--environment production]
guardana-collector finding list [--project acme/web] [--environment production]
```

`run list` is the time axis: when, which system and environment, the gate, the
cost. `finding list` groups occurrences by identity: the rule, the worst severity
it has been seen at, when it was first and last seen, and how many runs saw it —
which is the "has this been there since Tuesday" question, answered.

Both filter through the same tenant scope as everything else.

## Testing

- a run with a gate of `fail` is stored and read back as failing
- a run that sends no gate is stored as unknown and **not** as a pass
- the same `run_id` twice: stored once, answered `200` with `duplicate`
- two *different* runs with no run id: both stored
- one run id in two projects: two runs, because the index is scoped
- a finding seen in three runs is one identity with three occurrences
- the identity survives a line moving in a file (the engine's rule, asserted here)
- a v6 envelope still ingests, and stores nulls
- `run list` and `finding list` honour a pinned key's environment
- migration 0005 up and down with rows present

## Acceptance criteria

- The gate reaches the collector, and absence of it is never a pass.
- One definition of finding identity in the product, computed in `guardana-core`.
- A retried submission does not double-count.
- The envelope is v7; the collector accepts 2–7; a v6 agent still reports.
- `Reporter.submit`'s signature is unchanged.

## What the code changed about this design

**`Store.add` returns whether it stored.** The design had the endpoint answer
`duplicate`, which would have meant the endpoint knowing something the store had
decided — and the in-memory store not deduplicating at all. Both stores now
deduplicate and both say so, because two implementations held to different rules
are two implementations that behave differently.

**Timestamps are refused without a timezone.** The wire format carries them as
strings, and a naive one would be read back in whatever zone the collector happens
to run in. `AwareDatetime` refuses it at the door, which is the line the manifest
already holds.

**`monitor` sends no run block.** Its cycles are not saved runs and it builds no
manifest, so a monitor submission is stored as a run that did not say — never as
one that passed. Recorded as debt rather than papered over with a gate inferred
from the fact that an alert fired.

## What this item deliberately does not deliver

- **Finding status, owner, waivers** — item 24, and the reason `Finding` is not yet
  a table.
- **A regression view in the collector.** Comparing two runs is `guardana diff`'s
  question and the collector runs no comparisons; what this adds is the data such a
  view would need.
- **Pagination on the new listings.** They are CLI reads bounded by a limit, like
  every other collector read.
