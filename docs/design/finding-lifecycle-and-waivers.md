---
title: "Finding lifecycle and waivers"
nav_order: 170
summary: "statuses, waivers that expire, and why this is not a second `baseline`"
status: accepted
---

# Design: the finding lifecycle, and waivers that expire

**Status:** accepted · **Implemented in:** 0.11.0 · **Component:** collector

## The problem

The collector records every sighting of a finding and nothing about what anybody
decided. `finding list` can say a problem has been seen by nine runs since
Tuesday; it cannot say that someone looked at it, that it is being fixed, that it
is a false positive, or that the team accepted the risk until the end of the
quarter. So a team triages in a spreadsheet, and the collector — the one place
with the history — is the one place that does not know the answer.

That is also how a scanner produces alert fatigue: re-litigating the same finding
every run is what makes people stop reading the output.

## The model

`Finding` becomes an entity. The identity that groups occurrences is the one the
engine has computed since 0.6 (`guardana.core.diff.finding_identity`) and already
sends on every occurrence, so the collector does not invent a second notion of
"the same finding" in a package that cannot import the first.

```
tracked_findings   (project_id, identity)  ← the entity: status, owner, waiver
findings           (submission_id, …)      ← the occurrences, unchanged
```

**The occurrence table keeps its name.** Renaming `findings` to
`finding_occurrences` reads better and would touch every query in the collector at
once, for a clarity a comment gives for free. The new table's name says which one
it is.

**The entity holds only what the sightings cannot say**: status, owner, waiver,
first and last seen. Severity, title and location stay where they are, computed by
aggregating occurrences — a copy on the entity is a second source of truth that
drifts the first time a rule's severity changes.

## Statuses

A closed set of six, and no free text:

| Status | Means | Set by |
|---|---|---|
| `open` | seen, nobody has said anything | ingest (first sighting), or a lapse |
| `acknowledged` | a human has read it | `finding status` |
| `in_progress` | somebody is fixing it | `finding status` |
| `resolved` | believed fixed | `finding status` |
| `false_positive` | the rule is wrong here | `finding status` |
| `accepted_risk` | waived, with an approver, a reason and a date | `finding waive` |

### What a new sighting does

- `resolved` → **reopens** to `open`. A fix that did not hold must not stay
  green because somebody once ticked a box; this is the single most important
  transition in the model.
- `false_positive` → stays. The identity is the rule plus the location, so the
  same identity really is the same judgement; reopening it every run would make
  the status useless and teach people to ignore the list.
- `accepted_risk` → stays **until the waiver expires** (below).
- anything else → unchanged, `last_seen_at` moves.

## Waivers expire, and expiry is evaluated when you read

A waiver carries three things, all required: **who approved it**, **why**, and
**when it lapses**. There is no indefinite waiver — accepted risk that never comes
back is a permanently disabled check with better manners.

**Expiry is computed at read time, never by a job.** The collector has no
scheduler, and a status that only becomes correct when a cron runs is a status
that is quietly wrong between runs. A waiver whose date has passed reports the
finding as `open`, with the lapse stated, and nothing had to run for that to be
true.

## This is not a second definition of accepted risk

`guardana baseline` already waives findings, with an approver, a reason and an
expiry. The fields here are deliberately the same, and so is the rule that an
expired waiver stops waiving. What differs is **scope, and it is stated in both
places**:

| | `guardana baseline` | collector waiver |
|---|---|---|
| Changes the build's exit code | **yes** | **no** |
| Lives | next to the code, in git | in the collector, shared by the team |
| Answers | "should this pipeline fail today" | "did anybody decide anything about this" |

The collector never tells an agent what to do — an agent that asked a server
whether to fail would be a gate with a network dependency, and a gate that fails
open when the network does. Deferred, and worth doing: exporting a project's
collector waivers **as** a baseline file, so a decision recorded centrally can be
applied locally without being retyped.

## Addressing a finding on the command line

Identities are `sha256:…` and nobody types those. Every command takes a **unique
prefix**, like git. An ambiguous prefix is refused with the candidates listed —
never resolved to the first match, because acting on the wrong finding is worse
than being asked to type four more characters.

## Migration

`0006` creates `tracked_findings` and back-fills it from what is already stored:
`select distinct project_id, identity from findings join submissions …`, every row
`open`, first and last seen taken from the occurrences. A collector that has been
running for months therefore arrives with its history intact rather than an empty
triage list.

The down migration drops the table, which loses statuses and waivers — stated in
the migration itself, because that is a real cost and the operator should meet it
before running the command, not after.

## What this deliberately does not include

- **No comments or discussion.** That is a ticket system's job, and every team
  already has one.
- **No per-status permissions.** There are no users yet; a key that may read may
  also triage, which is honest for a collector whose credentials are per project.
  RBAC lands with the team-platform milestone.
- **No notification on reopen.** Webhooks are their own item; inventing a
  half-integration here would be the thing people have to work around later.
