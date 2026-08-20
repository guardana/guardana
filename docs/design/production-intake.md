---
title: "Production intake"
nav_order: 23
summary: "why assessing production traffic has to be a second lane rather than a faster monitor, what an intake must refuse before it stores anything, and what has to exist before any of it is worth building"
status: proposed
---

# Production intake: assessing real traffic without being in its path

**Status:** proposed · **Written:** 2026-08-20 · **Horizon 2**

Not implemented. Written now because the shape of the measurement channel had to
be decided with this in mind, and because "we will add production monitoring
later" is the kind of intention that quietly turns into an inline guardrail.

## What `monitor` is, and what it is not

`guardana monitor` re-runs the same active probe on an interval and compares each
cycle with the first successful one, using the same definition of "worse" that
`guardana diff` uses. That is a genuine capability and it is **scheduled synthetic
testing**. It does not observe production traffic, it cannot see what real users
are doing, and it is not an inline control.

Two different things are therefore wanted, and the mistake would be to build the
second by loosening the first:

| Lane | Input | Timing | Cost |
|---|---|---|---|
| Active synthetic | prompts Guardana sends | on a schedule, inside a budget | money and requests against the target |
| Passive assessment | traffic the system already served | asynchronous, sampled | none against the target; storage and workers instead |

They must stay separate lanes with separate queues, because they fail differently
and because merging them is exactly how "assessment" ends up on the request path.

## The hard constraint

**Zero measurable overhead on the production request path.** Not "low", not
"asynchronous where possible": nothing Guardana does may be reached from the code
that answers a user. A system under test that gets slower because it is being
verified has been changed by the measurement, and the first person to notice will
turn the verification off.

That constraint decides the architecture on its own: telemetry leaves the
application by whatever exporter it already has, Guardana receives it out of
band, and everything else is a worker.

## What the receiver must refuse

An intake endpoint is the first thing in this project that accepts unbounded input
from outside on a continuous basis. The refusals are the design:

- **redaction before the queue, and a second policy before durable storage.**
  Two passes, because the first is about what may be held in memory and the second
  about what may be written down. A single pass means one bug is a permanent leak.
- **bounded payloads, rate limits and idempotency keys.** A duplicate OTLP export
  must not double a measurement; a retry storm must not become a bill.
- **tenant isolation on the ingest path, not only on read.** The existing
  collector enforces this at the query boundary; an intake adds a write boundary
  that needs the same treatment and the same negative tests.
- **the schema version recorded per event.** The OpenTelemetry GenAI conventions
  are still marked `Development` and have moved before. A stored event that does
  not say which convention it was written against is unreadable the moment they
  move again.
- **an explicit content mode.** A deployment must be able to store *only*
  normalized features and hashes — no prompts, no completions — and still get
  aggregates. If that mode is an afterthought it will not exist.

## What is refused permanently

- **No inline blocking.** Guardana verifies and gates. A tool that is sometimes in
  the request path is in the request path.
- **No second trace store.** MLflow, Phoenix, Langfuse and Jaeger hold traces
  well. The plan is to reference and exchange, not to duplicate — an intake that
  stores a normalized assessment and a pointer is more useful and much cheaper
  than one that becomes a worse copy of a tool the team already runs.
- **No automatic replay against production.** Replaying a captured interaction is
  the strongest thing a trace makes possible and it is a deliberate, approved act
  against an approved target, never a background job.

## What has to exist first

In order, and none of it is optional:

1. **The assessment channel** — shipped in 0.22.0. Without it there is nothing to
   put on a queue: a stream of findings answers "is it broken" and not "is it
   getting worse".
2. **Suites and versioned datasets** — otherwise two aggregates over different
   samples are averaged into one number that describes neither.
3. **Statistical honesty** — minimum sample size, minimum effect, confidence
   bounds. An alert with none of those is a random-number generator with a
   pager attached.

## The exit criteria, written before the work

A production lane is done when all of these hold, and each is a way the honest
version differs from the easy one:

- losing telemetry is reported as a **blind spot**, never as an improvement;
- a duplicated export does not double an assessment;
- backlog depth and dropped samples are measured and alertable — an intake that
  silently drops under load reports a quieter system;
- under overload the production model sees **no** added latency;
- raw content can be switched off entirely while aggregates keep working;
- a regression can be attributed to a specific deployment and model revision;
- two external observability systems can exchange scores with Guardana.

## See also

- [`assessment-channel.md`](assessment-channel.md) — the record this lane would carry
- [`trace-domain-model.md`](trace-domain-model.md) — what a recorded execution has to contain to be gradable
- [`../usage-monitor.md`](../usage-monitor.md) — the active lane, as it exists today
