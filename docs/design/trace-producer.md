---
title: "Producing a trace"
nav_order: 15
summary: "why a producer needs an append-only writer rather than a serializer, which inflated declaration actually leaks a pass, and what the model has to gain before an integrator can record human approval honestly"
status: accepted
---

# Producing a trace: the writer, the declaration, and the approving actor

**Status:** accepted, implemented — ships in the next release · **Written:**
2026-08-15 · **Continuous verification, item 1**

## The problem, stated precisely

[`analyze-trace`](../usage-analyze-trace.md) grades an execution somebody else
recorded. [`trace-domain-model.md`](trace-domain-model.md) settled what a trace *is*
and, more importantly, what an absence in one is allowed to mean. This document is
about the other end of the pipe: **how the file gets written.**

Today there is exactly one way, `serialize_trace(trace) -> str`, and it renders a
finished `Trace` in a single call. That is the right shape for its stated job —
converting an export, so an operator can add the authorization dimensions their
framework does not emit — and the wrong shape for a producer. A production agent
emits one event at a time, inside a session that may run for hours, and the file has
to be useful if the process dies halfway through. A whole-trace serializer says: hold
everything in memory, and if you crash, you have nothing.

So the deliverable is an **incremental writer**. The five gaps below are not
ergonomics. Each one is a way a file can be written that makes a rule report a pass
it did not earn — which is the one failure this project exists against.

## What the measurement says, and one claim it corrects

The gap table in [`ROADMAP.md`](../../ROADMAP.md) states that an integrator declaring
`approval` while its hook never supplies one "makes the approval rules run and pass on
empty". That was written from the model rather than from a run. Four traces, graded by
the released engine, say otherwise — and they locate the leak somewhere else.

All four are the same execution: an agent refunds order 12 with no approval anywhere.

| | header declares | span carries | verdict |
|---|---|---|---|
| **A** | `approval`, `effects` | the effect, no approval | `unverified`, exit `0` |
| **B** | `approval`, `effects` | a `mutates: true` tool call, no effect, no approval | **`✓ No findings.`, exit `0`** |
| **C** | `approval`, `effects` | the effect *and* `not_requested` | `HIGH`, exit `1` |
| **D** | `messages`, `tools` | the effect *and* the approval | `✓ No findings.`, exit `0` |

**A does not pass.** `guardana.trace.unapproved_side_effect` declines, once, for the
whole trace: *"1 consequential effect(s) executed with no approval record covering
them (refund (payment)) — this trace records approvals, so this build cannot tell an
action outside the approval policy from an approval that was skipped."* The contract
assertion is stricter still: `approval_required` yields a **finding** when no granted
approval precedes an in-scope effect, so an inflated `approval` declaration produces a
false *red*, not a false green.

**B is the false green.** The same four rules ran as in A and C. Every one of them
concluded that nothing was found, the run exited `0`, and nothing anywhere said the
recording was thin. The dimension that leaks is `effects`, not `approval` — because
the effect-shaped rules *iterate the effects* and consult the approvals. An empty list
of approvals is a lookup that misses, and the code notices. An empty list of effects
is a loop that does not run, and there is nothing left to notice with.

That is the general shape, and it is worth stating as a rule of thumb for any future
dimension: **a declared dimension that drives a loop is the dangerous one; a declared
dimension that answers a question is not.** `effects` and `retrieval` drive loops.
`approval`, `consent`, `policy` and `delegation` answer questions about what a loop
found.

**D is the quiet one.** The producer wrote the approval and the effect correctly and
declared neither, so both were read, dropped and never graded. The evidence of an
unapproved refund is sitting in the file. This is the safe direction and it is still a
defect: one typo in a declaration list silently removes a producer's entire
authorization coverage while every other signal about the run looks normal.

Two conclusions follow, and they set the priorities below. The engine's honesty
machinery works where it was pointed — an absence in a *consulted* dimension already
declines. The writer's job is the part nobody has covered: a declaration that is held
against what was written, and the loop-driving dimensions in particular.

## Decision 1 — append-only, and termination is declared in the header

The header is written once, at `open`. Spans are appended, one JSON object per line,
flushed as they go. Nothing rewrites an earlier byte, because a file being appended to
by a live agent is also a file an operator may copy or grade at any moment.

That creates one problem worth solving properly. `truncated: unterminated` is the
reason a reader needs — "we stopped looking" rather than "nothing happened after this"
— and it lives in the **header**, which by then is already on disk and cannot be
amended. Three ways out:

| Option | Rejected because |
|---|---|
| Rewrite the header on clean close | it is no longer append-only, and a file grabbed mid-session is a file with a header being rewritten under the reader |
| A footer record on every file, absence ⇒ unterminated | every trace ever hand-written or produced by `--write-trace` becomes `unterminated` overnight, which converts a working corpus into a corpus of declines. A change that turns everybody's passing files into inconclusive ones is not a safety improvement, it is a migration nobody agreed to |
| **A footer, promised in the header** | chosen |

The header gains `"terminated": true`, meaning *this producer will write a footer, so
read its absence as truncation*. A file without the key behaves exactly as it does
today. A file with it and no footer reads as `truncated: unterminated`, and every rule
that found nothing declines rather than passing.

This is the same shape as `instrumented`, deliberately: a promise in the header that
licenses a stronger reading of what follows, and never a reading the producer did not
ask for.

**The footer carries a count, not only a full stop.** `{"guardana_trace_end": 3,
"spans": 17}`. A footer that said nothing but "I finished" would certify a file whose
middle a log shipper had dropped — a *new* claim of completeness that can be wrong,
introduced by the mechanism installed to remove a false green. A file whose span
records do not add up to the declared count reads as `truncated: records_lost`, which
is a separate reason from `unterminated` because the two point at different systems to
go and look at. Records the reader could not parse still count: those are already
reported as unreadable, and folding them in here would invent a shipping problem the
file does not have.

**`TraceTruncation.UNTERMINATED` has existed since 0.14 and nothing in the shipped
source has ever set it.** Only a hand-written header could produce it. The writer is
the first thing that will — which is the usual finding here, and the usual reason to
check the seam rather than the enum.

## Decision 2 — the writer refuses at the source

Unknown keys are refused on *read* today. A producer with a typo learns about it when
somebody finally grades the file, by which time the run it was supposed to cover is
gone. The writer closes that: every span is serialized and **read back through the
native parser before the line is appended**, and a span that does not survive the round
trip raises instead of being written.

This is a per-span parse on the write path, which is a real cost and a defensible one.
The producing application is already doing model calls; a span parse is orders of
magnitude below the event that produced it, and the alternative is losing evidence
permanently rather than slowly. It is also not a switch: an opt-out here would be a
fail-open flag on the only validation a producer gets, and this codebase does not ship
those.

The typed Python API already makes most invalid states unrepresentable — a `SinkKind`
is an enum, not a string. What the round trip catches is the class that survives
typing: a required field left empty, a value the parser rejects for a reason the
constructor does not know, and any future divergence between what `serialize_trace`
writes and what `_native.py` accepts. The round-trip gate on persisted schemas exists
for exactly that divergence; this puts it on the writing path too.

## Decision 3 — an inflated declaration, and the honest limit of one session

`instrumented` is a promise, and the writer holds it in both directions. They are not
symmetric, and pretending they were would produce a check that fires on well-behaved
producers.

**Writing a block for an undeclared dimension is refused** (case D above). It is a bug
the integrator can fix in the line that caused it, the evidence would otherwise be
discarded in silence, and no legitimate producer needs it. Fail loudly on bad input.

**Declaring a dimension and never writing one is not decidable from a single
session.** An agent that made no tool calls genuinely produced no effects; a session
where nothing happened is a real session. A writer that refused to close such a file
would fire on every quiet hour of every correctly instrumented deployment, and a check
that fires on correct behaviour is a check somebody excludes.

What *is* decidable is a **contradiction inside the session**, and case B is exactly
one: a producer that declares `effects`, records a tool execution marked
`mutates: true`, and records no effect for it. That is not a quiet session. Decision 5
removes the case entirely rather than detecting it — once the sink map is the seam a
tool execution goes through, a mutating call cannot be recorded without its effect.

The rest of the question — *this producer has declared `approval` for six months and
has never once written one* — is a fact about a producer's history, not about a file.
It belongs with the fleet history in the continuous-verification milestone, next to the
already-deferred "a rule that declines on every target, release after release". Both
are the same missing capability, and neither is fixable by looking harder at one
document.

**Deriving `instrumented` from content is rejected for the same asymmetry.** Reading
"this file has no effects" as "this producer does not record effects" would stand the
rules down on every quiet session — which is why the field is a declaration and not a
measurement, and why the derivation the reader does for a header that omits the field
entirely can only ever *reduce* what runs.

## Decision 4 — the approving actor becomes structural (trace v3)

An agent framework's own gate returning "approved" is a policy decision by an
automated component. A person seeing the action and agreeing to it is human oversight.
Only the second one answers ASI09, and today the model cannot tell them apart:
`Approval.approver` is a free string, and the distinction lives in a documented
*convention* — `approvers: ["human:*"]` in
[`usage-contracts.md`](../usage-contracts.md) — which is a glob over text an integrator
types by hand. Nothing stops `human:auto-approve`, and nothing ever will; what a
structure stops is the integrator who was not thinking about it.

`Approval` gains `approver_kind`, a closed enum with exactly two members — `human` and
`automated` — alongside the existing identifier. There is deliberately no third member
for "unrecorded": that is the absent field, and a second spelling of it would be one
fact with two answers. The model offers two constructors and no default, so choosing
is the cheapest path and skipping is not a path at all.

The contract's `approvers` glob keeps its meaning by matching a **canonical
rendering**: `f"{kind}:{approver}"` when the kind is recorded, and the raw string when
it is not. So:

- a v3 producer writing `approver: "alice", approver_kind: human` matches the
  `human:*` that people already have in their contracts;
- a v2 file carrying `approver: "human:alice"` still matches it, unchanged;
- a v2 file carrying `approver: "alice"` still matches whatever it matched before.

On read, a v2 `approver` whose prefix names a known kind is parsed into that kind —
which promotes the convention that is already documented into the structure that
enforces it, rather than inventing a second one beside it.

This is a **trace v3**: a new field, absent in older files, exactly as v2 added
`Span.agent`. The version ladder in `_native.py` carries a v2 header forward unchanged
and the span parser accepts both shapes, so no existing file changes meaning. Doing it
now is the cheap moment — principle 14 puts a complete domain model before any freeze,
and the population of external producers is about to stop being zero.

## Decision 5 — the tool-to-sink map belongs to the integrator, with no implicit default

The engine cannot know that a framework's `terminal` tool is a shell. It knows no
vendor, by principle 1. So the integrator declares the map, and the writer turns a
recorded tool execution into a recorded effect through it.

The interesting question is the unmapped tool, and `SinkKind.OTHER` is a trap here:
`other` is deliberately on neither consequential list, so an effect recorded as `other`
is an effect no rule will ever fire on. Falling back to it silently would convert
"nobody mapped this tool" into "this tool is harmless", which is the same false green
this document opened with, one layer down.

So:

- the map has **no implicit default** — the integrator states one, and stating
  `other` is then a deliberate act with a name on it;
- a tool the producer marked `mutates: true` that has **no mapping** is refused at
  write time, because that is precisely the class where an unnoticed fallback costs a
  verdict;
- every unmapped tool name is collected and reported at `close`, so an integrator
  finds out from the run rather than from an auditor.

An effect of unknown kind is still an effect, and it is recorded as one. What is not
allowed is the absence of a record.

## The shape of the API

The contract is the file format; this is a convenience over it.

```python
from guardana.core.trace import Dimension, SinkKind, SinkMap, open_trace

with open_trace(
    path,
    trace_id=session_id,
    producer="acme-app",
    producer_version="1.4.0",
    instrumented=[Dimension.MESSAGES, Dimension.TOOLS, Dimension.APPROVAL, Dimension.EFFECTS],
    sinks=SinkMap({"terminal": SinkKind.SHELL, "refund": SinkKind.PAYMENT}, default=SinkKind.OTHER),
) as trace:
    trace.span(span_from_your_hook)
```

`open_trace` writes the header — including `terminated: true` — before the first span
exists, so a session that runs for hours is readable from the moment it starts. The
context manager writes the footer on a clean exit and *not* on an exception, because a
writer that tidied up after a crash would produce a file claiming to be complete over
an execution nobody saw the end of. A crash that never runs `__exit__` leaves the same
file, which is the point.

One method rather than two. An integrator hands over a `Span` built from whatever their
hook gave them, and the writer fills in the effect that a recorded tool call implies —
which is what makes the case in decision 3 unwritable rather than merely detectable.
`trace.unmapped_tools` names the tools that fell through the sink map, so the gap is
visible at the end of a run rather than at the end of an audit.

## What this is not

**Not a second SDK.** Guardana's contract is the published, versioned file format
(`schemas/trace-v3.schema.json`). Everything here is a convenience over it, and a team
emitting JSONL from Go or TypeScript stays a first-class producer — which is why every
decision above lands in the *format* first and the Python API second. A decision that
could only be expressed through the writer would be a decision those producers cannot
make.

**Not an enforcement point.** The writer records what happened; it decides nothing. A
helper that asked Guardana whether an action is allowed would be inline enforcement
wearing a library's clothes, and that is a standing non-goal. Nothing here runs in a
request path.

**Not an integration we carry.** The examples that come with this pin the upstream
version they were written against and state that a later release may break them. A green
build here must never depend on somebody else's release — which is a rule about
*dependencies*, not about directories: an example that never imports the framework it
integrates with, because its payloads are copied from that framework's own
documentation, runs in CI safely and pins this writer's API seen from outside the
repository. Checking one against the real framework is a manual step, recorded in the
example's README with the version and the date it was checked.

## Deferred, with the reason

| Deferred | Reason |
|---|---|
| Detecting a dimension declared and never written, across sessions | needs a producer's history, which is the fleet-history work in the same milestone. One session cannot tell a quiet hour from a hook that never fires |
| Rotation, size limits and multi-file sessions | a session that outgrows a file is a real operational problem and it is orthogonal to every decision here: the header/footer contract composes with a rotation scheme without changing. Deciding it now, with no producer running, would be inventing a shape from imagination |
| A structured approver for `consent` and `policy_decisions` | the same automated-versus-human distinction exists there, and it does not carry the same weight: a consent is by definition the subject's, and a policy decision is by definition automated. Adding a kind to both would be symmetry for its own sake |
| Async and thread-safe writing | an agent framework that calls hooks from several threads needs it, and none of the two worked examples does yet. A lock is easy to add and impossible to remove; the honest order is a real caller first |
