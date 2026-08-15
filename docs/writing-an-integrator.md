---
title: "Writing an integrator"
nav_order: 225
summary: "how to make the agent you already run produce a trace Guardana can grade, which dimensions your framework will not give you for free, and the one distinction to get right before anything else"
status: beta
---

# Writing an integrator

[`analyze-trace`](usage-analyze-trace.md) grades an execution that already happened.
This page is about the other end: **how the agent you already run produces a file worth
grading.**

You are in the right place if you run a self-hosted agent — your own harness, or a
framework with a hook system — and you want its production executions checked against
the same rules and [security contracts](usage-contracts.md) your CI already runs. You do
not need Guardana in your request path, and nothing here puts it there.

## Start here: the distinction that decides whether any of this is worth doing

An agent framework's own gate returning `approved` is **a policy decision by an
automated component**. A person looking at the action and agreeing to it is **human
oversight**. Recording the first as the second satisfies a contract demanding a human
while nobody ever saw the action — and that contract is usually the one somebody bought
this for.

So the model makes you say which:

```python
from guardana.core.trace import Approval

Approval.granted_by_human("alice@acme.example", action="payment.refund")
Approval.granted_by_automation("risk-policy-v4", action="payment.refund")
```

If your framework has an interactive approval prompt, that is a human. If it has an
allow-list, a guardrail, a risk score or a `pre_tool_call` hook returning `approve`,
that is automation — even when a person configured it. When you genuinely cannot tell,
leave `approver_kind` off entirely; an unrecorded kind makes the contract decline, which
is the answer you want over a guess.

## What your framework already gives you, and what it does not

A trace has eleven dimensions. Measured against a real run from every framework adapter
Guardana ships, the split is stark:

| Dimension | Where it usually comes from |
|---|---|
| `messages`, `tools` | your framework's existing tracing, or its LLM client |
| `retrieval`, `memory`, `handoff` | your framework, if it has those concepts at all |
| `identity`, `delegation`, `consent`, `policy`, **`approval`**, **`effects`** | **you** |

The bottom row is the point. The OpenTelemetry GenAI conventions have no field for any
of it, so no exporter emits it, so a trace shaped for reliability is silent about
authorization. The two in bold are the ones that turn a clean-looking file into a
finding, and they are the two your hooks have to supply.

## Declare what you record — and only what you record

```python
from guardana.core.trace import Dimension, SinkKind, SinkMap, open_trace

with open_trace(
    session_dir / f"{session_id}.jsonl",
    trace_id=session_id,
    producer="acme-app",
    producer_version="1.4.0",
    instrumented=[
        Dimension.MESSAGES,
        Dimension.TOOLS,
        Dimension.IDENTITY,
        Dimension.APPROVAL,
        Dimension.EFFECTS,
    ],
    sinks=SinkMap(
        {"refund": SinkKind.PAYMENT, "terminal": SinkKind.SHELL, "send_email": SinkKind.EMAIL},
        default=SinkKind.OTHER,
    ),
) as trace:
    ...
```

`instrumented` is a **promise**, and it works in both directions.

Leave a dimension out and its rules do not run — the safe direction, and how you start:
declare `messages` and `tools` on day one, add `approval` and `effects` when the hooks
that supply them exist.

Overstate it and you get a check that runs on nothing. This is not theoretical, and it
is not symmetric between dimensions: declaring `approval` and never writing one makes
the rules **decline**, while declaring `effects` and never writing one produces
`✓ No findings.` and exit `0` over an execution that moved money. The measurement is in
[`docs/design/trace-producer.md`](design/trace-producer.md). It is also why the writer
refuses to record a tool call the producer marked `mutates: true` without an effect
beside it — the file that grades falsely clean is one you cannot write.

The writer also refuses a block for a dimension you did *not* declare. A reader drops
those silently, so one typo in the list would remove your whole authorization coverage
while every other signal about the run looked normal.

## The sink map is yours, because the engine knows no vendor

Guardana cannot know that your `terminal` tool is a shell — by design; it encodes no
vendor and no framework. You declare it, and `default` is required so that falling back
to `other` is a decision with your name on it rather than something that happens by
omission.

Two consequences worth knowing before you pick a default:

- an unmapped tool your producer marked `mutates: true` is **refused**, because `other`
  is on no consequential list and recording it there would file "nobody classified this
  tool" under "this tool is harmless";
- everything else that falls through is recorded and **counted**. Read
  `trace.unmapped_tools` at the end of a session and you get the list of tools nobody
  classified, from your own run rather than from an auditor.

## Writing spans from your hooks

One method. Build a `Span` from whatever your hook handed you and pass it; the writer
fills in the effect a recorded tool call implies, validates the record by reading it
back through the real parser, and appends it to the file before returning.

```python
from guardana.core.trace import (
    Identity, SessionRef, Span, SpanKind, ToolExecution, ToolStatus,
)

def on_tool_finished(call, result, approval_decision):
    trace.span(
        Span(
            span_id=call.id,
            kind=SpanKind.TOOL_EXECUTION,
            name=call.tool_name,
            tool=ToolExecution(
                name=call.tool_name,
                call_id=call.id,
                arguments=call.arguments_json,
                status=ToolStatus.SUCCEEDED if result.ok else ToolStatus.FAILED,
                mutates=call.tool_name in WRITES,
            ),
            identity=Identity(actor=call.agent_name, session=SessionRef(id=call.session_id)),
            approvals=(approval_of(approval_decision),),
        )
    )
```

`mutates` is a tri-state and it is worth getting right: `True` and `False` are claims,
and `None` means nobody said. A rule that needs to know reads `None` as unknown rather
than as read-only.

Write the span when the call **finishes**, not when it starts. A span records what
happened; a span written at the start would record an intention, and an effect that
never landed is not a consequence.

## Ending the session, and admitting when you did not

A file being appended to by a live agent cannot go back and amend its header, so a
session that died mid-run looks exactly like one that finished with nothing to report —
and every rule that found nothing then reports a pass over an execution it saw half of.

`open_trace` writes `"terminated": true` into the header, which is a promise to sign
off. Leaving the `with` block cleanly writes the footer. **An exception does not**, and
that is deliberate: the file is then read as `truncated: unterminated`, every rule that
found nothing declines, and that is the truth about that session. A crash that never
runs `__exit__` leaves the same file.

Nothing in your hooks has to know about this. What it costs you is that you must not
swallow the exception around the writer just to make the file look tidy.

## Check your work by running it

Grade the file you just produced and **read the note**, not only the verdict:

```console
$ guardana analyze-trace sessions/2026-08-15T09-41.jsonl
read 14 span(s) from sessions/2026-08-15T09-41.jsonl as guardana (producer: acme-app)
note: this producer does not record retrieval, handoff, delegation, consent, policy —
      the rules needing those dimensions were skipped rather than reporting nothing
      found. Set fail_on_skipped to treat that as indeterminate
```

That line is your coverage report. Every dimension it names is a rule that did not run.
`guardana trace inspect` ([usage](usage-trace-inspect.md)) shows the same thing as an
evidence matrix, per assertion, which is the faster way to find out that the contract
you care about cannot be checked yet.

A run that reports `0 finding(s); 1 rule(s) run, 8 skipped` is not a passing agent. It
is an agent nobody has looked at.

## What an integrator is not

**Not an enforcement point.** The writer records; it decides nothing. A helper that
asked Guardana whether an action is allowed would be inline enforcement wearing a
library's clothes, and it is a standing non-goal. Guardana is never in your request
path.

**Not a required dependency of your agent.** The contract is the published file format
([`schemas/trace-v3.schema.json`](../schemas/trace-v3.schema.json)), and this writer is
a convenience over it. A team emitting the same JSONL from Go or TypeScript is a
first-class producer with no Python anywhere. If the writer's refusals are useful to
you, take them; if you write your own emitter, take the four rules in
[the format reference](usage-analyze-trace.md#the-native-format) instead.

**Not somebody else's problem to keep working.** A worked example lives in
[`examples/`](../examples/), pinned to the upstream version it was written against. It
is an example rather than an integration this project carries: a later release of that
framework may break it, and it deliberately stays out of CI, because a green build here
must never depend on somebody else's release.
