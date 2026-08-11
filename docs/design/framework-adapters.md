---
title: "Framework adapters"
nav_order: 20
summary: "the framework translators into that model, why a capability is probed rather than assumed, and the one field three frameworks proved was missing"
status: implemented
---

# Framework adapters: translators into the model, and the field they found missing

**Status:** accepted, implemented — ships in the next release · **Written:** 2026-08-10 · **Step four**

## The problem, stated precisely

`Trace` landed in 0.14.0 as the model for an execution Guardana did not conduct.
Its shape was decided by two inputs — a JSONL dialect written for it, and the
OpenTelemetry GenAI semantic conventions read against the published registry.
Two inputs, one of which Guardana wrote itself, is not enough evidence to freeze
an API on. 1.0 entry criterion 2 says so in as many words: three unrelated
inputs, **at least two of them independent framework adapters**.

This step supplies them, and it is the last one that may still change the shape.
Principle 14 is explicit that freezing the wrong model is worse than freezing
late, so an adapter that cannot express what its framework records is not an
adapter problem — it is a finding about the model, and the finding below is
exactly that.

There is a second, more immediate reason. Six rules require `CALL_TOOLS`, and the
one adapter that shipped could not offer tools, so every team probing a LangChain
model got six skips and a coverage note. A skip is honest; six of them, on the
checks that grade agency, is a hole. Closing it is the highest-value item in this
step and it goes first.

## What an adapter is, and the two shapes it takes

The 0.12 contract stands unchanged and is restated because everything below obeys
it: **the framework is never imported**, an object that does not fit is refused
when the target is built, no runtime dependency is added, and a reply this build
cannot read is an `EndpointError` rather than an empty string.

What is new is that there are now two things an adapter can do, and no framework
does both equally well:

| Shape | What it does | What it needs from the framework |
|---|---|---|
| **Driver** — `*_target()` | wraps the object as an `EndpointTarget` so `probe` sends prompts to it | a text-in/text-out call that takes plain Python types |
| **Translator** — `*_trace()` | turns the framework's own record of a run into a `Trace` | an accessible record of what happened |

The driver verifies the application by *asking it questions*. The translator
grades the answers it already gave. They are complementary, and criterion 2 asks
for the second — which is why this document leads with translation and treats
driving as the part that happens to be free when a framework's entry point takes
a `str`.

## What these frameworks actually expose

Every shape below was read by installing the library in a throwaway environment
and printing its dataclasses, not from memory or documentation. The versions are
recorded because a mapping written against a moving surface should say which
surface it met.

**pydantic-ai 2.27.0.** `AgentRunResult.all_messages()` returns an alternating
list of `ModelRequest` and `ModelResponse`, each carrying `parts` with an
explicit `part_kind` discriminator: `system-prompt`, `instruction`,
`user-prompt`, `text`, `thinking`, `tool-call`, `tool-return`, `retry-prompt`,
`file`. `ModelResponse` also carries `model_name`, `provider_name`, `usage` and
`finish_reason`. This is the closest thing to `Trace` anybody else has built, and
the mapping is nearly one to one.

**llama-index-core 0.14.23.** `Response` carries `response`, `source_nodes` and
`metadata`; each `NodeWithScore` carries `node_id`, `score`, `metadata` and
`get_content()`. `BaseRetriever.retrieve()` and `BaseQueryEngine.query()` both
accept a plain `str`. `LLM.chat()` does **not** — it requires the framework's own
`ChatMessage`, and a dict raises `AttributeError`. So LlamaIndex is reachable
without an import through retrieval, and only through retrieval.

**crewai 1.15.14.** `CrewOutput` carries `raw`, `tasks_output` and `token_usage`.
Every `TaskOutput` carries `description`, `name`, `raw`, `messages` (plain dicts)
and — the field this step turns on — **`agent: str`**, non-optional, naming which
agent produced that output.

**langchain-core 1.5.3.** `convert_to_openai_tool` accepts a plain OpenAI-shaped
`dict`, so `bind_tools` needs no framework type. `convert_to_messages` accepts a
whole conversation as dicts including `{"role": "assistant", "tool_calls": [...]}`
and `{"role": "tool", "tool_call_id": ...}` — the `(role, content)` tuple form the
0.12 adapter used cannot express either, and raises `KeyError: 'tool_call_id'`.
`AIMessage.tool_calls` is a list of plain dicts.

## The finding: the model cannot say who acted

CrewAI names an agent on every task output. OpenTelemetry has carried
`gen_ai.agent.name` and `gen_ai.agent.id` since the conventions settled, and
[`trace-domain-model.md`](trace-domain-model.md) lists them in its own table of
what Guardana reads. **It did not read them.** There is no field on `Span` to
read them into, and no rule could have noticed, because a rule cannot miss a
field that does not exist.

A single-agent trace does not care. A multi-agent one is unreadable without it: a
crew of three agents over twenty steps has two handoffs and eighteen spans whose
actor is recorded by the producer and dropped by us. `Handoff` records the
transition, not the actor — asking it who ran step eleven is asking a doorway who
is in the room.

Three ways out were considered.

**Put the agent name in `Span.name`.** Rejected. `name` is what the step *did*;
CrewAI's natural name for a task is its description. Overloading one string with
two facts is the escape hatch the model was built without, wearing a different
hat — and a rule that had to parse an actor out of a free-text name would be
reading a convention, not a field.

**Reuse `Identity`.** Rejected, and it is the same mistake `SessionRef` exists to
prevent. An agent name is not a credential, an audience or a claimed resource. A
crew whose agents are named would suddenly satisfy the `IDENTITY` dimension and
`session_as_identity` would stop declining on traces that carry no authentication
at all. Naming is not authenticating.

**Add `Span.agent: AgentRef | None`.** Taken. Two fields, `name` and `id`,
matching what OTel carries and what CrewAI reports, in its own file like every
other concept here. It costs a schema version, which is the point of having had a
migration seam at v1 rather than the reason not to use it.

### The rule that makes it load-bearing

A field with no reader is decoration, so the field arrives with the check it
enables: **`guardana.trace.handoff_authority_expansion`** — an agent handing work
to another agent *with more scope than it was itself carrying*. The delegating
agent's authority is on its `Delegation`; the authority crossing the boundary is
`Handoff.carried_scopes`; `Span.agent` is what ties the two to the same actor
across spans. Without the field the rule cannot be written, which is the test of
whether a field belongs.

It declines without `HANDOFF` and `DELEGATION` both, and it declines when
`carried_scopes` is `None` — "we did not record what crossed" is not "nothing
crossed", exactly as `Consent` already reads its own tri-state.

### trace-v1 → trace-v2

`TRACE_SCHEMA_VERSION` becomes 2. `schemas/trace-v2.schema.json` is published and
`trace-v1.schema.json` stays published, because a schema is a contract with
whoever already built against it.

`migrate_header` grows its first real step. A v1 header carries no `agent` on any
span and migrating it means exactly that — the field is absent, not empty, and a
v1 trace read by a v2 build declares the same dimensions it always did. The
migration invents nothing, which is the only kind of migration that is safe to
run on somebody's evidence.

A v2 document read by a v1 build is still refused loudly by the check that has
been there since v1. That is the half of versioning that protects the reader who
did not upgrade.

## What each adapter declares, and why never more

This is where an adapter can do the most damage, and the rule is one sentence:
**an adapter declares a dimension only when the framework actually reports it.**

The temptation is precisely the opposite. Declaring `APPROVAL` would make
`unapproved_side_effect` run instead of skip, and a run with more rules executing
looks better in a report. It is a false green with extra steps: the rule would
grade an absence the framework was never able to record, and fire on every
well-governed application whose instrumentation is quieter than ours. The
[capability mechanism](trace-domain-model.md) only works if the declaration is
true.

| Adapter | Declares | Because | Silent on |
|---|---|---|---|
| **pydantic-ai** | `MESSAGES`, `TOOLS` | typed parts, tool calls and tool returns are in `all_messages()` | everything authorization-shaped |
| **llama-index** | `MESSAGES`, `RETRIEVAL` | `source_nodes` is a real retrieval record with per-document identity and score | tools, identity, approvals, effects |
| **crewai** | `MESSAGES`, `HANDOFF` | task outputs name their agent, and consecutive tasks are the handoff | tools (the framework runs them out of band), everything authorization-shaped |

Three adapters, three different halves of the model, and none of them able to
answer for the other two. That is a better proof that the shape generalises than
three adapters that all populate the same fields would have been.

**`RETRIEVAL` becomes a capability.** `Dimension.RETRIEVAL` had no entry in
`TraceTarget`'s dimension table, because nothing needed it. `Capability.READ_RETRIEVAL`
is added with the rule below, through the same table, so a producer that does not
record retrieval stops the retrieval rule from running exactly as it stops the
others.

### Two traps the frameworks set, and how each is refused

**A session id is not an identity, and a run id is not either.** PydanticAI hands
out `conversation_id` and `run_id`. `conversation_id` maps to
`Span.conversation_id`; `run_id` becomes the trace id. Neither becomes an
`Identity`, and neither makes `IDENTITY` instrumented.

**CrewAI's "delegation" is not `Delegation`.** CrewAI calls agent-to-agent task
passing delegation, and `Agent.allow_delegation` is about that. Guardana's
`Delegation` is an authorization hop: who acts, on whose authority, across which
boundary, with which credential. Mapping one onto the other would make every crew
with `allow_delegation=True` declare the `DELEGATION` dimension and hand
`credential_passthrough` a trace with no credentials in it. CrewAI's delegation
is a `Handoff`. The word is the same and the concept is not, which is the most
common way a translator lies.

## Tool calling, and why the capability is probed rather than assumed

`bind_tools` exists on every LangChain chat model and raises `NotImplementedError`
on the ones that cannot do it. So neither branch of the obvious check is right:
`hasattr` says yes for a model that will refuse, and assuming refusal skips six
rules against models that would have worked.

The adapter therefore **binds a probe tool once, at construction**, and reports
`CALL_TOOLS` only if that succeeded. Binding sends nothing — it returns a bound
runnable — so the check costs no request and no token, and it happens before the
run rather than on the first prompt of a probe, which is the same rule the 0.12
adapter already followed for `invoke`.

A model that refuses keeps working for every text rule, and `guardana target
inspect` says tool calling is unavailable rather than leaving an operator to
infer it from six skips. `fail_on_skipped` still turns those skips into an
indeterminate result for anyone who wants it that way.

The conversation moves from `(role, content)` tuples to dicts for the reason
measured above: the tuple form cannot carry a tool call or a tool result, so an
agentic rule replaying its own history through it would raise mid-run. Text-only
behaviour is unchanged, which the existing tests pin.

**A tool double is offered, never executed.** `ToolSpec` carries a name and a
description, and the OpenAI-shaped dict built from it declares an empty parameter
object. Guardana offers tools to see what a model *asks for*; it does not run
them, and a framework's real tool is never bound in its place.

## Retrieval: the deterministic slice, without a live target

The roadmap's RAG item asks for `RetrieverTarget`, `CorpusTarget` and
`EmbeddingTarget`. They are not here — see the deferral table — but one check
does not need them, and the model was built for it in 0.14: `Retrieval` carries a
`tenant`, and so does every `RetrievedDocument`, specifically so a disagreement
between the two is expressible.

**`guardana.trace.cross_tenant_retrieval`** — a retrieval performed for one
tenant returned a document belonging to another. Deterministic, no judgement, no
request. `LLM09:2026`, `ASI06:2026`, `LLM02:2026`.

Declines: without `RETRIEVAL`; and on any retrieval where the query tenant or
every document tenant is absent, because a comparison with one side missing is
not a comparison. That decline is not a formality — a corpus that records no
tenant at all is the common case, and reporting "no cross-tenant retrieval found"
over it would be the exact false green this project exists to refuse.

Retrieval-time *injection* stays deferred for the reason
[`trace-domain-model.md`](trace-domain-model.md) already gave: without a sink,
"the agent then did something" is a judgement, and a judged rule shipped without
calibration is the opposite of what this project sells.

## Cost

Principle 2 holds unchanged. A translator walks the framework's record once and
builds a `Trace`; the rules then read spans already in memory, so the seventh
rule over a trace costs a pass and not a re-read. The tool-calling probe is one
`bind_tools` call at construction — no request, no token, no network.

Binary content is described and not carried, as the model requires: a PydanticAI
`FilePart` becomes a `Blob` with its media type, size and digest, and the bytes
are dropped before anything can put them in an evidence field.

## Rejected options

**A common `FrameworkAdapter` base class.** Tempting, and it would have forced
three genuinely different surfaces into one shape whose least common denominator
is `str`. The adapters share a contract, not an interface; the contract is
enforced by tests that every adapter must pass, which is where a shared
expectation belongs when the implementations have nothing structural in common.

**Importing the frameworks in tests only.** It would make the fixtures obviously
faithful, and it would put four fast-moving stacks — crewai alone installs 135
packages — into a security tool's test environment, where any of them could break
a release. The shapes were verified by running the real libraries during design,
which is where that evidence belongs; the tests use doubles built from what was
observed, and this document records the versions so the next reader can repeat
the check rather than trust it.

**A `crewai_target()` driver.** `Crew.kickoff(inputs=...)` takes a dict whose keys
are the placeholders of that specific crew's task templates. A driver would have
to guess them, and a guess that misses produces a crew answering a prompt nobody
sent — a probe that grades the wrong conversation while reporting confidently.
Deferred with that reason rather than shipped with a `input_key` parameter nobody
can set correctly without reading their own templates.

**Deriving `EFFECTS` from tool names.** A framework that records `send_email`
running is not a framework that records an email being sent. `ToolExecution.mutates`
is a tri-state for this reason and `None` stays `None`.

## Deliberately deferred, with the reason

| Deferred | Why |
|---|---|
| **`RetrieverTarget`, `CorpusTarget`, `EmbeddingTarget`** | A live retriever is a target that *sends* — its own budget surface, its own safety ceiling, its own threat model for who owns the corpus being written to. Folding three targets into the release that changes the trace schema would give neither its own tests. The deterministic trace-side check ships here so the model's `tenant` fields are exercised rather than asserted |
| **Retrieval-time injection, tenant-filter bypass, document and metadata poisoning** | Each needs either a live retriever to send to or the sink-aware work to say what "the agent obeyed" means. Stated as a gap rather than approximated with a judged rule |
| **A `crewai_target()` driver** | `kickoff()` takes the crew's own template placeholders; see the rejection above |
| **A LlamaIndex `LLM` driver** | `LLM.chat()` refuses a plain dict and requires the framework's `ChatMessage`, so driving a LlamaIndex model means importing LlamaIndex. The query engine is reachable without one and is the surface a RAG application actually deploys |
| **Tool calling through PydanticAI and CrewAI** | Both own their tool loop: an `Agent` calls its tools itself rather than reporting what it would call, so there is no seam to offer a double into. Their adapters translate the loop after the fact, which is what the trace rules grade |
| **Grading an adapter-built trace with the driven-run evaluators** | Unchanged from 0.14: `as_trajectory` makes it possible, and an evaluator calibrated on runs Guardana drove has not been measured on traces it did not |
| **A stable target ref for an in-process trace** | `TraceTarget.ref` is `source#trace_id`, and a framework's run id changes every run, so `diff` sees a new target each time. This is the same property a file-based trace already has, and fixing it means deciding what identifies "the same execution twice" — an `AISystem` question, not an adapter one |

## What this leaves for 1.0

Entry criterion 2 is met: raw JSONL, the OpenTelemetry conventions, and three
independent framework adapters, of which two are structurally unlike the first
input and unlike each other.

Criterion 1 — no framework-specific escape hatch — survived contact with three
frameworks and cost one field. `Span.agent` is a named concept with a reader, not
a bag; there is still no `attributes` dict on `Span`, and the fact that CrewAI
forced a *field* rather than a *bag* is the evidence that the constraint is doing
its job.

## Related

- [`trace-domain-model.md`](trace-domain-model.md) — the model these translate
  into, and the honesty boundary every one of them obeys.
- [`../integrations.md`](../integrations.md) — how a team wires an adapter up.
- [`../usage-analyze-trace.md`](../usage-analyze-trace.md) — grading a trace an
  adapter wrote.
- `ROADMAP.md`, *Next — the adapters, as translators into the model*.
