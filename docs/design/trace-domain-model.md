# The `Trace` domain model: grading an execution somebody else recorded

**Status:** accepted, implemented — ships in the next release · **Written:** 2026-08-09 · **Step three**

## The problem, stated precisely

Guardana verifies by *driving*: it sends prompts, offers tool doubles, reads
replies. `Trajectory` is the record of a run Guardana conducted, and every
agentic rule grades one. That is a strong position and it has one hard limit —
**it only sees the runs Guardana started.**

The interesting failures happen in the runs it did not. A production agent
handles a request, calls three MCP servers, reads two documents out of a vector
store, writes a note to memory, and sends an email. Nobody can reproduce that
from the outside: the retrieved documents were whatever the index held at
09:41, the memory already contained a note from Tuesday, and the credential
that reached the third server came from a delegation chain no prompt can
recreate.

What *does* exist is a trace. Every serious agent framework emits one, and since
the OpenTelemetry GenAI semantic conventions settled there is a shape they
broadly agree on. Grading a trace is the only way Guardana reaches the execution
that actually happened.

Principle 14 also puts this before 1.0: `Trace`, `AISystem` and `Deployment`
land before anything is frozen, because freezing the wrong shape is worse than
freezing late. Step two (MCP authorization) went first on purpose, and it paid
for itself — four distinctions arrived from meeting a real protocol that a schema
written from imagination would have flattened. They are in
[`mcp-authorization-depth.md`](mcp-authorization-depth.md) and each one is
represented below.

**What this is not.** Not a tracing SDK — Guardana does not instrument anybody's
application, and nothing here runs in a request path (a listed non-goal). Not a
Guardana wire protocol competing with OpenTelemetry. And not a passive traffic
tap: a trace arrives as a file, after the fact, by the operator's decision.

## The honesty boundary, decided first

This is the most important decision in the document, and it is not about which
checks to write.

**A trace records what an application chose to record.** That single sentence
governs everything below, because it breaks the inference every scanner wants to
make. When a trace shows no approval before a payment, there are three possible
worlds:

1. no approval was sought, and the payment went out unapproved — a finding;
2. an approval was sought and granted, and the framework does not emit approval
   spans — nothing wrong at all;
3. the trace was cut short before the approval span was written — unknown.

A rule that reads "no approval record" as world 1 fires on every well-governed
system whose instrumentation is merely quieter than ours. A rule that reads it as
world 2 passes on the one system that really did skip the approval. **Both are
false verdicts, in opposite directions, from the same absence.**

So absence is never read as evidence. Three states, and every check names which
one it is in:

| State | Meaning | What a rule may conclude |
|---|---|---|
| **recorded, present** | the dimension is instrumented and the record is there | grade it |
| **recorded, absent** | the dimension is instrumented and this step has no record | grade the absence — *this* is where a finding lives |
| **not instrumented** | the producer never emits this dimension at all | nothing; the rule does not run |

The third state is what makes the second one safe, and it is why this design
spends a capability on each dimension rather than a boolean on each record.

### The corollary, stated so no report implies otherwise

A clean trace analysis says: *in this recorded execution, these invariants held.*
It does not say the system is secure, and it cannot — the attacker's request may
simply not be in the file. That is a weaker claim than `probe` makes, and it is
stated in [`../usage-analyze-trace.md`](../usage-analyze-trace.md) rather than
left for a reader to infer.

## OpenTelemetry GenAI is the interoperability floor, not the domain model

Checked against the OpenTelemetry
[GenAI attribute registry](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)
and the
[GenAI semantic conventions repository](https://github.com/open-telemetry/semantic-conventions-genai)
on 2026-08-09. Reading them produced the single most useful finding in this
design.

**What the conventions carry, and Guardana therefore reads directly:**

| Convention | Guardana reads it as |
|---|---|
| `gen_ai.operation.name` (`chat`, `execute_tool`, `invoke_agent`, `retrieval`, `search_memory`, `upsert_memory`, `embeddings`, `plan`, …) | the span's kind |
| `gen_ai.input.messages` / `gen_ai.output.messages` — `[{role, parts:[…], finish_reason}]` | messages with typed content parts |
| part `type` = `text` (`content`), `tool_call` (`id`, `name`, `arguments`), `tool_call_response` (`id`, `response`) | `ContentPart` kinds |
| `gen_ai.system_instructions` | the system instruction parts |
| `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.response.model` | the model call |
| `gen_ai.usage.input_tokens` / `output_tokens`, `gen_ai.response.finish_reasons` | the call's cost and how it ended |
| `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.tool.description`, `gen_ai.tool.type`, `gen_ai.tool.definitions` | tool executions and tool offers |
| `gen_ai.agent.name` / `.id`, `gen_ai.conversation.id` | who acted, and which conversation |
| `gen_ai.data_source.id` | the retrieval source |
| `mcp.method.name`, `mcp.session.id`, `mcp.protocol.version`, `network.transport` | an MCP hop, and its session |
| `server.address` / `server.port`, `error.type` | the callee, and whether it failed |

**What they do not carry — and this is the finding:** there is no GenAI
convention for the credential a hop presented, the audience a token names, the
scopes in play, a delegation boundary, a consent grant, a human approval, a
policy decision, a memory write's provenance, an external side effect, or an
agent handoff. `mcp.session.id` is the closest thing to an identity in the whole
registry, and a session id is precisely *not* an identity — which is one of the
four things step two established.

So the authorization half of the domain — the half where the interesting failures
live — is **structurally absent** from an OTel-only trace. Two consequences, and
the design turns on both:

- **`Trace` is a superset of the conventions, not a rename of them.** Mapping
  OTel onto a model shaped like OTel would have produced a model that cannot
  represent the failures step two spent a release learning to name.
- **An OTel-imported trace declares those dimensions *not instrumented*.** The
  six rules below are then skipped by the runner, each with its reason, and
  `fail_on.fail_on_skipped` turns the coverage hole into an indeterminate result
  for anyone who wants it that way. What must not happen is the alternative: six
  rules finding nothing in a file that could not have contained it, and a report
  that reads clean.

### Rejected: a Guardana-only trace protocol

Tempting, because the model needs fields OTel does not have. Rejected: a format
nobody emits is a format nobody uses, and the whole value here is grading a trace
that already exists. The native JSONL dialect exists as the **superset carrier** —
what an operator writes when they want the authorization dimensions graded — and
it is defined as OTel plus named extensions, not as an alternative to it.

### Rejected: waiting for the conventions to grow the missing half

The conventions may one day carry identity. Waiting means the model that freezes
at 1.0 is shaped by a document still in flux, and it means the four distinctions
from step two go unrepresented in the meantime. When a convention does land,
adding a reader for it is a mapping change, not a model change — which is the
test of whether this layering is right.

## The four distinctions, made executable

Each came out of step two, each would have been flattened by a schema written
first, and each now has a field and a rule.

**Identity is three claims that can disagree.** `Identity` carries the credential
presented, the audience the token names, and the resource the callee claims to
be — separately, because the interesting failure is exactly where they diverge.
One `credential` field per call cannot express it.

**Delegation has a direction and a boundary.** `Delegation` records who is
acting, on whose authority, across which boundary, with which credential *on this
hop*. Token passthrough — deferred in step two as "not client-observable" — is
the same credential appearing on two hops that cross different boundaries. In a
trace it is observable, and it is rule 1 below. That is this step paying a
documented gap back.

**Consent is per client, not per user.** `Consent` is keyed on the client, with
the subject as a separate field. The confused deputy works because a decision
recorded against a user is read as a decision about a client, and a model with
`consents: dict[user, scopes]` cannot represent the bug at all.

**A session is not an identity.** `SessionRef` is its own type and never
substitutes for `Identity`. A step whose only identification is a session id is
rule 3.

## The model

Twelve concepts, one file each, under `guardana.core.trace`. The container is a
flat, ordered tuple of spans with parent links — the OTel shape — rather than a
tree, because a tree makes "what happened next" (the question every rule asks)
into a traversal, and because a flat list survives a producer that emits a parent
after its child.

```python
@dataclass(frozen=True, slots=True)
class Trace:
    trace_id: str
    spans: tuple[Span, ...]              # ordered as recorded
    provenance: Provenance               # who produced this, and a digest of the file
    instrumented: frozenset[Dimension]   # what the producer records at all
    truncated: TraceTruncation | None    # why it is incomplete, if it is
    unreadable: int = 0                  # records this build could not interpret
```

```python
@dataclass(frozen=True, slots=True)
class Span:
    span_id: str
    kind: SpanKind
    name: str
    parent_span_id: str | None
    # the model-call half — what OTel carries
    messages: tuple[Message, ...]
    system_instructions: tuple[ContentPart, ...]
    tool_offers: tuple[ToolDeclaration, ...]
    tool: ToolExecution | None
    retrieval: Retrieval | None
    memory: MemoryOperation | None
    handoff: Handoff | None
    # the authorization half — what OTel does not
    identity: Identity | None
    delegations: tuple[Delegation, ...]
    consents: tuple[Consent, ...]
    policy_decisions: tuple[PolicyDecision, ...]
    approvals: tuple[Approval, ...]
    effects: tuple[SideEffect, ...]
```

A span is the unit and the domain content hangs off it as optional blocks. The
alternative — a record type per concept, eleven of them in one JSONL stream — was
rejected because it duplicates ordering, parentage and timing eleven times, and
because it does not map onto an OTel span without inventing a join key.

### Typed content parts, and the multimodal carrier

`ContentPart` is what keeps a multimodal carrier from forcing a breaking change
later — the roadmap's stated reason for typing content at all. Kinds: `TEXT`,
`TOOL_CALL`, `TOOL_RESULT`, `IMAGE`, `AUDIO`, `VIDEO`, `DOCUMENT`, `REASONING`,
`REFUSAL`, `OPAQUE`.

Two rules about them, both fail-closed:

**Binary content is referenced, never carried.** An image part holds a media
type, a size, a URI or a digest — not the bytes. A trace with twenty base64
images would otherwise arrive in an evidence field and from there into a report,
a SARIF file and a collector envelope. Nothing in the redaction seam is shaped to
remove a megabyte of base64.

**A part kind this build does not know becomes `OPAQUE` and is kept.** Dropping
it is the fail-open: a text-reading rule over a trace whose payload was in a part
type we skipped would report clean on the one carrier that mattered. `OPAQUE`
records the producer's own type string, and a span carrying one is visible to any
rule that needs to decline.

### Dimensions, and why they are capabilities

`Dimension` names the parts of the domain a producer may or may not record:
`MESSAGES`, `TOOLS`, `RETRIEVAL`, `MEMORY`, `IDENTITY`, `DELEGATION`, `CONSENT`,
`POLICY`, `APPROVAL`, `EFFECTS`, `HANDOFF`.

`TraceTarget` translates the ones its rules depend on into capabilities —
`TRACE_IDENTITY`, `TRACE_CONSENT`, `TRACE_POLICY`, `TRACE_APPROVALS`,
`TRACE_EFFECTS` — and the runner does the rest, because it already skips a rule
whose target cannot satisfy it and already records the reason. This is the
`INSPECT_AUTHORIZATION` pattern from step two, reused rather than reinvented, and
it buys three things a boolean on the rule could not: the skip is in
`rules_skipped` with a reason, `fail_on_skipped` can escalate it, and the
manifest's coverage fingerprint records that this run checked less — so `diff`
against a richer trace says the reach changed instead of reading the missing
findings as an improvement.

**A declared dimension is believed; an undeclared one is derived from what is
present.** The native dialect declares explicitly. For everything else, a
dimension counts as instrumented when at least one record of it appears. That
derivation can only ever *reduce* what runs, which is the safe direction: a trace
with no consent records anywhere is indistinguishable from a producer that does
not emit them, and both correctly stop the consent rule from running.

### Truncation makes a silent rule speak

A trace cut off mid-execution is `Trajectory`'s truncation problem on somebody
else's data, and the answer is the same: a rule that **found** something in a
truncated trace reports it — the evidence is real — and a rule that found nothing
reports `inconclusive`, because the step it needed may have been in the part that
was cut. Silence has to keep meaning "the invariant held".

## Versioning and migration

`Trace` is a document a user keeps and a third party writes, so principle 11
applies: `schemas/trace-v1.schema.json`, `TRACE_SCHEMA_VERSION = 1`, and a
`guardana_trace` version on the header record of every native file.

Three decisions, because a first version is where migratability is designed and
not where it is exercised:

- **A version this build cannot read is refused, loudly.** A v2 document read as
  v1 would have its unknown fields dropped and be graded on what was left — a
  partial trace reported as a whole one. `TraceLoadError` names the version and
  the build.
- **The migration seam exists at v1**, shaped like the manifest's 1→2→3 chain, so
  a v2 reader is an added function rather than a rewritten one.
- **A missing header is an error, not a default.** Guessing v1 for a file with no
  version is how an unversioned format gets a version in name only.

`serialize_trace` writes the native form from any dialect. Its first job is a
test — the published schema and the reader cannot disagree if a round trip has to
validate — and its second is a real one: converting an OTel export into the
native dialect is how an operator adds the authorization dimensions their
framework does not emit.

## The six invariants

Each is deterministic, each maps to a public framework, and each exists because
the model carries a distinction that would otherwise be unrepresentable. Every
one names what makes it decline.

### 1. `guardana.trace.credential_passthrough`

*One credential crossed two trust boundaries.*

The token an agent received and the token it presents upstream must be different
tokens. The same credential digest on two `Delegation` hops with different
boundaries is the confused deputy, and it is the check step two deferred for
being invisible from outside. `MCP01:2025`, `ASI03:2026`, `LLM03:2026`.

Declines: without the `DELEGATION` dimension, and when fewer than two hops carry
a credential digest at all.

### 2. `guardana.trace.identity_disagreement`

*A token's audience is not the resource it was presented to.*

The three-field identity, read as three fields. A credential whose audience names
`https://a/` presented to a resource claiming to be `https://b/` is a token being
accepted — or offered — outside the audience it was minted for. `MCP01:2025`,
`ASI03:2026`.

Declines: without `IDENTITY`, and on any span where either the audience or the
claimed resource is absent — two thirds of a disagreement is not a disagreement.

### 3. `guardana.trace.session_as_identity`

*A step that changed something identified itself with a session and nothing else.*

The MCP specification forbids sessions as authentication in a sentence, and it is
not an MCP-only mistake. Fires on a span carrying a `SessionRef`, no credential,
and an effect or a state-changing tool execution. `MCP07:2025`, `ASI03:2026`.

Declines: without `IDENTITY`; and silent, deliberately, on a read-only span,
because an unauthenticated read is a different question with its own answer.

### 4. `guardana.trace.consent_scope_exceeded`

*A hop used a scope the client was never granted.*

Consent read per client, as step two established. Scopes on a delegation that do
not appear in any `Consent` for that client are privilege the user did not agree
to. `MCP02:2025`, `ASI03:2026`, `LLM03:2026`.

Declines: without `CONSENT`; and when a consent record exists whose scopes are
unknown rather than empty — "we did not record what was granted" is not "nothing
was granted".

### 5. `guardana.trace.policy_decision_ignored`

*A policy said no, or could not say, and the action happened anyway.*

Two shapes in one rule because they are two halves of one property — whether the
decision was load-bearing. A `DENY` followed by the action is a bypass. An
`ERROR` followed by the action is somebody else's fail-open, which is the failure
this whole project is named after, and it is reported at the same severity for
the same reason. `ASI02:2026`, `LLM10:2026`.

Declines: without `POLICY`; and on a decision whose subject action never appears
in the trace, because a decision about something that did not happen is not a
bypass.

### 6. `guardana.trace.unapproved_side_effect`

*An irreversible effect executed with its approval denied or never sought.*

The one rule that needs two dimensions — `APPROVAL` and `EFFECTS` — and the
clearest case for why absence must be tri-stated: run it against a trace that
does not record approvals and it fires on every payment any system ever made.
`ASI09:2026`, `ASI02:2026`, `LLM03:2026`.

Declines: without either dimension. An effect whose status is `ATTEMPTED` rather
than `EXECUTED` reports `inconclusive` — an attempt that may or may not have
landed is not an effect that did.

### Rejected: injection rules over retrieved content, in this step

`agent.tool_result_injection` already grades a driven run, and the trace
equivalent is the obvious next rule. It is not here, because the deterministic
form of "the agent followed the injected instruction" needs the retrieval and
sink-aware work that is its own roadmap item: without a sink, "the agent then did
something" is a judgement, and a judged rule shipped without calibration is the
opposite of what this project sells. The model carries `Retrieval` and
`SideEffect` so that rule is an addition, not a schema change.

## Third-party observations: somebody else's verdict, kept as theirs

Composition with promptfoo and garak was on the roadmap as the answer to a
landscape where "developer-centric security testing in CI" stopped being a
differentiator. The mechanism is narrow on purpose.

**An imported observation is a claim, not a finding.** It lands in `unverified`
with a `Verdict` of `inconclusive`, whose `evaluator_id` names the producer
(`imported:garak`). Guardana did not send the prompt, did not see the reply, and
cannot grade what it did not observe — so the report says who said it and stops
there. When Guardana can replay the same attack under its own contract, the
result of *that* is a finding.

**Provenance is kept whole**: producer, version, source file, the timestamp the
file states, and a digest of the bytes as read. A claim nobody can trace back is
a claim with no weight in an audit.

**Severity is carried when the producer stated one, and attributed.** Dropping it
loses what a triager needs; inventing one presents our opinion as measurement.
The evidence line names the producer, and `unverified` never fails a gate unless
an operator asks it to.

**One rule id per producer** (`imported.garak`, `imported.promptfoo`,
`imported.generic`) so a profile can exclude a producer with a glob and a
baseline can waive an individual claim — the finding fingerprint already covers
rule plus evidence summary, and the summary carries the foreign test id.

Three dialects, all verified against the producing code rather than from memory:

- **garak** (JSONL). `eval` records carry `probe`, `detector`, `passed`, `fails`,
  `nones`, `total_evaluated`. **`fails > 0` is a claim; `nones > 0` is garak
  telling us its own detector could not decide**, and an importer reading only
  `passed`/`total` folds those into passes. They are carried as a separate
  unknown, which is the same distinction Guardana makes about itself.
- **promptfoo** (JSON). `results[]` entries carry `success`, `score`, `error`,
  `testCase`, `gradingResult`, `metadata`. Two nestings exist in the wild
  (`results` as an array, and `results.results` beside an `evalId`); both are
  read and the file says which it was.
- **generic** — a documented shape for an internal harness, so composing does not
  require pretending to be one of the two above.

**A record that cannot be read is counted and reported, never dropped.** A
dropped record is a failed attack that disappears, which is a false green
arriving through the import path. Unreadable records become `errors`, and
`fail_on_error` — on by default — makes the run indeterminate.

## Cost: one parse, and the rules read

Principle 2, and the same seam as step two. `TraceTarget` parses the file once,
holds the `Trace`, and every rule reads it. A seventh rule costs a pass over
spans already in memory; it does not re-read the file. The reader is streaming
per line, so a large trace is bounded by its largest span rather than by the
file.

Nothing here sends a request, so both commands are offline by construction —
`analyze-trace` and `import-observations` open one file and no socket.

## Rejected options

**Making `Trajectory` into `Trace`.** They are different things and merging them
would have cost the distinction that matters: a `Trajectory` is an experiment
Guardana controlled, a `Trace` is a recording it did not. Every claim either one
supports depends on knowing which it is. `Trace.as_trajectory()` exists as a
one-way bridge, so the existing agentic evaluators can grade a recorded run — and
it is one-way because a `Trajectory` is not entitled to a trace's provenance.

**A new `TargetKind`.** Considered and taken: a trace is neither an artifact nor
an endpoint, and folding it into `ARTIFACT` would have offered every static rule
a JSONL file to fail to parse. `TargetKind.TRACE` keeps rule selection honest,
and `Surface` reads it as runtime evidence, because that is what it is.

**Reading a trace through the collector.** The collector ingests findings, not
traces, and the import contract is one direction only. A trace is a large
document full of raw prompts; routing it through a service would make the
privacy question about a network hop instead of about a file the operator chose.

**Taking an OpenTelemetry dependency.** The reader parses a JSON object with
`gen_ai.*` keys. Principle 6 puts a dependency in front of a justification, and
`opentelemetry-sdk` pulls a protobuf stack to read a shape that is four `dict`
lookups deep.

## Deliberately deferred, with the reason

| Deferred | Why |
|---|---|
| **The remaining named adapters — LlamaIndex, CrewAI, PydanticAI** | The roadmap's own reason, unchanged: three adapters written before the model bakes three frameworks' quirks into an API about to be frozen. They are translators into this model, and they are cheap once it is real. 1.0 entry criterion 2 asks for two independent adapters driving the model, so this is the criterion's remaining half — stated, not hidden |
| **OTLP over the wire** | A receiver is a service that listens, which is the continuous-verification milestone and a different security posture from reading a file. The mapping built here is what a receiver would reuse |
| **Metrics and logs from the conventions** | Only spans carry the message content and the tool calls rules grade. A metric says how many tokens were spent, which the manifest already records for runs Guardana drove |
| **Injection and sink rules over retrieved content** | Needs the retrieval and sink-aware output work; the model carries the fields so it is an addition rather than a schema change. See the rejection above |
| **Grading a trace against the driven-run evaluators** | `as_trajectory()` makes it possible and no rule does it yet: an evaluator calibrated on runs Guardana drove has not been measured on traces it did not, and `calibrate` is how that claim would be earned |
| **`finish_reason` on `Exchange`** | Deferred out of step one to be done "beside the trace work", and it is not here. A trace *carries* `gen_ai.response.finish_reasons` and the model records it; putting it on the live transport contract is a change third-party transports must follow, and doing it as a passenger to this step would give it no test of its own |
| **Replaying an imported trace** | The stated bar for turning a third-party claim into a finding, and it needs a target that can accept a recorded conversation as a script. `unverified` with provenance is the honest interim, and it is what the roadmap asked for |
| **Redacting a trace on the way in** | Evidence drawn from a trace goes through the same redactor as everything else, at the same seam. The *input file* is not rewritten, and an operator pointing this at a trace full of customer prompts should know the report is redacted and the file is theirs |

## What this leaves for 1.0

Entry criterion 1 — messages with typed content, retrieval, tool
offers/calls/results, identity and scopes, approvals, memory, side effects and
handoffs, with no framework-specific escape hatch — is met by the model above,
and the absence of an escape hatch is the part to keep checking: an `attributes`
free-for-all on `Span` would have made every later mapping easy and the freeze
meaningless.

Entry criterion 2 asks for three unrelated inputs. Two are here — raw JSONL and
the OpenTelemetry conventions — and they already disagreed usefully enough to
change the design once. The two independent framework adapters are the remaining
half.

## Related

- [`mcp-authorization-depth.md`](mcp-authorization-depth.md) — where the four
  distinctions came from, and what each one cost to learn.
- [`run-manifest-v2.md`](run-manifest-v2.md) — the run document a trace analysis
  writes, and why `source.kind` has said `imported_trace` since v2.
- [`../usage-analyze-trace.md`](../usage-analyze-trace.md) ·
  [`../usage-import-observations.md`](../usage-import-observations.md) — how an
  operator runs both.
- `ROADMAP.md`, *Next — the domain model, and only then the adapters*.
