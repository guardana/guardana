---
title: "guardana analyze-trace"
nav_order: 80
summary: "`guardana analyze-trace`: grade an execution your agent already performed, from OpenTelemetry GenAI spans or Guardana's native dialect"
status: stable
---

# `guardana analyze-trace` — grade an execution that already happened

`analyze-trace` reads a recorded agent execution when you need to check what happened offline. `scan` reads files; `probe` talks to a live model.

```bash
guardana analyze-trace trace.jsonl
```

It opens one file and calls no model and no tool; it sends nothing over the network unless you pass `--reporter`.

## What it is for

Some failures cannot be reproduced from outside. The documents your retriever returned
were whatever the index held at 09:41. The memory already contained a note from Tuesday.
The credential that reached the third MCP server came from a delegation chain no prompt
can recreate. A trace is the only place those are visible.

## The one thing to understand first

**A trace records what your application chose to record.** That bounds what any verdict
over it can mean, and Guardana would rather say so than let you find out later.

When no approval appears before a payment, three worlds fit the file:

1. no approval was sought, and the payment went out unapproved — a finding;
2. an approval *was* sought and your framework does not emit approval spans — nothing
   wrong at all;
3. the trace was cut short before the approval was written — unknown.

A tool that reads that absence as world 1 fires on every well-governed system. One that
reads it as world 2 passes on the one system that really skipped it. So Guardana reads it
as neither: **a dimension your producer does not record makes the rules that need it not
run**, and the command says which ones and why.

```
$ guardana analyze-trace otel-export.jsonl
read 2 span(s) from otel-export.jsonl as otel (producer: opentelemetry)
note: this producer does not record identity, delegation, consent, policy, approval,
      effects — the rules needing those dimensions were skipped rather than reporting
      nothing found. Set fail_on_skipped to treat that as indeterminate
```

Two consequences worth stating plainly:

- A clean result means *in this recorded execution, these invariants held.* It does not
  mean the system is secure — the request that broke it may simply not be in the file.
- A trace that no rule can check exits `2` (indeterminate), not `0`. Nothing was
  verified, so "passed" is not a sentence that run is entitled to.

## Two dialects

| `--dialect` | What it is |
|---|---|
| `otel` | **OpenTelemetry GenAI semantic conventions.** What your instrumentation already emits. Read from OTLP/JSON and from an SDK file exporter, and from all three generations of the message convention (`gen_ai.input.messages`, the `gen_ai.*.message` events, and the deprecated `gen_ai.prompt`) |
| `guardana` | **The native dialect: OpenTelemetry's message shape plus named extensions** for identity, delegation, consent, policy decisions, approvals and side effects — the half the conventions have no field for |

The dialect is detected from the file's first record and **announced on every run**,
because getting it wrong yields a partial trace and a partial trace grades clean. Pass
`--dialect` to override.

## Adding the half your framework does not emit

The OpenTelemetry conventions carry the model-call half of the picture: messages with
typed content parts, tool calls, retrieval, memory, tokens, agents, MCP sessions. They
have **no field** for the credential a hop presented, the audience a token names, a
delegation boundary, a consent grant, a human approval, a policy decision or an external
side effect — which is where most of the interesting failures live.

`--write-trace` converts any export into the native dialect so you can add them:

```bash
guardana analyze-trace otel-export.jsonl --write-trace enriched.jsonl
# add the blocks your framework knows about but does not emit, then:
guardana analyze-trace enriched.jsonl
```

**The written file is a faithful copy, not a redacted one.** Redaction applies to
*evidence* — what leaves in a report, a SARIF file or a collector envelope — and a
trace being converted is input, not evidence. Redacting it here would change what the
rules then grade while the file still looked authoritative. So if the export contains
customer prompts, API keys in tool arguments or personal data, the converted file
contains them too, in a form that is easier to read than the one it came from. Write it
where the original already belongs, and keep it out of a repository.

## The native format

JSONL. The first line is a header; every later line is one span. The published schema is
[`schemas/trace-v3.schema.json`](../schemas/trace-v3.schema.json), and each line
validates against it independently. Older files still read: v2 added `agent` to a span
and v3 added `approver_kind` to an approval, so an older record simply does not carry
one.

```jsonl
{"guardana_trace": 3, "trace_id": "t-42", "producer": {"name": "acme-harness", "version": "2.1"}, "instrumented": ["messages", "tools", "identity", "delegation", "consent", "policy", "approval", "effects"], "terminated": true}
{"span_id": "s1", "kind": "model_call", "name": "chat gpt-4o", "agent": {"name": "support-agent"}, "messages": [{"role": "user", "parts": [{"type": "text", "content": "refund order 12"}]}], "consents": [{"client": "support-agent", "granted": true, "scopes": ["orders:read"], "subject": "u-9"}]}
{"span_id": "s2", "kind": "tool_execution", "name": "refund", "tool": {"name": "refund", "arguments": "{\"order\": 12}", "mutates": true}, "identity": {"actor": "support-agent", "session": {"id": "sess-1", "protocol": "mcp"}}, "delegations": [{"actor": "support-agent", "boundary": "agent->billing-mcp", "credential": {"kind": "bearer", "digest": "sha256:…", "audience": ["https://billing.internal/"]}, "scopes": ["orders:read", "orders:refund"]}], "effects": [{"sink": "payment", "action": "refund", "target": "order/12", "status": "executed", "reversible": false}], "approvals": [{"action": "refund", "outcome": "not_requested"}]}
{"guardana_trace_end": 3, "spans": 2}
```

Seven rules of the format, each with a reason:

**`instrumented` is what licenses a finding.** List the dimensions your producer really
records. Leave one out and its rules do not run — which is the safe direction. If you
omit the field entirely, Guardana derives it from what is present, and derivation can only
ever *reduce* what runs.

**Unknown keys are refused, at every level.** The header, its `producer`, each span and
every object inside a span — message, part, tool, retrieval, credential, approval, effect
and the rest — accept only the keys `schemas/trace-v3.schema.json` defines. Anything else
stops the read with exit `3`. A misspelled `aprovals:` would leave the approval dimension
declared and empty; a misspelled `aprover` or a part written `{"type": "text", "text": …}`
would read as a missing value. Either way a rule grades nothing, or accuses a system that
did nothing wrong. The shapes are held the same way: a value where the schema has an object,
a list or a list of strings must be one, every item of `messages`, `approvals`, `effects`
and the other lists must be an object, and every part names its `type`. `"approvals":
{…}` or a bare-string part stops the read naming the span, rather than reading as no
approvals or as text nobody typed. The `otel` dialect stays tolerant, because an
OpenTelemetry span carries attributes from other domains.

**Values are refused unless they have the schema's type and, for a list of choices, are
one of them.** Every field typed in `schemas/trace-v3.schema.json` must hold that type:
`"reversible": "false"`, `"terminated": "true"`, `"input_tokens": "12"` or a `null` stop the
read with exit `3`, naming the span and the field. A field with a fixed list of values —
a span's `kind`, a tool's `status`, a memory `action`, a credential's `kind`, an effect's
`sink` and `status`, a policy or approval `outcome`, `approver_kind`, the header's
`truncated` — accepts exactly the values the schema lists, in lower case: `"Shell"` and
`"bash"` are refused, never read as `other`. An effect's `sink` and a policy decision's or
an approval's `outcome` are required. Write `other` or `unknown` when that is what you
mean. Read leniently, `"sink": "Shell"` would reach no contract forbidding a shell, and
`"terminated": "true"` would withdraw the promise that makes a missing footer
`unterminated`.

**Credentials are named, never carried.** Write a `digest` if you have one. If you write a
`value`, Guardana hashes it on read and keeps only the hash — the model has no field to
put a token in. Nothing here reaches a report at any privacy level.

**`scopes: []` and no `scopes` key are different facts.** `[]` means the client was
granted nothing; omitting it means nobody recorded what was granted. The first is
checkable, the second makes the rule decline.

**An approval says whether a *person* granted it.** `approver_kind` is `human` or
`automated`, and there is no member for "unrecorded" — that is the field being absent. A
framework's own gate returning "approved" is `automated`; recording it as `human` would
satisfy a contract demanding human oversight while nobody ever saw the action. A
contract's `approvers` list globs `kind:approver` (so `human:*` keeps working, and now
means it), and an older file spelling the convention into the name — `"human:alice"` —
is read as the structure it always stood for.

**A file that is still being appended to says so.** See below.

### Saying where the file ends

A producer that appends to a live file cannot go back and amend its header, so a
session that died mid-run is otherwise indistinguishable from one that finished with
nothing to report — and every rule that found nothing reports a pass over an execution
it saw half of.

Set `"terminated": true` in the header and write a final
`{"guardana_trace_end": 3, "spans": N}` record. Then:

| The file | Reads as |
|---|---|
| header promises, footer present, count matches | complete |
| header promises, no footer | `truncated: unterminated` — the run is still going, or the producer died |
| header promises, footer counts more spans than the file carries | `truncated: records_lost` — something between the producer and here dropped lines |
| header promises nothing | complete, exactly as every file written before this existed |

The promise is opt-in on purpose. Reading every footerless file as truncated would
convert every trace anybody already has into a decline, which is a migration rather
than a safety improvement. A footer in a file whose header did not promise one is
refused: half a promise is worse than neither.

[`guardana.core.trace.open_trace`](writing-an-integrator.md) writes all of this for
you, and refuses the files that would grade clean over something real.

### Versioning

`guardana_trace` is the schema version. A version this build cannot read is **refused**,
not read as v1 — reading it anyway would drop the fields we do not know and grade what was
left, which is a partial trace reported as a whole one. A file with no version key is
refused too: guessing is how an unversioned format acquires a version in name only.

## What it checks

Nine built-in rules, plus whatever your own [security contract](usage-contracts.md)
asserts. One works on a plain OpenTelemetry export; the rest need the authorization
half.

| Rule | What makes it fire | Needs |
|---|---|---|
| `guardana.trace.secret_in_tool_argument` | a credential appears in a recorded tool argument | messages/tools |
| `guardana.trace.credential_passthrough` | one credential crossed two trust boundaries — the confused deputy | delegation |
| `guardana.trace.identity_disagreement` | a token's audience is not the resource it was presented to | identity |
| `guardana.trace.session_as_identity` | a step that changed something identified itself with a session and nothing else | identity |
| `guardana.trace.consent_scope_exceeded` | a hop exercised a scope no consent granted | consent |
| `guardana.trace.policy_decision_ignored` | a policy said no — or could not say — and the action happened anyway | policy |
| `guardana.trace.unapproved_side_effect` | a consequential effect executed with its approval denied or never sought | approval + effects |
| `guardana.trace.cross_tenant_retrieval` | a retrieval for one tenant returned a document belonging to another | retrieval |
| `guardana.trace.handoff_authority_expansion` | an agent exercised a scope wider than the handoff carried to it | delegation + handoff |

Full mapping to OWASP and MITRE ATLAS:
[the generated catalog](generated/rule-catalog.md).

## A truncated trace is not a shorter one

If the header says `truncated`, or the file exceeds a read ceiling, then a rule that
**found** something still reports it — the evidence is real — and a rule that found
nothing reports `inconclusive`, because the step it needed may be in the part that is
missing.

A record this build could not interpret — a line torn off by a producer that was
killed mid-write, or one over a size ceiling — has the same effect and is reported
separately, by line number. It does not cost the rest of the file: the execution around
it still grades, and a rule that found nothing in it declines rather than passing,
because the step it needed may be exactly the record that would not parse.

When *every* rule ends up there, the run exits `2`. A trace cut short before anything
gradable happened is a run that established nothing, which is the same outcome as a
trace no rule could read at all — it just arrives with a full rule count in front of
it. This matters more the more traces are produced by a live recorder, because a
session that ends when the process does is `unterminated` by construction.

## Options

| Option | Meaning |
|---|---|
| `--target SCHEME://LOCATOR` | Build a trusted installed trace target instead of reading the positional trace file |
| `--target-option KEY=VALUE` | Repeatable, non-secret configuration passed to that target |
| `--dialect guardana\|otel` | Override detection |
| `--write-trace PATH` | Also write the trace in the native dialect, whole: a failed write leaves an earlier file as it was and exits `3`. A `PATH` that is `--output`, its `<stem>.exchanges.jsonl`, or a file the command reads — the trace, `--profile`, a `--rules` or `--contract` file or one read from such a directory, or a file the profile names under `rules.paths`, `contracts:`, `calibrations:` or a judge's `adapter` — exits `3` before any rule is loaded or run |
| `--profile`, `--preset` | Policy, as for every other command — see [`profiles.md`](profiles.md) |
| `--format human\|json\|sarif\|junit` | `json` is what [`guardana diff`](usage-diff.md) reads; an [installed format](outputs.md) is named the same way |
| `--output PATH` | Save the run |
| `--reporter server://URL` | Forward findings to a collector, or to an [installed reporter](outputs.md) as `<name>://<locator>` |
| `--ai-system`, `--environment`, `--deployment-id` | What this trace came from. Never guessed |
| `--rules`, `--plugins`, `--allow-plugin` | Rule loading and plugin trust, as for `scan`: `builtins` unless the flag or the profile's `plugins:` says otherwise |
| `--contract PATH` | A [security contract](usage-contracts.md) to check this execution against; repeatable, and a directory loads every `.yaml` in it |

The trace file and `--target` are mutually exclusive, and `--dialect` applies
only to a file. A custom target must be a trace target and implement
`TraceReader`; otherwise the command refuses it before grading anything.

## Exit codes

The [same contract as every command](exit-codes.md). `2` is the one to expect from a
sparse trace: no rule could run, so nothing was verified.

Two more routes to `2` exist here and nowhere else, and neither can be switched off:
a dimension named in `trace.require:` (or needed by a contract assertion) that this
producer does not record, and a set of contracts none of which was about the AI
system you named. Run [`guardana trace inspect`](usage-trace-inspect.md) first to
see which dimensions the file actually carries.

## Saved runs

A run over a trace records `source.kind: imported_trace` in its manifest, so a dashboard
can tell a recording from a live check. It compares with `guardana diff` like any other
run, and the coverage fingerprint records which dimensions were available — so a diff
against a richer trace says the *reach* changed instead of reading the missing findings as
an improvement.

The run also records which bytes it read, under `run.target.document`. `digest` is SHA-256
over the first `bytes` bytes of the trace file, and `kind` is `content` when that is the
whole file or `content_prefix` when a read ceiling stopped the reader first. Check it with
`head -c <bytes> trace.jsonl | sha256sum`. An edit changes the digest even when the file
keeps its size. The digest sits beside the target fingerprint, not inside it, so a trace
re-recorded at the same path is still the same target for `diff`. A run saved before
schema 11 carries `document: null`: the digest was not recorded.

## Related

- [`usage-trace-inspect.md`](usage-trace-inspect.md) — what this file can answer at
  all, before anything grades it
- [`usage-contracts.md`](usage-contracts.md) — your own invariants, as a versioned
  file this command checks
- [`usage-import-observations.md`](usage-import-observations.md) — carrying another
  tool's results in as unverified claims
- [`usage-probe.md`](usage-probe.md) — verifying a live endpoint or MCP server instead
- [`privacy.md`](privacy.md) — what evidence keeps, and what the redactor removes
