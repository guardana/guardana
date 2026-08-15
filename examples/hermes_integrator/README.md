# Example integrator: Hermes → a Guardana trace

A worked answer to *how do I make the agent I already run produce a trace Guardana can
grade?* — see [`docs/writing-an-integrator.md`](../../docs/writing-an-integrator.md) for
the guide this stands under.

It is a Hermes plugin. It registers four hooks, writes one JSONL trace per session, and
records the one thing no agent framework emits on its own: **who authorised a dangerous
action, and whether that was a person.**

## This is an example, not an integration this project carries

**Written against `hermes-agent` 0.19.0, read from the installed package on 2026-08-15.**
Hermes is somebody else's project and moves on its own schedule; a later release may
rename a hook or change a payload, and then this stops working.

`hermes-agent` is deliberately **not** a dependency of this package, and nothing here
imports it: the payloads are copied from its documentation and its source. That is what
lets the tests below run in CI without a green build here ever depending on another
project's release — what they pin is Guardana's writer seen from outside this repository,
not Hermes. Checking this example against the *real* Hermes is a manual step, described
at the end.

What Guardana keeps is the part that does not age: the published, versioned trace format
([`schemas/trace-v3.schema.json`](../../schemas/trace-v3.schema.json)) and the guide.
This directory is proof that the guide is followable.

## What it records, and what it refuses to claim

| Hermes | Trace |
|---|---|
| `on_session_start` | the header, declaring what this producer records |
| `post_approval_response` — `surface`, `choice` | an `Approval`: outcome, and **`human` vs `automated`** |
| `post_tool_call` — `tool_name`, `args`, `status` | a `tool_execution` span, and the effect its sink map implies |
| `on_session_end` | the footer, which is what says the session really ended |

Three decisions in there are worth more than the wiring:

**`surface: "smart"` is not a person.** Hermes has three approval surfaces: an
interactive CLI prompt, a gateway prompt, and *smart* mode, where an auxiliary LLM
auto-approves low-risk commands (`decided_by: "aux_llm"`). The first two are human
oversight and the third is a model deciding. Recording all three the same way would
satisfy an `approvers: ["human:*"]` contract while nobody ever saw the command.

**A tool with no approval record gets no approval record.** Hermes prompts only for
commands its dangerous-pattern detector matches, so most calls have no decision at all.
Writing `not_requested` for those would accuse the agent of skipping an approval its own
policy never asked for. Writing nothing lets Guardana decline instead — which is the
true answer, and the reason `guardana.trace.unapproved_side_effect` aggregates one
"outside the approval policy" line rather than firing.

**The header does not declare `identity`.** The spans carry an `identity` block and it
holds a session id and nothing else. A session id is not an identity; declaring the
dimension on the strength of one would let the session-as-authentication rule accuse an
agent whose authentication this recording never mentions.

## Install and enable

```bash
pip install hermes-agent guardana-core
pip install ./examples/hermes_integrator
```

Hermes finds pip-installed plugins through the `hermes_agent.plugins` entry-point group,
and entry-point plugins are opt-in. In `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - guardana
```

Traces are written to `$GUARDANA_TRACE_DIR`, defaulting to `./guardana-traces`. An
environment variable rather than plugin config, because this has to behave identically
under the CLI, the gateway and a kanban worker subprocess.

## What it produces

One line per record. This one is real — the plugin was loaded by Hermes' own plugin
manager and driven through `invoke_hook`:

```jsonl
{"guardana_trace": 3, "instrumented": ["approval", "effects", "tools"], "producer": {"name": "guardana-hermes", "version": "0.1.0"}, "terminated": true, "trace_id": "sess_real"}
{"approvals": [{"action": "terminal", "approver": "smart", "approver_kind": "automated", "outcome": "granted"}], "effects": [{"action": "terminal", "sink": "shell", "status": "executed"}], "identity": {"actor": "hermes", "session": {"id": "sess_real", "protocol": "hermes"}}, "kind": "tool_execution", "name": "terminal", "span_id": "call-1", "tool": {"arguments": "{\"command\": \"rm -rf ./build\"}", "call_id": "call-1", "mutates": true, "name": "terminal", "status": "succeeded"}}
{"guardana_trace_end": 3, "spans": 1}
```

Graded against a contract that says a shell command needs a person:

```console
$ guardana analyze-trace guardana-traces/sess_real.jsonl --contract shell-contract.yaml
read 1 span(s) from guardana-traces/sess_real.jsonl as guardana (producer: guardana-hermes)
note: this producer does not record messages, retrieval, handoff, identity, delegation,
      consent, policy — the rules needing those dimensions were skipped rather than
      reporting nothing found. Set fail_on_skipped to treat that as indeterminate
contracts: 1 assertion(s) apply to this execution
✖ [HIGH] contract.acme.shell-needs-a-person — A shell command is approved by a person before it runs
    contract acme (shell-contract.yaml) requires 'terminal' to be approved by human:*;
    it was approved by automated:smart

1 finding(s); 3 rule(s) run, 7 skipped.
```

`rm -rf ./build` ran because a language model said it looked fine. Nothing about the
agent changed between that run and a passing one — only which surface answered the
prompt — and that is the whole reason the approving actor is structural rather than a
naming convention.

Read the `note:` as well as the verdict. Seven rules did not run, and that is this
producer's coverage report.

## Running the tests

No Hermes needed — the payloads are copied from its documentation and its source, and
the tests drive `register()` with a stand-in context:

```bash
uv run --isolated --no-cache \
  --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./examples/hermes_integrator --with pytest \
  pytest examples/hermes_integrator/tests -q
```

`--no-cache` is not optional: uv otherwise serves a previously built wheel, and the
package metadata inside it — the entry point Hermes discovers — is exactly what a change
here touches.

To check it against the real thing, install `hermes-agent` too and drive its plugin
manager directly:

```python
from hermes_cli.plugins import discover_plugins, get_plugin_manager, invoke_hook

discover_plugins(force=True)
print(get_plugin_manager()._plugins["guardana"].hooks_registered)
# ['on_session_start', 'post_approval_response', 'post_tool_call', 'on_session_end']
```
