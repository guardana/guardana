# Example integrator: shell hooks → a Guardana trace

The second worked answer to *how do I make the agent I already run produce a trace
Guardana can grade?* — see [`docs/writing-an-integrator.md`](../../docs/writing-an-integrator.md)
for the guide, and [`../hermes_integrator/`](../hermes_integrator/) for the first.

**It exists to be structurally different.** The other example is a plugin: one process
holds the session, a callback fires per event, and the writer keeps the file open for
hours. This one is a **command**. The agent spawns it with a JSON payload on stdin, it
appends one record, and it exits. The header, the spans and the footer are written by
processes that never see each other, and there is no variable anywhere that outlives an
event.

That is what makes it worth having. One example lets a contract be written around it;
the second is what shows the recording surface is general. Two things had to exist
before this one could work at all, and neither was obvious from the first:

- **`resume_trace`.** Opening a file for writing on every event truncates it, so a
  naive port of the plugin would leave one span per session under a header claiming the
  rest. `resume_trace` creates the file on the session's first event and continues it on
  every later one, refusing a producer whose declaration changed halfway through and a
  file that has already signed off.
- **A correlation store.** The approval arrives in one process and the effect it
  authorised in the next. [`pending.py`](src/guardana_trace_hook/pending.py) is the
  whole of it: a JSON object beside the trace, keyed by the `tool_call_id` both events
  carry, emptied when the session ends. This is the part of an out-of-process
  integration you have to get right, and it is why the shape is worth a separate
  example rather than a paragraph.

## This is an example, not an integration this project carries

**The envelope is `hermes-agent` 0.19.0's, read from the installed package on
2026-08-15**, and the same shape is what agents with Claude-Code-style hooks emit —
that dialect is one Hermes explicitly accepts on the response side. A later release of
any of them may change a payload, and then this stops working.

Nothing here imports `hermes-agent`; the payloads are copied. That is what lets the
tests run in CI without a green build depending on somebody else's release. Checking it
against the real thing is the manual step at the end of this page.

## It decides nothing, and it cannot

Every event it listens for is a `post_*` one, where the agent parses no block directive
at all. Nothing is written to stdout — that is the channel a directive would travel on,
so even a diagnostic goes to stderr instead. A recorder able to change what the agent
does would be inline enforcement wearing a hook's clothes, which is a standing non-goal.

When it cannot record, it exits non-zero and says why on stderr. Read from the bridge's
own source: a failing exit is logged as a warning and changes nothing else. That is the
trade to want — a lost span has to be visible somewhere, and the agent's behaviour is
not this recorder's business.

## Install and configure

```bash
pip install guardana-core ./examples/shell_hook_integrator
```

The hook reads three environment variables. Two are deliberately required and have no
default; the hook refuses to record without them:

| Variable | Required | Meaning |
|---|---|---|
| `GUARDANA_TRACE_DIR` | yes | where sessions are written, one file each |
| `GUARDANA_TRACE_DEFAULT_SINK` | yes | where an unmapped tool lands. `other` is a valid answer and a deliberate one; it is on no consequential list, so inheriting it silently would file "nobody classified this tool" under "this tool is harmless" |
| `GUARDANA_TRACE_SINKS` | no, empty by default | `terminal=shell,write_file=filesystem,send_email=email` — which of *your* tools reach where |

```bash
export GUARDANA_TRACE_DIR=traces
export GUARDANA_TRACE_SINKS=terminal=shell
export GUARDANA_TRACE_DEFAULT_SINK=other
```

A sink name this build does not know is refused rather than folded into `other`, for
the reason the trace reader refuses an unknown dimension: a typo becomes a sink no rule
matches, and a rule that never matches is a check that quietly stopped running.

Then point the agent at it. For Hermes, in `~/.hermes/config.yaml` — note that each
event takes a **list of hook definitions**, not a bare command string:

```yaml
hooks:
  post_approval_response:
    - command: /usr/local/bin/guardana-trace-hook
  post_tool_call:
    - command: /usr/local/bin/guardana-trace-hook
  on_session_end:
    - command: /usr/local/bin/guardana-trace-hook
```

`on_session_end` is not optional. It is the only event that writes the footer, and
without it every session reads as `unterminated` — which is correct, and which makes
every rule that found nothing decline instead of passing.

## What it produces

This is real output written by three separate processes driven through Hermes' own shell-hook
bridge. Without Hermes, you can send the same three events by hand, one process per event,
with the variables above exported:

```bash
guardana-trace-hook <<'JSON'
{"hook_event_name": "post_approval_response", "tool_name": null, "tool_input": null, "session_id": "", "cwd": ".",
 "extra": {"command": "rm -rf ./build", "surface": "smart", "choice": "smart_approve",
           "session_key": "sess_shell", "tool_call_id": "call-1"}}
JSON
guardana-trace-hook <<'JSON'
{"hook_event_name": "post_tool_call", "tool_name": "terminal", "tool_input": {"command": "rm -rf ./build"},
 "session_id": "sess_shell", "cwd": ".", "extra": {"status": "ok", "tool_call_id": "call-1"}}
JSON
guardana-trace-hook <<'JSON'
{"hook_event_name": "on_session_end", "tool_name": null, "tool_input": null, "session_id": "sess_shell",
 "cwd": ".", "extra": {"completed": true}}
JSON
```

Either way, `traces/sess_shell.jsonl` holds:

```jsonl
{"guardana_trace": 3, "instrumented": ["approval", "effects", "tools"], "producer": {"name": "guardana-trace-hook"}, "terminated": true, "trace_id": "sess_shell"}
{"approvals": [{"action": "terminal", "approver": "smart", "approver_kind": "automated", "outcome": "granted"}], "effects": [{"action": "terminal", "sink": "shell", "status": "executed"}], "identity": {"actor": "guardana-trace-hook", "session": {"id": "sess_shell"}}, "kind": "tool_execution", "name": "terminal", "span_id": "call-1", "tool": {"arguments": "{\"command\": \"rm -rf ./build\"}", "call_id": "call-1", "mutates": true, "name": "terminal", "status": "succeeded"}}
{"guardana_trace_end": 3, "spans": 1}
```

Graded against a contract saved as `shell-contract.yaml`, which requires a person for a shell
command:

```yaml
schema_version: 1
name: acme
assertions:
  - id: shell-needs-a-person
    type: approval_required
    title: A shell command is approved by a person before it runs
    severity: high
    sinks: [shell]
    approvers: ["human:*"]
```

```console
$ guardana analyze-trace traces/sess_shell.jsonl --contract shell-contract.yaml
read 1 span(s) from traces/sess_shell.jsonl as guardana (producer: guardana-trace-hook)
note: this producer does not record messages, retrieval, handoff, identity, delegation, consent, policy — the rules needing those dimensions were skipped rather than reporting nothing found. Set fail_on_skipped to treat that as indeterminate
contracts: 1 assertion(s) apply to this execution
✖ [HIGH] contract.acme.shell-needs-a-person — A shell command is approved by a person before it runs
    contract acme (shell-contract.yaml) requires 'terminal' to be approved by human:*; it was approved by automated:smart  (traces/sess_shell.jsonl#sess_shell/call-1)

1 finding(s); 3 rule(s) run, 7 skipped.
```

The command exits `1`: the finding fails the run.

The approval crossed a process boundary and still landed on the call it authorised —
and it still says a language model made the decision, not a person.

## Running the tests

They spawn the installed command with real payloads on stdin, because a test that
called `record()` in one interpreter would share the state this shape does not have and
would pass over a recorder that truncated the file every time.

```bash
uv run --isolated --no-cache \
  --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./examples/shell_hook_integrator --with pytest \
  pytest examples/shell_hook_integrator/tests -q
```

To check it against a real agent, install the version this example was written against
(`pip install "hermes-agent==0.19.0"`), register the hooks as above, and drive the bridge
directly:

```python
from pathlib import Path

from agent import shell_hooks
from hermes_cli.plugins import invoke_hook
from utils import fast_safe_load

config_yaml = Path("~/.hermes/config.yaml").expanduser().read_text(encoding="utf-8")
shell_hooks.register_from_config(fast_safe_load(config_yaml), accept_hooks=True)
invoke_hook("post_tool_call", tool_name="terminal", args={"command": "..."},
            status="ok", session_id="sess", tool_call_id="call-1")
invoke_hook("on_session_end", session_id="sess", completed=True)
```
