# `guardana target inspect` — what an endpoint really supports

"OpenAI-compatible" describes a URL shape, not behaviour. A gateway can accept a
`tools` array and never call anything; a proxy can drop the system message. Either
one turns a rule into a check that runs, proves nothing, and reports a pass.

```bash
guardana target inspect --url https://api.example.com --model gpt-4o-mini
```

```text
endpoint https://api.example.com#gpt-4o-mini

  ✓ chat: supported — replied with text
  ✓ plant_system_prompt: supported — the system message reached the model
  ? call_tools: unknown — the endpoint accepted the tools array but returned no
    tool call: the model may have declined, or the gateway may be ignoring tools
  ✓ usage_metadata: supported — the endpoint reports token counts

⚠ declared but not confirmed: call_tools
  rules relying on these would run and prove nothing, which reads as a pass

4 rule(s) cannot run against this target:
    • guardana.agent.credential_exfiltration
    ...

This inspection cost 3 request(s).
```

## Declared versus verified

A target *declares* capabilities from what its client can do. Inspection reports
what the endpoint actually **demonstrated**. The gap between the two is the point
of the command:

- **supported** — a probe confirmed it.
- **unsupported** — a probe showed it is not there.
- **unknown** — the probe ran and settled nothing. Never folded into
  "unsupported": "it does not do this" and "we could not find out" call for
  different decisions.

Anything declared and not confirmed is listed under *declared but not confirmed*,
including the unknowns. A capability nobody could demonstrate is one no rule
should be trusted to exercise.

## Failing a pipeline on missing coverage

```bash
guardana target inspect --url ... --model ... --require chat,call_tools
```

Exits `2` if any named capability was not confirmed — indeterminate, because
nothing was established about the system under test, only about the pipe to it.

## Skipped rules now say why

A run records, for each rule that did not execute, the reason and the capability
that was missing:

```json
"rules_skipped": [
  {
    "rule_id": "guardana.agent.tool_argument_scope",
    "reason": "missing_capability",
    "missing": ["call_tools"],
    "detail": "https://api.example.com#gpt-4o-mini does not support call_tools, ..."
  }
]
```

A bare list of ids could not tell a rule that never applied from one the provider
cannot support. Most skips are ordinary, so they do not fail the gate by default.
When you are paying for coverage you expect to get, turn that on:

```yaml
fail_on:
  fail_on_skipped: true
```

The run then reports `indeterminate` rather than passing — a real finding still
outranks it, because a fact somebody has to fix should not be buried under a
warning about coverage.

## What it costs

Three requests, stated in the output. An inspection is cheap next to a probe, and
a team paying per token is entitled to know the price of every command.

## See also

- [`usage-plan.md`](usage-plan.md) — what a full run would cost
- [`usage-probe.md`](usage-probe.md) — the run itself
