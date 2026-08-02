# Safe active testing

`guardana scan` reads files and cannot break anything. `guardana probe` and
`guardana monitor` send real requests to a real system, and that deserves a page
of its own before you point either at something that matters.

## What an active run actually does

It sends adversarial prompts to your endpoint and grades the replies. Concretely,
that means it:

- **consumes tokens**, which on a paid endpoint costs money;
- **may trip abuse detection** — a burst of jailbreak attempts looks exactly like a
  burst of jailbreak attempts to a provider's safety systems;
- **writes to agent memory** where a rule tests memory poisoning, because that is
  the check;
- **reads whatever your tools return**, including production data if your tools
  reach production;
- **changes MCP server state** if a tool you exposed has side effects.

## What Guardana never does

**Guardana does not execute your tools.** When a rule offers a model a
`delete_file` tool, the call is answered by a double — a scripted stand-in that
returns text. Nothing is deleted. This is not a setting; it is how the trajectory
engine is built, and it is why a security test can safely offer a destructive tool.

**Guardana is never in the request path.** It does not proxy, intercept or block
your users' traffic. If something needs to be stopped in production, Guardana is
the wrong layer.

**Guardana sends nothing anywhere else.** No telemetry, no account, no phone-home.
The only network traffic is to the target you configured — plus your judge and your
collector, if you configured those.

## The gap that remains, stated plainly

Guardana simulates the tool. **Your deployment might not.** If the model under test
is wired to real tools by its own application — and it is a production agent, so it
probably is — then a prompt Guardana sends can cause that application to take a
real action. Guardana did not execute the tool; the system under test did.

This is why the recommendation is not "Guardana is safe" but:

> **Probe staging.** Probe production only when you understand what its tools do.

## Practical guidance

**Use a staging deployment with the same configuration.** Same model, same system
prompt, same tool manifest, non-production credentials and data. A security verdict
from staging transfers; a production incident does not.

**Point tools at a sandbox.** If you must exercise a production-shaped agent, give
it tool endpoints that write to a scratch environment.

**Bound the run.** Concurrency is bounded (`--concurrency`, default 4 for probe)
and rate limits are retried with backoff rather than hammered. Request, token, cost
and duration budgets arrive in **v0.7** — until then, size the run by choosing a
profile, not by hoping.

**Run deep checks on a schedule, not on every pull request.** A fast static gate
belongs in a PR. Endpoint probing belongs at deployment time and nightly. This
keeps cost predictable and stops a noisy check from blocking every merge.

**Watch the evidence.** Findings can quote model output, which can quote your data.
Evidence is redacted by default; enabling full evidence is a decision to make
deliberately — see [privacy and redaction](design/privacy-and-redaction.md).

## Reading a result honestly

A probe that reports zero findings has **not** told you the model is safe. It has
told you that these checks, with this evaluator, at this confidence, did not find
these problems on this run. A model is a probabilistic system: the same prompt can
land differently next time.

That is the whole reason `guardana diff` exists — a single run is a snapshot, and
the question worth gating on is whether the snapshot got worse.

## Coming in v0.7

Rules will declare their impact, so a policy can select by it:

```yaml
impact: passive | active | side_effecting
destructive: false
estimated_requests: 3
```

with `--safety passive|active` and an explicit `--allow-side-effects`, destructive
checks never running by default, and every attempted action reported as
**simulated**, **proposed** or **executed**. See the [roadmap](../ROADMAP.md).

## See also

- [Threat model](threat-model.md) — including what a hostile endpoint can do to Guardana
- [Product status](product-status.md) — what is and is not covered
- [`docs/usage-probe.md`](usage-probe.md) · [`docs/usage-monitor.md`](usage-monitor.md)
