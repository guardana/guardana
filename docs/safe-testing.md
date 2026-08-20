---
title: "Safe active testing"
nav_order: 40
summary: "before you point an active check at anything that matters"
status: stable
---

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

`probe --mcp` is narrower than that, deliberately. Against an MCP server Guardana
speaks only `server/discover`, `tools/list`, the `initialize` handshake where the
server still expects one, and unauthenticated `GET`s of the two authorization
discovery documents — it **never calls a tool**, because a tool call is a side
effect on somebody's system and no verification result is worth finding that out by
experiment. It also **declares no client capabilities**, so a server following the
`2026-07-28` Multi Round-Trip Requests pattern cannot ask it to run a model
completion or to prompt a human on the server's behalf: a server may only ask for
a capability the client declared, and Guardana declares none. It also refuses to fetch a discovery address that points
into the network running the scan or at the cloud metadata endpoint, and reports
the refusal as a finding rather than following it to be sure.

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
and duration budgets are hard ceilings: `--max-requests`, `--max-cost` and
`--max-duration` stop the run and report it as `indeterminate`, so an exhausted
budget can never be mistaken for a clean result. `guardana plan` prices the run
before it sends anything.

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

## See also

- [Threat model](threat-model.md) — including what a hostile endpoint can do to Guardana
- [Product status](product-status.md) — what is and is not covered
- [`docs/usage-probe.md`](usage-probe.md) · [`docs/usage-monitor.md`](usage-monitor.md)

## Declared impact, and what a run permits

Every rule declares how far it reaches, and every run declares how far it is
willing to let a rule reach.

| Impact | What it does |
|---|---|
| `passive` | reads only — a file scan, or reading a tool manifest |
| `active` | sends prompts to a model: costs money, appears in the target's logs |
| `side_effecting` | may cause the target to *act* — call a real tool, write to a real memory store |

```bash
guardana probe --url ... --model ... --safety passive   # send nothing
guardana probe --url ... --model ...                    # active, the default
guardana probe --url ... --model ... --safety side-effecting
```

`active` is the default because sending prompts is what a probe is for; a passive
default would make the ordinary command do nothing. `guardana scan` is passive
whatever this says — a file scan sends nothing.

**Nothing Guardana ships is `side_effecting` today, and that is a statement about
today rather than about the checks.** The agent rules drive Guardana's own harness
with its own tool doubles, so when a model "calls" a tool nothing outside the
process happens. The level is reserved for the case that changes it — evaluating a
trace from *your* agent, where the tools are real — because declaring it now would
label a risk that does not exist yet and devalue the label for when it does.

### Destructive is a separate switch

```bash
guardana probe ... --allow-destructive
```

A rule that can destroy or alter something the target owns never runs without
this, **whatever the impact ceiling says**. Two independent switches rather than a
fourth impact level, so raising one can never reach the other by accident.

Nothing shipped is destructive, and a test asserts it: if a built-in ever sets the
flag, that is a decision argued in a pull request rather than discovered by a user
whose `--allow-destructive` did something they did not expect.

### A rule refused for safety is reported, not dropped

It appears in `rules_skipped` with `reason: unsafe_mode` and a sentence naming the
flag that would permit it. A check that did not happen is a coverage gap whatever
the reason — and here the fix is a flag rather than a different provider, which is
what the reader needs to know.
