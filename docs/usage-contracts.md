---
title: "Security contracts"
nav_order: 100
summary: "**security contracts**: your application's own invariants — tenant boundary, required approval, allowed scopes, credential boundary, forbidden sink — as a versioned file the engine compiles into rules"
status: stable
---

# Security contracts — your application's threat model, executable

Built-in rules cover the risks everyone shares. What is dangerous in *your* system
depends on your data, your tools, your permissions and your business logic, and no
public framework knows any of that.

A **security contract** is a file your team keeps in its own repository, saying
what the application is allowed to do. Guardana compiles it into ordinary rules and
grades a recorded execution against it — deterministically, offline, with the same
evidence semantics as the built-ins.

```bash
guardana analyze-trace run.jsonl --contract checkout.yaml --ai-system checkout-agent
```

## A contract

```yaml
schema_version: 1
name: checkout
applies_to:
  ai_system: checkout-agent

assertions:
  - id: one-tenant-per-run
    type: tenant_boundary
    title: A single execution serves a single tenant
    severity: critical

  - id: never-shell
    type: forbidden_sink
    title: The checkout agent has no business running a shell
    severity: critical
    sinks: [shell, code_execution]

  - id: refunds-need-a-human
    type: approval_required
    title: A refund is approved by a person before it goes out
    severity: high
    actions: ["payment.*"]
    approvers: ["human:*"]

  - id: no-token-to-the-open-web
    type: credential_boundary
    title: Nothing we send to the public web carries a credential
    severity: critical
    boundaries: ["https://*.public.example/*"]

  - id: payment-scopes
    type: allowed_scopes
    title: The payments hop may only move money
    severity: high
    boundaries: ["https://pay.example/*"]
    allow: ["payments.*"]
```

Each assertion becomes a rule with the id `contract.<name>.<assertion-id>`, so a
profile can exclude one with a glob and a baseline can waive one without waiving
the rest.

## The five assertion kinds

| `type` | The invariant it proves | Evidence it needs |
|---|---|---|
| `tenant_boundary` | one execution stayed on one tenant, and every document it read belongs to that tenant | `retrieval` |
| `approval_required` | an action in scope happened only after an approval was **granted** | `approval` + `effects` |
| `allowed_scopes` | a hop across a named boundary exercised only scopes on the allow list | `delegation` |
| `credential_boundary` | a named boundary never received a credential at all | `delegation` |
| `forbidden_sink` | no side effect landed on a sink the application forbids | `effects` |

### `tenant_boundary`

Wider than the built-in `guardana.trace.cross_tenant_retrieval`, which compares one
retrieval against the documents it returned. An agent that retrieves for tenant A
and then, three steps later, for tenant B breaks no single retrieval — and whether
a run is *allowed* to serve two tenants is a fact only you know.

- `sources: [glob]` — limit it to certain stores. A selector that matches no
  retrieval **declines** rather than passing: a store glob is free text, and
  nothing at load time can tell `kb://*` from a typo.

### `approval_required`

Granted, not merely recorded: `denied`, `timed_out` and `not_requested` are each
the absence of authority.

- `actions: [glob]`, `sinks: [name]` — narrow what needs approval.
- `approvers: [glob]` — who may grant it. An approval whose approver nobody
  recorded makes the check **inconclusive**, not a finding: it may have been the
  right approver.
- Approvals recorded on the *same* step as the effect count. A span has no internal
  order, and one decision is commonly one span.
- Only `executed` and `attempted` effects need authority. A `failed` one changed
  nothing, and the refusal is the control working.

### `allowed_scopes`

Graded on what the hop **exercised**, not on what its credential *carries*. A token
minted with five scopes and used for one is a well-behaved hop.

- `boundaries: [glob]`, `allow: [glob]` — `allow` is required and may not be empty.
- A hop whose scopes the producer did not record makes the check inconclusive:
  reading "not recorded" as "none exercised" would pass every framework that omits
  the field.

### `credential_boundary`

- `boundaries: [glob]` — required. These must receive no credential at all.
- If **no** delegation anywhere in the trace records a credential, the check
  declines: this producer may not record them, and reading that as "no credential
  was sent" would be a quiet fail-open.

### `forbidden_sink`

- `sinks: [name]` — required, and checked against the closed sink list at load, so
  a typo cannot become a sink that never matches. One of `sql`, `shell`,
  `filesystem`, `http`, `messaging`, `email`, `payment`, `cloud_api`,
  `code_execution`, `other`.
- `actions: [glob]` — narrow it further.
- `statuses: [executed|attempted|failed]` — defaults to `executed` and `attempted`.
  An agent stopped mid-reach still reached; a `failed` effect is the system
  refusing, so counting it would report every working guardrail.

## Four outcomes, and only one is exit `0`

This is the part worth reading twice. A contract that could not be checked and a
contract that held used to look identical.

| Situation | Verdict | Exit |
|---|---|---|
| the contract applies and every invariant holds | pass | `0` |
| an invariant does not hold | fail | `1` |
| the contract needs evidence this producer does not record | **indeterminate** | `2` |
| contracts were loaded and none of them was about this execution | **indeterminate** | `2` |
| the contract names an AI system and you gave no `--ai-system` | refused | `3` |
| the contract file is missing or malformed | refused | `3` |

**An assertion you wrote is coverage you are paying for.** So a dimension it needs
and the producer does not record makes the run indeterminate with no `fail_on_*` in
front of it — `fail_on_skipped` defaults to off, and without this the default path
for "your contract could not be checked" would be a green build.

Use [`guardana trace inspect`](usage-trace-inspect.md) to see which dimensions a
producer records before you write assertions that depend on them.

**Excluding an assertion withdraws what it demanded.** `rules.exclude:` matching a
compiled rule id switches that assertion off *and* stops the run requiring the
evidence it would have read — and the exclusion is printed, so a green report never
reads as "your invariant held". `trace.require:` behaves the opposite way and is
meant to: it is a demand you stated outright rather than one implied by a check, so
it stands whether or not a rule wants the dimension.

## What your framework can actually prove today

Measured, not estimated — against a real run from each adapter, not a fixture:

| Producer | Dimensions it records | Assertion kinds it can grade |
|---|---|---|
| **pydantic-ai** 2.27 | `messages`, `tools` | none of the five |
| **llama-index** 0.14 | `messages`, `retrieval` | `tenant_boundary` |
| **crewai** 1.15 | `messages`, `handoff` | none of the five |
| **OpenTelemetry GenAI** | whatever your instrumentation emits | whatever it emits |
| **Guardana native** | whatever you write | all five |

So four of the five kinds — `approval_required`, `allowed_scopes`,
`credential_boundary`, `forbidden_sink` — decline against every framework adapter
that ships today, because no framework records approvals, delegations or side
effects on its own. **Contracts are for a team that instruments its own agent**:
emit Guardana's native dialect, or add the dimensions to an OpenTelemetry exporter,
or take `--write-trace` output and fill in what your framework left out. The
declines are the feature working — an assertion graded against evidence nobody
recorded would be the false green this whole mechanism exists to refuse — but they
are also why writing a contract before you have instrumented anything buys a run
that can only ever be `indeterminate`.

## `applies_to` — saying "not mine" without saying "fine"

```yaml
applies_to:
  ai_system: checkout-agent
```

Matched against `--ai-system`, which `analyze-trace` already takes and never
guesses.

- **not set** — the contract applies to whatever you point it at.
- **set and matching** — it applies.
- **set and not matching** — its assertions are recorded as *not applicable*.
  Nothing is missing, so it is not a coverage gap; it is also not a pass, and it is
  printed rather than dropped.
- **set, and no `--ai-system` given** — refused, exit `3`. A contract that cannot
  tell whether it applies must not report clean.

A team with one contract per agent can point all of them at every trace: as long as
**one** applies, the run proceeds. If none does, the run is indeterminate — that is
the wrong-file case, and it is the only way "not applicable" could become a silent
green.

## Loading contracts

```bash
# one file, repeatable
guardana analyze-trace run.jsonl --contract checkout.yaml --contract support.yaml

# a directory: every .yaml / .yml in it
guardana analyze-trace run.jsonl --contract ./contracts/
```

Or once, in `guardana.yaml`:

```yaml
name: production
contracts:
  - ./contracts/checkout.yaml
  - ./contracts/support.yaml
```

A path that does not exist, a directory with no contracts in it, and a file that
does not parse are all **exit `3`**, never a warning. A mistyped path would
otherwise run the built-ins, grade none of your invariants, and exit `0`.

## Versioning

`schema_version` is required, and a version this build has never heard of is
refused rather than read optimistically. Older versions migrate forward in memory
at load. There is no `contract migrate` command, deliberately: a saved run is
generated and Guardana may rewrite it, while a contract is hand-written and belongs
to you.

Unknown keys raise at load — including per-kind, so `sinks:` on a scope assertion
is caught rather than ignored. A gate you think you configured and did not is worse
than no gate.

## What a satisfied contract does and does not mean

It says: *in this recorded execution, these invariants held.* It does not say the
system is secure — the attacker's request may simply not be in the file. That is
the same bound [`usage-analyze-trace.md`](usage-analyze-trace.md) states for the
built-in trace rules.

Contract assertions send nothing. They grade a recording. Generated attacks aimed
at *breaking* an invariant are deliberately not part of this: the order is state
the invariant, prove it, and only then start generating traffic.

## A complete example

[`examples/contracts/checkout-agent.yaml`](../examples/contracts/checkout-agent.yaml)
ships all five kinds with the reasoning inline. It is not an illustration — a test
loads it through the real loader and compiles it, so a sample that stopped parsing
fails the build rather than teaching the schema wrong.

## Related

- [`usage-trace-inspect.md`](usage-trace-inspect.md) — what a producer records
- [`usage-analyze-trace.md`](usage-analyze-trace.md) — grading an execution
- [`design/security-contracts.md`](design/security-contracts.md) — why a contract is
  a third entity rather than a rule or a profile, and what was rejected
- [`profiles.md`](profiles.md) — `contracts:` and `trace.require:` in `guardana.yaml`
