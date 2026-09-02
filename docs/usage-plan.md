---
title: "guardana plan"
nav_order: 170
summary: "`guardana plan`: what a run would cost, before it costs anything"
status: stable
---

# `guardana plan` — what a run would cost, before it costs anything

Probing a hosted model costs money, and the number nobody could state before 0.7
was the upper bound. `guardana plan` states it, and **sends no request to do so**.

```bash
guardana plan probe --url https://api.example.com --model gpt-4o-mini
```

```text
14 rule(s) would run, 9 skipped.
requests: at least 14, at most 47

No request was sent to produce this estimate.
```

```bash
guardana plan scan .
```

```text
19 rule(s) would run, 0 skipped.
requests: 0 — every selected rule declares it sends nothing

No request was sent to produce this estimate.
```

A file scan of the built-in rules is free and complete: every one of them reads
files, never a model, and declares that about itself — see
[Where the numbers come from](#where-the-numbers-come-from). A third-party
artifact rule that stays silent about its cost is not assumed to be free; it
shows up in `unknown_cost` exactly like an undeclared endpoint rule would.

`--format json` gives the same numbers to a pipeline, with a `schema_version`.

## Flags

`plan scan` and `plan probe` both discover plugins to build the same registry the
run they are pricing would use, so both take the same plugin-trust flags
`scan`/`probe` do:

| Flag | Default | Meaning |
|---|---|---|
| `--plugins [all\|builtins\|allowlist\|disabled]` | `all` | Which installed plugins to load — same meaning as on `probe` |
| `--allow-plugin TEXT` | none | Distribution to trust; repeatable, needs `--plugins allowlist` |

`plan scan` also keeps `--no-plugins` as a deprecated alias for `--plugins disabled`,
exactly like `guardana scan` does.

## Where the numbers come from

Every rule declares an upper bound on the requests it will send
(`Rule.estimated_requests`): a YAML rule knows how many prompts it has, a
scenario how many steps, an agent rule its step budget. The plan sums the rules
the profile selects and the target can satisfy — the same selection the runner
would make.

`Rule.estimated_requests` defaults to unknown for every target kind, artifact
included: `guardana-core` has never read a rule's code, so it cannot promise an
artifact rule sends nothing — a third-party rule can do its own network I/O
exactly like an endpoint rule can. The 19 built-in artifact rules declare the
zero themselves, on their own base class in `guardana-rules` — not a public
extension point, so a third-party artifact rule declares its own
`estimated_requests` rather than inheriting theirs.

The declaration is **measured, not trusted**, on both sides of that split. A
gate in `guardana-rules` runs every shipped endpoint rule against a model that
never refuses, counts the requests it actually sends, and fails if any rule
spends more than it declared. A second gate runs every shipped artifact rule
with outbound connections blocked at the socket layer, and fails — naming the
rule — if one ever tries to open one: for a rule that only reads files, zero is
the only honest number, so there is nothing to spend less or more of. Either
way, the ceiling is a claim somebody checks, not a promise.

## Plan the run you are going to make

`plan probe` takes `--safety` and `--allow-destructive`, with the same meaning
they have on `probe`. They are not decoration: the runner refuses a rule that
reaches further than the run permits, and until 0.7.1 the plan did not apply that
check — so pricing a `--safety passive` probe listed every active rule that run
would go on to refuse. The selection is now literally the runner's, called from
one place, so a second copy cannot drift from the first.

```bash
guardana plan probe --url https://api.example.com --model m --safety passive
```

## Pricing an MCP server

`plan probe --mcp` prices an MCP run the same way, and it is where this command
earns its keep. Reading a manifest costs three requests; the authorization checks
send around a dozen, which is exactly the number somebody wants before pointing
this at production.

```bash
guardana plan probe --mcp https://mcp.example.com/mcp
```

**The ceiling is higher than any run spends, on purpose.** Each rule declares what
it would cost *alone*, because a plan cannot know which rule runs first — and the
first one to look buys an observation the rest then share — including the single
`server/discover` call that settles which revision of the protocol the server
speaks. A whole MCP probe declares around sixty requests and spends around a
dozen. An upper bound that is too
high refuses a budget that would have fitted, which is the safe direction to be
wrong in; the other way round is a ceiling that lets a run overspend.

**An stdio server is priced by refusing.** Working out what one would cost means
starting it, and starting the thing under examination is the one thing this
command must not do. `guardana probe --mcp … --allow-exec` is where that intent is
stated out loud.

## When the plan does not know

A rule that declares no request count — anything third-party that has not
implemented `estimated_requests` — is **named, not counted as free**:

```text
7 rule(s) would run, 0 skipped.
requests: at least 7, at most 22 — plus 2 of unknown cost
  these rules do not declare a request count, so the ceiling above is a
  lower bound on the worst case:
    • acme.custom.deep_probe
    • acme.custom.fuzzer
```

A plan with an unknown-cost rule never reports that it fits a budget, whatever
the numbers look like. Its ceiling is not a ceiling.

## Checking against a budget

If the profile (or a flag) sets `max_requests` and the worst case exceeds it, the
plan says so and exits `3` — invalid configuration, found before the run rather
than halfway through it:

```text
⚠ this plan does not fit its request budget — the run would stop early,
  and a run that stops early reports no verdict
```

## What it cannot tell you

Capabilities are read from what the target declares locally, so an endpoint that
turns out not to support tool calls will skip more rules than the plan predicted.
Asking the endpoint would make this command cost money, which is the one thing it
must not do. `guardana target inspect` is where that question belongs.

Tokens and wall time are not predicted. Nothing can know what a request will cost
before it is answered, and a guessed figure is one a team would budget against.

## See also

- [`docs/profiles.md`](profiles.md) — the `budgets:` block in `guardana.yaml`
- [`docs/exit-codes.md`](exit-codes.md) — what `3` and `6` mean
- [`docs/usage-run.md`](usage-run.md) — what a finished run actually cost
