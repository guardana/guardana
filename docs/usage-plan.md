# `guardana plan` — what a run would cost, before it costs anything

Probing a hosted model costs money, and the number nobody could state before 0.7
was the upper bound. `guardana plan` states it, and **sends no request to do so**.

```bash
guardana plan probe --url https://api.example.com --model gpt-4o-mini
guardana plan scan .
```

```text
13 rule(s) would run, 0 skipped.
requests: at least 13, at most 43
budget: 200 request(s)

No request was sent to produce this estimate.
```

`--format json` gives the same numbers to a pipeline, with a `schema_version`.

## Where the numbers come from

Every rule declares an upper bound on the requests it will send
(`Rule.estimated_requests`): a YAML rule knows how many prompts it has, a
scenario how many steps, an agent rule its step budget. The plan sums the rules
the profile selects and the target can satisfy — the same selection the runner
would make.

The declaration is **measured, not trusted**. A gate in `guardana-rules` runs
every shipped rule against a model that never refuses, counts the requests it
actually sends, and fails if any rule spends more than it declared. So the
ceiling is a claim somebody checks, not a promise.

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

- [`docs/configuration.md`](configuration.md) — the `budgets:` block
- [`docs/exit-codes.md`](exit-codes.md) — what `3` and `6` mean
- [`docs/usage-run.md`](usage-run.md) — what a finished run actually cost
