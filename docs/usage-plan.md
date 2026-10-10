---
title: "guardana plan"
nav_order: 170
summary: "`guardana plan`: what a run would cost, before it costs anything"
status: stable
---

# `guardana plan` — what a run would cost, before it costs anything

`guardana plan` estimates request costs when you need to budget a probe or scan without sending a request.

```bash
guardana plan probe --url https://api.example.com --model gpt-4o-mini
```

```text
14 rule(s) would run, 16 skipped.
requests: at least 14, at most 47 — plus up to 94 retries
  a request refused for a rate limit or a server error is retried up to 2 times, and each retry counts toward --max-requests
trials: 1 attempt(s) per case, counted in the requests above
judge calls: none — no selected rule grades with a judge

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
| `--profile PATH` | none (built-in default profile) | Path to a `guardana.yaml` policy file; all three subcommands |
| `--preset [ci\|pre-training\|monitor\|release]` | none | Named policy preset (mutually exclusive with `--profile`); all three subcommands |
| `--format [human\|json]` | `human` | Output format; all three subcommands. `plan scan` refuses any other name (exit `3`) before anything else runs |
| `--rules PATH` | none | Directory or file of custom YAML rules; repeatable; all three subcommands |
| `--plugins [all\|builtins\|allowlist\|disabled]` | `builtins`, or the profile's `plugins:` | Which installed plugins to load — same meaning as on `probe`; all three subcommands |
| `--allow-plugin TEXT` | none | Distribution to trust; repeatable, needs `--plugins allowlist`; all three subcommands |
| `--target SCHEME://LOCATOR` | none | Build a trusted installed target of the kind selected by `plan scan` or `plan probe` |
| `--target-option KEY=VALUE` | none | Repeatable, non-secret configuration passed to that target |
| `--url TEXT`, `--model TEXT` | — | `plan probe` only: the endpoint the probe would call, as on `probe` |
| `--mcp TEXT` | none | `plan probe` only: price an MCP server at this http(s) URL instead of a model endpoint |
| `--mcp-registry-entry PATH` | none | `plan probe` only: the registry `server.json` `probe --mcp-registry-entry` would compare, read and refused (exit `3`) as there; needs `--mcp` |
| `--a2a TEXT` | none | `plan probe` only: price an A2A agent, named by the http(s) URL of its card (ending in `.json`) or its origin, instead of a model endpoint; any other path is refused (exit `3`) — see [Pricing an A2A agent](#pricing-an-a2a-agent). Refused with the endpoint flags and `--mcp` (exit `3`) |
| `--provider [openai\|ollama\|tgi]` | `openai` | `plan probe` only: the wire protocol, as on `probe`; any other name is refused (exit `3`) |
| `--adapter PATH` | none | `plan probe` only: the adapter file `probe --adapter` would use, with the same refusals; its `${VAR}` headers are not read, so a plan needs no secret |
| `--system-prompt-file PATH` | none | `plan probe` only: the system prompt `probe` would plant; a file that cannot be read is refused (exit `3`) |
| `--fixtures PATH` | none | `plan probe` only: price the seeded checks from this [fixtures file](usage-fixtures.md) — see [Pricing seeded data](#pricing-seeded-data). No tenant key is read; refused with `--mcp`, `--a2a` and `--target` |
| `--safety [passive\|active\|side-effecting]` | `active` | `plan probe` only: how far rules may reach, as on `probe` |
| `--allow-destructive` | off | `plan probe` only: permit rules that can destroy or alter something the target owns, as on `probe` |
| `--trials INTEGER` | `1` (or `trials:` in the profile) | `plan probe` and `plan grade`: price the run at this many attempts per case, as `probe --trials` and `grade --trials` would make them |
| `--max-requests INTEGER` | the profile's `budgets:` | `plan probe` and `plan grade`: check the plan against this request ceiling; on `plan grade` it is the ceiling each judge is held to |
| `--max-input-tokens`, `--max-output-tokens`, `--max-duration` | the profile's `budgets:` | `plan probe` only: the ceilings `probe` would apply. A token ceiling on a transport that reports no token counts (an adapter, `--provider tgi`) is refused (exit `3`), as `probe` refuses it |
| `--max-requests-per-minute INTEGER` | the profile's `budgets:` | `plan probe` only: the pace `probe` would keep. The plan states the wall time it needs and refuses a `--max-duration` below it (exit `3`) — see [Checking against a budget](#checking-against-a-budget) |
| `--no-plugins` | off | `plan scan` only: deprecated alias for `--plugins disabled` |

No subcommand reads `--api-key-env`, a judge's `api_key_env` or an adapter's `${VAR}`
headers: a plan contacts nothing, so it needs no secret.

`plan scan` also keeps `--no-plugins` as a deprecated alias for `--plugins disabled`,
exactly like `guardana scan` does.

Target construction is configuration-only: `plan` calls the same
`from_locator` classmethod as the real command, but a conforming target does not
contact the system until a run or inspection starts. An installed endpoint target that
can plant a system prompt (`SystemPromptPlanter`) is planned as `probe` runs it: each
canary rule is priced against a view with its canary planted and every other rule
against the target itself, so the plan lists the rules the probe then runs.

## Where the numbers come from

Each built-in rule shape declares an upper bound on the requests it will send
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

**Retries are not in the ceiling.** A chat endpoint sends a request again, up to two
times, when it is refused for a rate limit or a server error, and every retry counts
toward `--max-requests`. The human output names how many retries the ceiling could
add; the JSON `requests.max` leaves them out. An MCP plan names none: its transport does
not retry.

The declaration is **measured, not trusted**, on both sides of that split. A
gate in `guardana-rules` runs every shipped endpoint rule against a model that
never refuses, counts the requests it actually sends, and fails if any rule
spends more than it declared. A second gate runs every shipped artifact rule
with outbound connections blocked at the socket layer, and fails — naming the
rule — if one ever tries to open one: for a rule that only reads files, zero is
the only honest number, so there is nothing to spend less or more of. Either
way, the ceiling is a claim somebody checks, not a promise.

## Pricing repeated trials

`--trials N` multiplies what each rule that repeats will send, and the plan says which
rules will not repeat, so the count is the run's, not an estimate of it:

```bash
guardana plan probe --mcp https://mcp.example.com --trials 5
```

```text
10 rule(s) would run, 20 skipped.
requests: at least 10, at most 77
trials: 5 attempt(s) per case, counted in the requests above
  10 rule(s) make one attempt per case whatever --trials says, because their verdict does not depend on a sampled reply:
    • guardana.agent.mcp_server_manifest
    • guardana.mcp.unauthenticated_access
    …
```

`--format json` carries the same facts as `trials.per_case` and `trials.single_attempt`
(plan schema `4`, [`schemas/plan-v4.schema.json`](../schemas/plan-v4.schema.json)). See
[`usage-probe.md`](usage-probe.md#repeated-trials) for what a trial is.

## Pricing judge calls

A rule graded by a judge configured under `evaluators:` — `llm_judge`,
`reference_judge` or `guard` — spends judge calls as well as target requests, and
each judge meter is bounded by `max_requests` on its own. `plan probe` builds those
judges from the profile, sends them nothing, and prices each meter: the verdicts a
rule grades (`Rule.graded_verdicts`: prompts × K, cases × K for a suite, graded steps
× K for a scenario, sessions × K for an agent run) times the calls one verdict costs
(`Evaluator.judge_calls_per_verdict`: `min_agreement` for `llm_judge` and
`reference_judge`, which share one meter; `1` for `guard`).

```text
requests: at least 1, at most 90
judge calls: at most 270
  llm_judge, reference_judge (one judge, its own meter): at most 270 call(s) against a budget of 100
⚠ this plan does not fit its request budget — the run would stop early,
  and a run that stops early reports no verdict
```

That is a 30-case suite graded by `reference_judge` at `--trials 3` with
`min_agreement: 3`. A rule or evaluator that does not declare its judge calls is
named under the judge line like an unknown-cost rule; while a judge is configured,
such a plan does not claim to fit. `plan scan` never prices judges, because `scan`
never builds one. In JSON, `judge_calls` carries `max`, `meters`, `unknown_cost` and
`complete`, and is `null` for `plan scan`. Judge tokens are not predicted.

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

## Pricing seeded data

`plan probe --fixtures FILE` prices the two checks a [fixtures file](usage-fixtures.md)
brings from the file itself: the tenant check at one request per seeded item and tenant per
trial, and the poisoned-document check at one request per poisoned document per trial. A
rule whose cost depends on what the target holds declares it through
`Rule.estimated_requests_for(target)`; without fixtures both checks are skipped for a
missing capability and cost nothing.

```bash
guardana plan probe --url https://support.example.test --model support-bot \
  --fixtures guardana-fixtures.yaml --trials 2
```

Each tenant is resolved as the probe would resolve it, without reading its key, so a
fixtures file the probe would refuse is refused here too (exit `3`). A run given fixtures
must complete every installed rule that checks seeded data and has something to check, so
a plan that would not select one — a profile that excludes it, `--safety passive` — names
it as a coverage shortfall and exits `3`.

## Pricing an MCP server

`plan probe --mcp` prices an MCP run the same way, and it is where this command
earns its keep: it states the most an MCP run can send before anything is pointed at
production, and [the probe page](usage-probe.md#cost) lists what those requests are.
`--mcp-registry-entry FILE` adds the registry comparison, which
sends nothing beyond the opening the other checks already buy.

```bash
guardana plan probe --mcp https://mcp.example.com/mcp
```

**The ceiling is usually higher than a run spends, on purpose.** Each rule declares what
it would cost *alone*, because a plan cannot know which rule runs first — and the
first one to look buys an observation the rest then share — including the single
`server/discover` call that settles which revision of the protocol the server
speaks, so a whole MCP probe declares several times what it spends. An upper bound that is too
high refuses a budget that would have fitted, which is the safe direction to be
wrong in; the other way round is a ceiling that lets a run overspend.

**An stdio server is priced by refusing.** Working out what one would cost means
starting it, and starting the thing under examination is the one thing this
command must not do. `guardana probe --mcp … --allow-exec` is where that intent is
stated out loud.

## Pricing an A2A agent

```bash
guardana plan probe --a2a https://agent.example.com
```

```text
3 rule(s) would run, 27 skipped.
requests: at least 3, at most 14
```

The three A2A rules declare fourteen requests between them; a run shares the card and
each read, and sends at most nine. No token variable is read, so a plan needs no
secret.

## Pricing a grade

`plan grade RECORDING` previews [`guardana grade`](usage-grade.md): it selects the rules
the grade would run, lists every rule the recording does not answer as skipped
`not_recorded`, prices the judge calls, and counts no target request, because every answer
comes from the recording. It takes `--profile`, `--preset`, `--rules`, `--plugins`,
`--allow-plugin`, `--trials`, `--max-requests` and `--format`, and refuses an unreadable
recording with exit `3`.

```bash
guardana plan grade answers.jsonl --rules rules/ --profile guardana.yaml
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

If the profile (or a flag) sets `max_requests` and the worst case — of the target
or of any judge meter — exceeds it, the plan says so and exits `3` — invalid
configuration, found before the run rather than halfway through it:

```text
⚠ this plan does not fit its request budget — the run would stop early,
  and a run that stops early reports no verdict
```

A token ceiling a judge's transport cannot enforce is refused with `3` too, the same
way `probe` refuses it.

With `max_requests_per_minute` set, the plan states the wall time the estimated
requests need at that pace. The first request goes at once and each further one
`60 / N` seconds later, so the time is one less than the requests, times `60 / N`: the
estimated target requests — a rule of unknown cost counted once — or the calls of the
busiest judge meter, whichever is larger. Retries and the time each reply takes are not
counted, so the real run takes longer. A `max_duration` that is not more than that
time exits `3`, since the run would stop before its last request, and `fits_budget` is
`false` in the JSON:

```text
wall time: 580s for the estimated requests at 6 request(s) per minute, retries not counted
⚠ this plan does not fit its time budget — 300s is not more than the 580s its requests need at 6 per minute, so the run would stop early, and a run that stops early reports no verdict
```

The JSON carries both as `budgets.max_requests_per_minute` and
`budgets.minimum_wall_time_seconds`, null when no rate is set.

## A run that could not pass

The plan exits `3` as well when the run it describes could not pass, and says why
on stderr, one line per cause:

- **no rule would run** — the profile, the flags and the target select none, and a
  run that verifies nothing reports no verdict;
- **a coverage shortfall** — a check the run's fixtures demand that it would not select,
  a graded recording whose run stopped, or, for `plan scan`, a path that holds no file
  other than `.guardanaignore` files (`empty_target`, the shortfall `scan` records);
- **a rule it would skip while `fail_on.fail_on_skipped` is on** — a capability the
  target does not declare, or a safety mode that refuses the rule. A rule about a protocol
  the target does not speak (an MCP or A2A rule against a chat endpoint, a chat rule
  against an MCP server or an A2A agent) is skipped `not_applicable` and is not one;
- **a file under `calibrations:` that would stop the run** — missing, unreadable, or
  measuring an evaluator another file measures too;
- **an error the run would record before its first rule** — a rule file that does not
  load, a plugin the trust mode refuses (the line names the distribution and how to
  admit it: `--plugins allowlist --allow-plugin <distribution>`, the profile's
  `plugins:`, or `--plugins all`), a rule whose `expect:` block its evaluator cannot grade, or a
  capability the target declares without implementing. The plan reads these from the
  same function the run does, so the two never list different errors.

With `fail_on.fail_on_error: false` the errors are printed as a warning and the plan
keeps its exit code, as the run would pass them. The JSON document on stdout is the
same either way.

The plan decides with the gate's own list of what leaves a run unanswered, applied to the
rules it would run, the rules it would skip and the errors it would record, so the plan and
the run cannot disagree about a skip, an error or an empty selection. The
[`release` preset](profiles.md#release-complete-coverage-or-no-pass) turns
`fail_on_skipped` on.

## What it cannot tell you

Capabilities are read from what the target declares locally, so an endpoint that
turns out not to support tool calls will skip more rules than the plan predicted.
Asking the endpoint would make this command cost money, which is the one thing it
must not do. `guardana target inspect` is where that question belongs.

Whether a check reaches a verdict is known only when it runs. With
`fail_on_inconclusive` or `fail_on_skipped` on, as in `--preset release`, the plan says so
on stderr, whether or not it refuses:

```text
note: fail_on_inconclusive is on — only the run can tell whether a check declines to reach a verdict, so this plan cannot promise a pass
note: fail_on_skipped is on — an endpoint may turn out not to support what it declares, and the run would then skip more rules than this plan lists
```

The second note appears for `plan probe` only.

How many cases each rule grades is known only after the run too. A rule that attempted
cases and graded none is an `ungraded_cases` shortfall whatever the profile says, and
`fail_on.min_graded_share` raises that bar per rule
([profiles](profiles.md#full-schema)). When the key is set, every plan says on stderr that
the floor is checked after the run:

```text
note: min_graded_share is set — only the run can tell how many cases each rule grades, so a rule below 80% is checked after it
```

A selected rule that grades with an evaluator nobody configured is refused by the plan in
the words the run would record. The plan finds the evaluator through the rule's declared
expectations, so a Python rule that reads an evaluator it does not declare is caught only
when it runs.

Tokens and wall time are not predicted. Nothing can know what a request will cost
before it is answered, and a guessed figure is one a team would budget against.

## See also

- [`docs/profiles.md`](profiles.md) — the `budgets:` block in `guardana.yaml`
- [`docs/exit-codes.md`](exit-codes.md) — what `3` and `6` mean
- [`docs/usage-run.md`](usage-run.md) — what a finished run actually cost
