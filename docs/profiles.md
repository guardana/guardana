---
title: "Profiles — guardana.yaml"
nav_order: 210
summary: "the `guardana.yaml` policy file: which rules run, what fails the build"
status: stable
---

# Profiles — `guardana.yaml`

A profile is a YAML file that picks which rules run and what makes the run
fail. Every command that runs the engine (`scan`, `probe`, `grade`,
`analyze-trace`, `monitor` and the others that select or grade rules) takes one
via `--profile PATH`; without it, a built-in default profile applies
(`include: ["*"]`, `fail_on.severity: high`, `fail_on.min_confidence: 0.0`).

Generate a starter file:

```bash
guardana init                # writes ./guardana.yaml
guardana init my-profile.yaml
```

`init`'s template:

```yaml
name: default
rules:
  include: ["guardana.*"]
fail_on:
  severity: high
  min_confidence: 0.0
```

## Full schema

The published schema is
[`profile/v1.schema.json`](https://guardana.dev/schemas/profile/v1.schema.json)
([`schemas/profile-v1.schema.json`](../schemas/profile-v1.schema.json)); it describes every
key below, and a test holds it to the keys the loader accepts. Every key is optional.

```yaml
schema_version: 1              # optional; absent means 1 — see "Schema version" below
name: pre-deploy               # free-form label, shown nowhere but reports/logs

rules:
  include: ["guardana.*", "acme.*"]   # glob patterns; rule matches if it matches
                                      # any include AND no exclude
  exclude: ["guardana.output.*"]     # optional; defaults to []
  paths: ["./team-rules"]            # optional; directories/files of custom
                                      # YAML rules to load — see writing-rules.md
  paths_exclude: ["data/*", "archive"]  # optional; globs (matched relative to the
                                         # scan root) of files/dirs to skip. A
                                         # `.guardanaignore` file at the root adds
                                         # more, one glob per line.

plugins:                        # optional; which installed plugins a run imports
  mode: allowlist               # all | builtins | allowlist | disabled
  allow: [acme-guardana-rules]  # distributions to admit; only with mode: allowlist

fail_on:
  severity: high                # one of: info | low | medium | high | critical
                                 # (case-insensitive); defaults to "high"
  min_confidence: 0.7           # 0.0-1.0; defaults to 0.0
  fail_on_inconclusive: false   # true: unverified checks also fail the gate
  fail_on_error: true           # false: a check that could not run stops blocking
  fail_on_skipped: false        # true: a selected rule the target cannot run is a gap
  min_graded_share: 0.8         # optional, (0, 1]; least share of its cases a rule grades

trace:                          # only ever governs `analyze-trace` / `trace inspect`
  require: [identity, approval, effects]   # optional; evidence this run demands. A
                                            # producer that does not record one of
                                            # these makes the run indeterminate —
                                            # with no fail_on_* in front of it

contracts:                      # optional; security contracts to load, files or
  - ./contracts/checkout.yaml   # directories — see usage-contracts.md

trials: 1                       # optional; attempts per case for rules that grade a
                                # sampled reply — see usage-probe.md#repeated-trials

calibrations: []                # optional; calibration files, beside this profile

evaluators:                     # config-wired evaluators — see the section below
  llm_judge:
    endpoint: "http://localhost:11434"   # any OpenAI-compatible server
    model: "llama3"
    api_key_env: "JUDGE_API_KEY"         # optional; env var holding the key
    provider: "openai"                   # optional; openai | ollama | tgi
    prompt_version: "2026.1"             # optional; versioned judging rubric
    min_agreement: 3                     # optional; samples per verdict (default 1)
  guard:                                 # optional safety-classifier evaluator
    endpoint: "http://localhost:8000"
    model: "llama-guard-3"

budgets:                        # optional; see "budgets:" below
  max_requests: 200

privacy:                        # optional; what evidence a run keeps — see privacy.md
  evidence_mode: redacted       # metadata_only | redacted | full

delivery:                       # optional; see "delivery:" below
  required: true                # every delivery must be acknowledged, or exit 8
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `schema_version` | integer | `1` | The profile schema the file was written for. See [Schema version](#schema-version). |
| `name` | string | `"custom"` | A label for the profile (informational only) |
| `rules.include` | list of glob patterns | `["*"]` | A rule's `id` must match at least one pattern here to run |
| `rules.exclude` | list of glob patterns | `[]` | A rule's `id` matching any of these is dropped, even if included |
| `rules.paths` | list of paths | `[]` | Directories (or single files) of custom declarative YAML rules to load, in addition to anything passed via the repeatable `--rules PATH` flag on `scan`/`probe`/`monitor`. A relative path is read beside the profile file, not from the current working directory, like `contracts` and `calibrations`; when it only exists in the working directory, the warning names both paths. A rule file that does not load never aborts the run: it is recorded in `errors`, which leaves the run indeterminate unless `fail_on.fail_on_error` is `false`. So is a directory that holds no `.yaml` or `.yml` file at its top level; rule files in its subdirectories are not read. See [`writing-rules.md`](writing-rules.md). |
| `plugins.mode` | `all\|builtins\|allowlist\|disabled` | not stated: `builtins` | Which installed plugins every command given this profile imports. See [Plugin trust](#plugin-trust-plugins). |
| `plugins.allow` | list of distribution names | — | The distributions `allowlist` admits beside Guardana's own. Required with `allowlist`, refused with any other mode. |
| `fail_on.severity` | `info\|low\|medium\|high\|critical` | `high` | The minimum severity a finding needs to be eligible to fail the gate |
| `fail_on.min_confidence` | float `0.0`–`1.0` | `0.0` | For findings that carry a `Verdict` (dynamic checks), the minimum confidence required to count toward the gate. Static findings have no verdict and always count once their severity threshold is met. |
| `fail_on.fail_on_inconclusive` | bool | `false` | When `true`, a check that ran but could not reach a verdict (reported on the `unverified` channel) also fails the gate — the strict posture for a hard CI gate. **`severity` does not apply to it.** A severity answers how bad a problem is, and an unverified result is the absence of an answer, so any of them fails the gate once this is on. This is what makes "an artifact I could not read does not get promoted" expressible in one key. |
| `fail_on.fail_on_error` | bool | **`true`** | A check that could not run *at all* — a plugin that failed to import, a custom rule file that would not load, a rule that raised, a request the endpoint refused with a `4xx` about that request (`stage: request`) — fails the gate. Note the default is the opposite of `fail_on_inconclusive`, and deliberately so: `inconclusive` is a verdict (the check ran and honestly could not tell), while an error means the check never happened while the result looked as though it had. With `false`, a request the endpoint refused lets the run pass as any other rule error does. Set `false` only if you would rather ship than fix the broken check. |
| `fail_on.fail_on_skipped` | bool | `false` | When `true`, a selected rule that did not run because the target lacks a capability it needs, or because the safety mode refuses it, leaves the run `indeterminate`. A rule the policy excludes is not skipped; it is not selected. A security contract about another system, and a rule about a protocol the target does not speak (an MCP or A2A rule against a chat endpoint, a chat rule against an MCP server), are recorded as `not_applicable` and do not count. |
| `fail_on.min_graded_share` | number in `(0, 1]` | unset | The least share of its case attempts each rule must grade. Graded is an assessment recorded `measured`; attempted is every assessment that is not `skipped`, so a rule whose every case was skipped is not checked. Checked per rule after the run: a rule below the floor is an `ungraded_cases` coverage shortfall ("graded 7 of 10 case attempts (70%), below the floor of 80%"), which leaves the run `indeterminate` unless a finding fails it. Without the key, a rule that attempted cases and graded none is the same shortfall under every policy and preset. Zero, a value above 1, a string or a boolean is refused at load. No preset sets it. `plan` cannot know the share before the run and says so when the key is set. |
| `trace.require` | list of dimension names | `[]` | Evidence a trace run demands: `messages`, `tools`, `retrieval`, `memory`, `identity`, `delegation`, `consent`, `policy`, `approval`, `effects`, `handoff`. A producer that does not record one makes the run **`indeterminate`, unconditionally** — no `fail_on_*` governs it, because you asked for this coverage by name. An unknown dimension raises at load. Governs traces only: a shared config carrying it does not affect `scan` or `probe`. See [`usage-trace-inspect.md`](usage-trace-inspect.md). |
| `contracts` | list of paths | `[]` | Security contracts to load — files, or directories of `.yaml`/`.yml`. Added to anything passed via the repeatable `--contract PATH` flag. Unlike a malformed *rule* file, a contract that will not load is a hard error: it is your own threat model, and a silently absent one is a gate you think you have. See [`usage-contracts.md`](usage-contracts.md). |
| `trials` | integer ≥ 1 | `1` | How many independent attempts `probe`, `monitor` and `plan probe` make at each case of a rule that grades a sampled model reply. `--trials N` wins over it. A rule that does not repeat (a protocol check, a `stateful` scenario) makes one attempt whatever this says, and the run records that. Anything other than a whole number of at least 1 is refused at load. See [`usage-probe.md`](usage-probe.md#repeated-trials). |
| `calibrations` | list of paths | `[]` | Calibration files written by `guardana calibrate --record`. A relative path is read beside the profile file, not from the current working directory; globs are not expanded. A missing listed path stops the run with exit code `3` (`INVALID_USAGE`), and so do two files that both record the same evaluator. A bare string is refused. |
| `evaluators` | mapping | `{}` | Config blocks for evaluators that need a model of their own, keyed by evaluator id — `llm_judge` and `guard`; any other block name is refused. `probe`, `grade`, `monitor`, `calibrate` and `rule test` build and register them from this block at startup, and `plan` builds them to price their calls without sending any; see the next section. With no block, a rule naming that evaluator is skipped **visibly**, never silently passed. |
| `budgets` | mapping | no ceiling | What a run may spend. See [`budgets:`](#budgets--a-ceiling-on-what-a-run-may-spend). |
| `privacy` | mapping | `evidence_mode: redacted` | What evidence a run keeps and how it is redacted. See [`privacy.md`](privacy.md). |
| `delivery.required` | bool | `false` | When `true`, a delivery to the collector or an installed reporter that was not acknowledged ends the command with exit `8`. See [`delivery:`](#delivery). |

`include`/`exclude` are matched with shell-style globbing (`fnmatch`) against
the rule's `id`, so namespacing rules (`guardana.*` for built-ins, `acme.*`
for a company's own) lets one profile mix and match cleanly — see
[`examples/guardana.yaml`](../examples/guardana.yaml) for a profile that
includes both.

## Plugin trust: `plugins:`

Every command starts by trusting only Guardana's own distributions (`builtins`). `guardana doctor` lists installed packs. Guardana refuses a pack until you admit it and records its entry points as errors, so while a pack stays refused every run is `indeterminate` under the default `fail_on_error`, whether or not it would have used the pack. Use `plugins:` to set trust for every command given this profile:

```yaml
plugins:
  mode: allowlist
  allow: [acme-guardana-rules]
```

A flag takes precedence over the profile: `--plugins` and its `--allow-plugin` list replace the entire `plugins:` setting. A pipeline that checks untrusted contributions should pass `--plugins builtins` as a flag. Then a `guardana.yaml` changed in the same pull request cannot widen trust. A preset sets no trust, and Guardana does not read `guardana.yaml` unless `--profile` names it. Guardana compares names the way pip does: `Acme_Rules` admits `acme-rules`. From Python, `Registry.discover(trust)` and `Verifier(trust=...)` take the trust as an argument and have no default. See [`SECURITY.md`](../SECURITY.md#the-plugin-trust-model) for the full model.

## Delivery

A run forwards its result when `--reporter` names a collector or an installed reporter. By
default a delivery that fails is said and the verdict decides the exit, so a scan whose
collector is down still passes. A pipeline whose result only counts once it arrives asks
for more:

```yaml
delivery:
  required: true
```

Then every delivery the run makes must be acknowledged, or the command exits `8` with the
verdict printed:

- **The collector** acknowledges with its own answer — a JSON object whose `status` is
  `ok`, with an integer `stored` and a boolean `duplicate` — not with any `2xx`, so a proxy,
  a health check or another service at its address does not count.
  A rejection, an unreachable collector and an answer that is not an acknowledgement are
  printed as `error:` lines ending `— the profile sets delivery.required`.
- **An installed reporter** acknowledges with the status `delivered`. Any other status,
  `not_sent` included, is followed by `error: the profile sets delivery.required, and the
  delivery was <status>`.

`8` replaces `0`, `1` and `2`; a run that stopped keeps `4`, `6` or `7`, and a redaction
failure stays `5` ([exit codes](exit-codes.md)). `import-observations` exits `8` instead of
`2` the same way. [`monitor`](usage-monitor.md) never stops a watch for it: it counts the
alert deliveries the collector did not acknowledge, prints `monitor: <n> alert deliveries not
acknowledged`, and ends a watch that would have exited `0`, `1` or `2` with `8`. A run that
forwards nothing is unaffected; one that names no `--reporter` says so once, as
`warning: the profile sets delivery.required, and this run names no --reporter`, and keeps its
exit. `scan --write-baseline` and `probe --write-mcp-pin` produce no report to forward, so they
refuse a collector or installed `--reporter` with exit `3` before anything is sent, whatever
the profile says. The setting decides the exit after the verdict, so it is
left out of the profile digest: setting it moves no run record and no recipe lock.
`guardana config explain` shows it after `plugins`.

## Schema version

A profile may state `schema_version: 1`; without it, a profile is version 1. A version this
build does not read is refused at load with exit `3`:

- above the current one: `invalid profile <path>: profile schema 2 was written by a newer
  Guardana; this build reads schema 1 — upgrade Guardana`, checked before unknown keys, so
  a key a newer release added is not reported as a typo;
- a boolean or anything but a whole number: `schema_version must be an integer`;
- below 1: `schema_version 0 does not exist`.

Guardana writes no `schema_version` while the schema is 1, so a profile `guardana init`
writes still loads in a release that predates the key. A key added later raises the
version.

## The gate

A run's exit code is `1` (fails) if **any** finding satisfies both:

1. `finding.severity >= fail_on.severity`, and
2. either the finding has no `verdict` (a static check — no confidence to
   gate on) **or** `finding.verdict.confidence >= fail_on.min_confidence`.

Otherwise the run exits `0`. This is the same logic behind `scan`, `probe`,
and each `monitor` cycle's gate check.

Checks that could not reach a verdict are reported on the separate
`unverified` channel and do **not** fail the gate by default; set
`fail_on.fail_on_inconclusive: true` to make them count.

**One thing no `fail_on` switch governs: coverage you demanded and did not get.**
A dimension named in `trace.require`, or needed by an assertion you wrote in a
security contract, that the producer does not record makes the run `indeterminate`
(exit `2`) with nothing to turn off. Every other branch above is behind a switch,
correctly — they cover checks nobody specifically asked for. This one you asked for
by name, and `fail_on_skipped` defaulting to off would otherwise turn "your
contract could not be checked" into exit `0`. The saved run records which demand
went unmet under `run.coverage.shortfall`. A model file the scan observed and no rule
read, or a model or notebook a rule could not read, lands there too, so a scan holding
one exits `2` under every preset, `ci` included
([`guardana scan`](usage-scan.md#model-files-no-rule-reads)).

## Config-wired evaluators: `llm_judge` and `guard`

Two built-in evaluators grade with a model of their own, so they only become
available once the `evaluators:` block tells Guardana where that model lives.
`probe`, `grade`, `monitor`, `calibrate` and `rule test` read the block at startup
and register the evaluators alongside the always-available `keyword`, `canary`, and
`length`.

Both blocks share the connection keys, read the way the endpoint commands read
`--url`, `--provider`, `--api-key-env` and `--adapter`:

| Key | Required | Meaning |
|---|---|---|
| `endpoint` | yes | Base URL of the judge's server — a local vLLM or Ollama keeps grading fully offline. With `adapter`, the URL the adapter posts to |
| `model` | yes | Model name to send |
| `api_key_env` | no | Env var holding the bearer API key, if the server needs one. Unset or empty is refused before anything is sent; `plan` never reads it |
| `provider` | no | Wire protocol: `openai` (default), `ollama` or `tgi`; any other name is refused |
| `adapter` | no | An [adapter file](usage-probe.md#probing-a-guarded-endpoint), read beside the profile when relative. Its `url:` may only repeat `endpoint`; it cannot be combined with `provider` or `api_key_env`. It may set `retry_statuses:` and refuses `declines:` and `metadata_paths:`: a judge either answers or is unavailable |

A judge's identity — what a recorded calibration is matched against — names its
model and a digest of its endpoint, and adds `provider=` and `adapter=<digest of the
file>` only when the block sets them, so a block that sets neither keeps the identity
it had. A judge block that sets `provider` or `adapter` needs the default judge
builder; a [Python caller](python-api.md) that passes its own `judge_endpoint` gets a
`ProfileError` for such a block rather than a judge built on the OpenAI wire.

`llm_judge` — an LLM judge with a versioned rubric — additionally takes:

| Key | Default | Meaning |
|---|---|---|
| `prompt_version` | `"2026.1"` | Which judging-prompt version to use; stamped into each finding's `evaluator_id` (`llm_judge@2026.1`) so results stay reproducible as the rubric evolves. `2026.1` gives the judge the conversation as one JSON-encoded line in a block it is told never to obey; `2025.1`, the earlier unfenced prompt, stays selectable. A calibration keeps applying only to the version it was measured for, so pin `"2025.1"` to keep one measured before `2026.1`; a run warns on stderr when they differ |
| `min_agreement` | `1` | Samples per verdict. With more than one, confidence is the fraction of samples agreeing — a measured, judge-aware number instead of a flat constant. The verdict is the first word of the judge's reply (markdown stripped); a reply with no such PASS/FAIL, or naming both, fails closed at reduced confidence, and a pass with fewer readable samples than `min_agreement` asked for is `inconclusive`. |

`guard` — an external safety classifier (Llama Guard / Granite Guardian
style) — takes only the endpoint keys. It is **opt-in on purpose** and grades
at conservative confidence: open-weight guards miss a large share of unsafe
content, so Guardana never uses one as an always-on all-clear. Over an agent run
or a whole conversation it classifies every reply joined into one text, in one
call; a calibration recorded on single replies measured it on shorter input than
that.

An unknown block name under `evaluators:`, a key a block does not take, and a block
that is not a mapping are a `ProfileError` when the profile loads (exit `3`), and a
profile built in Python is held to the same keys when its judges are wired. A rule
that names an unconfigured evaluator is skipped visibly in the run summary — the gate
never quietly weakens.

## Rule-specific configuration

`rule_config` (a top-level key, keyed by rule id) is threaded into a rule's
`RuleContext` at run time, letting a rule read profile-supplied configuration
values via `ctx.get(key, default)`. Built-in readers include
`guardana.supply_chain.hardcoded_secret`, which uses `entropy` to opt into a
high-entropy secret scan, and the MCP server manifest rule, which reads `pin`.
Other built-in or custom rules can use the mechanism for tunable parameters.

## Named presets: `--preset`

For the common moments you run Guardana, a built-in preset saves you from writing
a `guardana.yaml` at all. A preset tunes only the *failure bar* — which security
layer runs is already decided by the command (`scan` runs the build-time rules,
`probe`/`monitor` the runtime rules), so a preset never has to filter by layer.

| Preset | Fails on | For |
|---|---|---|
| `ci` | HIGH | The dev machine and CI — the standard gate. |
| `pre-training` | MEDIUM | The training server: stricter, so leads (a dataset loading script, an unpinned model download) block a run before it consumes bad data. An unpinned dataset pull is a LOW lead and does not block. |
| `monitor` | HIGH **and** inconclusive | A live monitor, so its own checks going dark (a downed judge, empty replies) is itself an alert. |
| `release` | HIGH, **and** a selected check that was skipped or reached no verdict | A release gate: it passes only when every selected check ran and decided. |

```bash
guardana scan .          --preset ci            # linter-style gate in CI
guardana scan ./data     --preset pre-training  # strict pre-run gate on the training box
guardana monitor --url … --model … --preset monitor
guardana scan .          --preset release       # every selected check ran and decided
```

A check that could not run at all (a rule file or plugin that did not load, a rule that
raised) leaves the run `indeterminate` under every preset, because `fail_on_error` is on
in all of them.

### `release`: complete coverage or no pass

`--preset release` fails on a HIGH finding, as `ci` does, and also leaves the run
`indeterminate` (exit `2`) when a selected rule was skipped or a check reached no verdict.
A rule about a protocol the target does not speak is not a skip that counts: against a
chat endpoint every MCP and A2A rule is recorded as `not_applicable`, and so is every chat
rule against an MCP server or an A2A agent. A capability missing within the protocol the
target speaks still counts. A preset cannot narrow which rules run, so an endpoint that
does not call tools skips every tool rule, an endpoint probed without a
[fixtures file](usage-fixtures.md) skips the two seeded-data rules, an stdio MCP server
skips the authorization rules, and a trace skips every rule needing a dimension its
producer does not record. `probe --preset release` is `indeterminate` against a target
that skips a selected rule this way, and `plan probe` says so before sending anything. A target written as a plugin
that does not say which protocol it speaks has every rule it cannot serve skipped for a
missing capability. To gate a release on the rules your target can serve, write the same
bar into a `guardana.yaml` and select those rules:

```yaml
name: release-chat-endpoint
rules:
  include: ["guardana.prompt.*", "guardana.output.*"]
fail_on:
  severity: high
  fail_on_skipped: true
  fail_on_inconclusive: true
```

`guardana plan scan` and `guardana plan probe` refuse such a run with exit `3` before it
sends anything when a rule would be skipped, a rule file or plugin did not load, or no rule
would run. Whether a check reaches a verdict is known only when it runs, so a plan that
passes can still end `indeterminate`; an endpoint can also turn out not to support a
capability it declared, and skip more than the plan listed.

Coverage the target never offered is not a skip. A `scan` whose path holds no file other
than `.guardanaignore` files, because the directory is empty or because the profile's
`rules.paths_exclude` and `.guardanaignore` removed every file, is an `empty_target`
coverage shortfall naming the scanned path. It is `indeterminate` (exit `2`) under every
preset, `release` included, and `plan scan` refuses it with exit `3`. Any other file
counts, a stray `.DS_Store` included, so check that the path a build produced holds what
you meant to scan. A single-file path is never empty.

Every preset makes **one attempt per case** (`trials: 1`), so choosing a preset never
multiplies what a gate costs. Raise it with `--trials` or `trials:` where you mean to pay
for it.

`--preset` and `--profile` are mutually exclusive — pass one or the other. When
you need finer control (per-rule config, custom rule directories, a wired judge),
write an explicit `guardana.yaml` as shown above; you can still ship as many
differently-named profile *files* as you like and select one with `--profile`.

## `budgets:` — a ceiling on what a run may spend

```yaml
budgets:
  max_requests: 200
  max_input_tokens: 250000
  max_output_tokens: 100000
  max_duration: 15m        # number with s / m / h; a bare number is seconds
  max_requests_per_minute: 30
```

Every ceiling is optional, and `probe` takes the same five as flags
(`--max-requests`, `--max-input-tokens`, `--max-output-tokens`,
`--max-duration`, `--max-requests-per-minute`), which win over the file; `grade` and
`plan probe` take them too. A flag sets only the ceiling it
names — it never clears one the profile configured.

Ceilings are checked **before each request**, so `max_requests: 200` means 200
requests were sent and never 201. A retry is a request: a call that is rate-limited
twice and then answered spends three. Token and duration ceilings can only be checked
once a request has been answered, so they stop the *next* one.

`max_requests_per_minute` paces the run instead of ending it: each request, a retry
included, waits for a slot at least `60 / N` seconds after the one before, so the rules
running at once share one rate. Every meter the budgets reach keeps it — the target's, and
each judge's own. A slot that lies past `max_duration` is not waited for: the run stops as
an exhausted budget, exit `6`. A target that sends nothing (a file scan, a trace, a
recording) accepts a rate, as it accepts `max_requests`. [`guardana plan
probe`](usage-plan.md#checking-against-a-budget) states the wall time a rate needs and
refuses a `max_duration` below it.

A token ceiling is held only while replies report their token counts. A token count
below zero is read as not reported, because adding a negative count to the sum would
let every later request pass the ceiling. The first reply that leaves out a count a
ceiling depends on stops the run as an exhausted budget, exit `6`, because no later
request could be measured against it.

**The ceiling belongs to the run, not to a pass of it.** `probe` runs each
canary-planting rule against a target of its own — the marker has to be in that
rule's system prompt and in no other — and every one of those passes shares one
meter. Otherwise `max_requests: 200` would buy 200 requests as many times as there
are canary rules installed, and adding one would quietly raise the bill. A
`monitor` cycle is a run of its own, so the ceiling applies per cycle: a single
total over a loop with no end is not a ceiling anybody could set.

A run that hits a ceiling stops, keeps the findings it already produced, records
`stopped_by: budget_exhausted` in its manifest, and exits `6`. It never passes the
gate, and [`guardana diff`](usage-diff.md) will not read its smaller finding count
as an improvement.

A budget nothing can enforce is refused before the first request, with exit `3` —
a token ceiling on a transport that reports no token counts, or any ceiling on a
target that does not meter itself. A ceiling the user believes in and nothing
watches is worse than no ceiling.

Use [`guardana plan`](usage-plan.md) to find out whether a budget fits, before
paying for the answer.
