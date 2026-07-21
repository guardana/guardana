# Profiles — `guardana.yaml`

A profile is a YAML file that picks which rules run and what makes the run
fail. Every command that runs the engine (`scan`, `probe`, `monitor`) takes
one via `--profile PATH`; without it, a built-in default profile applies
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

```yaml
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

fail_on:
  severity: high                # one of: info | low | medium | high | critical
                                 # (case-insensitive); defaults to "high"
  min_confidence: 0.7           # 0.0-1.0; defaults to 0.0
  fail_on_inconclusive: false   # true: unverified checks also fail the gate

evaluators:                     # config-wired evaluators — see the section below
  llm_judge:
    endpoint: "http://localhost:11434"   # any OpenAI-compatible server
    model: "llama3"
    api_key_env: "JUDGE_API_KEY"         # optional; env var holding the key
    prompt_version: "2025.1"             # optional; versioned judging rubric
    min_agreement: 3                     # optional; samples per verdict (default 1)
  guard:                                 # optional safety-classifier evaluator
    endpoint: "http://localhost:8000"
    model: "llama-guard-3"
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | `"custom"` | A label for the profile (informational only) |
| `rules.include` | list of glob patterns | `["*"]` | A rule's `id` must match at least one pattern here to run |
| `rules.exclude` | list of glob patterns | `[]` | A rule's `id` matching any of these is dropped, even if included |
| `rules.paths` | list of paths | `[]` | Directories (or single files) of custom declarative YAML rules to load, in addition to anything passed via the repeatable `--rules PATH` flag on `scan`/`probe`/`monitor`. A malformed rule file is reported as a warning and skipped — it never aborts the run. See [`writing-rules.md`](writing-rules.md). |
| `fail_on.severity` | `info\|low\|medium\|high\|critical` | `high` | The minimum severity a finding needs to be eligible to fail the gate |
| `fail_on.min_confidence` | float `0.0`–`1.0` | `0.0` | For findings that carry a `Verdict` (dynamic checks), the minimum confidence required to count toward the gate. Static findings have no verdict and always count once their severity threshold is met. |
| `fail_on.fail_on_inconclusive` | bool | `false` | When `true`, a check that ran but could not reach a verdict (reported on the `unverified` channel) also fails the gate — the strict posture for a hard CI gate. |
| `evaluators` | mapping | `{}` | Config blocks for evaluators that need a model of their own, keyed by evaluator id — `llm_judge` and `guard` today. `probe` and `monitor` build and register them from this block at startup; see the next section. With no block, a rule naming that evaluator is skipped **visibly**, never silently passed. |

`include`/`exclude` are matched with shell-style globbing (`fnmatch`) against
the rule's `id`, so namespacing rules (`guardana.*` for built-ins, `acme.*`
for a company's own) lets one profile mix and match cleanly — see
[`examples/guardana.yaml`](../examples/guardana.yaml) for a profile that
includes both.

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

## Config-wired evaluators: `llm_judge` and `guard`

Two built-in evaluators grade with a model of their own, so they only become
available once the `evaluators:` block tells Guardana where that model lives.
`probe` and `monitor` read the block at startup and register the evaluators
alongside the always-available `keyword`, `canary`, and `length`.

Both blocks share the endpoint keys:

| Key | Required | Meaning |
|---|---|---|
| `endpoint` | yes | Base URL of an OpenAI-compatible server — a local vLLM or Ollama (`/v1`) keeps grading fully offline |
| `model` | yes | Model name to send |
| `api_key_env` | no | Env var holding the bearer API key, if the server needs one |

`llm_judge` — an LLM judge with a versioned rubric — additionally takes:

| Key | Default | Meaning |
|---|---|---|
| `prompt_version` | `"2025.1"` | Which judging-prompt version to use; stamped into each finding's `evaluator_id` (`llm_judge@2025.1`) so results stay reproducible as the rubric evolves |
| `min_agreement` | `1` | Samples per verdict. With more than one, confidence is the fraction of samples agreeing — a measured, judge-aware number instead of a flat constant. A reply with no parseable PASS/FAIL verdict fails closed at reduced confidence. |

`guard` — an external safety classifier (Llama Guard / Granite Guardian
style) — takes only the endpoint keys. It is **opt-in on purpose** and grades
at conservative confidence: open-weight guards miss a large share of unsafe
content, so Guardana never uses one as an always-on all-clear.

A typo in any of these keys is a `ProfileError` at load time, and a rule that
names an unconfigured evaluator is skipped visibly in the run summary — the
gate never quietly weakens.

## Rule-specific configuration

`rule_config` (a top-level key, keyed by rule id) is threaded into a rule's
`RuleContext` at run time, letting a rule read profile-supplied
configuration values via `ctx.get(key, default)`. None of the built-in
rules currently read anything from it, but the mechanism is there for rules
(built-in or custom) that need tunable parameters.

## Named presets: `--preset`

For the common moments you run Guardana, a built-in preset saves you from writing
a `guardana.yaml` at all. A preset tunes only the *failure bar* — which security
layer runs is already decided by the command (`scan` runs the build-time rules,
`probe`/`monitor` the runtime rules), so a preset never has to filter by layer.

| Preset | Fails on | For |
|---|---|---|
| `ci` | HIGH | The dev machine and CI — the standard gate. |
| `pre-training` | MEDIUM | The training server: stricter, so leads (an unpinned dataset, a provenance gap) block a run before it consumes bad data. |
| `monitor` | HIGH **and** inconclusive | A live monitor, so its own checks going dark (a downed judge, empty replies) is itself an alert. |

```bash
guardana scan .          --preset ci            # linter-style gate in CI
guardana scan ./data     --preset pre-training  # strict pre-run gate on the training box
guardana monitor --url … --model … --preset monitor
```

`--preset` and `--profile` are mutually exclusive — pass one or the other. When
you need finer control (per-rule config, custom rule directories, a wired judge),
write an explicit `guardana.yaml` as shown above; you can still ship as many
differently-named profile *files* as you like and select one with `--profile`.
