---
title: "guardana monitor"
nav_order: 150
summary: "`guardana monitor`: scheduled re-verification"
status: stable
---

# `guardana monitor` — a long-running sampling observer

`guardana monitor` runs the same endpoint rules as `probe` on an interval next to a served model when you need to detect changes. It alerts when something changes. As a **sampling observer**, it polls outside the request path; it does not intercept traffic.

```bash
guardana monitor (--url <base-url> --model <name> | --target <scheme://locator>) [OPTIONS]
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--url TEXT` | — | Base URL of the OpenAI-compatible endpoint; required unless `--target` is used |
| `--model TEXT` | — | Model name; required unless `--target` is used |
| `--target SCHEME://LOCATOR` | none | Build a trusted installed endpoint target for each cycle |
| `--target-option KEY=VALUE` | none | Repeatable, non-secret configuration passed to that target |
| `--api-key-env TEXT` | none | Env var holding the bearer API key. Unset or empty is refused (exit `3`) before the first cycle |
| `--provider [openai\|ollama\|tgi]` | `openai` | Endpoint wire protocol — same meaning as on `probe`; any other name is refused (exit `3`) |
| `--adapter PATH` | none | Adapter file for a guarded endpoint — same file and same refusals as on [`probe`](usage-probe.md#probing-a-guarded-endpoint); cannot be combined with `--provider` or `--api-key-env` |
| `--system-prompt-file PATH` | none | File containing the system prompt already deployed in front of the model — same meaning as on `probe`; a file that cannot be read is refused (exit `3`) |
| `--interval FLOAT` | `60.0` | Seconds between sampling cycles |
| `--max-cycles INTEGER` | none (run forever) | Stop after this many cycles — mainly for testing/demos |
| `--concurrency INTEGER` | `4` | How many rules may query the model at once, per cycle — same meaning as on `probe` |
| `--trials INTEGER` | `1` (or `trials:` in the profile) | Independent attempts per case in every cycle, for rules that grade a sampled reply — same meaning as on `probe`, see [`usage-probe.md`](usage-probe.md#repeated-trials). A cycle costs its requests times this |
| `--profile PATH` | none (built-in default profile) | Path to a `guardana.yaml` policy file |
| `--preset [ci\|pre-training\|monitor\|release]` | none | Named policy preset (mutually exclusive with `--profile`); `--preset monitor` fails on HIGH **and** on inconclusive — see [`profiles.md`](profiles.md#named-presets---preset) |
| `--rules PATH` | none | Directory or file of custom YAML rules; repeatable. Combined with the profile's `rules.paths` — see [`writing-rules.md`](writing-rules.md). A malformed rule file is a warning, never an abort. |
| `--reporter TEXT` | none | Forward each **alert's** findings to a collector, e.g. `server://https://collector.example.com`; an [installed reporter](outputs.md) needs a saved run, so `<name>://` is refused with exit `3` |
| `--ai-system TEXT` | none | Which AI system this watch verifies, e.g. `support-agent`, sent with each forwarded alert. Never guessed. |
| `--environment TEXT` | none | Where it runs, e.g. `production`. Never guessed from a branch name. |
| `--deployment-id TEXT` | none | Which version of it, if you have an identifier. |
| `--plugins [all\|builtins\|allowlist\|disabled]` | `builtins`, or the profile's `plugins:` | Which installed plugins to load — same meaning as on `probe`. |
| `--allow-plugin TEXT` | none | Distribution to trust; repeatable, needs `--plugins allowlist` |

Each custom-target cycle builds a fresh target from the locator, so per-cycle
budgets and usage have the same lifetime as the built-in connection. The target
flags are mutually exclusive with the built-in connection flags.

`monitor` takes no budget flags: every cycle is held to the profile's `budgets:`, each on a
meter of its own. `max_requests_per_minute` paces a cycle's requests, retries included, and
each judge's calls on the judge's own meter; a cycle whose next slot lies past
`max_duration` stops as budget-stopped. The pace starts again with each cycle's meter, so
keep `--interval` at least `60 / N` seconds for the rate to hold between cycles too.

Note: `monitor` has no `--format` flag — alerts are always printed as human
text (findings inside an alert use the `human` renderer); forward to a
collector for machine-readable persistence. The alert renders with the gate its cycle
recorded, so a cycle refused only for a skip (`fail_on_skipped`, as in `--preset release`)
says so instead of printing `✓ No findings.`

## Evidence leaves this command twice, and both are redacted

An alert is printed *and* — with `--reporter` — sent to a collector, so the
profile's [`privacy:`](privacy.md) block governs both. **In 0.7.0 it governed
neither**: the printed alert went through a renderer built with no policy, which
falls back to `full`, and the forwarded result had passed through no redactor at
all. Of the three commands that emit findings this is the one that runs unattended
for hours and ships every alert somewhere central, so it is the worst of the three
to have missed. Fixed in 0.7.1, with a test on each exit.

## What each cycle runs

Each cycle is a full probe — literally the same probe pass `guardana probe`
runs. That includes the canary handling: every cycle plants a **fresh random
canary** in a dedicated system prompt (merged with your
`--system-prompt-file` contents, if given), so the CRITICAL
`guardana.prompt.system_prompt_leak.canary` rule genuinely runs on every
cycle instead of being skipped for lack of a planted prompt. See
[`usage-probe.md`](usage-probe.md#how-canary-rules-work) for the mechanics.

With `--trials N`, every cycle makes N attempts at each case of a rule that repeats, and
all cycles use the same N, so two cycles always compare.

## How it decides to alert

On each cycle, `monitor` re-runs the full endpoint-rule set against the
target and checks three things:

1. **Gate failure** — the same `fail_on` policy check `scan`/`probe` use.
2. **A check that could not run** — more errors than the first cycle. Kept
   separate because an error is not a state a check moved into: the check
   produced nothing at all. Under a policy with `fail_on_error` turned off, a
   monitor would otherwise watch its own rules crash in silence.
3. **Deterioration against the first cycle**, decided by exactly the same code
   `guardana diff` runs (see [`usage-diff.md`](usage-diff.md)). That means a new
   problem, a problem finally proven, a rising severity, a rule that stopped
   running — and a check that used to reach a verdict and no longer can. The last
   one *lowers* the finding count, which is why comparing tallies used to read
   going blind as an improvement.

Any condition fires an alert with the cycle number and a reason
(`"gate failed"`, `"checks that could not run exceeded baseline"`, or
`"worse than the first cycle: …"` naming what moved). `monitor` never
exits on its own (unless `--max-cycles` is set) — it's meant to run as a
long-lived process (e.g. a systemd unit or sidecar container) next to your
served model.

## Exit codes

A run bounded by `--max-cycles` ends with the worst outcome any of its cycles earned.
Each cycle is judged twice: as `probe` judges a run, and against the first cycle as
[`guardana diff`](usage-diff.md#exit-codes) judges a comparison. So a cycle that fails
the policy exits `1` even when a later cycle is clean, a cycle that verified nothing
or could not be compared with the first is `2`, and a budget-stopped cycle is `6`. A
policy failure outranks a stop: each cycle is a complete run, so what one cycle proved
stays proven whatever cut a later one short. An alert raised only by a change the
policy's bar does not reach — a regression `diff` would also exit `0` for — leaves the
exit code at `0`. A cycle a transient endpoint failure prevented, or one its target
stopped part-way ([as `probe` decides it](usage-probe.md#when-the-target-fails-part-way)),
is not sampled: it is reported as a warning naming the cause, is never the cycle the
others are compared with, and proves no coverage. A finding a stopped cycle produced
before the stop is still proven, so when it fails the policy the cycle alerts (printed
and forwarded to `--reporter`) and the run exits `1`. Otherwise such a cycle earns no
exit code of its own; if no sampled cycle earned anything worse, the run exits `4`.
When the first cycle is such a cycle, the watch ends there with exit `4` and the cause
after `error:`, after alerting any failure that cycle proved. `--max-cycles 0` samples
nothing and exits `2`.

A profile that sets [`delivery.required`](profiles.md#delivery) adds one more: each alert
the collector did not acknowledge — it rejected it, could not be reached, or answered without
its own acknowledgement — is printed as an `error:` line and counted, and the watch goes on.
When the watch ends, `monitor: <n> alert deliveries not acknowledged` follows the cycle count,
and a final `0`, `1` or `2` becomes `8`; `4`, `6` and `7` stay. Without the key a failed
alert delivery is a warning and changes no code.

An unbounded run never ends on its own. Ctrl-C exits `7` whatever the cycles before
it found — the alerts already printed are the record of those cycles, and the code
says the watch did not finish. See [`exit-codes.md`](exit-codes.md).

## Example

```console
$ guardana monitor --url http://localhost:11434 --model llama3 --interval 300 --max-cycles 3
--- ALERT (cycle 1): gate failed ---
✖ [HIGH] guardana.prompt.jailbreak.dan_style — Jailbreak via persona override and encoding smuggling
    No refusal marker found; response likely complied.  (http://localhost:11434#llama3)

1 finding(s); 8 rule(s) run, 0 skipped.
```

Skipped checks are part of that trailing count: rules the target does not
offer (e.g. a2a rules, or rules needing `plant_system_prompt`/`seeded_data`
against a plain chat endpoint) are reported as skipped rather than run.

## Forwarding alerts to a collector

```bash
guardana monitor --url http://localhost:11434 --model llama3 --reporter server://https://collector.example.com
```

## Trying it without a live model

`monitor` needs a running OpenAI-compatible endpoint — if `--url` is
unreachable, the command reports a clear connection error and exits
non-zero instead of sampling forever. The fastest way to get one locally:

```bash
ollama serve &
ollama pull llama3
guardana monitor --url http://localhost:11434 --model llama3 --max-cycles 1
```

Any other OpenAI-compatible local server (vLLM, HF-TGI, LM Studio, etc.)
works the same way — just point `--url`/`--model` at it.

Each alert's `ScanResult` is submitted to the collector as it fires, tagged
with `<url>#<model>` as the source.
