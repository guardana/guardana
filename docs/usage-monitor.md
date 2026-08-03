# `guardana monitor` — a long-running sampling observer

Runs the same endpoint rules as `probe`, but repeatedly, on an interval,
next to a served model — and alerts when something changes. It is
explicitly a **sampling observer**, not an inline production sidecar: it
polls, it doesn't intercept traffic.

```bash
guardana monitor --url <base-url> --model <name> [OPTIONS]
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--url TEXT` (required) | — | Base URL of the OpenAI-compatible endpoint |
| `--model TEXT` (required) | — | Model name to send in each request |
| `--api-key-env TEXT` | none | Env var holding the bearer API key |
| `--provider [openai\|ollama\|tgi]` | `openai` | Endpoint wire protocol — same meaning as on `probe` |
| `--system-prompt-file PATH` | none | File containing the system prompt already deployed in front of the model — same meaning as on `probe` |
| `--interval FLOAT` | `60.0` | Seconds between sampling cycles |
| `--max-cycles INTEGER` | none (run forever) | Stop after this many cycles — mainly for testing/demos |
| `--concurrency INTEGER` | `4` | How many rules may query the model at once, per cycle — same meaning as on `probe` |
| `--profile PATH` | none (built-in default profile) | Path to a `guardana.yaml` policy file |
| `--preset [ci\|pre-training\|monitor]` | none | Named policy preset (mutually exclusive with `--profile`); `--preset monitor` fails on HIGH **and** on inconclusive — see [`profiles.md`](profiles.md#named-presets---preset) |
| `--rules PATH` | none | Directory or file of custom YAML rules; repeatable. Combined with the profile's `rules.paths` — see [`writing-rules.md`](writing-rules.md). A malformed rule file is a warning, never an abort. |
| `--reporter TEXT` | none | Forward each **alert's** findings to a collector, e.g. `server://https://collector.example.com` |
| `--plugins [all\|builtins\|allowlist\|disabled]` | `all` | Which installed plugins to load — same meaning as on `probe`. Added in 0.7.1; before that `monitor` was the one command with no way to restrict what it imported. |
| `--allow-plugin TEXT` | none | Distribution to trust; repeatable, needs `--plugins allowlist` |

Note: `monitor` has no `--format` flag — alerts are always printed as human
text (findings inside an alert use the `human` renderer); forward to a
collector for machine-readable persistence.

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

## Example

```console
$ guardana monitor --url http://localhost:11434 --model llama3 --interval 300 --max-cycles 3
--- ALERT (cycle 1): worse than the first cycle: appeared ---
✖ [HIGH] guardana.prompt.jailbreak.dan_style — Jailbreak via persona override and encoding smuggling
    No refusal marker found; response likely complied.  (http://localhost:11434#llama3)

1 finding(s); 8 rule(s) run, 0 skipped.
```

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
