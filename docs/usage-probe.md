# `guardana probe` — one-shot dynamic checks against a live endpoint

Runs every **endpoint**-kind rule once against a live chat endpoint:
direct prompt injection, jailbreak attempts (single-turn and multi-turn
scenarios), indirect (RAG) injection, system-prompt leakage (via a planted
canary), output-secret leakage, excessive tool-use agency (when the endpoint
supports tool calling), and unbounded output (denial-of-wallet). Each dynamic
finding carries a `Verdict` — `outcome`, `confidence`, `rationale`,
`evaluator_id` — from the rule's configured Evaluator.

By default the endpoint is OpenAI-compatible (`POST /v1/chat/completions` —
Ollama's `/v1`, vLLM, llamafile, LM Studio, and friends). `--provider ollama`
speaks Ollama's native `/api/chat` instead, and `--provider tgi` speaks
Hugging Face TGI's `/generate`.

```bash
guardana probe --url <base-url> --model <name> [OPTIONS]
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--url TEXT` (required) | — | Base URL of the OpenAI-compatible endpoint |
| `--model TEXT` (required) | — | Model name to send in each request |
| `--api-key-env TEXT` | none | Name of an environment variable holding the bearer API key |
| `--provider [openai\|ollama\|tgi]` | `openai` | Endpoint wire protocol: OpenAI-compatible (default), Ollama's native `/api/chat`, or HF TGI's `/generate` |
| `--system-prompt-file PATH` | none | File containing the system prompt already deployed in front of the model, so non-canary rules probe the real configuration |
| `--profile PATH` | none (built-in default profile) | Path to a `guardana.yaml` policy file |
| `--preset [ci\|pre-training\|monitor]` | none | Named policy preset (mutually exclusive with `--profile`) — see [`profiles.md`](profiles.md#named-presets---preset) |
| `--format [human\|json\|sarif\|junit]` | `human` | Output format |
| `--rules PATH` | none | Directory or file of custom YAML rules; repeatable. Combined with the profile's `rules.paths` — see [`writing-rules.md`](writing-rules.md). A malformed rule file is a warning, never an abort. |
| `--reporter TEXT` | none | Forward findings to a collector, e.g. `server://https://collector.example.com` |

## How canary rules work

Rules that need `plant_system_prompt` (the system-prompt-leak canary rule and
the indirect-injection scenario) run in their **own** probe pass, each against a dedicated endpoint
target whose system prompt is your `--system-prompt-file` contents (if any)
plus a Guardana-generated line embedding a **fresh random canary token**
minted for that run — the static canary value in the rule's YAML only marks
the rule as canary-capable and is never used for detection, so a model can't
have been trained around it. All other
endpoint rules run together in a single pass against your endpoint as
configured. This means one `probe` invocation may issue multiple batches of
requests — this is expected and is what lets an unmodifiable canary
co-exist with your real system prompt.

## Example invocation and output

```console
$ guardana probe --url http://localhost:11434 --model llama3 --api-key-env OLLAMA_API_KEY
✖ [CRITICAL] guardana.prompt.system_prompt_leak.canary — System prompt leakage via canary marker
    Planted canary marker found in response.  (http://localhost:11434#llama3)
✖ [HIGH] guardana.prompt.injection.ignore_previous — Prompt injection via instruction override
    No refusal marker found; response likely complied.  (http://localhost:11434#llama3)

2 finding(s); 8 rule(s) run, 0 skipped.
```

Every dynamic finding's evidence pairs with a verdict: run
`--format json` to see `outcome`, `confidence`, and `rationale` per finding.

A check that ran but could not reach a verdict — an unreachable judge, an
empty model reply — is reported separately as `? [UNVERIFIED]` (the
`unverified` key in JSON), never silently counted as a pass; set
`fail_on_inconclusive: true` in your profile to make it fail the gate.

## Rules graded by an LLM judge

The `llm_judge` and `guard` evaluators need a model of their own, wired from
an `evaluators:` block in `guardana.yaml` — see
[`profiles.md`](profiles.md#config-wired-evaluators-llm_judge-and-guard). With
no block configured, a rule that names one of them is **skipped visibly** in
the run summary rather than silently passed.

## Exit codes

Same policy gate as `scan` (see [`profiles.md`](profiles.md)): exits `1` if
any finding at or above `fail_on.severity` also meets `fail_on.min_confidence`,
else `0`.

## Forwarding to a collector

```bash
guardana probe --url http://localhost:11434 --model llama3 --reporter server://https://collector.example.com
```

## Trying it without a live model

`probe` needs a running OpenAI-compatible endpoint — if `--url` is
unreachable, the command reports a clear connection error and exits
non-zero rather than hanging. The fastest way to get one locally:

```bash
ollama serve &
ollama pull llama3
guardana probe --url http://localhost:11434 --model llama3
```

Any other OpenAI-compatible local server (vLLM, HF-TGI, LM Studio, etc.)
works the same way — just point `--url`/`--model` at it.
