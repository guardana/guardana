<div align="center">

# 🛡️ Guardana

**Security verification for self-hosted and self-built AI —
model files, live endpoints, and agents — from one rule engine
that runs on your laptop, in CI, and next to a served model.**

[![CI](https://github.com/guardana/guardana/actions/workflows/ci.yml/badge.svg)](https://github.com/guardana/guardana/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](#roadmap)
[![OWASP LLM Top 10](https://img.shields.io/badge/mapped-OWASP%20%C2%B7%20MITRE%20ATLAS%20%C2%B7%20NIST-informational.svg)](#standards-and-architecture)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Quickstart](#quickstart) · [Features](FEATURES.md) · [The 25 rules](#whats-in-the-box) · [Docs](docs/index.md) · [Architecture](docs/architecture.md) · [Roadmap](ROADMAP.md) · [Partner with us](#partner-with-us)

</div>

---

## Why Guardana exists

Existing AI red-team scanners (garak, Giskard, PyRIT, CyberSecEval, and
friends) are good at *sending* attacks. Their shared, documented weakness is
telling you whether an attack **actually succeeded**: keyword-graded dynamic
checks misjudge outcomes at rates reported as high as **37%**
([Fujitsu Research, 2024](https://arxiv.org/abs/2410.16527)).
A scanner that can't tell a refusal from a compliance isn't a security tool —
it's a random number generator with a progress bar.

**Guardana's answer:** treat *"did it succeed, and how confident are we?"* as a
first-class, pluggable, versioned component — the **Evaluator** — instead of
bolting a regex onto the end of a probe. Every dynamic finding carries an
`outcome`, a `confidence`, a `rationale`, and the id of the evaluator that
produced it. Grading logic is swappable without touching the rule that produced
it, and the confidence is right there in the report so you know how much to
trust it.

Static supply-chain checks (pickle opcodes, unsafe model formats, dependency
risk) don't have this problem — they're deterministic. So Guardana ships them
as the reliable, no-false-positive-theater **front door**, and builds
evaluator-graded dynamic checks and a live monitor around that core.

## How it compares

Most tools do one of these things well. Guardana's bet is that the team running
a self-hosted model wants one engine covering the model file, the live endpoint,
*and* the running service — with a confidence on every dynamic verdict.

| | Static model-artifact scan | Live endpoint probe | Long-running monitor | Graded confidence (not keyword) | OWASP-LLM / ATLAS mapping | SARIF / CI gate |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| **Guardana** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| garak | — | ✅ | — | partial | partial | partial |
| ModelScan | ✅ | — | — | n/a | — | — |
| promptfoo | — | ✅ | — | ✅ | — | ✅ |
| PyRIT | — | ✅ | — | partial | — | — |
| Giskard | — | ✅ | — | ✅ | partial | — |

<sub>Checkmarks reflect each tool's primary, documented focus as of July 2026 —
these are excellent tools with different goals, not competitors to dismiss.
Corrections welcome via PR.</sub>

## Quickstart

Guardana is a `uv` workspace. Until the packages land on PyPI (see
[Roadmap](#roadmap)), install from source:

```bash
git clone https://github.com/guardana/guardana
cd guardana
uv sync
```

See it find something real — a bundled deliberately-vulnerable model directory:

```console
$ uv run guardana scan examples/vulnerable-model

✖ [CRITICAL] guardana.supply_chain.pickle_opcode — Dangerous pickle opcode (arbitrary code on load)
    unpickling imports non-allowlisted callable: posix.system  (examples/vulnerable-model/model.pt)
✖ [HIGH] guardana.supply_chain.dependency_risk — Unsafe model/deserialization loader call
    torch.load without weights_only=True  (examples/vulnerable-model/load_model.py:3)
▲ [MEDIUM] guardana.supply_chain.hallucinated_package — Import of unknown package (possible slopsquat lead)
    unknown import 'torchutilz' (lead — verify it exists on PyPI)  (examples/vulnerable-model/train.py:1)

3 finding(s); 17 rule(s) run, 0 skipped.
```

That exits `1` — the same signal a CI gate reads. Now point it at your own code:

```bash
uv run guardana scan path/to/your/project   # static scan of a repo or model dir
uv run guardana rules                  # list every discovered rule + its standards tags
uv run guardana init                   # write a starter guardana.yaml policy file
uv run guardana new-rule acme.prompt.demo  # scaffold a custom YAML rule (run via --rules)
uv run guardana scan . --format sarif  # SARIF 2.1.0 for GitHub code scanning
uv run guardana --version              # print the installed version
```

(Running `guardana scan .` at the repo root exits `1` on purpose — this repo
bundles the deliberately-vulnerable `examples/vulnerable-model/` fixture. Point
it at `packages/` for a clean run.)

> **PyPI coming soon.** Once published you'll be able to run
> `uvx --from guardana-cli guardana scan .` with zero install, or
> `uv add guardana-cli`. Until then, the source checkout above is the supported
> path. (The console script is `guardana`; its distribution is `guardana-cli`,
> hence `--from`.)

## Three ways to run it

One engine, three entry points, no separate tools to learn:

| Mode | Command | Use it for |
|---|---|---|
| **Dev / CI** | `guardana scan <path>` | Fast, static, no-network scan of a repo or model directory. Drops into a pipeline as a linter-like gate. |
| **Live probe** | `guardana probe --url <endpoint> --model <name>` | One-shot dynamic run against a live endpoint: prompt injection, jailbreak (single-turn and multi-turn scenarios), system-prompt leakage, output-secret checks — each graded by an Evaluator with a confidence. OpenAI-compatible by default; `--provider ollama\|tgi` speaks Ollama's native `/api/chat` or HF TGI's `/generate`. |
| **Monitor** | `guardana monitor --url <endpoint> --model <name>` | Long-running sampling observer next to a served model; alerts on policy-gate failure, a rise in findings over baseline, or a rise in *unverified* checks — a model whose safety checks go blind is itself the alert. |

Any of the three can forward findings to an optional central collector with
`--reporter server://<collector-url>` (see [central monitoring](#central-monitoring--self-hosted-or-managed)).

Full flag references and example output:
[`docs/usage-scan.md`](docs/usage-scan.md) ·
[`docs/usage-probe.md`](docs/usage-probe.md) ·
[`docs/usage-monitor.md`](docs/usage-monitor.md).

### Drop it into GitHub Actions

Works today, straight from the repo (no PyPI needed) — scans on every push and
uploads results to GitHub code scanning:

```yaml
# .github/workflows/ai-security.yml
name: AI security
on: [push, pull_request]
jobs:
  guardana:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - name: Scan for AI supply-chain risk
        run: >
          uvx --from
          git+https://github.com/guardana/guardana#subdirectory=packages/guardana-cli
          guardana scan . --format sarif > guardana.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()           # upload findings even when the gate fails the build
        with:
          sarif_file: guardana.sarif
```

## What's in the box

Twenty-five built-in rules, every finding tagged into the frameworks your compliance
process already speaks:

| Rule id | Severity | Kind | Standards |
|---|---|---|---|
| `guardana.supply_chain.pickle_opcode` | CRITICAL | artifact | OWASP LLM03/LLM05 · ATLAS T0018 · NIST supply-chain |
| `guardana.supply_chain.dependency_risk` | HIGH | artifact | OWASP LLM03 · NIST supply-chain |
| `guardana.supply_chain.remote_code` | HIGH | artifact | OWASP LLM03 · NIST supply-chain |
| `guardana.supply_chain.remote_code_config` | HIGH | artifact | OWASP LLM03 · ATLAS T0018 · NIST supply-chain |
| `guardana.supply_chain.notebook_payload` | HIGH | artifact | OWASP LLM03 · NIST supply-chain |
| `guardana.training.dataset_integrity` | MEDIUM | artifact | OWASP LLM04 · ML02 · NIST poisoning |
| `guardana.supply_chain.code_execution` | HIGH | artifact | OWASP LLM03 · NIST supply-chain |
| `guardana.supply_chain.insecure_transport` | HIGH | artifact | OWASP LLM03 · NIST supply-chain |
| `guardana.supply_chain.keras_lambda` | HIGH | artifact | OWASP LLM05 · ML06 · ATLAS T0018 |
| `guardana.supply_chain.saved_model_ops` | MEDIUM | artifact | OWASP LLM05 · ML06 · ATLAS T0018 |
| `guardana.supply_chain.malicious_dependency` | HIGH | artifact | OWASP LLM03 · ML06 · ATLAS T0018 |
| `guardana.supply_chain.model_format` | HIGH | artifact | OWASP LLM03/LLM05 · NIST supply-chain |
| `guardana.supply_chain.hallucinated_package` | MEDIUM | artifact | OWASP LLM03 |
| `guardana.supply_chain.provenance` | MEDIUM | artifact | OWASP LLM03 · NIST supply-chain |
| `guardana.supply_chain.hardcoded_secret` | HIGH | artifact | OWASP LLM02 |
| `guardana.output.secrets` | HIGH | endpoint | OWASP LLM02 |
| `guardana.prompt.injection.ignore_previous` | HIGH | endpoint | OWASP LLM01 · ATLAS T0051 |
| `guardana.prompt.mcp_tool_poisoning` | HIGH | artifact | OWASP LLM01/LLM05 · ATLAS T0051 |
| `guardana.prompt.hidden_instructions` | HIGH | artifact | OWASP LLM01/LLM05 · ATLAS T0051 |
| `guardana.prompt.jailbreak.dan_style` | HIGH | endpoint | OWASP LLM01 |
| `guardana.scenario.gradual_jailbreak` | HIGH | endpoint | OWASP LLM01 · ATLAS T0051 |
| `guardana.scenario.indirect_injection` | HIGH | endpoint | OWASP LLM01/LLM08 · ATLAS T0051 |
| `guardana.agent.excessive_tool_use` | HIGH | endpoint | OWASP LLM06 |
| `guardana.prompt.unbounded_consumption` | MEDIUM | endpoint | OWASP LLM10 |
| `guardana.prompt.system_prompt_leak.canary` | CRITICAL | endpoint | OWASP LLM07 · ATLAS T0056 |

The static seventeen (`artifact` kind) need no model and no network — they're the
CI front door. The dynamic eight (`endpoint` kind) probe a live model and grade
the result through an Evaluator; two of them (`scenario.gradual_jailbreak` and
`scenario.indirect_injection`) are **multi-turn scenarios** — declarative YAML
conversations graded per step and as a whole. `guardana rules` prints this list generated from what's actually
installed, **including any third-party rules you've added.**

A dynamic check that *cannot* reach a verdict — an unreachable judge, an empty
model reply — is never dropped into a false all-clear: it is reported in a
separate **unverified** channel in all four output formats, and
`fail_on_inconclusive: true` in your profile makes it fail the gate.

The complete, maintained capability surface — with recipes for what you can
build on it — is [`FEATURES.md`](FEATURES.md).

## Standards and architecture

Every finding carries typed references into **OWASP LLM Top 10 (2025)**, **OWASP
ML Top 10 (2023)**, **MITRE ATLAS v5.6.0**, and **NIST AI 100-2e2025** attack
classes — so results are filterable and reportable by whichever framework your
audit already uses.

Guardana is built on five extension points — **Target, Rule, Evaluator,
Report/Finding, Profile** — plus a **Registry** that discovers rules and
evaluators identically whether they ship in this repo or in your own private
package. The engine knows almost nothing about specific threats; all domain
knowledge lives in rules, evaluators, and targets. You add coverage by adding
one of those — never by patching the engine.

**Treat it as a framework, not just a CLI.** Because every extension point is a
small public base class discovered through standard Python entry points, you can
adapt Guardana to your own stack without forking it: ship your organization's
threat rules under your own `acme.*` namespace, bring your own **classifier**
(an `Evaluator` — the "did the attack succeed, and how sure are we" grader) when
the built-ins aren't strict enough, or teach it a new backend with a custom
`Target`. Two config-wired evaluators ship ready to point at your own models:
**`llm_judge`** (an LLM judge behind any OpenAI-compatible endpoint — a local
vLLM or Ollama works — with a versioned rubric and confidence measured as
agreement across samples) and the optional **`guard`** safety classifier
(Llama Guard / Granite Guardian style); both are enabled by an `evaluators:`
block in `guardana.yaml` ([docs/profiles.md](docs/profiles.md)). Keep it private or upstream it — the contract is identical either way,
and `guardana-core` is a plain library you can drive from your own code
(`Registry` + `Runner`) if you don't want the CLI at all.

- Author a rule as **declarative YAML** ("send this prompt, grade with this
  evaluator") or as a **Python plugin** — [`docs/writing-rules.md`](docs/writing-rules.md).
  `guardana new-rule` scaffolds the YAML, and the repeatable `--rules <dir>`
  flag (or `rules.paths` in `guardana.yaml`) runs it with no packaging.
- A complete, runnable example third-party package lives at
  [`examples/custom_rule/`](examples/custom_rule/) — a plugin rule, two YAML
  rules, and a **custom classifier** (`Evaluator`), all discovered via entry
  points. Install it and `guardana rules` shows its `acme.*` rules alongside the
  built-ins.
- The full model: [`docs/architecture.md`](docs/architecture.md) ·
  [`docs/extending.md`](docs/extending.md).

## Central monitoring — self-hosted or managed

Every scan, probe, and monitor run works **fully offline** — no network calls
beyond the target itself, no account, no lock-in. When you want fleet-wide
visibility, any run can forward its normalized findings to a collector with
`--reporter server://…`:

- **Self-hosted (`guardana-server`, OSS):** aggregate findings from every
  agent — dev machines, CI, live monitors — in one place. Ingest/list/trend over
  a versioned JSON API, plus an **opt-in monitoring dashboard**
  (`GUARDANA_DASHBOARD=1`, off by default) — a single self-contained page with
  severity, per-source/per-rule, and activity-over-time views. Auth and
  persistent storage are on the [roadmap](ROADMAP.md).
- **Managed cloud (planned):** the same collector, hosted for you, with
  dashboards, multi-team rollups, retention, and policy management — for teams
  that would rather not run it themselves.

Either way the engine stays fully independent: `guardana-core` never imports
`guardana-server`, even transitively — a boundary enforced by a test, not just a
promise. The collector is strictly additive; the engine delivers its full value
with or without it.

## Why "Guardana"?

**Guard** + **-ana**. *Guard* is the whole job — standing watch over the models,
endpoints, and agents you run yourself. The *-ana* suffix is the one in
*Americana* or *Victoriana*: a **collected body** of a thing. So Guardana is a
living **corpus of guardianship for AI** — the growing collection of rules,
evaluators, and checks that keep watch over your systems, together in one
engine.

It was chosen deliberately: a short, pronounceable, invented word — not another
*shield-* / *sentinel-* / *guard-X* in an already-crowded security namespace —
and verified unclaimed across PyPI, npm, and GitHub before a line was written,
so the name is the project's alone.

## Roadmap

Guardana v0.1 is the reliable static front door plus an evaluator-graded dynamic
core. Where it's headed:

| Version | Theme | Highlights |
|---|---|---|
| **v0.1** *(current)* | Reliable core | 25 rules · supply-chain + training-data + config-RCE + notebook + rules-file-backdoor · runtime: injection, jailbreaks, RAG-injection, **excessive-agency (tool-calling)**, **unbounded-consumption**, canary leak · scan/probe/monitor · LLM-judge & guard evaluators · SARIF & CI gate · plugin engine · optional collector |
| **v0.2** | Depth & calibration | OSV/CVE dependency matching + aliased imports · measured judge calibration (ECE/Brier) · engine robustness (plugin isolation, `errors` channel) · official GitHub Action & pre-commit hook |
| **v0.3** | Sharpen runtime depth | Sharpen LLM10 (finish_reason/latency signal) · deeper LLM06 tool-chains · adaptive attackers (Crescendo/GOAT) · behavioural drift gate · PII/toxicity evaluators |
| **v0.4+** | Compliance & provenance | AIBOM / CycloneDX ML-BOM export · model-signature verification · fine-tuning dataset hygiene |
| **Cloud** | Fleet visibility | Productized collector: dashboards, trends, multi-repo/model rollups, policy management — the additive layer the OSS engine already reports into |

The detailed, maintained version — priorities, what's deliberately deferred
and why, and the project's non-goals — is [`ROADMAP.md`](ROADMAP.md). See
[`CHANGELOG.md`](CHANGELOG.md) for released changes.

## Documentation

- [`docs/index.md`](docs/index.md) — documentation map
- [`docs/how-it-works.md`](docs/how-it-works.md) — **the whole product, A to Z** (engine, layers, extensions)
- [`docs/install.md`](docs/install.md) — installation
- [`docs/usage-scan.md`](docs/usage-scan.md) · [`docs/usage-probe.md`](docs/usage-probe.md) · [`docs/usage-monitor.md`](docs/usage-monitor.md)
- [`docs/profiles.md`](docs/profiles.md) — the `guardana.yaml` policy file
- [`docs/writing-rules.md`](docs/writing-rules.md) — author a rule (YAML or Python)
- [`docs/architecture.md`](docs/architecture.md) · [`docs/extending.md`](docs/extending.md)

## Contributing

Contributions are very welcome — new rules especially. Every rule maps to a
standard and ships with a positive + negative test fixture, which is how the
project stays honest about the false-positive/false-negative failure mode
dynamic checks are prone to.

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) (human contributors) and
[`CLAUDE.md`](CLAUDE.md) (AI-agent contributors) — they cover setup, the code
standards, and the single-commit PR workflow. Security issues go through
[`SECURITY.md`](SECURITY.md), never public issues.

## Partner with us

Guardana is open source and built to stay that way — but we're also looking for
the people who'll shape where it goes:

- **🏢 Design partners.** Running self-hosted or self-built AI in production and
  want Guardana wired into your CI and next to your models? Partner with us
  early — help prioritize the rules and integrations that matter to your stack,
  and get a direct line to the maintainers while the roadmap is still soft clay.
- **🧩 Rule & integration authors.** Have threat expertise, a model format, or a
  guardrail you know cold? The plugin model means your checks live in your
  package under your namespace — contribute them upstream or keep them private,
  same contract either way.
- **☁️ Cloud early access.** A managed, hosted version of the collector the OSS
  engine already reports into — dashboards, multi-team rollups, and retention,
  without running `guardana-server` yourself. If centralized AI-security posture
  is on your radar, reach out to help shape it — and use it first.
- **💬 Everyone else.** Stars, issues, ideas, and questions in
  [Discussions](https://github.com/guardana/guardana/discussions) genuinely move
  this forward.

Reach out: **hello@guardana.io** · [guardana.io](https://guardana.io) ·
[github.com/guardana](https://github.com/guardana)

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Use it, ship it, build on it.

<div align="center">
<sub>Built to guard the AI you run yourself.</sub>
</div>
