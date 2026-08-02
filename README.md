<div align="center">

# 🛡️ Guardana

**Open-source AI security verification, from build to production.**

Guardana scans AI artifacts, probes deployed models and agents, records
reproducible security evidence, and detects regressions between releases.
Run it locally, in CI/CD, as scheduled health checks, or with an optional
self-hosted collector.

[![CI](https://github.com/guardana/guardana/actions/workflows/ci.yml/badge.svg)](https://github.com/guardana/guardana/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![Status: beta](https://img.shields.io/badge/status-beta-yellow.svg)](docs/product-status.md)
[![OWASP LLM Top 10](https://img.shields.io/badge/mapped-OWASP%20%C2%B7%20MITRE%20ATLAS%20%C2%B7%20NIST-informational.svg)](#standards-and-architecture)
[![PyPI](https://img.shields.io/pypi/v/guardana-cli.svg)](https://pypi.org/project/guardana-cli/)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Quickstart](#quickstart) · [Features](FEATURES.md) · [Rule catalog](docs/generated/rule-catalog.md) · [Docs](docs/index.md) · [Status & limits](docs/product-status.md) · [Roadmap](ROADMAP.md) · [Partner with us](#partner-with-us)

</div>

---

> **Status.** The CLI and engine are **beta** — used to gate real builds, with the
> public API still moving between minor releases. The self-hosted collector is
> **experimental**: in-memory storage and no authentication, suitable for local
> evaluation, not yet for team production use. See
> [product status and known limitations](docs/product-status.md) before adopting.

- No account, no telemetry, no phone-home. The only network traffic is to the target you point it at.
- Offline static scanning; explicit `findings`, `unverified` and `errors` channels.
- Confidence and evaluator provenance on every dynamic verdict.
- SARIF, JSON, JUnit, CI gates, and release-to-release comparison.

## Why Guardana exists

AI systems have several security boundaries: the model artifact and its
dependencies, the prompts and templates, the endpoint's behaviour, the tools and
credentials an agent holds, retrieval and memory, and every deployment change
after that. Most tools cover one of them.

The harder problem is the verdict. Sending an attack is easy; knowing whether it
**landed** is not. Fujitsu Research measured keyword-based judging of jailbreak
attempts and found misclassification rates of up to **37%** against human labels
([arXiv:2410.16527](https://arxiv.org/abs/2410.16527)) — a limitation of *keyword
grading as a technique*, not a measurement of any particular tool. A check that
cannot tell a refusal from a compliance is not a security control.

**Guardana's approach:** deterministic evidence where the question allows it, an
evaluator-graded verdict where it does not, and an explicit "could not tell" where
neither is honest. Grading is a first-class, versioned, swappable component — the
**Evaluator** — so every dynamic finding carries an `outcome`, a `confidence`, a
`rationale`, and the id of the evaluator that produced it. Our own judge's
confidence is *measured* (Brier score and expected calibration error via
`guardana calibrate`), not asserted.

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

## Where Guardana fits

The AI-security tooling landscape has distinct categories, and Guardana is
complementary to most of them rather than a replacement:

| Category | Examples | What it does | Guardana's relationship |
|---|---|---|---|
| **Model/artifact scanners** | ModelScan, picklescan | Inspect model files for unsafe serialization | Overlapping — Guardana's static layer does this and reads more formats |
| **Red-team harnesses** | garak, PyRIT, promptfoo, DeepTeam | Generate and send large volumes of attacks | Complementary, and honestly: **they ship more attacks than Guardana does.** What they do not ship is an exit-code contract, a cost ceiling, a saved run, or a regression comparison — which is what makes a check something a pipeline can block on |
| **Evaluation frameworks** | DeepEval, Ragas | Measure answer quality: faithfulness, relevancy, hallucination | Different job — they measure whether the answer is *good*, Guardana verifies whether the system is *safe*. Run both |
| **Runtime guardrails** | LlamaFirewall, Llama Guard | Block or filter in the request path | Different job — Guardana verifies and gates, it is never inline |
| **AI observability** | LangSmith, Langfuse and friends | Trace and debug application behaviour | Complementary — trace ingestion is on the roadmap so their output becomes Guardana's input |
| **SAST / CVE / secrets** | Semgrep, Trivy, gitleaks | General code and dependency security | Complementary — Guardana stays dedicated to AI-specific risk |

What Guardana adds that none of the above provides as its primary job: **a
reproducible evidence record per run, and a verdict on whether the next release is
worse than the last one.**

## Quickstart

Run it with zero install straight from PyPI:

```bash
uvx --from guardana-cli guardana scan .        # zero-install run (uv)
# or add it to a project:
uv add guardana-cli        # or: pip install guardana-cli
```

The console script is `guardana`; its distribution is `guardana-cli` (which pulls
in `guardana-core`/`guardana-rules`/`guardana-report`), hence the `--from`.
Working on Guardana itself? Clone and `uv sync` instead — see
[`docs/install.md`](docs/install.md).

See it find something real — a bundled deliberately-vulnerable model directory
(from a clone; run `uv run guardana …` inside the checkout):

```console
$ uv run guardana scan examples/vulnerable-model

✖ [CRITICAL] guardana.supply_chain.pickle_opcode — Dangerous pickle opcode (arbitrary code on load)
    unpickling imports non-allowlisted callable: posix.system  (examples/vulnerable-model/model.pt)
✖ [HIGH] guardana.supply_chain.dependency_risk — Unsafe model/deserialization loader call
    torch.load without weights_only=True  (examples/vulnerable-model/load_model.py:3)
✖ [CRITICAL] guardana.supply_chain.remote_code_config — Model config requests custom-code execution on load
    '_attn_implementation_internal' names a Hub kernel repository transformers downloads and imports on load  (examples/vulnerable-model/config.json)
▲ [MEDIUM] guardana.supply_chain.hallucinated_package — Import of unknown package (possible slopsquat lead)
    import 'torchutilz' isn't a known package or a declared dependency  (examples/vulnerable-model/train.py:1)

12 finding(s); 19 rule(s) run, 0 skipped.
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

### Test a deployed model

```bash
guardana probe --url http://localhost:11434 --model llama3 \
  --preset ci --format json --output run.json
```

### Compare a release against the last accepted one

```bash
guardana diff accepted-run.json run.json
```

Exit `0` means nothing got worse, `1` means it did, and `2` means the two runs
could not honestly be compared — see [`docs/usage-diff.md`](docs/usage-diff.md).

### Before you probe anything that matters

Active checks send real requests and cost real money. Read this once:

- **Prefer staging.** A probe against production consumes tokens and may trip a
  provider's abuse detection.
- **Guardana never executes a real tool** — tool calls go to doubles. But a *model*
  wired to real tools by its own deployment can act on what Guardana prompted.
- **Evidence can contain sensitive text.** It is redacted by default; do not enable
  full evidence collection without reading
  [`docs/privacy-and-redaction.md`](docs/design/privacy-and-redaction.md).
- **`guardana monitor` is a scheduled active prober**, not passive traffic
  inspection and not an inline firewall.

> **On PyPI:** [`guardana-cli`](https://pypi.org/project/guardana-cli/) ·
> [`guardana-core`](https://pypi.org/project/guardana-core/) ·
> [`guardana-rules`](https://pypi.org/project/guardana-rules/) ·
> [`guardana-report`](https://pypi.org/project/guardana-report/) ·
> [`guardana-server`](https://pypi.org/project/guardana-server/) — all Apache-2.0,
> published via PyPI Trusted Publishing (no stored token).

## Four things you do with it

One engine, four verbs:

| Verb | Command | What it does |
|---|---|---|
| **Verify artifacts** | `guardana scan <path>` | Fast, static, no-network scan of a repository or model directory. Drops into a pipeline as a linter-like gate. |
| **Verify a deployed system** | `guardana probe --url … --model …` | One-shot adversarial run against a live target: prompt injection, single- and multi-turn jailbreaks, system-prompt leakage, agent trajectories, output-secret checks — each graded by an Evaluator with a confidence. |
| **Continuously re-verify** | `guardana monitor --url … --model …` | Scheduled re-runs next to a served model, alerting when a cycle is worse than the first. |
| **Compare evidence** | `guardana diff before.json after.json` | Runs no rules: reads two saved runs and answers whether the second is worse. Exit `2` — never a quiet `0` — when they cannot honestly be compared. |

**Targets, not modes.** `probe` points at an OpenAI-compatible endpoint, an Ollama
or HF TGI server, a guarded endpoint via an adapter, or a **live MCP server**
(`--mcp`). Those are targets the same verb supports, not separate ways to run the
tool.

> **What `monitor` is, precisely.** `guardana monitor` performs **scheduled
> synthetic security checks** against a configured target. It does **not** passively
> inspect production user traffic and does **not** sit inline in the request path.
> If you need in-path blocking, you need a guardrail product; Guardana verifies
> and gates.

`scan`, `probe` and `monitor` can each forward findings to an optional collector
with `--reporter server://<collector-url>` (see
[central monitoring](#central-monitoring--self-hosted-or-managed)).

Full flag references and example output:
[`docs/usage-scan.md`](docs/usage-scan.md) ·
[`docs/usage-probe.md`](docs/usage-probe.md) ·
[`docs/usage-diff.md`](docs/usage-diff.md) ·
[`docs/usage-monitor.md`](docs/usage-monitor.md).

### And five commands that make those four safe to gate on

| Command | Answers |
|---|---|
| [`guardana plan`](docs/usage-plan.md) | what would this run cost? — **without sending a request** |
| [`guardana target inspect`](docs/usage-target.md) | what does this endpoint *actually* support, as opposed to what it claims? |
| [`guardana run inspect\|migrate`](docs/usage-run.md) | what exactly was verified, at what cost, and under which policy? |
| [`guardana baseline create\|verify\|update`](docs/usage-baseline.md) | which findings have we accepted, by whom, and until when? |
| [`guardana doctor`](docs/usage-doctor.md) · `config explain` | what is this installation, and what is actually in force? |

Three properties run through all of them, and they are what make this a gate
rather than a report:

**Unknown is never zero.** A check that could not grade, a capability the provider
did not confirm, a cost nobody measured — each is its own outcome, never a pass.

**A budget cannot be used as an excuse.** A run that hits its ceiling exits `6`,
keeps what it found, and never passes; `guardana diff` refuses to read the missing
findings as an improvement.

**Exit codes are a contract.** Eight documented meanings
([`docs/exit-codes.md`](docs/exit-codes.md)), pinned by a test against the
documentation. Nothing to parse out of human-readable text.

### Drop it into GitHub Actions

The official Action scans on every push and uploads results to GitHub code
scanning (alerts annotate the exact source line):

```yaml
# .github/workflows/ai-security.yml
name: AI security
on: [push, pull_request]
jobs:
  guardana:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: guardana/guardana@v0.7   # moving tag → latest 0.7.x
        # with:
        #   args: --preset ci --baseline guardana-baseline.yaml
```

Prefer a local gate? A **pre-commit** hook installs straight from PyPI. Both are
in [`docs/integrations.md`](docs/integrations.md).

## What's in the box

Thirty-two built-in rules, every finding tagged into the frameworks your compliance
process already speaks — OWASP LLM Top 10, the OWASP Top 10 for Agentic
Applications (ASI), OWASP ML Top 10, MITRE ATLAS and NIST:

| Rule id | Severity | Kind | Standards |
|---|---|---|---|
| `guardana.supply_chain.pickle_opcode` | CRITICAL | artifact | OWASP LLM03/LLM05 · ATLAS T0018 · NIST supply-chain |
| `guardana.supply_chain.dependency_risk` | HIGH | artifact | OWASP LLM03 · NIST supply-chain |
| `guardana.supply_chain.remote_code` | HIGH | artifact | OWASP LLM03 · NIST supply-chain |
| `guardana.supply_chain.remote_code_config` | CRITICAL/HIGH | artifact | OWASP LLM03 · ATLAS T0018 · NIST supply-chain |
| `guardana.supply_chain.chat_template` | CRITICAL/HIGH | artifact | OWASP LLM03/LLM05 · ATLAS T0018 · NIST supply-chain |
| `guardana.supply_chain.onnx_graph` | HIGH/MEDIUM | artifact | OWASP LLM03/LLM05 · ATLAS T0018 · NIST supply-chain |
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
| `guardana.agent.excessive_tool_use` | HIGH | endpoint | OWASP LLM06 · ASI02 · ATLAS T0053 |
| `guardana.agent.tool_result_injection` | CRITICAL | endpoint | OWASP LLM01 · ASI01/ASI02 · ATLAS T0053/T0086 |
| `guardana.agent.credential_exfiltration` | CRITICAL | endpoint | OWASP LLM02 · ASI03 · ATLAS T0086/T0098 |
| `guardana.agent.tool_argument_scope` | HIGH | endpoint | OWASP LLM06 · ASI02 · ATLAS T0053/T0101 |
| `guardana.agent.memory_poisoning` | CRITICAL | endpoint | OWASP LLM01 · ASI06 · ATLAS T0080 |
| `guardana.agent.mcp_server_manifest` | CRITICAL/HIGH | endpoint | OWASP LLM01/LLM03 · ASI04 · ATLAS T0110/T0109 |
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

Every finding carries typed references into **OWASP LLM Top 10 (2025)**, the
**OWASP Top 10 for Agentic Applications (ASI01–ASI10)**, **OWASP ML Top 10
(2023)**, **MITRE ATLAS v5.6.0**, and **NIST AI 100-2e2025** attack classes — so
results are filterable and reportable by whichever framework your audit already
uses. The list is not closed: register your own control catalogue through the
`guardana.taxonomies` entry point and rules can map to it the same way.

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

> **Maturity: experimental.** The collector today keeps submissions **in memory**
> and has **no authentication**. It is suitable for local evaluation and
> development, not for team production use. Persistence (PostgreSQL), migrations,
> API-key authentication, project isolation, a finding lifecycle, an audit log and
> backup/restore are the v0.7 milestone — see
> [the collector design](docs/design/collector-domain-model.md). The label moves to
> `beta` when that ships.

- **Self-hosted (`guardana-server`, OSS):** aggregate findings from every
  agent — dev machines, CI, live monitors — in one place. Ingest/list/trend over
  a versioned JSON API, plus an **opt-in monitoring dashboard**
  (`GUARDANA_DASHBOARD=1`, off by default) — a single self-contained page with
  severity, per-source/per-rule, and activity-over-time views.
- **Managed cloud (planned):** the same collector, hosted for you, with
  dashboards, multi-team rollups, retention, and policy management — for teams
  that would rather not run it themselves.

Either way the engine stays fully independent: `guardana-core` never imports
`guardana-server`, even transitively — a boundary enforced by a test, not just a
promise. The collector is strictly additive; the engine delivers its full value
with or without it.

**What stays free, stated plainly:** the engine and every built-in rule are open
source permanently. If a managed service happens, it can only ever charge for
*hosting* and for *curated content* (language- and industry-specific attack
corpora, extended advisory data) — never for a security capability withheld from
the OSS build. That boundary is written into the project's
[principles](CLAUDE.md) and its [roadmap](ROADMAP.md).

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

Guardana 0.6 is a reliable static front door, an evaluator-graded dynamic core, a
result that distinguishes "found nothing" from "could not tell" from "never ran",
and a release-to-release regression gate. The next milestones are ordered by one
question — *what does a real company need before it can adopt this?* — which is
why platform work comes before coverage volume.

| Version | Outcome |
|---|---|
| **0.6** | Regression between runs — `guardana diff`, saved runs, one definition of "worse" |
| **0.7** *(current)* | Engine and CLI foundation — run manifest, usage accounting, budgets and `plan`, capability inspection, evidence redaction, safety modes, plugin trust, baseline lifecycle, stable exit codes |
| **0.8** | The company-ready remainder (persistent authenticated collector, containers, CI beyond GitHub, SBOM) and application-aware verification — a common trace model, imported real agent traces, sink-aware output handling, live retrieval targets |
| **0.9** | Team security platform — AI systems, deployments, RBAC, finding lifecycle, integrations |
| **1.0** | Stable extension platform — the point where a third-party rule pack is a safe investment |
| **1.1** | Continuous production verification — OTLP, replay, repeated runs with confidence intervals |
| **1.2** | Agent and protocol security — deep MCP, multi-agent identity and delegation |
| **1.3** | Multimodal and advanced assurance — images, documents, OCR, audio, adaptive attackers |

Language and industry corpora grow in a **parallel content lane** that does not
gate the platform work — corpus size is not the metric this project competes on.

The detailed version — exit criteria per milestone, what is deliberately deferred
and why, the commercial boundary, and the non-goals — is
[`ROADMAP.md`](ROADMAP.md). What ships *today*, with counts generated from the
registry rather than typed by hand, is [`FEATURES.md`](FEATURES.md) and the
[rule catalog](docs/generated/rule-catalog.md).

## Documentation

- [`docs/index.md`](docs/index.md) — documentation map
- [`docs/how-it-works.md`](docs/how-it-works.md) — **the whole product, A to Z** (engine, layers, extensions)
- [`docs/install.md`](docs/install.md) — installation
- [`docs/usage-scan.md`](docs/usage-scan.md) · [`docs/usage-probe.md`](docs/usage-probe.md) ·
[`docs/usage-diff.md`](docs/usage-diff.md) · [`docs/usage-monitor.md`](docs/usage-monitor.md)
- [`docs/profiles.md`](docs/profiles.md) — the `guardana.yaml` policy file
- [`docs/integrations.md`](docs/integrations.md) — GitHub Action & pre-commit
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

Reach out: **hello@guardana.io** · [guardana.dev](https://guardana.dev) ·
[github.com/guardana](https://github.com/guardana)

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Use it, ship it, build on it.

<div align="center">
<sub>Built to guard the AI you run yourself.</sub>
</div>
