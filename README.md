<div align="center">

# 🛡️ Guardana

**Open-source AI security verification, from build to production.**

Guardana scans AI artifacts, probes deployed models and agents, grades executions
they already performed, records reproducible evidence, and tells you whether this
release is worse than the last one.

[![CI](https://github.com/guardana/guardana/actions/workflows/ci.yml/badge.svg)](https://github.com/guardana/guardana/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![Status: beta](https://img.shields.io/badge/status-beta-yellow.svg)](docs/product-status.md)
[![OWASP LLM Top 10](https://img.shields.io/badge/mapped-OWASP%20%C2%B7%20MITRE%20ATLAS%20%C2%B7%20NIST-informational.svg)](#standards-and-extensibility)
[![PyPI](https://img.shields.io/pypi/v/guardana-cli.svg)](https://pypi.org/project/guardana-cli/)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Quickstart](#quickstart) · [Features](FEATURES.md) · [Rule catalog](docs/generated/rule-catalog.md) · [Docs](docs/index.md) · [Status & limits](docs/product-status.md) · [Roadmap](ROADMAP.md) · [Partner with us](#partner-with-us)

</div>

---

No account, no telemetry, no phone-home. The only network traffic is to the target
you point it at — and to a collector, if you run one and ask for it.

## The problem Guardana is built around

Sending an attack is easy. Knowing whether it **landed** is not.

Fujitsu Research measured keyword-based judging of jailbreak attempts and found
misclassification rates up to **37%** against human labels
([arXiv:2410.16527](https://arxiv.org/abs/2410.16527)) — a limit of *keyword grading
as a technique*, not of any particular tool. A check that cannot tell a refusal from
a compliance is not a security control.

So Guardana is built on one rule: **deterministic evidence where the question allows
it, a graded verdict where it does not, and an explicit "could not tell" where
neither is honest.** Three consequences you will notice immediately:

- **Grading is a component, not a regex at the end of a probe.** Every graded finding
  carries an outcome, a confidence, a rationale and the id of the **Evaluator** that
  produced it — and that evaluator is swappable without touching the rule. Our own
  judge's confidence is *measured* (Brier score, expected calibration error) via
  `guardana calibrate`, not asserted. A finding that is proof rather than judgement —
  a planted canary coming back, a server handing its manifest to an anonymous
  caller — carries no confidence, because there is nothing to be unsure about.
- **"Nothing found" has three meanings, and they are three channels.** `findings`,
  `unverified` (a check ran and could not reach a verdict) and `errors` (a check
  never ran). A gate can fail on any of them; none of them is quietly a pass.
- **Unknown is never zero.** A budget that ran out exits `6` and keeps what it found.
  A comparison that cannot honestly be made exits `2`. A capability the target never
  confirmed is recorded as unconfirmed, not as absent.

## Quickstart

```bash
uvx --from guardana-cli guardana scan .   # zero-install run (uv)
uv add guardana-cli                       # or: pip install guardana-cli
```

The console script is `guardana`; its distribution is `guardana-cli`. Working on
Guardana itself? Clone and `uv sync` — see [`docs/install.md`](docs/install.md).

See it find something real, against a bundled deliberately-vulnerable model
directory:

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

That exits `1` — the signal a CI gate reads. Then point it at your own work:

```bash
guardana scan path/to/your/project     # static, offline, no model needed
guardana rules                         # every discovered rule + its standards tags
guardana init                           # write a starter guardana.yaml
guardana scan . --format sarif          # SARIF 2.1.0 for GitHub code scanning
```

### Probe a deployed model

```bash
guardana probe --url http://localhost:11434 --model llama3 \
  --preset ci --format json --output run.json
```

### Or write it as a test

```python
from guardana.adapters.langchain import langchain_target
from guardana.testing import assert_secure


def test_the_repository_ships_no_dangerous_artifact():
    assert_secure("models", preset="ci")


def test_the_agent_keeps_its_instructions_to_itself(chat_model):
    assert_secure(langchain_target(chat_model, system_prompt=SYSTEM), preset="ci")
```

Same rules, same policy, same redaction, same three-state gate — and a run that
could not reach a verdict raises as loudly as one that found something.
[`docs/usage-testing.md`](docs/usage-testing.md)

### Compare a release against the last accepted one

```bash
guardana diff accepted-run.json run.json
```

`0` nothing got worse · `1` it did · `2` the two runs could not honestly be
compared. [`docs/usage-diff.md`](docs/usage-diff.md)

### Before you point an active check at anything that matters

- **Prefer staging.** A probe sends real requests, costs real money, and may trip a
  provider's abuse detection.
- **Guardana never executes a real tool** — tool calls go to doubles. But a *model*
  wired to real tools by its own deployment can act on what Guardana prompted.
- **Evidence can contain sensitive text.** It is redacted by default; read
  [`docs/privacy.md`](docs/privacy.md) before turning that off.
- **`guardana monitor` is a scheduled active prober** — not passive traffic
  inspection, and never inline in the request path.

## Six things you do with it

One engine. The verb is what you are verifying; the target is what you point it at.

| Verb | Command | What it does |
|---|---|---|
| **Verify artifacts** | [`guardana scan <path>`](docs/usage-scan.md) | Static, offline, deterministic. Drops into a pipeline like a linter. |
| **Verify a deployed system** | [`guardana probe --url … --model …`](docs/usage-probe.md) | One-shot adversarial run against a live endpoint, agent or **MCP server** (`--mcp`), each finding graded with a confidence. |
| **Verify a recorded run** | [`guardana analyze-trace trace.jsonl`](docs/usage-analyze-trace.md) | Grades an execution your production agent already performed, read from **OpenTelemetry GenAI** spans. Opens one file and no socket. |
| **Continuously re-verify** | [`guardana monitor --url … --model …`](docs/usage-monitor.md) | Scheduled re-runs next to a served model, alerting when a cycle is worse than the first. |
| **Compare evidence** | [`guardana diff a.json b.json`](docs/usage-diff.md) | Runs no rules: reads two saved runs and answers whether the second is worse. |
| **Import somebody else's** | [`guardana import-observations results.json`](docs/usage-import-observations.md) | Reads garak, promptfoo or your own harness's results into the `unverified` channel with their provenance intact. Never exits `0` — Guardana verified nothing. |

`scan`, `probe`, `monitor` and `analyze-trace` can each forward findings to an
optional collector with `--reporter server://<url>`.

### Eleven commands that make those safe to gate on

| Command | Answers |
|---|---|
| [`guardana plan`](docs/usage-plan.md) | what would this run cost? — **without sending a request** |
| [`guardana target inspect`](docs/usage-target.md) | what does this endpoint *actually* support, versus what it claims? |
| [`guardana run inspect\|migrate`](docs/usage-run.md) | what exactly was verified, at what cost, under which policy? |
| [`guardana baseline create\|verify\|update`](docs/usage-baseline.md) | which findings have we accepted, by whom, and until when? |
| [`guardana taxonomy`](docs/usage-taxonomy.md) | which framework entry does this reference name, in which edition? |
| [`guardana doctor`](docs/usage-doctor.md) · `config validate\|explain` | what is this installation, and what is actually in force? |
| `guardana rules` · `new-rule` · `calibrate` · `init` | what is installed, scaffold a rule, measure a judge, start a policy |

**Exit codes are a contract** — eight documented meanings
([`docs/exit-codes.md`](docs/exit-codes.md)), pinned by a test against the
documentation. Nothing to parse out of human-readable text.

### Drop it into GitHub Actions

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
      - uses: guardana/guardana@v0.13   # moving tag → latest 0.13.x
        # with:
        #   args: --preset ci --baseline guardana-baseline.yaml
```

A **pre-commit** hook installs straight from PyPI, and there are copyable templates
for GitLab, Jenkins and Azure DevOps — [`docs/integrations.md`](docs/integrations.md).

## What it checks

47 built-in rules, every finding tagged into the frameworks your compliance process
already speaks — **both editions** of the OWASP LLM Top 10, the OWASP Top 10 for
Agentic Applications (ASI), the OWASP MCP Top 10, OWASP ML Top 10, MITRE ATLAS
v5.6.0 and NIST AI 100-2e2025. A reference names its edition, because `LLM07` is
System Prompt Leakage in 2025 and Misinformation in 2026.

| Family | Rules | Surface | What it covers |
|---|---|---|---|
| `guardana.supply_chain.*` | 16 | build | pickle opcodes, unsafe deserialization sinks, `trust_remote_code`, config `auto_map` and kernel-dispatch RCE, chat-template SSTI, ONNX graphs, notebooks, Keras/TF code execution, advisory-backed malicious and hallucinated dependencies, insecure transport, hardcoded secrets, provenance |
| `guardana.prompt.*` | 7 | build + runtime | hidden-instruction rules-file backdoors and MCP tool poisoning on the file; injection, DAN-style jailbreak, canary-proven system-prompt leak, unbounded consumption and cost asymmetry against a live model |
| `guardana.agent.*` | 7 | runtime | tool-result injection, credential exfiltration through a tool argument, over-broad tool arguments, excessive tool use, memory poisoning across a session boundary, hidden context in a tool schema, a live MCP server's tool manifest |
| `guardana.mcp.*` | 6 | runtime | a live MCP server's **authorization surface**: unauthenticated access, discovery a conforming client can use, audience validation, session binding, scope breadth, discovery targets |
| `guardana.trace.*` | 7 | runtime | a **recorded** execution: a credential in a tool argument, one credential across two trust boundaries, a token outside its audience, a session standing in for an identity, a scope nobody consented to, a policy decision the run went ahead against, a consequential effect nobody approved |
| `guardana.scenario.*` | 2 | runtime | multi-turn conversations — a gradual jailbreak and indirect (RAG) injection — graded per step and as a whole |
| `guardana.output.*` | 1 | runtime | secrets in what the model said |
| `guardana.training.*` | 1 | build | training-data integrity |

The static 19 (`artifact` surface) need no model and no network — they are the CI
front door. The dynamic 28 (`endpoint` and `trace` surfaces) grade a live model, a
live MCP server, or an execution that already happened.

**Every rule id, severity and framework mapping** — generated from what is actually
installed, including any third-party rules you have added — is
[`docs/generated/rule-catalog.md`](docs/generated/rule-catalog.md), and
`guardana rules` prints the same list locally. The complete capability surface, with
recipes, is [`FEATURES.md`](FEATURES.md).

## Where Guardana fits

Complementary to most of the landscape rather than a replacement:

| Category | Examples | Guardana's relationship |
|---|---|---|
| **Model/artifact scanners** | ModelScan, picklescan | Overlapping — the static layer does this and reads more formats |
| **Red-team harnesses** | garak, PyRIT, promptfoo, DeepTeam | Complementary, and honestly: **they ship more attacks.** What they do not ship is an exit-code contract, a cost ceiling, a saved run or a regression comparison — and `import-observations` reads their results into Guardana's report |
| **Evaluation frameworks** | DeepEval, Ragas | Different job — they measure whether the answer is *good*, Guardana whether the system is *safe*. Run both |
| **Runtime guardrails** | LlamaFirewall, Llama Guard | Different job — Guardana verifies and gates, never inline |
| **AI observability** | LangSmith, Langfuse | Complementary — their OpenTelemetry output is `analyze-trace`'s input |
| **SAST / CVE / secrets** | Semgrep, Trivy, gitleaks | Complementary — Guardana stays dedicated to AI-specific risk |

What none of them provides as its primary job: **a reproducible evidence record per
run, and a verdict on whether the next release is worse than the last.**

## Standards and extensibility

Guardana is five extension points — **Target, Rule, Evaluator, Report/Finding,
Profile** — plus a **Registry** that discovers rules and evaluators identically
whether they ship here or in your own private package. The engine knows almost
nothing about specific threats; all domain knowledge lives in rules, evaluators and
targets. You add coverage by adding one of those, never by patching the engine.

**Treat it as a framework, not just a CLI.** Ship your organization's rules under
your own `acme.*` namespace, bring your own classifier when the built-ins are not
strict enough, or teach it a new backend with a custom `Target`. Two config-wired
evaluators ship ready to point at your own models: **`llm_judge`** (any
OpenAI-compatible endpoint, versioned rubric, confidence measured as agreement
across samples) and the optional **`guard`** safety classifier (Llama Guard /
Granite Guardian style). `guardana-core` is a plain library you can drive from your
own code if you do not want the CLI at all.

- Author a rule as **declarative YAML** or as a **Python plugin** —
  [`docs/writing-rules.md`](docs/writing-rules.md). `guardana new-rule` scaffolds
  the YAML and `--rules <dir>` runs it with no packaging.
- A complete third-party package lives at
  [`examples/custom_rule/`](examples/custom_rule/) — a plugin rule, two YAML rules
  and a custom `Evaluator`, all discovered through entry points. CI runs its tests.
- The framework catalogue is open too: register your own control set through the
  `guardana.taxonomies` entry point and rules map to it like any built-in.
- The full model: [`docs/architecture.md`](docs/architecture.md) ·
  [`docs/extending.md`](docs/extending.md).

## Central monitoring — self-hosted or managed

Every run works **fully offline**. When you want fleet-wide visibility, any run can
forward its normalized findings to a collector with `--reporter server://…`.

> **Maturity: beta.** The collector keeps what it is given — PostgreSQL with
> reversible migrations, a storage choice it refuses to make for you, separate
> health and readiness endpoints. Every route carrying a finding **requires a scoped
> API key**; one **project cannot read another's**; a key may be **pinned to one
> environment**. A run records **what it verified and where** — AI system,
> environment, deployment, the commit behind it — and whether it passed its gate.
> Findings carry a **lifecycle with waivers that expire**, every state change is
> **audited**, and **retention and deletion** are commands an operator runs on
> purpose. Standing one up is three commands. **Still missing: RBAC and human
> identities** — the panel signs in with a read key, not as a person. See
> [`docs/usage-collector.md`](docs/usage-collector.md) and
> [`docs/deployment.md`](docs/deployment.md).

- **Self-hosted (`guardana-server`, OSS)** — aggregate findings from dev machines,
  CI and live monitors over a versioned JSON API, plus an opt-in dashboard
  (`GUARDANA_DASHBOARD=1`, off by default).
- **Managed cloud (planned)** — the same collector, hosted, for teams that would
  rather not run it themselves.

`guardana-core` never imports `guardana-server`, even transitively — enforced by
import-linter and a test, not by a promise.

**What stays free, stated plainly:** the engine and every built-in rule are open
source permanently. A managed service could only ever charge for *hosting* and for
*curated content* (language and industry corpora, extended advisory data) — never
for a security capability withheld from the OSS build. That boundary is written into
the project's [principles](CLAUDE.md) and its [roadmap](ROADMAP.md).

## Where this is going

| | Outcome |
|---|---|
| **0.13** *(current)* | MCP in depth — six rules over a live server's authorization surface, the OWASP MCP Top 10 installed as data, a pinned manifest covering the whole tool declaration, and `plan probe --mcp` to price a run before it costs anything |
| **next** | The remaining framework adapters as translators into that model, tool-calling through an adapter, RAG targets, sink-aware output handling, and what a single run is entitled to claim |
| **1.0** | A compatibility contract — the point where a third-party rule pack is a safe investment. Not a feature count: it says what will not break under you |

Release history is [`CHANGELOG.md`](CHANGELOG.md). Beyond 1.0 the plan is kept as
**milestones rather than version numbers** — the team platform, continuous
production verification, multi-agent protocols, multimodal assurance — because a
milestone named for a version tells a reader the wrong thing the moment a breaking
change moves the number. Language and industry corpora grow in a **parallel content
lane** that does not gate the platform work; corpus size is not the metric this
project competes on.

Exit criteria per milestone, what is deliberately deferred and why, the commercial
boundary and the non-goals: [`ROADMAP.md`](ROADMAP.md).

## Why "Guardana"?

**Guard** + **-ana** — the suffix in *Americana*: a collected body of a thing. A
living corpus of guardianship for AI. Chosen as a short, pronounceable, invented
word rather than another *shield-*/*sentinel-*/*guard-X*, and verified unclaimed
across PyPI, npm and GitHub before a line was written.

## Documentation

- [`docs/index.md`](docs/index.md) — the map
- [`docs/product-status.md`](docs/product-status.md) — **read first**: maturity per component and the limits worth knowing
- [`docs/how-it-works.md`](docs/how-it-works.md) — the whole product, A to Z
- [`docs/install.md`](docs/install.md) · [`docs/profiles.md`](docs/profiles.md) · [`docs/exit-codes.md`](docs/exit-codes.md)
- [`docs/threat-model.md`](docs/threat-model.md) · [`docs/privacy.md`](docs/privacy.md) · [`docs/safe-testing.md`](docs/safe-testing.md)

## Contributing

New rules especially. Every rule maps to a standard and ships with a positive **and**
negative test fixture — that is how the project stays honest about the
false-positive/false-negative failure mode dynamic checks are prone to.

[`CONTRIBUTING.md`](CONTRIBUTING.md) (people) and [`CLAUDE.md`](CLAUDE.md) (AI
agents) cover setup, the code standards and the single-commit PR workflow. Security
issues go through [`SECURITY.md`](SECURITY.md), never public issues.

## Partner with us

- **🏢 Design partners.** Running self-hosted AI in production and want Guardana in
  your CI and next to your models? You get a direct line to the maintainers while
  the roadmap is still soft clay.
- **🧩 Rule & integration authors.** Your checks live in your package under your
  namespace — upstream them or keep them private, same contract either way.
- **☁️ Cloud early access.** A hosted version of the collector the OSS engine
  already reports into. Reach out to help shape it and use it first.
- **💬 Everyone else.** Stars, issues and questions in
  [Discussions](https://github.com/guardana/guardana/discussions) genuinely move
  this forward.

**hello@guardana.io** · [guardana.dev](https://guardana.dev) ·
[github.com/guardana](https://github.com/guardana)

> On PyPI: [`guardana-cli`](https://pypi.org/project/guardana-cli/) ·
> [`guardana-core`](https://pypi.org/project/guardana-core/) ·
> [`guardana-rules`](https://pypi.org/project/guardana-rules/) ·
> [`guardana-report`](https://pypi.org/project/guardana-report/) ·
> [`guardana-server`](https://pypi.org/project/guardana-server/) — all Apache-2.0,
> published via PyPI Trusted Publishing (no stored token).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Use it, ship it, build on it.

<div align="center">
<sub>Built to guard the AI you run yourself.</sub>
</div>
