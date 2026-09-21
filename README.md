<div align="center">

# 🛡️ Guardana

**Open-source AI security verification for every release.**

Guardana scans model artifacts, probes live endpoints and MCP servers, and analyzes
recorded agent traces. It produces reproducible evidence and a measured verdict,
including an explicit "could not tell". Run it on your laptop, in CI, or in production,
then compare a release with its accepted baseline.

[![CI](https://github.com/guardana/guardana/actions/workflows/ci.yml/badge.svg)](https://github.com/guardana/guardana/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![Status: beta](https://img.shields.io/badge/status-beta-yellow.svg)](docs/product-status.md)
[![OWASP LLM Top 10](https://img.shields.io/badge/mapped-OWASP%20%C2%B7%20MITRE%20ATLAS%20%C2%B7%20NIST-informational.svg)](#what-it-checks)
[![PyPI](https://img.shields.io/pypi/v/guardana-cli.svg)](https://pypi.org/project/guardana-cli/)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Quickstart](#quickstart) · [Features](FEATURES.md) · [Rule catalog](docs/generated/rule-catalog.md) · [Docs](docs/index.md) · [Status & limits](docs/product-status.md) · [Roadmap](ROADMAP.md) · [Partner with us](#partner-with-us)

</div>

---

**51 security checks to start. You add the ones only your team can know about.**
No account, telemetry, or phone-home. Artifact scans are offline. Active checks
connect to the target you choose and, when configured, an optional collector.

## Why Guardana

Security verification is not useful if an unknown result becomes a pass. Guardana
keeps four outcomes separate:

- `findings`: a check reached a negative verdict;
- `unverified`: it ran but could not decide;
- `errors`: it could not run;
- coverage shortfalls: required evidence was unavailable.

Results that require judgment carry an outcome, confidence, rationale, and
evaluator identity. `guardana calibrate` measures evaluator confidence against
labelled samples.

Unknown is never zero. An exhausted budget exits `6` and preserves its results. A
comparison that cannot honestly be made exits `2`. Missing evidence is not reported
as success.

## Quickstart

```bash
uvx --from guardana-cli guardana scan .   # zero-install run (uv)
uv add guardana-cli                       # or: pip install guardana-cli
```

The console command is `guardana`; the distribution is `guardana-cli`. For a source
checkout, clone and run `uv sync` as described in
[`docs/install.md`](docs/install.md).

Every published distribution has signed, keyless build provenance that you can verify
with `gh attestation verify`, plus a PEP 740 attestation on PyPI.

Scan the bundled vulnerable model directory:

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

That run exits `1`, which makes it usable as a CI gate. Then point Guardana at your
own work:

```bash
guardana scan path/to/your/project     # static, offline, no model needed
guardana init                          # write a starter guardana.yaml
guardana scan . --format sarif         # SARIF 2.1.0 for GitHub code scanning

guardana probe --url http://localhost:11434 --model llama3 --preset ci --output run.json
guardana diff accepted-run.json run.json   # 0 nothing worse · 1 it is · 2 cannot tell
```

You can also use the same rules, policy, redaction, and gate from a test
([`docs/usage-testing.md`](docs/usage-testing.md)):

```python
from guardana.adapters.langchain import langchain_target
from guardana.testing import assert_secure


def test_the_repository_ships_no_dangerous_artifact():
    assert_secure("models", preset="ci")


def test_the_agent_keeps_its_instructions_to_itself(chat_model):
    assert_secure(langchain_target(chat_model, system_prompt=SYSTEM), preset="ci")
```

### Before active testing

A probe sends real requests. It can cost money or trigger provider abuse detection,
so prefer staging. Guardana sends tool calls to doubles, but the surrounding
application can still act on a model response. Evidence may contain sensitive text
and is redacted by default. `guardana monitor` is a scheduled active probe, not an
inline or passive monitor. See [`docs/safe-testing.md`](docs/safe-testing.md) and
[`docs/privacy.md`](docs/privacy.md).

## What you do with it

One engine verifies artifacts, deployed systems, and recorded evidence.

| Verb | Command | What it does |
|---|---|---|
| **Verify artifacts** | [`guardana scan <path>`](docs/usage-scan.md) | Static, offline checks for code and model artifacts. |
| **Verify a deployed system** | [`guardana probe --url … --model …`](docs/usage-probe.md) | Bounded active checks against a model, agent, or MCP server. |
| **Verify a recorded run** | [`guardana analyze-trace trace.jsonl`](docs/usage-analyze-trace.md) | Checks OpenTelemetry GenAI spans against built-ins and your [security contract](docs/usage-contracts.md), without opening a socket. |
| **Inspect available evidence** | [`guardana trace inspect trace.jsonl`](docs/usage-trace-inspect.md) | Shows recorded evidence dimensions and policy gaps. |
| **Continuously re-verify** | [`guardana monitor --url … --model …`](docs/usage-monitor.md) | Re-runs active checks on a schedule and alerts when a cycle is worse than the first. |
| **Compare evidence** | [`guardana diff a.json b.json`](docs/usage-diff.md) | Reports whether the later saved run is worse, or refuses an invalid comparison. |
| **Import external observations** | [`guardana import-observations results.json`](docs/usage-import-observations.md) | Imports garak, promptfoo, or custom results as `unverified`, with provenance. It never exits `0` because Guardana verified nothing. |

`scan`, `probe`, `monitor`, and `analyze-trace` can forward findings to an optional
collector with `--reporter server://<url>`.

Supporting commands cover planning, capability inspection, configuration, baselines,
run inspection, rule testing, and extension packs. See
[`docs/index.md`](docs/index.md).

**Exit codes are a contract.** They have eight documented meanings and are tested
against [`docs/exit-codes.md`](docs/exit-codes.md). CI does not need to parse console
text.

### GitHub Actions

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
      - uses: guardana/guardana@v0.26   # moving tag → latest 0.26.x
        # with:
        #   args: --preset ci --baseline guardana-baseline.yaml
```

A pre-commit hook and templates for GitLab, Jenkins, and Azure DevOps are in
[`docs/integrations.md`](docs/integrations.md).

## What it checks

51 built-in rules, mapped to both editions of the OWASP LLM Top 10, the OWASP Top 10
for Agentic Applications, the OWASP MCP Top 10, OWASP ML Top 10, MITRE ATLAS v5.6.0,
and NIST AI 100-2e2025. References include their edition so changing identifiers do
not blur the result.

| Family | Rules | Surface | What it covers |
|---|---|---|---|
| `guardana.supply_chain.*` | 16 | build | unsafe loading, remote code, model formats, dependencies, transport, secrets, and provenance |
| `guardana.prompt.*` | 7 | build + runtime | hidden instructions, tool poisoning, injection, jailbreaks, prompt leakage, and resource consumption |
| `guardana.agent.*` | 7 | runtime | tool-result injection, credential exfiltration, broad arguments, excessive use, memory poisoning, tool schemas, and MCP server manifests |
| `guardana.mcp.*` | 8 | runtime | authentication, discovery, audience, session, scope, issuer, and cache handling |
| `guardana.trace.*` | 9 | runtime | recorded credential, identity, consent, policy, approval, retrieval, effect, and handoff boundaries |
| `guardana.scenario.*` | 2 | runtime | multi-turn jailbreak and indirect-injection scenarios |
| `guardana.output.*` | 1 | runtime | secrets in model output |
| `guardana.training.*` | 1 | build | training-data integrity |

The static 19 (`artifact` surface) need no model and no network.
The dynamic 32 (`endpoint` and `trace` surfaces) grade a live model, a live MCP
server, or a recorded execution.

The generated [rule catalog](docs/generated/rule-catalog.md) lists each installed
rule id, severity, and framework mapping, including third-party rules.
`guardana rules` prints the same registry. See [`FEATURES.md`](FEATURES.md) for the complete
capability overview.

## Where Guardana fits

Guardana complements the surrounding security and evaluation stack.

| Category | Examples | Guardana's relationship |
|---|---|---|
| **Model and artifact scanners** | ModelScan, picklescan | Overlaps at the static layer and covers additional AI artifact formats. |
| **Red-team harnesses** | garak, PyRIT, promptfoo, DeepTeam | Complements their attack libraries. Guardana separates findings, inconclusive results, errors, and missing coverage, and can import their observations. |
| **Evaluation frameworks** | DeepEval, Ragas | Measures security rather than answer quality. Run both when both matter. |
| **Runtime guardrails** | LlamaFirewall, Llama Guard | Verifies and gates; it does not run inline. |
| **AI observability** | LangSmith, Langfuse | Uses OpenTelemetry output as trace-analysis input. |
| **SAST, CVE, and secret scanners** | Semgrep, Trivy, gitleaks | Adds AI-specific verification beside general application security tools. |

The evidence record is the differentiator. A run records what was checked, what
could not be checked, and the sample used. That separates fewer findings from less
coverage and prevents invalid comparisons from being reported as no change.

## Extend it for your application

The 51 built-ins cover the risks everybody shares. Your application also has risks
created by its data, tools, permissions, and business rules. A support agent and a
coding agent should not share the same security policy.

Guardana exposes five extension points: **Target, Rule, Evaluator, Report/Finding,
and Profile**. A shared registry discovers extensions from Guardana or private
packages.

- **Rules** express prohibited behavior in YAML or Python.
  [`docs/writing-rules.md`](docs/writing-rules.md) explains both forms, and
  `guardana new-rule` scaffolds one.
- **Security contracts** describe application invariants such as tenant boundaries,
  required approval, allowed scopes, and credential boundaries
  ([`docs/usage-contracts.md`](docs/usage-contracts.md)).
- **Evaluators** control how replies are graded. Configuration supports `llm_judge`
  through an OpenAI-compatible endpoint and the optional `guard` classifier.
- **Targets** connect installed, trusted systems through a declared locator scheme.
- **Taxonomies** let a package register its own control set.

[`examples/custom_rule/`](examples/custom_rule/) is a working third-party package.
The `guardana-core` library also supports embedding the engine without the CLI. See
[`docs/extending.md`](docs/extending.md) and
[`docs/architecture.md`](docs/architecture.md). The extension API remains pre-1.0;
compatibility details are in [`docs/product-status.md`](docs/product-status.md).

## Central monitoring — self-hosted or managed

The collector is optional. Local and CI verification do not depend on it. When you
need shared visibility, runs can send normalized findings to self-hosted
`guardana-server`, backed by PostgreSQL with an opt-in dashboard. A managed version
of the same collector is planned.

> **Maturity: beta.** Finding routes require scoped API keys. Projects cannot read
> each other's data, and keys can be pinned to an environment. Findings have audited
> lifecycle states and expiring waivers. Operators control retention and deletion.
> **Still missing: RBAC and human identities.** The dashboard uses a read-scoped
> session rather than a human identity.
> [`docs/usage-collector.md`](docs/usage-collector.md) ·
> [`docs/deployment.md`](docs/deployment.md)

The engine and built-in rules are Apache-2.0. Hosting and curated content are the
planned boundary for a managed service, as recorded in the project
[principles](CLAUDE.md) and [roadmap](ROADMAP.md).

## Roadmap

| | Outcome |
|---|---|
| **0.17** | Added evidence inspection, required dimensions, and versioned security contracts. Uncheckable contracts become `indeterminate`, not passes. |
| **0.18** | Added positive, negative, and inconclusive rule fixtures; versioned pack validation; and evaluator calibration in run records. |
| **0.19** | Generated repository documentation and a pre-rendered rule explorer on guardana.dev, plus run-manifest round-trip checks. |
| **0.20** | Added extension locks by hashed rule declaration, schema 2 control catalogs, and round-trip checks for persisted schemas. |
| **0.21** | Distinguished human and automated approvers, marked incomplete traces, and stopped all-declined runs from exiting `0`. |
| **0.22** | Recorded passes as assessments, rejected comparisons when test definitions changed, enabled built-in rules on third-party targets, recorded rule ownership, and added parser property tests. |
| **0.23** | Completed reference-package conformance fixtures, centralized plugin trust, corrected refusal handling, and added enforced layering, CodeQL, and ten more coverage floors. |
| **0.24** | Made installed custom target locators work across target-building commands with shared trust, kind, budget, evidence, and exit behavior. Extension API 2 defines the contract while API 1 remains compatible. |
| **0.25** | Shipped finding, clean, and inconclusive samples for scenario and agent rules, played by `guardana rule test`; 11 of 51 built-ins are fully sampled. Refused scripts that could not play and fixed false greens exposed by writing the samples. |
| **0.26** *(current)* | Added `guardana new-pack`: one command writes an installable pack — manifest, entry points, a sampled rule for each declarative shape, a locator target and tests — that passes `pack validate` and `rule test` before it is edited. Fixed `pack validate` reporting a clean result about installed packs it had never read, and `new-rule` scaffolding a rule with no samples. 0.26.1 answered the first field report from a production deployment: an artifact the scanner could not read is now inconclusive rather than a low-severity finding a gate waves through. |
| **next** | Suites with versioned datasets and assessors, then paired statistical diff, then renderer and reporter plugins. |
| **1.0** | Define the compatibility contract that makes third-party rule packs a stable investment. |

Beyond 1.0, work is organized as milestones. Exit criteria, deferrals, and non-goals
are in [`ROADMAP.md`](ROADMAP.md). Release history is in
[`CHANGELOG.md`](CHANGELOG.md).

## Documentation

- [`docs/index.md`](docs/index.md) — documentation map
- [`docs/product-status.md`](docs/product-status.md) — maturity and known limits
- [`docs/how-it-works.md`](docs/how-it-works.md) — product overview
- [`docs/install.md`](docs/install.md) · [`docs/profiles.md`](docs/profiles.md) · [`docs/exit-codes.md`](docs/exit-codes.md)
- [`docs/threat-model.md`](docs/threat-model.md) · [`docs/privacy.md`](docs/privacy.md) · [`docs/safe-testing.md`](docs/safe-testing.md)

## Contributing

New rules are especially useful. A new rule must map to a standard and ship with a
positive and a negative fixture.

[`CONTRIBUTING.md`](CONTRIBUTING.md) covers contributors, and
[`CLAUDE.md`](CLAUDE.md) covers AI agents. Security issues go through
[`SECURITY.md`](SECURITY.md), never public issues.

## Partner with us

- **🏢 Design partners.** Bring Guardana into CI and beside self-hosted production
  models, with a direct line to the maintainers.
- **🧩 Rule and integration authors.** Keep checks private under your namespace or
  contribute them upstream.
- **☁️ Cloud early access.** Join early access to the planned hosted collector.
- **💬 Everyone else.** Share issues and questions in
  [Discussions](https://github.com/guardana/guardana/discussions).

**contact@guardana.dev** · [karauda.com/contact](https://karauda.com/contact) ·
[guardana.dev](https://guardana.dev) · [github.com/guardana](https://github.com/guardana)

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Use it, ship it, build on it.

<div align="center">
<sub>Built to guard the AI you run yourself.</sub>
</div>
