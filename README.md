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
[![OWASP LLM Top 10](https://img.shields.io/badge/mapped-OWASP%20%C2%B7%20MITRE%20ATLAS%20%C2%B7%20NIST-informational.svg)](#what-it-checks)
[![PyPI](https://img.shields.io/pypi/v/guardana-cli.svg)](https://pypi.org/project/guardana-cli/)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Quickstart](#quickstart) · [Features](FEATURES.md) · [Rule catalog](docs/generated/rule-catalog.md) · [Docs](docs/index.md) · [Status & limits](docs/product-status.md) · [Roadmap](ROADMAP.md) · [Partner with us](#partner-with-us)

</div>

---

**51 security checks to start. You add the ones only your team can know about.**
No account, no telemetry, no phone-home. The only network traffic is to the target you
point it at — and to a collector, if you run one and ask for it.

## Why this one

Sending an attack is easy. Knowing whether it **landed** is not. Fujitsu Research
measured keyword-based judging of jailbreak attempts and found misclassification
rates up to **37%** against human labels
([arXiv:2410.16527](https://arxiv.org/abs/2410.16527)) — a limit of keyword grading
as a technique, not of any one tool.

So Guardana is built on one rule: **deterministic evidence where the question allows
it, a graded verdict where it does not, and an explicit "could not tell" where
neither is honest.**

- **Grading is a swappable component, not a regex at the end of a probe.** Every
  graded finding carries an outcome, a confidence, a rationale and the id of the
  `Evaluator` that produced it, and that judge's confidence is *measured* — Brier
  score, expected calibration error — by `guardana calibrate`.
  Proof carries no confidence: a planted canary coming back is not a judgement.
- **"Nothing found" has four meanings, so it has four channels.** `findings`,
  `unverified` (a check ran and could not conclude), `errors` (a check never ran),
  and a **coverage shortfall** (evidence you demanded and this run could not get).
  None is quietly a pass, and the last one has no switch to turn it off.
- **Unknown is never zero.** An exhausted budget exits `6` and keeps what it found.
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
guardana init                          # write a starter guardana.yaml
guardana scan . --format sarif         # SARIF 2.1.0 for GitHub code scanning

guardana probe --url http://localhost:11434 --model llama3 --preset ci --output run.json
guardana diff accepted-run.json run.json   # 0 nothing worse · 1 it is · 2 cannot tell
```

Or write it as a test — same rules, same policy, same redaction, same three-state
gate, and a run that could not reach a verdict raises as loudly as one that found
something ([`docs/usage-testing.md`](docs/usage-testing.md)):

```python
from guardana.adapters.langchain import langchain_target
from guardana.testing import assert_secure


def test_the_repository_ships_no_dangerous_artifact():
    assert_secure("models", preset="ci")


def test_the_agent_keeps_its_instructions_to_itself(chat_model):
    assert_secure(langchain_target(chat_model, system_prompt=SYSTEM), preset="ci")
```

### Before you point an active check at anything that matters

A probe sends real requests, costs real money, and may trip a provider's abuse
detection — **prefer staging**. Guardana never executes a real tool (tool calls go
to doubles), but a *model* wired to real tools by its own deployment can act on what
Guardana prompted. Evidence can contain sensitive text and is redacted by default
([`docs/privacy.md`](docs/privacy.md)). `guardana monitor` is a scheduled active
prober — never passive inspection, never inline. Full ceilings:
[`docs/safe-testing.md`](docs/safe-testing.md).

## What you do with it

One engine. The verb is what you are verifying; the target is what you point it at.

| Verb | Command | What it does |
|---|---|---|
| **Verify artifacts** | [`guardana scan <path>`](docs/usage-scan.md) | Static, offline, deterministic. Drops into a pipeline like a linter. |
| **Verify a deployed system** | [`guardana probe --url … --model …`](docs/usage-probe.md) | One-shot adversarial run against a live endpoint, agent or **MCP server** (`--mcp`), each finding graded with a confidence. |
| **Verify a recorded run** | [`guardana analyze-trace trace.jsonl`](docs/usage-analyze-trace.md) | Grades an execution your production agent already performed, read from **OpenTelemetry GenAI** spans — against the built-in checks and against your own [security contract](docs/usage-contracts.md). Opens one file and no socket. |
| **Verify what the evidence allows** | [`guardana trace inspect trace.jsonl`](docs/usage-trace-inspect.md) | Prints which evidence dimensions a producer really records, and whether the ones your policy requires are there. No coverage percentage: one number hides which dimension is missing. |
| **Continuously re-verify** | [`guardana monitor --url … --model …`](docs/usage-monitor.md) | Scheduled re-runs next to a served model, alerting when a cycle is worse than the first. |
| **Compare evidence** | [`guardana diff a.json b.json`](docs/usage-diff.md) | Runs no rules: reads two saved runs and answers whether the second is worse. |
| **Import somebody else's** | [`guardana import-observations results.json`](docs/usage-import-observations.md) | Reads garak, promptfoo or your own harness's results into the `unverified` channel with their provenance intact. Never exits `0` — Guardana verified nothing. |

`scan`, `probe`, `monitor` and `analyze-trace` can each forward findings to an
optional collector with `--reporter server://<url>`.

A dozen more commands make those safe to gate on — `plan` prices a run without
sending a request, `target inspect` says what an endpoint really supports, `run
inspect` says what was verified under which policy, `baseline` records what you have
accepted and until when, `doctor` and `config explain` say what is actually in
force. The full list is [`docs/index.md`](docs/index.md).

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
      - uses: guardana/guardana@v0.23   # moving tag → latest 0.23.x
        # with:
        #   args: --preset ci --baseline guardana-baseline.yaml
```

A **pre-commit** hook installs straight from PyPI, and there are copyable templates
for GitLab, Jenkins and Azure DevOps — [`docs/integrations.md`](docs/integrations.md).

## What it checks

51 built-in rules, every finding tagged into the frameworks your compliance process
already speaks — **both editions** of the OWASP LLM Top 10, the OWASP Top 10 for
Agentic Applications (ASI), the OWASP MCP Top 10, OWASP ML Top 10, MITRE ATLAS
v5.6.0 and NIST AI 100-2e2025. A reference names its edition, because `LLM07` is
System Prompt Leakage in 2025 and Misinformation in 2026.

| Family | Rules | Surface | What it covers |
|---|---|---|---|
| `guardana.supply_chain.*` | 16 | build | pickle opcodes, unsafe deserialization sinks, `trust_remote_code`, config `auto_map` and kernel-dispatch RCE, chat-template SSTI, ONNX graphs, notebooks, Keras/TF code execution, advisory-backed malicious and hallucinated dependencies, insecure transport, hardcoded secrets, provenance |
| `guardana.prompt.*` | 7 | build + runtime | hidden-instruction rules-file backdoors and MCP tool poisoning on the file; injection, DAN-style jailbreak, canary-proven system-prompt leak, unbounded consumption and cost asymmetry against a live model |
| `guardana.agent.*` | 7 | runtime | tool-result injection, credential exfiltration through a tool argument, over-broad tool arguments, excessive tool use, memory poisoning across a session boundary, hidden context in a tool schema, a live MCP server's tool manifest |
| `guardana.mcp.*` | 8 | runtime | a live MCP server's **authorization surface**, over either revision of the protocol: unauthenticated access, discovery a conforming client can use, audience validation, session binding, scope breadth, discovery targets, issuer identification, cache scope |
| `guardana.trace.*` | 9 | runtime | a **recorded** execution: a credential in a tool argument, one credential across two trust boundaries, a token outside its audience, a session standing in for an identity, a scope nobody consented to, a policy decision the run went ahead against, a consequential effect nobody approved, a retrieval that crossed a tenant boundary, an agent that gained authority across a handoff |
| `guardana.scenario.*` | 2 | runtime | multi-turn conversations — a gradual jailbreak and indirect (RAG) injection — graded per step and as a whole |
| `guardana.output.*` | 1 | runtime | secrets in what the model said |
| `guardana.training.*` | 1 | build | training-data integrity |

The static 19 (`artifact` surface) need no model and no network — they are the CI
front door. The dynamic 32 (`endpoint` and `trace` surfaces) grade a live model, a
live MCP server, or an execution that already happened.

**Every rule id, severity and framework mapping** — generated from what is actually
installed, including third-party rules you have added — is
[`docs/generated/rule-catalog.md`](docs/generated/rule-catalog.md); `guardana rules`
prints the same list locally. The complete capability surface, with recipes, is
[`FEATURES.md`](FEATURES.md).

## Where Guardana fits

Complementary to most of the landscape rather than a replacement:

| Category | Examples | Guardana's relationship |
|---|---|---|
| **Model/artifact scanners** | ModelScan, picklescan | Overlapping — the static layer does this and reads more formats |
| **Red-team harnesses** | garak, PyRIT, promptfoo, DeepTeam | Complementary, and honestly: **they ship more attacks.** Several also ship CI integration, stored evals and scheduled re-runs — promptfoo documents self-hosting and model-drift scanning, Giskard documents continuous red teaming (checked 2026-08-20). What Guardana differs on is the *semantics*: an exhausted budget, an ungradable reply and missing coverage are three distinct outcomes, none of which is a pass. `import-observations` reads their results into Guardana's report |
| **Evaluation frameworks** | DeepEval, Ragas | Different job — they measure whether the answer is *good*, Guardana whether the system is *safe*. Run both |
| **Runtime guardrails** | LlamaFirewall, Llama Guard | Different job — Guardana verifies and gates, never inline |
| **AI observability** | LangSmith, Langfuse | Complementary — their OpenTelemetry output is `analyze-trace`'s input |
| **SAST / CVE / secrets** | Semgrep, Trivy, gitleaks | Complementary — Guardana stays dedicated to AI-specific risk |

Where Guardana differs: **the evidence record is the product.** A run says what it
checked, what it could not check, and on what sample — so "fewer findings" is
separable from "less coverage", and a comparison that cannot honestly be made is
refused rather than reported as no change. Comparisons here name a source and a date
rather than claiming firsts; the neighbours ship fast and this table is re-checked
each release.

## Your application has its own threat model

The 51 built-ins cover the risks everybody shares. The dangerous behaviour in *your*
application depends on your data, your tools, your permissions and your business
logic, and no public framework knows any of that. A support agent and a coding agent
should not have the same security policy.

So Guardana is five extension points — **Target, Rule, Evaluator, Report/Finding,
Profile** — plus a **Registry** that discovers rules and evaluators identically
whether they ship here or in your own private package. You add coverage by adding
one of those, never by patching the engine.

- **A rule** says what must never happen — declarative YAML or a Python plugin
  ([`docs/writing-rules.md`](docs/writing-rules.md)). `guardana new-rule` scaffolds
  one; `--rules <dir>` runs it with no packaging.
- **A security contract** states an application's invariants as data — one tenant
  per run, refunds need a human, this boundary never receives a credential
  ([`docs/usage-contracts.md`](docs/usage-contracts.md)).
- **An evaluator** decides how *your* organisation grades a reply. Two ship wired
  from config: `llm_judge` (any OpenAI-compatible endpoint, versioned rubric) and the
  optional `guard` safety classifier.
- **A target** connects Guardana to the stack you actually run, and the framework
  catalogue is open too — register your own control set through the
  `guardana.taxonomies` entry point.

[`examples/custom_rule/`](examples/custom_rule/) is a real third-party package doing
all four — it registers through every one of the entry-point groups, which is how a
documented seam stops being one nobody has run — and CI runs its fixtures on every
push. `guardana-core` is a plain
library you can drive from your own code if you do not want the CLI at all —
[`docs/architecture.md`](docs/architecture.md) ·
[`docs/extending.md`](docs/extending.md).

## Central monitoring — self-hosted or managed

Every run works **fully offline**. When you want fleet-wide visibility, any run can
forward its normalized findings to a collector with `--reporter server://…`:
self-hosted `guardana-server` (OSS, PostgreSQL, opt-in dashboard), or a managed
version of the same thing, planned.

> **Maturity: beta.** Every route carrying a finding requires a **scoped API key**;
> one project cannot read another's; a key may be pinned to one environment. A run
> records what it verified and where. Findings carry a **lifecycle with waivers that
> expire**, every state change is **audited**, and retention and deletion are
> commands an operator runs on purpose. **Still missing: RBAC and human identities**
> — the panel signs in with a read key, not as a person.
> [`docs/usage-collector.md`](docs/usage-collector.md) ·
> [`docs/deployment.md`](docs/deployment.md)

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
| **0.17** | The evidence matrix made visible and gateable — `guardana trace inspect`, and a policy that can *require* dimensions — plus **security contracts**: the application's own invariants (tenant boundary, required approval, allowed scopes, credential boundary, forbidden sink) as a versioned file the engine compiles into rules. A contract that could not be checked is `indeterminate`, never a pass, and no policy setting can turn that off |
| **0.18** | What a third party needs before the API freezes: `guardana rule test` running a rule's positive, negative and **inconclusive** fixtures; a versioned pack manifest and `guardana pack validate`, refusing an extension API this build cannot honour in **both** directions; and an evaluator's measured calibration carried into the run document rather than left null |
| **0.19** | Documentation generated onto guardana.dev from this repository's own prose and its own registry, with a **rule explorer** whose every filter is a pre-rendered page — because `script-src 'none'` is a claim a visitor checks, not a default. Plus a round-trip gate on the run manifest, which found the `deployment` block written on every run and read back on none |
| **0.20** | The pack author's last mile: `guardana pack lock` pins every installed extension by what it **is** — rules by their hashed declaration, so a sharpened corpus is visible where a version pin says nothing moved — and manifest schema 2 lets a pack declare the control catalogue it registers, which nothing could say before. Plus a round-trip gate on **every** persisted schema, which found a re-read run claiming its target metered nothing, and an approved MCP manifest whose server field the reader discarded |
| **0.21** | An agent can write its own trace and say **who** approved what: `approver_kind` makes "a person agreed" and "the agent's own gate allowed it" two different facts, so a contract demanding human oversight stops being satisfied by an auxiliary LLM auto-approving `rm -rf`. Plus a file that says where it ends, so a producer killed mid-session no longer reads as one that finished with nothing to report — and a run in which every check declined stops exiting `0` |
| **0.22** | A run records what it **measured**, not only what was wrong: one entry per graded case, passes included, so "fewer findings" stops being indistinguishable from "fewer cases graded" — and `diff` refuses to compare a case whose test definition changed. Plus the extension contract made true (a third-party target now runs the built-in rules, which the docs promised from 0.1 and thirty-five `isinstance` checks prevented), one owner per rule id with the distribution recorded in the evidence, and property tests over every parser that reads a file somebody else wrote |
| **0.23** *(current)* | The extension surface held to its own contract: the reference third-party package now implements the `FileReader` surface it declares and proves every rule with a finding, a clean **and** an inconclusive sample, so `guardana rule test 'acme.*'` exits 0 instead of reporting five gaps. Plugin trust became one policy rather than six — every command that discovers resolves it through one resolver, and a refusal now **refuses** instead of being reported as a verdict: `target inspect` no longer says every rule can run over an empty registry, and `pack validate` no longer accuses a pack of failing to register what it does register. Plus a layering contract and CodeQL enforced by tooling rather than discipline, and ten more per-area coverage floors |
| **next** | RAG as a live target — a retriever that *sends* has its own budget surface and its own answer to who owns the corpus — then sink-aware output handling |
| **1.0** | A compatibility contract — the point where a third-party rule pack is a safe investment. Not a feature count: it says what will not break under you |

Beyond 1.0 the plan is kept as **milestones rather than version numbers**, because a
milestone named for a version tells a reader the wrong thing the moment a breaking
change moves the number. Exit criteria, what is deliberately deferred and why, and
the non-goals: [`ROADMAP.md`](ROADMAP.md). Release history:
[`CHANGELOG.md`](CHANGELOG.md).

## Documentation

- [`docs/index.md`](docs/index.md) — the map
- [`docs/product-status.md`](docs/product-status.md) — **read first**: maturity per component and the limits worth knowing
- [`docs/how-it-works.md`](docs/how-it-works.md) — the whole product, A to Z
- [`docs/install.md`](docs/install.md) · [`docs/profiles.md`](docs/profiles.md) · [`docs/exit-codes.md`](docs/exit-codes.md)
- [`docs/threat-model.md`](docs/threat-model.md) · [`docs/privacy.md`](docs/privacy.md) · [`docs/safe-testing.md`](docs/safe-testing.md)

**Why "Guardana"?** **Guard** + **-ana**, the suffix in *Americana*: a collected
body of a thing. A living corpus of guardianship for AI — a short, pronounceable,
invented word rather than another *shield-*/*sentinel-*/*guard-X*, verified
unclaimed across PyPI, npm and GitHub before a line was written.

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
  already reports into.
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
