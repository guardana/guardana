---
title: "In your test suite"
nav_order: 50
summary: "`guardana.testing.assert_secure`: verification as an ordinary `pytest` assertion, plus the LangChain adapter"
status: stable
---

# Guardana in your test suite

`guardana.testing.assert_secure` runs Guardana from inside an ordinary `pytest`
test and fails it when the verdict is not a pass.

It exists because a security check that needs its own command, its own pipeline
stage and its own report is a check somebody runs on Tuesdays. A team already
runs `pytest`; this puts the verification where they already are, with no new
pipeline to own and no report to go and read.

Same rules, same policy, same redaction and the same three-state gate as
[`guardana scan`](usage-scan.md) and [`guardana probe`](usage-probe.md) — a
verdict does not change because the runner did.

```bash
pip install guardana-cli   # brings the engine, the rules and the reporters
```

## The two things it takes

```python
from guardana.testing import assert_secure


def test_the_repository_ships_no_dangerous_artifact():
    assert_secure("models", preset="ci")
```

**A target.** Either a path to scan — the static, offline half — or a `Target`
object for something live: an `EndpointTarget`, an `McpServerTarget`, or one of
the [framework adapters](#a-langchain-model) below.

**A policy.** `preset="ci"` (or `"pre-training"`, `"monitor"`), or
`profile=Path("guardana.yaml")`, or a `Profile` built in code. Passing both a
profile and a preset is a `ValueError`, exactly as `--profile` with `--preset` is
a usage error on the command line. With neither, the default applies: every rule,
fail on `HIGH`, evidence redacted.

A path that does not exist raises `ValueError` rather than passing. A scan pointed
at a typo finds nothing, and "no findings" from a directory nobody looked in is
the worst shape of false green there is — the same refusal `guardana scan` makes.

## What a failure looks like

```
E   guardana: 8 finding(s) at or above HIGH — examples/vulnerable-model
E
E     CRITICAL guardana.supply_chain.pickle_opcode
E              examples/vulnerable-model/model.pt
E              unpickling imports non-allowlisted callable: posix.system
E
E     HIGH     guardana.supply_chain.malicious_dependency
E              examples/vulnerable-model/requirements.txt
E              ultralytics==8.3.41: compromised build pipeline shipped a cryptominer
E              downloader; 8.3.43 is the clean release
E
E     MEDIUM   guardana.supply_chain.hallucinated_package  (below the bar)
E              examples/vulnerable-model/train.py:1
E              import 'torchutilz' isn't a known package or a declared dependency
E
E   policy: fails on HIGH and above; a check that could not run is indeterminate.
```

Findings below the failure bar are printed and marked rather than hidden: they did
not fail the build, and they are still what somebody asked this tool to look for.

The last line says what the run was told to fail on, so a surprising verdict is
explainable without going to read the profile.

## "Could not check" is not "checked and clean"

`assert_secure` raises on **anything that is not a pass**, and says which it was:

```
E   guardana: the run could not reach a verdict — http://localhost:11434#llama3
E
E     1 check(s) could not run:
E       - guardana.prompt.system_prompt_leak.canary (run): EndpointError: connection refused
E
E     6 check(s) skipped:
E       - guardana.agent.tool_result_injection: … does not support call_tools
E
E   policy: fails on HIGH and above; a check that could not run is indeterminate.
```

This is the distinction the rest of Guardana is built around, and a test suite is
where it goes quiet: an empty registry, an over-narrow profile, an endpoint that
was down, a target no installed rule applies to — every one of those used to be
indistinguishable from a clean result. The exception carries it too:

```python
from guardana.testing import SecurityAssertionError

try:
    assert_secure(target, preset="ci")
except SecurityAssertionError as failure:
    failure.outcome   # GateOutcome.FAIL or GateOutcome.INDETERMINATE
    failure.result    # the ScanResult: findings, unverified, errors, rules_run
```

Which reasons make a run indeterminate is the policy's decision, not this
function's — see [`profiles.md`](profiles.md) for `fail_on_error`,
`fail_on_inconclusive` and `fail_on_skipped`.

## Evidence in a CI log

The failure message is redacted by the profile's privacy policy before it is
raised. That is not a detail: the message goes into a CI log, which is a file on
somebody's build server, and a security tool that writes the credential it just
found into one has made a second incident out of the first.

Every preset and the default profile redact. A `Profile` you build in code
defaults to `full` evidence — see [`privacy.md`](privacy.md) — so set
`privacy=RedactionPolicy(mode=EvidenceMode.REDACTED)` if you assemble one by hand
and the result goes anywhere a person can read it.

## A live model

```python
import pytest
from guardana.core.target import EndpointTarget
from guardana.testing import assert_secure


@pytest.fixture
def local_model():
    return EndpointTarget(
        "http://localhost:11434",
        "llama3",
        provider="ollama",
        system_prompt=SYSTEM_PROMPT,   # what your application really sends
    )


def test_the_model_resists_prompt_injection(local_model):
    assert_secure(local_model, preset="ci")
```

This sends real requests and costs real money against a hosted provider. Bound it
in the profile — `budgets:` in [`profiles.md`](profiles.md) — and read
[`safe-testing.md`](safe-testing.md) before pointing it at anything that matters.
`guardana plan` prices the same run without sending a request.

Passing `system_prompt` is worth doing: without something planted, the
canary-backed system-prompt-leak rule has nothing to look for and is skipped, so
the coverage a run reports shrinks quietly.

## A LangChain model

```python
from guardana.adapters.langchain import langchain_target
from guardana.testing import assert_secure


def test_our_agent_keeps_its_instructions_to_itself(chat_model):
    target = langchain_target(chat_model, system_prompt=SYSTEM_PROMPT)
    assert_secure(target, preset="ci")
```

`langchain_target` wraps any LangChain chat model — `ChatOpenAI`,
`ChatAnthropic`, `ChatOllama`, anything with `invoke` — as an ordinary Guardana
target. It verifies the model **as your application calls it**, through whatever
client, credentials and configuration that object carries, instead of an endpoint
underneath it that nobody deployed.

`langchain` is never imported by Guardana, so it is not a dependency and no
release of it can break this. An object that is not a chat model is refused when
the target is built, not on the first prompt of a paid probe.

Three things to know:

- **Findings name it `http://langchain.invalid#<model>`.** `.invalid` is reserved
  and never resolves, so the reference says plainly that nothing was fetched over
  the network. Pass `name="support-agent"` to choose the label yourself — it is
  part of a finding's identity, so a stable one is what lets
  [`guardana diff`](usage-diff.md) line two runs up across a change of client.
- **Tool calling is wired up when the model supports it.** `bind_tools` exists on
  every LangChain chat model and raises on the ones without a function-calling API,
  so Guardana finds out by binding a throwaway tool once, at construction — it
  sends no request. A model that binds runs the six agentic rules; one that refuses
  skips them with a reason, and `fail_on_skipped: true` turns that into an
  indeterminate result rather than a pass. `guardana target inspect` shows which of
  the two you have.
- **Token budgets need a model that reports usage.** When the reply carries
  `usage_metadata` the tokens are counted; when it does not, the count is recorded
  as unknown rather than zero — so a *token* ceiling over such a model can never
  fire, while a *request* ceiling always can.

## A run your framework already performed

The adapters above *drive* a model. These translate the record of a run that
already happened into a [`Trace`](design/trace-domain-model.md), which
[`analyze-trace`](usage-analyze-trace.md)'s rules grade. Nothing is sent anywhere.

```python
from guardana.adapters.pydantic_ai import pydantic_ai_trace
from guardana.core.target import TraceTarget
from guardana.testing import assert_secure


def test_the_agent_run_holds_up(agent):
    result = agent.run_sync("refund order 7 and email the customer")
    assert_secure(TraceTarget(pydantic_ai_trace(result)), preset="ci")
```

| Adapter | Reads | Records |
|---|---|---|
| `guardana.adapters.pydantic_ai` | `AgentRunResult` from `agent.run_sync(...)` | messages with typed parts, tool calls and results |
| `guardana.adapters.llama_index` | a query `Response`, or the list `retriever.retrieve(...)` returns | messages, retrieval with per-document tenant, source and score |
| `guardana.adapters.crewai` | `CrewOutput` from `crew.kickoff(...)` | messages, the agent that performed each step, handoffs between agents |

None of the three libraries is ever imported, exactly as with `langchain_target`.

**An adapter declares only what its framework really reports**, and that is the
part worth understanding. PydanticAI records nothing about approvals, so a
PydanticAI trace does not claim to — and the rule that grades unapproved effects
is *skipped* rather than reporting that it found none. A run where nothing could
be checked prints `0 rules ran — nothing was checked (this is not an all-clear)`
and exits [`2`](exit-codes.md), which is the honest answer and not a pass.

To grade the dimensions your framework does not emit, write the trace out and add
them:

```python
from guardana.core.trace import serialize_trace

Path("run.jsonl").write_text(serialize_trace(crewai_trace(result, crew=crew)))
```

Then edit `run.jsonl` — it is the native dialect, one JSON object per line — and
run [`guardana analyze-trace run.jsonl`](usage-analyze-trace.md). The identity,
delegation, consent, policy and approval blocks are the half no framework emits
and the half where the interesting failures are.

## Choosing what is loaded

```python
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.registry import Registry


def test_with_only_guardanas_own_rules():
    trusted = Registry.discover(PluginTrust(mode=PluginMode.BUILTINS))
    assert_secure("models", preset="ci", registry=trusted)
```

Left out, `assert_secure` discovers entry-point rules and loads the rule
directories the profile names. Passed in, the registry is used exactly as given —
a registry you assembled is not one this should add to behind your back. See
[`extending.md`](extending.md) and `SECURITY.md` for what plugin trust means.

## What this is not

It is not a second engine, and it does not have its own idea of "secure". If a
check passes here and fails in CI, that is a fact about the target, not a
disagreement between two implementations.

It is also not `guardana.core.testing`, which is the other direction: test doubles
(scripted transports, crafted artifacts, fake credentials) for writing tests about
a **rule you are writing**. See [`writing-rules.md`](writing-rules.md).

## See also

- [`usage-scan.md`](usage-scan.md) · [`usage-probe.md`](usage-probe.md) — the same
  verification as commands, with reports, baselines and a collector
- [`profiles.md`](profiles.md) — what a policy can say
- [`privacy.md`](privacy.md) — evidence modes and what is kept
- [`exit-codes.md`](exit-codes.md) — the command-line equivalent of the three-state
  gate
