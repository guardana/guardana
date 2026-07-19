# Extending Guardana

The engine (`guardana-core`) knows almost nothing about specific threats —
it knows how to discover rules, run them against targets, and evaluate
outcomes. All domain knowledge lives in **rules**, **evaluators**, and
**targets**. Add coverage for a new threat, model category, or backend by
adding one of these — never by patching the engine. Read
[`architecture.md`](architecture.md) first for the shapes referenced below.

Every extension point works identically whether it lives in this repo
(upstreamed, shared) or in your own private package (kept internal) — same
base classes, same discovery mechanism where discovery exists.

## The public import surface

Everything an extension implements or touches is re-exported at the top of
`guardana.core`, so plugin code needs one import line:

```python
from guardana.core import (
    Capability, Evaluator, Evidence, Finding, Registry, Rule, RuleContext,
    RuleMeta, Runner, ScanResult, Severity, Target, TargetKind,
)
```

The deeper module paths used elsewhere in these docs
(`guardana.core.rule.Rule`, `guardana.core.target.Capability`, ...) remain
valid — the re-exports are the same objects. The full list is
`guardana.core.__all__`: `Capability`, `Evaluator`, `Evidence`,
`Exchange`, `Expectation`, `FailOn`, `Finding`, `Policy`, `Profile`,
`ProfileError`, `Provenance`, `Registry`, `Rule`, `RuleContext`, `RuleError`,
`RuleLoadError`, `RuleMeta`, `Runner`, `ScanResult`, `Severity`, `Surface`,
`Target`, `TargetKind`, `TaxonomyRef`, `Verdict`, and `__version__`.

## Adding a Rule

See [`writing-rules.md`](writing-rules.md) for the full guide (YAML schema,
Python plugin shape, and how [`examples/custom_rule/`](../examples/custom_rule/)
ships one of each). Short version: implement `guardana.core.rule.Rule` (or
drop a YAML file matching the catalog schema into a rule directory) and
register it via the `guardana.rules` entry point in your package's
`pyproject.toml`.

## Adding an Evaluator

An `Evaluator` turns a model response (or artifact observation) into a
`Verdict` — the "did it succeed, and how sure are we" judgment that's
Guardana's core differentiator. Implement:

```python
from guardana.core.evaluator import Evaluator, Expectation, Verdict
from guardana.core.exchange import Exchange

class MyEvaluator(Evaluator):
    id = "acme.severity_classifier"

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        # exchange.reply_text is the model's last reply (None when there is no
        # assistant text to grade — return "inconclusive" then, never "pass");
        # exchange.transcript is the whole conversation, for multi-turn goals.
        # expectation carries whatever the rule declared under `expect:`.
        if exchange.reply_text is None:
            return Verdict("inconclusive", 0.0, "no reply to grade", self.id)
        ...
        return Verdict(
            outcome="fail",       # "pass" | "fail" | "inconclusive"
            confidence=0.85,      # 0.0-1.0 — surfaced in every finding this grades
            rationale="...",      # short, human-readable justification
            evaluator_id=self.id,
        )
```

The fail-closed convention above is project law, not a style choice: an
evaluator that cannot actually grade returns `"inconclusive"` (surfaced on
the run's `unverified` channel), never a confident all-clear.

Register it the same way as a rule:

```toml
[project.entry-points."guardana.evaluators"]
my_evaluators = "acme_rules:provide_evaluators"
```

where `provide_evaluators()` returns an `Evaluator` instance or a list of
them. A YAML rule references your evaluator by its string `id` in its
`evaluator:` field, exactly as it would a built-in — swapping graders never
touches the rule.

[`examples/custom_rule/`](../examples/custom_rule/) ships a complete, runnable
one: `StrictRefusalClassifier` (id `acme.strict_refusal`, registered via the
`guardana.evaluators` entry point) plus a YAML rule that grades with it, and
tests proving it's discovered and used end-to-end — a package can mix built-in
and custom evaluators freely, referencing either by id. For the built-in
shapes, `guardana.core.evaluator.{keyword,canary,length,llm_judge,guard}` are
five small one-file examples spanning cheap heuristic, exact marker match,
reply-length lead, LLM-judge, and safety-classifier patterns. (`llm_judge` and `guard` need a
model of their own and are wired from the profile's `evaluators:` block —
see [`profiles.md`](profiles.md#config-wired-evaluators-llm_judge-and-guard).)

## Adding a Target

A `Target` is a uniform interface over the thing under test
(`guardana.core.target.Target`), so a rule never hard-codes whether it
talks to a file or a live model:

```python
from guardana.core.target import Capability, Target, TargetKind

class MyTarget(Target):
    kind = TargetKind.ARTIFACT   # or TargetKind.ENDPOINT

    def capabilities(self) -> set[Capability]:
        return {Capability.READ_FILES}

    @property
    def ref(self) -> str:
        return "..."  # stable identifier used in findings/reports

    # add whatever read/interaction surface your rules need, e.g. an
    # iter_files()-style method (ArtifactTarget) or a chat()-style method
    # (EndpointTarget) — there's no fixed interface beyond the base Target
```

Built-ins are `ArtifactTarget` (files: pickles, GGUF, ONNX, ML formats,
requirements/lockfiles, manifests) and `EndpointTarget`
(OpenAI-compatible / Ollama / vLLM / HF-TGI chat). A rule declares the
capabilities it needs via `required_capabilities` in `RuleMeta`; the
`Runner` skips a rule whose target can't satisfy them rather than crashing
— so a new `Target` subclass is usable by any existing rule that only needs
capabilities your target also provides (e.g. a new artifact-like target
that provides `READ_FILES` can run all 17 build-time artifact rules unmodified).

**`guardana.targets` is discovered by `Registry.discover()`**, the same way
as rules and evaluators (see
[`architecture.md`](architecture.md#current-entry-point-groups)): register a
`Target` subclass (the class itself, not an instance — targets are
parameterized by a path/URL at construction time) via the `guardana.targets`
entry point, and `registry.targets()` returns it. This is aimed at
library/embedding use; the CLI's own target selection remains path/URL-based
(`scan` always builds an `ArtifactTarget`, `probe`/`monitor` always build an
`EndpointTarget` via `build_endpoint()`) — a discovered custom `Target` isn't
yet CLI-selectable, only usable by code that drives a `Runner` directly.

## The entry-point contract (rules, evaluators & targets)

| Group | Provides | Loaded by |
|---|---|---|
| `guardana.rules` | one `Rule`, or an iterable of `Rule`s | `Registry.discover()` |
| `guardana.evaluators` | one `Evaluator`, or an iterable | `Registry.discover()` |
| `guardana.targets` | one `Target` subclass, or an iterable | `Registry.discover()` |

A package registers by adding to its `pyproject.toml`:

```toml
[project.entry-points."guardana.rules"]
my_rules = "acme_rules:provide_rules"

[project.entry-points."guardana.evaluators"]
my_evaluators = "acme_rules:provide_evaluators"

[project.entry-points."guardana.targets"]
my_targets = "acme_rules:provide_targets"
```

`provide_rules()` / `provide_evaluators()` are zero-argument callables
returning an instance or a list of instances. Any pip-installed package —
ours or a third party's private one — is discovered identically; there is
no built-in/custom distinction at the registry level, only namespacing by
`id`. `guardana scan --no-plugins` (and the equivalent bare `Registry()`)
disables entry-point discovery entirely — see
[`SECURITY.md`](../SECURITY.md) for why this exists and when to use it.

## Testing your extension

Every public `Rule`, `Evaluator`, and `Target` should ship with tests: a
rule needs a positive and a negative fixture (proving it fires on a bad
input and stays silent on a good one — this is the project's main defense
against the false-positive/false-negative failure mode dynamic checks are
prone to); an evaluator needs a test per `outcome` it can produce; a target
needs a test that `capabilities()` and its read/interaction surface behave.
[`examples/custom_rule/tests/`](../examples/custom_rule/tests/) shows the
pattern end-to-end for a rule package, including a discovery-proving test
you can copy.

For dynamic (endpoint) rules, `guardana.core.testing` ships transport test
doubles — `ScriptedTransport` (canned replies, records requests),
`RefusingTransport` (a well-behaved model that refuses everything),
`EchoingTransport` (discloses its planted system prompt — the canary-leak
fixture), `ToolCallingScriptedTransport` (calls the tools it was told to — the
excessive-agency fixture), and `FailingTransport` (raises like an unreachable
endpoint) — that plug into `EndpointTarget`'s `ChatTransport` seam, so both
fixtures run against a scripted model with no network. Worked example:
[`writing-rules.md`](writing-rules.md#testing-a-dynamic-rule-without-a-model).
