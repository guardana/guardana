---
title: "Extending Guardana"
nav_order: 260
summary: "add a Rule, an Evaluator, or a Target; the entry-point contract"
status: stable
---

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
    LocatorError, RuleMeta, Runner, ScanResult, Severity, SystemPromptPlanter,
    Target, TargetKind,
)
```

The deeper module paths used elsewhere in these docs
(`guardana.core.rule.Rule`, `guardana.core.target.Capability`, ...) remain
valid — the re-exports are the same objects. The full list is
`guardana.core.__all__`: `Capability`, `Evaluator`, `Evidence`,
`Exchange`, `Expectation`, `FailOn`, `Finding`, `Policy`, `Profile`,
`ProfileError`, `Provenance`, `Registry`, `Rule`, `RuleContext`, `RuleError`,
`RuleLoadError`, `RuleMeta`, `Runner`, `ScanResult`, `Severity`, `Surface`, `LocatorError`,
`SystemPromptPlanter`, `Target`, `TargetKind`, `TaxonomyRef`, `Verdict`, and
`__version__`.

Two names live on `guardana.core.registry` rather than at the top, because they
are what the registry refuses rather than something an extension implements:
`RESERVED_NAMESPACE` is the `guardana.` prefix no third-party id may take, and
`RESERVED_TARGET_SCHEMES` is the set of locator schemes — `file`, `http`,
`https`, `mcp`, `trace` — a third-party target may not claim. Read them rather
than repeating them: a scheme refused at discovery is a pack that does not load.

## Adding a Rule

See [`writing-rules.md`](writing-rules.md) for the full guide (YAML schema,
Python plugin shape, and how [`examples/custom_rule/`](../examples/custom_rule/)
ships one of each). Short version: implement `guardana.core.rule.Rule` (or
drop a YAML file matching the catalog schema into a rule directory) and
register it via the `guardana.rules` entry point in your package's
`pyproject.toml`.

### Repeated trials in a Python rule

A YAML rule repeats under `--trials` without any work from you. A Python rule makes one
attempt per case unless it opts in, and the saved run records that it did not repeat.
Opt in only when the verdict depends on a model sampling a reply:

- `with_trials(k)` returns a copy that makes `k` attempts at every case (the default
  returns `None`: the rule does not repeat);
- `trials_per_case` reports `k`, and `estimated_requests` and `graded_verdicts` multiply by it;
- each attempt records one assessment with `from_verdict(..., trial=n)`, `n` from 1;
- a rule that grades one attempt at several checkpoints — a conversation graded per turn —
  returns `True` from `grades_one_case`, so its bound counts one case per attempt;
- `guardana.core.trials.case_outcome(verdicts)` turns a case's attempts into at most one
  finding. When a later attempt raises, yield `failed_before_stop(...)` first so a
  failure already seen is not lost.

Every attempt must start from nothing. `TrajectoryRule` rebuilds its memory store per
attempt, but a `ToolDouble` of your own that keeps state is not rebuilt: build it inside
the attempt, or the second attempt reads what the first one left.

`Rule.deterministic` is a class attribute that defaults to `False`. Set it to `True`
only for a rule that grades in its own code and stamps verdicts with its own id, as
`guardana.output.secrets` does.

### Reading calibrations and concluding

These are additive extension points for a rule:

| Extension point | Use |
|---|---|
| `RuleContext.calibrations` | Read calibrations available to the rule. |
| `RuleContext.conclude(summary)` | Record the rule's conclusion. |
| `RuleContext.shortfall(CoverageShortfall)` | Report coverage the rule could not get. It joins the run's `coverage_shortfall`, which has no switch, so the run is `indeterminate` unless a finding fails it. |
| `Rule.estimated_requests_for(target)` | Price the rule against the target it is planned for; defaults to `estimated_requests`. `plan` reads this one. |
| `Rule.not_applicable_to(target)` | Return why the rule has nothing to check on `target` as a non-empty string, or `None`. The run and the plan record the rule as skipped `not_applicable`, never as a check that ran. Any other return (`False`, `""`) is an error naming the hook and what it returned, and the rule runs. A hook that raises is also an error naming the hook and the exception, recorded in the run and the plan, and the rule runs. Only rules the profile selects are asked. |
| `raise NotOffered(detail, missing=(...))` | From `guardana.core.rule`: the rule found, while it ran, that the target does not offer what it examines. Raised before the rule yields anything, the run records it as skipped `not_offered`, a coverage gap `fail_on_skipped` refuses, and `rule test` reports the sample as `not_offered`; raised after, it is an error of the rule. See [writing rules](writing-rules.md). |
| `RuleFixture.rule` | Use the variant of the declaring rule that a sample runs. |
| `Runner(calibrations=...)` | Pass calibrations to the runner. |
| `ScanResult.suites` | Read suite results from the scan result. |

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
        # assistant text to grade — return "inconclusive" then, never "pass").
        # A blank reply is None too: a provider that answers with an empty string
        # (a content filter, a tool-call-only turn) said nothing to grade, and the
        # seam decides that once so every evaluator agrees;
        # exchange.graded_replies is every assistant reply under grade, for a
        # check of something that must never be said in any of them;
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
evaluator that cannot actually grade returns `"inconclusive"` (surfaced on the
run's `unverified` channel), never a confident all-clear. Built-in YAML,
scenario, suite, and trajectory rules and calibration all grade through
`guardana.core.evaluator.grade`. Third-party Python rules call the evaluator
directly and are covered only if they use `guardana.core.evaluator.grade`, as
they should. That function changes an evaluator's `"pass"` to `"inconclusive"`
with confidence 0.0 under that evaluator's id when the exchange has no reply
text (`reply_text is None`). A `"fail"` stands, and an exchange built from an
agent run (`exchange.trajectory` set) is exempt, because a grader of tool
calls may clear a run that ended without final text.

`Exchange.graded_from` is the index into `messages` where the turns under grade
begin; the messages before it are context. It defaults to `0`, so an agent run
or a whole conversation puts every reply under grade. A scenario step starts it
after the last reply its grader read (the same evaluator and expectation), and a suite
case or a calibration row after the turns it scripted, so text the model never said is
never graded as its reply.
A rule that builds an `Exchange` for part of a longer conversation sets it the same
way; an index outside the conversation raises.

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

### Reading a declined request: `read_decline`

An application behind a guard declines some requests; the adapter's `declines:` names
which replies are declines and reads each as `refusal` or `ungraded`
([usage-probe](usage-probe.md#declines-retried-statuses-and-metadata)). A declined
exchange carries `exchange.decline` (a `Decline` with `name`, `reading` and `status`) and
ends on the user turn the application declined, so `reply_text` is `None`.

`grade` reads a declined exchange in two steps. When assistant turns are under grade
before the decline (a scenario's earlier steps, a conversation scope), `evaluate` grades
the exchange as it is first, and a `"fail"` stands. Otherwise, or when that was not a
fail, a decline read as `ungraded` is `"inconclusive"` and one read as `refusal` is what
`Evaluator.read_decline(exchange, expectation)` returns.
`grade_decline(evaluator, exchange, expectation) -> tuple[Verdict, bool]` returns the same
verdict and whether it came from the decline; a rule tags such an assessment
`declined:<name>`.

The base `read_decline` returns `"inconclusive"`: an evaluator that grades reply text has
none to grade, so a decline never passes through an evaluator that did not say what a
refusal means for it. Override it when a refusal is a verdict for your check:

```python
class MyRefusalCheck(Evaluator):
    id = "acme.refuses"

    def read_decline(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        # The guard refused on policy, which is the refusal this check looks for.
        return Verdict("pass", 1.0, "declined by the application as a refusal", self.id)
```

A `"pass"` from `read_decline` is not turned into `"inconclusive"` for the missing reply
text. Built-ins that override it: `keyword`, `canary`, `llm_judge` and `guard` pass a
refusal at confidence `1.0` without a judge call (`llm_judge` and `guard` only when no
earlier reply is under grade, since a decline cannot clear replies they did not clear);
`answered` and `reference_judge` fail it at `1.0`, because a declined task was not
answered. Every other built-in keeps the base.

A subclass of one of those six that redefines `evaluate` gets the base reading back
(`"inconclusive"`): the built-in reading holds only for the built-in grading, and a check
that grades replies its own way has not said what a refusal means for it. Override
`read_decline` in the subclass and return your own verdict; calling `super()` from there
still reaches the base. A subclass that keeps the built-in `evaluate` (a renamed `id`, say)
keeps the built-in reading.

### Reporting a measurement

`Verdict.measurement: Measurement | None` carries `value`, `unit`, `direction` and `threshold`. `from_verdict` carries the measurement onto the assessment.

An evaluator reports one by passing it with its verdict:

```python
from guardana.core.assessment import Direction
from guardana.core.evaluator import Measurement, Verdict

Verdict(
    "pass",
    1.0,
    "reply stayed under the limit",
    self.id,
    measurement=Measurement(len(reply), "chars", Direction.LOWER_IS_BETTER, 4000),
)
```

`Assessment.comparable_key` includes unit, direction and threshold. `diff` compares measurements only when both runs carry matching values for those fields.

### Declaring grader identity and determinism

`Evaluator.deterministic` is a class attribute that defaults to `False`. Set it to
`True` only when the evaluator's verdict does not need judge-error correction, as with
`canary`; an evaluator that does not declare it is treated as a judge.
`Evaluator.judge_identity` defaults to `None`. Set it to a string that identifies the
grader configuration the evaluator id does not name; matching compares it verbatim. A saved
run records it as `run.evaluators[].judge`, and `guardana diff` leaves out of its comparison
a rule whose judge identity changed.

`Evaluator.assessor_id` is the `evaluator_id` this evaluator's verdicts carry, known before
any verdict exists; it defaults to `id`. Override it when your verdicts carry another id (the
built-in judges answer `llm_judge@<prompt_version>`): a suite trial that could not be graded
— a recording held no reply for it — is recorded under it, and an ungraded trial under any
other id would be a second assessor, which judge-error correction refuses.

```python
class MyEvaluator(Evaluator):
    deterministic = True
    judge_identity = None
```

### Declaring what grading costs

`guardana plan probe` prices judge calls from two declarations, and both default to
`None`, which the plan reports as unknown rather than free:

- `Evaluator.judge_calls_per_verdict` — the model or service calls one `evaluate()`
  makes. Declare `0` for an evaluator that computes its verdict locally.
- `Rule.graded_verdicts` — a mapping from evaluator id to the verdicts one run grades
  with it, multiplied by `trials_per_case`. Declare `{}` for a rule that grades in its
  own code. YAML rules, suites, scenarios and agent rules declare it for you.

```python
class MyEvaluator(Evaluator):
    judge_calls_per_verdict: ClassVar[int] = 0
```

Both are read-only properties on the base classes, so assigning one on an instance
(`self.judge_calls_per_verdict = n` in `__init__`) is refused. When the cost depends on
configuration, override the property:

```python
class MyJudge(Evaluator):
    def __init__(self, samples: int) -> None:
        self.samples = samples

    @property
    def judge_calls_per_verdict(self) -> int:
        return self.samples
```

While a judge is configured under `evaluators:`, a plan that includes a rule of
unknown judge cost does not claim to fit its budget.

## Adding a Target

A `Target` is a uniform interface over the thing under test
(`guardana.core.target.Target`), so a rule never hard-codes whether it
talks to a file or a live model:

A capability has two halves. `Capability` is what your target **declares**;
a protocol in `guardana.core.target.protocols` is what a rule will **call**.
Implement the protocol for every capability you declare, and the built-in rules
work against your target without knowing it exists:

```python
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Self

from guardana.core import LocatorError
from guardana.core.source import PythonSource, UnreadSource, read_source
from guardana.core.target import Capability, Target, TargetKind

class MyTarget(Target):
    kind = TargetKind.ARTIFACT   # ARTIFACT, ENDPOINT or TRACE
    scheme = "acme-files"        # optional: makes --target acme-files://... work

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)
        self._sources: dict[Path, PythonSource | None] = {}
        self._unread: list[UnreadSource] = []

    @classmethod
    def from_locator(cls, locator: str, *, options: Mapping[str, str]) -> Self:
        # Parse configuration only. `guardana plan` calls this method and must
        # not contact a remote system.
        if options:
            raise LocatorError(f"unsupported option(s): {', '.join(sorted(options))}")
        root = Path(locator)
        if not root.is_dir():
            raise LocatorError(f"{root} is not a directory")
        return cls(root)

    def capabilities(self) -> set[Capability]:
        return {Capability.READ_FILES}   # so implement `FileReader`, below

    @property
    def ref(self) -> str:
        return f"my-target:{self._root}"  # stable identifier used in findings/reports

    # --- the FileReader surface `READ_FILES` promises ---

    def iter_files(self, suffixes: tuple[str, ...] | None = None) -> Iterator[Path]:
        # Suffixes compare in any case: a loader opens `model.PKL` like `model.pkl`.
        wanted = None if suffixes is None else {suffix.lower() for suffix in suffixes}
        for path in sorted(p for p in self._root.rglob("*") if p.is_file()):
            if wanted is None or path.suffix.lower() in wanted:
                yield path

    def python_source(self, path: Path) -> PythonSource | None:
        # Cache this: every rule that inspects Python asks through here, so a
        # target that re-reads per call turns a linear scan into a quadratic one.
        if path.suffix.lower() != ".py":
            return None
        if path not in self._sources:
            result = read_source(path)
            if isinstance(result, UnreadSource):
                self._unread.append(result)
                self._sources[path] = None
            else:
                self._sources[path] = result
        return self._sources[path]

    def unread_sources(self) -> tuple[UnreadSource, ...]:
        # A file you were *prevented* from reading (too large, unopenable) —
        # the runner turns these into `errors`: a check that did not run.
        return tuple(self._unread)
```

`ref` is printed in messages and saved in the run document, SARIF and the collector
envelope as it is. Guardana cleans the refs of its own targets and cannot clean yours:
when a ref contains a URL, build it with `guardana.core.target.display_url`, which
drops userinfo and the fragment and replaces a query with a digest placeholder, and
never put a credential in it any other way. The digest keeps two targets that differ
only by a query apart; it does not hide a short or guessable value.

`read_source` and `display_url` sit outside the [supported surface](compatibility.md#the-supported-surface), unlike `PythonSource` and `UnreadSource`: a minor release may change them, so pin `guardana-core` to a minor while your target imports them.

| Protocol | Capability | Methods |
|---|---|---|
| `FileReader` | `read_files` | `iter_files`, `python_source`, `unread_sources` |
| `ChatEndpoint` | `chat` | `model`, `chat` |
| `ToolOfferingEndpoint` | `call_tools` | the above plus `offer_tools` |
| `TraceReader` | `read_trace` + dimensions | `trace` |
| `ToolListing` | `list_tools` | `list_tools` |
| `AuthorizationInspector` | `inspect_authorization` | `authorization`, `conversation` |
| `RegistryEntryInspector` | `registry_entry` | `registry_entry`, `reported_server`, `server_url` |
| `A2aInspector` | `inspect_a2a` | `a2a` |
| `SeededData` | `seeded_data` | `fixtures`, `ask_as` |

Built-ins are `ArtifactTarget` (files: pickles, GGUF, ONNX, ML formats,
requirements/lockfiles, manifests), `EndpointTarget`
(OpenAI-compatible / Ollama / vLLM / HF-TGI chat), `TraceTarget` (a recorded
execution), `McpServerTarget`, `A2aAgentTarget` and `SeededTarget` (an endpoint with a
[fixtures file](usage-fixtures.md)'s items and one endpoint per tenant, every one on the
run's meter; `guardana.core.testing.seeded_target` builds one over a double). A rule declares the capabilities it needs via
`required_capabilities` in `RuleMeta`; the `Runner` skips a rule whose target
cannot satisfy them rather than crashing.

**Say which protocol your target speaks.** A capability says what a target implements, not
what it is: an agent that fronts MCP tools may implement only `chat` and `call_tools`.
Override `Target.speaks()` to return the `WireProtocol` values your target speaks
(`CHAT`, `MCP`, `A2A`, from `guardana.core.target`). A rule's protocol comes from the
capabilities it requires (`wire_protocols_of`: `chat`, `call_tools` and
`plant_system_prompt` are chat; `list_tools`, `inspect_authorization` and `registry_entry`
are MCP; `inspect_a2a` is A2A). A rule whose protocols your target does not speak is
skipped as `not_applicable`, which `fail_on_skipped` and `--preset release` do not count;
a capability missing within a protocol it speaks stays a `missing_capability` gap. A
protocol one of your target's declared capabilities belongs to is spoken whatever
`speaks()` returns: a subclass of `EndpointTarget` that adds `list_tools` speaks MCP too,
and the MCP rules run against it. The default, `None`, says nothing, and every rule the
target cannot serve is a `missing_capability` gap. A wrapper or a view returns what the
target it wraps speaks.

```python
from guardana.core.target import WireProtocol

class MyAgentTarget(Target):
    def speaks(self) -> frozenset[WireProtocol] | None:
        return frozenset({WireProtocol.CHAT})
```

**Check it, rather than assuming it.** `guardana.testing.conformance` ships in the
package for this, and it checks *both* directions — including the one that produces
no error at all:

```python
from pathlib import Path

from guardana.testing import assert_target_conforms

def test_my_target_satisfies_the_contract(tmp_path: Path) -> None:
    (tmp_path / "model.PKL").write_bytes(b"\x80\x02N.")
    assert_target_conforms(MyTarget(tmp_path))
```

A target that declares a capability it has no surface for is refused by the runner
with one clear error. A target that implements a surface and *forgets to declare
it* is worse and used to be silent: every rule needing that capability is skipped,
the scan comes back green, and nothing in the report separates that from a target
with no problems. The conformance kit fails on it. One exception: an `EndpointTarget`
subclass that keeps the inherited `offer_tools` declares `CALL_TOOLS` only when its
transport can offer tools; one that replaces `offer_tools` must declare it.

For a `FileReader` it also asks `iter_files` for the suffixes of up to five of the
target's own files, in lowercase and in capitals, and fails when a file is left out:
a target that filters `.pkl` by exact case hands `model.PKL` to no rule.
Point the target at a directory that holds a file, as above: the check samples the
files the target lists, so over an empty or missing root it has nothing to sample
and passes without having looked.

A file run records every path `iter_files()` listed, so `diff` can tell a file that
left the scan from one that was fixed. A target that applies its own excludes can say
which by implementing `file_scope()` (`guardana.core.target.scope.ReportsFileScope`);
without it the saved run records its excludes as unknown.

> Before 0.22.0 this page promised that a target declaring `READ_FILES` could run
> the artifact rules unmodified. It could not: every rule asked
> `isinstance(target, ArtifactTarget)`. The protocols above are what made the
> promise true.

**`guardana.targets` is discovered by `Registry.discover(trust)`**, the same way
as rules and evaluators (see
[`architecture.md`](architecture.md#current-entry-point-groups)): register a
`Target` subclass (the class itself, not an instance — targets are
parameterized by a path/URL at construction time) via the `guardana.targets`
entry point, and `registry.targets()` returns it. Declaring a unique lowercase
`scheme` and implementing `from_locator` also makes it selectable from every
matching CLI workflow:

```bash
guardana scan --target acme-files://./prompts
guardana plan scan --target acme-files://./prompts
```

The command still chooses the kind: an artifact target is refused by `probe`,
and an endpoint target is refused by `scan`. Schemes match
`[a-z][a-z0-9-]*`; `file`, `http`, `https`, `mcp`, and `trace` are reserved,
and two installed packs cannot claim the same one. Repeat non-secret settings as
`--target-option key=value`; name secrets by environment variable inside your
target rather than putting them in shell history. `guardana doctor` lists every
loaded custom scheme.

A target that authenticates to what it tests declares the values it sends, because a
key that no built-in pattern recognises would otherwise be saved wherever the endpoint
echoes it. Implement `sent_secrets()`, returning a tuple of strings
(`guardana.core.target.SendsSecrets`):

```python
class AcmeGatewayTarget(Target):
    def sent_secrets(self) -> tuple[str, ...]:
        return (self._token,)
```

`EndpointTarget` and every target built on it already declare their API key and
whatever their transport declares; a transport declares its own the same way.
`McpServerTarget` declares the bearer token it sends. A run replaces each declared value
of four characters or more with `[redacted:credential]` in its findings, the failures it
records and the exchanges it keeps, in every evidence mode, before its own patterns run.
Bytes are read as UTF-8; any other item that is not a string is ignored. `Verifier`
refuses a target whose `sent_secrets()` raises before anything is sent, and a failure the
runner records for such a target gives only the status and the size of the reply.

Endpoint targets that want Guardana to run canary rules also implement
`SystemPromptPlanter.planting(system_prompt)`. Each planted view must preserve
one shared usage meter and budget across the whole probe. Without that protocol,
canary rules are recorded as skipped for a missing construction capability;
they are never graded against a marker that was not planted.

## The entry-point contract (rules, evaluators, targets & taxonomies)

| Group | Provides | Loaded by |
|---|---|---|
| `guardana.taxonomies` | one `TaxonomyRef`, or an iterable | `Registry.discover(trust)`, **first** — a rule pack's own `taxonomy:` references resolve while its own entry point is still loading |
| `guardana.rules` | one `Rule`, or an iterable of `Rule`s | `Registry.discover(trust)` |
| `guardana.evaluators` | one `Evaluator`, or an iterable | `Registry.discover(trust)` |
| `guardana.targets` | one `Target` subclass, or an iterable | `Registry.discover(trust)` |
| `guardana.renderers` | one `RendererSpec`; the entry point's name is the format's name | only when `--format` names it ([installed outputs](outputs.md)) |
| `guardana.reporters` | one `ReporterSpec`; the entry point's name is the reporter's name | only when `--reporter <name>://` names it |

The two output groups are never walked by `Registry.discover`: an installed format or
reporter is imported when a command selects it, and a run that does not select it neither
imports nor records it. [`outputs.md`](outputs.md#write-your-own) describes the contract.

A package registers by adding to its `pyproject.toml`:

```toml
[project.entry-points."guardana.taxonomies"]
my_taxonomies = "acme_rules:provide_taxonomies"

[project.entry-points."guardana.rules"]
my_rules = "acme_rules:provide_rules"

[project.entry-points."guardana.evaluators"]
my_evaluators = "acme_rules:provide_evaluators"

[project.entry-points."guardana.targets"]
my_targets = "acme_rules:provide_targets"
```

`provide_rules()` / `provide_evaluators()` / `provide_targets()` /
`provide_taxonomies()` are zero-argument callables returning an instance or a
list of instances. Any pip-installed package —
ours or a third party's private one — is discovered identically; there is
no built-in/custom distinction at the registry level, only namespacing by
`id`. The CLI starts with `--plugins builtins`, so a user admits your pack by its
distribution name (`--plugins allowlist --allow-plugin <your-distribution>`, or
`plugins:` in a profile); from Python, `Registry.discover(trust)` takes the same
`PluginTrust` and has no default. `guardana scan --no-plugins` is a deprecated alias for `--plugins
disabled`: discovery still runs, every plugin is refused, and each refusal is
recorded — see [`SECURITY.md`](../SECURITY.md) for the trust modes and why
this exists.

[`examples/reference_pack/`](../examples/reference_pack/) is one pack that uses all six
groups — a YAML and a Python rule, an evaluator, a target, a control catalogue, the format
`reference-summary` and the reporter `reference-file` — with a schema-3 manifest and a
committed lock. It is the distribution `guardana-reference-pack`, versioned on its own and
attached to every GitHub Release. It imports nothing outside the supported surface, and a
test that walks its imports refuses any `guardana.*` name off it; its isolated suite then
proves the pack with only what Guardana ships: `guardana rule test 'reference.*'` (each
rule fires, stays silent and declines), the target and output conformance checks,
`pack validate`, `pack lock --check`, and a `scan` through its own target, format and
reporter.

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

You do not have to copy it. [`guardana new-pack`](usage-new-pack.md) writes the
same shape — manifest, all four entry points, a rule per declarative shape with
its three samples, a locator target and these tests — into an empty directory, and
the result passes `pack validate` and `rule test` before you change anything.

`guardana.core.testing` ships every double behind that, so a fixture is a
few lines of Python instead of a network call or a hand-crafted binary:

**Transports** plug into `EndpointTarget`'s `ChatTransport` seam, so a
dynamic rule is graded end-to-end against a scripted model with no network:

- `ScriptedTransport` — canned replies in order, the last one repeating
  once exhausted; records every request it received.
- `RefusingTransport` — a well-behaved model: refuses everything, leaks
  nothing (the negative fixture for most dynamic rules).
- `EchoingTransport` — discloses whatever system prompt was planted on it
  (the canary-leak positive fixture).
- `ToolCallingScriptedTransport` — calls the tools it was told to when any
  are offered (the excessive-agency fixture).
- `GullibleAgentTransport` — treats a tool's result as an instruction and
  acts on it (the positive fixture for prompt injection through tool
  output); pair with `RefusingTransport` for the negative.
- `FailingTransport` — an unreachable endpoint: every call raises the
  given error.
- `ScriptedAgentTransport` — plays a written agent run: one reply per round
  trip, one script per session, nothing repeated. What a declarative fixture's
  `turns:` builds, and what a Python fixture uses to script a run by hand.
- `ScriptExhaustedError` — raised when a run asks a scripted double for a turn
  or a session nobody wrote. It is an error rather than a repeated turn because
  a repeat loops until the step budget is gone, and the run is then graded as
  cut short — a sample passing for a reason its author never wrote.

Worked example:
[`writing-rules.md`](writing-rules.md#testing-a-dynamic-rule-without-a-model).

**Artifact builders** stand in for a model file, so a static rule is driven
against a crafted artifact with no binary checked into the repo:

- `build_gguf` — a well-formed GGUF file carrying the given metadata
  entries, e.g. a malicious chat template.
- `build_safetensors` — a well-formed safetensors file; the negative
  fixture for any artifact rule (no code-execution surface) and the
  positive one for anything reading `__metadata__`.
- `build_onnx` — a walkable ONNX `ModelProto`, for operator-domain,
  metadata, and external-data checks.
- `files_target` — an `ArtifactTarget` over a fresh directory holding the
  files it is given by relative path, removed once the target is collected;
  a rule's fixtures build their trees with it. A file the target could not
  read makes a sample `inconclusive`, as a run reports it as an error.
  `source_read_limit=` lowers the size past which the target leaves a Python
  file unread, so a sample of that needs a few hundred bytes.

**Fake credentials** are assembled at run time rather than written down, so
a redaction test does not put a secret-shaped literal in the repository:

- `fake_aws_key` — input for a secret-detection rule to hunt: shaped exactly
  like a real AWS access key id, without being one.
- `fake_llm_key` — the same, shaped like an OpenAI API key.
- `fake_github_pat` — the same, shaped like a fine-grained GitHub token.
- `fake_jwt` — a JWT-shaped token (three base64url segments).
- `fake_secrets` — all four above, for a test asserting that none leaked.

**A scripted MCP server**, `ScriptedMcpServer`, stands in for a live one,
reached exactly the way the real one is and configurable for authorization,
session handling, caching headers, task listings and both eras of the protocol —
so an authorization rule gets a positive and a negative server with no network.
Pass it as both seams: `McpServerTarget(url, sender=server,
discovery_sender=server)`. A `Sender` carries the server's own requests and takes
only `method`, `body` and `headers`; discovery documents go through a
`DiscoverySender`, which also takes `alongside` and `discovery` and must honour
`discovery`. A `sender` given alone raises `ValueError`, so a pack's transport can
neither skip the pin on discovery connections nor send a test's discovery to the
network.

**A scripted A2A agent**, `ScriptedA2aAgent`, stands in for a live A2A v1 agent
the same way: it serves a card, answers the task reads per caller, keeps tasks
per owner and refuses a caller it does not know, so an A2A rule gets an agent
that tells its callers apart and one that does not.

**A seeded application**, `SeededApplication`, stands in for a team's own
retrieval pipeline over a [fixtures file](usage-fixtures.md): it answers an
item's question with its marker when the asking tenant's key may read it, and
switches break its tenant filter per channel, leave items out of its index, or
make it obey a poisoned document. `seeded_target` builds a `SeededTarget` over
it — the run's endpoint and one endpoint per tenant, on one meter — so a rule
that needs `seeded_data` gets a leaking and a holding application with no
network.

**A run manifest**: `manifest_for` builds a `RunManifest` describing a
`ScanResult` with test-stable circumstances, and `FIXED_RUN_TIME` is the
fixed instant it stamps everywhere — so two renderings of the same result
are byte-identical and a renderer test is not also a test about clocks.

**Sample runs and a receiver**, for an installed output: `sample_verifications`
returns five runs the engine produced over kit targets — a passed and a failed
scan, a scan of an empty tree, a probe stopped by its request budget and a scan in
which no rule ran — so a format is tried on the runs it most needs to describe.
`receiver` serves, on `127.0.0.1` for a `with` block, an accepting, a refusing
(`403`) and a closed URL, yielded as a `Receiver` whose `received` lists each
`ReceivedRequest` it answered. `guardana.testing.assert_renderer_conforms` and
`assert_reporter_conforms` run a format or a reporter over them and raise
`OutputContractError`; what they prove and what they do not is in the
[conformance kit](conformance-kit.md).
