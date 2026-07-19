# Architecture

## Packages

```
guardana-core     Target / Rule / Evaluator / Finding / Profile,
                   the Registry (discovery) and Runner (execution).
                   No network I/O beyond what a Target itself performs.
guardana-rules     Built-in rules (YAML + Python plugin), each mapped to
                   OWASP / MITRE ATLAS / NIST.
guardana-cli       The `guardana` command: scan, probe, monitor, init, rules,
                   new-rule.
guardana-report    Renderers: human, SARIF, JSON, JUnit.
guardana-server    OPTIONAL collector. Ingests normalized Findings from many
                   agents; list/trend view. A separate, separately-deployed
                   service.
```

Each is `src/guardana/<name>` — a PEP 420 namespace package. No package
directory has a bare `guardana/__init__.py`; only the subpackages
(`guardana.core`, `guardana.rules`, etc.) do, so five distributions can
contribute to the same `guardana.*` namespace without conflict.

## The five abstractions

### 1. Target — what we inspect

`guardana.core.target.Target` is a uniform interface over the thing under
test, so a rule never hard-codes whether it's reading files or talking to a
model:

```python
class TargetKind(StrEnum):
    ARTIFACT = "artifact"
    ENDPOINT = "endpoint"

class Capability(StrEnum):
    READ_FILES = "read_files"
    CHAT = "chat"
    PLANT_SYSTEM_PROMPT = "plant_system_prompt"
    CALL_TOOLS = "call_tools"

class Target(ABC):
    kind: TargetKind
    def capabilities(self) -> set[Capability]: ...
    @property
    def ref(self) -> str: ...   # stable id used in findings/reports
```

Every `RuleMeta` also carries a derived **`surface`** (`Surface.BUILD` for
artifact rules, `Surface.RUNTIME` for endpoint rules) — the conceptual split
between securing how a model is *built* and how it *behaves*. It needs no
per-rule declaration; `guardana rules` groups by it and takes `--surface`.

Built-ins: `ArtifactTarget` (walks a directory, exposing `iter_files(suffixes)`
over model files, dependency manifests, and source, skipping `.git`,
`.venv`, `node_modules`, etc.) and `EndpointTarget` (a live chat endpoint,
exposing `chat(messages) -> str`, with a pluggable `ChatTransport` so tests
never hit the network). The transport is selected by a provider name —
`openai` (the default, any OpenAI-compatible server), `ollama` (native
`/api/chat`), or `tgi` (HF TGI `/generate`) — surfaced as `--provider` on
`probe`/`monitor`; a genuinely custom backend ships a `Target` through the
`guardana.targets` entry point instead. An OpenAI-compatible transport also
implements the optional `ToolCallingTransport` protocol, so `EndpointTarget`
advertises `CALL_TOOLS` and exposes `offer_tools(messages, tools)` — the seam
the excessive-agency rule uses to observe which tools a model calls (`ollama`
and `tgi` simply don't advertise the capability).

A rule declares which capabilities it needs (`required_capabilities` in
`RuleMeta`); the `Runner` skips a rule outright — no crash — when the
target it's given can't satisfy them, e.g. an endpoint-only prompt-injection
rule is skipped against an `ArtifactTarget`.

### 2. Rule — what to look for

```python
@dataclass(frozen=True, slots=True)
class RuleMeta:
    id: str
    title: str
    severity: Severity
    target_kind: TargetKind
    taxonomy: tuple[TaxonomyRef, ...] = ()
    required_capabilities: frozenset[Capability] = frozenset()
    evaluator: str | None = None

class Rule(ABC):
    meta: RuleMeta
    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]: ...
```

Two authoring paths, one contract: **declarative YAML** for "send this
corpus, grade with this evaluator", or a **Python plugin** (any `Rule`
subclass) for logic YAML can't express. Declarative rules come in two
shapes, both loaded by `load_yaml_rules`: single-turn `YamlRule` (a
`prompts:` list, each graded independently) and multi-turn `ScenarioRule` (a
`steps:` conversation graded per step and/or as a whole). See
[`writing-rules.md`](writing-rules.md) for the full authoring guide.

### 3. Evaluator — did it succeed, and how sure are we

The differentiator. `guardana.core.evaluator.Evaluator` turns a model
response into a verdict with a confidence and a rationale, instead of a
bare true/false:

```python
class Evaluator(ABC):
    id: str
    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict: ...

@dataclass(frozen=True, slots=True)
class Verdict:
    outcome: Literal["pass", "fail", "inconclusive"]
    confidence: float
    rationale: str
    evaluator_id: str
```

An `Exchange` (`guardana.core.exchange`) is the graded conversation — the
message sequence plus `reply_text` (the last assistant reply, `None` when
there is nothing to grade) and `transcript` (the whole conversation, so a
multi-turn scenario's "across the conversation" goal is gradable). Every
built-in evaluator fails closed on `reply_text is None`: the verdict is
`inconclusive`, never a silent pass.

Shipped evaluators: `keyword` (cheap refusal-marker matching — honestly
low-confidence, ~0.5–0.6), `canary` (near-perfect detection of a planted
marker verbatim, ~0.9–0.99), `length` (grades a reply by length — a runaway
answer to a divergence prompt is a lead, for the unbounded-consumption check),
`llm_judge` (a versioned judging prompt sent to
a judge model wired from the profile's `evaluators:` block; confidence is
measured as agreement across `min_agreement` samples, and the prompt version
is stamped into `evaluator_id` — `llm_judge@2025.1` — so grading stays
reproducible as the rubric evolves), and `guard` (an opt-in external
safety-classifier — see
[`profiles.md`](profiles.md#config-wired-evaluators-llm_judge-and-guard)). A
rule references an evaluator by its string `id`, resolved from the registry
at run time; swapping which evaluator grades a rule never requires touching
the rule itself.

### 4. Report / Finding — normalized result

```python
@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    taxonomy: tuple[TaxonomyRef, ...]
    target_ref: str
    evidence: Evidence
    verdict: Verdict | None = None   # present for evaluator-graded (dynamic) checks
```

One shape regardless of which rule produced it. `guardana-report` renders a
`ScanResult` — the findings, a rule-run/skip count, and the `unverified`
channel (checks that ran but could not reach a verdict — surfaced in every
format, never dropped into a false all-clear) — as `human`, `json`, `sarif`,
or `junit` via the `Renderer` protocol
(`render(result: ScanResult) -> str`). `Severity` is an `IntEnum`
(`INFO < LOW < MEDIUM < HIGH < CRITICAL`) so policies threshold with `>=`.
`TaxonomyRef` (`framework`, `id`, `title`) is how OWASP/MITRE/NIST mapping
becomes a typed, filterable field rather than a comment.

### 5. Profile / Policy — what to run and when to fail

```python
@dataclass(frozen=True, slots=True)
class Policy:
    include: tuple[str, ...] = ("*",)
    exclude: tuple[str, ...] = ()
    fail_on: FailOn = field(default_factory=FailOn)

@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    policy: Policy
    rule_config: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    evaluator_config: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    rule_paths: tuple[str, ...] = ()
```

Loaded from a `guardana.yaml` file by `load_profile`, or from a named preset
(`ci`/`pre-training`/`monitor`) via `--preset`. See
[`profiles.md`](profiles.md) for the full field-by-field schema and the presets.

## The Registry — uniform discovery

`guardana.core.registry.Registry` is the one place that finds rules and
evaluators, built-in or third-party, so nothing else in the engine
hard-codes a list of them:

```python
_RULE_GROUP = "guardana.rules"
_EVALUATOR_GROUP = "guardana.evaluators"
_TARGET_GROUP = "guardana.targets"

class Registry:
    @classmethod
    def discover(cls) -> Self:
        reg = cls()
        for ep in entry_points(group=_RULE_GROUP):
            _absorb(ep.load()(), reg.register_rule)
        for ep in entry_points(group=_EVALUATOR_GROUP):
            _absorb(ep.load()(), reg.register_evaluator)
        for ep in entry_points(group=_TARGET_GROUP):
            _absorb(ep.load()(), reg.register_target)
        return reg
```

`Registry.discover()` walks every installed package's `guardana.rules` and
`guardana.evaluators` [entry points](https://packaging.python.org/en/latest/specifications/entry-points/)
and calls each one (a zero-arg callable returning either a single `Rule`/
`Evaluator` or an iterable of them — `_absorb` handles both shapes). A
third-party package registered this way is discovered exactly like
`guardana-rules`' own built-ins — there is no built-in/custom distinction at
the registry level, only namespacing by `id` (`guardana.*` reserved for
built-ins; use your own prefix, e.g. `acme.*`).

`Registry()` (the bare constructor, no entry-point scan) backs
`guardana scan --no-plugins`: an empty registry that imports zero
third-party code, for untrusted environments. See
[`SECURITY.md`](../SECURITY.md) for the trust model this exists for.

**Declarative YAML rules are not entry points** — they're parsed straight
off disk by `load_yaml_rules(path)` and wired into the
registry by whoever provides them (`guardana-rules`' `provide_rules()`
walks its own `catalog/` directory via `importlib.resources`; a third-party
package does the same over its own bundled YAML directory, or a user points
at their own rules directory via `Registry.load_yaml_rule_dirs(paths)` — see
[`writing-rules.md`](writing-rules.md)). `load_yaml_rule_dirs` never raises:
a malformed rule file is recorded in the returned `RuleDirLoad.errors`
instead of aborting the scan, so one bad custom rule can't take down a run.
This is what backs the CLI's `--rules PATH` option (repeatable; also settable
via `guardana.yaml`'s `rules.paths`) on `scan`, `probe`, and `monitor`.

### Current entry-point groups

| Group | Provides | Wired into `Registry`? |
|---|---|---|
| `guardana.rules` | one `Rule`, or an iterable of `Rule`s | **Yes** — `Registry.discover()` |
| `guardana.evaluators` | one `Evaluator`, or an iterable | **Yes** — `Registry.discover()` |
| `guardana.targets` | one `Target` subclass, or an iterable | **Yes** — `Registry.discover()`. `Registry.targets()` exposes the discovered classes (types, not instances — targets are parameterized by a path/URL at construction time). The CLI itself still selects its built-in `ArtifactTarget`/`EndpointTarget` by path/URL; discovered custom targets are available to library/embedding use, not yet CLI-selectable — see [`extending.md`](extending.md#adding-a-target). |

## The Runner

```python
@dataclass(frozen=True, slots=True)
class Runner:
    registry: Registry
    profile: Profile

    def run(self, target: Target) -> ScanResult: ...
```

For each registered rule: skip it if `target.kind` doesn't match
`meta.target_kind`, or the profile's `Policy.matches(rule_id)` excludes it;
skip it (recording it under `rules_skipped`) if the target can't satisfy
`meta.required_capabilities`; otherwise run it, catching `RuleError` per
rule so one bad rule can't abort the whole scan. Findings whose verdict is
`inconclusive` are partitioned onto the result's `unverified` channel rather
than counted as confirmed findings — or dropped. `gate(result, policy)` is
the free function that turns a `ScanResult` into the pass/fail boolean CLI
commands use for their exit code (see [`profiles.md`](profiles.md#the-gate));
`fail_on_inconclusive: true` makes the unverified channel gate too.

## The core↔server boundary

**Hard rule: `guardana-core` never imports `guardana-server`, directly or
transitively.** The only connection is one-directional and data-only:

```python
class Reporter(Protocol):
    def submit(self, result: ScanResult, *, source: str) -> None: ...
```

`guardana.core.reporter.HttpReporter` (used by all three CLI commands via
`--reporter server://<url>`) POSTs a **versioned JSON envelope** to whatever
URL you give it — it doesn't know or care whether the receiving end is
`guardana-server` or something else entirely:

```json
{
  "schema_version": 2,
  "source": "<path or url#model>",
  "findings": [ ... serialized Findings ... ],
  "unverified": [ ... checks that ran but could not reach a verdict ... ],
  "summary": {"rules_run": 6, "rules_skipped": [], "max_severity": null, "unverified": 0}
}
```

`schema_version` (`guardana.core.reporter.ENVELOPE_SCHEMA_VERSION`, currently
`2`) is what lets an agent and a collector be upgraded independently: a
collector that doesn't understand a version rejects it outright rather than
silently misreading a renamed field. The `unverified` channel is carried over
the wire for the same reason it is surfaced locally — a check that could not be
graded must never reach the collector as a false all-clear.

`guardana-server` itself is a small, independently-deployed FastAPI app
(`guardana.server.app.create_app`) exposing `POST /findings`,
`GET /findings`, and `GET /trend` over an in-memory (or pluggable) `Store`.
It validates every submission with Pydantic models
(`guardana.server.envelope.Submission`), so a malformed POST — or one with an
unsupported `schema_version` — is rejected with `422` instead of poisoning
`/findings` and `/trend`.

This boundary is intentional and load-bearing: all OSS value (every rule, every
evaluator, every report format, every CLI mode) works fully offline with zero
dependency on the collector. The collector is a strictly separable layer —
self-hosted (`guardana-server`) or, later, a managed cloud — that can grow
(dashboard, auth, persistence, fleet management, retention) without ever forking
or depending-back-into the engine.

## Repository layout

```
guardana/
├─ packages/
│  ├─ guardana-core/   src/guardana/core/{target,rule,evaluator,report,profile,
│  │                                      registry,runner,reporter,monitor,testing}
│  ├─ guardana-rules/  src/guardana/rules/{supply_chain,prompt,output,training,agent,catalog}
│  ├─ guardana-cli/    src/guardana/cli/{scan,probe,monitor,init,rules,new_rule}
│  ├─ guardana-report/ src/guardana/report/{human,sarif,json_report,junit}
│  └─ guardana-server/ (optional collector; separate deploy)
├─ docs/               (this directory)
├─ examples/           (sample profile + custom-rule package)
├─ CLAUDE.md  CONTRIBUTING.md  CODE_OF_CONDUCT.md  SECURITY.md
└─ pyproject.toml      (uv workspace, ruff, mypy, pytest)
```
