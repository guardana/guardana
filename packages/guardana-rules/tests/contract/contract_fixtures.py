"""Building contracts and traces in code, so an assertion fixture is three lines.

Named `contract_fixtures.py` rather than `conftest.py` for the reason
`trace_fixtures.py` and `mcp_fixtures.py` are: two files called `conftest` in one
repository collide under `mypy --strict`. Self-contained for the same reason those
are — pytest puts a test file's own directory on the path and not its siblings', so a
cross-directory import is a suite that passes in full and fails when somebody runs one
folder.
"""

from collections.abc import Iterable
from typing import Any

from guardana.core.contract import SecurityContract, contract_from_dict
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext
from guardana.core.runner import Runner
from guardana.core.target import TraceTarget
from guardana.core.trace import Dimension, Provenance, Span, SpanKind, Trace, TraceTruncation
from guardana.rules.contract import compile_contract

_ALL_DIMENSIONS = frozenset(Dimension)


def contract(*assertions: dict[str, Any], name: str = "acme", **top: object) -> SecurityContract:
    """Build a contract through the real loader, so a fixture cannot describe an illegal one.

    Deliberately not constructing `SecurityContract` directly. A fixture that bypassed
    the loader could assert a shape the loader refuses, and the test would then prove a
    rule against input no user can produce.
    """
    return contract_from_dict(
        {"schema_version": 1, "name": name, "assertions": list(assertions), **top},
        source=f"{name}.yaml",
    )


def rule_of(
    *assertions: dict[str, Any], ai_system: str | None = None, name: str = "acme", **top: object
) -> Rule:
    """Compile a one-assertion contract and hand back the single rule it produced."""
    compiled = compile_contract(contract(*assertions, name=name, **top), ai_system)
    (rule,) = compiled.rules
    return rule


def trace_of(
    *spans: Span,
    records: Iterable[Dimension] = _ALL_DIMENSIONS,
    truncated: TraceTruncation | None = None,
) -> Trace:
    """Build a trace whose producer records `records` — everything, unless a test narrows it."""
    return Trace(
        trace_id="t-1",
        spans=tuple(spans),
        provenance=Provenance(producer="acme", source="acme.jsonl", dialect="guardana"),
        instrumented=frozenset(records),
        truncated=truncated,
    )


def span(span_id: str, kind: SpanKind = SpanKind.TOOL_EXECUTION, **blocks: object) -> Span:
    """Build one span with only the blocks a test cares about."""
    return Span(span_id=span_id, kind=kind, name=span_id, **blocks)  # type: ignore[arg-type]


def graded(rule: Rule, trace: Trace) -> tuple[Finding, ...]:
    """Run one rule directly, which is how a positive and negative fixture stay three lines."""
    return tuple(rule.run(TraceTarget(trace), RuleContext()))


def findings(results: Iterable[Finding]) -> tuple[Finding, ...]:
    """Just the findings — a rule may also yield an unverified verdict."""
    return tuple(f for f in results if f.verdict is None or f.verdict.outcome != "inconclusive")


def inconclusive(results: Iterable[Finding]) -> tuple[Finding, ...]:
    """Just the declines, which is the half a false-green audit reads."""
    return tuple(
        f for f in results if f.verdict is not None and f.verdict.outcome == "inconclusive"
    )


def runner_with(rule: Rule) -> Runner:
    """A runner over the built-in registry plus this rule, for testing that it is *skipped*.

    Skipping is the runner's job, not the rule's, so the only honest way to test the
    capability gate is through the seam where it is applied.
    """
    registry = Registry.discover()
    registry.register_rule(rule)
    return Runner(registry=registry, profile=Profile(name="t", policy=Policy()))
