"""Building traces in code, so a fixture is readable in review and carries no real data.

Every rule below gets a positive and a negative case, which is the repo's contract for a
rule. The helpers here keep each of those to a few lines, and — the part that matters —
make it easy to build the *third* case: a trace where the dimension the rule needs was
never recorded, which must produce no finding at all.
"""

from collections.abc import Iterable

from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext
from guardana.core.runner import Runner
from guardana.core.target import TraceTarget
from guardana.core.trace import (
    Dimension,
    Provenance,
    Span,
    SpanKind,
    Trace,
    TraceTruncation,
)

_ALL_DIMENSIONS = frozenset(Dimension)


def trace_of(
    *spans: Span,
    records: Iterable[Dimension] = _ALL_DIMENSIONS,
    truncated: TraceTruncation | None = None,
    unreadable: int = 0,
) -> Trace:
    """Build a trace whose producer records `records` — everything, unless a test narrows it."""
    return Trace(
        trace_id="t-1",
        spans=tuple(spans),
        provenance=Provenance(producer="acme", source="acme.jsonl", dialect="guardana"),
        instrumented=frozenset(records),
        truncated=truncated,
        unreadable=unreadable,
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


def built_in_runner() -> Runner:
    """A runner over the built-in registry, for the tests that check a rule is *skipped*.

    Skipping is the runner's job, not the rule's, so the only honest way to test the
    capability gate is through the seam where it is applied.

    A plain helper rather than a fixture, and this file is `trace_fixtures.py` rather than
    a second `conftest.py`, because two files of that name in one repository collide under
    `mypy --strict` — the same reason `mcp_fixtures.py` exists next door.
    """
    from guardana.core.profile import Policy, Profile  # noqa: PLC0415
    from guardana.core.registry import Registry  # noqa: PLC0415

    return Runner(registry=Registry.discover(), profile=Profile(name="t", policy=Policy()))
