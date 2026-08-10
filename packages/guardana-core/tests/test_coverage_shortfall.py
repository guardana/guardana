"""Coverage somebody demanded and did not get is `indeterminate`, with no switch in front of it.

This is the meeting point of the two halves of the release, and the easiest thing in
it to get wrong. The mechanism that already existed — a rule skipped for a missing
capability — reaches the gate only through `fail_on_skipped`, which defaults to
`false`. So the default path for "the contract you wrote could not be checked at all"
was a run that exits `0`, and that is the false green these tests pin shut.
"""

from pathlib import Path

from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile import FailOn, Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import (
    CheckError,
    CoverageShortfall,
    ScanResult,
    ShortfallKind,
    StopReason,
)
from guardana.core.report.finding import Evidence, Finding
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, TraceTarget
from guardana.core.trace import Dimension, Provenance, Span, SpanKind, Trace

_SHORTFALL = CoverageShortfall(
    kind=ShortfallKind.MISSING_DIMENSION, name="approval", detail="approvals are not recorded"
)


def _trace(*records: Dimension) -> Trace:
    return Trace(
        trace_id="t",
        spans=(Span(span_id="s", kind=SpanKind.TOOL_EXECUTION, name="s"),),
        provenance=Provenance(producer="acme", source="a.jsonl", dialect="guardana"),
        instrumented=frozenset(records),
    )


def _profile(*required: Dimension, **fail_on: object) -> Profile:
    return Profile(
        name="t",
        policy=Policy(fail_on=FailOn(**fail_on)),  # type: ignore[arg-type]
        required_dimensions=required,
    )


def test_a_shortfall_makes_the_run_indeterminate() -> None:
    result = ScanResult((), ("a-rule",), (), coverage_shortfall=(_SHORTFALL,))

    assert gate_outcome(result, Policy()) is GateOutcome.INDETERMINATE


def test_no_fail_on_setting_can_turn_a_shortfall_into_a_pass() -> None:
    """The one channel with no toggle, and the reason it is not a `CheckError`.

    `fail_on_error` would have been one line of YAML away from false, and `errors` is
    also the wrong word: a framework that does not emit approval spans has
    malfunctioned in no way at all.
    """
    result = ScanResult((), ("a-rule",), (), coverage_shortfall=(_SHORTFALL,))
    permissive = Policy(
        fail_on=FailOn(
            severity=Severity.CRITICAL,
            fail_on_error=False,
            fail_on_inconclusive=False,
            fail_on_skipped=False,
        )
    )

    assert gate_outcome(result, permissive) is GateOutcome.INDETERMINATE


def test_a_finding_still_outranks_a_shortfall() -> None:
    """A finding is a fact somebody must act on; "we could not tell" would bury it."""
    finding = Finding(
        rule_id="r",
        severity=Severity.CRITICAL,
        title="t",
        taxonomy=(),
        target_ref="x",
        evidence=Evidence(summary="s", detail=""),
    )
    result = ScanResult((finding,), ("r",), (), coverage_shortfall=(_SHORTFALL,))

    assert gate_outcome(result, Policy()) is GateOutcome.FAIL


def test_the_runner_reports_a_required_dimension_the_producer_does_not_record() -> None:
    runner = Runner(registry=Registry(), profile=_profile(Dimension.APPROVAL))

    result = runner.run(TraceTarget(_trace(Dimension.EFFECTS)))

    assert [g.name for g in result.coverage_shortfall] == ["approval"]
    assert gate_outcome(result, runner.profile.policy) is GateOutcome.INDETERMINATE


def test_the_runner_reports_nothing_when_every_required_dimension_is_recorded() -> None:
    runner = Runner(registry=Registry(), profile=_profile(Dimension.EFFECTS))

    result = runner.run(TraceTarget(_trace(Dimension.EFFECTS)))

    assert result.coverage_shortfall == ()


def test_a_required_dimension_is_measured_against_what_the_producer_declares() -> None:
    """Not against the capabilities derived from it, and the two come apart for one case.

    No rule needs `memory`, so no capability is licensed by it — but a producer that
    records memory has plainly satisfied `require: [memory]`, and checking the derived
    set would report that trace as missing evidence it visibly contains.
    """
    runner = Runner(registry=Registry(), profile=_profile(Dimension.MEMORY))

    result = runner.run(TraceTarget(_trace(Dimension.MEMORY)))

    assert result.coverage_shortfall == ()


def test_required_dimensions_never_reach_a_target_that_is_not_a_trace(tmp_path: Path) -> None:
    """A shared `guardana.yaml` must not turn `guardana scan` into a run that cannot pass.

    `trace.require` is a statement about a producer's instrumentation; demanding it of
    a file scan is a category error, and reading it as one would be a gate that fails
    closed on everything — as useless as one that fails open on everything.
    """
    runner = Runner(registry=Registry(), profile=_profile(Dimension.APPROVAL))

    result = runner.run(ArtifactTarget(tmp_path))

    assert result.coverage_shortfall == ()


def test_demanding_merges_without_duplicating_and_keeps_the_order_asked_in() -> None:
    profile = _profile(Dimension.APPROVAL).demanding([Dimension.EFFECTS, Dimension.APPROVAL])

    assert profile.required_dimensions == (Dimension.APPROVAL, Dimension.EFFECTS)


def test_merging_results_keeps_one_shortfall_per_thing_demanded() -> None:
    """`probe` merges one result per planted canary; one unmet demand is still one."""
    merged = ScanResult.merged(
        [
            ScanResult((), (), (), coverage_shortfall=(_SHORTFALL,)),
            ScanResult((), (), (), coverage_shortfall=(_SHORTFALL,)),
        ]
    )

    assert len(merged.coverage_shortfall) == 1


def test_merging_carries_every_field_a_result_has() -> None:
    """Enumerated from the dataclass, so a channel added later is covered by default.

    `ScanResult.merged` exists because callers used to rebuild the dataclass field by
    field and a channel added later was silently dropped by whoever forgot — which is
    how `errors` went missing from probe, monitor and baselines. A test naming the
    fields would repeat that mistake one level up, so this asks the type.
    """
    from dataclasses import fields  # noqa: PLC0415

    populated = ScanResult(
        findings=(),
        rules_run=("r",),
        rules_skipped=(),
        unverified=(),
        waived=(),
        errors=(CheckError(source="s", stage="load", reason="why"),),
        observations=(),
        coverage_shortfall=(_SHORTFALL,),
        stopped_by=StopReason.BUDGET_EXHAUSTED,
        usage=None,
        protocols={"mcp": "2026-07-28"},
    )

    merged = ScanResult.merged([populated])

    empty = ScanResult((), (), ())
    for field in fields(ScanResult):
        carried = getattr(merged, field.name)
        assert carried == getattr(populated, field.name), (
            f"{field.name} was dropped by ScanResult.merged"
        )
        if getattr(empty, field.name, None) != getattr(populated, field.name):
            assert carried != getattr(empty, field.name), f"{field.name} came back as its default"
