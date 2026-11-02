"""A rule that finds, while it runs, nothing of the kind it grades records a skip.

`NotApplicable` raised before the rule reports anything is a `not_applicable` skip, the
same as a rule whose `not_applicable_to` names a reason: not a check that ran, and not a
coverage gap. Raised after the rule reported, it is an error of that rule, and what it
reported is kept.
"""

from collections.abc import Iterable

from guardana.core.assessment import Assessment, AssessmentStatus
from guardana.core.gate import GateOutcome, OpenQuestion, gate_outcome, open_questions
from guardana.core.profile import Policy, Profile
from guardana.core.profile.presets import preset
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, ScanResult, SkippedRule, SkipReason
from guardana.core.report.check_error import bounded_reason
from guardana.core.rule import NotApplicable, Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import ScriptedTransport

_REF = "http://x#m"


def _meta(rule_id: str) -> RuleMeta:
    return RuleMeta(
        rule_id,
        rule_id,
        Severity.HIGH,
        TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CHAT}),
    )


class _NothingToGrade(Rule):
    """Find nothing of the kind this rule grades before reporting anything."""

    def __init__(
        self, rule_id: str = "acme.sessions", detail: str = "the server issues no sessions"
    ) -> None:
        self.meta = _meta(rule_id)
        self._detail = detail

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Raise `NotApplicable` naming why."""
        raise NotApplicable(self._detail)
        yield  # pragma: no cover — keeps this a generator


class _ReportsThenNothing(Rule):
    """Yield a finding, then claim there was nothing to grade."""

    meta = _meta("acme.late")

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Report once, then raise `NotApplicable`."""
        yield Finding(self.meta.id, Severity.HIGH, "t", (), target.ref, Evidence(summary="s"))
        raise NotApplicable("the server issues no sessions")


class _MeasuresThenNothing(Rule):
    """Record a measured case, then claim there was nothing to grade."""

    meta = _meta("acme.measured")

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Record one assessment, then raise `NotApplicable`."""
        ctx.record(
            Assessment(
                case_id="c",
                assessor="acme",
                subject_ref=target.ref,
                status=AssessmentStatus.MEASURED,
                rule_id=self.meta.id,
                passed=True,
            )
        )
        raise NotApplicable("the server issues no sessions")
        yield  # pragma: no cover — keeps this a generator


class _Clean(Rule):
    """Run and find nothing."""

    def __init__(self, rule_id: str = "acme.clean") -> None:
        self.meta = _meta(rule_id)

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Find nothing."""
        return ()


def _run(*rules: Rule, profile: Profile | None = None, concurrency: int = 1) -> ScanResult:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))
    return Runner(
        registry=registry,
        profile=profile or Profile("t", Policy()),
        concurrency=concurrency,
    ).run(target)


def test_a_rule_with_nothing_to_grade_is_recorded_as_a_not_applicable_skip() -> None:
    result = _run(_NothingToGrade(), _Clean())

    assert result.rules_skipped == (
        SkippedRule(
            "acme.sessions",
            SkipReason.NOT_APPLICABLE,
            (),
            f"acme.sessions has nothing to check on {_REF}: the server issues no sessions",
        ),
    )
    assert result.rules_run == ("acme.clean",)
    assert result.errors == ()
    assert result.unverified == ()


def test_a_not_applicable_skip_is_no_coverage_gap_and_the_release_preset_still_passes() -> None:
    release = preset("release")
    result = _run(_NothingToGrade(), _Clean(), profile=release)

    assert not result.rules_skipped[0].is_coverage_gap
    assert OpenQuestion.SKIPPED not in open_questions(result)
    assert gate_outcome(result, release.policy) is GateOutcome.PASS


def test_a_run_whose_only_rule_had_nothing_to_grade_verified_nothing() -> None:
    result = _run(_NothingToGrade())

    assert result.rules_run == ()
    assert result.verified_nothing
    assert gate_outcome(result, Policy()) is GateOutcome.INDETERMINATE


def test_a_run_time_not_applicable_skip_takes_its_place_in_rule_order() -> None:
    result = _run(
        _NothingToGrade("acme.first"), _Clean(), _NothingToGrade("acme.second"), concurrency=3
    )

    assert [(s.rule_id, s.reason) for s in result.rules_skipped] == [
        ("acme.first", SkipReason.NOT_APPLICABLE),
        ("acme.second", SkipReason.NOT_APPLICABLE),
    ]


def test_the_detail_is_cut_to_the_length_a_recorded_reason_may_have() -> None:
    result = _run(_NothingToGrade(detail="x" * 5000))

    detail = result.rules_skipped[0].detail
    assert detail == bounded_reason(f"acme.sessions has nothing to check on {_REF}: {'x' * 5000}")
    assert len(detail) < 5000


def test_not_applicable_raised_after_a_finding_is_an_error_and_the_finding_is_kept() -> None:
    result = _run(_ReportsThenNothing())

    assert [f.rule_id for f in result.findings] == ["acme.late"]
    assert [(e.source, e.stage, e.reason) for e in result.errors] == [
        ("acme.late", "run", "raised NotApplicable after reporting")
    ]
    assert result.rules_skipped == ()
    assert result.rules_run == ()


def test_not_applicable_raised_after_a_measured_case_is_an_error_and_the_case_is_kept() -> None:
    result = _run(_MeasuresThenNothing())

    assert [a.rule_id for a in result.assessments] == ["acme.measured"]
    assert [e.reason for e in result.errors] == ["raised NotApplicable after reporting"]
    assert result.rules_skipped == ()


def test_not_applicable_carries_its_detail() -> None:
    raised = NotApplicable("the server issues no sessions")

    assert str(raised) == "the server issues no sessions"
    assert raised.detail == "the server issues no sessions"
