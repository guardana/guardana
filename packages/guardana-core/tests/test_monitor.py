from guardana.core.evaluator import Verdict
from guardana.core.monitor import Alert, Monitor, MonitorConfig
from guardana.core.profile import FailOn, Policy
from guardana.core.report import CheckError, Evidence, Finding, ScanResult
from guardana.core.severity import Severity

_WATCHED = ("guardana.ep.rule0", "guardana.ep.rule1")
"""The plan every cycle runs. Held fixed on purpose: a monitor re-runs the same
rules, so a rule appearing only in the later cycle would be a change of plan
rather than the change of behaviour these tests are about."""


def _result(*severities: Severity) -> ScanResult:
    findings = tuple(
        Finding(
            rule_id=f"guardana.ep.rule{i}",
            severity=severity,
            title="hit",
            taxonomy=(),
            target_ref="http://fake#m",
            evidence=Evidence(summary="x"),
            verdict=Verdict(outcome="fail", confidence=0.9, rationale="r", evaluator_id="e"),
        )
        for i, severity in enumerate(severities)
    )
    # A clean scan still ran rules; `rules_run` must name at least one or the gate
    # treats it as "nothing was checked" and fails (see runner.gate).
    return ScanResult(findings, rules_run=_WATCHED, rules_skipped=())


def _monitor(*cycles: ScanResult, max_cycles: int, interval: float = 0.0) -> Monitor:
    scans = iter(cycles)
    return Monitor(
        scan=lambda: next(scans),
        policy=Policy(),
        config=MonitorConfig(interval_seconds=interval, max_cycles=max_cycles),
    )


def test_alerts_when_the_gate_fails() -> None:
    alerts: list[Alert] = []

    _monitor(_result(Severity.HIGH), _result(Severity.HIGH), max_cycles=2).run(
        alerts.append, sleep=lambda _s: None
    )

    assert [a.cycle for a in alerts] == [0, 1]
    assert all(a.reason == "gate failed" for a in alerts)


def test_clean_model_never_alerts() -> None:
    alerts: list[Alert] = []

    _monitor(_result(), _result(), max_cycles=2).run(alerts.append, sleep=lambda _s: None)

    assert alerts == []


def test_alerts_when_findings_rise_above_the_first_cycle_baseline() -> None:
    # A LOW finding never trips the HIGH gate; the alert must come from the
    # count rising above the baseline established on cycle 0.
    alerts: list[Alert] = []

    _monitor(_result(Severity.LOW), _result(Severity.LOW, Severity.LOW), max_cycles=2).run(
        alerts.append, sleep=lambda _s: None
    )

    assert [a.cycle for a in alerts] == [1]
    # Named more precisely than the count-based reason this replaced: the second
    # cycle has a problem the first did not, on a rule that ran in both.
    assert alerts[0].reason == "worse than the first cycle: appeared"


def test_a_finding_present_from_the_first_cycle_is_the_baseline_not_an_alert() -> None:
    alerts: list[Alert] = []

    _monitor(_result(Severity.LOW), _result(Severity.LOW), max_cycles=2).run(
        alerts.append, sleep=lambda _s: None
    )

    assert alerts == []


def test_low_confidence_finding_does_not_trip_a_confidence_gated_policy() -> None:
    alerts: list[Alert] = []
    monitor = Monitor(
        scan=lambda: ScanResult(
            (
                Finding(
                    rule_id="guardana.ep.weak",
                    severity=Severity.HIGH,
                    title="weak signal",
                    taxonomy=(),
                    target_ref="http://fake#m",
                    evidence=Evidence(summary="x"),
                    verdict=Verdict(
                        outcome="fail", confidence=0.5, rationale="r", evaluator_id="keyword"
                    ),
                ),
            ),
            rules_run=("r0",),
            rules_skipped=(),
        ),
        policy=Policy(fail_on=FailOn(severity=Severity.HIGH, min_confidence=0.9)),
        config=MonitorConfig(interval_seconds=0.0, max_cycles=1),
    )

    monitor.run(alerts.append, sleep=lambda _s: None)

    assert alerts == []


def _unverified(count: int) -> ScanResult:
    ungraded = tuple(
        Finding(
            rule_id=f"guardana.ep.rule{i}",
            severity=Severity.CRITICAL,
            title="could not grade",
            taxonomy=(),
            target_ref="http://fake#m",
            evidence=Evidence(summary="no reply"),
            verdict=Verdict(
                outcome="inconclusive", confidence=0.0, rationale="empty", evaluator_id="canary"
            ),
        )
        for i in range(count)
    )
    return ScanResult((), rules_run=_WATCHED, rules_skipped=(), unverified=ungraded)


def test_alerts_when_unverified_count_rises_above_baseline() -> None:
    # The monitor's own checks going dark (judge down, empty replies) must not read
    # as a healthy model. A rising unverified count alerts even under the default
    # policy (fail_on_inconclusive=False), which does not gate on inconclusive.
    alerts: list[Alert] = []

    _monitor(_unverified(0), _unverified(2), max_cycles=2).run(alerts.append, sleep=lambda _s: None)

    assert [a.cycle for a in alerts] == [1]
    # "blinded": these checks came back clean on the first cycle and can no longer
    # grade at all. The count rose too, but the state is the sharper statement.
    assert alerts[0].reason == "worse than the first cycle: blinded"


def test_does_not_sleep_after_the_final_cycle() -> None:
    sleeps: list[float] = []

    _monitor(_result(), _result(), max_cycles=2, interval=5.0).run(
        lambda _a: None, sleep=sleeps.append
    )

    assert sleeps == [5.0]


def _cycle(
    *,
    rule: str = "guardana.ep.watched",
    severity: Severity | None = None,
    outcome: str = "fail",
    ran: tuple[str, ...] = ("guardana.ep.watched",),
) -> ScanResult:
    """One monitored cycle: at most one finding, so counts stay flat while state moves."""
    if severity is None:
        return ScanResult((), rules_run=ran, rules_skipped=())
    finding = Finding(
        rule_id=rule,
        severity=severity,
        title="hit",
        taxonomy=(),
        target_ref="http://fake#m",
        evidence=Evidence(summary="x"),
        verdict=Verdict(outcome=outcome, confidence=0.9, rationale="r", evaluator_id="e"),  # type: ignore[arg-type]
    )
    channel = "unverified" if outcome == "inconclusive" else "findings"
    return ScanResult(
        findings=(finding,) if channel == "findings" else (),
        rules_run=ran,
        rules_skipped=(),
        unverified=(finding,) if channel == "unverified" else (),
    )


def _lenient() -> Policy:
    """A policy that does not fail on its own, so the alert under test is the comparison's."""
    return Policy(fail_on=FailOn(severity=Severity.CRITICAL))


def _watch(*cycles: ScanResult, policy: Policy) -> list[Alert]:
    alerts: list[Alert] = []
    scans = iter(cycles)
    Monitor(
        scan=lambda: next(scans),
        policy=policy,
        config=MonitorConfig(interval_seconds=0.0, max_cycles=len(cycles)),
    ).run(alerts.append, sleep=lambda _s: None)
    return alerts


def test_alerts_when_a_finding_gets_worse_without_getting_more_numerous() -> None:
    """One finding before, one after — a counter sees nothing, and the model got worse."""
    alerts = _watch(
        _cycle(severity=Severity.LOW), _cycle(severity=Severity.HIGH), policy=_lenient()
    )

    assert [a.cycle for a in alerts] == [1]
    assert "escalated" in alerts[0].reason


def test_alerts_when_a_proven_problem_stops_being_gradable() -> None:
    """Yesterday we knew, today we do not — and the finding count fell, which reads as progress."""
    alerts = _watch(
        _cycle(severity=Severity.HIGH),
        _cycle(severity=Severity.HIGH, outcome="inconclusive"),
        policy=_lenient(),
    )

    assert [a.cycle for a in alerts] == [1]
    assert "blinded" in alerts[0].reason


def test_alerts_when_a_rule_stops_running_mid_watch() -> None:
    """A monitored model whose checks quietly stop is the failure this whole channel exists for."""
    alerts = _watch(
        _cycle(ran=("guardana.ep.watched", "guardana.ep.other")),
        _cycle(ran=("guardana.ep.watched",)),
        policy=_lenient(),
    )

    assert [a.cycle for a in alerts] == [1]
    assert "coverage_lost" in alerts[0].reason


def test_does_not_alert_when_nothing_moved() -> None:
    assert (
        _watch(_cycle(severity=Severity.HIGH), _cycle(severity=Severity.HIGH), policy=_lenient())
        == []
    )


def test_an_improvement_is_not_an_alert() -> None:
    alerts = _watch(_cycle(severity=Severity.HIGH), _cycle(), policy=_lenient())

    assert alerts == []


def test_a_cycle_that_became_incomparable_alerts_rather_than_crashing() -> None:
    """A monitor that dies on a surprising cycle stops watching — the worst outcome available."""
    alerts = _watch(
        _cycle(ran=("guardana.ep.watched",)),
        _cycle(ran=("guardana.ep.somethingelse",)),
        policy=_lenient(),
    )

    assert [a.cycle for a in alerts] == [1]
    assert "compare" in alerts[0].reason


def test_alerts_when_a_check_starts_failing_to_run_even_under_a_lenient_gate() -> None:
    """A rule that starts crashing mid-watch is strictly worse than one that cannot grade.

    Kept as its own condition rather than folded into the comparison: an error is
    not attached to a check's state — the check produced nothing at all — so there
    is no state transition for `compare` to see. A policy with `fail_on_error`
    turned off would otherwise let a monitor watch its own rules crash in silence.
    """
    lenient = Policy(fail_on=FailOn(severity=Severity.CRITICAL, fail_on_error=False))
    clean = ScanResult((), rules_run=_WATCHED, rules_skipped=())
    crashing = ScanResult(
        (),
        rules_run=_WATCHED,
        rules_skipped=(),
        errors=(CheckError("guardana.ep.rule0", "run", "ValueError: boom"),),
    )

    alerts = _watch(clean, crashing, policy=lenient)

    assert [a.cycle for a in alerts] == [1]
    assert "could not run" in alerts[0].reason
