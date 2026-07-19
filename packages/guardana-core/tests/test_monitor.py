from guardana.core.evaluator import Verdict
from guardana.core.monitor import Alert, Monitor, MonitorConfig
from guardana.core.profile import FailOn, Policy
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity


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
    # A clean scan still ran rules; `rules_run` must be >= 1 or the gate treats it
    # as "nothing was checked" and fails (see runner.gate).
    return ScanResult(findings, rules_run=max(len(severities), 1), rules_skipped=())


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
    assert alerts[0].reason == "finding count exceeded baseline"


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
            rules_run=1,
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
            rule_id=f"guardana.ep.ungraded{i}",
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
    return ScanResult((), rules_run=1, rules_skipped=(), unverified=ungraded)


def test_alerts_when_unverified_count_rises_above_baseline() -> None:
    # The monitor's own checks going dark (judge down, empty replies) must not read
    # as a healthy model. A rising unverified count alerts even under the default
    # policy (fail_on_inconclusive=False), which does not gate on inconclusive.
    alerts: list[Alert] = []

    _monitor(_unverified(0), _unverified(2), max_cycles=2).run(alerts.append, sleep=lambda _s: None)

    assert [a.cycle for a in alerts] == [1]
    assert alerts[0].reason == "unverified count exceeded baseline"


def test_does_not_sleep_after_the_final_cycle() -> None:
    sleeps: list[float] = []

    _monitor(_result(), _result(), max_cycles=2, interval=5.0).run(
        lambda _a: None, sleep=sleeps.append
    )

    assert sleeps == [5.0]
