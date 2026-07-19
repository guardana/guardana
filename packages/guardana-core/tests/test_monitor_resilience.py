"""A monitor is a 24/7 process. A transient blip must not be fatal — but a
never-reachable endpoint must fail loudly instead of spinning forever."""

from collections.abc import Callable, Iterator

import pytest
from guardana.core.evaluator import Verdict
from guardana.core.monitor import Alert, Monitor, MonitorConfig
from guardana.core.profile import Policy
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.core.target import EndpointError

_CLEAN = ScanResult((), rules_run=1, rules_skipped=())
_HIT = ScanResult(
    (
        Finding(
            rule_id="guardana.ep.hit",
            severity=Severity.HIGH,
            title="hit",
            taxonomy=(),
            target_ref="http://fake#m",
            evidence=Evidence(summary="x"),
            verdict=Verdict(outcome="fail", confidence=0.9, rationale="r", evaluator_id="e"),
        ),
    ),
    rules_run=1,
    rules_skipped=(),
)


def _monitor(scan: Callable[[], ScanResult], *, max_cycles: int) -> Monitor:
    return Monitor(
        scan=scan,
        policy=Policy(),
        config=MonitorConfig(interval_seconds=0.0, max_cycles=max_cycles),
    )


def test_a_transient_failure_mid_run_does_not_kill_the_monitor() -> None:
    cycles: Iterator[ScanResult | Exception] = iter(
        [_CLEAN, OSError("connection reset by peer"), _HIT]
    )

    def scan() -> ScanResult:
        item = next(cycles)
        if isinstance(item, Exception):
            raise item
        return item

    alerts: list[Alert] = []
    errors: list[tuple[int, Exception]] = []

    _monitor(scan, max_cycles=3).run(
        alerts.append,
        on_error=lambda cycle, exc: errors.append((cycle, exc)),
        sleep=lambda _s: None,
    )

    assert [c for c, _ in errors] == [1]
    assert [a.cycle for a in alerts] == [2]


def test_an_endpoint_that_never_worked_fails_loudly_instead_of_spinning() -> None:
    # No successful cycle ever happened: this is a bad URL or a dead endpoint,
    # not a blip. Silently looping forever would hide a user's typo.
    def scan() -> ScanResult:
        raise EndpointError("nothing is listening")

    with pytest.raises(EndpointError):
        _monitor(scan, max_cycles=5).run(lambda _a: None, sleep=lambda _s: None)


def test_a_failed_cycle_does_not_corrupt_the_baseline() -> None:
    cycles: Iterator[ScanResult | Exception] = iter([_CLEAN, OSError("blip"), _CLEAN])

    def scan() -> ScanResult:
        item = next(cycles)
        if isinstance(item, Exception):
            raise item
        return item

    alerts: list[Alert] = []

    _monitor(scan, max_cycles=3).run(
        alerts.append, on_error=lambda _c, _e: None, sleep=lambda _s: None
    )

    # A skipped cycle must not be read as "findings dropped to zero" and then
    # "findings came back" — that would be a phantom regression alert.
    assert alerts == []


def test_a_programming_bug_is_never_swallowed() -> None:
    def scan() -> ScanResult:
        raise ZeroDivisionError("a real bug in a rule")

    with pytest.raises(ZeroDivisionError):
        _monitor(scan, max_cycles=2).run(
            lambda _a: None, on_error=lambda _c, _e: None, sleep=lambda _s: None
        )
