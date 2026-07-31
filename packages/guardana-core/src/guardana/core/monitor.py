import time
from collections.abc import Callable
from dataclasses import dataclass

from guardana.core.diff import IncomparableRunsError, compare
from guardana.core.profile.model import Policy
from guardana.core.report import ScanResult
from guardana.core.runner import gate
from guardana.core.target import EndpointError

# A monitored endpoint blips: a rate-limit, a 502, a dropped connection. A 24/7
# loop must survive those. A programming bug (anything else) must not be
# swallowed — it propagates so the operator sees it.
_TRANSIENT = (OSError, EndpointError)


@dataclass(frozen=True, slots=True)
class MonitorConfig:
    """How often to sample, and (in tests/CI) when to stop."""

    interval_seconds: float
    max_cycles: int | None = None


@dataclass(frozen=True, slots=True)
class Alert:
    """A cycle whose result crossed the line — with the reason it did."""

    cycle: int
    result: ScanResult
    reason: str


@dataclass(frozen=True, slots=True)
class Monitor:
    """A sampling observer: re-runs a scan on a loop and alerts on regression.

    Alerts when the policy gate fails, when a check that could not run appears, or
    when the cycle is *worse* than the first one by the same definition
    `guardana diff` uses — a new problem, a problem finally proven, a rising
    severity, a rule that stopped running, or a check that can no longer grade
    what it used to. That last one lowers the finding count, so a monitor
    comparing counts would have read going blind as an improvement.

    The scan is injected as a plain callable, so the monitor stays agnostic about
    what it samples. The CLI passes the very same probe `guardana probe` runs —
    which is how each monitored cycle plants a fresh canary instead of silently
    skipping the rules that need one.

    Not an inline production sidecar — a polling loop meant to run alongside a
    served model.
    """

    scan: Callable[[], ScanResult]
    policy: Policy
    config: MonitorConfig

    def _alert_reason(self, result: ScanResult, baseline: ScanResult) -> str | None:
        """Why this cycle should alert, or None if it shouldn't.

        Regression is not decided here. It is decided by `guardana.core.diff`, the
        same code `guardana diff` runs, because two definitions of "worse" in one
        project drift apart and the one that drifts is the one nobody reads. What
        this used to compare — three counts — could not see a finding that got more
        severe, or a check that stopped being gradable while the count stayed flat.
        """
        if gate(result, self.policy):
            return "gate failed"
        if len(result.errors) > len(baseline.errors):
            return "checks that could not run exceeded baseline"
        try:
            diff = compare(baseline, result)
        except IncomparableRunsError as exc:
            # A cycle that cannot be compared to the first one is a change in
            # itself — most likely the plan collapsing. Alerting is right; dying
            # here would stop the watch, which is the worst outcome available.
            return f"this cycle could not be compared with the first: {exc}"
        regressions = diff.regressions
        if not regressions:
            return None
        return "worse than the first cycle: " + ", ".join(
            sorted({change.kind.value for change in regressions})
        )

    def run(
        self,
        on_alert: Callable[[Alert], None],
        *,
        on_error: Callable[[int, Exception], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Sample until `max_cycles` is reached (forever, if it is None).

        A transient endpoint failure during a cycle is reported to `on_error`
        (if given) and the loop continues — one blip must not kill a long-running
        monitor. But a failure before any cycle has ever succeeded is not a blip;
        it's a dead endpoint or a bad URL, and it propagates rather than spinning.

        `sleep` is injectable so tests exercise the loop without waiting.
        """
        baseline: ScanResult | None = None
        cycle = 0
        while self.config.max_cycles is None or cycle < self.config.max_cycles:
            if cycle:
                sleep(self.config.interval_seconds)
            try:
                result = self.scan()
            except _TRANSIENT as exc:
                if baseline is None:
                    raise  # never worked once — surface it, don't loop on it
                if on_error is not None:
                    on_error(cycle, exc)
                cycle += 1
                continue

            if baseline is None:
                baseline = result
            reason = self._alert_reason(result, baseline)
            if reason is not None:
                on_alert(Alert(cycle, result, reason))
            cycle += 1
