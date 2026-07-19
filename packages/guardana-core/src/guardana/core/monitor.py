import time
from collections.abc import Callable
from dataclasses import dataclass

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

    Alerts when the policy gate fails, when the finding count rises above the
    baseline established on the first cycle, or when the count of checks it can no
    longer grade (`unverified`) rises above that baseline — a monitor whose own
    security checks quietly stop grading must never keep reporting all-clear.

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

    def _alert_reason(
        self, result: ScanResult, findings_baseline: int, unverified_baseline: int
    ) -> str | None:
        """Why this cycle should alert, or None if it shouldn't."""
        if gate(result, self.policy):
            return "gate failed"
        if len(result.findings) > findings_baseline:
            return "finding count exceeded baseline"
        if len(result.unverified) > unverified_baseline:
            return "unverified count exceeded baseline"
        return None

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
        established = False
        findings_baseline = 0
        unverified_baseline = 0
        cycle = 0
        while self.config.max_cycles is None or cycle < self.config.max_cycles:
            if cycle:
                sleep(self.config.interval_seconds)
            try:
                result = self.scan()
            except _TRANSIENT as exc:
                if not established:
                    raise  # never worked once — surface it, don't loop on it
                if on_error is not None:
                    on_error(cycle, exc)
                cycle += 1
                continue

            if not established:
                established = True
                findings_baseline = len(result.findings)
                unverified_baseline = len(result.unverified)
            reason = self._alert_reason(result, findings_baseline, unverified_baseline)
            if reason is not None:
                on_alert(Alert(cycle, result, reason))
            cycle += 1
