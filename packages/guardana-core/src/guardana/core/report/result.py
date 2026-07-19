from dataclasses import dataclass

from guardana.core.report.finding import Finding
from guardana.core.severity import Severity


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything one run produced: what was found, what ran, and what was skipped.

    `rules_skipped` is part of the result on purpose — a scan that quietly ran half
    the rules it claimed to would be worse than no scan. `unverified` carries the
    same weight: a check that ran but could not reach a verdict (an unreachable
    judge, a guard model that declined, an empty reply) is surfaced here, never
    dropped into a false all-clear.
    """

    findings: tuple[Finding, ...]
    rules_run: int
    rules_skipped: tuple[str, ...]
    unverified: tuple[Finding, ...] = ()

    def max_severity(self) -> Severity | None:
        """Return the worst severity found, or None on a clean result."""
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)
