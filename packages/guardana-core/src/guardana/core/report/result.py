from collections.abc import Sequence
from dataclasses import dataclass

from guardana.core.observation import Observation
from guardana.core.report.check_error import CheckError
from guardana.core.report.finding import Finding
from guardana.core.severity import Severity


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything one run produced: what was found, what ran, and what was skipped.

    `rules_skipped` is part of the result on purpose — a scan that quietly ran half
    the rules it claimed to would be worse than no scan. `unverified` carries the
    same weight: a check that ran but could not reach a verdict (an unreachable
    judge, a guard model that declined, an empty reply) is surfaced here, never
    dropped into a false all-clear. `waived` holds findings a baseline explicitly
    accepted with a reason: they no longer fail the gate, but they are still
    reported — a suppression you can see, never a silent drop. `observations` is
    the one channel that is not about problems: the components the run saw, so
    "what is deployed here" and "what changed since last time" are answerable
    without walking the target again.
    """

    findings: tuple[Finding, ...]
    rules_run: int
    rules_skipped: tuple[str, ...]
    unverified: tuple[Finding, ...] = ()
    waived: tuple[Finding, ...] = ()
    errors: tuple[CheckError, ...] = ()
    observations: tuple[Observation, ...] = ()

    @classmethod
    def merged(cls, results: Sequence["ScanResult"]) -> "ScanResult":
        """Combine several results into one, carrying every channel.

        Callers used to rebuild this dataclass field by field, which meant a
        channel added later was silently dropped by whoever forgot to pass it —
        exactly how `errors` went missing from probe, monitor and baselines. One
        constructor knows the full shape, so there is nowhere left to forget.
        """
        return cls(
            findings=tuple(f for r in results for f in r.findings),
            rules_run=sum(r.rules_run for r in results),
            rules_skipped=tuple(s for r in results for s in r.rules_skipped),
            unverified=tuple(f for r in results for f in r.unverified),
            waived=tuple(f for r in results for f in r.waived),
            errors=tuple(e for r in results for e in r.errors),
            # De-duplicated by ref: probe runs the same target several times (one
            # pass per planted canary), and the model under test is one component,
            # not one per pass.
            observations=tuple({o.ref: o for r in results for o in r.observations}.values()),
        )

    def max_severity(self) -> Severity | None:
        """Return the worst severity found, or None on a clean result."""
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)
