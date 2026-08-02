from collections.abc import Sequence
from dataclasses import dataclass

from guardana.core.observation import Observation
from guardana.core.report.check_error import CheckError
from guardana.core.report.finding import Finding
from guardana.core.report.stop import StopReason
from guardana.core.severity import Severity


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything one run produced: what was found, what ran, and what was skipped.

    `rules_run` names the rules rather than counting them, and `rules_skipped` is
    part of the result on purpose — a scan that quietly ran half the rules it
    claimed to would be worse than no scan. A count cannot tell "this rule found
    nothing" from "this rule never ran", so two runs with different profiles would
    compare as an improvement; the names are what make that lie impossible.
    `unverified` carries the
    same weight: a check that ran but could not reach a verdict (an unreachable
    judge, a guard model that declined, an empty reply) is surfaced here, never
    dropped into a false all-clear. `waived` holds findings a baseline explicitly
    accepted with a reason: they no longer fail the gate, but they are still
    reported — a suppression you can see, never a silent drop. `observations` is
    the one channel that is not about problems: the components the run saw, so
    "what is deployed here" and "what changed since last time" are answerable
    without walking the target again.

    `stopped_by` is set when the run ended before finishing its plan. It belongs
    to the result and not only to the exit code, because the report outlives the
    process that wrote it: one that does not say it was cut short reads as a
    complete pass, and its smaller finding count reads as an improvement.
    """

    findings: tuple[Finding, ...]
    rules_run: tuple[str, ...]
    rules_skipped: tuple[str, ...]
    unverified: tuple[Finding, ...] = ()
    waived: tuple[Finding, ...] = ()
    errors: tuple[CheckError, ...] = ()
    observations: tuple[Observation, ...] = ()
    stopped_by: StopReason | None = None

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
            # De-duplicated: probe runs the same rule once per planted canary, and
            # a rule that ran three times still ran once as far as coverage goes.
            rules_run=tuple(dict.fromkeys(rule for r in results for rule in r.rules_run)),
            rules_skipped=tuple(s for r in results for s in r.rules_skipped),
            unverified=tuple(f for r in results for f in r.unverified),
            waived=tuple(f for r in results for f in r.waived),
            errors=tuple(e for r in results for e in r.errors),
            # De-duplicated by ref: probe runs the same target several times (one
            # pass per planted canary), and the model under test is one component,
            # not one per pass.
            observations=tuple({o.ref: o for r in results for o in r.observations}.values()),
            # A stop recorded in any pass is a stop for the whole run: probe merges
            # one result per planted canary, and a budget that ran out during the
            # third pass leaves the first two looking complete. Dropping it here
            # would hand the merged report a completeness it does not have.
            stopped_by=next((r.stopped_by for r in results if r.stopped_by is not None), None),
        )

    @property
    def rules_run_count(self) -> int:
        """How many rules ran. Derived, never stored, so it cannot drift from the names."""
        return len(self.rules_run)

    def max_severity(self) -> Severity | None:
        """Return the worst severity found, or None on a clean result."""
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)
