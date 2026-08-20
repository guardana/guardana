from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from guardana.core.assessment import Assessment, AssessmentStatus
from guardana.core.observation import Observation
from guardana.core.report.check_error import CheckError
from guardana.core.report.finding import Finding
from guardana.core.report.shortfall import CoverageShortfall
from guardana.core.report.skipped import SkippedRule
from guardana.core.report.stop import StopReason
from guardana.core.severity import Severity
from guardana.core.usage import TargetUsage, total


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything one run produced: what was found, what ran, and what was skipped.

    `rules_run` names the rules rather than counting them, and `rules_skipped` is
    part of the result on purpose, and each skip carries *why* — a scan that
    quietly ran half the rules it claimed to would be worse than no scan, and a
    rule skipped because the provider cannot do something is a different fact
    from one that never applied. A count cannot tell "this rule found
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
    rules_skipped: tuple[SkippedRule, ...]
    unverified: tuple[Finding, ...] = ()
    waived: tuple[Finding, ...] = ()
    errors: tuple[CheckError, ...] = ()
    observations: tuple[Observation, ...] = ()
    coverage_shortfall: tuple[CoverageShortfall, ...] = ()
    """Coverage the operator demanded and this run did not get. Never a pass.

    The one channel with no policy toggle in front of it, and that is what it is
    for: `fail_on_skipped` defaults to off because most skips are ordinary, so a
    contract that could not be checked would otherwise exit `0` by default. A
    demand somebody wrote down and did not get is `indeterminate`, and there is
    nothing to switch off.
    """

    stopped_by: StopReason | None = None
    usage: TargetUsage | None = None
    """What the target spent producing this result, or None if it does not count.

    On the result rather than passed around beside it, so a caller that assembles
    a report cannot forget to carry it — the same reason every other channel lives
    here.
    """

    assessments: tuple[Assessment, ...] = ()
    """Every case this run measured, pass included. See `guardana.core.assessment`.

    The channel that makes a denominator exist: findings alone cannot separate a
    system that improved from a test that got weaker, because both lower the count.
    Empty is honest — an artifact scan looks for defects and measures nothing.
    """

    protocols: Mapping[str, str] = field(default_factory=dict)
    """Protocol versions the target negotiated, by protocol name; see `Target.protocols`.

    Carried here for the same reason as `usage`: only the target knows, only the
    runner holds the target, and a fact that has to be fetched separately by every
    caller is a fact some caller will forget. It lands in the manifest's coverage
    fingerprint, so a server that answered with an older revision — and therefore
    supported fewer methods — is visible as reduced reach rather than as a system
    that improved.
    """

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
            # De-duplicated by rule: probe runs several passes against one
            # target, and a rule the target cannot satisfy is one gap, not three.
            rules_skipped=tuple({s.rule_id: s for r in results for s in r.rules_skipped}.values()),
            unverified=tuple(f for r in results for f in r.unverified),
            waived=tuple(f for r in results for f in r.waived),
            # De-duplicated by comparability key: probe runs each case once per
            # planted canary, and three copies would inflate every rate.
            assessments=tuple(
                {a.comparable_key: a for r in results for a in r.assessments}.values()
            ),
            errors=tuple(e for r in results for e in r.errors),
            # De-duplicated by ref: probe runs the same target several times (one
            # pass per planted canary), and the model under test is one component,
            # not one per pass.
            observations=tuple({o.ref: o for r in results for o in r.observations}.values()),
            # De-duplicated by what was demanded: probe merges one result per
            # planted canary, and one unrecorded dimension is one shortfall however
            # many passes noticed it.
            coverage_shortfall=tuple(
                {(s.kind, s.name): s for r in results for s in r.coverage_shortfall}.values()
            ),
            # A stop recorded in any pass is a stop for the whole run: probe merges
            # one result per planted canary, and a budget that ran out during the
            # third pass leaves the first two looking complete. Dropping it here
            # would hand the merged report a completeness it does not have.
            stopped_by=next((r.stopped_by for r in results if r.stopped_by is not None), None),
            # Summed across passes: probe builds one target per planted canary, and
            # the run's bill is all of them. One unmetered pass makes the total
            # unknown rather than partial — see `total`.
            usage=total([r.usage for r in results]),
            # Merged rather than taken from the last pass: probe builds one target
            # per planted canary against one server, so every pass negotiated the
            # same protocol, and reading it off whichever finished last would lose
            # it entirely whenever that pass happened not to open a session.
            protocols={name: v for r in results for name, v in r.protocols.items()},
        )

    @property
    def skipped_rule_ids(self) -> tuple[str, ...]:
        """Just the ids of the rules that did not run, for callers that need only those."""
        return tuple(skip.rule_id for skip in self.rules_skipped)

    @property
    def rules_run_count(self) -> int:
        """How many rules ran. Derived, never stored, so it cannot drift from the names."""
        return len(self.rules_run)

    @property
    def verified_nothing(self) -> bool:
        """Whether this run reached no conclusion at all, about anything.

        A rule concludes by finding something, by finding something a baseline
        accepted, or by running and leaving no `unverified` entry behind. A rule
        that ran and could only decline concluded nothing — and a run made entirely
        of those established exactly as much as a run that executed no rule.

        Which is the point: `rules_run` being empty is already an unconditional
        `indeterminate`, and it counts *executions*. An endpoint that answers every
        request with an empty message makes every rule execute and none of them
        grade, so the run passes that guard with a full count and a verdict it did
        not earn.

        Deliberately not the same question as `fail_on_inconclusive`, which is a
        preference about *some* checks going dark and stays opt-in. This one is the
        whole run, and no toggle stands in front of it.
        """
        declined = {f.rule_id for f in self.unverified}
        concluded = (
            {f.rule_id for f in self.findings}
            | {f.rule_id for f in self.waived}
            | (set(self.rules_run) - declined)
        )
        return not concluded

    def max_severity(self) -> Severity | None:
        """Return the worst severity found, or None on a clean result."""
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    @property
    def measured(self) -> tuple[Assessment, ...]:
        """Only the assessments that actually produced a value — the denominator.

        A rate computed over cases nobody could measure describes the harness, not
        the system, so the other three statuses are excluded rather than failed.
        """
        return tuple(a for a in self.assessments if a.status is AssessmentStatus.MEASURED)

    @property
    def ungraded(self) -> tuple[Assessment, ...]:
        """Assessments that were attempted and produced no trustworthy verdict.

        Beside `measured` so a shrinking denominator is as legible as a falling
        score: a broken judge otherwise reports a perfect rate over two cases.
        """
        return tuple(a for a in self.assessments if a.status is AssessmentStatus.INCONCLUSIVE)
