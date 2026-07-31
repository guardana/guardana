"""What changed between two runs, in the vocabulary a person can act on.

"More findings" is not the question anyone actually has. A check that used to
prove a problem and now cannot grade it at all is worse while the count stays
flat; a finding somebody waived is not a finding somebody fixed. Each of those
gets its own name here, because a comparison that collapses them into one number
cannot be trusted to say which way things moved.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from guardana.core.severity import Severity

Outcome = Literal["fail", "unverified"]

DIFF_SCHEMA_VERSION = 1
"""Version of the JSON document `guardana diff --format json` writes.

Its own number rather than the run report's: a comparison and a run are separate
documents, and tying them together would force one to move because the other did.
"""


class ChangeKind(StrEnum):
    """One way a run can differ from the one before it."""

    APPEARED = "appeared"
    """A problem where there was none — the plain regression."""

    PROVEN = "proven"
    """A check that could not grade now proves a problem.

    Not a new problem: a problem that was there yesterday and could not be shown.
    It fails the gate because the evidence is new, not the flaw.
    """

    BLINDED = "blinded"
    """A check that used to reach a verdict no longer can.

    Reported as a regression, and the case people forget: yesterday we knew, today
    we do not. Calling that an improvement because the finding count dropped is
    the exact lie the `unverified` channel exists to prevent.
    """

    ESCALATED = "escalated"
    """The same check, now at a higher severity."""

    COVERAGE_LOST = "coverage_lost"
    """A rule that ran before did not run this time.

    Its findings would have vanished from the report either way; without this,
    turning a rule off would be indistinguishable from fixing what it found.
    """

    RESOLVED = "resolved"
    """A problem that is no longer reported."""

    CLARIFIED = "clarified"
    """A check that could not grade now grades clean."""

    DE_ESCALATED = "de_escalated"
    """The same check, now at a lower severity."""

    COVERAGE_GAINED = "coverage_gained"
    """A rule ran this time that did not run before.

    Neutral in itself, but worth naming: findings from a newly-added rule are new
    coverage, not a model that got worse overnight.
    """

    WAIVER_CHANGED = "waiver_changed"
    """The same problem, differently waived.

    A waiver is a decision about policy, not about the system under test, so it is
    never an improvement — and never silently one.
    """

    COUNT_CHANGED = "count_changed"
    """The same check at the same outcome, over a different number of findings.

    Reported and never gated: under a live model this number is a function of
    sampling, and under a static scan a genuinely new problem lands in a new
    location, which is a new identity and a regression in its own right.
    """

    @property
    def is_regression(self) -> bool:
        """Whether this change means the second run is worse than the first."""
        return self in _REGRESSIONS

    @property
    def is_improvement(self) -> bool:
        """Whether this change means the second run is better than the first."""
        return self in _IMPROVEMENTS


_REGRESSIONS = frozenset(
    {
        ChangeKind.APPEARED,
        ChangeKind.PROVEN,
        ChangeKind.BLINDED,
        ChangeKind.ESCALATED,
        ChangeKind.COVERAGE_LOST,
    }
)

_IMPROVEMENTS = frozenset(
    {
        ChangeKind.RESOLVED,
        ChangeKind.CLARIFIED,
        ChangeKind.DE_ESCALATED,
        ChangeKind.COVERAGE_GAINED,
    }
)


@dataclass(frozen=True, slots=True)
class CheckState:
    """What one check (a rule, in one place) looked like in one run.

    Absent from a run's state map means one of two things, and only the run's list
    of executed rules can say which: the check ran and found nothing, or it never
    ran. Treating those as the same is how a narrowed profile reads as progress.
    """

    outcome: Outcome
    severity: Severity
    confidence: float
    """The most confident verdict behind this state; 1.0 when there is no verdict.

    A static finding has no evaluator and no doubt — a file either contains the
    opcode or it does not — which is the same reading `gate()` already takes.
    """

    count: int
    waived: bool


@dataclass(frozen=True, slots=True)
class Change:
    """One difference between two runs, attributed to the check that moved."""

    kind: ChangeKind
    rule_id: str
    location: str
    detail: str
    before: CheckState | None = None
    after: CheckState | None = None
    rule_changed: bool = False
    """Whether the rule's own definition differs between the two runs.

    A rule whose corpus was sharpened will find more; blaming the model for that
    is the wrong answer to "why is it worse", so the comparison says both.
    """


@dataclass(frozen=True, slots=True)
class RunDiff:
    """Everything that moved between two runs, and what to make of it."""

    changes: tuple[Change, ...]
    unchanged: int
    notes: tuple[str, ...] = ()
    """Things a reader needs in order to weigh the changes: a different tool
    version, rules that changed definition. Never a substitute for a change."""

    @property
    def regressions(self) -> tuple[Change, ...]:
        """Only the changes that mean things got worse."""
        return tuple(c for c in self.changes if c.kind.is_regression)

    @property
    def improvements(self) -> tuple[Change, ...]:
        """Only the changes that mean things got better."""
        return tuple(c for c in self.changes if c.kind.is_improvement)
