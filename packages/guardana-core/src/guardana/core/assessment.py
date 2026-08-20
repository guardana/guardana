"""What a run *measured*, as opposed to what it found wrong.

One record per case actually measured, pass included — the passes are what give a
rate a denominator. A separate channel from `Finding` because a measurement and a
defect are different sentences: one has a denominator, a direction and an
uncertainty; the other has a severity and somebody who has to act.

Why it is shaped this way, and what was rejected:
[`docs/design/assessment-channel.md`](../../../../../docs/design/assessment-channel.md).
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from guardana.core.fingerprint import digest_of

if TYPE_CHECKING:
    from guardana.core.evaluator.base import Verdict


class AssessmentStatus(StrEnum):
    """Whether this case produced a measurement, and if not, why not.

    The three non-`MEASURED` members exist so none of them can be read as zero:
    averaging a case nobody could measure into a score invents data.
    """

    MEASURED = "measured"
    INCONCLUSIVE = "inconclusive"
    """The case ran and no trustworthy verdict came back. Never a pass, never a zero."""

    ERROR = "error"
    """The case did not run. Distinct from `INCONCLUSIVE`: nothing was even attempted."""

    SKIPPED = "skipped"
    """The case was not applicable here — an explicit absence, not a low score."""


class Direction(StrEnum):
    """Which way is better, for a numeric measurement.

    Recorded with the value, never inferred from it: a latency of 900 and a score
    of 900 do not move the same way.
    """

    HIGHER_IS_BETTER = "higher_is_better"
    LOWER_IS_BETTER = "lower_is_better"


@dataclass(frozen=True, slots=True)
class Assessment:
    """One case, measured once, by something that says what it was.

    `case_id` is the identity two runs are paired on: stable across runs, and
    different when the case itself is different.
    """

    case_id: str
    assessor: str
    """What produced the verdict — an evaluator id, or a rule grading in its own code."""

    subject_ref: str
    """What was measured: the target's `ref`, so a report names its own subject."""

    status: AssessmentStatus = AssessmentStatus.MEASURED
    rule_id: str = ""
    passed: bool | None = None
    """The boolean reading; None for a pure measurement, or for one nobody could take.

    Never `False` because the measurement failed — that is what `status` is for.
    """

    value: float | None = None
    unit: str | None = None
    direction: Direction | None = None
    threshold: float | None = None
    """The bound `passed` was decided against in *this* run, not the current one.

    A threshold that moved changes the verdict without changing the system.
    """

    confidence: float | None = None
    """How much the assessor trusts its own verdict, when it can say. Never invented."""

    dataset: str | None = None
    """Which versioned corpus this case came from, when it came from one.

    The same `case_id` over two datasets is two tests wearing one name, so this is
    part of `comparable_key`.
    """

    rationale: str = ""
    tags: tuple[str, ...] = ()
    """Slices a comparison may group by — language, category, tenant class."""

    @property
    def comparable_key(self) -> tuple[str, str, str | None]:
        """Return the triple two runs must agree on before their values may be compared."""
        return (self.case_id, self.assessor, self.dataset)


def case_id_for(rule_id: str, *parts: str) -> str:
    """Build a stable case id for a rule and the text that distinguishes the case.

    Hashed rather than positional: an index survives until somebody reorders the
    prompts, after which every case pairs with a different one and the comparison
    is confidently wrong. A digest also means the id is safe in a report that
    redacts the text it was built from.
    """
    # The algorithm prefix `digest_of` adds is dropped: it is already recorded once
    # per run in the manifest, and an id is read by people.
    return f"{rule_id}#{digest_of(*parts).split(':', 1)[-1][:12]}"


def from_verdict(  # noqa: PLR0913 — one keyword per fact the verdict cannot supply
    verdict: "Verdict",
    *,
    case_id: str,
    subject_ref: str,
    rule_id: str,
    dataset: str | None = None,
    tags: tuple[str, ...] = (),
) -> Assessment:
    """Turn one graded exchange into a measurement, keeping "could not grade" apart.

    `passed` is `None` for an inconclusive verdict, never `False`: a judge that
    could not read the reply has not observed a failure, and counting it as one
    makes a broken grader look like a worsening model.
    """
    inconclusive = verdict.outcome == "inconclusive"
    return Assessment(
        case_id=case_id,
        assessor=verdict.evaluator_id,
        subject_ref=subject_ref,
        status=AssessmentStatus.INCONCLUSIVE if inconclusive else AssessmentStatus.MEASURED,
        rule_id=rule_id,
        passed=None if inconclusive else verdict.outcome == "pass",
        confidence=None if inconclusive else verdict.confidence,
        dataset=dataset,
        rationale=verdict.rationale,
        tags=tags,
    )
