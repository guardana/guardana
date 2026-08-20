"""How the measurement channel moved between two runs, paired case by case.

What the change list cannot show: *over how many cases*. A suite that graded forty
yesterday and twelve today reports fewer findings, which every change kind reads
as an improvement.

Deliberately not a second report of per-case pass→fail — that already reaches the
comparison as a `Finding`, and counting it twice would double the one thing the
diff is most careful about. What is new is the denominator, the pairing, and the
refusal to compare cases whose definition moved.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from guardana.core.assessment import Assessment, AssessmentStatus

_NAMED_IN_A_NOTE = 3
"""How many case ids a note quotes before it stops. A note nobody finishes is a
note nobody reads, and the count above it is the part that matters."""


@dataclass(frozen=True, slots=True)
class MeasurementDelta:
    """The measured sample of two runs, paired on `case_id`.

    Every field is a count of cases, never of runs. `paired` is the only population
    any rate may be computed over: the others are the reasons a case is outside it,
    kept apart so none of them can be quietly read as a zero.
    """

    paired: int = 0
    """Cases both runs measured, with the same assessor and the same dataset."""

    incomparable: int = 0
    """Cases both runs have, graded by a different assessor or over a different dataset.

    Excluded from every rate rather than counted as changed. A rule whose
    expectation was edited produces the same `case_id` and a different definition
    of passing it, and pairing those two would attribute an authoring decision to
    the system under test.
    """

    only_before: int = 0
    only_after: int = 0
    passed_before: int = 0
    passed_after: int = 0
    blinded: tuple[str, ...] = ()
    """Cases that produced a value before and could not be graded this time.

    Named individually because this is the shape of going blind: the finding count
    falls, every gate stays green, and the reason is that the grader stopped
    working rather than that the model started behaving.
    """

    @property
    def sample_shrank(self) -> bool:
        """Whether the second run measured fewer of the paired cases than the first."""
        return bool(self.blinded) or self.only_before > self.only_after

    def notes(self) -> tuple[str, ...]:
        """Sentences a reader needs before believing any rate computed from this."""
        lines: list[str] = []
        if self.incomparable:
            lines.append(
                f"{self.incomparable} measured case(s) were not compared: the assessor or "
                f"the dataset changed, so the two results are not answers to one question"
            )
        if self.blinded:
            shown = self.blinded[:_NAMED_IN_A_NOTE]
            more = ", …" if len(self.blinded) > _NAMED_IN_A_NOTE else ""
            lines.append(
                f"{len(self.blinded)} case(s) produced a value before and could not be "
                f"graded this time ({', '.join(shown)}{more}) — a smaller sample, not a "
                f"better result"
            )
        if self.only_before:
            lines.append(f"{self.only_before} case(s) measured before are absent from this run")
        return tuple(lines)


def measure(before: Sequence[Assessment], after: Sequence[Assessment]) -> MeasurementDelta:
    """Pair two runs' assessments on `case_id` and count what each population is.

    Paired on the case alone, then checked for comparability — not paired on the
    full comparability key. Keying on all three would make an edited expectation
    look like one case disappearing and another arriving, which reads as lost
    coverage plus new coverage: two changes, both wrong, for one edit.
    """
    lhs = {a.case_id: a for a in before}
    rhs = {a.case_id: a for a in after}
    paired = incomparable = passed_before = passed_after = 0
    blinded: list[str] = []
    for case_id in sorted(lhs.keys() & rhs.keys()):
        was, now = lhs[case_id], rhs[case_id]
        if was.comparable_key != now.comparable_key:
            incomparable += 1
            continue
        if was.status is AssessmentStatus.MEASURED and now.status is not AssessmentStatus.MEASURED:
            blinded.append(case_id)
        if (
            was.status is not AssessmentStatus.MEASURED
            or now.status is not AssessmentStatus.MEASURED
        ):
            continue
        paired += 1
        passed_before += 1 if was.passed else 0
        passed_after += 1 if now.passed else 0
    return MeasurementDelta(
        paired=paired,
        incomparable=incomparable,
        only_before=len(lhs.keys() - rhs.keys()),
        only_after=len(rhs.keys() - lhs.keys()),
        passed_before=passed_before,
        passed_after=passed_after,
        blinded=tuple(blinded),
    )
