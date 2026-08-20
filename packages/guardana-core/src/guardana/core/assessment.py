"""What a run *measured*, as opposed to what it found wrong.

`Finding` answers "what is unsafe here". It is the only channel a run had, and it
records problems — so a check that ran and was satisfied left no trace at all
beyond its rule id in `rules_run`. That is enough to gate a build and not enough
to answer the next question anybody asks: **did this get better?**

Fewer findings has three causes and they are not distinguishable from the finding
count alone: the system improved, the test got weaker, or the sample changed. An
`Assessment` is the record that tells them apart — one per case actually
measured, pass included, carrying what graded it and against what.

Deliberately a separate channel rather than a `Finding` with `severity: info`.
A measurement and a defect are different sentences: one has a denominator, a
direction and an uncertainty, the other has a severity and somebody who has to
act. Folding either into the other is how "82/100" ends up gating a release.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from guardana.core.fingerprint import digest_of

if TYPE_CHECKING:
    from guardana.core.evaluator.base import Verdict


class AssessmentStatus(StrEnum):
    """Whether this case produced a measurement, and if not, why not.

    The three non-`MEASURED` members exist so none of them can be silently read
    as zero. A judge that could not parse a reply, a request that never left, and
    a case the target cannot support are three different facts, and averaging any
    of them into a score invents data.
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

    Recorded with the value because it cannot be inferred from the number: a
    latency of 900 and a pass rate of 900 do not move the same way, and a
    comparison that guesses will report half of all regressions as improvements.
    """

    HIGHER_IS_BETTER = "higher_is_better"
    LOWER_IS_BETTER = "lower_is_better"


@dataclass(frozen=True, slots=True)
class Assessment:
    """One case, measured once, by something that says what it was.

    `case_id` is the identity two runs are paired on. It has to be stable across
    runs and to *change* when the case changes — a rewritten prompt is a different
    test, and pairing it with the old one under the same name is precisely the
    comparison this channel exists to refuse.
    """

    case_id: str
    assessor: str
    """What produced the verdict — an evaluator id, or a rule grading in its own code."""

    subject_ref: str
    """What was measured: the target's `ref`, so a report names its own subject."""

    status: AssessmentStatus = AssessmentStatus.MEASURED
    rule_id: str = ""
    passed: bool | None = None
    """The boolean reading, or None when this case has no pass/fail sense.

    None for a pure measurement (latency, token count). Never `False` because the
    measurement could not be taken — that is what `status` is for.
    """

    value: float | None = None
    unit: str | None = None
    direction: Direction | None = None
    threshold: float | None = None
    """The bound `passed` was decided against in *this* run.

    Recorded per assessment rather than looked up later: a threshold that moved
    between two runs changes the verdict without changing the system, and a
    comparison that cannot see the old bound reports that as a regression.
    """

    confidence: float | None = None
    """How much the assessor trusts its own verdict, when it can say. Never invented."""

    dataset: str | None = None
    """Which versioned corpus this case came from, when it came from one.

    Part of comparability: the same `case_id` from two different datasets is two
    different tests wearing one name.
    """

    rationale: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
    """Slices a comparison may group by — language, category, tenant class."""

    @property
    def is_comparable_key(self) -> tuple[str, str, str | None]:
        """The triple two runs must agree on before their values may be compared."""
        return (self.case_id, self.assessor, self.dataset)


def case_id_for(rule_id: str, *parts: str) -> str:
    """Build a stable case id for a rule and the text that distinguishes the case.

    Hashed rather than positional. An index (`rule#0`) is stable only until the
    prompts are reordered, at which point every case silently pairs with a
    different one and the diff is confidently wrong. Hashing the text instead
    makes a reordering a no-op and a *rewording* a new case — which is the honest
    reading, because a rewritten prompt is not the same test.

    The text is not recoverable from the id: it is a digest, so a case id may be
    published in a report that redacts the prompt it came from.
    """
    # `digest_of` names its algorithm (`sha256:…`); the id carries the hash only,
    # because the algorithm is already recorded once per run in the manifest.
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

    `passed` is `None` for an inconclusive verdict, never `False`. The distinction
    is the whole reason this channel is not a boolean: a judge that could not read
    the reply has not observed a failure, and counting it as one makes a broken
    grader look like a worsening model — which is the direction that gets acted on.
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
