"""What did the checking, with what calibration, and what came of it."""

from dataclasses import dataclass
from datetime import datetime

from guardana.core.gate import GateOutcome
from guardana.core.report.stop import StopReason


@dataclass(frozen=True, slots=True)
class RuleRecord:
    """One rule that ran, with the digest of what it was when it ran.

    The digest is what stops a sharpened rule from being read as a worse model:
    more findings from a rule whose corpus grew is the test talking, not the
    target.
    """

    id: str
    digest: str
    version: str | None = None
    maturity: str | None = None


@dataclass(frozen=True, slots=True)
class CalibrationRecord:
    """How well an evaluator's confidence was measured, and when.

    `measured_at` matters as much as the scores: a calibration from six months
    ago describes a judge model that has since been replaced under the same name.
    """

    dataset_digest: str | None = None
    measured_at: datetime | None = None
    brier: float | None = None
    ece: float | None = None


@dataclass(frozen=True, slots=True)
class EvaluatorRecord:
    """One evaluator that graded, with its calibration when it has one."""

    id: str
    version: str | None = None
    digest: str | None = None
    calibration: CalibrationRecord | None = None


@dataclass(frozen=True, slots=True)
class ResultSummary:
    """The counts and the verdict, written by the engine rather than inferred.

    `gate` is a stored field on purpose. A consumer that re-derives the verdict
    from the counts will eventually derive it differently from the engine — a
    threshold read from the wrong place, an `unverified` channel nobody knew
    about — and the divergence shows up as a green build.

    It is nullable for exactly one case: a document migrated from schema version
    1, which never recorded a verdict. Computing one during migration would be
    that same re-derivation, done with this build's thresholds against another
    build's run — so the honest answer is that the old document does not say.
    """

    findings: int
    unverified: int
    waived: int
    errors: int
    observations: int
    rules_run: tuple[str, ...]
    rules_skipped: tuple[str, ...]
    max_severity: str | None
    gate: GateOutcome | None
    stopped_by: StopReason | None = None
