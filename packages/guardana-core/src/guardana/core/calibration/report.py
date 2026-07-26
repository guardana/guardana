from dataclasses import dataclass

# Below this many graded samples the metrics are noise: a handful of lucky
# answers produce a perfect score. Reporting that as a calibration would be the
# false confidence this whole measurement exists to expose.
MIN_RELIABLE_SAMPLES = 30


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    """How wrong an evaluator's confidence actually is, measured against known labels.

    Two metrics, because they answer different questions. **Brier** is the mean
    squared error of the predicted probability — one number for "how good are
    these predictions overall". **Expected calibration error** asks the narrower
    and, here, more damning question: when this judge says it is 90% sure, is it
    right 90% of the time? A judge can be no better than a coin flip and still
    claim certainty every time; accuracy hides that, ECE names it.

    `inconclusive` is counted and excluded from both. A judge that abstained has
    not made a prediction, and scoring an abstention as one would invent data —
    but a judge that abstains on half the corpus is not calibrated, it is absent,
    so the count is reported and `is_reliable` refuses.
    """

    evaluator_id: str
    graded: int
    inconclusive: int
    accuracy: float
    brier: float
    expected_calibration_error: float
    caveat: str

    @property
    def is_reliable(self) -> bool:
        """Whether these numbers are worth quoting; `caveat` says why not."""
        return not self.caveat
