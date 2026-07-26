from collections.abc import Sequence

from guardana.core.calibration.report import MIN_RELIABLE_SAMPLES, CalibrationReport
from guardana.core.calibration.sample import CalibrationSample
from guardana.core.evaluator.base import Evaluator

_BINS = 10
# (probability the attack succeeded, what the evaluator said, what happened)
_Prediction = tuple[float, bool, bool]
# Above this the evaluator is predicting the attack succeeded; below it, that it
# did not. A prediction sitting exactly here is a coin flip and counts as 'fail'.


def calibrate(evaluator: Evaluator, samples: Sequence[CalibrationSample]) -> CalibrationReport:
    """Measure how honest an evaluator's confidence is against known-correct labels.

    Asks the evaluator to grade every sample, then compares what it said — and how
    sure it was — with what actually happened. Raises on an empty corpus: there is
    no such thing as a calibration of nothing, and returning zeros would read like
    a perfect score.
    """
    if not samples:
        raise ValueError("a calibration needs at least one labelled sample")
    predictions: list[tuple[float, bool, bool]] = []
    inconclusive = 0
    for sample in samples:
        verdict = evaluator.evaluate(sample.exchange, sample.expectation)
        if verdict.outcome == "inconclusive":
            inconclusive += 1
            continue
        # The stated outcome is carried, never re-derived from the probability.
        # Deriving it meant any verdict at or below half confidence was scored as
        # the opposite prediction — so `LengthEvaluator`, which passes at exactly
        # 0.5, measured as 0% accurate while grading every sample correctly.
        predicted = verdict.outcome == "fail"
        probability = verdict.confidence if predicted else 1.0 - verdict.confidence
        predictions.append((probability, predicted, sample.attack_succeeded))
    return CalibrationReport(
        evaluator_id=evaluator.id,
        graded=len(predictions),
        inconclusive=inconclusive,
        accuracy=_accuracy(predictions),
        brier=_brier(predictions),
        expected_calibration_error=_ece(predictions),
        caveat=_caveat(len(predictions), inconclusive),
    )


def _caveat(graded: int, inconclusive: int) -> str:
    if graded == 0:
        return f"nothing was graded: the evaluator returned inconclusive {inconclusive} time(s)"
    if graded < MIN_RELIABLE_SAMPLES:
        return f"only {graded} graded samples; at least {MIN_RELIABLE_SAMPLES} are needed"
    corpus = graded + inconclusive
    if inconclusive * 2 >= corpus:
        return f"the evaluator abstained on {inconclusive} of {corpus} samples"
    return ""


def _accuracy(predictions: list[_Prediction]) -> float:
    if not predictions:
        return 0.0
    return sum(1 for _, predicted, actual in predictions if predicted == actual) / len(predictions)


def _brier(predictions: list[_Prediction]) -> float:
    if not predictions:
        return 0.0
    return sum((probability - actual) ** 2 for probability, _, actual in predictions) / len(
        predictions
    )


def _ece(predictions: list[_Prediction]) -> float:
    """Bin by stated confidence, then compare each bin's claim with its hit rate."""
    if not predictions:
        return 0.0
    bins: list[list[_Prediction]] = [[] for _ in range(_BINS)]
    for probability, predicted, actual in predictions:
        # A prediction's *confidence* is its distance from a coin flip, so 0.1 and
        # 0.9 are equally confident — the first that it did not happen.
        confidence = max(probability, 1.0 - probability)
        index = min(int(confidence * _BINS), _BINS - 1)
        bins[index].append((probability, predicted, actual))
    total = len(predictions)
    error = 0.0
    for bucket in bins:
        if not bucket:
            continue
        stated = sum(max(p, 1.0 - p) for p, _, _ in bucket) / len(bucket)
        observed = sum(1 for _, predicted, actual in bucket if predicted == actual) / len(bucket)
        error += (len(bucket) / total) * abs(observed - stated)
    return error
