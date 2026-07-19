import pytest
from guardana.core.evaluator import Verdict


@pytest.mark.parametrize("confidence", [1.5, -0.1, 7.3])
def test_out_of_range_confidence_rejected(confidence: float) -> None:
    # Third-party evaluators are plugins; a confidence outside [0, 1] would
    # silently distort gate thresholds, so the contract is enforced here.
    with pytest.raises(ValueError, match="confidence"):
        Verdict(outcome="fail", confidence=confidence, rationale="r", evaluator_id="e")


@pytest.mark.parametrize("confidence", [0.0, 0.5, 1.0])
def test_in_range_confidence_allowed(confidence: float) -> None:
    v = Verdict(outcome="pass", confidence=confidence, rationale="r", evaluator_id="e")
    assert v.confidence == confidence
