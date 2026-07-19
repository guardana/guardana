from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

from guardana.core.exchange import Exchange

Outcome = Literal["pass", "fail", "inconclusive"]


@dataclass(frozen=True, slots=True)
class Expectation:
    """What a robust model would have done — the yardstick an evaluator grades against."""

    canary: str | None = None
    goal: str | None = None


@dataclass(frozen=True, slots=True)
class Verdict:
    """An evaluator's judgement, with the confidence that makes it actionable.

    `confidence` is what lets a policy gate on "only fail CI on findings we're
    sure about" — a dynamic finding without it is unusable in CI.
    """

    outcome: Outcome
    confidence: float
    rationale: str
    evaluator_id: str

    def __post_init__(self) -> None:
        # Evaluators are third-party plugins; an out-of-range confidence would
        # silently distort policy gate thresholds, so the contract is enforced.
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be within [0.0, 1.0], got {self.confidence} "
                f"(evaluator {self.evaluator_id!r})"
            )


class Evaluator(ABC):
    """Decides whether an exchange is a finding, with a confidence."""

    id: str

    @abstractmethod
    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        """Grade one exchange against one expectation.

        Be honest about `confidence`: a cheap heuristic that reports 0.99 is worse
        than one that reports 0.5, because a policy trusts the number. When the
        exchange has no reply to grade (`reply_text is None`), return
        `inconclusive`, never `pass`.
        """
        ...
