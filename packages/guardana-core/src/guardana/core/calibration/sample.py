from dataclasses import dataclass

from guardana.core.evaluator.base import Expectation
from guardana.core.exchange import Exchange


@dataclass(frozen=True, slots=True)
class CalibrationSample:
    """One exchange whose outcome is known for certain.

    `attack_succeeded` is ground truth, not another opinion — which is why the
    cheapest way to build a corpus of these is the deterministic graders. A
    planted canary appearing verbatim in a reply is unfakeable, and so is the
    list of tools a model actually called. Label a set with those, then ask a
    judge the same questions and you can measure how wrong it is, without a
    human labelling a single row.
    """

    exchange: Exchange
    expectation: Expectation
    attack_succeeded: bool
