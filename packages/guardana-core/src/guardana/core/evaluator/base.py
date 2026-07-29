from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import ClassVar, Literal

from guardana.core.exchange import Exchange

Outcome = Literal["pass", "fail", "inconclusive"]


@dataclass(frozen=True, slots=True)
class Expectation:
    """What a robust model would have done — the yardstick an evaluator grades against.

    `canary` and `goal` are typed because the engine itself handles them: the probe
    plants the canary, and every grading path can render a goal. Anything else an
    evaluator needs lives in `fields`, the same open door a third-party evaluator
    uses — so a built-in and a plugin declare their inputs the same way.
    """

    canary: str | None = None
    goal: str | None = None
    fields: Mapping[str, object] = field(default_factory=dict)

    def get(self, name: str, default: object = None) -> object:
        """Read one evaluator-specific field, falling back to `default`."""
        return self.fields.get(name, default)


def check_expectation(
    evaluator_id: str, expects: Mapping[str, bool], expectation: Expectation
) -> str | None:
    """Return why `expectation` does not satisfy an evaluator's contract, or None.

    Two failures, both of which would otherwise produce a rule that looks
    configured and grades nothing: a required field the rule never set, and a
    field name the evaluator does not know — the `promts:` typo one level down.
    """
    for name, required in expects.items():
        if required and expectation.get(name) is None and _typed(expectation, name) is None:
            return f"evaluator {evaluator_id!r} requires 'expect.{name}'"
    unknown = sorted(set(expectation.fields) - set(expects))
    if unknown:
        return (
            f"evaluator {evaluator_id!r} does not use expect field(s): {', '.join(unknown)}; "
            f"it reads {', '.join(sorted(expects)) or 'none'}"
        )
    return None


def _typed(expectation: Expectation, name: str) -> object | None:
    return {"canary": expectation.canary, "goal": expectation.goal}.get(name)


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

    expects: ClassVar[Mapping[str, bool]] = {}
    """The `expect:` fields this evaluator reads, mapped to whether each is required.

    Declaring them is what lets a YAML author configure a third-party evaluator at
    all: the loader accepts exactly these keys for this evaluator and rejects the
    rest, so `expect: {canry: ...}` fails loudly instead of producing a rule that
    grades nothing. An evaluator that needs no configuration leaves it empty.
    """

    @abstractmethod
    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        """Grade one exchange against one expectation.

        Be honest about `confidence`: a cheap heuristic that reports 0.99 is worse
        than one that reports 0.5, because a policy trusts the number. When the
        exchange has no reply to grade (`reply_text is None`), return
        `inconclusive`, never `pass`.
        """
        ...
