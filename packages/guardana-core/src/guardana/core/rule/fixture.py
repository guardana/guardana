"""Samples a rule must classify correctly, declared where the engine can find them.

"Every rule ships a positive *and* a negative fixture" has been project law since
0.1 and a `pytest` convention in practice — which means the engine cannot see those
fixtures, and nothing can run them for a pack it did not ship. That is precisely the
third party's problem: their proof lives in their test suite and no one else's tool
can repeat it.

Declaring them here makes them data. `guardana rule test` runs them, `--write-corpus`
turns them into a labelled set an evaluator can be measured against, and a rule that
declares none is *reported as unchecked* rather than passing quietly.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from guardana.core.target import Target

if TYPE_CHECKING:
    from guardana.core.rule.base import Rule


class FixtureOutcome(StrEnum):
    """What a rule must conclude about one sample.

    Three values, and the third is why this type exists. A rule that cannot fire is
    caught by a positive sample and a rule that fires on everything is caught by a
    negative one — but **a rule that cannot decline is caught by nothing**, and it is
    the one that will eventually report "clean" about something it never examined.
    """

    FINDING = "finding"
    """The rule must report this: the evidence is there and it is conclusive."""

    CLEAN = "clean"
    """The rule must stay silent: the evidence is there and nothing is wrong."""

    INCONCLUSIVE = "inconclusive"
    """The rule must decline: it could not establish the thing it grades.

    An empty reply, an unparseable judgement, a canary that was never planted. The
    fixture nobody writes, and the one this project exists to insist on — a check
    with no way of saying "I could not tell" has only two answers available and will
    give the wrong one under exactly the circumstances that matter.
    """

    NOT_OFFERED = "not_offered"
    """The rule must raise `NotOffered`: the sample lacks what the rule examines.

    Optional: a rule is not asked to declare such a sample, and one that raised it is
    never read as `inconclusive`.
    """

    NOT_APPLICABLE = "not_applicable"
    """The rule must raise `NotApplicable`: the sample holds nothing of the kind it grades.

    Optional, like `not_offered`, and never read as `clean`: a rule that grades nothing
    has not shown that the thing it grades is sound.
    """


DEMANDED_OUTCOMES = (FixtureOutcome.FINDING, FixtureOutcome.CLEAN, FixtureOutcome.INCONCLUSIVE)
"""The outcomes every rule must declare a sample of before its fixtures prove anything."""


@dataclass(frozen=True, slots=True)
class RuleFixture:
    """One sample, the target that produces it, and what the rule must conclude.

    `target` is built by the fixture's author rather than described to the engine,
    so a plugin rule can sample a crafted artifact, a scripted MCP server or
    anything else `guardana.core.testing` can stand up — the same freedom the rule
    itself has, which is the point of the contract being a method and not a schema.
    """

    name: str
    """What this sample demonstrates, in a reader's words. Printed on failure."""

    target: Target
    outcome: FixtureOutcome
    note: str = ""
    """Why this sample is the shape it is, when that is not obvious from the name."""

    rule: "Rule | None" = None
    """The variant of the declaring rule this sample runs, when it needs one; None runs the rule.

    A suite samples its gate over a small dataset of its own, so the rule it verifies is
    the declaring rule with those cases in place of its dataset.
    """


@dataclass(frozen=True, slots=True)
class DeclaredFixture:
    """A fixture as a rule file declares it: a script, not yet a double.

    A scripted double is an iterator, so a `RuleFixture` built once at parse time
    would hand a second verification a double that had already played its replies
    — a three-step scenario verified twice would grade the second run against its
    last reply on every turn. The declaration keeps the script and builds a fresh
    target each time the rule is asked for its fixtures.
    """

    name: str
    outcome: FixtureOutcome
    build: Callable[[], Target]
    """Builds the target this sample runs against; called once per `materialise`."""

    note: str = ""
    rule: "Rule | None" = None
    """The variant of the declaring rule this sample runs; see `RuleFixture.rule`."""

    def materialise(self) -> RuleFixture:
        """Build this sample's double afresh and return it as a `RuleFixture`."""
        return RuleFixture(self.name, self.build(), self.outcome, self.note, self.rule)


def materialise(declared: Iterable[RuleFixture | DeclaredFixture]) -> tuple[RuleFixture, ...]:
    """Build every declared sample with a fresh double.

    A rule assembled by hand may hold finished `RuleFixture`s instead of
    declarations; those pass through unchanged.
    """
    return tuple(d.materialise() if isinstance(d, DeclaredFixture) else d for d in declared)
