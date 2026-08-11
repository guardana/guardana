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

from dataclasses import dataclass
from enum import StrEnum

from guardana.core.target import Target


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
