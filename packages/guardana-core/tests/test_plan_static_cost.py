"""`guardana-core` makes no claim about a rule it has never read — artifact included.

Keying `Rule.estimated_requests`'s default off `TargetKind.ARTIFACT` once claimed
zero requests for every artifact rule anywhere, third-party ones included — even
one that does its own network I/O per file, which is exactly the pack an
adversarial audit built and ran to demonstrate it: `plan scan` priced it at
`requests: 0`, `complete=True`, `fits_budget=True`, and exit `0`, where the
pre-cycle build correctly reported `unknown_cost` and refused the budget. The
engine must not make that promise on a rule's behalf, so this pins the reverted
behaviour rather than let the same mistake regress a second time. The honest zero
for a rule that only reads files now belongs to whoever actually wrote it — see
`guardana.rules._base.ArtifactRule` for the built-ins' own declaration, and
`guardana-rules/tests/test_scan_network.py` for the gate that measures it.
"""

from collections.abc import Iterable
from pathlib import Path

from guardana.core.plan import build_plan
from guardana.core.profile import default_profile
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import ScriptedTransport


class _Static(Rule):
    """An artifact rule that reads files and says nothing about its cost.

    Deliberately does not override `estimated_requests`: this is what a
    third-party artifact rule looks like before its author has declared
    anything, and the engine must not fill that silence in on their behalf.
    """

    meta = RuleMeta(
        id="test.static",
        title="reads files",
        severity=Severity.LOW,
        target_kind=TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


class _DeclaresZero(Rule):
    """The honest way to claim free: say so yourself. Contrast with `_Static`."""

    meta = RuleMeta(
        id="test.declares_zero",
        title="reads files and says so",
        severity=Severity.LOW,
        target_kind=TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    @property
    def estimated_requests(self) -> int | None:
        return 0

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


class _Dynamic(Rule):
    meta = RuleMeta(
        id="test.dynamic",
        title="sends prompts",
        severity=Severity.LOW,
        target_kind=TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


def test_an_undeclared_artifact_rule_stays_unknown_like_any_other_kind() -> None:
    # Not `0`: an `ArtifactTarget` having no transport of its own says nothing
    # about what a rule built against it does. See `Rule.estimated_requests`.
    assert _Static().estimated_requests is None


def test_an_endpoint_rule_that_declares_nothing_stays_unknown() -> None:
    """The honest answer for a rule that sends is "it did not say", never a guess."""
    assert _Dynamic().estimated_requests is None


def test_a_plan_over_an_undeclared_artifact_rule_is_not_claimed_complete(
    tmp_path: Path,
) -> None:
    # The regression this pins: a plan over a rule that reads files but never
    # said what it sends — indistinguishable, from the engine's side, from one
    # that does its own network I/O — must be named as unknown cost, never
    # priced as a free, complete file scan.
    registry = Registry()
    registry.register_rule(_Static())

    plan = build_plan(registry, default_profile(), ArtifactTarget(tmp_path))

    assert plan.rules == ("test.static",)
    assert plan.unknown_cost == ("test.static",)
    assert not plan.is_complete
    assert (plan.min_requests, plan.max_requests) == (1, 0)


def test_a_plan_over_a_rule_that_actually_declares_zero_is_complete_and_free(
    tmp_path: Path,
) -> None:
    registry = Registry()
    registry.register_rule(_DeclaresZero())

    plan = build_plan(registry, default_profile(), ArtifactTarget(tmp_path))

    assert plan.rules == ("test.declares_zero",)
    assert plan.unknown_cost == ()
    assert plan.is_complete
    assert (plan.min_requests, plan.max_requests) == (0, 0)


def test_the_floor_counts_only_rules_that_send() -> None:
    """A rule declaring zero must not raise the floor; an unknown one must."""
    registry = Registry()
    registry.register_rule(_Dynamic())
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))

    plan = build_plan(registry, default_profile(), target)

    assert plan.unknown_cost == ("test.dynamic",)
    assert plan.min_requests == 1
    assert plan.max_requests == 0
