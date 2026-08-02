"""A skipped rule has to say why, or "not applicable" and "unsupported" look alike.

`rules_skipped` was a list of ids. That is enough to see that a check did not
happen and not enough to know whether that is fine. A pickle rule skipped against
a live endpoint is normal; a tool-calling rule skipped because the provider does
not implement function calling is a hole in the coverage somebody paid for — and
under `--strict-coverage` it must be able to fail the build rather than pass
quietly.
"""

from collections.abc import Iterable

from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.profile import FailOn, Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, ScanResult, SkippedRule, SkipReason
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import ScriptedTransport


class _NeedsTools(Rule):
    meta = RuleMeta(
        "guardana.test.tools",
        "needs tools",
        Severity.HIGH,
        TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CALL_TOOLS}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        return ()


class _NeedsChat(Rule):
    meta = RuleMeta(
        "guardana.test.chat",
        "needs chat",
        Severity.HIGH,
        TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        yield Finding(self.meta.id, self.meta.severity, "t", (), target.ref, Evidence(summary="s"))


def _run(*rules: Rule, policy: Policy | None = None) -> ScanResult:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))
    return Runner(registry=registry, profile=Profile("t", policy or Policy())).run(target)


def test_a_skipped_rule_records_what_the_target_could_not_do() -> None:
    result = _run(_NeedsTools(), _NeedsChat())

    assert len(result.rules_skipped) == 1
    skipped = result.rules_skipped[0]
    assert skipped.rule_id == "guardana.test.tools"
    assert skipped.reason is SkipReason.MISSING_CAPABILITY
    assert skipped.missing == ("call_tools",)


def test_a_skipped_rule_explains_itself_in_words() -> None:
    # Read by a person in a CI log, so the sentence matters as much as the enum.
    skipped = _run(_NeedsTools(), _NeedsChat()).rules_skipped[0]

    assert "call_tools" in skipped.detail
    assert "http://x#m" in skipped.detail


def test_skipping_does_not_fail_the_gate_by_default() -> None:
    # Most skips are ordinary: a file rule against an endpoint, a tool rule against
    # a chat-only model somebody knowingly deployed.
    result = _run(_NeedsTools(), _NeedsChat())

    assert gate_outcome(result, Policy()) is GateOutcome.FAIL  # from the chat rule's finding


def test_strict_coverage_makes_an_unsupported_check_indeterminate() -> None:
    # The opt-in a team uses when they are paying for coverage they expect to get.
    class _Quiet(_NeedsChat):
        meta = RuleMeta(
            "guardana.test.quiet",
            "quiet",
            Severity.HIGH,
            TargetKind.ENDPOINT,
            required_capabilities=frozenset({Capability.CHAT}),
        )

        def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
            return ()

    policy = Policy(fail_on=FailOn(fail_on_skipped=True))
    result = _run(_NeedsTools(), _Quiet(), policy=policy)

    assert gate_outcome(result, policy) is GateOutcome.INDETERMINATE


def test_strict_coverage_still_reports_a_real_finding_as_a_failure() -> None:
    # A finding is a fact; missing coverage is the absence of one. The fact wins,
    # or the thing somebody has to fix gets buried under a warning.
    policy = Policy(fail_on=FailOn(fail_on_skipped=True))
    result = _run(_NeedsTools(), _NeedsChat(), policy=policy)

    assert gate_outcome(result, policy) is GateOutcome.FAIL


def test_merging_results_keeps_every_skip() -> None:
    one = ScanResult(
        findings=(),
        rules_run=(),
        rules_skipped=(SkippedRule("a", SkipReason.MISSING_CAPABILITY, ("chat",), "d"),),
    )
    two = ScanResult(
        findings=(),
        rules_run=(),
        rules_skipped=(SkippedRule("b", SkipReason.MISSING_CAPABILITY, ("chat",), "d"),),
    )

    merged = ScanResult.merged([one, two])

    assert {s.rule_id for s in merged.rules_skipped} == {"a", "b"}


def test_the_same_rule_skipped_in_two_passes_is_reported_once() -> None:
    # probe runs several passes against one target; the same rule skipped in each
    # is one gap, not three.
    skip = SkippedRule("a", SkipReason.MISSING_CAPABILITY, ("chat",), "d")
    merged = ScanResult.merged(
        [
            ScanResult(findings=(), rules_run=(), rules_skipped=(skip,)),
            ScanResult(findings=(), rules_run=(), rules_skipped=(skip,)),
        ]
    )

    assert len(merged.rules_skipped) == 1
