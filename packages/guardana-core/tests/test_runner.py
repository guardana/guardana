from collections.abc import Iterable
from pathlib import Path

from guardana.core.evaluator.base import Verdict
from guardana.core.profile import FailOn, Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.rule import Rule, RuleContext, RuleError, RuleMeta
from guardana.core.runner import Runner, gate
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind


class _Fires(Rule):
    meta = RuleMeta(
        "guardana.sc.demo",
        "demo",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        yield Finding(
            self.meta.id, self.meta.severity, "hit", (), target.ref, Evidence(summary="x")
        )


class _EndpointOnly(Rule):
    meta = RuleMeta("guardana.ep.demo", "ep", Severity.HIGH, TargetKind.ENDPOINT)

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        yield Finding(
            self.meta.id,
            self.meta.severity,
            "should not run",
            (),
            target.ref,
            Evidence(summary="x"),
        )


def _runner(*rules: Rule, policy: Policy | None = None) -> Runner:
    reg = Registry()
    for r in rules:
        reg.register_rule(r)
    return Runner(registry=reg, profile=Profile("t", policy or Policy()))


def test_runner_runs_matching_rule_and_skips_wrong_target_kind(tmp_path: Path) -> None:
    result = _runner(_Fires(), _EndpointOnly()).run(ArtifactTarget(tmp_path))
    assert result.rules_run == 1
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "guardana.sc.demo"


def test_runner_respects_policy_include(tmp_path: Path) -> None:
    policy = Policy(include=("guardana.other.*",))
    result = _runner(_Fires(), policy=policy).run(ArtifactTarget(tmp_path))
    assert result.findings == ()


def test_gate_fails_on_high_severity(tmp_path: Path) -> None:
    result = _runner(_Fires()).run(ArtifactTarget(tmp_path))
    assert gate(result, Policy(fail_on=FailOn(severity=Severity.HIGH))) is True


class _MissingCapability(Rule):
    meta = RuleMeta(
        "guardana.cap.demo",
        "cap_demo",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        yield Finding(
            self.meta.id,
            self.meta.severity,
            "should not run",
            (),
            target.ref,
            Evidence(summary="x"),
        )


def test_runner_skips_rule_missing_capability(tmp_path: Path) -> None:
    result = _runner(_MissingCapability()).run(ArtifactTarget(tmp_path))
    assert result.rules_run == 0
    assert len(result.findings) == 0
    assert "guardana.cap.demo" in result.rules_skipped


class _RaisesRuleError(Rule):
    meta = RuleMeta(
        "guardana.err.demo",
        "err_demo",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        raise RuleError("boom")


def test_runner_records_rule_that_raises_as_skipped(tmp_path: Path) -> None:
    result = _runner(_RaisesRuleError()).run(ArtifactTarget(tmp_path))
    assert result.findings == ()
    assert result.rules_run == 0
    assert "guardana.err.demo" in result.rules_skipped


class _Inconclusive(Rule):
    meta = RuleMeta(
        "guardana.incon.demo",
        "incon",
        Severity.HIGH,
        TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        yield Finding(
            self.meta.id,
            self.meta.severity,
            "unverified",
            (),
            target.ref,
            Evidence(summary="could not verify"),
            verdict=Verdict("inconclusive", 0.0, "judge unreachable", "x"),
        )


def test_inconclusive_finding_is_unverified_not_a_finding(tmp_path: Path) -> None:
    # The check ran but could not reach a verdict: it must be visible (unverified),
    # never dropped into silence and never counted as a confirmed finding.
    result = _runner(_Inconclusive()).run(ArtifactTarget(tmp_path))
    assert result.findings == ()
    assert result.rules_run == 1  # it DID run — unlike a capability skip
    assert len(result.unverified) == 1
    assert result.unverified[0].verdict is not None
    assert result.unverified[0].verdict.outcome == "inconclusive"


def test_gate_does_not_fail_on_inconclusive_by_default(tmp_path: Path) -> None:
    result = _runner(_Inconclusive()).run(ArtifactTarget(tmp_path))
    assert gate(result, Policy(fail_on=FailOn(severity=Severity.HIGH))) is False


def test_gate_fails_on_inconclusive_when_opted_in(tmp_path: Path) -> None:
    result = _runner(_Inconclusive()).run(ArtifactTarget(tmp_path))
    policy = Policy(fail_on=FailOn(severity=Severity.HIGH, fail_on_inconclusive=True))
    assert gate(result, policy) is True


def test_gate_fails_when_zero_rules_ran() -> None:
    # Zero rules ran means nothing was verified: a pass would be a confident
    # all-clear on a target nothing looked at — the fail-open the engine forbids.
    # This is the runtime backstop for a misconfigured include/exclude or an empty
    # registry, even under the most permissive policy.
    empty = ScanResult(findings=(), rules_run=0, rules_skipped=())
    assert gate(empty, Policy()) is True
    assert gate(empty, Policy(fail_on=FailOn(severity=Severity.CRITICAL))) is True
