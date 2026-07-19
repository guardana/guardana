from collections.abc import Iterable
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind


class _AlwaysFinds(Rule):
    meta = RuleMeta(
        id="guardana.test.always",
        title="always fires",
        severity=Severity.LOW,
        target_kind=TargetKind.ARTIFACT,
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        yield Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=target.ref,
            evidence=Evidence(summary="fired"),
        )


def test_rule_runs_and_yields_findings(tmp_path: Path) -> None:
    findings = list(_AlwaysFinds().run(ArtifactTarget(tmp_path), RuleContext(config={})))
    assert len(findings) == 1
    assert findings[0].rule_id == "guardana.test.always"


def test_rule_context_get_returns_default() -> None:
    ctx = RuleContext(config={"threshold": 5})
    assert ctx.get("threshold", 0) == 5
    assert ctx.get("missing", 42) == 42
