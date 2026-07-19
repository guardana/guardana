from guardana.core.rule import RuleMeta
from guardana.core.severity import Severity
from guardana.core.surface import Surface
from guardana.core.target import TargetKind


def _meta(kind: TargetKind) -> RuleMeta:
    return RuleMeta(id="x", title="x", severity=Severity.HIGH, target_kind=kind)


def test_artifact_rule_is_the_build_surface() -> None:
    assert _meta(TargetKind.ARTIFACT).surface is Surface.BUILD


def test_endpoint_rule_is_the_runtime_surface() -> None:
    assert _meta(TargetKind.ENDPOINT).surface is Surface.RUNTIME
