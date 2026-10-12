"""A scanned target's own ignore file cannot hide what a model loader reads from the scan."""

from pathlib import Path

import pytest
from guardana.core.rule import Rule, RuleContext
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture
from guardana.core.target.artifact import ArtifactTarget
from guardana.rules import provide_rules

_FAMILY = "guardana.supply_chain."
_ORDINARY_FILE_RULES = frozenset(
    {
        "code_execution",
        "dependency_risk",
        "hallucinated_package",
        "hardcoded_secret",
        "insecure_transport",
        "malicious_dependency",
        "notebook_payload",
        "provenance",
        "remote_code",
    }
)
"""Rules that read source, manifests, notebooks and cards, which a target's ignore file may
exclude; only the profile decides about the files a model loader reads."""
_HONEST_SAFETENSORS = b"\x02\x00\x00\x00\x00\x00\x00\x00{}"


def _rules() -> list[Rule]:
    return [rule for rule in provide_rules() if rule.meta.id.startswith(_FAMILY)]


def _positive_samples() -> list[tuple[Rule, RuleFixture]]:
    return [
        (rule, fixture)
        for rule in _rules()
        if rule.meta.id.removeprefix(_FAMILY) not in _ORDINARY_FILE_RULES
        for fixture in rule.fixtures()
        if fixture.outcome is FixtureOutcome.FINDING and isinstance(fixture.target, ArtifactTarget)
    ]


def _found(rule: Rule, fixture: RuleFixture, root: Path) -> set[tuple[str, str, str]]:
    findings = (fixture.rule or rule).run(ArtifactTarget(root), RuleContext())
    return {(f.rule_id, f.target_ref.replace(str(root), ""), f.title) for f in findings}


def test_every_ordinary_file_rule_is_a_shipped_rule() -> None:
    shipped = {rule.meta.id.removeprefix(_FAMILY) for rule in _rules()}

    assert shipped >= _ORDINARY_FILE_RULES


_SAMPLES = _positive_samples()


def test_the_model_loader_rules_have_positive_samples() -> None:
    assert len({rule.meta.id for rule, _ in _SAMPLES}) >= 6


@pytest.mark.parametrize(
    ("rule", "fixture"),
    _SAMPLES,
    ids=[f"{rule.meta.id.removeprefix(_FAMILY)}:{fixture.name[:40]}" for rule, fixture in _SAMPLES],
)
def test_an_ignore_file_excluding_everything_hides_no_finding(
    rule: Rule, fixture: RuleFixture
) -> None:
    root = Path(fixture.target.ref)
    found = _found(rule, fixture, root)
    for directory in {root, *(path.parent for path in root.rglob("*") if path.is_file())}:
        (directory / "model.safetensors").write_bytes(_HONEST_SAFETENSORS)
    (root / ".guardanaignore").write_text("*\n", encoding="utf-8")

    assert found
    assert found <= _found(rule, fixture, root)
