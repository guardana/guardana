"""A baseline keeps a waiver no check re-examined, and is reviewed only when someone wrote why."""

from pathlib import Path

import pytest
import yaml
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_SINK = "guardana.supply_chain.code_execution"


def _tree(tmp_path: Path) -> Path:
    tree = tmp_path / "src"
    tree.mkdir()
    (tree / "run.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    (tree / "notes.py").write_text("NOTE = 'nothing to see'\n", encoding="utf-8")
    return tree


def _created(tmp_path: Path, tree: Path) -> Path:
    baseline = tmp_path / "guardana-baseline.yaml"
    result = runner.invoke(app, ["baseline", "create", str(tree), "--output", str(baseline)])
    if result.exit_code != ExitCode.OK or _rules(baseline) != [_SINK]:
        raise RuntimeError(f"precondition: one waiver for the shell sink: {result.output}")
    return baseline


def _rules(baseline: Path) -> list[str]:
    return [waiver["rule"] for waiver in yaml.safe_load(baseline.read_text("utf-8"))["waivers"]]


def _edit(baseline: Path, **fields: str) -> None:
    document = yaml.safe_load(baseline.read_text("utf-8"))
    for waiver in document["waivers"]:
        waiver.update(fields)
    baseline.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def _attempt(tree: Path, baseline: Path, *profile: str) -> tuple[int, str]:
    result = runner.invoke(
        app, ["baseline", "update", str(tree), "--file", str(baseline), *profile]
    )
    return result.exit_code, " ".join(result.output.split())


def _update(tree: Path, baseline: Path) -> str:
    code, said = _attempt(tree, baseline)
    if code != ExitCode.OK:
        raise RuntimeError(f"precondition: the update should complete: {said}")
    return said


def test_control_an_update_over_the_same_rules_keeps_the_waiver(tmp_path: Path) -> None:
    tree = _tree(tmp_path)
    baseline = _created(tmp_path, tree)

    _update(tree, baseline)

    assert _rules(baseline) == [_SINK]


def test_control_an_update_after_the_fix_drops_the_waiver(tmp_path: Path) -> None:
    tree = _tree(tmp_path)
    baseline = _created(tmp_path, tree)
    (tree / "run.py").write_text("print('fixed')\n", encoding="utf-8")

    _update(tree, baseline)

    assert _rules(baseline) == []


def test_an_update_that_did_not_run_the_waived_rule_keeps_its_waiver(tmp_path: Path) -> None:
    tree = _tree(tmp_path)
    baseline = _created(tmp_path, tree)
    narrow = tmp_path / "narrow.yaml"
    narrow.write_text(f"rules:\n  exclude: ['{_SINK}']\n", encoding="utf-8")

    _code, said = _attempt(tree, baseline, "--profile", str(narrow))

    assert _rules(baseline) == [_SINK], said


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="a waiver whose file is gone is kept as unexamined and has to be removed by hand",
)
def test_an_update_after_the_waived_file_was_deleted_removes_the_waiver(tmp_path: Path) -> None:
    tree = _tree(tmp_path)
    baseline = _created(tmp_path, tree)
    (tree / "run.py").unlink()

    said = _update(tree, baseline)

    assert _rules(baseline) == [], said
    assert "removed:" in said, said


def _verify(baseline: Path) -> int:
    return runner.invoke(app, ["baseline", "verify", str(baseline)]).exit_code


def test_control_a_generated_baseline_fails_verification(tmp_path: Path) -> None:
    assert _verify(_created(tmp_path, _tree(tmp_path))) == ExitCode.POLICY_FAILED


def test_control_a_reviewed_baseline_passes_verification(tmp_path: Path) -> None:
    baseline = _created(tmp_path, _tree(tmp_path))
    _edit(baseline, reason="sandboxed build helper", approved_by="security@example.com")

    assert _verify(baseline) == ExitCode.OK


def test_a_waiver_with_no_reason_and_no_approver_fails_verification(tmp_path: Path) -> None:
    baseline = _created(tmp_path, _tree(tmp_path))
    _edit(baseline, reason="", approved_by="")

    assert _verify(baseline) == ExitCode.POLICY_FAILED


def test_control_an_active_waiver_leaves_no_finding_unwaived(tmp_path: Path) -> None:
    tree = _tree(tmp_path)
    baseline = _created(tmp_path, tree)
    _edit(baseline, reason="sandboxed", approved_by="security@example.com")

    assert "0 finding(s) are not waived" in _update(tree, baseline)


def test_an_expired_waiver_leaves_its_finding_unwaived(tmp_path: Path) -> None:
    tree = _tree(tmp_path)
    baseline = _created(tmp_path, tree)
    _edit(baseline, reason="sandboxed", approved_by="security@example.com", expires="2020-01-01")

    assert "1 finding(s) are not waived" in _update(tree, baseline)
