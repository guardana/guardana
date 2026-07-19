import os
import pickle
from pathlib import Path

from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


class _Evil:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("x",))


def test_scan_exits_nonzero_on_critical_finding(tmp_path: Path) -> None:
    (tmp_path / "m.pkl").write_bytes(pickle.dumps(_Evil()))
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "pickle_opcode" in result.stdout


def test_scan_clean_tree_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import os\n")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_rules_lists_builtin_rules() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "guardana.supply_chain.pickle_opcode" in result.stdout


def test_scan_rejects_invalid_format(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import os\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "bogus"])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert "ValueError" not in result.output


def test_version_prints_and_exits_zero() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "guardana" in result.stdout
    assert "0.1.0" in result.stdout


def test_scan_with_custom_rules_dir_runs_clean(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "demo.yaml").write_text(
        "id: acme.prompt.demo\n"
        "title: demo\n"
        "severity: high\n"
        "target_kind: endpoint\n"
        "evaluator: keyword\n"
        "requires: [chat]\n"
        "prompts: ['hi']\n"
        "expect: {goal: 'complied'}\n"
    )
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    (target_dir / "ok.py").write_text("import os\n")

    result = runner.invoke(app, ["scan", str(target_dir), "--rules", str(rules_dir)])

    assert result.exit_code == 0
    assert "warning: could not load rule" not in result.output
