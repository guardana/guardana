import os
import pickle
from pathlib import Path

from guardana.cli.main import app
from guardana.core import __version__
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


def test_scan_single_file_is_not_a_silent_pass(tmp_path: Path) -> None:
    # A single-file target must scan that file, not walk-nothing and pass clean.
    single = tmp_path / "x.py"
    single.write_text("import torch\ntorch.load('m.pt')\n")
    result = runner.invoke(app, ["scan", str(single)])
    assert result.exit_code == 1
    assert "dependency_risk" in result.stdout


def test_scan_baseline_waives_findings(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    (target / "m.pkl").write_bytes(pickle.dumps(_Evil()))
    baseline = tmp_path / "baseline.yaml"  # kept outside the scanned tree
    generated = runner.invoke(app, ["scan", str(target), "--write-baseline", str(baseline)])
    assert generated.exit_code == 0
    assert baseline.exists()
    # A CRITICAL finding normally fails the gate (exit 1); with it baselined the
    # same scan is green, and the finding is still reported as WAIVED.
    scanned = runner.invoke(app, ["scan", str(target), "--baseline", str(baseline)])
    assert scanned.exit_code == 0
    assert "WAIVED" in scanned.stdout


def test_baseline_survives_a_line_shift(tmp_path: Path) -> None:
    # F-E: an unrelated edit above a waived finding must not un-waive it.
    target = tmp_path / "d"
    target.mkdir()
    (target / "m.py").write_text("import torch\ntorch.load('a.pt')\n")
    baseline = tmp_path / "bl.yaml"
    assert (
        runner.invoke(app, ["scan", str(target), "--write-baseline", str(baseline)]).exit_code == 0
    )
    (target / "m.py").write_text("\n\n\nimport torch\ntorch.load('a.pt')\n")  # shift down 3 lines
    result = runner.invoke(app, ["scan", str(target), "--baseline", str(baseline)])
    assert result.exit_code == 0
    assert "WAIVED" in result.stdout


def test_scan_baseline_and_write_baseline_are_mutually_exclusive(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import os\n")
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--baseline", "x.yaml", "--write-baseline", "y.yaml"]
    )
    assert result.exit_code != 0


def test_scan_malformed_baseline_is_clean_error_not_traceback(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("import os\n")
    baseline = tmp_path / "bad.yaml"
    baseline.write_text("waivers: not-a-list\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--baseline", str(baseline)])
    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_rules_lists_builtin_rules() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "guardana.supply_chain.pickle_opcode" in result.stdout


def test_rules_includes_custom_yaml_pack(tmp_path: Path) -> None:
    (tmp_path / "my_rule.yaml").write_text(
        "id: acme.prompt.demo\n"
        "title: Demo custom rule\n"
        "severity: high\n"
        "target_kind: endpoint\n"
        "requires: [chat]\n"
        "evaluator: keyword\n"
        "prompts:\n"
        '  - "hello"\n'
    )
    result = runner.invoke(app, ["rules", "--rules", str(tmp_path)])
    assert result.exit_code == 0
    assert "acme.prompt.demo" in result.stdout


def test_rules_warns_on_unloadable_custom_pack(tmp_path: Path) -> None:
    (tmp_path / "broken.yaml").write_text("id: acme.broken\ntitle: no prompts\nseverity: high\n")
    result = runner.invoke(app, ["rules", "--rules", str(tmp_path)])
    assert result.exit_code == 0
    assert "warning: could not load rule" in result.output


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
    # The actual version, not a hardcoded literal, so a release bump doesn't break it.
    assert __version__ in result.stdout


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
