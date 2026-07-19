import json
import os
import pickle
from pathlib import Path

from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


class _Evil:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("x",))


def test_no_plugins_runs_no_entry_point_rules(tmp_path: Path) -> None:
    # --no-plugins is a security feature (SECURITY.md): it builds a bare Registry
    # so no third-party entry-point code is loaded or executed. The cost is that
    # the built-in plugin rules don't run either — including the one that would
    # otherwise flag this pickle.
    (tmp_path / "m.pkl").write_bytes(pickle.dumps(_Evil()))

    unsafe = runner.invoke(app, ["scan", str(tmp_path)])
    safe = runner.invoke(app, ["scan", str(tmp_path), "--no-plugins"])

    assert unsafe.exit_code == 1
    assert "pickle_opcode" in unsafe.stdout

    # Safe mode ran zero rules, so it must NOT report a green all-clear — it exits
    # non-zero and says nothing was checked, rather than passing this evil pickle.
    assert safe.exit_code == 1
    assert "pickle_opcode" not in safe.stdout
    assert "0 rule(s) run" in safe.stdout
    assert "nothing was checked" in safe.stdout


def test_no_plugins_reports_a_malformed_custom_rule_instead_of_crashing(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "broken.yaml").write_text("id: acme.broken\ntitle: [unclosed\n", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    (target / "ok.py").write_text("import os\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(target), "--rules", str(rules_dir), "--no-plugins"])

    # The malformed rule degrades to a warning (no crash, no traceback). With that
    # rule dropped and plugins off, zero rules ran — so the exit is non-zero and
    # the run reports nothing was checked, never a silent all-clear.
    assert result.exit_code == 1, result.output
    assert "warning: could not load rule" in result.output
    assert "nothing was checked" in result.output


def test_init_writes_profile_then_refuses_to_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "guardana.yaml"

    first = runner.invoke(app, ["init", str(target)])

    assert first.exit_code == 0, first.output
    assert "fail_on" in target.read_text(encoding="utf-8")

    second = runner.invoke(app, ["init", str(target)])

    assert second.exit_code == 1
    assert "not overwriting" in second.stdout


def test_rules_json_format_lists_every_rule() -> None:
    result = runner.invoke(app, ["rules", "--format", "json"])

    assert result.exit_code == 0, result.output
    listed = json.loads(result.stdout)
    ids = {entry["id"] for entry in listed}
    assert "guardana.supply_chain.pickle_opcode" in ids
    assert "guardana.prompt.system_prompt_leak.canary" in ids
    assert all({"id", "severity", "taxonomy", "surface"} <= entry.keys() for entry in listed)


def test_rules_surface_filter_lists_only_that_layer() -> None:
    result = runner.invoke(app, ["rules", "--format", "json", "--surface", "runtime"])

    assert result.exit_code == 0, result.output
    surfaces = {entry["surface"] for entry in json.loads(result.stdout)}
    assert surfaces == {"runtime"}


def test_scan_preset_pre_training_gates_a_vulnerable_model(tmp_path: Path) -> None:
    # A pre-training gate is stricter (fails on MEDIUM), so a slopsquat lead blocks.
    (tmp_path / "train.py").write_text("import torchutilz\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--preset", "pre-training"])
    assert result.exit_code == 1, result.output


def test_scan_rejects_both_profile_and_preset(tmp_path: Path) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: x\n", encoding="utf-8")
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--preset", "ci", "--profile", str(profile)]
    )
    assert result.exit_code != 0
    assert "not both" in result.output
