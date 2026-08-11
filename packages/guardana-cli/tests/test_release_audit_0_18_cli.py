"""The same audit, at the surface a user actually touches.

Each of these was found by running a command and reading what came back, which is
the only way three of them could have been found: the suite was green, the types
checked, and the documents were being written correctly and read wrongly.
"""

import json
from pathlib import Path

from guardana.cli.main import app
from guardana.core.manifest.records import CalibrationRecord, EvaluatorRecord
from guardana.core.report.run import REPORT_SCHEMA_VERSION
from typer.testing import CliRunner

runner = CliRunner()


def test_a_broken_calibrations_file_refuses_in_words_with_a_code_from_the_table(
    tmp_path: Path,
) -> None:
    """It exited `1` with a stack trace, and `1` means *policy failed*.

    So a pipeline reading exit codes would have reported a security regression when
    the only thing wrong was an unparseable JSON file. A wrong verdict is worse than
    a crash, and this project's own clean-install gate says a refusal must come in
    words with a code from the table.
    """
    broken = tmp_path / "cal.json"
    broken.write_text("not json at all\n", encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text(f"name: t\ncalibrations: ['{broken}']\n", encoding="utf-8")
    (tmp_path / "src").mkdir()

    result = runner.invoke(app, ["scan", str(tmp_path / "src"), "--profile", str(profile)])

    assert result.exit_code == 3, result.output
    assert "could not read calibrations" in result.output
    assert "Traceback" not in result.output


def test_a_calibrations_file_that_is_not_there_is_refused_rather_than_ignored(
    tmp_path: Path,
) -> None:
    """Skipping it would leave every evaluator recorded unmeasured — the opposite of
    what an operator who configured the file asked to have in their evidence."""
    profile = tmp_path / "guardana.yaml"
    profile.write_text(
        f"name: t\ncalibrations: ['{tmp_path / 'missing.json'}']\n", encoding="utf-8"
    )
    (tmp_path / "src").mkdir()

    result = runner.invoke(app, ["scan", str(tmp_path / "src"), "--profile", str(profile)])

    assert result.exit_code == 3, result.output
    assert "does not exist" in result.output


def test_pack_validate_counts_the_targets_a_registry_holds(tmp_path: Path) -> None:
    """The false red: the manifest accepts `provides.targets` and the command's
    registered set was built from rules and evaluators only, so any pack shipping a
    `Target` was accused of not registering it.

    Only the failing direction is assertable here: no distribution in this
    environment registers a target, which is itself how the defect survived. The
    passing direction is covered where a third party's entry points are real —
    `examples/custom_rule` now ships one, and its own suite asserts it.
    """
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        'schema_version: 1\nname: t\nextension_api: ">=1,<2"\n'
        "provides:\n  targets: [NoSuchTarget]\n",
        encoding="utf-8",
    )

    accused = runner.invoke(app, ["pack", "validate", str(bad)])

    assert accused.exit_code == 1, accused.output
    assert "NoSuchTarget" in accused.output


def test_run_inspect_shows_how_honest_the_judge_was(tmp_path: Path) -> None:
    """The measurement reached the document and no person reading the documented way.

    `run inspect` is *the* command for reading a saved run, and it never mentioned a
    calibration — so a feature whose whole point is "a reader sees how honest the
    confidence was" arrived only for whoever parsed the JSON themselves.
    """
    from dataclasses import replace  # noqa: PLC0415

    from guardana.core.manifest.serialize import manifest_to_dict  # noqa: PLC0415
    from guardana.core.report import ScanResult  # noqa: PLC0415
    from guardana.core.testing import manifest_for  # noqa: PLC0415

    manifest = replace(
        manifest_for(ScanResult((), ("r",), ())),
        evaluators=(
            EvaluatorRecord(
                id="canary",
                calibration=CalibrationRecord(dataset_digest="sha256:a", brier=0.08, ece=0.03),
            ),
            EvaluatorRecord(id="keyword"),
        ),
    )
    path = tmp_path / "run.json"
    document = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "run": manifest_to_dict(manifest),
        "findings": [],
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    result = runner.invoke(app, ["run", "inspect", str(path)])

    assert result.exit_code == 0, result.output
    assert "canary — brier 0.08" in result.output
    assert "keyword — confidence not measured" in result.output, (
        "an unmeasured evaluator says so; omitting it would let a reader assume the "
        "listed ones are all of them"
    )
