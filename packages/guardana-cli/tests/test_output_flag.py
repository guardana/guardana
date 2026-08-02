"""`--output` writes a run a second command can read.

A shell redirect looked like enough until the file became an input: PowerShell
writes UTF-16 and the reader on the other side sees a corrupt document a day
later, at which point nobody connects it to the redirect that caused it.
"""

import json
from pathlib import Path

from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.report import REPORT_SCHEMA_VERSION, load_report
from typer.testing import CliRunner

runner = CliRunner()

_INSECURE_SOURCE = 'import requests\n\nrequests.get("http://models.internal/weights")\n'


def test_output_writes_a_run_that_loads_back(tmp_path: Path) -> None:
    (tmp_path / "fetch.py").write_text(_INSECURE_SOURCE)
    out = tmp_path / "run.json"

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(out)])

    assert result.exit_code == 0  # a MEDIUM finding is below the default gate
    report = load_report(out)
    assert report.result.findings
    assert report.manifest.target.kind == "artifact"
    assert report.manifest.result_summary.gate is not None, (
        "a run written today records its verdict rather than leaving a reader to infer one"
    )


def test_the_saved_run_names_the_rules_that_ran_with_their_digests(tmp_path: Path) -> None:
    """Which rules ran is what stops a narrowed profile from reading as an improvement."""
    out = tmp_path / "run.json"

    runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(out)])

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == REPORT_SCHEMA_VERSION
    rules = payload["run"]["rules"]
    assert rules, "a scan that ran rules must say which"
    assert all(len(rule["digest"]) == 16 for rule in rules)


def test_a_narrowed_profile_produces_a_visibly_smaller_plan(tmp_path: Path) -> None:
    """The whole point of recording the plan, exercised end to end."""
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: narrow\nrules:\n  include: ['guardana.supply_chain.pickle_opcode']\n")
    wide, narrow = tmp_path / "wide.json", tmp_path / "narrow.json"

    common = ["scan", str(tmp_path), "--format", "json"]
    runner.invoke(app, [*common, "--output", str(wide)])
    runner.invoke(app, [*common, "--profile", str(profile), "--output", str(narrow)])

    def _ran(path: Path) -> set[str]:
        return {rule.id for rule in load_report(path).manifest.rules}

    assert _ran(narrow) < _ran(wide)


def test_a_report_that_cannot_be_written_exits_two_rather_than_looking_saved(
    tmp_path: Path,
) -> None:
    unwritable = tmp_path / "no-such-dir" / "run.json"

    result = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "json", "--output", str(unwritable)]
    )

    assert result.exit_code == ExitCode.INVALID_USAGE
