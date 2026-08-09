"""`guardana run inspect` and `run migrate` — reading a saved run without re-running it.

The interesting behaviour is what `inspect` says about a run that predates the
fields being asked about. "Not recorded" and "zero" have to look different on
screen, because the whole reason the loader keeps them apart is that somebody
eventually reads the output and decides something.
"""

import json
from pathlib import Path

from guardana.cli.main import app
from guardana.core.report import load_report
from typer.testing import CliRunner

runner = CliRunner()

_INVALID_USAGE = 3

_V1_RUN = {
    "schema_version": 1,
    "run": {
        "tool_version": "0.6.0",
        "target_kind": "endpoint",
        "target_ref": "http://localhost:11434#llama3",
        "profile": "ci",
        "rules": {"guardana.prompt.injection": "aaaabbbbccccdddd"},
        "rules_skipped": [],
        "started_at": "2026-07-25T09:00:00+00:00",
    },
    "findings": [],
    "unverified": [],
    "waived": [],
    "errors": [],
    "observations": [],
}


def _write_v1(tmp_path: Path, name: str = "old.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(_V1_RUN), encoding="utf-8")
    return path


def _scan_run(tmp_path: Path) -> Path:
    out = tmp_path / "run.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(out)])
    assert result.exit_code == 0, result.output
    return out


def test_inspect_describes_a_current_run(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "inspect", str(_scan_run(tmp_path))])

    assert result.exit_code == 0, result.output
    assert "artifact" in result.output
    assert "pass" in result.output


def test_inspect_says_a_migrated_run_does_not_record_its_cost(tmp_path: Path) -> None:
    # The point of the command. A blank here would read as "it cost nothing".
    result = runner.invoke(app, ["run", "inspect", str(_write_v1(tmp_path))])

    assert result.exit_code == 0, result.output
    assert "not recorded" in result.output
    assert "migrated from schema 1" in result.output


def test_inspect_says_a_migrated_run_has_no_recorded_verdict(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "inspect", str(_write_v1(tmp_path))])

    assert "not recorded" in result.output
    # And specifically not one this build computed on the old run's behalf.
    assert "gate: pass" not in result.output
    assert "gate: fail" not in result.output


def test_inspect_emits_json_when_asked(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "inspect", str(_scan_run(tmp_path)), "--format", "json"])

    payload = json.loads(result.output)
    assert payload["target"]["type"] == "artifact"
    assert payload["result_summary"]["gate"] == "pass"


def test_inspect_refuses_a_file_that_is_not_a_run(tmp_path: Path) -> None:
    junk = tmp_path / "junk.json"
    junk.write_text("{}", encoding="utf-8")

    result = runner.invoke(app, ["run", "inspect", str(junk)])

    assert result.exit_code == _INVALID_USAGE


def test_migrate_rewrites_a_version_one_file_in_place(tmp_path: Path) -> None:
    path = _write_v1(tmp_path)
    out = tmp_path / "new.json"

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text(encoding="utf-8"))["schema_version"] == 4
    assert load_report(out).manifest.migrated_from == 1


def test_migrate_keeps_the_unknowns_unknown(tmp_path: Path) -> None:
    # Migration must not be a place where blanks quietly become numbers.
    out = tmp_path / "new.json"
    runner.invoke(app, ["run", "migrate", str(_write_v1(tmp_path)), "--output", str(out)])

    written = json.loads(out.read_text(encoding="utf-8"))["run"]
    assert written["usage"]["requests"] is None
    assert written["result_summary"]["gate"] is None


def test_migrate_leaves_a_current_run_alone(tmp_path: Path) -> None:
    path = _scan_run(tmp_path)
    before = path.read_text(encoding="utf-8")
    out = tmp_path / "again.json"

    result = runner.invoke(app, ["run", "migrate", str(path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert "already" in result.output
    assert path.read_text(encoding="utf-8") == before
