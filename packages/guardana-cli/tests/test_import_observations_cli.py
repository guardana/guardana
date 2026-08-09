"""`guardana import-observations` — and the property that makes it safe to have.

**It never exits 0.** No rule ran, so "the policy passed" is a sentence this run is not
entitled to, and a command that produces evidence rather than a verdict must not be
gateable as if it produced one. A pipeline that treats any non-zero as failure is correct
by default here, which is the direction that cannot hurt anybody.

The rest of this file is about counts. A file with two claims and two hundred passing
results has to say where the other hundred and ninety-eight went, or the import looks like
the whole file.
"""

import json
from pathlib import Path

from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner, Result

runner = CliRunner()

_GARAK = [
    {"entry_type": "start_run setup", "garak_version": "0.13.1"},
    {
        "entry_type": "eval",
        "probe": "dan.Dan_11_0",
        "detector": "dan.DAN",
        "passed": 3,
        "fails": 2,
        "nones": 0,
        "total_evaluated": 5,
    },
    {
        "entry_type": "eval",
        "probe": "clean.Probe",
        "detector": "clean.Detector",
        "passed": 5,
        "fails": 0,
        "nones": 0,
        "total_evaluated": 5,
    },
]
_PROMPTFOO = {
    "version": 3,
    "results": [
        {
            "id": "c1",
            "success": False,
            "gradingResult": {"pass": False, "reason": "leaked"},
            "testCase": {"description": "extraction", "metadata": {"severity": "critical"}},
        }
    ],
}


def _jsonl(tmp_path: Path, records: list[object], name: str = "report.jsonl") -> Path:
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def _json(tmp_path: Path, document: object, name: str = "results.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _run(*args: str) -> Result:
    return runner.invoke(app, ["import-observations", *args])


def test_importing_garak_results_never_exits_zero(tmp_path: Path) -> None:
    """Guardana verified nothing here, and a command producing evidence must not look green."""
    result = _run(str(_jsonl(tmp_path, _GARAK)))
    assert result.exit_code == ExitCode.INDETERMINATE
    assert "has not graded them" in result.output


def test_a_claim_lands_in_the_unverified_channel_with_its_provenance(tmp_path: Path) -> None:
    output = tmp_path / "run.json"
    _run(str(_jsonl(tmp_path, _GARAK)), "--format", "json", "--output", str(output))
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["findings"] == []
    assert len(document["unverified"]) == 1
    claim = document["unverified"][0]
    assert claim["rule_id"] == "imported.garak"
    assert claim["verdict"]["outcome"] == "inconclusive"
    assert claim["verdict"]["evaluator_id"] == "imported:garak"
    assert claim["taxonomy"] == []
    assert "garak 0.13.1" in claim["evidence"]["detail"]


def test_the_results_the_producer_passed_are_counted_rather_than_imported(tmp_path: Path) -> None:
    result = _run(str(_jsonl(tmp_path, _GARAK)))
    assert "1 result(s) the producer marked as passing were not imported" in result.output
    assert "not verdicts" in result.output


def test_promptfoo_severity_is_carried_and_attributed(tmp_path: Path) -> None:
    """Dropping it loses what a triager needs; inventing one presents our guess as measurement."""
    output = tmp_path / "run.json"
    _run(str(_json(tmp_path, _PROMPTFOO)), "--format", "json", "--output", str(output))
    claim = json.loads(output.read_text(encoding="utf-8"))["unverified"][0]
    assert claim["severity"] == "CRITICAL"
    assert "as reported by promptfoo" in claim["evidence"]["detail"]


def test_the_target_the_other_tool_was_pointed_at_can_be_declared(tmp_path: Path) -> None:
    output = tmp_path / "run.json"
    _run(
        str(_jsonl(tmp_path, _GARAK)),
        "--target",
        "https://llm.internal/v1",
        "--format",
        "json",
        "--output",
        str(output),
    )
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["run"]["target"]["ref"] == "https://llm.internal/v1"
    assert document["run"]["target"]["fingerprint"] is None
    assert document["run"]["target"]["fingerprint_inputs"] == []


def test_a_file_no_producer_wrote_exits_three_rather_than_importing_nothing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "junk.txt"
    path.write_text("hello", encoding="utf-8")
    result = _run(str(path))
    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "not an observation document" in result.output


def test_a_missing_file_exits_three(tmp_path: Path) -> None:
    result = _run(str(tmp_path / "nope.json"))
    assert result.exit_code == ExitCode.INVALID_USAGE


def test_the_producer_can_be_forced_when_detection_would_guess(tmp_path: Path) -> None:
    result = _run(str(_jsonl(tmp_path, _GARAK, name="mislabelled.json")), "--producer", "garak")
    assert result.exit_code == ExitCode.INDETERMINATE
    assert "imported 1 claim(s)" in result.output


def test_an_unreadable_record_is_reported_rather_than_dropped(tmp_path: Path) -> None:
    """A dropped record is a failing check that disappears — a false green through the import."""
    records = [*_GARAK, {"entry_type": "verdict_v2"}]
    output = tmp_path / "run.json"
    result = _run(str(_jsonl(tmp_path, records)), "--format", "json", "--output", str(output))
    assert "could not be read" in result.output
    document = json.loads(output.read_text(encoding="utf-8"))
    assert len(document["errors"]) == 1
