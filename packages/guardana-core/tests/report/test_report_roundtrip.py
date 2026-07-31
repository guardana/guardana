"""A saved run is a contract: whatever `guardana diff` reads, someone else can too.

Serialization has existed since 0.1; reading a run back has not. The moment a
second command consumes the JSON output, its shape stops being an implementation
detail — hence a version on it from the first day rather than when it hurts.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from guardana.core.evaluator.base import Verdict
from guardana.core.observation import Observation, ObservationKind
from guardana.core.report import CheckError, Evidence, Finding, ScanResult
from guardana.core.report.load import ReportLoadError, load_report
from guardana.core.report.run import REPORT_SCHEMA_VERSION, RunMeta
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
from guardana.core.taxonomy import OWASP_LLM01
from guardana.report import get_renderer

_META = RunMeta(
    tool_version="0.6.0",
    target_kind=TargetKind.ENDPOINT,
    target_ref="http://localhost:11434#llama3",
    profile="ci",
    rules={"guardana.prompt.injection": "aaaabbbbccccdddd"},
    rules_skipped=("guardana.agent.memory_poisoning",),
    started_at=datetime(2026, 7, 31, 9, 12, 44, tzinfo=UTC),
)


def _finding(rule_id: str, *, outcome: str = "fail") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="demo",
        taxonomy=(OWASP_LLM01,),
        target_ref="http://localhost:11434#llama3",
        evidence=Evidence(summary="model complied", detail="…redacted…"),
        verdict=Verdict(outcome, 0.8, "2/2 judge samples agreed", "llm_judge"),  # type: ignore[arg-type]
    )


def _full_result() -> ScanResult:
    return ScanResult(
        findings=(_finding("guardana.prompt.injection"),),
        rules_run=("guardana.prompt.injection",),
        rules_skipped=("guardana.agent.memory_poisoning",),
        unverified=(_finding("guardana.prompt.leak", outcome="inconclusive"),),
        waived=(_finding("guardana.prompt.waived"),),
        errors=(CheckError("acme.broken", "run", "ValueError: boom"),),
        observations=(
            Observation(ObservationKind.MODEL, "llama3", "model.gguf", {"format": "gguf"}),
        ),
    )


def _write(tmp_path: Path, result: ScanResult, meta: RunMeta = _META) -> Path:
    path = tmp_path / "run.json"
    path.write_text(get_renderer("json", run=meta).render(result), encoding="utf-8")
    return path


def test_every_channel_survives_a_round_trip(tmp_path: Path) -> None:
    """A channel dropped in serialization is a channel a comparison cannot see."""
    original = _full_result()

    report = load_report(_write(tmp_path, original))

    assert report.result == original


def test_run_metadata_survives_a_round_trip(tmp_path: Path) -> None:
    report = load_report(_write(tmp_path, _full_result()))

    assert report.meta == _META


def test_a_report_without_a_schema_version_is_refused(tmp_path: Path) -> None:
    """Every run written by 0.5 and earlier. Reading it as empty would be the lie."""
    path = tmp_path / "old.json"
    path.write_text('{"findings": [], "summary": {"rules_run": 3}}', encoding="utf-8")

    with pytest.raises(ReportLoadError, match="schema_version"):
        load_report(path)


def test_a_newer_schema_version_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "future.json"
    path.write_text(f'{{"schema_version": {REPORT_SCHEMA_VERSION + 1}}}', encoding="utf-8")

    with pytest.raises(ReportLoadError, match="schema_version"):
        load_report(path)


def test_a_truncated_report_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "cut.json"
    path.write_text('{"schema_version": 1, "findings": [{"rule_id"', encoding="utf-8")

    with pytest.raises(ReportLoadError):
        load_report(path)


def test_a_missing_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ReportLoadError):
        load_report(tmp_path / "nope.json")


def test_a_taxonomy_entry_this_build_never_heard_of_still_loads(tmp_path: Path) -> None:
    """The taxonomy dictionary is open (entry points), so a report may carry ours plus theirs.

    Refusing here would mean a report produced with a third-party rule pack
    installed could not be compared on a machine without it — punishing exactly
    the extensibility the entry point exists for.
    """
    path = tmp_path / "acme.json"
    path.write_text(
        '{"schema_version": 1, "run": {"tool_version": "0.6.0", "target_kind": "artifact",'
        ' "target_ref": ".", "profile": "default", "rules": {"acme.r": "dddd"},'
        ' "rules_skipped": []},'
        ' "findings": [{"rule_id": "acme.r", "severity": "HIGH", "title": "t",'
        ' "taxonomy": [{"framework": "ACME-CONTROLS", "id": "ACME-14"}],'
        ' "target_ref": "x.py:1", "evidence": {"summary": "s", "detail": ""},'
        ' "verdict": null}]}',
        encoding="utf-8",
    )

    report = load_report(path)

    assert report.result.findings[0].taxonomy[0].framework == "ACME-CONTROLS"
    assert report.result.findings[0].taxonomy[0].id == "ACME-14"


def test_an_unknown_severity_is_refused(tmp_path: Path) -> None:
    """Severity is a closed vocabulary and orders the gate; guessing at one is not an option."""
    path = tmp_path / "bad.json"
    path.write_text(
        '{"schema_version": 1, "run": {"tool_version": "0.6.0", "target_kind": "artifact",'
        ' "target_ref": ".", "profile": "default", "rules": {}, "rules_skipped": []},'
        ' "findings": [{"rule_id": "r", "severity": "APOCALYPTIC", "title": "t",'
        ' "taxonomy": [], "target_ref": "x", "evidence": {"summary": "s"}}]}',
        encoding="utf-8",
    )

    with pytest.raises(ReportLoadError, match="severity"):
        load_report(path)
