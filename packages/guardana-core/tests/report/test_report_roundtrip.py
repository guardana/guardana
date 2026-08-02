"""A saved run is a contract: whatever `guardana diff` reads, someone else can too.

Serialization has existed since 0.1; reading a run back has not. The moment a
second command consumes the JSON output, its shape stops being an implementation
detail — hence a version on it from the first day rather than when it hurts.
"""

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from guardana.core.evaluator.base import Verdict
from guardana.core.gate import GateOutcome
from guardana.core.manifest import (
    ConfigurationRef,
    ExecutionSettings,
    RunManifest,
    RunUsage,
    TargetIdentity,
    ToolInfo,
)
from guardana.core.manifest.records import RuleRecord
from guardana.core.manifest.summary import summarize
from guardana.core.observation import Observation, ObservationKind
from guardana.core.report import (
    CheckError,
    Evidence,
    Finding,
    ScanResult,
    SkippedRule,
    SkipReason,
    StopReason,
)
from guardana.core.report.load import ReportLoadError, load_report
from guardana.core.report.run import REPORT_SCHEMA_VERSION
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
from guardana.core.taxonomy import OWASP_LLM01
from guardana.report import get_renderer

_STARTED = datetime(2026, 7, 31, 9, 12, 44, tzinfo=UTC)


def _manifest(result: ScanResult) -> RunManifest:
    return RunManifest(
        run_id="0191d4c2-0000-7000-8000-000000000000",
        created_at=_STARTED,
        started_at=_STARTED,
        completed_at=datetime(2026, 7, 31, 9, 13, 26, tzinfo=UTC),
        guardana=ToolInfo(version="0.6.0"),
        target=TargetIdentity(kind=TargetKind.ENDPOINT, ref="http://localhost:11434#llama3"),
        configuration=ConfigurationRef(profile_name="ci"),
        execution=ExecutionSettings(concurrency=4, timeout_seconds=30),
        usage=RunUsage(requests=7, wall_time_seconds=42.0),
        rules=(RuleRecord(id="guardana.prompt.injection", digest="aaaabbbbccccdddd"),),
        result_summary=summarize(result, GateOutcome.FAIL),
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
        rules_skipped=(
            SkippedRule(
                "guardana.agent.memory_poisoning",
                SkipReason.MISSING_CAPABILITY,
                ("call_tools",),
                "d",
            ),
        ),
        unverified=(_finding("guardana.prompt.leak", outcome="inconclusive"),),
        waived=(_finding("guardana.prompt.waived"),),
        errors=(CheckError("acme.broken", "run", "ValueError: boom"),),
        observations=(
            Observation(ObservationKind.MODEL, "llama3", "model.gguf", {"format": "gguf"}),
        ),
    )


def _write(tmp_path: Path, result: ScanResult) -> Path:
    path = tmp_path / "run.json"
    path.write_text(get_renderer("json", run=_manifest(result)).render(result), encoding="utf-8")
    return path


def test_every_channel_survives_a_round_trip(tmp_path: Path) -> None:
    """A channel dropped in serialization is a channel a comparison cannot see."""
    original = _full_result()

    report = load_report(_write(tmp_path, original))

    assert report.result == original


def test_run_metadata_survives_a_round_trip(tmp_path: Path) -> None:
    result = _full_result()

    report = load_report(_write(tmp_path, result))

    assert report.manifest == _manifest(result)


def test_the_recorded_cost_survives_a_round_trip(tmp_path: Path) -> None:
    """A usage figure that does not survive the file is a budget nobody can set."""
    usage = load_report(_write(tmp_path, _full_result())).manifest.usage

    assert usage.requests == 7
    assert usage.wall_time_seconds == 42.0


def test_the_recorded_gate_survives_a_round_trip(tmp_path: Path) -> None:
    """Stored, never re-derived: a reader that recomputes it will eventually differ."""
    report = load_report(_write(tmp_path, _full_result()))

    assert report.manifest.result_summary.gate is GateOutcome.FAIL


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


def test_a_stopped_run_survives_a_round_trip(tmp_path: Path) -> None:
    """The field that says the coverage is partial must not be lost in the file.

    A run cut short has fewer findings than a complete one. If the file does not
    carry the reason it was cut short, the next comparison reads that shortfall as
    an improvement — which is the whole point of recording it.
    """
    result = replace(_full_result(), stopped_by=StopReason.BUDGET_EXHAUSTED)

    report = load_report(_write(tmp_path, result))

    assert report.result.stopped_by is StopReason.BUDGET_EXHAUSTED
    assert report.manifest.result_summary.stopped_by is StopReason.BUDGET_EXHAUSTED


def test_a_document_with_no_run_block_is_refused(tmp_path: Path) -> None:
    """Rendering without a manifest produces findings and no run; it is not a saved run.

    Refused rather than read, because a document that cannot say which rules ran
    cannot be compared against one that can — the narrowed-profile problem again.
    """
    path = tmp_path / "no-run.json"
    path.write_text(get_renderer("json").render(_full_result()), encoding="utf-8")

    with pytest.raises(ReportLoadError):
        load_report(path)


def test_rendering_without_a_manifest_still_reports_every_finding(tmp_path: Path) -> None:
    """The worst reading of a missing manifest would be an empty findings list."""
    document = json.loads(get_renderer("json").render(_full_result()))

    assert len(document["findings"]) == 1
    assert len(document["unverified"]) == 1
    assert len(document["errors"]) == 1
