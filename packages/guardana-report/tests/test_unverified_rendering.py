"""An unverified check (ran, but could not reach a verdict) must be visible and
distinct in every output format — never dropped, never rendered as a confirmed
finding. That silent-drop would read as a clean pass to whatever consumes the
report."""

import json

from guardana.core.evaluator.base import Verdict
from guardana.core.report.finding import Evidence, Finding
from guardana.core.report.result import ScanResult
from guardana.core.severity import Severity
from guardana.report import get_renderer


def _unverified_result() -> ScanResult:
    finding = Finding(
        rule_id="guardana.prompt.judge.demo",
        severity=Severity.HIGH,
        title="Judged jailbreak",
        taxonomy=(),
        target_ref="http://x#m",
        evidence=Evidence(summary="grading did not complete"),
        verdict=Verdict("inconclusive", 0.0, "judge endpoint unreachable", "llm_judge@2025.1"),
    )
    return ScanResult(findings=(), rules_run=1, rules_skipped=(), unverified=(finding,))


def test_human_surfaces_unverified_distinctly() -> None:
    out = get_renderer("human").render(_unverified_result())
    assert "UNVERIFIED" in out
    assert "judge endpoint unreachable" in out
    assert "0 finding(s)" in out
    assert "1 unverified" in out


def test_json_lists_unverified_separately() -> None:
    payload = json.loads(get_renderer("json").render(_unverified_result()))
    assert payload["findings"] == []
    assert len(payload["unverified"]) == 1
    assert payload["unverified"][0]["verdict"]["outcome"] == "inconclusive"
    assert payload["summary"]["unverified"] == 1


def test_sarif_marks_unverified_as_review_note() -> None:
    doc = json.loads(get_renderer("sarif").render(_unverified_result()))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "note"
    assert results[0]["kind"] == "review"


def test_junit_marks_unverified_as_skipped_not_failure() -> None:
    xml = get_renderer("junit").render(_unverified_result())
    assert 'failures="0"' in xml
    assert 'skipped="1"' in xml
    assert "<skipped " in xml
    assert "<failure" not in xml
    assert "judge endpoint unreachable" in xml
