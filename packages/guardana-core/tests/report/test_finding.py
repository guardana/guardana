from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.core.taxonomy import OWASP_LLM05_2025


def _finding(sev: Severity) -> Finding:
    return Finding(
        rule_id="guardana.demo",
        severity=sev,
        title="demo",
        taxonomy=(OWASP_LLM05_2025,),
        target_ref="models/demo.pkl",
        evidence=Evidence(summary="found something"),
    )


def test_finding_defaults_verdict_none_and_is_frozen() -> None:
    f = _finding(Severity.HIGH)
    assert f.verdict is None
    assert f.evidence.summary == "found something"


def test_scan_result_reports_max_severity() -> None:
    result = ScanResult(
        findings=(_finding(Severity.LOW), _finding(Severity.HIGH)),
        rules_run=("r0", "r1"),
        rules_skipped=(),
    )
    assert result.max_severity() is Severity.HIGH


def test_scan_result_max_severity_none_when_empty() -> None:
    assert ScanResult(findings=(), rules_run=(), rules_skipped=()).max_severity() is None
