import json

from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.core.testing import manifest_for
from guardana.report import get_renderer


def _result() -> ScanResult:
    f = Finding(
        "guardana.sc.pickle",
        Severity.CRITICAL,
        "Dangerous pickle opcode",
        (),
        "model.pkl",
        Evidence(summary="REDUCE calls os.system"),
    )
    return ScanResult((f,), rules_run=("r0",), rules_skipped=())


def test_json_renderer_is_machine_readable() -> None:
    result = _result()
    out = json.loads(get_renderer("json", run=manifest_for(result)).render(result))
    assert out["findings"][0]["rule_id"] == "guardana.sc.pickle"
    assert out["findings"][0]["severity"] == "CRITICAL"
    assert out["run"]["result_summary"]["rules_run"] == ["r0"]


def test_human_renderer_mentions_rule_and_severity() -> None:
    out = get_renderer("human").render(_result())
    assert "guardana.sc.pickle" in out
    assert "CRITICAL" in out


def test_the_human_report_never_ticks_over_coverage_somebody_demanded_and_did_not_get() -> None:
    """The tick is what people scroll for, so it is never printed over unmet coverage.

    Same guard the `errors` and `stopped_by` branches already had, and the same
    reasoning: the terminal is where a run is judged, and a `✓` there outweighs an
    exit code nobody reads off a screen.
    """
    from guardana.core.report import CoverageShortfall, ShortfallKind  # noqa: PLC0415

    gap = CoverageShortfall(
        kind=ShortfallKind.MISSING_DIMENSION,
        name="approval",
        detail="this producer records no approvals",
    )
    result = ScanResult((), ("guardana.demo",), (), coverage_shortfall=(gap,))

    rendered = get_renderer("human").render(result)

    assert "✓" not in rendered
    assert "not an all-clear" in rendered
    assert "this producer records no approvals" in rendered


def test_junit_counts_unmet_coverage_as_an_error_rather_than_a_clean_suite() -> None:
    """`errors="0"` is what a CI dashboard reads as "this ran and was fine"."""
    from guardana.core.report import CoverageShortfall, ShortfallKind  # noqa: PLC0415

    gap = CoverageShortfall(
        kind=ShortfallKind.CONTRACT_NOT_APPLICABLE, name="checkout", detail="wrong system"
    )
    result = ScanResult((), ("guardana.demo",), (), coverage_shortfall=(gap,))

    rendered = get_renderer("junit").render(result)

    assert 'errors="1"' in rendered
    assert "wrong system" in rendered
