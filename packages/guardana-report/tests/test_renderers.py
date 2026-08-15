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


def test_the_human_report_never_ticks_over_a_run_where_every_check_declined() -> None:
    """A full rule count and not one verdict behind it. The tick used to print anyway.

    The other four denials all read something off the result that is obviously not a
    finding — zero rules, unmet coverage, a stop, an error. This one reads a full
    `rules_run` and a `unverified` entry for every name in it, which is what an
    endpoint answering with an empty message produces.
    """
    ungradable = Finding(
        "guardana.demo",
        Severity.HIGH,
        "could not grade",
        (),
        "http://x#m",
        Evidence(summary="no model reply to inspect"),
    )
    result = ScanResult((), ("guardana.demo",), (), unverified=(ungradable,))

    rendered = get_renderer("human").render(result)

    assert "✓" not in rendered
    assert "not an all-clear" in rendered


def test_the_human_report_still_ticks_when_a_check_reached_a_verdict() -> None:
    """The inversion: one rule that concluded is enough for the tick to be honest."""
    result = ScanResult((), ("guardana.demo",), ())

    assert "✓ No findings." in get_renderer("human").render(result)


def test_junit_does_not_render_a_run_of_pure_skips_as_a_clean_suite() -> None:
    """`failures="0" errors="0"` with everything skipped is green on every dashboard.

    Each declined check is honestly a `<skipped>`; a suite made only of them is not
    honestly a suite that ran. Same reasoning as the unmet-coverage case below, and
    the same fix — one error for the run itself.
    """
    ungradable = Finding(
        "guardana.demo",
        Severity.HIGH,
        "could not grade",
        (),
        "http://x#m",
        Evidence(summary="no model reply to inspect"),
    )
    result = ScanResult((), ("guardana.demo",), (), unverified=(ungradable,))

    out = get_renderer("junit").render(result)

    assert 'errors="1"' in out
    assert "nothing was verified" in out


def test_junit_stays_clean_when_a_check_reached_a_verdict() -> None:
    out = get_renderer("junit").render(ScanResult((), ("guardana.demo",), ()))

    assert 'errors="0"' in out
    assert "nothing was verified" not in out


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
