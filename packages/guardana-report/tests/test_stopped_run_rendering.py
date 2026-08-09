"""A run that was cut short must not print the tick people scroll for.

`StopReason` says why this exists in its own docstring: a report outlives the
process that wrote it, and one that does not say it was cut short reads as a
complete pass over the target. The exit code carries it — `6` for an exhausted
budget — but nobody reads an exit code off a terminal, and a job summary that says
"✓ No findings" over a run that stopped after two rules is the false green this
project exists against.

Found by running `probe --mcp --max-request 3` against a live server and reading
the output rather than the exit code.
"""

from guardana.core.report import ScanResult, StopReason
from guardana.report import HumanRenderer

_STOPPED = ScanResult(
    findings=(),
    rules_run=("r0", "r1"),
    rules_skipped=(),
    stopped_by=StopReason.BUDGET_EXHAUSTED,
)
_COMPLETE = ScanResult(findings=(), rules_run=("r0", "r1"), rules_skipped=())


def test_a_stopped_run_never_prints_the_tick() -> None:
    text = HumanRenderer().render(_STOPPED)

    assert "✓" not in text
    assert "not an all-clear" in text


def test_the_reason_it_stopped_is_named() -> None:
    text = HumanRenderer().render(_STOPPED)

    assert "budget_exhausted" in text


def test_the_summary_line_says_the_run_was_cut_short() -> None:
    # The summary is the line CI job summaries quote, so it carries it too.
    assert "stopped early" in HumanRenderer().render(_STOPPED).splitlines()[-1]


def test_an_interrupted_run_is_treated_the_same_way() -> None:
    interrupted = ScanResult(
        findings=(), rules_run=("r0",), rules_skipped=(), stopped_by=StopReason.INTERRUPTED
    )

    assert "✓" not in HumanRenderer().render(interrupted)


def test_a_complete_run_with_nothing_to_report_still_gets_its_tick() -> None:
    text = HumanRenderer().render(_COMPLETE)

    assert "✓ No findings." in text
    assert "stopped early" not in text
