"""`guardana trace inspect` — the command that lets an operator gate on evidence.

Two things it must never do: reach a network, and print a single coverage percentage.
The first is what makes it safe to point at a production recording; the second is what
keeps it useful, because one number hides which dimension is missing and that is the
entire question.
"""

import json
from pathlib import Path

from guardana.cli.main import app
from guardana.core.trace import (
    Approval,
    ApprovalOutcome,
    Dimension,
    EffectStatus,
    Provenance,
    SideEffect,
    SinkKind,
    Span,
    SpanKind,
    Trace,
    TraceTruncation,
    serialize_trace,
)
from typer.testing import CliRunner

runner = CliRunner()


def _write_trace(
    tmp_path: Path,
    *records: Dimension,
    truncated: TraceTruncation | None = None,
) -> Path:
    trace = Trace(
        trace_id="t-1",
        spans=(
            Span(
                span_id="s1",
                kind=SpanKind.TOOL_EXECUTION,
                name="refund",
                effects=(
                    SideEffect(
                        sink=SinkKind.PAYMENT, action="payment.refund", status=EffectStatus.EXECUTED
                    ),
                ),
                approvals=(Approval(action="payment.refund", outcome=ApprovalOutcome.GRANTED),),
            ),
        ),
        provenance=Provenance(producer="acme", source="a.jsonl", dialect="guardana"),
        instrumented=frozenset(records),
        truncated=truncated,
    )
    path = tmp_path / "trace.jsonl"
    path.write_text(serialize_trace(trace), encoding="utf-8")
    return path


def _profile(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "guardana.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_it_prints_one_row_per_dimension_and_never_a_percentage(tmp_path: Path) -> None:
    """No total, deliberately: "78% covered" is compatible with no identity evidence at all."""
    result = runner.invoke(
        app, ["trace", "inspect", str(_write_trace(tmp_path, Dimension.EFFECTS))]
    )

    assert result.exit_code == 0, result.output
    for dimension in Dimension:
        assert str(dimension) in result.output
    assert "%" not in result.output


def test_declared_and_recorded_are_printed_as_two_columns(tmp_path: Path) -> None:
    """The difference between them is a real and different failure, so it stays visible."""
    path = _write_trace(tmp_path, Dimension.EFFECTS, Dimension.APPROVAL, Dimension.RETRIEVAL)

    result = runner.invoke(app, ["trace", "inspect", str(path), "--format", "json"])

    rows = {row["dimension"]: row for row in json.loads(result.output)["dimensions"]}
    assert rows["approval"] == {
        "dimension": "approval",
        "declared": True,
        "records": 1,
        "required": False,
        "licenses": rows["approval"]["licenses"],
    }
    assert rows["retrieval"]["declared"] is True, "declared and empty is gradable"
    assert rows["retrieval"]["records"] == 0
    assert rows["memory"]["declared"] is False


def test_the_licensed_rules_come_from_the_registry_rather_than_a_written_down_list(
    tmp_path: Path,
) -> None:
    """So a rule pack a team installed is counted and the number cannot rot."""
    path = _write_trace(tmp_path, Dimension.EFFECTS)

    result = runner.invoke(app, ["trace", "inspect", str(path), "--format", "json"])

    rows = {row["dimension"]: row for row in json.loads(result.output)["dimensions"]}
    assert "guardana.trace.unapproved_side_effect" in rows["effects"]["licenses"]
    assert rows["memory"]["licenses"] == [], "no installed rule needs memory, and it says so"


def test_it_says_a_required_dimension_is_missing_before_a_pipeline_finds_out(
    tmp_path: Path,
) -> None:
    """The whole reason the command exists: seeing the gap before a rule is missed."""
    path = _write_trace(tmp_path, Dimension.EFFECTS)
    profile = _profile(tmp_path, "name: t\ntrace:\n  require: [approval, effects]\n")

    result = runner.invoke(app, ["trace", "inspect", str(path), "--profile", str(profile)])

    assert "requires approval" in result.output
    assert "indeterminate, never a pass" in result.output


def test_it_confirms_when_every_required_dimension_is_there(tmp_path: Path) -> None:
    path = _write_trace(tmp_path, Dimension.EFFECTS, Dimension.APPROVAL)
    profile = _profile(tmp_path, "name: t\ntrace:\n  require: [approval, effects]\n")

    result = runner.invoke(app, ["trace", "inspect", str(path), "--profile", str(profile)])

    assert "ok: every dimension this profile requires" in result.output


def test_it_says_a_truncated_trace_is_incomplete(tmp_path: Path) -> None:
    path = _write_trace(tmp_path, Dimension.EFFECTS, truncated=TraceTruncation.READ_LIMIT)

    result = runner.invoke(app, ["trace", "inspect", str(path)])

    assert "incomplete" in result.output


def test_a_missing_file_is_invalid_usage_rather_than_an_empty_matrix(tmp_path: Path) -> None:
    result = runner.invoke(app, ["trace", "inspect", str(tmp_path / "nope.jsonl")])

    assert result.exit_code == 3, result.output


def test_it_writes_no_run_document_and_opens_no_socket(tmp_path: Path) -> None:
    """Inspecting evidence somebody already has must not become an event of its own."""
    path = _write_trace(tmp_path, Dimension.EFFECTS)
    before = set(tmp_path.iterdir())

    result = runner.invoke(app, ["trace", "inspect", str(path)])

    assert result.exit_code == 0
    assert set(tmp_path.iterdir()) == before
