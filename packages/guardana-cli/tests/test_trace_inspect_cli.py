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
        "unlocks": [],
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


def test_a_dimension_needed_by_a_rule_does_not_claim_to_unlock_it_on_its_own(
    tmp_path: Path,
) -> None:
    """ "Needed by" and "would start working" are different numbers, and one used to stand in.

    `guardana.trace.unapproved_side_effect` needs approvals *and* side effects. A trace
    recording neither counted it under both, so an operator budgeting instrumentation
    read "approval: 1 rule" and got nothing at all for the work. The column that answers
    their actual question counts a rule only under the last dimension it is waiting for.
    """
    path = _write_trace(tmp_path, Dimension.MESSAGES)

    result = runner.invoke(app, ["trace", "inspect", str(path), "--format", "json"])

    rows = {row["dimension"]: row for row in json.loads(result.output)["dimensions"]}
    assert "guardana.trace.unapproved_side_effect" in rows["approval"]["licenses"]
    assert rows["approval"]["unlocks"] == [], "approvals alone leave that rule still waiting"
    assert rows["effects"]["unlocks"] == [], "and so do side effects alone"
    assert "guardana.trace.identity_disagreement" in rows["identity"]["unlocks"], (
        "a rule waiting on one dimension is unlocked by it"
    )


def test_recording_the_partner_dimension_makes_the_rule_unlockable(tmp_path: Path) -> None:
    """The other half of the same column: with approvals in hand, effects now buys the rule.

    Inverted by the trace rather than by the code — the same command over a producer
    that records one of the pair must move the rule into the other's `unlocks`.
    """
    path = _write_trace(tmp_path, Dimension.MESSAGES, Dimension.APPROVAL)

    result = runner.invoke(app, ["trace", "inspect", str(path), "--format", "json"])

    rows = {row["dimension"]: row for row in json.loads(result.output)["dimensions"]}
    assert "guardana.trace.unapproved_side_effect" in rows["effects"]["unlocks"]
    assert rows["approval"]["unlocks"] == [], "a dimension already recorded has nothing to buy"


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


def test_a_restrictive_plugin_mode_says_so_in_the_table_itself(tmp_path: Path) -> None:
    """A refused rule pack used to be absent from the matrix with no signal at all.

    Every "needed by"/"unlocks" cell read `0 rule(s)`, indistinguishable from a
    trace that genuinely licenses nothing — and the only correction lived on
    stderr, which a reader of the table alone never sees. The correction has to
    be in-band, in words that cannot be misread as "nothing here is worth
    instrumenting".
    """
    path = _write_trace(tmp_path, Dimension.EFFECTS)

    result = runner.invoke(app, ["trace", "inspect", str(path), "--plugins", "disabled"])

    assert result.exit_code == 0, result.output
    assert "could not load rule" in result.stderr
    assert "plugin trust is disabled" in result.stderr
    assert "could not load rule" not in result.stdout
    assert "dimension" in result.stdout
    assert "effects" in result.stdout
    assert "0 rule(s) were loaded to judge this trace against" in result.stdout
    assert "absence of evidence" in result.stdout


def test_full_trust_leaves_a_genuine_zero_reading_as_a_plain_count(tmp_path: Path) -> None:
    """The inversion target: the new note must appear only when nothing was loaded,
    never beside a matrix built from a complete registry."""
    path = _write_trace(tmp_path, Dimension.EFFECTS)

    result = runner.invoke(app, ["trace", "inspect", str(path)])

    assert result.exit_code == 0, result.output
    assert "0 rule(s) were loaded to judge this trace against" not in result.output


def test_the_json_form_counts_the_rules_actually_loaded(tmp_path: Path) -> None:
    """The same distinction the human table gets, for a consumer reading JSON."""
    path = _write_trace(tmp_path, Dimension.EFFECTS)

    full = json.loads(
        runner.invoke(app, ["trace", "inspect", str(path), "--format", "json"]).stdout
    )
    refused = json.loads(
        runner.invoke(
            app, ["trace", "inspect", str(path), "--format", "json", "--plugins", "disabled"]
        ).stdout
    )

    assert full["trace_rules_loaded"] > 0
    assert refused["trace_rules_loaded"] == 0
