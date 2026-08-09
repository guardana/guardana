"""`guardana analyze-trace` — the exit codes, and the sentences that keep the report honest.

Two properties carry most of this file.

**A record that could not be read reaches the `errors` channel**, not a warning on
stderr. `fail_on_error` is on by default, so an unreadable record makes the run
indeterminate instead of producing a report that reads complete over an execution missing
a step. Asserting on the log would be measuring the echo; the assertion is on the saved
document and the exit code.

**A trace that cannot be read at all exits `3`**, and never `0`. An empty trace grades
clean, which is what a mistyped path in a pipeline looks like — and that is the worst
shape of false green this project has.
"""

import json
from pathlib import Path

from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.manifest import SourceKind
from guardana.core.trace import TRACE_SCHEMA_VERSION
from typer.testing import CliRunner, Result

runner = CliRunner()

_HEADER = {
    "guardana_trace": 1,
    "trace_id": "t-1",
    "producer": {"name": "acme"},
    "instrumented": ["messages", "tools", "identity", "delegation", "approval", "effects"],
}
_KEY = "sk-proj-" + "A" * 24
_LEAKY_SPAN = {
    "span_id": "s1",
    "kind": "tool_execution",
    "name": "http",
    "tool": {"name": "http", "arguments": '{"h": "' + _KEY + '"}'},
}
_CLEAN_SPAN = {"span_id": "s1", "kind": "tool_execution", "name": "http", "tool": {"name": "http"}}


def _write(tmp_path: Path, *records: object, name: str = "trace.jsonl") -> Path:
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def _run(*args: str) -> Result:
    return runner.invoke(app, ["analyze-trace", *args])


def test_a_clean_trace_passes_and_says_which_dialect_it_was_read_as(tmp_path: Path) -> None:
    """Detection is load-bearing for correctness, so it announces its answer on every run."""
    result = _run(str(_write(tmp_path, _HEADER, _CLEAN_SPAN)))
    assert result.exit_code == ExitCode.OK
    assert "as guardana" in result.output
    assert "producer: acme" in result.output


def test_a_finding_in_a_trace_fails_the_gate(tmp_path: Path) -> None:
    result = _run(str(_write(tmp_path, _HEADER, _LEAKY_SPAN)))
    assert result.exit_code == ExitCode.POLICY_FAILED
    assert "secret_in_tool_argument" in result.output
    assert _KEY not in result.output


def test_a_trace_that_does_not_exist_exits_three_rather_than_reporting_no_findings(
    tmp_path: Path,
) -> None:
    result = _run(str(tmp_path / "nope.jsonl"))
    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "does not exist" in result.output


def test_a_directory_is_refused_rather_than_read_as_an_empty_trace(tmp_path: Path) -> None:
    result = _run(str(tmp_path))
    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "one JSONL trace file" in result.output


def test_a_trace_schema_this_build_cannot_read_exits_three(tmp_path: Path) -> None:
    result = _run(str(_write(tmp_path, {**_HEADER, "guardana_trace": 99})))
    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "schema version 99" in result.output


def test_an_unreadable_record_lands_in_the_errors_channel_of_the_saved_run(
    tmp_path: Path,
) -> None:
    """Measured where the value arrives — in the document — not in the log line about it."""
    oversized = {"span_id": "s2", "name": "x" * (1024 * 1024 + 10)}
    trace = _write(tmp_path, _HEADER, _CLEAN_SPAN, oversized)
    output = tmp_path / "run.json"
    result = _run(str(trace), "--format", "json", "--output", str(output))
    assert result.exit_code == ExitCode.INDETERMINATE
    document = json.loads(output.read_text(encoding="utf-8"))
    assert len(document["errors"]) == 1
    assert document["errors"][0]["stage"] == "load"
    assert document["run"]["result_summary"]["gate"] == "indeterminate"


def test_a_saved_run_over_a_trace_says_it_came_from_a_trace(tmp_path: Path) -> None:
    """A dashboard that cannot tell a recording from a live check reports one as the other."""
    output = tmp_path / "run.json"
    _run(str(_write(tmp_path, _HEADER, _CLEAN_SPAN)), "--format", "json", "--output", str(output))
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["run"]["source"]["kind"] == SourceKind.IMPORTED_TRACE
    assert document["run"]["target"]["type"] == "trace"
    assert "read_trace" in document["run"]["target"]["capabilities"]


def test_a_dimension_nobody_recorded_is_named_and_its_rules_are_skipped(tmp_path: Path) -> None:
    header = {**_HEADER, "instrumented": ["messages", "tools"]}
    output = tmp_path / "run.json"
    result = _run(
        str(_write(tmp_path, header, _CLEAN_SPAN)), "--format", "json", "--output", str(output)
    )
    assert "does not record" in result.output
    document = json.loads(output.read_text(encoding="utf-8"))
    skipped = {s["rule_id"] for s in document["run"]["result_summary"]["rules_skipped"]}
    assert "guardana.trace.unapproved_side_effect" in skipped


def test_an_opentelemetry_export_is_read_without_being_told_it_is_one(tmp_path: Path) -> None:
    record = {
        "name": "chat gpt-4o",
        "context": {"trace_id": "tr-1", "span_id": "sp-1"},
        "attributes": {
            "gen_ai.operation.name": "chat",
            "gen_ai.provider.name": "openai",
            "gen_ai.response.model": "gpt-4o",
            "gen_ai.input.messages": [
                {"role": "user", "parts": [{"type": "text", "content": "hello"}]}
            ],
        },
    }
    result = _run(str(_write(tmp_path, record, name="otel.jsonl")))
    assert "as otel" in result.output
    assert "does not record" in result.output
    assert "identity" in result.output


def test_an_export_no_rule_can_check_is_indeterminate_and_never_a_pass(tmp_path: Path) -> None:
    """The honest outcome, and the one that surprises people: a trace can be unanswerable.

    An OpenTelemetry export with no tool calls records nothing any shipped rule reads, so
    every rule is skipped and no rule ran. "The policy passed" is not a sentence that run
    is entitled to, and the gate says so rather than going green over a file it could not
    grade.
    """
    record = {
        "name": "chat",
        "spanId": "sp-1",
        "traceId": "tr-1",
        "attributes": {
            "gen_ai.operation.name": "chat",
            "gen_ai.input.messages": [
                {"role": "user", "parts": [{"type": "text", "content": "hello"}]}
            ],
        },
    }
    result = _run(str(_write(tmp_path, record, name="bare.jsonl")))
    assert result.exit_code == ExitCode.INDETERMINATE
    assert "0 rules ran" in result.output


def test_the_dialect_can_be_forced_when_a_file_is_ambiguous(tmp_path: Path) -> None:
    path = _write(tmp_path, {"trace_id": "t-1"}, name="ambiguous.jsonl")
    result = _run(str(path), "--dialect", "guardana")
    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "guardana_trace" in result.output


def test_write_trace_converts_an_export_into_the_dialect_that_can_declare_dimensions(
    tmp_path: Path,
) -> None:
    """The reason the converter is user-facing: it is how the missing half gets filled in."""
    record = {
        "name": "chat",
        "spanId": "sp-1",
        "traceId": "tr-1",
        "attributes": {"gen_ai.operation.name": "chat", "gen_ai.tool.name": "pay"},
    }
    source = _write(tmp_path, record, name="otel.jsonl")
    destination = tmp_path / "native.jsonl"
    result = _run(str(source), "--write-trace", str(destination))
    assert "native dialect" in result.output
    lines = destination.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["guardana_trace"] == TRACE_SCHEMA_VERSION
    assert "does not record" in _run(str(destination)).output


def test_the_models_a_trace_actually_called_are_reported_as_observations(tmp_path: Path) -> None:
    record = {
        "name": "chat",
        "spanId": "sp-1",
        "traceId": "tr-1",
        "attributes": {
            "gen_ai.operation.name": "chat",
            "gen_ai.provider.name": "ollama",
            "gen_ai.response.model": "llama3.1",
        },
    }
    output = tmp_path / "run.json"
    _run(
        str(_write(tmp_path, record, name="otel.jsonl")),
        "--format",
        "json",
        "--output",
        str(output),
    )
    document = json.loads(output.read_text(encoding="utf-8"))
    assert [o["name"] for o in document["observations"]] == ["llama3.1"]


def test_a_budget_a_trace_read_cannot_honour_is_refused_as_configuration(tmp_path: Path) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: t\nbudgets:\n  max_duration_seconds: 1\n", encoding="utf-8")
    result = _run(str(_write(tmp_path, _HEADER, _CLEAN_SPAN)), "--profile", str(profile))
    assert result.exit_code == ExitCode.INVALID_USAGE
    assert "duration" in result.output


def test_a_request_budget_is_accepted_because_reading_a_file_sends_nothing(tmp_path: Path) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: t\nbudgets:\n  max_requests: 5\n", encoding="utf-8")
    result = _run(str(_write(tmp_path, _HEADER, _CLEAN_SPAN)), "--profile", str(profile))
    assert result.exit_code == ExitCode.OK


def test_a_truncated_trace_says_a_quiet_rule_is_not_a_passing_one(tmp_path: Path) -> None:
    header = {**_HEADER, "truncated": "producer_limit"}
    result = _run(str(_write(tmp_path, header, _CLEAN_SPAN)))
    assert "incomplete" in result.output
    assert "inconclusive rather than a pass" in result.output
