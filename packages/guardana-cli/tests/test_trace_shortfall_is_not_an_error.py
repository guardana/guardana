"""`analyze-trace` never labels a coverage shortfall as an error the run did not record."""

import json
from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()

_TRACE = [
    {
        "guardana_trace": 3,
        "trace_id": "t-1",
        "producer": {"name": "demo-harness", "version": "1.0"},
        "instrumented": ["messages"],
        "terminated": True,
    },
    {
        "span_id": "s1",
        "kind": "model_call",
        "name": "chat demo",
        "messages": [
            {"role": "user", "parts": [{"type": "text", "content": "hello"}]},
            {"role": "assistant", "parts": [{"type": "text", "content": "hi"}]},
        ],
    },
    {"guardana_trace_end": 3, "spans": 1},
]


def _analyze(tmp_path: Path, mode: str) -> tuple[int, list[str], dict[str, object]]:
    trace = tmp_path / "trace.jsonl"
    trace.write_text("\n".join(json.dumps(record) for record in _TRACE) + "\n", encoding="utf-8")
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "name: withheld-demo\n"
        "rules: {include: ['guardana.trace.*']}\n"
        "trace: {require: [messages, retrieval]}\n"
        f"privacy: {{evidence_mode: {mode}}}\n",
        encoding="utf-8",
    )
    saved = tmp_path / "run.json"
    result = runner.invoke(
        app,
        [
            "analyze-trace",
            str(trace),
            "--profile",
            str(profile),
            "--format",
            "json",
            "--output",
            str(saved),
        ],
    )
    document = json.loads(saved.read_text(encoding="utf-8"))
    return result.exit_code, result.stderr.splitlines(), document


@pytest.mark.parametrize("mode", ["redacted", "metadata_only"])
def test_a_missing_dimension_is_recorded_as_a_shortfall_and_no_error(
    tmp_path: Path, mode: str
) -> None:
    code, _stderr, document = _analyze(tmp_path, mode)
    shortfall = document["run"]["coverage"]["shortfall"]  # type: ignore[index]

    assert code == ExitCode.INDETERMINATE
    assert document["errors"] == []
    assert [gap["name"] for gap in shortfall] == ["retrieval"]


@pytest.mark.parametrize("mode", ["redacted", "metadata_only"])
def test_a_shortfall_is_not_reported_as_an_error(tmp_path: Path, mode: str) -> None:
    _code, stderr, _document = _analyze(tmp_path, mode)

    assert [line for line in stderr if line.startswith("error:")] == [], stderr
    shortfall = "coverage missing (missing_dimension): retrieval"
    assert [line for line in stderr if line.startswith(shortfall)] != [], stderr
