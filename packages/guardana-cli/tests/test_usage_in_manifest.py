"""What the run spent has to reach the file, or nobody can budget the next one.

The interesting case is the endpoint: `probe` builds several targets (one per
planted canary), so the run's bill is the sum across all of them. A number read
off whichever target happened to be last would understate it — silently, which is
the failure mode this whole layer exists to avoid.
"""

import json
from pathlib import Path

import pytest
from guardana.cli import _endpoint as endpoint_module
from guardana.cli.main import app
from guardana.core.report import load_report
from guardana.core.testing import RefusingTransport
from typer.testing import CliRunner

runner = CliRunner()


def _scan(tmp_path: Path) -> Path:
    out = tmp_path / "run.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(out)])
    assert result.exit_code == 0, result.output
    return out


def _probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)
    out = tmp_path / "probe.json"
    result = runner.invoke(
        app,
        ["probe", "--url", "http://fake", "--model", "m", "--format", "json", "--output", str(out)],
    )
    assert result.exit_code in (0, 1), result.output
    return out


def test_a_file_scan_records_a_measured_zero_not_an_unknown(tmp_path: Path) -> None:
    usage = load_report(_scan(tmp_path)).manifest.usage

    assert usage.requests == 0
    assert usage.wall_time_seconds is not None
    assert usage.wall_time_seconds >= 0


def test_inspect_prints_a_measured_zero_as_a_number(tmp_path: Path) -> None:
    # The screen has to keep the distinction the document keeps.
    result = runner.invoke(app, ["run", "inspect", str(_scan(tmp_path))])

    assert "requests:  0" in result.output
    assert "requests:  not recorded" not in result.output


def test_a_scan_leaves_token_counts_unknown_rather_than_zero(tmp_path: Path) -> None:
    # Nothing was sent to a model, so there are no tokens to have counted. That is
    # not the same as a model that reported zero tokens.
    usage = load_report(_scan(tmp_path)).manifest.usage

    assert usage.input_tokens is None
    assert usage.output_tokens is None


def test_a_probe_records_the_requests_it_actually_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    usage = load_report(_probe(tmp_path, monkeypatch)).manifest.usage

    assert usage.requests is not None
    assert usage.requests > 0, "a probe that graded a model must record what it sent"


def test_a_probe_records_more_requests_than_it_ran_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bill is per request, not per rule, and it covers every canary pass.

    A rule sends one request per prompt, and probe runs each canary rule in its own
    pass against its own target. Counting one target, or one request per rule,
    would both understate the total — and this is the number a budget will be
    enforced against.
    """
    report = load_report(_probe(tmp_path, monkeypatch))

    requests = report.manifest.usage.requests
    assert requests is not None
    assert requests > len(report.manifest.rules)


def test_the_manifest_says_how_many_requests_reported_no_tokens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    usage = json.loads(_probe(tmp_path, monkeypatch).read_text(encoding="utf-8"))["run"]["usage"]

    assert usage["input_tokens"] is None
    assert usage["requests_missing_token_counts"] == usage["requests"], (
        "a scripted transport reports no tokens, so every request must be counted as missing"
    )


def test_a_probe_reports_its_wall_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    usage = load_report(_probe(tmp_path, monkeypatch)).manifest.usage

    assert usage.wall_time_seconds is not None
    assert usage.wall_time_seconds > 0
