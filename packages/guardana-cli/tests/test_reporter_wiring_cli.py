from pathlib import Path
from typing import ClassVar

import guardana.cli._endpoint as endpoint_module
import guardana.cli._reporting as reporting_module
import pytest
from guardana.cli.main import app
from guardana.core.report import ScanResult
from guardana.core.testing import RefusingTransport
from typer.testing import CliRunner

runner = CliRunner()


class _FakeReporter:
    """Captures `submit` calls instead of making network requests."""

    instances: ClassVar[list["_FakeReporter"]] = []

    def __init__(self, url: str) -> None:
        self.url = url
        self.calls: list[tuple[ScanResult, str]] = []
        _FakeReporter.instances.append(self)

    def submit(self, result: ScanResult, *, source: str) -> None:
        self.calls.append((result, source))


class _ExplodingReporter:
    """A collector that is down."""

    def __init__(self, url: str) -> None:
        pass

    def submit(self, result: ScanResult, *, source: str) -> None:
        raise ConnectionError("collector unreachable")


def test_scan_forwards_result_to_reporter_when_flag_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _FakeReporter.instances.clear()
    monkeypatch.setattr(reporting_module, "HttpReporter", _FakeReporter)
    (tmp_path / "ok.py").write_text("import os\n", encoding="utf-8")

    result = runner.invoke(
        app, ["scan", str(tmp_path), "--reporter", "server://http://collector/findings"]
    )

    assert result.exit_code == 0, result.output
    assert len(_FakeReporter.instances) == 1
    reporter = _FakeReporter.instances[0]
    assert reporter.url == "http://collector/findings"
    assert len(reporter.calls) == 1
    submitted_result, source = reporter.calls[0]
    assert isinstance(submitted_result, ScanResult)
    assert source == str(tmp_path)


def test_scan_does_not_construct_reporter_when_flag_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _FakeReporter.instances.clear()
    monkeypatch.setattr(reporting_module, "HttpReporter", _FakeReporter)
    (tmp_path / "ok.py").write_text("import os\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert _FakeReporter.instances == []


def test_probe_forwards_result_to_reporter_when_flag_set(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeReporter.instances.clear()
    monkeypatch.setattr(reporting_module, "HttpReporter", _FakeReporter)
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)

    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--reporter",
            "server://http://collector/findings",
        ],
    )

    assert result.exit_code == 0, result.output
    assert len(_FakeReporter.instances) == 1
    reporter = _FakeReporter.instances[0]
    assert len(reporter.calls) == 1
    _, source = reporter.calls[0]
    assert source == "http://fake#m"


def test_collector_outage_does_not_change_scan_exit_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The gate's verdict stands on its own: a dead collector is a warning, not a failure.
    monkeypatch.setattr(reporting_module, "HttpReporter", _ExplodingReporter)
    (tmp_path / "ok.py").write_text("import os\n", encoding="utf-8")

    result = runner.invoke(
        app, ["scan", str(tmp_path), "--reporter", "server://http://collector/findings"]
    )

    assert result.exit_code == 0, result.output
    assert "could not submit to reporter" in result.output


def test_collector_outage_does_not_mask_a_failing_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(reporting_module, "HttpReporter", _ExplodingReporter)
    (tmp_path / "bad.py").write_text("import torch\ntorch.load('m.pt')\n", encoding="utf-8")

    result = runner.invoke(
        app, ["scan", str(tmp_path), "--reporter", "server://http://collector/findings"]
    )

    assert result.exit_code == 1, result.output
    assert "could not submit to reporter" in result.output


def test_collector_outage_does_not_change_probe_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reporting_module, "HttpReporter", _ExplodingReporter)
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)

    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--reporter",
            "server://http://collector/findings",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "could not submit to reporter" in result.output
