"""The collector envelope carries its own version, never the run schema's.

The collector is released on its own cadence and refuses an envelope version it
does not speak, so a run schema bump that moved the envelope's number would cut
off every collector already deployed. The reporter is loaded afresh while the run
schema says another number, which is the only way to see a version taken from it.
"""

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from guardana.core.manifest import model as manifest_model
from guardana.core.report.result import ScanResult
from guardana.core.reporter import ENVELOPE_SCHEMA_VERSION

_KNOWN_HOLDERS = {
    ("guardana.core.manifest.model", "MANIFEST_SCHEMA_VERSION"),
    ("guardana.core.manifest", "MANIFEST_SCHEMA_VERSION"),
    ("guardana.core.report.serialize", "MANIFEST_SCHEMA_VERSION"),
    ("guardana.core.report.run", "REPORT_SCHEMA_VERSION"),
    ("guardana.core.report.load", "REPORT_SCHEMA_VERSION"),
}


def _run_schema_holders() -> list[tuple[ModuleType, str]]:
    """Every loaded `guardana.*` module-level `*_SCHEMA_VERSION` holding the run schema's number.

    Found by a scan rather than listed, so a new alias the reporter could read is moved too.
    """
    run_schema = manifest_model.MANIFEST_SCHEMA_VERSION
    return [
        (module, name)
        for module_name, module in sorted(sys.modules.copy().items())
        if module_name.startswith("guardana.") and isinstance(module, ModuleType)
        for name, value in vars(module).items()
        if name.endswith("_SCHEMA_VERSION") and type(value) is int and value == run_schema
    ]


def _schemas() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "schemas").is_dir() and (parent / "packages").is_dir():
            return parent / "schemas"
    raise AssertionError("could not locate schemas/")


def _fresh_reporter() -> ModuleType:
    """Execute `guardana.core.reporter` again under another name, leaving the loaded one alone."""
    spec = importlib.util.find_spec("guardana.core.reporter")
    if spec is None or spec.origin is None:
        raise AssertionError("guardana.core.reporter cannot be found")
    fresh_spec = importlib.util.spec_from_file_location("_reporter_under_test", spec.origin)
    if fresh_spec is None or fresh_spec.loader is None:
        raise AssertionError("guardana.core.reporter cannot be loaded from its file")
    module = importlib.util.module_from_spec(fresh_spec)
    fresh_spec.loader.exec_module(module)
    return module


def _submitted(reporter: ModuleType) -> dict[str, Any]:
    sent: list[bytes] = []
    reporter.HttpReporter(
        "https://collector.invalid", transport=lambda _u, b: sent.append(b)
    ).submit(ScanResult(findings=(), rules_run=("acme.rule",), rules_skipped=()), source="ci")
    payload: dict[str, Any] = json.loads(sent[0])
    return payload


def _published_envelope_schemas() -> list[Path]:
    return sorted(_schemas().glob("collector-envelope-v*.schema.json"))


def test_the_envelope_keeps_its_version_when_the_run_schema_moves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    moved = manifest_model.MANIFEST_SCHEMA_VERSION + 1000
    holders = _run_schema_holders()
    assert {(module.__name__, name) for module, name in holders} >= _KNOWN_HOLDERS
    for module, name in holders:
        monkeypatch.setattr(module, name, moved)

    reporter = _fresh_reporter()

    assert reporter.ENVELOPE_SCHEMA_VERSION == ENVELOPE_SCHEMA_VERSION
    assert _submitted(reporter)["schema_version"] == ENVELOPE_SCHEMA_VERSION


def test_the_envelope_carries_no_run_schema_version() -> None:
    """Only the run's identity travels, never the manifest that the run schema versions."""
    from guardana.core import reporter  # noqa: PLC0415 — the module the other test reloads

    payload = _submitted(reporter)

    assert "$schema" not in payload
    assert all(
        "schema_version" not in block for block in payload.values() if isinstance(block, dict)
    )


def test_the_published_envelope_schema_names_its_own_version() -> None:
    published = {
        int(match.group(1)): path
        for path in _published_envelope_schemas()
        if (match := re.fullmatch(r"collector-envelope-v(\d+)\.schema\.json", path.name))
    }

    assert ENVELOPE_SCHEMA_VERSION in published
    for version, path in published.items():
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema["properties"]["schema_version"] == {"const": version}, path.name
        assert schema["$id"].endswith(f"/collector-envelope/v{version}.schema.json"), path.name
        assert not re.search(r"/schemas/run/|run-v\d+", json.dumps(schema)), (
            f"{path.name} refers to the run schema, so it is not versioned apart from it"
        )
