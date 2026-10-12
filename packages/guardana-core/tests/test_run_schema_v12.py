"""Run schema 12 records what a file run listed and excluded and the plugin trust in force.

A version-11 run arrives with both null: no listing and no trust were recorded, which
is unknown, never "listed nothing" or "built-ins only".
"""

import copy
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from _documents import run_manifest, saved_run_at_v11, saved_run_at_v12, scan_result
from guardana.core.manifest.load import ManifestLoadError, manifest_from_dict
from guardana.core.manifest.migrations import migrate_v11
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.report.load import ReportLoadError, load_report
from guardana.core.report.serialize import run_to_dict
from guardana.core.target.scope import FileScope
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _errors(document: dict[str, Any]) -> list[str]:
    """Validate `document` against the v12 schema, in the shape a version-12 build wrote."""
    document = saved_run_at_v12(document)
    schema = json.loads((_SCHEMAS / "run-v12.schema.json").read_text(encoding="utf-8"))
    return [error.message for error in Draft202012Validator(schema).iter_errors(document)]


def _document() -> dict[str, Any]:
    return run_to_dict(scan_result(), run_manifest())


def _write(document: dict[str, Any], tmp_path: Path) -> Path:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _configuration(document: dict[str, Any]) -> dict[str, Any]:
    configuration: dict[str, Any] = document["run"]["configuration"]
    return configuration


# The document this build writes


def test_the_written_document_satisfies_the_v12_schema() -> None:
    assert not _errors(_document())


def test_the_scope_and_the_trust_are_written() -> None:
    document = _document()

    assert document["scope"] == {
        "files": ["model/weights.safetensors", "model/config.json", "model/old.pkl"],
        "excludes": [
            {"pattern": "model/build/*", "source": "profile", "file": None},
            {"pattern": "*.bak", "source": "ignore_file", "file": ".guardanaignore"},
            {"pattern": "*.pkl", "source": "ignore_file", "file": ".guardanaignore"},
        ],
        "ignored_directories": [".git", "*.egg-info"],
        "kept_models": [{"path": "model/old.pkl", "pattern": "*.pkl"}],
        "skipped_models": {
            "directories": [{"path": "env", "model_files": 2}],
            "searched_all": False,
        },
    }
    assert _configuration(document)["plugins"] == {"mode": "allowlist", "allowed": ["acme-rules"]}


@pytest.mark.parametrize(
    "scope",
    [
        None,
        FileScope(),
        FileScope(files=("a.py",), excludes=None),
    ],
    ids=["not a file run", "listed nothing", "excludes unknown"],
)
def test_the_scope_survives_being_saved_and_read_back(
    scope: FileScope | None, tmp_path: Path
) -> None:
    saved = run_to_dict(replace(scan_result(), scope=scope), run_manifest())

    assert not _errors(saved)
    assert load_report(_write(saved, tmp_path)).result.scope == scope


@pytest.mark.parametrize(
    "trust",
    [None, PluginTrust(mode=PluginMode.BUILTINS), PluginTrust(mode=PluginMode.DISABLED)],
    ids=["not recorded", "builtins", "disabled"],
)
def test_the_trust_survives_being_saved_and_read_back(trust: PluginTrust | None) -> None:
    manifest = run_manifest()
    manifest = replace(manifest, configuration=replace(manifest.configuration, plugins=trust))

    assert manifest_from_dict(manifest_to_dict(manifest)) == manifest


# The loader and the schema refuse what no writer produces

_SCOPE_BREAKAGES: dict[str, Callable[[dict[str, Any]], None]] = {
    "scope not an object": lambda doc: doc.update(scope=["a.py"]),
    "unknown key": lambda doc: doc["scope"].update(depth=3),
    "files missing": lambda doc: doc["scope"].pop("files"),
    "files not strings": lambda doc: doc["scope"].update(files=[1]),
    "exclude source unknown": lambda doc: doc["scope"]["excludes"][0].update(source="cli"),
    "exclude without pattern": lambda doc: doc["scope"]["excludes"][0].pop("pattern"),
}


@pytest.mark.parametrize("breakage", _SCOPE_BREAKAGES)
def test_the_loader_and_the_schema_refuse_the_same_malformed_scope(
    breakage: str, tmp_path: Path
) -> None:
    document = _document()
    _SCOPE_BREAKAGES[breakage](document)

    with pytest.raises(ReportLoadError, match="scope"):
        load_report(_write(document, tmp_path))
    assert _errors(document), f"the v12 schema accepts {breakage}, which the loader refuses"


_TRUST_BREAKAGES: dict[str, Callable[[dict[str, Any]], None]] = {
    "plugins missing": lambda cfg: cfg.pop("plugins"),
    "mode unknown": lambda cfg: cfg["plugins"].update(mode="some"),
    "allowed not a list": lambda cfg: cfg["plugins"].update(allowed="acme-rules"),
    "unknown key": lambda cfg: cfg["plugins"].update(stated=True),
}


@pytest.mark.parametrize("breakage", _TRUST_BREAKAGES)
def test_the_loader_and_the_schema_refuse_the_same_malformed_trust(breakage: str) -> None:
    document = _document()
    _TRUST_BREAKAGES[breakage](_configuration(document))

    with pytest.raises(ManifestLoadError, match="plugins"):
        manifest_from_dict(document["run"])
    assert _errors(document), f"the v12 schema accepts {breakage}, which the loader refuses"


def test_a_hand_written_document_without_a_scope_reads_it_as_unknown(tmp_path: Path) -> None:
    document = _document()
    del document["scope"]

    assert load_report(_write(document, tmp_path)).result.scope is None
    assert _errors(document), "a writer must still write the key"


# Version 11 forward


def test_a_v11_run_migrates_to_12_with_scope_and_trust_unknown() -> None:
    v11 = saved_run_at_v11(_document())

    migrated = migrate_v11(v11)

    assert migrated["schema_version"] == 12
    assert migrated["$schema"] == "https://guardana.dev/schemas/run/v12.schema.json"
    assert not _errors(migrated)
    assert migrated["scope"] is None
    assert _configuration(migrated)["plugins"] is None


def test_the_migration_overwrites_what_a_v11_run_should_not_hold() -> None:
    v11 = saved_run_at_v11(_document())
    v11["scope"] = _document()["scope"]
    _configuration(v11)["plugins"] = {"mode": "all", "allowed": []}

    migrated = migrate_v11(v11)

    assert migrated["scope"] is None
    assert _configuration(migrated)["plugins"] is None


def test_the_migration_recomputes_nothing_else() -> None:
    v11 = saved_run_at_v11(_document())
    before = copy.deepcopy(v11)

    migrated = migrate_v11(v11)

    assert v11 == before, "the migration must not edit the document it was handed"
    assert saved_run_at_v11(migrated) == v11


def test_a_loaded_v11_run_says_it_was_migrated_and_records_no_scope(tmp_path: Path) -> None:
    report = load_report(_write(saved_run_at_v11(_document()), tmp_path))

    assert report.manifest.migrated_from == 11
    assert report.result.scope is None
    assert report.manifest.configuration.plugins is None
