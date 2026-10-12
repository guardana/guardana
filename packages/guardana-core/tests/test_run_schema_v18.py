"""Run schema 18 records where each exclude came from and what the scanned target could not hide.

A version-17 run arrives with every exclude's file unknown, no kept model, since a
version-17 build let the target's ignore file exclude anything, and its skipped
directories unsearched.
"""

import copy
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from _documents import (
    run_manifest,
    saved_run_at_v9,
    saved_run_at_v10,
    saved_run_at_v11,
    saved_run_at_v12,
    saved_run_at_v13,
    saved_run_at_v14,
    saved_run_at_v15,
    saved_run_at_v16,
    saved_run_at_v17,
    scan_result,
)
from guardana.core.manifest.load import ManifestLoadError
from guardana.core.manifest.migrations import migrate_v17
from guardana.core.report.load import ReportLoadError, load_report, migrate_forward
from guardana.core.report.serialize import run_to_dict
from guardana.core.target.scope import (
    ExcludePattern,
    ExcludeSource,
    FileScope,
    KeptModel,
    SkippedDirectory,
    SkippedModels,
)
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _errors(document: dict[str, Any], version: int = 18) -> list[str]:
    schema = json.loads((_SCHEMAS / f"run-v{version}.schema.json").read_text(encoding="utf-8"))
    return [error.message for error in Draft202012Validator(schema).iter_errors(document)]


def _document() -> dict[str, Any]:
    return run_to_dict(scan_result(), run_manifest())


def _write(document: dict[str, Any], tmp_path: Path) -> Path:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


# The document this build writes


def test_the_written_document_satisfies_the_v18_schema() -> None:
    assert not _errors(_document())


@pytest.mark.parametrize(
    "scope",
    [
        None,
        FileScope(),
        FileScope(files=("a.py",), excludes=None),
        FileScope(
            files=("m/model.pkl",),
            excludes=(ExcludePattern("m", ExcludeSource.IGNORE_FILE, ".guardanaignore"),),
            kept_models=(KeptModel("m/model.pkl", "m"),),
            skipped_models=SkippedModels((SkippedDirectory("build", 3),), searched_all=True),
        ),
        FileScope(files=("a.py",), skipped_models=SkippedModels(searched_all=False)),
    ],
    ids=["not a file run", "listed nothing", "unknown", "kept and skipped", "search cut short"],
)
def test_the_scope_survives_being_saved_and_read_back(
    scope: FileScope | None, tmp_path: Path
) -> None:
    saved = run_to_dict(replace(scan_result(), scope=scope), run_manifest())

    assert not _errors(saved)
    assert load_report(_write(saved, tmp_path)).result.scope == scope


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("kept_models", [{"path": "a.pkl"}]),
        ("kept_models", None),
        ("skipped_models", {"directories": [], "searched_all": "yes"}),
        ("skipped_models", {"directories": [{"path": "env", "model_files": 0}]}),
        (
            "skipped_models",
            {"directories": [{"path": "env", "model_files": 0}], "searched_all": True},
        ),
        ("excludes", [{"pattern": "*.pkl", "source": "ignore_file"}]),
        ("excludes", [{"pattern": "*.pkl", "source": "ignore_file", "file": 3}]),
    ],
    ids=[
        "kept without pattern",
        "kept null",
        "searched_all not a boolean",
        "searched_all missing",
        "a skipped directory counting nothing",
        "exclude without file",
        "exclude file not a string",
    ],
)
def test_the_loader_and_the_schema_refuse_the_same_malformed_scope(
    key: str, value: object, tmp_path: Path
) -> None:
    document = _document()
    document["scope"][key] = value

    assert _errors(document)
    with pytest.raises(ReportLoadError, match="scope"):
        load_report(_write(document, tmp_path))


def test_a_scope_without_the_new_keys_is_refused(tmp_path: Path) -> None:
    document = _document()
    del document["scope"]["kept_models"]

    assert _errors(document)
    with pytest.raises(ReportLoadError, match="kept_models"):
        load_report(_write(document, tmp_path))


def test_the_v17_schema_refuses_what_only_v18_writes() -> None:
    written = _document()
    written["schema_version"] = 17
    written["$schema"] = "https://guardana.dev/schemas/run/v17.schema.json"

    assert _errors(written, version=17)
    assert not _errors(saved_run_at_v17(_document()), version=17)


# Version 17 forward


def test_a_v17_run_migrates_with_nothing_kept_and_nothing_searched() -> None:
    migrated = migrate_v17(saved_run_at_v17(_document()))

    assert migrated["schema_version"] == 18
    assert migrated["$schema"] == "https://guardana.dev/schemas/run/v18.schema.json"
    assert not _errors(migrated)
    scope = migrated["scope"]
    assert scope["kept_models"] == []
    assert scope["skipped_models"] is None
    assert [e["file"] for e in scope["excludes"]] == [None, None, None]


def test_a_v17_run_without_a_scope_migrates_without_one() -> None:
    v17 = saved_run_at_v17(run_to_dict(replace(scan_result(), scope=None), run_manifest()))

    migrated = migrate_v17(v17)

    assert migrated["scope"] is None
    assert not _errors(migrated)


def test_a_v17_scope_whose_excludes_are_unknown_stays_unknown() -> None:
    unknown = FileScope(files=("a.py",), excludes=None)
    v17 = saved_run_at_v17(run_to_dict(replace(scan_result(), scope=unknown), run_manifest()))

    migrated = migrate_v17(v17)

    assert migrated["scope"]["excludes"] is None
    assert not _errors(migrated)


def test_the_migration_does_not_edit_the_document_it_was_handed() -> None:
    v17 = saved_run_at_v17(_document())
    before = copy.deepcopy(v17)

    migrate_v17(v17)

    assert v17 == before


@pytest.mark.parametrize("scope", [[], {"excludes": "*.pkl"}], ids=["a list", "excludes text"])
def test_a_v17_run_with_a_malformed_scope_is_refused(scope: object) -> None:
    v17 = saved_run_at_v17(_document())
    v17["scope"] = scope

    with pytest.raises(ManifestLoadError, match="scope"):
        migrate_v17(v17)


def test_a_loaded_v17_run_says_it_was_migrated(tmp_path: Path) -> None:
    report = load_report(_write(saved_run_at_v17(_document()), tmp_path))

    assert report.manifest.migrated_from == 17
    assert report.result.scope is not None
    assert report.result.scope.kept_models == ()
    assert report.result.scope.skipped_models is None


@pytest.mark.parametrize(
    ("version", "shape"),
    [
        (17, saved_run_at_v17),
        (16, saved_run_at_v16),
        (15, saved_run_at_v15),
        (14, saved_run_at_v14),
        (13, saved_run_at_v13),
        (12, saved_run_at_v12),
        (11, saved_run_at_v11),
        (10, saved_run_at_v10),
        (9, saved_run_at_v9),
    ],
    ids=["v17", "v16", "v15", "v14", "v13", "v12", "v11", "v10", "v9"],
)
def test_every_older_version_reaches_18_through_the_chain(
    version: int, shape: Callable[[dict[str, Any]], dict[str, Any]]
) -> None:
    migrated = migrate_forward(shape(_document()), version)

    assert migrated["schema_version"] == 18
    assert not _errors(migrated)
    scope = migrated["scope"]
    assert scope is None or (scope["kept_models"] == [] and scope["skipped_models"] is None)
