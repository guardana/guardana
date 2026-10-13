"""Run schema 14 records the recipe a run was started from and the provider wire it spoke.

Three new facts: the recipe and what it declared answered (`run.recipe`), the provider
(`run.configuration.provider`) and the `incomplete_recording` shortfall kind. A
version-13 run arrives with the first two null, which is unknown, never "no recipe" or
"the OpenAI wire".
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
    saved_run_at_v13,
    saved_run_at_v14,
    scan_result,
)
from guardana.core.manifest import RecipeRecord, SubjectKind, SubjectSource
from guardana.core.manifest.load import ManifestLoadError, manifest_from_dict
from guardana.core.manifest.migrations import migrate_v13
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.report.load import load_report
from guardana.core.report.serialize import run_to_dict
from guardana.core.report.shortfall import ShortfallKind
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"
_RECIPE = "sha256:" + "ab" * 32
_LOCK = "sha256:" + "cd" * 32


def _errors(document: dict[str, Any], version: int = 14) -> list[str]:
    """Validate `document` against a run schema, a current one in the shape version 14 wrote."""
    if document["schema_version"] == 18:
        document = saved_run_at_v14(document)
    schema = json.loads((_SCHEMAS / f"run-v{version}.schema.json").read_text(encoding="utf-8"))
    return [error.message for error in Draft202012Validator(schema).iter_errors(document)]


def _document() -> dict[str, Any]:
    return run_to_dict(scan_result(), run_manifest())


def _write(document: dict[str, Any], tmp_path: Path) -> Path:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _run(document: dict[str, Any]) -> dict[str, Any]:
    run: dict[str, Any] = document["run"]
    return run


# The document this build writes


def test_the_written_document_satisfies_the_v14_schema() -> None:
    assert not _errors(_document())


def test_every_new_field_is_written() -> None:
    run = _run(_document())

    assert run["recipe"] == {
        "name": "checkout-assistant",
        "digest": _RECIPE,
        "lock_digest": _LOCK,
        "kind": "model_harness",
        "source": "recording",
        "unpinned": ["acme.local.tone"],
    }
    assert run["configuration"]["provider"] == "ollama"
    assert "incomplete_recording" in [gap["kind"] for gap in run["coverage"]["shortfall"]]


def test_every_new_field_survives_being_saved_and_read_back(tmp_path: Path) -> None:
    manifest = run_manifest()

    report = load_report(_write(run_to_dict(scan_result(), manifest), tmp_path))

    assert report.manifest.recipe == manifest.recipe
    assert report.manifest.configuration.provider == "ollama"
    assert report.manifest.coverage.shortfall == manifest.coverage.shortfall


@pytest.mark.parametrize(
    ("recipe", "provider"),
    [
        (None, None),
        (
            RecipeRecord(
                name="r",
                digest=_RECIPE,
                lock_digest=None,
                kind=SubjectKind.APPLICATION,
                source=SubjectSource.CONNECTION,
            ),
            "openai",
        ),
    ],
    ids=["no recipe, no provider", "unlocked application recipe"],
)
def test_the_subject_survives_being_saved_and_read_back(
    recipe: RecipeRecord | None, provider: str | None
) -> None:
    manifest = run_manifest()
    manifest = replace(
        manifest,
        recipe=recipe,
        configuration=replace(manifest.configuration, provider=provider),
    )

    assert not _errors(run_to_dict(scan_result(), manifest))
    assert manifest_from_dict(manifest_to_dict(manifest)) == manifest


def test_the_v13_schema_refuses_a_shortfall_kind_only_v14_writes() -> None:
    document = saved_run_at_v13(_document())
    _run(document)["coverage"]["shortfall"].append(
        {"kind": str(ShortfallKind.INCOMPLETE_RECORDING), "name": "r", "detail": "d"}
    )

    assert _errors(document, version=13)


# The records refuse what no run produces


@pytest.mark.parametrize(
    ("digest", "lock_digest"),
    [
        ("sha256:" + "ab" * 31, None),
        ("ab" * 32, None),
        (_RECIPE, "sha256:" + "CD" * 32),
        (_RECIPE, ""),
    ],
    ids=["short", "no algorithm", "lock upper case", "lock empty"],
)
def test_a_recipe_record_refuses_a_digest_no_reader_produced(
    digest: str, lock_digest: str | None
) -> None:
    with pytest.raises(ValueError, match="digest"):
        RecipeRecord(
            name="r",
            digest=digest,
            lock_digest=lock_digest,
            kind=SubjectKind.APPLICATION,
            source=SubjectSource.CONNECTION,
        )


def test_a_recipe_record_refuses_a_kind_nobody_declares() -> None:
    with pytest.raises(TypeError, match="kind"):
        RecipeRecord(
            name="r",
            digest=_RECIPE,
            lock_digest=None,
            kind="application",  # type: ignore[arg-type]
            source=SubjectSource.CONNECTION,
        )


_RUN_BREAKAGES: dict[str, Callable[[dict[str, Any]], None]] = {
    "recipe missing": lambda run: run.pop("recipe"),
    "recipe not an object": lambda run: run.update(recipe="checkout"),
    "recipe unknown key": lambda run: run["recipe"].update(subject="checkout"),
    "recipe name missing": lambda run: run["recipe"].pop("name"),
    "recipe lock digest missing": lambda run: run["recipe"].pop("lock_digest"),
    "recipe digest bare hex": lambda run: run["recipe"].update(digest="ab" * 32),
    "recipe digest null": lambda run: run["recipe"].update(digest=None),
    "recipe kind unknown": lambda run: run["recipe"].update(kind="model"),
    "recipe source unknown": lambda run: run["recipe"].update(source="replay"),
    "recipe unpinned not a list": lambda run: run["recipe"].update(unpinned="acme.x"),
    "recipe unpinned holds a number": lambda run: run["recipe"].update(unpinned=[1]),
    "provider missing": lambda run: run["configuration"].pop("provider"),
    "provider not a string": lambda run: run["configuration"].update(provider=1),
    "shortfall kind unknown": lambda run: run["coverage"]["shortfall"][1].update(
        kind="stopped_recording"
    ),
}


@pytest.mark.parametrize("breakage", _RUN_BREAKAGES)
def test_the_loader_and_the_schema_refuse_the_same_malformed_run_block(breakage: str) -> None:
    document = _document()
    _RUN_BREAKAGES[breakage](_run(document))

    with pytest.raises(ManifestLoadError):
        manifest_from_dict(document["run"])
    assert _errors(document), f"the v14 schema accepts {breakage}, which the loader refuses"


# Version 13 forward


def test_a_v13_run_migrates_to_14_with_every_new_field_unknown() -> None:
    v13 = saved_run_at_v13(_document())

    migrated = migrate_v13(v13)

    assert migrated["schema_version"] == 14
    assert migrated["$schema"] == "https://guardana.dev/schemas/run/v14.schema.json"
    assert not _errors(migrated)
    assert _run(migrated)["recipe"] is None
    assert _run(migrated)["configuration"]["provider"] is None


def test_the_migration_overwrites_what_a_v13_run_should_not_hold() -> None:
    v13 = saved_run_at_v13(_document())
    written = _run(_document())
    _run(v13)["recipe"] = written["recipe"]
    _run(v13)["configuration"]["provider"] = "ollama"

    migrated = migrate_v13(v13)

    assert _run(migrated)["recipe"] is None
    assert _run(migrated)["configuration"]["provider"] is None


def test_the_migration_recomputes_nothing_else() -> None:
    v13 = saved_run_at_v13(_document())
    before = copy.deepcopy(v13)

    migrated = migrate_v13(v13)

    assert v13 == before, "the migration must not edit the document it was handed"
    assert saved_run_at_v13(migrated) == v13


def test_a_loaded_v13_run_says_it_was_migrated_and_records_no_subject(tmp_path: Path) -> None:
    report = load_report(_write(saved_run_at_v13(_document()), tmp_path))

    assert report.manifest.migrated_from == 13
    assert report.manifest.recipe is None
    assert report.manifest.configuration.provider is None
