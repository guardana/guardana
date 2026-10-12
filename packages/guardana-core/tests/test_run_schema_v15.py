"""Run schema 15 records the fixtures file a run was given, the `seed_not_reached` shortfall
and whether each evaluator is deterministic.

A version-14 run arrives with `fixtures` null: no version-14 build took a fixtures file,
so the run was given none. Its evaluators arrive not deterministic, as an evaluator that
says nothing is read.
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
    saved_run_at_v14,
    saved_run_at_v15,
    scan_result,
)
from guardana.core.manifest import EvaluatorRecord, FixturesRecord
from guardana.core.manifest.load import ManifestLoadError, manifest_from_dict
from guardana.core.manifest.migrations import migrate_v14
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.report.load import load_report
from guardana.core.report.serialize import run_to_dict
from guardana.core.report.shortfall import ShortfallKind
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"
_DIGEST = "sha256:" + "fe" * 32


def _errors(document: dict[str, Any], version: int = 15) -> list[str]:
    """Validate `document` against a run schema, a current one in the shape version 15 wrote."""
    if document["schema_version"] == 18:
        document = saved_run_at_v15(document)
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


_RECORD = FixturesRecord(
    name="support-bot",
    digest=_DIGEST,
    data="synthetic",
    tenants=("acme", "globex"),
    documents=3,
    records=2,
    tools=4,
    markers=1,
)


# The document this build writes


def test_the_written_document_satisfies_the_v15_schema() -> None:
    assert not _errors(_document())


def test_the_fixtures_are_written_with_data_labelled_declared() -> None:
    run = _run(_document())

    assert run["fixtures"] == {
        "name": "support-bot",
        "digest": _DIGEST,
        "data": {"declared": "synthetic"},
        "tenants": ["acme", "globex"],
        "counts": {"documents": 3, "records": 2, "tools": 4},
        "markers": 1,
    }
    assert "seed_not_reached" in [gap["kind"] for gap in run["coverage"]["shortfall"]]


def test_every_new_field_survives_being_saved_and_read_back(tmp_path: Path) -> None:
    manifest = run_manifest()

    report = load_report(_write(run_to_dict(scan_result(), manifest), tmp_path))

    assert report.manifest.fixtures == manifest.fixtures
    assert report.manifest.coverage.shortfall == manifest.coverage.shortfall


@pytest.mark.parametrize(
    "fixtures", [None, replace(_RECORD, documents=0, tools=0)], ids=["none", "records only"]
)
def test_the_fixtures_survive_being_saved_and_read_back(fixtures: FixturesRecord | None) -> None:
    manifest = replace(run_manifest(), fixtures=fixtures)

    assert not _errors(run_to_dict(scan_result(), manifest))
    assert manifest_from_dict(manifest_to_dict(manifest)) == manifest


def test_the_v14_schema_refuses_what_only_v15_writes() -> None:
    document = saved_run_at_v14(_document())
    _run(document)["coverage"]["shortfall"].append(
        {"kind": str(ShortfallKind.SEED_NOT_REACHED), "name": "n", "detail": "d"}
    )
    with_fixtures = saved_run_at_v14(_document())
    _run(with_fixtures)["fixtures"] = _run(_document())["fixtures"]

    assert _errors(document, version=14)
    assert _errors(with_fixtures, version=14)


# The record refuses what no run produces


@pytest.mark.parametrize(
    "changes",
    [
        {"digest": "fe" * 32},
        {"tenants": ("acme",)},
        {"tenants": ("acme", "acme")},
        {"documents": -1},
        {"tools": True},
        {"markers": 0},
        {"data": " "},
    ],
    ids=[
        "bare digest",
        "one tenant",
        "a tenant twice",
        "negative count",
        "count a boolean",
        "no algorithm",
        "blank data",
    ],
)
def test_a_fixtures_record_refuses_what_no_fixtures_file_declares(
    changes: dict[str, Any],
) -> None:
    with pytest.raises((TypeError, ValueError), match=r"\w"):
        replace(_RECORD, **changes)


_RUN_BREAKAGES: dict[str, Callable[[dict[str, Any]], None]] = {
    "fixtures missing": lambda run: run.pop("fixtures"),
    "fixtures not an object": lambda run: run.update(fixtures="support-bot"),
    "fixtures unknown key": lambda run: run["fixtures"].update(verified=True),
    "fixtures name missing": lambda run: run["fixtures"].pop("name"),
    "fixtures digest bare hex": lambda run: run["fixtures"].update(digest="fe" * 32),
    "fixtures data a bare string": lambda run: run["fixtures"].update(data="synthetic"),
    "fixtures data unknown key": lambda run: run["fixtures"]["data"].update(verified=True),
    "fixtures one tenant": lambda run: run["fixtures"].update(tenants=["acme"]),
    "fixtures tenants hold a number": lambda run: run["fixtures"].update(tenants=["acme", 1]),
    "fixtures counts missing tools": lambda run: run["fixtures"]["counts"].pop("tools"),
    "fixtures count negative": lambda run: run["fixtures"]["counts"].update(records=-1),
    "fixtures markers missing": lambda run: run["fixtures"].pop("markers"),
    "fixtures markers zero": lambda run: run["fixtures"].update(markers=0),
}


def test_whether_an_evaluator_is_deterministic_survives_being_saved_and_read_back() -> None:
    manifest = run_manifest()
    deterministic = replace(
        manifest,
        evaluators=(
            *manifest.evaluators,
            EvaluatorRecord(id="tools_called", version="1", deterministic=True),
        ),
    )

    written = run_to_dict(scan_result(), deterministic)

    assert not _errors(written)
    assert [e["deterministic"] for e in _run(written)["evaluators"]] == [False, True]
    assert manifest_from_dict(manifest_to_dict(deterministic)) == deterministic


_EVALUATOR_BREAKAGES: dict[str, Callable[[dict[str, Any]], None]] = {
    "deterministic missing": lambda evaluator: evaluator.pop("deterministic"),
    "deterministic a string": lambda evaluator: evaluator.update(deterministic="yes"),
    "deterministic null": lambda evaluator: evaluator.update(deterministic=None),
}


@pytest.mark.parametrize("breakage", _EVALUATOR_BREAKAGES)
def test_the_loader_and_the_schema_refuse_the_same_malformed_deterministic_field(
    breakage: str,
) -> None:
    document = _document()
    _EVALUATOR_BREAKAGES[breakage](_run(document)["evaluators"][0])

    with pytest.raises(ManifestLoadError, match="deterministic"):
        manifest_from_dict(document["run"])
    assert _errors(document), f"the v15 schema accepts {breakage}, which the loader refuses"


def test_a_v14_run_reads_every_evaluator_as_not_deterministic() -> None:
    """No version-14 build recorded it, and a judge is what an evaluator that says nothing is."""
    v14 = saved_run_at_v14(_document())

    migrated = migrate_v14(v14)

    assert all("deterministic" not in e for e in _run(v14)["evaluators"])
    assert [e["deterministic"] for e in _run(migrated)["evaluators"]] == [False]


@pytest.mark.parametrize("breakage", _RUN_BREAKAGES)
def test_the_loader_and_the_schema_refuse_the_same_malformed_fixtures_block(
    breakage: str,
) -> None:
    document = _document()
    _RUN_BREAKAGES[breakage](_run(document))

    with pytest.raises(ManifestLoadError):
        manifest_from_dict(document["run"])
    assert _errors(document), f"the v15 schema accepts {breakage}, which the loader refuses"


# Version 14 forward


def test_a_v14_run_migrates_to_15_given_no_fixtures() -> None:
    migrated = migrate_v14(saved_run_at_v14(_document()))

    assert migrated["schema_version"] == 15
    assert migrated["$schema"] == "https://guardana.dev/schemas/run/v15.schema.json"
    assert not _errors(migrated)
    assert _run(migrated)["fixtures"] is None


def test_the_migration_overwrites_fixtures_a_v14_run_should_not_hold() -> None:
    v14 = saved_run_at_v14(_document())
    _run(v14)["fixtures"] = _run(_document())["fixtures"]

    assert _run(migrate_v14(v14))["fixtures"] is None


def test_the_migration_recomputes_nothing_else() -> None:
    v14 = saved_run_at_v14(_document())
    before = copy.deepcopy(v14)

    migrated = migrate_v14(v14)

    assert v14 == before, "the migration must not edit the document it was handed"
    assert saved_run_at_v14(migrated) == v14


def test_a_loaded_v14_run_says_it_was_migrated_and_records_no_fixtures(tmp_path: Path) -> None:
    report = load_report(_write(saved_run_at_v14(_document()), tmp_path))

    assert report.manifest.migrated_from == 14
    assert report.manifest.fixtures is None
