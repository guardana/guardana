"""Run schema 16 records a run its target stopped, two shortfall kinds, a case the application
declined, a recipe that named an installed target and the pace requests were held to.

A version-15 run arrives with `execution.max_requests_per_minute` null: no version-15 build
paced its requests, so the run set no rate.
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
    saved_run_at_v15,
    saved_run_at_v16,
    scan_result,
)
from guardana.core.assessment import Assessment, AssessmentStatus, UnmeasuredReason
from guardana.core.gate import StopReason
from guardana.core.manifest import SubjectSource
from guardana.core.manifest.load import ManifestLoadError, manifest_from_dict
from guardana.core.manifest.migrations import migrate_v15
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.manifest.summary import summarize
from guardana.core.report.load import load_report
from guardana.core.report.serialize import run_to_dict
from guardana.core.report.shortfall import ShortfallKind
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _errors(document: dict[str, Any], version: int = 16) -> list[str]:
    """Validate `document` against a run schema, a current one in the shape version 16 wrote."""
    if document["schema_version"] == 18:
        document = saved_run_at_v16(document)
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


def _stopped_by_its_target() -> dict[str, Any]:
    manifest = run_manifest()
    summary = replace(manifest.result_summary, stopped_by=StopReason.TARGET_UNAVAILABLE)
    return run_to_dict(
        replace(scan_result(), stopped_by=StopReason.TARGET_UNAVAILABLE),
        replace(manifest, result_summary=summary),
    )


def _declined_by_the_application() -> dict[str, Any]:
    declined = Assessment(
        case_id="guardana.prompt.jailbreak#9a8b7c6d5e4f",
        assessor="keyword",
        subject_ref="http://model.invalid/v1",
        status=AssessmentStatus.INCONCLUSIVE,
        rule_id="guardana.prompt.jailbreak",
        trial=1,
        reason=UnmeasuredReason.TARGET_DECLINED,
        tags=("declined:content_filter",),
    )
    result = replace(scan_result(), assessments=(*scan_result().assessments, declined))
    manifest = run_manifest()
    summary = summarize(result, manifest.result_summary.gate)
    return run_to_dict(result, replace(manifest, result_summary=summary))


def _from_a_target() -> dict[str, Any]:
    manifest = run_manifest()
    recipe = manifest.recipe
    if recipe is None:
        raise AssertionError("the shared manifest must carry a recipe")
    return run_to_dict(
        scan_result(), replace(manifest, recipe=replace(recipe, source=SubjectSource.TARGET))
    )


# The document this build writes


def test_the_written_document_satisfies_the_v16_schema() -> None:
    assert not _errors(_document())


def test_the_rate_and_the_new_shortfall_kinds_are_written() -> None:
    run = _run(_document())

    assert run["execution"]["max_requests_per_minute"] == 30
    kinds = [gap["kind"] for gap in run["coverage"]["shortfall"]]
    assert "empty_target" in kinds
    assert "ungraded_cases" in kinds


def test_every_new_field_survives_being_saved_and_read_back(tmp_path: Path) -> None:
    manifest = run_manifest()

    report = load_report(_write(run_to_dict(scan_result(), manifest), tmp_path))

    assert report.manifest.execution == manifest.execution
    assert report.manifest.coverage.shortfall == manifest.coverage.shortfall


@pytest.mark.parametrize("rate", [None, 1, 600], ids=["none", "one", "six hundred"])
def test_the_rate_survives_being_saved_and_read_back(rate: int | None) -> None:
    manifest = run_manifest()
    paced = replace(manifest, execution=replace(manifest.execution, max_requests_per_minute=rate))

    assert not _errors(run_to_dict(scan_result(), paced))
    assert manifest_from_dict(manifest_to_dict(paced)) == paced


def test_a_run_its_target_stopped_is_written_and_read_back(tmp_path: Path) -> None:
    document = _stopped_by_its_target()

    report = load_report(_write(document, tmp_path))

    assert not _errors(document)
    assert _run(document)["result_summary"]["stopped_by"] == "target_unavailable"
    assert report.result.stopped_by is StopReason.TARGET_UNAVAILABLE
    assert report.manifest.result_summary.stopped_by is StopReason.TARGET_UNAVAILABLE


def test_a_case_the_application_declined_is_written_and_read_back(tmp_path: Path) -> None:
    document = _declined_by_the_application()

    report = load_report(_write(document, tmp_path))

    assert not _errors(document)
    assert "target_declined" in [a["reason"] for a in document["assessments"]]
    assert UnmeasuredReason.TARGET_DECLINED in [a.reason for a in report.result.assessments]


@pytest.mark.parametrize("reason", list(UnmeasuredReason))
def test_every_unmeasured_reason_survives_being_saved_and_read_back(
    reason: UnmeasuredReason, tmp_path: Path
) -> None:
    result = scan_result()
    changed = replace(result.assessments[-1], reason=reason)
    saved = run_to_dict(replace(result, assessments=(changed,)), run_manifest())

    assert not _errors(saved)
    assert load_report(_write(saved, tmp_path)).result.assessments == (changed,)


_V16_STOPS = (StopReason.BUDGET_EXHAUSTED, StopReason.INTERRUPTED, StopReason.TARGET_UNAVAILABLE)


@pytest.mark.parametrize("reason", _V16_STOPS)
def test_every_v16_stop_reason_survives_being_saved_and_read_back(
    reason: StopReason, tmp_path: Path
) -> None:
    manifest = run_manifest()
    summary = replace(manifest.result_summary, stopped_by=reason)
    saved = run_to_dict(
        replace(scan_result(), stopped_by=reason), replace(manifest, result_summary=summary)
    )

    assert not _errors(saved)
    assert load_report(_write(saved, tmp_path)).result.stopped_by is reason


@pytest.mark.parametrize("kind", list(ShortfallKind))
def test_every_shortfall_kind_is_one_the_schema_accepts(kind: ShortfallKind) -> None:
    document = _document()
    _run(document)["coverage"]["shortfall"] = [{"kind": str(kind), "name": "n", "detail": "d"}]

    assert not _errors(document)


def test_a_recipe_that_named_a_target_is_written_and_read_back(tmp_path: Path) -> None:
    document = _from_a_target()

    report = load_report(_write(document, tmp_path))

    assert not _errors(document)
    assert _run(document)["recipe"]["source"] == "target"
    recipe = report.manifest.recipe
    assert recipe is not None
    assert recipe.source is SubjectSource.TARGET


def test_the_v15_schema_refuses_what_only_v16_writes() -> None:
    rated = saved_run_at_v15(_document())
    _run(rated)["execution"]["max_requests_per_minute"] = 30
    empty = saved_run_at_v15(_document())
    _run(empty)["coverage"]["shortfall"].append(
        {"kind": str(ShortfallKind.EMPTY_TARGET), "name": "n", "detail": "d"}
    )
    ungraded = saved_run_at_v15(_document())
    _run(ungraded)["coverage"]["shortfall"].append(
        {"kind": str(ShortfallKind.UNGRADED_CASES), "name": "n", "detail": "d"}
    )
    stopped = saved_run_at_v15(_stopped_by_its_target())
    declined = saved_run_at_v15(_declined_by_the_application())
    from_a_target = saved_run_at_v15(_from_a_target())

    for document in (rated, empty, ungraded, stopped, declined, from_a_target):
        assert _errors(document, version=15)
    assert not _errors(saved_run_at_v15(_document()), version=15)


# The record refuses what no run produces


_RATE_BREAKAGES: dict[str, Callable[[dict[str, Any]], None]] = {
    "rate missing": lambda execution: execution.pop("max_requests_per_minute"),
    "rate zero": lambda execution: execution.update(max_requests_per_minute=0),
    "rate a string": lambda execution: execution.update(max_requests_per_minute="30"),
    "rate a fraction": lambda execution: execution.update(max_requests_per_minute=1.5),
}


@pytest.mark.parametrize("breakage", _RATE_BREAKAGES)
def test_the_schema_refuses_a_malformed_rate(breakage: str) -> None:
    document = _document()
    _RATE_BREAKAGES[breakage](_run(document)["execution"])

    assert _errors(document), f"the v16 schema accepts {breakage}"


@pytest.mark.parametrize(
    ("where", "value"),
    [("stopped_by", "target_gone"), ("source", "socket")],
    ids=["stop reason", "recipe source"],
)
def test_the_loader_refuses_a_value_this_build_does_not_know(where: str, value: str) -> None:
    document = _document()
    run = _run(document)
    if where == "stopped_by":
        run["result_summary"]["stopped_by"] = value
    else:
        run["recipe"]["source"] = value

    with pytest.raises(ManifestLoadError):
        manifest_from_dict(run)
    assert _errors(document)


# Version 15 forward


def test_a_v15_run_migrates_to_16_with_no_rate() -> None:
    migrated = migrate_v15(saved_run_at_v15(_document()))

    assert migrated["schema_version"] == 16
    assert migrated["$schema"] == "https://guardana.dev/schemas/run/v16.schema.json"
    assert not _errors(migrated)
    assert _run(migrated)["execution"]["max_requests_per_minute"] is None


def test_the_migration_overwrites_a_rate_a_v15_run_should_not_hold() -> None:
    v15 = saved_run_at_v15(_document())
    _run(v15)["execution"]["max_requests_per_minute"] = 30

    assert _run(migrate_v15(v15))["execution"]["max_requests_per_minute"] is None


def test_the_migration_recomputes_nothing_else() -> None:
    v15 = saved_run_at_v15(_document())
    before = copy.deepcopy(v15)

    migrated = migrate_v15(v15)

    assert v15 == before, "the migration must not edit the document it was handed"
    assert saved_run_at_v15(migrated) == v15


def test_a_v15_run_without_an_execution_block_is_refused() -> None:
    v15 = saved_run_at_v15(_document())
    del _run(v15)["execution"]

    with pytest.raises(ManifestLoadError, match="execution"):
        migrate_v15(v15)


def test_a_loaded_v15_run_says_it_was_migrated_and_records_no_rate(tmp_path: Path) -> None:
    report = load_report(_write(saved_run_at_v15(_document()), tmp_path))

    assert report.manifest.migrated_from == 15
    assert report.manifest.execution.max_requests_per_minute is None


def test_a_summary_that_records_the_target_stop_reads_back_unchanged() -> None:
    manifest = run_manifest()
    summary = replace(manifest.result_summary, stopped_by=StopReason.TARGET_UNAVAILABLE)
    stopped = replace(manifest, result_summary=summary)

    assert manifest_from_dict(manifest_to_dict(stopped)) == stopped
