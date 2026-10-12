"""Run schema 17 records a rule the target does not offer and a run its target changed under.

A version-16 run arrives unchanged but for its version: no version-16 build wrote either
value, so there is nothing to carry or to fill.
"""

import copy
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from _documents import (
    run_manifest,
    saved_run_at_v16,
    saved_run_at_v17,
    scan_result,
)
from guardana.core.gate import StopReason
from guardana.core.manifest.load import ManifestLoadError, manifest_from_dict
from guardana.core.manifest.migrations import migrate_v16
from guardana.core.manifest.serialize import manifest_to_dict
from guardana.core.report import SkippedRule, SkipReason
from guardana.core.report.load import load_report
from guardana.core.report.serialize import run_to_dict
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _errors(document: dict[str, Any], version: int = 17) -> list[str]:
    """Validate `document` against a run schema, a current one in the shape version 17 wrote."""
    if document["schema_version"] == 18:
        document = saved_run_at_v17(document)
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


def _changed_under() -> dict[str, Any]:
    manifest = run_manifest()
    summary = replace(manifest.result_summary, stopped_by=StopReason.TARGET_CHANGED)
    return run_to_dict(
        replace(scan_result(), stopped_by=StopReason.TARGET_CHANGED),
        replace(manifest, result_summary=summary),
    )


# The document this build writes


def test_the_written_document_satisfies_the_v17_schema() -> None:
    assert not _errors(_document())


def test_a_not_offered_skip_is_written_and_read_back(tmp_path: Path) -> None:
    document = _document()

    report = load_report(_write(document, tmp_path))

    reasons = [s["reason"] for s in _run(document)["result_summary"]["rules_skipped"]]
    assert "not_offered" in reasons
    assert SkipReason.NOT_OFFERED in [s.reason for s in report.result.rules_skipped]
    assert (
        report.manifest.result_summary.rules_skipped == run_manifest().result_summary.rules_skipped
    )


def test_a_run_its_target_changed_under_is_written_and_read_back(tmp_path: Path) -> None:
    document = _changed_under()

    report = load_report(_write(document, tmp_path))

    assert not _errors(document)
    assert _run(document)["result_summary"]["stopped_by"] == "target_changed"
    assert report.result.stopped_by is StopReason.TARGET_CHANGED
    assert report.manifest.result_summary.stopped_by is StopReason.TARGET_CHANGED


@pytest.mark.parametrize("reason", list(SkipReason))
def test_every_skip_reason_survives_being_saved_and_read_back(
    reason: SkipReason, tmp_path: Path
) -> None:
    skipped = SkippedRule("acme.rule", reason, ("tasks",), "http://x#m: absent")
    manifest = run_manifest()
    summary = replace(manifest.result_summary, rules_skipped=(skipped,))
    saved = run_to_dict(
        replace(scan_result(), rules_skipped=(skipped,)), replace(manifest, result_summary=summary)
    )

    assert not _errors(saved)
    report = load_report(_write(saved, tmp_path))
    assert report.result.rules_skipped == (skipped,)
    assert report.manifest.result_summary.rules_skipped == (skipped,)


@pytest.mark.parametrize("reason", list(StopReason))
def test_every_stop_reason_survives_being_saved_and_read_back(
    reason: StopReason, tmp_path: Path
) -> None:
    manifest = run_manifest()
    summary = replace(manifest.result_summary, stopped_by=reason)
    saved = run_to_dict(
        replace(scan_result(), stopped_by=reason), replace(manifest, result_summary=summary)
    )

    assert not _errors(saved)
    assert load_report(_write(saved, tmp_path)).result.stopped_by is reason


def test_the_v16_schema_refuses_what_only_v17_writes() -> None:
    not_offered = saved_run_at_v16(_document())
    _run(not_offered)["result_summary"]["rules_skipped"].append(
        {"rule_id": "acme.rule", "reason": "not_offered", "missing": [], "detail": "d"}
    )
    changed = saved_run_at_v16(_changed_under())

    for document in (not_offered, changed):
        assert _errors(document, version=16)
    assert not _errors(saved_run_at_v16(_document()), version=16)


def test_the_loader_refuses_a_skip_reason_this_build_does_not_know() -> None:
    document = _document()
    _run(document)["result_summary"]["rules_skipped"][0]["reason"] = "not_supported"

    with pytest.raises(ManifestLoadError):
        manifest_from_dict(_run(document))
    assert _errors(document)


def test_a_summary_that_records_the_changed_target_reads_back_unchanged() -> None:
    manifest = run_manifest()
    summary = replace(manifest.result_summary, stopped_by=StopReason.TARGET_CHANGED)
    changed = replace(manifest, result_summary=summary)

    assert manifest_from_dict(manifest_to_dict(changed)) == changed


# Version 16 forward


def test_a_v16_run_migrates_to_17_moving_only_its_version() -> None:
    v16 = saved_run_at_v16(_document())

    migrated = migrate_v16(v16)

    assert migrated["schema_version"] == 17
    assert migrated["$schema"] == "https://guardana.dev/schemas/run/v17.schema.json"
    assert not _errors(migrated)
    assert {k: v for k, v in migrated.items() if k not in {"schema_version", "$schema"}} == {
        k: v for k, v in v16.items() if k not in {"schema_version", "$schema"}
    }


def test_the_migration_does_not_edit_the_document_it_was_handed() -> None:
    v16 = saved_run_at_v16(_document())
    before = copy.deepcopy(v16)

    migrated = migrate_v16(v16)

    assert v16 == before
    assert saved_run_at_v16(migrated) == v16


def test_a_v16_run_without_a_run_block_is_refused() -> None:
    v16 = saved_run_at_v16(_document())
    del v16["run"]

    with pytest.raises(ManifestLoadError, match="run"):
        migrate_v16(v16)


def test_a_loaded_v16_run_says_it_was_migrated(tmp_path: Path) -> None:
    report = load_report(_write(saved_run_at_v16(_document()), tmp_path))

    assert report.manifest.migrated_from == 16
    assert SkipReason.NOT_OFFERED not in [s.reason for s in report.result.rules_skipped]
