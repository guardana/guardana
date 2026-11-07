"""Run schema 19 spells every relative file path with `/`, whichever platform wrote the run.

A version-18 run written on Windows named a file `model\\weights.pkl`; it arrives as
`model/weights.pkl`, so it names, fingerprints and compares a file as a run written
anywhere else does. Nothing that is not such a relative path changes.
"""

import copy
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from _documents import (
    counted,
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
    saved_run_at_v18,
    scan_result,
)
from guardana.core.diff import compare_reports
from guardana.core.fingerprint import digest_of
from guardana.core.manifest.identity import TargetIdentity
from guardana.core.manifest.load import ManifestLoadError
from guardana.core.manifest.migrations import migrate_v18
from guardana.core.observation import Observation, ObservationKind
from guardana.core.report.finding import Evidence, Finding
from guardana.core.report.load import load_report, migrate_forward
from guardana.core.report.result import ScanResult
from guardana.core.report.serialize import run_to_dict
from guardana.core.report.shortfall import CoverageShortfall, ShortfallKind
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
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
_RULE = "guardana.supply_chain.pickle"
_ROOT = "models\\llama"


def _errors(document: dict[str, Any], version: int = 19) -> list[str]:
    schema = json.loads((_SCHEMAS / f"run-v{version}.schema.json").read_text(encoding="utf-8"))
    return [error.message for error in Draft202012Validator(schema).iter_errors(document)]


def _document() -> dict[str, Any]:
    return run_to_dict(scan_result(), run_manifest())


def _write(document: dict[str, Any], tmp_path: Path, name: str = "run.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _finding(ref: str, summary: str = "pickle calls os.system") -> Finding:
    return Finding(_RULE, Severity.HIGH, "pickle", (), ref, Evidence(summary=summary))


def _target(ref: str, fingerprint: str | None = None) -> TargetIdentity:
    return TargetIdentity(
        kind=TargetKind.ARTIFACT,
        ref=ref,
        fingerprint=digest_of(str(TargetKind.ARTIFACT), ref)
        if fingerprint is None
        else fingerprint,
        fingerprint_inputs=("kind", "ref"),
    )


def _windows_run(target: TargetIdentity | None = None) -> dict[str, Any]:
    """A version-18 run as a Windows build wrote it: every relative path spelled with `\\`."""
    result = replace(
        scan_result(),
        findings=(_finding("model\\weights.pkl:3"),),
        unverified=(_finding("dir\\a.zip:inner\\x.pkl", "could not parse"),),
        waived=(
            _finding("C:\\m\\w.pkl", "drive"),
            _finding("\\\\srv\\share\\w.pkl", "unc"),
            _finding("http://h#m", "endpoint"),
            _finding("already/posix\\name.pkl:1", "mixed"),
        ),
        observations=(
            Observation(ObservationKind.MODEL, "weights", "model\\weights.pkl", {}),
            Observation(ObservationKind.MODEL, "remote", "http://h#m", {}),
        ),
        coverage_shortfall=(
            CoverageShortfall(ShortfallKind.UNEXAMINED_COMPONENT, "dir\\b.onnx", "unread"),
            CoverageShortfall(ShortfallKind.MISSING_DIMENSION, "a\\b", "a label"),
        ),
        scope=FileScope(
            files=("model\\weights.pkl", "dir\\a.zip", "C:\\m\\w.pkl"),
            excludes=(
                ExcludePattern("build/*", ExcludeSource.PROFILE),
                ExcludePattern("*.bak", ExcludeSource.IGNORE_FILE, "sub\\.guardanaignore"),
            ),
            kept_models=(KeptModel("model\\old.pkl", "*.pkl"),),
            skipped_models=SkippedModels((SkippedDirectory("pkg\\env", 2),), searched_all=True),
        ),
    )
    manifest = run_manifest()
    manifest = replace(
        manifest,
        target=target or _target(_ROOT),
        coverage=replace(manifest.coverage, shortfall=result.coverage_shortfall),
    )
    return saved_run_at_v18(run_to_dict(result, counted(manifest, result)))


# The document this build writes


def test_the_written_document_satisfies_the_v19_schema() -> None:
    assert not _errors(_document())


def test_the_v18_schema_refuses_only_the_version_v19_writes() -> None:
    assert _errors(_document(), version=18)
    assert not _errors(saved_run_at_v18(_document()), version=18)


# Version 18 forward


def test_a_windows_v18_run_names_every_relative_file_with_slashes(tmp_path: Path) -> None:
    report = load_report(_write(_windows_run(), tmp_path))
    result = report.result

    assert report.manifest.migrated_from == 18
    assert [f.target_ref for f in result.findings] == ["model/weights.pkl:3"]
    assert [f.target_ref for f in result.unverified] == ["dir/a.zip:inner/x.pkl"]
    assert [o.ref for o in result.observations] == ["model/weights.pkl", "http://h#m"]
    scope = result.scope
    assert scope is not None
    assert scope.files == ("model/weights.pkl", "dir/a.zip", "C:\\m\\w.pkl")
    assert scope.excludes is not None
    assert [e.file for e in scope.excludes] == [None, "sub/.guardanaignore"]
    assert [k.path for k in scope.kept_models] == ["model/old.pkl"]
    assert scope.skipped_models is not None
    assert [d.path for d in scope.skipped_models.directories] == ["pkg/env"]
    assert [g.name for g in result.coverage_shortfall] == ["dir/b.onnx", "a\\b"]
    assert report.manifest.target.ref == "models/llama"
    assert report.manifest.target.fingerprint == digest_of("artifact", "models/llama")


def test_a_drive_absolute_unc_endpoint_or_slashed_ref_keeps_its_form(tmp_path: Path) -> None:
    result = load_report(_write(_windows_run(), tmp_path)).result

    assert [f.target_ref for f in result.waived] == [
        "C:\\m\\w.pkl",
        "\\\\srv\\share\\w.pkl",
        "http://h#m",
        "already/posix\\name.pkl:1",
    ]


def test_the_migrated_document_satisfies_the_v19_schema() -> None:
    migrated = migrate_v18(_windows_run())

    assert migrated["schema_version"] == 19
    assert migrated["$schema"] == "https://guardana.dev/schemas/run/v19.schema.json"
    assert not _errors(migrated)


def test_a_target_fingerprint_not_taken_over_the_old_ref_is_kept() -> None:
    migrated = migrate_v18(_windows_run(_target(_ROOT, fingerprint="sha256:" + "9" * 64)))

    target = migrated["run"]["target"]
    assert target["ref"] == "models/llama"
    assert target["fingerprint"] == "sha256:" + "9" * 64


def test_a_target_fingerprint_over_other_inputs_is_kept() -> None:
    other = replace(_target(_ROOT), fingerprint_inputs=("kind", "ref", "weights"))

    migrated = migrate_v18(_windows_run(other))

    assert migrated["run"]["target"]["fingerprint"] == digest_of("artifact", _ROOT)


def test_a_run_written_with_slashes_migrates_unchanged_but_for_its_version() -> None:
    written = _document()

    migrated = migrate_v18(saved_run_at_v18(written))

    assert migrated == written


def test_the_migration_does_not_edit_the_document_it_was_handed() -> None:
    v18 = _windows_run()
    before = copy.deepcopy(v18)

    migrate_v18(v18)

    assert v18 == before


@pytest.mark.parametrize(
    ("key", "value"),
    [("findings", {"target_ref": "a\\b"}), ("observations", ["a\\b"]), ("scope", [])],
    ids=["findings not a list", "an observation not an object", "scope not an object"],
)
def test_a_v18_run_with_a_malformed_channel_is_refused(key: str, value: object) -> None:
    v18 = _windows_run()
    v18[key] = value

    with pytest.raises(ManifestLoadError, match=key):
        migrate_v18(v18)


@pytest.mark.parametrize(
    ("kind", "ref", "rewritten"),
    [
        (TargetKind.ENDPOINT, "corp\\svc", "corp\\svc"),
        (TargetKind.ARTIFACT, "models\\llama", "models/llama"),
        (TargetKind.TRACE, "runs\\t.jsonl#abc", "runs/t.jsonl#abc"),
    ],
    ids=["a-label-stays", "a-file-target-moves", "a-trace-source-moves"],
)
def test_only_a_run_over_files_or_a_trace_is_rewritten(
    kind: TargetKind, ref: str, rewritten: str
) -> None:
    target = TargetIdentity(
        kind=kind,
        ref=ref,
        fingerprint=digest_of(str(kind), ref),
        fingerprint_inputs=("kind", "ref"),
    )
    v18 = _windows_run(target)
    v18["findings"][0]["target_ref"] = ref
    v18["assessments"][0]["subject_ref"] = ref

    migrated = migrate_v18(v18)

    assert migrated["schema_version"] == 19
    assert migrated["run"]["target"]["ref"] == rewritten
    assert migrated["findings"][0]["target_ref"] == rewritten
    assert migrated["assessments"][0]["subject_ref"] == rewritten
    assert migrated["assessments"][1]["subject_ref"] == "http://localhost:11434"


def test_a_rooted_ref_keeps_its_form() -> None:
    v18 = _windows_run()
    v18["findings"][0]["target_ref"] = "\\rooted\\w.pkl"

    assert migrate_v18(v18)["findings"][0]["target_ref"] == "\\rooted\\w.pkl"


def test_a_migrated_windows_run_outside_the_working_directory_is_the_same_target(
    tmp_path: Path,
) -> None:
    result = ScanResult(findings=(), rules_run=(_RULE,), rules_skipped=())
    written_on_windows = replace(run_manifest(), target=_target("..\\models"))
    written_now = replace(run_manifest(), target=_target("../models"))
    before = saved_run_at_v18(run_to_dict(result, counted(written_on_windows, result)))
    after = run_to_dict(result, counted(written_now, result))

    diff = compare_reports(
        load_report(_write(before, tmp_path, "before.json")),
        load_report(_write(after, tmp_path, "after.json")),
    )

    assert not [note for note in diff.notes if "different targets" in note]


def test_a_migrated_windows_run_and_this_build_s_run_compare_unchanged(tmp_path: Path) -> None:
    gone = _finding("models\\llama\\sub\\gone.pkl:2", "gone")
    before_result = ScanResult(
        findings=(_finding("models\\llama\\weights.pkl:3"), gone),
        rules_run=(_RULE,),
        rules_skipped=(),
        scope=FileScope(files=("models\\llama\\weights.pkl", "models\\llama\\sub\\gone.pkl")),
    )
    after_result = ScanResult(
        findings=(_finding("models/llama/weights.pkl:3"),),
        rules_run=(_RULE,),
        rules_skipped=(),
        scope=FileScope(files=("models/llama/weights.pkl", "models/llama/sub/gone.pkl")),
    )
    before_manifest = replace(run_manifest(), target=_target(_ROOT))
    after_manifest = replace(run_manifest(), target=_target("models/llama"))
    before = saved_run_at_v18(run_to_dict(before_result, counted(before_manifest, before_result)))
    after = run_to_dict(after_result, counted(after_manifest, after_result))

    diff = compare_reports(
        load_report(_write(before, tmp_path, "before.json")),
        load_report(_write(after, tmp_path, "after.json")),
    )

    assert [c.location for c in diff.changes] == ["sub/gone.pkl"]
    assert diff.unchanged == 1
    assert not [note for note in diff.notes if "different targets" in note]


@pytest.mark.parametrize(
    ("version", "shape"),
    [
        (18, saved_run_at_v18),
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
    ids=["v18", "v17", "v16", "v15", "v14", "v13", "v12", "v11", "v10", "v9"],
)
def test_every_older_version_reaches_19_through_the_chain(
    version: int, shape: Callable[[dict[str, Any]], dict[str, Any]]
) -> None:
    migrated = migrate_forward(shape(_document()), version)

    assert migrated["schema_version"] == 19
    assert not _errors(migrated)
