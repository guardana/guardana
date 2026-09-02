"""A migration that cannot carry a field refuses; it does not invent one.

`migrate_v1` stringified the old document's `target_kind`, so a version-1 run
that never recorded one produced the literal `"None"` — a value no reader can
place and one `run-v2.schema.json` rejects. `guardana run migrate` then exited
`0` having written that document *over the original*, because the default
destination is the file itself.

Every unit test around migration passed, for the same reason as last time: they
asserted on the objects the migration loaded, and the object was fine. What was
published was the file.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from guardana.core.manifest.load import ManifestLoadError
from guardana.core.manifest.migrations import migrate_v1
from guardana.core.report import ReportLoadError, load_report
from jsonschema import Draft202012Validator

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schemas" / "run-v2.schema.json"


def _validator() -> Draft202012Validator:
    schema: dict[str, Any] = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _v1(**overrides: object) -> dict[str, Any]:
    run: dict[str, Any] = {
        "tool_version": "0.6.0",
        "target_kind": "artifact",
        "target_ref": ".",
        "profile": "ci",
        "rules": {},
        "rules_skipped": [],
        "started_at": "2026-07-25T09:00:00+00:00",
    }
    run.update(overrides)
    return {
        "schema_version": 1,
        "run": run,
        "findings": [],
        "unverified": [],
        "waived": [],
        "errors": [],
        "observations": [],
    }


def test_a_version_one_run_without_a_target_kind_is_refused() -> None:
    document = _v1()
    del document["run"]["target_kind"]

    with pytest.raises(ManifestLoadError, match="target type"):
        migrate_v1(document)


def test_a_version_one_run_with_an_unknown_target_kind_is_refused() -> None:
    with pytest.raises(ManifestLoadError, match="target type"):
        migrate_v1(_v1(target_kind="vector_store"))


@pytest.mark.parametrize("missing", ["target_kind", "target_ref", "tool_version", "profile"])
def test_no_refusal_ever_produces_a_document_that_fails_the_schema(missing: str) -> None:
    """Whatever a broken version-1 document does, it must not become a valid-looking file.

    Parametrised over the fields a version-1 run could be missing, because the
    defect was one field and the class of defect is "stringify whatever is there".
    """
    document = _v1()
    del document["run"][missing]

    try:
        migrated = migrate_v1(document)
    except ManifestLoadError:
        return
    assert not list(_validator().iter_errors(migrated)), [
        e.message for e in _validator().iter_errors(migrated)
    ]


def test_reading_a_broken_older_run_raises_the_readers_own_error(tmp_path: Path) -> None:
    """`load_report` promises `ReportLoadError` and nothing else.

    The migration used to run outside its guard, so `ManifestLoadError` escaped
    through every caller — `guardana diff` and `guardana run inspect` printed a
    traceback and exited `1`, which in this project's table means "a finding
    failed the policy". An unreadable file is the one thing that is not.
    """
    # `target_ref` rather than `target_kind`, deliberately: this one makes the
    # *migration* raise. A field that only breaks the later parse would be caught
    # by the guard either way, so the test would pass with the migration back
    # outside it and prove nothing.
    document = _v1()
    del document["run"]["target_ref"]
    path = tmp_path / "old.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ReportLoadError):
        load_report(path)
