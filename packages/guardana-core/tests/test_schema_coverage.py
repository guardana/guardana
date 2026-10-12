"""Every JSON document Guardana emits has a published schema, and satisfies it.

Two failures this prevents, and the second is the one that actually happens: a
document with no schema at all, so a consumer has nothing to build against; and a
schema that drifts from the code because nothing compares them.

The list of documents is derived from the schemas directory rather than written
here, so adding a schema without a test is impossible and adding a document
without a schema shows up as an unversioned output in the audit below.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

_SCHEMAS = Path(__file__).resolve().parents[3] / "schemas"


def _schema(name: str) -> dict[str, object]:
    loaded: dict[str, object] = json.loads((_SCHEMAS / name).read_text(encoding="utf-8"))
    return loaded


@pytest.mark.parametrize("path", sorted(_SCHEMAS.glob("*.schema.json")))
def test_every_schema_is_a_valid_2020_12_schema(path: Path) -> None:
    Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))


@pytest.mark.parametrize("path", sorted(_SCHEMAS.glob("*.schema.json")))
def test_every_schema_carries_its_version_in_its_identifier(path: Path) -> None:
    # in-toto/SLSA practice: a consumer must be able to tell which contract it
    # holds before parsing the document.
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert schema["$id"].startswith("https://guardana.dev/schemas/")
    assert schema["$id"].endswith(".schema.json")
    assert "/v" in schema["$id"]


@pytest.mark.parametrize("path", sorted(_SCHEMAS.glob("*.schema.json")))
def test_every_schema_title_names_the_version_its_identifier_names(path: Path) -> None:
    schema = json.loads(path.read_text(encoding="utf-8"))
    version = schema["$id"].rsplit("/v", 1)[1].removesuffix(".schema.json")

    assert schema["title"].endswith(f" v{version}"), f"{path.name}: {schema['title']!r}"


@pytest.mark.parametrize("path", sorted(_SCHEMAS.glob("*.schema.json")))
def test_every_schema_refuses_unknown_fields_at_the_top_level(path: Path) -> None:
    # A document that silently accepts anything is not a contract. This is also
    # what makes a writer that invents a field fail loudly rather than producing
    # something every reader ignores.
    #
    # A schema for a JSONL format describes one *record*, so its top level is a
    # `oneOf` over the record shapes rather than one object. That is still closed —
    # every branch is — and the check follows the structure rather than exempting
    # the file, because an exemption is where an open schema would eventually hide.
    schema = json.loads(path.read_text(encoding="utf-8"))
    branches = schema.get("oneOf")
    if branches is None:
        assert schema.get("additionalProperties") is False, path.name
        return
    definitions = schema.get("$defs", {})
    for branch in branches:
        resolved = definitions[branch["$ref"].removeprefix("#/$defs/")]
        assert resolved.get("additionalProperties") is False, f"{path.name}: {branch}"


def test_a_diff_document_satisfies_its_schema() -> None:
    from guardana.core.diff import RunDiff  # noqa: PLC0415
    from guardana.report import get_diff_renderer  # noqa: PLC0415

    rendered = get_diff_renderer("json").render(
        RunDiff(changes=(), unchanged=0, notes=("a note",), incomplete=())
    )

    Draft202012Validator(_schema("diff-v3.schema.json")).validate(json.loads(rendered))


def test_every_change_kind_satisfies_the_diff_schema() -> None:
    from guardana.core.diff import Change, ChangeKind, CheckState, RunDiff  # noqa: PLC0415
    from guardana.core.severity import Severity  # noqa: PLC0415
    from guardana.report import get_diff_renderer  # noqa: PLC0415

    state = CheckState(
        outcome="fail", severity=Severity.HIGH, confidence=1.0, count=1, waived=False
    )
    changes = tuple(
        Change(kind=kind, rule_id="r", location="a.py", detail="d", before=state)
        for kind in ChangeKind
    )

    rendered = get_diff_renderer("json").render(RunDiff(changes=changes, unchanged=0))

    Draft202012Validator(_schema("diff-v3.schema.json")).validate(json.loads(rendered))


def test_an_incomplete_diff_document_satisfies_its_schema() -> None:
    from guardana.core.diff import RunDiff  # noqa: PLC0415
    from guardana.report import get_diff_renderer  # noqa: PLC0415

    rendered = get_diff_renderer("json").render(
        RunDiff(changes=(), unchanged=0, incomplete=("the second run ran out of budget",))
    )

    Draft202012Validator(_schema("diff-v3.schema.json")).validate(json.loads(rendered))


def test_the_schema_version_in_each_schema_matches_the_code() -> None:
    """A schema pinned to a version the code no longer writes is worse than none."""
    from guardana.cli.plan import PLAN_SCHEMA_VERSION  # noqa: PLC0415
    from guardana.core.diff.model import DIFF_SCHEMA_VERSION  # noqa: PLC0415
    from guardana.core.manifest.model import MANIFEST_SCHEMA_VERSION  # noqa: PLC0415
    from guardana.core.trace import TRACE_SCHEMA_VERSION  # noqa: PLC0415

    assert _schema("diff-v3.schema.json")["properties"]["schema_version"]["const"] == (  # type: ignore[index]
        DIFF_SCHEMA_VERSION
    )
    assert _schema("plan-v4.schema.json")["properties"]["schema_version"]["const"] == (  # type: ignore[index]
        PLAN_SCHEMA_VERSION
    )
    assert _schema("run-v18.schema.json")["properties"]["schema_version"]["const"] == (  # type: ignore[index]
        MANIFEST_SCHEMA_VERSION
    )
    assert (
        _schema("trace-v3.schema.json")["$defs"]["header"]["properties"][  # type: ignore[index]
            "guardana_trace"
        ]["const"]
        == TRACE_SCHEMA_VERSION
    )


def test_the_superseded_run_schemas_stay_pinned_to_the_versions_they_describe() -> None:
    """A saved run still has to validate against the schema it was written to.

    Which is the whole reason a new version is a new file rather than an edit: widening
    v3's target-kind enum in place would have changed a contract under a name that
    promised it had not.
    """
    for version in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17):
        assert (
            _schema(f"run-v{version}.schema.json")["properties"]["schema_version"][  # type: ignore[index]
                "const"
            ]
            == version
        )


def test_the_superseded_recording_schema_stays_pinned_to_format_1() -> None:
    """A format-1 recording is still read, so its contract stays as it was written."""
    header = _schema("recording-v1.schema.json")["$defs"]["header"]["properties"]  # type: ignore[index]

    assert header["guardana_recording"]["const"] == 1
    assert "subject_kind" not in header


def test_the_format_2_recording_schema_stays_pinned_to_a_reply_on_every_line() -> None:
    """A format-2 recording is still read, and none of its lines holds a decline."""
    defs: Any = _schema("recording-v2.schema.json")["$defs"]

    assert defs["header"]["properties"]["guardana_recording"]["const"] == 2
    assert "declined" not in defs["exchange"]["properties"]
    assert "reply" in defs["exchange"]["required"]


def test_the_dataset_schemas_name_the_formats_the_reader_reads() -> None:
    """The newest schema is the format this build writes; format 1 keeps its own contract."""
    from guardana.core.dataset import DATASET_FORMAT, READ_FORMATS  # noqa: PLC0415

    written: Any = _schema(f"dataset-v{DATASET_FORMAT}.schema.json")["$defs"]
    superseded: Any = _schema("dataset-v1.schema.json")["$defs"]

    assert written["header"]["properties"]["guardana_dataset"]["const"] == DATASET_FORMAT
    assert sorted(int(p.name[9]) for p in _SCHEMAS.glob("dataset-v*.schema.json")) == list(
        READ_FORMATS
    )
    assert superseded["header"]["properties"]["guardana_dataset"]["const"] == 1
    assert "observed" not in superseded["case"]["properties"]


@pytest.mark.parametrize(
    ("version", "added_later"),
    [(1, ("span", "agent")), (2, ("approval", "approver_kind"))],
)
def test_a_superseded_trace_schema_stays_pinned_to_the_version_it_describes(
    version: int, added_later: tuple[str, str]
) -> None:
    """The same promise on the trace side: an older file keeps its own contract.

    A third party writing a trace exporter built against `trace-v1`, and editing that
    file to describe v2 would move the contract under them while the name said it had
    not moved. Each entry also names the field the *next* version added, because a
    pinned `const` with a widened body is the same drift wearing the right number.
    """
    name = f"trace-v{version}.schema.json"
    assert (
        _schema(name)["$defs"]["header"]["properties"]["guardana_trace"]["const"]  # type: ignore[index]
        == version
    )
    where, field = added_later
    if where == "span":
        assert field not in _schema(name)["$defs"]["span"]["properties"]  # type: ignore[index]
    else:
        assert (
            field
            not in _schema(name)["$defs"]["span"]["properties"]["approvals"][  # type: ignore[index]
                "items"
            ]["properties"]
        )
