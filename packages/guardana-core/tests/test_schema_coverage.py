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

    Draft202012Validator(_schema("diff-v1.schema.json")).validate(json.loads(rendered))


def test_an_incomplete_diff_document_satisfies_its_schema() -> None:
    from guardana.core.diff import RunDiff  # noqa: PLC0415
    from guardana.report import get_diff_renderer  # noqa: PLC0415

    rendered = get_diff_renderer("json").render(
        RunDiff(changes=(), unchanged=0, incomplete=("the second run ran out of budget",))
    )

    Draft202012Validator(_schema("diff-v1.schema.json")).validate(json.loads(rendered))


def test_the_schema_version_in_each_schema_matches_the_code() -> None:
    """A schema pinned to a version the code no longer writes is worse than none."""
    from guardana.cli.plan import PLAN_SCHEMA_VERSION  # noqa: PLC0415
    from guardana.core.diff.model import DIFF_SCHEMA_VERSION  # noqa: PLC0415
    from guardana.core.manifest.model import MANIFEST_SCHEMA_VERSION  # noqa: PLC0415
    from guardana.core.trace import TRACE_SCHEMA_VERSION  # noqa: PLC0415

    assert _schema("diff-v1.schema.json")["properties"]["schema_version"]["const"] == (  # type: ignore[index]
        DIFF_SCHEMA_VERSION
    )
    assert _schema("plan-v1.schema.json")["properties"]["schema_version"]["const"] == (  # type: ignore[index]
        PLAN_SCHEMA_VERSION
    )
    assert _schema("run-v5.schema.json")["properties"]["schema_version"]["const"] == (  # type: ignore[index]
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
    for version in (2, 3, 4):
        assert (
            _schema(f"run-v{version}.schema.json")["properties"]["schema_version"][  # type: ignore[index]
                "const"
            ]
            == version
        )


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
