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
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert schema.get("additionalProperties") is False, path.name


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

    assert _schema("diff-v1.schema.json")["properties"]["schema_version"]["const"] == (  # type: ignore[index]
        DIFF_SCHEMA_VERSION
    )
    assert _schema("plan-v1.schema.json")["properties"]["schema_version"]["const"] == (  # type: ignore[index]
        PLAN_SCHEMA_VERSION
    )
    assert _schema("run-v2.schema.json")["properties"]["schema_version"]["const"] == (  # type: ignore[index]
        MANIFEST_SCHEMA_VERSION
    )
