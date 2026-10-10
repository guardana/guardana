"""The published envelope schema, held to both halves of the wire.

`schemas/collector-envelope-v8.schema.json` is what somebody builds a receiver or
an agent against without reading this repository. It is hand-written, so nothing
keeps it true except these checks: the engine's writer and every v8 envelope a
release wrote validate against it, and its properties are exactly the ones the
collector's `Submission` models, at every depth.
"""

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, get_args, get_origin

import pytest
from _documents import run_manifest, scan_result
from guardana.core.evaluator.base import Outcome
from guardana.core.gate import GateOutcome
from guardana.core.redaction import EvidenceMode
from guardana.core.report import SkipReason
from guardana.core.reporter import ENVELOPE_SCHEMA_VERSION, _serialize
from guardana.core.severity import Severity
from guardana.server.envelope import (
    SCHEMA_VERSION,
    EvidenceModeName,
    GateName,
    OutcomeName,
    SeverityName,
    Submission,
)
from jsonschema import Draft202012Validator
from pydantic import BaseModel
from test_historical_envelopes import stored_envelopes

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "schemas"
    / f"collector-envelope-v{SCHEMA_VERSION}.schema.json"
)


def _schema() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return loaded


def _validator() -> Draft202012Validator:
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def _written(*, declared: bool) -> dict[str, Any]:
    """The envelope the engine's own writer produces, with or without the optional blocks."""
    manifest = run_manifest()
    payload: dict[str, Any] = json.loads(
        _serialize(
            scan_result(),
            source="ci",
            deployment=manifest.deployment if declared else None,
            run=manifest if declared else None,
        )
    )
    return payload


def _errors(document: dict[str, Any]) -> list[str]:
    return [
        f"{'/'.join(str(p) for p in error.absolute_path)}: {error.message}"
        for error in _validator().iter_errors(document)
    ]


def test_the_schema_describes_the_version_both_halves_speak() -> None:
    assert SCHEMA_VERSION == ENVELOPE_SCHEMA_VERSION
    assert _schema()["properties"]["schema_version"] == {"const": SCHEMA_VERSION}
    assert _schema()["$id"] == (
        f"https://guardana.dev/schemas/collector-envelope/v{SCHEMA_VERSION}.schema.json"
    )


@pytest.mark.parametrize("declared", [True, False], ids=["with-run-and-deployment", "bare"])
def test_the_current_writer_validates(declared: bool) -> None:
    assert _errors(_written(declared=declared)) == []


def test_every_stored_envelope_of_this_version_validates() -> None:
    current = [
        (name, document)
        for name, document in stored_envelopes()
        if document["schema_version"] == SCHEMA_VERSION
    ]

    assert current, f"no stored envelope declares version {SCHEMA_VERSION}"
    for name, document in current:
        assert _errors(document) == [], name


def _drop_identity(document: dict[str, Any]) -> None:
    del document["findings"][0]["identity"]


def _add_tenant(document: dict[str, Any]) -> None:
    document["project"] = "acme/web"


def _older_version(document: dict[str, Any]) -> None:
    document["schema_version"] = SCHEMA_VERSION - 1


def _drop_unverified(document: dict[str, Any]) -> None:
    del document["unverified"]


def _unknown_gate(document: dict[str, Any]) -> None:
    document["run"]["gate"] = "skipped"


@pytest.mark.parametrize(
    "mutate",
    [_drop_identity, _add_tenant, _older_version, _drop_unverified, _unknown_gate],
    ids=["no-identity", "a-tenant", "older-version", "no-unverified", "unknown-gate"],
)
def test_the_schema_refuses_what_this_version_does_not_say(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    """Without these, a schema that accepted any object would pass every check above."""
    document = _written(declared=True)
    mutate(document)

    assert _errors(document)


def _models_in(annotation: object) -> Iterator[type[BaseModel]]:
    """Every Pydantic model an annotation can hold, through lists, unions and `Annotated`."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        yield annotation
        return
    if get_origin(annotation) is None:
        return
    for argument in get_args(annotation):
        yield from _models_in(argument)


def _model_paths(model: type[BaseModel], prefix: str = "") -> set[str]:
    paths: set[str] = set()
    for name, field in model.model_fields.items():
        path = f"{prefix}{name}"
        paths.add(path)
        for nested in _models_in(field.annotation):
            paths |= _model_paths(nested, f"{path}.")
    return paths


def _resolve(node: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    reference = node.get("$ref")
    if not isinstance(reference, str):
        return node
    target: dict[str, Any] = root
    for step in reference.removeprefix("#/").split("/"):
        target = target[step]
    return _resolve(target, root)


def _schema_paths(node: dict[str, Any], root: dict[str, Any], prefix: str = "") -> set[str]:
    node = _resolve(node, root)
    paths: set[str] = set()
    for branch in node.get("oneOf", []) + node.get("anyOf", []):
        paths |= _schema_paths(branch, root, prefix)
    if "items" in node:
        paths |= _schema_paths(node["items"], root, prefix)
    for name, child in node.get("properties", {}).items():
        path = f"{prefix}{name}"
        paths.add(path)
        paths |= _schema_paths(child, root, f"{path}.")
    return paths


def test_every_property_the_collector_accepts_is_published_and_nothing_else() -> None:
    """Both directions, at every depth.

    A field the collector models and the schema omits is one an integrator never
    learns to send; one the schema names and the collector does not model is a
    promise the collector drops at the door.
    """
    schema = _schema()
    accepted = _model_paths(Submission)
    published = _schema_paths(schema, schema)

    assert sorted(accepted - published) == [], "accepted by the collector, missing from the schema"
    assert sorted(published - accepted) == [], "published, and not modelled by the collector"


def _non_null(node: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    """The one branch of a nullable node that is not `null`, resolved and unwrapped from a list."""
    node = _resolve(node, root)
    for branch in node.get("oneOf", []):
        if branch.get("type") != "null":
            return _non_null(branch, root)
    return _non_null(node["items"], root) if "items" in node else node


def _enum_at(path: str) -> list[str]:
    schema = _schema()
    node = schema
    for step in path.split("."):
        node = _non_null(node, schema)["properties"][step]
    values: list[str] = _non_null(node, schema)["enum"]
    return values


@pytest.mark.parametrize(
    ("path", "values"),
    [
        ("findings.severity", [s.name for s in Severity]),
        ("summary.max_severity", [s.name for s in Severity]),
        ("summary.rules_skipped.reason", [str(r) for r in SkipReason]),
        ("findings.verdict.outcome", list(get_args(Outcome))),
        ("run.gate", [str(g) for g in GateOutcome]),
        ("run.evidence_mode", [str(m) for m in EvidenceMode]),
    ],
)
def test_a_published_enum_is_the_engine_s_own(path: str, values: list[str]) -> None:
    """A value the engine gains is an envelope change, so it raises the version first."""
    assert sorted(_enum_at(path)) == sorted(values)


@pytest.mark.parametrize(
    ("path", "accepted"),
    [
        ("findings.severity", SeverityName),
        ("summary.max_severity", SeverityName),
        ("findings.verdict.outcome", OutcomeName),
        ("run.gate", GateName),
        ("run.evidence_mode", EvidenceModeName),
    ],
)
def test_the_collector_accepts_exactly_a_published_enum(path: str, accepted: object) -> None:
    """A value the schema refuses is one the collector would otherwise store and rank."""
    assert sorted(get_args(accepted)) == sorted(_enum_at(path))
