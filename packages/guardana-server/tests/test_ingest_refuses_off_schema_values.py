"""Ingest holds every envelope to the values the published schema allows.

A severity, an outcome, a gate or a count the engine cannot write would otherwise be
stored and aggregated as though it meant something: an unknown severity ranked as
the worst, a confidence of 7.5 shown as a verdict.
"""

import json
import re
from collections.abc import Callable, Iterable, Iterator
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.db.migrations import apply_pending
from guardana.server.envelope import Submission
from guardana.server.store import InMemoryStore
from guardana.server.tenancy import TenantScope
from jsonschema import ValidationError
from test_envelope_schema import _resolve, _schema, _validator, _written
from test_historical_envelopes import bearer, serve, stored_envelopes, tenant
from test_server import _real_envelope

_OK = 200
_UNPROCESSABLE = 422

_Mutation = Callable[[dict[str, Any]], None]


def _envelope() -> dict[str, Any]:
    """What the engine's reporter sends, with a verdict, a summary and a run block."""
    document = _real_envelope()
    document["run"] = {
        "run_id": "run-1",
        "started_at": None,
        "completed_at": None,
        "tool_version": "0.9.0",
        "gate": "fail",
        "evidence_mode": "redacted",
        "requests": 1,
        "input_tokens": 0,
        "output_tokens": 0,
        "wall_time_seconds": 0.5,
    }
    return document


def _set(path: str, value: object) -> _Mutation:
    def mutate(document: dict[str, Any]) -> None:
        *parents, leaf = path.split(".")
        node: Any = document
        for step in parents:
            node = node[int(step)] if step.isdigit() else node[step]
        node[leaf] = value

    return mutate


_OFF_SCHEMA = {
    "unknown-severity": _set("findings.0.severity", "banana"),
    "lower-case-severity": _set("findings.0.severity", "high"),
    "unknown-max-severity": _set("summary.max_severity", "banana"),
    "upper-case-outcome": _set("findings.0.verdict.outcome", "PASSED"),
    "confidence-above-one": _set("findings.0.verdict.confidence", 7.5),
    "negative-confidence": _set("findings.0.verdict.confidence", -3),
    "nan-confidence": _set("findings.0.verdict.confidence", float("nan")),
    "infinite-confidence": _set("findings.0.verdict.confidence", float("inf")),
    "negative-rules-run": _set("summary.rules_run", -1),
    "negative-unverified": _set("summary.unverified", -1),
    "negative-errors": _set("summary.errors", -1),
    "negative-requests": _set("run.requests", -1),
    "negative-input-tokens": _set("run.input_tokens", -1),
    "negative-output-tokens": _set("run.output_tokens", -1),
    "negative-wall-time": _set("run.wall_time_seconds", -0.5),
    "infinite-wall-time": _set("run.wall_time_seconds", float("inf")),
    "upper-case-gate": _set("run.gate", "PASS"),
    "unknown-evidence-mode": _set("run.evidence_mode", "lol"),
}


def _client() -> TestClient:
    return TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))


def _post(client: TestClient, document: dict[str, Any]) -> int:
    # Serialized here because the JSON encoder writes NaN and Infinity, which an
    # agent built on Python's own `json` module can send.
    body = json.dumps(document)
    return client.post(
        "/findings", content=body, headers={"Content-Type": "application/json"}
    ).status_code


def test_the_envelope_these_values_are_taken_from_is_accepted() -> None:
    assert _post(_client(), _envelope()) == _OK


@pytest.mark.parametrize("mutate", list(_OFF_SCHEMA.values()), ids=list(_OFF_SCHEMA))
def test_a_value_outside_the_published_schema_is_refused_and_nothing_is_stored(
    mutate: _Mutation,
) -> None:
    client = _client()
    document = _envelope()
    mutate(document)

    assert _post(client, document) == _UNPROCESSABLE
    assert client.get("/findings").json() == []


@pytest.mark.parametrize(
    "mutate",
    [
        _set("findings.0.verdict.confidence", 0),
        _set("findings.0.verdict.confidence", 1),
        _set("summary.max_severity", None),
        _set("run.gate", None),
        _set("run.evidence_mode", None),
        _set("run.requests", None),
        _set("run.wall_time_seconds", 0),
    ],
    ids=[
        "confidence-zero",
        "confidence-one",
        "no-max",
        "no-gate",
        "no-mode",
        "no-requests",
        "zero-time",
    ],
)
def test_a_value_at_the_edge_of_the_schema_is_accepted(mutate: _Mutation) -> None:
    document = _envelope()
    mutate(document)

    assert _post(_client(), document) == _OK


def _legacy() -> dict[str, Any]:
    """An envelope an earlier collector accepted and stored as it came."""
    document = _envelope()
    _set("findings.0.severity", "banana")(document)
    _set("findings.0.verdict.confidence", 7.5)(document)
    _set("summary.rules_run", -1)(document)
    return document


def _read(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    """The answer of every read route, failing unless each answered 200."""
    answers: dict[str, Any] = {}
    for path in ("/findings", "/trend", "/stats"):
        response = client.get(path, headers=headers)
        assert response.status_code == _OK, (path, response.text)
        answers[path] = response.json()
    return answers


def test_post_refuses_what_an_earlier_collector_stored_naming_each_value() -> None:
    client = _client()

    response = client.post("/findings", json=_legacy())

    assert response.status_code == _UNPROCESSABLE
    assert [error["loc"] for error in response.json()["detail"]] == [
        ["body", "findings", 0, "severity"],
        ["body", "findings", 0, "verdict", "confidence"],
        ["body", "summary", "rules_run"],
    ]


def test_a_row_an_earlier_collector_stored_still_reads_back() -> None:
    store = InMemoryStore()
    store.add(TenantScope.unauthenticated(), Submission.model_validate(_legacy()))
    client = TestClient(create_app(store=store, dashboard=True, allow_unauthenticated=True))

    answers = _read(client, {})

    (held,) = answers["/findings"]
    assert held["findings"][0]["severity"] == "banana"
    assert held["findings"][0]["verdict"]["confidence"] == 7.5
    assert held["summary"]["rules_run"] == -1
    assert answers["/trend"]["banana"] == 1
    assert answers["/stats"]["by_severity"] == {"banana": 1, "CRITICAL": 1}


def test_a_row_an_earlier_collector_stored_still_reads_back_from_postgres(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
    served = serve(database_url, tenant(database_url), monkeypatch)
    served.store.add(served.scope, Submission.model_validate(_legacy()))
    monkeypatch.setenv("GUARDANA_DASHBOARD", "1")
    client = TestClient(create_app())

    answers = _read(client, bearer(served.token))

    (held,) = answers["/findings"]
    assert held["findings"][0]["severity"] == "banana"
    assert held["findings"][0]["verdict"]["confidence"] == 7.5
    assert held["summary"]["rules_run"] == -1


_VALUE_CONSTRAINTS = (
    "enum",
    "minimum",
    "exclusiveMinimum",
    "maximum",
    "exclusiveMaximum",
    "pattern",
)
"""Every keyword of the published schema that bounds a value an agent sends.

Not walked: `const`, which pins `schema_version` and is deliberately relaxed so a
collector accepts versions 2 to 8; the size keywords (`maxLength`, `maxItems`), which
the models enforce on parse; and the shape keywords (`type`, `required`,
`additionalProperties`, `minProperties`), which an older envelope is allowed to break.
"""

_Loc = tuple[str | int, ...]


def _schema_constraints(
    node: dict[str, Any], root: dict[str, Any], loc: _Loc = ()
) -> Iterator[tuple[_Loc, str, Any]]:
    """Yield `(location, keyword, bound)` for every value constraint, arrays at item 0."""
    node = _resolve(node, root)
    for keyword in _VALUE_CONSTRAINTS:
        if keyword in node:
            yield loc, keyword, node[keyword]
    for branch in node.get("oneOf", []) + node.get("anyOf", []):
        yield from _schema_constraints(branch, root, loc)
    if "items" in node:
        yield from _schema_constraints(node["items"], root, (*loc, 0))
    for name, child in node.get("properties", {}).items():
        yield from _schema_constraints(child, root, (*loc, name))


_CONSTRAINTS = sorted(
    {
        (loc, keyword, json.dumps(bound))
        for loc, keyword, bound in _schema_constraints(_schema(), _schema())
    },
    key=str,
)


def _children(node: object) -> dict[str | int, object]:
    if isinstance(node, list):
        indexed: dict[str | int, object] = dict(enumerate(node))
        return indexed
    if isinstance(node, dict):
        return node
    raise TypeError(f"{node!r} holds nothing")


def _at(document: object, loc: _Loc) -> object:
    for step in loc:
        document = _children(document)[step]
    return document


def _replace(document: dict[str, Any], loc: _Loc, value: object) -> None:
    *parents, leaf = loc
    parent = _at(document, tuple(parents))
    if isinstance(parent, list) and isinstance(leaf, int):
        parent[leaf] = value
        return
    if not isinstance(parent, dict):
        raise TypeError(f"nothing to replace at {loc}")
    parent[leaf] = value


def _violation(keyword: str, bound: object, current: object) -> object:
    """A value that breaks this one constraint and, where possible, nothing else."""
    if keyword == "enum":
        return "banana"
    if isinstance(bound, int | float) and keyword.startswith("exclusive"):
        return bound
    if isinstance(bound, int | float):
        return bound - 1 if keyword == "minimum" else bound + 1
    if isinstance(bound, str) and isinstance(current, str):
        for candidate in (current.upper(), current[:-6], current + "!", "!"):
            if re.search(bound, candidate) is None:
                return candidate
    raise AssertionError(f"no value violates {keyword} {bound!r} at {current!r}")


def _validators(errors: Iterable[ValidationError]) -> Iterator[tuple[_Loc, str]]:
    """Each failed keyword with where it failed, inside every `oneOf` branch too."""
    for error in errors:
        yield tuple(error.absolute_path), str(error.validator)
        yield from _validators(error.context or ())


def test_the_walk_finds_the_constraints_this_collector_must_hold() -> None:
    """Without this, a walk that found nothing would make the test below vacuous."""
    found = {(loc, keyword) for loc, keyword, _ in _CONSTRAINTS}

    assert {
        (("findings", 0, "severity"), "enum"),
        (("findings", 0, "identity"), "pattern"),
        (("unverified", 0, "verdict", "confidence"), "maximum"),
        (("summary", "rules_skipped", 0, "reason"), "enum"),
        (("run", "started_at"), "pattern"),
        (("run", "wall_time_seconds"), "minimum"),
    } <= found


def test_the_document_every_violation_is_made_from_is_valid_and_accepted() -> None:
    document = _written(declared=True)

    assert list(_validator().iter_errors(document)) == []
    assert _post(_client(), document) == _OK


@pytest.mark.parametrize(
    ("loc", "keyword", "bound"),
    [(loc, keyword, json.loads(bound)) for loc, keyword, bound in _CONSTRAINTS],
    ids=[f"{'.'.join(map(str, loc))}:{keyword}" for loc, keyword, _ in _CONSTRAINTS],
)
def test_ingest_refuses_a_violation_of_every_value_constraint_the_schema_publishes(
    loc: _Loc, keyword: str, bound: object
) -> None:
    document = _written(declared=True)
    _replace(document, loc, _violation(keyword, bound, _at(document, loc)))
    broken = set(_validators(_validator().iter_errors(document)))
    client = _client()

    assert (loc, keyword) in broken, "the value chosen does not break this constraint"
    # A nullable field reports its break at the `oneOf` around it too, so only the
    # field itself and its ancestors may fail.
    assert all(loc[: len(where)] == where for where, _ in broken), "it breaks another field"
    assert _post(client, document) == _UNPROCESSABLE
    assert client.get("/findings").json() == []


@pytest.mark.parametrize(
    "document",
    [document for _, document in stored_envelopes()],
    ids=[n for n, _ in stored_envelopes()],
)
def test_every_envelope_a_release_wrote_is_accepted(document: dict[str, Any]) -> None:
    assert _post(_client(), document) == _OK
