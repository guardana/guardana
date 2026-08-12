"""The one schema whose two halves live in different packages, walked end to end.

`guardana.core.reporter` writes the envelope and `guardana.server.envelope` reads
it, in two distributions with two test suites that have each always been right about
their own half. That is the same trap a saved run fell into — a field written
correctly and read wrongly, green on both sides — except here the two sides cannot
even import each other, so nothing but a test that crosses the boundary will ever
notice.

Three questions, in the order they can fail: does the door drop anything the agent
said, does any key make no difference, and does the store give back what came in.
"""

import json
from typing import Any

import pytest
from _documents import run_manifest, scan_result
from _roundtrip import key_paths, render, unread_keys
from conftest import Scoped, _clock
from guardana.core.reporter import _serialize
from guardana.server.envelope import Submission
from guardana.server.store import InMemoryStore
from guardana.server.tenancy import TenantScope
from pydantic import ValidationError

_NOT_A_FIELD = frozenset({"envelope.schema_version"})
"""The version is the envelope's own identity, not payload the collector stores.

`Submission` parses it — it is required, and an absent one is refused — but it is
not carried into what a reader gets back, because a stored submission is already
known to have arrived under the version it declared.
"""


def _envelope() -> dict[str, Any]:
    """The document an agent actually POSTs, built by the engine's own writer.

    Built rather than hand-written: a fixture typed out here would agree with
    whatever the reader expects, which is the one thing this must not do.
    """
    payload: dict[str, Any] = json.loads(
        _serialize(
            scan_result(),
            source="ci",
            deployment=run_manifest().deployment,
            run=run_manifest(),
        )
    )
    return payload


def _at(node: object, path: tuple[str | int, ...]) -> object:
    for step in path:
        if isinstance(node, dict) and isinstance(step, str):
            node = node.get(step, _MISSING)
        elif isinstance(node, list) and isinstance(step, int) and step < len(node):
            node = node[step]
        else:
            return _MISSING
    return node


_MISSING = object()


def test_the_collector_drops_nothing_the_agent_put_on_the_wire() -> None:
    """Every key the engine writes reaches a field the collector models.

    Pydantic ignores an unmodelled key rather than refusing it, which is the right
    behaviour for a fleet upgraded one agent at a time — and exactly why a field
    added on the engine side can be POSTed for releases while a dashboard shows
    nothing and no test anywhere goes red.
    """
    payload = _envelope()

    parsed = Submission.model_validate(payload).model_dump(mode="json")
    dropped = [
        render(path, "envelope")
        for path in key_paths(payload)
        if render(path, "envelope") not in _NOT_A_FIELD and _at(parsed, path) is _MISSING
    ]

    assert not dropped, (
        "keys an agent sends that the collector's schema does not model, so they are "
        "silently discarded at the door:\n  " + "\n  ".join(dropped)
    )


def test_no_key_of_an_envelope_can_be_deleted_without_the_collector_noticing() -> None:
    """The mutation that stops the assertion above passing on both sides being empty."""
    ignored = unread_keys(
        _envelope(),
        Submission.model_validate,
        root="envelope",
        refusal=ValidationError,
    )

    assert not ignored, (
        "keys an envelope carries that make no difference to the submission the "
        "collector builds — either nothing reads them, or the fixture leaves them at "
        "the schema's default:\n  " + "\n  ".join(ignored)
    )


def test_a_stored_submission_comes_back_as_the_one_that_arrived(scoped: Scoped) -> None:
    """The second half of the trip, and it runs against both stores.

    Parsing is where a field is dropped at the door; storage is where it is dropped
    after the door, which a dashboard cannot tell apart. Both stores answer here so
    the one nobody runs locally cannot be the one that forgets a column.
    """
    submitted = Submission.model_validate(_envelope())
    scoped.store.add(scoped.scope, submitted)

    (stored,) = scoped.store.submissions(scoped.scope)

    assert stored == submitted


@pytest.mark.parametrize("channel", ["findings", "unverified", "errors"])
def test_an_emptied_channel_is_stored_as_empty_and_not_as_absent(channel: str) -> None:
    """The mutation for the store trip: equality above must not pass on two empty stores.

    Emptying one channel has to change what comes back. A store that dropped the
    channel entirely would compare equal to a submission that had nothing in it,
    which is a dashboard reporting an all-clear about checks that crashed.
    """
    store, scope = InMemoryStore(clock=_clock), TenantScope.for_project(1)
    full = Submission.model_validate(_envelope())
    store.add(scope, full.model_copy(update={channel: []}))

    (stored,) = store.submissions(scope)

    assert stored != full
    assert getattr(stored, channel) == []
