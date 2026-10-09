"""Only an authorization refusal is a refusal: a server error is a question left unanswered.

A `500`, a `429` or a `503` says the server did not get as far as deciding who may
ask. Reading it as "declined on purpose" turned an overloaded or broken server into
one that validates every token it is handed.
"""

import json
from collections.abc import Mapping

import pytest
from _offline import refuse_name_lookups
from guardana.core.target import McpServerTarget
from guardana.core.target._mcp_client import carries_tools
from guardana.core.target._mcp_http import DiscoveryScope, RawReply
from guardana.core.testing import ScriptedMcpServer

pytestmark = pytest.mark.usefixtures(refuse_name_lookups.__name__)

ROUTABLE = "https://93.184.215.14/mcp"
TOOLS = [{"name": "read_file", "description": "Read a file."}]
_LISTING = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": TOOLS}}).encode()
_NOT_A_REFUSAL = (400, 404, 429, 500, 502, 503)


def _reply(status: int, body: bytes = b"") -> RawReply:
    return RawReply(status=status, headers={}, body=body)


@pytest.mark.parametrize("status", [401, 403])
def test_an_authorization_status_is_a_refusal(status: int) -> None:
    assert carries_tools(_reply(status)) is False


@pytest.mark.parametrize("status", _NOT_A_REFUSAL)
def test_any_other_error_status_is_unknown_rather_than_a_refusal(status: int) -> None:
    assert carries_tools(_reply(status)) is None


@pytest.mark.parametrize("code", [-32603, -32601, -32000])
def test_a_json_rpc_error_inside_a_success_status_is_unknown_rather_than_a_refusal(
    code: int,
) -> None:
    """`-32603` is the server failing; no JSON-RPC code is reserved for declining a caller."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": "Internal error"}}
    ).encode()

    assert carries_tools(_reply(200, body)) is None


@pytest.mark.parametrize(
    "result",
    [{}, {"tools": {"read_file": {}}}, {"tools": None}],
    ids=["empty", "not-a-list", "null"],
)
def test_a_success_without_a_tools_list_is_unknown_rather_than_a_refusal(
    result: dict[str, object],
) -> None:
    """Only `401` and `403` refuse; a `200` that lists nothing has not declined anyone."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()

    assert carries_tools(_reply(200, body)) is None


def test_a_listing_is_still_a_listing() -> None:
    assert carries_tools(_reply(200, _LISTING)) is True


class _FailingWithoutCredential:
    """A guarded server that answers every unauthenticated request with one error status."""

    def __init__(self, status: int, *, modern: bool) -> None:
        self.status = status
        self.inner = ScriptedMcpServer(
            ROUTABLE,
            tools=TOOLS,
            credential="operator-supplied-token",
            protocol_versions=["2026-07-28"] if modern else None,
        )

    def __call__(  # noqa: PLR0913 — the keywords the `Sender` protocol publishes
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
        discovery: DiscoveryScope | None = None,
    ) -> RawReply:
        request = json.loads((body or b"{}").decode("utf-8"))
        settling = request.get("method") == "server/discover"
        if method == "POST" and not settling and "Authorization" not in (headers or {}):
            return _reply(self.status)
        return self.inner(
            url,
            method=method,
            body=body,
            headers=headers,
            alongside=alongside,
            discovery=discovery,
        )


@pytest.mark.parametrize("modern", [False, True], ids=["legacy", "modern"])
@pytest.mark.parametrize("status", [429, 500, 503])
def test_a_server_error_to_an_anonymous_caller_is_recorded_as_unanswered(
    status: int, modern: bool
) -> None:
    server = _FailingWithoutCredential(status, modern=modern)
    target = McpServerTarget(
        ROUTABLE, credential="operator-supplied-token", sender=server, discovery_sender=server
    )

    anonymous = target.authorization().anonymous

    assert not anonymous.open_to_anyone
    assert anonymous.error is not None
    assert f"HTTP {status}" in anonymous.error


@pytest.mark.parametrize("modern", [False, True], ids=["legacy", "modern"])
def test_an_authorization_refusal_to_an_anonymous_caller_is_not_an_error(modern: bool) -> None:
    server = _FailingWithoutCredential(401, modern=modern)
    target = McpServerTarget(
        ROUTABLE, credential="operator-supplied-token", sender=server, discovery_sender=server
    )

    anonymous = target.authorization().anonymous

    assert anonymous.error is None
    assert anonymous.status == 401
