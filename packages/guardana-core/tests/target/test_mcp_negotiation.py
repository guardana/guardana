"""Which era of MCP a server speaks, how that is settled, and what is never claimed.

The revision published on 2026-07-28 removed the `initialize` handshake and
protocol sessions, and made every request carry its own version. A client that
guessed would be wrong half the time and would write the guess into a run
manifest, so the guess is what these tests are about — see
`docs/design/mcp-protocol-eras.md`.
"""

from collections.abc import Mapping
from typing import Any

import pytest
from guardana.core.target import McpError, McpServerTarget
from guardana.core.target._mcp_http import RawReply
from guardana.core.target._mcp_wire import (
    LATEST_VERSION,
    LEGACY_VERSION,
    META_CLIENT_CAPABILITIES,
    META_CLIENT_INFO,
    META_PROTOCOL_VERSION,
)
from guardana.core.testing import ScriptedMcpServer

ROUTABLE = "https://93.184.215.14/mcp"
TOOLS = [{"name": "read_file", "description": "Read a file."}]


def _methods(server: ScriptedMcpServer) -> list[str]:
    return [str(body.get("method")) for body in server.bodies]


def _meta_of(body: Mapping[str, Any]) -> Mapping[str, Any]:
    params = body.get("params") or {}
    return params.get("_meta") or {}


def test_a_modern_server_is_discovered_and_never_handshaken() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION])
    target = McpServerTarget(ROUTABLE, sender=server)

    assert [t.name for t in target.list_tools()] == ["read_file"]

    assert _methods(server) == ["server/discover", "tools/list"]
    assert target.protocols() == {"mcp": LATEST_VERSION}


def test_a_legacy_server_falls_back_to_the_handshake_it_still_expects() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)
    target = McpServerTarget(ROUTABLE, sender=server)

    assert [t.name for t in target.list_tools()] == ["read_file"]

    assert _methods(server) == ["server/discover", "initialize", "tools/list"]
    assert target.protocols() == {"mcp": LEGACY_VERSION}


def test_a_legacy_server_that_answers_an_era_ambiguous_method_is_not_read_as_modern() -> None:
    """The reason the probe is `server/discover` and not an ordinary request.

    The specification warns that some legacy servers do not check that a request
    arrived after `initialize` and will answer one anyway. A client that opened
    with `tools/list` would get a manifest from such a server and file
    `mcp: 2026-07-28` in the run manifest — a coverage claim about a revision that
    server has never heard of, written into the document a later `diff` compares
    against.
    """

    class _AnswersAnything(ScriptedMcpServer):
        def __call__(self, url: str, **kwargs: object) -> RawReply:
            reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
            method = str(self.bodies[-1].get("method")) if self.bodies else ""
            if method != "server/discover":
                return reply
            # Not a discovery result: a tool listing, which is exactly what an
            # over-permissive legacy framework hands back for an unknown method.
            return RawReply(
                status=200,
                headers={},
                body=b'{"jsonrpc":"2.0","id":1,"result":'
                b'{"tools":[{"name":"read_file","description":"Read a file."}]}}',
            )

    server = _AnswersAnything(ROUTABLE, tools=TOOLS)
    target = McpServerTarget(ROUTABLE, sender=server)

    target.list_tools()

    assert target.protocols() == {"mcp": LEGACY_VERSION}
    assert "initialize" in _methods(server), "the client stayed modern against a legacy server"


def test_an_unsupported_version_error_names_a_revision_and_the_client_retries_with_it() -> None:
    # A modern error identifies a modern server. Falling back to `initialize` here
    # would be sending a removed method to a server that named its versions.
    server = ScriptedMcpServer(
        ROUTABLE, tools=TOOLS, protocol_versions=[LEGACY_VERSION], credential=None
    )
    target = McpServerTarget(ROUTABLE, sender=server)

    target.list_tools()

    assert target.protocols() == {"mcp": LEGACY_VERSION}
    assert _methods(server) == ["server/discover", "initialize", "tools/list"]


def test_no_revision_in_common_is_refused_by_name_and_claims_no_coverage() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, protocol_versions=["2031-01-01"])
    target = McpServerTarget(ROUTABLE, sender=server)

    with pytest.raises(McpError, match="no revision in common"):
        target.list_tools()

    assert target.protocols() == {}, "a version nobody agreed on was recorded as reached"


def test_a_modern_request_states_its_version_in_the_body_and_in_the_header() -> None:
    # They have to be the same value: a server that finds them disagreeing MUST
    # reject the request with `HeaderMismatch`, so a client holding two copies of
    # one fact would eventually grade a rejection it caused itself.
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION])
    McpServerTarget(ROUTABLE, sender=server).list_tools()

    listing = server.bodies[-1]
    _, _, headers = server.requests[-1]
    meta = _meta_of(listing)
    assert meta[META_PROTOCOL_VERSION] == headers["MCP-Protocol-Version"] == LATEST_VERSION
    assert headers["Mcp-Method"] == "tools/list"
    assert meta[META_CLIENT_INFO]["name"] == "guardana"


def test_a_modern_request_declares_no_client_capabilities() -> None:
    """A safety property, not an omission.

    A server **MUST NOT** ask for a capability the client did not declare, so a
    client declaring none cannot be handed an `inputRequests` asking it to run a
    model completion or to prompt a human on the server's behalf.
    """
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION])
    McpServerTarget(ROUTABLE, sender=server).list_tools()

    assert _meta_of(server.bodies[-1])[META_CLIENT_CAPABILITIES] == {}


def test_a_legacy_request_carries_no_per_request_metadata() -> None:
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)
    McpServerTarget(ROUTABLE, sender=server).list_tools()

    listing = server.bodies[-1]
    _, _, headers = server.requests[-1]
    assert _meta_of(listing) == {}
    assert "Mcp-Method" not in headers
    assert headers["MCP-Protocol-Version"] == LEGACY_VERSION


def test_a_modern_conversation_never_sends_a_session_header() -> None:
    # The revision removed protocol sessions. A client that keeps sending the header
    # is asking a server to honour something it is supposed to ignore.
    server = ScriptedMcpServer(
        ROUTABLE,
        tools=TOOLS,
        protocol_versions=[LATEST_VERSION, LEGACY_VERSION],
        session_ids=["issued-to-a-legacy-client"],
    )
    target = McpServerTarget(ROUTABLE, sender=server)

    target.list_tools()

    assert all("Mcp-Session-Id" not in headers for _, _, headers in server.requests)


def test_an_interim_result_is_refused_rather_than_read_as_an_empty_manifest() -> None:
    """`input_required` has no `tools`, and a reader that shrugged would invent one.

    A server asking a question would have been recorded as a server offering
    nothing to poison — the exact fail-open shape this codebase hunts.
    """

    class _AsksForInput(ScriptedMcpServer):
        def __call__(self, url: str, **kwargs: object) -> RawReply:
            reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
            if str(self.bodies[-1].get("method")) != "tools/list":
                return reply
            return RawReply(
                status=200,
                headers={},
                body=b'{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",'
                b'"requestState":"opaque"}}',
            )

    server = _AsksForInput(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION])

    with pytest.raises(McpError, match="asked for client input"):
        McpServerTarget(ROUTABLE, sender=server).list_tools()


def test_an_unrecognised_result_type_is_refused_rather_than_guessed_past() -> None:
    class _Invents(ScriptedMcpServer):
        def __call__(self, url: str, **kwargs: object) -> RawReply:
            reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
            if str(self.bodies[-1].get("method")) != "tools/list":
                return reply
            return RawReply(
                status=200,
                headers={},
                body=b'{"jsonrpc":"2.0","id":1,"result":{"resultType":"partial","tools":[]}}',
            )

    server = _Invents(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION])

    with pytest.raises(McpError, match="unrecognised resultType"):
        McpServerTarget(ROUTABLE, sender=server).list_tools()


def test_a_result_with_no_result_type_is_read_as_complete() -> None:
    # Required of a client, and the only reason a legacy server keeps working.
    server = ScriptedMcpServer(ROUTABLE, tools=TOOLS)

    assert [t.name for t in McpServerTarget(ROUTABLE, sender=server).list_tools()] == ["read_file"]


def test_a_challenge_on_the_probe_leaves_the_era_open_and_the_handshake_settles_it() -> None:
    """An authorization challenge says who may ask, not which protocol answers.

    A protected modern server refuses `server/discover` to a caller with no
    credential, which is not an era signal, so the client falls back. The handshake
    then comes back as `UnsupportedProtocolVersionError` naming the versions the
    server does support — and *that* is conclusive. Giving up there reported
    `answered HTTP 400` about a server that had just said exactly how to reach it.
    """

    class _RefusesTheProbe(ScriptedMcpServer):
        def __call__(self, url: str, **kwargs: object) -> RawReply:
            reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
            if self.bodies and str(self.bodies[-1].get("method")) == "server/discover":
                return RawReply(
                    status=401, headers={}, body=b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000}}'
                )
            return reply

    server = _RefusesTheProbe(ROUTABLE, tools=TOOLS, protocol_versions=[LATEST_VERSION])
    target = McpServerTarget(ROUTABLE, sender=server)

    assert [t.name for t in target.list_tools()] == ["read_file"]

    assert target.protocols() == {"mcp": LATEST_VERSION}
    assert _methods(server) == ["server/discover", "initialize", "tools/list"]
