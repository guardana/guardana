"""A scripted MCP server, so an authorization rule gets both fixtures and no network.

Every rule needs a positive sample and a negative one, and for a rule about
authorization both are servers that behave in a particular way — not files that
contain a particular string. Writing them against a real server would make the
test suite need one; writing them against a mock of Guardana's own client would
test the mock.

So this is the server, in about a hundred lines: it answers handshakes and tool
listings, decides whether a caller is authorized, hands out session ids, and serves
the two discovery documents. Every knob is a behaviour somebody's real server has.
"""

import json
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from guardana.core.target._mcp_http import RawReply

_RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource"
_AUTHORIZATION_METADATA_PATHS = (
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
)


class ScriptedMcpServer:
    """An MCP server double reached the way the real one is: through a sender.

    Pass an instance as `McpServerTarget(..., sender=server)` and every request the
    target would have put on the network arrives here instead.

    ```python
    open_server = ScriptedMcpServer(url, tools=[{"name": "read", "description": "…"}])
    assert list(rule.run(McpServerTarget(url, sender=open_server), RuleContext()))

    guarded = ScriptedMcpServer(url, credential="s3cret", tools=[…])
    assert not list(rule.run(McpServerTarget(url, sender=guarded), RuleContext()))
    ```
    """

    def __init__(  # noqa: PLR0913 — one keyword per behaviour a real server varies in
        self,
        url: str,
        *,
        tools: Sequence[Mapping[str, Any]] = (),
        credential: str | None = None,
        accepts_any_token: bool = False,
        session_authenticates: bool = False,
        session_ids: Sequence[str] = (),
        challenge: str | None = None,
        resource_metadata: Mapping[str, Any] | None = None,
        authorization_metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self.url = url
        self.tools = list(tools)
        self.credential = credential
        self.accepts_any_token = accepts_any_token
        self.session_authenticates = session_authenticates
        self.session_ids = list(session_ids)
        self.challenge = challenge
        self.resource_metadata = resource_metadata
        self.authorization_metadata = authorization_metadata
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self._handed_out = 0

    def __call__(
        self,
        url: str,
        *,
        method: str = "POST",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        alongside: str | None = None,
    ) -> RawReply:
        """Answer one request the way the configured server would.

        `alongside` is accepted and ignored: it exists so the real sender can guard
        each redirect hop, and this double never redirects. Taking it keeps the
        signature the one the `Sender` protocol publishes, so a double cannot drift
        out of the contract it stands in for.
        """
        sent = dict(headers or {})
        self.requests.append((method, url, sent))
        if method == "GET":
            return self._metadata(url)
        if url != self.url:
            return _reply(404, {})
        if not self._authorized(sent):
            return _reply(401, {}, headers=self._challenge_headers())
        return self._json_rpc(body)

    def _authorized(self, headers: Mapping[str, str]) -> bool:
        if self.credential is None:
            return True
        presented = headers.get("Authorization")
        if presented == f"Bearer {self.credential}":
            return True
        if presented is not None and self.accepts_any_token:
            return True
        return self.session_authenticates and "Mcp-Session-Id" in headers

    def _json_rpc(self, body: bytes | None) -> RawReply:
        request = json.loads((body or b"{}").decode("utf-8"))
        method = request.get("method")
        if method == "initialize":
            return _reply(
                200,
                {"protocolVersion": "2025-11-25", "capabilities": {}},
                headers=self._session_headers(),
            )
        if method == "tools/list":
            return _reply(200, {"tools": self.tools})
        return _reply(200, {})

    def _metadata(self, url: str) -> RawReply:
        path = urlsplit(url).path
        if path.startswith(_RESOURCE_METADATA_PATH) and self.resource_metadata is not None:
            return _document(self.resource_metadata)
        if (
            any(path.startswith(prefix) for prefix in _AUTHORIZATION_METADATA_PATHS)
            and self.authorization_metadata is not None
        ):
            return _document(self.authorization_metadata)
        return _reply(404, {})

    def _session_headers(self) -> dict[str, str]:
        if not self.session_ids:
            return {}
        issued = self.session_ids[min(self._handed_out, len(self.session_ids) - 1)]
        self._handed_out += 1
        return {"Mcp-Session-Id": issued}

    def _challenge_headers(self) -> dict[str, str]:
        return {"WWW-Authenticate": self.challenge} if self.challenge else {}


def _reply(
    status: int, result: Mapping[str, Any], *, headers: Mapping[str, str] | None = None
) -> RawReply:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode("utf-8")
    return RawReply(status=status, headers=dict(headers or {}), body=payload)


def _document(content: Mapping[str, Any]) -> RawReply:
    return RawReply(
        status=200,
        headers={"Content-Type": "application/json"},
        body=json.dumps(content).encode("utf-8"),
    )
