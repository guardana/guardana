"""Seven defects an adversarial review found in the MCP authorization work.

Kept in one file because they share an origin rather than a subject: each is a
place where the code reached a confident answer it had not earned, and each is now
pinned by a test that fails if the answer goes back.
"""

from guardana.core.rule import RuleContext
from guardana.core.target import McpServerTarget
from guardana.core.target._mcp_http import RawReply
from guardana.core.testing import ScriptedMcpServer
from guardana.rules.mcp import (
    McpAuthorizationDiscoveryRule,
    McpSessionBindingRule,
    McpTokenAudienceRule,
    McpUnauthenticatedAccessRule,
)
from mcp_fixtures import CONFORMING_RESOURCE, CREDENTIAL, ROUTABLE, findings, guarded, outcomes

_TOOLS = [{"name": "read_file", "description": "Read a file."}]


class _SseServer(ScriptedMcpServer):
    """A server that answers over `text/event-stream`, which the specification allows.

    The client asks for it by name in every `Accept` header, and `result_of` has
    parsed it since 0.5 — but the authorization observations used a plain
    `json.loads`, so a perfectly good tool listing read as a refusal.
    """

    def __call__(self, url: str, **kwargs: object) -> RawReply:
        reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
        if url != self.url:
            return reply
        framed = b"event: message\ndata: " + reply.body + b"\n\n"
        return RawReply(
            status=reply.status,
            headers={**reply.headers, "Content-Type": "text/event-stream"},
            body=framed,
        )


def test_a_tool_listing_delivered_over_sse_is_still_a_tool_listing() -> None:
    # Read as a refusal, this silenced three checks at once and made a fourth
    # report a HIGH about missing metadata on an open development server.
    server = _SseServer(ROUTABLE, tools=_TOOLS)

    reported = findings(McpUnauthenticatedAccessRule(), server)

    assert reported, "an SSE tool listing read as a server that refused"
    assert "no credential" in reported[0].evidence.summary


def test_an_sse_server_does_not_get_a_metadata_finding_it_never_earned() -> None:
    server = _SseServer(ROUTABLE, tools=_TOOLS)

    assert findings(McpAuthorizationDiscoveryRule(), server) == []


def test_a_reply_nobody_can_parse_is_not_a_refusal() -> None:
    # `False` meant "the server declined", and an unreadable body was folded into
    # it — a pass on a question that was never answered.
    class _Gibberish(ScriptedMcpServer):
        def __call__(self, url: str, **kwargs: object) -> RawReply:
            reply = super().__call__(url, **kwargs)  # type: ignore[arg-type]
            if url != self.url:
                return reply
            return RawReply(status=200, headers=reply.headers, body=b"<html>not json</html>")

    reported = findings(McpUnauthenticatedAccessRule(), _Gibberish(ROUTABLE, tools=_TOOLS))

    assert outcomes(reported) == ["inconclusive"]
    assert "could not be read" in reported[0].evidence.summary


def test_the_session_sample_does_not_depend_on_which_rules_ran() -> None:
    # A server issuing one session per credential: reusing ids recorded by other
    # sections meant `session_binding` alone saw three identical ids and reported a
    # critical finding, while the same server with `token_audience` also selected
    # saw a fourth and reported nothing. A profile exclusion must not change what is
    # true about the target.
    def verdict(*, read_the_token_probe: bool) -> list[str]:
        server = guarded(session_ids=["one-and-only-session"] * 6, accepts_any_token=True)
        target = McpServerTarget(ROUTABLE, credential=CREDENTIAL, sender=server)
        if read_the_token_probe:
            list(McpTokenAudienceRule().run(target, RuleContext()))
        return [f.evidence.summary for f in McpSessionBindingRule().run(target, RuleContext())]

    assert verdict(read_the_token_probe=False) == verdict(read_the_token_probe=True)
    assert any("same session id" in line for line in verdict(read_the_token_probe=True))


def test_a_default_port_written_out_is_the_same_origin() -> None:
    # RFC 9728 documents omit `:443`, so comparing netloc verbatim reported a
    # conforming deployment the moment an operator wrote the port in `--mcp`.
    server = ScriptedMcpServer(
        "https://93.184.215.14:443/mcp",
        tools=_TOOLS,
        credential=CREDENTIAL,
        challenge=(
            "Bearer resource_metadata="
            '"https://93.184.215.14/.well-known/oauth-protected-resource", scope="s"'
        ),
        resource_metadata=CONFORMING_RESOURCE,
        authorization_metadata={"code_challenge_methods_supported": ["S256"]},
    )

    reported = findings(McpAuthorizationDiscoveryRule(), server, credential=CREDENTIAL)

    assert [f.evidence.summary for f in reported] == []


def test_an_injected_transport_alone_does_not_claim_an_authorization_surface() -> None:
    # Injecting a transport replaces the JSON-RPC half and not the HTTP half.
    # Claiming the capability anyway sent the authorization probe to the real
    # network from tests that believed they had none.
    class _Transport:
        def speak(self, wire: object) -> None:
            pass

        def request(self, method: str, params: object) -> dict[str, object]:
            return {"protocolVersion": "x"} if method == "initialize" else {"tools": []}

        def close(self) -> None:
            return None

    target = McpServerTarget("https://mcp.example/api", transport=_Transport())

    assert "inspect_authorization" not in {c.value for c in target.capabilities()}
