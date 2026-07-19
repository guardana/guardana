import json
from collections.abc import Sequence
from urllib.request import Request

import pytest
from guardana.core.target import Capability, TargetKind
from guardana.core.target.endpoint import (
    ChatMessage,
    EndpointError,
    EndpointTarget,
    UrllibTransport,
    _extract_content,
    _extract_tool_reply,
)


class _FakeTransport:
    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.seen: list[ChatMessage] = []
        self.base_url = ""

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        self.base_url = base_url
        self.seen = list(messages)
        return self.reply


def test_endpoint_sends_and_returns_reply() -> None:
    tx = _FakeTransport("I cannot help with that.")
    target = EndpointTarget("http://x", "m", transport=tx)

    assert target.kind is TargetKind.ENDPOINT
    assert Capability.CHAT in target.capabilities()

    out = target.chat([ChatMessage("user", "hello")])

    assert out == "I cannot help with that."
    assert tx.seen[0].content == "hello"


def test_endpoint_prepends_system_prompt_when_set() -> None:
    tx = _FakeTransport("ok")
    target = EndpointTarget("http://x", "m", system_prompt="be nice", transport=tx)

    assert Capability.PLANT_SYSTEM_PROMPT in target.capabilities()

    target.chat([ChatMessage("user", "hello")])

    assert tx.seen[0].role == "system"
    assert tx.seen[0].content == "be nice"
    assert tx.seen[1].content == "hello"


def test_trailing_slash_base_url_is_normalized() -> None:
    tx = _FakeTransport("ok")
    target = EndpointTarget("http://x/", "m", transport=tx)

    target.chat([ChatMessage("user", "hi")])

    assert tx.base_url == "http://x"
    assert target.ref == "http://x#m"


@pytest.mark.parametrize("bad_url", ["file:///etc/passwd", "ftp://host/x", "not-a-url"])
def test_non_http_base_url_rejected(bad_url: str) -> None:
    with pytest.raises(EndpointError, match="scheme"):
        EndpointTarget(bad_url, "m")


def test_extract_content_happy_path() -> None:
    payload = {"choices": [{"message": {"content": "hi"}}]}
    assert _extract_content(payload, ref="http://x#m") == "hi"


@pytest.mark.parametrize(
    "payload",
    [{}, {"choices": []}, {"choices": [{"message": {}}]}, ["not", "a", "mapping"]],
)
def test_extract_content_rejects_unexpected_shapes(payload: object) -> None:
    with pytest.raises(EndpointError, match="unexpected response"):
        _extract_content(payload, ref="http://x#m")


def test_null_content_is_rejected_not_stringified() -> None:
    # A refusal / tool-call reply has content: null. str(None) → "None" would be
    # graded as a clean pass — the exact fail-open a security scanner must not have.
    payload = {"choices": [{"message": {"content": None}}]}
    with pytest.raises(EndpointError, match="no text content"):
        _extract_content(payload, ref="http://x#m")


class _CannedResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, limit: int) -> bytes:
        return self._body[:limit]

    def __enter__(self) -> "_CannedResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return


def test_non_json_response_raises_endpoint_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "guardana.core.target.endpoint.urlopen",
        lambda request, timeout: _CannedResponse(b"<html>502 Bad Gateway</html>"),
    )
    with pytest.raises(EndpointError, match="non-JSON"):
        UrllibTransport().send("http://x", "m", [ChatMessage("user", "hi")], None)


def test_openai_v1_base_url_is_not_doubled(monkeypatch: pytest.MonkeyPatch) -> None:
    # The conventional OpenAI base already carries `/v1`; send() re-appends the
    # path, so an un-normalized base would POST to `.../v1/v1/chat/completions`
    # and 404 against a correctly-configured endpoint.
    seen: dict[str, object] = {}

    def fake_urlopen(request: Request, timeout: float) -> _CannedResponse:
        seen["url"] = request.full_url
        return _CannedResponse(b'{"choices": [{"message": {"content": "ok"}}]}')

    monkeypatch.setattr("guardana.core.target.endpoint.urlopen", fake_urlopen)

    target = EndpointTarget("https://api.openai.com/v1", "m")
    reply = target.chat([ChatMessage("user", "hi")])

    assert reply == "ok"
    assert seen["url"] == "https://api.openai.com/v1/chat/completions"
    assert target.ref == "https://api.openai.com#m"


def test_urllib_transport_posts_openai_chat_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_urlopen(request: Request, timeout: float) -> _CannedResponse:
        body = request.data
        assert isinstance(body, bytes)
        seen["url"] = request.full_url
        seen["auth"] = request.get_header("Authorization")
        seen["body"] = json.loads(body)
        return _CannedResponse(b'{"choices": [{"message": {"content": "ok"}}]}')

    monkeypatch.setattr("guardana.core.target.endpoint.urlopen", fake_urlopen)

    reply = UrllibTransport().send("http://x", "m", [ChatMessage("user", "hi")], "k")

    assert reply == "ok"
    assert seen["url"] == "http://x/v1/chat/completions"
    assert seen["auth"] == "Bearer k"
    assert seen["body"] == {"model": "m", "messages": [{"role": "user", "content": "hi"}]}


def test_extract_tool_reply_parses_tool_calls_with_null_content() -> None:
    # A tool-call response has content: null and a tool_calls array — normal here.
    payload = {
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [
                        {"function": {"name": "run_shell_command", "arguments": "{}"}},
                        {"function": {"name": "calculator", "arguments": "2+2"}},
                    ],
                }
            }
        ]
    }
    reply = _extract_tool_reply(payload, ref="x#m")
    assert reply.text is None
    assert [c.name for c in reply.tool_calls] == ["run_shell_command", "calculator"]


def test_extract_tool_reply_skips_a_malformed_tool_call() -> None:
    payload = {"choices": [{"message": {"tool_calls": [{"function": {"arguments": "x"}}, "junk"]}}]}
    reply = _extract_tool_reply(payload, ref="x#m")
    assert reply.tool_calls == ()


def test_extract_tool_reply_rejects_a_broken_envelope() -> None:
    with pytest.raises(EndpointError):
        _extract_tool_reply({"no": "choices"}, ref="x#m")
