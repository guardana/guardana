"""Named transports reach non-OpenAI self-hosted backends. Each must hit the right
path and parse the right field — and fail closed on a shape it doesn't recognize,
never invent a reply."""

import json
from urllib.request import Request

import pytest
from guardana.core.target import ChatMessage, EndpointError, EndpointTarget
from guardana.core.target._providers import OllamaTransport, TgiTransport, select_transport
from guardana.core.target.endpoint import UrllibTransport


class _Canned:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, limit: int) -> bytes:
        return self._body[:limit]

    def __enter__(self) -> "_Canned":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return


def _patch(
    monkeypatch: pytest.MonkeyPatch, body: bytes, seen: dict[str, object] | None = None
) -> None:
    def fake_urlopen(request: Request, timeout: float) -> _Canned:
        if seen is not None:
            seen["url"] = request.full_url
            assert isinstance(request.data, bytes)
            seen["body"] = json.loads(request.data)
        return _Canned(body)

    monkeypatch.setattr("guardana.core.target.endpoint.urlopen", fake_urlopen)


def test_ollama_posts_to_api_chat_and_parses_message_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}
    _patch(monkeypatch, b'{"message": {"content": "hi from ollama"}}', seen)
    reply = OllamaTransport().send("http://x", "llama3", [ChatMessage("user", "hey")], None)
    assert reply == "hi from ollama"
    assert seen["url"] == "http://x/api/chat"
    assert seen["body"] == {
        "model": "llama3",
        "messages": [{"role": "user", "content": "hey"}],
        "stream": False,
    }


def test_tgi_posts_to_generate_and_parses_generated_text(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}
    _patch(monkeypatch, b'{"generated_text": "hi from tgi"}', seen)
    reply = TgiTransport().send("http://x", "m", [ChatMessage("user", "hey")], None)
    assert reply == "hi from tgi"
    assert seen["url"] == "http://x/generate"


def test_tgi_handles_a_list_response(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, b'[{"generated_text": "from a list"}]')
    assert TgiTransport().send("http://x", "m", [ChatMessage("user", "h")], None) == "from a list"


def test_ollama_unexpected_shape_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, b'{"nope": 1}')
    with pytest.raises(EndpointError, match="Ollama"):
        OllamaTransport().send("http://x", "m", [ChatMessage("user", "h")], None)


def test_tgi_unexpected_shape_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, b'{"nope": 1}')
    with pytest.raises(EndpointError, match="TGI"):
        TgiTransport().send("http://x", "m", [ChatMessage("user", "h")], None)


def test_ollama_non_string_content_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, b'{"message": {"content": 123}}')
    with pytest.raises(EndpointError, match="Ollama"):
        OllamaTransport().send("http://x", "m", [ChatMessage("user", "h")], None)


def test_tgi_non_string_generated_text_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, b'{"generated_text": 123}')
    with pytest.raises(EndpointError, match="TGI"):
        TgiTransport().send("http://x", "m", [ChatMessage("user", "h")], None)


def test_ollama_non_dict_payload_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, b'"just a string"')
    with pytest.raises(EndpointError, match="Ollama"):
        OllamaTransport().send("http://x", "m", [ChatMessage("user", "h")], None)


def test_tgi_empty_list_payload_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, b"[]")
    with pytest.raises(EndpointError, match="TGI"):
        TgiTransport().send("http://x", "m", [ChatMessage("user", "h")], None)


def test_endpoint_target_selects_the_named_provider_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}
    _patch(monkeypatch, b'{"message": {"content": "ok"}}', seen)
    target = EndpointTarget("http://x", "m", provider="ollama")
    assert target.chat([ChatMessage("user", "hi")]) == "ok"
    assert seen["url"] == "http://x/api/chat"


def test_select_transport_returns_the_named_provider() -> None:
    assert isinstance(select_transport("openai"), UrllibTransport)
    assert isinstance(select_transport("ollama"), OllamaTransport)
    assert isinstance(select_transport("tgi"), TgiTransport)


def test_select_transport_rejects_an_unknown_provider() -> None:
    with pytest.raises(EndpointError, match="unknown provider"):
        select_transport("bananamodel")
