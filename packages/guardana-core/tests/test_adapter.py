from collections.abc import Mapping

import pytest
from guardana.core.target import AdapterConfig, ChatMessage, EndpointError, HttpAdapterTransport
from guardana.core.target.adapter import extract_path


def _stub_fetch(url: str, data: bytes, headers: Mapping[str, str]) -> object:
    return {}


def test_transport_fills_prompt_and_extracts_wrapped_reply() -> None:
    captured: dict[str, object] = {}

    def fake_fetch(url: str, data: bytes, headers: Mapping[str, str]) -> object:
        captured["url"] = url
        captured["data"] = data
        captured["headers"] = dict(headers)
        return {"data": {"reply": "the model said hi"}}

    config = AdapterConfig(
        url="https://api.example.com/v1/wellness/chat",
        body={"message": "{{prompt}}", "user_id_hash": "guardana"},
        response_path="data.reply",
        headers={"X-Api-Key": "secret123"},
    )
    transport = HttpAdapterTransport(config, fetch=fake_fetch)
    reply = transport.send(
        "https://api.example.com", "m", [ChatMessage(role="user", content="hello there")], None
    )
    assert reply == "the model said hi"
    assert b"hello there" in captured["data"]  # type: ignore[operator]
    assert captured["headers"] == {"X-Api-Key": "secret123"}
    assert captured["url"] == "https://api.example.com/v1/wellness/chat"


def test_transport_rejects_body_without_prompt_slot() -> None:
    config = AdapterConfig(url="https://x", body={"message": "static"}, response_path="reply")
    with pytest.raises(EndpointError):
        HttpAdapterTransport(config, fetch=_stub_fetch)


def test_transport_rejects_non_http_scheme() -> None:
    config = AdapterConfig(url="ftp://x", body={"m": "{{prompt}}"}, response_path="r")
    with pytest.raises(EndpointError):
        HttpAdapterTransport(config, fetch=_stub_fetch)


def test_extract_path_missing_key_fails_closed() -> None:
    with pytest.raises(EndpointError):
        extract_path({"data": {}}, "data.reply", ref="x")


def test_extract_path_non_string_leaf_fails_closed() -> None:
    with pytest.raises(EndpointError):
        extract_path({"data": {"reply": 42}}, "data.reply", ref="x")


def test_extract_path_indexes_into_lists() -> None:
    assert extract_path({"choices": [{"text": "hi"}]}, "choices.0.text", ref="x") == "hi"


def test_system_prompt_folded_into_prompt_when_no_slot() -> None:
    captured: dict[str, bytes] = {}

    def fake_fetch(url: str, data: bytes, headers: Mapping[str, str]) -> object:
        captured["data"] = data
        return {"reply": "ok"}

    config = AdapterConfig(url="https://x", body={"message": "{{prompt}}"}, response_path="reply")
    transport = HttpAdapterTransport(config, fetch=fake_fetch)
    transport.send(
        "https://x",
        "m",
        [ChatMessage(role="system", content="CANARY123"), ChatMessage(role="user", content="hi")],
        None,
    )
    # The planted system prompt must reach the endpoint, not be silently dropped.
    assert b"CANARY123" in captured["data"]


def test_system_slot_used_when_present() -> None:
    captured: dict[str, bytes] = {}

    def fake_fetch(url: str, data: bytes, headers: Mapping[str, str]) -> object:
        captured["data"] = data
        return {"reply": "ok"}

    config = AdapterConfig(
        url="https://x",
        body={"system": "{{system}}", "message": "{{prompt}}"},
        response_path="reply",
    )
    transport = HttpAdapterTransport(config, fetch=fake_fetch)
    transport.send(
        "https://x",
        "m",
        [ChatMessage(role="system", content="SYS"), ChatMessage(role="user", content="hi")],
        None,
    )
    assert b"SYS" in captured["data"]
