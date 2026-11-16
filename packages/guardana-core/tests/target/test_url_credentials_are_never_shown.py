"""A URL is shown and saved without the places a credential hides in it.

Userinfo, a query and a fragment can each carry a key. Every target `ref` and every
message that names a target URL goes through `display_url`, so a run document, a
SARIF `uri` or a line on stderr never repeats one — while a plain URL keeps the exact
spelling it always had, because a `ref` is part of a finding's identity.
"""

import re
from collections.abc import Callable, Mapping, Sequence
from io import BytesIO
from urllib.error import HTTPError, URLError

import pytest
from guardana.core.reporter import check_collector_url
from guardana.core.target import (
    ChatTransport,
    EndpointError,
    EndpointTarget,
    McpError,
    McpServerTarget,
    display_url,
    private_url_parts,
)
from guardana.core.target._mcp_authorization import (
    _authorization_server_urls,
    _resource_metadata_urls,
)
from guardana.core.target._mcp_client import HttpMcpTransport
from guardana.core.target._mcp_http import RawReply, send
from guardana.core.target._providers import OllamaTransport, TgiTransport
from guardana.core.target.adapter import AdapterConfig, FetchedReply, HttpAdapterTransport
from guardana.core.target.endpoint import ChatMessage, UrllibTransport
from guardana.core.testing import ScriptedMcpServer, ScriptedTransport

_MARKER = "s3cretvalue"
_PLACEHOLDER = re.compile(r"\[redacted:query:[0-9a-f]{12}\]")
_HELLO = [ChatMessage(role="user", content="hi")]


@pytest.mark.parametrize(
    "url",
    [
        "http://x",
        "http://127.0.0.1:8000/v1",
        "https://API.Example.com/v1/",
        "http://[::1]:8080/api",
        "http://host:99999/v1",
        "http://host/v1?",
    ],
)
def test_a_url_with_nothing_to_hide_is_returned_byte_for_byte(url: str) -> None:
    assert display_url(url) == url


@pytest.mark.parametrize(
    "url", ["ftp://user:pw@host/x?key=1", "mcp+stdio://server", "host:8000", ""]
)
def test_a_url_that_is_not_http_is_returned_unchanged(url: str) -> None:
    assert display_url(url) == url


def test_userinfo_and_a_fragment_are_dropped() -> None:
    assert display_url(f"https://me:{_MARKER}@host:8443/v1#{_MARKER}") == "https://host:8443/v1"


def test_a_query_becomes_a_digest_placeholder_the_redactor_recognises() -> None:
    shown = display_url(f"http://host/v1?key={_MARKER}")

    assert _MARKER not in shown
    assert shown.startswith("http://host/v1?")
    assert _PLACEHOLDER.fullmatch(shown.split("?", 1)[1])


def test_two_queries_stay_two_deployments() -> None:
    first = display_url("http://host/v1?tenant=a")
    second = display_url("http://host/v1?tenant=b")

    assert first != second
    assert display_url("http://host/v1?tenant=a") == first


def test_cleaning_a_cleaned_url_changes_nothing() -> None:
    once = display_url(f"http://u:{_MARKER}@host/v1?key={_MARKER}#frag")

    assert display_url(once) == once


def test_the_parts_that_can_carry_a_credential_are_named() -> None:
    assert private_url_parts("http://host/v1") == ()
    assert private_url_parts("http://u:p@host/v1?k=1#f") == ("userinfo", "query", "fragment")
    assert private_url_parts("http://@host/v1") == ("userinfo",)
    assert private_url_parts("http://host/v1#f") == ("fragment",)


def test_a_plain_endpoint_ref_keeps_its_spelling() -> None:
    target = EndpointTarget("http://x/v1/", "m", transport=ScriptedTransport("ok"))

    assert target.ref == "http://x#m"


def test_an_endpoint_ref_cleans_the_base_url_before_the_model() -> None:
    target = EndpointTarget(
        f"http://u:{_MARKER}@x/v1?key={_MARKER}#frag", "m", transport=ScriptedTransport("ok")
    )

    assert _MARKER not in target.ref
    assert target.ref.endswith("#m")
    assert target.ref.count("#") == 1
    assert _PLACEHOLDER.search(target.ref)


@pytest.mark.parametrize(
    ("module", "transport"),
    [
        ("guardana.core.target.endpoint", UrllibTransport()),
        ("guardana.core.target._providers", OllamaTransport()),
        ("guardana.core.target._providers", TgiTransport()),
    ],
    ids=["openai", "ollama", "tgi"],
)
def test_a_transport_error_names_the_endpoint_without_its_query(
    monkeypatch: pytest.MonkeyPatch, module: str, transport: ChatTransport
) -> None:
    monkeypatch.setattr(f"{module}.post_json", lambda *args, **kwargs: {"unexpected": True})

    with pytest.raises(EndpointError) as raised:
        transport.send(f"http://host?key={_MARKER}", "m", _HELLO, None)

    assert _MARKER not in str(raised.value)
    assert "http://host?[redacted:query:" in str(raised.value)


def test_an_adapter_error_names_the_endpoint_without_its_query() -> None:
    config = AdapterConfig(
        url=f"https://api.example.com/chat?key={_MARKER}",
        body={"message": "{{prompt}}"},
        response_path="data.reply",
    )
    transport = HttpAdapterTransport(
        config, fetch=lambda url, data, headers: FetchedReply(200, b'{"data": {}}')
    )

    with pytest.raises(EndpointError) as raised:
        transport.send("ignored", "m", _HELLO, None)

    assert _MARKER not in str(raised.value)


def test_the_adapter_still_sends_to_its_full_url() -> None:
    sent: list[str] = []
    config = AdapterConfig(
        url=f"https://api.example.com/chat?key={_MARKER}",
        body={"message": "{{prompt}}"},
        response_path="reply",
    )

    def fetch(url: str, data: bytes, headers: Mapping[str, str]) -> FetchedReply:
        sent.append(url)
        return FetchedReply(200, b'{"reply": "ok"}')

    HttpAdapterTransport(config, fetch=fetch).send("ignored", "m", _HELLO, None)

    assert sent == [config.url]


def test_the_adapter_default_fetch_names_the_endpoint_without_its_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Response(BytesIO):
        status = 200

        def __enter__(self) -> "_Response":
            return self

        def __exit__(self, *exc: object) -> None:
            self.close()

    monkeypatch.setattr(
        "guardana.core.target.endpoint.open_unredirected",
        lambda *args, **kwargs: _Response(b"not json"),
    )
    config = AdapterConfig(
        url=f"https://api.example.com/chat?key={_MARKER}",
        body={"message": "{{prompt}}"},
        response_path="reply",
    )

    with pytest.raises(EndpointError) as raised:
        HttpAdapterTransport(config).send("ignored", "m", _HELLO, None)

    assert _MARKER not in str(raised.value)


def test_an_mcp_ref_and_its_authorization_view_carry_no_query() -> None:
    url = f"https://93.184.215.14/mcp?key={_MARKER}"
    server = ScriptedMcpServer(url)
    target = McpServerTarget(url, sender=server, discovery_sender=server)

    assert _MARKER not in target.ref
    assert _PLACEHOLDER.search(target.ref)
    assert _MARKER not in target.authorization().server


def test_an_unreachable_mcp_server_is_named_without_its_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Opener:
        def open(self, *args: object, **kwargs: object) -> object:
            raise URLError("Connection refused")

    monkeypatch.setattr("guardana.core.target._mcp_http.build_opener", lambda *handlers: _Opener())

    with pytest.raises(McpError) as raised:
        send(f"http://127.0.0.1:9/mcp?key={_MARKER}")

    assert _MARKER not in str(raised.value)
    assert "could not reach http://127.0.0.1:9/mcp?[redacted:query:" in str(raised.value)


def test_an_mcp_error_status_names_the_server_without_its_query() -> None:
    def refusing(url: str, **kwargs: object) -> RawReply:
        return RawReply(status=500, headers={}, body=b"")

    transport = HttpMcpTransport(f"http://host/mcp?key={_MARKER}", send=refusing)

    with pytest.raises(HTTPError) as raised:
        transport.request("tools/list", {})

    with raised.value as error:
        assert error.code == 500
        assert _MARKER not in str(error)
        assert _MARKER not in error.filename
        assert _PLACEHOLDER.search(error.filename)


def _junk(url: str, **kwargs: object) -> RawReply:
    return RawReply(status=200, headers={}, body=b"not json")


def _gone(url: str, **kwargs: object) -> RawReply:
    raise McpError(f"could not reach {display_url(url)}: connection refused")


@pytest.mark.parametrize("send_it", [_junk, _gone], ids=["unreadable", "unreachable"])
def test_an_mcp_reply_error_names_the_server_without_its_query(
    send_it: Callable[..., RawReply],
) -> None:
    transport = HttpMcpTransport(f"http://host/mcp?key={_MARKER}", send=send_it)

    with pytest.raises(EndpointError) as raised:
        transport.request("tools/list", {})

    assert _MARKER not in str(raised.value)
    assert _PLACEHOLDER.search(str(raised.value))


def test_well_known_addresses_never_carry_the_server_userinfo() -> None:
    derived: Sequence[str] = (
        *_resource_metadata_urls(f"https://me:{_MARKER}@host/mcp", None),
        *_authorization_server_urls(f"https://me:{_MARKER}@issuer/tenant"),
        *_authorization_server_urls(f"https://me:{_MARKER}@issuer"),
    )

    assert derived
    assert all(_MARKER not in url and "@" not in url for url in derived)
    assert "https://host/.well-known/oauth-protected-resource/mcp" in derived


@pytest.mark.parametrize(
    "url",
    [
        f"http://user:{_MARKER}/rest@host/v1",
        f"http://user:{_MARKER}?rest@host/v1",
        f"http://user:{_MARKER}#rest@host/v1",
        f"http://user:12/{_MARKER}@host/v1",
        f"http://user:12?{_MARKER}@host/v1",
    ],
    ids=["slash", "question-mark", "hash", "numeric-start-slash", "numeric-start-query"],
)
def test_a_password_that_ends_the_host_early_is_never_shown(url: str) -> None:
    shown = display_url(url)

    assert _MARKER not in shown
    assert shown.startswith("[redacted:url:")
    assert display_url(shown) == shown


@pytest.mark.parametrize(
    "url",
    [
        f"http://user:{_MARKER}/rest@host/v1",
        f"http://user:{_MARKER}?rest@host/v1",
        f"http://user:12/{_MARKER}@host/v1",
    ],
)
def test_a_password_that_ends_the_host_early_counts_as_userinfo(url: str) -> None:
    assert "userinfo" in private_url_parts(url)


@pytest.mark.parametrize("url", [f"user:{_MARKER}@host:8000", f"ftp://{_MARKER}@host/v1"])
def test_a_url_that_is_not_http_is_refused_without_repeating_it(url: str) -> None:
    with pytest.raises(EndpointError) as refused:
        EndpointTarget(url, "m")

    assert _MARKER not in str(refused.value)
    assert "user" not in str(refused.value)


@pytest.mark.parametrize(
    "url", [f"collector:8000/?token={_MARKER}", f"https://u:{_MARKER}@127.0.0.1"]
)
def test_a_reporter_url_it_refuses_is_never_repeated(url: str) -> None:
    with pytest.raises(ValueError, match="reporter URL") as refused:
        check_collector_url(url)

    assert _MARKER not in str(refused.value)


@pytest.mark.parametrize(
    "url",
    [f"https://svc:1234?{_MARKER}@collector/", f"https://svc:1234#{_MARKER}@host/mcp"],
    ids=["numeric-start-question-mark", "numeric-start-hash"],
)
def test_a_numeric_password_start_cut_by_a_query_or_fragment_is_userinfo(url: str) -> None:
    assert "userinfo" in private_url_parts(url)
    assert _MARKER not in display_url(url)
    with pytest.raises(ValueError, match="reporter URL"):
        check_collector_url(url)


@pytest.mark.parametrize(
    "url", ["https://host/@scope/mcp", "https://registry.example/v1/@acme/tools"]
)
def test_an_at_sign_opening_a_path_segment_is_not_userinfo(url: str) -> None:
    assert private_url_parts(url) == ()
    assert display_url(url) == url


def test_an_email_in_the_query_keeps_the_host_and_redacts_the_query() -> None:
    shown = display_url("https://host/mcp?user=someone@example.com")

    assert shown.startswith("https://host/mcp?[redacted:query:")
    assert "example.com" not in shown
