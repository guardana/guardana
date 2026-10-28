"""A guarded endpoint's declines, retried statuses and metadata, against a local HTTP double.

A declared decline is raised as `RequestDeclined`, never graded as reply text and never
ended as an unreachable endpoint; an undeclared error reply is raised as the `HTTPError`
it is, its body still readable; the metadata a reply carries arrives in `ChatReply.meta`.
"""

import io
from collections.abc import Iterator, Sequence
from email.message import Message
from urllib.error import HTTPError

import pytest
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.keeping import ExchangeKeeper
from guardana.core.redaction import EvidenceMode, EvidenceRedactor, RedactionPolicy
from guardana.core.target import (
    ChatMessage,
    ChatReply,
    ChatWithMetadata,
    DeclaredDecline,
    Decline,
    DeclineReading,
    EndpointError,
    EndpointTarget,
    MetadataReportingTransport,
    RequestDeclined,
)
from guardana.core.target.adapter import (
    DEFAULT_RETRY_STATUSES,
    AdapterConfig,
    HttpAdapterTransport,
    _post,
)
from guardana.core.target.endpoint import UsageReportingTransport
from guardana.core.testing import ScriptedTransport
from guardana.core.testing._fake_provider import (
    FakeProvider,
    Scripted,
    adapter_reply,
    status_reply,
)

_HELLO = (ChatMessage(role="user", content="hello"),)
_FILTER = DeclaredDecline(
    name="content_filter",
    statuses=frozenset({400, 422}),
    reading=DeclineReading.REFUSAL,
    path="error.code",
    equals="content_policy",
)
_TOO_LARGE = DeclaredDecline(
    name="input_rejected", statuses=frozenset({413}), reading=DeclineReading.UNGRADED
)
_BLOCKED = DeclaredDecline(
    name="blocked_in_body",
    statuses=frozenset({200}),
    reading=DeclineReading.REFUSAL,
    path="guard.blocked",
    equals=True,
)


@pytest.fixture
def provider() -> Iterator[FakeProvider]:
    with FakeProvider() as double:
        yield double


@pytest.fixture
def slept(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    recorded: list[float] = []
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", recorded.append)
    return recorded


def _target(
    provider: FakeProvider,
    *,
    declines: Sequence[DeclaredDecline] = (_FILTER, _TOO_LARGE, _BLOCKED),
    retry_statuses: frozenset[int] = DEFAULT_RETRY_STATUSES,
    metadata_paths: dict[str, str] | None = None,
    budgets: Budgets | None = None,
) -> EndpointTarget:
    config = AdapterConfig(
        url=f"{provider.url}/chat",
        body={"message": "{{prompt}}"},
        response_path="data.reply",
        declines=tuple(declines),
        retry_statuses=retry_statuses,
        metadata_paths=metadata_paths or {},
    )
    return EndpointTarget(
        provider.url, "app", transport=HttpAdapterTransport(config), budgets=budgets
    )


def _declined(target: EndpointTarget) -> RequestDeclined:
    with pytest.raises(RequestDeclined) as raised:
        target.chat_reply(_HELLO)
    return raised.value


def test_a_declared_error_reply_is_a_decline_with_its_reading(provider: FakeProvider) -> None:
    provider.script(adapter_reply(None, fields={"error": {"code": "content_policy"}}, status=422))

    declined = _declined(_target(provider))

    assert declined.decline == Decline("content_filter", DeclineReading.REFUSAL, 422)
    assert str(declined) == "declined by the application: content_filter (HTTP 422)"


def test_a_status_alone_declares_an_ungraded_decline_whatever_the_body(
    provider: FakeProvider,
) -> None:
    provider.script(Scripted(status=413, body=b"<html>request entity too large</html>"))

    declined = _declined(_target(provider))

    assert declined.decline == Decline("input_rejected", DeclineReading.UNGRADED, 413)


def test_the_first_entry_that_matches_names_the_decline(provider: FakeProvider) -> None:
    broad = DeclaredDecline(
        name="any_400", statuses=frozenset({400}), reading=DeclineReading.UNGRADED
    )
    provider.script(
        adapter_reply(None, fields={"error": {"code": "content_policy"}}, status=400),
        adapter_reply(None, fields={"error": {"code": "content_policy"}}, status=400),
    )

    assert _declined(_target(provider, declines=(_FILTER, broad))).decline.name == "content_filter"
    assert _declined(_target(provider, declines=(broad, _FILTER))).decline.name == "any_400"


def test_an_entry_whose_value_differs_passes_to_the_next(provider: FakeProvider) -> None:
    broad = DeclaredDecline(
        name="any_400", statuses=frozenset({400}), reading=DeclineReading.UNGRADED
    )
    provider.script(adapter_reply(None, fields={"error": {"code": "bad_json"}}, status=400))

    assert _declined(_target(provider, declines=(_FILTER, broad))).decline.name == "any_400"


def _coded(equals: str | float | bool) -> DeclaredDecline:
    return DeclaredDecline(
        name="coded",
        statuses=frozenset({400}),
        reading=DeclineReading.REFUSAL,
        path="error.code",
        equals=equals,
    )


@pytest.mark.parametrize(
    ("found", "equals"),
    [(1, "1"), ("1", 1), (True, 1), (1, True), (None, "null"), ({"v": 1}, 1)],
)
def test_a_value_of_another_json_type_never_equals(
    provider: FakeProvider, found: object, equals: str | float | bool
) -> None:
    provider.script(adapter_reply(None, fields={"error": {"code": found}}, status=400))

    with pytest.raises(HTTPError) as raised:
        _target(provider, declines=(_coded(equals),)).chat_reply(_HELLO)
    raised.value.close()


def test_a_number_equals_the_same_number_however_written(provider: FakeProvider) -> None:
    provider.script(adapter_reply(None, fields={"error": {"code": 1.0}}, status=400))

    assert _declined(_target(provider, declines=(_coded(1),))).decline.name == "coded"


def test_an_undeclared_error_reply_is_raised_with_its_body_readable(
    provider: FakeProvider,
) -> None:
    provider.script(adapter_reply(None, fields={"error": {"code": "bad_json"}}, status=400))

    with pytest.raises(HTTPError) as raised:
        _target(provider).chat_reply(_HELLO)

    assert raised.value.code == 400
    assert b'"bad_json"' in raised.value.read()
    raised.value.close()


def test_an_error_body_that_is_not_json_matches_no_path_entry(provider: FakeProvider) -> None:
    provider.script(Scripted(status=400, body=b"content_policy"))

    with pytest.raises(HTTPError) as raised:
        _target(provider).chat_reply(_HELLO)

    assert raised.value.read() == b"content_policy"
    raised.value.close()


def test_a_2xx_flagged_without_an_answer_is_a_decline(provider: FakeProvider) -> None:
    provider.script(
        adapter_reply(None, fields={"guard": {"blocked": True}}),
        adapter_reply("   ", fields={"guard": {"blocked": True}}),
    )
    target = _target(provider)

    assert _declined(target).decline == Decline("blocked_in_body", DeclineReading.REFUSAL, 200)
    assert _declined(target).decline.name == "blocked_in_body"


def test_a_2xx_flagged_that_still_delivers_an_answer_is_graded_on_the_answer(
    provider: FakeProvider,
) -> None:
    provider.script(adapter_reply("here it is anyway", fields={"guard": {"blocked": True}}))

    assert _target(provider).chat_reply(_HELLO).text == "here it is anyway"


def test_a_2xx_not_flagged_and_without_an_answer_still_fails_closed(
    provider: FakeProvider,
) -> None:
    provider.script(adapter_reply(None, fields={"guard": {"blocked": False}}))

    with pytest.raises(EndpointError, match=r"data\.reply"):
        _target(provider).chat_reply(_HELLO)


def test_a_decline_is_sent_once_and_counted_once(
    provider: FakeProvider, slept: list[float]
) -> None:
    provider.script(adapter_reply(None, fields={"error": {"code": "content_policy"}}, status=400))
    target = _target(provider, budgets=Budgets(max_requests=5))

    _declined(target)

    assert len(provider.requests) == 1
    assert target.usage().requests == 1
    assert slept == []


def test_a_decline_needs_a_request_the_ceiling_still_allows(provider: FakeProvider) -> None:
    provider.script(adapter_reply(None, fields={"error": {"code": "content_policy"}}, status=400))
    target = _target(provider, budgets=Budgets(max_requests=1))

    _declined(target)
    with pytest.raises(BudgetExhausted):
        target.chat_reply(_HELLO)

    assert len(provider.requests) == 1


def test_the_retried_set_is_the_one_the_adapter_names(
    provider: FakeProvider, slept: list[float]
) -> None:
    provider.script(status_reply(502, retry_after="0"), adapter_reply("recovered"))
    target = _target(provider, retry_statuses=frozenset({502}))

    assert target.chat(_HELLO) == "recovered"
    assert len(provider.requests) == 2
    assert target.usage().requests == 2


def test_a_status_left_out_of_the_retried_set_is_raised_at_once(
    provider: FakeProvider, slept: list[float]
) -> None:
    provider.script(status_reply(503, retry_after="0"), adapter_reply("recovered"))
    target = _target(provider, retry_statuses=frozenset({502}))

    with pytest.raises(HTTPError) as raised:
        target.chat(_HELLO)
    raised.value.close()

    assert raised.value.code == 503
    assert len(provider.requests) == 1
    assert slept == []


def test_an_empty_retried_set_retries_not_even_a_rate_limit(
    provider: FakeProvider, slept: list[float]
) -> None:
    provider.script(status_reply(429, retry_after="0"), adapter_reply("recovered"))
    target = _target(provider, retry_statuses=frozenset())

    with pytest.raises(HTTPError) as raised:
        target.chat(_HELLO)
    raised.value.close()

    assert raised.value.code == 429
    assert len(provider.requests) == 1


_META = {
    "text": "meta.text",
    "number": "meta.number",
    "fraction": "meta.fraction",
    "flag": "meta.flag",
    "absent": "meta.absent",
    "nothing": "meta.nothing",
    "object": "meta.object",
    "listed": "meta.listed",
    "long": "meta.long",
    "at_limit": "meta.at_limit",
    "indexed": "meta.listed.0",
}


def _meta_fields() -> dict[str, object]:
    return {
        "meta": {
            "text": "self_harm",
            "number": 3,
            "fraction": 0.5,
            "flag": False,
            "nothing": None,
            "object": {"a": 1},
            "listed": ["first"],
            "long": "x" * 1025,
            "at_limit": "y" * 1024,
        }
    }


def test_metadata_keeps_short_scalars_and_leaves_out_everything_else(
    provider: FakeProvider,
) -> None:
    provider.script(adapter_reply("answer", fields=_meta_fields()))

    reply = _target(provider, metadata_paths=_META).chat_reply(_HELLO)

    assert reply.text == "answer"
    assert reply.meta == {
        "text": "self_harm",
        "number": "3",
        "fraction": "0.5",
        "flag": "false",
        "at_limit": "y" * 1024,
        "indexed": "first",
    }


def test_a_declined_reply_carries_its_metadata(provider: FakeProvider) -> None:
    provider.script(
        adapter_reply(
            None,
            fields={"error": {"code": "content_policy"}, "meta": {"request_id": "req-7"}},
            status=400,
        )
    )

    declined = _declined(_target(provider, metadata_paths={"request_id": "meta.request_id"}))

    assert declined.meta == {"request_id": "req-7"}


def test_chat_returns_the_text_chat_reply_carries(provider: FakeProvider) -> None:
    provider.script(adapter_reply("answer", fields={"meta": {"text": "x"}}))

    assert _target(provider, metadata_paths={"text": "meta.text"}).chat(_HELLO) == "answer"


def test_the_adapter_reports_metadata_and_never_claims_token_counts() -> None:
    transport = HttpAdapterTransport(
        AdapterConfig(url="http://x/chat", body={"m": "{{prompt}}"}, response_path="reply")
    )

    assert isinstance(transport, MetadataReportingTransport)
    assert not isinstance(transport, UsageReportingTransport)


def test_an_endpoint_is_a_chat_with_metadata_on_any_transport() -> None:
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("plain"))

    assert isinstance(target, ChatWithMetadata)
    assert target.chat_reply(_HELLO) == ChatReply(text="plain")


def _redacted() -> EvidenceRedactor:
    return EvidenceRedactor(RedactionPolicy(mode=EvidenceMode.FULL))


def test_chat_reply_keeps_the_exchange_as_chat_does(provider: FakeProvider) -> None:
    provider.script(adapter_reply("kept answer", fields={"meta": {"text": "x"}}))
    target = _target(provider, metadata_paths={"text": "meta.text"})
    keeper = ExchangeKeeper()
    target.keep_exchanges(keeper)

    target.for_rule("acme.one").chat_reply(_HELLO)

    (kept,) = keeper.recorded(_redacted())
    assert (kept.rule, kept.input[-1].content, kept.reply) == ("acme.one", "hello", "kept answer")


def test_a_declined_request_is_kept_as_the_decline_with_its_metadata_and_propagates(
    provider: FakeProvider,
) -> None:
    provider.script(
        adapter_reply(
            None,
            fields={"error": {"code": "content_policy"}, "meta": {"text": "weapons"}},
            status=400,
        )
    )
    target = _target(provider, metadata_paths={"category": "meta.text"})
    keeper = ExchangeKeeper()
    target.keep_exchanges(keeper)

    _declined(target.for_rule("acme.one"))

    (kept,) = keeper.recorded(_redacted())
    assert kept.reply is None
    assert kept.declined == Decline("content_filter", DeclineReading.REFUSAL, 400)
    assert kept.meta == {"category": "weapons"}
    assert not kept.altered


class _Reshaping(EndpointTarget):
    """A pack's endpoint that shapes every reply its own way."""

    def chat(self, messages: Sequence[ChatMessage]) -> str:
        return "PACK " + super().chat(messages)


def test_a_subclass_that_reshapes_chat_is_answered_through_it() -> None:
    target = _Reshaping("http://x", "m", transport=ScriptedTransport("reply"))

    assert target.chat_reply(_HELLO).text == "PACK reply"


class _UnclosableBody(io.BytesIO):
    """A reply body whose first `close()` fails, as a connection torn down underneath it can.

    Later calls close it, so the finaliser that closes the error again at collection is quiet.
    """

    failed = False

    def close(self) -> None:
        if not self.failed:
            self.failed = True
            raise OSError("the connection is already gone")
        super().close()


def _post_meeting(error: HTTPError, monkeypatch: pytest.MonkeyPatch) -> tuple[int, bytes]:
    def refused(*args: object, **kwargs: object) -> bytes:
        raise error

    monkeypatch.setattr("guardana.core.target.adapter.read_with_retry", refused)
    reply = _post("http://guarded.example/chat", b"{}", {}, timeout=1, retry_statuses=frozenset())
    return reply.status, reply.body


def test_an_error_reply_is_closed_once_its_body_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    error = HTTPError("http://x", 400, "Bad Request", Message(), io.BytesIO(b"blocked"))

    assert _post_meeting(error, monkeypatch) == (400, b"blocked")
    assert error.fp.closed


def test_an_error_reply_that_fails_to_close_is_read_all_the_same(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = HTTPError("http://x", 400, "Bad Request", Message(), _UnclosableBody(b"blocked"))

    assert _post_meeting(error, monkeypatch) == (400, b"blocked")
