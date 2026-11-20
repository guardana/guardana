"""An access check sends one request, as asked, and classifies only what came back.

Run against a real HTTP double, so what is asserted is what reached the wire: the
anonymous request carries no credential, nothing is retried or followed, and only a
chat completion counts as an answer.
"""

import os
import subprocess
import sys
import textwrap

import pytest
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.target import Capability, EndpointTarget
from guardana.core.target.access import AccessAnswer, AccessCheckingTransport
from guardana.core.target.endpoint import ACCESS_CHECK_PROMPT, UrllibTransport
from guardana.core.testing import ScriptedTransport
from guardana.core.testing._fake_provider import (
    FakeProvider,
    Scripted,
    delayed,
    json_reply,
    malformed_reply,
    openai_reply,
    oversized_reply,
    redirect_reply,
    status_reply,
)

_KEY = "sk-test-not-a-real-key"
_PROXY_VARIABLES = ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY")


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


def _asked(url: str, **kwargs: object) -> EndpointTarget:
    return EndpointTarget(url, "m", inference_access_check=True, **kwargs)  # type: ignore[arg-type]


def test_the_anonymous_request_carries_no_credential_of_any_kind() -> None:
    with FakeProvider(openai_reply("OK")) as provider:
        reply = _asked(provider.url, api_key=_KEY).check_access(credentials=False)

    assert reply.answer is AccessAnswer.COMPLETION
    (sent,) = provider.requests
    leaked = {"authorization", "cookie", "proxy-authorization", "api-key", "x-api-key"}
    assert leaked.isdisjoint(sent.headers)
    assert _KEY not in repr(sent)


def test_the_control_request_carries_the_configured_key() -> None:
    with FakeProvider(openai_reply("OK")) as provider:
        _asked(provider.url, api_key=_KEY).check_access(credentials=True)

    assert provider.requests[0].headers["authorization"] == f"Bearer {_KEY}"


def test_the_request_is_one_short_non_streaming_completion_on_the_named_route() -> None:
    with FakeProvider(openai_reply("OK")) as provider:
        _asked(f"{provider.url}/v1", system_prompt="planted").check_access(credentials=False)

    (sent,) = provider.requests
    assert (sent.method, sent.path) == ("POST", "/v1/chat/completions")
    assert sent.body == {
        "model": "m",
        "messages": [{"role": "user", "content": ACCESS_CHECK_PROMPT}],
        "stream": False,
    }


@pytest.mark.parametrize("status", [401, 403])
def test_a_401_or_403_is_a_refusal(status: int) -> None:
    with FakeProvider(status_reply(status)) as provider:
        reply = _asked(provider.url).check_access(credentials=False)

    assert (reply.answer, reply.status) == (AccessAnswer.REFUSED, status)


@pytest.mark.parametrize(
    ("scripted", "reason"),
    [
        (status_reply(429, retry_after="0"), "rate limited"),
        (status_reply(503), "HTTP 503"),
        (status_reply(404), "HTTP 404"),
        (status_reply(407), "HTTP 407"),
        (malformed_reply(), "not JSON"),
        (json_reply({"error": {"message": "missing key"}}), "not a chat completion"),
        (json_reply({"choices": []}), "not a chat completion"),
        (Scripted(status=204), "HTTP 204"),
    ],
)
def test_anything_but_a_completion_or_a_refusal_is_undecided_after_one_request(
    scripted: Scripted, reason: str
) -> None:
    with FakeProvider(scripted) as provider:
        reply = _asked(provider.url).check_access(credentials=False)

    assert reply.answer is AccessAnswer.UNDECIDED
    assert reason in reply.reason
    assert len(provider.requests) == 1, "an access check is never retried"


def test_an_oversized_completion_is_undecided() -> None:
    with FakeProvider(oversized_reply(8 * 1024 * 1024 + 2)) as provider:
        reply = _asked(provider.url).check_access(credentials=False)

    assert reply.answer is AccessAnswer.UNDECIDED
    assert "over" in reply.reason


def test_a_redirect_is_undecided_and_never_followed() -> None:
    with (
        FakeProvider(openai_reply("OK")) as elsewhere,
        FakeProvider(redirect_reply(f"{elsewhere.url}/v1/chat/completions")) as provider,
    ):
        reply = _asked(provider.url).check_access(credentials=False)

    assert reply.answer is AccessAnswer.UNDECIDED
    assert "redirect" in reply.reason
    assert elsewhere.requests == []


def test_a_route_that_does_not_answer_is_undecided() -> None:
    with FakeProvider(delayed(openai_reply("OK"), 2.0)) as provider:
        transport = UrllibTransport(timeout=0.2)
        target = EndpointTarget(provider.url, "m", transport=transport, inference_access_check=True)
        reply = target.check_access(credentials=False)

    assert (reply.answer, reply.status) == (AccessAnswer.UNDECIDED, None)
    assert "did not answer" in reply.reason


def test_nothing_is_sent_unless_the_run_asked_for_the_check() -> None:
    with FakeProvider(openai_reply("OK")) as provider:
        target = EndpointTarget(provider.url, "m")
        reply = target.check_access(credentials=False)

    assert Capability.INFERENCE_ACCESS not in target.capabilities()
    assert (reply.answer, reply.sent) == (AccessAnswer.UNDECIDED, False)
    assert provider.requests == []
    assert Capability.INFERENCE_ACCESS in _asked(provider.url).capabilities()


def test_a_control_with_no_key_or_an_address_with_a_user_part_sends_nothing() -> None:
    with FakeProvider(openai_reply("OK")) as provider:
        no_key = _asked(provider.url).check_access(credentials=True)
        host = provider.url.removeprefix("http://")
        user_part = _asked(f"http://user:pw@{host}").check_access(credentials=False)

    assert (no_key.answer, no_key.sent) == (AccessAnswer.UNDECIDED, False)
    assert (user_part.answer, user_part.sent) == (AccessAnswer.UNDECIDED, False)
    assert provider.requests == []


def test_a_transport_that_cannot_send_an_access_check_is_never_asked_to() -> None:
    transport = ScriptedTransport("OK")
    assert not isinstance(transport, AccessCheckingTransport)

    reply = EndpointTarget(
        "http://127.0.0.1:9", "m", transport=transport, inference_access_check=True
    ).check_access(credentials=False)

    assert (reply.answer, reply.sent) == (AccessAnswer.UNDECIDED, False)
    assert transport.seen == []


def test_each_request_counts_against_the_run_budget_and_its_usage() -> None:
    usage = {"prompt_tokens": 7, "completion_tokens": 1, "total_tokens": 8}
    with FakeProvider(status_reply(401), openai_reply("OK", usage=usage)) as provider:
        target = _asked(provider.url, api_key=_KEY, budgets=Budgets(max_requests=2))
        target.check_access(credentials=False)
        target.check_access(credentials=True)
        with pytest.raises(BudgetExhausted):
            target.check_access(credentials=False)

    assert len(provider.requests) == 2
    assert target.usage().requests == 2


def test_a_proxy_from_the_environment_is_recorded_on_the_reply() -> None:
    # In a child process: urllib's opener takes the environment's proxies when it is built,
    # at import, as it does in a real run.
    child = textwrap.dedent("""
        from guardana.core.target import EndpointTarget
        target = EndpointTarget("http://model.invalid", "m", inference_access_check=True)
        reply = target.check_access(credentials=False)
        print(reply.answer, reply.via_proxy)
    """)
    with FakeProvider(openai_reply("OK")) as proxy:
        environment = {k: v for k, v in os.environ.items() if k not in _PROXY_VARIABLES}
        environment |= {"http_proxy": proxy.url, "no_proxy": ""}
        ran = subprocess.run(  # noqa: S603 — a fixed command, this interpreter
            [sys.executable, "-c", child],
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )

    assert ran.stdout.split() == ["completion", "True"]
    assert proxy.requests[0].path == "http://model.invalid/v1/chat/completions"
