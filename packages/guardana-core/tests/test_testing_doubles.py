import pytest
from guardana.core.target import ChatMessage, EndpointTarget
from guardana.core.testing import (
    EchoingTransport,
    FailingTransport,
    RefusingTransport,
    ScriptedTransport,
)


def test_scripted_transport_returns_replies_in_order_then_repeats_last() -> None:
    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("first", "second"))

    replies = [target.chat([ChatMessage("user", "hi")]) for _ in range(3)]

    assert replies == ["first", "second", "second"]


def test_scripted_transport_records_what_it_was_sent() -> None:
    transport = ScriptedTransport("ok")
    target = EndpointTarget("http://x", "m", system_prompt="be nice", transport=transport)

    target.chat([ChatMessage("user", "hi")])

    assert [m.role for m in transport.seen[0]] == ["system", "user"]


def test_scripted_transport_requires_a_reply() -> None:
    with pytest.raises(ValueError, match="at least one reply"):
        ScriptedTransport()


def test_refusing_transport_refuses() -> None:
    target = EndpointTarget("http://x", "m", transport=RefusingTransport())

    assert "cannot help" in target.chat([ChatMessage("user", "hi")])


def test_echoing_transport_discloses_planted_system_prompt() -> None:
    target = EndpointTarget(
        "http://x", "m", system_prompt="token: ABC", transport=EchoingTransport()
    )

    assert "token: ABC" in target.chat([ChatMessage("user", "hi")])


def test_echoing_transport_without_system_prompt_refuses() -> None:
    target = EndpointTarget("http://x", "m", transport=EchoingTransport())

    assert "cannot help" in target.chat([ChatMessage("user", "hi")])


def test_failing_transport_raises_the_given_error() -> None:
    target = EndpointTarget("http://x", "m", transport=FailingTransport(OSError("refused")))

    with pytest.raises(OSError, match="refused"):
        target.chat([ChatMessage("user", "hi")])
