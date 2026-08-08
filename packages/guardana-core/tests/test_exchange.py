"""The Exchange is the unit an evaluator grades: a conversation, not a bare string.
`reply_text` is the seam where fail-closed lives — no gradable reply is None, which
an evaluator must treat as inconclusive, never a pass."""

from guardana.core.exchange import Exchange, Provenance
from guardana.core.target import ChatMessage


def test_reply_text_is_the_final_assistant_reply() -> None:
    ex = Exchange((ChatMessage("user", "hi"), ChatMessage("assistant", "hello")))
    assert ex.reply_text == "hello"


def test_reply_text_is_none_when_the_last_turn_is_not_an_assistant_reply() -> None:
    # A conversation left on a user turn has no reply to grade — not an empty pass.
    ex = Exchange((ChatMessage("assistant", "hi"), ChatMessage("user", "and you?")))
    assert ex.reply_text is None


def test_reply_text_is_none_for_an_empty_exchange() -> None:
    assert Exchange(()).reply_text is None


def test_single_reply_builds_a_gradable_exchange() -> None:
    ex = Exchange.single_reply("the model's answer")
    assert ex.reply_text == "the model's answer"


def test_default_provenance_is_probe() -> None:
    assert Exchange.single_reply("x").provenance is Provenance.PROBE


def test_transcript_renders_every_turn() -> None:
    ex = Exchange((ChatMessage("user", "ask"), ChatMessage("assistant", "answer")))
    assert ex.transcript == "user: ask\nassistant: answer"


def test_an_assistant_turn_with_no_text_is_no_reply() -> None:
    """A model that said nothing has not demonstrated that it says nothing wrong.

    `content: null` is already refused at the transport, but `content: ""` is a
    real answer shape — an Azure content filter returns it, and so does a turn that
    carried only tool calls. It reached the evaluators as a string, where the canary
    grader read "the marker is not in this reply" and returned a pass at 0.95
    confidence on a reply that carried no evidence in either direction.
    """
    ex = Exchange((ChatMessage("user", "hi"), ChatMessage("assistant", "")))
    assert ex.reply_text is None


def test_a_reply_of_only_whitespace_is_no_reply_either() -> None:
    ex = Exchange((ChatMessage("user", "hi"), ChatMessage("assistant", "  \n ")))
    assert ex.reply_text is None
