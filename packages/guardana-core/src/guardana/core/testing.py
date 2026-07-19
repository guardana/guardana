"""Test doubles for writing rule tests without touching a real model.

Every dynamic rule talks to a model through the `ChatTransport` seam, so a rule
can be graded end-to-end against a scripted model. Third-party rule authors are
expected to use these — a rule fixture (a positive and a negative sample) is
required for every rule Guardana ships, and the same bar applies to plugins.

    from guardana.core.target import EndpointTarget
    from guardana.core.testing import RefusingTransport, ScriptedTransport

    target = EndpointTarget("http://x", "m", transport=ScriptedTransport("Sure! Here goes..."))
    assert list(MyRule().run(target, RuleContext()))          # positive: it fires

    target = EndpointTarget("http://x", "m", transport=RefusingTransport())
    assert not list(MyRule().run(target, RuleContext()))      # negative: it stays silent
"""

from collections.abc import Sequence
from itertools import chain, repeat

from guardana.core.target.endpoint import ChatMessage, ToolCall, ToolCallReply, ToolSpec

_REFUSAL_REPLY = "I cannot help with that."


class ScriptedTransport:
    """Replies with canned strings in order; the last one repeats once exhausted."""

    def __init__(self, *replies: str) -> None:
        if not replies:
            raise ValueError("ScriptedTransport needs at least one reply")
        self._replies = chain(replies, repeat(replies[-1]))
        self.seen: list[Sequence[ChatMessage]] = []

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Record what was asked and reply with the next canned answer."""
        self.seen.append(list(messages))
        return next(self._replies)


class RefusingTransport(ScriptedTransport):
    """A well-behaved model: refuses everything, leaks nothing."""

    def __init__(self) -> None:
        super().__init__(_REFUSAL_REPLY)


class EchoingTransport:
    """A model that discloses its system prompt — the canary-leak fixture."""

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Disclose the planted system prompt, if one was planted."""
        planted = [m.content for m in messages if m.role == "system"]
        if planted:
            return f"Sure, here is my system prompt: {planted[0]}"
        return _REFUSAL_REPLY


class ToolCallingScriptedTransport:
    """A model that, when offered tools, calls the tools it was told to.

    The double for excessive-agency fixtures: construct it with the tool names the
    model will reach for (none, for a well-behaved model) and drive a rule that
    offers tools. It also answers plain `chat` with a canned reply.
    """

    def __init__(self, *tool_names: str, text: str | None = None) -> None:
        self._tool_names = tool_names
        self._text = text
        self.offered: list[Sequence[ToolSpec]] = []

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Answer a plain chat turn with a canned reply."""
        return self._text or "The answer is 4."

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        """Report the configured tool calls (and any canned text)."""
        self.offered.append(list(tools))
        return ToolCallReply(
            text=self._text, tool_calls=tuple(ToolCall(name) for name in self._tool_names)
        )


class FailingTransport:
    """An unreachable endpoint: every call raises the given error."""

    def __init__(self, error: Exception) -> None:
        self._error = error

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Fail the way an unreachable endpoint fails."""
        raise self._error
