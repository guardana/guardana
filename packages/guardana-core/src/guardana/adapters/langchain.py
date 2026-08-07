"""Probe a LangChain chat model as the thing it is, not the endpoint underneath it.

LangChain's chat models share one calling convention — `invoke(messages)` returning
a message with `.content` — and that convention is all this uses. `langchain` is
never imported, so it is not a dependency of `guardana-core` and no release of it
can break this file; an object that does not fit is refused when the target is
built, not on the first prompt of a probe.
"""

from collections.abc import Sequence
from typing import Protocol

from guardana.core.budget import Budgets
from guardana.core.target.endpoint import (
    ChatMessage,
    ChatReply,
    EndpointError,
    EndpointTarget,
)
from guardana.core.usage import TokenUsage

REF_HOST = "http://langchain.invalid"
"""What a finding names as the endpoint, because there is not one.

`.invalid` is reserved by RFC 2606 and guaranteed never to resolve, so a
`target_ref` of `http://langchain.invalid#gpt-4o` tells a reader at a glance that
nothing was fetched over the network — while still being a URL, which is what keeps
`EndpointTarget`'s scheme check (the one that stops a `file://` reaching urllib)
exactly as strict as it was.
"""

_ROLES = {"system": "system", "user": "human", "assistant": "ai"}
"""Guardana's roles in LangChain's spelling.

`tool` is deliberately absent: this adapter offers no tools, so a tool message here
would mean a rule ran that should have been skipped, and inventing a mapping for it
would send that rule a conversation the model never had.
"""


class LangChainModel(Protocol):
    """The one method this needs from a LangChain chat model.

    Positional-only, so the parameter's *name* is not part of the contract: LangChain
    calls it `input`, and a protocol that insisted on that would reject anything else
    somebody wraps their model in for no reason worth having.
    """

    def invoke(self, conversation: list[tuple[str, str]], /) -> object:
        """Send a conversation as `(role, content)` pairs and return the model's message."""
        ...


class LangChainTransport:
    """A `ChatTransport` that sends through a LangChain chat model.

    Implements `UsageReportingTransport` as well, so a token budget is enforceable
    whenever the model reports usage. When it does not, the request is recorded with
    unknown token counts — never zero — exactly as an HTTP provider that stays quiet
    is. A token ceiling over a model that never reports usage therefore cannot fire,
    which is a property of the model and is documented rather than papered over.
    """

    def __init__(self, model: LangChainModel) -> None:
        if not callable(getattr(model, "invoke", None)):
            raise EndpointError(
                f"{type(model).__name__} is not a LangChain chat model: this adapter calls "
                f"`invoke(messages)` and reads `.content` from the reply. Pass the chat model "
                f"itself (ChatOpenAI, ChatAnthropic, ChatOllama…), not a chain or an agent "
                f"executor"
            )
        self._model = model

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Send `messages` through the LangChain model and return its reply text."""
        return self.send_reporting_usage(base_url, model, messages, api_key).text

    def send_reporting_usage(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> ChatReply:
        """Send `messages` and return the reply with whatever usage the model reported."""
        ref = f"{base_url}#{model}"
        reply = self._model.invoke([_as_langchain(message, ref) for message in messages])
        return ChatReply(text=_text_of(reply, ref), usage=_usage_of(reply))


def _as_langchain(message: ChatMessage, ref: str) -> tuple[str, str]:
    """Turn one Guardana message into the `(role, content)` pair LangChain accepts."""
    role = _ROLES.get(message.role)
    if role is None:
        raise EndpointError(
            f"cannot send a {message.role!r} message to {ref}: this adapter offers no tools, "
            f"so there is no turn for a tool result to answer"
        )
    return (role, message.content)


def _text_of(reply: object, ref: str) -> str:
    """Read the reply's text, refusing anything this cannot grade.

    A `content` that is not text is not an empty answer — it is an answer this cannot
    read, and returning `""` for it would hand every evaluator a silent model that
    grades exactly like a well-behaved one. Multimodal replies arrive as a list of
    blocks, so the text blocks are joined; a reply with no text at all is an error.
    """
    content = getattr(reply, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        joined = "\n".join(_block_text(block) for block in content).strip()
        if joined:
            return joined
    raise EndpointError(
        f"the LangChain model behind {ref} returned no text to grade "
        f"({type(reply).__name__} with content {type(content).__name__})"
    )


def _block_text(block: object) -> str:
    if isinstance(block, str):
        return block
    if isinstance(block, dict) and block.get("type") == "text":
        return str(block.get("text", ""))
    return ""


def _usage_of(reply: object) -> TokenUsage | None:
    """Read `usage_metadata` when the model filled it in, and say nothing when it did not.

    `None` rather than zeros: a provider that reports nothing has not told us the
    request was free, and a run that records zero would let a token budget look
    enforced while nothing was counting.
    """
    metadata = getattr(reply, "usage_metadata", None)
    if not isinstance(metadata, dict):
        return None
    return TokenUsage(
        input_tokens=_count(metadata.get("input_tokens")),
        output_tokens=_count(metadata.get("output_tokens")),
    )


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def langchain_target(
    model: LangChainModel,
    *,
    name: str | None = None,
    system_prompt: str | None = None,
    budgets: Budgets | None = None,
) -> EndpointTarget:
    """Wrap a LangChain chat model as a Guardana endpoint target.

        from guardana.adapters.langchain import langchain_target
        from guardana.testing import assert_secure

        def test_the_agent_resists_injection(chat_model):
            assert_secure(langchain_target(chat_model, system_prompt=SYSTEM), preset="ci")

    `name` is what findings call the model, and it defaults to whatever the object
    calls itself (`model_name`, then `model`, then its class). It is part of the
    target reference, which is part of a finding's identity — so pass it explicitly
    when you want `guardana diff` to line two runs up across a change of client.

    `system_prompt` is what the application really puts in front of the model, and it
    is worth passing: without it the canary-backed system-prompt-leak rule has nothing
    planted to look for and is skipped, so the coverage a probe reports shrinks
    quietly. **Tool calling is not wired up**, so the five agentic rules skip too;
    `guardana target inspect` shows both, and `fail_on_skipped` turns them into an
    indeterminate result rather than a pass.
    """
    return EndpointTarget(
        REF_HOST,
        name or _name_of(model),
        system_prompt=system_prompt,
        transport=LangChainTransport(model),
        budgets=budgets,
    )


def _name_of(model: LangChainModel) -> str:
    """Ask the model what it calls itself, falling back to its class.

    Never guessed from a URL or a provider: the name lands in every finding's target
    reference, and a reference that changes shape between runs makes `diff` report a
    model swap that never happened.
    """
    for attribute in ("model_name", "model", "model_id"):
        value = getattr(model, attribute, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return type(model).__name__
