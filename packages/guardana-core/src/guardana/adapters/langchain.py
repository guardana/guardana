"""Probe a LangChain chat model as the thing it is, not the endpoint underneath it.

LangChain's chat models share one calling convention — `invoke(messages)` returning
a message with `.content` — and that convention is all this uses. `langchain` is
never imported, so it is not a dependency of `guardana-core` and no release of it
can break this file; an object that does not fit is refused when the target is
built, not on the first prompt of a probe.

Tool calling goes through the same door. `bind_tools` accepts a plain OpenAI-shaped
`dict`, so offering a tool needs no framework type either — and whether a given model
*can* be offered tools is established once, at construction, because `bind_tools`
exists on every chat model and raises on the ones that cannot do it.
"""

import json
from collections.abc import Sequence
from typing import Any, Protocol

from guardana.core.budget import Budgets
from guardana.core.target.endpoint import (
    ChatMessage,
    ChatReply,
    EndpointError,
    EndpointTarget,
    ToolCall,
    ToolCallReply,
    ToolSpec,
    openai_tool,
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

_PROBE_TOOL = ToolSpec(
    name="guardana_tool_support_probe",
    description="Offered once, at construction, to find out whether this model binds tools.",
)
"""The tool bound to nobody, so a capability is measured rather than assumed.

`hasattr(model, "bind_tools")` is true for a model that will refuse, and assuming a
refusal skips six agentic rules against models that would have worked. Binding
returns a runnable and sends nothing, so asking costs no request and no token.
"""


class LangChainModel(Protocol):
    """The one method this needs from a LangChain chat model.

    Positional-only, so the parameter's *name* is not part of the contract: LangChain
    calls it `input`, and a protocol that insisted on that would reject anything else
    somebody wraps their model in for no reason worth having.
    """

    def invoke(self, conversation: list[dict[str, Any]], /) -> object:
        """Send a conversation as role/content mappings and return the model's message."""
        ...


class LangChainTransport:
    """A `ChatTransport` that sends through a LangChain chat model.

    Implements `UsageReportingTransport` as well, so a token budget is enforceable
    whenever the model reports usage. When it does not, the request is recorded with
    unknown token counts — never zero — exactly as an HTTP provider that stays quiet
    is. A token ceiling over a model that never reports usage therefore cannot fire,
    which is a property of the model and is documented rather than papered over.

    Deliberately without `send_tools`: the capability is structural, so a model that
    cannot bind tools gets this class and one that can gets the subclass below. A
    single class with a `send_tools` that raises would advertise `CALL_TOOLS` through
    `ToolCallingTransport`'s structural check and fail on the first agentic rule.
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
        reply = self._model.invoke([_as_langchain(m, ref) for m in messages])
        return ChatReply(text=_text_of(reply, ref), usage=_usage_of(reply))


class LangChainToolTransport(LangChainTransport):
    """A `LangChainTransport` for a model that accepts bound tools.

    Only constructed when `bind_tools` has already been shown to work, which is what
    keeps `CALL_TOOLS` an observation rather than a hope.
    """

    def send_tools(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
        tools: Sequence[ToolSpec],
    ) -> ToolCallReply:
        """Offer `tools` to the model and report the calls it asked for.

        Bound per request rather than once, because the tools a rule offers change
        between rules and a binding cached from the first would answer every later one
        with the wrong menu.
        """
        ref = f"{base_url}#{model}"
        bound = _bind(self._model, tools, ref)
        invoke = getattr(bound, "invoke", None)
        if not callable(invoke):
            raise EndpointError(
                f"binding tools to the model behind {ref} returned "
                f"{type(bound).__name__}, which cannot be invoked"
            )
        reply = invoke([_as_langchain(m, ref) for m in messages])
        return ToolCallReply(text=_reply_text(reply), tool_calls=_tool_calls(reply))


def _bind(model: LangChainModel, tools: Sequence[ToolSpec], ref: str) -> object:
    """Bind tools in the OpenAI shape, turning a framework refusal into our error."""
    bind = getattr(model, "bind_tools", None)
    if not callable(bind):
        raise EndpointError(f"the model behind {ref} has no bind_tools")
    try:
        bound: object = bind([openai_tool(t) for t in tools])
    except (NotImplementedError, TypeError, ValueError) as exc:
        raise EndpointError(
            f"the LangChain model behind {ref} refused the offered tools: {exc}"
        ) from exc
    return bound


def _as_langchain(message: ChatMessage, ref: str) -> dict[str, Any]:
    """Turn one Guardana message into the mapping LangChain's converter accepts.

    A mapping rather than the `(role, content)` tuple this used before tool calling:
    the tuple form cannot carry a tool call or the id a tool result answers, and
    LangChain raises `KeyError: 'tool_call_id'` on the attempt. An agentic rule
    replaying its own history would have died mid-run on the second turn.
    """
    if message.role == "tool":
        if not message.tool_call_id:
            raise EndpointError(
                f"cannot send a tool result to {ref} with no tool_call_id: the model pairs a "
                f"result to the call it answers by that id, and an unpaired result is a turn "
                f"no provider accepts"
            )
        return {
            "role": "tool",
            "content": message.content,
            "tool_call_id": message.tool_call_id,
        }
    payload: dict[str, Any] = {"role": message.role, "content": message.content}
    if message.tool_calls:
        payload["tool_calls"] = [_as_langchain_call(c, ref) for c in message.tool_calls]
    return payload


def _as_langchain_call(call: ToolCall, ref: str) -> dict[str, Any]:
    """Render one previously-observed tool call the way LangChain reads them back.

    LangChain holds arguments as a mapping and Guardana holds them as the string the
    provider sent, so replaying a turn means parsing. Arguments that are not a JSON
    object are refused rather than replaced with `{}`: sending an empty call would
    continue the run against a conversation the model never had, and grade that.
    """
    return {
        "type": "tool_call",
        "name": call.name,
        "id": call.id,
        "args": _arguments(call, ref),
    }


def _arguments(call: ToolCall, ref: str) -> dict[str, Any]:
    if not call.arguments.strip():
        return {}
    try:
        parsed = json.loads(call.arguments)
    except json.JSONDecodeError as exc:
        raise EndpointError(
            f"cannot replay the call to {call.name!r} against {ref}: the arguments it was "
            f"recorded with are not JSON ({exc})"
        ) from exc
    if not isinstance(parsed, dict):
        raise EndpointError(
            f"cannot replay the call to {call.name!r} against {ref}: its arguments are a "
            f"{type(parsed).__name__}, and a tool call carries an object"
        )
    return parsed


def _text_of(reply: object, ref: str) -> str:
    """Read the reply's text, refusing anything this cannot grade.

    A `content` that is not text is not an empty answer — it is an answer this cannot
    read, and returning `""` for it would hand every evaluator a silent model that
    grades exactly like a well-behaved one. Multimodal replies arrive as a list of
    blocks, so the text blocks are joined; a reply with no text at all is an error.
    """
    text = _reply_text(reply)
    if text is not None:
        return text
    raise EndpointError(
        f"the LangChain model behind {ref} returned no text to grade "
        f"({type(reply).__name__} with content {type(getattr(reply, 'content', None)).__name__})"
    )


def _reply_text(reply: object) -> str | None:
    """Read whatever text a reply carries, or None when it carries none.

    None is a failure on the text path and normal on the tool path — a model that
    answered with tool calls and no prose said what an agency rule grades. The two
    callers differ in what they do about it, which is why the refusal lives in one of
    them rather than here.
    """
    content = getattr(reply, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        joined = "\n".join(_block_text(block) for block in content).strip()
        if joined:
            return joined
    return None


def _block_text(block: object) -> str:
    if isinstance(block, str):
        return block
    if isinstance(block, dict) and block.get("type") == "text":
        return str(block.get("text", ""))
    return ""


def _tool_calls(reply: object) -> tuple[ToolCall, ...]:
    """Read the calls the model asked for, including the ones LangChain could not parse.

    `invalid_tool_calls` holds a call whose arguments failed to parse, and dropping
    those is a false green with a clear shape: a model that asked to call
    `delete_everything` with malformed arguments still asked. The raw string is kept
    as recorded, which is also what makes it visible in the finding's evidence.
    """
    calls = [
        _tool_call(raw, json.dumps(raw.get("args", {}), sort_keys=True))
        for raw in _call_list(reply, "tool_calls")
    ]
    calls.extend(
        _tool_call(raw, _raw_arguments(raw)) for raw in _call_list(reply, "invalid_tool_calls")
    )
    return tuple(calls)


def _raw_arguments(raw: dict[str, Any]) -> str:
    """Keep an unparseable argument string exactly as the provider sent it."""
    args = raw.get("args")
    return args if isinstance(args, str) else ""


def _call_list(reply: object, attribute: str) -> list[dict[str, Any]]:
    raw = getattr(reply, attribute, None)
    return [c for c in raw if isinstance(c, dict)] if isinstance(raw, list) else []


def _tool_call(raw: dict[str, Any], arguments: str) -> ToolCall:
    name = raw.get("name")
    identifier = raw.get("id")
    return ToolCall(
        name=name if isinstance(name, str) else "",
        arguments=arguments,
        id=identifier if isinstance(identifier, str) else "",
    )


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


def supports_tools(model: LangChainModel) -> bool:
    """Ask the model whether it binds tools, by binding one and throwing it away.

    `BaseChatModel.bind_tools` exists on every chat model and raises
    `NotImplementedError` on the ones without a function-calling API, so neither
    branch of the obvious check is right on its own. Binding performs no request.

    A failure of any kind reads as "cannot", because the honest consequence is
    identical: the agentic rules skip with a reason, `guardana target inspect` says
    tool calling is unavailable, and `fail_on_skipped` can turn that into an
    indeterminate result. Guessing "can" instead would fail on the first rule and
    report an error where a skip is the truth.
    """
    bind = getattr(model, "bind_tools", None)
    if not callable(bind):
        return False
    try:
        bind([openai_tool(_PROBE_TOOL)])
    except Exception:
        return False
    return True


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
    quietly.

    **Tool calling is wired up when the model supports it.** Whether it does is
    established here by binding a throwaway tool, so a model with a function-calling
    API runs the six agentic rules and one without skips them with a reason.
    `guardana target inspect` shows which of the two happened.
    """
    transport = (
        LangChainToolTransport(model) if supports_tools(model) else LangChainTransport(model)
    )
    return EndpointTarget(
        REF_HOST,
        name or _name_of(model),
        system_prompt=system_prompt,
        transport=transport,
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
