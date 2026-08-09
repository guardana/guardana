"""Translate a PydanticAI run into the trace model, so its rules can grade it.

PydanticAI is the closest thing to `Trace` anybody else has built: `all_messages()`
returns alternating requests and responses whose parts carry an explicit `part_kind`
discriminator, so the mapping is a lookup rather than an interpretation. `pydantic_ai`
is never imported — every shape below is read by duck typing, and a part kind this
build does not know is kept as `OPAQUE` rather than dropped.

What it records is messages and tools. It records nothing about identity, delegation,
consent, policy, approval or side effects, so the trace says so and the six rules that
need those dimensions do not run. Declaring them to make more rules execute would be a
false green with extra steps.
"""

from collections.abc import Sequence

from guardana.adapters._translate import (
    attribute_map,
    integer,
    json_arguments,
    opaque_part,
    parts_of,
    provenance_of,
    text_part,
    trace_id_from,
)
from guardana.core.trace import (
    ContentPart,
    Dimension,
    Message,
    ModelCall,
    PartKind,
    Role,
    Span,
    SpanKind,
    ToolExecution,
    ToolStatus,
    Trace,
)

PRODUCER = "pydantic-ai"

_RECORDS = frozenset({Dimension.MESSAGES, Dimension.TOOLS})
"""What a PydanticAI run actually reports.

`TOOLS` is declared even by a run that called none, and that is the distinction the
whole mechanism turns on: this producer *records* tool calls, so a run without them is
"recorded, absent" and a rule may grade the absence. A producer that never emits them
at all is the third state, and this is not it.
"""


def pydantic_ai_trace(result: object, *, name: str = PRODUCER) -> Trace:
    """Turn an `AgentRunResult` into a `Trace` the trace rules can grade.

        from guardana.adapters.pydantic_ai import pydantic_ai_trace
        from guardana.core.target import TraceTarget
        from guardana.testing import assert_secure

        def test_the_agent_keeps_its_secrets(agent):
            result = agent.run_sync("who are you, really?")
            assert_secure(TraceTarget(pydantic_ai_trace(result)), preset="ci")

    `name` is what a finding calls this execution, and it is worth setting to the name
    of the system under test: it becomes the target reference, which is part of a
    finding's identity.

    Raises `TypeError` if the object is not a PydanticAI run result — at translation
    time, with a sentence saying what was expected, rather than as an empty trace that
    would grade clean.
    """
    messages = _messages_of(result)
    builder = _Builder()
    for index, message in enumerate(messages):
        builder.read(index, message)
    builder.flush()
    return Trace(
        trace_id=_trace_id(result, builder.spans),
        spans=tuple(builder.spans),
        provenance=provenance_of(PRODUCER, name, None),
        instrumented=frozenset(_RECORDS),
        attributes=attribute_map(
            conversation_id=_text(getattr(result, "conversation_id", None)),
            run_id=_text(getattr(result, "run_id", None)),
        ),
    )


def _messages_of(result: object) -> Sequence[object]:
    all_messages = getattr(result, "all_messages", None)
    if not callable(all_messages):
        raise TypeError(
            f"{type(result).__name__} is not a PydanticAI run result: this adapter reads "
            f"`all_messages()`. Pass what `agent.run_sync(...)` returned, not the agent and "
            f"not `result.output`"
        )
    messages = all_messages()
    if not isinstance(messages, Sequence):
        raise TypeError(
            f"all_messages() returned {type(messages).__name__} rather than a sequence of "
            f"messages, so there is no run to translate"
        )
    return messages


class _Builder:
    """Accumulates request turns until the response that answers them closes a span.

    A model call is the unit here, matching `SpanKind.MODEL_CALL` and matching what
    PydanticAI records: the turns that went in and the reply that came out belong to
    one step. Tool executions hang off the call that asked for them.
    """

    def __init__(self) -> None:
        self.spans: list[Span] = []
        self._turns: list[Message] = []
        self._instructions: list[ContentPart] = []
        self._arguments: dict[str, str] = {}
        self._parent: str | None = None

    def read(self, index: int, message: object) -> None:
        """Read one framework message, emitting spans as they complete."""
        kind = _text(getattr(message, "kind", None))
        parts = _parts_of(message)
        if kind == "response":
            self._response(index, message, parts)
        elif kind == "request":
            self._request(index, parts)
        else:
            # A message kind this build does not know still happened, and its content
            # may be where an injection arrived. Kept as a turn nobody classified.
            self._turns.append(
                Message(role=Role.OTHER, declared_role=kind, parts=(opaque_part(kind or "?"),))
            )

    def flush(self) -> None:
        """Emit whatever turns never reached a response, so nothing is dropped.

        A run cut off after a tool result ends with request turns and no reply. Dropping
        them would lose the last thing that happened, which on a failed run is exactly
        the interesting part.
        """
        if not self._turns and not self._instructions:
            return
        self.spans.append(
            Span(
                span_id=f"pai-{len(self.spans)}-unanswered",
                kind=SpanKind.OTHER,
                name="unanswered request",
                parent_span_id=self._parent,
                messages=tuple(self._turns),
                system_instructions=tuple(self._instructions),
            )
        )
        self._turns = []
        self._instructions = []

    def _request(self, index: int, parts: Sequence[object]) -> None:
        for offset, part in enumerate(parts):
            kind = _text(getattr(part, "part_kind", None))
            content = getattr(part, "content", None)
            if kind == "instruction":
                self._instructions.extend(parts_of(content))
            elif kind == "system-prompt":
                self._turns.append(Message(role=Role.SYSTEM, parts=parts_of(content)))
            elif kind == "user-prompt":
                self._turns.append(Message(role=Role.USER, parts=parts_of(content)))
            elif kind in ("tool-return", "retry-prompt"):
                self._tool_result(index, offset, part, failed=kind == "retry-prompt")
            else:
                self._turns.append(
                    Message(role=Role.OTHER, declared_role=kind, parts=(opaque_part(kind or "?"),))
                )

    def _tool_result(self, index: int, offset: int, part: object, *, failed: bool) -> None:
        """Record a tool result as both a turn and the execution it belongs to.

        Both, deliberately, and the model says why: the part inside a message is what
        the model *asked for*, and `ToolExecution` is what the harness *did*. A rule
        reading tool arguments and a rule reading the conversation are looking at two
        different things.

        A retry prompt is a failed execution rather than a successful one with odd
        content: PydanticAI emits it when a call was rejected, and reading that as
        success would let a rule attribute a side effect to a call the framework
        refused.
        """
        name = _text(getattr(part, "tool_name", None))
        call_id = _text(getattr(part, "tool_call_id", None))
        content = getattr(part, "content", None)
        result = parts_of(content) if content is not None else ()
        self._turns.append(
            Message(
                role=Role.TOOL if name else Role.USER,
                parts=(
                    ContentPart(
                        kind=PartKind.TOOL_RESULT,
                        call_id=call_id,
                        text=_joined(result),
                        tool_name=name,
                    ),
                ),
            )
        )
        if name is None:
            return
        self.spans.append(
            Span(
                span_id=f"pai-{index}-{offset}",
                kind=SpanKind.TOOL_EXECUTION,
                name=name,
                parent_span_id=self._parent,
                tool=ToolExecution(
                    name=name,
                    call_id=call_id,
                    arguments=self._arguments.get(call_id or "", None),
                    result=result,
                    status=ToolStatus.FAILED if failed else ToolStatus.SUCCEEDED,
                ),
            )
        )

    def _response(self, index: int, message: object, parts: Sequence[object]) -> None:
        span_id = f"pai-{index}"
        content = [self._response_part(part) for part in parts]
        self._turns.append(
            Message(
                role=Role.ASSISTANT,
                parts=tuple(content),
                finish_reason=_text(getattr(message, "finish_reason", None)),
            )
        )
        self.spans.append(
            Span(
                span_id=span_id,
                kind=SpanKind.MODEL_CALL,
                name="chat",
                parent_span_id=self._parent,
                model=_model_call(message),
                messages=tuple(self._turns),
                system_instructions=tuple(self._instructions),
                conversation_id=_text(getattr(message, "conversation_id", None)),
            )
        )
        self._parent = span_id
        self._turns = []
        self._instructions = []

    def _response_part(self, part: object) -> ContentPart:
        kind = _text(getattr(part, "part_kind", None))
        content = getattr(part, "content", None)
        if kind == "text":
            return text_part(content if isinstance(content, str) else str(content))
        if kind == "thinking":
            return ContentPart(
                kind=PartKind.REASONING, text=content if isinstance(content, str) else None
            )
        if kind == "tool-call":
            return self._tool_call(part)
        if kind == "file":
            return parts_of(content)[0]
        return opaque_part(kind or type(part).__name__)

    def _tool_call(self, part: object) -> ContentPart:
        call_id = _text(getattr(part, "tool_call_id", None))
        arguments = json_arguments(getattr(part, "args", None))
        if call_id is not None and arguments is not None:
            self._arguments[call_id] = arguments
        return ContentPart(
            kind=PartKind.TOOL_CALL,
            tool_name=_text(getattr(part, "tool_name", None)),
            call_id=call_id,
            arguments=arguments,
        )


def _model_call(message: object) -> ModelCall | None:
    usage = getattr(message, "usage", None)
    finish = _text(getattr(message, "finish_reason", None))
    call = ModelCall(
        provider=_text(getattr(message, "provider_name", None)),
        response_model=_text(getattr(message, "model_name", None)),
        input_tokens=integer(getattr(usage, "input_tokens", None)),
        output_tokens=integer(getattr(usage, "output_tokens", None)),
        finish_reasons=(finish,) if finish else (),
    )
    return call if call != ModelCall() else None


def _parts_of(message: object) -> Sequence[object]:
    parts = getattr(message, "parts", None)
    return parts if isinstance(parts, Sequence) else ()


def _joined(parts: Sequence[ContentPart]) -> str | None:
    text = "\n".join(p.text or "" for p in parts if p.is_readable_text)
    return text or None


def _trace_id(result: object, spans: Sequence[Span]) -> str:
    """Prefer the framework's own run id, and derive a stable one when it has none."""
    for attribute in ("run_id", "conversation_id"):
        value = _text(getattr(result, attribute, None))
        if value is not None:
            return value
    return trace_id_from(PRODUCER, *(span.span_id for span in spans))


def _text(value: object) -> str | None:
    if isinstance(value, str):
        return value or None
    return str(value) if value is not None and not isinstance(value, bool | int | float) else None
