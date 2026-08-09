"""Translate a CrewAI run into the trace model — the adapter that found the missing field.

Every `TaskOutput` carries a non-optional `agent`, naming which agent produced it.
Guardana's model had nowhere to put that until `Span.agent` (trace schema v2), and a
multi-agent execution without it is a list of steps nobody performed. This adapter is
why the field exists; see `docs/design/framework-adapters.md`.

Two traps, and both are refused here. **CrewAI's "delegation" is not `Delegation`** —
the framework calls agent-to-agent task passing delegation, while Guardana's
`Delegation` is an authorization hop with a credential and a boundary. Mapping one
onto the other would hand the credential-passthrough rule a trace with no credentials
in it. **A handoff is derived only where the crew says the chain is a chain** — in a
hierarchical crew, consecutive tasks are not a sequence, so without the crew object
this records no handoffs at all rather than inventing them.
"""

from collections.abc import Mapping, Sequence

from guardana.adapters._translate import (
    attribute_map,
    integer,
    opaque_part,
    parts_of,
    provenance_of,
    text_part,
    trace_id_from,
)
from guardana.core.trace import (
    AgentRef,
    ContentPart,
    Dimension,
    Handoff,
    Message,
    ModelCall,
    Role,
    Span,
    SpanKind,
    Trace,
)

PRODUCER = "crewai"

_ROLES = {
    "system": Role.SYSTEM,
    "user": Role.USER,
    "assistant": Role.ASSISTANT,
    "tool": Role.TOOL,
}


def crewai_trace(output: object, *, crew: object = None, name: str = PRODUCER) -> Trace:
    """Turn a `CrewOutput` into a `Trace`, one span per task and the actor on each.

        from guardana.adapters.crewai import crewai_trace
        from guardana.core.target import TraceTarget
        from guardana.testing import assert_secure

        def test_the_crew_keeps_work_inside_its_boundary(crew):
            result = crew.kickoff(inputs={"topic": "quarterly numbers"})
            assert_secure(TraceTarget(crewai_trace(result, crew=crew)), preset="ci")

    Pass `crew` to have handoffs recorded. A sequential crew feeds each task's output
    to the next as context, so a change of agent between consecutive tasks is a real
    handover and the payload is the previous agent's output — untrusted content
    arriving as an instruction. A hierarchical crew is not a chain, and neither is a
    crew nobody handed over, so in both cases the `HANDOFF` dimension goes undeclared
    and the rules needing it do not run.

    Raises `TypeError` if the object is not a crew result, rather than producing an
    empty trace that would grade clean.
    """
    tasks = _tasks_of(output)
    sequential = _is_sequential(crew)
    spans: list[Span] = []
    for index, task in enumerate(tasks):
        previous = tasks[index - 1] if index else None
        if sequential and previous is not None:
            spans.extend(_handoff(index, previous, task))
        spans.append(_task_span(index, task))
    return Trace(
        trace_id=trace_id_from(PRODUCER, name, *(_text(_agent_of(t)) or "" for t in tasks)),
        spans=tuple(spans),
        provenance=provenance_of(PRODUCER, name, None),
        instrumented=frozenset(_records(sequential)),
        attributes=attribute_map(tasks=len(tasks), process="sequential" if sequential else None),
    )


def _records(sequential: bool) -> set[Dimension]:
    """Declare messages always, and handoffs only where the crew's own shape implies them."""
    dimensions = {Dimension.MESSAGES}
    if sequential:
        dimensions.add(Dimension.HANDOFF)
    return dimensions


def _tasks_of(output: object) -> Sequence[object]:
    tasks = getattr(output, "tasks_output", None)
    if not isinstance(tasks, Sequence):
        raise TypeError(
            f"{type(output).__name__} is not a CrewAI result: this adapter reads "
            f"`tasks_output`. Pass what `crew.kickoff(...)` returned, not the crew and not "
            f"`result.raw`"
        )
    return tasks


def _is_sequential(crew: object) -> bool:
    """Believe the crew's declared process, and read anything else as "not a chain".

    Fail-closed on purpose: an unrecognised process means the ordering assumption is
    unproven, and an invented handoff is a record of something that did not happen.
    """
    if crew is None:
        return False
    process = getattr(crew, "process", None)
    return "sequential" in str(process).lower()


def _task_span(index: int, task: object) -> Span:
    """One task, performed by one agent, with whatever conversation it recorded."""
    actor = _text(_agent_of(task))
    turns = [_turn(m) for m in _messages_of(task)]
    output = _text(getattr(task, "raw", None))
    if output is not None:
        turns.append(Message(role=Role.ASSISTANT, parts=(text_part(output),)))
    description = _text(getattr(task, "description", None))
    return Span(
        span_id=f"crew-{index}",
        kind=SpanKind.AGENT_INVOCATION,
        name=_text(getattr(task, "name", None)) or description or f"task {index}",
        agent=AgentRef(name=actor) if actor else None,
        model=_model_call(task),
        system_instructions=(text_part(description),) if description else (),
        messages=tuple(turns),
    )


def _handoff(index: int, previous: object, task: object) -> list[Span]:
    """Record the boundary a sequential crew crosses when the acting agent changes."""
    giver = _text(_agent_of(previous))
    taker = _text(_agent_of(task))
    if not giver or not taker or giver == taker:
        return []
    payload = _text(getattr(previous, "raw", None))
    return [
        Span(
            span_id=f"crew-{index}-handoff",
            kind=SpanKind.HANDOFF,
            name=f"{giver} → {taker}",
            agent=AgentRef(name=giver),
            parent_span_id=f"crew-{index - 1}",
            handoff=Handoff(
                from_agent=giver,
                to_agent=taker,
                payload=(text_part(payload),) if payload else (),
            ),
        )
    ]


def _model_call(task: object) -> ModelCall | None:
    """Read the per-task token usage when the framework attached any."""
    usage = getattr(task, "token_usage", None)
    call = ModelCall(
        input_tokens=integer(getattr(usage, "prompt_tokens", None)),
        output_tokens=integer(getattr(usage, "completion_tokens", None)),
    )
    return call if call != ModelCall() else None


def _messages_of(task: object) -> Sequence[object]:
    messages = getattr(task, "messages", None)
    return messages if isinstance(messages, Sequence) and not isinstance(messages, str) else ()


def _turn(raw: object) -> Message:
    """Read one recorded turn, keeping a role this build does not know rather than dropping it."""
    if not isinstance(raw, Mapping):
        return Message(role=Role.OTHER, parts=(opaque_part(type(raw).__name__),))
    declared = _text(raw.get("role"))
    role = _ROLES.get(declared or "", Role.OTHER)
    return Message(
        role=role,
        declared_role=declared if role is Role.OTHER else None,
        parts=_content_parts(raw.get("content")),
    )


def _content_parts(content: object) -> tuple[ContentPart, ...]:
    return parts_of(content) if content is not None else ()


def _agent_of(task: object) -> object:
    return getattr(task, "agent", None)


def _text(value: object) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    text = value if isinstance(value, str) else str(value)
    return text.strip() or None
