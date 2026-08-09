"""Translating a CrewAI run — and the field this framework forced into the model.

Doubles built from the real `CrewOutput` / `TaskOutput` surface; `crewai` is never
imported and is not installed where this runs.
"""

import sys

import pytest
from guardana.adapters.crewai import crewai_trace
from guardana.core.target import Capability, TraceTarget
from guardana.core.trace import Dimension, PartKind, Role, SpanKind
from guardana.rules.trace import HandoffAuthorityExpansionRule


class _Usage:
    def __init__(self, prompt_tokens: int, completion_tokens: int) -> None:
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


class _Task:
    """A `TaskOutput`: what was asked, what came back, and which agent produced it."""

    def __init__(
        self,
        agent: str,
        raw: str,
        description: str = "",
        name: str | None = None,
        messages: list[dict[str, str]] | None = None,
    ) -> None:
        self.agent = agent
        self.raw = raw
        self.description = description
        self.name = name
        self.messages = messages or []
        self.token_usage = _Usage(11, 4)


class _Output:
    def __init__(self, tasks: list[_Task]) -> None:
        self.raw = tasks[-1].raw if tasks else ""
        self.tasks_output = tasks


class _Crew:
    def __init__(self, process: str = "Process.sequential") -> None:
        self.process = process


def _crew_run() -> _Output:
    return _Output(
        [
            _Task(
                "Senior Researcher",
                "the market grew 4%",
                description="research the market",
                name="research",
                messages=[{"role": "user", "content": "research the market"}],
            ),
            _Task("Writer", "Q3 report", description="write it up", name="write"),
        ]
    )


def test_every_task_becomes_a_span_that_names_the_agent_that_performed_it() -> None:
    """The reason `Span.agent` exists: a multi-agent run whose steps nobody performed."""
    trace = crewai_trace(_crew_run())

    actors = [(s.span_id, s.agent.name if s.agent else None) for s in trace.spans]
    assert actors == [("crew-0", "Senior Researcher"), ("crew-1", "Writer")]


def test_the_task_description_is_the_instruction_and_the_output_is_the_answer() -> None:
    span = crewai_trace(_crew_run()).spans[0]

    assert span.kind is SpanKind.AGENT_INVOCATION
    assert span.system_instructions[0].text == "research the market"
    assert [m.role for m in span.messages] == [Role.USER, Role.ASSISTANT]
    assert span.messages[-1].text() == "the market grew 4%"


def test_per_task_token_usage_survives_when_the_framework_attached_any() -> None:
    call = crewai_trace(_crew_run()).spans[0].model

    assert call is not None
    assert (call.input_tokens, call.output_tokens) == (11, 4)


def test_a_sequential_crew_records_the_handoff_between_two_agents() -> None:
    trace = crewai_trace(_crew_run(), crew=_Crew())

    handoffs = [s for s in trace.spans if s.kind is SpanKind.HANDOFF]
    assert len(handoffs) == 1
    handoff = handoffs[0].handoff
    assert handoff is not None
    assert (handoff.from_agent, handoff.to_agent) == ("Senior Researcher", "Writer")
    assert handoff.text() == "the market grew 4%"


def test_the_handoff_carries_no_scopes_because_crewai_records_none() -> None:
    """`None` is "not recorded", which is what stops the authority rule accusing anybody."""
    trace = crewai_trace(_crew_run(), crew=_Crew())

    handoff = next(s.handoff for s in trace.spans if s.handoff is not None)
    assert handoff.carried_scopes is None


def test_a_hierarchical_crew_records_no_handoffs_because_its_tasks_are_not_a_chain() -> None:
    """Deriving one would be a record of something that did not happen."""
    trace = crewai_trace(_crew_run(), crew=_Crew(process="Process.hierarchical"))

    assert not [s for s in trace.spans if s.kind is SpanKind.HANDOFF]
    assert Dimension.HANDOFF not in trace.instrumented


def test_without_the_crew_object_the_handoff_dimension_goes_undeclared() -> None:
    """The ordering assumption is unproven, so the rules needing it must not run."""
    trace = crewai_trace(_crew_run())

    assert trace.instrumented == frozenset({Dimension.MESSAGES})
    assert Capability.READ_HANDOFFS not in TraceTarget(trace).capabilities()


def test_two_consecutive_tasks_by_one_agent_are_not_a_handoff() -> None:
    output = _Output([_Task("Writer", "draft"), _Task("Writer", "final")])

    trace = crewai_trace(output, crew=_Crew())

    assert not [s for s in trace.spans if s.kind is SpanKind.HANDOFF]


def test_crewai_delegation_is_never_read_as_an_authorization_delegation() -> None:
    """The framework's word and Guardana's concept are different things with one name.

    Mapping CrewAI's agent-to-agent passing onto `Delegation` would declare the
    delegation dimension and hand the credential-passthrough rule a trace with no
    credentials in it at all.
    """
    trace = crewai_trace(_crew_run(), crew=_Crew())

    assert Dimension.DELEGATION not in trace.instrumented
    assert all(span.delegations == () for span in trace.spans)


def test_the_authority_rule_declines_on_a_crew_that_records_no_scopes() -> None:
    """It declines by name rather than reporting a clean multi-agent run."""
    trace = crewai_trace(_crew_run(), crew=_Crew())

    verdicts = [f.verdict for f in HandoffAuthorityExpansionRule().examine(trace)]

    assert [v.outcome for v in verdicts if v is not None] == ["inconclusive"]


def test_a_recorded_turn_whose_role_is_unknown_keeps_the_producers_word_for_it() -> None:
    output = _Output([_Task("Critic", "ok", messages=[{"role": "critic", "content": "weak"}])])

    message = crewai_trace(output).spans[0].messages[0]

    assert message.role is Role.OTHER
    assert message.declared_role == "critic"
    assert message.text() == "weak"


def test_a_turn_that_is_not_a_mapping_is_kept_as_opaque_rather_than_dropped() -> None:
    output = _Output([_Task("Critic", "ok", messages=[object()])])  # type: ignore[list-item]

    part = crewai_trace(output).spans[0].messages[0].parts[0]

    assert part.kind is PartKind.OPAQUE


def test_something_that_is_not_a_crew_result_is_refused() -> None:
    with pytest.raises(TypeError, match="not a CrewAI result"):
        crewai_trace(object())


def test_translating_the_same_run_twice_gives_the_same_trace_id() -> None:
    assert crewai_trace(_crew_run()).trace_id == crewai_trace(_crew_run()).trace_id


def test_the_adapter_never_imports_crewai() -> None:
    crewai_trace(_crew_run(), crew=_Crew())

    assert not [name for name in sys.modules if name.split(".")[0] == "crewai"]
