"""`TraceTarget` translates what a producer recorded into what a rule may run.

The mechanism the whole trace design rests on. The tests that matter are the ones
proving a capability is *absent* when a dimension is: that absence is what the runner
turns into a skip with a reason, instead of a rule finding nothing in a file that could
not have contained it.
"""

import pytest
from guardana.core.budget import BudgetExhausted, Budgets
from guardana.core.observation import ObservationKind
from guardana.core.target import Capability, TargetKind, TraceTarget
from guardana.core.trace import (
    Dimension,
    ModelCall,
    Provenance,
    Span,
    SpanKind,
    Trace,
)


def _trace(*dimensions: Dimension, spans: tuple[Span, ...] = ()) -> Trace:
    return Trace(
        trace_id="t-1",
        spans=spans,
        provenance=Provenance(producer="acme", source="acme.jsonl", dialect="guardana"),
        instrumented=frozenset(dimensions),
    )


def test_a_trace_is_neither_an_artifact_nor_an_endpoint() -> None:
    """Folding it into either would offer the wrong rules a target they cannot read."""
    assert TraceTarget(_trace()).kind is TargetKind.TRACE


def test_every_trace_can_be_read_even_when_it_records_nothing_else() -> None:
    assert TraceTarget(_trace()).capabilities() == {Capability.READ_TRACE}


@pytest.mark.parametrize(
    ("dimension", "capability"),
    [
        (Dimension.MESSAGES, Capability.READ_MESSAGES),
        (Dimension.TOOLS, Capability.READ_TOOL_CALLS),
        (Dimension.IDENTITY, Capability.READ_IDENTITY),
        (Dimension.DELEGATION, Capability.READ_DELEGATION),
        (Dimension.CONSENT, Capability.READ_CONSENT),
        (Dimension.POLICY, Capability.READ_POLICY_DECISIONS),
        (Dimension.APPROVAL, Capability.READ_APPROVALS),
        (Dimension.EFFECTS, Capability.READ_SIDE_EFFECTS),
    ],
)
def test_a_recorded_dimension_licenses_its_capability_and_nothing_else(
    dimension: Dimension, capability: Capability
) -> None:
    capabilities = TraceTarget(_trace(dimension)).capabilities()
    assert capabilities == {Capability.READ_TRACE, capability}


def test_a_dimension_nobody_records_is_named_so_a_command_can_say_what_went_unchecked() -> None:
    target = TraceTarget(_trace(Dimension.MESSAGES, Dimension.TOOLS))
    missing = target.missing_dimensions()
    assert Dimension.APPROVAL in missing
    assert Dimension.MESSAGES not in missing


def test_the_reference_names_the_file_first_and_the_producers_random_id_second() -> None:
    """Two runs over one file should read as the same target in a report and in a diff."""
    assert TraceTarget(_trace()).ref == "acme.jsonl#t-1"


def test_a_request_ceiling_is_accepted_because_reading_a_file_sends_nothing() -> None:
    """Without this, a guardana.yaml carrying probe budgets would stop the command starting."""
    TraceTarget(_trace()).apply_budgets(Budgets(max_requests=5, max_input_tokens=10))


def test_a_duration_ceiling_is_refused_because_this_target_does_not_interrupt_itself() -> None:
    with pytest.raises(BudgetExhausted, match="duration"):
        TraceTarget(_trace()).apply_budgets(Budgets(max_duration_seconds=1.0))


def test_the_models_that_actually_answered_are_reported_as_observations() -> None:
    """A trace is the one input that knows which model replied rather than which was configured."""
    spans = (
        Span(
            span_id="s1",
            kind=SpanKind.MODEL_CALL,
            name="chat",
            model=ModelCall(provider="openai", request_model="gpt-4o", response_model="gpt-4o-05"),
        ),
        Span(
            span_id="s2",
            kind=SpanKind.MODEL_CALL,
            name="chat",
            model=ModelCall(provider="openai", response_model="gpt-4o-05"),
        ),
        Span(span_id="s3", kind=SpanKind.TOOL_EXECUTION, name="pay"),
    )
    observations = TraceTarget(_trace(spans=spans)).observations()
    assert [o.name for o in observations] == ["gpt-4o-05"]
    assert observations[0].kind is ObservationKind.MODEL
    assert observations[0].attributes["provider"] == "openai"


def test_a_trace_with_no_model_call_observes_nothing_rather_than_inventing_a_model() -> None:
    spans = (Span(span_id="s1", kind=SpanKind.TOOL_EXECUTION, name="pay"),)
    assert TraceTarget(_trace(spans=spans)).observations() == ()
