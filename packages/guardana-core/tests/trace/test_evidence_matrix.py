"""The evidence matrix, which is the trace design's central mechanism made visible.

Two columns rather than one number, and the tests are mostly about why. `declared`
and `records` describe two different failures, and a report that collapsed them would
make "this execution had nothing to approve" indistinguishable from "this framework
emits no approvals" — the inference the whole trace model exists to refuse.
"""

from guardana.core.trace import (
    Approval,
    ApprovalOutcome,
    Consent,
    ContentPart,
    Delegation,
    Dimension,
    DimensionCoverage,
    EffectStatus,
    Handoff,
    Identity,
    MemoryAction,
    MemoryOperation,
    Message,
    PolicyDecision,
    PolicyOutcome,
    Provenance,
    Retrieval,
    Role,
    SideEffect,
    SinkKind,
    Span,
    SpanKind,
    ToolDeclaration,
    ToolExecution,
    Trace,
    evidence_matrix,
)


def _trace(*spans: Span, records: frozenset[Dimension] = frozenset()) -> Trace:
    return Trace(
        trace_id="t",
        spans=tuple(spans),
        provenance=Provenance(producer="acme", source="a.jsonl", dialect="guardana"),
        instrumented=records,
    )


def _row(trace: Trace, dimension: Dimension) -> DimensionCoverage:
    return next(r for r in evidence_matrix(trace) if r.dimension is dimension)


def test_every_dimension_appears_even_when_no_rule_needs_it() -> None:
    """An operator deciding what to require needs the domain, not this build's slice of it.

    A matrix listing only what is currently checkable would shrink whenever a
    capability was added or removed, which is a coverage report that moves for reasons
    that have nothing to do with the coverage.
    """
    rows = evidence_matrix(_trace())

    assert tuple(r.dimension for r in rows) == tuple(Dimension)


def test_declared_and_recorded_are_separate_facts() -> None:
    """The case a single number would hide, in both directions."""
    declared_and_empty = _trace(
        Span(span_id="s", kind=SpanKind.TOOL_EXECUTION, name="s"),
        records=frozenset({Dimension.APPROVAL}),
    )
    row = _row(declared_and_empty, Dimension.APPROVAL)

    assert row.declared is True
    assert row.records == 0
    assert row.is_gap is False, "an execution with nothing to approve is gradable, not a gap"

    undeclared = _trace(records=frozenset())
    assert _row(undeclared, Dimension.APPROVAL).is_gap is True


def test_plural_blocks_count_records_and_singular_blocks_count_steps() -> None:
    """One span with four delegations is four hops of authority, not one.

    Reporting it as one would understate exactly the dimension where the interesting
    failures live, which is the dimension an operator is deciding whether to require.
    """
    span = Span(
        span_id="s",
        kind=SpanKind.TOOL_EXECUTION,
        name="s",
        messages=(Message(role=Role.USER, parts=(ContentPart.of_text("hi"),)),),
        tool_offers=(ToolDeclaration(name="a"), ToolDeclaration(name="b")),
        tool=ToolExecution(name="a"),
        retrieval=Retrieval(query="q"),
        memory=MemoryOperation(action=MemoryAction.WRITE),
        handoff=Handoff(from_agent="a", to_agent="b"),
        identity=Identity(actor="a"),
        delegations=(
            Delegation(actor="a", boundary="x"),
            Delegation(actor="a", boundary="y"),
            Delegation(actor="a", boundary="z"),
        ),
        consents=(Consent(client="c", granted=True),),
        policy_decisions=(PolicyDecision(outcome=PolicyOutcome.ALLOW, action="a"),),
        approvals=(Approval(action="a", outcome=ApprovalOutcome.GRANTED),),
        effects=(
            SideEffect(sink=SinkKind.SQL, action="a", status=EffectStatus.EXECUTED),
            SideEffect(sink=SinkKind.HTTP, action="b", status=EffectStatus.ATTEMPTED),
        ),
    )
    counts = {r.dimension: r.records for r in evidence_matrix(_trace(span))}

    assert counts == {
        Dimension.MESSAGES: 1,
        Dimension.TOOLS: 3,
        Dimension.RETRIEVAL: 1,
        Dimension.MEMORY: 1,
        Dimension.HANDOFF: 1,
        Dimension.IDENTITY: 1,
        Dimension.DELEGATION: 3,
        Dimension.CONSENT: 1,
        Dimension.POLICY: 1,
        Dimension.APPROVAL: 1,
        Dimension.EFFECTS: 2,
    }


def test_records_are_summed_across_every_span() -> None:
    trace = _trace(
        Span(span_id="a", kind=SpanKind.TOOL_EXECUTION, name="a", tool=ToolExecution(name="t")),
        Span(span_id="b", kind=SpanKind.TOOL_EXECUTION, name="b", tool=ToolExecution(name="t")),
    )

    assert _row(trace, Dimension.TOOLS).records == 2
