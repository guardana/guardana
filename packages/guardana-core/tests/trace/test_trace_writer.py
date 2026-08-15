"""Writing a trace one span at a time, and refusing the files that would grade clean.

`serialize_trace` renders a finished trace in one call, which is right for converting
an export and wrong for a producer: a live agent cannot buffer a session that runs for
hours, and the file has to be worth reading if the process dies halfway through.

Every refusal here is a measured false green rather than a matter of taste. Grading four
hand-built traces against the released engine (written up in
`docs/design/trace-producer.md`) put the leak in one place: a producer that declares
`effects` and never writes one gets `✓ No findings.` and exit `0` over an execution that
refunded money. The declared dimensions that *drive* a rule's loop are the dangerous
ones, and the writer is where they stop being a promise.
"""

import json
from io import StringIO
from pathlib import Path

import pytest
from guardana.core.trace import (
    Approval,
    Dialect,
    Dimension,
    EffectStatus,
    Identity,
    Message,
    Role,
    SideEffect,
    SinkKind,
    Span,
    SpanKind,
    ToolExecution,
    ToolStatus,
    TraceTruncation,
    read_trace,
)
from guardana.core.trace.writer import SinkMap, TraceWriteError, TraceWriter, open_trace

_INSTRUMENTED = (Dimension.MESSAGES, Dimension.TOOLS, Dimension.APPROVAL, Dimension.EFFECTS)
_SINKS = SinkMap({"refund": SinkKind.PAYMENT}, default=SinkKind.OTHER)


_MUTATING_REFUND = ToolExecution(name="refund", status=ToolStatus.SUCCEEDED, mutates=True)


def _writer(
    path: Path,
    instrumented: tuple[Dimension, ...] = _INSTRUMENTED,
    sinks: SinkMap | None = _SINKS,
) -> TraceWriter:
    return open_trace(
        path,
        trace_id="t-1",
        producer="acme-app",
        producer_version="1.4.0",
        instrumented=instrumented,
        sinks=sinks,
    )


def _refund_span(
    span_id: str = "s2",
    tool: ToolExecution | None = _MUTATING_REFUND,
    approvals: tuple[Approval, ...] = (),
    effects: tuple[SideEffect, ...] = (),
    identity: Identity | None = None,
) -> Span:
    return Span(
        span_id=span_id,
        kind=SpanKind.TOOL_EXECUTION,
        name="refund",
        tool=tool,
        approvals=approvals,
        effects=effects,
        identity=identity,
    )


def _records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# --- append-only, and the promise that makes truncation legible -------------


def test_the_header_is_on_disk_before_the_first_span(tmp_path: Path) -> None:
    """A session that runs for hours is readable from the moment it starts."""
    path = tmp_path / "trace.jsonl"
    writer = _writer(path)

    header = _records(path)[0]

    assert header["trace_id"] == "t-1"
    assert header["terminated"] is True
    writer.close()


def test_a_session_closed_cleanly_reads_back_whole(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    with _writer(path) as trace:
        trace.span(_refund_span())

    read = read_trace(path, Dialect.GUARDANA)

    assert read.trace.truncated is None
    assert [span.span_id for span in read.trace.spans] == ["s2"]


def test_a_session_still_running_reads_as_unterminated(tmp_path: Path) -> None:
    """The reason the model has carried since 0.14 and nothing has ever produced.

    A collector or an operator grabbing the file mid-session must not be told the
    execution finished and nothing was found — it is still going.
    """
    path = tmp_path / "trace.jsonl"
    writer = _writer(path)
    writer.span(_refund_span())

    assert read_trace(path, Dialect.GUARDANA).trace.truncated is TraceTruncation.UNTERMINATED
    writer.close()


def test_an_exception_inside_the_session_leaves_the_file_unterminated(tmp_path: Path) -> None:
    """Which is the truth about that session, so the writer does not tidy it away."""
    path = tmp_path / "trace.jsonl"

    def fall_over(trace: TraceWriter) -> None:
        trace.span(_refund_span())
        raise RuntimeError("the agent fell over")

    with pytest.raises(RuntimeError), _writer(path) as trace:
        fall_over(trace)

    assert read_trace(path, Dialect.GUARDANA).trace.truncated is TraceTruncation.UNTERMINATED


def test_each_span_reaches_the_file_before_the_next_one_is_written(tmp_path: Path) -> None:
    """Buffering would lose exactly the spans a crashed session most needs to have kept."""
    path = tmp_path / "trace.jsonl"
    writer = _writer(path)

    writer.span(_refund_span(span_id="s1"))
    first = read_trace(path, Dialect.GUARDANA)
    writer.span(_refund_span(span_id="s2"))

    assert [span.span_id for span in first.trace.spans] == ["s1"]
    assert len(read_trace(path, Dialect.GUARDANA).trace.spans) == 2
    writer.close()


def test_the_footer_counts_what_was_written(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    with _writer(path) as trace:
        trace.span(_refund_span(span_id="s1"))
        trace.span(_refund_span(span_id="s2"))

    assert _records(path)[-1] == {"guardana_trace_end": 3, "spans": 2}


def test_a_span_written_after_close_is_refused(tmp_path: Path) -> None:
    """The file has already claimed to be complete; appending would make that a lie."""
    path = tmp_path / "trace.jsonl"
    writer = _writer(path)
    writer.close()

    with pytest.raises(TraceWriteError, match="closed"):
        writer.span(_refund_span())


# --- validation at the source ----------------------------------------------


def test_a_span_this_build_could_not_read_back_is_refused_at_write_time(tmp_path: Path) -> None:
    """Otherwise the producer learns about it when somebody finally grades the file.

    By then the run it was supposed to cover is gone. The check is a round trip
    through the real reader, so the writer and the reader cannot drift apart either.
    """
    path = tmp_path / "trace.jsonl"
    with _writer(path) as trace, pytest.raises(TraceWriteError, match="span_id"):
        trace.span(_refund_span(span_id=""))


def test_a_refused_span_does_not_reach_the_file(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    with _writer(path) as trace:
        with pytest.raises(TraceWriteError):
            trace.span(_refund_span(span_id=""))
        trace.span(_refund_span(span_id="s2"))

    assert [span.span_id for span in read_trace(path, Dialect.GUARDANA).trace.spans] == ["s2"]


# --- the declaration, held in both directions ------------------------------


def test_a_block_for_a_dimension_nobody_declared_is_refused(tmp_path: Path) -> None:
    """Measured: such a file reads, drops the block, and grades clean over the evidence.

    An unapproved refund written into a trace declaring only `messages` and `tools` is
    sitting in the file, read, discarded, and never graded.
    """
    path = tmp_path / "trace.jsonl"
    declared = (Dimension.MESSAGES, Dimension.TOOLS)
    approved = _refund_span(
        tool=ToolExecution(name="refund"),
        approvals=(Approval.granted_by_human("alice", action="refund"),),
    )
    with (
        _writer(path, instrumented=declared, sinks=None) as trace,
        pytest.raises(TraceWriteError, match="approval"),
    ):
        trace.span(approved)


def test_declaring_effects_without_a_sink_map_is_refused_when_the_session_opens(
    tmp_path: Path,
) -> None:
    """The engine knows no vendor, so it cannot know a framework's `terminal` is a shell.

    Refused at `open` rather than at the first tool call, because that is the moment
    the integrator is still writing the integration.
    """
    with pytest.raises(TraceWriteError, match="sink"):
        _writer(tmp_path / "trace.jsonl", sinks=None)


def test_a_mutating_tool_records_its_effect_even_when_the_integrator_forgot(
    tmp_path: Path,
) -> None:
    """This is the false green, closed: the measured file that graded clean cannot be written."""
    path = tmp_path / "trace.jsonl"
    with _writer(path) as trace:
        trace.span(_refund_span())

    (effect,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].effects

    assert effect.sink is SinkKind.PAYMENT
    assert effect.action == "refund"
    assert effect.status is EffectStatus.EXECUTED


def test_a_mutating_tool_nobody_mapped_is_refused_rather_than_recorded_as_harmless(
    tmp_path: Path,
) -> None:
    """`other` is on neither consequential list, so falling back to it silently would
    turn "nobody mapped this tool" into "this tool cannot hurt anyone"."""
    path = tmp_path / "trace.jsonl"
    with _writer(path) as trace, pytest.raises(TraceWriteError, match="terminal"):
        trace.span(_refund_span(tool=ToolExecution(name="terminal", mutates=True)))


def test_an_unmapped_tool_that_changed_nothing_takes_the_declared_default(
    tmp_path: Path,
) -> None:
    """An effect of unknown kind is still an effect. What is not allowed is no record."""
    path = tmp_path / "trace.jsonl"
    with _writer(path) as trace:
        trace.span(_refund_span(tool=ToolExecution(name="search")))

    (effect,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].effects
    assert effect.sink is SinkKind.OTHER


def test_the_tools_that_fell_through_to_the_default_are_reported(tmp_path: Path) -> None:
    """So an integrator finds out from their own run rather than from an auditor."""
    path = tmp_path / "trace.jsonl"
    with _writer(path) as trace:
        trace.span(_refund_span(span_id="s1", tool=ToolExecution(name="search")))
        trace.span(_refund_span(span_id="s2", tool=ToolExecution(name="browse")))
        trace.span(_refund_span(span_id="s3"))
        unmapped = trace.unmapped_tools

    assert unmapped == frozenset({"search", "browse"})


def test_an_effect_the_integrator_recorded_is_left_exactly_as_written(tmp_path: Path) -> None:
    """Derivation fills a gap; it never overrides somebody who knows more than the map."""
    path = tmp_path / "trace.jsonl"
    written = SideEffect(
        sink=SinkKind.PAYMENT,
        action="payment.refund",
        target="order/12",
        status=EffectStatus.EXECUTED,
        reversible=False,
    )
    with _writer(path) as trace:
        trace.span(_refund_span(effects=(written,)))

    (effect,) = read_trace(path, Dialect.GUARDANA).trace.spans[0].effects
    assert effect == written


def test_a_span_with_no_tool_gains_no_effect(tmp_path: Path) -> None:
    """A model call is not a side effect, and inventing one would accuse a system of it."""
    path = tmp_path / "trace.jsonl"
    with _writer(path) as trace:
        trace.span(
            Span(
                span_id="s1",
                kind=SpanKind.MODEL_CALL,
                name="chat",
                messages=(Message(role=Role.USER, parts=()),),
            )
        )

    assert read_trace(path, Dialect.GUARDANA).trace.spans[0].effects == ()


def test_identity_is_a_dimension_like_any_other(tmp_path: Path) -> None:
    """The check reads the same table the reader derives from, so the two cannot disagree."""
    path = tmp_path / "trace.jsonl"
    with _writer(path) as trace, pytest.raises(TraceWriteError, match="identity"):
        trace.span(_refund_span(identity=Identity(actor="a", claimed_resource="https://x/")))


def test_closing_twice_does_not_write_a_second_footer(tmp_path: Path) -> None:
    """An integrator that closes and also uses `with` would otherwise sign off twice."""
    path = tmp_path / "trace.jsonl"
    writer = _writer(path)
    writer.close()
    writer.close()

    assert [record for record in _records(path) if "guardana_trace_end" in record] == [
        {"guardana_trace_end": 3, "spans": 0}
    ]


def test_a_path_that_cannot_be_opened_is_refused_as_a_write_error(tmp_path: Path) -> None:
    """One exception type for the integrator to catch, whatever went wrong."""
    with pytest.raises(TraceWriteError, match="could not be opened"):
        _writer(tmp_path / "no-such-directory" / "trace.jsonl")


def test_a_sink_that_cannot_be_written_to_is_refused_when_the_header_goes_down(
    tmp_path: Path,
) -> None:
    """A producer whose disk is full learns at `open`, not after a session of lost spans."""

    class _FullDisk(StringIO):
        def write(self, s: str) -> int:
            raise OSError("no space left on device")

    with pytest.raises(TraceWriteError, match="could not be written"):
        TraceWriter(_FullDisk(), {"guardana_trace": 3}, frozenset(), None)
