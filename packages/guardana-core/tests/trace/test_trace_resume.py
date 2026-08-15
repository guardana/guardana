"""Continuing a trace another process started, which is what a shell-hook agent is.

`open_trace` assumes one long-lived process holds the file. A large family of agents
does not work that way: each hook fires a separate command with a JSON payload on
stdin, so the header, the spans and the footer are written by different processes that
never see each other. Truncating the file on every event — which opening for writing
does — would leave one span per session and a header claiming the rest.

`resume_trace` is the same contract from the other side: create the file on the first
event, continue it on every later one, and refuse the two ways that goes wrong — a
producer that changed its promise mid-session, and a file that has already signed off.
"""

import json
from pathlib import Path

import pytest
from guardana.core.trace import (
    Dialect,
    Dimension,
    SideEffect,
    SinkKind,
    SinkMap,
    Span,
    SpanKind,
    ToolExecution,
    TraceTruncation,
    open_trace,
    read_trace,
    resume_trace,
)
from guardana.core.trace.writer import TraceWriteError, TraceWriter

_INSTRUMENTED = (Dimension.TOOLS, Dimension.EFFECTS)
_SINKS = SinkMap({"terminal": SinkKind.SHELL}, default=SinkKind.OTHER)


def _resume(
    path: Path,
    instrumented: tuple[Dimension, ...] = _INSTRUMENTED,
    sinks: SinkMap | None = _SINKS,
    trace_id: str = "sess-1",
) -> TraceWriter:
    return resume_trace(
        path,
        trace_id=trace_id,
        producer="acme-hook",
        instrumented=instrumented,
        sinks=sinks,
    )


def _span(span_id: str) -> Span:
    return Span(
        span_id=span_id,
        kind=SpanKind.TOOL_EXECUTION,
        name="terminal",
        tool=ToolExecution(name="terminal", mutates=True),
    )


def _records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_the_first_event_of_a_session_creates_the_file(tmp_path: Path) -> None:
    path = tmp_path / "sess-1.jsonl"

    with _resume(path) as trace:
        trace.span(_span("s1"))

    assert _records(path)[0]["trace_id"] == "sess-1"


def test_a_later_event_continues_the_file_instead_of_truncating_it(tmp_path: Path) -> None:
    """The defect this exists against: one span per session, and a header over nothing."""
    path = tmp_path / "sess-1.jsonl"
    with _resume(path) as first:
        first.span(_span("s1"))
    with _resume(path) as second:
        second.span(_span("s2"))

    assert [span.span_id for span in read_trace(path, Dialect.GUARDANA).trace.spans] == ["s1", "s2"]


def test_only_one_header_is_ever_written(tmp_path: Path) -> None:
    path = tmp_path / "sess-1.jsonl"
    for step in range(3):
        with _resume(path) as trace:
            trace.span(_span(f"s{step}"))

    assert sum("guardana_trace" in record for record in _records(path)) == 1


def test_the_footer_counts_every_span_any_process_wrote(tmp_path: Path) -> None:
    """A count from this invocation alone would read as records lost on the way here."""
    path = tmp_path / "sess-1.jsonl"
    for step in range(3):
        with _resume(path) as trace:
            trace.span(_span(f"s{step}"))
    _resume(path).finish()

    assert _records(path)[-1] == {"guardana_trace_end": 3, "spans": 3}
    assert read_trace(path, Dialect.GUARDANA).trace.truncated is None


def test_leaving_the_block_of_a_resumed_writer_does_not_sign_the_session_off(
    tmp_path: Path,
) -> None:
    """The block is one event here, not the session — the next hook has not run yet.

    A writer that signed off whenever it let go of the file would make the first tool
    call of every out-of-process session look like the end of one.
    """
    path = tmp_path / "sess-1.jsonl"
    with _resume(path) as trace:
        trace.span(_span("s1"))

    assert not any("guardana_trace_end" in record for record in _records(path))
    assert read_trace(path, Dialect.GUARDANA).trace.truncated is TraceTruncation.UNTERMINATED


def test_a_session_that_never_reached_its_last_hook_is_unterminated(tmp_path: Path) -> None:
    path = tmp_path / "sess-1.jsonl"
    writer = _resume(path)
    writer.span(_span("s1"))
    writer._handle.close()

    assert read_trace(path, Dialect.GUARDANA).trace.truncated is TraceTruncation.UNTERMINATED


def test_a_producer_that_changed_its_promise_mid_session_is_refused(tmp_path: Path) -> None:
    """Half a session graded under one declaration and half under another is not one run."""
    path = tmp_path / "sess-1.jsonl"
    with _resume(path) as trace:
        trace.span(_span("s1"))

    with pytest.raises(TraceWriteError, match="instrumented"):
        _resume(path, instrumented=(Dimension.TOOLS,))


def test_a_second_session_writing_into_the_first_ones_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "sess-1.jsonl"
    with _resume(path) as trace:
        trace.span(_span("s1"))

    with pytest.raises(TraceWriteError, match="trace_id"):
        _resume(path, trace_id="sess-2")


def test_a_file_that_already_signed_off_is_refused(tmp_path: Path) -> None:
    """It claims to be complete, and appending would make that claim false."""
    path = tmp_path / "sess-1.jsonl"
    with _resume(path) as trace:
        trace.span(_span("s1"))
    _resume(path).finish()

    with pytest.raises(TraceWriteError, match="complete"):
        _resume(path)


def test_a_line_torn_off_by_a_crash_does_not_corrupt_the_next_one(tmp_path: Path) -> None:
    """The whole point of this shape is surviving a process that died. It died mid-write.

    The torn record is already lost, and refusing to continue would cost every span
    after it as well. So the file is closed off with a newline and the fragment stays
    exactly what it is: a record the reader reports as unreadable rather than one this
    writer hid by writing over it.
    """
    path = tmp_path / "sess-1.jsonl"
    with _resume(path) as trace:
        trace.span(_span("s1"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"span_id": "torn", "kind": "tool_ex')

    with _resume(path) as trace:
        trace.span(_span("s2"))

    read = read_trace(path, Dialect.GUARDANA)
    assert [span.span_id for span in read.trace.spans] == ["s1", "s2"]
    assert len(read.unreadable) == 1


def test_a_file_that_is_not_a_native_trace_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "sess-1.jsonl"
    path.write_text('{"resourceSpans": []}\n', encoding="utf-8")

    with pytest.raises(TraceWriteError, match="header"):
        _resume(path)


def test_an_empty_file_is_treated_as_a_session_nobody_has_started(tmp_path: Path) -> None:
    """A hook that fired, created the file and died before writing leaves exactly this."""
    path = tmp_path / "sess-1.jsonl"
    path.touch()

    with _resume(path) as trace:
        trace.span(_span("s1"))

    assert _records(path)[0]["trace_id"] == "sess-1"


def test_a_resumed_writer_refuses_an_undeclared_block_like_any_other(tmp_path: Path) -> None:
    """The declaration it enforces is the file's own, read back rather than re-supplied."""
    path = tmp_path / "sess-1.jsonl"
    started = open_trace(
        path, trace_id="sess-1", producer="acme-hook", instrumented=(Dimension.TOOLS,)
    )
    started.span(_span("s1"))
    started.close()

    with (
        _resume(path, instrumented=(Dimension.TOOLS,), sinks=None) as trace,
        pytest.raises(TraceWriteError, match="effects"),
    ):
        trace.span(
            Span(
                span_id="s2",
                kind=SpanKind.TOOL_EXECUTION,
                name="t",
                effects=(SideEffect(sink=SinkKind.SHELL, action="rm"),),
            )
        )
