"""Writing a native trace one span at a time, and refusing the ones that grade clean.

`serialize_trace` renders a finished trace in one call. That is right for converting
an export and wrong for a producer: a live agent cannot buffer a session that runs for
hours, and a file that stops mid-session has to say so rather than look finished.

Three refusals, each closing a measured false green rather than tidying an API. See
`docs/design/trace-producer.md` for the four traces that located them:

- a **block for an undeclared dimension** is dropped in silence by every reader, so
  one typo in a declaration list removes a producer's whole authorization coverage;
- a **declared `effects` dimension with nothing in it** is the clean pass — a
  recorded mutating tool call, no effect beside it, and `✓ No findings.`;
- a **span this build cannot read back** is evidence lost until somebody grades the
  file, by which time the run it covered is gone.

This is a convenience over the file format, never the only door in. The contract is
`schemas/trace-v3.schema.json`, and a team emitting JSONL from Go stays a
first-class producer.
"""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import IO

from guardana.core.trace import _native
from guardana.core.trace._parse import TraceLoadError, text_tuple
from guardana.core.trace.effect import EffectStatus, SideEffect, SinkKind
from guardana.core.trace.model import TRACE_SCHEMA_VERSION, Dimension
from guardana.core.trace.presence import dimensions_of
from guardana.core.trace.serialize import span_of
from guardana.core.trace.sinks import SinkMap
from guardana.core.trace.span import Span
from guardana.core.trace.tool import ToolExecution, ToolStatus

__all__ = ["SinkMap", "TraceWriteError", "TraceWriter", "open_trace", "resume_trace"]

_EFFECT_STATUS = {
    ToolStatus.SUCCEEDED: EffectStatus.EXECUTED,
    ToolStatus.FAILED: EffectStatus.FAILED,
    ToolStatus.UNKNOWN: EffectStatus.ATTEMPTED,
}
"""How far an effect got, read off how the tool call ended.

`UNKNOWN` becomes `ATTEMPTED` rather than `EXECUTED`: a producer that did not record
whether the call worked has not established that it landed, and reporting an attempt
as a consequence attributes to a system the very thing it might have refused.
"""


class TraceWriteError(Exception):
    """A trace this build refuses to write, and why.

    Raised rather than logged. A producer that learns about a malformed span from a
    warning has already shipped the run it was supposed to cover.
    """


def open_trace(  # noqa: PLR0913 — one keyword per fact the header records
    path: Path,
    *,
    trace_id: str,
    producer: str,
    instrumented: Iterable[Dimension],
    producer_version: str | None = None,
    sinks: SinkMap | None = None,
    recorded_at: datetime | None = None,
    attributes: Mapping[str, str] | None = None,
) -> "TraceWriter":
    """Start a trace file, writing its header before the first span exists.

    The header goes down immediately, so a session that runs for hours is readable
    from the moment it starts and a session that dies is readable at all. It declares
    `terminated`, which is what licenses a reader to call a missing footer truncation
    rather than a finished file.
    """
    declared = frozenset(instrumented)
    _refuse_effects_without_sinks(declared, sinks)
    header = _header(
        declared,
        trace_id=trace_id,
        producer=producer,
        producer_version=producer_version,
        recorded_at=recorded_at,
        attributes=attributes,
    )
    return TraceWriter(_opened(path, "w"), header, declared, sinks, session_scope=True)


def resume_trace(  # noqa: PLR0913 — the same keywords `open_trace` takes, by design
    path: Path,
    *,
    trace_id: str,
    producer: str,
    instrumented: Iterable[Dimension],
    producer_version: str | None = None,
    sinks: SinkMap | None = None,
    recorded_at: datetime | None = None,
    attributes: Mapping[str, str] | None = None,
) -> "TraceWriter":
    """Create the file on a session's first event, and continue it on every later one.

    `open_trace` assumes one process holds the file for the whole session. A large
    family of agents does not work that way: each hook fires a separate command, so the
    header, the spans and the footer are written by processes that never meet. Opening
    for writing on each of those leaves one span per session under a header claiming
    the rest.

    Takes the same keywords as `open_trace` so a hook script can call it unconditionally
    with one set of arguments, and refuses the two ways continuing goes wrong: a
    producer whose declaration changed halfway through a session, and a file that has
    already signed off.
    """
    declared = frozenset(instrumented)
    _refuse_effects_without_sinks(declared, sinks)
    existing = _existing_trace(path)
    if existing is None:
        header = _header(
            declared,
            trace_id=trace_id,
            producer=producer,
            producer_version=producer_version,
            recorded_at=recorded_at,
            attributes=attributes,
        )
        return TraceWriter(_opened(path, "w"), header, declared, sinks)
    existing.refuse_unless_continuable(path, trace_id, declared)
    handle = _opened(path, "a")
    if not existing.ends_with_newline:
        handle.write("\n")
    return TraceWriter(handle, None, declared, sinks, spans=existing.spans)


def _refuse_effects_without_sinks(declared: frozenset[Dimension], sinks: SinkMap | None) -> None:
    if Dimension.EFFECTS in declared and sinks is None:
        raise TraceWriteError(
            "this producer declares it records effects and passed no sink map, so a tool "
            "call could not be turned into an effect. The engine knows no vendor and "
            "cannot know which of your tools reaches a shell — pass sinks=SinkMap(...)"
        )


def _header(  # noqa: PLR0913 — one parameter per fact the header records
    declared: frozenset[Dimension],
    *,
    trace_id: str,
    producer: str,
    producer_version: str | None,
    recorded_at: datetime | None,
    attributes: Mapping[str, str] | None,
) -> dict[str, object]:
    """Build the first record: the version, the identity, and both promises."""
    return {
        _native.VERSION_KEY: TRACE_SCHEMA_VERSION,
        "trace_id": trace_id,
        "producer": {
            k: v
            for k, v in (
                ("name", producer),
                ("version", producer_version),
                ("recorded_at", recorded_at.isoformat() if recorded_at is not None else None),
            )
            if v is not None
        },
        "instrumented": sorted(str(d) for d in declared),
        "terminated": True,
        **({"attributes": dict(attributes)} if attributes else {}),
    }


@dataclass(frozen=True, slots=True)
class _ExistingTrace:
    """What one pass over a file already on disk says about continuing it.

    Counted rather than parsed. Only the first and last records are read as JSON; the
    spans between them are lines, because the count is all a footer needs and parsing
    every one of them on every hook invocation would make a session quadratic in its
    own length.
    """

    header: Mapping[str, object]
    spans: int
    closed: bool
    ends_with_newline: bool

    def refuse_unless_continuable(
        self, path: Path, trace_id: str, declared: frozenset[Dimension]
    ) -> None:
        """Refuse a file this session has no business appending to."""
        if self.closed:
            raise TraceWriteError(
                f"{path} already carries a footer, so it claims to be complete; appending "
                f"a span now would make that claim false"
            )
        if self.header.get("terminated") is not True:
            raise TraceWriteError(
                f"{path} was not written by a producer that promised a footer, so the "
                f"sign-off this would add is one no reader accepts. Start a new file rather "
                f"than continuing a hand-written or converted one"
            )
        if self.header.get("trace_id") != trace_id:
            raise TraceWriteError(
                f"{path} records trace_id {self.header.get('trace_id')!r} and this session is "
                f"{trace_id!r} — two executions in one file are not one execution"
            )
        recorded = frozenset(str(d) for d in text_tuple(self.header, "instrumented"))
        if recorded != frozenset(str(d) for d in declared):
            raise TraceWriteError(
                f"{path} declares instrumented {sorted(recorded)} and this call declares "
                f"{sorted(str(d) for d in declared)} — half a session graded under one "
                f"declaration and half under another is not one run"
            )


def _existing_trace(path: Path) -> _ExistingTrace | None:
    """Read what is already there, or `None` when this is the session's first event."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as exc:
        raise TraceWriteError(f"{path} could not be read to continue it: {exc}") from exc
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    header = _readable(path, lines[0], "header")
    if _native.VERSION_KEY not in header:
        raise TraceWriteError(
            f"{path} does not open with a native trace header, so there is nothing here to "
            f"continue (an OpenTelemetry export is converted with --write-trace, not appended to)"
        )
    return _ExistingTrace(
        header=header,
        spans=len(lines) - 1,
        closed=_signed_off(lines[-1]) if len(lines) > 1 else False,
        ends_with_newline=text.endswith("\n"),
    )


def _signed_off(line: str) -> bool:
    """Whether the file's last record is a footer.

    Read leniently, unlike the header. A last line that does not parse is the torn
    write this whole shape exists to survive — a process killed mid-append — and it is
    certainly not a sign-off. Refusing there would cost every span of the rest of the
    session to recover one that was already lost.
    """
    try:
        parsed = json.loads(line)
    except ValueError:
        return False
    return isinstance(parsed, dict) and _native.FOOTER_KEY in parsed


def _readable(path: Path, line: str, what: str) -> Mapping[str, object]:
    """Parse one record, refusing a file whose shape cannot be established."""
    try:
        parsed = json.loads(line)
    except ValueError as exc:
        raise TraceWriteError(f"{path}: its {what} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise TraceWriteError(f"{path}: its {what} is not a JSON object")
    return parsed


def _opened(path: Path, mode: str) -> IO[str]:
    try:
        return path.open(mode, encoding="utf-8")
    except OSError as exc:
        raise TraceWriteError(f"{path} could not be opened for writing: {exc}") from exc


class TraceWriter:
    """An open trace file: header written, spans appended, footer on close.

    Built by `open_trace` rather than constructed directly, because a writer whose
    header has not been written yet is a state no caller should be able to hold.
    """

    def __init__(  # noqa: PLR0913 — a handle, a header, two promises and two lifetimes
        self,
        handle: IO[str],
        header: Mapping[str, object] | None,
        instrumented: frozenset[Dimension],
        sinks: SinkMap | None,
        *,
        spans: int = 0,
        session_scope: bool = False,
    ) -> None:
        """Take an opened file, and write the header before anything else can happen.

        `header` is `None` when the file already carries one, and `spans` is then how
        many another process already wrote — a footer counting only this invocation's
        spans would read as records lost on the way here.

        `session_scope` says whether leaving a `with` block ends the *session* or only
        this writer's use of the file. It is the one real difference between a producer
        that holds the file for hours and one whose every event is a separate process.
        """
        self._handle = handle
        self._instrumented = instrumented
        self._sinks = sinks
        self._spans = spans
        self._session_scope = session_scope
        self._unmapped: set[str] = set()
        self._closed = False
        if header is not None:
            self._append(header)

    @property
    def unmapped_tools(self) -> frozenset[str]:
        """Tools that fell through to the sink map's default, so far.

        Read it at the end of a session and an integrator finds out which of their
        tools nobody classified — from their own run, rather than from an auditor.
        """
        return frozenset(self._unmapped)

    def span(self, span: Span) -> None:
        """Record one span, refusing anything a reader would drop or grade wrongly."""
        if self._closed:
            raise TraceWriteError(
                "this writer is closed; open the file again if the session is still going, "
                "and never after a footer, which claims the file is complete"
            )
        self._refuse_undeclared(span)
        record = span_of(self._with_effects(span))
        self._refuse_unreadable(record)
        self._append(record)
        self._spans += 1

    def finish(self) -> None:
        """Sign the session off: write the footer, then release the file.

        Separate from `close` because they are different claims. Releasing a file is
        housekeeping; a footer says *this execution is complete, and nothing after this
        point is missing*. A writer that signed off whenever it let go of the file would
        make every event of an out-of-process session look like the end of one.
        """
        if self._closed:
            return
        self._append({_native.FOOTER_KEY: TRACE_SCHEMA_VERSION, "spans": self._spans})
        self.close()

    def close(self) -> None:
        """Release the file without claiming the session ended."""
        if self._closed:
            return
        self._closed = True
        self._handle.close()

    def __enter__(self) -> "TraceWriter":
        """Hand back the open writer, so the footer is tied to leaving the block."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Sign off on a clean exit of a session-scoped writer; otherwise just let go.

        An exception never signs off, which is the truth about that session: a writer
        that tidied up after a crash would produce a file claiming to be complete over
        an execution nobody saw the end of. Neither does leaving the block of a resumed
        writer, because there the block is one event and not the session.
        """
        if exc_type is None and self._session_scope:
            self.finish()
        else:
            self.close()

    def _refuse_undeclared(self, span: Span) -> None:
        """Refuse a block whose dimension this producer did not declare.

        The safe direction for a reader — those blocks are dropped and their rules
        stand down — and a defect at the source: an unapproved refund written into a
        trace declaring only `messages` and `tools` sits in the file, read, discarded,
        and never graded. The producer can fix it in the line that caused it.
        """
        undeclared = sorted(str(d) for d in dimensions_of(span) - self._instrumented)
        if undeclared:
            raise TraceWriteError(
                f"span {span.span_id!r} records {', '.join(undeclared)} and this producer did "
                f"not declare it. A reader drops an undeclared block and stands its rules "
                f"down, so the evidence would be in the file and never graded — add it to "
                f"instrumented, or stop writing it"
            )

    def _with_effects(self, span: Span) -> Span:
        """Give a recorded tool call the effect that goes with it.

        The gap this closes is measured: a producer that declares `effects`, records a
        `mutates: true` tool call and writes no effect gets a clean pass over an
        execution that moved money, because the effect-shaped rules iterate the effects
        and an empty list is a loop that does not run.

        An effect the integrator wrote is left exactly as written — derivation fills a
        gap and never overrides somebody who knows more than the map does.
        """
        tool = span.tool
        if Dimension.EFFECTS not in self._instrumented or tool is None or span.effects:
            return span
        return _replace_effects(span, (self._effect_of(tool),))

    def _effect_of(self, tool: ToolExecution) -> SideEffect:
        """Turn one tool execution into the effect record the sink map describes."""
        sink = self._sinks.sink_for(tool.name) if self._sinks is not None else None
        if sink is None:
            self._refuse_unmapped_mutation(tool)
            self._unmapped.add(tool.name)
            sink = self._sinks.default if self._sinks is not None else SinkKind.OTHER
        return SideEffect(sink=sink, action=tool.name, status=_EFFECT_STATUS[tool.status])

    def _refuse_unmapped_mutation(self, tool: ToolExecution) -> None:
        """Refuse an unmapped tool the producer itself called a mutation.

        `other` is on neither consequential list, so letting a mutating call fall
        through to the default would record "nobody classified this tool" as "this tool
        cannot hurt anyone". A read-only tool falling through is a gap in a map; this
        one is a gap in a verdict.
        """
        if tool.mutates is True:
            raise TraceWriteError(
                f"tool {tool.name!r} changed something and no sink is mapped for it, so its "
                f"effect would be recorded as 'other' — which no rule treats as "
                f"consequential. Map it, or record the effect on the span yourself"
            )

    def _refuse_unreadable(self, record: Mapping[str, object]) -> None:
        """Read the span back through the real parser before it reaches the file.

        Unknown keys and unreadable values are refused on *read* today, which means a
        producer with a typo learns about it when somebody finally grades the file. The
        round trip also keeps the writer and the reader from drifting: they cannot
        disagree about a shape if every written span has to survive both.
        """
        try:
            _native.span_from(json.loads(json.dumps(record)))
        except (TraceLoadError, TypeError, ValueError) as exc:
            raise TraceWriteError(
                f"this span is not one this build could read back: {exc}"
            ) from exc

    def _append(self, record: Mapping[str, object]) -> None:
        """Append one record and push it to the file, so a crash keeps what came before."""
        try:
            self._handle.write(json.dumps(record, sort_keys=True) + "\n")
            self._handle.flush()
        except OSError as exc:
            raise TraceWriteError(f"this trace could not be written to: {exc}") from exc


def _replace_effects(span: Span, effects: tuple[SideEffect, ...]) -> Span:
    """Copy the span, carrying these effects instead of its own.

    Written out rather than `dataclasses.replace` because `Span` is slotted and this
    stays explicit about producing a new value: the caller's span is never mutated,
    since an integrator may well hold on to it.
    """
    fields = {f: getattr(span, f) for f in span.__dataclass_fields__}
    fields["effects"] = effects
    return Span(**fields)
