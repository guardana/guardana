"""Reading a native trace: what it refuses, and what it counts rather than drops.

Every test here inverts a production behaviour rather than a branch. The ones that
matter most are the refusals: a version from the future, a misspelled span key, a
dimension name nobody defined. Each of those, read leniently, produces a trace that
grades clean or a rule that accuses a system which did nothing wrong.
"""

import hashlib
import io
import json
import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.core.fingerprint import DigestKind
from guardana.core.trace import (
    TRACE_SCHEMA_VERSION,
    Dialect,
    Dimension,
    TraceLoadError,
    TraceTruncation,
    detect_dialect,
    load,
    read_trace,
)
from guardana.core.trace._native import migrate_header
from guardana.core.trace.limits import MAX_RECORD_BYTES, MAX_SPANS

_HEADER = {
    "guardana_trace": 1,
    "trace_id": "t-1",
    "producer": {"name": "acme", "version": "1.2", "recorded_at": "2026-08-09T10:00:00+00:00"},
    "instrumented": ["messages", "identity"],
}


def _write(tmp_path: Path, *records: object, name: str = "trace.jsonl") -> Path:
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def test_a_native_header_carries_the_producer_and_what_it_records(tmp_path: Path) -> None:
    path = _write(tmp_path, _HEADER, {"span_id": "s1", "kind": "model_call", "name": "chat"})
    read = read_trace(path)
    assert read.trace.trace_id == "t-1"
    assert read.trace.provenance.producer == "acme"
    assert read.trace.provenance.producer_version == "1.2"
    assert read.trace.instrumented == frozenset({Dimension.MESSAGES, Dimension.IDENTITY})
    assert len(read.trace.spans) == 1


def test_a_file_with_no_version_key_is_refused_rather_than_read_as_version_one(
    tmp_path: Path,
) -> None:
    """Guessing a version is how an unversioned format acquires a version in name only."""
    path = _write(tmp_path, {"trace_id": "t-1"}, name="headerless.jsonl")
    with pytest.raises(TraceLoadError, match="guardana_trace"):
        read_trace(path, Dialect.GUARDANA)


def test_a_version_this_build_cannot_read_is_refused(tmp_path: Path) -> None:
    """Reading it as v1 would drop the fields we do not know and grade what was left."""
    path = _write(tmp_path, {**_HEADER, "guardana_trace": 99})
    with pytest.raises(TraceLoadError, match="schema version 99"):
        read_trace(path)


def test_version_zero_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, {**_HEADER, "guardana_trace": 0})
    with pytest.raises(TraceLoadError, match="1 or greater"):
        read_trace(path, Dialect.GUARDANA)


def test_a_misspelled_span_key_is_refused_not_ignored(tmp_path: Path) -> None:
    """The defect this prevents: `aprovals` leaves the approval dimension declared and empty.

    The rule then runs, finds no approval, and reports a system that approved everything
    properly. A spelling mistake producing a false accusation is worse than a load error.
    """
    path = _write(tmp_path, _HEADER, {"span_id": "s1", "aprovals": []})
    with pytest.raises(TraceLoadError, match="aprovals"):
        read_trace(path)


def test_a_misspelled_dimension_is_refused_not_read_as_absent(tmp_path: Path) -> None:
    path = _write(tmp_path, {**_HEADER, "instrumented": ["aproval"]})
    with pytest.raises(TraceLoadError, match="aproval"):
        read_trace(path)


def test_a_misspelled_header_key_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, {**_HEADER, "instrumentd": []})
    with pytest.raises(TraceLoadError, match="instrumentd"):
        read_trace(path)


def test_an_unparseable_truncation_reason_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, {**_HEADER, "truncated": "somebody-unplugged-it"})
    with pytest.raises(TraceLoadError, match=r"truncated .* not one of"):
        read_trace(path)


def test_a_declared_truncation_survives_into_the_trace(tmp_path: Path) -> None:
    path = _write(tmp_path, {**_HEADER, "truncated": "producer_limit"}, {"span_id": "s1"})
    assert read_trace(path).trace.truncated is TraceTruncation.PRODUCER_LIMIT


def test_an_oversized_record_is_counted_unreadable_rather_than_parsed(tmp_path: Path) -> None:
    """A span carrying a base64 video must not decide the memory profile of the read."""
    huge = {"span_id": "s1", "name": "x" * (MAX_RECORD_BYTES + 10)}
    path = _write(tmp_path, _HEADER, huge, {"span_id": "s2"})
    read = read_trace(path)
    assert len(read.unreadable) == 1
    assert "over the" in read.unreadable[0].reason
    assert read.trace.unreadable == 1
    assert [s.span_id for s in read.trace.spans] == ["s2"]


def test_more_spans_than_the_ceiling_truncates_rather_than_shortening(tmp_path: Path) -> None:
    """A trace we stopped reading is incomplete, not smaller — a rule must not pass on it."""
    spans = [{"span_id": f"s{n}"} for n in range(MAX_SPANS + 5)]
    path = _write(tmp_path, _HEADER, *spans)
    read = read_trace(path)
    assert read.trace.truncated is TraceTruncation.READ_LIMIT
    assert len(read.trace.spans) == MAX_SPANS


def test_an_empty_file_is_refused_rather_than_read_as_an_empty_trace(tmp_path: Path) -> None:
    """An empty trace grades clean and exits 0, which is what a mistyped path looks like."""
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    with pytest.raises(TraceLoadError, match="no records"):
        read_trace(path)


def test_a_record_that_is_not_json_is_reported_by_line_number(tmp_path: Path) -> None:
    """Reported rather than refused, and never dropped in silence.

    This refused the whole file until a writer made a torn last line the expected way
    for a crashed session to end. The point it was written for is unchanged: a step
    nobody can interpret has to be visible with its line number, because a reader that
    skipped it quietly would grade an execution that never happened.
    """
    path = tmp_path / "broken.jsonl"
    path.write_text(json.dumps(_HEADER) + "\nnot json\n", encoding="utf-8")

    read = read_trace(path)

    assert read.trace.spans == ()
    assert read.trace.unreadable == 1
    assert read.unreadable[0].line == 2


def test_a_file_that_is_not_utf8_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "binary.jsonl"
    path.write_bytes(b"\xff\xfe{\x00")
    with pytest.raises(TraceLoadError, match="not UTF-8"):
        read_trace(path)


def test_detection_reads_the_first_record_and_not_the_filename(tmp_path: Path) -> None:
    native = _write(tmp_path, _HEADER, name="looks-like-otel.jsonl")
    otel = _write(tmp_path, {"name": "chat", "spanId": "abc"}, name="looks-native.jsonl")
    assert detect_dialect(native) is Dialect.GUARDANA
    assert detect_dialect(otel) is Dialect.OTEL


def test_a_credential_recorded_in_the_clear_is_digested_and_discarded(tmp_path: Path) -> None:
    """`CredentialRef` has no field for a value, so a producer's carelessness stops here."""
    span = {
        "span_id": "s1",
        "identity": {"credential": {"kind": "bearer", "value": "tok-live-secret"}},
    }
    read = read_trace(_write(tmp_path, _HEADER, span))
    credential = read.trace.spans[0].identity.credential  # type: ignore[union-attr]
    assert credential is not None
    assert credential.digest is not None
    assert "tok-live-secret" not in repr(read.trace)
    assert "tok-live-secret" not in read.trace.render()


def test_scopes_recorded_as_empty_are_not_the_same_as_scopes_never_recorded(
    tmp_path: Path,
) -> None:
    """The tri-state a rule depends on: a grant of none is a fact, an absent grant is not."""
    spans = [
        {"span_id": "s1", "consents": [{"client": "a", "granted": True, "scopes": []}]},
        {"span_id": "s2", "consents": [{"client": "b", "granted": True}]},
    ]
    read = read_trace(_write(tmp_path, _HEADER, *spans))
    assert read.trace.spans[0].consents[0].scopes == ()
    assert read.trace.spans[1].consents[0].scopes is None


def test_an_unreadable_timestamp_reads_as_absent_never_as_now(tmp_path: Path) -> None:
    """Substituting the current time would date somebody else's execution to our read."""
    path = _write(tmp_path, _HEADER, {"span_id": "s1", "started_at": "last tuesday"})
    assert read_trace(path).trace.spans[0].started_at is None


def test_a_version_one_trace_still_reads_under_this_build(tmp_path: Path) -> None:
    """The migration, tested by the property it exists for rather than by its return value.

    Every other test in this file writes a v1 header, so the whole file is the wide
    version of this. This one states it: v2 added `Span.agent`, and a v1 span that
    never had the field reads as absent — not as a span this build refuses, and not as
    an agent named "unknown", which is what inventing a default would have produced.
    """
    path = _write(tmp_path, {**_HEADER, "guardana_trace": 1}, {"span_id": "s1", "name": "chat"})

    read = read_trace(path)

    assert read.trace.spans[0].agent is None
    assert read.trace.schema_version == TRACE_SCHEMA_VERSION


def test_a_version_two_trace_carries_the_agent_that_performed_each_step(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {**_HEADER, "guardana_trace": 2},
        {"span_id": "s1", "agent": {"name": "researcher", "id": "a-1"}},
    )

    agent = read_trace(path).trace.spans[0].agent

    assert agent is not None
    assert (agent.name, agent.id) == ("researcher", "a-1")


def test_an_agent_record_with_no_name_reads_as_no_agent(tmp_path: Path) -> None:
    """A nameless actor is dropped rather than recorded, so two of them never compare equal."""
    path = _write(tmp_path, {**_HEADER, "guardana_trace": 2}, {"span_id": "s1", "agent": {}})

    assert read_trace(path).trace.spans[0].agent is None


def test_the_header_migration_hands_the_reader_a_current_version_document() -> None:
    """The seam's output is consumed, which the version this replaced could not claim.

    It took the already-parsed header's version and threw its own result away, so a
    migration that needed to change a field could not have. Asserting on what comes
    back is what makes the next migration a change with a test rather than a hope.
    """
    migrated = migrate_header({"guardana_trace": 1, "trace_id": "t-1"})

    assert migrated["guardana_trace"] == TRACE_SCHEMA_VERSION
    assert migrated["trace_id"] == "t-1"


def test_one_record_torn_by_a_crash_does_not_cost_the_whole_file(tmp_path: Path) -> None:
    """A producer killed mid-append leaves a partial line, and the rest is still evidence.

    Refusing the file was the behaviour until a writer made this an expected way for a
    session to end. `UnreadableRecord` has existed since the reader did, for exactly
    this: a step nobody can interpret is reported, never silently dropped and never
    allowed to take the execution around it with it.
    """
    path = tmp_path / "torn.jsonl"
    path.write_text(
        f"{json.dumps(_HEADER)}\n"
        f"{json.dumps({'span_id': 's1', 'kind': 'model_call', 'name': 'chat'})}\n"
        f'{{"span_id": "s2", "kind": "tool_ex\n'
        f"{json.dumps({'span_id': 's3', 'kind': 'model_call', 'name': 'chat'})}\n",
        encoding="utf-8",
    )

    read = read_trace(path, Dialect.GUARDANA)

    assert [span.span_id for span in read.trace.spans] == ["s1", "s3"]
    assert read.trace.unreadable == 1
    assert "line 3" in read.unreadable[0].reason or read.unreadable[0].line == 3


def test_a_header_this_build_cannot_parse_still_refuses_the_file(tmp_path: Path) -> None:
    """A record can be lost; the record saying what the file *is* cannot be guessed at."""
    path = tmp_path / "torn-header.jsonl"
    path.write_text('{"guardana_trace": 1, "trace_id": "t\n', encoding="utf-8")

    with pytest.raises(TraceLoadError, match="JSON"):
        read_trace(path, Dialect.GUARDANA)


def test_a_record_that_is_not_an_object_is_counted_rather_than_refusing_the_file(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path, _HEADER, {"span_id": "s1", "kind": "model_call", "name": "c"}, [1, 2])

    read = read_trace(path, Dialect.GUARDANA)

    assert [span.span_id for span in read.trace.spans] == ["s1"]
    assert read.trace.unreadable == 1


class _MeteredText(io.StringIO):
    """Text that remembers the longest piece any reader took from it at once."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.longest = 0
        self.consumed = 0

    def _meter(self, piece: str) -> str:
        self.longest = max(self.longest, len(piece))
        self.consumed += len(piece)
        return piece

    def readline(self, size: int | None = -1, /) -> str:  # type: ignore[override]
        return self._meter(super().readline(-1 if size is None else size))

    def __next__(self) -> str:  # type: ignore[override]
        return self._meter(super().__next__())


@pytest.fixture
def small_ceilings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("guardana.core.trace.load.MAX_RECORD_BYTES", 64)
    monkeypatch.setattr("guardana.core.trace.load.MAX_TRACE_BYTES", 10_000)


@pytest.mark.usefixtures("small_ceilings")
def test_an_oversized_line_is_skipped_without_ever_being_held_whole() -> None:
    """The per-record ceiling bounds memory only if it is checked before the line exists."""
    handle = _MeteredText("x" * 5_000 + '\n{"span_id":"s2"}\n')
    records = list(load._records(Path("t.jsonl"), handle))
    assert [type(r).__name__ for r in records] == ["_TooLong", "str"]
    assert records[1] == '{"span_id":"s2"}'
    assert handle.longest <= 65


@pytest.mark.usefixtures("small_ceilings")
def test_a_line_past_the_trace_ceiling_stops_the_read_without_reading_the_rest() -> None:
    handle = _MeteredText("x" * 100_000 + "\n")
    records = list(load._records(Path("t.jsonl"), handle))
    assert [type(r).__name__ for r in records] == ["_Overflow"]
    assert handle.consumed < 11_000


@pytest.mark.usefixtures("small_ceilings")
def test_padding_around_a_record_does_not_count_against_its_ceiling() -> None:
    padded = " " * 500 + '{"span_id":"s1"}' + " " * 500 + "\n"
    blank = " " * 500 + "\n"
    records = list(load._records(Path("t.jsonl"), _MeteredText(padded + blank)))
    assert records == ['{"span_id":"s1"}']


@pytest.mark.usefixtures("small_ceilings")
def test_whitespace_inside_a_record_counts_against_its_ceiling() -> None:
    record = '{"a": "' + " " * 100 + '"}'
    records = list(load._records(Path("t.jsonl"), _MeteredText(record + "\n")))
    assert len(records) == 1
    assert isinstance(records[0], load._TooLong)
    assert f"record is {len(record)} bytes" in records[0].reason


@pytest.mark.usefixtures("small_ceilings")
@pytest.mark.parametrize(
    "padding",
    [" " * 100_000 + "\n", "\n" * 100_000, " \n" * 50_000],
    ids=["one-blank-line", "empty-lines", "blank-lines"],
)
def test_whitespace_counts_toward_the_trace_ceiling_and_stops_the_read(padding: str) -> None:
    handle = _MeteredText(padding + '{"span_id":"s1"}\n')
    records = list(load._records(Path("t.jsonl"), handle))
    assert [type(r).__name__ for r in records] == ["_Overflow"]
    assert handle.consumed < 11_000


@pytest.mark.usefixtures("small_ceilings")
def test_the_record_ceiling_counts_utf8_bytes_not_characters() -> None:
    record = '{"a":"' + "\U0001f600" * 16 + '"}'
    assert len(record) <= 64 < len(record.encode("utf-8"))
    records = list(load._records(Path("t.jsonl"), _MeteredText(record + "\n")))
    assert len(records) == 1
    assert isinstance(records[0], load._TooLong)
    assert f"record is {len(record.encode('utf-8'))} bytes" in records[0].reason


@pytest.mark.usefixtures("small_ceilings")
def test_the_trace_ceiling_counts_utf8_bytes_not_characters() -> None:
    line = '{"a":"' + "\U0001f600" * 10 + '"}\n'
    text = line * 300
    assert len(text) < 10_000 < len(text.encode("utf-8"))
    records = list(load._records(Path("t.jsonl"), _MeteredText(text)))
    assert isinstance(records[-1], load._Overflow)


def test_blank_crlf_lines_count_every_byte_toward_the_trace_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("guardana.core.trace.load.MAX_TRACE_BYTES", 1_000)
    header = json.dumps(_HEADER).encode("utf-8")
    path = tmp_path / "trace.jsonl"
    path.write_bytes(header + b"\r\n" + b"\r\n" * 600 + b'{"span_id":"s1"}\r\n')
    assert len(header) + 2 + 600 < 1_000 < len(header) + 2 + 1_200

    read = read_trace(path, Dialect.GUARDANA)

    assert read.trace.truncated is TraceTruncation.READ_LIMIT
    assert read.trace.spans == ()


def test_crlf_line_endings_still_read_every_record(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    path.write_bytes(
        json.dumps(_HEADER).encode("utf-8") + b"\r\n" + b'{"span_id":"s1","kind":"model_call"}\r\n'
    )

    read = read_trace(path)

    assert [s.span_id for s in read.trace.spans] == ["s1"]
    assert read.unreadable == ()


def test_an_oversized_line_still_leaves_a_whole_file_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Skipping the rest of a line still passes its bytes through the digest."""
    monkeypatch.setattr("guardana.core.trace.load.MAX_RECORD_BYTES", 200)
    path = _write(tmp_path, _HEADER, {"span_id": "s1", "name": "x" * 500}, {"span_id": "s2"})
    read = read_trace(path)
    document = read.trace.provenance.document
    assert [s.span_id for s in read.trace.spans] == ["s2"]
    assert read.trace.unreadable == 1
    assert document is not None
    assert document.kind is DigestKind.CONTENT
    assert document.digest == f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _outcome_within_guard(read: Callable[[Path], object], path: Path) -> list[object]:
    """Read `path` on a thread; a read still blocked at the guard releases it and fails the test."""
    outcome: list[object] = []

    def attempt() -> None:
        try:
            outcome.append(read(path))
        except Exception as exc:
            outcome.append(exc)

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(10)
    if worker.is_alive():
        os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail(f"reading the FIFO at {path.name} blocked")
    return outcome


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no FIFOs")
@pytest.mark.parametrize(
    "read",
    [detect_dialect, lambda path: read_trace(path, Dialect.GUARDANA)],
    ids=["detect-dialect", "read-with-dialect"],
)
def test_a_trace_that_is_a_fifo_is_refused_without_blocking(
    tmp_path: Path, read: Callable[[Path], object]
) -> None:
    path = tmp_path / "trace.jsonl"
    os.mkfifo(path)

    outcome = _outcome_within_guard(read, path)

    assert len(outcome) == 1
    assert isinstance(outcome[0], TraceLoadError)
    assert "not a regular file" in str(outcome[0])
