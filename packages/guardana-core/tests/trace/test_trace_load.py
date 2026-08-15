"""Reading a native trace: what it refuses, and what it counts rather than drops.

Every test here inverts a production behaviour rather than a branch. The ones that
matter most are the refusals: a version from the future, a misspelled span key, a
dimension name nobody defined. Each of those, read leniently, produces a trace that
grades clean or a rule that accuses a system which did nothing wrong.
"""

import json
from pathlib import Path

import pytest
from guardana.core.trace import (
    TRACE_SCHEMA_VERSION,
    Dialect,
    Dimension,
    TraceLoadError,
    TraceTruncation,
    detect_dialect,
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
    with pytest.raises(TraceLoadError, match="not a known reason"):
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
