"""A file that stops mid-session, told apart from a session where nothing else happened.

`TraceTruncation.UNTERMINATED` has been in the model since 0.14 and nothing has ever
produced it: the header is written first and cannot be amended, so a crashed producer
leaves a file indistinguishable from a finished one. Every rule that found nothing then
reports a pass over an execution it saw half of.

The promise is in the header, and that is the compatibility half: a file that never
promised a footer reads exactly as it always did. Making the footer's absence mean
truncation for *every* file would convert every trace anybody has into a decline.
"""

import json
from pathlib import Path

import pytest
from guardana.core.trace import Dialect, TraceLoadError, TraceTruncation, read_trace
from guardana.core.trace.limits import MAX_RECORD_BYTES
from jsonschema import Draft202012Validator

_HEADER = {
    "guardana_trace": 3,
    "trace_id": "t-1",
    "producer": {"name": "acme", "version": "1.0"},
    "instrumented": ["messages"],
}
_SPAN = {"span_id": "s1", "kind": "model_call", "name": "chat"}
_FOOTER = {"guardana_trace_end": 3, "spans": 1}


def _write(tmp_path: Path, *records: object) -> Path:
    path = tmp_path / "trace.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def test_a_promised_footer_that_arrived_leaves_the_trace_whole(tmp_path: Path) -> None:
    path = _write(tmp_path, {**_HEADER, "terminated": True}, _SPAN, _FOOTER)
    read = read_trace(path, Dialect.GUARDANA)
    assert read.trace.truncated is None
    assert len(read.trace.spans) == 1


def test_a_promised_footer_that_never_arrived_is_the_reason_the_model_already_carries(
    tmp_path: Path,
) -> None:
    """The whole point: an agent that died mid-session, and a rule that must not pass."""
    path = _write(tmp_path, {**_HEADER, "terminated": True}, _SPAN)
    assert read_trace(path, Dialect.GUARDANA).trace.truncated is TraceTruncation.UNTERMINATED


def test_a_file_that_promised_nothing_reads_exactly_as_it_did_before(tmp_path: Path) -> None:
    """Every trace written before this existed, and every hand-edited one, is this file."""
    path = _write(tmp_path, _HEADER, _SPAN)
    assert read_trace(path, Dialect.GUARDANA).trace.truncated is None


def test_the_footer_is_not_read_as_a_span(tmp_path: Path) -> None:
    path = _write(tmp_path, {**_HEADER, "terminated": True}, _SPAN, _FOOTER)
    assert [span.span_id for span in read_trace(path, Dialect.GUARDANA).trace.spans] == ["s1"]


def test_a_footer_counting_more_spans_than_the_file_carries_is_truncation(
    tmp_path: Path,
) -> None:
    """A footer that only said "I finished" would certify a file with its middle eaten.

    Log shipping drops lines. A completeness claim that cannot notice that is a new
    false green introduced by the mechanism meant to remove one.
    """
    path = _write(tmp_path, {**_HEADER, "terminated": True}, _SPAN, {**_FOOTER, "spans": 4})
    assert read_trace(path, Dialect.GUARDANA).trace.truncated is TraceTruncation.RECORDS_LOST


def test_a_footer_in_a_file_that_never_promised_one_is_refused(tmp_path: Path) -> None:
    """Half a promise is the shape of the defects this repository keeps finding."""
    path = _write(tmp_path, _HEADER, _SPAN, _FOOTER)
    with pytest.raises(TraceLoadError, match="terminated"):
        read_trace(path, Dialect.GUARDANA)


def test_a_record_after_the_footer_is_refused(tmp_path: Path) -> None:
    """Otherwise a file could be "complete" and still have spans nobody counted."""
    path = _write(tmp_path, {**_HEADER, "terminated": True}, _SPAN, _FOOTER, _SPAN)
    with pytest.raises(TraceLoadError, match="after"):
        read_trace(path, Dialect.GUARDANA)


def test_a_footer_declaring_another_schema_version_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path, {**_HEADER, "terminated": True}, _SPAN, {"guardana_trace_end": 2, "spans": 1}
    )
    with pytest.raises(TraceLoadError, match="guardana_trace_end"):
        read_trace(path, Dialect.GUARDANA)


def test_a_footer_with_no_span_count_is_refused(tmp_path: Path) -> None:
    """The count is what makes the footer a completeness claim rather than a full stop."""
    path = _write(tmp_path, {**_HEADER, "terminated": True}, _SPAN, {"guardana_trace_end": 3})
    with pytest.raises(TraceLoadError, match="spans"):
        read_trace(path, Dialect.GUARDANA)


def test_a_truncation_the_producer_declared_outranks_a_missing_footer(tmp_path: Path) -> None:
    """A producer that hit its own limit said so; that reason is more specific than ours."""
    path = _write(tmp_path, {**_HEADER, "terminated": True, "truncated": "producer_limit"}, _SPAN)
    assert read_trace(path, Dialect.GUARDANA).trace.truncated is TraceTruncation.PRODUCER_LIMIT


def test_an_unreadable_span_still_counts_toward_the_footers_total(tmp_path: Path) -> None:
    """Otherwise a record the reader rejected would read as a record that went missing.

    Both are bad and they are different: one is a span this build could not parse, and
    the reader already reports those. Conflating them would report a shipping problem
    the file does not have.
    """
    path = tmp_path / "trace.jsonl"
    oversized = {"span_id": "s2", "kind": "model_call", "name": "x" * (MAX_RECORD_BYTES + 1)}
    path.write_text(
        "\n".join(
            json.dumps(r)
            for r in ({**_HEADER, "terminated": True}, _SPAN, oversized, {**_FOOTER, "spans": 2})
        )
        + "\n",
        encoding="utf-8",
    )
    read = read_trace(path, Dialect.GUARDANA)
    assert read.trace.truncated is None
    assert len(read.unreadable) == 1


def test_the_published_schema_describes_both_halves_of_the_promise() -> None:
    """A third party writes against the schema, not against this reader."""
    schema = json.loads(
        (Path(__file__).resolve().parents[4] / "schemas" / "trace-v3.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)

    assert not list(validator.iter_errors({**_HEADER, "terminated": True}))
    assert not list(validator.iter_errors(_FOOTER))
    assert not list(validator.iter_errors({**_HEADER, "truncated": "records_lost"}))
    assert list(validator.iter_errors({"guardana_trace_end": 3}))
    assert list(validator.iter_errors({**_FOOTER, "extra": 1}))
