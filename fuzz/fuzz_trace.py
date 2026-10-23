"""Fuzz the trace reader with arbitrary bytes: it may refuse a file, never crash on one.

uv run --group fuzz python fuzz/fuzz_trace.py -max_total_time=120
"""

import json
from collections.abc import Iterable

from _harness import run_fuzzer, scratch_file
from guardana.core.trace import TraceLoadError, read_trace


def one_input(data: bytes) -> None:
    """Read `data` as a trace file; `TraceLoadError` is the reader's documented refusal."""
    with scratch_file("trace.jsonl", data) as path:
        try:
            read_trace(path)
        except TraceLoadError:
            return


def seeds() -> Iterable[bytes]:
    """Yield a native trace (header, one tool span, footer) and an empty OTLP export."""
    records = (
        {"guardana_trace": 3, "trace_id": "seed", "terminated": True},
        {
            "span_id": "s1",
            "kind": "tool",
            "name": "search",
            "started_at": "2026-01-01T00:00:00Z",
            "ended_at": "2026-01-01T00:00:01Z",
            "tool": {"name": "search"},
        },
        {"guardana_trace_end": True, "spans": 1},
    )
    yield "".join(json.dumps(record) + "\n" for record in records).encode()
    yield json.dumps({"resourceSpans": []}).encode() + b"\n"


if __name__ == "__main__":
    run_fuzzer(one_input, seeds)
