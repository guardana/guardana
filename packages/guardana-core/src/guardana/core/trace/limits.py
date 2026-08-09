"""What bounds reading a trace, and why each bound is where it is.

A trace is a file somebody else wrote, so its size is not ours to assume. Every
bound here has the same shape: exceeding it marks the trace **truncated** rather
than quietly stopping, because a rule that found nothing in a trace we stopped
reading must not report a pass over the part it never saw.
"""

MAX_SPANS = 20_000
"""Spans read from one trace.

A production agent's day can be a million spans; a verification run is not a log
pipeline. Over the bound the trace is truncated, which every rule reads as a reason
it cannot conclude absence — not as a smaller, cleaner trace.
"""

MAX_RECORD_BYTES = 1024 * 1024
"""Bytes in one line. Over it the record is counted unreadable rather than parsed.

One span carrying a base64 video would otherwise decide the memory profile of the
whole read, and a producer that emits one is a producer whose other records are
worth reading.
"""

MAX_TRACE_BYTES = 64 * 1024 * 1024
"""Bytes read from one file, across all records.

The span ceiling alone does not bound this: twenty thousand large spans is a
different amount of memory from twenty thousand small ones.
"""
