"""Bounded, encoding-explicit file reading shared by the artifact scanners.

A scanned repository is untrusted input: an unreadable, crafted-huge, or
non-regular file must degrade to "skipped", never abort or stall the whole scan.
"""

from pathlib import Path

# The read bound. `ast.parse` handles far larger files than this comfortably, so
# the cap is generous — small enough to bound memory against a crafted file,
# large enough that real generated sources (`*_pb2.py`, vendored SDKs, notebook
# exports) are scanned rather than silently skipped. A file over the cap is read
# up to the bound and truncated, so a rule still sees the top of it.
MAX_SCAN_BYTES = 16 * 1024 * 1024


def read_bytes_bounded(path: Path, limit: int = MAX_SCAN_BYTES) -> tuple[bytes, bool] | None:
    """Read at most `limit` bytes; None means skip, the flag reports what was left behind.

    Every binary scanner goes through here so they all inherit the same two
    guards. The `is_file()` check is the important one: a FIFO or device node
    opens happily and then blocks on `read` until a writer appears, so a crafted
    repository could otherwise stall a whole scan just by naming one `model.h5`.
    The bound is the other: a `/dev/zero` symlink reports `st_size == 0`, so the
    read is capped directly rather than sized from `stat()`.
    """
    try:
        if not path.is_file():  # skip FIFOs, devices, sockets, dangling symlinks
            return None
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)  # +1 byte reveals truncation
    except OSError:
        return None
    return raw[:limit], len(raw) > limit


def read_text_bounded(path: Path, *, errors: str = "strict") -> str | None:
    """Read a text file for scanning; None means skip (not a regular file, unreadable, undecodable).

    Always decodes as UTF-8 — Python source is UTF-8 by default (PEP 3120), and
    locale-dependent decoding would make findings platform-dependent.
    """
    prefix = read_bytes_bounded(path)
    if prefix is None:
        return None
    raw, truncated = prefix
    try:
        # A truncated read can split a multibyte character at the bound, so strict
        # decoding would raise and skip the whole file — drop the dangling bytes
        # instead. A file that fits keeps the caller's strict decode, so a genuinely
        # non-UTF-8 source is still correctly skipped.
        return raw.decode("utf-8", errors="ignore" if truncated else errors)
    except UnicodeDecodeError:
        return None
