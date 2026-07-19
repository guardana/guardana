"""Bounded, encoding-explicit text reading shared by the artifact scanners.

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


def read_text_bounded(path: Path, *, errors: str = "strict") -> str | None:
    """Read a text file for scanning; None means skip (not a regular file, unreadable, undecodable).

    Reads at most `MAX_SCAN_BYTES` directly rather than trusting `stat()`, so a
    FIFO or a `/dev/zero` symlink (which report `st_size == 0`) can neither hang
    the scan nor exhaust memory. Always decodes as UTF-8 — Python source is UTF-8
    by default (PEP 3120), and locale-dependent decoding would make findings
    platform-dependent.
    """
    try:
        if not path.is_file():  # skip FIFOs, devices, sockets, dangling symlinks
            return None
        with path.open("rb") as handle:
            raw = handle.read(MAX_SCAN_BYTES + 1)  # +1 byte reveals truncation
        # A truncated read can split a multibyte character at the bound, so strict
        # decoding would raise and skip the whole file — drop the dangling bytes
        # instead. A file that fits keeps the caller's strict decode, so a genuinely
        # non-UTF-8 source is still correctly skipped.
        truncated = len(raw) > MAX_SCAN_BYTES
        return raw[:MAX_SCAN_BYTES].decode("utf-8", errors="ignore" if truncated else errors)
    except (OSError, UnicodeDecodeError):
        return None
