"""Bounded, encoding-explicit file reading shared by the artifact scanners.

A scanned repository is untrusted input: an unreadable, crafted-huge, or
non-regular file must degrade to "skipped", never abort or stall the whole scan.
"""

import io
import os
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Concatenate, ParamSpec, TypeVar

from guardana.core.formats import FormatError

_P = ParamSpec("_P")
_T = TypeVar("_T")

# The read bound. `ast.parse` handles far larger files than this comfortably, so
# the cap is generous — small enough to bound memory against a crafted file,
# large enough that real generated sources (`*_pb2.py`, vendored SDKs, notebook
# exports) are scanned rather than silently skipped. A file over the cap is read
# up to the bound and truncated, so a rule still sees the top of it.
MAX_SCAN_BYTES = 16 * 1024 * 1024

# A repository cloned without its LFS objects holds a small text file of this shape
# under the model's own name: the spec version, any extensions, the object id and size.
_LFS_POINTER = re.compile(
    rb"version https://git-lfs\.github\.com/spec/v1\n"
    rb"(?:ext-[0-9]+-[a-z0-9.-]+ sha256:[0-9a-f]{64}\n)*"
    rb"oid sha256:[0-9a-f]{64}\n"
    rb"size [0-9]+\n"
)
_LFS_POINTER_MAX_BYTES = 1024
"""Git LFS refuses a pointer file of this size or more."""
LFS_POINTER_REASON = "a Git LFS pointer, not the model; fetch the LFS object"
"""Why a file named as a model and holding a Git LFS pointer was not scanned."""


def is_lfs_pointer(content: bytes) -> bool:
    """Whether `content`, a whole file, is a Git LFS pointer and nothing else.

    A file that only opens like one may carry a model after it, as an HDF5 user block
    does, so the whole file has to be the pointer.
    """
    return len(content) < _LFS_POINTER_MAX_BYTES and _LFS_POINTER.fullmatch(content) is not None


def read_model(
    reader: Callable[Concatenate[Path, _P], _T], path: Path, *args: _P.args, **kwargs: _P.kwargs
) -> _T:
    """Run a `guardana.core.formats` reader, naming a Git LFS pointer for what it is.

    A pointer is text and never parses as a binary model format, so it is looked
    for only once the reader refused the file, and an honest model costs no extra read.
    """
    try:
        return reader(path, *args, **kwargs)
    except FormatError as exc:
        whole = read_bytes_bounded(path, _LFS_POINTER_MAX_BYTES)
        if whole is not None and not whole[1] and is_lfs_pointer(whole[0]):
            raise FormatError(LFS_POINTER_REASON) from exc
        raise


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


def open_regular(path: Path) -> io.FileIO:
    """Open a regular file for raw binary reading; raise OSError for anything else.

    A FIFO or device node blocks until a writer appears, and one swapped in after a check
    by name would block the open itself, so the file is opened without blocking and judged
    by its descriptor. The handle is unbuffered so each reader picks its own buffering.
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            return io.FileIO(fd, "r")
    except BaseException:
        os.close(fd)
        raise
    os.close(fd)
    raise OSError(f"{path.name} is not a regular file")


def read_text_prefix(
    path: Path, *, errors: str = "strict", limit: int = MAX_SCAN_BYTES
) -> tuple[str, bool] | None:
    """Read a text file for scanning; the flag reports a file longer than the bound.

    None means the file was not read at all: not a regular file, unreadable, or not
    UTF-8. Both outcomes leave text unexamined, so a rule that grades the file says
    so for either, rather than reporting what it did see as the whole file.

    Always decodes as UTF-8 — Python source is UTF-8 by default (PEP 3120), and
    locale-dependent decoding would make findings platform-dependent.
    """
    prefix = read_bytes_bounded(path, limit)
    if prefix is None:
        return None
    raw, truncated = prefix
    try:
        # A truncated read can split a multibyte character at the bound, so strict
        # decoding would raise and skip the whole file — drop the dangling bytes
        # instead. A file that fits keeps the caller's strict decode, so a genuinely
        # non-UTF-8 source is still correctly skipped.
        return raw.decode("utf-8", errors="ignore" if truncated else errors), truncated
    except UnicodeDecodeError:
        return None


def read_text_bounded(path: Path, *, errors: str = "strict") -> str | None:
    """Read a text file for scanning, dropping whatever lies past the bound unannounced.

    Prefer `read_text_prefix`: a caller of this one cannot tell a whole file from
    its first `MAX_SCAN_BYTES`, so it cannot report the rest as unexamined.
    """
    prefix = read_text_prefix(path, errors=errors)
    return None if prefix is None else prefix[0]
