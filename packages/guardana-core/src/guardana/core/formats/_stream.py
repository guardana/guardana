import io
import os
import stat
from pathlib import Path
from typing import BinaryIO

from guardana.core.formats.errors import UnreadableFileError


def open_regular(path: Path) -> BinaryIO:
    """Open a regular file for binary reading, refusing anything that could block.

    A FIFO, device node, or socket opens happily and then blocks on `read` until
    a writer shows up, so a crafted directory could stall an entire scan just by
    naming one `model.gguf`. One swapped in after a check by name would block the
    open itself, so the file is opened without blocking and judged by its
    descriptor. Anything that is not a regular file is refused as a `FormatError`.
    """
    try:
        fd = _open_without_blocking(path)
    except OSError as exc:
        raise UnreadableFileError(f"cannot read {path.name}: {exc}") from exc
    try:
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
    except OSError as exc:
        os.close(fd)
        raise UnreadableFileError(f"cannot read {path.name}: {exc}") from exc
    if not regular:
        os.close(fd)
        raise UnreadableFileError(f"cannot read {path.name}: not a regular file")
    return os.fdopen(fd, "rb")


def read_regular(path: Path, limit: int) -> bytes:
    """Return the regular file at `path`, up to `limit + 1` bytes, never waiting on a special file.

    The caller compares the length with `limit`, so a file over it is told apart from one
    that fits without the rest being read. Raises `OSError` as `open_regular_raw` does.
    """
    with io.BufferedReader(open_regular_raw(path)) as handle:
        return handle.read(limit + 1)


def open_regular_raw(path: Path) -> io.FileIO:
    """Open the regular file at `path` unbuffered for binary reading, never waiting on it.

    Raises `OSError` when the file cannot be opened, or when the descriptor it opened is
    not a regular file.
    """
    fd = _open_without_blocking(path)
    try:
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
    except OSError:
        os.close(fd)
        raise
    if not regular:
        os.close(fd)
        raise OSError("not a regular file")
    return io.FileIO(fd, "rb")


def _open_without_blocking(path: Path) -> int:
    """Open `path` for reading without waiting for a writer, as a FIFO's open otherwise does."""
    return os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
