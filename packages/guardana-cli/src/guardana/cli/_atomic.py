"""Writing a file whole or not at all, for the files a command replaces in place."""

import contextlib
import errno
import os
import secrets
import stat
from pathlib import Path


def write_whole(destination: Path, document: bytes) -> None:
    """Put `document` at `destination` through a file beside it, so a failed write leaves no half.

    A file this process may not write, and a directory, are refused before a staging file
    exists rather than replaced, and the new file gets the mode a plain write would leave: the
    existing file's, or the umask's for a new one. A link at `destination` is followed, so the
    file it names is the one replaced. Raises `OSError` naming `destination`, with the file
    there as it was.
    """
    target = Path(os.path.realpath(destination))
    try:
        found = target.stat()
    except FileNotFoundError:
        found = None
    mode = None
    if found is not None:
        _refuse_a_directory(found, destination)
        mode = stat.S_IMODE(found.st_mode)
        if not os.access(target, os.W_OK):
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(destination))
    _rename_over(target, document, mode)


def replace_whole(destination: Path, document: bytes) -> None:
    """Put `document` at `destination` as `write_whole` does, replacing a link there.

    A link at `destination` is replaced by the new file and never followed, so the file it
    names is left as it was; so is any other name a hard link gives the replaced file. A
    directory there is refused before a staging file exists.
    """
    try:
        found = destination.lstat()
    except FileNotFoundError:
        found = None
    if found is not None:
        _refuse_a_directory(found, destination)
    mode = None
    if found is not None and stat.S_ISREG(found.st_mode):
        mode = stat.S_IMODE(found.st_mode)
        if not os.access(destination, os.W_OK):
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(destination))
    _rename_over(destination, document, mode)


def _rename_over(target: Path, document: bytes, mode: int | None) -> None:
    """Write `document` to a new file beside `target`, then rename it over `target`."""
    staged = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
    handle = staged.open("xb")
    try:
        with handle:
            handle.write(document)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            staged.chmod(mode)
        staged.replace(target)
    except BaseException:
        _discard(staged)
        raise


def _refuse_a_directory(found: os.stat_result, destination: Path) -> None:
    """Raise `IsADirectoryError` naming `destination` when `found` describes a directory."""
    if stat.S_ISDIR(found.st_mode):
        raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), str(destination))


def _discard(staged: Path) -> None:
    """Remove the staging file `staged`, never raising over the error that abandoned it."""
    try:
        staged.unlink(missing_ok=True)
    except OSError:
        # Windows refuses to remove a read-only file, and the mode copied from the destination
        # may have made the staging file one.
        with contextlib.suppress(OSError):
            staged.chmod(stat.S_IRUSR | stat.S_IWUSR)
            staged.unlink(missing_ok=True)
