"""Writing a file whole or not at all, for the files a command replaces in place."""

import errno
import os
import secrets
import stat
from pathlib import Path


def write_whole(destination: Path, document: bytes) -> None:
    """Put `document` at `destination` through a file beside it, so a failed write leaves no half.

    A file this process may not write is refused rather than replaced, and the new file gets
    the mode a plain write would leave: the existing file's, or the umask's for a new one. A
    link at `destination` is followed, so the file it names is the one replaced. Raises
    `OSError` with the file at `destination` as it was.
    """
    target = Path(os.path.realpath(destination))
    try:
        mode: int | None = stat.S_IMODE(target.stat().st_mode)
    except FileNotFoundError:
        mode = None
    if mode is not None and not os.access(target, os.W_OK):
        raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(destination))
    _rename_over(target, document, mode)


def replace_whole(destination: Path, document: bytes) -> None:
    """Put `document` at `destination` as `write_whole` does, replacing a link there.

    A link at `destination` is replaced by the new file and never followed, so the file it
    names is left as it was; so is any other name a hard link gives the replaced file.
    """
    try:
        found = destination.lstat()
    except FileNotFoundError:
        found = None
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
        staged.unlink(missing_ok=True)
        raise
