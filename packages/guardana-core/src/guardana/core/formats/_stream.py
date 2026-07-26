from pathlib import Path
from typing import BinaryIO

from guardana.core.formats.errors import FormatError


def open_regular(path: Path) -> BinaryIO:
    """Open a regular file for binary reading, refusing anything that could block.

    A FIFO, device node, or socket opens happily and then blocks on `read` until
    a writer shows up, so a crafted directory could stall an entire scan just by
    naming one `model.gguf`. Anything that is not a regular file is refused as a
    `FormatError` — visible, and over in microseconds.
    """
    try:
        regular = path.is_file()
    except OSError as exc:
        raise FormatError(f"cannot read {path.name}: {exc}") from exc
    if not regular:
        raise FormatError(f"cannot read {path.name}: not a regular file")
    try:
        return path.open("rb")
    except OSError as exc:
        raise FormatError(f"cannot read {path.name}: {exc}") from exc
