"""Split a `Finding.target_ref` into its path and (optional) line.

A pure helper with no report dependencies, so both `finding` (for the fingerprint)
and `location` (for relativization) can use it without an import cycle.
"""

import re

_FILE_REF = re.compile(r"^(?P<path>.*):(?P<line>\d+)$")


def split_ref(ref: str) -> tuple[str, int | None]:
    """Split `"path:line"` into `(path, line)`; a ref with no trailing `:line` keeps `None`."""
    match = _FILE_REF.match(ref)
    if match:
        return match.group("path"), int(match.group("line"))
    return ref, None
