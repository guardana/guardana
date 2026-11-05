"""How a relative file path is spelled in what a run persists: with `/`, on every platform.

Its own module because both a target and the report package need it, and the report package
imports the target package.
"""

import re
from pathlib import PurePath

_DRIVE = re.compile(r"^[A-Za-z]:")


def is_legacy_windows_ref(ref: str) -> bool:
    r"""Whether `ref` is a relative file path a Windows build spelled with `\`.

    Such a ref has a `\` and no `/`, so it is neither an endpoint (`url#model`) nor a path
    already spelled the portable way. A drive-absolute (`C:\...`), rooted (`\dir`) or UNC
    (`\\server\share`) path is anchored and keeps its form. A trace's `source#id` qualifies:
    the part after `#` is the producer's id.
    """
    return "\\" in ref and "/" not in ref and not ref.startswith("\\") and not _DRIVE.match(ref)


def posix_ref(ref: str) -> str:
    """Spell a legacy Windows relative ref with `/`; return any other ref unchanged."""
    return ref.replace("\\", "/") if is_legacy_windows_ref(ref) else ref


def portable_ref(ref: str) -> str:
    r"""Spell a relative ref with `/` where `\` separates, as a migrated run spells it.

    Where `\` is an ordinary character in a file name the ref keeps every byte.
    """
    return posix_ref(ref) if len(PurePath("a\\b").parts) > 1 else ref
