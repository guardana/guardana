"""The structure an identifier a server hands out can show without anyone measuring entropy.

A few samples cannot support a randomness claim, and a number invented from them would be
worse than none, so these name structure only: an id handed out twice, an id short enough
to enumerate, or ids that are one counter wearing a prefix. Nothing here quotes an id.
"""

from collections.abc import Sequence
from itertools import pairwise
from os.path import commonprefix

SHORT_ID = 16
"""Below this many characters an id is short enough to enumerate rather than to guess.

A UUID is 36 characters and a 128-bit random token base64s to 22; this is a structural
observation, not a claim about entropy.
"""


def repeats(ids: Sequence[str]) -> bool:
    """Report whether any id appears more than once."""
    return len(set(ids)) < len(ids)


def shortest(ids: Sequence[str]) -> int:
    """Return the length of the shortest id; zero for no ids."""
    return min((len(value) for value in ids), default=0)


def counts_up(ids: Sequence[str], *, ordered: bool) -> bool:
    """Report whether the ids are one counter wearing a prefix.

    Compares the varying tail after the shared prefix, so `sess-1`, `sess-2` is caught
    while unrelated random ids are not. Needs at least two ids. `ordered` keeps the order
    the ids were issued in; without it the numeric tails are sorted first, because the
    order of a listing is the server's choice rather than the order of issue. Equal tails
    never count up: a repeated id is its own structure.
    """
    if len(ids) < 2:  # noqa: PLR2004 — one sample cannot show a sequence
        return False
    shared = len(commonprefix(list(ids)))  # noqa: RUF071 — ids, not paths: the character prefix is the point
    tails = [value[shared:] for value in ids]
    if not all(tail.isdigit() for tail in tails):
        return False
    numbers = [int(tail) for tail in tails]
    if not ordered:
        numbers.sort()
    return all(later > earlier for earlier, later in pairwise(numbers))


def id_structure(ids: Sequence[str], *, ordered: bool) -> str | None:
    """Name the structure the ids show, to follow "ids are …", or None when they show none.

    The phrase never quotes an id or any part of one, so it may stand in evidence about
    identifiers that must not.
    """
    if len(ids) < 2:  # noqa: PLR2004 — one sample cannot show a structure
        return None
    if repeats(ids):
        return "repeated: the same id was handed out more than once"
    if counts_up(ids, ordered=ordered):
        return "a counter: they differ only by an increasing number after a shared prefix"
    length = shortest(ids)
    if length < SHORT_ID:
        return f"as short as {length} characters, short enough to enumerate rather than guess"
    return None
