"""The two questions every persisted schema has to answer, asked once.

`test_manifest_round_trip.py` established the shape in 0.19 for one document out of
twelve, and the shape is the point rather than the document: a field written and never
read passes every gate this repository has, because the writer's tests and the
reader's tests are each right about their own half. The 0.18 audit found
`calibration` that way; 0.19 found `deployment` the same way one release later.

Two questions, and the second is what makes the first mean anything:

- **does every field survive the trip** — walked off the dataclass rather than
  listed, because a hand-written list is what the next added field escapes;
- **can any key be deleted without the reader noticing** — because equality can
  pass on both sides being empty, and a key whose removal changes nothing is a key
  nothing reads.

The baseline for the second question is the document read back **whole**, never the
object that produced it. Against the original, an ignored key looks read: the two
differ, but they differ for the deleted key's neighbours. That mistake was made
here first, and it is why the `deployment` defect survived the test written to catch
it.
"""

import copy
from collections.abc import Callable, Iterator
from dataclasses import fields, is_dataclass
from typing import Any

Document = dict[str, Any] | list[Any]
"""One persisted document: an object, or the record list of a JSONL file.

Both shapes appear among the schemas this gate covers, and the walk below is the
same for either — a trace's records are a list of objects, and a key missing from
one of them fails exactly the way a key missing from a run manifest does.
"""


def leaves(value: object, path: str) -> Iterator[tuple[str, object]]:
    """Walk an object down to the values a reader ends up holding.

    Nested dataclasses and sequences are descended into, so a field dropped three
    levels down is named at the depth it went missing rather than reported as one
    unequal block a reader then has to diff by eye.
    """
    if is_dataclass(value) and not isinstance(value, type):
        for member in fields(value):
            yield from leaves(getattr(value, member.name), f"{path}.{member.name}")
    elif isinstance(value, tuple | list):
        for index, item in enumerate(value):
            yield from leaves(item, f"{path}[{index}]")
    else:
        yield path, value


def lost_fields(
    written: object, read: object, root: str, exempt: frozenset[str] = frozenset()
) -> list[str]:
    """Name every leaf the writer recorded and the reader did not get back."""
    before = dict(leaves(written, root))
    after = dict(leaves(read, root))
    return [
        f"{path}: wrote {value!r}, read back {after.get(path, '<nothing at this path>')!r}"
        for path, value in before.items()
        if path not in exempt and after.get(path, object()) != value
    ]


def key_paths(node: object, prefix: tuple[str | int, ...] = ()) -> Iterator[tuple[str | int, ...]]:
    """Every key path in a JSON-shaped document, parents before children."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield (*prefix, key)
            yield from key_paths(value, (*prefix, key))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from key_paths(item, (*prefix, index))


def without(document: Document, path: tuple[str | int, ...]) -> Document:
    """A deep copy of `document` with exactly one key removed."""
    clone = copy.deepcopy(document)
    node: Any = clone
    for step in path[:-1]:
        node = node[step]
    del node[path[-1]]
    return clone


def render(path: tuple[str | int, ...], root: str) -> str:
    """Render a key path the way a reader would point at it in the file."""
    out = root
    for step in path:
        out += f"[{step}]" if isinstance(step, int) else f".{step}"
    return out


def undemonstrative_fields(
    value: object, root: str, exempt: frozenset[str] = frozenset()
) -> list[str]:
    """Name the fields of a fixture that are empty, and so can demonstrate nothing.

    The guard that makes a round-trip assertion mean something. A field left at its
    default reads back as its default whether or not anything reads it, so a fixture
    that forgets to populate a newly added field turns a green gate into a field
    nobody checked — the exact failure the gate was built for, one level up.

    `exempt` takes the same paths the round trip exempts, so one list of fields that
    are honestly outside the document excuses them in both places rather than two
    lists drifting apart.
    """
    if not is_dataclass(value) or isinstance(value, type):
        raise TypeError(f"{value!r} is not a dataclass instance")
    return [
        f"{root}.{member.name}"
        for member in fields(value)
        if f"{root}.{member.name}" not in exempt and not getattr(value, member.name)
    ]


def unread_keys(
    document: Document,
    read: Callable[[Document], object],
    *,
    root: str,
    refusal: type[Exception] | tuple[type[Exception], ...],
    exempt: frozenset[str] = frozenset(),
) -> list[str]:
    """Delete each key in turn and name the ones the reader never noticed.

    A reader that reads the key either refuses the document — many fields are
    required — or comes back with something different from what the whole document
    gave. Coming back *identical* means the value on disk changed nothing, which is
    true both of a field nobody reads and of a field whose fixture value happens to
    equal the reader's default. Both make a round-trip assertion meaningless, so
    both are reported rather than assumed away.
    """
    intact = read(document)
    ignored: list[str] = []
    for path in key_paths(document):
        rendered = render(path, root)
        if rendered in exempt:
            continue
        try:
            restored = read(without(document, path))
        except refusal:
            continue
        if restored == intact:
            ignored.append(rendered)
    return ignored
