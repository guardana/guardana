"""Reading a `WWW-Authenticate` challenge costs work linear in the header, whatever its shape.

A probed server sets this header, so a crafted one must not be able to stall the parse. The
work is counted, never timed: every character the parser reads goes through a string that
records it.
"""

import random
import re
from typing import SupportsIndex

import pytest
from guardana.core.target._mcp_authorization import challenge_parameters

_GRAMMAR = re.compile(r'(?<!\w)(\w++)\s*+=\s*+"([^"]*+)"')
"""What the parser reads, as a pattern: a word not inside another, `=` and a quoted value."""

_ALPHABET = 'aZ_0é٣ß \t\u00a0\u2028="",;-.\x00'
"""Word characters, Unicode digits and spaces, and the punctuation the grammar turns on."""


class _Counted(str):
    """A string that counts each character read from it."""

    reads = 0

    def __getitem__(self, key: SupportsIndex | slice, /) -> str:
        item = super().__getitem__(key)
        self.reads += max(len(item), 1)
        return item

    def find(
        self,
        sub: str,
        start: SupportsIndex | None = None,
        end: SupportsIndex | None = None,
        /,
    ) -> int:
        found = super().find(sub, start, end)
        begin = 0 if start is None else int(start)
        self.reads += (len(self) if found < 0 else found + len(sub)) - begin
        return found


def _reads(text: str) -> int:
    counted = _Counted(text)
    challenge_parameters(counted)
    return counted.reads


def _expected(text: str) -> dict[str, str]:
    return {name.lower(): value for name, value in _GRAMMAR.findall(text)}


_SHAPES = {
    "parameters": lambda n: 'a="x", ' * n,
    "a-word-run-without-a-parameter": lambda n: 'Bearer realm="x", ' + "a" * n,
    "an-unclosed-value": lambda n: 'a="' + "b" * n,
    "equals-without-a-quote": lambda n: "a = " * n,
    "words-awaiting-a-quote": lambda n: "a=" * n + '"',
    "quotes-without-names": lambda n: '="' * n,
    "space-before-a-parameter": lambda n: " " * n + 'a="x"',
    "unicode-words": lambda n: "é٣_ " * n,
}


@pytest.mark.parametrize("shape", list(_SHAPES))
@pytest.mark.parametrize("size", [2_000, 8_000])
def test_parsing_a_challenge_reads_each_character_a_bounded_number_of_times(
    shape: str, size: int
) -> None:
    text = _SHAPES[shape](size)

    assert _reads(text) <= 4 * len(text) + 8


@pytest.mark.parametrize(
    "text",
    [
        None,
        "",
        'Bearer realm="x", resource_metadata="https://h/m"',
        'Bearer Resource_Metadata = "a", scope="s"',
        'a="1", a="2"',
        'xa="1" a = b="2"',
        'a="unclosed',
        'é="1", ٣="2", _="3"',
        'a\u00a0=\u2028"x"',
        'a="x"b="y"',
        'realm=x, error="invalid_token"',
    ],
)
def test_the_parser_reads_the_parameters_the_grammar_names(text: str | None) -> None:
    assert challenge_parameters(text) == ({} if text is None else _expected(text))


def test_the_parser_agrees_with_the_grammar_on_arbitrary_headers() -> None:
    generator = random.Random(345)  # noqa: S311 - seeded generated text, not a secret
    for _ in range(5_000):
        text = "".join(generator.choices(_ALPHABET, k=generator.randrange(40)))
        assert challenge_parameters(text) == _expected(text), repr(text)
