"""Pickle opcodes read from a stream at least as leniently as CPython's unpicklers read them.

`pickletools.genops` reads the text arguments of protocol 0 more strictly than the unpickler
that loads the file: CPython reads INT and LONG in any base `int(s, 0)` accepts, stops a
number at its first NUL byte, and takes a GLOBAL name as UTF-8 without undoing escapes, so a
static reading built on `genops` stops where a load goes on. The opcode table and every
other argument reader are `pickletools`' own.
"""

import codecs
import pickletools
import warnings
from collections.abc import Callable, Iterator
from typing import IO

_NUL = b"\x00"
_QUOTES = (b"'", b'"')
_LONG_SUFFIX = b"L"
_OPCODES: dict[bytes, pickletools.OpcodeInfo] = {
    op.code.encode("latin-1"): op for op in pickletools.opcodes
}


def _line(stream: IO[bytes], *, final: bool = False) -> bytes:
    """Read a text argument; with `final`, also the last line of the stream, unterminated.

    The pure-Python unpickler joblib uses drops the last byte of such a line as if it were
    the newline, and imports the GLOBAL or INST names it gets.
    """
    data = stream.readline()
    if not data.endswith(b"\n") and not final:
        raise ValueError("no newline found when trying to read a text argument")
    return data[:-1]


def _spellings(text: bytes) -> Iterator[bytes]:
    """Yield the argument as written, then the part before its first NUL, where C stops."""
    yield text
    head = text.partition(_NUL)[0]
    if head != text:
        yield head


def _as_int(text: bytes) -> int:
    """Read `text` as an unpickler would: in base 10 (PUT, GET) or any base (INT, LONG)."""
    for spelling in _spellings(text):
        for base in (10, 0):
            try:
                return int(spelling, base)
            except ValueError:
                continue
    raise ValueError(f"no unpickler reads an integer from {text[:32]!r}")


def _read_decimalnl_short(stream: IO[bytes]) -> int:
    text = _line(stream)
    if text == b"00":
        return False
    if text == b"01":
        return True
    if text.startswith(_NUL):
        # strtol reads no digits before a NUL as 0; where the C library does not flag
        # that as an error, the unpickler accepts it.
        return 0
    return _as_int(text)


def _read_decimalnl_long(stream: IO[bytes]) -> int:
    text = _line(stream)
    candidates = (text[: -len(_LONG_SUFFIX)], text) if text.endswith(_LONG_SUFFIX) else (text,)
    for candidate in candidates:
        try:
            return _as_int(candidate)
        except ValueError:
            continue
    raise ValueError(f"no unpickler reads an integer from {text[:32]!r}")


def _read_floatnl(stream: IO[bytes]) -> float:
    text = _line(stream)
    for spelling in _spellings(text):
        try:
            return float(spelling)
        except ValueError:
            continue
    raise ValueError(f"no unpickler reads a float from {text[:32]!r}")


def _read_stringnl(stream: IO[bytes]) -> str:
    text = _line(stream)
    quote = text[:1]
    if quote not in _QUOTES or not text.endswith(quote):
        raise ValueError("STRING argument is not quoted")
    # Latin-1 decodes every byte; the unpickler's own decoding differs only for bytes no
    # allowlisted name contains.
    with warnings.catch_warnings():
        # The unpickler decodes an unknown escape such as `\q` as the two characters,
        # warning about it; under an error filter the warning would stop the read.
        warnings.simplefilter("ignore", DeprecationWarning)
        return codecs.escape_decode(text[1:-1])[0].decode("latin-1")


def _read_name(stream: IO[bytes]) -> str:
    return _line(stream, final=True).decode("utf-8", "backslashreplace")


def _read_name_pair(stream: IO[bytes]) -> str:
    module = _read_name(stream)
    return f"{module} {_read_name(stream)}"


_READERS: dict[str, Callable[[IO[bytes]], object]] = {
    "decimalnl_short": _read_decimalnl_short,
    "decimalnl_long": _read_decimalnl_long,
    "floatnl": _read_floatnl,
    "stringnl": _read_stringnl,
    "stringnl_noescape": _read_name,
    "stringnl_noescape_pair": _read_name_pair,
}


def read_opcodes(stream: IO[bytes]) -> Iterator[tuple[pickletools.OpcodeInfo, object]]:
    """Yield each opcode and its argument up to and including STOP, as `genops` does.

    Raises `ValueError` where the stream stops being one any unpickler reads further.
    """
    while True:
        code = stream.read(1)
        op = _OPCODES.get(code)
        if op is None:
            raise ValueError(f"opcode {code!r} unknown" if code else "pickle ended before STOP")
        arg = None if op.arg is None else _READERS.get(op.arg.name, op.arg.reader)(stream)
        yield op, arg
        if op.name == "STOP":
            return
