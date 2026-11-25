"""Tell from a file's first bytes whether a loader that opens files by content reads it.

`pickle.load`, `torch.load`, `joblib.load` and `np.load` take a file of any name and go by its
bytes, and a person unpacks an archive or a compressed file whatever it is called. This reads
a head, decompresses at most a bounded part of it and runs nothing.
"""

import bz2
import lzma
import pickletools
import re
import tarfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

FIRST_READ_BYTES = tarfile.BLOCKSIZE
"""Enough for every signature below and for one tar header."""
HEAD_MAX_BYTES = 64 * 1024
"""How far a head that still reads as a pickle where it ends is read, and decompressed."""

_SIGNATURES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"\x93NUMPY",
    b"7z\xbc\xaf\x27\x1c",
    b"\x04\x22\x4d\x18",
    b"\x28\xb5\x2f\xfd",
)
"""A zip, an empty zip, an NPY array, and 7z, lz4 and zstd, which joblib cannot decompress."""
_ZSTD_SKIPPABLE = re.compile(rb"[\x50-\x5f]\x2a\x4d\x18")
_LZMA_DICTIONARY = slice(1, 5)
_LZMA_MAX_DICTIONARY = 64 * 1024 * 1024
"""A larger dictionary is refused before decoding, so the file is reported unread."""
_JOBLIB_ZLIB = b"ZF"
_JOBLIB_HEADER = len(_JOBLIB_ZLIB) + len(f"{2**64:#x}")
_TAR_MAGIC = b"ustar"
_TAR_MAGIC_AT = 257

_IMPORT_LINES = frozenset({"GLOBAL", "INST"})
"""Opcodes naming the callable they import on two lines of their own."""
_IMPORTS = frozenset({"STACK_GLOBAL", "EXT1", "EXT2", "EXT4"})
"""Opcodes that import a callable named elsewhere in the stream or in a registry."""
_DOTTED_NAME = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")
_OPCODES = {op.code.encode("latin-1")[0]: op for op in pickletools.opcodes}
_LENGTHS = {
    pickletools.TAKEN_FROM_ARGUMENT1: (1, False),
    pickletools.TAKEN_FROM_ARGUMENT4: (4, True),
    pickletools.TAKEN_FROM_ARGUMENT4U: (4, False),
    pickletools.TAKEN_FROM_ARGUMENT8U: (8, False),
}
"""Each length-prefixed argument's prefix width and whether the prefix is signed."""


class _Decoder(Protocol):
    """A zlib, bzip2 or LZMA decompressor."""

    @property
    def eof(self) -> bool:
        """Whether the stream's end has been reached."""
        raise NotImplementedError

    @property
    def unused_data(self) -> bytes:
        """The input found after the stream's end."""
        raise NotImplementedError

    def decompress(self, data: bytes, max_length: int = -1, /) -> bytes:
        """Decode `data`, returning at most `max_length` bytes."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class _Codec:
    name: str
    matches: Callable[[bytes], bool]
    decoder: Callable[[], _Decoder]
    strong: bool
    """Whether a head this codec fails to decode is still a compressed file, reported unread,
    rather than other bytes read as they are."""


_CODECS = (
    _Codec(
        "gzip",
        lambda head: head.startswith(b"\x1f\x8b"),
        lambda: zlib.decompressobj(16 + zlib.MAX_WBITS),
        strong=True,
    ),
    _Codec("xz", lambda head: head.startswith(b"\xfd7zXZ"), lzma.LZMADecompressor, strong=True),
    _Codec(
        "bzip2",
        lambda head: re.match(rb"BZh[1-9]", head) is not None,
        bz2.BZ2Decompressor,
        strong=True,
    ),
    _Codec(
        "lzma",
        lambda head: head.startswith(b"\x5d\x00"),
        lambda: lzma.LZMADecompressor(memlimit=2 * _LZMA_MAX_DICTIONARY),
        strong=False,
    ),
    _Codec("zlib", lambda head: head.startswith(b"\x78"), zlib.decompressobj, strong=False),
)
"""What joblib decompresses a file with, by its first bytes."""
_JOBLIB = _Codec("joblib-zlib", lambda head: True, zlib.decompressobj, strong=False)


class _StreamEndError(Exception):
    """The bytes stop being a pickle stream here, as they would for an unpickler."""


class _RanOutError(Exception):
    """An argument runs past the bytes read."""


class _UndecodableError(Exception):
    """A compressed file that cannot be decompressed here, which is reported unread."""


def loader_reads(head: bytes, *, cut: bool) -> bool | None:
    """Whether a loader opening a file by content reads one whose first bytes are `head`.

    True for an archive, an NPY array, a pickle stream that imports a callable, and a
    compressed file that holds a tar or such a pickle or cannot be decompressed; None when
    the bytes read as a pickle to their end and the file goes on (`cut`), so only more of it
    can tell.
    """
    if head.startswith(_SIGNATURES) or _ZSTD_SKIPPABLE.match(head) or _tar(head):
        return True
    try:
        decompressed = _decompressed(head, cut=cut)
    except _UndecodableError:
        return True
    data, data_cut = (head, cut) if decompressed is None else decompressed
    if decompressed is not None and _tar(data):
        return True
    try:
        return _imports(data)
    except _StreamEndError:
        return False
    except _RanOutError:
        return None if data_cut else False


def _decompressed(head: bytes, *, cut: bool) -> tuple[bytes, bool] | None:
    """Decompress `head` as joblib would, within the bound.

    Return the bytes and whether more may follow them, or None for a head that is not
    compressed; raise `_UndecodableError` for a compressed file that cannot be decompressed.
    """
    found = _codec(head)
    if found is None:
        return None
    codec, body = found
    if codec.name == "lzma" and int.from_bytes(head[_LZMA_DICTIONARY], "little") > (
        _LZMA_MAX_DICTIONARY
    ):
        raise _UndecodableError
    decoder = codec.decoder()
    try:
        data = decoder.decompress(head[body:], HEAD_MAX_BYTES)
    except (zlib.error, lzma.LZMAError, OSError, EOFError):
        if codec.strong:
            raise _UndecodableError from None
        return None
    more = cut or len(data) >= HEAD_MAX_BYTES or (decoder.eof and bool(decoder.unused_data))
    return data, more


def _codec(head: bytes) -> tuple[_Codec, int] | None:
    if head.startswith(_JOBLIB_ZLIB):
        try:
            int(head[len(_JOBLIB_ZLIB) : _JOBLIB_HEADER], 16)
        except ValueError:
            return None
        return _JOBLIB, _JOBLIB_HEADER + (head[_JOBLIB_HEADER : _JOBLIB_HEADER + 1] == b" ")
    codec = next((codec for codec in _CODECS if codec.matches(head)), None)
    return None if codec is None else (codec, 0)


def _tar(head: bytes) -> bool:
    """Whether `tarfile` reads the first block as a header, or the block carries the magic."""
    if head[_TAR_MAGIC_AT : _TAR_MAGIC_AT + len(_TAR_MAGIC)] == _TAR_MAGIC:
        return True
    try:
        tarfile.TarInfo.frombuf(head[: tarfile.BLOCKSIZE], tarfile.ENCODING, "surrogateescape")
    except tarfile.HeaderError:
        return False
    return True


def _imports(head: bytes) -> bool:
    """Walk `head` as pickle streams, one after another, until one imports a callable.

    Arguments are skipped by their length and never checked, so the walk goes at least as far
    as an unpickler does.
    """
    position = 0
    while position < len(head):
        op = _OPCODES.get(head[position])
        if op is None:
            raise _StreamEndError
        position += 1
        if op.name in _IMPORTS:
            return True
        if op.name in _IMPORT_LINES:
            module, name, position = _two_lines(head, position)
            if _names_a_callable(module, name):
                return True
        else:
            position = _skip(head, position, op.arg)
    raise _RanOutError


def _two_lines(head: bytes, position: int) -> tuple[bytes, bytes, int]:
    first = head.find(b"\n", position)
    second = head.find(b"\n", first + 1) if first >= 0 else -1
    if second < 0:
        raise _RanOutError
    return head[position:first], head[first + 1 : second], second + 1


def _names_a_callable(module: bytes, name: bytes) -> bool:
    try:
        dotted = f"{module.decode('utf-8')}.{name.decode('utf-8')}"
    except UnicodeDecodeError:
        return False
    return _DOTTED_NAME.fullmatch(dotted) is not None


def _skip(head: bytes, position: int, arg: pickletools.ArgumentDescriptor | None) -> int:
    """Return where the argument of the opcode before `position` ends."""
    if arg is None:
        return position
    if arg.n >= 0:
        end = position + arg.n
    elif arg.n == pickletools.UP_TO_NEWLINE:
        newline = head.find(b"\n", position)
        if newline < 0:
            raise _RanOutError
        end = newline + 1
    else:
        width, signed = _LENGTHS[arg.n]
        if position + width > len(head):
            raise _RanOutError
        length = int.from_bytes(head[position : position + width], "little", signed=signed)
        if length < 0:
            raise _StreamEndError
        end = position + width + length
    if end > len(head):
        raise _RanOutError
    return end
