"""Compressed pickles, decompressed as joblib picks a decompressor: by the leading bytes.

`joblib.load` decompresses a file whatever it is named when its first bytes are a zlib,
gzip, bz2, lzma, xz or lz4 header, or its own legacy `ZF` header. The stdlib decodes all but
lz4. Every stream in the input is decoded back to back, as joblib's readers continue past the
end of one, up to a bound on the output and on the input read.
"""

import bz2
import io
import lzma
import os
import re
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import IO, Protocol

_LEGACY_MAGIC = b"ZF"
_LEGACY_LENGTH_DIGITS = len(f"{2**64:#x}")
_LEGACY_HEADER = len(_LEGACY_MAGIC) + _LEGACY_LENGTH_DIGITS
_STRONG_BZ2 = re.compile(rb"BZh[1-9]")
_LZMA_MAX_DICTIONARY = 64 * 1024 * 1024
"""The largest dictionary decoded, as large as the strongest xz preset writes."""
_LZMA_MEMORY_LIMIT = 2 * _LZMA_MAX_DICTIONARY
_BLOCK_BYTES = 8 * 1024
"""Input fed to a decoder per call, as joblib reads it, so output before damage is kept."""
MAX_STREAMS = 1024
"""Compressed streams decoded back to back in one file; one is what joblib writes."""
_CODEC_ERRORS = (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError)


class _Stream(Protocol):
    """One compressed stream being decoded, whatever its codec."""

    @property
    def eof(self) -> bool:
        """Whether the stream has ended."""

    @property
    def unused_data(self) -> bytes:
        """Input past the end of the stream."""

    @property
    def needs_input(self) -> bool:
        """Whether more output needs more input."""

    def feed(self, data: bytes, room: int) -> bytes:
        """Decode `data` after what was fed before, returning at most `room` bytes."""


class _ZlibStream:
    """A zlib or gzip stream, by its window bits."""

    def __init__(self, wbits: int) -> None:
        self._decoder = zlib.decompressobj(wbits)
        self._tail = b""

    @property
    def eof(self) -> bool:
        return self._decoder.eof

    @property
    def unused_data(self) -> bytes:
        return self._decoder.unused_data

    @property
    def needs_input(self) -> bool:
        return not self._tail

    def feed(self, data: bytes, room: int) -> bytes:
        out = self._decoder.decompress(self._tail + data, room)
        self._tail = self._decoder.unconsumed_tail
        return out


class _BufferedStream:
    """A bz2, lzma or xz stream, whose decoder keeps its own unread input."""

    def __init__(self, decoder: bz2.BZ2Decompressor | lzma.LZMADecompressor) -> None:
        self._decoder = decoder

    @property
    def eof(self) -> bool:
        return self._decoder.eof

    @property
    def unused_data(self) -> bytes:
        return self._decoder.unused_data

    @property
    def needs_input(self) -> bool:
        return self._decoder.needs_input

    def feed(self, data: bytes, room: int) -> bytes:
        return self._decoder.decompress(data, room)


def _lzma() -> _Stream:
    return _BufferedStream(lzma.LZMADecompressor(memlimit=_LZMA_MEMORY_LIMIT))


def _always(_head: bytes) -> bool:
    return True


def _never(_head: bytes) -> bool:
    return False


@dataclass(frozen=True, slots=True)
class _Codec:
    name: str
    magic: bytes
    start: Callable[[], _Stream] | None
    """None for a codec the stdlib cannot decode."""
    strong: Callable[[bytes], bool]
    """Whether a head this codec rejects is still a compressed file rather than other bytes."""

    refused: Callable[[bytes], bool]
    """Whether a head declares more than this scanner decodes, so it is not decoded at all."""


def _large_dictionary(head: bytes) -> bool:
    return int.from_bytes(head[1:5], "little") > _LZMA_MAX_DICTIONARY


_CODECS = (
    _Codec("zlib", b"\x78", lambda: _ZlibStream(zlib.MAX_WBITS), _never, _never),
    _Codec("gzip", b"\x1f\x8b", lambda: _ZlibStream(16 + zlib.MAX_WBITS), _always, _never),
    _Codec(
        "bz2",
        b"BZ",
        lambda: _BufferedStream(bz2.BZ2Decompressor()),
        lambda head: _STRONG_BZ2.match(head) is not None,
        _never,
    ),
    _Codec("lzma", b"\x5d\x00", _lzma, _never, _large_dictionary),
    _Codec("xz", b"\xfd7zXZ", _lzma, _always, _never),
    _Codec("lz4", b"\x04\x22\x4d\x18", None, _always, _never),
)
_LEGACY = _Codec("joblib-zlib", _LEGACY_MAGIC, lambda: _ZlibStream(zlib.MAX_WBITS), _never, _never)


@dataclass(frozen=True, slots=True)
class Inflated:
    """What decompressing one compressed file gave."""

    codec: str
    data: bytes | None
    """The decompressed bytes, or None when this scanner cannot decompress the file."""

    cut: bool = False
    """Whether bytes past `data` were left undecoded at a bound, so what follows is unknown."""

    shortfall: str | None = None
    """Why bytes past `data` were not decoded, a bound or damage; None when all were."""

    filled: bool = False
    """Whether `data` stopped at the output bound, the one shortfall a size bound names."""


def compressed(head: bytes) -> bool:
    """Whether joblib would decompress a file that starts with `head`."""
    return head.startswith(_LEGACY_MAGIC) or any(head.startswith(c.magic) for c in _CODECS)


def _body_start(head: bytes) -> tuple[_Codec, int] | None:
    if head.startswith(_LEGACY_MAGIC):
        try:
            int(head[len(_LEGACY_MAGIC) : _LEGACY_HEADER], 16)
        except ValueError:
            return None
        return _LEGACY, _LEGACY_HEADER + (head[_LEGACY_HEADER : _LEGACY_HEADER + 1] == b" ")
    codec = next((c for c in _CODECS if head.startswith(c.magic)), None)
    return None if codec is None else (codec, 0)


def _blocks(source: IO[bytes], start: int, input_limit: int, cut: list[bool]) -> Iterator[bytes]:
    """Read `source` from `start` up to `input_limit` bytes; `cut[0]` says more was left."""
    source.seek(start)
    left = input_limit - start
    while left > 0:
        block = source.read(min(_BLOCK_BYTES, left))
        if not block:
            return
        left -= len(block)
        yield block
    cut[0] = bool(source.read(1))


@dataclass(slots=True)
class _Drained:
    """What decoding streams back to back gave, and why it stopped."""

    out: bytearray
    raised: bool = False
    first_failed: bool = False
    """Whether the codec rejected the very first block it was fed."""

    streams: int = 1
    too_many_streams: bool = False


def _drain(start: Callable[[], _Stream], blocks: Iterator[bytes], limit: int) -> _Drained:
    """Decode streams back to back to `limit + 1` bytes, keeping every call's output."""
    drained = _Drained(bytearray())
    out = drained.out
    stream = start()
    data = b""
    calls = 0
    try:
        while len(out) <= limit:
            if stream.eof:
                data = stream.unused_data or next(blocks, b"")
                if not data:
                    break
                if drained.streams >= MAX_STREAMS:
                    drained.too_many_streams = True
                    break
                drained.streams += 1
                stream = start()
            elif stream.needs_input and not data:
                data = next(blocks, b"")
                if not data:
                    break
            calls += 1
            out += stream.feed(data, limit + 1 - len(out))
            data = b""
    except _CODEC_ERRORS:
        drained.raised = True
        drained.first_failed = calls == 1
    return drained


def inflate(source: IO[bytes], head: bytes, *, limit: int, input_limit: int) -> Inflated | None:
    """Decompress `source`, whose first bytes are `head`, as joblib would.

    None when joblib would not decompress it, or when a header that is weak evidence of
    compression is rejected with the first block fed to its codec: such bytes are read as
    they are. The output stops at `limit` bytes, the input at `input_limit` and the streams
    at `MAX_STREAMS`, each a `cut`; damage after some output keeps that output.
    """
    found = _body_start(head)
    if found is None:
        return None
    codec, body = found
    if codec.start is None or codec.refused(head):
        return Inflated(codec.name, None)
    input_cut = [False]
    drained = _drain(codec.start, _blocks(source, body, input_limit, input_cut), limit)
    data = bytes(drained.out[:limit])
    if drained.first_failed and not codec.strong(head):
        return None
    if drained.raised and not data:
        return Inflated(codec.name, None)
    shortfall = None
    if len(drained.out) > limit:
        shortfall = f"larger than {limit} bytes once decompressed"
    elif drained.too_many_streams:
        shortfall = f"made of more than {MAX_STREAMS} compressed streams"
    elif input_cut[0]:
        shortfall = f"longer than {input_limit} bytes compressed"
    elif drained.raised:
        shortfall = f"damaged after {len(data)} decompressed bytes"
    cut = shortfall is not None and not drained.raised
    filled = len(drained.out) > limit
    return Inflated(codec.name, data, cut=cut, shortfall=shortfall, filled=filled)


_TAR_CODECS = frozenset({"gzip", "bz2", "xz"})
"""The codecs `tar` decompresses an archive with by its first bytes (`-z`, `-j`, `-J`)."""
_DECODED_BYTES = 64 * 1024
"""Output taken from a decoder per call while a stream is read forward."""


class InflateError(Exception):
    """A compressed stream could not be decoded to the point asked for: damage or a bound."""


def _decoded(start: Callable[[], _Stream], source: IO[bytes]) -> Iterator[bytes]:
    """Decode `source` streams back to back, as `gzip -d` does, a bounded piece at a time.

    Bytes after the last stream that do not start another are ignored, as `gzip -d`
    ignores them; damage inside a stream, a cut one or more than `MAX_STREAMS` raises.
    """
    stream = start()
    streams = 1
    produced = False
    data = b""
    while True:
        if stream.eof:
            data = stream.unused_data or source.read(_BLOCK_BYTES)
            if not data:
                return
            if streams >= MAX_STREAMS:
                raise InflateError(f"made of more than {MAX_STREAMS} compressed streams")
            streams += 1
            stream = start()
            produced = False
        elif stream.needs_input and not data:
            data = source.read(_BLOCK_BYTES)
            if not data:
                raise InflateError("cut off before its compressed stream ends")
        try:
            out = stream.feed(data, _DECODED_BYTES)
        except _CODEC_ERRORS as error:
            if streams > 1 and not produced:
                return
            raise InflateError("damaged") from error
        data = b""
        if out:
            produced = True
            yield out


class InflatingReader(io.RawIOBase):
    """A gzip, bz2 or xz file read forward as its decompressed bytes, as `tar` reads it.

    Reading past `limit` decompressed bytes, damage, a cut stream or a seek backwards
    raises `InflateError`; only the bytes asked for are held in memory, so a seek forward
    decodes and drops what it passes.
    """

    def __init__(self, source: IO[bytes], codec: str, *, limit: int) -> None:
        super().__init__()
        found = next(c for c in _CODECS if c.name == codec)
        if found.start is None:
            raise InflateError(f"{codec} cannot be decompressed")
        self.codec = codec
        self.limit = limit
        self._position = 0
        self._pending = bytearray()
        source.seek(0)
        self._decoded = _decoded(found.start, source)

    def readable(self) -> bool:
        """Whether the stream can be read: always."""
        return True

    def read(self, size: int = -1, /) -> bytes:
        """Return up to `size` decompressed bytes, all that is left when `size` is negative."""
        while size < 0 or len(self._pending) < size:
            piece = next(self._decoded, None)
            if piece is None:
                break
            self._pending += piece
            if self._position + len(self._pending) > self.limit:
                raise InflateError(f"larger than {self.limit} bytes once decompressed")
        taken = len(self._pending) if size < 0 else min(size, len(self._pending))
        out = bytes(self._pending[:taken])
        del self._pending[:taken]
        self._position += taken
        return out

    def readinto(self, buffer: object, /) -> int:
        """Read into `buffer`, as a buffered reader wrapping this stream asks."""
        if not isinstance(buffer, memoryview | bytearray):
            raise TypeError(f"decompressed bytes are read into a byte buffer, not {type(buffer)}")
        with memoryview(buffer) as view, view.cast("B") as target:
            data = self.read(len(target))
            target[: len(data)] = data
        return len(data)

    def seek(self, offset: int, whence: int = os.SEEK_SET, /) -> int:
        """Move forward to `offset`, decoding what lies between; never backwards."""
        target = offset + (self._position if whence == os.SEEK_CUR else 0)
        if whence not in (os.SEEK_SET, os.SEEK_CUR) or target < self._position:
            raise InflateError("a compressed stream is read forward only")
        while self._position < target and self.read(min(target - self._position, _BLOCK_BYTES)):
            pass
        return self._position

    def tell(self) -> int:
        """Return how many decompressed bytes were read or passed."""
        return self._position


def tar_codec(head: bytes) -> str | None:
    """Name the codec `tar` would decompress a file starting with `head` with, or None."""
    codec = next((c for c in _CODECS if c.name in _TAR_CODECS and head.startswith(c.magic)), None)
    return codec.name if codec is not None and codec.strong(head) else None
