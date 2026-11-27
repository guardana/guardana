"""Tell, with bounded reads, whether a plain archive holds a member a caller names a model.

A person extracts a `.zip` or a tar and loads a member by its name, so such an archive is read
for its member names only: a zip's central directory, a tar's headers, through a decompressor
for a compressed tar. The walk stops at the first file member named a model. An archive that
declares more members than may be listed, outgrows the decompression bound, or cannot be
walked to its end may hold one, so it counts as holding one.
"""

import bz2
import lzma
import os
import re
import struct
import tarfile
import zlib
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Protocol

from guardana.core.formats._stream import open_regular_raw
from guardana.core.formats.content import FIRST_READ_BYTES, starts_as_tar

MAX_ENTRIES = 100_000
"""Members one zip may declare before it counts as holding a model unread."""
MAX_DIRECTORY_BYTES = MAX_ENTRIES * 256
"""A zip's central directory, read whole: room for each entry's record, name and extras."""
MAX_TAR_BLOCKS = 1_000_000
"""Header and sparse extension blocks one tar walk reads before the tar counts as unlisted."""
MAX_EXTENDED_HEADER_BYTES = 1024 * 1024
"""One PAX record set or GNU long name: room for hundreds of paths."""
MAX_STREAMS = 1024
"""Compressed streams written back to back one compressed tar may be read across."""
MIN_INFLATE_BYTES = 64 * 1024 * 1024
INFLATE_RATIO = 32
"""A compressed tar is decompressed up to this many times its size, or the floor above."""
LZMA_MEMORY_LIMIT = 128 * 1024 * 1024

_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
_ZIP_NAME = ".zip"
_END = struct.Struct("<4s4H2LH")
_END_SIGNATURE = b"PK\x05\x06"
_LOCATOR = struct.Struct("<4sLQL")
_LOCATOR_SIGNATURE = b"PK\x06\x07"
_END64 = struct.Struct("<4sQ2H2L4Q")
_END64_SIGNATURE = b"PK\x06\x06"
_CENTRAL = struct.Struct("<4s4xH18x3H12x")
_CENTRAL_SIGNATURE = b"PK\x01\x02"
_EXTRA = struct.Struct("<HH")
_UNICODE_PATH = 0x7075
_UNICODE_PATH_FIELDS = struct.Struct("<BL")
_UNICODE_PATH_HEADER = _UNICODE_PATH_FIELDS.size
_UTF8_FLAG = 0x800
_MAX_COMMENT = 0xFFFF
_UNSET16 = 0xFFFF
_UNSET32 = 0xFFFFFFFF
_BLOCK = tarfile.BLOCKSIZE
_CHUNK = 64 * 1024
_NOT_FILE_DATA = frozenset({tarfile.DIRTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE})
"""Member types a loader reads no bytes of; a link counts, since a loader follows it."""
_PAX = frozenset({tarfile.XHDTYPE, tarfile.SOLARIS_XHDTYPE})
_EXTENDED_TYPES = _PAX | {tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, tarfile.XGLTYPE}
_PAX_PATH = b"path"
_PAX_SIZE = b"size"
_PAX_SPARSE_NAME = b"GNU.sparse.name"
_GLOBAL_LAYOUT = re.compile(rb"(?:path|linkpath|size)\Z|GNU\.sparse\.")
"""Global PAX records that name, size or lay out every member after them, which tar readers
apply differently, so a tar carrying one is not listed."""
_BASE256 = (0o200, 0o377)
_UNSIGNED = struct.Struct("148B8x356B")
_SIGNED = struct.Struct("148b8x356b")
_SPARSE_EXTENDED_AT = 482
_SPARSE_EXTENSION_EXTENDED_AT = 504
_POSIX_PREFIX = slice(345, 500)


class ArchiveKind(StrEnum):
    """What an archive turned out to be by its bytes."""

    ZIP = "zip"
    TAR = "tar"


class _UnlistableError(Exception):
    """The archive cannot be listed to its end within the bounds."""


class _Decoder(Protocol):
    """A streaming decompressor with the interface of `bz2.BZ2Decompressor`."""

    @property
    def eof(self) -> bool:
        """Whether the stream's end has been reached."""
        raise NotImplementedError

    @property
    def needs_input(self) -> bool:
        """Whether more input is needed before more output can be returned."""
        raise NotImplementedError

    @property
    def unused_data(self) -> bytes:
        """The input found after the stream's end."""
        raise NotImplementedError

    def decompress(self, data: bytes, max_length: int = -1, /) -> bytes:
        """Decode `data`, returning at most `max_length` bytes."""
        raise NotImplementedError


class _Blocks(Protocol):
    """A tar's bytes, read forward."""

    def read(self, size: int) -> bytes | None:
        """Return `size` bytes, empty bytes at the end, or None for a short read."""
        raise NotImplementedError

    def skip(self, size: int) -> None:
        """Pass over `size` bytes; raise `_UnlistableError` when they are not there."""
        raise NotImplementedError


def holding_kind(path: Path, named: Callable[[str], bool]) -> ArchiveKind | None:
    """Return what the archive at `path` is when it holds a member `named` says is a model.

    None for a file that is no zip, tar or compressed tar, for one listed to its end with no
    such member, and for one that cannot be opened.
    """
    try:
        with open_regular_raw(path) as raw:
            size = os.fstat(raw.fileno()).st_size
            return _holding_kind(raw, size, path.name.lower().endswith(_ZIP_NAME), named)
    except OSError:
        return None


def _holding_kind(
    raw: BinaryIO, size: int, zip_named: bool, named: Callable[[str], bool]
) -> ArchiveKind | None:
    head = raw.read(FIRST_READ_BYTES)
    if head.startswith(_ZIP_MAGIC):
        return ArchiveKind.ZIP if _zip_holds(raw, size, named) else None
    codec = next((entry for entry in _CODECS if entry[0].match(head)), None)
    if codec is not None:
        raw.seek(0)
        limit = max(MIN_INFLATE_BYTES, INFLATE_RATIO * size)
        stream = _Inflating(raw, codec[0], codec[1], limit)
        return ArchiveKind.TAR if _compressed_tar_holds(stream, named) else None
    if starts_as_tar(head):
        raw.seek(0)
        return ArchiveKind.TAR if _tar_holds(_Seeking(raw, size), named) else None
    if zip_named and _zip_found(raw, size):
        return ArchiveKind.ZIP if _zip_holds(raw, size, named) else None
    return None


def _zip_found(raw: BinaryIO, size: int) -> bool:
    """Whether a zip's end record is where a zip reader looks for it, after data of any kind."""
    try:
        _zip_end(raw, size)
    except (_UnlistableError, struct.error):
        return False
    return True


def _zip_holds(raw: BinaryIO, size: int, named: Callable[[str], bool]) -> bool:
    try:
        entries, directory_size, end = _zip_end(raw, size)
        if entries > MAX_ENTRIES or directory_size > min(MAX_DIRECTORY_BYTES, end):
            return True
        raw.seek(end - directory_size)
        directory = raw.read(directory_size)
        return any(named(name) for name in _central_names(directory))
    except (_UnlistableError, struct.error):
        return True


def _zip_end(raw: BinaryIO, size: int) -> tuple[int, int, int]:
    """Return the entries and directory size a zip declares, and where its end records start."""
    tail_size = min(size, _END.size + _MAX_COMMENT)
    raw.seek(size - tail_size)
    tail = raw.read(tail_size)
    found = tail.rfind(_END_SIGNATURE)
    if found < 0 or found + _END.size > len(tail):
        raise _UnlistableError
    end = size - tail_size + found
    record = _END.unpack_from(tail, found)
    if _UNSET16 not in (record[3], record[4]) and _UNSET32 not in (record[5], record[6]):
        return max(record[3], record[4]), record[5], end
    locator_at = end - _LOCATOR.size
    end64 = locator_at - _END64.size
    if end64 < 0:
        raise _UnlistableError
    raw.seek(locator_at)
    if _LOCATOR.unpack(raw.read(_LOCATOR.size))[0] != _LOCATOR_SIGNATURE:
        raise _UnlistableError
    raw.seek(end64)
    record64 = _END64.unpack(raw.read(_END64.size))
    if record64[0] != _END64_SIGNATURE:
        raise _UnlistableError
    return max(record64[6], record64[7]), record64[8], end64


def _central_names(directory: bytes) -> list[str]:
    """Return every name a zip reader may give each member of a central directory.

    Walked by its size, as `zipfile` walks it: the name as its flag says to decode it, cut at
    a NUL as `zipfile` cuts it, and an Info-ZIP Unicode Path, which `unzip` shows instead.
    """
    names: list[str] = []
    position = 0
    for _ in range(MAX_ENTRIES):
        if position >= len(directory):
            return names
        if directory[position : position + 4] != _CENTRAL_SIGNATURE:
            raise _UnlistableError
        _, flags, name_size, extra_size, comment_size = _CENTRAL.unpack_from(directory, position)
        start = position + _CENTRAL.size
        raw_name = directory[start : start + name_size]
        extra = directory[start + name_size : start + name_size + extra_size]
        if len(raw_name) != name_size or len(extra) != extra_size:
            raise _UnlistableError
        name = raw_name.decode("utf-8" if flags & _UTF8_FLAG else "cp437", "replace")
        names.extend((name, name.split("\x00", 1)[0], *_unicode_paths(extra, raw_name)))
        position = start + name_size + extra_size + comment_size
    raise _UnlistableError


def _unicode_paths(extra: bytes, raw_name: bytes) -> list[str]:
    """Return the Info-ZIP Unicode Paths a zip reader shows for a member.

    One that is not UTF-8 is skipped, unless it claims to describe this very name, which
    newer `zipfile` releases refuse: the zip then cannot be listed.
    """
    paths: list[str] = []
    position = 0
    while position + _EXTRA.size <= len(extra):
        field, size = _EXTRA.unpack_from(extra, position)
        body = extra[position + _EXTRA.size : position + _EXTRA.size + size]
        position += _EXTRA.size + size
        if field != _UNICODE_PATH:
            continue
        if len(body) < _UNICODE_PATH_HEADER:
            raise _UnlistableError
        version, crc = _UNICODE_PATH_FIELDS.unpack_from(body)
        try:
            paths.append(body[_UNICODE_PATH_HEADER:].decode("utf-8"))
        except UnicodeDecodeError:
            if version == 1 and crc == zlib.crc32(raw_name):
                raise _UnlistableError from None
    return paths


class _Seeking:
    """A plain tar on disk, whose member data is skipped by seeking."""

    def __init__(self, raw: BinaryIO, size: int) -> None:
        self._raw = raw
        self._size = size

    def read(self, size: int) -> bytes | None:
        data = self._raw.read(size)
        if not data:
            return b""
        return data if len(data) == size else None

    def skip(self, size: int) -> None:
        if size > self._size - self._raw.tell():
            raise _UnlistableError
        self._raw.seek(size, os.SEEK_CUR)


class _Zlib:
    """A gzip decompressor with the interface of `bz2.BZ2Decompressor`."""

    def __init__(self) -> None:
        self._decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)

    @property
    def eof(self) -> bool:
        return self._decoder.eof

    @property
    def needs_input(self) -> bool:
        return not self._decoder.unconsumed_tail

    @property
    def unused_data(self) -> bytes:
        return self._decoder.unused_data

    def decompress(self, data: bytes, max_length: int = -1, /) -> bytes:
        return self._decoder.decompress(self._decoder.unconsumed_tail + data, max(max_length, 0))


def _xz() -> _Decoder:
    return lzma.LZMADecompressor(memlimit=LZMA_MEMORY_LIMIT)


_CODECS: tuple[tuple[re.Pattern[bytes], Callable[[], _Decoder]], ...] = (
    (re.compile(rb"\x1f\x8b"), _Zlib),
    (re.compile(rb"BZh[1-9]"), bz2.BZ2Decompressor),
    (re.compile(rb"\xfd7zXZ"), _xz),
)
"""The codecs `tar` decompresses an archive with by its first bytes (`-z`, `-j`, `-J`)."""


class _Inflating:
    """A compressed tar, decompressed a piece at a time up to `limit` bytes in all.

    Streams written back to back are read one after another, as `tar` reads them; bytes
    after the last that do not start another are ignored, as `tar` ignores them.
    """

    def __init__(
        self,
        raw: BinaryIO,
        magic: re.Pattern[bytes],
        decoder: Callable[[], _Decoder],
        limit: int,
    ) -> None:
        self._raw = raw
        self._magic = magic
        self._new = decoder
        self._decoder = decoder()
        self._pending = b""
        self._left = limit
        self._done = False
        self._streams = 0

    def read(self, size: int) -> bytes | None:
        out = bytearray()
        while len(out) < size:
            piece = self._next(size - len(out))
            if not piece:
                break
            out += piece
        if not out:
            return b""
        return bytes(out) if len(out) == size else None

    def skip(self, size: int) -> None:
        while size:
            piece = self._next(min(size, _CHUNK))
            if not piece:
                raise _UnlistableError
            size -= len(piece)

    def _next(self, wanted: int) -> bytes:
        while not self._done:
            decoder = self._decoder
            data = b""
            if decoder.needs_input:
                data, self._pending = self._pending or self._raw.read(_CHUNK), b""
            piece = decoder.decompress(data, min(wanted, _CHUNK))
            if decoder.eof:
                self._following(decoder.unused_data)
            elif not data and not piece:
                raise _UnlistableError
            if piece:
                self._left -= len(piece)
                if self._left < 0:
                    raise _UnlistableError
                return piece
        return b""

    def _following(self, unused: bytes) -> None:
        """Start on the stream after the one that ended, or end where none follows."""
        rest = unused if len(unused) >= _CHUNK else unused + self._raw.read(_CHUNK)
        if not self._magic.match(rest):
            self._done = True
            return
        self._streams += 1
        if self._streams >= MAX_STREAMS:
            raise _UnlistableError
        self._pending = rest
        self._decoder = self._new()


def _compressed_tar_holds(stream: _Inflating, named: Callable[[str], bool]) -> bool:
    try:
        first = stream.read(_BLOCK)
    except (_UnlistableError, zlib.error, lzma.LZMAError, OSError, EOFError):
        return True
    if first is None or not starts_as_tar(first):
        return False
    return _tar_holds(stream, named, first=first)


def _tar_holds(
    stream: _Blocks, named: Callable[[str], bool], *, first: bytes | None = None
) -> bool:
    try:
        return _walk_tar(stream, named, first)
    except (
        _UnlistableError,
        tarfile.TarError,
        zlib.error,
        lzma.LZMAError,
        OSError,
        EOFError,
        ValueError,
    ):
        return True


class _Extended:
    """What the extended headers in front of one member say of it."""

    def __init__(self) -> None:
        self.names: list[str] = []
        self.size: int | None = None
        self.records = 0

    def read(self, kind: bytes, payload: bytes) -> None:
        """Take what an extended header of `kind` carrying `payload` says of the next member."""
        if kind == tarfile.GNUTYPE_LONGNAME:
            self.names.append(_text(payload.split(b"\x00", 1)[0]))
        elif kind == tarfile.XGLTYPE:
            if any(_GLOBAL_LAYOUT.match(key) for key in _pax_records(payload)):
                raise _UnlistableError
        elif kind in _PAX:
            self.records += 1
            records = _pax_records(payload)
            self.names.extend(
                records[key].decode("utf-8", "surrogateescape")
                for key in (_PAX_PATH, _PAX_SPARSE_NAME)
                if key in records
            )
            if _PAX_SIZE in records:
                self.size = _pax_size(records[_PAX_SIZE])

    def name(self, header_name: str) -> str:
        """Return the member's name as `tarfile` gives it: the one extended name, or the header's.

        Tar readers choose differently between several names or PAX headers for one member,
        so such a member cannot be listed.
        """
        if len(self.names) > 1 or self.records > 1:
            raise _UnlistableError
        return self.names[0] if self.names else header_name


def _walk_tar(stream: _Blocks, named: Callable[[str], bool], first: bytes | None) -> bool:
    """Walk a tar's headers as `tarfile` does until a file member is named a model.

    False at the archive's end.
    """
    extended = _Extended()
    pending = first
    for _ in range(MAX_TAR_BLOCKS):
        header = pending if pending is not None else stream.read(_BLOCK)
        pending = None
        if header is None:
            raise _UnlistableError
        if not header.strip(b"\x00"):
            return False
        kind, stored = _header_fields(header)
        if kind in _EXTENDED_TYPES:
            extended.read(kind, _extended(stream, stored))
            continue
        if kind == tarfile.GNUTYPE_SPARSE:
            _skip_sparse_extensions(stream, header)
        header_name = _header_name(header, kind)
        kind = tarfile.DIRTYPE if kind == tarfile.AREGTYPE and header_name.endswith("/") else kind
        if kind not in _NOT_FILE_DATA and named(extended.name(header_name)):
            return True
        _skip_data(stream, kind, stored if extended.size is None else extended.size)
        extended = _Extended()
    raise _UnlistableError


def _header_fields(header: bytes) -> tuple[bytes, int]:
    """Return a checked header's type and the size it gives its data."""
    if _number(header[148:156]) not in _checksums(header):
        raise _UnlistableError
    stored = _number(header[124:136])
    if stored < 0:
        raise _UnlistableError
    return header[156:157], stored


def _number(field: bytes) -> int:
    """Read a numeric header field as `tarfile` does: base-256, or octal text up to a NUL."""
    if field[0] in _BASE256:
        value = int.from_bytes(field[1:], "big")
        return value if field[0] == _BASE256[0] else value - 256 ** (len(field) - 1)
    text = field.split(b"\x00", 1)[0].strip()
    try:
        return int(text or b"0", 8)
    except ValueError:
        raise _UnlistableError from None


def _checksums(header: bytes) -> tuple[int, int]:
    """Return the unsigned and the signed sum of a header, its checksum field read as blanks."""
    return 256 + sum(_UNSIGNED.unpack_from(header)), 256 + sum(_SIGNED.unpack_from(header))


def _skip_data(stream: _Blocks, kind: bytes, size: int) -> None:
    """Pass a member's data where `tarfile` reads some for its type; a size elsewhere is refused."""
    if kind in tarfile.REGULAR_TYPES or kind not in tarfile.SUPPORTED_TYPES:
        stream.skip(_padded(size))
    elif size:
        raise _UnlistableError


def _header_name(header: bytes, kind: bytes) -> str:
    name = header[:100].split(b"\x00", 1)[0]
    prefix = header[_POSIX_PREFIX].split(b"\x00", 1)[0]
    if prefix and kind not in tarfile.GNU_TYPES:
        name = prefix + b"/" + name
    return _text(name)


def _text(name: bytes) -> str:
    return name.decode(tarfile.ENCODING, "surrogateescape")


def _padded(size: int) -> int:
    return -(-size // _BLOCK) * _BLOCK


def _extended(stream: _Blocks, size: int) -> bytes:
    """Read the data of an extended header, the member's name or records, within the bound."""
    if size > MAX_EXTENDED_HEADER_BYTES:
        raise _UnlistableError
    padded = _padded(size)
    payload = stream.read(padded) if padded else b""
    if payload is None or len(payload) != padded:
        raise _UnlistableError
    return payload[:size]


def _skip_sparse_extensions(stream: _Blocks, header: bytes) -> None:
    """Pass the blocks an old GNU sparse member chains after its header, as `tarfile` does."""
    extended = header[_SPARSE_EXTENDED_AT]
    for _ in range(MAX_TAR_BLOCKS):
        if not extended:
            return
        block = stream.read(_BLOCK)
        if not block:
            raise _UnlistableError
        extended = block[_SPARSE_EXTENSION_EXTENDED_AT]
    raise _UnlistableError


def _pax_records(payload: bytes) -> dict[bytes, bytes]:
    """Return a PAX header's records, the last of each keyword; raise for a malformed one."""
    records: dict[bytes, bytes] = {}
    position = 0
    while position < len(payload) and payload[position]:
        space = payload.find(b" ", position)
        if space <= position or not payload[position:space].isdigit():
            raise _UnlistableError
        end = position + int(payload[position:space])
        if end <= space or end > len(payload) or payload[end - 1 : end] != b"\n":
            raise _UnlistableError
        key, equals, value = payload[space + 1 : end - 1].partition(b"=")
        if not equals:
            raise _UnlistableError
        records[key] = value
        position = end
    return records


def _pax_size(value: bytes) -> int:
    if not value.isdigit():
        raise _UnlistableError
    return int(value)
