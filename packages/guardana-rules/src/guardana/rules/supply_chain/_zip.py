"""A zip's end records, central directory and local headers, read with bounded reads.

`zipfile` reads the whole central directory into memory, and builds an entry for every
record in it, before a single member can be read; so what the end records declare is read
first, from the file's tail, and an archive that declares too much is refused.

`zipfile` also finds the directory by where the end record sits and shifts every member
offset by any difference from the offset the record declares, while the miniz reader inside
`torch.load` uses the declared offsets as they are. When the two differ, the readers see
different members under the same names, so a caller compares `declared_directory_start`
with `ZipFile.start_dir`.

Every function reads the open file it is given, so a caller that lists the archive from the
same handle lists what was checked.
"""

import lzma
import os
import struct
import zipfile
import zlib
from dataclasses import dataclass
from typing import IO

ARCHIVE_MAX_ENTRIES = 100_000
"""Entries one archive may list, read or not.

`zipfile` and `tarfile` parse every entry before the first member is read, so an archive
that declares more is refused before it is opened.
"""
ZIP_DIRECTORY_MAX_BYTES = ARCHIVE_MAX_ENTRIES * 256
"""The central directory `zipfile` reads whole: 256 bytes for each entry an archive may list,
room for the 46-byte fixed record, a long path and its extra fields."""

ZIP_ERRORS = (
    zipfile.BadZipFile,
    OSError,
    EOFError,
    ValueError,
    RuntimeError,
    NotImplementedError,
    OverflowError,
    struct.error,
    zlib.error,
    lzma.LZMAError,
)
"""What `zipfile` raises for a crafted archive or member: a damaged stream, a name that is
not in its declared encoding, an encrypted or unsupported member."""

_END = struct.Struct("<4s4H2LH")
_END_SIGNATURE = b"PK\x05\x06"
_LOCATOR = struct.Struct("<4sLQL")
_LOCATOR_SIGNATURE = b"PK\x06\x07"
_END64 = struct.Struct("<4sQ2H2L4Q")
_END64_SIGNATURE = b"PK\x06\x06"
_CENTRAL_RECORD = struct.Struct("<4s24x3H12x")
_CENTRAL_SIGNATURE = b"PK\x01\x02"
_MAX_COMMENT = 0xFFFF
_UNSET16 = 0xFFFF
_UNSET32 = 0xFFFFFFFF
_ENTRIES_HERE, _ENTRIES, _SIZE, _OFFSET = 3, 4, 5, 6
_ENTRIES_HERE64, _ENTRIES64, _SIZE64, _OFFSET64 = 6, 7, 8, 9
_CHUNK_BYTES = 64 * 1024


def _read_at(handle: IO[bytes], offset: int, size: int) -> bytes:
    handle.seek(offset)
    return handle.read(size)


@dataclass(frozen=True, slots=True)
class _EndRecords:
    """The end record `zipfile` finds, and the ZIP64 end records a locator before it leads to."""

    at: int
    end: tuple[int, ...]
    located: bool
    """Whether a ZIP64 locator sits right before the end record."""

    zip64: tuple[tuple[int, tuple[int, ...]], ...]
    """Each ZIP64 end record found, with where it sits: where the locator points and right
    before the locator, the two places `zipfile` releases read one from."""


def _end_record(handle: IO[bytes], file_size: int) -> tuple[int, tuple[int, ...]] | None:
    """Find the end record where `zipfile` looks for it: last in the file, or before a comment."""
    if file_size < _END.size:
        return None
    tail = _read_at(handle, file_size - _END.size, _END.size)
    if tail.startswith(_END_SIGNATURE) and tail.endswith(b"\x00\x00"):
        return file_size - _END.size, _END.unpack(tail)
    window_start = max(file_size - _MAX_COMMENT - 1 - _END.size, 0)
    window = _read_at(handle, window_start, file_size - window_start)
    at = window.rfind(_END_SIGNATURE)
    if at < 0 or len(window) - at < _END.size:
        return None
    return window_start + at, _END.unpack(window[at : at + _END.size])


def _end_records(handle: IO[bytes]) -> _EndRecords | None:
    """Read the end records; None when there is no end record, which `zipfile` refuses."""
    file_size = handle.seek(0, os.SEEK_END)
    found = _end_record(handle, file_size)
    if found is None:
        return None
    end_at, end = found
    if end_at < _LOCATOR.size:
        return _EndRecords(end_at, end, located=False, zip64=())
    locator = _read_at(handle, end_at - _LOCATOR.size, _LOCATOR.size)
    if not locator.startswith(_LOCATOR_SIGNATURE):
        return _EndRecords(end_at, end, located=False, zip64=())
    declared_at = _LOCATOR.unpack(locator)[2]
    adjacent_at = end_at - _LOCATOR.size - _END64.size
    records = []
    for at in dict.fromkeys((declared_at, adjacent_at)):
        # A locator may name any 64-bit offset; one past the end holds no record to read.
        record = _read_at(handle, at, _END64.size) if 0 <= at <= file_size else b""
        if len(record) == _END64.size and record.startswith(_END64_SIGNATURE):
            records.append((at, _END64.unpack(record)))
    return _EndRecords(end_at, end, located=True, zip64=tuple(records))


def declared_directory_start(handle: IO[bytes]) -> int | None:
    """Return the directory offset the end records declare; None when they cannot be read.

    None also when a locator names no ZIP64 end record, when two ZIP64 records declare
    different directories, or when one and the plain end record do, since readers differ
    on which of them they trust.
    """
    try:
        records = _end_records(handle)
    except (OSError, struct.error):
        return None
    if records is None:
        return None
    end = records.end
    if not records.located:
        return end[_OFFSET]
    if len({(fields[_SIZE64], fields[_OFFSET64]) for _at, fields in records.zip64}) != 1:
        return None
    end64 = records.zip64[0][1]
    for plain, wide in ((end[_SIZE], end64[_SIZE64]), (end[_OFFSET], end64[_OFFSET64])):
        if plain not in (_UNSET32, wide):
            return None
    return end64[_OFFSET64]


@dataclass(frozen=True, slots=True)
class ZipDirectory:
    """The entry count and byte size an end record declares for the central directory."""

    entries: int
    size: int
    start: int | None
    """Where `zipfile` reads this directory from; None for a 32-bit end record a ZIP64 one
    replaces, whose fields are only declared."""


def declared_directories(handle: IO[bytes]) -> tuple[ZipDirectory, ...]:
    """Every central directory `zipfile` may take this file to declare, from its end records.

    A ZIP64 end record replaces the plain one, and the plain record's fields that are not
    placeholders still count. Empty when no end record is found, which `zipfile` refuses
    on its own.
    """
    records = _end_records(handle)
    if records is None:
        return ()
    end = records.end
    entries, size = max(end[_ENTRIES_HERE], end[_ENTRIES]), end[_SIZE]
    if not records.zip64:
        return (ZipDirectory(entries, size, records.at - size),)
    declared = ZipDirectory(
        0 if entries == _UNSET16 else entries, 0 if size == _UNSET32 else size, None
    )
    wide = tuple(
        ZipDirectory(
            max(fields[_ENTRIES_HERE64], fields[_ENTRIES64]), fields[_SIZE64], at - fields[_SIZE64]
        )
        for at, fields in records.zip64
    )
    return (*wide, declared)


def counted_entries(handle: IO[bytes], directory: ZipDirectory, limit: int) -> int:
    """Count the records `zipfile` builds an entry for in `directory`, stopping past `limit`.

    `zipfile` walks the directory record by record to its declared size, whatever count
    the end record declares; this walks it the same way, in bounded chunks, and stops
    where `zipfile` would raise.
    """
    if directory.start is None or directory.start < 0:
        return 0
    count = position = chunk_at = 0
    chunk = b""
    while position < directory.size and count <= limit:
        if position + _CENTRAL_RECORD.size > chunk_at + len(chunk):
            chunk = _read_at(
                handle, directory.start + position, min(_CHUNK_BYTES, directory.size - position)
            )
            chunk_at = position
            if len(chunk) < _CENTRAL_RECORD.size:
                break
        signature, name, extra, comment = _CENTRAL_RECORD.unpack_from(chunk, position - chunk_at)
        if signature != _CENTRAL_SIGNATURE:
            break
        position += _CENTRAL_RECORD.size + name + extra + comment
        count += 1
    return count


def listing_refusal(handle: IO[bytes], *, max_entries: int, max_directory_bytes: int) -> str | None:
    """Why `zipfile` must not list the zip open on `handle`, or None when it may.

    Checks what the end records declare, then counts the directory's records within the
    byte bound. The caller hands `zipfile` this same handle, so what is listed is what
    was checked; an OSError while reading is the caller's to report.
    """
    directories = declared_directories(handle)
    for directory in directories:
        if directory.entries > max_entries:
            return (
                f"zip declares {directory.entries} entries, more than the {max_entries} "
                "an archive may list"
            )
        if directory.size > max_directory_bytes:
            return (
                f"zip declares a {directory.size}-byte central directory, more than the "
                f"{max_directory_bytes} bytes an archive may list"
            )
    for directory in directories:
        if counted_entries(handle, directory, max_entries) > max_entries:
            return f"zip central directory holds more than {max_entries} entries"
    return None


_LOCAL = struct.Struct("<4s5H3L2H")
_LOCAL_SIGNATURE = b"PK\x03\x04"
_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
_DESCRIPTOR_CHECK_BYTES = 8
"""A data descriptor's signature and CRC-32, which a streaming reader matches to end stored data."""
_CRC_BYTES = 4
_DESCRIPTOR_SIZES = struct.Struct("<LL")
_ENCRYPTED_FLAG = 0x01
_DATA_DESCRIPTOR_FLAG = 0x08
_UTF8_NAME_FLAG = 0x800
_EXTRA_HEADER = struct.Struct("<HH")
_ZIP64_FIELD = 0x0001
_ZIP64_SIZES = struct.Struct("<QQ")
_UNICODE_PATH_FIELD = 0x7075
_ATTRIBUTES_FIELD = 0x6C78
_ATTRIBUTES_VERSION, _ATTRIBUTES_INTERNAL, _ATTRIBUTES_EXTERNAL = 0x01, 0x02, 0x04
_MORE_BITS = 0x80


@dataclass(frozen=True, slots=True)
class _LocalHeader:
    """A member's local header, which a reader that walks the file reads for its entry."""

    version: int
    flags: int
    method: int
    crc: int
    packed: int
    size: int
    name: bytes
    fields: dict[int, bytes]
    repeats: bool
    """Whether the extra-field block holds two fields of one kind."""

    data_start: int


def _fields(extra: bytes) -> tuple[dict[int, bytes], bool]:
    """Return an extra-field block's fields by kind, and whether a kind repeats."""
    fields: dict[int, bytes] = {}
    repeats = False
    while len(extra) >= _EXTRA_HEADER.size:
        kind, size = _EXTRA_HEADER.unpack_from(extra)
        repeats = repeats or kind in fields
        fields[kind] = extra[_EXTRA_HEADER.size : _EXTRA_HEADER.size + size]
        extra = extra[_EXTRA_HEADER.size + size :]
    return fields, repeats


def _local_header(handle: IO[bytes], info: zipfile.ZipInfo) -> _LocalHeader | None:
    """Read the local header a member's directory entry points to; None when there is none."""
    header = _read_at(handle, info.header_offset, _LOCAL.size)
    if len(header) < _LOCAL.size or not header.startswith(_LOCAL_SIGNATURE):
        return None
    _sig, version, flags, method, _time, _date, crc, packed, size, name_length, extra_length = (
        _LOCAL.unpack(header)
    )
    name_and_extra = _read_at(handle, info.header_offset + _LOCAL.size, name_length + extra_length)
    fields, repeats = _fields(name_and_extra[name_length:])
    return _LocalHeader(
        version=version,
        flags=flags,
        method=method,
        crc=crc,
        packed=packed,
        size=size,
        name=name_and_extra[:name_length],
        fields=fields,
        repeats=repeats,
        data_start=info.header_offset + _LOCAL.size + name_length + extra_length,
    )


def member_disagreement(handle: IO[bytes], info: zipfile.ZipInfo) -> str | None:
    """Return how zip readers could read a member's bytes differently; None when they agree.

    `zipfile` reads a stored member's compressed size and the miniz reader in `torch.load`
    its size, and readers differ on which of the local header and the directory entry they
    trust, so each disagreement is named rather than read one way.
    """
    return _disagreement(_local_header(handle, info), info)


def _disagreement(  # noqa: PLR0911 — one return per disagreement named
    local: _LocalHeader | None, info: zipfile.ZipInfo
) -> str | None:
    """Return how a member's local header and directory entry let readers read it differently."""
    if info.compress_type == zipfile.ZIP_STORED and info.compress_size != info.file_size:
        return "is stored with a compressed size that differs from its size"
    if local is None:
        return "has no local header where its directory entry points"
    encoding = "utf-8" if info.flag_bits & _UTF8_NAME_FLAG else "cp437"
    if (
        local.name != info.orig_filename.encode(encoding)
        or local.flags != info.flag_bits
        or local.method != info.compress_type
    ):
        return "has a local header whose name, flags or method differ from its directory entry"
    central, repeats = _fields(info.extra)
    if local.repeats or repeats:
        return "repeats an extra field, whose copies zip readers choose between differently"
    unicode_path = local.fields.get(_UNICODE_PATH_FIELD)
    if unicode_path is not None and unicode_path != central.get(_UNICODE_PATH_FIELD):
        return "has a local header whose Unicode path differs from its directory entry's"
    if not _attributes_agree(local, info):
        return "has a local header whose file attributes differ from its directory entry's"
    pairs = (
        (local.crc, info.CRC),
        (local.packed, info.compress_size),
        (local.size, info.file_size),
    )
    if not local.flags & _DATA_DESCRIPTOR_FLAG and any(
        value not in (central_value, _UNSET32) for value, central_value in pairs
    ):
        return "has a local header whose sizes or checksum differ from its directory entry"
    return None


def _attributes_agree(local: _LocalHeader, info: zipfile.ZipInfo) -> bool:
    """Whether a libarchive `xl` field in the local header gives the entry's file attributes.

    `bsdtar` takes a member's type and mode from that field, read as it is read here.
    """
    data = local.fields.get(_ATTRIBUTES_FIELD, b"")
    if not data:
        return True
    bitmap, at = data[0], 1
    while data[at - 1] & _MORE_BITS and at < len(data):
        at += 1
    system = local.version >> 8
    if bitmap & _ATTRIBUTES_VERSION:
        if len(data) < at + 2:
            return True
        system, at = data[at + 1], at + 2
    if bitmap & _ATTRIBUTES_INTERNAL:
        at += 2
    if not bitmap & _ATTRIBUTES_EXTERNAL or len(data) < at + 4:
        return True
    external = int.from_bytes(data[at : at + 4], "little")
    return (system, external) == (info.create_system, info.external_attr)


def _streamed_sizes(local: _LocalHeader) -> tuple[int, int] | None:
    """Return the sizes a streaming reader takes from a local header; None if readers differ.

    The compressed size comes first. A size of 0xFFFFFFFF is read from the ZIP64 field:
    libarchive reads only such sizes from it, the size first, while Java's reader reads both
    when either is so marked.
    """
    marked = (local.packed == _UNSET32, local.size == _UNSET32)
    if not any(marked):
        return local.packed, local.size
    wide = local.fields.get(_ZIP64_FIELD, b"")
    if not all(marked) or len(wide) < _ZIP64_SIZES.size:
        return None
    size, packed = _ZIP64_SIZES.unpack_from(wide)
    return packed, size


class _OverBudgetError(Exception):
    """The walk read past what it may spend on one archive's member data."""


@dataclass(slots=True)
class _WalkBudget:
    """What the walk may still spend: bytes inflated, and data descriptor signatures matched."""

    inflated: int
    signatures: int

    def inflate(self, count: int) -> None:
        """Spend `count` inflated bytes."""
        self.inflated -= count
        if self.inflated < 0:
            raise _OverBudgetError

    def match(self) -> None:
        """Spend one data descriptor signature."""
        self.signatures -= 1
        if self.signatures < 0:
            raise _OverBudgetError


def unpacking_disagreement(  # noqa: PLR0911 — one return per disagreement named
    handle: IO[bytes], members: list[zipfile.ZipInfo], directory_start: int, *, inflate_limit: int
) -> str | None:
    """Return how a tool walking the zip could unpack what its directory lists otherwise, or not.

    None when it cannot.

    Such a tool, `bsdtar` reading a pipe among them, takes each member's name, type and
    sizes from its local header; it ends data a data descriptor follows where the
    descriptor's signature and CRC-32 match, compressed data where its stream ends, and
    then looks ahead for the next local header signature. So every local header must agree
    with its directory entry, every member's data must end where that entry says, and no
    byte between the members may hold a local header signature. Inflating is bounded by
    `inflate_limit` bytes.
    """
    budget = _WalkBudget(inflated=inflate_limit, signatures=ARCHIVE_MAX_ENTRIES)
    position = reach = 0
    try:
        for info in sorted(members, key=lambda info: info.header_offset):
            name = info.orig_filename
            if info.header_offset < reach:
                return f"member {name} overlaps the member before it"
            hidden = _find(handle, _LOCAL_SIGNATURE, position, info.header_offset)
            if hidden is not None:
                return _unlisted(hidden)
            local = _local_header(handle, info)
            disagreement = _disagreement(local, info)
            if local is None or disagreement is not None:
                return f"member {name} {disagreement}"
            disagreement = _streamed_disagreement(local, info)
            if disagreement is not None:
                return f"member {name} {disagreement}"
            position = local.data_start + info.compress_size
            ending = _end_disagreement(handle, info, local, budget)
            if ending is not None:
                return f"member {name} {ending}"
            reach = position + _descriptor_reach(handle, local, position)
            if reach > directory_start:
                return f"member {name} runs into its central directory"
    except _OverBudgetError:
        return (
            f"requires inflating more than {inflate_limit} bytes or matching more than "
            f"{ARCHIVE_MAX_ENTRIES} data descriptor signatures to find where members end"
        )
    hidden = _find(handle, _LOCAL_SIGNATURE, position, directory_start)
    return None if hidden is None else _unlisted(hidden)


def _unlisted(at: int) -> str:
    return f"holds a local header at byte {at} that its central directory does not list"


def _descriptor_reach(handle: IO[bytes], local: _LocalHeader, data_end: int) -> int:
    """Return how many bytes past a member's data a streaming reader may take as its descriptor.

    A member without the data descriptor flag has none. `bsdtar` skipping a member takes
    8-byte sizes whenever its local header holds a ZIP64 field, whatever the sizes, and a
    deflated member's descriptor may lack its signature.
    """
    if not local.flags & _DATA_DESCRIPTOR_FLAG:
        return 0
    signed = _read_at(handle, data_end, len(_DESCRIPTOR_SIGNATURE)) == _DESCRIPTOR_SIGNATURE
    size_bytes = _ZIP64_SIZES.size if _ZIP64_FIELD in local.fields else _DESCRIPTOR_SIZES.size
    return (len(_DESCRIPTOR_SIGNATURE) if signed else 0) + _CRC_BYTES + size_bytes


def _streamed_disagreement(local: _LocalHeader, info: zipfile.ZipInfo) -> str | None:
    """Return how the sizes a streaming reader takes from a local header differ from the entry's.

    With a data descriptor, a size of 0 defers to the descriptor.
    """
    sizes = _streamed_sizes(local)
    if sizes is None:
        return "has a local header whose ZIP64 sizes zip readers take differently"
    declared = (info.compress_size, info.file_size)
    if local.flags & _DATA_DESCRIPTOR_FLAG:
        agree = all(size in (0, want) for size, want in zip(sizes, declared, strict=True))
    else:
        agree = sizes == declared
    return None if agree else "has a local header whose sizes differ from its directory entry"


def _end_disagreement(
    handle: IO[bytes], info: zipfile.ZipInfo, local: _LocalHeader, budget: _WalkBudget
) -> str | None:
    """Return how a streaming reader could end a member's data elsewhere than its entry says."""
    start, size = local.data_start, info.compress_size
    described = info.flag_bits & _DATA_DESCRIPTOR_FLAG
    if not described:
        if info.compress_type == zipfile.ZIP_STORED:
            return None
        # A reader decoding the data ends it where its stream ends, then looks for the next
        # local header from there; only a signature inside the data is found that way.
        if _find(handle, _LOCAL_SIGNATURE, start, start + size) is None:
            return None
    if info.flag_bits & _ENCRYPTED_FLAG or info.compress_type not in (
        zipfile.ZIP_STORED,
        zipfile.ZIP_DEFLATED,
    ):
        return (
            "is encrypted or uses compression other than stored or deflate, and finding its "
            "data end requires decoding the scanner does not do"
        )
    if info.compress_type == zipfile.ZIP_STORED:
        return _stored_end_disagreement(handle, start, size, budget)
    return _deflate_end_disagreement(handle, start, size, budget)


def _stored_end_disagreement(
    handle: IO[bytes], start: int, size: int, budget: _WalkBudget
) -> str | None:
    """Return how a streaming reader ends described stored data elsewhere than `size` bytes on.

    It ends the data at the first data descriptor signature whose next four bytes are the
    CRC-32 of the data before it.
    """
    handle.seek(start)
    limit = size + _DESCRIPTOR_CHECK_BYTES
    window, base, read = b"", 0, 0
    crc, crc_end, search = 0, 0, 0
    while True:
        chunk = handle.read(min(_CHUNK_BYTES, limit - read))
        read += len(chunk)
        window += chunk
        while True:
            found = window.find(_DESCRIPTOR_SIGNATURE, search - base)
            if found < 0 or found + _DESCRIPTOR_CHECK_BYTES > len(window):
                break
            budget.match()
            crc = zlib.crc32(memoryview(window)[crc_end - base : found], crc)
            crc_end = base + found
            if int.from_bytes(window[found + 4 : found + 8], "little") == crc:
                if crc_end == size:
                    return None
                return (
                    f"has stored data a streaming reader ends at byte {start + crc_end}, "
                    "where a data descriptor's signature and CRC-32 match"
                )
            search = crc_end + 1
        if not chunk:
            return (
                f"has stored data with no matching data descriptor at byte {start + size}, "
                "where its directory entry says it ends, so a streaming reader reads on"
            )
        keep = max(len(window) - (_DESCRIPTOR_CHECK_BYTES - 1), crc_end - base)
        crc = zlib.crc32(memoryview(window)[crc_end - base : keep], crc)
        window, base, crc_end = window[keep:], base + keep, base + keep
        search = max(search, base)


def _deflate_end_disagreement(
    handle: IO[bytes], start: int, size: int, budget: _WalkBudget
) -> str | None:
    """Return how a deflate stream, where a streaming reader ends it, ends off `size` bytes on."""
    inflater = zlib.decompressobj(-zlib.MAX_WBITS)
    handle.seek(start)
    remaining = size
    try:
        while remaining and not inflater.eof:
            chunk = handle.read(min(_CHUNK_BYTES, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            while chunk and not inflater.eof:
                budget.inflate(len(inflater.decompress(chunk, _CHUNK_BYTES)))
                chunk = inflater.unconsumed_tail
    except zlib.error:
        return "has a deflate stream that does not decode"
    if not inflater.eof:
        return "has a deflate stream that does not end within the size its directory entry declares"
    if inflater.unused_data or remaining:
        return "has a deflate stream that ends before the size its directory entry declares"
    return None


def _find(handle: IO[bytes], needle: bytes, start: int, end: int) -> int | None:
    """Return the first offset in [start, end) at which `needle` starts; None if it starts at none.

    A match may run up to `len(needle) - 1` bytes past `end`.
    """
    keep = len(needle) - 1
    limit = end + keep
    handle.seek(start)
    window, base = b"", start
    while base < end:
        chunk = handle.read(min(_CHUNK_BYTES, limit - base - len(window)))
        window += chunk
        found = window.find(needle)
        if found >= 0:
            return base + found
        if not chunk:
            return None
        drop = max(len(window) - keep, 0)
        window, base = window[drop:], base + drop
    return None
