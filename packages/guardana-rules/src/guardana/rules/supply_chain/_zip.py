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

import os
import struct
import zipfile
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
_DATA_DESCRIPTOR_FLAG = 0x08
_UTF8_NAME_FLAG = 0x800


def member_disagreement(handle: IO[bytes], info: zipfile.ZipInfo) -> str | None:
    """Return how zip readers could read a member's bytes differently; None when they agree.

    `zipfile` reads a stored member's compressed size and the miniz reader in `torch.load`
    its size, and readers differ on which of the local header and the directory entry they
    trust, so each disagreement is named rather than read one way.
    """
    if info.compress_type == zipfile.ZIP_STORED and info.compress_size != info.file_size:
        return "is stored with a compressed size that differs from its size"
    header = _read_at(handle, info.header_offset, _LOCAL.size)
    if len(header) < _LOCAL.size or not header.startswith(_LOCAL_SIGNATURE):
        return "has no local header where its directory entry points"
    _sig, _version, flags, method, _time, _date, crc, packed, size, name_length, extra_length = (
        _LOCAL.unpack(header)
    )
    name = _read_at(handle, info.header_offset + _LOCAL.size, name_length)
    extra = _read_at(handle, info.header_offset + _LOCAL.size + name_length, extra_length)
    encoding = "utf-8" if info.flag_bits & _UTF8_NAME_FLAG else "cp437"
    if (
        name != info.orig_filename.encode(encoding)
        or flags != info.flag_bits
        or method != info.compress_type
    ):
        return "has a local header whose name, flags or method differ from its directory entry"
    if _repeats_a_field(info.extra) or _repeats_a_field(extra):
        return "repeats an extra field, whose copies zip readers choose between differently"
    pairs = ((crc, info.CRC), (packed, info.compress_size), (size, info.file_size))
    if not flags & _DATA_DESCRIPTOR_FLAG and any(
        local not in (central, _UNSET32) for local, central in pairs
    ):
        return "has a local header whose sizes or checksum differ from its directory entry"
    return None


_EXTRA_HEADER = struct.Struct("<HH")


def _repeats_a_field(extra: bytes) -> bool:
    """Whether an extra-field block holds two fields of one kind, such as two ZIP64 fields."""
    kinds: set[int] = set()
    while len(extra) >= _EXTRA_HEADER.size:
        kind, size = _EXTRA_HEADER.unpack_from(extra)
        if kind in kinds:
            return True
        kinds.add(kind)
        extra = extra[_EXTRA_HEADER.size + size :]
    return False
