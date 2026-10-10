"""What a zip's end records declare about its central directory, read from the file's tail.

`zipfile` reads the whole central directory into memory, and builds an entry for every
record in it, before a single member can be read; so what the end records declare is
read first, in a few bounded reads, and an archive that declares too much is refused.
"""

import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

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
_ZIP64_LOCATOR = struct.Struct("<4sLQL")
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP64_END = struct.Struct("<4sQ2H2L4Q")
_ZIP64_END_SIGNATURE = b"PK\x06\x06"
_CENTRAL_RECORD = struct.Struct("<4s24x3H12x")
_CENTRAL_SIGNATURE = b"PK\x01\x02"
_MAX_COMMENT = 0xFFFF
_ENTRIES_PLACEHOLDER = 0xFFFF
_BYTES_PLACEHOLDER = 0xFFFFFFFF
_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class ZipDirectory:
    """The entry count and byte size an end record declares for the central directory."""

    entries: int
    size: int
    start: int | None
    """Where `zipfile` reads this directory from; None for a 32-bit end record a ZIP64 one
    replaces, whose fields are only declared."""


def declared_directories(handle: BinaryIO) -> tuple[ZipDirectory, ...]:
    """Every central directory `zipfile` may take this file to declare, from its end records.

    The end record is found where `zipfile` looks for it: at the very end of the file when
    it carries no comment, else at the last signature within a comment's length of the
    end. A ZIP64 end record replaces it, and is looked for both where its locator points
    and right before the locator, the two places `zipfile` reads one from; the 32-bit
    fields that are not placeholders still count. Empty when no end record is found,
    which `zipfile` refuses on its own.
    """
    size = handle.seek(0, os.SEEK_END)
    start = max(size - _MAX_COMMENT - _END.size, 0)
    handle.seek(start)
    tail = handle.read(size - start)
    at = _end_record_offset(tail)
    if at is None:
        return ()
    fields = _END.unpack_from(tail, at)
    entries, directory = max(fields[3], fields[4]), fields[5]
    zip64 = _zip64_directories(handle, start + at)
    if not zip64:
        return (ZipDirectory(entries, directory, start + at - directory),)
    declared = ZipDirectory(
        0 if entries == _ENTRIES_PLACEHOLDER else entries,
        0 if directory == _BYTES_PLACEHOLDER else directory,
        None,
    )
    return (*zip64, declared)


def _end_record_offset(tail: bytes) -> int | None:
    last = len(tail) - _END.size
    if last >= 0 and tail.startswith(_END_SIGNATURE, last) and tail.endswith(b"\x00\x00"):
        return last
    at = tail.rfind(_END_SIGNATURE)
    return at if 0 <= at <= last else None


def _zip64_directories(handle: BinaryIO, end_at: int) -> tuple[ZipDirectory, ...]:
    locator_at = end_at - _ZIP64_LOCATOR.size
    if locator_at < 0:
        return ()
    handle.seek(locator_at)
    locator = handle.read(_ZIP64_LOCATOR.size)
    if len(locator) != _ZIP64_LOCATOR.size or not locator.startswith(_ZIP64_LOCATOR_SIGNATURE):
        return ()
    record_at = _ZIP64_LOCATOR.unpack(locator)[2]
    found: list[ZipDirectory] = []
    for at in dict.fromkeys((record_at, locator_at - _ZIP64_END.size)):
        if at < 0:
            continue
        handle.seek(at)
        record = handle.read(_ZIP64_END.size)
        if len(record) == _ZIP64_END.size and record.startswith(_ZIP64_END_SIGNATURE):
            fields = _ZIP64_END.unpack(record)
            found.append(ZipDirectory(max(fields[6], fields[7]), fields[8], at - fields[8]))
    return tuple(found)


def counted_entries(handle: BinaryIO, directory: ZipDirectory, limit: int) -> int:
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
            handle.seek(directory.start + position)
            chunk = handle.read(min(_CHUNK_BYTES, directory.size - position))
            chunk_at = position
            if len(chunk) < _CENTRAL_RECORD.size:
                break
        signature, name, extra, comment = _CENTRAL_RECORD.unpack_from(chunk, position - chunk_at)
        if signature != _CENTRAL_SIGNATURE:
            break
        position += _CENTRAL_RECORD.size + name + extra + comment
        count += 1
    return count


def listing_refusal(path: Path, *, max_entries: int, max_directory_bytes: int) -> str | None:
    """Why `zipfile` must not list the zip at `path`, or None when it may.

    Checks what the end records declare, then counts the directory's records within the
    byte bound. None too when the file is not a regular file or cannot be read, which the
    caller then reports; a FIFO would block the read until a writer appears.
    """
    try:
        if not path.is_file():
            return None
        with path.open("rb", buffering=0) as handle:
            return _refusal(handle, max_entries, max_directory_bytes)
    except OSError:
        return None


def _refusal(handle: BinaryIO, max_entries: int, max_directory_bytes: int) -> str | None:
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
