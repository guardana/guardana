"""The member list of a tar, and the member a link in it reads as, without extracting.

`tarfile` resolves a link by loading every remaining header, which moves the read
position past the members a caller has not reached yet; so the headers are all read
first, and a link is resolved here against that list.

`tarfile` reads every extended header whole while it lists, so `listing_refusal` walks the
header blocks first, as `tarfile` would, to say whether the archive may be given to it.
Where the walk cannot tell where `tarfile` reads next, it refuses rather than hand the
archive on.
"""

import bisect
import posixpath
import re
import struct
import tarfile
from dataclasses import dataclass, field
from typing import BinaryIO

TAR_MAX_HEADERS = 1_000_000
"""Headers read from one tar; each costs a 512-byte block, and a checkpoint holds a few."""
TAR_EXTENDED_HEADER_MAX_BYTES = 1024 * 1024
"""Bytes of extended headers (PAX `x`, `g`, `X`; GNU `L`, `K`) in front of one member.

They hold a path, a link target and a few attributes, and a path is at most 4 KiB on
common systems, so this is room for hundreds of them.
"""
TAR_HEADERS_PER_ENTRY = 4
"""Headers walked for each member an archive may list: its own, and in front of it a PAX
header, a GNU long name and a GNU long link."""
TAR_EXTENDED_HEADERS_PER_MEMBER = 8
"""Extended headers in front of one member, twice the four a writer puts there."""
TAR_GLOBAL_RECORDS_APPLIED_MAX = 1_000_000
"""Global PAX records `tarfile` applies, summed over every member and PAX header after them.

It copies the records in force into each; a `git archive` tar holds one, so this is room
for ten in front of 100,000 members.
"""
TAR_SPARSE_MAP_MAX_ENTRIES = 100_000
"""Regions the sparse maps of one tar list in all.

`tarfile` keeps a pair of numbers for each, and a file with holes lists a handful.
"""
_MAX_LINK_HOPS = 32
_END_OF_ARCHIVE_BYTES = 2 * tarfile.BLOCKSIZE
_NOT_FILE_DATA = frozenset({tarfile.DIRTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE})
_PAX_TYPES = frozenset({tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE})
_EXTENDED_TYPES = _PAX_TYPES | {tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}
_SPARSE_MAP = b"GNU.sparse.map"
_SPARSE_SIZE = b"GNU.sparse.size"
_SPARSE_OFFSET = b"GNU.sparse.offset"
_SPARSE_MAJOR = b"GNU.sparse.major"
_SPARSE_MINOR = b"GNU.sparse.minor"
_SIZE_KEYS = frozenset({b"size", _SPARSE_SIZE, b"GNU.sparse.realsize"})
_KEPT_KEYS = _SIZE_KEYS | {_SPARSE_MAP, _SPARSE_MAJOR, _SPARSE_MINOR}
_HEADER_SPARSE_ENTRIES = 4
_BLOCK_SPARSE_ENTRIES = 21
_SPARSE_EXTENDED_AT = 482
_SPARSE_BLOCK_EXTENDED_AT = 504
_PAX_RECORD_LENGTH = re.compile(rb"([0-9]{1,20}) ")
_PAX_SHORTEST_RECORD = 5
_NAME = slice(0, 100)
_SIZE = slice(124, 136)
_CHECKSUM = slice(148, 156)
_TYPE = slice(156, 157)
_BLANK_CHECKSUM = 8 * ord(" ")
_BASE256_POSITIVE = 0o200
_BASE256_NEGATIVE = 0o377
_SIGNED_BYTES = struct.Struct("148b8x356b")


class TarListingError(Exception):
    """Raised when a tar holds more headers than `TAR_MAX_HEADERS`, or a damaged one."""


def _normalised(name: str) -> str:
    return posixpath.normpath(name)


def _require_end_of_archive(archive: tarfile.TarFile) -> None:
    """Raise `TarListingError` unless the listing stopped at the end of the archive.

    `tarfile` stops listing at a header it cannot parse without raising, while `tar`
    warns and extracts the members after it; so the listing is whole only where the
    file ends or the zero blocks that close an archive begin. A tar cut at a member
    boundary has no member left unlisted, so it is whole.
    """
    handle = archive.fileobj
    if handle is None:
        raise TarListingError("tar could not be read past its headers")
    handle.seek(archive.offset)
    tail = handle.read(_END_OF_ARCHIVE_BYTES)
    if tail.strip(b"\x00"):
        raise TarListingError(f"tar has a damaged header at byte {archive.offset}")


@dataclass(slots=True)
class TarListing:
    """Every header of one tar, in order, with the positions each name occurs at."""

    members: list[tarfile.TarInfo] = field(default_factory=list)
    _positions: dict[str, list[int]] = field(default_factory=dict)

    @classmethod
    def read(cls, archive: tarfile.TarFile) -> "TarListing":
        """Read every header of `archive`, reading no member's data.

        Raises `TarListingError` past `TAR_MAX_HEADERS` or at a damaged header, and
        whatever `tarfile` raises for a malformed first header.
        """
        listing = cls()
        while (entry := archive.next()) is not None:
            if len(listing.members) >= TAR_MAX_HEADERS:
                raise TarListingError(f"tar holds more than {TAR_MAX_HEADERS} headers")
            listing._positions.setdefault(_normalised(entry.name), []).append(len(listing.members))
            listing.members.append(entry)
        _require_end_of_archive(archive)
        return listing

    def resolve(self, index: int) -> tarfile.TarInfo | None:
        """Return the member whose bytes `members[index]` reads as, following links.

        A hard link names a member before it and a symbolic link one relative to its own
        directory, the last of that name, as `tarfile` resolves them. None when a link
        names no member, or the chain is longer than any loader would follow.
        """
        position = index
        for _ in range(_MAX_LINK_HOPS):
            entry = self.members[position]
            if not (entry.islnk() or entry.issym()):
                return entry
            if entry.islnk():
                wanted, before = _normalised(entry.linkname), position
            else:
                joined = "/".join(filter(None, (posixpath.dirname(entry.name), entry.linkname)))
                wanted, before = _normalised(joined), len(self.members)
            positions = self._positions.get(wanted, [])
            earlier = bisect.bisect_left(positions, before)
            if earlier == 0:
                return None
            position = positions[earlier - 1]
        return None


def holds_file_data(entry: tarfile.TarInfo) -> bool:
    """Whether a loader opening `entry` reads bytes from the archive.

    A type `tarfile` does not know is read as a regular file, as `extractfile` reads it.
    """
    return entry.type not in _NOT_FILE_DATA


def _number(field: bytes) -> int:
    """Read a numeric header field as `tarfile` does: base-256, or octal text up to a NUL.

    Raises `ValueError` for a field `tarfile` cannot read either.
    """
    if field[0] in (_BASE256_POSITIVE, _BASE256_NEGATIVE):
        value = int.from_bytes(field[1:], "big")
        return value - 256 ** (len(field) - 1) if field[0] == _BASE256_NEGATIVE else value
    text = field.split(b"\x00", 1)[0]
    return int(text.decode("ascii").strip() or "0", 8)


@dataclass(frozen=True, slots=True)
class _Header:
    """The fields of one header block that say where `tarfile` reads next."""

    kind: bytes
    size: int
    named_as_directory: bool
    """An old-style file header whose name ends in a slash, which `tarfile` may read as a
    directory, whose data it does not skip."""
    sparse_extended: bool
    """A GNU sparse header followed by extension blocks before its data."""


def _header(block: bytes) -> _Header | None:
    """Read a header block, or None where `tarfile` stops listing.

    Checks what `tarfile` checks before it reads a header's fields: a whole block, not all
    zeros, a checksum and a size it can read. A header `tarfile` refuses for another field
    is walked past, and `tarfile` stops at it on its own.
    """
    if len(block) != tarfile.BLOCKSIZE or not block.strip(b"\x00"):
        return None
    try:
        checksum = _number(block[_CHECKSUM])
        size = _number(block[_SIZE])
    except ValueError:
        return None
    unsigned = _BLANK_CHECKSUM + sum(block[: _CHECKSUM.start]) + sum(block[_CHECKSUM.stop :])
    if checksum != unsigned and checksum != _BLANK_CHECKSUM + sum(_SIGNED_BYTES.unpack(block)):
        return None
    kind = block[_TYPE]
    name = block[_NAME].split(b"\x00", 1)[0]
    return _Header(
        kind,
        size,
        named_as_directory=kind == tarfile.AREGTYPE and name.endswith(b"/"),
        sparse_extended=block[_SPARSE_EXTENDED_AT] != 0,
    )


class _RefusedError(Exception):
    """The archive declares more than `tarfile` may be given to list, or what it cannot follow."""


def _malformed(what: str, start: int) -> _RefusedError:
    return _RefusedError(f"tar has a malformed {what} at byte {start}")


def _span(size: int, start: int) -> int:
    """Bytes a member of `size` occupies, as `tarfile` rounds it."""
    if size < 0:
        raise _RefusedError(f"tar declares a negative size at byte {start}")
    return -(-size // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE


@dataclass(frozen=True, slots=True)
class _PaxHeader:
    """What one PAX header holds that moves a member's data or costs `tarfile` memory."""

    kept: dict[bytes, bytes]
    """The size and sparse records, in the order `tarfile` keeps them, each its last value."""
    keywords: frozenset[bytes]
    offsets: int
    """`GNU.sparse.offset` records, which `tarfile` reads from this header alone."""


def _pax_header(payload: bytes, start: int) -> _PaxHeader:
    """Read the records of a PAX header; refuse one `tarfile` cannot parse."""
    kept: dict[bytes, bytes] = {}
    keywords: set[bytes] = set()
    offsets = position = 0
    while position < len(payload) and payload[position] != 0:
        match = _PAX_RECORD_LENGTH.match(payload, position)
        length = int(match.group(1)) if match is not None else 0
        end = position + length - 1
        if match is None or length < _PAX_SHORTEST_RECORD or end >= len(payload):
            raise _malformed("PAX header", start)
        keyword, equals, value = payload[match.end(1) + 1 : end].partition(b"=")
        if not keyword or not equals or payload[end] != ord("\n"):
            raise _malformed("PAX header", start)
        keywords.add(keyword)
        if keyword in _KEPT_KEYS:
            kept[keyword] = value
        offsets += keyword == _SPARSE_OFFSET
        position += length
    return _PaxHeader(kept, frozenset(keywords), offsets)


def _pax_size(value: bytes) -> int:
    """Return the member size `tarfile` reads from a PAX `size` record, zero for no number."""
    try:
        return int(value.decode("utf-8", "surrogateescape"))
    except ValueError:
        return 0


def _integer(text: bytes) -> int | None:
    """Read `text` as `int` does, or None where `int` raises."""
    try:
        return int(text)
    except ValueError:
        return None


def _reads_sparse_map(records: dict[bytes, bytes]) -> bool:
    """Whether `tarfile` reads a GNU sparse 1.0 map from the start of the member's data."""
    return (
        _SPARSE_MAP not in records
        and _SPARSE_SIZE not in records
        and records.get(_SPARSE_MAJOR) == b"1"
        and records.get(_SPARSE_MINOR) == b"0"
    )


@dataclass(slots=True)
class _Chain:
    """The extended headers walked in front of one member."""

    headers: int = 0
    declared: int = 0
    sized: dict[bytes, bytes] | None = None
    """The records of the first PAX header that gives the member a size, which `tarfile`
    applies last."""
    sized_headers: int = 0
    last_sized: bool = False
    """Whether the header right before the member is a PAX header giving it a size."""
    map_reads: int = 0
    """PAX headers that make `tarfile` read a sparse map from the member's data."""


@dataclass(slots=True)
class _HeaderWalk:
    """The position and counts of a walk through a tar's headers."""

    handle: BinaryIO
    max_entries: int
    position: int = 0
    members: int = 0
    headers: int = 0
    sparse_entries: int = 0
    global_kept: dict[bytes, bytes] = field(default_factory=dict)
    global_keywords: set[bytes] = field(default_factory=set)
    global_applied: int = 0
    """Global records in force, summed over the members and PAX headers read so far."""

    def _block(self, at: int) -> bytes:
        self.handle.seek(at)
        return self.handle.read(tarfile.BLOCKSIZE)

    def member(self) -> bool:
        """Walk one member and the extended headers in front of it; False at the end."""
        chain = _Chain()
        follow_up = False
        while True:
            start = self.position
            block = self._block(start)
            header = _header(block)
            if header is None:
                if not follow_up and not block.strip(b"\x00"):
                    return False
                raise _RefusedError(f"tar has a damaged header at byte {start}")
            self.headers += 1
            if self.headers > TAR_HEADERS_PER_ENTRY * self.max_entries:
                raise _RefusedError(
                    f"tar holds more than {TAR_HEADERS_PER_ENTRY * self.max_entries} headers"
                )
            kind = header.kind
            if header.named_as_directory:
                if follow_up:
                    # After an extended header, some `tarfile` releases read this as a
                    # directory and others as a file whose data they skip.
                    raise _RefusedError(f"tar has an ambiguous header at byte {start}")
                kind = tarfile.DIRTYPE
            if kind not in _EXTENDED_TYPES:
                self._past_data(header, kind, start, chain)
                return True
            self._past_extended(header, kind, start, chain)
            follow_up = True

    def _past_extended(self, header: _Header, kind: bytes, start: int, chain: _Chain) -> None:
        span = _span(header.size, start)
        chain.headers += 1
        if chain.headers > TAR_EXTENDED_HEADERS_PER_MEMBER:
            raise _RefusedError(
                f"tar has more than {TAR_EXTENDED_HEADERS_PER_MEMBER} extended headers "
                f"in front of one member at byte {start}"
            )
        chain.declared += header.size
        if chain.declared > TAR_EXTENDED_HEADER_MAX_BYTES:
            raise _RefusedError(
                f"tar extended headers before the member at byte {start} declare "
                f"{chain.declared} bytes, more than the {TAR_EXTENDED_HEADER_MAX_BYTES} "
                "a member may carry"
            )
        data_at = start + tarfile.BLOCKSIZE
        chain.last_sized = False
        if kind in _PAX_TYPES:
            self.handle.seek(data_at)
            pax = _pax_header(self.handle.read(span), start)
            if kind == tarfile.XGLTYPE:
                self.global_kept.update(pax.kept)
                self.global_keywords |= pax.keywords
                records = self.global_kept
            else:
                records = {**self.global_kept, **pax.kept}
                self._apply_globals(start)
                if b"size" in records:
                    chain.sized_headers += 1
                    chain.sized = records if chain.sized is None else chain.sized
                    chain.last_sized = True
            self._count_sparse(records, pax.offsets, chain, start)
        self.position = data_at + span

    def _count_sparse(
        self, records: dict[bytes, bytes], offsets: int, chain: _Chain, start: int
    ) -> None:
        """Count the sparse regions `tarfile` reads for the member these records describe."""
        if _SPARSE_MAP in records:
            self._spend_sparse((records[_SPARSE_MAP].count(b",") + 1) // 2, start)
        elif _SPARSE_SIZE in records:
            self._spend_sparse(offsets, start)
        elif _reads_sparse_map(records):
            chain.map_reads += 1

    def _spend_sparse(self, entries: int, start: int) -> None:
        self.sparse_entries += entries
        if self.sparse_entries > TAR_SPARSE_MAP_MAX_ENTRIES:
            raise _RefusedError(
                f"tar sparse maps up to byte {start} list more than "
                f"{TAR_SPARSE_MAP_MAX_ENTRIES} regions"
            )

    def _apply_globals(self, start: int) -> None:
        self.global_applied += len(self.global_keywords)
        if self.global_applied > TAR_GLOBAL_RECORDS_APPLIED_MAX:
            raise _RefusedError(
                f"tar global PAX records applied up to byte {start} number "
                f"{self.global_applied}, more than the {TAR_GLOBAL_RECORDS_APPLIED_MAX} "
                "an archive may carry"
            )

    def _past_sparse_blocks(self, header: _Header, start: int) -> int:
        """Walk an old GNU sparse member's extension blocks; return where its data starts."""
        data_at = start + tarfile.BLOCKSIZE
        self._spend_sparse(_HEADER_SPARSE_ENTRIES, start)
        more = header.sparse_extended
        while more:
            if data_at - start > TAR_EXTENDED_HEADER_MAX_BYTES:
                raise _RefusedError(f"tar sparse member at byte {start} has an oversized map")
            sparse = self._block(data_at)
            if len(sparse) < tarfile.BLOCKSIZE:
                raise _malformed("sparse member", start)
            self._spend_sparse(_BLOCK_SPARSE_ENTRIES, start)
            more = sparse[_SPARSE_BLOCK_EXTENDED_AT] != 0
            data_at += tarfile.BLOCKSIZE
        return data_at

    def _read_sparse_map(self, data_at: int, start: int) -> None:
        """Read a sparse 1.0 map as `tarfile` does, counting its regions.

        `tarfile` reads a block, then one more each time the next number has not ended.
        """
        first, newline, buffer = self._block(data_at).partition(b"\n")
        fields = _integer(first) if newline else None
        if fields is None or fields < 0:
            raise _malformed("sparse map", start)
        self._spend_sparse(fields, start)
        blocks = 1
        for _ in range(2 * fields):
            if b"\n" not in buffer:
                if blocks * tarfile.BLOCKSIZE >= TAR_EXTENDED_HEADER_MAX_BYTES:
                    raise _RefusedError(f"tar sparse member at byte {start} has an oversized map")
                buffer += self._block(data_at + blocks * tarfile.BLOCKSIZE)
                blocks += 1
            number, newline, buffer = buffer.partition(b"\n")
            if not newline or _integer(number) is None:
                raise _malformed("sparse map", start)

    def _require_agreed_size(self, kind: bytes, start: int, chain: _Chain) -> None:
        """Refuse a PAX size `tarfile` releases place the next header after differently.

        Some count it from the end of the member's header and take the `size` record as it
        is; others count it from where the member's data starts, after sparse extension
        blocks or a sparse map, or from an extended header between the PAX header and the
        member, and let a sparse size record replace it.
        """
        agreed = (
            chain.sized is not None
            and chain.sized_headers == 1
            and chain.last_sized
            and kind != tarfile.GNUTYPE_SPARSE
            and not chain.map_reads
            and not (_SIZE_KEYS - {b"size"}) & chain.sized.keys()
        )
        if not agreed:
            raise _RefusedError(
                f"tar gives the member at byte {start} a PAX size that `tarfile` releases "
                "read differently"
            )

    def _past_data(self, header: _Header, kind: bytes, start: int, chain: _Chain) -> None:
        if kind == tarfile.GNUTYPE_SPARSE:
            data_at = self._past_sparse_blocks(header, start)
        else:
            data_at = start + tarfile.BLOCKSIZE
        if chain.map_reads > 1:
            raise _RefusedError(f"tar has more than one sparse map for the member at byte {start}")
        if chain.map_reads:
            self._read_sparse_map(data_at, start)
        size = header.size
        if chain.sized is not None:
            self._require_agreed_size(kind, start, chain)
            size = _pax_size(chain.sized[b"size"])
        has_data = kind in tarfile.REGULAR_TYPES or kind not in tarfile.SUPPORTED_TYPES
        self.position = data_at + (_span(size, start) if has_data else 0)
        self.members += 1
        if self.members > self.max_entries:
            raise _RefusedError(f"tar holds more than {self.max_entries} members")
        self._apply_globals(start)


def listing_refusal(handle: BinaryIO, *, max_entries: int) -> str | None:
    """Why `tarfile` must not list this archive, or None when it may.

    Walks the header blocks where `tarfile` would read them, reading one block per header
    and seeking past member data. Refuses an archive with more than `max_entries` members
    or `TAR_HEADERS_PER_ENTRY` headers for each of them; more than
    `TAR_EXTENDED_HEADERS_PER_MEMBER` extended headers, or more than
    `TAR_EXTENDED_HEADER_MAX_BYTES` of them, in front of one member; more global PAX
    records applied than `TAR_GLOBAL_RECORDS_APPLIED_MAX`; sparse maps listing more than
    `TAR_SPARSE_MAP_MAX_ENTRIES` regions, or one stored in a member's data or extension
    blocks past `TAR_EXTENDED_HEADER_MAX_BYTES`; and any header the walk cannot follow.
    A PAX header within the bound is read to follow the size it gives its member.
    """
    walk = _HeaderWalk(handle, max_entries)
    try:
        while walk.member():
            pass
    except _RefusedError as refusal:
        return str(refusal)
    return None
