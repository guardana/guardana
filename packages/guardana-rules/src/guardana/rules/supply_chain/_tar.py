"""The member list of a tar, and the member a link in it reads as, without extracting.

`tarfile` resolves a link by loading every remaining header, which moves the read
position past the members a caller has not reached yet; so the headers are all read
first, and a link is resolved here against that list.

`tarfile` reads every extended header whole while it lists, so `listing_refusal` walks the
header blocks first, as `tarfile` would, to say whether the archive may be given to it.
Where the walk cannot tell where `tarfile` reads next, it refuses rather than hand the
archive on. It also refuses headers that `tarfile` and the `tar` commands (GNU tar, bsdtar,
busybox) would read as another name, size or layout, so the members listed are the members
a `tar` command unpacks.
"""

import bisect
import os
import posixpath
import re
import struct
import tarfile
from dataclasses import dataclass, field
from typing import Protocol

from guardana.rules.supply_chain._unpacking import gnu_checksum

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
_PAX_PATH = b"path"
_PAX_LINK_PATH = b"linkpath"
_PAX_SIZE = b"size"
_SPARSE_NAME = b"GNU.sparse.name"
_SPARSE_PREFIX = b"GNU.sparse."
_NAME_KEYS = frozenset({_PAX_PATH, _PAX_LINK_PATH, _SPARSE_NAME})
_SPARSE_KEY_PREFIX = _SPARSE_PREFIX.decode()
_SPARSE_NAME_KEY = _SPARSE_NAME.decode()
_SPARSE_MAP = b"GNU.sparse.map"
_SPARSE_SIZE = b"GNU.sparse.size"
_SPARSE_OFFSET = b"GNU.sparse.offset"
_SPARSE_MAJOR = b"GNU.sparse.major"
_SPARSE_MINOR = b"GNU.sparse.minor"
_SIZE_KEYS = frozenset({_PAX_SIZE, _SPARSE_SIZE, b"GNU.sparse.realsize"})
_KEPT_KEYS = _SIZE_KEYS | {_SPARSE_MAP, _SPARSE_MAJOR, _SPARSE_MINOR}
_HEADER_SPARSE_ENTRIES = 4
_SPARSE_EXTENDED_AT = 482
_GNU_SPARSE_FIELDS = slice(386, 495)
_PAX_RECORD_LENGTH = re.compile(rb"([0-9]{1,20}) ")
_PAX_SHORTEST_RECORD = 5
_NAME = slice(0, 100)
_SIZE = slice(124, 136)
_CHECKSUM = slice(148, 156)
_TYPE = slice(156, 157)
_MAGIC = slice(257, 265)
_PREFIX_START = 345
_PREFIX = slice(_PREFIX_START, 500)
_POSIX_MAGIC = b"ustar\x0000"
_GNU_MAGIC = b"ustar  \x00"
_BLANK_CHECKSUM = 8 * ord(" ")
_BASE256_POSITIVE = 0o200
_BASE256_NEGATIVE = 0o377
_AGREED_OCTAL = re.compile(rb" *[0-7]+[ \x00]*|\x00*")
_AGREED_CHECKSUM = re.compile(rb"[ 0-7\x00]*")
_SPARSE_FILE_STEP = re.compile(rb"GNUSparseFile\.[0-9]+")
_LINK_TYPES = frozenset({tarfile.SYMTYPE, tarfile.LNKTYPE})
_AGREED_BASE256_HIGH_BYTES = 4
_BYTE_SIGN = 0x80
_SIGNED_BYTES = struct.Struct("148b8x356b")


class TarSource(Protocol):
    """What the header walk reads a tar through: a file, or a decompressed stream."""

    def read(self, size: int = -1, /) -> bytes:
        """Read up to `size` bytes."""

    def seek(self, offset: int, whence: int = os.SEEK_SET, /) -> int:
        """Move to `offset`; the walk only ever moves forward."""


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


def _agreed_number(field: bytes) -> bool:
    """Whether every tar reader reads this numeric field as the same number.

    Readers differ on signs, separators, prefixes, a leading NUL, whitespace but a space,
    and base-256 values of 63 bits or more, so only octal digits padded with spaces or NULs,
    and a positive base-256 value under 2**63, are read alike.
    """
    if field[0] == _BASE256_POSITIVE:
        high = field[1:_AGREED_BASE256_HIGH_BYTES]
        return not any(high) and field[_AGREED_BASE256_HIGH_BYTES] < _BYTE_SIGN
    return _AGREED_OCTAL.fullmatch(field) is not None


def stored_sparse(entry: tarfile.TarInfo) -> bool:
    """Whether a tar reader may unpack `entry` from a sparse map, which readers apply apart.

    `tarfile`, GNU tar and bsdtar each read a map their own way and busybox reads none, so
    the bytes `tarfile` returns for such a member need not be the bytes unpacked.
    """
    return entry.type == tarfile.GNUTYPE_SPARSE or any(
        key.startswith(_SPARSE_KEY_PREFIX) and key != _SPARSE_NAME_KEY for key in entry.pax_headers
    )


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
    name: bytes
    """The name the header itself holds, its prefix joined."""
    named_as_directory: bool
    """An old-style file header whose name ends in a slash, which `tarfile` may read as a
    directory, whose data it does not skip."""
    slash_name: bool
    """A name field ending in a slash, which `tar` commands read as a directory's, without data."""
    disputed_prefix: bool
    """A prefix field `tarfile` joins in front of the name, which `tar` commands leave out
    under any magic but POSIX ustar's."""
    disputed: str | None
    """Why tar readers would read this header's size, checksum or layout differently."""


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
    prefix = block[_PREFIX].split(b"\x00", 1)[0]
    magic = block[_MAGIC]
    return _Header(
        kind,
        size,
        name=prefix + b"/" + name if prefix else name,
        named_as_directory=kind == tarfile.AREGTYPE and name.endswith(b"/"),
        slash_name=name.endswith(b"/"),
        disputed_prefix=block[_PREFIX_START] != 0 and magic != _POSIX_MAGIC,
        disputed=_disputed(block, kind, magic, checksum),
    )


def _disputed(block: bytes, kind: bytes, magic: bytes, checksum: int) -> str | None:
    """Why tar readers would read a header's size, checksum or layout differently, or None.

    `checksum` is the field as `tarfile` reads it; GNU tar reads past a leading NUL, and
    skips a block whose checksum it reads otherwise, unpacking from the next it can read.
    Only the GNU magic makes bsdtar read the old sparse fields, which it then reads for any
    type, while `tarfile` reads them for a sparse type alone; GNU tar and bsdtar walk a
    sparse member's extension blocks only under conditions `tarfile` does not check.
    """
    if not (
        _agreed_number(block[_SIZE])
        and _AGREED_CHECKSUM.fullmatch(block[_CHECKSUM])
        and gnu_checksum(block[_CHECKSUM]) == checksum
    ):
        return "whose size or checksum field tar readers read differently"
    sparse = kind == tarfile.GNUTYPE_SPARSE
    if sparse and magic != _GNU_MAGIC:
        return "of a sparse member without the GNU magic, which tar readers read differently"
    if sparse and block[_SPARSE_EXTENDED_AT]:
        return "of a sparse member with extension blocks, which tar readers walk differently"
    if not sparse and magic == _GNU_MAGIC and any(block[_GNU_SPARSE_FIELDS]):
        return "with GNU sparse fields on a member of another type, which some tar readers apply"
    return None


class _RefusedError(Exception):
    """The archive declares more than `tarfile` may be given to list, or what it cannot follow."""


def _malformed(what: str, start: int) -> _RefusedError:
    return _RefusedError(f"tar has a malformed {what} at byte {start}")


def _span(size: int) -> int:
    """Bytes a member of `size` occupies, as `tarfile` rounds it."""
    return -(-size // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE


@dataclass(frozen=True, slots=True)
class _PaxHeader:
    """What one PAX header holds that moves a member's data or costs `tarfile` memory."""

    kept: dict[bytes, bytes]
    """The size and sparse records, in the order `tarfile` keeps them, each its last value."""
    names: dict[bytes, bytes]
    """The records naming the member or its link target, each its last value."""
    keywords: frozenset[bytes]
    offsets: int
    """`GNU.sparse.offset` records, which `tarfile` reads from this header alone."""


def _pax_header(payload: bytes, start: int) -> _PaxHeader:
    """Read the records of a PAX header; refuse one `tarfile` cannot parse."""
    kept: dict[bytes, bytes] = {}
    names: dict[bytes, bytes] = {}
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
        if keyword in _NAME_KEYS:
            names[keyword] = value
        offsets += keyword == _SPARSE_OFFSET
        position += length
    return _PaxHeader(kept, names, frozenset(keywords), offsets)


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
    names: int = 0
    """Distinct names given to the member: GNU long names, PAX paths and sparse names."""
    link_names: int = 0
    """Link targets given to the member: GNU long links and PAX link paths."""
    pax_headers: int = 0
    slash_name: bool = False
    """Whether an extended header names the member with a trailing slash."""
    unread_by_busybox: bytes | None = None
    """A sparse name no PAX path repeats; busybox reads neither sparse records nor this name,
    and unpacks the member under its header's name."""


@dataclass(slots=True)
class _HeaderWalk:
    """The position and counts of a walk through a tar's headers."""

    handle: TarSource
    max_entries: int
    size: int | None
    """The archive's size: a header declared past it is no position `tarfile` can read.
    None for a stream whose size is known only at its end, where a read comes back short."""

    position: int = 0
    members: int = 0
    headers: int = 0
    sparse_entries: int = 0
    global_keywords: set[bytes] = field(default_factory=set)
    global_applied: int = 0
    """Global records in force, summed over the members and PAX headers read so far."""
    link_at: int | None = None
    sparse_directory_at: int | None = None
    """The first member busybox unpacks one directory below where the others do."""

    def _block(self, at: int) -> bytes:
        if self.size is not None and at > self.size:
            raise _RefusedError(f"tar reaches byte {at}, past its {self.size}-byte end")
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
            if header.disputed is not None:
                raise _RefusedError(f"tar has a header at byte {start} {header.disputed}")
            kind = header.kind
            if header.named_as_directory:
                if follow_up:
                    # After an extended header, some `tarfile` releases read this as a
                    # directory and others as a file whose data they skip.
                    raise _RefusedError(f"tar has an ambiguous header at byte {start}")
                kind = tarfile.DIRTYPE
            if kind not in _EXTENDED_TYPES:
                _require_one_name(header, start, chain)
                self._require_unpacked_alike(header, kind, start, chain)
                self._past_data(header, kind, start, chain)
                return True
            self._past_extended(header, kind, start, chain)
            follow_up = True

    def _require_unpacked_alike(
        self, header: _Header, kind: bytes, start: int, chain: _Chain
    ) -> None:
        """Refuse a sparse name busybox would unpack the member elsewhere than.

        busybox unpacks it under its header's name, which is accepted where it is the same,
        or where it is the name GNU tar and bsdtar give a sparse file, one `GNUSparseFile.<n>`
        directory below the file's own; and then only with no link that could lead that
        directory elsewhere.
        """
        if kind in _LINK_TYPES and self.link_at is None:
            self.link_at = start
        if chain.unread_by_busybox is not None:
            unpacked, listed = _steps(header.name), _steps(chain.unread_by_busybox)
            if unpacked != listed and not _sparse_file_steps(unpacked, listed):
                raise _RefusedError(
                    f"tar gives the member at byte {start} a sparse name busybox does not read, "
                    "so busybox unpacks it under the other name its header holds"
                )
            if unpacked != listed and self.sparse_directory_at is None:
                self.sparse_directory_at = start
        if self.link_at is not None and self.sparse_directory_at is not None:
            raise _RefusedError(
                f"tar holds a link at byte {self.link_at} and a sparse member at byte "
                f"{self.sparse_directory_at} that busybox unpacks into a directory of its own, "
                "which the link may lead elsewhere"
            )

    def _past_extended(self, header: _Header, kind: bytes, start: int, chain: _Chain) -> None:
        span = _span(header.size)
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
        if kind in (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            self.handle.seek(data_at)
            long_name = self.handle.read(header.size).split(b"\x00", 1)[0]
            _require_named({kind: long_name}, start)
            chain.names += kind == tarfile.GNUTYPE_LONGNAME
            chain.link_names += kind == tarfile.GNUTYPE_LONGLINK
            chain.slash_name |= kind == tarfile.GNUTYPE_LONGNAME and long_name.endswith(b"/")
        if kind == tarfile.XGLTYPE:
            self.handle.seek(data_at)
            pax = _pax_header(self.handle.read(span), start)
            if pax.names or any(_lays_out(keyword) for keyword in pax.keywords):
                raise _RefusedError(
                    f"tar has a global PAX header at byte {start} that names, sizes or lays out "
                    "the members after it, which tar readers apply differently"
                )
            self.global_keywords |= pax.keywords
        elif kind in _PAX_TYPES:
            self.handle.seek(data_at)
            pax = _pax_header(self.handle.read(span), start)
            _require_named(pax.names, start)
            if _PAX_PATH not in pax.names:
                chain.unread_by_busybox = pax.names.get(_SPARSE_NAME)
            chain.pax_headers += 1
            chain.names += len({pax.names.get(_PAX_PATH), pax.names.get(_SPARSE_NAME)} - {None})
            chain.link_names += _PAX_LINK_PATH in pax.names
            chain.slash_name |= any(
                name.endswith(b"/") for key, name in pax.names.items() if key != _PAX_LINK_PATH
            )
            self._apply_globals(start)
            if _PAX_SIZE in pax.kept:
                if not pax.kept[_PAX_SIZE].isdigit():
                    raise _RefusedError(
                        f"tar has a PAX header at byte {start} whose size record tar readers "
                        "read differently"
                    )
                chain.sized_headers += 1
                chain.sized = pax.kept if chain.sized is None else chain.sized
                chain.last_sized = True
            self._count_sparse(pax.kept, pax.offsets, chain, start)
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

    def _require_no_header_at_declared_end(
        self, declared: int, size: int, data_at: int, start: int
    ) -> None:
        """Refuse a PAX size a reader that keeps the header's own size would leave a header behind.

        busybox ignores a PAX `size` and reads its next header where the header's size ends,
        which for a size the header could not hold is the member's first data block.
        """
        if _span(declared) > _span(size):
            raise _RefusedError(
                f"tar gives the member at byte {start} a PAX size smaller than its header's, "
                "which tar readers skip differently"
            )
        at = data_at + _span(declared)
        if at == data_at + _span(size):
            return
        self.handle.seek(at)
        if _header(self.handle.read(tarfile.BLOCKSIZE)) is not None:
            raise _RefusedError(
                f"tar gives the member at byte {start} a PAX size some tar readers ignore, and "
                f"they read a header at byte {at}"
            )

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
            self._spend_sparse(_HEADER_SPARSE_ENTRIES, start)
        data_at = start + tarfile.BLOCKSIZE
        if chain.map_reads > 1:
            raise _RefusedError(f"tar has more than one sparse map for the member at byte {start}")
        if chain.map_reads:
            self._read_sparse_map(data_at, start)
        has_data = kind in tarfile.REGULAR_TYPES or kind not in tarfile.SUPPORTED_TYPES
        if not has_data and (header.size or chain.sized is not None):
            raise _RefusedError(
                f"tar gives the member at byte {start} a size although `tarfile` reads no data "
                "for its type, which other tar readers do"
            )
        size = header.size
        if chain.sized is not None:
            self._require_agreed_size(kind, start, chain)
            size = _pax_size(chain.sized[_PAX_SIZE])
            self._require_no_header_at_declared_end(header.size, size, data_at, start)
        if has_data and size and (header.slash_name or chain.slash_name):
            raise _RefusedError(
                f"tar names the member at byte {start} as a directory although it holds data, "
                "which tar readers skip differently"
            )
        self.position = data_at + (_span(size) if has_data else 0)
        self.members += 1
        if self.members > self.max_entries:
            raise _RefusedError(f"tar holds more than {self.max_entries} members")
        self._apply_globals(start)


def _steps(name: bytes) -> list[bytes]:
    """Return the steps of the path a `tar` command unpacks `name` to, past `.` and empty ones."""
    return [step for step in name.split(b"/") if step not in (b"", b".")]


def _sparse_file_steps(unpacked: list[bytes], listed: list[bytes]) -> bool:
    """Whether `unpacked` is the name GNU tar and bsdtar give the sparse file `listed`."""
    return (
        len(unpacked) > 1
        and _SPARSE_FILE_STEP.fullmatch(unpacked[-2]) is not None
        and unpacked[:-2] + unpacked[-1:] == listed
    )


def _lays_out(keyword: bytes) -> bool:
    """Whether a PAX record sets a member's size or sparse layout."""
    return keyword == _PAX_SIZE or keyword.startswith(_SPARSE_PREFIX)


def _require_named(names: dict[bytes, bytes], start: int) -> None:
    """Refuse an empty name or link target, or one holding a NUL, which tar readers end apart."""
    for name in names.values():
        if not name:
            raise _RefusedError(
                f"tar gives a member at byte {start} an empty name or link target, which tar "
                "readers read differently"
            )
        if b"\x00" in name:
            raise _RefusedError(
                f"tar gives a member at byte {start} a name or link target holding a NUL byte, "
                "which tar readers read differently"
            )


def _require_one_name(header: _Header, start: int, chain: _Chain) -> None:
    """Refuse a member whose headers give it a name tar readers would read differently."""
    if header.disputed_prefix:
        raise _RefusedError(
            f"tar has a header at byte {start} whose name prefix field tar readers read differently"
        )
    if chain.names > 1 or chain.link_names > 1 or chain.pax_headers > 1:
        raise _RefusedError(
            f"tar gives the member at byte {start} more than one name or extended header, "
            "which tar readers choose between differently"
        )


def _walk(handle: TarSource, max_entries: int, size: int | None) -> tuple[str | None, int]:
    """Walk every header; return why the archive is refused, and where the walk stopped."""
    walk = _HeaderWalk(handle, max_entries, size)
    try:
        while walk.member():
            pass
    except _RefusedError as refusal:
        return str(refusal), walk.position
    return None, walk.position


def stream_listing(handle: TarSource, *, max_entries: int) -> tuple[str | None, int]:
    """Walk a decompressed tar read forward from its start, as `listing_refusal` walks a file.

    Returns why `tarfile` must not list it, or None, and the offset of the block that ends
    the archive, where `tarfile` must stop listing too: a stream is read once, so a header
    `tarfile` stops at early is found by comparing where it stopped with this offset.
    """
    return _walk(handle, max_entries, None)


def listing_refusal(handle: TarSource, *, max_entries: int) -> str | None:
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
    return _walk(handle, max_entries, handle.seek(0, os.SEEK_END))[0]
