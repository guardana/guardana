"""How a tool that unpacks an archive reads a file, and where it writes each member.

A `tar` command takes a file for a codec or an archive format by its bytes, whatever it is
named. GNU tar and busybox decompress a file whose first bytes are a codec's signature unless
they are a tar header with `ustar` magic; `bsdtar` decompresses whatever passes a codec's check,
then reads the stream as the archive format whose check it passes best.

A tool resolves `.`, `..`, doubled and leading separators in a member's name, and a file system
may ignore case and Unicode normalization; so names are compared as so resolved, with a
backslash taken for a separator, ignoring case and Unicode normalization. A member listed at or
below the path of a link member is written where the link points, or over it, as the tool
decides, so where its bytes land is not where the listing places them.
"""

import re
import unicodedata
from collections.abc import Iterable

_LINK, _MEMBER = 0, 1

UNPACKING_PROBE_BYTES = 256 * 1024
"""Bytes read from the start of a stream to tell what a `tar` command takes it for.

`bsdtar` looks for a uuencoded file's `begin` line through about its first 128 KiB, and for an
ISO 9660 image's signature at byte 32769.
"""
TAR_OUTRANKS_ALL = 106
"""The `tar_bid` of a header no other archive format outranks: one with POSIX or GNU magic."""
TAR_OUTRANKS_ZIP = 33
"""The least `tar_bid` that outranks a zip `bsdtar` finds by its end record."""

_CODEC_SIGNATURES = (
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bz2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x1f\x9d", "compress"),
    (b"LZIP", "lzip"),
    (b"\xffLZMA", "lzma"),
    (b"\x5d\x00\x00", "lzma"),
    (b"\x89LZO", "lzop"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x02\x21\x4c\x18", "lz4"),
    (b"GRZipII\x00\x02\x04:)", "grzip"),
    (b"LRZI", "lrzip"),
    (b"\xed\xab\xee\xdb", "rpm"),
)
_ZSTD_SKIPPABLE = 0x184D2A50
_ZSTD_SKIPPABLE_MASK = 0xFFFFFFF0
_ZSTD_MAGIC_BYTES = 4
_LZMA_HEADER_END = 5
_LZMA_PROPERTIES_MAX = (4 * 5 + 4) * 9 + 8
_LZMA_DICTIONARIES = frozenset(1 << bits for bits in range(12, 28)) | frozenset(
    megabytes << 20 for megabytes in range(3, 64)
)
"""Dictionary sizes `bsdtar` takes a raw LZMA stream's header to declare."""
_TEXT_END = re.compile(rb"[\x00\x80-\xff]")
_UUENCODED_BEGIN = re.compile(rb"(?:\A|[\r\n])begin(?:-base64)? [0-7]{3} [^\r\n]*[\r\n]")

_ARCHIVE_SIGNATURES = (
    (b"070707", "cpio"),
    (b"070701", "cpio"),
    (b"070702", "cpio"),
    (b"070727", "cpio"),
    (b"\xc7\x71", "cpio"),
    (b"\x71\xc7", "cpio"),
    (b"!<arch>\n", "ar"),
    (b"!<thin>\n", "ar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"xar!", "xar"),
    (b"MSCF\x00\x00\x00\x00", "cab"),
    (b"WARC/", "warc"),
    (b"#mtree", "mtree"),
    (b"MZ", "self-extracting"),
    (b"\x7fELF", "self-extracting"),
)
"""`bsdtar` looks past an executable's head for the cab, LHA, RAR, 7z and zip data it may hold."""
_LHA_HEADER = re.compile(rb"\A..-l..-", re.DOTALL)
_ISO_SIGNATURE = b"CD001"
_ISO_SIGNATURE_AT = 32769

_TAR_BLOCK = 512
_TAR_END_BID = 10
_TAR_CHECKSUM_BID = 48
_TAR_TYPE_BID = 2
_TAR_MAGIC_BID = TAR_OUTRANKS_ALL - _TAR_CHECKSUM_BID - _TAR_TYPE_BID
_TAR_MAGICS = (b"ustar\x0000", b"ustar  \x00")
_TAR_MAGIC_SPAN = slice(257, 265)
_TAR_CHECKSUM_SPAN = slice(148, 156)
_TAR_TYPE_AT = 156
_TAR_NUMBER_SPANS = (
    slice(100, 108),
    slice(108, 116),
    slice(116, 124),
    slice(124, 136),
    slice(136, 148),
    slice(329, 337),
    slice(337, 345),
)
"""Mode, owner, group, size, time and device numbers, which `bsdtar` checks before it bids."""
_OCTAL = b"01234567"
_SIGNED_BYTE = 0x80


def codec_first(head: bytes) -> str | None:
    """Name the codec a `tar` command may decompress a stream starting with `head` with, or None.

    `bsdtar` also decodes a uuencoded file, whose `begin` line it finds after any number of
    lines of text, and takes a raw LZMA stream by the dictionary size its header declares.
    """
    codec = _signed(head, _CODEC_SIGNATURES)
    if codec is not None:
        return codec
    if int.from_bytes(head[:_ZSTD_MAGIC_BYTES], "little") & _ZSTD_SKIPPABLE_MASK == _ZSTD_SKIPPABLE:
        return "zstd"
    if (
        len(head) >= _LZMA_HEADER_END
        and head[0] <= _LZMA_PROPERTIES_MAX
        and int.from_bytes(head[1:_LZMA_HEADER_END], "little") in _LZMA_DICTIONARIES
    ):
        return "lzma"
    text_end = _TEXT_END.search(head)
    text = head if text_end is None else head[: text_end.start()]
    return "uuencode" if _UUENCODED_BEGIN.search(text) else None


def archive_first(head: bytes) -> str | None:
    """Name an archive format other than tar and zip that `bsdtar` may read `head` as, or None."""
    found = _signed(head, _ARCHIVE_SIGNATURES)
    if found is not None:
        return found
    if _LHA_HEADER.match(head):
        return "lha"
    if head[_ISO_SIGNATURE_AT : _ISO_SIGNATURE_AT + len(_ISO_SIGNATURE)] == _ISO_SIGNATURE:
        return "iso9660"
    return None


def tar_bid(head: bytes) -> int:
    """Return how strongly `bsdtar` takes a stream whose first block is `head` for a tar.

    It reads a stream as the archive format whose check it passes best. A tar header with a
    valid checksum, a type that is NUL, a digit or a letter, and numbers written in octal or
    base-256 bids `TAR_OUTRANKS_ALL` with POSIX or GNU magic; without, it outranks only a zip
    found by its end record. An end-of-archive block outranks nothing, and anything else is 0.
    """
    block = head[:_TAR_BLOCK]
    if len(block) < _TAR_BLOCK:
        return 0
    if not any(block):
        return _TAR_END_BID
    if not _checksum_matches(block) or not _type_passes(block[_TAR_TYPE_AT]):
        return 0
    if not all(_number_passes(block[span]) for span in _TAR_NUMBER_SPANS):
        return 0
    magic = _TAR_MAGIC_BID if block[_TAR_MAGIC_SPAN] in _TAR_MAGICS else 0
    return _TAR_CHECKSUM_BID + _TAR_TYPE_BID + magic


def _signed(head: bytes, signatures: tuple[tuple[bytes, str], ...]) -> str | None:
    return next((name for signature, name in signatures if head.startswith(signature)), None)


def _checksum_matches(block: bytes) -> bool:
    field = block[_TAR_CHECKSUM_SPAN]
    if field.translate(None, b" \x00" + _OCTAL):
        return False
    digits = field.lstrip(b" ")
    run = len(digits) - len(digits.lstrip(_OCTAL))
    declared = int(digits[:run], 8) if run else 0
    summed = block[: _TAR_CHECKSUM_SPAN.start] + b" " * 8 + block[_TAR_CHECKSUM_SPAN.stop :]
    unsigned = sum(summed)
    signed = unsigned - 256 * sum(byte >= _SIGNED_BYTE for byte in summed)
    return declared in (unsigned, signed)


def _type_passes(flag: int) -> bool:
    return flag == 0 or bytes([flag]).isalnum()


def _number_passes(field: bytes) -> bool:
    if field[0] in (0x00, 0x80, 0xFF):
        return True
    return not field.lstrip(b" ").lstrip(_OCTAL).translate(None, b" \x00")


def member_through_link(members: Iterable[tuple[Iterable[str], bool]]) -> tuple[str, str] | None:
    """Return a member listed at or below a link member's path, and that link; None if none is.

    `members` holds, for each archive member, every name a reader may give it and whether it
    is a link. Sorted, a path comes right before every path below it, and a link before a
    member of the same path, so one pass finds the links each path lies at or below.
    """
    entries: list[tuple[str, int, int, str]] = []
    for index, (names, is_link) in enumerate(members):
        kind = _LINK if is_link else _MEMBER
        for path, name in {folded_path(steps(name)): name for name in names}.items():
            entries.append((path, kind, index, name))
    entries.sort()
    links: list[tuple[str, int, str]] = []
    for path, kind, index, name in entries:
        while links and not path.startswith(links[-1][0]):
            links.pop()
        for _path, link_index, link in links:
            if link_index != index:
                return name, link
        if kind == _LINK:
            links.append((path, index, name))
    return None


def steps(name: str) -> list[str]:
    """Return the directories and file `name` leads to, resolving `.`, `..` and empty steps."""
    resolved: list[str] = []
    for step in name.replace("\\", "/").split("/"):
        if step == "..":
            if resolved:
                resolved.pop()
        elif step not in ("", "."):
            resolved.append(step)
    return resolved


def folded_path(path: list[str]) -> str:
    """Join the folded steps of `path`, each followed by `/`.

    A directory's path then starts the path of everything below it, and of nothing else.
    """
    return "".join(f"{folded(step)}/" for step in path)


def folded(text: str) -> str:
    """Fold `text` for a comparison that ignores case and Unicode normalization."""
    return unicodedata.normalize("NFD", text).casefold()
