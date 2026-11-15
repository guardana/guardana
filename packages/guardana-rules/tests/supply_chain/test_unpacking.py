"""What a `tar` command takes a file for, and where a tool unpacking an archive writes a member.

A `tar` command goes by a file's bytes: a codec's signature, another archive format's, or a tar
header strong enough to outrank them; GNU tar reads past blocks it cannot read as a header. A
tool unpacking an archive writes a member listed at or
below a link member where the link leads, or over it; names are compared past `.`, `..`, empty
steps and backslashes, ignoring case and Unicode normalization.
"""

import binascii
import io
import tarfile
import zipfile
from typing import Literal

import pytest
from guardana.rules.supply_chain._unpacking import (
    TAR_OUTRANKS_ALL,
    TAR_OUTRANKS_ZIP,
    archive_first,
    codec_first,
    gnu_checksum,
    gnu_header_offset,
    gnu_reads_as_tar,
    gnu_reads_header,
    member_through_link,
    tar_bid,
)

_Members = list[tuple[tuple[str, ...], bool]]


@pytest.mark.parametrize(
    ("members", "found"),
    [
        ([(("s",), True), (("s/model.pkl",), False)], ("s/model.pkl", "s")),
        ([(("notes.txt",), True), (("notes.txt",), False)], ("notes.txt", "notes.txt")),
        ([(("s/x",), False), (("s",), True)], ("s/x", "s")),
        ([(("S",), True), (("s/x",), False)], ("s/x", "S")),
        ([(("é",), True), (("é/x",), False)], ("é/x", "é")),
        ([(("s",), True), (("x/../s/m",), False)], ("x/../s/m", "s")),
        ([(("s",), True), (("s\\m",), False)], ("s\\m", "s")),
        ([(("./s/",), True), (("s//m",), False)], ("s//m", "./s/")),
        ([(("a",), True), (("a/b",), True)], ("a/b", "a")),
        ([(("s",), True), (("readme.txt", "s/m"), False)], ("s/m", "s")),
    ],
    ids=[
        "below",
        "over-a-same-named-link",
        "listed-before-the-link",
        "case",
        "unicode-normalization",
        "dot-dot",
        "backslash",
        "dot-and-empty-steps",
        "a-link-below-a-link",
        "one-of-several-names",
    ],
)
def test_a_member_at_or_below_a_link_is_found(
    members: _Members, found: tuple[str, str] | None
) -> None:
    assert member_through_link(members) == found


@pytest.mark.parametrize(
    "members",
    [
        [(("ab",), True), (("abc/x",), False)],
        [(("a",), False), (("a/b",), False)],
        [(("s", "s/x"), True)],
        [(("s", "s/x"), True), (("t",), False)],
        [(("docs/latest",), True), (("v1/readme.txt",), False), (("docs/index.txt",), False)],
    ],
    ids=[
        "a-longer-name",
        "no-link",
        "a-link-under-its-own-names",
        "a-member-after-a-link-under-its-own-names",
        "links-beside-members",
    ],
)
def test_members_beside_links_are_not_found(members: _Members) -> None:
    assert member_through_link(members) is None


def _header(name: str = "dir/file.txt", form: Literal[0, 1, 2] = tarfile.PAX_FORMAT) -> bytes:
    info = tarfile.TarInfo(name)
    info.size = 3
    return info.tobuf(form)[: tarfile.BLOCKSIZE]


def _rechecked(block: bytearray) -> bytes:
    block[148:156] = b" " * 8
    block[148:156] = b"%06o\x00 " % sum(block)
    return bytes(block)


def _v7(header: bytes) -> bytes:
    block = bytearray(header)
    block[257:265] = bytes(8)
    return _rechecked(block)


def _uuencoded(data: bytes) -> bytes:
    lines = [binascii.b2a_uu(data[i : i + 45]) for i in range(0, len(data), 45)]
    return b"begin 644 inner.tar\n" + b"".join(lines) + b"`\nend\n"


def _zip_head() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", b"hello\n")
    return buffer.getvalue()


_TEXT_LINES = b"plain text, one line of it\n" * (100 * 1024 // 27)


@pytest.mark.parametrize(
    ("head", "codec"),
    [
        (b"\x1f\x8b\x08\x00", "gzip"),
        (b"BZh91AY&SY", "bz2"),
        (b"\xfd7zXZ\x00\x00", "xz"),
        (b"\x1f\x9d\x90", "compress"),
        (b"LZIP\x01\x0c", "lzip"),
        (b"\xffLZMA\x00", "lzma"),
        (b"\x5d\x00\x00\x07\x00", "lzma"),
        (b"\x89LZO\x00\r\n\x1a\n", "lzop"),
        (b"\x28\xb5\x2f\xfd", "zstd"),
        (b"\x50\x2a\x4d\x18\x00\x00", "zstd"),
        (b"\x5f\x2a\x4d\x18\x00\x00", "zstd"),
        (b"\x04\x22\x4d\x18", "lz4"),
        (b"\x02\x21\x4c\x18", "lz4"),
        (b"GRZipII\x00\x02\x04:)", "grzip"),
        (b"LRZI\x00\x06", "lrzip"),
        (b"\xed\xab\xee\xdb\x03\x00", "rpm"),
        (b"\x00\x00\x10\x00\x00", "lzma"),
        (b"\xe0\x00\x00\x00\x08", "lzma"),
        (b"\x5e\x00\x00\x30\x00", "lzma"),
        (_uuencoded(b"data"), "uuencode"),
        (_TEXT_LINES + _uuencoded(b"data"), "uuencode"),
        (b"notes\r" + _uuencoded(b"data"), "uuencode"),
        (b"begin-base64 644 inner.tar\nZGF0YQ==\n====\n", "uuencode"),
    ],
    ids=[
        "gzip",
        "bzip2",
        "xz",
        "compress",
        "lzip",
        "lzma-utils",
        "lzma-as-gnu-tar-matches",
        "lzop",
        "zstd",
        "zstd-skippable-frame",
        "zstd-last-skippable-frame",
        "lz4",
        "lz4-legacy",
        "grzip",
        "lrzip",
        "rpm",
        "lzma-by-its-smallest-dictionary",
        "lzma-with-the-largest-properties",
        "lzma-by-a-dictionary-in-mebibytes",
        "uuencoded",
        "uuencoded-after-lines-of-text",
        "uuencoded-after-a-carriage-return",
        "base64",
    ],
)
def test_a_codec_a_tar_command_decompresses_is_named(head: bytes, codec: str) -> None:
    assert codec_first(head) == codec


@pytest.mark.parametrize(
    "head",
    [
        _header(),
        _header("a"),
        _header(form=tarfile.GNU_FORMAT),
        _zip_head(),
        b"\xe1\x00\x00\x10\x00\x00",
        b"\x5d\x00\x10\x00",
        b"\x5d\x01\x00\x10\x00\x00",
        b"\x4f\x2a\x4d\x18\x00\x00",
        b"\x2a\x4d",
        b"x\x00\n" + _uuencoded(b"data"),
        b"x\x80\n" + _uuencoded(b"data"),
        b"begin here.txt\n",
        b"begin 644 inner.tar",
        b"text\nbegin 64 inner.tar\n",
    ],
    ids=[
        "a-tar-header",
        "a-tar-header-of-a-one-letter-name",
        "a-gnu-tar-header",
        "a-zip",
        "lzma-properties-past-the-largest",
        "lzma-cut-before-its-dictionary",
        "lzma-with-a-dictionary-bsdtar-does-not-take",
        "a-frame-short-of-zstd-skippable",
        "two-bytes",
        "a-begin-line-after-a-nul",
        "a-begin-line-after-a-byte-past-ascii",
        "a-begin-line-without-a-mode",
        "a-begin-line-that-does-not-end",
        "a-begin-line-with-a-short-mode",
    ],
)
def test_bytes_no_tar_command_decompresses_name_no_codec(head: bytes) -> None:
    assert codec_first(head) is None


def _iso_at_its_offset() -> bytes:
    head = bytearray(40 * 1024)
    head[32769:32774] = b"CD001"
    return bytes(head)


@pytest.mark.parametrize(
    ("head", "found"),
    [
        (b"070707000000", "cpio"),
        (b"070701000000", "cpio"),
        (b"070702000000", "cpio"),
        (b"070727000000", "cpio"),
        (b"\xc7\x71\x00\x00", "cpio"),
        (b"\x71\xc7\x00\x00", "cpio"),
        (b"!<arch>\nfile", "ar"),
        (b"!<thin>\nfile", "ar"),
        (b"7z\xbc\xaf\x27\x1c\x00\x04", "7z"),
        (b"Rar!\x1a\x07\x00", "rar"),
        (b"Rar!\x1a\x07\x01\x00", "rar"),
        (b"xar!\x00\x1c\x00\x01", "xar"),
        (b"MSCF\x00\x00\x00\x00", "cab"),
        (b"WARC/1.0\r\n", "warc"),
        (b"#mtree\n", "mtree"),
        (b"MZ\x90\x00", "self-extracting"),
        (b"\x7fELF\x02\x01", "self-extracting"),
        (b"\x24\x00-lh5-\x10\x00", "lha"),
        (b"\x24\x00-lzs-\x10\x00", "lha"),
        (_iso_at_its_offset(), "iso9660"),
    ],
    ids=[
        "cpio-odc",
        "cpio-newc",
        "cpio-crc",
        "cpio-afio",
        "cpio-binary",
        "cpio-binary-big-endian",
        "ar",
        "ar-thin",
        "7z",
        "rar",
        "rar5",
        "xar",
        "cab",
        "warc",
        "mtree",
        "windows-executable",
        "elf-executable",
        "lha",
        "lha-larc",
        "iso9660",
    ],
)
def test_another_archive_format_bsdtar_reads_is_named(head: bytes, found: str) -> None:
    assert archive_first(head) == found


@pytest.mark.parametrize(
    "head",
    [_header(), _zip_head(), b"", b"07070", b"\x24\x00-lh5\x10\x00", bytes(32774)],
    ids=["a-tar-header", "a-zip", "nothing", "cut-short", "lha-without-its-closing-dash", "zeros"],
)
def test_bytes_of_no_other_format_name_none(head: bytes) -> None:
    assert archive_first(head) is None


def _with(header: bytes, start: int, value: bytes) -> bytes:
    block = bytearray(header)
    block[start : start + len(value)] = value
    return _rechecked(block)


def _checksum_written(header: bytes, spelled: bytes) -> bytes:
    """A header whose checksum field is `spelled`, formatted with the header's own sum."""
    block = bytearray(header)
    block[148:156] = b" " * 8
    block[148:156] = spelled % sum(block)
    return bytes(block)


def _signed_checksum(header: bytes) -> bytes:
    """A header whose checksum sums its bytes as signed, as some old `tar` programs did."""
    block = bytearray(header)
    block[0] = 0xE9
    block[148:156] = b" " * 8
    signed = sum(byte - 256 if byte > 0x7F else byte for byte in block)
    block[148:156] = b"%06o\x00 " % signed
    return bytes(block)


@pytest.mark.parametrize(
    ("head", "bid"),
    [
        (_header(), TAR_OUTRANKS_ALL),
        (_header(form=tarfile.USTAR_FORMAT), TAR_OUTRANKS_ALL),
        (_header(form=tarfile.GNU_FORMAT), TAR_OUTRANKS_ALL),
        (_with(_header(), 124, b"\x80" + bytes(10) + b"\x03"), TAR_OUTRANKS_ALL),
        (_with(_header(), 100, b"   644 \x00"), TAR_OUTRANKS_ALL),
        (_with(_header(), 329, bytes(16)), TAR_OUTRANKS_ALL),
        (_signed_checksum(_header()), TAR_OUTRANKS_ALL),
        (_checksum_written(_header(), b" %06o\x00"), TAR_OUTRANKS_ALL),
        (_with(_header(), 156, b"\x00"), TAR_OUTRANKS_ALL),
        (_with(_header(), 156, b"L"), TAR_OUTRANKS_ALL),
        (_with(_header(), 100, b"\x00junk\x00\x00\x00"), TAR_OUTRANKS_ALL),
        (_with(_header(), 136, b"\xff" * 12), TAR_OUTRANKS_ALL),
        (_v7(_header()), 50),
        (_with(_header(), 257, b"ustar\x00  "), 50),
        (bytes(tarfile.BLOCKSIZE), 10),
        (_header()[:-1], 0),
        (_with(_header(), 156, b"!"), 0),
        (_with(_header(), 100, b"0_000644"), 0),
        (_with(_header(), 136, b"1234567890\t\x00"), 0),
        (_with(_header(), 337, b"0000000x"), 0),
        (_header()[:148] + b"0000001\x00" + _header()[156:], 0),
        (_header()[:148] + b"+012345\x00" + _header()[156:], 0),
        (_checksum_written(_header(), b"%06ox\x00"), 0),
    ],
    ids=[
        "pax",
        "ustar",
        "gnu",
        "a-base-256-size",
        "a-mode-after-spaces",
        "device-numbers-of-nuls",
        "a-signed-checksum",
        "a-checksum-after-a-space",
        "a-type-of-nul",
        "a-type-of-a-letter",
        "a-mode-starting-with-a-nul",
        "a-negative-base-256-time",
        "v7",
        "ustar-magic-with-another-version",
        "an-end-of-archive-block",
        "short-of-a-block",
        "a-type-of-punctuation",
        "a-mode-with-an-underscore",
        "a-time-ending-in-a-tab",
        "a-device-number-with-a-letter",
        "a-checksum-that-does-not-match",
        "a-checksum-with-a-sign",
        "a-checksum-with-a-letter-after-its-digits",
    ],
)
def test_the_tar_bid_follows_the_header(head: bytes, bid: int) -> None:
    assert tar_bid(head) == bid


def test_a_v7_header_outranks_a_zip_and_an_end_block_does_not() -> None:
    assert tar_bid(_v7(_header())) >= TAR_OUTRANKS_ZIP > tar_bid(bytes(tarfile.BLOCKSIZE))


@pytest.mark.parametrize(
    ("field", "read"),
    [
        (b"012345\x00 ", 0o12345),
        (b" 12345\x00 ", 0o12345),
        (b"\t\n12345 ", 0o12345),
        (b"12 34   ", 0o12),
        (bytes(8), 0),
        (b"\x00\x00123456", 0),
        (b"\x00123456 ", 0o123456),
        (b"\x00 123456", 0o123456),
        (b" " * 8, None),
        (b"\x00" + b" " * 7, None),
        (b"12x45   ", None),
        (b"+12345\x00 ", None),
        (b"\x80" + bytes(7), None),
    ],
    ids=[
        "as-tar-writes-it",
        "after-a-space",
        "after-other-blanks",
        "up-to-a-blank",
        "nuls",
        "past-one-nul-only",
        "past-a-leading-nul",
        "past-a-leading-nul-and-blanks",
        "blanks",
        "a-nul-then-blanks",
        "a-letter-after-digits",
        "a-sign",
        "base-256",
    ],
)
def test_gnu_tar_reads_a_checksum_field_its_own_way(field: bytes, read: int | None) -> None:
    assert gnu_checksum(field) == read


def _gnu_only(header: bytes) -> bytes:
    """`header` with a checksum GNU tar reads past a leading NUL and `tarfile` reads as 0."""
    return _checksum_written(header, b"\x00%06o ")


def test_a_checksum_past_a_leading_nul_is_read_by_gnu_tar_alone() -> None:
    block = _gnu_only(_header())

    with pytest.raises(tarfile.HeaderError):
        tarfile.TarInfo.frombuf(block, "utf-8", "surrogateescape")
    assert tar_bid(block) == 0
    assert gnu_reads_header(block)


@pytest.mark.parametrize(
    ("block", "read"),
    [
        (_header(), True),
        (_v7(_header()), True),
        (_signed_checksum(_header()), True),
        (_gnu_only(_header()), True),
        (_gnu_only(_with(_header(), 124, b"\x80" + bytes(10) + b"\x03")), True),
        (_with(_with(_header(), 124, b"12x" + bytes(9)), 156, b"1"), True),
        (bytes(tarfile.BLOCKSIZE), False),
        (_header()[:148] + b"0000001\x00" + _header()[156:], False),
        (_with(_header(), 124, b"12x" + bytes(9)), False),
        (_with(_header(), 124, b" " * 12), False),
    ],
    ids=[
        "pax",
        "v7",
        "a-signed-checksum",
        "a-checksum-past-a-leading-nul",
        "a-base-256-size",
        "a-hard-link-whose-size-goes-unread",
        "a-block-of-zeros",
        "a-checksum-that-does-not-match",
        "a-size-gnu-tar-cannot-read",
        "a-size-of-blanks",
    ],
)
def test_gnu_tar_reads_a_header_by_its_checksum_and_size(block: bytes, read: bool) -> None:
    assert gnu_reads_header(block) is read


_GZIP_START = b"\x1f\x8b\x08\x04" + bytes(4) + b"\x00\xff\xa0\x0f"
"""A gzip header whose extra field runs on for 4,000 bytes."""
_GZIP_AND_USTAR = _with(_header(form=tarfile.USTAR_FORMAT), 0, _GZIP_START)


@pytest.mark.parametrize(
    ("head", "read"),
    [
        (_header(form=tarfile.USTAR_FORMAT), True),
        (_header(form=tarfile.GNU_FORMAT), True),
        (_with(_header(form=tarfile.USTAR_FORMAT), 263, b"XX"), True),
        (_GZIP_AND_USTAR, True),
        (_gnu_only(_GZIP_AND_USTAR), True),
        (_GZIP_AND_USTAR[:148] + b"0000001\x00" + _GZIP_AND_USTAR[156:], False),
        (_GZIP_START.ljust(tarfile.BLOCKSIZE, b"\x00"), False),
        (_v7(_header()), False),
        (_GZIP_AND_USTAR[: tarfile.BLOCKSIZE - 1], False),
    ],
    ids=[
        "posix-magic",
        "old-gnu-magic",
        "a-version-gnu-tar-does-not-check",
        "gzip-data-that-is-also-a-tar-header",
        "the-same-with-a-checksum-only-gnu-tar-reads",
        "a-checksum-that-does-not-match",
        "gzip-data",
        "a-v7-header-without-magic",
        "less-than-a-block",
    ],
)
def test_gnu_tar_reads_a_file_as_a_plain_tar_by_its_first_block(head: bytes, read: bool) -> None:
    """GNU tar looks for a tar before it looks for compressed data."""
    assert gnu_reads_as_tar(head) is read


class _Trickle(io.BytesIO):
    """A stream that hands back at most 700 bytes a read."""

    def read(self, size: int | None = -1, /) -> bytes:
        return super().read(700 if size is None or size < 0 else min(700, size))


_JUNK = b"J" * tarfile.BLOCKSIZE


@pytest.mark.parametrize(
    ("content", "offset"),
    [
        (_header(), 0),
        (3 * _JUNK + _header(), 3 * tarfile.BLOCKSIZE),
        (_JUNK * 4096 + _header(), 4096 * tarfile.BLOCKSIZE),
        (3 * _JUNK + bytes(tarfile.BLOCKSIZE) + _header(), None),
        (3 * _JUNK + _header()[:300], None),
        (_JUNK + b"J" * 100 + _header(), None),
        (8 * _JUNK, None),
        (b"", None),
    ],
    ids=[
        "at-the-start",
        "past-blocks-it-cannot-read",
        "past-the-first-read",
        "past-a-block-of-zeros",
        "cut-short-by-the-end",
        "off-a-block-boundary",
        "none",
        "empty",
    ],
)
def test_gnu_tar_finds_the_first_header_it_reads(content: bytes, offset: int | None) -> None:
    assert gnu_header_offset(io.BytesIO(content)) == offset
    assert gnu_header_offset(_Trickle(content)) == offset
