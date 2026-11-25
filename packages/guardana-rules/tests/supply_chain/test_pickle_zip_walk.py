"""A zip a person unpacks is checked as a tool that walks its local headers reads it.

`bsdtar` reading a pipe, and other streaming readers, take each member's name, type and
sizes from its local header, end its data where a data descriptor's CRC-32 matches or where
its compressed stream ends, and then look ahead for the next local header signature. A zip
such a tool would unpack otherwise than its central directory lists is unscanned. Every
archive here is built in code; nothing is unpickled.
"""

import bz2
import io
import lzma
import stat
import struct
import tempfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

import pytest
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import _zip, pickle_opcode
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_SYSTEM = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R."
_CLEAN = b"\x80\x02K\x00."
_TEXT = b"hello world\n" * 20
_WALKED = "so a tool that unpacks it by walking it may unpack members otherwise than listed"
_DESCRIBED = 0x08
_ZSTD = 93
_UNSET = 0xFFFFFFFF


@dataclass(frozen=True)
class _Member:
    """One zip member, written as its local entry and its directory entry say."""

    name: bytes
    data: bytes
    content: bytes | None = None
    """What the data unpacks to; the data itself when it is stored."""

    method: int = 0
    flags: int = 0
    declared: tuple[int, int] | None = None
    """The compressed size and size the directory entry declares; the real ones by default."""

    local_sizes: tuple[int, int] | None = None
    """The sizes the local header holds; 0 with a data descriptor, else the declared ones."""

    local_name: bytes | None = None
    local_extra: bytes = b""
    central_extra: bytes = b""
    trailer: bytes | None = None
    """The bytes after the data; a data descriptor by default when the flags call for one."""

    attributes: int = (stat.S_IFREG | 0o644) << 16
    offset: int | None = None
    """A local header another member wrote, which this directory entry points to instead."""


def _walked_zip(*members: _Member, before: bytes = b"", after: bytes = b"") -> bytes:
    body, directory = bytearray(before), bytearray()
    for member in members:
        content = member.data if member.content is None else member.content
        crc = zlib.crc32(content)
        declared = member.declared or (len(member.data), len(content))
        offset = len(body) if member.offset is None else member.offset
        if member.offset is None:
            described = member.flags & _DESCRIBED
            local_sizes = member.local_sizes or ((0, 0) if described else declared)
            name = member.name if member.local_name is None else member.local_name
            body += struct.pack(
                "<4s5H3L2H",
                b"PK\x03\x04",
                20,
                member.flags,
                member.method,
                0,
                0x21,
                0 if described else crc,
                *local_sizes,
                len(name),
                len(member.local_extra),
            )
            body += name + member.local_extra + member.data
            descriptor = struct.pack("<4s3L", b"PK\x07\x08", crc, *declared) if described else b""
            body += descriptor if member.trailer is None else member.trailer
        directory += struct.pack(
            "<4s6H3L5H2L",
            b"PK\x01\x02",
            0x0314,
            20,
            member.flags,
            member.method,
            0,
            0x21,
            crc,
            *declared,
            len(member.name),
            len(member.central_extra),
            0,
            0,
            0,
            member.attributes,
            offset,
        )
        directory += member.name + member.central_extra
    body += after
    count = len(members)
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, count, count, len(directory), len(body), 0)
    return bytes(body + directory + end)


def _local_entry(name: bytes, data: bytes) -> bytes:
    """A whole local entry, header and stored data, that no directory entry lists."""
    content = _walked_zip(_Member(name, data))
    return content[: content.index(b"PK\x01\x02")]


def _deflated(data: bytes, level: int = 9) -> bytes:
    packer = zlib.compressobj(level, zlib.DEFLATED, -zlib.MAX_WBITS)
    return packer.compress(data) + packer.flush()


def _bzipped(data: bytes) -> bytes:
    return bz2.compress(data)


_LZMA_FILTER = {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}
_LZMA_PROPERTIES = struct.pack("<BL", (2 * 5 + 0) * 9 + 3, 1 << 16)


def _lzma_zipped(data: bytes, *, header: bytes | None = None, cut: int = 0) -> bytes:
    """Zip's LZMA format: a version, the properties' size and the properties, then raw LZMA1.

    `cut` drops that many bytes from the end of the raw stream, its end marker among them.
    """
    packer = lzma.LZMACompressor(lzma.FORMAT_RAW, filters=[_LZMA_FILTER])
    raw = packer.compress(data) + packer.flush()
    if header is None:
        header = struct.pack("<2BH", 9, 4, len(_LZMA_PROPERTIES)) + _LZMA_PROPERTIES
    return header + raw[: len(raw) - cut]


def _descriptor(data: bytes) -> bytes:
    return struct.pack("<4s3L", b"PK\x07\x08", zlib.crc32(data), len(data), len(data))


def _wide_descriptor(data: bytes) -> bytes:
    """A data descriptor with 8-byte sizes, which ends a member with a local ZIP64 field."""
    return struct.pack("<4sLQQ", b"PK\x07\x08", zlib.crc32(data), len(data), len(data))


def _field(kind: int, data: bytes) -> bytes:
    return struct.pack("<HH", kind, len(data)) + data


def _unicode_path(stored: bytes, name: bytes) -> bytes:
    return _field(0x7075, struct.pack("<BL", 1, zlib.crc32(stored)) + name)


def _attributes(bitmap: int, *values: bytes) -> bytes:
    """A libarchive `xl` field: a bitmap, then the fields it names."""
    return _field(0x6C78, bytes([bitmap]) + b"".join(values))


_HIDDEN = _local_entry(b"model.pkl", _SYSTEM)
_UNMATCHED = b"PK\x07\x08\x01\x00\x00\x00"
"""A data descriptor signature and a CRC-32 the data before it does not have."""

_LINK_ATTRIBUTES = struct.pack("<L", (stat.S_IFLNK | 0o777) << 16)
_REGULAR_ATTRIBUTES = struct.pack("<L", (stat.S_IFREG | 0o644) << 16)
_MADE_ON_UNIX = struct.pack("<H", 0x0314)


def _summaries(tmp_path: Path, name: str, content: bytes) -> tuple[list[str], RuleContext, Path]:
    """Scan `content` alone, named `name`, in a directory of its own."""
    path = Path(tempfile.mkdtemp(dir=tmp_path)) / name
    path.write_bytes(content)
    ctx = RuleContext()
    findings = PickleOpcodeRule().run(ArtifactTarget(path.parent), ctx)
    return [f.evidence.summary for f in findings], ctx, path


def _walk_refusals(tmp_path: Path, name: str, content: bytes) -> list[str]:
    summaries, ctx, path = _summaries(tmp_path, name, content)
    refusals = [summary for summary in summaries if _WALKED in summary]
    if refusals:
        assert str(path) in ctx.examined_paths()
    return refusals


_UNPACKED_OTHERWISE = [
    (_walked_zip(_Member(b"readme.txt", _TEXT), before=_HIDDEN), "local header at byte 0"),
    (
        _walked_zip(_Member(b"a.txt", _TEXT, trailer=_HIDDEN), _Member(b"b.txt", _TEXT)),
        "that its central directory does not list",
    ),
    (_walked_zip(_Member(b"readme.txt", _TEXT), after=_HIDDEN), "does not list"),
    (
        _walked_zip(
            _Member(b"a.txt", _TEXT + _HIDDEN),
            _Member(b"model.pkl", _SYSTEM, offset=30 + len(b"a.txt") + len(_TEXT)),
        ),
        "overlaps the member before it",
    ),
    (
        _walked_zip(_Member(b"readme.txt", b"", offset=2), before=bytes(40)),
        "has no local header where its directory entry points",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT, declared=(4000, 4000))),
        "runs into its central directory",
    ),
    (
        _walked_zip(_Member(b"notes.txt", _SYSTEM, local_name=b"model.pkl")),
        "name, flags or method differ",
    ),
    (
        _walked_zip(
            _Member(b"notes.txt", _SYSTEM, local_extra=_unicode_path(b"notes.txt", b"model.pkl"))
        ),
        "Unicode path differs",
    ),
    (
        _walked_zip(
            _Member(b"s", b"/etc", local_extra=_attributes(0x05, _MADE_ON_UNIX, _LINK_ATTRIBUTES))
        ),
        "file attributes differ",
    ),
    (
        _walked_zip(_Member(b"s", b"/etc", local_extra=_attributes(0x04, _REGULAR_ATTRIBUTES))),
        "file attributes differ",
    ),
    (
        _walked_zip(
            _Member(
                b"s",
                b"/etc",
                local_extra=_attributes(0x07, _MADE_ON_UNIX, b"\x00\x00", _LINK_ATTRIBUTES),
            )
        ),
        "file attributes differ",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _TEXT,
                local_sizes=(_UNSET, len(_TEXT)),
                local_extra=_field(1, struct.pack("<QQ", len(_TEXT), len(_TEXT))),
            )
        ),
        "ZIP64 sizes zip readers take differently",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT, local_sizes=(_UNSET, _UNSET))),
        "ZIP64 sizes zip readers take differently",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _TEXT,
                local_sizes=(_UNSET, _UNSET),
                local_extra=_field(1, struct.pack("<QQ", len(_TEXT), 2)),
            )
        ),
        "sizes differ from its directory entry",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT, flags=_DESCRIBED, local_sizes=(2, 0))),
        "sizes differ from its directory entry",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT, flags=_DESCRIBED, local_sizes=(0, 2))),
        "sizes differ from its directory entry",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT + _descriptor(_TEXT) + _HIDDEN, flags=_DESCRIBED)),
        "a streaming reader ends at byte",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _TEXT,
                flags=_DESCRIBED,
                trailer=struct.pack("<4s3L", b"PK\x07\x08", 0, len(_TEXT), len(_TEXT)),
            ),
            _Member(b"notes.txt", _TEXT),
        ),
        "so a streaming reader reads on",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT, flags=_DESCRIBED, trailer=b"")),
        "so a streaming reader reads on",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _deflated(_TEXT) + _descriptor(_TEXT) + _HIDDEN,
                content=_TEXT,
                method=8,
                flags=_DESCRIBED,
            )
        ),
        "ends before the size its directory entry declares",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _deflated(_TEXT) + _HIDDEN, content=_TEXT, method=8)),
        "ends before the size its directory entry declares",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _deflated(_TEXT) + _HIDDEN[:2],
                content=_TEXT,
                method=8,
                trailer=_HIDDEN[2:],
            )
        ),
        "ends before the size its directory entry declares",
    ),
    (
        _walked_zip(
            _Member(b"readme.txt", _deflated(_TEXT)[:-2], content=_TEXT, method=8, flags=_DESCRIBED)
        ),
        "does not end within the size its directory entry declares",
    ),
    (
        _walked_zip(
            _Member(b"readme.txt", b"\xff" * 16, content=_TEXT, method=8, flags=_DESCRIBED)
        ),
        "deflate stream that does not decode",
    ),
    (
        _walked_zip(_Member(b"readme.txt", bytes(12) + _TEXT, flags=_DESCRIBED | 0x01)),
        "is encrypted or uses compression other than",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT, method=_ZSTD, flags=_DESCRIBED)),
        "is encrypted or uses compression other than",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT + _HIDDEN, method=_ZSTD)),
        "is encrypted or uses compression other than",
    ),
    (
        _walked_zip(
            _Member(b"readme.txt", _bzipped(_TEXT) + _HIDDEN, content=_TEXT, method=12, flags=0x01)
        ),
        "is encrypted or uses compression other than",
    ),
    (
        _walked_zip(
            _Member(b"readme.txt", _deflated(_TEXT) + _HIDDEN, content=_TEXT, method=8, flags=0x01)
        ),
        "is encrypted or uses compression other than",
    ),
    (
        _walked_zip(
            _Member(b"readme.txt", _TEXT, flags=_DESCRIBED, local_extra=_field(1, bytes(16))),
            _Member(b"notes.txt", _TEXT),
        ),
        "member notes.txt overlaps the member before it",
    ),
    (
        _walked_zip(
            _Member(b"readme.txt", _TEXT, flags=_DESCRIBED, local_extra=_field(1, bytes(16)))
        ),
        "member readme.txt runs into its central directory",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _deflated(_TEXT),
                content=_TEXT,
                method=8,
                flags=_DESCRIBED,
                local_extra=_field(1, bytes(16)),
            ),
            _Member(b"notes.txt", _TEXT),
        ),
        "member notes.txt overlaps the member before it",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _deflated(_TEXT),
                content=_TEXT,
                method=8,
                flags=_DESCRIBED,
                trailer=struct.pack("<2L", zlib.crc32(_TEXT), len(_deflated(_TEXT))),
            ),
            _Member(b"notes.txt", _TEXT),
        ),
        "member notes.txt overlaps the member before it",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _deflated(_TEXT),
                content=_TEXT,
                method=8,
                flags=_DESCRIBED,
                trailer=struct.pack(
                    "<4s2L", b"PK\x07\x08", zlib.crc32(_TEXT), len(_deflated(_TEXT))
                ),
            ),
            _Member(b"notes.txt", _TEXT),
        ),
        "member notes.txt overlaps the member before it",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT, content=_TEXT, method=12, flags=_DESCRIBED)),
        "bzip2 stream that does not decode",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT + _HIDDEN, content=_TEXT, method=12)),
        "bzip2 stream that does not decode",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _bzipped(_TEXT) + _descriptor(_TEXT) + _HIDDEN,
                content=_TEXT,
                method=12,
                flags=_DESCRIBED,
            )
        ),
        "bzip2 stream that ends before the size its directory entry declares",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _bzipped(_TEXT) + _HIDDEN, content=_TEXT, method=12)),
        "bzip2 stream that ends before the size its directory entry declares",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _bzipped(_TEXT) + bytes(8),
                content=_TEXT,
                method=12,
                flags=_DESCRIBED,
            )
        ),
        "bzip2 stream that ends before the size its directory entry declares",
    ),
    (
        _walked_zip(
            _Member(b"readme.txt", _bzipped(_TEXT)[:-4], content=_TEXT, method=12, flags=_DESCRIBED)
        ),
        "bzip2 stream that does not end within the size its directory entry declares",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT, content=_TEXT, method=14, flags=_DESCRIBED)),
        "LZMA header that does not decode",
    ),
    (
        _walked_zip(_Member(b"readme.txt", _TEXT + _HIDDEN, content=_TEXT, method=14)),
        "LZMA header that does not decode",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _lzma_zipped(_TEXT)[:6],
                content=_TEXT,
                method=14,
                flags=_DESCRIBED,
            )
        ),
        "LZMA header that does not decode",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _lzma_zipped(
                    _TEXT,
                    header=struct.pack("<2BH", 9, 4, 7) + _LZMA_PROPERTIES + bytes(2),
                ),
                content=_TEXT,
                method=14,
                flags=_DESCRIBED,
            )
        ),
        "LZMA header that does not decode",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _lzma_zipped(
                    _TEXT,
                    header=struct.pack("<2BHBL", 9, 4, 5, (4 * 5 + 4) * 9 + 8, 1 << 16),
                ),
                content=_TEXT,
                method=14,
                flags=_DESCRIBED,
            )
        ),
        "LZMA header that does not decode",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _lzma_zipped(_TEXT) + _descriptor(_TEXT) + _HIDDEN,
                content=_TEXT,
                method=14,
                flags=_DESCRIBED,
            )
        ),
        "LZMA stream that ends before the size its directory entry declares",
    ),
    (
        _walked_zip(
            _Member(b"readme.txt", _lzma_zipped(_TEXT) + _HIDDEN, content=_TEXT, method=14)
        ),
        "LZMA stream that ends before the size its directory entry declares",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _lzma_zipped(_TEXT, cut=6),
                content=_TEXT,
                method=14,
                flags=_DESCRIBED,
            )
        ),
        "LZMA stream that does not end within the size its directory entry declares",
    ),
    (
        _walked_zip(
            _Member(
                b"readme.txt",
                _lzma_zipped(b"")[:9] + b"\xff" * 16,
                content=_TEXT,
                method=14,
                flags=_DESCRIBED,
            )
        ),
        "LZMA stream that does not decode",
    ),
]


@pytest.mark.parametrize(
    ("content", "reason"),
    _UNPACKED_OTHERWISE,
    ids=[
        "hidden-before-the-first-member",
        "hidden-between-members",
        "hidden-after-the-last-member",
        "a-local-header-inside-another-member",
        "no-local-header",
        "data-running-into-the-directory",
        "local-name",
        "local-unicode-path",
        "local-attributes-of-a-link",
        "local-attributes-on-another-system",
        "local-attributes-of-a-link-after-internal-ones",
        "zip64-one-size-marked",
        "zip64-sizes-not-held",
        "zip64-sizes-differ",
        "described-compressed-size-differs",
        "described-size-differs",
        "stored-data-ending-at-an-earlier-descriptor",
        "stored-data-whose-descriptor-does-not-match",
        "stored-data-with-no-descriptor",
        "described-deflate-ending-early",
        "deflate-ending-early-before-a-local-header",
        "deflate-ending-early-before-a-local-header-across-its-end",
        "described-deflate-ending-late",
        "deflate-that-does-not-decode",
        "encrypted-and-described",
        "other-method-and-described",
        "other-method-holding-a-local-header",
        "encrypted-bzip2-holding-a-local-header",
        "encrypted-deflate-holding-a-local-header",
        "zip64-field-and-a-short-descriptor-before-a-member",
        "zip64-field-and-a-short-descriptor-before-the-directory",
        "deflate-with-a-zip64-field-and-a-short-descriptor",
        "deflate-with-a-descriptor-cut-short",
        "deflate-with-a-signed-descriptor-cut-short",
        "bzip2-that-does-not-decode",
        "bzip2-that-does-not-decode-holding-a-local-header",
        "described-bzip2-ending-early",
        "bzip2-ending-early-before-a-local-header",
        "described-bzip2-followed-by-extra-bytes",
        "described-bzip2-ending-late",
        "lzma-whose-header-does-not-decode",
        "lzma-whose-header-does-not-decode-holding-a-local-header",
        "lzma-header-cut-short",
        "lzma-properties-of-seven-bytes",
        "lzma-properties-out-of-range",
        "described-lzma-ending-early",
        "lzma-ending-early-before-a-local-header",
        "described-lzma-without-its-end-marker",
        "lzma-stream-that-does-not-decode",
    ],
)
def test_a_zip_a_streaming_reader_unpacks_otherwise_is_unscanned(
    tmp_path: Path, content: bytes, reason: str
) -> None:
    refusals = _walk_refusals(tmp_path, "bundle.zip", content)

    assert len(refusals) == 1, refusals
    assert reason in refusals[0], refusals


@pytest.mark.filterwarnings("ignore:Overlapped entries")
def test_two_entries_of_one_local_header_are_unscanned(tmp_path: Path) -> None:
    content = _walked_zip(_Member(b"notes.txt", _TEXT), _Member(b"notes.txt", _TEXT, offset=0))

    refusals = _walk_refusals(tmp_path, "bundle.zip", content)

    assert len(refusals) == 1, refusals
    assert "overlaps the member before it" in refusals[0], refusals


@pytest.mark.parametrize("name", ["bundle.zip", "bundle", "bundle.tar", "bundle.tar.gz"])
def test_every_name_a_person_unpacks_is_walked(tmp_path: Path, name: str) -> None:
    content = _walked_zip(_Member(b"readme.txt", _TEXT), before=_HIDDEN)

    assert _walk_refusals(tmp_path, name, content)


@pytest.mark.parametrize("name", ["model.pt", "arrays.npz"])
def test_a_model_archive_a_loader_reads_by_its_directory_is_not_walked(
    tmp_path: Path, name: str
) -> None:
    content = _walked_zip(_Member(b"archive/readme.txt", _TEXT), before=_HIDDEN)

    assert _walk_refusals(tmp_path, name, content) == []


def test_the_listed_members_are_still_scanned(tmp_path: Path) -> None:
    content = _walked_zip(_Member(b"model.pkl", _SYSTEM), before=_HIDDEN)

    summaries, _ctx, _path = _summaries(tmp_path, "bundle.zip", content)

    assert [s for s in summaries if _WALKED in s], summaries
    assert [s for s in summaries if "non-allowlisted" in s], summaries


class _Pipe:
    """A sink with no `tell` or `seek`, as a pipe is, so `zipfile` writes data descriptors."""

    def __init__(self) -> None:
        self.written = io.BytesIO()

    def write(self, data: bytes) -> int:
        return self.written.write(data)

    def flush(self) -> None:
        """Nothing is buffered."""

    def close(self) -> None:
        """Nothing is held open."""


def _python_inner() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.txt", _TEXT)
    return buffer.getvalue()


def _python_zip(method: int, *, piped: bool) -> bytes:
    pipe, file = _Pipe(), io.BytesIO()
    with zipfile.ZipFile(pipe if piped else file, "w", method) as archive:
        archive.writestr("readme.txt", _TEXT)
        archive.writestr("model.pkl", _CLEAN)
        archive.writestr("empty", b"")
        archive.writestr("dir/", b"")
        archive.writestr("inner.data", _python_inner())
    return (pipe.written if piped else file).getvalue()


@pytest.mark.parametrize(
    "content",
    [
        _python_zip(zipfile.ZIP_STORED, piped=False),
        _python_zip(zipfile.ZIP_STORED, piped=True),
        _python_zip(zipfile.ZIP_DEFLATED, piped=False),
        _python_zip(zipfile.ZIP_DEFLATED, piped=True),
        _python_zip(zipfile.ZIP_BZIP2, piped=False),
        _python_zip(zipfile.ZIP_BZIP2, piped=True),
        _python_zip(zipfile.ZIP_LZMA, piped=False),
        _python_zip(zipfile.ZIP_LZMA, piped=True),
        _walked_zip(
            _Member(
                b"readme.txt",
                _TEXT,
                local_sizes=(_UNSET, _UNSET),
                local_extra=_field(1, struct.pack("<QQ", len(_TEXT), len(_TEXT))),
            )
        ),
        _walked_zip(
            _Member(
                b"readme.txt",
                _deflated(_TEXT),
                content=_TEXT,
                method=8,
                local_sizes=(_UNSET, _UNSET),
                local_extra=_field(1, struct.pack("<QQ", len(_TEXT), len(_deflated(_TEXT)))),
            )
        ),
        _walked_zip(_Member(b"readme.txt", _TEXT, local_extra=_field(1, bytes(16)))),
        _walked_zip(_Member(b"readme.txt", _TEXT, flags=_DESCRIBED, local_sizes=(0, len(_TEXT)))),
        _walked_zip(
            _Member(b"blob", _UNMATCHED + _TEXT, flags=_DESCRIBED), _Member(b"notes.txt", _TEXT)
        ),
        _walked_zip(
            _Member(b"inner.data", _HIDDEN + _TEXT),
            _Member(
                b"packed.data",
                _deflated(_HIDDEN + _TEXT, level=0),
                content=_HIDDEN + _TEXT,
                method=8,
            ),
        ),
        _walked_zip(_Member(b"readme.txt", _deflated(_TEXT) + bytes(8), content=_TEXT, method=8)),
        _walked_zip(
            _Member(
                b"s", b"/etc", local_extra=_attributes(0x05, _MADE_ON_UNIX, _REGULAR_ATTRIBUTES)
            )
        ),
        _walked_zip(
            _Member(
                b"s",
                b"/etc",
                local_extra=_attributes(0x85, b"\x00", _MADE_ON_UNIX, _REGULAR_ATTRIBUTES),
            )
        ),
        _walked_zip(
            _Member(
                b"s",
                b"/etc",
                local_extra=_attributes(0x07, _MADE_ON_UNIX, b"\x01\x00", _REGULAR_ATTRIBUTES),
            )
        ),
        _walked_zip(_Member(b"s", b"/etc", local_extra=_attributes(0x04, _LINK_ATTRIBUTES[:3]))),
        _walked_zip(_Member(b"s", b"/etc", local_extra=_attributes(0x05, b"\x03"))),
        _walked_zip(
            _Member(b"s", b"/etc", local_extra=_attributes(0x01, _MADE_ON_UNIX, _LINK_ATTRIBUTES))
        ),
        _walked_zip(
            _Member(
                b"notes.txt",
                _TEXT,
                local_extra=_unicode_path(b"notes.txt", b"readme.txt"),
                central_extra=_unicode_path(b"notes.txt", b"readme.txt"),
            )
        ),
        _walked_zip(),
        _walked_zip(
            _Member(
                b"readme.txt",
                _TEXT,
                flags=_DESCRIBED,
                local_extra=_field(1, bytes(16)),
                trailer=_wide_descriptor(_TEXT),
            ),
            _Member(b"notes.txt", _TEXT),
        ),
        _walked_zip(
            _Member(b"readme.txt", _TEXT, flags=_DESCRIBED, trailer=_wide_descriptor(_TEXT)),
            _Member(b"notes.txt", _TEXT),
        ),
        _walked_zip(
            _Member(
                b"readme.txt",
                _deflated(_TEXT),
                content=_TEXT,
                method=8,
                flags=_DESCRIBED,
                trailer=struct.pack("<3L", zlib.crc32(_TEXT), len(_deflated(_TEXT)), len(_TEXT)),
            ),
            _Member(b"notes.txt", _TEXT),
        ),
    ],
    ids=[
        "python-stored",
        "python-stored-to-a-pipe",
        "python-deflated",
        "python-deflated-to-a-pipe",
        "python-bzip2",
        "python-bzip2-to-a-pipe",
        "python-lzma",
        "python-lzma-to-a-pipe",
        "zip64-sizes",
        "zip64-sizes-of-a-deflated-member",
        "zip64-field-beside-real-sizes",
        "described-with-its-size-in-the-local-header",
        "a-descriptor-signature-whose-crc-does-not-match",
        "local-header-signatures-inside-member-data",
        "deflate-ending-early-with-no-local-header-after",
        "local-attributes-of-the-directory-entry",
        "local-attributes-after-more-bitmap-bits",
        "local-attributes-after-internal-ones",
        "local-attributes-cut-short",
        "local-attributes-with-a-version-cut-short",
        "local-attributes-without-external-ones",
        "unicode-path-in-both-headers",
        "empty",
        "zip64-field-and-a-descriptor-with-8-byte-sizes",
        "a-descriptor-with-8-byte-sizes-and-no-zip64-field",
        "deflate-with-a-descriptor-without-its-signature",
    ],
)
def test_a_zip_a_streaming_reader_unpacks_as_listed_stays_clean(
    tmp_path: Path, content: bytes
) -> None:
    summaries, _ctx, _path = _summaries(tmp_path, "bundle.zip", content)

    assert summaries == []


def test_an_empty_zip_holding_a_local_entry_is_unscanned(tmp_path: Path) -> None:
    assert _walk_refusals(tmp_path, "bundle.zip", _walked_zip(before=_HIDDEN))


_PACKERS = {8: _deflated, 12: _bzipped, 14: _lzma_zipped}


@pytest.mark.parametrize("method", list(_PACKERS), ids=["deflate", "bzip2", "lzma"])
def test_inflating_past_the_bound_is_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, method: int
) -> None:
    monkeypatch.setattr(pickle_opcode, "_COMPRESSED_TAR_MIN_BYTES", len(_TEXT) - 1)
    monkeypatch.setattr(pickle_opcode, "_COMPRESSED_TAR_MAX_RATIO", 0)
    content = _walked_zip(
        _Member(
            b"readme.txt", _PACKERS[method](_TEXT), content=_TEXT, method=method, flags=_DESCRIBED
        )
    )

    refusals = _walk_refusals(tmp_path, "bundle.zip", content)

    assert refusals, refusals
    assert f"inflating more than {len(_TEXT) - 1} bytes" in refusals[0]


@pytest.mark.parametrize("method", list(_PACKERS), ids=["deflate", "bzip2", "lzma"])
@pytest.mark.parametrize(("floor", "ratio"), [(len(_TEXT), 0), (1, len(_TEXT))])
def test_inflating_up_to_the_bound_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, floor: int, ratio: int, method: int
) -> None:
    """The bound is the larger of a floor and a multiple of the file's size."""
    monkeypatch.setattr(pickle_opcode, "_COMPRESSED_TAR_MIN_BYTES", floor)
    monkeypatch.setattr(pickle_opcode, "_COMPRESSED_TAR_MAX_RATIO", ratio)
    content = _walked_zip(
        _Member(
            b"readme.txt", _PACKERS[method](_TEXT), content=_TEXT, method=method, flags=_DESCRIBED
        )
    )

    assert _walk_refusals(tmp_path, "bundle.zip", content) == []


def test_matching_past_the_descriptor_bound_is_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_zip, "ARCHIVE_MAX_ENTRIES", 2)
    content = _walked_zip(_Member(b"blob", _UNMATCHED * 2 + _TEXT, flags=_DESCRIBED))

    refusals = _walk_refusals(tmp_path, "bundle.zip", content)

    assert refusals, refusals
    assert "more than 2 data descriptor signatures" in refusals[0]


def test_matching_up_to_the_descriptor_bound_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_zip, "ARCHIVE_MAX_ENTRIES", 3)
    content = _walked_zip(_Member(b"blob", _UNMATCHED * 2 + _TEXT, flags=_DESCRIBED))

    assert _walk_refusals(tmp_path, "bundle.zip", content) == []


@pytest.mark.parametrize("chunk", [1, 3, 7, 64])
def test_signatures_across_read_chunks_are_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chunk: int
) -> None:
    monkeypatch.setattr(_zip, "_CHUNK_BYTES", chunk)
    early = _walked_zip(
        _Member(b"readme.txt", _TEXT + _descriptor(_TEXT) + _HIDDEN, flags=_DESCRIBED)
    )
    hidden = _walked_zip(_Member(b"readme.txt", _TEXT), before=_TEXT + _HIDDEN)
    inflated = _walked_zip(
        _Member(
            b"readme.txt",
            _deflated(_TEXT) + _descriptor(_TEXT) + _HIDDEN,
            content=_TEXT,
            method=8,
            flags=_DESCRIBED,
        )
    )
    early_at_eight = _walked_zip(
        _Member(b"readme.txt", _TEXT[:8] + _descriptor(_TEXT[:8]) + _HIDDEN, flags=_DESCRIBED)
    )
    straddling = _walked_zip(
        _Member(
            b"readme.txt",
            _deflated(_TEXT) + _HIDDEN[:1],
            content=_TEXT,
            method=8,
            trailer=_HIDDEN[1:],
        )
    )
    bzipped_early = _walked_zip(
        _Member(
            b"readme.txt",
            _bzipped(_TEXT) + _descriptor(_TEXT) + _HIDDEN,
            content=_TEXT,
            method=12,
            flags=_DESCRIBED,
        )
    )
    lzma_early = _walked_zip(
        _Member(
            b"readme.txt",
            _lzma_zipped(_TEXT) + _descriptor(_TEXT) + _HIDDEN,
            content=_TEXT,
            method=14,
            flags=_DESCRIBED,
        )
    )
    clean = _walked_zip(
        _Member(b"readme.txt", _UNMATCHED + _TEXT, flags=_DESCRIBED),
        _Member(b"packed.txt", _deflated(_TEXT), content=_TEXT, method=8, flags=_DESCRIBED),
        _Member(b"bzipped.txt", _bzipped(_TEXT), content=_TEXT, method=12, flags=_DESCRIBED),
        _Member(b"lzma.txt", _lzma_zipped(_TEXT), content=_TEXT, method=14, flags=_DESCRIBED),
    )

    assert _walk_refusals(tmp_path, "early.zip", early)
    assert _walk_refusals(tmp_path, "hidden.zip", hidden)
    assert _walk_refusals(tmp_path, "inflated.zip", inflated)
    assert _walk_refusals(tmp_path, "early-at-eight.zip", early_at_eight)
    assert _walk_refusals(tmp_path, "straddling.zip", straddling)
    assert _walk_refusals(tmp_path, "bzipped-early.zip", bzipped_early)
    assert _walk_refusals(tmp_path, "lzma-early.zip", lzma_early)
    assert _walk_refusals(tmp_path, "clean.zip", clean) == []


def _piped_model(method: int, pickle: bytes) -> bytes:
    """A zip written to a pipe, so every member carries a data descriptor."""
    pipe = _Pipe()
    with zipfile.ZipFile(pipe, "w", method) as archive:
        archive.writestr("readme.txt", _TEXT)
        archive.writestr("model.pkl", pickle)
    return pipe.written.getvalue()


_PIPED_METHODS = [zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA]


_STREAMED = {
    zipfile.ZIP_DEFLATED: _deflated,
    zipfile.ZIP_BZIP2: _bzipped,
    zipfile.ZIP_LZMA: _lzma_zipped,
}


@pytest.mark.parametrize("method", _PIPED_METHODS, ids=["deflate", "bzip2", "lzma"])
@pytest.mark.parametrize(
    ("stream", "declared"),
    [(_CLEAN + _SYSTEM, _CLEAN), (_CLEAN, b"\x80\x02K\x01.")],
    ids=["longer", "other-crc"],
)
def test_a_stream_that_decodes_to_other_bytes_than_declared_is_not_read(
    tmp_path: Path, method: int, stream: bytes, declared: bytes
) -> None:
    """`zipfile` stops at the declared size, while a streaming reader writes the whole stream."""
    archive = _walked_zip(
        _Member(
            b"model.pkl",
            _STREAMED[method](stream),
            content=declared,
            method=method,
            flags=_DESCRIBED,
        )
    )

    assert _walk_refusals(tmp_path, "bundle.zip", archive)


@pytest.mark.parametrize("method", _PIPED_METHODS, ids=["deflate", "bzip2", "lzma"])
def test_a_clean_pickle_in_a_piped_zip_is_read_and_clean(tmp_path: Path, method: int) -> None:
    summaries, ctx, path = _summaries(tmp_path, "bundle.zip", _piped_model(method, _CLEAN))

    assert summaries == []
    assert ctx.shortfalls() == ()
    assert str(path) in ctx.examined_paths()


@pytest.mark.parametrize("method", _PIPED_METHODS, ids=["deflate", "bzip2", "lzma"])
def test_a_harmful_pickle_in_a_piped_zip_is_found(tmp_path: Path, method: int) -> None:
    path = Path(tempfile.mkdtemp(dir=tmp_path)) / "bundle.zip"
    path.write_bytes(_piped_model(method, _SYSTEM))
    ctx = RuleContext()

    findings = list(PickleOpcodeRule().run(ArtifactTarget(path.parent), ctx))

    assert [f.severity for f in findings] == [Severity.CRITICAL], findings
    assert "os.system" in findings[0].evidence.summary
    assert ctx.shortfalls() == ()
