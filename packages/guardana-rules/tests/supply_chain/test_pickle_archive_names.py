"""A file named as an archive is read as a `tar` command reads it: by its bytes.

GNU tar and busybox decompress a file whose first bytes are a codec's signature, and `bsdtar`
also reads other archive formats, whatever the file is named. A `.zip`, a `.tar` or a file named
as a compressed tar that such a command may unpack otherwise than this rule reads it is
unscanned. Every file is built in code; nothing is unpickled.
"""

import binascii
import bz2
import gzip
import io
import lzma
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import pickle_opcode
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_SYSTEM = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R."
_CLEAN = b"\x80\x02K\x00."
_UNSCANNED = "Unscanned model file"


def _tar(*members: tuple[str, bytes], form: int = tarfile.PAX_FORMAT) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=form) as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _rechecked(block: bytearray) -> bytes:
    block[148:156] = b" " * 8
    block[148:156] = b"%06o\x00 " % sum(block)
    return bytes(block)


def _first_header(content: bytes, start: int, value: bytes) -> bytes:
    """`content` with `value` written into its first tar header at `start`, rechecked."""
    block = bytearray(content[: tarfile.BLOCKSIZE])
    block[start : start + len(value)] = value
    return _rechecked(block) + content[tarfile.BLOCKSIZE :]


def _v7(content: bytes) -> bytes:
    return _first_header(content, 257, bytes(8))


def _ar_named(*, magic: bool) -> bytes:
    """A tar whose first member's name is the start of an `ar` archive holding a pickle."""
    data = _SYSTEM
    header = b"model.pkl".ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
    header += b"644".ljust(8) + str(len(data)).encode().ljust(10) + b"`\n"
    ar = b"!<arch>\n" + header + data
    content = _first_header(_tar(("placeholder", b"hello\n")), 0, ar.ljust(100, b"\x00"))
    return content if magic else _v7(content)


def _cpio(name: bytes, data: bytes) -> bytes:
    """An odc `cpio` archive of one file."""
    entries = b""
    for entry_name, entry_data, mode in ((name, data, 0o100644), (b"TRAILER!!!", b"", 0)):
        fields = (0, 0, mode, 0, 0, 1, 0)
        header = b"070707" + b"".join(b"%06o" % field for field in fields)
        header += b"%011o" % 0 + b"%06o" % (len(entry_name) + 1) + b"%011o" % len(entry_data)
        entries += header + entry_name + b"\x00" + entry_data
    return entries


def _appended_zip(prefix: bytes) -> bytes:
    buffer = io.BytesIO(prefix)
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.writestr("model.pkl", _SYSTEM)
    return buffer.getvalue()


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _iso_in_zip() -> bytes:
    """A zip at byte 0 whose stored data puts an ISO 9660 signature at byte 32769."""
    name = "readme.txt"
    data = bytearray(40 * 1024)
    start = 32769 - 30 - len(name)
    data[start : start + 5] = b"CD001"
    return _zip({name: bytes(data)})


def _iso_in_tar() -> bytes:
    """A v7 tar whose one member's data puts an ISO 9660 signature at byte 32769 of the tar."""
    data = bytearray(40 * 1024)
    start = 32769 - tarfile.BLOCKSIZE
    data[start : start + 5] = b"CD001"
    return _v7(_tar(("a.bin", bytes(data))))


def _uuencoded(data: bytes) -> bytes:
    lines = [binascii.b2a_uu(data[i : i + 45]) for i in range(0, len(data), 45)]
    return b"begin 644 inner.tar\n" + b"".join(lines) + b"`\nend\n"


def _scan(tmp_path: Path, name: str, content: bytes) -> tuple[list[str], list[str], bool]:
    """Scan `content` alone, named `name`: the criticals, the unscanned summaries, examined."""
    path = Path(tempfile.mkdtemp(dir=tmp_path)) / name
    path.write_bytes(content)
    ctx = RuleContext()
    findings = list(PickleOpcodeRule().run(ArtifactTarget(path.parent), ctx))
    critical = [f.evidence.detail or "" for f in findings if f.severity.name == "CRITICAL"]
    unscanned = [f.evidence.summary for f in findings if f.title == _UNSCANNED]
    return critical, unscanned, str(path) in ctx.examined_paths()


_INNER = _tar(("model.pkl", _SYSTEM))
_NAMES = ["bundle.tar", "bundle.zip", "bundle.tar.gz"]


@pytest.mark.parametrize("name", _NAMES)
@pytest.mark.parametrize(
    ("content", "codec"),
    [
        (lzma.compress(_INNER, format=lzma.FORMAT_ALONE), "lzma"),
        (b"\x28\xb5\x2f\xfd" + _INNER, "zstd"),
        (b"\x1f\x9d\x90" + _INNER, "compress"),
        (b"LZIP\x01\x0c" + _INNER, "lzip"),
        (b"plain text, one line of it\n" * 3000 + _uuencoded(_INNER), "uuencode"),
    ],
    ids=["lzma", "zstd", "compress", "lzip", "uuencoded-after-text"],
)
def test_a_codec_this_rule_does_not_unpack_tars_from_is_unscanned(
    tmp_path: Path, name: str, content: bytes, codec: str
) -> None:
    critical, unscanned, examined = _scan(tmp_path, name, content)

    assert critical == []
    assert len(unscanned) == 1, unscanned
    assert f"file holds {codec} data that a tar command decodes" in unscanned[0]
    assert examined


@pytest.mark.parametrize("compress", [gzip.compress, bz2.compress, lzma.compress])
def test_a_compressed_tar_named_as_a_zip_is_read_as_a_tar(
    tmp_path: Path, compress: Callable[[bytes], bytes]
) -> None:
    critical, unscanned, _examined = _scan(tmp_path, "bundle.zip", compress(_INNER))

    assert critical == ["os.system in bundle.zip::model.pkl"]
    assert unscanned == []


@pytest.mark.parametrize(
    ("name", "content", "found"),
    [
        ("bundle.tar", _ar_named(magic=False), "ar"),
        ("bundle.zip", _cpio(b"model.pkl", _SYSTEM), "cpio"),
        ("bundle.tar", _cpio(b"model.pkl", _SYSTEM), "cpio"),
        ("bundle.zip", _iso_in_zip(), "iso9660"),
        ("bundle.tar", _appended_zip(bytes(tarfile.BLOCKSIZE) + _tar(("a.txt", b"hi\n"))), "zip"),
        ("bundle.tar", _appended_zip(_first_header(_tar(("a.txt", b"hi\n")), 156, b"!")), "zip"),
    ],
    ids=[
        "a-v7-tar-starting-as-ar",
        "cpio-named-as-a-zip",
        "cpio-named-as-a-tar",
        "a-zip-holding-an-iso-9660-signature",
        "a-zip-after-an-end-block",
        "a-zip-after-a-tar-header-of-an-odd-type",
    ],
)
def test_another_archive_format_a_tar_command_may_unpack_is_unscanned(
    tmp_path: Path, name: str, content: bytes, found: str
) -> None:
    _critical, unscanned, examined = _scan(tmp_path, name, content)

    assert unscanned == [
        f"file holds {found} archive data, which a tar command may unpack in place of what "
        "this scanner reads; not scanned"
    ]
    assert examined


@pytest.mark.parametrize(
    "content",
    [_ar_named(magic=True), _appended_zip(_v7(_tar(("a.txt", b"hi\n"))))],
    ids=["a-ustar-tar-starting-as-ar", "a-zip-after-a-v7-tar"],
)
def test_a_tar_that_outranks_the_other_format_is_read_as_a_tar(
    tmp_path: Path, content: bytes
) -> None:
    _critical, unscanned, _examined = _scan(tmp_path, "bundle.tar", content)

    assert unscanned == []


def test_a_7z_archive_named_as_a_zip_is_reported_once(tmp_path: Path) -> None:
    _critical, unscanned, _examined = _scan(
        tmp_path, "bundle.zip", b"7z\xbc\xaf\x27\x1c" + bytes(64)
    )

    assert len(unscanned) == 1, unscanned
    assert "7z" in unscanned[0]


def test_a_zip_after_another_archive_is_unscanned(tmp_path: Path) -> None:
    content = _appended_zip(_cpio(b"model.pkl", _SYSTEM))

    critical, unscanned, examined = _scan(tmp_path, "bundle.zip", content)

    assert critical == ["os.system in bundle.zip::model.pkl"]
    assert unscanned == [
        "zip data does not start at the file's first byte, and a tar command may read the "
        "bytes before it as another archive; not scanned"
    ]
    assert examined


def test_a_zip_of_text_after_another_archive_is_unscanned(tmp_path: Path) -> None:
    buffer = io.BytesIO(_cpio(b"model.pkl", _SYSTEM))
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.writestr("readme.txt", b"hello\n")

    critical, unscanned, examined = _scan(tmp_path, "bundle.zip", buffer.getvalue())

    assert critical == []
    assert len(unscanned) == 1, unscanned
    assert unscanned[0].startswith("zip data does not start at the file's first byte")
    assert examined


def test_a_compressed_file_named_as_a_tar_that_holds_a_zip_is_unscanned(tmp_path: Path) -> None:
    content = gzip.compress(_zip({"model.pkl": _SYSTEM}))

    critical, unscanned, examined = _scan(tmp_path, "bundle.tar.gz", content)

    assert critical == []
    assert unscanned == [
        "gzip-compressed file holds no tar this scanner reads, which a tar command may still "
        "unpack; not scanned"
    ]
    assert examined


@pytest.mark.parametrize(
    ("inner", "reason"),
    [
        (_ar_named(magic=False), "decompresses to ar archive data"),
        (_iso_in_tar(), "decompresses to iso9660 archive data"),
        (_tar(("x\nbegin 644 y\nz", b"hi\n")), "holds uuencode data after decompression"),
        (_tar(("]", b"hi\n")), "holds lzma data after decompression"),
    ],
    ids=[
        "a-v7-tar-starting-as-ar",
        "a-v7-tar-holding-an-iso-9660-signature",
        "a-tar-starting-with-a-uuencode-line",
        "a-tar-starting-as-lzma",
    ],
)
def test_a_compressed_tar_whose_bytes_a_tar_command_reads_otherwise_is_unscanned(
    tmp_path: Path, inner: bytes, reason: str
) -> None:
    _critical, unscanned, examined = _scan(tmp_path, "bundle.tgz", gzip.compress(inner))

    decompressed = [s for s in unscanned if s.startswith("gzip-compressed tar ")]
    assert len(decompressed) == 1, unscanned
    assert f"gzip-compressed tar {reason}" in decompressed[0]
    assert examined


def test_a_compressed_tar_that_outranks_the_other_format_is_read_as_a_tar(tmp_path: Path) -> None:
    _critical, unscanned, _examined = _scan(
        tmp_path, "bundle.tgz", gzip.compress(_ar_named(magic=True))
    )

    assert unscanned == []


@pytest.mark.parametrize("name", ["bundle.zip", "bundle.tar", "bundle.tgz"])
def test_a_file_named_as_an_archive_that_is_none_is_unscanned(tmp_path: Path, name: str) -> None:
    critical, unscanned, examined = _scan(tmp_path, name, b"<html>not found</html>\n")

    assert critical == []
    assert unscanned == [
        "file named as an archive is no zip, tar or pickle this scanner reads, which a tar "
        "command may still unpack; not scanned"
    ]
    assert examined


@pytest.mark.parametrize("name", ["bundle.zip", "bundle.tar"])
@pytest.mark.parametrize(
    "content",
    [b"", bytes(20 * tarfile.BLOCKSIZE), bytes(pickle_opcode._BLANK_MAX_BYTES)],
    ids=["empty", "an-empty-tar", "zeros-up-to-the-bound"],
)
def test_an_archive_name_on_nothing_or_zeros_stays_quiet(
    tmp_path: Path, name: str, content: bytes
) -> None:
    critical, unscanned, examined = _scan(tmp_path, name, content)

    assert (critical, unscanned, examined) == ([], [], False)


def test_zeros_past_the_bound_are_unscanned(tmp_path: Path) -> None:
    content = bytes(pickle_opcode._BLANK_MAX_BYTES + 1)

    _critical, unscanned, _examined = _scan(tmp_path, "bundle.tar", content)

    assert len(unscanned) == 1, unscanned
    assert "is no zip, tar or pickle" in unscanned[0]


@pytest.mark.parametrize(
    ("content", "critical"),
    [(_SYSTEM, ["os.system in model.pth.tar"]), (_CLEAN, [])],
    ids=["a-pickle-importing-a-callable", "a-clean-pickle"],
)
def test_a_legacy_torch_save_named_as_a_tar_is_read_as_a_pickle(
    tmp_path: Path, content: bytes, critical: list[str]
) -> None:
    found, unscanned, _examined = _scan(tmp_path, "model.pth.tar", content)

    assert (found, unscanned) == (critical, [])


@pytest.mark.parametrize(
    "content",
    [_tar(("model.pkl", _CLEAN)), _tar(("model.pkl", _CLEAN), form=tarfile.GNU_FORMAT)],
    ids=["pax", "gnu"],
)
@pytest.mark.parametrize("name", ["bundle.tar", "bundle.zip"])
def test_a_tar_ordinary_tools_write_stays_clean(tmp_path: Path, content: bytes, name: str) -> None:
    assert _scan(tmp_path, name, content)[:2] == ([], [])


def test_a_file_without_a_suffix_is_left_to_its_head(tmp_path: Path) -> None:
    assert _scan(tmp_path, "bundle", b"\x28\xb5\x2f\xfd" + _INNER) == ([], [], False)
