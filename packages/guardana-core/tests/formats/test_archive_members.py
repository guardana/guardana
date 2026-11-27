"""A plain archive is listed by its member names, within bounds, and never past them.

Every archive here is built in code. An archive that cannot be listed to its end counts as
holding a model, so a bound reached is never a clean listing.
"""

import bz2
import gzip
import io
import lzma
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.core.formats import archive_members
from guardana.core.formats.archive_members import ArchiveKind
from guardana.core.inventory import archive_holding_model, named_as_archived_model

_PICKLE = b"\x80\x02}q\x00."


def _zip(members: dict[str, bytes], method: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _tar(
    members: dict[str, bytes],
    tar_format: int = tarfile.PAX_FORMAT,
    pax_headers: dict[str, str] | None = None,
) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(
        fileobj=buffer, mode="w", format=tar_format, pax_headers=pax_headers or {}
    ) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


_WITH_MODEL = {"docs/readme.txt": b"x" * 3000, "weights/model.pkl": _PICKLE}
_WITHOUT_MODEL = {"docs/readme.txt": b"x" * 3000, "data/rows.csv": b"a,b\n1,2\n"}
_ARCHIVES: dict[str, tuple[Callable[[dict[str, bytes]], bytes], ArchiveKind]] = {
    "bundle.zip": (_zip, ArchiveKind.ZIP),
    "deflated.zip": (lambda m: _zip(m, zipfile.ZIP_DEFLATED), ArchiveKind.ZIP),
    "bundle.tar": (_tar, ArchiveKind.TAR),
    "gnu.tar": (lambda m: _tar(m, tarfile.GNU_FORMAT), ArchiveKind.TAR),
    "ustar.tar": (lambda m: _tar(m, tarfile.USTAR_FORMAT), ArchiveKind.TAR),
    "bundle.tar.gz": (lambda m: gzip.compress(_tar(m)), ArchiveKind.TAR),
    "bundle.tgz": (lambda m: gzip.compress(_tar(m)), ArchiveKind.TAR),
    "bundle.tar.bz2": (lambda m: bz2.compress(_tar(m)), ArchiveKind.TAR),
    "bundle.tbz2": (lambda m: bz2.compress(_tar(m)), ArchiveKind.TAR),
    "bundle.tbz": (lambda m: bz2.compress(_tar(m)), ArchiveKind.TAR),
    "bundle.tar.xz": (lambda m: lzma.compress(_tar(m)), ArchiveKind.TAR),
    "bundle.txz": (lambda m: lzma.compress(_tar(m)), ArchiveKind.TAR),
}


@pytest.mark.parametrize("name", sorted(_ARCHIVES))
def test_an_archive_holding_a_member_named_as_a_model_is_listed(tmp_path: Path, name: str) -> None:
    build, kind = _ARCHIVES[name]

    assert archive_holding_model(_write(tmp_path, name, build(_WITH_MODEL))) is kind


@pytest.mark.parametrize("name", sorted(_ARCHIVES))
def test_an_archive_of_text_and_data_is_not_listed(tmp_path: Path, name: str) -> None:
    build, _kind = _ARCHIVES[name]

    assert archive_holding_model(_write(tmp_path, name, build(_WITHOUT_MODEL))) is None


def test_a_name_that_already_makes_the_file_a_model_is_left_to_that_name(tmp_path: Path) -> None:
    data = gzip.compress(_tar(_WITH_MODEL))

    assert archive_holding_model(_write(tmp_path, "model.tar.gz", data)) is None
    assert archive_holding_model(_write(tmp_path, "weights.pth.tar", _tar(_WITH_MODEL))) is None


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("dir.zip", _zip({"weights.pkl/": b"", "weights.pkl/notes.txt": b"x"})),
        ("hdf5.zip", _zip({"train.h5": b"x", "val.hdf5": b"y"})),
        ("sdist.tar.gz", gzip.compress(_tar({"pkg-1.0/setup.py": b"", "pkg-1.0/pkg/a.py": b""}))),
        ("text.tar", b"not a tar at all\n" * 100),
        ("rows.tar.gz", gzip.compress(b"a,b\n" * 1000)),
        ("empty.zip", _zip({})),
        ("comment.tar", _tar({"a.txt": b"x"}, pax_headers={"comment": "built in code"})),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_an_archive_with_no_member_named_as_a_model_is_not_listed(
    tmp_path: Path, name: str, data: bytes
) -> None:
    assert archive_holding_model(_write(tmp_path, name, data)) is None


def test_a_zip_after_other_data_is_listed_by_its_end_record(tmp_path: Path) -> None:
    data = b"#!/bin/sh\nexit 0\n" * 40 + _zip({"model.pt": _PICKLE})

    assert archive_holding_model(_write(tmp_path, "installer.zip", data)) is ArchiveKind.ZIP


def test_a_zip_member_is_named_by_every_name_a_reader_gives_it(tmp_path: Path) -> None:
    unicode_path = b"model.pkl"
    info = zipfile.ZipInfo("readme.txt")
    info.extra = (
        struct.pack("<HHBL", 0x7075, 5 + len(unicode_path), 1, zlib.crc32(b"readme.txt"))
        + unicode_path
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(info, b"x")
    cut = _zip({"model.pklX.txt": _PICKLE}).replace(b"model.pklX.txt", b"model.pkl\x00.txt")

    assert archive_holding_model(_write(tmp_path, "unicode.zip", buffer.getvalue())) is not None
    assert archive_holding_model(_write(tmp_path, "cut.zip", cut)) is not None


def test_a_zip64_end_record_is_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 1)
    data = _zip({"a.txt": b"x", "b.txt": b"y", "model.joblib": _PICKLE})
    monkeypatch.undo()

    assert b"PK\x06\x06" in data
    assert archive_holding_model(_write(tmp_path, "big.zip", data)) is ArchiveKind.ZIP


def test_a_global_pax_record_that_names_every_member_makes_a_tar_unlisted(
    tmp_path: Path,
) -> None:
    data = _tar({"a.txt": b"x"}, pax_headers={"path": "model.pkl"})

    assert archive_holding_model(_write(tmp_path, "global.tar", data)) is ArchiveKind.TAR


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("damaged.tar.gz", b"\x1f\x8b\x08\x00" + b"\xff" * 200),
        ("cut.tar", _tar(_WITHOUT_MODEL)[:700]),
        ("cut.tar.xz", lzma.compress(_tar(_WITHOUT_MODEL))[:120]),
        ("no-end.zip", b"PK\x03\x04" + bytes(200)),
    ],
    ids=lambda value: value if isinstance(value, str) else "",
)
def test_an_archive_that_cannot_be_listed_to_its_end_counts_as_holding_a_model(
    tmp_path: Path, name: str, data: bytes
) -> None:
    assert archive_holding_model(_write(tmp_path, name, data)) is not None


def test_a_zip_declaring_more_members_than_the_bound_is_not_read_and_is_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(archive_members, "MAX_ENTRIES", 2)

    data = _zip({"a.txt": b"", "b.txt": b"", "c.txt": b""})

    assert archive_holding_model(_write(tmp_path, "many.zip", data)) is ArchiveKind.ZIP


def test_a_chain_of_long_names_ends_at_the_block_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(archive_members, "MAX_TAR_BLOCKS", 40)
    long_name = tarfile.TarInfo("././@LongLink")
    long_name.type = tarfile.GNUTYPE_LONGNAME
    long_name.size = 5
    block = long_name.tobuf(tarfile.GNU_FORMAT) + b"a.txt".ljust(tarfile.BLOCKSIZE, b"\x00")
    data = block * 200 + _tar({"a.txt": b"x"}, tarfile.GNU_FORMAT)

    assert archive_holding_model(_write(tmp_path, "chain.tar", data)) is ArchiveKind.TAR


def test_an_extended_header_past_its_bound_is_not_read_and_lists_the_tar(
    tmp_path: Path,
) -> None:
    long_name = tarfile.TarInfo("././@LongLink")
    long_name.type = tarfile.GNUTYPE_LONGNAME
    long_name.size = archive_members.MAX_EXTENDED_HEADER_BYTES + 1
    data = long_name.tobuf(tarfile.GNU_FORMAT) + bytes(4 * tarfile.BLOCKSIZE)

    assert archive_holding_model(_write(tmp_path, "huge-name.tar", data)) is ArchiveKind.TAR


class _CountingZlib(archive_members._Zlib):
    produced = 0

    def decompress(self, data: bytes, max_length: int = -1, /) -> bytes:
        out = super().decompress(data, max_length)
        _CountingZlib.produced += len(out)
        return out


def test_a_compressed_tar_is_decompressed_no_further_than_its_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    limit = 1024 * 1024
    monkeypatch.setattr(archive_members, "MIN_INFLATE_BYTES", limit)
    monkeypatch.setattr(
        archive_members,
        "_CODECS",
        ((archive_members._CODECS[0][0], _CountingZlib), *archive_members._CODECS[1:]),
    )
    _CountingZlib.produced = 0
    data = gzip.compress(_tar({"zeros.txt": bytes(16 * limit), "model.pkl": _PICKLE}), 9)

    assert archive_holding_model(_write(tmp_path, "bomb.tar.gz", data)) is ArchiveKind.TAR
    assert _CountingZlib.produced <= limit + 64 * 1024


@pytest.mark.parametrize(
    ("member", "named"),
    [
        ("weights/model.pkl", True),
        ("Model.PT", True),
        ("model.p" + chr(0x212A) + "l", True),
        ("ckpt/archive/storages", True),
        ("w/model.bin", True),
        ("clf.sav", True),
        ("x.pkl.gz", True),
        ("saved_model.pb", True),
        ("w.safetensors", True),
        ("w.keras", True),
        ("train.h5", False),
        ("train.hdf5", False),
        ("weights.pkl/", False),
        ("README", False),
        ("setup.py", False),
        ("rows.csv", False),
    ],
)
def test_a_member_is_named_as_a_model_by_its_last_part(member: str, *, named: bool) -> None:
    assert named_as_archived_model(member) is named
