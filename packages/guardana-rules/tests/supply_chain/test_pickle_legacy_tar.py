"""A file `tarfile` opens as a tar is read as `torch.load` reads it, whatever it is named.

`torch.load` opens any file that is not a zip as a legacy tar first, and `tarfile` accepts
a v7 header without the `ustar` magic; `pickle.load` reads the same bytes as one stream.
Every archive here is built in code; nothing is unpickled.
"""

import io
import struct
import tarfile
import zipfile
from pathlib import Path
from typing import IO, NoReturn

import pytest
from guardana.core.report import Finding
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_SYSTEM = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R."
_PLAIN = b"\x80\x02}q\x00."
_UNSCANNED = "Unscanned model file"
_NAMES = ("model.pt", "model.pth", "model.pth.tar", "bundle.tar", "pytorch_model.bin")


def _header(name: str, size: int, *, v7: bool) -> bytes:
    info = tarfile.TarInfo(name)
    info.size = size
    block = bytearray(info.tobuf(tarfile.USTAR_FORMAT))
    if v7:
        block[257:265] = bytes(8)
        block[148:156] = b" " * 8
        block[148:156] = b"%06o\x00 " % sum(block)
    return bytes(block)


def _legacy_tar(*members: tuple[str, bytes], v7: bool) -> bytes:
    blocks = b"".join(
        _header(name, len(data), v7=v7) + data + bytes(-len(data) % tarfile.BLOCKSIZE)
        for name, data in members
    )
    return blocks + bytes(2 * tarfile.BLOCKSIZE)


def _layout(first: tuple[str, bytes], pickled: bytes) -> tuple[tuple[str, bytes], ...]:
    return (first, ("pickle", pickled), ("tensors", _PLAIN), ("storages", _PLAIN))


_NATURAL = ("sys_info", _PLAIN)
_CRAFTED = ("N.", b"")
"""A first member whose name is a whole pickle, so the file read as one stream is clean."""


def _run(tmp_path: Path, name: str, content: bytes) -> tuple[list[Finding], RuleContext]:
    (tmp_path / name).write_bytes(content)
    ctx = RuleContext()
    return list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx)), ctx


@pytest.mark.parametrize("first", [_NATURAL, _CRAFTED], ids=["natural", "crafted-first-name"])
@pytest.mark.parametrize("name", _NAMES)
@pytest.mark.parametrize("v7", [False, True], ids=["ustar", "v7"])
def test_a_legacy_torch_tar_is_read_as_a_tar_whatever_it_is_named(
    tmp_path: Path, v7: bool, name: str, first: tuple[str, bytes]
) -> None:
    findings, _ctx = _run(tmp_path, name, _legacy_tar(*_layout(first, _SYSTEM), v7=v7))

    critical = [f for f in findings if f.severity is Severity.CRITICAL]
    assert [f.evidence.detail for f in critical] == [f"os.system in {name}::pickle"]


@pytest.mark.parametrize("first", [_NATURAL, _CRAFTED], ids=["natural", "crafted-first-name"])
@pytest.mark.parametrize("name", _NAMES)
@pytest.mark.parametrize("v7", [False, True], ids=["ustar", "v7"])
def test_a_clean_legacy_torch_tar_is_examined_without_a_finding_or_a_shortfall(
    tmp_path: Path, v7: bool, name: str, first: tuple[str, bytes]
) -> None:
    findings, ctx = _run(tmp_path, name, _legacy_tar(*_layout(first, _PLAIN), v7=v7))

    assert findings == []
    assert list(ctx.shortfalls()) == []
    assert str(tmp_path / name) in ctx.examined_paths()


def test_a_tar_whose_first_name_is_a_malicious_pickle_reports_both_readings(
    tmp_path: Path,
) -> None:
    content = _legacy_tar(("cos\nsystem\n(Vid\ntR.", b""), ("pickle", _PLAIN), v7=True)

    findings, _ctx = _run(tmp_path, "model.pth", content)

    assert [f.evidence.detail for f in findings] == ["os.system in model.pth"]


def test_a_raw_pickle_that_is_not_a_tar_is_read_as_a_stream_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refusing_open(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("a file that is not a tar was opened as one")

    monkeypatch.setattr(tarfile, "open", refusing_open)
    content = _SYSTEM + _PLAIN * 128

    findings, _ctx = _run(tmp_path, "model.pkl", content)

    assert [f.evidence.detail for f in findings] == ["os.system in model.pkl"]


def test_a_file_that_is_neither_a_pickle_nor_a_tar_is_unread_as_before(tmp_path: Path) -> None:
    findings, ctx = _run(tmp_path, "model.pth", b"\xff" * (4 * tarfile.BLOCKSIZE))

    assert [f.title for f in findings] == [_UNSCANNED]
    assert [gap.name for gap in ctx.shortfalls()] == [str(tmp_path / "model.pth")]


def test_a_first_block_with_a_bad_checksum_is_not_read_as_a_tar(tmp_path: Path) -> None:
    content = bytearray(_legacy_tar(*_layout(_CRAFTED, _SYSTEM), v7=True))
    content[148:156] = b"0000000\x00"

    findings, ctx = _run(tmp_path, "model.pth", bytes(content))

    assert findings == []
    assert list(ctx.shortfalls()) == []


def _link(name: str, target: str, kind: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info


@pytest.mark.parametrize("kind", [tarfile.LNKTYPE, tarfile.SYMTYPE], ids=["hard", "symbolic"])
def test_links_to_one_member_read_its_bytes_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: bytes
) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("a.pkl")
        info.size = len(_SYSTEM)
        archive.addfile(info, io.BytesIO(_SYSTEM))
        for n in range(20):
            archive.addfile(_link(f"l{n}.pkl", "a.pkl", kind))
    extracted: list[str] = []
    real_extractfile = tarfile.TarFile.extractfile

    def counting_extractfile(
        self: tarfile.TarFile, member: str | tarfile.TarInfo
    ) -> IO[bytes] | None:
        extracted.append(member if isinstance(member, str) else member.name)
        return real_extractfile(self, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", counting_extractfile)

    findings, _ctx = _run(tmp_path, "bundle.tar", buffer.getvalue())

    assert extracted == ["a.pkl"]
    assert [f.evidence.summary.rsplit(": ", 1)[-1] for f in findings] == ["os.system"]


def test_a_tensor_storage_whose_first_block_sums_like_a_tar_header_stays_quiet(
    tmp_path: Path,
) -> None:
    values = [0.0] * 1024
    values[0] = values[1] = -0.0
    storage = struct.pack("<1024f", *values)
    try:
        tarfile.TarInfo.frombuf(storage[: tarfile.BLOCKSIZE], tarfile.ENCODING, "strict")
    except tarfile.HeaderError:
        pytest.fail("these values no longer form a tar header; this fixture no longer bites")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/data.pkl", _PLAIN)
        archive.writestr("archive/data/0", storage)

    findings, ctx = _run(tmp_path, "model.pt", buffer.getvalue())

    assert findings == []
    assert list(ctx.shortfalls()) == []


def test_a_pickle_named_tar_holding_no_model_is_read_strictly_as_a_stream(
    tmp_path: Path,
) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("notes.txt")
        info.size = 3
        archive.addfile(info, io.BytesIO(b"abc"))

    findings, ctx = _run(tmp_path, "model.pkl", buffer.getvalue())

    assert [f.title for f in findings] == [_UNSCANNED]
    assert [gap.name for gap in ctx.shortfalls()] == [str(tmp_path / "model.pkl")]


def test_a_pickle_member_shaped_like_an_archive_is_still_read_as_a_stream(
    tmp_path: Path,
) -> None:
    member = bytearray(_SYSTEM.ljust(tarfile.BLOCKSIZE, b"\x00"))
    member[257:262] = b"ustar"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/data.pkl", bytes(member))

    findings, _ctx = _run(tmp_path, "model.pt", buffer.getvalue())

    critical = [f for f in findings if f.severity is Severity.CRITICAL]
    assert [f.evidence.detail for f in critical] == ["os.system in model.pt::archive/data.pkl"]
    assert _UNSCANNED in [f.title for f in findings]
