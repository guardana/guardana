"""A compressed tar is read as `tar` extracts it, for the members a person then loads.

`tar xzf`, `tar xjf` and `tar xJf` decompress the whole archive and extract every member,
and a member named as a model is then loaded by that name. Every archive here is built in
code; nothing is unpickled.
"""

import bz2
import gzip
import io
import lzma
import struct
import tarfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import ScanResult, ShortfallKind
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import pickle_opcode
from guardana.rules.supply_chain._tar import TAR_EXTENDED_HEADER_MAX_BYTES

_RULE_ID = "guardana.supply_chain.pickle_opcode"
_SYSTEM = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R."
_FLOATS = b"(dp0\nVweights\np1\n(lp2\nF0.0\naF1.0\nas."
_COMPRESSORS: dict[str, Callable[[bytes], bytes]] = {
    ".tar.gz": gzip.compress,
    ".tgz": gzip.compress,
    ".tar.bz2": bz2.compress,
    ".tbz2": bz2.compress,
    ".tar.xz": lzma.compress,
    ".txz": lzma.compress,
}


def _tar(*entries: tarfile.TarInfo | tuple[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for entry in entries:
            if isinstance(entry, tarfile.TarInfo):
                archive.addfile(entry)
                continue
            name, data = entry
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _run(tmp_path: Path, name: str, content: bytes) -> ScanResult:
    (tmp_path / name).write_bytes(content)
    registry = Registry()
    registry.register_rule(pickle_opcode.PickleOpcodeRule())
    return Runner(registry=registry, profile=Profile(name="t", policy=Policy())).run(
        ArtifactTarget(tmp_path)
    )


def _critical(result: ScanResult) -> list[str]:
    return [
        f.evidence.detail or ""
        for f in result.findings
        if f.rule_id == _RULE_ID and f.severity.name == "CRITICAL"
    ]


def _unscanned(result: ScanResult) -> list[str]:
    return [f.evidence.summary for f in result.unverified if f.rule_id == _RULE_ID]


def _unread(result: ScanResult) -> list[str]:
    return [
        gap.name
        for gap in result.coverage_shortfall
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
    ]


@pytest.mark.parametrize("ending", list(_COMPRESSORS))
def test_a_model_member_of_a_compressed_tar_is_read(tmp_path: Path, ending: str) -> None:
    content = _COMPRESSORS[ending](_tar(("README.md", b"weights\n"), ("model.pkl", _SYSTEM)))

    result = _run(tmp_path, f"weights{ending}", content)

    assert _critical(result) == [f"os.system in weights{ending}::model.pkl"]
    assert _unscanned(result) == []


def test_a_compressed_tar_of_data_stays_quiet(tmp_path: Path) -> None:
    content = gzip.compress(_tar(("data/train.csv", b"a,b\n1,2\n"), ("README.md", b"# data\n")))

    result = _run(tmp_path, "dataset.tar.gz", content)

    assert not result.findings
    assert not result.unverified
    assert _unread(result) == []


def test_a_model_tarball_that_was_read_is_no_longer_an_unexamined_component(
    tmp_path: Path,
) -> None:
    """`model.tar.gz` is a SageMaker model; once its members are read it has been examined."""
    content = gzip.compress(_tar(("model.pkl", _FLOATS), ("code/inference.txt", b"x\n")))

    result = _run(tmp_path, "model.tar.gz", content)

    assert not result.findings
    assert not result.unverified
    assert _unread(result) == []


def test_members_in_later_gzip_streams_are_read(tmp_path: Path) -> None:
    """`gzip -d` decodes streams written back to back as one, so `tar` sees them all."""
    archive = _tar(("README.md", b"x" * 4096), ("model.pkl", _SYSTEM))
    content = gzip.compress(archive[:2048]) + gzip.compress(archive[2048:])

    result = _run(tmp_path, "weights.tgz", content)

    assert _critical(result) == ["os.system in weights.tgz::model.pkl"]


def test_a_compressed_tar_past_its_decompression_bound_is_not_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_opcode, "_COMPRESSED_TAR_MIN_BYTES", 64 * 1024)
    monkeypatch.setattr(pickle_opcode, "_COMPRESSED_TAR_MAX_RATIO", 2)
    content = gzip.compress(_tar(("padding.bin", bytes(1024 * 1024)), ("model.pkl", _SYSTEM)))

    result = _run(tmp_path, "weights.tar.gz", content)

    assert _critical(result) == []
    assert any("once decompressed" in summary for summary in _unscanned(result))
    assert _unread(result) == [str(tmp_path / "weights.tar.gz")]


def test_a_cut_compressed_tar_is_not_scanned(tmp_path: Path) -> None:
    content = gzip.compress(_tar(("padding.txt", bytes(range(256)) * 512), ("model.pkl", _SYSTEM)))

    result = _run(tmp_path, "weights.tar.gz", content[: len(content) // 2])

    assert _critical(result) == []
    assert any("gzip-compressed tar" in summary for summary in _unscanned(result))
    assert _unread(result) == [str(tmp_path / "weights.tar.gz")]


def test_bytes_after_the_last_stream_that_gzip_ignores_do_not_fail_the_read(
    tmp_path: Path,
) -> None:
    content = gzip.compress(_tar(("model.pkl", _SYSTEM))) + bytes(512)

    result = _run(tmp_path, "weights.tar.gz", content)

    assert _critical(result) == ["os.system in weights.tar.gz::model.pkl"]
    assert _unscanned(result) == []


def test_a_link_named_as_a_model_in_a_compressed_tar_is_not_scanned(tmp_path: Path) -> None:
    link = tarfile.TarInfo("model.pkl")
    link.type = tarfile.SYMTYPE
    link.linkname = "blob"
    content = gzip.compress(_tar(("blob", _SYSTEM), link))

    result = _run(tmp_path, "weights.tar.gz", content)

    assert any("link" in summary and "model.pkl" in summary for summary in _unscanned(result))
    assert _unread(result) == [str(tmp_path / "weights.tar.gz")]


def test_a_model_format_no_reader_opens_inside_a_compressed_tar_is_not_scanned(
    tmp_path: Path,
) -> None:
    content = gzip.compress(_tar(("model.onnx", b"\x08\x07")))

    result = _run(tmp_path, "weights.tar.gz", content)

    assert any("model.onnx" in summary for summary in _unscanned(result))


def test_an_oversized_extended_header_in_a_compressed_tar_is_refused_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []
    real_open: Callable[..., object] = tarfile.open

    def recording(*args: object, **kwargs: object) -> object:
        calls.append(args)
        return real_open(*args, **kwargs)

    monkeypatch.setattr(tarfile, "open", recording)
    pax = tarfile.TarInfo("././@PaxHeader")
    pax.type = tarfile.XHDTYPE
    pax.size = 200 * 1024 * 1024
    content = gzip.compress(pax.tobuf(tarfile.USTAR_FORMAT) + bytes(2 * tarfile.BLOCKSIZE))

    result = _run(tmp_path, "weights.tar.gz", content)

    assert calls == []
    summaries = _unscanned(result)
    assert any(str(TAR_EXTENDED_HEADER_MAX_BYTES) in summary for summary in summaries)


def test_a_file_named_as_a_compressed_tar_that_is_a_plain_tar_is_read(tmp_path: Path) -> None:
    result = _run(tmp_path, "weights.tar.gz", _tar(("model.pkl", _SYSTEM)))

    assert _critical(result) == ["os.system in weights.tar.gz::model.pkl"]


@pytest.mark.parametrize(
    "content",
    [gzip.compress(b"plain text, not a tar\n" * 40), b"not compressed at all\n"],
    ids=["compressed-text", "plain-text"],
)
def test_a_file_named_as_a_compressed_tar_that_holds_no_tar_stays_quiet(
    tmp_path: Path, content: bytes
) -> None:
    result = _run(tmp_path, "notes.tar.gz", content)

    assert not result.findings
    assert not result.unverified
    assert _unread(result) == []


def _with_unreadable_mtime(header: bytes) -> bytes:
    """Return a header whose checksum holds but whose mtime `tarfile` refuses to parse."""
    block = bytearray(header[: tarfile.BLOCKSIZE])
    block[136:148] = b"zzzzzzzzzzz\x00"
    block[148:156] = b" " * 8
    block[148:156] = f"{sum(block):06o}\x00 ".encode()
    return bytes(block) + header[tarfile.BLOCKSIZE :]


def test_a_header_tarfile_stops_at_before_a_model_member_is_not_scanned(tmp_path: Path) -> None:
    """`tarfile` ends its listing at that header, so the members after it go unread."""
    plain = _tar(("README.md", b"x\n"), ("decoy.txt", b""), ("model.pkl", _SYSTEM))
    decoy = 2 * tarfile.BLOCKSIZE
    archive = plain[:decoy] + _with_unreadable_mtime(plain[decoy:])

    result = _run(tmp_path, "weights.tar.gz", gzip.compress(archive))

    assert _critical(result) == []
    assert f"tar has a damaged header at byte {decoy}; not scanned" in _unscanned(result)
    assert _unread(result) == [str(tmp_path / "weights.tar.gz")]


_TAR_COMPRESSORS: dict[str, Callable[[bytes], bytes]] = {
    "gzip": gzip.compress,
    "bz2": bz2.compress,
    "xz": lzma.compress,
}


@pytest.mark.parametrize("codec", list(_TAR_COMPRESSORS))
def test_a_tar_whose_bytes_are_a_compressed_tar_is_read_as_one(tmp_path: Path, codec: str) -> None:
    """`tar xf` and `tarfile.open` detect the compression whatever the file is named."""
    content = _TAR_COMPRESSORS[codec](_tar(("README.md", b"x\n"), ("model.pkl", _SYSTEM)))

    result = _run(tmp_path, "weights.tar", content)

    assert _critical(result) == ["os.system in weights.tar::model.pkl"]
    assert _unscanned(result) == []


@pytest.mark.parametrize("name", ["weights.tar", "weights.tar.gz"])
def test_a_compressed_tar_whose_first_bytes_are_also_a_pickle_is_read_both_ways(
    tmp_path: Path, name: str
) -> None:
    """joblib decompresses the same bytes and unpickles from the first header's name field."""
    content = gzip.compress(_tar(("cos\nsystem\n(S'id'\ntR.", b"x\n")))

    result = _run(tmp_path, name, content)

    assert _critical(result) == [f"os.system in {name}"]


@pytest.mark.parametrize(
    "content",
    [gzip.compress(_SYSTEM), lzma.compress(_SYSTEM), _SYSTEM],
    ids=["gzip", "xz", "uncompressed"],
)
def test_a_file_named_as_a_compressed_tar_that_holds_a_bare_pickle_is_read(
    tmp_path: Path, content: bytes
) -> None:
    """joblib.load picks its decompressor by the first bytes, whatever the name says."""
    result = _run(tmp_path, "weights.tar.gz", content)

    assert _critical(result) == ["os.system in weights.tar.gz"]


def test_a_file_named_as_a_compressed_tar_that_holds_a_clean_pickle_stays_quiet(
    tmp_path: Path,
) -> None:
    result = _run(tmp_path, "weights.tar.gz", gzip.compress(_FLOATS))

    assert not result.findings
    assert not result.unverified


@pytest.mark.parametrize(
    ("name", "compress"),
    [
        ("bundle.gz", gzip.compress),
        ("bundle.xz", lzma.compress),
        ("bundle.bz2", bz2.compress),
        ("bundle", gzip.compress),
        ("bundle.dat", gzip.compress),
        ("bundle.dat.gz", gzip.compress),
    ],
)
def test_a_compressed_tar_under_a_name_that_says_no_tar_is_read_as_one(
    tmp_path: Path, name: str, compress: Callable[[bytes], bytes]
) -> None:
    """`tar xf` detects a compressed tar by its content, whatever the file is named."""
    content = compress(_tar(("README.md", b"x\n"), ("model.pkl", _SYSTEM)))

    result = _run(tmp_path, name, content)

    assert _critical(result) == [f"os.system in {name}::model.pkl"]


def _gzip_with_long_name(data: bytes, name_bytes: int) -> bytes:
    """Gzip `data` behind an original-file-name field `name_bytes` long."""
    deflate = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    body = deflate.compress(data) + deflate.flush()
    header = b"\x1f\x8b\x08\x08" + bytes(4) + b"\x00\x03" + b"n" * name_bytes + b"\x00"
    trailer = struct.pack("<II", zlib.crc32(data), len(data) & 0xFFFFFFFF)
    return header + body + trailer


def test_a_compressed_tar_whose_header_hides_past_the_first_read_is_still_read(
    tmp_path: Path,
) -> None:
    """A gzip header can be longer than the bounded first read, which then shows no tar."""
    content = _gzip_with_long_name(_tar(("model.pkl", _SYSTEM)), 128 * 1024)

    result = _run(tmp_path, "bundle.gz", content)

    assert _critical(result) == ["os.system in bundle.gz::model.pkl"]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("rows.csv.gz", gzip.compress(b"a,b\n1,2\n" * 5000)),
        ("data.gz", gzip.compress(_tar(("data/train.csv", b"a,b\n1,2\n")))),
        ("notes.xz", lzma.compress(b"plain text\n" * 100)),
        ("damaged.gz", gzip.compress(b"a,b\n1,2\n" * 5000)[:200]),
    ],
)
def test_a_compressed_file_under_a_codec_name_that_holds_no_model_stays_quiet(
    tmp_path: Path, name: str, content: bytes
) -> None:
    result = _run(tmp_path, name, content)

    assert not result.findings
    assert not result.unverified
    assert _unread(result) == []


def test_a_file_named_only_by_a_codec_that_cannot_be_decompressed_is_not_scanned(
    tmp_path: Path,
) -> None:
    """`tar` or joblib may still read what this scanner cannot decompress, so it is not cleared."""
    content = b"\x1f\x8b\x08\x00" + bytes(6) + b"\xff" * 64

    result = _run(tmp_path, "bundle.gz", content)

    assert any("cannot decompress" in summary for summary in _unscanned(result))
    assert _unread(result) == [str(tmp_path / "bundle.gz")]
