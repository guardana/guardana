"""Files a real loader would import from are never cleared by reading them differently.

Each case is built in code and imports the harmless `builtins.len`. Where a case depends on
how CPython parses a stream, a recording unpickler whose `find_class` raises before any
import shows whether a load reaches the import; nothing is ever unpickled.
"""

import bz2
import gzip
import hashlib
import io
import lzma
import pickle
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.core import inventory
from guardana.core.report import Finding
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import _compressed, pickle_opcode
from guardana.rules.supply_chain._zip import declared_directory_start
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_HEADER = b"\x80\x02"
_CALL = b"cbuiltins\nlen\n(S'x'\ntR."
_IMPORT = "builtins.len"
_PLAIN = b"\x80\x02}q\x00."
_UNSCANNED = "Unscanned model file"


class _Reached(Exception):  # noqa: N818 - a recorded import, not an error
    pass


def _reaches_find_class(data: bytes) -> bool:
    """Whether any CPython unpickler, under the encodings loaders pass, reaches an import."""
    for base in (pickle.Unpickler, pickle._Unpickler):

        class Recording(base):  # type: ignore[valid-type,misc]
            def find_class(self, module: str, name: str) -> object:
                raise _Reached(f"{module}.{name}")

        for encoding in ("ASCII", "utf-8"):
            try:
                Recording(io.BytesIO(data), encoding=encoding).load()
            except _Reached:
                return True
            except Exception:  # noqa: S112 - any other end is a load that stopped
                continue
    return False


def _run(tmp_path: Path, name: str, content: bytes) -> tuple[list[Finding], RuleContext]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    ctx = RuleContext()
    return list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx)), ctx


def _critical(findings: list[Finding]) -> list[str]:
    return [f.evidence.summary for f in findings if f.severity is Severity.CRITICAL]


def _unscanned(findings: list[Finding]) -> list[str]:
    return [f.evidence.summary for f in findings if f.title == _UNSCANNED]


def _assert_flagged(findings: list[Finding]) -> None:
    assert any(_IMPORT in summary for summary in _critical(findings)), findings


def _zip(*members: tuple[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


def _torch_zip(data_pkl: bytes) -> bytes:
    return _zip(("archive/data.pkl", data_pkl), ("archive/version", b"3\n"))


def _tar(*members: tuple[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


# INT, LONG, FLOAT and GET arguments CPython reads and `pickletools.genops` refuses.
_DIFFERENTIAL_PREFIXES = {
    "int-hex": b"I0x10\n0",
    "long-hex": b"L0x10L\n0",
    "int-nul": b"I16\x00zz\n0",
    "long-nul": b"L16\x00zzL\n0",
    "float-nul": b"F1.0\x00zz\n0",
    "get-nul": b"Np1\n0g1\x00zz\n0",
    "string-utf8": b"S'\xc3\xa9'\n0",
}
_CONTROL_PREFIX = b"I16\n0"


@pytest.mark.parametrize("prefix", _DIFFERENTIAL_PREFIXES.values(), ids=_DIFFERENTIAL_PREFIXES)
def test_a_stream_cpython_reads_past_an_argument_reports_the_import_after_it(
    tmp_path: Path, prefix: bytes
) -> None:
    stream = _HEADER + prefix + _CALL
    assert _reaches_find_class(stream)

    findings, _ctx = _run(tmp_path, "model.pkl", stream)

    _assert_flagged(findings)


def test_the_decimal_control_is_flagged(tmp_path: Path) -> None:
    findings, _ctx = _run(tmp_path, "model.pkl", _HEADER + _CONTROL_PREFIX + _CALL)

    _assert_flagged(findings)


_DIFFERENTIAL_STREAMS = {
    **{label: _HEADER + prefix + _CALL for label, prefix in _DIFFERENTIAL_PREFIXES.items()},
    "headerless-int-hex": b"I0x10\n0" + _CALL,
    "global-bad-escape": _HEADER + b"cbuilt\\x\nlen\n0" + _CALL,
    "int-octal": _HEADER + b"I010\n0" + _CALL,
    "int-underscore": _HEADER + b"I1_0\n0" + _CALL,
    "put-get-whitespace": _HEADER + b"Np 1 \n0g1 \n0" + _CALL,
    "control": _HEADER + _CONTROL_PREFIX + _CALL,
}


@pytest.mark.parametrize("stream", _DIFFERENTIAL_STREAMS.values(), ids=_DIFFERENTIAL_STREAMS)
def test_no_stream_that_reaches_an_import_in_cpython_is_reported_clean(
    tmp_path: Path, stream: bytes
) -> None:
    assert _reaches_find_class(stream)

    findings, ctx = _run(tmp_path, "model.pt", _torch_zip(stream))

    assert _critical(findings) or (_unscanned(findings) and ctx.shortfalls())


@pytest.mark.parametrize("prefix", [b"I0x10\n0", b"L0x10L\n0"], ids=["int", "long"])
def test_a_torch_zip_whose_data_pkl_hides_behind_a_hex_integer_is_flagged(
    tmp_path: Path, prefix: bytes
) -> None:
    findings, _ctx = _run(tmp_path, "model.pt", _torch_zip(_HEADER + prefix + _CALL))

    _assert_flagged(findings)


def test_a_plain_zip_member_hiding_behind_a_hex_integer_is_flagged(tmp_path: Path) -> None:
    findings, _ctx = _run(
        tmp_path, "bundle.zip", _zip(("model.pkl", _HEADER + b"I0x10\n0" + _CALL))
    )

    _assert_flagged(findings)


def test_a_legacy_torch_file_whose_fourth_pickle_hides_behind_a_hex_integer_is_flagged(
    tmp_path: Path,
) -> None:
    magic = pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)
    version = pickle.dumps(1001, protocol=2)
    sys_info = pickle.dumps({"protocol_version": 1001, "little_endian": True}, protocol=2)
    content = magic + version + sys_info + _HEADER + b"I0x10\n0" + _CALL

    findings, _ctx = _run(tmp_path, "model.pt", content)

    _assert_flagged(findings)


def test_a_legacy_tar_pickle_member_hiding_behind_a_hex_integer_is_flagged(
    tmp_path: Path,
) -> None:
    content = _tar(("pickle", _HEADER + b"I0x10\n0" + _CALL))

    findings, _ctx = _run(tmp_path, "model.pt", content)

    _assert_flagged(findings)


def _local_header(name: str, data: bytes) -> tuple[bytes, int]:
    crc = zlib.crc32(data)
    encoded = name.encode()
    header = struct.pack(
        "<4s5H3L2H", b"PK\x03\x04", 20, 0, 0, 0, 0, crc, len(data), len(data), len(encoded), 0
    )
    return header + encoded + data, crc


def _directory_entry(name: str, data: bytes, crc: int, offset: int) -> bytes:
    encoded = name.encode()
    return (
        struct.pack(
            "<4s6H3L5H2L",
            b"PK\x01\x02",
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(encoded),
            0,
            0,
            0,
            0,
            0,
            offset,
        )
        + encoded
    )


def _two_directory_zip(declared: bytes, shifted: bytes) -> bytes:
    """A zip whose end record declares one directory while `zipfile` reads the next one."""
    out = b""
    first: list[tuple[str, bytes, int, int]] = []
    second: list[tuple[str, bytes, int, int]] = []
    for name, data in (("archive/data.pkl", declared), ("archive/version", b"3\n")):
        record, crc = _local_header(name, data)
        first.append((name, data, crc, len(out)))
        out += record
    out += bytes(256)
    for name, data in (("archive/data.pkl", shifted), ("archive/version", b"3\n")):
        record, crc = _local_header(name, data)
        second.append((name, data, crc, len(out)))
        out += record
    first_directory = b"".join(_directory_entry(*entry) for entry in first)
    declared_at = len(out)
    out += first_directory
    shift = len(first_directory)
    out += b"".join(_directory_entry(n, d, c, o - shift) for n, d, c, o in second)
    return out + struct.pack(
        "<4s4H2LH", b"PK\x05\x06", 0, 0, 2, 2, len(first_directory), declared_at, 0
    )


def test_a_zip_whose_readers_disagree_on_the_directory_is_unscanned(tmp_path: Path) -> None:
    content = _two_directory_zip(_HEADER + _CALL, _PLAIN)
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.read("archive/data.pkl") == _PLAIN

    findings, ctx = _run(tmp_path, "model.pt", content)

    assert any("disagree" in summary for summary in _unscanned(findings)), findings
    assert [gap.name for gap in ctx.shortfalls()] == [str(tmp_path / "model.pt")]


def test_the_directory_control_is_flagged(tmp_path: Path) -> None:
    findings, _ctx = _run(tmp_path, "model.pt", _torch_zip(_HEADER + _CALL))

    _assert_flagged(findings)


def _as_zip64(content: bytes) -> bytes:
    """Rewrite a small zip's end record as a ZIP64 end record, locator and plain end record."""
    end_at = content.rindex(b"PK\x05\x06")
    fields = list(struct.unpack("<4s4H2LH", content[end_at : end_at + 22]))
    size, offset = fields[5], fields[6]
    record = struct.pack(
        "<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, fields[3], fields[4], size, offset
    )
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, end_at, 1)
    fields[6] = 0xFFFFFFFF
    return content[:end_at] + record + locator + struct.pack("<4s4H2LH", *fields)


def test_a_zip64_whose_records_agree_is_read(tmp_path: Path) -> None:
    content = _as_zip64(_torch_zip(_HEADER + _CALL))
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.read("archive/data.pkl") == _HEADER + _CALL

    findings, _ctx = _run(tmp_path, "model.pt", content)

    _assert_flagged(findings)
    assert _unscanned(findings) == []


def test_a_zip64_behind_a_prefix_is_unscanned(tmp_path: Path) -> None:
    content = b"\x00" + _as_zip64(_torch_zip(_PLAIN))

    findings, _ctx = _run(tmp_path, "bundle.zip", content)

    assert any("disagree" in summary for summary in _unscanned(findings)), findings


def test_members_sharing_a_name_are_each_read(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("archive/data.pkl", _HEADER + _CALL)
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("archive/data.pkl", _PLAIN)

    findings, _ctx = _run(tmp_path, "model.pt", buffer.getvalue())

    _assert_flagged(findings)


def _npy_of_objects(pickled: bytes) -> bytes:
    header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    header = header.ljust(117) + b"\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header + pickled


def test_an_npz_that_starts_with_an_end_record_is_opened_as_a_zip(tmp_path: Path) -> None:
    archive = _zip(("x.npy", _npy_of_objects(_HEADER + _CALL)))

    findings, ctx = _run(tmp_path, "data.npz", b"PK\x05\x06junk\n." + archive)

    assert _unscanned(findings), findings
    assert list(ctx.shortfalls())


def test_the_npz_control_is_flagged(tmp_path: Path) -> None:
    findings, _ctx = _run(tmp_path, "data.npz", _zip(("x.npy", _npy_of_objects(_HEADER + _CALL))))

    _assert_flagged(findings)


def test_an_empty_zip_is_examined_without_noise(tmp_path: Path) -> None:
    findings, ctx = _run(tmp_path, "data.npz", _zip())

    assert findings == []
    assert list(ctx.shortfalls()) == []
    assert str(tmp_path / "data.npz") in ctx.examined_paths()


def test_a_plain_zip_behind_a_leading_byte_is_unscanned(tmp_path: Path) -> None:
    content = b"\x00" + _zip(("model.pkl", _HEADER + _CALL))
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.namelist() == ["model.pkl"]

    findings, ctx = _run(tmp_path, "bundle.zip", content)

    assert any("disagree" in summary for summary in _unscanned(findings)), findings
    assert str(tmp_path / "bundle.zip") in ctx.examined_paths()


def test_the_plain_zip_control_is_flagged(tmp_path: Path) -> None:
    findings, _ctx = _run(tmp_path, "bundle.zip", _zip(("model.pkl", _HEADER + _CALL)))

    _assert_flagged(findings)


_STORAGE_ARGS = _HEADER + b"(X\x01\x00\x00\x000X\x03\x00\x00\x00cpuctorch\nFloatStorage\ntq\x00."
_UNKNOWN_STORAGE_ARGS = (
    _HEADER + b"(X\x01\x00\x00\x000X\x03\x00\x00\x00cpuctorch\nQInt8Storage\ntq\x00."
)
_FLOATS = struct.pack("<q", 2) + b"cos\nsyst"
_TENSOR_ARGS = _HEADER + b"(X\x01\x00\x00\x000X\x01\x00\x00\x000K\x00tq\x00."
_TENSOR_LAYOUT = struct.pack("<i", 1) + bytes(4) + struct.pack("<qqq", 2, 1, 0)


def _count(value: int) -> bytes:
    return pickle.dumps(value, protocol=2)


def _legacy(storages: bytes, tensors: bytes) -> bytes:
    sys_info = pickle.dumps({"protocol_version": 1001, "little_endian": True}, protocol=2)
    return _tar(
        ("sys_info", sys_info),
        ("pickle", _PLAIN),
        ("storages", storages),
        ("tensors", tensors),
    )


_HONEST_STORAGES = _count(1) + _STORAGE_ARGS + _FLOATS + pickle.dumps([], protocol=2)
_HONEST_TENSORS = _count(1) + _TENSOR_ARGS + _TENSOR_LAYOUT


def test_an_honest_legacy_tar_with_raw_storages_is_clean(tmp_path: Path) -> None:
    findings, ctx = _run(tmp_path, "model.pt", _legacy(_HONEST_STORAGES, _HONEST_TENSORS))

    assert findings == []
    assert list(ctx.shortfalls()) == []


_LEGACY_TRICKS = {
    "second-storage": (
        _count(2) + _STORAGE_ARGS + _FLOATS + _HEADER + _CALL,
        _HONEST_TENSORS,
    ),
    "storage-views": (_count(1) + _STORAGE_ARGS + _FLOATS + _HEADER + _CALL, _HONEST_TENSORS),
    "second-tensor": (
        _HONEST_STORAGES,
        _count(2) + _TENSOR_ARGS + _TENSOR_LAYOUT + _HEADER + _CALL,
    ),
}


@pytest.mark.parametrize("members", _LEGACY_TRICKS.values(), ids=_LEGACY_TRICKS)
def test_a_pickle_after_raw_bytes_in_a_legacy_member_is_flagged(
    tmp_path: Path, members: tuple[bytes, bytes]
) -> None:
    findings, _ctx = _run(tmp_path, "model.pt", _legacy(*members))

    _assert_flagged(findings)


def test_the_legacy_control_without_raw_bytes_is_flagged(tmp_path: Path) -> None:
    storages = _count(2) + _STORAGE_ARGS + _HEADER + _CALL

    findings, _ctx = _run(tmp_path, "model.pt", _tar(("storages", storages)))

    _assert_flagged(findings)


_UNFOLLOWED = {
    "unknown-storage-type": _count(2) + _UNKNOWN_STORAGE_ARGS + _FLOATS + _HEADER + _CALL,
    "text-count": b"I2\n." + _STORAGE_ARGS + _FLOATS + _HEADER + _CALL,
}


@pytest.mark.parametrize("storages", _UNFOLLOWED.values(), ids=_UNFOLLOWED)
def test_a_legacy_layout_that_cannot_be_followed_is_unscanned(
    tmp_path: Path, storages: bytes
) -> None:
    findings, ctx = _run(tmp_path, "model.pt", _legacy(storages, _HONEST_TENSORS))

    assert any("cannot follow" in summary for summary in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def _zlib_streams(*parts: bytes) -> bytes:
    return b"".join(zlib.compress(part) for part in parts)


def _legacy_zfile(data: bytes) -> bytes:
    return b"ZF" + f"{len(data):#x}".ljust(19).encode() + zlib.compress(data)


_PAYLOAD = _HEADER + _CALL
_COMPRESSED = {
    "sav-zlib": ("model.sav", zlib.compress(_PAYLOAD)),
    "p-gzip": ("model.p", gzip.compress(_PAYLOAD)),
    "model-bz2": ("word2vec.model", bz2.compress(_PAYLOAD)),
    "joblib-zlib": ("model.joblib", zlib.compress(_PAYLOAD)),
    "pkl-lzma": ("model.pkl", lzma.compress(_PAYLOAD, format=lzma.FORMAT_ALONE)),
    "pkl-xz": ("model.pkl", lzma.compress(_PAYLOAD)),
    "pkl-legacy": ("model.pkl", _legacy_zfile(_PAYLOAD)),
    "bin-gzip": ("pytorch_model.bin", gzip.compress(_PAYLOAD)),
    "split-streams": ("model.joblib", _zlib_streams(_HEADER + b"(", _CALL)),
    "pkl-gz-name": ("model.pkl.gz", gzip.compress(_PAYLOAD)),
}


@pytest.mark.parametrize(("name", "content"), _COMPRESSED.values(), ids=_COMPRESSED)
def test_a_compressed_pickle_is_read_as_joblib_reads_it(
    tmp_path: Path, name: str, content: bytes
) -> None:
    findings, _ctx = _run(tmp_path, name, content)

    _assert_flagged(findings)


def test_the_compressed_control_is_flagged(tmp_path: Path) -> None:
    findings, _ctx = _run(tmp_path, "model.sav", _PAYLOAD)

    _assert_flagged(findings)


_UNDECODABLE = {
    "lz4": ("model.pkl", b"\x04\x22\x4d\x18" + bytes(32)),
    "corrupt-gzip": ("pytorch_model.bin", b"\x1f\x8b\x08\x00" + b"\xff" * 32),
    "corrupt-bz2": ("model.sav", b"BZh9" + b"\xff" * 32),
    "lzma-huge-dictionary": ("model.pkl", b"\x5d\x00\x00\x00\x80" + bytes(16)),
}


@pytest.mark.parametrize(("name", "content"), _UNDECODABLE.values(), ids=_UNDECODABLE)
def test_a_compressed_file_this_scanner_cannot_decode_is_unscanned(
    tmp_path: Path, name: str, content: bytes
) -> None:
    findings, ctx = _run(tmp_path, name, content)

    assert any("compressed" in summary for summary in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


@pytest.mark.parametrize(
    "head", [b"x\xff\xfe", b"\x5d\x00\x00\x01\x00\xff\xff"], ids=["zlib", "lzma"]
)
def test_bytes_that_only_look_compressed_are_left_alone_under_a_shared_name(
    tmp_path: Path, head: bytes
) -> None:
    findings, ctx = _run(tmp_path, "data.bin", head + b"\xff" * 64)

    assert findings == []
    assert list(ctx.shortfalls()) == []


def test_a_decompression_bomb_ends_at_the_bound_as_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_opcode, "_MEMBER_MAX_BYTES", 64 * 1024)
    bomb = gzip.compress(_HEADER + b"(" * (4 * 1024 * 1024))

    findings, ctx = _run(tmp_path, "model.pkl", bomb)

    assert any("larger than" in summary for summary in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def test_a_compressed_member_of_a_plain_zip_is_read(tmp_path: Path) -> None:
    content = _zip(("model.joblib", gzip.compress(_PAYLOAD)))

    findings, _ctx = _run(tmp_path, "bundle.zip", content)

    _assert_flagged(findings)


def test_a_compressed_member_of_a_tar_is_read(tmp_path: Path) -> None:
    content = _tar(("model.sav", zlib.compress(_PAYLOAD)))

    findings, _ctx = _run(tmp_path, "bundle.tar", content)

    _assert_flagged(findings)


def test_an_undecodable_compressed_member_is_unscanned(tmp_path: Path) -> None:
    content = _zip(("model.joblib", b"\x04\x22\x4d\x18" + bytes(32)))

    findings, ctx = _run(tmp_path, "bundle.zip", content)

    assert any("model.joblib" in summary for summary in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def test_members_decompressing_past_the_archive_bound_are_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_opcode, "_MAX_PICKLE_BYTES", 1024)
    filler = gzip.compress(_HEADER + b"N0" * 1024 + b".")
    content = _zip(("a.joblib", filler), ("b.joblib", gzip.compress(_PAYLOAD)))

    findings, ctx = _run(tmp_path, "bundle.zip", content)

    assert any("b.joblib" in summary for summary in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


@pytest.mark.parametrize("member", ["weights.pkl.gz", "model.joblib.xz", "state.pkl.z"])
def test_a_member_named_as_a_compressed_pickle_is_read(tmp_path: Path, member: str) -> None:
    content = _zip((member, gzip.compress(_PAYLOAD)))

    findings, _ctx = _run(tmp_path, "bundle.zip", content)

    _assert_flagged(findings)


@pytest.mark.parametrize(
    ("archive", "build"),
    [("bundle.zip", _zip), ("bundle.tar", _tar)],
    ids=["zip", "tar"],
)
@pytest.mark.parametrize(
    "member", ["model.safetensors", "model.gguf", "model.keras", "model.onnx", "model.tar.gz"]
)
def test_a_model_member_no_reader_here_opens_is_named_unscanned(
    tmp_path: Path, archive: str, build: Callable[..., bytes], member: str
) -> None:
    findings, ctx = _run(tmp_path, archive, build((f"dir/{member}", b"\x00" * 64)))

    assert any(member in summary for summary in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def test_an_honest_torch_checkpoint_stays_clean(tmp_path: Path) -> None:
    data_pkl = (
        b"\x80\x02}q\x00X\x06\x00\x00\x00weightq\x01ctorch._utils\n_rebuild_tensor_v2\nq\x02"
        b"((X\x07\x00\x00\x00storageq\x03ctorch\nFloatStorage\nq\x04X\x01\x00\x00\x000q\x05"
        b"X\x03\x00\x00\x00cpuq\x06K\x04tq\x07QK\x00K\x04\x85q\x08K\x01\x85q\x09\x89"
        b"ccollections\nOrderedDict\nq\x0a)Rq\x0btq\x0cRq\x0ds."
    )
    content = _zip(
        ("archive/data.pkl", data_pkl),
        ("archive/byteorder", b"little"),
        ("archive/data/0", b"\x1f\x8b\x08\x00" + b"x\x9c" + bytes(10)),
        ("archive/data/1", b"x\x9c" + bytes(14)),
        ("archive/version", b"3\n"),
        ("archive/.data/serialization_id", b"1234567890123456789012345678901234567890"),
    )

    findings, ctx = _run(tmp_path, "model.pt", content)

    assert findings == []
    assert list(ctx.shortfalls()) == []
    assert str(tmp_path / "model.pt") in ctx.examined_paths()


_INVENTORY_SUFFIX_SETS = ("_PICKLE_SNIFFED_SUFFIXES", "_SNIFFED_SUFFIXES", "_HDF5_SUFFIXES")
_INVENTORY_FILE_SETS = ("_MODEL_DIRECTORY_FILES",)
"""Inventory names that may or may not exist in this tree; each found one is checked too."""


def test_every_model_name_the_inventory_knows_is_read_or_named_inside_an_archive() -> None:
    names = [
        *(f"model{suffix}" for suffix in inventory._MODEL_SUFFIXES),
        *(f"model{ending}" for ending, _format in inventory._MODEL_NAME_ENDINGS),
        *inventory._MODEL_NAMES,
        *(
            f"model{suffix}"
            for key in _INVENTORY_SUFFIX_SETS
            for suffix in getattr(inventory, key, ())
        ),
        *(name for key in _INVENTORY_FILE_SETS for name in getattr(inventory, key, ())),
        "model.hdf",
        "model.weights",
        "model.tf",
        "model.weights.h5",
        "config.json",
    ]

    assert [
        name
        for name in names
        if not (pickle_opcode._model_named(name) or pickle_opcode._unread_model(name))
    ] == []


@pytest.mark.parametrize("member", ["model.hdf", "model.weights", "model.tf", "config.json"])
def test_keras_files_in_a_model_archive_are_named_and_in_a_plain_one_are_not(
    tmp_path: Path, member: str
) -> None:
    content = _zip(("archive/data.pkl", _PLAIN), (f"archive/{member}", bytes(64)))

    model_findings, _ctx = _run(tmp_path / "model", "model.pt", content)
    plain_findings, plain_ctx = _run(tmp_path / "plain", "bundle.zip", _zip((member, bytes(64))))

    assert any(member in summary for summary in _unscanned(model_findings)), model_findings
    assert plain_findings == []
    assert list(plain_ctx.shortfalls()) == []


def _framed(first: bytes, frame_bytes: int) -> bytes:
    """A protocol 4 pickle whose frame runs `frame_bytes` past the start of `first`."""
    body = first.ljust(frame_bytes, b"\x00")
    return b"\x80\x04\x95" + struct.pack("<Q", len(body)) + body


def _second_load_reaches_find_class(data: bytes) -> bool:
    """Whether a second `load` from a file without `peek` reaches an import."""

    class Recording(pickle._Unpickler):
        def find_class(self, module: str, name: str) -> object:
            raise _Reached(f"{module}.{name}")

    handle = io.BytesIO(data)
    try:
        Recording(handle).load()
        Recording(handle).load()
    except _Reached:
        return True
    except Exception:
        return False
    return False


def test_a_pickle_read_from_where_a_frame_ends_past_its_stop_is_flagged(tmp_path: Path) -> None:
    content = _framed(b"K\x01. ", 64) + _HEADER + _CALL
    assert _second_load_reaches_find_class(content)

    findings, _ctx = _run(tmp_path, "model.pt", content)

    _assert_flagged(findings)


def test_a_legacy_storages_count_framed_over_its_storage_is_not_clean(tmp_path: Path) -> None:
    count = _framed(b"K\x01." + _STORAGE_ARGS + struct.pack("<q", 32), 0)
    storages = count + (_HEADER + _CALL).ljust(128, b"\x00") + pickle.dumps([], protocol=2)

    findings, ctx = _run(tmp_path, "model.pt", _legacy(storages, _HONEST_TENSORS))

    assert _critical(findings) or (_unscanned(findings) and ctx.shortfalls())
    assert any("cannot follow" in summary for summary in _unscanned(findings)), findings


def _bad_trailer(data: bytes) -> bytes:
    stored = zlib.compressobj(0)
    good = stored.compress(data + bytes(20_000)) + stored.flush()
    return good[:-4] + bytes(4)


def test_a_compressed_pickle_damaged_after_its_import_is_flagged(tmp_path: Path) -> None:
    findings, ctx = _run(tmp_path, "model.sav", _bad_trailer(_PAYLOAD))

    _assert_flagged(findings)
    assert any("damaged" in summary for summary in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def test_a_compressed_member_damaged_after_its_import_is_flagged(tmp_path: Path) -> None:
    findings, _ctx = _run(tmp_path, "bundle.zip", _zip(("model.joblib", _bad_trailer(_PAYLOAD))))

    _assert_flagged(findings)


def test_an_lzma_pickle_damaged_after_its_import_is_flagged(tmp_path: Path) -> None:
    noise = b"".join(hashlib.sha256(i.to_bytes(4, "little")).digest() for i in range(1500))
    packed = lzma.compress(_PAYLOAD + noise, format=lzma.FORMAT_ALONE)
    assert len(packed) > 4 * 8192
    damaged = packed[:-3] + b"\xff\xff\xff"

    findings, _ctx = _run(tmp_path, "model.p", damaged)

    _assert_flagged(findings)


@pytest.mark.parametrize("name", ["model.pkl.z", "bundle.zip"])
def test_concatenated_empty_streams_cost_a_bounded_number_of_decoder_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    calls = [0]
    real_feed = _compressed._ZlibStream.feed

    def counting(self: _compressed._ZlibStream, data: bytes, room: int) -> bytes:
        calls[0] += 1
        return real_feed(self, data, room)

    monkeypatch.setattr(_compressed._ZlibStream, "feed", counting)
    streams = zlib.compress(b"") * (256 * 1024 // len(zlib.compress(b"")))
    content = streams if name.endswith(".z") else _zip(("model.joblib", streams))

    findings, ctx = _run(tmp_path, name, content)

    assert calls[0] <= _compressed.MAX_STREAMS + len(streams) // 8192 + 2
    assert any("streams" in summary for summary in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def test_zip64_records_that_declare_different_directories_have_no_declared_start(
    tmp_path: Path,
) -> None:
    content = _torch_zip(_PLAIN)
    end_at = content.rindex(b"PK\x05\x06")
    fields = list(struct.unpack("<4s4H2LH", content[end_at : end_at + 22]))

    def record(offset: int) -> bytes:
        return struct.pack(
            "<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, fields[3], fields[4], fields[5], offset
        )

    named = record(0)
    fields[6] = 0xFFFFFFFF
    data = (
        content[:end_at]
        + named
        + record(struct.unpack("<L", content[end_at + 16 : end_at + 20])[0])
        + struct.pack("<4sLQL", b"PK\x06\x07", 0, end_at, 1)
        + struct.pack("<4s4H2LH", *fields)
    )
    path = tmp_path / "model.pt"
    path.write_bytes(data)

    with path.open("rb") as handle:
        assert declared_directory_start(handle) is None


@pytest.mark.parametrize(("archive", "build"), [("data.zip", _zip), ("data.tar", _tar)])
def test_an_hdf5_file_in_a_plain_archive_is_taken_for_a_dataset(
    tmp_path: Path, archive: str, build: Callable[..., bytes]
) -> None:
    findings, ctx = _run(tmp_path, archive, build(("train.h5", b"\x89HDF\r\n\x1a\n" + bytes(64))))

    assert findings == []
    assert list(ctx.shortfalls()) == []


def test_an_hdf5_file_in_a_model_archive_is_named_unscanned(tmp_path: Path) -> None:
    content = _zip(("archive/data.pkl", _PLAIN), ("archive/extra.h5", bytes(64)))

    findings, _ctx = _run(tmp_path, "model.pt", content)

    assert any("archive/extra.h5" in summary for summary in _unscanned(findings)), findings


def test_an_unknown_string_escape_does_not_stop_the_scan(tmp_path: Path) -> None:
    findings, _ctx = _run(tmp_path, "model.pkl", _HEADER + b"S'\\q'\n0" + _CALL)

    _assert_flagged(findings)


@pytest.mark.parametrize(
    "stream",
    [b"cbuiltins\nlenX", b"(ibuiltins\nlenX", _HEADER + b"cbuiltins\nlenX"],
    ids=["global", "inst", "global-after-header"],
)
@pytest.mark.parametrize("name", ["model.pkl", "model.sav"])
def test_an_import_on_an_unterminated_last_line_is_flagged(
    tmp_path: Path, stream: bytes, name: str
) -> None:
    assert _reaches_find_class(stream)

    findings, _ctx = _run(tmp_path, name, stream)

    _assert_flagged(findings)


def _unicode_path_zip(stored: str, shown: str) -> bytes:
    body = struct.pack("<BL", 1, zlib.crc32(stored.encode())) + shown.encode()
    info = zipfile.ZipInfo(stored)
    info.extra = struct.pack("<HH", 0x7075, len(body)) + body
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(info, _PAYLOAD)
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("stored", "shown"),
    [("model.pkl", "notes.txt"), ("notes.txt", "model.pkl")],
    ids=["stored-as-model", "shown-as-model"],
)
def test_a_member_named_as_a_model_by_any_zip_reader_is_read(
    tmp_path: Path, stored: str, shown: str
) -> None:
    findings, _ctx = _run(tmp_path, "bundle.zip", _unicode_path_zip(stored, shown))

    _assert_flagged(findings)


def _text(value: str) -> bytes:
    encoded = value.encode()
    return b"X" + struct.pack("<I", len(encoded)) + encoded


def test_an_import_after_an_embedded_pickle_is_reported(tmp_path: Path) -> None:
    wrapper = b"cjoblib.numpy_pickle\nNumpyArrayWrapper\n)\x81}b"
    inner = b"\x80\x02]q\x00."
    benign = _HEADER + wrapper + inner + b"."
    trick = _HEADER + _text("builtins") + _text("len") + wrapper + inner + b"0\x93" + _text("x")
    trick += b"\x85R."

    benign_findings, _ctx = _run(tmp_path / "benign", "model.joblib", benign)
    findings, _ctx = _run(tmp_path / "trick", "model.joblib", trick)

    assert not any(_IMPORT in summary for summary in _critical(benign_findings))
    _assert_flagged(findings)


def test_a_unicode_path_newer_zip_readers_refuse_is_unscanned_on_every_python(
    tmp_path: Path,
) -> None:
    body = struct.pack("<BL", 1, zlib.crc32(b"model.pkl")) + b"\xff\xfe"
    info = zipfile.ZipInfo("model.pkl")
    info.extra = struct.pack("<HH", 0x7075, len(body)) + body
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(info, _PLAIN)

    findings, ctx = _run(tmp_path, "bundle.zip", buffer.getvalue())

    assert any("malformed zip" in summary for summary in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def _straddling(padding: int) -> bytes:
    """A frame whose last BINUNICODE runs past its end: C on 3.11 and 3.12 reads on from there."""
    marker = b"\x8c\x08builtins\x8c\x03len\x93"
    frame = b"\x8c\x01a0" * padding + b"X" + struct.pack("<I", 64) + b"T" * 5
    framed = b"\x80\x04\x95" + struct.pack("<Q", len(frame)) + frame + b"U" * 59
    return framed + b"B" + struct.pack("<I", len(marker)) + marker + b"0."


@pytest.mark.parametrize("padding", [1, 3000], ids=["small", "big"])
def test_a_read_that_crosses_a_frame_end_is_unscanned(tmp_path: Path, padding: int) -> None:
    findings, ctx = _run(tmp_path, "model.pkl", _straddling(padding))

    assert any("crosses the end of a frame" in s for s in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def test_a_torch_member_that_crosses_a_frame_end_is_unscanned(tmp_path: Path) -> None:
    findings, ctx = _run(tmp_path, "model.pt", _torch_zip(_straddling(1)))

    assert any("crosses the end of a frame" in s for s in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def _hand_zip(
    data: bytes, *, packed: int, size: int, local_method: int = 0, central_method: int = 0
) -> bytes:
    name = b"archive/data.pkl"
    crc = zlib.crc32(data[:packed])
    local = struct.pack(
        "<4s5H3L2H",
        b"PK\x03\x04",
        20,
        0,
        local_method,
        0x6000,
        0x5945,
        crc,
        packed,
        size,
        len(name),
        0,
    )
    central = struct.pack(
        "<4s6H3L5H2L",
        b"PK\x01\x02",
        20,
        20,
        0,
        central_method,
        0x6000,
        0x5945,
        crc,
        packed,
        size,
        len(name),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    body = local + name + data
    directory = central + name
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(directory), len(body), 0)
    return body + directory + end


def test_a_stored_member_whose_sizes_differ_is_unscanned(tmp_path: Path) -> None:
    content = _hand_zip(_PLAIN + _PAYLOAD, packed=len(_PLAIN), size=len(_PLAIN + _PAYLOAD))
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.read("archive/data.pkl") == _PLAIN

    findings, ctx = _run(tmp_path, "model.pt", content)

    assert any("differs from its size" in s for s in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def test_a_local_header_that_disagrees_with_the_directory_is_unscanned(tmp_path: Path) -> None:
    content = _hand_zip(_PAYLOAD, packed=len(_PAYLOAD), size=len(_PAYLOAD), local_method=8)

    findings, ctx = _run(tmp_path, "model.pt", content)

    assert any("local header" in s for s in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def test_a_legacy_storages_hard_link_is_walked_as_torch_reads_it(tmp_path: Path) -> None:
    storages = _count(2) + _STORAGE_ARGS + _FLOATS + _HEADER + _CALL
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in (("x.pkl", storages), ("pickle", _PLAIN), ("tensors", _count(0))):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("storages")
        link.type = tarfile.LNKTYPE
        link.linkname = "x.pkl"
        archive.addfile(link)

    findings, _ctx = _run(tmp_path, "model.pt", buffer.getvalue())

    _assert_flagged(findings)


def _utf8_flagged_zip() -> bytes:
    name = b"archive/\xff\xfe"
    crc = zlib.crc32(b"x")
    local = struct.pack("<4s5H3L2H", b"PK\x03\x04", 20, 0x800, 0, 0, 0, crc, 1, 1, len(name), 0)
    central = struct.pack(
        "<4s6H3L5H2L",
        b"PK\x01\x02",
        20,
        20,
        0x800,
        0,
        0,
        0,
        crc,
        1,
        1,
        len(name),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    body = local + name + b"x"
    directory = central + name
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(directory), len(body), 0)
    return body + directory + end


def _undecodable_member_zip() -> bytes:
    name = b"archive/junk"
    data = b"\xff" * 16
    crc = zlib.crc32(data)
    local = struct.pack("<4s5H3L2H", b"PK\x03\x04", 20, 0, 8, 0, 0, crc, 16, 32, len(name), 0)
    central = struct.pack(
        "<4s6H3L5H2L",
        b"PK\x01\x02",
        20,
        20,
        0,
        8,
        0,
        0,
        crc,
        16,
        32,
        len(name),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    body = local + name + data
    directory = central + name
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(directory), len(body), 0)
    return body + directory + end


@pytest.mark.parametrize(
    "content", [_utf8_flagged_zip(), _undecodable_member_zip()], ids=["name", "deflate"]
)
def test_a_zip_zipfile_raises_on_is_unscanned_and_the_scan_goes_on(
    tmp_path: Path, content: bytes
) -> None:
    (tmp_path / "z_evil.pkl").write_bytes(_PAYLOAD)

    findings, ctx = _run(tmp_path, "a_model.pt", content)

    _assert_flagged(findings)
    assert _unscanned(findings), findings
    assert any(gap.name.endswith("a_model.pt") for gap in ctx.shortfalls())


def test_a_member_with_two_zip64_fields_is_unscanned(tmp_path: Path) -> None:
    name = b"archive/data.pkl"
    packer = zlib.compressobj(9, zlib.DEFLATED, -15)
    data = packer.compress(_PAYLOAD) + packer.flush()
    crc = zlib.crc32(_PAYLOAD)
    extra = struct.pack("<HHQ", 1, 8, 0xFFFFFFFF) + struct.pack("<HHQ", 1, 8, len(_PAYLOAD))
    local = struct.pack(
        "<4s5H3L2H", b"PK\x03\x04", 45, 0, 8, 0, 0, crc, len(data), 0xFFFFFFFF, len(name), 0
    )
    central = struct.pack(
        "<4s6H3L5H2L",
        b"PK\x01\x02",
        45,
        45,
        0,
        8,
        0,
        0,
        crc,
        len(data),
        0xFFFFFFFF,
        len(name),
        len(extra),
        0,
        0,
        0,
        0,
        0,
    )
    body = local + name + data
    directory = central + name + extra
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(directory), len(body), 0)

    findings, ctx = _run(tmp_path, "model.pt", body + directory + end)

    assert any(
        "repeats an extra field" in s or "malformed zip" in s for s in _unscanned(findings)
    ), findings
    assert list(ctx.shortfalls())


def test_a_torch_pickle_that_ends_before_its_stop_is_unscanned(tmp_path: Path) -> None:
    cut_short = _HEADER + b"X" + struct.pack("<I", 24) + b"abc"

    findings, ctx = _run(tmp_path, "model.pt", _torch_zip(cut_short))

    assert any("ends before its STOP" in s for s in _unscanned(findings)), findings
    assert list(ctx.shortfalls())


def _empty_end_record(at: int) -> bytes:
    return struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0, 0, 0, at, 0)


@pytest.mark.parametrize(
    "body", [_npy_of_objects(_PAYLOAD), _PAYLOAD], ids=["object-array", "raw-pickle"]
)
def test_a_plain_zip_whose_first_bytes_are_not_a_zip_is_also_read_as_a_stream(
    tmp_path: Path, body: bytes
) -> None:
    findings, _ctx = _run(tmp_path, "arrays.zip", body + _empty_end_record(len(body)))

    _assert_flagged(findings)


@pytest.mark.parametrize("member", ["weights", "weights.dat"])
def test_a_plain_zip_member_that_starts_as_an_object_array_is_read_whatever_its_name(
    tmp_path: Path, member: str
) -> None:
    findings, _ctx = _run(tmp_path, "arrays.zip", _zip((member, _npy_of_objects(_PAYLOAD))))

    _assert_flagged(findings)


def test_a_plain_zip_of_text_stays_clean(tmp_path: Path) -> None:
    findings, ctx = _run(tmp_path, "docs.zip", _zip(("README", b"hello\n"), ("notes.dat", b"1")))

    assert findings == []
    assert list(ctx.shortfalls()) == []


def _odd_member_zip(
    name: bytes, *, flags: int, method: int, local_name: bytes | None = None
) -> bytes:
    data = b"\xff" * 16
    crc = zlib.crc32(data)
    stored_name = name if local_name is None else local_name
    local = struct.pack(
        "<4s5H3L2H", b"PK\x03\x04", 20, flags, method, 0, 0, crc, 16, 16, len(stored_name), 0
    )
    central = struct.pack(
        "<4s6H3L5H2L",
        b"PK\x01\x02",
        20,
        20,
        flags,
        method,
        0,
        0,
        crc,
        16,
        16,
        len(name),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    body = local + stored_name + data
    directory = central + name
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(directory), len(body), 0)
    return body + directory + end


@pytest.mark.parametrize(
    ("flags", "method"), [(0x1, 0), (0, 9)], ids=["encrypted", "unsupported-method"]
)
def test_a_plain_zip_member_no_loader_can_open_is_left_alone(
    tmp_path: Path, flags: int, method: int
) -> None:
    content = _odd_member_zip(b"report.docx", flags=flags, method=method)

    findings, ctx = _run(tmp_path, "docs.zip", content)

    assert findings == []
    assert list(ctx.shortfalls()) == []


def test_a_plain_zip_member_whose_headers_disagree_is_unscanned(tmp_path: Path) -> None:
    content = _odd_member_zip(b"report.docx", flags=0, method=0, local_name=b"report.docy")

    findings, ctx = _run(tmp_path, "docs.zip", content)

    assert _unscanned(findings), findings
    assert list(ctx.shortfalls())
