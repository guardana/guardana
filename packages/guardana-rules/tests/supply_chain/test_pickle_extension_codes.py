"""An extension code names a callable through a registry only the loading process holds.

A stream a loader reads as a pickle that uses one is left unread wherever it sits, raw or
inside an archive: from its first byte when it is named as a pickle, in the four pickles
after a legacy `torch.save` magic number, under a name other formats share when the stream
reaches a clean STOP, and wherever a pickle opens with a PROTO opcode. Tensor storages,
numeric arrays and other bytes that merely contain the opcode stay quiet. Every file here
is built in code; nothing is unpickled.
"""

import gzip
import io
import math
import pickle
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_EXTENSION_CODES = {
    "EXT1": b"\x82\x01",
    "EXT2": b"\x83\x01\x00",
    "EXT4": b"\x84\x01\x00\x00\x00",
}
_UNSCANNED = "Unscanned model file"
_RAW_EXTENSION = (
    "pickle names a callable by an extension-registry code this scanner cannot resolve; "
    "not scanned past it"
)
_Wrap = Callable[[bytes], bytes]
_NPY_OBJECTS = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }\n"
_NPY_FLOATS = b"{'descr': '<f4', 'fortran_order': False, 'shape': (1,), }\n"


def _stream(code: bytes) -> bytes:
    return b"\x80\x02" + code + b"."


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _tar(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _array(header: bytes, data: bytes) -> bytes:
    return b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header + data


def _object_array(stream: bytes) -> bytes:
    return _array(_NPY_OBJECTS, stream)


def _unread(ctx: RuleContext) -> list[str]:
    return [
        gap.name
        for gap in ctx.shortfalls()
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
        and gap.detail.startswith("guardana.supply_chain.pickle_opcode could not read it: ")
    ]


def _run(tmp_path: Path, name: str, content: bytes) -> tuple[list[tuple[str, str]], RuleContext]:
    path = tmp_path / name
    path.write_bytes(content)
    ctx = RuleContext()
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))
    return [(f.title, f.evidence.summary) for f in findings], ctx


_CONTAINERS: dict[str, tuple[str, str, str, _Wrap]] = {
    "zip-checkpoint-member": (
        "model.pt",
        "zip",
        "archive/data.pkl",
        lambda stream: _zip({"archive/version": b"3", "archive/data.pkl": stream}),
    ),
    "plain-zip-sniffed-member": (
        "bundle.zip",
        "zip",
        "weights.bin",
        lambda stream: _zip({"weights.bin": stream}),
    ),
    "npz-object-array": (
        "arrays.npz",
        "zip",
        "x.npy",
        lambda stream: _zip({"x.npy": _object_array(stream)}),
    ),
    "legacy-tar-member": (
        "checkpoint.tar",
        "tar",
        "pickle",
        lambda stream: _tar({"sys_info": pickle.dumps({}, protocol=2), "pickle": stream}),
    ),
    "plain-tar-sniffed-member": (
        "bundle.tar",
        "tar",
        "model.bin",
        lambda stream: _tar({"model.bin": stream}),
    ),
}


@pytest.mark.parametrize("code", _EXTENSION_CODES.values(), ids=_EXTENSION_CODES.keys())
@pytest.mark.parametrize("container", _CONTAINERS.values(), ids=_CONTAINERS.keys())
def test_an_archive_member_using_an_extension_code_is_unscanned_and_named(
    tmp_path: Path, container: tuple[str, str, str, _Wrap], code: bytes
) -> None:
    name, kind, member, build = container

    findings, ctx = _run(tmp_path, name, build(_stream(code)))

    assert findings == [
        (
            _UNSCANNED,
            f"{kind} member is a pickle that names a callable by an extension-registry code "
            f"this scanner cannot resolve ({member})",
        )
    ]
    assert _unread(ctx) == [str(tmp_path / name)]


@pytest.mark.parametrize("code", _EXTENSION_CODES.values(), ids=_EXTENSION_CODES.keys())
@pytest.mark.parametrize(
    ("name", "wrap"),
    [
        ("model.pt", lambda stream: _zip({"archive/data.pkl": stream})),
        ("checkpoint.tar", lambda stream: _tar({"pickle": stream})),
    ],
    ids=["zip", "tar"],
)
def test_an_extension_code_has_the_verdict_of_the_same_bytes_as_a_raw_pickle(
    tmp_path: Path, name: str, wrap: _Wrap, code: bytes
) -> None:
    raw_dir, archived_dir = tmp_path / "raw", tmp_path / "archived"
    raw_dir.mkdir()
    archived_dir.mkdir()

    raw, raw_ctx = _run(raw_dir, "model.pkl", _stream(code))
    archived, archived_ctx = _run(archived_dir, name, wrap(_stream(code)))

    assert [title for title, _summary in raw] == [_UNSCANNED]
    assert [title for title, _summary in archived] == [_UNSCANNED]
    assert _unread(raw_ctx) == [str(raw_dir / "model.pkl")]
    assert _unread(archived_ctx) == [str(archived_dir / name)]


@pytest.mark.parametrize("code", _EXTENSION_CODES.values(), ids=_EXTENSION_CODES.keys())
def test_a_bin_that_is_a_pickle_using_an_extension_code_is_unscanned(
    tmp_path: Path, code: bytes
) -> None:
    findings, ctx = _run(tmp_path, "pytorch_model.bin", _stream(code))

    assert [title for title, _summary in findings] == [_UNSCANNED]
    assert _unread(ctx) == [str(tmp_path / "pytorch_model.bin")]


@pytest.mark.parametrize("header", [b"\x80\x00", b"\x80\x01", b"\x80\x02"], ids=["0", "1", "2"])
def test_an_extension_code_in_a_second_pickle_after_a_complete_one_is_unscanned(
    tmp_path: Path, header: bytes
) -> None:
    findings, ctx = _run(
        tmp_path, "model.pkl", pickle.dumps({}, protocol=2) + header + b"\x82\x01."
    )

    assert [title for title, _summary in findings] == [_UNSCANNED]
    assert _unread(ctx) == [str(tmp_path / "model.pkl")]


def test_a_tensor_storage_holding_an_extension_opcode_byte_stays_clean(tmp_path: Path) -> None:
    storage = b"\x82\x01\x00\x00" + bytes(range(256)) * 4

    findings, ctx = _run(
        tmp_path,
        "model.pt",
        _zip({"archive/data.pkl": pickle.dumps({}, protocol=2), "archive/data/0": storage}),
    )

    assert findings == []
    assert _unread(ctx) == []


def test_tensor_bytes_after_a_complete_pickle_stay_data_when_they_hold_an_extension_opcode(
    tmp_path: Path,
) -> None:
    trailing = b"\x82\x01\x00\x00" + bytes(range(256))

    findings, ctx = _run(
        tmp_path, "checkpoint.tar", _tar({"pickle": pickle.dumps({}, protocol=2) + trailing})
    )

    assert findings == []
    assert _unread(ctx) == []


_HEADERLESS_FIRST = b"I1\n." + _stream(_EXTENSION_CODES["EXT1"])


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("pytorch_model.bin", _HEADERLESS_FIRST),
        ("bundle.zip", _zip({"weights.bin": _HEADERLESS_FIRST})),
        ("bundle.tar", _tar({"model.bin": _HEADERLESS_FIRST})),
    ],
    ids=["bin", "zip-sniffed-member", "tar-sniffed-member"],
)
def test_a_sniffed_file_whose_later_pickle_uses_an_extension_code_is_unscanned(
    tmp_path: Path, name: str, content: bytes
) -> None:
    findings, ctx = _run(tmp_path, name, content)

    assert [title for title, _summary in findings] == [_UNSCANNED]
    assert _unread(ctx) == [str(tmp_path / name)]


def _legacy_checkpoint(numel: int) -> bytes:
    """A legacy `torch.save` stream: its pickles, then one storage's element count and bytes."""
    pickles = (
        0x1950A86A20F9469CFC6C,
        1001,
        {"protocol_version": 1001, "little_endian": True},
        {"weight": None},
        ["0"],
    )
    return (
        b"".join(pickle.dumps(value, protocol=2) for value in pickles)
        + numel.to_bytes(8, "little")
        + bytes(range(64))
    )


@pytest.mark.parametrize(
    "numel", [0x00820280, 0x01820280, 0x01820180], ids=["code-zero", "code-one", "protocol-1"]
)
def test_a_legacy_checkpoint_whose_storage_size_reads_as_an_extension_code_stays_clean(
    tmp_path: Path, numel: int
) -> None:
    """`torch.load` reads the storage size and bytes after the five pickles raw."""
    findings, ctx = _run(tmp_path, "model.pt", _legacy_checkpoint(numel))

    assert findings == []
    assert _unread(ctx) == []


_LEGACY_MAGIC_PICKLE = pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)
_LEGACY_FOLLOWING = (
    pickle.dumps(1001, protocol=2),
    pickle.dumps({"protocol_version": 1001}, protocol=2),
    pickle.dumps({"weight": None}, protocol=2),
    pickle.dumps(["0"], protocol=2),
)


_MAGIC = 0x1950A86A20F9469CFC6C.to_bytes(10, "little")
_MAGIC_FORMS = {
    "after-a-popped-value": b"N0\x8a\x0a" + _MAGIC + b".",
    "through-the-memo": b"\x8a\x0a" + _MAGIC + b"q\x000h\x00.",
    "text": b"L%dL\n." % 0x1950A86A20F9469CFC6C,
}


@pytest.mark.parametrize("magic", _MAGIC_FORMS.values(), ids=_MAGIC_FORMS.keys())
@pytest.mark.parametrize("name", ["model.pt", "pytorch_model.bin"])
def test_a_magic_number_a_first_pickle_returns_in_any_form_starts_the_legacy_pickles(
    tmp_path: Path, name: str, magic: bytes
) -> None:
    content = magic + b"M\xe9\x03.}.\x82\x01.]." + (1).to_bytes(8, "little") + bytes(4)

    findings, ctx = _run(tmp_path, name, content)

    assert findings == [(_UNSCANNED, _RAW_EXTENSION)]
    assert _unread(ctx) == [str(tmp_path / name)]


@pytest.mark.parametrize("name", ["model.pt", "pytorch_model.bin"])
@pytest.mark.parametrize("position", range(len(_LEGACY_FOLLOWING)))
def test_a_headerless_extension_code_in_a_pickle_torch_reads_after_its_magic_is_unscanned(
    tmp_path: Path, name: str, position: int
) -> None:
    """`torch.load` unpickles the four pickles after the magic, whatever they open with."""
    following = list(_LEGACY_FOLLOWING)
    following[position] = b"\x82\x01."
    content = _LEGACY_MAGIC_PICKLE + b"".join(following) + (1).to_bytes(8, "little") + bytes(4)

    findings, ctx = _run(tmp_path, name, content)

    assert findings == [(_UNSCANNED, _RAW_EXTENSION)]
    assert _unread(ctx) == [str(tmp_path / name)]


def test_extension_shaped_bytes_in_legacy_storage_data_stay_quiet(tmp_path: Path) -> None:
    content = (
        _LEGACY_MAGIC_PICKLE
        + b"".join(_LEGACY_FOLLOWING)
        + (3).to_bytes(8, "little")
        + b"\x82\x01.\x80\x01\x82\x01."
    )

    findings, ctx = _run(tmp_path, "model.pt", content)

    assert findings == []
    assert _unread(ctx) == []


def test_callables_before_an_extension_code_in_a_raw_pickle_do_not_clear_what_follows(
    tmp_path: Path,
) -> None:
    findings, ctx = _run(
        tmp_path, "model.pkl", b"\x80\x02cos\nsystem\n" + _EXTENSION_CODES["EXT1"] + b"."
    )

    assert [title for title, _summary in findings] == [
        "Dangerous pickle opcode (arbitrary code on load)",
        _UNSCANNED,
    ]
    assert findings[1][1] == _RAW_EXTENSION
    assert _unread(ctx) == [str(tmp_path / "model.pkl")]


def test_a_raw_pickle_using_an_extension_code_says_so(tmp_path: Path) -> None:
    findings, _ctx = _run(tmp_path, "model.pkl", _stream(_EXTENSION_CODES["EXT2"]))

    assert findings == [(_UNSCANNED, _RAW_EXTENSION)]


_UNHEADED_PREFIXES = {"protocol-0": b"\x80\x00", "protocol-1": b"\x80\x01", "no-header": b""}
"""What a stream of protocol 0 or 1 opens with: a PROTO opcode no writer emits, or nothing."""


def _unheaded(prefix: bytes) -> bytes:
    return prefix + b"\x82\x01U\x03abc\x85R."


_NO_STOP = b"\x82\x01\x00\x00" + bytes(range(256))
"""Bytes that open with an extension code and never reach a clean STOP."""


def _framed(stream: bytes) -> bytes:
    return b"\x80\x04\x95" + len(stream).to_bytes(8, "little") + stream


_NAMED_MEMBERS: dict[str, tuple[str, str, str, _Wrap]] = {
    "zip-checkpoint-pickle": (
        "model.pt",
        "zip",
        "archive/data.pkl",
        lambda stream: _zip({"archive/version": b"3", "archive/data.pkl": stream}),
    ),
    "zip-checkpoint-framed-pickle": (
        "model.pt",
        "zip",
        "archive/data.pkl",
        lambda stream: _zip({"archive/data.pkl": _framed(stream)}),
    ),
    "npz-object-array": (
        "arrays.npz",
        "zip",
        "x.npy",
        lambda stream: _zip({"x.npy": _object_array(stream)}),
    ),
    "legacy-tar-pickle": (
        "checkpoint.tar",
        "tar",
        "pickle",
        lambda stream: _tar({"sys_info": pickle.dumps({}, protocol=2), "pickle": stream}),
    ),
    "plain-zip-compressed-pickle": (
        "bundle.zip",
        "zip",
        "model.pkl.gz",
        lambda stream: _zip({"model.pkl.gz": gzip.compress(stream)}),
    ),
}


@pytest.mark.parametrize("prefix", _UNHEADED_PREFIXES.values(), ids=_UNHEADED_PREFIXES.keys())
@pytest.mark.parametrize("container", _NAMED_MEMBERS.values(), ids=_NAMED_MEMBERS.keys())
def test_a_member_named_as_a_pickle_is_unscanned_for_an_extension_code_without_a_modern_header(
    tmp_path: Path, container: tuple[str, str, str, _Wrap], prefix: bytes
) -> None:
    name, kind, member, build = container

    findings, ctx = _run(tmp_path, name, build(_unheaded(prefix)))

    assert findings == [
        (
            _UNSCANNED,
            f"{kind} member is a pickle that names a callable by an extension-registry code "
            f"this scanner cannot resolve ({member})",
        )
    ]
    assert _unread(ctx) == [str(tmp_path / name)]


_NAMED_FILES: dict[str, tuple[str, _Wrap]] = {
    "pkl": ("model.pkl", lambda stream: stream),
    "pt-stream": ("model.pt", lambda stream: stream),
    "compressed-pkl": ("model.pkl.gz", gzip.compress),
    "object-npy": ("weights.npy", _object_array),
}


@pytest.mark.parametrize("prefix", _UNHEADED_PREFIXES.values(), ids=_UNHEADED_PREFIXES.keys())
@pytest.mark.parametrize("file", _NAMED_FILES.values(), ids=_NAMED_FILES.keys())
def test_a_file_named_as_a_pickle_says_it_uses_an_extension_code_without_a_modern_header(
    tmp_path: Path, file: tuple[str, _Wrap], prefix: bytes
) -> None:
    name, build = file

    findings, ctx = _run(tmp_path, name, build(_unheaded(prefix)))

    assert findings == [(_UNSCANNED, _RAW_EXTENSION)]
    assert _unread(ctx) == [str(tmp_path / name)]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("pytorch_model.bin", _unheaded(b"\x80\x01")),
        ("model.sav", gzip.compress(_unheaded(b"\x80\x00"))),
        ("bundle.zip", _zip({"weights.bin": _unheaded(b"\x80\x01")})),
        ("bundle.zip", _zip({"README": b"text", "blob": _unheaded(b"\x80\x01")})),
        ("bundle.tar", _tar({"model.bin": _unheaded(b"\x80\x00")})),
    ],
    ids=["bin", "compressed-sav", "zip-sniffed-member", "zip-unnamed-member", "tar-sniffed-member"],
)
def test_a_sniffed_file_that_opens_with_any_proto_opcode_is_a_pickle_for_an_extension_code(
    tmp_path: Path, name: str, content: bytes
) -> None:
    findings, ctx = _run(tmp_path, name, content)

    assert [title for title, _summary in findings] == [_UNSCANNED]
    assert _unread(ctx) == [str(tmp_path / name)]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("pytorch_model.bin", _NO_STOP),
        ("model.sav", gzip.compress(_NO_STOP)),
        ("bundle.zip", _zip({"weights.bin": _NO_STOP})),
        ("bundle.zip", _zip({"README": b"text", "blob": _unheaded(b"")})),
        ("bundle.tar", _tar({"model.bin": _NO_STOP})),
        (
            "model.pt",
            _zip({"archive/data.pkl": pickle.dumps({}, protocol=2), "archive/extra": b"\x82\x01."}),
        ),
        (
            "model.pt",
            _zip(
                {"archive/data.pkl": pickle.dumps({}, protocol=2), "archive/data/0": b"\x82\x01."}
            ),
        ),
        (
            "model.pt",
            _zip(
                {
                    "archive/data.pkl": pickle.dumps({}, protocol=2),
                    "archive/data/0": _stream(_EXTENSION_CODES["EXT1"]),
                }
            ),
        ),
        (
            "weights.npy",
            _array(_NPY_FLOATS, b"\x82\x01\x00\x00"),
        ),
    ],
    ids=[
        "bin",
        "compressed-sav",
        "zip-sniffed-member",
        "zip-unnamed-member",
        "tar-sniffed-member",
        "checkpoint-extra-member",
        "tensor-storage",
        "tensor-storage-with-a-proto-opcode",
        "numeric-npy",
    ],
)
def test_bytes_read_as_no_pickle_stay_quiet_when_they_start_with_an_extension_opcode(
    tmp_path: Path, name: str, content: bytes
) -> None:
    findings, ctx = _run(tmp_path, name, content)

    assert findings == []
    assert _unread(ctx) == []


@pytest.mark.parametrize("code", [b"\x82\x00", b"\x84\xff\xff\xff\xff"], ids=["zero", "negative"])
def test_a_pickle_member_refused_for_a_code_no_registry_holds_stays_quiet(
    tmp_path: Path, code: bytes
) -> None:
    findings, ctx = _run(tmp_path, "model.pt", _zip({"archive/data.pkl": code + b"."}))

    assert findings == []
    assert _unread(ctx) == []


@pytest.mark.parametrize("layout", ["storages", "tensors"])
def test_a_legacy_member_whose_later_pickle_uses_an_extension_code_is_unscanned(
    tmp_path: Path, layout: str
) -> None:
    # Torch reads the pickle after the count where `pickle.load` would stop, so only a
    # walk in torch's order reaches the headerless extension code.
    member = pickle.dumps(1, protocol=2) + b"\x82\x01."

    findings, ctx = _run(tmp_path, "checkpoint.tar", _tar({"pickle": b"N.", layout: member}))

    assert findings == [
        (
            _UNSCANNED,
            "tar member is a pickle that names a callable by an extension-registry code "
            f"this scanner cannot resolve ({layout})",
        )
    ]
    assert _unread(ctx) == [str(tmp_path / "checkpoint.tar")]


def test_an_extension_code_after_an_embedded_pickle_is_read_as_part_of_the_pickle(
    tmp_path: Path,
) -> None:
    # The STOP leaves an object below it, so a loader reads on past it as joblib does.
    findings, ctx = _run(tmp_path, "model.joblib", b"NN.\x82\x01.")

    assert findings == [(_UNSCANNED, _RAW_EXTENSION)]
    assert _unread(ctx) == [str(tmp_path / "model.joblib")]


_SNIFFED_NAMES = ("model.p", "model.sav", "w2v.model", "pytorch_model.bin")


@pytest.mark.parametrize(
    "stream", [b"\x82\x01.", b"(l\x82\x01a.", _unheaded(b"")], ids=["bare", "list", "call"]
)
@pytest.mark.parametrize("name", _SNIFFED_NAMES)
def test_a_sniffed_file_that_reaches_a_clean_stop_past_an_extension_code_is_unscanned(
    tmp_path: Path, name: str, stream: bytes
) -> None:
    """`pickle.load` reads these names whatever their first byte is."""
    findings, ctx = _run(tmp_path, name, stream)

    assert findings == [(_UNSCANNED, _RAW_EXTENSION)]
    assert _unread(ctx) == [str(tmp_path / name)]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("bundle.zip", _zip({"weights.bin": b"(l\x82\x01a."})),
        ("bundle.tar", _tar({"model.bin": b"\x82\x01."})),
        ("model.sav", gzip.compress(b"\x82\x01.")),
    ],
    ids=["zip-member", "tar-member", "compressed"],
)
def test_a_sniffed_member_that_reaches_a_clean_stop_past_an_extension_code_is_unscanned(
    tmp_path: Path, name: str, content: bytes
) -> None:
    findings, ctx = _run(tmp_path, name, content)

    assert [title for title, _summary in findings] == [_UNSCANNED]
    assert _unread(ctx) == [str(tmp_path / name)]


def test_a_sniffed_stream_read_past_an_extension_code_counts_at_stop_or_at_a_real_import(
    tmp_path: Path,
) -> None:
    (tmp_path / "broken").mkdir()
    (tmp_path / "whole").mkdir()

    (tmp_path / "called").mkdir()
    (tmp_path / "data").mkdir()

    broken, _ctx = _run(tmp_path / "broken", "model.p", b"\x82\x01cos\nsystem\n\x00")
    whole, _ctx = _run(tmp_path / "whole", "model.p", b"\x82\x01\x85cos\nsystem\n0.")
    called, _ctx = _run(tmp_path / "called", "model.p", b"\x82\x01cos\nsystem\n(S'id'\ntR\xff")
    data, data_ctx = _run(tmp_path / "data", "model.p", b"\x82\x01I1\n\xff")

    critical = "Dangerous pickle opcode (arbitrary code on load)"
    assert [title for title, _summary in broken] == [critical, _UNSCANNED]
    assert [title for title, _summary in whole] == [critical, _UNSCANNED]
    assert [title for title, _summary in called] == [critical, _UNSCANNED]
    assert data == []
    assert _unread(data_ctx) == []


@pytest.mark.parametrize("seed", range(64))
def test_tensor_values_in_a_sniffed_file_stay_quiet(tmp_path: Path, seed: int) -> None:
    values = [math.sin(seed * 7919 + n * n) * (1 + n % 5) for n in range(1024)]
    content = struct.pack(f"<{len(values)}f", *values)
    if seed % 2:
        content = struct.pack(f"<{len(values)}e", *values)

    findings, ctx = _run(tmp_path, "pytorch_model.bin", content)

    assert findings == []
    assert _unread(ctx) == []


def test_an_extension_code_outranks_a_read_that_ran_out_beside_it(tmp_path: Path) -> None:
    """A frame's STOP starts two reads: one hits an extension code, the other runs out."""
    later = b"\x80\x02\x82\x01."
    content = _framed(b"N." + later) + b"\x80\x02("

    findings, ctx = _run(tmp_path, "model.pkl", content)

    assert findings == [(_UNSCANNED, _RAW_EXTENSION)]
    assert _unread(ctx) == [str(tmp_path / "model.pkl")]


def test_a_member_named_as_a_pickle_only_by_its_unicode_path_is_read_as_one(
    tmp_path: Path,
) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("blob")
        unicode_path = b"model.pkl"
        info.extra = (
            struct.pack("<HH", 0x7075, 5 + len(unicode_path))
            + struct.pack("<BL", 1, zlib.crc32(b"blob"))
            + unicode_path
        )
        archive.writestr(info, b"\x82\x01.")

    findings, ctx = _run(tmp_path, "bundle.zip", buffer.getvalue())

    assert findings == [
        (
            _UNSCANNED,
            "zip member is a pickle that names a callable by an extension-registry code "
            "this scanner cannot resolve (blob)",
        )
    ]
    assert _unread(ctx) == [str(tmp_path / "bundle.zip")]


@pytest.mark.parametrize("header", [b"\x80\x00", b"\x80\x01"], ids=["protocol-0", "protocol-1"])
def test_a_proto_opcode_of_any_protocol_makes_an_unnamed_member_a_pickle(
    tmp_path: Path, header: bytes
) -> None:
    """The stream never reaches a STOP, so only its PROTO opcode says it is a pickle."""
    content = _zip(
        {"archive/data.pkl": pickle.dumps({}, protocol=2), "archive/extra": header + _NO_STOP}
    )

    findings, ctx = _run(tmp_path, "model.pt", content)

    assert [title for title, _summary in findings] == [_UNSCANNED]
    assert _unread(ctx) == [str(tmp_path / "model.pt")]
