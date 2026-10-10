"""An extension code names a callable through a registry only the loading process holds.

A pickle that opens with a protocol 2+ header and then uses one is left unread wherever
it sits, raw or inside an archive; tensor bytes that merely contain the opcode stay quiet.
Every file here is built in code; nothing is unpickled.
"""

import io
import pickle
import tarfile
import zipfile
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


def _object_array(stream: bytes) -> bytes:
    return b"\x93NUMPY\x01\x00" + len(_NPY_OBJECTS).to_bytes(2, "little") + _NPY_OBJECTS + stream


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
    "zip-tensor-storage": (
        "model.pt",
        "zip",
        "archive/data/0",
        lambda stream: _zip(
            {"archive/data.pkl": pickle.dumps({}, protocol=2), "archive/data/0": stream}
        ),
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


def test_an_extension_code_in_a_second_pickle_after_a_complete_one_is_unscanned(
    tmp_path: Path,
) -> None:
    findings, ctx = _run(
        tmp_path, "model.pkl", pickle.dumps({}, protocol=2) + _stream(_EXTENSION_CODES["EXT1"])
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


def test_a_legacy_checkpoint_whose_storage_size_reads_as_extension_code_zero_stays_clean(
    tmp_path: Path,
) -> None:
    findings, ctx = _run(tmp_path, "model.pt", _legacy_checkpoint(0x00820280))

    assert findings == []
    assert _unread(ctx) == []


def test_a_legacy_checkpoint_whose_trailing_pickle_uses_extension_code_one_is_unscanned(
    tmp_path: Path,
) -> None:
    findings, ctx = _run(tmp_path, "model.pt", _legacy_checkpoint(0x01820280))

    assert [title for title, _summary in findings] == [_UNSCANNED]
    assert _unread(ctx) == [str(tmp_path / "model.pt")]


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
