"""A pickle is read under the names loaders open it by, and only those.

`torch.load`, `pickle.load` and `joblib.load` take any path, so a model saved as
`model.th`, `model.dat` or with no suffix at all is unpickled exactly like `model.pkl`.
A name that says nothing about the format is read by its first bytes, in one bounded
read, so the data files that share those names stay quiet. Everything here is built in
code; nothing is unpickled.
"""

import gzip
import io
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import pickle_opcode
from guardana.rules.supply_chain._npy import NPY_MAGIC
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_SYSTEM = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R."
_SYSTEM_PROTOCOL_0 = b"cos\nsystem\n(Vid\ntR."
_CLEAN = b"\x80\x02}q\x00X\x01\x00\x00\x00wq\x01G?\xf0\x00\x00\x00\x00\x00\x00s."
_CRITICAL = "Dangerous pickle opcode (arbitrary code on load)"
_UNSCANNED = "Unscanned model file"


def _npy(descr: str, data: bytes) -> bytes:
    header = f"{{'descr': '{descr}', 'fortran_order': False, 'shape': (1,), }}\n".encode()
    return NPY_MAGIC + b"\x01\x00" + len(header).to_bytes(2, "little") + header + data


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _scan(root: Path) -> tuple[list[tuple[str, str]], RuleContext]:
    ctx = RuleContext()
    findings = [
        (f.title, f.target_ref.rsplit("/", 1)[-1])
        for f in PickleOpcodeRule().run(ArtifactTarget(root), ctx)
    ]
    return findings, ctx


def _unread(ctx: RuleContext) -> list[str]:
    return [gap.name for gap in ctx.shortfalls() if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("model.th", _SYSTEM),
        ("clf.pkl3", _SYSTEM),
        ("model.mdl", _SYSTEM),
        ("model.pkl.gzip", gzip.compress(_SYSTEM)),
        ("model.ckpt.gz", gzip.compress(_SYSTEM)),
        ("arr.npy.gz", gzip.compress(_SYSTEM)),
        ("arr.npy.gz", gzip.compress(_npy("|O", _SYSTEM))),
        ("model.dat", _SYSTEM),
        ("model", _SYSTEM),
        ("model", _SYSTEM_PROTOCOL_0),
        ("model.dat.gz", gzip.compress(_SYSTEM)),
        ("model", gzip.compress(_SYSTEM)),
        ("checkpoint", _zip({"archive/data.pkl": _SYSTEM, "archive/version": b"3\n"})),
        ("weights.dat", _npy("|O", _SYSTEM)),
    ],
)
def test_a_pickle_under_a_name_a_loader_opens_is_read(
    tmp_path: Path, name: str, content: bytes
) -> None:
    (tmp_path / name).write_bytes(content)
    findings, ctx = _scan(tmp_path)
    assert findings == [(_CRITICAL, name)]
    assert ctx.examined_paths() == {str(tmp_path / name)}


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("model.th", _CLEAN),
        ("model.dat", _CLEAN),
        ("model", _CLEAN),
        ("arr.npy.gz", gzip.compress(_npy("<f8", bytes(8)))),
        ("model.dat.gz", gzip.compress(_CLEAN)),
    ],
)
def test_a_clean_pickle_under_those_names_is_examined_and_clean(
    tmp_path: Path, name: str, content: bytes
) -> None:
    (tmp_path / name).write_bytes(content)
    findings, ctx = _scan(tmp_path)
    assert findings == []
    assert ctx.examined_paths() == {str(tmp_path / name)}


def test_a_pickle_whose_import_lies_past_the_head_is_still_read(tmp_path: Path) -> None:
    padding = b"x" * (2 * 64 * 1024)
    prefix = b"\x80\x02X" + len(padding).to_bytes(4, "little") + padding + b"0"
    (tmp_path / "model").write_bytes(prefix + _SYSTEM[2:])
    findings, _ctx = _scan(tmp_path)
    assert findings == [(_CRITICAL, "model")]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("LICENSE", b"Permission is hereby granted, free of charge, to any person\n"),
        ("Makefile", b"all:\n\tpython -m build\n"),
        (".gitignore", b"*.pyc\n__pycache__/\n"),
        ("run", b"\x7fELF\x02\x01\x01" + bytes(64)),
        ("table.dat", bytes(range(256)) * 4),
        ("measurements.dat", b"1.0 2.0 3.0\n4.0 5.0 6.0\n"),
        ("values.dat.gz", gzip.compress(b"1.0 2.0 3.0\n" * 100)),
        (
            "trace.dat",
            b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"0" * 64 + b"\nsize 1\n",
        ),
        ("bundle", _zip({"README.txt": b"hello\n", "data.csv": b"a,b\n1,2\n"})),
        ("archive.dat", b"7z\xbc\xaf\x27\x1c" + bytes(26)),
        ("numbers.dat", _npy("<f8", bytes(8))),
    ],
)
def test_a_data_file_under_a_name_that_says_nothing_stays_quiet(
    tmp_path: Path, name: str, content: bytes
) -> None:
    (tmp_path / name).write_bytes(content)
    findings, ctx = _scan(tmp_path)
    assert findings == []
    assert _unread(ctx) == []


def test_plain_zip_members_are_peeked_up_to_a_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_opcode, "_PEEK_MAX_MEMBERS", 3)
    members = {f"notes/{index}.txt": b"plain text\n" for index in range(5)}
    (tmp_path / "bundle.zip").write_bytes(_zip(members))
    findings, ctx = _scan(tmp_path)
    assert findings == [(_UNSCANNED, "bundle.zip")]
    assert _unread(ctx) == [str(tmp_path / "bundle.zip")]
    detail = next(gap.detail for gap in ctx.shortfalls())
    assert "2 member(s)" in detail
    assert "first bytes" in detail


def test_plain_zip_members_are_peeked_up_to_a_byte_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_opcode, "_PEEK_MAX_BYTES", 200)
    members = {f"notes/{index}.txt": b"plain text\n" * 40 for index in range(4)}
    (tmp_path / "bundle.zip").write_bytes(_zip(members))
    findings, ctx = _scan(tmp_path)
    assert findings == [(_UNSCANNED, "bundle.zip")]
    assert "first bytes" in next(gap.detail for gap in ctx.shortfalls())


def test_a_plain_zip_within_the_peek_bounds_is_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_opcode, "_PEEK_MAX_MEMBERS", 5)
    members = {f"notes/{index}.txt": b"plain text\n" for index in range(5)}
    (tmp_path / "bundle.zip").write_bytes(_zip(members))
    findings, ctx = _scan(tmp_path)
    assert findings == []
    assert _unread(ctx) == []


def test_a_pickle_peeked_before_the_bound_is_still_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_opcode, "_PEEK_MAX_MEMBERS", 1)
    (tmp_path / "bundle.zip").write_bytes(_zip({"blob": _SYSTEM, "notes.txt": b"text\n"}))
    findings, _ctx = _scan(tmp_path)
    assert sorted(findings) == [(_CRITICAL, "bundle.zip"), (_UNSCANNED, "bundle.zip")]


def _tar(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@pytest.mark.parametrize(("name", "pack"), [("bundle.zip", _zip), ("bundle.tar", _tar)])
def test_a_dat_member_of_a_plain_archive_is_read_when_it_is_a_pickle(
    tmp_path: Path, name: str, pack: Callable[[dict[str, bytes]], bytes]
) -> None:
    (tmp_path / name).write_bytes(
        pack({"model.dat": _SYSTEM_PROTOCOL_0, "table.dat": bytes(range(256)) * 4})
    )
    findings, ctx = _scan(tmp_path)
    assert findings == [(_CRITICAL, name)]
    assert _unread(ctx) == []


@pytest.mark.parametrize(("name", "pack"), [("bundle.zip", _zip), ("bundle.tar", _tar)])
def test_dat_members_of_a_plain_archive_that_hold_data_stay_quiet(
    tmp_path: Path, name: str, pack: Callable[[dict[str, bytes]], bytes]
) -> None:
    (tmp_path / name).write_bytes(
        pack({"table.dat": bytes(range(256)) * 4, "values.dat": b"1.0 2.0\n" * 10})
    )
    findings, ctx = _scan(tmp_path)
    assert findings == []
    assert _unread(ctx) == []
