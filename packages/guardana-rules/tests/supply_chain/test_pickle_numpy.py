"""A NumPy array file that holds Python objects is a pickle, and is read as one.

`np.save` writes an object array as an NPY header followed by a pickle stream, and
`np.load(..., allow_pickle=True)` unpickles it; an `.npz` is a zip of such files. Every
sample here is bytes built in code: nothing is unpickled and numpy is never imported.
"""

import hashlib
import io
import zipfile
from pathlib import Path

import pytest
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import pickle_opcode
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_SYSTEM = b"cos\nsystem\n(Vid\ntR."
"""A protocol-0 pickle that imports `os.system` and calls it."""

_EVAL = b"cbuiltins\neval\n(V1\ntR."

_NUMPY_OBJECT_ARRAY = (
    b"\x80\x04\x95\xa3\x00\x00\x00\x00\x00\x00\x00\x8c\x16numpy._core.multiarray\x94"
    b"\x8c\x0c_reconstruct\x94\x93\x94\x8c\x05numpy\x94\x8c\x07ndarray\x94\x93\x94K\x00"
    b"\x85\x94C\x01b\x94\x87\x94R\x94(K\x01K\x04\x85\x94h\x03\x8c\x05dtype\x94\x93\x94"
    b"\x8c\x02O8\x94\x89\x88\x87\x94R\x94(K\x03\x8c\x01|\x94NNNJ\xff\xff\xff\xffJ\xff\xff"
    b"\xff\xffK?t\x94b\x89]\x94(}\x94\x8c\x01a\x94K\x01s]\x94(K\x01K\x02e\x8c\x01s\x94"
    b"C\x01x\x94et\x94b."
)
"""The stream `np.save` writes for `np.array([{"a": 1}, [1, 2], "s", b"x"], dtype=object)`."""

_RULE = "guardana.supply_chain.pickle_opcode"


def _npy(
    descr: object,
    body: bytes,
    *,
    version: tuple[int, int] = (1, 0),
    header: str | None = None,
) -> bytes:
    """An NPY file declaring `descr`, laid out as `np.save` writes it, followed by `body`."""
    text = header or f"{{'descr': {descr!r}, 'fortran_order': False, 'shape': (1,), }}"
    width = 2 if version == (1, 0) else 4
    raw = text.encode("latin1" if version < (3, 0) else "utf8")
    raw += b" " * (63 - (8 + width + len(raw)) % 64) + b"\n"
    return b"\x93NUMPY" + bytes(version) + len(raw).to_bytes(width, "little") + raw + body


def _npz(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _summary(*callables: str) -> str:
    named = sorted(callables)
    digest = hashlib.sha256("\n".join(named).encode()).hexdigest()[:12]
    return (
        f"unpickling imports {len(named)} non-allowlisted callable(s) (set {digest}): "
        f"{', '.join(named)}"
    )


def _unread(ctx: RuleContext) -> list[str]:
    return [
        gap.name
        for gap in ctx.shortfalls()
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
        and gap.detail.startswith(f"{_RULE} could not read it: ")
    ]


def _scan(tmp_path: Path, name: str, content: bytes) -> tuple[Path, RuleContext, list[str]]:
    """Scan one file; return its path, the context, and each finding's title."""
    path = tmp_path / name
    path.write_bytes(content)
    ctx = RuleContext()
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))
    return path, ctx, [f.title for f in findings]


@pytest.mark.parametrize("descr", ["|O", "O", "<O8", "object"])
def test_an_object_array_importing_os_system_is_critical(tmp_path: Path, descr: str) -> None:
    path = tmp_path / "weights.npy"
    path.write_bytes(_npy(descr, _SYSTEM))

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    reported = [(f.severity, f.target_ref, f.evidence.summary, f.evidence.detail) for f in findings]
    assert reported == [
        (Severity.CRITICAL, str(path), _summary("os.system"), "os.system in weights.npy")
    ]


@pytest.mark.parametrize("version", [(1, 0), (2, 0), (3, 0)])
def test_every_npy_version_is_read(tmp_path: Path, version: tuple[int, int]) -> None:
    _path, _ctx, titles = _scan(tmp_path, "weights.npy", _npy("|O", _EVAL, version=version))

    assert titles == ["Dangerous pickle opcode (arbitrary code on load)"]


def test_the_stream_numpy_writes_for_an_object_array_is_clean(tmp_path: Path) -> None:
    path, ctx, titles = _scan(tmp_path, "arrays.npy", _npy("|O", _NUMPY_OBJECT_ARRAY))

    assert titles == []
    assert _unread(ctx) == []
    assert str(path) in ctx.examined_paths()


def test_a_numeric_array_holds_no_pickle_and_is_examined_clean(tmp_path: Path) -> None:
    # The bytes after a numeric header are values numpy copies into memory as they
    # are; even ones that would parse as a malicious pickle are never unpickled.
    path, ctx, titles = _scan(tmp_path, "weights.npy", _npy("<f4", _SYSTEM + bytes(3)))

    assert titles == []
    assert _unread(ctx) == []
    assert str(path) in ctx.examined_paths()


@pytest.mark.parametrize(
    "descr",
    [
        [("a", "<f4"), ("b", "|O")],
        [("a", "<f4"), ("nested", [("b", "<i8"), ("c", "|O", (2,))])],
        [(("title", "a"), "|O")],
    ],
    ids=["field", "nested-field", "titled-field"],
)
def test_a_structured_dtype_with_an_object_field_is_read_as_a_pickle(
    tmp_path: Path, descr: object
) -> None:
    _path, _ctx, titles = _scan(tmp_path, "records.npy", _npy(descr, _SYSTEM))

    assert titles == ["Dangerous pickle opcode (arbitrary code on load)"]


def test_a_structured_dtype_without_an_object_field_is_clean(tmp_path: Path) -> None:
    descr = [("a", "<f4"), ("b", [("c", "<i8"), ("d", "|S3", (2,))]), ("", "|V4")]
    path, ctx, titles = _scan(tmp_path, "records.npy", _npy(descr, _SYSTEM))

    assert titles == []
    assert _unread(ctx) == []
    assert str(path) in ctx.examined_paths()


def test_an_npz_names_the_member_that_imports_the_callable(tmp_path: Path) -> None:
    archive = _npz(
        {
            "arr_0.npy": _npy("<f8", bytes(8)),
            "arr_1.npy": _npy("|O", _SYSTEM),
            "arr_2.npy": _npy("|O", _NUMPY_OBJECT_ARRAY),
        }
    )
    path = tmp_path / "bundle.npz"
    path.write_bytes(archive)
    ctx = RuleContext()

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))

    assert [(f.severity, f.evidence.detail) for f in findings] == [
        (Severity.CRITICAL, "os.system in bundle.npz::arr_1.npy")
    ]
    assert _unread(ctx) == []


def test_an_npz_of_numeric_and_numpy_written_arrays_is_clean(tmp_path: Path) -> None:
    archive = _npz({"a.npy": _npy("<f4", _SYSTEM), "b.npy": _npy("|O", _NUMPY_OBJECT_ARRAY)})
    path, ctx, titles = _scan(tmp_path, "bundle.npz", archive)

    assert titles == []
    assert _unread(ctx) == []
    assert str(path) in ctx.examined_paths()


def test_a_truncated_npz_is_unread_not_clean(tmp_path: Path) -> None:
    archive = _npz({"arr_0.npy": _npy("|O", _NUMPY_OBJECT_ARRAY)})
    path, ctx, titles = _scan(tmp_path, "bundle.npz", archive[: len(archive) // 2])

    assert titles == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]


def test_an_npz_member_with_a_malformed_header_is_unread(tmp_path: Path) -> None:
    archive = _npz({"arr_0.npy": b"\x93NUMPY\x01\x00\xff\x00{'descr'"})
    path, ctx, titles = _scan(tmp_path, "bundle.npz", archive)

    assert titles == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]


def test_an_npz_member_declaring_objects_that_holds_no_pickle_is_unread(tmp_path: Path) -> None:
    archive = _npz({"arr_0.npy": _npy("|O", b"\xff\xfe not a pickle")})
    path, ctx, titles = _scan(tmp_path, "bundle.npz", archive)

    assert titles == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]


def test_an_npy_that_is_a_raw_pickle_is_read_as_one(tmp_path: Path) -> None:
    # `np.load(..., allow_pickle=True)` unpickles a file without the NPY magic.
    _path, _ctx, titles = _scan(tmp_path, "weights.npy", _SYSTEM)

    assert titles == ["Dangerous pickle opcode (arbitrary code on load)"]


def _with_header_length(length: int) -> bytes:
    return b"\x93NUMPY\x01\x00" + length.to_bytes(2, "little") + b"{'descr': '|O'}"


@pytest.mark.parametrize(
    "content",
    [
        b"\xff\xfe not an array file at all",
        b"\x93NUMPY",
        b"\x93NUMPY\x09\x00\x10\x00",
        _with_header_length(4096),
        _npy("|O", _SYSTEM, header="['descr', 'fortran_order', 'shape']"),
        _npy("|O", _SYSTEM, header="{'descr': '|O', 'shape': (1,)}"),
        _npy("|O", _SYSTEM, header="{'descr': __import__('os'), 'fortran_order': 0, 'shape': 0}"),
        _npy("|O", _SYSTEM, header="{'descr': '|O', 'fortran_order': False, 'shape': (1,"),
        _npy("f4,O", _SYSTEM),
        _npy(7, _SYSTEM),
        _npy([("a",)], _SYSTEM),
    ],
    ids=[
        "bad-magic",
        "no-version",
        "unknown-version",
        "header-past-the-file",
        "not-a-dict",
        "missing-key",
        "not-a-literal",
        "unterminated-literal",
        "unclassified-dtype",
        "dtype-not-a-string",
        "field-without-a-dtype",
    ],
)
def test_an_npy_whose_header_cannot_be_read_is_unread_not_clean(
    tmp_path: Path, content: bytes
) -> None:
    path, ctx, titles = _scan(tmp_path, "weights.npy", content)

    assert titles == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]
    assert str(path) in ctx.examined_paths()


def _numeric_header(fortran_order: str, shape: str) -> str:
    return f"{{'descr': '<f4', 'fortran_order': {fortran_order}, 'shape': {shape}, }}"


@pytest.mark.parametrize(
    "content",
    [
        _npy("<f4", bytes(4), header=_numeric_header("'False'", "'not a shape'")),
        _npy("<f4", bytes(4), header=_numeric_header("0", "(1,)")),
        _npy("<f4", bytes(4), header=_numeric_header("None", "(1,)")),
        _npy("<f4", bytes(4), header=_numeric_header("False", "[1]")),
        _npy("<f4", bytes(4), header=_numeric_header("False", "(1.0,)")),
        _npy("<f4", bytes(4), header=_numeric_header("False", "1")),
        _npy([("a", "<f4", "x")], bytes(4)),
        _npy([("a", "<f4", -1)], bytes(4)),
        _npy([("a", "<f4", (2.0,))], bytes(4)),
        _npy([("a", "<f4", True)], bytes(4)),
        _npy([(1, "<f4")], bytes(4)),
        _npy([("a", "|O"), ("b", "<f4", "x")], _SYSTEM),
        _npy([("a", "|O"), ("b", [("c", "<f4", "x")])], _SYSTEM),
        _npy([("a", "|O"), ("b", 7)], _SYSTEM),
    ],
    ids=[
        "string-fields",
        "integer-fortran-order",
        "none-fortran-order",
        "list-shape",
        "float-dimension",
        "integer-shape",
        "string-field-shape",
        "negative-field-shape",
        "float-field-dimension",
        "bool-field-shape",
        "integer-field-name",
        "object-field-beside-a-malformed-one",
        "object-field-beside-a-malformed-nested-one",
        "object-field-beside-a-dtype-that-is-no-dtype",
    ],
)
def test_a_header_numpy_refuses_is_unread_not_a_numeric_array(
    tmp_path: Path, content: bytes
) -> None:
    path, ctx, titles = _scan(tmp_path, "weights.npy", content)

    assert titles == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]


@pytest.mark.parametrize(
    "descr",
    [
        [("a", "<f4", 2)],
        [("a", "<f4", (2, 3))],
        [("a", "<f4", [2])],
        [("a", "<f4", ())],
        [(("title", "a"), "<f4")],
    ],
    ids=["integer", "tuple", "list", "empty", "titled-field"],
)
def test_field_shapes_numpy_accepts_keep_a_numeric_array_clean(
    tmp_path: Path, descr: object
) -> None:
    _path, ctx, titles = _scan(tmp_path, "records.npy", _npy(descr, bytes(8)))

    assert titles == []
    assert _unread(ctx) == []


def test_a_header_numpy_refuses_inside_an_npz_is_unread(tmp_path: Path) -> None:
    member = _npy("<f4", bytes(4), header=_numeric_header("'False'", "'not a shape'"))

    path, ctx, titles = _scan(tmp_path, "arrays.npz", _npz({"x.npy": member}))

    assert titles == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]


def test_an_object_array_with_no_pickle_after_its_header_is_unread(tmp_path: Path) -> None:
    path, ctx, titles = _scan(tmp_path, "weights.npy", _npy("|O", b"\xff\xfe"))

    assert titles == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]


def test_an_object_array_whose_import_cannot_be_resolved_is_unread(tmp_path: Path) -> None:
    path, ctx, titles = _scan(tmp_path, "weights.npy", _npy("|O", b"\x80\x04h\x05h\x06\x93."))

    assert titles == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]


def _wide_header(width: int) -> str:
    """A valid numeric header padded past `width` bytes with a long shape literal."""
    zeros = "0, " * (width // 3)
    return f"{{'descr': '<f4', 'fortran_order': False, 'shape': ({zeros}), }}"


def test_a_header_longer_than_the_parse_bound_is_unread(tmp_path: Path) -> None:
    content = _npy("<f4", b"", version=(2, 0), header=_wide_header(70 * 1024))
    path, ctx, titles = _scan(tmp_path, "weights.npy", content)

    assert titles == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]


def test_header_bytes_are_spent_from_the_archive_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_opcode, "_ARCHIVE_OPCODE_FLOOR", 0)
    members = {
        f"arr_{n}.npy": _npy("<f4", b"", version=(2, 0), header=_wide_header(16 * 1024))
        for n in range(8)
    }
    path, ctx, titles = _scan(tmp_path, "arrays.npz", _npz(members))

    assert titles == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]


@pytest.mark.parametrize("name", ["features.bin", "state.p", "vectors.model", "w.sav"])
def test_an_object_array_under_a_name_read_by_content_is_read_as_one(
    tmp_path: Path, name: str
) -> None:
    _path, _ctx, titles = _scan(tmp_path, name, _npy("|O", _SYSTEM))

    assert titles == ["Dangerous pickle opcode (arbitrary code on load)"]


def test_an_object_array_named_like_a_tensor_storage_is_read_as_an_array(tmp_path: Path) -> None:
    # `np.load` reads any npz member that starts as an NPY file, whatever torch would make
    # of the name.
    archive = _npz({"x/data.pkl": b"not read by numpy", "x/data/0": _npy("|O", _SYSTEM)})
    path = tmp_path / "bundle.npz"
    path.write_bytes(archive)

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [(f.severity, f.evidence.detail) for f in findings] == [
        (Severity.CRITICAL, "os.system in bundle.npz::x/data/0")
    ]


def test_an_object_array_with_tar_magic_inside_it_is_an_array_not_a_nested_archive(
    tmp_path: Path,
) -> None:
    head = _npy("|O", b"")
    body = _SYSTEM + b"\x00" * (257 - len(head) - len(_SYSTEM)) + b"ustar\x0000"
    member = head + body
    if member[257:262] != b"ustar":
        raise AssertionError("the sample must carry tar magic where a tar header has it")
    path = tmp_path / "bundle.npz"
    path.write_bytes(_npz({"arr_0.npy": member}))

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [(f.severity, f.evidence.detail) for f in findings] == [
        (Severity.CRITICAL, "os.system in bundle.npz::arr_0.npy")
    ]
