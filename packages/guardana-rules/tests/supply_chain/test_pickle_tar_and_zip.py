"""A tar or a plain zip is read for the members a loader would unpickle from it.

Legacy `torch.save` writes a tar whose `pickle`, `storages` and `tensors` members are
unpickled by `torch.load`; a plain archive is extracted by a person who then loads a
member by its name. Every archive here is built in code; nothing is unpickled.
"""

import gzip
import io
import stat
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import pickle_opcode
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_SYSTEM = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R."
_UNSCANNED = "Unscanned model file"


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


def _link(name: str, target: str, kind: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target
    return info


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _run(tmp_path: Path, name: str, content: bytes) -> tuple[list[str], list[str], RuleContext]:
    path = tmp_path / name
    path.write_bytes(content)
    ctx = RuleContext()
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))
    return [f.title for f in findings], [f.evidence.detail or "" for f in findings], ctx


def test_a_legacy_torch_tar_names_the_member_it_unpickles(tmp_path: Path) -> None:
    content = _tar(("sys_info", b"\x80\x02}q\x00."), ("pickle", _SYSTEM))

    _titles, details, _ctx = _run(tmp_path, "checkpoint.tar", content)

    assert details == ["os.system in checkpoint.tar::pickle"]


def test_a_hard_link_is_read_through_to_the_member_it_names(tmp_path: Path) -> None:
    content = _tar(("blob", _SYSTEM), _link("pickle", "blob", tarfile.LNKTYPE))

    _titles, details, _ctx = _run(tmp_path, "checkpoint.tar", content)

    assert details == ["os.system in checkpoint.tar::pickle"]


def test_a_model_named_link_to_nothing_is_unread(tmp_path: Path) -> None:
    content = _tar(_link("model.pkl", "missing", tarfile.SYMTYPE))

    titles, _details, ctx = _run(tmp_path, "bundle.tar", content)

    assert titles == [_UNSCANNED]
    assert [
        gap.name for gap in ctx.shortfalls() if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
    ] == [str(tmp_path / "bundle.tar")]


def test_a_cut_torch_tar_is_unread_not_clean(tmp_path: Path) -> None:
    content = _tar(("pickle", _SYSTEM + bytes(4096)))

    titles, _details, _ctx = _run(tmp_path, "model.pth.tar", content[:1024])

    assert _UNSCANNED in titles


def test_a_tar_of_source_and_text_is_not_read_as_a_model(tmp_path: Path) -> None:
    content = _tar(("README.txt", b"hello\n"), ("setup.py", b"import os\n"))

    titles, _details, ctx = _run(tmp_path, "release.tar", content)

    assert titles == []
    assert str(tmp_path / "release.tar") not in ctx.examined_paths()


def test_a_plain_zip_reads_the_members_named_as_models(tmp_path: Path) -> None:
    content = _zip({"docs/README.txt": b"hello\n", "weights/model.pkl": _SYSTEM})

    _titles, details, ctx = _run(tmp_path, "bundle.zip", content)

    assert details == ["os.system in bundle.zip::weights/model.pkl"]
    assert str(tmp_path / "bundle.zip") in ctx.examined_paths()


def test_a_plain_zip_of_text_is_not_read_as_a_model(tmp_path: Path) -> None:
    content = _zip({"docs/README.txt": b"hello\n", "src/app.py": b"x = 1\n"})

    titles, _details, ctx = _run(tmp_path, "docs.zip", content)

    assert titles == []
    assert str(tmp_path / "docs.zip") not in ctx.examined_paths()


def test_a_torch_save_zip_named_as_a_tar_has_every_member_read(tmp_path: Path) -> None:
    content = _zip({"archive/data.pkl": b"\x80\x02}q\x00.", "archive/extra": _SYSTEM})

    _titles, details, _ctx = _run(tmp_path, "checkpoint.tar", content)

    assert details == ["os.system in checkpoint.tar::archive/extra"]


def _typed(name: str, data: bytes, kind: bytes) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.type = kind
    return info, data


def _tar_with_types(*entries: tuple[tarfile.TarInfo, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for info, data in entries:
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("name", "kind", "model"),
    [
        ("model.pth.tar", tarfile.LNKTYPE, "pickle"),
        ("bundle.tar", tarfile.LNKTYPE, "evil.pkl"),
        ("bundle.tar", tarfile.SYMTYPE, "evil.pkl"),
    ],
    ids=["torch-tar-hard-link", "hard-link", "symbolic-link"],
)
def test_a_link_does_not_hide_the_members_after_it(
    tmp_path: Path, name: str, kind: bytes, model: str
) -> None:
    content = _tar(("README.txt", b"hello\n"), _link("a.pkl", "README.txt", kind), (model, _SYSTEM))

    _titles, details, _ctx = _run(tmp_path, name, content)

    assert details == [f"os.system in {name}::{model}"]


@pytest.mark.parametrize(("name", "member"), [("model.pth.tar", "pickle"), ("b.tar", "m.pkl")])
def test_a_member_of_a_type_tarfile_does_not_know_is_read_as_a_file(
    tmp_path: Path, name: str, member: str
) -> None:
    content = _tar_with_types(_typed(member, _SYSTEM, b"Z"))

    _titles, details, _ctx = _run(tmp_path, name, content)

    assert details == [f"os.system in {name}::{member}"]


_PROLOG = b"cat(tom).\nparent(tom, bob).\n"
_NOT_A_PICKLE = b"\x93\x1b\x05\xcb\x004\xeb\xc0.,\x86\xe6\x01\xa1O." * 64


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("src.zip", _zip({"prolog/family.p": _PROLOG})),
        ("src.tar", _tar(("prolog/family.p", _PROLOG))),
        ("firmware.zip", _zip({"blobs/fw.bin": _NOT_A_PICKLE})),
        ("firmware.tar", _tar(("blobs/fw.bin", _NOT_A_PICKLE))),
    ],
    ids=["prolog-in-zip", "prolog-in-tar", "firmware-in-zip", "firmware-in-tar"],
)
def test_a_member_named_by_a_shared_suffix_is_read_only_when_it_is_a_pickle(
    tmp_path: Path, name: str, content: bytes
) -> None:
    titles, _details, ctx = _run(tmp_path, name, content)

    assert titles == []
    assert list(ctx.shortfalls()) == []


def test_a_pickle_named_by_a_shared_suffix_in_an_archive_is_still_read(tmp_path: Path) -> None:
    _titles, details, _ctx = _run(tmp_path, "bundle.zip", _zip({"data/state.p": _SYSTEM}))

    assert details == ["os.system in bundle.zip::data/state.p"]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("images.zip", _zip({f"img/{n}.jpg": b"\xff\xd8\xff" for n in range(5)})),
        ("images.tar", _tar(*((f"img/{n}.jpg", b"\xff\xd8\xff") for n in range(5)))),
    ],
    ids=["zip", "tar"],
)
def test_the_member_bound_counts_only_the_members_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, content: bytes
) -> None:
    monkeypatch.setattr(pickle_opcode, "_ARCHIVE_MAX_MEMBERS", 3)

    titles, _details, _ctx = _run(tmp_path, name, content)

    assert titles == []


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("bundle.zip", _zip({f"m/{n}.pkl": b"\x80\x02K\x00." for n in range(5)})),
        ("bundle.tar", _tar(*((f"m/{n}.pkl", b"\x80\x02K\x00.") for n in range(5)))),
    ],
    ids=["zip", "tar"],
)
def test_models_past_the_member_bound_are_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, content: bytes
) -> None:
    monkeypatch.setattr(pickle_opcode, "_ARCHIVE_MAX_MEMBERS", 3)

    titles, _details, _ctx = _run(tmp_path, name, content)

    assert titles == [_UNSCANNED]


def test_a_torch_tar_inside_a_zip_is_a_nested_archive_not_clean(tmp_path: Path) -> None:
    content = _zip({"checkpoints/model_best.pth.tar": _tar(("pickle", _SYSTEM))})

    titles, _details, ctx = _run(tmp_path, "release.zip", content)

    assert titles == [_UNSCANNED]
    assert [gap.name for gap in ctx.shortfalls()] == [str(tmp_path / "release.zip")]


def _members_only(*entries: tuple[str, bytes]) -> bytes:
    """A tar's member blocks with no end-of-archive marker after them."""
    blocks = b""
    for name, data in entries:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        padding = b"\x00" * (-len(data) % tarfile.BLOCKSIZE)
        blocks += info.tobuf(tarfile.PAX_FORMAT) + data + padding
    return blocks


def test_a_damaged_header_before_a_model_member_is_unread_not_clean(tmp_path: Path) -> None:
    content = (
        _members_only(("README.txt", b"hello\n"))
        + b"X" * tarfile.BLOCKSIZE
        + _members_only(("evil.pkl", _SYSTEM))
        + b"\x00" * (2 * tarfile.BLOCKSIZE)
    )

    titles, _details, ctx = _run(tmp_path, "bundle.tar", content)

    assert titles == [_UNSCANNED]
    assert [gap.name for gap in ctx.shortfalls()] == [str(tmp_path / "bundle.tar")]


@pytest.mark.parametrize(
    "content",
    [
        _tar(("README.txt", b"hello\n"), ("model.pkl", b"\x80\x02K\x00.")),
        _members_only(("README.txt", b"hello\n"), ("model.pkl", b"\x80\x02K\x00.")),
    ],
    ids=["end-marker", "cut-at-a-member-boundary"],
)
def test_a_tar_that_ends_where_its_last_member_does_is_read_whole(
    tmp_path: Path, content: bytes
) -> None:
    titles, _details, ctx = _run(tmp_path, "bundle.tar", content)

    assert titles == []
    assert list(ctx.shortfalls()) == []
    assert str(tmp_path / "bundle.tar") in ctx.examined_paths()


def _zip_over_a_tar(tar: bytes) -> bytes:
    """A zip whose one stored entry, at byte 0, holds `tar`, after a first block that is both
    the entry's local header and a tar header."""
    name = b"readme.txt"
    extra = tarfile.BLOCKSIZE - 30 - len(name)
    crc = zlib.crc32(tar)
    local = struct.pack(
        "<4s5H3L2H", b"PK\x03\x04", 20, 0, 0, 0, 0x21, crc, len(tar), len(tar), len(name), extra
    )
    block = bytearray(tarfile.TarInfo("x").tobuf(tarfile.USTAR_FORMAT))
    block[:44] = local + name + struct.pack("<HH", 0xCAFE, extra - 4)
    block[148:156] = b" " * 8
    block[148:156] = b"%06o\x00 " % sum(block)
    central = (
        struct.pack(
            "<4s6H3L5H2L",
            b"PK\x01\x02",
            20,
            20,
            0,
            0,
            0,
            0x21,
            crc,
            len(tar),
            len(tar),
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(block) + len(tar), 0)
    return bytes(block) + tar + central + end


@pytest.mark.parametrize("name", ["bundle.tar", "bundle.zip", "bundle", "bundle.dat"])
def test_a_zip_whose_first_block_is_a_tar_header_is_read_as_a_tar_too(
    tmp_path: Path, name: str
) -> None:
    """`tar` unpacks a tar from bytes that open as one, whatever zip they also hold."""
    content = _zip_over_a_tar(_tar(("model.pkl", _SYSTEM)))
    assert [info.filename for info in zipfile.ZipFile(io.BytesIO(content)).infolist()] == [
        "readme.txt"
    ]

    _titles, details, ctx = _run(tmp_path, name, content)

    assert f"os.system in {name}::model.pkl" in details
    assert str(tmp_path / name) in ctx.examined_paths()


def test_a_plain_zip_after_a_tar_is_read_as_the_tar_too(tmp_path: Path) -> None:
    buffer = io.BytesIO(_tar(("model.pkl", _SYSTEM)))
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.writestr("readme.txt", b"hello\n")

    _titles, details, _ctx = _run(tmp_path, "bundle.zip", buffer.getvalue())

    assert "os.system in bundle.zip::model.pkl" in details


_CLEAN = b"\x80\x02K\x00."
_THROUGH = "at or below the link member"


def _summaries(tmp_path: Path, name: str, content: bytes) -> tuple[list[str], RuleContext]:
    (tmp_path / name).write_bytes(content)
    ctx = RuleContext()
    findings = PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx)
    return [f.evidence.summary for f in findings], ctx


def _zip_with_links(members: dict[str, bytes], links: dict[str, str], extra: bytes = b"") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, to in links.items():
            link = zipfile.ZipInfo(name)
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            link.extra = extra
            archive.writestr(link, to)
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _unicode_path(stored: str, name: str) -> bytes:
    """An Info-ZIP Unicode Path field giving the member stored as `stored` the name `name`."""
    data = struct.pack("<BL", 1, zlib.crc32(stored.encode())) + name.encode()
    return struct.pack("<HH", 0x7075, len(data)) + data


def _stored_as(content: bytes, placeholder: bytes, raw: bytes) -> bytes:
    """`content` with a member's name bytes `placeholder` replaced by `raw`, flags unchanged."""
    assert content.count(placeholder) == 2
    return content.replace(placeholder, raw)


_OVER_A_LINK = _tar(
    ("model.pkl", _CLEAN), _link("notes.txt", "model.pkl", tarfile.SYMTYPE), ("notes.txt", _SYSTEM)
)
_OVER_A_HARD_LINK = _tar(
    ("model.pkl", _CLEAN), _link("notes.txt", "model.pkl", tarfile.LNKTYPE), ("notes.txt", _SYSTEM)
)
_BELOW_A_LINK = _tar(_link("weights", ".", tarfile.SYMTYPE), ("weights/a.txt", b"hi\n"))


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("bundle.tar", _OVER_A_LINK),
        ("bundle.tar", _BELOW_A_LINK),
        ("bundle.tar.gz", gzip.compress(_BELOW_A_LINK)),
        ("bundle.tar", _OVER_A_HARD_LINK),
        ("bundle.tar.gz", gzip.compress(_OVER_A_HARD_LINK)),
        ("bundle.tar.gz", gzip.compress(_OVER_A_LINK)),
        ("bundle.zip", _zip_with_links({"weights/a.txt": b"hi\n"}, {"weights": "."})),
        ("bundle.zip", _zip_with_links({"weights/a.txt": b"hi\n"}, {"Weights": "."})),
        (
            "bundle.zip",
            _zip_with_links({"weights/a.txt": b"hi\n"}, {"t": "."}, _unicode_path("t", "weights")),
        ),
        (
            "bundle.zip",
            _stored_as(_zip_with_links({"\u00e9/a.txt": b"hi\n"}, {"Q9": "."}), b"Q9", b"\xc3\xa9"),
        ),
    ],
    ids=[
        "tar-file-over-a-same-named-link",
        "tar-file-below-a-directory-link",
        "compressed-tar-file-below-a-directory-link",
        "tar-file-over-a-hard-link",
        "compressed-tar-file-over-a-hard-link",
        "compressed-tar",
        "zip",
        "zip-name-in-another-case",
        "zip-unicode-path",
        "zip-name-bytes-read-as-utf8",
    ],
)
def test_a_member_at_or_below_a_link_leaves_the_archive_unscanned(
    tmp_path: Path, name: str, content: bytes
) -> None:
    """Unpacked, such a member is written where the link leads, which the listing does not show."""
    summaries, ctx = _summaries(tmp_path, name, content)

    assert [s for s in summaries if _THROUGH in s], summaries
    assert str(tmp_path / name) in ctx.examined_paths()


@pytest.mark.parametrize(
    ("name", "content"),
    [
        (
            "bundle.tar",
            _tar(
                ("v1/model.pkl", _CLEAN),
                _link("latest", "v1", tarfile.SYMTYPE),
                ("docs/a.txt", b"hi\n"),
            ),
        ),
        (
            "bundle.zip",
            _zip_with_links({"v1/model.pkl": _CLEAN, "docs/a.txt": b"hi\n"}, {"latest": "v1"}),
        ),
    ],
    ids=["tar", "zip"],
)
def test_links_beside_the_members_leave_an_archive_scanned(
    tmp_path: Path, name: str, content: bytes
) -> None:
    summaries, _ctx = _summaries(tmp_path, name, content)

    assert summaries == []
