"""An archive is refused before `zipfile` or `tarfile` lists it when it declares too much.

Both libraries read a zip's whole central directory, and a tar's extended headers, before
any member can be read. Each archive here declares its size in a few crafted bytes rather
than holding it; nothing is unpickled.
"""

import io
import os
import re
import struct
import tarfile
import threading
import zipfile
from pathlib import Path
from typing import Literal

import pytest
from guardana.core.gate import exit_code_for, gate_outcome
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import ScanResult, ShortfallKind
from guardana.core.rule import Rule
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import _tar, pickle_opcode
from guardana.rules.supply_chain._zip import declared_directories, listing_refusal
from guardana.rules.supply_chain.keras_lambda import KerasLambdaRule

_RULE_ID = "guardana.supply_chain.pickle_opcode"
_SYSTEM = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00id\x85R."
_HUGE = 200 * 1024 * 1024
_ZIP64_END = struct.Struct("<4sQ2H2L4Q")


def _run(tmp_path: Path, name: str, content: bytes, rule: Rule | None = None) -> ScanResult:
    (tmp_path / name).write_bytes(content)
    registry = Registry()
    registry.register_rule(rule or pickle_opcode.PickleOpcodeRule())
    return Runner(registry=registry, profile=Profile(name="t", policy=Policy())).run(
        ArtifactTarget(tmp_path)
    )


def _unscanned(result: ScanResult, rule_id: str = _RULE_ID) -> list[str]:
    return [f.evidence.summary for f in result.unverified if f.rule_id == rule_id]


def _unread(result: ScanResult, rule_id: str = _RULE_ID) -> list[str]:
    return [
        gap.name
        for gap in result.coverage_shortfall
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT and gap.detail.startswith(rule_id)
    ]


def _critical(result: ScanResult) -> list[str]:
    return [
        f.evidence.summary
        for f in result.findings
        if f.rule_id == _RULE_ID and f.severity.name == "CRITICAL"
    ]


def _assert_refused(result: ScanResult, path: Path, bound: int) -> None:
    summaries = _unscanned(result)
    assert any(str(bound) in summary for summary in summaries), summaries
    assert _unread(result) == [str(path)]
    assert exit_code_for(gate_outcome(result, Policy())) == 2


def _assert_refused_saying(result: ScanResult, path: Path, reason: str) -> None:
    summaries = _unscanned(result)
    assert any(reason in summary for summary in summaries), summaries
    assert _unread(result) == [str(path)]
    assert exit_code_for(gate_outcome(result, Policy())) == 2


def _spy(monkeypatch: pytest.MonkeyPatch, owner: object, name: str) -> list[object]:
    """Record every call to `owner.name`, which still runs, so a test can say none came."""
    calls: list[object] = []
    real = getattr(owner, name)

    def recording(*args: object, **kwargs: object) -> object:
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(owner, name, recording)
    return calls


def _zip_spy(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    return _spy(monkeypatch, zipfile, "ZipFile")


def _tar_spy(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    return _spy(monkeypatch, tarfile, "open")


def _zip(
    members: dict[str, bytes],
    *,
    force_zip64: bool = False,
    zip64_end: bool = False,
    comment: bytes = b"",
) -> bytes:
    buffer = io.BytesIO()
    with pytest.MonkeyPatch.context() as patch:
        if zip64_end:
            # The end record takes its ZIP64 form past this many entries.
            patch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 0)
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in members.items():
                with archive.open(name, "w", force_zip64=force_zip64) as member:
                    member.write(data)
            archive.comment = comment
    return buffer.getvalue()


def _with_zip64_end(content: bytes, **fields: int) -> bytes:
    """`content` with the named fields of its ZIP64 end record replaced."""
    at = content.rindex(b"PK\x06\x06")
    names = ("sig", "size", "made", "needed", "disk", "start", "here", "total", "bytes", "offset")
    values = dict(zip(names, _ZIP64_END.unpack_from(content, at), strict=True))
    values.update(fields)
    record = _ZIP64_END.pack(*(values[name] for name in names))
    return content[:at] + record + content[at + _ZIP64_END.size :]


def _with_end_directory_bytes(content: bytes, size: int) -> bytes:
    """`content` with the central directory size its 32-bit end record declares replaced."""
    at = content.rindex(b"PK\x05\x06") + 12
    return content[:at] + struct.pack("<L", size) + content[at + 4 :]


_CHECKPOINT = {"archive/data.pkl": _SYSTEM, "archive/version": b"3\n"}


def test_a_zip64_end_record_declaring_too_many_entries_is_refused_unopened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = _with_zip64_end(_zip(_CHECKPOINT, zip64_end=True), here=300_000, total=300_000)
    calls = _zip_spy(monkeypatch)

    result = _run(tmp_path, "model.pt", content)

    assert calls == []
    _assert_refused(result, tmp_path / "model.pt", pickle_opcode._ARCHIVE_MAX_ENTRIES)


def test_a_keras_archive_declaring_too_many_entries_is_refused_unopened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = b'{"class_name": "Sequential", "config": {"layers": []}}'
    content = _with_zip64_end(
        _zip({"config.json": config}, zip64_end=True), here=300_000, total=300_000
    )
    calls = _zip_spy(monkeypatch)
    rule = KerasLambdaRule()

    result = _run(tmp_path, "model.keras", content, rule)

    assert calls == []
    summaries = _unscanned(result, rule.meta.id)
    assert any(str(pickle_opcode._ARCHIVE_MAX_ENTRIES) in s for s in summaries), summaries
    assert _unread(result, rule.meta.id) == [str(tmp_path / "model.keras")]
    assert exit_code_for(gate_outcome(result, Policy())) == 2


@pytest.mark.parametrize("zip64", [False, True], ids=["end-record", "zip64-end-record"])
def test_a_zip_declaring_a_central_directory_past_the_bound_is_refused_unopened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, zip64: bool
) -> None:
    oversized = pickle_opcode._ZIP_DIRECTORY_MAX_BYTES + 1
    archive = _zip(_CHECKPOINT, zip64_end=zip64)
    if zip64:
        content = _with_zip64_end(archive, bytes=oversized)
    else:
        content = _with_end_directory_bytes(archive, oversized)
    calls = _zip_spy(monkeypatch)

    result = _run(tmp_path, "model.pt", content)

    assert calls == []
    _assert_refused(result, tmp_path / "model.pt", pickle_opcode._ZIP_DIRECTORY_MAX_BYTES)


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("bundle.zip", _zip({f"img/{n}.jpg": b"\xff\xd8\xff" for n in range(5)})),
        (
            "bundle.tar",
            b"".join(tarfile.TarInfo(f"img/{n}.jpg").tobuf(tarfile.USTAR_FORMAT) for n in range(5))
            + bytes(2 * tarfile.BLOCKSIZE),
        ),
    ],
    ids=["zip", "tar"],
)
def test_an_archive_listing_more_entries_than_the_bound_is_refused_unopened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, content: bytes
) -> None:
    """Every entry counts, read or not: the library parses each one before any is read."""
    monkeypatch.setattr(pickle_opcode, "_ARCHIVE_MAX_ENTRIES", 4)
    zip_calls = _zip_spy(monkeypatch)
    tar_calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, name, content)

    assert zip_calls == []
    assert tar_calls == []
    _assert_refused(result, tmp_path / name, 4)


@pytest.mark.parametrize(
    "archive",
    [
        _zip(_CHECKPOINT),
        _zip(_CHECKPOINT, force_zip64=True),
        _zip(_CHECKPOINT, zip64_end=True),
        _zip(_CHECKPOINT, force_zip64=True, zip64_end=True),
        _zip(_CHECKPOINT, comment=b"a release comment"),
        _zip(_CHECKPOINT, zip64_end=True, comment=b"release"),
    ],
    ids=["plain", "zip64-entries", "zip64-end-record", "zip64-both", "comment", "zip64-comment"],
)
def test_a_zip_within_the_bounds_is_still_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, archive: bytes
) -> None:
    calls = _zip_spy(monkeypatch)

    result = _run(tmp_path, "model.pt", archive)

    assert calls
    assert _critical(result)
    assert _unscanned(result) == []


def test_a_zip_with_no_end_record_is_reported_by_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tail the bound cannot read is left to `zipfile`, which refuses it as before."""
    content = _zip(_CHECKPOINT)
    content = content[: content.rindex(b"PK\x05\x06")]
    calls = _zip_spy(monkeypatch)

    result = _run(tmp_path, "model.pt", content)

    assert calls
    assert _unscanned(result) == ["malformed zip container; not scanned"]


_CENTRAL_RECORD = struct.pack("<4s6H3L5H2L", b"PK\x01\x02", 20, 20, *([0] * 14))


def _declaring_one_entry(records: int) -> bytes:
    """A zip whose end record declares one entry in front of `records` more of them."""
    archive = _zip(_CHECKPOINT)
    directory_at = archive.index(b"PK\x01\x02")
    end_at = archive.rindex(b"PK\x05\x06")
    directory = archive[directory_at:end_at] + _CENTRAL_RECORD * records
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(directory), directory_at, 0)
    return archive[:directory_at] + directory + end


def test_a_zip_directory_holding_more_records_than_it_declares_is_refused_unopened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`zipfile` lists every record in the directory, whatever count the end record gives."""
    monkeypatch.setattr(pickle_opcode, "_ARCHIVE_MAX_ENTRIES", 4)
    content = _declaring_one_entry(8)
    calls = _zip_spy(monkeypatch)

    result = _run(tmp_path, "model.pt", content)

    assert calls == []
    _assert_refused_saying(result, tmp_path / "model.pt", "holds more than 4 entries")


def test_the_32_bit_end_record_beside_a_zip64_one_is_checked_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oversized = pickle_opcode._ZIP_DIRECTORY_MAX_BYTES + 1
    content = _with_end_directory_bytes(_zip(_CHECKPOINT, zip64_end=True), oversized)
    calls = _zip_spy(monkeypatch)

    result = _run(tmp_path, "model.pt", content)

    assert calls == []
    _assert_refused(result, tmp_path / "model.pt", pickle_opcode._ZIP_DIRECTORY_MAX_BYTES)


def test_the_directory_bound_holds_a_checkpoint_with_the_entry_bound_of_tensors() -> None:
    """A checkpoint with as many entries as an archive may list, each named at length."""
    stem = "a-fine-tuned-model-checkpoint-named-at-length/data/"
    entries = 2000
    members = {f"{stem}{99_999 - n}": b"" for n in range(entries)}
    archive = _zip(members, force_zip64=True, zip64_end=True)

    directory = declared_directories(io.BytesIO(archive))[0]

    assert directory.entries == entries
    per_entry = directory.size / entries
    assert per_entry * pickle_opcode._ARCHIVE_MAX_ENTRIES <= pickle_opcode._ZIP_DIRECTORY_MAX_BYTES


def _header(
    name: str, kind: bytes, size: int, fmt: Literal[0, 1, 2] = tarfile.USTAR_FORMAT
) -> bytes:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = size
    return info.tobuf(fmt)


def _padded(data: bytes) -> bytes:
    return data + bytes(-len(data) % tarfile.BLOCKSIZE)


def _record(keyword: str, value: str) -> bytes:
    body = f" {keyword}={value}\n".encode()
    length = len(body)
    while length != len(str(length)) + len(body):
        length = len(str(length)) + len(body)
    return str(length).encode() + body


def _pax(kind: bytes, *records: bytes) -> bytes:
    payload = b"".join(records)
    return _header("././@PaxHeader", kind, len(payload)) + _padded(payload)


def _member(name: str, data: bytes, *, declared: int | None = None) -> bytes:
    size = len(data) if declared is None else declared
    return _header(name, tarfile.REGTYPE, size) + _padded(data)


_END = bytes(2 * tarfile.BLOCKSIZE)


@pytest.mark.parametrize(
    "kind",
    [
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
    ],
    ids=["pax", "pax-global", "solaris", "gnu-long-name", "gnu-long-link"],
)
def test_a_tar_declaring_an_oversized_extended_header_is_refused_unopened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: bytes
) -> None:
    content = _member("sys_info", b"\x80\x02}q\x00.") + _header("././@Long", kind, _HUGE) + _END
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "model.pth.tar", content)

    assert calls == []
    _assert_refused(result, tmp_path / "model.pth.tar", _tar.TAR_EXTENDED_HEADER_MAX_BYTES)


def test_extended_headers_in_front_of_one_member_count_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_tar, "TAR_EXTENDED_HEADER_MAX_BYTES", 1024)
    long_name = _header("././@LongLink", tarfile.GNUTYPE_LONGNAME, 768) + _padded(bytes(768))
    pax = _header("././@PaxHeader", tarfile.XHDTYPE, 768) + _padded(bytes(768))
    content = long_name + pax + _member("pickle", _SYSTEM) + _END
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "model.pth.tar", content)

    assert calls == []
    _assert_refused(result, tmp_path / "model.pth.tar", 1024)


def _fake_oversized_header() -> bytes:
    """Member data that reads as a PAX header declaring far more than the bound."""
    return _header("././@PaxHeader", tarfile.XHDTYPE, _HUGE)


def test_a_pax_size_that_covers_a_header_shaped_block_is_followed_past_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The member's PAX size, not its header's, says where `tarfile` reads the next header."""
    data = _fake_oversized_header()
    content = (
        _pax(tarfile.XHDTYPE, _record("size", str(len(data))))
        + _member("notes.txt", data, declared=0)
        + _member("pickle", _SYSTEM)
        + _END
    )
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "model.pth.tar", content)

    assert calls
    assert _critical(result)


def test_a_pax_size_that_uncovers_a_header_shaped_block_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A PAX size of zero makes `tarfile` read the member's data as the next header."""
    data = _fake_oversized_header()
    content = (
        _pax(tarfile.XHDTYPE, _record("path", "notes.txt"), _record("size", "0"))
        + _member("notes.txt", data)
        + _END
    )
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "model.pth.tar", content)

    assert calls == []
    _assert_refused(result, tmp_path / "model.pth.tar", _tar.TAR_EXTENDED_HEADER_MAX_BYTES)


def _checksummed(block: bytearray) -> bytes:
    block[148:156] = b" " * 8
    block[148:156] = b"%06o\x00 " % sum(block)
    return bytes(block)


def test_a_header_tarfile_releases_read_differently_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After a long name, an old-style file header named as a directory has no agreed size."""
    long_name = _header("././@LongLink", tarfile.GNUTYPE_LONGNAME, 4) + _padded(b"dir/")
    content = long_name + _header("dir/", tarfile.AREGTYPE, tarfile.BLOCKSIZE) + _END
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "model.pth.tar", content)

    assert calls == []
    assert [s for s in _unscanned(result) if "ambiguous header at byte 1024" in s]
    assert _unread(result) == [str(tmp_path / "model.pth.tar")]


def _damaged(member: bytes) -> bytes:
    block = bytearray(member)
    block[148:156] = b"0000000\x00"
    return bytes(block)


def _sparse_old_gnu() -> bytes:
    block = bytearray(_header("sparse.bin", tarfile.GNUTYPE_SPARSE, 0, tarfile.GNU_FORMAT))
    block[482] = 1
    return _checksummed(block) + bytes(tarfile.BLOCKSIZE)


_SIBLING = _member("ck/data.pkl", _SYSTEM) + _END


def _sparse_10(fields: list[int], *, data: int = 0, extra: bytes = b"") -> bytes:
    """A sparse 1.0 member as bsdtar writes one: its map at the start of its data."""
    sparse_map = _padded(f"{len(fields) // 2}\n".encode() + b"".join(b"%d\n" % n for n in fields))
    records = (
        _record("GNU.sparse.major", "1"),
        _record("GNU.sparse.minor", "0"),
        _record("GNU.sparse.name", "ck/weights.bin"),
        _record("GNU.sparse.realsize", "20971520"),
    )
    header = _header("ck/GNUSparseFile.0/weights.bin", tarfile.REGTYPE, len(sparse_map) + data)
    return _pax(tarfile.XHDTYPE, *records, extra) + header + sparse_map + _padded(bytes(data))


@pytest.mark.parametrize(
    "content",
    [
        _sparse_10([0, 0, 20971520, 0]) + _SIBLING,
        _sparse_10([0, 3], data=3) + _SIBLING,
        _sparse_old_gnu() + _SIBLING,
        _pax(tarfile.XHDTYPE, _record("GNU.sparse.map", "0,3"))
        + _member("ck/weights.bin", b"abc")
        + _SIBLING,
        _pax(
            tarfile.XHDTYPE,
            _record("GNU.sparse.size", "3"),
            _record("GNU.sparse.offset", "0"),
            _record("GNU.sparse.numbytes", "3"),
        )
        + _member("ck/weights.bin", b"abc")
        + _SIBLING,
        _pax(tarfile.XGLTYPE, _record("GNU.sparse.map", "0,0"))
        + _member("ck/weights.bin", b"")
        + _SIBLING,
    ],
    ids=["bsdtar-1.0", "1.0-with-data", "gnu-type-s", "pax-0.1", "pax-0.0", "global-0.1"],
)
def test_a_sparse_member_is_followed_to_the_members_after_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes
) -> None:
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "bundle.tar", content)

    assert calls
    assert _critical(result)
    assert _unscanned(result) == []


def _long_name(size: int = 0) -> bytes:
    return _header("././@LongLink", tarfile.GNUTYPE_LONGNAME, size) + _padded(bytes(size))


def _sized(*records: bytes) -> bytes:
    return _pax(tarfile.XHDTYPE, _record("size", "0"), *records)


@pytest.mark.parametrize(
    "content",
    [
        _pax(
            tarfile.XHDTYPE,
            _record("GNU.sparse.major", "1"),
            _record("GNU.sparse.minor", "0"),
            _record("size", "0"),
        )
        + _header("ck/weights.bin", tarfile.REGTYPE, 2 * tarfile.BLOCKSIZE)
        + _padded(b"0\n")
        + _SIBLING,
        _sized() + _sparse_old_gnu() + _SIBLING,
        _sized() + _long_name(4) + _member("ck/weights.bin", b"") + _SIBLING,
        _sized() + _sized() + _member("ck/weights.bin", b"") + _SIBLING,
        _sized(_record("GNU.sparse.realsize", "0")) + _member("ck/weights.bin", b"") + _SIBLING,
    ],
    ids=["sparse-1.0-map", "gnu-type-s", "long-name-between", "two-sizes", "sparse-realsize"],
)
def test_a_pax_size_tarfile_releases_place_differently_is_refused_unopened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes
) -> None:
    """Some releases count a PAX size from the member's header, others from its data."""
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "bundle.tar", content)

    assert calls == []
    _assert_refused_saying(result, tmp_path / "bundle.tar", "releases read differently")


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (_sparse_10([0, 1] * 5) + _SIBLING, "more than 4 regions"),
        (
            _pax(tarfile.XHDTYPE, _record("GNU.sparse.map", ",".join(["0,1"] * 5)))
            + _member("ck/weights.bin", b"")
            + _SIBLING,
            "more than 4 regions",
        ),
        (
            _pax(tarfile.XGLTYPE, _record("GNU.sparse.map", ",".join(["0,1"] * 5)))
            + _member("ck/weights.bin", b"")
            + _SIBLING,
            "more than 4 regions",
        ),
        (
            _pax(
                tarfile.XHDTYPE,
                _record("GNU.sparse.size", "0"),
                *[_record("GNU.sparse.offset", "0")] * 5,
            )
            + _member("ck/weights.bin", b"")
            + _SIBLING,
            "more than 4 regions",
        ),
        (_sparse_old_gnu() + _SIBLING, "more than 4 regions"),
        (_sparse_10([10**500] * 6) + _SIBLING, "oversized map"),
    ],
    ids=[
        "1.0-entries",
        "0.1-entries",
        "global-entries",
        "0.0-entries",
        "gnu-s-blocks",
        "1.0-bytes",
    ],
)
def test_a_sparse_map_past_its_bounds_is_refused_unopened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes, reason: str
) -> None:
    monkeypatch.setattr(_tar, "TAR_SPARSE_MAP_MAX_ENTRIES", 4)
    monkeypatch.setattr(_tar, "TAR_EXTENDED_HEADER_MAX_BYTES", 1024)
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "bundle.tar", content)

    assert calls == []
    _assert_refused_saying(result, tmp_path / "bundle.tar", reason)


def _global_records(records: int, members: int, *, pax_per_member: bool) -> bytes:
    found = b"".join(_record(f"key{n}", "v") for n in range(records))
    each = _pax(tarfile.XHDTYPE, _record("comment", "m")) if pax_per_member else b""
    entries = b"".join(each + _member(f"img/{n}.jpg", b"\xff\xd8\xff") for n in range(members))
    return _pax(tarfile.XGLTYPE, found) + entries + _SIBLING


@pytest.mark.parametrize(
    ("pax_per_member", "refused"), [(False, False), (True, True)], ids=["members", "pax-headers"]
)
def test_global_records_count_once_for_every_member_and_pax_header_after_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pax_per_member: bool, refused: bool
) -> None:
    """`tarfile` copies the global records into each member and each PAX header."""
    monkeypatch.setattr(_tar, "TAR_GLOBAL_RECORDS_APPLIED_MAX", 100)
    content = _global_records(20, 3, pax_per_member=pax_per_member)
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "bundle.tar", content)

    if refused:
        assert calls == []
        _assert_refused_saying(result, tmp_path / "bundle.tar", "more than the 100")
    else:
        assert calls
        assert _critical(result)


def test_a_git_archive_global_record_stays_far_inside_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`git archive` writes one global `comment` record in front of every member."""
    content = _pax(tarfile.XGLTYPE, _record("comment", "326a98b7f07968f4daf9e36007862c91ad440ae4"))
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "repo.tar", content + _SIBLING)

    assert calls
    assert _critical(result)
    applied_at_most = _tar.TAR_HEADERS_PER_ENTRY * pickle_opcode._ARCHIVE_MAX_ENTRIES
    assert applied_at_most * 2 <= _tar.TAR_GLOBAL_RECORDS_APPLIED_MAX
    assert _tar.TAR_GLOBAL_RECORDS_APPLIED_MAX < 814 * 10_000


def test_an_error_tarfile_raises_while_listing_is_reported_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`tarfile` raises IndexError on a sparse member cut inside its extension blocks."""
    monkeypatch.setattr(pickle_opcode, "listing_refusal", lambda *_args, **_kwargs: None)
    content = _sparse_old_gnu()[: tarfile.BLOCKSIZE]

    result = _run(tmp_path, "model.pth.tar", content)

    assert result.errors == ()
    _assert_refused_saying(result, tmp_path / "model.pth.tar", "malformed tar archive")


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (
            _member("pickle", b"\x80\x02}q\x00.")
            + _damaged(_member("tensors", b"\x80\x02}q\x00."))
            + _END,
            "damaged header at byte 1024",
        ),
        (
            _pax(tarfile.XHDTYPE, _record("size", "-512")) + _member("m", b"") + _END,
            "negative size at byte 1024",
        ),
        (
            _pax(tarfile.XHDTYPE, b"99 size=1\n") + _member("m", b"") + _END,
            "malformed PAX header at byte 0",
        ),
        (
            _header("././@LongLink", tarfile.GNUTYPE_LONGNAME, 0),
            "damaged header at byte 512",
        ),
    ],
    ids=["damaged-checksum", "negative-pax-size", "pax-framing", "ends-in-extended"],
)
def test_a_header_the_walk_cannot_follow_is_refused_unopened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes, reason: str
) -> None:
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "model.pth.tar", content)

    assert calls == []
    _assert_refused_saying(result, tmp_path / "model.pth.tar", reason)


def test_more_extended_headers_in_front_of_one_member_than_the_bound_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bound = _tar.TAR_EXTENDED_HEADERS_PER_MEMBER
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "model.pth.tar", _long_name() * (bound + 1) + _member("m", b"") + _END)

    assert calls == []
    _assert_refused_saying(result, tmp_path / "model.pth.tar", f"more than {bound} extended")


def test_headers_past_the_bound_for_the_entries_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every header counts, the extended ones in front of each member included."""
    monkeypatch.setattr(pickle_opcode, "_ARCHIVE_MAX_ENTRIES", 2)
    bound = 2 * _tar.TAR_HEADERS_PER_ENTRY
    member = _long_name() * 4 + _member("m", b"")
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "model.pth.tar", member * 2 + _END)

    assert calls == []
    _assert_refused_saying(result, tmp_path / "model.pth.tar", f"more than {bound} headers")


_LONG_DIRECTORY = "checkpoints/" + "epoch-0042-" * 10 + "/"


def _formatted_tar(fmt: int, *, pax_headers: dict[str, str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=fmt, pax_headers=pax_headers) as archive:
        payload = tarfile.TarInfo(_LONG_DIRECTORY + "model.pkl")
        payload.size = len(_SYSTEM)
        archive.addfile(payload, io.BytesIO(_SYSTEM))
        if fmt != tarfile.USTAR_FORMAT:
            link = tarfile.TarInfo("weights/model.pkl")
            link.type = tarfile.SYMTYPE
            link.linkname = "../" + _LONG_DIRECTORY + "model.pkl"
            archive.addfile(link)
    return buffer.getvalue()


@pytest.mark.parametrize(
    "content",
    [
        _formatted_tar(tarfile.USTAR_FORMAT),
        _formatted_tar(tarfile.GNU_FORMAT),
        _formatted_tar(tarfile.PAX_FORMAT),
        _formatted_tar(tarfile.PAX_FORMAT, pax_headers={"comment": "release"}),
    ],
    ids=["ustar", "gnu", "pax", "pax-global"],
)
def test_a_tar_within_the_bounds_is_still_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes
) -> None:
    calls = _tar_spy(monkeypatch)

    result = _run(tmp_path, "bundle.tar", content)

    assert calls
    assert _critical(result)
    assert _unscanned(result) == []


class _CountingReader(io.BytesIO):
    """A file that counts its reads and the bytes they return."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.reads = 0
        self.read_bytes = 0

    def read(self, size: int | None = -1, /) -> bytes:
        data = super().read(size)
        self.reads += 1
        self.read_bytes += len(data)
        return data


def test_the_tar_walk_reads_one_block_per_header() -> None:
    members = 200
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for n in range(members):
            info = tarfile.TarInfo(f"archive/data/{n}")
            info.size = 3000
            archive.addfile(info, io.BytesIO(bytes(3000)))
    handle = _CountingReader(buffer.getvalue())

    refusal = _tar.listing_refusal(handle, max_entries=members)

    assert refusal is None
    assert handle.reads == members + 1
    assert handle.read_bytes <= (members + 1) * tarfile.BLOCKSIZE


_MIB = 1024 * 1024
_DOCS = Path(__file__).resolve().parents[4] / "docs"


def _passage(page: str, opening: str, closing: str = "\n\n") -> str:
    text = (_DOCS / page).read_text(encoding="utf-8")
    start = text.index(opening)
    return text[start : text.index(closing, start + len(opening))]


def test_the_scan_page_states_each_archive_bound_as_the_code_sets_it() -> None:
    paragraph = _passage("usage-scan.md", "An archive is refused before it is opened")
    entries = f"{pickle_opcode._ARCHIVE_MAX_ENTRIES:,}"

    stated = re.findall(r"\b\d[\d,]*(?: MiB)?", paragraph)

    assert _tar.TAR_EXTENDED_HEADER_MAX_BYTES % _MIB == 0
    assert stated == [
        entries,
        f"{pickle_opcode._ZIP_DIRECTORY_MAX_BYTES:,}",
        entries,
        entries,
        f"{_tar.TAR_HEADERS_PER_ENTRY * pickle_opcode._ARCHIVE_MAX_ENTRIES:,}",
        str(_tar.TAR_EXTENDED_HEADERS_PER_MEMBER),
        f"{_tar.TAR_EXTENDED_HEADER_MAX_BYTES // _MIB} MiB",
        f"{_tar.TAR_GLOBAL_RECORDS_APPLIED_MAX:,}",
        f"{_tar.TAR_SPARSE_MAP_MAX_ENTRIES:,}",
        f"{_tar.TAR_EXTENDED_HEADER_MAX_BYTES // _MIB} MiB",
    ]


def test_the_known_limit_states_the_entry_bound_as_the_code_sets_it() -> None:
    section = _passage("product-status.md", "### An archive with more than", "\n### ")

    assert re.findall(r"\b\d[\d,]+", section) == [f"{pickle_opcode._ARCHIVE_MAX_ENTRIES:,}"] * 2


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
def test_the_zip_listing_check_never_opens_a_fifo(tmp_path: Path) -> None:
    fifo = tmp_path / "model.keras"
    os.mkfifo(fifo)
    refusals: list[str | None] = []
    worker = threading.Thread(
        target=lambda: refusals.append(
            listing_refusal(fifo, max_entries=10, max_directory_bytes=1024)
        ),
        daemon=True,
    )

    worker.start()
    worker.join(timeout=10)
    blocked = worker.is_alive()
    if blocked:
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        worker.join(timeout=10)

    assert not blocked
    assert refusals == [None]
