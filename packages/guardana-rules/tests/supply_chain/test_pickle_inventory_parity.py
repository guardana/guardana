"""What `pickle_opcode` reads, the inventory lists, so a run without the rule is unverified.

A pickle with no PROTO opcode under a name a loader opens by content, and a plain `.zip` or
tar holding a member named as a model, are models the rule reads. The inventory lists them
by the same core checks the rule counts them examined by, so every listed one is examined
when the rule runs, and a run without it reports them unread. Everything is built in code;
nothing is unpickled.
"""

import bz2
import collections
import gzip
import io
import lzma
import pickle
import random
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.inventory import named_as_archived_model, observe
from guardana.core.observation import ObservationKind
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import ScanResult, ShortfallKind
from guardana.core.rule import Rule, RuleContext
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import pickle_opcode
from guardana.rules.supply_chain.keras_lambda import KerasLambdaRule
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_SNIFFED_NAMES = ("model.sav", "model.p", "model.bin", "model.dat", "model.model", "model")
_CLEAN = {
    protocol: pickle.dumps(collections.OrderedDict(w=1), protocol=protocol) for protocol in (0, 1)
}
_SYSTEM = {0: b"cos\nsystem\n(Vid\ntR.", 1: b"cos\nsystem\n(X\x02\x00\x00\x00idtR."}
_CLEAN_HEADED = b"\x80\x02}q\x00X\x01\x00\x00\x00wq\x01K\x01s."


def _zip(members: dict[str, bytes], method: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _tar(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _entry(
    name: str,
    data: bytes,
    *,
    kind: bytes = tarfile.REGTYPE,
    link: str = "",
    pax: dict[str, str] | None = None,
) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = link
    info.size = len(data)
    info.pax_headers = pax or {}
    return info, data


def _tar_of(
    *entries: tuple[tarfile.TarInfo, bytes],
    tar_format: int = tarfile.PAX_FORMAT,
    global_pax: dict[str, str] | None = None,
) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(
        fileobj=buffer, mode="w", format=tar_format, pax_headers=global_pax or {}
    ) as archive:
        for info, data in entries:
            archive.addfile(info, io.BytesIO(data) if data else None)
    return buffer.getvalue()


def _unicode_path_zip(stored: str, shown: str) -> bytes:
    info = zipfile.ZipInfo(stored)
    path = shown.encode()
    crc = zlib.crc32(stored.encode())
    info.extra = struct.pack("<HHBL", 0x7075, 5 + len(path), 1, crc) + path
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(info, _CLEAN_HEADED)
    return buffer.getvalue()


_ARCHIVES: dict[str, tuple[str, Callable[[dict[str, bytes]], bytes]]] = {
    "stored-zip": ("model.zip", _zip),
    "deflated-zip": ("model.zip", lambda members: _zip(members, zipfile.ZIP_DEFLATED)),
    "tar": ("model.tar", _tar),
    "tar-gz": ("bundle.tar.gz", lambda members: gzip.compress(_tar(members))),
    "tgz": ("bundle.tgz", lambda members: gzip.compress(_tar(members))),
    "tar-bz2": ("bundle.tar.bz2", lambda members: bz2.compress(_tar(members))),
    "tar-xz": ("bundle.tar.xz", lambda members: lzma.compress(_tar(members))),
}


def _run(root: Path, rule: Rule) -> ScanResult:
    registry = Registry()
    registry.register_rule(rule)
    return Runner(registry=registry, profile=Profile(name="t", policy=Policy())).run(
        ArtifactTarget(root)
    )


def _models(result: ScanResult) -> list[tuple[str, str]]:
    return [
        (Path(item.ref).name, item.attributes["format"])
        for item in result.observations
        if item.kind is ObservationKind.MODEL
    ]


def _unexamined(result: ScanResult) -> list[str]:
    return [
        gap.detail
        for gap in result.coverage_shortfall
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
    ]


@pytest.mark.parametrize("protocol", [0, 1])
@pytest.mark.parametrize("name", _SNIFFED_NAMES)
def test_a_clean_headerless_pickle_under_a_sniffed_name_is_a_component_the_rule_passes(
    tmp_path: Path, name: str, protocol: int
) -> None:
    (tmp_path / name).write_bytes(_CLEAN[protocol])

    result = _run(tmp_path, PickleOpcodeRule())

    assert _models(result) == [(name, "pickle")]
    assert not result.findings
    assert not _unexamined(result)
    assert gate_outcome(result, Policy()) is GateOutcome.PASS


@pytest.mark.parametrize("protocol", [0, 1])
@pytest.mark.parametrize("name", _SNIFFED_NAMES)
def test_a_headerless_pickle_importing_os_system_is_a_component_that_fails_the_run(
    tmp_path: Path, name: str, protocol: int
) -> None:
    (tmp_path / name).write_bytes(_SYSTEM[protocol])

    result = _run(tmp_path, PickleOpcodeRule())

    assert _models(result) == [(name, "pickle")]
    assert [finding.severity for finding in result.findings] == [Severity.CRITICAL]
    assert gate_outcome(result, Policy()) is GateOutcome.FAIL


@pytest.mark.parametrize("archive", sorted(_ARCHIVES))
def test_a_plain_archive_holding_a_clean_model_is_a_component_the_rule_passes(
    tmp_path: Path, archive: str
) -> None:
    name, build = _ARCHIVES[archive]
    (tmp_path / name).write_bytes(build({"model.pkl": _CLEAN_HEADED}))

    result = _run(tmp_path, PickleOpcodeRule())

    assert [model for model, _format in _models(result)] == [name]
    assert not result.findings
    assert not _unexamined(result)
    assert gate_outcome(result, Policy()) is GateOutcome.PASS


@pytest.mark.parametrize("archive", sorted(_ARCHIVES))
def test_a_plain_archive_holding_a_pickle_importing_os_system_fails_the_run(
    tmp_path: Path, archive: str
) -> None:
    name, build = _ARCHIVES[archive]
    (tmp_path / name).write_bytes(build({"model.pkl": _SYSTEM[0]}))

    result = _run(tmp_path, PickleOpcodeRule())

    assert [model for model, _format in _models(result)] == [name]
    assert Severity.CRITICAL in {finding.severity for finding in result.findings}
    assert gate_outcome(result, Policy()) is GateOutcome.FAIL


@pytest.mark.parametrize(
    ("name", "data", "model_format"),
    [
        *((name, _CLEAN[0], "pickle") for name in _SNIFFED_NAMES),
        ("model.zip", _zip({"model.pkl": _CLEAN_HEADED}), "zip-archive"),
        ("model.tar", _tar({"model.pkl": _CLEAN_HEADED}), "tar-archive"),
        ("bundle.tar.gz", gzip.compress(_tar({"model.pkl": _CLEAN_HEADED})), "tar-archive"),
    ],
    ids=lambda value: value if isinstance(value, str) and "." in value else None,
)
def test_without_the_rule_such_a_model_leaves_the_run_unverified(
    tmp_path: Path, name: str, data: bytes, model_format: str
) -> None:
    (tmp_path / name).write_bytes(data)

    result = _run(tmp_path, KerasLambdaRule())

    unexamined = _unexamined(result)
    assert len(unexamined) == 1
    assert unexamined[0].startswith(f"1 {model_format} model component(s)")
    assert name in unexamined[0]
    assert gate_outcome(result, Policy()) is GateOutcome.INDETERMINATE


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("model.pkl", _CLEAN[0]),
        ("model.sav", _CLEAN_HEADED),
        ("model.pt", _zip({"archive/data.pkl": _CLEAN_HEADED})),
    ],
)
def test_the_controls_keep_their_one_component(tmp_path: Path, name: str, data: bytes) -> None:
    (tmp_path / name).write_bytes(data)

    result = _run(tmp_path, PickleOpcodeRule())

    assert len(_models(result)) == 1
    assert not _unexamined(result)


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("data.zip", _zip({"rows.csv": b"a,b\n1,2\n", "notes.txt": b"hello"})),
        ("sdist.tar.gz", gzip.compress(_tar({"pkg-1.0/setup.py": b"", "pkg-1.0/a.py": b""}))),
        ("dir.zip", _zip({"weights.pkl/": b"", "weights.pkl/notes.txt": b"x"})),
        ("hdf5.tar", _tar({"train.h5": b"x"})),
        ("model", b"MIT License\n" * 50),
        ("model.dat", bytes(range(256)) * 8),
        ("model.p", pickle.dumps({"w": [1, 2]}, protocol=0)),
    ],
)
def test_a_file_holding_no_model_is_no_component_with_or_without_the_rule(
    tmp_path: Path, name: str, data: bytes
) -> None:
    (tmp_path / name).write_bytes(data)

    for rule in (PickleOpcodeRule(), KerasLambdaRule()):
        result = _run(tmp_path, rule)
        assert not _models(result)
        assert not _unexamined(result)
        assert gate_outcome(result, Policy()) is GateOutcome.PASS


def _member_names() -> list[str]:
    suffixes = {
        *pickle_opcode._SUFFIXES,
        *pickle_opcode._MODEL_MEMBER_SUFFIXES,
        *pickle_opcode._UNREAD_MODEL_SUFFIXES,
        *pickle_opcode._DATASET_SHARED_SUFFIXES,
        *pickle_opcode._COMPRESSED_SUFFIXES,
        ".txt",
        ".py",
        ".csv",
        ".json",
        ".zip",
        ".tar",
        ".gz",
        "",
    }
    endings = {
        *pickle_opcode._COMPRESSED_MODEL_ENDINGS,
        *pickle_opcode._TORCH_TAR_NAMES,
        *pickle_opcode._COMPRESSED_TAR_ENDINGS,
    }
    whole = {
        *pickle_opcode._LEGACY_TORCH_MEMBERS,
        *pickle_opcode._UNREAD_MODEL_NAMES,
        *pickle_opcode._KERAS_DIRECTORY_FILES,
        "README",
        "model.tar",
        "weights.pkl/",
    }
    stems = [f"w{suffix}" for suffix in suffixes | endings] + sorted(whole)
    return [
        variant
        for stem in stems
        for variant in (stem, stem.upper(), f"deep/dir/{stem}", f".{stem.lstrip('w')}")
    ]


def test_the_inventory_names_an_archived_model_exactly_as_the_rule_does() -> None:
    names = _member_names()
    disagreements = [
        name
        for name in names
        if named_as_archived_model(name)
        is not (pickle_opcode._model_named(name) or pickle_opcode._unread_model(name, plain=True))
    ]

    assert len(names) > 300
    assert not disagreements


def test_every_file_the_inventory_lists_from_its_bytes_the_rule_examines(tmp_path: Path) -> None:
    rng = random.Random(350)  # noqa: S311 — seeded generated bytes, not a secret
    heads = [
        *_CLEAN.values(),
        *_SYSTEM.values(),
        pickle.dumps([1, "x", 2.0], protocol=0),
        pickle.dumps(collections.Counter("ab"), protocol=1),
        b"cnumpy.core.multiarray\n_reconstruct\n" + bytes(40),
        b"c__builtin__\nset\n(]tR.",
        *(bytes(rng.randrange(256) for _ in range(rng.choice((16, 600, 5000)))) for _ in range(60)),
        *(b"c" + bytes(rng.randrange(32, 127) for _ in range(300)) for _ in range(30)),
    ]
    archives = [
        _zip({"model.pkl": _CLEAN_HEADED}),
        _zip({"notes.txt": b"x"}),
        _tar({"w/model.bin": b"\x00"}),
        gzip.compress(_tar({"a.txt": b"x"})),
        b"\x1f\x8b\x08\x00" + bytes(64),
        b"PK\x03\x04" + bytes(64),
        _tar({"a.txt": b"x"})[:700],
        b"#!/bin/sh\n" * 30 + _zip({"m.joblib": _CLEAN_HEADED}),
        _zip({"model.pklX.txt": _CLEAN_HEADED}).replace(b"model.pklX.txt", b"model.pkl\x00.txt"),
        _unicode_path_zip("readme.txt", "model.pkl"),
        _tar_of(_entry("a.txt", b"x", pax={"path": "w/model.pkl"})),
        _tar_of(_entry("model.pkl", b"", kind=tarfile.SYMTYPE, link="a.txt")),
        _tar_of(
            _entry("a.txt", b"x"), _entry("model.pkl", b"", kind=tarfile.LNKTYPE, link="a.txt")
        ),
        _tar_of(_entry("a.txt", b"x"), global_pax={"path": "model.pkl"}),
        _tar_of(_entry("d" * 150 + "/model.pt", _CLEAN_HEADED), tar_format=tarfile.GNU_FORMAT),
        gzip.compress(_zip({"model.pkl": _CLEAN_HEADED})),
        lzma.compress(_tar({"model.pkl": _SYSTEM[0]})),
    ]
    for index, head in enumerate(heads):
        folder = tmp_path / f"h{index}"
        folder.mkdir()
        (folder / _SNIFFED_NAMES[index % len(_SNIFFED_NAMES)]).write_bytes(head)
    for index, data in enumerate(archives):
        for name in ("bundle.zip", "bundle.tar", "bundle.tar.gz"):
            folder = tmp_path / f"a{index}-{name}"
            folder.mkdir()
            (folder / name).write_bytes(data)

    target = ArtifactTarget(tmp_path)
    listed = {item.ref for item in observe(target) if item.kind is ObservationKind.MODEL}
    context = RuleContext()
    list(PickleOpcodeRule().run(target, context))

    assert len(listed) > 20
    assert listed <= set(context.examined_paths())


def _member_tars() -> dict[str, bytes]:
    """Tars whose one member's path is long enough that a writer cuts its header name."""
    suffixes = (".py", ".png", ".pdf", ".txt", ".bin.txt", ".dat.csv", ".pkl", ".pt", ".bin")
    tars: dict[str, bytes] = {}
    for tar_format, label in ((tarfile.PAX_FORMAT, "pax"), (tarfile.GNU_FORMAT, "gnu")):
        for length in range(95, 111):
            for suffix in suffixes:
                path = "src/" + "a" * (length - len(suffix) - 6) + "/x" + suffix
                data = _tar_of(_entry(path, b"print(1)\n"), tar_format=tar_format)
                key = f"{label}-{length}-{suffix.strip('.').replace('.', '-')}"
                tars[f"{key}.tar"] = data
                tars[f"{key}.tar.gz"] = gzip.compress(data)
    tars["header-model-pax-text.tar"] = _tar_of(_entry("model.pkl", b"x", pax={"path": "a.txt"}))
    tars["header-text-pax-model.tar"] = _tar_of(
        _entry("a.txt", _CLEAN_HEADED, pax={"path": "model.pkl"})
    )
    return tars


def _member_zips() -> dict[str, bytes]:
    def with_path(version: int, crc_of: bytes, path: bytes) -> bytes:
        info = zipfile.ZipInfo("readme.txt")
        info.extra = struct.pack("<HHBL", 0x7075, 5 + len(path), version, zlib.crc32(crc_of)) + path
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(info, b"hello")
        return buffer.getvalue()

    counted = bytearray(_zip({"a.txt": b"x"}))
    struct.pack_into("<HH", counted, counted.rfind(b"PK\x05\x06") + 8, 2, 2)
    return {
        "unicode-v1-ours-not-utf8.zip": with_path(1, b"readme.txt", b"\xffmodel.pkl"),
        "unicode-v2-not-utf8.zip": with_path(2, b"", b"\xffmodel.pkl"),
        "unicode-v1-other-not-utf8.zip": with_path(1, b"other", b"\xffmodel.pkl"),
        "unicode-model.zip": with_path(1, b"readme.txt", b"model.pkl"),
        "declares-two-holds-one.zip": bytes(counted),
        "empty-streams.tar.gz": gzip.compress(b"") * 1100,
    }


def _tarfile_names_a_model(path: Path) -> bool:
    try:
        with tarfile.open(path) as archive:
            return any(
                named_as_archived_model(member.name)
                for member in archive.getmembers()
                if not member.isdir()
            )
    except tarfile.TarError:
        return True


def test_an_archive_is_listed_by_the_names_its_reader_gives_its_members(tmp_path: Path) -> None:
    tars = _member_tars()
    zips = _member_zips()
    for name, data in {**tars, **zips}.items():
        folder = tmp_path / name.replace(".", "-")
        folder.mkdir()
        (folder / name).write_bytes(data)

    target = ArtifactTarget(tmp_path)
    listed = {Path(item.ref).name for item in observe(target) if item.kind is ObservationKind.MODEL}
    context = RuleContext()
    list(PickleOpcodeRule().run(target, context))
    examined = {Path(path).name for path in context.examined_paths()}

    expected_tars = {
        name for name in tars if _tarfile_names_a_model(tmp_path / name.replace(".", "-") / name)
    }
    assert {name for name in listed if name in tars} == expected_tars
    assert "header-text-pax-model.tar" in expected_tars
    assert "header-model-pax-text.tar" not in expected_tars
    assert {name for name in listed if name in zips} == {
        "unicode-v1-ours-not-utf8.zip",
        "unicode-model.zip",
        "empty-streams.tar.gz",
    }
    assert listed <= examined
