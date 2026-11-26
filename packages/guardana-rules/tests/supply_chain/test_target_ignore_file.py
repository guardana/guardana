"""A scanned target's own ignore file cannot hide what a model loader reads from the scan."""

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest
from guardana.core.rule import Rule, RuleContext
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture
from guardana.core.target.artifact import ArtifactTarget
from guardana.rules import provide_rules

_FAMILY = "guardana.supply_chain."
_ORDINARY_FILE_RULES = frozenset(
    {
        "code_execution",
        "dependency_risk",
        "hallucinated_package",
        "hardcoded_secret",
        "insecure_transport",
        "malicious_dependency",
        "notebook_payload",
        "provenance",
        "remote_code",
    }
)
"""Rules that read source, manifests, notebooks and cards, which a target's ignore file may
exclude; only the profile decides about the files a model loader reads."""
_HONEST_SAFETENSORS = b"\x02\x00\x00\x00\x00\x00\x00\x00{}"


def _rules() -> list[Rule]:
    return [rule for rule in provide_rules() if rule.meta.id.startswith(_FAMILY)]


def _positive_samples() -> list[tuple[Rule, RuleFixture]]:
    return [
        (rule, fixture)
        for rule in _rules()
        if rule.meta.id.removeprefix(_FAMILY) not in _ORDINARY_FILE_RULES
        for fixture in rule.fixtures()
        if fixture.outcome is FixtureOutcome.FINDING and isinstance(fixture.target, ArtifactTarget)
    ]


def _found(rule: Rule, fixture: RuleFixture, root: Path) -> set[tuple[str, str, str]]:
    findings = (fixture.rule or rule).run(ArtifactTarget(root), RuleContext())
    return {(f.rule_id, f.target_ref.replace(str(root), ""), f.title) for f in findings}


def test_every_ordinary_file_rule_is_a_shipped_rule() -> None:
    shipped = {rule.meta.id.removeprefix(_FAMILY) for rule in _rules()}

    assert shipped >= _ORDINARY_FILE_RULES


_SAMPLES = _positive_samples()


def test_the_model_loader_rules_have_positive_samples() -> None:
    assert len({rule.meta.id for rule, _ in _SAMPLES}) >= 6


@pytest.mark.parametrize(
    ("rule", "fixture"),
    _SAMPLES,
    ids=[f"{rule.meta.id.removeprefix(_FAMILY)}:{fixture.name[:40]}" for rule, fixture in _SAMPLES],
)
def test_an_ignore_file_excluding_everything_hides_no_finding(
    rule: Rule, fixture: RuleFixture
) -> None:
    root = Path(fixture.target.ref)
    found = _found(rule, fixture, root)
    for directory in {root, *(path.parent for path in root.rglob("*") if path.is_file())}:
        (directory / "model.safetensors").write_bytes(_HONEST_SAFETENSORS)
    (root / ".guardanaignore").write_text("*\n", encoding="utf-8")

    assert found
    assert found <= _found(rule, fixture, root)


_SYSTEM = b"cos\nsystem\n(S'id'\ntR."
_SYSTEM_V2 = b"\x80\x02" + _SYSTEM


def _zipped(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, data)
        archive.writestr("archive/version", "3")
    return buffer.getvalue()


def _tarred(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _npy_of_objects(payload: bytes) -> bytes:
    header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    header += b" " * (63 - len(header) - 10) + b"\n"
    return b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header + payload


def _joblib_zlib(payload: bytes) -> bytes:
    return b"ZF" + f"{len(payload):#x}".encode().ljust(19) + zlib.compress(payload)


_BY_CONTENT = {
    "torch zip": _zipped("archive/data.pkl", _SYSTEM_V2),
    "tar": _tarred("data.pkl", _SYSTEM_V2),
    "gzip tar": gzip.compress(_tarred("data.pkl", _SYSTEM_V2)),
    "gzip": gzip.compress(_SYSTEM_V2),
    "bzip2": bz2.compress(_SYSTEM_V2),
    "xz": lzma.compress(_SYSTEM_V2),
    "lzma": lzma.compress(_SYSTEM_V2, format=lzma.FORMAT_ALONE),
    "zlib": zlib.compress(_SYSTEM_V2),
    "joblib zlib": _joblib_zlib(_SYSTEM_V2),
    "zstd": b"\x28\xb5\x2f\xfd" + bytes(60),
    "npy": _npy_of_objects(_SYSTEM_V2),
    "7z": b"7z\xbc\xaf\x27\x1c" + bytes(26),
    "protocol 0": _SYSTEM,
    "protocol 0 after a clean pickle": b"(dp0\n." + _SYSTEM,
    "protocol 0 after a hexadecimal INT": b"I0x10\n0" + _SYSTEM,
    "protocol 1": b"]q\x00(cos\nsystem\nq\x01e.",
    "stack global": b"\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85R.",
    "pickle past its head": b"(" + b"S'" + b"a" * 70_000 + b"'\n0" + _SYSTEM,
}
"""What a loader opening a file by content reads: archives, compressed streams, arrays and
pickles with no protocol header."""
_CONTENT_READ_NAMES = ("w2v.model", "clf.sav", "weights.dat", "x.p", "bundle", "w.bin")


def _pickle_rule() -> Rule:
    return next(rule for rule in provide_rules() if rule.meta.id == f"{_FAMILY}pickle_opcode")


def _reported(root: Path) -> set[tuple[str, str]]:
    findings = _pickle_rule().run(ArtifactTarget(root), RuleContext())
    return {(f.target_ref.replace(str(root), ""), f.title) for f in findings}


@pytest.mark.parametrize("name", _CONTENT_READ_NAMES)
@pytest.mark.parametrize("kind", sorted(_BY_CONTENT))
def test_an_ignore_file_hides_nothing_a_loader_reads_by_content(
    tmp_path: Path, kind: str, name: str
) -> None:
    (tmp_path / name).write_bytes(_BY_CONTENT[kind])
    reported = _reported(tmp_path)
    (tmp_path / ".guardanaignore").write_text(f"{name}\n", encoding="utf-8")

    assert _reported(tmp_path) == reported


@pytest.mark.parametrize("kind", ["protocol 0", "torch zip", "gzip"])
def test_an_ignore_file_hides_nothing_behind_a_link_to_another_name(
    tmp_path: Path, kind: str
) -> None:
    (tmp_path / "blobs").mkdir()
    (tmp_path / "blobs" / "part.txt").write_bytes(_BY_CONTENT[kind])
    (tmp_path / "x.p").symlink_to(tmp_path / "blobs" / "part.txt")
    reported = _reported(tmp_path)
    (tmp_path / ".guardanaignore").write_text("x.p\nblobs\n", encoding="utf-8")

    assert reported
    assert _reported(tmp_path) == reported
