"""One archive costs a bounded number of operations, and reaching a bound is never clean.

Counted, never timed: the opcodes the rule reads and the members opened are
the work, so the tests count them.
"""

import collections
import io
import os
import pickle
import pickletools
import struct
import sys
import types
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import IO

import pytest
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import ScanResult, ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.runner import Runner
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import pickle_opcode
from guardana.rules.supply_chain._opcodes import read_opcodes
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule

_RULE_ID = "guardana.supply_chain.pickle_opcode"


class _Evil:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("echo pwned",))


def _zip(members: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _count_opcodes(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Patch the rule's opcode reader to count every opcode it yields; read `[0]` after."""
    walked = [0]
    real_reader = read_opcodes

    def counting(stream: IO[bytes]) -> Iterator[tuple[pickletools.OpcodeInfo, object]]:
        for item in real_reader(stream):
            walked[0] += 1
            yield item

    monkeypatch.setattr(pickle_opcode, "read_opcodes", counting)
    return walked


def _run(root: Path) -> ScanResult:
    # The rule comes from the module these tests patch: discovery could import a fresh
    # copy of it after another test cleared `sys.modules`, and the patches would miss.
    registry = Registry()
    registry.register_rule(pickle_opcode.PickleOpcodeRule())
    return Runner(registry=registry, profile=Profile(name="t", policy=Policy())).run(
        ArtifactTarget(root)
    )


def _unverified_naming(result: ScanResult, bound: int) -> list[str]:
    return [
        f.evidence.summary
        for f in result.unverified
        if f.rule_id == _RULE_ID and str(bound) in f.evidence.summary
    ]


def _unread(result: ScanResult) -> list[str]:
    return [
        gap.name
        for gap in result.coverage_shortfall
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT and gap.detail.startswith(_RULE_ID)
    ]


def test_opcodes_walked_across_members_stop_at_the_archive_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deflated members of cheap opcodes cost the archive's bound, not their sum."""
    monkeypatch.setattr(pickle_opcode, "_ARCHIVE_OPCODE_FLOOR", 2000)
    member = b"\x80\x02" + b"N0" * 3000 + b"."  # NONE, POP: no import, all work
    archive = _zip({f"archive/p{i}.pkl": member for i in range(3)})
    (tmp_path / "model.pt").write_bytes(archive)
    bound = 2000 + len(archive)
    walked = _count_opcodes(monkeypatch)

    result = _run(tmp_path)

    assert walked[0] <= bound
    assert _unverified_naming(result, bound), [f.evidence.summary for f in result.unverified]
    assert not [f for f in result.findings if f.rule_id == _RULE_ID]
    assert _unread(result) == [str(tmp_path / "model.pt")]


def test_a_payload_found_before_the_opcode_bound_is_still_critical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_opcode, "_ARCHIVE_OPCODE_FLOOR", 0)
    padding = b"\x80\x02" + b"N0" * 5000 + b"."
    archive = _zip({"archive/a.pkl": pickle.dumps(_Evil()), "archive/b.pkl": padding})
    (tmp_path / "model.pt").write_bytes(archive)

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert any(f.severity.name == "CRITICAL" and "system" in f.evidence.summary for f in findings)
    assert any(
        f.title == "Unscanned model file" and str(len(archive)) in f.evidence.summary
        for f in findings
    )


def test_members_past_the_archive_bound_are_not_opened_and_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bound = 4
    monkeypatch.setattr(pickle_opcode, "_ARCHIVE_MAX_MEMBERS", bound)
    members = {f"archive/data/{i}": b"\x00" * 16 for i in range(9)}
    members["archive/data.pkl"] = pickle.dumps(_Evil())
    (tmp_path / "model.pt").write_bytes(_zip(members))
    opened = [0]
    real_open = zipfile.ZipFile.open

    def counting_open(self: zipfile.ZipFile, *args: object, **kwargs: object) -> object:
        opened[0] += 1
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(zipfile.ZipFile, "open", counting_open)

    result = _run(tmp_path)

    assert opened[0] <= bound
    assert _unverified_naming(result, bound), [f.evidence.summary for f in result.unverified]
    assert _unread(result) == [str(tmp_path / "model.pt")]


class _Storage:
    def __init__(self, key: str, numel: int) -> None:
        self.key = key
        self.numel = numel


def _fake_torch(monkeypatch: pytest.MonkeyPatch) -> tuple[object, type]:
    """The two globals a state dict imports, under the names torch gives them."""
    torch = types.ModuleType("torch")
    utils = types.ModuleType("torch._utils")

    def _rebuild_tensor_v2(*args: object) -> None:
        """Never called: the rule reads a pickle's opcodes, never its objects."""

    _rebuild_tensor_v2.__module__ = "torch._utils"
    _rebuild_tensor_v2.__qualname__ = "_rebuild_tensor_v2"
    float_storage = type("FloatStorage", (), {"__module__": "torch"})
    utils._rebuild_tensor_v2 = _rebuild_tensor_v2  # type: ignore[attr-defined]
    torch.FloatStorage = float_storage  # type: ignore[attr-defined]
    torch._utils = utils  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "torch", torch)
    monkeypatch.setitem(sys.modules, "torch._utils", utils)
    return _rebuild_tensor_v2, float_storage


def _torch_checkpoint(monkeypatch: pytest.MonkeyPatch, tensors: int) -> bytes:
    """A state dict laid out as `torch.save` writes one: a pickle plus one member per storage."""
    rebuild, float_storage = _fake_torch(monkeypatch)
    rows = cols = 8

    class _Tensor:
        def __init__(self, key: str) -> None:
            self.storage = _Storage(key, rows * cols)

        def __reduce__(self) -> tuple[object, tuple[object, ...]]:
            args: tuple[object, ...] = (
                self.storage,
                0,
                (rows, cols),
                (cols, 1),
                False,
                collections.OrderedDict(),
            )
            return (rebuild, args)

    class _Pickler(pickle.Pickler):
        def persistent_id(self, obj: object) -> object:
            if isinstance(obj, _Storage):
                return ("storage", float_storage, obj.key, "cpu", obj.numel)
            return None

    state = collections.OrderedDict((f"layers.{i}.weight", _Tensor(str(i))) for i in range(tensors))
    buffer = io.BytesIO()
    _Pickler(buffer, protocol=2).dump(state)
    weights = struct.pack(f"<{rows * cols}f", *(0.01 * k - 0.3 for k in range(rows * cols)))
    members = {
        "archive/data.pkl": buffer.getvalue(),
        "archive/.format_version": b"1",
        "archive/.storage_alignment": b"64",
        "archive/byteorder": b"little",
    }
    members.update({f"archive/data/{i}": weights for i in range(tensors)})
    members["archive/version"] = b"3\n"
    members["archive/.data/serialization_id"] = b"0123456789012345678901234567890123456789"
    return _zip(members, zipfile.ZIP_STORED)


def test_a_torch_shaped_checkpoint_stays_clean_within_its_own_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The negative half: a stored checkpoint walks fewer opcodes than it has bytes.

    That holds with no floor at all, so the bound never cuts one, whatever its size.
    """
    monkeypatch.setattr(pickle_opcode, "_ARCHIVE_OPCODE_FLOOR", 0)
    tensors = 200
    checkpoint = _torch_checkpoint(monkeypatch, tensors)
    (tmp_path / "model.pt").write_bytes(checkpoint)
    walked = _count_opcodes(monkeypatch)
    ctx = RuleContext()

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))

    assert findings == []
    assert ctx.shortfalls() == ()
    assert tensors < walked[0] <= len(checkpoint)
    assert tensors + 7 < pickle_opcode._ARCHIVE_MAX_MEMBERS


def test_an_entry_shadowed_by_a_later_one_of_the_same_name_is_still_scanned(
    tmp_path: Path,
) -> None:
    """Every entry is read, including one that opening the archive by name would skip."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("model/data.pkl", pickle.dumps(_Evil(), protocol=2))
        benign = pickle.dumps({"weights": [1, 2]}, protocol=2)
        with pytest.warns(UserWarning, match="Duplicate"):
            archive.writestr("model/data.pkl", benign)
    (tmp_path / "model.pt").write_bytes(buffer.getvalue())

    result = _run(tmp_path)

    assert any(
        f.rule_id == _RULE_ID and "system" in f.title + f.evidence.summary for f in result.findings
    )
