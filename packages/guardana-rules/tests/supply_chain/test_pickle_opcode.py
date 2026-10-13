import collections
import hashlib
import io
import os
import pickle
import re
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.profile import FailOn, Policy, Profile
from guardana.core.redaction import EvidenceRedactor
from guardana.core.registry import Registry
from guardana.core.report import ShortfallKind
from guardana.core.rule import RuleContext
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import pickle_opcode
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule, _scan_opcodes


def _zip_with(member_name: str, payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("archive/version", b"3")
        zf.writestr(member_name, payload)
    return buffer.getvalue()


def test_scans_pickle_inside_a_zip_based_pt(tmp_path: Path) -> None:
    # Modern torch.save() writes a ZIP. The malicious pickle lives in a member;
    # the rule must unzip and scan it, not degrade to a LOW "unscanned".
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/data.pkl", pickle.dumps(_Evil())))
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any(f.severity.name == "CRITICAL" and "system" in f.evidence.summary for f in findings)


def test_scans_zip_member_regardless_of_extension(tmp_path: Path) -> None:
    # CVE-2025-1889: hiding the payload under a non-.pkl member name evaded
    # scanners that filtered by extension. Every member is scanned.
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/weights.bin", pickle.dumps(_Evil())))
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any(f.severity.name == "CRITICAL" for f in findings)


def test_benign_zip_pt_is_clean(tmp_path: Path) -> None:
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/data.pkl", pickle.dumps({"w": [1, 2]})))
    assert list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext())) == []


def test_nested_archive_member_is_flagged_not_silently_skipped(tmp_path: Path) -> None:
    # A member whose content is itself an archive is a container the scanner cannot
    # see into — it could hide a malicious pickle. It must surface as an unscanned
    # finding (loud), never be silently ignored.
    inner = _zip_with("archive/data.pkl", pickle.dumps(_Evil()))
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/nested.zip", inner))
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any(f.title == "Unscanned model file" for f in findings)


def _pickle_padded_past(limit: int) -> bytes:
    """A protocol-2 pickle whose payload sits behind `limit` bytes of declared string."""
    pad = limit + 1024
    return (
        b"\x80\x02"
        + b"X"
        + pad.to_bytes(4, "little")  # BINUNICODE, `pad` bytes of content
        + b"a" * pad
        + b"cposix\nsystem\n"  # GLOBAL posix.system — behind the cap
        + b"."
    )


def test_a_zip_member_the_cap_cut_is_flagged_not_silently_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Padding a member past the per-member read cap must not erase it from the scan.

    Deflate makes this cheap for an attacker: sixty-five megabytes of padding
    compress to a file of a few kilobytes, so no size heuristic sees it coming. The
    payload behind the padding is never read, and reading half a pickle proves
    nothing about the other half — so the member is unscanned, and an unscanned
    member is a visible finding.
    """
    monkeypatch.setattr(pickle_opcode, "_MEMBER_MAX_BYTES", 4096)
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/data.pkl", _pickle_padded_past(4096)))

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert findings, "a pickle padded past the member cap scanned clean"
    assert any(f.title == "Unscanned model file" for f in findings)


def test_an_oversized_member_that_is_not_a_pickle_stays_quiet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half: a real checkpoint's tensor storages must not become noise.

    Every member is read, whatever its name, and a 7B checkpoint's storages are
    routinely larger than the cap. Flagging each of them would put a LOW finding
    per tensor on every honest model — so the report is reserved for a member that
    was still parsing as a pickle when the cap cut it.
    """
    monkeypatch.setattr(pickle_opcode, "_MEMBER_MAX_BYTES", 4096)
    tensor_bytes = bytes(range(1, 256)) * 64  # no valid opcode stream, over the cap
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/data/0", tensor_bytes))

    assert list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext())) == []


@pytest.mark.parametrize(
    "stream",
    [
        b"\x80\x04\x93.",  # STACK_GLOBAL with an empty stack
        b"\x80\x04h\x05h\x06\x93.",  # STACK_GLOBAL over two memo misses (None operands)
    ],
    ids=["empty-stack", "memo-miss"],
)
def test_an_unresolvable_stack_global_inside_a_zip_fails_closed_too(
    tmp_path: Path, stream: bytes
) -> None:
    """The same crafted stream must not become quiet by being put in an archive.

    A raw `.pkl` whose `STACK_GLOBAL` operands this scanner cannot model reports LOW
    "unscanned", because an unpickler may well resolve what the model here could not.
    Inside a ZIP member it reported nothing at all — and a ZIP is what
    `torch.save` writes, so the silent half was the half a real checkpoint takes.
    """
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/data.pkl", stream))

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.title for f in findings] == ["Unscanned model file"]
    assert findings[0].severity.name == "LOW"


def test_unreadable_zip_member_is_flagged_and_scan_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # zipfile raises RuntimeError for an encrypted member. One such member must not
    # abort the whole scan (an attacker-triggerable DoS) nor pass as clean.
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/data.pkl", pickle.dumps({"w": 1})))
    real_open = zipfile.ZipFile.open

    def boom(
        self: zipfile.ZipFile, name: str | zipfile.ZipInfo, *args: object, **kwargs: object
    ) -> object:
        member = name.filename if isinstance(name, zipfile.ZipInfo) else name
        if member.endswith("data.pkl"):
            raise RuntimeError("File is encrypted, password required for extraction")
        return real_open(self, name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(zipfile.ZipFile, "open", boom)
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any(f.title == "Unscanned model file" and f.severity.name == "LOW" for f in findings)


def test_dangerous_global_before_a_broken_tail_is_still_critical(tmp_path: Path) -> None:
    # Pickle executes opcodes as encountered, so a payload before a deliberately
    # broken tail runs. It must surface as CRITICAL, not hide behind LOW.
    payload = pickle.dumps(_Evil())[:-1] + b"\xff\xff\xff"  # valid prefix, garbage tail
    (tmp_path / "model.pkl").write_bytes(payload)
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert any(f.severity.name == "CRITICAL" and "system" in f.evidence.summary for f in findings)


def test_7z_compressed_model_is_flagged_as_unscannable(tmp_path: Path) -> None:
    # nullifAI evaded both torch.load and picklescan with a 7z-compressed file.
    # Guardana can't decompress 7z, so it fails loud: a lead, never silent-clean.
    (tmp_path / "model.pt").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 1
    assert (
        "7z" in findings[0].evidence.summary or "compress" in findings[0].evidence.summary.lower()
    )


class _Evil:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (os.system, ("echo pwned",))


_SYSTEM = f"{os.system.__module__}.system"


def test_flags_os_system_reduce(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(pickle.dumps(_Evil()))
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings, "expected a finding for os.system in __reduce__"
    assert "os" in findings[0].evidence.summary
    assert findings[0].severity.name == "CRITICAL"


def test_ignores_benign_allowlisted_pickle(tmp_path: Path) -> None:
    (tmp_path / "ok.pkl").write_bytes(pickle.dumps({"a": [1, 2, 3]}))
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_does_not_crash_on_non_pickle_file(tmp_path: Path) -> None:
    # A zip-based torch.save() container (or any corrupted file) is not a
    # valid pickle opcode stream; pickletools.genops raises plain ValueError
    # on it, which must not abort the scan.
    (tmp_path / "model.pt").write_bytes(b"PK\x03\x04 not a real pickle stream")
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert isinstance(findings, list)
    if findings:
        assert len(findings) == 1
        assert findings[0].severity.name == "LOW"


class _EvalGadget:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (eval, ("1+1",))


def test_flags_builtins_eval_gadget(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(pickle.dumps(_EvalGadget()))
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings, "expected a finding for builtins.eval in __reduce__"
    assert any("eval" in f.evidence.summary for f in findings)


def _short_binunicode(text: str) -> bytes:
    body = text.encode("utf-8")
    return b"\x8c" + bytes([len(body)]) + body


def _memo_indirection_stream() -> bytes:
    # The dangerous operands `posix`/`system` are memoized, then two *allowlisted*
    # strings are pushed so a "last two string loads" heuristic sees `torch.nn`.
    # The real operands are restored from the memo with BINGET right before
    # STACK_GLOBAL, so an unpickler resolves posix.system while the heuristic
    # reports a clean allowlisted ref — the false negative under test.
    return (
        b"\x80\x04"  # PROTO 4
        + _short_binunicode("posix")
        + b"\x94"  # MEMOIZE -> memo[0]
        + _short_binunicode("system")
        + b"\x94"  # MEMOIZE -> memo[1]
        + _short_binunicode("torch")  # benign, allowlisted module
        + _short_binunicode("nn")  # benign qualname
        + b"h\x00"  # BINGET 0 -> pushes 'posix'
        + b"h\x01"  # BINGET 1 -> pushes 'system'
        + b"\x93"  # STACK_GLOBAL
        + b"."  # STOP
    )


def test_memo_indirection_is_not_silently_clean(tmp_path: Path) -> None:
    (tmp_path / "evasion.pkl").write_bytes(_memo_indirection_stream())
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings, "memo-indirected posix.system must not scan clean"
    severities = {f.severity.name for f in findings}
    assert severities <= {"CRITICAL", "LOW"}
    if "CRITICAL" in severities:
        assert any("system" in f.evidence.summary for f in findings)


@pytest.mark.parametrize(
    "stream",
    [
        b"\x80\x04\x93.",  # STACK_GLOBAL with an empty stack
        b"\x80\x04h\x05h\x06\x93.",  # STACK_GLOBAL over two memo misses (None operands)
    ],
    ids=["empty-stack", "memo-miss"],
)
def test_unresolvable_stack_global_fails_closed_to_low(tmp_path: Path, stream: bytes) -> None:
    # A STACK_GLOBAL whose operands can't be resolved to two strings is not
    # provably clean; it must surface as the visible LOW "unscanned" finding,
    # never as an absent (silently clean) result.
    (tmp_path / "crafted.pkl").write_bytes(stream)
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert len(findings) == 1
    assert findings[0].severity.name == "LOW"
    assert findings[0].title == "Unscanned model file"


def test_flags_global_opcode(tmp_path: Path) -> None:
    # Protocol 0/1 use the arg-based GLOBAL opcode instead of STACK_GLOBAL.
    (tmp_path / "old.pkl").write_bytes(pickle.dumps(_Evil(), protocol=0))
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings, "expected a finding for the GLOBAL-opcode os.system"
    assert any("system" in f.evidence.summary for f in findings)


def test_allowlisted_global_opcode_is_clean(tmp_path: Path) -> None:
    # A GLOBAL resolving to an allowlisted module (`collections`) is not flagged.
    (tmp_path / "ok.pkl").write_bytes(b"ccollections\nOrderedDict\n.")
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings == []


def test_binput_binget_memo_indirection_is_flagged(tmp_path: Path) -> None:
    # The same evasion via the indexed BINPUT/BINGET memo ops (not just MEMOIZE):
    # memoize the dangerous operands, push benign decoys, then restore from memo.
    stream = (
        _short_binunicode("posix")
        + b"q\x00"  # BINPUT 0
        + _short_binunicode("system")
        + b"q\x01"  # BINPUT 1
        + _short_binunicode("torch")
        + _short_binunicode("nn")
        + b"h\x00"  # BINGET 0 -> 'posix'
        + b"h\x01"  # BINGET 1 -> 'system'
        + b"\x93."  # STACK_GLOBAL, STOP
    )
    (tmp_path / "p2.pkl").write_bytes(stream)
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert findings, "BINPUT/BINGET memo indirection must not scan clean"
    assert {f.severity.name for f in findings} <= {"CRITICAL", "LOW"}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is POSIX-only")
def test_a_fifo_named_like_a_checkpoint_cannot_stall_the_scan(tmp_path: Path) -> None:
    # A plain read of a FIFO blocks until a writer appears, so a crafted repo
    # could hang `guardana scan` indefinitely by naming one `model.pkl`. It must
    # be skipped — and skipped visibly, because nothing was examined.
    os.mkfifo(tmp_path / "model.pkl")
    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))
    assert [f.severity.name for f in findings] == ["LOW"]
    assert "not scanned" in findings[0].evidence.summary


def test_an_unreadable_member_is_unverified_and_not_a_finding(tmp_path: Path) -> None:
    """ "I could not read this" is the absence of an answer, not a problem of a size.

    Graded as a LOW finding it was governed by `fail_on.severity`, so a profile
    failing on `medium` promoted a model store holding members nobody had parsed
    while the run reported `unverified: 0`.
    """
    inner = _zip_with("archive/data.pkl", pickle.dumps(_Evil()))
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/nested.zip", inner))

    result = Runner(
        registry=Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        profile=Profile(name="t", policy=Policy()),
    ).run(ArtifactTarget(tmp_path))

    unscanned = [f for f in result.unverified if f.title == "Unscanned model file"]
    assert unscanned, [f.title for f in result.findings]
    assert not [f for f in result.findings if f.title == "Unscanned model file"]
    assert all(f.verdict is not None and f.verdict.outcome == "inconclusive" for f in unscanned)


def test_a_medium_gate_asking_for_inconclusive_refuses_an_unread_artifact(tmp_path: Path) -> None:
    """The reporter's case: `fail_on.severity: medium` plus `fail_on_inconclusive`.

    Severity is not consulted for an unverified result, because "how bad is the
    thing I could not measure" has no answer. Before this, every unread member was
    LOW and the medium threshold waved the whole store through.
    """
    inner = _zip_with("archive/data.pkl", pickle.dumps(_Evil()))
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/nested.zip", inner))
    policy = Policy(fail_on=FailOn(severity=Severity.MEDIUM, fail_on_inconclusive=True))

    result = Runner(
        registry=Registry.discover(PluginTrust(mode=PluginMode.BUILTINS)),
        profile=Profile(name="t", policy=policy),
    ).run(ArtifactTarget(tmp_path))

    assert gate_outcome(result, policy) is not GateOutcome.PASS


def _s(text: str) -> bytes:
    return _short_binunicode(text)


_REDUCE_ID = _s("id") + b"\x85R."  # SHORT_BINUNICODE 'id', TUPLE1, REDUCE, STOP
_OS_SYSTEM = b"\x80\x04" + _s("os") + _s("system")


@pytest.mark.parametrize(
    "stream",
    [
        _OS_SYSTEM + _s("builtins") + _s("str") + b"00\x93" + _REDUCE_ID,
        _OS_SYSTEM + b"(" + _s("builtins") + _s("str") + b"1\x93" + _REDUCE_ID,
        _OS_SYSTEM + b"(" + _s("builtins") + _s("str") + b"t0\x93" + _REDUCE_ID,
        _OS_SYSTEM + _s("torch") + _s("nn") + b"\x860\x93" + _REDUCE_ID,
        _OS_SYSTEM + _s("torch") + b"200\x93" + _REDUCE_ID,
        b"\x80\x04}\x94"
        + _s("os")
        + b"\x94"
        + _s("torch")
        + b"\x94"
        + _s("system")
        + b"\x94"
        + _s("x")
        + b"\x94h\x01h\x03\x93"
        + _REDUCE_ID,
    ],
    ids=["pop", "pop-mark", "tuple", "tuple2", "dup", "memoize-a-dict"],
)
def test_stack_global_takes_the_operands_an_unpickler_would(tmp_path: Path, stream: bytes) -> None:
    """Every opcode that pops or pushes moves the operands STACK_GLOBAL reads.

    A model that tracked only string loads resolved stale, allowlisted decoys here
    while an unpickler resolves `os.system`, so the stream scanned clean.
    """
    (tmp_path / "model.pkl").write_bytes(stream)

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.severity.name for f in findings] == ["CRITICAL"]
    assert findings[0].evidence.summary.endswith(": os.system")


def test_a_popped_decoy_inside_a_checkpoint_zip_is_critical_too(tmp_path: Path) -> None:
    stream = _OS_SYSTEM + _s("builtins") + _s("str") + b"00\x93" + _REDUCE_ID
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/data.pkl", stream))

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.severity.name for f in findings] == ["CRITICAL"]
    assert findings[0].evidence.summary.endswith(": os.system")


def test_inst_imports_its_class_like_global(tmp_path: Path) -> None:
    """Protocol 0's INST names a callable and calls it with the marked arguments."""
    (tmp_path / "model.pkl").write_bytes(b"(S'id'\nios\nsystem\n.")

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.severity.name for f in findings] == ["CRITICAL"]
    assert findings[0].evidence.summary.endswith(": os.system")


def test_an_allowlisted_inst_is_clean(tmp_path: Path) -> None:
    (tmp_path / "ok.pkl").write_bytes(b"(icollections\nOrderedDict\n.")

    assert list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext())) == []


def test_an_append_to_a_list_under_a_mark_is_followed_as_the_c_unpickler_does(
    tmp_path: Path,
) -> None:
    """The C unpickler's APPEND reaches under the MARK, so the MARK stays and fences
    nothing the model could mistake for a refusal."""
    stream = b"\x80\x02](Na" + _s("os") + _s("system") + b"\x93" + _REDUCE_ID
    (tmp_path / "model.pkl").write_bytes(stream)

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.severity.name for f in findings] == ["CRITICAL"]
    assert findings[0].evidence.summary.endswith(": os.system")


@pytest.mark.parametrize(
    "stream",
    [
        b"\x80\x02]N(a" + _s("os") + _s("system") + b"\x93" + _REDUCE_ID,
        b"\x80\x02\x82\x01.",
    ],
    ids=["mark-left-above-the-stack", "extension-code"],
)
def test_a_stream_the_model_cannot_follow_to_its_end_is_unscanned(
    tmp_path: Path, stream: bytes
) -> None:
    (tmp_path / "model.pkl").write_bytes(stream)

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.title for f in findings] == ["Unscanned model file"]


def test_a_mark_left_above_the_stack_inside_a_zip_is_unscanned(tmp_path: Path) -> None:
    stream = b"\x80\x02]N(a" + _s("os") + _s("system") + b"\x93" + _REDUCE_ID
    (tmp_path / "model.pt").write_bytes(_zip_with("archive/data.pkl", stream))

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.title for f in findings] == ["Unscanned model file"]


def test_real_pickles_of_every_protocol_stay_clean(tmp_path: Path) -> None:
    """The negative half: modelling every opcode adds no noise to an honest pickle."""
    shared = ["same"]
    value = {
        "weights": [1.5, 2, None, True, (1,), (1, 2), (1, 2, 3), ()],
        "names": collections.OrderedDict(a=frozenset({1}), b={2, 3}),
        "shared": [shared, shared, 2**70, "x" * 300],
    }
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        (tmp_path / f"p{protocol}.pkl").write_bytes(pickle.dumps(value, protocol=protocol))

    assert list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext())) == []


_GADGETS_UNDER_ALLOWED_ROOTS = [
    ("numpy.testing._private.utils", "runstring"),
    ("torch.hub", "load"),
    ("torch.serialization", "load"),
    ("collections", "namedtuple"),
    ("numpy", "load"),
]


@pytest.mark.parametrize(
    ("module", "name"),
    _GADGETS_UNDER_ALLOWED_ROOTS,
    ids=[f"{m}.{n}" for m, n in _GADGETS_UNDER_ALLOWED_ROOTS],
)
def test_a_callable_under_an_allowed_top_level_package_is_still_dangerous(
    module: str, name: str
) -> None:
    """The allowlist names exact callables; `numpy` or `torch` alone names nothing safe."""
    by_global = f"c{module}\n{name}\n(S'x'\ntR.".encode()
    by_stack = (
        b"\x80\x04"
        + b"\x8c"
        + bytes([len(module)])
        + module.encode()
        + b"\x8c"
        + bytes([len(name)])
        + name.encode()
        + b"\x93\x8c\x01x\x85R."
    )

    for stream in (by_global, by_stack):
        assert _scan_opcodes(stream).refs == [f"{module}.{name}"]


def test_the_callables_a_tensor_or_array_is_rebuilt_from_stay_allowed() -> None:
    honest = [
        ("torch._utils", "_rebuild_tensor_v2"),
        ("torch", "FloatStorage"),
        ("collections", "OrderedDict"),
        ("numpy.core.multiarray", "_reconstruct"),
        ("numpy._core.multiarray", "scalar"),
        ("numpy", "dtype"),
        ("numpy.dtypes", "Float64DType"),
    ]
    for module, name in honest:
        stream = f"c{module}\n{name}\n.".encode()
        assert _scan_opcodes(stream).refs == [], f"{module}.{name}"


def _checkpoint(tmp_path: Path, members: dict[str, bytes]) -> Path:
    path = tmp_path / "optimizer.pt"
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return path


# bfloat16 values whose first byte happens to be the NEXT_BUFFER opcode.
_RAW_STORAGE = bytes.fromhex("97938b9ba5a28ea1859685a8bc90afae") * 64


def test_a_raw_tensor_storage_beside_its_data_pkl_is_not_read_as_a_pickle(
    tmp_path: Path,
) -> None:
    _checkpoint(
        tmp_path,
        {
            "optimizer/data.pkl": pickle.dumps({"state": {}}, protocol=2),
            "optimizer/data/71": _RAW_STORAGE,
        },
    )

    assert list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext())) == []


def test_a_malicious_data_pkl_beside_raw_storages_is_still_critical(tmp_path: Path) -> None:
    _checkpoint(
        tmp_path,
        {
            "optimizer/data.pkl": pickle.dumps(_Evil()),
            "optimizer/data/0": _RAW_STORAGE,
            "optimizer/data/1": _RAW_STORAGE,
        },
    )

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [(f.severity, f.evidence.detail) for f in findings] == [
        (Severity.CRITICAL, f"{_SYSTEM} in optimizer.pt::optimizer/data.pkl")
    ]


def test_a_pickle_stored_as_a_tensor_storage_beside_a_benign_data_pkl_is_critical(
    tmp_path: Path,
) -> None:
    _checkpoint(
        tmp_path,
        {
            "archive/data.pkl": pickle.dumps({"w": 1}, protocol=2),
            "archive/data/0": _RAW_STORAGE,
            "archive/data/1": pickle.dumps(_Evil(), protocol=4),
        },
    )

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [(f.severity, f.evidence.detail) for f in findings] == [
        (Severity.CRITICAL, f"{_SYSTEM} in optimizer.pt::archive/data/1")
    ]


def test_a_pickle_hiding_its_import_in_a_tensor_storage_is_not_cleared(tmp_path: Path) -> None:
    _checkpoint(
        tmp_path,
        {
            "archive/data.pkl": pickle.dumps({"w": 1}, protocol=2),
            "archive/data/0": b"\x80\x04h\x05h\x06\x93.",
        },
    )

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.title for f in findings] == ["Unscanned model file"]
    assert "archive/data/0" in findings[0].evidence.summary


def test_a_nested_archive_stored_as_a_tensor_storage_is_reported(tmp_path: Path) -> None:
    _checkpoint(
        tmp_path,
        {
            "archive/data.pkl": pickle.dumps({"w": 1}, protocol=2),
            "archive/data/0": _zip_with("archive/data.pkl", pickle.dumps(_Evil())),
        },
    )

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.evidence.summary for f in findings] == [
        "zip member is a nested archive (archive/data/0); not scanned"
    ]


def test_a_storage_shaped_member_with_no_data_pkl_beside_it_is_still_scanned(
    tmp_path: Path,
) -> None:
    """Only `torch.load`'s own layout is exempt; elsewhere a name proves nothing."""
    _checkpoint(
        tmp_path,
        {"other/data.pkl": pickle.dumps({}), "optimizer/data/0": pickle.dumps(_Evil())},
    )

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.severity for f in findings] == [Severity.CRITICAL]


def test_bytes_rebuilt_by_protocol_2_are_not_a_dangerous_import(tmp_path: Path) -> None:
    (tmp_path / "rng_state.pth").write_bytes(pickle.dumps({"rng": b"\x00\xff" * 8}, protocol=2))

    assert list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext())) == []


def test_a_dangerous_global_beside_rebuilt_bytes_still_fires(tmp_path: Path) -> None:
    (tmp_path / "rng_state.pth").write_bytes(
        pickle.dumps({"rng": b"\x00\xff", "hook": _Evil()}, protocol=2)
    )

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [f.evidence.summary for f in findings] == [_summary(_SYSTEM)]


def _summary(*callables: str) -> str:
    """The summary of a file importing exactly `callables`."""
    named = sorted(callables)
    digest = hashlib.sha256("\n".join(named).encode()).hexdigest()[:12]
    return (
        f"unpickling imports {len(named)} non-allowlisted callable(s) (set {digest}): "
        f"{', '.join(named)}"
    )


def _global(module: str, name: str) -> bytes:
    """A protocol-0 pickle that imports `module.name` and calls it."""
    return f"c{module}\n{name}\n(S'x'\ntR.".encode()


def _unread(ctx: RuleContext) -> list[str]:
    return [
        gap.name
        for gap in ctx.shortfalls()
        if gap.kind is ShortfallKind.UNEXAMINED_COMPONENT
        and gap.detail.startswith("guardana.supply_chain.pickle_opcode could not read it: ")
    ]


def test_a_file_importing_several_callables_is_one_finding_naming_each_once(
    tmp_path: Path,
) -> None:
    _checkpoint(
        tmp_path,
        {
            "archive/data.pkl": _global("subprocess", "Popen") + _global("builtins", "eval"),
            "archive/extra.pkl": _global("builtins", "eval"),
        },
    )

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].evidence.summary == _summary("builtins.eval", "subprocess.Popen")
    assert findings[0].evidence.detail == (
        "builtins.eval in optimizer.pt::archive/data.pkl; "
        "builtins.eval in optimizer.pt::archive/extra.pkl; "
        "subprocess.Popen in optimizer.pt::archive/data.pkl"
    )


def test_a_raw_pickle_names_its_callables_without_a_member(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(_global("os", "system") + _global("builtins", "exec"))

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext()))

    assert [(f.evidence.summary, f.evidence.detail) for f in findings] == [
        (
            _summary("builtins.exec", "os.system"),
            "builtins.exec in model.pkl; os.system in model.pkl",
        )
    ]


def test_swapping_one_callable_for_another_moves_the_fingerprint(tmp_path: Path) -> None:
    """A waiver granted for one import must not cover a file that now imports another."""
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "model.pkl").write_bytes(_global("os", "system") + _global("builtins", "eval"))
    (second / "model.pkl").write_bytes(_global("os", "system") + _global("builtins", "exec"))

    (before,) = PickleOpcodeRule().run(ArtifactTarget(first), RuleContext())
    (after,) = PickleOpcodeRule().run(ArtifactTarget(second), RuleContext())
    (again,) = PickleOpcodeRule().run(ArtifactTarget(first), RuleContext())

    assert before.fingerprint == again.fingerprint
    same_file = replace(after, target_ref=before.target_ref)
    assert same_file.fingerprint != before.fingerprint


def test_callables_found_before_a_later_member_raises_are_still_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _checkpoint(
        tmp_path,
        {"archive/data.pkl": pickle.dumps(_Evil()), "archive/later.pkl": pickle.dumps({})},
    )
    real_open = zipfile.ZipFile.open

    def failing(
        self: zipfile.ZipFile, name: str | zipfile.ZipInfo, *args: object, **kwargs: object
    ) -> object:
        member = name.filename if isinstance(name, zipfile.ZipInfo) else name
        if member == "archive/later.pkl":
            raise LookupError("a decoder this rule does not expect")
        return real_open(self, name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(zipfile.ZipFile, "open", failing)
    registry = Registry()
    registry.register_rule(PickleOpcodeRule())

    result = Runner(registry=registry, profile=Profile(name="t", policy=Policy())).run(
        ArtifactTarget(tmp_path)
    )

    assert [f.evidence.summary for f in result.findings] == [_summary(_SYSTEM)]
    assert [e.source for e in result.errors] == ["guardana.supply_chain.pickle_opcode"]


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("model.pt", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32),
        ("model.pt", b"PK\x03\x04 not a real zip"),
        ("model.pt", _zip_with("archive/nested.zip", _zip_with("archive/data.pkl", b"."))),
        ("model.pt", _zip_with("archive/data.pkl", b"\x80\x04h\x05h\x06\x93.")),
        ("model.pkl", b"\x80\x02\x82\x01."),
    ],
    ids=["7z", "malformed-zip", "nested-archive", "unresolvable-member", "extension-code"],
)
def test_a_file_left_unread_is_a_named_shortfall_beside_its_finding(
    tmp_path: Path, name: str, payload: bytes
) -> None:
    path = tmp_path / name
    path.write_bytes(payload)
    ctx = RuleContext()

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))

    assert [f.title for f in findings] == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]
    assert str(path) in ctx.examined_paths()


_HIDDEN_OS = (
    b"\x80\x04"
    + _s("builtins")
    + _s("str")
    + b"\x93"
    + _s("os")
    + b"\x85R"
    + _s("system")
    + b"\x93"
)
"""Builds "os" through an allowlisted call, so the import after it has no operand to read."""


@pytest.mark.parametrize(
    "stream",
    [
        b"\x80\x04h\x05h\x06\x93.",
        _HIDDEN_OS + _s("id") + b"\x85R0" + _global("subprocess", "Popen"),
    ],
    ids=["memo-miss", "import-built-by-a-call"],
)
def test_a_raw_pickle_whose_import_cannot_be_resolved_is_a_named_shortfall(
    tmp_path: Path, stream: bytes
) -> None:
    """The opcodes after the import it hides were never read, so the file is unexamined."""
    path = tmp_path / "model.pkl"
    path.write_bytes(stream)
    ctx = RuleContext()

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))

    assert [f.title for f in findings] == ["Unscanned model file"]
    assert "cannot resolve" in findings[0].evidence.summary
    assert "zip" not in findings[0].evidence.summary
    assert _unread(ctx) == [str(path)]


def test_an_unresolved_remainder_is_reported_beside_the_callables_found_before_it(
    tmp_path: Path,
) -> None:
    """A waiver for the first import must not cover what the unread remainder hides."""
    raw = tmp_path / "model.pkl"
    raw.write_bytes(_global("subprocess", "Popen")[:-1] + b"0" + _HIDDEN_OS + _REDUCE_ID)
    _checkpoint(tmp_path, {"archive/data.pkl": raw.read_bytes()})
    ctx = RuleContext()

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))

    assert sorted((f.target_ref, f.title) for f in findings) == sorted(
        (str(path), title)
        for path in (raw, tmp_path / "optimizer.pt")
        for title in ("Dangerous pickle opcode (arbitrary code on load)", "Unscanned model file")
    )
    assert sorted(_unread(ctx)) == sorted([str(raw), str(tmp_path / "optimizer.pt")])


def test_an_oversized_raw_pickle_is_reported_beside_the_callables_found_before_the_cut(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_opcode, "_MAX_PICKLE_BYTES", 4096)
    path = tmp_path / "model.pkl"
    path.write_bytes(_global("subprocess", "Popen")[:-1] + b"0" + _pickle_padded_past(4096)[2:])
    ctx = RuleContext()

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))

    assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.LOW]
    assert _unread(ctx) == [str(path)]


def _callables(count: int, last: str) -> bytes:
    names = [f"package_number_{i:04d}.callable_function_{i:04d}" for i in range(count - 1)]
    return b"".join(_global(*name.split("."))[:-1] + b"0" for name in names) + _global(
        *last.split(".")
    )


def test_the_callable_set_survives_the_evidence_bound_in_the_fingerprint(tmp_path: Path) -> None:
    """Swapping the last of many callables moves the fingerprint even past the bound."""
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "model.pkl").write_bytes(_callables(700, "zzz_pkg.benign"))
    (second / "model.pkl").write_bytes(_callables(700, "zzz_os.system"))
    redactor = EvidenceRedactor()

    (before,) = PickleOpcodeRule().run(ArtifactTarget(first), RuleContext())
    (after,) = PickleOpcodeRule().run(ArtifactTarget(second), RuleContext())
    before, after = redactor.redact(before), redactor.redact(after)

    assert "zzz_" not in before.evidence.summary, "the fixture must be cut by the bound"
    assert re.match(
        r"unpickling imports 700 non-allowlisted callable\(s\) \(set [0-9a-f]{12}\): ",
        before.evidence.summary,
    )
    assert replace(after, target_ref=before.target_ref).fingerprint != before.fingerprint


def test_the_callable_set_digest_is_stable_and_names_the_set(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(_global("os", "system") + _global("builtins", "exec"))

    (finding,) = PickleOpcodeRule().run(ArtifactTarget(tmp_path), RuleContext())

    digest = hashlib.sha256(b"builtins.exec\nos.system").hexdigest()[:12]
    assert finding.evidence.summary == (
        f"unpickling imports 2 non-allowlisted callable(s) (set {digest}): builtins.exec, os.system"
    )


def test_an_unreadable_bin_is_a_named_shortfall(tmp_path: Path) -> None:
    """A `.bin` that cannot be opened may be a model, so it is not left out as one that is not."""
    path = tmp_path / "pytorch_model.bin"
    path.write_bytes(_zip_with("archive/data.pkl", pickle.dumps(_Evil())))
    path.chmod(0)
    ctx = RuleContext()
    try:
        findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))
    finally:
        path.chmod(0o600)

    assert [f.title for f in findings] == ["Unscanned model file"]
    assert _unread(ctx) == [str(path)]


def test_a_clean_or_malicious_pickle_reports_no_shortfall(tmp_path: Path) -> None:
    (tmp_path / "ok.pkl").write_bytes(pickle.dumps({"w": 1}))
    (tmp_path / "bad.pkl").write_bytes(pickle.dumps(_Evil()))
    ctx = RuleContext()

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))

    assert [f.severity for f in findings] == [Severity.CRITICAL]
    assert ctx.shortfalls() == ()


@pytest.mark.parametrize("probe", [64 * 1024, 1024])
def test_a_headerless_bin_still_a_pickle_at_the_cut_is_reported_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, probe: int
) -> None:
    """A `.bin` read up to the bound while still parsing as a pickle is not left out."""
    monkeypatch.setattr(pickle_opcode, "_MAX_PICKLE_BYTES", 4096)
    monkeypatch.setattr(pickle_opcode, "_BIN_PROBE_BYTES", probe)
    path = tmp_path / "pytorch_model.bin"
    path.write_bytes(_pickle_padded_past(4096)[2:] + b"cos\nsystem\n(S'id'\ntR.")
    ctx = RuleContext()

    findings = list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx))

    assert [(f.title, f.evidence.summary) for f in findings] == [
        ("Unscanned model file", "raw pickle larger than 4096 bytes; not scanned in full")
    ]
    assert _unread(ctx) == [str(path)]
    assert ctx.examined_paths() == frozenset({str(path)})


def test_a_bin_of_bytes_that_are_no_pickle_past_the_bound_is_left_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_opcode, "_MAX_PICKLE_BYTES", 4096)
    (tmp_path / "vocab.bin").write_bytes(b"\xff" * 8192)
    ctx = RuleContext()

    assert list(PickleOpcodeRule().run(ArtifactTarget(tmp_path), ctx)) == []
    assert ctx.shortfalls() == ()
    assert ctx.examined_paths() == frozenset()
