import io
import os
import pickle
import zipfile
from pathlib import Path

import pytest
from guardana.core.rule import RuleContext
from guardana.core.target import ArtifactTarget
from guardana.rules.supply_chain import pickle_opcode
from guardana.rules.supply_chain.pickle_opcode import PickleOpcodeRule


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

    def boom(self: zipfile.ZipFile, name: str, *args: object, **kwargs: object) -> object:
        if str(name).endswith("data.pkl"):
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
