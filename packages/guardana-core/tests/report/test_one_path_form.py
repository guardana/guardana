"""A file path is spelled with `/` on every platform, and an older Windows waiver still waives.

A baseline of version 2 or older written on Windows fingerprinted `model\\weights.pkl`;
the finding this build reports is at `model/weights.pkl`. The waiver keeps waiving
that finding, and nothing else.
"""

import ntpath
import sys
from datetime import date
from pathlib import Path, PureWindowsPath
from typing import cast

import pytest
import yaml
from guardana.core import _path_spelling
from guardana.core._path_spelling import is_legacy_windows_ref, posix_ref
from guardana.core.report import location
from guardana.core.report.baseline import (
    BASELINE_VERSION,
    Baseline,
    Waiver,
    apply_baseline,
    read_baseline,
    windows_fingerprint,
)
from guardana.core.report.finding import Evidence, Finding, fingerprint_of
from guardana.core.report.location import relativize
from guardana.core.report.result import ScanResult
from guardana.core.severity import Severity
from guardana.core.target import TraceTarget
from guardana.core.trace import Provenance, Span, SpanKind, Trace

_RULE = "guardana.supply-chain.pickle-exec"
_SUMMARY = "pickle calls os.system"


def _finding(
    ref: str = "model/weights.pkl:3", rule: str = _RULE, summary: str = _SUMMARY
) -> Finding:
    return Finding(
        rule_id=rule,
        severity=Severity.HIGH,
        title="t",
        taxonomy=(),
        target_ref=ref,
        evidence=Evidence(summary=summary),
    )


_WINDOWS_FINGERPRINT = fingerprint_of(_RULE, "model\\weights.pkl", _SUMMARY)
"""What a version-2 build on Windows wrote for the finding at `model/weights.pkl:3`."""


def test_the_digest_a_windows_build_wrote_is_pinned() -> None:
    assert _WINDOWS_FINGERPRINT == "565063e10288361e"


def _baseline(
    tmp_path: Path,
    *,
    version: int = 2,
    location: str = "model\\weights.pkl:3",
    expires: str | None = None,
) -> Baseline:
    path = tmp_path / "guardana-baseline.yaml"
    waiver = {
        "fingerprint": _WINDOWS_FINGERPRINT,
        "rule": _RULE,
        "location": location,
        "reason": "accepted",
        "approved_by": "owner",
        "expires": expires,
    }
    path.write_text(yaml.safe_dump({"version": version, "waivers": [waiver]}), encoding="utf-8")
    return read_baseline(path)


def _waived(baseline: Baseline, finding: Finding, today: date | None = None) -> bool:
    result = ScanResult(findings=(finding,), rules_run=(finding.rule_id,), rules_skipped=())
    applied = apply_baseline(result, baseline.active(today), baseline.active_legacy(today))
    return applied.waived == (finding,)


# The written form


def test_a_finding_fingerprint_over_a_slashed_path_is_pinned() -> None:
    assert _finding().fingerprint == "55a06e32823b0f0c"


class _WindowsPath(PureWindowsPath):
    r"""A Windows path resolved against `C:\work`, so `relativize` runs as it does there."""

    def resolve(self) -> "_WindowsPath":
        return _WindowsPath(ntpath.normpath(ntpath.join("C:\\work", self)))


@pytest.fixture
def windows_base(monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(location, "Path", _WindowsPath)
    monkeypatch.setattr(location, "PurePath", PureWindowsPath)
    monkeypatch.setattr(_path_spelling, "PurePath", PureWindowsPath)
    return cast("Path", _WindowsPath("C:\\work"))


@pytest.mark.parametrize(
    ("ref", "written"),
    [
        ("C:\\work\\model\\weights.pkl:3", "model/weights.pkl:3"),
        ("C:\\work\\dir\\a.zip", "dir/a.zip"),
        ("model\\weights.pkl", "model/weights.pkl"),
        ("..\\models", "../models"),
        ("..\\models\\weights.pkl:3", "../models/weights.pkl:3"),
        (".\\..\\weights.pkl", "./../weights.pkl"),
        ("runs\\t.jsonl#abc", "runs/t.jsonl#abc"),
        ("c#\\model\\x.pkl", "c#/model/x.pkl"),
    ],
    ids=[
        "absolute-with-a-line",
        "absolute",
        "relative",
        "outside",
        "outside-with-a-line",
        "outside-through-dot",
        "trace",
        "directory-with-a-hash",
    ],
)
def test_a_relative_file_is_written_with_slashes_on_windows(
    windows_base: Path, ref: str, written: str
) -> None:
    assert relativize(ref, windows_base) == written


@pytest.mark.parametrize(
    "ref",
    [
        "C:\\other\\weights.pkl:3",
        "D:\\weights.pkl",
        "\\\\server\\share\\weights.pkl",
        "\\rooted\\weights.pkl",
        "http://host/v1#model",
        "..\\a.zip:inner/x.pkl",
    ],
    ids=["other-directory", "other-drive", "unc", "rooted", "endpoint", "already-mixed"],
)
def test_an_anchored_path_or_an_endpoint_keeps_its_form_on_windows(
    windows_base: Path, ref: str
) -> None:
    assert relativize(ref, windows_base) == ref


@pytest.mark.parametrize(
    "ref",
    [
        "model\\weights.pkl:3",
        "..\\models",
        "..\\models\\weights.pkl:3",
        "C:\\other\\weights.pkl:3",
        "\\\\server\\share\\weights.pkl",
        "\\rooted\\weights.pkl",
        "http://host/v1#model",
        "runs\\t.jsonl#abc",
        "..\\a.zip:inner/x.pkl",
        ".\\..\\weights.pkl",
    ],
)
def test_the_writer_and_the_run_migration_spell_a_windows_ref_alike(
    windows_base: Path, ref: str
) -> None:
    assert relativize(ref, windows_base) == posix_ref(ref)


@pytest.mark.parametrize(
    "ref",
    ["..\\weights.pkl:3", "../x/./weights.pkl", "..//weights.pkl", "../name\\with.pkl"],
    ids=["backslash-name", "dot-segment", "double-separator", "both"],
)
@pytest.mark.skipif(sys.platform == "win32", reason="there a backslash separates")
def test_a_path_outside_the_base_keeps_every_byte_off_windows(tmp_path: Path, ref: str) -> None:
    assert relativize(ref, tmp_path / "base") == ref


def test_with_no_base_a_relative_ref_is_only_spelled_with_slashes_on_windows(
    windows_base: Path,
) -> None:
    assert relativize("model\\weights.pkl:3", None) == "model/weights.pkl:3"
    assert relativize("C:\\work\\model\\weights.pkl:3", None) == "C:\\work\\model\\weights.pkl:3"


@pytest.mark.skipif(sys.platform == "win32", reason="there a backslash separates")
@pytest.mark.parametrize("ref", ["foo\\bar.pkl:3", "/abs/weights.pkl", "../x/./y.pkl"])
def test_with_no_base_every_ref_keeps_every_byte_off_windows(ref: str) -> None:
    assert relativize(ref, None) == ref


@pytest.mark.parametrize(
    ("ref", "legacy"),
    [
        ("model\\weights.pkl:3", True),
        ("..\\models", True),
        ("model/weights.pkl", False),
        ("C:\\m\\w.pkl", False),
        ("\\\\srv\\share\\w.pkl", False),
        ("\\rooted\\w.pkl", False),
        ("http://h\\x#m", False),
    ],
)
def test_only_a_relative_ref_with_a_backslash_reads_as_windows(ref: str, legacy: bool) -> None:
    assert is_legacy_windows_ref(ref) is legacy


def test_a_trace_read_from_a_relative_file_is_named_with_slashes_on_windows(
    windows_base: Path,
) -> None:
    trace = Trace(
        trace_id="abc",
        spans=(Span(span_id="s", kind=SpanKind.TOOL_EXECUTION, name="s"),),
        provenance=Provenance(producer="acme", source="runs\\t.jsonl", dialect="guardana"),
        instrumented=frozenset(),
    )

    assert TraceTarget(trace).ref == "runs/t.jsonl#abc"
    assert relativize(TraceTarget(trace).ref, windows_base) == "runs/t.jsonl#abc"


def test_the_baseline_version_is_three() -> None:
    assert BASELINE_VERSION == 3


# A waiver written on Windows


def test_a_v2_windows_waiver_waives_the_finding_at_the_slashed_path(tmp_path: Path) -> None:
    baseline = _baseline(tmp_path)

    assert baseline.waivers[0].legacy_path
    assert _waived(baseline, _finding())


def test_control_the_same_waiver_in_a_v3_file_does_not_waive(tmp_path: Path) -> None:
    assert not _waived(_baseline(tmp_path, version=3), _finding())


def test_a_v2_waiver_whose_location_has_a_slash_never_matches_the_windows_way(
    tmp_path: Path,
) -> None:
    baseline = _baseline(tmp_path, location="model/weights.pkl:3")

    assert not baseline.waivers[0].legacy_path
    assert not _waived(baseline, _finding())


@pytest.mark.parametrize(
    "finding",
    [_finding(rule="guardana.other"), _finding(summary="pickle imports subprocess")],
    ids=["another rule", "another summary"],
)
def test_a_windows_waiver_does_not_waive_a_different_finding(
    finding: Finding, tmp_path: Path
) -> None:
    assert not _waived(_baseline(tmp_path), finding)


def test_an_expired_windows_waiver_does_not_waive(tmp_path: Path) -> None:
    baseline = _baseline(tmp_path, expires="2026-01-31")

    assert baseline.active_legacy(date(2026, 2, 1)) == frozenset()
    assert not _waived(baseline, _finding(), today=date(2026, 2, 1))
    assert _waived(baseline, _finding(), today=date(2026, 1, 31))


@pytest.mark.parametrize(
    "ref", ["http://h/v1#model", "weights.pkl:3"], ids=["an endpoint", "no directory"]
)
def test_a_ref_whose_fingerprint_never_differed_has_no_windows_fingerprint(ref: str) -> None:
    assert windows_fingerprint(_finding(ref)) is None


def test_a_finding_carrying_the_waivers_own_fingerprint_keeps_the_slashed_path_unwaived(
    tmp_path: Path,
) -> None:
    named_with_a_backslash = _finding("model\\weights.pkl:3")
    other_file = _finding()
    baseline = _baseline(tmp_path)
    result = ScanResult(
        findings=(named_with_a_backslash, other_file),
        rules_run=(_RULE,),
        rules_skipped=(),
    )

    applied = apply_baseline(result, baseline.active(), baseline.active_legacy())

    assert named_with_a_backslash.fingerprint == baseline.waivers[0].fingerprint
    assert applied.waived == (named_with_a_backslash,)
    assert applied.findings == (other_file,)


def test_a_v2_waiver_for_a_trace_written_on_windows_waives_the_finding(tmp_path: Path) -> None:
    finding = _finding("runs/t.jsonl#abc")
    written = fingerprint_of(_RULE, "runs\\t.jsonl#abc", _SUMMARY)
    path = tmp_path / "guardana-baseline.yaml"
    waiver = {"fingerprint": written, "rule": _RULE, "location": "runs\\t.jsonl#abc"}
    path.write_text(yaml.safe_dump({"version": 2, "waivers": [waiver]}), encoding="utf-8")

    assert windows_fingerprint(finding) == written
    assert _waived(read_baseline(path), finding)


@pytest.mark.parametrize(("version", "waives"), [(2, True), (3, False)])
def test_a_waiver_with_no_location_matches_the_windows_way_only_in_an_older_file(
    tmp_path: Path, version: int, waives: bool
) -> None:
    path = tmp_path / "guardana-baseline.yaml"
    waiver = {"fingerprint": _WINDOWS_FINGERPRINT, "rule": _RULE}
    path.write_text(yaml.safe_dump({"version": version, "waivers": [waiver]}), encoding="utf-8")

    assert _waived(read_baseline(path), _finding()) is waives


def test_a_slashed_path_has_the_fingerprint_windows_wrote_for_it() -> None:
    assert windows_fingerprint(_finding()) == _WINDOWS_FINGERPRINT


def test_a_v2_waiver_without_an_approver_is_still_unreviewed() -> None:
    waiver = Waiver(fingerprint="0123456789abcdef", reason="accepted", approved_by="")

    assert Baseline(waivers=(waiver,), version=2).unreviewed == (waiver,)
    assert Baseline(waivers=(waiver,), version=1).unreviewed == ()
