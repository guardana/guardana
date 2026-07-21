from pathlib import Path

import pytest
from guardana.core.report import (
    BaselineError,
    Evidence,
    Finding,
    ScanResult,
    apply_baseline,
    load_baseline,
    serialize_baseline,
)
from guardana.core.severity import Severity


def _finding(rule_id: str = "guardana.x", ref: str = "a.py:1") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="t",
        taxonomy=(),
        target_ref=ref,
        evidence=Evidence(summary="s"),
    )


def test_fingerprint_is_line_independent_but_content_sensitive() -> None:
    # F-E: a line shift must NOT change the fingerprint (else a baseline churns on
    # unrelated edits) ...
    assert _finding(ref="a.py:1").fingerprint == _finding(ref="a.py:2").fingerprint
    # ... but a different file or rule still differs, so a genuinely new finding
    # still fails the gate (fail-closed).
    assert _finding(ref="a.py:1").fingerprint != _finding(ref="b.py:1").fingerprint
    assert _finding(rule_id="other", ref="a.py:1").fingerprint != _finding(ref="a.py:1").fingerprint
    assert len(_finding().fingerprint) == 16


def test_apply_baseline_moves_only_matching_to_waived() -> None:
    keep = _finding(ref="keep.py:1")
    waive = _finding(ref="waive.py:1")
    result = ScanResult(findings=(keep, waive), rules_run=2, rules_skipped=())
    out = apply_baseline(result, frozenset({waive.fingerprint}))
    assert out.findings == (keep,)
    assert out.waived == (waive,)


def test_serialize_then_load_roundtrips_and_waives(tmp_path: Path) -> None:
    f = _finding(ref="x.py:9")
    result = ScanResult(findings=(f,), rules_run=1, rules_skipped=())
    path = tmp_path / "guardana-baseline.yaml"
    path.write_text(serialize_baseline(result), encoding="utf-8")
    fingerprints = load_baseline(path)
    assert f.fingerprint in fingerprints
    out = apply_baseline(result, fingerprints)
    assert out.findings == ()
    assert out.waived == (f,)


def test_load_baseline_empty_is_no_waivers(tmp_path: Path) -> None:
    path = tmp_path / "b.yaml"
    path.write_text("", encoding="utf-8")
    assert load_baseline(path) == frozenset()


def test_load_baseline_malformed_waivers_raises(tmp_path: Path) -> None:
    path = tmp_path / "b.yaml"
    path.write_text("waivers: not-a-list\n", encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_load_baseline_waiver_without_fingerprint_raises(tmp_path: Path) -> None:
    path = tmp_path / "b.yaml"
    path.write_text("waivers:\n  - reason: because\n", encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_load_baseline_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(BaselineError):
        load_baseline(tmp_path / "nope.yaml")
