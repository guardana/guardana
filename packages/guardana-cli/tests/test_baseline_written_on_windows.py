"""A version-2 baseline written on Windows keeps waiving its finding, and `update` rewrites it.

Such a file fingerprinted `src\\run.py`, where this build reports `src/run.py`.
"""

import sys
from pathlib import Path

import pytest
import yaml
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.report.baseline import windows_fingerprint
from guardana.core.report.finding import Finding
from guardana.core.report.load import load_report
from typer.testing import CliRunner

runner = CliRunner()

_SINK = "guardana.supply_chain.code_execution"


def _finding(tmp_path: Path) -> Finding:
    """Scan `src` from `tmp_path` and return the one finding this build reports there."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "run.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    saved = tmp_path / "run.json"
    runner.invoke(app, ["scan", "src", "--format", "json", "--output", str(saved)])
    findings = load_report(saved).result.findings
    saved.unlink()
    if [f.rule_id for f in findings] != [_SINK] or findings[0].target_ref != "src/run.py:2":
        raise RuntimeError(f"precondition: one shell sink at src/run.py:2, got {findings}")
    return findings[0]


def _windows_baseline(tmp_path: Path, finding: Finding, *, version: int = 2) -> Path:
    """Write the baseline a Windows build of an older version wrote for `finding`."""
    fingerprint = windows_fingerprint(finding)
    if fingerprint is None:
        raise RuntimeError("precondition: the finding is in a directory")
    baseline = tmp_path / "guardana-baseline.yaml"
    waiver = {
        "fingerprint": fingerprint,
        "rule": finding.rule_id,
        "location": "src\\run.py:2",
        "reason": "the command is a constant",
        "approved_by": "owner",
        "expires": "2099-12-31",
    }
    baseline.write_text(
        yaml.safe_dump({"version": version, "waivers": [waiver]}, sort_keys=False),
        encoding="utf-8",
    )
    return baseline


def _scan(baseline: Path) -> int:
    return runner.invoke(app, ["scan", "src", "--baseline", str(baseline)]).exit_code


def _update(baseline: Path, *profile: str) -> tuple[int, str]:
    result = runner.invoke(app, ["baseline", "update", "src", "--file", str(baseline), *profile])
    return result.exit_code, " ".join(result.output.split())


@pytest.fixture(autouse=True)
def _in_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)


def test_a_v2_windows_waiver_waives_the_finding_in_a_scan(tmp_path: Path) -> None:
    baseline = _windows_baseline(tmp_path, _finding(tmp_path))

    assert _scan(baseline) == ExitCode.OK


def test_control_the_same_waiver_in_a_v3_file_leaves_the_finding_failing(tmp_path: Path) -> None:
    baseline = _windows_baseline(tmp_path, _finding(tmp_path), version=3)

    assert _scan(baseline) == ExitCode.POLICY_FAILED


def test_an_update_rewrites_a_windows_waiver_with_the_finding_it_waives(tmp_path: Path) -> None:
    finding = _finding(tmp_path)
    baseline = _windows_baseline(tmp_path, finding)

    code, said = _update(baseline)

    assert code == ExitCode.OK, said
    document = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    assert document["version"] == 3
    assert document["waivers"] == [
        {
            "fingerprint": finding.fingerprint,
            "rule": _SINK,
            "location": "src/run.py:2",
            "reason": "the command is a constant",
            "approved_by": "owner",
            "expires": "2099-12-31",
        }
    ]
    assert "1 waiver(s) kept, 0 removed" in said, said
    assert "0 finding(s) are not waived" in said, said
    assert _scan(baseline) == ExitCode.OK


def test_an_update_that_did_not_run_the_rule_keeps_the_windows_waiver_and_version(
    tmp_path: Path,
) -> None:
    baseline = _windows_baseline(tmp_path, _finding(tmp_path))
    written = baseline.read_text(encoding="utf-8")
    narrow = tmp_path / "narrow.yaml"
    narrow.write_text(f"rules:\n  exclude: ['{_SINK}']\n", encoding="utf-8")

    code, said = _update(baseline, "--profile", str(narrow))

    assert code == ExitCode.OK, said
    assert yaml.safe_load(baseline.read_text(encoding="utf-8")) == yaml.safe_load(written)
    assert f"{_SINK} did not run" in said, said


def test_an_update_after_the_fix_removes_the_windows_waiver(tmp_path: Path) -> None:
    baseline = _windows_baseline(tmp_path, _finding(tmp_path))
    (tmp_path / "src" / "run.py").write_text("print('fixed')\n", encoding="utf-8")

    code, said = _update(baseline)

    assert code == ExitCode.OK, said
    assert yaml.safe_load(baseline.read_text(encoding="utf-8"))["waivers"] == [], said
    assert "is fixed" in said, said


def test_an_update_after_the_file_was_deleted_names_it_with_slashes(tmp_path: Path) -> None:
    baseline = _windows_baseline(tmp_path, _finding(tmp_path))
    (tmp_path / "src" / "run.py").unlink()
    (tmp_path / "src" / "other.py").write_text("X = 1\n", encoding="utf-8")

    code, said = _update(baseline)

    assert code == ExitCode.OK, said
    assert yaml.safe_load(baseline.read_text(encoding="utf-8"))["waivers"] == [], said
    assert "src/run.py is no longer in the scanned tree" in said, said


def test_an_update_keeps_the_waiver_already_written_for_the_finding_over_a_windows_one(
    tmp_path: Path,
) -> None:
    finding = _finding(tmp_path)
    baseline = _windows_baseline(tmp_path, finding)
    document = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    document["waivers"].append(
        {
            "fingerprint": finding.fingerprint,
            "rule": finding.rule_id,
            "location": "src/run.py:2",
            "reason": "reviewed on Linux",
            "approved_by": "owner",
            "expires": "2099-12-31",
        }
    )
    baseline.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    code, said = _update(baseline)

    assert code == ExitCode.OK, said
    written = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    assert written["version"] == 3
    assert [w["reason"] for w in written["waivers"]] == ["reviewed on Linux"]
    assert "another waiver in this file already waives" in said, said
    assert "1 waiver(s) kept, 1 removed" in said, said
    assert "is fixed" not in said, said


def test_an_update_keeps_an_active_windows_waiver_beside_an_expired_one_for_the_finding(
    tmp_path: Path,
) -> None:
    finding = _finding(tmp_path)
    baseline = _windows_baseline(tmp_path, finding)
    document = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    document["waivers"].insert(
        0,
        {
            "fingerprint": finding.fingerprint,
            "rule": finding.rule_id,
            "location": "src/run.py:2",
            "reason": "lapsed",
            "approved_by": "owner",
            "expires": "2001-01-01",
        },
    )
    baseline.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    code, said = _update(baseline)

    assert code == ExitCode.OK, said
    written = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    assert [w["reason"] for w in written["waivers"]] == ["lapsed", "the command is a constant"]
    assert "0 finding(s) are not waived" in said, said
    assert _scan(baseline) == ExitCode.OK


def test_an_update_leaves_two_waivers_written_for_one_finding_as_they_are(
    tmp_path: Path,
) -> None:
    finding = _finding(tmp_path)
    native = {
        "fingerprint": finding.fingerprint,
        "rule": finding.rule_id,
        "location": "src/run.py:2",
        "approved_by": "owner",
    }
    baseline = tmp_path / "guardana-baseline.yaml"
    document = {
        "version": 3,
        "waivers": [
            {**native, "reason": "first", "expires": "2001-01-01"},
            {**native, "reason": "renewed", "expires": "2099-12-31"},
        ],
    }
    baseline.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    code, said = _update(baseline)

    assert code == ExitCode.OK, said
    written = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    assert [w["reason"] for w in written["waivers"]] == ["first", "renewed"]
    assert "already waives" not in said, said
    assert _scan(baseline) == ExitCode.OK


def test_an_update_keeps_the_active_one_of_two_windows_waivers_for_one_finding(
    tmp_path: Path,
) -> None:
    finding = _finding(tmp_path)
    baseline = _windows_baseline(tmp_path, finding)
    document = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    document["waivers"].insert(
        0, {**document["waivers"][0], "reason": "lapsed", "expires": "2001-01-01"}
    )
    baseline.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    code, said = _update(baseline)

    assert code == ExitCode.OK, said
    written = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    assert [w["reason"] for w in written["waivers"]] == ["the command is a constant"]
    assert "already waives" in said, said
    assert _scan(baseline) == ExitCode.OK


@pytest.mark.skipif(sys.platform == "win32", reason="a file name cannot hold a backslash there")
def test_a_file_name_holding_a_backslash_is_not_read_as_a_windows_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = tmp_path / "tree"
    (tree / "pkg").mkdir(parents=True)
    source = "import os\nos.system(cmd)\n"
    (tree / "pkg\\run.py").write_text(source, encoding="utf-8")
    (tree / "pkg" / "run.py").write_text(source, encoding="utf-8")
    monkeypatch.chdir(tree)
    saved = tmp_path / "run.json"
    runner.invoke(app, ["scan", ".", "--format", "json", "--output", str(saved)])
    found = {f.target_ref: f for f in load_report(saved).result.findings}
    if set(found) != {"pkg\\run.py:2", "pkg/run.py:2"}:
        raise RuntimeError(f"precondition: both files report one sink, got {sorted(found)}")
    named = found["pkg\\run.py:2"]
    baseline = tmp_path / "guardana-baseline.yaml"
    waiver = {
        "fingerprint": named.fingerprint,
        "rule": named.rule_id,
        "location": named.target_ref,
        "reason": "the command is a constant",
        "approved_by": "owner",
        "expires": "2099-12-31",
    }
    baseline.write_text(yaml.safe_dump({"version": 2, "waivers": [waiver]}), encoding="utf-8")

    scanned = runner.invoke(
        app, ["scan", ".", "--baseline", str(baseline), "--format", "json", "--output", str(saved)]
    )
    assert scanned.exit_code == ExitCode.POLICY_FAILED, scanned.output
    report = load_report(saved).result
    assert [f.target_ref for f in report.waived] == ["pkg\\run.py:2"]
    assert [f.target_ref for f in report.findings] == ["pkg/run.py:2"]

    updated = runner.invoke(app, ["baseline", "update", ".", "--file", str(baseline)])
    said = " ".join(updated.output.split())
    assert updated.exit_code == ExitCode.OK, said
    written = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    assert written["version"] == 3
    assert [w["fingerprint"] for w in written["waivers"]] == [named.fingerprint]
    assert "1 finding(s) are not waived" in said, said


def _named_with_a_backslash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Scan a tree holding one sink in `pkg\\run.py`; return that file and a version-2 baseline."""
    tree = tmp_path / "tree"
    tree.mkdir()
    named = tree / "pkg\\run.py"
    named.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    (tree / "other.py").write_text("X = 1\n", encoding="utf-8")
    monkeypatch.chdir(tree)
    saved = tmp_path / "run.json"
    runner.invoke(app, ["scan", ".", "--format", "json", "--output", str(saved)])
    (finding,) = load_report(saved).result.findings
    baseline = tmp_path / "guardana-baseline.yaml"
    waiver = {
        "fingerprint": finding.fingerprint,
        "rule": finding.rule_id,
        "location": finding.target_ref,
        "reason": "the command is a constant",
        "approved_by": "owner",
        "expires": "2099-12-31",
    }
    baseline.write_text(yaml.safe_dump({"version": 2, "waivers": [waiver]}), encoding="utf-8")
    return named, baseline


@pytest.mark.skipif(sys.platform == "win32", reason="a file name cannot hold a backslash there")
def test_an_update_clears_a_waiver_for_a_file_named_with_a_backslash_once_it_is_fixed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    named, baseline = _named_with_a_backslash(tmp_path, monkeypatch)
    named.write_text("print('fixed')\n", encoding="utf-8")

    updated = runner.invoke(app, ["baseline", "update", ".", "--file", str(baseline)])

    said = " ".join(updated.output.split())
    assert updated.exit_code == ExitCode.OK, said
    written = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    assert written["waivers"] == [], said
    assert written["version"] == 3, said
    assert "is fixed" in said, said


@pytest.mark.skipif(sys.platform == "win32", reason="a file name cannot hold a backslash there")
def test_an_update_keeps_a_waiver_for_a_deleted_file_named_with_a_backslash_as_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    named, baseline = _named_with_a_backslash(tmp_path, monkeypatch)
    named.unlink()

    updated = runner.invoke(app, ["baseline", "update", ".", "--file", str(baseline)])

    said = " ".join(updated.output.split())
    assert updated.exit_code == ExitCode.OK, said
    assert len(yaml.safe_load(baseline.read_text(encoding="utf-8"))["waivers"]) == 1, said
    assert "this run did not list pkg/run.py" in said, said


def test_an_update_keeps_a_windows_waiver_for_a_present_file_the_run_did_not_list(
    tmp_path: Path,
) -> None:
    baseline = _windows_baseline(tmp_path, _finding(tmp_path))
    narrow = tmp_path / "narrow.yaml"
    narrow.write_text("rules:\n  paths_exclude: ['src/run.py']\n", encoding="utf-8")

    updated = runner.invoke(
        app, ["baseline", "update", ".", "--file", str(baseline), "--profile", str(narrow)]
    )

    said = " ".join(updated.output.split())
    assert updated.exit_code == ExitCode.OK, said
    assert len(yaml.safe_load(baseline.read_text(encoding="utf-8"))["waivers"]) == 1, said
    assert "this run did not list src/run.py" in said, said
    assert "no longer in the scanned tree" not in said, said


def test_an_update_from_another_directory_keeps_a_windows_waiver_it_cannot_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = _windows_baseline(tmp_path, _finding(tmp_path))
    monkeypatch.chdir(tmp_path / "src")

    updated = runner.invoke(app, ["baseline", "update", ".", "--file", str(baseline)])

    said = " ".join(updated.output.split())
    assert updated.exit_code == ExitCode.OK, said
    assert len(yaml.safe_load(baseline.read_text(encoding="utf-8"))["waivers"]) == 1, said
    assert "no longer in the scanned tree" not in said, said


def test_an_update_of_a_fixed_file_under_the_working_directory_says_it_is_fixed(
    tmp_path: Path,
) -> None:
    baseline = _windows_baseline(tmp_path, _finding(tmp_path))
    (tmp_path / "src" / "run.py").write_text("print('fixed')\n", encoding="utf-8")

    updated = runner.invoke(app, ["baseline", "update", ".", "--file", str(baseline)])

    said = " ".join(updated.output.split())
    assert updated.exit_code == ExitCode.OK, said
    assert "is fixed" in said, said
    assert "no longer in the scanned tree" not in said, said
