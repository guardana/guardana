"""One test per code, asserting the exact integer, plus one that pins the table.

A code nobody tests is a code that drifts, and a documented table nothing checks
is a table that stops being true. Both have happened in this repository to other
numbers, which is why the documentation is parsed here rather than trusted.
"""

import json
import re
from pathlib import Path

import pytest
from guardana.cli.exit_codes import ExitCode, code_for
from guardana.cli.main import app
from guardana.core.gate import GateOutcome
from guardana.core.report import StopReason
from typer.testing import CliRunner

runner = CliRunner()

_DOC = Path(__file__).resolve().parents[3] / "docs" / "exit-codes.md"
_ROW = re.compile(r"^\|\s*(\d)\s*\|\s*(.+?)\s*\|$", re.MULTILINE)


def test_the_documented_table_matches_the_code() -> None:
    documented = {int(code) for code, _meaning in _ROW.findall(_DOC.read_text(encoding="utf-8"))}

    assert documented == {int(member) for member in ExitCode}


def test_every_code_is_documented_with_a_meaning() -> None:
    rows = dict(_ROW.findall(_DOC.read_text(encoding="utf-8")))

    assert all(rows[str(int(member))].strip() for member in ExitCode)


def test_a_verdict_maps_to_its_code() -> None:
    assert code_for(GateOutcome.PASS) is ExitCode.OK
    assert code_for(GateOutcome.FAIL) is ExitCode.POLICY_FAILED
    assert code_for(GateOutcome.INDETERMINATE) is ExitCode.INDETERMINATE


def test_a_stop_outranks_the_verdict_it_would_otherwise_have_had() -> None:
    # The direction that matters: lowering a budget until the run ends early must
    # not convert a failure into anything quieter.
    assert code_for(GateOutcome.FAIL, StopReason.BUDGET_EXHAUSTED) is ExitCode.BUDGET_EXHAUSTED
    assert code_for(GateOutcome.PASS, StopReason.BUDGET_EXHAUSTED) is ExitCode.BUDGET_EXHAUSTED
    assert code_for(GateOutcome.PASS, StopReason.INTERRUPTED) is ExitCode.INTERRUPTED


def test_a_clean_scan_exits_zero(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == ExitCode.OK


def test_a_scan_with_a_blocking_finding_exits_one() -> None:
    result = runner.invoke(app, ["scan", "examples/vulnerable-model"])

    assert result.exit_code == ExitCode.POLICY_FAILED


def test_a_broken_profile_exits_three(tmp_path: Path) -> None:
    # Invalid configuration, not a policy failure: a typo must never read as a
    # security finding.
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: x\nrules:\n  includ: ['*']\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--profile", str(profile)])

    assert result.exit_code == ExitCode.INVALID_USAGE


def test_a_budget_that_cannot_be_enforced_exits_three(tmp_path: Path) -> None:
    # A token ceiling on a transport that reports no tokens: refused up front, and
    # refused as configuration rather than as a security verdict.
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: x\nbudgets:\n  max_duration: 5m\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--profile", str(profile)])

    assert result.exit_code == ExitCode.INVALID_USAGE


def test_an_unreachable_endpoint_exits_four() -> None:
    result = runner.invoke(
        app, ["probe", "--url", "http://127.0.0.1:9", "--model", "m", "--concurrency", "1"]
    )

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE


def test_a_run_that_executed_no_rules_exits_two(tmp_path: Path) -> None:
    # Nothing was verified. Non-zero either way; the point is that a pipeline can
    # tell this from a target that got worse.
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: x\nrules:\n  include: ['nothing.matches.this']\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--profile", str(profile)])

    assert result.exit_code == ExitCode.INDETERMINATE


def test_an_unreadable_run_exits_three(tmp_path: Path) -> None:
    junk = tmp_path / "junk.json"
    junk.write_text("{}", encoding="utf-8")

    result = runner.invoke(app, ["run", "inspect", str(junk)])

    assert result.exit_code == ExitCode.INVALID_USAGE


def test_an_impossible_comparison_exits_two(tmp_path: Path) -> None:
    empty = tmp_path / "a.json"
    empty.write_text(json.dumps({"schema_version": 2}), encoding="utf-8")

    result = runner.invoke(app, ["diff", str(empty), str(empty)])

    assert result.exit_code == ExitCode.INDETERMINATE


@pytest.mark.parametrize("member", list(ExitCode))
def test_no_code_is_zero_except_the_pass(member: ExitCode) -> None:
    assert (member == 0) is (member is ExitCode.OK)


def test_init_refusing_to_overwrite_is_usage_not_policy(tmp_path: Path) -> None:
    # Every command shares one table, or the table is not a contract. These three
    # exited 1 — "the policy failed" — for what are plainly usage errors.
    existing = tmp_path / "guardana.yaml"
    existing.write_text("name: x\n", encoding="utf-8")

    result = runner.invoke(app, ["init", str(existing)])

    assert result.exit_code == ExitCode.INVALID_USAGE


def test_new_rule_with_an_unknown_evaluator_is_usage_not_policy(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["new-rule", "acme.demo.check", "--dir", str(tmp_path), "--evaluator", "nope"]
    )

    assert result.exit_code == ExitCode.INVALID_USAGE
