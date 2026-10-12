"""A baseline is written only from a run the gate would let answer its question.

`baseline create`, `baseline update` and `scan --write-baseline` snapshot what a scan
saw. A run that verified nothing, stopped early or could not run a check saw less than
it claims, so each command refuses it with the gate's own open questions, exits `2` and
leaves the file as it was.
"""

from pathlib import Path

import pytest
import yaml
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.testing import fake_aws_key
from typer.testing import CliRunner

runner = CliRunner()

_SELECTS_NOTHING = "name: audit\nrules:\n  exclude: ['*']\n"

_BROKEN_RULE = """
id: acme.broken.rule
title: A rule whose evaluator nobody configured
severity: high
target_kind: endpoint
taxonomy: [LLM01:2025]
evaluator: no_such_evaluator
prompts:
  - "hello"
expect:
  keywords: ["x"]
"""


def _repo_with_a_finding(tmp_path: Path) -> Path:
    source = tmp_path / "app"
    source.mkdir()
    (source / "settings.py").write_text(
        f'AWS_ACCESS_KEY_ID = "{fake_aws_key()}"\n', encoding="utf-8"
    )
    return source


def _profile(tmp_path: Path, body: str) -> Path:
    profile = tmp_path / "guardana.yaml"
    profile.write_text(body, encoding="utf-8")
    return profile


@pytest.mark.parametrize("command", ["scan", "create"])
def test_a_baseline_is_not_written_over_a_run_that_verified_nothing(
    tmp_path: Path, command: str
) -> None:
    source = _repo_with_a_finding(tmp_path)
    out = tmp_path / "baseline.yaml"
    profile = _profile(tmp_path, _SELECTS_NOTHING)
    argv = (
        ["scan", str(source), "--write-baseline", str(out)]
        if command == "scan"
        else ["baseline", "create", str(source), "--output", str(out)]
    )

    result = runner.invoke(app, [*argv, "--profile", str(profile)])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert not out.exists(), "a baseline was written from a run that verified nothing"
    assert "nothing_verified" in result.output


def test_update_keeps_every_waiver_when_the_run_verified_nothing(tmp_path: Path) -> None:
    source = _repo_with_a_finding(tmp_path)
    baseline = tmp_path / "baseline.yaml"
    created = runner.invoke(app, ["baseline", "create", str(source), "--output", str(baseline)])
    assert created.exit_code == ExitCode.OK, created.output
    before = baseline.read_text(encoding="utf-8")
    assert yaml.safe_load(before)["waivers"], "the fixture produced no waiver to protect"
    profile = _profile(tmp_path, _SELECTS_NOTHING)

    result = runner.invoke(
        app,
        ["baseline", "update", str(source), "--file", str(baseline), "--profile", str(profile)],
    )

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert baseline.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("command", ["scan", "create"])
def test_a_check_that_did_not_run_blocks_a_baseline_whatever_fail_on_error_says(
    tmp_path: Path, command: str
) -> None:
    source = _repo_with_a_finding(tmp_path)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "broken.yaml").write_text(_BROKEN_RULE, encoding="utf-8")
    profile = _profile(
        tmp_path,
        f"name: lenient\nrules:\n  paths: ['{rules}']\nfail_on:\n  fail_on_error: false\n",
    )
    out = tmp_path / "baseline.yaml"
    argv = (
        ["scan", str(source), "--write-baseline", str(out)]
        if command == "scan"
        else ["baseline", "create", str(source), "--output", str(out)]
    )

    result = runner.invoke(app, [*argv, "--profile", str(profile)])

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert not out.exists()


@pytest.mark.parametrize("command", ["scan", "create"])
def test_a_complete_run_still_writes_its_baseline(tmp_path: Path, command: str) -> None:
    source = _repo_with_a_finding(tmp_path)
    out = tmp_path / "baseline.yaml"
    argv = (
        ["scan", str(source), "--write-baseline", str(out)]
        if command == "scan"
        else ["baseline", "create", str(source), "--output", str(out)]
    )

    result = runner.invoke(app, argv)

    assert result.exit_code == ExitCode.OK, result.output
    assert yaml.safe_load(out.read_text(encoding="utf-8"))["waivers"]
