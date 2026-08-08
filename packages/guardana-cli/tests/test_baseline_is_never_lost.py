"""A waiver carries a person's decision, so nothing may remove one on a guess.

`baseline update` decides a finding is fixed by not seeing it — and a rule that
could not run produces exactly that absence. So a scan with one broken rule
deleted the waiver, the reason somebody wrote and the name of whoever approved
it, printed "is fixed", and exited `0`.

Also here: `scan --baseline` now says which waivers lapsed and which nobody ever
filled in. An expired waiver already stops waiving, so the gate was right — but
the build went red with nothing on screen explaining why, and the first guess is
always that the model got worse.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.testing import fake_aws_key
from typer.testing import CliRunner

runner = CliRunner()

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
    """A directory the built-in rules will flag, so a baseline has something to hold.

    The credential is assembled by `guardana.core.testing` rather than written
    here, for the reason that module exists: a secret-shaped literal in a test
    file is a secret-shaped literal in the repository, and the dogfood scan is
    right to say so.
    """
    source = tmp_path / "app"
    source.mkdir()
    (source / "settings.py").write_text(
        f'AWS_ACCESS_KEY_ID = "{fake_aws_key()}"\n', encoding="utf-8"
    )
    return source


def _waivers(path: Path) -> list[dict[str, object]]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = loaded["waivers"]
    assert isinstance(entries, list)
    return entries


def _reviewed_baseline(tmp_path: Path, source: Path, expires: str | None) -> Path:
    """Create a baseline and fill in the fields a person is supposed to fill in."""
    baseline = tmp_path / "guardana-baseline.yaml"
    runner.invoke(app, ["baseline", "create", str(source), "--output", str(baseline)])
    document = yaml.safe_load(baseline.read_text(encoding="utf-8"))
    for waiver in document["waivers"]:
        waiver["reason"] = "accepted for this test"
        waiver["approved_by"] = "a person"
        waiver["expires"] = expires
    baseline.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return baseline


def test_update_refuses_to_edit_the_file_when_a_check_did_not_run(tmp_path: Path) -> None:
    source = _repo_with_a_finding(tmp_path)
    baseline = _reviewed_baseline(tmp_path, source, expires=None)
    before = baseline.read_text(encoding="utf-8")
    assert _waivers(baseline), "the fixture produced no waivers to protect"
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "broken.yaml").write_text(_BROKEN_RULE, encoding="utf-8")
    profile = tmp_path / "guardana.yaml"
    profile.write_text(f"name: t\nrules:\n  paths: ['{rules}']\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["baseline", "update", str(source), "--file", str(baseline), "--profile", str(profile)],
    )

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert baseline.read_text(encoding="utf-8") == before, (
        "an incomplete scan removed a waiver, and with it the reason a person wrote"
    )


def test_update_still_removes_a_waiver_when_the_scan_was_complete(tmp_path: Path) -> None:
    # The other half of the contract: refusing on a broken scan must not turn
    # `update` into a command that never updates.
    source = _repo_with_a_finding(tmp_path)
    baseline = _reviewed_baseline(tmp_path, source, expires=None)
    (source / "settings.py").write_text("SAFE = 1\n", encoding="utf-8")

    result = runner.invoke(app, ["baseline", "update", str(source), "--file", str(baseline)])

    assert result.exit_code == ExitCode.OK, result.output
    assert _waivers(baseline) == []


def test_a_scan_says_when_a_waiver_it_was_given_has_lapsed(tmp_path: Path) -> None:
    source = _repo_with_a_finding(tmp_path)
    yesterday = (datetime.now(UTC).date() - timedelta(days=1)).isoformat()
    baseline = _reviewed_baseline(tmp_path, source, expires=yesterday)

    result = runner.invoke(app, ["scan", str(source), "--baseline", str(baseline)])

    assert "expired" in result.output, result.output
    assert result.exit_code == ExitCode.POLICY_FAILED, "an expired waiver must stop waiving"


def test_a_scan_says_when_a_waiver_still_has_the_generated_placeholder(tmp_path: Path) -> None:
    source = _repo_with_a_finding(tmp_path)
    baseline = tmp_path / "unreviewed.yaml"
    runner.invoke(app, ["baseline", "create", str(source), "--output", str(baseline)])

    result = runner.invoke(app, ["scan", str(source), "--baseline", str(baseline)])

    assert "placeholder" in result.output, result.output


@pytest.mark.parametrize("flag", ["--write-baseline"])
def test_writing_a_baseline_over_a_broken_scan_is_indeterminate(tmp_path: Path, flag: str) -> None:
    """`baseline create` answers this with `2`, so `scan --write-baseline` must too.

    Nothing failed a policy: a question was left unanswered. Two commands giving
    different codes for one situation is an exit-code table only half the tool
    honours.
    """
    source = _repo_with_a_finding(tmp_path)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "broken.yaml").write_text(_BROKEN_RULE, encoding="utf-8")

    result = runner.invoke(
        app, ["scan", str(source), flag, str(tmp_path / "out.yaml"), "--rules", str(rules)]
    )

    assert result.exit_code == ExitCode.INDETERMINATE, result.output
