"""The exit-code table is a contract, so every command has to honour it.

Two ways it was not. An unreadable saved run reached the user as a traceback and
exit `1` — which the table defines as "a finding failed the policy", the one
thing a broken input file is not. And `scan --write-baseline` answered a check
that could not run with `1`, while `baseline create` answered the identical
situation with `2`.

Codes are read by pipelines that never see the message beside them, so a code
that means two things means nothing.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def _unreadable_v1(tmp_path: Path, name: str = "old.json") -> Path:
    """A version-1 run missing a field the current schema needs."""
    document: dict[str, Any] = {
        "schema_version": 1,
        "run": {
            "tool_version": "0.6.0",
            "profile": "ci",
            "rules": {},
            "rules_skipped": [],
            "started_at": "2026-07-25T09:00:00+00:00",
        },
        "findings": [],
        "unverified": [],
        "waived": [],
        "errors": [],
        "observations": [],
    }
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _current_run(tmp_path: Path) -> Path:
    path = tmp_path / "current.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--output", str(path)])
    assert path.exists(), result.output
    return path


@pytest.mark.parametrize("command", [["run", "inspect"], ["run", "migrate"]])
def test_an_unreadable_saved_run_is_invalid_usage(tmp_path: Path, command: list[str]) -> None:
    result = runner.invoke(app, [*command, str(_unreadable_v1(tmp_path))])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit), (
        "the user got a traceback instead of a message"
    )


def test_comparing_against_an_unreadable_run_is_not_a_policy_failure(tmp_path: Path) -> None:
    baseline = _unreadable_v1(tmp_path)
    current = _current_run(tmp_path)

    result = runner.invoke(app, ["diff", str(baseline), str(current)])

    assert result.exit_code != ExitCode.POLICY_FAILED, result.output
    assert result.exit_code in (ExitCode.INDETERMINATE, ExitCode.INVALID_USAGE), result.output


def test_a_refused_migration_leaves_the_original_file_untouched(tmp_path: Path) -> None:
    """`migrate` writes in place by default, so a half-done migration destroys evidence."""
    path = _unreadable_v1(tmp_path)
    before = path.read_text(encoding="utf-8")

    runner.invoke(app, ["run", "migrate", str(path)])

    assert path.read_text(encoding="utf-8") == before
