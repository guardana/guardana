"""`guardana diff` — the re-test gate, end to end.

Three exit codes, because "nothing to report" has three meanings here too: no
regression, a regression, and a comparison that could not honestly be made. The
third is the one that must never be green.
"""

import json
from dataclasses import replace
from pathlib import Path

from guardana.cli.main import app
from guardana.core.evaluator.base import Verdict
from guardana.core.manifest.records import RuleRecord
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.severity import Severity
from guardana.core.target import TargetKind
from guardana.core.testing import manifest_for
from guardana.report import get_renderer
from typer.testing import CliRunner

runner = CliRunner()

_RULE = "guardana.prompt.injection"
_OTHER = "guardana.prompt.leak"
_ENDPOINT = "http://localhost:11434#llama3"

_NO_REGRESSION = 0
_REGRESSION = 1
_INCOMPARABLE = 2


def _finding(*, severity: Severity = Severity.HIGH, outcome: str = "fail") -> Finding:
    return Finding(
        _RULE,
        severity,
        "prompt injection",
        (),
        _ENDPOINT,
        Evidence(summary="the model complied"),
        Verdict(outcome, 0.9, "the model complied", "keyword"),  # type: ignore[arg-type]
    )


def _write(
    path: Path,
    *,
    findings: tuple[Finding, ...] = (),
    unverified: tuple[Finding, ...] = (),
    ran: tuple[str, ...] = (_RULE, _OTHER),
    kind: TargetKind = TargetKind.ENDPOINT,
) -> Path:
    result = ScanResult(findings=findings, rules_run=ran, rules_skipped=(), unverified=unverified)
    manifest = replace(
        manifest_for(result, target_ref=_ENDPOINT, target_kind=kind, tool_version="0.6.0"),
        rules=tuple(RuleRecord(id=rule, digest="aaaabbbbccccdddd") for rule in ran),
    )
    path.write_text(get_renderer("json", run=manifest).render(result), encoding="utf-8")
    return path


def test_an_unchanged_pair_of_runs_exits_zero(tmp_path: Path) -> None:
    before = _write(tmp_path / "a.json", findings=(_finding(),))
    after = _write(tmp_path / "b.json", findings=(_finding(),))

    result = runner.invoke(app, ["diff", str(before), str(after)])

    assert result.exit_code == _NO_REGRESSION
    assert "no regression" in result.stdout.lower()


def test_a_new_problem_fails_the_gate(tmp_path: Path) -> None:
    before = _write(tmp_path / "a.json")
    after = _write(tmp_path / "b.json", findings=(_finding(),))

    result = runner.invoke(app, ["diff", str(before), str(after)])

    assert result.exit_code == _REGRESSION
    assert _RULE in result.stdout


def test_a_fixed_problem_exits_zero_and_says_so(tmp_path: Path) -> None:
    before = _write(tmp_path / "a.json", findings=(_finding(),))
    after = _write(tmp_path / "b.json")

    result = runner.invoke(app, ["diff", str(before), str(after)])

    assert result.exit_code == _NO_REGRESSION
    assert "no longer reported" in result.stdout


def test_a_check_that_went_blind_fails_the_gate(tmp_path: Path) -> None:
    """The count falls here. A comparison that counted would call this progress."""
    before = _write(tmp_path / "a.json", findings=(_finding(),))
    after = _write(tmp_path / "b.json", unverified=(_finding(outcome="inconclusive"),))

    result = runner.invoke(app, ["diff", str(before), str(after)])

    assert result.exit_code == _REGRESSION


def test_a_rule_that_stopped_running_fails_the_gate(tmp_path: Path) -> None:
    before = _write(tmp_path / "a.json", ran=(_RULE, _OTHER))
    after = _write(tmp_path / "b.json", ran=(_RULE,))

    result = runner.invoke(app, ["diff", str(before), str(after)])

    assert result.exit_code == _REGRESSION
    assert _OTHER in result.stdout


def test_a_run_from_an_older_guardana_is_refused_with_two(tmp_path: Path) -> None:
    """Every run saved by 0.5 and earlier. Reading it as empty is the failure mode."""
    old = tmp_path / "old.json"
    old.write_text('{"findings": [], "summary": {"rules_run": 3}}', encoding="utf-8")
    current = _write(tmp_path / "new.json")

    result = runner.invoke(app, ["diff", str(old), str(current)])

    assert result.exit_code == _INCOMPARABLE
    assert "schema_version" in result.stdout + str(result.stderr)


def test_two_different_kinds_of_target_are_refused_with_two(tmp_path: Path) -> None:
    files = _write(tmp_path / "a.json", kind=TargetKind.ARTIFACT)
    model = _write(tmp_path / "b.json", kind=TargetKind.ENDPOINT)

    assert runner.invoke(app, ["diff", str(files), str(model)]).exit_code == _INCOMPARABLE


def test_a_missing_file_is_refused_with_two(tmp_path: Path) -> None:
    present = _write(tmp_path / "a.json")

    result = runner.invoke(app, ["diff", str(present), str(tmp_path / "nope.json")])

    assert result.exit_code == _INCOMPARABLE


def test_a_regression_below_the_profile_bar_does_not_fail_the_gate(tmp_path: Path) -> None:
    """The same regression, gated or not depending on the policy the team chose."""
    profile = tmp_path / "guardana.yaml"
    profile.write_text("name: strict\nfail_on:\n  severity: critical\n")
    before = _write(tmp_path / "a.json")
    after = _write(tmp_path / "b.json", findings=(_finding(severity=Severity.HIGH),))

    assert runner.invoke(app, ["diff", str(before), str(after)]).exit_code == _REGRESSION
    strict = runner.invoke(app, ["diff", str(before), str(after), "--profile", str(profile)])
    assert strict.exit_code == _NO_REGRESSION


def test_json_output_carries_the_changes_and_a_schema_version(tmp_path: Path) -> None:
    before = _write(tmp_path / "a.json")
    after = _write(tmp_path / "b.json", findings=(_finding(),))

    result = runner.invoke(app, ["diff", str(before), str(after), "--format", "json"])

    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["changes"][0]["kind"] == "appeared"
    assert payload["changes"][0]["regression"] is True
    assert payload["summary"]["regressions"] == 1
