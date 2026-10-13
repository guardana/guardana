"""`--trials` end to end: what a probe sends, what it saves, and what a comparison does with it.

Driven through the command rather than the runner, because the merge of canary passes
is where the trials of one case could collapse into one.
"""

import json
from pathlib import Path

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.report import load_report
from guardana.core.testing import RefusingTransport, ScriptedTransport
from typer.testing import CliRunner

runner = CliRunner()


class _CountingRefusal(RefusingTransport):
    """Refuses everything, and counts every request it was sent."""

    sent = 0

    def send(self, *args: object, **kwargs: object) -> str:
        type(self).sent += 1
        return super().send(*args, **kwargs)  # type: ignore[arg-type]


def _probe(monkeypatch: pytest.MonkeyPatch, out: Path, *extra: str) -> int:
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)
    result = runner.invoke(
        app,
        ["probe", "--url", "http://fake", "--model", "m", "--output", str(out), *extra],
    )
    return result.exit_code


def test_a_probe_with_trials_saves_every_trial_and_what_each_rule_did(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = tmp_path / "run.json"

    assert _probe(monkeypatch, out, "--trials", "3", "--format", "json") == 0

    document = json.loads(out.read_text(encoding="utf-8"))
    run = document["run"]
    assert document["schema_version"] == 18
    assert run["execution"]["trials"] == 3
    repeating = [r for r in run["rules"] if r["trial_summary"] is not None]
    assert repeating, "no rule repeated at --trials 3"
    for rule in repeating:
        summary = rule["trial_summary"]
        assert summary["trials_per_case"] == 3
        assert summary["cases_failed"] == summary["cases_incomplete"] == 0
        assert summary["bound"] is not None
        trials = [a["trial"] for a in document["assessments"] if a["rule_id"] == rule["id"]]
        assert sorted(set(trials)) == [1, 2, 3]
        assert len(trials) == 3 * summary["cases"]
    # The canary rule runs in a pass of its own and must keep all its trials through
    # the merge.
    canary = next(r for r in repeating if "canary" in r["id"])
    assert canary["trial_summary"]["cases"] >= 1

    loaded = load_report(out)
    assert loaded.result.trials_per_case == {r["id"]: 3 for r in repeating}


def test_every_request_the_trials_add_was_priced_by_the_plan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _CountingRefusal.sent = 0
    monkeypatch.setattr(endpoint_module, "transport_factory", _CountingRefusal)
    plan = runner.invoke(
        app,
        [
            "plan",
            "probe",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--trials",
            "3",
            "--format",
            "json",
        ],
    )
    priced = json.loads(plan.output)
    assert priced["trials"]["per_case"] == 3

    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--trials",
            "3",
            "--output",
            str(tmp_path / "r.json"),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert priced["requests"]["min"] <= _CountingRefusal.sent <= priced["requests"]["max"]


def test_the_human_report_states_the_trials_and_the_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)

    result = runner.invoke(app, ["probe", "--url", "http://fake", "--model", "m", "--trials", "2"])

    assert result.exit_code == 0, result.output
    assert "Trials" in result.output
    assert "cases in 2 trials each · ASR@2 ≤" in result.output
    assert (
        "graded by keyword · uncorrected — judge error not measured: no calibration "
        "recorded for keyword"
    ) in result.output
    assert "graded by canary\n" in result.output
    assert "grader error not corrected" not in result.output
    assert "static prompt set · no adaptive attacker ran" in result.output


def test_a_comparison_across_a_change_in_trials_is_refused_by_rule(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    once, thrice = tmp_path / "once.json", tmp_path / "thrice.json"
    assert _probe(monkeypatch, once, "--format", "json") == 0
    assert _probe(monkeypatch, thrice, "--trials", "3", "--format", "json") == 0

    result = runner.invoke(app, ["diff", str(once), str(thrice)])

    assert result.exit_code == int(ExitCode.INDETERMINATE), result.output
    assert "trials changed 1 → 3" in result.output
    assert "No regression" not in result.output


def test_the_same_trials_on_both_sides_compare(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    assert _probe(monkeypatch, first, "--trials", "2", "--format", "json") == 0
    assert _probe(monkeypatch, second, "--trials", "2", "--format", "json") == 0

    result = runner.invoke(app, ["diff", str(first), str(second)])

    assert result.exit_code == 0, result.output


def test_zero_trials_is_refused_before_anything_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", ScriptedTransport)

    result = runner.invoke(app, ["probe", "--url", "http://fake", "--model", "m", "--trials", "0"])

    assert result.exit_code == int(ExitCode.INVALID_USAGE)


def test_trials_in_the_profile_reach_the_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text("trials: 2\n", encoding="utf-8")
    out = tmp_path / "run.json"

    assert _probe(monkeypatch, out, "--profile", str(profile), "--format", "json") == 0

    assert json.loads(out.read_text(encoding="utf-8"))["run"]["execution"]["trials"] == 2


def test_a_monitor_cycle_makes_every_trial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _CountingRefusal)
    argv = ["monitor", "--url", "http://fake", "--model", "m", "--max-cycles", "1"]

    _CountingRefusal.sent = 0
    once = runner.invoke(app, argv)
    single = _CountingRefusal.sent
    _CountingRefusal.sent = 0
    thrice = runner.invoke(app, [*argv, "--trials", "3"])

    assert once.exit_code == thrice.exit_code == 0, thrice.output
    assert _CountingRefusal.sent == 3 * single


def test_run_inspect_says_how_many_trials_were_asked_for_and_made(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = tmp_path / "run.json"
    assert _probe(monkeypatch, out, "--trials", "2", "--format", "json") == 0

    result = runner.invoke(app, ["run", "inspect", str(out)])

    assert result.exit_code == 0, result.output
    assert "trials:    2 per case asked;" in result.output


def test_one_trial_is_not_reported_as_repeating(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = tmp_path / "run.json"
    assert _probe(monkeypatch, out, "--format", "json") == 0

    result = runner.invoke(app, ["run", "inspect", str(out)])

    assert "trials:    1 per case asked; 0 rule(s) and 0 suite(s) repeated" in result.output


def test_a_profile_asking_for_trials_changes_nothing_about_a_file_scan(tmp_path: Path) -> None:
    profile = tmp_path / "guardana.yaml"
    profile.write_text("trials: 5\n", encoding="utf-8")
    (tmp_path / "model.py").write_text("x = 1\n", encoding="utf-8")
    out = tmp_path / "scan.json"

    plan = runner.invoke(
        app, ["plan", "scan", str(tmp_path), "--profile", str(profile), "--format", "json"]
    )
    scan = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--profile",
            str(profile),
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )

    assert json.loads(plan.output)["trials"] == {"per_case": 1, "single_attempt": []}
    assert scan.exit_code == 0, scan.output
    assert json.loads(out.read_text(encoding="utf-8"))["run"]["execution"]["trials"] == 1


def test_a_rule_that_reported_a_finding_never_gets_a_bound() -> None:
    from guardana.cli._run_meta import _Grading, _trial_summary  # noqa: PLC0415
    from guardana.core.assessment import Assessment  # noqa: PLC0415
    from guardana.core.evaluator.base import Expectation  # noqa: PLC0415
    from guardana.core.report import ScanResult  # noqa: PLC0415
    from guardana.core.rule.base import RuleMeta  # noqa: PLC0415
    from guardana.core.rule.yaml_rule import YamlRule  # noqa: PLC0415
    from guardana.core.severity import Severity  # noqa: PLC0415
    from guardana.core.target import TargetKind  # noqa: PLC0415

    rule = YamlRule(
        meta=RuleMeta("acme.p", "t", Severity.HIGH, TargetKind.ENDPOINT),
        prompts=("p",),
        expectation=Expectation(goal="g"),
    )
    passes = [
        Assessment(
            case_id="c", assessor="k", subject_ref="s", rule_id="acme.p", passed=True, trial=1
        )
    ]
    result = ScanResult((), ("acme.p",), (), assessments=tuple(passes))

    grading = _Grading(evaluators={}, calibrations={}, starter_digest="sha256:0")

    clean = _trial_summary(rule, passes, result, set(), grading)
    contradicted = _trial_summary(rule, passes, result, {"acme.p"}, grading)

    assert clean is not None
    assert clean.bound is not None
    assert contradicted is not None
    assert contradicted.bound is None
    assert contradicted.correction is not None
    assert contradicted.correction.status == "uncorrected"
    assert contradicted.correction.reason == (
        "judge error not measured: no calibration recorded for k"
    )


def test_a_scenario_graded_at_several_turns_is_one_case_in_the_saved_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "walk.yaml").write_text(
        "id: acme.scenario.walk\n"
        "title: t\n"
        "severity: high\n"
        "target_kind: endpoint\n"
        "taxonomy: [LLM01:2025]\n"
        "requires: [chat]\n"
        "steps:\n"
        "  - send: first\n"
        "    expect: {evaluator: keyword, goal: g}\n"
        "  - send: second\n"
        "    expect: {evaluator: keyword, goal: g}\n"
        "expect: {evaluator: keyword, goal: g}\n",
        encoding="utf-8",
    )
    out = tmp_path / "run.json"

    code = _probe(monkeypatch, out, "--rules", str(rules), "--trials", "2", "--format", "json")

    assert code == 0
    run = json.loads(out.read_text(encoding="utf-8"))["run"]
    walk = next(r for r in run["rules"] if r["id"] == "acme.scenario.walk")
    assert walk["trial_summary"]["cases"] == 1
    assert walk["trial_summary"]["bound"] == pytest.approx(0.95)
