"""A suite end to end: what a probe sends, saves, prints and gates on.

Driven through the command against a fake endpoint, because the calibrations, the
judge's budget and the saved summary are all wired there and nowhere else.
"""

import json
import re
from collections.abc import Sequence
from pathlib import Path
from xml.etree import ElementTree

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.calibration.report import MIN_RELIABLE_SAMPLES
from guardana.core.manifest.records import SuiteOutcome
from guardana.core.profile import Profile
from guardana.core.profile.model import Policy
from guardana.core.registry import Registry
from guardana.core.report import load_report
from guardana.core.target import ChatMessage
from guardana.report import get_renderer
from typer.testing import CliRunner

runner = CliRunner()

_SUITE_ID = "acme.quality.answers"
_HEADER = {"guardana_dataset": 1, "name": "answers", "version": "1"}
_REPLY = "The answer is 42."


class _Answering:
    """A model that answers every question, and a judge that passes every reply."""

    sent = 0

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        """Count the request and answer it."""
        type(self).sent += 1
        return "PASS: agrees" if "judge" in base_url else _REPLY


def _suite(
    tmp_path: Path,
    *,
    evaluator: str,
    expect: dict[str, object],
    cases: int = 30,
    min_sample: int = 30,
) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    lines = [json.dumps(_HEADER)] + [json.dumps({"input": f"Q{n}?"}) for n in range(cases)]
    (rules / "answers.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rule = {
        "id": _SUITE_ID,
        "title": "The assistant still answers",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM01:2025"],
        "evaluator": evaluator,
        "requires": ["chat"],
        "dataset": "./answers.jsonl",
        "expect": expect,
        "gate": {"min_pass_rate": 0.9, "min_sample": min_sample},
    }
    (rules / "answers.yaml").write_text(json.dumps(rule), encoding="utf-8")
    return rules


def _profile(tmp_path: Path, *extra: str) -> Path:
    path = tmp_path / "guardana.yaml"
    path.write_text("\n".join(["rules:", "  include: ['acme.*']", *extra]) + "\n", "utf-8")
    return path


def _probe(
    monkeypatch: pytest.MonkeyPatch, rules: Path, profile: Path, *extra: str
) -> tuple[int, str]:
    monkeypatch.setattr(endpoint_module, "transport_factory", _Answering)
    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://model.test",
            "--model",
            "m",
            "--rules",
            str(rules),
            "--profile",
            str(profile),
            *extra,
        ],
    )
    return result.exit_code, result.output


def test_a_probe_saves_what_the_suite_concluded_and_reads_it_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules = _suite(tmp_path, evaluator="contains", expect={"contains_all": ["42"]})
    out = tmp_path / "run.json"

    code, output = _probe(
        monkeypatch,
        rules,
        _profile(tmp_path),
        "--trials",
        "3",
        "--format",
        "json",
        "--output",
        str(out),
    )

    assert code == 0, output
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["schema_version"] == 18
    record = next(r for r in document["run"]["rules"] if r["id"] == _SUITE_ID)
    assert record["trial_summary"] is None
    assert record["suite"]["outcome"] == "pass"
    assert record["suite"]["trials_per_case"] == 3
    assert record["suite"]["cases"] == record["suite"]["measured"] == 30
    assert len([a for a in document["assessments"] if a["rule_id"] == _SUITE_ID]) == 90

    report = load_report(out)
    assert report.result.suites[_SUITE_ID].outcome is SuiteOutcome.PASS
    assert report.result.trials_per_case == {_SUITE_ID: 3}
    human = get_renderer("human", run=report.manifest).render(report.result)
    measured = human.split("Measured\n", 1)[1].splitlines()
    assert len(measured) >= 1
    assert measured[0].startswith(f"  {_SUITE_ID}  answers@1: 30 of 30 cases measured")
    assert "Trials" not in human
    inspected = runner.invoke(app, ["run", "inspect", str(out)])
    assert inspected.exit_code == 0, inspected.output


def test_the_terminal_report_measures_the_suite_and_leaves_it_out_of_trials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules = _suite(tmp_path, evaluator="contains", expect={"contains_all": ["42"]})

    code, output = _probe(monkeypatch, rules, _profile(tmp_path), "--trials", "2")

    assert code == 0, output
    assert f"Measured\n  {_SUITE_ID}  " in output
    assert "one attempt per case" not in output
    assert "Trials" not in output
    assert "ASR@" not in output


def _answered_corpus(tmp_path: Path) -> Path:
    """Thirty refusals labelled as the failure `answered` looks for, and thirty answers."""
    rows = [
        {
            "messages": [{"role": "assistant", "content": f"I can't help with request {i}."}],
            "expect": {},
            "attack_succeeded": True,
        }
        for i in range(MIN_RELIABLE_SAMPLES)
    ] + [
        {
            "messages": [{"role": "assistant", "content": f"Step {i} is as follows."}],
            "expect": {},
            "attack_succeeded": False,
        }
        for i in range(MIN_RELIABLE_SAMPLES)
    ]
    path = tmp_path / "answered.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_a_judged_suite_declines_without_a_calibration_and_concludes_with_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules = _suite(tmp_path, evaluator="answered", expect={})

    code, output = _probe(monkeypatch, rules, _profile(tmp_path))

    assert code == int(ExitCode.INDETERMINATE), output
    assert "declined: uncorrected" in output

    calibration = tmp_path / "cal.json"
    recorded = runner.invoke(
        app,
        [
            "calibrate",
            "--evaluator",
            "answered",
            "--corpus",
            str(_answered_corpus(tmp_path)),
            "--record",
            str(calibration),
        ],
    )
    assert recorded.exit_code == 0, recorded.output
    out = tmp_path / "run.json"

    code, output = _probe(
        monkeypatch,
        rules,
        _profile(tmp_path, f"calibrations: ['{calibration}']"),
        "--format",
        "json",
        "--output",
        str(out),
    )

    assert code == 0, output
    record = next(r for r in load_report(out).manifest.rules if r.id == _SUITE_ID)
    assert record.suite is not None
    assert record.suite.outcome is SuiteOutcome.PASS
    assert record.suite.correction.status == "corrected"
    evaluator = next(e for e in load_report(out).manifest.evaluators if e.id == "answered")
    assert evaluator.calibration is not None


def _junit(output: str) -> ElementTree.Element:
    document = output[output.index("<?xml") :].encode()
    return ElementTree.fromstring(document)  # noqa: S314 — our own output


def test_junit_writes_one_testcase_per_suite_in_place_of_its_finding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules = _suite(tmp_path, evaluator="contains", expect={"contains_all": ["43"]})

    code, output = _probe(monkeypatch, rules, _profile(tmp_path), "--format", "junit")

    assert code == int(ExitCode.POLICY_FAILED), output
    root = _junit(output)
    assert root.tag == "testsuite"
    cases = [c for c in root.iter("testcase") if c.get("name") == _SUITE_ID]
    assert len(cases) == 1
    assert cases[0].find("failure") is not None
    assert cases[0].find("system-out") is not None
    assert root.get("failures") == "1"


def test_junit_counts_a_declined_suite_as_an_error_not_a_skip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules = _suite(tmp_path, evaluator="answered", expect={})

    code, output = _probe(monkeypatch, rules, _profile(tmp_path), "--format", "junit")

    assert code == int(ExitCode.INDETERMINATE), output
    root = _junit(output)
    cases = [c for c in root.iter("testcase") if c.get("name") == _SUITE_ID]
    assert len(cases) == 1
    assert cases[0].find("error") is not None
    assert cases[0].find("skipped") is None
    erroring = [c for c in root.iter("testcase") if c.find("error") is not None]
    assert root.get("errors") == str(len(erroring))
    assert root.get("skipped") == "0"
    assert not [c for c in root.iter("testcase") if c.get("name") == "guardana.unverified"]


def test_the_plan_prices_a_suite_at_its_cases_times_its_trials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rules = _suite(tmp_path, evaluator="contains", expect={"contains_all": ["42"]})
    monkeypatch.setattr(endpoint_module, "transport_factory", _Answering)

    plan = runner.invoke(
        app,
        [
            "plan",
            "probe",
            "--url",
            "http://model.test",
            "--model",
            "m",
            "--rules",
            str(rules),
            "--profile",
            str(_profile(tmp_path)),
            "--trials",
            "3",
            "--format",
            "json",
        ],
    )

    assert plan.exit_code == 0, plan.output
    priced = json.loads(plan.output)
    assert priced["requests"]["max"] == 90


def test_a_judge_over_its_budget_stops_the_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Five cases send five requests; three judge samples each would take fifteen."""
    rules = _suite(tmp_path, evaluator="llm_judge", expect={"goal": "g"}, cases=5, min_sample=1)
    profile = _profile(
        tmp_path,
        "evaluators:",
        "  llm_judge: {endpoint: 'http://judge.test/v1', model: j, min_agreement: 3}",
    )
    _Answering.sent = 0
    out = tmp_path / "run.json"

    code, output = _probe(
        monkeypatch,
        rules,
        profile,
        "--max-requests",
        "10",
        "--format",
        "json",
        "--output",
        str(out),
    )

    assert code == int(ExitCode.BUDGET_EXHAUSTED), output
    assert _Answering.sent <= 5 + 10
    report = load_report(out)
    assert _SUITE_ID in report.result.suites
    assert _SUITE_ID not in report.result.trials_per_case


def test_reference_judge_is_registered_exactly_when_llm_judge_is_configured() -> None:
    bare, judged = Registry(), Registry()
    wire_config_evaluators(bare, Profile(name="t", policy=Policy()))
    wire_config_evaluators(
        judged,
        Profile(
            name="t",
            policy=Policy(),
            evaluator_config={"llm_judge": {"endpoint": "http://j/v1", "model": "j"}},
        ),
    )

    assert "reference_judge" not in bare.evaluators()
    assert {"llm_judge", "reference_judge"} <= set(judged.evaluators())
    identity = judged.evaluators()["reference_judge"].judge_identity
    assert identity == judged.evaluators()["llm_judge"].judge_identity
    assert identity is not None
    assert re.search(r"model=j; endpoint=\w+; samples=1", identity)


def test_rule_test_leaves_a_suite_out_of_the_corpus(tmp_path: Path) -> None:
    rules = _suite(tmp_path, evaluator="contains", expect={"contains_all": ["42"]})
    spec = json.loads((rules / "answers.yaml").read_text(encoding="utf-8"))
    spec["fixtures"] = [{"name": "answers", "reply": _REPLY, "outcome": "clean"}]
    (rules / "answers.yaml").write_text(json.dumps(spec), encoding="utf-8")
    corpus = tmp_path / "corpus.jsonl"

    result = runner.invoke(
        app, ["rule", "test", _SUITE_ID, "--rules", str(rules), "--write-corpus", str(corpus)]
    )

    assert "wrote 0 labelled sample(s)" in result.output, result.output
    assert "1 from a suite" in result.output
    assert corpus.read_text(encoding="utf-8") == ""


def test_a_monitor_gives_the_judge_a_fresh_budget_every_cycle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Each cycle sends three cases and nine judge samples, under a ceiling of ten."""
    rules = _suite(tmp_path, evaluator="llm_judge", expect={"goal": "g"}, cases=3, min_sample=1)
    profile = _profile(
        tmp_path,
        "budgets: {max_requests: 10}",
        "evaluators:",
        "  llm_judge: {endpoint: 'http://judge.test/v1', model: j, min_agreement: 3}",
    )
    monkeypatch.setattr(endpoint_module, "transport_factory", _Answering)
    _Answering.sent = 0

    result = runner.invoke(
        app,
        [
            "monitor",
            "--url",
            "http://model.test",
            "--model",
            "m",
            "--rules",
            str(rules),
            "--profile",
            str(profile),
            "--max-cycles",
            "2",
            "--interval",
            "0",
        ],
    )

    # Every cycle's suite declines for want of a calibrated judge, so the watch ends
    # indeterminate, as a probe of the same cycle would.
    assert result.exit_code == ExitCode.INDETERMINATE, result.output
    assert _Answering.sent == 2 * (3 + 9)
