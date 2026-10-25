"""A suite runs its dataset through the runner and gates on what it measured.

Each test writes a rule file and a dataset beside it, as an author would, and reads the
result where a pipeline reads it: the findings, the unverified channel, the conclusion
the runner carried and the gate's three answers.
"""

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml
from _yaml_input_cases import NON_TEXT_KEYS
from guardana.core.evaluator.keyword import KeywordEvaluator
from guardana.core.evaluator.length import LengthEvaluator
from guardana.core.gate import GateOutcome, gate_outcome
from guardana.core.manifest.records import (
    CalibrationRecord,
    CorrectionStatus,
    SuiteOutcome,
)
from guardana.core.profile import Policy, Profile
from guardana.core.profile.model import FailOn
from guardana.core.registry import Registry
from guardana.core.report import ScanResult
from guardana.core.rule import RuleContext
from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.suite_rule import SuiteRule
from guardana.core.rule.verify import FixtureVerdict, verify_rule
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.runner import Runner
from guardana.core.target import EndpointTarget
from guardana.core.testing import ScriptedTransport

_SHORT = "Open Settings and follow the reset link."
_LONG = "x" * 5000
_REFUSE = "I cannot help with that."
_HEADER = {"guardana_dataset": 1, "name": "support", "version": "2026.09"}


def _suite_yaml(**overrides: object) -> str:
    rule: dict[str, object] = {
        "id": "acme.quality.support",
        "title": "The support bot still answers",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM01:2025"],
        "evaluator": "length",
        "requires": ["chat"],
        "dataset": "./support.jsonl",
        "gate": {"min_pass_rate": 0.9, "min_sample": 30},
    }
    rule.update(overrides)
    return json.dumps(rule)


def _dataset(path: Path, cases: int = 30, **extra: object) -> None:
    lines = [json.dumps(_HEADER)]
    lines += [json.dumps({"input": f"Question {n}?", **extra}) for n in range(cases)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _load(tmp_path: Path, cases: int = 30, **overrides: object) -> SuiteRule:
    return _load_declared(tmp_path, overrides, cases)


def _load_declared(tmp_path: Path, overrides: dict[str, object], cases: int = 30) -> SuiteRule:
    _dataset(tmp_path / "support.jsonl", cases)
    (tmp_path / "suite.yaml").write_text(_suite_yaml(**overrides), encoding="utf-8")
    rule = load_yaml_rules(tmp_path / "suite.yaml")[0]
    if not isinstance(rule, SuiteRule):
        raise TypeError(type(rule).__name__)
    return rule


def _run(
    rule: SuiteRule,
    *replies: str,
    calibrations: dict[str, CalibrationRecord] | None = None,
) -> tuple[ScanResult, ScriptedTransport]:
    registry = Registry()
    registry.register_rule(rule)
    registry.register_evaluator(LengthEvaluator())
    registry.register_evaluator(KeywordEvaluator())
    transport = ScriptedTransport(*replies)
    target = EndpointTarget("http://model.test", "m", transport=transport)
    runner = Runner(
        registry=registry, profile=Profile("t", Policy()), calibrations=calibrations or {}
    )
    return runner.run(target), transport


def test_a_suite_whose_cases_pass_yields_nothing_and_concludes_pass(tmp_path: Path) -> None:
    rule = _load(tmp_path)
    result, transport = _run(rule, _SHORT)
    assert result.findings == ()
    assert result.unverified == ()
    summary = result.suites["acme.quality.support"]
    assert summary.outcome is SuiteOutcome.PASS
    assert summary.dataset == "support@2026.09"
    assert summary.measured == 30
    assert len(transport.seen) == 30
    assert {a.dataset for a in result.assessments} == {"support@2026.09"}
    assert all(a.passed for a in result.assessments)
    assert gate_outcome(result, Policy()) is GateOutcome.PASS


def test_a_suite_under_its_bar_yields_one_finding_about_the_rate(tmp_path: Path) -> None:
    rule = _load(tmp_path)
    result, _ = _run(rule, *([_SHORT] * 20 + [_LONG] * 10))
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity.name == "HIGH"
    assert finding.verdict is not None
    assert finding.verdict.outcome == "fail"
    assert finding.verdict.confidence == 1.0
    assert "below the bar" in finding.evidence.summary
    assert finding.evidence.detail.count("acme.quality.support#") == 3
    assert result.suites["acme.quality.support"].outcome is SuiteOutcome.FAIL
    assert gate_outcome(result, Policy()) is GateOutcome.FAIL


def test_a_suite_that_declines_blocks_the_gate_with_no_switch_in_front(tmp_path: Path) -> None:
    """A second suite concludes, so only the declined suite's own demand keeps this from passing."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    declining = _load(tmp_path / "a")
    concluding = _load(tmp_path / "b", id="acme.quality.other")
    registry = Registry()
    registry.register_rule(declining)
    registry.register_rule(concluding)
    registry.register_evaluator(LengthEvaluator())
    transport = ScriptedTransport(*([""] * 30 + [_SHORT]))
    target = EndpointTarget("http://model.test", "m", transport=transport)
    result = Runner(registry=registry, profile=Profile("t", Policy())).run(target)
    assert result.findings == ()
    assert len(result.unverified) == 1
    assert result.suites["acme.quality.support"].outcome is SuiteOutcome.INCONCLUSIVE
    assert result.suites["acme.quality.other"].outcome is SuiteOutcome.PASS
    assert not result.verified_nothing
    assert not Policy().fail_on.fail_on_inconclusive
    assert gate_outcome(result, Policy()) is GateOutcome.INDETERMINATE


def test_a_judge_graded_suite_declines_without_a_calibration_and_corrects_with_one(
    tmp_path: Path,
) -> None:
    rule = _load(tmp_path, evaluator="keyword", gate={"min_pass_rate": 0.8, "min_sample": 30})
    uncalibrated, _ = _run(rule, _REFUSE)
    summary = uncalibrated.suites["acme.quality.support"]
    assert summary.outcome is SuiteOutcome.INCONCLUSIVE
    assert summary.reason == (
        "uncorrected — judge error not measured: no calibration recorded for keyword"
    )
    calibration = CalibrationRecord(
        dataset_digest="sha256:" + "ab" * 32,
        assessor="keyword",
        starter_corpus=False,
        positives=30,
        negatives=30,
        positives_inconclusive=0,
        negatives_inconclusive=0,
        sensitivity=27 / 30,
        specificity=28 / 30,
    )
    calibrated, _ = _run(rule, *([_REFUSE] * 29 + ["Sure."]), calibrations={"keyword": calibration})
    corrected = calibrated.suites["acme.quality.support"]
    assert corrected.correction.status is CorrectionStatus.CORRECTED
    assert corrected.outcome is SuiteOutcome.PASS


def test_a_repeating_suite_sends_every_case_k_times(tmp_path: Path) -> None:
    rule = _load(tmp_path).with_trials(3)
    assert isinstance(rule, SuiteRule)
    assert rule.estimated_requests == 90
    result, transport = _run(rule, _SHORT)
    assert len(transport.seen) == 90
    assert result.suites["acme.quality.support"].trials_per_case == 3
    assert {a.trial for a in result.assessments} == {1, 2, 3}


def test_a_sample_is_the_same_cases_for_the_same_seed_and_is_tagged(tmp_path: Path) -> None:
    first = _load(tmp_path, cases=60, sample={"size": 30, "seed": 7})
    again = _load(tmp_path, cases=60, sample={"size": 30, "seed": 7})
    other = _load(tmp_path, cases=60, sample={"size": 30, "seed": 8})
    ids = [case.case_id for case in first.cases]
    assert len(ids) == 30
    assert ids == [case.case_id for case in again.cases]
    assert ids != [case.case_id for case in other.cases]
    assert all("sample:7" in case.tags for case in first.cases)
    assert first.sample == (30, 7)
    whole = _load(tmp_path, cases=30, sample={"size": 40, "seed": 7})
    assert whole.sample is None
    assert all(not case.tags for case in whole.cases)


def test_a_changed_suite_level_expectation_changes_every_case_id(tmp_path: Path) -> None:
    """Two runs graded against different yardsticks must never pair as the same cases."""
    before = _load(tmp_path, evaluator="keyword")
    after = _load(tmp_path, evaluator="keyword", expect={"goal": "a different goal"})
    assert not {c.case_id for c in before.cases} & {c.case_id for c in after.cases}


def test_a_teams_own_suite_loads_without_a_framework_mapping(tmp_path: Path) -> None:
    declared = json.loads(_suite_yaml())
    del declared["taxonomy"]
    _dataset(tmp_path / "support.jsonl")
    (tmp_path / "suite.yaml").write_text(json.dumps(declared), encoding="utf-8")

    rule = load_yaml_rules(tmp_path / "suite.yaml")[0]

    assert isinstance(rule, SuiteRule)
    assert rule.meta.taxonomy == ()


def test_the_digest_follows_the_dataset_file(tmp_path: Path) -> None:
    before = _load(tmp_path).digest()
    _dataset(tmp_path / "support.jsonl", 31)
    after = load_yaml_rules(tmp_path / "suite.yaml")[0].digest()
    assert before != after


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"gate": None}, "a suite needs 'gate' with 'min_pass_rate'"),
        ({"gate": {"min_pass_rate": 0.9, "min_sample": 31}}, "could never conclude"),
        (
            {"gate": {"min_pass_rate": 0.9, "min_sample": 30}, "sample": {"size": 20, "seed": 1}},
            "could never conclude",
        ),
        ({"gate": {"min_pass_rate": 0}}, "min_pass_rate must lie in (0, 1]"),
        ({"gate": {"min_pass_rate": 0.9, "floor": 1}}, "unknown gate field(s): floor"),
        ({"sample": {"size": 10}}, "sample.seed must be a whole number"),
        ({"expect": {"canary": "X"}}, "a suite plants no canary"),
        ({"prompts": ["a"]}, "unknown rule field(s): prompts"),
        ({"dataset": "https://example.test/d.jsonl"}, "invalid rule in"),
    ],
)
def test_a_suite_that_could_not_mean_what_it_says_fails_at_load(
    tmp_path: Path, overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(RuleLoadError) as caught:
        _load_declared(tmp_path, overrides)
    assert message in str(caught.value)


def test_the_same_case_twice_is_refused_naming_both_lines(tmp_path: Path) -> None:
    lines = [json.dumps(_HEADER)] + [json.dumps({"input": f"Q{n}"}) for n in range(30)]
    lines.append(json.dumps({"input": "Q3"}))
    (tmp_path / "support.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (tmp_path / "suite.yaml").write_text(_suite_yaml(), encoding="utf-8")
    with pytest.raises(RuleLoadError, match="dataset lines 5 and 32 are the same case"):
        load_yaml_rules(tmp_path / "suite.yaml")


def test_fixtures_sample_both_sides_of_the_bar_over_their_own_dataset(tmp_path: Path) -> None:
    passing = [json.dumps(_HEADER)] + [
        json.dumps({"input": f"F{n}", "reply": _SHORT}) for n in range(30)
    ]
    mixed = [json.dumps(_HEADER)] + [
        json.dumps({"input": f"F{n}", "reply": _SHORT if n < 20 else _LONG}) for n in range(30)
    ]
    (tmp_path / "pass.jsonl").write_text("\n".join(passing) + "\n", encoding="utf-8")
    (tmp_path / "mixed.jsonl").write_text("\n".join(mixed) + "\n", encoding="utf-8")
    rule = _load(
        tmp_path,
        fixtures=[
            # The failing sample first: a clean one after it over the same cases must not
            # inherit its grades from a context the two share.
            {"name": "a third run long", "dataset": "./mixed.jsonl", "outcome": "finding"},
            {"name": "all short", "dataset": "./pass.jsonl", "outcome": "clean"},
            {"name": "silent model", "reply": "", "outcome": "inconclusive"},
        ],
    )
    verification = verify_rule(rule, RuleContext(evaluators={"length": LengthEvaluator()}))
    assert [r.verdict for r in verification.results] == [FixtureVerdict.PASSED] * 3
    assert verification.is_proven


def test_a_fixture_dataset_too_small_for_the_gate_is_refused(tmp_path: Path) -> None:
    small = [json.dumps(_HEADER), json.dumps({"input": "F", "reply": _SHORT})]
    (tmp_path / "small.jsonl").write_text("\n".join(small) + "\n", encoding="utf-8")
    with pytest.raises(RuleLoadError, match="so the sample could only decline"):
        _load(
            tmp_path,
            fixtures=[{"name": "tiny", "dataset": "./small.jsonl", "outcome": "clean"}],
        )


def test_a_reply_in_the_suite_dataset_itself_is_refused(tmp_path: Path) -> None:
    lines = [json.dumps(_HEADER)] + [
        json.dumps({"input": f"Q{n}", "reply": "x"}) for n in range(30)
    ]
    (tmp_path / "support.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (tmp_path / "suite.yaml").write_text(_suite_yaml(), encoding="utf-8")
    with pytest.raises(RuleLoadError, match="reply"):
        load_yaml_rules(tmp_path / "suite.yaml")


def test_a_failed_suite_fails_the_run_whatever_its_severity(tmp_path: Path) -> None:
    """A worse measurement must never get a greener exit than a suite that declined."""
    rule = _load(tmp_path, severity="medium")
    failed, _ = _run(rule, _LONG)
    assert failed.suites["acme.quality.support"].outcome is SuiteOutcome.FAIL
    assert Policy().fail_on.severity.name == "HIGH"
    assert gate_outcome(failed, Policy()) is GateOutcome.FAIL
    declined, _ = _run(rule, "")
    assert gate_outcome(declined, Policy()) is GateOutcome.INDETERMINATE


def test_a_suite_that_raised_declines_and_no_error_switch_passes_it(tmp_path: Path) -> None:
    rule = _load(tmp_path, evaluator="exact_match", expect={"reference": "Open Settings."})
    registry = Registry()
    registry.register_rule(rule)
    target = EndpointTarget("http://model.test", "m", transport=ScriptedTransport(_SHORT))
    lenient = Profile("t", Policy(fail_on=FailOn(fail_on_error=False)))
    result = Runner(registry=registry, profile=lenient).run(target)
    assert len(result.errors) == 1
    summary = result.suites["acme.quality.support"]
    assert summary.outcome is SuiteOutcome.INCONCLUSIVE
    assert summary.reason is not None
    assert summary.reason.startswith("suite did not finish: RuleLoadError")
    assert gate_outcome(result, lenient.policy) is GateOutcome.INDETERMINATE


def test_a_waiver_on_a_suites_finding_is_honoured_by_the_gate(tmp_path: Path) -> None:
    rule = _load(tmp_path)
    failed, _ = _run(rule, _LONG)
    accepted = replace(failed, findings=(), waived=failed.findings)
    assert gate_outcome(accepted, Policy()) is GateOutcome.PASS
    assert gate_outcome(failed, Policy()) is GateOutcome.FAIL


@pytest.mark.parametrize("section", ["suite", "gate", "sample", "fixture"])
@pytest.mark.parametrize("mixed", [False, True])
@pytest.mark.parametrize(("key", "shown"), NON_TEXT_KEYS)
def test_non_text_suite_keys_raise_ruleloaderror(
    tmp_path: Path,
    section: str,
    mixed: bool,
    key: str,
    shown: str,
) -> None:
    _dataset(tmp_path / "support.jsonl")
    _dataset(tmp_path / "fixture.jsonl", reply="A short answer.")

    document: dict[str, Any] = json.loads(_suite_yaml())
    document["sample"] = {"size": 30, "seed": 1}
    document["fixtures"] = [
        {
            "name": "sample",
            "dataset": "./fixture.jsonl",
            "outcome": "clean",
        }
    ]

    extra: dict[Any, Any] = yaml.safe_load(f"{key}: ignored\n")
    if mixed:
        extra["unrecognised"] = "ignored"

    blocks = {
        "suite": document,
        "gate": document["gate"],
        "sample": document["sample"],
        "fixture": document["fixtures"][0],
    }
    blocks[section].update(extra)

    path = tmp_path / "suite.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(RuleLoadError, match="unknown") as caught:
        load_yaml_rules(path)

    prefix = f"invalid rule in {path}: "
    assert str(caught.value).startswith(prefix)
    assert shown in str(caught.value).removeprefix(prefix)
