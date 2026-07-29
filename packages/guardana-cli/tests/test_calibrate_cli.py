"""`guardana calibrate`: the measurement, the corpus it reads, and the exit code.

The command exists so a confidence is a checked number rather than a claim. That
makes its failure modes the interesting part — a corpus that lost a line, a
measurement that did not happen, a rubric inheriting someone else's accuracy.
"""

import json
from pathlib import Path

import pytest
from guardana.cli.main import app
from guardana.core.calibration.corpus import CorpusError, bundled_corpus, dump_corpus, load_corpus
from guardana.core.calibration.report import MIN_RELIABLE_SAMPLES
from guardana.core.evaluator.base import Expectation
from guardana.core.evaluator.llm_judge import JudgeCalibration, LlmJudgeEvaluator
from guardana.core.exchange import Exchange
from typer.testing import CliRunner

runner = CliRunner()


def test_the_bundled_starter_corpus_loads_and_is_big_enough_to_mean_something() -> None:
    samples = load_corpus(bundled_corpus())

    assert len(samples) >= MIN_RELIABLE_SAMPLES
    assert {s.attack_succeeded for s in samples} == {True, False}, (
        "a corpus of one class cannot separate a good judge from a stuck one"
    )


def test_a_corpus_line_without_a_known_outcome_is_refused(tmp_path: Path) -> None:
    # Skipping it would quietly measure a different corpus than the author meant,
    # and the number would still look like a calibration.
    path = tmp_path / "corpus.jsonl"
    path.write_text(
        json.dumps({"messages": [{"role": "assistant", "content": "hi"}], "expect": {}}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(CorpusError, match="attack_succeeded"):
        load_corpus(path)


def test_a_malformed_line_names_the_line(tmp_path: Path) -> None:
    path = tmp_path / "corpus.jsonl"
    path.write_text("{ not json\n", encoding="utf-8")

    with pytest.raises(CorpusError, match=":1"):
        load_corpus(path)


def test_a_corpus_round_trips(tmp_path: Path) -> None:
    original = load_corpus(bundled_corpus())
    path = tmp_path / "again.jsonl"
    path.write_text(dump_corpus(original), encoding="utf-8")

    assert len(load_corpus(path)) == len(original)


def test_calibrate_measures_a_registered_evaluator() -> None:
    result = runner.invoke(app, ["calibrate", "--evaluator", "canary"])

    assert "Calibration of canary" in result.stdout
    assert "accuracy" in result.stdout


def test_calibrate_refuses_an_evaluator_nobody_configured() -> None:
    result = runner.invoke(app, ["calibrate", "--evaluator", "llm_judge"])

    assert result.exit_code != 0
    assert "no evaluator 'llm_judge'" in result.output


def test_an_unreliable_measurement_exits_nonzero(tmp_path: Path) -> None:
    # "We measured nothing" must not read as "we measured, and it was fine".
    path = tmp_path / "tiny.jsonl"
    path.write_text(dump_corpus(load_corpus(bundled_corpus())[:3]), encoding="utf-8")

    result = runner.invoke(app, ["calibrate", "--evaluator", "canary", "--corpus", str(path)])

    assert result.exit_code == 1
    assert "NOT RELIABLE" in result.stdout


def test_an_unmeasured_metric_renders_as_a_dash_not_a_zero(tmp_path: Path) -> None:
    # `keyword` grades every one of these, so use an evaluator that abstains:
    # `canary` on samples with no canary at all.
    rows = [
        {
            "messages": [{"role": "assistant", "content": "nothing to see"}],
            "expect": {},
            "attack_succeeded": False,
        }
    ] * MIN_RELIABLE_SAMPLES
    path = tmp_path / "abstain.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    result = runner.invoke(app, ["calibrate", "--evaluator", "canary", "--corpus", str(path)])

    assert result.exit_code == 1
    assert "accuracy      —" in result.stdout


def test_a_judge_without_a_calibration_says_its_confidence_is_raw() -> None:
    judge = LlmJudgeEvaluator(lambda prompt: "FAIL: it complied")

    verdict = judge.evaluate(Exchange.single_reply("sure"), Expectation(goal="g"))

    assert "raw sample agreement" in verdict.rationale


def test_a_calibrated_judge_cannot_claim_more_than_it_was_measured_at() -> None:
    calibration = JudgeCalibration(evaluator_id="llm_judge@2025.1", accuracy=0.6, samples=40)
    judge = LlmJudgeEvaluator(lambda prompt: "FAIL: it complied", calibration=calibration)

    verdict = judge.evaluate(Exchange.single_reply("sure"), Expectation(goal="g"))

    assert verdict.confidence == pytest.approx(0.6)
    assert "calibrated against 40" in verdict.rationale


def test_a_calibration_measured_for_another_rubric_is_not_inherited() -> None:
    stale = JudgeCalibration(evaluator_id="llm_judge@2024.9", accuracy=0.99, samples=40)
    judge = LlmJudgeEvaluator(lambda prompt: "FAIL: it complied", calibration=stale)

    verdict = judge.evaluate(Exchange.single_reply("sure"), Expectation(goal="g"))

    assert "raw agreement" in verdict.rationale
    assert verdict.confidence != pytest.approx(0.99)


def test_a_calibration_from_too_few_samples_is_refused() -> None:
    with pytest.raises(ValueError, match=str(MIN_RELIABLE_SAMPLES)):
        JudgeCalibration(evaluator_id="llm_judge@2025.1", accuracy=1.0, samples=3)
