"""`guardana calibrate`: the measurement, the corpus it reads, and the exit code.

The command exists so a confidence is a checked number rather than a claim. That
makes its failure modes the interesting part — a corpus that lost a line, a
measurement that did not happen, a rubric inheriting someone else's accuracy.
"""

import json
import re
from pathlib import Path
from urllib.error import HTTPError, URLError

import guardana.cli._endpoint as endpoint_module
import guardana.cli.calibrate as calibrate_module
import pytest
from guardana.cli._evaluators import wire_config_evaluators
from guardana.cli.calibrate import _record
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core import judge_error
from guardana.core.calibration import CalibrationReport
from guardana.core.calibration.corpus import CorpusError, bundled_corpus, dump_corpus, load_corpus
from guardana.core.calibration.report import MIN_RELIABLE_SAMPLES
from guardana.core.calibration.store import load_calibrations
from guardana.core.evaluator.base import Evaluator, Expectation, Verdict
from guardana.core.evaluator.config import _identity
from guardana.core.evaluator.keyword import KeywordEvaluator
from guardana.core.evaluator.llm_judge import JudgeCalibration, LlmJudgeEvaluator
from guardana.core.exchange import Exchange
from guardana.core.manifest.records import TrialSummary
from guardana.core.profile import Profile
from guardana.core.profile.errors import ProfileError
from guardana.core.profile.model import Policy
from guardana.core.registry import Registry
from guardana.core.target.connection import Connection, resolve_connection
from guardana.core.testing import FailingTransport, ScriptedTransport
from guardana.core.trials import clean_bound
from typer.testing import CliRunner, Result

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_JUDGE = "http://judge.test:8080/v1"


def plain(output: str) -> str:
    """An assertion on a Rich-rendered message is an assertion on the terminal's
    width unless the output is normalised."""
    return " ".join(_ANSI.sub("", output).replace("│", " ").split())


def test_the_bundled_starter_corpus_loads_and_is_big_enough_to_mean_something() -> None:
    samples = load_corpus(bundled_corpus())

    positives = sum(1 for s in samples if s.attack_succeeded)
    negatives = len(samples) - positives
    assert positives >= MIN_RELIABLE_SAMPLES, "sensitivity is measured over the positives alone"
    assert negatives >= MIN_RELIABLE_SAMPLES, "specificity is measured over the negatives alone"


def test_the_bundled_starter_corpus_does_not_flatter_a_refusal_phrase_grader() -> None:
    # A corpus whose every negative carries a stock refusal phrase, and whose every
    # positive lacks one, measures `keyword` as a perfect judge.
    samples = load_corpus(bundled_corpus())
    evaluator = KeywordEvaluator()
    verdicts = [(evaluator.evaluate(s.exchange, s.expectation), s) for s in samples]

    missed = sum(1 for v, s in verdicts if s.attack_succeeded and v.outcome == "pass")
    false_alarms = sum(1 for v, s in verdicts if not s.attack_succeeded and v.outcome == "fail")
    assert missed > 0
    assert false_alarms > 0


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
    assert "no evaluator 'llm_judge'" in plain(result.output)


def test_a_restrictive_plugin_mode_is_named_when_no_evaluator_loaded() -> None:
    """`--plugins disabled` used to leave `known: ` empty with no explanation, so
    a typo'd evaluator id and a refused plugin looked exactly the same failure.
    """
    result = runner.invoke(app, ["calibrate", "--evaluator", "keyword", "--plugins", "disabled"])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert "could not load evaluator" in plain(result.output)
    assert "plugin trust is disabled" in plain(result.output)
    assert "no evaluator 'keyword' is registered" in plain(result.output)


def test_an_unreliable_measurement_exits_nonzero(tmp_path: Path) -> None:
    # "We measured nothing" must not read as "we measured, and it was fine".
    path = tmp_path / "tiny.jsonl"
    path.write_text(dump_corpus(load_corpus(bundled_corpus())[:3]), encoding="utf-8")

    result = runner.invoke(app, ["calibrate", "--evaluator", "canary", "--corpus", str(path)])

    assert result.exit_code == ExitCode.INDETERMINATE
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

    assert result.exit_code == ExitCode.INDETERMINATE
    assert "accuracy      —" in result.stdout


def test_a_judge_without_a_calibration_says_its_confidence_is_raw() -> None:
    judge = LlmJudgeEvaluator(lambda prompt: "FAIL: it complied")

    verdict = judge.evaluate(Exchange.single_reply("sure"), Expectation(goal="g"))

    assert "raw sample agreement" in verdict.rationale


def test_a_calibrated_judge_cannot_claim_more_than_it_was_measured_at() -> None:
    calibration = JudgeCalibration(evaluator_id="llm_judge@2026.1", accuracy=0.6, samples=40)
    judge = LlmJudgeEvaluator(lambda prompt: "FAIL: it complied", calibration=calibration)

    verdict = judge.evaluate(Exchange.single_reply("sure"), Expectation(goal="g"))

    assert verdict.confidence == pytest.approx(0.6)
    assert "calibrated against 40" in verdict.rationale


@pytest.mark.parametrize("measured_for", ["llm_judge@2024.9", "llm_judge@2025.1"])
def test_a_calibration_measured_for_another_rubric_is_not_inherited(measured_for: str) -> None:
    stale = JudgeCalibration(evaluator_id=measured_for, accuracy=0.99, samples=40)
    judge = LlmJudgeEvaluator(lambda prompt: "FAIL: it complied", calibration=stale)

    verdict = judge.evaluate(Exchange.single_reply("sure"), Expectation(goal="g"))

    assert "raw agreement" in verdict.rationale
    assert verdict.confidence != pytest.approx(0.99)


def test_a_calibration_from_too_few_samples_is_refused() -> None:
    with pytest.raises(ValueError, match=str(MIN_RELIABLE_SAMPLES)):
        JudgeCalibration(evaluator_id="llm_judge@2025.1", accuracy=1.0, samples=3)


def _keyword_corpus(tmp_path: Path, positives: int, negatives: int) -> Path:
    """Labelled replies `keyword` grades without a mistake: refusals held, the rest complied."""
    rows = [
        {
            "messages": [{"role": "assistant", "content": f"Sure, step {i} is as follows."}],
            "expect": {"goal": "g"},
            "attack_succeeded": True,
        }
        for i in range(positives)
    ] + [
        {
            "messages": [{"role": "assistant", "content": f"I can't help with request {i}."}],
            "expect": {"goal": "g"},
            "attack_succeeded": False,
        }
        for i in range(negatives)
    ]
    path = tmp_path / "keyword.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_calibrate_states_the_assessor_the_judge_and_each_class() -> None:
    result = runner.invoke(app, ["calibrate", "--evaluator", "keyword"])

    lines = result.stdout.splitlines()
    assert "  assessor      keyword" in lines
    assert "  judge         not stated" in lines
    assert any(
        re.fullmatch(r"  positives     \d+ graded, 0 inconclusive, sensitivity 0\.\d{4}", line)
        for line in lines
    ), result.stdout
    assert any(
        re.fullmatch(r"  negatives     \d+ graded, 0 inconclusive, specificity 0\.\d{4}", line)
        for line in lines
    ), result.stdout
    assert (
        "  starter corpus: demonstration corpus; calibration can be recorded but cannot "
        "correct rates"
    ) in lines


def test_an_operator_corpus_is_not_called_the_starter(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["calibrate", "--evaluator", "keyword", "--corpus", str(_keyword_corpus(tmp_path, 30, 30))],
    )

    assert result.exit_code == 0, result.output
    assert "starter corpus" not in result.stdout
    assert "  positives     30 graded, 0 inconclusive, sensitivity 1.0000" in result.stdout


def test_a_class_measured_too_thinly_is_named_and_still_recorded(tmp_path: Path) -> None:
    destination = tmp_path / "cal.json"

    result = runner.invoke(
        app,
        [
            "calibrate",
            "--evaluator",
            "keyword",
            "--corpus",
            str(_keyword_corpus(tmp_path, 5, 40)),
            "--record",
            str(destination),
        ],
    )

    assert result.exit_code == 0, result.output
    assert (
        "  RATE CAVEAT: only 5 positives graded in calibration; 30 needed to measure sensitivity"
    ) in result.stdout
    entry = json.loads(destination.read_text(encoding="utf-8"))["calibrations"][0]
    assert (entry["positives"], entry["negatives"]) == (5, 40)


@pytest.mark.parametrize(("corpus", "starter"), [(False, True), (True, False)])
def test_a_recorded_calibration_carries_what_a_correction_matches_on(
    tmp_path: Path, corpus: bool, starter: bool
) -> None:
    destination = tmp_path / "cal.json"
    source = ["--corpus", str(_keyword_corpus(tmp_path, 30, 31))] if corpus else []

    result = runner.invoke(
        app, ["calibrate", "--evaluator", "keyword", *source, "--record", str(destination)]
    )

    assert result.exit_code == 0, result.output
    entry = json.loads(destination.read_text(encoding="utf-8"))["calibrations"][0]
    assert entry["assessor"] == "keyword"
    assert entry["starter_corpus"] is starter
    assert entry["judge_identity"] is None
    assert entry["positives"] + entry["negatives"] == entry["samples"]
    assert entry["positives_inconclusive"] == entry["negatives_inconclusive"] == 0
    assert 0.0 <= entry["sensitivity"] <= 1.0
    assert 0.0 <= entry["specificity"] <= 1.0
    if corpus:
        assert (entry["positives"], entry["negatives"]) == (30, 31)
        assert entry["sensitivity"] == entry["specificity"] == 1.0


def _judge_identity(**cfg: object) -> str | None:
    registry = Registry()
    profile = Profile(
        name="t", policy=Policy(), evaluator_config={"llm_judge": {"model": "j", **cfg}}
    )
    wire_config_evaluators(registry, profile)
    return registry.evaluators()["llm_judge"].judge_identity


def test_a_judge_identity_names_the_model_endpoint_and_samples() -> None:
    identity = _judge_identity(endpoint="https://judge.example/v1", min_agreement=3)

    assert identity is not None
    assert re.fullmatch(r"model=j; endpoint=[0-9a-f]{12}; samples=3", identity), identity


def test_a_judge_identity_changes_with_the_samples_and_the_host() -> None:
    base = _judge_identity(endpoint="https://judge.example/v1")

    assert base != _judge_identity(endpoint="https://judge.example/v1", min_agreement=2)
    assert base != _judge_identity(endpoint="https://other.example/v1")
    assert base != _judge_identity(endpoint="https://judge.example:8443/v1")


def test_two_spellings_of_one_endpoint_are_one_judge() -> None:
    assert _judge_identity(endpoint="HTTPS://Judge.Example/v1/") == _judge_identity(
        endpoint="https://judge.example:443/v1"
    )
    assert _judge_identity(endpoint="http://judge.example/v1") == _judge_identity(
        endpoint="http://judge.example:80/v1"
    )


def test_a_judge_identity_never_carries_credentials_or_a_query() -> None:
    def identity(endpoint: str) -> str:
        resolved = resolve_connection(Connection(endpoint, "j"), sending=False)
        return _identity({"model": "j", "endpoint": endpoint}, "llm_judge", resolved)

    plain_url = identity("https://judge.example/v1")
    secret = identity("https://user:hunter2@judge.example/v1?key=s3cr3t#frag")

    assert secret == plain_url
    assert secret is not None
    assert "hunter2" not in secret
    assert "s3cr3t" not in secret
    assert "judge.example" not in secret


def test_a_judge_endpoint_with_an_unreadable_port_is_a_profile_error() -> None:
    with pytest.raises(ProfileError, match="port"):
        _judge_identity(endpoint="https://judge.example:99999/v1")


def test_a_guard_states_its_model_and_endpoint() -> None:
    registry = Registry()
    guard = {"endpoint": "http://g/v1", "model": "llama-guard"}
    wire_config_evaluators(
        registry, Profile(name="t", policy=Policy(), evaluator_config={"guard": guard})
    )

    identity = registry.evaluators()["guard"].judge_identity
    assert identity is not None
    assert re.fullmatch(r"model=llama-guard; endpoint=[0-9a-f]{12}", identity), identity


def test_counts_pooled_over_several_assessors_are_not_recorded_as_one_judge(
    tmp_path: Path,
) -> None:
    report = CalibrationReport(
        evaluator_id="acme_judge",
        graded=60,
        inconclusive=0,
        accuracy=0.9,
        brier=0.1,
        expected_calibration_error=0.05,
        caveat="",
        assessor=None,
        assessor_caveat="the verdicts carried 2 assessor ids (a@1, a@2)",
        judge_identity=None,
        positives=30,
        negatives=30,
        positives_inconclusive=0,
        negatives_inconclusive=0,
        sensitivity=0.9,
        specificity=0.9,
        class_caveat="",
    )
    destination = tmp_path / "cal.json"

    _record(report, None, destination)

    entry = load_calibrations(destination)["acme_judge"]
    assert entry.samples == 60
    assert entry.assessor is None
    assert entry.positives is None
    assert entry.sensitivity is None
    assert entry.starter_corpus is True
    reason = judge_error.correct(
        TrialSummary(
            trials_per_case=1,
            cases=12,
            cases_failed=0,
            cases_incomplete=0,
            bound=clean_bound(12),
            mean_success_rate=0.0,
        ),
        judge_error.Grading(assessors=("acme_judge@1",), judges=("acme_judge@1",)),
        {"acme_judge": KeywordEvaluator()},
        {"acme_judge": entry.as_record()},
    ).reason
    assert reason is not None
    assert "several assessor ids" in reason, "a rerun cannot add counts this writer never keeps"
    assert "rerun" not in reason


def _judge_profile(tmp_path: Path, block: str = "llm_judge", endpoint: str = _JUDGE) -> Path:
    path = tmp_path / "guardana.yaml"
    path.write_text(
        f"name: t\nevaluators:\n  {block}:\n    endpoint: '{endpoint}'\n    model: judge\n",
        encoding="utf-8",
    )
    return path


def _judge_fails_with(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", lambda: FailingTransport(error))


def _rejected() -> HTTPError:
    return HTTPError(_JUDGE, 401, "Unauthorized", {}, None)  # type: ignore[arg-type]


def _one_error_line(result: Result) -> str:
    """The single line a failed command owes its reader, with no traceback behind it."""
    assert isinstance(result.exception, SystemExit), result.exception
    assert "Traceback" not in result.output
    errors = [line for line in result.stderr.splitlines() if not line.startswith("warning: ")]
    assert len(errors) == 1, result.stderr
    assert errors[0].startswith("error: "), result.stderr
    return errors[0]


@pytest.mark.parametrize(
    ("error", "said"),
    [
        (_rejected(), f"endpoint {_JUDGE} (evaluators.llm_judge) rejected the request (HTTP 401)"),
        (
            HTTPError(_JUDGE, 429, "Too Many Requests", {}, None),  # type: ignore[arg-type]
            f"endpoint {_JUDGE} (evaluators.llm_judge) kept rate-limiting the judge (HTTP 429) "
            "even after retries — wait for its quota to reset",
        ),
        (
            HTTPError(_JUDGE, 503, "Unavailable", {}, None),  # type: ignore[arg-type]
            f"endpoint {_JUDGE} (evaluators.llm_judge) returned HTTP 503",
        ),
        (
            URLError("connection refused"),
            f"could not reach endpoint {_JUDGE} (evaluators.llm_judge)",
        ),
    ],
)
def test_a_judge_that_cannot_be_used_is_an_unavailable_endpoint_in_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception, said: str
) -> None:
    _judge_fails_with(monkeypatch, error)

    result = runner.invoke(app, ["calibrate", "--profile", str(_judge_profile(tmp_path))])

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    assert said in _one_error_line(result)


def test_advice_for_a_rejected_judge_names_no_flag_calibrate_lacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _judge_fails_with(monkeypatch, _rejected())

    result = runner.invoke(app, ["calibrate", "--profile", str(_judge_profile(tmp_path))])

    line = _one_error_line(result)
    assert "--adapter" not in line
    assert "--api-key-env" not in line
    assert "--concurrency" not in line


def test_a_failed_judge_leaves_the_calibration_file_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _judge_fails_with(monkeypatch, _rejected())
    fresh = tmp_path / "fresh.json"
    kept = tmp_path / "kept.json"
    kept.write_text("recorded earlier\n", encoding="utf-8")
    profile = str(_judge_profile(tmp_path))

    for destination in (fresh, kept):
        result = runner.invoke(
            app, ["calibrate", "--profile", profile, "--record", str(destination)]
        )
        assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output

    assert not fresh.exists()
    assert kept.read_text(encoding="utf-8") == "recorded earlier\n"


def test_the_guard_is_named_by_its_own_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _judge_fails_with(monkeypatch, _rejected())

    result = runner.invoke(
        app,
        ["calibrate", "--evaluator", "guard", "--profile", str(_judge_profile(tmp_path, "guard"))],
    )

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    assert f"endpoint {_JUDGE} (evaluators.guard) rejected" in _one_error_line(result)


def test_a_judge_endpoint_carrying_credentials_is_refused_without_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _judge_profile(tmp_path, endpoint="http://user:hunter2@judge.test:8080/v1?key=s3cr3t")

    with _rejected() as rejected:
        _judge_fails_with(monkeypatch, rejected)
        result = runner.invoke(app, ["calibrate", "--profile", str(profile)])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    line = _one_error_line(result)
    assert line.startswith("error: evaluators.llm_judge.endpoint "), line
    assert "hunter2" not in result.output
    assert "s3cr3t" not in result.output


class _NetworkedPlugin(Evaluator):
    """A third-party grader that calls a model of its own, configured where Guardana cannot see."""

    id = "acme.remote_judge"

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        raise URLError("connection refused")


def test_a_plugin_judge_that_cannot_be_reached_is_named_by_its_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def wire(registry: Registry, profile: Profile, budgets: object = None) -> None:
        registry.register_evaluator(_NetworkedPlugin())

    monkeypatch.setattr(calibrate_module, "wire_config_evaluators", wire)

    result = runner.invoke(app, ["calibrate", "--evaluator", "acme.remote_judge"])

    assert result.exit_code == ExitCode.TARGET_UNAVAILABLE, result.output
    assert "could not reach endpoint of evaluator 'acme.remote_judge'" in _one_error_line(result)


@pytest.mark.parametrize(
    ("ceiling", "stopped"), [(2, True), (100_000, False)], ids=["stops", "fits"]
)
def test_a_calibration_the_budget_stops_exits_6_and_records_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, ceiling: int, stopped: bool
) -> None:
    judge = ScriptedTransport('{"verdict": "pass", "confidence": 0.9}')
    monkeypatch.setattr(endpoint_module, "transport_factory", lambda: judge)
    profile = _judge_profile(tmp_path)
    profile.write_text(
        profile.read_text(encoding="utf-8") + f"budgets:\n  max_requests: {ceiling}\n",
        encoding="utf-8",
    )
    record = tmp_path / "calibrations.json"

    result = runner.invoke(app, ["calibrate", "--profile", str(profile), "--record", str(record)])

    assert len(judge.seen) <= ceiling
    if stopped:
        assert result.exit_code == ExitCode.BUDGET_EXHAUSTED, result.output
        assert "nothing was measured or recorded" in plain(result.output)
        assert not record.exists()
    else:
        assert result.exit_code != ExitCode.BUDGET_EXHAUSTED, result.output
        assert len(judge.seen) > 2, "the judge was asked past the ceiling that stops the other case"


@pytest.mark.parametrize("bar", ["nan", "inf", "-0.1", "1.5"])
def test_a_max_ece_outside_zero_to_one_is_refused_before_anything_is_graded(
    bar: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    graded: list[object] = []
    monkeypatch.setattr(calibrate_module, "calibrate", lambda *a: graded.append(a))

    result = runner.invoke(app, ["calibrate", "--evaluator", "keyword", "--max-ece", bar])

    assert result.exit_code == ExitCode.INVALID_USAGE, result.output
    assert graded == []


@pytest.mark.parametrize("bar", ["0", "1"])
def test_the_bounds_of_max_ece_are_accepted(bar: str) -> None:
    result = runner.invoke(app, ["calibrate", "--evaluator", "keyword", "--max-ece", bar])

    assert result.exit_code != ExitCode.INVALID_USAGE, result.output
