from pathlib import Path
from urllib.error import URLError

import guardana.cli._endpoint as endpoint_module
import guardana.cli._probe_run as probe_run_module
import pytest
from guardana.cli._probe_run import _with_random_canary
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import app
from guardana.core.evaluator.base import Expectation
from guardana.core.gate import GateOutcome
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.report import load_report
from guardana.core.rule.base import RuleMeta
from guardana.core.rule.scenario_rule import ScenarioRule, ScenarioStep
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.testing import (
    EchoingTransport,
    FailingTransport,
    RefusingTransport,
    ScriptedTransport,
)
from typer.testing import CliRunner

runner = CliRunner()

_TYPER_USAGE_ERROR = int(ExitCode.INVALID_USAGE)
"""Argument-parsing errors use Guardana's invalid-usage code, not Click's default."""
_ENDPOINT_UNREACHABLE = 4


def _unreachable() -> FailingTransport:
    return FailingTransport(URLError("Connection refused"))


def test_probe_clean_model_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)

    result = runner.invoke(app, ["probe", "--url", "http://fake", "--model", "m"])

    assert result.exit_code == 0, result.output


def test_probe_concurrency_flag_reaches_the_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)
    seen: list[int] = []

    def recording_runner(*, registry: Registry, profile: Profile, concurrency: int = 1) -> Runner:
        seen.append(concurrency)
        return Runner(registry=registry, profile=profile, concurrency=concurrency)

    monkeypatch.setattr(probe_run_module, "Runner", recording_runner)
    result = runner.invoke(
        app, ["probe", "--url", "http://fake", "--model", "m", "--concurrency", "3"]
    )

    assert result.exit_code == 0, result.output
    assert seen
    assert set(seen) == {3}


def test_probe_rejects_a_nonsense_concurrency(monkeypatch: pytest.MonkeyPatch) -> None:
    # A limit of zero would mean "run nothing" — a scan that verified nothing while
    # exiting cleanly is the fail-open this project refuses.
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)

    result = runner.invoke(
        app, ["probe", "--url", "http://fake", "--model", "m", "--concurrency", "0"]
    )

    assert result.exit_code == _TYPER_USAGE_ERROR, result.output


def test_probe_leaking_canary_exits_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", EchoingTransport)

    result = runner.invoke(app, ["probe", "--url", "http://fake", "--model", "m"])

    assert result.exit_code == 1, result.output
    assert "system_prompt_leak" in result.output


def test_probe_of_a_model_that_answers_nothing_exits_indeterminate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An endpoint replying with an empty message to everything verified nothing.

    Not a hypothetical: a rate-limited gateway, a content filter and a wrong model
    name all produce it. Every rule runs, every evaluator declines for want of a
    reply, and the run used to print "0 finding(s)", exit `0`, and record `gate:
    pass` in a document a collector then stores.
    """
    monkeypatch.setattr(endpoint_module, "transport_factory", lambda: ScriptedTransport(""))
    saved = tmp_path / "run.json"

    result = runner.invoke(
        app,
        [
            "probe",
            "--url",
            "http://fake",
            "--model",
            "m",
            "--format",
            "json",
            "--output",
            str(saved),
        ],
    )

    assert result.exit_code == int(ExitCode.INDETERMINATE), result.output
    report = load_report(saved)
    assert report.result.findings == ()
    assert report.result.unverified, "the checks must still be reported, not just counted"
    # The verdict outlives the process: a collector reads this document, and `pass`
    # is what it used to store about a run that established nothing.
    assert report.manifest.result_summary.gate is GateOutcome.INDETERMINATE


def test_probe_rejects_invalid_format(monkeypatch: pytest.MonkeyPatch) -> None:
    # Stub the transport so a validation regression can't fall through to a real
    # network call and make this test pass for the wrong reason.
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)

    result = runner.invoke(
        app, ["probe", "--url", "http://fake", "--model", "m", "--format", "bogus"]
    )

    assert result.exit_code == _TYPER_USAGE_ERROR, result.output
    assert "Traceback" not in result.output


def test_probe_unreachable_endpoint_exits_two_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", _unreachable)

    result = runner.invoke(app, ["probe", "--url", "http://fake", "--model", "m"])

    assert result.exit_code == _ENDPOINT_UNREACHABLE, result.output
    assert "Traceback" not in result.output
    assert "could not reach endpoint" in result.output


def _canary_scenario() -> ScenarioRule:
    meta = RuleMeta(
        id="acme.scenario.leak",
        title="scenario leak",
        severity=Severity.CRITICAL,
        target_kind=TargetKind.ENDPOINT,
        required_capabilities=frozenset({Capability.CHAT, Capability.PLANT_SYSTEM_PROMPT}),
    )
    return ScenarioRule(
        meta=meta,
        steps=(ScenarioStep(send="hi"),),
        conversation_evaluator="canary",
        conversation_expect=Expectation(canary="STATIC_CANARY"),
    )


def test_scenario_canary_rule_is_recognised_and_gets_a_fresh_canary_planted() -> None:
    # A ScenarioRule canary rule used to be routed to the un-planted pass, where its
    # canary was never set and it passed a fully-leaky model. It must be recognised
    # as needing planting and get a fresh random canary swapped into its grade.
    rule = _canary_scenario()

    prepared = _with_random_canary(rule)
    assert prepared is not None, "a scenario canary rule must be routed to the planted pass"
    planted, canary = prepared

    assert canary.startswith("GUARDANA_CANARY_")
    assert canary != "STATIC_CANARY"
    assert isinstance(planted, ScenarioRule)
    assert planted.conversation_expect is not None
    assert planted.conversation_expect.canary == canary


def test_probe_saves_a_run_a_comparison_can_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The dynamic half of `--output`, which is where the interesting comparisons live.

    Probe assembles its result from several runner passes (one per planted canary),
    so the plan a saved run records has to survive that merge — if it did not, every
    dynamic comparison would start by reporting most of its rules as never having run.
    """
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)
    out = tmp_path / "run.json"

    argv = ["probe", "--url", "http://fake", "--model", "m", "--format", "json"]
    result = runner.invoke(app, [*argv, "--output", str(out)])

    assert result.exit_code == 0, result.output
    report = load_report(out)
    assert report.manifest.target.kind == TargetKind.ENDPOINT
    assert report.manifest.target.ref == "http://fake#m"
    assert report.manifest.rules, "a probe that ran rules must record which"
    assert all(len(rule.digest) == 16 for rule in report.manifest.rules)


def test_two_probe_runs_of_the_same_model_compare_as_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A canary is planted fresh every run, so two runs are never byte-identical."""
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    argv = ["probe", "--url", "http://fake", "--model", "m", "--format", "json"]
    for path in (first, second):
        runner.invoke(app, [*argv, "--output", str(path)])

    assert runner.invoke(app, ["diff", str(first), str(second)]).exit_code == 0
