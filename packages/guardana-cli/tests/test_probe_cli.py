from urllib.error import URLError

import guardana.cli._endpoint as endpoint_module
import pytest
from guardana.cli._probe_run import _needs_planted_canary, _with_random_canary
from guardana.cli.main import app
from guardana.core.evaluator.base import Expectation
from guardana.core.rule.base import RuleMeta
from guardana.core.rule.scenario_rule import ScenarioRule, ScenarioStep
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.testing import EchoingTransport, FailingTransport, RefusingTransport
from typer.testing import CliRunner

runner = CliRunner()

_TYPER_USAGE_ERROR = 2
_ENDPOINT_UNREACHABLE = 2


def _unreachable() -> FailingTransport:
    return FailingTransport(URLError("Connection refused"))


def test_probe_clean_model_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", RefusingTransport)

    result = runner.invoke(app, ["probe", "--url", "http://fake", "--model", "m"])

    assert result.exit_code == 0, result.output


def test_probe_leaking_canary_exits_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_module, "transport_factory", EchoingTransport)

    result = runner.invoke(app, ["probe", "--url", "http://fake", "--model", "m"])

    assert result.exit_code == 1, result.output
    assert "system_prompt_leak" in result.output


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

    assert _needs_planted_canary(rule) is True
    planted, canary = _with_random_canary(rule)

    assert canary.startswith("GUARDANA_CANARY_")
    assert canary != "STATIC_CANARY"
    assert isinstance(planted, ScenarioRule)
    assert planted.conversation_expect is not None
    assert planted.conversation_expect.canary == canary
