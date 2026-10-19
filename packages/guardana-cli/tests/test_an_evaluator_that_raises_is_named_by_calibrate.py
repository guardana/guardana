"""`guardana calibrate` names an evaluator that raises while grading instead of blaming itself."""

import re
from pathlib import Path

import guardana.cli.calibrate as calibrate_module
import pytest
import typer
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import main
from guardana.core.evaluator.base import Evaluator, Expectation, Verdict
from guardana.core.evaluator.guard import GuardEvaluator
from guardana.core.exchange import Exchange
from guardana.core.profile import Profile
from guardana.core.registry import Registry

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_ID = "acme.broken_grader"


class _BrokenGrader(Evaluator):
    """A third-party grader whose own code fails on every sample."""

    id = _ID

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        raise RuntimeError("grader state was never initialised")


def _calibrate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> tuple[object, str]:
    def wire(registry: Registry, profile: Profile, budgets: object = None) -> None:
        registry.register_evaluator(_BrokenGrader())

    monkeypatch.delenv("GUARDANA_DEBUG", raising=False)
    monkeypatch.setattr(calibrate_module, "wire_config_evaluators", wire)
    with pytest.raises(SystemExit) as stopped:
        main(["calibrate", "--evaluator", _ID])
    said = " ".join(_ANSI.sub("", capsys.readouterr().err).split())
    return stopped.value.code, said


def test_an_evaluator_that_raises_while_grading_ends_the_run_as_an_internal_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, said = _calibrate(monkeypatch, capsys)

    assert code == ExitCode.INTERNAL_ERROR, said
    assert "RuntimeError" in said


def test_an_evaluator_that_raises_while_grading_is_named_and_not_called_a_guardana_defect(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _code, said = _calibrate(monkeypatch, capsys)

    assert _ID in said, said
    assert "Guardana defect" not in said, said


def test_a_failure_of_the_calibration_itself_is_still_reported_as_a_guardana_defect(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken_measurement(evaluator: Evaluator, samples: object) -> None:
        raise ZeroDivisionError("the measurement itself failed")

    monkeypatch.setattr(calibrate_module, "calibrate", broken_measurement)
    code, said = _calibrate(monkeypatch, capsys)

    assert code == ExitCode.INTERNAL_ERROR, said
    assert "Guardana defect" in said, said
    assert _ID not in said, said


def test_a_judge_built_from_the_profile_that_raises_is_reported_as_a_guardana_defect(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def classify(text: str) -> str:
        raise RuntimeError("guard reply was never parsed")

    def wire(registry: Registry, profile: Profile, budgets: object = None) -> None:
        registry.register_evaluator(GuardEvaluator(classify))

    monkeypatch.delenv("GUARDANA_DEBUG", raising=False)
    monkeypatch.setattr(calibrate_module, "wire_config_evaluators", wire)
    with pytest.raises(SystemExit) as stopped:
        main(["calibrate", "--evaluator", GuardEvaluator.id])
    said = " ".join(_ANSI.sub("", capsys.readouterr().err).split())

    assert stopped.value.code == ExitCode.INTERNAL_ERROR, said
    assert "Guardana defect" in said, said


class _ExitingGrader(Evaluator):
    """A third-party grader that ends the process from inside its own code."""

    id = _ID

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        raise typer.Exit(code=0)


def test_an_evaluator_that_exits_zero_while_grading_is_named_and_records_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def wire(registry: Registry, profile: Profile, budgets: object = None) -> None:
        registry.register_evaluator(_ExitingGrader())

    record = tmp_path / "calibrations.json"
    monkeypatch.delenv("GUARDANA_DEBUG", raising=False)
    monkeypatch.setattr(calibrate_module, "wire_config_evaluators", wire)
    with pytest.raises(SystemExit) as stopped:
        main(["calibrate", "--evaluator", _ID, "--record", str(record)])
    said = " ".join(_ANSI.sub("", capsys.readouterr().err).split())

    assert stopped.value.code == ExitCode.INTERNAL_ERROR, said
    assert _ID in said, said
    assert not record.exists()


class _ThirdPartyGuard(GuardEvaluator):
    """A third-party grader built on Guardana's guard, failing in its own override."""

    id = "acme.guard"

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        raise RuntimeError("acme guard state was never initialised")


def test_a_third_party_subclass_of_a_guardana_judge_that_raises_is_named(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def wire(registry: Registry, profile: Profile, budgets: object = None) -> None:
        registry.register_evaluator(_ThirdPartyGuard(lambda text: "safe"))

    monkeypatch.delenv("GUARDANA_DEBUG", raising=False)
    monkeypatch.setattr(calibrate_module, "wire_config_evaluators", wire)
    with pytest.raises(SystemExit) as stopped:
        main(["calibrate", "--evaluator", _ThirdPartyGuard.id])
    said = " ".join(_ANSI.sub("", capsys.readouterr().err).split())

    assert stopped.value.code == ExitCode.INTERNAL_ERROR, said
    assert _ThirdPartyGuard.id in said, said
    assert "Guardana defect" not in said, said


class _UnreachableGrader(Evaluator):
    """A third-party grader whose network is down, which Guardana's endpoint handling reports."""

    id = _ID

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        raise ConnectionRefusedError("grader host refused the connection")


def test_control_an_endpoint_failure_inside_the_evaluator_keeps_its_own_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def wire(registry: Registry, profile: Profile, budgets: object = None) -> None:
        registry.register_evaluator(_UnreachableGrader())

    monkeypatch.delenv("GUARDANA_DEBUG", raising=False)
    monkeypatch.setattr(calibrate_module, "wire_config_evaluators", wire)
    with pytest.raises(SystemExit) as stopped:
        main(["calibrate", "--evaluator", _ID])
    said = " ".join(_ANSI.sub("", capsys.readouterr().err).split())

    assert stopped.value.code == ExitCode.TARGET_UNAVAILABLE, said
