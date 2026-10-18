"""`guardana calibrate` names an evaluator that raises while grading instead of blaming itself."""

import re

import guardana.cli.calibrate as calibrate_module
import pytest
from guardana.cli.exit_codes import ExitCode
from guardana.cli.main import main
from guardana.core.evaluator.base import Evaluator, Expectation, Verdict
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


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="the failure is reported as a Guardana defect and the evaluator is not named",
)
def test_an_evaluator_that_raises_while_grading_is_named_and_not_called_a_guardana_defect(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _code, said = _calibrate(monkeypatch, capsys)

    assert _ID in said, said
    assert "Guardana defect" not in said, said
