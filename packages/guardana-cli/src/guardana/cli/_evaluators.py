"""Build config-driven evaluators (the LLM judge and the guard) and register them.

The judge's differentiating value is that it grades "did the attack succeed" — but
it needs a model to ask, and nothing built one from config until here. Both the
judge and the optional guard model are ordinary endpoints, so they can point at a
local OpenAI-compatible server for fully offline grading. Absent config leaves an
evaluator unregistered, and a rule that names it is then skipped visibly by the
runner — never a silent pass.
"""

import os
from collections.abc import Callable, Mapping

from guardana.cli._endpoint import build_endpoint
from guardana.core.evaluator.guard import GuardEvaluator
from guardana.core.evaluator.llm_judge import JudgeCalibration, LlmJudgeEvaluator
from guardana.core.profile import Profile
from guardana.core.profile.errors import ProfileError
from guardana.core.registry import Registry
from guardana.core.target import ChatMessage

_DEFAULT_PROMPT_VERSION = "2025.1"


def wire_config_evaluators(registry: Registry, profile: Profile) -> None:
    """Register every evaluator that must be built from `guardana.yaml` config.

    Today those are `llm_judge` (a judge model) and the optional `guard` (a safety
    classifier). Call after discovery so they join the evaluator set the runner
    resolves every rule against.
    """
    judge_cfg = profile.evaluator_config.get("llm_judge")
    if judge_cfg is not None:
        registry.register_evaluator(_build_llm_judge(judge_cfg))
    guard_cfg = profile.evaluator_config.get("guard")
    if guard_cfg is not None:
        registry.register_evaluator(GuardEvaluator(_endpoint_call(guard_cfg, "guard")))


def _build_llm_judge(cfg: Mapping[str, object]) -> LlmJudgeEvaluator:
    judge = _endpoint_call(cfg, "llm_judge")
    version = cfg.get("prompt_version", _DEFAULT_PROMPT_VERSION)
    if not isinstance(version, str):
        raise ProfileError("evaluators.llm_judge.prompt_version must be a string")
    min_agreement = cfg.get("min_agreement", 1)
    # `bool` is an `int` subclass, so `min_agreement: true` would slip through — reject it.
    if not isinstance(min_agreement, int) or isinstance(min_agreement, bool):
        raise ProfileError("evaluators.llm_judge.min_agreement must be an integer")
    try:
        return LlmJudgeEvaluator(judge, version, min_agreement, _calibration(cfg))
    except ValueError as exc:  # unknown prompt_version or min_agreement < 1 — config typos
        raise ProfileError(f"evaluators.llm_judge: {exc}") from exc


def _calibration(cfg: Mapping[str, object]) -> JudgeCalibration | None:
    """Read a measured accuracy from config, if the operator recorded one.

    Deliberately numbers rather than a corpus path: measuring costs one judge call
    per sample, and a scan is the wrong moment to spend that. Run
    `guardana calibrate`, then record what it measured — an explicit, auditable
    act rather than something that quietly happens on every run.
    """
    raw = cfg.get("calibration")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ProfileError("evaluators.llm_judge.calibration must be a mapping")
    accuracy = raw.get("accuracy")
    samples = raw.get("samples")
    evaluator_id = raw.get("evaluator_id")
    if not isinstance(accuracy, int | float) or isinstance(accuracy, bool):
        raise ProfileError("evaluators.llm_judge.calibration.accuracy must be a number")
    if not isinstance(samples, int) or isinstance(samples, bool):
        raise ProfileError("evaluators.llm_judge.calibration.samples must be an integer")
    if not isinstance(evaluator_id, str) or not evaluator_id:
        raise ProfileError(
            "evaluators.llm_judge.calibration.evaluator_id must name the judge that was "
            "measured, e.g. llm_judge@2025.1 — a changed rubric must not inherit an "
            "older measurement"
        )
    try:
        return JudgeCalibration(
            evaluator_id=evaluator_id, accuracy=float(accuracy), samples=samples
        )
    except ValueError as exc:
        raise ProfileError(f"evaluators.llm_judge.calibration: {exc}") from exc


def _endpoint_call(cfg: Mapping[str, object], what: str) -> Callable[[str], str]:
    """Build a `prompt -> reply` callable from an endpoint config block."""
    target = build_endpoint(
        _require_str(cfg, "endpoint", what),
        _require_str(cfg, "model", what),
        api_key=_api_key(cfg, what),
    )

    def call(prompt: str) -> str:
        return target.chat([ChatMessage(role="user", content=prompt)])

    return call


def _require_str(cfg: Mapping[str, object], key: str, what: str) -> str:
    value = cfg.get(key)
    if not isinstance(value, str) or not value:
        raise ProfileError(f"evaluators.{what}.{key} must be a non-empty string")
    return value


def _api_key(cfg: Mapping[str, object], what: str) -> str | None:
    env = cfg.get("api_key_env")
    if env is None:
        return None
    if not isinstance(env, str):
        raise ProfileError(f"evaluators.{what}.api_key_env must be a string")
    return os.environ.get(env)
