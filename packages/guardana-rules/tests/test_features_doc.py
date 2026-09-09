"""FEATURES.md stays an overview and delegates volatile detail to generated docs."""

from pathlib import Path

from guardana.core.evaluator.guard import GuardEvaluator
from guardana.core.evaluator.llm_judge import LlmJudgeEvaluator
from guardana.rules import provide_evaluators


def _features_text() -> str:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "FEATURES.md"
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise AssertionError("could not locate FEATURES.md at the repo root")


def test_rule_detail_points_to_the_generated_catalog() -> None:
    """Do not grow FEATURES.md into a second hand-maintained rule catalog."""
    text = _features_text()
    assert "[generated rule catalog](docs/generated/rule-catalog.md)" in text


def test_every_builtin_evaluator_is_presented() -> None:
    # provide_evaluators() covers the always-available pair; the judge and the
    # guard are config-wired rather than entry-point-provided, so list them
    # explicitly — they are just as user-visible.
    text = _features_text()
    ids = [e.id for e in provide_evaluators()] + [LlmJudgeEvaluator.id, GuardEvaluator.id]
    missing = [i for i in ids if f"`{i}`" not in text]
    assert not missing, f"FEATURES.md does not mention evaluator(s): {missing}"
