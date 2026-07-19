"""Validation of a declarative multi-turn scenario mapping into a `ScenarioRule`.

Same loud-at-load discipline as `_yaml_schema`: a typo'd key, a scalar where a
mapping belongs, or — most dangerous — a scenario with no `expect` anywhere fails
the build. An ungraded scenario would drive turns and pass everything, the exact
false-negative the fixture law exists to prevent.
"""

from pathlib import Path
from typing import Any

from guardana.core.evaluator.base import Expectation
from guardana.core.rule._yaml_schema import (
    _EVALUATOR_REQUIRED_EXPECT,
    _parse_capabilities,
    _parse_severity,
    _parse_target_kind,
    _parse_taxonomy,
    _require_str,
    reject_unknown_keys,
    require_canary_is_plantable,
)
from guardana.core.rule.base import RuleMeta
from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.scenario_rule import ScenarioRule, ScenarioStep

_ALLOWED_SCENARIO_KEYS = frozenset(
    {
        "id",
        "title",
        "severity",
        "target_kind",
        "taxonomy",
        "requires",
        "steps",
        "stateful",
        "expect",
    }
)
_ALLOWED_STEP_KEYS = frozenset({"send", "expect"})
_ALLOWED_STEP_EXPECT_KEYS = frozenset({"evaluator", "goal", "canary"})


def is_scenario(raw: dict[str, Any]) -> bool:
    """Report whether a rule doc is a scenario (carries `steps:`) vs a single-turn rule."""
    return "steps" in raw


def parse_scenario(raw: dict[str, Any], path: Path) -> ScenarioRule:
    """Validate a scenario mapping into a `ScenarioRule`, failing loudly on any error."""
    reject_unknown_keys(raw, _ALLOWED_SCENARIO_KEYS, "scenario", path)
    meta = RuleMeta(
        id=_require_str(raw, "id", path),
        title=_require_str(raw, "title", path),
        severity=_parse_severity(raw, path),
        target_kind=_parse_target_kind(raw, path),
        taxonomy=_parse_taxonomy(raw.get("taxonomy"), path),
        required_capabilities=_parse_capabilities(raw.get("requires"), path),
        evaluator=None,
    )
    steps = _parse_steps(raw.get("steps"), path)
    stateful = _parse_bool(raw.get("stateful", False), "stateful", path)
    conv_evaluator, conv_expect = _parse_expect_block(raw.get("expect"), path)

    if not any(step.expect is not None for step in steps) and conv_expect is None:
        raise RuleLoadError(
            f"invalid scenario in {path}: at least one 'expect' (a step's or the "
            f"conversation's) is required — an ungraded scenario passes everything"
        )
    uses_canary = conv_evaluator == "canary" or any(step.evaluator == "canary" for step in steps)
    require_canary_is_plantable(uses_canary, meta.required_capabilities, path)
    return ScenarioRule(
        meta=meta,
        steps=steps,
        stateful=stateful,
        conversation_evaluator=conv_evaluator,
        conversation_expect=conv_expect,
    )


def _parse_steps(value: object, path: Path) -> tuple[ScenarioStep, ...]:
    if not isinstance(value, list) or not value:
        raise RuleLoadError(f"invalid scenario in {path}: 'steps' must be a non-empty list")
    return tuple(_parse_step(entry, path) for entry in value)


def _parse_step(raw: object, path: Path) -> ScenarioStep:
    if not isinstance(raw, dict):
        raise RuleLoadError(f"invalid scenario in {path}: each step must be a mapping")
    reject_unknown_keys(raw, _ALLOWED_STEP_KEYS, "step", path)
    send = _require_str(raw, "send", path)
    evaluator, expect = _parse_expect_block(raw.get("expect"), path)
    return ScenarioStep(send=send, evaluator=evaluator, expect=expect)


def _parse_expect_block(raw: object, path: Path) -> tuple[str | None, Expectation | None]:
    """Parse an `expect:` block (a step's or the conversation's) into (evaluator, expectation)."""
    if raw is None:
        return None, None
    if not isinstance(raw, dict):
        raise RuleLoadError(f"invalid scenario in {path}: 'expect' must be a mapping")
    reject_unknown_keys(raw, _ALLOWED_STEP_EXPECT_KEYS, "expect", path)
    evaluator = _require_str(raw, "evaluator", path)
    expectation = Expectation(canary=raw.get("canary"), goal=raw.get("goal"))
    required = _EVALUATOR_REQUIRED_EXPECT.get(evaluator)
    if required and getattr(expectation, required) is None:
        raise RuleLoadError(
            f"invalid scenario in {path}: evaluator {evaluator!r} requires 'expect.{required}'"
        )
    return evaluator, expectation


def _parse_bool(value: object, key: str, path: Path) -> bool:
    if not isinstance(value, bool):
        raise RuleLoadError(f"invalid scenario in {path}: '{key}' must be true or false")
    return value
