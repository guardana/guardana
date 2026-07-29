"""Validation of a declarative agent-run rule into a typed `TrajectoryRule`.

Same law as the other two shapes: a key nobody recognises is an error, not a
default. A rule whose `tools:` block was silently ignored would offer the model
nothing, watch it call nothing, and report every model clean.
"""

from pathlib import Path
from typing import Any

from guardana.core.rule._yaml_schema import (
    check_evaluator_expectations,
    parse_expectation,
    parse_meta,
    reject_unknown_keys,
)
from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.trajectory_rule import TrajectoryRule
from guardana.core.target.endpoint import ToolSpec
from guardana.core.trajectory import DEFAULT_MAX_STEPS, MAX_STEPS_CEILING, StaticToolDouble
from guardana.core.trajectory.tool_double import ToolOffer

_ALLOWED_KEYS = frozenset(
    {
        "id",
        "title",
        "severity",
        "target_kind",
        "taxonomy",
        "evaluator",
        "requires",
        "task",
        "tools",
        "max_steps",
        "expect",
    }
)
_ALLOWED_TOOL_KEYS = frozenset({"name", "description", "returns"})


def is_trajectory(raw: dict[str, Any]) -> bool:
    """Report whether this mapping declares an agent run rather than prompts or steps."""
    return "task" in raw


def parse_trajectory(raw: dict[str, Any], path: Path) -> TrajectoryRule:
    """Validate an agent-run mapping into a `TrajectoryRule`."""
    reject_unknown_keys(raw, _ALLOWED_KEYS, "trajectory rule", path)
    meta = parse_meta(raw, path, allowed=_ALLOWED_KEYS)
    task = raw.get("task")
    if not isinstance(task, str) or not task:
        raise RuleLoadError(f"invalid rule in {path}: 'task' must be a non-empty string")
    tools = _parse_tools(raw.get("tools"), path)
    expectation = parse_expectation(raw.get("expect"), path)
    check_evaluator_expectations(meta, expectation, path)
    return TrajectoryRule(
        meta=meta,
        task=task,
        tools=tools,
        max_steps=_parse_max_steps(raw.get("max_steps"), path),
        expectation=expectation,
    )


def _parse_tools(value: object, path: Path) -> tuple[ToolOffer, ...]:
    if not isinstance(value, list) or not value:
        raise RuleLoadError(
            f"invalid rule in {path}: 'tools' must be a non-empty list — a run that offers "
            f"no tools can never observe a tool being misused"
        )
    offers: list[ToolOffer] = []
    seen: set[str] = set()
    for entry in value:
        if not isinstance(entry, dict):
            raise RuleLoadError(f"invalid rule in {path}: every entry in 'tools' must be a mapping")
        reject_unknown_keys(entry, _ALLOWED_TOOL_KEYS, "tool", path)
        name = _required_string(entry, "name", path)
        if name in seen:
            # Two doubles under one name: whichever loses is dead configuration,
            # and which one wins would depend on ordering.
            raise RuleLoadError(f"invalid rule in {path}: tool {name!r} is declared twice")
        seen.add(name)
        offers.append(
            ToolOffer(
                spec=ToolSpec(name=name, description=_required_string(entry, "description", path)),
                double=StaticToolDouble(_required_string(entry, "returns", path)),
            )
        )
    return tuple(offers)


def _parse_max_steps(value: object, path: Path) -> int:
    if value is None:
        return DEFAULT_MAX_STEPS
    # `bool` is an `int`, and `max_steps: true` would become one step.
    if not isinstance(value, int) or isinstance(value, bool):
        raise RuleLoadError(f"invalid rule in {path}: 'max_steps' must be an integer")
    if value < 1 or value > MAX_STEPS_CEILING:
        raise RuleLoadError(
            f"invalid rule in {path}: 'max_steps' must be between 1 and {MAX_STEPS_CEILING}"
        )
    return value


def _required_string(raw: dict[str, Any], key: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise RuleLoadError(f"invalid rule in {path}: every tool needs a non-empty '{key}'")
    return value
