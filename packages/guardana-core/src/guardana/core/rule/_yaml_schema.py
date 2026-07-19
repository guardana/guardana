"""Validation of a declarative YAML rule mapping into typed `RuleMeta` / `Expectation`.

Every check here fails loudly at load time. A typo (`promts:`), a scalar where a
list belongs (`prompts: "..."` → single-character prompts), or a wrong type would
otherwise produce a rule that runs silently and passes everything — the exact
false-negative the fixture law exists to prevent. Kept separate from
`yaml_rule.py` so the parsing vocabulary and the `YamlRule` type each stay small.
"""

from pathlib import Path
from typing import Any

from guardana.core.evaluator.base import Expectation
from guardana.core.rule.base import RuleMeta
from guardana.core.rule.errors import RuleLoadError
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import TaxonomyRef, by_short_id

_ALLOWED_RULE_KEYS = frozenset(
    {
        "id",
        "title",
        "severity",
        "target_kind",
        "taxonomy",
        "evaluator",
        "requires",
        "prompts",
        "expect",
    }
)
_ALLOWED_EXPECT_KEYS = frozenset({"canary", "goal"})

# The built-in evaluators that consume a specific `expect` field. A rule naming
# one of these must carry the field, or the evaluator would run against nothing
# and report a confident "all clear" (canary) — so we reject it at load. A
# third-party evaluator's needs are unknown to us, so we don't invent any.
_EVALUATOR_REQUIRED_EXPECT = {"canary": "canary", "llm_judge": "goal"}


def reject_unknown_keys(
    raw: dict[str, Any], allowed: frozenset[str], what: str, path: Path
) -> None:
    """Reject any key not in `allowed` — a misspelled key must fail, not be ignored."""
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise RuleLoadError(
            f"invalid rule in {path}: unknown {what} field(s): {', '.join(unknown)}"
        )


def _require_str(raw: dict[str, Any], key: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise RuleLoadError(f"invalid rule in {path}: '{key}' must be a non-empty string")
    return value


def str_list(value: object, what: str, path: Path) -> tuple[str, ...]:
    """Parse a list of strings, refusing a bare string.

    `tuple("abc")` would explode a string into single characters — a rule that
    silently runs junk prompts. So a scalar where a list belongs is an error.
    """
    if value is None:
        return ()
    if not isinstance(value, list):
        raise RuleLoadError(
            f"invalid rule in {path}: '{what}' must be a list of strings, "
            f"got {type(value).__name__}"
        )
    for item in value:
        if not isinstance(item, str):
            raise RuleLoadError(f"invalid rule in {path}: every entry in '{what}' must be a string")
    return tuple(value)


def _parse_taxonomy(value: object, path: Path) -> tuple[TaxonomyRef, ...]:
    refs = []
    for ref_id in str_list(value, "taxonomy", path):
        ref = by_short_id.get(ref_id)
        if ref is None:
            raise RuleLoadError(f"invalid rule in {path}: unknown taxonomy id {ref_id!r}")
        refs.append(ref)
    return tuple(refs)


def _parse_capabilities(value: object, path: Path) -> frozenset[Capability]:
    caps = set()
    for name in str_list(value, "requires", path):
        try:
            caps.add(Capability[name.upper()])
        except KeyError as exc:
            raise RuleLoadError(
                f"invalid rule in {path}: unknown capability {name!r} in 'requires'"
            ) from exc
    return frozenset(caps)


def _parse_severity(raw: dict[str, Any], path: Path) -> Severity:
    name = _require_str(raw, "severity", path)
    try:
        return Severity[name.upper()]
    except KeyError as exc:
        raise RuleLoadError(f"invalid rule in {path}: unknown severity {name!r}") from exc


def _parse_target_kind(raw: dict[str, Any], path: Path) -> TargetKind:
    name = _require_str(raw, "target_kind", path)
    try:
        kind = TargetKind[name.upper()]
    except KeyError as exc:
        raise RuleLoadError(f"invalid rule in {path}: unknown target_kind {name!r}") from exc
    if kind is not TargetKind.ENDPOINT:
        raise RuleLoadError(
            f"invalid rule in {path}: YAML rules are dynamic endpoint rules; "
            f"target_kind must be 'endpoint'"
        )
    return kind


def parse_meta(raw: dict[str, Any], path: Path) -> RuleMeta:
    """Validate the rule-level fields into a `RuleMeta`."""
    reject_unknown_keys(raw, _ALLOWED_RULE_KEYS, "rule", path)
    return RuleMeta(
        id=_require_str(raw, "id", path),
        title=_require_str(raw, "title", path),
        severity=_parse_severity(raw, path),
        target_kind=_parse_target_kind(raw, path),
        taxonomy=_parse_taxonomy(raw.get("taxonomy"), path),
        required_capabilities=_parse_capabilities(raw.get("requires"), path),
        evaluator=_require_str(raw, "evaluator", path),
    )


def parse_expectation(raw: object, path: Path) -> Expectation:
    """Validate the `expect:` mapping into an `Expectation`."""
    if raw is None:
        return Expectation()
    if not isinstance(raw, dict):
        raise RuleLoadError(f"invalid rule in {path}: 'expect' must be a mapping")
    reject_unknown_keys(raw, _ALLOWED_EXPECT_KEYS, "expect", path)
    return Expectation(canary=raw.get("canary"), goal=raw.get("goal"))


def check_evaluator_expectations(meta: RuleMeta, expectation: Expectation, path: Path) -> None:
    """Reject a rule whose built-in evaluator needs an `expect` field it didn't set."""
    required = _EVALUATOR_REQUIRED_EXPECT.get(meta.evaluator or "")
    if required and getattr(expectation, required) is None:
        raise RuleLoadError(
            f"invalid rule in {path}: evaluator {meta.evaluator!r} requires 'expect.{required}'"
        )
    require_canary_is_plantable(meta.evaluator == "canary", meta.required_capabilities, path)


def require_canary_is_plantable(
    uses_canary: bool, capabilities: frozenset[Capability], path: Path
) -> None:
    """Reject a canary-graded rule that can't have its canary planted.

    The canary evaluator only finds a leak if the marker was planted in the
    target's system prompt — which the probe does only for a rule that declares
    `requires: [plant_system_prompt]`. Without it the canary is never planted, the
    evaluator never finds it, and the rule passes everything: a silent gate. So it
    is a load-time error, not a rule that looks configured but checks nothing.
    """
    if uses_canary and Capability.PLANT_SYSTEM_PROMPT not in capabilities:
        raise RuleLoadError(
            f"invalid rule in {path}: evaluator 'canary' needs its marker planted, so "
            f"the rule must declare requires: [plant_system_prompt] — otherwise the "
            f"canary is never planted and the rule silently passes everything"
        )
