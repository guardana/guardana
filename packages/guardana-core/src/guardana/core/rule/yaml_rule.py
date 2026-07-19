from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml
from guardana.core.evaluator.base import Expectation
from guardana.core.exchange import Exchange
from guardana.core.report import Evidence, Finding
from guardana.core.rule._scenario_schema import is_scenario, parse_scenario
from guardana.core.rule._yaml_schema import (
    check_evaluator_expectations,
    parse_expectation,
    parse_meta,
    str_list,
)
from guardana.core.rule.base import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleLoadError
from guardana.core.target import ChatMessage, Target
from guardana.core.target.endpoint import EndpointTarget


@dataclass(frozen=True, slots=True)
class YamlRule(Rule):
    """A dynamic rule authored declaratively — no Python required."""

    meta: RuleMeta
    prompts: tuple[str, ...]
    expectation: Expectation

    @property
    def planted_canary(self) -> str | None:
        """The canary marker this rule expects to see planted in the target's setup, if any."""
        return self.expectation.canary

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Send each prompt, grade each reply, and yield a finding per failure."""
        if not isinstance(target, EndpointTarget):
            return
        evaluator_id = self.meta.evaluator or ""
        evaluator = ctx.evaluators.get(evaluator_id)
        if evaluator is None:
            # Resolved late from the registry; an absent id is a loud RuleError
            # (visible skip), never a rule that resolves to nothing and passes.
            raise RuleLoadError(f"unknown evaluator: {evaluator_id!r}")
        for prompt in self.prompts:
            reply = target.chat([ChatMessage(role="user", content=prompt)])
            exchange = Exchange(
                (
                    ChatMessage(role="user", content=prompt),
                    ChatMessage(role="assistant", content=reply),
                )
            )
            verdict = evaluator.evaluate(exchange, self.expectation)
            # `fail` is a finding; `inconclusive` is surfaced too (the runner routes
            # it to `unverified`) so a check that could not grade is never a silent
            # pass. Only a real `pass` yields nothing.
            if verdict.outcome == "pass":
                continue
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=target.ref,
                evidence=Evidence(summary=verdict.rationale, detail=reply),
                verdict=verdict,
            )


def _build_rule(raw: object, path: Path) -> Rule:
    if not isinstance(raw, dict):
        raise RuleLoadError(
            f"invalid rule in {path}: each rule must be a mapping, got {type(raw).__name__}"
        )
    if is_scenario(raw):
        return parse_scenario(raw, path)
    meta = parse_meta(raw, path)
    prompts = str_list(raw.get("prompts"), "prompts", path)
    if not prompts:
        raise RuleLoadError(f"invalid rule in {path}: at least one prompt is required")
    expectation = parse_expectation(raw.get("expect"), path)
    check_evaluator_expectations(meta, expectation, path)
    return YamlRule(meta=meta, prompts=prompts, expectation=expectation)


def load_yaml_rules(path: Path) -> list[Rule]:
    """Parse a YAML file into one or more `Rule`s. Accepts a single rule mapping or a list."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        # Surface as RuleLoadError so Registry.load_yaml_rule_dirs keeps its
        # never-raises contract for malformed or unreadable user rule files.
        raise RuleLoadError(f"invalid rule file {path}: {exc}") from exc
    if raw is None:
        raise RuleLoadError(f"{path} is empty")
    raw_rules = raw if isinstance(raw, list) else [raw]
    return [_build_rule(entry, path) for entry in raw_rules]
