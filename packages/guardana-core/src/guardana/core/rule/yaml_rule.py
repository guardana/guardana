from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

import yaml
from guardana.core.evaluator.base import Expectation
from guardana.core.exchange import Exchange
from guardana.core.report import Evidence, Finding
from guardana.core.rule._digest import declaration_digest
from guardana.core.rule._fixture_schema import parse_fixtures
from guardana.core.rule._scenario_schema import is_scenario, parse_scenario
from guardana.core.rule._trajectory_schema import is_trajectory, parse_trajectory
from guardana.core.rule._yaml_schema import (
    check_evaluator_expectations,
    parse_expectation,
    parse_meta,
    str_list,
)
from guardana.core.rule.base import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleError, RuleLoadError
from guardana.core.rule.fixture import RuleFixture
from guardana.core.target import ChatMessage, Target
from guardana.core.target.endpoint import EndpointTarget


@dataclass(frozen=True, slots=True)
class YamlRule(Rule):
    """A dynamic rule authored declaratively — no Python required."""

    meta: RuleMeta
    prompts: tuple[str, ...]
    expectation: Expectation
    source_digest: str = ""
    """Hash of the declaration this rule was parsed from; see `Rule.digest`."""

    declared_fixtures: tuple[RuleFixture, ...] = ()
    """Samples from the rule file's `fixtures:` block, if it has one.

    Named `declared_fixtures` because `fixtures()` is the contract every rule
    implements: a field and a method cannot share a name, and the method is the
    part a third party overrides.
    """

    def fixtures(self) -> Iterable[RuleFixture]:
        """Return the samples this rule file declared."""
        return self.declared_fixtures

    def digest(self) -> str:
        """Return the declaration hash, falling back to the metadata-only default.

        A rule built by hand rather than parsed (a test, or a plugin assembling one
        programmatically) has no declaration to hash, and the base implementation
        still gives it a stable identity.
        """
        return self.source_digest or super().digest()

    @property
    def estimated_requests(self) -> int:
        """One request per prompt: `run` sends all of them, and does not stop early.

        Every prompt is a separate test of the same claim, so stopping at the
        first failure would leave the rest ungraded — which means this is an exact
        count rather than a ceiling.
        """
        return len(self.prompts)

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        """Report the single evaluator and expectation every prompt is graded with."""
        return ((self.meta.evaluator or "", self.expectation),)

    def with_canary(self, canary: str) -> "Rule | None":
        """Swap the declared canary for the token the probe planted this run."""
        if self.expectation.canary is None:
            return None
        return replace(self, expectation=replace(self.expectation, canary=canary))

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Send each prompt, grade each reply, and yield a finding per failure."""
        if not isinstance(target, EndpointTarget):
            # Unreachable while the capability contract holds: the runner only
            # plans this rule against a target that declared `chat`. If it ever
            # runs, the contract is broken, and that belongs in `errors` rather
            # than looking like a rule that ran and found nothing.
            raise RuleError(f"{self.meta.id} needs a chat endpoint, got {type(target).__name__}")
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
    if is_trajectory(raw):
        return parse_trajectory(raw, path)
    meta = parse_meta(raw, path)
    prompts = str_list(raw.get("prompts"), "prompts", path)
    if not prompts:
        raise RuleLoadError(f"invalid rule in {path}: at least one prompt is required")
    expectation = parse_expectation(raw.get("expect"), path)
    check_evaluator_expectations(meta, expectation, path)
    return YamlRule(
        meta=meta,
        prompts=prompts,
        expectation=expectation,
        source_digest=declaration_digest(raw),
        declared_fixtures=parse_fixtures(raw.get("fixtures"), path),
    )


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
