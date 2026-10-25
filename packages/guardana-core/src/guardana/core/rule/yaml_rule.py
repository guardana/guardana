from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

import yaml
from guardana.core._yaml import load_yaml
from guardana.core.assessment import case_id_for, from_verdict
from guardana.core.evaluator.base import Expectation, Verdict, grade_decline
from guardana.core.report import Evidence, Finding
from guardana.core.rule._digest import declaration_digest
from guardana.core.rule._fixture_schema import parse_fixtures
from guardana.core.rule._scenario_schema import is_scenario, parse_scenario
from guardana.core.rule._send import answered, decline_reason, decline_tags, send
from guardana.core.rule._suite_schema import is_suite, parse_suite
from guardana.core.rule._trajectory_schema import is_trajectory, parse_trajectory
from guardana.core.rule._yaml_schema import (
    check_evaluator_expectations,
    parse_expectation,
    parse_meta,
    str_list,
)
from guardana.core.rule.base import Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleError, RuleLoadError
from guardana.core.rule.fixture import DeclaredFixture, RuleFixture, materialise
from guardana.core.target import ChatMessage, Target
from guardana.core.target.protocols import ChatEndpoint
from guardana.core.trials import CaseOutcome, case_outcome, check_trials, failed_before_stop


@dataclass(frozen=True, slots=True)
class YamlRule(Rule):
    """A dynamic rule authored declaratively — no Python required."""

    meta: RuleMeta
    prompts: tuple[str, ...]
    expectation: Expectation
    source_digest: str = ""
    """Hash of the declaration this rule was parsed from; see `Rule.digest`."""

    declared_fixtures: tuple[RuleFixture | DeclaredFixture, ...] = ()
    """Samples from the rule file's `fixtures:` block, if it has one.

    Named `declared_fixtures` because `fixtures()` is the contract every rule
    implements: a field and a method cannot share a name, and the method is the
    part a third party overrides.
    """

    trials_per_case: int = 1
    """How many independent attempts `run` makes at each prompt; set by `with_trials`."""

    def fixtures(self) -> Iterable[RuleFixture]:
        """Build this rule file's samples, each with a double that has played nothing.

        A scripted double is an iterator, so handing out the same one twice would
        grade a second verification against replies the first consumed.
        """
        return materialise(self.declared_fixtures)

    def digest(self) -> str:
        """Return the declaration hash, falling back to the metadata-only default.

        A rule built by hand rather than parsed (a test, or a plugin assembling one
        programmatically) has no declaration to hash, and the base implementation
        still gives it a stable identity.

        `Rule.digest(self)` rather than `super().digest()`, and that is not style.
        `@dataclass(slots=True)` builds a *new* class object and throws the
        original away, while the zero-argument `super()` closure still points at
        the original — so the call raises `TypeError` every time it is reached.
        It was reached only when `source_digest` was empty, which is exactly the
        hand-built case no fixture had, so it sat here undetected until something
        started asking every rule for its digest.
        """
        return self.source_digest or Rule.digest(self)

    @property
    def estimated_requests(self) -> int:
        """One request per prompt per trial: `run` sends all of them, and does not stop early.

        Every prompt is a separate test of the same claim, and every trial a separate
        attempt at it, so stopping at the first failure would leave the rest ungraded
        — which means this is an exact count rather than a ceiling.
        """
        return len(self.prompts) * self.trials_per_case

    @property
    def graded_verdicts(self) -> Mapping[str, int]:
        """One verdict per prompt per trial, all from the rule's evaluator."""
        return {self.meta.evaluator or "": len(self.prompts) * self.trials_per_case}

    def with_trials(self, trials: int) -> "Rule | None":
        """Send every prompt `trials` times: the verdict depends on a sampled reply."""
        return replace(self, trials_per_case=check_trials(trials))

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        """Report the single evaluator and expectation every prompt is graded with."""
        return ((self.meta.evaluator or "", self.expectation),)

    def with_canary(self, canary: str) -> "Rule | None":
        """Swap the declared canary for the token the probe planted this run."""
        if self.expectation.canary is None:
            return None
        return replace(self, expectation=replace(self.expectation, canary=canary))

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Send each prompt once per trial, grade each reply, and yield a finding per failed case.

        Every trial is a fresh request with no history, so K replies to one prompt are K
        attempts at the same case rather than one longer conversation. A request the
        application declines is graded as the evaluator reads a decline.
        """
        if not isinstance(target, ChatEndpoint):
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
            case_id = case_id_for(self.meta.id, prompt)
            verdicts: list[Verdict] = []
            replies: list[str] = []
            try:
                for trial in range(1, self.trials_per_case + 1):
                    asked = (ChatMessage(role="user", content=prompt),)
                    sent = send(target, asked)
                    exchange = answered(asked, sent)
                    verdict, from_decline = grade_decline(evaluator, exchange, self.expectation)
                    # `pass` included: without the passes there is no denominator. The
                    # `dataset` is this rule's declaration digest — the same hash `diff`
                    # uses for "rule definition changed", so a sharpened corpus makes two
                    # runs incomparable rather than making the model look worse.
                    ctx.record(
                        from_verdict(
                            verdict,
                            case_id=case_id,
                            subject_ref=target.ref,
                            rule_id=self.meta.id,
                            dataset=self.digest(),
                            tags=decline_tags(exchange, from_decline),
                            trial=trial,
                            reason=decline_reason(exchange),
                        )
                    )
                    verdicts.append(verdict)
                    replies.append(sent.evidence)
            except Exception:
                # A failure already seen is kept when a later trial stops the rule: a
                # spent budget or a grader that raised must not take it back.
                partial = failed_before_stop(verdicts, self.trials_per_case)
                if partial is not None:
                    yield self._finding(partial, replies, target.ref)
                raise
            # A failed trial is a finding; a trial that could not be graded, with none
            # failed, is surfaced too (the runner routes it to `unverified`) so a case
            # that was not fully measured is never a silent pass.
            outcome = case_outcome(verdicts)
            if outcome is not None:
                yield self._finding(outcome, replies, target.ref)

    def _finding(self, outcome: CaseOutcome, replies: list[str], target_ref: str) -> Finding:
        """One case's finding, with the reply or the decline of the trial its verdict came from."""
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=target_ref,
            evidence=Evidence(summary=outcome.verdict.rationale, detail=replies[outcome.trial - 1]),
            verdict=outcome.verdict,
        )


def _build_rule(raw: object, path: Path) -> Rule:
    if not isinstance(raw, dict):
        raise RuleLoadError(
            f"invalid rule in {path}: each rule must be a mapping, got {type(raw).__name__}"
        )
    if is_suite(raw):
        return parse_suite(raw, path)
    if is_scenario(raw):
        return parse_scenario(raw, path)
    if is_trajectory(raw):
        return parse_trajectory(raw, path)
    meta = parse_meta(raw, path)
    prompts = str_list(raw.get("prompts"), "prompts", path)
    if not prompts:
        raise RuleLoadError(f"invalid rule in {path}: at least one prompt is required")
    repeated = sorted({prompt for prompt in prompts if prompts.count(prompt) > 1})
    if repeated:
        # A prompt is its own case id, so a repeated prompt would be one case recorded
        # twice, and the second set of grades would overwrite the first.
        raise RuleLoadError(
            f"invalid rule in {path}: prompts must be distinct; {repeated[0]!r} appears twice"
        )
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
        raw = load_yaml(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        # Surface as RuleLoadError so Registry.load_yaml_rule_dirs keeps its
        # never-raises contract for malformed or unreadable user rule files.
        raise RuleLoadError(f"invalid rule file {path}: {exc}") from exc
    if raw is None:
        raise RuleLoadError(f"{path} is empty")
    raw_rules = raw if isinstance(raw, list) else [raw]
    return [_build_rule(entry, path) for entry in raw_rules]
