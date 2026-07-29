from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Self

from guardana.core.evaluator.base import Evaluator, check_expectation
from guardana.core.report.check_error import CheckError
from guardana.core.rule.base import Rule
from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.target import Target
from guardana.core.taxonomy import TaxonomyRef
from guardana.core.taxonomy import register as register_taxonomy

_RULE_GROUP = "guardana.rules"
_EVALUATOR_GROUP = "guardana.evaluators"
_TARGET_GROUP = "guardana.targets"
_TAXONOMY_GROUP = "guardana.taxonomies"
_CANARY_EVALUATOR_ID = "canary"
# Never planted for real: only used to ask a rule whether it participates at all.
_MARKER = "GUARDANA_CANARY_PARTICIPATION_CHECK"


@dataclass(frozen=True, slots=True)
class RuleDirLoad:
    """Outcome of loading YAML rules from a set of directories/files."""

    loaded: tuple[str, ...]
    errors: tuple[CheckError, ...]


class Registry:
    """Single discovery point for rules, evaluators, and targets (built-in or third-party)."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._evaluators: dict[str, Evaluator] = {}
        self._targets: list[type[Target]] = []
        self._load_errors: list[CheckError] = []

    @property
    def load_errors(self) -> tuple[CheckError, ...]:
        """Every plugin or rule file that could not be loaded, and why."""
        return tuple(self._load_errors)

    def record_load_error(self, error: CheckError) -> None:
        """Record something that could not be loaded, so the run can report it."""
        self._load_errors.append(error)

    def register_rule(self, rule: Rule) -> None:
        """Add a rule, keyed by id: a later rule with the same id replaces the earlier.

        De-duping matters because the same rule can arrive from two sources (a
        profile's `rules.paths` and a `--rules` flag over an overlapping dir) —
        running it twice means doubled findings and, on a live model, doubled
        probe calls. Last-wins also lets a custom rule override a built-in by
        reusing its id, exactly as an evaluator can.
        """
        _require_canary_participation(rule)
        for i, existing in enumerate(self._rules):
            if existing.meta.id == rule.meta.id:
                self._rules[i] = rule
                return
        self._rules.append(rule)

    def register_evaluator(self, evaluator: Evaluator) -> None:
        """Add an evaluator under its own `id`, replacing any previous holder of that id."""
        self._evaluators[evaluator.id] = evaluator

    def register_target(self, target: type[Target]) -> None:
        """Add a target class a third-party package advertises for its own backend."""
        self._targets.append(target)

    def rules(self) -> tuple[Rule, ...]:
        """Every registered rule, built-in and third-party alike."""
        return tuple(self._rules)

    def evaluators(self) -> Mapping[str, Evaluator]:
        """Every registered evaluator, keyed by the id rules reference it with."""
        return dict(self._evaluators)

    def targets(self) -> tuple[type[Target], ...]:
        """Every registered target class."""
        return tuple(self._targets)

    def expectation_errors(self) -> tuple[CheckError, ...]:
        """Every rule whose `expect:` block does not satisfy its evaluator's contract.

        Checked here rather than at parse time because a third-party evaluator does
        not exist yet while its rules are being parsed. An unsatisfied contract is a
        check that cannot grade what it claims to, so it belongs in `errors` — a
        rule reading a field its evaluator ignores looks configured and tests
        nothing.

        Evaluators that are not registered are left alone: that is the
        "judge nobody configured" case, which the rule itself reports when it runs.
        """
        errors: list[CheckError] = []
        for rule in self._rules:
            for evaluator_id, expectation in rule.declared_expectations():
                evaluator = self._evaluators.get(evaluator_id)
                if evaluator is None:
                    continue
                problem = check_expectation(evaluator_id, evaluator.expects, expectation)
                if problem is not None:
                    errors.append(CheckError(source=rule.meta.id, stage="load", reason=problem))
        return tuple(errors)

    def load_yaml_rule_dirs(self, paths: Iterable[Path]) -> RuleDirLoad:
        """Load and register declarative YAML rules from directories or files.

        Never raises: a malformed or unloadable rule file is recorded in
        `RuleDirLoad.errors` instead of aborting the caller's scan.
        """
        loaded: list[str] = []
        errors: list[CheckError] = []
        for path in paths:
            for file in _yaml_files(path):
                try:
                    for rule in load_yaml_rules(file):
                        self.register_rule(rule)
                        loaded.append(rule.meta.id)
                except (RuleLoadError, OSError) as exc:
                    errors.append(CheckError.from_exception(str(file), "load", exc))
        self._load_errors.extend(errors)
        return RuleDirLoad(tuple(loaded), tuple(errors))

    @classmethod
    def discover(cls) -> Self:
        """Load every rule, evaluator, and target advertised by an installed package.

        This imports third-party code: an installed plugin is trusted code (see
        SECURITY.md). `guardana scan --no-plugins` skips discovery entirely.

        Each entry point is isolated. One that fails to import — a pack pinned to a
        library you do not have, a typo in a provider — is recorded in
        `load_errors` and the rest still load. Without that isolation a single
        broken third-party package left the user with no rules at all, built-ins
        included, which is the most complete failure mode a scanner has.
        """
        reg = cls()
        for group, expected, register in (
            # Taxonomies first: a rule can only name a framework that is already
            # registered, and a YAML rule pack resolves its `taxonomy:` ids while
            # its own entry point is being loaded.
            (_TAXONOMY_GROUP, TaxonomyRef, register_taxonomy),
            (_RULE_GROUP, Rule, reg.register_rule),
            (_EVALUATOR_GROUP, Evaluator, reg.register_evaluator),
            (_TARGET_GROUP, Target, reg.register_target),
        ):
            for ep in entry_points(group=group):
                try:
                    _absorb(ep.load()(), expected, register)
                except Exception as exc:
                    reg.record_load_error(CheckError.from_exception(ep.name, "discovery", exc))
        return reg


def _require_canary_participation(rule: Rule) -> None:
    """Refuse a rule that grades by canary but will not accept the planted one.

    The probe plants a fresh token and hands it to `Rule.with_canary`. A rule that
    grades by canary and returns None there never sees the marker, so its
    evaluator finds nothing and reports a confident pass for a fully leaking
    model. Checked once, here, because this is the single point every rule —
    built-in, YAML, or a third party's own class — passes through.

    Keyed off the *declared* evaluator, not off `PLANT_SYSTEM_PROMPT`: a rule may
    legitimately need a system prompt planted without grading by canary. A plugin
    rule that reaches for the canary evaluator through `ctx.evaluators` without
    declaring it stays beyond what any static check can see — which is why
    `Rule.with_canary` says so where an author will read it.
    """
    if rule.meta.evaluator == _CANARY_EVALUATOR_ID and rule.with_canary(_MARKER) is None:
        raise RuleLoadError(
            f"rule {rule.meta.id!r} grades with a planted canary but its `with_canary` "
            f"returns None, so the marker would never be planted and the rule would "
            f"pass every model"
        )


def _absorb(
    produced: object, expected: type | tuple[type, ...], register: Callable[[Any], None]
) -> None:
    """Register everything a provider returned, refusing anything of the wrong type.

    Validated before registering, not after: a provider that returns a mapping
    (or a bare string, which is iterable) used to put junk into the rule list, and
    the *next* provider then crashed on it — so whether isolation worked at all
    depended on entry-point ordering.
    """
    items = produced if isinstance(produced, Iterable) else (produced,)
    for item in items:
        if not isinstance(item, expected) and not (
            isinstance(item, type) and issubclass(item, expected)
        ):
            raise TypeError(f"provider returned {type(item).__name__}, expected {expected}")
        register(item)


def _yaml_files(path: Path) -> list[Path]:
    if not path.is_dir():
        return [path]
    return sorted(p for p in path.iterdir() if p.suffix in (".yaml", ".yml"))
