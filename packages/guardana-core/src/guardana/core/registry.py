from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Self

from guardana.core.evaluator.base import Evaluator
from guardana.core.rule.base import Rule
from guardana.core.rule.errors import RuleLoadError
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.target import Target

_RULE_GROUP = "guardana.rules"
_EVALUATOR_GROUP = "guardana.evaluators"
_TARGET_GROUP = "guardana.targets"


@dataclass(frozen=True, slots=True)
class RuleDirLoad:
    """Outcome of loading YAML rules from a set of directories/files."""

    loaded: tuple[str, ...]
    errors: tuple[str, ...]


class Registry:
    """Single discovery point for rules, evaluators, and targets (built-in or third-party)."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._evaluators: dict[str, Evaluator] = {}
        self._targets: list[type[Target]] = []

    def register_rule(self, rule: Rule) -> None:
        """Add a rule, keyed by id: a later rule with the same id replaces the earlier.

        De-duping matters because the same rule can arrive from two sources (a
        profile's `rules.paths` and a `--rules` flag over an overlapping dir) —
        running it twice means doubled findings and, on a live model, doubled
        probe calls. Last-wins also lets a custom rule override a built-in by
        reusing its id, exactly as an evaluator can.
        """
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

    def load_yaml_rule_dirs(self, paths: Iterable[Path]) -> RuleDirLoad:
        """Load and register declarative YAML rules from directories or files.

        Never raises: a malformed or unloadable rule file is recorded in
        `RuleDirLoad.errors` instead of aborting the caller's scan.
        """
        loaded: list[str] = []
        errors: list[str] = []
        for path in paths:
            for file in _yaml_files(path):
                try:
                    for rule in load_yaml_rules(file):
                        self.register_rule(rule)
                        loaded.append(rule.meta.id)
                except (RuleLoadError, OSError) as exc:
                    errors.append(f"{file}: {exc}")
        return RuleDirLoad(tuple(loaded), tuple(errors))

    @classmethod
    def discover(cls) -> Self:
        """Load every rule, evaluator, and target advertised by an installed package.

        This imports third-party code: an installed plugin is trusted code (see
        SECURITY.md). `guardana scan --no-plugins` skips discovery entirely.
        """
        reg = cls()
        for ep in entry_points(group=_RULE_GROUP):
            _absorb(ep.load()(), reg.register_rule)
        for ep in entry_points(group=_EVALUATOR_GROUP):
            _absorb(ep.load()(), reg.register_evaluator)
        for ep in entry_points(group=_TARGET_GROUP):
            _absorb(ep.load()(), reg.register_target)
        return reg


def _absorb(produced: Any, register: Callable[[Any], None]) -> None:  # noqa: ANN401
    items = produced if isinstance(produced, Iterable) else (produced,)
    for item in items:
        register(item)


def _yaml_files(path: Path) -> list[Path]:
    if not path.is_dir():
        return [path]
    return sorted(p for p in path.iterdir() if p.suffix in (".yaml", ".yml"))
