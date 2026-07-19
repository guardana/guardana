from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from guardana.core.evaluator.base import Evaluator
from guardana.core.report import Finding
from guardana.core.severity import Severity
from guardana.core.surface import Surface
from guardana.core.target import Capability, Target, TargetKind
from guardana.core.taxonomy import TaxonomyRef


@dataclass(frozen=True, slots=True)
class RuleMeta:
    """Everything the engine knows about a rule before running it.

    What it is, what it maps to in the standards, and what a target must support
    for the rule to run at all.
    """

    id: str
    title: str
    severity: Severity
    target_kind: TargetKind
    taxonomy: tuple[TaxonomyRef, ...] = ()
    required_capabilities: frozenset[Capability] = frozenset()
    evaluator: str | None = None

    @property
    def surface(self) -> Surface:
        """The security layer this rule belongs to (build vs runtime), from what it inspects."""
        return Surface.BUILD if self.target_kind is TargetKind.ARTIFACT else Surface.RUNTIME


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Per-run configuration for one rule, from the profile's `rule_config`.

    `evaluators` is the registry's evaluator set, resolved late so a rule (catalog
    or user-authored) grades against whatever the runner registered — including a
    judge wired from config at scan time.
    """

    config: Mapping[str, object] = field(default_factory=dict)
    evaluators: Mapping[str, Evaluator] = field(default_factory=dict)

    def get(self, key: str, default: object) -> object:
        """Read one config value, falling back to `default`."""
        return self.config.get(key, default)


class Rule(ABC):
    """A single security check. Authored as a plugin (this class) or as YAML."""

    meta: RuleMeta

    @abstractmethod
    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Check `target` and yield a finding per problem found.

        Yield nothing when the target is clean. Raise `RuleError` when the rule
        cannot run at all — the runner records it as skipped instead of failing
        the whole scan.
        """
        ...
