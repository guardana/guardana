from collections.abc import Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatch

from guardana.core.severity import Severity


@dataclass(frozen=True, slots=True)
class FailOn:
    """The bar a finding must clear to fail the build."""

    severity: Severity = Severity.HIGH
    min_confidence: float = 0.0
    fail_on_inconclusive: bool = False


@dataclass(frozen=True, slots=True)
class Policy:
    """Which rules run, and which findings fail the build."""

    include: tuple[str, ...] = ("*",)
    exclude: tuple[str, ...] = ()
    fail_on: FailOn = field(default_factory=FailOn)

    def matches(self, rule_id: str) -> bool:
        """Whether a rule id survives the include/exclude globs (exclude wins)."""
        included = any(fnmatch(rule_id, pat) for pat in self.include)
        excluded = any(fnmatch(rule_id, pat) for pat in self.exclude)
        return included and not excluded


@dataclass(frozen=True, slots=True)
class Profile:
    """A `guardana.yaml`, parsed: the policy plus any rule/evaluator configuration."""

    name: str
    policy: Policy
    rule_config: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    evaluator_config: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    rule_paths: tuple[str, ...] = ()
