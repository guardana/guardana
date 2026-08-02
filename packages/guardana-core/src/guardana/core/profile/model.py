from collections.abc import Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatch

from guardana.core.budget import Budgets
from guardana.core.redaction import RedactionPolicy
from guardana.core.severity import Severity


@dataclass(frozen=True, slots=True)
class FailOn:
    """The bar a finding must clear to fail the build."""

    severity: Severity = Severity.HIGH
    min_confidence: float = 0.0
    fail_on_inconclusive: bool = False
    # Defaults to True where `fail_on_inconclusive` defaults to False, because the
    # two are not the same thing. `inconclusive` is a verdict — the check ran and
    # honestly said "I cannot tell", and you cannot gate on that. An error is a
    # defect: the check did not run, while the result looks as though it did.
    fail_on_error: bool = True
    fail_on_skipped: bool = False
    """Whether a rule the target could not satisfy makes the run indeterminate.

    Off by default, because most skips are ordinary — a file rule against an
    endpoint, a tool-calling rule against a model nobody claimed could call tools.
    On, it says "I am paying for this coverage and I want to know when I did not
    get it", which is the setting a team uses once they have decided what their
    provider must support.
    """


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
    path_excludes: tuple[str, ...] = ()
    budgets: Budgets = field(default_factory=Budgets)
    privacy: RedactionPolicy = field(default_factory=RedactionPolicy)
    """What evidence this run may keep. See `guardana.core.redaction`.

    A `Profile` built in code defaults to `full`, matching what the engine did
    before the redactor existed; `guardana.yaml` and every CLI command default to
    `redacted`. The difference is deliberate: a library caller has already decided
    what to do with the objects it is handed, while a command writes files.
    """
