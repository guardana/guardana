from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from guardana.core.evaluator.base import Evaluator, Expectation
from guardana.core.report import Finding
from guardana.core.rule._digest import digest_parts
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

    def declared_expectations(self) -> Iterable[tuple[str, Expectation]]:
        """Return the (evaluator id, expectation) pairs this rule will grade with.

        Declaring them lets the engine check, once discovery has loaded the package
        that defines an evaluator, that every rule naming it actually satisfies its
        contract. A rule that grades entirely in Python declares nothing and is not
        checked — there is nothing to check against.
        """
        return ()

    def digest(self) -> str:
        """Return a short, stable hash of *what this rule is* — its declaration, not its results.

        Two runs are only comparable if they ran the same tests. When a rule's
        corpus is sharpened between runs, more findings are the sharper test
        talking, not a worse model, and a comparison that could not tell the
        difference would hand the customer the wrong culprit.

        The default covers the declaration every rule has (`meta`), so a
        third-party rule is comparable without its author doing anything. What it
        cannot cover is the *implementation* of a rule written in Python: that
        code can change while the declaration stays identical. The tool version
        recorded alongside a run is what covers the rest, and an author who wants
        it tighter overrides this to fold in their own package version.

        **Never fold in a planted canary.** The probe plants a fresh random token
        per run, so a digest covering its value would differ on every run and
        report "this rule changed" every single time — which is the same as
        reporting nothing at all.
        """
        return digest_parts(
            (
                self.meta.id,
                self.meta.title,
                self.meta.severity.name,
                self.meta.target_kind,
                self.meta.evaluator or "",
                ",".join(f"{t.framework}:{t.id}" for t in self.meta.taxonomy),
                ",".join(sorted(self.meta.required_capabilities)),
            )
        )

    def with_canary(self, canary: str) -> "Rule | None":
        """Return a copy of this rule looking for `canary`, or None if it plants none.

        The probe plants a fresh random token per run — a canary shipped in a rules
        file is public and could be trained around — and hands it here so the rule
        looks for exactly what was planted. Default None: this rule uses no canary
        and runs in the ordinary pass.

        **A rule graded by a canary must override this.** Returning None leaves the
        marker unplanted, the evaluator then finds nothing, and the rule reports a
        confident pass for every model, leaky or not. Registration refuses a rule
        that grades by canary and does not participate, so the mistake cannot ship
        quietly.
        """
        return None

    @abstractmethod
    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Check `target` and yield a finding per problem found.

        Yield nothing when the target is clean. Raise `RuleError` when the rule
        cannot run at all — the runner records it as skipped instead of failing
        the whole scan.
        """
        ...
