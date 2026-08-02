"""What a run would cost, worked out without spending anything.

A command that tells you what a run will cost must not cost anything itself, so
nothing here sends a request. Everything it reports comes from what the rules
declare and what the target says about itself.
"""

from dataclasses import dataclass

from guardana.core.budget import Budgets
from guardana.core.profile.model import Profile
from guardana.core.registry import Registry
from guardana.core.target import Target


@dataclass(frozen=True, slots=True)
class RunPlan:
    """The rules a run would execute, and what they would spend.

    `unknown_cost` is the field that keeps the rest honest. A rule that does not
    declare its request count contributes nothing to `max_requests`, so the
    ceiling would understate a run that includes one — unless the plan says so
    out loud, which is what this list is for.
    """

    rules: tuple[str, ...]
    skipped: tuple[str, ...]
    unknown_cost: tuple[str, ...]
    min_requests: int
    max_requests: int
    budgets: Budgets

    @property
    def is_complete(self) -> bool:
        """Whether every selected rule declared what it would spend."""
        return not self.unknown_cost

    @property
    def exceeds_budget(self) -> bool:
        """Whether the worst case would hit the configured request ceiling.

        Only the request ceiling: tokens and wall time cannot be predicted from a
        declaration, and guessing at them would produce a warning nobody could
        act on. A plan with an unknown-cost rule never claims to fit — its ceiling
        is not a ceiling.
        """
        limit = self.budgets.max_requests
        if limit is None:
            return False
        return not self.is_complete or self.max_requests > limit


def build_plan(registry: Registry, profile: Profile, target: Target) -> RunPlan:
    """Work out what running `profile`'s rules against `target` would cost.

    Selects exactly the way `Runner` does — same kind, same policy globs, same
    capability check — so the plan describes the run that would actually happen
    rather than an idealised one. It differs in one way, and the difference is
    stated rather than hidden: capabilities come from what the target *declares*
    without being asked, so an endpoint that turns out not to support tool calls
    will skip more rules than this predicted.
    """
    capabilities = target.capabilities()
    selected: list[str] = []
    skipped: list[str] = []
    unknown: list[str] = []
    ceiling = 0
    for rule in registry.rules():
        meta = rule.meta
        if meta.target_kind != target.kind or not profile.policy.matches(meta.id):
            continue
        if meta.required_capabilities - capabilities:
            skipped.append(meta.id)
            continue
        selected.append(meta.id)
        declared = rule.estimated_requests
        if declared is None:
            unknown.append(meta.id)
        else:
            ceiling += declared
    return RunPlan(
        rules=tuple(selected),
        skipped=tuple(skipped),
        unknown_cost=tuple(unknown),
        # Every selected rule sends at least one request; the ceiling is the sum of
        # what they declared. A rule that declares nothing widens the gap between
        # the two, which is exactly what `unknown_cost` is there to make visible.
        min_requests=len(selected),
        max_requests=ceiling,
        budgets=profile.budgets,
    )
