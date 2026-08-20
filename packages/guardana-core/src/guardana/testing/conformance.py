"""Prove a custom `Target` actually satisfies what it declares.

The extension contract has two halves. `Capability` is the half a target
declares, and until 0.22 it was the only half that existed: the surface a rule
would call was undocumented, so `docs/extending.md` said a target with
`READ_FILES` "can run all 19 build-time artifact rules unmodified" while every
one of those rules asked whether it was an `ArtifactTarget` and refused it.

This is how a third party checks the other half without installing Guardana's
test suite or reading its rules. It is deliberately in the shipped package, not
in `tests/`: a conformance kit somebody has to vendor is a conformance kit
nobody runs.
"""

from guardana.core.target import Target
from guardana.core.target.protocols import CAPABILITY_SURFACE, unmet_surfaces


class TargetContractError(AssertionError):
    """A target's declared capabilities and its actual surface disagree."""


def assert_target_conforms(target: Target) -> None:
    """Refuse a target whose declarations and surface do not match, in either direction.

    Both directions are checked, and the second is the one that is easy to miss.
    A target that *under*-declares — it implements `iter_files` and forgets
    `READ_FILES` — is not broken in any way a run will report: the runner simply
    skips every rule that needed it, the scan comes back clean, and the missing
    coverage looks like a healthy target. That is a fail-open, and it is silent.

        >>> from guardana.testing.conformance import assert_target_conforms
        >>> assert_target_conforms(MyTarget("s3://models/"))   # doctest: +SKIP

    Raises `TargetContractError` naming every mismatch, so one run of this says
    everything that is wrong rather than one thing per fix-and-retry.
    """
    declared = target.capabilities()
    problems = [f"declares {unmet} but does not implement it" for unmet in unmet_surfaces(target)]
    problems.extend(
        f"implements {surface.__name__} but does not declare {capability} — "
        f"every rule needing it will be skipped and the run will look clean"
        for capability, surface in sorted(CAPABILITY_SURFACE.items())
        if capability not in declared and isinstance(target, surface)
    )
    if not target.ref:
        problems.append("has an empty `ref`, so its findings cannot name what they are about")
    if problems:
        raise TargetContractError(
            f"{type(target).__name__} does not satisfy the target contract:\n  "
            + "\n  ".join(problems)
        )
