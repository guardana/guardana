"""Prove a custom `Target` actually satisfies what it declares.

`Capability` is what a target declares; a protocol in
`guardana.core.target.protocols` is what a rule will call. This checks that the
two agree, from a third party's own test suite.

Deliberately in the shipped package rather than in `tests/`: a conformance kit
somebody has to vendor is a conformance kit nobody runs.
"""

from typing import TYPE_CHECKING

from guardana.core.target import Capability, EndpointTarget, Target, ToolCallingTransport
from guardana.core.target.base import REQUESTED_CAPABILITIES
from guardana.core.target.protocols import CAPABILITY_SURFACE, FileReader, unmet_surfaces

if TYPE_CHECKING:
    from pathlib import Path

_SUFFIX_SAMPLE = 5
"""How many distinct suffixes of the target's own files the suffix-case check asks about."""


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
        if capability not in declared
        and isinstance(target, surface)
        and not _fixed_at_construction(target, capability)
    )
    if not target.ref:
        problems.append("has an empty `ref`, so its findings cannot name what they are about")
    if isinstance(target, FileReader):
        problems.extend(_suffix_case_problems(target))
    if problems:
        raise TargetContractError(
            f"{type(target).__name__} does not satisfy the target contract:\n  "
            + "\n  ".join(problems)
        )


def _fixed_at_construction(target: Target, capability: Capability) -> bool:
    """Whether how the target was built, not its class, decides that it lacks `capability`.

    A requested capability is declared only when the run asks for the check that needs it,
    so a target offering the surface without declaring it is the default, not a fail-open.
    `EndpointTarget` always has `offer_tools`, and declares `CALL_TOOLS` only when the
    transport it was built with speaks the function-calling API, the way it declares
    `PLANT_SYSTEM_PROMPT` only when built with a system prompt. A subclass that replaces
    `offer_tools` offers tools its own way, so it must declare the capability.
    """
    if capability in REQUESTED_CAPABILITIES:
        return True
    return (
        capability is Capability.CALL_TOOLS
        and isinstance(target, EndpointTarget)
        and type(target).offer_tools is EndpointTarget.offer_tools
        and not isinstance(target.transport, ToolCallingTransport)
    )


def _suffix_case_problems(target: FileReader) -> list[str]:
    """Name each of the target's own files that a suffix asked in another case leaves out.

    A rule asks for `.pkl` and a loader opens `model.PKL` all the same, so a target that
    filters by exact case hands that file to no rule and the scan reads clean.
    """
    sample: dict[str, Path] = {}
    for path in target.iter_files():
        if path.suffix and path.suffix not in sample:
            sample[path.suffix] = path
            if len(sample) == _SUFFIX_SAMPLE:
                break
    return [
        f"iter_files(({asked!r},)) leaves out {path.name} — suffixes compare in any case, "
        f"so every rule asking for {asked!r} would skip it and the run would look clean"
        for suffix, path in sample.items()
        for asked in sorted({suffix.lower(), suffix.upper()})
        if path not in target.iter_files((asked,))
    ]
