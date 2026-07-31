"""Assemble the `run` block a saved run carries.

Built here rather than in the runner because the circumstances of a run are the
command's knowledge, not the engine's: which profile the user named, which
version of the tool this is, and what time it is. The engine stays a library that
does not consult a clock.
"""

from datetime import UTC, datetime

from guardana.core import __version__
from guardana.core.profile import Profile
from guardana.core.registry import Registry
from guardana.core.report import RunMeta, ScanResult
from guardana.core.target import TargetKind


def build_run_meta(
    registry: Registry,
    profile: Profile,
    result: ScanResult,
    *,
    target_kind: TargetKind,
    target_ref: str,
) -> RunMeta:
    """Describe the run that produced `result`, digesting the rules that actually ran.

    Only the rules that ran are digested. A rule that was skipped or errored did
    not test anything, and listing it as part of the plan would let a later
    comparison treat a check that never happened as coverage it had.
    """
    digests = {
        rule.meta.id: rule.digest() for rule in registry.rules() if rule.meta.id in result.rules_run
    }
    return RunMeta(
        tool_version=__version__,
        target_kind=target_kind,
        target_ref=target_ref,
        profile=profile.name,
        rules=digests,
        rules_skipped=result.rules_skipped,
        started_at=datetime.now(UTC),
    )
