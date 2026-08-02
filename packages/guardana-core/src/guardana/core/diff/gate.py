"""Whether a comparison should stop a deployment.

The mirror of `runner.gate`, and the place where a threshold is most tempting to
apply too widely: the two changes that say "we no longer know" carry no evidence
to threshold *on*, so a policy that filtered everything by confidence would
quietly switch them off.
"""

from guardana.core.diff.model import ChangeKind, RunDiff
from guardana.core.profile.model import Policy

_NO_EVIDENCE_TO_WEIGH = frozenset({ChangeKind.BLINDED, ChangeKind.COVERAGE_LOST})
"""Regressions that report an absence of knowledge rather than a graded verdict.

An unverified result carries confidence 0.0 by definition — that is what
"could not tell" means — and a rule that did not run carries no severity at all.
Applying `min_confidence` to these would mean that raising a policy's confidence
bar silently disables exactly the two signals that say a check stopped working.
"""


def gate_diff(diff: RunDiff, policy: Policy) -> bool:
    """Decide whether this comparison should fail the build.

    A regression counts when it clears the policy's severity bar, and — for the
    regressions backed by a graded verdict — its confidence bar. A rule that ran
    before and not now always counts: what it would have found is unknown, and an
    unknown of unknown severity cannot be thresholded away.

    An incomplete comparison — either side stopped part-way — fails before any
    threshold is consulted. There is no verdict to weigh when half the picture was
    never taken.
    """
    # Before any threshold: a comparison that could not be made in full has no
    # verdict to threshold. No policy setting can wave this through, deliberately
    # — otherwise a spent budget would become a way to quiet a red comparison.
    if diff.incomplete:
        return True
    threshold = policy.fail_on
    for change in diff.changes:
        if not change.kind.is_regression:
            continue
        if change.kind is ChangeKind.COVERAGE_LOST:
            return True
        state = change.after
        if state is None or state.severity < threshold.severity:
            continue
        if change.kind in _NO_EVIDENCE_TO_WEIGH:
            return True
        if state.confidence >= threshold.min_confidence:
            return True
    return False
