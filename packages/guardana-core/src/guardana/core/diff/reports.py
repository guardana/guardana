"""Comparing two *saved* runs, which know things a bare result does not.

A `ScanResult` cannot say what kind of target it came from or when it was made.
A saved run can, and both are refusals waiting to happen: comparing a file scan
against a live-model probe is meaningless, and a pair handed over in the wrong
order turns a regression into a clean bill of health without anyone noticing.
"""

from guardana.core.diff.compare import RunContext, compare
from guardana.core.diff.errors import IncomparableRunsError
from guardana.core.diff.model import RunDiff
from guardana.core.report import RunReport


def compare_reports(before: RunReport, after: RunReport) -> RunDiff:
    """Compare two saved runs, refusing pairs that cannot honestly be compared.

    Adds two refusals to the ones `compare` already makes: a different kind of
    target, and a pair whose timestamps say they were handed over the wrong way
    round. A note is added — not a refusal — when the tool version differs, since
    a fleet has to be able to upgrade.
    """
    if before.meta.target_kind != after.meta.target_kind:
        raise IncomparableRunsError(
            f"the runs examined different kinds of target "
            f"({before.meta.target_kind} and {after.meta.target_kind}) — "
            f"there is nothing to compare between them"
        )
    _refuse_if_out_of_order(before, after)
    diff = compare(
        before.result,
        after.result,
        before_context=RunContext(root=before.meta.target_ref, rules=before.meta.rules),
        after_context=RunContext(root=after.meta.target_ref, rules=after.meta.rules),
    )
    notes = _target_note(before, after) + _version_note(before, after) + diff.notes
    return RunDiff(changes=diff.changes, unchanged=diff.unchanged, notes=notes)


def _refuse_if_out_of_order(before: RunReport, after: RunReport) -> None:
    """Refuse a pair given newest-first, rather than reporting its regressions as fixes.

    Only when both runs recorded a time; a run without one is not evidence of
    anything, and inventing an order for it would be worse than not checking.
    """
    started_before, started_after = before.meta.started_at, after.meta.started_at
    if started_before is None or started_after is None:
        return
    if started_before > started_after:
        raise IncomparableRunsError(
            f"the run given first ({started_before.isoformat()}) is newer than the one given "
            f"second ({started_after.isoformat()}) — pass them oldest first, or a regression "
            f"reads as a fix"
        )


def _version_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    if before.meta.tool_version == after.meta.tool_version:
        return ()
    return (
        f"the runs were made by different Guardana versions "
        f"({before.meta.tool_version} and {after.meta.tool_version}); a rule's behaviour "
        f"may have changed with it, not only the system under test",
    )


def _target_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    if before.meta.target_ref == after.meta.target_ref:
        return ()
    return (
        f"the runs examined different targets ({before.meta.target_ref} and "
        f"{after.meta.target_ref}) — intended when comparing two models, worth "
        f"a second look otherwise",
    )
