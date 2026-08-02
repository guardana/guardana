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
    if before.manifest.target.kind != after.manifest.target.kind:
        raise IncomparableRunsError(
            f"the runs examined different kinds of target "
            f"({before.manifest.target.kind} and {after.manifest.target.kind}) — "
            f"there is nothing to compare between them"
        )
    _refuse_if_out_of_order(before, after)
    diff = compare(
        before.result,
        after.result,
        before_context=RunContext(root=before.manifest.target.ref, rules=_digests(before)),
        after_context=RunContext(root=after.manifest.target.ref, rules=_digests(after)),
    )
    notes = (
        _target_note(before, after)
        + _version_note(before, after)
        + _migration_note(before, after)
        + diff.notes
    )
    return RunDiff(changes=diff.changes, unchanged=diff.unchanged, notes=notes)


def _digests(report: RunReport) -> dict[str, str]:
    """Each rule that ran, mapped to the digest of what it was when it ran."""
    return {rule.id: rule.digest for rule in report.manifest.rules}


def _migration_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    """Say so when one side was migrated, rather than letting its gaps read as facts.

    A migrated run carries explicit unknowns where an older schema recorded
    nothing — no usage, no gate verdict. Comparing against it is still worth
    doing; reading its blanks as measurements is not.
    """
    migrated = [
        label
        for label, report in (("first", before), ("second", after))
        if report.manifest.migrated_from is not None
    ]
    if not migrated:
        return ()
    return (
        f"the {' and '.join(migrated)} run(s) were migrated from an older saved-run schema, "
        f"so what they do not record (cost, and the gate verdict) is unknown rather than zero",
    )


def _refuse_if_out_of_order(before: RunReport, after: RunReport) -> None:
    """Refuse a pair given newest-first, rather than reporting its regressions as fixes.

    Only when both runs recorded a time; a run without one is not evidence of
    anything, and inventing an order for it would be worse than not checking.
    """
    started_before, started_after = before.manifest.started_at, after.manifest.started_at
    if started_before is None or started_after is None:
        return
    if started_before > started_after:
        raise IncomparableRunsError(
            f"the run given first ({started_before.isoformat()}) is newer than the one given "
            f"second ({started_after.isoformat()}) — pass them oldest first, or a regression "
            f"reads as a fix"
        )


def _version_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    if before.manifest.guardana.version == after.manifest.guardana.version:
        return ()
    return (
        f"the runs were made by different Guardana versions "
        f"({before.manifest.guardana.version} and {after.manifest.guardana.version}); "
        f"a rule's behaviour may have changed with it, not only the system under test",
    )


def _target_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    if before.manifest.target.ref == after.manifest.target.ref:
        return ()
    return (
        f"the runs examined different targets ({before.manifest.target.ref} and "
        f"{after.manifest.target.ref}) — intended when comparing two models, worth "
        f"a second look otherwise",
    )
