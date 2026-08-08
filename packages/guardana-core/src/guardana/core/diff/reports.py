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
        before_context=_context(before),
        after_context=_context(after),
    )
    notes = (
        _target_note(before, after)
        + _version_note(before, after)
        + _coverage_note(before, after)
        + _migration_note(before, after)
        + diff.notes
    )
    return RunDiff(
        changes=diff.changes,
        unchanged=diff.unchanged,
        notes=notes,
        incomplete=diff.incomplete,
    )


def _context(report: RunReport) -> RunContext:
    """Describe one side of the comparison: what it examined, with which rules, from which build."""
    return RunContext(
        root=report.manifest.target.ref,
        rules={rule.id: rule.digest for rule in report.manifest.rules},
        tool_version=report.manifest.guardana.version,
    )


def _coverage_note(before: RunReport, after: RunReport) -> tuple[str, ...]:
    """Say when the two runs could check different things, and name what moved.

    A run with a narrower reach reports fewer findings, and subtracting two lists
    cannot tell that from a fix. The rule list alone never could: it says nothing
    about a rule whose corpus was trimmed, an evaluator that stopped being
    installed, a target that lost a capability, or a server that answered with an
    older protocol revision. The fingerprint covers all of those in one value.

    A run that recorded no fingerprint is *unknown*, never "the same": saying
    nothing changed about coverage nobody measured is the shape of false green this
    project refuses everywhere else.
    """
    first, second = before.manifest.coverage, after.manifest.coverage
    if first.digest is None or second.digest is None:
        return (
            "one of the runs records no coverage fingerprint, so whether the two verified "
            "the same amount is unknown rather than settled — re-run the older side to compare "
            "reach as well as findings",
        )
    if first.digest == second.digest:
        return ()
    return (
        f"the two runs did not have the same reach{_coverage_detail(before, after)} — "
        f"a difference in findings may be a difference in what could be checked",
    )


def _coverage_detail(before: RunReport, after: RunReport) -> str:
    """Name the catalogues and protocols that moved, so the note is actionable.

    Silent about the rest of the fingerprint on purpose: a differing digest whose
    catalogues and protocols match means the rules, their trial counts, the
    evaluators or the target's capabilities moved, and `diff` already reports those
    per rule. Restating them here in the aggregate would be the same finding twice.
    """
    parts = []
    catalogues = _changed_catalogues(before, after)
    if catalogues:
        parts.append(f"framework catalogue(s) {', '.join(catalogues)} differ")
    if before.manifest.coverage.protocols != after.manifest.coverage.protocols:
        parts.append(
            f"negotiated protocols went from {before.manifest.coverage.protocols or 'none'} "
            f"to {after.manifest.coverage.protocols or 'none'}"
        )
    return f" ({'; '.join(parts)})" if parts else ""


def _changed_catalogues(before: RunReport, after: RunReport) -> list[str]:
    first = {c.framework: c.digest for c in before.manifest.coverage.taxonomies}
    second = {c.framework: c.digest for c in after.manifest.coverage.taxonomies}
    return sorted(name for name in first | second if first.get(name) != second.get(name))


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
