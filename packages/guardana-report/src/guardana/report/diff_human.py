"""A comparison, for a person reading a CI log.

Regressions first and in full, because that is what someone scrolling a failed
build is looking for. Improvements below, so a run is allowed to be good news.
Notes last and never instead of a change — a caveat that displaces the finding it
qualifies is a caveat nobody reads.
"""

from guardana.core.diff import Change, ChangeKind, RunDiff

_MARK = {True: "✖", False: "✓"}


class DiffHumanRenderer:
    """Human-readable comparison of two runs."""

    name = "human"

    def render(self, diff: RunDiff) -> str:
        """Render one comparison to text."""
        regressions, improvements = diff.regressions, diff.improvements
        other = tuple(
            c for c in diff.changes if not c.kind.is_regression and not c.kind.is_improvement
        )
        blocks: list[str] = []
        if diff.incomplete:
            # First, above everything. A reader who stops after the first block
            # must not walk away with a verdict this comparison cannot give.
            blocks.append(
                "⚠ This comparison is incomplete\n"
                + "\n".join(f"  • {reason}" for reason in diff.incomplete)
            )
        if regressions:
            blocks.append(_section("Worse than the previous run", regressions, worse=True))
        if improvements:
            blocks.append(_section("Better", improvements, worse=False))
        if other:
            blocks.append(_section("Also changed", other, worse=False))
        measured = _measurement(diff)
        if measured:
            blocks.append(measured)
        if diff.notes:
            blocks.append("Worth knowing\n" + "\n".join(f"  • {note}" for note in diff.notes))
        if not regressions and not diff.incomplete:
            blocks.append("✓ No regression against the previous run.")
        blocks.append(
            f"{len(diff.changes)} change(s); {diff.unchanged} check(s) unchanged, "
            f"{len(regressions)} worse."
        )
        return "\n\n".join(blocks)


def _measurement(diff: RunDiff) -> str:
    """Render the measured sample, or nothing when neither run measured anything.

    Printed as counts and never as a single percentage. A pass rate with no
    denominator beside it is the number this whole channel exists to stop being
    quoted: 100% of the two cases a broken judge still managed to grade reads
    exactly like 100% of four hundred.
    """
    m = diff.measurement
    if not (m.paired or m.incomparable or m.only_before or m.only_after):
        return ""
    lines = [
        f"Measured cases\n  {m.paired} case(s) compared like for like: "
        f"{m.passed_before} → {m.passed_after} passing"
    ]
    if m.incomparable:
        lines.append(f"  {m.incomparable} not compared (the assessor or dataset changed)")
    if m.only_before or m.only_after:
        lines.append(f"  {m.only_before} gone, {m.only_after} new")
    return "\n".join(lines)


def _section(title: str, changes: tuple[Change, ...], *, worse: bool) -> str:
    """Render one group, printing a repeated explanation once rather than per line.

    Turning off a profile's rules produces one lost-coverage entry per rule, each
    with the same sentence attached. Eighteen copies of it is how a real signal
    starts looking like boilerplate to skip.
    """
    lines = [f"{title} ({len(changes)})"]
    previous_detail = ""
    for change in changes:
        lines.append(f"  {_MARK[worse]} [{_label(change)}] {change.rule_id}{_where(change)}")
        if change.detail != previous_detail:
            lines.append(f"      {change.detail}")
            previous_detail = change.detail
        if change.rule_changed:
            lines.append("      note: this rule's own definition changed between the two runs")
    return "\n".join(lines)


def _label(change: Change) -> str:
    """Name the movement, with the severity when there is one to name.

    `COVERAGE_LOST` deliberately has none: the whole point is that nobody knows
    what the rule would have found, so borrowing a severity from somewhere would
    be inventing the number.
    """
    if change.kind is ChangeKind.COVERAGE_LOST:
        return "NOT RUN"
    state = change.after or change.before
    severity = state.severity.name if state is not None else "?"
    return f"{change.kind.value.replace('_', ' ').upper()} · {severity}"


def _where(change: Change) -> str:
    return f" — {change.location}" if change.location else ""
