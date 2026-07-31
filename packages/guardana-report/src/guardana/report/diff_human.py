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
        if regressions:
            blocks.append(_section("Worse than the previous run", regressions, worse=True))
        if improvements:
            blocks.append(_section("Better", improvements, worse=False))
        if other:
            blocks.append(_section("Also changed", other, worse=False))
        if diff.notes:
            blocks.append("Worth knowing\n" + "\n".join(f"  • {note}" for note in diff.notes))
        if not regressions:
            blocks.append("✓ No regression against the previous run.")
        blocks.append(
            f"{len(diff.changes)} change(s); {diff.unchanged} check(s) unchanged, "
            f"{len(regressions)} worse."
        )
        return "\n\n".join(blocks)


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
