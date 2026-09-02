"""`guardana trace inspect` — what a recorded execution can answer, before anything grades it.

Opens one file and no socket, writes no run document, and reaches no network. It
exists because the trace design's central mechanism — a producer that does not
record a dimension stops the rules needing it from running — was visible only as a
skip note *after* a run. An operator cannot gate on evidence they can only see once
a rule has already been missed.
"""

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from guardana.cli._plugins import resolve_trust, warn_about_load_errors
from guardana.cli._profile import resolve_profile
from guardana.cli._rules_loading import load_custom_rules
from guardana.cli._trace_input import load_trace_or_exit, trace_source
from guardana.core.registry import Registry
from guardana.core.rule import Rule
from guardana.core.target import Capability, TargetKind, dimensions_of
from guardana.core.trace import Dialect, Dimension, DimensionCoverage, Trace, evidence_matrix

trace_app = typer.Typer(help="Inspect a recorded execution without grading it.")


class InspectFormat(StrEnum):
    """How `guardana trace inspect` prints the evidence matrix."""

    human = "human"
    json = "json"


@trace_app.command()
def inspect(  # noqa: PLR0913, PLR0917 — one typer.Option per CLI flag; the command's surface
    trace: Annotated[Path, typer.Argument(help="JSONL trace file to inspect")],
    dialect: Annotated[
        Dialect | None,
        typer.Option(
            "--dialect",
            help="guardana|otel. Detected from the file's first record when not given.",
        ),
    ] = None,
    profile: Annotated[Path | None, typer.Option(help="guardana.yaml path")] = None,
    preset: Annotated[
        str | None, typer.Option(help="Named policy preset: ci|pre-training|monitor")
    ] = None,
    format: Annotated[InspectFormat, typer.Option(help="human|json")] = InspectFormat.human,
    plugins: Annotated[
        str,
        typer.Option(help="Which installed plugins to load: all|builtins|allowlist|disabled"),
    ] = "all",
    allow_plugin: Annotated[
        list[str],
        typer.Option("--allow-plugin", help="Distribution to trust; repeatable, needs allowlist."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
    rules: Annotated[
        list[Path],
        typer.Option("--rules", help="Directory or file of custom YAML rules; repeatable."),
    ] = [],  # noqa: B006 — typer builds the option from a literal default
) -> None:
    """Print which evidence dimensions this trace carries, and which rules they license.

    Pass `--profile` to see whether the dimensions that profile requires are
    actually there: this is the command that answers "would my gate go indeterminate"
    before a pipeline finds out.
    """
    prof = resolve_profile(profile, preset)
    read = load_trace_or_exit(trace, dialect)
    registry = Registry.discover(resolve_trust(plugins, allow_plugin, no_plugins=False))
    warn_about_load_errors(registry, what="rule")
    load_custom_rules(registry, prof, rules)
    matrix = evidence_matrix(read.trace)
    licensed = _licensed_rules(registry)
    unlocked = _unlocked_rules(registry, read.trace.instrumented)
    required = frozenset(prof.required_dimensions)
    # A restrictive `--plugins` mode can empty `_trace_rules(registry)` entirely,
    # and every "needed by"/"unlocks" cell reads `0 rule(s)` identically whether
    # nothing needs a dimension or nothing was loaded to ask. This count is what
    # lets the render tell those two apart instead of reading like a clean matrix.
    trace_rule_count = len(_trace_rules(registry))
    if format is InspectFormat.json:
        document = _document(read.trace, matrix, licensed, unlocked, required, trace_rule_count)
        typer.echo(json.dumps(document, indent=2))
        return
    typer.echo(trace_source(read))
    typer.echo("")
    for line in _table(matrix, licensed, unlocked, required):
        typer.echo(line)
    for line in _notes(read.trace, matrix, required, trace_rule_count):
        typer.echo(line)


def _licensed_rules(registry: Registry) -> dict[str, tuple[str, ...]]:
    """Which installed rules each dimension is needed by, keyed by dimension name.

    Counted from the registry rather than from a written-down list, so a rule pack a
    team installed is included and the number cannot rot the way a hand-maintained
    table does. A dimension no installed rule needs reports none, which is honest and
    immediately useful: it says the evidence would buy nothing here today.

    **Needed by, not unlocked by.** A rule wanting two dimensions is counted under both
    of them, so this number alone cannot answer "what do I instrument next" —
    `_unlocked_rules` answers that, and the gap between the two is the useful part.
    """
    licensed: dict[str, list[str]] = {}
    for rule in _trace_rules(registry):
        for dimension in _dimensions_of(rule.meta.required_capabilities):
            licensed.setdefault(dimension, []).append(rule.meta.id)
    return {name: tuple(sorted(ids)) for name, ids in licensed.items()}


def _unlocked_rules(
    registry: Registry, declared: frozenset[Dimension]
) -> dict[str, tuple[str, ...]]:
    """Which rules recording *this one further dimension* would actually make runnable.

    A rule is unlocked by a dimension exactly when that dimension is the only one it
    still lacks — so an assertion needing approvals *and* side effects unlocks under
    neither on its own, and an operator budgeting instrumentation work sees that before
    they do it rather than after. Counting "needs it" alone told them the opposite.
    """
    unlocked: dict[str, list[str]] = {}
    for rule in _trace_rules(registry):
        needed = {str(d) for d in dimensions_of(rule.meta.required_capabilities)}
        missing = needed - {str(d) for d in declared}
        if len(missing) == 1:
            unlocked.setdefault(missing.pop(), []).append(rule.meta.id)
    return {name: tuple(sorted(ids)) for name, ids in unlocked.items()}


def _trace_rules(registry: Registry) -> list[Rule]:
    return [rule for rule in registry.rules() if rule.meta.target_kind is TargetKind.TRACE]


def _dimensions_of(capabilities: frozenset[Capability]) -> list[str]:
    """Which dimensions a rule's capability set corresponds to, via the one shared table."""
    return [str(d) for d in dimensions_of(capabilities)]


def _table(
    matrix: tuple[DimensionCoverage, ...],
    licensed: dict[str, tuple[str, ...]],
    unlocked: dict[str, tuple[str, ...]],
    required: frozenset[Dimension],
) -> list[str]:
    """Render the matrix as aligned columns, one row per dimension and no total.

    **No coverage percentage, deliberately.** One number is compatible with having no
    identity evidence whatsoever, and a team gating on a number rather than on a name
    ships the day the missing part is the part that mattered.

    Two rule counts rather than one, because they answer different questions and the
    old single column silently answered the wrong one. `needed by` is how many rules
    read this dimension; `unlocks` is how many would start running if this were the
    next thing instrumented. They differ wherever a rule wants two dimensions, and
    `needed by 1 / unlocks 0` is the row that says "this one needs a partner".
    """
    rows = [("dimension", "declared", "records", "required", "needed by", "unlocks")]
    rows += [
        (
            str(row.dimension),
            "yes" if row.declared else "no",
            str(row.records),
            "yes" if row.dimension in required else "-",
            f"{len(licensed.get(str(row.dimension), ()))} rule(s)",
            # Nothing to buy where the evidence is already there, and printing `0` for
            # a dimension the producer records would read as "worthless" rather than
            # as "already counted".
            "-" if row.declared else f"{len(unlocked.get(str(row.dimension), ()))} rule(s)",
        )
        for row in matrix
    ]
    widths = [max(len(cell) for cell in column) for column in zip(*rows, strict=True)]
    return [
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip()
        for row in rows
    ]


def _notes(
    trace: Trace,
    matrix: tuple[DimensionCoverage, ...],
    required: frozenset[Dimension],
    trace_rule_count: int,
) -> list[str]:
    """Say what a clean-looking matrix still does not mean."""
    lines = [""]
    if trace_rule_count == 0:
        # The equivalent of `target inspect`'s three-way branch: an empty
        # "needed by"/"unlocks" column is not a clean result here either, and
        # must not be read as "no dimension here is worth instrumenting" when
        # the real cause is that no trace rule was loaded to ask in the first
        # place. Said in-band, not only on stderr, because this table is the
        # thing an operator reads on its own to decide what to instrument next.
        lines.append(
            "note: 0 rule(s) were loaded to judge this trace against — every "
            "'needed by' and 'unlocks' count above is not a clean 0, it is an "
            "absence of evidence: nothing here says a dimension is not worth "
            "instrumenting"
        )
    missing = [row.dimension for row in matrix if row.is_gap and row.dimension in required]
    if missing:
        lines.append(
            f"error: this profile requires {', '.join(str(d) for d in missing)}, which this "
            f"producer does not record — `guardana analyze-trace` on this file is "
            f"indeterminate, never a pass"
        )
    elif required:
        lines.append(
            f"ok: every dimension this profile requires "
            f"({', '.join(sorted(str(d) for d in required))}) is recorded here"
        )
    gaps = [row.dimension for row in matrix if row.is_gap]
    if gaps:
        lines.append(
            f"note: {', '.join(str(d) for d in gaps)} are not recorded at all, so the rules "
            f"needing them do not run — their silence is not evidence that nothing happened"
        )
    if trace.truncated is not None:
        lines.append(
            f"note: the trace is incomplete ({trace.truncated}), so a step this file does "
            f"not contain may still have happened"
        )
    return lines


def _document(  # noqa: PLR0913, PLR0917 — one already-computed report fact per argument
    trace: Trace,
    matrix: tuple[DimensionCoverage, ...],
    licensed: dict[str, tuple[str, ...]],
    unlocked: dict[str, tuple[str, ...]],
    required: frozenset[Dimension],
    trace_rule_count: int,
) -> dict[str, object]:
    """Build the machine-readable matrix — the same facts, named rather than aligned.

    `trace_rules_loaded` carries the correction `_notes` prints for the human
    table: an empty `licenses`/`unlocks` list reads the same for "nothing needs
    this" and "nothing was loaded to ask" unless a consumer can check this count
    first.
    """
    return {
        "trace_id": trace.trace_id,
        "source": trace.provenance.source,
        "dialect": trace.provenance.dialect,
        "producer": trace.provenance.producer,
        "spans": len(trace.spans),
        "truncated": None if trace.truncated is None else str(trace.truncated),
        "trace_rules_loaded": trace_rule_count,
        "dimensions": [
            {
                "dimension": str(row.dimension),
                "declared": row.declared,
                "records": row.records,
                "required": row.dimension in required,
                "licenses": list(licensed.get(str(row.dimension), ())),
                # Additive beside `licenses`, which keeps its meaning: every rule that
                # reads this dimension. This is the subset that has nothing else
                # missing, which is the one a team deciding what to instrument needs.
                "unlocks": [] if row.declared else list(unlocked.get(str(row.dimension), ())),
            }
            for row in matrix
        ],
    }


__all__ = ["trace_app"]
