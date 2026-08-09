"""Reading a trace for a command, and saying out loud what reading it could not do.

Every function here exists because the same sentence has to be true of both trace
commands: what a run over a recording is entitled to claim is bounded by what the
producer recorded, and those bounds belong on the operator's screen rather than in a
document they have not read.
"""

from pathlib import Path

import typer
from guardana.cli.exit_codes import ExitCode
from guardana.core.report import CheckError, ScanResult
from guardana.core.target import TraceTarget
from guardana.core.trace import Dialect, TraceLoadError, TraceRead, read_trace

_LOAD_STAGE = "load"


def load_trace_or_exit(path: Path, dialect: Dialect | None) -> TraceRead:
    """Read a trace, or exit `3` naming what was wrong with the file.

    A trace that cannot be read is invalid input rather than an indeterminate result:
    nothing ran. The one thing this must never do is return an empty trace, because a
    run over one reports "no findings" and exits `0` — a mistyped path gating a build
    on nothing at all, which is the worst shape of false green this project has.
    """
    if not path.exists():
        typer.echo(f"error: {path} does not exist, so there is no trace to analyse", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE)
    if path.is_dir():
        typer.echo(f"error: {path} is a directory; pass one JSONL trace file", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE)
    try:
        return read_trace(path, dialect)
    except TraceLoadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE) from exc


def trace_source(read: TraceRead) -> str:
    """Say which dialect the file was read as, and how much of it arrived.

    Printed on every run, because dialect detection is load-bearing for
    correctness: a file read as the wrong dialect yields a partial trace, and a
    partial trace grades clean. An operator who can see what it was read as can
    correct it with `--dialect`.
    """
    trace = read.trace
    return (
        f"read {len(trace.spans)} span(s) from {trace.provenance.source} as "
        f"{trace.provenance.dialect} (producer: {trace.provenance.producer})"
    )


def record_errors(result: ScanResult, read: TraceRead) -> ScanResult:
    """Put every unreadable record into the `errors` channel.

    Not a warning on stderr. A dropped record is a step that disappears, and
    `fail_on_error` — on by default — is what turns that into an indeterminate result
    instead of a report that reads complete. A CI log nobody greps is not a control.
    """
    if not read.unreadable:
        return result
    errors = tuple(
        CheckError(
            source=f"{read.trace.provenance.source}:{record.line}",
            stage=_LOAD_STAGE,
            reason=record.reason,
        )
        for record in read.unreadable
    )
    return ScanResult.merged([result, ScanResult((), (), (), errors=errors)])


def describe_coverage(read: TraceRead, target: TraceTarget) -> list[str]:
    """Say what this trace could not answer, and why that is not a pass.

    Three separate facts, and each one is a different reason a clean report means
    less than it looks like it means.
    """
    lines: list[str] = []
    trace = read.trace
    if trace.truncated is not None:
        lines.append(
            f"note: the trace is incomplete ({trace.truncated}) — a rule that found nothing "
            f"reports inconclusive rather than a pass, because the step it needed may be in "
            f"the part that is missing"
        )
    if read.unreadable:
        lines.append(
            f"warning: {len(read.unreadable)} record(s) could not be read and are in the "
            f"errors channel; the execution graded here is missing them"
        )
    missing = target.missing_dimensions()
    if missing:
        lines.append(
            f"note: this producer does not record {', '.join(str(d) for d in missing)} — the "
            f"rules needing those dimensions were skipped rather than reporting nothing found. "
            f"Set fail_on_skipped to treat that as indeterminate"
        )
    unreadable_parts = trace.unreadable_parts()
    if unreadable_parts:
        lines.append(
            f"note: {unreadable_parts} message part(s) are carriers this build cannot examine "
            f"as text (images, audio, opaque types); they are kept in the trace and no "
            f"text-reading rule saw inside them"
        )
    return lines
