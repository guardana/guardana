"""The exchanges a probe keeps beside its saved run, as every command that reads one finds it."""

import hashlib
from collections.abc import Iterable
from pathlib import Path

import typer
from guardana.cli.exit_codes import ExitCode
from guardana.core.recording import Recording
from guardana.core.report import ReportLoadError, load_report
from guardana.core.verify import exchanges_path, exchanges_recorded_by

_SIDECAR_SUFFIX = ".exchanges.jsonl"


def same_file(path: Path, other: Path) -> bool:
    """Whether two paths name one file, also through another case or a hard link."""
    try:
        return path.samefile(other)
    except OSError:
        return path.resolve() == other.resolve()


def refuse_writing_over_an_input(
    output: Path | None,
    inputs: Iterable[Path | None],
    *,
    what: str | None = None,
    in_place: bool = False,
) -> None:
    """Exit `3` when the report at `output` would replace or remove a file the command reads.

    Writing a report removes the exchanges an earlier run kept beside it, which can be an
    input. `what` describes the input in the message, which otherwise names it; `in_place`
    lets `output` be the input itself. A directory is not an input here.
    """
    if output is None:
        return
    for given in inputs:
        if given is None or given.is_dir():
            continue
        described = what or f"{given}, which this command reads"
        if not in_place and same_file(output, given):
            problem = f"--output {output} is {described}, and the report would replace it"
        elif same_file(exchanges_path(output), given):
            problem = (
                f"{given} is where a run saved at {output} keeps its exchanges, and "
                f"writing the report there would remove {what or 'it'}"
            )
        else:
            continue
        typer.echo(f"error: {problem} — choose another --output", err=True)
        raise typer.Exit(code=ExitCode.INVALID_USAGE)


def refuse_writing_over_named_inputs(
    output: Path | None, named: Iterable[tuple[str, Path | None]]
) -> None:
    """Exit `3` as `refuse_writing_over_an_input` does, naming the flag or key behind each file."""
    for name, given in named:
        if given is not None:
            refuse_writing_over_an_input(output, [given], what=f"{given}, which {name} names")


def kept_by_a_run(sidecar: Path) -> bool:
    """Whether a saved run beside `sidecar` (`run.json` or `run`) records exactly its bytes."""
    return any(exchanges_recorded_by(run) is not None for run in runs_beside(sidecar))


def digest_of(path: Path) -> str | None:
    """Return the sha256 digest of the file at `path` as a run records it, or None if unreadable."""
    try:
        with path.open("rb") as handle:
            return f"sha256:{hashlib.file_digest(handle, 'sha256').hexdigest()}"
    except OSError:
        return None


def runs_beside(recording: Path) -> tuple[Path, ...]:
    """Return the saved runs a probe could have kept `recording` beside, `run.json` first.

    `run.json` and `run` both keep their exchanges in `run.exchanges.jsonl`. Names are
    matched as the directory spells them, so a filesystem that ignores case never pairs a
    sidecar with another spelling of its run.
    """
    try:
        names = {entry.name for entry in recording.parent.iterdir()}
    except OSError:
        return ()
    name = _spelled_on_disk(recording, names)
    if name is None or len(name) <= len(_SIDECAR_SUFFIX):
        return ()
    if not name.lower().endswith(_SIDECAR_SUFFIX):
        return ()
    base = name[: -len(_SIDECAR_SUFFIX)]
    candidates = (recording.with_name(candidate) for candidate in (f"{base}.json", base))
    return tuple(
        run
        for run in candidates
        if run.name in names and run.is_file() and same_file(exchanges_path(run), recording)
    )


def _spelled_on_disk(path: Path, names: set[str]) -> str | None:
    """Return the name the directory lists for `path`, which may differ from it in case."""
    if path.name in names:
        return path.name
    folded = path.name.lower()
    return next(
        (
            name
            for name in sorted(names)
            if name.lower() == folded and same_file(path.with_name(name), path)
        ),
        None,
    )


def warn_unless_its_run_recorded(path: Path, recording: Recording) -> None:
    """Warn when no run beside a probe's sidecar records these exchanges.

    Silent when either run sharing the sidecar records them; otherwise the first run found
    is named. A warning and never a refusal: the recording is graded as given, and one with
    no run beside it is read as any recording is.
    """
    read = recording.digest
    digest = read.digest if read is not None else "not digested"
    problems = [_problem(path, run, digest) for run in runs_beside(path)]
    if problems and all(problem is not None for problem in problems):
        _warn(str(problems[0]))


def _problem(path: Path, run: Path, digest: str) -> str | None:
    """Say why `run` does not vouch for the sidecar at `path`, or None when it records `digest`."""
    try:
        record = load_report(run).manifest.exchanges
    except ReportLoadError as exc:
        return f"{path} could not be checked against {run}: {exc}"
    if record is None:
        return f"{run} records no exchanges, so {path} beside it is not that run's"
    if digest != record.digest:
        return (
            f"{path} is not the exchanges {run} kept: the run records {record.digest}, "
            f"the file is {digest}"
        )
    return None


def _warn(problem: str) -> None:
    typer.echo(f"warning: {problem}; grading it as given", err=True)
