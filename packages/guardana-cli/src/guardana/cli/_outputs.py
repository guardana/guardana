"""The format a run writes and the installed reporter it delivers to, chosen before the run.

Selection runs before discovery and before anything is sent, so every refusal is an
exit `3` that cost nothing. From the moment a reporter is prepared, `RunOutputs` guards
its delivery line: the command prints exactly one, whether it delivered or ended first.
"""

import os
from pathlib import Path
from types import TracebackType
from typing import NoReturn, Self

import typer
from guardana.cli._exit import exit_with, print_debug_traceback
from guardana.cli._formats import OutputFormat, format_name, is_built_in_format, resolve_format
from guardana.cli._output import emit
from guardana.cli._plugins import admission_forms
from guardana.cli._reporting import split_reporter
from guardana.cli._sidecar import digest_of
from guardana.cli.exit_codes import ExitCode, code_for
from guardana.core.budget import BudgetExhausted
from guardana.core.gate import GateOutcome
from guardana.core.origin import Origin
from guardana.core.output import (
    BoundaryError,
    Delivery,
    DeliveryStatus,
    OutputError,
    OutputSelectionError,
    OutputSelectionKind,
    PreparedReporter,
    SelectedRenderer,
    deliver,
    format_delivery_line,
    render,
    sanitise_reason,
    select_reporter,
)
from guardana.core.plugins import PluginTrust
from guardana.core.verify import (
    UnenforceableBudgetError,
    Verification,
    exchanges_path,
    exchanges_recorded_by,
    recorded_by_partner,
)
from guardana.report import get_renderer

MONITOR_REFUSAL = (
    "monitor runs cycles, not a saved run; an installed reporter runs with scan, probe or "
    "analyze-trace"
)
"""Why `monitor` refuses an installed reporter."""

IMPORT_REFUSAL = "import-observations loads no plugins; it forwards to the collector only"
"""Why `import-observations` refuses an installed reporter."""

NOT_PRODUCED = "the run's report was not produced"
_DEFECT = "this is a defect in Guardana"


def refuse_selection(exc: OutputSelectionError) -> typer.Exit:
    """Print a refused selection as `error: <message>` and return the exit `3` to raise.

    A trust refusal is followed by the ways to admit the distribution, narrowest first.
    """
    lines = [f"error: {exc.message}"]
    if exc.kind is OutputSelectionKind.REFUSED:
        first, *rest = admission_forms(list(exc.distributions))
        lines.append(f"  to load it, state the trust, narrowest first: {first}")
        lines.extend(f"    or {form}" for form in rest)
    typer.echo("\n".join(lines), err=True)
    return typer.Exit(code=ExitCode.INVALID_USAGE)


def _unsupported(name: str, message: str) -> typer.Exit:
    return refuse_selection(OutputSelectionError(OutputSelectionKind.UNSUPPORTED, name, message))


def refuse_installed_reporter(reporter: str | None, why: str) -> None:
    """Exit `3` when `reporter` names an installed reporter this command cannot run.

    Decided from the value alone: no metadata is read and nothing is imported.
    """
    split = split_reporter(reporter)
    if split is not None:
        raise _unsupported(split[0], why)


def refuse_installed_output_beside(
    flag: str, given: object, output_format: str, reporter: tuple[str, str] | None
) -> None:
    """Exit `3` when `flag` was `given` beside an installed format or reporter.

    The flag makes the command write something other than the run's report, which an
    installed output needs.
    """
    if given is None:
        return
    if reporter is not None:
        name = reporter[0]
    elif not is_built_in_format(output_format):
        name = output_format
    else:
        return
    raise _unsupported(
        name, f"an installed output needs the run's report, which {flag} does not produce"
    )


def refuse_collector_beside(flag: str, given: object, *, collector: bool) -> None:
    """Exit `3` when `flag` was `given` beside a collector `--reporter`, whatever the profile says.

    The flag ends the command before a report exists, so nothing would be forwarded and a
    required delivery would pass with nothing delivered.
    """
    if given is not None and collector:
        raise _unsupported(
            "server", f"the collector needs the run's report, which {flag} does not produce"
        )


def refuse_output_beside(flag: str, given: object, output: Path | None) -> None:
    """Exit `3` when `flag` was `given` beside `--output`, which the flag never writes.

    The flag ends the command before a report exists, so an earlier run left at `output`
    would later be read as this one.
    """
    if given is not None and output is not None:
        typer.echo(
            f"error: {flag} writes no report, so --output {output} would be left as it is "
            f"— pass one or the other",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INVALID_USAGE)


def warn_without_a_reporter(delivery_required: bool, reporter: str | None) -> None:
    """Say once on stderr that the profile requires a delivery this run cannot make."""
    if delivery_required and not reporter:
        typer.echo(
            "warning: the profile sets delivery.required, and this run names no --reporter",
            err=True,
        )


def select_outputs(
    output_format: str,
    reporter: tuple[str, str] | None,
    trust: PluginTrust,
    *,
    collector: bool = False,
) -> "RunOutputs":
    """Select the format and the installed reporter under `trust`, or exit `3` saying why.

    `reporter` is what `split_reporter` returned; a collector value is not selected here,
    and `collector` says whether the run forwards to one after its report is produced.
    """
    try:
        chosen = resolve_format(output_format, trust)
        prepared = None if reporter is None else select_reporter(reporter[0], reporter[1], trust)
    except OutputSelectionError as exc:
        raise refuse_selection(exc) from exc
    return RunOutputs(chosen, prepared, collector=collector)


def _distribution(origin: Origin) -> str:
    return origin.describe() if origin.distribution is not None else "an unnamed distribution"


def _why(exc: BaseException | None) -> str:
    """Say why a command that ended before delivering sent nothing."""
    if isinstance(exc, KeyboardInterrupt):
        return "the run was interrupted"
    if isinstance(exc, typer.Exit):
        if isinstance(exc.__cause__, BudgetExhausted | UnenforceableBudgetError):
            return "the budget was refused before sending"
        if exc.exit_code == ExitCode.TARGET_UNAVAILABLE:
            return "the target or judge was unavailable"
        if exc.exit_code == ExitCode.INVALID_USAGE:
            return "the run was refused before sending"
    if isinstance(exc, typer.BadParameter):
        return "the run was refused before sending"
    return "the run ended before its report was produced"


class RunOutputs:
    """What one run writes and where it delivers, and the guard of its delivery line.

    Entered right after selection: a command that leaves the block without delivering
    prints `delivery: not_sent` with the reason, never twice and never after a delivery.
    `collector` says whether the run forwards to the built-in collector once its report
    is produced.
    """

    def __init__(
        self,
        chosen: OutputFormat | SelectedRenderer,
        reporter: PreparedReporter | None,
        *,
        collector: bool = False,
    ) -> None:
        self.format = chosen
        self.reporter = reporter
        self.collector = collector
        self._delivery: Delivery | None = None
        self._settled = reporter is None
        self._delivering = False

    @property
    def format_name(self) -> str:
        """The name the format was selected by."""
        return format_name(self.format)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._settled:
            return
        if self._delivering:
            # Interrupted mid-delivery: whether anything left the machine is not known.
            self._line(Delivery(DeliveryStatus.UNKNOWN, detail="the run was interrupted"))
            return
        self.not_sent(_why(exc))

    def not_sent(self, why: str) -> None:
        """Print the `not_sent` line once, if a reporter was selected and nothing settled it."""
        if self._settled:
            return
        self._line(Delivery(DeliveryStatus.NOT_SENT, detail=why))

    def _line(self, delivery: Delivery) -> None:
        self._settled = True
        if self.reporter is not None:
            line = format_delivery_line(self.reporter.name, self.reporter.destination, delivery)
            typer.echo(line, err=True)

    def write(
        self, verification: Verification, output: Path | None, *, keeps_exchanges: bool = False
    ) -> None:
        """Render the run in the selected format and print it or write it to `output`.

        Once the report is written, exchanges an earlier run kept beside `output` are
        removed, unless `keeps_exchanges` says the caller writes this run's own there.
        An installed format that fails ends the command: the verdict is printed, nothing is
        written, and the exit is `8` unless the run stopped. When Guardana's own redaction
        fails for it, the exit is `5` unless the run stopped. Either way the file at
        `output`, and the exchanges kept beside it, are removed unless this process may not
        write to them, which keeps them with a warning. A report that cannot be written
        exits `3` and removes nothing.
        """
        name = self.format_name
        if isinstance(self.format, OutputFormat):
            renderer = get_renderer(name, run=verification.manifest)
            rendered, verbatim = renderer.render(verification.result), False
        else:
            rendered, verbatim = self._rendered(self.format, verification, output), True
        try:
            emit_report(
                rendered,
                output,
                self.format_name,
                verbatim=verbatim,
                keeps_exchanges=keeps_exchanges,
            )
        except typer.Exit:
            self.not_sent("the run's report could not be written")
            raise

    def _rendered(
        self, chosen: SelectedRenderer, verification: Verification, output: Path | None
    ) -> str:
        """Render the run in the installed format, or end the command as `write` says."""
        try:
            rendered = render(chosen, verification)
        except BoundaryError as exc:
            print_debug_traceback(exc.__cause__ or exc)
            _print_verdict(verification)
            typer.echo(
                f"error: the run could not be redacted for the format {exc.name}: {exc.reason} "
                f"— nothing was written; {_DEFECT}",
                err=True,
            )
            _remove_earlier(output)
            self._not_produced(verification, ExitCode.INTERNAL_ERROR)
        except OutputError as exc:
            self._failed(exc, verification, output)
        return rendered

    def _failed(
        self, exc: OutputError, verification: Verification, output: Path | None
    ) -> NoReturn:
        owner = exc.origin.distribution or "the distribution that installed it"
        _print_verdict(verification)
        typer.echo(
            f"error: the format {exc.name} from {_distribution(exc.origin)} failed: "
            f"{sanitise_reason(exc.reason)} — nothing was written; report it to {owner}",
            err=True,
        )
        _remove_earlier(output)
        self._not_produced(verification, ExitCode.OUTPUT_FAILED)

    def end_unwritten(self, verification: Verification, why: str) -> NoReturn:
        """Say nothing was sent because `why`, then exit `3` unless the run stopped."""
        self.not_sent(why)
        raise typer.Exit(code=_unless_stopped(verification, ExitCode.INVALID_USAGE))

    def _not_produced(self, verification: Verification, code: ExitCode) -> NoReturn:
        """Say the report was not produced to the reporter or collector, then exit with `code`."""
        self.not_sent(NOT_PRODUCED)
        if self.collector:
            typer.echo(f"warning: nothing was forwarded to the collector: {NOT_PRODUCED}", err=True)
        raise typer.Exit(code=_unless_stopped(verification, code))

    def deliver(self, verification: Verification) -> Delivery | None:
        """Deliver the run to the selected reporter and print its line; None without a reporter.

        When Guardana's own redaction fails for the reporter, nothing is sent, the verdict
        is printed and the exit is `5` unless the run stopped.
        """
        if self.reporter is None:
            return None
        self._delivering = True
        try:
            delivery = deliver(self.reporter, verification)
        except BoundaryError as exc:
            self._delivering = False
            print_debug_traceback(exc.__cause__ or exc)
            _print_verdict(verification)
            typer.echo(
                f"error: the run could not be redacted for the reporter {exc.name}: "
                f"{exc.reason} — nothing was sent; {_DEFECT}",
                err=True,
            )
            self._line(Delivery(DeliveryStatus.NOT_SENT, detail=f"redaction failed: {exc.reason}"))
            raise typer.Exit(code=_unless_stopped(verification, ExitCode.INTERNAL_ERROR)) from exc
        self._delivering = False
        self._line(delivery)
        self._delivery = delivery
        return delivery

    def end(
        self,
        verification: Verification,
        *,
        delivery_required: bool = False,
        collector_acknowledged: bool | None = None,
    ) -> None:
        """End with the run's code, or `8` when a delivery failed and no stop outranks it.

        A delivery fails when the reporter's status is `unknown`, and, with
        `delivery_required`, when it is anything but `delivered` or the collector did not
        acknowledge (`collector_acknowledged` False; None when nothing was forwarded). The
        verdict is printed whenever `8` replaces its code.
        """
        failed = self._delivery is not None and self._delivery.status is DeliveryStatus.UNKNOWN
        if delivery_required:
            if self._delivery is not None and self._delivery.status is not DeliveryStatus.DELIVERED:
                typer.echo(
                    f"error: the profile sets delivery.required, and the delivery was "
                    f"{self._delivery.status}",
                    err=True,
                )
                failed = True
            failed = failed or collector_acknowledged is False
        if failed:
            _end_unacknowledged(verification)
        exit_with(verification.gate, verification.result)


def emit_report(
    rendered: str,
    output: Path | None,
    output_format: str,
    *,
    verbatim: bool = False,
    keeps_exchanges: bool = False,
) -> None:
    """Print a run's report or write it to `output`, beside no other run's exchanges.

    Once written, exchanges the run it replaced kept beside `output` are removed unless
    `keeps_exchanges` says the caller writes this run's own there. A write that fails
    exits `3` as `emit` does and removes nothing, since what is at `output` may be no run.
    """
    owned = earlier_run_kept(output) if output is not None else None
    emit(rendered, output, output_format, verbatim=verbatim)
    if output is not None and not keeps_exchanges:
        remove_earlier_exchanges(output, owned=owned)


def _remove_earlier(output: Path | None) -> None:
    """Remove what this run did not write at `output` and beside it, and say so.

    A file this process may not write to is kept, with a warning: it was protected, and
    nothing says it holds a run.
    """
    if output is None:
        return
    if _protected(output):
        return
    owned = earlier_run_kept(output)
    _remove(
        output,
        removed=f"removed {output}: this run did not write it",
        kept=f"{output} still holds what was there before this run",
    )
    remove_earlier_exchanges(output, owned=owned, keep_protected=True)


def earlier_run_kept(output: Path) -> str | None:
    """Return the digest of the exchanges beside `output` the run saved there records, if any.

    Only the run being replaced can establish that the sidecar was an earlier run's, so a
    caller asks before it writes or removes anything at `output`.
    """
    return exchanges_recorded_by(output)


def remove_earlier_exchanges(
    output: Path, *, owned: str | None, keep_protected: bool = False
) -> None:
    """Remove the exchanges the replaced run at `output` kept beside it, or warn that they remain.

    `owned` is `earlier_run_kept(output)`, read before `output` was replaced, and the sidecar
    is removed only while it still holds those bytes. Any other file there is kept, and said
    to be: its name alone says nothing of whose it is. `run` and `run.json` share one
    sidecar, so exchanges the other of the two recorded are kept too. With `keep_protected`,
    a sidecar this process may not write to is kept as well, with a warning.
    """
    sidecar = exchanges_path(output)
    partner = recorded_by_partner(output)
    if partner is not None:
        typer.echo(f"warning: kept {sidecar}: it holds the exchanges {partner} recorded", err=True)
        return
    if owned is None or digest_of(sidecar) != owned:
        if sidecar.is_file() or sidecar.is_symlink():
            typer.echo(
                f"warning: kept {sidecar}: no run saved at {output} before this one recorded "
                f"it, so it is not an earlier run's exchanges",
                err=True,
            )
        return
    if keep_protected and _protected(sidecar):
        return
    _remove(
        sidecar,
        removed=f"removed {sidecar}, which an earlier run at this path kept",
        kept=f"{sidecar} still holds exchanges an earlier run kept, not this run's",
    )


def _protected(path: Path) -> bool:
    """Return whether `path` is an existing file this process may not write to, warning if so.

    Removing a file needs only the directory's permission, so the file's own decides.
    """
    if not path.is_file() or os.access(path, os.W_OK):
        return False
    typer.echo(
        f"warning: kept {path}: it is not writable, so it still holds what was there "
        f"before this run",
        err=True,
    )
    return True


def _remove(path: Path, *, removed: str, kept: str) -> None:
    """Remove `path` if a file or link is there and print `removed`, or warn that it is `kept`."""
    if not (path.is_file() or path.is_symlink()):
        return
    try:
        path.unlink()
    except OSError as exc:
        typer.echo(f"warning: {kept}: could not remove it: {exc}", err=True)
        return
    typer.echo(removed, err=True)


def _end_unacknowledged(verification: Verification) -> NoReturn:
    """Exit `8` for a failed delivery with the verdict printed, or with the stop's code."""
    code = _unless_stopped(verification, ExitCode.OUTPUT_FAILED)
    if code is ExitCode.OUTPUT_FAILED:
        _print_verdict(verification)
    raise typer.Exit(code=code)


def print_verdict(outcome: GateOutcome, code: ExitCode) -> None:
    """Print the line that says which verdict, and which code, a replaced exit stands for."""
    typer.echo(f"the run's verdict: {outcome} (exit {int(code)})", err=True)


def _print_verdict(verification: Verification) -> None:
    print_verdict(verification.gate, code_for(verification.gate, verification.result.stopped_by))


def _unless_stopped(verification: Verification, code: ExitCode) -> ExitCode:
    """Return `code`, or the stop's code when the run stopped: a stop outranks the output."""
    if verification.result.stopped_by is not None:
        return code_for(verification.gate, verification.result.stopped_by)
    return code


__all__ = [
    "IMPORT_REFUSAL",
    "MONITOR_REFUSAL",
    "NOT_PRODUCED",
    "RunOutputs",
    "emit_report",
    "print_verdict",
    "refuse_collector_beside",
    "refuse_installed_output_beside",
    "refuse_installed_reporter",
    "refuse_selection",
    "select_outputs",
    "warn_without_a_reporter",
]
