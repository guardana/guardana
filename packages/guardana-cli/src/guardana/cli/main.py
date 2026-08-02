import typer
from guardana.cli.baseline import baseline_app
from guardana.cli.calibrate import calibrate_command
from guardana.cli.diff import diff
from guardana.cli.exit_codes import ExitCode
from guardana.cli.init import init
from guardana.cli.monitor import monitor
from guardana.cli.new_rule import new_rule
from guardana.cli.plan import plan_app
from guardana.cli.probe import probe
from guardana.cli.rules import rules
from guardana.cli.run import run_app
from guardana.cli.scan import scan
from guardana.cli.target import target_app
from guardana.core import __version__


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"guardana {__version__}")
        raise typer.Exit


def _main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    pass


def _use_guardana_exit_code_for_usage_errors() -> None:
    """Make argument-parsing errors exit `3` rather than Click's default of `2`.

    An unknown option or a bad enum value is invalid usage: nothing ran. Exit `2`
    in Guardana's table means "the result could not be established", which is a
    statement about a run that happened — so leaving these at `2` would make the
    documented table untrue for the one class of error every command shares and
    nobody writes by hand.

    Applied to Typer's vendored copy of Click as well as to Click itself, because
    they are different modules and Typer raises from its own. Reaching into a
    private module is not something to do lightly; it is pinned by a test that
    asserts the behaviour rather than the mechanism, so a Typer release that
    rearranges this fails loudly instead of quietly restoring `2`.
    """
    import click  # noqa: PLC0415
    from typer import _click as vendored_click  # noqa: PLC0415

    for module in (click, vendored_click):
        module.exceptions.UsageError.exit_code = int(ExitCode.INVALID_USAGE)


_use_guardana_exit_code_for_usage_errors()

app = typer.Typer(help="Guardana — verify the security of self-hosted/self-built AI.")
app.callback()(_main)
app.command()(scan)
app.command()(init)
app.command()(rules)
app.command()(probe)
app.command()(diff)
app.command()(monitor)
app.command(name="new-rule")(new_rule)
app.command(name="calibrate")(calibrate_command)
app.add_typer(run_app, name="run")
app.add_typer(plan_app, name="plan")
app.add_typer(target_app, name="target")
app.add_typer(baseline_app, name="baseline")
