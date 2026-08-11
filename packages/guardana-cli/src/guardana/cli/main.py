import typer
from guardana.cli.analyze_trace import analyze_trace
from guardana.cli.baseline import baseline_app
from guardana.cli.calibrate import calibrate_command
from guardana.cli.config import config_app
from guardana.cli.diff import diff
from guardana.cli.doctor import doctor
from guardana.cli.exit_codes import ExitCode
from guardana.cli.import_observations import import_observations
from guardana.cli.init import init
from guardana.cli.monitor import monitor
from guardana.cli.new_rule import new_rule
from guardana.cli.pack import pack_app
from guardana.cli.plan import plan_app
from guardana.cli.probe import probe
from guardana.cli.rule import rule_app
from guardana.cli.rules import rules
from guardana.cli.run import run_app
from guardana.cli.scan import scan
from guardana.cli.target import target_app
from guardana.cli.taxonomy import taxonomy
from guardana.cli.trace import trace_app
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

    Applied to whichever Click a given Typer actually raises from, because that
    moved: Typer **0.26** vendored Click as `typer._click` and dropped the
    standalone dependency, so importing `click` unconditionally crashes every
    command on a clean install of a current Typer — while importing only the
    vendored one crashes on anything older. Both are patched when both are there,
    and neither is required to be.

    Reaching into a private module is not something to do lightly; it is pinned by
    a test that asserts the behaviour rather than the mechanism, so a Typer release
    that rearranges this fails loudly instead of quietly restoring `2`.

    Finding none of them **raises**. The exit-code table is a contract a pipeline
    gates on, and a table the tool silently stops honouring is worse than one it
    never promised.
    """
    import importlib  # noqa: PLC0415

    patched = 0
    for name in ("typer._click", "click"):
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        module.exceptions.UsageError.exit_code = int(ExitCode.INVALID_USAGE)
        patched += 1
    if not patched:
        raise RuntimeError(
            "neither typer._click nor click could be imported, so a usage error would "
            f"exit 2 instead of {int(ExitCode.INVALID_USAGE)} and the documented exit-code "
            "table would be untrue"
        )


_use_guardana_exit_code_for_usage_errors()

app = typer.Typer(help="Guardana — verify the security of self-hosted/self-built AI.")
app.callback()(_main)
app.command()(scan)
app.command()(init)
app.command()(rules)
app.command()(taxonomy)
app.command()(probe)
app.command()(diff)
app.command()(monitor)
app.command(name="analyze-trace")(analyze_trace)
app.command(name="import-observations")(import_observations)
app.command(name="new-rule")(new_rule)
app.command(name="calibrate")(calibrate_command)
app.add_typer(run_app, name="run")
app.add_typer(plan_app, name="plan")
app.add_typer(target_app, name="target")
app.add_typer(baseline_app, name="baseline")
app.add_typer(config_app, name="config")
app.add_typer(trace_app, name="trace")
app.add_typer(rule_app, name="rule")
app.add_typer(pack_app, name="pack")
app.command()(doctor)
