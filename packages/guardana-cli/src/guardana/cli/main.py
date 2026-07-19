import typer
from guardana.cli.init import init
from guardana.cli.monitor import monitor
from guardana.cli.new_rule import new_rule
from guardana.cli.probe import probe
from guardana.cli.rules import rules
from guardana.cli.scan import scan
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


app = typer.Typer(help="Guardana — verify the security of self-hosted/self-built AI.")
app.callback()(_main)
app.command()(scan)
app.command()(init)
app.command()(rules)
app.command()(probe)
app.command()(monitor)
app.command(name="new-rule")(new_rule)
