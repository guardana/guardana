from urllib.error import URLError

import typer
from guardana.core.report import ScanResult
from guardana.core.reporter import HttpReporter
from guardana.core.target import EndpointError

_SERVER_SCHEME = "server://"

# Only a collector being unreachable is a "degrade to a warning" event. A bad
# URL (ValueError from HttpReporter) is a usage error, and a serialization bug
# is our bug — neither should be silently swallowed as "collector outage".
_COLLECTOR_UNREACHABLE = (OSError, URLError, EndpointError)


def reporter_from_url(url: str) -> HttpReporter:
    """Build the `HttpReporter` for a `--reporter` CLI flag value.

    Accepts either a bare collector URL or one prefixed with the `server://` scheme.
    """
    target = url.removeprefix(_SERVER_SCHEME)
    return HttpReporter(target)


def submit_safely(url: str, result: ScanResult, *, source: str) -> None:
    """Forward findings to a collector, degrading to a warning if it is unreachable.

    A collector outage must never change the gate's exit code — the scan already
    ran and its verdict stands on its own. But a bad `--reporter` URL or a bug in
    serialization is not an outage; those propagate so the user actually learns
    their findings are not being collected.
    """
    try:
        reporter_from_url(url).submit(result, source=source)
    except _COLLECTOR_UNREACHABLE as exc:
        typer.echo(f"warning: could not submit to reporter: {exc}", err=True)
