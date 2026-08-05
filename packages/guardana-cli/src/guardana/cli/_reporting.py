import json
import os
from urllib.error import HTTPError, URLError

import typer
from guardana.core.manifest import DeploymentRef, RunManifest
from guardana.core.report import ScanResult
from guardana.core.reporter import HttpReporter, check_collector_url
from guardana.core.target import EndpointError

_SERVER_SCHEME = "server://"
TOKEN_VARIABLE = "GUARDANA_COLLECTOR_TOKEN"  # noqa: S105 — the name of a variable, not a value
"""Where the collector's API key is read from.

An environment variable and deliberately not a flag. A credential on a command
line lands in shell history, in `ps`, and in the echoed command of most CI logs —
which is why `probe` takes `--api-key-env` rather than `--api-key`, and this
follows the same rule one step further by naming the variable itself.
"""

# Only a collector being unreachable is a "degrade to a warning" event. A bad
# URL (ValueError from HttpReporter) is a usage error, and a serialization bug
# is our bug — neither should be silently swallowed as "collector outage".
_COLLECTOR_UNREACHABLE = (OSError, URLError, EndpointError)


def reporter_from_url(
    url: str, deployment: DeploymentRef | None = None, run: RunManifest | None = None
) -> HttpReporter:
    """Build the `HttpReporter` for a `--reporter` CLI flag value.

    Accepts either a bare collector URL or one prefixed with the `server://` scheme,
    and carries the API key from `GUARDANA_COLLECTOR_TOKEN` when one is set, plus
    what the run says it verified and where. A
    collector that requires a key answers `401` without it, which `submit_safely`
    reports as a rejection rather than as an outage — so a fleet that has not been
    given its credential says so instead of going quiet.
    """
    target = url.removeprefix(_SERVER_SCHEME)
    return HttpReporter(
        target,
        api_key=os.environ.get(TOKEN_VARIABLE) or None,
        deployment=deployment,
        run=run,
    )


def check_reporter_url(url: str | None) -> None:
    """Refuse a `--reporter` value that cannot name a collector, before the run starts.

    Up front rather than at submission time, because the submission is the last
    thing a run does: a probe that spends its whole budget and only then discovers
    the URL was a typo has verified something and told nobody. Raised as a usage
    error, so it exits `3` like every other bad flag instead of ending the run with
    a rendered traceback and a code outside the documented table.
    """
    if url is None:
        return
    try:
        check_collector_url(url.removeprefix(_SERVER_SCHEME))
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--reporter") from exc


def _why(exc: HTTPError) -> str:
    """Return the collector's own explanation, or a fallback that does not invent one."""
    try:
        detail = json.loads(exc.read()).get("detail")
    except (ValueError, OSError):
        detail = None
    if isinstance(detail, str) and detail:
        return detail
    return f"{exc.reason} — check that its schema version matches this agent's"


def submit_safely(
    url: str,
    result: ScanResult,
    *,
    source: str,
    deployment: DeploymentRef | None = None,
    run: RunManifest | None = None,
) -> None:
    """Forward findings to a collector, degrading to a warning if it is unreachable.

    A collector outage must never change the gate's exit code — the scan already
    ran and its verdict stands on its own. But a bad `--reporter` URL or a bug in
    serialization is not an outage; those propagate so the user actually learns
    their findings are not being collected.
    """
    try:
        reporter_from_url(url, deployment, run).submit(result, source=source)
    except HTTPError as exc:
        # A rejected envelope is not an outage — swallowing it as "unreachable" is
        # how a whole fleet can stop reporting while the dashboard keeps showing
        # stale data as current. The collector's own sentence is preferred over a
        # guess at why: a key pinned to another environment answers `403` with the
        # reason, and telling that operator to "check the schema version" sends
        # them after the wrong thing entirely — the same mistake as reading a
        # database outage as a rejected credential.
        typer.echo(
            f"warning: the collector rejected this submission (HTTP {exc.code}): {_why(exc)}",
            err=True,
        )
    except _COLLECTOR_UNREACHABLE as exc:
        typer.echo(f"warning: could not submit to reporter: {exc}", err=True)
