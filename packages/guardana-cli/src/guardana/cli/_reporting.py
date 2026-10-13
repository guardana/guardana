import json
import os
from urllib.error import HTTPError, URLError

import typer
from guardana.core.manifest import DeploymentRef, RunManifest
from guardana.core.output import RESERVED_REPORTER_NAMES, is_output_name, sanitise_reason
from guardana.core.report import ScanResult
from guardana.core.reporter import (
    HttpReporter,
    UnacknowledgedSubmissionError,
    check_collector_url,
)
from guardana.core.target import EndpointError

_SERVER_SCHEME = "server://"
TOKEN_VARIABLE = "GUARDANA_COLLECTOR_TOKEN"  # noqa: S105 — the name of a variable, not a value
"""Where the collector's API key is read from.

An environment variable and deliberately not a flag. A credential on a command
line lands in shell history, in `ps`, and in the echoed command of most CI logs —
which is why `probe` takes `--api-key-env` rather than `--api-key`, and this
follows the same rule one step further by naming the variable itself.
"""

# Only a collector being unreachable, or answering without acknowledging, is a
# failed delivery. A bad URL (ValueError from HttpReporter) is a usage error, and a
# serialization bug is our bug — neither should be swallowed as a collector outage.
_NOT_DELIVERED = (OSError, URLError, EndpointError, UnacknowledgedSubmissionError)


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


def split_reporter(value: str | None) -> tuple[str, str] | None:
    """Return `(name, rest)` when `value` names an installed reporter as `<name>://<rest>`.

    None for every collector value, so `check_reporter_url` keeps its path and its
    message for a bare URL, a `server://` one and a `host:port`. A misspelt scheme such
    as `htps://` is split, and its selection names the collector forms.
    """
    if value is None:
        return None
    name, separator, rest = value.partition("://")
    if not separator or not is_output_name(name) or name in RESERVED_REPORTER_NAMES:
        return None
    return name, rest


def installed_reporter_or_check(value: str | None) -> tuple[str, str] | None:
    """Split an installed reporter off `value`, or check `value` as a collector URL.

    Returns what `split_reporter` returns; a collector value that cannot name a
    collector is refused as `check_reporter_url` refuses it.
    """
    split = split_reporter(value)
    if split is None:
        check_reporter_url(value)
    return split


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


_MAX_DETAIL_BYTES = 64 * 1024
"""The most of a collector's error body read for its explanation; a longer one gives none."""


def _why(exc: HTTPError) -> str:
    """Return the collector's own explanation, or a fallback that does not invent one."""
    try:
        body = exc.read(_MAX_DETAIL_BYTES + 1)
        parsed = json.loads(body) if len(body) <= _MAX_DETAIL_BYTES else None
        detail = parsed.get("detail") if isinstance(parsed, dict) else None
    except (ValueError, OSError, RecursionError):
        detail = None
    if isinstance(detail, str) and detail:
        return detail
    return f"{exc.reason} — check that its schema version matches this agent's"


def submit_safely(  # noqa: PLR0913 — a destination, a run, and whether it must arrive
    url: str,
    result: ScanResult,
    *,
    source: str,
    deployment: DeploymentRef | None = None,
    run: RunManifest | None = None,
    required: bool = False,
) -> bool:
    """Forward findings to a collector and return whether it acknowledged them.

    A collector that rejects, cannot be reached, or answers without acknowledging is said
    as a warning, or as an error when the profile sets `delivery.required` (`required`),
    with what it said sanitised: the collector token withheld, secrets redacted, control
    characters dropped;
    the caller decides the exit, since the scan already ran and its verdict stands on its
    own. A bad `--reporter` URL or a bug in serialization is not an outage; those
    propagate so the user actually learns their findings are not being collected.
    """
    level, suffix = (
        ("error", " — the profile sets delivery.required") if required else ("warning", "")
    )
    # What comes back is written by the other side, which can echo the credential it was
    # sent or carry escape sequences, so it is printed only once sanitised.
    token = os.environ.get(TOKEN_VARIABLE)
    secrets = (token,) if token else ()
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
            f"{level}: the collector rejected this submission (HTTP {exc.code}): "
            f"{sanitise_reason(_why(exc), secrets)}{suffix}",
            err=True,
        )
        return False
    except _NOT_DELIVERED as exc:
        typer.echo(
            f"{level}: could not submit to reporter: {sanitise_reason(str(exc), secrets)}{suffix}",
            err=True,
        )
        return False
    return True
