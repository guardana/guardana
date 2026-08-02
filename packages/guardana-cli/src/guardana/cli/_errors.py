from collections.abc import Callable
from typing import TypeVar
from urllib.error import HTTPError, URLError

import typer
from guardana.cli.exit_codes import ExitCode
from guardana.core.target import EndpointError

_HTTP_CLIENT_ERROR = 400
_HTTP_RATE_LIMITED = 429
_HTTP_SERVER_ERROR = 500

T = TypeVar("T")


def run_against_endpoint(url: str, action: Callable[[], T]) -> T:
    """Run `action`, turning endpoint connection/response failures into a clean CLI error.

    Catches network failures (`URLError`/`OSError`) and malformed responses
    (`EndpointError`), prints a one-line message to stderr, and exits with
    `TARGET_UNAVAILABLE` — the user's environment, kept apart from the gate's
    "ran, found blocking issues" and from our own defects. A 4xx is
    reported distinctly from an unreachable host: a rejected request usually means
    a wrong auth header or body, not a down endpoint.
    """
    try:
        return action()
    except HTTPError as exc:
        if exc.code == _HTTP_RATE_LIMITED:
            # Reaching here means the retries were already exhausted, so this is a
            # sustained limit rather than a blip. Naming the knob beats the generic
            # 4xx advice, which would send someone to check an auth header that is
            # working fine.
            message = (
                f"endpoint {url} kept rate-limiting the probe (HTTP 429) even after retries — "
                f"lower --concurrency, or wait for the quota to reset"
            )
        elif _HTTP_CLIENT_ERROR <= exc.code < _HTTP_SERVER_ERROR:
            message = (
                f"endpoint {url} rejected the request (HTTP {exc.code}) — "
                f"check the auth header / body (an --adapter's headers, or --api-key-env)"
            )
        else:
            message = f"endpoint {url} returned HTTP {exc.code}"
        typer.echo(f"error: {message}", err=True)
        raise typer.Exit(code=ExitCode.TARGET_UNAVAILABLE) from exc
    except (URLError, OSError, EndpointError) as exc:
        typer.echo(f"error: could not reach endpoint {url}: {exc}", err=True)
        raise typer.Exit(code=ExitCode.TARGET_UNAVAILABLE) from exc
