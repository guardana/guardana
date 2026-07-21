from collections.abc import Callable
from typing import TypeVar
from urllib.error import HTTPError, URLError

import typer
from guardana.core.target import EndpointError

_CONNECTION_EXIT_CODE = 2
_HTTP_CLIENT_ERROR = 400
_HTTP_SERVER_ERROR = 500

T = TypeVar("T")


def run_against_endpoint(url: str, action: Callable[[], T]) -> T:
    """Run `action`, turning endpoint connection/response failures into a clean CLI error.

    Catches network failures (`URLError`/`OSError`) and malformed responses
    (`EndpointError`), prints a one-line message to stderr, and exits with code 2 —
    distinct from the gate's exit 1 ("ran, found blocking issues"). A 4xx is
    reported distinctly from an unreachable host: a rejected request usually means
    a wrong auth header or body, not a down endpoint.
    """
    try:
        return action()
    except HTTPError as exc:
        if _HTTP_CLIENT_ERROR <= exc.code < _HTTP_SERVER_ERROR:
            message = (
                f"endpoint {url} rejected the request (HTTP {exc.code}) — "
                f"check the auth header / body (an --adapter's headers, or --api-key-env)"
            )
        else:
            message = f"endpoint {url} returned HTTP {exc.code}"
        typer.echo(f"error: {message}", err=True)
        raise typer.Exit(code=_CONNECTION_EXIT_CODE) from exc
    except (URLError, OSError, EndpointError) as exc:
        typer.echo(f"error: could not reach endpoint {url}: {exc}", err=True)
        raise typer.Exit(code=_CONNECTION_EXIT_CODE) from exc
