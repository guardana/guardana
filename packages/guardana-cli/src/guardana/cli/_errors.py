from collections.abc import Callable
from typing import TypeVar
from urllib.error import URLError

import typer
from guardana.core.target import EndpointError

_CONNECTION_EXIT_CODE = 2

T = TypeVar("T")


def run_against_endpoint(url: str, action: Callable[[], T]) -> T:
    """Run `action`, turning endpoint connection/response failures into a clean CLI error.

    Catches network failures (`OSError`/`URLError`) and malformed responses
    (`EndpointError`), prints a one-line message to stderr, and exits with code 2 —
    distinct from the gate's exit 1 ("ran, found blocking issues").
    """
    try:
        return action()
    except (URLError, OSError, EndpointError) as exc:
        typer.echo(f"error: could not reach endpoint {url}: {exc}", err=True)
        raise typer.Exit(code=_CONNECTION_EXIT_CODE) from exc
