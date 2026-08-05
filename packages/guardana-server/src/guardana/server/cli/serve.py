"""`serve` — start the collector, without anybody having to know an ASGI factory.

Every other command in this parser runs one statement against the database and
exits. This one does the opposite: it hands the application to a server that
manages its own connections, so it is the one command dispatched without a
connection of its own — a collector must be able to start while its database is
still coming up, and then answer `/readyz` with the truth.

The ASGI server is an **extra** (`guardana-server[serve]`), not a dependency: a
deployment that already runs gunicorn or hypercorn should not be made to install a
second one. The import is therefore late, and its absence is an answer rather than
an ImportError from somewhere in the middle of a start-up sequence.
"""

import argparse
import importlib
from types import ModuleType

from guardana.server.app import create_app
from guardana.server.cli.codes import EXIT_OK

_LOOPBACK = "127.0.0.1"
_DEFAULT_PORT = 8000


class ServerNotInstalledError(RuntimeError):
    """Raised when `serve` is asked for and no ASGI server is installed."""


def add_arguments(commands: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    """Register `serve`."""
    serve = commands.add_parser("serve", help="Run the collector's HTTP API.")
    serve.add_argument(
        "--host",
        default=_LOOPBACK,
        help=(
            f"Interface to bind (default {_LOOPBACK}). Use 0.0.0.0 to accept "
            f"connections from outside this machine — deliberately not the default."
        ),
    )
    serve.add_argument(
        "--port", type=int, default=_DEFAULT_PORT, help=f"Port (default {_DEFAULT_PORT})."
    )
    serve.set_defaults(handler=run, needs_connection=False)


def _uvicorn() -> ModuleType:
    try:
        return importlib.import_module("uvicorn")
    except ImportError as exc:
        raise ServerNotInstalledError(
            'no ASGI server is installed. Install one with: pip install "guardana-server[serve]" '
            "— or run the app yourself with any ASGI server: "
            "gunicorn -k uvicorn.workers.UvicornWorker 'guardana.server:create_app()'"
        ) from exc


def run(arguments: argparse.Namespace) -> int:
    """Build the app — refusing here, in words, if it cannot be built — and serve it.

    The app is constructed *before* the server starts rather than passed as a
    factory string, so a storage backend nobody chose and a collector that could
    authenticate nobody are reported by this command, with this command's exit
    codes, instead of surfacing as a traceback from inside a worker.
    """
    server = _uvicorn()
    app = create_app()
    server.run(app, host=arguments.host, port=arguments.port)
    return EXIT_OK
