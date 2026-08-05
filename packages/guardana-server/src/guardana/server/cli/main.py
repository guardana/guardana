"""The `guardana-collector` parser: one connection, one table of exit codes.

Every command group registers itself and sets its own handler, so adding one never
means editing a dispatch chain that somebody has to remember to extend.
"""

import argparse
import sys
from collections.abc import Sequence

from guardana.server.cli import inventory, keys, schema, tenants
from guardana.server.cli.codes import EXIT_FAILED, EXIT_INVALID_USAGE, EXIT_OK
from guardana.server.db.migrations import MigrationError
from guardana.server.db.settings import StorageNotConfiguredError, resolve_storage
from guardana.server.tenancy import TenancyError

_DESCRIPTION = (
    "Apply, inspect and undo the collector's schema; manage its tenants and "
    "credentials; read back what runs have reported."
)
_ARGPARSE_USAGE_EXIT = 2


def _connection_url() -> str:
    choice = resolve_storage()
    if choice.database_url is None:
        raise StorageNotConfiguredError(
            "this command needs a PostgreSQL connection string; GUARDANA_STORAGE=memory "
            "has no schema to migrate"
        )
    return choice.database_url


def build_parser() -> argparse.ArgumentParser:
    """Assemble the whole command surface from the three command groups."""
    parser = argparse.ArgumentParser(prog="guardana-collector", description=_DESCRIPTION)
    commands = parser.add_subparsers(dest="command", required=True)
    schema.add_arguments(commands)
    tenants.add_arguments(commands)
    keys.add_arguments(commands)
    inventory.add_arguments(commands)
    return parser


def _parse(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse arguments, translating argparse's usage exit into this product's code.

    Argparse exits `2` on a bad flag; the table the rest of the tool uses says `3`.
    An exit-code table the tool itself does not honour is a contract a pipeline
    cannot gate on, and translating once here covers every flag on every command.
    `--help` still exits `0`.
    """
    try:
        return build_parser().parse_args(argv)
    except SystemExit as requested:
        if requested.code == _ARGPARSE_USAGE_EXIT:
            raise SystemExit(EXIT_INVALID_USAGE) from None
        raise


def main(argv: Sequence[str] | None = None) -> int:
    """Run a collector command. Returns the exit code rather than raising."""
    arguments = _parse(argv)

    try:
        url = _connection_url()
    except StorageNotConfiguredError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_USAGE

    from psycopg import connect  # noqa: PLC0415 — imported here so --help needs no database

    try:
        with connect(url) as connection:
            return int(arguments.handler(arguments, connection))
    except TenancyError as exc:
        # Naming a tenant that does not exist, or a slug that is not one, is a usage
        # error: the command was pointed at nothing.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_USAGE
    except MigrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except Exception as exc:  # a connection that cannot be made is not a usage error
        print(f"error: could not reach the database: {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":  # pragma: no cover — the console-script entry point covers this
    raise SystemExit(main())


__all__ = ["EXIT_FAILED", "EXIT_INVALID_USAGE", "EXIT_OK", "build_parser", "main"]
