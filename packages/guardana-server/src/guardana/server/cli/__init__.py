"""`guardana-collector` — the collector's schema, tenants and credentials.

A package rather than one module: migrations, tenants and keys are three
responsibilities, and a file that grows a fourth stops being readable in review.
The console-script entry point (`guardana.server.cli:main`) is unchanged.
"""

from guardana.server.cli.codes import EXIT_FAILED, EXIT_INVALID_USAGE, EXIT_OK
from guardana.server.cli.main import main

__all__ = ["EXIT_FAILED", "EXIT_INVALID_USAGE", "EXIT_OK", "main"]
