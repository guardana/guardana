"""The three exit codes the collector command uses.

The same three meanings the rest of the product uses, so one table covers the whole
tool. Their own module because every command group needs them and none of them may
import the parser that dispatches to it.
"""

EXIT_OK = 0
"""Did what was asked."""

EXIT_FAILED = 1
"""The database said no, or could not be reached."""

EXIT_INVALID_USAGE = 3
"""The command was pointed at nothing, or named something that does not exist."""
