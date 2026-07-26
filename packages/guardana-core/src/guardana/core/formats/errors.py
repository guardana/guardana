class FormatError(Exception):
    """A model artifact could not be read as the format its name claims.

    Raised — never swallowed — by every reader in this package. A rule turns it
    into a visible "not scanned" finding, because an artifact nobody could parse
    is an open question, not a clean bill of health.
    """
