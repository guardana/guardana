from enum import IntEnum


class Severity(IntEnum):
    """Ordered so policies can threshold with `>=`."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50
