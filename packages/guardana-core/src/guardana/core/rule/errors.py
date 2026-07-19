class RuleError(Exception):
    """Base class for rule failures."""


class RuleLoadError(RuleError):
    """A rule could not be constructed or loaded."""
