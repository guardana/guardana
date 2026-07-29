from dataclasses import dataclass


class TaxonomyError(Exception):
    """Raised when a framework reference cannot be registered or resolved."""


@dataclass(frozen=True, slots=True)
class TaxonomyRef:
    """One entry in a security standard (OWASP, MITRE ATLAS, NIST) a rule maps to."""

    framework: str
    id: str
    title: str
