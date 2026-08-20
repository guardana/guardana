"""Where a registered rule, evaluator or target came from.

A run's evidence names the checks that ran. Until this existed it could not name
*whose* checks they were: two distributions can advertise the same rule id, and
`Rule.digest()` covers the declaration, so a rule that copies a built-in's
metadata and returns nothing produces an identical id and an identical digest.
The document then says the built-in ran, and nothing in it disagrees.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Provenance:
    """Which installed distribution, or which file, supplied one registered object.

    `distribution` and `version` come from `importlib.metadata` when the object
    arrived through an entry point. `source` is the file a YAML rule was parsed
    from. A registration with none of the three is *unattributed* — a rule built
    in code by a test or an embedding caller — and stays distinguishable from one
    that names its origin, because "nobody said" and "nothing installed" are
    different facts.
    """

    distribution: str | None = None
    version: str | None = None
    source: str | None = None

    @property
    def is_builtin(self) -> bool:
        """Whether this came from one of Guardana's own reviewed distributions."""
        from guardana.core.plugins import BUILTIN_DISTRIBUTIONS  # noqa: PLC0415 — cycle

        return self.distribution in BUILTIN_DISTRIBUTIONS

    def describe(self) -> str:
        """Return a short, stable phrase naming this origin, for an error a human reads."""
        if self.distribution is not None:
            return f"{self.distribution} {self.version}" if self.version else self.distribution
        if self.source is not None:
            return self.source
        return "an unattributed registration"


UNATTRIBUTED = Provenance()
"""The origin of an object registered in code rather than discovered."""
