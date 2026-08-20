"""Where a registered rule, evaluator or target came from.

A run's evidence names the checks that ran. It could not name *whose* they were:
two distributions can advertise the same rule id, and `Rule.digest()` covers the
declaration — so a rule copying a built-in's metadata produced an identical id and
an identical digest, and the document agreed with itself.

Named `Origin` rather than `Provenance` on purpose. Two classes already carry that
name — `guardana.core.exchange.Provenance` and `guardana.core.trace.Provenance` —
and a third would make `from guardana.core… import Provenance` a question rather
than an import.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Origin:
    """Which installed distribution, or which file, supplied one registered object.

    `distribution` and `version` come from `importlib.metadata` when the object
    arrived through an entry point; `source` is the file a YAML rule was parsed
    from. All three absent means *unattributed* — built in code by a test or an
    embedding caller — and that stays distinguishable from "nothing installed".
    """

    distribution: str | None = None
    version: str | None = None
    source: str | None = None

    @property
    def is_builtin(self) -> bool:
        """Whether this came from one of Guardana's own reviewed distributions."""
        from guardana.core.plugins import BUILTIN_DISTRIBUTIONS  # noqa: PLC0415 — import cycle

        return self.distribution in BUILTIN_DISTRIBUTIONS

    def describe(self) -> str:
        """Return a short, stable phrase naming this origin, for an error a human reads."""
        if self.distribution is not None:
            return f"{self.distribution} {self.version}" if self.version else self.distribution
        if self.source is not None:
            return self.source
        return "an unattributed registration"


UNATTRIBUTED = Origin()
"""The origin of an object registered in code rather than discovered."""
