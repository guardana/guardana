"""How much installed third-party code a run is willing to import.

`--no-plugins` was all-or-nothing, and the nothing included Guardana's own rules —
so the safe mode was also the useless mode, and nobody used it. That is the worst
shape a security control can have: present, documented, and switched off.

Three settings instead. The middle one is the point: load the reviewed built-ins,
discover nothing else.
"""

from dataclasses import dataclass
from enum import StrEnum

BUILTIN_DISTRIBUTIONS = frozenset({"guardana-core", "guardana-rules", "guardana-report"})
"""Distributions whose entry points are Guardana's own, reviewed in this repository.

Matched by distribution name rather than by entry-point name or module path: a
third party can name their entry point `builtin` and their module `guardana_rules`,
and neither is a claim anybody checked. The distribution name is what pip
installed and what a lockfile pins.
"""


class PluginMode(StrEnum):
    """How much installed code a run will import."""

    ALL = "all"
    """Every entry point on the system. The default, and what a plugin API is for."""

    BUILTINS = "builtins"
    """Only Guardana's own distributions. Safe mode that still checks things."""

    ALLOWLIST = "allowlist"
    """The built-ins plus distributions the user named."""

    DISABLED = "disabled"
    """Nothing at all — not even the built-ins. YAML rules still load from disk."""


@dataclass(frozen=True, slots=True)
class PluginTrust:
    """Which distributions a run will load entry points from."""

    mode: PluginMode = PluginMode.ALL
    allowed: frozenset[str] = frozenset()

    def allows(self, distribution: str | None) -> bool:
        """Whether an entry point from `distribution` may be loaded.

        `None` — an entry point that cannot name its origin — is treated as
        third-party. Reading it as trusted would make the allowlist bypassable by
        anything that fails to record where it came from.
        """
        if self.mode is PluginMode.ALL:
            return True
        if self.mode is PluginMode.DISABLED:
            return False
        if distribution is None:
            return False
        if distribution in BUILTIN_DISTRIBUTIONS:
            return True
        return self.mode is PluginMode.ALLOWLIST and distribution in self.allowed

    def describe(self) -> str:
        """Return a phrase for an error message, naming what this run permits."""
        if self.mode is PluginMode.ALLOWLIST:
            return f"allowlist ({', '.join(sorted(self.allowed)) or 'built-ins only'})"
        return str(self.mode)
