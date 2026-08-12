"""What an extension package declares about itself: which API it needs, and what it provides.

1.0 promises that `Rule`, `Evaluator` and `Target` will not break under a third
party. A promise is only useful to somebody who can tell whether *this* build keeps
it for *their* package — so a pack says which extension API it was written against,
and this build refuses to load one it cannot honour rather than hoping.
"""

from dataclasses import dataclass, field


class PackError(Exception):
    """Raised when a pack manifest cannot be read, or declares an API this build lacks."""


PACK_SCHEMA_VERSION = 2
"""Version of `guardana-pack.yaml`, moved independently of the extension API.

Two numbers because they answer two questions. `extension_api` says which `Rule`,
`Evaluator`, `Target` and `Finding` a pack was written against; this says what a
*manifest* may contain. Schema 2 adds `provides.taxonomies`, so the fourth
extension group can finally be declared — and a v1 manifest still loads, migrated
forward in memory, because a manifest belongs to its author and Guardana does not
rewrite somebody else's file.

Declared here rather than beside the loader: the model is what both the loader and
every reader of a `PackManifest` depend on, and a version living in the parser is a
version the parser is free to reinterpret.
"""

EXTENSION_API_VERSION = 1
"""The version of the extension contract this build implements.

**Deliberately not the product version.** In 0.x the product's minor breaks API by
design, so a pack pinned to `guardana>=0.17,<0.18` would need re-releasing on every
minor even when nothing it touches moved. This integer changes only when `Rule`,
`Evaluator`, `Target` or `Finding` actually change shape, which is what a pack can
usefully bind to — and what makes "too old" and "too new" two answerable questions
instead of one guess about a version range.
"""


@dataclass(frozen=True, slots=True)
class ApiRange:
    """The extension API versions a pack says it works with.

    A closed range with both ends declared, because both ends are real failures. A
    pack built for an older API may rely on behaviour since removed; one built for a
    newer API may call something this build does not have. Loading either and hoping
    is how a scanner starts producing verdicts nobody can account for.
    """

    minimum: int
    below: int

    def accepts(self, api: int) -> bool:
        """Whether this build's extension API falls inside the declared range."""
        return self.minimum <= api < self.below

    def why_not(self, api: int) -> str:
        """Say which side of the range this build is on, in the author's terms.

        Two messages and one outcome. An author told only "incompatible" checks the
        wrong end, and an author who stops checking is the failure a compatibility
        declaration exists to prevent.
        """
        if api < self.minimum:
            return (
                f"needs extension API >={self.minimum} and this build implements {api} — "
                f"the pack is newer than Guardana; upgrade Guardana"
            )
        return (
            f"needs extension API <{self.below} and this build implements {api} — the pack "
            f"is older than Guardana and may rely on behaviour that has since changed; "
            f"upgrade the pack"
        )

    def __str__(self) -> str:
        """Render the range the way the manifest spells it."""
        return f">={self.minimum},<{self.below}"


@dataclass(frozen=True, slots=True)
class PackManifest:
    """One extension package's declaration, as read from `guardana-pack.yaml`."""

    name: str
    extension_api: ApiRange
    source: str
    """Where this was read from, so an error can name the file rather than the pack."""

    rules: tuple[str, ...] = field(default_factory=tuple)
    evaluators: tuple[str, ...] = field(default_factory=tuple)
    targets: tuple[str, ...] = field(default_factory=tuple)
    taxonomies: tuple[str, ...] = field(default_factory=tuple)
    """Control catalogues this pack registers, by **framework name** (schema 2).

    The framework rather than each entry, because a pack registers a catalogue: a
    team shipping two hundred controls would otherwise maintain two hundred lines
    that say one thing, and a list that long is a list that rots. `ACME-CONTROLS`,
    not `ACME-CONTROLS:ACME-14`.

    The fourth extension group waited a release for this. A pack could register a
    catalogue and its manifest had nowhere to say so, which left `pack validate`
    blind to the whole category — and a pack registering *only* a taxonomy could not
    write a valid manifest at all, because `provides:` had to list something and
    none of the three things it could list were what that pack shipped.
    """

    description: str = ""
    schema_version: int = PACK_SCHEMA_VERSION
    migrated_from: int | None = None
    """The version this manifest declared, when it was older than the current one.

    Carried so `pack validate` can say a manifest was read as an earlier schema
    rather than silently treating it as current. A migration nobody can see is a
    migration nobody can check.
    """

    @property
    def provides(self) -> tuple[str, ...]:
        """Every id this pack claims to register, in one sequence."""
        return (*self.rules, *self.evaluators, *self.targets, *self.taxonomies)

    def loadable_by(self, api: int = EXTENSION_API_VERSION) -> bool:
        """Whether this build may load the pack at all."""
        return self.extension_api.accepts(api)
