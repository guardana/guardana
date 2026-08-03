"""Where the collector's storage comes from, and what happens when nobody said.

The important decision here is the one that produces *no* storage. A collector
that quietly falls back to memory is a collector somebody deploys, restarts, and
then asks where last week went. So there is no fallback: the choice is made, or
the process refuses to start and says what to set.

Same shape as "no default credentials", one layer down — the unsafe configuration
must not be the one you get by not deciding.
"""

import os
from dataclasses import dataclass
from enum import StrEnum

DATABASE_URL_VARIABLE = "GUARDANA_DATABASE_URL"
STORAGE_VARIABLE = "GUARDANA_STORAGE"
MIGRATE_ON_START_VARIABLE = "GUARDANA_MIGRATE_ON_START"

_TRUTHY = frozenset({"1", "true", "yes", "on"})


class StorageNotConfiguredError(RuntimeError):
    """Raised when nothing said where to keep submissions. Never defaulted around."""


class StorageKind(StrEnum):
    """Which store a collector was told to use."""

    POSTGRES = "postgres"
    MEMORY = "memory"


@dataclass(frozen=True, slots=True)
class StorageChoice:
    """What the environment asked for: a kind, and the connection string if any."""

    kind: StorageKind
    database_url: str | None = None

    @property
    def is_ephemeral(self) -> bool:
        """Whether this storage forgets everything when the process ends."""
        return self.kind is StorageKind.MEMORY


def resolve_storage(environ: dict[str, str] | None = None) -> StorageChoice:
    """Decide where submissions go, refusing to guess.

    `GUARDANA_DATABASE_URL` wins. `GUARDANA_STORAGE=memory` is how somebody
    evaluating Guardana on a laptop opts into the ephemeral store — deliberately a
    thing you type, because the alternative is a store that reaches production by
    being what happens when nobody chose.
    """
    env = os.environ if environ is None else environ
    url = env.get(DATABASE_URL_VARIABLE, "").strip()
    if url:
        return StorageChoice(kind=StorageKind.POSTGRES, database_url=url)
    requested = env.get(STORAGE_VARIABLE, "").strip().lower()
    if requested == StorageKind.MEMORY:
        return StorageChoice(kind=StorageKind.MEMORY)
    if requested:
        raise StorageNotConfiguredError(
            f"{STORAGE_VARIABLE}={requested!r} is not a storage kind; "
            f"set {DATABASE_URL_VARIABLE} to a PostgreSQL connection string, "
            f"or {STORAGE_VARIABLE}=memory to accept a store that forgets on restart"
        )
    raise StorageNotConfiguredError(
        f"the collector was not told where to keep submissions. Set "
        f"{DATABASE_URL_VARIABLE} to a PostgreSQL connection string (run "
        f"`guardana-collector migrate` first), or {STORAGE_VARIABLE}=memory to "
        f"accept a store that forgets everything when the process ends. There is "
        f"no default: an ephemeral store nobody chose is one that reaches production"
    )


def migrate_on_start(environ: dict[str, str] | None = None) -> bool:
    """Whether this deployment wants the server to migrate before serving.

    Off by default. The supported path is `guardana-collector migrate` with
    readiness holding traffic back, because a rolling deploy that migrates on boot
    briefly runs two versions of the code against one schema. A single-node Docker
    Compose gains nothing from that ceremony, which is what this exists for.
    """
    env = os.environ if environ is None else environ
    return env.get(MIGRATE_ON_START_VARIABLE, "").strip().lower() in _TRUTHY
