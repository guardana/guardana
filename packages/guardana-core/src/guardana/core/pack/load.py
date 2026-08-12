"""Read a pack manifest, refusing anything this build cannot honour.

The same discipline `contract/load.py` established and for the same reason, so this
does not need re-deciding: `schema_version` is required, a version this build has
never heard of is refused rather than read optimistically, older versions migrate
forward in memory at load, and unknown keys raise.

**No `pack migrate` command.** A saved run is generated and Guardana may rewrite it;
a manifest is hand-written and belongs to its author.
"""

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from guardana.core.pack.model import (
    PACK_SCHEMA_VERSION,
    ApiRange,
    PackError,
    PackManifest,
)

MANIFEST_NAME = "guardana-pack.yaml"
"""The file a pack ships *inside its package directory*, not at the repo root.

`pack validate` has to work against an **installed distribution**, and
`pyproject.toml` is not in a wheel — a manifest a user cannot read from what they
installed cannot be checked at the only moment that matters.
"""

_ALLOWED_KEYS = frozenset({"schema_version", "name", "description", "extension_api", "provides"})
_ALLOWED_PROVIDES_KEYS = frozenset({"rules", "evaluators", "targets", "taxonomies"})
_V1_PROVIDES_KEYS = frozenset({"rules", "evaluators", "targets"})
"""What `provides:` could name at schema 1 — three groups out of the four that exist.

Kept as its own set rather than derived, because the v1→v2 migration has to refuse a
v1 manifest that names `taxonomies:`. Widening the check to the current keys would
accept a document that declares a key its own version had not invented, which is a
manifest whose `schema_version` no longer describes it.
"""

_RANGE = re.compile(r"^>=\s*(\d+)\s*,\s*<\s*(\d+)$")


def load_manifest(path: Path) -> PackManifest:
    """Parse one `guardana-pack.yaml`, or raise `PackError` naming the file and the problem."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
        raise PackError(f"could not read pack manifest {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise PackError(f"invalid pack manifest {path}: the file must be a mapping")
    _reject_unknown(raw, _ALLOWED_KEYS, "pack manifest", path)
    declared = _check_version(raw, path)
    raw = _migrated(raw, declared, path)
    provides = _provides(raw.get("provides"), path)
    return PackManifest(
        name=_require_str(raw, "name", path),
        extension_api=_api_range(raw.get("extension_api"), path),
        source=str(path),
        rules=provides.get("rules", ()),
        evaluators=provides.get("evaluators", ()),
        targets=provides.get("targets", ()),
        taxonomies=provides.get("taxonomies", ()),
        description=str(raw.get("description", "")),
        schema_version=PACK_SCHEMA_VERSION,
        migrated_from=declared if declared != PACK_SCHEMA_VERSION else None,
    )


def _check_version(raw: dict[str, Any], path: Path) -> int:
    """Return the version this manifest declares, refusing one this build cannot read."""
    version = raw.get("schema_version")
    if version is None:
        raise PackError(
            f"invalid pack manifest {path}: no schema_version — a manifest is a document "
            f"you keep, so it has to say which version it is (this build writes "
            f"{PACK_SCHEMA_VERSION})"
        )
    if not isinstance(version, int) or isinstance(version, bool) or version > PACK_SCHEMA_VERSION:
        raise PackError(
            f"invalid pack manifest {path}: schema_version {version!r} is newer than this "
            f"build reads ({PACK_SCHEMA_VERSION}). A document this build cannot read is "
            f"not one it may read optimistically"
        )
    if version < _OLDEST_READABLE:
        raise PackError(
            f"invalid pack manifest {path}: schema_version {version!r} is not a version "
            f"this build has ever written (the oldest is {_OLDEST_READABLE})"
        )
    return version


def _migrated(raw: dict[str, Any], version: int, path: Path) -> dict[str, Any]:
    """Carry an older manifest forward in memory, one version at a time.

    Chained the way `manifest/load.py` chains, so a manifest three versions behind
    passes through every step rather than needing a direct migration written for
    each pair. **In memory only** — there is no `pack migrate`: a saved run is
    generated and Guardana may rewrite it, and a manifest is hand-written and
    belongs to its author.
    """
    document = raw
    while version < PACK_SCHEMA_VERSION:
        document = _MIGRATIONS[version](document, path)
        version += 1
    return document


def _migrate_v1_to_v2(raw: dict[str, Any], path: Path) -> dict[str, Any]:
    """Carry a schema 1 manifest to schema 2, which knows the fourth extension group.

    A v1 manifest simply declares no catalogues, which is what it meant — the group
    it could not name is the group it could not have shipped a declaration for. What
    this must not do is *accept* `taxonomies:` on a document claiming version 1: a
    key invented after the version that names it is a manifest whose own
    `schema_version` no longer describes it, and reading it anyway would make the
    version a decoration.
    """
    provides = raw.get("provides")
    if isinstance(provides, dict):
        _reject_unknown(provides, _V1_PROVIDES_KEYS, "schema 1 provides", path)
    return raw


_MIGRATIONS: dict[int, Callable[[dict[str, Any], Path], dict[str, Any]]] = {
    1: _migrate_v1_to_v2,
}

_OLDEST_READABLE = min(_MIGRATIONS) if _MIGRATIONS else PACK_SCHEMA_VERSION


def _api_range(raw: object, path: Path) -> ApiRange:
    """Parse `extension_api: ">=1,<2"`, requiring both ends.

    Both ends, because both directions are real failures and an open-ended range
    silently claims compatibility with an API nobody has written yet.
    """
    if not isinstance(raw, str):
        raise PackError(
            f"invalid pack manifest {path}: 'extension_api' is required and must be a "
            f'string like ">=1,<2"'
        )
    match = _RANGE.match(raw.strip())
    if match is None:
        raise PackError(
            f"invalid pack manifest {path}: 'extension_api' must be a closed range like "
            f'">=1,<2", got {raw!r} — an open end claims compatibility with an API that '
            f"does not exist yet"
        )
    minimum, below = int(match.group(1)), int(match.group(2))
    if minimum >= below:
        raise PackError(
            f"invalid pack manifest {path}: 'extension_api' range {raw!r} accepts nothing"
        )
    return ApiRange(minimum=minimum, below=below)


def _provides(raw: object, path: Path) -> dict[str, tuple[str, ...]]:
    if raw is None:
        raise PackError(
            f"invalid pack manifest {path}: 'provides' is required — a manifest that "
            f"names nothing cannot be checked against what the package registers, which "
            f"is the one thing it is for"
        )
    if not isinstance(raw, dict):
        raise PackError(f"invalid pack manifest {path}: 'provides' must be a mapping")
    _reject_unknown(raw, _ALLOWED_PROVIDES_KEYS, "provides", path)
    provided = {key: _id_list(raw.get(key), key, path) for key in _ALLOWED_PROVIDES_KEYS}
    if not any(provided.values()):
        raise PackError(f"invalid pack manifest {path}: 'provides' lists nothing at all")
    return provided


def _id_list(raw: object, key: str, path: Path) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PackError(f"invalid pack manifest {path}: 'provides.{key}' must be a list")
    for entry in raw:
        if not isinstance(entry, str) or not entry.strip():
            raise PackError(
                f"invalid pack manifest {path}: every entry in 'provides.{key}' must be a "
                f"non-empty id"
            )
    return tuple(raw)


def _require_str(raw: dict[str, Any], key: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PackError(f"invalid pack manifest {path}: '{key}' is required")
    return value


def _reject_unknown(raw: dict[str, Any], allowed: frozenset[str], what: str, path: Path) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise PackError(
            f"invalid pack manifest {path}: unknown {what} key(s): {', '.join(unknown)}; "
            f"expected {sorted(allowed)}"
        )
