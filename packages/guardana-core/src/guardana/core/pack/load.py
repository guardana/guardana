"""Read a pack manifest, refusing anything this build cannot honour.

The same discipline `contract/load.py` established and for the same reason, so this
does not need re-deciding: `schema_version` is required, a version this build has
never heard of is refused rather than read optimistically, older versions migrate
forward in memory at load, and unknown keys raise.

**No `pack migrate` command.** A saved run is generated and Guardana may rewrite it;
a manifest is hand-written and belongs to its author.
"""

import re
from pathlib import Path
from typing import Any

import yaml
from guardana.core.pack.model import ApiRange, PackError, PackManifest

MANIFEST_NAME = "guardana-pack.yaml"
"""The file a pack ships *inside its package directory*, not at the repo root.

`pack validate` has to work against an **installed distribution**, and
`pyproject.toml` is not in a wheel — a manifest a user cannot read from what they
installed cannot be checked at the only moment that matters.
"""

PACK_SCHEMA_VERSION = 1

_ALLOWED_KEYS = frozenset({"schema_version", "name", "description", "extension_api", "provides"})
_ALLOWED_PROVIDES_KEYS = frozenset({"rules", "evaluators", "targets"})

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
    _check_version(raw, path)
    provides = _provides(raw.get("provides"), path)
    return PackManifest(
        name=_require_str(raw, "name", path),
        extension_api=_api_range(raw.get("extension_api"), path),
        source=str(path),
        rules=provides.get("rules", ()),
        evaluators=provides.get("evaluators", ()),
        targets=provides.get("targets", ()),
        description=str(raw.get("description", "")),
    )


def _check_version(raw: dict[str, Any], path: Path) -> None:
    version = raw.get("schema_version")
    if version is None:
        raise PackError(
            f"invalid pack manifest {path}: no schema_version — a manifest is a document "
            f"you keep, so it has to say which version it is (this build writes "
            f"{PACK_SCHEMA_VERSION})"
        )
    if not isinstance(version, int) or version > PACK_SCHEMA_VERSION:
        raise PackError(
            f"invalid pack manifest {path}: schema_version {version!r} is newer than this "
            f"build reads ({PACK_SCHEMA_VERSION}). A document this build cannot read is "
            f"not one it may read optimistically"
        )
    # Only version 1 exists. When 2 lands, migrate 1 -> 2 here, in memory, chained —
    # never by rewriting the author's file.


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
