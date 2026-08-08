"""Read a taxonomy catalogue: framework data as a file, never as engine logic.

Product principle 1 says the engine knows no regulation. A catalogue is where the
name of a standard, the wording of its entries and their ranking live, so a curator
edits YAML and nobody edits Python when OWASP publishes an edition.

Every check here fails loudly. A catalogue that half-loaded would leave rules
mapping to entries that resolve to nothing, and a mapping is mandatory — so a
malformed file is one exception at import rather than twenty rule-load failures
whose cause is a directory away.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from guardana.core.fingerprint import digest_of
from guardana.core.taxonomy._ref import Relation, TaxonomyError, TaxonomyRef

_CATALOG_KEYS = frozenset(
    {"scheme", "edition", "title", "source", "published", "version", "entries"}
)
_ENTRY_KEYS = frozenset({"id", "title", "rank", "supersedes"})
_LINK_KEYS = frozenset({"ref", "relation", "note"})


@dataclass(frozen=True, slots=True)
class Correspondence:
    """One directed statement: `subject` stands to `other` as `relation` says.

    Declared by the newer catalogue and readable from both sides through
    `inverted`, so the crosswalk is written once and cannot disagree with itself.
    """

    subject: str
    other: str
    relation: Relation
    note: str = ""

    @property
    def inverted(self) -> "Correspondence":
        """The same statement with the two entries swapped and the relation reversed."""
        return Correspondence(
            subject=self.other,
            other=self.subject,
            relation=self.relation.inverse,
            note=self.note,
        )


@dataclass(frozen=True, slots=True)
class TaxonomyCatalog:
    """One published edition of one framework, as an immutable data file.

    `digest` is taken over the parsed content rather than the file's bytes, so a
    reformatting or a new comment is not a changed catalogue while a reworded entry
    is. It is pinned in the run manifest: a report read years later then says which
    editions were installed and which revision of each, without asking anyone to
    remember.
    """

    scheme: str
    title: str
    digest: str
    refs: tuple[TaxonomyRef, ...]
    correspondences: tuple[Correspondence, ...] = ()
    edition: str | None = None
    version: str | None = None
    source: str | None = None
    published: str | None = None

    @property
    def framework(self) -> str:
        """The framework name entries of this catalogue carry in a report."""
        return f"{self.scheme}-{self.edition}" if self.edition else self.scheme


def load_catalog(path: Path) -> TaxonomyCatalog:
    """Read one catalogue file, refusing anything it cannot read exactly."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise TaxonomyError(f"cannot read taxonomy catalogue {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise TaxonomyError(f"{path}: a taxonomy catalogue must be a mapping")
    _reject_unknown(raw, _CATALOG_KEYS, "catalogue", path)
    scheme = _text(raw, "scheme", path)
    edition = _optional_text(raw, "edition", path)
    refs, correspondences = _entries(raw.get("entries"), scheme, edition, path)
    return TaxonomyCatalog(
        scheme=scheme,
        edition=edition,
        title=_text(raw, "title", path),
        version=_optional_text(raw, "version", path),
        source=_optional_text(raw, "source", path),
        published=_optional_text(raw, "published", path),
        digest=digest_of(yaml.safe_dump(raw, sort_keys=True, allow_unicode=True)),
        refs=refs,
        correspondences=correspondences,
    )


def load_catalogs(directory: Path) -> tuple[TaxonomyCatalog, ...]:
    """Read every catalogue in `directory`, in a stable order.

    An empty directory is an error, not an empty registry. Every rule must map to a
    framework, so a build that shipped without its catalogues cannot check anything
    — and it has to say that once, here, rather than as one failure per rule.
    """
    files = sorted(p for p in directory.glob("*.yaml"))
    if not files:
        raise TaxonomyError(
            f"no taxonomy catalogue found in {directory}; this build cannot resolve any "
            f"framework reference, so every rule's mapping would fail to load"
        )
    return tuple(load_catalog(path) for path in files)


def _entries(
    raw: object, scheme: str, edition: str | None, path: Path
) -> tuple[tuple[TaxonomyRef, ...], tuple[Correspondence, ...]]:
    if not isinstance(raw, list) or not raw:
        raise TaxonomyError(f"{path}: 'entries' must be a non-empty list")
    refs: list[TaxonomyRef] = []
    links: list[Correspondence] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise TaxonomyError(f"{path}: every entry must be a mapping")
        _reject_unknown(entry, _ENTRY_KEYS, "entry", path)
        local_id = _text(entry, "id", path)
        if local_id in seen:
            raise TaxonomyError(f"{path}: entry {local_id!r} is declared twice")
        seen.add(local_id)
        ref = TaxonomyRef(
            scheme=scheme,
            id=local_id,
            title=_text(entry, "title", path),
            edition=edition,
            rank=_optional_rank(entry, path),
        )
        refs.append(ref)
        links.extend(_supersedes(entry.get("supersedes"), ref.reference, path))
    return tuple(refs), tuple(links)


def _supersedes(raw: object, subject: str, path: Path) -> list[Correspondence]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not raw:
        raise TaxonomyError(f"{path}: 'supersedes' must be a non-empty list")
    out: list[Correspondence] = []
    for link in raw:
        if not isinstance(link, dict):
            raise TaxonomyError(f"{path}: every 'supersedes' entry must be a mapping")
        _reject_unknown(link, _LINK_KEYS, "supersedes", path)
        name = _text(link, "relation", path)
        try:
            relation = Relation(name)
        except ValueError as exc:
            raise TaxonomyError(
                f"{path}: unknown relation {name!r}; expected one of "
                f"{', '.join(sorted(r.value for r in Relation))}"
            ) from exc
        out.append(
            Correspondence(
                subject=subject,
                other=_text(link, "ref", path),
                relation=relation,
                note=(_optional_text(link, "note", path) or "").strip(),
            )
        )
    return out


def _reject_unknown(raw: dict[str, Any], allowed: frozenset[str], what: str, path: Path) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise TaxonomyError(f"{path}: unknown {what} field(s): {', '.join(unknown)}")


def _text(raw: dict[str, Any], key: str, path: Path) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise TaxonomyError(f"{path}: {key!r} must be a non-empty string")
    return value


def _optional_text(raw: dict[str, Any], key: str, path: Path) -> str | None:
    """Read an optional field, refusing a non-string rather than coercing one.

    `edition: 2026` unquoted is an integer in YAML, and `str()`-ing it here would
    let one catalogue say `"2026"` and another `2026` for the same edition — two
    identities for one control, which is what this whole module exists to prevent.
    """
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise TaxonomyError(
            f'{path}: {key!r} must be a non-empty string when present (quote it: {key}: "{value}")'
        )
    return value


def _optional_rank(raw: dict[str, Any], path: Path) -> int | None:
    value = raw.get("rank")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TaxonomyError(f"{path}: 'rank' must be an integer")
    return value
