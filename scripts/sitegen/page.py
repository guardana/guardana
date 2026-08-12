"""One documentation page: what its frontmatter claims, and where it lands.

Frontmatter exists so the build never infers navigation from a filename or from a
first heading. Both inferences look free and both reorder a nav silently the day
somebody retitles a page — which is the class of drift this repository keeps
finding in its own prose. Four fields, refused when absent.
"""

from dataclasses import dataclass
from pathlib import Path

import yaml

from sitegen.errors import SiteBuildError

STATUSES = frozenset(
    {
        # For a documentation page: how far the thing it documents has got.
        "stable",
        "beta",
        "draft",
        # For a design document: the first word of its `**Status:**` line, so the
        # site says the same thing the document does. `docs/design/README.md` is
        # where those four are defined.
        "proposed",
        "accepted",
        "implemented",
        "superseded",
    }
)

_REQUIRED = ("title", "nav_order", "summary", "status")
_FENCE = "---\n"


@dataclass(frozen=True, slots=True)
class Page:
    """A markdown source file, its declared metadata, and the HTML it becomes."""

    relative: Path
    """Where the source sits under `docs/`, e.g. `design/exit-codes.md`."""

    title: str
    nav_order: int
    summary: str
    status: str
    body: str

    @property
    def output(self) -> Path:
        """The path of the rendered page, relative to `site/docs/`."""
        return self.relative.with_suffix(".html")

    @property
    def url(self) -> str:
        """Where the page is served from, for a canonical link."""
        return "/docs/" + self.output.as_posix()


def read_pages(docs: Path) -> list[Page]:
    """Read every markdown file under `docs/`, refusing one that does not describe itself."""
    pages = [
        _page(path, path.relative_to(docs))
        for path in sorted(docs.rglob("*.md"))
        if not _ignored(path.relative_to(docs))
    ]
    _refuse_duplicate_nav_orders(pages)
    return pages


def _ignored(relative: Path) -> bool:
    """`docs/superpowers/` is a gitignored scratch area, not documentation."""
    return relative.parts[0] == "superpowers"


def _page(path: Path, relative: Path) -> Page:
    text = path.read_text(encoding="utf-8")
    if not text.startswith(_FENCE):
        raise SiteBuildError(
            f"{relative}: no YAML frontmatter. Every page states its own "
            f"{', '.join(_REQUIRED)}; the build will not infer a title from the "
            f"filename, because an inferred nav reorders itself the day a heading changes"
        )
    block, _, body = text[len(_FENCE) :].partition(f"\n{_FENCE}")
    try:
        declared = yaml.safe_load(block)
    except yaml.YAMLError as exc:
        raise SiteBuildError(f"{relative}: frontmatter is not valid YAML: {exc}") from exc
    if not isinstance(declared, dict):
        raise SiteBuildError(f"{relative}: frontmatter must be a mapping")
    missing = [key for key in _REQUIRED if not declared.get(key)]
    if missing:
        raise SiteBuildError(f"{relative}: frontmatter is missing {', '.join(missing)}")
    return Page(
        relative=relative,
        title=_text(declared, "title", relative),
        nav_order=_order(declared, relative),
        summary=_text(declared, "summary", relative),
        status=_status(declared, relative),
        body=body.lstrip("\n"),
    )


def _text(declared: dict[str, object], key: str, relative: Path) -> str:
    value = declared[key]
    if not isinstance(value, str) or not value.strip():
        raise SiteBuildError(f"{relative}: frontmatter '{key}' must be a non-empty string")
    return value.strip()


def _order(declared: dict[str, object], relative: Path) -> int:
    value = declared["nav_order"]
    if isinstance(value, bool) or not isinstance(value, int):
        raise SiteBuildError(f"{relative}: frontmatter 'nav_order' must be an integer")
    return value


def _status(declared: dict[str, object], relative: Path) -> str:
    value = _text(declared, "status", relative)
    if value not in STATUSES:
        raise SiteBuildError(
            f"{relative}: frontmatter status {value!r} is not one of {sorted(STATUSES)}. "
            f"A status nobody can place is a badge a reader invents a meaning for"
        )
    return value


def _refuse_duplicate_nav_orders(pages: list[Page]) -> None:
    """Two pages claiming one position in one directory sort by whatever comes second.

    Refused rather than tie-broken by filename: a nav whose order depends on a
    detail nobody declared moves when a page is renamed, and nobody would connect
    the two.
    """
    seen: dict[tuple[str, int], Path] = {}
    for page in sorted(pages, key=lambda p: p.relative.as_posix()):
        key = (page.relative.parent.as_posix(), page.nav_order)
        if key in seen:
            raise SiteBuildError(
                f"{page.relative} and {seen[key]} both claim nav_order {page.nav_order} "
                f"in the same directory"
            )
        seen[key] = page.relative
