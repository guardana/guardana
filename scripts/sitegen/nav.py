"""The sidebar, grouped the way `docs/index.md` already groups the documentation.

The map exists and is curated: `docs/index.md` sorts every page under a heading
that names who needs it, and `generate_llms_txt.py` already derives a second
artifact from the same headings. A nav invented separately would be a third
opinion about the same set, and the three would drift in the usual direction.

So the sections come from the map, the order inside a section comes from each
page's `nav_order`, and the label comes from each page's `title`. A page the map
does not list still gets a nav entry, because a rendered page nobody can navigate
to is a page nobody reads.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from sitegen.errors import SiteBuildError
from sitegen.page import Page

_HEADING = re.compile(r"^## (.+)$")
_BULLET = re.compile(r"^- \[[^\]]*\]\(([^)]+)\)")

UNLISTED_SECTION = "Also here"
"""Where a rendered page the map does not mention ends up.

Never dropped. The map is hand-written, so a page added without a bullet is an
ordinary oversight — and a nav that silently omitted it would hide the page from
everyone except whoever remembered the URL.
"""


@dataclass(frozen=True, slots=True)
class NavEntry:
    """One line in the sidebar."""

    label: str
    href: str
    """Relative to `site/docs/`, so a page rewrites it against its own depth."""

    status: str


@dataclass(frozen=True, slots=True)
class NavSection:
    """One heading in the sidebar, and what sits under it."""

    title: str
    entries: tuple[NavEntry, ...]


HOME = Path("index.md")
"""The map itself, which is the one page the map does not list.

It sits above the sections rather than inside one — a link to "Documentation" from
the documentation home is what a reader expects at the top of a sidebar, and
letting it fall through to `UNLISTED_SECTION` filed the front page under "Also
here", at the bottom, which is exactly backwards.
"""


def build(
    index: Path, pages: list[Page], extra: dict[str, tuple[NavEntry, ...]]
) -> list[NavSection]:
    """Group `pages` into sidebar sections, adding `extra` entries under named headings."""
    by_relative = {page.relative: page for page in pages}
    sections: list[NavSection] = []
    placed: set[Path] = {HOME}
    headings = _sections(index)
    _refuse_an_extra_with_nowhere_to_go(extra, {heading for heading, _targets in headings})
    for heading, targets in headings:
        entries = [_entry(by_relative[target]) for target in targets if target in by_relative]
        placed.update(target for target in targets if target in by_relative)
        entries.extend(extra.get(heading, ()))
        if entries:
            sections.append(NavSection(heading, tuple(_ordered(entries, by_relative))))
    unlisted = [page for page in pages if page.relative not in placed]
    if unlisted:
        sections.append(
            NavSection(
                UNLISTED_SECTION,
                tuple(_entry(page) for page in sorted(unlisted, key=lambda p: p.nav_order)),
            )
        )
    _refuse_a_page_with_no_entry(pages, sections)
    return sections


def _refuse_an_extra_with_nowhere_to_go(
    extra: dict[str, tuple[NavEntry, ...]], headings: set[str]
) -> None:
    """Refuse a generated entry filed under a heading the map no longer has.

    Dropped silently, it would take the rule explorer out of the sidebar the day
    somebody reworded a heading in `docs/index.md` — with every gate still green,
    because no *page* went missing. The explorer has no markdown source, so nothing
    else in this module would notice.
    """
    homeless = sorted(set(extra) - headings)
    if homeless:
        raise SiteBuildError(
            f"docs/index.md has no heading(s) {homeless} to file generated nav entries "
            f"under; it has {sorted(headings)}"
        )


def _entry(page: Page) -> NavEntry:
    return NavEntry(page.title, page.output.as_posix(), page.status)


def _ordered(entries: list[NavEntry], by_relative: dict[Path, Page]) -> list[NavEntry]:
    order = {page.output.as_posix(): page.nav_order for page in by_relative.values()}
    return sorted(entries, key=lambda entry: order.get(entry.href, 0))


def _sections(index: Path) -> list[tuple[str, list[Path]]]:
    """Read `docs/index.md` into (heading, [page paths relative to docs/]).

    A bullet wrapped over two lines is joined first — `usage-probe.md` is written
    that way, and reading line by line drops it from the nav entirely.
    """
    lines = index.read_text(encoding="utf-8").splitlines()
    joined: list[str] = []
    for line in lines:
        if joined and line.startswith("  ") and joined[-1].startswith("- "):
            joined[-1] = f"{joined[-1]} {line.strip()}"
        else:
            joined.append(line)

    found: list[tuple[str, list[Path]]] = []
    for line in joined:
        heading = _HEADING.match(line)
        if heading is not None:
            found.append((heading.group(1), []))
            continue
        bullet = _BULLET.match(line)
        if bullet is None or not found:
            continue
        target = bullet.group(1).split("#")[0]
        if target.startswith(("http", "..", "mailto:")):
            continue
        found[-1][1].append(Path(target))
    if not found:
        raise SiteBuildError(
            "docs/index.md yielded no sections — its heading or bullet format changed, "
            "so update the nav with it rather than publishing a site with no navigation"
        )
    return found


def _refuse_a_page_with_no_entry(pages: list[Page], sections: list[NavSection]) -> None:
    linked = {entry.href for section in sections for entry in section.entries}
    linked.add(HOME.with_suffix(".html").as_posix())
    missing = sorted(
        page.output.as_posix() for page in pages if page.output.as_posix() not in linked
    )
    if missing:
        raise SiteBuildError(f"pages rendered with no way to navigate to them: {missing}")
