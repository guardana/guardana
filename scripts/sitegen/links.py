"""Where a link written for the repository has to point once the page is a web page.

`test_docs_consistency.py` already refuses a link at a file that does not exist. It
checks the markdown, and the markdown is not what a reader clicks: `.md` becomes
`.html`, a page outside `docs/` has no rendered form at all, and an anchor that
GitHub generated has to be generated the same way here. Each of those is a place
the link survives the existing gate and breaks on the site.

Anything outside `docs/` goes to GitHub rather than being rendered. The site is the
documentation; `README.md`, `CONTRIBUTING.md` and the example packages are
repository files, and a reader following one of those wants the repository.
"""

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sitegen.page import Page

_BLOB = "https://github.com/guardana/guardana/blob/main/"
_TREE = "https://github.com/guardana/guardana/tree/main/"
_EXTERNAL = ("http://", "https://", "mailto:")


@dataclass
class LinkResolver:
    """Rewrites one page's links, collecting every one it could not honour.

    Collected rather than raised on the first failure: a rename breaks links in
    several files at once, and a build that names one of them per run makes the
    author run it once per broken link.
    """

    repo: Path
    docs: Path
    anchors: dict[Path, frozenset[str]]
    problems: list[str] = field(default_factory=list)

    def for_page(self, page: Page) -> Callable[[str], str]:
        """Return the rewriter for one page's links."""

        def resolve(href: str) -> str:
            return self._resolve(page, href)

        return resolve

    def _resolve(self, page: Page, href: str) -> str:
        if not href.strip():
            self._problem(page, href, "is empty")
            return href
        if href.startswith(_EXTERNAL):
            return href
        target, _, fragment = href.partition("#")
        if not target:
            self._check_fragment(page, href, page.relative, fragment)
            return f"#{fragment}"
        resolved = (self.docs / page.relative.parent / target).resolve()
        if self.docs in resolved.parents or resolved == self.docs:
            return self._within_docs(page, href, resolved, fragment)
        return self._outside_docs(page, href, resolved)

    def _within_docs(self, page: Page, href: str, resolved: Path, fragment: str) -> str:
        relative = resolved.relative_to(self.docs)
        if relative in self.anchors:
            self._check_fragment(page, href, relative, fragment)
            hop = os.path.relpath(relative.with_suffix(".html"), page.relative.parent)
            return Path(hop).as_posix() + (f"#{fragment}" if fragment else "")
        if resolved.exists():
            # A file under docs/ that is not a rendered page — a generated JSON, say.
            # It ships in the repository, so the repository is where it is readable.
            return _github(resolved.relative_to(self.repo), resolved.is_dir())
        self._problem(page, href, "points at a file that does not exist")
        return href

    def _outside_docs(self, page: Page, href: str, resolved: Path) -> str:
        if not resolved.exists():
            self._problem(page, href, "points at a file that does not exist")
            return href
        if self.repo not in resolved.parents:
            self._problem(page, href, "points outside the repository")
            return href
        return _github(resolved.relative_to(self.repo), resolved.is_dir())

    def _check_fragment(self, page: Page, href: str, target: Path, fragment: str) -> None:
        if not fragment or fragment in self.anchors.get(target, frozenset()):
            return
        self._problem(
            page,
            href,
            f"names an anchor {target.as_posix()} does not have — the page would load "
            f"at the top, which reads as the link working",
        )

    def _problem(self, page: Page, href: str, why: str) -> None:
        self.problems.append(f"{page.relative.as_posix()} → {href!r} {why}")


def _github(relative: Path, is_directory: bool) -> str:
    base = _TREE if is_directory else _BLOB
    return base + relative.as_posix()
