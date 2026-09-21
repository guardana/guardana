#!/usr/bin/env python3
"""Generate `site/sitemap.xml` and `site/robots.txt` from the pages actually built.

    uv run python scripts/generate_sitemap.py            # write them
    uv run python scripts/generate_sitemap.py --check    # exit 1 if stale; write nothing

The same pair of guards `build_site.py`, `sync_site.py` and `generate_llms_txt.py`
have, for the same reason: a list of URLs written by hand is a list that keeps
naming a page after it is gone.

**The URLs come from the built tree, not from `docs/index.md`.** A sitemap is a
claim about what answers a request, and only a file that exists answers one —
deriving it from the curated map would let a page that failed to build stay listed.

**Every URL is the form the host serves.** Cloudflare answers `/docs/usage-scan`
and redirects `/docs/usage-scan.html` to it, so listing file names would publish a
sitemap of redirects. `sitegen.page.served_path` is that rule, shared with the
canonical link so the two cannot drift.

**No `lastmod`, `changefreq` or `priority`.** A modification time in a checkout is
when the clone happened, not when the page changed, so writing one would commit a
number that means nothing and churns on every machine. The other two are hints
search engines have said for years that they ignore.
"""

import argparse
import sys
from pathlib import Path
from xml.sax.saxutils import escape

_REPO = Path(__file__).resolve().parent.parent
_SITE = _REPO / "site"
_SITEMAP = _SITE / "sitemap.xml"
_ROBOTS = _SITE / "robots.txt"
_ORIGIN = "https://guardana.dev"

sys.path.insert(0, str(_REPO / "scripts"))

from sitegen.page import served_path  # noqa: E402

_NAMED = 8
"""How many stale paths `--check` prints before it stops listing them."""


def _urls() -> list[str]:
    """Every page in the built site, as the URL it is served at, in a stable order."""
    pages = sorted(path.relative_to(_SITE).as_posix() for path in _SITE.rglob("*.html"))
    return [_ORIGIN + served_path(page) for page in pages]


def _sitemap() -> str:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    lines.extend(f"  <url><loc>{escape(url)}</loc></url>" for url in _urls())
    lines.append("</urlset>")
    return "\n".join(lines) + "\n"


def _robots() -> str:
    """Everything is public documentation, so the only thing worth saying is where the map is."""
    return f"User-agent: *\nAllow: /\n\nSitemap: {_ORIGIN}/sitemap.xml\n"


def main() -> int:
    """Write the two files, or report that what is on disk no longer matches the site."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="exit 1 if it is out of date; write nothing"
    )
    arguments = parser.parse_args()

    if not _SITE.is_dir():
        print("site/ has not been built; run scripts/build_site.py first", file=sys.stderr)
        return 1

    wanted = {_SITEMAP: _sitemap(), _ROBOTS: _robots()}
    stale = [
        path
        for path, content in wanted.items()
        if not path.exists() or path.read_text(encoding="utf-8") != content
    ]

    if arguments.check:
        if stale:
            shown = ", ".join(path.relative_to(_REPO).as_posix() for path in stale[:_NAMED])
            print(f"{shown} is out of date", file=sys.stderr)
            print("run `uv run python scripts/generate_sitemap.py`", file=sys.stderr)
            return 1
        print(f"site/sitemap.xml lists {len(_urls())} pages; site/robots.txt is current")
        return 0

    for path, content in wanted.items():
        path.write_text(content, encoding="utf-8")
    print(f"wrote site/sitemap.xml ({len(_urls())} pages) and site/robots.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
