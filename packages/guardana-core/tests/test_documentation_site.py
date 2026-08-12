"""The documentation site, checked the way the landing page is: by reading what shipped.

`test_landing_page.py` exists because a page advertised twenty-five rules through
three releases that took the number to thirty-two. The docs site is a hundred and
ninety files rather than one, generated rather than typed, and therefore prone to
the opposite failure: a build nobody re-ran, and a link that survives the markdown
gate and breaks once it is a web page.

Every check here reads `site/docs/` — what a visitor is actually served — rather
than the markdown it came from.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest

_HREF = re.compile(r'(?:href|src)="([^"]+)"')
_ID = re.compile(r'id="([^"]+)"')
_TAG = re.compile(r"<[a-zA-Z/][^>]*>")
_SCRIPTABLE = re.compile(r"<script|\son\w+\s*=|(?:href|src)\s*=\s*\"javascript:", re.IGNORECASE)
"""Matched against the *tags* of a page, never against its text.

`design/mcp-authorization-depth.html` names the `javascript:` scheme as one of the
things a poisoned MCP tool description reaches for, inside a `<code>` span. A
scanner that read the prose would report the page describing the attack as
carrying it — a false red on a security page, which is the failure mode this
project spends the most effort refusing in the other direction.
"""


def _repo() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "README.md").is_file() and (parent / "packages").is_dir():
            return parent
    raise AssertionError("could not locate the repository root")


def _site() -> Path:
    return _repo() / "site" / "docs"


def _pages() -> list[Path]:
    pages = sorted(_site().rglob("*.html"))
    assert pages, "site/docs has no pages — run `uv run python scripts/build_site.py`"
    return pages


def test_the_built_site_matches_the_documentation_it_came_from() -> None:
    """Run as a subprocess, because the command is the thing under test.

    A page edited without rebuilding turns this red immediately rather than
    waiting for a release to notice, which is the same guard `generate_docs.py`,
    `sync_site.py` and `generate_llms_txt.py` each already have.
    """
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(_repo() / "scripts" / "build_site.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=_repo(),
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_every_link_in_the_rendered_site_resolves() -> None:
    """The half `test_docs_consistency.py` cannot see.

    That test checks `.md` targets in markdown. What ships is HTML, where every
    internal target has been rewritten to `.html`, every page outside `docs/` has
    become a GitHub URL, and every anchor has been regenerated. Each rewrite is a
    place a link that passes over there breaks over here.
    """
    site = _site()
    anchors = {page: set(_ID.findall(page.read_text(encoding="utf-8"))) for page in _pages()}
    broken = []
    for page in _pages():
        for raw in _HREF.findall(page.read_text(encoding="utf-8")):
            if raw.startswith(("http://", "https://", "mailto:", "data:")):
                continue
            target, _, fragment = raw.partition("#")
            resolved = page if not target else (page.parent / target).resolve()
            if not resolved.exists():
                broken.append(f"{page.relative_to(site)} → {raw}")
            elif fragment and resolved.suffix == ".html" and fragment not in anchors[resolved]:
                broken.append(f"{page.relative_to(site)} → {raw} (no such anchor)")

    assert not broken, "links that do not work on the built site:\n  " + "\n  ".join(broken)


def test_no_page_ships_anything_the_content_security_policy_forbids() -> None:
    """`script-src 'none'` is a claim a visitor checks in devtools, not a default.

    A page carrying a script tag, an inline handler or a `javascript:` URL would
    not merely fail to work — it would be a security project shipping a page that
    silently does nothing while looking as though it does, on the site where the
    claim is read.
    """
    offenders = [
        page.relative_to(_site()).as_posix()
        for page in _pages()
        if _SCRIPTABLE.search(" ".join(_TAG.findall(page.read_text(encoding="utf-8"))))
    ]

    assert not offenders, f"pages that would need script to work: {offenders}"


def test_the_policy_still_forbids_reaching_any_host() -> None:
    """`connect-src 'none'` is the line the design document called non-negotiable.

    Free-text search over the prose is the one feature worth relaxing `script-src`
    for, and `docs/design/documentation-site.md` says that if it is ever taken, the
    network stays shut. This is that promise as a test rather than a paragraph — if
    the docs site ever needs to reach a host, that is a decision with a design
    document, not a header edit somebody makes on the way past.
    """
    headers = (_repo() / "site" / "_headers").read_text(encoding="utf-8")

    assert "connect-src 'none'" in headers
    assert "default-src 'none'" in headers
    assert "frame-ancestors 'none'" in headers


def test_the_landing_page_loads_no_image_from_a_host_the_policy_forbids() -> None:
    """The badge test, and it is a policy test wearing a badge's clothes.

    Every third-party badge worth linking to — Product Hunt's included — ships as an
    `<img>` from the vendor's own CDN, and `img-src 'self' data:` blocks it. The
    tempting fix is one host in the header; the honest one is to draw the mark
    inline, which is what `.btn-ph` does. This fails if anybody ever takes the other
    route, because a policy visitors can check is worth more than a rendered badge.
    """
    page = (_repo() / "site" / "index.html").read_text(encoding="utf-8")
    headers = (_repo() / "site" / "_headers").read_text(encoding="utf-8")

    remote = [src for src in _HREF.findall(page) if src.startswith(("http://", "https://"))]
    assert "img-src 'self' data:" in headers
    assert not [src for src in remote if "<img" in page[: page.index(src)][-200:]], (
        "the landing page loads an image from another host, which `img-src 'self' "
        "data:` refuses — so it renders as a broken image, or the header was widened"
    )


def test_the_landing_page_links_to_the_product_hunt_launch() -> None:
    """A launch page nobody can reach from the product is a launch page nobody reaches."""
    page = (_repo() / "site" / "index.html").read_text(encoding="utf-8")

    assert "https://www.producthunt.com/products/guardana?launch=guardana" in page


def test_the_landing_page_sends_readers_to_the_documentation_site() -> None:
    """The open item `site/README.md` carried from when the domain was parked."""
    page = (_repo() / "site" / "index.html").read_text(encoding="utf-8")

    assert '<a href="/docs/"' in page, (
        "the header's Docs link no longer points at /docs/ — it pointed at the GitHub "
        "README for three releases while the site had no documentation of its own"
    )


def test_every_rule_in_the_registry_has_a_page_and_appears_in_the_index() -> None:
    """The explorer is generated, and this is what makes that worth anything.

    An explorer that quietly stopped listing a rule would be the landing page's
    stale count with better typography: it is the page a reader trusts to be
    complete, so completeness is what gets pinned.
    """
    from guardana.rules import provide_rules  # noqa: PLC0415 — registry, not core

    index = (_site() / "rules" / "index.html").read_text(encoding="utf-8")
    missing = []
    for rule in provide_rules():
        page = _site() / "rules" / f"{rule.meta.id}.html"
        if not page.is_file():
            missing.append(f"{rule.meta.id}: no page")
        elif rule.meta.id not in index:
            missing.append(f"{rule.meta.id}: not listed on the explorer index")

    assert not missing, "\n  ".join(missing)


def test_the_explorer_offers_a_filter_for_every_framework_entry_a_rule_maps_to() -> None:
    """ "Does it cover LLM03 in the 2026 edition?" is answerable by navigation alone."""
    from guardana.rules import provide_rules  # noqa: PLC0415 — registry, not core

    referenced = {ref.reference for rule in provide_rules() for ref in rule.meta.taxonomy}
    missing = sorted(
        reference
        for reference in referenced
        if not (
            _site() / "rules" / "by" / f"reference-{reference.replace(':', '-')}.html"
        ).is_file()
    )

    assert not missing, f"framework entries with no filter page: {missing}"


@pytest.mark.parametrize(
    "page",
    ["index.html", "rules/index.html", "usage-scan.html", "design/documentation-site.html"],
)
def test_a_representative_page_carries_its_own_title_and_navigation(page: str) -> None:
    html = (_site() / page).read_text(encoding="utf-8")

    assert "<title>" in html
    assert "— Guardana documentation</title>" in html
    assert '<meta name="description"' in html
    assert '<nav class="side">' in html
    assert '<link rel="canonical" href="https://guardana.dev/docs/' in html
