"""The documentation site, checked the way the landing page is: by reading what shipped.

`test_landing_page.py` exists because a page advertised twenty-five rules through
three releases that took the number to thirty-two. The docs site is a hundred and
ninety files rather than one, generated rather than typed, and therefore prone to
the opposite failure: a build nobody re-ran, and a link that survives the markdown
gate and breaks once it is a web page.

Every check here reads `site/docs/` — what a visitor is actually served — rather
than the markdown it came from.
"""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from guardana.core.manifest.serialize import SCHEMA_URL

_HREF = re.compile(r'(?:href|src|srcset)="([^"]+)"')
_ID = re.compile(r'id="([^"]+)"')
_TAG = re.compile(r"<[a-zA-Z/][^>]*>")
_SCRIPTABLE = re.compile(r"<script|\son\w+\s*=|(?:href|src)\s*=\s*\"javascript:", re.IGNORECASE)
"""Matched against the *tags* of a page, never against its text.

A security page may name the `javascript:` scheme as one of the things a
poisoned MCP tool description reaches for, inside a `<code>` span. A
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
    """`connect-src 'none'` is non-negotiable for the documentation site.

    Free-text search over the prose is the one feature worth relaxing `script-src`
    for, and if it is ever taken, the network stays shut. If the docs site ever
    needs to reach a host, that is a deliberate decision, not a header edit
    somebody makes on the way past.
    """
    headers = (_repo() / "site" / "_headers").read_text(encoding="utf-8")

    assert "connect-src 'none'" in headers
    assert "default-src 'none'" in headers
    assert "frame-ancestors 'none'" in headers


def test_the_landing_page_loads_no_image_from_a_host_the_policy_forbids() -> None:
    """The badge test, and it is a policy test wearing a badge's clothes.

    Every third-party badge worth linking to — Product Hunt's included — ships as an
    `<img>` from the vendor's own CDN, and `img-src 'self' data:` blocks it. The
    tempting fix is one host in the header; the honest one is to draw the mark inline
    or serve it from the site, which is what the footer's DevHunt badge does. This
    fails if anybody ever takes the other route, because a policy visitors can check
    is worth more than a rendered badge.
    """
    page = (_repo() / "site" / "index.html").read_text(encoding="utf-8")
    headers = (_repo() / "site" / "_headers").read_text(encoding="utf-8")

    images = [
        url
        for tag in re.findall(r"<(?:img|source)\b[^>]*>", page)
        for url in re.findall(r'\s(?:src|srcset)="([^"]+)"', tag)
    ]
    assert "img-src 'self' data:" in headers
    assert not [url for url in images if url.startswith(("http://", "https://", "//"))], (
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
    ["index.html", "rules/index.html", "usage-scan.html", "studies/first-run-study.html"],
)
def test_a_representative_page_carries_its_own_title_and_navigation(page: str) -> None:
    html = (_site() / page).read_text(encoding="utf-8")

    assert "<title>" in html
    assert "— Guardana documentation</title>" in html
    assert '<meta name="description"' in html
    assert '<nav class="side"' in html
    # A narrow screen gets the same navigation folded away, so content is the first thing
    # it shows rather than a screen of links.
    assert '<details class="mnav">' in html
    assert '<link rel="canonical" href="https://guardana.dev/docs/' in html


def test_the_sitemap_lists_urls_the_host_answers_rather_than_redirects() -> None:
    """A sitemap of redirects is worse than none: it tells a crawler the wrong canonical.

    The host serves a page without its extension and a directory by its index, and
    307s the file form to it. So every `<loc>` must be the served form, and each one
    must have a file behind it — a URL in a sitemap is a claim that something answers.
    """
    site = _repo() / "site"
    sitemap = (site / "sitemap.xml").read_text(encoding="utf-8")
    locs = re.findall(r"<loc>([^<]+)</loc>", sitemap)

    assert locs, "the sitemap lists nothing — run `uv run python scripts/generate_sitemap.py`"
    assert not [url for url in locs if url.endswith(".html")]

    origin = "https://guardana.dev"
    missing = []
    for url in locs:
        path = url.removeprefix(origin).lstrip("/")
        candidate = site / (
            f"{path}index.html" if path.endswith("/") or not path else f"{path}.html"
        )
        if not candidate.is_file():
            missing.append(url)

    assert not missing, missing[:5]


def test_the_schema_a_saved_run_names_is_served_at_that_url() -> None:
    """A run's `$schema` is a URL a validator dereferences, so the site serves that file."""
    served = _repo() / "site" / SCHEMA_URL.removeprefix("https://guardana.dev/")

    assert served.is_file(), f"{SCHEMA_URL} is not in site/ — run scripts/build_site.py"
    assert json.loads(served.read_text(encoding="utf-8"))["$id"] == SCHEMA_URL


def test_a_published_schema_can_be_read_from_another_origin() -> None:
    """Browser-based validators fetch a `$id` cross-origin; a schema holds nothing private."""
    headers = (_repo() / "site" / "_headers").read_text(encoding="utf-8")
    block = headers.split("/schemas/*", 1)

    assert len(block) == 2, "site/_headers has no /schemas/* block"
    assert "Access-Control-Allow-Origin: *" in block[1].split("\n/", 1)[0]


def test_robots_points_at_the_sitemap() -> None:
    """A sitemap nothing announces is a file only somebody who guessed the name will find."""
    robots = (_repo() / "site" / "robots.txt").read_text(encoding="utf-8")

    assert "Sitemap: https://guardana.dev/sitemap.xml" in robots


def test_robots_lets_search_and_ai_use_the_documentation() -> None:
    """The site exists to be found and quoted correctly, so no use of it is withheld."""
    robots = (_repo() / "site" / "robots.txt").read_text(encoding="utf-8")

    assert "Content-Signal: search=yes, ai-input=yes, ai-train=yes" in robots


def test_every_page_points_agents_at_llms_txt_and_the_sitemap() -> None:
    """An agent that reads headers finds the plain-text map without parsing a page."""
    headers = (_repo() / "site" / "_headers").read_text(encoding="utf-8")
    every_page = headers.split("\n/schemas/*", 1)[0]

    assert '</llms.txt>; rel="describedby"' in every_page
    assert '</sitemap.xml>; rel="sitemap"' in every_page


def test_the_landing_page_loads_nothing_from_another_host() -> None:
    """Fonts, styles and icons come from the site itself, and the policy says so.

    The page promises that the only traffic is to the target a user points Guardana
    at; a font from a third party would tell that party who is reading the promise.
    """
    page = (_repo() / "site" / "index.html").read_text(encoding="utf-8")
    headers = (_repo() / "site" / "_headers").read_text(encoding="utf-8")
    loads = re.findall(
        r'<link[^>]*rel="(?:stylesheet|preconnect|preload|icon|dns-prefetch)"[^>]*href="([^"]+)"',
        page,
    )

    assert loads, "the landing page links no asset — update this test with the page"
    assert not [href for href in loads if href.startswith(("http://", "https://", "//"))]
    assert "https://" not in headers.split("Content-Security-Policy:", 1)[1].splitlines()[0]


def test_every_local_link_on_the_landing_page_resolves() -> None:
    """The landing page is hand-written, so its site paths get the check the docs tree gets."""
    site = _repo() / "site"
    page = (site / "index.html").read_text(encoding="utf-8")
    missing = []
    for raw in _HREF.findall(page):
        if not raw.startswith("/") or raw.startswith("//"):
            continue
        path = raw.split("#", 1)[0].split("?", 1)[0].lstrip("/")
        candidates = (
            [site / path / "index.html"]
            if not path or path.endswith("/")
            else [
                site / path,
                site / f"{path}.html",
            ]
        )
        if not any(candidate.is_file() for candidate in candidates):
            missing.append(raw)

    assert not missing, f"landing page links that site/ does not serve: {missing}"


_BRAND_V1 = "site/assets/brand/v1"
_BRAND_V1_DIGEST = "6d177eb80cb233c8fce3b613f11788f548ca0cbfc7bd573e2fada5debcb64e4c"
"""SHA-256 of `SHA256SUMS`: the digest a vendored copy of v1 is pinned to."""


def test_the_brand_files_match_the_digest_file_that_lists_them() -> None:
    root = _repo() / _BRAND_V1
    listed = {}
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest
    on_disk = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }

    assert on_disk == listed, "SHA256SUMS does not describe the files beside it"


def test_the_published_brand_version_is_never_edited_in_place() -> None:
    """Another site vendors v1 by digest, so a change is a v2 at a new path, never an edit."""
    digest = hashlib.sha256((_repo() / _BRAND_V1 / "SHA256SUMS").read_bytes()).hexdigest()

    assert digest == _BRAND_V1_DIGEST, (
        f"{_BRAND_V1} changed; publish the change as site/assets/brand/v2/ instead"
    )


_REMOVED = ("/docs/design/", "/docs/maintainers/")


def _served(site: Path, path: str) -> Path | None:
    """The file the host answers a URL path with, or None when nothing answers it."""
    relative = path.lstrip("/")
    candidates = (
        [site / relative / "index.html"]
        if not relative or relative.endswith("/")
        else [site / relative, site / f"{relative}.html", site / relative / "index.html"]
    )
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def _redirect_problems(rules: str, site: Path) -> list[str]:
    """Every way a `_redirects` file can send a visitor nowhere, or hide a live page."""
    problems: list[str] = []
    seen: list[str] = []
    for number, line in enumerate(rules.splitlines(), start=1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3 or fields[2] != "301":
            problems.append(f"{number}: not `source destination 301`: {line!r}")
            continue
        source, destination, _ = fields
        if destination.startswith(_REMOVED) or _served(site, destination) is None:
            problems.append(f"{number}: {destination} is not a page the site serves")
        if not source.endswith("*") and _served(site, source) is not None:
            problems.append(f"{number}: {source} is a live page, and a redirect always wins")
        swallowed_by = [s for s in seen if s.endswith("*") and source.startswith(s[:-1])]
        if swallowed_by:
            problems.append(f"{number}: {source} comes after {swallowed_by[0]}, which wins")
        seen.append(source)
    sources = set(seen)
    problems.extend(
        f"{source} has no rule for {source}.html"
        for source in sorted(sources)
        if not source.endswith(("*", ".html", "/")) and f"{source}.html" not in sources
    )
    return problems


def test_every_redirect_lands_on_a_page_the_site_serves() -> None:
    """A removed page keeps its subject: each redirect ends on a live page, never on another 404.

    A rule matches its path literally, so the `.html` form of a removed page needs a
    rule of its own; the host's extension handling only applies to files that exist.
    """
    site = _repo() / "site"
    problems = _redirect_problems((site / "_redirects").read_text(encoding="utf-8"), site)

    assert not problems, "site/_redirects:\n  " + "\n  ".join(problems)


def test_a_redirect_to_nowhere_or_behind_a_wildcard_is_reported() -> None:
    site = _repo() / "site"
    rules = (
        "/docs/design/* /docs/ 301\n"
        "/docs/design/trace-producer /docs/writing-an-integrator 301\n"
        "/docs/maintainers/lessons /docs/maintainers/lessons 301\n"
        "/docs/usage-scan /docs/ 301\n"
    )

    problems = _redirect_problems(rules, site)

    assert any("comes after /docs/design/*" in p for p in problems)
    assert any("/docs/maintainers/lessons is not a page" in p for p in problems)
    assert any("/docs/usage-scan is a live page" in p for p in problems)
    assert any("no rule for /docs/design/trace-producer.html" in p for p in problems)
