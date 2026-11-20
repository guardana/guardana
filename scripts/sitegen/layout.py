"""The HTML shell every generated page shares, with the landing page's header and footer.

Assets are linked relatively rather than from the site root, so the tree opens
from the filesystem as well as it does over HTTP — `open site/docs/index.html` has
to work, because a preview nobody can run is a preview nobody does.
"""

from collections.abc import Callable
from dataclasses import dataclass
from html import escape

from sitegen.nav import NavSection
from sitegen.page import served_path

_REPO = "https://github.com/guardana/guardana"
_MAINTAINER = "Konrad Karauda"
# The landing page's own header icons, drawn inline so the header costs no request.
LOGO = (
    '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" '
    'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.8 '
    '4.5 5.6v6.1c0 4.6 3.2 8.2 7.5 9.5 4.3-1.3 7.5-4.9 7.5-9.5V5.6z"/><path d="m8.6 12.1 '
    '2.4 2.4 4.5-4.8"/></svg>'
)
_MOON = (
    '<svg class="moon" viewBox="0 0 24 24" aria-hidden="true" fill="none" '
    'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
    'stroke-linejoin="round"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 '
    '10.5z"/></svg>'
)
_SUN = (
    '<svg class="sun" viewBox="0 0 24 24" aria-hidden="true" fill="none" '
    'stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" '
    'cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 '
    '12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4"/></svg>'
)
_STAR = (
    '<svg class="star" viewBox="0 0 24 24" aria-hidden="true" fill="currentColor"><path '
    'd="M12 2.8l2.83 5.73 6.32.92-4.57 4.46 1.08 6.29L12 17.23 6.34 20.2l1.08-6.29L2.85 '
    '9.45l6.32-.92z"/></svg>'
)


@dataclass(frozen=True, slots=True)
class Chrome:
    """Everything a page needs from outside itself in order to be rendered."""

    sections: tuple[NavSection, ...]
    version: str
    notes: bool = False
    """Whether at least one note is published, and so whether the header links to them."""


def site_header(*, link: Callable[[str], str], version: str | None, notes: bool) -> str:
    """The landing page's header; `link` turns a path from the site root into an href."""
    pill = (
        f'<a class="vlink" href="{_REPO}/releases"><span class="ver mono">v{escape(version)}'
        "</span></a>\n"
        if version
        else ""
    )
    notes_link = f'<a href="{link("notes/")}">Notes</a>\n' if notes else ""
    return f"""<header class="top"><div class="w">
<a class="logo" href="{link("")}">{LOGO}<span>guard<b>ana</b></span></a>
{pill}<nav class="links" aria-label="Primary">
<a href="{link("docs/")}" class="sm-keep">Docs</a>
<a href="{link("docs/rules/")}" class="sm-keep">Rules</a>
{notes_link}</nav>
<div class="right">
<input type="checkbox" id="theme" aria-label="Switch between light and dark mode">
<label class="tgl" for="theme" title="Switch between light and dark mode">{_MOON}{_SUN}</label>
<a class="btn sm p" href="{_REPO}">{_STAR}<span>Star<span class="xs-vh"> on GitHub</span></span></a>
</div>
</div></header>"""


def site_footer(*, link: Callable[[str], str], notes: bool) -> str:
    """The landing page's footer; `link` turns a path from the site root into an href."""
    notes_item = f'<li><a href="{link("notes/")}">Notes</a></li>' if notes else ""
    badge = link("assets/badges/devhunt-")
    return f"""<footer class="ft"><div class="w">
<div class="fb">
<a class="logo" href="{link("")}">{LOGO}<span>guard<b>ana</b></span></a>
<p>Guardana · Apache-2.0 · Maintained by {_MAINTAINER} · github.com/guardana/guardana</p>
<a class="badge2" href="https://devhunt.org/tool/guardana" rel="noopener"><img class="b-lt" \
src="{badge}light.svg" alt="Featured on DevHunt" width="147" height="36"><img class="b-dk" \
src="{badge}dark.svg" alt="Featured on DevHunt" width="147" height="36"></a>
</div>
<div><h4>Products</h4><ul><li><a href="{link("")}">Guardana</a></li><li><a \
href="https://control.guardana.dev/">Guardana Control</a> <span class="tag2">alpha</span></li></ul></div>
<div><h4>Guardana</h4><ul><li><a href="{link("docs/")}">Documentation</a></li><li><a \
href="{link("docs/rules/")}">Rule catalogue</a></li><li><a href="{_REPO}/releases">Releases</a></li>\
{notes_item}</ul></div>
<div><h4>Get it</h4><ul><li><a href="https://pypi.org/project/guardana-cli/">PyPI</a></li><li><a \
href="https://github.com/marketplace/actions/guardana-ai-security-scan">GitHub Action</a></li><li><a \
href="{_REPO}">Source</a></li></ul></div>
<div><h4>More</h4><ul><li><a href="{link("llms.txt")}">llms.txt</a></li><li><a \
href="{link("sitemap.xml")}">Sitemap</a></li><li><a \
href="https://www.producthunt.com/products/guardana?launch=guardana" rel="noopener">Product Hunt</a>\
</li></ul></div>
</div></footer>"""


def page(  # noqa: PLR0913 — one keyword per fact the shell needs; none is derivable
    *,
    chrome: Chrome,
    href: str,
    title: str,
    summary: str,
    body: str,
    edit_path: str | None,
) -> str:
    """Wrap rendered content in the shell, with `href` marked current in the nav."""
    up = "../" * (href.count("/"))

    def link(path: str) -> str:
        # Read from the filesystem, a link to a directory opens a listing, so name its index.
        return f"{up}../{path}index.html" if path == "" or path.endswith("/") else f"{up}../{path}"

    edit = (
        f'<p class="pagefoot"><a href="{_REPO}/blob/main/{escape(edit_path)}">Edit this page on '
        "GitHub</a></p>\n"
        if edit_path
        else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} — Guardana documentation</title>
<meta name="description" content="{escape(summary)}">
<link rel="canonical" href="https://guardana.dev{escape(served_path("docs/" + href))}">
<link rel="icon" href="{up}../favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="{up}../assets/brand/v1/tokens.css">
<link rel="stylesheet" href="{up}../assets/site.css">
<link rel="stylesheet" href="{up}docs.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
{site_header(link=link, version=chrome.version, notes=chrome.notes)}
<div class="shell">
<nav class="side" aria-label="Documentation">
{_sidebar(chrome.sections, href, up)}
</nav>
<details class="mnav">
<summary>Menu · <b>{escape(_current_label(chrome.sections, href))}</b></summary>
<nav class="inner" aria-label="Documentation">
{_sidebar(chrome.sections, href, up)}
</nav>
</details>
<main id="main">
{body}
{edit}</main>
</div>
{site_footer(link=link, notes=chrome.notes)}
</body>
</html>
"""


def _current_label(sections: tuple[NavSection, ...], current: str) -> str:
    for section in sections:
        for entry in section.entries:
            if entry.href == current:
                return entry.label
    return "Overview"


def _sidebar(sections: tuple[NavSection, ...], current: str, up: str) -> str:
    home = ' aria-current="page"' if current == "index.html" else ""
    out: list[str] = [f'<ul class="home"><li><a href="{up}index.html"{home}>Overview</a></li></ul>']
    for section in sections:
        out.append(f"<h2>{escape(section.title)}</h2><ul>")
        for entry in section.entries:
            here = ' aria-current="page"' if entry.href == current else ""
            tag = (
                f'<span class="tag">{escape(entry.status)}</span>'
                if entry.status not in ("stable", "")
                else ""
            )
            out.append(
                f'<li><a href="{up}{escape(entry.href)}"{here}>{escape(entry.label)}{tag}</a></li>'
            )
        out.append("</ul>")
    return "\n".join(out)


def heading(title_html: str, summary_html: str, status: str, crumb: str = "") -> str:
    """Open a page: where you are, what this is, and how settled it is.

    Both title and summary arrive already rendered, because both are markdown an
    author wrote — "`guardana scan` — static, offline, CI-friendly" has a code span
    in it, and escaping that printed backticks at the top of every command page.
    """
    badge = (
        f'<span class="status {escape(status)}">{escape(status)}</span>'
        if status != "stable"
        else ""
    )
    trail = f'<p class="crumb">{crumb}</p>' if crumb else ""
    return f'{trail}<h1>{title_html}{badge}</h1><p class="lede">{summary_html}</p>'
