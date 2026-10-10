"""The HTML shell every generated page shares.

Assets are linked relatively rather than from the site root, so the tree opens
from the filesystem as well as it does over HTTP — `open site/docs/index.html` has
to work, because a preview nobody can run is a preview nobody does.
"""

from dataclasses import dataclass
from html import escape

from sitegen.nav import NavSection
from sitegen.page import served_path

_REPO = "https://github.com/guardana/guardana"
_MAINTAINER = "Konrad Karauda"
# The mark, drawn inline so the header costs no request: a shield with a check.
MARK = (
    '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" '
    'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 2.8 4.5 5.6v6.1c0 4.6 3.2 8.2 7.5 9.5 4.3-1.3 7.5-4.9 7.5-9.5V5.6z" '
    'style="color:var(--brand)"/><path d="m8.6 12.1 2.4 2.4 4.5-4.8"/></svg>'
)


@dataclass(frozen=True, slots=True)
class Chrome:
    """Everything a page needs from outside itself in order to be rendered."""

    sections: tuple[NavSection, ...]
    version: str
    notes: bool = False
    """Whether at least one note is published, and so whether the header links to them."""


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
    edit = (
        f'<a href="{_REPO}/blob/main/{escape(edit_path)}">Edit this page on GitHub</a>'
        if edit_path
        else f'<a href="{_REPO}">Source on GitHub</a>'
    )
    notes = f'<a href="{up}../notes/index.html">Notes</a>\n' if chrome.notes else ""
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
<link rel="stylesheet" href="{up}docs.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="top"><div class="bar">
<a class="mark" href="{up}../">{MARK}<span class="w">guard<b>ana</b></span></a>
<nav>
<a href="{up}index.html">Documentation</a>
<a href="{up}rules/index.html">Rules</a>
{notes}<a href="{_REPO}">GitHub</a>
</nav>
</div></header>
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
</main>
</div>
<footer class="foot"><div class="bar">
<span class="who">Guardana {escape(chrome.version)} · Apache-2.0 ·
maintained by {_MAINTAINER}</span>
{edit}
<a href="{_REPO}">github.com/guardana</a>
<a href="{up}../llms.txt">llms.txt</a>
</div></footer>
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
