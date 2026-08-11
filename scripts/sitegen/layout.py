"""The HTML shell every generated page shares.

Assets are linked relatively rather than from the site root, so the tree opens
from the filesystem as well as it does over HTTP — `open site/docs/index.html` has
to work, because a preview nobody can run is a preview nobody does.
"""

from dataclasses import dataclass
from html import escape

from sitegen.nav import NavSection

_ICON = (
    "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
    "<text y='.9em' font-size='90'>🛡️</text></svg>"
)
_REPO = "https://github.com/guardana/guardana"


@dataclass(frozen=True, slots=True)
class Chrome:
    """Everything a page needs from outside itself in order to be rendered."""

    sections: tuple[NavSection, ...]
    version: str


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
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} — Guardana documentation</title>
<meta name="description" content="{escape(summary)}">
<link rel="canonical" href="https://guardana.dev/docs/{escape(href)}">
<link rel="icon" href="{_ICON}">
<link rel="stylesheet" href="{up}docs.css">
</head>
<body>
<header class="top"><div class="bar">
<a class="mark" href="{up}../">guard<span>ana</span></a>
<nav>
<a href="{up}index.html">Documentation</a>
<a href="{up}rules/index.html">Rules</a>
<a href="{_REPO}">GitHub</a>
</nav>
</div></header>
<div class="shell">
<nav class="side">
{_sidebar(chrome.sections, href, up)}
</nav>
<main>
{body}
</main>
</div>
<footer class="foot"><div class="bar">
<span>Guardana {escape(chrome.version)} · Apache-2.0</span>
{edit}
<a href="{up}../llms.txt">llms.txt</a>
</div></footer>
</body>
</html>
"""


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
