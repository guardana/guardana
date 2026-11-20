"""Render `notes/*.md` into `site/notes/`: one page per note, an index and an Atom feed.

Notes are dated articles, kept apart from `docs/` because a documentation page
holds no history and a note is nothing but a record of when something was true.
Following them needs no account and no script: the feed is the subscription.

With no note on disk the tree is empty, so nothing is written and nothing links
to it. Every URL a note page, the index or the feed carries is the served form
(`sitegen.page.served_path`), and no page loads anything from another host.
"""

import datetime
import os
import re
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from sitegen import layout, render
from sitegen.diagram import DiagramError
from sitegen.errors import SiteBuildError
from sitegen.page import read_pages, served_path

ORIGIN = "https://guardana.dev"
FEED_ID = "tag:guardana.dev,2026:notes"
"""The feed's permanent identity; a reader that sees it change treats it as a new feed."""

_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_RESERVED_SLUGS = frozenset({"index"})
"""`index.html` is the list of notes, so a note called `index` would overwrite it."""
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
"""C0 control characters XML 1.0 cannot carry, so a feed holding one would not parse."""
_REQUIRED = ("title", "date", "summary")
_OPTIONAL = ("devto",)
_FENCE = "---\n"
_EXTERNAL = ("http://", "https://", "mailto:")
_AUTHOR = "Guardana maintainers"
_FEED_TITLE = "Guardana notes"
_FEED_SUBTITLE = "Articles from the Guardana maintainers about AI security verification."
# Docs pages fill a grid column beside the sidebar; a note page has no sidebar, so
# its column is centred instead. Inline, because docs.css is shared with site/docs/.
_STYLE = (
    "main.notes{margin:0 auto;padding:34px 20px 88px}"
    ".notes-index{list-style:none;padding:0}"
    ".notes-index li{margin:0 0 26px}"
    ".notes-index time,.notes time{color:var(--faint);font-size:14px}"
    ".notes-index h2{font-size:21px;margin:2px 0 4px;border:0;padding:0}"
    ".notes-index p{margin:0;color:var(--muted)}"
)


@dataclass(frozen=True, slots=True)
class Note:
    """One article: its declared metadata, its markdown body, and where it is served."""

    slug: str
    source: str
    """The source path relative to the repository, for error messages."""

    title: str
    date: datetime.date
    summary: str
    devto: str | None
    body: str

    @property
    def output(self) -> str:
        """The path of the rendered page, relative to `site/notes/`."""
        return f"{self.slug}.html"

    @property
    def url(self) -> str:
        """The absolute URL this note is served at."""
        return ORIGIN + served_path(f"notes/{self.output}")


def read_notes(notes: Path) -> list[Note]:
    """Read every note under `notes/`, newest first; refuse one that does not describe itself.

    An absent directory is no notes, not an error: the tree it would build is empty.
    """
    if not notes.is_dir():
        return []
    strays = sorted(
        path.relative_to(notes).as_posix()
        for path in notes.rglob("*")
        if path.is_file() and (path.parent != notes or path.suffix != ".md")
    )
    if strays:
        raise SiteBuildError(
            f"notes/{strays[0]}: notes/ holds only <slug>.md files, side by side; "
            f"this file would not be built"
        )
    parsed = [_note(path) for path in sorted(notes.glob("*.md"))]
    _refuse_duplicate_titles(parsed)
    return sorted(parsed, key=lambda note: (note.date, note.slug), reverse=True)


def build_notes(repo: Path) -> dict[str, str]:
    """Render the whole notes tree, keyed by path under `site/notes/`; empty with no notes."""
    notes = read_notes(repo / "notes")
    if not notes:
        return {}
    docs = repo / "docs"
    links = _Links(
        repo=repo,
        docs_anchors={page.relative: render.anchors_of(page.body) for page in read_pages(docs)},
        note_anchors={note.slug: render.anchors_of(note.body) for note in notes},
    )
    files = {
        "index.html": _index(notes),
        "feed.xml": _parsed(_feed(notes)),
    }
    for note in notes:
        files[note.output] = _note_page(note, links.for_note(note))
    if links.problems:
        raise SiteBuildError(
            "links that do not survive rendering:\n  " + "\n  ".join(sorted(links.problems))
        )
    return files


def _note(path: Path) -> Note:
    source = f"notes/{path.name}"
    slug = path.stem
    if not _SLUG.fullmatch(slug) or slug in _RESERVED_SLUGS:
        raise SiteBuildError(
            f"{source}: the file name is the URL, so it must be lowercase words joined by "
            f"hyphens (and not {', '.join(sorted(_RESERVED_SLUGS))}), got {slug!r}"
        )
    text = path.read_text(encoding="utf-8")
    if not text.startswith(_FENCE):
        raise SiteBuildError(f"{source}: no YAML front matter; a note states {_keys()}")
    block, closed, body = text[len(_FENCE) :].partition(f"\n{_FENCE}")
    if not closed:
        raise SiteBuildError(f"{source}: front matter has no closing '---' line")
    try:
        declared = yaml.safe_load(block)
    except (yaml.YAMLError, ValueError) as exc:
        # PyYAML raises ValueError, not YAMLError, for a date-shaped value that is no date.
        raise SiteBuildError(f"{source}: front matter is not valid YAML: {exc}") from exc
    if not isinstance(declared, dict):
        raise SiteBuildError(f"{source}: front matter must be a mapping of {_keys()}")
    unknown = sorted(str(key) for key in declared if key not in (*_REQUIRED, *_OPTIONAL))
    if unknown:
        raise SiteBuildError(
            f"{source}: unknown front matter {', '.join(unknown)}; a note states {_keys()}"
        )
    missing = [key for key in _REQUIRED if key not in declared]
    if missing:
        raise SiteBuildError(f"{source}: front matter is missing {', '.join(missing)}")
    note = Note(
        slug=slug,
        source=source,
        title=_plain(declared, "title", source),
        date=_date(declared["date"], source),
        summary=_plain(declared, "summary", source),
        devto=_devto(declared.get("devto"), source),
        body=body.lstrip("\n"),
    )
    if not note.body.strip():
        raise SiteBuildError(f"{source}: the note has no body")
    return note


def _keys() -> str:
    return ", ".join(_REQUIRED) + " and optionally " + ", ".join(_OPTIONAL)


def _text(declared: dict[object, object], key: str, source: str) -> str:
    value = declared[key]
    if not isinstance(value, str) or not value.strip():
        raise SiteBuildError(f"{source}: front matter '{key}' must be a non-empty string")
    return value.strip()


def _plain(declared: dict[object, object], key: str, source: str) -> str:
    """Read a title or summary: one line of text, inline code allowed, no link or image.

    Front matter is rendered outside the link resolver, so a link there would ship
    unchecked and an image would load from wherever it points.
    """
    value = _text(declared, key, source)
    if _CONTROL.search(value):
        raise SiteBuildError(f"{source}: front matter '{key}' holds a control character")
    for token in render.parser().parseInline(value):
        if any(child.type in ("link_open", "image") for child in token.children or ()):
            raise SiteBuildError(
                f"{source}: front matter '{key}' may not hold a link or an image; "
                f"put them in the body, where links are checked"
            )
    return value


def _date(value: object, source: str) -> datetime.date:
    """Accept a bare ISO date, written plain or quoted; a time of day is refused."""
    if isinstance(value, datetime.datetime):
        raise SiteBuildError(f"{source}: front matter 'date' must be a date without a time")
    if isinstance(value, datetime.date):
        return value
    if isinstance(value, str) and _ISO_DATE.fullmatch(value.strip()):
        try:
            return datetime.date.fromisoformat(value.strip())
        except ValueError:
            pass
    raise SiteBuildError(f"{source}: front matter 'date' must be an ISO date, got {value!r}")


def _devto(value: object, source: str) -> str | None:
    if value is None:
        return None
    parts = urlsplit(value) if isinstance(value, str) else None
    if parts is None or parts.scheme != "https" or parts.hostname != "dev.to":
        raise SiteBuildError(
            f"{source}: front matter 'devto' must be the https://dev.to/ URL of the "
            f"cross-post, got {value!r}"
        )
    return str(value)


def _refuse_duplicate_titles(notes: list[Note]) -> None:
    seen: dict[str, str] = {}
    for note in notes:
        key = note.title.casefold()
        if key in seen:
            raise SiteBuildError(
                f"{note.source} and {seen[key]} share the title {note.title!r}; "
                f"a reader of the index or the feed could not tell them apart"
            )
        seen[key] = note.source


@dataclass
class _Links:
    """Rewrites a note's local links to served URLs, collecting every one it cannot honour.

    A note links into the documentation or to another note. Any other repository
    file has no page on this site, so it is refused rather than sent to a host the
    reader did not choose; the author writes that URL out in full instead.
    """

    repo: Path
    docs_anchors: dict[Path, frozenset[str]]
    note_anchors: dict[str, frozenset[str]]
    problems: list[str] = field(default_factory=list)

    def for_note(self, note: Note) -> Callable[[str], str]:
        """Return the rewriter for one note's links."""

        def resolve(href: str) -> str:
            return self._resolve(note, href)

        return resolve

    def _resolve(self, note: Note, href: str) -> str:
        if not href.strip():
            self._problem(note, href, "is empty")
            return href
        if href.startswith(_EXTERNAL):
            return href
        target, _, fragment = href.partition("#")
        suffix = f"#{fragment}" if fragment else ""
        if not target:
            self._fragment(note, href, self.note_anchors[note.slug], fragment)
            return suffix
        notes = self.repo / "notes"
        docs = self.repo / "docs"
        resolved = Path(os.path.normpath(notes / target))
        if docs in resolved.parents:
            relative = resolved.relative_to(docs)
            if relative in self.docs_anchors:
                self._fragment(note, href, self.docs_anchors[relative], fragment)
                return served_path("docs/" + relative.with_suffix(".html").as_posix()) + suffix
        elif (
            resolved.parent == notes
            and resolved.suffix == ".md"
            and resolved.stem in self.note_anchors
        ):
            self._fragment(note, href, self.note_anchors[resolved.stem], fragment)
            return served_path(f"notes/{resolved.stem}.html") + suffix
        self._problem(
            note,
            href,
            "points at a file that does not exist"
            if not resolved.exists()
            else "points at a file with no page on this site; link a published page under "
            "docs/ or notes/, or write the full URL",
        )
        return href

    def _fragment(self, note: Note, href: str, anchors: frozenset[str], fragment: str) -> None:
        if fragment and fragment not in anchors:
            self._problem(note, href, "names an anchor its target does not have")

    def _problem(self, note: Note, href: str, why: str) -> None:
        self.problems.append(f"{note.source} → {href!r} {why}")


def _note_page(note: Note, resolve: Callable[[str], str]) -> str:
    title_html, body = render.split_heading(note.body)
    _refuse_images(note, body)
    try:
        html = render.render(body, resolve).html
    except DiagramError as exc:
        raise SiteBuildError(f"{note.source}: diagram: {exc}") from None
    crosspost = (
        f'<p class="crumb"><a href="{escape(note.devto)}">Also on dev.to</a></p>'
        if note.devto
        else ""
    )
    heading = layout.heading(
        title_html or escape(note.title),
        render.inline(note.summary),
        "stable",
        crumb=f'<a href="/notes/">Notes</a> · {_time(note.date)}',
    )
    return _shell(
        path=served_path(f"notes/{note.output}"),
        title=f"{note.title} — Guardana notes",
        description=render.inline_text(note.summary),
        body=heading + crosspost + render.wrap_tables(html),
    )


def _refuse_images(note: Note, body: str) -> None:
    """Refuse any image: the tree publishes no image file, and a remote one reaches another host."""
    for token in render.parser().parse(body):
        if any(child.type == "image" for child in token.children or ()):
            raise SiteBuildError(
                f"{note.source}: a note cannot embed an image; the notes tree publishes "
                f"no files besides its pages, and a remote image is a request to another host"
            )


def _index(notes: list[Note]) -> str:
    items = "\n".join(
        f'<li>{_time(note.date)}<h2><a href="{served_path("notes/" + note.output)}">'
        f"{escape(note.title)}</a></h2><p>{render.inline(note.summary)}</p></li>"
        for note in notes
    )
    body = (
        layout.heading(
            "Notes",
            'Articles from the Guardana maintainers. Follow them with the <a href="/notes/'
            'feed.xml">Atom feed</a>; nothing here needs an account.',
            "stable",
        )
        + f'<ol class="notes-index">\n{items}\n</ol>'
    )
    return _shell(
        path=served_path("notes/index.html"),
        title=_FEED_TITLE,
        description=_FEED_SUBTITLE,
        body=body,
    )


def _time(date: datetime.date) -> str:
    return f'<time datetime="{date.isoformat()}">{date.isoformat()}</time>'


def _shell(*, path: str, title: str, description: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<meta name="description" content="{escape(description)}">
<link rel="canonical" href="{ORIGIN}{escape(path)}">
<link rel="alternate" type="application/atom+xml" title="{_FEED_TITLE}" href="/notes/feed.xml">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/brand/v1/tokens.css">
<link rel="stylesheet" href="/assets/site.css">
<link rel="stylesheet" href="/docs/docs.css">
<style>{_STYLE}</style>
</head>
<body>
{layout.site_header(link=_from_root, version=None, notes=True)}
<main class="notes">
{body}
<p class="pagefoot"><a href="/notes/feed.xml">Atom feed</a></p>
</main>
{layout.site_footer(link=_from_root, notes=True)}
</body>
</html>
"""


def _from_root(path: str) -> str:
    return f"/{path}"


def _feed(notes: list[Note]) -> str:
    """Write the Atom 1.0 feed: the summary of each note, newest first, with stable ids."""
    entries = "".join(
        f"""  <entry>
    <id>tag:guardana.dev,{note.date.isoformat()}:notes/{note.slug}</id>
    <title>{escape(note.title)}</title>
    <link rel="alternate" type="text/html" href="{note.url}"/>
    <updated>{_timestamp(note.date)}</updated>
    <summary>{escape(render.inline_text(note.summary))}</summary>
  </entry>
"""
        for note in notes
    )
    return f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>{FEED_ID}</id>
  <title>{_FEED_TITLE}</title>
  <subtitle>{escape(_FEED_SUBTITLE)}</subtitle>
  <link rel="self" type="application/atom+xml" href="{ORIGIN}/notes/feed.xml"/>
  <link rel="alternate" type="text/html" href="{ORIGIN}{served_path("notes/index.html")}"/>
  <updated>{_timestamp(notes[0].date)}</updated>
  <author><name>{_AUTHOR}</name></author>
{entries}</feed>
"""


def _parsed(feed: str) -> str:
    """Return the feed unchanged once it parses as XML; a feed readers reject is not shipped."""
    try:
        ET.fromstring(feed)  # noqa: S314 — the generator's own output, every value escaped
    except ET.ParseError as exc:
        raise SiteBuildError(f"notes/feed.xml would not parse as XML: {exc}") from exc
    return feed


def _timestamp(date: datetime.date) -> str:
    """Atom requires a date-time; a note carries a date, so it is midnight UTC on that day."""
    return f"{date.isoformat()}T00:00:00Z"
