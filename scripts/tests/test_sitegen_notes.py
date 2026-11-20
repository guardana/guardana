"""The notes tree: dated articles under `notes/`, built to `site/notes/` with an Atom feed.

Every note here is written by the test into a temporary repository, so nothing
in the real `notes/` (which may not exist) is read or required.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

import generate_llms_txt
import generate_sitemap
from sitegen import SiteBuildError, build_notes, layout
from sitegen import notes as notes_module
from sitegen.notes import FEED_ID, read_notes

_ATOM = "{http://www.w3.org/2005/Atom}"
_TAG = re.compile(r"<[a-zA-Z/][^>]*>")
_DOC = (
    '---\ntitle: "Scan"\nnav_order: 10\nsummary: "s"\nstatus: stable\n---\n'
    "# Scan\n\n## Exit codes\n\nText.\n"
)


def _note(
    title: str, date: str, summary: str = "What it is about.", body: str = "Text.\n", **extra: str
) -> str:
    lines = [f'title: "{title}"', f"date: {date}", f'summary: "{summary}"']
    lines.extend(f"{key}: {value}" for key, value in extra.items())
    return "---\n" + "\n".join(lines) + "\n---\n" + body


def _repo(tmp_path: Path, notes: dict[str, str]) -> Path:
    (tmp_path / "docs").mkdir(parents=True)
    (tmp_path / "docs" / "usage-scan.md").write_text(_DOC, encoding="utf-8")
    (tmp_path / "README.md").write_text("# Readme\n", encoding="utf-8")
    (tmp_path / "notes").mkdir()
    for name, text in notes.items():
        (tmp_path / "notes" / name).write_text(text, encoding="utf-8")
    return tmp_path


def _two_notes(tmp_path: Path) -> Path:
    return _repo(
        tmp_path,
        {
            "first-note.md": _note(
                "First note",
                "2026-09-01",
                devto="https://dev.to/g/first",
                body="# First note\n\nSee [exit codes](../docs/usage-scan.md#exit-codes), "
                "[the next one](second-note.md#details) and [OWASP](https://owasp.org/).\n\n"
                "| a | b |\n|---|---|\n| 1 | 2 |\n",
            ),
            "second-note.md": _note(
                "Second note",
                "2026-10-02",
                body="Body without a heading.\n\n## Details\n\n[Up](#details)\n",
            ),
        },
    )


def test_a_note_carries_its_canonical_feed_link_and_served_urls(tmp_path: Path) -> None:
    files = build_notes(_two_notes(tmp_path))

    html = files["first-note.html"]
    assert '<link rel="canonical" href="https://guardana.dev/notes/first-note">' in html
    assert 'rel="alternate" type="application/atom+xml"' in html
    assert 'href="/notes/feed.xml"' in html
    assert 'href="/docs/usage-scan#exit-codes"' in html
    assert 'href="/notes/second-note#details"' in html
    assert '<a href="https://dev.to/g/first">Also on dev.to</a>' in html
    assert '<a class="logo" href="/">' in html
    assert '<a href="/docs/" class="sm-keep">Docs</a>' in html
    assert '<a href="/notes/">Notes</a>' in html
    assert '<div class="table-wrap"><table>' in html
    assert ".md" not in "".join(re.findall(r'href="([^"]+)"', html))
    assert "Also on dev.to" not in files["second-note.html"]
    assert 'href="#details"' in files["second-note.html"]


def test_the_index_lists_the_newest_note_first(tmp_path: Path) -> None:
    index = build_notes(_two_notes(tmp_path))["index.html"]

    assert index.index("Second note") < index.index("First note")
    assert '<link rel="canonical" href="https://guardana.dev/notes/">' in index
    assert '<time datetime="2026-10-02">' in index
    assert "What it is about." in index


def test_the_feed_is_atom_with_stable_ids_and_served_links(tmp_path: Path) -> None:
    repo = _two_notes(tmp_path)
    feed = build_notes(repo)["feed.xml"]

    root = ET.fromstring(feed)  # noqa: S314 — the generator's own output, not untrusted input

    assert root.tag == f"{_ATOM}feed"
    assert root.findtext(f"{_ATOM}id") == FEED_ID
    assert root.findtext(f"{_ATOM}updated") == "2026-10-02T00:00:00Z"
    entries = root.findall(f"{_ATOM}entry")
    assert [entry.findtext(f"{_ATOM}id") for entry in entries] == [
        "tag:guardana.dev,2026-10-02:notes/second-note",
        "tag:guardana.dev,2026-09-01:notes/first-note",
    ]
    assert [entry.find(f"{_ATOM}link").get("href") for entry in entries] == [  # type: ignore[union-attr]
        "https://guardana.dev/notes/second-note",
        "https://guardana.dev/notes/first-note",
    ]
    assert entries[1].findtext(f"{_ATOM}updated") == "2026-09-01T00:00:00Z"
    assert build_notes(repo)["feed.xml"] == feed


@pytest.mark.parametrize("make_dir", [True, False])
def test_no_note_builds_nothing_and_the_docs_header_does_not_link_notes(
    tmp_path: Path, make_dir: bool
) -> None:
    if make_dir:
        (tmp_path / "notes").mkdir()

    assert build_notes(tmp_path) == {}
    assert read_notes(tmp_path / "notes") == []
    without = _docs_page(notes=False)
    assert "notes/" not in without
    assert ">Notes<" not in without


def test_the_docs_header_links_notes_once_one_exists() -> None:
    assert '<a href="../notes/index.html">Notes</a>' in _docs_page(notes=True)


def _docs_page(*, notes: bool) -> str:
    return layout.page(
        chrome=layout.Chrome((), "0.0.0", notes=notes),
        href="index.html",
        title="t",
        summary="s",
        body="",
        edit_path=None,
    )


@pytest.mark.parametrize(
    ("name", "text", "reason"),
    [
        ("a.md", '---\ntitle: "A"\ndate: 2026-10-01\n---\nBody\n', "missing summary"),
        ("a.md", _note("A", "2026-13-45"), "not valid YAML"),
        ("a.md", _note("A", "next week"), "'date' must be an ISO date"),
        ("a.md", _note("A", "2026-10-01 10:00:00"), "without a time"),
        ("a.md", _note("A", "2026-10-01", draft="true"), "unknown front matter draft"),
        ("a.md", _note("A", "2026-10-01", devto="https://example.com/a"), "'devto' must be"),
        ("a.md", "No front matter.\n", "no YAML front matter"),
        ("First_Note.md", _note("A", "2026-10-01"), "lowercase words"),
        ("index.md", _note("A", "2026-10-01"), "lowercase words"),
        ("a.md", _note("A", "2026-10-01") + "[x](missing.md)\n", "does not exist"),
        ("a.md", _note("A", "2026-10-01") + "[x](../README.md)\n", "no page on this site"),
        ("a.md", _note("A", "2026-10-01") + "[x](../docs/usage-scan.md#nope)\n", "anchor"),
        ("a.md", _note("A", "2026-10-01") + "![x](https://example.com/x.png)\n", "image"),
        ("a.md", _note("A", "2026-10-01", summary="![x](https://evil.example/p.png)"), "image"),
        ("a.md", _note("A", "2026-10-01", summary="[x](../docs/usage-scan.md)"), "link"),
        ("a.md", _note("[A](https://example.com)", "2026-10-01"), "link"),
        ("a.md", _note("A", "2026-10-01", summary="A\\x01B"), "control character"),
        ("a.md", '---\ntitle: "A"\ndate: 2026-10-01\nsummary: "s"\nBody\n', "no closing"),
        ("a.md", _note("A", "2026-10-01", body=""), "has no body"),
        ("a.md", _note("A", "2026-10-01", body="\n\n  \n"), "has no body"),
    ],
)
def test_a_note_that_does_not_describe_itself_fails_the_build_naming_the_file(
    tmp_path: Path, name: str, text: str, reason: str
) -> None:
    repo = _repo(tmp_path, {name: text})

    with pytest.raises(SiteBuildError, match=re.escape(reason)) as raised:
        build_notes(repo)

    assert f"notes/{name}" in str(raised.value)


def test_two_notes_with_one_title_are_refused(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path, {"a.md": _note("Same", "2026-10-01"), "b.md": _note("same", "2026-10-02")}
    )

    with pytest.raises(SiteBuildError, match="share the title") as raised:
        build_notes(repo)

    assert "notes/a.md" in str(raised.value)
    assert "notes/b.md" in str(raised.value)


@pytest.mark.parametrize("stray", ["drafts/a.md", "b.MD", "c.markdown", "x.txt"])
def test_a_file_that_is_not_a_note_is_refused_rather_than_skipped(
    tmp_path: Path, stray: str
) -> None:
    repo = _repo(tmp_path, {"a.md": _note("A", "2026-10-01")})
    (repo / "notes" / stray).parent.mkdir(exist_ok=True)
    (repo / "notes" / stray).write_text(_note("B", "2026-10-01"), encoding="utf-8")

    with pytest.raises(SiteBuildError, match=re.escape(f"notes/{stray}")):
        build_notes(repo)


def test_a_feed_that_would_not_parse_fails_the_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(notes_module, "_feed", lambda _notes: "<feed><entry></feed>")

    with pytest.raises(SiteBuildError, match="would not parse"):
        build_notes(_repo(tmp_path, {"a.md": _note("A", "2026-10-01")}))


def test_no_output_carries_a_script_or_loads_from_another_host(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        {
            "a.md": _note("A <script>", "2026-10-01", summary="<script>alert(1)</script>")
            + "<script>alert(1)</script>\n\n<img src=https://example.com/x.png>\n\n"
            "```mermaid\nflowchart LR\n  accTitle: t\n  accDescr: d\n  A --> B\n```\n",
        },
    )

    files = build_notes(repo)

    assert set(files) == {"index.html", "feed.xml", "a.html"}
    for name, content in files.items():
        tags = " ".join(_TAG.findall(content))
        assert "<script" not in tags.lower(), name
        assert not re.search(r'\ssrc\s*=\s*"?(?:https?:)?//', tags), name
        assert not re.search(r'<link[^>]+href="(?:https?:)?//(?!guardana\.dev/)', tags), name


def test_the_sitemap_lists_built_notes_in_served_form(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = tmp_path / "site"
    for name in build_notes(_two_notes(tmp_path / "repo")):
        (site / "notes").mkdir(parents=True, exist_ok=True)
        (site / "notes" / name).write_text("x", encoding="utf-8")
    monkeypatch.setattr(generate_sitemap, "_SITE", site)

    assert generate_sitemap._urls() == [
        "https://guardana.dev/notes/first-note",
        "https://guardana.dev/notes/",
        "https://guardana.dev/notes/second-note",
    ]


def test_llms_txt_lists_notes_with_their_served_url_and_summary(tmp_path: Path) -> None:
    repo = _two_notes(tmp_path / "repo")

    assert generate_llms_txt._notes(repo / "notes") == [
        ("Second note", "https://guardana.dev/notes/second-note", "What it is about."),
        ("First note", "https://guardana.dev/notes/first-note", "What it is about."),
    ]
    assert generate_llms_txt._notes(tmp_path / "absent") == []
