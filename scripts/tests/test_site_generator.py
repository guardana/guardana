"""The generator's own branches, which reading the built site cannot reach.

`test_documentation_site.py` reads `site/docs/` — what a visitor is served — and
that is the right check for everything the current pages exercise. It is also why
it cannot see a branch no current page happens to take: a path nothing triggers
renders nothing, so a site built from it looks perfect.

Two such branches, both deliberate, neither previously run by anything:

- a heading carrying a link is left in the body rather than lifted into the shell,
  because lifting it would render the link without the rewriter and ship a raw
  `.md` href. No page has a link in its `# ` heading today;
- tables are wrapped by substituting on `<table>`, which is only safe because the
  markdown parser escapes raw HTML. Nothing said so, and nothing would have
  noticed if that setting changed.
"""

import pytest

from sitegen import render
from sitegen.build import _tables


def test_a_heading_with_a_link_stays_in_the_body_rather_than_losing_its_rewrite() -> None:
    """The branch the whole docs tree currently avoids by having no such heading.

    Lifting it would render the link through `renderInline`, which does not go
    through the link resolver — so the page would ship an unrewritten `.md` href
    that a reader clicks and a link checker never sees. Two headings is the lesser
    outcome, and this pins that it is the one taken.
    """
    heading, body = render.split_heading("# See [the rules](rules.md)\n\ntext\n")

    assert heading == ""
    assert body.startswith("# See [the rules](rules.md)")


def test_a_plain_heading_is_still_lifted_out_of_the_body() -> None:
    """The other side, so the assertion above cannot pass by nothing being lifted ever."""
    heading, body = render.split_heading("# `guardana taxonomy`\n\ntext\n")

    assert "guardana taxonomy" in heading
    assert not body.startswith("#")


def test_the_parser_escapes_raw_html_so_the_table_wrapper_cannot_reach_prose() -> None:
    """`_tables` substitutes on the literal `<table>`, and that is safe for one reason only.

    Raw HTML is off, so a document mentioning `<table>` in prose or in a code fence
    renders it escaped and the substitution never sees it. Turning raw HTML on would
    make the wrapper start opening `<div>`s inside somebody's example and never
    close them — silent, and visible only as a broken layout on one page.
    """
    markdown = (
        "Prose mentioning <table> literally.\n\n"
        "```html\n<table><tr><td>x</td></tr></table>\n```\n\n"
        "| a | b |\n|---|---|\n| 1 | 2 |\n"
    )

    html = render.render(markdown, lambda href: href).html
    wrapped = _tables(html)

    assert "&lt;table&gt;" in html, "raw HTML is no longer escaped; the table wrapper is now unsafe"
    assert wrapped.count('<div class="table-wrap">') == 1
    assert wrapped.count("</div>") == html.count("</table>")


@pytest.mark.parametrize("markdown", ["", "\n\n", "text with no heading\n"])
def test_a_page_with_no_opening_heading_keeps_its_body_whole(markdown: str) -> None:
    """The third way out of that loop, which an empty or heading-less page takes."""
    heading, body = render.split_heading(markdown)

    assert heading == ""
    assert body == markdown
