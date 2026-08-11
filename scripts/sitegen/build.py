"""Assemble every page of `site/docs/` in memory, then hand it to the caller.

Built into a dict rather than written straight to disk, because `--check` and
`--write` must answer from the same bytes. A checker that re-derives the answer a
second way is a checker that can disagree with the build it is guarding.
"""

from html import escape
from pathlib import Path
from typing import Any

from sitegen import explorer, layout, nav, render, theme
from sitegen.errors import SiteBuildError
from sitegen.links import LinkResolver
from sitegen.page import Page, read_pages

_RULES_ENTRY = nav.NavEntry("Rule explorer", "rules/index.html", "stable")
_RULES_SECTION = "Reference"
"""The heading in `docs/index.md` the explorer's nav entry joins.

Matched by text, and `nav.build` refuses a heading it cannot find rather than
quietly leaving the entry out — the explorer is the page this whole site is built
around, and a rename in the map is exactly how it would disappear from the sidebar
with nothing red.
"""


def build(repo: Path, version: str) -> dict[str, str]:
    """Render the whole documentation site, keyed by path under `site/docs/`."""
    docs = repo / "docs"
    pages = read_pages(docs)
    rules = explorer.load_rules(docs / "generated" / "rules.json")
    chrome = layout.Chrome(
        tuple(nav.build(docs / "index.md", pages, {_RULES_SECTION: (_RULES_ENTRY,)})), version
    )
    files = {"docs.css": theme.CSS}
    files.update(_prose(repo, docs, pages, chrome))
    files.update(_explorer(rules, chrome))
    return files


def _prose(repo: Path, docs: Path, pages: list[Page], chrome: layout.Chrome) -> dict[str, str]:
    anchors = {page.relative: render.anchors_of(page.body) for page in pages}
    resolver = LinkResolver(repo=repo, docs=docs, anchors=anchors)
    rendered = {}
    for page in pages:
        title_html, body = render.split_heading(page.body)
        rendered[page.output.as_posix()] = layout.page(
            chrome=chrome,
            href=page.output.as_posix(),
            title=page.title,
            summary=render.inline_text(page.summary),
            body=layout.heading(
                title_html or render.inline(page.title),
                render.inline(page.summary),
                page.status,
            )
            + _tables(render.render(body, resolver.for_page(page)).html),
            edit_path=f"docs/{page.relative.as_posix()}",
        )
    if resolver.problems:
        raise SiteBuildError(
            "links that do not survive rendering:\n  " + "\n  ".join(sorted(resolver.problems))
        )
    return rendered


def _tables(html: str) -> str:
    """Wrap every table so a wide one scrolls inside itself instead of the page."""
    return html.replace("<table>", '<div class="table-wrap"><table>').replace(
        "</table>", "</table></div>"
    )


def _explorer(rules: list[dict[str, Any]], chrome: layout.Chrome) -> dict[str, str]:
    grouped = explorer.index_facets(rules)
    files = {"rules/index.html": _explorer_index(rules, grouped, chrome)}
    for rule in rules:
        href = explorer.rule_href(str(rule["id"]))
        files[href] = _rule_page(rule, chrome, href)
    for facet in explorer.FACETS:
        for value, matching in grouped[facet.key].items():
            href = explorer.filter_href(facet.key, value)
            files[href] = _filter_page(facet, value, matching, chrome, href)
    return files


def _explorer_index(
    rules: list[dict[str, Any]],
    grouped: dict[str, dict[str, list[dict[str, Any]]]],
    chrome: layout.Chrome,
) -> str:
    up = "../"
    body = (
        layout.heading("Rule explorer", escape(explorer.summary_line(rules)), "stable")
        + "<p>Every filter below is a page, not a script: this site ships "
        "<code>script-src &#39;none&#39;</code> and <code>connect-src &#39;none&#39;</code>, "
        "so nothing here runs and nothing here calls home. Open devtools and check.</p>"
        + explorer.facet_panels(grouped, up)
        + "<h2>Every rule</h2>"
        + explorer.table(rules, up)
    )
    return layout.page(
        chrome=chrome,
        href="rules/index.html",
        title="Rule explorer",
        summary=explorer.summary_line(rules),
        body=body,
        edit_path=None,
    )


def _filter_page(
    facet: explorer.Facet,
    value: str,
    matching: list[dict[str, Any]],
    chrome: layout.Chrome,
    href: str,
) -> str:
    up = "../" * href.count("/")
    label = explorer.label_for(facet.key, value)
    title = f"{facet.heading}: {label}"
    plural = "rule" if len(matching) == 1 else "rules"
    summary = f"{len(matching)} {plural}. {facet.blurb}"
    body = layout.heading(
        escape(title),
        escape(summary),
        "stable",
        crumb=f'<a href="{up}rules/index.html">Rule explorer</a>',
    ) + explorer.table(matching, up)
    return layout.page(
        chrome=chrome, href=href, title=title, summary=summary, body=body, edit_path=None
    )


def _rule_page(rule: dict[str, Any], chrome: layout.Chrome, href: str) -> str:
    up = "../" * href.count("/")
    goal = rule.get("goal")
    reasoning = (
        f"<h2>What a secure system does</h2><p>{escape(str(goal))}</p>"
        if goal
        else "<h2>What a secure system does</h2><p>This rule grades in code rather than "
        "against a declared expectation, so it states no goal here. Its behaviour is its "
        "fixtures, which <code>guardana rule test</code> runs.</p>"
    )
    body = (
        layout.heading(
            escape(str(rule["title"])),
            f'<span class="rid">{escape(str(rule["id"]))}</span>',
            "stable",
            crumb=f'<a href="{up}rules/index.html">Rule explorer</a>',
        )
        + explorer.rule_properties(rule, up)
        + reasoning
        + "<h2>Maps to</h2>"
        + explorer.rule_taxonomy(rule, up)
        + f'<p><a href="{up}writing-rules.html">How a rule is written</a> · '
        f'<a href="{up}profiles.html">Selecting it in a profile</a></p>'
    )
    return layout.page(
        chrome=chrome,
        href=href,
        title=str(rule["id"]),
        summary=str(rule["title"]),
        body=body,
        edit_path=None,
    )
