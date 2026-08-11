"""Markdown to HTML, with every internal link rewritten and every fragment checked.

The link rewrite happens on the token stream rather than on the prose, because a
regex over markdown also rewrites the `.md` inside a fenced example, and a
documentation site whose examples have been quietly edited is worse than one whose
links are stale.

Fragments are checked because that is where a `.md` → `.html` rewrite really
breaks: the file resolves, the anchor does not, and the reader lands at the top of
a long page believing they are looking at the section they asked for.
"""

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from markdown_it import MarkdownIt
from markdown_it.token import Token

_PUNCTUATION = re.compile(r"[^\w\- ]", re.UNICODE)


def parser() -> MarkdownIt:
    """Build the one parser configuration this site uses.

    `html` stays off. No documentation page contains raw HTML today, and leaving
    the door open would mean the CSP is the only thing between a pasted snippet
    and the page — a second line of defence standing in for a first.
    """
    return MarkdownIt("commonmark", {"html": False, "linkify": False}).enable(
        ["table", "strikethrough"]
    )


def slug(text: str) -> str:
    """Turn a heading's rendered text into the anchor GitHub would give it.

    GitHub's algorithm, deliberately: every `#fragment` written in this repository
    was written against a page rendered by GitHub, so any other slugger would break
    links that work today — silently, since a missing anchor still loads the page.

    The input is the *rendered* text, not the markdown source, and the difference
    is load-bearing. GitHub slugs a heading after inline parsing, so an emphasis
    marker is gone and an underscore inside a code span is not: the heading
    "Config-wired evaluators: `llm_judge` and `guard`" earns
    `config-wired-evaluators-llm_judge-and-guard`, and stripping backticks and
    underscores together with a regex over the source loses the middle one.
    """
    return _PUNCTUATION.sub("", text.strip().lower()).replace(" ", "-")


_LEADING_COMMENT = re.compile(r"\A\s*<!--.*?-->\s*", re.DOTALL)


def split_heading(markdown: str) -> tuple[str, str]:
    """Lift a page's opening `# ` heading out of its body, rendered.

    The shell prints one heading; leaving the markdown's own in the body prints a
    second one under it. The body's is the richer of the two — "`guardana taxonomy`
    — which framework entry a rule actually means" against a nav label of "guardana
    taxonomy" — so the body's is the one shown and the frontmatter title stays what
    the sidebar says.

    A heading containing a link stays where it is. Inline rendering here does not go
    through the link rewriter, and a page shipping one unrewritten `.md` link is a
    worse outcome than a page with two headings.

    The leading generated-by comment goes too: with raw HTML off — which is how this
    parser is configured, deliberately — a comment renders as visible escaped text,
    so `docs/generated/` pages were displaying their own do-not-edit marker to
    readers who cannot edit them anyway.
    """
    body = _LEADING_COMMENT.sub("", markdown)
    lines = body.splitlines()
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        if line.startswith("# ") and "](" not in line:
            return parser().renderInline(line[2:].strip()), "\n".join(lines[index + 1 :]).lstrip(
                "\n"
            )
        break
    return "", body


def plain(inline: Token) -> str:
    """Read the text a heading renders to, with code spans kept and markup gone."""
    if not inline.children:
        return inline.content
    return "".join(
        child.content for child in inline.children if child.type in ("text", "code_inline")
    )


def inline(markdown: str) -> str:
    """Render a one-line fragment as HTML: a page's summary, or a lifted heading.

    A summary is markdown like everything else an author writes — the frontmatter
    ones were lifted from `docs/index.md`'s bullets, backticks included — so
    escaping it printed the backticks at the top of every page.
    """
    return str(parser().renderInline(markdown))


def inline_text(markdown: str) -> str:
    """Resolve the same fragment's markup rather than rendering it.

    For `<meta name="description">`, where markup would be shown verbatim by every
    search engine and link preview that quotes it.
    """
    return "".join(plain(token) for token in parser().parseInline(markdown))


@dataclass(frozen=True, slots=True)
class Rendered:
    """One page's HTML, and the anchors it offers to anybody linking at it."""

    html: str
    anchors: frozenset[str]


def anchors_of(markdown: str) -> frozenset[str]:
    """Every anchor a rendered page will carry, without rendering it.

    Computed off the same body the renderer is given, opening heading already
    lifted out. Computing it off the whole file would promise an anchor for a
    heading the page does not print — a link checker agreeing with a link that
    does not work, which is worse than no link checker.
    """
    return frozenset(_headings(parser().parse(split_heading(markdown)[1])).values())


def render(markdown: str, resolve: Callable[[str], str]) -> Rendered:
    """Render one page, passing every local link target through `resolve`.

    `resolve` is handed the raw href and returns what the HTML should carry. It is
    also where a broken target is recorded — this function does not judge links,
    it only guarantees that every one of them is offered.
    """
    md = parser()
    tokens = md.parse(markdown)
    headings = _headings(tokens)
    for index, token in enumerate(tokens):
        if token.type == "heading_open" and index in headings:
            token.attrSet("id", headings[index])
        for child in _inline_children(token):
            if child.type == "link_open":
                child.attrSet("href", resolve(str(child.attrGet("href") or "")))
            elif child.type == "image":
                child.attrSet("src", resolve(str(child.attrGet("src") or "")))
    return Rendered(md.renderer.render(tokens, md.options, {}), frozenset(headings.values()))


def _inline_children(token: Token) -> Iterator[Token]:
    if token.type == "inline" and token.children:
        yield from token.children


def _headings(tokens: list[Token]) -> dict[int, str]:
    """Map the index of each `heading_open` token to the anchor its text earns.

    Repeats get GitHub's `-1`, `-2` suffix. Two sections called "Why" on one page
    is ordinary writing, and giving both the same id would send every link to the
    first one.
    """
    assigned: dict[int, str] = {}
    used: dict[str, int] = {}
    for index, token in enumerate(tokens):
        if token.type != "heading_open" or index + 1 >= len(tokens):
            continue
        base = slug(plain(tokens[index + 1]))
        if not base:
            continue
        seen = used.get(base, 0)
        used[base] = seen + 1
        assigned[index] = base if seen == 0 else f"{base}-{seen}"
    return assigned
