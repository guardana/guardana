"""The deprecation policy in `docs/compatibility.md` stays as strong as it was written.

The release script enforces one part of it: a candidate whose supported surface moved
needs a changelog section announcing the move. That part is pinned to the script's own
pattern, so the page and the gate name the same sections. No code can enforce the
rest of the policy (how long a name stays deprecated, which release may remove it), so
those statements are pinned word for word: an edit that weakens one has to edit this
file too, where a reviewer sees it.
"""

import re

import pytest

import release

_KEEP_A_CHANGELOG = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
"""Every section a changelog entry can be filed under."""

_POLICY = (
    "The supported surface changes incompatibly only in a major release.",
    "A name to be removed is deprecated first, for at least one minor release, and removed only"
    " in the next major.",
    'Deprecation means a `DeprecationWarning` where Python can raise one, and a "Deprecated"'
    " entry in the [changelog](../CHANGELOG.md) that names the replacement.",
    "support for an API version is dropped only in a major release.",
    "A Python version is supported until its upstream end of life. Dropping one is announced one"
    " minor release ahead.",
    "| Minor | Compatible opt-in functionality, a new opt-in check, or a deprecation. |",
    "| Major | A contract break, a removal, dropping a reader for an older persisted document, a"
    " check enabled by default that can fail a previously passing build, or an intentionally"
    " stricter default. |",
    "Dropping an envelope version is a major release.",
)


def _page() -> str:
    """The compatibility page with its line breaks folded, so rewrapping is not an edit."""
    text = release._VERSIONING.read_text(encoding="utf-8")
    return re.sub(r"(?<![\n|])[ \t]*\n[ \t]*(?![\n|])", " ", text)


def _announcing_sections() -> set[str]:
    """The changelog sections the release script accepts as announcing a moved surface."""
    return {
        section
        for section in _KEEP_A_CHANGELOG
        if release._SURFACE_SECTION_RE.search(f"### {section}\n\n- a name\n")
    }


@pytest.mark.parametrize("statement", _POLICY)
def test_the_policy_statement_is_still_on_the_page(statement: str) -> None:
    assert statement in _page(), f"docs/compatibility.md no longer says: {statement}"


@pytest.mark.parametrize(
    "where", ["`scripts/release.py` refuses a candidate", "## How a change is caught"]
)
def test_the_page_names_the_sections_the_release_script_accepts(where: str) -> None:
    page = _page()
    start = page.index(where) + len(where)
    end = page.find("\n\n", start + 2)
    paragraph = page[start : end if end != -1 else len(page)]

    named = set(re.findall(r"[`\"]([A-Z][a-z]+)[`\"]", paragraph)) & set(_KEEP_A_CHANGELOG)

    assert named == _announcing_sections() == {"Changed", "Deprecated", "Removed"}
