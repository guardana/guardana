"""Every generated docs page opens with a skip link targeting the main content (#87)."""
from __future__ import annotations

import re

from sitegen import layout

_FOCUSABLE = re.compile(r'<(?:a\s[^>]*href=|button|input|select|textarea|summary)[^>]*>', re.I)


def _render() -> str:
    return layout.page(
        chrome=layout.Chrome((), "0.0.0"),
        href="index.html",
        title="T",
        summary="s",
        body="<p>Text.</p>",
        edit_path=None,
    )


def test_first_focusable_link_targets_main_content() -> None:
    html = _render()
    first = _FOCUSABLE.search(html)
    assert first is not None
    assert 'href="#main"' in first.group(0)
    assert 'class="skip"' in first.group(0)


def test_main_content_carries_matching_id() -> None:
    assert '<main id="main">' in _render()


def test_skip_link_visible_on_focus_css() -> None:
    from sitegen import theme

    assert ".skip:focus" in theme.CSS or ".skip:focus-visible" in theme.CSS
