"""What the site publishes for machines: a share card, and `llms.txt`.

Both are claims made somewhere nobody re-reads. A share preview is only ever seen
outside the repository, and `llms.txt` is read by a model that will not notice it is
describing a page that moved — which is the same shape as every stale number this
project has already had to fix, one hop further away from anyone who would spot it.

So: every URL a crawler is handed has to resolve to a file that exists, the image has
to be the size it declares, and the generated file has to be the one the generator
produces. `test_docs_consistency.py` runs the generator's own `--check`; this covers
the half that lives in HTML.
"""

import json
import re
import struct
from pathlib import Path

import pytest
from guardana.core import __version__
from guardana.core.manifest.serialize import SCHEMA_URL

_OG_IMAGE_WIDTH = 1200
_OG_IMAGE_HEIGHT = 630
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _repo() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "README.md").is_file() and (parent / "packages").is_dir():
            return parent
    raise AssertionError("could not locate the repository root")


def _page() -> str:
    return (_repo() / "site" / "index.html").read_text(encoding="utf-8")


def _meta(prop: str) -> str:
    match = re.search(rf'<meta (?:property|name)="{re.escape(prop)}" content="([^"]*)">', _page())
    assert match is not None, (
        f"site/index.html no longer declares {prop!r} — a share preview without it "
        f"falls back to whatever the crawler guesses from the markup"
    )
    return match.group(1)


@pytest.mark.parametrize(
    "prop",
    ["og:title", "og:description", "og:type", "og:site_name", "og:url", "og:image", "og:image:alt"],
)
def test_the_page_declares_the_fields_a_share_preview_needs(prop: str) -> None:
    assert _meta(prop).strip(), f"{prop} is declared and empty, which is worse than absent"


def test_every_url_handed_to_a_crawler_is_absolute() -> None:
    """A crawler resolves nothing against the page it fetched, so a relative path is a dead link."""
    for prop in ("og:url", "og:image"):
        assert _meta(prop).startswith("https://guardana.dev/"), (
            f"{prop} is {_meta(prop)!r}; a share crawler needs an absolute URL on the "
            f"site's own origin"
        )


def test_the_share_image_exists_and_is_the_size_it_claims() -> None:
    """Declared dimensions that do not match the file make X and LinkedIn re-crop it.

    Read out of the PNG's IHDR rather than trusted from the filename, because the
    point of the check is the case where somebody re-rendered the card at a different
    size and left the meta tags alone.
    """
    name = _meta("og:image").removeprefix("https://guardana.dev/")
    image = _repo() / "site" / name

    assert image.is_file(), f"og:image points at /{name} and site/{name} does not exist"
    header = image.read_bytes()[:24]
    assert header[:8] == _PNG_SIGNATURE, f"site/{name} is not a PNG, but og:image:type says it is"
    width, height = struct.unpack(">II", header[16:24])
    assert (width, height) == (_OG_IMAGE_WIDTH, _OG_IMAGE_HEIGHT), (
        f"site/{name} is {width}x{height}; the page declares "
        f"{_OG_IMAGE_WIDTH}x{_OG_IMAGE_HEIGHT} — re-render it or fix the tags"
    )
    assert int(_meta("og:image:width")) == width
    assert int(_meta("og:image:height")) == height


def test_the_share_image_states_no_count_that_could_go_stale() -> None:
    """The one claim in this file a test cannot read is the one inside the PNG.

    So the check moves to its source: `scripts/og_card.html` must not carry a rule
    count, because a number rendered into an image is a claim no gate here can ever
    verify — and this repository has now had that number go stale on the landing page,
    in the README and in the GitHub repository description.
    """
    card = (_repo() / "scripts" / "og_card.html").read_text(encoding="utf-8")
    body = card.split("<body>", 1)[1]

    assert not re.search(r"\b\d+\s*(?:security\s*)?(?:checks?|rules?)\b", body), (
        "scripts/og_card.html renders a rule count into the share image; nothing can "
        "check it once it is pixels"
    )


def _headline(html: str) -> str:
    match = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.DOTALL)
    assert match is not None, "no <h1> to compare"
    return " ".join(re.sub(r"<[^>]+>", " ", match.group(1)).split())


def test_the_share_card_says_what_the_landing_headline_says() -> None:
    """The card is pixels nobody re-reads, so its source and its alt text follow the page's h1."""
    headline = _headline(_page())
    card = (_repo() / "scripts" / "og_card.html").read_text(encoding="utf-8")

    assert _headline(card) == headline, (
        f"scripts/og_card.html says {_headline(card)!r} and the landing page says "
        f"{headline!r}; update the card, re-render site/og.png and fix og:image:alt"
    )
    assert headline in _meta("og:image:alt"), (
        f"og:image:alt does not contain the landing headline {headline!r}"
    )


def test_the_page_points_at_llms_txt_and_the_file_is_there() -> None:
    """A link element and a missing file is a 404 offered to every model that follows it."""
    page = _page()

    assert 'href="/llms.txt"' in page, "site/index.html no longer points at /llms.txt"
    assert (_repo() / "site" / "llms.txt").is_file(), "site/llms.txt does not exist"


def test_nothing_the_site_publishes_is_excluded_from_the_deploy() -> None:
    """`.assetsignore` keeps maintainer files off the site; it must not eat a published one.

    `site/README.md` shipped as a public page once because wrangler uploads everything
    in the assets directory. The ignore file that fixed it is one edit away from the
    opposite mistake, and this is the direction nobody would notice: a share image or
    an `llms.txt` that 404s looks exactly like one nobody asked for.
    """
    ignored = {
        line.strip()
        for line in (_repo() / "site" / ".assetsignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }

    assert {"llms.txt", "og.png"}.isdisjoint(ignored), (
        f"site/.assetsignore excludes something the page links to: {sorted(ignored)}"
    )


def _served_file(path: str) -> Path:
    """Map a URL path to the file behind it: itself, or the page the host serves without `.html`."""
    site = _repo() / "site"
    if not path or path.endswith("/"):
        return site / f"{path}index.html"
    return site / path if (site / path).is_file() else site / f"{path}.html"


def test_every_guardana_dev_url_in_llms_txt_is_a_file_the_site_serves() -> None:
    llms = (_repo() / "site" / "llms.txt").read_text(encoding="utf-8")
    urls = re.findall(r"\((https://guardana\.dev/[^)]+)\)", llms)
    missing = [url for url in urls if not _served_file(url.split("/", 3)[3]).is_file()]

    assert urls, "llms.txt names no guardana.dev URL — its schema list is gone"
    assert not missing, f"llms.txt points at files site/ does not serve: {missing}"


def test_llms_txt_lists_the_schema_a_saved_run_is_written_to() -> None:
    assert f"({SCHEMA_URL})" in (_repo() / "site" / "llms.txt").read_text(encoding="utf-8")


def _structured_data() -> dict[str, dict[str, object]]:
    blocks = re.findall(r'<script type="application/ld\+json">(.*?)</script>', _page(), re.DOTALL)
    return {str(block.get("name", block["@type"])): block for block in map(json.loads, blocks)}


def test_the_structured_data_states_the_version_that_ships() -> None:
    assert _structured_data()["Guardana"]["softwareVersion"] == __version__


def test_guardana_control_is_described_where_it_answers() -> None:
    """Control's structured data points at its own site and names its latest release."""
    control = _structured_data()["Guardana Control"]

    assert control["url"] == "https://control.guardana.dev/"
    assert control["codeRepository"] == "https://github.com/guardana/control"
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:-[a-z]+)?", str(control["softwareVersion"]))


def test_the_landing_page_links_control_where_it_answers() -> None:
    assert 'href="https://control.guardana.dev/"' in _page()
    assert "website is coming soon" not in _page()


def test_llms_txt_names_no_control_resource_that_does_not_answer() -> None:
    """Control publishes no llms.txt yet; the related-project entry stays on its README."""
    assert "control.guardana.dev" not in (_repo() / "site" / "llms.txt").read_text(encoding="utf-8")
