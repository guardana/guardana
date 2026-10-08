"""The sitemap and robots.txt match the built site, and `--check` never writes."""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

import generate_sitemap


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    site = tmp_path / "site"
    monkeypatch.setattr(generate_sitemap, "_REPO", tmp_path)
    monkeypatch.setattr(generate_sitemap, "_SITE", site)
    monkeypatch.setattr(generate_sitemap, "_SITEMAP", site / "sitemap.xml")
    monkeypatch.setattr(generate_sitemap, "_ROBOTS", site / "robots.txt")
    monkeypatch.setattr(sys, "argv", ["generate_sitemap.py"])
    return site


def _build(site: Path) -> None:
    site.mkdir()
    (site / "index.html").write_text("<h1>Home</h1>", encoding="utf-8")
    (site / "docs").mkdir()
    (site / "docs/x.html").write_text("<h1>X</h1>", encoding="utf-8")
    (site / "docs/ignored.txt").write_text("Not a page", encoding="utf-8")


def _snapshot(site: Path) -> dict[str, tuple[bytes, int]]:
    return {
        path.relative_to(site).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in site.rglob("*")
        if path.is_file()
    }


def test_write_lists_sorted_built_pages_in_served_form_and_writes_robots(site: Path) -> None:
    _build(site)

    assert generate_sitemap.main() == 0

    root = ET.fromstring((site / "sitemap.xml").read_text(encoding="utf-8"))  # noqa: S314 — generated fixture output
    namespace = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    assert root.tag == f"{namespace}urlset"
    assert [loc.text for loc in root.findall(f"{namespace}url/{namespace}loc")] == [
        "https://guardana.dev/docs/x",
        "https://guardana.dev/",
    ]
    assert (site / "robots.txt").read_text(encoding="utf-8") == (
        "User-agent: *\n"
        "Content-Signal: search=yes, ai-input=yes, ai-train=yes\n"
        "Allow: /\n"
        "\nSitemap: https://guardana.dev/sitemap.xml\n"
    )
    first = {name: content for name, (content, _) in _snapshot(site).items()}
    assert generate_sitemap.main() == 0
    assert {name: content for name, (content, _) in _snapshot(site).items()} == first


def test_check_after_write_succeeds_without_writing(
    site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _build(site)
    assert generate_sitemap.main() == 0
    before = _snapshot(site)
    monkeypatch.setattr(sys, "argv", ["generate_sitemap.py", "--check"])

    assert generate_sitemap.main() == 0
    assert _snapshot(site) == before


@pytest.mark.parametrize("name", ["sitemap.xml", "robots.txt"])
@pytest.mark.parametrize("missing", [True, False])
def test_check_rejects_each_missing_or_stale_output_without_writing(
    site: Path, monkeypatch: pytest.MonkeyPatch, name: str, missing: bool
) -> None:
    _build(site)
    assert generate_sitemap.main() == 0
    output = site / name
    if missing:
        output.unlink()
    else:
        output.write_text("stale\n", encoding="utf-8")
    before = _snapshot(site)
    monkeypatch.setattr(sys, "argv", ["generate_sitemap.py", "--check"])

    assert generate_sitemap.main() == 1
    assert _snapshot(site) == before


def test_check_before_write_fails_without_creating_outputs(
    site: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _build(site)
    before = _snapshot(site)
    monkeypatch.setattr(sys, "argv", ["generate_sitemap.py", "--check"])

    assert generate_sitemap.main() == 1
    assert _snapshot(site) == before


@pytest.mark.parametrize("arguments", [[], ["--check"]])
def test_missing_site_fails_without_creating_it(
    site: Path, monkeypatch: pytest.MonkeyPatch, arguments: list[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["generate_sitemap.py", *arguments])

    assert generate_sitemap.main() == 1
    assert not site.exists()
