"""The icons and security.txt guardana.dev serves by convention, and the icon renderer."""

import struct
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import generate_well_known as well_known
from sitegen import icon
from sitegen.errors import SiteBuildError

_REPO = Path(__file__).resolve().parents[2]
_NOW = datetime(2026, 9, 30, 12, tzinfo=UTC)
_SQUARE = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 4 4">{}</svg>'
_SECURITY_MD = (
    "# Security Policy\n\n## Reporting a vulnerability\n\n"
    "Open a [private advisory](https://github.com/acme/tool/security/advisories/new).\n"
    "Or email **security@acme.test**.\n\n## Scope\n\nMail other@acme.test about scope.\n"
)


def _site(tmp_path: Path) -> tuple[Path, Path]:
    site = tmp_path / "site"
    site.mkdir()
    (site / "favicon.svg").write_text(
        (_REPO / "site" / "favicon.svg").read_text(encoding="utf-8"), encoding="utf-8"
    )
    security_md = tmp_path / "SECURITY.md"
    security_md.write_text(_SECURITY_MD, encoding="utf-8")
    return site, security_md


def _recompressed(png: bytes) -> bytes:
    """The same PNG with its image data deflated at another level, as another zlib might."""
    head, rest = png.split(b"IDAT", 1)
    length = struct.unpack(">I", head[-4:])[0]
    data = zlib.compress(zlib.decompress(rest[:length]), 1)
    chunk = b"IDAT" + data
    return (
        head[:-4]
        + struct.pack(">I", len(data))
        + chunk
        + struct.pack(">I", zlib.crc32(chunk))
        + rest[length + 4 :]
    )


def _pixel(rgba: bytes, size: int, x: int, y: int) -> bytes:
    start = (y * size + x) * 4
    return rgba[start : start + 4]


def test_the_published_files_are_the_ones_the_source_renders() -> None:
    assert well_known.stale(_REPO / "site", _REPO / "SECURITY.md", datetime.now(UTC)) == []


def test_a_fresh_site_is_stale_until_written_and_current_after(tmp_path: Path) -> None:
    site, security_md = _site(tmp_path)

    before = well_known.stale(site, security_md, _NOW)
    first = well_known.write(site, security_md, _NOW)
    after = well_known.stale(site, security_md, _NOW)
    second = well_known.write(site, security_md, _NOW)

    assert len(before) == 4
    assert len(first) == 4
    assert after == []
    assert second == []


def test_a_redrawn_icon_makes_every_rendered_file_stale(tmp_path: Path) -> None:
    site, security_md = _site(tmp_path)
    well_known.write(site, security_md, _NOW)
    svg = site / "favicon.svg"
    svg.write_text(svg.read_text(encoding="utf-8").replace("#5B3DF5", "#000000"), encoding="utf-8")

    assert set(well_known.stale(site, security_md, _NOW)) == {
        "favicon.ico",
        "apple-touch-icon.png",
        "apple-touch-icon-precomposed.png",
    }


def test_a_file_with_the_same_pixels_but_other_bytes_is_left_alone(tmp_path: Path) -> None:
    site, security_md = _site(tmp_path)
    well_known.write(site, security_md, _NOW)
    touch = site / "apple-touch-icon.png"
    original = touch.read_bytes()
    touch.write_bytes(_recompressed(original))

    written = well_known.write(site, security_md, _NOW)

    assert touch.read_bytes() != original
    assert written == []
    assert well_known.stale(site, security_md, _NOW) == []


def test_an_icon_whose_chunk_crc_is_wrong_is_stale_and_rewritten(tmp_path: Path) -> None:
    """Pixels behind a CRC a decoder refuses are not pixels anyone will see."""
    site, security_md = _site(tmp_path)
    well_known.write(site, security_md, _NOW)
    touch = site / "apple-touch-icon.png"
    original = touch.read_bytes()
    ihdr_crc = 8 + 8 + 13
    corrupt = bytearray(original)
    corrupt[ihdr_crc] ^= 0xFF
    touch.write_bytes(bytes(corrupt))

    assert icon.png_pixels(bytes(corrupt)) is None
    assert icon.png_pixels(original[:-4]) is None
    assert well_known.stale(site, security_md, _NOW) != []
    well_known.write(site, security_md, _NOW)
    assert touch.read_bytes() == original


def test_security_txt_names_the_reporting_channels_of_security_md_only(tmp_path: Path) -> None:
    site, security_md = _site(tmp_path)
    well_known.write(site, security_md, _NOW)
    text = (site / ".well-known" / "security.txt").read_text(encoding="utf-8")

    assert text.splitlines()[:3] == [
        "Contact: https://github.com/acme/tool/security/advisories/new",
        "Contact: mailto:security@acme.test",
        "Expires: 2027-03-29T00:00:00Z",
    ]
    assert "other@acme.test" not in text


def test_security_md_without_a_reporting_channel_is_refused() -> None:
    with pytest.raises(SiteBuildError, match="Reporting a vulnerability"):
        well_known.contacts("# Security Policy\n\nNothing here.\n")
    with pytest.raises(SiteBuildError, match="names no advisory URL or email"):
        well_known.contacts("## Reporting a vulnerability\n\nAsk around.\n")


def test_expires_is_kept_while_far_away_and_refreshed_when_close(tmp_path: Path) -> None:
    site, security_md = _site(tmp_path)
    well_known.write(site, security_md, _NOW)
    target = site / ".well-known" / "security.txt"
    first = target.read_text(encoding="utf-8")

    kept = well_known.write(site, security_md, _NOW + timedelta(days=80))
    kept_text = target.read_text(encoding="utf-8")
    refreshed = well_known.write(site, security_md, _NOW + timedelta(days=100))

    assert kept == []
    assert kept_text == first
    assert refreshed == [".well-known/security.txt"]
    assert "Expires: 2027-07-07T00:00:00Z" in target.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("days_later", "is_stale"), [(0, False), (140, False), (151, True), (200, True)]
)
def test_check_fails_once_expires_is_under_thirty_days_away(
    tmp_path: Path, days_later: int, is_stale: bool
) -> None:
    site, security_md = _site(tmp_path)
    well_known.write(site, security_md, _NOW)

    stale = well_known.stale(site, security_md, _NOW + timedelta(days=days_later))

    assert (".well-known/security.txt" in stale) is is_stale


def test_check_fails_on_an_expiry_more_than_a_year_ahead(tmp_path: Path) -> None:
    site, security_md = _site(tmp_path)
    well_known.write(site, security_md, _NOW)
    target = site / ".well-known" / "security.txt"
    target.write_text(
        target.read_text(encoding="utf-8").replace("2027-03-29", "2028-03-29"), encoding="utf-8"
    )

    assert well_known.stale(site, security_md, _NOW) == [".well-known/security.txt"]


def test_a_hand_edited_security_txt_is_stale(tmp_path: Path) -> None:
    site, security_md = _site(tmp_path)
    well_known.write(site, security_md, _NOW)
    target = site / ".well-known" / "security.txt"
    target.write_text(target.read_text(encoding="utf-8") + "Hiring: https://x.test\n", "utf-8")

    assert well_known.stale(site, security_md, _NOW) == [".well-known/security.txt"]


def test_a_filled_rect_covers_its_area_and_rounds_its_corners() -> None:
    svg = _SQUARE.format('<rect width="4" height="4" rx="2" fill="#ff0000"/>')

    rounded = icon.render(svg, 16)
    square = icon.render(svg, 16, full_bleed=True)

    assert _pixel(rounded, 16, 8, 8) == b"\xff\x00\x00\xff"
    assert _pixel(rounded, 16, 0, 0) == b"\x00\x00\x00\x00"
    assert _pixel(square, 16, 0, 0) == b"\xff\x00\x00\xff"


def test_a_stroke_is_drawn_along_its_path_with_round_caps() -> None:
    svg = _SQUARE.format(
        '<path d="m1 2 h2" fill="none" stroke="#fff" stroke-width="1"'
        ' stroke-linejoin="round" stroke-linecap="round"/>'
    )

    rgba = icon.render(svg, 8)

    assert _pixel(rgba, 8, 4, 4) == b"\xff\xff\xff\xff"
    assert _pixel(rgba, 8, 4, 1) == b"\x00\x00\x00\x00"
    assert _pixel(rgba, 8, 1, 4)[3] > 0


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ('<circle r="1"/>', "<circle> is not supported"),
        ('<rect width="4" height="4" stroke="#fff"/>', "attributes"),
        ('<path d="M0 0 A1 1 0 0 1 2 2" stroke="#fff" stroke-linejoin="round"/>', "lacks"),
        ('<path d="M0 0 L1 1" stroke="#fff" stroke-linejoin="miter"/>', "linejoin"),
        ('<path d="M0 0 L1 1" stroke="#fff" stroke-linejoin="round"/>', "linecap"),
        ('<path d="M0 0 L1 1 z" fill="#fff" stroke="#fff" stroke-linejoin="round"/>', "filled"),
        ('<rect width="4" height="4" fill="red"/>', "#rgb"),
    ],
)
def test_svg_outside_the_supported_subset_is_refused(body: str, reason: str) -> None:
    with pytest.raises(SiteBuildError, match=reason):
        icon.render(_SQUARE.format(body), 8)


def test_a_non_square_viewbox_is_refused() -> None:
    with pytest.raises(SiteBuildError, match="square"):
        icon.render('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 4 2"/>', 8)


def test_relative_and_absolute_path_commands_trace_the_same_points() -> None:
    absolute = icon.subpaths("M1 1 L3 1 V3 H1 Z")
    relative = icon.subpaths("m1 1 2 0v2h-2z")

    assert absolute == relative == [([(1, 1), (3, 1), (3, 3), (1, 3)], True)]


def test_png_and_ico_round_trip_their_pixels() -> None:
    small = icon.render(_SQUARE.format('<rect width="4" height="4" fill="#123"/>'), 2)
    large = bytes(range(64))

    assert icon.png_pixels(icon.png(small, 2)) == (2, small)
    assert icon.ico_pixels(icon.ico({2: small, 4: large})) == {2: small, 4: large}
    assert icon.png_pixels(b"GIF89a") is None
    assert icon.ico_pixels(b"\x00\x00\x02\x00\x00\x00") is None
