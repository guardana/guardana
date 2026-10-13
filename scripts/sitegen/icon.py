"""Render the site's SVG icon to PNG and ICO, and read those back, with the standard library.

Only the SVG subset `site/favicon.svg` uses is understood: a square `viewBox`, a
filled `rect` with `rx`, and a stroked `path` of straight and cubic segments with
round joins. Anything else raises, so a redrawn icon cannot be rendered wrong
without anyone noticing.
"""

import itertools
import math
import re
import struct
import zlib
from xml.etree import ElementTree

from sitegen.errors import SiteBuildError

Point = tuple[float, float]
Color = tuple[int, int, int]

_SVG = "{http://www.w3.org/2000/svg}"
_SAMPLES = 4
"""Samples per pixel along each axis; coverage comes in steps of 1/16."""
_CURVE_STEPS = 24
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PATH_TOKEN = re.compile(r"[MmLlHhVvCcZz]|[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")
_ARITY = {"M": 2, "L": 2, "H": 1, "V": 1, "C": 6}
_RECT_ATTRIBUTES = frozenset({"x", "y", "width", "height", "rx", "fill"})
_PATH_ATTRIBUTES = frozenset(
    {"d", "fill", "stroke", "stroke-width", "stroke-linejoin", "stroke-linecap"}
)
_SHORT_HEX = 3
_VIEWBOX_FIELDS = 4
_IHDR_LENGTH = 13
_BIT_DEPTH = 8
_RGBA_COLOR_TYPE = 6
_ICO_HEADER = 6
_ICO_ENTRY = 16
_ICO_FULL_SIDE = 256


class _Canvas:
    """A supersampled coverage mask for one shape at a time, composited into RGBA."""

    def __init__(self, size: int, scale: float) -> None:
        self.size = size
        self.width = size * _SAMPLES
        self.scale = scale * _SAMPLES
        self.pixels = [0.0] * (size * size * 4)

    def mask(self) -> bytearray:
        return bytearray(self.width * self.width)

    def composite(self, mask: bytearray, color: Color) -> None:
        red, green, blue = (channel / 255 for channel in color)
        area = _SAMPLES * _SAMPLES
        for pixel_y in range(self.size):
            starts = [(pixel_y * _SAMPLES + sub) * self.width for sub in range(_SAMPLES)]
            rows = [mask[start : start + self.width] for start in starts]
            for pixel_x in range(self.size):
                start = pixel_x * _SAMPLES
                covered = sum(sum(row[start : start + _SAMPLES]) for row in rows)
                if not covered:
                    continue
                alpha = covered / area
                index = (pixel_y * self.size + pixel_x) * 4
                keep = 1 - alpha
                self.pixels[index] = red * alpha + self.pixels[index] * keep
                self.pixels[index + 1] = green * alpha + self.pixels[index + 1] * keep
                self.pixels[index + 2] = blue * alpha + self.pixels[index + 2] * keep
                self.pixels[index + 3] = alpha + self.pixels[index + 3] * keep

    def rgba(self) -> bytes:
        out = bytearray()
        for index in range(0, len(self.pixels), 4):
            alpha = self.pixels[index + 3]
            if alpha <= 0:
                out += b"\x00\x00\x00\x00"
                continue
            out += bytes(_byte(self.pixels[index + k] / alpha) for k in range(3))
            out.append(_byte(alpha))
        return bytes(out)


def _byte(value: float) -> int:
    return min(255, max(0, int(value * 255 + 0.5)))


def _number(element: ElementTree.Element, name: str, default: float | None = None) -> float:
    raw = element.get(name)
    if raw is None:
        if default is None:
            raise SiteBuildError(f"icon: <{_tag(element)}> has no {name}")
        return default
    try:
        return float(raw)
    except ValueError:
        raise SiteBuildError(f"icon: <{_tag(element)}> {name}={raw!r} is not a number") from None


def _color(raw: str | None) -> Color | None:
    if raw is None or raw == "none":
        return None
    hex_digits = raw.removeprefix("#")
    if raw.startswith("#") and len(hex_digits) == _SHORT_HEX:
        hex_digits = "".join(digit * 2 for digit in hex_digits)
    if not raw.startswith("#") or not re.fullmatch(r"[0-9a-fA-F]{6}", hex_digits):
        raise SiteBuildError(f"icon: colour {raw!r} is not #rgb or #rrggbb")
    return (int(hex_digits[0:2], 16), int(hex_digits[2:4], 16), int(hex_digits[4:6], 16))


def _tag(element: ElementTree.Element) -> str:
    return element.tag.removeprefix(_SVG)


def _cubic(start: Point, first: Point, second: Point, end: Point) -> list[Point]:
    points = []
    for step in range(1, _CURVE_STEPS + 1):
        t = step / _CURVE_STEPS
        u = 1 - t
        a, b, c, d = u * u * u, 3 * u * u * t, 3 * u * t * t, t * t * t
        points.append(
            (
                a * start[0] + b * first[0] + c * second[0] + d * end[0],
                a * start[1] + b * first[1] + c * second[1] + d * end[1],
            )
        )
    return points


def _commands(data: str) -> list[tuple[str, list[float]]]:
    """Split path data into commands with their numbers, spelling out implicit repeats."""
    if _PATH_TOKEN.sub("", data).strip(" ,\t\r\n"):
        raise SiteBuildError(f"icon: path data uses a command this renderer lacks: {data!r}")
    tokens = _PATH_TOKEN.findall(data)
    commands: list[tuple[str, list[float]]] = []
    command = ""
    position = 0
    while position < len(tokens):
        if tokens[position].isalpha():
            command = tokens[position]
            position += 1
            if command in "Zz":
                commands.append((command, []))
                continue
        if command in ("", "Z", "z"):
            raise SiteBuildError(f"icon: path data has a number with no command: {data!r}")
        arity = _ARITY[command.upper()]
        chunk = tokens[position : position + arity]
        if len(chunk) < arity or any(token.isalpha() for token in chunk):
            raise SiteBuildError(f"icon: {command} needs {arity} numbers in {data!r}")
        commands.append((command, [float(token) for token in chunk]))
        position += arity
        if command in "Mm":
            command = "l" if command == "m" else "L"
    return commands


def _advance(kind: str, values: list[float], current: Point, offset: Point) -> list[Point]:
    dx, dy = offset
    if kind == "C":
        return _cubic(
            current,
            (values[0] + dx, values[1] + dy),
            (values[2] + dx, values[3] + dy),
            (values[4] + dx, values[5] + dy),
        )
    if kind == "H":
        return [(values[0] + dx, current[1])]
    if kind == "V":
        return [(current[0], values[0] + dy)]
    return [(values[0] + dx, values[1] + dy)]


def subpaths(data: str) -> list[tuple[list[Point], bool]]:
    """Flatten SVG path data into polylines, each with whether it was closed."""
    lines: list[tuple[list[Point], bool]] = []
    points: list[Point] = []
    current: Point = (0.0, 0.0)
    for command, values in _commands(data):
        kind = command.upper()
        if kind == "Z":
            if len(points) > 1:
                lines.append((points, True))
            current = points[0] if points else current
            points = []
            continue
        if kind == "M":
            if len(points) > 1:
                lines.append((points, False))
            points = []
        elif not points:
            points = [current]
        offset = current if command.islower() else (0.0, 0.0)
        points.extend(_advance(kind, values, current, offset))
        current = points[-1]
    if len(points) > 1:
        lines.append((points, False))
    return lines


def _fill_rect(canvas: _Canvas, element: ElementTree.Element, *, full_bleed: bool) -> bytearray:
    left, top = _number(element, "x", 0.0), _number(element, "y", 0.0)
    right, bottom = left + _number(element, "width"), top + _number(element, "height")
    radius = 0.0 if full_bleed else min(_number(element, "rx", 0.0), (right - left) / 2)
    mask = canvas.mask()
    for row in range(canvas.width):
        v = (row + 0.5) / canvas.scale
        if not top <= v < bottom:
            continue
        inset = 0.0
        corner = max(top + radius - v, v - (bottom - radius), 0.0)
        if corner > 0:
            inset = radius - (radius * radius - corner * corner) ** 0.5
        first = max(0, math.ceil((left + inset) * canvas.scale - 0.5))
        last = min(canvas.width, math.ceil((right - inset) * canvas.scale - 0.5))
        if last > first:
            mask[row * canvas.width + first : row * canvas.width + last] = b"\x01" * (last - first)
    return mask


def _stroke(canvas: _Canvas, lines: list[tuple[list[Point], bool]], width: float) -> bytearray:
    mask = canvas.mask()
    half = width / 2
    reach = half * half
    for points, closed in lines:
        segments = list(itertools.pairwise(points))
        if closed:
            segments.append((points[-1], points[0]))
        for (ax, ay), (bx, by) in segments:
            first_x = max(0, int((min(ax, bx) - half) * canvas.scale))
            last_x = min(canvas.width, int((max(ax, bx) + half) * canvas.scale) + 1)
            first_y = max(0, int((min(ay, by) - half) * canvas.scale))
            last_y = min(canvas.width, int((max(ay, by) + half) * canvas.scale) + 1)
            ex, ey = bx - ax, by - ay
            length = ex * ex + ey * ey
            for row in range(first_y, last_y):
                v = (row + 0.5) / canvas.scale
                for column in range(first_x, last_x):
                    u = (column + 0.5) / canvas.scale
                    t = 0.0 if length == 0 else ((u - ax) * ex + (v - ay) * ey) / length
                    t = min(1.0, max(0.0, t))
                    du, dv = u - (ax + t * ex), v - (ay + t * ey)
                    if du * du + dv * dv <= reach:
                        mask[row * canvas.width + column] = 1
    return mask


def _path(canvas: _Canvas, element: ElementTree.Element) -> tuple[bytearray, Color] | None:
    if _color(element.get("fill")) is not None:
        raise SiteBuildError("icon: a filled <path> is not supported, only a stroked one")
    color = _color(element.get("stroke"))
    if color is None:
        return None
    if element.get("stroke-linejoin") != "round":
        raise SiteBuildError("icon: a stroked <path> must use stroke-linejoin=round")
    lines = subpaths(element.get("d", ""))
    if element.get("stroke-linecap") != "round" and not all(closed for _, closed in lines):
        raise SiteBuildError("icon: an open stroked <path> must use stroke-linecap=round")
    return _stroke(canvas, lines, _number(element, "stroke-width", 1.0)), color


def render(svg: str, size: int, *, full_bleed: bool = False) -> bytes:
    """Rasterise the icon to `size` square RGBA pixels; `full_bleed` squares the corners."""
    root = ElementTree.fromstring(svg)  # noqa: S314 — the repository's own icon, not input from outside
    if root.tag != f"{_SVG}svg":
        raise SiteBuildError("icon: the root element is not <svg>")
    box = [float(value) for value in root.get("viewBox", "").split()]
    if len(box) != _VIEWBOX_FIELDS or box[0] or box[1] or box[2] != box[3] or box[2] <= 0:
        raise SiteBuildError("icon: the viewBox must be a square starting at 0 0")
    canvas = _Canvas(size, size / box[2])
    for element in root:
        tag = _tag(element)
        allowed = {"rect": _RECT_ATTRIBUTES, "path": _PATH_ATTRIBUTES}.get(tag)
        if allowed is None:
            raise SiteBuildError(f"icon: <{tag}> is not supported")
        extra = set(element.attrib) - allowed
        if extra:
            raise SiteBuildError(f"icon: <{tag}> attributes {sorted(extra)} are not supported")
        if tag == "rect":
            color = _color(element.get("fill", "#000000"))
            if color is not None:
                canvas.composite(_fill_rect(canvas, element, full_bleed=full_bleed), color)
            continue
        stroked = _path(canvas, element)
        if stroked is not None:
            canvas.composite(*stroked)
    return canvas.rgba()


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png(rgba: bytes, size: int) -> bytes:
    """Encode square straight-RGBA pixels as a PNG, every scanline unfiltered."""
    stride = size * 4
    raw = b"".join(b"\x00" + rgba[row * stride : (row + 1) * stride] for row in range(size))
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        _PNG_SIGNATURE
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(raw, 9))
        + _chunk(b"IEND", b"")
    )


def _png_chunks(data: bytes) -> tuple[bytes, bytes] | None:
    """Return a PNG's IHDR body and joined IDAT data, or None unless every chunk is whole.

    A decoder such as libpng refuses a chunk whose CRC does not match or a file that
    ends before IEND, so the pixels such a file carries are not what a browser shows.
    """
    position, header, compressed = len(_PNG_SIGNATURE), b"", b""
    while position + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[position : position + 8])
        end = position + 8 + length
        if end + 4 > len(data):
            return None
        body = data[position + 8 : end]
        if zlib.crc32(kind + body) != struct.unpack(">I", data[end : end + 4])[0]:
            return None
        position = end + 4
        if kind == b"IEND":
            return header, compressed
        if kind == b"IHDR":
            header = body
        elif kind == b"IDAT":
            compressed += body
    return None


def png_pixels(data: bytes) -> tuple[int, bytes] | None:
    """Decode a PNG `png` wrote into its size and RGBA pixels, or None for anything else.

    Pixels rather than bytes, because two zlib builds may compress the same
    scanlines differently and a check must not depend on which one ran.
    """
    chunks = _png_chunks(data) if data.startswith(_PNG_SIGNATURE) else None
    if chunks is None or len(chunks[0]) != _IHDR_LENGTH:
        return None
    header, compressed = chunks
    width, height, depth, color_type, _, _, interlace = struct.unpack(">IIBBBBB", header)
    if width != height or depth != _BIT_DEPTH or color_type != _RGBA_COLOR_TYPE or interlace:
        return None
    try:
        raw = zlib.decompress(compressed)
    except zlib.error:
        return None
    stride = width * 4 + 1
    if len(raw) != stride * height or any(raw[row * stride] for row in range(height)):
        return None
    return width, b"".join(raw[row * stride + 1 : (row + 1) * stride] for row in range(height))


def ico(images: dict[int, bytes]) -> bytes:
    """Pack one PNG per size into an ICO, the form every current browser reads."""
    encoded = [(size, png(rgba, size)) for size, rgba in sorted(images.items())]
    offset = _ICO_HEADER + _ICO_ENTRY * len(encoded)
    directory = struct.pack("<HHH", 0, 1, len(encoded))
    for size, data in encoded:
        side = 0 if size >= _ICO_FULL_SIDE else size
        directory += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    return directory + b"".join(data for _, data in encoded)


def ico_pixels(data: bytes) -> dict[int, bytes] | None:
    """Decode an ICO `ico` wrote into size-to-RGBA pixels, or None for anything else."""
    if len(data) < _ICO_HEADER:
        return None
    reserved, kind, count = struct.unpack("<HHH", data[:_ICO_HEADER])
    if reserved or kind != 1 or len(data) < _ICO_HEADER + _ICO_ENTRY * count:
        return None
    images: dict[int, bytes] = {}
    for entry in range(count):
        start = _ICO_HEADER + _ICO_ENTRY * entry + 8
        length, offset = struct.unpack("<II", data[start : start + 8])
        decoded = png_pixels(data[offset : offset + length])
        if decoded is None:
            return None
        images[decoded[0]] = decoded[1]
    return images
