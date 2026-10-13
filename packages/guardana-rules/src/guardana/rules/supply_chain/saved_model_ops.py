import contextlib
import re
import warnings
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.rule.fixture import FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection
from guardana.core.severity import Severity
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0018,
    NIST_SUPPLY_CHAIN,
    OWASP_ASI05_2026,
    OWASP_LLM05_2025,
    OWASP_LLM10_2026,
    OWASP_ML06_2023,
)
from guardana.rules._base import ArtifactRule
from guardana.rules.supply_chain import _samples
from guardana.rules.supply_chain._leads import lead_verdict, unread_component, unscanned_verdict
from guardana.rules.supply_chain._reading import (
    LFS_POINTER_REASON,
    is_lfs_pointer,
    read_bytes_bounded,
)

# TensorFlow SavedModel graph operators that touch the filesystem on model load.
# In a serialized GraphDef these op types appear verbatim as ASCII, so a bounded
# bytes-scan surfaces them without deserializing (and without ever running the
# graph). They have legitimate uses in data pipelines, so this is a lead — a
# `WriteFile` that rewrites `~/.ssh/authorized_keys` looks the same at the byte
# level as a benign checkpoint write.
_FILESYSTEM_OPS = ("ReadFile", "WriteFile")
# These read the file a string tensor names. A vocabulary table reads the model's own
# asset, so one is a lead only beside a string constant naming a file elsewhere.
_PATH_OPS = ("MatchingFiles", "InitializeTableFromTextFile", "InitializeTableFromTextFileV2")
_BINARY_OP_PATTERNS = tuple(
    (op, re.compile(re.escape(op.encode()) + (b"(?!V2)" if f"{op}V2" in _PATH_OPS else b"")))
    for op in (*_FILESYSTEM_OPS, *_PATH_OPS)
)
_PRINT_OP = "PrintV2"
# `PrintV2` writes to the file its `output_stream` names after this prefix. Protobuf
# keeps a string's bytes as written, so a binary graph holds the prefix verbatim.
_FILE_SCHEME = "file://"
# `TensorProto.string_val` is field 8, length-delimited: what a string `Const` holds.
_STRING_VAL_KEY = 0x42
_MAX_VARINT_BYTES = 10
_MAX_PATH_BYTES = 4096
_MAX_PATH_SHOWN = 200
_CONTINUATION = 0x80
_ASSETS_DIRECTORY = "assets"
_PATH_SEPARATORS = re.compile(r"[\\/]")
_DRIVE = re.compile(r"[A-Za-z]:[\\/]")
# TensorFlow opens a path through its file systems, which read `gs://`, `s3://` and
# `hdfs://` as readily as a local path.
_URL_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")
# Long enough and plain enough that weight bytes taken for a string do not pass for one.
_PATH_SHAPE = re.compile(r"[\w.\-~+@:/\\ ]{5,}")
_MAX_SCAN_BYTES = 64 * 1024 * 1024
# TensorFlow reads the text form only under this name, and only when no binary graph exists.
_TEXT_GRAPH_NAME = "saved_model.pbtxt"
# In the text form an operator is the string value of an `op` field, which protobuf
# lets a writer escape, split across adjacent literals and interleave with comments.
# Python's text_format separates tokens with any Unicode whitespace. A comment must end at
# its newline, so a run of `#` has one parse, not exponentially many.
_TEXT_GAP = r"(?:\s|#[^\n]*\n)*"
_TEXT_STRING = r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'"
_TEXT_OP_FIELD = re.compile(
    rf"op(?<![\w.]op){_TEXT_GAP}:{_TEXT_GAP}((?:{_TEXT_STRING})(?:{_TEXT_GAP}(?:{_TEXT_STRING}))*)"
)
_TEXT_STRING_LITERAL = re.compile(_TEXT_STRING)
# A string constant's value and a string attribute, which hold a tensor's text and
# `PrintV2`'s output stream.
_TEXT_STRING_FIELD = re.compile(
    rf"(?<![\w.])(string_val|s){_TEXT_GAP}:{_TEXT_GAP}"
    rf"((?:{_TEXT_STRING})(?:{_TEXT_GAP}(?:{_TEXT_STRING}))*)"
)
_TEXT_ESCAPE = re.compile(
    r"\\(?:([0-7]{1,3})|x([0-9a-fA-F]{1,2})|u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|(.))", re.DOTALL
)
_MAX_CODE_POINT = 0x10FFFF
_TEXT_SIMPLE_ESCAPES = {
    "a": b"\a", "b": b"\b", "f": b"\f", "n": b"\n", "r": b"\r", "t": b"\t", "v": b"\v",
}  # fmt: skip
_CUNESCAPE_HEX = re.compile(r"(\\+)x([0-9a-fA-F])(?![0-9a-fA-F])")


def _padded_hex(match: re.Match[str]) -> str:
    """Pad a one-digit hex escape whose backslash is not itself escaped."""
    if len(match.group(1)) % 2:
        return f"{match.group(1)}x0{match.group(2)}"
    return match.group(0)


def _python_unescape(literal: str) -> bytes:
    """Decode a string literal body exactly as Python's protobuf `text_format` does.

    Raises `ValueError` where that parser rejects the literal.
    """
    with warnings.catch_warnings():
        # An unknown escape is kept as written, with a warning nothing needs to see.
        warnings.simplefilter("ignore", DeprecationWarning)
        text = _CUNESCAPE_HEX.sub(_padded_hex, literal)
        text = text.encode("raw_unicode_escape").decode("raw_unicode_escape")
        text = text.encode("utf-8").decode("unicode_escape")
        return text.encode("latin-1")


def _unescape(literal: str) -> bytes:
    """Decode the body of a protobuf text-format string literal as the C++ parser does."""
    if "\\" not in literal:
        return literal.encode("utf-8", "surrogateescape")
    out = bytearray()
    position = 0
    for match in _TEXT_ESCAPE.finditer(literal):
        out += literal[position : match.start()].encode("utf-8", "surrogateescape")
        position = match.end()
        octal, short_hex, unicode4, unicode8, other = match.groups()
        if octal:
            out.append(int(octal, 8) & 0xFF)
        elif short_hex:
            out.append(int(short_hex, 16))
        elif unicode4 or unicode8:
            code = int(unicode4 or unicode8, 16)
            if code <= _MAX_CODE_POINT:
                out += chr(code).encode("utf-8", "surrogatepass")
        else:
            out += _TEXT_SIMPLE_ESCAPES.get(other, other.encode("utf-8", "surrogateescape"))
    out += literal[position:].encode("utf-8", "surrogateescape")
    return bytes(out)


@dataclass(frozen=True, slots=True)
class _Lead:
    """One operator worth a look: what to say about it and why it is only a lead."""

    op: str
    summary: str
    rationale: str


def _file_op_lead(op: str) -> _Lead:
    return _Lead(
        op,
        f"{op} filesystem op in SavedModel graph (load-time file I/O)",
        f"{op} op present; legitimate in data pipelines, so a lead, not a verdict",
    )


def _path_op_lead(op: str, path: str) -> _Lead:
    shown = path[:_MAX_PATH_SHOWN] + ("..." if len(path) > _MAX_PATH_SHOWN else "")
    return _Lead(
        op,
        f"{op} op in SavedModel graph beside a string constant naming {shown!r}, outside "
        "the model's assets (load-time file I/O)",
        f"{op} op and that path present, not tied through the graph, so a lead, not a verdict",
    )


def _print_lead() -> _Lead:
    return _Lead(
        _PRINT_OP,
        f"{_PRINT_OP} op in SavedModel graph beside a {_FILE_SCHEME} output stream (writes a file)",
        f"{_PRINT_OP} op and a file stream present; legitimate for logging, so a lead",
    )


def names_a_file_elsewhere(value: str, assets: frozenset[str]) -> bool:
    """Whether a string is an absolute path, a `..` path or a URL naming a file outside `assets`.

    A path whose file name the model ships under its own `assets/` is taken for that
    asset: TensorFlow writes the export-time path of an asset and feeds the copy. Bytes
    of another shape, such as an enclosing message or weights read as a string, are no path.
    """
    if _PATH_SHAPE.fullmatch(value) is None:
        return False
    path = value.removeprefix(_FILE_SCHEME)
    parts = _PATH_SEPARATORS.split(path)
    elsewhere = (
        _URL_SCHEME.match(value) is not None
        or path.startswith(("/", "\\"))
        or _DRIVE.match(path) is not None
        or ".." in parts
    )
    return elsewhere and parts[-1] not in assets


def _varint_at(data: bytes, offset: int) -> tuple[int, int] | None:
    """Decode the varint at `offset`; return it and the offset after it, or None."""
    value = 0
    for index in range(_MAX_VARINT_BYTES):
        if offset + index >= len(data):
            return None
        byte = data[offset + index]
        value |= (byte & 0x7F) << (7 * index)
        if byte < _CONTINUATION:
            return value, offset + index + 1
    return None


def _decoded(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _binary_strings(data: bytes) -> Iterator[str]:
    """Yield every string constant value a binary graph may hold, read at each field key.

    Every byte equal to the key is tried, so a key hidden inside a neighbour's bytes or
    a length written in more bytes than it needs is still read.
    """
    position = data.find(_STRING_VAL_KEY)
    while position >= 0:
        header = _varint_at(data, position + 1)
        if header is not None:
            length, start = header
            if 0 < length <= _MAX_PATH_BYTES and start + length <= len(data):
                value = _decoded(data[start : start + length])
                if value is not None:
                    yield value
        position = data.find(_STRING_VAL_KEY, position + 1)


def _text_strings(data: bytes) -> Iterator[tuple[str, str]]:
    """Yield each `string_val` and `s` field of a text graph with its value, decoded both ways."""
    text = data.decode("utf-8", "surrogateescape")
    for field, value in _TEXT_STRING_FIELD.findall(text):
        bodies = [literal[1:-1] for literal in _TEXT_STRING_LITERAL.findall(value)]
        decoded = [b"".join(_unescape(body) for body in bodies)]
        with contextlib.suppress(ValueError):
            decoded.append(b"".join(_python_unescape(body) for body in bodies))
        for each in dict.fromkeys(decoded):
            yield field, each.decode("utf-8", "replace")


def _path_leads(
    ops: list[str], strings: Iterable[str], assets: Callable[[], frozenset[str]]
) -> list[_Lead]:
    """Lead on each path op present when a string constant names a file elsewhere."""
    if not ops:
        return []
    names = assets()
    path = next((value for value in strings if names_a_file_elsewhere(value, names)), None)
    return [] if path is None else [_path_op_lead(op, path) for op in ops]


def _binary_leads(data: bytes, assets: Callable[[], frozenset[str]]) -> list[_Lead]:
    """Return the leads in a binary graph, its operators found wherever their names sit."""
    present = [op for op, pattern in _BINARY_OP_PATTERNS if pattern.search(data)]
    leads = [_file_op_lead(op) for op in present if op in _FILESYSTEM_OPS]
    leads += _path_leads([op for op in present if op in _PATH_OPS], _binary_strings(data), assets)
    if _PRINT_OP.encode() in data and _FILE_SCHEME.encode() in data:
        leads.append(_print_lead())
    return leads


def _text_leads(data: bytes, assets: Callable[[], frozenset[str]]) -> tuple[list[_Lead], bool]:
    """Return the leads a text graph's `op` fields name, and whether every op value decoded."""
    names, decoded = _text_op_names(data)
    leads = [_file_op_lead(op) for op in _FILESYSTEM_OPS if op.encode() in names]
    strings = list(_text_strings(data))
    path_ops = [op for op in _PATH_OPS if op.encode() in names]
    leads += _path_leads(path_ops, (value for field, value in strings if field != "s"), assets)
    streams = (value for field, value in strings if field == "s")
    if _PRINT_OP.encode() in names and any(value.startswith(_FILE_SCHEME) for value in streams):
        leads.append(_print_lead())
    return leads, decoded


def _text_op_names(data: bytes) -> tuple[set[bytes], bool]:
    """Return the operator names a text graph's `op` fields hold, and whether all decoded.

    Each value is decoded the way both protobuf parsers decode it, so an operator one of
    them would load is found; a value Python's parser cannot decode is not cleared.
    """
    names: set[bytes] = set()
    decoded = True
    text = data.decode("utf-8", "surrogateescape")
    for value in set(_TEXT_OP_FIELD.findall(text)):
        bodies = [literal[1:-1] for literal in _TEXT_STRING_LITERAL.findall(value)]
        names.add(b"".join(_unescape(body) for body in bodies))
        try:
            names.add(b"".join(_python_unescape(body) for body in bodies))
        except ValueError:
            decoded = False
    return names, decoded


def _asset_names(target: FileReader, graph: Path) -> frozenset[str]:
    """Return the names of the files the model beside `graph` ships under `assets/`."""
    assets = graph.parent / _ASSETS_DIRECTORY
    return frozenset(path.name for path in target.iter_files() if assets in path.parents)


class SavedModelOpsRule(ArtifactRule):
    """Flag operators in a TensorFlow SavedModel graph that read or write files.

    Reads every binary `.pb` graph and the text form TensorFlow loads in its place,
    `saved_model.pbtxt`. `ReadFile` and `WriteFile` are leads wherever they sit;
    `MatchingFiles` and a table filled from a text file are leads beside a string
    constant naming a file outside the model's assets, and `PrintV2` beside a `file://`
    output stream.
    """

    meta = RuleMeta(
        id="guardana.supply_chain.saved_model_ops",
        title="TensorFlow SavedModel filesystem operator",
        severity=Severity.MEDIUM,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM05_2025,
            OWASP_LLM10_2026,
            OWASP_ML06_2023,
            ATLAS_T0018,
            NIST_SUPPLY_CHAIN,
            OWASP_ASI05_2026,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
        detection=Detection.HEURISTIC,
    )

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a graph with a `WriteFile` op, one without and one longer than the read bound."""
        return materialise(
            (
                _samples.sample(
                    "a SavedModel graph carrying a WriteFile op",
                    FixtureOutcome.FINDING,
                    {"saved_model.pb": b"\n\x0bsave/Write\x12\tWriteFile"},
                ),
                _samples.sample(
                    "a SavedModel graph of constants only",
                    FixtureOutcome.CLEAN,
                    {"saved_model.pb": b"\n\x05const\x12\x05Const"},
                ),
                _samples.sample(
                    "a graph padded past the read bound, its WriteFile op after the padding",
                    FixtureOutcome.INCONCLUSIVE,
                    {"saved_model.pb": bytes(_MAX_SCAN_BYTES) + b"\x12\tWriteFile"},
                ),
            )
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every `.pb` graph and every `saved_model.pbtxt` for operators that touch files."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".pb", ".pbtxt")):
            if path.suffix.lower() == ".pb":
                yield from self._scan(target, path, ctx, text=False)
            elif path.name.lower() == _TEXT_GRAPH_NAME:
                yield from self._scan(target, path, ctx, text=True)

    def _scan(
        self, target: FileReader, path: Path, ctx: RuleContext, *, text: bool
    ) -> Iterator[Finding]:
        prefix = read_bytes_bounded(path, _MAX_SCAN_BYTES)
        if prefix is None:
            yield self._unscanned(path, ctx, "the file could not be read", "was not read")
            return
        data, truncated = prefix
        if not truncated and is_lfs_pointer(data):
            yield self._unscanned(path, ctx, LFS_POINTER_REASON, "was not fetched")
            return
        if truncated:
            # Past the bound the graph is unread, so an op sitting after it is
            # invisible, and silence about the tail reads exactly like a clean graph.
            reason = f"only the first {_MAX_SCAN_BYTES} bytes were read"
            yield self._unscanned(path, ctx, reason, "was read only in part")
        else:
            ctx.examined(path)

        def assets() -> frozenset[str]:
            return _asset_names(target, path)

        if text:
            leads, decoded = _text_leads(data, assets)
            if not decoded:
                reason = "an op field's value could not be decoded as protobuf decodes it"
                yield self._unscanned(path, ctx, reason, "was not decoded in full")
        else:
            leads = _binary_leads(data, assets)
        for lead in leads:
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=str(path),
                evidence=Evidence(summary=lead.summary, detail=f"file={path.name}"),
                verdict=lead_verdict(lead.rationale),
            )

    def _unscanned(self, path: Path, ctx: RuleContext, reason: str, how: str) -> Finding:
        """Name the graph as an unread component and build its inconclusive finding."""
        ctx.shortfall(unread_component(self.meta.id, path, reason))
        return Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title="SavedModel not scanned",
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(summary=reason, detail=f"file={path.name}"),
            verdict=unscanned_verdict(f"the graph {how}, so nothing was cleared"),
        )
