import re
import warnings
from collections.abc import Callable, Iterable, Iterator
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
# level as a benign checkpoint write. Argument evaluation (the follow-on) needs
# a protobuf parser; presence alone is the first-pass signal.
_FILESYSTEM_OPS = (b"ReadFile", b"WriteFile")
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


def _binary_ops(data: bytes) -> tuple[list[bytes], bool]:
    """Return the filesystem operators named anywhere in a binary graph; it always decodes."""
    return [op for op in _FILESYSTEM_OPS if op in data], True


def _text_ops(data: bytes) -> tuple[list[bytes], bool]:
    """Return the filesystem operators a text graph's `op` fields name, and whether all decoded.

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
    return [op for op in _FILESYSTEM_OPS if op in names], decoded


class SavedModelOpsRule(ArtifactRule):
    """Flag filesystem operators (`ReadFile`/`WriteFile`) in a TensorFlow SavedModel graph.

    Reads every binary `.pb` graph and the text form TensorFlow loads in its place,
    `saved_model.pbtxt`.
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
        """Scan every `.pb` graph and every `saved_model.pbtxt` for filesystem operators."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files((".pb", ".pbtxt")):
            if path.suffix.lower() == ".pb":
                yield from self._scan(path, ctx, _binary_ops)
            elif path.name.lower() == _TEXT_GRAPH_NAME:
                yield from self._scan(path, ctx, _text_ops)

    def _scan(
        self, path: Path, ctx: RuleContext, find_ops: Callable[[bytes], tuple[list[bytes], bool]]
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
        ops, decoded = find_ops(data)
        if not decoded:
            reason = "an op field's value could not be decoded as protobuf decodes it"
            yield self._unscanned(path, ctx, reason, "was not decoded in full")
        for op in ops:
            name = op.decode()
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=str(path),
                evidence=Evidence(
                    summary=f"{name} filesystem op in SavedModel graph (load-time file I/O)",
                    detail=f"file={path.name}",
                ),
                verdict=lead_verdict(
                    f"{name} op present; legitimate in data pipelines, so a lead, not a verdict"
                ),
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
