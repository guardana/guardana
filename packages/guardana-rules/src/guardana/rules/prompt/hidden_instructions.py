from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.formats import FormatError, read_safetensors_header
from guardana.core.report import Evidence, Finding
from guardana.core.rule import RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, FileReader, Target, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0051,
    ATLAS_T0080,
    OWASP_ASI01_2026,
    OWASP_LLM01_2025,
    OWASP_LLM01_2026,
    OWASP_LLM05_2025,
    OWASP_LLM10_2026,
)
from guardana.rules._base import ArtifactRule
from guardana.rules.prompt._injection_markers import OVERRIDE_PHRASE, has_smuggled_char
from guardana.rules.supply_chain._leads import unscanned_verdict
from guardana.rules.supply_chain._reading import read_text_bounded

# Files an AI coding assistant or a model loader reads as *instructions* or as
# trusted context: agent rule files, and Markdown docs / model cards. A payload
# hidden in one of these (the "Rules File Backdoor") silently steers the model.
_RULE_FILE_NAMES = frozenset({".cursorrules", ".windsurfrules", ".clinerules"})
_DOC_SUFFIXES = (".md", ".mdc")
# safetensors is the format everyone reaches for *because* it cannot carry code —
# which makes its one free-text channel, `__metadata__`, the natural place to
# hide a directive in an artifact reviewers treat as inert. Hubs render it and
# agents read it back.
_SAFETENSORS_SUFFIX = ".safetensors"
_UNSCANNED_TITLE = "Model metadata not scanned"
_PRESENT_TITLE = "Invisible characters in a file an agent reads as context"

# The two smuggling characters a text extractor also produces on its own: PDF
# extraction scatters them through ordinary prose, so their presence alone says
# nothing about intent and they are graded by shape below. Every other character
# the shared detector knows — the bidi controls and the Unicode Tags block — has
# no typographic use in such a file at all.
_ZERO_WIDTH_CHARS = frozenset((chr(0x200B), chr(0x2060)))
# A zero-width channel carries one bit per character, so a shorter run cannot
# spell even a single byte of a hidden instruction.
_PAYLOAD_RUN = 8


def _is_instruction_file(path: Path) -> bool:
    return path.suffix in _DOC_SUFFIXES or path.name.lower() in _RULE_FILE_NAMES


def _longest_zero_width_run(text: str) -> int:
    longest = 0
    current = 0
    for char in text:
        current = current + 1 if char in _ZERO_WIDTH_CHARS else 0
        longest = max(longest, current)
    return longest


def _near_override_phrase(text: str) -> bool:
    return any(
        any(char in _ZERO_WIDTH_CHARS for char in line) and OVERRIDE_PHRASE.search(line)
        for line in text.splitlines()
    )


def _payload_shape(text: str) -> str | None:
    """Describe why the invisible characters carry a plausible payload, or None if they do not.

    Concealment is the signal, but presence is not concealment: one zero-width
    space between two words is what extracting text from a PDF leaves behind,
    while a bidi override, a Tags character or a run long enough to encode a byte
    is nobody's typography.
    """
    if any(has_smuggled_char(char) and char not in _ZERO_WIDTH_CHARS for char in text):
        return "bidi override or Unicode-Tags character"
    run = _longest_zero_width_run(text)
    if run >= _PAYLOAD_RUN:
        return f"a run of {run} zero-width characters"
    if _near_override_phrase(text):
        return "zero-width characters alongside instruction-override phrasing"
    return None


def _first_payload_shape(texts: Iterable[str]) -> str | None:
    for text in texts:
        shape = _payload_shape(text)
        if shape is not None:
            return shape
    return None


class HiddenInstructionsRule(ArtifactRule):
    """Flags invisible instruction-smuggling characters in text an agent reads as context.

    The signal is *concealment*, not imperative language: an agent rules file, a
    model card, or a model's metadata block is meant to carry text, so directive
    prose is not itself suspect. A bidirectional-override or Unicode-Tags
    character hiding a directive a human reviewer cannot see is — that is the
    Rules-File-Backdoor mechanism.

    Presence and concealment are graded apart. Characters shaped like a payload
    are the rule's HIGH finding; zero-width characters that are merely there stay
    LOW and informational, because a corpus built out of PDFs carries them
    everywhere and a rule that shouts at that corpus is the rule a team silences
    before it ever sees the real thing.
    """

    meta = RuleMeta(
        id="guardana.prompt.hidden_instructions",
        title="Hidden instruction smuggled into a file an agent reads as context",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(
            OWASP_LLM01_2025,
            OWASP_LLM01_2026,
            OWASP_LLM05_2025,
            OWASP_LLM10_2026,
            ATLAS_T0051,
            OWASP_ASI01_2026,
            ATLAS_T0080,
        ),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan agent rule files, model cards, and safetensors metadata for smuggled characters."""
        if not isinstance(target, FileReader):
            return
        for path in target.iter_files():
            if _is_instruction_file(path):
                yield from self._scan_text(path)
        for path in target.iter_files((_SAFETENSORS_SUFFIX,)):
            yield from self._scan_safetensors(path)

    def _scan_text(self, path: Path) -> Iterator[Finding]:
        text = read_text_bounded(path, errors="ignore")
        if text is None or not has_smuggled_char(text):
            return
        shape = _payload_shape(text)
        if shape is None:
            yield self._present(
                path,
                "invisible characters present, not shaped like an instruction payload",
                f"file={path.name}",
            )
            return
        yield self._finding(
            path,
            f"invisible instruction-smuggling character (bidi/zero-width/tag): {shape}",
            f"file={path.name}",
        )

    def _scan_safetensors(self, path: Path) -> Iterator[Finding]:
        try:
            header = read_safetensors_header(path)
        except FormatError as exc:
            yield self._unscanned(path, str(exc))
            return
        smuggled = {
            key: value
            for key, value in header.metadata.items()
            if has_smuggled_char(key) or has_smuggled_char(value)
        }
        if not smuggled:
            return
        detail = f"file={path.name}; entries={', '.join(repr(key) for key in smuggled)}"
        shape = _first_payload_shape(
            text for key, value in smuggled.items() for text in (key, value)
        )
        if shape is None:
            yield self._present(
                path,
                "invisible characters in the safetensors __metadata__ block, "
                "not shaped like an instruction payload",
                detail,
            )
            return
        yield self._finding(
            path,
            "invisible instruction-smuggling character in the safetensors "
            f"__metadata__ block: {shape}",
            detail,
        )

    def _finding(self, path: Path, summary: str, detail: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(summary=summary, detail=detail),
        )

    def _present(self, path: Path, summary: str, detail: str) -> Finding:
        """Report invisible characters that were examined and found not to carry a payload."""
        return Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title=_PRESENT_TITLE,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(summary=summary, detail=detail),
        )

    def _unscanned(self, path: Path, reason: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title=_UNSCANNED_TITLE,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(
                summary=f"model metadata not scanned for hidden instructions: {reason}",
                detail=f"file={path.name}",
            ),
            verdict=unscanned_verdict(
                "the metadata block could not be read, so nothing was cleared"
            ),
        )
