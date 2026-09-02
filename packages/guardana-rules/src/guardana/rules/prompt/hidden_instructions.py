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
from guardana.rules.prompt._injection_markers import has_smuggled_char
from guardana.rules.supply_chain._leads import lead_verdict
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


def _is_instruction_file(path: Path) -> bool:
    return path.suffix in _DOC_SUFFIXES or path.name.lower() in _RULE_FILE_NAMES


class HiddenInstructionsRule(ArtifactRule):
    """Flags invisible instruction-smuggling characters in text an agent reads as context.

    The signal is *concealment*, not imperative language: an agent rules file, a
    model card, or a model's metadata block is meant to carry text, so directive
    prose is not itself suspect. A bidirectional-override or Unicode-Tags
    character hiding a directive a human reviewer cannot see is — that is the
    Rules-File-Backdoor mechanism.
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
        if text is None:
            return
        if has_smuggled_char(text):
            yield self._finding(
                path,
                "invisible instruction-smuggling character (bidi/zero-width/tag)",
                f"file={path.name}",
            )

    def _scan_safetensors(self, path: Path) -> Iterator[Finding]:
        try:
            header = read_safetensors_header(path)
        except FormatError as exc:
            yield self._unscanned(path, str(exc))
            return
        smuggled = [
            key
            for key, value in header.metadata.items()
            if has_smuggled_char(key) or has_smuggled_char(value)
        ]
        if smuggled:
            yield self._finding(
                path,
                "invisible instruction-smuggling character in the safetensors __metadata__ block",
                f"file={path.name}; entries={', '.join(repr(key) for key in smuggled)}",
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
            verdict=lead_verdict("the metadata block could not be read, so nothing was cleared"),
        )
