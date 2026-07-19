from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import ATLAS_T0051, OWASP_LLM01, OWASP_LLM05
from guardana.rules.prompt._injection_markers import has_smuggled_char
from guardana.rules.supply_chain._reading import read_text_bounded

# Files an AI coding assistant or a model loader reads as *instructions* or as
# trusted context: agent rule files, and Markdown docs / model cards. A payload
# hidden in one of these (the "Rules File Backdoor") silently steers the model.
_RULE_FILE_NAMES = frozenset({".cursorrules", ".windsurfrules", ".clinerules"})
_DOC_SUFFIXES = (".md", ".mdc")


def _is_instruction_file(path: Path) -> bool:
    return path.suffix in _DOC_SUFFIXES or path.name.lower() in _RULE_FILE_NAMES


class HiddenInstructionsRule(Rule):
    """Flags invisible instruction-smuggling characters in agent rule files and model cards.

    The signal is *concealment*, not imperative language: an agent rules file or a
    model card is meant to carry instructions, so directive prose is not itself
    suspect. A bidirectional-override or Unicode-Tags character hiding a directive
    a human reviewer cannot see is — that is the Rules-File-Backdoor mechanism.
    """

    meta = RuleMeta(
        id="guardana.prompt.hidden_instructions",
        title="Hidden instruction smuggled into an agent rule file or model card",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM01, OWASP_LLM05, ATLAS_T0051),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan agent rule files and Markdown docs/model cards for smuggled characters."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files():
            if _is_instruction_file(path):
                yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        text = read_text_bounded(path, errors="ignore")
        if text is None:
            return
        if has_smuggled_char(text):
            yield Finding(
                rule_id=self.meta.id,
                severity=self.meta.severity,
                title=self.meta.title,
                taxonomy=self.meta.taxonomy,
                target_ref=str(path),
                evidence=Evidence(
                    summary="invisible instruction-smuggling character (bidi/zero-width/tag)",
                    detail=f"file={path.name}",
                ),
            )
