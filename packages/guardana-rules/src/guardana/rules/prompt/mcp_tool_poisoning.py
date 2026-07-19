import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import ArtifactTarget, Capability, Target, TargetKind
from guardana.core.taxonomy import ATLAS_T0051, OWASP_LLM01, OWASP_LLM05
from guardana.rules.prompt._injection_markers import OVERRIDE_PHRASE, has_hidden_char
from guardana.rules.supply_chain._leads import lead_verdict
from guardana.rules.supply_chain._reading import read_text_bounded

# An MCP tool description is fed to the agent's model as trusted context, so
# instructions hidden in it are indirect prompt injection ("tool poisoning"). The
# hidden-char and override-phrase detectors are shared with `hidden_instructions`
# (`_injection_markers`); the base64 signal is specific to a tool manifest.
# A long unbroken base64 run is an encoded payload far more often than legit prose.
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{48,}={0,2}")


def _mcp_tools(doc: object) -> list[dict[str, object]] | None:
    """Return the tool objects if `doc` is an MCP tool manifest, else None (shape gate)."""
    tools = doc.get("tools") if isinstance(doc, dict) else doc
    if not isinstance(tools, list):
        return None
    objects = [t for t in tools if isinstance(t, dict)]
    is_tool_shape = any("name" in t and "description" in t for t in objects)
    return objects if is_tool_shape else None


def _iter_strings(node: object) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _iter_strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_strings(item)


class McpToolPoisoningRule(Rule):
    """Flag hidden instructions in an MCP tool manifest — indirect prompt injection."""

    meta = RuleMeta(
        id="guardana.prompt.mcp_tool_poisoning",
        title="MCP tool description carries a hidden instruction (tool poisoning)",
        severity=Severity.HIGH,
        target_kind=TargetKind.ARTIFACT,
        taxonomy=(OWASP_LLM01, OWASP_LLM05, ATLAS_T0051),
        required_capabilities=frozenset({Capability.READ_FILES}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Scan every JSON file that has the shape of an MCP tool manifest."""
        if not isinstance(target, ArtifactTarget):
            return
        for path in target.iter_files((".json",)):
            yield from self._scan(path)

    def _scan(self, path: Path) -> Iterator[Finding]:
        raw = read_text_bounded(path, errors="ignore")
        if raw is None:
            return
        try:
            doc = json.loads(raw)
        except ValueError:
            return
        tools = _mcp_tools(doc)
        if tools is None:
            return
        strings = list(_iter_strings(tools))
        if any(has_hidden_char(s) for s in strings):
            yield self._finding(
                path, "invisible/hidden Unicode in a tool description", Severity.HIGH
            )
        if any(OVERRIDE_PHRASE.search(s) for s in strings):
            yield self._finding(
                path, "instruction-override phrase in a tool description", Severity.HIGH
            )
        if any(_BASE64_BLOB.search(s) for s in strings):
            yield self._finding(
                path,
                "long base64 blob in a tool description (possible encoded payload)",
                Severity.MEDIUM,
                lead=True,
            )

    def _finding(
        self, path: Path, summary: str, severity: Severity, *, lead: bool = False
    ) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=str(path),
            evidence=Evidence(summary=summary, detail=f"file={path.name}"),
            verdict=lead_verdict(summary) if lead else None,
        )
