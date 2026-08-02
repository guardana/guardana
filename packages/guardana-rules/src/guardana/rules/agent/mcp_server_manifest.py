import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path

from guardana.core.evaluator.base import Verdict
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, McpServerTarget, McpTool, Target, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0084_001,
    ATLAS_T0109,
    ATLAS_T0110,
    OWASP_ASI04,
    OWASP_LLM01,
    OWASP_LLM03,
)
from guardana.rules.prompt._injection_markers import OVERRIDE_PHRASE, has_hidden_char

PIN_SCHEMA_VERSION = 1


def pin_document(server: str, tools: Iterable[McpTool]) -> dict[str, object]:
    """Build the approved-manifest document for a server's current tool list.

    Descriptions are stored as digests rather than text: the pin records *that*
    the wording was approved, and a repository full of tool prose invites editing
    the record instead of re-reviewing the change.
    """
    return {
        "schema_version": PIN_SCHEMA_VERSION,
        "server": server,
        "tools": {tool.name: _digest(tool.description) for tool in sorted(tools, key=_name)},
    }


class McpServerManifestRule(Rule):
    """Reads a live MCP server's tool manifest: hidden instructions, and drift from the pin.

    A tool description is fed to the agent's model as trusted context, so an
    instruction hidden in one is indirect prompt injection with an audience of
    one. Reading it from a file catches that before adoption; reading it from the
    running server is what catches a description changed *after* adoption — the
    shape of a rug pull, and the reason `AML.T0109` exists.

    Without an approved manifest to compare against, drift cannot be detected at
    all. That is reported as `inconclusive`, never as a clean server: "nothing
    changed" and "we have no idea whether anything changed" are different answers.
    """

    meta = RuleMeta(
        id="guardana.agent.mcp_server_manifest",
        title="Live MCP tool manifest carries a hidden instruction or has drifted",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_LLM01, OWASP_LLM03, OWASP_ASI04, ATLAS_T0110, ATLAS_T0109, ATLAS_T0084_001),
        required_capabilities=frozenset({Capability.LIST_TOOLS}),
        impact=Impact.ACTIVE,
    )

    @property
    def estimated_requests(self) -> int:
        """One manifest listing. Reading what a server advertises costs no model call."""
        return 1

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Fetch the live manifest, scan every description, and compare it with the pin."""
        if not isinstance(target, McpServerTarget):
            return
        tools = target.list_tools()
        yield from self._poisoned(target.ref, tools)
        yield from self._drifted(target.ref, tools, ctx)

    def _poisoned(self, ref: str, tools: tuple[McpTool, ...]) -> Iterator[Finding]:
        for tool in tools:
            if has_hidden_char(tool.description):
                yield self._finding(
                    ref, f"invisible/hidden Unicode in the description of {tool.name!r}"
                )
            if OVERRIDE_PHRASE.search(tool.description):
                yield self._finding(
                    ref, f"instruction-override phrase in the description of {tool.name!r}"
                )

    def _drifted(self, ref: str, tools: tuple[McpTool, ...], ctx: RuleContext) -> Iterator[Finding]:
        pin_path = ctx.get("pin", None)
        if not isinstance(pin_path, str) or not pin_path:
            yield self._unverified(
                ref,
                "no approved manifest is pinned, so a description changed after adoption "
                "cannot be detected; write one with `guardana probe --mcp … --write-mcp-pin`",
            )
            return
        try:
            pinned = _load_pin(Path(pin_path))
        except (OSError, ValueError) as exc:
            yield self._unverified(ref, f"the pinned manifest at {pin_path} is unusable: {exc}")
            return
        live = {tool.name: _digest(tool.description) for tool in tools}
        for name, digest in sorted(pinned.items()):
            if name not in live:
                yield self._finding(
                    ref, f"tool {name!r} was approved but the server no longer offers it"
                )
            elif live[name] != digest:
                yield self._finding(
                    ref,
                    f"the description of {name!r} changed after it was approved (rug pull)",
                    severity=Severity.CRITICAL,
                )
        for name in sorted(set(live) - set(pinned)):
            yield self._finding(ref, f"tool {name!r} appeared after the manifest was approved")

    def _finding(self, ref: str, summary: str, severity: Severity | None = None) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=severity or self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=ref,
            evidence=Evidence(summary=summary, detail=f"server={ref}"),
        )

    def _unverified(self, ref: str, why: str) -> Finding:
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=ref,
            evidence=Evidence(summary=why, detail=f"server={ref}"),
            verdict=Verdict("inconclusive", 0.0, why, self.meta.id),
        )


def _load_pin(path: Path) -> Mapping[str, str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        # ValueError, not TypeError: every caller treats an unusable pin as "the
        # comparison could not run", and a second exception type would only add a
        # way to forget one of them.
        raise ValueError("a pinned manifest must be a JSON object")  # noqa: TRY004
    version = document.get("schema_version")
    if version != PIN_SCHEMA_VERSION:
        raise ValueError(f"unsupported pin schema_version {version!r}")
    tools = document.get("tools")
    if not isinstance(tools, dict):
        raise ValueError("a pinned manifest needs a 'tools' object")  # noqa: TRY004
    return {name: digest for name, digest in tools.items() if isinstance(digest, str)}


def _digest(description: str) -> str:
    return hashlib.sha256(description.encode("utf-8")).hexdigest()


def _name(tool: McpTool) -> str:
    return tool.name
