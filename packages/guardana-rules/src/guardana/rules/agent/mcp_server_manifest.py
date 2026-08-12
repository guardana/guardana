import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

from guardana.core.evaluator.base import Verdict
from guardana.core.fingerprint import digest_of
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, McpServerTarget, McpTool, Target, TargetKind
from guardana.core.taxonomy import (
    ATLAS_T0084_001,
    ATLAS_T0109,
    ATLAS_T0110,
    OWASP_ASI04_2026,
    OWASP_LLM01_2025,
    OWASP_LLM01_2026,
    OWASP_LLM03_2025,
    OWASP_LLM04_2026,
    OWASP_MCP03_2025,
    OWASP_MCP04_2025,
    OWASP_MCP10_2025,
)
from guardana.rules.prompt._injection_markers import OVERRIDE_PHRASE, has_hidden_char

PIN_SCHEMA_VERSION = 2
_DESCRIPTIONS_ONLY = 1

_V1_COVERAGE = (
    "the pinned manifest is schema_version 1, which records tool descriptions and "
    "nothing else — a widened parameter or a rewritten property description would not "
    "be detected. Re-approve with `--write-mcp-pin` to cover the whole declaration"
)


def pin_document(server: str, tools: Iterable[McpTool]) -> dict[str, object]:
    """Build the approved-manifest document for a server's current tool list.

    Declarations are stored as digests rather than text: the pin records *that*
    the manifest was approved, and a repository full of tool prose invites editing
    the record instead of re-reviewing the change.

    The digest covers the whole declaration — schemas and annotations included —
    because a tool whose prose is untouched while its input schema gains a
    parameter is a tool that can now be asked to do something nobody approved.
    """
    return {
        "schema_version": PIN_SCHEMA_VERSION,
        "server": server,
        "tools": {tool.name: declaration_digest(tool) for tool in sorted(tools, key=_name)},
    }


def declaration_digest(tool: McpTool) -> str:
    """Digest everything a server declared about one tool, canonically ordered."""
    return digest_of(json.dumps(tool.declaration(), sort_keys=True, ensure_ascii=False))


@dataclass(frozen=True, slots=True)
class _Pin:
    """An approved manifest as read from disk, and how much of a tool it covers."""

    version: int
    tools: Mapping[str, str]
    server: str | None
    """Which server this manifest was approved for, as the pin records it.

    Read rather than discarded, because a pin compared against the wrong server is
    the one input that makes every verdict this rule produces meaningless — and
    silently so. Two servers with overlapping tool names compare clean against each
    other's pin, which is a rug-pull check reporting "nothing changed" about a
    server nobody ever approved.
    """

    def digest_of_tool(self, tool: McpTool) -> str:
        """Digest a live tool the same way this pin's version recorded it."""
        if self.version == _DESCRIPTIONS_ONLY:
            return _legacy_digest(tool.description)
        return declaration_digest(tool)

    def describes(self, ref: str) -> str | None:
        """Say why this pin cannot speak for `ref`, or `None` when it can.

        A pin that names no server is refused rather than assumed to match: every
        pin Guardana has ever written records one, so an absent name means the file
        was hand-made or edited, and "assume it is the right one" is the reading
        that turns this check into a rubber stamp.
        """
        if self.server is None:
            return (
                "the pinned manifest does not say which server it was approved for, so "
                "it cannot be told apart from another server's pin — re-approve with "
                "`guardana probe --mcp … --write-mcp-pin`"
            )
        if self.server != ref:
            return (
                f"the pinned manifest was approved for {self.server!r} and this run "
                f"probed {ref!r}, so drift cannot be compared — point --mcp-pin at this "
                f"server's approved manifest"
            )
        return None


class McpServerManifestRule(Rule):
    """Reads a live MCP server's tool manifest: hidden instructions, and drift from the pin.

    A tool description is fed to the agent's model as trusted context, so an
    instruction hidden in one is indirect prompt injection with an audience of
    one. Reading it from a file catches that before adoption; reading it from the
    running server is what catches a description changed *after* adoption — the
    shape of a rug pull, and the reason `AML.T0109` exists.

    The declaration is more than its prose. A property description inside an input
    schema is read by the model exactly like the tool description, and a parameter
    widened without a word of the prose changing is drift a description digest
    cannot see — so both the marker scan and the pin cover the whole declaration.

    Without an approved manifest to compare against, drift cannot be detected at
    all. That is reported as `inconclusive`, never as a clean server: "nothing
    changed" and "we have no idea whether anything changed" are different answers.
    """

    meta = RuleMeta(
        id="guardana.agent.mcp_server_manifest",
        title="Live MCP tool manifest carries a hidden instruction or has drifted",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(
            OWASP_LLM01_2025,
            OWASP_LLM01_2026,
            OWASP_LLM03_2025,
            OWASP_LLM04_2026,
            OWASP_ASI04_2026,
            OWASP_MCP03_2025,
            OWASP_MCP04_2025,
            OWASP_MCP10_2025,
            ATLAS_T0110,
            ATLAS_T0109,
            ATLAS_T0084_001,
        ),
        required_capabilities=frozenset({Capability.LIST_TOOLS}),
        impact=Impact.ACTIVE,
    )

    @property
    def estimated_requests(self) -> int:
        """Three: the discovery probe, the handshake it may fall back to, and the listing.

        It said one until the meter was fixed and started counting the `initialize`
        that always went with it. The declaration and the meter were wrong in the
        same direction, which is why the test comparing them stayed green.

        The third is which era the server speaks, asked once and shared with every
        other rule. A modern server needs no handshake and costs two.
        """
        return 3

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Fetch the live manifest, scan every declaration, and compare it with the pin."""
        if not isinstance(target, McpServerTarget):
            return
        tools = target.list_tools()
        yield from self._poisoned(target.ref, tools)
        yield from self._drifted(target.ref, tools, ctx)

    def _poisoned(self, ref: str, tools: tuple[McpTool, ...]) -> Iterator[Finding]:
        for tool in tools:
            for where, text in _readable_text(tool):
                if has_hidden_char(text):
                    yield self._finding(ref, f"invisible/hidden Unicode in {where}")
                if OVERRIDE_PHRASE.search(text):
                    yield self._finding(ref, f"instruction-override phrase in {where}")

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
        mismatch = pinned.describes(ref)
        if mismatch is not None:
            # Never a finding: the server may be perfectly intact, and saying it
            # drifted on the strength of somebody else's approved manifest would be
            # a confident answer to a question this run cannot ask.
            yield self._unverified(ref, mismatch)
            return
        if pinned.version == _DESCRIPTIONS_ONLY:
            # An older pin still compares, and still says what it cannot compare.
            # Reading it silently would report "no drift" about schemas nobody
            # recorded, which is the shape of a false green.
            yield self._unverified(ref, _V1_COVERAGE)
        live = {tool.name: pinned.digest_of_tool(tool) for tool in tools}
        for name, digest in sorted(pinned.tools.items()):
            if name not in live:
                yield self._finding(
                    ref, f"tool {name!r} was approved but the server no longer offers it"
                )
            elif live[name] != digest:
                yield self._finding(
                    ref,
                    f"the declaration of {name!r} changed after it was approved (rug pull)",
                    severity=Severity.CRITICAL,
                )
        for name in sorted(set(live) - set(pinned.tools)):
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


def _readable_text(tool: McpTool) -> Iterator[tuple[str, str]]:
    """Yield every string a model will read out of one tool declaration, with where it sits.

    Schemas included, and keys as well as values: a property *named* with an
    invisible character is as much a smuggled instruction as one described with
    it, and the model is shown both.
    """
    yield f"the description of {tool.name!r}", tool.description
    if tool.title:
        yield f"the title of {tool.name!r}", tool.title
    for label, block in (
        ("input schema", tool.input_schema),
        ("output schema", tool.output_schema),
        ("annotations", tool.annotations),
    ):
        yield from _strings(block, f"{label} of {tool.name!r}")


def _strings(value: object, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                yield f"{path} (key {key!r})", key
            yield from _strings(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}[{index}]")


def _load_pin(path: Path) -> _Pin:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        # ValueError, not TypeError: every caller treats an unusable pin as "the
        # comparison could not run", and a second exception type would only add a
        # way to forget one of them.
        raise ValueError("a pinned manifest must be a JSON object")  # noqa: TRY004
    version = document.get("schema_version")
    if version not in (_DESCRIPTIONS_ONLY, PIN_SCHEMA_VERSION):
        raise ValueError(f"unsupported pin schema_version {version!r}")
    tools = document.get("tools")
    if not isinstance(tools, dict):
        raise ValueError("a pinned manifest needs a 'tools' object")  # noqa: TRY004
    server = document.get("server")
    return _Pin(
        version=version,
        tools={name: digest for name, digest in tools.items() if isinstance(digest, str)},
        server=server if isinstance(server, str) and server else None,
    )


def _legacy_digest(description: str) -> str:
    """Reproduce a schema_version 1 digest, so an older pin still compares."""
    return hashlib.sha256(description.encode("utf-8")).hexdigest()


def _name(tool: McpTool) -> str:
    return tool.name
