from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.safety import Impact
from guardana.core.severity import Severity
from guardana.core.target import Capability, McpAuthorizationView, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_LLM02_2026, OWASP_MCP01_2025
from guardana.rules.mcp._base import McpAuthorizationRule


class McpDiscoveryTargetRule(McpAuthorizationRule):
    """An MCP server that points its client at an address a client must not follow.

    Authorization discovery is the one place in MCP where the server chooses a URL
    and the client fetches it, which makes it a server-side request forgery
    primitive aimed at whoever is running the client. The specification names the
    destinations: cloud metadata at `169.254.169.254`, where a fetch returns
    credentials; internal services on a loopback port; `javascript:` and `file:`
    schemes, where a URL is opened rather than fetched; and plain `http://` for an
    authorization endpoint that **MUST** be served over HTTPS.

    The check and the guard are the same code path, and that is the point. Guardana
    refuses to fetch such an address, and **the refusal is the finding** — a
    scanner that followed the URL to prove it was dangerous would have performed
    the attack in order to report it, which is the confused deputy this whole area
    is about.

    Loopback and private addresses are refused only when the server under test is
    itself somewhere else. A development server on `127.0.0.1` pointing at an
    authorization server on `127.0.0.1` is a normal setup, and reporting it would
    make this rule noise on the first machine anybody tries it on.
    """

    meta = RuleMeta(
        id="guardana.mcp.discovery_target",
        title="MCP server directs its client to an address a client must not follow",
        severity=Severity.HIGH,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_MCP01_2025, OWASP_LLM02_2026, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.INSPECT_AUTHORIZATION}),
        impact=Impact.ACTIVE,
    )

    claim = "the addresses it directs a client to were never seen"

    @property
    def estimated_requests(self) -> int:
        """The discovery probe, the anonymous pair, then the documented attempts per document."""
        return 9

    def examine(self, view: McpAuthorizationView) -> Iterator[Finding]:
        """Report every discovery address this run refused to fetch, and why."""
        blocked = self.unreachable(view)
        if blocked is not None:
            yield blocked
            return
        for document in view.refused_addresses:
            yield self.finding(
                view,
                f"the server directed this client to {document.url} during authorization "
                f"discovery, which was not fetched because {document.refused}",
            )
