from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_LLM03_2026, OWASP_MCP01_2025
from guardana.core.trace import Delegation, Trace
from guardana.rules.trace._base import TraceRule

_HOPS_NEEDED_TO_COMPARE = 2
"""One hop cannot cross two boundaries, so a single credentialed hop is not evidence."""


class CredentialPassthroughRule(TraceRule):
    """One credential crossing two trust boundaries — the confused deputy, proven.

    The token a service receives and the token it presents upstream must be different
    tokens. When they are the same one, the upstream service reads the caller's
    credential as its own client's, which is what the MCP specification forbids as
    token passthrough and what OAuth calls a confused deputy.

    Step two deferred this check with a stated reason: it happens between a server and
    a service Guardana is not talking to, and no sequence of client requests makes it
    observable. In a trace it *is* observable, which is the point of the trace work —
    and it needs exactly the field a naive schema would have flattened, because a
    model with one credential per call cannot say that two hops carried the same one.
    """

    meta = RuleMeta(
        id="guardana.trace.credential_passthrough",
        title="A credential was presented across two different trust boundaries",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_MCP01_2025, OWASP_ASI03_2026, OWASP_LLM03_2026),
        required_capabilities=frozenset({Capability.READ_TRACE, Capability.READ_DELEGATION}),
    )

    claim = "whether one credential crossed two boundaries is not established"

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Compare every credentialed hop against every other, by digest.

        Only digests are compared, never values — `CredentialRef` has no field for a
        value. A hop whose credential nobody digested is not evidence of reuse and is
        skipped, which is the fail-closed direction: the alternative turns every
        two-hop trace into a finding.
        """
        hops: list[tuple[str, Delegation]] = [
            (span.span_id, delegation)
            for span in trace.spans
            for delegation in span.credentialed_delegations()
        ]
        if len(hops) < _HOPS_NEEDED_TO_COMPARE:
            return
        reported: set[tuple[str, ...]] = set()
        for index, (span_id, hop) in enumerate(hops):
            for other_span, other in hops[index + 1 :]:
                if not self._is_passthrough(hop, other):
                    continue
                key = (self._digest(hop), *sorted((hop.boundary, other.boundary)))
                if key in reported:
                    continue
                reported.add(key)
                yield self.finding(
                    trace,
                    f"the same credential ({hop.credential.kind if hop.credential else '?'}, "
                    f"digest {self._digest(hop)}) was presented across two trust boundaries: "
                    f"{hop.boundary!r} by {hop.actor} in span {span_id}, then "
                    f"{other.boundary!r} by {other.actor} in span {other_span} — the upstream "
                    f"service reads the caller's credential as its own client's",
                    span=trace.span(other_span),
                )

    def _is_passthrough(self, hop: Delegation, other: Delegation) -> bool:
        """Whether these two hops are the same credential across different boundaries.

        Different boundaries is the whole condition. The same credential used twice
        *within* one boundary is one client talking to one service twice, which is
        ordinary; carrying it across is the defect.
        """
        return (
            hop.credential is not None
            and other.credential is not None
            and hop.credential.is_same_as(other.credential)
            and hop.boundary != other.boundary
        )

    def _digest(self, hop: Delegation) -> str:
        return hop.credential.digest or "" if hop.credential is not None else ""
