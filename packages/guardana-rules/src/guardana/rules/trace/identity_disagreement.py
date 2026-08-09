from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP01_2025
from guardana.core.trace import Trace
from guardana.rules.trace._base import TraceRule


class IdentityDisagreementRule(TraceRule):
    """A token's audience is not the resource it was presented to.

    Identity in a trace is three claims that can disagree: the credential the caller
    presented, the audience its token names, and the resource the callee says it is.
    Audience binding is the control that stops a token minted for one service being
    replayed against another, and it only works when those three agree.

    This is the distinction the MCP work established, written as a check. A schema with
    one `credential` field could not express it, which is why the model has three.
    """

    meta = RuleMeta(
        id="guardana.trace.identity_disagreement",
        title="A token was presented to a resource outside its audience",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_MCP01_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.READ_TRACE, Capability.READ_IDENTITY}),
    )

    claim = "whether a token was presented outside its audience is not established"

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Compare audience against claimed resource, and decline where either is absent.

        Two thirds of a disagreement is not a disagreement: a span recording an audience
        and no resource, or a resource and no audience, is skipped rather than reported.
        An empty audience means nobody wrote one down — which is the same fact as an
        absent claim, and not evidence of a mismatch.
        """
        for span in trace.spans:
            identity = span.identity
            credential = identity.credential if identity is not None else None
            resource = identity.claimed_resource if identity is not None else None
            if credential is None or resource is None or not credential.audience:
                continue
            if any(self._covers(audience, resource) for audience in credential.audience):
                continue
            yield self.finding(
                trace,
                f"the credential presented in span {span.span_id} names audience "
                f"{', '.join(credential.audience)} while the callee claims to be {resource} — "
                f"a token accepted outside its audience is a token that can be replayed from "
                f"one service against another",
                span=span,
            )

    def _covers(self, audience: str, resource: str) -> bool:
        """Whether an audience value names this resource.

        Compared after trimming a trailing slash, because `https://a/` and `https://a`
        are the same resource and an operator writing one of each is not a finding.
        Nothing looser than that: a prefix match would read `https://a.evil.test` as
        covered by `https://a`.
        """
        return audience.rstrip("/") == resource.rstrip("/")
