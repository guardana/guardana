from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_LLM03_2026, OWASP_MCP02_2025
from guardana.core.trace import Trace
from guardana.rules.trace._base import TraceRule


class ConsentScopeExceededRule(TraceRule):
    """A hop exercised a scope the client was never granted.

    Consent is recorded **per client**, not per user, and that is the distinction the
    MCP work paid for: the confused deputy works because a decision recorded against a
    user gets read as a decision about a client. A model keyed on the subject cannot
    express the bug, so this reads the grant by client and the exercise by hop.

    A scope in use with no matching grant is privilege nobody agreed to — the escalation
    OWASP calls scope creep, seen from the inside rather than inferred from what a
    server advertises.
    """

    meta = RuleMeta(
        id="guardana.trace.consent_scope_exceeded",
        title="A scope was exercised that no consent record granted",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_MCP02_2025, OWASP_ASI03_2026, OWASP_LLM03_2026),
        required_capabilities=frozenset({Capability.READ_TRACE, Capability.READ_CONSENT}),
    )

    claim = "whether an ungranted scope was exercised is not established"

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Compare exercised scopes against granted ones, declining where a grant is silent.

        A consent that says nothing about its scopes makes "this scope was never granted"
        unprovable for that client, so the rule declines by name for it rather than
        treating an unrecorded grant as a grant of nothing. A grant of `()` is different
        and is believed: it says the client was granted no scopes, and a hop exercising
        one then is a finding.
        """
        granted, silent = self._grants(trace)
        if not granted:
            return
        if silent:
            yield self.unverified(
                trace,
                f"the consent record(s) for {', '.join(sorted(silent))} do not say which "
                f"scopes were granted, so {self.claim} for them",
            )
        for span in trace.spans:
            for hop in span.delegations:
                if hop.scopes is None or hop.actor in silent or hop.actor not in granted:
                    continue
                allowed = granted[hop.actor]
                exceeded = sorted(set(hop.scopes) - allowed)
                if not exceeded:
                    continue
                yield self.finding(
                    trace,
                    f"{hop.actor} exercised scope(s) {', '.join(exceeded)} across "
                    f"{hop.boundary!r} in span {span.span_id}, and the consent recorded for "
                    f"that client grants "
                    f"{', '.join(sorted(allowed)) if allowed else 'nothing'}",
                    span=span,
                )

    def _grants(self, trace: Trace) -> tuple[dict[str, set[str]], set[str]]:
        """Collect what each client was granted, and which clients' grants stayed silent.

        A refused consent contributes no scopes but still registers the client, so a hop
        by a client whose only consent was a refusal is compared against nothing —
        which is what makes the refusal mean something. One silent record poisons that
        client for the whole trace, because it is enough to make the absence unprovable.
        """
        granted: dict[str, set[str]] = {}
        silent: set[str] = set()
        for span in trace.spans:
            for consent in span.consents:
                granted.setdefault(consent.client, set())
                if not consent.granted:
                    continue
                if consent.scopes is None:
                    silent.add(consent.client)
                else:
                    granted[consent.client].update(consent.scopes)
        return granted, silent
