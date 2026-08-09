from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import OWASP_ASI03_2026, OWASP_MCP07_2025
from guardana.core.trace import Trace
from guardana.rules.trace._base import TraceRule


class SessionAsIdentityRule(TraceRule):
    """A step that changed something identified itself with a session and nothing else.

    > MCP Servers **MUST NOT** use sessions for authentication.

    It is not an MCP-only mistake, and a trace is where it becomes visible on any
    protocol: a session id says which connection this is, never who it belongs to.
    Anything that guesses or steals the id inherits whatever the session could do.

    Deliberately silent on a read-only step. An unauthenticated read is a different
    question with its own answer, and firing on every recorded read would bury the case
    where an unidentified caller *changed* something.
    """

    meta = RuleMeta(
        id="guardana.trace.session_as_identity",
        title="A state-changing step was identified by a session rather than a credential",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_MCP07_2025, OWASP_ASI03_2026),
        required_capabilities=frozenset({Capability.READ_TRACE, Capability.READ_IDENTITY}),
    )

    claim = "whether a state-changing step was authenticated is not established"

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Find spans that changed something while carrying only a session reference.

        `changes_something` is conservative on purpose: an executed side effect, or a
        tool the producer stated mutates. A tool whose mutation is unknown does not
        count, because guessing from its name would put this verdict on a heuristic
        nobody measured.
        """
        for span in trace.spans:
            identity = span.identity
            if identity is None or not identity.is_session_only:
                continue
            if not span.changes_something():
                continue
            session = identity.session
            protocol = f" ({session.protocol})" if session is not None and session.protocol else ""
            yield self.finding(
                trace,
                f"span {span.span_id} changed something while presenting only a session id"
                f"{protocol} — a session says which connection this is, never who it belongs "
                f"to, so anything holding the id inherits what the session could do",
                span=span,
            )
