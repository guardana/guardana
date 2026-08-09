from collections.abc import Iterator

from guardana.core.report import Finding
from guardana.core.rule import RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, TargetKind
from guardana.core.taxonomy import ATLAS_T0057, OWASP_ASI03_2026, OWASP_LLM02_2026
from guardana.core.trace import Span, Trace
from guardana.rules.trace._base import TraceRule

from guardana.rules._secrets import (  # isort: skip — shared with the two scanning rules
    ALLOWLIST,
    REPLY_SECRET_PATTERNS,
    redact,
)


class SecretInToolArgumentRule(TraceRule):
    """A credential travelled out of the conversation inside a tool argument.

    The one check here that works on a plain OpenTelemetry export, because it needs only
    what the conventions carry: tool calls and their arguments. An agent that puts an API
    key into `http_request(headers=…)` or a password into a shell command has moved a
    secret from wherever it was configured into somebody else's log — and in a trace it
    is already *in* a log, which is the point.

    Patterns are the ones the two secret-scanning rules use, so there is one definition
    of what a credential looks like. Precision over recall: no bare-entropy matching, and
    documentation fixtures are allowlisted, because a false positive here teaches people
    to switch the rule off.
    """

    meta = RuleMeta(
        id="guardana.trace.secret_in_tool_argument",
        title="A credential appeared in a recorded tool argument",
        severity=Severity.HIGH,
        target_kind=TargetKind.TRACE,
        taxonomy=(OWASP_LLM02_2026, OWASP_ASI03_2026, ATLAS_T0057),
        required_capabilities=frozenset({Capability.READ_TRACE, Capability.READ_TOOL_CALLS}),
    )

    claim = "whether a credential travelled in a tool argument is not established"

    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Scan every recorded tool argument, from the execution and from the message part.

        Both places, because they are different records of the same call and a producer may
        emit either: an `execute_tool` span carries the arguments as an attribute, while a
        chat span carries them inside an assistant message's `tool_call` part.
        """
        for span in trace.spans:
            for tool_name, arguments in self._arguments(span):
                for label, secret in self._secrets(arguments):
                    yield self.finding(
                        trace,
                        f"a {label} appears in the arguments of {tool_name} in span "
                        f"{span.span_id} ({redact(secret)}) — the credential is now in "
                        f"whatever holds this trace",
                        span=span,
                    )

    def _arguments(self, span: Span) -> Iterator[tuple[str, str]]:
        if span.tool is not None and span.tool.arguments:
            yield span.tool.name, span.tool.arguments
        for message in span.messages:
            for part in message.tool_calls():
                if part.arguments:
                    yield part.tool_name or "an unnamed tool", part.arguments

    def _secrets(self, text: str) -> Iterator[tuple[str, str]]:
        """Yield each credential-shaped match, skipping the public example values.

        The allowlist is the same one the file and reply scanners use: quoting AWS's
        canonical example key is citation, not leakage, and a rule that cannot tell the
        difference is a rule people exclude.
        """
        for label, pattern in REPLY_SECRET_PATTERNS:
            for match in pattern.finditer(text):
                found = match.group(0)
                if found not in ALLOWLIST:
                    yield label, found
