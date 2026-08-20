"""What every trace rule shares: one parsed trace, and two ways to speak.

The parse is bought by the target and read here. The two ways to speak are a
finding — *this invariant does not hold in this recorded execution* — and an
unverified verdict — *this question could not be answered, and here is why*. There
is deliberately no third way, because silence has to keep meaning "the invariant
held".

The dimension a rule needs is a *capability*, so the runner skips the rule before it
runs and records the reason. That is what stops the most dangerous inference a trace
invites: a producer that does not emit approvals must not have its silence read as
"nothing was approved". See `docs/design/trace-domain-model.md`.
"""

from abc import abstractmethod
from collections.abc import Iterable, Iterator

from guardana.core.evaluator.base import Verdict
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext
from guardana.core.severity import Severity
from guardana.core.target import Target
from guardana.core.target.protocols import TraceReader
from guardana.core.trace import Span, Trace


class TraceRule(Rule):
    """A rule that grades one invariant over an execution somebody else recorded.

    Subclasses implement `examine` and read nothing but the trace: the file was read
    once, before any rule ran, and every rule shares that parse.
    """

    claim = "this check could not be made"
    """What this rule would have established, phrased to follow "so …" in a sentence."""

    @property
    def estimated_requests(self) -> int | None:
        """Zero: reading a recorded execution sends nothing anywhere.

        Stated rather than left unknown, because `plan` prints "plus N rules of
        unknown cost" and a rule that provably costs nothing should not be in that
        number.
        """
        return 0

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Grade the trace, and decline rather than pass over a trace read in part.

        A rule that **found** something reports it — the evidence is real, and neither
        a cut nor an unparseable record can un-happen it. A rule that found nothing
        declines, because the step it needed may have been in the part that is missing.

        Two ways a file is read in part, and they are different facts. `truncated` is
        the producer or the reader saying where it stopped. `unreadable` is a record
        that arrived and could not be interpreted — a line torn off by a crashed
        producer, or one over a ceiling — which leaves `truncated` empty and the file
        just as partial.

        The type check is the belt to the capability's braces, and it returns rather
        than asserting because an `assert` vanishes under `python -O`.
        """
        if not isinstance(target, TraceReader):
            return
        trace = target.trace
        found = list(self.examine(trace))
        yield from found
        if found:
            return
        if trace.truncated is not None:
            yield self.unverified(
                trace,
                f"the trace is incomplete ({trace.truncated}), so {self.claim}",
            )
        elif trace.unreadable:
            yield self.unverified(
                trace,
                f"this build could not read {trace.unreadable} record(s) of the trace, "
                f"so {self.claim}",
            )

    @abstractmethod
    def examine(self, trace: Trace) -> Iterator[Finding]:
        """Grade the recorded execution, yielding a finding or an unverified verdict per claim."""

    def finding(
        self,
        trace: Trace,
        summary: str,
        *,
        span: Span | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        """Report that the invariant this rule tests does not hold in this execution."""
        return Finding(
            rule_id=self.meta.id,
            severity=severity or self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=self._ref(trace, span),
            evidence=Evidence(summary=summary, detail=self._detail(trace, span)),
        )

    def unverified(self, trace: Trace, why: str, *, span: Span | None = None) -> Finding:
        """Report that the question could not be answered, which is never a pass."""
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=self._ref(trace, span),
            evidence=Evidence(summary=why, detail=self._detail(trace, span)),
            verdict=Verdict("inconclusive", 0.0, why, self.meta.id),
        )

    def _ref(self, trace: Trace, span: Span | None) -> str:
        """Point at the span rather than the file when there is one to point at.

        A finding fingerprint drops the line number from a file reference but keeps the
        path, so naming the span is what lets a baseline waive *this* step of *this*
        trace rather than everything the file contains.
        """
        base = f"{trace.provenance.source}#{trace.trace_id}"
        return f"{base}/{span.span_id}" if span is not None else base

    def _detail(self, trace: Trace, span: Span | None) -> str:
        lines = [f"trace: {trace.provenance.describe()}"]
        if span is not None:
            lines.append(span.render())
        return "\n".join(lines)
