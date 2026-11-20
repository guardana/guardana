from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import replace
from typing import ClassVar, Literal

from guardana.core.assessment import case_id_for, from_verdict
from guardana.core.evaluator.base import Verdict
from guardana.core.report import CoverageShortfall, Evidence, Finding, ShortfallKind
from guardana.core.rule import NotApplicable, Rule, RuleContext, RuleMeta
from guardana.core.rule.errors import RuleError
from guardana.core.rule.fixture import DeclaredFixture, FixtureOutcome, RuleFixture, materialise
from guardana.core.safety import Detection, Impact
from guardana.core.severity import Severity
from guardana.core.target import (
    AccessAnswer,
    AccessReply,
    Capability,
    EndpointTarget,
    InferenceAccessCheck,
    Target,
    TargetKind,
)
from guardana.core.target.endpoint import ACCESS_CHECK_PROMPT
from guardana.core.taxonomy import ATLAS_T0040, OWASP_LLM06_2026, OWASP_LLM10_2025
from guardana.core.testing import ScriptedAccessTransport

_CONFIDENCE = 1.0
_ANONYMOUS = "the request with no credential"
_CONTROL = "the request with the configured key"
_COMPLETED = AccessReply(AccessAnswer.COMPLETION, 200, "answered with a chat completion")


class UnauthenticatedInferenceRule(Rule):
    """A chat completions route that runs the model for a caller presenting no credential.

    Runs only when the operator asks for it (`probe --require-auth`). The route gets one
    short request with no credential and, only when that request is refused with 401 or
    403, the same request with the configured key. A completion to the first request is a
    finding. A refusal of the first and a completion to the second is a pass. Anything
    else proves neither, and the run that demanded the check ends `indeterminate`.

    Critical wherever the route is: whoever reaches it runs the model at the operator's
    cost. A loopback or private address is named in the finding and does not lower it.
    """

    meta = RuleMeta(
        id="guardana.endpoint.unauthenticated_inference",
        title="Chat route returns a completion to a caller without a credential",
        severity=Severity.CRITICAL,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(OWASP_LLM10_2025, OWASP_LLM06_2026, ATLAS_T0040),
        required_capabilities=frozenset({Capability.CHAT, Capability.INFERENCE_ACCESS}),
        impact=Impact.ACTIVE,
        detection=Detection.INVARIANT,
    )

    deterministic: ClassVar[bool] = True

    @property
    def estimated_requests(self) -> int:
        """The request with no credential and, after a refusal, the one with the key."""
        return 2

    @property
    def graded_verdicts(self) -> Mapping[str, int]:
        """Empty: the target classifies each answer and this rule decides, asking no evaluator."""
        return {}

    def fixtures(self) -> Iterable[RuleFixture]:
        """Sample a route answering anybody, one checking the key, and one refusing the key."""
        return materialise(
            (
                DeclaredFixture(
                    "a route that answers a request carrying no credential",
                    FixtureOutcome.FINDING,
                    lambda: _route(_COMPLETED),
                ),
                DeclaredFixture(
                    "a route that refuses no credential and answers the configured key",
                    FixtureOutcome.CLEAN,
                    lambda: _route(_refused(401)),
                ),
                DeclaredFixture(
                    "a route that refuses the configured key as well",
                    FixtureOutcome.INCONCLUSIVE,
                    lambda: _route(_refused(401), _refused(403)),
                ),
            )
        )

    def finding(self, ref: str, verdict: Verdict, detail: str) -> Finding:
        """Report a verdict on the route `ref` names, with the account of its requests."""
        return Finding(
            rule_id=self.meta.id,
            severity=self.meta.severity,
            title=self.meta.title,
            taxonomy=self.meta.taxonomy,
            target_ref=ref,
            evidence=Evidence(summary=verdict.rationale, detail=detail),
            verdict=verdict,
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterator[Finding]:
        """Ask with no credential; ask with the key only after a refusal; decide from both."""
        if not isinstance(target, InferenceAccessCheck):
            # Unreachable while the capability contract holds: a target declaring
            # `inference_access` without its surface is refused before any rule runs.
            raise RuleError(f"{self.meta.id} needs a target that can send an access check")
        if Capability.INFERENCE_ACCESS not in target.capabilities():
            raise NotApplicable("the run did not ask for an access check")
        case = _Case(self, ctx, target.ref, target.access_route)
        anonymous = target.check_access(credentials=False)
        if anonymous.answer is AccessAnswer.COMPLETION:
            summary = (
                "the route returned a chat completion to a request without a credential, "
                "allowing callers who can reach it to run the model"
            )
            if target.access_route_is_local:
                summary += "; the route's address is loopback or private"
            yield case.finding(case.decided("fail", summary, anonymous))
            return
        if anonymous.answer is not AccessAnswer.REFUSED:
            yield case.undecided(_settled_nothing(_ANONYMOUS, anonymous), anonymous)
            return
        control = target.check_access(credentials=True)
        if control.answer is AccessAnswer.COMPLETION:
            summary = (
                "the route refused the request without a credential and returned a chat "
                "completion to the same request with the configured key"
            )
            case.decided("pass", summary, anonymous, control)
            return
        if control.answer is AccessAnswer.REFUSED:
            why = (
                f"{_CONTROL} was also {control.reason}, leaving the authentication check "
                f"inconclusive"
            )
        else:
            why = (
                f"{_settled_nothing(_CONTROL, control)}, leaving it unclear whether the "
                f"first refusal was due to a missing credential"
            )
        yield case.undecided(why, anonymous, control)


class _Case:
    """The one case a run of the rule grades: recorded once, with every request it sent."""

    def __init__(
        self, rule: UnauthenticatedInferenceRule, ctx: RuleContext, ref: str, route: str
    ) -> None:
        self._rule = rule
        self._ctx = ctx
        self._ref = ref
        self._route = route

    def decided(
        self, outcome: Literal["pass", "fail"], summary: str, *legs: AccessReply
    ) -> tuple[Verdict, str]:
        """Record a pass or a fail; return its verdict and the account of the requests."""
        return self._record(Verdict(outcome, _CONFIDENCE, summary, self._rule.meta.id), legs)

    def undecided(self, why: str, *legs: AccessReply) -> Finding:
        """Record that nothing was decided: a shortfall with no switch, and the verdict."""
        rule_id = self._rule.meta.id
        self._ctx.shortfall(CoverageShortfall(ShortfallKind.DEMANDED_CHECK, rule_id, why))
        return self.finding(self._record(Verdict("inconclusive", 0.0, why, rule_id), legs))

    def finding(self, graded: tuple[Verdict, str]) -> Finding:
        """Report a verdict with the account of the requests it was read from."""
        verdict, detail = graded
        return self._rule.finding(self._ref, verdict, detail)

    def _record(self, verdict: Verdict, legs: Sequence[AccessReply]) -> tuple[Verdict, str]:
        detail = _account(self._route, legs)
        self._ctx.record(
            from_verdict(
                replace(verdict, rationale=f"{verdict.rationale} ({detail})"),
                case_id=case_id_for(self._rule.meta.id, ACCESS_CHECK_PROMPT),
                subject_ref=self._ref,
                rule_id=self._rule.meta.id,
                dataset=self._rule.digest(),
            )
        )
        return verdict, detail


def _settled_nothing(leg: str, reply: AccessReply) -> str:
    """Say why one request settled nothing: it was never sent, or the answer was not decisive."""
    if not reply.sent:
        return f"{leg} was not sent: {reply.reason}"
    return f"{leg} got no decisive answer: the route {reply.reason}"


def _account(route: str, legs: Sequence[AccessReply]) -> str:
    """Name the route, what each request got, how many were sent, and through what."""
    sent = [leg for leg in legs if leg.sent]
    parts = [f"route {route}"]
    for name, leg in zip(("no credential", "configured key"), legs, strict=False):
        parts.append(f"{name}: {leg.reason if leg.sent else 'not sent'}")
    parts.append(f"{len(sent)} request(s) sent")
    parts.append("through a proxy" if any(leg.via_proxy for leg in sent) else "no proxy")
    return "; ".join(parts)


def _refused(status: int) -> AccessReply:
    return AccessReply(AccessAnswer.REFUSED, status, f"refused with HTTP {status}")


def _route(anonymous: AccessReply, credentialed: AccessReply = _COMPLETED) -> Target:
    """Build a route that answers as scripted, asked for the check, reaching no host."""
    return EndpointTarget(
        "http://fixture.invalid",
        "fixture",
        api_key="fixture",
        transport=ScriptedAccessTransport(anonymous, credentialed),
        inference_access_check=True,
    )
