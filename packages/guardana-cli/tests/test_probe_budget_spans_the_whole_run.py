"""A request ceiling bounds the probe, not each of the passes it happens to take.

`probe` runs a canary rule in a pass of its own, against a target whose system
prompt carries that rule's marker — otherwise the rule has nothing to observe. Each
pass used to build its own target, and a target owns the meter that enforces the
ceiling, so `--max-requests 200` bought 200 requests *per pass* and the real
ceiling was 200 times however many canary rules happened to be installed.

That is the failure the budget exists to prevent, in the direction that costs
money: the number in the plan and the number on the invoice were different, and
adding a canary rule silently raised the second one.
"""

from collections.abc import Iterable, Sequence

from guardana.cli import _endpoint
from guardana.cli._probe_run import Connection, run_probe
from guardana.core.budget import Budgets
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding, StopReason
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.severity import Severity
from guardana.core.target import Capability, ChatMessage, EndpointTarget, Target, TargetKind

_CEILING = 4


class _CountingTransport:
    """Counts every request the whole probe sends, across every target it builds."""

    sent = 0

    def send(
        self,
        base_url: str,
        model: str,
        messages: Sequence[ChatMessage],
        api_key: str | None,
    ) -> str:
        type(self).sent += 1
        return "sure, here you go"


class _Chatty(Rule):
    """Sends more requests than any ceiling under test, so the ceiling is what stops it."""

    _CANARY: str | None = None

    def __init__(self, rule_id: str, *, plants_a_canary: bool) -> None:
        capabilities = {Capability.CHAT}
        if plants_a_canary:
            capabilities.add(Capability.PLANT_SYSTEM_PROMPT)
        self.meta = RuleMeta(
            rule_id,
            "chatty",
            Severity.HIGH,
            TargetKind.ENDPOINT,
            required_capabilities=frozenset(capabilities),
        )
        self._plants_a_canary = plants_a_canary

    def with_canary(self, canary: str) -> "Rule | None":
        if not self._plants_a_canary:
            return None
        planted = _Chatty(self.meta.id, plants_a_canary=True)
        planted._CANARY = canary
        return planted

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        if not isinstance(target, EndpointTarget):
            return
        for _ in range(100):
            target.chat([ChatMessage(role="user", content="hello")])
        yield Finding(self.meta.id, self.meta.severity, "chatty", (), target.ref, Evidence("spoke"))


def _registry() -> Registry:
    registry = Registry()
    registry.register_rule(_Chatty("acme.test.plain", plants_a_canary=False))
    registry.register_rule(_Chatty("acme.test.canary_one", plants_a_canary=True))
    registry.register_rule(_Chatty("acme.test.canary_two", plants_a_canary=True))
    return registry


def test_the_request_ceiling_bounds_every_pass_of_one_probe_together() -> None:
    _CountingTransport.sent = 0
    _endpoint.transport_factory = _CountingTransport
    try:
        result = run_probe(
            _registry(),
            Profile(name="t", policy=Policy(), budgets=Budgets(max_requests=_CEILING)),
            Connection(url="http://model.invalid", model="m"),
        )
    finally:
        _endpoint.transport_factory = None

    assert _CountingTransport.sent <= _CEILING, (
        f"the probe sent {_CountingTransport.sent} requests under a ceiling of {_CEILING} "
        f"— three passes, three ceilings"
    )
    assert result.result.stopped_by is StopReason.BUDGET_EXHAUSTED


def test_the_manifest_reports_what_the_whole_probe_spent_exactly_once() -> None:
    """The bill is the run's, not the sum of overlapping snapshots of one meter."""
    _CountingTransport.sent = 0
    _endpoint.transport_factory = _CountingTransport
    try:
        result = run_probe(
            _registry(),
            Profile(name="t", policy=Policy(), budgets=Budgets(max_requests=_CEILING)),
            Connection(url="http://model.invalid", model="m"),
        )
    finally:
        _endpoint.transport_factory = None

    assert result.result.usage is not None
    assert result.result.usage.requests == _CountingTransport.sent
