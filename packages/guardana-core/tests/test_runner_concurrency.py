"""Guards for running endpoint rules concurrently.

Dynamic rules are network-bound: each one waits on a served model, so running
them strictly one after another makes a probe as slow as the sum of its round
trips. Overlapping them is the single largest wall-clock win available — but only
if it changes nothing else, which is what these tests pin:

* the same report, in the same order, whichever rule finishes first;
* the concurrency limit is a limit, not a suggestion (a probe must not become a
  load test against someone's production model);
* a rule that raises is still recorded, and an unreachable endpoint still aborts
  the whole run rather than being reported per-rule.
"""

import threading
from collections.abc import Iterable
from urllib.error import URLError

from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Evidence, Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import ScriptedTransport

_RULE_COUNT = 6
_LIMIT = 3


class _Tracked(Rule):
    """A rule that reports how many of its peers were running alongside it."""

    peak = 0
    _live = 0
    _lock = threading.Lock()
    _gate = threading.Barrier(_LIMIT, timeout=5)

    def __init__(self, index: int, *, sync: bool) -> None:
        self._index = index
        self._sync = sync
        self.meta = RuleMeta(
            id=f"test.concurrency.rule{index:02d}",
            title=f"rule {index}",
            severity=Severity.LOW,
            target_kind=TargetKind.ENDPOINT,
            taxonomy=(),
            required_capabilities=frozenset({Capability.CHAT}),
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Record concurrent occupancy, then yield one finding naming this rule."""
        with _Tracked._lock:
            _Tracked._live += 1
            _Tracked.peak = max(_Tracked.peak, _Tracked._live)
        try:
            if self._sync:
                # Block until `_LIMIT` rules are inside at once: with a pool this
                # releases, and without one it times out — so the test cannot pass
                # by accident on a sequential runner.
                _Tracked._gate.wait()
        finally:
            with _Tracked._lock:
                _Tracked._live -= 1
        yield Finding(
            rule_id=self.meta.id,
            severity=Severity.LOW,
            title=self.meta.title,
            taxonomy=(),
            target_ref=target.ref,
            evidence=Evidence(summary=f"rule {self._index} ran"),
        )


class _Raising(Rule):
    meta = RuleMeta(
        id="test.concurrency.raising",
        title="raises",
        severity=Severity.LOW,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(),
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Fail the way a buggy third-party rule does."""
        raise RuntimeError("boom")
        yield  # pragma: no cover — unreachable, keeps this a generator


class _Unreachable(Rule):
    meta = RuleMeta(
        id="test.concurrency.unreachable",
        title="endpoint down",
        severity=Severity.LOW,
        target_kind=TargetKind.ENDPOINT,
        taxonomy=(),
        required_capabilities=frozenset({Capability.CHAT}),
    )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Fail the way an unreachable endpoint does."""
        raise URLError("connection refused")
        yield  # pragma: no cover — unreachable, keeps this a generator


def _target() -> EndpointTarget:
    return EndpointTarget("http://x", "m", transport=ScriptedTransport("ok"))


def _registry(*rules: Rule) -> Registry:
    registry = Registry()
    for rule in rules:
        registry.register_rule(rule)
    return registry


def _reset() -> None:
    _Tracked.peak = 0
    _Tracked._live = 0
    _Tracked._gate = threading.Barrier(_LIMIT, timeout=5)


def test_endpoint_rules_actually_overlap() -> None:
    _reset()
    rules = [_Tracked(i, sync=True) for i in range(_RULE_COUNT)]
    result = Runner(
        registry=_registry(*rules), profile=Profile(name="t", policy=Policy()), concurrency=_LIMIT
    ).run(_target())
    assert result.rules_run == _RULE_COUNT
    assert _Tracked.peak > 1


def test_the_limit_is_respected() -> None:
    # A probe must not turn into a load test against someone's served model.
    _reset()
    rules = [_Tracked(i, sync=True) for i in range(_RULE_COUNT)]
    Runner(
        registry=_registry(*rules), profile=Profile(name="t", policy=Policy()), concurrency=_LIMIT
    ).run(_target())
    assert _Tracked.peak <= _LIMIT


def test_findings_keep_rule_order_whatever_finishes_first() -> None:
    # Two runs of the same probe must produce byte-identical reports, or a CI diff
    # is noise. Thread scheduling must not leak into the output.
    _reset()
    rules = [_Tracked(i, sync=False) for i in range(_RULE_COUNT)]
    concurrent = Runner(
        registry=_registry(*rules), profile=Profile(name="t", policy=Policy()), concurrency=_LIMIT
    ).run(_target())
    sequential = Runner(
        registry=_registry(*rules), profile=Profile(name="t", policy=Policy()), concurrency=1
    ).run(_target())
    assert [f.rule_id for f in concurrent.findings] == [f.rule_id for f in sequential.findings]


def test_a_raising_rule_is_recorded_and_the_rest_still_run() -> None:
    _reset()
    rules: list[Rule] = [_Tracked(i, sync=False) for i in range(2)]
    rules.append(_Raising())
    result = Runner(
        registry=_registry(*rules), profile=Profile(name="t", policy=Policy()), concurrency=_LIMIT
    ).run(_target())
    assert result.rules_run == 2
    assert [e.source for e in result.errors] == ["test.concurrency.raising"]


def test_an_unreachable_endpoint_still_aborts_the_whole_run() -> None:
    # Every rule would fail identically, so this stays a single top-level failure
    # with its own exit code rather than N per-rule errors.
    _reset()
    rules: list[Rule] = [_Tracked(i, sync=False) for i in range(2)]
    rules.append(_Unreachable())
    runner = Runner(
        registry=_registry(*rules), profile=Profile(name="t", policy=Policy()), concurrency=_LIMIT
    )
    try:
        runner.run(_target())
    except URLError:
        return
    raise AssertionError("an unreachable endpoint must propagate, not be swallowed")


def test_artifact_scans_stay_sequential() -> None:
    # File work is local and already linear-cost; a thread pool there buys little
    # and costs determinism, so concurrency is an endpoint-only behaviour.
    _reset()
    rules = [_Tracked(i, sync=False) for i in range(2)]
    runner = Runner(
        registry=_registry(*rules), profile=Profile(name="t", policy=Policy()), concurrency=_LIMIT
    )
    assert runner.concurrency_for(TargetKind.ARTIFACT) == 1
    assert runner.concurrency_for(TargetKind.ENDPOINT) == _LIMIT
