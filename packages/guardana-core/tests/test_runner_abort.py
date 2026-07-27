"""Aborting a concurrent probe must actually end it.

When the runner was sequential, a propagating `URLError` and a Ctrl-C both ended
the run immediately — that is what `_execute_one`'s docstring promises. A thread
pool quietly took it away: `ThreadPoolExecutor` workers are non-daemon and
CPython joins them at interpreter exit, so the CLI printed "could not reach
endpoint", returned, and then sat there while every in-flight rule finished its
network work.

Two things are pinned here: the process is free to exit while rules are still in
flight, and once the endpoint is known to be down no *further* rules are started
against it.
"""

import subprocess
import sys
import textwrap
import time
from collections.abc import Iterable
from urllib.error import URLError

from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import ScriptedTransport

_BLOCK_SECONDS = 3.0
_EXIT_BUDGET_SECONDS = 2.5
_STARTED: list[str] = []


class _Blocking(Rule):
    def __init__(self, index: int) -> None:
        self._index = index
        self.meta = RuleMeta(
            id=f"test.abort.block{index:02d}",
            title="blocks",
            severity=Severity.LOW,
            target_kind=TargetKind.ENDPOINT,
            taxonomy=(),
            required_capabilities=frozenset({Capability.CHAT}),
        )

    def run(self, target: Target, ctx: RuleContext) -> Iterable[Finding]:
        """Stand in for a rule waiting on a slow model."""
        _STARTED.append(self.meta.id)
        time.sleep(_BLOCK_SECONDS)
        return ()


class _Unreachable(Rule):
    meta = RuleMeta(
        id="test.abort.unreachable",
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


def test_no_further_rules_start_once_the_endpoint_is_known_to_be_down() -> None:
    # Every rule would fail identically, so continuing to send prompts to a dead
    # or limping endpoint is pure harm.
    _STARTED.clear()
    registry = Registry()
    registry.register_rule(_Unreachable())
    for index in range(8):
        registry.register_rule(_Blocking(index))
    runner = Runner(registry=registry, profile=Profile(name="t", policy=Policy()), concurrency=2)

    started = time.perf_counter()
    try:
        runner.run(EndpointTarget("http://x", "m", transport=ScriptedTransport("ok")))
    except URLError:
        pass
    else:  # pragma: no cover — the rule above always raises
        raise AssertionError("URLError must propagate")

    # With 8 blocking rules at concurrency 2 an un-aborted run would take ~12 s.
    assert time.perf_counter() - started < _BLOCK_SECONDS * 2
    assert len(_STARTED) <= 2


def test_the_process_exits_without_waiting_for_in_flight_rules() -> None:
    # Run in a subprocess: the failure mode is CPython joining non-daemon workers
    # at interpreter exit, which nothing inside this process can observe.
    script = textwrap.dedent(f"""
        import time
        from collections.abc import Iterable
        from urllib.error import URLError
        from guardana.core.profile.model import Policy, Profile
        from guardana.core.registry import Registry
        from guardana.core.report import Finding
        from guardana.core.rule import Rule, RuleContext, RuleMeta
        from guardana.core.runner import Runner
        from guardana.core.severity import Severity
        from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
        from guardana.core.testing import ScriptedTransport

        def make(index, fail):
            class R(Rule):
                meta = RuleMeta(
                    id=f"t.r{{index}}", title="t", severity=Severity.LOW,
                    target_kind=TargetKind.ENDPOINT, taxonomy=(),
                    required_capabilities=frozenset({{Capability.CHAT}}),
                )
                def run(self, target, ctx):
                    if fail:
                        raise URLError("refused")
                    time.sleep({_BLOCK_SECONDS})
                    return ()
            return R()

        registry = Registry()
        registry.register_rule(make(0, True))
        for i in range(1, 5):
            registry.register_rule(make(i, False))
        try:
            Runner(
                registry=registry, profile=Profile(name="t", policy=Policy()), concurrency=4
            ).run(EndpointTarget("http://x", "m", transport=ScriptedTransport("ok")))
        except URLError:
            pass
    """)
    started = time.perf_counter()
    subprocess.run([sys.executable, "-c", script], check=True, timeout=30)  # noqa: S603
    elapsed = time.perf_counter() - started

    assert elapsed < _EXIT_BUDGET_SECONDS, (
        f"process took {elapsed:.2f}s to exit — it is waiting for in-flight rules"
    )
