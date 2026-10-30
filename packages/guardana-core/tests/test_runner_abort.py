"""Aborting a concurrent probe must actually end it.

A target that went away stops the run: no further rule starts, and the rules already
in flight finish and record what happened to them. A Ctrl-C ends the process even
while rules are in flight, which a non-daemon `ThreadPoolExecutor` would not allow,
since CPython joins its workers at exit.
"""

import signal
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterable
from urllib.error import URLError

import pytest
from guardana.core.profile.model import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.report import Finding, StopReason
from guardana.core.rule import Rule, RuleContext, RuleMeta
from guardana.core.runner import Runner
from guardana.core.severity import Severity
from guardana.core.target import Capability, EndpointTarget, Target, TargetKind
from guardana.core.testing import ScriptedTransport

_BLOCK_SECONDS = 3.0
_IN_FLIGHT_SECONDS = 30.0
_EXIT_BUDGET_SECONDS = 10.0
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
    result = runner.run(EndpointTarget("http://x", "m", transport=ScriptedTransport("ok")))

    assert result.stopped_by is StopReason.TARGET_UNAVAILABLE
    # With 8 blocking rules at concurrency 2 an un-aborted run would take ~12 s.
    assert time.perf_counter() - started < _BLOCK_SECONDS * 2
    assert len(_STARTED) <= 2


@pytest.mark.skipif(sys.platform == "win32", reason="sends SIGINT")
def test_ctrl_c_ends_the_process_without_waiting_for_in_flight_rules() -> None:
    # Run in a subprocess: the failure mode is CPython joining non-daemon workers
    # at interpreter exit, which nothing inside this process can observe.
    script = textwrap.dedent(f"""
        import time
        from guardana.core.profile.model import Policy, Profile
        from guardana.core.registry import Registry
        from guardana.core.rule import Rule, RuleMeta
        from guardana.core.runner import Runner
        from guardana.core.severity import Severity
        from guardana.core.target import Capability, EndpointTarget, TargetKind
        from guardana.core.testing import ScriptedTransport

        def make(index):
            class R(Rule):
                meta = RuleMeta(
                    id=f"t.r{{index}}", title="t", severity=Severity.LOW,
                    target_kind=TargetKind.ENDPOINT, taxonomy=(),
                    required_capabilities=frozenset({{Capability.CHAT}}),
                )
                def run(self, target, ctx):
                    print("started", flush=True)
                    time.sleep({_IN_FLIGHT_SECONDS})
                    return ()
            return R()

        registry = Registry()
        for i in range(4):
            registry.register_rule(make(i))
        Runner(
            registry=registry, profile=Profile(name="t", policy=Policy()), concurrency=4
        ).run(EndpointTarget("http://x", "m", transport=ScriptedTransport("ok")))
    """)
    with subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ) as child:
        try:
            if child.stdout is None:
                pytest.fail("the child process has no stdout pipe")
            started = [child.stdout.readline() for _ in range(4)]
            assert started == ["started\n"] * 4, "every rule must be in flight before Ctrl-C"
            interrupted = time.perf_counter()
            child.send_signal(signal.SIGINT)
            child.wait(timeout=_IN_FLIGHT_SECONDS)
            elapsed = time.perf_counter() - interrupted
        finally:
            child.kill()

    assert elapsed < _EXIT_BUDGET_SECONDS, (
        f"process took {elapsed:.2f}s to exit after Ctrl-C — it is waiting for in-flight rules"
    )
