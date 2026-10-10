"""A `regex` search runs in a worker process and is abandoned when it outlives its bound.

`re` cannot be interrupted from another thread, so the only way to stop a pattern that
backtracks catastrophically is to kill the process running it. An abandoned search says
nothing about the reply, so it is `inconclusive`: for `must_match: false` a half-run
search that found nothing would otherwise read as a pass.
"""

import gc
import io
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from guardana.core.evaluator import Expectation, _regex_worker, regex
from guardana.core.evaluator.regex import SEARCH_TIMEOUT_SECONDS, RegexEvaluator
from guardana.core.exchange import Exchange
from guardana.core.profile import Policy, Profile
from guardana.core.registry import Registry
from guardana.core.rule.yaml_rule import load_yaml_rules
from guardana.core.runner import Runner
from guardana.core.target import EndpointTarget
from guardana.core.testing import ScriptedTransport
from guardana.core.trajectory.model import Trajectory, TrajectoryStep

_BACKTRACKS = r"(a+)+$"
_CRAFTED = "a" * 40 + "b"
_SLACK_SECONDS = 1.0
"""How far past its bound a timed-out search may return.

Killing and reaping a worker takes milliseconds even on a loaded runner, while a stop that
waits for the worker's own alarm overruns by the whole bound (0.5 s or more here).
"""

_HANG_GUARD_SECONDS = 30.0
"""Only stops a test that hangs; it covers starting an interpreter, never a bound."""

_SHORT = 0.5


def _expect(pattern: str, *, must_match: bool = True) -> Expectation:
    return Expectation(fields={"pattern": pattern, "must_match": must_match})


def _alive(evaluator: RegexEvaluator) -> subprocess.Popen[bytes]:
    process = evaluator._worker._process
    if process is None:
        raise AssertionError("no worker process is running")
    return process


@pytest.mark.parametrize("must_match", [True, False])
def test_a_backtracking_search_ends_within_its_bound_and_is_inconclusive(
    must_match: bool,
) -> None:
    with RegexEvaluator() as evaluator:
        evaluator.evaluate(Exchange.single_reply("warm up"), _expect("warm"))
        started = time.monotonic()
        verdict = evaluator.evaluate(
            Exchange.single_reply(_CRAFTED), _expect(_BACKTRACKS, must_match=must_match)
        )
        elapsed = time.monotonic() - started

    assert elapsed < SEARCH_TIMEOUT_SECONDS + _SLACK_SECONDS
    assert (verdict.outcome, verdict.confidence) == ("inconclusive", 0.0)
    assert verdict.rationale == f"regex search exceeded {SEARCH_TIMEOUT_SECONDS:g} s; not evaluated"


def test_the_default_bound_is_two_seconds() -> None:
    assert SEARCH_TIMEOUT_SECONDS == 2.0
    assert RegexEvaluator().search_timeout == SEARCH_TIMEOUT_SECONDS


def test_a_normal_pattern_still_passes_a_match_and_fails_a_miss() -> None:
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        found = evaluator.evaluate(Exchange.single_reply("order 12345"), _expect(r"\d{5}"))
        missed = evaluator.evaluate(Exchange.single_reply("order"), _expect(r"\d{5}"))
        never = evaluator.evaluate(
            Exchange.single_reply("order 12345"), _expect(r"\d{5}", must_match=False)
        )

    assert (found.outcome, found.confidence) == ("pass", 1.0)
    assert (missed.outcome, missed.confidence) == ("fail", 1.0)
    assert (never.outcome, never.confidence) == ("fail", 1.0)


def test_one_worker_serves_every_reply() -> None:
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        verdicts = [
            evaluator.evaluate(Exchange.single_reply(f"reply {n}"), _expect(r"reply \d+"))
            for n in range(25)
        ]
        process = _alive(evaluator)

        assert {v.outcome for v in verdicts} == {"pass"}
        assert evaluator._worker.starts == 1
        assert process.poll() is None


def test_after_a_timeout_the_next_reply_is_searched_by_a_fresh_worker() -> None:
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        evaluator.evaluate(Exchange.single_reply("warm up"), _expect("warm"))
        first = _alive(evaluator)

        stalled = evaluator.evaluate(Exchange.single_reply(_CRAFTED), _expect(_BACKTRACKS))
        after = evaluator.evaluate(Exchange.single_reply("order 12345"), _expect(r"\d{5}"))

        assert stalled.outcome == "inconclusive"
        assert first.poll() is not None
        assert after.outcome == "pass"
        assert _alive(evaluator).pid != first.pid
        assert evaluator._worker.starts == 2


def test_a_worker_that_died_between_searches_is_replaced() -> None:
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        evaluator.evaluate(Exchange.single_reply("warm up"), _expect("warm"))
        first = _alive(evaluator)
        first.kill()
        first.wait()

        verdict = evaluator.evaluate(Exchange.single_reply("order 12345"), _expect(r"\d{5}"))

        assert verdict.outcome == "pass"
        assert _alive(evaluator).pid != first.pid


def test_closing_the_evaluator_leaves_no_worker_running() -> None:
    evaluator = RegexEvaluator(search_timeout=_SHORT)
    evaluator.evaluate(Exchange.single_reply("warm up"), _expect("warm"))
    process = _alive(evaluator)

    evaluator.close()

    assert process.poll() is not None
    assert evaluator._worker.pid is None


def test_an_evaluator_that_is_collected_stops_its_worker() -> None:
    evaluator = RegexEvaluator(search_timeout=_SHORT)
    evaluator.evaluate(Exchange.single_reply("warm up"), _expect("warm"))
    process = _alive(evaluator)

    del evaluator
    gc.collect()

    assert process.poll() is not None


def test_a_closed_evaluator_starts_a_worker_again_when_asked() -> None:
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        evaluator.evaluate(Exchange.single_reply("warm up"), _expect("warm"))
        evaluator.close()

        verdict = evaluator.evaluate(Exchange.single_reply("order 12345"), _expect(r"\d{5}"))

        assert verdict.outcome == "pass"


@pytest.mark.parametrize("must_match", [True, False])
def test_a_worker_that_cannot_start_is_inconclusive_never_a_pass(
    must_match: bool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "executable", str(tmp_path / "no-such-python"))
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        verdict = evaluator.evaluate(
            Exchange.single_reply("order"), _expect(r"\d{5}", must_match=must_match)
        )

    assert (verdict.outcome, verdict.confidence) == ("inconclusive", 0.0)
    assert "could not start" in verdict.rationale


def _agent_run(*texts: str) -> Exchange:
    return Exchange.from_trajectory(
        Trajectory(task="look it up", steps=tuple(TrajectoryStep(t, ()) for t in texts))
    )


def test_a_later_match_still_fails_a_run_whose_earlier_reply_timed_out() -> None:
    pattern = r"(a+)+$|ACCT-\d{4}"
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        verdict = evaluator.evaluate(
            _agent_run(_CRAFTED, "Account ACCT-7731."), _expect(pattern, must_match=False)
        )

    assert verdict.outcome == "fail"
    assert "assistant turn 2 of 2" in verdict.rationale


def test_a_run_whose_unmatched_replies_include_a_timeout_never_passes() -> None:
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        verdict = evaluator.evaluate(
            _agent_run(_CRAFTED, "Done."), _expect(_BACKTRACKS, must_match=False)
        )

    assert verdict.outcome == "inconclusive"
    assert verdict.rationale == (
        f"assistant turn 1 of 2: regex search exceeded {_SHORT:g} s; not evaluated"
    )


@pytest.mark.parametrize("bad", [0, -1.0, float("nan"), float("inf"), True, "2"])
def test_a_search_timeout_that_is_not_a_positive_number_is_refused(bad: object) -> None:
    with pytest.raises(ValueError, match="search_timeout"):
        RegexEvaluator(search_timeout=bad)  # type: ignore[arg-type]


def test_an_abandoned_search_lands_on_the_unverified_channel(tmp_path: Path) -> None:
    rule_file = {
        "id": "acme.quality.no_runaway",
        "title": "Replies never end in a run of a",
        "severity": "high",
        "target_kind": "endpoint",
        "taxonomy": ["LLM09:2025"],
        "evaluator": "regex",
        "expect": {"pattern": _BACKTRACKS, "must_match": False},
        "requires": ["chat"],
        "prompts": ["Say something."],
    }
    (tmp_path / "rule.yaml").write_text(json.dumps(rule_file), encoding="utf-8")
    (rule,) = load_yaml_rules(tmp_path / "rule.yaml")
    registry = Registry()
    registry.register_rule(rule)
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        registry.register_evaluator(evaluator)
        target = EndpointTarget("http://x", "m", transport=ScriptedTransport(_CRAFTED))

        result = Runner(registry=registry, profile=Profile("t", Policy())).run(target)

    assert result.findings == ()
    (unverified,) = result.unverified
    assert unverified.verdict is not None
    assert unverified.verdict.outcome == "inconclusive"
    assert "exceeded" in unverified.verdict.rationale


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="needs an interval timer")
def test_a_worker_whose_parent_is_gone_gives_up_its_search_and_exits() -> None:
    worker = subprocess.Popen(  # noqa: S603 - this interpreter and a file shipped with it
        [sys.executable, "-I", _regex_worker.__file__, f"{_SHORT:g}"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        stdin, stdout = worker.stdin, worker.stdout
        if stdin is None or stdout is None:
            raise AssertionError("the worker has no pipes")
        assert json.loads(stdout.readline()) == _regex_worker.READY
        stdin.write((json.dumps([7, _BACKTRACKS, _CRAFTED]) + "\n").encode("ascii"))
        stdin.close()

        assert worker.wait(timeout=_SHORT + _SLACK_SECONDS) == 0
        sequence, answer = json.loads(stdout.readline())
        assert sequence == 7
        assert "abandoned" in answer
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait()
        if worker.stdout is not None:
            worker.stdout.close()


_INTERRUPTED = """
import os, sys
from guardana.core.evaluator import Expectation
from guardana.core.evaluator.regex import RegexEvaluator
from guardana.core.exchange import Exchange

evaluator = RegexEvaluator(search_timeout=60)
evaluator.evaluate(Exchange.single_reply("warm up"), Expectation(fields={"pattern": "warm"}))
print(evaluator._worker.pid, flush=True)
raise KeyboardInterrupt
"""


@pytest.mark.skipif(sys.platform == "win32", reason="probes a process id with signal 0")
def test_an_interrupted_run_leaves_no_worker_behind() -> None:
    finished = subprocess.run(  # noqa: S603 - this interpreter and a script defined above
        [sys.executable, "-c", _INTERRUPTED],
        capture_output=True,
        text=True,
        timeout=_HANG_GUARD_SECONDS,
        check=False,
    )

    assert "KeyboardInterrupt" in finished.stderr
    pid = int(finished.stdout.strip())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_a_timed_out_search_returns_on_time_without_the_worker_alarm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Where the worker has no alarm (Windows), only the parent's kill ends the search.
    monkeypatch.setattr(regex, "_BACKSTOP_FACTOR", 0.0)
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        evaluator.evaluate(Exchange.single_reply("warm up"), _expect("warm"))
        started = time.monotonic()
        verdict = evaluator.evaluate(Exchange.single_reply(_CRAFTED), _expect(_BACKTRACKS))
        elapsed = time.monotonic() - started

    assert verdict.outcome == "inconclusive"
    assert elapsed < _SHORT + _SLACK_SECONDS


def test_closing_during_a_search_returns_at_once_and_the_search_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(regex, "_BACKSTOP_FACTOR", 0.0)
    evaluator = RegexEvaluator(search_timeout=60)
    evaluator.evaluate(Exchange.single_reply("warm up"), _expect("warm"))
    verdicts: list[str] = []
    search = threading.Thread(
        target=lambda: verdicts.append(
            evaluator.evaluate(
                Exchange.single_reply(_CRAFTED), _expect(_BACKTRACKS, must_match=False)
            ).outcome
        ),
        daemon=True,
    )
    search.start()
    time.sleep(0.3)

    started = time.monotonic()
    evaluator.close()
    search.join(timeout=_HANG_GUARD_SECONDS)

    assert time.monotonic() - started < _SLACK_SECONDS
    assert verdicts == ["inconclusive"]


def test_an_interrupted_search_never_hands_its_answer_to_the_next_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        evaluator.evaluate(Exchange.single_reply("warm up"), _expect("warm"))
        replies = evaluator._worker._replies
        real_get = replies.get

        def interrupted(*args: object, **kwargs: object) -> bytes:
            monkeypatch.setattr(replies, "get", real_get)
            raise KeyboardInterrupt

        monkeypatch.setattr(replies, "get", interrupted)
        with pytest.raises(KeyboardInterrupt):
            evaluator.evaluate(Exchange.single_reply("order"), _expect(r"\d{5}"))
        time.sleep(0.3)

        verdict = evaluator.evaluate(
            Exchange.single_reply("leaks SECRET"), _expect("SECRET", must_match=False)
        )

    assert verdict.outcome == "fail"


def test_an_answer_out_of_turn_is_inconclusive_and_replaces_the_worker() -> None:
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        evaluator.evaluate(Exchange.single_reply("warm up"), _expect("warm"))
        first = _alive(evaluator)
        evaluator._worker._replies.put(b"[0, false]\n")

        stale = evaluator.evaluate(
            Exchange.single_reply("leaks SECRET"), _expect("SECRET", must_match=False)
        )
        after = evaluator.evaluate(
            Exchange.single_reply("leaks SECRET"), _expect("SECRET", must_match=False)
        )

        assert stale.outcome == "inconclusive"
        assert "out of turn" in stale.rationale
        assert first.poll() is not None
        assert after.outcome == "fail"


@pytest.mark.parametrize("executable", [None, ""])
def test_an_interpreter_that_cannot_be_named_is_inconclusive(
    executable: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "executable", executable)
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        verdict = evaluator.evaluate(Exchange.single_reply("order"), _expect("x", must_match=False))

    assert (verdict.outcome, verdict.confidence) == ("inconclusive", 0.0)
    assert "could not start" in verdict.rationale


def test_a_frozen_application_does_not_start_itself_as_a_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        verdict = evaluator.evaluate(Exchange.single_reply("order"), _expect("x", must_match=False))

        assert evaluator._worker.starts == 0
    assert verdict.outcome == "inconclusive"
    assert "could not start" in verdict.rationale


def test_a_request_that_cannot_be_written_is_inconclusive() -> None:
    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        evaluator.evaluate(Exchange.single_reply("warm up"), _expect("warm"))
        process = _alive(evaluator)
        pipe = process.stdin
        closed = io.BytesIO()
        closed.close()
        process.stdin = closed
        try:
            verdict = evaluator.evaluate(
                Exchange.single_reply("order"), _expect("x", must_match=False)
            )
        finally:
            if pipe is not None:
                pipe.close()

    assert verdict.outcome == "inconclusive"


def _capturing_popen(
    monkeypatch: pytest.MonkeyPatch, then: Callable[[], None] = lambda: None
) -> list[subprocess.Popen[bytes]]:
    started: list[subprocess.Popen[bytes]] = []
    real = subprocess.Popen

    def popen(command: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
        process = real(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        started.append(process)
        then()
        return process

    monkeypatch.setattr(subprocess, "Popen", popen)
    return started


def test_a_relay_that_cannot_start_leaves_no_worker_and_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = _capturing_popen(monkeypatch)

    def refuse(self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    with RegexEvaluator(search_timeout=_SHORT) as evaluator:
        monkeypatch.setattr(threading.Thread, "start", refuse)
        verdict = evaluator.evaluate(Exchange.single_reply("order"), _expect("x", must_match=False))
        monkeypatch.undo()

        (process,) = started
        assert process.poll() is not None
        assert evaluator._worker.pid is None
    assert verdict.outcome == "inconclusive"
    assert "could not start" in verdict.rationale


def test_a_close_racing_a_worker_start_still_stops_that_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluator = RegexEvaluator(search_timeout=_SHORT)
    closing: list[threading.Thread] = []

    def close_meanwhile() -> None:
        closer = threading.Thread(target=evaluator.close, daemon=True)
        closer.start()
        closing.append(closer)
        time.sleep(0.2)

    started = _capturing_popen(monkeypatch, close_meanwhile)
    verdict = evaluator.evaluate(Exchange.single_reply("order"), _expect("x", must_match=False))
    closing[0].join(timeout=_HANG_GUARD_SECONDS)

    (process,) = started
    try:
        process.wait(timeout=_SLACK_SECONDS)
        assert evaluator._worker.pid is None
    finally:
        evaluator.close()
    assert verdict.outcome in {"pass", "inconclusive"}
