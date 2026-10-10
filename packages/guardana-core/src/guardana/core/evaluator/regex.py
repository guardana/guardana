import contextlib
import functools
import importlib.resources
import json
import math
import queue
import re
import subprocess
import sys
import threading
import weakref
from collections.abc import Mapping
from typing import ClassVar

from guardana.core.evaluator import _regex_worker
from guardana.core.evaluator._turns import which_turn
from guardana.core.evaluator.base import Evaluator, Expectation, Outcome, Verdict
from guardana.core.exchange import Exchange

MAX_REPLY_CHARS = 64 * 1024
"""The longest reply a pattern is searched in; a longer one is inconclusive, never truncated."""

SEARCH_TIMEOUT_SECONDS = 2.0
"""How long one search may run before it is abandoned as `inconclusive`.

A pattern without nested unbounded quantifiers searches a 64 KiB reply in milliseconds,
so two seconds is far above any honest search and still costs a stalled one seconds.
"""

_START_TIMEOUT_SECONDS = 30.0
"""How long a fresh worker may take to start, so a slow start never reads as a slow search."""

_EXIT_TIMEOUT_SECONDS = 1.0

_BACKSTOP_FACTOR = 2.0
"""The worker gives up a search on its own after this many bounds, should its parent be gone."""


class _NotSearchedError(Exception):
    """The worker did not say whether the pattern occurs; the message says why."""


@functools.cache
def _worker_source() -> str:
    """Return the worker's source, read as a resource so it also runs from a zip."""
    return (
        importlib.resources.files(__package__ or "guardana.core.evaluator")
        .joinpath("_regex_worker.py")
        .read_text(encoding="utf-8")
    )


class _SearchWorker:
    """One worker process that runs searches, started on first use and reused until it is stopped.

    A thread cannot interrupt `re`, so a search that outlives the bound is ended by
    killing its process; the next search starts a fresh one. Searches are serialised,
    and the bound runs from the moment a request is sent, never while it waits its turn.
    Every request carries a sequence number the answer must echo, so an answer left
    unread by an interrupted search is never taken for the next one's.
    """

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout
        self._lock = threading.Lock()
        # Guards only the handle, so `stop` from another thread never waits for a search.
        self._handle = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._replies: queue.Queue[bytes] = queue.Queue()
        self._sequence = 0
        self.starts = 0

    @property
    def pid(self) -> int | None:
        """The running worker's process id, or None when none is running."""
        process = self._process
        return None if process is None or process.poll() is not None else process.pid

    def search(self, pattern: str, text: str) -> bool:
        """Return whether `pattern` occurs in `text`; raise `_NotSearchedError` if unknown."""
        with self._lock:
            try:
                process, replies = self._running()
                self._sequence += 1
                self._send(process, [self._sequence, pattern, text])
                answer = self._next(replies, self.timeout)
            except BaseException:
                self.stop()
                raise
            match answer:
                case None:
                    raise _NotSearchedError(
                        f"regex search exceeded {self.timeout:g} s; not evaluated"
                    )
                case [int() as sequence, result] if sequence == self._sequence:
                    pass
                case _:
                    self.stop()
                    raise _NotSearchedError("regex worker answered out of turn; not evaluated")
        if isinstance(result, bool):
            return result
        raise _NotSearchedError(f"regex search failed in its worker ({result}); not evaluated")

    def stop(self) -> None:
        """Kill the worker, if one is running, and reap it.

        Only the input pipe is closed here: the relay thread may be blocked reading the
        output, and it closes that pipe itself once the killed worker's output ends.
        """
        with self._handle:
            process, self._process = self._process, None
        if process is None:
            return
        if process.poll() is None:
            with contextlib.suppress(OSError):
                process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=_EXIT_TIMEOUT_SECONDS)
        if process.stdin is not None:
            with contextlib.suppress(OSError, ValueError):
                process.stdin.close()

    def _send(self, process: subprocess.Popen[bytes], request: list[object]) -> None:
        """Write one request line; a worker that cannot take it is not searched."""
        stdin = process.stdin
        if stdin is None:
            raise _NotSearchedError("regex worker has no input; not evaluated")
        try:
            stdin.write((json.dumps(request) + "\n").encode("ascii"))
            stdin.flush()
        except (OSError, ValueError) as exc:
            raise _NotSearchedError(f"regex worker stopped ({exc}); not evaluated") from exc

    def _running(self) -> tuple[subprocess.Popen[bytes], queue.Queue[bytes]]:
        """Return the live worker and its reply queue, starting a fresh one when there is none."""
        process = self._process
        if process is not None and process.poll() is None:
            return process, self._replies
        self.stop()
        if getattr(sys, "frozen", False):
            raise _NotSearchedError(
                "regex worker could not start (a frozen application has no Python to run it); "
                "not evaluated"
            )
        backstop = f"{_BACKSTOP_FACTOR * self.timeout:g}"
        # A queue per process, so a reply a killed worker had in flight never reaches the next.
        replies: queue.Queue[bytes] = queue.Queue()
        with self._handle:
            try:
                process = subprocess.Popen(  # noqa: S603 - this interpreter, source shipped with it
                    [sys.executable, "-I", "-c", _worker_source(), backstop],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
            except (ImportError, OSError, TypeError, ValueError) as exc:
                raise _NotSearchedError(
                    f"regex worker could not start ({exc}); not evaluated"
                ) from exc
            self._process, self._replies = process, replies
        self.starts += 1
        try:
            threading.Thread(
                target=_relay, args=(process, replies), name="guardana-regex-relay", daemon=True
            ).start()
        except RuntimeError as exc:
            self.stop()
            if process.stdout is not None:
                process.stdout.close()
            raise _NotSearchedError(f"regex worker could not start ({exc}); not evaluated") from exc
        if self._next(replies, _START_TIMEOUT_SECONDS) != _regex_worker.READY:
            raise _NotSearchedError("regex worker did not start; not evaluated")
        return process, replies

    def _next(self, replies: queue.Queue[bytes], timeout: float) -> object:
        """Return the worker's next answer, or None once a worker silent too long is stopped."""
        try:
            line = replies.get(timeout=timeout)
        except queue.Empty:
            self.stop()
            return None
        if not line:
            raise _NotSearchedError("regex worker exited before answering; not evaluated")
        try:
            result: object = json.loads(line)
        except ValueError as exc:
            raise _NotSearchedError(
                "regex worker answered something unreadable; not evaluated"
            ) from exc
        return result


def _relay(process: subprocess.Popen[bytes], replies: queue.Queue[bytes]) -> None:
    """Hand each line the worker writes to `replies`, then an empty line once its output ends."""
    stdout = process.stdout
    try:
        if stdout is not None:
            for line in iter(stdout.readline, b""):
                replies.put(line)
    except (OSError, ValueError):
        pass
    finally:
        if stdout is not None:
            with contextlib.suppress(OSError):
                stdout.close()
        replies.put(b"")


class RegexEvaluator(Evaluator):
    """Grades a reply by whether `pattern` occurs anywhere in it (`re.search`).

    `must_match` (default true) passes a reply the pattern is found in; false
    passes a reply it is not found in. The pattern must compile, which is checked
    before any reply is read. Confidence 1.0: a match is a fact.

    A reply longer than `MAX_REPLY_CHARS` is inconclusive, never truncated. Each
    search runs in a worker process and is abandoned after `search_timeout` seconds
    (`SEARCH_TIMEOUT_SECONDS` by default), which is inconclusive: a pattern that
    backtracks catastrophically neither hangs the run nor reads as a pass. The
    worker starts on the first search, serves every later one, and is stopped by
    `close`, when the evaluator is collected, or when the interpreter exits.

    `must_match: true` describes the answer and reads the final reply. `must_match:
    false` names what must never be said and reads every reply under grade, each
    within the same bounds.
    """

    id = "regex"
    deterministic: ClassVar[bool] = True
    judge_calls_per_verdict: ClassVar[int] = 0
    expects: ClassVar[Mapping[str, bool]] = {"pattern": True, "must_match": False}

    def __init__(self, search_timeout: float = SEARCH_TIMEOUT_SECONDS) -> None:
        if (
            isinstance(search_timeout, bool)
            or not isinstance(search_timeout, int | float)
            or not math.isfinite(search_timeout)
            or search_timeout <= 0
        ):
            raise ValueError(
                f"search_timeout must be a positive number of seconds, got {search_timeout!r}"
            )
        self._worker = _SearchWorker(float(search_timeout))
        weakref.finalize(self, self._worker.stop)

    @property
    def search_timeout(self) -> float:
        """Seconds one search may run before its verdict is `inconclusive`."""
        return self._worker.timeout

    def close(self) -> None:
        """Stop the worker process; a later search starts a fresh one."""
        self._worker.stop()

    def __enter__(self) -> "RegexEvaluator":
        """Return this evaluator, to be closed when the block ends."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Stop the worker process."""
        self.close()

    @classmethod
    def check_fields(cls, expectation: Expectation) -> str | None:
        """Return why `pattern` or `must_match` is unusable, or None."""
        pattern = expectation.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            return f"evaluator {cls.id!r}: 'expect.pattern' must be a non-empty string"
        try:
            re.compile(pattern)
        except re.error as exc:
            return f"evaluator {cls.id!r}: 'expect.pattern' does not compile: {exc}"
        if not isinstance(expectation.get("must_match", True), bool):
            return f"evaluator {cls.id!r}: 'expect.must_match' must be true or false"
        return None

    def evaluate(self, exchange: Exchange, expectation: Expectation) -> Verdict:
        """Pass when finding the pattern is what `must_match` asked for."""
        problem = self.check_fields(expectation)
        if problem is not None:
            return Verdict("inconclusive", 0.0, problem, self.id)
        pattern = str(expectation.get("pattern"))
        if expectation.get("must_match", True) is not True:
            return self._never_said(exchange, pattern)
        reply = exchange.reply_text
        if reply is None:
            return Verdict("inconclusive", 0.0, "No model reply to search.", self.id)
        if len(reply) > MAX_REPLY_CHARS:
            return self._too_long("reply", len(reply))
        try:
            found = self._worker.search(pattern, reply)
        except _NotSearchedError as exc:
            return Verdict("inconclusive", 0.0, str(exc), self.id)
        said = "found" if found else "not found"
        outcome: Outcome = "pass" if found else "fail"
        return Verdict(outcome, 1.0, f"pattern {said} in the reply (must_match=True).", self.id)

    def _never_said(self, exchange: Exchange, pattern: str) -> Verdict:
        """Fail on the first reply under grade the pattern occurs in; pass only if none."""
        replies = exchange.graded_replies
        unsearched: Verdict | None = None
        for position, text in enumerate(replies, start=1):
            if not text.strip():
                continue
            where = which_turn(position, len(replies), alone="the reply")
            if len(text) > MAX_REPLY_CHARS:
                unsearched = unsearched or self._too_long(
                    which_turn(position, len(replies), alone="reply"), len(text)
                )
                continue
            try:
                found = self._worker.search(pattern, text)
            except _NotSearchedError as exc:
                reason = str(exc) if len(replies) == 1 else f"{where}: {exc}"
                unsearched = unsearched or Verdict("inconclusive", 0.0, reason, self.id)
                continue
            if found:
                return Verdict(
                    "fail", 1.0, f"pattern found in {where} (must_match=False).", self.id
                )
        if unsearched is not None:
            return unsearched
        if exchange.reply_text is None:
            return Verdict("inconclusive", 0.0, "No model reply to search.", self.id)
        return Verdict("pass", 1.0, "pattern not found in the reply (must_match=False).", self.id)

    def _too_long(self, what: str, length: int) -> Verdict:
        return Verdict(
            "inconclusive",
            0.0,
            f"{what} is {length} characters, over the {MAX_REPLY_CHARS}-character "
            "bound the pattern is searched within; not graded.",
            self.id,
        )
