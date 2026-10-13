"""The process `RegexEvaluator` searches in, so a search that never ends can be killed.

The parent runs this source with `python -I -S -c`, so no `.pth` file or `sitecustomize`
runs before it. It announces itself with one `"ready"` line, then answers each
`[sequence, pattern, text]` JSON line on stdin with one `[sequence, answer]` line on
stdout: `true` or `false` for whether the pattern was found, or a string naming why it was
not searched. A `[sequence, pattern, text, "spans"]` line is answered with every non-empty
match as `[start, end, value_start, value_end]`, the value being the `value` group's span
or, when there is none or it did not take part, the match's own. It imports only the
standard library, so a scanned tree cannot shadow a module it loads, and importing it
starts nothing.
"""

import json
import re
import signal
import sys
from collections.abc import Callable
from types import FrameType
from typing import IO, TypeVar

READY = "ready"
"""The first line the worker writes, once it is reading requests."""


class _AbandonedError(Exception):
    """A search outlived the backstop and was given up."""


def _abandon(signum: int, frame: FrameType | None) -> None:
    raise _AbandonedError


def answer(pattern: str, text: str, backstop: float) -> bool | str:
    """Return whether `pattern` occurs in `text`, or why the search did not finish."""
    return _bounded(lambda: re.search(pattern, text) is not None, backstop)


def find_spans(pattern: str, text: str, backstop: float) -> list[list[int]] | str:
    """Return every non-empty match of `pattern` in `text`, or why the search did not finish."""

    def spans() -> list[list[int]]:
        compiled = re.compile(pattern)
        valued = "value" in compiled.groupindex
        found: list[list[int]] = []
        for match in compiled.finditer(text):
            start, end = match.span()
            if start == end:
                continue
            value = match.span("value") if valued else (-1, -1)
            found.append([start, end, *((start, end) if value == (-1, -1) else value)])
        return found

    return _bounded(spans, backstop)


_Answer = TypeVar("_Answer")


def _bounded(search: Callable[[], _Answer], backstop: float) -> _Answer | str:
    """Run `search` under the backstop alarm, returning why it did not finish when it did not.

    `re` checks for signals while it backtracks, so an alarm ends a runaway search
    even when the parent that would have killed this process is gone. A `backstop`
    of zero sets no alarm.
    """
    alarm = hasattr(signal, "setitimer") and backstop > 0
    try:
        if alarm:
            signal.setitimer(signal.ITIMER_REAL, backstop)
        try:
            return search()
        finally:
            if alarm:
                signal.setitimer(signal.ITIMER_REAL, 0)
    except _AbandonedError:
        return f"search abandoned after {backstop:g} s"
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def serve(requests: IO[str], replies: IO[str], backstop: float) -> None:
    """Answer every request line until `requests` closes."""
    # An interrupt from the terminal is the parent's to handle; it stops this process.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _abandon)
    replies.write(json.dumps(READY) + "\n")
    replies.flush()
    for line in requests:
        sequence: object = None
        result: object
        try:
            sequence, pattern, text, *kind = json.loads(line)
            if kind == ["spans"]:
                result = find_spans(str(pattern), str(text), backstop)
            elif not kind:
                result = answer(str(pattern), str(text), backstop)
            else:
                result = f"unreadable request: unknown kind {kind!r}"
        except (TypeError, ValueError) as exc:
            result = f"unreadable request: {exc}"
        replies.write(json.dumps([sequence, result]) + "\n")
        replies.flush()


if __name__ == "__main__":
    serve(sys.stdin, sys.stdout, float(sys.argv[1]))
