"""The process `RegexEvaluator` searches in, so a search that never ends can be killed.

The parent runs this source with `python -I -c`. It announces itself with one `"ready"`
line, then answers each `[sequence, pattern, text]` JSON line on stdin with one
`[sequence, answer]` line on stdout: `true` or `false` for whether the pattern was found,
or a string naming why it was not searched. It imports only the standard library, so a
scanned tree cannot shadow a module it loads, and importing it starts nothing.
"""

import json
import re
import signal
import sys
from types import FrameType
from typing import IO

READY = "ready"
"""The first line the worker writes, once it is reading requests."""


class _AbandonedError(Exception):
    """A search outlived the backstop and was given up."""


def _abandon(signum: int, frame: FrameType | None) -> None:
    raise _AbandonedError


def answer(pattern: str, text: str, backstop: float) -> bool | str:
    """Return whether `pattern` occurs in `text`, or why the search did not finish.

    `re` checks for signals while it backtracks, so an alarm ends a runaway search
    even when the parent that would have killed this process is gone. A `backstop`
    of zero sets no alarm.
    """
    alarm = hasattr(signal, "setitimer") and backstop > 0
    try:
        if alarm:
            signal.setitimer(signal.ITIMER_REAL, backstop)
        try:
            return re.search(pattern, text) is not None
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
        try:
            sequence, pattern, text = json.loads(line)
            result = answer(str(pattern), str(text), backstop)
        except (TypeError, ValueError) as exc:
            result = f"unreadable request: {exc}"
        replies.write(json.dumps([sequence, result]) + "\n")
        replies.flush()


if __name__ == "__main__":
    serve(sys.stdin, sys.stdout, float(sys.argv[1]))
