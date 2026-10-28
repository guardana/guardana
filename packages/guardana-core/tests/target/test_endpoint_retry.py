"""Guards for the retry/backoff around a served model's rate limits.

A probe sends many requests to one endpoint, so a 429 is an ordinary event, not
an outage — and the runner treats a connection failure as fatal to the whole run
(every rule would fail identically). Without a retry, one rate-limited request
therefore aborted the entire probe. Concurrency makes that likelier, so the two
land together.

The rule that matters: a retry may only turn a *transient* refusal into a real
answer. It must never turn a genuine failure into silence.
"""

import io
import json
from email.message import Message
from http.client import BadStatusLine, RemoteDisconnected
from urllib.error import HTTPError, URLError

import pytest
from guardana.core.target.endpoint import _MAX_BACKOFF_SECONDS as _MAX_BACKOFF
from guardana.core.target.endpoint import (
    EndpointError,
    EndpointUnreachable,
    close_http_error,
    post_json,
)

_REPLY = {"choices": [{"message": {"content": "hi"}}]}


class _CannedResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self, size: int = -1) -> bytes:
        return self._payload

    def __enter__(self) -> "_CannedResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _rate_limited(headers: dict[str, str] | None = None) -> HTTPError:
    return HTTPError("http://x", 429, "Too Many Requests", headers or {}, None)  # type: ignore[arg-type]


@pytest.fixture
def slept(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    recorded: list[float] = []
    monkeypatch.setattr("guardana.core.target.endpoint._sleep", recorded.append)
    return recorded


def _install(
    monkeypatch: pytest.MonkeyPatch, responses: list[_CannedResponse | Exception]
) -> list[int]:
    calls: list[int] = []

    def fake_urlopen(request: object, timeout: float) -> _CannedResponse:
        calls.append(1)
        outcome = responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr("guardana.core.target.endpoint.open_unredirected", fake_urlopen)
    return calls


def test_a_rate_limited_request_is_retried_and_succeeds(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    calls = _install(
        monkeypatch, [_rate_limited(), _CannedResponse(json.dumps(_REPLY).encode("utf-8"))]
    )
    assert post_json("http://x", {}, None, "ref") == _REPLY
    assert len(calls) == 2
    assert slept  # it waited rather than hammering


def test_retries_are_bounded_and_the_failure_still_surfaces(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    # Exhausting the retries must raise, never return a made-up "empty" reply:
    # a rule that got silence here would grade a model it never reached.
    calls = _install(monkeypatch, [_rate_limited() for _ in range(10)])
    with pytest.raises(HTTPError):
        post_json("http://x", {}, None, "ref")
    assert 1 < len(calls) <= 4


def test_a_client_error_is_not_retried(monkeypatch: pytest.MonkeyPatch, slept: list[float]) -> None:
    # A 400 means the request is wrong; repeating it wastes the run and hides the
    # cause behind a delay.
    calls = _install(monkeypatch, [HTTPError("http://x", 400, "Bad Request", {}, None)])  # type: ignore[arg-type]
    with pytest.raises(HTTPError):
        post_json("http://x", {}, None, "ref")
    assert len(calls) == 1
    assert not slept


def test_a_server_error_is_retried(monkeypatch: pytest.MonkeyPatch, slept: list[float]) -> None:
    calls = _install(
        monkeypatch,
        [
            HTTPError("http://x", 503, "Service Unavailable", {}, None),  # type: ignore[arg-type]
            _CannedResponse(json.dumps(_REPLY).encode("utf-8")),
        ],
    )
    assert post_json("http://x", {}, None, "ref") == _REPLY
    assert len(calls) == 2


def test_retry_after_is_honoured_but_capped(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    # A server (or an attacker in front of one) that answers `Retry-After: 86400`
    # must not be able to park the scan for a day.
    _install(
        monkeypatch,
        [
            _rate_limited({"Retry-After": "86400"}),
            _CannedResponse(json.dumps(_REPLY).encode("utf-8")),
        ],
    )
    post_json("http://x", {}, None, "ref")
    assert slept
    assert max(slept) <= _MAX_BACKOFF


def test_an_unparseable_retry_after_falls_back_to_backoff(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    _install(
        monkeypatch,
        [
            _rate_limited({"Retry-After": "soon-ish"}),
            _CannedResponse(json.dumps(_REPLY).encode("utf-8")),
        ],
    )
    post_json("http://x", {}, None, "ref")
    assert slept
    assert all(delay > 0 for delay in slept)


@pytest.mark.parametrize("header", ["nan", "inf", "-inf"])
def test_a_non_finite_retry_after_falls_back_instead_of_crashing(
    monkeypatch: pytest.MonkeyPatch, slept: list[float], header: str
) -> None:
    # `float("nan")` parses without raising and survives both `max` and `min`
    # (every NaN comparison is false), and `time.sleep(nan)` raises ValueError —
    # which the runner records as "check could not run" for every rule that
    # touched the endpoint. A rate limit must never do that.
    _install(
        monkeypatch,
        [
            _rate_limited({"Retry-After": header}),
            _CannedResponse(json.dumps(_REPLY).encode("utf-8")),
        ],
    )
    assert post_json("http://x", {}, None, "ref") == _REPLY
    assert slept
    assert all(0 < delay <= _MAX_BACKOFF for delay in slept)


def test_an_oversized_reply_is_still_refused_after_a_retry(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    # The retry path must not become a way around the response cap.
    _install(monkeypatch, [_rate_limited(), _CannedResponse(b"x" * (8 * 1024 * 1024 + 1))])
    with pytest.raises(EndpointError):
        post_json("http://x", {}, None, "ref")


def test_a_timeout_is_the_target_not_answering_and_is_not_retried(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    calls = _install(monkeypatch, [TimeoutError("timed out")])

    with pytest.raises(EndpointUnreachable, match="ref did not answer within 7 seconds"):
        post_json("http://x", {}, None, "ref", timeout=7)
    assert len(calls) == 1
    assert not slept


@pytest.mark.parametrize(
    "failure",
    [ConnectionResetError("reset by peer"), RemoteDisconnected("closed"), BadStatusLine("junk")],
    ids=["reset", "disconnected", "malformed-http"],
)
def test_a_connection_that_breaks_while_sending_is_the_target_unreachable(
    monkeypatch: pytest.MonkeyPatch, slept: list[float], failure: Exception
) -> None:
    calls = _install(monkeypatch, [failure])

    with pytest.raises(EndpointUnreachable, match="connection to ref failed"):
        post_json("http://x", {}, None, "ref")
    assert len(calls) == 1
    assert not slept


def test_an_unreachable_endpoint_is_still_an_endpoint_error() -> None:
    assert issubclass(EndpointUnreachable, EndpointError)


def test_a_connection_that_times_out_is_the_target_not_answering(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    _install(monkeypatch, [URLError(TimeoutError("timed out"))])

    with pytest.raises(EndpointUnreachable, match="ref did not answer within 30 seconds"):
        post_json("http://x", {}, None, "ref")
    assert not slept


def test_a_refused_connection_stays_the_url_error_it_is(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    _install(monkeypatch, [URLError(ConnectionRefusedError("refused"))])

    with pytest.raises(URLError) as raised:
        post_json("http://x", {}, None, "ref")
    assert not isinstance(raised.value, EndpointError)


class _UnclosableBody(io.BytesIO):
    """A reply body whose first `close()` fails, as a connection torn down underneath it can.

    Later calls close it, so the finaliser that closes the error again at collection is quiet.
    """

    failed = False

    def close(self) -> None:
        if not self.failed:
            self.failed = True
            raise OSError("the connection is already gone")
        super().close()


def _error(code: int, body: io.BytesIO) -> HTTPError:
    return HTTPError("http://x", code, "status", Message(), body)


def test_an_error_status_that_is_retried_is_closed_before_the_next_attempt(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    body = io.BytesIO(b"busy")
    error = _error(503, body)
    _install(monkeypatch, [error, _CannedResponse(json.dumps(_REPLY).encode("utf-8"))])
    assert post_json("http://x", {}, None, "ref") == _REPLY
    assert error.fp.closed


def test_a_refused_redirect_is_closed(monkeypatch: pytest.MonkeyPatch, slept: list[float]) -> None:
    error = _error(302, io.BytesIO(b"moved"))
    _install(monkeypatch, [error])
    with pytest.raises(EndpointError, match="redirect"):
        post_json("http://x", {}, None, "ref")
    assert error.fp.closed


def test_a_redirect_whose_reply_fails_to_close_is_still_refused(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    _install(monkeypatch, [_error(302, _UnclosableBody(b"moved"))])
    with pytest.raises(EndpointError, match="redirect"):
        post_json("http://x", {}, None, "ref")


def test_an_error_status_the_retries_did_not_clear_reaches_the_caller_unread(
    monkeypatch: pytest.MonkeyPatch, slept: list[float]
) -> None:
    # The caller quotes this body or matches a decline against it, and closes it then.
    error = _error(400, io.BytesIO(b'{"error":"input_rejected"}'))
    _install(monkeypatch, [error])
    with pytest.raises(HTTPError) as raised:
        post_json("http://x", {}, None, "ref")
    assert raised.value is error
    assert raised.value.read() == b'{"error":"input_rejected"}'
    raised.value.close()


class _BrokenCloseBody(io.BytesIO):
    """A reply body whose first `close()` fails with an error that is not about I/O."""

    failed = False

    def close(self) -> None:
        if not self.failed:
            self.failed = True
            raise RuntimeError("the transport is in a bad state")
        super().close()


def test_closing_an_error_reply_never_raises() -> None:
    close_http_error(_error(500, _UnclosableBody(b"gone")))
    close_http_error(_error(500, _BrokenCloseBody(b"gone")))
    close_http_error(ValueError("no reply to close"))
