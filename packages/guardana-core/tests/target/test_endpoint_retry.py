"""Guards for the retry/backoff around a served model's rate limits.

A probe sends many requests to one endpoint, so a 429 is an ordinary event, not
an outage — and the runner treats a connection failure as fatal to the whole run
(every rule would fail identically). Without a retry, one rate-limited request
therefore aborted the entire probe. Concurrency makes that likelier, so the two
land together.

The rule that matters: a retry may only turn a *transient* refusal into a real
answer. It must never turn a genuine failure into silence.
"""

import json
from urllib.error import HTTPError

import pytest
from guardana.core.target.endpoint import _MAX_BACKOFF_SECONDS as _MAX_BACKOFF
from guardana.core.target.endpoint import EndpointError, post_json

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

    monkeypatch.setattr("guardana.core.target.endpoint.urlopen", fake_urlopen)
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
