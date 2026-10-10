"""Bounds on what one caller can send, and how often.

An ingest endpoint with no limits is a denial of service with a nice API: one
misconfigured agent in a fleet, or one loop in a pipeline, and the collector's
disk or its database connections are gone — and the runs nobody could submit are
the runs nobody notices are missing.

Both limits are deliberately modest and both are honest about what they are. The
rate limiter lives in the process, so a deployment running four workers has four
times the limit; that is written down rather than implied, because a limit
somebody believes is global and is not is worse than one they know they have to
put a proxy in front of.
"""

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from guardana.server.app import _credential, create_app
from guardana.server.auth import Scope
from guardana.server.limits import Limits, RateLimiter
from guardana.server.store import InMemoryStore
from test_authentication import _bearer, _issue, _migrated

_TOO_MANY = 429
_TOO_LARGE = 413
_OK = 200
_UNAUTHORIZED = 401
_UNAVAILABLE = 503


@pytest.fixture
def collector(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("GUARDANA_STORAGE", "memory")
    monkeypatch.setenv("GUARDANA_ALLOW_UNAUTHENTICATED", "1")
    return TestClient(create_app(InMemoryStore(), allow_unauthenticated=True))


def test_a_body_over_the_limit_is_refused_before_it_is_parsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`413`, not a validation error: the size is the objection, not the shape."""
    monkeypatch.setenv("GUARDANA_MAX_BODY_BYTES", "2048")
    client = TestClient(create_app(InMemoryStore(), allow_unauthenticated=True))

    response = client.post(
        "/findings", content=b"x" * 4096, headers={"Content-Type": "application/json"}
    )

    assert response.status_code == _TOO_LARGE
    assert "too large" in response.json()["detail"]


def test_a_body_under_the_limit_still_reaches_the_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The limit must not become the reason nothing works: a small body is unaffected."""
    monkeypatch.setenv("GUARDANA_MAX_BODY_BYTES", "2048")
    client = TestClient(create_app(InMemoryStore(), allow_unauthenticated=True))

    response = client.post("/findings", json={"source": "app", "schema_version": 7})

    # Whatever the route decides, it decided it: the size check let it through,
    # which is the point. A limiter that also blocks ordinary traffic is a limiter
    # somebody turns off.
    assert response.status_code != _TOO_LARGE


def test_a_lying_content_length_does_not_get_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """The header is a claim; the bytes are the fact.

    A limiter that trusts `Content-Length` is bypassed by not sending one, which is
    exactly what a chunked request does.
    """
    monkeypatch.setenv("GUARDANA_MAX_BODY_BYTES", "1024")
    client = TestClient(create_app(InMemoryStore(), allow_unauthenticated=True))

    def chunks() -> "list[bytes]":
        return [b"x" * 512] * 8

    response = client.post(
        "/findings", content=iter(chunks()), headers={"Content-Type": "application/json"}
    )

    assert response.status_code == _TOO_LARGE


def test_health_is_never_rate_limited(collector: TestClient) -> None:
    """An orchestrator probing every ten seconds must not be told to slow down.

    A readiness probe answered `429` is a rolling deploy that stalls, which is a
    self-inflicted outage caused by a control meant to prevent one.
    """
    limits = Limits(max_body_bytes=1024, requests_per_minute=1)
    limiter = RateLimiter(limits, clock=lambda: 0.0)

    assert limiter.allows("1.2.3.4", path="/healthz")
    assert limiter.allows("1.2.3.4", path="/healthz")
    assert limiter.allows("1.2.3.4", path="/readyz")


def test_the_limiter_refuses_past_the_allowance(monkeypatch: pytest.MonkeyPatch) -> None:
    now = 0.0
    limiter = RateLimiter(Limits(max_body_bytes=1024, requests_per_minute=2), clock=lambda: now)

    assert limiter.allows("key:1", path="/findings")
    assert limiter.allows("key:1", path="/findings")
    assert not limiter.allows("key:1", path="/findings")


def test_the_allowance_returns_with_time() -> None:
    """A limiter that never forgives is an outage with a timer on it."""
    now = 0.0
    limiter = RateLimiter(Limits(max_body_bytes=1024, requests_per_minute=2), clock=lambda: now)
    limiter.allows("key:1", path="/findings")
    limiter.allows("key:1", path="/findings")

    now = 61.0

    assert limiter.allows("key:1", path="/findings")


def test_one_caller_cannot_spend_another_callers_allowance() -> None:
    """Or the first noisy agent in a fleet silences every other one."""
    limiter = RateLimiter(Limits(max_body_bytes=1024, requests_per_minute=1), clock=lambda: 0.0)
    limiter.allows("key:1", path="/findings")

    assert limiter.allows("key:2", path="/findings")


def test_ingest_answers_429_when_the_rate_is_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    """And says how long to wait, so a client backs off rather than hammering."""
    monkeypatch.setenv("GUARDANA_RATE_LIMIT_PER_MINUTE", "1")
    client = TestClient(create_app(InMemoryStore(), allow_unauthenticated=True))

    client.post("/findings", json={})
    response = client.post("/findings", json={})

    assert response.status_code == _TOO_MANY
    assert response.headers["Retry-After"]


def test_limits_can_be_turned_off_but_only_by_saying_so(monkeypatch: pytest.MonkeyPatch) -> None:
    """`0` is an explicit decision; an absent variable gets the default, never none."""
    monkeypatch.setenv("GUARDANA_RATE_LIMIT_PER_MINUTE", "0")
    limits = Limits.from_environment()

    assert limits.requests_per_minute == 0

    monkeypatch.delenv("GUARDANA_RATE_LIMIT_PER_MINUTE")
    assert Limits.from_environment().requests_per_minute > 0


def test_a_nonsense_limit_is_refused_at_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    """A typo in a limit must not silently become "no limit"."""
    monkeypatch.setenv("GUARDANA_MAX_BODY_BYTES", "eight megabytes")

    with pytest.raises(ValueError, match="GUARDANA_MAX_BODY_BYTES"):
        Limits.from_environment()


def test_a_declared_oversize_is_refused_before_the_body_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An honest client is turned away without a byte of its body being buffered."""
    monkeypatch.setenv("GUARDANA_MAX_BODY_BYTES", "16")
    client = TestClient(create_app(InMemoryStore(), allow_unauthenticated=True))

    response = client.post(
        "/findings",
        content=b"x" * 64,
        headers={"Content-Type": "application/json", "Content-Length": "64"},
    )

    assert response.status_code == _TOO_LARGE


def test_a_body_that_passed_the_check_still_reaches_the_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The middleware consumes the stream, so it has to hand the body on.

    Without that the route awaits a stream that has already ended, sees an empty
    body, and every submission fails validation — a limiter that breaks the thing
    it was protecting.
    """
    monkeypatch.setenv("GUARDANA_MAX_BODY_BYTES", "65536")
    client = TestClient(create_app(InMemoryStore(), allow_unauthenticated=True))

    response = client.post("/findings", json={"source": "app", "schema_version": 7})

    assert response.status_code == _OK
    assert response.json()["status"] == "ok"


def test_the_limiter_forgets_callers_that_went_quiet() -> None:
    """One entry per caller, keyed on a peer address, would otherwise grow forever."""
    now = 0.0
    limiter = RateLimiter(Limits(max_body_bytes=1024, requests_per_minute=5), clock=lambda: now)
    for caller in range(10_100):
        limiter.allows(f"peer:{caller}", path="/findings")

    now = 200.0
    limiter.allows("peer:new", path="/findings")

    assert len(limiter._seen) < 10_100


def test_the_limiter_stays_bounded_while_every_caller_is_active() -> None:
    """Callers that are all still inside their minute cannot be swept as quiet ones."""
    limiter = RateLimiter(Limits(max_body_bytes=1024, requests_per_minute=5), clock=lambda: 0.0)

    for caller in range(10_100):
        limiter.allows(f"peer:{caller}", path="/findings")

    assert len(limiter._seen) <= 10_000


def test_a_credential_earns_its_own_allowance_only_once_it_was_accepted() -> None:
    limiter = RateLimiter(Limits(max_body_bytes=1024, requests_per_minute=5), clock=lambda: 0.0)

    assert limiter.caller_for("peer:1", "token:a") == "peer:1"
    limiter.vouch("token:a")
    assert limiter.caller_for("peer:1", "token:a") == "token:a"
    limiter.forget("token:a")
    assert limiter.caller_for("peer:1", "token:a") == "peer:1"


def _unverifiable_collector(monkeypatch: pytest.MonkeyPatch, per_minute: int) -> TestClient:
    """A key-checking collector whose database is down, so no credential is ever accepted."""
    monkeypatch.setenv("GUARDANA_DATABASE_URL", "postgresql://guardana@127.0.0.1:1/absent")
    monkeypatch.delenv("GUARDANA_MIGRATE_ON_START", raising=False)
    monkeypatch.setenv("GUARDANA_RATE_LIMIT_PER_MINUTE", str(per_minute))
    return TestClient(create_app())


def test_rotating_bogus_tokens_does_not_buy_a_fresh_allowance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A token nobody accepted is no identity, so its requests are charged to the peer."""
    client = _unverifiable_collector(monkeypatch, per_minute=3)

    statuses = [
        client.get("/findings", headers={"Authorization": f"Bearer invalid{index}"}).status_code
        for index in range(6)
    ]

    assert statuses[:3] == [_UNAVAILABLE] * 3
    assert statuses[3:] == [_TOO_MANY] * 3


def test_an_accepted_key_keeps_its_allowance_while_bogus_tokens_exhaust_the_peer(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An agent sharing an address with an attacker is not locked out by the attacker."""
    _migrated(database_url)
    token = _issue(database_url, "ci", (Scope.READ,))
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    monkeypatch.setenv("GUARDANA_RATE_LIMIT_PER_MINUTE", "3")
    client = TestClient(create_app())

    assert client.get("/findings", headers=_bearer(token)).status_code == _OK
    rejected = [
        client.get("/findings", headers=_bearer(f"gdn_bogus{index}")).status_code
        for index in range(3)
    ]

    assert rejected == [_UNAUTHORIZED, _UNAUTHORIZED, _TOO_MANY]
    assert client.get("/findings", headers=_bearer(token)).status_code == _OK


_SPELLINGS = ("Bearer", "bearer", "BEARER")


def _request(authorization: str) -> Request:
    return Request({"type": "http", "headers": [(b"authorization", authorization.encode())]})


def test_every_spelling_of_the_bearer_scheme_is_one_rate_limit_caller() -> None:
    keys = {_credential(_request(f"{scheme} gdn_test_token ")) for scheme in _SPELLINGS}

    assert len(keys) == 1
    assert None not in keys


def test_a_header_that_is_not_a_bearer_token_is_charged_to_the_peer() -> None:
    assert _credential(_request("Basic dXNlcjpwYXNz")) is None
    assert _credential(_request("Bearer ")) is None


def test_respelling_the_scheme_does_not_buy_a_key_a_fresh_allowance(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Authentication reads the scheme in any case, so the limiter has to as well."""
    _migrated(database_url)
    token = _issue(database_url, "ci", (Scope.READ,))
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    monkeypatch.setenv("GUARDANA_RATE_LIMIT_PER_MINUTE", "3")
    client = TestClient(create_app())

    # The first request is charged to the peer and earns the key its own allowance,
    # which the next three spend.
    spent = [client.get("/findings", headers=_bearer(token)).status_code for _ in range(4)]
    respelled = [
        client.get("/findings", headers={"Authorization": f"{scheme} {token}"}).status_code
        for scheme in _SPELLINGS
    ]

    assert spent == [_OK] * 4
    assert respelled == [_TOO_MANY] * 3
