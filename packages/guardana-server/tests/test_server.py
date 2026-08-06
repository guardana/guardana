import json
import threading
from typing import Any
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient
from guardana.core.evaluator import Verdict
from guardana.core.manifest import DeploymentRef
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.reporter import HttpReporter
from guardana.core.severity import Severity
from guardana.core.taxonomy import OWASP_LLM01
from guardana.server import create_app
from guardana.server.envelope import SCHEMA_VERSION
from guardana.server.store import InMemoryStore
from guardana.server.tenancy import TenantScope

_OK = 200
_UNPROCESSABLE = 422


def _client() -> TestClient:
    return TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))


def _result() -> ScanResult:
    """One run with two findings — the input every envelope below is built from."""
    return ScanResult(
        findings=(
            Finding(
                rule_id="guardana.prompt.injection.ignore_previous",
                severity=Severity.HIGH,
                title="Prompt injection succeeded",
                taxonomy=(OWASP_LLM01,),
                target_ref="https://target#model",
                evidence=Evidence(summary="model followed injected instruction"),
                verdict=Verdict(
                    outcome="fail", confidence=0.9, rationale="complied", evaluator_id="keyword"
                ),
            ),
            Finding(
                rule_id="guardana.supply_chain.pickle_opcode",
                severity=Severity.CRITICAL,
                title="Unsafe pickle opcode",
                taxonomy=(),
                target_ref="model.pkl",
                evidence=Evidence(summary="GLOBAL opcode found"),
            ),
        ),
        rules_run=("r0", "r1"),
        rules_skipped=(),
    )


def _real_envelope(source: str = "ci") -> dict[str, Any]:
    """The exact bytes a Guardana agent would POST — built by the real reporter.

    This is the contract test between engine and collector: the two are
    deliberately decoupled, so nothing but a test like this proves they agree.
    """
    captured: list[bytes] = []
    reporter = HttpReporter("http://collector", transport=lambda _url, body: captured.append(body))
    reporter.submit(_result(), source=source)
    payload: dict[str, Any] = json.loads(captured[0])
    return payload


def test_collector_accepts_the_envelope_the_reporter_actually_sends() -> None:
    response = _client().post("/findings", json=_real_envelope())

    assert response.status_code == _OK
    # `accepted_by` names the credential that wrote the run and `project` the tenant
    # it wrote into — both None here, because this app was built in the
    # explicitly-unauthenticated evaluation mode where there is neither.
    assert response.json() == {
        "status": "ok",
        "duplicate": False,
        "stored": 2,
        "accepted_by": None,
        "project": None,
    }


def test_collector_accepts_and_retains_the_unverified_channel() -> None:
    # The reporter forwards checks that ran but could not grade (envelope v2). The
    # collector must accept and keep them — dropping them would recreate the false
    # all-clear at the collector boundary that the channel exists to prevent.
    captured: list[bytes] = []
    result = ScanResult(
        findings=(),
        rules_run=("r0",),
        rules_skipped=(),
        unverified=(
            Finding(
                rule_id="guardana.prompt.system_prompt_leak.canary",
                severity=Severity.CRITICAL,
                title="System prompt leak",
                taxonomy=(OWASP_LLM01,),
                target_ref="https://target#model",
                evidence=Evidence(summary="no reply to grade"),
                verdict=Verdict(
                    outcome="inconclusive", confidence=0.0, rationale="empty", evaluator_id="canary"
                ),
            ),
        ),
    )
    HttpReporter("http://c", transport=lambda _url, body: captured.append(body)).submit(
        result, source="ci"
    )
    envelope = json.loads(captured[0])

    client = _client()
    assert client.post("/findings", json=envelope).status_code == _OK
    stored = client.get("/findings").json()
    assert len(stored[0]["unverified"]) == 1
    assert stored[0]["summary"]["unverified"] == 1


def test_get_findings_returns_stored_submission() -> None:
    client = _client()
    client.post("/findings", json=_real_envelope(source="ci"))

    response = client.get("/findings")

    assert response.status_code == _OK
    body = response.json()
    assert len(body) == 1
    assert body[0]["source"] == "ci"


def test_get_findings_filters_by_source() -> None:
    client = _client()
    client.post("/findings", json=_real_envelope(source="ci"))

    response = client.get("/findings", params={"source": "other"})

    assert response.status_code == _OK
    assert response.json() == []


def test_get_trend_reflects_severity_counts() -> None:
    client = _client()
    client.post("/findings", json=_real_envelope())

    response = client.get("/trend")

    assert response.status_code == _OK
    assert response.json() == {"HIGH": 1, "CRITICAL": 1}


def test_malformed_submission_is_rejected_and_cannot_poison_trend() -> None:
    # A collector that 500s on every /trend after one bad POST would be trivially
    # DoS-able; a malformed body must be refused at the door instead.
    client = _client()

    response = client.post("/findings", json={"source": "ci", "findings": ["not-a-finding"]})

    assert response.status_code == _UNPROCESSABLE
    assert client.get("/trend").status_code == _OK
    assert client.get("/trend").json() == {}
    assert client.get("/findings").json() == []


def test_submission_without_a_source_is_rejected() -> None:
    response = _client().post("/findings", json={"findings": []})

    assert response.status_code == _UNPROCESSABLE


def test_unknown_schema_version_is_rejected() -> None:
    envelope = _real_envelope()
    envelope["schema_version"] = 99

    response = _client().post("/findings", json=envelope)

    assert response.status_code == _UNPROCESSABLE
    assert "schema_version" in response.json()["detail"]


def test_store_is_bounded_so_a_long_running_collector_cannot_grow_without_limit() -> None:
    store = InMemoryStore(max_submissions=2)
    client = TestClient(create_app(store, allow_unauthenticated=True))

    for source in ("a", "b", "c"):
        client.post("/findings", json=_real_envelope(source=source))

    assert [s.source for s in store.submissions(TenantScope.unauthenticated())] == ["b", "c"]


def test_omitted_schema_version_is_rejected_not_assumed() -> None:
    # Guessing an absent version as v1 is exactly what versioning exists to prevent.
    envelope = _real_envelope()
    del envelope["schema_version"]

    assert _client().post("/findings", json=envelope).status_code == _UNPROCESSABLE


def test_an_oversized_body_is_rejected_at_the_door() -> None:
    # The store bounds submission COUNT; without a per-body cap one POST could
    # still exhaust memory. Pydantic must reject it before anything is stored.
    envelope = _real_envelope()
    envelope["findings"] = envelope["findings"] * 5000  # well over the cap
    client = _client()

    assert client.post("/findings", json=envelope).status_code == _UNPROCESSABLE
    assert client.get("/findings").json() == []


def test_get_findings_is_paginated_newest_first() -> None:
    client = _client()
    for i in range(5):
        client.post("/findings", json=_real_envelope(source=f"run{i}"))

    body = client.get("/findings", params={"limit": 2}).json()

    assert [s["source"] for s in body] == ["run4", "run3"]


def test_get_findings_rejects_an_absurd_limit() -> None:
    assert _client().get("/findings", params={"limit": 100_000}).status_code == _UNPROCESSABLE


def test_concurrent_reads_and_writes_do_not_500(monkeypatch: pytest.MonkeyPatch) -> None:
    # A full deque evicts on every append; iterating it in `trend()` while a
    # writer appends used to raise "deque mutated during iteration" and 500.
    #
    # The rate limit is turned off here on purpose: 1200 requests from one caller
    # in a few seconds is exactly what it exists to refuse, and this test is about
    # the store rather than about the limiter.
    monkeypatch.setenv("GUARDANA_RATE_LIMIT_PER_MINUTE", "0")
    store = InMemoryStore(max_submissions=50)
    client = TestClient(create_app(store, allow_unauthenticated=True))
    payload = _real_envelope()
    errors: list[str] = []
    iterations = 150

    def writer() -> None:
        for _ in range(iterations):
            client.post("/findings", json=payload)

    def reader() -> None:
        for _ in range(iterations):
            if client.get("/trend").status_code != _OK:
                errors.append("trend 500")
            if client.get("/findings").status_code != _OK:
                errors.append("findings 500")

    threads = [threading.Thread(target=writer) for _ in range(3)]
    threads += [threading.Thread(target=reader) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []


def test_collector_accepts_a_v2_agent_that_cannot_report_errors() -> None:
    # A fleet upgrades one agent at a time. A v2 agent simply reports no errors —
    # honest, because a v2 agent could not observe them — and must not be rejected.
    client = TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))
    response = client.post(
        "/findings",
        json={"source": "old-agent", "schema_version": 2, "findings": [], "unverified": []},
    )
    assert response.status_code == _OK


def test_collector_retains_the_errors_channel() -> None:
    # An agent whose checks are crashing must not render as clean on a dashboard —
    # the same reason v2 had to carry `unverified`, one layer further out.
    client = TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))
    payload = {
        "source": "ci",
        "schema_version": 3,
        "findings": [],
        "unverified": [],
        "errors": [{"source": "acme.buggy", "stage": "run", "reason": "ValueError: typo"}],
        "summary": {"rules_run": 3, "errors": 1},
    }
    assert client.post("/findings", json=payload).status_code == _OK

    stored = client.get("/findings").json()
    assert stored[0]["errors"][0]["source"] == "acme.buggy"
    assert stored[0]["summary"]["errors"] == 1


def test_collector_still_rejects_a_version_it_does_not_speak() -> None:
    client = TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))
    response = client.post(
        "/findings", json={"source": "future", "schema_version": 99, "findings": []}
    )
    assert response.status_code == _UNPROCESSABLE


def test_collector_accepts_the_v4_envelope_and_keeps_which_rules_ran() -> None:
    """A count cannot separate a clean fleet from a fleet with a narrowed profile.

    Without the names, an agent that excluded half its rules reports the same
    "0 findings" a fully-covered agent does, and the dashboard shows both green.
    """
    store = InMemoryStore()
    response = TestClient(create_app(store, allow_unauthenticated=True)).post(
        "/findings",
        json={
            "source": "agent",
            "schema_version": 4,
            "findings": [],
            "summary": {"rules_run": 2, "rules_executed": ["guardana.a", "guardana.b"]},
        },
    )

    assert response.status_code == _OK
    summary = store.submissions(TenantScope.unauthenticated())[0].summary
    assert summary is not None
    assert summary.rules_executed == ["guardana.a", "guardana.b"]


def test_the_reporter_reaches_the_collector_at_the_url_a_user_writes() -> None:
    """The documented command end to end: `--reporter server://http://host:port`.

    The envelope contract above posts the reporter's bytes to `/findings` by hand,
    which proves the two agree on the *body* and nothing at all about the *path*.
    Aimed at the bare collector URL every doc shows, the reporter POSTed to `/`,
    which no collector serves — so the submission came back `404`, the CLI printed a
    warning, and the scan still exited `0`. A whole fleet reporting nothing while a
    dashboard shows stale data as current is the failure this project says matters
    most, and only a test that goes through the real app can see it.
    """
    client = _client()
    reached: list[str] = []

    def through_the_running_app(url: str, payload: bytes) -> None:
        reached.append(url)
        client.post(
            urlsplit(url).path, content=payload, headers={"Content-Type": "application/json"}
        ).raise_for_status()

    HttpReporter("http://collector", transport=through_the_running_app).submit(
        _result(), source="ci"
    )

    assert reached == ["http://collector/findings"]
    assert len(client.get("/findings").json()) == 1


def test_a_reporter_url_that_already_names_the_route_is_left_alone() -> None:
    # Somebody behind a reverse proxy may well point at the full path; appending a
    # second `/findings` to it would break a configuration that works today.
    reached: list[str] = []

    HttpReporter(
        "https://collector.example.com/guardana/findings",
        transport=lambda url, _payload: reached.append(url),
    ).submit(_result(), source="ci")

    assert reached == ["https://collector.example.com/guardana/findings"]


def test_the_collector_accepts_the_deployment_block_the_reporter_actually_sends() -> None:
    """v6, built by the engine's serializer rather than by hand.

    A hand-written dict proves the collector accepts what the *test author* thinks
    the agent sends. The only thing that proves the two agree is the real bytes —
    which is the lesson the `/findings` path taught the expensive way.
    """
    reporter = HttpReporter(
        "http://collector",
        deployment=DeploymentRef(
            ai_system="support-agent",
            environment="production",
            deployment_id="2026-08-05.3",
            commit_sha="abc1234",
            model_name="gpt-4o-mini",
        ),
        transport=lambda _url, _body: None,
    )
    captured: list[bytes] = []
    reporter._transport = lambda _url, body: captured.append(body)

    reporter.submit(_result(), source="ci")
    envelope = json.loads(captured[0])

    assert envelope["schema_version"] == SCHEMA_VERSION
    client = _client()
    assert client.post("/findings", json=envelope).status_code == _OK
    stored = client.get("/findings").json()[0]
    assert stored["deployment"]["ai_system"] == "support-agent"
    assert stored["deployment"]["environment"] == "production"
    assert stored["deployment"]["commit_sha"] == "abc1234"


def test_a_run_that_declares_nothing_sends_no_deployment_block() -> None:
    # A block of eight nulls is noise on the wire and a lie in a listing: "declared
    # nothing" and "declared eight unknowns" must not look different.
    assert "deployment" not in _real_envelope()


def test_a_v5_agent_still_reports_to_a_v6_collector() -> None:
    """A fleet upgrades one agent at a time; the collector must not require the newest."""
    envelope = _real_envelope()
    envelope["schema_version"] = 5

    client = _client()

    assert client.post("/findings", json=envelope).status_code == _OK
    assert client.get("/findings").json()[0]["deployment"] is None
