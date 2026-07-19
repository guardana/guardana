import json
import threading
from typing import Any

from fastapi.testclient import TestClient
from guardana.core.evaluator import Verdict
from guardana.core.report import Evidence, Finding, ScanResult
from guardana.core.reporter import HttpReporter
from guardana.core.severity import Severity
from guardana.core.taxonomy import OWASP_LLM01
from guardana.server import create_app
from guardana.server.store import InMemoryStore

_OK = 200
_UNPROCESSABLE = 422


def _client() -> TestClient:
    return TestClient(create_app())


def _real_envelope(source: str = "ci") -> dict[str, Any]:
    """The exact bytes a Guardana agent would POST — built by the real reporter.

    This is the contract test between engine and collector: the two are
    deliberately decoupled, so nothing but a test like this proves they agree.
    """
    captured: list[bytes] = []
    result = ScanResult(
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
        rules_run=2,
        rules_skipped=(),
    )
    reporter = HttpReporter("http://collector", transport=lambda _url, body: captured.append(body))
    reporter.submit(result, source=source)
    payload: dict[str, Any] = json.loads(captured[0])
    return payload


def test_collector_accepts_the_envelope_the_reporter_actually_sends() -> None:
    response = _client().post("/findings", json=_real_envelope())

    assert response.status_code == _OK
    assert response.json() == {"status": "ok", "stored": 2}


def test_collector_accepts_and_retains_the_unverified_channel() -> None:
    # The reporter forwards checks that ran but could not grade (envelope v2). The
    # collector must accept and keep them — dropping them would recreate the false
    # all-clear at the collector boundary that the channel exists to prevent.
    captured: list[bytes] = []
    result = ScanResult(
        findings=(),
        rules_run=1,
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
    client = TestClient(create_app(store))

    for source in ("a", "b", "c"):
        client.post("/findings", json=_real_envelope(source=source))

    assert [s.source for s in store.list()] == ["b", "c"]


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


def test_concurrent_reads_and_writes_do_not_500() -> None:
    # A full deque evicts on every append; iterating it in `trend()` while a
    # writer appends used to raise "deque mutated during iteration" and 500.
    store = InMemoryStore(max_submissions=50)
    client = TestClient(create_app(store))
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
