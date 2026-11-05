"""What the collector answers to an accepted envelope is what the reporter reads as acknowledged.

The agent accepts only a JSON object whose `status` is `ok`, so the two halves are pinned
together here: a collector that changed its answer would turn every delivery a profile
requires into a failure.
"""

from fastapi.testclient import TestClient
from guardana.core.report import ScanResult
from guardana.core.reporter import HttpReporter, _acknowledgement
from guardana.server import create_app
from guardana.server.store import InMemoryStore

_UNPROCESSABLE = 422


def _client() -> TestClient:
    return TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))


def test_the_collectors_answer_to_a_stored_and_a_repeated_run_is_an_acknowledgement() -> None:
    client = _client()
    answers: list[bytes] = []

    def through_the_running_app(url: str, payload: bytes) -> None:
        response = client.post(
            "/findings", content=payload, headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        answers.append(response.content)

    reporter = HttpReporter("http://collector", transport=through_the_running_app)
    reporter.submit(ScanResult((), (), ()), source="ci")
    reporter.submit(ScanResult((), (), ()), source="ci")

    assert len(answers) == 2
    assert all(_acknowledgement(answer) is not None for answer in answers)


def test_the_collectors_refusal_is_not_an_acknowledgement() -> None:
    response = _client().post("/findings", json={"schema_version": 999, "source": "ci"})

    assert response.status_code == _UNPROCESSABLE
    assert _acknowledgement(response.content) is None
