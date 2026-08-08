"""The collector holds no catalogue, so the agent has to send the title (v8).

A short id stopped being self-explanatory the day a framework published a second
edition: `LLM07` is System Prompt Leakage in `OWASP-LLM-2025` and Misinformation in
`OWASP-LLM-2026`. The collector cannot look one up — it never imports the engine,
which is the whole architecture — so a dashboard chip reading `LLM07` is a chip
nobody can act on. The identity stays `framework` + `id`; the title is what makes
it readable.

Backwards compatibility runs the other way: a v2-to-v7 agent sends no title, and
that is honest, because it could not observe one. The collector never fills it in.
"""

from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.envelope import SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS, TaxonomyRefIn
from guardana.server.store import InMemoryStore

_OK = 200


def _client() -> TestClient:
    return TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))


def _submission(taxonomy: list[dict[str, str]], version: int = SCHEMA_VERSION) -> dict[str, object]:
    return {
        "source": "agent",
        "schema_version": version,
        "findings": [
            {
                "rule_id": "guardana.prompt.system_prompt_leak.canary",
                "severity": "CRITICAL",
                "title": "System prompt leakage via canary marker",
                "target_ref": "http://x#m",
                "evidence": {"summary": "canary found"},
                "taxonomy": taxonomy,
            }
        ],
    }


def test_the_current_version_is_accepted_and_the_title_is_stored() -> None:
    client = _client()

    posted = client.post(
        "/findings",
        json=_submission(
            [{"framework": "OWASP-LLM-2025", "id": "LLM07", "title": "System Prompt Leakage"}]
        ),
    )
    assert posted.status_code == _OK, posted.text

    (submission,) = client.get("/findings").json()
    (finding,) = submission["findings"]
    assert finding["taxonomy"] == [
        {"framework": "OWASP-LLM-2025", "id": "LLM07", "title": "System Prompt Leakage"}
    ]


def test_an_older_agent_sends_no_title_and_is_still_accepted() -> None:
    client = _client()

    posted = client.post(
        "/findings",
        json=_submission([{"framework": "OWASP-LLM-2025", "id": "LLM07"}], version=7),
    )

    assert posted.status_code == _OK, posted.text
    (submission,) = client.get("/findings").json()
    (finding,) = submission["findings"]
    assert finding["taxonomy"][0]["title"] is None, (
        "the collector holds no catalogue; a title it invented would be a guess at an edition"
    )


def test_the_previous_envelope_versions_stay_supported() -> None:
    # A fleet upgrades one agent at a time. Dropping a version here would take a
    # working agent offline on a collector upgrade.
    assert frozenset(range(2, SCHEMA_VERSION + 1)) == SUPPORTED_SCHEMA_VERSIONS


def test_the_identity_is_the_pair_not_the_short_id() -> None:
    ref = TaxonomyRefIn(framework="OWASP-LLM-2026", id="LLM07", title="Misinformation")

    assert ref.framework == "OWASP-LLM-2026"
    assert ref.id == "LLM07"
