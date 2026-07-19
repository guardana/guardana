import pytest
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.rule_catalog import rule_catalog
from guardana.server.store import InMemoryStore

_OK = 200
_NOT_FOUND = 404


def test_dashboard_is_off_by_default() -> None:
    client = TestClient(create_app())
    assert client.get("/").status_code == _NOT_FOUND
    assert client.get("/stats").status_code == _NOT_FOUND
    assert client.get("/catalog").status_code == _NOT_FOUND
    # The core endpoints are unaffected.
    assert client.get("/trend").status_code == _OK


def test_catalog_endpoint_serves_human_rule_descriptions() -> None:
    client = TestClient(create_app(dashboard=True))
    catalog = client.get("/catalog").json()
    entry = catalog["guardana.supply_chain.pickle_opcode"]
    assert entry["name"]
    assert entry["description"]


def test_rule_catalog_loader_returns_entries_and_handles_unknown_language() -> None:
    catalog = rule_catalog()
    assert "guardana.prompt.system_prompt_leak.canary" in catalog
    assert rule_catalog("zz") == {}


def test_dashboard_page_and_stats_mount_when_enabled() -> None:
    client = TestClient(create_app(dashboard=True))

    page = client.get("/")
    assert page.status_code == _OK
    assert "text/html" in page.headers["content-type"]
    assert "Guardana" in page.text
    assert 'fetch("stats")' in page.text  # the page fetches the aggregation endpoint

    stats = client.get("/stats")
    assert stats.status_code == _OK
    body = stats.json()
    assert set(body) >= {"by_severity", "by_source", "by_rule", "series", "totals"}


def test_env_var_enables_the_dashboard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDANA_DASHBOARD", "1")
    client = TestClient(create_app())
    assert client.get("/").status_code == _OK


def test_stats_reflects_stored_findings() -> None:
    store = InMemoryStore(clock=lambda: 1.0)
    client = TestClient(create_app(store, dashboard=True))
    envelope = {
        "schema_version": 2,
        "source": "ci#model",
        "findings": [
            {
                "rule_id": "guardana.prompt.injection.ignore_previous",
                "severity": "HIGH",
                "title": "t",
                "target_ref": "ref",
                "evidence": {"summary": "s"},
            }
        ],
        "unverified": [],
    }
    assert client.post("/findings", json=envelope).status_code == _OK

    stats = client.get("/stats").json()
    assert stats["by_severity"] == {"HIGH": 1}
    assert stats["totals"]["findings"] == 1
    assert stats["by_source"][0]["source"] == "ci#model"
