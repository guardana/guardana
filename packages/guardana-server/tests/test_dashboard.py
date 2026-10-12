import pytest
from fastapi.testclient import TestClient
from guardana.server import create_app
from guardana.server.envelope import Submission
from guardana.server.rule_catalog import rule_catalog
from guardana.server.stats import STATS_WINDOW
from guardana.server.store import InMemoryStore, StoredSubmission
from guardana.server.tenancy import TenantScope

_OK = 200
_NOT_FOUND = 404


def test_dashboard_is_off_by_default() -> None:
    client = TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))
    assert client.get("/").status_code == _NOT_FOUND
    assert client.get("/stats").status_code == _NOT_FOUND
    assert client.get("/catalog").status_code == _NOT_FOUND
    # The core endpoints are unaffected.
    assert client.get("/trend").status_code == _OK


def test_catalog_endpoint_serves_human_rule_descriptions() -> None:
    client = TestClient(
        create_app(store=InMemoryStore(), dashboard=True, allow_unauthenticated=True)
    )
    catalog = client.get("/catalog").json()
    entry = catalog["guardana.supply_chain.pickle_opcode"]
    assert entry["name"]
    assert entry["description"]


def test_rule_catalog_loader_returns_entries_and_handles_unknown_language() -> None:
    catalog = rule_catalog()
    assert "guardana.prompt.system_prompt_leak.canary" in catalog
    assert rule_catalog("zz") == {}


def test_dashboard_page_and_stats_mount_when_enabled() -> None:
    client = TestClient(
        create_app(store=InMemoryStore(), dashboard=True, allow_unauthenticated=True)
    )

    page = client.get("/")
    assert page.status_code == _OK
    assert "text/html" in page.headers["content-type"]
    assert "Guardana" in page.text
    # The page reads the aggregation endpoint through one helper, so a 401 can be
    # told from an outage: "sign in" and "the collector is down" are different
    # things to put in front of a person.
    assert 'readJson("stats")' in page.text

    stats = client.get("/stats")
    assert stats.status_code == _OK
    body = stats.json()
    assert set(body) >= {"by_severity", "by_source", "by_rule", "series", "totals"}


def test_env_var_enables_the_dashboard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDANA_DASHBOARD", "1")
    client = TestClient(create_app(store=InMemoryStore(), allow_unauthenticated=True))
    assert client.get("/").status_code == _OK


def test_stats_reflects_stored_findings() -> None:
    store = InMemoryStore(clock=lambda: 1.0)
    client = TestClient(create_app(store, dashboard=True, allow_unauthenticated=True))
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


class _RecordingStore(InMemoryStore):
    """An in-memory store that remembers the bound every `records` call asked for."""

    def __init__(self) -> None:
        super().__init__()
        self.limits: list[int | None] = []

    def records(
        self, scope: TenantScope, source: str | None = None, limit: int | None = None
    ) -> list[StoredSubmission]:
        self.limits.append(limit)
        return super().records(scope, source, limit)


def test_stats_never_asks_the_store_for_the_whole_history() -> None:
    """A durable store has no upper size, so an unbounded read is the whole project's past."""
    store = _RecordingStore()
    client = TestClient(create_app(store, dashboard=True, allow_unauthenticated=True))
    store.limits.clear()

    assert client.get("/stats").status_code == _OK

    assert store.limits
    assert all(limit is not None and limit <= STATS_WINDOW + 1 for limit in store.limits)


def test_stats_says_when_it_aggregated_only_the_newest_window() -> None:
    """A capped aggregate must not read as everything the collector holds."""
    store = InMemoryStore()
    scope = TenantScope.unauthenticated()
    for index in range(STATS_WINDOW + 1):
        store.add(scope, Submission(source=f"agent-{index}", schema_version=5))
    client = TestClient(create_app(store, dashboard=True, allow_unauthenticated=True))

    body = client.get("/stats").json()

    assert body["totals"]["submissions"] == STATS_WINDOW
    assert body["window"] == {"limit": STATS_WINDOW, "complete": False}
    assert "agent-0" not in {source["source"] for source in body["by_source"]}


def test_the_page_says_when_the_counts_cover_only_the_newest_window() -> None:
    """A capped aggregate must not read as the whole history on the dashboard either."""
    from guardana.server.dashboard import render_dashboard  # noqa: PLC0415

    page = render_dashboard(30)

    assert "w && !w.complete" in page
    assert "newest submissions (of more than" in page


_SKIPPED_AND_UNDECIDED = {
    "schema_version": 7,
    "source": "https://chat.example/v1",
    "summary": {
        "rules_skipped": [
            {
                "rule_id": "guardana.agent.tool_use",
                "reason": "missing_capability",
                "missing": ["tool_calls"],
            }
        ]
    },
    "run": {"gate": "indeterminate"},
}


def test_stats_carries_skipped_checks_and_recorded_gates() -> None:
    """A run with nothing found, a check skipped and no decision is not a clean run."""
    client = TestClient(create_app(InMemoryStore(), dashboard=True, allow_unauthenticated=True))
    assert client.post("/findings", json=_SKIPPED_AND_UNDECIDED).status_code == _OK

    stats = client.get("/stats").json()

    assert stats["totals"]["findings"] == 0
    assert stats["totals"]["skipped"] == 1
    assert stats["by_gate"] == {"indeterminate": 1}
    assert stats["by_source"][0]["skipped"] == 1
    assert stats["by_source"][0]["gate"] == "indeterminate"


def test_the_page_lists_skipped_checks_and_undecided_gates_beside_findings() -> None:
    from guardana.server.dashboard import render_dashboard  # noqa: PLC0415

    page = render_dashboard(30)

    assert ".flatMap(itemsOf)" in page
    assert "(sub.summary || {}).rules_skipped" in page
    assert 's.reason !== "not_applicable"' in page
    assert 'gate === "indeterminate"' in page
    assert "skipped checks" in page
    assert "indeterminate gates" in page
    assert "gate not recorded" in page
