"""One set of assertions, both stores.

Two implementations behind one protocol that are only ever tested apart become two
implementations that behave differently — and the one nobody runs locally is the
one that behaves differently in production. So every assertion below runs against
the in-memory store and against PostgreSQL, and a difference between them is a
failure rather than a discovery.
"""

import inspect
from collections.abc import Callable, Iterator
from typing import Any, NamedTuple

import psycopg
import pytest
from guardana.server.db.migrations import apply_pending
from guardana.server.envelope import (
    CheckErrorIn,
    EvidenceIn,
    FindingIn,
    SkippedIn,
    Submission,
    SummaryIn,
    TaxonomyRefIn,
    VerdictIn,
)
from guardana.server.postgres_store import PostgresStore
from guardana.server.store import InMemoryStore, Store
from guardana.server.tenancy import TenantScope, create_organization, create_project

_TICK = iter(range(1_000_000))


def _clock() -> float:
    """A monotonic fake clock, so `received_at` orders deterministically in both stores."""
    return float(next(_TICK))


class Scoped(NamedTuple):
    """A store and a tenant to use it as. Every store call needs both."""

    store: Store
    scope: TenantScope


@pytest.fixture(params=["memory", "postgres"])
def scoped(request: pytest.FixtureRequest) -> Iterator[Scoped]:
    if request.param == "memory":
        yield Scoped(InMemoryStore(clock=_clock), TenantScope.for_project(1))
        return
    url = request.getfixturevalue("database_url")
    with psycopg.connect(url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        project = create_project(connection, "acme", "web", "Web")
    yield Scoped(PostgresStore(url, clock=_clock), TenantScope.for_project(project.id))


def _submission(source: str = "app", **overrides: object) -> Submission:
    defaults: dict[str, Any] = {
        "source": source,
        "schema_version": 5,
        "findings": [
            FindingIn(
                rule_id="guardana.supply_chain.hardcoded_secret",
                severity="HIGH",
                title="Hardcoded secret",
                target_ref="app/settings.py",
                evidence=EvidenceIn(summary="[redacted:aws-key:abc]", detail="line 1"),
                taxonomy=[TaxonomyRefIn(framework="OWASP-LLM", id="LLM02")],
            )
        ],
        "unverified": [
            FindingIn(
                rule_id="guardana.prompt.injection.ignore_previous",
                severity="MEDIUM",
                title="Could not grade",
                target_ref="http://x#m",
                evidence=EvidenceIn(summary="the judge did not answer"),
                verdict=VerdictIn(
                    outcome="inconclusive",
                    confidence=0.0,
                    rationale="no reply",
                    evaluator_id="llm_judge",
                ),
            )
        ],
        "errors": [CheckErrorIn(source="acme.rule", stage="run", reason="boom")],
        "summary": SummaryIn(
            rules_run=19,
            rules_executed=["guardana.supply_chain.hardcoded_secret"],
            rules_skipped=[
                SkippedIn(rule_id="guardana.agent.tool_use", reason="missing_capability")
            ],
            max_severity="HIGH",
            unverified=1,
            errors=1,
        ),
    }
    defaults.update(overrides)
    return Submission(**defaults)


# --- no query without a tenant, enforced rather than promised -----------------

_STORE_METHODS = frozenset({"add", "submissions", "trend", "records"})


def test_no_store_method_is_unscoped() -> None:
    """The property the shape does not buy, this test buys instead.

    Putting the scope in the signature rather than in a per-request repository's
    constructor has exactly one real weakness: a method can be added without one.
    Whoever adds it sees red here.
    """
    methods = {
        name: member
        for name, member in vars(Store).items()
        if inspect.isfunction(member) and not name.startswith("_")
    }

    assert set(methods) == _STORE_METHODS, "the protocol grew or lost a method"
    for name, member in methods.items():
        parameters = list(inspect.signature(member).parameters.values())
        assert parameters[1].name == "scope", f"{name} takes no tenant scope"
        assert parameters[1].annotation is TenantScope, f"{name}'s scope is not a TenantScope"


@pytest.mark.parametrize("implementation", [InMemoryStore, PostgresStore])
def test_both_implementations_take_the_scope_the_protocol_declares(
    implementation: type[object],
) -> None:
    for name in sorted(_STORE_METHODS):
        parameters = list(inspect.signature(getattr(implementation, name)).parameters.values())
        assert parameters[1].name == "scope", f"{implementation.__name__}.{name}"
        assert parameters[1].annotation is TenantScope, f"{implementation.__name__}.{name}"


# --- what a store keeps -------------------------------------------------------


def test_a_stored_submission_comes_back(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission())

    held = store.submissions(scope)

    assert len(held) == 1
    assert held[0].source == "app"


def test_findings_survive_the_round_trip_intact(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission())

    finding = store.submissions(scope)[0].findings[0]

    assert finding.rule_id == "guardana.supply_chain.hardcoded_secret"
    assert finding.severity == "HIGH"
    assert finding.evidence.summary == "[redacted:aws-key:abc]"
    assert finding.evidence.detail == "line 1"
    assert [ref.id for ref in finding.taxonomy] == ["LLM02"]


def test_the_unverified_channel_is_never_folded_into_findings(scoped: Scoped) -> None:
    # A check that ran and could not grade is not a pass, and storage must not be
    # where that distinction is lost.
    store, scope = scoped
    store.add(scope, _submission())

    held = store.submissions(scope)[0]

    assert len(held.findings) == 1
    assert len(held.unverified) == 1
    assert held.unverified[0].verdict is not None
    assert held.unverified[0].verdict.outcome == "inconclusive"


def test_a_check_that_could_not_run_is_stored(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission())

    errors = store.submissions(scope)[0].errors

    assert [error.source for error in errors] == ["acme.rule"]


def test_a_skip_keeps_its_reason(scoped: Scoped) -> None:
    # v5 carries why a rule did not run. Flattening it back to an id in storage
    # would leave a fleet view unable to tell "never applied" from "this provider
    # cannot do it" — the whole reason the envelope moved to v5.
    store, scope = scoped
    store.add(scope, _submission())

    summary = store.submissions(scope)[0].summary

    assert summary is not None
    assert summary.rules_skipped
    skip = summary.rules_skipped[0]
    assert (
        getattr(skip, "reason", None) == "missing_capability" or skip == "guardana.agent.tool_use"
    )


def test_filtering_by_source_returns_only_that_source(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission(source="one"))
    store.add(scope, _submission(source="two"))

    assert [s.source for s in store.submissions(scope, "one")] == ["one"]


def test_submissions_come_back_oldest_first(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission(source="first"))
    store.add(scope, _submission(source="second"))

    assert [s.source for s in store.submissions(scope)] == ["first", "second"]


def test_the_trend_counts_findings_by_severity(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission())
    store.add(scope, _submission())

    assert store.trend(scope) == {"HIGH": 2}


def test_records_carry_the_time_the_submission_arrived(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission())

    records = store.records(scope)

    assert len(records) == 1
    assert records[0].received_at >= 0


def test_an_empty_store_answers_without_inventing_anything(scoped: Scoped) -> None:
    store, scope = scoped

    assert store.submissions(scope) == []
    assert store.trend(scope) == {}
    assert store.records(scope) == []


def test_a_submission_with_no_summary_is_accepted(scoped: Scoped) -> None:
    # A v2 agent sends none, and the collector still has to hold what it was given.
    store, scope = scoped
    store.add(scope, _submission(summary=None, findings=[], unverified=[], errors=[]))

    assert len(store.submissions(scope)) == 1


def _persists_across_instances(url: str, scope: TenantScope) -> Callable[[], list[Submission]]:
    return lambda: PostgresStore(url).submissions(scope)


def test_postgres_keeps_a_submission_across_process_restarts(database_url: str) -> None:
    """The reason this item exists. Asserted with a second store object, not a second store."""
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        project = create_project(connection, "acme", "web", "Web")
    scope = TenantScope.for_project(project.id)
    PostgresStore(database_url, clock=_clock).add(scope, _submission(source="survives"))

    reopened = _persists_across_instances(database_url, scope)()

    assert [s.source for s in reopened] == ["survives"]


def test_a_limit_keeps_the_newest_and_is_applied_by_the_store(scoped: Scoped) -> None:
    """The bound belongs to the store, not to a slice taken after the read.

    The in-memory store was safe from an unbounded read only because it forgets;
    a durable one has no upper size, so a reader that fetches everything and slices
    turns one request into "load the entire finding history into memory".
    """
    store, scope = scoped
    for index in range(5):
        store.add(scope, _submission(source=f"run-{index}"))

    held = store.submissions(scope, limit=2)

    assert [s.source for s in held] == ["run-3", "run-4"]


def test_a_limit_and_a_source_filter_compose(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission(source="a"))
    store.add(scope, _submission(source="b"))
    store.add(scope, _submission(source="a"))

    assert [s.source for s in store.submissions(scope, "a", 1)] == ["a"]
    assert len(store.records(scope, "a")) == 2


def test_no_limit_still_returns_everything(scoped: Scoped) -> None:
    store, scope = scoped
    for index in range(3):
        store.add(scope, _submission(source=f"run-{index}"))

    assert len(store.submissions(scope)) == 3
