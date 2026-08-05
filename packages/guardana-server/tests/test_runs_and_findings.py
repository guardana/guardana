"""A run the collector can answer questions about, and a finding it can follow.

Three questions failed on the same missing facts before this: is production
failing, has this finding been there since Tuesday, and did that pipeline actually
run. All three are about the *run*, and a submission said nothing about one.
"""

from datetime import UTC, datetime

import psycopg
import pytest
from conftest import Scoped, _clock, _submission
from guardana.server.db.migrations import apply_pending
from guardana.server.envelope import EvidenceIn, FindingIn, RunIn
from guardana.server.postgres_store import PostgresStore
from guardana.server.store import InMemoryStore, Store
from guardana.server.tenancy import TenantScope, create_organization, create_project
from pydantic import ValidationError


def _run(gate: str | None = "fail", run_id: str | None = "run-1") -> RunIn:
    return RunIn(
        run_id=run_id,
        started_at=datetime(2026, 8, 5, 10, 0, tzinfo=UTC),
        completed_at=datetime(2026, 8, 5, 10, 0, 12, tzinfo=UTC),
        tool_version="0.9.0",
        gate=gate,
        evidence_mode="redacted",
        requests=12,
        input_tokens=340,
        output_tokens=180,
        wall_time_seconds=12.5,
    )


def _finding(identity: str, rule_id: str = "guardana.prompt.injection") -> FindingIn:
    return FindingIn(
        identity=identity,
        rule_id=rule_id,
        severity="HIGH",
        title="Prompt injection",
        target_ref="http://model#m",
        evidence=EvidenceIn(summary="the model complied"),
    )


# --- the run's own facts ------------------------------------------------------


def test_a_failing_run_is_stored_as_failing(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission(run=_run(gate="fail")))

    held = store.submissions(scope)[0].run

    assert held is not None
    assert held.gate == "fail"
    assert held.tool_version == "0.9.0"
    assert held.requests == 12


def test_a_run_that_did_not_say_is_unknown_and_not_a_pass(scoped: Scoped) -> None:
    """A fleet with one old agent must not read as green because the old one cannot speak."""
    store, scope = scoped
    store.add(scope, _submission(run=None))

    held = store.submissions(scope)[0].run

    assert held is None, "absence must stay absence"


def test_a_run_with_no_gate_is_not_recorded_as_passing(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission(run=_run(gate=None)))

    held = store.submissions(scope)[0].run

    assert held is not None
    assert held.gate is None
    assert held.gate != "pass"


def test_the_cost_of_a_run_survives_the_round_trip(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(scope, _submission(run=_run()))

    held = store.submissions(scope)[0].run

    assert held is not None
    assert (held.input_tokens, held.output_tokens) == (340, 180)
    assert held.wall_time_seconds == 12.5


# --- the same run twice -------------------------------------------------------


def test_the_same_run_submitted_twice_is_stored_once(database_url: str) -> None:
    """A retried pipeline job is not two runs, and must not double the findings.

    Without this, "production got worse" answers from a duplicate — which is the
    same class of wrong answer as a false green, reached from the other side.
    """
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        project = create_project(connection, "acme", "web", "Web")
    scope = TenantScope.for_project(project.id)
    store = PostgresStore(database_url, clock=_clock)

    store.add(scope, _submission(source="ci", run=_run(run_id="retried")))
    store.add(scope, _submission(source="ci", run=_run(run_id="retried")))

    assert len(store.submissions(scope)) == 1
    assert store.trend(scope) == {"HIGH": 1}


def test_two_runs_that_identify_nothing_are_both_stored(database_url: str) -> None:
    # A pre-v7 agent names no run, so nothing may be treated as a duplicate.
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        project = create_project(connection, "acme", "web", "Web")
    scope = TenantScope.for_project(project.id)
    store = PostgresStore(database_url, clock=_clock)

    store.add(scope, _submission(source="ci", run=_run(run_id=None)))
    store.add(scope, _submission(source="ci", run=_run(run_id=None)))

    assert len(store.submissions(scope)) == 2


# --- following one finding across runs ---------------------------------------


def test_a_finding_keeps_its_identity_across_runs(scoped: Scoped) -> None:
    store, scope = scoped
    for index in range(3):
        store.add(
            scope,
            _submission(
                source=f"run-{index}",
                findings=[_finding("sha256:abc")],
                unverified=[],
                errors=[],
                summary=None,
                run=_run(run_id=f"run-{index}"),
            ),
        )

    seen = {s.findings[0].identity for s in store.submissions(scope)}

    assert seen == {"sha256:abc"}


def test_two_different_findings_do_not_share_an_identity(scoped: Scoped) -> None:
    store, scope = scoped
    store.add(
        scope,
        _submission(
            findings=[_finding("sha256:aaa"), _finding("sha256:bbb", "guardana.other")],
            unverified=[],
            errors=[],
            summary=None,
        ),
    )

    identities = {f.identity for f in store.submissions(scope)[0].findings}

    assert identities == {"sha256:aaa", "sha256:bbb"}


def test_a_pre_v7_finding_carries_no_identity_rather_than_a_made_up_one(
    scoped: Scoped,
) -> None:
    # An invented identity would silently link two findings that are not the same.
    store, scope = scoped
    store.add(scope, _submission())

    assert store.submissions(scope)[0].findings[0].identity is None


@pytest.mark.parametrize("implementation", ["memory", "postgres"])
def test_both_stores_agree_about_all_of_it(database_url: str, implementation: str) -> None:
    """One contract, both implementations — the difference is a failure, not a discovery."""
    if implementation == "memory":
        store: Store = InMemoryStore(clock=_clock)
        scope = TenantScope.for_project(1)
    else:
        with psycopg.connect(database_url) as connection:
            apply_pending(connection)
            create_organization(connection, "acme", "Acme")
            project = create_project(connection, "acme", "web", "Web")
        store = PostgresStore(database_url, clock=_clock)
        scope = TenantScope.for_project(project.id)
    store.add(
        scope,
        _submission(findings=[_finding("sha256:abc")], unverified=[], errors=[], run=_run()),
    )

    held = store.submissions(scope)[0]

    assert held.run is not None
    assert held.run.gate == "fail"
    assert held.findings[0].identity == "sha256:abc"


def test_a_timestamp_with_no_timezone_is_refused(scoped: Scoped) -> None:
    """A time nobody can place is not a time.

    Stored naive, it would be read back in whatever zone the collector happens to
    run in, and a run that finished at nine would be filed at whatever nine meant
    to somebody else's server.
    """
    with pytest.raises(ValidationError):
        RunIn.model_validate({"started_at": "2026-08-05T10:00:00"})


def test_a_timestamp_with_a_timezone_is_kept(scoped: Scoped) -> None:
    aware = RunIn.model_validate({"started_at": "2026-08-05T10:00:00+02:00"})
    assert aware.started_at is not None


def test_a_store_says_whether_it_actually_stored(scoped: Scoped) -> None:
    """One contract, both stores: a duplicate is reported, not silently dropped."""
    store, scope = scoped

    assert store.add(scope, _submission(run=_run(run_id="once"))) is True
    assert store.add(scope, _submission(run=_run(run_id="once"))) is False
    assert len(store.submissions(scope)) == 1


def test_a_run_with_no_id_is_always_new(scoped: Scoped) -> None:
    store, scope = scoped

    assert store.add(scope, _submission(run=_run(run_id=None))) is True
    assert store.add(scope, _submission(run=_run(run_id=None))) is True


@pytest.mark.parametrize("implementation", ["memory", "postgres"])
def test_one_run_id_in_two_projects_is_two_runs(database_url: str, implementation: str) -> None:
    """Deduplication is scoped like every other query, on both stores.

    Two teams whose pipelines happen to mint the same identifier are not one run,
    and a dedupe that forgot the tenant would silently drop the second team's
    evidence — a cross-tenant effect reached through a de-duplication rule rather
    than through a query.
    """
    store, one, two = _two_scopes(database_url, implementation)

    assert store.add(one, _submission(run=_run(run_id="r"))) is True
    assert store.add(two, _submission(run=_run(run_id="r"))) is True
    assert len(store.submissions(one)) == 1
    assert len(store.submissions(two)) == 1


def _two_scopes(database_url: str, implementation: str) -> tuple[Store, TenantScope, TenantScope]:
    if implementation == "memory":
        return InMemoryStore(clock=_clock), TenantScope.for_project(1), TenantScope.for_project(2)
    with psycopg.connect(database_url) as connection:
        apply_pending(connection)
        create_organization(connection, "acme", "Acme")
        one = create_project(connection, "acme", "web", "Web")
        two = create_project(connection, "acme", "api", "API")
    return (
        PostgresStore(database_url, clock=_clock),
        TenantScope.for_project(one.id),
        TenantScope.for_project(two.id),
    )
