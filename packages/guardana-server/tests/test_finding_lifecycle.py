"""What somebody decided about a finding, and what a new sighting does to it.

The transition that matters most here is `resolved` seen again. A fix that did not
hold must not stay green because somebody once ticked a box — that is the same
fail-open this project refuses everywhere else, arrived at through triage instead
of through a rule.

The second is the waiver. It expires, and it expires **when you read it**: the
collector has no scheduler, so a status that only becomes correct once a job runs
is a status that is quietly wrong in between.
"""

import datetime

import pytest
from conftest import DbConnection, _submission
from guardana.server.cli.codes import EXIT_INVALID_USAGE
from guardana.server.cli.main import main as collector
from guardana.server.db.migrations import apply_pending
from guardana.server.lifecycle import (
    AmbiguousIdentityError,
    TrackedFinding,
    UnknownIdentityError,
    WaiverError,
    list_tracked,
    record_sighting,
    set_status,
    waive,
)
from guardana.server.postgres_store import PostgresStore
from guardana.server.tenancy import TenantScope, create_organization, create_project

_TODAY = datetime.date(2026, 8, 6)
_IDENTITY = "sha256:" + "a" * 64
_OTHER = "sha256:" + "b" * 64
_PROJECT = "acme/web"


@pytest.fixture
def project(connection: DbConnection) -> int:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    created = create_project(connection, "acme", "web", "Web")
    connection.commit()
    return created.id


def _seen(connection: DbConnection, project_id: int, identity: str = _IDENTITY) -> None:
    record_sighting(connection, project_id, identity, datetime.datetime.now(tz=datetime.UTC))
    connection.commit()


def _only(connection: DbConnection) -> TrackedFinding:
    entries = list_tracked(connection, _PROJECT, today=_TODAY)
    assert len(entries) == 1
    return entries[0]


def test_a_first_sighting_opens_a_finding(connection: DbConnection, project: int) -> None:
    _seen(connection, project)

    entry = _only(connection)

    assert entry.status == "open"


def test_a_resolved_finding_reopens_when_it_is_seen_again(
    connection: DbConnection, project: int
) -> None:
    """The most important transition in the model: a fix that did not hold."""
    _seen(connection, project)
    set_status(connection, _PROJECT, _IDENTITY, status="resolved")
    connection.commit()

    _seen(connection, project)

    assert _only(connection).status == "open"


def test_a_false_positive_stays_one_when_it_is_seen_again(
    connection: DbConnection, project: int
) -> None:
    """The identity is the rule plus the location, so it really is the same judgement.

    Reopening it every run would make the status useless and teach people to stop
    reading the list — which is the failure mode triage exists to prevent.
    """
    _seen(connection, project)
    set_status(connection, _PROJECT, _IDENTITY, status="false_positive")
    connection.commit()

    _seen(connection, project)

    assert _only(connection).status == "false_positive"


def test_an_acknowledged_finding_stays_acknowledged(connection: DbConnection, project: int) -> None:
    _seen(connection, project)
    set_status(connection, _PROJECT, _IDENTITY, status="acknowledged", owner="konrad")
    connection.commit()

    _seen(connection, project)

    entry = _only(connection)
    assert entry.status == "acknowledged"
    assert entry.owner == "konrad"


def test_a_live_waiver_holds_across_sightings(connection: DbConnection, project: int) -> None:
    _seen(connection, project)
    waive(
        connection,
        _PROJECT,
        _IDENTITY,
        approver="konrad",
        reason="accepted until the vendor ships a fix",
        expires=datetime.date(2026, 12, 31),
    )
    connection.commit()

    _seen(connection, project)

    entry = _only(connection)
    assert entry.status == "accepted_risk"
    assert entry.waiver_lapsed is False


def test_an_expired_waiver_reports_open_without_anything_having_run(
    connection: DbConnection, project: int
) -> None:
    """Expiry is a property of the date, not of a job somebody remembered to schedule."""
    _seen(connection, project)
    waive(
        connection,
        _PROJECT,
        _IDENTITY,
        approver="konrad",
        reason="until the next release",
        expires=datetime.date(2026, 8, 5),
    )
    connection.commit()

    entry = _only(connection)

    assert entry.status == "open"
    assert entry.waiver_lapsed is True


def test_a_waiver_expiring_today_still_waives(connection: DbConnection, project: int) -> None:
    """The boundary, stated: a waiver is good through the day it names."""
    _seen(connection, project)
    waive(connection, _PROJECT, _IDENTITY, approver="k", reason="r", expires=_TODAY)
    connection.commit()

    assert _only(connection).status == "accepted_risk"


def test_a_waiver_needs_an_approver_a_reason_and_a_date(
    connection: DbConnection, project: int
) -> None:
    """There is no indefinite waiver: that is a disabled check with better manners."""
    _seen(connection, project)

    with pytest.raises(WaiverError, match="reason"):
        waive(connection, _PROJECT, _IDENTITY, approver="k", reason="  ", expires=_TODAY)


def test_a_status_outside_the_closed_set_is_refused(connection: DbConnection, project: int) -> None:
    """Free text would make `resolved` and `Resolved` two states in one project."""
    _seen(connection, project)

    with pytest.raises(ValueError, match="not a status"):
        set_status(connection, _PROJECT, _IDENTITY, status="Resolved")


def test_accepted_risk_cannot_be_set_without_going_through_a_waiver(
    connection: DbConnection, project: int
) -> None:
    """Otherwise a status change would produce accepted risk with nobody's name on it."""
    _seen(connection, project)

    with pytest.raises(ValueError, match="finding waive"):
        set_status(connection, _PROJECT, _IDENTITY, status="accepted_risk")


def test_a_prefix_addresses_a_finding(connection: DbConnection, project: int) -> None:
    """Nobody types a sha256. Git solved this and the answer is the same one."""
    _seen(connection, project)

    set_status(connection, _PROJECT, "sha256:aaaaaaaa", status="acknowledged")
    connection.commit()

    assert _only(connection).status == "acknowledged"


def test_an_ambiguous_prefix_is_refused_with_the_candidates(
    connection: DbConnection, project: int
) -> None:
    """Acting on the wrong finding is worse than being asked to type four more characters."""
    _seen(connection, project)
    _seen(connection, project, "sha256:" + "a" * 63 + "b")

    with pytest.raises(AmbiguousIdentityError) as refused:
        set_status(connection, _PROJECT, "sha256:aaaa", status="acknowledged")

    assert "sha256:aaaaaaaa" in str(refused.value)


def test_an_unknown_prefix_is_refused(connection: DbConnection, project: int) -> None:
    _seen(connection, project)

    with pytest.raises(UnknownIdentityError):
        set_status(connection, _PROJECT, "sha256:ffff", status="acknowledged")


def test_one_project_cannot_triage_another_projects_finding(
    connection: DbConnection, project: int
) -> None:
    """The tenant boundary holds here too, or triage is a way around it."""
    create_project(connection, "acme", "other", "Other")
    connection.commit()
    _seen(connection, project)

    with pytest.raises(UnknownIdentityError):
        set_status(connection, "acme/other", _IDENTITY, status="acknowledged")

    assert list_tracked(connection, "acme/other", today=_TODAY) == ()


def test_ingest_records_the_sighting(connection: DbConnection, database_url: str) -> None:
    """The lifecycle starts at ingest or it does not start: nothing else sees a finding."""
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    created = create_project(connection, "acme", "web", "Web")
    connection.commit()

    submission = _submission()
    for finding in submission.findings:
        finding.identity = _IDENTITY

    PostgresStore(database_url).add(TenantScope.for_project(created.id), submission)

    entries = list_tracked(connection, _PROJECT, today=_TODAY)
    assert [entry.rule_id for entry in entries] == ["guardana.supply_chain.hardcoded_secret"]
    assert entries[0].status == "open"


def test_a_sighting_is_dated_by_the_same_clock_as_the_run_that_saw_it(
    connection: DbConnection, database_url: str
) -> None:
    """One write, one clock.

    `received_at` came from the store's injectable clock and the sighting from a
    second reading of the wall, so a finding's `first_seen` could disagree with the
    run that first saw it — and migration 0006 built those dates from `received_at`,
    which would make backfilled rows and new rows mean different things.
    """
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    created = create_project(connection, "acme", "web", "Web")
    connection.commit()
    submission = _submission()
    for finding in submission.findings:
        finding.identity = _IDENTITY

    # 2023-11-14, and deliberately not today: a wall-clock read is indistinguishable
    # from an injected one on the day the test runs.
    PostgresStore(database_url, clock=lambda: 1_699_920_000.0).add(
        TenantScope.for_project(created.id), submission
    )

    entry = list_tracked(connection, _PROJECT, today=_TODAY)[0]
    assert (entry.first_seen, entry.last_seen) == ("2023-11-14", "2023-11-14")


def test_a_finding_that_cannot_be_linked_is_not_tracked(
    connection: DbConnection, database_url: str
) -> None:
    """An agent older than 0.9 sends no identity, and an unlinkable sighting is not an entity.

    Tracking it under a made-up key would give a team a triage list where the same
    problem appears once per run, which is worse than not offering triage at all.
    """
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    created = create_project(connection, "acme", "web", "Web")
    connection.commit()
    submission = _submission()
    assert all(finding.identity is None for finding in submission.findings)

    PostgresStore(database_url).add(TenantScope.for_project(created.id), submission)

    assert list_tracked(connection, _PROJECT, today=_TODAY) == ()


def test_an_ambiguous_prefix_is_a_usage_error_not_a_database_outage(
    connection: DbConnection,
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Found by running it: the refusal came out as "could not reach the database".

    An operator reading that goes to look at PostgreSQL, and PostgreSQL is fine.
    The same mistake as reporting a database outage as a rejected credential, and
    the collector has made it before — which is why it has a test now.
    """
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    created = create_project(connection, "acme", "web", "Web")
    connection.commit()
    record_sighting(connection, created.id, _IDENTITY, datetime.datetime.now(tz=datetime.UTC))
    record_sighting(connection, created.id, _OTHER, datetime.datetime.now(tz=datetime.UTC))
    connection.commit()
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)

    code = collector(
        ["finding", "status", "sha256:", "--project", _PROJECT, "--status", "resolved"]
    )

    assert code == EXIT_INVALID_USAGE
    message = capsys.readouterr().err
    assert "matches 2 findings" in message
    assert "could not reach the database" not in message


def test_the_short_form_the_listing_prints_addresses_the_finding(
    connection: DbConnection, project: int
) -> None:
    """`finding list` shows eight hex characters, so eight hex characters must work.

    A command that refuses what its own output shows is a command people use once.
    """
    _seen(connection, project)

    set_status(connection, _PROJECT, "aaaaaaaa", status="acknowledged")
    connection.commit()

    assert _only(connection).status == "acknowledged"


def test_filtering_by_status_does_not_return_a_short_page(
    connection: DbConnection, project: int
) -> None:
    """The filter runs in SQL, so a limited page holds what was asked for.

    Filtering a limited page afterwards returns fewer rows than requested while
    more exist — a listing that quietly understates how much there is, which for a
    finding list is the wrong direction to be wrong in.
    """
    for index in range(6):
        _seen(connection, project, f"sha256:{index:064d}")
    set_status(connection, _PROJECT, "sha256:" + "0" * 64, status="resolved")
    connection.commit()

    page = list_tracked(connection, _PROJECT, status="open", today=_TODAY, limit=5)

    assert len(page) == 5
    assert {entry.status for entry in page} == {"open"}


def test_a_lapsed_waiver_is_found_by_filtering_for_open(
    connection: DbConnection, project: int
) -> None:
    """And never by filtering for accepted risk, which it no longer is."""
    _seen(connection, project)
    waive(
        connection,
        _PROJECT,
        _IDENTITY,
        approver="k",
        reason="r",
        expires=datetime.date(2026, 1, 1),
    )
    connection.commit()

    assert len(list_tracked(connection, _PROJECT, status="open", today=_TODAY)) == 1
    assert list_tracked(connection, _PROJECT, status="accepted_risk", today=_TODAY) == ()
