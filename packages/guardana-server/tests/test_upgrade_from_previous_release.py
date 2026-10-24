"""The upgrade `docs/deployment.md` describes, from the oldest schema a release shipped.

The database starts at the smallest non-zero migration count any release in
`historical/releases.json` shipped, holding what an operator of that release would have:
a run with a finding and a key, written with only the columns that schema has, before
there were tenants. It is migrated forward with the runner the `migrate` command uses,
which adopts both into one project, and then the key issued before the upgrade sends
every stored envelope through the real route. Everything, the pre-upgrade run included,
has to come back through the scoped store.
"""

import json
from typing import Any

import psycopg
import pytest
from conftest import DbConnection
from guardana.server.auth import Scope, generate_key
from guardana.server.db.migrations import apply_pending, load_migrations, read_state
from guardana.server.envelope import Submission
from packaging.version import Version
from test_historical_envelopes import HISTORICAL, bearer, serve, stored_envelopes
from test_migrations import _apply_through

_OK = 200
_TENANCY = 3
"""The migration that introduced projects; the writer below knows only the schema before it."""


def oldest_upgradable_release() -> tuple[str, int]:
    """The oldest release that shipped a collector schema, with its migration count."""
    releases: dict[str, Any] = json.loads(
        (HISTORICAL / "releases.json").read_text(encoding="utf-8")
    )
    shipped = [
        (version, int(release["collector_migrations"]))
        for version, release in releases.items()
        if int(release["collector_migrations"]) > 0
    ]
    if not shipped:
        raise AssertionError("no release in releases.json shipped a collector migration")
    return min(shipped, key=lambda entry: (entry[1], Version(entry[0])))


def _a_collector_from_before_the_upgrade(connection: DbConnection) -> str:
    """Write one submission, its finding and a key in the pre-tenancy schema; return the token."""
    issued, secret_hash = generate_key("issued-before-the-upgrade", (Scope.INGEST, Scope.READ))
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into submissions (received_at, source, schema_version, rules_run) "
            "values (now() - interval '1 day', 'before-the-upgrade', 5, 1) returning id",
        )
        row = cursor.fetchone()
        if row is None:
            raise AssertionError("the pre-upgrade submission was not written")
        cursor.execute(
            "insert into findings (submission_id, channel, position, rule_id, severity, title, "
            "target_ref, evidence_summary) values "
            "(%s, 'findings', 0, 'guardana.supply_chain.pickle_opcode', 'CRITICAL', "
            "'Dangerous pickle opcode', 'model.pkl', 'imports os.system')",
            (row[0],),
        )
        cursor.execute(
            "insert into api_keys (name, prefix, secret_hash, scopes) values (%s, %s, %s, %s)",
            (issued.name, issued.prefix, secret_hash, [scope.value for scope in issued.scopes]),
        )
    connection.commit()
    return issued.token


def _adopted_project(connection: DbConnection) -> int:
    with connection.cursor() as cursor:
        cursor.execute(
            "select p.id from projects p join organizations o on o.id = p.organization_id "
            "where o.adopted"
        )
        rows = cursor.fetchall()
    if len(rows) != 1:
        raise AssertionError(f"expected one adopted project, found {len(rows)}")
    project_id: int = rows[0][0]
    return project_id


def test_the_oldest_upgradable_release_is_the_first_collector_schema() -> None:
    version, count = oldest_upgradable_release()

    assert version == "0.8.0"
    assert 0 < count < _TENANCY < len(load_migrations()), (
        "the upgrade below has to start before tenancy and end where this build is"
    )


def test_a_collector_upgraded_from_the_oldest_release_keeps_its_data_and_takes_every_envelope(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, count = oldest_upgradable_release()
    with psycopg.connect(database_url) as connection:
        _apply_through(connection, count)
        token = _a_collector_from_before_the_upgrade(connection)

        apply_pending(connection)

        assert read_state(connection).is_current
        project_id = _adopted_project(connection)
    collector = serve(database_url, project_id, monkeypatch, token=token)
    envelopes = [document for _, document in stored_envelopes()]
    for document in envelopes:
        response = collector.client.post(
            "/findings", json=document, headers=bearer(collector.token)
        )
        assert response.status_code == _OK, response.text

    before, *after = [record.submission for record in collector.store.records(collector.scope)]

    assert before.source == "before-the-upgrade"
    assert [(f.rule_id, f.title) for f in before.findings] == [
        ("guardana.supply_chain.pickle_opcode", "Dangerous pickle opcode")
    ]
    assert after == [Submission.model_validate(document) for document in envelopes]
    assert [stored.schema_version for stored in after] == [
        document["schema_version"] for document in envelopes
    ]
