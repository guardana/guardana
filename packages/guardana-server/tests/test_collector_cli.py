"""`guardana-collector` — the command an operator runs, including when it goes wrong.

Exit codes match the CLI's table, because one product with two tables is a product
whose exit status means nothing. `0` did what was asked, `1` the database said no,
`3` the command was pointed at nothing.
"""

import psycopg
import pytest
from guardana.server.auth import Scope, list_keys
from guardana.server.cli import EXIT_FAILED, EXIT_INVALID_USAGE, EXIT_OK, main
from guardana.server.db.migrations import read_state
from guardana.server.envelope import DeploymentIn, Submission
from guardana.server.postgres_store import PostgresStore
from guardana.server.tenancy import (
    TenantScope,
    list_organizations,
    list_projects,
    resolve_project,
)
from test_migrations import _apply_through, _legacy_submission


def _tenanted(database_url: str) -> None:
    """A migrated collector with one organization, one project and one key."""
    main(["migrate"])
    main(["bootstrap", "--org", "acme", "--project", "web"])


def _pre_tenancy_collector(database_url: str) -> None:
    """A 0.8 collector: migrated to 0002, holding a run, with no tenants at all."""
    with psycopg.connect(database_url) as connection:
        _apply_through(connection, 2)
        _legacy_submission(connection)


def test_migrate_applies_the_schema(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)

    assert main(["migrate"]) == EXIT_OK

    assert "applied  0001" in capsys.readouterr().out
    with psycopg.connect(database_url) as connection:
        assert read_state(connection).is_current


def test_migrating_a_current_database_says_so_and_succeeds(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    assert main(["migrate"]) == EXIT_OK
    assert "already current" in capsys.readouterr().out


def test_status_reports_pending_before_and_applied_after(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)

    main(["status"])
    before = capsys.readouterr().out
    main(["migrate"])
    capsys.readouterr()
    main(["status"])
    after = capsys.readouterr().out

    assert "pending  0001" in before
    assert "applied  0001" in after


def test_rollback_undoes_the_last_migration(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    assert main(["rollback"]) == EXIT_OK

    assert "rolled back" in capsys.readouterr().out
    with psycopg.connect(database_url) as connection:
        state = read_state(connection)
    # One step, so the newest is gone and everything before it stayed. Asserted as
    # a relationship rather than as "empty": the moment a second migration shipped,
    # an emptiness assertion would have been testing the migration count.
    assert len(state.pending) == 1
    assert state.applied


def test_rolling_back_an_unmigrated_database_says_nothing_to_do(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)

    assert main(["rollback"]) == EXIT_OK
    assert "nothing to roll back" in capsys.readouterr().out


def test_no_database_url_is_a_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARDANA_DATABASE_URL", raising=False)
    monkeypatch.delenv("GUARDANA_STORAGE", raising=False)

    assert main(["status"]) == EXIT_INVALID_USAGE


def test_the_memory_store_has_no_schema_to_migrate(monkeypatch: pytest.MonkeyPatch) -> None:
    # Told plainly rather than failing to connect to nothing: `GUARDANA_STORAGE=memory`
    # is a valid configuration for the server and a meaningless one for this command.
    monkeypatch.delenv("GUARDANA_DATABASE_URL", raising=False)
    monkeypatch.setenv("GUARDANA_STORAGE", "memory")

    assert main(["migrate"]) == EXIT_INVALID_USAGE


def test_an_unreachable_database_is_a_failure_not_a_usage_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The distinction the exit-code table exists for: the command was right and the
    # environment was not.
    monkeypatch.setenv("GUARDANA_DATABASE_URL", "postgresql://nobody@127.0.0.1:1/nothing")

    assert main(["status"]) == EXIT_FAILED


def test_key_create_prints_the_key_once(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    capsys.readouterr()

    assert main(["key", "create", "--project", "acme/web", "--name", "github-actions"]) == EXIT_OK

    printed = capsys.readouterr().out
    assert "gdn_" in printed
    assert "only time it is shown" in printed


def test_a_created_key_never_appears_again(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """There is no command that returns a key after it is created.

    A credential a system can re-read is a credential that leaks through every
    path that reads it.
    """
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    capsys.readouterr()
    main(["key", "create", "--project", "acme/web", "--name", "ci"])
    token = next(word for word in capsys.readouterr().out.split() if word.startswith("gdn_"))

    main(["key", "list"])

    assert token not in capsys.readouterr().out


def test_key_create_defaults_to_ingest_only(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A CI job writes and does not browse, so the default credential cannot read
    # every finding an organisation has ever recorded.
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    main(["key", "create", "--project", "acme/web", "--name", "ci"])
    capsys.readouterr()

    main(["key", "list"])

    listed = capsys.readouterr().out
    assert "ingest" in listed
    assert "read" not in listed
    assert "acme/web" in listed


def test_key_list_on_a_fresh_collector_says_nothing_can_write(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    main(["key", "list"])

    assert "nothing can write to this collector" in capsys.readouterr().out


def test_key_revoke_names_a_key_that_does_not_exist(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])

    assert main(["key", "revoke", "deadbeef"]) == EXIT_INVALID_USAGE


def test_key_revoke_marks_it_revoked_in_the_listing(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    capsys.readouterr()
    main(["key", "create", "--project", "acme/web", "--name", "ci"])
    token = next(word for word in capsys.readouterr().out.split() if word.startswith("gdn_"))
    prefix = token.split("_")[1]

    assert main(["key", "revoke", prefix]) == EXIT_OK

    capsys.readouterr()
    main(["key", "list"])
    assert "revoked" in capsys.readouterr().out


# --- tenants ------------------------------------------------------------------


def test_bootstrap_creates_an_organization_a_project_and_one_key(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Three entities, one command — because a security boundary needs a short path.

    Tenancy would otherwise take the first run of a real collector from two commands
    to five, and a tool that is harder to start is a tool fewer people run.
    """
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    assert main(["bootstrap", "--org", "acme", "--project", "web"]) == EXIT_OK

    printed = capsys.readouterr().out
    assert "gdn_" in printed
    assert "only time it is shown" in printed
    assert "acme/web" in printed
    with psycopg.connect(database_url) as connection:
        assert [p.reference for p in list_projects(connection)] == ["acme/web"]
        assert list_keys(connection)[0].project_ref == "acme/web"


def test_bootstrapping_twice_refuses_and_names_key_create(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A command that quietly succeeds the second time is one somebody runs twice in
    a script and never notices issued two credentials."""
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    capsys.readouterr()

    assert main(["bootstrap", "--org", "acme", "--project", "web"]) == EXIT_INVALID_USAGE

    assert "key create" in capsys.readouterr().err


def test_bootstrap_mints_an_ingest_key_and_says_how_to_get_a_read_one(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The same default as `key create`: the first credential is the one that ends up
    # in CI, and a pipeline credential that reads the whole finding history is a much
    # bigger secret than it looks.
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    main(["bootstrap", "--org", "acme", "--project", "web"])

    printed = capsys.readouterr().out
    with psycopg.connect(database_url) as connection:
        assert list_keys(connection)[0].scopes == (Scope.INGEST,)
    assert "--scope read" in printed


def test_key_create_without_a_project_is_a_usage_error(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)

    with pytest.raises(SystemExit) as raised:
        main(["key", "create", "--name", "ci"])

    assert raised.value.code == EXIT_INVALID_USAGE


def test_key_create_does_not_guess_even_when_exactly_one_project_exists(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issuing a credential against a tenant nobody named has the same shape as a
    default credential."""
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)

    with pytest.raises(SystemExit):
        main(["key", "create", "--name", "second"])


def test_key_create_on_a_collector_with_no_projects_says_what_to_run(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Told what to do next, not only what went wrong.
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    assert main(["key", "create", "--project", "acme/web", "--name", "ci"]) == EXIT_INVALID_USAGE

    assert "bootstrap" in capsys.readouterr().err


def test_key_list_can_be_narrowed_to_one_project(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    main(["project", "create", "--org", "acme", "--slug", "api", "--name", "API"])
    main(["key", "create", "--project", "acme/api", "--name", "api-ci"])
    capsys.readouterr()

    main(["key", "list", "--project", "acme/api"])

    listed = capsys.readouterr().out
    assert "api-ci" in listed
    assert "first-key" not in listed


def test_org_list_marks_the_adopted_organization(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An administrator who upgraded without reading a changelog still finds out
    where their history went."""
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _pre_tenancy_collector(database_url)
    main(["migrate"])
    capsys.readouterr()

    main(["org", "list"])

    listed = capsys.readouterr().out
    assert "adopted" in listed
    assert "migration 0003" in listed


def test_org_list_on_a_fresh_collector_says_what_to_run(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    main(["org", "list"])

    assert "bootstrap" in capsys.readouterr().out


def test_project_list_on_a_fresh_collector_says_what_to_run(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])
    capsys.readouterr()

    main(["project", "list"])

    assert "bootstrap" in capsys.readouterr().out


def test_org_rename_moves_the_adopted_name_out_of_the_way(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _pre_tenancy_collector(database_url)
    main(["migrate"])

    assert main(["org", "rename", "--slug", "adopted", "--to", "acme"]) == EXIT_OK

    with psycopg.connect(database_url) as connection:
        assert [o.slug for o in list_organizations(connection)] == ["acme"]


def test_project_rename_keeps_the_keys_pointing_at_it(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A reference is a name, not an identity: a key hangs off the project's id.
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)

    assert main(["project", "rename", "--project", "acme/web", "--to", "api"]) == EXIT_OK

    with psycopg.connect(database_url) as connection:
        assert list_keys(connection)[0].project_ref == "acme/api"


def test_a_slug_that_is_not_a_slug_is_a_usage_error(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    main(["migrate"])

    assert main(["org", "create", "--slug", "Acme Inc!", "--name", "Acme"]) == EXIT_INVALID_USAGE


def test_renaming_an_organization_onto_a_taken_slug_is_a_usage_error(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    main(["org", "create", "--slug", "globex", "--name", "Globex"])

    assert main(["org", "rename", "--slug", "globex", "--to", "acme"]) == EXIT_INVALID_USAGE


@pytest.mark.parametrize(
    "argv",
    [
        ["org", "delete", "--slug", "acme"],
        ["project", "delete", "--project", "acme/web"],
    ],
)
def test_there_is_no_command_that_deletes_a_tenant(argv: list[str]) -> None:
    """Removing tenant data is retention, and deserves to be designed there rather
    than smuggled in here."""
    with pytest.raises(SystemExit):
        main(argv)


def test_bootstrap_adds_a_second_project_to_an_organization_that_exists(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """It refuses a repeated *project*, not a repeated organization.

    A second team inside one organization is the case the granular commands are
    for, but reaching for `bootstrap` again is what people do — and it issues one
    credential for a tenant that did not exist a moment ago, which is not the
    double-credential mistake the refusal guards against.
    """
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    capsys.readouterr()

    assert main(["bootstrap", "--org", "acme", "--project", "api"]) == EXIT_OK

    with psycopg.connect(database_url) as connection:
        assert [p.reference for p in list_projects(connection)] == ["acme/web", "acme/api"]
        assert [o.slug for o in list_organizations(connection)] == ["acme"]


def test_help_still_exits_zero() -> None:
    """Translating argparse's usage exit must not catch the one that means success."""
    with pytest.raises(SystemExit) as raised:
        main(["--help"])

    assert raised.value.code == EXIT_OK


def test_naming_no_command_at_all_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as raised:
        main([])

    assert raised.value.code == EXIT_INVALID_USAGE


# --- what the runs reported ---------------------------------------------------


def _report(database_url: str, ai_system: str, environment: str, commit: str = "abc1234") -> None:
    """One submission with a deployment block, written the way ingest writes it."""
    with psycopg.connect(database_url) as connection:
        project = resolve_project(connection, "acme/web")
    PostgresStore(database_url).add(
        TenantScope.for_project(project.id),
        Submission(
            source="ci",
            schema_version=6,
            deployment=DeploymentIn(
                ai_system=ai_system, environment=environment, commit_sha=commit
            ),
        ),
    )


def test_system_list_shows_what_runs_declared(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    _report(database_url, "support-agent", "production")
    _report(database_url, "search-agent", "dev")
    capsys.readouterr()

    assert main(["system", "list"]) == EXIT_OK

    listed = capsys.readouterr().out
    assert "support-agent" in listed
    assert "search-agent" in listed
    assert "acme/web" in listed


def test_a_typo_shows_up_as_a_second_system(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The cost of inferring rather than requiring, and the reason it is survivable.

    A mistake that is visible is a different thing from a mistake that is not; the
    listing is what makes this one the first kind.
    """
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    _report(database_url, "support-agent", "production")
    _report(database_url, "suport-agent", "production")
    capsys.readouterr()

    main(["system", "list"])

    listed = capsys.readouterr().out
    assert "support-agent" in listed
    assert "suport-agent" in listed


def test_environment_list_shows_what_runs_declared(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    _report(database_url, "support-agent", "production")
    _report(database_url, "support-agent", "dev")
    capsys.readouterr()

    main(["environment", "list"])

    listed = capsys.readouterr().out
    assert "production" in listed
    assert "dev" in listed


def test_deployment_list_can_be_narrowed_to_one_system(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    _report(database_url, "support-agent", "production", commit="aaa1111")
    _report(database_url, "search-agent", "production", commit="bbb2222")
    capsys.readouterr()

    main(["deployment", "list", "--ai-system", "support-agent"])

    listed = capsys.readouterr().out
    assert "aaa1111" in listed
    assert "bbb2222" not in listed


def test_an_inventory_listing_never_crosses_a_project(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # An aggregate is a query, and a query without a tenant filter is the same
    # cross-tenant read as any other — reintroduced one level down.
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    main(["bootstrap", "--org", "globex", "--project", "web"])
    _report(database_url, "support-agent", "production")
    capsys.readouterr()

    main(["system", "list", "--project", "globex/web"])

    assert "support-agent" not in capsys.readouterr().out


def test_a_listing_with_nothing_reported_says_how_one_gets_there(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    capsys.readouterr()

    main(["system", "list"])

    assert "--ai-system" in capsys.readouterr().out


def test_key_create_can_pin_an_environment(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    capsys.readouterr()

    assert (
        main(
            [
                "key",
                "create",
                "--project",
                "acme/web",
                "--name",
                "prod",
                "--environment",
                "Production",
            ]
        )
        == EXIT_OK
    )

    assert "environment production" in capsys.readouterr().out
    with psycopg.connect(database_url) as connection:
        pinned = next(k for k in list_keys(connection) if k.name == "prod")
    assert pinned.environment == "production"


def test_key_list_shows_the_pin(
    database_url: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GUARDANA_DATABASE_URL", database_url)
    _tenanted(database_url)
    main(
        ["key", "create", "--project", "acme/web", "--name", "prod", "--environment", "production"]
    )
    capsys.readouterr()

    main(["key", "list"])

    assert "[production]" in capsys.readouterr().out
