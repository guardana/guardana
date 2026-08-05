"""Tenant scope, organizations and projects — what "nobody" means, and why it is not "everybody"."""

import pytest
from conftest import DbConnection
from guardana.server.db.migrations import apply_pending
from guardana.server.tenancy import (
    TenancyError,
    TenantScope,
    UnscopedQueryError,
    create_organization,
    create_project,
    list_organizations,
    list_projects,
    parse_project_reference,
    rename_organization,
    rename_project,
    resolve_project,
)


def test_a_project_scope_carries_that_project() -> None:
    assert TenantScope.for_project(7).require_project() == 7


def test_a_project_scope_is_not_unauthenticated() -> None:
    assert TenantScope.for_project(7).is_unauthenticated is False


def test_the_unauthenticated_scope_names_no_project() -> None:
    assert TenantScope.unauthenticated().is_unauthenticated is True


def test_asking_the_unauthenticated_scope_for_a_project_raises() -> None:
    # A scope that belongs to nobody must never quietly mean "everybody".
    with pytest.raises(UnscopedQueryError, match="belongs to no project"):
        TenantScope.unauthenticated().require_project()


def test_two_scopes_for_the_same_project_are_equal() -> None:
    # The in-memory store keys records by scope, so equality is a contract here.
    assert TenantScope.for_project(3) == TenantScope.for_project(3)
    assert TenantScope.for_project(3) != TenantScope.for_project(4)


def test_a_scope_may_narrow_to_one_environment() -> None:
    scope = TenantScope.for_project(7, environment="production")

    assert scope.require_project() == 7
    assert scope.environment == "production"


def test_a_project_scope_names_no_environment() -> None:
    # Unpinned means the whole project, and it has to be distinguishable from
    # "pinned to an environment that happens to be called nothing".
    assert TenantScope.for_project(7).environment is None


def test_an_environment_is_normalized_when_the_scope_is_built() -> None:
    # `Production`, `production ` and `production` must be one environment, or the
    # grouping in a dashboard depends on who typed what.
    assert TenantScope.for_project(7, environment=" Production ").environment == "production"


def test_a_scope_narrowed_to_a_different_environment_is_a_different_scope() -> None:
    assert TenantScope.for_project(7, environment="dev") != TenantScope.for_project(
        7, environment="production"
    )
    assert TenantScope.for_project(7, environment="dev") != TenantScope.for_project(7)


# --- naming a tenant ----------------------------------------------------------


def test_a_project_reference_is_organization_slash_project() -> None:
    assert parse_project_reference("acme/web") == ("acme", "web")


@pytest.mark.parametrize("reference", ["acme", "acme/", "/web", "acme/web/extra", "", "  /  "])
def test_a_reference_that_is_not_two_slugs_is_refused(reference: str) -> None:
    # Refused rather than best-effort parsed: a reference this cannot read is not a
    # reference this issued, and guessing at it is how a query reaches the wrong
    # tenant.
    with pytest.raises(TenancyError):
        parse_project_reference(reference)


@pytest.mark.parametrize("slug", ["acme inc", "-acme", "acme;drop", "a" * 64, ""])
def test_a_slug_that_could_be_read_two_ways_is_refused(slug: str) -> None:
    with pytest.raises(TenancyError, match="is not a slug"):
        parse_project_reference(f"{slug}/web")


@pytest.mark.parametrize(
    ("written", "normalized"), [("Acme", "acme"), (" acme ", "acme"), ("ACME", "acme")]
)
def test_a_slug_is_normalized_rather_than_refused(written: str, normalized: str) -> None:
    # Case and surrounding space are not two different tenants. Refusing them would
    # be defensible; treating them as distinct would not, and that is the failure
    # this normalization exists to prevent.
    assert parse_project_reference(f"{written}/web")[0] == normalized


# --- organizations and projects ----------------------------------------------


def test_creating_an_organization_and_a_project(connection: DbConnection) -> None:
    apply_pending(connection)

    organization = create_organization(connection, "acme", "Acme Inc")
    project = create_project(connection, "acme", "web", "Web app")

    assert organization.adopted is False
    assert project.reference == "acme/web"
    assert project.organization_id == organization.id


def test_two_organizations_cannot_share_a_slug(connection: DbConnection) -> None:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")

    with pytest.raises(TenancyError, match="already exists"):
        create_organization(connection, "acme", "Acme Again")


def test_two_projects_of_one_organization_cannot_share_a_slug(connection: DbConnection) -> None:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    create_project(connection, "acme", "web", "Web")

    with pytest.raises(TenancyError, match="already exists"):
        create_project(connection, "acme", "web", "Web again")


def test_two_organizations_may_each_have_a_project_called_web(connection: DbConnection) -> None:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    create_organization(connection, "globex", "Globex")

    first = create_project(connection, "acme", "web", "Web")
    second = create_project(connection, "globex", "web", "Web")

    assert first.id != second.id
    assert {first.reference, second.reference} == {"acme/web", "globex/web"}


def test_a_project_in_an_organization_that_does_not_exist_is_refused(
    connection: DbConnection,
) -> None:
    apply_pending(connection)

    with pytest.raises(TenancyError, match="no organization"):
        create_project(connection, "ghost", "web", "Web")


def test_resolving_a_reference_that_names_nothing_says_what_to_run(
    connection: DbConnection,
) -> None:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")

    with pytest.raises(TenancyError, match="bootstrap"):
        resolve_project(connection, "acme/nope")


def test_listing_projects_of_one_organization_excludes_the_others(
    connection: DbConnection,
) -> None:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    create_organization(connection, "globex", "Globex")
    create_project(connection, "acme", "web", "Web")
    create_project(connection, "globex", "api", "API")

    assert [p.reference for p in list_projects(connection, "acme")] == ["acme/web"]
    assert len(list_projects(connection)) == 2


# --- renaming what the migration invented ------------------------------------


def test_renaming_an_organization_keeps_its_projects(connection: DbConnection) -> None:
    # A name the migration invented must not be permanent, and renaming it must not
    # be a quiet loss of what hung underneath.
    apply_pending(connection)
    create_organization(connection, "adopted", "adopted")
    create_project(connection, "adopted", "adopted", "adopted")

    rename_organization(connection, "adopted", new_slug="acme", new_name="Acme Inc")

    assert [p.reference for p in list_projects(connection, "acme")] == ["acme/adopted"]
    assert list_organizations(connection)[0].name == "Acme Inc"


def test_renaming_an_organization_keeps_the_adopted_mark(connection: DbConnection) -> None:
    # The mark records a fact about history, not a name — so it survives the rename
    # that the fact itself invites.
    apply_pending(connection)
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into organizations (slug, name, adopted) values ('adopted', 'adopted', true)"
        )
    connection.commit()

    rename_organization(connection, "adopted", new_slug="acme")

    assert list_organizations(connection)[0].adopted is True


def test_renaming_an_organization_onto_a_taken_slug_is_refused(connection: DbConnection) -> None:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    create_organization(connection, "globex", "Globex")

    with pytest.raises(TenancyError, match="already exists"):
        rename_organization(connection, "globex", new_slug="acme")


def test_renaming_an_organization_that_does_not_exist_is_refused(
    connection: DbConnection,
) -> None:
    apply_pending(connection)

    with pytest.raises(TenancyError, match="no organization"):
        rename_organization(connection, "ghost", new_slug="acme")


def test_renaming_a_project(connection: DbConnection) -> None:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    create_project(connection, "acme", "web", "Web")

    renamed = rename_project(connection, "acme/web", new_slug="api", new_name="API")

    assert renamed.reference == "acme/api"
    assert renamed.name == "API"


def test_renaming_a_project_onto_a_taken_slug_is_refused(connection: DbConnection) -> None:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme")
    create_project(connection, "acme", "web", "Web")
    create_project(connection, "acme", "api", "API")

    with pytest.raises(TenancyError, match="already exists"):
        rename_project(connection, "acme/api", new_slug="web")


def test_a_rename_that_keeps_the_name_only_changes_the_slug(connection: DbConnection) -> None:
    apply_pending(connection)
    create_organization(connection, "acme", "Acme Inc")

    renamed = rename_organization(connection, "acme", new_slug="acme-inc")

    assert renamed.slug == "acme-inc"
    assert renamed.name == "Acme Inc"
