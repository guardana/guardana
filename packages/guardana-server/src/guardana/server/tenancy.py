"""Who owns a row — organizations, projects, and the scope of every query.

The tenant is the **project**. An organization is what a project belongs to and
what gets named and billed; isolation runs along the project because that is the
line a team draws for itself — "web" and "api" are not the same body of evidence
even when one department pays for both.

The scope is a type rather than a bare `int`, because `submissions(scope, source,
limit)` with three positional primitives is a mistake waiting for a distracted
afternoon.
"""

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # psycopg is a runtime dependency of the collector, not of the engine
    from psycopg import Connection

_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_REFERENCE_PARTS = 2


class TenancyError(RuntimeError):
    """An organization or project that cannot be created, found or named."""


class UnscopedQueryError(RuntimeError):
    """A durable-storage query with no tenant. Never treated as "every tenant"."""


@dataclass(frozen=True, slots=True)
class TenantScope:
    """The project an operation on the store is performed for.

    `unauthenticated()` exists only for the evaluation mode (`GUARDANA_STORAGE=memory`
    plus an explicit acknowledgement that nothing is authenticated). The in-memory
    store treats it as an ordinary tenant; `PostgresStore` refuses it — a scope that
    belongs to nobody must not be able to reach durable evidence, and making that
    structural beats making it a rule somebody has to remember.
    """

    project_id: int | None = None

    @classmethod
    def for_project(cls, project_id: int) -> "TenantScope":
        """Return the scope of one project."""
        return cls(project_id=project_id)

    @classmethod
    def unauthenticated(cls) -> "TenantScope":
        """Return the scope of a collector that authenticates nobody."""
        return cls(project_id=None)

    @property
    def is_unauthenticated(self) -> bool:
        """Whether this scope names no project at all."""
        return self.project_id is None

    def require_project(self) -> int:
        """Return the project this scope names, or refuse."""
        if self.project_id is None:
            raise UnscopedQueryError(
                "this request belongs to no project, and a query without a tenant is not a "
                "query for every tenant; the unauthenticated scope reaches the in-memory "
                "store only"
            )
        return self.project_id


@dataclass(frozen=True, slots=True)
class Organization:
    """A tenant's owner: what gets named, and what projects hang off."""

    id: int
    slug: str
    name: str
    adopted: bool = False
    """Whether migration 0003 created this one to hold pre-tenancy rows."""


@dataclass(frozen=True, slots=True)
class Project:
    """The tenant itself. Every submission and every API key belongs to exactly one."""

    id: int
    organization_id: int
    organization_slug: str
    slug: str
    name: str

    @property
    def reference(self) -> str:
        """How a person names this project on a command line: `organization/project`."""
        return f"{self.organization_slug}/{self.slug}"


def check_slug(value: str, what: str) -> str:
    """Validate a slug at the door, because a slug is half of a tenant reference."""
    candidate = value.strip()
    if not _SLUG.match(candidate):
        raise TenancyError(
            f"{what} {value!r} is not a slug: lower-case letters, digits, dot, dash and "
            f"underscore, starting with a letter or a digit, at most 63 characters"
        )
    return candidate


def parse_project_reference(reference: str) -> tuple[str, str]:
    """Split `organization/project`, refusing anything else.

    Refused rather than best-effort parsed, for the same reason a malformed API key
    is: a reference this cannot read is not a reference this issued, and guessing at
    it is how a query reaches the wrong tenant.
    """
    parts = reference.split("/")
    if len(parts) != _REFERENCE_PARTS:
        raise TenancyError(
            f"{reference!r} is not a project reference; write it as organization/project, "
            f"for example acme/web"
        )
    return check_slug(parts[0], "organization"), check_slug(parts[1], "project")


def create_organization(
    connection: "Connection[tuple[object, ...]]", slug: str, name: str
) -> Organization:
    """Create an organization, refusing a slug that is already taken."""
    checked = check_slug(slug, "organization")
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into organizations (slug, name) values (%s, %s) "
            "on conflict (slug) do nothing returning id",
            (checked, name.strip() or checked),
        )
        row = cursor.fetchone()
    if row is None:
        # `on conflict do nothing` rather than a look-then-insert: two `org create`
        # commands racing would both pass the look and one would surface a raw
        # UniqueViolation traceback instead of a sentence.
        connection.rollback()
        raise TenancyError(f"an organization called {checked!r} already exists")
    connection.commit()
    return Organization(id=int(str(row[0])), slug=checked, name=name.strip() or checked)


def find_organization(
    connection: "Connection[tuple[object, ...]]", slug: str
) -> Organization | None:
    """Return the organization with this slug, or `None`."""
    with connection.cursor() as cursor:
        cursor.execute(
            "select id, slug, name, adopted from organizations where slug = %s",
            (check_slug(slug, "organization"),),
        )
        row = cursor.fetchone()
    return None if row is None else _organization(row)


def list_organizations(connection: "Connection[tuple[object, ...]]") -> tuple[Organization, ...]:
    """Every organization this collector holds, oldest first."""
    with connection.cursor() as cursor:
        cursor.execute("select id, slug, name, adopted from organizations order by id")
        rows = cursor.fetchall()
    return tuple(_organization(row) for row in rows)


def rename_organization(
    connection: "Connection[tuple[object, ...]]",
    slug: str,
    *,
    new_slug: str,
    new_name: str | None = None,
) -> Organization:
    """Rename an organization, keeping its projects and its adoption mark.

    Exists because a name migration 0003 invented must not be permanent. The
    adoption mark is a historical fact rather than a name, so it survives — which is
    also why it is a column and not the slug.
    """
    existing = find_organization(connection, slug)
    if existing is None:
        raise TenancyError(f"there is no organization called {slug!r}")
    checked = check_slug(new_slug, "organization")
    name = existing.name if new_name is None else (new_name.strip() or existing.name)
    with connection.cursor() as cursor:
        cursor.execute(
            "update organizations set slug = %s, name = %s where id = %s "
            "and not exists (select 1 from organizations where slug = %s and id <> %s)",
            (checked, name, existing.id, checked, existing.id),
        )
        changed = cursor.rowcount > 0
    if not changed:
        connection.rollback()
        raise TenancyError(f"an organization called {checked!r} already exists")
    connection.commit()
    return Organization(id=existing.id, slug=checked, name=name, adopted=existing.adopted)


def create_project(
    connection: "Connection[tuple[object, ...]]", organization_slug: str, slug: str, name: str
) -> Project:
    """Create a project inside an existing organization."""
    organization = find_organization(connection, organization_slug)
    if organization is None:
        raise TenancyError(
            f"there is no organization called {organization_slug!r}; create it with "
            f"`guardana-collector org create --slug {organization_slug} --name …`"
        )
    checked = check_slug(slug, "project")
    with connection.cursor() as cursor:
        cursor.execute(
            "insert into projects (organization_id, slug, name) values (%s, %s, %s) "
            "on conflict (organization_id, slug) do nothing returning id",
            (organization.id, checked, name.strip() or checked),
        )
        row = cursor.fetchone()
    if row is None:
        connection.rollback()
        raise TenancyError(f"a project called {organization.slug}/{checked} already exists")
    connection.commit()
    return Project(
        id=int(str(row[0])),
        organization_id=organization.id,
        organization_slug=organization.slug,
        slug=checked,
        name=name.strip() or checked,
    )


def list_projects(
    connection: "Connection[tuple[object, ...]]", organization_slug: str | None = None
) -> tuple[Project, ...]:
    """Every project, or every project of one organization, oldest first."""
    checked = None if organization_slug is None else check_slug(organization_slug, "organization")
    with connection.cursor() as cursor:
        cursor.execute(
            "select p.id, p.organization_id, o.slug, p.slug, p.name from projects p "
            "join organizations o on o.id = p.organization_id "
            "where (%s::text is null or o.slug = %s) order by p.id",
            (checked, checked),
        )
        rows = cursor.fetchall()
    return tuple(_project(row) for row in rows)


def find_project(connection: "Connection[tuple[object, ...]]", reference: str) -> Project | None:
    """Return the project this `organization/project` reference names, or `None`."""
    organization_slug, project_slug = parse_project_reference(reference)
    with connection.cursor() as cursor:
        cursor.execute(
            "select p.id, p.organization_id, o.slug, p.slug, p.name from projects p "
            "join organizations o on o.id = p.organization_id "
            "where o.slug = %s and p.slug = %s",
            (organization_slug, project_slug),
        )
        row = cursor.fetchone()
    return None if row is None else _project(row)


def resolve_project(connection: "Connection[tuple[object, ...]]", reference: str) -> Project:
    """Return the project this reference names, or refuse and name what to run."""
    project = find_project(connection, reference)
    if project is None:
        raise TenancyError(
            f"there is no project {reference!r}; list what exists with "
            f"`guardana-collector project list`, or create the first one with "
            f"`guardana-collector bootstrap --org … --project …`"
        )
    return project


def rename_project(
    connection: "Connection[tuple[object, ...]]",
    reference: str,
    *,
    new_slug: str,
    new_name: str | None = None,
) -> Project:
    """Rename a project. Keys keep pointing at it: they hang off its id, not its name."""
    existing = resolve_project(connection, reference)
    checked = check_slug(new_slug, "project")
    name = existing.name if new_name is None else (new_name.strip() or existing.name)
    with connection.cursor() as cursor:
        cursor.execute(
            "update projects set slug = %s, name = %s where id = %s and not exists ("
            "select 1 from projects where organization_id = %s and slug = %s and id <> %s)",
            (checked, name, existing.id, existing.organization_id, checked, existing.id),
        )
        changed = cursor.rowcount > 0
    if not changed:
        connection.rollback()
        raise TenancyError(
            f"a project called {existing.organization_slug}/{checked} already exists"
        )
    connection.commit()
    return Project(
        id=existing.id,
        organization_id=existing.organization_id,
        organization_slug=existing.organization_slug,
        slug=checked,
        name=name,
    )


def _organization(row: tuple[object, ...]) -> Organization:
    return Organization(
        id=int(str(row[0])), slug=str(row[1]), name=str(row[2]), adopted=bool(row[3])
    )


def _project(row: tuple[object, ...]) -> Project:
    return Project(
        id=int(str(row[0])),
        organization_id=int(str(row[1])),
        organization_slug=str(row[2]),
        slug=str(row[3]),
        name=str(row[4]),
    )
