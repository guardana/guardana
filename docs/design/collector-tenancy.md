# Design: collector tenancy — organizations and projects

**Status:** accepted, not yet implemented · **Written:** 2026-08-04 · **Phase C, item 21**

## The problem

Every API key a collector issues can read every finding the collector holds.
Persistence (item 19) and authentication (item 20) made the collector something a
team can keep and something a stranger cannot write to, but they did not make it
something *two* teams can share. One instance therefore serves one team, which is
why its maturity label is still `experimental` and why "project/environment
isolation" is still unticked on the company-ready checklist.

Principle 12 says tenancy is part of the definition of done rather than a later
hardening pass, so the isolation tests are written with the feature and not after
it.

## What must not get harder

Stated first, because a security boundary added carelessly is how a tool that
anybody could run becomes a tool only its authors run.

- **A local scan is untouched.** `pip install guardana && guardana scan .` does
  not involve a collector, an organization or a key, and nothing here changes
  that. The engine still never imports the server.
- **The envelope stays at v5.** An agent sends exactly what it sends today, so no
  fleet has to be upgraded in step with a collector. This is a direct consequence
  of taking the project from the key rather than from the envelope.
- **Evaluating the collector on a laptop stays two variables.**
  `GUARDANA_STORAGE=memory` with `GUARDANA_ALLOW_UNAUTHENTICATED=1` still starts a
  collector with a working dashboard and no database, no organization and no key.
- **Standing a real collector up gains one command, not four.**
  `guardana-collector bootstrap --org acme --project web` creates the
  organization, the project and the first key together and prints the key once.
  The granular `org create` / `project create` / `key create --project` commands
  exist for the second team, not for the first run.

The full first-run path gains exactly one line, the last one:

```bash
docker compose -f deploy/docker-compose.dev.yml up -d
export GUARDANA_DATABASE_URL=postgresql://…
guardana-collector migrate
guardana-collector bootstrap --org acme --project web   # prints the key, once
uvicorn 'guardana.server:create_app' --factory
```

`bootstrap` refuses when that organization and project already exist, naming
`key create` instead. A command that quietly succeeds the second time is a command
somebody runs twice in a script and never notices issued two credentials.

## Four decisions

### 1. A database with data is adopted, not refused

The alternatives were refusing to migrate until an administrator names an
organization, and leaving the tenant column empty so pre-tenancy rows become
invisible.

The third is worst: the rows still exist, they vanish from every view, and the
team reads that as data loss. Refusing is the most faithful to "a decision, never
a default", but it stops an upgrade half-way, and that is exactly the pressure
that produces workarounds — the same argument that makes every migration ship a
rollback.

Adoption creates no leak, and that is what settles it. Every pre-tenancy row and
every pre-tenancy key lands in the *same* project, which is where they already
were together; an organization created afterwards is invisible to the old keys.

Three conditions make adoption honest rather than convenient:

- **The organization is called `adopted`, not `default`.** The name states what
  happened: this is where migration `0003` put the rows that predate tenancy. A
  thing called `default` is a thing nobody chose.
- **It is created only when there is something to adopt.** On an empty database
  the migration creates no organization at all, so a fresh install does not get a
  tenant it never asked for.
- **It can be renamed.** `org rename` and `project rename` exist because a name
  the migration invented must not be permanent.

The adoption condition covers **submissions or api_keys**, not submissions alone.
A collector that has issued keys but received no runs is a real state, and
`api_keys.project_id` is `not null` — so keying adoption off submissions alone
would fail the migration on exactly that database.

### 2. The scope is the first argument of every `Store` method

The alternative was a per-request repository — `store.for_project(id)` returning
an object that carries the scope. It has one genuine advantage: a method cannot
be added without a scope, because the scope lives in the constructor. It also has
a failure mode this does not: an object holding a tenant can be stored in a module
global and reused by the next request.

So the scope goes in the signature, and the missing property is bought with a
test rather than with a shape:

```python
class Store(Protocol):
    def add(self, scope: TenantScope, submission: Submission) -> None: ...
    def submissions(self, scope: TenantScope, source: str | None = None,
                    limit: int | None = None) -> list[Submission]: ...
    def trend(self, scope: TenantScope) -> dict[str, int]: ...
    def records(self, scope: TenantScope, source: str | None = None,
                limit: int | None = None) -> list[StoredSubmission]: ...
```

`test_no_store_method_is_unscoped` walks the protocol's public methods and asserts
each takes `scope: TenantScope` first. Whoever adds a fifth method without one
sees red — the same trade this repository makes everywhere else, where a promise
that could rot becomes a gate that cannot.

`TenantScope` is a type rather than a bare `int`, because `submissions(scope,
source, limit)` with three positional primitives is a mistake waiting for a
distracted afternoon.

### 3. The project comes from the key, never from the envelope

If the envelope named the project, the runner would declare where it writes, and a
credential that does not bound the write is not a boundary at all. Taking it from
the key also means the envelope does not move to v6: an agent and a collector
still upgrade independently, and nothing in `guardana-core` changes.

The cost is real and is accepted: a team with ten projects needs ten keys in CI.
That is the same reasoning that gave keys two scopes instead of one, and it is the
direction a credential should err in.

A rule for whoever revisits this: if the envelope ever carries a project
identifier, a mismatch with the key must be a **refusal**, never "prefer the more
specific one". Anything else re-opens the hole this decision closes.

### 4. "Unknown project on ingest" stops being reachable

Decision 3 removes the question. The project is read from the authenticated key,
and `api_keys.project_id` has a foreign key onto `projects`, so a submission
cannot name a project that does not exist.

What remains is a deleted project with a surviving key, and the answer is `on
delete restrict` plus **no delete command in this item**. Removing tenant data is
retention (item 26) and deserves to be designed there rather than smuggled in
here. The domain model's related question — a `Deployment` created but marked
unclaimed — belongs to item 22, where deployments arrive.

## Design

### Schema, migration 0003

```sql
create table organizations (
    id          bigserial    primary key,
    slug        text         not null unique,
    name        text         not null,
    created_at  timestamptz  not null default now()
);

create table projects (
    id               bigserial    primary key,
    organization_id  bigint       not null references organizations (id) on delete restrict,
    slug             text         not null,
    name             text         not null,
    created_at       timestamptz  not null default now(),
    unique (organization_id, slug)
);

alter table submissions add column project_id bigint references projects (id) on delete restrict;
alter table api_keys    add column project_id bigint references projects (id) on delete restrict;
```

Adoption runs only when there is something to adopt, then both columns become
`not null` — so no row can exist without a tenant, and a scoped query cannot
silently fail to return one.

Indexes are replaced rather than added. Every read now filters on `project_id`
first, which makes `submissions_received_at_idx` and `submissions_source_idx` dead
weight paid for on every insert:

```sql
drop index submissions_received_at_idx;
drop index submissions_source_idx;
create index submissions_project_received_idx on submissions (project_id, received_at desc);
create index submissions_project_source_idx   on submissions (project_id, source);
```

`trend()` now joins `findings` to `submissions` to filter by tenant, and this
composite index is what keeps that join driven by the submission side. Principle 2
— cost grows with the target, not with the rule count — applies to the collector's
queries as much as to a scan.

### The rollback refuses to merge two tenants

`0003.down.sql` drops the tenant columns, which on a database serving two teams
would silently merge their evidence into one undifferentiated pile. So it checks
first and raises:

```sql
do $$
begin
    if (select count(distinct project_id) from submissions) > 1
       or (select count(distinct project_id) from api_keys) > 1 then
        raise exception 'refusing to roll back tenancy: this database holds data for more '
                        'than one project, and dropping the tenant column would merge them';
    end if;
end $$;
```

This is a fourth entry in the table of things the migration runner refuses,
alongside an edited migration, a renumbered one, and a database written by a newer
build. Unlike those three it is specific to one migration, which is the right
place for it: only this migration can destroy an isolation boundary.

The down file also **restores the two indexes it dropped**. A rollback that leaves
the database missing what the previous migration created is a rollback that only
half went backwards, and the next reader pays for it in query plans nobody
associates with a schema change.

### The unauthenticated mode has a scope that cannot touch a database

A collector running `GUARDANA_STORAGE=memory` with authentication explicitly
disabled has no organizations, no projects and no keys — and it must keep working,
because that is the path somebody evaluating Guardana takes first.

`TenantScope.unauthenticated()` is that scope. The in-memory store treats it as an
ordinary tenant; **`PostgresStore` raises `UnscopedQueryError` on it**, on read and
on write alike. A scope that belongs to nobody must not be able to reach durable
evidence, and making that structural beats making it a rule someone has to
remember.

Two paths reach it, and both are tested rather than reasoned about:

- `guard()` returns no identity only when there is no database URL, so a collector
  with a database can never fall into this scope;
- `create_app(store=…)` leaves `database_url` unset, and already refuses to build
  unless the caller passes `allow_unauthenticated=True`. That refusal is what
  stops an embedder handing in a `PostgresStore` and getting an unauthenticated,
  unscoped collector.

### Identity carries the tenant

`authenticate()` reads `project_id` alongside the scopes, and `Authenticated`
gains it. The app derives the scope from the identity, so no handler chooses a
tenant:

```python
scope = identity.scope if identity is not None else TenantScope.unauthenticated()
```

### Commands

A new `tenancy.py` holds the domain — `TenantScope`, organizations, projects, and
resolving a `org/project` reference — beside `auth.py`, which already holds keys.
`cli.py` becomes a package so each command group stays one short file:
`cli/schema.py` (migrate, status, rollback), `cli/keys.py`, `cli/tenants.py`.

```bash
guardana-collector bootstrap --org acme --project web   # org + project + first key
guardana-collector org create --slug acme --name "Acme Inc"
guardana-collector org list                             # marks the adopted one
guardana-collector org rename --slug adopted --to acme
guardana-collector project create --org acme --slug web --name "Web app"
guardana-collector project list [--org acme]
guardana-collector project rename --project acme/web --to api
guardana-collector key create --project acme/web --name github-actions
guardana-collector key list [--project acme/web]
```

`key create` requires `--project` and does not guess when exactly one exists.
Issuing a credential against a tenant nobody named is the same shape as a default
credential. On a collector with no organizations it says what to run instead of
what went wrong.

`org list` marks the adopted organization for what it is, so an administrator who
upgraded without reading a changelog still finds out where their history went.

## Testing

Every isolation test takes the `database_url` fixture, so it cannot quietly not
run: without a database it skips, and `GUARDANA_REQUIRE_POSTGRES=1` — which CI
sets — turns that skip into a failure.

- the `Store` contract, parametrised over both implementations, with a scope on
  every call
- **cross-tenant read**: write under project A, read under B — `submissions`,
  `trend` and `records` each return nothing, on both stores
- **cross-tenant write**: two keys, two projects; each sees only its own after
  both have written
- both of the above **between two organizations** and **between two projects of
  one organization**
- over HTTP, not only at the store: key A posts, key B gets, and gets nothing
- `PostgresStore` refuses `TenantScope.unauthenticated()`
- no `Store` method is unscoped (protocol introspection)
- `0003` on a database with submissions **and** keys: both adopted, and the
  pre-existing key still authenticates afterwards
- `0003` on a database with keys and no submissions: adopted
- `0003` on an empty database: no organization is created
- `0003` rollback with one project: succeeds
- `0003` rollback with two projects: refuses, and the message says why
- `bootstrap` creates all three and prints the key once
- `key create` without `--project`, and on a collector with no organizations:
  usage error naming the next command
- an unauthenticated collector still ingests, reads and renders its dashboard

## Acceptance criteria

- Cross-tenant read and write fail, per entity, as tests, on both stores.
- Migration up and down on a database with data.
- No query without a scope, enforced by a test rather than by review.
- The envelope stays at v5 and `guardana-core` is unchanged.
- First run of a real collector is three commands.
- The engine still does not import the collector (`lint-imports`).

## What this item deliberately does not deliver

The maturity label stays `experimental`. The checklist entry is
"project/environment **isolation**", environments arrive in item 22, and a
checklist that moves to match what shipped is not a checklist.

Also out of scope, each with its own item: human roles and browser sessions (the
dashboard still refuses to mount on an authenticated collector), the audit log
(25), deletion and retention (26), environments and deployments (22).

## Open questions

1. **An organization-scoped key**, so one CI credential can write to several
   projects. It is a real request from a monorepo, and it is also how a leaked
   credential stops being contained. Waiting for someone to ask, and for the role
   model in item 24.
2. **Recording which key wrote a submission.** One column, obviously useful, and
   it is the first row of the audit log rather than a field on storage — so it
   lands with item 25 and its retention question.
3. **The in-memory store's bound is shared across tenants**, so one noisy tenant
   could evict another's. It cannot happen today, because the unauthenticated mode
   has exactly one scope. If that ever changes, the bound has to become per-scope.
