# Design: collector persistence and migrations

**Status:** implemented in 0.8 · **Written:** 2026-08-03 · **Phase C, item 19**

## The problem

`guardana-server` keeps submissions in a bounded in-memory deque. A team that
runs it loses every finding on restart, and the store is the default — so nobody
has to choose it, which means somebody will run it in production without knowing
they chose anything.

Everything the collector is *for* — history, ownership, regression between
deployments, an audit trail — needs somewhere to live. Persistence is therefore
the first item of Phase C, and migrations have to exist before the first row is
written: principle 11 says a persisted schema is versioned and migratable, and a
migration bolted on after there is data to lose is a migration nobody trusts.

## Scope, deliberately narrow

This item delivers **the migration machinery plus today's schema**. Organizations,
projects, API keys and the AI-system model arrive as migrations `0002` and later,
in items 20–22.

That ordering is not laziness. It is the only way the migration path gets
exercised the way the acceptance criteria demand — *up and down on a database
with data in it* — rather than against an empty database where every migration
trivially works.

Two things this explicitly does **not** deliver, stated so the presence of a
database is not read as the presence of either:

- **No tenancy.** Every row is global until item 21.
- **No authentication.** Ingest is still unauthenticated until item 20.

The collector's maturity label stays `experimental` until both land. A database
does not make a service safe to expose.

## Design

### Layout

```
packages/guardana-server/src/guardana/server/
  db/
    settings.py      where the connection string comes from, and what happens without one
    connection.py    the pool
    migrations.py    discover, checksum, apply, roll back
    sql/
      0001_submissions.up.sql
      0001_submissions.down.sql
  postgres_store.py  the `Store` protocol, over psycopg3
  cli.py             guardana-collector migrate | rollback | status
```

`Store` (the protocol) is untouched. Two implementations behind one interface is
what the protocol was for, and a contract test runs the same assertions against
both so they cannot drift.

### The migration runner

Numbered SQL files, applied in order, recorded in a table.

```sql
create table schema_migrations (
    version     integer      primary key,
    name        text         not null,
    checksum    text         not null,
    applied_at  timestamptz  not null default now()
);
```

Five rules, each earning its place:

**Every migration ships a down file.** A missing `.down.sql` is a load error, not
a warning. A migration that cannot be undone is an upgrade nobody will risk, and
"we will write the rollback if we need it" is a decision made under exactly the
pressure that produces bad rollbacks.

**One transaction per migration, including its own bookkeeping row.** A migration
that fails half-way leaves the database as it found it, rather than in a state no
version describes.

**A Postgres advisory lock around the whole run.** Two replicas starting at once
must not both apply `0007`. The lock makes concurrent migration safe rather than
merely unlikely.

**The checksum of an applied migration is verified, and a mismatch refuses.**
Editing a migration that has already run somewhere means two databases disagree
about what version `0004` means, and nothing would ever notice. This is the same
argument as a versioned document: what somebody's database already contains is a
contract.

**A gap is refused.** An unapplied migration numbered below the highest applied
version is a rebase accident, and applying only what comes after it would skip
that migration on that database forever.

### Health and readiness are separate endpoints

- `GET /healthz` — the process is running. Touches no database.
- `GET /readyz` — connects, compares `schema_migrations` against the files on
  disk, and returns `503` while anything is pending.

Separate because a rolling deploy must not send traffic at a schema that is not
there yet. A single endpoint answering both questions makes the *deploy* the
thing that decides whether a half-migrated database receives writes.

### Migrations are applied by a command, not by starting the server

`guardana-collector migrate` is the documented path, and readiness holds traffic
back until it has run. `GUARDANA_MIGRATE_ON_START=1` exists for a single-node
Docker Compose, where the ceremony buys nothing.

### Choosing a store is a decision, never a default

`create_app()` resolves storage in this order:

1. an explicit `store=` argument — tests and embedders,
2. `GUARDANA_DATABASE_URL` → PostgreSQL,
3. `GUARDANA_STORAGE=memory` → the in-memory store, and the dashboard says so,
4. otherwise **refuse to start**, naming both options.

An ephemeral store that is the default is an ephemeral store that reaches
production. Making the choice explicit costs one environment variable and removes
a class of incident that only shows up as "where did last week go".

This is the same principle as "no default credentials", one layer down: the unsafe
configuration must not be the one you get by not deciding.

### The schema at 0001

Exactly what the envelope carries today, normalised into two tables:

```sql
create table submissions (
    id              bigserial    primary key,
    received_at     timestamptz  not null,
    source          text         not null,
    schema_version  integer      not null,
    rules_run       integer      not null default 0,
    rules_executed  text[]       not null default '{}',
    rules_skipped   jsonb        not null default '[]',
    max_severity    text,
    unverified      integer      not null default 0,
    error_count     integer      not null default 0,
    errors          jsonb        not null default '[]'
);

create table findings (
    id                  bigserial primary key,
    submission_id       bigint    not null references submissions(id) on delete cascade,
    channel             text      not null,   -- findings | unverified
    position            integer   not null,
    rule_id             text      not null,
    severity            text      not null,
    title               text      not null,
    target_ref          text      not null,
    evidence_summary    text      not null,
    evidence_detail     text,
    taxonomy            jsonb     not null default '[]',
    verdict_outcome     text,
    verdict_confidence  double precision,
    verdict_rationale   text,
    verdict_evaluator   text
);
```

`channel` rather than two tables, because `unverified` is the same shape and the
distinction is a property of the finding, not of its storage. `position` preserves
the order the agent sent, so a round trip returns what was submitted.

The `errors` and `rules_skipped` channels are stored as `jsonb`: they are read as
whole documents and never filtered on, and modelling them as tables now would be
inventing structure ahead of a query that wants it.

### Dependencies

One new production dependency on `guardana-server` only: `psycopg[binary]>=3.2`.

`guardana-core` is untouched, and the import-linter contract still forbids the
engine from importing the collector. Justification for the dependency: talking to
PostgreSQL requires a PostgreSQL driver, psycopg3 is the maintained one, and the
alternative — an ORM — would add a second large dependency and a query layer the
collector has no use for.

## Testing

Tests that need a database are marked `postgres` and take a session fixture.
Without a database they **skip loudly**; with `GUARDANA_REQUIRE_POSTGRES=1` set,
the skip becomes a failure. CI sets it and runs a `postgres:16` service container.

That asymmetry is the point. Item 21's cross-tenant tests are the ones that must
never be quietly absent, and "the isolation test did not run" reading as green is
the same fail-open this project rejects everywhere else — just relocated into the
test suite.

Coverage:

- migrate up on an empty database; the tables exist
- migrate up twice; the second is a no-op
- migrate down; the tables are gone and `schema_migrations` is empty
- **insert rows, migrate forward, assert the rows survived** — the acceptance
  criterion, and the one an empty-database test cannot make
- an applied migration whose file was edited is refused, naming the version
- a migration file with no down file is refused at load
- two runners racing apply each migration exactly once
- `/readyz` fails while a migration is pending and passes after
- `/healthz` answers without a database at all
- the `Store` contract test, parametrised over both implementations
- `create_app()` with no database and no explicit choice refuses to start

## Acceptance criteria

- `guardana-collector migrate`, `rollback` and `status` work against a real
  PostgreSQL, and each is tested.
- A submission survives a process restart.
- Readiness fails while migrations are pending.
- No configuration produces a running collector that silently forgets data.
- The engine still does not import the collector (`lint-imports`).

## Open questions

1. **Retention of `findings` rows on `submissions` delete** is `cascade` here.
   Item 26 (retention) may want the submission gone and an aggregate kept; that
   is a decision for retention, not for storage, and cascade is the honest
   default until it is made.
2. **Whether `rules_skipped` stays `jsonb`.** Item 21 gives coverage gaps a
   tenant, and a fleet view that filters on skip reason would want a table. Left
   as a document until there is a query.
