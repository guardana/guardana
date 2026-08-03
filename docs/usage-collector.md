# The collector — persistence, migrations, and what a database does not fix

The collector (`guardana-server`) aggregates findings from many agents. It is
**optional in every direction**: the engine never imports it, no feature needs it,
and nothing is sent anywhere unless a run is given `--reporter`.

> **Maturity: experimental.** It now keeps what it is given, which is what this
> page is about. It still has **no authentication and no tenancy** — anyone who
> can reach the port can read every finding in it. Do not expose it. Those land
> with the next two items, and the label moves to `beta` when they do.

## Choosing where submissions go

There is no default, on purpose. A store nobody chose is a store somebody
deploys, and the ephemeral one loses everything on restart.

```bash
# Durable. What a team should run.
export GUARDANA_DATABASE_URL=postgresql://guardana:secret@db:5432/guardana

# Ephemeral, and you had to say so. For evaluating Guardana on a laptop.
export GUARDANA_STORAGE=memory
```

With neither set, the collector refuses to start and says which to set. This is
the same rule as "no default credentials", one layer down: the unsafe
configuration must not be the one you get by not deciding.

## Migrations

```bash
guardana-collector status      # what is applied, what is pending
guardana-collector migrate     # apply everything pending
guardana-collector rollback    # undo the most recent (--steps N for more)
```

Exit codes match [the table the rest of the tool uses](exit-codes.md): `0` did
what was asked, `1` the database said no, `3` the command was pointed at nothing.

**Every migration ships a rollback**, checked when the migration set is loaded
rather than when it is needed. A schema change that cannot be undone is an upgrade
nobody will risk, and "we will write the rollback if we need it" is a decision
made under exactly the pressure that produces bad rollbacks.

**Each migration runs in one transaction**, together with the row that records it.
One that fails half-way leaves the database as it found it, rather than in a state
no version describes.

**A Postgres advisory lock covers the whole run**, so two replicas starting
together cannot both apply the same version.

### Three things the runner refuses

| Refused | Why |
|---|---|
| a migration edited after it was applied | two databases now disagree about what version four *is*, and nothing else would ever notice. The checksum is recorded when it is applied and checked every time after. Add a new migration instead |
| a migration numbered below the highest applied one | a rebase accident. Applying only what comes after would skip it on that database forever, while every other database has it |
| a database holding a migration this build does not ship | it was written by a newer Guardana, and an older collector would write rows the newer schema does not describe |

## Health and readiness are two questions

```bash
curl -s localhost:8000/healthz   # the process is running. Touches no database
curl -s localhost:8000/readyz    # the schema this build expects is the one present
```

`/readyz` returns `503` while a migration is pending, so a rolling deploy does not
send traffic at a schema that is not there yet — and returns `503` again after a
rollback, which is the direction that matters during an incident.

Under `GUARDANA_STORAGE=memory` it reports `"storage": "memory"` rather than a
plain "ready". A fleet view that cannot tell durable from ephemeral will read one
as the other, and the ephemeral one is the one that forgets.

## Applying migrations

`guardana-collector migrate` is the supported path. `GUARDANA_MIGRATE_ON_START=1`
makes the server migrate before serving, which is what a single-node Docker
Compose wants and what a rolling deploy should not have: migrating on boot means
two versions of the code briefly run against one schema.

## Running one locally

```bash
docker compose -f deploy/docker-compose.dev.yml up -d
export GUARDANA_DATABASE_URL=postgresql://guardana:guardana@127.0.0.1:55439/guardana_test
uv run guardana-collector migrate
uv run uvicorn 'guardana.server:create_app' --factory
```

Then point a run at it:

```bash
guardana scan . --reporter server://http://127.0.0.1:8000
```

A collector that is unreachable never changes a gate's exit code — the scan
already ran and its verdict stands on its own. A collector that *rejects* a
submission is different and says so, because a whole fleet silently failing to
report while a dashboard shows stale data as current is the failure that matters.

## Contributing to the collector

Its tests need a real PostgreSQL. Without one they **skip**, so changing a rule
does not require running a database. Setting `GUARDANA_REQUIRE_POSTGRES=1` turns
that skip into a failure, and CI sets it — because "the isolation test did not
run" reading as a green build is the same fail-open this project refuses
everywhere else, relocated into the test suite.

```bash
docker compose -f deploy/docker-compose.dev.yml up -d
uv run pytest packages/guardana-server
```

Every assertion about storage runs against **both** the in-memory store and
PostgreSQL, from one parametrised contract test. Two implementations tested apart
become two implementations that behave differently, and the one nobody runs
locally is the one that behaves differently in production.

## See also

- [`design/collector-domain-model.md`](design/collector-domain-model.md) — the model the next items build
- [`design/2026-08-03-collector-persistence-design.md`](design/2026-08-03-collector-persistence-design.md) — why this item is shaped the way it is
- [`architecture.md`](architecture.md#the-coreserver-boundary) — why the engine never imports this
- [`privacy.md`](privacy.md) — evidence is redacted by the agent before it is sent
