# Deploying the collector in production

Everything Guardana does on a laptop or in CI works without this page. The
collector is the optional part: one place where many pipelines' runs and findings
land, so a team can ask "is production worse than last week" and get an answer
from evidence rather than from memory.

This is how to run one you can keep — and how to upgrade it without a surprise.
The images and their tags are [`deploy/docker/README.md`](../deploy/docker/README.md);
what the collector does and deliberately does not do is
[`usage-collector.md`](usage-collector.md).

## What you are deploying

| Piece | What it is | Durable? |
|---|---|---|
| `db` | PostgreSQL 16 | **yes** — the `guardana-data` volume is the only state that matters |
| `collector` | the HTTP API pipelines report to | no |
| `migrate` | a one-shot command, run on purpose | no |

Two decisions are baked into [`deploy/docker-compose.yml`](../deploy/docker-compose.yml)
and are worth understanding before you change them.

**No credential has a default.** Every secret is `${VAR:?}`, so Compose refuses to
start rather than fall back to something guessable. This is the same rule the
collector applies to its own storage — it will not start without being told where
to keep submissions — because the unsafe configuration must never be the one you
get by not deciding.

**Migrations are not run on start.** A rolling deploy would otherwise briefly run
two versions of the code against one schema, and the operator undoing that at
three in the morning wants one instruction (`rollback`), not a restart with a
different environment variable. `/readyz` fails while a migration is pending, so a
half-upgraded collector never quietly serves traffic.

## Standing one up

```bash
cp deploy/env.example deploy/.env
$EDITOR deploy/.env                    # it has no defaults; fill them in

docker compose -f deploy/docker-compose.yml --profile migrate run --rm migrate
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml run --rm collector \
  bootstrap --org acme --project web   # prints the key, once
```

`bootstrap` creates the organization, the project and the first API key together.
Store the key immediately: only a digest is kept, and there is no command that
prints it again — a credential a system can re-read is a credential that leaks
through every path that reads it.

Check what you have:

```bash
curl -fsS http://127.0.0.1:8000/healthz    # the process answers
curl -fsS http://127.0.0.1:8000/readyz     # storage reachable, schema current
```

They are separate on purpose. `/healthz` is liveness. `/readyz` is the one that
fails while a migration is pending or the database is unreachable — point an
orchestrator's readiness probe at it, and alert on it rather than on `/healthz`.

## Put TLS in front of it

The collector publishes on **loopback**. Ingest carries API keys and evidence, so
a public interface without TLS is a credential leak with extra steps. Terminate
TLS with whatever you already run:

```nginx
server {
    listen 443 ssl;
    server_name collector.example.com;
    ssl_certificate     /etc/letsencrypt/live/collector.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/collector.example.com/privkey.pem;

    # Submissions are small, but a run with a lot of evidence is not tiny.
    client_max_body_size 32m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Caddy needs two lines for the same thing:

```caddyfile
collector.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

Then point pipelines at the public name — the URL keeps its own scheme, and a
bare `host:port` is refused rather than guessed:

```bash
export GUARDANA_COLLECTOR_TOKEN=gdn_…     # a masked/secret CI variable
guardana scan . --ai-system support-agent --environment production \
  --reporter server://https://collector.example.com
```

## Upgrading

```bash
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml --profile migrate run --rm migrate
docker compose -f deploy/docker-compose.yml up -d
```

In that order, and never with the middle step skipped. What protects you if it
goes wrong is built into the migration runner: every migration ships a rollback,
each runs in its own committed transaction under an advisory lock, and the runner
**refuses** a migration edited after it was applied, one numbered below the
highest applied, or a database written by a newer build than the one you are
running. So a collector pointed at a database from the future stops rather than
writing into it.

To undo one step:

```bash
docker compose -f deploy/docker-compose.yml --profile migrate run --rm migrate rollback --steps 1
docker compose -f deploy/docker-compose.yml status   # or: guardana-collector status
```

Roll the *image* back to the matching tag at the same time. A collector older
than its schema is exactly the situation `/readyz` and the version check exist to
stop, and they will stop it.

**Pin the image to a minor tag** (`:0.9`) rather than `latest`. You want fixes
without a schema you did not plan for; `latest` gives you both.

## Backups, and restoring one

The `guardana-data` volume is the only state that matters, and the only backup
that counts is one you have restored. This procedure is **exercised by the test
suite** (`packages/guardana-server/tests/test_backup_restore.py`) — the same
programs with the same flags, restored into a database that never held the data,
and then read back through the same scoped store the server uses.

Take one:

```bash
set -a; . deploy/.env; set +a
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom \
  > "guardana-$(date -u +%Y-%m-%d).dump"
```

Restore it — into an **empty** database, which is what a rebuild on a new machine
actually looks like:

```bash
docker compose -f deploy/docker-compose.yml stop collector     # nothing writes mid-restore

docker compose -f deploy/docker-compose.yml exec -T db psql -U "$POSTGRES_USER" -d postgres \
  -c "drop database if exists \"$POSTGRES_DB\" with (force)" \
  -c "create database \"$POSTGRES_DB\""

docker compose -f deploy/docker-compose.yml exec -T db \
  pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists \
  < guardana-2026-08-05.dump

docker compose -f deploy/docker-compose.yml start collector
curl -fsS http://127.0.0.1:8000/readyz     # storage reachable, schema current
```

Three things this procedure is deliberate about:

**Run `pg_dump` inside the database container.** Not because it is tidier —
because the client tools and the server then cannot drift apart. `pg_dump` 17
against PostgreSQL 16 produces a dump that `pg_restore` cannot load back into 16:
it carries `SET transaction_timeout`, a parameter 16 has never heard of, and the
restore ends with "errors ignored" and a non-zero exit. That is a backup that
looks fine every day and fails on the one day it matters. If you do run the tools
on the host, install the client matching your server's major version.

**Restore into an empty database.** Restoring over the live one passes even when
the dump is half-written, because the data was already there. The test does the
same thing for the same reason.

**Check `/readyz`, not `/healthz`.** A restore that dropped the migration history
leaves a collector that answers requests and cannot be upgraded — `/readyz` is the
endpoint that reads storage and schema state, and the test asserts the restored
database reports the same applied migrations as the original.

Keep the dump somewhere your `deploy/.env` is not. A backup stored beside the
credentials for the system it came from is one theft, not two.

## What to watch

| Signal | Why |
|---|---|
| `/readyz` | the only endpoint that knows about storage and pending migrations |
| container restarts | a collector that cannot reach its database exits rather than serving half a service |
| `guardana-collector status` | which migrations are applied, and whether any are pending |
| disk on the `guardana-data` volume | there is **no retention yet**: submissions accumulate until you remove them |

That last row is a real limitation, not a footnote. Until retention lands, size
the volume for the runs you keep and watch it like any other database.

## What this deployment does not give you yet

Being explicit, because a deployment guide that oversells is worse than none:

- **no finding lifecycle and no waivers in the collector** — accepted risk lives
  in `guardana baseline` next to the code, which is the right place for it today;
- **no audit log** — who created a key, who read what, is not recorded;
- **no retention or deletion** — nothing removes old submissions;
- **no dashboard on an authenticated collector** — the read-only page refuses to
  mount when API keys are required, because a browser cannot present a bearer
  token and every panel would load empty;
- **no Kubernetes manifests** — the image, the environment variables and the two
  probes are all a Deployment needs, but we do not ship one we have not exercised.

These are the collector's open items on the
[roadmap](../ROADMAP.md#milestone-team-security-platform), and none of them is
worked around silently: each is absent, and says so.

## Running it without Compose

The image is the unit; Compose is a convenience:

```bash
docker run -d --name guardana-collector \
  -e GUARDANA_DATABASE_URL="postgresql://guardana:…@db.internal:5432/guardana" \
  -p 127.0.0.1:8000:8000 \
  ghcr.io/guardana/guardana-collector:0.9
```

Or without a container at all — `pip install "guardana-server[serve]"`, then
`guardana-collector migrate` and `guardana-collector serve`. The ASGI server is an
extra rather than a dependency, so a site that already runs gunicorn points it at
`guardana.server:create_app()` instead.
