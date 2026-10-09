---
title: "Deploying the collector"
nav_order: 290
summary: "running the collector in production: Compose, TLS, upgrades, what to watch, and what it does not give you yet"
status: beta
---

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

If the proxy connects from outside loopback, set `FORWARDED_ALLOW_IPS` in the collector's environment to the client address shown in its access log for a forwarded request. Uvicorn trusts `X-Forwarded-Proto` and `X-Forwarded-For` only from those addresses; the default is `127.0.0.1,::1`. This applies to a proxy in another container or a host proxy reaching a Compose published port through Docker's gateway. Without that trust, the dashboard session cookie lacks `Secure` and per-address limits count requests as coming from the proxy. Never use `*` on a port others can reach, since callers could claim `https` and any client address.

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
docker compose -f deploy/docker-compose.yml stop collector     # nothing writes while the schema changes
docker compose -f deploy/docker-compose.yml --profile migrate run --rm migrate
docker compose -f deploy/docker-compose.yml up -d
curl -fsS https://collector.example.com/readyz                 # ready once storage and schema agree
```

In that order, and never with the migration skipped. The old collector stops before the
schema changes, because a collector refuses a database written by a newer build, and the
new image starts only after the migration. Send traffic back once `/readyz` answers. What protects you if it
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

**Pin the image to a minor tag** (`:0.30`) rather than `latest`. You want fixes
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
BACKUP="guardana-$(date -u +%Y-%m-%d).dump"
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom \
  > "$BACKUP"
```

Restore it — into an **empty** database, which is what a rebuild on a new machine
actually looks like. Name the dump you are restoring and check that it reads before
anything is dropped:

```bash
set -a; . deploy/.env; set +a
BACKUP=guardana-2026-08-05.dump                                 # the dump to restore
docker compose -f deploy/docker-compose.yml exec -T db pg_restore --list < "$BACKUP" > /dev/null

docker compose -f deploy/docker-compose.yml stop collector     # nothing writes mid-restore

docker compose -f deploy/docker-compose.yml exec -T db psql -U "$POSTGRES_USER" -d postgres \
  -c "drop database if exists \"$POSTGRES_DB\" with (force)" \
  -c "create database \"$POSTGRES_DB\""

docker compose -f deploy/docker-compose.yml exec -T db \
  pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists \
  < "$BACKUP"

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

## Rotating an API key

Rotate on a schedule, when someone who held a key leaves, and at once when a key
may have leaked. Both keys work until the old one is revoked, allowing pipelines to switch without a gap in key validity.

1. **Issue** the new key for the same project, with the same `--scope` and
   `--environment` as the one it replaces. `key list` shows both: the scopes, and the
   environment in brackets after the project. Repeat them, because `--scope` defaults
   to `ingest` alone and a key created without `--environment` may write to any
   environment of the project:

   ```bash
   docker compose -f deploy/docker-compose.yml run --rm collector key list --project acme/web
   docker compose -f deploy/docker-compose.yml run --rm collector \
     key create --project acme/web --name github-actions-2 \
     --scope ingest --environment production   # the old key's values; prints the key, once
   ```

2. **Deploy** it: replace `GUARDANA_COLLECTOR_TOKEN` in every pipeline that used
   the old key, and let one run report with it.
3. **Revoke** the old key by the prefix `key list` shows:

   ```bash
   docker compose -f deploy/docker-compose.yml run --rm collector key list --project acme/web
   docker compose -f deploy/docker-compose.yml run --rm collector key revoke <old-prefix>
   ```

4. **Confirm** the old key is refused. An empty body stores nothing whatever the
   answer: `401` means the key is revoked, and `422` means it still works.

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' -X POST https://collector.example.com/findings \
     -H "Authorization: Bearer $OLD_KEY" -H 'Content-Type: application/json' -d '{}'
   ```

Rotation changes who may write, never what was written: the runs the old key
sent stay in the project. A key belongs to one project, so a team with several
projects rotates each key on its own.

## If the database credential leaks

1. Change the role password and restrict the hosts it may connect from.
2. Update `GUARDANA_DATABASE_URL` and restart every replica. Run `guardana-collector status` to confirm the new credential works.
3. Treat the stored findings as disclosed and tell each project's owners.
4. Run `guardana-collector key list`, then revoke every key nobody issued with `guardana-collector key revoke`.

Database read access exposes every project. Write access can add API keys, rewrite submissions and edit the audit log. Stored API keys are digests, so the leak does not expose existing keys.

## Which test exercises each procedure

A procedure nobody has run is a belief. Each of these is run by a PostgreSQL test
in `packages/guardana-server/tests/`, which CI refuses to skip; deletion is
described in [`usage-collector.md`](usage-collector.md).

| Procedure | Test |
|---|---|
| backup and restore | `test_backup_restore.py` |
| upgrade, roll back one step, migrate forward | `test_migrations.py` |
| upgrade from the schema of an older release, then ingest every envelope a published release wrote | `test_upgrade_from_previous_release.py` |
| key rotation | `test_key_rotation.py` |
| retention, and deleting a project or an organization | `test_retention_and_deletion.py` |

## What to watch

Two limits are on by default and worth knowing before a fleet meets them:
`GUARDANA_MAX_BODY_BYTES` (8 MiB, answering `413`) and
`GUARDANA_RATE_LIMIT_PER_MINUTE` (120 per caller, answering `429` with
`Retry-After`). The rate limiter counts **per worker process** — for a global
limit, rate-limit at the proxy that already terminates TLS.

| Signal | Why |
|---|---|
| `/readyz` | the only endpoint that knows about storage and pending migrations |
| container restarts | a collector that cannot reach its database exits rather than serving half a service |
| `guardana-collector status` | which migrations are applied, and whether any are pending |
| disk on the `guardana-data` volume | retention is per project and **off until you set it**: submissions accumulate until a policy or a delete removes them |

That last row is the one to act on. `guardana-collector retention set --project
ORG/PROJECT --keep-days N` records a policy and deletes nothing; `retention apply`
removes what the policy says is too old, and only when it runs. Without a policy the
volume grows for as long as agents report: `--forever` is the default on purpose,
because silently deleting a customer's evidence is the worse failure. To bound the
growth, run `apply` on a schedule and alert when it fails:

```bash
# cron, daily at 03:00; --dry-run first, by hand, to see what would go
0 3 * * * cd /srv/guardana && docker compose -f deploy/docker-compose.yml run --rm collector \
  retention apply --project acme/web || logger -t guardana "retention apply failed"
```

## What this deployment does not give you yet

Being explicit, because a deployment guide that oversells is worse than none:

- **no user accounts** — the read-only panel signs in with a read-scoped API key
  rather than with a person's identity, so "who looked at this" is answerable only
  down to the credential. OIDC/SSO and human roles are not built; see the
  roadmap's [Later list](../ROADMAP.md#later) for conditional possibilities;
- **no quality trend** — the collector aggregates findings, `unverified` and
  errors. It does not yet store the measurement channel, so it can say a system is
  accumulating security problems and cannot say whether its answers got better;
- **no Kubernetes manifests or Helm chart** — the image, the environment variables
  and the two probes are all a Deployment needs, but we do not ship one we have not
  exercised;
- **one process, scaled by replicas you run yourself** — there is no worker pool,
  no queue and no leader election, so anything periodic is something you schedule
  outside the collector.

What this list no longer contains, because it shipped: finding lifecycle, waivers,
audit log, retention and deletion, and a restore-tested backup procedure. Each is
in [`docs/usage-collector.md`](usage-collector.md).

These collector features are absent, and their absence is not silently worked
around; see the [roadmap](../ROADMAP.md) for future direction.

## Running it without Compose

The image is the unit; Compose is a convenience:

```bash
docker run -d --name guardana-collector \
  -e GUARDANA_DATABASE_URL="postgresql://guardana:…@db.internal:5432/guardana" \
  -p 127.0.0.1:8000:8000 \
  ghcr.io/guardana/guardana-collector:0.41
```

Or without a container at all — `pip install "guardana-server[serve]"`, then
`guardana-collector migrate` and `guardana-collector serve`. The ASGI server is an
extra rather than a dependency, so a site that already runs gunicorn points it at
`guardana.server:create_app()` instead.
