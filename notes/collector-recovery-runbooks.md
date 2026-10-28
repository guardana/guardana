---
title: "Collector recovery runbooks (#143)"
date: 2026-10-23
summary: "The proof upgraded a database created by 0.41.0, checked rollback and readiness, and restored a Compose backup in place and onto a new volume."
---
The maintainer ran this proof with Guardana 1.0.0rc5 from PyPI, using proof scripts at commit `5b02b59e`. The [workflow run](https://github.com/guardana/guardana/actions/runs/40005613709) records the results.

## Migrations

The proof followed “Migrations” and “Applying migrations” in `docs/usage-collector.md`. On ubuntu-24.04, it installed `guardana-server[serve]` 0.41.0 and 1.0.0rc5 from PyPI into separate environments. Environment creation, installation and metadata checks each exited 0. A throwaway `postgres:16-alpine` container published PostgreSQL on loopback.

With 1.0.0rc5 pointed at an unreachable database:

```console
$ guardana-collector status
```

The command exited 4 and reported a refused connection.

The proof then used 0.41.0 against the throwaway database:

```console
$ guardana-collector migrate
$ guardana-collector status
$ guardana-collector bootstrap --org acme --project web --scope ingest --scope read
$ guardana-collector bootstrap --org globex --project api --scope ingest --scope read
$ guardana-collector serve --port 35505
```

Migrate, status and both bootstrap commands exited 0. Migrations `0001`–`0007` were applied. Serve started the collector; `/readyz` returned 200.

Both tenants ingested a `proof.synthetic_check` finding with HTTP 200. Each original key read only its tenant's finding and trend: `acme/web` held one HIGH finding; `globex/api` held one MEDIUM finding. Both findings pointed to `app/settings.py:3`. The proof stopped 0.41.0 before changing the schema.

With 1.0.0rc5, status exited 0 and showed:

```text
7 applied, 1 pending
…
  pending  0008 run_identity_per_environment
```

Serve on port 34675 started before migration. Its `/readyz` returned 503 with one migration pending.

```console
$ guardana-collector migrate
$ guardana-collector status
$ guardana-collector serve --port 55975
```

Migrate and status exited 0. Migration `0008` was applied; status showed eight applied and none pending. The collector returned `/readyz` 200. The 0.41.0 findings and trends read back unchanged with the original keys.

A new `proof.after_upgrade` finding for `acme/web` returned HTTP 200. Readback showed two HIGH findings for acme and the unchanged MEDIUM finding for globex.

```console
$ guardana-collector rollback
$ guardana-collector migrate
```

Rollback exited 0 and removed `0008` while the collector ran. Readiness became 503. Migrate exited 0, reapplied `0008` and restored readiness to 200.

```console
$ guardana-collector rollback --steps 6
$ guardana-collector status
$ guardana-collector migrate
```

Rollback exited 1. It rolled back `0004`–`0008`, then refused to remove `0003 tenancy` because dropping the tenant column would merge projects. Status exited 0: three applied, five pending. Migrate exited 0 and restored the later migrations. Serve on port 47417 returned `/readyz` 200. Original keys read the same findings and trends; no tenant's data merged into another's.

```console
$ GUARDANA_MIGRATE_ON_START=1 guardana-collector serve --port 59591
$ guardana-collector serve --port 41661
```

The first started against an empty database and returned `/readyz` 200. Plain serve against another empty database returned 503 with eight migrations pending.

## Backup and restore

The proof used the Compose deployment copied from `deploy/`, with `COMPOSE_PROJECT_NAME=guardana-proof`. The deployment files matched `v1.0.0rc5`. It pinned both collector and migrate images to the exact tag `1.0.0rc5` of `ghcr.io/guardana/guardana-collector`; the candidate carried only exact tags.

Pull, migrate and startup commands exited 0. Both tenants were bootstrapped with ingest and read scopes. The page's one-key example omitted read scope. Health and readiness checks exited 0.

Each tenant ingested its synthetic finding with HTTP 200. Its key read only that finding and trend: acme had HIGH 1; globex had MEDIUM 1.

The proof read both blocks from “Backups, and restoring one” in `docs/deployment.md` and ran them as written, setting only `BACKUP=` for restores. The backup block exited 0:

```bash
set -a; . deploy/.env; set +a
BACKUP="guardana-$(date -u +%Y-%m-%d).dump"
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom \
  > "$BACKUP"
```

After the dump, acme ingested a `proof.after_backup` sentinel with HTTP 200. Readback showed it alongside the original finding.

The restore block ran as written, with only `BACKUP=` set:

```bash
set -a; . deploy/.env; set +a
BACKUP=guardana-2026-10-23.dump

docker compose -f deploy/docker-compose.yml exec -T db pg_restore --list < "$BACKUP" > /dev/null &&
docker compose -f deploy/docker-compose.yml stop collector &&
docker compose -f deploy/docker-compose.yml exec -T db psql -U "$POSTGRES_USER" -d postgres \
  -v ON_ERROR_STOP=1 \
  -c "drop database if exists \"$POSTGRES_DB\" with (force)" \
  -c "create database \"$POSTGRES_DB\"" &&
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists \
  < "$BACKUP" &&
docker compose -f deploy/docker-compose.yml start collector &&
curl -fsS --retry 30 --retry-delay 1 --retry-all-errors http://127.0.0.1:8000/readyz
```

With `BACKUP=unreadable.dump`, it exited 1 at the archive check, before stopping the collector or dropping the database. Readiness remained 200. Both tenants' data and the sentinel remained intact.

The in-place restore exited 0. Readiness returned 200. The original keys read each tenant's backup finding and trend unchanged; the sentinel was gone.

```console
$ docker compose -f deploy/docker-compose.yml down -v
$ docker compose -f deploy/docker-compose.yml up -d
```

Both commands exited 0. The new volume initially returned `/readyz` 503 with eight migrations pending. The same restore block exited 0. Readiness became 200. Original keys again read the unchanged backup findings and trends, separated by tenant, with no sentinel.

[#194](https://github.com/guardana/guardana/pull/194) made the final curl wait for `/readyz`: an earlier local restore succeeded but its immediate curl exited 52. In this run, retries recovered from connection resets during restart.

## What this proof does not show

This proof covers the upgrade from 0.41.0 and these rollback and restore paths. It does not establish recovery from every earlier schema or damaged backup.

The new-volume check ran on the same runner. It did not move the dump to another host. Installation and image pulls used the network.
