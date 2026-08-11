# Official container images

Two images, published to the GitHub Container Registry on every release:

| Image | What it is | Entrypoint |
|---|---|---|
| `ghcr.io/guardana/guardana:0.19` | the CLI — `scan`, `probe`, `monitor`, `diff` and the rest | `guardana` |
| `ghcr.io/guardana/guardana-collector:0.19` | the optional collector | `guardana-collector` |

Three tags: the exact version, the moving minor (what the table above pins), and
`latest`. Pin the **moving minor** in a pipeline — it picks up fixes without changing which rules
run. A pre-release never moves `latest` or the minor tag.

Both are built from `python:3.13-slim-bookworm` in two stages, so the shipped
image carries no build tooling, and both run as **uid 10001**, not root. Each
release pushes `linux/amd64` and `linux/arm64`, with an SBOM and a signed
provenance attestation attached in the registry.

## The CLI

```bash
docker run --rm -v "$PWD:/work:ro" ghcr.io/guardana/guardana:0.19 scan /work
```

`/work` is the working directory inside the image; mounting read-only is enough,
because a scan never writes to what it reads. Exit codes are the ones in
[`docs/exit-codes.md`](../../docs/exit-codes.md) — `0` clean, `1` findings, `3` a
usage error — so a pipeline gates on the container the same way it gates on the
command.

Writing a report out needs a writable mount:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/guardana/guardana:0.19 \
  scan /work --format sarif --output /work/guardana.sarif
```

The file is written as uid 10001. On a host where that matters, add
`--user "$(id -u):$(id -g)"` — the image does not care which uid it runs as, it
only refuses to run as root by default.

**The same flag is the answer to `Path '/work' is not readable`.** A workspace
only its owner can read (mode `0700`, which several CI systems produce) is
unreadable to uid 10001, and the scan refuses rather than reporting an empty
directory — a scanner that cannot see its target must never answer "no findings".
Run it as yourself and it reads what you can read:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" \
  ghcr.io/guardana/guardana:0.19 scan /work
```

## The collector

```bash
docker run --rm \
  -e GUARDANA_DATABASE_URL="postgresql://guardana:...@db:5432/guardana" \
  ghcr.io/guardana/guardana-collector:0.19 migrate

docker run -d --name guardana-collector -p 8000:8000 \
  -e GUARDANA_DATABASE_URL="postgresql://guardana:...@db:5432/guardana" \
  ghcr.io/guardana/guardana-collector:0.19
```

The default command is `serve --host 0.0.0.0 --port 8000`. Binding every
interface is right inside a container and wrong on a laptop, which is why the
image says it and the command itself defaults to loopback.

**Migrations are not run on start.** A rolling deploy would otherwise run two
versions of the code against one schema, and the operator undoing that at three in
the morning wants one instruction (`rollback`), not a restart with a different
environment variable. `/readyz` fails while a migration is pending, so a
half-upgraded collector never quietly serves traffic.

`/healthz` is liveness (the process answers) and `/readyz` is readiness (storage
reachable, schema current). The image's own `HEALTHCHECK` uses `/healthz`; point
an orchestrator's readiness probe at `/readyz`.

What the collector does and deliberately does not is
[`docs/usage-collector.md`](../../docs/usage-collector.md); a full deployment —
Compose file, TLS, upgrades — is
[`docs/deployment.md`](../../docs/deployment.md).

## If a pull says `unauthorized`

The images are public. If a fresh machine cannot pull one, the package's
visibility was never flipped after the first release — a package created by a
workflow starts private whatever the repository is. That is a maintainer setting,
not something to work around with a token:
[`docs/maintainers/github-setup.md`](../../docs/maintainers/github-setup.md).

## Building them yourself

From the repository root, because both Dockerfiles copy from `packages/`:

```bash
docker build -f deploy/docker/cli.Dockerfile -t guardana-cli:dev .
docker build -f deploy/docker/collector.Dockerfile -t guardana-collector:dev .
```

`uv run python scripts/image_smoke.py` builds both and runs them — the same
checks CI runs on every push, including a scan of the deliberately malicious
fixture that must exit `1`. An image whose rule catalog failed to ship reports
"no findings" and exits `0`, and that is the failure this project exists to
prevent.
