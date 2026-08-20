# guardana-server

Guardana's optional collector — a minimal FastAPI service that ingests findings
from many agents and, optionally, serves a read-only monitoring dashboard.

Part of **[Guardana](https://github.com/guardana/guardana)** — security
verification for self-hosted and self-built AI (model files, live endpoints,
and agents) from one rule engine that runs on your laptop, in CI, and next to
a served model.

## Run it

```bash
pip install "guardana-server[serve]"      # `[serve]` adds the ASGI server

export GUARDANA_DATABASE_URL=postgresql://guardana:secret@db:5432/guardana
guardana-collector migrate                # never on start: see the docs for why
guardana-collector bootstrap --org acme --project web    # prints the key, once
guardana-collector serve                  # http://127.0.0.1:8000
```

`serve` binds loopback unless you pass `--host 0.0.0.0`. The ASGI server is an
extra rather than a dependency, so a deployment that already runs gunicorn or
hypercorn can point it at the app instead:
`gunicorn -k uvicorn.workers.UvicornWorker 'guardana.server:create_app()'`.

There is an official image too:
`docker run -p 8000:8000 -e GUARDANA_DATABASE_URL=… ghcr.io/guardana/guardana-collector:0.22`.

The dashboard is a single self-contained page (no build step, works offline)
showing severity, per-source/per-rule breakdowns, an activity-over-time trend,
the `unverified` counter, and a filterable recent-findings table. It is
**read-only**, and signs in with a read-scoped API key that it holds in an
`HttpOnly`, `SameSite=Strict` cookie — a browser has nowhere safe to put a bearer
token, so it never gets one. It is still a panel over a security database: put it
behind the same network boundary as the collector itself (see
[SECURITY.md](https://github.com/guardana/guardana/blob/main/SECURITY.md)).

- Main README & quickstart: https://github.com/guardana/guardana#readme
- Documentation: https://guardana.dev

Licensed under Apache-2.0.
