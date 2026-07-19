# guardana-server

Guardana's optional collector — a minimal FastAPI service that ingests findings
from many agents and, optionally, serves a read-only monitoring dashboard.

Part of **[Guardana](https://github.com/guardana/guardana)** — security
verification for self-hosted and self-built AI (model files, live endpoints,
and agents) from one rule engine that runs on your laptop, in CI, and next to
a served model.

## Run it

```bash
# API only (POST/GET /findings, GET /trend):
uvicorn --factory guardana.server:create_app

# With the opt-in dashboard (adds GET / and GET /stats):
GUARDANA_DASHBOARD=1 uvicorn --factory guardana.server:create_app
# or, from your own code: create_app(dashboard=True, refresh_seconds=15)
```

The dashboard is a single self-contained page (no build step, works offline)
showing severity, per-source/per-rule breakdowns, an activity-over-time trend,
the `unverified` counter, and a filterable recent-findings table. It is
**read-only and unauthenticated** — do not expose it to an untrusted network
(see [SECURITY.md](https://github.com/guardana/guardana/blob/main/SECURITY.md)).

- Main README & quickstart: https://github.com/guardana/guardana#readme
- Documentation: https://guardana.dev

Licensed under Apache-2.0.
