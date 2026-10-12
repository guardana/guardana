# `acme-guardana-outputs` — an installed format and an installed reporter

A runnable example of adding an output to Guardana from another package, owned by a
fictional company *Acme*, with no change to Guardana. It ships:

| Name | Group | What it does |
|---|---|---|
| `acme-table` | `guardana.renderers` | `--format acme-table`: the run as one CSV table (RFC 4180, every cell quoted, `\r\n`) — the verdict row, every finding, error, skip, shortfall, case and suite, and each rule that ran with no finding |
| `acme-webhook` | `guardana.reporters` | `--reporter acme-webhook://…`: the run's summary as one signed [Standard Webhooks](https://www.standardwebhooks.com/) delivery |

Both are imported only when a run selects them; selecting the table never imports the
webhook. Standard library only.

## Install and select both

```bash
pip install ./examples/output_pack

export ACME_WEBHOOK_SECRET="whsec_$(openssl rand -base64 24)"
export ACME_WEBHOOK_URL="https://hooks.example.com/guardana"

guardana scan . --plugins allowlist --allow-plugin acme-guardana-outputs \
  --format acme-table --output run.csv \
  --reporter acme-webhook://env:ACME_WEBHOOK_URL
```

An installed output is third-party code, so it runs only under a plugin trust that
admits its distribution. `acme-webhook://https://hooks.example.com/guardana` names the
URL directly; `env:NAME` keeps a URL that carries a token out of shell history and CI
logs. Plain `http` is accepted only for `localhost`, `127.0.0.1` and `::1`.

## The delivery line

Every run with a reporter prints one line to stderr, whatever happened:

```
delivery: delivered — acme-webhook to https://hooks.example.com (HTTP 204, 1 attempt)
delivery: rejected — acme-webhook to https://hooks.example.com (HTTP 410, 1 attempt): the receiver no longer accepts deliveries
delivery: unreachable — acme-webhook to https://hooks.example.com (3 attempts): connection refused
```

Only `scheme://host[:port]` is shown, never the path or query. The webhook connects directly
to the destination and ignores `HTTP_PROXY`, `HTTPS_PROXY` and their lowercase forms, so no
proxy sees the signed summary. By default, the command keeps the run's exit code if a receiver
refuses delivery or cannot be reached. Under `delivery.required`, the command exits `8`
instead. A delivery with the outcome `unknown` exits `8` either way
([delivery status](../../docs/outputs.md#delivery-status)). The webhook makes at most three
attempts within 25 seconds and retries only on no answer, `408`, `429` and `5xx`.

## What the webhook sends

`{"type": "run.completed", "timestamp": …, "data": {…}}`: the run id, the verdict and its
exit code, every open question, counts of every channel (each key present, zero
included), the target, the declared deployment fields and up to 50 findings as rule id,
severity and title, most severe first. No evidence, prompt or reply. The `webhook-id`
is derived from the run id, so a receiver drops a repeat. A receiver verifies the
signature with any Standard Webhooks library:

```python
from standardwebhooks.webhooks import Webhook

payload = Webhook(secret).verify(body, headers)
```

## Export a saved run from Python

A run saved with `--format json --output run.json` is exported after the fact, so one
paid probe gives both a comparable run and a table:

```python
from pathlib import Path

from guardana.core.output import render, select_renderer
from guardana.core.plugins import PluginMode, PluginTrust
from guardana.core.verify import load_verification

trust = PluginTrust(mode=PluginMode.ALLOWLIST, allowed=frozenset({"acme-guardana-outputs"}))
table = render(select_renderer("acme-table", trust), load_verification(Path("run.json")))
```

## Tests

`tests/` installs this package beside Guardana in an isolated environment and runs the
CLI against it: `scan` and `grade` with the network refused, `probe` against a scripted
endpoint, `pack validate` and `pack lock`, and the webhook against a receiver that checks
every delivery with the reference `standardwebhooks` verifier, which the tests alone
install. Both outputs also pass Guardana's own output checks
([conformance kit](../../docs/conformance-kit.md)), and the webhook is delivered with every
proxy variable pointing at a refusing address:

```bash
uv run --isolated --no-cache --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./packages/guardana-cli --with ./packages/guardana-report \
  --with ./examples/output_pack --with standardwebhooks==1.1.0 --with pytest \
  pytest examples/output_pack/tests
```
