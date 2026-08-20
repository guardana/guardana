---
name: full-gate
description: Run every Guardana gate in the right order, with the cache traps that have twice produced a false green. Use before tagging a release, before opening a PR, or whenever "is this green" needs an answer you can rely on.
---

# The full gate

`CLAUDE.md` lists the gates. This is how to run them so the answer is true.

## Run in this order

Fast feedback first, and the isolated ones last because they are slow and they
catch a different class of problem.

```bash
rm -rf .ruff_cache                                   # see "cache traps" below
find packages examples -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null

uv run ruff check .
uv run ruff format --check .
uv run mypy --strict .
uv run lint-imports

docker compose -f deploy/docker-compose.dev.yml up -d   # PostgreSQL on 55439
uv run pytest --cov --cov-report=json:.coverage.json
uv run python scripts/critical_coverage.py .coverage.json

uv run guardana scan packages                        # dogfood: must stay at zero

uv run python scripts/generate_docs.py               # all four must report "current"
uv run python scripts/sync_site.py
uv run python scripts/build_site.py --check
uv run python scripts/generate_llms_txt.py --check

uv run --isolated --no-cache \
  --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./examples/custom_rule --with pytest pytest examples/custom_rule/tests -q
uv run --isolated --no-cache \
  --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./examples/hermes_integrator --with pytest \
  pytest examples/hermes_integrator/tests -q
uv run --isolated --no-cache \
  --with ./packages/guardana-core --with ./packages/guardana-rules \
  --with ./examples/shell_hook_integrator --with pytest \
  pytest examples/shell_hook_integrator/tests -q

uv run python scripts/clean_install_check.py         # before a tag, always
```

## Cache traps — each of these has produced a false green here

**`.ruff_cache`** answered for a file that had changed. A green local gate cut a
tag that CI then rejected (0.19.0). Delete it before a gate you intend to act on.

**`--no-cache` on the isolated example runs is not a speed trade.** Without it,
`uv` serves a previously built wheel for `./examples/custom_rule`, and the data
files inside it — `guardana-pack.yaml`, the YAML rules — are exactly what a change
to the extension contract touches. `--refresh` and `--refresh-package` were both
measured and both returned the stale wheel. This gate has produced a false green
**twice**, including a pushed tag in 0.20.0 whose CI was red on the very tests the
command had just reported passing.

**`__pycache__` after inverting behaviour.** Flipping `>` to `<` keeps the file
size identical; written within the same second, Python reuses the old bytecode and
you are running the old code while reading the new.

**PostgreSQL.** Without it, ~245 tests skip and the run still exits 0. CI sets
`GUARDANA_REQUIRE_POSTGRES=1`, so a locally-green suite can be a CI failure. Start
the dev compose file first.

## Reading the result

A skipped test is not a passing test. Report the skip count and why. If
PostgreSQL or `pg_dump` were absent, say which gates therefore did not run rather
than reporting the suite as green.

Never report a gate as passing without having read its output in this session.
